//! Import from and export to other password managers.
//!
//! Both run on the client: the file is read (or written) locally and each
//! item goes through the normal API, so access rules and the audit log apply.
//! The summaries returned here never contain secret values, which is what
//! lets an agent run an import without the passwords entering its context.

use crate::{write_private, Client};
use jaword_core::access::valid_path;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAX_FILE: u64 = 20 * 1024 * 1024;
const MAX_VALUE: usize = 16 * 1024;

pub struct ImportOpts {
    pub file: PathBuf,
    pub prefix: String,
    pub dry_run: bool,
    pub remove_source: bool,
}

/// RFC 4180 CSV: quoted fields, doubled quotes, commas and newlines inside quotes.
pub fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut rows = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => quoted = false,
                _ => field.push(c),
            }
        } else {
            match c {
                '"' if field.is_empty() => quoted = true,
                ',' => row.push(std::mem::take(&mut field)),
                '\r' if chars.peek() == Some(&'\n') => {}
                '\n' | '\r' => {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                }
                _ => field.push(c),
            }
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows.retain(|r| r.iter().any(|f| !f.trim().is_empty()));
    rows
}

fn csv_field(s: &str) -> String {
    if s.contains(['"', ',', '\n', '\r']) || s.starts_with(' ') || s.ends_with(' ') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Turn a free-text title into one valid path segment.
pub fn slug(title: &str) -> String {
    let mut out = String::new();
    for c in title.trim().chars().flat_map(|c| c.to_lowercase()) {
        let c = if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' { c } else if c == '.' { '.' } else { '-' };
        // No doubled separators, so ".." can never appear.
        if matches!(c, '-' | '.') && matches!(out.chars().last(), Some('-') | Some('.') | None) {
            continue;
        }
        out.push(c);
    }
    let trimmed: String = out.trim_start_matches(['_', '-', '.']).chars().take(60).collect();
    let trimmed = trimmed.trim_end_matches(['-', '.']).to_string();
    if trimmed.is_empty() { "item".into() } else { trimmed }
}

/// A folder name from an export, as a path segment; empty when it has no usable characters.
fn slug_part(name: &str) -> String {
    if name.chars().any(|c| c.is_ascii_alphanumeric()) {
        slug(name)
    } else {
        String::new()
    }
}

fn host_of(url: &str) -> &str {
    let rest = url.split("://").nth(1).unwrap_or(url);
    rest.split(['/', '?', '#', ':']).next().unwrap_or("")
}

fn find_col(header: &[String], names: &[&str]) -> Option<usize> {
    header.iter().position(|h| names.contains(&h.as_str()))
}

pub fn import_file(c: &Client, o: &ImportOpts) -> Result<Value, String> {
    let prefix = o.prefix.trim_matches('/');
    if !valid_path(prefix) {
        return Err("prefix must be a valid path like `logins` or `imported/1password`".into());
    }
    let meta = std::fs::metadata(&o.file).map_err(|e| format!("{}: {e}", o.file.display()))?;
    if meta.len() > MAX_FILE {
        return Err("file is larger than 20 MB".into());
    }
    let text = Zeroizing::new(std::fs::read_to_string(&o.file).map_err(|e| format!("{}: {e}", o.file.display()))?);
    let mut rows = parse_csv(&text);
    if rows.len() < 2 {
        return Err("no rows found; expected a CSV export with a header line".into());
    }
    let header: Vec<String> = rows.remove(0).iter().map(|h| h.trim().to_lowercase()).collect();
    // Column names used by 1Password, Bitwarden, Chrome/Edge, Firefox, LastPass and KeePassXC exports.
    let col_title = find_col(&header, &["title", "name", "account", "group/title"]);
    let col_url = find_col(&header, &["url", "urls", "website", "login_uri", "web site", "origin"]);
    // NordPass has both `username` and `email`; the real username column wins.
    let col_user = find_col(&header, &["username", "login_username", "user name", "login name", "user"]);
    let col_email = find_col(&header, &["email", "e-mail"]);
    let col_pass = find_col(&header, &["password", "login_password"]).ok_or_else(|| {
        "this CSV has no `password` column. Expected a password-manager export with columns like Title, Url, Username, Password".to_string()
    })?;
    let col_notes = find_col(&header, &["notes", "note", "extra", "notesplain", "comments"]);
    let col_tags = find_col(&header, &["tags"]);
    let col_folder = find_col(&header, &["folder", "grouping", "group"]);
    let col_otp = find_col(&header, &["otpauth", "login_totp", "totp", "otp"]);
    let get = |row: &Vec<String>, col: Option<usize>| col.and_then(|i| row.get(i)).map(|s| s.trim().to_string()).unwrap_or_default();

    let (mut imported, mut no_password, mut too_large, mut totp, mut already) = (0u32, 0u32, 0u32, 0u32, 0u32);
    let mut used: HashSet<String> = HashSet::new();
    // What is already in the vault under this prefix: path -> (username, url).
    let existing: std::collections::HashMap<String, (String, String)> = c
        .list(&format!("{prefix}/"))
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .map(|s| (s["path"].as_str().unwrap_or("").to_string(), (s["meta"]["username"].as_str().unwrap_or("").to_string(), s["meta"]["url"].as_str().unwrap_or("").to_string())))
        .collect();
    let mut paths: Vec<String> = Vec::new();
    let mut failed: Vec<Value> = Vec::new();

    for row in &rows {
        let password = Zeroizing::new(row.get(col_pass).cloned().unwrap_or_default());
        let title = get(row, col_title);
        let url = get(row, col_url).split([',', '\n']).next().unwrap_or("").trim().chars().take(2048).collect::<String>();
        if password.is_empty() {
            no_password += 1;
            continue;
        }
        if password.len() > MAX_VALUE {
            too_large += 1;
            continue;
        }
        if !get(row, col_otp).is_empty() {
            totp += 1;
        }
        let name = if !title.is_empty() { title.clone() } else { host_of(&url).to_string() };
        // A folder column in the export becomes real folders under the prefix.
        let sub: String = get(row, col_folder).split(['/', '\\']).map(slug_part).filter(|p| !p.is_empty()).map(|p| format!("{p}/")).collect();
        let base = format!("{prefix}/{sub}{}", slug(&name));
        // Many sites sign in with the email address; use it when no username was saved.
        let user_now = Some(get(row, col_user)).filter(|u| !u.is_empty()).unwrap_or_else(|| get(row, col_email)).chars().take(256).collect::<String>();
        let tags: Vec<String> = get(row, col_tags)
            .split([',', ';'])
            .map(|t| t.trim().chars().take(64).collect::<String>())
            .filter(|t| !t.is_empty())
            .take(32)
            .collect();
        let meta = json!({
            "title": title.chars().take(200).collect::<String>(),
            "username": user_now,
            "url": url,
            "notes": get(row, col_notes).chars().take(8000).collect::<String>(),
            "tags": tags,
        });
        // Find a free path: first locally (duplicates inside the file), then on the server.
        let mut done = false;
        for n in 1..=50 {
            let path = if n == 1 { base.clone() } else { format!("{base}-{n}") };
            if used.contains(&path) {
                continue;
            }
            if let Some((u, link)) = existing.get(&path) {
                // Same place, same login: it was imported before. Leave it alone.
                if *u == user_now && *link == url {
                    already += 1;
                    done = true;
                    break;
                }
                continue;
            }
            if o.dry_run {
                used.insert(path.clone());
                paths.push(path);
                imported += 1;
                done = true;
                break;
            }
            let body = Zeroizing::new(json!({"path": path, "kind": "password", "meta": meta, "value": password.as_str()}).to_string());
            match c.post_raw("/v1/secrets/create", &body) {
                Ok(_) => {
                    used.insert(path.clone());
                    paths.push(path);
                    imported += 1;
                    done = true;
                    break;
                }
                Err(e) if e.status == 409 => {
                    used.insert(path);
                }
                Err(e) => {
                    failed.push(json!({"path": path, "error": e.message}));
                    done = true;
                    if e.status == 401 || e.status == 0 || e.status == 503 {
                        return Err(format!("stopped after {imported} items: {}", e.message));
                    }
                    break;
                }
            }
        }
        if !done {
            failed.push(json!({"path": base, "error": "could not find a free path"}));
        }
    }

    let mut removed = false;
    if o.remove_source && !o.dry_run && failed.is_empty() {
        removed = std::fs::remove_file(&o.file).is_ok();
    }
    let shown: Vec<&String> = paths.iter().take(500).collect();
    Ok(json!({
        "dry_run": o.dry_run,
        "imported": imported,
        "already_in_vault": already,
        "skipped_no_password": no_password,
        "skipped_too_large": too_large,
        "one_time_codes_not_imported": totp,
        "failed": failed,
        "source_file_removed": removed,
        "source_file_warning": if removed || o.dry_run { Value::Null } else { json!("the export file still holds every password in plain text; delete it once you have checked the import") },
        "paths": shown,
    }))
}

pub fn export(c: &Client, out: &Path, format: &str, prefix: &str, metadata_only: bool) -> Result<Value, String> {
    if !matches!(format, "csv" | "json") {
        return Err("format must be csv or json".into());
    }
    let list = c.list(prefix).map_err(|e| e.message)?;
    let items = list.as_array().cloned().unwrap_or_default();
    let mut records: Vec<Value> = Vec::new();
    for s in &items {
        let path = s["path"].as_str().unwrap_or("");
        let mut rec = json!({
            "title": s["meta"]["title"].as_str().filter(|t| !t.is_empty()).unwrap_or(path),
            "url": s["meta"]["url"], "username": s["meta"]["username"], "notes": s["meta"]["notes"],
            "tags": s["meta"]["tags"].as_array().map(|a| a.iter().filter_map(|t| t.as_str()).collect::<Vec<_>>().join(",")).unwrap_or_default(),
            "path": path, "kind": s["kind"], "version": s["current_version"],
        });
        if !metadata_only {
            let v = c.post("/v1/secrets/reveal", &json!({"path": path})).map_err(|e| {
                if e.status == 403 {
                    format!("not permitted to read `{path}`. A full export needs a human or admin token with reveal; agents can only use --metadata-only")
                } else {
                    e.message
                }
            })?;
            rec["password"] = v["value"].clone();
        }
        records.push(rec);
    }
    let text = Zeroizing::new(if format == "json" {
        serde_json::to_string_pretty(&records).map_err(|e| e.to_string())?
    } else {
        // Column order that 1Password, Bitwarden and most others accept on import.
        let cols: &[&str] = if metadata_only {
            &["title", "url", "username", "notes", "tags", "path", "kind", "version"]
        } else {
            &["title", "url", "username", "password", "notes", "tags", "path", "kind"]
        };
        let mut t = cols.iter().map(|c| { let mut s = c.to_string(); s[..1].make_ascii_uppercase(); s }).collect::<Vec<_>>().join(",");
        t.push('\n');
        for r in &records {
            let line: Vec<String> = cols.iter().map(|k| csv_field(&r[*k].as_str().map(str::to_string).unwrap_or_else(|| if r[*k].is_null() { String::new() } else { r[*k].to_string() }))).collect();
            t.push_str(&line.join(","));
            t.push('\n');
        }
        t
    });
    write_private(out, text.as_bytes());
    Ok(json!({
        "exported": records.len(),
        "file": out.display().to_string(),
        "contains_secret_values": !metadata_only,
        "warning": if metadata_only { Value::Null } else { json!("this file holds every exported password in plain text; move it where it needs to go, then delete it") },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_parsing() {
        let rows = parse_csv("\u{feff}Title,Url,Password\r\n\"A, Inc\",https://a.example,\"p\"\"q,\nr\"\n\nB,,x\n");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[1], vec!["A, Inc", "https://a.example", "p\"q,\nr"]);
        assert_eq!(rows[2], vec!["B", "", "x"]);
        assert_eq!(parse_csv("a,b"), vec![vec!["a", "b"]]);
        assert_eq!(parse_csv("a,\n"), vec![vec!["a", ""]]);
    }

    #[test]
    fn csv_writing_roundtrips() {
        for v in ["plain", "with,comma", "with \"quote\"", "multi\nline", " padded "] {
            let line = format!("{},x\n", csv_field(v));
            assert_eq!(parse_csv(&line)[0][0], v);
        }
    }

    #[test]
    fn slugs_are_always_valid_path_segments() {
        assert_eq!(slug("Proxmox Root (pve)"), "proxmox-root-pve");
        assert_eq!(slug("  GitHub.com  "), "github.com");
        assert_eq!(slug("../../etc/passwd"), "etc-passwd");
        assert_eq!(slug("a..b"), "a.b");
        assert_eq!(slug("Ünïcödé & Co."), "n-c-d-co");
        assert_eq!(slug("???"), "item");
        assert_eq!(slug(""), "item");
        for t in ["Proxmox Root", "../x", "a/b\\c", "-lead", ".hidden", "trail.", "x".repeat(300).as_str(), "A  B", "日本語", "a..b..c"] {
            let p = format!("imported/{}", slug(t));
            assert!(valid_path(&p), "{t:?} -> {p}");
        }
    }

    #[test]
    fn host_extraction() {
        assert_eq!(host_of("https://github.com/login?x=1"), "github.com");
        assert_eq!(host_of("example.org:8443/path"), "example.org");
        assert_eq!(host_of(""), "");
    }
}
