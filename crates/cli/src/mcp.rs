//! MCP (Model Context Protocol) server over stdio.
//!
//! This is the agent-facing surface. By design it has **no tool that returns a
//! secret value**: agents work with paths, metadata and version numbers, and
//! ask the vault to generate or rotate. Even if a tool here were added by
//! mistake, the server refuses `reveal` for agent tokens.

use crate::{ApiError, Client};
use serde_json::{json, Value};
use std::io::{BufRead, Write};

const POLICY_SCHEMA: &str = r#"{"type":"object","description":"Generation policy. One of: {\"type\":\"password\",\"length\":32,\"symbols\":\"\"(optional, empty = none)} | {\"type\":\"hex\",\"bytes\":32} | {\"type\":\"base64url\",\"bytes\":32} | {\"type\":\"words\",\"words\":5,\"separator\":\"-\",\"capitalize\":true,\"number\":false} (4-10 random dictionary words)"}"#;

fn tools() -> Value {
    let policy: Value = serde_json::from_str(POLICY_SCHEMA).unwrap_or(Value::Null);
    let path = json!({"type": "string", "description": "Secret path, lowercase segments, e.g. home-lab/proxmox-root"});
    json!([
        {
            "name": "vault_status",
            "description": "Check whether the vault is initialized and unsealed, and which identity/permissions this agent has.",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "secret_list",
            "description": "List secrets this agent may see (path, kind, version, metadata). Never returns secret values. Payment cards (kind card) show brand, last four digits and expiry; gift cards (kind gift_card) show the store, last four and balance_cents. Card numbers, security codes and PINs are never returned, and cards can only be added by a person.",
            "inputSchema": {"type": "object", "properties": {"prefix": {"type": "string", "description": "Optional path prefix, e.g. home-lab/"}}}
        },
        {
            "name": "secret_get",
            "description": "Get one secret's metadata and full version history (who changed it and when). Never returns the value.",
            "inputSchema": {"type": "object", "properties": {"path": path}, "required": ["path"]}
        },
        {
            "name": "secret_create",
            "description": "Create a secret. The vault generates the value internally and does not return it. Only pass `value` when a third party issued the credential and it is already known to you.",
            "inputSchema": {"type": "object", "properties": {
                "path": path,
                "kind": {"type": "string", "enum": ["password", "api_key", "ssh_key", "config", "note"]},
                "title": {"type": "string", "description": "Friendly name, e.g. Proxmox root"},
                "username": {"type": "string"},
                "url": {"type": "string"},
                "notes": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "policy": policy,
                "value": {"type": "string", "description": "Avoid. Externally issued value to store as-is."}
            }, "required": ["path"]}
        },
        {
            "name": "secret_update_metadata",
            "description": "Change a secret's title, username, url, notes or tags. Omitted fields are kept.",
            "inputSchema": {"type": "object", "properties": {
                "path": path,
                "title": {"type": "string"},
                "username": {"type": "string"},
                "url": {"type": "string"},
                "notes": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}}
            }, "required": ["path"]}
        },
        {
            "name": "secret_generate",
            "description": "Generate a new version of a secret inside the vault without pushing it anywhere. The value is not returned. Use secret_rotate instead when the live system must change too.",
            "inputSchema": {"type": "object", "properties": {"path": path, "policy": policy}, "required": ["path"]}
        },
        {
            "name": "secret_rotate",
            "description": "Rotate a credential end to end: the vault generates a new value, applies it to the target system through the secret's configured driver, and makes it current only if that succeeds. On failure the previous value stays current. Returns the new version number, never the value.",
            "inputSchema": {"type": "object", "properties": {"path": path}, "required": ["path"]}
        },
        {
            "name": "secret_import_file",
            "description": "Import a CSV export from another password manager (1Password, Bitwarden, Chrome, Firefox, LastPass, KeePassXC) into the vault. The file is read by this tool, not by you: do NOT open, cat or read the file yourself, it contains plain-text passwords. Returns counts and the created paths only. Run with dry_run first. Needs `create` and `write` on the target prefix.",
            "inputSchema": {"type": "object", "properties": {
                "file": {"type": "string", "description": "Absolute path of the CSV export on this machine"},
                "prefix": {"type": "string", "description": "Folder to import into, e.g. logins (default: imported)"},
                "dry_run": {"type": "boolean"},
                "remove_source": {"type": "boolean", "description": "Delete the export file after a fully successful import"}
            }, "required": ["file"]}
        },
        {
            "name": "secret_export_inventory",
            "description": "Write an inventory of secrets (title, site, username, tags, path, version; no values) to a CSV or JSON file. A full export including values can only be done by a human with `jaword export`.",
            "inputSchema": {"type": "object", "properties": {
                "out": {"type": "string", "description": "Absolute output file path"},
                "format": {"type": "string", "enum": ["csv", "json"]},
                "prefix": {"type": "string"}
            }, "required": ["out"]}
        },
        {
            "name": "secret_restore",
            "description": "Make an earlier version of a secret current again, for when a new password did not take on the real system. Recorded as a new version. The value is not returned. Version numbers come from secret_get.",
            "inputSchema": {"type": "object", "properties": {"path": path, "version": {"type": "integer"}}, "required": ["path", "version"]}
        },
        {
            "name": "gift_card_record",
            "description": "Record money spent from, or added to, a gift card so its balance stays right. Returns the card with the new balance_cents. Does not move money and never reveals the card number. Fails if the spend is more than what is left.",
            "inputSchema": {"type": "object", "properties": {
                "path": path,
                "direction": {"type": "string", "enum": ["spend", "add"]},
                "amount_cents": {"type": "integer", "minimum": 1, "description": "Amount in cents, always positive: 1234 means 12.34"},
                "note": {"type": "string", "description": "What it was for, one short line"}
            }, "required": ["path", "direction", "amount_cents"]}
        },
        {
            "name": "secret_move",
            "description": "Move or rename a secret to a new path (for example into another folder). History and rotation setup move with it.",
            "inputSchema": {"type": "object", "properties": {"path": path, "new_path": {"type": "string", "description": "Destination path, e.g. business/vpn"}}, "required": ["path", "new_path"]}
        },
        {
            "name": "folder_list",
            "description": "List folders (path prefixes) with how many items each holds.",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "folder_create",
            "description": "Create an empty folder, e.g. personal or work/clients.",
            "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
        },
        {
            "name": "folder_move",
            "description": "Rename or move a folder and everything inside it. Changes the path of every item in it.",
            "inputSchema": {"type": "object", "properties": {"from": {"type": "string"}, "to": {"type": "string"}}, "required": ["from", "to"]}
        },
        {
            "name": "folder_delete",
            "description": "Delete a folder. With move_to its items are moved there first (empty string = top level). WITHOUT move_to every item inside is deleted: only do that when the user explicitly asked for the contents to be deleted.",
            "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "move_to": {"type": "string"}}, "required": ["path"]}
        },
        {
            "name": "vault_update_status",
            "description": "Show the vault's installed version, the latest release it knows about and the result of the last update check or install. Needs `upgrade` on `sys/update`.",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "vault_update_check",
            "description": "Ask the vault to look up the latest signed release. Read vault_update_status a few seconds later for the result.",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "vault_update_apply",
            "description": "Install a signed release on the vault. The vault verifies the signature itself; unsigned or tampered releases are refused. IMPORTANT: this restarts the vault, which then stays sealed (nothing can be read or rotated) until a human enters the passphrase. Only do this when the user asked for it.",
            "inputSchema": {"type": "object", "properties": {"version": {"type": "string", "description": "Exact release tag, e.g. v0.2.0"}}, "required": ["version"]}
        },
        {
            "name": "secret_delete",
            "description": "Soft-delete a secret (an admin can still recover it).",
            "inputSchema": {"type": "object", "properties": {"path": path}, "required": ["path"]}
        }
    ])
}

fn arg<'a>(args: &'a Value, k: &str) -> Result<&'a str, ApiError> {
    args[k].as_str().ok_or_else(|| ApiError { status: 400, message: format!("missing string argument `{k}`") })
}

fn call(c: &Client, name: &str, args: &Value) -> Result<Value, ApiError> {
    match name {
        "vault_status" => {
            let mut st = c.get("/v1/sys/status")?;
            st["identity"] = c.get("/v1/whoami").unwrap_or_else(|e| json!({"error": e.message}));
            Ok(st)
        }
        "secret_list" => c.list(args["prefix"].as_str().unwrap_or("")),
        "secret_get" => c.get_secret(arg(args, "path")?),
        "secret_create" => {
            let mut body = json!({
                "path": arg(args, "path")?,
                "kind": args["kind"].as_str().unwrap_or("password"),
                "meta": {
                    "title": args["title"].as_str().unwrap_or(""),
                    "username": args["username"].as_str().unwrap_or(""),
                    "url": args["url"].as_str().unwrap_or(""),
                    "notes": args["notes"].as_str().unwrap_or(""),
                    "tags": args.get("tags").cloned().unwrap_or(json!([])),
                }
            });
            if let Some(p) = args.get("policy").filter(|p| !p.is_null()) {
                body["policy"] = p.clone();
            }
            if let Some(v) = args["value"].as_str() {
                body["value"] = json!(v);
            }
            c.post("/v1/secrets/create", &body)
        }
        "secret_update_metadata" => {
            let path = arg(args, "path")?;
            let mut meta = c.get_secret(path)?["meta"].clone();
            for k in ["title", "username", "url", "notes", "tags"] {
                if let Some(v) = args.get(k).filter(|v| !v.is_null()) {
                    meta[k] = v.clone();
                }
            }
            c.post("/v1/secrets/update", &json!({"path": path, "meta": meta}))
        }
        "secret_generate" => {
            let mut body = json!({"path": arg(args, "path")?});
            if let Some(p) = args.get("policy").filter(|p| !p.is_null()) {
                body["policy"] = p.clone();
            }
            c.post("/v1/secrets/generate", &body)
        }
        "secret_rotate" => c.post("/v1/secrets/rotate", &json!({"path": arg(args, "path")?})),
        "secret_import_file" => crate::transfer::import_file(
            c,
            &crate::transfer::ImportOpts {
                file: arg(args, "file")?.into(),
                prefix: args["prefix"].as_str().unwrap_or("imported").to_string(),
                dry_run: args["dry_run"].as_bool().unwrap_or(false),
                remove_source: args["remove_source"].as_bool().unwrap_or(false),
            },
        )
        .map_err(|m| ApiError { status: 400, message: m }),
        "secret_export_inventory" => crate::transfer::export(
            c,
            std::path::Path::new(arg(args, "out")?),
            args["format"].as_str().unwrap_or("csv"),
            args["prefix"].as_str().unwrap_or(""),
            true,
        )
        .map_err(|m| ApiError { status: 400, message: m }),
        "secret_restore" => c.post("/v1/secrets/restore", &json!({"path": arg(args, "path")?, "version": args["version"].as_i64().ok_or_else(|| ApiError { status: 400, message: "missing integer argument `version`".into() })?})),
        "gift_card_record" => {
            let bad = |m: &str| ApiError { status: 400, message: m.into() };
            let cents = args["amount_cents"].as_i64().filter(|n| *n > 0).ok_or_else(|| bad("`amount_cents` must be a positive integer"))?;
            let signed = match args["direction"].as_str() {
                Some("spend") => -cents,
                Some("add") => cents,
                _ => return Err(bad("`direction` must be spend or add")),
            };
            c.post("/v1/secrets/ledger", &json!({"path": arg(args, "path")?, "cents": signed, "note": args["note"].as_str().unwrap_or("")}))
        }
        "secret_move" => c.post("/v1/secrets/move", &json!({"path": arg(args, "path")?, "new_path": arg(args, "new_path")?})),
        "folder_list" => c.get("/v1/folders"),
        "folder_create" => c.post("/v1/folders/create", &json!({"path": arg(args, "path")?})),
        "folder_move" => c.post("/v1/folders/move", &json!({"from": arg(args, "from")?, "to": arg(args, "to")?})),
        "folder_delete" => {
            let mut body = json!({"path": arg(args, "path")?});
            if let Some(m) = args["move_to"].as_str() {
                body["move_to"] = json!(m);
            }
            c.post("/v1/folders/delete", &body)
        }
        "vault_update_status" => c.get("/v1/sys/update"),
        "vault_update_check" => c.post("/v1/sys/update", &json!({"action": "check"})),
        "vault_update_apply" => c.post("/v1/sys/update", &json!({"action": "apply", "version": arg(args, "version")?})),
        "secret_delete" => c.post("/v1/secrets/delete", &json!({"path": arg(args, "path")?})),
        _ => Err(ApiError { status: 404, message: format!("unknown tool `{name}`") }),
    }
}

fn handle(c: &Client, req: &Value) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = req["method"].as_str().unwrap_or("");
    let result: Result<Value, (i64, String)> = match method {
        "initialize" => Ok(json!({
            "protocolVersion": req["params"]["protocolVersion"].as_str().unwrap_or("2025-06-18"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "jaword", "version": env!("CARGO_PKG_VERSION")},
            "instructions": "jaword is a secrets vault. You manage credentials by path and never see their values: create or generate them inside the vault, and use secret_rotate to change a live credential. Do not ask the user to paste secrets into chat."
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools()})),
        "tools/call" => {
            let name = req["params"]["name"].as_str().unwrap_or("");
            let empty = json!({});
            let args = req["params"].get("arguments").unwrap_or(&empty);
            Ok(match call(c, name, args) {
                Ok(v) => json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&v).unwrap_or_default()}]}),
                Err(e) => json!({"content": [{"type": "text", "text": format!("error: {}", e.message)}], "isError": true}),
            })
        }
        m if m.starts_with("notifications/") => return None,
        _ => Err((-32601, format!("method not found: {method}"))),
    };
    // Requests without an id are notifications and get no reply.
    let id = id?;
    Some(match result {
        Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
        Err((code, message)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}),
    })
}

pub fn serve(c: &Client) {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(req) => handle(c, &req),
            Err(_) => Some(json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}})),
        };
        if let Some(r) = reply {
            if writeln!(out, "{r}").and_then(|_| out.flush()).is_err() {
                break;
            }
        }
    }
}
