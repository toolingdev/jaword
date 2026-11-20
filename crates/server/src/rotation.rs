//! Guided rotation setup for "a user on a server".
//!
//! Everything a person would otherwise do by hand in a terminal: give the
//! vault its own SSH identity, learn and pin a server's host key, produce the
//! one-time script that authorises the vault on that server for exactly one
//! account, and test the whole path without changing anything.
//!
//! All of this is admin-only and every external value (host, port, account,
//! keys) is validated against a strict alphabet before it reaches a command
//! line or a generated script.

use crate::drivers::{hostish, ssh_args, ssh_dir};
use serde::Serialize;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// A Unix account name: the conservative POSIX portable form.
pub fn valid_account(a: &str) -> bool {
    let b = a.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-'))
}

fn valid_key(key_type: &str, key: &str) -> bool {
    matches!(key_type, "ssh-ed25519" | "ecdsa-sha2-nistp256" | "ssh-rsa")
        && (40..=1024).contains(&key.len())
        && key.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

/// How a host appears in known_hosts: bare for port 22, `[host]:port` otherwise.
pub fn hostspec(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

async fn run(cmd: &mut Command, stdin: Option<&[u8]>, secs: u64) -> Result<(i32, String, String), String> {
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| format!("could not start helper: {e}"))?;
    if let (Some(data), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let _ = pipe.write_all(data).await;
        let _ = pipe.shutdown().await;
    }
    let out = tokio::time::timeout(Duration::from_secs(secs), child.wait_with_output())
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|e| format!("helper failed: {e}"))?;
    Ok((
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// The vault's own SSH public key, created on first use.
pub async fn identity() -> Result<String, String> {
    let dir = ssh_dir();
    let key = dir.join("id_ed25519");
    if !key.exists() {
        std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let (code, _, err) = run(
            Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-C", "jaword-vault", "-f"]).arg(&key),
            None,
            20,
        )
        .await?;
        if code != 0 {
            return Err(format!("could not create the vault's SSH key: {}", err.trim()));
        }
    }
    let text = std::fs::read_to_string(key.with_extension("pub")).map_err(|e| format!("cannot read the vault's public key: {e}"))?;
    let mut parts = text.split_whitespace();
    match (parts.next(), parts.next()) {
        (Some(t), Some(k)) if valid_key(t, k) => Ok(format!("{t} {k}")),
        _ => Err("the vault's public key file is malformed".into()),
    }
}

#[derive(Debug, Serialize)]
pub struct HostKey {
    pub key_type: String,
    pub key: String,
    pub fingerprint: String,
    /// `new` (never seen), `trusted` (matches what was pinned), `changed`
    /// (differs from what was pinned: possible impersonation).
    pub status: &'static str,
}

/// Ask a server for its host key. This is an unauthenticated fetch; the
/// fingerprint is shown to a person, who decides whether to trust it.
pub async fn scan(host: &str, port: u16) -> Result<HostKey, String> {
    if !hostish(host) || port == 0 {
        return Err("that server name is not valid".into());
    }
    let (_, out, _) = run(Command::new("ssh-keyscan").args(["-T", "6", "-t", "ed25519", "-p", &port.to_string(), "--", host]), None, 12).await?;
    let line = out.lines().find(|l| !l.starts_with('#') && !l.trim().is_empty()).ok_or_else(|| format!("could not reach {host} on port {port}"))?;
    let mut parts = line.split_whitespace();
    let (key_type, key) = match (parts.next(), parts.next(), parts.next()) {
        (Some(_), Some(t), Some(k)) if valid_key(t, k) => (t.to_string(), k.to_string()),
        _ => return Err("the server sent a host key in an unexpected form".into()),
    };
    let (code, fp_out, _) = run(Command::new("ssh-keygen").args(["-l", "-f", "-"]), Some(format!("{host} {key_type} {key}\n").as_bytes()), 10).await?;
    let fingerprint = fp_out.split_whitespace().nth(1).filter(|f| f.starts_with("SHA256:") && code == 0).ok_or("could not compute the fingerprint")?.to_string();

    let kh = ssh_dir().join("known_hosts");
    let status = if kh.exists() {
        let (_, found, _) = run(Command::new("ssh-keygen").args(["-F", &hostspec(host, port), "-f"]).arg(&kh), None, 10).await?;
        let pinned: Vec<&str> = found.lines().filter(|l| !l.starts_with('#')).filter_map(|l| l.split_whitespace().nth(2)).collect();
        if pinned.is_empty() {
            "new"
        } else if pinned.contains(&key.as_str()) {
            "trusted"
        } else {
            "changed"
        }
    } else {
        "new"
    };
    Ok(HostKey { key_type, key, fingerprint, status })
}

/// Pin a host key the person confirmed. Replaces any earlier pin for that host.
pub async fn trust(host: &str, port: u16, key_type: &str, key: &str) -> Result<(), String> {
    if !hostish(host) || port == 0 || !valid_key(key_type, key) {
        return Err("invalid server or key".into());
    }
    let dir = ssh_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let kh = dir.join("known_hosts");
    let spec = hostspec(host, port);
    if kh.exists() {
        let _ = run(Command::new("ssh-keygen").args(["-R", &spec, "-f"]).arg(&kh), None, 10).await;
        let _ = std::fs::remove_file(kh.with_extension("old"));
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&kh).map_err(|e| format!("cannot write known hosts: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    writeln!(f, "{spec} {key_type} {key}").map_err(|e| format!("cannot write known hosts: {e}"))
}

/// The script a person runs once, as root, on the server. Short enough to
/// read. It lets the vault's key run exactly one helper, and that helper will
/// only set passwords for accounts listed in /etc/jaword-rotate/accounts.
pub fn server_script(account: &str, pubkey: &str) -> Result<String, String> {
    if !valid_account(account) {
        return Err("that account name is not valid".into());
    }
    let mut parts = pubkey.split_whitespace();
    let (t, k) = match (parts.next(), parts.next()) {
        (Some(t), Some(k)) if valid_key(t, k) => (t, k),
        _ => return Err("invalid public key".into()),
    };
    Ok(format!(
        r#"# Lets the jaword vault set the password of the account "{account}"
# on this server, and nothing else: no shell, no other accounts.
# Run once, as root. Safe to run again.
set -eu

install -d -m 755 /etc/jaword-rotate
touch /etc/jaword-rotate/accounts
grep -qx -- '{account}' /etc/jaword-rotate/accounts || echo '{account}' >> /etc/jaword-rotate/accounts

cat > /usr/local/sbin/jaword-chpasswd <<'HELPER'
#!/bin/sh
# Reads one "account:password" line and sets it, only for allowed accounts.
set -eu
IFS= read -r line || [ -n "$line" ]
user=${{line%%:*}}
rest=${{line#*:}}
[ "$user" != "$line" ] && [ -n "$rest" ] || {{ echo "bad input" >&2; exit 2; }}
if [ "$user" = "jaword-test" ]; then
  # The vault's test: checks access, changes nothing.
  grep -qx -- "$rest" /etc/jaword-rotate/accounts || {{ echo "user not allowed" >&2; exit 2; }}
  id "$rest" >/dev/null 2>&1 || {{ echo "no such account" >&2; exit 3; }}
  echo "ok"; exit 0
fi
grep -qx -- "$user" /etc/jaword-rotate/accounts || {{ echo "user not allowed" >&2; exit 2; }}
printf '%s\n' "$line" | /usr/sbin/chpasswd
HELPER
chmod 755 /usr/local/sbin/jaword-chpasswd

install -d -m 700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
grep -qF -- '{k}' /root/.ssh/authorized_keys || \
  echo 'restrict,command="/usr/local/sbin/jaword-chpasswd" {t} {k} jaword-vault' >> /root/.ssh/authorized_keys

echo "jaword: this server now accepts password changes for {account}"
"#
    ))
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Checks {
    pub reached: bool,
    pub identity: bool,
    pub signed_in: bool,
    pub allowed: bool,
    /// What to do about the first failed check; empty when all passed.
    pub message: String,
}

/// Turn ssh's exit code and output into the four checks the UI shows.
pub fn classify(code: i32, stdout: &str, stderr: &str) -> Checks {
    let all = |r, i, s, a, m: &str| Checks { reached: r, identity: i, signed_in: s, allowed: a, message: m.to_string() };
    let e = stderr.to_ascii_lowercase();
    if code == 0 && stdout.trim() == "ok" {
        return all(true, true, true, true, "");
    }
    if e.contains("could not resolve") || e.contains("connection refused") || e.contains("timed out") || e.contains("no route to host") || e.contains("network is unreachable") {
        return all(false, false, false, false, "The vault could not reach that server. Check the name, and that it is switched on and on the same network.");
    }
    if e.contains("host key verification failed") || e.contains("identification has changed") || e.contains("host key is known") {
        return all(true, false, false, false, "The server's identity is not trusted yet, or has changed. Confirm it in step 1.");
    }
    if e.contains("permission denied") {
        return all(true, true, false, false, "The server did not accept the vault's key. Run the script from step 2 on the server.");
    }
    if e.contains("user not allowed") {
        return all(true, true, true, false, "The server accepts the vault, but not for this account. Run the script from step 2 again for this account.");
    }
    if e.contains("no such account") {
        return all(true, true, true, false, "That account does not exist on the server.");
    }
    if e.contains("bad input") {
        return all(true, true, true, false, "The server has an older helper. Run the script from step 2 again to update it.");
    }
    all(true, true, code != 255, false, "The server answered in an unexpected way. Run the script from step 2 again.")
}

/// Prove the whole path works, without changing any password.
pub async fn test(host: &str, port: u16, account: &str) -> Result<Checks, String> {
    if !hostish(host) || port == 0 || !valid_account(account) {
        return Err("invalid server or account".into());
    }
    let mut cmd = Command::new("ssh");
    cmd.args(ssh_args(port, "root", host)).arg("chpasswd");
    match run(&mut cmd, Some(format!("jaword-test:{account}\n").as_bytes()), 25).await {
        Ok((code, out, err)) => Ok(classify(code, &out, &err)),
        Err(e) if e == "timed out" => Ok(classify(255, "", "connection timed out")),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDTx7BPH3Ge1DtVH8cPucMPFyGzSGJpEPNirP+LaE6FB";

    #[test]
    fn account_names() {
        for ok in ["root", "jaword-demo", "svc_app1", "_apt"] {
            assert!(valid_account(ok), "{ok}");
        }
        for bad in ["", "Root", "a b", "a;id", "a'b", "$(id)", "a\nb", "-x", "1abc", "a/b", "é", &"a".repeat(33)] {
            assert!(!valid_account(bad), "{bad:?}");
        }
    }

    #[test]
    fn script_embeds_only_validated_values() {
        let s = server_script("jaword-demo", KEY).unwrap();
        assert!(s.contains("grep -qx -- 'jaword-demo' /etc/jaword-rotate/accounts"));
        assert!(s.contains("restrict,command=\"/usr/local/sbin/jaword-chpasswd\" ssh-ed25519 AAAAC3"));
        assert!(s.contains("user=${line%%:*}"), "shell braces must survive formatting");
        assert!(server_script("x'; rm -rf /; '", KEY).is_err());
        assert!(server_script("ok", "ssh-ed25519 AAAA' ; id #").is_err());
        assert!(server_script("ok", "not-a-key").is_err());
    }

    #[test]
    fn the_generated_helper_enforces_its_allowlist() {
        // Run the helper from the script locally with a stand-in for chpasswd.
        let dir = std::env::temp_dir().join(format!("jaword-helper-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = server_script("alice", KEY).unwrap();
        let helper = script.split("<<'HELPER'\n").nth(1).unwrap().split("\nHELPER\n").next().unwrap();
        let helper = helper
            .replace("/etc/jaword-rotate/accounts", dir.join("accounts").to_str().unwrap())
            .replace("/usr/sbin/chpasswd", &format!("tee {}", dir.join("applied").to_str().unwrap()))
            .replace("id \"$rest\" >/dev/null 2>&1", "true");
        std::fs::write(dir.join("helper.sh"), helper).unwrap();
        std::fs::write(dir.join("accounts"), "alice\n").unwrap();
        let run = |input: &str| {
            use std::io::Write;
            let mut c = std::process::Command::new("/bin/sh").arg(dir.join("helper.sh")).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
            c.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
            let o = c.wait_with_output().unwrap();
            (o.status.code().unwrap(), String::from_utf8_lossy(&o.stdout).trim().to_string(), String::from_utf8_lossy(&o.stderr).trim().to_string())
        };
        assert_eq!(run("jaword-test:alice\n"), (0, "ok".into(), "".into()));
        assert!(!dir.join("applied").exists(), "the test must not change anything");
        assert_eq!(run("jaword-test:root\n").0, 2);
        assert_eq!(run("root:hunter2hunter2\n").2, "user not allowed");
        assert_eq!(run("alice:\n").2, "bad input");
        assert_eq!(run("no-colon\n").2, "bad input");
        assert_eq!(run("alice:S3cret!value\n").0, 0);
        assert_eq!(std::fs::read_to_string(dir.join("applied")).unwrap(), "alice:S3cret!value\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn classification() {
        assert_eq!(classify(0, "ok\n", ""), Checks { reached: true, identity: true, signed_in: true, allowed: true, message: String::new() });
        assert!(!classify(255, "", "ssh: Could not resolve hostname nope: nodename nor servname provided").reached);
        let c = classify(255, "", "Host key verification failed.");
        assert!(c.reached && !c.identity);
        let c = classify(255, "", "root@h: Permission denied (publickey).");
        assert!(c.identity && !c.signed_in);
        let c = classify(2, "", "user not allowed");
        assert!(c.signed_in && !c.allowed);
        // A password change that "succeeds" is never mistaken for a passed test.
        assert!(!classify(0, "", "").allowed);
        assert!(!classify(0, "something else", "").allowed);
    }

    #[test]
    fn host_specs() {
        assert_eq!(hostspec("pve", 22), "pve");
        assert_eq!(hostspec("pve", 2222), "[pve]:2222");
    }
}
