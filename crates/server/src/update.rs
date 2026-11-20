//! Self-update, server side.
//!
//! The vault process is unprivileged and sandboxed: it cannot replace its own
//! binary. All it does is drop a small request file. A separate root helper
//! (`deploy/jaword-updater`) downloads the release, verifies its signature
//! against the pinned release key, installs it, and rolls back if the new
//! version does not start.
//!
//! The helper trusts nothing this process writes except "which version was
//! asked for", and it validates even that. A fully compromised vault process
//! therefore still cannot install unsigned code.

use serde_json::{json, Value};
use std::path::PathBuf;

pub struct Updater {
    dir: PathBuf,
    status: PathBuf,
    signers: PathBuf,
}

/// Strictly `vMAJOR.MINOR.PATCH`, nothing else, so it is safe in file names
/// and URLs and compares cleanly.
pub fn valid_version(v: &str) -> bool {
    let Some(rest) = v.strip_prefix('v') else { return false };
    let parts: Vec<&str> = rest.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()))
}

impl Updater {
    pub fn from_env() -> Updater {
        let get = |k: &str, d: &str| PathBuf::from(std::env::var(k).unwrap_or_else(|_| d.to_string()));
        Updater {
            dir: get("JAWORD_UPDATE_DIR", "/var/lib/jaword/update"),
            status: get("JAWORD_UPDATE_STATUS", "/run/jaword-update/status.json"),
            signers: get("JAWORD_UPDATE_SIGNERS", "/etc/jaword/release_signers"),
        }
    }

    /// Updates are off until a release signing key has been installed.
    pub fn enabled(&self) -> bool {
        std::fs::metadata(&self.signers).map(|m| m.is_file() && m.len() > 0).unwrap_or(false)
    }

    pub fn status(&self) -> Value {
        let helper = std::fs::read(&self.status)
            .ok()
            .filter(|b| b.len() <= 4096)
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .unwrap_or(Value::Null);
        json!({
            "current": concat!("v", env!("CARGO_PKG_VERSION")),
            "enabled": self.enabled(),
            "pending_request": self.dir.join("request.json").exists(),
            "helper": helper,
        })
    }

    pub fn request(&self, action: &str, version: Option<&str>) -> Result<(), String> {
        if !self.enabled() {
            return Err("updates are disabled: no release signing key is installed on the vault host".into());
        }
        let body = match (action, version) {
            ("check", None) => json!({"action": "check"}),
            ("apply", Some(v)) if valid_version(v) => json!({"action": "apply", "version": v}),
            ("apply", _) => return Err("apply needs a version like v0.2.0".into()),
            _ => return Err("action must be check or apply".into()),
        };
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("update dir: {e}"))?;
        let tmp = self.dir.join(".request.tmp");
        std::fs::write(&tmp, body.to_string()).map_err(|e| format!("write request: {e}"))?;
        std::fs::rename(&tmp, self.dir.join("request.json")).map_err(|e| format!("write request: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_strings() {
        for ok in ["v0.1.0", "v12.34.56", "v0.0.99999"] {
            assert!(valid_version(ok), "{ok}");
        }
        for bad in ["0.1.0", "v1.2", "v1.2.3.4", "v1.2.x", "v1.2.3-rc1", "v1.2.3/../x", "v1..3", "v1.2.3 ", "v1.2.3;id", "v123456.1.1", "", "v"] {
            assert!(!valid_version(bad), "{bad:?}");
        }
    }

    #[test]
    fn disabled_without_signers_and_request_format() {
        let d = std::env::temp_dir().join(format!("jaword-upd-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let mut u = Updater { dir: d.join("update"), status: d.join("status.json"), signers: d.join("signers") };
        assert!(!u.enabled());
        assert!(u.request("check", None).is_err());
        std::fs::write(&u.signers, "jaword-release ssh-ed25519 AAAA\n").unwrap();
        assert!(u.enabled());
        assert!(u.request("apply", Some("v1.0.0; rm -rf /")).is_err());
        assert!(u.request("apply", None).is_err());
        assert!(u.request("install", None).is_err());
        u.request("apply", Some("v0.2.0")).unwrap();
        // Exact, space-free form the root helper parses.
        assert_eq!(std::fs::read_to_string(u.dir.join("request.json")).unwrap(), r#"{"action":"apply","version":"v0.2.0"}"#);
        assert_eq!(u.status()["pending_request"], true);
        u.status = d.join("missing.json");
        assert!(u.status()["helper"].is_null());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
