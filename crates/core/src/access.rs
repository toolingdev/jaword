//! Secret path validation and capability policy matching.

use serde::{Deserialize, Serialize};

pub const MAX_PATH_LEN: usize = 200;
/// Fixed address the `upgrade` capability is granted on.
pub const SYS_UPDATE: &str = "sys/update";

/// `sys` is kept for the vault's own addresses; no item or folder may live there.
pub fn reserved(path: &str) -> bool {
    path == "sys" || path.starts_with("sys/")
}

/// Paths look like `home-lab/proxmox-root`: lowercase segments of `[a-z0-9._-]`,
/// each starting with an alphanumeric. No traversal, no empty segments.
pub fn valid_path(p: &str) -> bool {
    if p.is_empty() || p.len() > MAX_PATH_LEN {
        return false;
    }
    p.split('/').all(|seg| {
        let mut ch = seg.chars();
        match ch.next() {
            Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
            _ => return false,
        }
        seg.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
            && !seg.contains("..")
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cap {
    /// See that a secret exists and read its metadata and history.
    List,
    Create,
    /// Edit metadata (username, url, notes, tags, generation policy).
    Update,
    /// Store a caller-supplied value. Whoever holds this knows that value,
    /// so agents normally get `generate`/`rotate` instead.
    Write,
    /// Have the vault generate a new version (value is never returned).
    Generate,
    /// Run the secret's rotation driver.
    Rotate,
    /// Read plaintext. Never grantable to agent tokens.
    Reveal,
    Delete,
    /// Ask the vault to check for or install a signed release. Granted on
    /// the fixed path `sys/update`. The signature, not this capability, is
    /// what decides whether code is accepted.
    Upgrade,
}

impl Cap {
    pub fn parse(s: &str) -> Option<Cap> {
        Some(match s {
            "list" => Cap::List,
            "create" => Cap::Create,
            "update" => Cap::Update,
            "write" => Cap::Write,
            "generate" => Cap::Generate,
            "rotate" => Cap::Rotate,
            "reveal" => Cap::Reveal,
            "delete" => Cap::Delete,
            "upgrade" => Cap::Upgrade,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Full control, including tokens, drivers, audit, seal.
    Admin,
    /// A person with scoped access; may hold `reveal`.
    Human,
    /// An automated agent; can never reveal plaintext or administer.
    Agent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Glob: `*` matches one segment, a trailing `**` matches any remainder.
    pub path: String,
    pub caps: Vec<Cap>,
}

pub fn valid_pattern(p: &str) -> bool {
    if p.is_empty() || p.len() > MAX_PATH_LEN {
        return false;
    }
    let segs: Vec<&str> = p.split('/').collect();
    segs.iter().enumerate().all(|(i, s)| match *s {
        "**" => i == segs.len() - 1,
        "*" => true,
        other => valid_path(other),
    })
}

pub fn pattern_matches(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').collect();
    let segs: Vec<&str> = path.split('/').collect();
    for (i, p) in pat.iter().enumerate() {
        if *p == "**" {
            return i == pat.len() - 1 && segs.len() > i;
        }
        match segs.get(i) {
            Some(s) if *p == "*" || p == s => {}
            _ => return false,
        }
    }
    pat.len() == segs.len()
}

/// Central authorization decision. Default deny.
pub fn allowed(role: Role, rules: &[Rule], cap: Cap, path: &str) -> bool {
    if !valid_path(path) {
        return false;
    }
    match role {
        Role::Admin => true,
        Role::Agent if cap == Cap::Reveal => false,
        _ => rules
            .iter()
            .any(|r| r.caps.contains(&cap) && pattern_matches(&r.path, path)),
    }
}

/// Validate a rule set before it is stored on a token.
pub fn validate_rules(role: Role, rules: &[Rule]) -> Result<(), &'static str> {
    if rules.len() > 64 {
        return Err("too many rules");
    }
    for r in rules {
        if !valid_pattern(&r.path) {
            return Err("invalid path pattern");
        }
        if r.caps.is_empty() {
            return Err("rule has no capabilities");
        }
        if role == Role::Agent && r.caps.contains(&Cap::Reveal) {
            return Err("agent tokens cannot hold reveal");
        }
        // `upgrade` is a vault-wide power, so it is only ever granted on its
        // own fixed address and never rides along with a folder rule.
        let on_sys = r.path == SYS_UPDATE;
        if r.caps.contains(&Cap::Upgrade) != on_sys || (on_sys && r.caps.len() != 1) {
            return Err("the upgrade permission is granted on sys/update, on its own");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_validation() {
        for ok in ["a", "infra/pve/root", "db/prod-1/app_user", "x/1.2/y"] {
            assert!(valid_path(ok), "{ok}");
        }
        for bad in [
            "", "/a", "a/", "a//b", "../a", "a/../b", "a/..", "A/b", "a b", "a/.b", "a/-b",
            "a\0b", "a/b?x", "a/%2e%2e", "a\\b", "a/b..c", "é",
        ] {
            assert!(!valid_path(bad), "{bad:?}");
        }
        assert!(!valid_path(&"a".repeat(201)));
    }

    #[test]
    fn globbing() {
        assert!(pattern_matches("infra/**", "infra/pve/root"));
        assert!(pattern_matches("infra/**", "infra/x"));
        assert!(!pattern_matches("infra/**", "infra"));
        assert!(!pattern_matches("infra/**", "infrared/x"));
        assert!(pattern_matches("infra/*/root", "infra/pve/root"));
        assert!(!pattern_matches("infra/*/root", "infra/pve/sub/root"));
        assert!(!pattern_matches("infra/*", "infra/pve/root"));
        assert!(pattern_matches("**", "anything/at/all"));
        assert!(pattern_matches("a/b", "a/b"));
        assert!(!pattern_matches("a/b", "a/b/c"));
        assert!(!pattern_matches("a/b/c", "a/b"));
        assert!(valid_pattern("infra/*/x/**"));
        assert!(!valid_pattern("infra/**/x"));
        assert!(!valid_pattern("infra/a*"));
    }

    #[test]
    fn authorization() {
        let rules = vec![Rule { path: "infra/**".into(), caps: vec![Cap::List, Cap::Rotate, Cap::Reveal] }];
        assert!(allowed(Role::Human, &rules, Cap::Reveal, "infra/pve/root"));
        assert!(!allowed(Role::Human, &rules, Cap::Reveal, "office/nas"));
        assert!(!allowed(Role::Human, &rules, Cap::Delete, "infra/pve/root"));
        // Even if a rule somehow carries reveal, an agent is refused.
        assert!(!allowed(Role::Agent, &rules, Cap::Reveal, "infra/pve/root"));
        assert!(allowed(Role::Agent, &rules, Cap::Rotate, "infra/pve/root"));
        assert!(allowed(Role::Admin, &[], Cap::Reveal, "any/thing"));
        assert!(!allowed(Role::Admin, &[], Cap::Reveal, "../etc"));
        assert!(!allowed(Role::Agent, &[], Cap::List, "infra/x"));
        assert!(validate_rules(Role::Agent, &rules).is_err());
        assert!(validate_rules(Role::Human, &rules).is_ok());
        // Upgrade cannot be attached to a folder, or bundled with other powers.
        let up = |path: &str, caps: Vec<Cap>| validate_rules(Role::Agent, &[Rule { path: path.into(), caps }]);
        assert!(up("sys/update", vec![Cap::Upgrade]).is_ok());
        assert!(up("home-lab/**", vec![Cap::List, Cap::Upgrade]).is_err());
        assert!(up("**", vec![Cap::Upgrade]).is_err());
        assert!(up("sys/update", vec![Cap::Upgrade, Cap::List]).is_err());
        assert!(up("sys/update", vec![Cap::List]).is_err());
        assert!(reserved("sys") && reserved("sys/update") && !reserved("system/x") && !reserved("personal/sys"));
    }
}
