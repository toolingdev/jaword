//! People and addresses.
//!
//! An item of kind `identity` describes one person or one place: "Me, home",
//! "Me, work", a spouse, a relative. Contact details and the address are
//! metadata, readable by anyone who may list the item, because an agent has
//! to read them to use them. Identity numbers (a national ID, a passport, a
//! driving licence) are the sealed value: a small JSON object of
//! label -> number. Only the labels are shown without revealing.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const IDENTITY: &str = "identity";
pub const MAX_SEALED: usize = 12;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PersonInfo {
    #[serde(default)]
    pub full_name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub phone: String,
    /// YYYY-MM-DD, or empty.
    #[serde(default)]
    pub birthday: String,
    #[serde(default)]
    pub company: String,
    #[serde(default)]
    pub line1: String,
    #[serde(default)]
    pub line2: String,
    #[serde(default)]
    pub city: String,
    /// State, province or region.
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub postal: String,
    #[serde(default)]
    pub country: String,
    /// Labels of the sealed numbers, set by the vault from the value.
    #[serde(default)]
    pub sealed: Vec<String>,
}

/// The value stored for an identity that has no sealed numbers.
pub const EMPTY_VALUE: &str = "{}";

/// Check a sealed value and return its labels, sorted. The error text never
/// repeats a label or a number.
pub fn inspect(value: &str) -> Result<Vec<String>, &'static str> {
    let map: BTreeMap<String, String> =
        serde_json::from_str(value).map_err(|_| "private numbers are not in the expected form")?;
    if map.len() > MAX_SEALED {
        return Err("at most 12 private numbers per person");
    }
    for (label, number) in &map {
        let label_ok = !label.trim().is_empty() && label.len() <= 40 && !label.chars().any(|c| c.is_control());
        let number_ok = !number.is_empty() && number.len() <= 200 && !number.chars().any(|c| c.is_control());
        if !label_ok || !number_ok {
            return Err("each private number needs a short label and a one-line value");
        }
    }
    Ok(map.into_keys().collect())
}

fn valid_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let num = |r: std::ops::Range<usize>| s[r].parse::<u32>().ok();
    matches!((num(0..4), num(5..7), num(8..10)), (Some(y), Some(m), Some(d)) if (1900..=2100).contains(&y) && (1..=12).contains(&m) && (1..=31).contains(&d))
}

pub fn validate(p: &PersonInfo) -> Result<(), &'static str> {
    let fields = [&p.full_name, &p.email, &p.phone, &p.company, &p.line1, &p.line2, &p.city, &p.region, &p.postal, &p.country];
    if fields.iter().any(|f| f.len() > 200 || f.chars().any(|c| c.is_control())) {
        return Err("each detail must be one line of at most 200 characters");
    }
    if !(p.birthday.is_empty() || valid_date(&p.birthday)) {
        return Err("birthday must look like 1990-04-23");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_labels_without_echo() {
        assert_eq!(inspect(EMPTY_VALUE).unwrap(), Vec::<String>::new());
        let v = r#"{"Passport":"X1234567","Driver's license":"D7654321"}"#;
        assert_eq!(inspect(v).unwrap(), vec!["Driver's license".to_string(), "Passport".to_string()]);
        for bad in [r#"{"Passport":""}"#, r#"{"":"X1234567"}"#, r#"{"Passport":123}"#, r#"["X1234567"]"#, "X1234567", "{\"P\":\"a\\nb\"}"] {
            let e = inspect(bad).unwrap_err();
            assert!(!e.contains("X1234567") && !e.contains("Passport"), "{e}");
        }
        let many: BTreeMap<String, String> = (0..13).map(|i| (format!("n{i}"), "1".to_string())).collect();
        assert!(inspect(&serde_json::to_string(&many).unwrap()).is_err());
    }

    #[test]
    fn validates_details() {
        let ok = PersonInfo { full_name: "Test Person".into(), birthday: "1990-04-23".into(), ..Default::default() };
        assert!(validate(&ok).is_ok());
        assert!(validate(&PersonInfo::default()).is_ok());
        for bad in ["04/23/1990", "1990-13-01", "1990-04-32", "90-04-23"] {
            assert!(validate(&PersonInfo { birthday: bad.into(), ..Default::default() }).is_err(), "{bad}");
        }
        assert!(validate(&PersonInfo { city: "a\nb".into(), ..Default::default() }).is_err());
        assert!(validate(&PersonInfo { line1: "x".repeat(201), ..Default::default() }).is_err());
    }
}
