//! Payment cards and gift cards.
//!
//! The secret half (card number, security code, gift card PIN) is stored as
//! the item's value, a small JSON object, and is encrypted and versioned
//! exactly like a password. The descriptive half (brand, last four digits,
//! expiry, balance) lives in the metadata so people and agents can pick the
//! right card without ever seeing the number.
//!
//! The vault, not the client, derives the brand and last four digits from the
//! number, and owns the gift card ledger: a client cannot claim a different
//! card or rewrite the spending history through a metadata update.

use serde::{Deserialize, Serialize};

pub const CARD: &str = "card";
pub const GIFT_CARD: &str = "gift_card";
pub const MAX_LEDGER: usize = 2000;
/// Ten million in the card's currency; anything larger is a typo.
pub const MAX_CENTS: i64 = 1_000_000_000;

pub fn is_card_kind(kind: &str) -> bool {
    kind == CARD || kind == GIFT_CARD
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CardInfo {
    /// Set by the vault from the card number.
    #[serde(default)]
    pub brand: String,
    /// Set by the vault from the card number.
    #[serde(default)]
    pub last4: String,
    /// 1..=12, or 0 when not recorded.
    #[serde(default)]
    pub exp_month: u8,
    /// Four digits, or 0 when not recorded.
    #[serde(default)]
    pub exp_year: u16,
    #[serde(default)]
    pub holder: String,
    #[serde(default)]
    pub zip: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub at: i64,
    /// Negative for money spent, positive for money added.
    pub cents: i64,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub by: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct GiftInfo {
    #[serde(default)]
    pub merchant: String,
    /// Set by the vault from the card number.
    #[serde(default)]
    pub last4: String,
    #[serde(default)]
    pub initial_cents: i64,
    /// Owned by the vault: changed only through `Vault::ledger_add`.
    #[serde(default)]
    pub ledger: Vec<Entry>,
}

impl GiftInfo {
    pub fn balance(&self) -> i64 {
        self.ledger.iter().fold(self.initial_cents, |sum, e| sum.saturating_add(e.cents))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CardValue {
    number: String,
    #[serde(default)]
    cvv: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GiftValue {
    number: String,
    #[serde(default)]
    pin: String,
}

/// What the vault learns from a card value without keeping the number.
#[derive(Debug, PartialEq)]
pub struct Facts {
    pub last4: String,
    pub brand: String,
}

fn last4(number: &str) -> String {
    let n = number.len();
    number[n.saturating_sub(4)..].to_string()
}

/// Card network from the leading digits. Only the well-known ranges.
pub fn brand(number: &str) -> &'static str {
    let lead = |n: usize| number.get(..n).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    match () {
        _ if number.starts_with('4') => "Visa",
        _ if (51..=55).contains(&lead(2)) || (2221..=2720).contains(&lead(4)) => "Mastercard",
        _ if matches!(lead(2), 34 | 37) => "American Express",
        _ if lead(4) == 6011 || lead(2) == 65 || (644..=649).contains(&lead(3)) => "Discover",
        _ if (3528..=3589).contains(&lead(4)) => "JCB",
        _ if matches!(lead(2), 36 | 38) || (300..=305).contains(&lead(3)) => "Diners Club",
        _ => "Card",
    }
}

/// Check a card or gift card value and return what may be shown about it.
/// The error text never repeats any part of the value.
pub fn inspect(kind: &str, value: &str) -> Result<Facts, &'static str> {
    match kind {
        CARD => {
            let v: CardValue = serde_json::from_str(value).map_err(|_| "card details are not in the expected form")?;
            if !(12..=19).contains(&v.number.len()) || !v.number.bytes().all(|b| b.is_ascii_digit()) {
                return Err("card number must be 12 to 19 digits");
            }
            if !(v.cvv.is_empty() || ((3..=4).contains(&v.cvv.len()) && v.cvv.bytes().all(|b| b.is_ascii_digit()))) {
                return Err("security code must be 3 or 4 digits");
            }
            Ok(Facts { last4: last4(&v.number), brand: brand(&v.number).to_string() })
        }
        GIFT_CARD => {
            let v: GiftValue = serde_json::from_str(value).map_err(|_| "gift card details are not in the expected form")?;
            if !(4..=64).contains(&v.number.len()) || !v.number.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err("gift card number must be 4 to 64 letters, digits or dashes");
            }
            if v.pin.len() > 32 || !v.pin.bytes().all(|b| b.is_ascii_graphic()) {
                return Err("gift card PIN must be at most 32 characters with no spaces");
            }
            Ok(Facts { last4: last4(&v.number), brand: String::new() })
        }
        _ => Err("not a card"),
    }
}

pub fn validate_card(c: &CardInfo) -> Result<(), &'static str> {
    if c.exp_month > 12 || !(c.exp_year == 0 || (2000..=2100).contains(&c.exp_year)) {
        return Err("expiry date is not valid");
    }
    if (c.exp_month == 0) != (c.exp_year == 0) {
        return Err("expiry needs both a month and a year");
    }
    if c.holder.len() > 100 || c.zip.len() > 16 {
        return Err("card field too long");
    }
    Ok(())
}

pub fn validate_gift(g: &GiftInfo) -> Result<(), &'static str> {
    if g.merchant.len() > 100 {
        return Err("store name too long");
    }
    if !(0..=MAX_CENTS).contains(&g.initial_cents) {
        return Err("starting balance is out of range");
    }
    Ok(())
}

/// "12.34" from 1234, for messages.
pub fn money(cents: i64) -> String {
    format!("{}{}.{:02}", if cents < 0 { "-" } else { "" }, cents.abs() / 100, cents.abs() % 100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brands() {
        assert_eq!(brand("4111111111111111"), "Visa");
        assert_eq!(brand("5555555555554444"), "Mastercard");
        assert_eq!(brand("2223003122003222"), "Mastercard");
        assert_eq!(brand("378282246310005"), "American Express");
        assert_eq!(brand("6011111111111117"), "Discover");
        assert_eq!(brand("3530111333300000"), "JCB");
        assert_eq!(brand("9999999999999999"), "Card");
    }

    #[test]
    fn inspects_without_echoing() {
        let f = inspect(CARD, r#"{"number":"4111111111111111","cvv":"123"}"#).unwrap();
        assert_eq!(f, Facts { last4: "1111".into(), brand: "Visa".into() });
        assert!(inspect(CARD, r#"{"number":"4111111111111111"}"#).is_ok());
        for bad in [
            r#"{"number":"4111 1111 1111 1111"}"#,
            r#"{"number":"411111"}"#,
            r#"{"number":"4111111111111111","cvv":"12"}"#,
            r#"{"number":"4111111111111111","extra":1}"#,
            "4111111111111111",
        ] {
            let e = inspect(CARD, bad).unwrap_err();
            assert!(!e.contains("4111"), "{e}");
        }
        let g = inspect(GIFT_CARD, r#"{"number":"ABCD-1234-XYZ9","pin":"8842"}"#).unwrap();
        assert_eq!(g.last4, "XYZ9");
        assert!(inspect(GIFT_CARD, r#"{"number":"AB"}"#).is_err());
        assert!(inspect(GIFT_CARD, r#"{"number":"ABCD1234","pin":"12 34"}"#).is_err());
        assert!(inspect("password", "x").is_err());
    }

    #[test]
    fn balance_and_money() {
        let mut g = GiftInfo { initial_cents: 5000, ..Default::default() };
        g.ledger.push(Entry { at: 1, cents: -1234, ..Default::default() });
        g.ledger.push(Entry { at: 2, cents: 500, ..Default::default() });
        assert_eq!(g.balance(), 4266);
        assert_eq!(money(4266), "42.66");
        assert_eq!(money(-5), "-0.05");
        assert!(validate_gift(&GiftInfo { initial_cents: -1, ..Default::default() }).is_err());
        assert!(validate_card(&CardInfo { exp_month: 13, exp_year: 2030, ..Default::default() }).is_err());
        assert!(validate_card(&CardInfo { exp_month: 8, exp_year: 0, ..Default::default() }).is_err());
        assert!(validate_card(&CardInfo { exp_month: 8, exp_year: 2029, ..Default::default() }).is_ok());
    }
}
