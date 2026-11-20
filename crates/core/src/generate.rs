//! Secret generation from the OS CSPRNG with unbiased sampling.

use crate::crypto::{fill_random, CryptoError};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
/// Conservative default symbol set: safe in shells, YAML, URLs and most
/// password forms without quoting surprises.
const SYMBOLS: &str = "!@#%^*-_=+";
const AMBIGUOUS: &str = "Il1O0o";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Policy {
    /// Character-class password.
    Password {
        #[serde(default = "d_len")]
        length: usize,
        #[serde(default = "d_true")]
        lower: bool,
        #[serde(default = "d_true")]
        upper: bool,
        #[serde(default = "d_true")]
        digits: bool,
        /// `None` = default symbol set, `Some("")` = no symbols.
        #[serde(default)]
        symbols: Option<String>,
        #[serde(default)]
        exclude_ambiguous: bool,
    },
    /// Random bytes, hex encoded (`bytes` of entropy).
    Hex {
        #[serde(default = "d_bytes")]
        bytes: usize,
    },
    /// Random bytes, base64url (no padding).
    Base64url {
        #[serde(default = "d_bytes")]
        bytes: usize,
    },
    /// Random dictionary words: easier to read aloud and type than symbols.
    Words {
        #[serde(default = "d_words")]
        words: usize,
        /// Between words: "" (run together), "-", ".", " " or "_".
        #[serde(default = "d_sep")]
        separator: String,
        #[serde(default = "d_true")]
        capitalize: bool,
        /// Append one random digit to one of the words, for sites that insist on a number.
        #[serde(default)]
        number: bool,
    },
}

/// The EFF large word list: 7,776 words, about 12.9 bits each.
pub const WORDLIST: &str = include_str!("wordlist.txt");
pub const WORDS_MIN: usize = 4;
pub const WORDS_MAX: usize = 10;

fn wordlist() -> &'static [&'static str] {
    static LIST: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| WORDLIST.lines().filter(|l| !l.is_empty()).collect())
}

fn d_words() -> usize {
    5
}
fn d_sep() -> String {
    "-".into()
}

fn d_len() -> usize {
    32
}
fn d_true() -> bool {
    true
}
fn d_bytes() -> usize {
    32
}

impl Default for Policy {
    fn default() -> Self {
        Policy::Password {
            length: 32,
            lower: true,
            upper: true,
            digits: true,
            symbols: None,
            exclude_ambiguous: false,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GenError {
    #[error("invalid generation policy: {0}")]
    Policy(&'static str),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Uniform integer in `0..n` by rejection sampling (no modulo bias).
fn uniform(n: u32) -> Result<u32, CryptoError> {
    debug_assert!(n > 0);
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let mut b = [0u8; 4];
        fill_random(&mut b)?;
        let v = u32::from_le_bytes(b);
        if v < zone {
            return Ok(v % n);
        }
    }
}

pub fn generate(policy: &Policy) -> Result<Zeroizing<String>, GenError> {
    match policy {
        Policy::Hex { bytes } => {
            check_bytes(*bytes)?;
            let raw = Zeroizing::new(crate::crypto::random_bytes(*bytes)?);
            let mut s = Zeroizing::new(String::with_capacity(bytes * 2));
            for b in raw.iter() {
                s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
                s.push(char::from_digit((b & 15) as u32, 16).unwrap());
            }
            Ok(s)
        }
        Policy::Base64url { bytes } => {
            check_bytes(*bytes)?;
            let raw = Zeroizing::new(crate::crypto::random_bytes(*bytes)?);
            Ok(Zeroizing::new(b64url(&raw)))
        }
        Policy::Words { words, separator, capitalize, number } => {
            if !(WORDS_MIN..=WORDS_MAX).contains(words) {
                return Err(GenError::Policy("words must be 4..=10"));
            }
            if !matches!(separator.as_str(), "" | "-" | "." | " " | "_") {
                return Err(GenError::Policy("separator must be empty, dash, dot, space or underscore"));
            }
            let list = wordlist();
            let digit_at = if *number { Some(uniform(*words as u32)? as usize) } else { None };
            let mut out = Zeroizing::new(String::new());
            for i in 0..*words {
                if i > 0 {
                    out.push_str(separator);
                }
                let w = list[uniform(list.len() as u32)? as usize];
                let mut chars = w.chars();
                match (chars.next(), *capitalize) {
                    (Some(first), true) => {
                        out.extend(first.to_uppercase());
                        out.push_str(chars.as_str());
                    }
                    _ => out.push_str(w),
                }
                if digit_at == Some(i) {
                    out.push(char::from_digit(uniform(10)?, 10).expect("0..10 is a digit"));
                }
            }
            Ok(out)
        }
        Policy::Password { length, lower, upper, digits, symbols, exclude_ambiguous } => {
            if *length < 12 || *length > 256 {
                return Err(GenError::Policy("length must be 12..=256"));
            }
            let sym = symbols.as_deref().unwrap_or(SYMBOLS);
            if sym.len() > 64 || !sym.chars().all(|c| c.is_ascii_punctuation()) {
                return Err(GenError::Policy("symbols must be ASCII punctuation, max 64"));
            }
            let mut classes: Vec<Vec<char>> = Vec::new();
            for (on, set) in [(*lower, LOWER), (*upper, UPPER), (*digits, DIGITS), (true, sym)] {
                if !on {
                    continue;
                }
                let mut chars: Vec<char> = set
                    .chars()
                    .filter(|c| !(*exclude_ambiguous && AMBIGUOUS.contains(*c)))
                    .collect();
                chars.sort_unstable();
                chars.dedup();
                if !chars.is_empty() {
                    classes.push(chars);
                }
            }
            let all: Vec<char> = classes.iter().flatten().copied().collect();
            if all.len() < 10 {
                return Err(GenError::Policy("character set too small"));
            }
            // One guaranteed character from every enabled class, the rest from
            // the full set, then a Fisher-Yates shuffle so positions are uniform.
            let mut out: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(*length));
            for c in &classes {
                out.push(c[uniform(c.len() as u32)? as usize]);
            }
            while out.len() < *length {
                out.push(all[uniform(all.len() as u32)? as usize]);
            }
            for i in (1..out.len()).rev() {
                let j = uniform(i as u32 + 1)? as usize;
                out.swap(i, j);
            }
            Ok(Zeroizing::new(out.iter().collect()))
        }
    }
}

fn check_bytes(n: usize) -> Result<(), GenError> {
    if !(16..=512).contains(&n) {
        return Err(GenError::Policy("bytes must be 16..=512"));
    }
    Ok(())
}

fn b64url(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::with_capacity(data.len() * 4 / 3 + 3);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            s.push(T[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            s.push(T[n as usize & 63] as char);
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_password_has_all_classes() {
        for _ in 0..200 {
            let p = generate(&Policy::default()).unwrap();
            assert_eq!(p.chars().count(), 32);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn no_symbols_and_no_ambiguous() {
        let pol = Policy::Password {
            length: 40,
            lower: true,
            upper: true,
            digits: true,
            symbols: Some(String::new()),
            exclude_ambiguous: true,
        };
        for _ in 0..100 {
            let p = generate(&pol).unwrap();
            assert!(p.chars().all(|c| c.is_ascii_alphanumeric() && !AMBIGUOUS.contains(c)));
        }
    }

    #[test]
    fn rejects_weak_policies() {
        let short = Policy::Password {
            length: 6,
            lower: true,
            upper: true,
            digits: true,
            symbols: None,
            exclude_ambiguous: false,
        };
        assert!(generate(&short).is_err());
        let tiny = Policy::Password {
            length: 20,
            lower: false,
            upper: false,
            digits: false,
            symbols: Some("!".into()),
            exclude_ambiguous: false,
        };
        assert!(generate(&tiny).is_err());
        assert!(generate(&Policy::Hex { bytes: 4 }).is_err());
    }

    #[test]
    fn outputs_differ_and_encode_correctly() {
        let a = generate(&Policy::Hex { bytes: 32 }).unwrap();
        let b = generate(&Policy::Hex { bytes: 32 }).unwrap();
        assert_eq!(a.len(), 64);
        assert_ne!(*a, *b);
        assert_eq!(b64url(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(generate(&Policy::Base64url { bytes: 32 }).unwrap().len(), 43);
    }

    #[test]
    fn word_passwords() {
        assert_eq!(wordlist().len(), 7776);
        assert!(wordlist().iter().all(|w| w.len() >= 3 && w.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')));
        let pol = |words, sep: &str, cap, num| Policy::Words { words, separator: sep.into(), capitalize: cap, number: num };
        for _ in 0..50 {
            let p = generate(&pol(5, " ", false, false)).unwrap();
            let parts: Vec<&str> = p.split(' ').collect();
            assert_eq!(parts.len(), 5);
            assert!(parts.iter().all(|w| wordlist().contains(w)), "{}", p.as_str());
        }
        let p = generate(&pol(6, "", true, true)).unwrap();
        assert_eq!(p.chars().filter(|c| c.is_ascii_uppercase()).count(), 6);
        assert_eq!(p.chars().filter(|c| c.is_ascii_digit()).count(), 1);
        assert_ne!(*generate(&pol(4, "-", true, false)).unwrap(), *generate(&pol(4, "-", true, false)).unwrap());
        assert!(generate(&pol(3, "-", true, false)).is_err());
        assert!(generate(&pol(11, "-", true, false)).is_err());
        assert!(generate(&pol(5, "; rm", true, false)).is_err());
        // Stored form, and defaults for anything left out.
        let j: Policy = serde_json::from_str(r#"{"type":"words"}"#).unwrap();
        assert_eq!(j, pol(5, "-", true, false));
    }

    #[test]
    fn uniform_is_roughly_flat() {
        let mut counts = [0u32; 7];
        for _ in 0..70_000 {
            counts[uniform(7).unwrap() as usize] += 1;
        }
        for c in counts {
            assert!((9_000..11_000).contains(&c), "bucket {c} far from 10000");
        }
    }
}
