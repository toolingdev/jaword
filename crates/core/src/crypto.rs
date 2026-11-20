//! Cryptographic primitives for jaword.
//!
//! Everything here is a thin, misuse-resistant wrapper over vetted RustCrypto
//! implementations. No custom algorithms.
//!
//! * AEAD: XChaCha20-Poly1305 with a random 192-bit nonce per message.
//! * Passphrase KDF: Argon2id (v1.3).
//! * Key separation: HKDF-SHA256 with distinct labels.
//! * MAC: HMAC-SHA256.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as MacKeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const SALT_LEN: usize = 16;
/// Format byte prepended to every sealed blob, so algorithms can be migrated.
const BLOB_V1: u8 = 0x01;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("random source failure")]
    Random,
    #[error("decryption failed")]
    Decrypt,
    #[error("malformed ciphertext")]
    Malformed,
    #[error("invalid KDF parameters")]
    KdfParams,
    #[error("invalid key length")]
    KeyLen,
}

/// A 256-bit symmetric key, wiped from memory on drop. Never `Debug`/`Display`.
#[derive(Clone)]
pub struct Key([u8; KEY_LEN]);

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Key {
    pub fn random() -> Result<Self, CryptoError> {
        let mut k = [0u8; KEY_LEN];
        fill_random(&mut k)?;
        Ok(Key(k))
    }

    pub fn from_slice(b: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; KEY_LEN] = b.try_into().map_err(|_| CryptoError::KeyLen)?;
        Ok(Key(arr))
    }

    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Derive an independent sub-key for one purpose.
    pub fn subkey(&self, label: &str) -> Key {
        let hk = Hkdf::<Sha256>::new(Some(b"jaword/v1/subkey"), &self.0);
        let mut out = [0u8; KEY_LEN];
        hk.expand(label.as_bytes(), &mut out)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Key(out)
    }
}

pub fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buf).map_err(|_| CryptoError::Random)
}

pub fn random_bytes(n: usize) -> Result<Vec<u8>, CryptoError> {
    let mut v = vec![0u8; n];
    fill_random(&mut v)?;
    Ok(v)
}

/// Encrypt `plaintext`, binding it to `aad`.
/// Output: `version(1) || nonce(24) || ciphertext || tag(16)`.
pub fn seal(key: &Key, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let ct = cipher
        .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Malformed)?;
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(BLOB_V1);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a blob produced by [`seal`]. Fails if key, aad, or data differ.
pub fn open(key: &Key, aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if blob.len() < 1 + NONCE_LEN + TAG_LEN || blob[0] != BLOB_V1 {
        return Err(CryptoError::Malformed);
    }
    let (nonce, ct) = blob[1..].split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError::Malformed)?;
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    cipher
        .decrypt(&XNonce::from(nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decrypt)
}

/// Wrap one key under another.
pub fn wrap_key(kek: &Key, aad: &[u8], key: &Key) -> Result<Vec<u8>, CryptoError> {
    seal(kek, aad, key.expose())
}

pub fn unwrap_key(kek: &Key, aad: &[u8], blob: &[u8]) -> Result<Key, CryptoError> {
    let pt = open(kek, aad, blob)?;
    Key::from_slice(&pt)
}

/// Argon2id cost parameters, stored next to the salt so they can be raised later.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// Unseal is rare and human-driven, so cost is set well above OWASP minimums.
    pub const DEFAULT: KdfParams = KdfParams { m_kib: 128 * 1024, t: 3, p: 1 };
    /// Cheap parameters for unit tests only.
    pub const TEST: KdfParams = KdfParams { m_kib: 8 * 1024, t: 1, p: 1 };

    /// Reject stored parameters that are too weak or absurdly expensive
    /// (a tampered seal record must not be able to downgrade or DoS the KDF).
    pub fn validate(&self, min: &KdfParams) -> Result<(), CryptoError> {
        if self.m_kib < min.m_kib || self.t < min.t || self.p < 1 {
            return Err(CryptoError::KdfParams);
        }
        if self.m_kib > 4 * 1024 * 1024 || self.t > 64 || self.p > 16 {
            return Err(CryptoError::KdfParams);
        }
        Ok(())
    }
}

pub fn derive_passphrase_key(
    passphrase: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<Key, CryptoError> {
    if salt.len() < SALT_LEN {
        return Err(CryptoError::KdfParams);
    }
    let p = argon2::Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN))
        .map_err(|_| CryptoError::KdfParams)?;
    let a2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    a2.hash_password_into(passphrase, salt, out.as_mut())
        .map_err(|_| CryptoError::KdfParams)?;
    Key::from_slice(out.as_ref())
}

/// HMAC-SHA256 over length-prefixed parts (unambiguous concatenation).
pub fn mac(key: &Key, parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as MacKeyInit>::new_from_slice(key.expose())
        .expect("HMAC accepts any key length");
    for p in parts {
        m.update(&(p.len() as u64).to_be_bytes());
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let k = Key::random().unwrap();
        let blob = seal(&k, b"aad", b"hunter2").unwrap();
        assert_eq!(&open(&k, b"aad", &blob).unwrap()[..], b"hunter2");
    }

    #[test]
    fn nonces_are_unique() {
        let k = Key::random().unwrap();
        let a = seal(&k, b"", b"x").unwrap();
        let b = seal(&k, b"", b"x").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_aad_key_or_tamper_fails() {
        let k = Key::random().unwrap();
        let blob = seal(&k, b"secret:1:v1", b"pw").unwrap();
        assert_eq!(open(&k, b"secret:1:v2", &blob).unwrap_err(), CryptoError::Decrypt);
        assert_eq!(
            open(&Key::random().unwrap(), b"secret:1:v1", &blob).unwrap_err(),
            CryptoError::Decrypt
        );
        for i in 0..blob.len() {
            let mut t = blob.clone();
            t[i] ^= 0x01;
            assert!(open(&k, b"secret:1:v1", &t).is_err(), "flip at byte {i} accepted");
        }
        assert_eq!(open(&k, b"", &blob[..10]).unwrap_err(), CryptoError::Malformed);
    }

    #[test]
    fn wrap_unwrap() {
        let kek = Key::random().unwrap();
        let k = Key::random().unwrap();
        let w = wrap_key(&kek, b"dek", &k).unwrap();
        assert_eq!(unwrap_key(&kek, b"dek", &w).unwrap().expose(), k.expose());
    }

    #[test]
    fn subkeys_are_separated_and_stable() {
        let k = Key::from_slice(&[7u8; 32]).unwrap();
        assert_ne!(k.subkey("a").expose(), k.subkey("b").expose());
        assert_eq!(k.subkey("a").expose(), k.subkey("a").expose());
        assert_ne!(k.subkey("a").expose(), k.expose());
    }

    #[test]
    fn argon2id_known_answer_is_deterministic() {
        let a = derive_passphrase_key(b"pass", &[1u8; 16], &KdfParams::TEST).unwrap();
        let b = derive_passphrase_key(b"pass", &[1u8; 16], &KdfParams::TEST).unwrap();
        let c = derive_passphrase_key(b"pass", &[2u8; 16], &KdfParams::TEST).unwrap();
        assert_eq!(a.expose(), b.expose());
        assert_ne!(a.expose(), c.expose());
        assert!(derive_passphrase_key(b"pass", &[1u8; 4], &KdfParams::TEST).is_err());
    }

    #[test]
    fn kdf_params_downgrade_rejected() {
        let weak = KdfParams { m_kib: 8, t: 1, p: 1 };
        assert!(weak.validate(&KdfParams::DEFAULT).is_err());
        assert!(KdfParams::DEFAULT.validate(&KdfParams::DEFAULT).is_ok());
        let huge = KdfParams { m_kib: u32::MAX, t: 3, p: 1 };
        assert!(huge.validate(&KdfParams::DEFAULT).is_err());
    }

    #[test]
    fn mac_is_length_prefixed() {
        let k = Key::from_slice(&[9u8; 32]).unwrap();
        assert_ne!(mac(&k, &[b"ab", b"c"]), mac(&k, &[b"a", b"bc"]));
        assert!(ct_eq(&mac(&k, &[b"x"]), &mac(&k, &[b"x"])));
    }
}
