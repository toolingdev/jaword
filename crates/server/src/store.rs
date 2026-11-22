//! The vault: encrypted storage, key hierarchy, tokens, versions and audit.
//!
//! Key hierarchy
//! -------------
//! passphrase --Argon2id--> KEK --wraps--> master key (MK)
//! recovery key ----HKDF--> KEK --wraps--> master key (MK)
//! MK --HKDF--> wrap key   (wraps a fresh data key per secret version)
//!           -> meta key   (encrypts metadata and rotation driver config)
//!           -> audit key  (HMAC chain over the audit log)
//!           -> token key  (HMAC of API tokens; raw tokens are never stored)
//!
//! Every ciphertext is bound (AEAD associated data) to the row it belongs to,
//! so blobs cannot be swapped between secrets or versions.

use jaword_core::{
    access::{self, Cap, Role, Rule},
    crypto::{self, KdfParams, Key},
    generate::{self, Policy},
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::sync::{Mutex, MutexGuard, RwLock, TryLockError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use crate::cards::{self, CardInfo, GiftInfo};
use crate::drivers::{Driver, RotationSetup};

pub const MAX_VALUE: usize = 16 * 1024;
pub const MIN_PASSPHRASE: usize = 14;
const KINDS: &[&str] = &["password", "api_key", "ssh_key", "config", "note", cards::CARD, cards::GIFT_CARD];

#[derive(Debug)]
pub enum VErr {
    Sealed,
    NotInitialized,
    AlreadyInitialized,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict(String),
    BadRequest(String),
    RateLimited(u64),
    Internal(String),
}
pub type R<T> = Result<T, VErr>;

impl From<rusqlite::Error> for VErr {
    fn from(e: rusqlite::Error) -> Self {
        VErr::Internal(format!("db: {e}"))
    }
}
impl From<crypto::CryptoError> for VErr {
    fn from(e: crypto::CryptoError) -> Self {
        VErr::Internal(format!("crypto: {e}"))
    }
}
impl From<serde_json::Error> for VErr {
    fn from(e: serde_json::Error) -> Self {
        VErr::Internal(format!("json: {e}"))
    }
}

fn bad<T>(m: &str) -> R<T> {
    Err(VErr::BadRequest(m.to_string()))
}

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

struct Keys {
    wrap: Key,
    meta: Key,
    audit: Key,
    token: Key,
    rows: Key,
}

impl Keys {
    fn from_master(mk: &Key) -> Keys {
        Keys {
            wrap: mk.subkey("dek-wrap"),
            meta: mk.subkey("metadata"),
            audit: mk.subkey("audit-mac"),
            token: mk.subkey("token-mac"),
            rows: mk.subkey("row-mac"),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SealRecord {
    v: u32,
    kdf: KdfParams,
    salt: String,
    mk_pass: String,
    mk_recovery: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Meta {
    /// Human-friendly name shown in the UI, e.g. "Proxmox root". The path is
    /// the unique address; the title is free text.
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Generation policy reused on every rotation.
    #[serde(default)]
    pub policy: Option<Policy>,
    /// Present on payment cards only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<CardInfo>,
    /// Present on gift cards only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gift: Option<GiftInfo>,
}

/// Make card metadata consistent with the item's kind and value. The brand,
/// last four digits and gift card ledger are the vault's: they come from the
/// value or from what is already stored, never from the caller.
fn settle_cards(kind: &str, meta: &mut Meta, old: Option<&Meta>, value: Option<&str>) -> R<()> {
    let facts = match (cards::is_card_kind(kind), value) {
        (true, Some(v)) => Some(cards::inspect(kind, v).map_err(|e| VErr::BadRequest(e.into()))?),
        _ => None,
    };
    match kind {
        cards::CARD => {
            meta.gift = None;
            meta.policy = None;
            let c = meta.card.get_or_insert_with(CardInfo::default);
            let prev = old.and_then(|m| m.card.as_ref());
            match (&facts, prev) {
                (Some(f), _) => {
                    c.last4 = f.last4.clone();
                    c.brand = f.brand.clone();
                }
                (None, Some(p)) => {
                    c.last4 = p.last4.clone();
                    c.brand = p.brand.clone();
                }
                (None, None) => return bad("enter the card number"),
            }
            cards::validate_card(c).map_err(|e| VErr::BadRequest(e.into()))
        }
        cards::GIFT_CARD => {
            meta.card = None;
            meta.policy = None;
            let g = meta.gift.get_or_insert_with(GiftInfo::default);
            let prev = old.and_then(|m| m.gift.as_ref());
            g.ledger = prev.map(|p| p.ledger.clone()).unwrap_or_default();
            match (&facts, prev) {
                (Some(f), _) => g.last4 = f.last4.clone(),
                (None, Some(p)) => g.last4 = p.last4.clone(),
                (None, None) => return bad("enter the gift card number"),
            }
            cards::validate_gift(g).map_err(|e| VErr::BadRequest(e.into()))?;
            if g.balance() < 0 {
                return bad("starting balance is less than what was already spent");
            }
            Ok(())
        }
        _ => {
            meta.card = None;
            meta.gift = None;
            Ok(())
        }
    }
}

fn no_cards(kind: &str) -> R<()> {
    if cards::is_card_kind(kind) {
        return bad("a card number cannot be generated or rotated; enter the new card details instead");
    }
    Ok(())
}

impl Meta {
    fn validate(&self) -> R<()> {
        if self.title.len() > 200 || self.username.len() > 256 || self.url.len() > 2048 || self.notes.len() > 8192 {
            return bad("metadata field too long");
        }
        if self.tags.len() > 32 || self.tags.iter().any(|t| t.is_empty() || t.len() > 64) {
            return bad("invalid tags");
        }
        if let Some(p) = &self.policy {
            generate::generate(p).map_err(|e| VErr::BadRequest(e.to_string()))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Actor {
    pub token_id: String,
    pub name: String,
    pub role: Role,
    pub rules: Vec<Rule>,
}

impl Actor {
    pub fn label(&self) -> String {
        format!("{}:{}", self.name, self.token_id)
    }
    fn can(&self, cap: Cap, path: &str) -> bool {
        access::allowed(self.role, &self.rules, cap, path)
    }
    fn require(&self, cap: Cap, path: &str) -> R<()> {
        if !access::valid_path(path) {
            return bad("invalid path");
        }
        if self.can(cap, path) {
            Ok(())
        } else {
            Err(VErr::Forbidden)
        }
    }
    fn require_admin(&self) -> R<()> {
        if self.role == Role::Admin {
            Ok(())
        } else {
            Err(VErr::Forbidden)
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub initialized: bool,
    pub sealed: bool,
    pub version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SecretView {
    pub path: String,
    pub kind: String,
    pub current_version: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub meta: Meta,
    pub has_driver: bool,
    pub pending_rotation: bool,
    /// When the current value was set (not when metadata last changed), and by whom.
    pub changed_at: i64,
    pub changed_by: String,
    /// Set when the vault rotates this on its own.
    pub rotate_every_days: Option<u32>,
    /// Money left on a gift card, in cents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance_cents: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct FolderView {
    pub path: String,
    /// Items in this folder and all folders beneath it.
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct VersionView {
    pub version: i64,
    pub state: String,
    pub created_at: i64,
    pub created_by: String,
}

#[derive(Debug, Serialize)]
pub struct SecretDetail {
    #[serde(flatten)]
    pub secret: SecretView,
    pub versions: Vec<VersionView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<RotationSetup>,
}

#[derive(Debug, Serialize)]
pub struct TokenView {
    pub id: String,
    pub name: String,
    pub role: Role,
    pub rules: Vec<Rule>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct AuditRow {
    pub seq: i64,
    pub ts: i64,
    pub actor: String,
    pub action: String,
    pub path: String,
    pub outcome: String,
    pub detail: String,
}

pub struct InitOutput {
    pub recovery_key: Zeroizing<String>,
    pub root_token: Zeroizing<String>,
}

/// Everything the driver runner needs; holds plaintext, wiped on drop.
pub struct RotationJob {
    pub path: String,
    pub version: i64,
    pub driver: Driver,
    pub username: String,
    pub new_value: Zeroizing<String>,
    pub old_value: Zeroizing<String>,
    secret_id: String,
    actor: String,
}

struct SecretRow {
    id: String,
    path: String,
    kind: String,
    current_version: i64,
    created_at: i64,
    updated_at: i64,
    meta_blob: Vec<u8>,
    driver_blob: Option<Vec<u8>>,
    row_mac: Vec<u8>,
}

pub struct Vault {
    db: Mutex<Connection>,
    keys: RwLock<Option<Keys>>,
    /// Serializes Argon2 work so parallel requests cannot exhaust memory.
    throttle: Mutex<()>,
    kdf_new: KdfParams,
    kdf_min: KdfParams,
    fail_delay_ms: u64,
}

const SCHEMA: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA foreign_keys = ON;
PRAGMA secure_delete = ON;
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  path TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL,
  current_version INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted_at INTEGER,
  meta_blob BLOB NOT NULL,
  driver_blob BLOB,
  row_mac BLOB NOT NULL DEFAULT x''
);
CREATE TABLE IF NOT EXISTS versions (
  secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  state TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  wrapped_dek BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  PRIMARY KEY (secret_id, version)
);
CREATE TABLE IF NOT EXISTS tokens (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  mac BLOB NOT NULL,
  role TEXT NOT NULL,
  rules TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  revoked_at INTEGER,
  last_used_at INTEGER,
  row_mac BLOB NOT NULL DEFAULT x''
);
CREATE TABLE IF NOT EXISTS folders (path TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  path TEXT NOT NULL,
  outcome TEXT NOT NULL,
  detail TEXT NOT NULL,
  mac BLOB NOT NULL
);
";

fn aad_value(id: &str, v: i64) -> Vec<u8> {
    format!("jaword:v1:value:{id}:{v}").into_bytes()
}
fn aad_dek(id: &str, v: i64) -> Vec<u8> {
    format!("jaword:v1:dek:{id}:{v}").into_bytes()
}
fn aad_meta(id: &str) -> Vec<u8> {
    format!("jaword:v1:meta:{id}").into_bytes()
}
fn aad_driver(id: &str) -> Vec<u8> {
    format!("jaword:v1:driver:{id}").into_bytes()
}

fn random_id(bytes: usize) -> R<String> {
    Ok(hex::encode(crypto::random_bytes(bytes)?))
}

fn role_str(r: Role) -> &'static str {
    match r {
        Role::Admin => "admin",
        Role::Human => "human",
        Role::Agent => "agent",
    }
}
fn role_parse(s: &str) -> R<Role> {
    match s {
        "admin" => Ok(Role::Admin),
        "human" => Ok(Role::Human),
        "agent" => Ok(Role::Agent),
        _ => Err(VErr::Internal("unknown role in db".into())),
    }
}

fn outcome<T>(r: &R<T>) -> (&'static str, String) {
    match r {
        Ok(_) => ("ok", String::new()),
        Err(VErr::Forbidden) => ("denied", String::new()),
        Err(VErr::NotFound) => ("not_found", String::new()),
        Err(VErr::BadRequest(m)) | Err(VErr::Conflict(m)) => ("rejected", m.clone()),
        Err(_) => ("error", String::new()),
    }
}

impl Vault {
    pub fn open(path: &str, kdf_new: KdfParams, kdf_min: KdfParams) -> R<Vault> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                // Create with 0600 before SQLite touches it; WAL/SHM inherit the mode.
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|e| VErr::Internal(format!("open db: {e}")))?;
            }
            Connection::open(path)?
        };
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Vault {
            db: Mutex::new(conn),
            keys: RwLock::new(None),
            throttle: Mutex::new(()),
            fail_delay_ms: if kdf_min == KdfParams::TEST { 0 } else { 1000 },
            kdf_new,
            kdf_min,
        })
    }

    fn db(&self) -> MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn with_keys<T>(&self, f: impl FnOnce(&Keys) -> R<T>) -> R<T> {
        let g = self.keys.read().unwrap_or_else(|p| p.into_inner());
        match g.as_ref() {
            Some(k) => f(k),
            None => Err(VErr::Sealed),
        }
    }

    fn seal_record(&self) -> R<Option<SealRecord>> {
        let s: Option<String> = self
            .db()
            .query_row("SELECT v FROM meta WHERE k='seal'", [], |r| r.get(0))
            .optional()?;
        Ok(match s {
            Some(s) => Some(serde_json::from_str(&s)?),
            None => None,
        })
    }

    pub fn status(&self) -> R<Status> {
        let initialized = self.seal_record()?.is_some();
        let sealed = self.keys.read().unwrap_or_else(|p| p.into_inner()).is_none();
        Ok(Status { initialized, sealed, version: env!("CARGO_PKG_VERSION") })
    }

    // ---------------------------------------------------------------- seal

    pub fn init(&self, passphrase: &str) -> R<InitOutput> {
        if passphrase.len() < MIN_PASSPHRASE {
            return bad("passphrase must be at least 14 characters");
        }
        // Hold the throttle lock so two inits cannot race.
        let _guard = self.throttle.lock().unwrap_or_else(|p| p.into_inner());
        if self.seal_record()?.is_some() {
            return Err(VErr::AlreadyInitialized);
        }
        let mk = Key::random()?;
        let salt = crypto::random_bytes(crypto::SALT_LEN)?;
        let kek = crypto::derive_passphrase_key(passphrase.as_bytes(), &salt, &self.kdf_new)?;
        let recovery = Zeroizing::new(crypto::random_bytes(32)?);
        let rkek = Key::from_slice(&recovery)?.subkey("recovery-kek");
        let rec = SealRecord {
            v: 1,
            kdf: self.kdf_new,
            salt: hex::encode(&salt),
            mk_pass: hex::encode(crypto::wrap_key(&kek, b"jaword:v1:mk:pass", &mk)?),
            mk_recovery: hex::encode(crypto::wrap_key(&rkek, b"jaword:v1:mk:recovery", &mk)?),
        };
        let keys = Keys::from_master(&mk);
        let (token_id, token, mac) = new_token(&keys)?;
        {
            let mut db = self.db();
            let tx = db.transaction()?;
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO meta (k, v) VALUES ('seal', ?1)",
                params![serde_json::to_string(&rec)?],
            )?;
            if inserted != 1 {
                return Err(VErr::AlreadyInitialized);
            }
            tx.execute(
                "INSERT INTO tokens (id,name,mac,role,rules,created_at) VALUES (?1,'root',?2,'admin','[]',?3)",
                params![token_id, mac.to_vec(), now()],
            )?;
            reseal_token_row(&tx, &keys, &token_id)?;
            audit_tx(&tx, &keys, "system", "sys.init", "", "ok", "")?;
            tx.commit()?;
        }
        *self.keys.write().unwrap_or_else(|p| p.into_inner()) = Some(keys);
        Ok(InitOutput {
            recovery_key: Zeroizing::new(format!("jwr_{}", hex::encode(&recovery[..]))),
            root_token: token,
        })
    }

    /// Unseal with the passphrase or the recovery key.
    ///
    /// Only one attempt runs at a time (bounded memory), and every failure
    /// costs a fixed delay on top of Argon2. There is deliberately no
    /// escalating lockout: that would let anyone who can reach the port keep
    /// the owner locked out of their own vault.
    pub fn unseal(&self, credential: &str) -> R<()> {
        let rec = self.seal_record()?.ok_or(VErr::NotInitialized)?;
        if self.keys.read().unwrap_or_else(|p| p.into_inner()).is_some() {
            return Err(VErr::Conflict("vault is already unsealed".into()));
        }
        let _th = match self.throttle.try_lock() {
            Ok(g) => g,
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
            Err(TryLockError::WouldBlock) => return Err(VErr::RateLimited(2)),
        };
        let attempt = || -> R<Key> {
            if let Some(hexkey) = credential.strip_prefix("jwr_") {
                let raw = Zeroizing::new(hex::decode(hexkey).map_err(|_| VErr::Unauthorized)?);
                let rkek = Key::from_slice(&raw).map_err(|_| VErr::Unauthorized)?.subkey("recovery-kek");
                let blob = hex::decode(&rec.mk_recovery).map_err(|_| VErr::Internal("seal record".into()))?;
                crypto::unwrap_key(&rkek, b"jaword:v1:mk:recovery", &blob).map_err(|_| VErr::Unauthorized)
            } else {
                rec.kdf.validate(&self.kdf_min).map_err(|_| VErr::Internal("seal record KDF parameters rejected".into()))?;
                let salt = hex::decode(&rec.salt).map_err(|_| VErr::Internal("seal record".into()))?;
                let kek = crypto::derive_passphrase_key(credential.as_bytes(), &salt, &rec.kdf)?;
                let blob = hex::decode(&rec.mk_pass).map_err(|_| VErr::Internal("seal record".into()))?;
                crypto::unwrap_key(&kek, b"jaword:v1:mk:pass", &blob).map_err(|_| VErr::Unauthorized)
            }
        };
        match attempt() {
            Ok(mk) => {
                let keys = Keys::from_master(&mk);
                audit_tx(&self.db(), &keys, "system", "sys.unseal", "", "ok", "")?;
                *self.keys.write().unwrap_or_else(|p| p.into_inner()) = Some(keys);
                Ok(())
            }
            Err(e) => {
                std::thread::sleep(Duration::from_millis(self.fail_delay_ms));
                Err(e)
            }
        }
    }

    pub fn seal(&self, a: &Actor) -> R<()> {
        a.require_admin()?;
        self.log(&a.label(), "sys.seal", "", "ok", "")?;
        *self.keys.write().unwrap_or_else(|p| p.into_inner()) = None;
        Ok(())
    }

    /// Admin-only actions that have no item of their own (rotation setup helpers).
    pub fn authorize_admin(&self, a: &Actor, action: &str, detail: &str) -> R<()> {
        let r = a.require_admin();
        let (o, _) = outcome(&r);
        self.log(&a.label(), action, "", o, detail)?;
        r
    }

    /// The identity scheduled rotations run under. Not a token: it exists
    /// only inside the server and cannot be presented from outside.
    pub fn schedule_actor() -> Actor {
        Actor { token_id: "vault".into(), name: "schedule".into(), role: Role::Admin, rules: Vec::new() }
    }

    /// Items whose schedule says they are due. Skips anything with a rotation
    /// in flight, and anything whose last attempt failed within a day, so a
    /// broken target is retried daily rather than hammered.
    pub fn due_rotations(&self) -> R<Vec<String>> {
        self.with_keys(|k| {
            let db = self.db();
            let mut st = db.prepare(
                "SELECT id,path,kind,current_version,created_at,updated_at,meta_blob,driver_blob,row_mac
                 FROM secrets WHERE deleted_at IS NULL AND driver_blob IS NOT NULL",
            )?;
            let rows = st.query_map([], row_to_secret)?.collect::<Result<Vec<_>, _>>()?;
            let t = now();
            let mut due = Vec::new();
            for s in rows {
                if verify_secret_row(k, &s).is_err() {
                    continue;
                }
                let blob = s.driver_blob.as_ref().expect("filtered by the query");
                let Ok(plain) = crypto::open(&k.meta, &aad_driver(&s.id), blob) else { continue };
                let Some(days) = serde_json::from_slice::<RotationSetup>(&plain).ok().and_then(|r| r.every_days) else { continue };
                let changed: i64 = db.query_row(
                    "SELECT created_at FROM versions WHERE secret_id=?1 AND version=?2",
                    params![s.id, s.current_version],
                    |r| r.get(0),
                )?;
                if t - changed < days as i64 * 86400 {
                    continue;
                }
                let (state, at): (String, i64) = db.query_row(
                    "SELECT state, created_at FROM versions WHERE secret_id=?1 ORDER BY version DESC LIMIT 1",
                    params![s.id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                if state == "pending" || (state == "failed" && t - at < 86400) {
                    continue;
                }
                due.push(s.path);
            }
            Ok(due)
        })
    }

    /// Gate and audit a self-update request. Admins, or tokens holding
    /// `upgrade` on `sys/update`.
    pub fn authorize_upgrade(&self, a: &Actor, detail: &str) -> R<()> {
        let r = if a.role == Role::Admin { Ok(()) } else { a.require(Cap::Upgrade, "sys/update") };
        let (o, _) = outcome(&r);
        self.log(&a.label(), "sys.update", "", o, detail)?;
        r
    }

    /// Re-wrap the master key under a new passphrase (vault must be unsealed).
    pub fn change_passphrase(&self, a: &Actor, current: &str, new: &str) -> R<()> {
        a.require_admin()?;
        if new.len() < MIN_PASSPHRASE {
            return bad("passphrase must be at least 14 characters");
        }
        let _th = self.throttle.lock().unwrap_or_else(|p| p.into_inner());
        let mut rec = self.seal_record()?.ok_or(VErr::NotInitialized)?;
        let salt = hex::decode(&rec.salt).map_err(|_| VErr::Internal("seal record".into()))?;
        let kek = crypto::derive_passphrase_key(current.as_bytes(), &salt, &rec.kdf)?;
        let blob = hex::decode(&rec.mk_pass).map_err(|_| VErr::Internal("seal record".into()))?;
        let mk = crypto::unwrap_key(&kek, b"jaword:v1:mk:pass", &blob).map_err(|_| VErr::Forbidden)?;
        let new_salt = crypto::random_bytes(crypto::SALT_LEN)?;
        let new_kek = crypto::derive_passphrase_key(new.as_bytes(), &new_salt, &self.kdf_new)?;
        rec.kdf = self.kdf_new;
        rec.salt = hex::encode(&new_salt);
        rec.mk_pass = hex::encode(crypto::wrap_key(&new_kek, b"jaword:v1:mk:pass", &mk)?);
        self.db().execute("UPDATE meta SET v=?1 WHERE k='seal'", params![serde_json::to_string(&rec)?])?;
        self.log(&a.label(), "sys.passphrase", "", "ok", "")
    }

    // --------------------------------------------------------------- audit

    fn log(&self, actor: &str, action: &str, path: &str, outcome: &str, detail: &str) -> R<()> {
        self.with_keys(|k| audit_tx(&self.db(), k, actor, action, path, outcome, detail))
    }

    fn logged<T>(&self, a: &Actor, action: &str, path: &str, r: R<T>) -> R<T> {
        let (o, d) = outcome(&r);
        // Fail closed: if the audit record cannot be written, the caller gets an error.
        self.log(&a.label(), action, path, o, &d)?;
        r
    }

    /// Record an event that has no authenticated actor (bad token, etc.).
    pub fn log_anonymous(&self, who: &str, action: &str, detail: &str) {
        let _ = self.log(who, action, "", "denied", detail);
    }

    pub fn audit_list(&self, a: &Actor, limit: i64, before: Option<i64>) -> R<Vec<AuditRow>> {
        a.require_admin()?;
        self.with_keys(|_| Ok(()))?;
        let db = self.db();
        let mut st = db.prepare(
            "SELECT seq,ts,actor,action,path,outcome,detail FROM audit WHERE seq < ?1 ORDER BY seq DESC LIMIT ?2",
        )?;
        let rows = st
            .query_map(params![before.unwrap_or(i64::MAX), limit.clamp(1, 500)], |r| {
                Ok(AuditRow {
                    seq: r.get(0)?,
                    ts: r.get(1)?,
                    actor: r.get(2)?,
                    action: r.get(3)?,
                    path: r.get(4)?,
                    outcome: r.get(5)?,
                    detail: r.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Walk the whole HMAC chain. Returns (rows checked, first bad seq).
    pub fn audit_verify(&self, a: &Actor) -> R<(i64, Option<i64>)> {
        a.require_admin()?;
        self.with_keys(|k| {
            let db = self.db();
            let mut st = db.prepare("SELECT seq,ts,actor,action,path,outcome,detail,mac FROM audit ORDER BY seq ASC")?;
            let mut rows = st.query([])?;
            let mut prev: Vec<u8> = Vec::new();
            let mut n = 0i64;
            let mut expect_seq: Option<i64> = None;
            while let Some(r) = rows.next()? {
                let seq: i64 = r.get(0)?;
                let mac: Vec<u8> = r.get(7)?;
                let calc = audit_mac(
                    k,
                    &prev,
                    seq,
                    r.get(1)?,
                    &r.get::<_, String>(2)?,
                    &r.get::<_, String>(3)?,
                    &r.get::<_, String>(4)?,
                    &r.get::<_, String>(5)?,
                    &r.get::<_, String>(6)?,
                );
                let gap = expect_seq.map(|e| e != seq).unwrap_or(false);
                if gap || !crypto::ct_eq(&calc, &mac) {
                    return Ok((n, Some(seq)));
                }
                expect_seq = Some(seq + 1);
                prev = mac;
                n += 1;
            }
            Ok((n, None))
        })
    }

    // -------------------------------------------------------------- tokens

    pub fn authenticate(&self, bearer: &str) -> R<Actor> {
        self.with_keys(|k| {
            let (id, _) = parse_token(bearer).ok_or(VErr::Unauthorized)?;
            let db = self.db();
            let row: Option<(String, Vec<u8>, String, String, Option<i64>, Option<i64>, Vec<u8>)> = db
                .query_row(
                    "SELECT name,mac,role,rules,expires_at,revoked_at,row_mac FROM tokens WHERE id=?1",
                    params![id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
                )
                .optional()?;
            // Always compute a MAC so unknown ids cost the same as known ones.
            let calc = crypto::mac(&k.token, &[bearer.as_bytes()]);
            let (name, mac, role, rules, exp, rev, row_mac) = row.ok_or(VErr::Unauthorized)?;
            if !crypto::ct_eq(&calc, &mac) {
                return Err(VErr::Unauthorized);
            }
            // The role, rules and lifetime are authenticated too: editing the
            // tokens table directly cannot upgrade or un-revoke a token.
            if !crypto::ct_eq(&token_row_mac(k, id, &name, &mac, &role, &rules, exp, rev), &row_mac) {
                tracing::error!("token row {id} failed its integrity check (database tampering?)");
                return Err(VErr::Unauthorized);
            }
            if rev.is_some() || exp.map(|e| e <= now()).unwrap_or(false) {
                return Err(VErr::Unauthorized);
            }
            db.execute("UPDATE tokens SET last_used_at=?1 WHERE id=?2", params![now(), id])?;
            Ok(Actor { token_id: id.to_string(), name, role: role_parse(&role)?, rules: serde_json::from_str(&rules)? })
        })
    }

    pub fn create_token(
        &self,
        a: &Actor,
        name: &str,
        role: Role,
        rules: Vec<Rule>,
        ttl_days: Option<u32>,
    ) -> R<(String, Zeroizing<String>)> {
        let r = (|| {
            a.require_admin()?;
            if name.is_empty()
                || name.len() > 64
                || !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            {
                return bad("token name must be 1-64 chars of [A-Za-z0-9._-]");
            }
            access::validate_rules(role, &rules).map_err(|m| VErr::BadRequest(m.into()))?;
            if matches!(ttl_days, Some(d) if d == 0 || d > 3650) {
                return bad("ttl_days must be 1..=3650");
            }
            self.with_keys(|k| {
                let (id, token, mac) = new_token(k)?;
                let exp = ttl_days.map(|d| now() + d as i64 * 86400);
                let db = self.db();
                db.execute(
                    "INSERT INTO tokens (id,name,mac,role,rules,created_at,expires_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                    params![id, name, mac.to_vec(), role_str(role), serde_json::to_string(&rules)?, now(), exp],
                )?;
                reseal_token_row(&db, k, &id)?;
                Ok((id, token))
            })
        })();
        let (o, d) = outcome(&r);
        let detail = match &r {
            Ok((id, _)) => format!("created {name}:{id} role={}", role_str(role)),
            Err(_) => d,
        };
        self.log(&a.label(), "token.create", "", o, &detail)?;
        r
    }

    pub fn list_tokens(&self, a: &Actor) -> R<Vec<TokenView>> {
        a.require_admin()?;
        self.with_keys(|_| Ok(()))?;
        let db = self.db();
        let mut st = db.prepare(
            "SELECT id,name,role,rules,created_at,expires_at,revoked_at,last_used_at FROM tokens ORDER BY created_at",
        )?;
        let raw = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                    r.get::<_, Option<i64>>(6)?,
                    r.get::<_, Option<i64>>(7)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        raw.into_iter()
            .map(|t| {
                Ok(TokenView {
                    id: t.0,
                    name: t.1,
                    role: role_parse(&t.2)?,
                    rules: serde_json::from_str(&t.3)?,
                    created_at: t.4,
                    expires_at: t.5,
                    revoked_at: t.6,
                    last_used_at: t.7,
                })
            })
            .collect()
    }

    pub fn revoke_token(&self, a: &Actor, id: &str) -> R<()> {
        let r = (|| {
            a.require_admin()?;
            self.with_keys(|k| {
                let db = self.db();
                let n = db.execute("UPDATE tokens SET revoked_at=?1 WHERE id=?2 AND revoked_at IS NULL", params![now(), id])?;
                if n == 0 {
                    return Err(VErr::NotFound);
                }
                reseal_token_row(&db, k, id)
            })
        })();
        let (o, _) = outcome(&r);
        let safe_id: String = id.chars().filter(|c| c.is_ascii_hexdigit()).take(32).collect();
        self.log(&a.label(), "token.revoke", "", o, &safe_id)?;
        r
    }

    // ------------------------------------------------------------- secrets

    fn load(&self, db: &Connection, k: &Keys, path: &str) -> R<SecretRow> {
        let s = db.query_row(
            "SELECT id,path,kind,current_version,created_at,updated_at,meta_blob,driver_blob,row_mac
             FROM secrets WHERE path=?1 AND deleted_at IS NULL",
            params![path],
            row_to_secret,
        )
        .optional()?
        .ok_or(VErr::NotFound)?;
        verify_secret_row(k, &s)?;
        Ok(s)
    }

    fn view(&self, db: &Connection, k: &Keys, s: &SecretRow) -> R<SecretView> {
        let meta: Meta = serde_json::from_slice(&crypto::open(&k.meta, &aad_meta(&s.id), &s.meta_blob)?)?;
        let pending: i64 = db.query_row(
            "SELECT COUNT(*) FROM versions WHERE secret_id=?1 AND state='pending'",
            params![s.id],
            |r| r.get(0),
        )?;
        let (changed_at, changed_by): (i64, String) = db
            .query_row(
                "SELECT created_at, created_by FROM versions WHERE secret_id=?1 AND version=?2",
                params![s.id, s.current_version],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .unwrap_or((s.updated_at, String::new()));
        Ok(SecretView {
            path: s.path.clone(),
            kind: s.kind.clone(),
            current_version: s.current_version,
            created_at: s.created_at,
            updated_at: s.updated_at,
            balance_cents: meta.gift.as_ref().map(|g| g.balance()),
            meta,
            has_driver: s.driver_blob.is_some(),
            pending_rotation: pending > 0,
            changed_at,
            changed_by,
            rotate_every_days: match &s.driver_blob {
                Some(b) => serde_json::from_slice::<RotationSetup>(&crypto::open(&k.meta, &aad_driver(&s.id), b)?)?.every_days,
                None => None,
            },
        })
    }

    pub fn create(
        &self,
        a: &Actor,
        path: &str,
        kind: &str,
        mut meta: Meta,
        value: Option<Zeroizing<String>>,
        policy: Option<Policy>,
    ) -> R<SecretView> {
        let r = (|| {
            a.require(Cap::Create, path)?;
            if access::reserved(path) {
                return bad("`sys` is reserved for the vault itself; choose another folder name");
            }
            if value.is_some() {
                a.require(Cap::Write, path)?;
            }
            if !KINDS.contains(&kind) {
                return bad("kind must be one of password, api_key, ssh_key, config, note, card, gift_card");
            }
            if policy.is_some() {
                meta.policy = policy;
            }
            settle_cards(kind, &mut meta, None, value.as_ref().map(|v| v.as_str()))?;
            meta.validate()?;
            let value = match value {
                Some(v) => v,
                None => generate::generate(meta.policy.as_ref().unwrap_or(&Policy::default()))
                    .map_err(|e| VErr::BadRequest(e.to_string()))?,
            };
            check_value(&value)?;
            self.with_keys(|k| {
                let mut db = self.db();
                let tx = db.transaction()?;
                let exists: i64 =
                    tx.query_row("SELECT COUNT(*) FROM secrets WHERE path=?1", params![path], |r| r.get(0))?;
                if exists > 0 {
                    return Err(VErr::Conflict("a secret already exists at this path".into()));
                }
                let id = random_id(16)?;
                let t = now();
                tx.execute(
                    "INSERT INTO secrets (id,path,kind,current_version,created_at,updated_at,meta_blob)
                     VALUES (?1,?2,?3,1,?4,?4,?5)",
                    params![id, path, kind, t, crypto::seal(&k.meta, &aad_meta(&id), &serde_json::to_vec(&meta)?)?],
                )?;
                put_version(&tx, k, &id, 1, value.as_bytes(), &a.label(), "current")?;
                reseal_secret_row(&tx, k, &id)?;
                let s = tx.query_row(
                    "SELECT id,path,kind,current_version,created_at,updated_at,meta_blob,driver_blob,row_mac FROM secrets WHERE id=?1",
                    params![id],
                    row_to_secret,
                )?;
                let v = self.view(&tx, k, &s)?;
                tx.commit()?;
                Ok(v)
            })
        })();
        self.logged(a, "secret.create", path, r)
    }

    pub fn list(&self, a: &Actor, prefix: &str) -> R<Vec<SecretView>> {
        if prefix.len() > access::MAX_PATH_LEN {
            return bad("prefix too long");
        }
        self.with_keys(|k| {
            let db = self.db();
            let mut st = db.prepare(
                "SELECT id,path,kind,current_version,created_at,updated_at,meta_blob,driver_blob,row_mac
                 FROM secrets WHERE deleted_at IS NULL ORDER BY path",
            )?;
            let rows = st.query_map([], row_to_secret)?.collect::<Result<Vec<_>, _>>()?;
            rows.iter()
                .filter(|s| s.path.starts_with(prefix) && a.can(Cap::List, &s.path))
                .map(|s| {
                    verify_secret_row(k, s)?;
                    self.view(&db, k, s)
                })
                .collect()
        })
    }

    pub fn get(&self, a: &Actor, path: &str) -> R<SecretDetail> {
        a.require(Cap::List, path)?;
        self.with_keys(|k| {
            let db = self.db();
            let s = self.load(&db, k, path)?;
            let mut st = db.prepare(
                "SELECT version,state,created_at,created_by FROM versions WHERE secret_id=?1 ORDER BY version DESC",
            )?;
            let versions = st
                .query_map(params![s.id], |r| {
                    Ok(VersionView { version: r.get(0)?, state: r.get(1)?, created_at: r.get(2)?, created_by: r.get(3)? })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            // Driver config (hosts, commands) is only shown to admins.
            let driver = match (&s.driver_blob, a.role) {
                (Some(b), Role::Admin) => {
                    Some(serde_json::from_slice(&crypto::open(&k.meta, &aad_driver(&s.id), b)?)?)
                }
                _ => None,
            };
            Ok(SecretDetail { secret: self.view(&db, k, &s)?, versions, driver })
        })
    }

    /// Update metadata and/or store a caller-supplied value as a new version.
    pub fn update(&self, a: &Actor, path: &str, meta: Option<Meta>, value: Option<Zeroizing<String>>) -> R<SecretView> {
        let r = (|| {
            if !access::valid_path(path) || (meta.is_none() && value.is_none()) {
                return bad("invalid path or nothing to update");
            }
            if meta.is_some() {
                a.require(Cap::Update, path)?;
            }
            if value.is_some() {
                a.require(Cap::Write, path)?;
            }
            if let Some(m) = &meta {
                m.validate()?;
            }
            if let Some(v) = &value {
                check_value(v)?;
            }
            self.with_keys(|k| {
                let mut db = self.db();
                let tx = db.transaction()?;
                let s = self.load(&tx, k, path)?;
                let old: Meta = serde_json::from_slice(&crypto::open(&k.meta, &aad_meta(&s.id), &s.meta_blob)?)?;
                // A new card number changes the last four digits, so the
                // metadata follows the value even when only the value was sent.
                let mut meta = meta.clone();
                if meta.is_none() && value.is_some() && cards::is_card_kind(&s.kind) {
                    meta = Some(old.clone());
                }
                if let Some(m) = meta.as_mut() {
                    settle_cards(&s.kind, m, Some(&old), value.as_ref().map(|v| v.as_str()))?;
                    m.validate()?;
                }
                if let Some(m) = &meta {
                    tx.execute(
                        "UPDATE secrets SET meta_blob=?1, updated_at=?2 WHERE id=?3",
                        params![crypto::seal(&k.meta, &aad_meta(&s.id), &serde_json::to_vec(m)?)?, now(), s.id],
                    )?;
                }
                if let Some(v) = &value {
                    promote_new(&tx, k, &s.id, v.as_bytes(), &a.label())?;
                }
                let s = self.load(&tx, k, path)?;
                let view = self.view(&tx, k, &s)?;
                tx.commit()?;
                Ok(view)
            })
        })();
        self.logged(a, "secret.update", path, r)
    }

    /// Generate a new current version inside the vault. The value is not returned.
    pub fn generate(&self, a: &Actor, path: &str, policy: Option<Policy>) -> R<SecretView> {
        let r = (|| {
            a.require(Cap::Generate, path)?;
            self.with_keys(|k| {
                let mut db = self.db();
                let tx = db.transaction()?;
                let s = self.load(&tx, k, path)?;
                no_cards(&s.kind)?;
                let mut meta: Meta = serde_json::from_slice(&crypto::open(&k.meta, &aad_meta(&s.id), &s.meta_blob)?)?;
                if let Some(p) = policy {
                    meta.policy = Some(p);
                    meta.validate()?;
                    tx.execute(
                        "UPDATE secrets SET meta_blob=?1 WHERE id=?2",
                        params![crypto::seal(&k.meta, &aad_meta(&s.id), &serde_json::to_vec(&meta)?)?, s.id],
                    )?;
                }
                let value = generate::generate(meta.policy.as_ref().unwrap_or(&Policy::default()))
                    .map_err(|e| VErr::BadRequest(e.to_string()))?;
                promote_new(&tx, k, &s.id, value.as_bytes(), &a.label())?;
                let s = self.load(&tx, k, path)?;
                let view = self.view(&tx, k, &s)?;
                tx.commit()?;
                Ok(view)
            })
        })();
        self.logged(a, "secret.generate", path, r)
    }

    pub fn reveal(&self, a: &Actor, path: &str, version: Option<i64>) -> R<Zeroizing<String>> {
        let r = (|| {
            a.require(Cap::Reveal, path)?;
            self.with_keys(|k| {
                let db = self.db();
                let s = self.load(&db, k, path)?;
                read_version(&db, k, &s.id, version.unwrap_or(s.current_version))
            })
        })();
        let (o, _) = outcome(&r);
        let d = version.map(|v| format!("version {v}")).unwrap_or_default();
        self.log(&a.label(), "secret.reveal", path, o, &d)?;
        r
    }

    /// Record money spent from (negative) or added to (positive) a gift card.
    /// Needs only the right to edit details: the card number stays sealed.
    pub fn ledger_add(&self, a: &Actor, path: &str, cents: i64, note: &str) -> R<SecretView> {
        let r = (|| {
            a.require(Cap::Update, path)?;
            if cents == 0 || cents.abs() > cards::MAX_CENTS {
                return bad("amount must be more than zero and under ten million");
            }
            if note.len() > 200 || note.chars().any(|c| c.is_control()) {
                return bad("note must be one line of at most 200 characters");
            }
            self.with_keys(|k| {
                let mut db = self.db();
                let tx = db.transaction()?;
                let s = self.load(&tx, k, path)?;
                if s.kind != cards::GIFT_CARD {
                    return bad("only gift cards have a balance");
                }
                let mut meta: Meta = serde_json::from_slice(&crypto::open(&k.meta, &aad_meta(&s.id), &s.meta_blob)?)?;
                let g = meta.gift.get_or_insert_with(GiftInfo::default);
                if g.ledger.len() >= cards::MAX_LEDGER {
                    return bad("this card's history is full");
                }
                let left = g.balance();
                if left + cents < 0 {
                    return Err(VErr::BadRequest(format!("only {} left on this card", cards::money(left))));
                }
                g.ledger.push(cards::Entry { at: now(), cents, note: note.to_string(), by: a.label() });
                tx.execute(
                    "UPDATE secrets SET meta_blob=?1, updated_at=?2 WHERE id=?3",
                    params![crypto::seal(&k.meta, &aad_meta(&s.id), &serde_json::to_vec(&meta)?)?, now(), s.id],
                )?;
                let s = self.load(&tx, k, path)?;
                let view = self.view(&tx, k, &s)?;
                tx.commit()?;
                Ok(view)
            })
        })();
        self.logged(a, if cents < 0 { "card.spend" } else { "card.add" }, path, r)
    }

    /// Make an earlier version current again, for when a new password did
    /// not take on the real system. Recorded as a new version, so history
    /// stays a straight line. Nothing is revealed to the caller.
    pub fn restore_version(&self, a: &Actor, path: &str, version: i64) -> R<SecretView> {
        let r = (|| {
            a.require(Cap::Generate, path)?;
            self.with_keys(|k| {
                let mut db = self.db();
                let tx = db.transaction()?;
                let s = self.load(&tx, k, path)?;
                if version == s.current_version {
                    return bad("that version is already the current one");
                }
                let old = read_version(&tx, k, &s.id, version)?;
                promote_new(&tx, k, &s.id, old.as_bytes(), &a.label())?;
                if cards::is_card_kind(&s.kind) {
                    // The restored card may be a different card: keep the label honest.
                    let mut meta: Meta = serde_json::from_slice(&crypto::open(&k.meta, &aad_meta(&s.id), &s.meta_blob)?)?;
                    let before = meta.clone();
                    settle_cards(&s.kind, &mut meta, Some(&before), Some(old.as_str()))?;
                    tx.execute(
                        "UPDATE secrets SET meta_blob=?1 WHERE id=?2",
                        params![crypto::seal(&k.meta, &aad_meta(&s.id), &serde_json::to_vec(&meta)?)?, s.id],
                    )?;
                }
                let s = self.load(&tx, k, path)?;
                let view = self.view(&tx, k, &s)?;
                tx.commit()?;
                Ok(view)
            })
        })();
        let (o, d) = outcome(&r);
        let detail = if r.is_ok() { format!("restored version {version}") } else { d };
        self.log(&a.label(), "secret.restore", path, o, &detail)?;
        r
    }

    pub fn delete(&self, a: &Actor, path: &str) -> R<()> {
        let r = (|| {
            a.require(Cap::Delete, path)?;
            self.with_keys(|k| {
                let db = self.db();
                let s = self.load(&db, k, path)?;
                // Soft delete: free the path, keep ciphertext for recovery by an admin.
                db.execute(
                    "UPDATE secrets SET deleted_at=?1, path=?2 WHERE id=?3",
                    params![now(), format!("{}#deleted#{}", s.path, s.id), s.id],
                )?;
                reseal_secret_row(&db, k, &s.id)?;
                Ok(())
            })
        })();
        self.logged(a, "secret.delete", path, r)
    }

    // ------------------------------------------------------------- folders
    //
    // A folder is simply a path prefix: `personal/github` lives in folder
    // `personal`. The `folders` table only remembers folders that are empty,
    // so a person can create one before putting anything in it.

    /// Move one secret. Needs `delete`+`list` where it is and `create` where
    /// it is going. A token that could read values at the destination but not
    /// at the source is refused, so moving can never be used to gain `reveal`.
    fn move_row(&self, tx: &Connection, k: &Keys, a: &Actor, from: &str, to: &str) -> R<()> {
        a.require(Cap::Delete, from)?;
        a.require(Cap::List, from)?;
        a.require(Cap::Create, to)?;
        if access::reserved(to) {
            return bad("`sys` is reserved for the vault itself; choose another folder name");
        }
        if a.role != Role::Admin && a.can(Cap::Reveal, to) && !a.can(Cap::Reveal, from) {
            return Err(VErr::Forbidden);
        }
        let s = self.load(tx, k, from)?;
        let taken: i64 = tx.query_row("SELECT COUNT(*) FROM secrets WHERE path=?1", params![to], |r| r.get(0))?;
        if taken > 0 {
            return Err(VErr::Conflict(format!("an item already exists at {to}")));
        }
        tx.execute("UPDATE secrets SET path=?1, updated_at=?2 WHERE id=?3", params![to, now(), s.id])?;
        reseal_secret_row(tx, k, &s.id)
    }

    pub fn move_secret(&self, a: &Actor, path: &str, new_path: &str) -> R<SecretView> {
        let r = (|| {
            if !access::valid_path(path) || !access::valid_path(new_path) || path == new_path {
                return bad("invalid path, or the item is already there");
            }
            self.with_keys(|k| {
                let mut db = self.db();
                let tx = db.transaction()?;
                self.move_row(&tx, k, a, path, new_path)?;
                let s = self.load(&tx, k, new_path)?;
                let v = self.view(&tx, k, &s)?;
                tx.commit()?;
                Ok(v)
            })
        })();
        let (o, d) = outcome(&r);
        let detail = if r.is_ok() { format!("moved to {new_path}") } else { d };
        self.log(&a.label(), "secret.move", path, o, &detail)?;
        r
    }

    pub fn folders(&self, a: &Actor) -> R<Vec<FolderView>> {
        self.with_keys(|_| {
            let db = self.db();
            let mut st = db.prepare("SELECT path FROM secrets WHERE deleted_at IS NULL")?;
            let paths = st.query_map([], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
            let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
            for p in paths.iter().filter(|p| a.can(Cap::List, p)) {
                let segs: Vec<&str> = p.split('/').collect();
                for i in 1..segs.len() {
                    *counts.entry(segs[..i].join("/")).or_insert(0) += 1;
                }
            }
            let mut st = db.prepare("SELECT path FROM folders")?;
            for f in st.query_map([], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()? {
                if a.can(Cap::List, &format!("{f}/x")) {
                    // Show parents of an empty folder too.
                    let segs: Vec<&str> = f.split('/').collect();
                    for i in 1..=segs.len() {
                        counts.entry(segs[..i].join("/")).or_insert(0);
                    }
                }
            }
            Ok(counts.into_iter().map(|(path, count)| FolderView { path, count }).collect())
        })
    }

    pub fn create_folder(&self, a: &Actor, path: &str) -> R<()> {
        let r = (|| {
            if !valid_folder(path) {
                return bad("invalid folder name");
            }
            a.require(Cap::Create, &format!("{path}/x"))?;
            self.with_keys(|_| {
                self.db().execute("INSERT OR IGNORE INTO folders (path, created_at) VALUES (?1, ?2)", params![path, now()])?;
                Ok(())
            })
        })();
        self.logged(a, "folder.create", path, r)
    }

    /// Rename or move a folder: every item under `from` is re-homed under
    /// `to`, keeping sub-folders. All or nothing.
    pub fn move_folder(&self, a: &Actor, from: &str, to: &str) -> R<usize> {
        let r = (|| {
            if !valid_folder(from) || !valid_folder(to) || from == to {
                return bad("invalid folder, or nothing to change");
            }
            if to.starts_with(&format!("{from}/")) {
                return bad("a folder cannot be moved inside itself");
            }
            self.with_keys(|k| {
                let mut db = self.db();
                let tx = db.transaction()?;
                let n = self.rehome(&tx, k, a, from, to)?;
                tx.execute("INSERT OR IGNORE INTO folders (path, created_at) VALUES (?1, ?2)", params![to, now()])?;
                tx.commit()?;
                Ok(n)
            })
        })();
        let (o, d) = outcome(&r);
        let detail = match &r {
            Ok(n) => format!("moved to {to} ({n} items)"),
            Err(_) => d,
        };
        self.log(&a.label(), "folder.move", from, o, &detail)?;
        r
    }

    /// Delete a folder. With `move_to`, its items are moved there first
    /// (pass an empty string for the top level); otherwise they are deleted.
    pub fn delete_folder(&self, a: &Actor, path: &str, move_to: Option<&str>) -> R<usize> {
        let r = (|| {
            if !valid_folder(path) {
                return bad("invalid folder");
            }
            if let Some(dest) = move_to {
                if (!dest.is_empty() && !valid_folder(dest)) || dest == path || dest.starts_with(&format!("{path}/")) {
                    return bad("choose a different folder to move the items to");
                }
            }
            self.with_keys(|k| {
                let mut db = self.db();
                let tx = db.transaction()?;
                let n = match move_to {
                    Some(dest) => self.rehome(&tx, k, a, path, dest)?,
                    None => {
                        let prefix = format!("{path}/");
                        let mut st = tx.prepare("SELECT path FROM secrets WHERE deleted_at IS NULL")?;
                        let inside: Vec<String> = st
                            .query_map([], |r| r.get::<_, String>(0))?
                            .collect::<Result<Vec<_>, _>>()?
                            .into_iter()
                            .filter(|p| p.starts_with(&prefix))
                            .collect();
                        drop(st);
                        for p in &inside {
                            a.require(Cap::Delete, p)?;
                            let s = self.load(&tx, k, p)?;
                            tx.execute(
                                "UPDATE secrets SET deleted_at=?1, path=?2 WHERE id=?3",
                                params![now(), format!("{}#deleted#{}", s.path, s.id), s.id],
                            )?;
                            reseal_secret_row(&tx, k, &s.id)?;
                        }
                        a.require(Cap::Delete, &format!("{path}/x"))?;
                        drop_folder_rows(&tx, path, None)?;
                        inside.len()
                    }
                };
                tx.commit()?;
                Ok(n)
            })
        })();
        let (o, d) = outcome(&r);
        let detail = match (&r, move_to) {
            (Ok(n), Some(dest)) => format!("{n} items moved to {}", if dest.is_empty() { "top level" } else { dest }),
            (Ok(n), None) => format!("{n} items deleted"),
            (Err(_), _) => d,
        };
        self.log(&a.label(), "folder.delete", path, o, &detail)?;
        r
    }

    /// Move everything under `from` to sit under `to` ("" = top level).
    fn rehome(&self, tx: &Connection, k: &Keys, a: &Actor, from: &str, to: &str) -> R<usize> {
        let prefix = format!("{from}/");
        let mut st = tx.prepare("SELECT path FROM secrets WHERE deleted_at IS NULL")?;
        let inside: Vec<String> = st
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|p| p.starts_with(&prefix))
            .collect();
        drop(st);
        for p in &inside {
            let rest = &p[prefix.len()..];
            let dest = if to.is_empty() { rest.to_string() } else { format!("{to}/{rest}") };
            if !access::valid_path(&dest) {
                return bad("the new location makes an item's address too long");
            }
            self.move_row(tx, k, a, p, &dest)?;
        }
        if inside.is_empty() {
            // Nothing inside to check permissions against, so check the folder itself.
            a.require(Cap::Delete, &format!("{from}/x"))?;
            if !to.is_empty() {
                a.require(Cap::Create, &format!("{to}/x"))?;
            }
        }
        drop_folder_rows(tx, from, if to.is_empty() { None } else { Some(to) })?;
        Ok(inside.len())
    }

    pub fn set_driver(&self, a: &Actor, path: &str, driver: Option<RotationSetup>) -> R<()> {
        let r = (|| {
            a.require_admin()?;
            if !access::valid_path(path) {
                return bad("invalid path");
            }
            if let Some(d) = &driver {
                d.validate().map_err(VErr::BadRequest)?;
            }
            self.with_keys(|k| {
                let db = self.db();
                let s = self.load(&db, k, path)?;
                if driver.is_some() {
                    no_cards(&s.kind)?;
                }
                let blob = match &driver {
                    Some(d) => Some(crypto::seal(&k.meta, &aad_driver(&s.id), &serde_json::to_vec(d)?)?),
                    None => None,
                };
                db.execute("UPDATE secrets SET driver_blob=?1 WHERE id=?2", params![blob, s.id])?;
                Ok(())
            })
        })();
        self.logged(a, "secret.driver", path, r)
    }

    // ------------------------------------------------------------ rotation

    /// Step 1: generate the new value and store it as `pending` *before* the
    /// remote system is touched, so a crash can never lose a live credential.
    pub fn rotate_prepare(&self, a: &Actor, path: &str) -> R<RotationJob> {
        let r = (|| {
            a.require(Cap::Rotate, path)?;
            self.with_keys(|k| {
                let mut db = self.db();
                let tx = db.transaction()?;
                let s = self.load(&tx, k, path)?;
                let blob = s
                    .driver_blob
                    .as_ref()
                    .ok_or_else(|| VErr::BadRequest("no rotation driver configured for this secret".into()))?;
                let driver: Driver = serde_json::from_slice::<RotationSetup>(&crypto::open(&k.meta, &aad_driver(&s.id), blob)?)?.driver;
                let pending: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM versions WHERE secret_id=?1 AND state='pending'",
                    params![s.id],
                    |r| r.get(0),
                )?;
                if pending > 0 {
                    return Err(VErr::Conflict("a rotation is already pending for this secret".into()));
                }
                let meta: Meta = serde_json::from_slice(&crypto::open(&k.meta, &aad_meta(&s.id), &s.meta_blob)?)?;
                let new_value = generate::generate(meta.policy.as_ref().unwrap_or(&Policy::default()))
                    .map_err(|e| VErr::BadRequest(e.to_string()))?;
                let old_value = read_version(&tx, k, &s.id, s.current_version)?;
                let next = next_version(&tx, &s.id)?;
                put_version(&tx, k, &s.id, next, new_value.as_bytes(), &a.label(), "pending")?;
                tx.commit()?;
                Ok(RotationJob {
                    path: s.path,
                    version: next,
                    driver,
                    username: meta.username,
                    new_value,
                    old_value,
                    secret_id: s.id,
                    actor: a.label(),
                })
            })
        })();
        let (o, d) = outcome(&r);
        if r.is_err() {
            self.log(&a.label(), "secret.rotate", path, o, &d)?;
        }
        r
    }

    /// Step 2: record the driver result. Success promotes the pending version;
    /// failure keeps the old one current and parks the new value as `failed`
    /// (still recoverable by a human in case the remote change half-applied).
    pub fn rotate_finish(&self, job: &RotationJob, result: Result<(), String>) -> R<i64> {
        self.with_keys(|k| {
            let mut db = self.db();
            let tx = db.transaction()?;
            match &result {
                Ok(()) => {
                    set_current(&tx, k, &job.secret_id, job.version)?;
                    audit_tx(&tx, k, &job.actor, "secret.rotate", &job.path, "ok", &format!("version {}", job.version))?;
                }
                Err(msg) => {
                    tx.execute(
                        "UPDATE versions SET state='failed' WHERE secret_id=?1 AND version=?2",
                        params![job.secret_id, job.version],
                    )?;
                    audit_tx(&tx, k, &job.actor, "secret.rotate", &job.path, "error", msg)?;
                }
            }
            tx.commit()?;
            Ok(job.version)
        })
    }

    /// Admin recovery for a rotation interrupted by a crash: promote or discard
    /// the pending version after checking the remote system by hand.
    pub fn resolve_pending(&self, a: &Actor, path: &str, promote: bool) -> R<()> {
        let r = (|| {
            a.require_admin()?;
            self.with_keys(|k| {
                let mut db = self.db();
                let tx = db.transaction()?;
                let s = self.load(&tx, k, path)?;
                let v: Option<i64> = tx
                    .query_row(
                        "SELECT version FROM versions WHERE secret_id=?1 AND state='pending'",
                        params![s.id],
                        |r| r.get(0),
                    )
                    .optional()?;
                let v = v.ok_or(VErr::NotFound)?;
                if promote {
                    set_current(&tx, k, &s.id, v)?;
                } else {
                    tx.execute("UPDATE versions SET state='failed' WHERE secret_id=?1 AND version=?2", params![s.id, v])?;
                }
                tx.commit()?;
                Ok(())
            })
        })();
        self.logged(a, if promote { "rotate.promote" } else { "rotate.discard" }, path, r)
    }
}

fn valid_folder(p: &str) -> bool {
    access::valid_path(p) && p.len() <= 150 && !access::reserved(p)
}

/// Remove the remembered-folder rows at and under `from`; with `to`, recreate
/// them under the new location so empty sub-folders survive a rename.
fn drop_folder_rows(tx: &Connection, from: &str, to: Option<&str>) -> R<()> {
    let prefix = format!("{from}/");
    let mut st = tx.prepare("SELECT path FROM folders")?;
    let rows: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|p| p == from || p.starts_with(&prefix))
        .collect();
    drop(st);
    for p in rows {
        tx.execute("DELETE FROM folders WHERE path=?1", params![p])?;
        if let Some(to) = to {
            let moved = format!("{to}{}", &p[from.len()..]);
            if valid_folder(&moved) {
                tx.execute("INSERT OR IGNORE INTO folders (path, created_at) VALUES (?1, ?2)", params![moved, now()])?;
            }
        }
    }
    Ok(())
}

fn check_value(v: &str) -> R<()> {
    if v.is_empty() {
        return bad("value is empty");
    }
    if v.len() > MAX_VALUE {
        return bad("value too large (max 16 KiB)");
    }
    Ok(())
}

fn row_to_secret(r: &rusqlite::Row<'_>) -> rusqlite::Result<SecretRow> {
    Ok(SecretRow {
        id: r.get(0)?,
        path: r.get(1)?,
        kind: r.get(2)?,
        current_version: r.get(3)?,
        created_at: r.get(4)?,
        updated_at: r.get(5)?,
        meta_blob: r.get(6)?,
        driver_blob: r.get(7)?,
        row_mac: r.get(8)?,
    })
}

fn secret_row_mac(k: &Keys, id: &str, path: &str, kind: &str, current: i64) -> [u8; 32] {
    crypto::mac(&k.rows, &[b"secret", id.as_bytes(), path.as_bytes(), kind.as_bytes(), &current.to_be_bytes()])
}

/// Detects edits made directly to the database: swapping the paths of two
/// secrets, or rolling `current_version` back to an older value.
fn verify_secret_row(k: &Keys, s: &SecretRow) -> R<()> {
    if crypto::ct_eq(&secret_row_mac(k, &s.id, &s.path, &s.kind, s.current_version), &s.row_mac) {
        Ok(())
    } else {
        Err(VErr::Internal(format!("integrity check failed for secret row {} (database tampering?)", s.id)))
    }
}

fn reseal_secret_row(db: &Connection, k: &Keys, id: &str) -> R<()> {
    let (path, kind, cur): (String, String, i64) = db.query_row(
        "SELECT path,kind,current_version FROM secrets WHERE id=?1",
        params![id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    db.execute("UPDATE secrets SET row_mac=?1 WHERE id=?2", params![secret_row_mac(k, id, &path, &kind, cur).to_vec(), id])?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn token_row_mac(k: &Keys, id: &str, name: &str, mac: &[u8], role: &str, rules: &str, exp: Option<i64>, rev: Option<i64>) -> [u8; 32] {
    let opt = |v: Option<i64>| v.map(|x| x.to_string()).unwrap_or_else(|| "-".into());
    crypto::mac(
        &k.rows,
        &[b"token", id.as_bytes(), name.as_bytes(), mac, role.as_bytes(), rules.as_bytes(), opt(exp).as_bytes(), opt(rev).as_bytes()],
    )
}

fn reseal_token_row(db: &Connection, k: &Keys, id: &str) -> R<()> {
    let (name, mac, role, rules, exp, rev): (String, Vec<u8>, String, String, Option<i64>, Option<i64>) = db.query_row(
        "SELECT name,mac,role,rules,expires_at,revoked_at FROM tokens WHERE id=?1",
        params![id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
    )?;
    db.execute("UPDATE tokens SET row_mac=?1 WHERE id=?2", params![token_row_mac(k, id, &name, &mac, &role, &rules, exp, rev).to_vec(), id])?;
    Ok(())
}

fn next_version(db: &Connection, id: &str) -> R<i64> {
    let max: i64 =
        db.query_row("SELECT COALESCE(MAX(version),0) FROM versions WHERE secret_id=?1", params![id], |r| r.get(0))?;
    Ok(max + 1)
}

fn put_version(db: &Connection, k: &Keys, id: &str, v: i64, value: &[u8], by: &str, state: &str) -> R<()> {
    let dek = Key::random()?;
    let ct = crypto::seal(&dek, &aad_value(id, v), value)?;
    let wrapped = crypto::wrap_key(&k.wrap, &aad_dek(id, v), &dek)?;
    db.execute(
        "INSERT INTO versions (secret_id,version,state,created_at,created_by,wrapped_dek,ciphertext)
         VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![id, v, state, now(), by, wrapped, ct],
    )?;
    Ok(())
}

fn read_version(db: &Connection, k: &Keys, id: &str, v: i64) -> R<Zeroizing<String>> {
    let row: Option<(Vec<u8>, Vec<u8>)> = db
        .query_row(
            "SELECT wrapped_dek,ciphertext FROM versions WHERE secret_id=?1 AND version=?2",
            params![id, v],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (wrapped, ct) = row.ok_or(VErr::NotFound)?;
    let dek = crypto::unwrap_key(&k.wrap, &aad_dek(id, v), &wrapped)?;
    let pt = crypto::open(&dek, &aad_value(id, v), &ct)?;
    let s = std::str::from_utf8(&pt).map_err(|_| VErr::Internal("stored value is not UTF-8".into()))?;
    Ok(Zeroizing::new(s.to_string()))
}

fn set_current(db: &Connection, k: &Keys, id: &str, v: i64) -> R<()> {
    db.execute("UPDATE versions SET state='previous' WHERE secret_id=?1 AND state='current'", params![id])?;
    db.execute("UPDATE versions SET state='current' WHERE secret_id=?1 AND version=?2", params![id, v])?;
    db.execute("UPDATE secrets SET current_version=?1, updated_at=?2 WHERE id=?3", params![v, now(), id])?;
    reseal_secret_row(db, k, id)
}

fn promote_new(db: &Connection, k: &Keys, id: &str, value: &[u8], by: &str) -> R<i64> {
    let v = next_version(db, id)?;
    put_version(db, k, id, v, value, by, "pending")?;
    set_current(db, k, id, v)?;
    Ok(v)
}

/// Token format: `jw_<16 hex id>_<43 char base64url secret>` (256-bit secret).
fn new_token(k: &Keys) -> R<(String, Zeroizing<String>, [u8; 32])> {
    let id = random_id(8)?;
    let secret = generate::generate(&Policy::Base64url { bytes: 32 }).map_err(|e| VErr::Internal(e.to_string()))?;
    let token = Zeroizing::new(format!("jw_{id}_{}", secret.as_str()));
    let mac = crypto::mac(&k.token, &[token.as_bytes()]);
    Ok((id, token, mac))
}

fn parse_token(t: &str) -> Option<(&str, &str)> {
    let rest = t.strip_prefix("jw_")?;
    let (id, secret) = rest.split_at_checked(16)?;
    let secret = secret.strip_prefix('_')?;
    if !id.bytes().all(|b| b.is_ascii_hexdigit()) || secret.len() != 43 {
        return None;
    }
    Some((id, secret))
}

#[allow(clippy::too_many_arguments)]
fn audit_mac(k: &Keys, prev: &[u8], seq: i64, ts: i64, actor: &str, action: &str, path: &str, outcome: &str, detail: &str) -> [u8; 32] {
    crypto::mac(
        &k.audit,
        &[
            prev,
            &seq.to_be_bytes(),
            &ts.to_be_bytes(),
            actor.as_bytes(),
            action.as_bytes(),
            path.as_bytes(),
            outcome.as_bytes(),
            detail.as_bytes(),
        ],
    )
}

fn audit_tx(db: &Connection, k: &Keys, actor: &str, action: &str, path: &str, outcome: &str, detail: &str) -> R<()> {
    // Keep log lines bounded and single-line.
    let clean = |s: &str, n: usize| -> String { s.chars().filter(|c| !c.is_control()).take(n).collect() };
    let (actor, path, detail) = (clean(actor, 128), clean(path, 256), clean(detail, 512));
    let last: Option<(i64, Vec<u8>)> = db
        .query_row("SELECT seq,mac FROM audit ORDER BY seq DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    let (seq, prev) = match last {
        Some((s, m)) => (s + 1, m),
        None => (1, Vec::new()),
    };
    let ts = now();
    let mac = audit_mac(k, &prev, seq, ts, &actor, action, &path, outcome, &detail);
    db.execute(
        "INSERT INTO audit (seq,ts,actor,action,path,outcome,detail,mac) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![seq, ts, actor, action, path, outcome, detail, mac.to_vec()],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "correct horse battery staple";

    fn vault() -> (Vault, Actor, InitOutput) {
        let v = Vault::open(":memory:", KdfParams::TEST, KdfParams::TEST).unwrap();
        let out = v.init(PASS).unwrap();
        let root = v.authenticate(&out.root_token).unwrap();
        (v, root, out)
    }

    fn agent(v: &Vault, root: &Actor, caps: Vec<Cap>) -> Actor {
        let (_, t) = v
            .create_token(root, "agent-1", Role::Agent, vec![Rule { path: "infra/**".into(), caps }], None)
            .unwrap();
        v.authenticate(&t).unwrap()
    }

    #[test]
    fn init_once_and_seal_cycle() {
        let (v, root, out) = vault();
        assert!(matches!(v.init(PASS), Err(VErr::AlreadyInitialized)));
        v.create(&root, "infra/a", "password", Meta::default(), Some(Zeroizing::new("s3cret-value".into())), None).unwrap();
        v.seal(&root).unwrap();
        assert!(matches!(v.authenticate(&out.root_token), Err(VErr::Sealed)));
        assert!(matches!(v.list(&root, ""), Err(VErr::Sealed)));
        assert!(matches!(v.unseal("wrong passphrase!!"), Err(VErr::Unauthorized)));
        // No lockout: a failed guess by someone else must not block the owner.
        v.unseal(PASS).unwrap();
        assert!(matches!(v.unseal(PASS), Err(VErr::Conflict(_))));
        assert_eq!(v.reveal(&root, "infra/a", None).unwrap().as_str(), "s3cret-value");
        v.seal(&root).unwrap();
        v.unseal(&out.recovery_key).unwrap();
        assert_eq!(v.reveal(&root, "infra/a", None).unwrap().as_str(), "s3cret-value");
    }

    #[test]
    fn cards_and_gift_cards() {
        let (v, root, _) = vault();
        let val = |s: &str| Some(Zeroizing::new(s.to_string()));
        let visa = r#"{"number":"4111111111111111","cvv":"123"}"#;
        let mc = r#"{"number":"5555555555554444","cvv":"321"}"#;

        // The vault derives brand and last four; a lying client is overruled.
        let lie = Meta {
            title: "Everyday".into(),
            card: Some(CardInfo { brand: "Amex".into(), last4: "0000".into(), exp_month: 8, exp_year: 2029, ..Default::default() }),
            ..Default::default()
        };
        let c = v.create(&root, "infra/visa", "card", lie, val(visa), None).unwrap();
        let info = c.meta.card.unwrap();
        assert_eq!((info.brand.as_str(), info.last4.as_str(), info.exp_month), ("Visa", "1111", 8));
        assert!(c.balance_cents.is_none());
        assert_eq!(v.reveal(&root, "infra/visa", None).unwrap().as_str(), visa);

        // No number, a malformed one, or a generated one: all refused.
        assert!(matches!(v.create(&root, "infra/none", "card", Meta::default(), None, None), Err(VErr::BadRequest(_))));
        assert!(matches!(v.create(&root, "infra/junk", "card", Meta::default(), val("4111111111111111"), None), Err(VErr::BadRequest(_))));
        assert!(matches!(v.generate(&root, "infra/visa", None), Err(VErr::BadRequest(_))));
        assert_eq!(v.get(&root, "infra/visa").unwrap().secret.current_version, 1);

        // A replacement card updates the label by itself; restoring puts it back.
        let c = v.update(&root, "infra/visa", None, val(mc)).unwrap();
        let info = c.meta.card.unwrap();
        assert_eq!((info.brand.as_str(), info.last4.as_str(), info.exp_year), ("Mastercard", "4444", 2029));
        let c = v.restore_version(&root, "infra/visa", 1).unwrap();
        assert_eq!(c.meta.card.unwrap().last4, "1111");

        // Card details do not leak onto ordinary items.
        let stray = Meta { card: Some(CardInfo::default()), gift: Some(GiftInfo::default()), ..Default::default() };
        let p = v.create(&root, "infra/pw", "password", stray, None, None).unwrap();
        assert!(p.meta.card.is_none() && p.meta.gift.is_none());

        // Gift card: balance is the start minus the ledger.
        let gift = Meta {
            gift: Some(GiftInfo { merchant: "Bookshop".into(), initial_cents: 5000, ..Default::default() }),
            ..Default::default()
        };
        let g = v.create(&root, "infra/gift", "gift_card", gift, val(r#"{"number":"ABCD-1234-XYZ9","pin":"8842"}"#), None).unwrap();
        assert_eq!(g.balance_cents, Some(5000));
        assert_eq!(g.meta.gift.as_ref().unwrap().last4, "XYZ9");

        // An agent that may edit details can record a spend but never see the number.
        let a = agent(&v, &root, vec![Cap::List, Cap::Update]);
        let g = v.ledger_add(&a, "infra/gift", -1234, "lunch").unwrap();
        assert_eq!(g.balance_cents, Some(3766));
        assert!(matches!(v.reveal(&a, "infra/gift", None), Err(VErr::Forbidden)));
        assert!(matches!(v.ledger_add(&a, "infra/gift", -9999, ""), Err(VErr::BadRequest(m)) if m.contains("37.66")));
        assert!(matches!(v.ledger_add(&a, "infra/gift", 0, ""), Err(VErr::BadRequest(_))));
        assert!(matches!(v.ledger_add(&a, "infra/visa", -100, ""), Err(VErr::BadRequest(_))));
        let reader = agent(&v, &root, vec![Cap::List]);
        assert!(matches!(v.ledger_add(&reader, "infra/gift", -100, ""), Err(VErr::Forbidden)));
        assert_eq!(v.ledger_add(&root, "infra/gift", 2000, "reload").unwrap().balance_cents, Some(5766));

        // Editing details cannot rewrite history or relabel the card.
        let mut m = v.get(&root, "infra/gift").unwrap().secret.meta;
        let gi = m.gift.as_mut().unwrap();
        gi.ledger.clear();
        gi.last4 = "0000".into();
        gi.merchant = "Corner Bookshop".into();
        let g = v.update(&root, "infra/gift", Some(m), None).unwrap();
        let gi = g.meta.gift.unwrap();
        assert_eq!((gi.ledger.len(), gi.last4.as_str(), gi.merchant.as_str()), (2, "XYZ9", "Corner Bookshop"));
        assert_eq!(g.balance_cents, Some(5766));
        assert_eq!(gi.ledger[0].by, a.label());

        // Old stored metadata (no card fields) still reads, and stays byte-compatible.
        assert_eq!(serde_json::to_string(&Meta::default()).unwrap().contains("card"), false);
    }

    #[test]
    fn weak_passphrase_rejected() {
        let v = Vault::open(":memory:", KdfParams::TEST, KdfParams::TEST).unwrap();
        assert!(matches!(v.init("short"), Err(VErr::BadRequest(_))));
    }

    #[test]
    fn agent_cannot_reveal_or_administer() {
        let (v, root, _) = vault();
        let a = agent(&v, &root, vec![Cap::List, Cap::Create, Cap::Generate, Cap::Rotate, Cap::Update]);
        let s = v.create(&a, "infra/db", "password", Meta::default(), None, None).unwrap();
        assert_eq!(s.current_version, 1);
        assert!(matches!(v.reveal(&a, "infra/db", None), Err(VErr::Forbidden)));
        assert!(matches!(v.create(&a, "office/x", "password", Meta::default(), None, None), Err(VErr::Forbidden)));
        assert!(matches!(v.list_tokens(&a), Err(VErr::Forbidden)));
        assert!(matches!(v.audit_list(&a, 10, None), Err(VErr::Forbidden)));
        assert!(matches!(v.set_driver(&a, "infra/db", None), Err(VErr::Forbidden)));
        assert!(matches!(v.seal(&a), Err(VErr::Forbidden)));
        assert!(matches!(
            v.create_token(&a, "x", Role::Admin, vec![], None),
            Err(VErr::Forbidden)
        ));
        // Reveal cannot be smuggled into an agent token at creation either.
        assert!(matches!(
            v.create_token(&root, "sneaky", Role::Agent, vec![Rule { path: "**".into(), caps: vec![Cap::Reveal] }], None),
            Err(VErr::BadRequest(_))
        ));
    }

    #[test]
    fn list_is_filtered_by_policy() {
        let (v, root, _) = vault();
        v.create(&root, "infra/a", "password", Meta::default(), None, None).unwrap();
        v.create(&root, "office/nas", "password", Meta::default(), None, None).unwrap();
        let a = agent(&v, &root, vec![Cap::List]);
        let seen: Vec<String> = v.list(&a, "").unwrap().into_iter().map(|s| s.path).collect();
        assert_eq!(seen, vec!["infra/a"]);
        assert!(matches!(v.get(&a, "office/nas"), Err(VErr::Forbidden)));
    }

    #[test]
    fn versions_and_history() {
        let (v, root, _) = vault();
        v.create(&root, "infra/k", "api_key", Meta::default(), Some(Zeroizing::new("one-value".into())), None).unwrap();
        v.update(&root, "infra/k", None, Some(Zeroizing::new("two-value".into()))).unwrap();
        let g = v.generate(&root, "infra/k", Some(Policy::Hex { bytes: 32 })).unwrap();
        assert_eq!(g.current_version, 3);
        assert_eq!(v.reveal(&root, "infra/k", Some(1)).unwrap().as_str(), "one-value");
        assert_eq!(v.reveal(&root, "infra/k", Some(2)).unwrap().as_str(), "two-value");
        assert_eq!(v.reveal(&root, "infra/k", None).unwrap().len(), 64);
        let d = v.get(&root, "infra/k").unwrap();
        let states: Vec<&str> = d.versions.iter().map(|x| x.state.as_str()).collect();
        assert_eq!(states, vec!["current", "previous", "previous"]);
        assert!(matches!(v.reveal(&root, "infra/k", Some(99)), Err(VErr::NotFound)));
    }

    #[test]
    fn ciphertext_cannot_be_swapped_between_rows() {
        let (v, root, _) = vault();
        v.create(&root, "infra/a", "password", Meta::default(), Some(Zeroizing::new("value-of-a".into())), None).unwrap();
        v.create(&root, "infra/b", "password", Meta::default(), Some(Zeroizing::new("value-of-b".into())), None).unwrap();
        {
            let db = v.db();
            // Attacker with DB write access copies A's encrypted version onto B.
            db.execute(
                "UPDATE versions SET wrapped_dek=(SELECT wrapped_dek FROM versions v2 JOIN secrets s ON s.id=v2.secret_id WHERE s.path='infra/a'),
                                     ciphertext=(SELECT ciphertext FROM versions v2 JOIN secrets s ON s.id=v2.secret_id WHERE s.path='infra/a')
                 WHERE secret_id=(SELECT id FROM secrets WHERE path='infra/b')",
                [],
            )
            .unwrap();
        }
        assert!(matches!(v.reveal(&root, "infra/b", None), Err(VErr::Internal(_))));
        assert_eq!(v.reveal(&root, "infra/a", None).unwrap().as_str(), "value-of-a");
    }

    #[test]
    fn nothing_sensitive_is_stored_in_clear() {
        let (v, root, out) = vault();
        let meta = Meta { username: "svc-account-zebra".into(), notes: "note-giraffe".into(), ..Default::default() };
        v.create(&root, "infra/a", "password", meta, Some(Zeroizing::new("plaintext-walrus".into())), None).unwrap();
        let db = v.db();
        let mut dump = Vec::new();
        for (table, cols) in [
            ("meta", "k || v"),
            ("secrets", "hex(meta_blob) || path"),
            ("versions", "hex(ciphertext) || hex(wrapped_dek)"),
            ("tokens", "hex(mac) || name || rules"),
            ("audit", "actor || action || path || detail"),
        ] {
            let mut st = db.prepare(&format!("SELECT {cols} FROM {table}")).unwrap();
            let rows: Vec<String> = st.query_map([], |r| r.get(0)).unwrap().map(|x| x.unwrap()).collect();
            dump.extend(rows);
        }
        let all = dump.join("\n");
        let secret_part = out.root_token.rsplit('_').next().unwrap();
        for needle in ["plaintext-walrus", "svc-account-zebra", "note-giraffe", secret_part, PASS] {
            assert!(!all.contains(needle), "{needle} found in database");
            assert!(!all.contains(&hex::encode_upper(needle)), "{needle} found hex-encoded");
        }
    }

    #[test]
    fn tokens_expire_and_revoke() {
        let (v, root, _) = vault();
        let (id, t) = v.create_token(&root, "tmp", Role::Human, vec![], Some(1)).unwrap();
        assert!(v.authenticate(&t).is_ok());
        {
            let db = v.db();
            db.execute("UPDATE tokens SET expires_at=?1 WHERE id=?2", params![now() - 1, id]).unwrap();
            v.with_keys(|k| reseal_token_row(&db, k, &id)).unwrap();
        }
        assert!(matches!(v.authenticate(&t), Err(VErr::Unauthorized)));
        let (id2, t2) = v.create_token(&root, "tmp2", Role::Human, vec![], None).unwrap();
        v.revoke_token(&root, &id2).unwrap();
        assert!(matches!(v.authenticate(&t2), Err(VErr::Unauthorized)));
        // Right id, wrong secret; malformed; empty.
        let forged = format!("jw_{id2}_{}", "A".repeat(43));
        for bad in [forged.as_str(), "jw_zz", "", "Bearer x", "jw_0000000000000000_short"] {
            assert!(matches!(v.authenticate(bad), Err(VErr::Unauthorized)), "{bad}");
        }
    }

    #[test]
    fn audit_chain_detects_tampering() {
        let (v, root, _) = vault();
        v.create(&root, "infra/a", "password", Meta::default(), None, None).unwrap();
        v.reveal(&root, "infra/a", None).unwrap();
        let (n, bad) = v.audit_verify(&root).unwrap();
        assert!(n >= 3 && bad.is_none());
        v.db().execute("UPDATE audit SET actor='nobody' WHERE action='secret.reveal'", []).unwrap();
        assert!(v.audit_verify(&root).unwrap().1.is_some());
    }

    #[test]
    fn audit_chain_detects_deleted_row() {
        let (v, root, _) = vault();
        v.create(&root, "infra/a", "password", Meta::default(), None, None).unwrap();
        v.reveal(&root, "infra/a", None).unwrap();
        v.reveal(&root, "infra/a", None).unwrap();
        v.db().execute("DELETE FROM audit WHERE seq=3", []).unwrap();
        assert!(v.audit_verify(&root).unwrap().1.is_some());
    }

    #[test]
    fn rotation_success_and_failure() {
        let (v, root, _) = vault();
        v.create(&root, "infra/r", "password", Meta::default(), Some(Zeroizing::new("original-pw".into())), None).unwrap();
        let a = agent(&v, &root, vec![Cap::Rotate, Cap::List]);
        assert!(matches!(v.rotate_prepare(&a, "infra/r"), Err(VErr::BadRequest(_))));
        let d = Driver::Exec { argv: vec!["/usr/bin/true".into()], stdin: "{{new}}".into(), timeout_secs: 5 };
        v.set_driver(&root, "infra/r", Some(d.into())).unwrap();

        let job = v.rotate_prepare(&a, "infra/r").unwrap();
        assert_eq!(job.old_value.as_str(), "original-pw");
        assert!(matches!(v.rotate_prepare(&a, "infra/r"), Err(VErr::Conflict(_))));
        // Until the driver confirms, the old value stays current.
        assert_eq!(v.reveal(&root, "infra/r", None).unwrap().as_str(), "original-pw");
        v.rotate_finish(&job, Err("remote refused".into())).unwrap();
        assert_eq!(v.reveal(&root, "infra/r", None).unwrap().as_str(), "original-pw");
        assert_eq!(v.reveal(&root, "infra/r", Some(2)).unwrap().as_str(), job.new_value.as_str());

        let job2 = v.rotate_prepare(&a, "infra/r").unwrap();
        v.rotate_finish(&job2, Ok(())).unwrap();
        assert_eq!(v.reveal(&root, "infra/r", None).unwrap().as_str(), job2.new_value.as_str());
        let states: Vec<String> = v.get(&root, "infra/r").unwrap().versions.into_iter().map(|x| x.state).collect();
        assert_eq!(states, vec!["current", "failed", "previous"]);
        // Agents never see driver config.
        assert!(v.get(&a, "infra/r").unwrap().driver.is_none());
    }

    #[test]
    fn delete_frees_path_and_hides_secret() {
        let (v, root, _) = vault();
        v.create(&root, "infra/d", "password", Meta::default(), None, None).unwrap();
        v.delete(&root, "infra/d").unwrap();
        assert!(matches!(v.get(&root, "infra/d"), Err(VErr::NotFound)));
        assert!(v.list(&root, "").unwrap().is_empty());
        v.create(&root, "infra/d", "password", Meta::default(), None, None).unwrap();
    }

    #[test]
    fn change_passphrase() {
        let (v, root, _) = vault();
        assert!(matches!(v.change_passphrase(&root, "not the passphrase", "another long passphrase"), Err(VErr::Forbidden)));
        v.change_passphrase(&root, PASS, "another long passphrase").unwrap();
        v.seal(&root).unwrap();
        assert!(v.unseal(PASS).is_err());
        v.unseal("another long passphrase").unwrap();
    }

    #[test]
    fn direct_database_edits_are_detected() {
        let (v, root, _) = vault();
        v.create(&root, "infra/a", "password", Meta::default(), Some(Zeroizing::new("value-of-a".into())), None).unwrap();
        v.create(&root, "infra/b", "password", Meta::default(), Some(Zeroizing::new("value-of-b".into())), None).unwrap();
        v.update(&root, "infra/b", None, Some(Zeroizing::new("value-of-b2".into()))).unwrap();
        let (aid, agent_tok) = v
            .create_token(&root, "ag", Role::Agent, vec![Rule { path: "infra/**".into(), caps: vec![Cap::List] }], None)
            .unwrap();
        let (rid, revoked_tok) = v.create_token(&root, "old", Role::Human, vec![], None).unwrap();
        v.revoke_token(&root, &rid).unwrap();
        assert!(v.authenticate(&agent_tok).is_ok());
        {
            let db = v.db();
            // 1. Swap the paths of two secrets so `infra/a` would return b's value.
            db.execute_batch(
                "UPDATE secrets SET path='tmp' WHERE path='infra/a';
                 UPDATE secrets SET path='infra/a' WHERE path='infra/b';
                 UPDATE secrets SET path='infra/b' WHERE path='tmp';",
            )
            .unwrap();
            // 2. Promote an agent token to admin. 3. Un-revoke a revoked token.
            db.execute("UPDATE tokens SET role='admin' WHERE id=?1", params![aid]).unwrap();
            db.execute("UPDATE tokens SET revoked_at=NULL WHERE id=?1", params![rid]).unwrap();
        }
        assert!(matches!(v.reveal(&root, "infra/a", None), Err(VErr::Internal(_))));
        assert!(matches!(v.list(&root, ""), Err(VErr::Internal(_))));
        assert!(matches!(v.authenticate(&agent_tok), Err(VErr::Unauthorized)));
        assert!(matches!(v.authenticate(&revoked_tok), Err(VErr::Unauthorized)));
    }

    #[test]
    fn version_rollback_is_detected() {
        let (v, root, _) = vault();
        v.create(&root, "infra/a", "password", Meta::default(), Some(Zeroizing::new("old-leaked".into())), None).unwrap();
        v.update(&root, "infra/a", None, Some(Zeroizing::new("new-value".into()))).unwrap();
        v.db().execute("UPDATE secrets SET current_version=1", []).unwrap();
        assert!(matches!(v.reveal(&root, "infra/a", None), Err(VErr::Internal(_))));
    }

    #[test]
    fn write_capability_is_separate_from_update() {
        let (v, root, _) = vault();
        let a = agent(&v, &root, vec![Cap::List, Cap::Create, Cap::Update, Cap::Generate]);
        // An agent without `write` cannot choose a secret's value, at create or later.
        assert!(matches!(
            v.create(&a, "infra/x", "password", Meta::default(), Some(Zeroizing::new("i-know-this".into())), None),
            Err(VErr::Forbidden)
        ));
        v.create(&a, "infra/x", "password", Meta::default(), None, None).unwrap();
        assert!(matches!(v.update(&a, "infra/x", None, Some(Zeroizing::new("i-know-this".into()))), Err(VErr::Forbidden)));
        let m = Meta { username: "svc".into(), ..Default::default() };
        assert_eq!(v.update(&a, "infra/x", Some(m), None).unwrap().meta.username, "svc");
    }

    #[test]
    fn folders_move_rename_and_delete() {
        let (v, root, _) = vault();
        let val = |s: &str| Some(Zeroizing::new(s.to_string()));
        v.create(&root, "personal/github", "password", Meta::default(), val("gh-password"), None).unwrap();
        v.create(&root, "personal/banks/chase", "password", Meta::default(), val("chase-password"), None).unwrap();
        v.create(&root, "work/vpn", "password", Meta::default(), val("vpn-password"), None).unwrap();
        v.create_folder(&root, "business").unwrap();
        v.create_folder(&root, "personal/empty-sub").unwrap();
        let names = |v: &Vault| v.folders(&root).unwrap().into_iter().map(|f| format!("{}:{}", f.path, f.count)).collect::<Vec<_>>();
        assert_eq!(names(&v), ["business:0", "personal:2", "personal/banks:1", "personal/empty-sub:0", "work:1"]);

        // Move one item; its value and history come along.
        v.move_secret(&root, "work/vpn", "business/vpn").unwrap();
        assert_eq!(v.reveal(&root, "business/vpn", None).unwrap().as_str(), "vpn-password");
        assert!(matches!(v.get(&root, "work/vpn"), Err(VErr::NotFound)));
        assert!(matches!(v.move_secret(&root, "business/vpn", "personal/github"), Err(VErr::Conflict(_))));

        // Rename a folder: sub-folders (even empty ones) follow.
        assert_eq!(v.move_folder(&root, "personal", "home").unwrap(), 2);
        assert_eq!(v.reveal(&root, "home/banks/chase", None).unwrap().as_str(), "chase-password");
        assert_eq!(names(&v), ["business:1", "home:2", "home/banks:1", "home/empty-sub:0"]);
        assert!(matches!(v.move_folder(&root, "home", "home/inner"), Err(VErr::BadRequest(_))));

        // Delete a folder but keep its items by moving them elsewhere.
        assert_eq!(v.delete_folder(&root, "home/banks", Some("business")).unwrap(), 1);
        assert_eq!(v.reveal(&root, "business/chase", None).unwrap().as_str(), "chase-password");
        // Delete a folder and everything in it.
        assert_eq!(v.delete_folder(&root, "business", None).unwrap(), 2);
        assert!(matches!(v.get(&root, "business/chase"), Err(VErr::NotFound)));
        assert_eq!(names(&v), ["home:1", "home/empty-sub:0"]);
        assert!(v.audit_verify(&root).unwrap().1.is_none());
    }

    #[test]
    fn moving_respects_permissions_and_cannot_gain_reveal() {
        let (v, root, _) = vault();
        v.create(&root, "work/vpn", "password", Meta::default(), Some(Zeroizing::new("vpn-password".into())), None).unwrap();
        v.create(&root, "infra/a", "password", Meta::default(), None, None).unwrap();
        // Agent scoped to infra cannot pull a work item into its own area, or push one out.
        let a = agent(&v, &root, vec![Cap::List, Cap::Create, Cap::Delete]);
        assert!(matches!(v.move_secret(&a, "work/vpn", "infra/vpn"), Err(VErr::Forbidden)));
        assert!(matches!(v.move_secret(&a, "infra/a", "work/a"), Err(VErr::Forbidden)));
        assert!(matches!(v.move_folder(&a, "work", "infra/work"), Err(VErr::Forbidden)));
        assert!(matches!(v.delete_folder(&a, "work", None), Err(VErr::Forbidden)));
        v.move_secret(&a, "infra/a", "infra/sub/a").unwrap();
        // A person who may delete in `work` and read values in `personal`
        // must not be able to read work passwords by moving them over.
        let (_, t) = v
            .create_token(
                &root,
                "mover",
                Role::Human,
                vec![
                    Rule { path: "work/**".into(), caps: vec![Cap::List, Cap::Delete] },
                    Rule { path: "personal/**".into(), caps: vec![Cap::List, Cap::Create, Cap::Reveal] },
                ],
                None,
            )
            .unwrap();
        let h = v.authenticate(&t).unwrap();
        assert!(matches!(v.move_secret(&h, "work/vpn", "personal/vpn"), Err(VErr::Forbidden)));
        assert!(matches!(v.move_folder(&h, "work", "personal/work"), Err(VErr::Forbidden)));
        assert_eq!(v.reveal(&root, "work/vpn", None).unwrap().as_str(), "vpn-password");
    }

    #[test]
    fn scheduled_rotations_come_due_and_back_off() {
        let (v, root, _) = vault();
        let val = |s: &str| Some(Zeroizing::new(s.to_string()));
        let drv = |days| RotationSetup { driver: Driver::Exec { argv: vec!["/usr/bin/true".into()], stdin: "{{new}}".into(), timeout_secs: 5 }, every_days: days };
        for p in ["a/fresh", "a/old", "a/manual", "a/none"] {
            v.create(&root, p, "password", Meta::default(), val("starting-value"), None).unwrap();
        }
        v.set_driver(&root, "a/fresh", Some(drv(Some(90)))).unwrap();
        v.set_driver(&root, "a/old", Some(drv(Some(90)))).unwrap();
        v.set_driver(&root, "a/manual", Some(drv(None))).unwrap();
        assert_eq!(v.list(&root, "a/old").unwrap()[0].rotate_every_days, Some(90));
        assert!(v.due_rotations().unwrap().is_empty());
        let age = |path: &str, days: i64| {
            v.db().execute("UPDATE versions SET created_at=?1 WHERE secret_id=(SELECT id FROM secrets WHERE path=?2)", params![now() - days * 86400, path]).unwrap();
        };
        age("a/old", 91);
        age("a/manual", 400);
        age("a/none", 400);
        assert_eq!(v.due_rotations().unwrap(), vec!["a/old"]);
        // A failed attempt today is not retried until tomorrow.
        let sched = Vault::schedule_actor();
        let job = v.rotate_prepare(&sched, "a/old").unwrap();
        assert!(v.due_rotations().unwrap().is_empty(), "pending rotations are not started twice");
        v.rotate_finish(&job, Err("target down".into())).unwrap();
        assert!(v.due_rotations().unwrap().is_empty());
        v.db().execute("UPDATE versions SET created_at=?1 WHERE state='failed'", params![now() - 2 * 86400]).unwrap();
        assert_eq!(v.due_rotations().unwrap(), vec!["a/old"]);
        // Success resets the clock.
        let job = v.rotate_prepare(&sched, "a/old").unwrap();
        v.rotate_finish(&job, Ok(())).unwrap();
        assert!(v.due_rotations().unwrap().is_empty());
        assert_eq!(v.get(&root, "a/old").unwrap().versions[0].created_by, "schedule:vault");
        v.seal(&root).unwrap();
        assert!(matches!(v.due_rotations(), Err(VErr::Sealed)));
    }

    #[test]
    fn restore_brings_back_an_old_password_as_a_new_version() {
        let (v, root, _) = vault();
        let val = |s: &str| Some(Zeroizing::new(s.to_string()));
        v.create(&root, "home/power", "password", Meta::default(), val("the-old-one"), None).unwrap();
        v.update(&root, "home/power", None, val("the-new-one")).unwrap();
        let s = v.restore_version(&root, "home/power", 1).unwrap();
        assert_eq!(s.current_version, 3);
        assert_eq!(v.reveal(&root, "home/power", None).unwrap().as_str(), "the-old-one");
        assert_eq!(v.reveal(&root, "home/power", Some(2)).unwrap().as_str(), "the-new-one");
        assert!(matches!(v.restore_version(&root, "home/power", 3), Err(VErr::BadRequest(_))));
        assert!(matches!(v.restore_version(&root, "home/power", 9), Err(VErr::NotFound)));
        // An agent may put an old version back without ever seeing it; one without the right may not.
        let (_, t) = v.create_token(&root, "ag", Role::Agent, vec![Rule { path: "home/**".into(), caps: vec![Cap::List, Cap::Generate] }], None).unwrap();
        let ag = v.authenticate(&t).unwrap();
        assert_eq!(v.restore_version(&ag, "home/power", 2).unwrap().current_version, 4);
        assert!(matches!(v.reveal(&ag, "home/power", None), Err(VErr::Forbidden)));
        let (_, t) = v.create_token(&root, "ro", Role::Agent, vec![Rule { path: "home/**".into(), caps: vec![Cap::List] }], None).unwrap();
        assert!(matches!(v.restore_version(&v.authenticate(&t).unwrap(), "home/power", 1), Err(VErr::Forbidden)));
        // Word passwords are a valid stored shape and generate inside the vault.
        let words = jaword_core::generate::Policy::Words { words: 5, separator: "-".into(), capitalize: true, number: false };
        let g = v.generate(&root, "home/power", Some(words)).unwrap();
        assert_eq!(v.reveal(&root, "home/power", None).unwrap().split('-').count(), 5);
        assert!(g.meta.policy.is_some());
    }

    #[test]
    fn sys_is_reserved() {
        let (v, root, _) = vault();
        v.create(&root, "personal/a", "password", Meta::default(), None, None).unwrap();
        assert!(matches!(v.create(&root, "sys/update", "password", Meta::default(), None, None), Err(VErr::BadRequest(_))));
        assert!(matches!(v.create(&root, "sys/x/y", "password", Meta::default(), None, None), Err(VErr::BadRequest(_))));
        assert!(matches!(v.create_folder(&root, "sys"), Err(VErr::BadRequest(_))));
        assert!(matches!(v.move_secret(&root, "personal/a", "sys/a"), Err(VErr::BadRequest(_))));
        assert!(matches!(v.move_folder(&root, "personal", "sys"), Err(VErr::BadRequest(_))));
        assert!(matches!(v.delete_folder(&root, "personal", Some("sys")), Err(VErr::BadRequest(_))));
        // Folder tokens can no longer carry the update permission.
        assert!(matches!(
            v.create_token(&root, "t", Role::Agent, vec![Rule { path: "personal/**".into(), caps: vec![Cap::List, Cap::Upgrade] }], None),
            Err(VErr::BadRequest(_))
        ));
        let (_, t) = v.create_token(&root, "updater", Role::Agent, vec![Rule { path: "sys/update".into(), caps: vec![Cap::Upgrade] }], None).unwrap();
        assert!(v.authorize_upgrade(&v.authenticate(&t).unwrap(), "check").is_ok());
        assert!(v.get(&root, "personal/a").is_ok());
    }

    #[test]
    fn input_limits() {
        let (v, root, _) = vault();
        let big = Zeroizing::new("x".repeat(MAX_VALUE + 1));
        assert!(matches!(v.create(&root, "infra/big", "password", Meta::default(), Some(big), None), Err(VErr::BadRequest(_))));
        assert!(matches!(v.create(&root, "infra/../x", "password", Meta::default(), None, None), Err(VErr::BadRequest(_))));
        assert!(matches!(v.create(&root, "infra/k", "bogus", Meta::default(), None, None), Err(VErr::BadRequest(_))));
        v.create(&root, "infra/k", "password", Meta::default(), None, None).unwrap();
        assert!(matches!(v.create(&root, "infra/k", "password", Meta::default(), None, None), Err(VErr::Conflict(_))));
    }
}
