//! HTTP API and embedded web UI.
//!
//! Auth is a bearer token in the `Authorization` header only (no cookies), so
//! cross-site request forgery has nothing to ride on. On top of that the
//! server pins the `Host` header (DNS-rebinding defence), rejects foreign
//! `Origin`s, caps body size and sends a strict Content-Security-Policy.

use axum::{
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use jaword_core::{
    access::{Role, Rule},
    generate::Policy,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::drivers::{self, RotationSetup};
use crate::store::{Actor, Meta, VErr, Vault};

const AUTH_FAILS_PER_MIN: u32 = 20;

pub struct App {
    pub vault: Vault,
    pub updater: crate::update::Updater,
    pub allowed_hosts: Vec<String>,
    fails: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl App {
    pub fn new(vault: Vault, allowed_hosts: Vec<String>) -> App {
        App { vault, updater: crate::update::Updater::from_env(), allowed_hosts, fails: Mutex::new(HashMap::new()) }
    }

    fn blocked(&self, ip: IpAddr) -> bool {
        let mut m = self.fails.lock().unwrap_or_else(|p| p.into_inner());
        m.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(60));
        matches!(m.get(&ip), Some((n, _)) if *n >= AUTH_FAILS_PER_MIN)
    }

    fn note_failure(&self, ip: IpAddr) {
        let mut m = self.fails.lock().unwrap_or_else(|p| p.into_inner());
        if m.len() > 10_000 {
            m.clear();
        }
        m.entry(ip).or_insert((0, Instant::now())).0 += 1;
    }
}

type S = State<Arc<App>>;
type Ip = ConnectInfo<SocketAddr>;

pub struct ApiErr(VErr);
impl From<VErr> for ApiErr {
    fn from(e: VErr) -> Self {
        ApiErr(e)
    }
}
type Res = Result<Json<Value>, ApiErr>;

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        let (code, err, msg): (StatusCode, &str, String) = match self.0 {
            VErr::Sealed => (StatusCode::SERVICE_UNAVAILABLE, "sealed", "vault is sealed".into()),
            VErr::NotInitialized => (StatusCode::SERVICE_UNAVAILABLE, "not_initialized", "vault is not initialized".into()),
            VErr::AlreadyInitialized => (StatusCode::CONFLICT, "already_initialized", "vault is already initialized".into()),
            VErr::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", "missing or invalid credentials".into()),
            VErr::Forbidden => (StatusCode::FORBIDDEN, "forbidden", "not permitted".into()),
            VErr::NotFound => (StatusCode::NOT_FOUND, "not_found", "not found".into()),
            VErr::Conflict(m) => (StatusCode::CONFLICT, "conflict", m),
            VErr::BadRequest(m) => (StatusCode::BAD_REQUEST, "bad_request", m),
            VErr::RateLimited(s) => {
                let mut r = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({"error": "rate_limited", "message": format!("too many attempts, retry in {s}s")})),
                )
                    .into_response();
                if let Ok(v) = HeaderValue::from_str(&s.to_string()) {
                    r.headers_mut().insert(header::RETRY_AFTER, v);
                }
                return r;
            }
            VErr::Internal(detail) => {
                // Details stay in the server log; clients get nothing to probe with.
                tracing::error!("internal error: {detail}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error".into())
            }
        };
        (code, Json(json!({"error": err, "message": msg}))).into_response()
    }
}

/// The address to attribute a request to. Behind a local reverse proxy
/// (e.g. `tailscale serve`) every connection comes from loopback, so the
/// proxy's `X-Forwarded-For` is used, and only then: a remote peer cannot
/// choose its own address by sending the header itself.
fn client_ip(peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    if !peer.is_loopback() {
        return peer;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(peer)
}

fn is_proxied(headers: &HeaderMap) -> bool {
    ["x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "forwarded", "tailscale-user-login"]
        .iter()
        .any(|h| headers.contains_key(*h))
}

fn actor(app: &App, headers: &HeaderMap, ip: IpAddr) -> Result<Actor, ApiErr> {
    let ip = client_ip(ip, headers);
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match token.map(|t| app.vault.authenticate(t)) {
        Some(Ok(a)) => Ok(a),
        Some(Err(VErr::Sealed)) => Err(VErr::Sealed.into()),
        Some(Err(VErr::Internal(e))) => Err(VErr::Internal(e).into()),
        _ => {
            // Valid tokens are never rate limited (256-bit secrets cannot be
            // guessed); the limiter only stops failed attempts from flooding
            // the audit log, without letting one noisy client lock out others
            // that share its address behind a reverse proxy.
            if app.blocked(ip) {
                return Err(VErr::RateLimited(60).into());
            }
            app.note_failure(ip);
            app.vault.log_anonymous(&format!("anonymous@{ip}"), "auth.fail", "");
            Err(VErr::Unauthorized.into())
        }
    }
}

// ------------------------------------------------------------------ guards

async fn guard(State(app): S, req: Request, next: Next) -> Response {
    let host_ok = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| app.allowed_hosts.iter().any(|a| a.eq_ignore_ascii_case(h)))
        .unwrap_or(false);
    let origin_ok = match req.headers().get(header::ORIGIN).and_then(|o| o.to_str().ok()) {
        None => true,
        Some(o) => {
            let hostpart = o.strip_prefix("https://").or_else(|| o.strip_prefix("http://")).unwrap_or("");
            app.allowed_hosts.iter().any(|a| a.eq_ignore_ascii_case(hostpart))
        }
    };
    let method_ok = matches!(*req.method(), Method::GET | Method::POST);
    let mut resp = if !host_ok || !origin_ok {
        (StatusCode::FORBIDDEN, Json(json!({"error": "forbidden", "message": "host or origin not allowed"}))).into_response()
    } else if !method_ok {
        StatusCode::METHOD_NOT_ALLOWED.into_response()
    } else {
        next.run(req).await
    };
    let h = resp.headers_mut();
    for (k, v) in [
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::CACHE_CONTROL, "no-store"),
        (header::STRICT_TRANSPORT_SECURITY, "max-age=31536000"),
    ] {
        // Static assets (fonts) may set their own caching; everything else is no-store.
        if k == header::CACHE_CONTROL && h.contains_key(header::CACHE_CONTROL) {
            continue;
        }
        h.insert(k, HeaderValue::from_static(v));
    }
    h.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
    h.insert("cross-origin-resource-policy", HeaderValue::from_static("same-origin"));
    h.insert("permissions-policy", HeaderValue::from_static("camera=(), microphone=(), geolocation=()"));
    resp
}

// ---------------------------------------------------------------- requests

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitReq {
    passphrase: Zeroizing<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnsealReq {
    credential: Zeroizing<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PassphraseReq {
    current: Zeroizing<String>,
    new: Zeroizing<String>,
}
#[derive(Deserialize)]
struct ListQ {
    #[serde(default)]
    prefix: String,
}
#[derive(Deserialize)]
struct PathQ {
    path: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateReq {
    path: String,
    #[serde(default = "d_kind")]
    kind: String,
    #[serde(default)]
    meta: Meta,
    /// Omit to have the vault generate the value (recommended for agents).
    #[serde(default)]
    value: Option<Zeroizing<String>>,
    #[serde(default)]
    policy: Option<Policy>,
}
fn d_kind() -> String {
    "password".into()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateReq {
    path: String,
    #[serde(default)]
    meta: Option<Meta>,
    #[serde(default)]
    value: Option<Zeroizing<String>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerateReq {
    path: String,
    #[serde(default)]
    policy: Option<Policy>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathReq {
    path: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevealReq {
    path: String,
    #[serde(default)]
    version: Option<i64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DriverReq {
    path: String,
    driver: Option<RotationSetup>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotTargetReq {
    host: String,
    #[serde(default)]
    port: Option<u16>,
    account: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotTrustReq {
    host: String,
    #[serde(default)]
    port: Option<u16>,
    key_type: String,
    key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveReq {
    path: String,
    promote: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenReq {
    name: String,
    role: Role,
    #[serde(default)]
    rules: Vec<Rule>,
    #[serde(default)]
    ttl_days: Option<u32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreReq {
    path: String,
    version: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MoveReq {
    path: String,
    new_path: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FolderMoveReq {
    from: String,
    to: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FolderDeleteReq {
    path: String,
    /// Present = move the items there ("" for top level); absent = delete them.
    #[serde(default)]
    move_to: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateSysReq {
    action: String,
    #[serde(default)]
    version: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeReq {
    id: String,
}
#[derive(Deserialize)]
struct AuditQ {
    #[serde(default = "d_limit")]
    limit: i64,
    #[serde(default)]
    before: Option<i64>,
}
fn d_limit() -> i64 {
    100
}

fn ok<T: serde::Serialize>(v: T) -> Res {
    Ok(Json(serde_json::to_value(v).map_err(VErr::from)?))
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, VErr> + Send + 'static) -> Result<T, ApiErr> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ApiErr(VErr::Internal(format!("task: {e}"))))?
        .map_err(ApiErr)
}

// ---------------------------------------------------------------- handlers

async fn status(State(app): S) -> Res {
    ok(app.vault.status()?)
}

async fn init(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<InitReq>) -> Res {
    // Whoever initializes the vault owns it, so only accept that from the
    // machine itself (run `jaword init` on the vault host), and never
    // through a reverse proxy, where remote clients also arrive from loopback.
    if !addr.ip().is_loopback() || is_proxied(&h) {
        return Err(VErr::Forbidden.into());
    }
    let out = blocking(move || app.vault.init(&r.passphrase)).await?;
    Ok(Json(json!({"recovery_key": out.recovery_key.as_str(), "root_token": out.root_token.as_str()})))
}

async fn unseal(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<UnsealReq>) -> Res {
    let ip = client_ip(addr.ip(), &h);
    if app.blocked(ip) {
        return Err(VErr::RateLimited(60).into());
    }
    let a2 = app.clone();
    match blocking(move || a2.vault.unseal(&r.credential)).await {
        Ok(()) => Ok(Json(json!({"sealed": false}))),
        Err(e) => {
            if matches!(e.0, VErr::Unauthorized) {
                app.note_failure(ip);
                tracing::warn!("failed unseal attempt from {ip}");
            }
            Err(e)
        }
    }
}

async fn seal(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    app.vault.seal(&a)?;
    Ok(Json(json!({"sealed": true})))
}

async fn passphrase(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<PassphraseReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    blocking(move || app.vault.change_passphrase(&a, &r.current, &r.new)).await?;
    Ok(Json(json!({"changed": true})))
}

async fn update_status(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    app.vault.authorize_upgrade(&a, "status")?;
    Ok(Json(app.updater.status()))
}

async fn update_request(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<UpdateSysReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    let detail: String = format!("{} {}", r.action, r.version.as_deref().unwrap_or("")).chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ' ')).take(40).collect();
    app.vault.authorize_upgrade(&a, detail.trim())?;
    app.updater.request(&r.action, r.version.as_deref()).map_err(VErr::BadRequest)?;
    Ok(Json(json!({"requested": true})))
}

async fn whoami(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    Ok(Json(json!({"id": a.token_id, "name": a.name, "role": a.role, "rules": a.rules})))
}

async fn list(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Query(q): Query<ListQ>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    ok(app.vault.list(&a, &q.prefix)?)
}

async fn get_secret(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Query(q): Query<PathQ>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    ok(app.vault.get(&a, &q.path)?)
}

async fn create(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<CreateReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    ok(app.vault.create(&a, &r.path, &r.kind, r.meta, r.value, r.policy)?)
}

async fn update(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<UpdateReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    ok(app.vault.update(&a, &r.path, r.meta, r.value)?)
}

async fn generate(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<GenerateReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    ok(app.vault.generate(&a, &r.path, r.policy)?)
}

async fn rotate(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<PathReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    let job = app.vault.rotate_prepare(&a, &r.path)?;
    // Detached task: if the client disconnects mid-rotation the driver still
    // completes and its result is still recorded.
    let app2 = app.clone();
    let done = tokio::spawn(async move {
        let result = drivers::run(&job.driver, &job.new_value, &job.old_value, &job.username).await;
        let rec = app2.vault.rotate_finish(&job, result.clone());
        (job.version, result, rec)
    })
    .await
    .map_err(|e| ApiErr(VErr::Internal(format!("rotation task: {e}"))))?;
    let (version, result, rec) = done;
    rec?;
    match result {
        Ok(()) => Ok(Json(json!({"path": r.path, "rotated": true, "version": version}))),
        Err(msg) => Ok(Json(json!({"path": r.path, "rotated": false, "failed_version": version, "error": msg}))),
    }
}

async fn resolve(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<ResolveReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    app.vault.resolve_pending(&a, &r.path, r.promote)?;
    Ok(Json(json!({"resolved": true})))
}

async fn reveal(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<RevealReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    let v = app.vault.reveal(&a, &r.path, r.version)?;
    Ok(Json(json!({"path": r.path, "value": v.as_str()})))
}

async fn delete(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<PathReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    app.vault.delete(&a, &r.path)?;
    Ok(Json(json!({"deleted": true})))
}

async fn driver(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<DriverReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    app.vault.set_driver(&a, &r.path, r.driver)?;
    Ok(Json(json!({"saved": true})))
}

async fn restore(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<RestoreReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    ok(app.vault.restore_version(&a, &r.path, r.version)?)
}

async fn move_secret(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<MoveReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    ok(app.vault.move_secret(&a, &r.path, &r.new_path)?)
}

async fn folders(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    ok(app.vault.folders(&a)?)
}

async fn folder_create(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<PathReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    app.vault.create_folder(&a, &r.path)?;
    Ok(Json(json!({"created": true})))
}

async fn folder_move(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<FolderMoveReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    let n = app.vault.move_folder(&a, &r.from, &r.to)?;
    Ok(Json(json!({"moved": n})))
}

async fn folder_delete(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<FolderDeleteReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    let n = app.vault.delete_folder(&a, &r.path, r.move_to.as_deref())?;
    Ok(Json(json!({"items": n, "moved": r.move_to.is_some()})))
}

// Guided rotation setup. Admin only; each call is audited.

async fn rotation_prepare(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<RotTargetReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    let port = r.port.unwrap_or(22);
    if !drivers::hostish(&r.host) || port == 0 || !crate::rotation::valid_account(&r.account) {
        return Err(VErr::BadRequest("Check the server name and the account name: letters, digits, dots and dashes only.".into()).into());
    }
    app.vault.authorize_admin(&a, "rotation.prepare", &format!("{}:{} {}", r.host, port, r.account))?;
    let key = crate::rotation::identity().await.map_err(VErr::Internal)?;
    let script = crate::rotation::server_script(&r.account, &key).map_err(VErr::BadRequest)?;
    let (host_key, scan_error) = match crate::rotation::scan(&r.host, port).await {
        Ok(k) => (Some(k), None),
        Err(e) => (None, Some(e)),
    };
    Ok(Json(json!({"public_key": key, "script": script, "host_key": host_key, "scan_error": scan_error})))
}

async fn rotation_trust(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<RotTrustReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    let port = r.port.unwrap_or(22);
    if !drivers::hostish(&r.host) || port == 0 {
        return Err(VErr::BadRequest("invalid server".into()).into());
    }
    app.vault.authorize_admin(&a, "rotation.trust", &format!("{}:{}", r.host, port))?;
    crate::rotation::trust(&r.host, port, &r.key_type, &r.key).await.map_err(VErr::BadRequest)?;
    Ok(Json(json!({"trusted": true})))
}

async fn rotation_test(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<RotTargetReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    let port = r.port.unwrap_or(22);
    app.vault.authorize_admin(&a, "rotation.test", &format!("{}:{} {}", r.host.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')).take(64).collect::<String>(), port, r.account.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')).take(32).collect::<String>()))?;
    ok(crate::rotation::test(&r.host, port, &r.account).await.map_err(VErr::BadRequest)?)
}

async fn tokens(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    ok(app.vault.list_tokens(&a)?)
}

async fn token_create(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<TokenReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    let (id, token) = app.vault.create_token(&a, &r.name, r.role, r.rules, r.ttl_days)?;
    Ok(Json(json!({"id": id, "token": token.as_str()})))
}

async fn token_revoke(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Json(r): Json<RevokeReq>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    app.vault.revoke_token(&a, &r.id)?;
    Ok(Json(json!({"revoked": true})))
}

async fn audit(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap, Query(q): Query<AuditQ>) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    ok(app.vault.audit_list(&a, q.limit, q.before)?)
}

async fn audit_verify(State(app): S, ConnectInfo(addr): Ip, h: HeaderMap) -> Res {
    let a = actor(&app, &h, addr.ip())?;
    let (rows, bad) = app.vault.audit_verify(&a)?;
    Ok(Json(json!({"rows": rows, "intact": bad.is_none(), "first_bad_seq": bad})))
}

// ---------------------------------------------------------------------- ui

fn asset(ctype: &'static str, body: &'static str) -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, ctype)
        .body(Body::from(body))
        .expect("static response")
}

fn font(bytes: &'static [u8]) -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, "font/woff2")
        .header(header::CACHE_CONTROL, "private, max-age=604800")
        .body(Body::from(bytes))
        .expect("static response")
}
async fn font_text() -> Response {
    font(include_bytes!("../ui/fonts/atkinson-next.woff2"))
}
async fn font_mono() -> Response {
    font(include_bytes!("../ui/fonts/atkinson-mono.woff2"))
}

// The word list is public data; the browser uses it to build word passwords locally.
async fn ui_words() -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "private, max-age=604800")
        .body(Body::from(jaword_core::generate::WORDLIST))
        .expect("static response")
}

async fn ui_index() -> Response {
    asset("text/html; charset=utf-8", include_str!("../ui/index.html"))
}
async fn ui_js() -> Response {
    asset("text/javascript; charset=utf-8", include_str!("../ui/app.js"))
}
async fn ui_css() -> Response {
    asset("text/css; charset=utf-8", include_str!("../ui/style.css"))
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/", get(ui_index))
        .route("/app.js", get(ui_js))
        .route("/style.css", get(ui_css))
        .route("/wordlist.txt", get(ui_words))
        .route("/fonts/atkinson-next.woff2", get(font_text))
        .route("/fonts/atkinson-mono.woff2", get(font_mono))
        .route("/v1/sys/status", get(status))
        .route("/v1/sys/init", post(init))
        .route("/v1/sys/unseal", post(unseal))
        .route("/v1/sys/seal", post(seal))
        .route("/v1/sys/passphrase", post(passphrase))
        .route("/v1/sys/update", get(update_status).post(update_request))
        .route("/v1/whoami", get(whoami))
        .route("/v1/secrets", get(list))
        .route("/v1/secrets/get", get(get_secret))
        .route("/v1/secrets/create", post(create))
        .route("/v1/secrets/update", post(update))
        .route("/v1/secrets/generate", post(generate))
        .route("/v1/secrets/rotate", post(rotate))
        .route("/v1/secrets/resolve", post(resolve))
        .route("/v1/secrets/reveal", post(reveal))
        .route("/v1/secrets/delete", post(delete))
        .route("/v1/secrets/driver", post(driver))
        .route("/v1/secrets/move", post(move_secret))
        .route("/v1/secrets/restore", post(restore))
        .route("/v1/rotation/prepare", post(rotation_prepare))
        .route("/v1/rotation/trust", post(rotation_trust))
        .route("/v1/rotation/test", post(rotation_test))
        .route("/v1/folders", get(folders))
        .route("/v1/folders/create", post(folder_create))
        .route("/v1/folders/move", post(folder_move))
        .route("/v1/folders/delete", post(folder_delete))
        .route("/v1/tokens", get(tokens))
        .route("/v1/tokens/create", post(token_create))
        .route("/v1/tokens/revoke", post(token_revoke))
        .route("/v1/audit", get(audit))
        .route("/v1/audit/verify", get(audit_verify))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .with_state(app)
}
