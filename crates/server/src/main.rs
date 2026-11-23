//! jawordd: the jaword vault server.
#![forbid(unsafe_code)]

mod cards;
mod drivers;
mod http;
mod people;
mod rotation;
mod store;
mod update;

use jaword_core::crypto::KdfParams;
use axum::response::IntoResponse;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

const MAX_CONNECTIONS: usize = 256;
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(330);

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() {
    // `--version` is used by the update helper to confirm what a binary is
    // before and after installing it. Anything else is rejected rather than
    // silently starting a server.
    if let Some(arg) = std::env::args().nth(1) {
        if arg == "--version" || arg == "-V" {
            println!("jawordd {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        eprintln!("unknown argument {arg:?}; jawordd is configured through JAWORD_* environment variables");
        std::process::exit(2);
    }
    tracing_subscriber::fmt().with_target(false).init();

    let db_path = env("JAWORD_DB", "jaword.db");
    let listen = env("JAWORD_LISTEN", "127.0.0.1:8200");
    let addr: SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("JAWORD_LISTEN must be ip:port, got {listen:?}");
            std::process::exit(2);
        }
    };
    // Host names clients may use to reach us (DNS-rebinding protection).
    let mut hosts: Vec<String> = env("JAWORD_ALLOWED_HOSTS", "")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    hosts.push(addr.to_string());
    if addr.ip().is_loopback() {
        hosts.push(format!("localhost:{}", addr.port()));
    }

    let vault = match store::Vault::open(&db_path, KdfParams::DEFAULT, KdfParams::DEFAULT) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("cannot open vault database {db_path:?}: {e:?}");
            std::process::exit(1);
        }
    };
    let st = vault.status().ok();
    tracing::info!(
        "jawordd {} listening on http://{addr} (db {db_path}, initialized={}, sealed=true)",
        env!("CARGO_PKG_VERSION"),
        st.map(|s| s.initialized).unwrap_or(false)
    );
    if !addr.ip().is_loopback() {
        tracing::warn!("listening on a non-loopback address without TLS; put this behind `tailscale serve` or another TLS terminator");
    }

    let app = Arc::new(http::App::new(vault, hosts));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    // Scheduled rotations: every few minutes, rotate whatever is due. Does
    // nothing while the vault is sealed.
    let sched = app.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let Ok(due) = sched.vault.due_rotations() else { continue };
            for path in due {
                let Ok(job) = sched.vault.rotate_prepare(&store::Vault::schedule_actor(), &path) else { continue };
                let result = drivers::run(&job.driver, &job.new_value, &job.old_value, &job.username).await;
                match &result {
                    Ok(()) => tracing::info!("scheduled rotation of {path} succeeded"),
                    Err(e) => tracing::warn!("scheduled rotation of {path} failed, previous value kept: {e}"),
                }
                let _ = sched.vault.rotate_finish(&job, result);
            }
        }
    });
    let router = http::router(app);
    let shutdown = async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async { match term.as_mut() { Some(t) => { t.recv().await; } None => std::future::pending().await } } => {}
        }
    };
    tokio::pin!(shutdown);

    // Hand-rolled accept loop instead of `axum::serve` so we control the
    // limits that protect against connection-exhaustion attacks.
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, peer) = tokio::select! {
            _ = &mut shutdown => break,
            acc = listener.accept() => match acc {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        // At capacity: drop the new connection rather than queue without bound.
        let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
        let router = router.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = stream.set_nodelay(true);
            let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                req.extensions_mut().insert(axum::extract::ConnectInfo(peer));
                let router = router.clone();
                async move {
                    // Bounds slow request bodies; long enough for the slowest rotation driver.
                    match tokio::time::timeout(REQUEST_TIMEOUT, router.oneshot(req.map(axum::body::Body::new))).await {
                        Ok(r) => r,
                        Err(_) => Ok(axum::http::StatusCode::REQUEST_TIMEOUT.into_response()),
                    }
                }
            });
            let mut conn = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
            conn.http1()
                .timer(hyper_util::rt::TokioTimer::new())
                // A client must finish sending its request line and headers quickly.
                .header_read_timeout(HEADER_TIMEOUT)
                .max_buf_size(64 * 1024);
            conn.http2()
                .timer(hyper_util::rt::TokioTimer::new())
                .max_concurrent_streams(32)
                .keep_alive_interval(Some(Duration::from_secs(20)))
                .keep_alive_timeout(Duration::from_secs(10));
            let _ = conn.serve_connection(hyper_util::rt::TokioIo::new(stream), svc).await;
        });
    }
    tracing::info!("shutting down");
}
