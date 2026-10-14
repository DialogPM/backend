//! Dialog relay server (Rust). Drop-in replacement for the Go server in `server/`: same
//! environment variables, database schema and HTTP/WebSocket API.

mod adaptive_pow;
mod admin;
mod admin_cli;
mod api;
mod auth;
mod config;
mod db;
mod error;
mod ids;
mod jobs;
mod keytrans;
mod metrics;
mod push;
mod ratelimit;
mod sealed;
mod settings;
mod sms;
mod state;
mod storage;
mod totp;
mod validate;
mod ws;
mod zk;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::config::Config;
use crate::state::{AppState, Inner};

const JOB_INTERVAL: Duration = Duration::from_secs(600);

pub fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// ":8080" listens on all addresses, IPv4 and IPv6, like Go.
fn listen_addr(a: &str) -> String {
    if a.starts_with(':') {
        format!("[::]{a}")
    } else {
        a.to_string()
    }
}

/// Binds the listener; for "[::]:port" makes sure the socket is dual-stack.
fn bind(addr: &str) -> std::io::Result<tokio::net::TcpListener> {
    let sa: SocketAddr = match addr.parse() {
        Ok(sa) => sa,
        Err(_) => {
            use std::net::ToSocketAddrs;
            addr.to_socket_addrs()?.next().ok_or_else(|| std::io::Error::other("no address"))?
        }
    };
    let socket = if sa.is_ipv6() { tokio::net::TcpSocket::new_v6()? } else { tokio::net::TcpSocket::new_v4()? };
    if sa.is_ipv6() && sa.ip().is_unspecified() {
        socket2::SockRef::from(&socket).set_only_v6(false)?;
    }
    socket.set_reuseaddr(true)?;
    socket.bind(sa)?;
    socket.listen(1024)
}

fn init_logging(cfg: &Config) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::Layer;
    let filter = tracing_subscriber::EnvFilter::new(format!("{},sqlx=warn", cfg.log_level));
    let fmt = if cfg.log_format == "json" {
        tracing_subscriber::fmt::layer().json().with_target(false).boxed()
    } else {
        tracing_subscriber::fmt::layer().with_target(false).boxed()
    };
    tracing_subscriber::registry()
        .with(fmt.with_filter(filter))
        // Last WARN/ERROR events for the admin API (GET /v1/admin/logs).
        .with(admin::logbuf::RingLayer.with_filter(tracing_subscriber::filter::LevelFilter::WARN))
        .init();
}

/// Probes GET /healthz on the configured address (container health checks).
async fn healthcheck() -> i32 {
    let addr = std::env::var("CHATAPP_LISTEN_ADDR").ok().map(|a| a.trim().to_string()).filter(|a| !a.is_empty()).unwrap_or_else(|| ":8080".into());
    let addr = if addr.starts_with(':') {
        format!("127.0.0.1{addr}")
    } else {
        addr
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    match client.get(format!("http://{addr}/healthz")).send().await {
        Ok(r) if r.status().is_success() => 0,
        Ok(r) => {
            eprintln!("healthcheck: status {}", r.status().as_u16());
            1
        }
        Err(e) => {
            eprintln!("healthcheck: {e}");
            1
        }
    }
}

#[tokio::main]
async fn main() {
    // Operator subcommands (`reports ...`, see admin_cli.rs); otherwise start the server.
    let args: Vec<String> = std::env::args().skip(1).collect();
    match admin_cli::parse(&args) {
        Ok(Some(cmd)) => {
            if let Err(e) = admin_cli::run(cmd).await {
                eprintln!("chatserver: {e}");
                std::process::exit(1);
            }
            return;
        }
        Ok(None) => {}
        Err(e) => {
            eprintln!("chatserver: {e}\n{}", admin_cli::USAGE);
            std::process::exit(2);
        }
    }
    // Go-style flags: -healthcheck, --healthcheck, -healthcheck=true|false.
    let mut health = false;
    for a in std::env::args().skip(1) {
        let flag = a.trim_start_matches('-');
        let (name, value) = flag.split_once('=').unwrap_or((flag, "true"));
        if !a.starts_with('-') || name != "healthcheck" {
            eprintln!("flag provided but not defined: {a}");
            std::process::exit(2);
        }
        health = match value {
            "1" | "t" | "T" | "true" | "TRUE" | "True" => true,
            "0" | "f" | "F" | "false" | "FALSE" | "False" => false,
            _ => {
                eprintln!("invalid boolean value {value:?} for -healthcheck");
                std::process::exit(2);
            }
        };
    }
    if health {
        std::process::exit(healthcheck().await);
    }
    if let Err(e) = run().await {
        eprintln!("chatserver: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let cfg = Config::from_env().map_err(|e| format!("configuration: {e}"))?;
    init_logging(&cfg);
    metrics::init();

    let pool = db::open_with_retry(&cfg.mysql_dsn, Duration::from_secs(120))
        .await
        .map_err(|e| format!("database: {e}"))?;
    db::migrate(&pool)
        .await
        .map_err(|e| format!("migrations: {e}"))?;

    let store = connect_storage(&cfg).await?;

    let runtime_settings = settings::Runtime::new(settings::Settings::from_config(&cfg));
    runtime_settings
        .load(&pool)
        .await
        .map_err(|e| format!("load admin settings: {e}"))?;
    let admin = admin::Admin::new(&cfg.admin_public_keys);
    match &admin {
        Some(_) => info!(keys = cfg.admin_public_keys.len(), "admin API enabled"),
        None => info!("admin API disabled (CHATAPP_ADMIN_PUBLIC_KEYS not set)"),
    }

    let sms: Option<Arc<dyn sms::SmsSender>> = match cfg.sms_provider.as_str() {
        "log" => Some(Arc::new(sms::LogSender)),
        "twilio" => Some(Arc::new(sms::TwilioSender::new(
            cfg.twilio_account_sid.clone(),
            cfg.twilio_auth_token.clone(),
            cfg.twilio_from.clone(),
        ))),
        _ => None,
    };

    let fcm: Option<Arc<dyn push::Notifier>> = if cfg.fcm_credentials_file.is_empty() {
        info!("FCM push disabled (CHATAPP_FCM_CREDENTIALS_FILE not set)");
        None
    } else {
        let creds = std::fs::read(&cfg.fcm_credentials_file)
            .map_err(|e| format!("read CHATAPP_FCM_CREDENTIALS_FILE: {e}"))?;
        let fcm = push::fcm::Fcm::new(&creds).map_err(|e| format!("push notifications: {e}"))?;
        info!(
            provider = "fcm",
            project_id = fcm.project_id(),
            "push notifications enabled"
        );
        Some(Arc::new(fcm))
    };
    let voip: Option<Arc<dyn push::Notifier>> = if cfg.apns_key_file.is_empty() {
        info!("APNs VoIP call pushes disabled (CHATAPP_APNS_KEY_FILE not set)");
        None
    } else {
        let key = std::fs::read(&cfg.apns_key_file)
            .map_err(|e| format!("read CHATAPP_APNS_KEY_FILE: {e}"))?;
        let apns = push::apns::Apns::new(
            &key,
            &cfg.apns_key_id,
            &cfg.apns_team_id,
            &cfg.apns_topic,
            cfg.apns_sandbox,
        )?;
        info!(
            provider = "apns_voip",
            topic = apns.topic(),
            sandbox = cfg.apns_sandbox,
            "VoIP call pushes enabled"
        );
        Some(Arc::new(apns))
    };

    let limits = if cfg.disable_rate_limits {
        warn!("rate limits are DISABLED (CHATAPP_DISABLE_RATE_LIMITS=true); never do this in production");
        ratelimit::Rules::default()
    } else {
        ratelimit::Rules::defaults()
    };

    let sealed =
        sealed::Issuer::new(&cfg.server_secret).map_err(|e| format!("sealed sender keys: {e}"))?;
    let hub = ws::Hub::new(pool.clone());
    let push = push::Dispatcher::new(fcm, voip, pool.clone());
    let st = AppState(Arc::new(Inner {
        cfg: cfg.clone(),
        db: pool,
        store,
        sms,
        limits,
        limiter: ratelimit::Limiter::new(),
        prov: api::provisioning::ProvisioningStore::default(),
        hub: hub.clone(),
        push: push.clone(),
        sealed,
        zk: Arc::new(zk::ZkParams::new(&cfg.server_secret)),
        kt: Arc::new(keytrans::KtLog::new(&cfg.server_secret)),
        settings: runtime_settings,
        admin,
    }));

    let app = api::router(st.clone());
    let addr = listen_addr(&cfg.listen_addr);
    let listener = bind(&addr).map_err(|e| format!("listen {addr}: {e}"))?;
    let jobs = tokio::spawn(jobs::run(st.clone(), JOB_INTERVAL));
    // Key transparency: backfills accounts without a log entry, then keeps up.
    let kt_sequencer = tokio::spawn(keytrans::run_sequencer(st.db.clone()));
    // Daily statistics (admin API) are counted in memory and written once a minute.
    let stats_flusher = tokio::spawn(metrics::run_flusher(st.db.clone(), Duration::from_secs(60)));
    // Raises the registration proof-of-work during a registration surge (adaptive_pow.rs).
    let adaptive_pow = tokio::spawn(adaptive_pow::run(st.clone()));
    info!(
        addr = %cfg.listen_addr,
        name = %cfg.server_name,
        version = api::VERSION,
        registration_enabled = st.settings.get().registration_enabled,
        sms_provider = %cfg.sms_provider,
        push_enabled = st.push.enabled(),
        "listening"
    );

    serve(listener, app, hub).await;
    push.close(Duration::from_secs(20)).await;
    jobs.abort();
    kt_sequencer.abort();
    stats_flusher.abort();
    adaptive_pow.abort();
    metrics::flush(&st.db).await;
    info!("stopped");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal handler");
        tokio::select! { _ = ctrl_c => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}

/// HTTP server with connection limits like the Go server's (10 s to read request headers,
/// which also bounds idle keep-alive connections; 64 KiB of headers) and its shutdown order: stop accepting, wait up
/// to 20 s for in-flight requests, then close the WebSockets.
async fn serve(listener: tokio::net::TcpListener, app: axum::Router, hub: Arc<ws::Hub>) {
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
    use hyper_util::server::conn::auto::Builder;
    use tower::ServiceExt;

    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_buf_size(64 << 10)
        .keep_alive(true);
    builder.http2().timer(TokioTimer::new()).keep_alive_interval(Some(Duration::from_secs(60)));
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let signal = shutdown_signal();
    tokio::pin!(signal);
    loop {
        let (stream, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            _ = &mut signal => break,
        };
        let _ = stream.set_nodelay(true);
        let svc = app.clone().layer(axum::Extension(axum::extract::ConnectInfo(peer)));
        let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
            svc.clone().oneshot(req.map(axum::body::Body::new))
        });
        let conn = builder.serve_connection_with_upgrades(TokioIo::new(stream), svc).into_owned();
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!(error = %e, "connection error");
            }
        });
    }
    info!("shutting down");
    drop(listener);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    if tokio::time::timeout_at(deadline, graceful.shutdown()).await.is_err() {
        warn!("shutdown: in-flight requests did not finish within 20 s");
    }
    // Upgraded WebSockets are not tracked by the graceful watcher: close them explicitly.
    hub.shutdown(deadline.saturating_duration_since(tokio::time::Instant::now()).max(Duration::from_secs(1))).await;
}

async fn connect_storage(cfg: &Config) -> Result<Arc<dyn storage::Store>, String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let mut delay = Duration::from_secs(1);
    loop {
        match storage::Minio::connect(
            &cfg.minio_endpoint,
            &cfg.minio_access_key,
            &cfg.minio_secret_key,
            &cfg.minio_bucket,
            cfg.minio_use_ssl,
            &cfg.minio_region,
        )
        .await
        {
            Ok(s) => return Ok(Arc::new(s)),
            Err(e) if tokio::time::Instant::now() + delay < deadline => {
                warn!(error = %e, retry_in = ?delay, "object storage not ready, retrying");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(10));
            }
            Err(e) => return Err(format!("object storage: {e}")),
        }
    }
}
