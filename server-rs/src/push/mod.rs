//! Mobile wake-up pushes (API section 14, docs/PUSH-SETUP.md). A push never carries message
//! data, the sender or the conversation: only "new message" or "incoming call" (with the call
//! id), plus the opaque tag the device registered so an app holding several accounts knows
//! which one to wake. The Dispatcher decides when to push (bounded async queue, per-device
//! coalescing, fallback for sockets that stopped acknowledging, token clearing); a Notifier
//! delivers one push (FCM for Android and iOS alerts, APNs for iOS VoIP call pushes).
//!
//! Tokens are secrets of the user's install: they are never logged.

pub mod apns;
pub mod fcm;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sqlx::MySqlPool;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::storage::async_trait_shim::BoxFuture;

/// FCM registration token (Android directly, iOS through FCM's APNs integration).
pub const PROVIDER_FCM: &str = "fcm";
/// APNs PushKit (VoIP) token of an iOS device: incoming call offers only.
pub const PROVIDER_APNS_VOIP: &str = "apns_voip";
/// Maximum accepted length of an FCM registration token.
pub const MAX_TOKEN_LEN: usize = 4096;
/// Maximum accepted length of an APNs device token (64 hex characters today).
pub const MAX_VOIP_TOKEN_LEN: usize = 512;
/// Maximum length of the client-chosen push tag.
pub const MAX_TAG_LEN: usize = 64;

#[derive(Debug)]
pub enum PushError {
    /// The provider says the token is no longer valid: forget it.
    InvalidToken(String),
    Other(String),
}

/// What a push announces.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Wake {
    /// Envelopes are queued: fetch them.
    Message,
    /// An incoming call offer is queued (high priority, rings on iOS through CallKit).
    Call { call_id: String },
}

impl Wake {
    /// At most one push per device and kind within this interval (calls: per call id).
    fn interval(&self) -> Duration {
        match self {
            Wake::Message => MESSAGE_INTERVAL,
            Wake::Call { .. } => CALL_INTERVAL,
        }
    }

    /// How long a socket may take to acknowledge an envelope before a push is sent anyway.
    fn ack_grace(&self) -> Duration {
        match self {
            Wake::Message => MESSAGE_ACK_GRACE,
            Wake::Call { .. } => CALL_ACK_GRACE,
        }
    }
}

/// A call id as clients produce it (UUID-like: letters, digits and '-', at most 64).
pub fn valid_call_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

/// A push tag: 1..64 of letters, digits, '-' and '_'.
pub fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= MAX_TAG_LEN
        && tag.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

pub trait Notifier: Send + Sync {
    /// Delivers one push to `token`. `tag` is the device's push tag ("" when none).
    fn send<'a>(&'a self, token: &'a str, tag: &'a str, wake: &'a Wake)
        -> BoxFuture<'a, Result<(), PushError>>;
}

const MESSAGE_INTERVAL: Duration = Duration::from_secs(10);
const CALL_INTERVAL: Duration = Duration::from_secs(60);
const MESSAGE_ACK_GRACE: Duration = Duration::from_secs(10);
const CALL_ACK_GRACE: Duration = Duration::from_secs(3);
const WORKERS: usize = 4;
const QUEUE_SIZE: usize = 4096;
const SEND_TIMEOUT: Duration = Duration::from_secs(60);
const PRUNE_EVERY: Duration = Duration::from_secs(10);

/// Retry policy of the HTTP notifiers.
pub(crate) const MAX_ATTEMPTS: u32 = 4;
const BASE_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

type Key = (String, i64, Wake);

struct Notifiers {
    fcm: Option<Arc<dyn Notifier>>,
    voip: Option<Arc<dyn Notifier>>,
}

pub struct Dispatcher {
    fcm_enabled: bool,
    voip_enabled: bool,
    db: MySqlPool,
    tx: Mutex<Option<mpsc::Sender<Key>>>,
    last: Mutex<(HashMap<Key, Instant>, Option<Instant>)>,
    /// Envelopes delivered on a socket and waiting for their acknowledgement (one per key).
    watching: Mutex<HashSet<Key>>,
    workers: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl Dispatcher {
    /// With neither notifier the dispatcher is disabled: notify does nothing.
    pub fn new(
        fcm: Option<Arc<dyn Notifier>>,
        voip: Option<Arc<dyn Notifier>>,
        db: MySqlPool,
    ) -> Arc<Dispatcher> {
        let (fcm_enabled, voip_enabled) = (fcm.is_some(), voip.is_some());
        let mut d = Dispatcher {
            fcm_enabled,
            voip_enabled,
            db: db.clone(),
            tx: Mutex::new(None),
            last: Mutex::new((HashMap::new(), None)),
            watching: Mutex::new(HashSet::new()),
            workers: Mutex::new(Vec::new()),
        };
        if !fcm_enabled && !voip_enabled {
            return Arc::new(d);
        }
        let notifiers = Arc::new(Notifiers { fcm, voip });
        let (tx, rx) = mpsc::channel::<Key>(QUEUE_SIZE);
        let rx = Arc::new(tokio::sync::Mutex::new(rx));
        let mut handles = Vec::new();
        for _ in 0..WORKERS {
            let (rx, notifiers, db) = (rx.clone(), notifiers.clone(), db.clone());
            handles.push(tokio::spawn(async move {
                loop {
                    let key = { rx.lock().await.recv().await };
                    let Some(key) = key else { return };
                    let _ =
                        tokio::time::timeout(SEND_TIMEOUT, send_one(&notifiers, &db, &key)).await;
                }
            }));
        }
        d.tx = Mutex::new(Some(tx));
        d.workers = Mutex::new(handles);
        Arc::new(d)
    }

    /// Some push provider is configured.
    pub fn enabled(&self) -> bool {
        self.fcm_enabled || self.voip_enabled
    }

    /// Direct APNs VoIP pushes are configured.
    pub fn voip_enabled(&self) -> bool {
        self.voip_enabled
    }

    /// Records a push for `key` unless one was recorded less than its interval ago.
    fn admit(&self, key: &Key, now: Instant) -> bool {
        let mut last = self.last.lock().unwrap();
        let (map, last_prune) = &mut *last;
        if last_prune.is_none_or(|t| now.duration_since(t) >= PRUNE_EVERY) {
            *last_prune = Some(now);
            map.retain(|k, t| now.duration_since(*t) < k.2.interval());
        }
        if map
            .get(key)
            .is_some_and(|t| now.duration_since(*t) < key.2.interval())
        {
            return false; // coalesced with the previous push
        }
        map.insert(key.clone(), now);
        true
    }

    /// Schedules a push unless an equal one was scheduled recently. Never blocks.
    pub fn notify(&self, account: &str, device: i64, wake: Wake) {
        if !self.enabled() {
            return;
        }
        let key = (account.to_string(), device, wake);
        let tx = self.tx.lock().unwrap();
        let Some(tx) = tx.as_ref() else { return };
        if !self.admit(&key, Instant::now()) {
            return;
        }
        if tx.try_send(key.clone()).is_err() {
            warn!(account, device, "push queue full, dropping push");
            // Not sent: the next event may try again.
            self.last.lock().unwrap().0.remove(&key);
        }
    }

    /// For an envelope just written to the device's socket: pushes anyway if it is still
    /// unacknowledged after a grace period. A suspended phone (iOS freezes apps in the
    /// background) keeps its TCP connection open for a while, so the server would otherwise
    /// believe it reachable. One check per device and kind at a time.
    pub fn notify_unless_acked(self: &Arc<Self>, account: &str, device: i64, envelope_id: &str, wake: Wake) {
        if !self.enabled() {
            return;
        }
        let key = (account.to_string(), device, wake);
        if !self.watching.lock().unwrap().insert(key.clone()) {
            return;
        }
        let (me, id) = (self.clone(), envelope_id.to_string());
        tokio::spawn(async move {
            tokio::time::sleep(key.2.ack_grace()).await;
            me.watching.lock().unwrap().remove(&key);
            let pending = sqlx::query!("SELECT 1 AS one FROM envelopes WHERE id = ?", &id)
                .fetch_optional(&me.db)
                .await;
            match pending {
                Ok(Some(_)) => {
                    debug!(account = %key.0, device = key.1, "envelope not acknowledged in time, pushing");
                    me.notify(&key.0, key.1, key.2);
                }
                Ok(None) => {}
                Err(e) => warn!(error = %e, "push: check acknowledgement"),
            }
        });
    }

    /// Stops accepting pushes and waits (up to `timeout`) for queued ones.
    pub async fn close(&self, timeout: Duration) {
        self.tx.lock().unwrap().take();
        let handles: Vec<_> = std::mem::take(&mut *self.workers.lock().unwrap());
        let _ = tokio::time::timeout(timeout, futures_util::future::join_all(handles)).await;
    }
}

/// SHA-256 of a push token (indexed).
pub fn token_hash(token: &str) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(token.as_bytes()).to_vec()
}

/// Registered tokens of one device.
#[derive(Default)]
struct DeviceTokens {
    fcm: Option<String>,
    voip: Option<String>,
    tag: String,
}

/// Which providers to try, in order, for `wake`: VoIP only for calls (Apple requires every
/// VoIP push to report a call to CallKit), then FCM.
fn route(wake: &Wake, t: &DeviceTokens, fcm: bool, voip: bool) -> Vec<&'static str> {
    let mut out = Vec::new();
    if matches!(wake, Wake::Call { .. }) && voip && t.voip.is_some() {
        out.push(PROVIDER_APNS_VOIP);
    }
    if fcm && t.fcm.is_some() {
        out.push(PROVIDER_FCM);
    }
    out
}

async fn send_one(n: &Notifiers, db: &MySqlPool, key: &Key) {
    let (account, device, wake) = (key.0.as_str(), key.1, &key.2);
    let row = sqlx::query!(
        "SELECT push_provider AS `push_provider: String`, push_token AS `push_token: String`, push_tag AS `push_tag: String`, voip_token AS `voip_token: String` FROM devices
         WHERE account_id = ? AND device_id = ?",
        account,
        device
    )
    .fetch_optional(db)
    .await;
    let tokens = match row {
        Ok(Some(r)) => DeviceTokens {
            fcm: r
                .push_token
                .filter(|t| !t.is_empty() && r.push_provider == PROVIDER_FCM),
            voip: r.voip_token.filter(|t| !t.is_empty()),
            tag: r.push_tag.unwrap_or_default(),
        },
        Ok(None) => return,
        Err(e) => {
            error!(account, device, error = %e, "push: load token");
            return;
        }
    };
    for provider in route(wake, &tokens, n.fcm.is_some(), n.voip.is_some()) {
        let (notifier, token) = match provider {
            PROVIDER_APNS_VOIP => (n.voip.as_ref(), tokens.voip.as_deref()),
            _ => (n.fcm.as_ref(), tokens.fcm.as_deref()),
        };
        let (Some(notifier), Some(token)) = (notifier, token) else { continue };
        match notifier.send(token, &tokens.tag, wake).await {
            Ok(()) => {
                crate::metrics::PUSHES_SENT.add(1);
                debug!(account, device, provider, "push sent");
                return;
            }
            Err(PushError::InvalidToken(e)) => {
                crate::metrics::PUSH_FAILURES.add(1);
                info!(account, device, provider, error = %e, "push token rejected by provider, clearing it");
                // Not bounded by the send timeout.
                let (db, account, token) = (db.clone(), account.to_string(), token.to_string());
                tokio::spawn(async move { clear_token(&db, &account, device, provider, &token).await });
            }
            // A failed VoIP push still falls back to an FCM alert.
            Err(PushError::Other(e)) => {
                crate::metrics::PUSH_FAILURES.add(1);
                warn!(account, device, provider, error = %e, "push failed")
            }
        }
    }
}

async fn clear_token(db: &MySqlPool, account: &str, device: i64, provider: &str, token: &str) {
    let sql = if provider == PROVIDER_APNS_VOIP {
        "UPDATE devices SET voip_token = NULL, voip_token_hash = NULL
         WHERE account_id = ? AND device_id = ? AND voip_token_hash = ?"
    } else {
        "UPDATE devices SET push_provider = '', push_token = NULL, push_token_hash = NULL
         WHERE account_id = ? AND device_id = ? AND push_token_hash = ?"
    };
    if let Err(e) = sqlx::query(sql)
        .bind(account)
        .bind(device)
        .bind(token_hash(token))
        .execute(db)
        .await
    {
        error!(account, device, error = %e, "push: clear token");
    }
}

/// One HTTP attempt failed: (temporary?, retry_after, error).
pub(crate) type AttemptError = (bool, Duration, PushError);

/// Runs `attempt` until it succeeds, fails permanently or MAX_ATTEMPTS is reached, with
/// exponential backoff (plus jitter, or the server's Retry-After) between attempts.
pub(crate) async fn with_retries<'a, F>(mut attempt: F) -> Result<(), PushError>
where
    F: FnMut() -> BoxFuture<'a, Result<(), AttemptError>>,
{
    let mut n = 1;
    loop {
        match attempt().await {
            Ok(()) => return Ok(()),
            Err((temporary, retry_after, err)) => {
                if !temporary || n >= MAX_ATTEMPTS {
                    return Err(err);
                }
                let mut delay = (BASE_BACKOFF * 2u32.pow(n - 1)).min(MAX_BACKOFF);
                delay += Duration::from_millis(rand::random_range(0..=delay.as_millis() as u64 / 5));
                if retry_after > delay {
                    delay = retry_after.min(MAX_BACKOFF);
                }
                tokio::time::sleep(delay).await;
                n += 1;
            }
        }
    }
}

/// Retry-After as seconds or an HTTP date.
pub(crate) fn retry_after(h: &reqwest::header::HeaderMap) -> Duration {
    h.get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let v = v.trim();
            v.parse::<u64>()
                .ok()
                .filter(|s| *s > 0)
                .map(Duration::from_secs)
                .or_else(|| {
                    httpdate::parse_http_date(v)
                        .ok()
                        .and_then(|t| t.duration_since(std::time::SystemTime::now()).ok())
                })
        })
        .unwrap_or_default()
}

/// Reads at most 64 KiB of a response body.
pub(crate) async fn read_body(resp: reqwest::Response) -> String {
    let mut stream = resp.bytes_stream();
    let mut body = Vec::new();
    while let Some(Ok(chunk)) = futures_util::StreamExt::next(&mut stream).await {
        body.extend_from_slice(&chunk);
        if body.len() >= 64 << 10 {
            body.truncate(64 << 10);
            break;
        }
    }
    String::from_utf8_lossy(&body).into_owned()
}

#[cfg(test)]
pub(crate) mod testutil {
    //! A local HTTP server standing in for FCM / Google OAuth / APNs (no network).

    use std::sync::{Arc, Mutex};

    use axum::body::Bytes;
    use axum::http::{HeaderMap, StatusCode, Uri};
    use axum::response::IntoResponse;
    use axum::Router;

    #[derive(Clone, Debug)]
    pub struct Seen {
        pub path: String,
        pub headers: HeaderMap,
        pub body: String,
    }

    /// Answers every request with the next scripted (status, body), the last one repeating.
    pub async fn serve(script: Vec<(u16, &'static str)>) -> (String, Arc<Mutex<Vec<Seen>>>) {
        let seen = Arc::new(Mutex::new(Vec::<Seen>::new()));
        let script = Arc::new(Mutex::new(script));
        let s2 = seen.clone();
        let app = Router::new().fallback(move |uri: Uri, headers: HeaderMap, body: Bytes| {
            let (seen, script) = (s2.clone(), script.clone());
            async move {
                let path = uri.path().to_string();
                let body = String::from_utf8_lossy(&body).into_owned();
                seen.lock().unwrap().push(Seen { path: path.clone(), headers, body });
                if path == "/token" {
                    return (StatusCode::OK, r#"{"access_token":"at-1","expires_in":3600}"#)
                        .into_response();
                }
                let mut s = script.lock().unwrap();
                let (code, text) = if s.len() > 1 { s.remove(0) } else { s[0] };
                (StatusCode::from_u16(code).unwrap(), text).into_response()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), seen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lazy_pool() -> MySqlPool {
        sqlx::mysql::MySqlPoolOptions::new()
            .connect_lazy("mysql://u:p@127.0.0.1:1/none")
            .unwrap()
    }

    struct Nop;
    impl Notifier for Nop {
        fn send<'a>(&'a self, _: &'a str, _: &'a str, _: &'a Wake) -> BoxFuture<'a, Result<(), PushError>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn disabled_without_credentials() {
        let d = Dispatcher::new(None, None, lazy_pool());
        assert!(!d.enabled());
        assert!(!d.voip_enabled());
        // No-ops (nothing queued, no task spawned, no database access).
        d.notify("acc", 1, Wake::Message);
        d.notify_unless_acked("acc", 1, "env", Wake::Message);
        assert!(d.watching.lock().unwrap().is_empty());
        d.close(Duration::from_millis(10)).await;
    }

    #[tokio::test]
    async fn coalesces_per_device_and_call() {
        let d = Dispatcher::new(Some(Arc::new(Nop)), None, lazy_pool());
        assert!(d.enabled() && !d.voip_enabled());
        let t0 = Instant::now();
        let msg = |dev: i64| ("acc".to_string(), dev, Wake::Message);
        let call = |id: &str| ("acc".to_string(), 1, Wake::Call { call_id: id.into() });
        assert!(d.admit(&msg(1), t0));
        // At most one message push per device per 10 s.
        assert!(!d.admit(&msg(1), t0 + Duration::from_secs(9)));
        assert!(d.admit(&msg(2), t0 + Duration::from_secs(1)));
        assert!(d.admit(&msg(1), t0 + Duration::from_secs(11)));
        // Calls are not held back by message pushes; the same call is pushed once.
        assert!(d.admit(&call("c1"), t0));
        assert!(!d.admit(&call("c1"), t0 + Duration::from_secs(30)));
        assert!(d.admit(&call("c2"), t0 + Duration::from_secs(1)));
        d.close(Duration::from_millis(10)).await;
    }

    #[test]
    fn routes_calls_to_voip_first() {
        let call = Wake::Call { call_id: "c".into() };
        let both = DeviceTokens { fcm: Some("f".into()), voip: Some("v".into()), tag: String::new() };
        assert_eq!(route(&call, &both, true, true), vec![PROVIDER_APNS_VOIP, PROVIDER_FCM]);
        // Messages never use VoIP.
        assert_eq!(route(&Wake::Message, &both, true, true), vec![PROVIDER_FCM]);
        // VoIP not configured on the server, or no VoIP token: FCM.
        assert_eq!(route(&call, &both, true, false), vec![PROVIDER_FCM]);
        let fcm_only = DeviceTokens { fcm: Some("f".into()), ..Default::default() };
        assert_eq!(route(&call, &fcm_only, true, true), vec![PROVIDER_FCM]);
        // No FCM credentials on the server: VoIP alone.
        assert_eq!(route(&call, &both, false, true), vec![PROVIDER_APNS_VOIP]);
        assert!(route(&Wake::Message, &DeviceTokens::default(), true, true).is_empty());
    }

    #[test]
    fn validators() {
        assert!(valid_call_id("3f1c2a9e-0b6d-4c1e-9a7b-2d4e6f8a0b1c"));
        assert!(!valid_call_id(""));
        assert!(!valid_call_id("a b"));
        assert!(!valid_call_id(&"a".repeat(65)));
        assert!(valid_tag("Zm9v_bar-1"));
        assert!(!valid_tag(""));
        assert!(!valid_tag("a/b"));
        assert!(!valid_tag(&"a".repeat(65)));
    }
}
