//! WebSocket delivery hub: one socket per device, queued envelope delivery, real-time pushes,
//! events and presence. Process-local (horizontal scaling would need a pub/sub bus).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket};
use std::panic::AssertUnwindSafe;

use futures_util::{FutureExt, SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::MySqlPool;
use tokio::sync::{mpsc, Notify};
use tracing::{debug, warn};

use crate::db::{placeholders, RowExt};
use crate::ids;

/// Another socket of the same device connected.
pub const STATUS_REPLACED: u16 = 4000;
/// Device unlinked or account deleted.
pub const STATUS_DEVICE_REMOVED: u16 = 4001;
pub const STATUS_GOING_AWAY: u16 = 1001;
pub const STATUS_INTERNAL: u16 = 1011;

const SEND_BUFFER: usize = 1024;
const DRAIN_BATCH: i64 = 200;
const MAX_SUBSCRIPTIONS: usize = 1000;
const MAX_INBOUND_FRAME: usize = 256 << 10;
const MAX_SENT_IDS_TRACKED: usize = 100_000;
const CLOSE_HANDSHAKE_WAIT: Duration = Duration::from_secs(5);
const PING_INTERVAL: Duration = Duration::from_secs(30);
/// Ping every 30 s + 45 s without pong = dead after 75 s.
const PONG_TIMEOUT: Duration = Duration::from_secs(45);
const WRITE_TIMEOUT: Duration = Duration::from_secs(15);

enum OutMsg {
    Data {
        text: String,
        envelope_id: Option<String>,
    },
    Close {
        code: u16,
        reason: String,
    },
}

/// Handle to one device socket, shared with the hub.
#[derive(Clone)]
struct ConnHandle {
    id: u64,
    account: String,
    device: i64,
    /// The user is at this device (not idle, app in the foreground). An account shows online
    /// only while one of its connected devices is active.
    active: Arc<AtomicBool>,
    tx: mpsc::Sender<OutMsg>,
    resync: Arc<Notify>,
    closing: Arc<CloseSignal>,
}

#[derive(Default)]
struct CloseSignal {
    requested: AtomicBool,
    reason: Mutex<Option<(u16, String)>>,
    notify: Notify,
}

impl ConnHandle {
    /// Queues a frame without blocking. When the buffer is full, stored envelopes are
    /// recovered by re-reading the queue from the database; other frames are dropped.
    fn enqueue(&self, m: OutMsg) {
        match self.tx.try_send(m) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(m)) | Err(mpsc::error::TrySendError::Closed(m)) => {
                match m {
                    OutMsg::Data {
                        envelope_id: Some(_),
                        ..
                    } => self.resync.notify_one(),
                    OutMsg::Close { code, reason } => self.request_close(code, reason),
                    _ => {}
                }
            }
        }
    }

    /// Asks the writer to close the socket with `code` (first request wins).
    fn request_close(&self, code: u16, reason: String) {
        if !self.closing.requested.swap(true, Ordering::SeqCst) {
            *self.closing.reason.lock().unwrap() = Some((code, reason));
        }
        self.closing.notify.notify_waiters();
        self.closing.notify.notify_one();
    }
}

#[derive(Default)]
struct HubState {
    closed: bool,
    conns: HashMap<(String, i64), ConnHandle>,
    account_conns: HashMap<String, HashMap<i64, ConnHandle>>,
    /// target account -> subscribed connection ids
    subscribers: HashMap<String, HashSet<u64>>,
    /// connection id -> (handle, subscribed targets)
    subs_of: HashMap<u64, (ConnHandle, HashSet<String>)>,
    /// last-seen privacy of connected accounts
    privacy_nobody: HashMap<String, bool>,
    /// privacy of each connection's own account (as known to the conn)
    active: usize,
}

pub struct Hub {
    db: MySqlPool,
    state: Mutex<HubState>,
    next_id: AtomicU64,
    all_closed: Notify,
}

fn presence_frame(account: &str, online: bool, last_seen: Option<i64>, hidden: bool) -> String {
    let (online, last_seen) = if hidden {
        (false, None)
    } else {
        (online, last_seen)
    };
    json!({"type": "presence", "account_id": account, "online": online, "last_seen": last_seen})
        .to_string()
}

fn envelope_frame(env_json: &str) -> String {
    format!(r#"{{"type":"envelope","envelope":{env_json}}}"#)
}

fn event_frame(event: &Value) -> String {
    json!({"type": "event", "event": event}).to_string()
}

impl Hub {
    pub fn new(db: MySqlPool) -> Arc<Hub> {
        Arc::new(Hub {
            db,
            state: Mutex::new(HubState::default()),
            next_id: AtomicU64::new(1),
            all_closed: Notify::new(),
        })
    }

    /// Whether the account shows online: one of its connected devices is active.
    fn online_locked(st: &HubState, account: &str) -> bool {
        st.account_conns
            .get(account)
            .is_some_and(|d| d.values().any(|h| h.active.load(Ordering::Relaxed)))
    }

    /// Presence frames for all subscribers of `account` (computed under the lock).
    fn presence_change_locked(
        st: &HubState,
        account: &str,
        online: bool,
        last_seen: Option<i64>,
    ) -> Vec<(ConnHandle, String)> {
        let Some(subs) = st.subscribers.get(account) else {
            return Vec::new();
        };
        let last_seen = if online {
            Some(crate::now_millis())
        } else {
            last_seen
        };
        let target_hidden = st.privacy_nobody.get(account).copied().unwrap_or(false);
        subs.iter()
            .filter_map(|id| st.subs_of.get(id))
            .map(|(h, _)| {
                let hidden =
                    target_hidden || st.privacy_nobody.get(&h.account).copied().unwrap_or(false);
                (
                    h.clone(),
                    presence_frame(account, online, last_seen, hidden),
                )
            })
            .collect()
    }

    fn deliver(frames: Vec<(ConnHandle, String)>) {
        for (h, f) in frames {
            h.enqueue(OutMsg::Data {
                text: f,
                envelope_id: None,
            });
        }
    }

    /// Adds the socket, replacing (and closing) a previous socket of the same device.
    fn register(&self, h: &ConnHandle, privacy_nobody: bool) -> bool {
        let (old, notify) = {
            let mut st = self.state.lock().unwrap();
            if st.closed {
                return false;
            }
            let was_online = Self::online_locked(&st, &h.account);
            let old = st.conns.insert((h.account.clone(), h.device), h.clone());
            st.account_conns.entry(h.account.clone()).or_default().insert(h.device, h.clone());
            let came_online = !was_online && Self::online_locked(&st, &h.account);
            st.privacy_nobody.insert(h.account.clone(), privacy_nobody);
            st.subs_of.insert(h.id, (h.clone(), HashSet::new()));
            st.active += 1;
            let notify = if came_online {
                Self::presence_change_locked(&st, &h.account, true, None)
            } else {
                Vec::new()
            };
            (old, notify)
        };
        if let Some(old) = old {
            old.request_close(STATUS_REPLACED, "replaced by a new connection".into());
        }
        Self::deliver(notify);
        true
    }

    /// The device reports whether the user is at it (`presence_state` frame). When the last
    /// active device goes away, subscribers see the account offline, last seen `since` (when the
    /// user went idle, at most an hour back).
    async fn set_active(&self, h: &ConnHandle, active: bool, since: Option<i64>) {
        let now = crate::now_millis();
        let since = since.map_or(now, |s| s.clamp(now - 3_600_000, now));
        let (went_away, notify) = {
            let st = self.state.lock().unwrap();
            if st.conns.get(&(h.account.clone(), h.device)).map(|c| c.id) != Some(h.id) {
                return;
            }
            let was = Self::online_locked(&st, &h.account);
            h.active.store(active, Ordering::Relaxed);
            let is = Self::online_locked(&st, &h.account);
            match (was, is) {
                (false, true) => (false, Self::presence_change_locked(&st, &h.account, true, None)),
                (true, false) => (true, Self::presence_change_locked(&st, &h.account, false, Some(since))),
                _ => (false, Vec::new()),
            }
        };
        Self::deliver(notify);
        if went_away {
            if let Err(e) = sqlx::query!("UPDATE accounts SET last_seen_at = ? WHERE id = ?", since, &h.account)
                .execute(&self.db)
                .await
            {
                warn!(error = %e, "set last seen failed");
            }
        }
    }

    /// Removes the socket if it is still the active one of its device.
    async fn unregister(&self, h: &ConnHandle) {
        let now = crate::now_millis();
        let (went_offline, notify) = {
            let mut st = self.state.lock().unwrap();
            let was_online = Self::online_locked(&st, &h.account);
            if let Some((_, targets)) = st.subs_of.remove(&h.id) {
                for t in targets {
                    if let Some(set) = st.subscribers.get_mut(&t) {
                        set.remove(&h.id);
                        if set.is_empty() {
                            st.subscribers.remove(&t);
                        }
                    }
                }
            }
            let key = (h.account.clone(), h.device);
            let mut disconnected = false;
            if st.conns.get(&key).map(|c| c.id) == Some(h.id) {
                st.conns.remove(&key);
                if let Some(devs) = st.account_conns.get_mut(&h.account) {
                    devs.remove(&h.device);
                    if devs.is_empty() {
                        st.account_conns.remove(&h.account);
                        disconnected = true;
                    }
                }
            }
            // An account that was already away (idle) keeps the last seen of when it went away.
            let went_offline = was_online && !Self::online_locked(&st, &h.account);
            let notify = if went_offline {
                Self::presence_change_locked(&st, &h.account, false, Some(now))
            } else {
                Vec::new()
            };
            if disconnected {
                st.privacy_nobody.remove(&h.account);
            }
            st.active -= 1;
            if st.active == 0 {
                self.all_closed.notify_waiters();
            }
            (went_offline, notify)
        };
        if let Err(e) = sqlx::query!(
            "UPDATE devices SET last_seen_at = ? WHERE account_id = ? AND device_id = ?",
            now,
            &h.account,
            h.device
        )
        .execute(&self.db)
        .await
        {
            warn!(error = %e, "touch device failed");
        }
        if went_offline {
            if let Err(e) = sqlx::query!("UPDATE accounts SET last_seen_at = ? WHERE id = ?", now, &h.account)
                .execute(&self.db)
                .await
            {
                warn!(error = %e, "set last seen failed");
            }
        }
        Self::deliver(notify);
    }

    async fn presence_records(
        &self,
        accounts: &[String],
    ) -> Result<HashMap<String, (bool, Option<i64>)>, sqlx::Error> {
        let mut out = HashMap::new();
        for part in accounts.chunks(500) {
            let sql = format!(
                "SELECT id, privacy_last_seen, last_seen_at FROM accounts WHERE id IN ({})",
                placeholders(part.len())
            );
            let mut q = sqlx::query(&sql);
            for a in part {
                q = q.bind(a);
            }
            for r in q.fetch_all(&self.db).await? {
                out.insert(
                    r.string("id"),
                    (
                        r.string("privacy_last_seen") == "nobody",
                        r.opt_i64("last_seen_at"),
                    ),
                );
            }
        }
        Ok(out)
    }

    /// The requested accounts whose access key was presented correctly (in request order).
    async fn authorized_targets(
        &self,
        requested: Vec<(String, Vec<u8>)>,
    ) -> Result<Vec<String>, sqlx::Error> {
        let mut stored: HashMap<String, Option<Vec<u8>>> = HashMap::new();
        for part in requested.chunks(500) {
            let sql = format!(
                "SELECT id, unidentified_access_key FROM accounts WHERE id IN ({})",
                placeholders(part.len())
            );
            let mut q = sqlx::query(&sql);
            for (a, _) in part {
                q = q.bind(a);
            }
            for r in q.fetch_all(&self.db).await? {
                stored.insert(r.string("id"), r.opt_bytes("unidentified_access_key"));
            }
        }
        Ok(requested
            .into_iter()
            .filter(|(id, key)| access_key_matches(stored.get(id).and_then(|k| k.as_deref()), key))
            .map(|(id, _)| id)
            .collect())
    }

    /// Replaces the presence subscriptions of the socket and sends the current presence of
    /// every subscribed (existing) account.
    async fn subscribe(&self, h: &ConnHandle, targets: Vec<String>) {
        let records = match self.presence_records(&targets).await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "presence lookup failed");
                return;
            }
        };
        let frames = {
            let mut st = self.state.lock().unwrap();
            if st.conns.get(&(h.account.clone(), h.device)).map(|c| c.id) != Some(h.id) {
                return;
            }
            let old: HashSet<String> = st
                .subs_of
                .get(&h.id)
                .map(|(_, t)| t.clone())
                .unwrap_or_default();
            for t in old {
                if let Some(set) = st.subscribers.get_mut(&t) {
                    set.remove(&h.id);
                    if set.is_empty() {
                        st.subscribers.remove(&t);
                    }
                }
            }
            let now = crate::now_millis();
            let self_hidden = st.privacy_nobody.get(&h.account).copied().unwrap_or(false);
            let mut new_subs = HashSet::new();
            let mut frames = Vec::new();
            for t in targets {
                let Some((rec_nobody, rec_last_seen)) = records.get(&t) else {
                    continue;
                };
                new_subs.insert(t.clone());
                st.subscribers.entry(t.clone()).or_default().insert(h.id);
                let online = Self::online_locked(&st, &t);
                let target_hidden = if st.account_conns.contains_key(&t) {
                    st.privacy_nobody.get(&t).copied().unwrap_or(false)
                } else {
                    *rec_nobody
                };
                let last_seen = if online { Some(now) } else { *rec_last_seen };
                frames.push(presence_frame(
                    &t,
                    online,
                    last_seen,
                    target_hidden || self_hidden,
                ));
            }
            if let Some(entry) = st.subs_of.get_mut(&h.id) {
                entry.1 = new_subs;
            }
            frames
        };
        for f in frames {
            h.enqueue(OutMsg::Data {
                text: f,
                envelope_id: None,
            });
        }
    }

    /// Ends every presence subscription to `account` (its access key changed): each
    /// subscriber gets a last "offline, unknown" frame and no further updates.
    pub fn revoke_presence_subscribers(&self, account: &str) {
        let frames = {
            let mut st = self.state.lock().unwrap();
            let Some(subs) = st.subscribers.remove(account) else {
                return;
            };
            let mut frames = Vec::new();
            for id in subs {
                if let Some((h, targets)) = st.subs_of.get_mut(&id) {
                    targets.remove(account);
                    frames.push((h.clone(), presence_frame(account, false, None, true)));
                }
            }
            frames
        };
        Self::deliver(frames);
    }

    /// Updates the cached last-seen privacy of a connected account and re-sends presence
    /// where visibility may have changed.
    pub async fn set_privacy(&self, account: &str, nobody: bool) {
        let (notify, resub) = {
            let mut st = self.state.lock().unwrap();
            let Some(devs) = st.account_conns.get(account) else {
                return;
            };
            if devs.is_empty() {
                return;
            }
            let handles: Vec<ConnHandle> = devs.values().cloned().collect();
            st.privacy_nobody.insert(account.to_string(), nobody);
            let notify = if Self::online_locked(&st, account) {
                Self::presence_change_locked(&st, account, true, None)
            } else {
                Vec::new()
            };
            let resub: Vec<(ConnHandle, Vec<String>)> = handles
                .into_iter()
                .map(|h| {
                    let t = st
                        .subs_of
                        .get(&h.id)
                        .map(|(_, t)| t.iter().cloned().collect())
                        .unwrap_or_default();
                    (h, t)
                })
                .collect();
            (notify, resub)
        };
        Self::deliver(notify);
        for (h, targets) in resub {
            self.subscribe(&h, targets).await;
        }
    }

    fn get(&self, account: &str, device: i64) -> Option<ConnHandle> {
        self.state
            .lock()
            .unwrap()
            .conns
            .get(&(account.to_string(), device))
            .cloned()
    }

    fn account_sockets(&self, account: &str) -> Vec<ConnHandle> {
        self.state
            .lock()
            .unwrap()
            .account_conns
            .get(account)
            .map(|d| d.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Pushes a stored envelope (JSON object) if the device is connected; it stays queued
    /// until acknowledged. Returns whether a socket was found.
    pub fn send_envelope(&self, account: &str, device: i64, id: &str, envelope_json: &str) -> bool {
        match self.get(account, device) {
            Some(h) => {
                h.enqueue(OutMsg::Data {
                    text: envelope_frame(envelope_json),
                    envelope_id: Some(id.to_string()),
                });
                true
            }
            None => false,
        }
    }

    /// Pushes a non-stored envelope (online=true messages) if the device is connected.
    pub fn send_ephemeral(&self, account: &str, device: i64, envelope_json: &str) -> bool {
        match self.get(account, device) {
            Some(h) => {
                h.enqueue(OutMsg::Data {
                    text: envelope_frame(envelope_json),
                    envelope_id: None,
                });
                true
            }
            None => false,
        }
    }

    pub fn is_connected(&self, account: &str, device: i64) -> bool {
        self.get(account, device).is_some()
    }

    /// Pushes `{"type":"event","event":event}` to all connected devices of the account
    /// except `except_device` (0 = none).
    pub fn send_event(&self, account: &str, except_device: i64, event: &Value) {
        let frame = event_frame(event);
        for h in self.account_sockets(account) {
            if h.device != except_device {
                h.enqueue(OutMsg::Data {
                    text: frame.clone(),
                    envelope_id: None,
                });
            }
        }
    }

    pub fn send_device_event(&self, account: &str, device: i64, event: &Value) {
        if let Some(h) = self.get(account, device) {
            h.enqueue(OutMsg::Data {
                text: event_frame(event),
                envelope_id: None,
            });
        }
    }

    /// Closes the socket of a removed device (after flushing pending frames).
    pub fn close_device(&self, account: &str, device: i64, reason: &str) {
        if let Some(h) = self.get(account, device) {
            h.enqueue(OutMsg::Close {
                code: STATUS_DEVICE_REMOVED,
                reason: reason.into(),
            });
        }
    }

    /// Sends `event` to every socket of the account and then closes them.
    pub fn close_account(&self, account: &str, event: &Value, reason: &str) {
        let frame = event_frame(event);
        for h in self.account_sockets(account) {
            h.enqueue(OutMsg::Data {
                text: frame.clone(),
                envelope_id: None,
            });
            h.enqueue(OutMsg::Close {
                code: STATUS_DEVICE_REMOVED,
                reason: reason.into(),
            });
        }
    }

    /// Open WebSockets (admin overview).
    pub fn online_count(&self) -> usize {
        self.state.lock().unwrap().conns.len()
    }

    pub fn connected_devices(&self, account: &str) -> Vec<i64> {
        self.account_sockets(account)
            .iter()
            .map(|h| h.device)
            .collect()
    }

    /// Closes all sockets with "going away" and waits (up to `timeout`) for them to finish.
    pub async fn shutdown(&self, timeout: Duration) {
        let (all, waiter) = {
            let mut st = self.state.lock().unwrap();
            st.closed = true;
            let all: Vec<ConnHandle> = st.conns.values().cloned().collect();
            let waiter = (st.active > 0).then(|| self.all_closed.notified());
            (all, waiter)
        };
        for h in all {
            h.request_close(STATUS_GOING_AWAY, "server shutting down".into());
        }
        if let Some(w) = waiter {
            let _ = tokio::time::timeout(timeout, w).await;
        }
    }

    /// Runs an upgraded socket of an authenticated device until it closes.
    pub async fn serve(
        self: Arc<Self>,
        socket: WebSocket,
        account: String,
        device: i64,
        privacy_nobody: bool,
        active: bool,
    ) {
        let (tx, rx) = mpsc::channel(SEND_BUFFER);
        let h = ConnHandle {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            account,
            device,
            active: Arc::new(AtomicBool::new(active)),
            tx,
            resync: Arc::new(Notify::new()),
            closing: Arc::new(CloseSignal::default()),
        };
        let (mut sink, mut stream) = socket.split();
        if !self.register(&h, privacy_nobody) {
            let _ = sink
                .send(Message::Close(Some(CloseFrame {
                    code: STATUS_GOING_AWAY,
                    reason: "server shutting down".into(),
                })))
                .await;
            return;
        }
        // Always unregister, even if the connection task panics (Go: defer unregister).
        let run = AssertUnwindSafe(self.clone().run_conn(h.clone(), sink, stream, rx)).catch_unwind();
        if run.await.is_err() {
            tracing::error!(account = %h.account, device = h.device, "panic in websocket connection");
            h.request_close(STATUS_INTERNAL, String::new());
        }
        self.unregister(&h).await;
    }

    async fn run_conn(
        self: Arc<Self>,
        h: ConnHandle,
        sink: Sink,
        mut stream: futures_util::stream::SplitStream<WebSocket>,
        rx: mpsc::Receiver<OutMsg>,
    ) {
        let last_pong = Arc::new(AtomicI64::new(crate::now_millis()));
        let mut writer = tokio::spawn(writer_loop(self.clone(), h.clone(), sink, rx, last_pong.clone()));
        // Reader: stops on close/error, or when the writer finished (socket closing).
        loop {
            tokio::select! {
                msg = stream.next() => {
                    let msg = match msg {
                        Some(Ok(m)) => m,
                        Some(Err(e)) => {
                            // Frames above the read limit close with 1009, like Go.
                            let text = e.to_string();
                            if text.contains("too long") || text.contains("Space limit") {
                                h.request_close(1009, "message too big".into());
                                let _ = tokio::time::timeout(CLOSE_HANDSHAKE_WAIT, &mut writer).await;
                                writer.abort();
                                return;
                            }
                            break;
                        }
                        None => break,
                    };
                    match msg {
                        Message::Text(t) => self.handle_inbound(&h, t.as_str()).await,
                        Message::Pong(_) => last_pong.store(crate::now_millis(), Ordering::Relaxed),
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
                _ = &mut writer => {
                    // The writer sent a close frame or failed: give the peer a moment to
                    // answer the close handshake, then drop the connection.
                    let _ = tokio::time::timeout(CLOSE_HANDSHAKE_WAIT, async {
                        while let Some(Ok(m)) = stream.next().await {
                            if matches!(m, Message::Close(_)) { break; }
                        }
                    }).await;
                    return;
                }
            }
        }
        h.request_close(1000, String::new());
        let _ = tokio::time::timeout(CLOSE_HANDSHAKE_WAIT, &mut writer).await;
        writer.abort();
    }

    async fn handle_inbound(&self, h: &ConnHandle, text: &str) {
        #[derive(Deserialize)]
        struct Inbound {
            #[serde(default, rename = "type")]
            kind: String,
            #[serde(default)]
            id: String,
            /// presence_subscribe: `{"account_id", "access_key"}` objects (see
            /// `parse_subscriptions`); anything malformed is skipped.
            #[serde(default)]
            subscriptions: Vec<Value>,
            /// presence_state: whether the user is at this device, and since when not.
            #[serde(default)]
            active: Option<bool>,
            #[serde(default)]
            since: Option<i64>,
        }
        // Same decoding rules as HTTP bodies (Go: null = zero value, case-insensitive names).
        let Ok(v) = serde_json::from_str::<Value>(text) else { return };
        let Ok(m) = serde_json::from_value::<Inbound>(crate::validate::go_compat(v)) else {
            return;
        };
        match m.kind.as_str() {
            "ack" => {
                let Some(id) = ids::normalize_uuid(&m.id) else {
                    return;
                };
                if let Err(e) = sqlx::query!(
                    "DELETE FROM envelopes WHERE id = ? AND account_id = ? AND device_id = ?",
                    &id,
                    &h.account,
                    h.device
                )
                .execute(&self.db)
                .await
                {
                    warn!(error = %e, "websocket ack failed");
                }
            }
            "presence_subscribe" => {
                let targets = match self
                    .authorized_targets(parse_subscriptions(m.subscriptions))
                    .await
                {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(error = %e, "presence access check failed");
                        return;
                    }
                };
                self.subscribe(h, targets).await;
            }
            "presence_state" => {
                if let Some(active) = m.active {
                    self.set_active(h, active, m.since).await;
                }
            }
            "ping" => h.enqueue(OutMsg::Data {
                text: r#"{"type":"pong"}"#.into(),
                envelope_id: None,
            }),
            _ => {}
        }
    }
}

/// Presence subscriptions as sent by clients: `{"account_id", "access_key"}` pairs, deduplicated
/// and capped. The access key is the target's unidentified access key (16 bytes, derived from
/// its profile key, see api/sealed.rs), which an account shares only with the conversations it
/// accepted: strangers cannot watch whether it is online or when it was last seen.
fn parse_subscriptions(raw: Vec<Value>) -> Vec<(String, Vec<u8>)> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in raw {
        if out.len() >= MAX_SUBSCRIPTIONS {
            break;
        }
        let Some(id) = item
            .get("account_id")
            .and_then(Value::as_str)
            .and_then(ids::normalize_uuid)
        else {
            continue;
        };
        let Some(key) = item
            .get("access_key")
            .and_then(Value::as_str)
            .and_then(crate::validate::b64::decode)
            .filter(|k| k.len() == 16)
        else {
            continue;
        };
        if seen.insert(id.clone()) {
            out.push((id, key));
        }
    }
    out
}

/// Constant-time check of a presented access key against the stored one (none stored: no
/// access).
fn access_key_matches(stored: Option<&[u8]>, presented: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    matches!(stored, Some(s) if s.len() == 16 && bool::from(s.ct_eq(presented)))
}

type Sink = futures_util::stream::SplitSink<WebSocket, Message>;

async fn write(sink: &mut Sink, text: String) -> bool {
    matches!(
        tokio::time::timeout(
            WRITE_TIMEOUT,
            sink.send(Message::Text(Utf8Bytes::from(text)))
        )
        .await,
        Ok(Ok(()))
    )
}

async fn close(sink: &mut Sink, code: u16, reason: String) {
    let _ = tokio::time::timeout(
        WRITE_TIMEOUT,
        sink.send(Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        }))),
    )
    .await;
}

/// Writes every queued envelope not yet written on this socket, oldest first.
async fn drain(
    hub: &Hub,
    h: &ConnHandle,
    sink: &mut Sink,
    sent: &mut HashSet<String>,
) -> Result<(), String> {
    let mut after = 0i64;
    loop {
        let batch = crate::api::messages::fetch_envelopes(
            &hub.db,
            &h.account,
            h.device,
            after,
            DRAIN_BATCH,
        )
        .await
        .map_err(|e| e.to_string())?;
        let n = batch.len() as i64;
        for (seq, env) in batch {
            after = seq;
            if sent.contains(&env.id) {
                continue;
            }
            mark_sent(sent, &env.id);
            if !write(sink, envelope_frame(&env.to_json())).await {
                return Err("write failed".into());
            }
        }
        if n < DRAIN_BATCH {
            return Ok(());
        }
    }
}

fn mark_sent(sent: &mut HashSet<String>, id: &str) {
    if sent.len() >= MAX_SENT_IDS_TRACKED {
        sent.clear();
    }
    sent.insert(id.to_string());
}

/// Resolves PONG_TIMEOUT after the outstanding ping (never when there is none).
async fn pong_deadline(ping_sent_at: Option<i64>) {
    match ping_sent_at {
        Some(at) => {
            let left = at + PONG_TIMEOUT.as_millis() as i64 - crate::now_millis();
            tokio::time::sleep(Duration::from_millis(left.max(0) as u64)).await;
        }
        None => std::future::pending().await,
    }
}

async fn writer_loop(
    hub: Arc<Hub>,
    h: ConnHandle,
    mut sink: Sink,
    mut rx: mpsc::Receiver<OutMsg>,
    last_pong: Arc<AtomicI64>,
) {
    let mut sent: HashSet<String> = HashSet::new();
    if let Err(e) = drain(&hub, &h, &mut sink, &mut sent).await {
        warn!(error = %e, "websocket queue drain failed");
        close(&mut sink, STATUS_INTERNAL, "queue drain failed".into()).await;
        return;
    }
    if !write(&mut sink, r#"{"type":"queue_empty"}"#.into()).await {
        return;
    }
    let mut ticker = tokio::time::interval(PING_INTERVAL);
    ticker.tick().await;
    let mut ping_sent_at: Option<i64> = None;
    loop {
        if h.closing.requested.load(Ordering::SeqCst) {
            let (code, reason) = h
                .closing
                .reason
                .lock()
                .unwrap()
                .take()
                .unwrap_or((STATUS_GOING_AWAY, String::new()));
            close(&mut sink, code, reason).await;
            return;
        }
        tokio::select! {
            _ = h.closing.notify.notified() => continue,
            m = rx.recv() => {
                let Some(m) = m else { return };
                match m {
                    OutMsg::Close { code, reason } => {
                        close(&mut sink, code, reason).await;
                        return;
                    }
                    OutMsg::Data { text, envelope_id } => {
                        if let Some(id) = envelope_id {
                            if sent.contains(&id) {
                                continue;
                            }
                            mark_sent(&mut sent, &id);
                        }
                        if !write(&mut sink, text).await {
                            close(&mut sink, STATUS_GOING_AWAY, "write failed".into()).await;
                            return;
                        }
                    }
                }
            }
            _ = h.resync.notified() => {
                if drain(&hub, &h, &mut sink, &mut sent).await.is_err() {
                    close(&mut sink, STATUS_GOING_AWAY, "resync failed".into()).await;
                    return;
                }
            }
            _ = pong_deadline(ping_sent_at) => {
                // 45 s after a ping without a pong: the connection is dead.
                if ping_sent_at.is_some_and(|at| last_pong.load(Ordering::Relaxed) < at) {
                    debug!(account = %h.account, device = h.device, "websocket ping timeout");
                    return;
                }
                ping_sent_at = None;
            }
            _ = ticker.tick() => {
                let now = crate::now_millis();
                if tokio::time::timeout(WRITE_TIMEOUT, sink.send(Message::Ping(Default::default()))).await.is_err() {
                    return;
                }
                if ping_sent_at.is_none() {
                    ping_sent_at = Some(now);
                }
            }
        }
    }
}

#[cfg(test)]
mod presence_access_tests {
    use super::*;

    const A: &str = "11111111-1111-4111-8111-111111111111";

    #[test]
    fn subscriptions_need_a_well_formed_access_key() {
        let key = crate::validate::b64::encode(&[7u8; 16]);
        let parsed = parse_subscriptions(vec![
            json!({"account_id": A, "access_key": key}),
            json!({"account_id": A, "access_key": key}),
            json!({"account_id": "22222222-2222-4222-8222-222222222222"}),
            json!({"account_id": "33333333-3333-4333-8333-333333333333", "access_key": "c2hvcnQ="}),
            json!(A),
            json!({"account_id": "not-a-uuid", "access_key": key}),
        ]);
        assert_eq!(parsed, vec![(A.to_string(), vec![7u8; 16])]);
    }

    #[test]
    fn access_key_must_match_the_stored_one() {
        assert!(access_key_matches(Some(&[1u8; 16]), &[1u8; 16]));
        assert!(!access_key_matches(Some(&[1u8; 16]), &[2u8; 16]));
        assert!(!access_key_matches(None, &[1u8; 16]));
        assert!(!access_key_matches(Some(&[]), &[]));
    }
}
