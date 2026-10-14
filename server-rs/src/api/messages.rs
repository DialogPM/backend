//! 1:1 messages, the envelope queue and the WebSocket endpoint (API section 7).

use std::collections::BTreeMap;

use axum::body::Body;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{MySql, MySqlPool, Transaction};

use super::{no_content, query_int, reply};
use crate::auth::Principal;
use crate::error::{
    bad_request, conflict, gone, not_found, too_large, unauthorized, ApiError, ApiResult,
};
use crate::ids;
use crate::push::Wake;
use crate::state::AppState;
use crate::validate::{
    b64, parse_json, path_uuid, MAX_DEVICE_ID, MAX_JSON_BODY, MAX_MESSAGE_CONTENT,
};

// Envelope types (libsignal CiphertextMessageType, plus 6 for sealed sender).
pub const ENVELOPE_WHISPER: i64 = 2;
pub const ENVELOPE_PREKEY: i64 = 3;
pub const ENVELOPE_SEALED: i64 = 6;
pub const ENVELOPE_SENDER_KEY: i64 = 7;
pub const ENVELOPE_PLAINTEXT: i64 = 8;

pub fn valid_envelope_type(t: i64) -> bool {
    matches!(
        t,
        ENVELOPE_WHISPER | ENVELOPE_PREKEY | ENVELOPE_SENDER_KEY | ENVELOPE_PLAINTEXT
    )
}

const DEFAULT_FETCH_LIMIT: i64 = 100;
const MAX_FETCH_LIMIT: i64 = 1000;
/// Bounds the size of one multi-row INSERT (256 KiB content each).
const ENVELOPE_INSERT_BATCH: usize = 32;

/// Wire representation of a message envelope.
#[derive(Serialize, Clone, Debug)]
pub struct Envelope {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: i64,
    pub source_account: String,
    pub source_device: i64,
    pub destination_device: i64,
    pub group_id: Option<String>,
    pub timestamp: i64,
    pub server_timestamp: i64,
    #[serde(with = "b64")]
    pub content: Vec<u8>,
    /// Destination account (not serialized; the recipient knows who it is).
    #[serde(skip)]
    pub dest_account: String,
}

impl Envelope {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("envelope serializes")
    }
}

/// JSON body limit for a 1:1 send: one base64 content per device plus overhead.
pub fn max_send_body(st: &AppState) -> usize {
    let per_device = MAX_MESSAGE_CONTENT * 4 / 3 + 1024;
    (st.settings.get().max_devices as usize * per_device + (64 << 10)).max(MAX_JSON_BODY)
}

#[derive(Deserialize)]
pub struct OutgoingMessage {
    #[serde(default)]
    pub device_id: i64,
    #[serde(default)]
    pub registration_id: i64,
    #[serde(default, rename = "type")]
    pub kind: i64,
    #[serde(default, with = "b64")]
    pub content: Vec<u8>,
}

#[derive(Deserialize)]
pub struct SendRequest {
    #[serde(default)]
    pub timestamp: i64,
    #[serde(default)]
    pub online: bool,
    #[serde(default)]
    pub messages: Vec<OutgoingMessage>,
    /// Set by the caller's client on an incoming-call offer (the content stays encrypted):
    /// offline devices then get a high-priority call push carrying only this id (API 14).
    #[serde(default)]
    pub call_id: Option<String>,
}

pub fn validate_content(content: &[u8]) -> Result<(), ApiError> {
    if content.is_empty() {
        return Err(bad_request("content must not be empty"));
    }
    if content.len() > MAX_MESSAGE_CONTENT {
        return Err(too_large("content exceeds 256 KiB"));
    }
    Ok(())
}

pub fn validate_timestamp(ts: i64) -> Result<(), ApiError> {
    if ts <= 0 {
        return Err(bad_request(
            "timestamp must be a positive millisecond timestamp",
        ));
    }
    Ok(())
}

pub async fn send_message(
    State(st): State<AppState>,
    p: Principal,
    Path(account_id): Path<String>,
    body: Body,
) -> ApiResult {
    send_messages(&st, Some(&p), &account_id, body).await
}

/// Stores and delivers a 1:1 message. `p` is None for sealed sender deliveries: the envelopes
/// then carry no source and must all be sealed.
pub async fn send_messages(
    st: &AppState,
    p: Option<&Principal>,
    account_id: &str,
    body: Body,
) -> ApiResult {
    let dest = path_uuid("account_id", account_id)?;
    let req: SendRequest = parse_json(body, max_send_body(st)).await?;
    validate_timestamp(req.timestamp)?;
    let wake = match req.call_id.as_deref() {
        None | Some("") => Wake::Message,
        Some(id) if crate::push::valid_call_id(id) => Wake::Call { call_id: id.to_string() },
        Some(_) => return Err(bad_request("invalid call_id")),
    };
    if req.messages.len() as i64 > MAX_DEVICE_ID {
        return Err(bad_request("too many messages"));
    }
    let mut given: BTreeMap<i64, OutgoingMessage> = BTreeMap::new();
    for m in req.messages {
        if m.device_id < 1 || m.device_id > MAX_DEVICE_ID {
            return Err(bad_request("device_id must be in 1..127"));
        }
        if given.contains_key(&m.device_id) {
            return Err(bad_request(format!("duplicate device_id {}", m.device_id)));
        }
        if p.is_none() && m.kind != ENVELOPE_SEALED {
            return Err(bad_request("anonymous deliveries must be sealed"));
        }
        if p.is_some() && !valid_envelope_type(m.kind) {
            return Err(bad_request("invalid message type"));
        }
        validate_content(&m.content)?;
        given.insert(m.device_id, m);
    }

    let server_ts = crate::now_millis();
    let mut tx = st.db.begin().await?;
    // A shared lock on the destination account row serializes against device changes
    // (login, unlink, recovery lock it exclusively).
    let exists = sqlx::query!("SELECT id FROM accounts WHERE id = ? FOR SHARE", &dest)
        .fetch_optional(&mut *tx)
        .await?;
    if exists.is_none() {
        return Err(not_found("unknown account"));
    }
    let mut current = device_registrations(&mut tx, &dest).await?;
    if let Some(p) = p {
        if dest == p.account {
            current.remove(&p.device);
        }
    }
    let missing: Vec<i64> = current
        .keys()
        .filter(|d| !given.contains_key(d))
        .copied()
        .collect();
    let extra: Vec<i64> = given
        .keys()
        .filter(|d| !current.contains_key(d))
        .copied()
        .collect();
    if !missing.is_empty() || !extra.is_empty() {
        return Err(conflict("device list mismatch")
            .with("missing_devices", missing)
            .with("extra_devices", extra));
    }
    let stale: Vec<i64> = given
        .iter()
        .filter(|(d, m)| current[d] != m.registration_id)
        .map(|(d, _)| *d)
        .collect();
    if !stale.is_empty() {
        return Err(gone("stale registration ids").with("stale_devices", stale));
    }
    let envs: Vec<Envelope> = given
        .into_iter()
        .map(|(d, m)| Envelope {
            id: ids::new_uuid(),
            kind: m.kind,
            source_account: p.map(|p| p.account.clone()).unwrap_or_default(),
            source_device: p.map(|p| p.device).unwrap_or(0),
            destination_device: d,
            group_id: None,
            timestamp: req.timestamp,
            server_timestamp: server_ts,
            content: m.content,
            dest_account: dest.clone(),
        })
        .collect();
    if !req.online {
        insert_envelopes(&mut tx, &envs).await?;
    }
    tx.commit().await?;
    deliver_wake(st, &envs, req.online, &wake);
    Ok(reply(
        StatusCode::OK,
        json!({"server_timestamp": server_ts}),
    ))
}

/// Pushes envelopes to connected devices after they were stored (or, for ephemeral messages,
/// instead of storing them). A stored envelope for a device without an open socket schedules a
/// mobile push (asynchronous, coalesced); one written to a socket that does not acknowledge
/// it in time does too. Ephemeral envelopes never do, and neither do envelopes between the
/// devices of one account (copies of what we sent from another device, read/settings syncs):
/// they would show "New message" on the phone for a message we wrote ourselves. The device
/// fetches them at its next connection.
pub fn deliver(st: &AppState, envs: &[Envelope], ephemeral: bool) {
    deliver_wake(st, envs, ephemeral, &Wake::Message)
}

/// [`deliver`] announcing `wake` (a call offer) in the pushes.
pub fn deliver_wake(st: &AppState, envs: &[Envelope], ephemeral: bool, wake: &Wake) {
    crate::metrics::bump(crate::metrics::ENVELOPES_SENT, envs.len() as i64);
    for e in envs {
        let j = e.to_json();
        if ephemeral {
            st.hub
                .send_ephemeral(&e.dest_account, e.destination_device, &j);
            continue;
        }
        let own_sync = !e.source_account.is_empty() && e.source_account == e.dest_account;
        if own_sync {
            st.hub.send_envelope(&e.dest_account, e.destination_device, &e.id, &j);
            continue;
        }
        if st
            .hub
            .send_envelope(&e.dest_account, e.destination_device, &e.id, &j)
        {
            st.push
                .notify_unless_acked(&e.dest_account, e.destination_device, &e.id, wake.clone());
        } else {
            st.push.notify(&e.dest_account, e.destination_device, wake.clone());
        }
    }
}

/// device_id -> registration_id of an account.
pub async fn device_registrations(
    tx: &mut Transaction<'_, MySql>,
    account: &str,
) -> Result<BTreeMap<i64, i64>, sqlx::Error> {
    let rows = sqlx::query!("SELECT device_id AS `device_id: i64`, registration_id AS `registration_id: i64` FROM devices WHERE account_id = ?", account)
        .fetch_all(&mut **tx)
        .await?;
    Ok(rows
        .iter()
        .map(|r| (r.device_id, r.registration_id))
        .collect())
}

pub async fn insert_envelopes(
    tx: &mut Transaction<'_, MySql>,
    envs: &[Envelope],
) -> Result<(), sqlx::Error> {
    for batch in envs.chunks(ENVELOPE_INSERT_BATCH) {
        let mut sql = String::from(
            "INSERT INTO envelopes (id, account_id, device_id, type, source_account, source_device,
             group_id, client_timestamp, server_timestamp, content) VALUES ",
        );
        sql.push_str(&vec!["(?,?,?,?,?,?,?,?,?,?)"; batch.len()].join(","));
        let mut q = sqlx::query(&sql);
        for e in batch {
            q = q
                .bind(&e.id)
                .bind(&e.dest_account)
                .bind(e.destination_device)
                .bind(e.kind)
                .bind(&e.source_account)
                .bind(e.source_device)
                .bind(&e.group_id)
                .bind(e.timestamp)
                .bind(e.server_timestamp)
                .bind(&e.content);
        }
        q.execute(&mut **tx).await?;
    }
    Ok(())
}

/// Up to `limit` queued envelopes of a device with seq > `after_seq`, as (seq, envelope).
pub async fn fetch_envelopes(
    db: &MySqlPool,
    account: &str,
    device: i64,
    after_seq: i64,
    limit: i64,
) -> Result<Vec<(i64, Envelope)>, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT seq AS `seq: i64`, id AS `id: String`, type AS `type: i64`, source_account AS `source_account: String`, source_device AS `source_device: i64`, group_id AS `group_id: String`, client_timestamp, server_timestamp, content
         FROM envelopes WHERE account_id = ? AND device_id = ? AND seq > ? ORDER BY seq LIMIT ?",
        account,
        device,
        after_seq,
        limit
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.seq,
                Envelope {
                    id: r.id,
                    kind: r.r#type,
                    source_account: r.source_account,
                    source_device: r.source_device,
                    destination_device: device,
                    group_id: r.group_id,
                    timestamp: r.client_timestamp,
                    server_timestamp: r.server_timestamp,
                    content: r.content,
                    dest_account: account.to_string(),
                },
            )
        })
        .collect())
}

pub async fn fetch_messages(
    State(st): State<AppState>,
    p: Principal,
    RawQuery(q): RawQuery,
) -> ApiResult {
    let limit = query_int(
        q.as_deref(),
        "limit",
        DEFAULT_FETCH_LIMIT,
        1,
        MAX_FETCH_LIMIT,
    )?;
    let mut envs: Vec<Envelope> = fetch_envelopes(&st.db, &p.account, p.device, 0, limit + 1)
        .await?
        .into_iter()
        .map(|(_, e)| e)
        .collect();
    let more = envs.len() as i64 > limit;
    envs.truncate(limit as usize);
    Ok(reply(
        StatusCode::OK,
        json!({"envelopes": envs, "more": more}),
    ))
}

pub async fn ack_message(
    State(st): State<AppState>,
    p: Principal,
    Path(id): Path<String>,
) -> ApiResult {
    let id = ids::normalize_uuid(&id).ok_or_else(|| bad_request("id must be a UUID"))?;
    // Idempotent: an unknown or already acknowledged id is not an error.
    sqlx::query!("DELETE FROM envelopes WHERE id = ? AND account_id = ? AND device_id = ?", &id, &p.account, p.device)
        .execute(&st.db)
        .await?;
    Ok(no_content())
}

/// Upgrades an authenticated request to the delivery socket.
pub async fn websocket(
    State(st): State<AppState>,
    p: Principal,
    RawQuery(query): RawQuery,
    ws: Result<WebSocketUpgrade, axum::extract::ws::rejection::WebSocketUpgradeRejection>,
) -> Response {
    // `?active=0`: the user is away from this device (idle desktop, app in the background); it
    // connects without showing the account online. Older clients send nothing: active.
    let active = !query.as_deref().unwrap_or("").split('&').any(|kv| kv == "active=0");
    // Same order as Go: account lookup first, then the upgrade.
    let privacy = match sqlx::query!("SELECT privacy_last_seen AS `privacy_last_seen: String` FROM accounts WHERE id = ?", &p.account)
        .fetch_optional(&st.db)
        .await
    {
        Ok(Some(r)) => r.privacy_last_seen,
        Ok(None) => return unauthorized("account not found").into_response(),
        Err(e) => return ApiError::from(e).into_response(),
    };
    let ws = match ws {
        Ok(ws) => ws,
        // Like coder/websocket: a request that is not a WebSocket handshake gets 426.
        Err(e) => return (StatusCode::UPGRADE_REQUIRED, e.body_text()).into_response(),
    };
    let hub = st.hub.clone();
    ws.max_message_size(256 << 10)
        .on_upgrade(move |socket| hub.serve(socket, p.account, p.device, privacy == "nobody", active))
}
