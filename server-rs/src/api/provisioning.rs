//! Device linking by QR code (API section 13).
//!
//! Sessions are short-lived (5 minutes) and kept in memory: the server runs as a single
//! instance, and losing them on restart only means the user scans again.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{ConnectInfo, FromRequestParts, Path, RawQuery, Request, State};
use axum::http::{HeaderMap, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::accounts::create_device;
use super::{no_content, reply};
use crate::auth::Principal;
use crate::error::{
    bad_request, conflict, internal_from, not_found, rate_limited, unauthorized, ApiError,
    ApiResult,
};
use crate::ids;
use crate::state::AppState;
use crate::validate::{b64, parse_json, DeviceInfo, MAX_JSON_BODY};

const PROVISIONING_TTL_MS: i64 = 5 * 60 * 1000;
const MAX_PROVISIONING_BODY: usize = 8 << 10;
const MAX_LINK_PAYLOAD: usize = 4 << 10;
/// Sessions live in memory: cap them so unauthenticated requests cannot exhaust it.
const MAX_PROVISIONING_SESSIONS: usize = 10000;

struct Session {
    mode: String,  // "new" | "existing"
    state: String, // waiting | claimed | approved | done
    device_name: String,
    /// Creating account (mode existing) or approving account.
    account: String,
    /// Poll keys (sha256) of the two sides.
    creator_key: Vec<u8>,
    /// The new device's key (== creator_key for mode new).
    new_key: Option<Vec<u8>>,
    payload: Option<Vec<u8>>,
    link_token: String,
    expires_at: i64,
}

impl Session {
    fn view(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("mode".into(), json!(self.mode));
        m.insert("state".into(), json!(self.state));
        m.insert(
            "device_name".into(),
            if self.device_name.is_empty() {
                Value::Null
            } else {
                json!(self.device_name)
            },
        );
        m.insert("expires_at".into(), json!(self.expires_at));
        m
    }
}

struct LinkToken {
    account: String,
    expires_at: i64,
}

#[derive(Default)]
struct Sessions {
    sessions: HashMap<String, Session>,
    /// hex(sha256(token)) -> account
    tokens: HashMap<String, LinkToken>,
}

impl Sessions {
    /// A live session (None if unknown or expired).
    fn get(&mut self, id: &str) -> Option<&mut Session> {
        if self
            .sessions
            .get(id)
            .is_some_and(|s| crate::now_millis() > s.expires_at)
        {
            self.sessions.remove(id);
        }
        self.sessions.get_mut(id)
    }

    fn cleanup(&mut self) {
        let now = crate::now_millis();
        self.sessions.retain(|_, s| now <= s.expires_at);
        self.tokens.retain(|_, t| now <= t.expires_at);
    }
}

/// In-memory device-linking sessions and link tokens.
#[derive(Default)]
pub struct ProvisioningStore {
    inner: Mutex<Sessions>,
}

impl ProvisioningStore {
    /// Drops expired sessions and tokens.
    pub fn cleanup(&self) {
        self.inner.lock().unwrap().cleanup();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Sessions> {
        self.inner.lock().unwrap()
    }
}

fn random_b64(n: usize) -> String {
    URL_SAFE_NO_PAD.encode(ids::random_bytes(n))
}

fn hash_key(k: &str) -> Vec<u8> {
    Sha256::digest(k.as_bytes()).to_vec()
}

fn valid_device_name(n: &str) -> Result<String, ApiError> {
    let n = n.trim();
    if n.is_empty() || n.chars().count() > 64 {
        return Err(bad_request("device_name must be 1-64 characters"));
    }
    Ok(n.to_string())
}

fn session_not_found() -> ApiError {
    not_found("link session not found or expired")
}

#[derive(Deserialize)]
struct CreateRequest {
    #[serde(default)]
    mode: String,
    #[serde(default)]
    device_name: String,
}

/// POST /v1/provisioning. Mode "existing" requires authentication, mode "new" does not.
pub async fn create(State(st): State<AppState>, req: Request) -> ApiResult {
    let (mut parts, body) = req.into_parts();
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0)
        .ok_or_else(|| internal_from("provisioning", "missing peer address"))?;
    st.rate_limit(
        &format!("provision:ip:{}", st.client_ip(&parts.headers, peer)),
        st.limits.login_ip,
    )?;
    let req: CreateRequest = parse_json(body, MAX_PROVISIONING_BODY).await?;
    let (account, name) = match req.mode.as_str() {
        "new" => (String::new(), valid_device_name(&req.device_name)?),
        "existing" => (
            Principal::from_request_parts(&mut parts, &st)
                .await?
                .account,
            String::new(),
        ),
        _ => return Err(bad_request("mode must be new or existing")),
    };
    let poll_key = random_b64(32);
    let creator_key = hash_key(&poll_key);
    let sess = Session {
        mode: req.mode.clone(),
        state: "waiting".into(),
        device_name: name,
        account,
        new_key: (req.mode == "new").then(|| creator_key.clone()),
        creator_key,
        payload: None,
        link_token: String::new(),
        expires_at: crate::now_millis() + PROVISIONING_TTL_MS,
    };
    let id = hex::encode(ids::random_bytes(16));
    let expires_at = sess.expires_at;
    {
        let mut ps = st.prov.lock();
        if ps.sessions.len() >= MAX_PROVISIONING_SESSIONS {
            ps.cleanup();
            if ps.sessions.len() >= MAX_PROVISIONING_SESSIONS {
                return Err(rate_limited(Duration::from_secs(60)));
            }
        }
        ps.sessions.insert(id.clone(), sess);
    }
    Ok(reply(
        StatusCode::OK,
        json!({"id": id, "poll_key": poll_key, "expires_at": expires_at}),
    ))
}

#[derive(Deserialize)]
struct ClaimRequest {
    #[serde(default)]
    device_name: String,
}

pub async fn claim(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Body,
) -> ApiResult {
    st.rate_limit(
        &format!("provision:ip:{}", st.client_ip(&headers, peer)),
        st.limits.login_ip,
    )?;
    let req: ClaimRequest = parse_json(body, MAX_PROVISIONING_BODY).await?;
    let name = valid_device_name(&req.device_name)?;
    let mut ps = st.prov.lock();
    let sess = ps.get(&id).ok_or_else(session_not_found)?;
    if sess.mode != "existing" || sess.state != "waiting" {
        return Err(conflict("link session cannot be claimed"));
    }
    let poll_key = random_b64(32);
    sess.new_key = Some(hash_key(&poll_key));
    sess.device_name = name;
    sess.state = "claimed".into();
    Ok(reply(StatusCode::OK, json!({"poll_key": poll_key})))
}

pub async fn get_session(
    State(st): State<AppState>,
    p: Principal,
    Path(id): Path<String>,
) -> ApiResult {
    let mut ps = st.prov.lock();
    match ps.get(&id) {
        Some(sess) if !(sess.mode == "existing" && sess.account != p.account) => {
            Ok(reply(StatusCode::OK, sess.view()))
        }
        _ => Err(session_not_found()),
    }
}

pub async fn poll(
    State(st): State<AppState>,
    Path(id): Path<String>,
    RawQuery(q): RawQuery,
) -> ApiResult {
    let key = q
        .and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == "key")
                .map(|(_, v)| v.into_owned())
        })
        .unwrap_or_default();
    let mut ps = st.prov.lock();
    let sess = ps.get(&id).ok_or_else(session_not_found)?;
    if key.is_empty() {
        return Err(session_not_found());
    }
    let h = hash_key(&key);
    let is_new = sess
        .new_key
        .as_ref()
        .is_some_and(|k| bool::from(h.as_slice().ct_eq(k)));
    let is_creator = bool::from(h.as_slice().ct_eq(&sess.creator_key));
    if !is_new && !is_creator {
        return Err(session_not_found());
    }
    let mut out = sess.view();
    if is_new && sess.state == "approved" {
        let payload = sess.payload.take();
        out.insert(
            "payload".into(),
            payload
                .map(|p| Value::String(b64::encode(&p)))
                .unwrap_or(Value::Null),
        );
        out.insert(
            "link_token".into(),
            json!(std::mem::take(&mut sess.link_token)),
        );
        sess.state = "done".into();
    }
    Ok(reply(StatusCode::OK, out))
}

#[derive(Deserialize)]
struct ApproveRequest {
    #[serde(default, with = "b64")]
    payload: Vec<u8>,
}

pub async fn approve(
    State(st): State<AppState>,
    p: Principal,
    Path(id): Path<String>,
    body: Body,
) -> ApiResult {
    let req: ApproveRequest = parse_json(body, MAX_PROVISIONING_BODY).await?;
    if req.payload.is_empty() || req.payload.len() > MAX_LINK_PAYLOAD {
        return Err(bad_request("payload must be 1-4096 bytes"));
    }
    let mut ps = st.prov.lock();
    let token = random_b64(32);
    {
        let sess = match ps.get(&id) {
            Some(s) if !(s.mode == "existing" && s.account != p.account) => s,
            _ => return Err(session_not_found()),
        };
        let ready = (sess.mode == "new" && sess.state == "waiting")
            || (sess.mode == "existing" && sess.state == "claimed");
        if !ready {
            return Err(conflict("link session is not waiting for approval"));
        }
        sess.account = p.account.clone();
        sess.payload = Some(req.payload);
        sess.link_token = token.clone();
        sess.state = "approved".into();
    }
    ps.tokens.insert(
        hex::encode(hash_key(&token)),
        LinkToken {
            account: p.account.clone(),
            expires_at: crate::now_millis() + PROVISIONING_TTL_MS,
        },
    );
    Ok(no_content())
}

#[derive(Deserialize)]
struct LinkRequest {
    #[serde(default)]
    link_token: String,
    #[serde(default)]
    device: Option<DeviceInfo>,
}

/// POST /v1/auth/link body (keys in Go's sorted map order).
#[derive(Serialize)]
struct LinkResponse {
    account_id: String,
    device_id: i64,
    #[serde(with = "b64")]
    identity_key: Vec<u8>,
    kdf: Box<RawValue>,
    number: String,
    token: String,
    #[serde(with = "b64")]
    wrapped_account_key: Vec<u8>,
}

pub async fn link_device(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult {
    st.rate_limit(
        &format!("login:ip:{}", st.client_ip(&headers, peer)),
        st.limits.login_ip,
    )?;
    let req: LinkRequest = parse_json(body, MAX_JSON_BODY).await?;
    let device = DeviceInfo::validate(req.device.as_ref())?;
    let key = hex::encode(hash_key(&req.link_token));
    let tok = st.prov.lock().tokens.remove(&key); // single use
    let account = match tok {
        Some(t) if crate::now_millis() <= t.expires_at && !req.link_token.is_empty() => t.account,
        _ => return Err(unauthorized("invalid or expired link token")),
    };

    // Retry only the transaction: the link token is already consumed (single use).
    let (row, device_id, token) = crate::db::retry_tx(|| async {
        let mut tx = st.db.begin().await?;
        let row = sqlx::query!("SELECT number AS `number: String`, wrapped_account_key, identity_key, kdf AS `kdf: String` FROM accounts WHERE id = ? FOR UPDATE", &account)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else {
            return Err(unauthorized("account no longer exists"));
        };
        let (device_id, token) = create_device(&st, &mut tx, &account, device).await?;
        tx.commit().await?;
        Ok((row, device_id, token))
    })
    .await?;
    st.hub
        .send_event(&account, device_id, &json!({"kind": "devices_changed"}));
    let kdf = RawValue::from_string(row.kdf)
        .map_err(|e| internal_from("invalid stored kdf", e))?;
    Ok(reply(
        StatusCode::OK,
        LinkResponse {
            account_id: account,
            device_id,
            identity_key: row.identity_key,
            kdf,
            number: row.number,
            token,
            wrapped_account_key: row.wrapped_account_key,
        },
    ))
}
