//! Abuse and account-takeover defences: spam reports, the registration proof-of-work and the
//! approval of new password logins by an existing device ("require approval for new logins").

use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{MySql, Transaction};
use subtle::ConstantTimeEq;
use tracing::info;

use super::accounts::create_device;
use super::{no_content, reply};
use crate::auth::Principal;
use crate::error::{bad_request, conflict, gone, not_found, ApiError, ApiResult};
use crate::ids;
use crate::state::AppState;
use crate::validate::{b64, parse_json, validate_device_name, DeviceInfo, MAX_JSON_BODY};

/// A login waiting for approval expires after this.
pub const LOGIN_REQUEST_TTL_MS: i64 = 10 * 60 * 1000;
/// Pending login requests kept per account (older ones must expire or be answered first).
const MAX_PENDING_LOGIN_REQUESTS: i64 = 5;
/// How long one poll waits for an answer before replying "pending".
const LOGIN_POLL_WAIT: Duration = Duration::from_secs(20);
const POW_CHALLENGE_TTL_MS: i64 = 10 * 60 * 1000;
const POW_CONTEXT: &[u8] = b"chatapp-register-pow-v1";
const MAX_REPORT_ENVELOPES: usize = 20;

const LOGIN_PENDING: i64 = 0;
const LOGIN_APPROVED: i64 = 1;
const LOGIN_DENIED: i64 = 2;

// --- spam reports ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ReportRequest {
    #[serde(default)]
    account_id: String,
    /// Optional server envelope ids of the reported messages.
    #[serde(default)]
    envelope_ids: Vec<String>,
    /// Optional category shown to the operator (see REPORT_REASONS).
    #[serde(default)]
    reason: Option<String>,
}

/// Report categories a client may send with POST /v1/report.
pub const REPORT_REASONS: [&str; 5] = ["spam", "abuse", "harassment", "illegal", "other"];

/// POST /v1/report: reports an account for spam or abuse. Stored for admin review (table
/// spam_reports); one row per reporter and reported account.
pub async fn report_spam(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    st.rate_limit(
        &format!("report:acct:{}", p.account),
        st.limits.report_account,
    )?;
    let req: ReportRequest = parse_json(body, MAX_JSON_BODY).await?;
    let reported = ids::normalize_uuid(&req.account_id)
        .ok_or_else(|| bad_request("account_id must be an account UUID"))?;
    if reported == p.account {
        return Err(bad_request("cannot report your own account"));
    }
    let reason = req.reason.as_deref().map(str::trim).filter(|r| !r.is_empty());
    if reason.is_some_and(|r| !REPORT_REASONS.contains(&r)) {
        return Err(bad_request("reason must be one of spam, abuse, harassment, illegal, other"));
    }
    if req.envelope_ids.len() > MAX_REPORT_ENVELOPES {
        return Err(bad_request("envelope_ids has too many entries"));
    }
    let envelopes = req
        .envelope_ids
        .iter()
        .map(|e| ids::normalize_uuid(e).ok_or_else(|| bad_request("envelope_ids must be UUIDs")))
        .collect::<Result<Vec<_>, _>>()?;
    let exists = sqlx::query!("SELECT id FROM accounts WHERE id = ?", &reported)
        .fetch_optional(&st.db)
        .await?;
    if exists.is_none() {
        return Err(not_found("unknown account"));
    }
    let envelopes = (!envelopes.is_empty())
        .then(|| serde_json::to_string(&envelopes).unwrap_or_default());
    let now = crate::now_millis();
    sqlx::query!(
        "INSERT INTO spam_reports (reporter_id, reported_id, envelope_ids, reason, report_count, created_at, updated_at)
         VALUES (?, ?, ?, ?, 1, ?, ?)
         ON DUPLICATE KEY UPDATE envelope_ids = COALESCE(VALUES(envelope_ids), envelope_ids),
             reason = COALESCE(VALUES(reason), reason), report_count = report_count + 1,
             updated_at = VALUES(updated_at), resolved_at = NULL, resolution = NULL, resolution_note = NULL",
        &p.account,
        &reported,
        &envelopes,
        reason,
        now,
        now
    )
    .execute(&st.db)
    .await?;
    info!(reporter = %p.account, reported = %reported, "spam report");
    Ok(no_content())
}

// --- registration proof-of-work -----------------------------------------------------------------

/// Number of leading zero bits of a hash.
fn leading_zero_bits(h: &[u8]) -> u32 {
    let mut n = 0;
    for b in h {
        if *b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

/// SHA-256(context || challenge || nonce as 8 big-endian bytes) must start with `bits` zero bits.
pub fn pow_valid(challenge: &[u8], nonce: u64, bits: u32) -> bool {
    let mut h = Sha256::new();
    h.update(POW_CONTEXT);
    h.update(challenge);
    h.update(nonce.to_be_bytes());
    leading_zero_bits(&h.finalize()) >= bits
}

/// POST /v1/accounts/challenge: a single-use proof-of-work challenge for registration
/// (`difficulty` 0 = none required, no challenge).
pub async fn registration_challenge(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult {
    st.rate_limit(
        &format!("register-challenge:ip:{}", st.client_ip(&headers, peer)),
        st.limits.register_ip,
    )?;
    let bits = crate::adaptive_pow::effective_bits(&st);
    if bits == 0 {
        return Ok(reply(StatusCode::OK, json!({"difficulty": 0})));
    }
    let challenge = ids::random_bytes(32);
    let expires_at = crate::now_millis() + POW_CHALLENGE_TTL_MS;
    sqlx::query!(
        "INSERT INTO registration_challenges (challenge, difficulty, expires_at) VALUES (?, ?, ?)",
        &challenge,
        bits,
        expires_at
    )
    .execute(&st.db)
    .await?;
    Ok(reply(
        StatusCode::OK,
        json!({"challenge": b64::encode(&challenge), "difficulty": bits, "expires_at": expires_at}),
    ))
}

#[derive(Deserialize)]
pub struct PowSolution {
    #[serde(default, with = "b64")]
    pub challenge: Vec<u8>,
    #[serde(default)]
    pub nonce: u64,
}

fn pow_error(msg: &str) -> ApiError {
    crate::metrics::inc(&crate::metrics::POW_REJECTED);
    ApiError::new(StatusCode::FORBIDDEN, "pow_required", msg.to_string())
}

/// Checks (and consumes) the registration proof-of-work when the server requires one.
pub async fn check_registration_pow(
    st: &AppState,
    pow: Option<&PowSolution>,
) -> Result<(), ApiError> {
    if st.settings.get().pow_bits == 0 {
        return Ok(());
    }
    let pow = pow.ok_or_else(|| pow_error("registration requires a proof-of-work"))?;
    if pow.challenge.len() != 32 {
        return Err(pow_error("invalid proof-of-work challenge"));
    }
    let row = sqlx::query!(
        "SELECT difficulty AS `difficulty: i64` FROM registration_challenges WHERE challenge = ? AND expires_at >= ?",
        &pow.challenge,
        crate::now_millis()
    )
    .fetch_optional(&st.db)
    .await?;
    let Some(row) = row else {
        return Err(pow_error("invalid or expired proof-of-work challenge"));
    };
    // Single use, even when the solution is wrong.
    let res = sqlx::query!("DELETE FROM registration_challenges WHERE challenge = ?", &pow.challenge)
        .execute(&st.db)
        .await?;
    if res.rows_affected() != 1 {
        return Err(pow_error("invalid or expired proof-of-work challenge"));
    }
    if !pow_valid(&pow.challenge, pow.nonce, row.difficulty as u32) {
        return Err(pow_error("wrong proof-of-work solution"));
    }
    Ok(())
}

// --- approval of new logins -----------------------------------------------------------------------

/// Whether a password login to `account` (locked by tx) must be approved by an existing device:
/// the account turned the setting on and still has at least one device.
pub async fn login_approval_required(
    tx: &mut Transaction<'_, MySql>,
    account: &str,
) -> Result<bool, ApiError> {
    let row = sqlx::query!(
        "SELECT login_approval AS `login_approval: bool`, (SELECT COUNT(*) FROM devices WHERE account_id = ?) AS `devices!: i64`
         FROM accounts WHERE id = ?",
        account,
        account
    )
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row.is_some_and(|r| r.login_approval && r.devices > 0))
}

/// Records a login waiting for approval; returns the reply for the requester. `shown_name`
/// is what the approving device sees (the device itself may only carry a placeholder name,
/// its real one being encrypted later).
pub async fn create_login_request(
    tx: &mut Transaction<'_, MySql>,
    account: &str,
    device: &DeviceInfo,
    shown_name: &str,
) -> Result<serde_json::Value, ApiError> {
    let shown_name = if shown_name.is_empty() || validate_device_name(shown_name).is_err() {
        device.name.as_str()
    } else {
        shown_name
    };
    let now = crate::now_millis();
    sqlx::query!("DELETE FROM login_requests WHERE account_id = ? AND expires_at < ?", account, now)
        .execute(&mut **tx)
        .await?;
    let pending = sqlx::query!("SELECT COUNT(*) AS `n!: i64` FROM login_requests WHERE account_id = ?", account)
        .fetch_one(&mut **tx)
        .await?
        .n;
    if pending >= MAX_PENDING_LOGIN_REQUESTS {
        return Err(conflict("too many logins are waiting for approval"));
    }
    let id = hex::encode(ids::random_bytes(16));
    let (secret, secret_hash) = ids::new_token();
    let expires_at = now + LOGIN_REQUEST_TTL_MS;
    sqlx::query!(
        "INSERT INTO login_requests
         (id, account_id, secret_hash, name, device_name, platform, registration_id, status, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
        &id,
        account,
        &secret_hash,
        shown_name,
        &device.name,
        &device.platform,
        device.registration_id,
        now,
        expires_at
    )
    .execute(&mut **tx)
    .await?;
    Ok(json!({
        "status": "approval_required",
        "request_id": id,
        "secret": secret,
        "expires_at": expires_at,
    }))
}

#[derive(Deserialize)]
struct LoginPollRequest {
    #[serde(default)]
    request_id: String,
    #[serde(default)]
    secret: String,
}

fn valid_request_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn login_gone() -> ApiError {
    gone("this login request expired or does not exist")
}

/// POST /v1/auth/login/poll: long poll of a login waiting for approval. Replies
/// {"status":"pending"} after a while, the full login reply once approved (the device is
/// created then), 403 login_denied when denied and 410 when expired or unknown.
pub async fn login_poll(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult {
    st.rate_limit(
        &format!("login-poll:ip:{}", st.client_ip(&headers, peer)),
        st.limits.login_poll_ip,
    )?;
    let req: LoginPollRequest = parse_json(body, MAX_JSON_BODY).await?;
    if !valid_request_id(&req.request_id) || !ids::valid_token_format(&req.secret) {
        return Err(login_gone());
    }
    let secret_hash = ids::hash_token(&req.secret);
    let deadline = tokio::time::Instant::now() + LOGIN_POLL_WAIT;
    loop {
        let row = sqlx::query!(
            "SELECT secret_hash, status AS `status: i64`, expires_at FROM login_requests WHERE id = ?",
            &req.request_id
        )
        .fetch_optional(&st.db)
        .await?;
        let Some(row) = row else {
            return Err(login_gone());
        };
        if !bool::from(row.secret_hash.as_slice().ct_eq(&secret_hash))
            || row.expires_at < crate::now_millis()
        {
            return Err(login_gone());
        }
        match row.status {
            LOGIN_APPROVED => return finish_approved_login(&st, &req.request_id).await,
            LOGIN_DENIED => {
                sqlx::query!("DELETE FROM login_requests WHERE id = ?", &req.request_id)
                    .execute(&st.db)
                    .await?;
                return Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    "login_denied",
                    "the login was denied on another device",
                ));
            }
            _ => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(reply(StatusCode::OK, json!({"status": "pending"})));
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Creates the device of an approved login request and consumes the request.
async fn finish_approved_login(st: &AppState, id: &str) -> ApiResult {
    let mut tx = st.db.begin().await?;
    let req = sqlx::query!(
        "SELECT account_id AS `account_id: String`, device_name AS `device_name: String`,
         platform AS `platform: String`, registration_id AS `registration_id: i64` FROM login_requests
         WHERE id = ? AND status = ? FOR UPDATE",
        id,
        LOGIN_APPROVED
    )
    .fetch_optional(&mut *tx)
    .await?;
    let Some(req) = req else {
        return Err(login_gone());
    };
    let account = req.account_id;
    let acct = sqlx::query!(
        "SELECT number AS `number: String`, wrapped_account_key, identity_key FROM accounts WHERE id = ? FOR UPDATE",
        &account
    )
    .fetch_optional(&mut *tx)
    .await?;
    let Some(acct) = acct else {
        return Err(login_gone());
    };
    let device = DeviceInfo {
        name: req.device_name,
        platform: req.platform,
        registration_id: req.registration_id,
    };
    let (device_id, token) = create_device(st, &mut tx, &account, &device).await?;
    sqlx::query!("DELETE FROM login_requests WHERE id = ?", id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    st.hub
        .send_event(&account, device_id, &json!({"kind": "devices_changed"}));
    info!(account = %account, device = device_id, "approved login");
    Ok(reply(
        StatusCode::OK,
        json!({
            "status": "approved",
            "account_id": account,
            "number": acct.number,
            "device_id": device_id,
            "token": token,
            "wrapped_account_key": b64::encode(&acct.wrapped_account_key),
            "identity_key": b64::encode(&acct.identity_key),
        }),
    ))
}

#[derive(Serialize)]
struct LoginRequestView {
    id: String,
    name: String,
    platform: String,
    created_at: i64,
    expires_at: i64,
}

/// GET /v1/account/login-requests: logins waiting for approval by one of our devices.
pub async fn list_login_requests(State(st): State<AppState>, p: Principal) -> ApiResult {
    let rows = sqlx::query!(
        "SELECT id AS `id: String`, name AS `name: String`, platform AS `platform: String`, created_at, expires_at FROM login_requests
         WHERE account_id = ? AND status = ? AND expires_at >= ? ORDER BY created_at",
        &p.account,
        LOGIN_PENDING,
        crate::now_millis()
    )
    .fetch_all(&st.db)
    .await?;
    let out: Vec<LoginRequestView> = rows
        .iter()
        .map(|r| LoginRequestView {
            id: r.id.clone(),
            name: r.name.clone(),
            platform: r.platform.clone(),
            created_at: r.created_at,
            expires_at: r.expires_at,
        })
        .collect();
    Ok(reply(StatusCode::OK, json!({"requests": out})))
}

#[derive(Deserialize)]
struct AnswerRequest {
    #[serde(default)]
    approve: Option<bool>,
}

/// POST /v1/account/login-requests/{id} {"approve": bool}: an existing device approves or
/// denies a pending login.
pub async fn answer_login_request(
    State(st): State<AppState>,
    p: Principal,
    Path(id): Path<String>,
    body: Body,
) -> ApiResult {
    let req: AnswerRequest = parse_json(body, MAX_JSON_BODY).await?;
    let Some(approve) = req.approve else {
        return Err(bad_request("approve is required"));
    };
    if !valid_request_id(&id) {
        return Err(not_found("no such login request"));
    }
    let res = sqlx::query!(
        "UPDATE login_requests SET status = ?
         WHERE id = ? AND account_id = ? AND status = ? AND expires_at >= ?",
        if approve { LOGIN_APPROVED } else { LOGIN_DENIED },
        &id,
        &p.account,
        LOGIN_PENDING,
        crate::now_millis()
    )
    .execute(&st.db)
    .await?;
    if res.rows_affected() == 0 {
        return Err(not_found("no such login request"));
    }
    // Other devices drop the prompt.
    st.hub
        .send_event(&p.account, p.device, &json!({"kind": "login_request"}));
    info!(account = %p.account, device = p.device, approve, "login request answered");
    Ok(no_content())
}

#[derive(Deserialize)]
struct LoginApprovalSetting {
    #[serde(default)]
    enabled: Option<bool>,
}

/// PUT /v1/account/login-approval {"enabled": bool}
pub async fn set_login_approval(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    let req: LoginApprovalSetting = parse_json(body, MAX_JSON_BODY).await?;
    let Some(enabled) = req.enabled else {
        return Err(bad_request("enabled is required"));
    };
    sqlx::query!("UPDATE accounts SET login_approval = ? WHERE id = ?", enabled, &p.account)
        .execute(&st.db)
        .await?;
    // Logins already waiting stay pending until answered or expired.
    Ok(no_content())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_of_work() {
        assert_eq!(leading_zero_bits(&[0, 0, 0x10, 0xff]), 19);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
        assert_eq!(leading_zero_bits(&[0, 0]), 16);
        let challenge = [42u8; 32];
        let bits = 12;
        let nonce = (0u64..).find(|n| pow_valid(&challenge, *n, bits)).unwrap();
        assert!(pow_valid(&challenge, nonce, bits));
        assert!(pow_valid(&challenge, nonce, 0));
        assert!(valid_request_id(&hex::encode([1u8; 16])));
        assert!(!valid_request_id("ABCDEF"));
    }
}
