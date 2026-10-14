//! Registration, login, recovery and account settings (API sections 3-4).

use std::collections::BTreeSet;
use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use sqlx::{MySql, Transaction};
use subtle::ConstantTimeEq;
use tracing::{error, info, warn};

use super::groups::{lock_group, push_group_updated, remove_members_tx, GroupChange};
use super::totp::{check_totp, totp_enabled};
use super::{no_content, query_strings, reply};
use crate::auth::Principal;
use crate::db::{is_duplicate_key, RowExt};
use crate::error::{bad_request, forbidden, internal_from, unauthorized, ApiError, ApiResult};
use crate::ids;
use crate::state::AppState;
use crate::validate::{
    b64, hash_auth_key, parse_json, parse_kdf, require_len, require_range, valid_phone, DeviceInfo,
    AUTH_KEY_LEN, EC_PUBLIC_KEY_LEN, MAX_DEVICE_ID, MAX_JSON_BODY, MAX_WRAPPED_KEY_LEN,
    RECOVERY_PUB_KEY_LEN,
};

const RECOVERY_CHALLENGE_TTL_MS: i64 = 5 * 60 * 1000;
const RECOVERY_CONTEXT: &str = "chatapp-recover-v1:";
const PHONE_CODE_TTL_MS: i64 = 10 * 60 * 1000;
const PHONE_CODE_MAX_ATTEMPTS: i64 = 5;
const MAX_NUMBER_ATTEMPTS: usize = 20;
const ED25519_SIGNATURE_LEN: usize = 64;

/// A login with a wrong number or password (counted for the admin security overview).
fn failed_login() -> ApiError {
    crate::metrics::inc(&crate::metrics::FAILED_AUTH_LOGINS);
    unauthorized("invalid number or password")
}

fn too_many_devices() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "too_many_devices",
        "device limit reached",
    )
}

/// Compared against when the account does not exist, so that unknown numbers and wrong
/// passwords take the same code path.
fn dummy_auth_hash() -> Vec<u8> {
    Sha256::digest(b"chatapp-dummy-auth-key").to_vec()
}

fn raw_json(s: String) -> Result<Box<RawValue>, ApiError> {
    RawValue::from_string(s).map_err(|e| internal_from("invalid stored json", e))
}

/// Allocates the smallest free device id for `account` (which must be locked by the caller's
/// transaction) and inserts the device with a fresh token.
pub async fn create_device(
    st: &AppState,
    tx: &mut Transaction<'_, MySql>,
    account: &str,
    d: &DeviceInfo,
) -> Result<(i64, String), ApiError> {
    // Banned accounts (admin CLI `reports ban-account`) cannot log in or link devices.
    let banned = sqlx::query!("SELECT id FROM accounts WHERE id = ? AND banned_at IS NOT NULL", account)
        .fetch_optional(&mut **tx)
        .await?;
    if banned.is_some() {
        return Err(forbidden("this account has been banned"));
    }
    let rows = sqlx::query!("SELECT device_id AS `device_id: i64` FROM devices WHERE account_id = ? FOR UPDATE", account)
        .fetch_all(&mut **tx)
        .await?;
    let used: BTreeSet<i64> = rows.iter().map(|r| r.device_id).collect();
    if used.len() as i64 >= st.settings.get().max_devices {
        return Err(too_many_devices());
    }
    let device_id = (1..=MAX_DEVICE_ID)
        .find(|id| !used.contains(id))
        .ok_or_else(too_many_devices)?;
    let (token, hash) = ids::new_token();
    let now = crate::now_millis();
    sqlx::query!(
        "INSERT INTO devices
         (account_id, device_id, name, platform, registration_id, token_hash, created_at, last_seen_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        account,
        device_id,
        &d.name,
        &d.platform,
        d.registration_id,
        &hash,
        now,
        now
    )
    .execute(&mut **tx)
    .await?;
    crate::metrics::bump(crate::metrics::NEW_DEVICES, 1);
    Ok((device_id, token))
}

#[derive(Deserialize)]
struct RegisterRequest {
    #[serde(default)]
    kdf: Option<Box<RawValue>>,
    #[serde(default, with = "b64")]
    auth_key: Vec<u8>,
    #[serde(default, with = "b64")]
    wrapped_account_key: Vec<u8>,
    #[serde(default, with = "b64")]
    identity_key: Vec<u8>,
    #[serde(default, with = "b64")]
    recovery_public_key: Vec<u8>,
    #[serde(default)]
    device: Option<DeviceInfo>,
    /// Solution of a POST /v1/accounts/challenge proof-of-work (when the server requires one).
    #[serde(default)]
    pow: Option<super::security::PowSolution>,
}

pub async fn register(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult {
    st.rate_limit(
        &format!("register:ip:{}", st.client_ip(&headers, peer)),
        st.limits.register_ip,
    )?;
    if !st.settings.get().registration_enabled {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "registration_disabled",
            "registration is disabled on this server",
        ));
    }
    let req: RegisterRequest = parse_json(body, MAX_JSON_BODY).await?;
    let kdf = parse_kdf(req.kdf.as_deref())?;
    require_len("auth_key", &req.auth_key, AUTH_KEY_LEN)?;
    require_range(
        "wrapped_account_key",
        &req.wrapped_account_key,
        1,
        MAX_WRAPPED_KEY_LEN,
    )?;
    require_len("identity_key", &req.identity_key, EC_PUBLIC_KEY_LEN)?;
    require_len(
        "recovery_public_key",
        &req.recovery_public_key,
        RECOVERY_PUB_KEY_LEN,
    )?;
    let device = DeviceInfo::validate(req.device.as_ref())?;
    super::security::check_registration_pow(&st, req.pow.as_ref()).await?;

    let account_id = ids::new_uuid();
    let mut tx = st.db.begin().await?;
    let now = crate::now_millis();
    let mut number = String::new();
    for _ in 0..MAX_NUMBER_ATTEMPTS {
        let candidate = ids::new_account_number();
        let res = sqlx::query!(
            "INSERT INTO account_numbers (number, account_id, created_at) VALUES (?, ?, ?)",
            &candidate,
            &account_id,
            now
        )
        .execute(&mut *tx)
        .await;
        match res {
            Err(e) if is_duplicate_key(&e) => continue, // collision with an existing or deleted number
            Err(e) => return Err(e.into()),
            Ok(_) => {
                number = candidate;
                break;
            }
        }
    }
    if number.is_empty() {
        return Err(internal_from(
            "register",
            "could not allocate a unique account number",
        ));
    }
    sqlx::query!(
        "INSERT INTO accounts
         (id, number, auth_key_hash, kdf, wrapped_account_key, identity_key, recovery_public_key, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        &account_id,
        &number,
        hash_auth_key(&req.auth_key),
        &kdf,
        &req.wrapped_account_key,
        &req.identity_key,
        &req.recovery_public_key,
        now
    )
    .execute(&mut *tx)
    .await?;
    let (device_id, token) = create_device(&st, &mut tx, &account_id, device).await?;
    tx.commit().await?;
    crate::metrics::bump(crate::metrics::REGISTRATIONS, 1);
    info!(account = %account_id, "account registered");
    // Into the key transparency log right away, so contacts can verify the key at once.
    crate::keytrans::sequence_now(&st.db).await;
    Ok(reply(
        StatusCode::OK,
        json!({"account_id": account_id, "number": number, "device_id": device_id, "token": token}),
    ))
}

#[derive(Deserialize)]
struct NumberRequest {
    #[serde(default)]
    number: String,
}

#[derive(Serialize)]
struct KdfResponse {
    kdf: Box<RawValue>,
}

pub async fn prelogin(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult {
    st.rate_limit(
        &format!("prelogin:ip:{}", st.client_ip(&headers, peer)),
        st.limits.login_ip,
    )?;
    let req: NumberRequest = parse_json(body, MAX_JSON_BODY).await?;
    if !ids::valid_number(&req.number) {
        return Err(bad_request("number must be 16 digits"));
    }
    st.rate_limit(
        &format!("prelogin:number:{}", req.number),
        st.limits.login_number,
    )?;
    let row = sqlx::query!("SELECT kdf AS `kdf: String` FROM accounts WHERE number = ?", &req.number)
        .fetch_optional(&st.db)
        .await?;
    let kdf = match row {
        Some(r) => r.kdf,
        None => crate::validate::fake_kdf(&st.cfg.server_secret, &req.number),
    };
    Ok(reply(
        StatusCode::OK,
        KdfResponse {
            kdf: raw_json(kdf)?,
        },
    ))
}

#[derive(Deserialize)]
struct LoginRequest {
    #[serde(default)]
    number: String,
    #[serde(default, with = "b64")]
    auth_key: Vec<u8>,
    #[serde(default)]
    device: Option<DeviceInfo>,
    /// Current two-step verification code, when the account has it enabled.
    #[serde(default)]
    totp: String,
    /// Name shown to the account's devices when the login needs their approval (clients
    /// that encrypt device names send only a placeholder in `device`).
    #[serde(default)]
    display_name: String,
}

struct AccountSecrets {
    id: String,
    auth_key_hash: Vec<u8>,
    wrapped_account_key: Vec<u8>,
    identity_key: Vec<u8>,
    recovery_public_key: Vec<u8>,
}

async fn load_account_by_number(
    st: &AppState,
    number: &str,
) -> Result<Option<AccountSecrets>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT id AS `id: String`, auth_key_hash, wrapped_account_key, identity_key, recovery_public_key
         FROM accounts WHERE number = ?",
        number
    )
    .fetch_optional(&st.db)
    .await?;
    Ok(row.map(|r| AccountSecrets {
        id: r.id,
        auth_key_hash: r.auth_key_hash,
        wrapped_account_key: r.wrapped_account_key,
        identity_key: r.identity_key,
        recovery_public_key: r.recovery_public_key,
    }))
}

pub async fn login(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult {
    st.rate_limit(
        &format!("login:ip:{}", st.client_ip(&headers, peer)),
        st.limits.login_ip,
    )?;
    let req: LoginRequest = parse_json(body, MAX_JSON_BODY).await?;
    if !ids::valid_number(&req.number) {
        return Err(bad_request("number must be 16 digits"));
    }
    st.rate_limit(
        &format!("login:number:{}", req.number),
        st.limits.login_number,
    )?;
    require_len("auth_key", &req.auth_key, AUTH_KEY_LEN)?;
    let device = DeviceInfo::validate(req.device.as_ref())?;
    let acct = load_account_by_number(&st, &req.number).await?;
    let expected = match &acct {
        Some(a) => a.auth_key_hash.clone(),
        None => dummy_auth_hash(),
    };
    let matches = bool::from(hash_auth_key(&req.auth_key).as_slice().ct_eq(&expected));
    let acct = match acct {
        Some(a) if matches => a,
        _ => return Err(failed_login()),
    };

    let mut tx = st.db.begin().await?;
    // Lock the account row and re-check the password inside the transaction (it may have
    // been changed or the account deleted concurrently).
    let row = sqlx::query!("SELECT auth_key_hash FROM accounts WHERE id = ? FOR UPDATE", &acct.id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(row) = row else {
        return Err(failed_login());
    };
    if !bool::from(
        row.auth_key_hash
            .as_slice()
            .ct_eq(&hash_auth_key(&req.auth_key)),
    ) {
        return Err(failed_login());
    }
    check_totp(&st, &mut tx, &acct.id, &req.totp).await?;
    if super::security::login_approval_required(&mut tx, &acct.id).await? {
        // The device is created (and the wrapped account key handed out) only once one of
        // the account's devices approves (POST /v1/auth/login/poll).
        let pending = super::security::create_login_request(&mut tx, &acct.id, device, &req.display_name).await?;
        tx.commit().await?;
        st.hub
            .send_event(&acct.id, 0, &json!({"kind": "login_request"}));
        info!(account = %acct.id, "login waiting for approval");
        return Ok(reply(StatusCode::ACCEPTED, pending));
    }
    let (device_id, token) = create_device(&st, &mut tx, &acct.id, device).await?;
    tx.commit().await?;
    st.hub
        .send_event(&acct.id, device_id, &json!({"kind": "devices_changed"}));
    Ok(reply(
        StatusCode::OK,
        json!({
            "account_id": acct.id,
            "number": req.number,
            "device_id": device_id,
            "token": token,
            "wrapped_account_key": b64::encode(&acct.wrapped_account_key),
            "identity_key": b64::encode(&acct.identity_key),
        }),
    ))
}

pub async fn recover_challenge(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult {
    st.rate_limit(
        &format!("recover:ip:{}", st.client_ip(&headers, peer)),
        st.limits.recover_ip,
    )?;
    let req: NumberRequest = parse_json(body, MAX_JSON_BODY).await?;
    if !ids::valid_number(&req.number) {
        return Err(bad_request("number must be 16 digits"));
    }
    let challenge = ids::random_bytes(32);
    let row = sqlx::query!("SELECT id AS `id: String` FROM accounts WHERE number = ?", &req.number)
        .fetch_optional(&st.db)
        .await?;
    // Unknown number: return a random challenge and store nothing.
    if let Some(row) = row {
        let account_id = row.id;
        let now = crate::now_millis();
        sqlx::query!("DELETE FROM recovery_challenges WHERE account_id = ? AND expires_at < ?", &account_id, now)
            .execute(&st.db)
            .await?;
        sqlx::query!(
            "INSERT INTO recovery_challenges (challenge, account_id, expires_at) VALUES (?, ?, ?)",
            &challenge,
            &account_id,
            now + RECOVERY_CHALLENGE_TTL_MS
        )
        .execute(&st.db)
        .await?;
    }
    Ok(reply(
        StatusCode::OK,
        json!({"challenge": b64::encode(&challenge)}),
    ))
}

#[derive(Deserialize)]
struct RecoverRequest {
    #[serde(default)]
    number: String,
    #[serde(default, with = "b64")]
    challenge: Vec<u8>,
    #[serde(default, with = "b64")]
    signature: Vec<u8>,
    #[serde(default)]
    kdf: Option<Box<RawValue>>,
    #[serde(default, with = "b64")]
    auth_key: Vec<u8>,
    #[serde(default, with = "b64")]
    wrapped_account_key: Vec<u8>,
    #[serde(default)]
    device: Option<DeviceInfo>,
}

/// The transactional part of recovery (retried on deadlock; the challenge stays consumed).
async fn recover_tx(st: &AppState, account: &str, req: &RecoverRequest, kdf: &str, device: &DeviceInfo) -> Result<(i64, String, Vec<i64>), ApiError> {
    let mut tx = st.db.begin().await?;
    let exists = sqlx::query!("SELECT id FROM accounts WHERE id = ? FOR UPDATE", account)
        .fetch_optional(&mut *tx)
        .await?;
    if exists.is_none() {
        return Err(unauthorized("recovery failed"));
    }
    sqlx::query!("UPDATE accounts SET auth_key_hash = ?, kdf = ?, wrapped_account_key = ?, totp_secret = NULL, totp_pending = NULL WHERE id = ?", hash_auth_key(&req.auth_key), kdf, &req.wrapped_account_key, account)
        .execute(&mut *tx)
        .await?;
    let old_devices: Vec<i64> =
        sqlx::query!("SELECT device_id AS `device_id: i64` FROM devices WHERE account_id = ? FOR UPDATE", account)
            .fetch_all(&mut *tx)
            .await?
            .iter()
            .map(|r| r.device_id)
            .collect();
    // The old devices (one may be lost or stolen: the reason to recover) wipe themselves.
    super::devices::record_revocations(&mut tx, account, None).await?;
    // Cascades to keys and queued envelopes.
    sqlx::query!("DELETE FROM devices WHERE account_id = ?", account)
        .execute(&mut *tx)
        .await?;
    // Logins waiting for approval were made with the old password.
    sqlx::query!("DELETE FROM login_requests WHERE account_id = ?", account)
        .execute(&mut *tx)
        .await?;
    let (device_id, token) = create_device(&st, &mut tx, account, device).await?;
    // Close the old sockets before the new device's token becomes valid, so the new device
    // (which may reuse an old device id) is never affected.
    for d in &old_devices {
        st.hub.close_device(account, *d, "account recovered");
    }
    tx.commit().await?;
    Ok((device_id, token, old_devices))
}

pub async fn recover(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult {
    st.rate_limit(
        &format!("recover:ip:{}", st.client_ip(&headers, peer)),
        st.limits.recover_ip,
    )?;
    let req: RecoverRequest = parse_json(body, MAX_JSON_BODY).await?;
    if !ids::valid_number(&req.number) {
        return Err(bad_request("number must be 16 digits"));
    }
    require_len("challenge", &req.challenge, 32)?;
    require_len("signature", &req.signature, ED25519_SIGNATURE_LEN)?;
    let kdf = parse_kdf(req.kdf.as_deref())?;
    require_len("auth_key", &req.auth_key, AUTH_KEY_LEN)?;
    require_range(
        "wrapped_account_key",
        &req.wrapped_account_key,
        1,
        MAX_WRAPPED_KEY_LEN,
    )?;
    let device = DeviceInfo::validate(req.device.as_ref())?;
    let failed = || unauthorized("recovery failed");
    let Some(acct) = load_account_by_number(&st, &req.number).await? else {
        return Err(failed());
    };

    // Consume the challenge first: it is single-use even if the signature is wrong.
    let res = sqlx::query!("DELETE FROM recovery_challenges WHERE challenge = ? AND account_id = ? AND expires_at >= ?", &req.challenge, &acct.id, crate::now_millis())
        .execute(&st.db)
        .await?;
    if res.rows_affected() != 1 {
        return Err(failed());
    }
    let mut msg = RECOVERY_CONTEXT.as_bytes().to_vec();
    msg.extend_from_slice(&req.challenge);
    if !ed25519::verify(&acct.recovery_public_key, &msg, &req.signature) {
        return Err(failed());
    }

    let (device_id, token, old_devices) = crate::db::retry_tx(|| recover_tx(&st, &acct.id, &req, &kdf, device)).await?;
    info!(account = %acct.id, removed_devices = old_devices.len(), "account recovered");
    Ok(reply(
        StatusCode::OK,
        json!({
            "account_id": acct.id,
            "number": req.number,
            "device_id": device_id,
            "token": token,
            "wrapped_account_key": b64::encode(&req.wrapped_account_key),
            "identity_key": b64::encode(&acct.identity_key),
        }),
    ))
}

/// GET /v1/account body (keys in Go's sorted map order).
#[derive(Serialize)]
struct AccountView {
    account_id: String,
    created_at: i64,
    discoverable_by_phone: bool,
    kdf: Box<RawValue>,
    login_approval: bool,
    number: String,
    phone: Option<String>,
    phone_verified: bool,
    privacy: serde_json::Value,
    totp_enabled: bool,
    username: Option<String>,
    #[serde(with = "b64")]
    wrapped_account_key: Vec<u8>,
}

pub async fn get_account(State(st): State<AppState>, p: Principal) -> ApiResult {
    let row = sqlx::query!(
        "SELECT number AS `number: String`, created_at, phone AS `phone: String`,
         discoverable_by_phone AS `discoverable_by_phone: bool`, privacy_last_seen AS `privacy_last_seen: String`,
         username AS `username: String`,
         kdf AS `kdf: String`, wrapped_account_key, login_approval AS `login_approval: bool`
         FROM accounts WHERE id = ?",
        &p.account
    )
    .fetch_optional(&st.db)
    .await?;
    let Some(row) = row else {
        return Err(unauthorized("account not found"));
    };
    let totp_enabled = totp_enabled(&st, &p.account).await?;
    let phone = row.phone;
    Ok(reply(
        StatusCode::OK,
        AccountView {
            account_id: p.account.clone(),
            created_at: row.created_at,
            discoverable_by_phone: row.discoverable_by_phone,
            // Lets a logged-in device notice a password change made on another device. The
            // wrapped key is useless without the password (and the device already has the key).
            kdf: raw_json(row.kdf)?,
            login_approval: row.login_approval,
            number: row.number,
            phone_verified: phone.is_some(),
            phone,
            privacy: json!({"last_seen": row.privacy_last_seen}),
            totp_enabled,
            username: row.username,
            wrapped_account_key: row.wrapped_account_key,
        },
    ))
}

const SELECT_AUTH_KEY: &str = "SELECT auth_key_hash FROM accounts WHERE id = ?";
const SELECT_AUTH_KEY_LOCKED: &str = "SELECT auth_key_hash FROM accounts WHERE id = ? FOR UPDATE";

/// Checks the current password auth key of the account (403 on mismatch).
async fn verify_auth_key<'e, E>(
    st: &AppState,
    db: E,
    account: &str,
    auth_key: &[u8],
    lock: bool,
) -> Result<(), ApiError>
where
    E: sqlx::Executor<'e, Database = MySql>,
{
    require_len("auth_key", auth_key, AUTH_KEY_LEN)?;
    // A stolen session token must not allow guessing the password online.
    st.rate_limit(
        &format!("password:acct:{account}"),
        st.limits.password_account,
    )?;
    let q = if lock {
        SELECT_AUTH_KEY_LOCKED
    } else {
        SELECT_AUTH_KEY
    };
    let row = sqlx::query(q).bind(account).fetch_optional(db).await?;
    let Some(row) = row else {
        return Err(unauthorized("account not found"));
    };
    if !bool::from(
        row.bytes("auth_key_hash")
            .as_slice()
            .ct_eq(&hash_auth_key(auth_key)),
    ) {
        return Err(forbidden("wrong auth_key"));
    }
    Ok(())
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    #[serde(default, with = "b64")]
    auth_key: Vec<u8>,
    #[serde(default)]
    kdf: Option<Box<RawValue>>,
    #[serde(default, with = "b64")]
    new_auth_key: Vec<u8>,
    #[serde(default, with = "b64")]
    wrapped_account_key: Vec<u8>,
}

pub async fn change_password(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    let req: ChangePasswordRequest = parse_json(body, MAX_JSON_BODY).await?;
    let kdf = parse_kdf(req.kdf.as_deref())?;
    require_len("new_auth_key", &req.new_auth_key, AUTH_KEY_LEN)?;
    require_range(
        "wrapped_account_key",
        &req.wrapped_account_key,
        1,
        MAX_WRAPPED_KEY_LEN,
    )?;
    require_len("auth_key", &req.auth_key, AUTH_KEY_LEN)?;
    let mut tx = st.db.begin().await?;
    verify_auth_key(&st, &mut *tx, &p.account, &req.auth_key, true).await?;
    sqlx::query!(
        "UPDATE accounts SET auth_key_hash = ?, kdf = ?, wrapped_account_key = ? WHERE id = ?",
        hash_auth_key(&req.new_auth_key),
        &kdf,
        &req.wrapped_account_key,
        &p.account
    )
    .execute(&mut *tx)
    .await?;
    // A login waiting for approval would get a key wrapped with the new password.
    sqlx::query!("DELETE FROM login_requests WHERE account_id = ?", &p.account)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(no_content())
}

#[derive(Deserialize)]
struct PrivacyRequest {
    #[serde(default)]
    last_seen: String,
}

pub async fn set_privacy(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    let req: PrivacyRequest = parse_json(body, MAX_JSON_BODY).await?;
    if req.last_seen != "everyone" && req.last_seen != "nobody" {
        return Err(bad_request("last_seen must be everyone or nobody"));
    }
    sqlx::query!("UPDATE accounts SET privacy_last_seen = ? WHERE id = ?", &req.last_seen, &p.account)
        .execute(&st.db)
        .await?;
    // Not tied to the request: finishes even if the client goes away.
    let (hub, account, nobody) = (st.hub.clone(), p.account.clone(), req.last_seen == "nobody");
    let _ = tokio::spawn(async move { hub.set_privacy(&account, nobody).await }).await;
    Ok(no_content())
}

#[derive(Deserialize)]
struct AuthKeyRequest {
    #[serde(default, with = "b64")]
    auth_key: Vec<u8>,
}

pub async fn delete_account(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    let req: AuthKeyRequest = parse_json(body, MAX_JSON_BODY).await?;
    verify_auth_key(&st, &st.db, &p.account, &req.auth_key, false).await?;
    // Not tied to the request: the deletion completes even if the client goes away.
    let st2 = st.clone();
    tokio::spawn(async move { delete_account_data(&st2, &p.account, &req.auth_key).await })
        .await
        .map_err(|e| internal_from("delete account task", e))??;
    Ok(no_content())
}

/// Removes the account and everything it owns. The account number stays in account_numbers
/// (tombstone) so it is never reused.
async fn delete_account_data(
    st: &AppState,
    account: &str,
    auth_key: &[u8],
) -> Result<(), ApiError> {
    let mut tx = st.db.begin().await?;
    verify_auth_key(st, &mut *tx, account, auth_key, true).await?;
    let attachments = query_strings(
        &mut *tx,
        sqlx::query("SELECT id FROM attachments WHERE owner_id = ?").bind(account),
    )
    .await?;
    let mut groups = query_strings(
        &mut *tx,
        sqlx::query("SELECT group_id FROM group_members WHERE account_id = ?").bind(account),
    )
    .await?;
    groups.sort(); // consistent lock order
    let mut changes: Vec<GroupChange> = Vec::new();
    for g in &groups {
        if let Err(e) = lock_group(&mut tx, g).await {
            if e.status == StatusCode::NOT_FOUND {
                continue;
            }
            return Err(e);
        }
        changes.push(remove_members_tx(&mut tx, g, &[account.to_string()]).await?);
    }
    // The username stays reserved for a while so nobody can impersonate the deleted account.
    super::username::reserve_released_username(st, &mut tx, account).await?;
    sqlx::query!("UPDATE account_numbers SET deleted_at = ? WHERE account_id = ?", crate::now_millis(), account)
        .execute(&mut *tx)
        .await?;
    // The account's other devices wipe themselves.
    super::devices::record_revocations(&mut tx, account, None).await?;
    // Cascades to devices, keys, envelopes, profile, vault, phone codes, challenges,
    // memberships and attachment rows.
    sqlx::query!("DELETE FROM accounts WHERE id = ?", account)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    st.hub.close_account(
        account,
        &json!({"kind": "account_deleted"}),
        "account deleted",
    );
    for ch in &changes {
        push_group_updated(st, ch);
    }
    for id in &attachments {
        if let Err(e) = st.store.delete(id).await {
            warn!(attachment = %id, error = %e, "delete attachment object failed");
        }
    }
    info!(
        account,
        groups = changes.len(),
        attachments = attachments.len(),
        "account deleted"
    );
    Ok(())
}

#[derive(Deserialize)]
struct PhoneRequest {
    #[serde(default)]
    phone: String,
}

pub async fn set_phone(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    let Some(sms) = st.sms.clone() else {
        return Err(forbidden("phone verification is disabled on this server"));
    };
    let req: PhoneRequest = parse_json(body, MAX_JSON_BODY).await?;
    if !valid_phone(&req.phone) {
        return Err(bad_request("phone must be in E.164 format"));
    }
    st.rate_limit(&format!("phone:acct:{}", p.account), st.limits.phone_code)?;
    // Also per destination: many accounts must not be able to flood one phone with SMS.
    st.rate_limit(&format!("phone:num:{}", req.phone), st.limits.phone_number)?;
    let code = ids::new_numeric_code(6);
    sqlx::query!(
        "INSERT INTO phone_codes (account_id, phone, code_hash, attempts, expires_at)
         VALUES (?, ?, ?, 0, ?)
         ON DUPLICATE KEY UPDATE phone = VALUES(phone), code_hash = VALUES(code_hash), attempts = 0, expires_at = VALUES(expires_at)",
        &p.account,
        &req.phone,
        phone_code_hash(&st, &p.account, &req.phone, &code),
        crate::now_millis() + PHONE_CODE_TTL_MS
    )
    .execute(&st.db)
    .await?;
    if let Err(e) = sms
        .send(
            &req.phone,
            &format!("Your Dialog verification code is {code}"),
        )
        .await
    {
        error!(error = %e, "sms send failed");
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            "internal",
            "could not send verification code",
        ));
    }
    Ok(reply(StatusCode::OK, json!({"sent": true})))
}

fn phone_code_hash(st: &AppState, account: &str, phone: &str, code: &str) -> Vec<u8> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(st.cfg.server_secret.as_bytes()).expect("hmac key");
    mac.update(format!("phone-code\x00{account}\x00{phone}\x00{code}").as_bytes());
    mac.finalize().into_bytes().to_vec()
}

#[derive(Deserialize)]
struct VerifyPhoneRequest {
    #[serde(default)]
    phone: String,
    #[serde(default)]
    code: String,
}

pub async fn verify_phone(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    let req: VerifyPhoneRequest = parse_json(body, MAX_JSON_BODY).await?;
    if !valid_phone(&req.phone) {
        return Err(bad_request("phone must be in E.164 format"));
    }
    if req.code.len() != 6 {
        return Err(bad_request("code must be 6 digits"));
    }
    let invalid = || bad_request("invalid or expired code");
    let mut tx = st.db.begin().await?;
    let row = sqlx::query!("SELECT phone AS `phone: String`, code_hash, attempts AS `attempts: i64`, expires_at AS `expires_at: i64` FROM phone_codes WHERE account_id = ? FOR UPDATE", &p.account)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(row) = row else {
        return Err(invalid());
    };
    if row.expires_at < crate::now_millis()
        || row.attempts >= PHONE_CODE_MAX_ATTEMPTS
        || row.phone != req.phone
    {
        return Err(invalid());
    }
    let expected = phone_code_hash(&st, &p.account, &req.phone, &req.code);
    if !bool::from(row.code_hash.as_slice().ct_eq(&expected)) {
        // The attempt counter is committed before failing.
        sqlx::query!("UPDATE phone_codes SET attempts = attempts + 1 WHERE account_id = ?", &p.account)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Err(invalid());
    }
    let phone_hash = Sha256::digest(req.phone.as_bytes()).to_vec();
    let displaced =
        sqlx::query!("SELECT id AS `id: String` FROM accounts WHERE phone_hash = ? AND id <> ? FOR UPDATE", &phone_hash, &p.account)
            .fetch_optional(&mut *tx)
            .await?
            .map(|r| r.id);
    if let Some(displaced) = displaced {
        sqlx::query!("UPDATE accounts SET phone = NULL, phone_hash = NULL WHERE id = ?", &displaced)
            .execute(&mut *tx)
            .await?;
    }
    // A verified number is findable through other users' phone contacts by default (the user
    // can turn this off with PUT /v1/account/discoverable).
    sqlx::query!(
        "UPDATE accounts SET phone = ?, phone_hash = ?, discoverable_by_phone = 1 WHERE id = ?",
        &req.phone,
        &phone_hash,
        &p.account
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!("DELETE FROM phone_codes WHERE account_id = ?", &p.account)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(no_content())
}

pub async fn delete_phone(State(st): State<AppState>, p: Principal) -> ApiResult {
    sqlx::query!("UPDATE accounts SET phone = NULL, phone_hash = NULL WHERE id = ?", &p.account)
        .execute(&st.db)
        .await?;
    sqlx::query!("DELETE FROM phone_codes WHERE account_id = ?", &p.account)
        .execute(&st.db)
        .await?;
    Ok(no_content())
}

#[derive(Deserialize)]
struct DiscoverableRequest {
    #[serde(default)]
    discoverable: Option<bool>,
}

pub async fn set_discoverable(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    let req: DiscoverableRequest = parse_json(body, MAX_JSON_BODY).await?;
    let Some(discoverable) = req.discoverable else {
        return Err(bad_request("discoverable is required"));
    };
    sqlx::query!("UPDATE accounts SET discoverable_by_phone = ? WHERE id = ?", discoverable, &p.account)
        .execute(&st.db)
        .await?;
    Ok(no_content())
}

/// Ed25519 verification of recovery signatures (ed25519-dalek, cofactorless like Go's
/// crypto/ed25519.Verify; non-canonical S is rejected).
mod ed25519 {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    pub fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(public_key), <[u8; 64]>::try_from(sig))
        else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
            return false;
        };
        vk.verify(msg, &Signature::from_bytes(&sig)).is_ok()
    }

    #[cfg(test)]
    mod tests {
        use ed25519_dalek::{Signer, SigningKey};

        #[test]
        fn verifies() {
            let sk = SigningKey::from_bytes(&[7u8; 32]);
            let sig = sk.sign(b"challenge");
            let pk = sk.verifying_key().to_bytes();
            assert!(super::verify(&pk, b"challenge", &sig.to_bytes()));
            assert!(!super::verify(&pk, b"other", &sig.to_bytes()));
            assert!(!super::verify(&pk[..31], b"challenge", &sig.to_bytes()));
        }
    }
}
