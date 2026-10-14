//! Device list, unlinking and renaming (API section 5).

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;

use super::{no_content, reply};
use crate::auth::Principal;
use crate::error::{bad_request, not_found, unauthorized, ApiResult};
use crate::state::AppState;
use crate::validate::{b64, parse_json, validate_device_name, MAX_DEVICE_ID, MAX_JSON_BODY};

#[derive(Serialize)]
struct DeviceView {
    device_id: i64,
    name: String,
    platform: String,
    created_at: i64,
    last_seen_at: i64,
    current: bool,
    /// Device name encrypted by the account's devices (opaque here); `name` is then only a
    /// placeholder.
    #[serde(with = "b64::opt", skip_serializing_if = "Option::is_none")]
    encrypted_name: Option<Vec<u8>>,
}

pub async fn list_devices(State(st): State<AppState>, p: Principal) -> ApiResult {
    let rows = sqlx::query!("SELECT device_id AS `device_id: i64`, name AS `name: String`, name_enc, platform AS `platform: String`, created_at, last_seen_at FROM devices WHERE account_id = ? ORDER BY device_id", &p.account)
        .fetch_all(&st.db)
        .await?;
    let out: Vec<DeviceView> = rows
        .into_iter()
        .map(|r| {
            let device_id = r.device_id;
            DeviceView {
                device_id,
                name: r.name,
                platform: r.platform,
                created_at: r.created_at,
                last_seen_at: r.last_seen_at,
                current: device_id == p.device,
                encrypted_name: r.name_enc,
            }
        })
        .collect();
    Ok(reply(StatusCode::OK, json!({"devices": out})))
}

pub async fn delete_device(
    State(st): State<AppState>,
    p: Principal,
    Path(device_id): Path<String>,
) -> ApiResult {
    let device_id = match device_id.parse::<i64>() {
        Ok(d) if (1..=MAX_DEVICE_ID).contains(&d) => d,
        _ => return Err(bad_request("device_id must be in 1..127")),
    };
    let mut tx = st.db.begin().await?;
    // Lock the account row: device set changes are serialized per account.
    let exists = sqlx::query!("SELECT id FROM accounts WHERE id = ? FOR UPDATE", &p.account)
        .fetch_optional(&mut *tx)
        .await?;
    if exists.is_none() {
        return Err(unauthorized("account not found"));
    }
    // The removed device can then find out and wipe itself, even while locked.
    record_revocations(&mut tx, &p.account, Some(device_id)).await?;
    // Cascades to the device's keys and queued envelopes.
    let res = sqlx::query!("DELETE FROM devices WHERE account_id = ? AND device_id = ?", &p.account, device_id)
        .execute(&mut *tx)
        .await?;
    if res.rows_affected() == 0 {
        return Err(not_found("unknown device"));
    }
    tx.commit().await?;
    st.hub
        .close_device(&p.account, device_id, "device unlinked");
    st.hub
        .send_event(&p.account, device_id, &json!({"kind": "devices_changed"}));
    info!(account = %p.account, device = device_id, "device unlinked");
    Ok(no_content())
}

/// Largest encrypted device name (nonce + ciphertext + tag of a padded name).
const MAX_ENCRYPTED_NAME: usize = 512;

#[derive(Deserialize)]
struct RenameRequest {
    #[serde(default)]
    name: String,
    /// The real name, encrypted for the account's own devices; `name` is then a placeholder.
    /// Absent: a plaintext rename (older clients), which drops any encrypted name.
    #[serde(default, with = "b64::opt")]
    encrypted_name: Option<Vec<u8>>,
}

pub async fn rename_device(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    let req: RenameRequest = parse_json(body, MAX_JSON_BODY).await?;
    validate_device_name(&req.name)?;
    if let Some(e) = &req.encrypted_name {
        if e.len() < 28 || e.len() > MAX_ENCRYPTED_NAME {
            return Err(bad_request("encrypted_name must be 28..512 bytes"));
        }
    }
    sqlx::query!(
        "UPDATE devices SET name = ?, name_enc = ? WHERE account_id = ? AND device_id = ?",
        &req.name,
        &req.encrypted_name,
        &p.account,
        p.device
    )
    .execute(&st.db)
        .await?;
    st.hub
        .send_event(&p.account, p.device, &json!({"kind": "devices_changed"}));
    Ok(no_content())
}

// --- remote wipe (docs/API.md, "Device revocation check") ------------------------------------

/// Bytes of a device's revocation secret.
const REVOCATION_SECRET_LEN: usize = 32;
/// Revocation records are kept this long (a lost device may stay off for months).
pub const REVOCATION_KEEP_MS: i64 = 400 * 24 * 3600 * 1000;

/// Keeps the revocation hashes of the devices about to be deleted (all of the account's when
/// `device` is None), so they can learn they were removed. Run in the deleting transaction.
pub async fn record_revocations(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    account: &str,
    device: Option<i64>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT IGNORE INTO device_revocations (account_id, device_id, secret_hash, revoked_at)
         SELECT account_id, device_id, revocation_hash, ? FROM devices
         WHERE account_id = ? AND (? IS NULL OR device_id = ?) AND revocation_hash IS NOT NULL",
        crate::now_millis(),
        account,
        device,
        device
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[derive(Deserialize)]
struct RevocationRequest {
    /// SHA-256 of the device's revocation secret.
    #[serde(with = "b64")]
    hash: Vec<u8>,
}

/// PUT /v1/devices/current/revocation: registers this device's revocation hash.
pub async fn set_revocation(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    let req: RevocationRequest = parse_json(body, MAX_JSON_BODY).await?;
    if req.hash.len() != 32 {
        return Err(bad_request("hash must be 32 bytes"));
    }
    sqlx::query!("UPDATE devices SET revocation_hash = ? WHERE account_id = ? AND device_id = ?", &req.hash, &p.account, p.device)
        .execute(&st.db)
        .await?;
    Ok(no_content())
}

#[derive(Deserialize)]
struct RevocationStatusRequest {
    #[serde(with = "b64")]
    secret: Vec<u8>,
}

/// POST /v1/devices/revocation-status (no authentication): whether the device holding this
/// revocation secret was removed. Only the secret's owner can ask about it.
pub async fn revocation_status(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult {
    st.rate_limit(&format!("revocation:ip:{}", st.client_ip(&headers, peer)), st.limits.revocation_ip)?;
    let req: RevocationStatusRequest = parse_json(body, MAX_JSON_BODY).await?;
    if req.secret.len() != REVOCATION_SECRET_LEN {
        return Err(bad_request("secret must be 32 bytes"));
    }
    let hash = Sha256::digest(&req.secret).to_vec();
    let removed = sqlx::query!("SELECT 1 AS one FROM device_revocations WHERE secret_hash = ?", &hash)
        .fetch_optional(&st.db)
        .await?
        .is_some();
    Ok(reply(StatusCode::OK, json!({"removed": removed})))
}

