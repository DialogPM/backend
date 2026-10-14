//! Pre-key upload and bundle fetching (API section 5).

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use sqlx::{MySql, Transaction};

use super::messages::device_registrations;
use super::{no_content, reply};
use crate::auth::Principal;
use crate::error::{bad_request, not_found, ApiError, ApiResult};
use crate::state::AppState;
use crate::validate::{
    b64, parse_json, path_uuid, require_len, require_range, EC_PUBLIC_KEY_LEN, MAX_DEVICE_ID,
    MAX_JSON_BODY, MAX_KYBER_PUBLIC_KEY_LEN, MAX_ONE_TIME_KEYS_PER_REQ, MAX_ONE_TIME_KEYS_STORED,
    SIGNATURE_LEN,
};

// Key kinds in device_signed_keys and device_one_time_keys.
const KEY_KIND_EC: i64 = 0;
const KEY_KIND_KYBER: i64 = 1;

/// When a device's one-time key count drops below this after a fetch, the device is sent a
/// keys_low event.
const KEYS_LOW_THRESHOLD: i64 = 20;

/// JSON `null` leaves the zero value (like Go's encoding/json).
pub(crate) fn null_default<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(
    d: D,
) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Deserialize)]
struct SignedKeyIn {
    #[serde(default, deserialize_with = "null_default")]
    id: u32,
    #[serde(default, with = "b64")]
    public_key: Vec<u8>,
    #[serde(default, with = "b64")]
    signature: Vec<u8>,
}

#[derive(Deserialize)]
struct PreKeyIn {
    #[serde(default, deserialize_with = "null_default")]
    id: u32,
    #[serde(default, with = "b64")]
    public_key: Vec<u8>,
}

#[derive(Deserialize)]
struct PutKeysRequest {
    #[serde(default)]
    signed_prekey: Option<SignedKeyIn>,
    #[serde(default)]
    kyber_last_resort: Option<SignedKeyIn>,
    #[serde(default, deserialize_with = "null_default")]
    prekeys: Vec<PreKeyIn>,
    #[serde(default, deserialize_with = "null_default")]
    kyber_prekeys: Vec<SignedKeyIn>,
}

fn validate_ec_key(field: &str, k: &[u8]) -> Result<(), ApiError> {
    require_len(field, k, EC_PUBLIC_KEY_LEN)
}

fn validate_kyber_key(field: &str, k: &[u8]) -> Result<(), ApiError> {
    require_range(field, k, 1, MAX_KYBER_PUBLIC_KEY_LEN)
}

pub async fn put_keys(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    let req: PutKeysRequest = parse_json(body, MAX_JSON_BODY).await?;
    if let Some(k) = &req.signed_prekey {
        validate_ec_key("signed_prekey.public_key", &k.public_key)?;
        require_len("signed_prekey.signature", &k.signature, SIGNATURE_LEN)?;
    }
    if let Some(k) = &req.kyber_last_resort {
        validate_kyber_key("kyber_last_resort.public_key", &k.public_key)?;
        require_len("kyber_last_resort.signature", &k.signature, SIGNATURE_LEN)?;
    }
    if req.prekeys.len() > MAX_ONE_TIME_KEYS_PER_REQ
        || req.kyber_prekeys.len() > MAX_ONE_TIME_KEYS_PER_REQ
    {
        return Err(bad_request("at most 200 one-time keys per list"));
    }
    for k in &req.prekeys {
        validate_ec_key("prekeys[].public_key", &k.public_key)?;
    }
    for k in &req.kyber_prekeys {
        validate_kyber_key("kyber_prekeys[].public_key", &k.public_key)?;
        require_len("kyber_prekeys[].signature", &k.signature, SIGNATURE_LEN)?;
    }

    let mut tx = st.db.begin().await?;
    for (kind, k) in [
        (KEY_KIND_EC, &req.signed_prekey),
        (KEY_KIND_KYBER, &req.kyber_last_resort),
    ] {
        let Some(k) = k else { continue };
        sqlx::query!(
            "INSERT INTO device_signed_keys (account_id, device_id, kind, key_id, public_key, signature)
             VALUES (?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE key_id = VALUES(key_id), public_key = VALUES(public_key), signature = VALUES(signature)",
            &p.account,
            p.device,
            kind,
            k.id,
            &k.public_key,
            &k.signature
        )
        .execute(&mut *tx)
        .await?;
    }
    let one_time = req
        .prekeys
        .iter()
        .map(|k| (KEY_KIND_EC, k.id, &k.public_key, None))
        .chain(
            req.kyber_prekeys
                .iter()
                .map(|k| (KEY_KIND_KYBER, k.id, &k.public_key, Some(&k.signature))),
        );
    for (kind, id, public_key, signature) in one_time {
        sqlx::query!(
            "INSERT INTO device_one_time_keys (account_id, device_id, kind, key_id, public_key, signature)
             VALUES (?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE public_key = VALUES(public_key), signature = VALUES(signature)",
            &p.account,
            p.device,
            kind,
            id,
            public_key,
            signature
        )
        .execute(&mut *tx)
        .await?;
    }
    if !req.prekeys.is_empty() || !req.kyber_prekeys.is_empty() {
        let (ec, kyber) = count_one_time_keys(&mut *tx, &p.account, p.device).await?;
        if ec > MAX_ONE_TIME_KEYS_STORED || kyber > MAX_ONE_TIME_KEYS_STORED {
            return Err(bad_request("too many one-time keys stored for this device"));
        }
    }
    tx.commit().await?;
    Ok(no_content())
}

/// (EC, Kyber) one-time key counts of a device.
async fn count_one_time_keys<'e>(
    db: impl sqlx::Executor<'e, Database = MySql>,
    account: &str,
    device: i64,
) -> Result<(i64, i64), sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT kind AS `kind: i64`, COUNT(*) AS `n!: i64` FROM device_one_time_keys WHERE account_id = ? AND device_id = ? GROUP BY kind",
        account,
        device
    )
    .fetch_all(db)
    .await?;
    let (mut ec, mut kyber) = (0, 0);
    for r in &rows {
        match r.kind {
            KEY_KIND_EC => ec = r.n,
            KEY_KIND_KYBER => kyber = r.n,
            _ => {}
        }
    }
    Ok((ec, kyber))
}

pub async fn key_count(State(st): State<AppState>, p: Principal) -> ApiResult {
    let (ec, kyber) = count_one_time_keys(&st.db, &p.account, p.device).await?;
    Ok(reply(
        StatusCode::OK,
        json!({"prekeys": ec, "kyber_prekeys": kyber}),
    ))
}

#[derive(Serialize, Clone)]
struct SignedKeyOut {
    id: u32,
    #[serde(with = "b64")]
    public_key: Vec<u8>,
    #[serde(with = "b64::opt")]
    signature: Option<Vec<u8>>,
}

#[derive(Serialize)]
struct PreKeyOut {
    id: u32,
    #[serde(with = "b64")]
    public_key: Vec<u8>,
}

#[derive(Serialize)]
struct DeviceBundle {
    device_id: i64,
    registration_id: i64,
    signed_prekey: SignedKeyOut,
    kyber_prekey: SignedKeyOut,
    #[serde(skip_serializing_if = "Option::is_none")]
    prekey: Option<PreKeyOut>,
}

pub async fn get_keys(
    State(st): State<AppState>,
    p: Principal,
    Path((account_id, device)): Path<(String, String)>,
) -> ApiResult {
    fetch_bundles(&st, Some(&p), &account_id, &device).await
}

/// Serves the pre-key bundles of `account_id`'s devices (`device` is `*` or an id). `p` is
/// None for sealed sender fetches; otherwise the caller's own device is skipped for `*`.
pub async fn fetch_bundles(
    st: &AppState,
    p: Option<&Principal>,
    account_id: &str,
    device: &str,
) -> ApiResult {
    let target = path_uuid("account_id", account_id)?;
    let mut want_device = 0; // 0 = all devices
    if device != "*" {
        want_device = match device.parse::<i64>() {
            Ok(d) if (1..=MAX_DEVICE_ID).contains(&d) => d,
            _ => return Err(bad_request("device must be * or a device id in 1..127")),
        };
    }

    let mut tx = st.db.begin().await?;
    let identity_key = match sqlx::query!("SELECT identity_key FROM accounts WHERE id = ?", &target)
        .fetch_optional(&mut *tx)
        .await?
    {
        Some(r) => r.identity_key,
        None => return Err(not_found("unknown account")),
    };
    let regs = device_registrations(&mut tx, &target).await?;
    let devices: Vec<i64> = if want_device != 0 {
        if !regs.contains_key(&want_device) {
            return Err(not_found("unknown device"));
        }
        vec![want_device]
    } else {
        regs.keys()
            .copied()
            .filter(|d| {
                (1..=MAX_DEVICE_ID).contains(d)
                    && !p.is_some_and(|p| p.account == target && p.device == *d)
            })
            .collect()
    };
    let mut bundles = Vec::new();
    let mut low_devices = Vec::new();
    for d in devices {
        let Some(mut b) = build_bundle(&mut tx, &target, d).await? else {
            continue; // no signed pre-key (or no Kyber key) uploaded yet
        };
        b.registration_id = regs[&d];
        bundles.push(b);
        let (ec, kyber) = count_one_time_keys(&mut *tx, &target, d).await?;
        if ec < KEYS_LOW_THRESHOLD || kyber < KEYS_LOW_THRESHOLD {
            low_devices.push(d);
        }
    }
    tx.commit().await?;
    for d in low_devices {
        st.hub
            .send_device_event(&target, d, &json!({"kind": "keys_low"}));
    }
    Ok(reply(
        StatusCode::OK,
        json!({"identity_key": b64::encode(&identity_key), "devices": bundles}),
    ))
}

/// Assembles the bundle of one device, atomically consuming one EC and one Kyber one-time
/// pre-key (SKIP LOCKED: concurrent fetches never obtain the same key). None when the device
/// has no signed pre-key or no Kyber key at all.
async fn build_bundle(
    tx: &mut Transaction<'_, MySql>,
    account: &str,
    device: i64,
) -> Result<Option<DeviceBundle>, sqlx::Error> {
    let rows = sqlx::query!("SELECT kind AS `kind: i64`, key_id AS `key_id: i64`, public_key, signature FROM device_signed_keys WHERE account_id = ? AND device_id = ?", account, device)
        .fetch_all(&mut **tx)
        .await?;
    let (mut signed, mut last_resort) = (None, None);
    for r in rows {
        let k = SignedKeyOut {
            id: r.key_id as u32,
            public_key: r.public_key,
            signature: Some(r.signature),
        };
        match r.kind {
            KEY_KIND_EC => signed = Some(k),
            KEY_KIND_KYBER => last_resort = Some(k),
            _ => {}
        }
    }
    let Some(signed) = signed else {
        return Ok(None);
    };
    let Some(kyber) = take_one_time_key(tx, account, device, KEY_KIND_KYBER)
        .await?
        .or(last_resort)
    else {
        return Ok(None);
    };
    let prekey = take_one_time_key(tx, account, device, KEY_KIND_EC)
        .await?
        .map(|k| PreKeyOut {
            id: k.id,
            public_key: k.public_key,
        });
    Ok(Some(DeviceBundle {
        device_id: device,
        registration_id: 0,
        signed_prekey: signed,
        kyber_prekey: kyber,
        prekey,
    }))
}

async fn take_one_time_key(
    tx: &mut Transaction<'_, MySql>,
    account: &str,
    device: i64,
    kind: i64,
) -> Result<Option<SignedKeyOut>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT key_id AS `key_id: i64`, public_key, signature FROM device_one_time_keys
         WHERE account_id = ? AND device_id = ? AND kind = ? ORDER BY key_id LIMIT 1 FOR UPDATE SKIP LOCKED",
        account,
        device,
        kind
    )
    .fetch_optional(&mut **tx)
    .await?;
    let Some(r) = row else { return Ok(None) };
    let k = SignedKeyOut {
        id: r.key_id as u32,
        public_key: r.public_key,
        signature: r.signature,
    };
    sqlx::query!("DELETE FROM device_one_time_keys WHERE account_id = ? AND device_id = ? AND kind = ? AND key_id = ?", account, device, kind, k.id)
        .execute(&mut **tx)
        .await?;
    Ok(Some(k))
}
