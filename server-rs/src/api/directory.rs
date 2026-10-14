//! Directory lookups and profiles (API sections 6 and 8).

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::keys::null_default;
use super::{no_content, reply};
use crate::auth::Principal;
use crate::db::{placeholders, RowExt};
use crate::error::{bad_request, not_found, too_large, ApiResult};
use crate::ids;
use crate::state::AppState;
use crate::validate::{
    b64, optional_attachment_id, parse_json, path_uuid, MAX_JSON_BODY, MAX_PHONE_HASHES,
    MAX_PROFILE_DATA,
};

const PHONE_HASH_LEN: usize = 32;

/// Go's base64.RawURLEncoding: no padding, non-zero trailing bits accepted.
const RAW_URL_LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone),
);

/// Replies with the directory entry of the account whose `column` equals `value`.
pub(crate) async fn write_directory_entry(st: &AppState, column: &str, value: &str) -> ApiResult {
    let row = sqlx::query(&format!(
        "SELECT id, number, identity_key, username FROM accounts WHERE {column} = ?"
    ))
    .bind(value)
    .fetch_optional(&st.db)
    .await?;
    let Some(r) = row else {
        return Err(not_found("unknown account"));
    };
    Ok(reply(
        StatusCode::OK,
        json!({
            "account_id": r.string("id"),
            "number": r.string("number"),
            "identity_key": r.opt_bytes("identity_key").map(|b| b64::encode(&b)),
            "username": r.opt_string("username"),
        }),
    ))
}

pub async fn by_number(
    State(st): State<AppState>,
    p: Principal,
    Path(number): Path<String>,
) -> ApiResult {
    st.rate_limit(
        &format!("dir-number:acct:{}", p.account),
        st.limits.directory_number,
    )?;
    if !ids::valid_number(&number) {
        return Err(bad_request("number must be 16 digits"));
    }
    write_directory_entry(&st, "number", &number).await
}

pub async fn by_account(
    State(st): State<AppState>,
    _p: Principal,
    Path(account_id): Path<String>,
) -> ApiResult {
    let id = path_uuid("account_id", &account_id)?;
    write_directory_entry(&st, "id", &id).await
}

/// Finds one account by the SHA-256 of its phone number (search box), only if the owner keeps
/// the number findable.
pub async fn phone(
    State(st): State<AppState>,
    p: Principal,
    Path(hash): Path<String>,
) -> ApiResult {
    st.rate_limit(
        &format!("dir-number:acct:{}", p.account),
        st.limits.directory_number,
    )?;
    let cleaned: String = hash.chars().filter(|c| *c != '\r' && *c != '\n').collect();
    let hash = match RAW_URL_LENIENT.decode(cleaned) {
        Ok(h) if h.len() == PHONE_HASH_LEN => h,
        _ => return Err(bad_request("hash must be a base64url SHA-256 value")),
    };
    let row = sqlx::query!("SELECT id AS `id: String`, number AS `number: String`, identity_key, username AS `username: String` FROM accounts WHERE phone_hash = ? AND discoverable_by_phone = 1", &hash)
        .fetch_optional(&st.db)
        .await?;
    let Some(r) = row else {
        return Err(not_found("unknown account"));
    };
    Ok(reply(
        StatusCode::OK,
        json!({
            "account_id": r.id,
            "number": r.number,
            "identity_key": Some(r.identity_key).map(|b| b64::encode(&b)),
            "username": r.username,
        }),
    ))
}

#[derive(Deserialize)]
struct PhonesRequest {
    #[serde(default, deserialize_with = "null_default")]
    hashes: Vec<Option<String>>,
}

#[derive(Serialize)]
struct PhoneMatch {
    #[serde(with = "b64")]
    hash: Vec<u8>,
    account_id: String,
    number: String,
}

pub async fn phones(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    st.rate_limit(
        &format!("dir-phones:acct:{}", p.account),
        st.limits.directory_phones,
    )?;
    let req: PhonesRequest = parse_json(body, MAX_JSON_BODY).await?;
    // Decoded like Go's [][]byte: null entries are empty, bad base64 fails the whole body.
    let mut hashes = Vec::with_capacity(req.hashes.len());
    for h in &req.hashes {
        match h {
            None => hashes.push(Vec::new()),
            Some(s) => hashes.push(
                b64::decode(s)
                    .ok_or_else(|| bad_request("invalid JSON body: illegal base64 data"))?,
            ),
        }
    }
    if hashes.len() > MAX_PHONE_HASHES {
        return Err(bad_request("at most 1000 hashes per request"));
    }
    let mut unique: Vec<Vec<u8>> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for h in hashes {
        if h.len() != PHONE_HASH_LEN {
            return Err(bad_request("hashes must be 32-byte SHA-256 values"));
        }
        if seen.insert(h.clone()) {
            unique.push(h);
        }
    }
    let mut matches = Vec::new();
    if !unique.is_empty() {
        // phone_hash is only set for verified phones.
        let sql = format!(
            "SELECT phone_hash, id, number FROM accounts WHERE discoverable_by_phone = 1 AND phone_hash IN ({})",
            placeholders(unique.len())
        );
        let mut q = sqlx::query(&sql);
        for h in &unique {
            q = q.bind(h);
        }
        for r in q.fetch_all(&st.db).await? {
            matches.push(PhoneMatch {
                hash: r.bytes("phone_hash"),
                account_id: r.string("id"),
                number: r.string("number"),
            });
        }
    }
    Ok(reply(StatusCode::OK, json!({"matches": matches})))
}

#[derive(Deserialize)]
struct PutProfileRequest {
    #[serde(default, with = "b64")]
    data: Vec<u8>,
    #[serde(default)]
    avatar_id: Option<String>,
}

pub async fn put_profile(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    let req: PutProfileRequest = parse_json(body, MAX_JSON_BODY).await?;
    if req.data.is_empty() {
        return Err(bad_request("data is required"));
    }
    if req.data.len() > MAX_PROFILE_DATA {
        return Err(too_large("data exceeds 64 KiB"));
    }
    optional_attachment_id("avatar_id", req.avatar_id.as_deref())?;
    sqlx::query!(
        "INSERT INTO profiles (account_id, data, avatar_id, updated_at) VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE data = VALUES(data), avatar_id = VALUES(avatar_id), updated_at = VALUES(updated_at)",
        &p.account,
        &req.data,
        &req.avatar_id,
        crate::now_millis()
    )
    .execute(&st.db)
    .await?;
    Ok(no_content())
}

pub async fn get_profile(
    State(st): State<AppState>,
    _p: Principal,
    Path(account_id): Path<String>,
) -> ApiResult {
    let id = path_uuid("account_id", &account_id)?;
    let row = sqlx::query!("SELECT data, avatar_id AS `avatar_id: String`, updated_at FROM profiles WHERE account_id = ?", &id)
        .fetch_optional(&st.db)
        .await?;
    let Some(r) = row else {
        return Err(not_found("no profile"));
    };
    Ok(reply(
        StatusCode::OK,
        json!({
            "data": Some(r.data).map(|b| b64::encode(&b)),
            "avatar_id": r.avatar_id,
            "updated_at": r.updated_at,
        }),
    ))
}
