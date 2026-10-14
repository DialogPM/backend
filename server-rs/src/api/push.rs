//! Push token registration of the calling device (API section 14, docs/PUSH-SETUP.md).

use axum::body::Body;
use axum::extract::State;
use serde::Deserialize;
use tracing::debug;

use super::no_content;
use crate::auth::Principal;
use crate::error::{bad_request, unauthorized, ApiError, ApiResult};
use crate::push::{
    token_hash, valid_tag, MAX_TOKEN_LEN, MAX_VOIP_TOKEN_LEN, PROVIDER_APNS_VOIP, PROVIDER_FCM,
};
use crate::state::AppState;
use crate::validate::{parse_json, MAX_JSON_BODY};

/// Accepts printable ASCII without spaces (FCM tokens are URL-safe base64 plus ':' and
/// similar), 1..4096 characters.
fn validate_push_token(token: &str) -> Result<(), ApiError> {
    if token.is_empty() {
        return Err(bad_request("token must not be empty"));
    }
    if token.len() > MAX_TOKEN_LEN {
        return Err(bad_request("token exceeds 4096 characters"));
    }
    if token.bytes().any(|c| c <= b' ' || c > b'~') {
        return Err(bad_request("token must be printable ASCII without spaces"));
    }
    Ok(())
}

/// An APNs device token: hex (64 characters today), at most MAX_VOIP_TOKEN_LEN.
fn validate_voip_token(token: &str) -> Result<(), ApiError> {
    if token.len() < 32 || token.len() > MAX_VOIP_TOKEN_LEN || !token.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(bad_request("token must be a hex APNs device token"));
    }
    Ok(())
}

#[derive(Deserialize)]
struct PushRequest {
    #[serde(default)]
    provider: String,
    #[serde(default)]
    token: String,
    /// Opaque value pushes carry back so an app with several accounts knows which one to wake.
    #[serde(default)]
    tag: Option<String>,
}

/// Registers the calling device's push token: provider "fcm" (messages and calls) or
/// "apns_voip" (iOS PushKit token, incoming calls only). An empty token with "apns_voip"
/// removes the VoIP token; empty provider and token disable push for the device. Within one
/// account a token belongs to one device (it is moved); devices of other accounts on the same
/// phone keep sharing it.
pub async fn set_push(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    let req: PushRequest = parse_json(body, MAX_JSON_BODY).await?;
    let tag = match req.tag.as_deref() {
        None | Some("") => None,
        Some(t) if valid_tag(t) => Some(t),
        Some(_) => return Err(bad_request("tag must be 1..64 letters, digits, '-' or '_'")),
    };
    match req.provider.as_str() {
        "" => {
            if !req.token.is_empty() {
                return Err(bad_request("token must be empty when provider is empty"));
            }
            clear_push(&st, &p).await?;
            return Ok(no_content());
        }
        PROVIDER_FCM => validate_push_token(&req.token)?,
        PROVIDER_APNS_VOIP if req.token.is_empty() => {
            sqlx::query!(
                "UPDATE devices SET voip_token = NULL, voip_token_hash = NULL
                 WHERE account_id = ? AND device_id = ?",
                &p.account,
                p.device
            )
            .execute(&st.db)
            .await?;
            return Ok(no_content());
        }
        PROVIDER_APNS_VOIP => validate_voip_token(&req.token)?,
        _ => return Err(bad_request(r#"provider must be "fcm", "apns_voip" or empty"#)),
    }
    let hash = token_hash(&req.token);
    register(&st, &p, &req.provider, &req.token, &hash, tag).await??;
    // Never log the token itself.
    debug!(account = %p.account, device = p.device, provider = %req.provider, "push token registered");
    Ok(no_content())
}

async fn register(
    st: &AppState,
    p: &Principal,
    provider: &str,
    token: &str,
    hash: &[u8],
    tag: Option<&str>,
) -> Result<Result<(), ApiError>, sqlx::Error> {
    let voip = provider == PROVIDER_APNS_VOIP;
    let mut tx = st.db.begin().await?;
    // Detach the token from the account's other devices: a token identifies one app
    // installation, which is one device of an account (other accounts on the phone keep it).
    let detach = if voip {
        "UPDATE devices SET voip_token = NULL, voip_token_hash = NULL
         WHERE account_id = ? AND voip_token_hash = ? AND device_id <> ?"
    } else {
        "UPDATE devices SET push_provider = '', push_token = NULL, push_token_hash = NULL
         WHERE account_id = ? AND push_token_hash = ? AND device_id <> ?"
    };
    sqlx::query(detach)
        .bind(&p.account)
        .bind(hash)
        .bind(p.device)
        .execute(&mut *tx)
        .await?;
    let set = if voip {
        "UPDATE devices SET voip_token = ?, voip_token_hash = ?, push_tag = COALESCE(?, push_tag)
         WHERE account_id = ? AND device_id = ?"
    } else {
        "UPDATE devices SET push_provider = 'fcm', push_token = ?, push_token_hash = ?,
                push_tag = COALESCE(?, push_tag)
         WHERE account_id = ? AND device_id = ?"
    };
    let res = sqlx::query(set)
        .bind(token)
        .bind(hash)
        .bind(tag)
        .bind(&p.account)
        .bind(p.device)
        .execute(&mut *tx)
        .await?;
    if res.rows_affected() == 0 {
        // Either the device vanished or the values were unchanged; tell them apart.
        let row = sqlx::query!("SELECT 1 AS one FROM devices WHERE account_id = ? AND device_id = ?", &p.account, p.device)
            .fetch_optional(&mut *tx)
            .await?;
        if row.is_none() {
            return Ok(Err(unauthorized("device not found")));
        }
    }
    tx.commit().await?;
    Ok(Ok(()))
}

/// Disables push for the calling device.
pub async fn delete_push(State(st): State<AppState>, p: Principal) -> ApiResult {
    clear_push(&st, &p).await?;
    Ok(no_content())
}

async fn clear_push(st: &AppState, p: &Principal) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE devices SET push_provider = '', push_token = NULL, push_token_hash = NULL,
                push_tag = NULL, voip_token = NULL, voip_token_hash = NULL
         WHERE account_id = ? AND device_id = ?",
        &p.account,
        p.device
    )
    .execute(&st.db)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_validation() {
        assert!(validate_push_token("fcm:APA91b-x_y").is_ok());
        assert!(validate_push_token("").is_err());
        assert!(validate_push_token("a b").is_err());
        assert!(validate_push_token(&"a".repeat(MAX_TOKEN_LEN + 1)).is_err());
        assert!(validate_voip_token(&"ab12".repeat(16)).is_ok());
        assert!(validate_voip_token("abc").is_err());
        assert!(validate_voip_token(&"zz".repeat(32)).is_err());
        assert!(validate_voip_token(&"a".repeat(MAX_VOIP_TOKEN_LEN + 2)).is_err());
    }
}
