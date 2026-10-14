//! Sealed sender: certificates, unidentified access keys, anonymous delivery and pre-key
//! fetches (API section 7a).

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use subtle::ConstantTimeEq;

use super::{keys, messages, no_content, reply};
use crate::auth::Principal;
use crate::error::{bad_request, internal_from, unauthorized, ApiError, ApiResult};
use crate::state::AppState;
use crate::validate::{b64, parse_json, path_uuid, MAX_JSON_BODY};

/// How long a sender certificate stays valid (clients refresh it well before).
const SENDER_CERTIFICATE_TTL_MS: i64 = 24 * 3600 * 1000;

const UNIDENTIFIED_ACCESS_HEADER: &str = "Unidentified-Access-Key";

/// Go's base64.StdEncoding: padding required, non-zero trailing bits accepted.
const STD_LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

/// Issues a certificate binding this device to the account identity key.
pub async fn sender_certificate(State(st): State<AppState>, p: Principal) -> ApiResult {
    let identity_key = match sqlx::query!("SELECT identity_key FROM accounts WHERE id = ?", &p.account)
        .fetch_optional(&st.db)
        .await?
    {
        Some(r) => r.identity_key,
        None => return Err(unauthorized("account not found")),
    };
    let expires = crate::now_millis() + SENDER_CERTIFICATE_TTL_MS;
    let cert = st
        .sealed
        .sender_certificate(&p.account, p.device, &identity_key, expires)
        .map_err(|e| internal_from("issue sender certificate", e))?;
    Ok(reply(
        StatusCode::OK,
        json!({"certificate": b64::encode(&cert), "expires": expires}),
    ))
}

#[derive(Deserialize)]
struct SetAccessRequest {
    #[serde(default, with = "b64::opt")]
    key: Option<Vec<u8>>,
}

/// Stores (or clears, with null) the account's access key.
pub async fn set_unidentified_access(
    State(st): State<AppState>,
    p: Principal,
    body: Body,
) -> ApiResult {
    let req: SetAccessRequest = parse_json(body, MAX_JSON_BODY).await?;
    if req.key.as_ref().is_some_and(|k| k.len() != 16) {
        return Err(bad_request("key must be 16 bytes"));
    }
    let previous = sqlx::query!("SELECT unidentified_access_key FROM accounts WHERE id = ?", &p.account)
        .fetch_optional(&st.db)
        .await?
        .and_then(|r| r.unidentified_access_key);
    sqlx::query!("UPDATE accounts SET unidentified_access_key = ? WHERE id = ?", &req.key, &p.account)
        .execute(&st.db)
        .await?;
    if previous.is_some() && previous != req.key {
        // A rotated key (e.g. after blocking someone): presence subscriptions made with the
        // old key end now; holders of the new key subscribe again when they receive it.
        st.hub.revoke_presence_subscribers(&p.account);
    }
    Ok(no_content())
}

/// Verifies the access key presented for the destination account. Every failure looks the
/// same, so the endpoint does not reveal which accounts exist.
async fn check_unidentified_access(
    st: &AppState,
    headers: &HeaderMap,
    dest: &str,
) -> Result<(), ApiError> {
    let denied = || unauthorized("invalid unidentified access key");
    let raw: String = headers
        .get(UNIDENTIFIED_ACCESS_HEADER)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .unwrap_or_default()
        .chars()
        .filter(|c| *c != '\r' && *c != '\n')
        .collect();
    let presented = match STD_LENIENT.decode(raw) {
        Ok(b) if b.len() == 16 => b,
        _ => return Err(denied()),
    };
    let row = sqlx::query!("SELECT unidentified_access_key FROM accounts WHERE id = ?", dest)
        .fetch_optional(&st.db)
        .await?;
    let Some(row) = row else { return Err(denied()) };
    let stored = row.unidentified_access_key.unwrap_or_default();
    if stored.len() != 16 || !bool::from(stored.as_slice().ct_eq(&presented)) {
        return Err(denied());
    }
    Ok(())
}

/// Delivers sealed envelopes without authenticating the sender.
pub async fn sealed_send(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    body: Body,
) -> ApiResult {
    st.rate_limit(
        &format!("sealed:ip:{}", st.client_ip(&headers, peer)),
        st.limits.sealed_ip,
    )?;
    let dest = path_uuid("account_id", &account_id)?;
    check_unidentified_access(&st, &headers, &dest).await?;
    messages::send_messages(&st, None, &account_id, body).await
}

/// Serves pre-key bundles to a sender holding the access key, so starting a session does not
/// reveal who talks to whom either.
pub async fn sealed_keys(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((account_id, device)): Path<(String, String)>,
) -> ApiResult {
    st.rate_limit(
        &format!("sealed-keys:ip:{}", st.client_ip(&headers, peer)),
        st.limits.sealed_keys_ip,
    )?;
    let dest = path_uuid("account_id", &account_id)?;
    check_unidentified_access(&st, &headers, &dest).await?;
    keys::fetch_bundles(&st, None, &account_id, &device).await
}
