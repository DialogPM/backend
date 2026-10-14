//! Voice calls: ICE servers with short-lived TURN credentials.

use axum::extract::State;
use axum::http::StatusCode;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::json;
use sha1::Sha1;
use sha2::Sha256;

use super::reply;
use crate::auth::Principal;
use crate::error::ApiResult;
use crate::state::AppState;

/// One RTCIceServer entry as WebRTC expects it.
#[derive(Serialize)]
struct IceServer {
    urls: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    username: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    credential: String,
}

/// Granularity of the credential expiry. Within one window the same account gets the same
/// username, so coturn's per-user quota (`--user-quota`) still applies to an account that keeps
/// asking for new credentials.
const EXPIRY_STEP_SECS: i64 = 600;

/// coturn's REST API scheme ("use-auth-secret"): username is "<expiry unix time>:<anything>",
/// password is base64(HMAC-SHA1(secret, username)).
///
/// The part after the colon is an opaque tag, HMAC-SHA256(secret, account || expiry) truncated:
/// coturn logs the username next to the client IP, and must not learn which account it is. The
/// tag changes with every expiry window, so log lines from different windows are not linkable.
/// The expiry is rounded up to `EXPIRY_STEP_SECS`: credentials stay valid between `ttl_secs` and
/// `ttl_secs + EXPIRY_STEP_SECS`.
pub fn turn_credentials(
    secret: &str,
    account: &str,
    now_secs: i64,
    ttl_secs: i64,
) -> (String, String) {
    let expiry = (now_secs + ttl_secs).div_euclid(EXPIRY_STEP_SECS) * EXPIRY_STEP_SECS + EXPIRY_STEP_SECS;
    let mut tag = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    tag.update(b"chatapp-turn-user\0");
    tag.update(account.as_bytes());
    tag.update(b"\0");
    tag.update(expiry.to_string().as_bytes());
    let tag = hex::encode(&tag.finalize().into_bytes()[..12]);
    let username = format!("{expiry}:{tag}");
    let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(username.as_bytes());
    let pass = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    (username, pass)
}

/// GET /v1/calls/ice
pub async fn ice_servers(State(st): State<AppState>, p: Principal) -> ApiResult {
    let mut servers = Vec::new();
    if !st.cfg.stun_urls.is_empty() {
        servers.push(IceServer {
            urls: st.cfg.stun_urls.clone(),
            username: String::new(),
            credential: String::new(),
        });
    }
    let ttl = st.cfg.turn_credential_ttl.as_secs() as i64;
    if !st.cfg.turn_urls.is_empty() {
        crate::metrics::TURN_CREDENTIALS_ISSUED.add(1);
        let (username, credential) = turn_credentials(
            &st.cfg.turn_secret,
            &p.account,
            crate::now_millis() / 1000,
            ttl,
        );
        servers.push(IceServer {
            urls: st.cfg.turn_urls.clone(),
            username,
            credential,
        });
    }
    Ok(reply(
        StatusCode::OK,
        json!({"ice_servers": servers, "ttl": ttl}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turn_username_is_opaque_and_coturn_compatible() {
        let secret = "0123456789abcdef0123";
        let (user, pass) = turn_credentials(secret, "acc-123456", 1_000_000, 3600);
        let (expiry, tag) = user.split_once(':').unwrap();
        let expiry: i64 = expiry.parse().unwrap();
        assert!(expiry >= 1_000_000 + 3600 && expiry <= 1_000_000 + 3600 + EXPIRY_STEP_SECS);
        assert_eq!(expiry % EXPIRY_STEP_SECS, 0);
        assert!(!user.contains("acc-123456"));
        assert_eq!(tag.len(), 24);
        // coturn: password = base64(HMAC-SHA1(secret, username)).
        let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(user.as_bytes());
        assert_eq!(pass, base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes()));
        // Same account in the same window: same username (per-user quotas apply).
        assert_eq!(turn_credentials(secret, "acc-123456", 1_000_001, 3600).0, user);
        // Other account or other window: unrelated tag.
        let other = turn_credentials(secret, "acc-654321", 1_000_000, 3600).0;
        assert_ne!(other, user);
        let later = turn_credentials(secret, "acc-123456", 1_000_000 + 2 * EXPIRY_STEP_SECS, 3600).0;
        assert_ne!(later.split_once(':').unwrap().1, tag);
    }
}
