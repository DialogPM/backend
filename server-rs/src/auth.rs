//! Bearer-token authentication of devices.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use subtle::ConstantTimeEq;
use tracing::warn;

use crate::error::{unauthorized, ApiError};
use crate::ids;
use crate::state::AppState;

/// The authenticated (account, device) pair. Use it as a handler argument.
#[derive(Clone, Debug)]
pub struct Principal {
    pub account: String,
    pub device: i64,
}

const LAST_SEEN_UPDATE_INTERVAL: i64 = 60_000; // ms

/// Token from the Authorization header, or from `?token=` when `allow_query` (WebSocket).
fn bearer_token(parts: &Parts, allow_query: bool) -> String {
    if let Some(h) = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .filter(|v| !v.is_empty())
    {
        let h = h.to_str().unwrap_or("");
        if let Some((scheme, tok)) = h.split_once(' ') {
            if scheme.eq_ignore_ascii_case("bearer") {
                return tok.trim().to_string();
            }
        }
        return String::new();
    }
    if allow_query {
        if let Some(q) = parts.uri.query() {
            for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
                if k == "token" {
                    return v.into_owned();
                }
            }
        }
    }
    String::new()
}

impl FromRequestParts<AppState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, Self::Rejection> {
        let is_ws = parts.uri.path() == "/v1/ws";
        let token = bearer_token(parts, is_ws);
        if !ids::valid_token_format(&token) {
            return Err(unauthorized("missing or invalid token"));
        }
        let hash = ids::hash_token(&token);
        // Banned accounts (admin CLI `reports ban-account`) are rejected like unknown tokens.
        let row = sqlx::query!(
            "SELECT d.account_id AS `account_id: String`, d.device_id AS `device_id: i64`, d.token_hash, d.last_seen_at FROM devices d
             JOIN accounts a ON a.id = d.account_id
             WHERE d.token_hash = ? AND a.banned_at IS NULL",
            &hash
        )
            .fetch_optional(&st.db)
            .await?;
        let Some(row) = row else {
            return Err(unauthorized("missing or invalid token"));
        };
        let stored = row.token_hash;
        if !bool::from(stored.as_slice().ct_eq(&hash)) {
            return Err(unauthorized("missing or invalid token"));
        }
        let p = Principal {
            account: row.account_id,
            device: row.device_id,
        };
        st.rate_limit(
            &format!("dev:{}:{}", p.account, p.device),
            st.limits.authenticated_user,
        )?;
        let last_seen = row.last_seen_at;
        let now = crate::now_millis();
        if now - last_seen > LAST_SEEN_UPDATE_INTERVAL {
            if let Err(e) = sqlx::query!(
                "UPDATE devices SET last_seen_at = ? WHERE account_id = ? AND device_id = ?",
                now,
                &p.account,
                p.device
            )
            .execute(&st.db)
            .await
            {
                warn!(error = %e, "update device last_seen failed");
            }
        }
        Ok(p)
    }
}
