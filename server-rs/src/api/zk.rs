//! zkgroup credentials (docs/ZKGROUP-DESIGN.md, step 1).

use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use serde::Serialize;
use serde_json::json;

use super::{query_int, reply};
use crate::auth::Principal;
use crate::error::{bad_request, ApiResult};
use crate::state::AppState;
use crate::validate::b64;
use crate::zk::{day_aligned, MAX_CREDENTIAL_DAYS};

const DAY: i64 = 86_400;

#[derive(Serialize)]
struct Credential {
    redemption_time: i64,
    #[serde(with = "b64")]
    credential: Vec<u8>,
}

/// GET /v1/certificate/auth/group?redemption_start_seconds=S&redemption_end_seconds=E
/// Day-aligned auth credentials for S..=E (at most 7 days, starting no earlier than
/// yesterday and no later than today + 7 days).
pub async fn group_auth_credentials(State(st): State<AppState>, p: Principal, RawQuery(q): RawQuery) -> ApiResult {
    let now = crate::now_millis() / 1000;
    let today = now - now.rem_euclid(DAY);
    let start = query_int(q.as_deref(), "redemption_start_seconds", today, 0, i64::MAX)?;
    let end = query_int(q.as_deref(), "redemption_end_seconds", start + (MAX_CREDENTIAL_DAYS as i64 - 1) * DAY, 0, i64::MAX)?;
    if !day_aligned(start as u64) || !day_aligned(end as u64) {
        return Err(bad_request("redemption times must be day-aligned (UTC midnight)"));
    }
    if end < start || (end - start) / DAY >= MAX_CREDENTIAL_DAYS as i64 {
        return Err(bad_request("at most 7 days of credentials per request"));
    }
    if start < today - DAY || end > today + MAX_CREDENTIAL_DAYS as i64 * DAY {
        return Err(bad_request("redemption times out of range"));
    }
    let account = uuid::Uuid::parse_str(&p.account).map_err(|_| crate::error::internal())?;
    let zk = st.zk.clone();
    let credentials = tokio::task::spawn_blocking(move || {
        (0..=(end - start) / DAY)
            .map(|i| {
                let day = start + i * DAY;
                Credential { redemption_time: day, credential: zk.auth_credential(account, day as u64) }
            })
            .collect::<Vec<_>>()
    })
    .await
    .map_err(|e| crate::error::internal_from("credential issuance", e))?;
    Ok(reply(StatusCode::OK, json!({ "credentials": credentials })))
}
