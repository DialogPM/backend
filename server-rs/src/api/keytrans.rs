//! Key transparency endpoints (docs/KEY-TRANSPARENCY.md). Public and unauthenticated: the
//! log is public data, and looking a key up must not tell the server who is asking.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use serde_json::json;

use super::{query_int, reply};
use crate::error::{bad_request, not_found, ApiResult};
use crate::keytrans::{Hash, KtLog};
use crate::state::AppState;
use crate::validate::{b64, path_uuid};

/// Most entries per GET /v1/kt/entries.
const MAX_ENTRIES: i64 = 1000;

fn hashes(v: &[Hash]) -> Vec<String> {
    v.iter().map(|h| b64::encode(h)).collect()
}

fn limit(st: &AppState, headers: &HeaderMap, peer: SocketAddr) -> Result<(), crate::error::ApiError> {
    st.rate_limit(&format!("kt:ip:{}", st.client_ip(headers, peer)), st.limits.sealed_ip)
}

/// GET /v1/kt/head?since=N — the current signed tree head, plus a consistency proof from
/// size N when 0 < N.
pub async fn head(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(q): RawQuery,
) -> ApiResult {
    limit(&st, &headers, peer)?;
    let since = query_int(q.as_deref(), "since", 0, 0, i64::MAX)? as u64;
    let v = st.kt.head(&st.db, since).await?;
    Ok(reply(
        StatusCode::OK,
        json!({ "head": v.head, "consistency": v.consistency.as_deref().map(hashes) }),
    ))
}

/// GET /v1/kt/proof/{account_id}?since=N — the account's log entry with its inclusion proof
/// under the current head (and a consistency proof from size N).
pub async fn proof(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    RawQuery(q): RawQuery,
) -> ApiResult {
    limit(&st, &headers, peer)?;
    let account_id = path_uuid("account_id", &account_id)?;
    let since = query_int(q.as_deref(), "since", 0, 0, i64::MAX)? as u64;
    let Some((entry, v)) = st.kt.proof(&st.db, &account_id, since).await? else {
        return Err(not_found("the account is not in the log"));
    };
    Ok(reply(
        StatusCode::OK,
        json!({
            "head": v.head,
            "consistency": v.consistency.as_deref().map(hashes),
            "entry": entry,
            "inclusion": hashes(v.inclusion.as_deref().unwrap_or_default()),
        }),
    ))
}

/// GET /v1/kt/consistency?first=M&second=N — consistency proof between two log sizes.
pub async fn consistency(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(q): RawQuery,
) -> ApiResult {
    limit(&st, &headers, peer)?;
    let first = query_int(q.as_deref(), "first", 0, 1, i64::MAX)? as u64;
    let second = query_int(q.as_deref(), "second", 0, 1, i64::MAX)? as u64;
    let proof = st.kt.consistency(&st.db, first, second).await?;
    Ok(reply(StatusCode::OK, json!({ "proof": hashes(&proof) })))
}

/// GET /v1/kt/entries?start=S&end=E — entries [S, E) (at most 1000), for clients monitoring
/// their own account.
pub async fn entries(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(q): RawQuery,
) -> ApiResult {
    limit(&st, &headers, peer)?;
    let start = query_int(q.as_deref(), "start", 0, 0, i64::MAX)?;
    let end = query_int(q.as_deref(), "end", start + MAX_ENTRIES, 0, i64::MAX)?;
    if end < start || end - start > MAX_ENTRIES {
        return Err(bad_request(format!("at most {MAX_ENTRIES} entries per request")));
    }
    let entries = KtLog::entries(&st.db, start as u64, end as u64).await?;
    Ok(reply(StatusCode::OK, json!({ "entries": entries })))
}
