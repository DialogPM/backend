//! What the apps read of the operator statements (crate::operator): notices for the account,
//! and the badge of an account in its directory entry. Everything here carries the signature
//! of an admin key; the apps verify it themselves.

use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use serde_json::{json, Value};

use super::reply;
use crate::auth::Principal;
use crate::db::RowExt;
use crate::error::ApiResult;
use crate::operator::EVERYONE;
use crate::state::AppState;
use crate::validate::b64;

/// Notices one request returns; the app asks again from the last id.
const PAGE: i64 = 100;

/// The badge of an account for its directory entry (None: not an official account).
pub(crate) async fn badge_of(st: &AppState, account: &str) -> Result<Option<Value>, sqlx::Error> {
    let row = sqlx::query("SELECT label, issued_at, signer, signature FROM operator_badges WHERE account_id = ?")
        .bind(account)
        .fetch_optional(&st.db)
        .await?;
    Ok(row.map(|r| {
        json!({"label": r.string("label"), "issued_at": r.i64("issued_at"),
               "key": b64::encode(&r.bytes("signer")), "signature": b64::encode(&r.bytes("signature"))})
    }))
}

/// GET /v1/notices?after=<id>: the operator's notices for this account and for everyone,
/// oldest first, after the given id.
pub async fn notices(State(st): State<AppState>, p: Principal, RawQuery(q): RawQuery) -> ApiResult {
    let after: i64 = q
        .as_deref()
        .and_then(|q| url::form_urlencoded::parse(q.as_bytes()).find(|(k, _)| k == "after").map(|(_, v)| v.into_owned()))
        .and_then(|v| v.parse().ok())
        .filter(|v| *v >= 0)
        .unwrap_or(0);
    let rows = sqlx::query(
        "SELECT id, account_id, title, body, created_at, signer, signature FROM operator_notices
         WHERE id > ? AND (account_id IS NULL OR account_id = ?) ORDER BY id LIMIT ?",
    )
    .bind(after)
    .bind(&p.account)
    .bind(PAGE + 1)
    .fetch_all(&st.db)
    .await?;
    let more = rows.len() as i64 > PAGE;
    let items: Vec<Value> = rows
        .iter()
        .take(PAGE as usize)
        .map(|r| {
            json!({"id": r.i64("id"), "target": r.opt_string("account_id").unwrap_or_else(|| EVERYONE.into()),
                   "title": r.string("title"), "body": r.string("body"), "created_at": r.i64("created_at"),
                   "key": b64::encode(&r.bytes("signer")), "signature": b64::encode(&r.bytes("signature"))})
        })
        .collect();
    Ok(reply(StatusCode::OK, json!({ "notices": items, "more": more })))
}
