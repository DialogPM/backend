//! Admin side of the operator statements (crate::operator): granting the badge of an official
//! account and publishing notices. The admin app signs each statement with its key; the
//! request signature (auth.rs) only says who may call the API, the statement signature is
//! what the apps verify.

use axum::body::Body;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::info;

use super::{account_id, int_param, json_body, params};
use crate::api::{no_content, reply};
use crate::db::RowExt;
use crate::error::{bad_request, not_found, ApiError, ApiResult};
use crate::operator::{self, EVERYONE};
use crate::state::AppState;
use crate::validate::b64;

/// A statement as the admin app sends it: who signed, and the signature.
#[derive(Deserialize)]
struct Signed {
    #[serde(default)]
    key: String,
    #[serde(default)]
    signature: String,
}

impl Signed {
    /// The signer (one of the configured admin keys) and the signature, when it verifies.
    fn check(&self, st: &AppState, message: &str) -> Result<([u8; 32], Vec<u8>), ApiError> {
        let key: [u8; 32] = b64::decode(&self.key)
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| bad_request("key must be a base64 Ed25519 public key"))?;
        let signature = b64::decode(&self.signature).ok_or_else(|| bad_request("signature must be base64"))?;
        let known = st.admin.as_ref().is_some_and(|a| a.verifier.has_key(&key));
        if !known || !operator::verify(&key, message, &signature) {
            return Err(bad_request("the statement is not signed by an admin key of this server"));
        }
        Ok((key, signature))
    }
}

fn recent(ms: i64, name: &str) -> Result<(), ApiError> {
    if (ms - crate::now_millis()).abs() > operator::MAX_SKEW_MS {
        return Err(bad_request(format!("{name} must be the current time (check the clock of this computer)")));
    }
    Ok(())
}

/// What the admin app needs to sign a badge, and the badge an account has.
pub(super) async fn account_extras(st: &AppState, id: &str) -> Result<Value, sqlx::Error> {
    let key = sqlx::query("SELECT identity_key FROM accounts WHERE id = ?").bind(id).fetch_optional(&st.db).await?;
    let badge = sqlx::query("SELECT label, issued_at FROM operator_badges WHERE account_id = ?").bind(id).fetch_optional(&st.db).await?;
    Ok(json!({
        "identity_key": key.and_then(|r| r.opt_bytes("identity_key")).map(|k| b64::encode(&k)),
        "badge": badge.map(|r| json!({"label": r.string("label"), "issued_at": r.i64("issued_at")})),
    }))
}

#[derive(Deserialize)]
struct BadgeRequest {
    #[serde(default)]
    label: String,
    #[serde(default)]
    issued_at: i64,
    #[serde(flatten)]
    signed: Signed,
}

/// POST /v1/admin/accounts/{id}/badge {label, issued_at, key, signature}
pub async fn set_badge(State(st): State<AppState>, Path(id): Path<String>, body: Body) -> ApiResult {
    let id = account_id(&id)?;
    let req: BadgeRequest = json_body(body).await?;
    let label = operator::clean_line(&req.label, operator::MAX_LABEL)
        .filter(|l| *l == req.label)
        .ok_or_else(|| bad_request("label must be 1-40 characters on one line, without spaces around it"))?;
    recent(req.issued_at, "issued_at")?;
    let identity = sqlx::query("SELECT identity_key FROM accounts WHERE id = ?")
        .bind(&id)
        .fetch_optional(&st.db)
        .await?
        .ok_or_else(|| not_found("unknown account"))?
        .opt_bytes("identity_key")
        .ok_or_else(|| bad_request("the account has no identity key"))?;
    // Signed over the key the account has now: the admin app read it a moment ago, and a key
    // replaced in between must not get the badge.
    let (signer, signature) = req.signed.check(&st, &operator::badge_string(&id, &identity, req.issued_at, &label))?;
    sqlx::query(
        "INSERT INTO operator_badges (account_id, label, issued_at, signer, signature) VALUES (?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE label = VALUES(label), issued_at = VALUES(issued_at), signer = VALUES(signer), signature = VALUES(signature)",
    )
    .bind(&id)
    .bind(&label)
    .bind(req.issued_at)
    .bind(&signer[..])
    .bind(&signature)
    .execute(&st.db)
    .await?;
    info!(account = %id, "admin marked an account as official");
    Ok(no_content())
}

/// POST /v1/admin/accounts/{id}/unbadge
pub async fn remove_badge(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult {
    let id = account_id(&id)?;
    let done = sqlx::query("DELETE FROM operator_badges WHERE account_id = ?").bind(&id).execute(&st.db).await?;
    if done.rows_affected() == 0 {
        return Err(not_found("the account has no badge"));
    }
    info!(account = %id, "admin removed an official badge");
    Ok(no_content())
}

/// GET /v1/admin/badges: the official accounts.
pub async fn list_badges(State(st): State<AppState>) -> ApiResult {
    let rows = sqlx::query(
        "SELECT b.account_id, b.label, b.issued_at, a.number, a.username
         FROM operator_badges b JOIN accounts a ON a.id = b.account_id ORDER BY b.issued_at DESC",
    )
    .fetch_all(&st.db)
    .await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({"account_id": r.string("account_id"), "label": r.string("label"), "issued_at": r.i64("issued_at"),
                   "number": r.string("number"), "username": r.opt_string("username")})
        })
        .collect();
    Ok(reply(StatusCode::OK, json!({ "items": items })))
}

#[derive(Deserialize)]
struct NoticeRequest {
    /// `*` or an account id.
    #[serde(default)]
    target: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    created_at: i64,
    #[serde(flatten)]
    signed: Signed,
}

/// POST /v1/admin/notices {target, title, body, created_at, key, signature} → {"id": n}
pub async fn publish_notice(State(st): State<AppState>, body: Body) -> ApiResult {
    let req: NoticeRequest = json_body(body).await?;
    let target = if req.target == EVERYONE { None } else { Some(account_id(&req.target)?) };
    // Exactly the text that was signed: nothing is trimmed here.
    let title = operator::clean_line(&req.title, operator::MAX_TITLE)
        .filter(|t| *t == req.title)
        .ok_or_else(|| bad_request("title must be 1-120 characters on one line, without spaces around it"))?;
    let text = operator::clean_text(&req.body, operator::MAX_BODY)
        .filter(|t| *t == req.body)
        .ok_or_else(|| bad_request("body must be 1-2000 characters, without spaces around it"))?;
    recent(req.created_at, "created_at")?;
    if let Some(account) = &target {
        let exists = sqlx::query("SELECT id FROM accounts WHERE id = ?").bind(account).fetch_optional(&st.db).await?;
        if exists.is_none() {
            return Err(not_found("unknown account"));
        }
    }
    let message = operator::notice_string(target.as_deref().unwrap_or(EVERYONE), req.created_at, &title, &text);
    let (signer, signature) = req.signed.check(&st, &message)?;
    let done = sqlx::query("INSERT INTO operator_notices (account_id, title, body, created_at, signer, signature) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(&target)
        .bind(&title)
        .bind(&text)
        .bind(req.created_at)
        .bind(&signer[..])
        .bind(&signature)
        .execute(&st.db)
        .await?;
    let id = done.last_insert_id();
    // Connected apps fetch it now; the others when they connect.
    let event = json!({"kind": "operator_notice", "id": id});
    match &target {
        Some(account) => st.hub.send_event(account, 0, &event),
        None => st.hub.broadcast_event(&event),
    }
    info!(id, everyone = target.is_none(), "admin published a notice");
    Ok(reply(StatusCode::OK, json!({ "id": id })))
}

/// GET /v1/admin/notices?limit=50&offset=0, newest first.
pub async fn list_notices(State(st): State<AppState>, RawQuery(q): RawQuery) -> ApiResult {
    let p = params(&q);
    let limit = int_param(&p, "limit", 50, 1, 200)?;
    let offset = int_param(&p, "offset", 0, 0, 1_000_000)?;
    let total = sqlx::query("SELECT COUNT(*) AS v FROM operator_notices").fetch_one(&st.db).await?.i64("v");
    let rows = sqlx::query(
        "SELECT n.id, n.account_id, n.title, n.body, n.created_at, a.number
         FROM operator_notices n LEFT JOIN accounts a ON a.id = n.account_id ORDER BY n.id DESC LIMIT ? OFFSET ?",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&st.db)
    .await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({"id": r.i64("id"), "target": r.opt_string("account_id").unwrap_or_else(|| EVERYONE.into()), "number": r.opt_string("number"),
                   "title": r.string("title"), "body": r.string("body"), "created_at": r.i64("created_at")})
        })
        .collect();
    Ok(reply(StatusCode::OK, json!({ "total": total, "items": items })))
}

/// POST /v1/admin/notices/{id}/delete: the server stops handing it out. Apps that already
/// have it keep it.
pub async fn delete_notice(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult {
    let id: u64 = id.parse().map_err(|_| bad_request("notice id must be a number"))?;
    let done = sqlx::query("DELETE FROM operator_notices WHERE id = ?").bind(id).execute(&st.db).await?;
    if done.rows_affected() == 0 {
        return Err(not_found("unknown notice"));
    }
    info!(id, "admin deleted a notice");
    Ok(no_content())
}
