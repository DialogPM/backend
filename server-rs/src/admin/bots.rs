//! Bots in the admin API (docs/ADMIN-API.md): the operator sees every bot with its owner and
//! can switch one off or delete it. A bot that is off keeps its name, chats and token, but
//! its token is refused and nobody can start it or write to it until it is switched on again.
//!
//! The operator sees what the server stores anyway: a bot's public description, who created
//! it and how many people started it. Not who those people are in the list, and no messages
//! (what a bot sent is in its recipients' queues only until they fetch it).

use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use serde_json::{json, Value};
use tracing::info;

use super::params;
use crate::api::{no_content, reply};
use crate::db::RowExt;
use crate::error::{not_found, ApiResult};
use crate::state::AppState;
use crate::validate::path_uuid;

const PAGE: i64 = 200;

/// GET /v1/admin/bots?q=…: bots whose username or name contains `q` (all when empty),
/// newest first, at most 200, with the total.
pub async fn list(State(st): State<AppState>, RawQuery(q): RawQuery) -> ApiResult {
    let p = params(&q);
    let needle = p.get("q").map(|s| s.trim().trim_start_matches('@').to_lowercase()).unwrap_or_default();
    let like = format!("%{}%", needle.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
    let total = sqlx::query("SELECT COUNT(*) AS v FROM bots WHERE username LIKE ? OR LOWER(name) LIKE ?")
        .bind(&like)
        .bind(&like)
        .fetch_one(&st.db)
        .await?
        .i64("v");
    let rows = sqlx::query(
        "SELECT b.id, b.username, b.name, b.about, b.owner_account_id, b.disabled_at, b.created_at, a.number AS owner_number,
                (SELECT COUNT(*) FROM bot_chats c WHERE c.bot_id = b.id AND c.active = 1) AS subscribers,
                (SELECT COUNT(*) FROM bot_updates u WHERE u.bot_id = b.id) AS pending_updates
         FROM bots b JOIN accounts a ON a.id = b.owner_account_id
         WHERE b.username LIKE ? OR LOWER(b.name) LIKE ?
         ORDER BY b.created_at DESC, b.id LIMIT ?",
    )
    .bind(&like)
    .bind(&like)
    .bind(PAGE)
    .fetch_all(&st.db)
    .await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.string("id"),
                "username": r.string("username"),
                "name": r.string("name"),
                "about": r.string("about"),
                "owner_account_id": r.string("owner_account_id"),
                "owner_number": r.string("owner_number"),
                "created_at": r.i64("created_at"),
                "disabled_at": r.opt_i64("disabled_at"),
                "subscribers": r.i64("subscribers"),
                "pending_updates": r.i64("pending_updates"),
            })
        })
        .collect();
    Ok(reply(StatusCode::OK, json!({"items": items, "total": total})))
}

async fn set_disabled(st: &AppState, id: &str, disabled: bool) -> ApiResult {
    let id = path_uuid("id", id)?;
    let at = disabled.then(crate::now_millis);
    // An already disabled bot keeps the time it was first switched off.
    let done = sqlx::query("UPDATE bots SET disabled_at = IF(? IS NULL, NULL, COALESCE(disabled_at, ?)) WHERE id = ?")
        .bind(at)
        .bind(at)
        .bind(&id)
        .execute(&st.db)
        .await?;
    if done.rows_affected() == 0 && sqlx::query("SELECT 1 FROM bots WHERE id = ?").bind(&id).fetch_optional(&st.db).await?.is_none() {
        return Err(not_found("unknown bot"));
    }
    info!(bot = %id, disabled, "admin: bot switched");
    // A script waiting in getUpdates finds out at its next call.
    crate::api::bots::wake(&id);
    Ok(no_content())
}

/// POST /v1/admin/bots/{id}/disable
pub async fn disable(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult {
    set_disabled(&st, &id, true).await
}

/// POST /v1/admin/bots/{id}/enable
pub async fn enable(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult {
    set_disabled(&st, &id, false).await
}

/// POST /v1/admin/bots/{id}/delete: as if its owner had deleted it (its name becomes free).
pub async fn delete(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult {
    let id = path_uuid("id", &id)?;
    if !crate::api::bots::remove(&st, &id).await? {
        return Err(not_found("unknown bot"));
    }
    info!(bot = %id, "admin: bot deleted");
    Ok(no_content())
}
