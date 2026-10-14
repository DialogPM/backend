//! Group bans: accounts an admin removed (or whose join request an admin rejected) can't
//! rejoin with the invite link or ask again. Admins list them and lift a ban; adding the
//! account back (or approving its request) lifts it too.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Serialize;
use serde_json::json;

use super::groups::{begin_mutation, finish_mutation, find_member, load_members, ROLE_ADMIN};
use super::{no_content, reply};
use crate::auth::Principal;
use crate::error::{forbidden, not_found, ApiResult};
use crate::state::AppState;
use crate::validate::path_uuid;

#[derive(Serialize)]
struct BanJson {
    account_id: String,
    banned_by: String,
    banned_at: i64,
}

/// GET /v1/groups/{group_id}/bans (admins), newest first.
pub async fn list_bans(
    State(st): State<AppState>,
    p: Principal,
    Path(group_id): Path<String>,
) -> ApiResult {
    let gid = path_uuid("group_id", &group_id)?;
    let members = load_members(&st.db, &gid).await?;
    match find_member(&members, &p.account) {
        Some(me) if me.role == ROLE_ADMIN => {}
        _ => return Err(forbidden("only admins can do this")),
    }
    let rows = sqlx::query!(
        "SELECT account_id AS `account_id: String`, banned_by AS `banned_by: String`, banned_at FROM group_bans WHERE group_id = ? ORDER BY banned_at DESC",
        &gid
    )
    .fetch_all(&st.db)
    .await?;
    let out: Vec<BanJson> = rows
        .into_iter()
        .map(|r| BanJson {
            account_id: r.account_id,
            banned_by: r.banned_by,
            banned_at: r.banned_at,
        })
        .collect();
    Ok(reply(StatusCode::OK, json!({ "bans": out })))
}

/// DELETE /v1/groups/{group_id}/bans/{account_id} (admins): the account may rejoin by link.
pub async fn delete_ban(
    State(st): State<AppState>,
    p: Principal,
    Path((group_id, account_id)): Path<(String, String)>,
) -> ApiResult {
    let gid = path_uuid("group_id", &group_id)?;
    let target = path_uuid("account_id", &account_id)?;
    let mut m = begin_mutation(&st, &gid, &p, true).await?;
    let res = sqlx::query!("DELETE FROM group_bans WHERE group_id = ? AND account_id = ?", &gid, &target)
        .execute(&mut *m.tx)
        .await?;
    if res.rows_affected() == 0 {
        return Err(not_found("no such ban"));
    }
    // Other admins' lists resync.
    finish_mutation(&st, m, true).await?;
    Ok(no_content())
}
