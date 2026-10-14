//! Group invite links. The link holds a secret that never reaches the server; clients derive
//! from it a token (sent here, stored hashed) and a key for the blob (an encrypted preview of
//! the group, opaque to the server). With approval, joining creates a request that an admin
//! approves or rejects; without it, the token alone adds the caller as a member.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::MySql;

use super::groups::{
    ban_member, begin_mutation, bump_revision, find_member, finish_mutation, insert_member_now,
    is_banned, load_members, lock_group, member_ids, push_group_updated, unban_member,
    GroupChange, ROLE_ADMIN,
};
use super::{no_content, reply};
use crate::auth::Principal;
use crate::db::is_duplicate_key;
use crate::error::{bad_request, conflict, forbidden, not_found, too_large, ApiError, ApiResult};
use crate::state::AppState;
use crate::validate::{b64, parse_json, path_uuid, MAX_GROUP_METADATA, MAX_JSON_BODY};

const INVITE_TOKEN_LEN: usize = 32;
const MAX_INVITE_INTRO: usize = 4 << 10;
/// Pending requests kept per group (older ones must be handled first).
const MAX_JOIN_REQUESTS: i64 = 500;

pub struct InviteRow {
    pub group_id: String,
    pub approval: bool,
    pub blob: Vec<u8>,
}

fn token_hash(token: &[u8]) -> Vec<u8> {
    Sha256::digest(token).to_vec()
}

fn validate_token(token: &[u8]) -> Result<(), ApiError> {
    if token.len() != INVITE_TOKEN_LEN {
        return Err(bad_request("token must be 32 bytes"));
    }
    Ok(())
}

/// The invite of a group, or None when it has none.
pub async fn load_invite<'e, E>(db: E, group_id: &str) -> Result<Option<InviteRow>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = MySql>,
{
    let row = sqlx::query!(
        "SELECT group_id AS `group_id: String`, approval AS `approval: bool`, preview FROM group_invites WHERE group_id = ?",
        group_id
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| InviteRow {
        group_id: r.group_id,
        approval: r.approval,
        blob: r.preview,
    }))
}

/// The invite a token belongs to (404 for unknown or revoked links).
async fn invite_by_token<'e, E>(db: E, token: &[u8]) -> Result<InviteRow, ApiError>
where
    E: sqlx::Executor<'e, Database = MySql>,
{
    let row = sqlx::query!(
        "SELECT group_id AS `group_id: String`, approval AS `approval: bool`, preview FROM group_invites WHERE token_hash = ?",
        token_hash(token)
    )
    .fetch_optional(db)
    .await?;
    row.map(|r| InviteRow {
        group_id: r.group_id,
        approval: r.approval,
        blob: r.preview,
    })
    .ok_or_else(|| not_found("this invite link is not valid anymore"))
}

pub async fn count_join_requests<'e, E>(db: E, group_id: &str) -> Result<i64, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = MySql>,
{
    let r = sqlx::query!("SELECT COUNT(*) AS `n!: i64` FROM group_join_requests WHERE group_id = ?", group_id)
        .fetch_one(db)
        .await?;
    Ok(r.n)
}

#[derive(Deserialize)]
struct PutInviteRequest {
    #[serde(default, with = "b64")]
    token: Vec<u8>,
    #[serde(default)]
    approval: bool,
    #[serde(default, with = "b64")]
    blob: Vec<u8>,
}

/// PUT /v1/groups/{group_id}/invite (admins): creates the link, replaces it (reset) or
/// updates its blob / approval.
pub async fn put_invite(
    State(st): State<AppState>,
    p: Principal,
    Path(group_id): Path<String>,
    body: Body,
) -> ApiResult {
    let gid = path_uuid("group_id", &group_id)?;
    let req: PutInviteRequest = parse_json(body, MAX_JSON_BODY).await?;
    validate_token(&req.token)?;
    if req.blob.is_empty() || req.blob.len() > MAX_GROUP_METADATA {
        return Err(bad_request("blob is required and must not exceed 64 KiB"));
    }
    let mut m = begin_mutation(&st, &gid, &p, true).await?;
    let res = sqlx::query!(
        "INSERT INTO group_invites (group_id, token_hash, approval, preview, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE token_hash = VALUES(token_hash), approval = VALUES(approval), preview = VALUES(preview),
             created_by = VALUES(created_by), created_at = VALUES(created_at)",
        &gid,
        token_hash(&req.token),
        req.approval,
        &req.blob,
        &p.account,
        crate::now_millis()
    )
    .execute(&mut *m.tx)
    .await;
    match res {
        Err(e) if is_duplicate_key(&e) => return Err(conflict("token already in use")),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    finish_mutation(&st, m, true).await?;
    Ok(no_content())
}

/// DELETE /v1/groups/{group_id}/invite (admins): turns the link off.
pub async fn delete_invite(
    State(st): State<AppState>,
    p: Principal,
    Path(group_id): Path<String>,
) -> ApiResult {
    let gid = path_uuid("group_id", &group_id)?;
    let mut m = begin_mutation(&st, &gid, &p, true).await?;
    let res = sqlx::query!("DELETE FROM group_invites WHERE group_id = ?", &gid)
        .execute(&mut *m.tx)
        .await?;
    finish_mutation(&st, m, res.rows_affected() > 0).await?;
    Ok(no_content())
}

#[derive(Deserialize)]
struct LookupRequest {
    #[serde(default, with = "b64")]
    token: Vec<u8>,
}

/// POST /v1/invites/lookup: the preview of a link (any account holding it).
pub async fn lookup(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    st.rate_limit(
        &format!("invite:acct:{}", p.account),
        st.limits.invite_account,
    )?;
    let req: LookupRequest = parse_json(body, MAX_JSON_BODY).await?;
    validate_token(&req.token)?;
    let inv = invite_by_token(&st.db, &req.token).await?;
    let members = load_members(&st.db, &inv.group_id).await?;
    let requested = sqlx::query!(
        "SELECT COUNT(*) AS `n!: i64` FROM group_join_requests WHERE group_id = ? AND account_id = ?",
        &inv.group_id,
        &p.account
    )
    .fetch_one(&st.db)
    .await?
    .n;
    Ok(reply(
        StatusCode::OK,
        json!({
            "group_id": inv.group_id,
            "approval": inv.approval,
            "blob": b64::encode(&inv.blob),
            "member_count": members.len(),
            "is_member": find_member(&members, &p.account).is_some(),
            "requested": requested > 0,
            "banned": is_banned(&st.db, &inv.group_id, &p.account).await?,
        }),
    ))
}

#[derive(Deserialize)]
struct JoinRequest {
    #[serde(default, with = "b64")]
    token: Vec<u8>,
    /// Absent/null is stored as NULL.
    #[serde(default, with = "b64::opt")]
    intro: Option<Vec<u8>>,
}

/// POST /v1/invites/join: joins right away, or asks the admins when the link requires approval.
pub async fn join(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    st.rate_limit(
        &format!("invite:acct:{}", p.account),
        st.limits.invite_account,
    )?;
    let req: JoinRequest = parse_json(body, MAX_JSON_BODY).await?;
    validate_token(&req.token)?;
    if req
        .intro
        .as_ref()
        .is_some_and(|i| i.len() > MAX_INVITE_INTRO)
    {
        return Err(too_large("intro exceeds 4 KiB"));
    }
    let mut tx = st.db.begin().await?;
    let inv = invite_by_token(&mut *tx, &req.token).await?;
    let gid = inv.group_id;
    let mut g = lock_group(&mut tx, &gid).await?;
    // The link may have been reset while we waited for the lock.
    let inv = invite_by_token(&mut *tx, &req.token).await?;
    let members = load_members(&mut *tx, &gid).await?;
    if find_member(&members, &p.account).is_some() {
        tx.commit().await?;
        return Ok(reply(
            StatusCode::OK,
            json!({"status": "member", "group_id": gid}),
        ));
    }
    if is_banned(&mut *tx, &gid, &p.account).await? {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "banned",
            "an admin removed you from this group",
        ));
    }
    if members.len() as i64 >= st.cfg.max_group_members {
        return Err(bad_request("group member limit reached"));
    }
    let now = crate::now_millis();
    let status = if inv.approval {
        let n = count_join_requests(&mut *tx, &gid).await?;
        if n >= MAX_JOIN_REQUESTS {
            return Err(conflict("too many pending requests"));
        }
        sqlx::query!(
            "INSERT INTO group_join_requests (group_id, account_id, intro, requested_at)
             VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE intro = VALUES(intro), requested_at = VALUES(requested_at)",
            &gid,
            &p.account,
            &req.intro,
            now
        )
        .execute(&mut *tx)
        .await?;
        "requested"
    } else {
        insert_member_now(&mut tx, &gid, &p.account, now, &p.account).await?;
        sqlx::query!("DELETE FROM group_join_requests WHERE group_id = ? AND account_id = ?", &gid, &p.account)
            .execute(&mut *tx)
            .await?;
        "joined"
    };
    // Members (admins see the request count) resync.
    let rev = bump_revision(&mut tx, &mut g).await?;
    let after = load_members(&mut *tx, &gid).await?;
    tx.commit().await?;
    push_group_updated(
        &st,
        &GroupChange {
            group_id: gid.clone(),
            revision: rev,
            recipients: member_ids(&after),
        },
    );
    Ok(reply(
        StatusCode::OK,
        json!({"status": status, "group_id": gid}),
    ))
}

#[derive(Serialize)]
struct JoinRequestJson {
    account_id: String,
    #[serde(with = "b64::opt")]
    intro: Option<Vec<u8>>,
    requested_at: i64,
}

/// GET /v1/groups/{group_id}/requests (admins).
pub async fn list_join_requests(
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
    let rows = sqlx::query!("SELECT account_id AS `account_id: String`, intro, requested_at FROM group_join_requests WHERE group_id = ? ORDER BY requested_at", &gid)
        .fetch_all(&st.db)
        .await?;
    let out: Vec<JoinRequestJson> = rows
        .into_iter()
        .map(|r| JoinRequestJson {
            account_id: r.account_id,
            intro: r.intro,
            requested_at: r.requested_at,
        })
        .collect();
    Ok(reply(StatusCode::OK, json!({"requests": out})))
}

/// POST /v1/groups/{group_id}/requests/{account_id}/approve (admins).
pub async fn approve_join_request(
    State(st): State<AppState>,
    p: Principal,
    Path((group_id, account_id)): Path<(String, String)>,
) -> ApiResult {
    let gid = path_uuid("group_id", &group_id)?;
    let target = path_uuid("account_id", &account_id)?;
    let mut m = begin_mutation(&st, &gid, &p, true).await?;
    let res = sqlx::query!("DELETE FROM group_join_requests WHERE group_id = ? AND account_id = ?", &gid, &target)
        .execute(&mut *m.tx)
        .await?;
    if res.rows_affected() == 0 {
        return Err(not_found("no such request"));
    }
    if find_member(&m.members, &target).is_none() {
        if m.members.len() as i64 >= st.cfg.max_group_members {
            return Err(bad_request("group member limit reached"));
        }
        insert_member_now(&mut m.tx, &gid, &target, crate::now_millis(), &p.account).await?;
    }
    unban_member(&mut m.tx, &gid, &target).await?;
    finish_mutation(&st, m, true).await?;
    Ok(no_content())
}

/// DELETE /v1/groups/{group_id}/requests/{account_id}: an admin rejects the request, or the
/// requester withdraws it.
pub async fn delete_join_request(
    State(st): State<AppState>,
    p: Principal,
    Path((group_id, account_id)): Path<(String, String)>,
) -> ApiResult {
    let gid = path_uuid("group_id", &group_id)?;
    let target = path_uuid("account_id", &account_id)?;
    let mut tx = st.db.begin().await?;
    let mut g = lock_group(&mut tx, &gid).await?;
    let members = load_members(&mut *tx, &gid).await?;
    if target != p.account {
        match find_member(&members, &p.account) {
            Some(me) if me.role == ROLE_ADMIN => {}
            _ => return Err(forbidden("only admins can do this")),
        }
    }
    let res = sqlx::query!("DELETE FROM group_join_requests WHERE group_id = ? AND account_id = ?", &gid, &target)
        .execute(&mut *tx)
        .await?;
    if res.rows_affected() == 0 {
        return Err(not_found("no such request"));
    }
    if target != p.account {
        // Rejected by an admin: no new requests (an admin can still add the account).
        ban_member(&mut tx, &gid, &target, &p.account).await?;
    }
    let rev = bump_revision(&mut tx, &mut g).await?;
    tx.commit().await?;
    push_group_updated(
        &st,
        &GroupChange {
            group_id: gid,
            revision: rev,
            recipients: member_ids(&members),
        },
    );
    Ok(no_content())
}
