//! Groups: membership, settings, metadata and group sends (API section 8).

use std::collections::{BTreeMap, HashSet};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::mysql::MySqlRow;
use sqlx::{MySql, Transaction};

use super::invites::{count_join_requests, load_invite};
use super::messages::{
    deliver, insert_envelopes, validate_content, validate_timestamp, Envelope, ENVELOPE_SENDER_KEY,
};
use super::{no_content, reply};
use crate::auth::Principal;
use crate::db::{is_foreign_key_violation, placeholders, RowExt};
use crate::error::{
    bad_request, conflict, forbidden, gone, not_found, too_large, ApiError, ApiResult,
};
use crate::ids;
use crate::state::AppState;
use crate::validate::{
    b64, optional_attachment_id, parse_json, path_uuid, MAX_DEVICE_ID, MAX_GROUP_METADATA,
    MAX_JSON_BODY,
};

pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_MEMBER: &str = "member";

const MAX_DISAPPEARING_SECONDS: i64 = 365 * 24 * 3600;

fn group_not_found() -> ApiError {
    not_found("unknown group")
}

/// Result of a membership mutation, used to notify devices.
#[derive(Clone, Debug, Default)]
pub struct GroupChange {
    pub group_id: String,
    pub revision: i64,
    /// Current members plus the members removed by the mutation.
    pub recipients: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct GroupRow {
    pub id: String,
    pub revision: i64,
    pub metadata: Vec<u8>,
    pub avatar_id: Option<String>,
    pub created_by: String,
    pub created_at: i64,
    pub only_admins_send: bool,
    pub only_admins_edit: bool,
    // Group rules (see migration 0005).
    pub disappearing_seconds: i64,
    pub hide_members: bool,
    pub member_names: String,
}

impl GroupRow {
    fn from_row(r: &MySqlRow) -> GroupRow {
        GroupRow {
            id: r.string("id"),
            revision: r.i64("revision"),
            metadata: r.bytes("metadata"),
            avatar_id: r.opt_string("avatar_id"),
            created_by: r.string("created_by"),
            created_at: r.i64("created_at"),
            only_admins_send: r.boolean("only_admins_send"),
            only_admins_edit: r.boolean("only_admins_edit"),
            disappearing_seconds: r.i64("disappearing_seconds"),
            hide_members: r.boolean("hide_members"),
            member_names: r.string("member_names"),
        }
    }

    fn settings_json(&self) -> Value {
        json!({
            "only_admins_send": self.only_admins_send,
            "only_admins_edit": self.only_admins_edit,
            "disappearing_seconds": self.disappearing_seconds,
            "hide_members": self.hide_members,
            "member_names": self.member_names,
        })
    }
}

/// Body of PUT /v1/groups/{id}/settings (and "settings" when creating a group). Omitted
/// fields keep their value.
#[derive(Deserialize, Default)]
pub struct GroupSettingsPatch {
    #[serde(default)]
    only_admins_send: Option<bool>,
    #[serde(default)]
    only_admins_edit: Option<bool>,
    #[serde(default)]
    disappearing_seconds: Option<i64>,
    #[serde(default)]
    hide_members: Option<bool>,
    #[serde(default)]
    member_names: Option<String>,
}

impl GroupSettingsPatch {
    /// Validates the patch and applies it to g.
    fn apply(&self, g: &mut GroupRow) -> Result<(), ApiError> {
        if let Some(d) = self.disappearing_seconds {
            if !(0..=MAX_DISAPPEARING_SECONDS).contains(&d) {
                return Err(bad_request("disappearing_seconds out of range"));
            }
        }
        if let Some(n) = &self.member_names {
            if n != "number" && n != "first_name" {
                return Err(bad_request(
                    r#"member_names must be "number" or "first_name""#,
                ));
            }
        }
        if let Some(v) = self.only_admins_send {
            g.only_admins_send = v;
        }
        if let Some(v) = self.only_admins_edit {
            g.only_admins_edit = v;
        }
        if let Some(v) = self.disappearing_seconds {
            g.disappearing_seconds = v;
        }
        if let Some(v) = self.hide_members {
            g.hide_members = v;
        }
        if let Some(v) = &self.member_names {
            g.member_names = v.clone();
        }
        Ok(())
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct GroupMember {
    pub account_id: String,
    pub role: String,
    pub joined_at: i64,
    pub added_by: String,
}

const LOAD_GROUP: &str = "SELECT id, revision, metadata, avatar_id, created_by, created_at,
    only_admins_send, only_admins_edit, disappearing_seconds, hide_members, member_names
    FROM chat_groups WHERE id = ?";
const LOAD_GROUP_FOR_UPDATE: &str =
    "SELECT id, revision, metadata, avatar_id, created_by, created_at,
    only_admins_send, only_admins_edit, disappearing_seconds, hide_members, member_names
    FROM chat_groups WHERE id = ? FOR UPDATE";
const LOAD_GROUP_FOR_SHARE: &str =
    "SELECT id, revision, metadata, avatar_id, created_by, created_at,
    only_admins_send, only_admins_edit, disappearing_seconds, hide_members, member_names
    FROM chat_groups WHERE id = ? FOR SHARE";

async fn load_group(
    tx: &mut Transaction<'_, MySql>,
    id: &str,
    sql: &'static str,
) -> Result<GroupRow, ApiError> {
    match sqlx::query(sql).bind(id).fetch_optional(&mut **tx).await? {
        Some(r) => Ok(GroupRow::from_row(&r)),
        None => Err(group_not_found()),
    }
}

/// Locks the group row (SELECT ... FOR UPDATE); not_found if it does not exist. All membership
/// mutations take it, which serializes them per group.
pub async fn lock_group(tx: &mut Transaction<'_, MySql>, id: &str) -> Result<GroupRow, ApiError> {
    load_group(tx, id, LOAD_GROUP_FOR_UPDATE).await
}

/// The members of a group ordered by seniority.
pub async fn load_members<'e, E>(db: E, group_id: &str) -> Result<Vec<GroupMember>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = MySql>,
{
    let rows = sqlx::query!("SELECT account_id AS `account_id: String`, role AS `role: String`, joined_at, added_by AS `added_by: String` FROM group_members WHERE group_id = ? ORDER BY member_seq", group_id)
        .fetch_all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| GroupMember {
            account_id: r.account_id,
            role: r.role,
            joined_at: r.joined_at,
            added_by: r.added_by,
        })
        .collect())
}

pub fn find_member<'a>(members: &'a [GroupMember], account: &str) -> Option<&'a GroupMember> {
    members.iter().find(|m| m.account_id == account)
}

pub fn member_ids(members: &[GroupMember]) -> Vec<String> {
    members.iter().map(|m| m.account_id.clone()).collect()
}

/// Increments the revision of a locked group and returns the new value.
pub async fn bump_revision(
    tx: &mut Transaction<'_, MySql>,
    g: &mut GroupRow,
) -> Result<i64, sqlx::Error> {
    sqlx::query!("UPDATE chat_groups SET revision = revision + 1 WHERE id = ?", &g.id)
        .execute(&mut **tx)
        .await?;
    g.revision += 1;
    Ok(g.revision)
}

/// Removes accounts from a group whose row is locked by tx. If no admin is left the
/// longest-standing member is promoted; if no member is left the group is deleted.
pub async fn remove_members_tx(
    tx: &mut Transaction<'_, MySql>,
    group_id: &str,
    accounts: &[String],
) -> Result<GroupChange, ApiError> {
    let mut g = load_group(tx, group_id, LOAD_GROUP).await?;
    for a in accounts {
        sqlx::query!("DELETE FROM group_members WHERE group_id = ? AND account_id = ?", group_id, a)
            .execute(&mut **tx)
            .await?;
    }
    let remaining = load_members(&mut **tx, group_id).await?;
    let mut recipients = member_ids(&remaining);
    recipients.extend(accounts.iter().cloned());
    let ch = GroupChange {
        group_id: group_id.to_string(),
        revision: g.revision + 1,
        recipients,
    };
    if remaining.is_empty() {
        sqlx::query!("DELETE FROM chat_groups WHERE id = ?", group_id)
            .execute(&mut **tx)
            .await?;
        return Ok(ch);
    }
    if !remaining.iter().any(|m| m.role == ROLE_ADMIN) {
        sqlx::query!(
            "UPDATE group_members SET role = ? WHERE group_id = ? AND account_id = ?",
            ROLE_ADMIN,
            group_id,
            &remaining[0].account_id
        )
        .execute(&mut **tx)
            .await?;
    }
    bump_revision(tx, &mut g).await?;
    Ok(ch)
}

/// Bans `account` from rejoining the group by link or request (group row locked by tx).
pub(crate) async fn ban_member(
    tx: &mut Transaction<'_, MySql>,
    gid: &str,
    account: &str,
    by: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO group_bans (group_id, account_id, banned_by, banned_at) VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE banned_by = VALUES(banned_by), banned_at = VALUES(banned_at)",
        gid,
        account,
        by,
        crate::now_millis()
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(crate) async fn unban_member(
    tx: &mut Transaction<'_, MySql>,
    gid: &str,
    account: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!("DELETE FROM group_bans WHERE group_id = ? AND account_id = ?", gid, account)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(crate) async fn is_banned<'e, E>(db: E, gid: &str, account: &str) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = MySql>,
{
    Ok(
        sqlx::query!("SELECT account_id FROM group_bans WHERE group_id = ? AND account_id = ?", gid, account)
            .fetch_optional(db)
            .await?
            .is_some(),
    )
}

/// Sends a group_updated event to all devices of the affected accounts.
pub fn push_group_updated(st: &AppState, ch: &GroupChange) {
    let event = json!({"kind": "group_updated", "group_id": ch.group_id, "revision": ch.revision});
    let mut seen = HashSet::new();
    for a in &ch.recipients {
        if seen.insert(a.as_str()) {
            st.hub.send_event(a, 0, &event);
        }
    }
}

/// Validates, normalizes and de-duplicates a list of account ids.
fn parse_account_ids(field: &str, raw: &[String], max: i64) -> Result<Vec<String>, ApiError> {
    if raw.len() as i64 > max {
        return Err(bad_request(format!("{field} has too many entries")));
    }
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(raw.len());
    for r in raw {
        let id = ids::normalize_uuid(r)
            .ok_or_else(|| bad_request(format!("{field} must contain account UUIDs")))?;
        if seen.insert(id.clone()) {
            out.push(id);
        }
    }
    Ok(out)
}

/// 404 if any of the accounts does not exist.
async fn require_accounts_exist(
    tx: &mut Transaction<'_, MySql>,
    accounts: &[String],
) -> Result<(), ApiError> {
    if accounts.is_empty() {
        return Ok(());
    }
    let sql = format!(
        "SELECT COUNT(*) FROM accounts WHERE id IN ({})",
        placeholders(accounts.len())
    );
    let mut q = sqlx::query(&sql);
    for a in accounts {
        q = q.bind(a);
    }
    let n = q.fetch_one(&mut **tx).await?.i64("COUNT(*)");
    if n != accounts.len() as i64 {
        return Err(not_found("unknown account"));
    }
    Ok(())
}

fn validate_metadata(b: &[u8]) -> Result<(), ApiError> {
    if b.is_empty() {
        return Err(bad_request("metadata is required"));
    }
    if b.len() > MAX_GROUP_METADATA {
        return Err(too_large("metadata exceeds 64 KiB"));
    }
    Ok(())
}

async fn insert_member(
    tx: &mut Transaction<'_, MySql>,
    gid: &str,
    account: &str,
    role: &str,
    now: i64,
    added_by: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!("INSERT INTO group_members (group_id, account_id, role, joined_at, added_by) VALUES (?, ?, ?, ?, ?)", gid, account, role, now, added_by)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(crate) async fn insert_member_now(
    tx: &mut Transaction<'_, MySql>,
    gid: &str,
    account: &str,
    now: i64,
    added_by: &str,
) -> Result<(), sqlx::Error> {
    insert_member(tx, gid, account, ROLE_MEMBER, now, added_by).await
}

#[derive(Deserialize)]
struct CreateGroupRequest {
    #[serde(default, with = "b64")]
    metadata: Vec<u8>,
    #[serde(default)]
    avatar_id: Option<String>,
    #[serde(default)]
    members: Option<Vec<String>>,
    // Optional initial rules.
    #[serde(default)]
    settings: Option<GroupSettingsPatch>,
}

pub async fn create_group(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    let req: CreateGroupRequest = parse_json(body, MAX_JSON_BODY).await?;
    validate_metadata(&req.metadata)?;
    optional_attachment_id("avatar_id", req.avatar_id.as_deref())?;
    let members = parse_account_ids(
        "members",
        req.members.as_deref().unwrap_or_default(),
        st.cfg.max_group_members + 1,
    )?;
    let others: Vec<String> = members.into_iter().filter(|m| *m != p.account).collect();
    if others.len() as i64 + 1 > st.cfg.max_group_members {
        return Err(bad_request("too many members"));
    }
    let mut rules = GroupRow {
        member_names: "number".into(),
        ..Default::default()
    };
    if let Some(s) = &req.settings {
        s.apply(&mut rules)?;
    }
    let group_id = ids::new_uuid();
    let mut tx = st.db.begin().await?;
    require_accounts_exist(&mut tx, &others).await?;
    let now = crate::now_millis();
    sqlx::query!(
        "INSERT INTO chat_groups
         (id, revision, metadata, avatar_id, created_by, created_at, only_admins_send, only_admins_edit,
          disappearing_seconds, hide_members, member_names) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &group_id,
        &req.metadata,
        &req.avatar_id,
        &p.account,
        now,
        rules.only_admins_send,
        rules.only_admins_edit,
        rules.disappearing_seconds,
        rules.hide_members,
        &rules.member_names
    )
    .execute(&mut *tx)
    .await?;
    insert_member(&mut tx, &group_id, &p.account, ROLE_ADMIN, now, &p.account).await?;
    for m in &others {
        insert_member(&mut tx, &group_id, m, ROLE_MEMBER, now, &p.account).await?;
    }
    tx.commit().await?;
    let mut recipients = vec![p.account.clone()];
    recipients.extend(others);
    push_group_updated(
        &st,
        &GroupChange {
            group_id: group_id.clone(),
            revision: 1,
            recipients,
        },
    );
    Ok(reply(
        StatusCode::OK,
        json!({"group_id": group_id, "revision": 1}),
    ))
}

pub async fn list_groups(State(st): State<AppState>, p: Principal) -> ApiResult {
    let rows = sqlx::query!(
        "SELECT g.id AS `id: String`, g.revision FROM chat_groups g
         JOIN group_members m ON m.group_id = g.id WHERE m.account_id = ? ORDER BY g.created_at, g.id",
        &p.account
    )
    .fetch_all(&st.db)
    .await?;
    let out: Vec<Value> = rows
        .iter()
        .map(|r| json!({"group_id": r.id, "revision": r.revision}))
        .collect();
    Ok(reply(StatusCode::OK, json!({"groups": out})))
}

pub async fn get_group(
    State(st): State<AppState>,
    p: Principal,
    Path(group_id): Path<String>,
) -> ApiResult {
    let gid = path_uuid("group_id", &group_id)?;
    // Read group and members in one consistent snapshot.
    let mut tx = st.db.begin().await?;
    let g = load_group(&mut tx, &gid, LOAD_GROUP_FOR_SHARE).await?;
    let members = load_members(&mut *tx, &gid).await?;
    let inv = load_invite(&mut *tx, &gid).await?;
    let mut requests = count_join_requests(&mut *tx, &gid).await?;
    tx.commit().await?;
    let me =
        find_member(&members, &p.account).ok_or_else(|| forbidden("not a member of this group"))?;
    let invite = match inv {
        Some(inv) => json!({"approval": inv.approval}),
        None => Value::Null,
    };
    if me.role != ROLE_ADMIN {
        requests = 0; // only admins handle requests
    }
    Ok(reply(
        StatusCode::OK,
        json!({
            "invite": invite,
            "join_requests": requests,
            "group_id": g.id,
            "revision": g.revision,
            "metadata": b64::encode(&g.metadata),
            "avatar_id": g.avatar_id,
            "created_by": g.created_by,
            "created_at": g.created_at,
            "settings": g.settings_json(),
            "members": members,
        }),
    ))
}

/// A group mutation in progress: the group row is locked and the caller is a member (and an
/// admin when required). Finish it with `finish_mutation`.
pub(crate) struct Mutation {
    pub tx: Transaction<'static, MySql>,
    pub g: GroupRow,
    pub members: Vec<GroupMember>,
    pub me: GroupMember,
}

pub(crate) async fn begin_mutation(
    st: &AppState,
    gid: &str,
    p: &Principal,
    admin_only: bool,
) -> Result<Mutation, ApiError> {
    let mut tx = st.db.begin().await?;
    let g = lock_group(&mut tx, gid).await?;
    let members = load_members(&mut *tx, gid).await?;
    let me = find_member(&members, &p.account)
        .cloned()
        .ok_or_else(|| forbidden("not a member of this group"))?;
    if admin_only && me.role != ROLE_ADMIN {
        return Err(forbidden("only admins can do this"));
    }
    Ok(Mutation { tx, g, members, me })
}

/// Commits the mutation; when something changed the revision is bumped and events pushed.
pub(crate) async fn finish_mutation(
    st: &AppState,
    m: Mutation,
    changed: bool,
) -> Result<(), ApiError> {
    let Mutation { mut tx, mut g, .. } = m;
    if !changed {
        tx.commit().await?;
        return Ok(());
    }
    let rev = bump_revision(&mut tx, &mut g).await?;
    let after = load_members(&mut *tx, &g.id).await?;
    tx.commit().await?;
    push_group_updated(
        st,
        &GroupChange {
            group_id: g.id.clone(),
            revision: rev,
            recipients: member_ids(&after),
        },
    );
    Ok(())
}

#[derive(Deserialize)]
struct MetadataRequest {
    #[serde(default, with = "b64")]
    metadata: Vec<u8>,
    #[serde(default)]
    avatar_id: Option<String>,
}

pub async fn put_metadata(
    State(st): State<AppState>,
    p: Principal,
    Path(group_id): Path<String>,
    body: Body,
) -> ApiResult {
    let gid = path_uuid("group_id", &group_id)?;
    let req: MetadataRequest = parse_json(body, MAX_JSON_BODY).await?;
    validate_metadata(&req.metadata)?;
    optional_attachment_id("avatar_id", req.avatar_id.as_deref())?;
    let mut m = begin_mutation(&st, &gid, &p, false).await?;
    if m.g.only_admins_edit && m.me.role != ROLE_ADMIN {
        return Err(forbidden("only admins can edit this group"));
    }
    sqlx::query!(
        "UPDATE chat_groups SET metadata = ?, avatar_id = ? WHERE id = ?",
        &req.metadata,
        &req.avatar_id,
        &gid
    )
    .execute(&mut *m.tx)
        .await?;
    finish_mutation(&st, m, true).await?;
    Ok(no_content())
}

pub async fn put_settings(
    State(st): State<AppState>,
    p: Principal,
    Path(group_id): Path<String>,
    body: Body,
) -> ApiResult {
    let gid = path_uuid("group_id", &group_id)?;
    let req: GroupSettingsPatch = parse_json(body, MAX_JSON_BODY).await?;
    let mut m = begin_mutation(&st, &gid, &p, true).await?;
    req.apply(&mut m.g)?;
    sqlx::query!(
        "UPDATE chat_groups SET only_admins_send = ?, only_admins_edit = ?,
         disappearing_seconds = ?, hide_members = ?, member_names = ? WHERE id = ?",
        m.g.only_admins_send,
        m.g.only_admins_edit,
        m.g.disappearing_seconds,
        m.g.hide_members,
        &m.g.member_names,
        &gid
    )
    .execute(&mut *m.tx)
    .await?;
    finish_mutation(&st, m, true).await?;
    Ok(no_content())
}

#[derive(Deserialize)]
struct AddMembersRequest {
    #[serde(default)]
    account_ids: Option<Vec<String>>,
}

pub async fn add_members(
    State(st): State<AppState>,
    p: Principal,
    Path(group_id): Path<String>,
    body: Body,
) -> ApiResult {
    let gid = path_uuid("group_id", &group_id)?;
    let req: AddMembersRequest = parse_json(body, MAX_JSON_BODY).await?;
    let accounts = parse_account_ids(
        "account_ids",
        req.account_ids.as_deref().unwrap_or_default(),
        st.cfg.max_group_members,
    )?;
    if accounts.is_empty() {
        return Err(bad_request("account_ids must not be empty"));
    }
    let mut m = begin_mutation(&st, &gid, &p, true).await?;
    let add: Vec<String> = accounts
        .into_iter()
        .filter(|a| find_member(&m.members, a).is_none())
        .collect();
    if add.is_empty() {
        finish_mutation(&st, m, false).await?; // all already members
        return Ok(no_content());
    }
    if (m.members.len() + add.len()) as i64 > st.cfg.max_group_members {
        return Err(bad_request("group member limit reached"));
    }
    require_accounts_exist(&mut m.tx, &add).await?;
    let now = crate::now_millis();
    for a in &add {
        insert_member(&mut m.tx, &gid, a, ROLE_MEMBER, now, &p.account).await?;
        // Re-added by an admin: a ban is lifted.
        unban_member(&mut m.tx, &gid, a).await?;
        // Added by an admin: a pending link request is settled.
        sqlx::query!("DELETE FROM group_join_requests WHERE group_id = ? AND account_id = ?", &gid, a)
            .execute(&mut *m.tx)
            .await?;
    }
    finish_mutation(&st, m, true).await?;
    Ok(no_content())
}

pub async fn remove_member(
    State(st): State<AppState>,
    p: Principal,
    Path((group_id, account_id)): Path<(String, String)>,
) -> ApiResult {
    let gid = path_uuid("group_id", &group_id)?;
    let target = path_uuid("account_id", &account_id)?;
    let mut tx = st.db.begin().await?;
    lock_group(&mut tx, &gid).await?;
    let members = load_members(&mut *tx, &gid).await?;
    let me =
        find_member(&members, &p.account).ok_or_else(|| forbidden("not a member of this group"))?;
    if target != p.account {
        if me.role != ROLE_ADMIN {
            return Err(forbidden("only admins can remove other members"));
        }
        if find_member(&members, &target).is_none() {
            return Err(not_found("not a member of this group"));
        }
    }
    let ch = remove_members_tx(&mut tx, &gid, std::slice::from_ref(&target)).await?;
    if target != p.account {
        // Removed by an admin: no coming back by invite link or join request.
        ban_member(&mut tx, &gid, &target, &p.account).await?;
    }
    tx.commit().await?;
    push_group_updated(&st, &ch);
    Ok(no_content())
}

#[derive(Deserialize)]
struct SetRoleRequest {
    #[serde(default)]
    role: String,
}

pub async fn set_role(
    State(st): State<AppState>,
    p: Principal,
    Path((group_id, account_id)): Path<(String, String)>,
    body: Body,
) -> ApiResult {
    let gid = path_uuid("group_id", &group_id)?;
    let target = path_uuid("account_id", &account_id)?;
    let req: SetRoleRequest = parse_json(body, MAX_JSON_BODY).await?;
    if req.role != ROLE_ADMIN && req.role != ROLE_MEMBER {
        return Err(bad_request("role must be admin or member"));
    }
    let mut m = begin_mutation(&st, &gid, &p, true).await?;
    let t =
        find_member(&m.members, &target).ok_or_else(|| not_found("not a member of this group"))?;
    if t.role == req.role {
        finish_mutation(&st, m, false).await?;
        return Ok(no_content());
    }
    if req.role == ROLE_MEMBER {
        let admins = m.members.iter().filter(|x| x.role == ROLE_ADMIN).count();
        if admins <= 1 {
            return Err(conflict("a group must keep at least one admin"));
        }
    }
    sqlx::query!(
        "UPDATE group_members SET role = ? WHERE group_id = ? AND account_id = ?",
        &req.role,
        &gid,
        &target
    )
    .execute(&mut *m.tx)
        .await?;
    finish_mutation(&st, m, true).await?;
    Ok(no_content())
}

#[derive(Serialize)]
struct GroupDevice {
    account_id: String,
    device_id: i64,
    registration_id: i64,
}

/// All devices of all members of a group.
async fn load_group_devices(
    tx: &mut Transaction<'_, MySql>,
    gid: &str,
) -> Result<Vec<GroupDevice>, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT d.account_id AS `account_id: String`, d.device_id AS `device_id: i64`, d.registration_id AS `registration_id: i64` FROM devices d
         JOIN group_members m ON m.account_id = d.account_id
         WHERE m.group_id = ? ORDER BY d.account_id, d.device_id",
        gid
    )
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| GroupDevice {
            account_id: r.account_id,
            device_id: r.device_id,
            registration_id: r.registration_id,
        })
        .collect())
}

pub async fn group_devices(
    State(st): State<AppState>,
    p: Principal,
    Path(group_id): Path<String>,
) -> ApiResult {
    let gid = &path_uuid("group_id", &group_id)?;
    let mut tx = st.db.begin().await?;
    load_group(&mut tx, gid, LOAD_GROUP_FOR_SHARE).await?;
    let members = load_members(&mut *tx, gid).await?;
    if find_member(&members, &p.account).is_none() {
        return Err(forbidden("not a member of this group"));
    }
    let devices = load_group_devices(&mut tx, gid).await?;
    tx.commit().await?;
    Ok(reply(StatusCode::OK, json!({"devices": devices})))
}

#[derive(Deserialize)]
struct GroupRecipient {
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    device_id: i64,
    #[serde(default)]
    registration_id: i64,
}

#[derive(Deserialize)]
struct GroupSendRequest {
    #[serde(default)]
    timestamp: i64,
    #[serde(default)]
    online: bool,
    #[serde(default, with = "b64")]
    content: Vec<u8>,
    #[serde(default)]
    recipients: Option<Vec<GroupRecipient>>,
}

type RecipientRef = (String, i64);

fn refs_json(refs: &[&RecipientRef]) -> Value {
    Value::Array(
        refs.iter()
            .map(|(a, d)| json!({"account_id": a, "device_id": d}))
            .collect(),
    )
}

enum SendError {
    Api(ApiError),
    Db(sqlx::Error),
}

impl From<ApiError> for SendError {
    fn from(e: ApiError) -> Self {
        SendError::Api(e)
    }
}

impl From<sqlx::Error> for SendError {
    fn from(e: sqlx::Error) -> Self {
        SendError::Db(e)
    }
}

pub async fn group_send(
    State(st): State<AppState>,
    p: Principal,
    Path(group_id): Path<String>,
    body: Body,
) -> ApiResult {
    let gid = path_uuid("group_id", &group_id)?;
    let req: GroupSendRequest = parse_json(body, MAX_JSON_BODY).await?;
    validate_timestamp(req.timestamp)?;
    validate_content(&req.content)?;
    let recipients = req.recipients.unwrap_or_default();
    if recipients.len() as i64 > st.cfg.max_group_members * MAX_DEVICE_ID {
        return Err(bad_request("too many recipients"));
    }
    // Keyed (and thus sorted) by (account, device).
    let mut given: BTreeMap<RecipientRef, i64> = BTreeMap::new();
    for rc in recipients {
        let id = ids::normalize_uuid(&rc.account_id)
            .ok_or_else(|| bad_request("recipients[].account_id must be a UUID"))?;
        if rc.device_id < 1 || rc.device_id > MAX_DEVICE_ID {
            return Err(bad_request("recipients[].device_id must be in 1..127"));
        }
        let key = (id, rc.device_id);
        if given.contains_key(&key) {
            return Err(bad_request("duplicate recipient"));
        }
        given.insert(key, rc.registration_id);
    }

    let server_ts = crate::now_millis();
    let mut attempt = 0;
    let envs = loop {
        match send_tx(
            &st,
            &p,
            &gid,
            &req.content,
            req.timestamp,
            req.online,
            server_ts,
            &given,
        )
        .await
        {
            Ok(envs) => break envs,
            // A device removed concurrently makes the insert fail its foreign key; re-validate.
            Err(SendError::Db(e)) if is_foreign_key_violation(&e) && attempt < 2 => attempt += 1,
            Err(SendError::Db(e)) => return Err(e.into()),
            Err(SendError::Api(e)) => return Err(e),
        }
    };
    deliver(&st, &envs, req.online);
    Ok(reply(
        StatusCode::OK,
        json!({"server_timestamp": server_ts}),
    ))
}

#[allow(clippy::too_many_arguments)]
async fn send_tx(
    st: &AppState,
    p: &Principal,
    gid: &str,
    content: &[u8],
    timestamp: i64,
    online: bool,
    server_ts: i64,
    given: &BTreeMap<RecipientRef, i64>,
) -> Result<Vec<Envelope>, SendError> {
    let mut tx = st.db.begin().await?;
    let g = load_group(&mut tx, gid, LOAD_GROUP_FOR_SHARE).await?;
    let members = load_members(&mut *tx, gid).await?;
    let me =
        find_member(&members, &p.account).ok_or_else(|| forbidden("not a member of this group"))?;
    if g.only_admins_send && me.role != ROLE_ADMIN {
        return Err(forbidden("only admins can send to this group").into());
    }
    let devices = load_group_devices(&mut tx, gid).await?;
    let current: BTreeMap<RecipientRef, i64> = devices
        .into_iter()
        .filter(|d| !(d.account_id == p.account && d.device_id == p.device))
        .map(|d| ((d.account_id, d.device_id), d.registration_id))
        .collect();
    let missing: Vec<&RecipientRef> = current.keys().filter(|k| !given.contains_key(*k)).collect();
    let extra: Vec<&RecipientRef> = given.keys().filter(|k| !current.contains_key(*k)).collect();
    if !missing.is_empty() || !extra.is_empty() {
        return Err(conflict("recipient list mismatch")
            .with("missing", refs_json(&missing))
            .with("extra", refs_json(&extra))
            .into());
    }
    // registration_id 0 (omitted) skips the check.
    let stale: Vec<&RecipientRef> = given
        .iter()
        .filter(|(k, reg)| **reg != 0 && **reg != current[*k])
        .map(|(k, _)| k)
        .collect();
    if !stale.is_empty() {
        return Err(gone("stale registration ids")
            .with("stale", refs_json(&stale))
            .into());
    }
    let envs: Vec<Envelope> = given
        .keys()
        .map(|(account, device)| Envelope {
            id: ids::new_uuid(),
            kind: ENVELOPE_SENDER_KEY,
            source_account: p.account.clone(),
            source_device: p.device,
            destination_device: *device,
            group_id: Some(gid.to_string()),
            timestamp,
            server_timestamp: server_ts,
            content: content.to_vec(),
            dest_account: account.clone(),
        })
        .collect();
    if !online {
        insert_envelopes(&mut tx, &envs).await?;
    }
    tx.commit().await?;
    Ok(envs)
}
