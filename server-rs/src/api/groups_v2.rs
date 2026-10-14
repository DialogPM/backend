//! Private groups (zkgroup, docs/ZKGROUP-DESIGN.md stage 2, API section "Groups v2").
//!
//! The server stores, per group, only:
//! * the group's public parameters (the group is identified by their GroupIdentifier);
//! * members and pending members as `UuidCiphertext`s (account ids encrypted with the group's
//!   secret parameters, which only members hold) with a role and a revision;
//! * the attributes (title, description, avatar) and settings (timer, rules) as blobs encrypted
//!   by the clients; who may change them / add members (plaintext access levels);
//! * a change log, each change signed with the server's zkgroup notary key.
//!
//! Group requests are anonymous: no account token, only a `Group-Auth` header carrying the
//! group's public parameters and a zkgroup auth credential presentation for them. Verifying it
//! tells the server the caller's ciphertext in this group and nothing else; the role checks run
//! on ciphertexts. The server therefore never learns which account is in which group (except
//! through message routing: group sends still name their recipients, until stage 4).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::OnceLock;

use axum::body::Body;
use axum::extract::{ConnectInfo, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{MySql, Transaction};
use zkgroup::auth::AnyAuthCredentialPresentation;
use zkgroup::groups::{GroupPublicParams, UuidCiphertext};
use zkgroup::Timestamp;

use super::messages::{deliver, insert_envelopes, validate_content, validate_timestamp, Envelope, ENVELOPE_SENDER_KEY};
use super::{query_int, reply};
use crate::auth::Principal;
use crate::db::{is_duplicate_key, is_foreign_key_violation, placeholders, RowExt};
use crate::error::{bad_request, conflict, forbidden, gone, not_found, too_large, unauthorized, ApiError, ApiResult};
use crate::ids;
use crate::state::AppState;
use crate::validate::{b64, parse_json, MAX_DEVICE_ID, MAX_JSON_BODY};
use crate::zk::ZkParams;

/// Header of anonymous group requests: `<base64 GroupPublicParams>:<base64 presentation>`.
pub const AUTH_HEADER: &str = "group-auth";
/// Encrypted attributes / settings blob limit.
pub const MAX_BLOB: usize = 64 << 10;
const MAX_CHANGES_PAGE: i64 = 100;
const UID_CIPHERTEXT_LEN: usize = 65;

/// Whether new groups should be created as v2 by clients (CHATAPP_GROUPS_V2_DEFAULT). Off by
/// default until invite links work for v2 groups (stage 5); the v2 API itself is always on.
pub fn default_on() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var("CHATAPP_GROUPS_V2_DEFAULT").is_ok_and(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
    })
}

// ---------------------------------------------------------------------------
// Model and authorization (pure, unit tested)
// ---------------------------------------------------------------------------

/// A member's role, and an access level ("who may": any member / only admins).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Member,
    Admin,
}

impl Role {
    fn code(self) -> i64 {
        match self {
            Role::Member => 1,
            Role::Admin => 2,
        }
    }
    fn from_code(c: i64) -> Role {
        if c == 2 {
            Role::Admin
        } else {
            Role::Member
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Member {
    pub uid: Vec<u8>,
    pub role: Role,
    pub joined_revision: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Pending {
    pub uid: Vec<u8>,
    pub role: Role,
    pub added_by: Vec<u8>,
    pub added_revision: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GroupState {
    pub revision: i64,
    pub attributes: Vec<u8>,
    pub settings: Vec<u8>,
    pub edit_access: Role,
    pub members_access: Role,
    pub members: Vec<Member>,
    pub pending: Vec<Pending>,
}

impl GroupState {
    fn member(&self, uid: &[u8]) -> Option<usize> {
        self.members.iter().position(|m| m.uid == uid)
    }
    fn pending_of(&self, uid: &[u8]) -> Option<usize> {
        self.pending.iter().position(|m| m.uid == uid)
    }
}

/// One change to a group. Uids are UuidCiphertexts; blobs are encrypted by the clients.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    AddMember {
        #[serde(with = "b64")]
        uid: Vec<u8>,
        role: Role,
    },
    RemoveMember {
        #[serde(with = "b64")]
        uid: Vec<u8>,
    },
    ModifyRole {
        #[serde(with = "b64")]
        uid: Vec<u8>,
        role: Role,
    },
    /// Invites a member who accepts (AcceptPending) or declines (RemovePending of itself).
    AddPending {
        #[serde(with = "b64")]
        uid: Vec<u8>,
        role: Role,
    },
    RemovePending {
        #[serde(with = "b64")]
        uid: Vec<u8>,
    },
    AcceptPending,
    ModifyAttributes {
        #[serde(with = "b64")]
        blob: Vec<u8>,
    },
    ModifySettings {
        #[serde(with = "b64")]
        blob: Vec<u8>,
    },
    ModifyAccess {
        attributes: Role,
        members: Role,
    },
}

/// A change as stored in the log and signed by the server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Change {
    pub revision: i64,
    /// Ciphertext of the member who made the change.
    #[serde(with = "b64")]
    pub source: Vec<u8>,
    pub actions: Vec<Action>,
    /// Consequences applied by the server (an admin promoted when the last one left).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub server_actions: Vec<Action>,
}

fn valid_uid(uid: &[u8]) -> Result<(), ApiError> {
    if uid.len() != UID_CIPHERTEXT_LEN || zkgroup::deserialize::<UuidCiphertext>(uid).is_err() {
        return Err(bad_request("invalid member ciphertext"));
    }
    Ok(())
}

fn valid_blob(field: &str, b: &[u8]) -> Result<(), ApiError> {
    if b.is_empty() {
        return Err(bad_request(format!("{field} is required")));
    }
    if b.len() > MAX_BLOB {
        return Err(too_large(format!("{field} exceeds 64 KiB")));
    }
    Ok(())
}

fn not_a_member() -> ApiError {
    forbidden("not a member of this group")
}

/// Applies `actions` by `caller` (its ciphertext) to `state`, checking every permission.
/// Returns the actions the server added (promotion of a new admin). The revision is bumped.
pub fn apply(state: &mut GroupState, caller: &[u8], actions: &[Action], max_members: i64) -> Result<Vec<Action>, ApiError> {
    if actions.is_empty() {
        return Err(bad_request("no actions"));
    }
    if actions.len() as i64 > 2 * max_members + 8 {
        return Err(bad_request("too many actions"));
    }
    let caller_role = state.member(caller).map(|i| state.members[i].role);
    let caller_pending = state.pending_of(caller).is_some();
    let leaving = actions.iter().any(|a| matches!(a, Action::RemoveMember { uid } if uid == caller));
    let accepting = actions.iter().any(|a| matches!(a, Action::AcceptPending));
    let declining = actions.iter().any(|a| matches!(a, Action::RemovePending { uid } if uid == caller));
    if (leaving || accepting || declining) && actions.len() != 1 {
        return Err(bad_request("leaving, accepting or declining must be the only action"));
    }
    match caller_role {
        Some(_) => {}
        None if caller_pending && (accepting || declining) => {}
        None => return Err(not_a_member()),
    }
    let is_admin = caller_role == Some(Role::Admin);
    let new_revision = state.revision + 1;
    for a in actions {
        match a {
            Action::AddMember { uid, role } | Action::AddPending { uid, role } => {
                valid_uid(uid)?;
                let may = is_admin || (state.members_access == Role::Member && *role == Role::Member);
                if !may {
                    return Err(forbidden("only admins can add members"));
                }
                if state.member(uid).is_some() || state.pending_of(uid).is_some() {
                    return Err(bad_request("already a member"));
                }
                if matches!(a, Action::AddMember { .. }) {
                    state.members.push(Member { uid: uid.clone(), role: *role, joined_revision: new_revision });
                } else {
                    state.pending.push(Pending {
                        uid: uid.clone(),
                        role: *role,
                        added_by: caller.to_vec(),
                        added_revision: new_revision,
                    });
                }
                if (state.members.len() + state.pending.len()) as i64 > max_members {
                    return Err(bad_request("too many members"));
                }
            }
            Action::RemoveMember { uid } => {
                if uid != caller && !is_admin {
                    return Err(forbidden("only admins can remove members"));
                }
                let i = state.member(uid).ok_or_else(|| not_found("not a member"))?;
                state.members.remove(i);
            }
            Action::ModifyRole { uid, role } => {
                if !is_admin {
                    return Err(forbidden("only admins can change roles"));
                }
                let i = state.member(uid).ok_or_else(|| not_found("not a member"))?;
                state.members[i].role = *role;
            }
            Action::RemovePending { uid } => {
                if uid != caller && !is_admin {
                    return Err(forbidden("only admins can revoke invitations"));
                }
                let i = state.pending_of(uid).ok_or_else(|| not_found("no such invitation"))?;
                state.pending.remove(i);
            }
            Action::AcceptPending => {
                let i = state.pending_of(caller).ok_or_else(|| forbidden("no pending invitation"))?;
                let p = state.pending.remove(i);
                state.members.push(Member { uid: p.uid, role: p.role, joined_revision: new_revision });
            }
            Action::ModifyAttributes { blob } => {
                if state.edit_access == Role::Admin && !is_admin {
                    return Err(forbidden("only admins can edit this group"));
                }
                valid_blob("attributes", blob)?;
                state.attributes = blob.clone();
            }
            Action::ModifySettings { blob } => {
                if !is_admin {
                    return Err(forbidden("only admins can change the group settings"));
                }
                valid_blob("settings", blob)?;
                state.settings = blob.clone();
            }
            Action::ModifyAccess { attributes, members } => {
                if !is_admin {
                    return Err(forbidden("only admins can change the group settings"));
                }
                state.edit_access = *attributes;
                state.members_access = *members;
            }
        }
    }
    let mut server_actions = Vec::new();
    // Like v1: when no admin is left, the longest-standing member becomes one.
    if !state.members.is_empty() && !state.members.iter().any(|m| m.role == Role::Admin) {
        let next = state
            .members
            .iter_mut()
            .min_by(|a, b| (a.joined_revision, &a.uid).cmp(&(b.joined_revision, &b.uid)))
            .expect("not empty");
        next.role = Role::Admin;
        server_actions.push(Action::ModifyRole { uid: next.uid.clone(), role: Role::Admin });
    }
    state.revision = new_revision;
    Ok(server_actions)
}

/// A verified `Group-Auth` header.
#[derive(Debug, Clone)]
pub struct GroupAuth {
    /// GroupIdentifier.
    pub id: Vec<u8>,
    pub public_params: Vec<u8>,
    /// The caller's UuidCiphertext in this group.
    pub uid: Vec<u8>,
}

/// Verifies a `Group-Auth` header value against the server's parameters at `now` (seconds).
pub fn verify_auth(zk: &ZkParams, value: &str, now: u64) -> Result<GroupAuth, ApiError> {
    let invalid = || unauthorized("invalid group credential");
    let (pp, pres) = value.trim().split_once(':').ok_or_else(invalid)?;
    let pp = b64::decode(pp).ok_or_else(invalid)?;
    let pres = b64::decode(pres).ok_or_else(invalid)?;
    let params: GroupPublicParams = zkgroup::deserialize(&pp).map_err(|_| invalid())?;
    let p = AnyAuthCredentialPresentation::new(&pres).map_err(|_| invalid())?;
    let id = params.get_group_identifier().to_vec();
    zk.secret
        .verify_auth_credential_presentation(params, &p, Timestamp::from_epoch_seconds(now))
        .map_err(|_| invalid())?;
    Ok(GroupAuth { id, public_params: pp, uid: zkgroup::serialize(&p.get_aci_ciphertext()) })
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

fn group_auth(st: &AppState, headers: &HeaderMap, peer: SocketAddr) -> Result<GroupAuth, ApiError> {
    // Anonymous requests: limited per address (like sealed sender deliveries).
    st.rate_limit(&format!("groupsv2:ip:{}", st.client_ip(headers, peer)), st.limits.sealed_ip)?;
    let value = headers
        .get(AUTH_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| unauthorized("missing group credential"))?;
    verify_auth(&st.zk, value, crate::now_millis() as u64 / 1000)
}

async fn load_state(tx: &mut Transaction<'_, MySql>, auth: &GroupAuth, lock: bool) -> Result<GroupState, ApiError> {
    let sql = if lock {
        "SELECT public_params, revision, attributes, settings, edit_access, members_access FROM groups_v2 WHERE id = ? FOR UPDATE"
    } else {
        "SELECT public_params, revision, attributes, settings, edit_access, members_access FROM groups_v2 WHERE id = ? FOR SHARE"
    };
    let row = sqlx::query(sql)
        .bind(&auth.id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| not_found("unknown group"))?;
    // The identifier is derived from the parameters; this only guards against a corrupt row.
    if row.bytes("public_params") != auth.public_params {
        return Err(unauthorized("invalid group credential"));
    }
    let members = sqlx::query!("SELECT uid_ciphertext, role AS `role: i64`, joined_revision FROM group_members_v2 WHERE group_id = ? ORDER BY joined_revision, uid_ciphertext", &auth.id)
        .fetch_all(&mut **tx)
        .await?
        .into_iter()
        .map(|r| Member { uid: r.uid_ciphertext, role: Role::from_code(r.role), joined_revision: r.joined_revision })
        .collect();
    let pending = sqlx::query!("SELECT uid_ciphertext, role AS `role: i64`, added_by, added_revision FROM group_pending_v2 WHERE group_id = ? ORDER BY added_revision, uid_ciphertext", &auth.id)
        .fetch_all(&mut **tx)
        .await?
        .into_iter()
        .map(|r| Pending {
            uid: r.uid_ciphertext,
            role: Role::from_code(r.role),
            added_by: r.added_by,
            added_revision: r.added_revision,
        })
        .collect();
    Ok(GroupState {
        revision: row.i64("revision"),
        attributes: row.bytes("attributes"),
        settings: row.bytes("settings"),
        edit_access: Role::from_code(row.i64("edit_access")),
        members_access: Role::from_code(row.i64("members_access")),
        members,
        pending,
    })
}

/// Writes the difference between `old` and `new` (group row locked).
async fn store_state(tx: &mut Transaction<'_, MySql>, id: &[u8], old: &GroupState, new: &GroupState) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE groups_v2 SET revision = ?, attributes = ?, settings = ?, edit_access = ?, members_access = ?, updated_at = ? WHERE id = ?",
        new.revision,
        &new.attributes,
        &new.settings,
        new.edit_access.code(),
        new.members_access.code(),
        crate::now_millis(),
        id
    )
    .execute(&mut **tx)
    .await?;
    let old_m: HashMap<&[u8], &Member> = old.members.iter().map(|m| (m.uid.as_slice(), m)).collect();
    let new_m: HashMap<&[u8], &Member> = new.members.iter().map(|m| (m.uid.as_slice(), m)).collect();
    for uid in old_m.keys().filter(|u| !new_m.contains_key(*u)) {
        sqlx::query!("DELETE FROM group_members_v2 WHERE group_id = ? AND uid_ciphertext = ?", id, *uid).execute(&mut **tx).await?;
    }
    for m in new.members.iter().filter(|m| old_m.get(m.uid.as_slice()) != Some(m)) {
        sqlx::query!(
            "INSERT INTO group_members_v2 (group_id, uid_ciphertext, role, joined_revision) VALUES (?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE role = VALUES(role), joined_revision = VALUES(joined_revision)",
            id,
            &m.uid,
            m.role.code(),
            m.joined_revision
        )
        .execute(&mut **tx)
        .await?;
    }
    let old_p: HashMap<&[u8], &Pending> = old.pending.iter().map(|m| (m.uid.as_slice(), m)).collect();
    let new_p: HashMap<&[u8], &Pending> = new.pending.iter().map(|m| (m.uid.as_slice(), m)).collect();
    for uid in old_p.keys().filter(|u| !new_p.contains_key(*u)) {
        sqlx::query!("DELETE FROM group_pending_v2 WHERE group_id = ? AND uid_ciphertext = ?", id, *uid).execute(&mut **tx).await?;
    }
    for p in new.pending.iter().filter(|p| old_p.get(p.uid.as_slice()) != Some(p)) {
        sqlx::query!(
            "INSERT INTO group_pending_v2 (group_id, uid_ciphertext, role, added_by, added_revision) VALUES (?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE role = VALUES(role), added_by = VALUES(added_by), added_revision = VALUES(added_revision)",
            id,
            &p.uid,
            p.role.code(),
            &p.added_by,
            p.added_revision
        )
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Appends a signed change to the log; returns (change bytes, signature).
async fn log_change(st: &AppState, tx: &mut Transaction<'_, MySql>, id: &[u8], change: &Change) -> Result<(Vec<u8>, [u8; 64]), ApiError> {
    let bytes = serde_json::to_vec(change).map_err(|e| crate::error::internal_from("change", e))?;
    let sig = st.zk.sign_group_change(id, &bytes);
    sqlx::query!(
        "INSERT INTO group_changes_v2 (group_id, revision, `change`, signature, created_at) VALUES (?, ?, ?, ?, ?)",
        id,
        change.revision,
        &bytes,
        &sig[..],
        crate::now_millis()
    )
    .execute(&mut **tx)
        .await?;
    Ok((bytes, sig))
}

fn state_json(s: &GroupState) -> Value {
    json!({
        "revision": s.revision,
        "attributes": b64::encode(&s.attributes),
        "settings": b64::encode(&s.settings),
        "access": { "attributes": s.edit_access, "members": s.members_access },
        "members": s.members.iter().map(|m| json!({
            "uid": b64::encode(&m.uid), "role": m.role, "joined_revision": m.joined_revision,
        })).collect::<Vec<_>>(),
        "pending": s.pending.iter().map(|p| json!({
            "uid": b64::encode(&p.uid), "role": p.role, "added_by": b64::encode(&p.added_by), "added_revision": p.added_revision,
        })).collect::<Vec<_>>(),
    })
}

// ---------------------------------------------------------------------------
// Handlers: group state (anonymous, Group-Auth)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct MemberIn {
    #[serde(with = "b64")]
    uid: Vec<u8>,
    role: Role,
}

fn default_member() -> Role {
    Role::Member
}

fn default_admin() -> Role {
    Role::Admin
}

#[derive(Deserialize)]
struct CreateRequest {
    #[serde(default, with = "b64")]
    attributes: Vec<u8>,
    #[serde(default, with = "b64")]
    settings: Vec<u8>,
    #[serde(default = "default_member")]
    attributes_access: Role,
    /// Who may add members: only admins unless the creator says otherwise.
    #[serde(default = "default_admin")]
    members_access: Role,
    members: Vec<MemberIn>,
    #[serde(default)]
    pending: Vec<MemberIn>,
}

/// POST /v2/groups: creates the group whose parameters are in Group-Auth. The caller must list
/// itself as an admin.
pub async fn create(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult {
    let auth = group_auth(&st, &headers, peer)?;
    let req: CreateRequest = parse_json(body, MAX_JSON_BODY).await?;
    valid_blob("attributes", &req.attributes)?;
    valid_blob("settings", &req.settings)?;
    if (req.members.len() + req.pending.len()) as i64 > st.cfg.max_group_members {
        return Err(bad_request("too many members"));
    }
    let mut seen = HashSet::new();
    for m in req.members.iter().chain(req.pending.iter()) {
        valid_uid(&m.uid)?;
        if !seen.insert(m.uid.clone()) {
            return Err(bad_request("duplicate member"));
        }
    }
    if !req.members.iter().any(|m| m.uid == auth.uid && m.role == Role::Admin) {
        return Err(forbidden("the creator must be an admin of the group"));
    }
    let state = GroupState {
        revision: 1,
        attributes: req.attributes.clone(),
        settings: req.settings.clone(),
        edit_access: req.attributes_access,
        members_access: req.members_access,
        members: req.members.iter().map(|m| Member { uid: m.uid.clone(), role: m.role, joined_revision: 1 }).collect(),
        pending: req
            .pending
            .iter()
            .map(|m| Pending { uid: m.uid.clone(), role: m.role, added_by: auth.uid.clone(), added_revision: 1 })
            .collect(),
    };
    let mut actions: Vec<Action> = vec![
        Action::ModifyAttributes { blob: req.attributes },
        Action::ModifySettings { blob: req.settings },
        Action::ModifyAccess { attributes: req.attributes_access, members: req.members_access },
    ];
    actions.extend(req.members.iter().map(|m| Action::AddMember { uid: m.uid.clone(), role: m.role }));
    actions.extend(req.pending.iter().map(|m| Action::AddPending { uid: m.uid.clone(), role: m.role }));
    let change = Change { revision: 1, source: auth.uid.clone(), actions, server_actions: vec![] };

    let now = crate::now_millis();
    let mut tx = st.db.begin().await?;
    let inserted = sqlx::query!(
        "INSERT INTO groups_v2 (id, public_params, revision, attributes, settings, edit_access, members_access, created_at, updated_at)
         VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?)",
        &auth.id,
        &auth.public_params,
        &state.attributes,
        &state.settings,
        state.edit_access.code(),
        state.members_access.code(),
        now,
        now
    )
    .execute(&mut *tx)
    .await;
    match inserted {
        Err(e) if is_duplicate_key(&e) => return Err(conflict("group already exists")),
        r => r?,
    };
    let empty = GroupState { members: vec![], pending: vec![], ..state.clone() };
    store_state(&mut tx, &auth.id, &empty, &state).await?;
    let (bytes, sig) = log_change(&st, &mut tx, &auth.id, &change).await?;
    tx.commit().await?;
    Ok(reply(
        StatusCode::OK,
        json!({ "revision": 1, "change": b64::encode(&bytes), "signature": b64::encode(&sig) }),
    ))
}

/// GET /v2/groups: the group's current state (members and pending members only).
pub async fn get_state(State(st): State<AppState>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap) -> ApiResult {
    let auth = group_auth(&st, &headers, peer)?;
    let mut tx = st.db.begin().await?;
    let state = load_state(&mut tx, &auth, false).await?;
    tx.commit().await?;
    if state.member(&auth.uid).is_none() && state.pending_of(&auth.uid).is_none() {
        return Err(not_a_member());
    }
    Ok(reply(StatusCode::OK, state_json(&state)))
}

/// GET /v2/groups/changes?since=N: signed changes after revision N (from the caller's join on).
pub async fn changes(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(q): RawQuery,
) -> ApiResult {
    let auth = group_auth(&st, &headers, peer)?;
    let since = query_int(q.as_deref(), "since", 0, 0, i64::MAX)?;
    let mut tx = st.db.begin().await?;
    let state = load_state(&mut tx, &auth, false).await?;
    let from = match (state.member(&auth.uid), state.pending_of(&auth.uid)) {
        (Some(i), _) => state.members[i].joined_revision,
        (None, Some(i)) => state.pending[i].added_revision,
        (None, None) => return Err(not_a_member()),
    };
    let rows = sqlx::query!(
        "SELECT revision, `change`, signature FROM group_changes_v2 WHERE group_id = ? AND revision > ? AND revision >= ?
         ORDER BY revision LIMIT ?",
        &auth.id,
        since,
        from,
        MAX_CHANGES_PAGE
    )
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let list: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "revision": r.revision,
                "change": b64::encode(&r.change),
                "signature": b64::encode(&r.signature),
            })
        })
        .collect();
    let more = list.len() as i64 == MAX_CHANGES_PAGE;
    Ok(reply(StatusCode::OK, json!({ "revision": state.revision, "changes": list, "more": more })))
}

#[derive(Deserialize)]
struct ModifyRequest {
    /// Must be the current revision + 1.
    revision: i64,
    actions: Vec<Action>,
}

/// PATCH /v2/groups: applies actions as the caller. 409 (with the current revision) when the
/// group changed in between.
pub async fn modify(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult {
    let auth = group_auth(&st, &headers, peer)?;
    let req: ModifyRequest = parse_json(body, MAX_JSON_BODY).await?;
    let mut tx = st.db.begin().await?;
    let old = load_state(&mut tx, &auth, true).await?;
    if old.member(&auth.uid).is_none() && old.pending_of(&auth.uid).is_none() {
        return Err(not_a_member());
    }
    if req.revision != old.revision + 1 {
        return Err(conflict("revision mismatch").with("revision", old.revision));
    }
    let mut new = old.clone();
    let server_actions = apply(&mut new, &auth.uid, &req.actions, st.cfg.max_group_members)?;
    let change = Change { revision: new.revision, source: auth.uid.clone(), actions: req.actions, server_actions };
    if new.members.is_empty() {
        // The last member left: the group is gone (with its log).
        sqlx::query!("DELETE FROM groups_v2 WHERE id = ?", &auth.id).execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok(reply(StatusCode::OK, json!({ "revision": new.revision, "deleted": true })));
    }
    store_state(&mut tx, &auth.id, &old, &new).await?;
    let (bytes, sig) = log_change(&st, &mut tx, &auth.id, &change).await?;
    tx.commit().await?;
    Ok(reply(
        StatusCode::OK,
        json!({ "revision": new.revision, "change": b64::encode(&bytes), "signature": b64::encode(&sig) }),
    ))
}

// ---------------------------------------------------------------------------
// Handlers: group sends (authenticated; the server learns sender and recipients, not the group)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DevicesRequest {
    accounts: Vec<String>,
}

#[derive(Serialize)]
struct DeviceOut {
    account_id: String,
    device_id: i64,
    registration_id: i64,
}

fn parse_accounts(raw: &[String], max: i64) -> Result<Vec<String>, ApiError> {
    if raw.len() as i64 > max {
        return Err(bad_request("too many accounts"));
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for a in raw {
        let id = ids::normalize_uuid(a).ok_or_else(|| bad_request("accounts must contain account UUIDs"))?;
        if seen.insert(id.clone()) {
            out.push(id);
        }
    }
    Ok(out)
}

async fn devices_of<'e, E>(db: E, accounts: &[String]) -> Result<BTreeMap<(String, i64), i64>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = MySql>,
{
    if accounts.is_empty() {
        return Ok(BTreeMap::new());
    }
    let sql = format!(
        "SELECT d.account_id, d.device_id, d.registration_id FROM devices d JOIN accounts a ON a.id = d.account_id
         WHERE d.account_id IN ({}) AND a.banned_at IS NULL",
        placeholders(accounts.len())
    );
    let mut q = sqlx::query(&sql);
    for a in accounts {
        q = q.bind(a);
    }
    Ok(q.fetch_all(db)
        .await?
        .iter()
        .map(|r| ((r.string("account_id"), r.i64("device_id")), r.i64("registration_id")))
        .collect())
}

/// POST /v2/groups/devices: the devices of the given accounts (the members a client decrypted).
pub async fn devices(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    let req: DevicesRequest = parse_json(body, MAX_JSON_BODY).await?;
    let accounts = parse_accounts(&req.accounts, st.cfg.max_group_members)?;
    let devs = devices_of(&st.db, &accounts).await?;
    let list: Vec<DeviceOut> = devs
        .into_iter()
        .filter(|((a, d), _)| !(*a == p.account && *d == p.device))
        .map(|((account_id, device_id), registration_id)| DeviceOut { account_id, device_id, registration_id })
        .collect();
    Ok(reply(StatusCode::OK, json!({ "devices": list })))
}

#[derive(Deserialize)]
struct Recipient {
    account_id: String,
    device_id: i64,
    #[serde(default)]
    registration_id: i64,
}

#[derive(Deserialize)]
struct SendRequest {
    /// The clients' local id of the group (derived from the master key; the server cannot link
    /// it to the group's identifier).
    group_id: String,
    timestamp: i64,
    #[serde(default)]
    online: bool,
    #[serde(with = "b64")]
    content: Vec<u8>,
    recipients: Vec<Recipient>,
}

fn refs_json(refs: &[&(String, i64)]) -> Value {
    Value::Array(refs.iter().map(|(a, d)| json!({ "account_id": a, "device_id": d })).collect())
}

/// PUT /v2/groups/messages: one sender key ciphertext to the devices of the given accounts.
/// Every device of each named account must be listed (409 missing/extra, 410 stale), like
/// PUT /v1/groups/{id}/messages but for the recipient list the client decrypted.
pub async fn send(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    let req: SendRequest = parse_json(body, MAX_JSON_BODY).await?;
    validate_timestamp(req.timestamp)?;
    validate_content(&req.content)?;
    let tag = ids::normalize_uuid(&req.group_id).ok_or_else(|| bad_request("group_id must be a UUID"))?;
    if req.recipients.len() as i64 > st.cfg.max_group_members * MAX_DEVICE_ID {
        return Err(bad_request("too many recipients"));
    }
    let mut given: BTreeMap<(String, i64), i64> = BTreeMap::new();
    for rc in &req.recipients {
        let id = ids::normalize_uuid(&rc.account_id).ok_or_else(|| bad_request("recipients[].account_id must be a UUID"))?;
        if rc.device_id < 1 || rc.device_id > MAX_DEVICE_ID {
            return Err(bad_request("recipients[].device_id must be in 1..127"));
        }
        if given.insert((id, rc.device_id), rc.registration_id).is_some() {
            return Err(bad_request("duplicate recipient"));
        }
    }
    let accounts: Vec<String> = given.keys().map(|(a, _)| a.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    if accounts.len() as i64 > st.cfg.max_group_members {
        return Err(bad_request("too many recipients"));
    }
    let server_ts = crate::now_millis();
    let mut attempt = 0;
    let envs = loop {
        let mut tx = st.db.begin().await?;
        let current: BTreeMap<(String, i64), i64> = devices_of(&mut *tx, &accounts)
            .await?
            .into_iter()
            .filter(|((a, d), _)| !(*a == p.account && *d == p.device))
            .collect();
        let missing: Vec<&(String, i64)> = current.keys().filter(|k| !given.contains_key(*k)).collect();
        let extra: Vec<&(String, i64)> = given.keys().filter(|k| !current.contains_key(*k)).collect();
        if !missing.is_empty() || !extra.is_empty() {
            return Err(conflict("recipient list mismatch").with("missing", refs_json(&missing)).with("extra", refs_json(&extra)));
        }
        let stale: Vec<&(String, i64)> = given.iter().filter(|(k, reg)| **reg != 0 && **reg != current[*k]).map(|(k, _)| k).collect();
        if !stale.is_empty() {
            return Err(gone("stale registration ids").with("stale", refs_json(&stale)));
        }
        let envs: Vec<Envelope> = given
            .keys()
            .map(|(account, device)| Envelope {
                id: ids::new_uuid(),
                kind: ENVELOPE_SENDER_KEY,
                source_account: p.account.clone(),
                source_device: p.device,
                destination_device: *device,
                group_id: Some(tag.clone()),
                timestamp: req.timestamp,
                server_timestamp: server_ts,
                content: req.content.clone(),
                dest_account: account.clone(),
            })
            .collect();
        if !req.online {
            match insert_envelopes(&mut tx, &envs).await {
                // A device removed concurrently fails the foreign key: re-validate.
                Err(e) if is_foreign_key_violation(&e) && attempt < 2 => {
                    attempt += 1;
                    continue;
                }
                r => r?,
            }
        }
        tx.commit().await?;
        break envs;
    };
    deliver(&st, &envs, req.online);
    Ok(reply(StatusCode::OK, json!({ "server_timestamp": server_ts })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkgroup::auth::AuthCredentialWithPniZkcResponse;
    use zkgroup::groups::GroupSecretParams;
    use zkgroup::{ServerPublicParams, SECONDS_PER_DAY};

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn rnd() -> [u8; 32] {
        use rand::RngCore;
        let mut r = [0u8; 32];
        rand::rng().fill_bytes(&mut r);
        r
    }

    fn now() -> u64 {
        crate::now_millis() as u64 / 1000
    }

    /// A Group-Auth header value for `account` in `group`, built like the client does.
    fn header(zk: &ZkParams, account: uuid::Uuid, group: &GroupSecretParams) -> String {
        let day = now() - now() % SECONDS_PER_DAY;
        let resp: AuthCredentialWithPniZkcResponse = zkgroup::deserialize(&zk.auth_credential(account, day)).unwrap();
        let public: ServerPublicParams = zkgroup::deserialize(&zk.public_serialized).unwrap();
        let aci = libsignal_core::Aci::from(account);
        let cred = resp
            .receive_without_pni(aci, crate::zk::PNI_SALT, Timestamp::from_epoch_seconds(day), &public)
            .unwrap();
        let pres = cred.present(&public, group, rnd());
        format!("{}:{}", b64::encode(&zkgroup::serialize(&group.get_public_params())), b64::encode(&zkgroup::serialize(&pres)))
    }

    fn uid(group: &GroupSecretParams, account: uuid::Uuid) -> Vec<u8> {
        zkgroup::serialize(&group.encrypt_service_id(libsignal_core::Aci::from(account).into()))
    }

    fn state(group: &GroupSecretParams, admin: uuid::Uuid, members: &[uuid::Uuid]) -> GroupState {
        let mut m = vec![Member { uid: uid(group, admin), role: Role::Admin, joined_revision: 1 }];
        m.extend(members.iter().map(|a| Member { uid: uid(group, *a), role: Role::Member, joined_revision: 1 }));
        GroupState {
            revision: 1,
            attributes: vec![1],
            settings: vec![2],
            edit_access: Role::Member,
            members_access: Role::Admin,
            members: m,
            pending: vec![],
        }
    }

    #[test]
    fn presentation_gives_the_member_ciphertext() {
        let zk = ZkParams::new(SECRET);
        let group = GroupSecretParams::derive_from_master_key(zkgroup::groups::GroupMasterKey::new(rnd()));
        let ana = uuid::Uuid::new_v4();
        let auth = verify_auth(&zk, &header(&zk, ana, &group), now()).unwrap();
        assert_eq!(auth.uid, uid(&group, ana));
        assert_eq!(auth.id, group.get_group_identifier().to_vec());
        // The ciphertext of an account is the same in every presentation (deterministic).
        assert_eq!(verify_auth(&zk, &header(&zk, ana, &group), now()).unwrap().uid, auth.uid);
    }

    #[test]
    fn wrong_group_params_are_rejected() {
        let zk = ZkParams::new(SECRET);
        let a = GroupSecretParams::generate(rnd());
        let b = GroupSecretParams::generate(rnd());
        let h = header(&zk, uuid::Uuid::new_v4(), &a);
        let (_, pres) = h.split_once(':').unwrap();
        let swapped = format!("{}:{pres}", b64::encode(&zkgroup::serialize(&b.get_public_params())));
        assert_eq!(verify_auth(&zk, &swapped, now()).unwrap_err().status, StatusCode::UNAUTHORIZED);
        // Another server's credential does not verify either.
        let other = ZkParams::new("fedcba9876543210fedcba9876543210");
        assert!(verify_auth(&other, &h, now()).is_err());
        // Nor an expired one (redemption day long past), nor garbage.
        assert!(verify_auth(&zk, &h, now() + 10 * SECONDS_PER_DAY).is_err());
        assert!(verify_auth(&zk, "AAAA:AAAA", now()).is_err());
        assert!(verify_auth(&zk, "no-colon", now()).is_err());
    }

    #[test]
    fn non_member_is_rejected() {
        let group = GroupSecretParams::generate(rnd());
        let (admin, bob, eve) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let mut s = state(&group, admin, &[bob]);
        let before = s.clone();
        for actions in [
            vec![Action::ModifyAttributes { blob: vec![9] }],
            vec![Action::AddMember { uid: uid(&group, eve), role: Role::Member }],
            vec![Action::AcceptPending],
            vec![Action::RemoveMember { uid: uid(&group, eve) }],
        ] {
            let e = apply(&mut s, &uid(&group, eve), &actions, 256).unwrap_err();
            assert_eq!(e.status, StatusCode::FORBIDDEN, "{actions:?}");
        }
        assert_eq!(s, before);
    }

    #[test]
    fn non_admin_cannot_add_remove_or_promote() {
        let group = GroupSecretParams::generate(rnd());
        let (admin, bob, carl, dan) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let mut s = state(&group, admin, &[bob, carl]);
        let bob_uid = uid(&group, bob);
        for actions in [
            vec![Action::AddMember { uid: uid(&group, dan), role: Role::Member }],
            vec![Action::AddPending { uid: uid(&group, dan), role: Role::Member }],
            vec![Action::RemoveMember { uid: uid(&group, carl) }],
            vec![Action::RemoveMember { uid: uid(&group, admin) }],
            vec![Action::ModifyRole { uid: bob_uid.clone(), role: Role::Admin }],
            vec![Action::ModifySettings { blob: vec![3] }],
            vec![Action::ModifyAccess { attributes: Role::Member, members: Role::Member }],
        ] {
            let e = apply(&mut s.clone(), &bob_uid, &actions, 256).unwrap_err();
            assert_eq!(e.status, StatusCode::FORBIDDEN, "{actions:?}");
        }
        // Members may edit attributes while the access allows it, and leave.
        apply(&mut s, &bob_uid, &[Action::ModifyAttributes { blob: vec![7] }], 256).unwrap();
        assert_eq!(s.attributes, vec![7]);
        s.edit_access = Role::Admin;
        assert!(apply(&mut s.clone(), &bob_uid, &[Action::ModifyAttributes { blob: vec![8] }], 256).is_err());
        // With members_access = member, members add (but not as admins).
        s.members_access = Role::Member;
        assert!(apply(&mut s.clone(), &bob_uid, &[Action::AddMember { uid: uid(&group, dan), role: Role::Admin }], 256).is_err());
        apply(&mut s, &bob_uid, &[Action::AddMember { uid: uid(&group, dan), role: Role::Member }], 256).unwrap();
        assert!(s.member(&uid(&group, dan)).is_some());
        apply(&mut s, &bob_uid, &[Action::RemoveMember { uid: bob_uid.clone() }], 256).unwrap();
        assert!(s.member(&bob_uid).is_none());
    }

    #[test]
    fn admin_changes_and_promotion() {
        let group = GroupSecretParams::generate(rnd());
        let (admin, bob, carl) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let mut s = state(&group, admin, &[bob]);
        let a = uid(&group, admin);
        apply(&mut s, &a, &[Action::AddMember { uid: uid(&group, carl), role: Role::Member }], 256).unwrap();
        assert_eq!(s.revision, 2);
        assert_eq!(s.members.last().unwrap().joined_revision, 2);
        // Duplicate add, bad ciphertext, too many members.
        assert!(apply(&mut s.clone(), &a, &[Action::AddMember { uid: uid(&group, carl), role: Role::Member }], 256).is_err());
        assert!(apply(&mut s.clone(), &a, &[Action::AddMember { uid: vec![0xff; 65], role: Role::Member }], 256).is_err());
        assert!(apply(&mut s.clone(), &a, &[Action::AddMember { uid: uid(&group, uuid::Uuid::new_v4()), role: Role::Member }], 3).is_err());
        apply(&mut s, &a, &[Action::ModifyRole { uid: uid(&group, bob), role: Role::Admin }], 256).unwrap();
        apply(&mut s, &a, &[Action::RemoveMember { uid: uid(&group, carl) }], 256).unwrap();
        assert_eq!(s.members.len(), 2);
        // The last admin leaves: the longest-standing member is promoted by the server.
        apply(&mut s, &a, &[Action::ModifyRole { uid: uid(&group, bob), role: Role::Member }], 256).unwrap();
        let promoted = apply(&mut s, &a, &[Action::RemoveMember { uid: a.clone() }], 256).unwrap();
        assert_eq!(promoted, vec![Action::ModifyRole { uid: uid(&group, bob), role: Role::Admin }]);
        assert_eq!(s.members[0].role, Role::Admin);
        // Leaving must be the only action.
        let b = uid(&group, bob);
        assert!(apply(&mut s.clone(), &b, &[Action::RemoveMember { uid: b.clone() }, Action::ModifyAttributes { blob: vec![1] }], 256).is_err());
    }

    #[test]
    fn pending_members() {
        let group = GroupSecretParams::generate(rnd());
        let (admin, bob, carl) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let mut s = state(&group, admin, &[]);
        let (a, b, c) = (uid(&group, admin), uid(&group, bob), uid(&group, carl));
        apply(&mut s, &a, &[Action::AddPending { uid: b.clone(), role: Role::Member }, Action::AddPending { uid: c.clone(), role: Role::Admin }], 256).unwrap();
        assert_eq!(s.pending.len(), 2);
        assert_eq!(s.pending[0].added_by, a);
        // A pending member can only accept or decline, alone.
        assert_eq!(apply(&mut s.clone(), &b, &[Action::ModifyAttributes { blob: vec![1] }], 256).unwrap_err().status, StatusCode::FORBIDDEN);
        assert!(apply(&mut s.clone(), &b, &[Action::RemovePending { uid: c.clone() }], 256).is_err());
        apply(&mut s, &b, &[Action::AcceptPending], 256).unwrap();
        assert!(s.member(&b).is_some_and(|i| s.members[i].role == Role::Member));
        apply(&mut s, &c, &[Action::RemovePending { uid: c.clone() }], 256).unwrap();
        assert!(s.pending.is_empty() && s.member(&c).is_none());
        // Accepting without an invitation.
        assert!(apply(&mut s, &c, &[Action::AcceptPending], 256).is_err());
    }

    #[test]
    fn change_signature_verifies_with_public_params() {
        let zk = ZkParams::new(SECRET);
        let id = [7u8; 32];
        let change = br#"{"revision":2}"#;
        let sig = zk.sign_group_change(&id, change);
        let public: ServerPublicParams = zkgroup::deserialize(&zk.public_serialized).unwrap();
        let mut msg = crate::zk::GROUP_CHANGE_CONTEXT.to_vec();
        msg.extend_from_slice(&id);
        msg.extend_from_slice(change);
        public.verify_signature(&msg, sig).unwrap();
        msg.push(0);
        assert!(public.verify_signature(&msg, sig).is_err());
    }

    #[test]
    fn actions_wire_format() {
        let a: Action = serde_json::from_str(r#"{"type":"modify_access","attributes":"admin","members":"member"}"#).unwrap();
        assert_eq!(a, Action::ModifyAccess { attributes: Role::Admin, members: Role::Member });
        let a: Action = serde_json::from_str(r#"{"type":"accept_pending"}"#).unwrap();
        assert_eq!(a, Action::AcceptPending);
        assert!(serde_json::from_str::<Action>(r#"{"type":"promote_admin"}"#).is_err());
    }
}
