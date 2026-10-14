//! Public usernames (API section 6).

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::json;
use sqlx::{MySql, Transaction};

use super::directory::write_directory_entry;
use super::{no_content, reply};
use crate::auth::Principal;
use crate::db::is_duplicate_key;
use crate::error::{bad_request, conflict, not_found, unauthorized, ApiResult};
use crate::ids;
use crate::state::AppState;
use crate::validate::{b64, parse_json, path_uuid, MAX_JSON_BODY};

/// Largest accepted encrypted username of a username link (nonce + padded name + tag is 60
/// bytes with the current client; some room for future formats).
const MAX_ENCRYPTED_USERNAME: usize = 128;

/// Usernames: 3-32 chars, a-z 0-9 _ . starting with a letter, stored lowercase
/// (Go: `^[a-z][a-z0-9_.]{2,31}$` and no ".."). Only ASCII input is accepted: lowercasing
/// Unicode would map look-alikes such as the Kelvin sign (U+212A) onto ASCII letters, and
/// mixed-script names are a classic impersonation trick.
pub(crate) fn normalize_username(u: &str) -> (String, bool) {
    let t = u.trim();
    let u = t.strip_prefix('@').unwrap_or(t).trim().to_ascii_lowercase();
    let b = u.as_bytes();
    let ok = (3..=32).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'.')
        && !u.contains("..");
    (u, ok)
}

/// Signal-style discriminator rules (`nickname.01`), checked only when a username is *set*:
/// a trailing `.<digits>` segment must have 2-9 digits, must not be all zeros and may start
/// with 0 only in the 2-digit form ("01".."09"). Usernames without a numeric suffix stay
/// valid, and existing usernames are still looked up by their exact string (a stored
/// "bob.1" keeps resolving; it just cannot be newly chosen).
fn discriminator_ok(u: &str) -> bool {
    let Some((_, d)) = u.rsplit_once('.') else {
        return true;
    };
    if d.is_empty() || !d.bytes().all(|c| c.is_ascii_digit()) {
        return true; // not a discriminator ("a.b", "x_1.y")
    }
    (2..=9).contains(&d.len()) && d.bytes().any(|c| c != b'0') && !(d.len() > 2 && d.starts_with('0'))
}

#[derive(Deserialize)]
struct SetUsernameRequest {
    #[serde(default)]
    username: Option<String>,
}

/// Keeps the current username of `account` (locked by tx) reserved for it, so that after a
/// change, removal or account deletion nobody else can take it over right away.
pub(crate) async fn reserve_released_username(
    st: &AppState,
    tx: &mut Transaction<'_, MySql>,
    account: &str,
) -> Result<(), sqlx::Error> {
    if st.cfg.username_reservation_days == 0 {
        return Ok(());
    }
    let expires_at = crate::now_millis() + st.cfg.username_reservation_days * 86_400_000;
    sqlx::query!(
        "INSERT INTO username_reservations (username, account_id, expires_at)
         SELECT username, id, ? FROM accounts WHERE id = ? AND username IS NOT NULL
         ON DUPLICATE KEY UPDATE account_id = VALUES(account_id), expires_at = VALUES(expires_at)",
        expires_at,
        account
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// PUT /v1/account/username {"username": "name" | null}
pub async fn set_username(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    st.rate_limit(
        &format!("username:acct:{}", p.account),
        st.limits.directory_number,
    )?;
    let req: SetUsernameRequest = parse_json(body, MAX_JSON_BODY).await?;
    let mut value: Option<String> = None;
    if let Some(u) = req.username.as_deref().filter(|u| !u.trim().is_empty()) {
        let (u, ok) = normalize_username(u);
        if !ok {
            return Err(bad_request(
                "username must be 3-32 characters: letters, digits, _ or ., starting with a letter",
            ));
        }
        if !discriminator_ok(&u) {
            return Err(bad_request(
                "the number after the last . must have 2-9 digits, not all zeros, and no leading zero unless it has 2 digits",
            ));
        }
        value = Some(u);
    }
    let mut tx = st.db.begin().await?;
    let row = sqlx::query!("SELECT username AS `username: String` FROM accounts WHERE id = ? FOR UPDATE", &p.account)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(row) = row else {
        return Err(unauthorized("account not found"));
    };
    let current = row.username;
    if current == value {
        return Ok(no_content());
    }
    if let Some(v) = &value {
        // Released recently by someone else: still theirs.
        let reserved = sqlx::query!(
            "SELECT account_id AS `account_id: String` FROM username_reservations WHERE username = ? AND expires_at >= ?",
            v,
            crate::now_millis()
        )
        .fetch_optional(&mut *tx)
        .await?;
        if reserved.is_some_and(|r| r.account_id != p.account) {
            return Err(conflict("this username is taken"));
        }
    }
    reserve_released_username(&st, &mut tx, &p.account).await?;
    match sqlx::query!("UPDATE accounts SET username = ? WHERE id = ?", &value, &p.account)
        .execute(&mut *tx)
        .await
    {
        Err(e) if is_duplicate_key(&e) => return Err(conflict("this username is taken")),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    // A username link encrypts the old username: it would now point to the wrong name.
    sqlx::query!("DELETE FROM username_links WHERE account_id = ?", &p.account)
        .execute(&mut *tx)
        .await?;
    if let Some(v) = &value {
        // Our own (or an expired) reservation of the new name is used up.
        sqlx::query!("DELETE FROM username_reservations WHERE username = ?", v)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(no_content())
}

/// GET /v1/directory/username/{username}
pub async fn directory_username(
    State(st): State<AppState>,
    p: Principal,
    Path(username): Path<String>,
) -> ApiResult {
    st.rate_limit(
        &format!("dir-number:acct:{}", p.account),
        st.limits.directory_number,
    )?;
    let (u, ok) = normalize_username(&username);
    if !ok {
        return Err(not_found("unknown account"));
    }
    write_directory_entry(&st, "username", &u).await
}

#[derive(Deserialize)]
struct UsernameLinkRequest {
    #[serde(with = "b64")]
    encrypted_username: Vec<u8>,
}

/// PUT /v1/account/username/link {"encrypted_username": b64} -> {"handle": uuid}
///
/// Creates (or replaces, which is how a link is reset) the account's username link. The
/// blob is encrypted by the client with a key that only exists in the link itself, so the
/// server learns nothing beyond "this random handle belongs to this account".
pub async fn put_username_link(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    st.rate_limit(
        &format!("username:acct:{}", p.account),
        st.limits.directory_number,
    )?;
    let req: UsernameLinkRequest = parse_json(body, MAX_JSON_BODY).await?;
    if req.encrypted_username.len() < 28 || req.encrypted_username.len() > MAX_ENCRYPTED_USERNAME {
        return Err(bad_request("encrypted_username has an invalid size"));
    }
    let mut tx = st.db.begin().await?;
    let row = sqlx::query!("SELECT username AS `username: String` FROM accounts WHERE id = ? FOR UPDATE", &p.account)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(row) = row else {
        return Err(unauthorized("account not found"));
    };
    if row.username.is_none() {
        return Err(conflict("set a username first"));
    }
    let handle = ids::new_uuid();
    sqlx::query!("DELETE FROM username_links WHERE account_id = ?", &p.account)
        .execute(&mut *tx)
        .await?;
    sqlx::query!(
        "INSERT INTO username_links (handle, account_id, encrypted_username, created_at) VALUES (?, ?, ?, ?)",
        &handle,
        &p.account,
        &req.encrypted_username,
        crate::now_millis()
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(reply(StatusCode::OK, json!({ "handle": handle })))
}

/// GET /v1/account/username/link -> {"handle": uuid} (404 when there is none)
pub async fn get_own_username_link(State(st): State<AppState>, p: Principal) -> ApiResult {
    let row = sqlx::query!("SELECT handle AS `handle: String` FROM username_links WHERE account_id = ?", &p.account)
        .fetch_optional(&st.db)
        .await?;
    match row {
        Some(r) => Ok(reply(StatusCode::OK, json!({ "handle": r.handle }))),
        None => Err(not_found("no username link")),
    }
}

/// DELETE /v1/account/username/link
pub async fn delete_username_link(State(st): State<AppState>, p: Principal) -> ApiResult {
    sqlx::query!("DELETE FROM username_links WHERE account_id = ?", &p.account)
        .execute(&st.db)
        .await?;
    Ok(no_content())
}

/// GET /v1/username/link/{handle} -> {"encrypted_username": b64}
pub async fn resolve_username_link(
    State(st): State<AppState>,
    p: Principal,
    Path(handle): Path<String>,
) -> ApiResult {
    st.rate_limit(
        &format!("dir-number:acct:{}", p.account),
        st.limits.directory_number,
    )?;
    let handle = path_uuid("handle", &handle)?;
    let row = sqlx::query!("SELECT encrypted_username FROM username_links WHERE handle = ?", &handle)
        .fetch_optional(&st.db)
        .await?;
    match row {
        Some(r) => Ok(reply(
            StatusCode::OK,
            json!({ "encrypted_username": b64::encode(&r.encrypted_username) }),
        )),
        None => Err(not_found("unknown username link")),
    }
}

#[cfg(test)]
mod tests {
    use super::{discriminator_ok, normalize_username};

    #[test]
    fn discriminators() {
        for ok in ["alice", "alice.01", "alice.09", "alice.10", "alice.123456789", "a.b", "a_b.c1", "a.b.42"] {
            assert!(discriminator_ok(ok), "{ok}");
        }
        for bad in ["alice.0", "alice.1", "alice.00", "alice.000", "alice.012", "alice.1234567890"] {
            assert!(!discriminator_ok(bad), "{bad}");
        }
        // Old-style names with a dotted number are still accepted by the lookup normalizer.
        assert!(normalize_username("bob.1").1);
    }

    #[test]
    fn usernames() {
        assert_eq!(normalize_username(" @Alice_1 "), ("alice_1".into(), true));
        assert!(!normalize_username("al").1);
        assert!(!normalize_username("1alice").1);
        assert!(!normalize_username("a..b").1);
        // Look-alikes and other scripts are refused, not folded onto ASCII.
        assert!(!normalize_username("\u{212A}ate").1);
        assert!(!normalize_username("p\u{0430}ypal").1);
        assert!(!normalize_username("\u{130}nes").1);
    }
}
