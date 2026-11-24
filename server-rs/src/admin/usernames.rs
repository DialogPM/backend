//! Blocked usernames: names an operator keeps anyone from taking, because they would pass for
//! the service itself ("support", "admin", ...).
//!
//! A blocked entry is a pattern:
//! * a plain name blocks that name and the same name with a numeric suffix (`support` also
//!   blocks `support.01`: the suffix only tells apart people who want the same name);
//! * with `*` at the end, at the start or both, it blocks every name that starts with, ends
//!   with or contains the rest (`support*`, `*admin`, `*support*`).
//! Blocking a pattern also takes the name away from the accounts that hold a matching one,
//! unless asked not to. Accounts are otherwise untouched (no ban, no logout).

use axum::body::Body;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::json;
use sqlx::{MySql, Transaction};
use tracing::info;

use super::{json_body, params};
use crate::api::{no_content, reply};
use crate::db::RowExt;
use crate::error::{bad_request, not_found, ApiError, ApiResult};
use crate::state::AppState;

/// Patterns an operator may keep; far more than a list of service names needs.
const MAX_PATTERNS: i64 = 5000;
/// Accounts whose name one request may take away (a pattern matching more is refused: it is
/// most likely a mistake).
const MAX_RELEASED: usize = 5000;
/// Names shown as a preview of what a pattern matches.
const PREVIEW: usize = 20;

#[derive(Debug, Clone, PartialEq)]
pub struct Pattern {
    /// The name without the `*`s: lowercase letters, digits, `_` and `.`.
    core: String,
    /// `*` at the start: anything may come before.
    any_before: bool,
    /// `*` at the end: anything may come after.
    any_after: bool,
}

impl Pattern {
    /// Parses what an operator typed: a username (with or without `@`), optionally with `*`
    /// at the start and/or the end.
    pub fn parse(input: &str) -> Result<Pattern, &'static str> {
        let t = input.trim();
        let t = t.strip_prefix('@').unwrap_or(t).trim().to_ascii_lowercase();
        let (any_before, t) = match t.strip_prefix('*') {
            Some(rest) => (true, rest),
            None => (false, t.as_str()),
        };
        let (any_after, core) = match t.strip_suffix('*') {
            Some(rest) => (true, rest),
            None => (false, t),
        };
        let valid_chars = core.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'.');
        if !valid_chars || !(3..=32).contains(&core.len()) {
            return Err("a blocked username has 3-32 characters (letters, digits, _ or .), optionally with * at the start or the end");
        }
        // A plain name is one that could be a username: anything else could never be taken,
        // so blocking it would be a typing mistake.
        if !any_before && !any_after && !crate::api::username::normalize_username(core).1 {
            return Err("this is not a possible username (it must start with a letter and may not contain ..)");
        }
        Ok(Pattern { core: core.to_string(), any_before, any_after })
    }

    /// The stored form (`support`, `support*`, `*admin`, `*support*`).
    pub fn text(&self) -> String {
        format!("{}{}{}", if self.any_before { "*" } else { "" }, self.core, if self.any_after { "*" } else { "" })
    }

    pub fn matches(&self, username: &str) -> bool {
        match (self.any_before, self.any_after) {
            (true, true) => username.contains(&self.core),
            (false, true) => username.starts_with(&self.core),
            (true, false) => username.ends_with(&self.core),
            (false, false) => {
                username == self.core
                    || username
                        .strip_prefix(&self.core)
                        .and_then(|rest| rest.strip_prefix('.'))
                        .is_some_and(|d| !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit()))
            }
        }
    }

    /// A LIKE operand that selects every username this pattern may match (and possibly more:
    /// the rows are checked with `matches`). `_` is a wildcard for LIKE and a letter here.
    fn like(&self) -> String {
        let escaped = self.core.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
        match (self.any_before, self.any_after) {
            (true, _) => format!("%{escaped}%"),
            (false, _) => format!("{escaped}%"),
        }
    }
}

/// Whether an operator blocked `username` (already normalized). Called with the transaction
/// that sets the name.
pub async fn is_blocked(tx: &mut Transaction<'_, MySql>, username: &str) -> Result<bool, sqlx::Error> {
    let rows = sqlx::query("SELECT pattern FROM blocked_usernames").fetch_all(&mut **tx).await?;
    Ok(rows.iter().any(|r| Pattern::parse(&r.string("pattern")).is_ok_and(|p| p.matches(username))))
}

fn pattern_of(input: &str) -> Result<Pattern, ApiError> {
    Pattern::parse(input).map_err(bad_request)
}

/// GET /v1/admin/usernames: the blocked patterns, newest first.
pub async fn list(State(st): State<AppState>) -> ApiResult {
    let rows = sqlx::query("SELECT pattern, created_at FROM blocked_usernames ORDER BY created_at DESC, pattern")
        .fetch_all(&st.db)
        .await?;
    let items: Vec<_> = rows.iter().map(|r| json!({"pattern": r.string("pattern"), "created_at": r.i64("created_at")})).collect();
    Ok(reply(StatusCode::OK, json!({ "items": items })))
}

/// The usernames in use that `pattern` matches: (account id, username).
async fn holders(tx: &mut Transaction<'_, MySql>, pattern: &Pattern, lock: bool) -> Result<Vec<(String, String)>, sqlx::Error> {
    let sql = format!(
        "SELECT id, username FROM accounts WHERE username LIKE ? ORDER BY username{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let rows = sqlx::query(&sql).bind(pattern.like()).fetch_all(&mut **tx).await?;
    Ok(rows
        .iter()
        .map(|r| (r.string("id"), r.string("username")))
        .filter(|(_, u)| pattern.matches(u))
        .collect())
}

/// GET /v1/admin/usernames/matches?pattern=…: what blocking the pattern would take away.
pub async fn matches(State(st): State<AppState>, RawQuery(q): RawQuery) -> ApiResult {
    let p = params(&q);
    let pattern = pattern_of(p.get("pattern").map(String::as_str).unwrap_or(""))?;
    let mut tx = st.db.begin().await?;
    let found = holders(&mut tx, &pattern, false).await?;
    let usernames: Vec<&str> = found.iter().take(PREVIEW).map(|(_, u)| u.as_str()).collect();
    Ok(reply(StatusCode::OK, json!({"pattern": pattern.text(), "count": found.len(), "usernames": usernames})))
}

#[derive(Deserialize)]
struct BlockRequest {
    #[serde(default)]
    pattern: String,
    /// false: only keep the name from being taken from now on; accounts that hold a matching
    /// name keep it.
    #[serde(default = "yes")]
    release: bool,
}

fn yes() -> bool {
    true
}

/// POST /v1/admin/usernames/block {"pattern": "support", "release": true}
pub async fn block(State(st): State<AppState>, body: Body) -> ApiResult {
    let req: BlockRequest = json_body(body).await?;
    let pattern = pattern_of(&req.pattern)?;
    let mut tx = st.db.begin().await?;
    let count = sqlx::query("SELECT COUNT(*) AS v FROM blocked_usernames").fetch_one(&mut *tx).await?.i64("v");
    if count >= MAX_PATTERNS {
        return Err(bad_request("too many blocked usernames"));
    }
    sqlx::query("INSERT INTO blocked_usernames (pattern, created_at) VALUES (?, ?) ON DUPLICATE KEY UPDATE pattern = pattern")
        .bind(pattern.text())
        .bind(crate::now_millis())
        .execute(&mut *tx)
        .await?;
    let mut released = 0usize;
    if req.release {
        let found = holders(&mut tx, &pattern, true).await?;
        if found.len() > MAX_RELEASED {
            return Err(bad_request(format!("{} accounts use a matching username: choose a narrower pattern", found.len())));
        }
        for (account, username) in &found {
            sqlx::query("UPDATE accounts SET username = NULL WHERE id = ?").bind(account).execute(&mut *tx).await?;
            // A username link encrypts the name the account no longer has.
            sqlx::query("DELETE FROM username_links WHERE account_id = ?").bind(account).execute(&mut *tx).await?;
            // Nothing is kept for the previous owner either.
            sqlx::query("DELETE FROM username_reservations WHERE username = ?").bind(username).execute(&mut *tx).await?;
        }
        released = found.len();
    }
    tx.commit().await?;
    // Counts only: which names an operator blocks says nothing about users, but the log is
    // not the place for it either.
    info!(released, "admin blocked a username pattern");
    Ok(reply(StatusCode::OK, json!({"pattern": pattern.text(), "released": released})))
}

#[derive(Deserialize)]
struct UnblockRequest {
    #[serde(default)]
    pattern: String,
}

/// POST /v1/admin/usernames/unblock {"pattern": "support"}: the name can be taken again
/// (nobody gets it back by itself).
pub async fn unblock(State(st): State<AppState>, body: Body) -> ApiResult {
    let req: UnblockRequest = json_body(body).await?;
    let pattern = pattern_of(&req.pattern)?;
    let done = sqlx::query("DELETE FROM blocked_usernames WHERE pattern = ?").bind(pattern.text()).execute(&st.db).await?;
    if done.rows_affected() == 0 {
        return Err(not_found("this username is not blocked"));
    }
    info!("admin unblocked a username pattern");
    Ok(no_content())
}

#[derive(Deserialize, Default)]
struct RemoveRequest {
    /// Also keep the name (and its numbered forms) from being taken again, by anyone.
    #[serde(default)]
    block: bool,
}

/// POST /v1/admin/accounts/{id}/username/remove {"block": true}: takes the username away from
/// one account (someone calling themselves "admin"). The account is otherwise untouched (no
/// ban, no sign-out) and can choose another name; with `block` the removed one stays unavailable.
pub async fn remove(State(st): State<AppState>, Path(id): Path<String>, body: Body) -> ApiResult {
    let id = crate::ids::normalize_uuid(&id).ok_or_else(|| bad_request("account id must be a UUID"))?;
    let req: RemoveRequest = json_body(body).await?;
    let mut tx = st.db.begin().await?;
    let row = sqlx::query("SELECT username FROM accounts WHERE id = ? FOR UPDATE")
        .bind(&id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| not_found("unknown account"))?;
    let username = row.opt_string("username").ok_or_else(|| bad_request("this account has no username"))?;
    if req.block {
        // The name as a plain pattern (which also covers its numbered forms).
        let pattern = pattern_of(&username)?;
        let count = sqlx::query("SELECT COUNT(*) AS v FROM blocked_usernames").fetch_one(&mut *tx).await?.i64("v");
        if count >= MAX_PATTERNS {
            return Err(bad_request("too many blocked usernames"));
        }
        sqlx::query("INSERT INTO blocked_usernames (pattern, created_at) VALUES (?, ?) ON DUPLICATE KEY UPDATE pattern = pattern")
            .bind(pattern.text())
            .bind(crate::now_millis())
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("UPDATE accounts SET username = NULL WHERE id = ?").bind(&id).execute(&mut *tx).await?;
    // A username link encrypts the name the account no longer has.
    sqlx::query("DELETE FROM username_links WHERE account_id = ?").bind(&id).execute(&mut *tx).await?;
    // Nothing is kept for the previous owner either.
    sqlx::query("DELETE FROM username_reservations WHERE username = ?").bind(&username).execute(&mut *tx).await?;
    tx.commit().await?;
    info!(account = %id, blocked = req.block, "admin removed a username");
    Ok(reply(StatusCode::OK, json!({"username": username, "blocked": req.block})))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Pattern {
        Pattern::parse(s).unwrap()
    }

    #[test]
    fn a_plain_name_also_covers_its_numbered_forms() {
        let support = p("support");
        for taken in ["support", "support.01", "support.1234"] {
            assert!(support.matches(taken), "{taken}");
        }
        for free in ["supporter", "support_team", "support.team", "mysupport", "support.", "support.1a", "suppor"] {
            assert!(!support.matches(free), "{free}");
        }
    }

    #[test]
    fn stars_widen_the_match() {
        assert!(p("support*").matches("support_team") && p("support*").matches("support") && !p("support*").matches("mysupport"));
        assert!(p("*admin").matches("the_admin") && p("*admin").matches("admin") && !p("*admin").matches("admins"));
        assert!(p("*admin*").matches("the_admins") && !p("*admin*").matches("adm.in"));
    }

    #[test]
    fn what_an_operator_types_is_normalized() {
        assert_eq!(p("  @Support ").text(), "support");
        assert_eq!(p("*Admin*").text(), "*admin*");
        assert_eq!(p("dialog*").text(), "dialog*");
        assert_eq!(p(&p("*admin").text()), p("*admin"), "the stored form parses back");
    }

    #[test]
    fn impossible_or_sweeping_patterns_are_refused() {
        for bad in ["", "ab", "*ab*", "*", "**", "sup*port", "sup port", "ădmin", "1admin", "a..b", "support**", &"a".repeat(33)] {
            assert!(Pattern::parse(bad).is_err(), "{bad:?}");
        }
        // With a star the rest need not be a whole username.
        assert!(Pattern::parse("*.admin").is_ok() && Pattern::parse("*007").is_ok());
    }

    #[test]
    fn like_operands_do_not_treat_underscores_as_wildcards() {
        assert_eq!(p("the_admin").like(), "the\\_admin%");
        assert_eq!(p("*the_admin").like(), "%the\\_admin%");
        assert_eq!(p("support*").like(), "support%");
    }
}
