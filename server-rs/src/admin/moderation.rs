//! Account bans, unbans and forced logouts, shared by the admin API and the admin CLI.

use sqlx::MySqlPool;

use crate::ids;

pub struct BanOutcome {
    pub already_banned: bool,
    pub devices: usize,
    pub reports_resolved: u64,
}

/// Bans an account: sets accounts.banned_at (the server then rejects its tokens and refuses
/// to create devices for it, see auth.rs and api::accounts::create_device) and ban_reason,
/// replaces every device token with a random one nobody knows (drops all sessions), removes
/// push tokens and pending login requests, and resolves the open reports against it (as
/// "banned"). Keys, messages and group memberships are kept, so the ban can be lifted
/// (`unban_account`; the account then needs to log in again). Returns None for an unknown
/// account. The caller closes open WebSockets (the API at once; for the CLI, another process,
/// the server's maintenance job does it within its 10-minute interval).
pub async fn ban_account(pool: &MySqlPool, account: &str, reason: Option<&str>) -> Result<Option<BanOutcome>, sqlx::Error> {
    let now = crate::now_millis();
    let mut tx = pool.begin().await?;
    let row = sqlx::query!("SELECT banned_at FROM accounts WHERE id = ? FOR UPDATE", account)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let already = row.banned_at.is_some();
    if !already {
        sqlx::query!("UPDATE accounts SET banned_at = ?, ban_reason = ? WHERE id = ?", now, reason, account)
            .execute(&mut *tx)
            .await?;
    } else if reason.is_some() {
        sqlx::query!("UPDATE accounts SET ban_reason = ? WHERE id = ?", reason, account)
            .execute(&mut *tx)
            .await?;
    }
    let devices: Vec<i64> =
        sqlx::query!("SELECT device_id AS `device_id: i64` FROM devices WHERE account_id = ? FOR UPDATE", account)
            .fetch_all(&mut *tx)
            .await?
            .iter()
            .map(|r| r.device_id)
            .collect();
    for device in &devices {
        let (_, hash) = ids::new_token();
        sqlx::query!(
            "UPDATE devices SET token_hash = ?, push_provider = '', push_token = NULL, push_token_hash = NULL,
                 push_tag = NULL, voip_token = NULL, voip_token_hash = NULL
             WHERE account_id = ? AND device_id = ?",
            hash,
            account,
            device
        )
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query!("DELETE FROM login_requests WHERE account_id = ?", account)
        .execute(&mut *tx)
        .await?;
    let resolved = sqlx::query!(
        "UPDATE spam_reports SET resolved_at = ?, resolution = 'banned' WHERE reported_id = ? AND resolved_at IS NULL",
        now,
        account
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(Some(BanOutcome { already_banned: already, devices: devices.len(), reports_resolved: resolved }))
}

/// Lifts a ban. Returns false for an unknown account.
pub async fn unban_account(pool: &MySqlPool, account: &str) -> Result<bool, sqlx::Error> {
    let exists = sqlx::query!("SELECT id FROM accounts WHERE id = ?", account)
        .fetch_optional(pool)
        .await?;
    if exists.is_none() {
        return Ok(false);
    }
    sqlx::query!("UPDATE accounts SET banned_at = NULL, ban_reason = NULL WHERE id = ?", account)
        .execute(pool)
        .await?;
    Ok(true)
}

/// Unlinks every device of the account, like the account deleting them itself (cascades to
/// their keys, queued envelopes and push tokens) and drops pending login requests. Returns
/// the removed device ids, or None for an unknown account.
pub async fn logout_account(pool: &MySqlPool, account: &str) -> Result<Option<Vec<i64>>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    // Lock the account row: device set changes are serialized per account.
    let exists = sqlx::query!("SELECT id FROM accounts WHERE id = ? FOR UPDATE", account)
        .fetch_optional(&mut *tx)
        .await?;
    if exists.is_none() {
        return Ok(None);
    }
    let devices: Vec<i64> =
        sqlx::query!("SELECT device_id AS `device_id: i64` FROM devices WHERE account_id = ? FOR UPDATE", account)
            .fetch_all(&mut *tx)
            .await?
            .iter()
            .map(|r| r.device_id)
            .collect();
    sqlx::query!("DELETE FROM devices WHERE account_id = ?", account)
        .execute(&mut *tx)
        .await?;
    sqlx::query!("DELETE FROM login_requests WHERE account_id = ?", account)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Some(devices))
}
