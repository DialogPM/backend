//! Periodic background maintenance (expiry of envelopes, codes, challenges, attachments,
//! inactive devices).

use std::time::Duration;

use tracing::{debug, info, warn};

use crate::api::attachments::{ATTACHMENT_UPLOADED, KIND_MESSAGE};
use crate::db::RowExt;
use crate::state::AppState;

/// Attachments never (successfully) uploaded are removed after this.
const STALE_UPLOAD_AGE_MS: i64 = 24 * 3600 * 1000;
const CLEANUP_BATCH: i64 = 5000;
const DAY_MS: i64 = 86_400_000;

pub async fn run(st: AppState, interval: Duration) {
    let mut t = tokio::time::interval(interval);
    loop {
        t.tick().await;
        if tokio::time::timeout(Duration::from_secs(300), run_once(&st))
            .await
            .is_err()
        {
            warn!("maintenance jobs timed out");
        }
        st.limiter.cleanup();
        if let Some(a) = &st.admin {
            a.cleanup();
        }
    }
}

pub async fn run_once(st: &AppState) {
    st.prov.cleanup();
    let now = crate::now_millis();

    match delete_batched(
        st,
        "DELETE FROM envelopes WHERE server_timestamp < ? LIMIT ?",
        now - st.cfg.message_ttl_days * DAY_MS,
    )
    .await
    {
        Ok(n) if n > 0 => info!(count = n, "expired envelopes"),
        Ok(_) => {}
        Err(e) => warn!(error = %e, "expire envelopes failed"),
    }
    match delete_batched(
        st,
        "DELETE FROM recovery_challenges WHERE expires_at < ? LIMIT ?",
        now,
    )
    .await
    {
        Ok(n) if n > 0 => debug!(count = n, "expired recovery challenges"),
        Ok(_) => {}
        Err(e) => warn!(error = %e, "expire recovery challenges failed"),
    }
    match delete_batched(
        st,
        "DELETE FROM phone_codes WHERE expires_at < ? LIMIT ?",
        now,
    )
    .await
    {
        Ok(n) if n > 0 => debug!(count = n, "expired phone codes"),
        Ok(_) => {}
        Err(e) => warn!(error = %e, "expire phone codes failed"),
    }

    for (query, what) in [
        ("DELETE FROM login_requests WHERE expires_at < ? LIMIT ?", "login requests"),
        ("DELETE FROM registration_challenges WHERE expires_at < ? LIMIT ?", "registration challenges"),
        ("DELETE FROM username_reservations WHERE expires_at < ? LIMIT ?", "username reservations"),
    ] {
        match delete_batched(st, query, now).await {
            Ok(n) if n > 0 => debug!(count = n, what, "expired"),
            Ok(_) => {}
            Err(e) => warn!(error = %e, what, "expire failed"),
        }
    }
    let inactive_days = st.settings.get().inactive_device_days;
    if inactive_days > 0 {
        match unlink_inactive_devices(st, now - inactive_days * DAY_MS).await {
            Ok(n) if n > 0 => info!(count = n, "unlinked inactive devices"),
            Ok(_) => {}
            Err(e) => warn!(error = %e, "unlink inactive devices failed"),
        }
    }

    // Revocation records of removed devices (remote wipe), after a long time.
    if let Err(e) = sqlx::query!(
        "DELETE FROM device_revocations WHERE revoked_at < ? LIMIT ?",
        now - crate::api::devices::REVOCATION_KEEP_MS,
        CLEANUP_BATCH
    )
    .execute(&st.db)
    .await
    {
        warn!(error = %e, "prune device revocations failed");
    }

    // Accounts banned with the admin CLI (another process): close their open WebSockets.
    // Their tokens no longer authenticate, so they cannot reconnect.
    match sqlx::query!("SELECT id AS `id: String` FROM accounts WHERE banned_at >= ?", now - DAY_MS)
        .fetch_all(&st.db)
        .await
    {
        Ok(rows) => {
            for r in rows {
                let account = r.id;
                if !st.hub.connected_devices(&account).is_empty() {
                    st.hub.close_account(&account, &serde_json::json!({"kind": "account_banned"}), "account banned");
                    info!(account = %account, "closed sockets of banned account");
                }
            }
        }
        Err(e) => warn!(error = %e, "close banned sockets failed"),
    }

    // Message attachments past their TTL, and uploads that never completed.
    let expired = expire_attachments(
        st,
        "SELECT id FROM attachments WHERE kind = ? AND created_at < ? LIMIT ?",
        Some(KIND_MESSAGE),
        now - st.cfg.attachment_ttl_days * DAY_MS,
    )
    .await
    .unwrap_or_else(|e| {
        warn!(error = %e, "expire attachments failed");
        0
    });
    let stale = expire_attachments(
        st,
        "SELECT id FROM attachments WHERE state <> ? AND created_at < ? LIMIT ?",
        None,
        now - STALE_UPLOAD_AGE_MS,
    )
    .await
    .unwrap_or_else(|e| {
        warn!(error = %e, "expire stale uploads failed");
        0
    });
    if expired + stale > 0 {
        info!(expired, stale_uploads = stale, "expired attachments");
    }
}

/// Unlinks devices not seen since `cutoff`, except the most recently active device of each
/// account (an account is never left without a device by this job; that device can still
/// be unlinked by the user or replaced by recovery).
async fn unlink_inactive_devices(st: &AppState, cutoff: i64) -> Result<usize, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT d.account_id AS `account_id: String`, d.device_id AS `device_id: i64` FROM devices d
         WHERE d.last_seen_at < ? AND EXISTS (
             SELECT 1 FROM devices o WHERE o.account_id = d.account_id AND o.device_id <> d.device_id
               AND (o.last_seen_at > d.last_seen_at
                    OR (o.last_seen_at = d.last_seen_at AND o.device_id < d.device_id)))
         LIMIT ?",
        cutoff,
        CLEANUP_BATCH
    )
    .fetch_all(&st.db)
    .await?;
    let mut n = 0;
    for r in rows {
        let (account, device) = (r.account_id, r.device_id);
        // Re-checked: the device may have come back since the SELECT. Cascades to keys and
        // queued envelopes.
        let res = sqlx::query!(
            "DELETE FROM devices WHERE account_id = ? AND device_id = ? AND last_seen_at < ?",
            &account,
            device,
            cutoff
        )
        .execute(&st.db)
        .await?;
        if res.rows_affected() == 0 {
            continue;
        }
        n += 1;
        st.hub.close_device(&account, device, "device inactive");
        st.hub
            .send_event(&account, device, &serde_json::json!({"kind": "devices_changed"}));
        info!(account = %account, device, "unlinked inactive device");
    }
    Ok(n)
}

/// Runs a "DELETE ... WHERE x < ? LIMIT ?" until it affects fewer rows than the batch.
async fn delete_batched(st: &AppState, query: &str, arg: i64) -> Result<u64, sqlx::Error> {
    let mut total = 0;
    loop {
        let n = sqlx::query(query)
            .bind(arg)
            .bind(CLEANUP_BATCH)
            .execute(&st.db)
            .await?
            .rows_affected();
        total += n;
        if (n as i64) < CLEANUP_BATCH {
            return Ok(total);
        }
    }
}

/// Deletes objects and rows selected by `query` (`kind` or the uploaded state first, then the
/// cutoff, then LIMIT).
async fn expire_attachments(
    st: &AppState,
    query: &str,
    kind: Option<&str>,
    cutoff: i64,
) -> Result<usize, sqlx::Error> {
    let mut total = 0;
    loop {
        let mut q = sqlx::query(query);
        q = match kind {
            Some(k) => q.bind(k),
            None => q.bind(ATTACHMENT_UPLOADED),
        };
        let ids: Vec<String> = q
            .bind(cutoff)
            .bind(CLEANUP_BATCH)
            .fetch_all(&st.db)
            .await?
            .iter()
            .map(|r| r.string("id"))
            .collect();
        let n = ids.len();
        let mut deleted = 0;
        for id in ids {
            if let Err(e) = st.store.delete(&id).await {
                // Keep the row so the object is retried on the next run.
                warn!(attachment = %id, error = %e, "delete attachment object failed");
                continue;
            }
            sqlx::query!("DELETE FROM attachments WHERE id = ?", &id)
                .execute(&st.db)
                .await?;
            deleted += 1;
        }
        total += deleted;
        if (n as i64) < CLEANUP_BATCH || deleted == 0 {
            return Ok(total);
        }
    }
}
