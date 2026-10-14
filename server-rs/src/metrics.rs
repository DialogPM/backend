//! In-memory operational counters for the admin API (docs/ADMIN-API.md): security events since
//! the server started, rolling 24-hour counters, and daily aggregates that are flushed to the
//! `daily_stats` table. Only numbers: nothing here says who did what, and no IP addresses.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;

use sqlx::MySqlPool;

const DAY_MS: i64 = 86_400_000;
const HOUR_MS: i64 = 3_600_000;

/// Unix ms when the server started (set by `init`).
static STARTED_AT: AtomicI64 = AtomicI64::new(0);

pub fn init() {
    let _ = STARTED_AT.compare_exchange(0, crate::now_millis(), Ordering::Relaxed, Ordering::Relaxed);
}

pub fn started_at() -> i64 {
    match STARTED_AT.load(Ordering::Relaxed) {
        0 => crate::now_millis(),
        t => t,
    }
}

// --- security counters (since start) -----------------------------------------------------------

pub static FAILED_AUTH_LOGINS: AtomicU64 = AtomicU64::new(0);
pub static FAILED_TOTP: AtomicU64 = AtomicU64::new(0);
pub static FAILED_ADMIN_AUTH: AtomicU64 = AtomicU64::new(0);
pub static POW_REJECTED: AtomicU64 = AtomicU64::new(0);

pub fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

pub fn get(c: &AtomicU64) -> u64 {
    c.load(Ordering::Relaxed)
}

/// Requests refused by a rate limit, per bucket (the rate-limit key up to its first ':',
/// e.g. "login", "dev", "register"; never the rest of the key, which holds IPs or ids).
static RATE_LIMITED: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());
const MAX_BUCKETS: usize = 64;

pub fn rate_limited(key: &str) {
    let bucket = key.split(':').next().unwrap_or("");
    let bucket = if !bucket.is_empty() && bucket.len() <= 32 && bucket.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        bucket
    } else {
        "other"
    };
    let mut m = RATE_LIMITED.lock().unwrap();
    if let Some(n) = m.get_mut(bucket) {
        *n += 1;
    } else if m.len() < MAX_BUCKETS {
        m.insert(bucket.to_string(), 1);
    } else {
        *m.entry("other".into()).or_default() += 1;
    }
}

pub fn rate_limited_snapshot() -> BTreeMap<String, u64> {
    RATE_LIMITED.lock().unwrap().clone()
}

// --- rolling 24-hour counters ------------------------------------------------------------------

/// Events in the last 24 hours, in hourly slots (the oldest hour is partially included).
pub struct Rolling24h {
    slots: Mutex<[(i64, u64); 24]>,
}

impl Rolling24h {
    pub const fn new() -> Rolling24h {
        Rolling24h { slots: Mutex::new([(-1, 0); 24]) }
    }

    pub fn add_at(&self, now_ms: i64, n: u64) {
        let hour = now_ms.div_euclid(HOUR_MS);
        let mut s = self.slots.lock().unwrap();
        let slot = &mut s[hour.rem_euclid(24) as usize];
        if slot.0 != hour {
            *slot = (hour, 0);
        }
        slot.1 += n;
    }

    pub fn add(&self, n: u64) {
        self.add_at(crate::now_millis(), n)
    }

    pub fn sum_at(&self, now_ms: i64) -> u64 {
        let hour = now_ms.div_euclid(HOUR_MS);
        self.slots
            .lock()
            .unwrap()
            .iter()
            .filter(|(h, _)| *h > hour - 24 && *h <= hour)
            .map(|(_, n)| n)
            .sum()
    }

    pub fn sum(&self) -> u64 {
        self.sum_at(crate::now_millis())
    }
}

pub static TURN_CREDENTIALS_ISSUED: Rolling24h = Rolling24h::new();
pub static PUSHES_SENT: Rolling24h = Rolling24h::new();
pub static PUSH_FAILURES: Rolling24h = Rolling24h::new();

// --- daily statistics (table daily_stats) -----------------------------------------------------

pub const REGISTRATIONS: &str = "registrations";
pub const NEW_DEVICES: &str = "new_devices";
pub const ENVELOPES_SENT: &str = "envelopes_sent";
pub const ATTACHMENTS_UPLOADED: &str = "attachments_uploaded";
pub const DAILY_METRICS: [&str; 4] = [REGISTRATIONS, NEW_DEVICES, ENVELOPES_SENT, ATTACHMENTS_UPLOADED];

/// Increments not yet written to daily_stats: (day, metric) -> count.
static PENDING: Mutex<BTreeMap<(i64, &'static str), i64>> = Mutex::new(BTreeMap::new());

/// Counts `n` events of `metric` today (UTC). Cheap: written to the database by `flush`.
pub fn bump(metric: &'static str, n: i64) {
    if n <= 0 {
        return;
    }
    let day = crate::now_millis().div_euclid(DAY_MS);
    *PENDING.lock().unwrap().entry((day, metric)).or_default() += n;
}

pub fn day_of(ms: i64) -> i64 {
    ms.div_euclid(DAY_MS)
}

/// Writes the pending daily counters (failed writes are kept for the next flush).
pub async fn flush(db: &MySqlPool) {
    let pending = std::mem::take(&mut *PENDING.lock().unwrap());
    for ((day, metric), n) in pending {
        let r = sqlx::query!(
            "INSERT INTO daily_stats (day, metric, value) VALUES (?, ?, ?)
             ON DUPLICATE KEY UPDATE value = value + VALUES(value)",
            day,
            metric,
            n
        )
        .execute(db)
        .await;
        if let Err(e) = r {
            tracing::warn!(error = %e, "write daily statistics failed");
            *PENDING.lock().unwrap().entry((day, metric)).or_default() += n;
        }
    }
}

/// Flushes the daily counters every `interval` (and is aborted at shutdown after a final flush).
pub async fn run_flusher(db: MySqlPool, interval: std::time::Duration) {
    let mut t = tokio::time::interval(interval);
    t.tick().await;
    loop {
        t.tick().await;
        flush(&db).await;
    }
}

/// "YYYY-MM-DD" (UTC) of a day number.
pub fn date_string(day: i64) -> String {
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = day + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rolling_window() {
        let r = Rolling24h::new();
        let t0 = 1_000 * HOUR_MS;
        r.add_at(t0, 2);
        r.add_at(t0 + HOUR_MS, 3);
        assert_eq!(r.sum_at(t0 + HOUR_MS), 5);
        assert_eq!(r.sum_at(t0 + 23 * HOUR_MS), 5);
        assert_eq!(r.sum_at(t0 + 24 * HOUR_MS), 3);
        // The slot of t0 is reused 24 hours later.
        r.add_at(t0 + 24 * HOUR_MS, 1);
        assert_eq!(r.sum_at(t0 + 24 * HOUR_MS), 4);
        assert_eq!(r.sum_at(t0 + 48 * HOUR_MS), 0);
    }

    #[test]
    fn rate_limit_buckets_keep_only_the_prefix() {
        rate_limited("login:ip:203.0.113.9");
        rate_limited("login:number:1234567890123456");
        rate_limited("weird key/with stuff");
        let s = rate_limited_snapshot();
        assert!(s["login"] >= 2);
        assert!(s.keys().all(|k| !k.contains('.') && !k.contains(' ')));
    }

    #[test]
    fn dates() {
        assert_eq!(date_string(0), "1970-01-01");
        assert_eq!(date_string(day_of(951_782_400_000)), "2000-02-29");
        assert_eq!(date_string(day_of(1_790_000_000_123)), "2026-09-21");
    }
}
