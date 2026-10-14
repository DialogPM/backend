//! Adaptive registration proof-of-work: when registrations surge (a bot wave), the server
//! raises the difficulty on its own, one bit at a time (each bit doubles the work), and brings
//! it back down once the wave is over. Admins set the threshold and the ceiling at runtime
//! (settings `pow_adaptive`, `pow_adaptive_threshold`, `pow_adaptive_max_bits`).
//!
//! The extra bits live in memory: a restart goes back to the base difficulty, and the next
//! check (one minute later) raises it again if the wave is still going.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use crate::state::AppState;

/// Bits added on top of the base `pow_bits` right now.
static EXTRA_BITS: AtomicI64 = AtomicI64::new(0);
/// Registrations counted in the last hour at the last check (for the admin dashboard).
static LAST_HOUR: AtomicI64 = AtomicI64::new(0);
/// When the extra bits last changed (ms).
static CHANGED_AT: AtomicI64 = AtomicI64::new(0);

const CHECK_EVERY: Duration = Duration::from_secs(60);
/// While the wave lasts: one more bit at most every 5 minutes.
const RAISE_EVERY_MS: i64 = 5 * 60 * 1000;
/// After it: one bit less at most every 15 minutes.
const LOWER_EVERY_MS: i64 = 15 * 60 * 1000;

/// Difficulty to hand out now (base + adaptive extra, capped by the ceiling).
pub fn effective_bits(st: &AppState) -> i64 {
    let s = st.settings.get();
    if s.pow_bits == 0 {
        return 0; // proof-of-work turned off by the admin: never forced back on
    }
    if !s.pow_adaptive {
        return s.pow_bits;
    }
    (s.pow_bits + EXTRA_BITS.load(Ordering::Relaxed)).min(s.pow_adaptive_max_bits.max(s.pow_bits))
}

/// {base_bits, extra_bits, effective_bits, registrations_last_hour, changed_at} for the admin API.
pub fn status(st: &AppState) -> serde_json::Value {
    let s = st.settings.get();
    serde_json::json!({
        "enabled": s.pow_adaptive,
        "base_bits": s.pow_bits,
        "extra_bits": EXTRA_BITS.load(Ordering::Relaxed),
        "effective_bits": effective_bits(st),
        "threshold_per_hour": s.pow_adaptive_threshold,
        "max_bits": s.pow_adaptive_max_bits,
        "registrations_last_hour": LAST_HOUR.load(Ordering::Relaxed),
        "changed_at": match CHANGED_AT.load(Ordering::Relaxed) { 0 => serde_json::Value::Null, t => t.into() },
    })
}

/// The next extra bits for `count` registrations in the last hour (pure, unit-tested).
fn next_extra(extra: i64, count: i64, threshold: i64, room: i64, since_change_ms: i64) -> i64 {
    if count > threshold && extra < room && since_change_ms >= RAISE_EVERY_MS {
        extra + 1
    } else if count * 2 < threshold && extra > 0 && since_change_ms >= LOWER_EVERY_MS {
        extra - 1
    } else {
        extra
    }
}

pub async fn run(st: AppState) {
    loop {
        tokio::time::sleep(CHECK_EVERY).await;
        let now = crate::now_millis();
        let count: i64 = match sqlx::query_scalar!("SELECT COUNT(*) FROM accounts WHERE created_at >= ?", now - 3_600_000)
            .fetch_one(&st.db)
            .await
        {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(error = %e, "adaptive proof-of-work: cannot count registrations");
                continue;
            }
        };
        LAST_HOUR.store(count, Ordering::Relaxed);
        let s = st.settings.get();
        let extra = EXTRA_BITS.load(Ordering::Relaxed);
        if !s.pow_adaptive || s.pow_bits == 0 {
            if extra != 0 {
                EXTRA_BITS.store(0, Ordering::Relaxed);
                CHANGED_AT.store(now, Ordering::Relaxed);
            }
            continue;
        }
        let room = (s.pow_adaptive_max_bits - s.pow_bits).max(0);
        let since = now - CHANGED_AT.load(Ordering::Relaxed);
        let next = next_extra(extra.min(room), count, s.pow_adaptive_threshold, room, since);
        if next != extra {
            EXTRA_BITS.store(next, Ordering::Relaxed);
            CHANGED_AT.store(now, Ordering::Relaxed);
            tracing::warn!(
                registrations_last_hour = count,
                threshold = s.pow_adaptive_threshold,
                difficulty = s.pow_bits + next,
                "adaptive proof-of-work: registration difficulty {}",
                if next > extra { "raised" } else { "lowered" }
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raises_during_a_wave_and_lowers_after() {
        let long = LOWER_EVERY_MS;
        // Above the threshold: +1, but not more often than every 5 minutes, and never past the room.
        assert_eq!(next_extra(0, 150, 100, 3, RAISE_EVERY_MS), 1);
        assert_eq!(next_extra(1, 150, 100, 3, RAISE_EVERY_MS - 1), 1);
        assert_eq!(next_extra(3, 500, 100, 3, long), 3);
        // Between half the threshold and the threshold: hold.
        assert_eq!(next_extra(2, 80, 100, 3, long), 2);
        // Below half: -1 every 15 minutes, down to 0.
        assert_eq!(next_extra(2, 10, 100, 3, long), 1);
        assert_eq!(next_extra(1, 10, 100, 3, long - 1), 1);
        assert_eq!(next_extra(0, 0, 100, 3, long), 0);
    }
}
