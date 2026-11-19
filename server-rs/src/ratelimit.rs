//! In-memory token bucket rate limiting keyed by strings (IP, number, account, device).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// `burst` requests per `window`, refilled continuously.
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct Rule {
    pub burst: u32,
    pub window: Duration,
}

impl Rule {
    pub const fn new(burst: u32, window: Duration) -> Rule {
        Rule { burst, window }
    }
    pub fn disabled(&self) -> bool {
        self.burst == 0 || self.window.is_zero()
    }
    fn rate(&self) -> f64 {
        self.burst as f64 / self.window.as_secs_f64()
    }
}

struct Bucket {
    tokens: f64,
    last: Instant,
    rule: Rule,
}

#[derive(Default)]
pub struct Limiter {
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl Limiter {
    pub fn new() -> Limiter {
        Limiter::default()
    }

    /// Consumes one token; on refusal returns how long until one is available.
    pub fn allow(&self, key: &str, rule: Rule) -> Result<(), Duration> {
        self.allow_n(key, rule, 1)
    }

    /// Consumes `n` tokens at once (e.g. one per envelope of a fan-out); on refusal returns
    /// how long until they are all available. `n` above the burst is never allowed.
    pub fn allow_n(&self, key: &str, rule: Rule, n: u32) -> Result<(), Duration> {
        if rule.disabled() || n == 0 {
            return Ok(());
        }
        let n = n as f64;
        let now = Instant::now();
        let mut map = self.buckets.lock().unwrap();
        let b = map.entry(key.to_string()).or_insert(Bucket {
            tokens: rule.burst as f64,
            last: now,
            rule,
        });
        if b.rule != rule {
            *b = Bucket {
                tokens: rule.burst as f64,
                last: now,
                rule,
            };
        } else {
            let elapsed = now.duration_since(b.last).as_secs_f64();
            b.tokens = (b.tokens + elapsed * rule.rate()).min(rule.burst as f64);
            b.last = now;
        }
        if b.tokens >= n {
            b.tokens -= n;
            return Ok(());
        }
        let wait = Duration::from_secs_f64((n.min(rule.burst as f64) - b.tokens) / rule.rate());
        Err(wait.max(Duration::from_secs(1)))
    }

    /// Removes buckets that have fully refilled; returns how many.
    pub fn cleanup(&self) -> usize {
        let now = Instant::now();
        let mut map = self.buckets.lock().unwrap();
        let before = map.len();
        map.retain(|_, b| {
            b.tokens + now.duration_since(b.last).as_secs_f64() * b.rule.rate()
                < b.rule.burst as f64
        });
        before - map.len()
    }
}

/// The API's rate limit table (docs/API.md section 12).
#[derive(Clone, Copy, Debug, Default)]
pub struct Rules {
    pub register_ip: Rule,
    /// Applied separately to prelogin and login.
    pub login_ip: Rule,
    /// Applied separately to prelogin and login.
    pub login_number: Rule,
    /// Shared by challenge and recover.
    pub recover_ip: Rule,
    pub directory_number: Rule,
    pub directory_phones: Rule,
    pub phone_code: Rule,
    /// Per device, every authenticated request.
    pub authenticated_user: Rule,
    /// Anonymous (sealed sender) deliveries per IP.
    pub sealed_ip: Rule,
    /// Anonymous pre-key fetches per IP.
    pub sealed_keys_ip: Rule,
    /// Password checks of a logged-in account (change password, delete).
    pub password_account: Rule,
    /// Two-step codes per account and day, on top of login_number.
    pub totp_daily: Rule,
    /// Verification SMS per destination number.
    pub phone_number: Rule,
    /// Group invite link lookups and joins per account.
    pub invite_account: Rule,
    /// Spam reports per reporting account.
    pub report_account: Rule,
    /// Long polls of a login waiting for approval, per IP.
    pub login_poll_ip: Rule,
    /// Revocation checks of (possibly locked) devices, per IP.
    pub revocation_ip: Rule,
    /// Pre-key bundle fetches per (fetching account, target account): every fetch consumes
    /// one-time keys of the target, so this bounds how fast one account can drain another.
    pub keys_pair: Rule,
    /// Pre-key bundle fetches per target account, all fetchers together (authenticated and
    /// sealed).
    pub keys_target: Rule,
    /// Call offers (sends with a `call_id`) per sender (account, or IP for sealed sends).
    pub call_sender: Rule,
    /// Call offers per (sender, destination account).
    pub call_pair: Rule,
    /// Envelopes (one per recipient device) of group v2 sends, per sending account.
    pub group_send_account: Rule,
    /// `POST /v2/groups/devices` lookups per account.
    pub group_devices_account: Rule,
    /// Bytes of message content stored per sender (account, or IP for sealed sends): bounds
    /// how fast one sender can fill recipients' queues.
    pub send_bytes_sender: Rule,
    /// `PATCH /v2/groups` per group, all members together (the change log grows per change).
    pub group_modify: Rule,
    /// Pages of `GET /v1/kt/entries` per IP (the log lists every account id).
    pub kt_entries_ip: Rule,
}

impl Rules {
    pub fn defaults() -> Rules {
        let min = |m: u64| Duration::from_secs(60 * m);
        Rules {
            register_ip: Rule::new(5, min(60)),
            login_ip: Rule::new(20, min(10)),
            login_number: Rule::new(10, min(10)),
            recover_ip: Rule::new(10, min(60)),
            directory_number: Rule::new(60, min(1)),
            directory_phones: Rule::new(10, min(60)),
            phone_code: Rule::new(5, min(60)),
            authenticated_user: Rule::new(600, min(1)),
            sealed_ip: Rule::new(600, min(1)),
            sealed_keys_ip: Rule::new(60, min(1)),
            password_account: Rule::new(10, min(10)),
            totp_daily: Rule::new(30, min(24 * 60)),
            phone_number: Rule::new(3, min(60)),
            invite_account: Rule::new(30, min(10)),
            report_account: Rule::new(20, min(24 * 60)),
            login_poll_ip: Rule::new(120, min(10)),
            revocation_ip: Rule::new(60, min(10)),
            keys_pair: Rule::new(20, min(60)),
            keys_target: Rule::new(1000, min(60)),
            call_sender: Rule::new(10, min(1)),
            call_pair: Rule::new(3, min(1)),
            // 2 000 envelopes per minute sustained: ~4 messages per minute to a 256-member
            // group with two devices each, with a burst of ten times that.
            group_send_account: Rule::new(20_000, min(10)),
            group_devices_account: Rule::new(60, min(1)),
            // 1 GiB per 10 minutes: a 256 KiB message to a 256-member group with two devices
            // each is 128 MiB of stored content, so this allows a handful of those.
            send_bytes_sender: Rule::new(1 << 30, min(10)),
            group_modify: Rule::new(60, min(1)),
            kt_entries_ip: Rule::new(120, min(10)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket() {
        let l = Limiter::new();
        let r = Rule::new(2, Duration::from_secs(60));
        assert!(l.allow("k", r).is_ok());
        assert!(l.allow("k", r).is_ok());
        assert!(l.allow("k", r).is_err());
        assert!(l.allow("other", r).is_ok());
        assert!(l.allow("k", Rule::default()).is_ok());
    }

    #[test]
    fn bucket_n() {
        let l = Limiter::new();
        let r = Rule::new(10, Duration::from_secs(60));
        assert!(l.allow_n("k", r, 4).is_ok());
        assert!(l.allow_n("k", r, 6).is_ok());
        assert!(l.allow_n("k", r, 1).is_err());
        // More than the burst can never be granted; the wait is bounded by the burst.
        assert!(l.allow_n("fresh", r, 11).unwrap_err() <= Duration::from_secs(61));
        assert!(l.allow_n("fresh", r, 0).is_ok());
        assert!(l.allow_n("fresh", Rule::default(), 50).is_ok());
    }
}
