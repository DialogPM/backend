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

impl Bucket {
    /// How full the bucket would be now, from 0 (spent) to 1 (refilled: forgetting it changes
    /// nothing).
    fn fill(&self, now: Instant) -> f64 {
        let tokens = self.tokens + now.duration_since(self.last).as_secs_f64() * self.rule.rate();
        (tokens / self.rule.burst as f64).min(1.0)
    }
}

/// Buckets kept at most (about 150 bytes each). Many keys are chosen by the caller (numbers,
/// addresses, account pairs), so without a bound the map could be grown at will.
pub const MAX_BUCKETS: usize = 500_000;

pub struct Limiter {
    buckets: Mutex<HashMap<String, Bucket>>,
    capacity: usize,
}

impl Default for Limiter {
    fn default() -> Limiter {
        Limiter::with_capacity(MAX_BUCKETS)
    }
}

impl Limiter {
    pub fn new() -> Limiter {
        Limiter::default()
    }

    pub fn with_capacity(capacity: usize) -> Limiter {
        Limiter { buckets: Mutex::new(HashMap::new()), capacity: capacity.max(2) }
    }

    /// Makes room for a new bucket in a full map. Refilled buckets go first (forgetting them
    /// changes nothing). Then, down to seven eighths of the capacity (so that the scan is not
    /// repeated for every new key), the fullest go: a forgotten bucket starts over full, so this
    /// gives back the least, and a caller that has spent its budget is the last to be
    /// forgotten, however many other keys it creates.
    fn make_room(map: &mut HashMap<String, Bucket>, capacity: usize, now: Instant) {
        map.retain(|_, b| b.fill(now) < 1.0);
        let target = capacity - (capacity / 8).max(1);
        if map.len() <= target {
            return;
        }
        let mut fills: Vec<f64> = map.values().map(|b| b.fill(now)).collect();
        let k = fills.len() - target;
        let idx = fills.len() - k;
        let (_, threshold, _) = fills.select_nth_unstable_by(idx, |a, b| a.total_cmp(b));
        let threshold = *threshold;
        let mut left = k;
        map.retain(|_, b| {
            if left > 0 && b.fill(now) >= threshold {
                left -= 1;
                false
            } else {
                true
            }
        });
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
        if map.len() >= self.capacity && !map.contains_key(key) {
            Self::make_room(&mut map, self.capacity, now);
        }
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
        map.retain(|_, b| b.fill(now) < 1.0);
        before - map.len()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.lock().unwrap().len()
    }
}

/// A token bucket owned by one caller (e.g. one WebSocket connection), outside any shared map.
pub struct LocalBucket {
    tokens: f64,
    last: Instant,
    rule: Rule,
}

impl LocalBucket {
    /// Starts full.
    pub fn new(rule: Rule) -> LocalBucket {
        LocalBucket { tokens: rule.burst as f64, last: Instant::now(), rule }
    }

    /// Consumes `n` tokens (at most the burst) if available; otherwise consumes nothing and
    /// returns how long until they are.
    pub fn take(&mut self, n: u32) -> Result<(), Duration> {
        if self.rule.disabled() {
            return Ok(());
        }
        let now = Instant::now();
        let n = (n as f64).min(self.rule.burst as f64);
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rule.rate())
            .min(self.rule.burst as f64);
        self.last = now;
        if self.tokens >= n {
            self.tokens -= n;
            return Ok(());
        }
        Err(Duration::from_secs_f64((n - self.tokens) / self.rule.rate()))
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
    /// `POST /v2/groups` per IP, on top of the anonymous group request limit: a created group
    /// is stored until its last member leaves, and the server cannot tell who created it.
    pub group_create_ip: Rule,
    /// Polls of device link sessions per IP (clients poll every 1.5 s, two devices per link).
    pub provision_poll_ip: Rule,
    /// zkgroup auth credential requests per account (clients fetch a week at a time).
    pub zk_credentials_account: Rule,
    /// Bot API calls with a token that is not a bot's, per IP.
    pub bot_token_ip: Rule,
    /// Messages one bot sends, all chats together.
    pub bot_send: Rule,
    /// Messages one bot sends to one chat.
    pub bot_send_chat: Rule,
    /// Messages an account sends to bots.
    pub bot_message_account: Rule,
    /// Bots created, changed or deleted per account.
    pub bot_manage_account: Rule,
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
            group_create_ip: Rule::new(30, min(10)),
            // 2 per second sustained: two devices of one link polling, with room for others
            // behind the same address.
            provision_poll_ip: Rule::new(1200, min(10)),
            zk_credentials_account: Rule::new(30, min(60)),
            bot_token_ip: Rule::new(30, min(10)),
            // 30 per second sustained, like the Telegram Bot API.
            bot_send: Rule::new(1800, min(1)),
            bot_send_chat: Rule::new(60, min(1)),
            bot_message_account: Rule::new(120, min(1)),
            bot_manage_account: Rule::new(60, min(10)),
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

    #[test]
    fn disabled_rules() {
        assert!(Rule::default().disabled());
        assert!(Rule::new(0, Duration::from_secs(60)).disabled());
        assert!(Rule::new(5, Duration::ZERO).disabled());
        assert!(!Rule::new(1, Duration::from_millis(1)).disabled());
        // A disabled rule never creates a bucket.
        let l = Limiter::new();
        for _ in 0..100 {
            assert!(l.allow("k", Rule::default()).is_ok());
        }
        assert_eq!(l.cleanup(), 0);
    }

    #[test]
    fn refusal_says_how_long_to_wait() {
        let l = Limiter::new();
        let r = Rule::new(1, Duration::from_secs(600));
        assert!(l.allow("k", r).is_ok());
        let wait = l.allow("k", r).unwrap_err();
        // One token per 600 s, nothing refilled yet.
        assert!(wait > Duration::from_secs(590) && wait <= Duration::from_secs(600), "{wait:?}");
        // Never less than a second, however fast the rule refills.
        let fast = Rule::new(1, Duration::from_secs(2));
        assert!(l.allow("f", fast).is_ok());
        assert!(l.allow("f", fast).unwrap_err() >= Duration::from_secs(1));
    }

    #[test]
    fn tokens_refill_over_time() {
        let l = Limiter::new();
        let r = Rule::new(2, Duration::from_millis(40));
        assert!(l.allow_n("k", r, 2).is_ok());
        assert!(l.allow("k", r).is_err());
        std::thread::sleep(Duration::from_millis(60));
        // Refilled, but never above the burst.
        assert!(l.allow_n("k", r, 2).is_ok());
        assert!(l.allow("k", r).is_err());
    }

    #[test]
    fn a_changed_rule_starts_a_fresh_bucket() {
        let l = Limiter::new();
        let small = Rule::new(1, Duration::from_secs(60));
        let big = Rule::new(3, Duration::from_secs(60));
        assert!(l.allow("k", small).is_ok());
        assert!(l.allow("k", small).is_err());
        assert!(l.allow_n("k", big, 3).is_ok());
        assert!(l.allow("k", big).is_err());
    }

    #[test]
    fn cleanup_keeps_buckets_that_are_still_limiting() {
        let l = Limiter::new();
        assert!(l.allow("slow", Rule::new(1, Duration::from_secs(600))).is_ok());
        assert!(l.allow("fast", Rule::new(1, Duration::from_millis(5))).is_ok());
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(l.cleanup(), 1, "only the refilled bucket goes");
        assert!(l.allow("slow", Rule::new(1, Duration::from_secs(600))).is_err());
        assert_eq!(l.cleanup(), 0);
    }

    #[test]
    fn the_map_is_bounded_and_spent_buckets_survive_eviction() {
        let l = Limiter::with_capacity(64);
        let r = Rule::new(10, Duration::from_secs(600));
        // The attacker's own bucket, spent.
        assert!(l.allow_n("me", r, 10).is_ok());
        assert!(l.allow("me", r).is_err());
        // Fresh keys (one token used each) fill the map many times over.
        for i in 0..10_000 {
            let _ = l.allow(&format!("k{i}"), r);
            assert!(l.len() <= 64, "map grew to {}", l.len());
        }
        // The spent bucket was never forgotten: still refused.
        assert!(l.allow("me", r).is_err());
    }

    #[test]
    fn eviction_prefers_refilled_buckets() {
        let l = Limiter::with_capacity(8);
        let slow = Rule::new(2, Duration::from_secs(600));
        let fast = Rule::new(1, Duration::from_millis(5));
        for i in 0..4 {
            assert!(l.allow_n(&format!("spent{i}"), slow, 2).is_ok());
        }
        for i in 0..4 {
            assert!(l.allow(&format!("fast{i}"), fast).is_ok());
        }
        std::thread::sleep(Duration::from_millis(30));
        assert!(l.allow("new", slow).is_ok());
        for i in 0..4 {
            assert!(l.allow(&format!("spent{i}"), slow).is_err(), "spent{i} was reset");
        }
    }

    #[test]
    fn local_bucket() {
        let mut b = LocalBucket::new(Rule::new(3, Duration::from_secs(3)));
        assert!(b.take(2).is_ok());
        assert!(b.take(1).is_ok());
        let wait = b.take(1).unwrap_err();
        assert!(wait > Duration::from_millis(900) && wait <= Duration::from_secs(1), "{wait:?}");
        // More than the burst costs the whole burst, never more.
        let mut b = LocalBucket::new(Rule::new(3, Duration::from_secs(3)));
        assert!(b.take(50).is_ok());
        assert!(b.take(1).is_err());
        let mut off = LocalBucket::new(Rule::default());
        for _ in 0..100 {
            assert!(off.take(1000).is_ok());
        }
    }

    #[test]
    fn default_table_limits_everything() {
        let d = Rules::defaults();
        for (name, r) in [
            ("register_ip", d.register_ip), ("login_ip", d.login_ip), ("login_number", d.login_number),
            ("recover_ip", d.recover_ip), ("directory_number", d.directory_number),
            ("directory_phones", d.directory_phones), ("phone_code", d.phone_code),
            ("authenticated_user", d.authenticated_user), ("sealed_ip", d.sealed_ip),
            ("sealed_keys_ip", d.sealed_keys_ip), ("password_account", d.password_account),
            ("totp_daily", d.totp_daily), ("phone_number", d.phone_number),
            ("invite_account", d.invite_account), ("report_account", d.report_account),
            ("login_poll_ip", d.login_poll_ip), ("revocation_ip", d.revocation_ip),
            ("keys_pair", d.keys_pair), ("keys_target", d.keys_target), ("call_sender", d.call_sender),
            ("call_pair", d.call_pair), ("group_send_account", d.group_send_account),
            ("group_devices_account", d.group_devices_account), ("send_bytes_sender", d.send_bytes_sender),
            ("group_modify", d.group_modify), ("kt_entries_ip", d.kt_entries_ip),
            ("group_create_ip", d.group_create_ip), ("provision_poll_ip", d.provision_poll_ip),
            ("zk_credentials_account", d.zk_credentials_account),
        ] {
            assert!(!r.disabled(), "{name} is not limited");
        }
        // The all-zero table (rate limits switched off) limits nothing.
        assert!(Rules::default().register_ip.disabled());
    }
}
