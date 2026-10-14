//! Ring buffer of the last WARN/ERROR log events for GET /v1/admin/logs, fed by a tracing
//! layer. Messages are sanitized: IP addresses and long token-like strings are masked (the
//! server should never log them, this is a second line of defence).

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::{Mutex, OnceLock};

use regex::Regex;
use serde::Serialize;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

pub const CAPACITY: usize = 1000;
const MAX_MESSAGE: usize = 2000;

#[derive(Clone, Debug, Serialize)]
pub struct LogEntry {
    pub ts: i64,
    pub level: &'static str,
    pub target: String,
    pub message: String,
}

static RING: Mutex<VecDeque<LogEntry>> = Mutex::new(VecDeque::new());

/// The tracing layer (add it to the subscriber in main).
pub struct RingLayer;

#[derive(Default)]
struct Collect {
    message: String,
    fields: String,
}

impl Visit for Collect {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.fields, " {}={}", field.name(), value);
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={:?}", field.name(), value);
        }
    }
}

impl<S: Subscriber> Layer<S> for RingLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let level = match *meta.level() {
            Level::ERROR => "error",
            Level::WARN => "warn",
            _ => return,
        };
        let mut c = Collect::default();
        event.record(&mut c);
        let mut message = c.message;
        message.push_str(&c.fields);
        push(LogEntry {
            ts: crate::now_millis(),
            level,
            target: meta.target().to_string(),
            message: sanitize(&message),
        });
    }
}

fn push(e: LogEntry) {
    let mut r = RING.lock().unwrap();
    if r.len() >= CAPACITY {
        r.pop_front();
    }
    r.push_back(e);
}

/// Newest first; `min_level` "warn" returns warnings and errors, "error" only errors.
pub fn recent(min_level: &str, limit: usize) -> Vec<LogEntry> {
    RING.lock()
        .unwrap()
        .iter()
        .rev()
        .filter(|e| min_level != "error" || e.level == "error")
        .take(limit)
        .cloned()
        .collect()
}

/// Masks IPv4 addresses ("x.x.x.x"), IPv6 addresses ("x:x::x") and long base64/hex runs
/// (possible tokens or keys; UUIDs and account numbers are shorter and stay readable).
pub fn sanitize(s: &str) -> String {
    static RES: OnceLock<[Regex; 3]> = OnceLock::new();
    let [v4, v6, token] = RES.get_or_init(|| {
        [
            Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").unwrap(),
            // Anything with "::" or at least 5 colons between hex groups.
            Regex::new(r"(?i)[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}").unwrap(),
            Regex::new(r"[A-Za-z0-9+/_]{32,}={0,2}").unwrap(),
        ]
    });
    let s = v4.replace_all(s, "x.x.x.x");
    let s = v6.replace_all(&s, |c: &regex::Captures| {
        let m = &c[0];
        if m.contains("::") || m.matches(':').count() >= 5 {
            "x:x::x".to_string()
        } else {
            m.to_string()
        }
    });
    let s = token.replace_all(&s, "[redacted]");
    let mut out = s.into_owned();
    if out.len() > MAX_MESSAGE {
        let mut cut = MAX_MESSAGE;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_ips_and_tokens() {
        assert_eq!(sanitize("peer 203.0.113.7:443 failed"), "peer x.x.x.x:443 failed");
        assert_eq!(sanitize("from 2001:db8::1 ok"), "from x:x::x ok");
        assert_eq!(sanitize("from fe80:0:0:0:1:2:3:4 ok"), "from x:x::x ok");
        assert_eq!(sanitize("at ::1"), "at x:x::x");
        assert_eq!(sanitize("token=abcdefghijklmnopqrstuvwxyzABCDEF0123456789 end"), "token=[redacted] end");
        // Account ids, times and short values stay readable.
        let id = "account=0b6c8a52-3c1e-4f0e-9a43-2d4f7d1e8b11 at 12:30";
        assert_eq!(sanitize(id), id);
        assert_eq!(sanitize("version 1.0.0"), "version 1.0.0");
    }

    #[test]
    fn ring_keeps_the_newest() {
        for i in 0..(CAPACITY + 5) {
            push(LogEntry { ts: i as i64, level: if i % 2 == 0 { "warn" } else { "error" }, target: "t".into(), message: format!("m{i}") });
        }
        let all = recent("warn", 5000);
        assert!(all.len() <= CAPACITY);
        assert_eq!(all[0].ts, (CAPACITY + 4) as i64);
        assert!(recent("error", 10).iter().all(|e| e.level == "error"));
        assert_eq!(recent("warn", 3).len(), 3);
    }
}
