//! Settings an admin can change at runtime (PUT /v1/admin/settings, docs/ADMIN-API.md).
//! Defaults come from the environment (`Config`); overrides are stored in `admin_settings`
//! and applied at startup, so they survive restarts. Handlers read the current values with
//! `st.settings.get()`.

use std::sync::RwLock;

use serde_json::{json, Map, Value};
use sqlx::MySqlPool;

use crate::config::Config;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub registration_enabled: bool,
    /// Leading zero bits required by the registration proof-of-work; 0 disables it.
    pub pow_bits: i64,
    pub max_devices: i64,
    pub attachment_max_bytes: i64,
    /// Linked devices not seen for this many days are unlinked; 0 disables.
    pub inactive_device_days: i64,
    /// Undelivered messages (queued envelopes) are deleted after this many days.
    pub message_ttl_days: i64,
    /// Raise the proof-of-work automatically during a registration surge (adaptive_pow.rs).
    pub pow_adaptive: bool,
    /// Registrations per hour above which the difficulty goes up.
    pub pow_adaptive_threshold: i64,
    /// Ceiling of the adaptive difficulty (bits).
    pub pow_adaptive_max_bits: i64,
    /// Client versions announced in `/v1/info` (`client_versions`), in the order of
    /// [`VERSION_NAMES`], packed by [`parse_version`]; 0 = not announced. An app older than
    /// "latest" offers the update, one older than "min" requires it.
    pub client_versions: [i64; 6],
}

/// Version settings (strings "major.minor.patch", "" = not announced), per platform.
pub const VERSION_NAMES: [&str; 6] = [
    "client_latest_desktop",
    "client_min_desktop",
    "client_latest_android",
    "client_min_android",
    "client_latest_ios",
    "client_min_ios",
];

/// "1.2.3" as a comparable number (each part 0..=9999); "" is 0. None when malformed.
pub fn parse_version(v: &str) -> Option<i64> {
    if v.is_empty() {
        return Some(0);
    }
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let mut n = 0i64;
    for p in parts {
        if p.is_empty() || p.len() > 4 || !p.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        n = n * 10_000 + p.parse::<i64>().ok()?;
    }
    Some(n)
}

/// The inverse of [`parse_version`].
pub fn format_version(n: i64) -> String {
    if n <= 0 {
        return String::new();
    }
    format!("{}.{}.{}", n / 100_000_000, n / 10_000 % 10_000, n % 10_000)
}

impl Settings {
    /// `client_versions` of `/v1/info`: {platform: {"latest", "min"}} with only what is set,
    /// None when nothing is announced.
    pub fn client_versions_json(&self) -> Option<Value> {
        let mut out = Map::new();
        for (i, platform) in ["desktop", "android", "ios"].into_iter().enumerate() {
            let mut m = Map::new();
            for (j, key) in ["latest", "min"].into_iter().enumerate() {
                let v = self.client_versions[i * 2 + j];
                if v > 0 {
                    m.insert(key.into(), Value::String(format_version(v)));
                }
            }
            if !m.is_empty() {
                out.insert(platform.into(), Value::Object(m));
            }
        }
        (!out.is_empty()).then_some(Value::Object(out))
    }
}

impl Settings {
    pub fn from_config(c: &Config) -> Settings {
        Settings {
            registration_enabled: c.registration_enabled,
            pow_bits: c.registration_pow_bits,
            max_devices: c.max_devices,
            attachment_max_bytes: c.attachment_max_bytes,
            inactive_device_days: c.inactive_device_days,
            message_ttl_days: c.message_ttl_days,
            pow_adaptive: true,
            pow_adaptive_threshold: 100,
            // ~10 s on a phone (each bit doubles the work of the default 20 bits).
            pow_adaptive_max_bits: 23,
            client_versions: [0; 6],
        }
    }
}

pub const NAMES: [&str; 15] = [
    "registration_enabled",
    "pow_bits",
    "max_devices",
    "attachment_max_bytes",
    "inactive_device_days",
    "message_ttl_days",
    "pow_adaptive",
    "pow_adaptive_threshold",
    "pow_adaptive_max_bits",
    "client_latest_desktop",
    "client_min_desktop",
    "client_latest_android",
    "client_min_android",
    "client_latest_ios",
    "client_min_ios",
];

/// Inclusive range of the integer settings an admin may set.
pub fn range(name: &str) -> Option<(i64, i64)> {
    Some(match name {
        "pow_bits" => (0, 28),
        "max_devices" => (1, 20),
        "attachment_max_bytes" => (1 << 20, 2 << 30),
        "inactive_device_days" => (7, 365),
        "message_ttl_days" => (1, 365),
        "pow_adaptive_threshold" => (10, 100_000),
        "pow_adaptive_max_bits" => (0, 28),
        _ => return None,
    })
}

/// A validated change: Some(value) sets an override, None removes it (back to the env value).
pub type Change = (&'static str, Option<Value>);

/// Validates a PUT body (any subset of the settings; `null` resets one to its env value).
pub fn validate_changes(body: &Value) -> Result<Vec<Change>, String> {
    let obj = body.as_object().ok_or("body must be a JSON object")?;
    if obj.is_empty() {
        return Err("no settings given".into());
    }
    let mut out = Vec::new();
    for (k, v) in obj {
        let Some(name) = NAMES.iter().copied().find(|n| *n == k.as_str()) else {
            return Err(format!("unknown setting {k:?}"));
        };
        if v.is_null() {
            out.push((name, None));
            continue;
        }
        if VERSION_NAMES.contains(&name) {
            let text = v.as_str().map(str::trim).ok_or_else(|| format!("{name} must be a string"))?;
            let n = parse_version(text).ok_or_else(|| format!("{name} must be a version like 1.2.3, or empty"))?;
            out.push((name, Some(Value::String(format_version(n)))));
            continue;
        }
        let value = match range(name) {
            None => Value::Bool(v.as_bool().ok_or_else(|| format!("{name} must be a boolean"))?),
            Some((min, max)) => {
                let n = v
                    .as_i64()
                    .filter(|n| (min..=max).contains(n))
                    .ok_or_else(|| format!("{name} must be an integer in {min}..{max}"))?;
                Value::from(n)
            }
        };
        out.push((name, Some(value)));
    }
    Ok(out)
}

fn apply(s: &mut Settings, name: &str, v: &Value) -> bool {
    match (name, v) {
        ("registration_enabled", Value::Bool(b)) => s.registration_enabled = *b,
        ("pow_bits", v) if v.is_i64() => s.pow_bits = v.as_i64().unwrap_or_default(),
        ("max_devices", v) if v.is_i64() => s.max_devices = v.as_i64().unwrap_or_default(),
        ("attachment_max_bytes", v) if v.is_i64() => s.attachment_max_bytes = v.as_i64().unwrap_or_default(),
        ("inactive_device_days", v) if v.is_i64() => s.inactive_device_days = v.as_i64().unwrap_or_default(),
        ("message_ttl_days", v) if v.is_i64() => s.message_ttl_days = v.as_i64().unwrap_or_default(),
        ("pow_adaptive", Value::Bool(b)) => s.pow_adaptive = *b,
        ("pow_adaptive_threshold", v) if v.is_i64() => s.pow_adaptive_threshold = v.as_i64().unwrap_or_default(),
        ("pow_adaptive_max_bits", v) if v.is_i64() => s.pow_adaptive_max_bits = v.as_i64().unwrap_or_default(),
        (name, Value::String(text)) => match (VERSION_NAMES.iter().position(|n| *n == name), parse_version(text)) {
            (Some(i), Some(n)) => s.client_versions[i] = n,
            _ => return false,
        },
        _ => return false,
    }
    true
}

struct Current {
    values: Settings,
    /// Names whose value comes from admin_settings.
    overridden: Vec<&'static str>,
}

pub struct Runtime {
    env: Settings,
    cur: RwLock<Current>,
}

impl Runtime {
    pub fn new(env: Settings) -> Runtime {
        Runtime { env, cur: RwLock::new(Current { values: env, overridden: Vec::new() }) }
    }

    /// The current values (copy).
    pub fn get(&self) -> Settings {
        self.cur.read().unwrap().values
    }

    /// Applies validated changes in memory (after they were stored).
    pub fn apply_changes(&self, changes: &[Change]) {
        let mut cur = self.cur.write().unwrap();
        for (name, v) in changes {
            cur.overridden.retain(|n| n != name);
            match v {
                Some(v) => {
                    if apply(&mut cur.values, name, v) {
                        cur.overridden.push(name);
                    }
                }
                None => {
                    let env = self.env_value(name);
                    apply(&mut cur.values, name, &env);
                }
            }
        }
    }

    fn env_value(&self, name: &str) -> Value {
        value_of(&self.env, name)
    }

    /// {name: {value, source: "env"|"override"}} for every setting.
    pub fn describe(&self) -> Value {
        let cur = self.cur.read().unwrap();
        let mut m = Map::new();
        for name in NAMES {
            let source = if cur.overridden.contains(&name) { "override" } else { "env" };
            m.insert(name.into(), json!({"value": value_of(&cur.values, name), "source": source}));
        }
        Value::Object(m)
    }

    /// Loads the stored overrides (startup). Invalid stored values are ignored with a warning.
    pub async fn load(&self, db: &MySqlPool) -> Result<(), sqlx::Error> {
        let rows = sqlx::query!("SELECT name AS `name: String`, value AS `value: String` FROM admin_settings")
            .fetch_all(db)
            .await?;
        let mut changes = Vec::new();
        for r in rows {
            let (name, raw) = (r.name, r.value);
            let parsed = serde_json::from_str::<Value>(&raw).ok().map(|v| {
                let mut m = Map::new();
                m.insert(name.clone(), v);
                Value::Object(m)
            });
            match parsed.as_ref().map(validate_changes) {
                Some(Ok(mut c)) => changes.append(&mut c),
                _ => tracing::warn!(setting = %name, "ignoring invalid stored admin setting"),
            }
        }
        if !changes.is_empty() {
            tracing::info!(count = changes.len(), "applied admin setting overrides");
        }
        self.apply_changes(&changes);
        Ok(())
    }

    /// Stores and applies validated changes.
    pub async fn save(&self, db: &MySqlPool, changes: &[Change]) -> Result<(), sqlx::Error> {
        let mut tx = db.begin().await?;
        for (name, v) in changes {
            match v {
                Some(v) => {
                    let value = v.to_string();
                    let now = crate::now_millis();
                    sqlx::query!("REPLACE INTO admin_settings (name, value, updated_at) VALUES (?, ?, ?)", name, value, now)
                        .execute(&mut *tx)
                        .await?;
                }
                None => {
                    sqlx::query!("DELETE FROM admin_settings WHERE name = ?", name).execute(&mut *tx).await?;
                }
            }
        }
        tx.commit().await?;
        self.apply_changes(changes);
        Ok(())
    }
}

fn value_of(s: &Settings, name: &str) -> Value {
    match name {
        "registration_enabled" => Value::Bool(s.registration_enabled),
        "pow_bits" => s.pow_bits.into(),
        "max_devices" => s.max_devices.into(),
        "attachment_max_bytes" => s.attachment_max_bytes.into(),
        "inactive_device_days" => s.inactive_device_days.into(),
        "message_ttl_days" => s.message_ttl_days.into(),
        "pow_adaptive" => Value::Bool(s.pow_adaptive),
        "pow_adaptive_threshold" => s.pow_adaptive_threshold.into(),
        "pow_adaptive_max_bits" => s.pow_adaptive_max_bits.into(),
        name => match VERSION_NAMES.iter().position(|n| *n == name) {
            Some(i) => Value::String(format_version(s.client_versions[i])),
            None => Value::Null,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Settings {
        Settings::from_config(&Config::default())
    }

    #[test]
    fn validation_ranges() {
        let ok = |v: Value| validate_changes(&v).is_ok();
        assert!(ok(json!({"pow_bits": 0})));
        assert!(ok(json!({"pow_bits": 28})));
        assert!(!ok(json!({"pow_bits": 29})));
        assert!(!ok(json!({"pow_bits": -1})));
        assert!(!ok(json!({"pow_bits": 20.5})));
        assert!(!ok(json!({"pow_bits": "20"})));
        assert!(ok(json!({"max_devices": 1})));
        assert!(ok(json!({"max_devices": 20})));
        assert!(!ok(json!({"max_devices": 0})));
        assert!(!ok(json!({"max_devices": 21})));
        assert!(ok(json!({"attachment_max_bytes": 1 << 20})));
        assert!(ok(json!({"attachment_max_bytes": 2i64 << 30})));
        assert!(!ok(json!({"attachment_max_bytes": (1 << 20) - 1})));
        assert!(!ok(json!({"attachment_max_bytes": (2i64 << 30) + 1})));
        assert!(ok(json!({"inactive_device_days": 7})));
        assert!(ok(json!({"inactive_device_days": 365})));
        assert!(!ok(json!({"inactive_device_days": 6})));
        assert!(!ok(json!({"inactive_device_days": 366})));
        assert!(ok(json!({"registration_enabled": false})));
        assert!(!ok(json!({"registration_enabled": 0})));
        assert!(!ok(json!({"unknown": 1})));
        assert!(!ok(json!({})));
        assert!(!ok(json!([1])));
        assert!(ok(json!({"max_devices": null})));
    }

    #[test]
    fn overrides_and_reset() {
        let rt = Runtime::new(env());
        let c = validate_changes(&json!({"max_devices": 3, "registration_enabled": false})).unwrap();
        rt.apply_changes(&c);
        assert_eq!(rt.get().max_devices, 3);
        assert!(!rt.get().registration_enabled);
        let d = rt.describe();
        assert_eq!(d["max_devices"], json!({"value": 3, "source": "override"}));
        assert_eq!(d["pow_bits"], json!({"value": 20, "source": "env"}));
        rt.apply_changes(&validate_changes(&json!({"max_devices": null})).unwrap());
        assert_eq!(rt.get().max_devices, 6);
        assert_eq!(rt.describe()["max_devices"]["source"], "env");
        assert_eq!(rt.describe()["registration_enabled"]["source"], "override");
    }

    #[test]
    fn client_versions() {
        assert_eq!(parse_version(""), Some(0));
        assert_eq!(parse_version("1.0.1"), Some(100_000_001));
        assert!(parse_version("0.1.10") > parse_version("0.1.9"));
        assert!(parse_version("1.0.0") > parse_version("0.99.99"));
        for bad in ["1.0", "1.0.0.0", "1.0.x", "v1.0.0", "1..0", "1.0.12345", " 1.0.0"] {
            assert_eq!(parse_version(bad), None, "{bad}");
        }
        assert_eq!(format_version(parse_version("12.3.45").unwrap()), "12.3.45");
        let ok = |v: Value| validate_changes(&v).is_ok();
        assert!(ok(json!({"client_latest_ios": "1.0.1"})));
        assert!(ok(json!({"client_min_ios": ""})));
        assert!(!ok(json!({"client_latest_ios": "1.0"})));
        assert!(!ok(json!({"client_latest_ios": 101})));

        let rt = Runtime::new(env());
        assert_eq!(rt.get().client_versions_json(), None);
        assert_eq!(rt.describe()["client_latest_desktop"], json!({"value": "", "source": "env"}));
        rt.apply_changes(&validate_changes(&json!({"client_latest_desktop": "0.1.2", "client_min_desktop": "0.1.0", "client_latest_ios": " 1.0.1 "})).unwrap());
        assert_eq!(
            rt.get().client_versions_json(),
            Some(json!({"desktop": {"latest": "0.1.2", "min": "0.1.0"}, "ios": {"latest": "1.0.1"}}))
        );
        assert_eq!(rt.describe()["client_latest_ios"], json!({"value": "1.0.1", "source": "override"}));
        rt.apply_changes(&validate_changes(&json!({"client_latest_ios": null, "client_min_desktop": ""})).unwrap());
        assert_eq!(rt.get().client_versions_json(), Some(json!({"desktop": {"latest": "0.1.2"}})));
    }
}
