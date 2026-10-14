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
    /// Raise the proof-of-work automatically during a registration surge (adaptive_pow.rs).
    pub pow_adaptive: bool,
    /// Registrations per hour above which the difficulty goes up.
    pub pow_adaptive_threshold: i64,
    /// Ceiling of the adaptive difficulty (bits).
    pub pow_adaptive_max_bits: i64,
}

impl Settings {
    pub fn from_config(c: &Config) -> Settings {
        Settings {
            registration_enabled: c.registration_enabled,
            pow_bits: c.registration_pow_bits,
            max_devices: c.max_devices,
            attachment_max_bytes: c.attachment_max_bytes,
            inactive_device_days: c.inactive_device_days,
            pow_adaptive: true,
            pow_adaptive_threshold: 100,
            // ~10 s on a phone (each bit doubles the work of the default 20 bits).
            pow_adaptive_max_bits: 23,
        }
    }
}

pub const NAMES: [&str; 8] = [
    "registration_enabled",
    "pow_bits",
    "max_devices",
    "attachment_max_bytes",
    "inactive_device_days",
    "pow_adaptive",
    "pow_adaptive_threshold",
    "pow_adaptive_max_bits",
];

/// Inclusive range of the integer settings an admin may set.
pub fn range(name: &str) -> Option<(i64, i64)> {
    Some(match name {
        "pow_bits" => (0, 28),
        "max_devices" => (1, 20),
        "attachment_max_bytes" => (1 << 20, 2 << 30),
        "inactive_device_days" => (7, 365),
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
        ("pow_adaptive", Value::Bool(b)) => s.pow_adaptive = *b,
        ("pow_adaptive_threshold", v) if v.is_i64() => s.pow_adaptive_threshold = v.as_i64().unwrap_or_default(),
        ("pow_adaptive_max_bits", v) if v.is_i64() => s.pow_adaptive_max_bits = v.as_i64().unwrap_or_default(),
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
        "pow_adaptive" => Value::Bool(s.pow_adaptive),
        "pow_adaptive_threshold" => s.pow_adaptive_threshold.into(),
        "pow_adaptive_max_bits" => s.pow_adaptive_max_bits.into(),
        _ => Value::Null,
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
}
