//! Server configuration from environment variables (same names and defaults as the Go server).

use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Config {
    /// Turns off all rate limits (development and automated tests only).
    pub disable_rate_limits: bool,
    pub listen_addr: String,
    pub mysql_dsn: String,

    pub minio_endpoint: String,
    pub minio_access_key: String,
    pub minio_secret_key: String,
    pub minio_bucket: String,
    pub minio_use_ssl: bool,
    pub minio_region: String,

    pub server_name: String,
    pub server_secret: String,
    pub registration_enabled: bool,

    pub max_devices: i64,
    pub max_group_members: i64,
    pub attachment_max_bytes: i64,
    pub attachment_ttl_days: i64,
    /// Bounds what one account may upload per 24 hours (storage abuse).
    pub attachment_daily_bytes: i64,
    pub message_ttl_days: i64,
    pub vault_quota_bytes: i64,
    /// Linked devices not seen for this many days are unlinked (the most recently active
    /// device of an account is always kept); 0 disables.
    pub inactive_device_days: i64,
    /// Leading zero bits of SHA-256 required by the registration proof-of-work; 0 disables.
    pub registration_pow_bits: i64,
    /// How long a released username stays reserved for its previous owner.
    pub username_reservation_days: i64,

    /// "log", "twilio" or "none".
    pub sms_provider: String,
    pub twilio_account_sid: String,
    pub twilio_auth_token: String,
    pub twilio_from: String,

    /// Firebase service account JSON used for push notifications; empty disables push.
    pub fcm_credentials_file: String,
    /// APNs token-based auth key (.p8) for direct VoIP (PushKit) pushes of incoming calls to
    /// iOS; empty disables them (calls then go through FCM like messages).
    pub apns_key_file: String,
    /// The key's 10-character Key ID and the Apple Developer Team ID.
    pub apns_key_id: String,
    pub apns_team_id: String,
    /// apns-topic of VoIP pushes: the app's bundle id + ".voip".
    pub apns_topic: String,
    /// APNs development environment (apps signed for development); production otherwise.
    pub apns_sandbox: bool,

    /// turn:/turns: URLs of a coturn server using "use-auth-secret" with `turn_secret`.
    pub turn_urls: Vec<String>,
    pub turn_secret: String,
    pub turn_credential_ttl: Duration,
    pub stun_urls: Vec<String>,

    /// e.g. "X-Forwarded-For" or "X-Real-IP"; empty = use the peer address.
    pub trusted_proxy_header: String,
    pub log_level: String,
    /// "text" or "json".
    pub log_format: String,

    /// Ed25519 public keys allowed to call the admin API (CHATAPP_ADMIN_PUBLIC_KEYS); empty
    /// disables it (docs/ADMIN-API.md).
    pub admin_public_keys: Vec<[u8; 32]>,
    /// JSON file `{"last_at": ms, "size_bytes": n}` written by the backup script; shown in the
    /// admin overview.
    pub backup_status_file: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            disable_rate_limits: false,
            listen_addr: ":8080".into(),
            mysql_dsn: String::new(),
            minio_endpoint: "localhost:9000".into(),
            minio_access_key: String::new(),
            minio_secret_key: String::new(),
            minio_bucket: "chatapp-attachments".into(),
            minio_use_ssl: false,
            minio_region: String::new(),
            server_name: "Dialog".into(),
            server_secret: String::new(),
            registration_enabled: true,
            max_devices: 6,
            max_group_members: 256,
            attachment_max_bytes: 100 << 20,
            attachment_ttl_days: 30,
            attachment_daily_bytes: 2 << 30,
            message_ttl_days: 30,
            vault_quota_bytes: 1 << 30,
            inactive_device_days: 30,
            registration_pow_bits: 20,
            username_reservation_days: 30,
            sms_provider: "log".into(),
            twilio_account_sid: String::new(),
            twilio_auth_token: String::new(),
            twilio_from: String::new(),
            fcm_credentials_file: String::new(),
            apns_key_file: String::new(),
            apns_key_id: String::new(),
            apns_team_id: String::new(),
            apns_topic: "pm.dialog.chat.voip".into(),
            apns_sandbox: false,
            turn_urls: Vec::new(),
            turn_secret: String::new(),
            turn_credential_ttl: Duration::from_secs(3600),
            stun_urls: Vec::new(),
            trusted_proxy_header: String::new(),
            log_level: "info".into(),
            log_format: "text".into(),
            admin_public_keys: Vec::new(),
            backup_status_file: String::new(),
        }
    }
}

fn split_list(v: &str) -> Vec<String> {
    v.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

impl Config {
    /// Loads the configuration using `lookup` (`std::env::var` in production).
    pub fn load(lookup: impl Fn(&str) -> Option<String>) -> Result<Config, String> {
        let mut c = Config::default();
        let mut errs: Vec<String> = Vec::new();
        let get = |name: &str| {
            lookup(name)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };

        macro_rules! string {
            ($name:expr, $field:expr) => {
                if let Some(v) = get($name) {
                    $field = v;
                }
            };
        }
        macro_rules! boolean {
            ($name:expr, $field:expr) => {
                if let Some(v) = get($name) {
                    match parse_bool(&v) {
                        Some(b) => $field = b,
                        None => errs.push(format!("{}: invalid boolean {:?}", $name, v)),
                    }
                }
            };
        }
        macro_rules! integer {
            ($name:expr, $field:expr, $min:expr, $max:expr) => {
                if let Some(v) = get($name) {
                    match v.parse::<i64>() {
                        Ok(n) if n >= $min && n <= $max => $field = n,
                        _ => errs.push(format!(
                            "{}: must be an integer in [{}, {}]",
                            $name, $min, $max
                        )),
                    }
                }
            };
        }

        string!("CHATAPP_LISTEN_ADDR", c.listen_addr);
        string!("CHATAPP_MYSQL_DSN", c.mysql_dsn);
        string!("CHATAPP_MINIO_ENDPOINT", c.minio_endpoint);
        string!("CHATAPP_MINIO_ACCESS_KEY", c.minio_access_key);
        string!("CHATAPP_MINIO_SECRET_KEY", c.minio_secret_key);
        string!("CHATAPP_MINIO_BUCKET", c.minio_bucket);
        boolean!("CHATAPP_MINIO_USE_SSL", c.minio_use_ssl);
        string!("CHATAPP_MINIO_REGION", c.minio_region);
        string!("CHATAPP_SERVER_NAME", c.server_name);
        if let Some(v) = lookup("CHATAPP_SERVER_SECRET") {
            c.server_secret = v;
        }
        boolean!("CHATAPP_REGISTRATION_ENABLED", c.registration_enabled);
        boolean!("CHATAPP_DISABLE_RATE_LIMITS", c.disable_rate_limits);
        integer!("CHATAPP_MAX_DEVICES", c.max_devices, 1, 127);
        integer!("CHATAPP_MAX_GROUP_MEMBERS", c.max_group_members, 2, 100_000);
        integer!(
            "CHATAPP_ATTACHMENT_MAX_BYTES",
            c.attachment_max_bytes,
            1,
            5i64 << 40
        );
        integer!(
            "CHATAPP_ATTACHMENT_TTL_DAYS",
            c.attachment_ttl_days,
            1,
            36_500
        );
        integer!(
            "CHATAPP_ATTACHMENT_DAILY_BYTES",
            c.attachment_daily_bytes,
            1 << 20,
            1i64 << 50
        );
        integer!("CHATAPP_MESSAGE_TTL_DAYS", c.message_ttl_days, 1, 36_500);
        integer!(
            "CHATAPP_VAULT_QUOTA_BYTES",
            c.vault_quota_bytes,
            0,
            1i64 << 50
        );
        integer!(
            "CHATAPP_INACTIVE_DEVICE_DAYS",
            c.inactive_device_days,
            0,
            36_500
        );
        integer!(
            "CHATAPP_REGISTRATION_POW_BITS",
            c.registration_pow_bits,
            0,
            32
        );
        integer!(
            "CHATAPP_USERNAME_RESERVATION_DAYS",
            c.username_reservation_days,
            0,
            3650
        );
        string!("CHATAPP_SMS_PROVIDER", c.sms_provider);
        string!("CHATAPP_TWILIO_ACCOUNT_SID", c.twilio_account_sid);
        string!("CHATAPP_TWILIO_AUTH_TOKEN", c.twilio_auth_token);
        string!("CHATAPP_TWILIO_FROM", c.twilio_from);
        string!("CHATAPP_FCM_CREDENTIALS_FILE", c.fcm_credentials_file);
        string!("CHATAPP_APNS_KEY_FILE", c.apns_key_file);
        string!("CHATAPP_APNS_KEY_ID", c.apns_key_id);
        string!("CHATAPP_APNS_TEAM_ID", c.apns_team_id);
        string!("CHATAPP_APNS_TOPIC", c.apns_topic);
        boolean!("CHATAPP_APNS_SANDBOX", c.apns_sandbox);
        string!("CHATAPP_TRUSTED_PROXY_HEADER", c.trusted_proxy_header);
        if let Some(v) = lookup("CHATAPP_TURN_URLS") {
            c.turn_urls = split_list(&v);
        }
        if let Some(v) = lookup("CHATAPP_STUN_URLS") {
            c.stun_urls = split_list(&v);
        }
        string!("CHATAPP_TURN_SECRET", c.turn_secret);
        let mut ttl = c.turn_credential_ttl.as_secs() as i64;
        integer!("CHATAPP_TURN_TTL_SECONDS", ttl, 60, 7 * 86_400);
        c.turn_credential_ttl = Duration::from_secs(ttl as u64);
        string!("CHATAPP_LOG_FORMAT", c.log_format);
        if let Some(v) = get("CHATAPP_ADMIN_PUBLIC_KEYS") {
            match crate::admin::auth::parse_keys(&v) {
                Ok(k) => c.admin_public_keys = k,
                Err(e) => errs.push(format!("CHATAPP_ADMIN_PUBLIC_KEYS: {e}")),
            }
        }
        string!("CHATAPP_BACKUP_STATUS_FILE", c.backup_status_file);
        if let Some(v) = get("CHATAPP_LOG_LEVEL") {
            match parse_slog_level(&v) {
                Some(l) => c.log_level = l.into(),
                None => errs.push(format!("CHATAPP_LOG_LEVEL: invalid level {v:?}")),
            }
        }

        if c.mysql_dsn.is_empty() {
            errs.push("CHATAPP_MYSQL_DSN is required".into());
        }
        if c.server_secret.len() < 32 {
            errs.push(
                "CHATAPP_SERVER_SECRET is required and must be at least 32 characters".into(),
            );
        }
        if c.minio_access_key.is_empty() || c.minio_secret_key.is_empty() {
            errs.push("CHATAPP_MINIO_ACCESS_KEY and CHATAPP_MINIO_SECRET_KEY are required".into());
        }
        c.sms_provider = c.sms_provider.to_ascii_lowercase();
        match c.sms_provider.as_str() {
            "log" | "none" => {}
            "twilio" => {
                if c.twilio_account_sid.is_empty()
                    || c.twilio_auth_token.is_empty()
                    || c.twilio_from.is_empty()
                {
                    errs.push("twilio SMS provider requires CHATAPP_TWILIO_ACCOUNT_SID, CHATAPP_TWILIO_AUTH_TOKEN and CHATAPP_TWILIO_FROM".into());
                }
            }
            other => errs.push(format!(
                "CHATAPP_SMS_PROVIDER: unknown provider {other:?} (log, twilio, none)"
            )),
        }
        for u in &c.turn_urls {
            if !u.starts_with("turn:") && !u.starts_with("turns:") {
                errs.push(format!(
                    "CHATAPP_TURN_URLS: {u:?} is not a turn: or turns: URL"
                ));
            }
        }
        for u in &c.stun_urls {
            if !u.starts_with("stun:") && !u.starts_with("stuns:") {
                errs.push(format!("CHATAPP_STUN_URLS: {u:?} is not a stun: URL"));
            }
        }
        if !c.turn_urls.is_empty() && c.turn_secret.len() < 16 {
            errs.push(
                "CHATAPP_TURN_SECRET (at least 16 characters) is required with CHATAPP_TURN_URLS"
                    .into(),
            );
        }
        if !c.apns_key_file.is_empty() {
            let id_ok = |v: &str| v.len() == 10 && v.bytes().all(|b| b.is_ascii_alphanumeric());
            if !id_ok(&c.apns_key_id) || !id_ok(&c.apns_team_id) {
                errs.push("CHATAPP_APNS_KEY_FILE requires CHATAPP_APNS_KEY_ID and CHATAPP_APNS_TEAM_ID (10 characters each)".into());
            }
            if !c.apns_topic.ends_with(".voip") || c.apns_topic.len() <= 5 {
                errs.push(format!(
                    "CHATAPP_APNS_TOPIC: {:?} must be the bundle id followed by \".voip\"",
                    c.apns_topic
                ));
            }
        }
        if c.log_format != "text" && c.log_format != "json" {
            errs.push("CHATAPP_LOG_FORMAT: must be text or json".into());
        }
        if errs.is_empty() {
            Ok(c)
        } else {
            Err(errs.join("\n"))
        }
    }

    pub fn from_env() -> Result<Config, String> {
        Config::load(|k| std::env::var(k).ok())
    }
}

/// Parses a level like Go's slog.Level.UnmarshalText ("debug", "INFO+2", "warn-4", ...) and
/// maps it to the nearest tracing level.
fn parse_slog_level(v: &str) -> Option<&'static str> {
    let lower = v.to_ascii_lowercase();
    let (name, offset) = match lower.find(['+', '-']) {
        Some(i) => (&lower[..i], lower[i..].parse::<i64>().ok()?),
        None => (lower.as_str(), 0),
    };
    let base = match name {
        "debug" => -4,
        "info" => 0,
        "warn" => 4,
        "error" => 8,
        _ => return None,
    };
    Some(match base + offset {
        l if l < 0 => "debug",
        l if l < 4 => "info",
        l if l < 8 => "warn",
        _ => "error",
    })
}

/// Parses booleans like Go's strconv.ParseBool.
fn parse_bool(v: &str) -> Option<bool> {
    match v {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn required_and_defaults() {
        assert!(Config::load(env(&[])).is_err());
        let c = Config::load(env(&[
            ("CHATAPP_MYSQL_DSN", "u:p@tcp(h:3306)/db"),
            ("CHATAPP_SERVER_SECRET", "0123456789abcdef0123456789abcdef"),
            ("CHATAPP_MINIO_ACCESS_KEY", "a"),
            ("CHATAPP_MINIO_SECRET_KEY", "b"),
            ("CHATAPP_MAX_DEVICES", "3"),
        ]))
        .unwrap();
        assert_eq!(c.max_devices, 3);
        assert_eq!(c.max_group_members, 256);
        assert_eq!(c.inactive_device_days, 30);
        assert_eq!(c.registration_pow_bits, 20);
        assert!(Config::load(env(&[("CHATAPP_MAX_DEVICES", "500")])).is_err());
        assert_eq!(parse_slog_level("INFO+4"), Some("warn"));
        assert_eq!(parse_slog_level("debug"), Some("debug"));
        assert_eq!(parse_slog_level("error-1"), Some("warn"));
        assert_eq!(parse_slog_level("loud"), None);
    }

    #[test]
    fn apns_voip_settings() {
        let base = [
            ("CHATAPP_MYSQL_DSN", "u:p@tcp(h:3306)/db"),
            ("CHATAPP_SERVER_SECRET", "0123456789abcdef0123456789abcdef"),
            ("CHATAPP_MINIO_ACCESS_KEY", "a"),
            ("CHATAPP_MINIO_SECRET_KEY", "b"),
        ];
        let c = Config::load(env(&base)).unwrap();
        assert!(c.apns_key_file.is_empty());
        assert_eq!(c.apns_topic, "pm.dialog.chat.voip");
        assert!(!c.apns_sandbox);
        let with = |extra: &[(&'static str, &'static str)]| {
            let mut v = base.to_vec();
            v.extend_from_slice(extra);
            Config::load(env(&v))
        };
        // A key file needs its Key ID and Team ID.
        assert!(with(&[("CHATAPP_APNS_KEY_FILE", "/k.p8")]).is_err());
        assert!(with(&[
            ("CHATAPP_APNS_KEY_FILE", "/k.p8"),
            ("CHATAPP_APNS_KEY_ID", "ABC123DEFG"),
            ("CHATAPP_APNS_TEAM_ID", "short"),
        ])
        .is_err());
        assert!(with(&[
            ("CHATAPP_APNS_KEY_FILE", "/k.p8"),
            ("CHATAPP_APNS_KEY_ID", "ABC123DEFG"),
            ("CHATAPP_APNS_TEAM_ID", "ABCDE12345"),
            ("CHATAPP_APNS_TOPIC", "pm.dialog.chat"),
        ])
        .is_err());
        let c = with(&[
            ("CHATAPP_APNS_KEY_FILE", "/k.p8"),
            ("CHATAPP_APNS_KEY_ID", "ABC123DEFG"),
            ("CHATAPP_APNS_TEAM_ID", "ABCDE12345"),
            ("CHATAPP_APNS_SANDBOX", "true"),
        ])
        .unwrap();
        assert!(c.apns_sandbox);
    }
}
