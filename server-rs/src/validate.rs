//! Request parsing and validation helpers shared by the handlers.

use axum::body::Body;
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{bad_request, too_large, ApiError};
use crate::ids;

// Size limits (decoded bytes).
pub const MAX_JSON_BODY: usize = 2 << 20;
pub const AUTH_KEY_LEN: usize = 32;
/// libsignal serialized Curve25519 public key (type byte + 32).
pub const EC_PUBLIC_KEY_LEN: usize = 33;
pub const SIGNATURE_LEN: usize = 64;
/// Kyber1024 serialized is 1569 bytes.
pub const MAX_KYBER_PUBLIC_KEY_LEN: usize = 4096;
pub const RECOVERY_PUB_KEY_LEN: usize = 32;
pub const MAX_WRAPPED_KEY_LEN: usize = 1024;
/// Characters.
pub const MAX_DEVICE_NAME_LEN: usize = 128;
pub const MAX_MESSAGE_CONTENT: usize = 256 << 10;
pub const MAX_PROFILE_DATA: usize = 64 << 10;
pub const MAX_GROUP_METADATA: usize = 64 << 10;
pub const MAX_VAULT_RECORD_DATA: usize = 256 << 10;
pub const MAX_VAULT_RECORD_ID_LEN: usize = 128;
pub const MAX_VAULT_RECORDS: usize = 500;
pub const MAX_ONE_TIME_KEYS_PER_REQ: usize = 200;
/// Per device and kind; far above normal client behaviour.
pub const MAX_ONE_TIME_KEYS_STORED: i64 = 5000;
pub const MAX_REGISTRATION_ID: i64 = 16380;
pub const MAX_DEVICE_ID: i64 = 127;
pub const MAX_PHONE_HASHES: usize = 1000;

/// Reads a JSON body of at most `limit` bytes. Unknown fields are ignored (like Go's
/// encoding/json); trailing data after the value is rejected.
pub async fn parse_json<T: DeserializeOwned>(body: Body, limit: usize) -> Result<T, ApiError> {
    let bytes = read_body(body, limit).await?;
    parse_json_bytes(&bytes)
}

/// Reads the whole body, failing with 413 above `limit` bytes.
pub async fn read_body(body: Body, limit: usize) -> Result<bytes::Bytes, ApiError> {
    axum::body::to_bytes(body, limit).await.map_err(|e| {
        let msg = e.to_string();
        if msg.contains("length limit") {
            too_large(format!("request body exceeds {limit} bytes"))
        } else {
            bad_request("could not read request body")
        }
    })
}

pub fn parse_json_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    if bytes.iter().all(|b| b.is_ascii_whitespace()) {
        return Err(bad_request("empty request body"));
    }
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = serde_json::Value::deserialize(&mut de)
        .map_err(|e| bad_request(format!("invalid JSON body: {e}")))?;
    de.end()
        .map_err(|_| bad_request("unexpected data after JSON body"))?;
    // Go's encoding/json semantics: `null` leaves a field at its zero value (here: like an
    // absent field, so serde defaults apply), a `null` body decodes nothing, field names match
    // case-insensitively, and the last of duplicate keys wins (Value already keeps the last).
    let value = go_compat(if value.is_null() {
        serde_json::Value::Object(Default::default())
    } else {
        value
    });
    // Re-serialize instead of from_value so RawValue fields keep working.
    let normalized = serde_json::to_vec(&value).expect("value serializes");
    serde_json::from_slice(&normalized).map_err(|e| bad_request(format!("invalid JSON body: {e}")))
}

pub fn go_compat(v: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if v.is_null() {
                    continue;
                }
                let key = if k.bytes().any(|b| b.is_ascii_uppercase()) {
                    k.to_ascii_lowercase()
                } else {
                    k
                };
                out.insert(key, go_compat(v));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.into_iter().map(go_compat).collect()),
        other => other,
    }
}

/// Serde helpers for byte fields, encoded like Go's encoding/json (standard base64 with
/// padding). Decoding also accepts unpadded input.
pub mod b64 {
    use base64::alphabet;
    use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
    use base64::engine::DecodePaddingMode;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn encode(b: &[u8]) -> String {
        STANDARD.encode(b)
    }

    /// Go's base64.StdEncoding: padding required, non-zero trailing bits accepted, CR/LF ignored.
    const GO_STD: GeneralPurpose = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical)
            .with_decode_allow_trailing_bits(true),
    );

    pub fn decode(s: &str) -> Option<Vec<u8>> {
        let s: String = s.chars().filter(|c| *c != '\r' && *c != '\n').collect();
        GO_STD.decode(s).ok()
    }

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(b))
    }

    /// `null` decodes to an empty vector (Go: nil slice).
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s: Option<String> = Option::deserialize(d)?;
        match s {
            None => Ok(Vec::new()),
            Some(s) => decode(&s).ok_or_else(|| serde::de::Error::custom("illegal base64 data")),
        }
    }

    /// For `Option<Vec<u8>>` fields: absent/null = None.
    pub mod opt {
        use super::*;
        pub fn serialize<S: Serializer>(b: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
            match b {
                Some(b) => s.serialize_str(&encode(b)),
                None => s.serialize_none(),
            }
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
            let s: Option<String> = Option::deserialize(d)?;
            match s {
                None => Ok(None),
                Some(s) => decode(&s)
                    .map(Some)
                    .ok_or_else(|| serde::de::Error::custom("illegal base64 data")),
            }
        }
    }

    /// For `Vec<Vec<u8>>` fields.
    pub mod list {
        use super::*;
        use serde::ser::SerializeSeq;
        pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(v.len()))?;
            for b in v {
                seq.serialize_element(&encode(b))?;
            }
            seq.end()
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
            let v: Option<Vec<String>> = Option::deserialize(d)?;
            v.unwrap_or_default()
                .iter()
                .map(|s| decode(s).ok_or_else(|| serde::de::Error::custom("illegal base64 data")))
                .collect()
        }
    }
}

/// Password KDF description stored opaquely (but validated) by the server. Field order
/// matches the Go server's canonical serialization.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KdfParams {
    #[serde(default)]
    pub alg: String,
    #[serde(with = "b64", default)]
    pub salt: Vec<u8>,
    #[serde(default)]
    pub m: i64,
    #[serde(default)]
    pub t: i64,
    #[serde(default)]
    pub p: i64,
}

pub const DEFAULT_KDF_M: i64 = 65536;
pub const DEFAULT_KDF_T: i64 = 3;
pub const DEFAULT_KDF_P: i64 = 1;
pub const KDF_SALT_LEN: usize = 16;

/// Validates the kdf object and returns its canonical JSON serialization.
pub fn parse_kdf(raw: Option<&serde_json::value::RawValue>) -> Result<String, ApiError> {
    let raw = match raw {
        Some(r) if r.get().trim() != "null" => r,
        _ => return Err(bad_request("kdf is required")),
    };
    let k: KdfParams =
        serde_json::from_str(raw.get()).map_err(|_| bad_request("invalid kdf object"))?;
    if k.alg != "argon2id" {
        return Err(bad_request("kdf.alg must be argon2id"));
    }
    if k.salt.len() != KDF_SALT_LEN {
        return Err(bad_request("kdf.salt must be 16 bytes"));
    }
    if k.m < 8 || k.m > 4 << 20 {
        return Err(bad_request("kdf.m out of range"));
    }
    if k.t < 1 || k.t > 100 {
        return Err(bad_request("kdf.t out of range"));
    }
    if k.p < 1 || k.p > 255 {
        return Err(bad_request("kdf.p out of range"));
    }
    Ok(serde_json::to_string(&k).expect("kdf serializes"))
}

/// Deterministic KDF answer for an unknown number (no account enumeration).
pub fn fake_kdf(secret: &str, number: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(number.as_bytes());
    let salt = mac.finalize().into_bytes()[..KDF_SALT_LEN].to_vec();
    serde_json::to_string(&KdfParams {
        alg: "argon2id".into(),
        salt,
        m: DEFAULT_KDF_M,
        t: DEFAULT_KDF_T,
        p: DEFAULT_KDF_P,
    })
    .expect("kdf serializes")
}

/// Device object sent at registration, login, recovery and linking.
#[derive(Deserialize, Clone, Debug, Default)]
pub struct DeviceInfo {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub registration_id: i64,
}

impl DeviceInfo {
    pub fn validate(d: Option<&DeviceInfo>) -> Result<&DeviceInfo, ApiError> {
        let d = d.ok_or_else(|| bad_request("device is required"))?;
        validate_device_name(&d.name)?;
        if !matches!(
            d.platform.as_str(),
            "desktop" | "android" | "ios" | "web" | "cli"
        ) {
            return Err(bad_request(
                "device.platform must be one of desktop, android, ios, web, cli",
            ));
        }
        if d.registration_id < 1 || d.registration_id > MAX_REGISTRATION_ID {
            return Err(bad_request("device.registration_id must be in 1..16380"));
        }
        Ok(d)
    }
}

pub fn validate_device_name(name: &str) -> Result<(), ApiError> {
    let n = name.chars().count();
    if n < 1 || n > MAX_DEVICE_NAME_LEN || name.trim().is_empty() {
        return Err(bad_request("device name must be 1..128 characters"));
    }
    if name.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f) {
        return Err(bad_request(
            "device name must not contain control characters",
        ));
    }
    Ok(())
}

pub fn require_len(field: &str, b: &[u8], n: usize) -> Result<(), ApiError> {
    if b.len() != n {
        return Err(bad_request(format!("{field} must be {n} bytes")));
    }
    Ok(())
}

pub fn require_range(field: &str, b: &[u8], min: usize, max: usize) -> Result<(), ApiError> {
    if b.len() < min || b.len() > max {
        return Err(bad_request(format!("{field} must be {min}..{max} bytes")));
    }
    Ok(())
}

pub fn hash_auth_key(auth_key: &[u8]) -> Vec<u8> {
    Sha256::digest(auth_key).to_vec()
}

/// E.164: `+` then 7..15 digits, no leading zero.
pub fn valid_phone(p: &str) -> bool {
    let Some(d) = p.strip_prefix('+') else {
        return false;
    };
    (7..=15).contains(&d.len()) && !d.starts_with('0') && d.bytes().all(|c| c.is_ascii_digit())
}

/// Validates a UUID path parameter.
pub fn path_uuid(name: &str, value: &str) -> Result<String, ApiError> {
    ids::normalize_uuid(value).ok_or_else(|| bad_request(format!("{name} must be a UUID")))
}

/// Validates a nullable attachment id reference.
pub fn optional_attachment_id(field: &str, v: Option<&str>) -> Result<(), ApiError> {
    match v {
        Some(id) if !ids::valid_attachment_id(id) => Err(bad_request(format!(
            "{field} must be null or a 32-character lowercase hex attachment id"
        ))),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_roundtrip() {
        let raw = serde_json::value::RawValue::from_string(
            r#"{"alg":"argon2id","salt":"AAAAAAAAAAAAAAAAAAAAAA==","m":65536,"t":3,"p":1}"#.into(),
        )
        .unwrap();
        let s = parse_kdf(Some(&raw)).unwrap();
        assert_eq!(
            s,
            r#"{"alg":"argon2id","salt":"AAAAAAAAAAAAAAAAAAAAAA==","m":65536,"t":3,"p":1}"#
        );
        assert!(fake_kdf("secret", "1234567890123456").contains("argon2id"));
    }

    #[test]
    fn go_json_semantics() {
        #[derive(Deserialize)]
        struct R {
            #[serde(default)]
            online: bool,
            #[serde(default)]
            name: String,
            #[serde(default, with = "b64")]
            data: Vec<u8>,
        }
        let r: R =
            parse_json_bytes(br#"{"Online":true,"name":null,"data":"AB==","name":"x"}"#).unwrap();
        assert!(r.online);
        assert_eq!(r.name, "x");
        assert_eq!(r.data, vec![0]);
        let r: R = parse_json_bytes(b"null").unwrap();
        assert!(!r.online);
        assert!(
            parse_json_bytes::<R>(br#"{"data":"AA"}"#).is_err(),
            "unpadded base64 is rejected like Go"
        );
    }

    #[test]
    fn phones() {
        assert!(valid_phone("+40712345678"));
        assert!(!valid_phone("0712345678"));
        assert!(!valid_phone("+0712345678"));
    }
}
