//! Request signatures of the admin API (docs/ADMIN-API.md, "Authentication").
//!
//! The server stores only Ed25519 *public* keys (CHATAPP_ADMIN_PUBLIC_KEYS). Every request
//! carries `X-Admin-Key`, `X-Admin-Timestamp` (unix ms), `X-Admin-Nonce` and
//! `X-Admin-Signature`, an Ed25519 signature over
//!
//! ```text
//! "dialog-admin-v1\n" + METHOD + "\n" + PATH_WITH_QUERY + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + hex(sha256(body))
//! ```
//!
//! A request is accepted when the key is listed, the timestamp is within 60 s of the server
//! clock, the signature verifies (strict RFC 8032 verification), and the nonce was not used
//! with that key in the last 5 minutes.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const CONTEXT: &str = "dialog-admin-v1";
pub const HEADER_KEY: &str = "x-admin-key";
pub const HEADER_TIMESTAMP: &str = "x-admin-timestamp";
pub const HEADER_NONCE: &str = "x-admin-nonce";
pub const HEADER_SIGNATURE: &str = "x-admin-signature";
/// Largest accepted clock difference.
pub const MAX_SKEW_MS: i64 = 60_000;
/// How long a used nonce is remembered (longer than the timestamp window, so a captured
/// request can never be replayed).
pub const NONCE_TTL_MS: i64 = 5 * 60_000;
/// Bound on remembered nonces per key (at 60 s validity this is >300 requests per second).
const MAX_NONCES_PER_KEY: usize = 100_000;

/// The exact string that is signed.
pub fn signing_string(method: &str, path_with_query: &str, timestamp: &str, nonce: &str, body: &[u8]) -> String {
    format!(
        "{CONTEXT}\n{method}\n{path_with_query}\n{timestamp}\n{nonce}\n{}",
        hex::encode(Sha256::digest(body))
    )
}

/// Signs a request the way the admin app must; returns the base64 `X-Admin-Signature`.
/// (Used by tests and documented as the reference implementation.)
#[cfg_attr(not(test), allow(dead_code))]
pub fn sign_admin_request(
    sk: &ed25519_dalek::SigningKey,
    method: &str,
    path_with_query: &str,
    ts: i64,
    nonce: &str,
    body: &[u8],
) -> String {
    use ed25519_dalek::Signer;
    let msg = signing_string(method, path_with_query, &ts.to_string(), nonce, body);
    STANDARD.encode(sk.sign(msg.as_bytes()).to_bytes())
}

/// Short identifier of a key for logs: the first 8 bytes of SHA-256(public key), hex.
pub fn fingerprint(pk: &[u8; 32]) -> String {
    hex::encode(&Sha256::digest(pk)[..8])
}

/// Parses CHATAPP_ADMIN_PUBLIC_KEYS (comma-separated standard base64 Ed25519 keys).
pub fn parse_keys(v: &str) -> Result<Vec<[u8; 32]>, String> {
    let mut out: Vec<[u8; 32]> = Vec::new();
    for k in v.split(',').map(str::trim).filter(|k| !k.is_empty()) {
        let bytes = STANDARD
            .decode(k)
            .map_err(|_| format!("{k:?} is not standard base64"))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| format!("{k:?} is not a 32-byte Ed25519 public key"))?;
        VerifyingKey::from_bytes(&key).map_err(|_| format!("{k:?} is not a valid Ed25519 public key"))?;
        if !out.contains(&key) {
            out.push(key);
        }
    }
    Ok(out)
}

/// The signature headers of one request.
pub struct SignedHeaders<'a> {
    pub key: &'a str,
    pub timestamp: &'a str,
    pub nonce: &'a str,
    pub signature: &'a str,
}

/// Why a request was rejected (logged at debug level only; the client always gets 401).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Reject {
    BadHeaders,
    UnknownKey,
    StaleTimestamp,
    BadSignature,
    ReplayedNonce,
}

pub struct Verifier {
    keys: Vec<([u8; 32], VerifyingKey)>,
    /// key index -> nonce -> time it was seen (ms).
    nonces: Mutex<HashMap<usize, HashMap<String, i64>>>,
}

pub fn valid_nonce(n: &str) -> bool {
    (16..=64).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Verifier {
    pub fn new(keys: &[[u8; 32]]) -> Verifier {
        Verifier {
            keys: keys
                .iter()
                .filter_map(|k| VerifyingKey::from_bytes(k).ok().map(|vk| (*k, vk)))
                .collect(),
            nonces: Mutex::new(HashMap::new()),
        }
    }

    /// Checks one request; on success returns the fingerprint of the key that signed it.
    pub fn verify(&self, method: &str, path_with_query: &str, h: &SignedHeaders, body: &[u8], now_ms: i64) -> Result<String, Reject> {
        let pk: [u8; 32] = STANDARD
            .decode(h.key.trim())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(Reject::BadHeaders)?;
        let sig: [u8; 64] = STANDARD
            .decode(h.signature.trim())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(Reject::BadHeaders)?;
        if h.timestamp.is_empty() || h.timestamp.len() > 16 || !h.timestamp.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Reject::BadHeaders);
        }
        if !valid_nonce(h.nonce) {
            return Err(Reject::BadHeaders);
        }
        // Constant-time lookup: every configured key is compared.
        let mut found: Option<usize> = None;
        for (i, (k, _)) in self.keys.iter().enumerate() {
            if bool::from(k.as_slice().ct_eq(&pk)) {
                found = Some(i);
            }
        }
        let idx = found.ok_or(Reject::UnknownKey)?;
        let ts: i64 = h.timestamp.parse().map_err(|_| Reject::BadHeaders)?;
        if (now_ms - ts).abs() > MAX_SKEW_MS {
            return Err(Reject::StaleTimestamp);
        }
        let msg = signing_string(method, path_with_query, h.timestamp, h.nonce, body);
        self.keys[idx]
            .1
            .verify_strict(msg.as_bytes(), &Signature::from_bytes(&sig))
            .map_err(|_| Reject::BadSignature)?;
        // Only signed requests reach the nonce cache, so it cannot be filled by strangers.
        let mut all = self.nonces.lock().unwrap();
        let seen = all.entry(idx).or_default();
        if seen.len() >= MAX_NONCES_PER_KEY / 2 {
            seen.retain(|_, t| now_ms - *t <= NONCE_TTL_MS);
        }
        if let Some(t) = seen.get(h.nonce) {
            if now_ms - *t <= NONCE_TTL_MS {
                return Err(Reject::ReplayedNonce);
            }
        }
        if seen.len() >= MAX_NONCES_PER_KEY {
            return Err(Reject::ReplayedNonce);
        }
        seen.insert(h.nonce.to_string(), now_ms);
        Ok(fingerprint(&pk))
    }

    /// Drops expired nonces (called periodically).
    pub fn prune(&self, now_ms: i64) {
        let mut all = self.nonces.lock().unwrap();
        for seen in all.values_mut() {
            seen.retain(|_, t| now_ms - *t <= NONCE_TTL_MS);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// Seed of the documented example key: bytes 0x00, 0x01, ..., 0x1f.
    fn example_key() -> SigningKey {
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = i as u8;
        }
        SigningKey::from_bytes(&seed)
    }

    const NOW: i64 = 1_790_000_000_000;

    struct Req {
        method: &'static str,
        path: String,
        key: String,
        ts: String,
        nonce: String,
        sig: String,
        body: Vec<u8>,
    }

    fn signed(sk: &SigningKey, method: &'static str, path: &str, ts: i64, nonce: &str, body: &[u8]) -> Req {
        Req {
            method,
            path: path.into(),
            key: STANDARD.encode(sk.verifying_key().to_bytes()),
            ts: ts.to_string(),
            nonce: nonce.into(),
            sig: sign_admin_request(sk, method, path, ts, nonce, body),
            body: body.to_vec(),
        }
    }

    fn check(v: &Verifier, r: &Req, now: i64) -> Result<String, Reject> {
        v.verify(
            r.method,
            &r.path,
            &SignedHeaders { key: &r.key, timestamp: &r.ts, nonce: &r.nonce, signature: &r.sig },
            &r.body,
            now,
        )
    }

    #[test]
    fn worked_example() {
        // The values documented in docs/ADMIN-API.md.
        let sk = example_key();
        let pk = STANDARD.encode(sk.verifying_key().to_bytes());
        let path = "/v1/admin/accounts?query=abc&limit=20";
        let msg = signing_string("GET", path, "1790000000000", "0123456789abcdef", b"");
        let sig = sign_admin_request(&sk, "GET", path, 1_790_000_000_000, "0123456789abcdef", b"");
        let body = br#"{"reason":"spam"}"#;
        let path2 = "/v1/admin/accounts/0b6c8a52-3c1e-4f0e-9a43-2d4f7d1e8b11/ban";
        let msg2 = signing_string("POST", path2, "1790000000000", "nonce_example_0002", body);
        let sig2 = sign_admin_request(&sk, "POST", path2, 1_790_000_000_000, "nonce_example_0002", body);
        assert_eq!(pk, "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=");
        assert_eq!(
            msg,
            "dialog-admin-v1\nGET\n/v1/admin/accounts?query=abc&limit=20\n1790000000000\n0123456789abcdef\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            msg2,
            "dialog-admin-v1\nPOST\n/v1/admin/accounts/0b6c8a52-3c1e-4f0e-9a43-2d4f7d1e8b11/ban\n1790000000000\nnonce_example_0002\n0239caecc27b45b72235ca016a0f4bfdb7c5a718d30d32e64cb8804f63d68a16"
        );
        assert_eq!(fingerprint(&sk.verifying_key().to_bytes()), "56475aa75463474c");
        assert_eq!(sig, EXAMPLE_SIG_GET);
        assert_eq!(sig2, EXAMPLE_SIG_POST);
        let v = Verifier::new(&parse_keys(&pk).unwrap());
        let r = signed(&sk, "GET", path, 1_790_000_000_000, "0123456789abcdef", b"");
        assert!(check(&v, &r, NOW).is_ok());
    }

    const EXAMPLE_SIG_GET: &str = "Lv+e12xoXB4MjXPbKaOBr/E00DxX1wtfNT5IjT/imxwzYfbeOCLrmJ3wAb1a8WPqGW85ALlOMERdy1wjFvXvBA==";
    const EXAMPLE_SIG_POST: &str = "jvGyG9VLxrl9DqRfX5DsCdJb65YP73+z9YH2T/56l+uui8P46e/Umvb/YeHTPe16Zm8UjWtQK6fjEFCpjZkxBg==";

    #[test]
    fn accepts_valid_and_rejects_wrong_key() {
        let sk = example_key();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let v = Verifier::new(&[sk.verifying_key().to_bytes()]);
        let r = signed(&sk, "GET", "/v1/admin/overview", NOW, "aaaaaaaaaaaaaaaa", b"");
        assert_eq!(check(&v, &r, NOW).unwrap(), fingerprint(&sk.verifying_key().to_bytes()));
        // A key that is not configured.
        let r = signed(&other, "GET", "/v1/admin/overview", NOW, "bbbbbbbbbbbbbbbb", b"");
        assert_eq!(check(&v, &r, NOW), Err(Reject::UnknownKey));
        // The configured key in the header, signed by another key.
        let mut r = signed(&other, "GET", "/v1/admin/overview", NOW, "cccccccccccccccc", b"");
        r.key = STANDARD.encode(sk.verifying_key().to_bytes());
        assert_eq!(check(&v, &r, NOW), Err(Reject::BadSignature));
    }

    #[test]
    fn rejects_stale_timestamps() {
        let sk = example_key();
        let v = Verifier::new(&[sk.verifying_key().to_bytes()]);
        let ok_old = signed(&sk, "GET", "/v1/admin/overview", NOW - MAX_SKEW_MS, "dddddddddddddddd", b"");
        assert!(check(&v, &ok_old, NOW).is_ok());
        let old = signed(&sk, "GET", "/v1/admin/overview", NOW - MAX_SKEW_MS - 1, "eeeeeeeeeeeeeeee", b"");
        assert_eq!(check(&v, &old, NOW), Err(Reject::StaleTimestamp));
        let future = signed(&sk, "GET", "/v1/admin/overview", NOW + MAX_SKEW_MS + 1, "ffffffffffffffff", b"");
        assert_eq!(check(&v, &future, NOW), Err(Reject::StaleTimestamp));
    }

    #[test]
    fn rejects_replayed_nonces() {
        let sk = example_key();
        let v = Verifier::new(&[sk.verifying_key().to_bytes()]);
        let r = signed(&sk, "GET", "/v1/admin/overview", NOW, "nonce-0000000001", b"");
        assert!(check(&v, &r, NOW).is_ok());
        assert_eq!(check(&v, &r, NOW + 1000), Err(Reject::ReplayedNonce));
        // Same nonce, new timestamp and signature: still a replay within 5 minutes.
        let r2 = signed(&sk, "GET", "/v1/admin/overview", NOW + 30_000, "nonce-0000000001", b"");
        assert_eq!(check(&v, &r2, NOW + 30_000), Err(Reject::ReplayedNonce));
        // After the nonce expired it may be reused (with a fresh timestamp).
        v.prune(NOW + NONCE_TTL_MS + 1);
        let r3 = signed(&sk, "GET", "/v1/admin/overview", NOW + NONCE_TTL_MS + 1, "nonce-0000000001", b"");
        assert!(check(&v, &r3, NOW + NONCE_TTL_MS + 1).is_ok());
    }

    #[test]
    fn rejects_tampering() {
        let sk = example_key();
        let v = Verifier::new(&[sk.verifying_key().to_bytes()]);
        let base = || signed(&sk, "POST", "/v1/admin/accounts/x/ban", NOW, "gggggggggggggggg", br#"{"reason":"spam"}"#);
        let mut r = base();
        r.body = br#"{"reason":"spam!"}"#.to_vec();
        assert_eq!(check(&v, &r, NOW), Err(Reject::BadSignature));
        let mut r = base();
        r.path = "/v1/admin/accounts/y/ban".into();
        assert_eq!(check(&v, &r, NOW), Err(Reject::BadSignature));
        let mut r = base();
        r.path = "/v1/admin/accounts/x/ban?x=1".into();
        assert_eq!(check(&v, &r, NOW), Err(Reject::BadSignature));
        let mut r = base();
        r.method = "PUT";
        assert_eq!(check(&v, &r, NOW), Err(Reject::BadSignature));
        let mut r = base();
        r.ts = (NOW + 1).to_string();
        assert_eq!(check(&v, &r, NOW), Err(Reject::BadSignature));
        // A failed request does not burn its nonce: the genuine one still goes through.
        assert!(check(&v, &base(), NOW).is_ok());
    }

    #[test]
    fn rejects_malformed_headers() {
        let sk = example_key();
        let v = Verifier::new(&[sk.verifying_key().to_bytes()]);
        let mut r = signed(&sk, "GET", "/v1/admin/overview", NOW, "short", b"");
        assert_eq!(check(&v, &r, NOW), Err(Reject::BadHeaders));
        r = signed(&sk, "GET", "/v1/admin/overview", NOW, "has spaces in it!!", b"");
        assert_eq!(check(&v, &r, NOW), Err(Reject::BadHeaders));
        r = signed(&sk, "GET", "/v1/admin/overview", NOW, "hhhhhhhhhhhhhhhh", b"");
        r.ts = format!("+{}", NOW);
        assert_eq!(check(&v, &r, NOW), Err(Reject::BadHeaders));
        r = signed(&sk, "GET", "/v1/admin/overview", NOW, "hhhhhhhhhhhhhhhh", b"");
        r.sig = "AAAA".into();
        assert_eq!(check(&v, &r, NOW), Err(Reject::BadHeaders));
    }

    #[test]
    fn parses_key_list() {
        let a = STANDARD.encode(example_key().verifying_key().to_bytes());
        let b = STANDARD.encode(SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes());
        assert_eq!(parse_keys(&format!(" {a} , {b},{a}")).unwrap().len(), 2);
        assert!(parse_keys("").unwrap().is_empty());
        assert!(parse_keys("not-base64!").is_err());
        assert!(parse_keys("AAAA").is_err());
    }
}
