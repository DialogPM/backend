//! Random identifiers: account ids (UUID v4), account numbers, bearer tokens, attachment ids.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};

/// Random lowercase RFC 4122 version 4 UUID.
pub fn new_uuid() -> String {
    uuid::Uuid::new_v4().hyphenated().to_string()
}

/// Validates a UUID (any version, either case) and returns its lowercase canonical form.
pub fn normalize_uuid(s: &str) -> Option<String> {
    let b = s.as_bytes();
    if b.len() != 36 {
        return None;
    }
    for (i, c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if *c != b'-' {
                    return None;
                }
            }
            _ => {
                if !c.is_ascii_hexdigit() {
                    return None;
                }
            }
        }
    }
    Some(s.to_ascii_lowercase())
}

/// Number of decimal digits of an account number.
pub const NUMBER_LENGTH: usize = 16;

/// Uniformly random 16-digit number whose first digit is never zero.
pub fn new_account_number() -> String {
    let n: u64 = rand::rng().random_range(1_000_000_000_000_000u64..10_000_000_000_000_000u64);
    n.to_string()
}

pub fn valid_number(s: &str) -> bool {
    s.len() == NUMBER_LENGTH && !s.starts_with('0') && s.bytes().all(|c| c.is_ascii_digit())
}

/// New bearer token (32 random bytes, base64url without padding) and its SHA-256 hash, which
/// is the only value stored.
pub fn new_token() -> (String, Vec<u8>) {
    let token = URL_SAFE_NO_PAD.encode(random_bytes(32));
    let hash = hash_token(&token);
    (token, hash)
}

pub fn hash_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Whether `s` looks like a token issued by `new_token`.
pub fn valid_token_format(s: &str) -> bool {
    s.len() == 43
        && URL_SAFE_NO_PAD
            .decode(s)
            .map(|b| b.len() == 32)
            .unwrap_or(false)
}

/// 128 random bits as 32 lowercase hex characters.
pub fn new_attachment_id() -> String {
    hex::encode(random_bytes(16))
}

pub fn valid_attachment_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    rand::rng().fill_bytes(&mut b);
    b
}

/// Random decimal code with the given number of digits (leading zeros allowed).
pub fn new_numeric_code(digits: u32) -> String {
    let n: u64 = rand::rng().random_range(0..10u64.pow(digits));
    format!("{n:0width$}", width = digits as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        let n = new_account_number();
        assert!(valid_number(&n), "{n}");
        let (t, h) = new_token();
        assert!(valid_token_format(&t));
        assert_eq!(h, hash_token(&t));
        assert!(valid_attachment_id(&new_attachment_id()));
        assert_eq!(
            normalize_uuid("ABCDEF01-2345-6789-abcd-ef0123456789").unwrap(),
            "abcdef01-2345-6789-abcd-ef0123456789"
        );
        assert!(normalize_uuid(&new_uuid()).is_some());
        assert_eq!(new_numeric_code(6).len(), 6);
    }
}
