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

    #[test]
    fn uuids() {
        assert_eq!(normalize_uuid(""), None);
        assert_eq!(normalize_uuid("abcdef01-2345-6789-abcd-ef012345678"), None, "too short");
        assert_eq!(normalize_uuid("abcdef01-2345-6789-abcd-ef01234567899"), None, "too long");
        assert_eq!(normalize_uuid("abcdef0102345-6789-abcd-ef0123456789"), None, "hyphen missing");
        assert_eq!(normalize_uuid("abcdef01-2345-6789-abcd-ef012345678g"), None, "not hex");
        assert_eq!(normalize_uuid("abcdef01-2345-6789-abcd-ef01234-6789"), None, "hyphen in a digit place");
        assert_eq!(normalize_uuid("{bcdef01-2345-6789-abcd-ef012345678}"), None);
        let u = new_uuid();
        assert_eq!(normalize_uuid(&u).as_deref(), Some(u.as_str()), "already canonical");
        assert_ne!(new_uuid(), new_uuid());
    }

    #[test]
    fn account_numbers() {
        assert!(valid_number("1234567890123456"));
        assert!(!valid_number("0234567890123456"), "leading zero");
        assert!(!valid_number("123456789012345"), "15 digits");
        assert!(!valid_number("12345678901234567"), "17 digits");
        assert!(!valid_number("123456789012345a"));
        assert!(!valid_number("１２３４５６７８９０１２３４５６"), "non-ASCII digits");
        assert!(!valid_number(""));
        for _ in 0..200 {
            let n = new_account_number();
            assert!(valid_number(&n), "{n}");
        }
    }

    #[test]
    fn tokens() {
        let (a, ha) = new_token();
        let (b, hb) = new_token();
        assert_ne!(a, b);
        assert_ne!(ha, hb);
        assert_eq!(ha.len(), 32);
        // SHA-256, so a stored hash can be checked independently.
        assert_eq!(
            hex::encode(hash_token("abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(!valid_token_format(""));
        assert!(!valid_token_format(&a[..42]));
        assert!(!valid_token_format(&format!("{a}A")));
        assert!(!valid_token_format(&format!("{}+", &a[..42])), "standard alphabet");
        assert!(!valid_token_format(&format!("{}=", &a[..42])), "padding");
        assert!(!valid_token_format(&format!("{} ", &a[..42])));
    }

    #[test]
    fn attachment_ids_and_codes() {
        assert!(valid_attachment_id("0123456789abcdef0123456789abcdef"));
        assert!(!valid_attachment_id("0123456789ABCDEF0123456789ABCDEF"), "uppercase");
        assert!(!valid_attachment_id("0123456789abcdef0123456789abcde"));
        assert!(!valid_attachment_id("0123456789abcdef0123456789abcdeff"));
        assert!(!valid_attachment_id("0123456789abcdef0123456789abcdeg"));
        assert!(!valid_attachment_id("../456789abcdef0123456789abcdef01"));
        assert_ne!(new_attachment_id(), new_attachment_id());
        assert_eq!(random_bytes(0).len(), 0);
        assert_eq!(random_bytes(33).len(), 33);
        for digits in [1u32, 6, 8] {
            for _ in 0..50 {
                let c = new_numeric_code(digits);
                assert_eq!(c.len(), digits as usize);
                assert!(c.bytes().all(|b| b.is_ascii_digit()), "{c}");
            }
        }
    }
}
