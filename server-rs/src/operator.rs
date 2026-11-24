//! Statements signed by the operator: the badge of an official account and notices shown in
//! the apps.
//!
//! Users are told not to trust the server, so "this account is official" and "this message
//! comes from the operator" must not be things the server can say by itself. They are signed
//! with an admin key (the Ed25519 keys of CHATAPP_ADMIN_PUBLIC_KEYS, whose private halves
//! live only in the admin app) and the apps verify the signature against the operator keys
//! they pinned from `/v1/info` at first contact. The server checks the signature too, to
//! refuse garbage early, but it only stores and delivers.
//!
//! Signed strings (UTF-8, `\n` between fields, numbers in decimal):
//!
//! * badge:  `dialog-operator-badge-v1`, account id, base64(identity key), issued_at (ms), label
//! * notice: `dialog-operator-notice-v1`, target (`*` or an account id), created_at (ms),
//!   hex(sha256(title)), hex(sha256(body))
//!
//! The badge covers the identity key: a badge does not pass to whoever replaces the account's
//! key. The notice covers its target: a notice for one account cannot be shown to another.

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use sha2::{Digest, Sha256};

pub const BADGE_CONTEXT: &str = "dialog-operator-badge-v1";
pub const NOTICE_CONTEXT: &str = "dialog-operator-notice-v1";
/// Target of a notice for every account.
pub const EVERYONE: &str = "*";

pub const MAX_LABEL: usize = 40;
pub const MAX_TITLE: usize = 120;
pub const MAX_BODY: usize = 2000;
/// A statement must be signed about now: its time may differ from the server's by this much.
pub const MAX_SKEW_MS: i64 = 10 * 60 * 1000;

pub fn badge_string(account_id: &str, identity_key: &[u8], issued_at: i64, label: &str) -> String {
    format!("{BADGE_CONTEXT}\n{account_id}\n{}\n{issued_at}\n{label}", crate::validate::b64::encode(identity_key))
}

pub fn notice_string(target: &str, created_at: i64, title: &str, body: &str) -> String {
    format!(
        "{NOTICE_CONTEXT}\n{target}\n{created_at}\n{}\n{}",
        hex::encode(Sha256::digest(title.as_bytes())),
        hex::encode(Sha256::digest(body.as_bytes()))
    )
}

pub fn verify(key: &[u8; 32], message: &str, signature: &[u8]) -> bool {
    let (Ok(key), Ok(sig)) = (VerifyingKey::from_bytes(key), Signature::from_slice(signature)) else {
        return false;
    };
    key.verify(message.as_bytes(), &sig).is_ok()
}

/// One line of visible text, trimmed: no control characters, 1..=max characters.
pub fn clean_line(s: &str, max: usize) -> Option<String> {
    let t = s.trim();
    let n = t.chars().count();
    (n >= 1 && n <= max && !t.chars().any(char::is_control)).then(|| t.to_string())
}

/// Text of several lines, trimmed: no control characters but line breaks, 1..=max characters.
pub fn clean_text(s: &str, max: usize) -> Option<String> {
    let t = s.trim().replace("\r\n", "\n");
    let n = t.chars().count();
    (n >= 1 && n <= max && !t.chars().any(|c| c.is_control() && c != '\n')).then_some(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn statements_are_bound_to_what_they_are_about() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let badge = badge_string("0b6c8a52-3c1e-4f0e-9a43-2d4f7d1e8b11", &[5u8; 33], 1_790_000_000_000, "Dialog Support");
        let sig = sk.sign(badge.as_bytes()).to_bytes();
        assert!(verify(&pk, &badge, &sig));
        // Another account, another identity key, another label, another signer.
        for other in [
            badge_string("1b6c8a52-3c1e-4f0e-9a43-2d4f7d1e8b11", &[5u8; 33], 1_790_000_000_000, "Dialog Support"),
            badge_string("0b6c8a52-3c1e-4f0e-9a43-2d4f7d1e8b11", &[6u8; 33], 1_790_000_000_000, "Dialog Support"),
            badge_string("0b6c8a52-3c1e-4f0e-9a43-2d4f7d1e8b11", &[5u8; 33], 1_790_000_000_000, "Dialog Admin"),
        ] {
            assert!(!verify(&pk, &other, &sig));
        }
        assert!(!verify(&SigningKey::from_bytes(&[8u8; 32]).verifying_key().to_bytes(), &badge, &sig));
        assert!(!verify(&pk, &badge, &sig[..63]));

        let notice = notice_string(EVERYONE, 1_790_000_000_000, "Maintenance", "Tonight at 23:00.");
        let sig = sk.sign(notice.as_bytes()).to_bytes();
        assert!(verify(&pk, &notice, &sig));
        assert!(!verify(&pk, &notice_string("0b6c8a52-3c1e-4f0e-9a43-2d4f7d1e8b11", 1_790_000_000_000, "Maintenance", "Tonight at 23:00."), &sig));
        assert!(!verify(&pk, &notice_string(EVERYONE, 1_790_000_000_000, "Maintenance", "Tonight at 22:00."), &sig));
        // A notice is not a badge: the contexts differ.
        assert!(!verify(&pk, &badge, &sig));
    }

    #[test]
    fn the_signed_strings_are_fixed() {
        // The admin app and the apps build the same strings: these must not change.
        assert_eq!(
            badge_string("0b6c8a52-3c1e-4f0e-9a43-2d4f7d1e8b11", &[5, 1, 2], 1790000000000, "Dialog Support"),
            "dialog-operator-badge-v1\n0b6c8a52-3c1e-4f0e-9a43-2d4f7d1e8b11\nBQEC\n1790000000000\nDialog Support"
        );
        assert_eq!(
            notice_string("*", 1790000000000, "Hi", "there"),
            "dialog-operator-notice-v1\n*\n1790000000000\n3639efcd08abb273b1619e82e78c29a7df02c1051b1820e99fc395dcaa3326b8\ne244f187f696561d5fd7e00f618e7ba641dc52e3c137380f6fa23a854b773aac"
        );
    }

    #[test]
    fn text_fields() {
        assert_eq!(clean_line("  Dialog Support ", MAX_LABEL).as_deref(), Some("Dialog Support"));
        assert!(clean_line("", MAX_LABEL).is_none() && clean_line("a\nb", MAX_LABEL).is_none());
        assert!(clean_line(&"x".repeat(MAX_LABEL + 1), MAX_LABEL).is_none());
        assert_eq!(clean_text("a\r\nb\n", MAX_BODY).as_deref(), Some("a\nb"));
        assert!(clean_text("a\u{7}b", MAX_BODY).is_none() && clean_text("   ", MAX_BODY).is_none());
    }
}
