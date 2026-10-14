//! RFC 6238 TOTP (HMAC-SHA1, 30 s steps, 6 digits), the variant every authenticator supports.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

pub const PERIOD_SECS: i64 = 30;
pub const DIGITS: usize = 6;
/// Steps before / after the current one that are accepted (clock drift).
pub const SKEW: i64 = 1;

/// Random 160-bit secret.
pub fn new_secret() -> Vec<u8> {
    crate::ids::random_bytes(20)
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Base32 without padding (shown to users and put in otpauth URIs).
pub fn encode(secret: &[u8]) -> String {
    let mut out = String::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &b in secret {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(B32[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn step(unix_secs: i64) -> i64 {
    unix_secs.div_euclid(PERIOD_SECS)
}

/// RFC 4226 HOTP code for a time step.
pub fn code(secret: &[u8], step: i64) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("hmac key");
    mac.update(&(step as u64).to_be_bytes());
    let sum = mac.finalize().into_bytes();
    let off = (sum[sum.len() - 1] & 0x0f) as usize;
    let v = u32::from_be_bytes([sum[off], sum[off + 1], sum[off + 2], sum[off + 3]]) & 0x7fff_ffff;
    format!("{:06}", v % 1_000_000)
}

/// Checks `code` around `now_secs`; returns the matching step. Steps at or before
/// `last_used` are rejected so a code cannot be replayed.
pub fn verify(secret: &[u8], code_in: &str, now_secs: i64, last_used: i64) -> Option<i64> {
    let c: String = code_in.trim().chars().filter(|c| *c != ' ').collect();
    if c.len() != DIGITS {
        return None;
    }
    let current = step(now_secs);
    for d in -SKEW..=SKEW {
        let s = current + d;
        if s <= last_used {
            continue;
        }
        if bool::from(code(secret, s).as_bytes().ct_eq(c.as_bytes())) {
            return Some(s);
        }
    }
    None
}

fn path_escape(s: &str) -> String {
    // Exactly Go's url.PathEscape.
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~$&+:=@".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// otpauth:// link encoded in the QR code for authenticator apps.
pub fn uri(secret: &[u8], issuer: &str, account: &str) -> String {
    let label = path_escape(&format!("{issuer}:{account}"));
    // Go's url.Values.Encode: keys sorted, values escaped with QueryEscape.
    let pairs = [
        ("algorithm", "SHA1".to_string()),
        ("digits", DIGITS.to_string()),
        ("issuer", issuer.to_string()),
        ("period", PERIOD_SECS.to_string()),
        ("secret", encode(secret)),
    ];
    let q: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", query_escape(v)))
        .collect();
    format!("otpauth://totp/{label}?{}", q.join("&"))
}

/// Go's url.QueryEscape.
fn query_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else if b == b' ' {
            out.push('+');
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_vectors() {
        let secret = b"12345678901234567890";
        // RFC 6238 appendix B (SHA1, 8 digits) truncated to 6 digits.
        assert_eq!(code(secret, step(59)), "287082");
        assert_eq!(code(secret, step(1111111109)), "081804");
        assert_eq!(encode(b"foobar"), "MZXW6YTBOI");
        let s = step(1_000_000);
        assert_eq!(verify(secret, &code(secret, s), 1_000_000, 0), Some(s));
        assert_eq!(verify(secret, &code(secret, s), 1_000_000, s), None);
        // Same escaping as Go's url.PathEscape / url.Values.Encode.
        assert_eq!(
            uri(b"foobar", "My Chat (EU)*", "1234"),
            "otpauth://totp/My%20Chat%20%28EU%29%2A:1234?algorithm=SHA1&digits=6&issuer=My+Chat+%28EU%29%2A&period=30&secret=MZXW6YTBOI"
        );
    }
}
