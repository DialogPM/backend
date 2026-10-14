//! Direct APNs client for iOS VoIP (PushKit) pushes of incoming calls, with token-based
//! authentication: an ES256 JWT signed with the team's .p8 auth key (reused for 40 minutes;
//! Apple accepts tokens up to one hour old and refuses refreshing more than every 20).
//!
//! VoIP pushes wake the app even when it was terminated, and iOS requires the app to report
//! every one of them to CallKit right away: they are sent for call offers only.

use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::json;
use tokio::sync::Mutex;

use super::{read_body, retry_after, with_retries, AttemptError, Notifier, PushError, Wake};
use crate::storage::async_trait_shim::BoxFuture;

const PRODUCTION: &str = "https://api.push.apple.com";
const SANDBOX: &str = "https://api.sandbox.push.apple.com";
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(15);
const JWT_LIFETIME: Duration = Duration::from_secs(40 * 60);
/// A call push older than this is dropped by APNs (the caller stopped ringing).
const CALL_TTL_SECS: u64 = 60;

pub struct Apns {
    base: String,
    topic: String,
    team_id: String,
    key_id: String,
    key: EncodingKey,
    client: reqwest::Client,
    jwt: Mutex<Option<(String, Instant)>>,
}

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    iat: u64,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl Apns {
    /// Parses the .p8 key and checks that it signs; no network request until the first push.
    pub fn new(
        key_pem: &[u8],
        key_id: &str,
        team_id: &str,
        topic: &str,
        sandbox: bool,
    ) -> Result<Apns, String> {
        Self::with_endpoint(key_pem, key_id, team_id, topic, if sandbox { SANDBOX } else { PRODUCTION })
    }

    /// Like [`Apns::new`] with another APNs origin (tests).
    pub(crate) fn with_endpoint(
        key_pem: &[u8],
        key_id: &str,
        team_id: &str,
        topic: &str,
        base: &str,
    ) -> Result<Apns, String> {
        // Do not quote errors: they could contain parts of the key.
        let bad = || "apns: CHATAPP_APNS_KEY_FILE is not a valid .p8 (P-256) auth key".to_string();
        let key = EncodingKey::from_ec_pem(key_pem).map_err(|_| bad())?;
        let client = reqwest::Client::builder()
            .timeout(ATTEMPT_TIMEOUT)
            .build()
            .map_err(|e| e.to_string())?;
        let a = Apns {
            base: base.trim_end_matches('/').to_string(),
            topic: topic.to_string(),
            team_id: team_id.to_string(),
            key_id: key_id.to_string(),
            key,
            client,
            jwt: Mutex::new(None),
        };
        a.sign(now_secs()).map_err(|_| bad())?;
        Ok(a)
    }

    pub fn topic(&self) -> &str {
        &self.topic
    }

    fn sign(&self, iat: u64) -> Result<String, jsonwebtoken::errors::Error> {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        jsonwebtoken::encode(&header, &Claims { iss: &self.team_id, iat }, &self.key)
    }

    /// The provider token, signed again when older than JWT_LIFETIME or after APNs refused it.
    async fn provider_token(&self, refresh: bool) -> Result<String, String> {
        let mut cached = self.jwt.lock().await;
        if let Some((tok, at)) = cached.as_ref() {
            if !refresh && at.elapsed() < JWT_LIFETIME {
                return Ok(tok.clone());
            }
        }
        let tok = self.sign(now_secs()).map_err(|e| format!("sign jwt: {e}"))?;
        *cached = Some((tok.clone(), Instant::now()));
        Ok(tok)
    }

    async fn send_once(&self, token: &str, body: &str, refresh: bool) -> Result<(), AttemptError> {
        let jwt = self
            .provider_token(refresh)
            .await
            .map_err(|e| (false, Duration::ZERO, PushError::Other(format!("apns: {e}"))))?;
        let resp = self
            .client
            .post(format!("{}/3/device/{token}", self.base))
            .bearer_auth(jwt)
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "voip")
            .header("apns-priority", "10")
            .header("apns-expiration", (now_secs() + CALL_TTL_SECS).to_string())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .send()
            .await
            // The URL holds the device token: never in an error message.
            .map_err(|e| {
                (
                    true,
                    Duration::ZERO,
                    PushError::Other(format!("apns: request failed: {}", e.without_url())),
                )
            })?;
        let status = resp.status().as_u16();
        let retry_after = retry_after(resp.headers());
        let text = read_body(resp).await;
        if status == 200 {
            return Ok(());
        }
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
        let reason: String = parsed["reason"]
            .as_str()
            .unwrap_or("")
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(64)
            .collect();
        let msg = if reason.is_empty() {
            format!("apns: HTTP {status}")
        } else {
            format!("apns: HTTP {status} ({reason})")
        };
        match (status, reason.as_str()) {
            // The token is no longer (or never was) valid for this app and environment.
            (410, _) | (400, "BadDeviceToken") => {
                Err((false, Duration::ZERO, PushError::InvalidToken(msg)))
            }
            // Our provider token: sign a new one and try again.
            (403, "ExpiredProviderToken") | (403, "InvalidProviderToken") => {
                Err((true, Duration::ZERO, PushError::Other(msg)))
            }
            _ => Err((status == 429 || status >= 500, retry_after, PushError::Other(msg))),
        }
    }
}

/// The VoIP payload: an empty aps, the call id and the device's push tag; nothing about the
/// caller (the app fetches and decrypts the offer once CallKit shows the call).
pub(crate) fn voip_body(tag: &str, call_id: &str) -> String {
    let mut b = json!({"aps": {}, "type": "call", "call_id": call_id});
    if !tag.is_empty() {
        b["p"] = json!(tag);
    }
    b.to_string()
}

impl Notifier for Apns {
    fn send<'a>(&'a self, token: &'a str, tag: &'a str, wake: &'a Wake) -> BoxFuture<'a, Result<(), PushError>> {
        Box::pin(async move {
            let Wake::Call { call_id } = wake else {
                // Apple ends VoIP delivery to apps that do not report a call for each push.
                return Err(PushError::Other("apns: VoIP pushes are for calls only".into()));
            };
            // An APNs device token is hex; anything else cannot be put in the URL path.
            if token.is_empty() || !token.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(PushError::InvalidToken("apns: malformed device token".into()));
            }
            let body = voip_body(tag, call_id);
            let refresh = std::sync::atomic::AtomicBool::new(false);
            with_retries(|| {
                let again = refresh.swap(false, std::sync::atomic::Ordering::SeqCst);
                let refresh = &refresh;
                let body = &body;
                Box::pin(async move {
                    let r = self.send_once(token, body, again).await;
                    if let Err((true, _, PushError::Other(m))) = &r {
                        if m.contains("ProviderToken") {
                            refresh.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                    r
                })
            })
            .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push::testutil::serve;

    /// Throwaway P-256 key generated for these tests only.
    const TEST_KEY: &[u8] = include_bytes!("testdata/test-apns.p8");
    const TOKEN: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

    fn client(base: &str) -> Apns {
        Apns::with_endpoint(TEST_KEY, "ABC123DEFG", "ABCDE12345", "pm.dialog.chat.voip", base).unwrap()
    }

    #[test]
    fn rejects_bad_keys() {
        assert!(Apns::new(b"nope", "ABC123DEFG", "ABCDE12345", "t.voip", false).is_err());
        let rsa = include_bytes!("testdata/test-rsa.pem");
        assert!(Apns::new(rsa, "ABC123DEFG", "ABCDE12345", "t.voip", true).is_err());
        assert_eq!(client(PRODUCTION).topic(), "pm.dialog.chat.voip");
    }

    #[tokio::test]
    async fn sends_voip_push_with_jwt() {
        let (base, seen) = serve(vec![(200, "")]).await;
        let a = client(&base);
        a.send(TOKEN, "tag-1", &Wake::Call { call_id: "call-1".into() }).await.unwrap();
        a.send(TOKEN, "", &Wake::Call { call_id: "call-2".into() }).await.unwrap();
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        let s = &seen[0];
        assert_eq!(s.path, format!("/3/device/{TOKEN}"));
        assert_eq!(s.headers["apns-topic"], "pm.dialog.chat.voip");
        assert_eq!(s.headers["apns-push-type"], "voip");
        assert_eq!(s.headers["apns-priority"], "10");
        let body: serde_json::Value = serde_json::from_str(&s.body).unwrap();
        assert_eq!(body, json!({"aps": {}, "type": "call", "call_id": "call-1", "p": "tag-1"}));
        // ES256 JWT with kid / iss, reused for the second push.
        let auth = s.headers["authorization"].to_str().unwrap();
        let jwt = auth.strip_prefix("bearer ").or_else(|| auth.strip_prefix("Bearer ")).unwrap();
        let header = jsonwebtoken::decode_header(jwt).unwrap();
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid.as_deref(), Some("ABC123DEFG"));
        assert_eq!(seen[1].headers["authorization"], s.headers["authorization"]);
    }

    #[tokio::test]
    async fn invalid_tokens_and_messages() {
        let (base, seen) = serve(vec![(410, r#"{"reason":"Unregistered","timestamp":1}"#)]).await;
        let a = client(&base);
        let call = Wake::Call { call_id: "c".into() };
        match a.send(TOKEN, "", &call).await {
            Err(PushError::InvalidToken(m)) => {
                assert!(m.contains("Unregistered"));
                assert!(!m.contains(TOKEN));
            }
            other => panic!("unexpected {other:?}"),
        }
        let (base2, _) = serve(vec![(400, r#"{"reason":"BadDeviceToken"}"#)]).await;
        assert!(matches!(client(&base2).send(TOKEN, "", &call).await, Err(PushError::InvalidToken(_))));
        // A topic mismatch is a server configuration error: the token is kept.
        let (base3, _) = serve(vec![(400, r#"{"reason":"DeviceTokenNotForTopic"}"#)]).await;
        assert!(matches!(client(&base3).send(TOKEN, "", &call).await, Err(PushError::Other(_))));
        // Never a VoIP push for a message; never a malformed token in the URL.
        assert!(matches!(a.send(TOKEN, "", &Wake::Message).await, Err(PushError::Other(_))));
        assert!(matches!(a.send("../x", "", &call).await, Err(PushError::InvalidToken(_))));
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn refreshes_a_refused_provider_token() {
        let (base, seen) = serve(vec![(403, r#"{"reason":"ExpiredProviderToken"}"#), (200, "")]).await;
        client(&base).send(TOKEN, "", &Wake::Call { call_id: "c".into() }).await.unwrap();
        assert_eq!(seen.lock().unwrap().len(), 2);
    }
}
