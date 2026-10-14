//! Firebase Cloud Messaging HTTP v1 client, authenticated with OAuth2 access tokens obtained
//! with a JWT signed by the service account key (cached until shortly before expiry).

use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;

use super::{read_body, retry_after, with_retries, AttemptError, Notifier, PushError, Wake};
use crate::storage::async_trait_shim::BoxFuture;

const DEFAULT_ENDPOINT: &str = "https://fcm.googleapis.com";
const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(15);

pub struct Fcm {
    project_id: String,
    url: String,
    client_email: String,
    token_uri: String,
    key: EncodingKey,
    key_id: String,
    client: reqwest::Client,
    token: Mutex<Option<(String, Instant)>>,
}

#[derive(Deserialize)]
struct Credentials {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    project_id: String,
    #[serde(default)]
    client_email: String,
    #[serde(default)]
    private_key: String,
    #[serde(default)]
    token_uri: String,
    #[serde(default)]
    private_key_id: String,
}

impl Fcm {
    /// Parses the service account credentials; no network request until the first push.
    pub fn new(credentials_json: &[u8]) -> Result<Fcm, String> {
        Self::with_endpoint(credentials_json, DEFAULT_ENDPOINT)
    }

    /// Like [`Fcm::new`] with another FCM API origin (tests).
    pub(crate) fn with_endpoint(credentials_json: &[u8], endpoint: &str) -> Result<Fcm, String> {
        let c: Credentials = serde_json::from_slice(credentials_json)
            .map_err(|e| format!("fcm credentials: invalid JSON: {e}"))?;
        if c.kind != "service_account" {
            return Err(format!(
                "fcm credentials: type must be \"service_account\", got {:?}",
                c.kind
            ));
        }
        if c.project_id.is_empty() {
            return Err("fcm credentials: project_id is missing".into());
        }
        // Do not quote errors: they could contain parts of the key.
        let key = EncodingKey::from_rsa_pem(c.private_key.as_bytes()).map_err(|_| {
            "fcm credentials: client_email or private_key is missing or invalid".to_string()
        })?;
        if c.client_email.is_empty() {
            return Err(
                "fcm credentials: client_email or private_key is missing or invalid".into(),
            );
        }
        let client = reqwest::Client::builder()
            .timeout(ATTEMPT_TIMEOUT)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Fcm {
            url: format!(
                "{endpoint}/v1/projects/{}/messages:send",
                c.project_id
            ),
            project_id: c.project_id,
            client_email: c.client_email,
            token_uri: if c.token_uri.is_empty() {
                "https://oauth2.googleapis.com/token".into()
            } else {
                c.token_uri
            },
            key,
            key_id: c.private_key_id,
            client,
            token: Mutex::new(None),
        })
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    async fn access_token(&self) -> Result<String, String> {
        let mut cached = self.token.lock().await;
        if let Some((tok, exp)) = cached.as_ref() {
            // Refreshed 10 s before expiry, like Go's oauth2.
            if Instant::now() + Duration::from_secs(10) < *exp {
                return Ok(tok.clone());
            }
        }
        #[derive(Serialize)]
        struct Claims<'a> {
            iss: &'a str,
            scope: &'a str,
            aud: &'a str,
            iat: u64,
            exp: u64,
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Like Go's oauth2/jws: iat backdated 10 s (clock skew), kid = private_key_id.
        let mut header = Header::new(Algorithm::RS256);
        if !self.key_id.is_empty() {
            header.kid = Some(self.key_id.clone());
        }
        let now = now.saturating_sub(10);
        let jwt = jsonwebtoken::encode(
            &header,
            &Claims {
                iss: &self.client_email,
                scope: SCOPE,
                aud: &self.token_uri,
                iat: now,
                exp: now + 3600,
            },
            &self.key,
        )
        .map_err(|e| format!("sign jwt: {e}"))?;
        #[derive(Deserialize)]
        struct TokenResp {
            access_token: String,
            #[serde(default)]
            expires_in: u64,
        }
        let resp = self
            .client
            .post(&self.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", jwt.as_str()),
            ])
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("token endpoint: HTTP {}", resp.status().as_u16()));
        }
        let t: TokenResp = resp.json().await.map_err(|e| e.to_string())?;
        let ttl = if t.expires_in == 0 {
            3600
        } else {
            t.expires_in
        };
        *cached = Some((
            t.access_token.clone(),
            Instant::now() + Duration::from_secs(ttl),
        ));
        Ok(t.access_token)
    }

    /// One attempt: Ok, or (temporary?, retry_after, error).
    async fn send_once(&self, body: &serde_json::Value) -> Result<(), AttemptError> {
        let tok = self.access_token().await.map_err(|e| {
            let short: String = e.chars().take(200).collect();
            (
                true,
                Duration::ZERO,
                PushError::Other(format!("fcm: obtain access token: {short}")),
            )
        })?;
        let resp = self
            .client
            .post(&self.url)
            .bearer_auth(tok)
            .json(body)
            .send()
            .await
            .map_err(|e| {
                (
                    true,
                    Duration::ZERO,
                    PushError::Other(format!("fcm: request failed: {}", e.without_url())),
                )
            })?;
        let status = resp.status().as_u16();
        let retry_after = retry_after(resp.headers());
        let text = read_body(resp).await;
        if (200..300).contains(&status) {
            return Ok(());
        }
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
        let rpc_status = parsed["error"]["status"].as_str().unwrap_or("").to_string();
        let error_code = parsed["error"]["details"]
            .as_array()
            .and_then(|d| {
                d.iter().find_map(|x| {
                    let t = x["@type"].as_str().unwrap_or("");
                    let c = x["errorCode"].as_str().unwrap_or("");
                    (t.ends_with("google.firebase.fcm.v1.FcmError") && !c.is_empty())
                        .then(|| c.to_string())
                })
            })
            .unwrap_or_default();
        let mut msg = format!("fcm: HTTP {status}");
        if !rpc_status.is_empty() {
            msg += &format!(" {rpc_status}");
        }
        if !error_code.is_empty() {
            msg += &format!(" ({error_code})");
        }
        let invalid = match error_code.as_str() {
            "UNREGISTERED" | "INVALID_ARGUMENT" => true,
            "" => rpc_status == "INVALID_ARGUMENT",
            _ => false,
        };
        if invalid {
            return Err((false, Duration::ZERO, PushError::InvalidToken(msg)));
        }
        Err((
            status == 429 || status >= 500,
            retry_after,
            PushError::Other(msg),
        ))
    }
}

/// Call pushes are useless once the caller stopped ringing.
const CALL_TTL_SECS: u64 = 60;

/// The FCM v1 message for `wake`. Android gets a data-only high-priority message (the app's
/// background handler decides what to show); iOS gets a visible alert with fixed, localized
/// text (loc-key, see ios/Runner/*.lproj/Localizable.strings) since the app cannot run before
/// it is shown. Nothing identifies the sender or the conversation.
pub(crate) fn message_body(token: &str, tag: &str, wake: &Wake, now_secs: u64) -> serde_json::Value {
    let mut data = serde_json::Map::new();
    if !tag.is_empty() {
        data.insert("p".into(), json!(tag));
    }
    match wake {
        Wake::Message => {
            data.insert("type".into(), json!("new_message"));
            json!({"message": {
                "token": token,
                "data": data,
                "android": {"priority": "HIGH", "collapse_key": "new_message", "ttl": "86400s"},
                "apns": {
                    "headers": {"apns-priority": "10", "apns-collapse-id": "new_message", "apns-push-type": "alert"},
                    "payload": {"aps": {"alert": {"loc-key": "NEW_MESSAGE"}, "sound": "default", "mutable-content": 1, "thread-id": "chatapp"}}
                }
            }})
        }
        Wake::Call { call_id } => {
            data.insert("type".into(), json!("call"));
            data.insert("call_id".into(), json!(call_id));
            json!({"message": {
                "token": token,
                "data": data,
                "android": {"priority": "HIGH", "ttl": format!("{CALL_TTL_SECS}s")},
                "apns": {
                    "headers": {
                        "apns-priority": "10",
                        "apns-push-type": "alert",
                        "apns-collapse-id": "call",
                        "apns-expiration": (now_secs + CALL_TTL_SECS).to_string()
                    },
                    "payload": {"aps": {"alert": {"loc-key": "INCOMING_CALL"}, "sound": "default", "thread-id": "chatapp-calls"}}
                }
            }})
        }
    }
}

impl Notifier for Fcm {
    /// Pushes a wake-up, retrying 5xx / 429 / network errors with backoff.
    fn send<'a>(&'a self, token: &'a str, tag: &'a str, wake: &'a Wake) -> BoxFuture<'a, Result<(), PushError>> {
        Box::pin(async move {
            let body = message_body(token, tag, wake, crate::now_millis() as u64 / 1000);
            with_retries(|| Box::pin(self.send_once(&body))).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push::testutil::serve;

    /// Throwaway key generated for these tests only.
    const TEST_KEY: &str = include_str!("testdata/test-rsa.pem");

    fn creds(token_uri: &str) -> Vec<u8> {
        json!({
            "type": "service_account",
            "project_id": "dialog-test",
            "client_email": "push@dialog-test.iam.gserviceaccount.com",
            "private_key": TEST_KEY,
            "private_key_id": "kid-1",
            "token_uri": token_uri,
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn rejects_bad_credentials() {
        assert!(Fcm::new(b"not json").is_err());
        assert!(Fcm::new(br#"{"type":"authorized_user"}"#).is_err());
        let no_key = json!({"type": "service_account", "project_id": "p", "client_email": "e", "private_key": "x"});
        let e = Fcm::new(no_key.to_string().as_bytes()).err().unwrap();
        assert!(!e.contains('x'), "error must not quote the key: {e}");
        assert_eq!(Fcm::new(&creds("https://oauth2.googleapis.com/token")).unwrap().project_id(), "dialog-test");
    }

    #[test]
    fn payloads_carry_no_content() {
        let m = message_body("tok", "tag1", &Wake::Message, 1000);
        assert_eq!(m["message"]["data"], json!({"type": "new_message", "p": "tag1"}));
        assert_eq!(m["message"]["android"]["priority"], "HIGH");
        assert_eq!(m["message"]["android"]["collapse_key"], "new_message");
        assert_eq!(m["message"]["apns"]["payload"]["aps"]["alert"], json!({"loc-key": "NEW_MESSAGE"}));
        assert!(m["message"].get("notification").is_none());
        let c = message_body("tok", "", &Wake::Call { call_id: "c-1".into() }, 1000);
        assert_eq!(c["message"]["data"], json!({"type": "call", "call_id": "c-1"}));
        assert_eq!(c["message"]["android"]["ttl"], "60s");
        assert_eq!(c["message"]["apns"]["headers"]["apns-expiration"], "1060");
        assert_eq!(c["message"]["apns"]["payload"]["aps"]["alert"], json!({"loc-key": "INCOMING_CALL"}));
    }

    #[tokio::test]
    async fn sends_with_oauth_token() {
        let (base, seen) = serve(vec![(200, r#"{"name":"projects/dialog-test/messages/1"}"#)]).await;
        let fcm = Fcm::with_endpoint(&creds(&format!("{base}/token")), &base).unwrap();
        fcm.send("device-token", "t", &Wake::Message).await.unwrap();
        fcm.send("device-token", "t", &Wake::Call { call_id: "c".into() }).await.unwrap();
        let seen = seen.lock().unwrap().clone();
        // One token exchange (cached), then the two sends.
        let paths: Vec<_> = seen.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(paths, ["/token", "/v1/projects/dialog-test/messages:send", "/v1/projects/dialog-test/messages:send"]);
        assert!(seen[0].body.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"));
        assert_eq!(seen[1].headers["authorization"], "Bearer at-1");
        let body: serde_json::Value = serde_json::from_str(&seen[2].body).unwrap();
        assert_eq!(body["message"]["token"], "device-token");
        assert_eq!(body["message"]["data"]["type"], "call");
    }

    #[tokio::test]
    async fn unregistered_token_is_invalid() {
        let (base, seen) = serve(vec![(
            404,
            r#"{"error":{"code":404,"status":"NOT_FOUND","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}"#,
        )])
        .await;
        let fcm = Fcm::with_endpoint(&creds(&format!("{base}/token")), &base).unwrap();
        match fcm.send("secret-device-token", "", &Wake::Message).await {
            Err(PushError::InvalidToken(m)) => {
                assert!(m.contains("UNREGISTERED"));
                assert!(!m.contains("secret-device-token"));
            }
            other => panic!("unexpected {other:?}"),
        }
        // Not retried.
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn retries_server_errors() {
        let (base, seen) = serve(vec![(503, "{}"), (200, "{}")]).await;
        let fcm = Fcm::with_endpoint(&creds(&format!("{base}/token")), &base).unwrap();
        fcm.send("tok", "", &Wake::Message).await.unwrap();
        assert_eq!(seen.lock().unwrap().len(), 3);
        let (base, _) = serve(vec![(403, r#"{"error":{"status":"PERMISSION_DENIED"}}"#)]).await;
        let fcm = Fcm::with_endpoint(&creds(&format!("{base}/token")), &base).unwrap();
        assert!(matches!(fcm.send("tok", "", &Wake::Message).await, Err(PushError::Other(_))));
    }
}
