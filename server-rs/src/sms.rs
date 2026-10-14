//! Phone verification codes through a pluggable SMS provider.

use crate::storage::async_trait_shim::BoxFuture;

pub trait SmsSender: Send + Sync {
    fn send<'a>(&'a self, phone: &'a str, text: &'a str) -> BoxFuture<'a, Result<(), String>>;
}

/// Writes messages to the server log (development, servers without an SMS gateway).
pub struct LogSender;

impl SmsSender for LogSender {
    fn send<'a>(&'a self, phone: &'a str, text: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            tracing::info!(phone, text, "sms (log provider)");
            Ok(())
        })
    }
}

/// Twilio Messages REST API.
pub struct TwilioSender {
    pub account_sid: String,
    pub auth_token: String,
    pub from: String,
    pub client: reqwest::Client,
    pub base_url: String,
}

impl TwilioSender {
    pub fn new(account_sid: String, auth_token: String, from: String) -> TwilioSender {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("http client");
        TwilioSender {
            account_sid,
            auth_token,
            from,
            client,
            base_url: "https://api.twilio.com".into(),
        }
    }
}

impl SmsSender for TwilioSender {
    fn send<'a>(&'a self, phone: &'a str, text: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let sid: String =
                url::form_urlencoded::byte_serialize(self.account_sid.as_bytes()).collect();
            let endpoint = format!("{}/2010-04-01/Accounts/{sid}/Messages.json", self.base_url);
            let resp = self
                .client
                .post(endpoint)
                .basic_auth(&self.account_sid, Some(&self.auth_token))
                .form(&[("To", phone), ("From", self.from.as_str()), ("Body", text)])
                .send()
                .await
                .map_err(|e| format!("twilio request: {e}"))?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let body: String = body.chars().take(512).collect();
                return Err(format!("twilio: status {status}: {}", body.trim()));
            }
            Ok(())
        })
    }
}
