//! Shared server state handed to every handler.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::HeaderMap;
use sqlx::MySqlPool;

use crate::config::Config;
use crate::error::{rate_limited, ApiError};
use crate::push::Dispatcher;
use crate::ratelimit::{Limiter, Rule, Rules};
use crate::sealed::Issuer;
use crate::sms::SmsSender;
use crate::storage::Store;
use crate::ws::Hub;

pub struct Inner {
    pub cfg: Config,
    pub db: MySqlPool,
    pub store: Arc<dyn Store>,
    /// None disables phone verification.
    pub sms: Option<Arc<dyn SmsSender>>,
    pub limits: Rules,
    pub limiter: Limiter,
    pub prov: crate::api::provisioning::ProvisioningStore,
    pub hub: Arc<Hub>,
    pub push: Arc<Dispatcher>,
    pub sealed: Issuer,
    /// zkgroup server parameters.
    pub zk: Arc<crate::zk::ZkParams>,
    /// Key transparency log (keytrans.rs).
    pub kt: Arc<crate::keytrans::KtLog>,
    /// Settings an admin can change at runtime (registration, limits); read with
    /// `settings.get()` instead of the corresponding `cfg` fields.
    pub settings: crate::settings::Runtime,
    /// Admin API (None: disabled).
    pub admin: Option<crate::admin::Admin>,
    /// Attachment uploads in progress per account.
    pub uploads: crate::api::attachments::UploadSlots,
    /// Countries of addresses, for daily totals only (geoip.rs).
    pub geoip: crate::geoip::Shared,
}

#[derive(Clone)]
pub struct AppState(pub Arc<Inner>);

impl std::ops::Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl Inner {
    /// Consumes a token for `key` under `rule`; 429 when exhausted.
    pub fn rate_limit(&self, key: &str, rule: Rule) -> Result<(), ApiError> {
        self.limiter.allow(key, rule).map_err(|wait| {
            crate::metrics::rate_limited(key);
            rate_limited(wait)
        })
    }

    /// Consumes `n` tokens for `key` under `rule` (fan-outs); 429 when exhausted.
    pub fn rate_limit_n(&self, key: &str, rule: Rule, n: u32) -> Result<(), ApiError> {
        self.limiter.allow_n(key, rule, n).map_err(|wait| {
            crate::metrics::rate_limited(key);
            rate_limited(wait)
        })
    }

    /// Country of the client, for the daily totals (None without a GeoIP database).
    pub fn client_country(&self, headers: &HeaderMap, peer: SocketAddr) -> Option<crate::geoip::Country> {
        if !self.geoip.enabled() {
            return None;
        }
        match self.client_ip(headers, peer).parse() {
            Ok(ip) => self.geoip.country(ip),
            Err(_) => Some(crate::geoip::UNKNOWN),
        }
    }

    /// Client address, honouring the configured trusted proxy header (right-most entry of
    /// X-Forwarded-For, the one appended by our own proxy).
    pub fn client_ip(&self, headers: &HeaderMap, peer: SocketAddr) -> String {
        client_ip(&self.cfg.trusted_proxy_header, headers, peer)
    }
}

/// See [`Inner::client_ip`]. The header may come in several lines (a proxy may append its own
/// line after one the client sent): the last line is the proxy's, and within it the right-most
/// entry.
fn client_ip(trusted_header: &str, headers: &HeaderMap, peer: SocketAddr) -> String {
    if !trusted_header.is_empty() {
        if let Some(v) = headers.get_all(trusted_header).iter().next_back().and_then(|v| v.to_str().ok()) {
            if let Some(last) = v.split(',').next_back() {
                if let Ok(ip) = last.trim().parse::<std::net::IpAddr>() {
                    return ip.to_canonical().to_string();
                }
            }
        }
    }
    peer.ip().to_canonical().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn client_ip_uses_the_proxys_entry() {
        let peer: SocketAddr = "10.0.0.2:5000".parse().unwrap();
        let mut h = HeaderMap::new();
        // No trusted header configured: the peer, whatever the client sends.
        h.append("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        assert_eq!(client_ip("", &h, peer), "10.0.0.2");
        // One line: its right-most entry (the one our proxy appended).
        let mut h = HeaderMap::new();
        h.append("x-forwarded-for", HeaderValue::from_static("1.2.3.4, 203.0.113.7"));
        assert_eq!(client_ip("X-Forwarded-For", &h, peer), "203.0.113.7");
        // The client's own line first, the proxy's line after it: the proxy's counts.
        let mut h = HeaderMap::new();
        h.append("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        h.append("x-forwarded-for", HeaderValue::from_static("198.51.100.9"));
        assert_eq!(client_ip("X-Forwarded-For", &h, peer), "198.51.100.9");
        let mut h = HeaderMap::new();
        h.append("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        h.append("x-forwarded-for", HeaderValue::from_static("5.6.7.8, 198.51.100.9"));
        assert_eq!(client_ip("X-Forwarded-For", &h, peer), "198.51.100.9");
        // IPv4-mapped IPv6 is shown as IPv4; garbage falls back to the peer.
        let mut h = HeaderMap::new();
        h.append("x-real-ip", HeaderValue::from_static("::ffff:192.0.2.1"));
        assert_eq!(client_ip("X-Real-IP", &h, peer), "192.0.2.1");
        let mut h = HeaderMap::new();
        h.append("x-real-ip", HeaderValue::from_static("not an address"));
        assert_eq!(client_ip("X-Real-IP", &h, peer), "10.0.0.2");
    }
}
