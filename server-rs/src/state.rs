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

    /// Client address, honouring the configured trusted proxy header (right-most entry of
    /// X-Forwarded-For, the one appended by our own proxy).
    pub fn client_ip(&self, headers: &HeaderMap, peer: SocketAddr) -> String {
        let hdr = &self.cfg.trusted_proxy_header;
        if !hdr.is_empty() {
            if let Some(v) = headers.get(hdr.as_str()).and_then(|v| v.to_str().ok()) {
                if let Some(last) = v.split(',').next_back() {
                    if let Ok(ip) = last.trim().parse::<std::net::IpAddr>() {
                        return ip.to_canonical().to_string();
                    }
                }
            }
        }
        peer.ip().to_canonical().to_string()
    }
}
