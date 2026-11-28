//! Admin API under /v1/admin (docs/ADMIN-API.md). Enabled only when CHATAPP_ADMIN_PUBLIC_KEYS
//! lists at least one Ed25519 public key; every request must be signed (auth.rs).
//!
//! It exposes operational and moderation data only: never message content (the server has
//! none), never who talks to whom, never IP addresses.

pub mod auth;
pub mod bots;
pub mod logbuf;
pub mod moderation;
pub mod operator;
pub mod usernames;

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Path, RawQuery, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::MySqlPool;
use tracing::{debug, info};

use crate::api::{no_content, reply};
use crate::db::RowExt;
use crate::error::{bad_request, not_found, rate_limited, unauthorized, ApiError, ApiResult};
use crate::metrics;
use crate::ratelimit::{Limiter, Rule};
use crate::state::AppState;

/// Largest admin request body.
const MAX_ADMIN_BODY: usize = 64 << 10;
/// Failed signature checks allowed (all keys and clients together) before 429.
const FAILED_AUTH_RULE: Rule = Rule::new(20, Duration::from_secs(60));
const DAY_MS: i64 = 86_400_000;

/// Admin state kept in `Inner::admin` (None: the admin API is disabled).
pub struct Admin {
    pub verifier: auth::Verifier,
    failures: Limiter,
}

impl Admin {
    pub fn new(keys: &[[u8; 32]]) -> Option<Admin> {
        (!keys.is_empty()).then(|| Admin { verifier: auth::Verifier::new(keys), failures: Limiter::new() })
    }

    /// Periodic cleanup of expired nonces and limiter buckets.
    pub fn cleanup(&self) {
        self.verifier.prune(crate::now_millis());
        self.failures.cleanup();
    }
}

/// The /v1/admin routes (empty when the admin API is disabled, so they answer 404 like any
/// unknown path).
pub fn routes(st: &AppState) -> Router<AppState> {
    if st.admin.is_none() {
        return Router::new();
    }
    Router::new()
        .route("/v1/admin/overview", get(overview))
        .route("/v1/admin/stats", get(stats))
        .route("/v1/admin/countries", get(countries))
        .route("/v1/admin/platforms", get(platforms))
        .route("/v1/admin/reports", get(list_reports))
        .route("/v1/admin/reports/{id}/resolve", post(resolve_report))
        .route("/v1/admin/accounts", get(search_accounts))
        .route("/v1/admin/accounts/{id}", get(get_account))
        .route("/v1/admin/accounts/{id}/ban", post(ban))
        .route("/v1/admin/accounts/{id}/unban", post(unban))
        .route("/v1/admin/accounts/{id}/logout", post(logout))
        .route("/v1/admin/accounts/{id}/username/remove", post(usernames::remove))
        .route("/v1/admin/accounts/{id}/badge", post(operator::set_badge))
        .route("/v1/admin/accounts/{id}/unbadge", post(operator::remove_badge))
        .route("/v1/admin/badges", get(operator::list_badges))
        .route("/v1/admin/notices", get(operator::list_notices).post(operator::publish_notice))
        .route("/v1/admin/notices/{id}/delete", post(operator::delete_notice))
        .route("/v1/admin/usernames", get(usernames::list))
        .route("/v1/admin/usernames/matches", get(usernames::matches))
        .route("/v1/admin/usernames/block", post(usernames::block))
        .route("/v1/admin/usernames/unblock", post(usernames::unblock))
        .route("/v1/admin/bots", get(bots::list))
        .route("/v1/admin/bots/{id}/disable", post(bots::disable))
        .route("/v1/admin/bots/{id}/enable", post(bots::enable))
        .route("/v1/admin/bots/{id}/delete", post(bots::delete))
        .route("/v1/admin/settings", get(get_settings).put(put_settings))
        .route("/v1/admin/queue/purge", post(purge_queue))
        .route("/v1/admin/security", get(security))
        .route("/v1/admin/logs", get(logs))
        .route("/v1/admin/calls", get(calls))
        .route_layer(from_fn_with_state(st.clone(), require_signature))
}

pub fn is_admin_path(path: &str) -> bool {
    path == "/v1/admin" || path.starts_with("/v1/admin/")
}

/// Verifies the request signature (body included) before the handler runs.
async fn require_signature(State(st): State<AppState>, req: axum::extract::Request, next: Next) -> Response {
    let Some(admin) = st.admin.as_ref() else {
        return not_found("no such endpoint").into_response();
    };
    let (parts, body) = req.into_parts();
    let path_q = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or_else(|| parts.uri.path());
    let hdr = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("");
    let signed = auth::SignedHeaders {
        key: hdr(auth::HEADER_KEY),
        timestamp: hdr(auth::HEADER_TIMESTAMP),
        nonce: hdr(auth::HEADER_NONCE),
        signature: hdr(auth::HEADER_SIGNATURE),
    };
    let now = crate::now_millis();
    // Headers first: a request without a configured key or with a stale timestamp is refused
    // before its body is read or any signature is verified.
    let checked = match admin.verifier.precheck(&signed, now) {
        Ok(()) => match crate::validate::read_body(body, MAX_ADMIN_BODY).await {
            Ok(bytes) => admin.verifier.verify(parts.method.as_str(), path_q, &signed, &bytes, now).map(|f| (f, bytes)),
            Err(e) => return e.into_response(),
        },
        Err(reason) => Err(reason),
    };
    match checked {
        Ok((fingerprint, bytes)) => {
            // Never the query string or the body (they may hold account numbers or reasons).
            info!(method = %parts.method, path = %parts.uri.path(), key = %fingerprint, "admin request");
            next.run(axum::http::Request::from_parts(parts, Body::from(bytes))).await
        }
        Err(reason) => {
            metrics::inc(&metrics::FAILED_ADMIN_AUTH);
            debug!(?reason, path = %parts.uri.path(), "admin request rejected");
            if let Err(wait) = admin.failures.allow("admin-auth", FAILED_AUTH_RULE) {
                metrics::rate_limited("admin_auth");
                return rate_limited(wait).into_response();
            }
            unauthorized("unauthorized").into_response()
        }
    }
}

/// CORS for the admin API, so a desktop app's webview may call it directly: any origin may
/// send signed requests (no cookies or ambient credentials exist; the signature is the
/// only authorization). Only active while the admin API is enabled.
pub async fn cors(State(st): State<AppState>, req: axum::extract::Request, next: Next) -> Response {
    if st.admin.is_none() || !is_admin_path(req.uri().path()) {
        return next.run(req).await;
    }
    if req.method() == Method::OPTIONS {
        let mut resp = StatusCode::NO_CONTENT.into_response();
        let h = resp.headers_mut();
        h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST, PUT"));
        h.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("content-type, x-admin-key, x-admin-timestamp, x-admin-nonce, x-admin-signature"),
        );
        h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("600"));
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        return resp;
    }
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    resp
}

// --- helpers -------------------------------------------------------------------------------------

fn params(q: &Option<String>) -> HashMap<String, String> {
    q.as_deref()
        .map(|q| url::form_urlencoded::parse(q.as_bytes()).into_owned().collect())
        .unwrap_or_default()
}

fn int_param(p: &HashMap<String, String>, name: &str, def: i64, min: i64, max: i64) -> Result<i64, ApiError> {
    match p.get(name).map(String::as_str) {
        None | Some("") => Ok(def),
        Some(v) => v
            .parse::<i64>()
            .ok()
            .filter(|n| (min..=max).contains(n))
            .ok_or_else(|| bad_request(format!("{name} must be an integer in {min}..{max}"))),
    }
}

async fn json_body<T: DeserializeOwned>(body: Body) -> Result<T, ApiError> {
    let bytes = crate::validate::read_body(body, MAX_ADMIN_BODY).await?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return serde_json::from_str("{}").map_err(|e| bad_request(format!("invalid JSON body: {e}")));
    }
    serde_json::from_slice(&bytes).map_err(|e| bad_request(format!("invalid JSON body: {e}")))
}

fn account_id(id: &str) -> Result<String, ApiError> {
    crate::ids::normalize_uuid(id).ok_or_else(|| bad_request("account id must be a UUID"))
}

async fn scalar(db: &MySqlPool, sql: &str, binds: &[i64]) -> Result<Option<i64>, sqlx::Error> {
    let mut q = sqlx::query(sql);
    for b in binds {
        q = q.bind(*b);
    }
    Ok(q.fetch_one(db).await?.opt_i64("v"))
}

/// Trims an optional free-text field and bounds its length.
fn note(v: Option<String>, name: &str) -> Result<Option<String>, ApiError> {
    let v = v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    if v.as_ref().is_some_and(|s| s.chars().count() > 500) {
        return Err(bad_request(format!("{name} must be at most 500 characters")));
    }
    Ok(v)
}

// --- GET /overview ---------------------------------------------------------------------------

/// Database aggregates are cached briefly: the dashboard polls, and some are table scans.
static OVERVIEW_CACHE: Mutex<Option<(Instant, Value)>> = Mutex::new(None);
const OVERVIEW_CACHE_TTL: Duration = Duration::from_secs(10);

async fn db_overview(db: &MySqlPool) -> Result<Value, sqlx::Error> {
    if let Some((at, v)) = OVERVIEW_CACHE.lock().unwrap().as_ref() {
        if at.elapsed() < OVERVIEW_CACHE_TTL {
            return Ok(v.clone());
        }
    }
    let now = crate::now_millis();
    let (d1, d7) = (now - DAY_MS, now - 7 * DAY_MS);
    let n = |v: Option<i64>| v.unwrap_or(0);
    let accounts_total = n(scalar(db, "SELECT COUNT(*) AS v FROM accounts", &[]).await?);
    let new_24h = n(scalar(db, "SELECT COUNT(*) AS v FROM accounts WHERE created_at >= ?", &[d1]).await?);
    let new_7d = n(scalar(db, "SELECT COUNT(*) AS v FROM accounts WHERE created_at >= ?", &[d7]).await?);
    let banned = n(scalar(db, "SELECT COUNT(*) AS v FROM accounts WHERE banned_at IS NOT NULL", &[]).await?);
    let devices_total = n(scalar(db, "SELECT COUNT(*) AS v FROM devices", &[]).await?);
    let active_24h = n(scalar(db, "SELECT COUNT(*) AS v FROM devices WHERE last_seen_at >= ?", &[d1]).await?);
    let active_7d = n(scalar(db, "SELECT COUNT(*) AS v FROM devices WHERE last_seen_at >= ?", &[d7]).await?);
    let env = sqlx::query!(
        "SELECT COUNT(*) AS `n?: i64`, CAST(COALESCE(SUM(LENGTH(content)), 0) AS SIGNED) AS `b?: i64`, MIN(server_timestamp) AS `o?: i64` FROM envelopes",
    )
    .fetch_one(db)
    .await?;
    let att = sqlx::query!(
        "SELECT COUNT(*) AS `n?: i64`, CAST(COALESCE(SUM(size), 0) AS SIGNED) AS `b?: i64` FROM attachments WHERE state = ?",
        crate::api::attachments::ATTACHMENT_UPLOADED
    )
    .fetch_one(db)
    .await?;
    let vault = n(scalar(db, "SELECT CAST(COALESCE(SUM(vault_bytes), 0) AS SIGNED) AS v FROM accounts", &[]).await?);
    let db_size = scalar(
        db,
        "SELECT CAST(COALESCE(SUM(data_length + index_length), 0) AS SIGNED) AS v
         FROM information_schema.tables WHERE table_schema = DATABASE()",
        &[],
    )
    .await?;
    let kt_size = n(scalar(db, "SELECT size AS v FROM kt_state WHERE id = 1", &[]).await.unwrap_or(None));
    let kt_last = if kt_size > 0 {
        scalar(db, "SELECT created_at AS v FROM kt_leaves WHERE idx = ?", &[kt_size - 1]).await.ok().flatten()
    } else {
        None
    };
    let open_reports = n(scalar(db, "SELECT COUNT(*) AS v FROM spam_reports WHERE resolved_at IS NULL", &[]).await?);
    let v = json!({
        "accounts": {"total": accounts_total, "new_24h": new_24h, "new_7d": new_7d, "banned": banned},
        "devices": {"total": devices_total, "active_24h": active_24h, "active_7d": active_7d},
        "messages": {
            "queued_envelopes": env.n.unwrap_or(0),
            "queued_bytes": env.b.unwrap_or(0),
            "oldest_queued_at": env.o,
        },
        "storage": {
            "attachments_count": att.n.unwrap_or(0),
            "attachments_bytes": att.b.unwrap_or(0),
            "vault_bytes": vault,
        },
        "database": {"size_bytes": db_size},
        "key_transparency": {"log_size": kt_size, "last_sequenced_at": kt_last},
        "moderation": {"open_reports": open_reports, "banned_accounts": banned},
    });
    *OVERVIEW_CACHE.lock().unwrap() = Some((Instant::now(), v.clone()));
    Ok(v)
}

fn deployed_commit() -> Option<String> {
    let clean = |s: &str| {
        let s = s.trim();
        (!s.is_empty() && s.len() <= 128).then(|| s.to_string())
    };
    if let Some(c) = std::env::var("CHATAPP_COMMIT").ok().as_deref().and_then(clean) {
        return Some(c);
    }
    std::fs::read_to_string("/app/DEPLOYED_COMMIT").ok().as_deref().and_then(clean)
}

/// {"last_at": ms, "size_bytes": n} from CHATAPP_BACKUP_STATUS_FILE, or null.
fn backup_status(path: &str) -> Value {
    if path.is_empty() {
        return Value::Null;
    }
    let Ok(raw) = std::fs::read(path) else {
        return Value::Null;
    };
    if raw.len() > 64 << 10 {
        return Value::Null;
    }
    match serde_json::from_slice::<Value>(&raw) {
        Ok(v) if v.is_object() => json!({
            "last_at": v.get("last_at").and_then(Value::as_i64),
            "size_bytes": v.get("size_bytes").and_then(Value::as_i64),
        }),
        _ => Value::Null,
    }
}

#[cfg(target_os = "linux")]
fn system_info() -> Value {
    let load: Option<Vec<f64>> = std::fs::read_to_string("/proc/loadavg").ok().and_then(|s| {
        let v: Vec<f64> = s.split_whitespace().take(3).filter_map(|x| x.parse().ok()).collect();
        (v.len() == 3).then_some(v)
    });
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mem = |key: &str| -> Option<u64> {
        meminfo
            .lines()
            .find(|l| l.starts_with(key) && l[key.len()..].starts_with(':'))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|kb| kb.parse::<u64>().ok())
            .map(|kb| kb * 1024)
    };
    let (disk_total, disk_avail) = statvfs_root().map_or((None, None), |(t, a)| (Some(t), Some(a)));
    json!({
        "load_avg": load,
        "mem_total_bytes": mem("MemTotal"),
        "mem_available_bytes": mem("MemAvailable"),
        "disk_total_bytes": disk_total,
        "disk_available_bytes": disk_avail,
        "cpus": std::thread::available_parallelism().map(|n| n.get()).ok(),
    })
}

#[cfg(target_os = "linux")]
fn statvfs_root() -> Option<(u64, u64)> {
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: a valid NUL-terminated path and a properly sized out-parameter.
    let rc = unsafe { libc::statvfs(c"/".as_ptr(), &mut s) };
    if rc != 0 {
        return None;
    }
    let frsize = s.f_frsize as u64;
    Some((s.f_blocks as u64 * frsize, s.f_bavail as u64 * frsize))
}

#[cfg(not(target_os = "linux"))]
fn system_info() -> Value {
    json!({
        "load_avg": null,
        "mem_total_bytes": null,
        "mem_available_bytes": null,
        "disk_total_bytes": null,
        "disk_available_bytes": null,
        "cpus": std::thread::available_parallelism().map(|n| n.get()).ok(),
    })
}

async fn overview(State(st): State<AppState>) -> ApiResult {
    let mut v = db_overview(&st.db).await?;
    let s = st.settings.get();
    let now = crate::now_millis();
    let started = metrics::started_at();
    let o = v.as_object_mut().expect("object");
    o.insert(
        "server".into(),
        json!({
            "version": crate::api::VERSION,
            "commit": deployed_commit(),
            "started_at": started,
            "uptime_s": (now - started).max(0) / 1000,
            "name": st.cfg.server_name,
        }),
    );
    if let Some(d) = o.get_mut("devices").and_then(Value::as_object_mut) {
        d.insert("online_now".into(), st.hub.online_count().into());
    }
    o.insert("system".into(), system_info());
    o.insert(
        "features".into(),
        json!({
            "registration_enabled": s.registration_enabled,
            "pow_bits": crate::adaptive_pow::effective_bits(&st),
            "pow_adaptive": crate::adaptive_pow::status(&st),
            "push_enabled": st.push.enabled(),
            "voip_push_enabled": st.push.voip_enabled(),
            "turn_enabled": !st.cfg.turn_urls.is_empty(),
            "groups_v2": crate::api::groups_v2::default_on(),
            "max_devices": s.max_devices,
        }),
    );
    o.insert("backup".into(), backup_status(&st.cfg.backup_status_file));
    Ok(reply(StatusCode::OK, v))
}

// --- GET /countries ------------------------------------------------------------------------

/// Accounts active and registered per country over the last `days` days: daily totals only
/// (metrics.rs), from the country of the address at connection time (geoip.rs).
async fn countries(State(st): State<AppState>, RawQuery(q): RawQuery) -> ApiResult {
    let p = params(&q);
    let days = int_param(&p, "days", 30, 1, 365)?;
    metrics::flush(&st.db).await;
    let today = metrics::day_of(crate::now_millis());
    let first = today - days + 1;
    let rows = sqlx::query(
        "SELECT day, metric, value FROM daily_stats WHERE day >= ? AND day <= ? AND (metric LIKE 'active:%' OR metric LIKE 'reg:%')",
    )
    .bind(first)
    .bind(today)
    .fetch_all(&st.db)
    .await?;
    #[derive(Default)]
    struct Totals {
        active_today: i64,
        active_days: i64,
        registrations: i64,
    }
    let mut by_country: std::collections::BTreeMap<String, Totals> = Default::default();
    for r in &rows {
        let (metric, day, value) = (r.string("metric"), r.i64("day"), r.i64("value"));
        let Some((kind, country)) = metric.split_once(':') else { continue };
        let t = by_country.entry(country.to_string()).or_default();
        match kind {
            "active" => {
                t.active_days += value;
                if day == today {
                    t.active_today += value;
                }
            }
            "reg" => t.registrations += value,
            _ => {}
        }
    }
    let mut items: Vec<(String, Totals)> = by_country.into_iter().collect();
    items.sort_by(|a, b| b.1.active_days.cmp(&a.1.active_days).then(b.1.registrations.cmp(&a.1.registrations)).then(a.0.cmp(&b.0)));
    let items: Vec<Value> = items
        .into_iter()
        .map(|(country, t)| json!({"country": country, "active_today": t.active_today, "active_days": t.active_days, "registrations": t.registrations}))
        .collect();
    Ok(reply(
        StatusCode::OK,
        json!({"enabled": st.geoip.enabled(), "days": days, "items": items, "attribution": "IP Geolocation by DB-IP (https://db-ip.com)"}),
    ))
}

// --- GET /platforms ------------------------------------------------------------------------

/// The groups of `GET /platforms`, in the order they are returned. `desktop`: a desktop app
/// that has not said its system yet (older than the `os` parameter); `other`: web and cli.
const PLATFORM_GROUPS: [&str; 7] = ["android", "ios", "windows", "macos", "linux", "desktop", "other"];

#[derive(Default, Clone, Copy, PartialEq, Debug)]
struct PlatformTotals {
    devices: i64,
    new_devices: i64,
    active_devices: i64,
    active_accounts: i64,
}

/// One entry per group, zeros for those without devices; rows of an unknown group are dropped.
fn platform_items(rows: &[(String, PlatformTotals)]) -> Vec<Value> {
    PLATFORM_GROUPS
        .iter()
        .map(|group| {
            let t = rows.iter().find(|(g, _)| g == group).map(|(_, t)| *t).unwrap_or_default();
            json!({
                "platform": group,
                "devices": t.devices,
                "new_devices": t.new_devices,
                "active_devices": t.active_devices,
                "active_accounts": t.active_accounts,
            })
        })
        .collect()
}

/// Devices and accounts per platform: the linked devices as they are now, those linked in the
/// last `days` days and the accounts seen in that time, from `devices` (platform, os,
/// created_at, last_seen_at). An account active on two platforms counts for both.
async fn platforms(State(st): State<AppState>, RawQuery(q): RawQuery) -> ApiResult {
    let p = params(&q);
    let days = int_param(&p, "days", 30, 1, 365)?;
    // The same days as /stats: from the start of the UTC day `days - 1` days ago.
    let since = (metrics::day_of(crate::now_millis()) - days + 1) * 86_400_000;
    let rows = sqlx::query(
        "SELECT g, COUNT(*) AS devices, CAST(COALESCE(SUM(is_new), 0) AS SIGNED) AS new_devices,
                CAST(COALESCE(SUM(is_active), 0) AS SIGNED) AS active_devices,
                COUNT(DISTINCT CASE WHEN is_active = 1 THEN account_id END) AS active_accounts
         FROM (SELECT account_id,
                      CASE WHEN platform = 'android' THEN 'android'
                           WHEN platform = 'ios' THEN 'ios'
                           WHEN platform = 'desktop' AND os IN ('windows', 'macos', 'linux') THEN os
                           WHEN platform = 'desktop' THEN 'desktop'
                           ELSE 'other' END AS g,
                      created_at >= ? AS is_new, last_seen_at >= ? AS is_active
               FROM devices) d
         GROUP BY g",
    )
    .bind(since)
    .bind(since)
    .fetch_all(&st.db)
    .await?;
    let rows: Vec<(String, PlatformTotals)> = rows
        .iter()
        .map(|r| {
            (
                r.string("g"),
                PlatformTotals {
                    devices: r.i64("devices"),
                    new_devices: r.i64("new_devices"),
                    active_devices: r.i64("active_devices"),
                    active_accounts: r.i64("active_accounts"),
                },
            )
        })
        .collect();
    let total = sqlx::query("SELECT COUNT(DISTINCT account_id) AS n FROM devices WHERE last_seen_at >= ?")
        .bind(since)
        .fetch_one(&st.db)
        .await?
        .i64("n");
    Ok(reply(StatusCode::OK, json!({"days": days, "active_accounts": total, "items": platform_items(&rows)})))
}

// --- GET /stats ----------------------------------------------------------------------------

async fn stats(State(st): State<AppState>, RawQuery(q): RawQuery) -> ApiResult {
    let p = params(&q);
    let days = int_param(&p, "days", 30, 1, 365)?;
    metrics::flush(&st.db).await;
    let today = metrics::day_of(crate::now_millis());
    let first = today - days + 1;
    let rows = sqlx::query!(
        "SELECT day AS `day: i64`, metric AS `metric: String`, value FROM daily_stats WHERE day >= ? AND day <= ?",
        first,
        today
    )
    .fetch_all(&st.db)
    .await?;
    let mut by_day: HashMap<(i64, String), i64> = HashMap::new();
    for r in rows {
        by_day.insert((r.day, r.metric), r.value);
    }
    let out: Vec<Value> = (first..=today)
        .map(|d| {
            let mut m = serde_json::Map::new();
            m.insert("date".into(), metrics::date_string(d).into());
            for metric in metrics::DAILY_METRICS {
                m.insert(metric.into(), by_day.get(&(d, metric.to_string())).copied().unwrap_or(0).into());
            }
            Value::Object(m)
        })
        .collect();
    Ok(reply(StatusCode::OK, json!({"days": out})))
}

// --- reports ----------------------------------------------------------------------------------

async fn list_reports(State(st): State<AppState>, RawQuery(q): RawQuery) -> ApiResult {
    let p = params(&q);
    let filter = match p.get("status").map(String::as_str).unwrap_or("open") {
        "open" | "" => "WHERE r.resolved_at IS NULL",
        "resolved" => "WHERE r.resolved_at IS NOT NULL",
        "all" => "",
        _ => return Err(bad_request("status must be open, resolved or all")),
    };
    let limit = int_param(&p, "limit", 50, 1, 500)?;
    let offset = int_param(&p, "offset", 0, 0, 1_000_000)?;
    let total = scalar(&st.db, &format!("SELECT COUNT(*) AS v FROM spam_reports r {filter}"), &[]).await?.unwrap_or(0);
    let rows = sqlx::query(&format!(
        "SELECT r.id, r.created_at, r.updated_at, r.reporter_id, r.reported_id, a.number, r.reason,
                r.envelope_ids, r.report_count, r.resolved_at, r.resolution, r.resolution_note
         FROM spam_reports r LEFT JOIN accounts a ON a.id = r.reported_id
         {filter} ORDER BY r.updated_at DESC, r.id DESC LIMIT ? OFFSET ?"
    ))
    .bind(limit)
    .bind(offset)
    .fetch_all(&st.db)
    .await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|r| {
            let resolved_at = r.opt_i64("resolved_at");
            json!({
                "id": r.i64("id"),
                "created_at": r.i64("created_at"),
                "updated_at": r.i64("updated_at"),
                "reporter_account_id": r.string("reporter_id"),
                "reported_account_id": r.string("reported_id"),
                "reported_number": r.opt_string("number"),
                "reason": r.opt_string("reason"),
                "envelope_count": r
                    .opt_string("envelope_ids")
                    .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
                    .map_or(0, |v| v.len()),
                "report_count": r.i64("report_count"),
                "status": if resolved_at.is_some() { "resolved" } else { "open" },
                "resolved_at": resolved_at,
                "resolution": r.opt_string("resolution"),
                "note": r.opt_string("resolution_note"),
            })
        })
        .collect();
    Ok(reply(StatusCode::OK, json!({"total": total, "items": items})))
}

#[derive(Deserialize)]
struct ResolveRequest {
    #[serde(default)]
    action: String,
    #[serde(default)]
    note: Option<String>,
}

async fn resolve_report(State(st): State<AppState>, Path(id): Path<String>, body: Body) -> ApiResult {
    let id: u64 = id.parse().map_err(|_| bad_request("report id must be a number"))?;
    let req: ResolveRequest = json_body(body).await?;
    let note = note(req.note, "note")?;
    let row = sqlx::query!("SELECT reported_id AS `reported_id: String` FROM spam_reports WHERE id = ?", id)
        .fetch_optional(&st.db)
        .await?
        .ok_or_else(|| not_found("unknown report"))?;
    let reported = row.reported_id;
    match req.action.as_str() {
        "dismiss" => {
            let now = crate::now_millis();
            sqlx::query!(
                "UPDATE spam_reports SET resolved_at = COALESCE(resolved_at, ?), resolution = 'dismissed',
                     resolution_note = ? WHERE id = ?",
                now,
                note,
                id
            )
            .execute(&st.db)
            .await?;
        }
        "ban" => {
            let reason = note.clone().unwrap_or_else(|| format!("report {id}"));
            if do_ban(&st, &reported, Some(&reason)).await?.is_none() {
                // The reported account was deleted meanwhile: just close the report.
                let now = crate::now_millis();
                sqlx::query!("UPDATE spam_reports SET resolved_at = COALESCE(resolved_at, ?) WHERE id = ?", now, id)
                    .execute(&st.db)
                    .await?;
            }
            sqlx::query!("UPDATE spam_reports SET resolution = 'banned', resolution_note = ? WHERE id = ?", note, id)
                .execute(&st.db)
                .await?;
        }
        _ => return Err(bad_request("action must be dismiss or ban")),
    }
    *OVERVIEW_CACHE.lock().unwrap() = None;
    info!(report = id, action = %req.action, "admin resolved report");
    Ok(no_content())
}

// --- accounts ---------------------------------------------------------------------------------

async fn search_accounts(State(st): State<AppState>, RawQuery(q): RawQuery) -> ApiResult {
    let p = params(&q);
    let query = p.get("query").map(|s| s.trim().to_string()).unwrap_or_default();
    let limit = int_param(&p, "limit", 20, 1, 100)?;
    if query.len() > 64 {
        return Err(bad_request("query too long"));
    }
    if query.is_empty() {
        // Without a query: every account, newest first, one page at a time.
        let offset = int_param(&p, "offset", 0, 0, i64::MAX)?;
        let total: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM accounts").fetch_one(&st.db).await?;
        let rows = sqlx::query(&format!("{ACCOUNT_ROW_SQL} ORDER BY a.created_at DESC LIMIT ? OFFSET ?"))
            .bind(limit)
            .bind(offset)
            .fetch_all(&st.db)
            .await?;
        let items: Vec<Value> = rows.iter().map(account_row_json).collect();
        return Ok(reply(StatusCode::OK, json!({"total": total, "items": items})));
    }
    let mut conds: Vec<&str> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    if crate::ids::valid_number(&query) {
        conds.push("a.number = ?");
        binds.push(query.clone());
    }
    let (username, username_ok) = crate::api::username::normalize_username(&query);
    if username_ok {
        conds.push("a.username = ?");
        binds.push(username);
    }
    let prefix = query.to_ascii_lowercase();
    if (4..=36).contains(&prefix.len()) && prefix.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        conds.push("a.id LIKE ?");
        binds.push(format!("{prefix}%"));
    }
    if conds.is_empty() {
        return Err(bad_request("query must be an account number, a username or an account id prefix of at least 4 characters"));
    }
    let sql = format!("{ACCOUNT_ROW_SQL} WHERE {} ORDER BY a.created_at DESC LIMIT ?", conds.join(" OR "));
    let mut q = sqlx::query(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    let rows = q.bind(limit).fetch_all(&st.db).await?;
    let items: Vec<Value> = rows.iter().map(account_row_json).collect();
    Ok(reply(StatusCode::OK, json!({"total": items.len(), "items": items})))
}

/// One row of the account list / search results.
const ACCOUNT_ROW_SQL: &str = "SELECT a.id, a.number, a.username, a.created_at, a.banned_at,
        a.inactive_delete_days, a.last_active_at,
        (SELECT COUNT(*) FROM devices d WHERE d.account_id = a.id) AS devices,
        (SELECT MAX(d.last_seen_at) FROM devices d WHERE d.account_id = a.id) AS last_seen_at
     FROM accounts a";

fn account_row_json(r: &sqlx::mysql::MySqlRow) -> Value {
    json!({
        "id": r.string("id"),
        "number": r.string("number"),
        "username": r.opt_string("username"),
        "created_at": r.i64("created_at"),
        "banned_at": r.opt_i64("banned_at"),
        "devices": r.i64("devices"),
        "last_seen_at": r.opt_i64("last_seen_at"),
        "last_active_at": r.i64("last_active_at").max(r.i64("created_at")),
        "inactive_delete_days": r.i64("inactive_delete_days"),
        "inactive_delete_at": inactive_delete_at(r),
    })
}

/// When the account is deleted for inactivity if it stays away (null: never, also for banned
/// accounts, which the job keeps).
fn inactive_delete_at(r: &sqlx::mysql::MySqlRow) -> Option<i64> {
    if r.opt_i64("banned_at").is_some() {
        return None;
    }
    crate::api::accounts::inactive_delete_at(r.i64("inactive_delete_days"), r.i64("last_active_at"), r.i64("created_at"))
}

async fn get_account(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult {
    let id = account_id(&id)?;
    let r = sqlx::query!(
        "SELECT id AS `id: String`, number AS `number: String`, username AS `username: String`, created_at, banned_at,
                ban_reason AS `ban_reason: String`, login_approval AS `login_approval: bool`,
                (totp_secret IS NOT NULL) AS `totp_enabled!: i64`, discoverable_by_phone AS `discoverable_by_phone: bool`
         FROM accounts WHERE id = ?",
        id
    )
    .fetch_optional(&st.db)
    .await?
    .ok_or_else(|| not_found("unknown account"))?;
    // Device names are encrypted for the account's own devices: never returned.
    let devices: Vec<Value> = sqlx::query!(
        "SELECT device_id AS `device_id: i64`, platform AS `platform: String`, created_at, last_seen_at FROM devices WHERE account_id = ? ORDER BY device_id",
        id
    )
    .fetch_all(&st.db)
    .await?
    .iter()
    .map(|d| {
        json!({
            "device_id": d.device_id,
            "platform": d.platform,
            "created_at": d.created_at,
            "last_seen_at": d.last_seen_at,
        })
    })
    .collect();
    let against = sqlx::query!("SELECT COUNT(*) AS `v!: i64` FROM spam_reports WHERE reported_id = ?", id)
        .fetch_one(&st.db)
        .await?
        .v;
    let by = sqlx::query!("SELECT COUNT(*) AS `v!: i64` FROM spam_reports WHERE reporter_id = ?", id)
        .fetch_one(&st.db)
        .await?
        .v;
    let extras = operator::account_extras(&st, &id).await?;
    let inactivity = sqlx::query("SELECT inactive_delete_days, last_active_at, created_at, banned_at FROM accounts WHERE id = ?")
        .bind(&id)
        .fetch_optional(&st.db)
        .await?
        .ok_or_else(|| not_found("unknown account"))?;
    Ok(reply(
        StatusCode::OK,
        json!({
            "id": r.id,
            "number": r.number,
            "username": r.username,
            "created_at": r.created_at,
            "banned_at": r.banned_at,
            "ban_reason": r.ban_reason,
            "login_approval": r.login_approval,
            "totp_enabled": r.totp_enabled != 0,
            "discoverable": r.discoverable_by_phone,
            "last_active_at": inactivity.i64("last_active_at").max(inactivity.i64("created_at")),
            "inactive_delete_days": inactivity.i64("inactive_delete_days"),
            "inactive_delete_at": inactive_delete_at(&inactivity),
            "devices": devices,
            "reports_against": against,
            "reports_by": by,
            // The key a badge is signed over, and the badge the account has (null: none).
            "identity_key": extras["identity_key"],
            "badge": extras["badge"],
        }),
    ))
}

/// Bans and closes the account's WebSockets now.
async fn do_ban(st: &AppState, account: &str, reason: Option<&str>) -> Result<Option<moderation::BanOutcome>, ApiError> {
    let out = moderation::ban_account(&st.db, account, reason).await?;
    if out.is_some() {
        st.hub.close_account(account, &json!({"kind": "account_banned"}), "account banned");
        *OVERVIEW_CACHE.lock().unwrap() = None;
        info!(account, "admin banned account");
    }
    Ok(out)
}

#[derive(Deserialize)]
struct BanRequest {
    #[serde(default)]
    reason: Option<String>,
}

async fn ban(State(st): State<AppState>, Path(id): Path<String>, body: Body) -> ApiResult {
    let id = account_id(&id)?;
    let req: BanRequest = json_body(body).await?;
    let reason = note(req.reason, "reason")?;
    do_ban(&st, &id, reason.as_deref()).await?.ok_or_else(|| not_found("unknown account"))?;
    Ok(no_content())
}

async fn unban(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult {
    let id = account_id(&id)?;
    if !moderation::unban_account(&st.db, &id).await? {
        return Err(not_found("unknown account"));
    }
    *OVERVIEW_CACHE.lock().unwrap() = None;
    info!(account = %id, "admin unbanned account");
    Ok(no_content())
}

async fn logout(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult {
    let id = account_id(&id)?;
    let devices = moderation::logout_account(&st.db, &id).await?.ok_or_else(|| not_found("unknown account"))?;
    for d in &devices {
        st.hub.close_device(&id, *d, "device unlinked");
    }
    info!(account = %id, devices = devices.len(), "admin logged out all devices");
    Ok(no_content())
}

// --- settings ---------------------------------------------------------------------------------

async fn get_settings(State(st): State<AppState>) -> ApiResult {
    Ok(reply(StatusCode::OK, st.settings.describe()))
}

async fn put_settings(State(st): State<AppState>, body: Body) -> ApiResult {
    let v: Value = json_body(body).await?;
    let changes = crate::settings::validate_changes(&v).map_err(bad_request)?;
    st.settings.save(&st.db, &changes).await?;
    let names: Vec<&str> = changes.iter().map(|(n, _)| *n).collect();
    info!(settings = ?names, "admin changed settings");
    Ok(reply(StatusCode::OK, st.settings.describe()))
}

/// Deletes undelivered messages (queued envelopes): all of them, or only those waiting for
/// devices not seen for `inactive_days` days (devices that may never come back). Messages are
/// end-to-end encrypted, so the server can only drop them; recipients never receive them.
async fn purge_queue(State(st): State<AppState>, body: Body) -> ApiResult {
    #[derive(serde::Deserialize)]
    struct Req {
        /// "all" or "inactive".
        scope: String,
        #[serde(default)]
        inactive_days: Option<i64>,
    }
    let req: Req = json_body(body).await?;
    let deleted = match req.scope.as_str() {
        // Runtime queries (not sqlx::query!): admin-only, no offline query data needed.
        "all" => sqlx::query("DELETE FROM envelopes").execute(&st.db).await?.rows_affected(),
        "inactive" => {
            let days = req.inactive_days.unwrap_or(7);
            if !(1..=365).contains(&days) {
                return Err(bad_request("inactive_days must be in 1..365"));
            }
            let cutoff = crate::now_millis() - days * 86_400_000;
            sqlx::query(
                "DELETE e FROM envelopes e JOIN devices d ON d.account_id = e.account_id AND d.device_id = e.device_id
                 WHERE d.last_seen_at < ?",
            )
            .bind(cutoff)
            .execute(&st.db)
            .await?
            .rows_affected()
        }
        _ => return Err(bad_request("scope must be \"all\" or \"inactive\"")),
    };
    info!(scope = %req.scope, deleted, "admin purged queued messages");
    Ok(reply(StatusCode::OK, json!({ "deleted": deleted })))
}

// --- security, logs, calls ----------------------------------------------------------------------

async fn security() -> ApiResult {
    Ok(reply(
        StatusCode::OK,
        json!({
            "since": metrics::started_at(),
            "failed_auth_logins": metrics::get(&metrics::FAILED_AUTH_LOGINS),
            "failed_totp": metrics::get(&metrics::FAILED_TOTP),
            "rate_limited": metrics::rate_limited_snapshot(),
            "failed_admin_auth": metrics::get(&metrics::FAILED_ADMIN_AUTH),
            "pow_rejected": metrics::get(&metrics::POW_REJECTED),
        }),
    ))
}

async fn logs(RawQuery(q): RawQuery) -> ApiResult {
    let p = params(&q);
    let level = match p.get("level").map(String::as_str).unwrap_or("warn") {
        "warn" | "" => "warn",
        "error" => "error",
        _ => return Err(bad_request("level must be warn or error")),
    };
    let limit = int_param(&p, "limit", 200, 1, logbuf::CAPACITY as i64)?;
    Ok(reply(StatusCode::OK, json!({"items": logbuf::recent(level, limit as usize)})))
}

async fn calls(State(st): State<AppState>) -> ApiResult {
    Ok(reply(
        StatusCode::OK,
        json!({
            "turn_enabled": !st.cfg.turn_urls.is_empty(),
            "turn_urls_count": st.cfg.turn_urls.len(),
            "turn_credentials_issued_24h": metrics::TURN_CREDENTIALS_ISSUED.sum(),
            "voip_push_enabled": st.push.voip_enabled(),
            "push_enabled": st.push.enabled(),
            "pushes_sent_24h": metrics::PUSHES_SENT.sum(),
            "push_failures_24h": metrics::PUSH_FAILURES.sum(),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platforms_always_list_every_group() {
        let t = |devices, new_devices, active_devices, active_accounts| PlatformTotals { devices, new_devices, active_devices, active_accounts };
        let items = platform_items(&[("linux".into(), t(4, 1, 3, 2)), ("android".into(), t(10, 5, 8, 7)), ("bogus".into(), t(9, 9, 9, 9))]);
        let names: Vec<&str> = items.iter().map(|i| i["platform"].as_str().unwrap()).collect();
        assert_eq!(names, PLATFORM_GROUPS, "fixed order, unknown groups dropped");
        assert_eq!(items[0], json!({"platform": "android", "devices": 10, "new_devices": 5, "active_devices": 8, "active_accounts": 7}));
        assert_eq!(items[4], json!({"platform": "linux", "devices": 4, "new_devices": 1, "active_devices": 3, "active_accounts": 2}));
        // A group without devices is there with zeros, the desktops of unknown system included.
        assert_eq!(items[5], json!({"platform": "desktop", "devices": 0, "new_devices": 0, "active_devices": 0, "active_accounts": 0}));
    }

    #[test]
    fn backup_status_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("status.json");
        assert_eq!(backup_status(""), Value::Null);
        assert_eq!(backup_status(p.to_str().unwrap()), Value::Null);
        std::fs::write(&p, r#"{"last_at": 1790000000000, "size_bytes": 12345}"#).unwrap();
        assert_eq!(backup_status(p.to_str().unwrap()), json!({"last_at": 1790000000000i64, "size_bytes": 12345}));
        std::fs::write(&p, "garbage").unwrap();
        assert_eq!(backup_status(p.to_str().unwrap()), Value::Null);
    }

    #[test]
    fn admin_paths() {
        assert!(is_admin_path("/v1/admin/overview"));
        assert!(is_admin_path("/v1/admin"));
        assert!(!is_admin_path("/v1/administrator"));
    }
}
