//! HTTP API (docs/API.md). Same routes, bodies and error format as the Go server.
//!
//! Handler conventions:
//! * `async fn h(State(st): State<AppState>, p: Principal, Path(..), ..., body: Body) -> ApiResult`
//!   (`Principal` authenticates; `Body` must come last and is parsed with
//!   `validate::parse_json(body, limit)`).
//! * Peer address: `ConnectInfo(peer): ConnectInfo<SocketAddr>` + `st.client_ip(&headers, peer)`.
//! * Replies: `reply(StatusCode::OK, value)` or `no_content()`.

pub mod accounts;
pub mod attachments;
pub mod bots;
pub mod calls;
pub mod devices;
pub mod directory;
pub mod group_bans;
pub mod groups;
pub mod groups_v2;
pub mod invites;
pub mod keytrans;
pub mod keys;
pub mod messages;
pub mod operator;
pub mod provisioning;
pub mod push;
pub mod sealed;
pub mod security;
pub mod totp;
pub mod username;
pub mod vault;
pub mod zk;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::Router;
use serde::Serialize;
use serde_json::json;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::error::{not_found, ApiError, ApiResult};
use crate::state::AppState;

/// Reported by GET /v1/info.
pub const VERSION: &str = "1.0.0";

pub fn reply<T: Serialize>(status: StatusCode, v: T) -> Response {
    (status, axum::Json(v)).into_response()
}

pub fn no_content() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

pub fn router(st: AppState) -> Router {
    Router::new()
        .route("/v1/info", get(info))
        // Sealed sender: certificates (authenticated) and anonymous delivery (access key).
        .route("/v1/certificate/delivery", get(sealed::sender_certificate))
        .route(
            "/v1/account/unidentified-access",
            put(sealed::set_unidentified_access),
        )
        .route("/v1/sealed/messages/{account_id}", put(sealed::sealed_send))
        .route(
            "/v1/sealed/keys/{account_id}/{device}",
            get(sealed::sealed_keys),
        )
        // zkgroup auth credentials (private groups, docs/ZKGROUP-DESIGN.md).
        .route("/v1/certificate/auth/group", get(zk::group_auth_credentials))
        // Private groups v2 (anonymous, Group-Auth header; sends authenticated).
        .route(
            "/v2/groups",
            post(groups_v2::create).get(groups_v2::get_state).patch(groups_v2::modify),
        )
        .route("/v2/groups/changes", get(groups_v2::changes))
        .route("/v2/groups/devices", post(groups_v2::devices))
        .route("/v2/groups/messages", put(groups_v2::send))
        // Accounts & authentication.
        .route("/v1/accounts", post(accounts::register))
        .route("/v1/auth/prelogin", post(accounts::prelogin))
        .route("/v1/auth/login", post(accounts::login))
        .route("/v1/auth/login/poll", post(security::login_poll))
        .route(
            "/v1/accounts/challenge",
            post(security::registration_challenge),
        )
        .route(
            "/v1/auth/recover/challenge",
            post(accounts::recover_challenge),
        )
        .route("/v1/auth/recover", post(accounts::recover))
        .route("/v1/auth/link", post(provisioning::link_device))
        .route(
            "/v1/account",
            get(accounts::get_account).delete(accounts::delete_account),
        )
        .route("/v1/account/password", put(accounts::change_password))
        .route("/v1/account/privacy", put(accounts::set_privacy))
        .route(
            "/v1/account/phone",
            post(accounts::set_phone).delete(accounts::delete_phone),
        )
        .route("/v1/account/phone/verify", post(accounts::verify_phone))
        .route("/v1/account/discoverable", put(accounts::set_discoverable))
        .route(
            "/v1/account/inactive-deletion",
            put(accounts::set_inactive_deletion),
        )
        .route("/v1/account/username", put(username::set_username))
        .route(
            "/v1/account/username/link",
            get(username::get_own_username_link)
                .put(username::put_username_link)
                .delete(username::delete_username_link),
        )
        .route("/v1/username/link/{handle}", get(username::resolve_username_link))
        .route(
            "/v1/account/login-approval",
            put(security::set_login_approval),
        )
        .route(
            "/v1/account/login-requests",
            get(security::list_login_requests),
        )
        .route(
            "/v1/account/login-requests/{id}",
            post(security::answer_login_request),
        )
        // Abuse reports.
        .route("/v1/report", post(security::report_spam))
        .route("/v1/account/totp/setup", post(totp::setup))
        .route("/v1/account/totp/enable", post(totp::enable))
        .route("/v1/account/totp", delete(totp::disable))
        // Devices.
        .route("/v1/devices", get(devices::list_devices))
        .route("/v1/devices/{device_id}", delete(devices::delete_device))
        .route("/v1/devices/current/revocation", put(devices::set_revocation))
        .route("/v1/devices/revocation-status", post(devices::revocation_status))
        // Go routes DELETE /v1/devices/current to the {device_id} handler ("current" is then
        // rejected as an invalid id).
        .route(
            "/v1/devices/current",
            put(devices::rename_device).delete(|st, p| devices::delete_device(st, p, axum::extract::Path("current".to_string()))),
        )
        .route(
            "/v1/devices/current/push",
            put(push::set_push).delete(push::delete_push),
        )
        // Device linking by QR code.
        .route("/v1/provisioning", post(provisioning::create))
        .route("/v1/provisioning/{id}/claim", post(provisioning::claim))
        .route("/v1/provisioning/{id}", get(provisioning::get_session))
        .route("/v1/provisioning/{id}/poll", get(provisioning::poll))
        .route("/v1/provisioning/{id}/payload", post(provisioning::approve))
        // Pre-keys.
        .route("/v1/keys", put(keys::put_keys))
        .route("/v1/keys/count", get(keys::key_count))
        .route("/v1/keys/{account_id}/{device}", get(keys::get_keys))
        // Directory.
        .route("/v1/directory/number/{number}", get(directory::by_number))
        .route(
            "/v1/directory/account/{account_id}",
            get(directory::by_account),
        )
        .route(
            "/v1/directory/username/{username}",
            get(username::directory_username),
        )
        .route("/v1/directory/phones", post(directory::phones))
        .route("/v1/directory/phone/{hash}", get(directory::phone))
        // Profiles.
        .route("/v1/profile", put(directory::put_profile))
        .route("/v1/profile/{account_id}", get(directory::get_profile))
        // Messages.
        // PUT sends to {account_id}, DELETE acknowledges envelope {id} (one path pattern).
        .route(
            "/v1/messages/{id}",
            put(messages::send_message).delete(messages::ack_message),
        )
        .route("/v1/messages", get(messages::fetch_messages))
        // WebSocket.
        .route("/v1/ws", get(messages::websocket))
        .route("/v1/notices", get(operator::notices))
        // Bots (section 22): the owner's bots, talking to a bot, and the Bot API.
        .route("/v1/bots", post(bots::create).get(bots::list))
        .route("/v1/bots/username/{username}", get(bots::by_username))
        .route("/v1/bots/{id}", get(bots::get).patch(bots::update).delete(bots::delete))
        .route("/v1/bots/{id}/token", post(bots::reset_token))
        .route("/v1/bots/{id}/subscribers", get(bots::subscribers))
        .route("/v1/bots/{id}/send", post(bots::owner_send))
        .route("/v1/bots/{id}/start", post(bots::start))
        .route("/v1/bots/{id}/stop", post(bots::stop))
        .route("/v1/bots/{id}/messages", post(bots::send_to_bot))
        .route("/v1/bots/{id}/callback", post(bots::callback))
        .route("/v1/bot-chats", get(bots::chats))
        .route("/bot/{token}/{method}", get(bots::bot_api).post(bots::bot_api))
        // Groups.
        .route(
            "/v1/groups",
            post(groups::create_group).get(groups::list_groups),
        )
        .route("/v1/groups/{group_id}", get(groups::get_group))
        .route("/v1/groups/{group_id}/metadata", put(groups::put_metadata))
        .route("/v1/groups/{group_id}/settings", put(groups::put_settings))
        .route("/v1/groups/{group_id}/members", post(groups::add_members))
        .route(
            "/v1/groups/{group_id}/members/{account_id}",
            delete(groups::remove_member),
        )
        .route(
            "/v1/groups/{group_id}/members/{account_id}/role",
            put(groups::set_role),
        )
        .route("/v1/groups/{group_id}/devices", get(groups::group_devices))
        .route("/v1/groups/{group_id}/messages", put(groups::group_send))
        .route(
            "/v1/groups/{group_id}/invite",
            put(invites::put_invite).delete(invites::delete_invite),
        )
        .route(
            "/v1/groups/{group_id}/requests",
            get(invites::list_join_requests),
        )
        .route(
            "/v1/groups/{group_id}/requests/{account_id}/approve",
            post(invites::approve_join_request),
        )
        .route(
            "/v1/groups/{group_id}/requests/{account_id}",
            delete(invites::delete_join_request),
        )
        .route("/v1/groups/{group_id}/bans", get(group_bans::list_bans))
        .route(
            "/v1/groups/{group_id}/bans/{account_id}",
            delete(group_bans::delete_ban),
        )
        .route("/v1/invites/lookup", post(invites::lookup))
        .route("/v1/invites/join", post(invites::join))
        // Voice calls.
        .route("/v1/calls/ice", get(calls::ice_servers))
        // Attachments.
        .route("/v1/attachments", post(attachments::create))
        .route(
            "/v1/attachments/{id}",
            put(attachments::upload).get(attachments::download),
        )
        // Vault.
        .route(
            "/v1/vault/records",
            put(vault::put_records).get(vault::get_records),
        )
        // Key transparency (public, unauthenticated; docs/KEY-TRANSPARENCY.md).
        .route("/v1/kt/head", get(keytrans::head))
        .route("/v1/kt/proof/{account_id}", get(keytrans::proof))
        .route("/v1/kt/consistency", get(keytrans::consistency))
        .route("/v1/kt/entries", get(keytrans::entries))
        // Health check (not part of the client API).
        .route("/healthz", get(health))
        // Admin API (docs/ADMIN-API.md; empty unless CHATAPP_ADMIN_PUBLIC_KEYS is set).
        .merge(crate::admin::routes(&st))
        .fallback(fallback)
        // Go's mux answers an unknown method with the catch-all 404, not 405.
        .method_not_allowed_fallback(fallback)
        .layer(axum::middleware::from_fn(retry_deadlocks))
        // Inside the header layers, so panic responses get the security headers too.
        .layer(tower_http::catch_panic::CatchPanicLayer::custom(
            |err: Box<dyn std::any::Any + Send>| {
                let msg = err
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                tracing::error!(panic = %msg, "panic in handler");
                crate::error::internal().into_response()
            },
        ))
        .layer(axum::middleware::from_fn(log_request))
        .layer(axum::middleware::from_fn_with_state(st.clone(), crate::admin::cors))
        // Bodies are limited per endpoint by the handlers themselves.
        .layer(DefaultBodyLimit::disable())
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .with_state(st)
}

/// Largest request body buffered for a possible retry. Bodies are buffered before the
/// handler authenticates, so this stays small; larger or chunked bodies are passed through
/// unbuffered (no retry) and the handler applies its own limit, like the Go server.
const MAX_RETRY_BODY: u64 = 4 << 20;

/// Re-runs a request whose transaction hit a MySQL deadlock (like the Go server's InTx),
/// up to 3 attempts. Streaming uploads and the WebSocket are passed through unchanged.
async fn retry_deadlocks(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let path = req.uri().path();
    let streaming = path == "/v1/ws"
        || (req.method() == axum::http::Method::PUT && path.starts_with("/v1/attachments/"));
    // These consume a single-use secret before their transaction and retry it themselves.
    // Registration consumes its proof-of-work challenge; login polls are long and idempotent.
    let single_use = path == "/v1/auth/recover"
        || path == "/v1/auth/link"
        || path == "/v1/accounts"
        || path == "/v1/auth/login/poll";
    // Admin requests carry a single-use nonce: a re-run would be rejected as a replay.
    if streaming || single_use || crate::admin::is_admin_path(path) {
        return next.run(req).await;
    }
    let declared = req
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if !matches!(declared, Some(n) if n <= MAX_RETRY_BODY) && req.method() != axum::http::Method::GET && req.method() != axum::http::Method::DELETE {
        return next.run(req).await;
    }
    let (parts, body) = req.into_parts();
    // Read before the handler authenticates: the deadline (for the declared length) keeps a
    // slow sender from holding the buffer.
    let deadline = crate::validate::body_read_timeout(declared.unwrap_or(0));
    let bytes = match tokio::time::timeout(deadline, axum::body::to_bytes(body, MAX_RETRY_BODY as usize)).await {
        Ok(Ok(b)) => b,
        Ok(Err(_)) => return crate::error::bad_request("could not read request body").into_response(),
        Err(_) => return crate::validate::body_timeout().into_response(),
    };
    let mut attempt = 0;
    loop {
        let r =
            axum::http::Request::from_parts(parts.clone(), axum::body::Body::from(bytes.clone()));
        let resp = next.clone().run(r).await;
        if resp
            .extensions()
            .get::<crate::error::RetryableDbError>()
            .is_none()
            || attempt >= 2
        {
            return resp;
        }
        attempt += 1;
        tokio::time::sleep(std::time::Duration::from_millis(20 * attempt)).await;
    }
}

/// Debug log of every request (never the query string: the WebSocket token may be there).
async fn log_request(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let (method, mut path, start) = (req.method().clone(), req.uri().path().to_string(), std::time::Instant::now());
    // A Bot API path carries the bot's token: never logged.
    if let Some(rest) = path.strip_prefix("/bot/") {
        path = format!("/bot/<token>/{}", rest.split_once('/').map(|(_, m)| m).unwrap_or(""));
    }
    let resp = next.run(req).await;
    tracing::debug!(%method, %path, status = resp.status().as_u16(), duration_ms = start.elapsed().as_millis() as u64, "request");
    resp
}

async fn fallback() -> ApiError {
    not_found("no such endpoint")
}

async fn info(State(st): State<AppState>) -> Response {
    let s = st.settings.get();
    let mut body = json!({
        "name": st.cfg.server_name,
        "version": VERSION,
        "registration_enabled": s.registration_enabled,
        "phone_verification_enabled": st.sms.is_some(),
        "max_attachment_bytes": s.attachment_max_bytes,
        "max_devices": s.max_devices,
        "push_enabled": st.push.enabled(),
        "voip_push_enabled": st.push.voip_enabled(),
        "turn_enabled": !st.cfg.turn_urls.is_empty(),
        // Clients pin this key and check sender certificates of sealed messages against it.
        "sealed_sender_trust_root": crate::validate::b64::encode(&st.sealed.trust_root_serialized()),
        // Clients pin these and verify the zkgroup credentials the server issues.
        "zkgroup_public_params": crate::validate::b64::encode(&st.zk.public_serialized),
        // Private groups v2 (API section "Groups v2"); whether clients create new groups as v2.
        "groups_v2": true,
        "groups_v2_default": groups_v2::default_on(),
        // Clients pin this key and verify the key transparency tree heads with it.
        "kt_public_key": crate::validate::b64::encode(&st.kt.public_key),
    });
    // The keys that sign the operator statements (official badges, notices; operator.rs).
    // Clients pin them at first contact. Absent while the admin API is disabled.
    if let Some(admin) = st.admin.as_ref() {
        let keys: Vec<String> = admin.verifier.keys().iter().map(|k| crate::validate::b64::encode(k)).collect();
        body["operator_keys"] = keys.into();
    }
    // The app versions the operator announces (admin settings): an app older than "latest"
    // offers its update, one older than "min" requires it. Absent when nothing is announced.
    if let Some(v) = s.client_versions_json() {
        body["client_versions"] = v;
    }
    reply(StatusCode::OK, body)
}

async fn health(State(st): State<AppState>) -> ApiResult {
    let ok = tokio::time::timeout(std::time::Duration::from_secs(3), crate::db::ping(&st.db))
        .await
        .unwrap_or(false);
    if !ok {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "database unavailable",
        ));
    }
    Ok(reply(StatusCode::OK, json!({"status": "ok"})))
}

/// Parses an optional integer query parameter.
pub fn query_int(
    query: Option<&str>,
    name: &str,
    def: i64,
    min: i64,
    max: i64,
) -> Result<i64, ApiError> {
    let v = query
        .and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.into_owned())
        })
        .unwrap_or_default();
    if v.is_empty() {
        return Ok(def);
    }
    match v.parse::<i64>() {
        Ok(n) if n >= min && n <= max => Ok(n),
        _ => Err(crate::error::bad_request(format!(
            "{name} must be an integer in {min}..{max}"
        ))),
    }
}

/// Runs `SELECT single_string_column ...` and collects the values.
pub async fn query_strings<'q>(
    db: impl sqlx::Executor<'q, Database = sqlx::MySql>,
    q: sqlx::query::Query<'q, sqlx::MySql, sqlx::mysql::MySqlArguments>,
) -> Result<Vec<String>, sqlx::Error> {
    use crate::db::RowExt;
    use sqlx::{Column, Row};
    Ok(q.fetch_all(db)
        .await?
        .iter()
        .map(|r| r.string(r.column(0).name()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_int_defaults_and_bounds() {
        assert_eq!(query_int(None, "limit", 100, 1, 1000).unwrap(), 100);
        assert_eq!(query_int(Some("other=5"), "limit", 100, 1, 1000).unwrap(), 100);
        assert_eq!(query_int(Some("limit="), "limit", 100, 1, 1000).unwrap(), 100);
        assert_eq!(query_int(Some("a=b&limit=5"), "limit", 100, 1, 1000).unwrap(), 5);
        assert_eq!(query_int(Some("limit=1"), "limit", 100, 1, 1000).unwrap(), 1);
        assert_eq!(query_int(Some("limit=1000"), "limit", 100, 1, 1000).unwrap(), 1000);
        // The first occurrence counts.
        assert_eq!(query_int(Some("limit=7&limit=9"), "limit", 100, 1, 1000).unwrap(), 7);
        for bad in ["limit=0", "limit=1001", "limit=-1", "limit=abc", "limit=1.5", "limit=99999999999999999999"] {
            let e = query_int(Some(bad), "limit", 100, 1, 1000).unwrap_err();
            assert_eq!(e.status, StatusCode::BAD_REQUEST, "{bad}");
        }
    }

    #[tokio::test]
    async fn replies() {
        let r = reply(StatusCode::CREATED, json!({"id": "x"}));
        assert_eq!(r.status(), StatusCode::CREATED);
        assert_eq!(r.headers().get(header::CONTENT_TYPE).unwrap(), "application/json");
        let body = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], br#"{"id":"x"}"#);
        let r = no_content();
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        let body = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        assert!(body.is_empty());
    }
}
