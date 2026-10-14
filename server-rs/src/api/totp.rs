//! Two-step verification (TOTP, RFC 6238). Secrets are stored AES-GCM encrypted with a key
//! derived from the server secret; totp_last_step blocks code replay.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;
use sqlx::{MySql, Transaction};
use tracing::info;

use super::{no_content, reply};
use crate::auth::Principal;
use crate::error::{bad_request, conflict, internal_from, ApiError, ApiResult};
use crate::state::AppState;
use crate::totp;
use crate::validate::{parse_json, MAX_JSON_BODY};

const NONCE_LEN: usize = 12;

fn totp_required() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "totp_required",
        "two-step verification code required",
    )
}

fn invalid_totp() -> ApiError {
    crate::metrics::inc(&crate::metrics::FAILED_TOTP);
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "invalid_totp",
        "invalid two-step verification code",
    )
}

fn totp_aead(st: &AppState) -> Aes256Gcm {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(st.cfg.server_secret.as_bytes()).expect("hmac key");
    mac.update(b"chatapp/totp-at-rest/v1");
    Aes256Gcm::new_from_slice(&mac.finalize().into_bytes()).expect("aes-256 key")
}

/// nonce || ciphertext || tag, bound to the account id.
fn seal_totp(st: &AppState, account: &str, secret: &[u8]) -> Vec<u8> {
    let nonce = crate::ids::random_bytes(NONCE_LEN);
    let ct = totp_aead(st)
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: secret,
                aad: account.as_bytes(),
            },
        )
        .expect("aes-gcm seal");
    let mut out = nonce;
    out.extend_from_slice(&ct);
    out
}

fn open_totp(st: &AppState, account: &str, sealed: &[u8]) -> Result<Vec<u8>, ApiError> {
    if sealed.len() < NONCE_LEN {
        return Err(internal_from("open totp secret", "totp secret too short"));
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    totp_aead(st)
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: account.as_bytes(),
            },
        )
        .map_err(|e| internal_from("open totp secret", e))
}

fn now_secs() -> i64 {
    crate::now_millis().div_euclid(1000)
}

/// Verifies a code for an account with TOTP enabled, inside tx (row locked), and records the
/// step. Ok when TOTP is not enabled.
pub async fn check_totp(
    st: &AppState,
    tx: &mut Transaction<'_, MySql>,
    account: &str,
    code: &str,
) -> Result<(), ApiError> {
    let row =
        sqlx::query!("SELECT totp_secret, totp_last_step FROM accounts WHERE id = ? FOR UPDATE", account)
            .fetch_one(&mut **tx)
            .await?;
    let Some(sealed) = row.totp_secret else {
        return Ok(());
    };
    let last_step = row.totp_last_step;
    if code.is_empty() {
        return Err(totp_required());
    }
    totp_rate_limit(st, account)?;
    let secret = open_totp(st, account, &sealed)?;
    let Some(step) = totp::verify(&secret, code, now_secs(), last_step) else {
        return Err(invalid_totp());
    };
    sqlx::query!("UPDATE accounts SET totp_last_step = ? WHERE id = ?", step, account)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Bounds guesses of 6-digit codes: 10 per 10 minutes and 30 per day, so an attacker who
/// knows the password needs on average decades to hit a valid code.
fn totp_rate_limit(st: &AppState, account: &str) -> Result<(), ApiError> {
    st.rate_limit(&format!("totp:{account}"), st.limits.login_number)?;
    st.rate_limit(&format!("totp-day:{account}"), st.limits.totp_daily)
}

pub async fn totp_enabled(st: &AppState, account: &str) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!("SELECT totp_secret FROM accounts WHERE id = ?", account)
        .fetch_one(&st.db)
        .await?;
    Ok(row.totp_secret.is_some())
}

/// POST /v1/account/totp/setup: new pending secret (enabled only after a code confirms it).
pub async fn setup(State(st): State<AppState>, p: Principal) -> ApiResult {
    if totp_enabled(&st, &p.account).await? {
        return Err(conflict("two-step verification is already enabled"));
    }
    let number = sqlx::query!("SELECT number AS `number: String` FROM accounts WHERE id = ?", &p.account)
        .fetch_one(&st.db)
        .await?
        .number;
    let secret = totp::new_secret();
    sqlx::query!(
        "UPDATE accounts SET totp_pending = ? WHERE id = ?",
        seal_totp(&st, &p.account, &secret),
        &p.account
    )
    .execute(&st.db)
        .await?;
    Ok(reply(
        StatusCode::OK,
        json!({"secret": totp::encode(&secret), "uri": totp::uri(&secret, &st.cfg.server_name, &number)}),
    ))
}

#[derive(Deserialize)]
struct CodeRequest {
    #[serde(default)]
    code: String,
}

/// POST /v1/account/totp/enable {code}: confirms the pending secret.
pub async fn enable(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    let req: CodeRequest = parse_json(body, MAX_JSON_BODY).await?;
    totp_rate_limit(&st, &p.account)?;
    let row = sqlx::query!("SELECT totp_pending, totp_secret FROM accounts WHERE id = ?", &p.account)
        .fetch_one(&st.db)
        .await?;
    if row.totp_secret.is_some() {
        return Err(conflict("two-step verification is already enabled"));
    }
    let Some(pending) = row.totp_pending else {
        return Err(bad_request("start the setup first"));
    };
    let secret = open_totp(&st, &p.account, &pending)?;
    let Some(step) = totp::verify(&secret, &req.code, now_secs(), 0) else {
        return Err(invalid_totp());
    };
    sqlx::query!("UPDATE accounts SET totp_secret = totp_pending, totp_pending = NULL, totp_last_step = ? WHERE id = ?", step, &p.account)
        .execute(&st.db)
        .await?;
    info!(account = %p.account, "two-step verification enabled");
    Ok(no_content())
}

/// DELETE /v1/account/totp {code}: turns two-step verification off (needs a current code).
pub async fn disable(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    let req: CodeRequest = parse_json(body, MAX_JSON_BODY).await?;
    if req.code.is_empty() {
        return Err(invalid_totp());
    }
    let mut tx = st.db.begin().await?;
    check_totp(&st, &mut tx, &p.account, &req.code).await?;
    sqlx::query!("UPDATE accounts SET totp_secret = NULL, totp_pending = NULL WHERE id = ?", &p.account)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    info!(account = %p.account, "two-step verification disabled");
    Ok(no_content())
}
