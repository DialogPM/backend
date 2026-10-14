//! Attachments: slot creation, streaming upload into object storage, download (API section 9).

use std::time::Duration;

use axum::body::{Body, HttpBody};
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use futures_util::{StreamExt, TryStreamExt};
use serde::Deserialize;
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::time::Instant;
use tokio_util::io::StreamReader;
use tracing::{error, warn};

use super::keys::null_default;
use super::{no_content, reply};
use crate::auth::Principal;
use crate::error::{
    bad_request, conflict, forbidden, internal_from, not_found, storage_unavailable, too_large,
    ApiError, ApiResult,
};
use crate::ids;
use crate::state::AppState;
use crate::storage::StorageError;
use crate::validate::{parse_json, MAX_JSON_BODY};

// Attachment states.
pub const ATTACHMENT_CREATED: i64 = 0;
pub const ATTACHMENT_UPLOADING: i64 = 1;
pub const ATTACHMENT_UPLOADED: i64 = 2;

pub const KIND_MESSAGE: &str = "message";
pub const KIND_AVATAR: &str = "avatar";

/// Deadline for streaming `size` bytes: a fixed allowance plus a very conservative minimum
/// throughput of 64 KiB/s.
fn transfer_timeout(size: i64) -> Duration {
    Duration::from_secs(5 * 60 + (size.max(0) / (64 << 10)) as u64)
}

#[derive(Deserialize)]
struct CreateRequest {
    #[serde(default)]
    size: Option<i64>,
    #[serde(default, deserialize_with = "null_default")]
    kind: String,
}

pub async fn create(State(st): State<AppState>, p: Principal, body: Body) -> ApiResult {
    let req: CreateRequest = parse_json(body, MAX_JSON_BODY).await?;
    let size = match req.size {
        Some(s) if s >= 1 => s,
        _ => return Err(bad_request("size must be a positive integer")),
    };
    if size > st.settings.get().attachment_max_bytes {
        return Err(too_large("attachment exceeds max_attachment_bytes"));
    }
    if req.kind != KIND_MESSAGE && req.kind != KIND_AVATAR {
        return Err(bad_request("kind must be message or avatar"));
    }
    // Per-account daily quota (declared sizes, including uploads that never completed).
    // SUM is a DECIMAL: read it as text and parse, like RowExt::i64 did.
    let used: i64 = sqlx::query!("SELECT COALESCE(SUM(size), 0) AS `used!: String` FROM attachments WHERE owner_id = ? AND created_at > ?", &p.account, crate::now_millis() - 24 * 3600 * 1000)
        .fetch_one(&st.db)
        .await?
        .used
        .split('.')
        .next()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or_else(|| panic!("column used: not an integer"));
    if used + size > st.cfg.attachment_daily_bytes {
        let mut e = ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "quota_exceeded",
            "daily upload quota reached",
        );
        e.retry_after = Some(Duration::from_secs(3600));
        return Err(e);
    }
    let id = ids::new_attachment_id();
    sqlx::query!(
        "INSERT INTO attachments (id, owner_id, kind, size, state, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        &id,
        &p.account,
        &req.kind,
        size,
        ATTACHMENT_CREATED,
        crate::now_millis()
    )
    .execute(&st.db)
    .await?;
    Ok(reply(StatusCode::OK, json!({"id": id})))
}

fn path_attachment_id(id: &str) -> Result<String, ApiError> {
    if !ids::valid_attachment_id(id) {
        return Err(bad_request(
            "id must be a 32-character lowercase hex attachment id",
        ));
    }
    Ok(id.to_string())
}

pub async fn upload(
    State(st): State<AppState>,
    p: Principal,
    Path(id): Path<String>,
    body: Body,
) -> ApiResult {
    let id = path_attachment_id(&id)?;
    let row = sqlx::query!("SELECT owner_id AS `owner_id: String`, size, state FROM attachments WHERE id = ?", &id)
        .fetch_optional(&st.db)
        .await?;
    let Some(row) = row else {
        return Err(not_found("unknown attachment"));
    };
    let (owner, size) = (row.owner_id, row.size);
    if owner != p.account {
        return Err(forbidden("only the creator can upload this attachment"));
    }
    // Known length (Content-Length, or an empty body): must match the declared size.
    if let Some(len) = body.size_hint().exact() {
        if len as i128 != size as i128 {
            if len as i128 > size as i128 {
                return Err(too_large("body is larger than the declared size"));
            }
            return Err(bad_request("body length does not match the declared size"));
        }
    }
    // Claim the upload slot atomically (only once).
    let res =
        sqlx::query!("UPDATE attachments SET state = ? WHERE id = ? AND owner_id = ? AND state = ?", ATTACHMENT_UPLOADING, &id, &p.account, ATTACHMENT_CREATED)
            .execute(&st.db)
            .await?;
    if res.rows_affected() != 1 {
        return Err(conflict("attachment already uploaded"));
    }
    // From here on the transfer runs in its own task, so the slot is released (or the upload
    // completed) even if the client goes away and this request future is dropped.
    let st2 = st.clone();
    tokio::spawn(async move { store_upload(&st2, &id, size, body).await })
        .await
        .map_err(|e| internal_from("attachment upload task failed", e))?
}

async fn store_upload(st: &AppState, id: &str, size: i64, body: Body) -> ApiResult {
    let release = || async {
        if let Err(e) = sqlx::query!("UPDATE attachments SET state = ? WHERE id = ? AND state = ?", ATTACHMENT_CREATED, id, ATTACHMENT_UPLOADING)
            .execute(&st.db)
            .await
        {
            warn!(attachment = %id, error = %e, "reset attachment state failed");
        }
    };
    let deadline = Instant::now() + transfer_timeout(size);
    let mut reader = StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));

    let put = st.store.put(id, Box::pin(&mut reader), size as u64);
    let result = match tokio::time::timeout_at(deadline, put).await {
        Ok(r) => r,
        Err(_) => Err(StorageError::Read(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "upload deadline exceeded",
        ))),
    };
    if let Err(e) = result {
        release().await;
        return Err(match e {
            StorageError::SizeMismatch => bad_request("body is shorter than the declared size"),
            StorageError::Read(_) => bad_request("upload interrupted"),
            e => {
                error!(attachment = %id, error = %e, "attachment upload to storage failed");
                storage_unavailable(e)
            }
        });
    }
    // The store read exactly size bytes; anything left means the body was too long.
    let mut extra = [0u8; 1];
    let n = match tokio::time::timeout_at(deadline, reader.read(&mut extra)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };
    if n > 0 {
        release().await;
        if let Err(e) = st.store.delete(id).await {
            warn!(attachment = %id, error = %e, "delete oversized attachment failed");
        }
        return Err(too_large("body is larger than the declared size"));
    }
    sqlx::query!("UPDATE attachments SET state = ?, uploaded_at = ? WHERE id = ?", ATTACHMENT_UPLOADED, crate::now_millis(), id)
        .execute(&st.db)
        .await?;
    crate::metrics::bump(crate::metrics::ATTACHMENTS_UPLOADED, 1);
    Ok(no_content())
}

pub async fn download(
    State(st): State<AppState>,
    _p: Principal,
    Path(id): Path<String>,
) -> ApiResult {
    let id = path_attachment_id(&id)?;
    let row = sqlx::query!("SELECT state AS `state: i64` FROM attachments WHERE id = ?", &id)
        .fetch_optional(&st.db)
        .await?;
    if row.is_none_or(|r| r.state != ATTACHMENT_UPLOADED) {
        return Err(not_found("unknown attachment"));
    }
    let (stream, size) = match st.store.get(&id).await {
        Ok(v) => v,
        Err(StorageError::NotFound) => return Err(not_found("unknown attachment")),
        Err(e) => {
            error!(attachment = %id, error = %e, "attachment download from storage failed");
            return Err(storage_unavailable(e));
        }
    };
    // Write deadline: the stream ends (and the connection breaks) once it passes.
    let deadline = tokio::time::sleep(transfer_timeout(size as i64));
    let log_id = id.clone();
    let stream = stream.take_until(deadline).inspect_err(
        move |e| warn!(attachment = %log_id, error = %e, "attachment download interrupted"),
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, size.to_string())
        .body(Body::from_stream(stream))
        .map_err(|e| internal_from("build download response", e))
}
