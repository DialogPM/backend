//! API errors, rendered as `{"error": code, "message": message, ...extra}`.

use std::time::Duration;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value};

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub extra: Map<String, Value>,
    pub retry_after: Option<Duration>,
    pub retryable: bool,
}

pub type ApiResult<T = Response> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        ApiError {
            status,
            code,
            message: message.into(),
            extra: Map::new(),
            retry_after: None,
            retryable: false,
        }
    }

    /// Adds an extra field to the error body.
    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.extra.insert(key.to_string(), value.into());
        self
    }
}

pub fn bad_request(msg: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "bad_request", msg)
}
pub fn unauthorized(msg: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized", msg)
}
pub fn forbidden(msg: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, "forbidden", msg)
}
pub fn not_found(msg: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "not_found", msg)
}
pub fn conflict(msg: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, "conflict", msg)
}
pub fn gone(msg: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::GONE, "gone", msg)
}
pub fn too_large(msg: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", msg)
}
pub fn rate_limited(wait: Duration) -> ApiError {
    let mut e = ApiError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "too many requests",
    );
    e.retry_after = Some(wait);
    e
}
/// Object storage (MinIO/S3) failed; details are logged, not returned.
pub fn storage_unavailable(cause: impl std::fmt::Display) -> ApiError {
    tracing::error!(error = %cause, "object storage failure");
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "storage_unavailable",
        "the server's file storage (MinIO) is not reachable",
    )
}
pub fn internal() -> ApiError {
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "internal server error",
    )
}
/// Logs an unexpected error and returns the generic internal error.
pub fn internal_from(context: &str, err: impl std::fmt::Display) -> ApiError {
    tracing::error!(error = %err, "{context}");
    internal()
}

/// Response marker: the request failed on a MySQL deadlock / lock wait timeout and may be
/// retried as a whole (its transaction was rolled back). See `api::retry_deadlocks`.
#[derive(Clone, Copy, Debug)]
pub struct RetryableDbError;

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        if crate::db::is_retryable(&e) {
            tracing::warn!(error = %e, "database deadlock");
            let mut err = internal();
            err.retryable = true;
            return err;
        }
        internal_from("database error", e)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = self.extra;
        body.insert("error".into(), Value::String(self.code.into()));
        body.insert("message".into(), Value::String(self.message));
        let mut resp = (self.status, axum::Json(Value::Object(body))).into_response();
        if self.retryable {
            resp.extensions_mut().insert(RetryableDbError);
        }
        if let Some(wait) = self.retry_after {
            let secs = wait.as_secs_f64().ceil().max(1.0) as u64;
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
        }
        resp
    }
}
