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
/// A recipient's message queue is full (the sender is not at fault, so not 429).
pub fn queue_full(msg: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::INSUFFICIENT_STORAGE, "queue_full", msg)
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn body_json(resp: Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn constructors_map_to_status_and_code() {
        let cases = [
            (bad_request("m"), StatusCode::BAD_REQUEST, "bad_request"),
            (unauthorized("m"), StatusCode::UNAUTHORIZED, "unauthorized"),
            (forbidden("m"), StatusCode::FORBIDDEN, "forbidden"),
            (not_found("m"), StatusCode::NOT_FOUND, "not_found"),
            (conflict("m"), StatusCode::CONFLICT, "conflict"),
            (gone("m"), StatusCode::GONE, "gone"),
            (too_large("m"), StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            (queue_full("m"), StatusCode::INSUFFICIENT_STORAGE, "queue_full"),
            (rate_limited(Duration::from_secs(3)), StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            (storage_unavailable("disk"), StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable"),
            (internal(), StatusCode::INTERNAL_SERVER_ERROR, "internal"),
            (internal_from("ctx", "cause"), StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        ];
        for (e, status, code) in cases {
            assert_eq!(e.status, status, "{code}");
            assert_eq!(e.code, code);
            assert!(!e.retryable);
        }
        assert_eq!(bad_request("no name").to_string(), "bad_request: no name");
    }

    #[tokio::test]
    async fn body_has_error_message_and_extra_fields() {
        let resp = conflict("taken").with("suggestion", "ana.02").with("left", 3).into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert!(resp.headers().get(header::RETRY_AFTER).is_none());
        assert!(resp.extensions().get::<RetryableDbError>().is_none());
        assert_eq!(
            body_json(resp).await,
            serde_json::json!({"error": "conflict", "message": "taken", "suggestion": "ana.02", "left": 3})
        );
    }

    #[tokio::test]
    async fn internal_details_are_not_returned() {
        let resp = internal_from("database error", "secret table name").into_response();
        let body = body_json(resp).await;
        assert_eq!(body, serde_json::json!({"error": "internal", "message": "internal server error"}));
        let resp = storage_unavailable("minio password wrong").into_response();
        assert!(!body_json(resp).await.to_string().contains("password"));
    }

    #[test]
    fn retry_after_is_rounded_up_to_whole_seconds() {
        let secs = |d: Duration| {
            let resp = rate_limited(d).into_response();
            resp.headers().get(header::RETRY_AFTER).unwrap().to_str().unwrap().to_string()
        };
        assert_eq!(secs(Duration::from_millis(1)), "1");
        assert_eq!(secs(Duration::from_millis(1500)), "2");
        assert_eq!(secs(Duration::from_secs(60)), "60");
    }

    #[test]
    fn database_errors_become_internal() {
        let e: ApiError = sqlx::Error::RowNotFound.into();
        assert_eq!(e.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!e.retryable);
        // Only an error marked retryable carries the marker for `api::retry_deadlocks`.
        let mut e = internal();
        e.retryable = true;
        assert!(e.into_response().extensions().get::<RetryableDbError>().is_some());
    }
}
