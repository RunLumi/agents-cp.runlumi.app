use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::RequestId;

/// Validation failures returned by the pure core value types.
///
/// Variants intentionally contain no rejected input, so formatting or logging
/// an error cannot expose a cursor, credential, or request body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreError {
    InvalidResourceId,
    InvalidRequestId,
    InvalidEventId,
    InvalidActorId,
    InvalidCorrelationId,
    InvalidTimestamp,
    InvalidCursor,
    InconsistentPageCursor,
    InvalidEventType,
    InvalidIdempotencyKey,
    InvalidIdempotencyDigest,
    InvalidRequestFingerprint,
    InvalidEndpointScope,
    InvalidSuccessStatus,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidResourceId => "invalid resource ID",
            Self::InvalidRequestId => "invalid request ID",
            Self::InvalidEventId => "invalid event ID",
            Self::InvalidActorId => "invalid actor ID",
            Self::InvalidCorrelationId => "invalid correlation ID",
            Self::InvalidTimestamp => "invalid UTC timestamp",
            Self::InvalidCursor => "invalid cursor",
            Self::InconsistentPageCursor => "page cursor and has_more are inconsistent",
            Self::InvalidEventType => "invalid event type",
            Self::InvalidIdempotencyKey => "invalid idempotency key",
            Self::InvalidIdempotencyDigest => "invalid idempotency key digest",
            Self::InvalidRequestFingerprint => "invalid request fingerprint",
            Self::InvalidEndpointScope => "invalid idempotency endpoint scope",
            Self::InvalidSuccessStatus => "stored response status is not successful",
        };
        f.write_str(message)
    }
}

impl std::error::Error for CoreError {}

/// Stable error codes exposed by the API contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiErrorCode {
    BadRequest,
    ValidationFailed,
    AuthenticationRequired,
    PermissionDenied,
    NotFound,
    MethodNotAllowed,
    PayloadTooLarge,
    UnsupportedMediaType,
    Conflict,
    IdempotencyConflict,
    IdempotencyInProgress,
    RateLimited,
    InternalError,
    ServiceUnavailable,
}

impl ApiErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::ValidationFailed => "validation_failed",
            Self::AuthenticationRequired => "authentication_required",
            Self::PermissionDenied => "permission_denied",
            Self::NotFound => "not_found",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::PayloadTooLarge => "payload_too_large",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::Conflict => "conflict",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::IdempotencyInProgress => "idempotency_in_progress",
            Self::RateLimited => "rate_limited",
            Self::InternalError => "internal_error",
            Self::ServiceUnavailable => "service_unavailable",
        }
    }

    pub const fn status_code(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::ValidationFailed => 422,
            Self::AuthenticationRequired => 401,
            Self::PermissionDenied => 403,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::PayloadTooLarge => 413,
            Self::UnsupportedMediaType => 415,
            Self::Conflict | Self::IdempotencyConflict | Self::IdempotencyInProgress => 409,
            Self::RateLimited => 429,
            Self::InternalError => 500,
            Self::ServiceUnavailable => 503,
        }
    }
}

/// JSON error response with the stable `{ "error": { ... } }` envelope.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiError {
    pub error: ApiErrorBody,
}

/// Error fields consumed by API clients.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub code: ApiErrorCode,
    pub message: String,
    pub request_id: RequestId,
    pub details: std::collections::BTreeMap<String, Value>,
}

impl ApiError {
    pub fn new(code: ApiErrorCode, message: impl Into<String>, request_id: RequestId) -> Self {
        Self {
            error: ApiErrorBody {
                code,
                message: message.into(),
                request_id,
                details: std::collections::BTreeMap::new(),
            },
        }
    }

    pub fn with_detail(mut self, key: impl Into<String>, value: Value) -> Self {
        self.error.details.insert(key.into(), value);
        self
    }
}

// Error detail values may contain data that must not reach diagnostic logs.
impl fmt::Debug for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiError")
            .field("code", &self.error.code)
            .field("request_id", &self.error.request_id)
            .field("details", &"[redacted]")
            .finish()
    }
}

impl fmt::Debug for ApiErrorBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiErrorBody")
            .field("code", &self.code)
            .field("request_id", &self.request_id)
            .field("details", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn request_id() -> RequestId {
        "req_0123456789abcdef0123456789abcdef".parse().unwrap()
    }

    #[test]
    fn api_error_matches_frozen_envelope_and_status_map() {
        let error = ApiError::new(
            ApiErrorCode::PermissionDenied,
            "You do not have permission to perform this action.",
            request_id(),
        );
        assert_eq!(ApiErrorCode::PermissionDenied.status_code(), 403);
        assert_eq!(
            serde_json::to_value(error).unwrap(),
            json!({
                "error": {
                    "code": "permission_denied",
                    "message": "You do not have permission to perform this action.",
                    "request_id": "req_0123456789abcdef0123456789abcdef",
                    "details": {}
                }
            })
        );
    }

    #[test]
    fn error_debug_does_not_print_detail_payload() {
        let error = ApiError::new(ApiErrorCode::BadRequest, "bad", request_id())
            .with_detail("input", json!("sensitive request body"));
        let debug = format!("{error:?}");
        assert!(!debug.contains("sensitive request body"));
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn error_codes_serialize_as_stable_snake_case() {
        assert_eq!(
            serde_json::to_string(&ApiErrorCode::IdempotencyInProgress).unwrap(),
            "\"idempotency_in_progress\""
        );
        assert_eq!(ApiErrorCode::IdempotencyInProgress.status_code(), 409);
    }
}
