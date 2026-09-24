//! Stable JSON error helpers for HTTP handlers and middleware.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::core::{ApiError, ApiErrorCode, RequestContext, RequestId};

/// Marker used by the request boundary to distinguish an already-normalized
/// domain/API error from Axum's unstructured rejection responses.
#[derive(Clone)]
struct ApiErrorResponse(ApiError);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.error.code.status_code())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let marker = ApiErrorResponse(self.clone());
        let mut response = (status, Json(self)).into_response();
        // Keep a private typed copy so the outer request boundary can enforce
        // that the JSON envelope uses its trusted, generated request ID.
        response.extensions_mut().insert(marker);
        response
    }
}

pub(crate) fn is_api_error_response(response: &Response) -> bool {
    response.extensions().get::<ApiErrorResponse>().is_some()
}

pub(crate) fn bind_request_id(response: Response, request_id: RequestId) -> Response {
    let Some(marker) = response.extensions().get::<ApiErrorResponse>() else {
        return response;
    };
    if marker.0.error.request_id == request_id {
        return response;
    }

    let mut error = marker.0.clone();
    error.error.request_id = request_id;
    let mut rebound = error.into_response();
    for name in [
        axum::http::header::ALLOW,
        axum::http::header::RETRY_AFTER,
        axum::http::header::WWW_AUTHENTICATE,
    ] {
        if let Some(value) = response.headers().get(&name) {
            rebound.headers_mut().insert(name, value.clone());
        }
    }
    rebound
}

pub(crate) fn for_status(status: StatusCode, request_id: RequestId) -> ApiError {
    let (code, message) = match status {
        StatusCode::BAD_REQUEST => (
            ApiErrorCode::BadRequest,
            "The request is malformed or invalid.",
        ),
        StatusCode::UNAUTHORIZED => (
            ApiErrorCode::AuthenticationRequired,
            "Authentication is required.",
        ),
        StatusCode::FORBIDDEN => (
            ApiErrorCode::PermissionDenied,
            "You do not have permission to perform this action.",
        ),
        StatusCode::NOT_FOUND => (
            ApiErrorCode::NotFound,
            "The requested resource was not found.",
        ),
        StatusCode::METHOD_NOT_ALLOWED => (
            ApiErrorCode::MethodNotAllowed,
            "This method is not allowed for the requested resource.",
        ),
        StatusCode::PAYLOAD_TOO_LARGE => (
            ApiErrorCode::PayloadTooLarge,
            "The request body exceeds the allowed size.",
        ),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => (
            ApiErrorCode::UnsupportedMediaType,
            "The request content type is not supported.",
        ),
        StatusCode::CONFLICT => (
            ApiErrorCode::Conflict,
            "The request conflicts with current state.",
        ),
        StatusCode::UNPROCESSABLE_ENTITY => (
            ApiErrorCode::ValidationFailed,
            "The request contains invalid fields.",
        ),
        StatusCode::TOO_MANY_REQUESTS => (
            ApiErrorCode::RateLimited,
            "Too many requests. Try again later.",
        ),
        StatusCode::SERVICE_UNAVAILABLE => (
            ApiErrorCode::ServiceUnavailable,
            "The service is temporarily unavailable.",
        ),
        _ => (ApiErrorCode::InternalError, "An unexpected error occurred."),
    };

    ApiError::new(code, message, request_id)
}

/// Build an application error with the ID established by the HTTP boundary.
pub fn api_error(
    context: &RequestContext,
    code: ApiErrorCode,
    message: impl Into<String>,
) -> ApiError {
    ApiError::new(code, message, context.request_id.clone())
}

pub fn bad_request(request_id: RequestId, message: &'static str) -> ApiError {
    ApiError::new(ApiErrorCode::BadRequest, message, request_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_id() -> RequestId {
        "req_0123456789abcdef0123456789abcdef".parse().unwrap()
    }

    #[test]
    fn framework_statuses_map_to_frozen_api_codes_and_statuses() {
        for (status, code) in [
            (StatusCode::BAD_REQUEST, ApiErrorCode::BadRequest),
            (
                StatusCode::UNAUTHORIZED,
                ApiErrorCode::AuthenticationRequired,
            ),
            (StatusCode::FORBIDDEN, ApiErrorCode::PermissionDenied),
            (StatusCode::NOT_FOUND, ApiErrorCode::NotFound),
            (
                StatusCode::METHOD_NOT_ALLOWED,
                ApiErrorCode::MethodNotAllowed,
            ),
            (StatusCode::PAYLOAD_TOO_LARGE, ApiErrorCode::PayloadTooLarge),
            (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                ApiErrorCode::UnsupportedMediaType,
            ),
            (StatusCode::CONFLICT, ApiErrorCode::Conflict),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                ApiErrorCode::ValidationFailed,
            ),
            (StatusCode::TOO_MANY_REQUESTS, ApiErrorCode::RateLimited),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiErrorCode::InternalError,
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                ApiErrorCode::ServiceUnavailable,
            ),
        ] {
            let error = for_status(status, request_id());
            assert_eq!(error.error.code, code);
            assert_eq!(code.status_code(), status.as_u16());
        }
    }

    #[test]
    fn status_conversion_discards_framework_error_text() {
        let response = for_status(StatusCode::BAD_REQUEST, request_id()).into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(is_api_error_response(&response));
    }

    #[test]
    fn handler_error_helper_uses_the_trusted_request_context_id() {
        let context = RequestContext::new(
            request_id(),
            "trace-1".parse().unwrap(),
            "2026-09-24T00:00:00.000Z".parse().unwrap(),
        );
        let error = api_error(
            &context,
            ApiErrorCode::PermissionDenied,
            "You do not have permission to perform this action.",
        );

        assert_eq!(error.error.request_id, context.request_id);
        assert_eq!(error.error.code, ApiErrorCode::PermissionDenied);
    }

    #[test]
    fn boundary_rebinding_changes_only_a_mismatched_request_id() {
        let error = ApiError::new(
            ApiErrorCode::Conflict,
            "The request conflicts with current state.",
            request_id(),
        )
        .with_detail("reason", serde_json::json!("version_changed"));
        let expected_id: RequestId = "req_1123456789abcdef0123456789abcdef".parse().unwrap();

        let response = bind_request_id(error.into_response(), expected_id.clone());
        let marker = response.extensions().get::<ApiErrorResponse>().unwrap();

        assert_eq!(marker.0.error.request_id, expected_id);
        assert_eq!(marker.0.error.code, ApiErrorCode::Conflict);
        assert_eq!(
            marker.0.error.details.get("reason"),
            Some(&serde_json::json!("version_changed"))
        );
    }
}
