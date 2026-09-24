use axum::{
    body::Body,
    extract::DefaultBodyLimit,
    http::{HeaderValue, Method, Request, Response, header},
    middleware::Next,
    response::IntoResponse,
};
use serde::Serialize;

use crate::{
    core::{ActorContext, RequestContext},
    routes::errors,
};

use super::platform;

pub const MAX_JSON_BODY_BYTES: usize = 1_048_576;
const REQUEST_ID_HEADER: &str = "x-request-id";
const CORRELATION_ID_HEADER: &str = "x-correlation-id";

/// Axum applies this limit to JSON/byte extractors without buffering the body
/// in this middleware. The app router must install it alongside
/// [`request_boundary`].
pub fn json_body_limit() -> DefaultBodyLimit {
    DefaultBodyLimit::max(MAX_JSON_BODY_BYTES)
}

/// Establish trusted request identity, normalize unstructured framework
/// errors, and emit one bounded structured record after each request.
pub async fn request_boundary(request: Request<Body>, next: Next) -> Response<Body> {
    let request_id = platform::new_request_id();
    let incoming_correlation = request
        .headers()
        .get(CORRELATION_ID_HEADER)
        .and_then(|value| value.to_str().ok());
    let correlation_id = platform::correlation_id(incoming_correlation, &request_id);
    let mut context = RequestContext::new(
        request_id.clone(),
        correlation_id.clone(),
        platform::received_at(),
    );
    context.actor = Some(ActorContext::anonymous());

    let method = bounded_method(request.method());
    let route = matched_route(&request);
    let started_at_ms = platform::monotonic_now_ms();
    let mut request = request;
    request.extensions_mut().insert(context.clone());
    let mut response = next.run(request).await;

    if response.status().is_client_error() || response.status().is_server_error() {
        if errors::is_api_error_response(&response) {
            response = errors::bind_request_id(response, request_id.clone());
        } else {
            response = normalize_unstructured_error(response, request_id.clone());
        }
    }

    // The framework and application do not get to choose the request identity
    // returned to the caller. It always matches the envelope from this layer.
    response.headers_mut().insert(
        header::HeaderName::from_static(REQUEST_ID_HEADER),
        HeaderValue::from_str(request_id.as_str())
            .expect("generated request IDs contain only visible ASCII"),
    );

    emit_request_log(RequestLog {
        event: "http_request",
        request_id: request_id.as_str(),
        correlation_id: correlation_id.as_str(),
        method,
        route: &route,
        status: response.status().as_u16(),
        duration_ms: elapsed_ms(started_at_ms, platform::monotonic_now_ms()),
    });

    response
}

fn matched_route(request: &Request<Body>) -> String {
    request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|matched| {
            let route = matched.as_str();
            if route.len() <= 160 && route.is_ascii() {
                route.to_owned()
            } else {
                "other".to_owned()
            }
        })
        .unwrap_or_else(|| "unmatched".to_owned())
}

fn bounded_method(method: &Method) -> &'static str {
    match method.as_str() {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "PATCH" => "PATCH",
        "DELETE" => "DELETE",
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        "CONNECT" => "CONNECT",
        "TRACE" => "TRACE",
        _ => "OTHER",
    }
}

fn normalize_unstructured_error(
    original: Response<Body>,
    request_id: crate::core::RequestId,
) -> Response<Body> {
    let original_status = original.status();
    let mut normalized = errors::for_status(original_status, request_id).into_response();

    // Preserve protocol metadata that remains meaningful after replacing the
    // framework body with the stable envelope.
    for name in [header::ALLOW, header::RETRY_AFTER, header::WWW_AUTHENTICATE] {
        if let Some(value) = original.headers().get(&name) {
            normalized.headers_mut().insert(name, value.clone());
        }
    }

    normalized
}

fn elapsed_ms(started_at_ms: f64, finished_at_ms: f64) -> u64 {
    if !started_at_ms.is_finite() || !finished_at_ms.is_finite() {
        return 0;
    }
    (finished_at_ms - started_at_ms).max(0.0).round() as u64
}

#[derive(Serialize)]
struct RequestLog<'a> {
    event: &'static str,
    request_id: &'a str,
    correlation_id: &'a str,
    method: &'static str,
    route: &'a str,
    status: u16,
    duration_ms: u64,
}

fn emit_request_log(log: RequestLog<'_>) {
    if let Ok(record) = serde_json::to_string(&log) {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("{}", record);

        #[cfg(not(target_arch = "wasm32"))]
        let _ = record;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        sync::Arc,
        task::{Context, Poll, Wake, Waker},
    };

    use axum::{
        Json, Router,
        http::StatusCode,
        routing::{get, post},
    };
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use tower_service::Service;

    use super::*;

    #[derive(Deserialize, Serialize)]
    struct TestPayload {
        name: String,
    }

    async fn ok() -> &'static str {
        "ok"
    }

    async fn accept_json(Json(payload): Json<TestPayload>) -> Json<TestPayload> {
        Json(payload)
    }

    async fn context_echo(
        axum::Extension(context): axum::Extension<RequestContext>,
    ) -> Json<Value> {
        Json(serde_json::json!({
            "request_id": context.request_id.as_str(),
            "correlation_id": context.correlation_id.as_str(),
            "actor_type": context.actor.as_ref().map(|actor| actor.actor_type),
        }))
    }

    async fn internal_failure() -> (StatusCode, &'static str) {
        (StatusCode::INTERNAL_SERVER_ERROR, "secret diagnostic text")
    }

    async fn matched_path_probe(request: Request<Body>, next: Next) -> Response<Body> {
        let has_matched_path = request
            .extensions()
            .get::<axum::extract::MatchedPath>()
            .is_some();
        let mut response = next.run(request).await;
        response.headers_mut().insert(
            "x-test-matched-path-visible",
            HeaderValue::from_static(if has_matched_path { "yes" } else { "no" }),
        );
        response
    }

    fn test_router() -> Router {
        Router::new()
            .route("/api/ok", get(ok))
            .route("/api/json", post(accept_json))
            .route("/api/context", get(context_echo))
            .route("/api/only-get", get(ok))
            .route("/api/failure", get(internal_failure))
            .layer(json_body_limit())
            .layer(axum::middleware::from_fn(request_boundary))
    }

    fn test_request(
        method: &str,
        uri: &str,
        content_type: Option<&str>,
        body: Body,
    ) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(content_type) = content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        builder.body(body).unwrap()
    }

    fn send(request: Request<Body>) -> Response<Body> {
        let mut router = test_router();
        block_on(router.call(request)).unwrap()
    }

    fn send_with_probe(request: Request<Body>) -> Response<Body> {
        let mut router = Router::new()
            .route("/api/ok", get(ok))
            .layer(axum::middleware::from_fn(matched_path_probe));
        block_on(router.call(request)).unwrap()
    }

    fn assert_error_response(response: Response<Body>, status: StatusCode, code: &str) -> Value {
        assert_eq!(response.status(), status);
        let header_request_id = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .expect("every response has a generated request ID")
            .to_str()
            .unwrap()
            .to_owned();
        let bytes = block_on(axum::body::to_bytes(
            response.into_body(),
            MAX_JSON_BODY_BYTES,
        ))
        .unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(value["error"]["code"], code);
        assert_eq!(value["error"]["request_id"], header_request_id);
        assert!(value["error"]["details"].is_object());
        value
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        struct ThreadWaker(std::thread::Thread);

        impl Wake for ThreadWaker {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.unpark();
            }
        }

        let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::park(),
            }
        }
    }

    #[test]
    fn logged_request_record_has_only_bounded_transport_dimensions() {
        let request_id = platform::new_request_id();
        let correlation_id = platform::correlation_id(Some("trace-1"), &request_id);
        let encoded = serde_json::to_string(&RequestLog {
            event: "http_request",
            request_id: request_id.as_str(),
            correlation_id: correlation_id.as_str(),
            method: "POST",
            route: "/api/v1/checks",
            status: 400,
            duration_ms: 2,
        })
        .unwrap();
        let value: Value = serde_json::from_str(&encoded).unwrap();

        assert_eq!(value["request_id"], request_id.as_str());
        assert_eq!(value["correlation_id"], "trace-1");
        assert_eq!(value["route"], "/api/v1/checks");
        assert_eq!(value["status"], 400);
        assert_eq!(value["duration_ms"], 2);
        assert_eq!(value.as_object().unwrap().len(), 7);
        assert!(!encoded.contains("authorization"));
        assert!(!encoded.contains("body"));
    }

    #[test]
    fn success_extractor_and_internal_responses_share_the_boundary_id() {
        let success = send(test_request("GET", "/api/ok", None, Body::empty()));
        assert_eq!(success.status(), StatusCode::OK);
        let success_id = success
            .headers()
            .get(REQUEST_ID_HEADER)
            .expect("successes also receive a request ID")
            .to_str()
            .unwrap()
            .to_owned();
        assert!(success_id.starts_with("req_"));

        let malformed = send(test_request(
            "POST",
            "/api/json",
            Some("application/json"),
            Body::from("{"),
        ));
        let malformed = assert_error_response(malformed, StatusCode::BAD_REQUEST, "bad_request");
        assert_eq!(malformed["error"]["request_id"].as_str().unwrap().len(), 36);

        let unsupported_media = send(test_request(
            "POST",
            "/api/json",
            Some("text/plain"),
            Body::from("{}"),
        ));
        assert_error_response(
            unsupported_media,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        );

        let invalid_fields = send(test_request(
            "POST",
            "/api/json",
            Some("application/json"),
            Body::from("{}"),
        ));
        assert_error_response(
            invalid_fields,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
        );

        let internal = send(test_request("GET", "/api/failure", None, Body::empty()));
        let internal = assert_error_response(
            internal,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
        );
        assert_eq!(
            internal["error"]["message"],
            "An unexpected error occurred."
        );
        assert!(!internal.to_string().contains("secret diagnostic text"));
    }

    #[test]
    fn server_generated_request_id_and_validated_correlation_context_reach_handlers() {
        let mut router = test_router();
        let request = Request::builder()
            .method("GET")
            .uri("/api/context")
            .header(REQUEST_ID_HEADER, "req_00000000000000000000000000000000")
            .header(CORRELATION_ID_HEADER, "client-trace-42")
            .body(Body::empty())
            .unwrap();
        let response = block_on(router.call(request)).unwrap();
        let header_request_id = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let bytes = block_on(axum::body::to_bytes(
            response.into_body(),
            MAX_JSON_BODY_BYTES,
        ))
        .unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();

        assert_ne!(header_request_id, "req_00000000000000000000000000000000");
        assert_eq!(
            value["request_id"].as_str(),
            Some(header_request_id.as_str())
        );
        assert_eq!(value["correlation_id"], "client-trace-42");
        assert_eq!(value["actor_type"], "anonymous");
    }

    #[test]
    fn router_layer_can_read_matched_path_before_calling_next() {
        let response = send_with_probe(test_request("GET", "/api/ok", None, Body::empty()));

        assert_eq!(
            response
                .headers()
                .get("x-test-matched-path-visible")
                .unwrap(),
            "yes"
        );
    }

    #[test]
    fn route_and_method_failures_are_normalized_without_leaking_framework_text() {
        let not_found = send(test_request("GET", "/does-not-exist", None, Body::empty()));
        assert_error_response(not_found, StatusCode::NOT_FOUND, "not_found");

        let method_mismatch = send(test_request(
            "POST",
            "/api/only-get",
            Some("application/json"),
            Body::empty(),
        ));
        let method_mismatch = assert_error_response(
            method_mismatch,
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
        );
        assert!(
            method_mismatch["error"]["message"]
                .as_str()
                .unwrap()
                .contains("method is not allowed")
        );
    }

    #[test]
    fn oversized_json_is_rejected_by_the_default_body_limit() {
        let oversized = send(test_request(
            "POST",
            "/api/json",
            Some("application/json"),
            Body::from(vec![b'a'; MAX_JSON_BODY_BYTES + 1]),
        ));
        assert_error_response(
            oversized,
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
        );
    }

    #[test]
    fn normalizing_a_method_mismatch_preserves_the_allow_header() {
        let request_id = platform::new_request_id();
        let original = Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::ALLOW, "GET, POST")
            .body(Body::from("framework text"))
            .unwrap();

        let response = normalize_unstructured_error(original, request_id);
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers().get(header::ALLOW).unwrap(), "GET, POST");
    }

    #[test]
    fn duration_is_nonnegative_even_if_wall_clock_moves_backwards() {
        assert_eq!(elapsed_ms(42.0, 41.0), 0);
        assert_eq!(elapsed_ms(41.0, 43.4), 2);
    }

    #[test]
    fn json_extractor_limit_matches_the_frozen_one_mib_contract() {
        assert_eq!(MAX_JSON_BODY_BYTES, 1_048_576);
    }
}
