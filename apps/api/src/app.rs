use std::sync::Arc;

use axum::{Router, middleware, routing::get, routing::post};
use worker::{Env, Queue};

use crate::{
    adapters::d1::D1Adapter,
    http::{json_body_limit, request_boundary},
    routes::{foundation_checks, health::health, meta::meta},
};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) database: Option<Arc<D1Adapter>>,
    pub(crate) queue: Option<Queue>,
}

/// Construct the HTTP router for one Worker request. Public liveness/meta
/// routes remain available when a storage binding is unavailable; internal
/// foundation probes exist only in Wrangler's explicit development env.
pub fn router(env: Env) -> Router {
    let is_development = env
        .var("ENVIRONMENT")
        .map(|value| value.to_string() == "development")
        .unwrap_or(false);
    let state = Arc::new(AppState {
        database: env.d1("DB").ok().map(D1Adapter::new).map(Arc::new),
        queue: env.queue("OUTBOX_QUEUE").ok(),
    });

    let mut routes = Router::<Arc<AppState>>::new()
        .route("/api/health", get(health))
        .route("/api/v1/meta", get(meta));

    if is_development {
        routes = routes
            .route(
                "/api/v1/_internal/foundation-checks",
                post(foundation_checks::create),
            )
            .route(
                "/api/v1/_internal/foundation-checks/{event_id}",
                get(foundation_checks::status),
            );
    }

    routes
        .layer(json_body_limit())
        .layer(middleware::from_fn(request_boundary))
        .with_state(state)
}
