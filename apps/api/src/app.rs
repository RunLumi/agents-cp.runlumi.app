use std::sync::Arc;

use axum::{
    Router, middleware,
    routing::{delete, get, patch, post},
};
use worker::{Env, Queue, SendEmail};

use crate::{
    adapters::d1::D1Adapter,
    http::{json_body_limit, request_boundary},
    routes::{
        account, auth, device_auth, foundation_checks, health::health, meta::meta, organizations,
    },
};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) database: Option<Arc<D1Adapter>>,
    pub(crate) queue: Option<Queue>,
    pub(crate) environment: String,
    pub(crate) email: Option<SendEmail>,
    pub(crate) email_from: Option<String>,
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
        environment: env
            .var("ENVIRONMENT")
            .map(|value| value.to_string())
            .unwrap_or_else(|_| "production".to_owned()),
        email: env.send_email("EMAIL").ok(),
        email_from: env.var("EMAIL_FROM").ok().map(|value| value.to_string()),
    });

    let mut routes = Router::<Arc<AppState>>::new()
        .route("/api/health", get(health))
        .route("/api/v1/meta", get(meta))
        .route("/api/v1/auth/signup", post(auth::signup))
        .route("/api/v1/auth/verify-email", post(auth::verify_email))
        .route("/api/v1/auth/login/start", post(auth::login_start))
        .route("/api/v1/auth/login/complete", post(auth::login_complete))
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/auth/refresh", post(auth::refresh))
        .route("/api/v1/auth/device-code", post(device_auth::start))
        .route(
            "/api/v1/auth/device-code/approve",
            post(device_auth::approve),
        )
        .route(
            "/api/v1/auth/device-code/exchange",
            post(device_auth::exchange),
        )
        .route("/api/v1/me", get(auth::me))
        .route(
            "/api/v1/me/identities/link/start",
            post(auth::link_identity_start),
        )
        .route("/api/v1/me/identities/link", post(auth::link_identity))
        .route(
            "/api/v1/orgs",
            post(organizations::create).get(organizations::list),
        )
        .route(
            "/api/v1/orgs/{org_id}",
            get(organizations::get).patch(organizations::update),
        )
        .route(
            "/api/v1/orgs/{org_id}/members",
            get(organizations::list_members),
        )
        .route(
            "/api/v1/orgs/{org_id}/invitations",
            get(organizations::list_invitations).post(organizations::invite),
        )
        .route(
            "/api/v1/orgs/{org_id}/invitations/{invitation_id}",
            delete(organizations::revoke_invitation),
        )
        .route(
            "/api/v1/orgs/{org_id}/invitations/{invitation_id}/resend",
            post(organizations::resend_invitation),
        )
        .route(
            "/api/v1/invitations/{invitation_id}/accept",
            post(organizations::accept_invitation),
        )
        .route(
            "/api/v1/orgs/{org_id}/members/{member_id}",
            patch(organizations::change_role).delete(organizations::remove_member),
        )
        .route(
            "/api/v1/orgs/{org_id}/ownership-transfer",
            post(organizations::transfer_ownership),
        )
        .route("/api/v1/orgs/{org_id}/leave", post(organizations::leave))
        .route(
            "/api/v1/orgs/{org_id}/suspend",
            post(organizations::suspend),
        )
        .route("/api/v1/orgs/{org_id}/resume", post(organizations::resume))
        .route(
            "/api/v1/orgs/{org_id}/deletion",
            post(organizations::begin_deletion),
        )
        .route(
            "/api/v1/orgs/{org_id}/teams",
            get(organizations::list_teams).post(organizations::create_team),
        )
        .route(
            "/api/v1/orgs/{org_id}/teams/{team_id}/members",
            post(organizations::add_team_member),
        )
        .route(
            "/api/v1/orgs/{org_id}/teams/{team_id}/members/{member_id}",
            delete(organizations::remove_team_member),
        )
        .route("/api/v1/orgs/{org_id}/audit", get(organizations::audit))
        .route("/api/v1/account/sessions", get(account::sessions))
        .route(
            "/api/v1/account/sessions/revoke-all",
            post(account::revoke_all_sessions),
        )
        .route(
            "/api/v1/account/sessions/{session_id}",
            delete(account::revoke_session),
        )
        .route("/api/v1/account/reauth", post(account::reauthenticate))
        .route(
            "/api/v1/account/security-events",
            get(account::security_events),
        );

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
