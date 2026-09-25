use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, Response, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    adapters::{add_seconds, new_resource_id, new_secret, sha256_hex},
    app::AppState,
    core::{ApiError, ApiErrorCode, RequestContext},
    http::auth::{clear_session_cookies, require_csrf, require_session},
    repositories::{IdentityRepository, SecurityEventInput, SecurityEventRepository},
    routes::{
        errors,
        support::{database, database_error, domain_error, secure_cookie},
    },
};

const REAUTH_TTL_SECONDS: u32 = 5 * 60;

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<u16>,
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EmptyRequest {}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ReauthRequest {
    pub purpose: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReauthResponse {
    pub grant_id: String,
    pub token: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize)]
pub struct PageResponse<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[worker::send]
pub async fn sessions(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Response<Body>, ApiError> {
    reject_cursor(&context, query.cursor.as_deref())?;
    let authenticated = require_session(&state, &headers, &context).await?;
    let database = database(&state, &context)?;
    let sessions = IdentityRepository::new(database)
        .list_sessions(
            authenticated.principal.user_id.as_str(),
            &context.received_at,
            page_limit(query.limit),
            0,
        )
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(Json(PageResponse {
        items: sessions,
        next_cursor: None,
        has_more: false,
    })
    .into_response())
}

#[worker::send]
pub async fn revoke_session(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    let database = database(&state, &context)?;
    let repository = IdentityRepository::new(database);
    if !repository
        .revoke_owned_session(
            &session_id,
            authenticated.principal.user_id.as_str(),
            &context.received_at,
            "user_revoked",
        )
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::NotFound,
            "resource_not_found",
            "The session was not found.",
        ));
    }
    let event_id = generated_id("sec");
    let statement = security_statement(
        database,
        &context,
        &authenticated.principal,
        &event_id,
        "session.revoked.v1",
        &session_id,
    )?;
    database
        .batch(vec![statement])
        .await
        .map_err(|error| database_error(&context, error))?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    if session_id == authenticated.session.session_id {
        clear_session_cookies(&mut response, secure_cookie(&state));
    }
    Ok(response)
}

#[worker::send]
pub async fn revoke_all_sessions(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(_body): Json<EmptyRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    let database = database(&state, &context)?;
    let repository = IdentityRepository::new(database);
    let statement = repository
        .revoke_all_other_sessions_statement(
            authenticated.principal.user_id.as_str(),
            &authenticated.session.session_id,
            &context.received_at,
            "user_revoked_all",
        )
        .map_err(|error| database_error(&context, error))?;
    let event_id = generated_id("sec");
    let audit = security_statement(
        database,
        &context,
        &authenticated.principal,
        &event_id,
        "session.revoked_all.v1",
        &authenticated.session.session_id,
    )?;
    database
        .batch(vec![statement, audit])
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[worker::send]
pub async fn reauthenticate(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<ReauthRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    let purpose = body.purpose.as_deref().unwrap_or("ownership_transfer");
    if !matches!(
        purpose,
        "ownership_transfer"
            | "identity_link"
            | "org_lifecycle"
            | "passkey_management"
            | "password_change"
            | "account_recovery"
    ) {
        return Err(domain_error(
            &context,
            ApiErrorCode::ValidationFailed,
            "purpose_invalid",
            "Choose a supported security-check purpose.",
        ));
    }
    let database = database(&state, &context)?;
    let grant_id = generated_id("rag");
    let token = new_secret();
    let token_hash = sha256_hex(&token)
        .await
        .map_err(|_| service_unavailable(&context))?;
    let expires_at = add_seconds(&context.received_at, REAUTH_TTL_SECONDS)
        .map_err(|_| service_unavailable(&context))?;
    let repository = IdentityRepository::new(database);
    let grant_statement = repository
        .insert_reauth_statement(
            &grant_id,
            authenticated.principal.user_id.as_str(),
            authenticated.principal.session_id.as_str(),
            purpose,
            &token_hash,
            &expires_at,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let event_id = generated_id("sec");
    let audit = security_statement(
        database,
        &context,
        &authenticated.principal,
        &event_id,
        "reauthentication.granted.v1",
        &grant_id,
    )?;
    database
        .batch(vec![grant_statement, audit])
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok((
        StatusCode::CREATED,
        Json(ReauthResponse {
            grant_id,
            token,
            expires_at: expires_at.as_str().to_owned(),
        }),
    )
        .into_response())
}

#[worker::send]
pub async fn security_events(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Response<Body>, ApiError> {
    reject_cursor(&context, query.cursor.as_deref())?;
    let authenticated = require_session(&state, &headers, &context).await?;
    let database = database(&state, &context)?;
    let events = SecurityEventRepository::new(database)
        .list_for_user(
            authenticated.principal.user_id.as_str(),
            page_limit(query.limit),
            0,
        )
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(Json(PageResponse {
        items: events,
        next_cursor: None,
        has_more: false,
    })
    .into_response())
}

fn security_statement<'a>(
    database: &'a crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    principal: &crate::core::Principal,
    event_id: &'a str,
    action: &'a str,
    resource_id: &'a str,
) -> Result<worker::d1::D1PreparedStatement, ApiError> {
    let metadata = json!({});
    let input = SecurityEventInput {
        event_id,
        organization_id: None,
        actor_type: "user",
        actor_id: Some(principal.user_id.as_str()),
        effective_user_id: Some(principal.user_id.as_str()),
        session_id: Some(principal.session_id.as_str()),
        device_id: None,
        action,
        resource_type: "session",
        resource_id: Some(resource_id),
        outcome: "success",
        reason: None,
        metadata: &metadata,
        request_id: context.request_id.as_str(),
        correlation_id: context.correlation_id.as_str(),
        created_at: &context.received_at,
    };
    SecurityEventRepository::new(database)
        .insert_statement(&input)
        .map_err(|_| service_unavailable(context))
}

fn generated_id(prefix: &str) -> String {
    new_resource_id(prefix).as_str().to_owned()
}

fn page_limit(limit: Option<u16>) -> u16 {
    limit.unwrap_or(50).clamp(1, 100)
}

fn reject_cursor(context: &RequestContext, cursor: Option<&str>) -> Result<(), ApiError> {
    if cursor.is_some_and(|value| !value.is_empty()) {
        return Err(domain_error(
            context,
            ApiErrorCode::BadRequest,
            "invalid_cursor",
            "The pagination cursor is invalid.",
        ));
    }
    Ok(())
}

fn service_unavailable(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::ServiceUnavailable,
        "The identity store is unavailable.",
    )
}
