use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{Extension, State},
    http::{HeaderMap, Response, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    adapters::{add_seconds, new_resource_id, new_secret, sha256_hex},
    app::AppState,
    core::{ApiError, ApiErrorCode, Principal, RequestContext},
    http::auth::{require_csrf, require_session, set_session_cookies},
    modules::identity::{validate_device_label, validate_pkce_challenge},
    repositories::{
        DeviceAuthorizationRepository, IdentityRepository, SecurityEventInput, SecurityEventRepository,
    },
    routes::{
        errors,
        support::{database, database_error, domain_error, secure_cookie},
    },
};

const DEVICE_TTL_SECONDS: u32 = 10 * 60;
const SESSION_TTL_SECONDS: u32 = 60 * 60 * 24 * 30;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceCodeRequest {
    pub device_name: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveDeviceRequest {
    pub device_authorization_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeDeviceRequest {
    pub device_code: String,
    pub code_verifier: String,
}

#[derive(Debug, Serialize)]
pub struct DeviceCodeResponse {
    pub device_authorization_id: String,
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_at: String,
}

#[worker::send]
pub async fn start(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    Json(body): Json<DeviceCodeRequest>,
) -> Result<Response<Body>, ApiError> {
    let device_name = validate_device_label(&body.device_name).map_err(|_| validation_error(&context, "device_name_invalid", "Enter a valid device name."))?;
    let code_challenge = validate_pkce_challenge(&body.code_challenge).map_err(|_| validation_error(&context, "pkce_invalid", "The PKCE challenge is invalid."))?;
    if body.code_challenge_method != "S256" {
        return Err(validation_error(&context, "pkce_invalid", "Only S256 PKCE is supported."));
    }
    let database = database(&state, &context)?;
    let id = generated_id("dev");
    let user_code = new_secret()[..8].to_ascii_uppercase();
    let device_code = new_secret();
    let user_code_hash = sha256_hex(&user_code).await.map_err(|_| service_unavailable(&context))?;
    let device_code_hash = sha256_hex(&device_code).await.map_err(|_| service_unavailable(&context))?;
    let expires_at = add_seconds(&context.received_at, DEVICE_TTL_SECONDS).map_err(|_| service_unavailable(&context))?;
    let statement = DeviceAuthorizationRepository::new(database)
        .insert_statement(&id, &user_code_hash, &device_code_hash, &code_challenge, &device_name, &expires_at, &context.received_at)
        .map_err(|error| database_error(&context, error))?;
    database.batch(vec![statement]).await.map_err(|error| database_error(&context, error))?;
    Ok((StatusCode::CREATED, Json(DeviceCodeResponse {
        device_authorization_id: id,
        device_code,
        user_code,
        verification_uri: "/desktop".to_owned(),
        expires_at: expires_at.as_str().to_owned(),
    })).into_response())
}

#[worker::send]
pub async fn approve(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<ApproveDeviceRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    let database = database(&state, &context)?;
    let repository = DeviceAuthorizationRepository::new(database);
    let result = repository
        .approve_statement(&body.device_authorization_id, authenticated.principal.user_id.as_str(), &context.received_at)
        .map_err(|error| database_error(&context, error))?
        .run()
        .await
        .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&result).unwrap_or_default() != 1 {
        return Err(domain_error(&context, ApiErrorCode::Conflict, "device_code_expired", "The device authorization is no longer available."));
    }
    let event_id = generated_id("sec");
    let metadata = json!({ "device_label": "approved" });
    let security_statement = security_statement(database, &context, &authenticated.principal, &event_id, &body.device_authorization_id, metadata)?;
    database.batch(vec![security_statement]).await.map_err(|error| database_error(&context, error))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[worker::send]
pub async fn exchange(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    Json(body): Json<ExchangeDeviceRequest>,
) -> Result<Response<Body>, ApiError> {
    if body.device_code.len() > 256 || body.code_verifier.len() > 256 {
        return Err(validation_error(&context, "device_code_invalid", "The device authorization is invalid."));
    }
    let database = database(&state, &context)?;
    let device_repository = DeviceAuthorizationRepository::new(database);
    let device_hash = sha256_hex(&body.device_code).await.map_err(|_| service_unavailable(&context))?;
    let authorization = device_repository
        .find_by_device_code_hash(&device_hash)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| domain_error(&context, ApiErrorCode::AuthenticationRequired, "device_code_invalid", "The device authorization is invalid or expired."))?;
    if authorization.status != "approved" || authorization.expires_at.as_str() <= context.received_at.as_str() {
        return Err(domain_error(&context, ApiErrorCode::AuthenticationRequired, "device_code_expired", "The device authorization is invalid or expired."));
    }
    let verifier_hash = sha256_hex(&body.code_verifier).await.map_err(|_| service_unavailable(&context))?;
    if !constant_time_eq(verifier_hash.as_bytes(), authorization.code_challenge.as_bytes()) {
        return Err(domain_error(&context, ApiErrorCode::AuthenticationRequired, "device_code_invalid", "The device authorization is invalid or expired."));
    }
    let Some(user_id) = authorization.user_id.as_deref() else {
        return Err(domain_error(&context, ApiErrorCode::AuthenticationRequired, "device_code_invalid", "The device authorization is invalid or expired."));
    };
    let identity = IdentityRepository::new(database);
    let user = identity.find_user_by_id(user_id).await.map_err(|error| database_error(&context, error))?.ok_or_else(|| service_unavailable(&context))?;
    let session_id = generated_id("ses");
    let session_token = new_secret();
    let csrf_token = new_secret();
    let session_hash = sha256_hex(&session_token).await.map_err(|_| service_unavailable(&context))?;
    let csrf_hash = sha256_hex(&csrf_token).await.map_err(|_| service_unavailable(&context))?;
    let expires_at = add_seconds(&context.received_at, SESSION_TTL_SECONDS).map_err(|_| service_unavailable(&context))?;
    let session_statement = identity
        .insert_session_statement(&session_id, user_id, &session_hash, &csrf_hash, &authorization.device_label, "Lumi Agents Desktop", &expires_at, &context.received_at)
        .map_err(|error| database_error(&context, error))?;
    let consume_statement = device_repository
        .consume_statement(&authorization.device_authorization_id, &device_hash, &context.received_at)
        .map_err(|error| database_error(&context, error))?;
    let principal = Principal::new(
        crate::core::UserId::new(user_id).map_err(|_| service_unavailable(&context))?,
        crate::core::SessionId::new(&session_id).map_err(|_| service_unavailable(&context))?,
        user.email.clone(),
        user.display_name.clone(),
        user.email_verified,
    );
    let event_id = generated_id("sec");
    let metadata = json!({ "device_label": authorization.device_label });
    let security_statement = security_statement(database, &context, &principal, &event_id, &authorization.device_authorization_id, metadata)?;
    let results = database.batch(vec![consume_statement, session_statement, security_statement]).await.map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[0]).unwrap_or_default() != 1 {
        return Err(domain_error(&context, ApiErrorCode::Conflict, "device_code_replayed", "The device authorization is no longer available."));
    }
    let mut response = Json(json!({ "session": { "device_label": authorization.device_label, "expires_at": expires_at.as_str() } })).into_response();
    set_session_cookies(&mut response, &session_token, &csrf_token, secure_cookie(&state));
    Ok(response)
}

fn security_statement<'a>(
    database: &'a crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    principal: &Principal,
    event_id: &'a str,
    resource_id: &'a str,
    metadata: serde_json::Value,
) -> Result<worker::d1::D1PreparedStatement, ApiError> {
    let input = SecurityEventInput {
        event_id,
        organization_id: None,
        actor_type: "user",
        actor_id: Some(principal.user_id.as_str()),
        effective_user_id: Some(principal.user_id.as_str()),
        session_id: Some(principal.session_id.as_str()),
        device_id: None,
        action: "device_code.approved.v1",
        resource_type: "device_authorization",
        resource_id: Some(resource_id),
        outcome: "success",
        reason: None,
        metadata: &metadata,
        request_id: context.request_id.as_str(),
        correlation_id: context.correlation_id.as_str(),
        created_at: &context.received_at,
    };
    SecurityEventRepository::new(database).insert_statement(&input).map_err(|_| service_unavailable(context))
}

fn generated_id(prefix: &str) -> String {
    new_resource_id(prefix).as_str().to_owned()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).fold(0, |difference, (left, right)| difference | (left ^ right)) == 0
}

fn validation_error(context: &RequestContext, reason: &str, message: &str) -> ApiError {
    domain_error(context, ApiErrorCode::ValidationFailed, reason, message)
}

fn service_unavailable(context: &RequestContext) -> ApiError {
    errors::api_error(context, ApiErrorCode::ServiceUnavailable, "The identity store is unavailable.")
}
