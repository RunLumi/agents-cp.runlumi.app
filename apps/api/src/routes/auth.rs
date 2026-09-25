use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{Extension, State},
    http::{HeaderMap, Response, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::{add_seconds, deliver_auth_code, new_resource_id, new_secret, sha256_hex},
    app::AppState,
    core::{ApiError, ApiErrorCode, Principal, RequestContext},
    http::auth::{clear_session_cookies, require_csrf, require_session, set_session_cookies},
    modules::identity::{ChallengeKind, NormalizedEmail, validate_display_name},
    repositories::{IdentityRepository, SecurityEventInput, SecurityEventRepository, UserRecord},
    routes::{
        errors,
        support::{
            database, database_error, domain_error, is_development, outbox_statement,
            secure_cookie, user_json,
        },
    },
};

const CHALLENGE_TTL_SECONDS: u32 = 10 * 60;
const SESSION_TTL_SECONDS: u32 = 60 * 60 * 24 * 30;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignupRequest {
    pub email: String,
    pub display_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    pub challenge_id: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginStartRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginCompleteRequest {
    pub challenge_id: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkIdentityStartRequest {
    pub email: String,
    pub reauth_grant_id: String,
    pub reauth_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkIdentityRequest {
    pub challenge_id: String,
    pub code: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EmptyRequest {}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub development_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub user: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<ChallengeResponse>,
}

#[derive(Debug, Serialize)]
pub struct UserOnlyResponse {
    pub user: Value,
}

#[worker::send]
pub async fn signup(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    Json(body): Json<SignupRequest>,
) -> Result<Response<Body>, ApiError> {
    let database = database(&state, &context)?;
    let email = NormalizedEmail::parse(&body.email)
        .map_err(|_| validation_error(&context, "email_invalid", "Enter a valid email address."))?;
    enforce_rate_limit(&state, &context, &format!("signup:{}", email.as_str()), 5).await?;
    let display_name = validate_display_name(&body.display_name).map_err(|_| {
        validation_error(
            &context,
            "display_name_invalid",
            "Enter a valid display name.",
        )
    })?;
    let repository = IdentityRepository::new(database);
    if repository
        .find_user_by_email(email.as_str())
        .await
        .map_err(|error| database_error(&context, error))?
        .is_some()
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "identity_conflict",
            "An account with this verified identity already exists.",
        ));
    }

    let user_id = generated_id("usr");
    let identity_id = generated_id("idn");
    let challenge_id = generated_id("idn");
    let event_id = generated_id("sec");
    let code = new_secret();
    let code_hash = sha256_hex(&code)
        .await
        .map_err(|_| service_unavailable(&context))?;
    let expires_at = add_seconds(&context.received_at, CHALLENGE_TTL_SECONDS)
        .map_err(|_| service_unavailable(&context))?;
    let user_statement = repository
        .insert_user_statement(
            &user_id,
            email.as_str(),
            &display_name,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let identity_statement = repository
        .insert_identity_statement(&identity_id, &user_id, email.as_str(), &context.received_at)
        .map_err(|error| database_error(&context, error))?;
    let challenge_statement = repository
        .insert_challenge_statement(
            &challenge_id,
            Some(&user_id),
            email.as_str(),
            ChallengeKind::Verification.as_str(),
            &code_hash,
            &expires_at,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let security_statement = security_statement(
        database,
        &context,
        None,
        &event_id,
        None,
        "identity.created.v1",
        "user",
        Some(&user_id),
        "success",
        json!({ "provider": "email" }),
    )?;
    database
        .batch(vec![
            user_statement,
            identity_statement,
            challenge_statement,
            security_statement,
        ])
        .await
        .map_err(|error| database_error(&context, error))?;
    deliver_auth_code(&state, email.as_str(), &code, "verification")
        .await
        .map_err(|_| service_unavailable(&context))?;
    let user = repository
        .find_user_by_id(&user_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| service_unavailable(&context))?;

    let verification = ChallengeResponse {
        challenge_id,
        expires_at: expires_at.as_str().to_owned(),
        development_code: is_development(&state).then_some(code),
    };
    Ok((
        StatusCode::CREATED,
        Json(UserResponse {
            user: user_json(&user),
            verification: Some(verification),
        }),
    )
        .into_response())
}

#[worker::send]
pub async fn verify_email(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    Json(body): Json<VerifyRequest>,
) -> Result<Response<Body>, ApiError> {
    let database = database(&state, &context)?;
    let repository = IdentityRepository::new(database);
    let challenge = repository
        .find_challenge(&body.challenge_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| {
            authentication_error(
                &context,
                "verification_invalid",
                "The verification link is invalid or expired.",
            )
        })?;
    let user_id = challenge.user_id.clone().ok_or_else(|| {
        authentication_error(
            &context,
            "verification_invalid",
            "The verification link is invalid or expired.",
        )
    })?;
    if challenge.kind != ChallengeKind::Verification.as_str() {
        return Err(authentication_error(
            &context,
            "verification_invalid",
            "The verification link is invalid or expired.",
        ));
    }
    if challenge.status == "consumed"
        && let Some(user) = repository
            .find_user_by_id(&user_id)
            .await
            .map_err(|error| database_error(&context, error))?
    {
        return Ok(Json(UserOnlyResponse {
            user: user_json(&user),
        })
        .into_response());
    }
    if challenge.status != "pending" {
        return Err(authentication_error(
            &context,
            "verification_expired",
            "The verification link is invalid or expired.",
        ));
    }
    let code_hash = sha256_hex(&body.code)
        .await
        .map_err(|_| service_unavailable(&context))?;
    if !repository
        .consume_challenge(&challenge.challenge_id, &code_hash, &context.received_at)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        let _ = repository
            .record_failed_challenge(&challenge.challenge_id)
            .await;
        return Err(authentication_error(
            &context,
            "verification_invalid",
            "The verification link is invalid or expired.",
        ));
    }
    let event_id = generated_id("sec");
    let security_statement = security_statement(
        database,
        &context,
        None,
        &event_id,
        None,
        "identity.verified.v1",
        "user",
        Some(&user_id),
        "success",
        json!({ "provider": "email" }),
    )?;
    let mut statements = repository
        .verify_user_statements(&user_id, &challenge.email, &context.received_at)
        .map_err(|error| database_error(&context, error))?;
    statements.push(security_statement);
    database
        .batch(statements)
        .await
        .map_err(|error| database_error(&context, error))?;
    let user = repository
        .find_user_by_id(&user_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| service_unavailable(&context))?;
    Ok(Json(UserOnlyResponse {
        user: user_json(&user),
    })
    .into_response())
}

#[worker::send]
pub async fn login_start(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    Json(body): Json<LoginStartRequest>,
) -> Result<Response<Body>, ApiError> {
    let database = database(&state, &context)?;
    let email = NormalizedEmail::parse(&body.email)
        .map_err(|_| validation_error(&context, "email_invalid", "Enter a valid email address."))?;
    enforce_rate_limit(&state, &context, &format!("login:{}", email.as_str()), 10).await?;
    let repository = IdentityRepository::new(database);
    let user = repository
        .find_user_by_email(email.as_str())
        .await
        .map_err(|error| database_error(&context, error))?;
    let challenge_id = generated_id("idn");
    let code = new_secret();
    let code_hash = sha256_hex(&code)
        .await
        .map_err(|_| service_unavailable(&context))?;
    let expires_at = add_seconds(&context.received_at, CHALLENGE_TTL_SECONDS)
        .map_err(|_| service_unavailable(&context))?;
    let statement = repository
        .insert_challenge_statement(
            &challenge_id,
            user.as_ref().map(|user| user.user_id.as_str()),
            email.as_str(),
            ChallengeKind::Login.as_str(),
            &code_hash,
            &expires_at,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    database
        .batch(vec![statement])
        .await
        .map_err(|error| database_error(&context, error))?;
    if user.is_some() {
        deliver_auth_code(&state, email.as_str(), &code, "login")
            .await
            .map_err(|_| service_unavailable(&context))?;
    }
    let response = ChallengeResponse {
        challenge_id,
        expires_at: expires_at.as_str().to_owned(),
        development_code: (is_development(&state) && user.is_some()).then_some(code),
    };
    Ok((StatusCode::ACCEPTED, Json(response)).into_response())
}

#[worker::send]
pub async fn login_complete(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<LoginCompleteRequest>,
) -> Result<Response<Body>, ApiError> {
    let database = database(&state, &context)?;
    let repository = IdentityRepository::new(database);
    let challenge = repository
        .find_challenge(&body.challenge_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| {
            authentication_error(
                &context,
                "login_invalid",
                "The sign-in link is invalid or expired.",
            )
        })?;
    if challenge.kind != ChallengeKind::Login.as_str() || challenge.status != "pending" {
        return Err(authentication_error(
            &context,
            "login_invalid",
            "The sign-in link is invalid or expired.",
        ));
    }
    let Some(user_id) = challenge.user_id.as_deref() else {
        return Err(authentication_error(
            &context,
            "login_invalid",
            "The sign-in link is invalid or expired.",
        ));
    };
    let code_hash = sha256_hex(&body.code)
        .await
        .map_err(|_| service_unavailable(&context))?;
    if !repository
        .consume_challenge(&challenge.challenge_id, &code_hash, &context.received_at)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        let _ = repository
            .record_failed_challenge(&challenge.challenge_id)
            .await;
        return Err(authentication_error(
            &context,
            "login_invalid",
            "The sign-in link is invalid or expired.",
        ));
    }
    let user = repository
        .find_user_by_id(user_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| {
            authentication_error(
                &context,
                "login_invalid",
                "The sign-in link is invalid or expired.",
            )
        })?;
    let (response, session_token, csrf_token) = create_session(
        &state,
        &context,
        database,
        &repository,
        &user,
        &headers,
        "auth.login.completed.v1",
        None,
    )
    .await?;
    let mut response = response;
    set_session_cookies(
        &mut response,
        &session_token,
        &csrf_token,
        secure_cookie(&state),
    );
    Ok(response)
}

#[worker::send]
pub async fn logout(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(_body): Json<EmptyRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    let database = database(&state, &context)?;
    let repository = IdentityRepository::new(database);
    let event_id = generated_id("sec");
    let security_statement = security_statement(
        database,
        &context,
        Some(&authenticated.principal),
        &event_id,
        None,
        "auth.logout.v1",
        "session",
        Some(&authenticated.session.session_id),
        "success",
        json!({ "scope": "web" }),
    )?;
    let statements = vec![
        repository
            .revoke_session_statement(
                &authenticated.session.session_id,
                &context.received_at,
                "user_logout",
            )
            .map_err(|error| database_error(&context, error))?,
        security_statement,
    ];
    database
        .batch(statements)
        .await
        .map_err(|error| database_error(&context, error))?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    clear_session_cookies(&mut response, secure_cookie(&state));
    Ok(response)
}

#[worker::send]
pub async fn refresh(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(_body): Json<EmptyRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    let database = database(&state, &context)?;
    let repository = IdentityRepository::new(database);
    let user = repository
        .find_user_by_id(authenticated.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| authentication_error(&context, "session_revoked", "Sign in again."))?;
    let (mut response, session_token, csrf_token) = create_session(
        &state,
        &context,
        database,
        &repository,
        &user,
        &headers,
        "auth.session.rotated.v1",
        Some(&authenticated.session.session_id),
    )
    .await?;
    set_session_cookies(
        &mut response,
        &session_token,
        &csrf_token,
        secure_cookie(&state),
    );
    Ok(response)
}

#[worker::send]
pub async fn link_identity_start(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<LinkIdentityStartRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    if !authenticated.principal.email_verified {
        return Err(domain_error(
            &context,
            ApiErrorCode::PermissionDenied,
            "email_verification_required",
            "Verify your current email before linking another identity.",
        ));
    }
    let email = NormalizedEmail::parse(&body.email)
        .map_err(|_| validation_error(&context, "email_invalid", "Enter a valid email address."))?;
    let database = database(&state, &context)?;
    let repository = IdentityRepository::new(database);
    if repository
        .find_user_by_email(email.as_str())
        .await
        .map_err(|error| database_error(&context, error))?
        .is_some()
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "identity_conflict",
            "That identity is already linked to an account.",
        ));
    }
    let reauth_hash = sha256_hex(&body.reauth_token)
        .await
        .map_err(|_| service_unavailable(&context))?;
    if !repository
        .consume_reauth(
            &body.reauth_grant_id,
            authenticated.principal.user_id.as_str(),
            authenticated.principal.session_id.as_str(),
            "identity_link",
            &reauth_hash,
            &context.received_at,
        )
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::PermissionDenied,
            "reauthentication_required",
            "Complete a recent security check before linking an identity.",
        ));
    }
    let challenge_id = generated_id("idn");
    let code = new_secret();
    let code_hash = sha256_hex(&code)
        .await
        .map_err(|_| service_unavailable(&context))?;
    let expires_at = add_seconds(&context.received_at, CHALLENGE_TTL_SECONDS)
        .map_err(|_| service_unavailable(&context))?;
    let challenge_statement = repository
        .insert_challenge_statement(
            &challenge_id,
            Some(authenticated.principal.user_id.as_str()),
            email.as_str(),
            ChallengeKind::IdentityLink.as_str(),
            &code_hash,
            &expires_at,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let event_id = generated_id("sec");
    let metadata = json!({ "provider": "email" });
    let security_statement = security_statement(
        database,
        &context,
        Some(&authenticated.principal),
        &event_id,
        None,
        "identity.link_started.v1",
        "identity",
        Some(&challenge_id),
        "success",
        metadata.clone(),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&authenticated.principal),
        None,
        "identity.link_started.v1",
        &metadata,
    )?;
    database
        .batch(vec![challenge_statement, security_statement, outbox])
        .await
        .map_err(|error| database_error(&context, error))?;
    deliver_auth_code(&state, email.as_str(), &code, "identity_link")
        .await
        .map_err(|_| service_unavailable(&context))?;
    Ok((
        StatusCode::ACCEPTED,
        Json(ChallengeResponse {
            challenge_id,
            expires_at: expires_at.as_str().to_owned(),
            development_code: is_development(&state).then_some(code),
        }),
    )
        .into_response())
}

#[worker::send]
pub async fn link_identity(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<LinkIdentityRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    let database = database(&state, &context)?;
    let repository = IdentityRepository::new(database);
    let challenge = repository
        .find_challenge(&body.challenge_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| {
            domain_error(
                &context,
                ApiErrorCode::PermissionDenied,
                "identity_conflict",
                "The identity link challenge is invalid or expired.",
            )
        })?;
    if challenge.kind != ChallengeKind::IdentityLink.as_str()
        || challenge.user_id.as_deref() != Some(authenticated.principal.user_id.as_str())
        || challenge.status != "pending"
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::PermissionDenied,
            "identity_conflict",
            "The identity link challenge is invalid or expired.",
        ));
    }
    let email = NormalizedEmail::parse(&challenge.email).map_err(|_| {
        domain_error(
            &context,
            ApiErrorCode::Conflict,
            "identity_conflict",
            "The identity link challenge is invalid or expired.",
        )
    })?;
    if let Some(existing) = repository
        .find_user_by_email(email.as_str())
        .await
        .map_err(|error| database_error(&context, error))?
    {
        let _ = existing;
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "identity_conflict",
            "That identity is already linked to an account.",
        ));
    }
    let code_hash = sha256_hex(&body.code)
        .await
        .map_err(|_| service_unavailable(&context))?;
    if !repository
        .consume_challenge(&challenge.challenge_id, &code_hash, &context.received_at)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        let _ = repository
            .record_failed_challenge(&challenge.challenge_id)
            .await;
        return Err(domain_error(
            &context,
            ApiErrorCode::PermissionDenied,
            "identity_conflict",
            "The identity link challenge is invalid or expired.",
        ));
    }
    let identity_id = generated_id("idn");
    let statement = repository
        .link_identity_statement(
            &identity_id,
            authenticated.principal.user_id.as_str(),
            "email",
            email.as_str(),
            email.as_str(),
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let event_id = generated_id("sec");
    let metadata = json!({ "provider": "email" });
    let security_statement = security_statement(
        database,
        &context,
        Some(&authenticated.principal),
        &event_id,
        None,
        "identity.linked.v1",
        "identity",
        Some(&identity_id),
        "success",
        metadata.clone(),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&authenticated.principal),
        None,
        "identity.linked.v1",
        &metadata,
    )?;
    database
        .batch(vec![statement, security_statement, outbox])
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "identity": { "id": identity_id, "provider": "email", "email": email.as_str(), "email_verified": true } })),
    )
        .into_response())
}

#[worker::send]
pub async fn me(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    let database = database(&state, &context)?;
    let user = IdentityRepository::new(database)
        .find_user_by_id(authenticated.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| authentication_error(&context, "session_revoked", "Sign in again."))?;
    let organizations = crate::repositories::OrganizationRepository::new(database)
        .list_for_user(authenticated.principal.user_id.as_str(), 100, 0)
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(Json(json!({ "user": user_json(&user), "organizations": organizations })).into_response())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_session(
    state: &Arc<AppState>,
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    repository: &IdentityRepository<'_>,
    user: &UserRecord,
    headers: &HeaderMap,
    action: &str,
    previous_session_id: Option<&str>,
) -> Result<(Response<Body>, String, String), ApiError> {
    create_session_with_statements(
        state,
        context,
        database,
        repository,
        user,
        headers,
        action,
        previous_session_id,
        Vec::new(),
    )
    .await
}

/// Create the canonical LoginSession while allowing an authenticator route
/// to include its credential/ceremony mutations in the same D1 transaction.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_session_with_statements(
    _state: &Arc<AppState>,
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    repository: &IdentityRepository<'_>,
    user: &UserRecord,
    headers: &HeaderMap,
    action: &str,
    previous_session_id: Option<&str>,
    extra_statements: Vec<D1PreparedStatement>,
) -> Result<(Response<Body>, String, String), ApiError> {
    let session_id = generated_id("ses");
    let session_token = new_secret();
    let csrf_token = new_secret();
    let token_hash = sha256_hex(&session_token)
        .await
        .map_err(|_| service_unavailable(context))?;
    let csrf_hash = sha256_hex(&csrf_token)
        .await
        .map_err(|_| service_unavailable(context))?;
    let expires_at = add_seconds(&context.received_at, SESSION_TTL_SECONDS)
        .map_err(|_| service_unavailable(context))?;
    let device_label = headers
        .get("x-device-label")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .unwrap_or("Browser");
    let platform = headers
        .get("x-platform")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .unwrap_or("web");
    let statement = repository
        .insert_session_statement(
            &session_id,
            &user.user_id,
            &token_hash,
            &csrf_hash,
            device_label,
            platform,
            &expires_at,
            &context.received_at,
        )
        .map_err(|error| database_error(context, error))?;
    let event_id = generated_id("sec");
    let principal = Principal::new(
        user_id_from_str(&user.user_id, context)?,
        session_id_from_str(&session_id, context)?,
        user.email.clone(),
        user.display_name.clone(),
        user.email_verified,
    );
    let security_statement = security_statement(
        database,
        context,
        Some(&principal),
        &event_id,
        None,
        action,
        "session",
        Some(&session_id),
        "success",
        json!({ "scope": "web" }),
    )?;
    let outbox = outbox_statement(
        database,
        context,
        Some(&principal),
        None,
        action,
        &json!({ "scope": "web" }),
    )?;
    let mut statements = extra_statements;
    statements.extend([statement, security_statement, outbox]);
    if let Some(previous_session_id) = previous_session_id {
        statements.push(
            repository
                .revoke_session_statement(previous_session_id, &context.received_at, "rotated")
                .map_err(|error| database_error(context, error))?,
        );
    }
    database
        .batch(statements)
        .await
        .map_err(|error| database_error(context, error))?;
    Ok((
        Json(UserOnlyResponse {
            user: user_json(user),
        })
        .into_response(),
        session_token,
        csrf_token,
    ))
}

#[allow(clippy::too_many_arguments)]
fn security_statement<'a>(
    database: &'a crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    principal: Option<&Principal>,
    event_id: &'a str,
    organization_id: Option<&'a str>,
    action: &'a str,
    resource_type: &'a str,
    resource_id: Option<&'a str>,
    outcome: &'a str,
    metadata: Value,
) -> Result<worker::d1::D1PreparedStatement, ApiError> {
    let (actor_type, actor_id, effective_user_id, session_id) =
        principal.map_or(("anonymous", "", "", ""), |principal| {
            (
                "user",
                principal.user_id.as_str(),
                principal.user_id.as_str(),
                principal.session_id.as_str(),
            )
        });
    let input = SecurityEventInput {
        event_id,
        organization_id,
        actor_type,
        actor_id: (!actor_id.is_empty()).then_some(actor_id),
        effective_user_id: (!effective_user_id.is_empty()).then_some(effective_user_id),
        session_id: (!session_id.is_empty()).then_some(session_id),
        device_id: None,
        action,
        resource_type,
        resource_id,
        outcome,
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

fn user_id_from_str(
    value: &str,
    context: &RequestContext,
) -> Result<crate::core::UserId, ApiError> {
    crate::core::UserId::new(value).map_err(|_| service_unavailable(context))
}

fn session_id_from_str(
    value: &str,
    context: &RequestContext,
) -> Result<crate::core::SessionId, ApiError> {
    crate::core::SessionId::new(value).map_err(|_| service_unavailable(context))
}

fn validation_error(context: &RequestContext, reason: &str, message: &str) -> ApiError {
    domain_error(context, ApiErrorCode::ValidationFailed, reason, message)
}

fn authentication_error(context: &RequestContext, reason: &str, message: &str) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::AuthenticationRequired,
        reason,
        message,
    )
}

pub(crate) async fn enforce_rate_limit(
    state: &Arc<AppState>,
    context: &RequestContext,
    bucket: &str,
    limit: i64,
) -> Result<(), ApiError> {
    let database = database(state, context)?;
    let key = sha256_hex(bucket)
        .await
        .map_err(|_| service_unavailable(context))?;
    let expires_at =
        add_seconds(&context.received_at, 15 * 60).map_err(|_| service_unavailable(context))?;
    if IdentityRepository::new(database)
        .allow_auth_attempt(&key, &context.received_at, &expires_at, limit)
        .await
        .map_err(|error| database_error(context, error))?
    {
        Ok(())
    } else {
        Err(domain_error(
            context,
            ApiErrorCode::RateLimited,
            "rate_limited",
            "Too many attempts. Try again later.",
        ))
    }
}

fn service_unavailable(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::ServiceUnavailable,
        "The identity store is unavailable.",
    )
}
