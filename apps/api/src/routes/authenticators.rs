use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{Extension, Path, State},
    http::{HeaderMap, Response, StatusCode},
    response::IntoResponse,
};
use passkey_auth::{
    AuthenticationState, PasskeyCredential as VerifierCredential, RegistrationState,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::{
        add_seconds, deliver_auth_code, new_resource_id, new_secret,
        password::{self, DUMMY_PASSWORD_HASH},
        sha256_hex,
        webauthn::{
            AdapterError, AuthenticationResponse, RegistrationResponse, WebAuthnAdapter,
            WebAuthnFailure, user_handle_matches,
        },
    },
    app::AppState,
    core::{ApiError, ApiErrorCode, Principal, RequestContext},
    http::auth::{require_csrf, require_session, set_session_cookies},
    modules::{
        authenticators::{
            self, CeremonyStatus, CounterAssessment, PasskeyCredential, WebAuthnCeremonyKind,
            assess_counter, can_revoke_passkey, validate_password,
        },
        identity::NormalizedEmail,
    },
    repositories::{
        AuthenticatorRepository, IdentityRepository, PasskeyRecord, SecurityEventInput,
        SecurityEventRepository, UserRecord,
    },
    routes::{
        account::ReauthResponse,
        auth::{
            self, ChallengeResponse, EmptyRequest, UserResponse, create_session_with_statements,
        },
        errors,
        support::{database, database_error, domain_error, is_development, secure_cookie},
    },
};

const CEREMONY_TTL_SECONDS: u32 = 5 * 60;
const RECOVERY_TTL_SECONDS: u32 = 15 * 60;
const MAX_LABEL_CHARS: usize = 120;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeySignupStartRequest {
    pub email: String,
    pub display_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyCompleteRequest {
    pub ceremony_id: String,
    pub credential: RegistrationResponse,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyLoginCompleteRequest {
    pub ceremony_id: String,
    pub credential: AuthenticationResponse,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordSignupRequest {
    pub email: String,
    pub display_name: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordLoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordForgotRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordResetRequest {
    pub challenge_id: String,
    pub code: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReauthCredentialRequest {
    pub reauth_grant_id: String,
    pub reauth_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyAddStartRequest {
    pub label: String,
    pub reauth_grant_id: String,
    pub reauth_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyLabelRequest {
    pub label: String,
    pub reauth_grant_id: String,
    pub reauth_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordAccountRequest {
    pub password: String,
    pub reauth_grant_id: String,
    pub reauth_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReauthStartRequest {
    pub purpose: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReauthPasswordRequest {
    pub purpose: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct CeremonyStartResponse {
    pub ceremony_id: String,
    pub expires_at: String,
    pub public_key: Value,
}

#[derive(Debug, Serialize)]
pub struct PasskeySummary {
    pub passkey_id: String,
    pub label: String,
    pub transports: Vec<String>,
    pub backup_eligible: Option<bool>,
    pub backup_state: Option<bool>,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PasskeyListResponse {
    pub items: Vec<PasskeySummary>,
    pub password_configured: bool,
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct PageResponse<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
pub struct PasswordStatusResponse {
    pub configured: bool,
}

#[derive(Debug, Serialize)]
struct RecoveryStartResponse {
    pub challenge_id: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub development_code: Option<String>,
}

#[derive(Debug, Serialize)]
struct ReauthCompleteResponse {
    pub grant: ReauthResponse,
}

#[worker::send]
pub async fn passkey_signup_start(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    Json(body): Json<PasskeySignupStartRequest>,
) -> Result<Response<Body>, ApiError> {
    let database = database(&state, &context)?;
    let email = NormalizedEmail::parse(&body.email)
        .map_err(|_| validation_error(&context, "email_invalid", "Enter a valid email address."))?;
    let display_name = crate::modules::identity::validate_display_name(&body.display_name)
        .map_err(|_| validation_error(&context, "display_name_invalid", "Enter a valid name."))?;
    auth::enforce_rate_limit(
        &state,
        &context,
        &format!("passkey-signup:{}", email.as_str()),
        5,
    )
    .await?;
    if IdentityRepository::new(database)
        .find_user_by_email(email.as_str())
        .await
        .map_err(|error| database_error(&context, error))?
        .is_some()
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "identity_conflict",
            "An account with this email already exists.",
        ));
    }
    let adapter = webauthn_adapter(&state, &context)?;
    let pending_user_id = generated_id("usr");
    let ceremony_id = generated_id("cer");
    let (public_key, ceremony_state) = adapter
        .start_registration(
            pending_user_id.as_bytes(),
            email.as_str(),
            &display_name,
            &[],
        )
        .map_err(|error| passkey_error(&context, error))?;
    let state_json =
        serde_json::to_string(&ceremony_state).map_err(|_| service_unavailable(&context))?;
    let expires_at = add_seconds(&context.received_at, CEREMONY_TTL_SECONDS)
        .map_err(|_| service_unavailable(&context))?;
    let statement = AuthenticatorRepository::new(database)
        .insert_ceremony_statement(
            &ceremony_id,
            WebAuthnCeremonyKind::PasskeySignup,
            None,
            Some(&pending_user_id),
            Some(email.as_str()),
            Some(&display_name),
            None,
            &state_json,
            &expires_at,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    database
        .batch(vec![statement])
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok((
        StatusCode::CREATED,
        Json(CeremonyStartResponse {
            ceremony_id,
            expires_at: expires_at.as_str().to_owned(),
            public_key,
        }),
    )
        .into_response())
}

#[worker::send]
pub async fn passkey_signup_complete(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<PasskeyCompleteRequest>,
) -> Result<Response<Body>, ApiError> {
    let database = database(&state, &context)?;
    let repository = AuthenticatorRepository::new(database);
    let ceremony = repository
        .find_ceremony(&body.ceremony_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| ceremony_invalid(&context))?;
    ensure_pending(&ceremony, WebAuthnCeremonyKind::PasskeySignup, &context)?;
    let pending_user_id = ceremony
        .pending_user_id
        .as_deref()
        .ok_or_else(|| ceremony_invalid(&context))?;
    let email = ceremony
        .email
        .as_deref()
        .ok_or_else(|| ceremony_invalid(&context))?;
    let display_name = ceremony
        .display_name
        .as_deref()
        .ok_or_else(|| ceremony_invalid(&context))?;
    let state_json: RegistrationState =
        serde_json::from_str(&ceremony.state_json).map_err(|_| ceremony_invalid(&context))?;
    let adapter = webauthn_adapter(&state, &context)?;
    let verified = match adapter.finish_registration(&state_json, &body.credential) {
        Ok(value) => value,
        Err(error) => {
            let _ = repository
                .record_failed_ceremony(&ceremony.ceremony_id)
                .await;
            return Err(passkey_error(&context, error));
        }
    };
    if repository
        .find_passkey_by_credential(&verified.credential_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .is_some()
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "credential_conflict",
            "This authenticator is already registered.",
        ));
    }
    if IdentityRepository::new(database)
        .find_user_by_email(email)
        .await
        .map_err(|error| database_error(&context, error))?
        .is_some()
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "identity_conflict",
            "An account with this email already exists.",
        ));
    }
    if !repository
        .consume_ceremony(
            &ceremony.ceremony_id,
            WebAuthnCeremonyKind::PasskeySignup,
            &context.received_at,
        )
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Err(ceremony_invalid(&context));
    }

    let identity_id = generated_id("idn");
    let passkey_id = generated_id("psk");
    let verification_challenge_id = generated_id("idn");
    let verification_code = new_secret();
    let verification_hash = sha256_hex(&verification_code)
        .await
        .map_err(|_| service_unavailable(&context))?;
    let verification_expiry = add_seconds(&context.received_at, CEREMONY_TTL_SECONDS)
        .map_err(|_| service_unavailable(&context))?;
    let user = UserRecord {
        user_id: pending_user_id.to_owned(),
        email: email.to_owned(),
        display_name: display_name.to_owned(),
        email_verified: false,
        version: 1,
        created_at: context.received_at.as_str().to_owned(),
        updated_at: context.received_at.as_str().to_owned(),
    };
    let identity = IdentityRepository::new(database);
    let mut statements = vec![
        identity
            .insert_user_statement(
                &user.user_id,
                &user.email,
                &user.display_name,
                &context.received_at,
            )
            .map_err(|error| database_error(&context, error))?,
        identity
            .insert_identity_statement(
                &identity_id,
                &user.user_id,
                &user.email,
                &context.received_at,
            )
            .map_err(|error| database_error(&context, error))?,
        identity
            .insert_challenge_statement(
                &verification_challenge_id,
                Some(&user.user_id),
                &user.email,
                "verification",
                &verification_hash,
                &verification_expiry,
                &context.received_at,
            )
            .map_err(|error| database_error(&context, error))?,
        repository
            .insert_passkey_statement(
                &passkey_id,
                &user.user_id,
                &verified.credential_id,
                &verified.public_key_cose,
                verified.sign_count,
                &verified.transports,
                None,
                None,
                "Passkey",
                &context.received_at,
            )
            .map_err(|error| database_error(&context, error))?,
    ];
    let identity_event_id = generated_id("sec");
    statements.push(user_event_statement(
        database,
        &context,
        Some(&user.user_id),
        None,
        &identity_event_id,
        "identity.created.v1",
        "user",
        Some(&user.user_id),
        "success",
        json!({ "provider": "email", "method": "passkey" }),
    )?);
    let passkey_event_id = generated_id("sec");
    statements.push(user_event_statement(
        database,
        &context,
        Some(&user.user_id),
        None,
        &passkey_event_id,
        authenticators::PASSKEY_EVENT_REGISTERED,
        "passkey",
        Some(&passkey_id),
        "success",
        json!({ "method": "passkey" }),
    )?);
    let (_response, session_token, csrf_token) = create_session_with_statements(
        &state,
        &context,
        database,
        &identity,
        &user,
        &headers,
        "auth.login.completed.v1",
        None,
        statements,
    )
    .await?;
    deliver_auth_code(&state, &user.email, &verification_code, "verification")
        .await
        .map_err(|_| service_unavailable(&context))?;
    let mut response = Json(UserResponse {
        user: user_json(&user),
        verification: Some(ChallengeResponse {
            challenge_id: verification_challenge_id,
            expires_at: verification_expiry.as_str().to_owned(),
            development_code: is_development(&state).then_some(verification_code),
        }),
    })
    .into_response();
    set_session_cookies(
        &mut response,
        &session_token,
        &csrf_token,
        secure_cookie(&state),
    );
    Ok(response)
}

#[worker::send]
pub async fn passkey_login_start(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    Json(_body): Json<EmptyRequest>,
) -> Result<Response<Body>, ApiError> {
    let database = database(&state, &context)?;
    auth::enforce_rate_limit(&state, &context, "passkey-login-start", 60).await?;
    let adapter = webauthn_adapter(&state, &context)?;
    let (public_key, ceremony_state) = adapter
        .start_authentication(&[])
        .map_err(|error| passkey_error(&context, error))?;
    let ceremony_id = generated_id("cer");
    let expires_at = add_seconds(&context.received_at, CEREMONY_TTL_SECONDS)
        .map_err(|_| service_unavailable(&context))?;
    let state_json =
        serde_json::to_string(&ceremony_state).map_err(|_| service_unavailable(&context))?;
    AuthenticatorRepository::new(database)
        .insert_ceremony_statement(
            &ceremony_id,
            WebAuthnCeremonyKind::PasskeyLogin,
            None,
            None,
            None,
            None,
            None,
            &state_json,
            &expires_at,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?
        .run()
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok((
        StatusCode::CREATED,
        Json(CeremonyStartResponse {
            ceremony_id,
            expires_at: expires_at.as_str().to_owned(),
            public_key,
        }),
    )
        .into_response())
}

#[worker::send]
pub async fn passkey_login_complete(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<PasskeyLoginCompleteRequest>,
) -> Result<Response<Body>, ApiError> {
    let database = database(&state, &context)?;
    auth::enforce_rate_limit(&state, &context, "passkey-login-complete", 30).await?;
    let repository = AuthenticatorRepository::new(database);
    let ceremony = repository
        .find_ceremony(&body.ceremony_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| ceremony_invalid(&context))?;
    ensure_pending(&ceremony, WebAuthnCeremonyKind::PasskeyLogin, &context)?;
    let state_json: AuthenticationState =
        serde_json::from_str(&ceremony.state_json).map_err(|_| ceremony_invalid(&context))?;
    let stored = repository
        .find_passkey_by_credential(&body.credential.id)
        .await
        .map_err(|error| database_error(&context, error))?
        .filter(|record| record.revoked_at.is_none())
        .ok_or_else(|| ceremony_invalid(&context))?;
    if !user_handle_matches(body.credential.user_handle.as_deref(), &stored.user_id) {
        return Err(ceremony_invalid(&context));
    }
    let adapter = webauthn_adapter(&state, &context)?;
    let verifier_credential = adapter
        .verifier_credential(
            &stored.credential_id,
            &stored.public_key_cose,
            stored.sign_count,
            stored.transports.clone(),
        )
        .map_err(|error| passkey_error(&context, error))?;
    let verified =
        match adapter.finish_authentication(&state_json, &body.credential, &verifier_credential) {
            Ok(value) => value,
            Err(error) => {
                if error.0 == WebAuthnFailure::CounterRegression {
                    record_authenticator_event(
                        database,
                        &context,
                        Some(&stored.user_id),
                        None,
                        authenticators::PASSKEY_EVENT_SUSPICIOUS_COUNTER,
                        "passkey",
                        Some(&stored.passkey_id),
                        json!({ "method": "passkey" }),
                    )
                    .await;
                }
                let _ = repository
                    .record_failed_ceremony(&ceremony.ceremony_id)
                    .await;
                return Err(passkey_error(&context, error));
            }
        };
    if assess_counter(stored.sign_count.max(0) as u32, verified.new_counter)
        == CounterAssessment::SuspiciousPositiveRegression
    {
        return Err(passkey_error(
            &context,
            AdapterError(WebAuthnFailure::CounterRegression),
        ));
    }
    if !repository
        .consume_ceremony(
            &ceremony.ceremony_id,
            WebAuthnCeremonyKind::PasskeyLogin,
            &context.received_at,
        )
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Err(ceremony_invalid(&context));
    }
    let user = IdentityRepository::new(database)
        .find_user_by_id(&stored.user_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| service_unavailable(&context))?;
    let counter_statement = repository
        .update_passkey_counter_statement(
            &stored.user_id,
            &stored.credential_id,
            i64::from(verified.new_counter),
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let event_id = generated_id("sec");
    let auth_event = user_event_statement(
        database,
        &context,
        Some(&user.user_id),
        None,
        &event_id,
        authenticators::PASSKEY_EVENT_AUTHENTICATED,
        "passkey",
        Some(&stored.passkey_id),
        "success",
        json!({ "method": "passkey" }),
    )?;
    let identity = IdentityRepository::new(database);
    let (response, session_token, csrf_token) = create_session_with_statements(
        &state,
        &context,
        database,
        &identity,
        &user,
        &headers,
        "auth.login.completed.v1",
        None,
        vec![counter_statement, auth_event],
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
pub async fn password_signup(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<PasswordSignupRequest>,
) -> Result<Response<Body>, ApiError> {
    let database = database(&state, &context)?;
    let email = NormalizedEmail::parse(&body.email)
        .map_err(|_| validation_error(&context, "email_invalid", "Enter a valid email address."))?;
    let display_name = crate::modules::identity::validate_display_name(&body.display_name)
        .map_err(|_| validation_error(&context, "display_name_invalid", "Enter a valid name."))?;
    validate_password(&body.password)
        .map_err(|_| validation_error(&context, "password_invalid", "Choose a longer password."))?;
    auth::enforce_rate_limit(
        &state,
        &context,
        &format!("password-signup:{}", email.as_str()),
        5,
    )
    .await?;
    if IdentityRepository::new(database)
        .find_user_by_email(email.as_str())
        .await
        .map_err(|error| database_error(&context, error))?
        .is_some()
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "identity_conflict",
            "An account with this email already exists.",
        ));
    }
    let encoded_hash =
        password::hash_password(&body.password).map_err(|_| service_unavailable(&context))?;
    let (algorithm, memory_kib, time_cost, parallelism) =
        password::algorithm_metadata(&encoded_hash);
    let user_id = generated_id("usr");
    let identity_id = generated_id("idn");
    let verification_challenge_id = generated_id("idn");
    let verification_code = new_secret();
    let verification_hash = sha256_hex(&verification_code)
        .await
        .map_err(|_| service_unavailable(&context))?;
    let verification_expiry = add_seconds(&context.received_at, CEREMONY_TTL_SECONDS)
        .map_err(|_| service_unavailable(&context))?;
    let user = UserRecord {
        user_id: user_id.clone(),
        email: email.as_str().to_owned(),
        display_name: display_name.clone(),
        email_verified: false,
        version: 1,
        created_at: context.received_at.as_str().to_owned(),
        updated_at: context.received_at.as_str().to_owned(),
    };
    let identity = IdentityRepository::new(database);
    let authenticators = AuthenticatorRepository::new(database);
    let mut statements = vec![
        identity
            .insert_user_statement(
                &user.user_id,
                &user.email,
                &user.display_name,
                &context.received_at,
            )
            .map_err(|error| database_error(&context, error))?,
        identity
            .insert_identity_statement(
                &identity_id,
                &user.user_id,
                &user.email,
                &context.received_at,
            )
            .map_err(|error| database_error(&context, error))?,
        identity
            .insert_challenge_statement(
                &verification_challenge_id,
                Some(&user.user_id),
                &user.email,
                "verification",
                &verification_hash,
                &verification_expiry,
                &context.received_at,
            )
            .map_err(|error| database_error(&context, error))?,
        authenticators
            .insert_password_statement(
                &user.user_id,
                &encoded_hash,
                &algorithm,
                memory_kib,
                time_cost,
                parallelism,
                &context.received_at,
            )
            .map_err(|error| database_error(&context, error))?,
    ];
    let identity_event_id = generated_id("sec");
    statements.push(user_event_statement(
        database,
        &context,
        Some(&user.user_id),
        None,
        &identity_event_id,
        "identity.created.v1",
        "user",
        Some(&user.user_id),
        "success",
        json!({ "provider": "email", "method": "password" }),
    )?);
    let password_event_id = generated_id("sec");
    statements.push(user_event_statement(
        database,
        &context,
        Some(&user.user_id),
        None,
        &password_event_id,
        authenticators::PASSWORD_EVENT_CONFIGURED,
        "password",
        Some(&user.user_id),
        "success",
        json!({ "method": "password" }),
    )?);
    let (_response, session_token, csrf_token) = create_session_with_statements(
        &state,
        &context,
        database,
        &identity,
        &user,
        &headers,
        "auth.login.completed.v1",
        None,
        statements,
    )
    .await?;
    deliver_auth_code(&state, &user.email, &verification_code, "verification")
        .await
        .map_err(|_| service_unavailable(&context))?;
    let mut response = Json(UserResponse {
        user: user_json(&user),
        verification: Some(ChallengeResponse {
            challenge_id: verification_challenge_id,
            expires_at: verification_expiry.as_str().to_owned(),
            development_code: is_development(&state).then_some(verification_code),
        }),
    })
    .into_response();
    set_session_cookies(
        &mut response,
        &session_token,
        &csrf_token,
        secure_cookie(&state),
    );
    Ok(response)
}

#[worker::send]
pub async fn password_login(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<PasswordLoginRequest>,
) -> Result<Response<Body>, ApiError> {
    let database = database(&state, &context)?;
    let email = NormalizedEmail::parse(&body.email)
        .map_err(|_| validation_error(&context, "email_invalid", "Enter a valid email address."))?;
    validate_password(&body.password).map_err(|_| generic_password_failure(&context))?;
    auth::enforce_rate_limit(
        &state,
        &context,
        &format!("password-login:{}", email.as_str()),
        10,
    )
    .await?;
    let identity = IdentityRepository::new(database);
    let user = identity
        .find_user_by_email(email.as_str())
        .await
        .map_err(|error| database_error(&context, error))?;
    let credential = if let Some(user) = user.as_ref() {
        AuthenticatorRepository::new(database)
            .find_password(&user.user_id)
            .await
            .map_err(|error| database_error(&context, error))?
    } else {
        None
    };
    let valid = credential
        .as_ref()
        .is_some_and(|record| password::verify_password(&record.encoded_hash, &body.password));
    if !valid {
        if credential.is_none() {
            let _ = password::verify_password(DUMMY_PASSWORD_HASH, &body.password);
        }
        return Err(generic_password_failure(&context));
    }
    let user = user.ok_or_else(|| generic_password_failure(&context))?;
    let credential = credential.ok_or_else(|| generic_password_failure(&context))?;
    let mut extra = Vec::new();
    if password::needs_rehash(&credential.encoded_hash) {
        let replacement =
            password::hash_password(&body.password).map_err(|_| service_unavailable(&context))?;
        let (algorithm, memory_kib, time_cost, parallelism) =
            password::algorithm_metadata(&replacement);
        let event_id = generated_id("sec");
        extra.push(
            AuthenticatorRepository::new(database)
                .upsert_password_statement(
                    &user.user_id,
                    &replacement,
                    &algorithm,
                    memory_kib,
                    time_cost,
                    parallelism,
                    &context.received_at,
                )
                .map_err(|error| database_error(&context, error))?,
        );
        extra.push(user_event_statement(
            database,
            &context,
            Some(&user.user_id),
            None,
            &event_id,
            authenticators::PASSWORD_EVENT_CHANGED,
            "password",
            Some(&user.user_id),
            "success",
            json!({ "reason": "rehash" }),
        )?);
    }
    let (mut response, session_token, csrf_token) = create_session_with_statements(
        &state,
        &context,
        database,
        &identity,
        &user,
        &headers,
        "auth.login.completed.v1",
        None,
        extra,
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
pub async fn password_forgot(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    Json(body): Json<PasswordForgotRequest>,
) -> Result<Response<Body>, ApiError> {
    let database = database(&state, &context)?;
    let email = NormalizedEmail::parse(&body.email)
        .map_err(|_| validation_error(&context, "email_invalid", "Enter a valid email address."))?;
    auth::enforce_rate_limit(
        &state,
        &context,
        &format!("password-forgot:{}", email.as_str()),
        5,
    )
    .await?;
    let user = IdentityRepository::new(database)
        .find_user_by_email(email.as_str())
        .await
        .map_err(|error| database_error(&context, error))?
        .filter(|user| user.email_verified);
    let challenge_id = generated_id("rec");
    let code = new_secret();
    let code_hash = sha256_hex(&code)
        .await
        .map_err(|_| service_unavailable(&context))?;
    let expires_at = add_seconds(&context.received_at, RECOVERY_TTL_SECONDS)
        .map_err(|_| service_unavailable(&context))?;
    AuthenticatorRepository::new(database)
        .insert_recovery_statement(
            &challenge_id,
            user.as_ref().map(|user| user.user_id.as_str()),
            email.as_str(),
            &code_hash,
            &expires_at,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?
        .run()
        .await
        .map_err(|error| database_error(&context, error))?;
    if let Some(user) = user.as_ref() {
        deliver_auth_code(&state, &user.email, &code, "password_reset")
            .await
            .map_err(|_| service_unavailable(&context))?;
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(RecoveryStartResponse {
            challenge_id,
            expires_at: expires_at.as_str().to_owned(),
            development_code: (is_development(&state) && user.is_some()).then_some(code),
        }),
    )
        .into_response())
}

#[worker::send]
pub async fn password_reset(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    Json(body): Json<PasswordResetRequest>,
) -> Result<Response<Body>, ApiError> {
    let database = database(&state, &context)?;
    validate_password(&body.password)
        .map_err(|_| validation_error(&context, "password_invalid", "Choose a longer password."))?;
    auth::enforce_rate_limit(&state, &context, "password-reset", 10).await?;
    let repository = AuthenticatorRepository::new(database);
    let challenge = repository
        .find_recovery(&body.challenge_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| generic_recovery_failure(&context))?;
    if challenge.status != "pending"
        || challenge.expires_at.as_str() <= context.received_at.as_str()
    {
        return Err(generic_recovery_failure(&context));
    }
    let code_hash = sha256_hex(&body.code)
        .await
        .map_err(|_| service_unavailable(&context))?;
    if !repository
        .consume_recovery(&body.challenge_id, &code_hash, &context.received_at)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        let _ = repository.record_failed_recovery(&body.challenge_id).await;
        return Err(generic_recovery_failure(&context));
    }
    let Some(user_id) = challenge.user_id.as_deref() else {
        return Err(generic_recovery_failure(&context));
    };
    let encoded_hash =
        password::hash_password(&body.password).map_err(|_| service_unavailable(&context))?;
    let (algorithm, memory_kib, time_cost, parallelism) =
        password::algorithm_metadata(&encoded_hash);
    let user = IdentityRepository::new(database)
        .find_user_by_id(user_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| generic_recovery_failure(&context))?;
    let password_statement = repository
        .upsert_password_statement(
            &user.user_id,
            &encoded_hash,
            &algorithm,
            memory_kib,
            time_cost,
            parallelism,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let revoke_sessions = IdentityRepository::new(database)
        .revoke_user_sessions_statement(&user.user_id, &context.received_at)
        .map_err(|error| database_error(&context, error))?;
    let reset_event_id = generated_id("sec");
    let recovery_event_id = generated_id("sec");
    let reset_event = user_event_statement(
        database,
        &context,
        Some(&user.user_id),
        None,
        &reset_event_id,
        authenticators::PASSWORD_EVENT_RESET,
        "password",
        Some(&user.user_id),
        "success",
        json!({ "method": "recovery" }),
    )?;
    let recovery_event = user_event_statement(
        database,
        &context,
        Some(&user.user_id),
        None,
        &recovery_event_id,
        authenticators::RECOVERY_EVENT_COMPLETED,
        "account",
        Some(&user.user_id),
        "success",
        json!({ "method": "password" }),
    )?;
    database
        .batch(vec![
            password_statement,
            revoke_sessions,
            reset_event,
            recovery_event,
        ])
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[worker::send]
pub async fn list_passkeys(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    let database = database(&state, &context)?;
    let repository = AuthenticatorRepository::new(database);
    let records = repository
        .list_passkeys(authenticated.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?;
    let password_configured = repository
        .find_password(authenticated.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?
        .is_some();
    let items = records.iter().map(PasskeySummary::from).collect();
    Ok(Json(PasskeyListResponse {
        items,
        password_configured,
    })
    .into_response())
}

#[worker::send]
pub async fn passkey_add_start(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<PasskeyAddStartRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    let label = validate_label(&body.label, &context)?;
    let database = database(&state, &context)?;
    let repository = AuthenticatorRepository::new(database);
    consume_reauth_grant(
        database,
        &context,
        &authenticated.principal,
        &body.reauth_grant_id,
        &body.reauth_token,
        "passkey_management",
    )
    .await?;
    let user = IdentityRepository::new(database)
        .find_user_by_id(authenticated.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| service_unavailable(&context))?;
    let records = repository
        .list_passkeys(authenticated.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?;
    let adapter = webauthn_adapter(&state, &context)?;
    let excluded_ids = records
        .iter()
        .map(|record| record.credential_id.clone())
        .collect::<Vec<_>>();
    let (public_key, ceremony_state) = adapter
        .start_registration(
            authenticated.principal.user_id.as_str().as_bytes(),
            &user.email,
            &user.display_name,
            &excluded_ids,
        )
        .map_err(|error| passkey_error(&context, error))?;
    let ceremony_id = generated_id("cer");
    let expires_at = add_seconds(&context.received_at, CEREMONY_TTL_SECONDS)
        .map_err(|_| service_unavailable(&context))?;
    let state_json =
        serde_json::to_string(&ceremony_state).map_err(|_| service_unavailable(&context))?;
    repository
        .insert_ceremony_statement(
            &ceremony_id,
            WebAuthnCeremonyKind::PasskeyAdd,
            Some(authenticated.principal.user_id.as_str()),
            None,
            None,
            Some(&label),
            Some(authenticated.principal.session_id.as_str()),
            &state_json,
            &expires_at,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?
        .run()
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok((
        StatusCode::CREATED,
        Json(CeremonyStartResponse {
            ceremony_id,
            expires_at: expires_at.as_str().to_owned(),
            public_key,
        }),
    )
        .into_response())
}

#[worker::send]
pub async fn passkey_add_complete(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<PasskeyCompleteRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    let database = database(&state, &context)?;
    let repository = AuthenticatorRepository::new(database);
    let ceremony = repository
        .find_ceremony(&body.ceremony_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| ceremony_invalid(&context))?;
    ensure_pending(&ceremony, WebAuthnCeremonyKind::PasskeyAdd, &context)?;
    if ceremony.user_id.as_deref() != Some(authenticated.principal.user_id.as_str())
        || ceremony.session_id.as_deref() != Some(authenticated.principal.session_id.as_str())
    {
        return Err(ceremony_invalid(&context));
    }
    let state_json: RegistrationState =
        serde_json::from_str(&ceremony.state_json).map_err(|_| ceremony_invalid(&context))?;
    let adapter = webauthn_adapter(&state, &context)?;
    let verified = match adapter.finish_registration(&state_json, &body.credential) {
        Ok(value) => value,
        Err(error) => {
            let _ = repository
                .record_failed_ceremony(&ceremony.ceremony_id)
                .await;
            return Err(passkey_error(&context, error));
        }
    };
    if repository
        .find_passkey_by_credential(&verified.credential_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .is_some()
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "credential_conflict",
            "This authenticator is already registered.",
        ));
    }
    if !repository
        .consume_ceremony(
            &ceremony.ceremony_id,
            WebAuthnCeremonyKind::PasskeyAdd,
            &context.received_at,
        )
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Err(ceremony_invalid(&context));
    }
    let passkey_id = generated_id("psk");
    let label = ceremony.display_name.as_deref().unwrap_or("Passkey");
    let passkey_statement = repository
        .insert_passkey_statement(
            &passkey_id,
            authenticated.principal.user_id.as_str(),
            &verified.credential_id,
            &verified.public_key_cose,
            verified.sign_count,
            &verified.transports,
            None,
            None,
            label,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let event_id = generated_id("sec");
    let event = user_event_statement(
        database,
        &context,
        Some(authenticated.principal.user_id.as_str()),
        Some(authenticated.principal.session_id.as_str()),
        &event_id,
        authenticators::PASSKEY_EVENT_REGISTERED,
        "passkey",
        Some(&passkey_id),
        "success",
        json!({ "method": "passkey" }),
    )?;
    database
        .batch(vec![passkey_statement, event])
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "passkey_id": passkey_id })),
    )
        .into_response())
}

#[worker::send]
pub async fn revoke_passkey(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(passkey_id): Path<String>,
    Json(body): Json<ReauthCredentialRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    let database = database(&state, &context)?;
    let repository = AuthenticatorRepository::new(database);
    let target = repository
        .find_passkey(authenticated.principal.user_id.as_str(), &passkey_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .filter(|record| record.revoked_at.is_none())
        .ok_or_else(|| resource_not_found(&context))?;
    let active_count = repository
        .active_passkey_count(authenticated.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?;
    let password_configured = repository
        .find_password(authenticated.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?
        .is_some();
    let target_domain: PasskeyCredential = target.clone().into();
    if !can_revoke_passkey(&target_domain, active_count as usize, password_configured) {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "last_login_method_required",
            "Add another passkey or configure a password before removing this one.",
        ));
    }
    consume_reauth_grant(
        database,
        &context,
        &authenticated.principal,
        &body.reauth_grant_id,
        &body.reauth_token,
        "passkey_management",
    )
    .await?;
    if !repository
        .revoke_passkey(
            authenticated.principal.user_id.as_str(),
            &passkey_id,
            &context.received_at,
        )
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Err(resource_not_found(&context));
    }
    let event_id = generated_id("sec");
    let event = user_event_statement(
        database,
        &context,
        Some(authenticated.principal.user_id.as_str()),
        Some(authenticated.principal.session_id.as_str()),
        &event_id,
        authenticators::PASSKEY_EVENT_REVOKED,
        "passkey",
        Some(&passkey_id),
        "success",
        json!({ "method": "passkey" }),
    )?;
    database
        .batch(vec![event])
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[worker::send]
pub async fn rename_passkey(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(passkey_id): Path<String>,
    Json(body): Json<PasskeyLabelRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    let label = validate_label(&body.label, &context)?;
    let database = database(&state, &context)?;
    let repository = AuthenticatorRepository::new(database);
    let record = repository
        .find_passkey(authenticated.principal.user_id.as_str(), &passkey_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .filter(|record| record.revoked_at.is_none())
        .ok_or_else(|| resource_not_found(&context))?;
    consume_reauth_grant(
        database,
        &context,
        &authenticated.principal,
        &body.reauth_grant_id,
        &body.reauth_token,
        "passkey_management",
    )
    .await?;
    let update = repository
        .update_passkey_label_statement(
            authenticated.principal.user_id.as_str(),
            &record.passkey_id,
            &label,
        )
        .map_err(|error| database_error(&context, error))?;
    database
        .batch(vec![update])
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(Json(json!({ "passkey_id": passkey_id, "label": label })).into_response())
}

#[worker::send]
pub async fn password_status(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    let database = database(&state, &context)?;
    let configured = AuthenticatorRepository::new(database)
        .find_password(authenticated.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?
        .is_some();
    Ok(Json(PasswordStatusResponse { configured }).into_response())
}

#[worker::send]
pub async fn set_account_password(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<PasswordAccountRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    validate_password(&body.password)
        .map_err(|_| validation_error(&context, "password_invalid", "Choose a longer password."))?;
    let database = database(&state, &context)?;
    let existing = AuthenticatorRepository::new(database)
        .find_password(authenticated.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?;
    consume_reauth_grant(
        database,
        &context,
        &authenticated.principal,
        &body.reauth_grant_id,
        &body.reauth_token,
        "password_change",
    )
    .await?;
    let encoded_hash =
        password::hash_password(&body.password).map_err(|_| service_unavailable(&context))?;
    let (algorithm, memory_kib, time_cost, parallelism) =
        password::algorithm_metadata(&encoded_hash);
    let event_id = generated_id("sec");
    let action = if existing.is_some() {
        authenticators::PASSWORD_EVENT_CHANGED
    } else {
        authenticators::PASSWORD_EVENT_CONFIGURED
    };
    let statement = AuthenticatorRepository::new(database)
        .upsert_password_statement(
            authenticated.principal.user_id.as_str(),
            &encoded_hash,
            &algorithm,
            memory_kib,
            time_cost,
            parallelism,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let event = user_event_statement(
        database,
        &context,
        Some(authenticated.principal.user_id.as_str()),
        Some(authenticated.principal.session_id.as_str()),
        &event_id,
        action,
        "password",
        Some(authenticated.principal.user_id.as_str()),
        "success",
        json!({ "method": "password" }),
    )?;
    let revoke_others = IdentityRepository::new(database)
        .revoke_all_other_sessions_statement(
            authenticated.principal.user_id.as_str(),
            authenticated.principal.session_id.as_str(),
            &context.received_at,
            "password_changed",
        )
        .map_err(|error| database_error(&context, error))?;
    database
        .batch(vec![statement, event, revoke_others])
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[worker::send]
pub async fn reauth_passkey_start(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<ReauthStartRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    validate_reauth_purpose(&body.purpose, &context)?;
    let database = database(&state, &context)?;
    let records = AuthenticatorRepository::new(database)
        .list_passkeys(authenticated.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?;
    if records.is_empty() {
        return Err(domain_error(
            &context,
            ApiErrorCode::PermissionDenied,
            "password_fallback_required",
            "Use your password to complete this security check.",
        ));
    }
    let adapter = webauthn_adapter(&state, &context)?;
    let credentials = verifier_credentials(adapter, &records, &context)?;
    let (public_key, ceremony_state) = adapter
        .start_authentication(&credentials)
        .map_err(|error| passkey_error(&context, error))?;
    let ceremony_id = generated_id("cer");
    let expires_at = add_seconds(&context.received_at, CEREMONY_TTL_SECONDS)
        .map_err(|_| service_unavailable(&context))?;
    let state_json =
        serde_json::to_string(&ceremony_state).map_err(|_| service_unavailable(&context))?;
    AuthenticatorRepository::new(database)
        .insert_ceremony_statement(
            &ceremony_id,
            WebAuthnCeremonyKind::Reauthenticate,
            Some(authenticated.principal.user_id.as_str()),
            None,
            None,
            Some(&body.purpose),
            Some(authenticated.principal.session_id.as_str()),
            &state_json,
            &expires_at,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?
        .run()
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok((
        StatusCode::CREATED,
        Json(CeremonyStartResponse {
            ceremony_id,
            expires_at: expires_at.as_str().to_owned(),
            public_key,
        }),
    )
        .into_response())
}

#[worker::send]
pub async fn reauth_passkey_complete(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<PasskeyLoginCompleteRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    let database = database(&state, &context)?;
    let repository = AuthenticatorRepository::new(database);
    let ceremony = repository
        .find_ceremony(&body.ceremony_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| ceremony_invalid(&context))?;
    ensure_pending(&ceremony, WebAuthnCeremonyKind::Reauthenticate, &context)?;
    if ceremony.user_id.as_deref() != Some(authenticated.principal.user_id.as_str())
        || ceremony.session_id.as_deref() != Some(authenticated.principal.session_id.as_str())
    {
        return Err(ceremony_invalid(&context));
    }
    let purpose = ceremony
        .display_name
        .as_deref()
        .unwrap_or("passkey_management");
    validate_reauth_purpose(purpose, &context)?;
    let stored = repository
        .find_passkey_by_credential(&body.credential.id)
        .await
        .map_err(|error| database_error(&context, error))?
        .filter(|record| {
            record.revoked_at.is_none()
                && record.user_id == authenticated.principal.user_id.as_str()
        })
        .ok_or_else(|| ceremony_invalid(&context))?;
    if !user_handle_matches(body.credential.user_handle.as_deref(), &stored.user_id) {
        return Err(ceremony_invalid(&context));
    }
    let adapter = webauthn_adapter(&state, &context)?;
    let verifier = adapter
        .verifier_credential(
            &stored.credential_id,
            &stored.public_key_cose,
            stored.sign_count,
            stored.transports.clone(),
        )
        .map_err(|error| passkey_error(&context, error))?;
    let state_json: AuthenticationState =
        serde_json::from_str(&ceremony.state_json).map_err(|_| ceremony_invalid(&context))?;
    let verified = adapter
        .finish_authentication(&state_json, &body.credential, &verifier)
        .map_err(|error| passkey_error(&context, error))?;
    if assess_counter(stored.sign_count.max(0) as u32, verified.new_counter)
        == CounterAssessment::SuspiciousPositiveRegression
    {
        return Err(passkey_error(
            &context,
            AdapterError(WebAuthnFailure::CounterRegression),
        ));
    }
    if !repository
        .consume_ceremony(
            &ceremony.ceremony_id,
            WebAuthnCeremonyKind::Reauthenticate,
            &context.received_at,
        )
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Err(ceremony_invalid(&context));
    }
    let counter = repository
        .update_passkey_counter_statement(
            &stored.user_id,
            &stored.credential_id,
            i64::from(verified.new_counter),
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let event_id = generated_id("sec");
    let event = user_event_statement(
        database,
        &context,
        Some(authenticated.principal.user_id.as_str()),
        Some(authenticated.principal.session_id.as_str()),
        &event_id,
        authenticators::PASSKEY_EVENT_AUTHENTICATED,
        "passkey",
        Some(&stored.passkey_id),
        "success",
        json!({ "method": "passkey", "purpose": purpose }),
    )?;
    database
        .batch(vec![counter, event])
        .await
        .map_err(|error| database_error(&context, error))?;
    let grant = issue_reauth_grant(database, &context, &authenticated.principal, purpose).await?;
    Ok(Json(ReauthCompleteResponse { grant }).into_response())
}

#[worker::send]
pub async fn reauth_password(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<ReauthPasswordRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    validate_reauth_purpose(&body.purpose, &context)?;
    validate_password(&body.password).map_err(|_| generic_password_failure(&context))?;
    let database = database(&state, &context)?;
    let credential = AuthenticatorRepository::new(database)
        .find_password(authenticated.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?;
    let valid = credential
        .as_ref()
        .is_some_and(|record| password::verify_password(&record.encoded_hash, &body.password));
    if !valid {
        if credential.is_none() {
            let _ = password::verify_password(DUMMY_PASSWORD_HASH, &body.password);
        }
        return Err(generic_password_failure(&context));
    }
    let grant =
        issue_reauth_grant(database, &context, &authenticated.principal, &body.purpose).await?;
    Ok(Json(ReauthCompleteResponse { grant }).into_response())
}

impl From<&PasskeyRecord> for PasskeySummary {
    fn from(value: &PasskeyRecord) -> Self {
        Self {
            passkey_id: value.passkey_id.clone(),
            label: value.label.clone(),
            transports: value.transports.clone(),
            backup_eligible: value.backup_eligible,
            backup_state: value.backup_state,
            created_at: value.created_at.clone(),
            last_used_at: value.last_used_at.clone(),
        }
    }
}

fn webauthn_adapter<'a>(
    state: &'a Arc<AppState>,
    context: &RequestContext,
) -> Result<&'a WebAuthnAdapter, ApiError> {
    state
        .webauthn
        .as_ref()
        .ok_or_else(|| service_unavailable(context))
}

fn verifier_credentials(
    adapter: &WebAuthnAdapter,
    records: &[PasskeyRecord],
    context: &RequestContext,
) -> Result<Vec<VerifierCredential>, ApiError> {
    records
        .iter()
        .map(|record| {
            adapter
                .verifier_credential(
                    &record.credential_id,
                    &record.public_key_cose,
                    record.sign_count,
                    record.transports.clone(),
                )
                .map_err(|error| passkey_error(context, error))
        })
        .collect()
}

fn ensure_pending(
    ceremony: &crate::repositories::CeremonyRecord,
    kind: WebAuthnCeremonyKind,
    context: &RequestContext,
) -> Result<(), ApiError> {
    if ceremony.kind != kind.as_str()
        || ceremony.status != CeremonyStatus::Pending.as_str()
        || ceremony.expires_at.as_str() <= context.received_at.as_str()
    {
        return Err(ceremony_invalid(context));
    }
    Ok(())
}

async fn consume_reauth_grant(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    principal: &Principal,
    grant_id: &str,
    token: &str,
    purpose: &str,
) -> Result<(), ApiError> {
    let repository = IdentityRepository::new(database);
    let token_hash = sha256_hex(token)
        .await
        .map_err(|_| service_unavailable(context))?;
    if !repository
        .consume_reauth(
            grant_id,
            principal.user_id.as_str(),
            principal.session_id.as_str(),
            purpose,
            &token_hash,
            &context.received_at,
        )
        .await
        .map_err(|error| database_error(context, error))?
    {
        return Err(domain_error(
            context,
            ApiErrorCode::PermissionDenied,
            "reauthentication_required",
            "Complete a recent security check before continuing.",
        ));
    }
    Ok(())
}

async fn issue_reauth_grant(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    principal: &Principal,
    purpose: &str,
) -> Result<ReauthResponse, ApiError> {
    let grant_id = generated_id("rag");
    let token = new_secret();
    let token_hash = sha256_hex(&token)
        .await
        .map_err(|_| service_unavailable(context))?;
    let expires_at =
        add_seconds(&context.received_at, 5 * 60).map_err(|_| service_unavailable(context))?;
    let statement = IdentityRepository::new(database)
        .insert_reauth_statement(
            &grant_id,
            principal.user_id.as_str(),
            principal.session_id.as_str(),
            purpose,
            &token_hash,
            &expires_at,
            &context.received_at,
        )
        .map_err(|error| database_error(context, error))?;
    let event_id = generated_id("sec");
    let event = user_event_statement(
        database,
        context,
        Some(principal.user_id.as_str()),
        Some(principal.session_id.as_str()),
        &event_id,
        "reauthentication.granted.v1",
        "reauthentication_grant",
        Some(&grant_id),
        "success",
        json!({ "purpose": purpose }),
    )?;
    database
        .batch(vec![statement, event])
        .await
        .map_err(|error| database_error(context, error))?;
    Ok(ReauthResponse {
        grant_id,
        token,
        expires_at: expires_at.as_str().to_owned(),
    })
}

fn validate_reauth_purpose(purpose: &str, context: &RequestContext) -> Result<(), ApiError> {
    if matches!(
        purpose,
        "passkey_management" | "password_change" | "account_recovery"
    ) {
        Ok(())
    } else {
        Err(validation_error(
            context,
            "purpose_invalid",
            "Choose a supported security-check purpose.",
        ))
    }
}

fn validate_label(value: &str, context: &RequestContext) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty()
        || value.chars().count() > MAX_LABEL_CHARS
        || value.chars().any(char::is_control)
    {
        return Err(validation_error(
            context,
            "label_invalid",
            "Choose a shorter passkey label.",
        ));
    }
    Ok(value.to_owned())
}

#[allow(clippy::too_many_arguments, clippy::needless_lifetimes)]
fn user_event_statement(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    user_id: Option<&str>,
    session_id: Option<&str>,
    event_id: &str,
    action: &str,
    resource_type: &str,
    resource_id: Option<&str>,
    outcome: &str,
    metadata: Value,
) -> Result<D1PreparedStatement, ApiError> {
    let input = SecurityEventInput {
        event_id,
        organization_id: None,
        actor_type: if user_id.is_some() {
            "user"
        } else {
            "anonymous"
        },
        actor_id: user_id,
        effective_user_id: user_id,
        session_id,
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

#[allow(clippy::too_many_arguments)]
async fn record_authenticator_event(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    user_id: Option<&str>,
    session_id: Option<&str>,
    action: &str,
    resource_type: &str,
    resource_id: Option<&str>,
    metadata: Value,
) {
    let event_id = generated_id("sec");
    let Ok(statement) = user_event_statement(
        database,
        context,
        user_id,
        session_id,
        &event_id,
        action,
        resource_type,
        resource_id,
        "failure",
        metadata,
    ) else {
        return;
    };
    let _ = database.batch(vec![statement]).await;
}

fn passkey_error(context: &RequestContext, error: AdapterError) -> ApiError {
    let reason = error.0.as_str();
    domain_error(
        context,
        ApiErrorCode::AuthenticationRequired,
        reason,
        "Passkey verification failed. Start a new sign-in attempt and try again.",
    )
}

fn ceremony_invalid(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::AuthenticationRequired,
        "ceremony_invalid",
        "This security check is invalid or expired. Start again.",
    )
}

fn generic_password_failure(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::AuthenticationRequired,
        "password_login_failed",
        "The email or password could not be verified.",
    )
}

fn generic_recovery_failure(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::AuthenticationRequired,
        "recovery_invalid",
        "This recovery link is invalid or expired. Request a new one and try again.",
    )
}

fn resource_not_found(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::NotFound,
        "resource_not_found",
        "The passkey was not found.",
    )
}

fn validation_error(context: &RequestContext, reason: &str, message: &str) -> ApiError {
    domain_error(context, ApiErrorCode::ValidationFailed, reason, message)
}

fn service_unavailable(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::ServiceUnavailable,
        "The identity store is unavailable.",
    )
}

fn generated_id(prefix: &str) -> String {
    new_resource_id(prefix).as_str().to_owned()
}

fn user_json(user: &UserRecord) -> Value {
    json!({
        "id": user.user_id,
        "email": user.email,
        "display_name": user.display_name,
        "email_verified": user.email_verified,
        "created_at": user.created_at,
    })
}
