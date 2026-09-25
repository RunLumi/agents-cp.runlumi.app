//! P03 device routes: the desktop-facing enrollment/token/heartbeat/policy
//! flow and the org session-side administration surface.
//!
//! Device identity is asymmetric: the server stores a public key and never a
//! private secret; short-lived device tokens (hashed at rest) authenticate
//! device-side calls. Session-side routes go through the central
//! authorization service like every other protected route.

use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, Response, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    adapters::{
        add_seconds, d1::BindValue, new_resource_id, new_secret, sha256_hex, verify_device_proof,
    },
    app::AppState,
    core::{ApiError, ApiErrorCode, RequestContext},
    http::auth::require_csrf,
    modules::{
        authorization::Permission,
        devices::{
            self, DEVICE_TOKEN_TTL_SECONDS, DeviceStatus, ENROLLMENT_TTL_SECONDS, EnrollmentStatus,
            validate_capability_report, validate_enrollment_input, version_at_least,
        },
        policy::{self, PolicyInputs},
    },
    repositories::{DeviceRepository, OrganizationRepository, PolicyRepository, ProjectRepository},
    routes::{
        authorization::authorize_org,
        errors,
        support::{
            database, database_error, domain_error, idempotency_key, outbox_statement,
            security_event_statement,
        },
    },
};

const PAGE_LIMIT_DEFAULT: i32 = 50;
const PAGE_LIMIT_MAX: i32 = 100;

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

fn generated_id(prefix: &str) -> String {
    new_resource_id(prefix).as_str().to_owned()
}

fn validation_error(context: &RequestContext, reason: &str, message: &str) -> ApiError {
    domain_error(context, ApiErrorCode::ValidationFailed, reason, message)
}

fn service_unavailable(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::ServiceUnavailable,
        "The device store is unavailable.",
    )
}

fn denial(context: &RequestContext, code: ApiErrorCode, reason: &str, message: &str) -> ApiError {
    errors::api_error(context, code, message).with_detail("reason", json!(reason))
}

fn page_limit(query: &ListQuery) -> i32 {
    match query.limit {
        None => PAGE_LIMIT_DEFAULT,
        Some(0) => PAGE_LIMIT_DEFAULT,
        Some(value) if value > PAGE_LIMIT_MAX => PAGE_LIMIT_MAX,
        Some(value) => value,
    }
}

/// Encode the keyset cursor for `(created_at, id)` descending pages. Hex
/// packing keeps the value opaque to clients while remaining cheap to decode.
fn encode_page_cursor(created_at: &str, id: &str) -> String {
    use std::fmt::Write;
    let raw = format!("{created_at}|{id}");
    let mut encoded = String::with_capacity(raw.len() * 2);
    for byte in raw.as_bytes() {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn decode_page_cursor(raw: &str, context: &RequestContext) -> Result<(String, String), ApiError> {
    fn hex_value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }
    let invalid = || validation_error(context, "cursor_invalid", "The cursor is invalid.");
    let bytes = raw.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return Err(invalid());
    }
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let high = hex_value(pair[0]).ok_or_else(invalid)?;
        let low = hex_value(pair[1]).ok_or_else(invalid)?;
        decoded.push(high << 4 | low);
    }
    let text = String::from_utf8(decoded).map_err(|_| invalid())?;
    text.split_once('|')
        .map(|(created_at, id)| (created_at.to_owned(), id.to_owned()))
        .ok_or_else(invalid)
}

/// Authenticate a device-side request from `Authorization: DeviceToken <hex>`.
/// The token row is joined against the device row so an expired token and a
/// revoked device are both rejected before any handler logic runs.
pub(crate) async fn require_device(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    context: &RequestContext,
) -> Result<crate::repositories::DeviceRecord, ApiError> {
    let raw_token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("DeviceToken "))
        .ok_or_else(|| {
            denial(
                context,
                ApiErrorCode::AuthenticationRequired,
                "device_token_expired",
                "A device token is required.",
            )
        })?;
    if raw_token.len() > 256 || !raw_token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(denial(
            context,
            ApiErrorCode::AuthenticationRequired,
            "device_token_expired",
            "The device token is invalid.",
        ));
    }
    let database = database(state, context)?;
    let token_hash = sha256_hex(raw_token)
        .await
        .map_err(|_| service_unavailable(context))?;
    const TOKEN_LOOKUP_SQL: &str = r#"
SELECT d.device_id, d.org_id, d.enrolled_by_user_id, d.name, d.platform, d.app_version,
       d.public_key, d.key_fingerprint, d.status, d.capabilities, d.capability_reported_at,
       d.last_seen_at, d.revoked_at, d.revoked_by_user_id, d.created_at, d.updated_at
FROM device_tokens t
JOIN devices d ON d.device_id = t.device_id
WHERE t.token_hash = ?1 AND t.expires_at > ?2 AND d.status = 'active'
LIMIT 1
"#;
    let statement = database
        .prepare(
            TOKEN_LOOKUP_SQL,
            &[
                BindValue::Text(token_hash.as_str()),
                BindValue::Text(context.received_at.as_str()),
            ],
        )
        .map_err(|_| service_unavailable(context))?;
    let device = statement
        .first::<crate::repositories::DeviceRecord>(None)
        .await
        .map_err(|_| service_unavailable(context))?
        .ok_or_else(|| {
            denial(
                context,
                ApiErrorCode::AuthenticationRequired,
                "device_token_expired",
                "The device token is expired or revoked.",
            )
        })?;
    Ok(device)
}

/// Compile and persist a new org policy snapshot when the compiled payload
/// differs from the latest one (deterministic compilation makes payload
/// equality a safe version gate). Returns the current version.
async fn refresh_policy_snapshot(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    org_id: &str,
    min_client_version: Option<&str>,
) -> Result<i64, ApiError> {
    let repository = PolicyRepository::new(database);
    let latest = repository
        .latest_snapshot(org_id)
        .await
        .map_err(|_| service_unavailable(context))?;

    let devices = DeviceRepository::new(database)
        .list_devices_by_org(org_id, None, PAGE_LIMIT_MAX)
        .await
        .map_err(|_| service_unavailable(context))?;
    let projects = ProjectRepository::new(database);
    let mut bindings: Vec<(String, bool)> = Vec::new();
    for device in &devices {
        for binding in projects
            .list_bindings_by_device(&device.device_id, PAGE_LIMIT_MAX)
            .await
            .map_err(|_| service_unavailable(context))?
        {
            let archived = projects
                .find_project(&binding.project_id)
                .await
                .map_err(|_| service_unavailable(context))?
                .is_none_or(|project| project.archived_at.is_some());
            bindings.push((binding.project_id, archived));
        }
    }
    let member_active = devices
        .iter()
        .any(|device| DeviceStatus::parse(&device.status) == Some(DeviceStatus::Active));
    let inputs = PolicyInputs {
        org_active: true,
        member_active,
        project_bindings: &bindings,
        min_client_version,
    };
    let payload = policy::compile_policy_payload(&inputs, None).map_err(|_| {
        errors::api_error(
            context,
            ApiErrorCode::InternalError,
            "The policy snapshot could not be compiled.",
        )
    })?;
    let payload_text = payload.to_string();
    if let Some(latest) = &latest
        && latest.payload == payload_text
    {
        return Ok(latest.policy_version);
    }
    let policy_version = repository
        .next_policy_version(org_id)
        .await
        .map_err(|_| service_unavailable(context))?;
    let expires_at = add_seconds(&context.received_at, policy::DEFAULT_POLICY_TTL_SECONDS)
        .map_err(|_| service_unavailable(context))?;
    let statement = repository
        .insert_snapshot_statement(
            &generated_id("pol"),
            org_id,
            policy_version,
            &payload_text,
            context.received_at.as_str(),
            expires_at.as_str(),
        )
        .map_err(|_| service_unavailable(context))?;
    statement
        .run()
        .await
        .map_err(|_| service_unavailable(context))?;
    Ok(policy_version)
}

async fn latest_min_client_version(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    org_id: &str,
) -> Result<Option<String>, ApiError> {
    let statement = database
        .prepare(
            "SELECT min_client_version FROM org_device_policy_settings WHERE org_id = ?1 LIMIT 1",
            &[BindValue::Text(org_id)],
        )
        .map_err(|_| service_unavailable(context))?;
    let row = statement
        .first::<serde_json::Value>(None)
        .await
        .map_err(|_| service_unavailable(context))?;
    Ok(row
        .and_then(|row| {
            row.get("min_client_version")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .filter(|value| !value.is_empty()))
}

fn device_json(device: &crate::repositories::DeviceRecord) -> Value {
    json!({
        "id": device.device_id,
        "org_id": device.org_id,
        "name": device.name,
        "platform": device.platform,
        "app_version": device.app_version,
        "status": device.status,
        "capabilities": device
            .capabilities
            .as_deref()
            .and_then(|text| serde_json::from_str::<Value>(text).ok()),
        "last_seen_at": device.last_seen_at,
        "enrolled_by_user_id": device.enrolled_by_user_id,
        "created_at": device.created_at,
    })
}

// ---------------------------------------------------------------------------
// device-side flow (desktop client)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginEnrollmentRequest {
    pub org_slug: String,
    pub public_key: String,
    pub key_fingerprint: String,
    pub device_name: String,
    pub platform: String,
    pub app_version: String,
}

#[derive(Debug, Serialize)]
pub struct BeginEnrollmentResponse {
    pub enrollment_id: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_at: String,
}

/// Begin an anonymous enrollment: the desktop generates an Ed25519 keypair,
/// submits the public key plus bounded metadata, and receives a one-time
/// user code a signed-in org member must approve in the browser (F19-001).
#[worker::send]
pub async fn begin_enrollment(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    Json(body): Json<BeginEnrollmentRequest>,
) -> Result<Response<Body>, ApiError> {
    let input = validate_enrollment_input(
        &body.public_key,
        &body.key_fingerprint,
        &body.device_name,
        &body.platform,
        &body.app_version,
    )
    .map_err(|_| {
        validation_error(
            &context,
            "device_invalid",
            "The enrollment payload is invalid.",
        )
    })?;
    let database = database(&state, &context)?;
    let organization = OrganizationRepository::new(database)
        .find_organization_by_slug(&body.org_slug)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| {
            denial(
                &context,
                ApiErrorCode::NotFound,
                "device_not_found",
                "No such organization.",
            )
        })?;
    if organization.state != "active" {
        return Err(denial(
            &context,
            ApiErrorCode::PermissionDenied,
            "organization_suspended",
            "The organization is not accepting enrollments.",
        ));
    }
    let enrollment_id = generated_id("enr");
    let user_code = new_secret();
    let code_hash = sha256_hex(&user_code)
        .await
        .map_err(|_| service_unavailable(&context))?;
    let challenge = new_secret();
    let expires_at = add_seconds(&context.received_at, ENROLLMENT_TTL_SECONDS)
        .map_err(|_| service_unavailable(&context))?;
    let statement = DeviceRepository::new(database)
        .insert_enrollment_statement(
            &crate::repositories::DeviceEnrollmentInput {
                enrollment_id: &enrollment_id,
                org_id: &organization.org_id,
                code_hash: &code_hash,
                public_key: &input.public_key,
                key_fingerprint: &input.key_fingerprint,
                device_name: &input.device_name,
                platform: &input.platform,
                app_version: &input.app_version,
                challenge: &challenge,
            },
            expires_at.as_str(),
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    statement
        .run()
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok((
        StatusCode::CREATED,
        Json(BeginEnrollmentResponse {
            enrollment_id,
            user_code,
            verification_uri: "/devices".to_owned(),
            expires_at: expires_at.as_str().to_owned(),
        }),
    )
        .into_response())
}

#[derive(Debug, Serialize)]
pub struct EnrollmentStatusResponse {
    pub status: &'static str,
    pub challenge: Option<String>,
}

/// Poll enrollment status. The proof challenge is released only after a human
/// approved the device, so possession of a pending enrollment grants nothing.
#[worker::send]
pub async fn enrollment_status(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    Path(enrollment_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    let database = database(&state, &context)?;
    let enrollment = DeviceRepository::new(database)
        .find_enrollment(&enrollment_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| {
            denial(
                &context,
                ApiErrorCode::NotFound,
                "device_not_found",
                "No such enrollment.",
            )
        })?;
    let status =
        EnrollmentStatus::parse(&enrollment.status).ok_or_else(|| service_unavailable(&context))?;
    let expired = enrollment.expires_at.as_str() <= context.received_at.as_str();
    // "approved" = a member approved this enrollment; the proof challenge is
    // released to the device only at that point.
    let approved = status == EnrollmentStatus::Pending && enrollment.approved_by_user_id.is_some();
    let wire_status = match (status, expired, approved) {
        (EnrollmentStatus::Pending, true, _) => {
            DeviceRepository::new(database)
                .expire_enrollment(&enrollment_id, &context.received_at)
                .await
                .map_err(|_| service_unavailable(&context))?;
            "expired"
        }
        (EnrollmentStatus::Pending, false, true) => "approved",
        (EnrollmentStatus::Pending, false, false) => "pending",
        (EnrollmentStatus::Completed, _, _) => "completed",
        (EnrollmentStatus::Expired, _, _) => "expired",
        (EnrollmentStatus::Denied, _, _) => "denied",
    };
    let challenge = if wire_status == "approved" {
        enrollment.challenge.clone()
    } else {
        None
    };
    Ok((
        StatusCode::OK,
        Json(EnrollmentStatusResponse {
            status: wire_status,
            challenge,
        }),
    )
        .into_response())
}

/// Complete an enrollment: prove possession of the enrollment key by signing
/// the released challenge; the device row, enrollment close, and first device
/// token commit in one D1 batch.
#[worker::send]
pub async fn complete_enrollment(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    Path(enrollment_id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response<Body>, ApiError> {
    let signature = body
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| validation_error(&context, "device_invalid", "signature is required."))?;
    if signature.is_empty() || signature.len() > 512 || !is_hex(signature) {
        return Err(denial(
            &context,
            ApiErrorCode::PermissionDenied,
            "device_proof_invalid",
            "The device proof is invalid.",
        ));
    }
    let database = database(&state, &context)?;
    let enrollment = DeviceRepository::new(database)
        .find_enrollment(&enrollment_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| {
            denial(
                &context,
                ApiErrorCode::NotFound,
                "device_not_found",
                "No such enrollment.",
            )
        })?;
    if EnrollmentStatus::parse(&enrollment.status) != Some(EnrollmentStatus::Pending)
        || enrollment.approved_by_user_id.is_none()
        || enrollment.expires_at.as_str() <= context.received_at.as_str()
    {
        return Err(denial(
            &context,
            ApiErrorCode::PermissionDenied,
            "enrollment_expired",
            "The enrollment is not awaiting completion.",
        ));
    }
    let Some(challenge) = enrollment.challenge.as_deref() else {
        return Err(denial(
            &context,
            ApiErrorCode::PermissionDenied,
            "device_proof_invalid",
            "No challenge is pending for this enrollment.",
        ));
    };
    let verified = verify_device_proof(&enrollment.public_key, signature, challenge)
        .await
        .unwrap_or(false);
    if !verified {
        return Err(denial(
            &context,
            ApiErrorCode::PermissionDenied,
            "device_proof_invalid",
            "The device proof is invalid.",
        ));
    }
    let device_id = enrollment
        .device_id
        .clone()
        .ok_or_else(|| service_unavailable(&context))?;
    let raw_token = new_secret();
    let token_hash = sha256_hex(&raw_token)
        .await
        .map_err(|_| service_unavailable(&context))?;
    let token_expires_at = add_seconds(&context.received_at, DEVICE_TOKEN_TTL_SECONDS)
        .map_err(|_| service_unavailable(&context))?;
    let statements = DeviceRepository::new(database)
        .complete_enrollment_statements(
            &enrollment_id,
            &device_id,
            &token_hash,
            token_expires_at.as_str(),
            &context.received_at,
        )
        .map_err(|error| {
            worker::console_log!(
                "complete prepare failed: {:?}",
                worker::Error::RustError(error.to_string())
            );
            database_error(&context, error)
        })?;
    database.batch(statements).await.map_err(|error| {
        worker::console_log!("complete batch failed: {}", error.to_string());
        database_error(&context, error)
    })?;
    let device = DeviceRepository::new(database)
        .find_device(&device_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| service_unavailable(&context))?;
    let policy_version = refresh_policy_snapshot(database, &context, &device.org_id, None).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "device": device_json(&device),
            "device_token": raw_token,
            "token_expires_at": token_expires_at.as_str().to_owned(),
            "policy_version": policy_version,
        })),
    )
        .into_response())
}

fn is_hex(value: &str) -> bool {
    value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------
// device token refresh, heartbeat, policy, bindings (device-token auth)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct NonceResponse {
    pub nonce: String,
    pub expires_at: String,
}

/// Issue a short-lived single-use nonce for the token refresh proof.
#[worker::send]
pub async fn token_nonce(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
) -> Result<Response<Body>, ApiError> {
    // Binding existence is validated so the route stays unavailable when the
    // D1 binding is missing (consistent with other storage-backed routes).
    database(&state, &context)?;
    let nonce = new_secret();
    let expires_at = add_seconds(&context.received_at, ENROLLMENT_TTL_SECONDS)
        .map_err(|_| service_unavailable(&context))?;
    Ok((
        StatusCode::OK,
        Json(NonceResponse {
            nonce,
            expires_at: expires_at.as_str().to_owned(),
        }),
    )
        .into_response())
}

#[derive(Debug, Serialize)]
pub struct DeviceTokenResponse {
    pub device_token: String,
    pub token_expires_at: String,
    pub policy_version: Option<i64>,
}

/// Exchange a valid proof for a fresh short-lived device token. Every gate
/// from plan03 P03-BE-03 applies: device active, enrollment completed,
/// membership active, org active, and app version above the org minimum.
#[worker::send]
pub async fn refresh_token(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    Json(body): Json<Value>,
) -> Result<Response<Body>, ApiError> {
    let device_id = body
        .get("device_id")
        .and_then(Value::as_str)
        .ok_or_else(|| validation_error(&context, "device_invalid", "device_id is required."))?;
    let signature = body
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| validation_error(&context, "device_invalid", "signature is required."))?;
    let app_version = body
        .get("app_version")
        .and_then(Value::as_str)
        .ok_or_else(|| validation_error(&context, "device_invalid", "app_version is required."))?;
    devices::validate_app_version(app_version)
        .map_err(|_| validation_error(&context, "device_invalid", "app_version is invalid."))?;
    if signature.is_empty() || signature.len() > 512 || !is_hex(signature) {
        return Err(denial(
            &context,
            ApiErrorCode::PermissionDenied,
            "device_proof_invalid",
            "The device proof is invalid.",
        ));
    }
    let database = database(&state, &context)?;
    let device = load_active_device(database, device_id, &context).await?;
    let organization = OrganizationRepository::new(database)
        .find_organization(&device.org_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| {
            denial(
                &context,
                ApiErrorCode::NotFound,
                "device_not_found",
                "The device organization no longer exists.",
            )
        })?;
    if organization.state != "active" {
        return Err(denial(
            &context,
            ApiErrorCode::PermissionDenied,
            "organization_suspended",
            "The organization is not active.",
        ));
    }
    let membership_active = OrganizationRepository::new(database)
        .find_membership(&device.org_id, device.enrolled_by_user_id.as_str())
        .await
        .map_err(|_| service_unavailable(&context))?
        .is_some_and(|membership| membership.status == "active");
    if !membership_active {
        return Err(denial(
            &context,
            ApiErrorCode::PermissionDenied,
            "membership_required",
            "The enrolling member is no longer active.",
        ));
    }
    let min_client_version = latest_min_client_version(database, &context, &device.org_id).await?;
    if let Some(minimum) = min_client_version.as_deref()
        && !version_at_least(app_version, minimum)
    {
        return Err(denial(
            &context,
            ApiErrorCode::PermissionDenied,
            "client_version_too_old",
            "The device client version is below the org minimum.",
        ));
    }
    // Proof-of-possession: sign the device's last seen nonce. The nonce is
    // delivered by GET /devices/token/nonce and never stored server-side.
    let nonce = body
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| validation_error(&context, "device_invalid", "nonce is required."))?;
    if nonce.is_empty() || nonce.len() > 256 {
        return Err(denial(
            &context,
            ApiErrorCode::PermissionDenied,
            "device_proof_invalid",
            "The nonce is invalid.",
        ));
    }
    let verified = verify_device_proof(&device.public_key, signature, nonce)
        .await
        .unwrap_or(false);
    if !verified {
        return Err(denial(
            &context,
            ApiErrorCode::PermissionDenied,
            "device_proof_invalid",
            "The device proof is invalid.",
        ));
    }
    let raw_token = new_secret();
    let token_hash = sha256_hex(&raw_token)
        .await
        .map_err(|_| service_unavailable(&context))?;
    let token_expires_at = add_seconds(&context.received_at, DEVICE_TOKEN_TTL_SECONDS)
        .map_err(|_| service_unavailable(&context))?;
    DeviceRepository::new(database)
        .insert_device_token(
            &token_hash,
            device_id,
            token_expires_at.as_str(),
            &context.received_at,
        )
        .await
        .map_err(|error| database_error(&context, error))?;
    let policy_version = refresh_policy_snapshot(
        database,
        &context,
        &device.org_id,
        min_client_version.as_deref(),
    )
    .await?;
    Ok((
        StatusCode::OK,
        Json(DeviceTokenResponse {
            device_token: raw_token,
            token_expires_at: token_expires_at.as_str().to_owned(),
            policy_version: Some(policy_version),
        }),
    )
        .into_response())
}

async fn load_active_device(
    database: &crate::adapters::d1::D1Adapter,
    device_id: &str,
    context: &RequestContext,
) -> Result<crate::repositories::DeviceRecord, ApiError> {
    let device = DeviceRepository::new(database)
        .find_device(device_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .ok_or_else(|| {
            denial(
                context,
                ApiErrorCode::NotFound,
                "device_not_found",
                "The device does not exist.",
            )
        })?;
    if DeviceStatus::parse(&device.status) != Some(DeviceStatus::Active) {
        return Err(denial(
            context,
            ApiErrorCode::PermissionDenied,
            "device_revoked",
            "The device has been revoked.",
        ));
    }
    Ok(device)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatRequest {
    pub capabilities: Option<Value>,
    pub app_version: String,
}

#[derive(Debug, Serialize)]
pub struct HeartbeatResponse {
    pub server_time: String,
    pub policy_version: Option<i64>,
    pub min_client_version: Option<String>,
}

#[worker::send]
pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<HeartbeatRequest>,
) -> Result<Response<Body>, ApiError> {
    devices::validate_app_version(&body.app_version)
        .map_err(|_| validation_error(&context, "device_invalid", "app_version is invalid."))?;
    let capabilities = match &body.capabilities {
        Some(value) => Some(validate_capability_report(&value.to_string()).map_err(|_| {
            validation_error(
                &context,
                "device_invalid",
                "The capability report is invalid.",
            )
        })?),
        None => None,
    };
    let device = require_device(&state, &headers, &context).await?;
    let database = database(&state, &context)?;
    let updated = DeviceRepository::new(database)
        .update_heartbeat(
            &device.device_id,
            &context.received_at,
            capabilities.as_deref(),
            &body.app_version,
        )
        .await
        .map_err(|error| database_error(&context, error))?;
    if !updated {
        return Err(denial(
            &context,
            ApiErrorCode::PermissionDenied,
            "device_revoked",
            "The device has been revoked.",
        ));
    }
    let policy_version = PolicyRepository::new(database)
        .latest_snapshot(&device.org_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .map(|snapshot| snapshot.policy_version);
    let min_client_version = latest_min_client_version(database, &context, &device.org_id).await?;
    Ok((
        StatusCode::OK,
        Json(HeartbeatResponse {
            server_time: context.received_at.as_str().to_owned(),
            policy_version,
            min_client_version,
        }),
    )
        .into_response())
}

#[worker::send]
pub async fn fetch_policy(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiError> {
    let device = require_device(&state, &headers, &context).await?;
    let database = database(&state, &context)?;
    let snapshot = PolicyRepository::new(database)
        .latest_snapshot(&device.org_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| {
            denial(
                &context,
                ApiErrorCode::NotFound,
                "device_not_found",
                "No policy snapshot exists for this organization yet.",
            )
        })?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "policy_id": snapshot.policy_id,
            "org_id": snapshot.org_id,
            "policy_version": snapshot.policy_version,
            "issued_at": snapshot.issued_at,
            "expires_at": snapshot.expires_at,
            "signature": Value::Null,
            "payload": serde_json::from_str::<Value>(&snapshot.payload)
                .unwrap_or_else(|_| json!({})),
        })),
    )
        .into_response())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAckRequest {
    pub policy_version: i64,
}

#[worker::send]
pub async fn ack_policy(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<PolicyAckRequest>,
) -> Result<Response<Body>, ApiError> {
    if body.policy_version <= 0 {
        return Err(validation_error(
            &context,
            "policy_invalid",
            "policy_version must be positive.",
        ));
    }
    let device = require_device(&state, &headers, &context).await?;
    let database = database(&state, &context)?;
    PolicyRepository::new(database)
        .ack_policy_version(
            &generated_id("pak"),
            &device.org_id,
            &device.device_id,
            body.policy_version,
            &context.received_at,
        )
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateBindingRequest {
    pub project_id: String,
    pub workspace_identity: String,
    pub display_name: String,
    pub environment_type: String,
}

/// Device-side binding: always explicit, always same-org, never auto-created
/// (F26-002). Archived projects reject new bindings (F07-005).
#[worker::send]
pub async fn create_binding(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<CreateBindingRequest>,
) -> Result<Response<Body>, ApiError> {
    let device = require_device(&state, &headers, &context).await?;
    let identity =
        devices::validate_workspace_identity(&body.workspace_identity).map_err(|_| {
            validation_error(
                &context,
                "workspace_invalid",
                "The workspace identity is invalid.",
            )
        })?;
    let display_name =
        devices::validate_workspace_display_name(&body.display_name).map_err(|_| {
            validation_error(
                &context,
                "workspace_invalid",
                "The display name is invalid.",
            )
        })?;
    let environment = crate::modules::projects::EnvironmentType::parse(&body.environment_type)
        .ok_or_else(|| {
            validation_error(
                &context,
                "workspace_invalid",
                "The environment type is invalid.",
            )
        })?;
    let database = database(&state, &context)?;
    let projects = ProjectRepository::new(database);
    let project = projects
        .find_project(&body.project_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .filter(|project| project.org_id == device.org_id)
        .ok_or_else(|| {
            denial(
                &context,
                ApiErrorCode::PermissionDenied,
                "resource_scope_mismatch",
                "The project belongs to another organization.",
            )
        })?;
    if project.archived_at.is_some() {
        return Err(denial(
            &context,
            ApiErrorCode::Conflict,
            "project_archived",
            "Archived projects reject new workspace bindings.",
        ));
    }
    if projects
        .binding_identity_count(&device.device_id, &identity)
        .await
        .map_err(|error| database_error(&context, error))?
        > 0
    {
        return Err(denial(
            &context,
            ApiErrorCode::Conflict,
            "workspace_binding_conflict",
            "This workspace is already bound on the device.",
        ));
    }
    let binding = crate::repositories::WorkspaceBindingRecord {
        binding_id: generated_id("wsb"),
        org_id: device.org_id.clone(),
        project_id: project.project_id.clone(),
        device_id: device.device_id.clone(),
        workspace_identity: identity,
        display_name,
        environment_type: environment.as_str().to_owned(),
        last_seen_at: Some(context.received_at.as_str().to_owned()),
        created_at: context.received_at.as_str().to_owned(),
        updated_at: context.received_at.as_str().to_owned(),
    };
    projects
        .insert_binding(&binding)
        .await
        .map_err(|error| database_error(&context, error))?;
    let binding_event = outbox_statement(
        database,
        &context,
        None,
        Some(&device.org_id),
        "project.binding_created.v1",
        &json!({
            "binding_id": binding.binding_id,
            "project_id": binding.project_id,
            "device_id": device.device_id,
        }),
    )?;
    database
        .batch(vec![binding_event])
        .await
        .map_err(|error| database_error(&context, error))?;
    refresh_policy_snapshot(database, &context, &device.org_id, None).await?;
    let mut response = (
        StatusCode::CREATED,
        Json(json!({
            "id": binding.binding_id,
            "org_id": binding.org_id,
            "project_id": binding.project_id,
            "device_id": binding.device_id,
            "workspace_identity": binding.workspace_identity,
            "display_name": binding.display_name,
            "environment_type": binding.environment_type,
            "last_seen_at": binding.last_seen_at,
            "created_at": binding.created_at,
        })),
    )
        .into_response();
    response.headers_mut().insert(
        "location",
        format!("/api/v1/devices/bindings/{}", binding.binding_id)
            .parse()
            .expect("location value"),
    );
    Ok(response)
}

#[worker::send]
pub async fn list_device_bindings(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiError> {
    let device = require_device(&state, &headers, &context).await?;
    let database = database(&state, &context)?;
    let bindings = ProjectRepository::new(database)
        .list_bindings_by_device(&device.device_id, PAGE_LIMIT_MAX)
        .await
        .map_err(|error| database_error(&context, error))?;
    let items: Vec<Value> = bindings.iter().map(binding_json).collect();
    Ok((
        StatusCode::OK,
        Json(json!({ "items": items, "next_cursor": Value::Null, "has_more": false })),
    )
        .into_response())
}

#[worker::send]
pub async fn delete_device_binding(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(binding_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    let device = require_device(&state, &headers, &context).await?;
    let database = database(&state, &context)?;
    let projects = ProjectRepository::new(database);
    let binding = projects
        .find_binding(&binding_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .filter(|binding| binding.device_id == device.device_id)
        .ok_or_else(|| {
            denial(
                &context,
                ApiErrorCode::NotFound,
                "workspace_binding_conflict",
                "No such binding for this device.",
            )
        })?;
    let deleted = projects
        .delete_binding(&binding.binding_id, &binding.project_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    if !deleted {
        return Err(denial(
            &context,
            ApiErrorCode::NotFound,
            "workspace_binding_conflict",
            "No such binding for this device.",
        ));
    }
    let binding_event = outbox_statement(
        database,
        &context,
        None,
        Some(&device.org_id),
        "project.binding_removed.v1",
        &json!({
            "binding_id": binding.binding_id,
            "project_id": binding.project_id,
            "device_id": device.device_id,
        }),
    )?;
    database
        .batch(vec![binding_event])
        .await
        .map_err(|error| database_error(&context, error))?;
    refresh_policy_snapshot(database, &context, &device.org_id, None).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

fn binding_json(binding: &crate::repositories::WorkspaceBindingRecord) -> Value {
    json!({
        "id": binding.binding_id,
        "org_id": binding.org_id,
        "project_id": binding.project_id,
        "device_id": binding.device_id,
        "workspace_identity": binding.workspace_identity,
        "display_name": binding.display_name,
        "environment_type": binding.environment_type,
        "last_seen_at": binding.last_seen_at,
        "created_at": binding.created_at,
    })
}

// ---------------------------------------------------------------------------
// session-side admin surface
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
}

/// Approve a pending enrollment: any active org member may confirm a device
/// presented to them (device-flow trust model, mirroring the P02 approve
/// route). Device + enrollment close + first token commit atomically.
#[worker::send]
pub async fn approve_enrollment(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, enrollment_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::DevicesRead,
        Some("device"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    idempotency_key(&headers, &context)?;
    let database = database(&state, &context)?;
    let repository = DeviceRepository::new(database);
    let enrollment = repository
        .find_enrollment(&enrollment_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .filter(|enrollment| enrollment.org_id == org_id)
        .ok_or_else(|| {
            denial(
                &context,
                ApiErrorCode::NotFound,
                "device_not_found",
                "No such enrollment.",
            )
        })?;
    if EnrollmentStatus::parse(&enrollment.status) != Some(EnrollmentStatus::Pending) {
        return Err(denial(
            &context,
            ApiErrorCode::Conflict,
            "enrollment_expired",
            "The enrollment is no longer pending.",
        ));
    }
    if enrollment.expires_at.as_str() <= context.received_at.as_str() {
        repository
            .expire_enrollment(&enrollment_id, &context.received_at)
            .await
            .map_err(|_| service_unavailable(&context))?;
        return Err(denial(
            &context,
            ApiErrorCode::Conflict,
            "enrollment_expired",
            "The enrollment has expired.",
        ));
    }
    if repository
        .device_fingerprint_count(org_id.as_str(), &enrollment.key_fingerprint)
        .await
        .map_err(|error| database_error(&context, error))?
        > 0
    {
        return Err(denial(
            &context,
            ApiErrorCode::Conflict,
            "device_fingerprint_conflict",
            "A device with this key fingerprint is already enrolled.",
        ));
    }
    let device_id = generated_id("dvc");
    let mut statements = repository
        .approve_enrollment_statements(
            &enrollment,
            &device_id,
            access.principal.user_id.as_str(),
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let event_id = generated_id("sec");
    let security_statement = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(org_id.as_str()),
        &event_id,
        "device.enrolled.v1",
        "device",
        Some(&device_id),
        "success",
        &json!({ "enrollment_id": enrollment_id }),
    )?;
    statements.push(security_statement);
    database
        .batch(statements)
        .await
        .map_err(|error| database_error(&context, error))?;
    let device = DeviceRepository::new(database)
        .find_device(&device_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| service_unavailable(&context))?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "device": device_json(&device) })),
    )
        .into_response())
}

#[worker::send]
pub async fn list_devices(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
    Path(org_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::DevicesRead,
        Some("device"),
        None,
    )
    .await?;
    let limit = page_limit(&query);
    let cursor = query
        .cursor
        .as_deref()
        .map(|raw| decode_page_cursor(raw, &context))
        .transpose()?;
    let database = database(&state, &context)?;
    let mut devices = DeviceRepository::new(database)
        .list_devices_by_org(
            org_id.as_str(),
            cursor
                .as_ref()
                .map(|(created_at, device_id)| (created_at.as_str(), device_id.as_str())),
            limit + 1,
        )
        .await
        .map_err(|error| database_error(&context, error))?;
    let has_more = devices.len() > limit as usize;
    if has_more {
        devices.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        devices
            .last()
            .map(|device| encode_page_cursor(&device.created_at, &device.device_id))
    } else {
        None
    };
    let items: Vec<Value> = devices.iter().map(device_json).collect();
    Ok((
        StatusCode::OK,
        Json(json!({
            "items": items,
            "next_cursor": next_cursor,
            "has_more": has_more,
        })),
    )
        .into_response())
}

#[worker::send]
pub async fn get_device(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, device_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::DevicesRead,
        Some("device"),
        Some(&device_id),
    )
    .await?;
    let database = database(&state, &context)?;
    let device = DeviceRepository::new(database)
        .find_device(&device_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .filter(|device| device.org_id == org_id)
        .ok_or_else(|| {
            denial(
                &context,
                ApiErrorCode::NotFound,
                "device_not_found",
                "No such device.",
            )
        })?;
    Ok((StatusCode::OK, Json(device_json(&device))).into_response())
}

/// Revoke a managed device: `devices.manage` or the enrolling member. The
/// revoke and token invalidation share one D1 batch; the audit event commits
/// alongside them.
#[worker::send]
pub async fn revoke_device(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, device_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::DevicesRead,
        Some("device"),
        Some(&device_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    idempotency_key(&headers, &context)?;
    let is_manager = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::DevicesManage,
        Some("device"),
        Some(&device_id),
    )
    .await
    .is_ok();
    let database = database(&state, &context)?;
    let device = DeviceRepository::new(database)
        .find_device(&device_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .filter(|device| device.org_id == org_id)
        .ok_or_else(|| {
            denial(
                &context,
                ApiErrorCode::NotFound,
                "device_not_found",
                "No such device.",
            )
        })?;
    let self_revoke = device.enrolled_by_user_id == access.principal.user_id.as_str();
    if !is_manager && !self_revoke {
        return Err(denial(
            &context,
            ApiErrorCode::PermissionDenied,
            "permission_denied",
            "Only org device managers or the enrolling member can revoke a device.",
        ));
    }
    let revoked = DeviceRepository::new(database)
        .revoke_device(
            &device_id,
            access.principal.user_id.as_str(),
            &context.received_at,
        )
        .await
        .map_err(|error| database_error(&context, error))?;
    if !revoked {
        return Err(denial(
            &context,
            ApiErrorCode::Conflict,
            "device_revoked",
            "The device was already revoked.",
        ));
    }
    let event_id = generated_id("sec");
    let statement = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(org_id.as_str()),
        &event_id,
        "device.revoked.v1",
        "device",
        Some(&device_id),
        "success",
        &json!({}),
    )?;
    database
        .batch(vec![statement])
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
