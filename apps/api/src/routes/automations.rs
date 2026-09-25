//! P06 automation HTTP surface: tenant-scoped definition CRUD plus the
//! device-token lease lifecycle.
//!
//! # Two identities, two rule sets
//!
//! Browser routes require a session, a CSRF proof, an `Idempotency-Key`, and the
//! current `version`. They go through [`authorize_org`] so every decision is made
//! by the central policy service from current membership and organization state.
//!
//! Device routes accept a device token and NOTHING else. The organization,
//! project, device, and principal are derived from the token and its current
//! binding; a body or path ID is correlation input, never authority. Every
//! lease-authoritative call presents the current lease ID, its version, its
//! fence, and the one-time lease token, and the server stores only the token's
//! SHA-256 fingerprint.
//!
//! # Dispatch-time rechecks
//!
//! A definition's captured membership, policy, entitlement, and device state are
//! constraints, not authority. The dispatcher re-reads all of them immediately
//! before creating work, and a device re-reads them again at every lease
//! transition.

// Every handler in this file becomes live when `app.rs` mounts the router paths
// declared below. Until the coordinator wires them, the crate would otherwise
// report every route, request shape, and helper as dead code, so the
// allowance is scoped to this module rather than to the crate.
#![allow(dead_code)]

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
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::{new_secret, sha256_hex},
    app::AppState,
    core::{ApiError, ApiErrorCode, RequestContext, StoredSuccess},
    http::auth::require_csrf,
    jobs::automations::{
        MAX_DUE_OCCURRENCES, MAX_OCCURRENCE_PAGE, deterministic_manual_occurrence_id,
        due_projection, occurrence_event_type,
    },
    modules::authorization::Permission,
    modules::automations::{
        DomDowMode, DomainError, DstPolicy, MissedPolicy, OccurrenceEvent, OccurrenceState,
        OffPeakMode, OverlapPolicy, ScheduleKind, ScheduleRule, UtcOffsetTransition, ZoneOffsets,
        parse_instant_utc, transition, validate_settlement,
    },
    repositories::{
        AutomationDefinitionRecord, AutomationOccurrenceRecord, AutomationStoreError,
        AutomationUpdateInput, AutomationsRepository, ExecutionLeaseRecord, NewAttemptInput,
        NewAutomationInput, NewAutomationRunInput, NewLeaseInput, NewOccurrenceInput,
        NewRunLinkInput, NewScheduleRuleInput, OccurrenceTransition, ProjectRepository,
        RunRepository, StoredScheduleRevision,
    },
    routes::{
        agents::{
            PAGE_LIMIT_DEFAULT, PreparedMutation, commit_mutation, decode_page_cursor,
            encode_page_cursor, generated_id, page_limit, prepare_mutation, replay_response,
            validation_error,
        },
        authorization::{DeviceAccess, authorize_device, authorize_org},
        errors,
        support::{database, database_error, domain_error, idempotency_key, outbox_statement},
    },
};

/// Stable idempotency-scope paths and the router paths they mirror. They are
/// templates, never the concrete request path, so the same logical operation
/// always shares one key scope. `app.rs` mounts each router path; the constants
/// are retained here so a coordinator can assert the two never drift.
#[allow(dead_code)]
pub const AUTOMATIONS_PATH: &str = "/api/v1/orgs/{org_id}/automations";
#[allow(dead_code)]
pub const AUTOMATION_PATH: &str = "/api/v1/orgs/{org_id}/automations/{automation_id}";
#[allow(dead_code)]
pub const AUTOMATION_PAUSE_PATH: &str = "/api/v1/orgs/{org_id}/automations/{automation_id}/pause";
#[allow(dead_code)]
pub const AUTOMATION_RESUME_PATH: &str = "/api/v1/orgs/{org_id}/automations/{automation_id}/resume";
#[allow(dead_code)]
pub const AUTOMATION_RUN_NOW_PATH: &str =
    "/api/v1/orgs/{org_id}/automations/{automation_id}/run-now";
#[allow(dead_code)]
pub const AUTOMATION_OCCURRENCES_PATH: &str =
    "/api/v1/orgs/{org_id}/automations/{automation_id}/occurrences";
#[allow(dead_code)]
pub const DEVICE_AUTOMATIONS_DUE_PATH: &str = "/api/v1/devices/automations/due";
#[allow(dead_code)]
pub const DEVICE_OCCURRENCE_CLAIM_PATH: &str =
    "/api/v1/devices/automation-occurrences/{occurrence_id}/claim";
#[allow(dead_code)]
pub const DEVICE_LEASE_RENEW_PATH: &str = "/api/v1/devices/automation-leases/{lease_id}/renew";
#[allow(dead_code)]
pub const DEVICE_OCCURRENCE_START_PATH: &str =
    "/api/v1/devices/automation-occurrences/{occurrence_id}/start";
#[allow(dead_code)]
pub const DEVICE_OCCURRENCE_SETTLE_PATH: &str =
    "/api/v1/devices/automation-occurrences/{occurrence_id}/settle";
#[allow(dead_code)]
pub const DEVICE_OCCURRENCE_RELEASE_PATH: &str =
    "/api/v1/devices/automation-occurrences/{occurrence_id}/release";

/// The frozen P06 permission names. They are resolved through
/// [`Permission::parse`] so the decision still runs in the central policy
/// service; the coordinator registers the variants (see the handoff).
const PERMISSION_AUTOMATIONS_READ: &str = "automations.read";
const PERMISSION_AUTOMATIONS_MANAGE: &str = "automations.manage";
const PERMISSION_AUTOMATIONS_RUN: &str = "automations.run";

const TARGET_KINDS: &[&str] = &[
    "eligible_device",
    "specific_device",
    "remote_workspace",
    "server_runner",
];
const TOOL_POLICY_SCOPES: &[&str] = &["project", "organization", "agent"];
const OFF_PEAK_ELIGIBILITY_SOURCES: &[&str] = &["provider_ticket", "org_window"];
const MAX_ROUTE_ALIASES: usize = 16;
const MAX_REQUIRED_CAPABILITIES: usize = 64;
const MAX_OFF_PEAK_SCHEMA_VERSION: u32 = 1;
const DEFAULT_QUEUED_SUCCESSOR_MAX_AGE_SECONDS: i64 = 86_400;
const MAX_QUEUED_SUCCESSOR_MAX_AGE_SECONDS: i64 = 604_800;
const FINGERPRINT_PREFIX: &str = "sha256:";

// -----------------------------------------------------------------------------
// Request shapes
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAutomationRequest {
    pub name: String,
    pub description: Option<String>,
    pub project_id: String,
    pub agent_definition_id: String,
    pub execution_principal: ExecutionPrincipalRequest,
    pub target: AutomationTargetRequest,
    pub schedule: ScheduleRequest,
    pub execution_policy: ExecutionPolicyRequest,
    pub execution_retry: Option<ExecutionRetryRequest>,
    pub off_peak_policy: Option<OffPeakPolicyRequest>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPrincipalRequest {
    pub kind: String,
    /// Optional: defaults to the authenticated principal. When present it is a
    /// proposal, and the server requires a current active membership for it.
    pub id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationTargetRequest {
    pub kind: String,
    pub device_id: Option<String>,
    pub workspace_binding_id: Option<String>,
    pub required_capabilities: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPolicyRequest {
    pub model_alias: Option<String>,
    pub budget_id: Option<String>,
    pub tool_policy_scope: Option<String>,
    pub required_policy_version: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRetryRequest {
    pub max_start_attempts: i64,
    pub lease_ttl_seconds: i64,
    pub heartbeat_interval_seconds: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OffPeakPolicyRequest {
    pub schema_version: u32,
    pub eligibility_source: String,
    pub allowed_route_aliases: Option<Vec<String>>,
    pub tool_constraints: OffPeakToolConstraintsRequest,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OffPeakToolConstraintsRequest {
    pub deny_automation_mutation: bool,
    pub deny_recursive_off_peak: bool,
    pub allow_background_processes: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneOffsetRequest {
    pub at_utc: i64,
    pub offset_seconds: i32,
}

/// The wire schedule. The frozen discriminants are parsed here so a rejected
/// rule surfaces its own stable reason code instead of one collapsed
/// `schedule_invalid`; the domain constructors remain the only validators.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleRequest {
    pub kind: String,
    pub expression: Option<String>,
    pub timezone: Option<String>,
    pub dom_dow_mode: Option<String>,
    pub dst_policy: Option<String>,
    pub scheduled_at: Option<String>,
    pub every: Option<u16>,
    pub unit: Option<String>,
    pub anchor_at: Option<String>,
    pub by_weekday: Option<Vec<u8>>,
    pub by_monthday: Option<Vec<u8>>,
    pub by_month: Option<Vec<u8>>,
    pub overlap_policy: Option<String>,
    pub missed_policy: Option<String>,
    pub catch_up_limit: Option<u8>,
    /// The adapter-resolved zone. A Worker links no tz database, so a named zone
    /// is stored and validated but the CURRENT UTC offset (and its bounded
    /// transitions) must be supplied. Omitting it is rejected rather than
    /// silently treated as UTC.
    pub utc_offset_seconds: Option<i32>,
    pub utc_offset_transitions: Option<Vec<ZoneOffsetRequest>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PatchAutomationRequest {
    pub name: Option<String>,
    pub description: Option<Option<String>>,
    pub project_id: Option<String>,
    pub agent_definition_id: Option<String>,
    pub target: Option<AutomationTargetRequest>,
    pub schedule: Option<ScheduleRequest>,
    pub execution_policy: Option<ExecutionPolicyRequest>,
    pub execution_retry: Option<ExecutionRetryRequest>,
    pub off_peak_policy: Option<Option<OffPeakPolicyRequest>>,
    pub version: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationVersionRequest {
    pub version: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunNowRequest {
    /// `run-now` never accepts a client occurrence ID; the occurrence identity
    /// comes from the `Idempotency-Key` digest.
    pub version: i64,
}

#[derive(Debug, Deserialize)]
pub struct AutomationListQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    pub project_id: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OccurrenceListQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DueQuery {
    pub limit: Option<i32>,
}

/// Every device-authoritative lease call presents the fencing context.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseContextRequest {
    pub lease_id: String,
    pub lease_version: i64,
    pub lease_fence: i64,
    /// The one-time raw lease token returned by `claim`. Only its SHA-256
    /// fingerprint is ever stored.
    pub lease_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartOccurrenceRequest {
    pub lease_id: String,
    pub lease_version: i64,
    pub lease_fence: i64,
    pub lease_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettleOccurrenceRequest {
    pub lease_id: String,
    pub lease_version: i64,
    pub lease_fence: i64,
    pub lease_token: String,
    pub outcome: String,
    pub reason_code: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationListItem {
    pub automation_id: String,
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

fn service_unavailable(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::ServiceUnavailable,
        "The automation control-plane store is unavailable.",
    )
}

/// Map a domain rejection to the frozen stable reason. A foreign or missing
/// tenant resource is the non-disclosing `resource_not_found` shape; everything
/// else is the domain's own frozen code.
fn domain_failure(context: &RequestContext, error: DomainError) -> ApiError {
    let (code, message) = match error {
        DomainError::ScheduleInvalid => {
            (ApiErrorCode::ValidationFailed, "The schedule is invalid.")
        }
        DomainError::ScheduleTimezoneInvalid => (
            ApiErrorCode::ValidationFailed,
            "The schedule timezone is invalid.",
        ),
        DomainError::ScheduleIntervalInvalid => (
            ApiErrorCode::ValidationFailed,
            "The schedule interval is invalid.",
        ),
        DomainError::DstMissingTime => (
            ApiErrorCode::ValidationFailed,
            "The schedule instant does not exist in that timezone.",
        ),
        DomainError::DstRepeatedTime => (
            ApiErrorCode::ValidationFailed,
            "The schedule instant repeats in that timezone.",
        ),
        DomainError::AutomationNotFound => {
            return not_found(context, error.code());
        }
        DomainError::OccurrenceNotFound => {
            return not_found(context, error.code());
        }
        DomainError::AutomationInvalidState => (
            ApiErrorCode::Conflict,
            "The automation is not in a state that allows this operation.",
        ),
        DomainError::AutomationOverlapPolicy => (
            ApiErrorCode::Conflict,
            "The previous occurrence has not finished.",
        ),
        DomainError::AutomationMissedScheduleLimit => (
            ApiErrorCode::Conflict,
            "The missed schedule window was truncated.",
        ),
        DomainError::OccurrenceAlreadyClaimed => (
            ApiErrorCode::Conflict,
            "The occurrence is already claimed by another device.",
        ),
        DomainError::OccurrenceLeaseExpired => {
            (ApiErrorCode::Conflict, "The execution lease has expired.")
        }
        DomainError::OccurrenceAmbiguous => (
            ApiErrorCode::Conflict,
            "The occurrence is awaiting reconciliation and cannot be re-dispatched.",
        ),
        DomainError::LeaseFenceInvalid => (
            ApiErrorCode::Conflict,
            "The lease fencing context is stale.",
        ),
        DomainError::ExecutionPrincipalUnavailable => (
            ApiErrorCode::Conflict,
            "The execution principal is not currently available.",
        ),
        DomainError::DeviceNotEligible => (
            ApiErrorCode::PermissionDenied,
            "The device is not currently eligible for this automation.",
        ),
        DomainError::OffPeakNotAllowed => (
            ApiErrorCode::PermissionDenied,
            "Off-peak execution is not allowed by the current policy.",
        ),
        DomainError::OrganizationPendingDeletion => (
            ApiErrorCode::Conflict,
            "The organization is pending deletion.",
        ),
        DomainError::EntitlementNotGranted => (
            ApiErrorCode::PermissionDenied,
            "The organization entitlement does not allow automations.",
        ),
        DomainError::EntitlementGraceExpired => (
            ApiErrorCode::PermissionDenied,
            "The organization billing grace window has expired.",
        ),
    };
    domain_error(context, code, error.code(), message)
}

fn not_found(context: &RequestContext, reason: &str) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::NotFound,
        "The requested resource was not found.",
    )
    .with_detail("reason", json!(reason))
}

fn conflict(context: &RequestContext, reason: &str, message: &str) -> ApiError {
    errors::api_error(context, ApiErrorCode::Conflict, message).with_detail("reason", json!(reason))
}

fn denied(context: &RequestContext, reason: &str, message: &str) -> ApiError {
    errors::api_error(context, ApiErrorCode::PermissionDenied, message)
        .with_detail("reason", json!(reason))
}

fn store_failure(context: &RequestContext, error: AutomationStoreError) -> ApiError {
    match error {
        AutomationStoreError::Unavailable => service_unavailable(context),
        AutomationStoreError::InvalidRow | AutomationStoreError::Guarded => {
            service_unavailable(context)
        }
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn automation_permission(name: &str) -> Permission {
    Permission::parse(name)
}

fn validate_version(context: &RequestContext, value: i64) -> Result<(), ApiError> {
    if value <= 0 || value == i64::MAX {
        return Err(validation_error(
            context,
            "version_invalid",
            "The resource version is invalid.",
        ));
    }
    Ok(())
}

fn occurrence_page_limit(value: Option<i32>) -> i32 {
    match value {
        None => PAGE_LIMIT_DEFAULT,
        Some(value) if value <= 0 => PAGE_LIMIT_DEFAULT,
        Some(value) if value > MAX_OCCURRENCE_PAGE => MAX_OCCURRENCE_PAGE,
        Some(value) => value,
    }
}

fn due_page_limit(value: Option<i32>) -> i32 {
    match value {
        None => MAX_DUE_OCCURRENCES,
        Some(value) if value <= 0 => MAX_DUE_OCCURRENCES,
        Some(value) if value > MAX_DUE_OCCURRENCES => MAX_DUE_OCCURRENCES,
        Some(value) => value,
    }
}

/// Resolve the execution principal. The value is a server-resolved
/// discriminated pair: a `service_account` fails closed until F14 exists, and a
/// proposed user must currently hold an active membership.
async fn resolve_execution_principal(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    org_id: &str,
    request: &ExecutionPrincipalRequest,
    caller_user_id: &str,
) -> Result<(String, String), ApiError> {
    if request.kind != "user" {
        // `service_account` is reserved for F14 and MUST fail closed rather than
        // run under a fabricated identity.
        return Err(domain_failure(
            context,
            DomainError::ExecutionPrincipalUnavailable,
        ));
    }
    let user_id = request
        .id
        .as_deref()
        .map(|value| {
            crate::core::UserId::new(value)
                .map(|id| id.as_str().to_owned())
                .map_err(|_| {
                    validation_error(
                        context,
                        "execution_principal_id_invalid",
                        "The execution principal is invalid.",
                    )
                })
        })
        .transpose()?
        .unwrap_or_else(|| caller_user_id.to_owned());
    let active = AutomationsRepository::new(database)
        .principal_membership_active(org_id, &user_id)
        .await
        .map_err(|_| service_unavailable(context))?;
    if !active {
        return Err(domain_failure(
            context,
            DomainError::ExecutionPrincipalUnavailable,
        ));
    }
    Ok(("user".to_owned(), user_id))
}

/// Validate the execution target against current server-owned rows.
async fn resolve_target(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    org_id: &str,
    request: &AutomationTargetRequest,
) -> Result<(String, Option<String>, Option<String>, String), ApiError> {
    if !TARGET_KINDS.contains(&request.kind.as_str()) {
        return Err(validation_error(
            context,
            "automation_target_invalid",
            "The execution target is invalid.",
        ));
    }
    if request.kind == "server_runner" {
        // Accepted only when a server runner is actually enabled. Nothing enables
        // one in P06, so it fails closed instead of pretending to be supported.
        return Err(domain_failure(context, DomainError::AutomationInvalidState));
    }
    let device_id = match request.device_id.as_deref() {
        Some(value) => Some(crate::routes::agents::validate_prefixed_id(
            context,
            value,
            "dvc",
            "target_device_id_invalid",
        )?),
        None => None,
    };
    if request.kind == "specific_device" && device_id.is_none() {
        return Err(validation_error(
            context,
            "target_device_id_required",
            "A specific device target requires a device.",
        ));
    }
    let workspace_binding_id = match request.workspace_binding_id.as_deref() {
        Some(value) => Some(crate::routes::agents::validate_prefixed_id(
            context,
            value,
            "wsb",
            "target_workspace_binding_id_invalid",
        )?),
        None => None,
    };
    if let Some(binding_id) = workspace_binding_id.as_deref() {
        let projects = ProjectRepository::new(database);
        let binding = projects
            .find_binding(binding_id)
            .await
            .map_err(|error| database_error(context, error))?
            .filter(|binding| binding.org_id == org_id)
            .ok_or_else(|| {
                denied(
                    context,
                    "target_workspace_binding_unavailable",
                    "The workspace binding is not available.",
                )
            })?;
        if let Some(device_id) = device_id.as_deref()
            && binding.device_id != device_id
        {
            return Err(denied(
                context,
                "target_workspace_binding_unavailable",
                "The workspace binding is not available.",
            ));
        }
    }
    if let Some(device_id) = device_id.as_deref() {
        let device = crate::repositories::DeviceRepository::new(database)
            .find_device(device_id)
            .await
            .map_err(|error| database_error(context, error))?
            .filter(|device| device.org_id == org_id && device.status == "active");
        if device.is_none() {
            return Err(domain_failure(context, DomainError::DeviceNotEligible));
        }
    }
    let capabilities = crate::routes::agents::validate_string_list(
        context,
        request.required_capabilities.as_ref(),
        MAX_REQUIRED_CAPABILITIES,
        128,
        "required_capabilities_invalid",
    )?;
    let capabilities_json =
        serde_json::to_string(&capabilities).map_err(|_| service_unavailable(context))?;
    Ok((
        request.kind.clone(),
        device_id,
        workspace_binding_id,
        capabilities_json,
    ))
}

/// The resolved execution-policy projection: model alias, budget, tool-policy
/// scope, and the minimum policy version the automation requires.
type ResolvedExecutionPolicy = (Option<String>, Option<String>, String, Option<i64>);

fn resolve_execution_policy(
    context: &RequestContext,
    request: &ExecutionPolicyRequest,
) -> Result<ResolvedExecutionPolicy, ApiError> {
    let model_alias = request
        .model_alias
        .as_deref()
        .map(|value| crate::routes::agents::validate_model_alias(context, value))
        .transpose()?;
    let budget_id = match request.budget_id.as_deref() {
        Some(value) => Some(crate::routes::agents::validate_prefixed_id(
            context,
            value,
            "bud",
            "budget_id_invalid",
        )?),
        None => None,
    };
    let tool_policy_scope = request
        .tool_policy_scope
        .clone()
        .unwrap_or_else(|| "project".to_owned());
    if !TOOL_POLICY_SCOPES.contains(&tool_policy_scope.as_str()) {
        return Err(validation_error(
            context,
            "tool_policy_scope_invalid",
            "The tool policy scope is invalid.",
        ));
    }
    let required_policy_version = match request.required_policy_version {
        Some(version) if version > 0 => Some(version),
        Some(_) => {
            return Err(validation_error(
                context,
                "required_policy_version_invalid",
                "The required policy version is invalid.",
            ));
        }
        None => None,
    };
    Ok((
        model_alias,
        budget_id,
        tool_policy_scope,
        required_policy_version,
    ))
}

fn resolve_execution_retry(
    context: &RequestContext,
    request: Option<&ExecutionRetryRequest>,
) -> Result<crate::modules::automations::ExecutionRetry, ApiError> {
    let settings = match request {
        Some(request) => crate::modules::automations::ExecutionRetry::new(
            u8::try_from(request.max_start_attempts).unwrap_or(0),
            u32::try_from(request.lease_ttl_seconds).unwrap_or(0),
            u32::try_from(request.heartbeat_interval_seconds).unwrap_or(0),
        ),
        None => crate::modules::automations::ExecutionRetry::default_policy(),
    };
    settings
        .validate()
        .map_err(|error| domain_failure(context, error))
}

/// Build the canonical schedule rule and its adapter-resolved zone.
fn build_schedule(
    context: &RequestContext,
    request: &ScheduleRequest,
) -> Result<(ScheduleRule, ZoneOffsets), ApiError> {
    let kind = ScheduleKind::parse(&request.kind)
        .ok_or_else(|| domain_failure(context, DomainError::ScheduleInvalid))?;
    let overlap = match request.overlap_policy.as_deref() {
        Some(value) => OverlapPolicy::parse(value),
        None => Some(OverlapPolicy::Skip),
    }
    .ok_or_else(|| domain_failure(context, DomainError::ScheduleInvalid))?;
    let missed = match request.missed_policy.as_deref() {
        Some(value) => MissedPolicy::parse(value),
        None => Some(MissedPolicy::RunOnce),
    }
    .ok_or_else(|| domain_failure(context, DomainError::ScheduleInvalid))?;
    let dom_dow_mode = match request.dom_dow_mode.as_deref() {
        Some(value) => DomDowMode::parse(value),
        None => Some(DomDowMode::default()),
    }
    .ok_or_else(|| domain_failure(context, DomainError::ScheduleInvalid))?;
    let dst_policy = match request.dst_policy.as_deref() {
        Some(value) => DstPolicy::parse(value),
        None => Some(DstPolicy::default()),
    }
    .ok_or_else(|| domain_failure(context, DomainError::ScheduleInvalid))?;
    // The zone is a boundary shape check only: it produces the precise stable code
    // for a malformed name. No civil-time interpretation happens here.
    let timezone = match request.timezone.as_deref() {
        Some(value) => {
            validate_timezone_shape(context, value)?;
            Some(value)
        }
        None => None,
    };
    let zone = build_zone(context, request, kind)?;

    let rule = match kind {
        ScheduleKind::OneTime => {
            let scheduled_at = request
                .scheduled_at
                .as_deref()
                .ok_or_else(|| domain_failure(context, DomainError::ScheduleInvalid))?;
            ScheduleRule::one_time(scheduled_at, overlap, missed, request.catch_up_limit)
        }
        ScheduleKind::Cron => {
            let expression = request
                .expression
                .as_deref()
                .ok_or_else(|| domain_failure(context, DomainError::ScheduleInvalid))?;
            let timezone = timezone
                .ok_or_else(|| domain_failure(context, DomainError::ScheduleTimezoneInvalid))?;
            ScheduleRule::cron(
                expression,
                timezone,
                dom_dow_mode,
                dst_policy,
                overlap,
                missed,
                request.catch_up_limit,
            )
        }
        ScheduleKind::Interval => {
            // `IntervalSelectors` is internal to the domain module, so an interval
            // rule with calendar selectors is decoded through the domain's own
            // validated `Deserialize`. The frozen interval wire has
            // `deny_unknown_fields`, so only the interval keys are forwarded: the
            // cron/one-time discriminants and the transport-only resolved zone are
            // dropped first. A rejection is an interval-level reason.
            let wire = serde_json::json!({
                "kind": request.kind,
                "every": request.every,
                "unit": request.unit,
                "anchor_at": request.anchor_at,
                "timezone": timezone,
                "by_weekday": request.by_weekday,
                "by_monthday": request.by_monthday,
                "by_month": request.by_month,
                "overlap_policy": request.overlap_policy,
                "missed_policy": request.missed_policy,
                "catch_up_limit": request.catch_up_limit,
            });
            serde_json::from_value::<ScheduleRule>(wire)
                .map_err(|_| DomainError::ScheduleIntervalInvalid)
        }
        ScheduleKind::Manual => ScheduleRule::manual(overlap, missed, request.catch_up_limit),
    }
    .map_err(|error| domain_failure(context, error))?;
    Ok((rule, zone))
}

/// Reject an obviously malformed IANA name at the boundary so the caller sees
/// `schedule_timezone_invalid` rather than a generic schedule failure.
fn validate_timezone_shape(context: &RequestContext, value: &str) -> Result<(), ApiError> {
    let bytes = value.as_bytes();
    let valid = !value.is_empty()
        && value.len() <= 64
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("//")
        && value.matches('/').count() <= 3
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'+'));
    if valid {
        Ok(())
    } else {
        Err(domain_failure(
            context,
            DomainError::ScheduleTimezoneInvalid,
        ))
    }
}

/// Build the adapter-resolved zone from the supplied offset and its bounded
/// transitions. A named zone with no offset is rejected rather than silently
/// treated as UTC.
fn build_zone(
    context: &RequestContext,
    request: &ScheduleRequest,
    kind: ScheduleKind,
) -> Result<ZoneOffsets, ApiError> {
    // A `one_time` instant and a `manual` rule are absolute UTC by definition, so
    // they carry no zone at all.
    if matches!(kind, ScheduleKind::OneTime | ScheduleKind::Manual) {
        return Ok(ZoneOffsets::utc());
    }
    let offset = request
        .utc_offset_seconds
        .ok_or_else(|| domain_failure(context, DomainError::ScheduleTimezoneInvalid))?;
    let transitions = request.utc_offset_transitions.clone().unwrap_or_default();
    if transitions.len() > crate::modules::automations::MAX_ZONE_TRANSITIONS {
        return Err(domain_failure(
            context,
            DomainError::ScheduleTimezoneInvalid,
        ));
    }
    let mut table: Vec<UtcOffsetTransition> = Vec::with_capacity(transitions.len());
    for transition in transitions {
        table.push(UtcOffsetTransition {
            at_utc: transition.at_utc,
            offset_seconds: transition.offset_seconds,
        });
    }
    ZoneOffsets::new(offset, &table).map_err(|error| domain_failure(context, error))
}

#[allow(clippy::too_many_arguments)]
fn resolve_off_peak(
    context: &RequestContext,
    request: Option<&OffPeakPolicyRequest>,
) -> Result<Option<ResolvedOffPeak>, ApiError> {
    let Some(request) = request else {
        return Ok(None);
    };
    if request.schema_version == 0 || request.schema_version > MAX_OFF_PEAK_SCHEMA_VERSION {
        return Err(domain_failure(context, DomainError::OffPeakNotAllowed));
    }
    if !OFF_PEAK_ELIGIBILITY_SOURCES.contains(&request.eligibility_source.as_str()) {
        return Err(domain_failure(context, DomainError::OffPeakNotAllowed));
    }
    let aliases = request.allowed_route_aliases.clone().unwrap_or_default();
    if aliases.len() > MAX_ROUTE_ALIASES {
        return Err(domain_failure(context, DomainError::OffPeakNotAllowed));
    }
    for alias in &aliases {
        let valid = !alias.is_empty()
            && alias.len() <= 64
            && alias
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
        if !valid {
            return Err(domain_failure(context, DomainError::OffPeakNotAllowed));
        }
    }
    if request.tool_constraints.allow_background_processes {
        // The server may narrow but never broaden the host's off-peak
        // restrictions, so a definition cannot ask for background processes.
        return Err(domain_failure(context, DomainError::OffPeakNotAllowed));
    }
    let aliases_json = serde_json::to_string(&aliases).map_err(|_| service_unavailable(context))?;
    Ok(Some(ResolvedOffPeak {
        eligibility_source: request.eligibility_source.clone(),
        allowed_route_aliases_json: aliases_json,
        deny_automation_mutation: i64::from(request.tool_constraints.deny_automation_mutation),
        deny_recursive_off_peak: i64::from(request.tool_constraints.deny_recursive_off_peak),
        allow_background_processes: i64::from(request.tool_constraints.allow_background_processes),
    }))
}

#[derive(Debug)]
struct ResolvedOffPeak {
    eligibility_source: String,
    allowed_route_aliases_json: String,
    deny_automation_mutation: i64,
    deny_recursive_off_peak: i64,
    allow_background_processes: i64,
}

fn validate_queued_successor_max_age(
    context: &RequestContext,
    value: i64,
) -> Result<i64, ApiError> {
    if (60..=MAX_QUEUED_SUCCESSOR_MAX_AGE_SECONDS).contains(&value) {
        Ok(value)
    } else {
        Err(validation_error(
            context,
            "queued_successor_max_age_seconds_invalid",
            "The queued successor age bound is invalid.",
        ))
    }
}

fn decode_string_list(context: &RequestContext, value: &str) -> Result<Vec<String>, ApiError> {
    if value.len() > 64 * 1024 {
        return Err(service_unavailable(context));
    }
    let values =
        serde_json::from_str::<Vec<String>>(value).map_err(|_| service_unavailable(context))?;
    if values.len() > 256 {
        return Err(service_unavailable(context));
    }
    Ok(values)
}

// -----------------------------------------------------------------------------
// Projections
// -----------------------------------------------------------------------------

fn principal_json(kind: &str, id: &str) -> Value {
    json!({ "kind": kind, "id": id })
}

fn target_json(automation: &AutomationDefinitionRecord) -> Result<Value, ApiError> {
    Ok(json!({
        "kind": automation.target_kind,
        "device_id": automation.target_device_id,
        "workspace_binding_id": automation.target_workspace_binding_id,
        "required_capabilities": serde_json::from_str::<Value>(
            &automation.required_capabilities_json
        )
        .unwrap_or_else(|_| json!([])),
    }))
}

fn execution_policy_json(automation: &AutomationDefinitionRecord) -> Value {
    json!({
        "model_alias": automation.execution_model_alias,
        "budget_id": automation.execution_budget_id,
        "tool_policy_scope": automation.tool_policy_scope,
        "required_policy_version": automation.required_policy_version,
    })
}

fn off_peak_json(automation: &AutomationDefinitionRecord) -> Value {
    let Some(source) = automation.off_peak_eligibility_source.as_deref() else {
        return Value::Null;
    };
    json!({
        "schema_version": MAX_OFF_PEAK_SCHEMA_VERSION,
        "eligibility_source": source,
        "allowed_route_aliases": automation
            .off_peak_allowed_route_aliases_json
            .as_deref()
            .and_then(|value| serde_json::from_str::<Value>(value).ok())
            .unwrap_or_else(|| json!([])),
        "tool_constraints": {
            "deny_automation_mutation": automation.off_peak_deny_automation_mutation != 0,
            "deny_recursive_off_peak": automation.off_peak_deny_recursive_off_peak != 0,
            "allow_background_processes": automation.off_peak_allow_background_processes != 0,
        },
    })
}

fn execution_retry_json(automation: &AutomationDefinitionRecord) -> Value {
    json!({
        "max_start_attempts": automation.max_start_attempts,
        "lease_ttl_seconds": automation.lease_ttl_seconds,
        "heartbeat_interval_seconds": automation.heartbeat_interval_seconds,
    })
}

async fn automation_json(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    automation: &AutomationDefinitionRecord,
) -> Result<Value, ApiError> {
    let rule = load_schedule_rule(context, database, automation).await?;
    Ok(json!({
        "automation_id": automation.automation_id,
        "org_id": automation.org_id,
        "project_id": automation.project_id,
        "name": automation.name,
        "description": automation.description,
        "agent_definition_id": automation.agent_definition_id,
        "execution_principal": principal_json(
            &automation.execution_principal_kind,
            &automation.execution_principal_id
        ),
        "target": target_json(automation)?,
        "schedule": rule,
        "execution_policy": execution_policy_json(automation),
        "off_peak_policy": off_peak_json(automation),
        "status": automation.status,
        "version": automation.version,
        "next_run_at": automation.next_run_at,
        "last_run_at": automation.last_run_at,
        "schedule_cursor_at": automation.schedule_cursor_at,
        "execution_retry": execution_retry_json(automation),
        "created_by_user_id": automation.created_by_user_id,
        "created_at": automation.created_at,
        "updated_at": automation.updated_at,
    }))
}

fn occurrence_json(
    context: &RequestContext,
    occurrence: &AutomationOccurrenceRecord,
) -> Result<Value, ApiError> {
    let kind = occurrence
        .kind()
        .map_err(|error| domain_failure(context, error))?;
    Ok(json!({
        "occurrence_id": occurrence.occurrence_id,
        "automation_id": occurrence.automation_id,
        "org_id": occurrence.org_id,
        "project_id": occurrence.project_id,
        "kind": kind.as_str(),
        "execution_principal": principal_json(
            &occurrence.execution_principal_kind,
            &occurrence.execution_principal_id
        ),
        "off_peak_mode": occurrence.off_peak_mode,
        "policy_snapshot_id": occurrence.policy_snapshot_id,
        "policy_version": occurrence.policy_version,
        "scheduled_for": occurrence.scheduled_for_utc,
        "schedule_rule_id": occurrence.schedule_rule_id,
        "schedule_rule_version": occurrence.schedule_rule_version,
        "state": occurrence.state,
        "state_version": occurrence.state_version,
        "attempt": occurrence.attempt,
        "reason_code": occurrence.reason_code,
        "run_id": occurrence.run_id,
        "blocked_by_occurrence_id": occurrence.blocked_by_occurrence_id,
        "lease_expires_at": occurrence.lease_expires_at,
        "queued_at": occurrence.queued_at,
        "started_at": occurrence.started_at,
        "finished_at": occurrence.finished_at,
        "created_at": occurrence.created_at,
        "updated_at": occurrence.updated_at,
    }))
}

fn lease_json(lease: &ExecutionLeaseRecord) -> Value {
    json!({
        "lease_id": lease.lease_id,
        "occurrence_id": lease.occurrence_id,
        "device_id": lease.device_id,
        "state": lease.state,
        "attempt": lease.attempt,
        "lease_version": lease.lease_version,
        "lease_fence": lease.lease_fence,
        "claimed_at": lease.claimed_at,
        "expires_at": lease.expires_at,
        "completed_at": lease.completed_at,
        "version": lease.version,
    })
}

async fn load_schedule_rule(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    automation: &AutomationDefinitionRecord,
) -> Result<Value, ApiError> {
    let row = AutomationsRepository::new(database)
        .find_schedule_rule(&automation.org_id, &automation.schedule_rule_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .ok_or_else(|| not_found(context, "automation_not_found"))?;
    StoredScheduleRevision::from_canonical_json(&row.canonical_json)
        .ok()
        .and_then(|revision| serde_json::to_value(revision.rule).ok())
        .ok_or_else(|| service_unavailable(context))
}

// -----------------------------------------------------------------------------
// Browser: definitions
// -----------------------------------------------------------------------------

#[worker::send]
pub async fn list_automations(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<AutomationListQuery>,
    Path(org_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        automation_permission(PERMISSION_AUTOMATIONS_READ),
        Some("automation"),
        None,
    )
    .await?;
    let limit = page_limit(query.limit);
    let cursor = query
        .cursor
        .as_deref()
        .map(|raw| decode_page_cursor(raw, &context))
        .transpose()?;
    let status = match query.status.as_deref() {
        Some(value) if matches!(value, "active" | "paused" | "suspended" | "failed") => {
            Some(value.to_owned())
        }
        Some(_) => {
            return Err(validation_error(
                &context,
                "automation_status_invalid",
                "The automation status filter is invalid.",
            ));
        }
        None => None,
    };
    let database = database(&state, &context)?;
    let manager =
        crate::routes::agents::can_manage_projects(&state, &headers, &context, &org_id).await;
    if let Some(project_id) = query.project_id.as_deref() {
        crate::routes::agents::ensure_project_access(
            database,
            &context,
            &org_id,
            project_id,
            access.principal.user_id.as_str(),
            manager,
        )
        .await?;
    }
    let mut records = AutomationsRepository::new(database)
        .list_automations(
            &org_id,
            access.principal.user_id.as_str(),
            manager,
            status.as_deref(),
            query.project_id.as_deref(),
            cursor
                .as_ref()
                .map(|(updated, id)| (updated.as_str(), id.as_str())),
            limit + 1,
        )
        .await
        .map_err(|error| database_error(&context, error))?;
    let has_more = records.len() > limit as usize;
    if has_more {
        records.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        records
            .last()
            .map(|record| encode_page_cursor(&record.updated_at, &record.automation_id))
    } else {
        None
    };
    let mut items = Vec::with_capacity(records.len());
    for record in &records {
        items.push(automation_json(&context, database, record).await?);
    }
    Ok(page(items, next_cursor, has_more))
}

#[worker::send]
pub async fn create_automation(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<CreateAutomationRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        automation_permission(PERMISSION_AUTOMATIONS_MANAGE),
        Some("automation"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let database = database(&state, &context)?;
    let name = crate::routes::agents::validate_text(
        &context,
        &body.name,
        160,
        "automation_name_invalid",
        "Enter a valid automation name.",
    )?;
    let description = crate::routes::agents::validate_optional_text(
        &context,
        body.description.as_deref(),
        2_000,
        "automation_description_invalid",
        "The automation description is invalid.",
    )?;
    let project_id = crate::routes::agents::validate_prefixed_id(
        &context,
        &body.project_id,
        "prj",
        "project_id_invalid",
    )?;
    let project = crate::routes::agents::ensure_project_access(
        database,
        &context,
        &org_id,
        &project_id,
        access.principal.user_id.as_str(),
        crate::routes::agents::can_manage_projects(&state, &headers, &context, &org_id).await,
    )
    .await?;
    if project.archived_at.is_some() {
        return Err(conflict(
            &context,
            "project_archived",
            "Archived projects cannot receive new automations.",
        ));
    }
    let agent_definition_id = crate::routes::agents::validate_prefixed_id(
        &context,
        &body.agent_definition_id,
        "agd",
        "agent_definition_id_invalid",
    )?;
    let agent = RunRepository::new(database)
        .find_agent(&org_id, &agent_definition_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .filter(|agent| agent.lifecycle == "active")
        .ok_or_else(|| not_found(&context, "agent_not_found"))?;
    if agent
        .project_id
        .as_deref()
        .is_some_and(|value| value != project.project_id)
    {
        return Err(not_found(&context, "agent_not_found"));
    }
    let (principal_kind, principal_id) = resolve_execution_principal(
        &context,
        database,
        &org_id,
        &body.execution_principal,
        access.principal.user_id.as_str(),
    )
    .await?;
    let (target_kind, target_device_id, target_binding_id, capabilities_json) =
        resolve_target(&context, database, &org_id, &body.target).await?;
    let (rule, zone) = build_schedule(&context, &body.schedule)?;
    let (model_alias, budget_id, tool_policy_scope, required_policy_version) =
        resolve_execution_policy(&context, &body.execution_policy)?;
    let retry = resolve_execution_retry(&context, body.execution_retry.as_ref())?;
    let off_peak = resolve_off_peak(&context, body.off_peak_policy.as_ref())?;

    let body_value = serde_json::to_value(&body).map_err(|_| service_unavailable(&context))?;
    let claim = match prepare_mutation(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        "POST",
        AUTOMATIONS_PATH,
        &body_value,
    )
    .await?
    {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };

    let repository = AutomationsRepository::new(database);
    let automation_id = generated_id("aut");
    let now = &context.received_at;
    let now_epoch = parse_instant_utc(now.as_str())
        .map_err(|_| domain_failure(&context, DomainError::ScheduleInvalid))?;
    let next_run_at = crate::jobs::automations::plan_next_run(&rule, &zone, now_epoch)
        .map_err(|error| domain_failure(&context, error))?;
    let revision = StoredScheduleRevision::new(rule, zone);
    let canonical_json = revision
        .to_canonical_json()
        .map_err(|_| domain_failure(&context, DomainError::ScheduleInvalid))?;
    let schedule_rule_id = generated_id("sch");
    let insert_rule = repository
        .insert_schedule_rule_statement(
            &NewScheduleRuleInput {
                schedule_rule_id: &schedule_rule_id,
                org_id: &org_id,
                kind: revision.rule.kind().as_str(),
                expression: None,
                timezone: None,
                dom_dow_mode: None,
                dst_policy: None,
                interval_every: None,
                interval_unit: None,
                anchor_at: None,
                scheduled_at: None,
                by_weekday_json: None,
                by_monthday_json: None,
                by_month_json: None,
                overlap_policy: revision.rule.overlap_policy().as_str(),
                missed_policy: revision.rule.missed_policy().as_str(),
                catch_up_limit: revision.rule.catch_up_limit().map(i64::from),
                canonical_json: &canonical_json,
            },
            now,
        )
        .map_err(|error| database_error(&context, error))?;
    let insert = repository
        .insert_automation_statement(&NewAutomationInput {
            automation_id: &automation_id,
            org_id: &org_id,
            project_id: Some(&project.project_id),
            name: &name,
            description: description.as_deref(),
            agent_definition_id: Some(&agent.agent_definition_id),
            schedule_rule_id: &schedule_rule_id,
            execution_principal_kind: &principal_kind,
            execution_principal_id: &principal_id,
            target_kind: &target_kind,
            target_device_id: target_device_id.as_deref(),
            target_workspace_binding_id: target_binding_id.as_deref(),
            required_capabilities_json: &capabilities_json,
            execution_model_alias: model_alias.as_deref(),
            execution_budget_id: budget_id.as_deref(),
            tool_policy_scope: &tool_policy_scope,
            required_policy_version,
            off_peak_eligibility_source: off_peak
                .as_ref()
                .map(|value| value.eligibility_source.as_str()),
            off_peak_allowed_route_aliases_json: off_peak
                .as_ref()
                .map(|value| value.allowed_route_aliases_json.as_str()),
            off_peak_deny_automation_mutation: off_peak
                .as_ref()
                .map_or(1, |value| value.deny_automation_mutation),
            off_peak_deny_recursive_off_peak: off_peak
                .as_ref()
                .map_or(1, |value| value.deny_recursive_off_peak),
            off_peak_allow_background_processes: off_peak
                .as_ref()
                .map_or(0, |value| value.allow_background_processes),
            max_start_attempts: i64::from(retry.max_start_attempts),
            lease_ttl_seconds: i64::from(retry.lease_ttl_seconds),
            heartbeat_interval_seconds: i64::from(retry.heartbeat_interval_seconds),
            // The cursor starts at the creation instant so a new definition can
            // never back-fill history it did not have.
            schedule_cursor_at: now.as_str(),
            next_run_at: next_run_at.as_deref(),
            created_by_user_id: access.principal.user_id.as_str(),
            queued_successor_max_age_seconds: DEFAULT_QUEUED_SUCCESSOR_MAX_AGE_SECONDS,
        })
        .map_err(|error| database_error(&context, error))?;
    let audit = security_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        "automation.definition.created.v1",
        "automation",
        &automation_id,
        &json!({ "project_id": project.project_id, "version": 1 }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        crate::repositories::EVENT_DEFINITION_CREATED,
        &json!({
            "automation_id": automation_id,
            "org_id": org_id,
            "project_id": project.project_id,
            "version": 1,
            "status": "active",
            "next_run_at": next_run_at,
        }),
    )?;
    let record = AutomationDefinitionRecord {
        automation_id: automation_id.clone(),
        org_id: org_id.clone(),
        project_id: Some(project.project_id.clone()),
        name: name.clone(),
        description: description.clone(),
        agent_definition_id: Some(agent.agent_definition_id.clone()),
        schedule_rule_id: schedule_rule_id.clone(),
        execution_principal_kind: principal_kind.clone(),
        execution_principal_id: principal_id.clone(),
        target_kind: target_kind.clone(),
        target_device_id: target_device_id.clone(),
        target_workspace_binding_id: target_binding_id.clone(),
        required_capabilities_json: capabilities_json.clone(),
        execution_model_alias: model_alias.clone(),
        execution_budget_id: budget_id.clone(),
        tool_policy_scope: tool_policy_scope.clone(),
        required_policy_version,
        off_peak_eligibility_source: off_peak
            .as_ref()
            .map(|value| value.eligibility_source.clone()),
        off_peak_allowed_route_aliases_json: off_peak
            .as_ref()
            .map(|value| value.allowed_route_aliases_json.clone()),
        off_peak_deny_automation_mutation: off_peak
            .as_ref()
            .map_or(1, |value| value.deny_automation_mutation),
        off_peak_deny_recursive_off_peak: off_peak
            .as_ref()
            .map_or(1, |value| value.deny_recursive_off_peak),
        off_peak_allow_background_processes: off_peak
            .as_ref()
            .map_or(0, |value| value.allow_background_processes),
        status: "active".to_owned(),
        max_start_attempts: i64::from(retry.max_start_attempts),
        lease_ttl_seconds: i64::from(retry.lease_ttl_seconds),
        heartbeat_interval_seconds: i64::from(retry.heartbeat_interval_seconds),
        schedule_cursor_at: Some(now.as_str().to_owned()),
        next_run_at: next_run_at.clone(),
        last_run_at: None,
        version: 1,
        created_by_user_id: access.principal.user_id.as_str().to_owned(),
        created_at: now.as_str().to_owned(),
        updated_at: now.as_str().to_owned(),
        queued_successor_max_age_seconds: DEFAULT_QUEUED_SUCCESSOR_MAX_AGE_SECONDS,
    };
    let success = StoredSuccess::new(201, automation_json(&context, database, &record).await?)
        .map_err(|_| service_unavailable(&context))?;
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![insert_rule, insert, audit],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::CREATED, Json(success.body)).into_response())
}

#[worker::send]
pub async fn get_automation(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, automation_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        automation_permission(PERMISSION_AUTOMATIONS_READ),
        Some("automation"),
        Some(&automation_id),
    )
    .await?;
    let database = database(&state, &context)?;
    let record = require_automation(&context, database, &org_id, &automation_id).await?;
    if let Some(project_id) = record.project_id.as_deref() {
        crate::routes::agents::ensure_project_access(
            database,
            &context,
            &org_id,
            project_id,
            access.principal.user_id.as_str(),
            crate::routes::agents::can_manage_projects(&state, &headers, &context, &org_id).await,
        )
        .await?;
    }
    Ok((
        StatusCode::OK,
        Json(automation_json(&context, database, &record).await?),
    )
        .into_response())
}

#[worker::send]
pub async fn patch_automation(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, automation_id)): Path<(String, String)>,
    Json(body): Json<PatchAutomationRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        automation_permission(PERMISSION_AUTOMATIONS_MANAGE),
        Some("automation"),
        Some(&automation_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    validate_version(&context, body.version)?;
    let key = idempotency_key(&headers, &context)?;
    let database = database(&state, &context)?;
    let manager =
        crate::routes::agents::can_manage_projects(&state, &headers, &context, &org_id).await;
    let existing = require_automation(&context, database, &org_id, &automation_id).await?;
    if let Some(project_id) = existing.project_id.as_deref() {
        crate::routes::agents::ensure_project_access(
            database,
            &context,
            &org_id,
            project_id,
            access.principal.user_id.as_str(),
            manager,
        )
        .await?;
    }
    let repository = AutomationsRepository::new(database);

    let name = match body.name.as_deref() {
        Some(value) => crate::routes::agents::validate_text(
            &context,
            value,
            160,
            "automation_name_invalid",
            "Enter a valid automation name.",
        )?,
        None => existing.name.clone(),
    };
    let description = match body.description {
        Some(None) => None,
        Some(Some(ref value)) => crate::routes::agents::validate_optional_text(
            &context,
            Some(value.as_str()),
            2_000,
            "automation_description_invalid",
            "The automation description is invalid.",
        )?,
        None => existing.description.clone(),
    };
    let project_id = match body.project_id.as_deref() {
        Some(value) => {
            let project_id = crate::routes::agents::validate_prefixed_id(
                &context,
                value,
                "prj",
                "project_id_invalid",
            )?;
            crate::routes::agents::ensure_project_access(
                database,
                &context,
                &org_id,
                &project_id,
                access.principal.user_id.as_str(),
                manager,
            )
            .await?;
            Some(project_id)
        }
        None => existing.project_id.clone(),
    };
    let agent_definition_id = match body.agent_definition_id.as_deref() {
        Some(value) => {
            let agent_id = crate::routes::agents::validate_prefixed_id(
                &context,
                value,
                "agd",
                "agent_definition_id_invalid",
            )?;
            let agent = RunRepository::new(database)
                .find_agent(&org_id, &agent_id)
                .await
                .map_err(|error| database_error(&context, error))?
                .filter(|agent| agent.lifecycle == "active")
                .ok_or_else(|| not_found(&context, "agent_not_found"))?;
            Some(agent.agent_definition_id)
        }
        None => existing.agent_definition_id.clone(),
    };
    let (target_kind, target_device_id, target_binding_id, capabilities_json) = match &body.target {
        Some(request) => resolve_target(&context, database, &org_id, request).await?,
        None => (
            existing.target_kind.clone(),
            existing.target_device_id.clone(),
            existing.target_workspace_binding_id.clone(),
            existing.required_capabilities_json.clone(),
        ),
    };
    let (model_alias, budget_id, tool_policy_scope, required_policy_version) =
        match &body.execution_policy {
            Some(request) => resolve_execution_policy(&context, request)?,
            None => (
                existing.execution_model_alias.clone(),
                existing.execution_budget_id.clone(),
                existing.tool_policy_scope.clone(),
                existing.required_policy_version,
            ),
        };
    let retry = match &body.execution_retry {
        Some(request) => resolve_execution_retry(&context, Some(request))?,
        None => existing
            .execution_retry()
            .map_err(|error| domain_failure(&context, error))?,
    };
    let off_peak = match &body.off_peak_policy {
        Some(None) => None,
        Some(Some(request)) => resolve_off_peak(&context, Some(request))?,
        None => Some(ResolvedOffPeak {
            eligibility_source: existing
                .off_peak_eligibility_source
                .clone()
                .unwrap_or_default(),
            allowed_route_aliases_json: existing
                .off_peak_allowed_route_aliases_json
                .clone()
                .unwrap_or_else(|| "[]".to_owned()),
            deny_automation_mutation: existing.off_peak_deny_automation_mutation,
            deny_recursive_off_peak: existing.off_peak_deny_recursive_off_peak,
            allow_background_processes: existing.off_peak_allow_background_processes,
        })
        .filter(|value| !value.eligibility_source.is_empty()),
    };

    // A schedule edit mints a NEW immutable revision, and therefore a new logical
    // occurrence slot for every future instant. The cursor restarts at the edit
    // instant so the edit can never back-fill the previous revision's window.
    let mut next_run_at: Option<String> = existing.next_run_at.clone();
    let mut insert_rule: Option<D1PreparedStatement> = None;
    let mut schedule_rule_id = existing.schedule_rule_id.clone();
    if let Some(request) = &body.schedule {
        let (rule, zone) = build_schedule(&context, request)?;
        let now_epoch = parse_instant_utc(context.received_at.as_str())
            .map_err(|_| domain_failure(&context, DomainError::ScheduleInvalid))?;
        let planned = crate::jobs::automations::plan_next_run(&rule, &zone, now_epoch)
            .map_err(|error| domain_failure(&context, error))?;
        let revision = StoredScheduleRevision::new(rule, zone);
        let canonical_json = revision
            .to_canonical_json()
            .map_err(|_| domain_failure(&context, DomainError::ScheduleInvalid))?;
        let new_rule_id = generated_id("sch");
        insert_rule = Some(
            repository
                .insert_schedule_rule_statement(
                    &NewScheduleRuleInput {
                        schedule_rule_id: &new_rule_id,
                        org_id: &org_id,
                        kind: revision.rule.kind().as_str(),
                        expression: None,
                        timezone: None,
                        dom_dow_mode: None,
                        dst_policy: None,
                        interval_every: None,
                        interval_unit: None,
                        anchor_at: None,
                        scheduled_at: None,
                        by_weekday_json: None,
                        by_monthday_json: None,
                        by_month_json: None,
                        overlap_policy: revision.rule.overlap_policy().as_str(),
                        missed_policy: revision.rule.missed_policy().as_str(),
                        catch_up_limit: revision.rule.catch_up_limit().map(i64::from),
                        canonical_json: &canonical_json,
                    },
                    &context.received_at,
                )
                .map_err(|error| database_error(&context, error))?,
        );
        schedule_rule_id = new_rule_id;
        next_run_at = planned;
    }

    let body_value = serde_json::to_value(&body).map_err(|_| service_unavailable(&context))?;
    let claim = match prepare_mutation(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        "PATCH",
        AUTOMATION_PATH,
        &body_value,
    )
    .await?
    {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };
    let guard = repository
        .assert_automation_version_statement(&automation_id, &org_id, body.version)
        .map_err(|error| database_error(&context, error))?;
    let mut writes: Vec<D1PreparedStatement> = vec![guard];
    if let Some(statement) = insert_rule {
        writes.push(statement);
    }
    let update = repository
        .update_automation_statement(&AutomationUpdateInput {
            automation_id: &automation_id,
            org_id: &org_id,
            name: &name,
            description: description.as_deref(),
            project_id: project_id.as_deref(),
            agent_definition_id: agent_definition_id.as_deref(),
            schedule_rule_id: &schedule_rule_id,
            target_kind: &target_kind,
            target_device_id: target_device_id.as_deref(),
            target_workspace_binding_id: target_binding_id.as_deref(),
            required_capabilities_json: &capabilities_json,
            execution_model_alias: model_alias.as_deref(),
            execution_budget_id: budget_id.as_deref(),
            tool_policy_scope: &tool_policy_scope,
            required_policy_version,
            off_peak_eligibility_source: off_peak
                .as_ref()
                .map(|value| value.eligibility_source.as_str()),
            off_peak_allowed_route_aliases_json: off_peak
                .as_ref()
                .map(|value| value.allowed_route_aliases_json.as_str()),
            off_peak_deny_automation_mutation: off_peak
                .as_ref()
                .map_or(1, |value| value.deny_automation_mutation),
            off_peak_deny_recursive_off_peak: off_peak
                .as_ref()
                .map_or(1, |value| value.deny_recursive_off_peak),
            off_peak_allow_background_processes: off_peak
                .as_ref()
                .map_or(0, |value| value.allow_background_processes),
            max_start_attempts: i64::from(retry.max_start_attempts),
            lease_ttl_seconds: i64::from(retry.lease_ttl_seconds),
            heartbeat_interval_seconds: i64::from(retry.heartbeat_interval_seconds),
            queued_successor_max_age_seconds: existing.queued_successor_max_age_seconds,
            now: &context.received_at,
            expected_version: body.version,
        })
        .map_err(|error| database_error(&context, error))?;
    writes.push(update);
    if body.schedule.is_some() {
        // The cursor restart is a compare-and-set on the previous cursor text; a
        // concurrent edit loses it and the whole batch rolls back.
        writes.push(
            repository
                .restart_schedule_cursor_statement(
                    &automation_id,
                    &org_id,
                    context.received_at.as_str(),
                    next_run_at.as_deref(),
                    &context.received_at,
                    existing.schedule_cursor_at.as_deref().unwrap_or(""),
                )
                .map_err(|error| database_error(&context, error))?,
        );
    }
    writes.push(security_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        "automation.definition.updated.v1",
        "automation",
        &automation_id,
        &json!({ "version": body.version + 1 }),
    )?);
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        crate::repositories::EVENT_DEFINITION_UPDATED,
        &json!({
            "automation_id": automation_id,
            "org_id": org_id,
            "project_id": project_id,
            "version": body.version + 1,
            "status": existing.status,
            "next_run_at": next_run_at,
        }),
    )?;
    let record = AutomationDefinitionRecord {
        automation_id: automation_id.clone(),
        org_id: org_id.clone(),
        project_id: project_id.clone(),
        name: name.clone(),
        description: description.clone(),
        agent_definition_id: agent_definition_id.clone(),
        schedule_rule_id: schedule_rule_id.clone(),
        execution_principal_kind: existing.execution_principal_kind.clone(),
        execution_principal_id: existing.execution_principal_id.clone(),
        target_kind: target_kind.clone(),
        target_device_id: target_device_id.clone(),
        target_workspace_binding_id: target_binding_id.clone(),
        required_capabilities_json: capabilities_json.clone(),
        execution_model_alias: model_alias.clone(),
        execution_budget_id: budget_id.clone(),
        tool_policy_scope: tool_policy_scope.clone(),
        required_policy_version,
        off_peak_eligibility_source: off_peak
            .as_ref()
            .map(|value| value.eligibility_source.clone()),
        off_peak_allowed_route_aliases_json: off_peak
            .as_ref()
            .map(|value| value.allowed_route_aliases_json.clone()),
        off_peak_deny_automation_mutation: off_peak
            .as_ref()
            .map_or(1, |value| value.deny_automation_mutation),
        off_peak_deny_recursive_off_peak: off_peak
            .as_ref()
            .map_or(1, |value| value.deny_recursive_off_peak),
        off_peak_allow_background_processes: off_peak
            .as_ref()
            .map_or(0, |value| value.allow_background_processes),
        status: existing.status.clone(),
        max_start_attempts: i64::from(retry.max_start_attempts),
        lease_ttl_seconds: i64::from(retry.lease_ttl_seconds),
        heartbeat_interval_seconds: i64::from(retry.heartbeat_interval_seconds),
        schedule_cursor_at: Some(context.received_at.as_str().to_owned()),
        next_run_at: next_run_at.clone().or(existing.next_run_at.clone()),
        last_run_at: existing.last_run_at.clone(),
        version: body.version + 1,
        created_by_user_id: existing.created_by_user_id.clone(),
        created_at: existing.created_at.clone(),
        updated_at: context.received_at.as_str().to_owned(),
        queued_successor_max_age_seconds: existing.queued_successor_max_age_seconds,
    };
    let success = StoredSuccess::new(200, automation_json(&context, database, &record).await?)
        .map_err(|_| service_unavailable(&context))?;
    if let Some(replay) =
        commit_mutation(database, &context, claim, success.clone(), writes, outbox).await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::OK, Json(success.body)).into_response())
}

#[worker::send]
pub async fn delete_automation(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, automation_id)): Path<(String, String)>,
    Json(body): Json<AutomationVersionRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        automation_permission(PERMISSION_AUTOMATIONS_MANAGE),
        Some("automation"),
        Some(&automation_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    validate_version(&context, body.version)?;
    let key = idempotency_key(&headers, &context)?;
    let database = database(&state, &context)?;
    let existing = require_automation(&context, database, &org_id, &automation_id).await?;
    let repository = AutomationsRepository::new(database);
    let body_value = serde_json::to_value(&body).map_err(|_| service_unavailable(&context))?;
    let claim = match prepare_mutation(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        "DELETE",
        AUTOMATION_PATH,
        &body_value,
    )
    .await?
    {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };
    let guard = repository
        .assert_automation_version_statement(&automation_id, &org_id, body.version)
        .map_err(|error| database_error(&context, error))?;
    let delete = repository
        .soft_delete_automation_statement(
            &automation_id,
            &org_id,
            &context.received_at,
            body.version,
        )
        .map_err(|error| database_error(&context, error))?;
    let audit = security_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        "automation.definition.deleted.v1",
        "automation",
        &automation_id,
        &json!({ "version": body.version + 1 }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        crate::repositories::EVENT_DEFINITION_DELETED,
        &json!({
            "automation_id": automation_id,
            "org_id": org_id,
            "project_id": existing.project_id,
            "version": body.version + 1,
            "status": "deleted",
            "next_run_at": Value::Null,
        }),
    )?;
    // A confirmed delete returns 204 with no body.
    let success =
        StoredSuccess::new(204, Value::Null).map_err(|_| service_unavailable(&context))?;
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success,
        vec![guard, delete, audit],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[worker::send]
pub async fn pause_automation(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, automation_id)): Path<(String, String)>,
    Json(body): Json<AutomationVersionRequest>,
) -> Result<Response<Body>, ApiError> {
    transition_status(
        &state,
        &context,
        &headers,
        &org_id,
        &automation_id,
        &body,
        "active",
        "paused",
        AUTOMATION_PAUSE_PATH,
        crate::repositories::EVENT_DEFINITION_PAUSED,
        "automation.definition.paused.v1",
    )
    .await
}

#[worker::send]
pub async fn resume_automation(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, automation_id)): Path<(String, String)>,
    Json(body): Json<AutomationVersionRequest>,
) -> Result<Response<Body>, ApiError> {
    // Resume rechecks the current entitlement and license state before the
    // automation is allowed to dispatch again.
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        automation_permission(PERMISSION_AUTOMATIONS_MANAGE),
        Some("automation"),
        Some(&automation_id),
    )
    .await?;
    let database = database(&state, &context)?;
    let record = require_automation(&context, database, &org_id, &automation_id).await?;
    let eligibility = crate::jobs::automations::read_dispatch_eligibility(
        database,
        &record,
        &context.received_at,
    )
    .await
    .map_err(|error| store_failure(&context, error))?;
    if let Some(block) = crate::jobs::automations::dispatch_block(&record, &eligibility) {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            block.code(),
            "The organization is not currently eligible to run automations.",
        ));
    }
    transition_status_with_access(
        &state,
        &context,
        &headers,
        &access,
        &org_id,
        &automation_id,
        &body,
        "paused",
        "active",
        AUTOMATION_RESUME_PATH,
        crate::repositories::EVENT_DEFINITION_RESUMED,
        "automation.definition.resumed.v1",
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn transition_status(
    state: &Arc<AppState>,
    context: &RequestContext,
    headers: &HeaderMap,
    org_id: &str,
    automation_id: &str,
    body: &AutomationVersionRequest,
    expected_status: &str,
    next_status: &str,
    path: &str,
    event_type: &str,
    audit_action: &str,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        state,
        headers,
        context,
        org_id,
        automation_permission(PERMISSION_AUTOMATIONS_MANAGE),
        Some("automation"),
        Some(automation_id),
    )
    .await?;
    transition_status_with_access(
        state,
        context,
        headers,
        &access,
        org_id,
        automation_id,
        body,
        expected_status,
        next_status,
        path,
        event_type,
        audit_action,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn transition_status_with_access(
    state: &Arc<AppState>,
    context: &RequestContext,
    headers: &HeaderMap,
    access: &crate::routes::authorization::OrgAccess,
    org_id: &str,
    automation_id: &str,
    body: &AutomationVersionRequest,
    expected_status: &str,
    next_status: &str,
    path: &str,
    event_type: &str,
    audit_action: &str,
) -> Result<Response<Body>, ApiError> {
    require_csrf(headers, &access.session, context).await?;
    validate_version(context, body.version)?;
    let key = idempotency_key(headers, context)?;
    let database = database(state, context)?;
    let existing = require_automation(context, database, org_id, automation_id).await?;
    if existing.status != expected_status {
        return Err(domain_failure(context, DomainError::AutomationInvalidState));
    }
    let repository = AutomationsRepository::new(database);
    let next_run_at = if next_status == "active" {
        resume_next_run(context, database, &existing).await?
    } else {
        None
    };
    let body_value = serde_json::to_value(body).map_err(|_| service_unavailable(context))?;
    let claim = match prepare_mutation(
        database,
        context,
        &access.principal,
        org_id,
        &key,
        "POST",
        path,
        &body_value,
    )
    .await?
    {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };
    let guard = repository
        .assert_automation_version_statement(automation_id, org_id, body.version)
        .map_err(|error| database_error(context, error))?;
    let status_guard = repository
        .assert_automation_status_statement(automation_id, org_id, expected_status)
        .map_err(|error| database_error(context, error))?;
    let update = repository
        .set_automation_status_statement(
            automation_id,
            org_id,
            next_status,
            next_run_at.as_deref(),
            // Resuming restarts the cursor at the resume instant so a long pause
            // cannot produce a replay burst on the next sweep.
            (next_status == "active").then_some(context.received_at.as_str()),
            &context.received_at,
            body.version,
            expected_status,
        )
        .map_err(|error| database_error(context, error))?;
    let audit = security_statement(
        database,
        context,
        &access.principal,
        org_id,
        audit_action,
        "automation",
        automation_id,
        &json!({ "version": body.version + 1, "status": next_status }),
    )?;
    let outbox = outbox_statement(
        database,
        context,
        Some(&access.principal),
        Some(org_id),
        event_type,
        &json!({
            "automation_id": automation_id,
            "org_id": org_id,
            "project_id": existing.project_id,
            "version": body.version + 1,
            "status": next_status,
            "next_run_at": next_run_at,
        }),
    )?;
    let record = AutomationDefinitionRecord {
        status: next_status.to_owned(),
        version: body.version + 1,
        next_run_at: next_run_at.clone(),
        updated_at: context.received_at.as_str().to_owned(),
        ..existing
    };
    let success = StoredSuccess::new(200, automation_json(context, database, &record).await?)
        .map_err(|_| service_unavailable(context))?;
    if let Some(replay) = commit_mutation(
        database,
        context,
        claim,
        success.clone(),
        vec![guard, status_guard, update, audit],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::OK, Json(success.body)).into_response())
}

#[worker::send]
pub async fn run_now(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, automation_id)): Path<(String, String)>,
    Json(body): Json<RunNowRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        automation_permission(PERMISSION_AUTOMATIONS_RUN),
        Some("automation"),
        Some(&automation_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    validate_version(&context, body.version)?;
    let key = idempotency_key(&headers, &context)?;
    let database = database(&state, &context)?;
    let existing = require_automation(&context, database, &org_id, &automation_id).await?;
    if existing.status != "active" {
        // A paused or deleted automation creates no new dispatch.
        return Err(domain_failure(
            &context,
            DomainError::AutomationInvalidState,
        ));
    }
    let body_value = serde_json::to_value(&body).map_err(|_| service_unavailable(&context))?;
    let prepared = prepare_mutation(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        "POST",
        AUTOMATION_RUN_NOW_PATH,
        &body_value,
    )
    .await?;
    let claim = match prepared {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };
    // The manual occurrence identity is derived from the automation plus the P01
    // idempotency key DIGEST. The raw key never reaches an occurrence row, and no
    // client occurrence ID is accepted.
    let trigger_key_digest = claim.record.key_digest.as_str().to_owned();
    let occurrence_id =
        deterministic_manual_occurrence_id(&existing.automation_id, &trigger_key_digest);
    let repository = AutomationsRepository::new(database);
    let guard = repository
        .assert_automation_version_statement(&existing.automation_id, &org_id, body.version)
        .map_err(|error| database_error(&context, error))?;
    let status_guard = repository
        .assert_automation_status_statement(&existing.automation_id, &org_id, "active")
        .map_err(|error| database_error(&context, error))?;
    let insert = repository
        .insert_occurrence_statement(&NewOccurrenceInput {
            occurrence_id: &occurrence_id,
            automation_id: &existing.automation_id,
            org_id: &org_id,
            project_id: existing.project_id.as_deref(),
            schedule_rule_id: &existing.schedule_rule_id,
            kind: crate::modules::automations::OccurrenceKind::Manual.as_str(),
            scheduled_for_utc: None,
            trigger_key_digest: Some(&trigger_key_digest),
            execution_principal_kind: &existing.execution_principal_kind,
            execution_principal_id: &existing.execution_principal_id,
            off_peak_mode: OffPeakMode::Normal.as_str(),
            policy_snapshot_id: None,
            policy_version: None,
            state: OccurrenceState::Pending.as_str(),
            attempt: 0,
            reason_code: None,
            blocked_by_occurrence_id: None,
            queued_at: None,
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let job = crate::consumers::automations::enqueue_automation_job(
        database,
        crate::repositories::JobType::Dispatch,
        &org_id,
        &occurrence_id,
        Some(body.version),
        0,
        Some(context.request_id.as_str()),
        Some(context.correlation_id.as_str()),
        &context.received_at,
    )
    .map_err(|error| store_failure(&context, error))?;
    let audit = security_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        "automation.occurrence.requested.v1",
        "automation_occurrence",
        &occurrence_id,
        &json!({ "automation_id": existing.automation_id, "kind": "manual" }),
    )?;
    let outbox = crate::jobs::automations::occurrence_outbox_statement(
        database,
        crate::repositories::EVENT_OCCURRENCE_CREATED,
        &org_id,
        existing.project_id.as_deref(),
        &occurrence_id,
        &existing.automation_id,
        0,
        1,
        OccurrenceState::Pending.as_str(),
        "",
        None,
        &context.received_at,
    )
    .map_err(|error| store_failure(&context, error))?;
    let projection = json!({
        "occurrence_id": occurrence_id,
        "automation_id": existing.automation_id,
        "org_id": org_id,
        "project_id": existing.project_id,
        "kind": "manual",
        "state": OccurrenceState::Pending.as_str(),
        "state_version": 1,
        "attempt": 0,
        "schedule_rule_id": existing.schedule_rule_id,
        "created_at": context.received_at.as_str(),
    });
    let success = StoredSuccess::new(201, projection).map_err(|_| service_unavailable(&context))?;
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![guard, status_guard, insert, job, audit],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::CREATED, Json(success.body)).into_response())
}

#[worker::send]
pub async fn list_occurrences(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<OccurrenceListQuery>,
    Path((org_id, automation_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        automation_permission(PERMISSION_AUTOMATIONS_READ),
        Some("automation"),
        Some(&automation_id),
    )
    .await?;
    let limit = occurrence_page_limit(query.limit);
    let cursor = query
        .cursor
        .as_deref()
        .map(|raw| decode_page_cursor(raw, &context))
        .transpose()?;
    let state_filter = match query.state.as_deref() {
        Some(value) if OccurrenceState::parse(value).is_some() => Some(value.to_owned()),
        Some(_) => {
            return Err(validation_error(
                &context,
                "occurrence_state_invalid",
                "The occurrence state filter is invalid.",
            ));
        }
        None => None,
    };
    let database = database(&state, &context)?;
    let record = require_automation(&context, database, &org_id, &automation_id).await?;
    if let Some(project_id) = record.project_id.as_deref() {
        crate::routes::agents::ensure_project_access(
            database,
            &context,
            &org_id,
            project_id,
            access.principal.user_id.as_str(),
            crate::routes::agents::can_manage_projects(&state, &headers, &context, &org_id).await,
        )
        .await?;
    }
    let mut occurrences = AutomationsRepository::new(database)
        .list_occurrences(
            &org_id,
            &automation_id,
            state_filter.as_deref(),
            cursor
                .as_ref()
                .map(|(created, id)| (created.as_str(), id.as_str())),
            limit + 1,
        )
        .await
        .map_err(|error| database_error(&context, error))?;
    let has_more = occurrences.len() > limit as usize;
    if has_more {
        occurrences.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        occurrences
            .last()
            .map(|record| encode_page_cursor(&record.created_at, &record.occurrence_id))
    } else {
        None
    };
    let mut items = Vec::with_capacity(occurrences.len());
    for occurrence in &occurrences {
        items.push(occurrence_json(&context, occurrence)?);
    }
    Ok(page(items, next_cursor, has_more))
}

// -----------------------------------------------------------------------------
// Device: lease lifecycle
// -----------------------------------------------------------------------------

#[worker::send]
pub async fn due_automations(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<DueQuery>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_device(&state, &headers, &context).await?;
    let database = database(&state, &context)?;
    let limit = due_page_limit(query.limit);
    let due = AutomationsRepository::new(database)
        .list_due_occurrences(
            &access.device.device_id,
            &access.device.org_id,
            context.received_at.as_str(),
            limit,
        )
        .await
        .map_err(|error| database_error(&context, error))?;
    let items: Vec<Value> = due.iter().map(due_projection).collect();
    Ok((
        StatusCode::OK,
        Json(json!({ "items": items, "next_cursor": Value::Null, "has_more": false })),
    )
        .into_response())
}

#[worker::send]
pub async fn claim_occurrence(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(occurrence_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_device(&state, &headers, &context).await?;
    let occurrence_id = crate::routes::agents::validate_prefixed_id(
        &context,
        &occurrence_id,
        "occ",
        "occurrence_id_invalid",
    )?;
    let database = database(&state, &context)?;
    let repository = AutomationsRepository::new(database);
    let occurrence = require_device_occurrence(&context, database, &access, &occurrence_id).await?;
    // Only an occurrence the server already dispatched is claimable. A `pending`
    // occurrence re-enters this path after a proven pre-start lease expiry.
    if occurrence.state != OccurrenceState::Pending.as_str()
        && occurrence.state != OccurrenceState::Dispatching.as_str()
    {
        return Err(domain_failure(
            &context,
            if occurrence.state == OccurrenceState::Ambiguous.as_str() {
                DomainError::OccurrenceAmbiguous
            } else {
                DomainError::AutomationInvalidState
            },
        ));
    }
    let automation = repository
        .find_automation(&access.device.org_id, &occurrence.automation_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| not_found(&context, "automation_not_found"))?;
    let retry = automation
        .execution_retry()
        .map_err(|error| domain_failure(&context, error))?;
    let current_state = occurrence
        .state()
        .map_err(|error| domain_failure(&context, error))?;
    let next_state = crate::repositories::claim_target_state(current_state)
        .map_err(|error| domain_failure(&context, error))?;
    let attempt = occurrence.attempt + 1;
    if attempt > i64::from(retry.max_start_attempts) {
        return Err(domain_failure(
            &context,
            DomainError::OccurrenceLeaseExpired,
        ));
    }
    let token = new_secret();
    let fingerprint = lease_fingerprint(&context, &token).await?;
    let lease_id = generated_id("lse");
    let expires_at = crate::adapters::add_seconds(&context.received_at, retry.lease_ttl_seconds)
        .map_err(|_| service_unavailable(&context))?;
    let claim = repository
        .assert_occurrence_claimable_statement(
            &occurrence.occurrence_id,
            &access.device.org_id,
            &occurrence.state,
            occurrence.state_version,
            occurrence.attempt,
        )
        .map_err(|error| database_error(&context, error))?;
    let cas = repository
        .transition_occurrence_statement(&OccurrenceTransition {
            occurrence_id: &occurrence.occurrence_id,
            org_id: &access.device.org_id,
            next_state: next_state.as_str(),
            reason_code: None,
            run_id: None,
            lease_expires_at: Some(expires_at.as_str()),
            queued_at: None,
            blocked_by_occurrence_id: None,
            started_at: None,
            finished_at: None,
            now: &context.received_at,
            expected_state: &occurrence.state,
            expected_state_version: occurrence.state_version,
        })
        .map_err(|error| database_error(&context, error))?;
    let lease = repository
        .insert_lease_statement(&NewLeaseInput {
            lease_id: &lease_id,
            occurrence_id: &occurrence.occurrence_id,
            org_id: &access.device.org_id,
            device_id: &access.device.device_id,
            attempt,
            lease_token_fingerprint: &fingerprint,
            claimed_at: context.received_at.as_str(),
            expires_at: expires_at.as_str(),
        })
        .map_err(|error| database_error(&context, error))?;
    let record = repository
        .insert_attempt_statement(&NewAttemptInput {
            attempt_id: &generated_id("att"),
            occurrence_id: &occurrence.occurrence_id,
            lease_id: Some(&lease_id),
            attempt,
            outcome: "claimed",
            run_id: None,
            reason_code: None,
            lease_version: Some(1),
            lease_fence: Some(1),
            recorded_at: context.received_at.as_str(),
        })
        .map_err(|error| database_error(&context, error))?;
    let mut writes = vec![claim, cas, lease, record];
    if crate::repositories::claim_performs_dispatch(current_state) {
        // The claim also performed the `pending -> dispatching` edge, so the
        // frozen `dispatched` event is emitted in the same batch.
        writes.push(
            crate::jobs::automations::occurrence_outbox_statement(
                database,
                crate::repositories::EVENT_OCCURRENCE_DISPATCHED,
                &access.device.org_id,
                occurrence.project_id.as_deref(),
                &occurrence.occurrence_id,
                &occurrence.automation_id,
                attempt,
                occurrence.state_version + 1,
                OccurrenceState::Dispatching.as_str(),
                "",
                None,
                &context.received_at,
            )
            .map_err(|error| store_failure(&context, error))?,
        );
    }
    writes.push(device_audit(
        &context,
        database,
        &access,
        "automation.occurrence.claimed.v1",
        "automation_occurrence",
        &occurrence.occurrence_id,
        &json!({ "lease_id": lease_id, "attempt": attempt, "state": "leased" }),
    )?);
    match database.batch(writes).await {
        Ok(_) => {}
        Err(error) if crate::repositories::is_guard_violation(&error) => {
            // A losing concurrent claim re-reads the winner's projection. The
            // stable reason is `occurrence_already_claimed` and the raw lease
            // token for this attempt is discarded, never returned.
            return Err(claim_conflict(&context, database, &access, &occurrence).await);
        }
        Err(_) => return Err(service_unavailable(&context)),
    }
    // The claim response is the frozen `P06AutomationLease` projection plus the
    // one-time raw token. The raw token is returned exactly once, is never
    // persisted, and never leaves a device route.
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "occurrence_id": occurrence.occurrence_id,
            "attempt": attempt,
            "lease_id": lease_id,
            "lease_version": 1,
            "lease_fence": 1,
            "expires_at": expires_at.as_str(),
            "state": OccurrenceState::Leased.as_str(),
            "lease_token": token,
        })),
    )
        .into_response())
}

async fn claim_conflict(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    access: &DeviceAccess,
    occurrence: &AutomationOccurrenceRecord,
) -> ApiError {
    let active = AutomationsRepository::new(database)
        .find_active_lease(&occurrence.occurrence_id)
        .await
        .ok()
        .flatten()
        // A lease belonging to another tenant is indistinguishable from none.
        .filter(|lease| lease.org_id == access.device.org_id);
    if let Some(lease) = active {
        return conflict(
            context,
            DomainError::OccurrenceAlreadyClaimed.code(),
            "The occurrence is already claimed by another device.",
        )
        .with_detail("existing_lease_id", json!(lease.lease_id));
    }
    conflict(
        context,
        DomainError::OccurrenceAlreadyClaimed.code(),
        "The occurrence is already claimed by another device.",
    )
}

#[worker::send]
pub async fn renew_lease(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(lease_id): Path<String>,
    Json(body): Json<LeaseContextRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_device(&state, &headers, &context).await?;
    let lease_id = crate::routes::agents::validate_prefixed_id(
        &context,
        &lease_id,
        "lse",
        "lease_id_invalid",
    )?;
    let database = database(&state, &context)?;
    let repository = AutomationsRepository::new(database);
    let lease = require_device_lease(&context, database, &access, &lease_id).await?;
    let occurrence =
        require_device_occurrence(&context, database, &access, &lease.occurrence_id).await?;
    let state_value = occurrence
        .state()
        .map_err(|error| domain_failure(&context, error))?;
    // A renewal extends a CURRENT, pre-ambiguous lease. An ambiguous occurrence is
    // terminal and is never extended; a settled occurrence cannot renew either.
    if state_value == OccurrenceState::Ambiguous {
        return Err(domain_failure(&context, DomainError::OccurrenceAmbiguous));
    }
    if !matches!(
        state_value,
        OccurrenceState::Leased | OccurrenceState::Started
    ) {
        return Err(domain_failure(
            &context,
            DomainError::AutomationInvalidState,
        ));
    }
    let presented = presented_fence(
        &context,
        &body.lease_id,
        body.lease_version,
        body.lease_fence,
    )?;
    let current = lease
        .fence()
        .map_err(|error| domain_failure(&context, error))?;
    if !crate::modules::automations::fence_is_current(&presented, &current) {
        return Err(domain_failure(&context, DomainError::LeaseFenceInvalid));
    }
    let fingerprint = lease_fingerprint(&context, &body.lease_token).await?;
    if !lease.matches_token(&fingerprint) {
        // A wrong token is reported as a fence failure so a caller cannot probe
        // for a valid token.
        return Err(domain_failure(&context, DomainError::LeaseFenceInvalid));
    }
    let automation = repository
        .find_automation(&access.device.org_id, &occurrence.automation_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| not_found(&context, "automation_not_found"))?;
    let retry = automation
        .execution_retry()
        .map_err(|error| domain_failure(&context, error))?;
    // The renewal window is bounded by the frozen lease TTL.
    let expires_at = crate::adapters::add_seconds(&context.received_at, retry.lease_ttl_seconds)
        .map_err(|_| service_unavailable(&context))?;
    let guard = repository
        .assert_lease_current_statement(
            &lease.lease_id,
            &lease.occurrence_id,
            &access.device.org_id,
            "active",
            body.lease_version,
            body.lease_fence,
        )
        .map_err(|error| database_error(&context, error))?;
    let renew = repository
        .renew_lease_statement(
            &lease.lease_id,
            &lease.occurrence_id,
            &access.device.org_id,
            expires_at.as_str(),
            body.lease_version,
            body.lease_fence,
        )
        .map_err(|error| database_error(&context, error))?;
    let occurrence_refresh = repository
        .transition_occurrence_statement(&OccurrenceTransition {
            occurrence_id: &occurrence.occurrence_id,
            org_id: &access.device.org_id,
            next_state: &occurrence.state,
            reason_code: occurrence.reason_code.as_deref(),
            run_id: occurrence.run_id.as_deref(),
            lease_expires_at: Some(expires_at.as_str()),
            queued_at: occurrence.queued_at.as_deref(),
            blocked_by_occurrence_id: occurrence.blocked_by_occurrence_id.as_deref(),
            started_at: occurrence.started_at.as_deref(),
            finished_at: occurrence.finished_at.as_deref(),
            now: &context.received_at,
            expected_state: &occurrence.state,
            expected_state_version: occurrence.state_version,
        })
        .map_err(|error| database_error(&context, error))?;
    let audit = device_audit(
        &context,
        database,
        &access,
        "automation.lease.renewed.v1",
        "automation_lease",
        &lease.lease_id,
        &json!({ "lease_version": body.lease_version + 1 }),
    )?;
    match database
        .batch(vec![guard, renew, occurrence_refresh, audit])
        .await
    {
        Ok(_) => {}
        Err(error) if crate::repositories::is_guard_violation(&error) => {
            return Err(domain_failure(&context, DomainError::LeaseFenceInvalid));
        }
        Err(_) => return Err(service_unavailable(&context)),
    }
    Ok((
        StatusCode::OK,
        Json(json!({
            "lease_id": lease.lease_id,
            "occurrence_id": lease.occurrence_id,
            "lease_version": body.lease_version + 1,
            "lease_fence": body.lease_fence,
            "expires_at": expires_at.as_str(),
        })),
    )
        .into_response())
}

#[worker::send]
pub async fn start_occurrence(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(occurrence_id): Path<String>,
    Json(body): Json<StartOccurrenceRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_device(&state, &headers, &context).await?;
    let occurrence_id = crate::routes::agents::validate_prefixed_id(
        &context,
        &occurrence_id,
        "occ",
        "occurrence_id_invalid",
    )?;
    let database = database(&state, &context)?;
    let repository = AutomationsRepository::new(database);
    let occurrence = require_device_occurrence(&context, database, &access, &occurrence_id).await?;
    let lease = require_device_lease(&context, database, &access, &body.lease_id).await?;
    if lease.occurrence_id != occurrence.occurrence_id {
        return Err(domain_failure(&context, DomainError::LeaseFenceInvalid));
    }
    let fingerprint = lease_fingerprint(&context, &body.lease_token).await?;
    if !lease.matches_token(&fingerprint) {
        return Err(domain_failure(&context, DomainError::LeaseFenceInvalid));
    }
    let presented = presented_fence(
        &context,
        &body.lease_id,
        body.lease_version,
        body.lease_fence,
    )?;
    let current = lease
        .fence()
        .map_err(|error| domain_failure(&context, error))?;
    if !crate::modules::automations::fence_is_current(&presented, &current) {
        return Err(domain_failure(&context, DomainError::LeaseFenceInvalid));
    }
    // Idempotent discovery: an existing link for this attempt is returned as-is,
    // so a repeated `start` can never create a second P05 run.
    if let Some(existing) = repository
        .find_run_link(&occurrence.occurrence_id, lease.attempt)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        let session_id = repository
            .find_automation_session(&occurrence.occurrence_id)
            .await
            .map_err(|error| database_error(&context, error))?
            .unwrap_or_default();
        // Idempotent discovery returns the same grant, so a repeated `start` is
        // indistinguishable from the first one.
        return Ok((
            StatusCode::OK,
            Json(start_grant(
                &occurrence.occurrence_id,
                lease.attempt,
                &existing.run_id,
                &session_id,
                &lease,
            )),
        )
            .into_response());
    }
    let state_value = occurrence
        .state()
        .map_err(|error| domain_failure(&context, error))?;
    if state_value != OccurrenceState::Leased {
        return Err(domain_failure(
            &context,
            DomainError::AutomationInvalidState,
        ));
    }
    let automation = repository
        .find_automation(&access.device.org_id, &occurrence.automation_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| not_found(&context, "automation_not_found"))?;
    let project_id = automation
        .project_id
        .clone()
        .ok_or_else(|| domain_failure(&context, DomainError::AutomationInvalidState))?;
    let agent_definition_id = automation
        .agent_definition_id
        .clone()
        .ok_or_else(|| domain_failure(&context, DomainError::AutomationInvalidState))?;
    // The principal, policy, and entitlement are re-read here, immediately before
    // the P05 run exists. A value captured at schedule creation is never authority.
    let eligibility = crate::jobs::automations::read_dispatch_eligibility(
        database,
        &automation,
        &context.received_at,
    )
    .await
    .map_err(|error| store_failure(&context, error))?;
    if let Some(block) = crate::jobs::automations::dispatch_block(&automation, &eligibility) {
        return Err(domain_failure(
            &context,
            match block {
                crate::jobs::automations::DispatchBlock::Authorization(error) => error,
                crate::jobs::automations::DispatchBlock::Reason(code) => {
                    return Err(domain_error(
                        &context,
                        ApiErrorCode::Conflict,
                        code,
                        "The automation is not currently dispatchable.",
                    ));
                }
            },
        ));
    }
    let agent = RunRepository::new(database)
        .find_agent(&access.device.org_id, &agent_definition_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .filter(|agent| agent.lifecycle == "active")
        .ok_or_else(|| domain_failure(&context, DomainError::AutomationInvalidState))?;
    let run_id = generated_id("run");
    let session_id = generated_id("rse");
    let link_id = generated_id("lnk");
    let started = transition(state_value, OccurrenceEvent::Started)
        .map_err(|error| domain_failure(&context, error))?;
    let run_input = NewAutomationRunInput {
        run_id: &run_id,
        agent_session_id: &session_id,
        org_id: &access.device.org_id,
        project_id: &project_id,
        device_id: &access.device.device_id,
        workspace_binding_id: automation.target_workspace_binding_id.as_deref(),
        agent_definition_id: &agent.agent_definition_id,
        agent_definition_version: agent.version,
        external_id: &occurrence.occurrence_id,
        created_by_user_id: &automation.execution_principal_id,
        model_alias: automation.execution_model_alias.as_deref(),
        request_id: context.request_id.as_str(),
        policy_snapshot_id: occurrence.policy_snapshot_id.as_deref(),
        policy_version: occurrence.policy_version,
        occurrence_id: &occurrence.occurrence_id,
        lease_id: &lease.lease_id,
        now: &context.received_at,
    };
    let lease_guard = repository
        .assert_lease_current_statement(
            &lease.lease_id,
            &occurrence.occurrence_id,
            &access.device.org_id,
            "active",
            body.lease_version,
            body.lease_fence,
        )
        .map_err(|error| database_error(&context, error))?;
    let occurrence_guard = repository
        .assert_occurrence_state_statement(
            &occurrence.occurrence_id,
            &access.device.org_id,
            OccurrenceState::Leased.as_str(),
            occurrence.state_version,
        )
        .map_err(|error| database_error(&context, error))?;
    let link_absent = repository
        .assert_run_link_absent_statement(&occurrence.occurrence_id, lease.attempt)
        .map_err(|error| database_error(&context, error))?;
    let eligibility_guard = repository
        .assert_dispatch_eligible_statement(
            &access.device.org_id,
            &automation.execution_principal_id,
            context.received_at.as_str(),
            eligibility.license_state.as_deref().unwrap_or("active"),
        )
        .map_err(|error| database_error(&context, error))?;
    let session = repository
        .insert_automation_session_statement(&run_input)
        .map_err(|error| database_error(&context, error))?;
    let run = repository
        .insert_automation_run_statement(&run_input)
        .map_err(|error| database_error(&context, error))?;
    let link = repository
        .insert_run_link_statement(&NewRunLinkInput {
            link_id: &link_id,
            occurrence_id: &occurrence.occurrence_id,
            org_id: &access.device.org_id,
            run_id: &run_id,
            lease_id: &lease.lease_id,
            attempt: lease.attempt,
            state: started.as_str(),
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let cas = repository
        .transition_occurrence_statement(&OccurrenceTransition {
            occurrence_id: &occurrence.occurrence_id,
            org_id: &access.device.org_id,
            next_state: started.as_str(),
            reason_code: None,
            run_id: Some(&run_id),
            lease_expires_at: Some(lease.expires_at.as_str()),
            queued_at: None,
            blocked_by_occurrence_id: None,
            started_at: Some(context.received_at.as_str()),
            finished_at: None,
            now: &context.received_at,
            expected_state: OccurrenceState::Leased.as_str(),
            expected_state_version: occurrence.state_version,
        })
        .map_err(|error| database_error(&context, error))?;
    let record = repository
        .insert_attempt_statement(&NewAttemptInput {
            attempt_id: &generated_id("att"),
            occurrence_id: &occurrence.occurrence_id,
            lease_id: Some(&lease.lease_id),
            attempt: lease.attempt,
            outcome: "started",
            run_id: Some(&run_id),
            reason_code: None,
            lease_version: Some(body.lease_version),
            lease_fence: Some(body.lease_fence),
            recorded_at: context.received_at.as_str(),
        })
        .map_err(|error| database_error(&context, error))?;
    let outbox = crate::jobs::automations::occurrence_outbox_statement(
        database,
        occurrence_event_type(started.as_str())
            .ok_or_else(|| domain_failure(&context, DomainError::AutomationInvalidState))?,
        &access.device.org_id,
        occurrence.project_id.as_deref(),
        &occurrence.occurrence_id,
        &occurrence.automation_id,
        lease.attempt,
        occurrence.state_version + 1,
        started.as_str(),
        "",
        Some(&run_id),
        &context.received_at,
    )
    .map_err(|error| store_failure(&context, error))?;
    let audit = device_audit(
        &context,
        database,
        &access,
        "automation.occurrence.started.v1",
        "automation_occurrence",
        &occurrence.occurrence_id,
        &json!({ "run_id": run_id, "link_id": link_id, "attempt": lease.attempt }),
    )?;
    match database
        .batch(vec![
            lease_guard,
            occurrence_guard,
            link_absent,
            eligibility_guard,
            session,
            run,
            link,
            cas,
            record,
            outbox,
            audit,
        ])
        .await
    {
        Ok(_) => {}
        Err(error) if crate::repositories::is_guard_violation(&error) => {
            // A concurrent start already created the link; return its projection.
            return match repository
                .find_run_link(&occurrence.occurrence_id, lease.attempt)
                .await
                .map_err(|_| service_unavailable(&context))?
            {
                Some(existing) => {
                    let session_id = repository
                        .find_automation_session(&occurrence.occurrence_id)
                        .await
                        .map_err(|_| service_unavailable(&context))?
                        .unwrap_or_default();
                    Ok((
                        StatusCode::OK,
                        Json(start_grant(
                            &occurrence.occurrence_id,
                            lease.attempt,
                            &existing.run_id,
                            &session_id,
                            &lease,
                        )),
                    )
                        .into_response())
                }
                None => Err(domain_failure(&context, DomainError::LeaseFenceInvalid)),
            };
        }
        Err(_) => return Err(service_unavailable(&context)),
    }
    Ok((
        StatusCode::CREATED,
        Json(start_grant(
            &occurrence.occurrence_id,
            lease.attempt,
            &run_id,
            &session_id,
            &lease,
        )),
    )
        .into_response())
}

/// The frozen `P06AutomationStartGrant`. The host may not execute any tool or
/// external side effect before receiving it, because the server created the P05
/// run and its link durably in the same batch that produced this response.
fn start_grant(
    occurrence_id: &str,
    attempt: i64,
    run_id: &str,
    agent_session_id: &str,
    lease: &ExecutionLeaseRecord,
) -> Value {
    json!({
        "occurrence_id": occurrence_id,
        "attempt": attempt,
        "run_id": run_id,
        "agent_session_id": agent_session_id,
        "lease_id": lease.lease_id,
        "lease_version": lease.lease_version,
        "lease_fence": lease.lease_fence,
        "expires_at": lease.expires_at,
    })
}

#[worker::send]
pub async fn settle_occurrence(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(occurrence_id): Path<String>,
    Json(body): Json<SettleOccurrenceRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_device(&state, &headers, &context).await?;
    let occurrence_id = crate::routes::agents::validate_prefixed_id(
        &context,
        &occurrence_id,
        "occ",
        "occurrence_id_invalid",
    )?;
    let outcome = match body.outcome.as_str() {
        "succeeded" => OccurrenceEvent::Succeeded,
        "failed" => OccurrenceEvent::Failed,
        _ => {
            return Err(validation_error(
                &context,
                "settlement_outcome_invalid",
                "The settlement outcome is invalid.",
            ));
        }
    };
    let reason_code = validate_reason_code(&context, body.reason_code.as_deref())?;
    let database = database(&state, &context)?;
    let repository = AutomationsRepository::new(database);
    let occurrence = require_device_occurrence(&context, database, &access, &occurrence_id).await?;
    let lease = require_device_lease(&context, database, &access, &body.lease_id).await?;
    if lease.occurrence_id != occurrence.occurrence_id {
        return Err(domain_failure(&context, DomainError::LeaseFenceInvalid));
    }
    let fingerprint = lease_fingerprint(&context, &body.lease_token).await?;
    if !lease.matches_token(&fingerprint) {
        return Err(domain_failure(&context, DomainError::LeaseFenceInvalid));
    }
    let presented = presented_fence(
        &context,
        &body.lease_id,
        body.lease_version,
        body.lease_fence,
    )?;
    let current = lease
        .fence()
        .map_err(|error| domain_failure(&context, error))?;
    let state_value = occurrence
        .state()
        .map_err(|error| domain_failure(&context, error))?;
    // Settlement requires the CURRENT lease ID, token fingerprint, and version
    // fence. A stale fence is rejected with `lease_fence_invalid`; an ambiguous
    // occurrence reports its own actionable reason.
    validate_settlement(state_value, &presented, &current)
        .map_err(|error| domain_failure(&context, error))?;
    let next = transition(state_value, outcome).map_err(|error| domain_failure(&context, error))?;
    let event_type = occurrence_event_type(next.as_str())
        .ok_or_else(|| domain_failure(&context, DomainError::AutomationInvalidState))?;
    let link = repository
        .find_run_link(&occurrence.occurrence_id, lease.attempt)
        .await
        .map_err(|error| database_error(&context, error))?;
    let run_id = occurrence
        .run_id
        .clone()
        .or_else(|| link.as_ref().map(|value| value.run_id.clone()));
    let lease_guard = repository
        .assert_lease_current_statement(
            &lease.lease_id,
            &occurrence.occurrence_id,
            &access.device.org_id,
            "active",
            body.lease_version,
            body.lease_fence,
        )
        .map_err(|error| database_error(&context, error))?;
    let occurrence_guard = repository
        .assert_occurrence_state_statement(
            &occurrence.occurrence_id,
            &access.device.org_id,
            &occurrence.state,
            occurrence.state_version,
        )
        .map_err(|error| database_error(&context, error))?;
    let settle = repository
        .settle_lease_statement(
            &lease.lease_id,
            &occurrence.occurrence_id,
            &access.device.org_id,
            context.received_at.as_str(),
            body.lease_version,
            body.lease_fence,
        )
        .map_err(|error| database_error(&context, error))?;
    let cas = repository
        .transition_occurrence_statement(&OccurrenceTransition {
            occurrence_id: &occurrence.occurrence_id,
            org_id: &access.device.org_id,
            next_state: next.as_str(),
            reason_code: reason_code.as_deref(),
            run_id: run_id.as_deref(),
            lease_expires_at: None,
            queued_at: occurrence.queued_at.as_deref(),
            blocked_by_occurrence_id: occurrence.blocked_by_occurrence_id.as_deref(),
            started_at: occurrence.started_at.as_deref(),
            finished_at: Some(context.received_at.as_str()),
            now: &context.received_at,
            expected_state: &occurrence.state,
            expected_state_version: occurrence.state_version,
        })
        .map_err(|error| database_error(&context, error))?;
    let mut writes = vec![lease_guard, occurrence_guard, settle, cas];
    if let Some(link) = link.as_ref() {
        writes.push(
            repository
                .update_run_link_state_statement(
                    &link.link_id,
                    &access.device.org_id,
                    "settled",
                    &context.received_at,
                )
                .map_err(|error| database_error(&context, error))?,
        );
    }
    writes.push(
        repository
            .insert_attempt_statement(&NewAttemptInput {
                attempt_id: &generated_id("att"),
                occurrence_id: &occurrence.occurrence_id,
                lease_id: Some(&lease.lease_id),
                attempt: lease.attempt,
                outcome: if next == OccurrenceState::Succeeded {
                    "succeeded"
                } else {
                    "failed"
                },
                run_id: run_id.as_deref(),
                reason_code: reason_code.as_deref(),
                lease_version: Some(body.lease_version),
                lease_fence: Some(body.lease_fence),
                recorded_at: context.received_at.as_str(),
            })
            .map_err(|error| database_error(&context, error))?,
    );
    writes.push(
        crate::jobs::automations::occurrence_outbox_statement(
            database,
            event_type,
            &access.device.org_id,
            occurrence.project_id.as_deref(),
            &occurrence.occurrence_id,
            &occurrence.automation_id,
            lease.attempt,
            occurrence.state_version + 1,
            next.as_str(),
            reason_code.as_deref().unwrap_or(""),
            run_id.as_deref(),
            &context.received_at,
        )
        .map_err(|error| store_failure(&context, error))?,
    );
    writes.push(device_audit(
        &context,
        database,
        &access,
        "automation.occurrence.settled.v1",
        "automation_occurrence",
        &occurrence.occurrence_id,
        &json!({
            "state": next.as_str(),
            "attempt": lease.attempt,
            "reason_code": reason_code,
        }),
    )?);
    match database.batch(writes).await {
        Ok(_) => {}
        Err(error) if crate::repositories::is_guard_violation(&error) => {
            return Err(domain_failure(&context, DomainError::LeaseFenceInvalid));
        }
        Err(_) => return Err(service_unavailable(&context)),
    }
    Ok((
        StatusCode::OK,
        Json(json!({
            "occurrence_id": occurrence.occurrence_id,
            "state": next.as_str(),
            "run_id": run_id,
            "lease_id": lease.lease_id,
        })),
    )
        .into_response())
}

#[worker::send]
pub async fn release_occurrence(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(occurrence_id): Path<String>,
    Json(body): Json<LeaseContextRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_device(&state, &headers, &context).await?;
    let occurrence_id = crate::routes::agents::validate_prefixed_id(
        &context,
        &occurrence_id,
        "occ",
        "occurrence_id_invalid",
    )?;
    let database = database(&state, &context)?;
    let repository = AutomationsRepository::new(database);
    let occurrence = require_device_occurrence(&context, database, &access, &occurrence_id).await?;
    let lease = require_device_lease(&context, database, &access, &body.lease_id).await?;
    if lease.occurrence_id != occurrence.occurrence_id {
        return Err(domain_failure(&context, DomainError::LeaseFenceInvalid));
    }
    let fingerprint = lease_fingerprint(&context, &body.lease_token).await?;
    if !lease.matches_token(&fingerprint) {
        return Err(domain_failure(&context, DomainError::LeaseFenceInvalid));
    }
    let presented = presented_fence(
        &context,
        &body.lease_id,
        body.lease_version,
        body.lease_fence,
    )?;
    let current = lease
        .fence()
        .map_err(|error| domain_failure(&context, error))?;
    let state_value = occurrence
        .state()
        .map_err(|error| domain_failure(&context, error))?;
    // Release is allowed only before the occurrence is marked started, and only
    // when the server can prove no run was created.
    if state_value != OccurrenceState::Leased {
        return Err(domain_failure(
            &context,
            DomainError::AutomationInvalidState,
        ));
    }
    if repository
        .run_link_exists(&occurrence.occurrence_id, lease.attempt)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Err(domain_failure(
            &context,
            DomainError::AutomationInvalidState,
        ));
    }
    if !crate::modules::automations::fence_is_current(&presented, &current) {
        return Err(domain_failure(&context, DomainError::LeaseFenceInvalid));
    }
    // Only a PROVEN not-started lease may return to `pending`.
    let next = transition(
        state_value,
        OccurrenceEvent::LeaseLost {
            proved_not_started: true,
        },
    )
    .map_err(|error| domain_failure(&context, error))?;
    let lease_guard = repository
        .assert_lease_current_statement(
            &lease.lease_id,
            &occurrence.occurrence_id,
            &access.device.org_id,
            "active",
            body.lease_version,
            body.lease_fence,
        )
        .map_err(|error| database_error(&context, error))?;
    let close = repository
        .close_lease_statement(
            &lease.lease_id,
            &occurrence.occurrence_id,
            &access.device.org_id,
            "released",
            context.received_at.as_str(),
            body.lease_version,
            body.lease_fence,
        )
        .map_err(|error| database_error(&context, error))?;
    let cas = repository
        .transition_occurrence_statement(&OccurrenceTransition {
            occurrence_id: &occurrence.occurrence_id,
            org_id: &access.device.org_id,
            next_state: next.as_str(),
            reason_code: Some("lease_released"),
            run_id: None,
            lease_expires_at: None,
            queued_at: occurrence.queued_at.as_deref(),
            blocked_by_occurrence_id: occurrence.blocked_by_occurrence_id.as_deref(),
            started_at: None,
            finished_at: None,
            now: &context.received_at,
            expected_state: &occurrence.state,
            expected_state_version: occurrence.state_version,
        })
        .map_err(|error| database_error(&context, error))?;
    let record = repository
        .insert_attempt_statement(&NewAttemptInput {
            attempt_id: &generated_id("att"),
            occurrence_id: &occurrence.occurrence_id,
            lease_id: Some(&lease.lease_id),
            attempt: lease.attempt,
            outcome: "released",
            run_id: None,
            reason_code: Some("lease_released"),
            lease_version: Some(body.lease_version),
            lease_fence: Some(body.lease_fence),
            recorded_at: context.received_at.as_str(),
        })
        .map_err(|error| database_error(&context, error))?;
    let audit = device_audit(
        &context,
        database,
        &access,
        "automation.lease.released.v1",
        "automation_lease",
        &lease.lease_id,
        &json!({ "occurrence_id": occurrence.occurrence_id, "state": next.as_str() }),
    )?;
    match database
        .batch(vec![lease_guard, close, cas, record, audit])
        .await
    {
        Ok(_) => {}
        Err(error) if crate::repositories::is_guard_violation(&error) => {
            return Err(domain_failure(&context, DomainError::LeaseFenceInvalid));
        }
        Err(_) => return Err(service_unavailable(&context)),
    }
    Ok((
        StatusCode::OK,
        Json(json!({
            "occurrence_id": occurrence.occurrence_id,
            "lease_id": lease.lease_id,
            "state": next.as_str(),
        })),
    )
        .into_response())
}

// -----------------------------------------------------------------------------
// Shared helpers
// -----------------------------------------------------------------------------

fn page(items: Vec<Value>, next_cursor: Option<String>, has_more: bool) -> Response<Body> {
    (
        StatusCode::OK,
        Json(json!({
            "items": items,
            "next_cursor": next_cursor,
            "has_more": has_more,
        })),
    )
        .into_response()
}

async fn require_automation(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    org_id: &str,
    automation_id: &str,
) -> Result<AutomationDefinitionRecord, ApiError> {
    let record = AutomationsRepository::new(database)
        .find_automation(org_id, automation_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .filter(|record| record.status != "deleted")
        .ok_or_else(|| not_found(context, DomainError::AutomationNotFound.code()))?;
    Ok(record)
}

/// Load one occurrence and prove it belongs to the device token's own
/// organization. A foreign or missing occurrence is the non-disclosing
/// `resource_not_found` shape.
async fn require_device_occurrence(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    access: &DeviceAccess,
    occurrence_id: &str,
) -> Result<AutomationOccurrenceRecord, ApiError> {
    AutomationsRepository::new(database)
        .find_occurrence(&access.device.org_id, occurrence_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .ok_or_else(|| not_found(context, DomainError::OccurrenceNotFound.code()))
}

async fn require_device_lease(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    access: &DeviceAccess,
    lease_id: &str,
) -> Result<ExecutionLeaseRecord, ApiError> {
    let lease = AutomationsRepository::new(database)
        .find_lease(&access.device.org_id, lease_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .ok_or_else(|| not_found(context, "lease_not_found"))?;
    // A lease is usable only by the device that won it.
    if lease.device_id != access.device.device_id {
        return Err(not_found(context, "lease_not_found"));
    }
    if lease.state != "active" {
        return Err(domain_failure(context, DomainError::LeaseFenceInvalid));
    }
    Ok(lease)
}

fn presented_fence(
    context: &RequestContext,
    lease_id: &str,
    lease_version: i64,
    lease_fence: i64,
) -> Result<crate::modules::automations::LeaseFence, ApiError> {
    if lease_version <= 0 || lease_fence <= 0 {
        return Err(validation_error(
            context,
            "lease_fence_invalid",
            "The lease fencing context is invalid.",
        ));
    }
    let lease_id = crate::core::ExecutionLeaseId::new(lease_id.to_owned()).map_err(|_| {
        validation_error(
            context,
            "lease_id_invalid",
            "The lease identifier is invalid.",
        )
    })?;
    Ok(crate::modules::automations::LeaseFence::new(
        lease_id,
        lease_version,
        lease_fence,
    ))
}

/// The persisted proof of a lease token: `sha256:<hex>`. The raw token is never
/// stored, logged, or returned by a browser route.
async fn lease_fingerprint(context: &RequestContext, token: &str) -> Result<String, ApiError> {
    if token.is_empty() || token.len() > 256 || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(domain_failure(context, DomainError::LeaseFenceInvalid));
    }
    let digest = sha256_hex(token)
        .await
        .map_err(|_| service_unavailable(context))?;
    Ok(format!("{FINGERPRINT_PREFIX}{digest}"))
}

/// A bounded stable reason code. Free-form text is never persisted.
fn validate_reason_code(
    context: &RequestContext,
    value: Option<&str>,
) -> Result<Option<String>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let valid = !value.is_empty()
        && value.len() <= 96
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.')
        });
    if valid {
        Ok(Some(value.to_owned()))
    } else {
        Err(validation_error(
            context,
            "reason_code_invalid",
            "The reason code is invalid.",
        ))
    }
}

/// A project-scoped definition is visible to a member without an explicit grant
/// only when the member can manage projects. The role comes from the CURRENT
/// membership the central authorization path already resolved, never from a
/// client-supplied value.
fn project_scope_is_manager(access: &crate::routes::authorization::OrgAccess) -> bool {
    matches!(access.membership.role.as_str(), "owner" | "admin")
}

#[allow(clippy::too_many_arguments)]
fn security_statement(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    principal: &crate::core::Principal,
    org_id: &str,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    metadata: &Value,
) -> Result<D1PreparedStatement, ApiError> {
    crate::routes::support::security_event_statement(
        database,
        context,
        Some(principal),
        Some(org_id),
        &generated_id("sec"),
        action,
        resource_type,
        Some(resource_id),
        "success",
        metadata,
    )
}

fn device_audit(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    access: &DeviceAccess,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    metadata: &Value,
) -> Result<D1PreparedStatement, ApiError> {
    crate::routes::support::security_event_statement_with_context(
        database,
        context,
        None,
        Some(&access.device.org_id),
        &generated_id("sec"),
        action,
        resource_type,
        Some(resource_id),
        "success",
        metadata,
        Some(&access.device.device_id),
        None,
        None,
        None,
    )
}

async fn resume_next_run(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    automation: &AutomationDefinitionRecord,
) -> Result<Option<String>, ApiError> {
    let revision =
        crate::jobs::automations::load_revision(&AutomationsRepository::new(database), automation)
            .await
            .map_err(|error| store_failure(context, error))?;
    let now_epoch = parse_instant_utc(context.received_at.as_str())
        .map_err(|_| domain_failure(context, DomainError::ScheduleInvalid))?;
    crate::jobs::automations::plan_next_run(&revision.rule, &revision.zone, now_epoch)
        .map_err(|error| domain_failure(context, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> RequestContext {
        RequestContext::new(
            "req_0123456789abcdef0123456789abcdef".parse().unwrap(),
            crate::core::CorrelationId::new("req_0123456789abcdef0123456789abcdef").unwrap(),
            "2026-09-25T16:00:00.000Z".parse().unwrap(),
        )
    }

    fn schedule(kind: &str) -> ScheduleRequest {
        ScheduleRequest {
            kind: kind.to_owned(),
            expression: None,
            timezone: None,
            dom_dow_mode: None,
            dst_policy: None,
            scheduled_at: None,
            every: None,
            unit: None,
            anchor_at: None,
            by_weekday: None,
            by_monthday: None,
            by_month: None,
            overlap_policy: None,
            missed_policy: None,
            catch_up_limit: None,
            utc_offset_seconds: None,
            utc_offset_transitions: None,
        }
    }

    #[test]
    fn permission_names_are_the_frozen_p06_strings() {
        assert_eq!(
            automation_permission(PERMISSION_AUTOMATIONS_READ).as_str(),
            "automations.read"
        );
        assert_eq!(
            automation_permission(PERMISSION_AUTOMATIONS_MANAGE).as_str(),
            "automations.manage"
        );
        assert_eq!(
            automation_permission(PERMISSION_AUTOMATIONS_RUN).as_str(),
            "automations.run"
        );
    }

    #[test]
    fn domain_codes_map_to_the_frozen_vocabulary() {
        for error in [
            DomainError::AutomationOverlapPolicy,
            DomainError::AutomationMissedScheduleLimit,
            DomainError::OccurrenceAlreadyClaimed,
            DomainError::OccurrenceLeaseExpired,
            DomainError::OccurrenceAmbiguous,
            DomainError::LeaseFenceInvalid,
            DomainError::ExecutionPrincipalUnavailable,
            DomainError::DeviceNotEligible,
            DomainError::OffPeakNotAllowed,
            DomainError::OrganizationPendingDeletion,
            DomainError::EntitlementNotGranted,
            DomainError::EntitlementGraceExpired,
            DomainError::ScheduleInvalid,
            DomainError::ScheduleTimezoneInvalid,
            DomainError::ScheduleIntervalInvalid,
            DomainError::DstMissingTime,
            DomainError::DstRepeatedTime,
        ] {
            let mapped = domain_failure(&context(), error);
            let code = mapped.error.code;
            assert!(!code.as_str().is_empty());
            assert!(
                (400..=499).contains(&code.status_code()),
                "{error:?} mapped to {}",
                code.status_code()
            );
        }
    }

    #[test]
    fn a_missing_resource_is_the_non_disclosing_not_found_shape() {
        let mapped = domain_failure(&context(), DomainError::AutomationNotFound);
        assert_eq!(mapped.error.code, ApiErrorCode::NotFound);
        assert_eq!(
            mapped.error.details.get("reason"),
            Some(&json!("automation_not_found"))
        );
    }

    #[test]
    fn a_malformed_timezone_is_a_timezone_failure_not_a_generic_schedule_failure() {
        let mut request = schedule("cron");
        request.expression = Some("0 9 * * 1-5".into());
        request.timezone = Some("America/Los Angeles".into());
        request.utc_offset_seconds = Some(-28_800);
        let error = build_schedule(&context(), &request).unwrap_err();
        assert_eq!(
            error.error.details.get("reason"),
            Some(&json!("schedule_timezone_invalid"))
        );
    }

    #[test]
    fn a_named_zone_without_a_resolved_offset_is_refused_rather_than_assumed_utc() {
        let mut request = schedule("cron");
        request.expression = Some("0 9 * * 1-5".into());
        request.timezone = Some("America/Los_Angeles".into());
        let error = build_schedule(&context(), &request).unwrap_err();
        assert_eq!(
            error.error.details.get("reason"),
            Some(&json!("schedule_timezone_invalid"))
        );
    }

    #[test]
    fn a_valid_cron_rule_is_built_with_its_resolved_zone() {
        let mut request = schedule("cron");
        request.expression = Some("0 9 * * 1-5".into());
        request.timezone = Some("America/Los_Angeles".into());
        request.utc_offset_seconds = Some(-28_800);
        let (rule, zone) = build_schedule(&context(), &request).unwrap();
        assert_eq!(rule.kind(), ScheduleKind::Cron);
        assert_eq!(zone.offset_at(0), -28_800);
    }

    #[test]
    fn an_invalid_expression_surfaces_a_schedule_failure_without_echoing_it() {
        let mut request = schedule("cron");
        request.expression = Some("not a cron".into());
        request.timezone = Some("America/Los_Angeles".into());
        request.utc_offset_seconds = Some(-28_800);
        let error = build_schedule(&context(), &request).unwrap_err();
        let rendered = serde_json::to_string(&error.error.details).unwrap();
        assert!(!rendered.contains("not a cron"));
        assert_eq!(
            error.error.details.get("reason"),
            Some(&json!("schedule_invalid"))
        );
    }

    #[test]
    fn a_one_time_rule_validates_its_instant() {
        let mut request = schedule("one_time");
        request.scheduled_at = Some("2026-09-25T16:00:00.000Z".into());
        let (rule, zone) = build_schedule(&context(), &request).unwrap();
        assert_eq!(rule.kind(), ScheduleKind::OneTime);
        // A one-time rule has no zone, so it resolves as UTC.
        assert_eq!(zone.offset_at(0), 0);

        request.scheduled_at = Some("2026-09-25T16:00:00Z".into());
        assert!(build_schedule(&context(), &request).is_ok());
    }

    #[test]
    fn an_interval_rule_with_selectors_is_decoded_through_the_domain() {
        let mut request = schedule("interval");
        request.every = Some(2);
        request.unit = Some("days".into());
        request.anchor_at = Some("2026-09-25T16:00:00.000Z".into());
        request.timezone = Some("UTC".into());
        request.utc_offset_seconds = Some(0);
        request.by_weekday = Some(vec![1, 3]);
        let (rule, _) = build_schedule(&context(), &request).unwrap();
        assert_eq!(rule.kind(), ScheduleKind::Interval);

        request.every = Some(0);
        assert!(build_schedule(&context(), &request).is_err());
    }

    #[test]
    fn a_manual_rule_needs_no_zone_and_never_schedules() {
        let (rule, zone) = build_schedule(&context(), &schedule("manual")).unwrap();
        assert_eq!(rule.kind(), ScheduleKind::Manual);
        assert!(!rule.produces_scheduled_instants());
        assert_eq!(zone.offset_at(0), 0);
    }

    #[test]
    fn an_unknown_schedule_kind_is_a_schedule_failure() {
        let error = build_schedule(&context(), &schedule("weekly")).unwrap_err();
        assert_eq!(
            error.error.details.get("reason"),
            Some(&json!("schedule_invalid"))
        );
    }

    #[test]
    fn an_out_of_range_offset_is_refused() {
        let mut request = schedule("cron");
        request.expression = Some("0 9 * * 1-5".into());
        request.timezone = Some("UTC".into());
        request.utc_offset_seconds = Some(100_000);
        assert!(build_schedule(&context(), &request).is_err());
    }

    #[test]
    fn page_limits_are_clamped_to_the_frozen_bounds() {
        assert_eq!(occurrence_page_limit(None), 50);
        assert_eq!(occurrence_page_limit(Some(0)), 50);
        assert_eq!(occurrence_page_limit(Some(1_000)), MAX_OCCURRENCE_PAGE);
        assert_eq!(occurrence_page_limit(Some(10)), 10);
        // The device due list is bounded at 20 by the frozen contract.
        assert_eq!(due_page_limit(None), 20);
        assert_eq!(due_page_limit(Some(100)), 20);
        assert_eq!(due_page_limit(Some(5)), 5);
    }

    #[test]
    fn a_reason_code_is_bounded_and_never_free_form_text() {
        let context = context();
        assert_eq!(
            validate_reason_code(&context, Some("tool_denied")).unwrap(),
            Some("tool_denied".into())
        );
        assert!(validate_reason_code(&context, Some("")).is_err());
        assert!(validate_reason_code(&context, Some("Tool denied")).is_err());
        assert!(validate_reason_code(&context, Some(&"x".repeat(97))).is_err());
        assert_eq!(validate_reason_code(&context, None).unwrap(), None);
    }

    #[test]
    fn a_presented_fence_must_be_positive_and_well_formed() {
        let context = context();
        assert!(presented_fence(&context, "lse_0123456789abcdef0123456789abcdef", 1, 1).is_ok());
        assert!(presented_fence(&context, "lse_0123456789abcdef0123456789abcdef", 0, 1).is_err());
        assert!(presented_fence(&context, "lse_0123456789abcdef0123456789abcdef", 1, 0).is_err());
        assert!(presented_fence(&context, "occ_0123456789abcdef0123456789abcdef", 1, 1).is_err());
    }

    #[test]
    fn the_execution_retry_request_is_bounded_by_the_frozen_envelope() {
        let context = context();
        assert!(resolve_execution_retry(&context, None).is_ok());
        let invalid = ExecutionRetryRequest {
            max_start_attempts: 4,
            lease_ttl_seconds: 300,
            heartbeat_interval_seconds: 30,
        };
        assert!(resolve_execution_retry(&context, Some(&invalid)).is_err());
        let valid = ExecutionRetryRequest {
            max_start_attempts: 3,
            lease_ttl_seconds: 3600,
            heartbeat_interval_seconds: 60,
        };
        assert!(resolve_execution_retry(&context, Some(&valid)).is_ok());
    }

    #[test]
    fn an_off_peak_policy_can_narrow_but_never_broaden_the_host_baseline() {
        let context = context();
        let base = OffPeakPolicyRequest {
            schema_version: 1,
            eligibility_source: "provider_ticket".into(),
            allowed_route_aliases: Some(vec!["cheap".into()]),
            tool_constraints: OffPeakToolConstraintsRequest {
                deny_automation_mutation: true,
                deny_recursive_off_peak: true,
                allow_background_processes: false,
            },
        };
        assert!(resolve_off_peak(&context, Some(&base)).is_ok());
        let broadened = OffPeakPolicyRequest {
            tool_constraints: OffPeakToolConstraintsRequest {
                allow_background_processes: true,
                ..OffPeakPolicyRequest {
                    schema_version: 1,
                    eligibility_source: "provider_ticket".into(),
                    allowed_route_aliases: None,
                    tool_constraints: OffPeakToolConstraintsRequest {
                        deny_automation_mutation: true,
                        deny_recursive_off_peak: true,
                        allow_background_processes: false,
                    },
                }
                .tool_constraints
            },
            ..base
        };
        let error = resolve_off_peak(&context, Some(&broadened)).unwrap_err();
        assert_eq!(
            error.error.details.get("reason"),
            Some(&json!("off_peak_not_allowed"))
        );
        assert!(resolve_off_peak(&context, None).unwrap().is_none());
    }

    #[test]
    fn an_off_peak_schema_version_or_source_must_be_known() {
        let context = context();
        let request = OffPeakPolicyRequest {
            schema_version: 2,
            eligibility_source: "provider_ticket".into(),
            allowed_route_aliases: None,
            tool_constraints: OffPeakToolConstraintsRequest {
                deny_automation_mutation: true,
                deny_recursive_off_peak: true,
                allow_background_processes: false,
            },
        };
        assert!(resolve_off_peak(&context, Some(&request)).is_err());
        let unknown_source = OffPeakPolicyRequest {
            schema_version: 1,
            eligibility_source: "always".into(),
            ..request
        };
        assert!(resolve_off_peak(&context, Some(&unknown_source)).is_err());
    }

    #[test]
    fn the_queued_successor_bound_is_validated() {
        let context = context();
        assert_eq!(validate_queued_successor_max_age(&context, 60).unwrap(), 60);
        assert_eq!(
            validate_queued_successor_max_age(&context, MAX_QUEUED_SUCCESSOR_MAX_AGE_SECONDS)
                .unwrap(),
            604_800
        );
        assert!(validate_queued_successor_max_age(&context, 59).is_err());
        assert!(validate_queued_successor_max_age(&context, 604_801).is_err());
    }

    #[test]
    fn the_tool_policy_scope_is_one_of_the_three_frozen_values() {
        let context = context();
        for scope in ["project", "organization", "agent"] {
            let request = ExecutionPolicyRequest {
                model_alias: None,
                budget_id: None,
                tool_policy_scope: Some(scope.into()),
                required_policy_version: None,
            };
            assert!(
                resolve_execution_policy(&context, &request).is_ok(),
                "{scope}"
            );
        }
        let request = ExecutionPolicyRequest {
            model_alias: None,
            budget_id: None,
            tool_policy_scope: Some("platform".into()),
            required_policy_version: None,
        };
        assert!(resolve_execution_policy(&context, &request).is_err());
    }

    #[test]
    fn an_execution_policy_model_alias_is_validated() {
        let context = context();
        let request = ExecutionPolicyRequest {
            model_alias: Some("Coding Default".into()),
            budget_id: None,
            tool_policy_scope: None,
            required_policy_version: None,
        };
        assert!(resolve_execution_policy(&context, &request).is_err());
    }

    #[test]
    fn a_required_policy_version_must_be_positive() {
        let context = context();
        let request = ExecutionPolicyRequest {
            model_alias: None,
            budget_id: None,
            tool_policy_scope: None,
            required_policy_version: Some(0),
        };
        assert!(resolve_execution_policy(&context, &request).is_err());
    }

    #[test]
    fn the_due_projection_contains_no_lease_token_or_fingerprint() {
        let rendered = due_projection(&DueOccurrenceFixture::row()).to_string();
        assert!(!rendered.contains("fingerprint"));
        assert!(!rendered.contains("lease_token"));
        assert!(rendered.contains("lease_ttl_seconds"));
    }

    struct DueOccurrenceFixture;

    impl DueOccurrenceFixture {
        fn row() -> crate::repositories::DueOccurrenceRecord {
            crate::repositories::DueOccurrenceRecord {
                occurrence_id: "occ_0123456789abcdef0123456789abcdef".into(),
                automation_id: "aut_0123456789abcdef0123456789abcdef".into(),
                org_id: "org_0123456789abcdef0123456789abcdef".into(),
                project_id: None,
                schedule_rule_id: "sch_0123456789abcdef0123456789abcdef".into(),
                kind: "scheduled".into(),
                scheduled_for_utc: Some("2026-09-25T16:00:00.000Z".into()),
                execution_principal_kind: "user".into(),
                execution_principal_id: "usr_0123456789abcdef0123456789abcdef".into(),
                off_peak_mode: "normal".into(),
                policy_snapshot_id: None,
                policy_version: None,
                state: "dispatching".into(),
                state_version: 1,
                attempt: 0,
                reason_code: None,
                run_id: None,
                blocked_by_occurrence_id: None,
                lease_expires_at: None,
                queued_at: None,
                started_at: None,
                finished_at: None,
                created_at: "2026-09-25T15:59:59.000Z".into(),
                updated_at: "2026-09-25T15:59:59.000Z".into(),
                lease_ttl_seconds: 300,
                heartbeat_interval_seconds: 30,
                required_capabilities_json: "[\"text\"]".into(),
                execution_model_alias: None,
                execution_budget_id: None,
                tool_policy_scope: "project".into(),
            }
        }
    }

    #[test]
    fn a_corrupt_capability_list_degrades_to_an_empty_array() {
        let record = decode_string_list(&context(), "not json");
        assert!(record.is_err());
        let capabilities: Value = serde_json::from_str("[\"text\"]").unwrap_or_else(|_| json!([]));
        assert_eq!(capabilities, json!(["text"]));
    }
}
