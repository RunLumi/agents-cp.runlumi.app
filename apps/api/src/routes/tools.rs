//! P05 tool, MCP, and tool-policy administration plus the device tool-decision
//! broker (P05-CG `p05-cg-v1`, F13, F04, F16, F23).
//!
//! The control plane is the policy, approval, and audit authority. It never
//! executes a tool, never resolves a secret, and never stores raw tool
//! arguments. `POST /runs/{run_id}/tool-decisions` resolves the run, its device,
//! its organization, and its current policy from server state, hands them to the
//! pure evaluator in `modules::tool_policy`, and records the resulting decision
//! in the run timeline, the audit log, and the domain outbox.
//!
//! The evaluator itself is not duplicated here: `modules::tool_policy` owns
//! risk-class floors, MCP review state, browser/computer rules, and the
//! fail-closed default. This module owns only the transport boundary (bounded
//! request validation, the `deny_unknown_fields` write surface), the mapping
//! between D1 rows and domain values, tenant scope, and persistence.
//!
//! Two invariants are worth stating explicitly, because they are the reason the
//! broker cannot be a client override:
//!
//! * the risk class, fingerprint, and source that decide a call come from the
//!   tenant catalog, never from the request body, and
//! * an approval is bound to the exact tool, fingerprint, and redacted argument
//!   summary the broker recorded, so it cannot be replayed for a changed tool,
//!   a changed fingerprint, or changed high-impact arguments.
//!
//! The shared idempotency and pagination helpers live here so
//! `routes::approvals` can reuse them without a shared-file edit; they should
//! move to `routes::support` when the coordinator wires the P05 modules.

use std::{collections::BTreeSet, sync::Arc};

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
    adapters::{add_seconds, new_resource_id, sha256_hex},
    app::AppState,
    core::{
        ActorId, ApiError, ApiErrorCode, CapabilityId, CredentialId, IdempotencyKeyDigest,
        IdempotencyRecord, IdempotencyScope, IdempotencyState, McpRegistrationId, OrganizationId,
        Principal, RequestContext, RequestFingerprint, RunId, StoredSuccess, Timestamp, ToolCallId,
        ToolId, UserId,
    },
    http::auth::require_csrf,
    modules::{
        authorization::{
            AuthorizationDecision, DenyReason, MembershipRole, MembershipSnapshot,
            MembershipStatus, OrganizationContext, OrganizationState, Permission, ResourceContext,
            authorize,
        },
        policy_p05::{self as snapshot_policy, PolicyDecision, ToolPolicySection},
        tool_policy::{
            AgentToolPolicy, ApprovalMode, BrowserAction, BrowserPolicy, CapabilityDefinition,
            CapabilityLifecycle, ComputerAction, ComputerPolicy, DecisionReasonCode, ExecutionMode,
            ExternalSubmitPolicy, McpPolicyStatus, McpRegistration, McpSource, PlatformToolPolicy,
            PolicyEvaluationInput, PolicyPosture, RiskClass, RuntimeCapabilities,
            TOOL_POLICY_SCHEMA_VERSION, ToolCall, ToolCatalog, ToolDecision, ToolDefinition,
            ToolLifecycle, ToolPolicyLayer, ToolSource, evaluate,
        },
    },
    repositories::{
        AgentDefinitionRecord, ApprovalRepository, ApprovalRequestRecord,
        CapabilityDefinitionRecord, DeviceRecord, IdempotencyClaimToken, IdempotencyLookup,
        IdempotencyRepository, IdentityRepository, InheritedApproval, McpRegistrationRecord,
        McpRegistrationUpdate, MembershipRecord, NewApprovalRequest, NewMcpRegistration,
        NewRunEventInput, NewToolCallRef, NewToolDefinition, OrganizationRecord,
        OrganizationRepository, PolicyRepository, RunRepository, RunToolScopeRecord,
        ToolCallRefRecord, ToolDefinitionRecord, ToolDefinitionUpdate, ToolPolicyRecord,
        ToolRepository,
    },
    routes::{
        authorization::{authorize_device, authorize_org},
        errors,
        support::{
            database, database_error, deterministic_resource_id, domain_error, idempotency_key,
            outbox_statement, security_event_statement, security_event_statement_with_context,
        },
        usage::{ScopedMutationCommit, commit_scoped_mutation, prepare_scoped_mutation},
    },
};

/// Approval request lifetime, matching the P05-CG example timeline.
pub const APPROVAL_TTL_SECONDS: u32 = 15 * 60;

const PAGE_LIMIT_DEFAULT: i32 = 50;
const PAGE_LIMIT_MAX: i32 = 100;
/// One extra row proves `has_more` without a second query.
pub const PAGE_FETCH_EXTRA: i32 = 1;
const CAPABILITY_IDS_MAX: usize = 32;
const CAPABILITY_CATALOG_MAX: i32 = 500;
const METADATA_MAX: usize = 4_096;
const ORIGIN_MAX: usize = 255;
const LIST_MAX: usize = 256;
const CURSOR_MAX: usize = 512;
/// Route-level decision reasons for an approval that can no longer be used. They
/// are P05-CG codes; every other reason comes from the evaluator's own code
/// enum so the two layers cannot drift.
const REASON_APPROVAL_EXPIRED: &str = "approval_expired";
const REASON_APPROVAL_RESOLVED: &str = "approval_already_resolved";
const RUN_EVENT_DECISION: &str = "tool.decision_recorded.v1";
const RUN_EVENT_DENIED: &str = "tool.denied.v1";
const RUN_EVENT_APPROVAL_REQUESTED: &str = "tool.approval_requested.v1";

// ---------------------------------------------------------------------------
// Wire mapping between D1 text columns and the pure domain values
// ---------------------------------------------------------------------------

/// Catalog lifecycle as stored by migration `0010`. `review` is the frozen
/// column value for a tool that must be re-reviewed before it runs again.
fn tool_lifecycle(value: &str) -> Option<ToolLifecycle> {
    match value {
        "active" => Some(ToolLifecycle::Active),
        "review" => Some(ToolLifecycle::Review),
        "disabled" => Some(ToolLifecycle::Disabled),
        _ => None,
    }
}

/// The frozen column has no `deprecated` value, so a deprecated lifecycle is not
/// writable and is reported as a validation failure instead of being coerced
/// into a different meaning.
fn tool_lifecycle_text(value: ToolLifecycle) -> Option<&'static str> {
    match value {
        ToolLifecycle::Active => Some("active"),
        ToolLifecycle::Review => Some("review"),
        ToolLifecycle::Disabled => Some("disabled"),
        ToolLifecycle::Deprecated => None,
    }
}

fn tool_source(value: &str) -> Option<ToolSource> {
    match value {
        "built_in" => Some(ToolSource::BuiltIn),
        "plugin" => Some(ToolSource::Plugin),
        "custom" => Some(ToolSource::Custom),
        _ => None,
    }
}

fn mcp_source(value: &str) -> Option<McpSource> {
    match value {
        "built_in" => Some(McpSource::BuiltIn),
        "plugin" => Some(McpSource::Plugin),
        "custom" => Some(McpSource::Custom),
        _ => None,
    }
}

fn mcp_policy_status(value: &str) -> Option<McpPolicyStatus> {
    match value {
        "approved" => Some(McpPolicyStatus::Approved),
        "pending_review" => Some(McpPolicyStatus::PendingReview),
        "denied" => Some(McpPolicyStatus::Denied),
        "disabled" => Some(McpPolicyStatus::Disabled),
        _ => None,
    }
}

/// `revoked` is not one of the frozen column values, so it is not writable.
fn mcp_policy_status_text(value: McpPolicyStatus) -> Option<&'static str> {
    match value {
        McpPolicyStatus::Approved => Some("approved"),
        McpPolicyStatus::PendingReview => Some("pending_review"),
        McpPolicyStatus::Denied => Some("denied"),
        McpPolicyStatus::Disabled => Some("disabled"),
        McpPolicyStatus::Revoked => None,
    }
}

fn external_submit_policy(value: &str) -> Option<ExternalSubmitPolicy> {
    match value {
        "allow" => Some(ExternalSubmitPolicy::Allow),
        "require_session_approval" | "session_approval" => {
            Some(ExternalSubmitPolicy::SessionApproval)
        }
        "require_per_use_approval" | "per_use_approval" => {
            Some(ExternalSubmitPolicy::PerUseApproval)
        }
        "deny" => Some(ExternalSubmitPolicy::Deny),
        _ => None,
    }
}

/// How the current policy was obtained. A non-`ok` state never produces an
/// `allow` decision: the evaluator denies when no valid layer is supplied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PolicyState {
    Ok,
    Missing,
    SchemaUnsupported,
}

impl PolicyState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Missing => "missing",
            Self::SchemaUnsupported => "schema_unsupported",
        }
    }
}

// ---------------------------------------------------------------------------
// Request and response shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ToolListQuery {
    pub limit: Option<u16>,
    pub cursor: Option<String>,
    pub source: Option<String>,
    pub risk_class: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct McpListQuery {
    pub limit: Option<u16>,
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateToolRequest {
    pub name: String,
    pub source: String,
    pub risk_class: String,
    #[serde(default)]
    pub capability_ids: Vec<String>,
    pub fingerprint: String,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateToolRequest {
    pub version: i64,
    pub lifecycle: Option<String>,
    pub risk_class: Option<String>,
    pub capability_ids: Option<Vec<String>>,
    pub fingerprint: Option<String>,
    pub metadata: Option<Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct EndpointMetadata {
    pub url: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct CommandMetadata {
    pub command: Option<String>,
    pub arguments: Vec<String>,
    pub working_directory: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolListEntry {
    pub tool_id: String,
    pub fingerprint: String,
    pub risk_class: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateMcpRequest {
    pub source: String,
    pub transport: String,
    #[serde(default)]
    pub endpoint_metadata: Option<EndpointMetadata>,
    #[serde(default)]
    pub command_metadata: Option<CommandMetadata>,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub required_secret_handles: Vec<String>,
    #[serde(default)]
    pub tool_fingerprint: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateMcpRequest {
    pub version: i64,
    pub policy_status: Option<String>,
    pub transport: Option<String>,
    pub endpoint_metadata: Option<EndpointMetadata>,
    pub command_metadata: Option<CommandMetadata>,
    pub allowed_origins: Option<Vec<String>>,
    pub required_secret_handles: Option<Vec<String>>,
    pub tool_fingerprint: Option<String>,
    pub tool_list: Option<Vec<ToolListEntry>>,
}

/// The written tool policy document plus the optimistic row `version`.
///
/// The stored document is a [`ToolPolicyLayer`], which is also valid as the P03
/// policy snapshot `tools` section, so one document is both the administration
/// surface and the snapshot projection the execution host is evaluated against.
/// The written browser policy. `external_submit` is a wire string so the frozen
/// P05-CG values are accepted verbatim instead of the domain variant names.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BrowserPolicyRequest {
    pub allowed_domains: Vec<String>,
    pub blocked_domains: Vec<String>,
    pub allow_download: bool,
    pub allow_upload: bool,
    pub allow_authenticated: bool,
    pub allow_clipboard: bool,
    pub external_submit: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ComputerPolicyRequest {
    pub allow_accessibility: bool,
    pub allow_screen_capture: bool,
    pub allow_keyboard_mouse: bool,
    pub allow_shell_escalation: bool,
    pub allowed_applications: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutToolPolicyRequest {
    pub schema_version: u32,
    pub default_posture: PolicyPosture,
    pub default_approval_mode: ApprovalMode,
    #[serde(default)]
    pub tool_ids: Vec<String>,
    /// Explicit per-tool denials. A deny is never widened by another layer.
    #[serde(default)]
    pub denied_tool_ids: Vec<String>,
    #[serde(default)]
    pub mcp_ids: Vec<String>,
    #[serde(default)]
    pub denied_mcp_ids: Vec<String>,
    #[serde(default)]
    pub tool_approval_modes: std::collections::BTreeMap<String, ApprovalMode>,
    #[serde(default)]
    pub browser: BrowserPolicyRequest,
    #[serde(default)]
    pub computer: ComputerPolicyRequest,
    pub version: i64,
}

impl PutToolPolicyRequest {
    /// Build the domain layer. `version` is the row version the caller supplies
    /// for optimistic concurrency; the stored document carries the layer version
    /// that the repository advances.
    fn layer(&self) -> Result<ToolPolicyLayer, &'static str> {
        Ok(ToolPolicyLayer {
            schema_version: self.schema_version,
            default_posture: self.default_posture,
            tool_ids: self.tool_ids.iter().cloned().collect(),
            denied_tool_ids: self.denied_tool_ids.iter().cloned().collect(),
            mcp_ids: self.mcp_ids.iter().cloned().collect(),
            denied_mcp_ids: self.denied_mcp_ids.iter().cloned().collect(),
            default_approval_mode: self.default_approval_mode,
            tool_approval_modes: self.tool_approval_modes.clone(),
            browser: BrowserPolicy {
                allowed_domains: self.browser.allowed_domains.iter().cloned().collect(),
                blocked_domains: self.browser.blocked_domains.iter().cloned().collect(),
                allow_download: self.browser.allow_download,
                allow_upload: self.browser.allow_upload,
                allow_authenticated: self.browser.allow_authenticated,
                allow_clipboard: self.browser.allow_clipboard,
                external_submit: external_submit_policy(
                    self.browser.external_submit.as_deref().unwrap_or("deny"),
                )
                .ok_or("external_submit")?,
            },
            computer: ComputerPolicy {
                allow_accessibility: self.computer.allow_accessibility,
                allow_screen_capture: self.computer.allow_screen_capture,
                allow_keyboard_mouse: self.computer.allow_keyboard_mouse,
                allow_shell_escalation: self.computer.allow_shell_escalation,
                allowed_applications: self.computer.allowed_applications.iter().cloned().collect(),
            },
        })
    }
}

/// The device-scoped decision request. There is no `decision`, `allow`, or
/// `approved` field: the host asks for a decision and the server evaluates
/// current policy.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDecisionRequest {
    pub tool_call_id: String,
    pub tool_id: String,
    pub tool_fingerprint: String,
    pub capability_ids: Vec<String>,
    pub risk_class: String,
    pub arguments_summary: String,
    /// Required by policy evaluation for browser-risk tools. Additive to the
    /// frozen request shape: without it a browser-shaped call cannot be shown
    /// to satisfy the domain policy and is denied.
    #[serde(default)]
    pub browser_action: Option<BrowserAction>,
    /// Required by policy evaluation for computer-risk tools.
    #[serde(default)]
    pub computer_action: Option<ComputerAction>,
}

pub fn tool_json(tool: &ToolDefinitionRecord) -> Value {
    json!({
        "tool_id": tool.tool_id,
        "id": tool.tool_id,
        "org_id": tool.org_id,
        "name": tool.name,
        "source": tool.source,
        "risk_class": tool.risk_class,
        "capability_ids": json_field(&tool.capability_ids_json),
        "fingerprint": tool.fingerprint,
        "lifecycle": tool.lifecycle,
        "metadata": json_field(&tool.metadata_json),
        "version": tool.version,
        "created_at": tool.created_at,
        "updated_at": tool.updated_at,
    })
}

pub fn mcp_json(registration: &McpRegistrationRecord) -> Value {
    json!({
        "mcp_id": registration.mcp_registration_id,
        "id": registration.mcp_registration_id,
        "org_id": registration.org_id,
        "source": registration.source,
        "transport": registration.transport,
        "endpoint_metadata": json_field(&registration.endpoint_metadata_json),
        "command_metadata": json_field(&registration.command_metadata_json),
        "allowed_origins": json_field(&registration.allowed_origins_json),
        "required_secret_handles": json_field(&registration.required_secret_handles_json),
        "tool_fingerprint": registration.tool_fingerprint,
        "tool_list": json_field(&registration.tool_list_json),
        "policy_status": registration.policy_status,
        "version": registration.version,
        "created_at": registration.created_at,
        "updated_at": registration.updated_at,
    })
}

/// Public approval projection. It exposes the exact binding and the redacted
/// risk-relevant argument summary, never an argument body or a secret.
pub fn approval_json(approval: &ApprovalRequestRecord) -> Value {
    json!({
        "id": approval.approval_id,
        "org_id": approval.org_id,
        "project_id": approval.project_id,
        "run_id": approval.run_id,
        "tool_call_id": approval.tool_call_id,
        "tool_id": approval.tool_id,
        "tool_fingerprint": approval.tool_fingerprint,
        "risk_class": approval.risk_class,
        "approval_mode": approval.approval_mode,
        "status": approval.status,
        "arguments_summary": approval.arguments_summary,
        "requested_by_principal_id": approval.requested_by_principal_id,
        "requested_at": approval.requested_at,
        "expires_at": approval.expires_at,
        "resolved_by_principal_id": approval.resolved_by_principal_id,
        "resolved_at": approval.resolved_at,
        "resolution_reason": approval.resolution_reason,
        "version": approval.version,
    })
}

fn json_field(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or(Value::Null)
}

fn string_list(raw: &str) -> BTreeSet<String> {
    serde_json::from_str::<Value>(raw)
        .ok()
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

// ---------------------------------------------------------------------------
// Tool catalog routes
// ---------------------------------------------------------------------------

/// `GET /api/v1/orgs/{org_id}/tools`
#[worker::send]
pub async fn list_tools(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<ToolListQuery>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ToolsRead,
        Some("tool"),
        None,
    )
    .await?;
    let source = optional_filter(&context, query.source.as_deref())?;
    let risk_class = optional_filter(&context, query.risk_class.as_deref())?;
    if !source.is_empty() && tool_source(&source).is_none() {
        return Err(validation_error(
            &context,
            "source_invalid",
            "Choose a valid tool source.",
        ));
    }
    if !risk_class.is_empty() && RiskClass::parse(&risk_class).is_none() {
        return Err(validation_error(
            &context,
            "risk_class_invalid",
            "Choose a valid tool risk class.",
        ));
    }
    let limit = page_limit(query.limit);
    let cursor = decode_page_cursor(query.cursor.as_deref(), &context)?;
    let tools = ToolRepository::new(database(&state, &context)?)
        .list_tools(
            &org_id,
            &source,
            &risk_class,
            cursor
                .as_ref()
                .map(|(timestamp, id)| (timestamp.as_str(), id.as_str())),
            limit + PAGE_FETCH_EXTRA,
        )
        .await
        .map_err(|error| database_error(&context, error))?;
    let last = tools
        .last()
        .map(|tool| (tool.updated_at.clone(), tool.tool_id.clone()));
    Ok(Json(finish_page(tools, limit, tool_json, last)).into_response())
}

/// `POST /api/v1/orgs/{org_id}/tools`
#[worker::send]
pub async fn create_tool(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<CreateToolRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ToolsManage,
        Some("tool"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let name = bounded_name(&context, &body.name)?;
    let source = tool_source(&body.source).ok_or_else(|| {
        validation_error(&context, "source_invalid", "Choose a valid tool source.")
    })?;
    let risk_class = RiskClass::parse(&body.risk_class).ok_or_else(|| {
        validation_error(
            &context,
            "risk_class_invalid",
            "Choose a valid tool risk class.",
        )
    })?;
    let fingerprint = fingerprint_value(&context, &body.fingerprint)?;
    let capability_ids = capability_ids_value(&context, &body.capability_ids)?;
    let metadata = metadata_value(&context, body.metadata.as_ref())?;
    let database = database(&state, &context)?;
    let create_path = format!("/api/v1/orgs/{org_id}/tools");
    let fingerprint_input = format!(
        "POST\\n{create_path}\\n{name}:{}:{}:{fingerprint}:{capability_ids}:{metadata}",
        source.as_str(),
        risk_class.as_str()
    );
    if let Some(success) = lookup_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &create_path,
        &fingerprint_input,
        database,
        &context,
    )
    .await?
    {
        return Ok(replay_response(&success));
    }
    let tool_id = deterministic_resource_id(
        "tool",
        &key,
        &format!("tool:{org_id}:{fingerprint}"),
        &context,
    )
    .await?;
    let repository = ToolRepository::new(database);
    if let Some(existing) = repository
        .find_tool(&tool_id, &org_id)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        if existing.fingerprint != fingerprint || existing.name != name {
            return Err(idempotency_conflict(&context));
        }
        return Ok((StatusCode::OK, Json(tool_json(&existing))).into_response());
    }
    if let Some(existing) = repository
        .find_tool_by_fingerprint(&org_id, &fingerprint)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "tool_fingerprint_conflict",
            "A tool with this fingerprint is already registered.",
        )
        .with_detail("existing_tool_id", json!(existing.tool_id)));
    }
    let expected = ToolDefinitionRecord {
        tool_id: tool_id.clone(),
        org_id: org_id.clone(),
        name: name.clone(),
        source: source.as_str().to_owned(),
        risk_class: risk_class.as_str().to_owned(),
        capability_ids_json: capability_ids.clone(),
        fingerprint: fingerprint.clone(),
        lifecycle: tool_lifecycle_text(ToolLifecycle::Active)
            .unwrap_or("active")
            .to_owned(),
        metadata_json: metadata.clone(),
        version: 1,
        created_by_user_id: access.principal.user_id.as_str().to_owned(),
        created_at: context.received_at.as_str().to_owned(),
        updated_at: context.received_at.as_str().to_owned(),
    };
    let mutation = begin_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &create_path,
        &fingerprint_input,
        database,
        &context,
    )
    .await?;
    let pending = match mutation {
        MutationClaim::Replay(success) => return Ok(replay_response(&success)),
        MutationClaim::Pending(pending) => pending,
    };
    let success =
        StoredSuccess::new(201, tool_json(&expected)).map_err(|_| internal_error(&context))?;
    let insert = repository
        .insert_tool_statement(&NewToolDefinition {
            tool_id: &tool_id,
            org_id: &org_id,
            name: &name,
            source: source.as_str(),
            risk_class: risk_class.as_str(),
            capability_ids_json: &capability_ids,
            fingerprint: &fingerprint,
            metadata_json: &metadata,
            created_by_user_id: access.principal.user_id.as_str(),
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let event_metadata = json!({
        "source": source.as_str(),
        "risk_class": risk_class.as_str(),
    });
    let security = session_security_event(
        database,
        &context,
        &access.principal,
        &org_id,
        "tool.catalog_tool_created.v1",
        "tool",
        &tool_id,
        "success",
        &event_metadata,
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "tool.catalog_updated.v1",
        &event_metadata,
    )?;
    let results = commit_mutation(
        database,
        &pending,
        &context.received_at,
        &success,
        vec![insert, security],
        outbox,
    )
    .await
    .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[2]).unwrap_or_default() != 1 {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "tool_fingerprint_conflict",
            "A tool with this fingerprint is already registered.",
        ));
    }
    Ok(replay_response(&success))
}

/// `PATCH /api/v1/orgs/{org_id}/tools/{tool_id}`
#[worker::send]
pub async fn update_tool(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, tool_id)): Path<(String, String)>,
    Json(body): Json<UpdateToolRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ToolsManage,
        Some("tool"),
        Some(&tool_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    if ToolId::new(tool_id.as_str()).is_err() {
        return Err(not_found(&context, "The tool was not found."));
    }
    if body.version < 1 {
        return Err(validation_error(
            &context,
            "version_invalid",
            "Reload the tool before updating it.",
        ));
    }
    let lifecycle = match body.lifecycle.as_deref() {
        Some(value) => Some(tool_lifecycle(value).ok_or_else(|| {
            validation_error(
                &context,
                "lifecycle_invalid",
                "Choose a valid tool lifecycle.",
            )
        })?),
        None => None,
    };
    let risk_class = match body.risk_class.as_deref() {
        Some(value) => Some(RiskClass::parse(value).ok_or_else(|| {
            validation_error(
                &context,
                "risk_class_invalid",
                "Choose a valid tool risk class.",
            )
        })?),
        None => None,
    };
    let capability_ids = match body.capability_ids.as_ref() {
        Some(values) => Some(capability_ids_value(&context, values)?),
        None => None,
    };
    let fingerprint = match body.fingerprint.as_deref() {
        Some(value) => Some(fingerprint_value(&context, value)?),
        None => None,
    };
    let metadata = match body.metadata.as_ref() {
        Some(value) => Some(metadata_value(&context, Some(value))?),
        None => None,
    };
    let database = database(&state, &context)?;
    let repository = ToolRepository::new(database);
    let current = repository
        .find_tool(&tool_id, &org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context, "The tool was not found."))?;
    if body.version != current.version {
        return Err(version_conflict(&context));
    }
    let fingerprint_changed = fingerprint
        .as_ref()
        .is_some_and(|value| *value != current.fingerprint);
    // A changed fingerprint is a new identity. Without an explicit lifecycle it
    // falls back to `review`, so no earlier approval can be inherited.
    let lifecycle = lifecycle.unwrap_or(if fingerprint_changed {
        ToolLifecycle::Deprecated
    } else {
        tool_lifecycle(&current.lifecycle).unwrap_or(ToolLifecycle::Active)
    });
    let next = ToolDefinitionRecord {
        tool_id: current.tool_id.clone(),
        org_id: current.org_id.clone(),
        name: current.name.clone(),
        source: current.source.clone(),
        risk_class: risk_class
            .map(|value| value.as_str().to_owned())
            .unwrap_or(current.risk_class),
        capability_ids_json: capability_ids.unwrap_or(current.capability_ids_json.clone()),
        fingerprint: fingerprint.unwrap_or(current.fingerprint.clone()),
        lifecycle: tool_lifecycle_text(lifecycle)
            .ok_or_else(|| {
                validation_error(
                    &context,
                    "lifecycle_invalid",
                    "Choose a valid tool lifecycle.",
                )
            })?
            .to_owned(),
        metadata_json: metadata.unwrap_or(current.metadata_json.clone()),
        version: current.version + 1,
        created_by_user_id: current.created_by_user_id.clone(),
        created_at: current.created_at.clone(),
        updated_at: context.received_at.as_str().to_owned(),
    };
    let success =
        StoredSuccess::new(200, tool_json(&next)).map_err(|_| internal_error(&context))?;
    let version_guard = repository
        .assert_tool_version_statement(&tool_id, &org_id, body.version)
        .map_err(|error| database_error(&context, error))?;
    let update = repository
        .update_tool_statement(&ToolDefinitionUpdate {
            tool_id: &next.tool_id,
            org_id: &org_id,
            name: &next.name,
            source: &next.source,
            risk_class: &next.risk_class,
            capability_ids_json: &next.capability_ids_json,
            fingerprint: &next.fingerprint,
            lifecycle: &next.lifecycle,
            metadata_json: &next.metadata_json,
            expected_version: body.version,
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let event_metadata = json!({
        "lifecycle": tool_lifecycle_text(lifecycle).unwrap_or("disabled"),
        "fingerprint_changed": fingerprint_changed,
    });
    let security = session_security_event(
        database,
        &context,
        &access.principal,
        &org_id,
        "tool.catalog_tool_updated.v1",
        "tool",
        &tool_id,
        "success",
        &event_metadata,
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "tool.catalog_updated.v1",
        &event_metadata,
    )?;
    let results = database
        .batch(vec![version_guard, update, security, outbox])
        .await
        .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[2]).unwrap_or_default() != 1 {
        return Err(version_conflict(&context));
    }
    Ok(replay_response(&success))
}

// ---------------------------------------------------------------------------
// MCP catalog routes
// ---------------------------------------------------------------------------

/// `GET /api/v1/orgs/{org_id}/mcp`
#[worker::send]
pub async fn list_mcp(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<McpListQuery>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ToolsRead,
        Some("mcp_registration"),
        None,
    )
    .await?;
    let limit = page_limit(query.limit);
    let cursor = decode_page_cursor(query.cursor.as_deref(), &context)?;
    let registrations = ToolRepository::new(database(&state, &context)?)
        .list_mcp_registrations(
            &org_id,
            cursor
                .as_ref()
                .map(|(timestamp, id)| (timestamp.as_str(), id.as_str())),
            limit + PAGE_FETCH_EXTRA,
        )
        .await
        .map_err(|error| database_error(&context, error))?;
    let last = registrations
        .last()
        .map(|row| (row.updated_at.clone(), row.mcp_registration_id.clone()));
    Ok(Json(finish_page(registrations, limit, mcp_json, last)).into_response())
}

/// `POST /api/v1/orgs/{org_id}/mcp`
///
/// A new registration is always stored `pending_review`: an unreviewed MCP
/// source can never authorize a tool, so approval is an explicit second step.
#[worker::send]
pub async fn create_mcp(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<CreateMcpRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ToolsManage,
        Some("mcp_registration"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let source = mcp_source(&body.source).ok_or_else(|| {
        validation_error(&context, "source_invalid", "Choose a valid MCP source.")
    })?;
    let transport = transport_value(&context, &body.transport)?;
    let (endpoint_metadata, command_metadata) = transport_metadata(
        &context,
        &state,
        transport,
        body.endpoint_metadata.as_ref(),
        body.command_metadata.as_ref(),
    )?;
    let allowed_origins = origins_value(&context, &body.allowed_origins)?;
    let secret_handles = secret_handles_value(&context, &body.required_secret_handles)?;
    let tool_fingerprint = match body.tool_fingerprint.as_deref() {
        Some(value) => Some(fingerprint_value(&context, value)?),
        None => None,
    };
    let database = database(&state, &context)?;
    let create_path = format!("/api/v1/orgs/{org_id}/mcp");
    let fingerprint_input = format!(
        "POST\\n{create_path}\\n{}:{}:{endpoint_metadata}:{command_metadata}:{allowed_origins}:{secret_handles}:{}",
        source.as_str(),
        transport.as_str(),
        tool_fingerprint.clone().unwrap_or_default()
    );
    if let Some(success) = lookup_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &create_path,
        &fingerprint_input,
        database,
        &context,
    )
    .await?
    {
        return Ok(replay_response(&success));
    }
    let mcp_id = deterministic_resource_id(
        "mcp",
        &key,
        &format!(
            "mcp:{org_id}:{}:{}",
            source.as_str(),
            tool_fingerprint.clone().unwrap_or_default()
        ),
        &context,
    )
    .await?;
    let repository = ToolRepository::new(database);
    if let Some(existing) = repository
        .find_mcp_registration(&mcp_id, &org_id)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Ok((StatusCode::OK, Json(mcp_json(&existing))).into_response());
    }
    let expected = McpRegistrationRecord {
        mcp_registration_id: mcp_id.clone(),
        org_id: org_id.clone(),
        source: source.as_str().to_owned(),
        transport: transport.as_str().to_owned(),
        endpoint_metadata_json: endpoint_metadata.clone(),
        command_metadata_json: command_metadata.clone(),
        allowed_origins_json: allowed_origins.clone(),
        required_secret_handles_json: secret_handles.clone(),
        tool_fingerprint: tool_fingerprint.clone(),
        tool_list_json: "[]".to_owned(),
        policy_status: mcp_policy_status_text(McpPolicyStatus::PendingReview)
            .unwrap_or("pending_review")
            .to_owned(),
        version: 1,
        created_by_user_id: access.principal.user_id.as_str().to_owned(),
        created_at: context.received_at.as_str().to_owned(),
        updated_at: context.received_at.as_str().to_owned(),
    };
    let mutation = begin_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &create_path,
        &fingerprint_input,
        database,
        &context,
    )
    .await?;
    let pending = match mutation {
        MutationClaim::Replay(success) => return Ok(replay_response(&success)),
        MutationClaim::Pending(pending) => pending,
    };
    let success =
        StoredSuccess::new(201, mcp_json(&expected)).map_err(|_| internal_error(&context))?;
    let insert = repository
        .insert_mcp_statement(&NewMcpRegistration {
            mcp_registration_id: &mcp_id,
            org_id: &org_id,
            source: source.as_str(),
            transport: transport.as_str(),
            endpoint_metadata_json: &endpoint_metadata,
            command_metadata_json: &command_metadata,
            allowed_origins_json: &allowed_origins,
            required_secret_handles_json: &secret_handles,
            tool_fingerprint: tool_fingerprint.as_deref(),
            tool_list_json: "[]",
            policy_status: mcp_policy_status_text(McpPolicyStatus::PendingReview)
                .unwrap_or("pending_review"),
            created_by_user_id: access.principal.user_id.as_str(),
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let event_metadata = json!({
        "source": source.as_str(),
        "transport": transport.as_str(),
        "policy_status": mcp_policy_status_text(McpPolicyStatus::PendingReview)
            .unwrap_or("pending_review"),
    });
    let security = session_security_event(
        database,
        &context,
        &access.principal,
        &org_id,
        "tool.mcp_registration_created.v1",
        "mcp_registration",
        &mcp_id,
        "success",
        &event_metadata,
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "tool.mcp_registration_changed.v1",
        &event_metadata,
    )?;
    let results = commit_mutation(
        database,
        &pending,
        &context.received_at,
        &success,
        vec![insert, security],
        outbox,
    )
    .await
    .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[2]).unwrap_or_default() != 1 {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "mcp_source_not_allowed",
            "The MCP registration could not be created.",
        ));
    }
    Ok(replay_response(&success))
}

/// `PATCH /api/v1/orgs/{org_id}/mcp/{mcp_id}`
#[worker::send]
pub async fn update_mcp(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, mcp_id)): Path<(String, String)>,
    Json(body): Json<UpdateMcpRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ToolsManage,
        Some("mcp_registration"),
        Some(&mcp_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    if McpRegistrationId::new(mcp_id.as_str()).is_err() {
        return Err(not_found(&context, "The MCP registration was not found."));
    }
    if body.version < 1 {
        return Err(validation_error(
            &context,
            "version_invalid",
            "Reload the MCP registration before updating it.",
        ));
    }
    let policy_status = match body.policy_status.as_deref() {
        Some(value) => Some(mcp_policy_status(value).ok_or_else(|| {
            validation_error(
                &context,
                "policy_status_invalid",
                "Choose a valid MCP policy status.",
            )
        })?),
        None => None,
    };
    let requested_transport = match body.transport.as_deref() {
        Some(value) => Some(transport_value(&context, value)?),
        None => None,
    };
    let database = database(&state, &context)?;
    let repository = ToolRepository::new(database);
    let current = repository
        .find_mcp_registration(&mcp_id, &org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context, "The MCP registration was not found."))?;
    if body.version != current.version {
        return Err(version_conflict(&context));
    }
    let transport = requested_transport
        .unwrap_or(McpTransport::parse(&current.transport).unwrap_or(McpTransport::Http));
    // Merge transport metadata: an omitted section keeps the stored value, and a
    // supplied one is re-validated against the effective transport.
    let stored_endpoint = if transport.as_str() == current.transport {
        serde_json::from_str::<EndpointMetadata>(&current.endpoint_metadata_json).ok()
    } else {
        None
    };
    let stored_command = if transport.as_str() == current.transport {
        serde_json::from_str::<CommandMetadata>(&current.command_metadata_json).ok()
    } else {
        None
    };
    let endpoint_source = body.endpoint_metadata.as_ref().or(stored_endpoint.as_ref());
    let command_source = body.command_metadata.as_ref().or(stored_command.as_ref());
    let (endpoint_metadata, command_metadata) =
        transport_metadata(&context, &state, transport, endpoint_source, command_source)?;
    let allowed_origins = match body.allowed_origins.as_ref() {
        Some(values) => origins_value(&context, values)?,
        None => current.allowed_origins_json.clone(),
    };
    let secret_handles = match body.required_secret_handles.as_ref() {
        Some(values) => secret_handles_value(&context, values)?,
        None => current.required_secret_handles_json.clone(),
    };
    let tool_fingerprint = match body.tool_fingerprint.as_deref() {
        Some(value) => Some(fingerprint_value(&context, value)?),
        None => current.tool_fingerprint.clone(),
    };
    let tool_list = match body.tool_list.as_ref() {
        Some(entries) => tool_list_value(&context, entries)?,
        None => current.tool_list_json.clone(),
    };
    let next = McpRegistrationRecord {
        mcp_registration_id: current.mcp_registration_id.clone(),
        org_id: current.org_id.clone(),
        source: current.source.clone(),
        transport: transport.as_str().to_owned(),
        endpoint_metadata_json: endpoint_metadata,
        command_metadata_json: command_metadata,
        allowed_origins_json: allowed_origins,
        required_secret_handles_json: secret_handles,
        tool_fingerprint,
        tool_list_json: tool_list,
        policy_status: match policy_status {
            Some(value) => mcp_policy_status_text(value)
                .ok_or_else(|| {
                    validation_error(
                        &context,
                        "policy_status_invalid",
                        "Choose a valid MCP policy status.",
                    )
                })?
                .to_owned(),
            None => current.policy_status.clone(),
        },
        version: current.version + 1,
        created_by_user_id: current.created_by_user_id.clone(),
        created_at: current.created_at.clone(),
        updated_at: context.received_at.as_str().to_owned(),
    };
    let success = StoredSuccess::new(200, mcp_json(&next)).map_err(|_| internal_error(&context))?;
    let version_guard = repository
        .assert_mcp_version_statement(&mcp_id, &org_id, body.version)
        .map_err(|error| database_error(&context, error))?;
    let update = repository
        .update_mcp_statement(&McpRegistrationUpdate {
            mcp_registration_id: &next.mcp_registration_id,
            org_id: &org_id,
            source: &next.source,
            transport: &next.transport,
            endpoint_metadata_json: &next.endpoint_metadata_json,
            command_metadata_json: &next.command_metadata_json,
            allowed_origins_json: &next.allowed_origins_json,
            required_secret_handles_json: &next.required_secret_handles_json,
            tool_fingerprint: next.tool_fingerprint.as_deref(),
            tool_list_json: &next.tool_list_json,
            policy_status: &next.policy_status,
            expected_version: body.version,
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let event_metadata = json!({
        "policy_status": next.policy_status,
        "transport": next.transport,
    });
    let security = session_security_event(
        database,
        &context,
        &access.principal,
        &org_id,
        "tool.mcp_registration_changed.v1",
        "mcp_registration",
        &mcp_id,
        "success",
        &event_metadata,
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "tool.mcp_registration_changed.v1",
        &event_metadata,
    )?;
    let results = database
        .batch(vec![version_guard, update, security, outbox])
        .await
        .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[2]).unwrap_or_default() != 1 {
        return Err(version_conflict(&context));
    }
    Ok(replay_response(&success))
}

// ---------------------------------------------------------------------------
// Tool policy document routes
// ---------------------------------------------------------------------------

/// `GET /api/v1/orgs/{org_id}/policy/tools`
///
/// An organization that never published a policy still receives a document: the
/// fail-closed default layer, flagged with `policy_state: "missing"`.
#[worker::send]
pub async fn get_tool_policy(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ToolsRead,
        Some("tool_policy"),
        None,
    )
    .await?;
    let record = ToolRepository::new(database(&state, &context)?)
        .find_tool_policy(&org_id, None)
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(Json(policy_json(&org_id, record.as_ref())).into_response())
}

/// `PUT /api/v1/orgs/{org_id}/policy/tools`
#[worker::send]
pub async fn put_tool_policy(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<PutToolPolicyRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ToolsManage,
        Some("tool_policy"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    if body.version < 0 {
        return Err(validation_error(
            &context,
            "version_invalid",
            "Reload the tool policy before updating it.",
        ));
    }
    if body.schema_version != TOOL_POLICY_SCHEMA_VERSION {
        return Err(validation_error(
            &context,
            "policy_schema_unsupported",
            "The tool policy schema version is not supported.",
        ));
    }
    let layer = body.layer().map_err(|field| {
        validation_error(
            &context,
            "policy_invalid",
            if field == "external_submit" {
                "Choose a valid browser external-submit policy."
            } else {
                "The tool policy is invalid."
            },
        )
    })?;
    if !layer.validate() {
        return Err(validation_error(
            &context,
            "policy_invalid",
            "The tool policy is invalid.",
        ));
    }
    let database = database(&state, &context)?;
    let repository = ToolRepository::new(database);
    let current = repository
        .find_tool_policy(&org_id, None)
        .await
        .map_err(|error| database_error(&context, error))?;
    let (expected, write, guard) = match current.as_ref() {
        Some(policy) => {
            if policy.version != body.version {
                return Err(version_conflict(&context));
            }
            let document_json = serde_json::to_string(&layer).map_err(|_| {
                validation_error(&context, "policy_invalid", "The tool policy is invalid.")
            })?;
            let next = ToolPolicyRecord {
                tool_policy_id: policy.tool_policy_id.clone(),
                org_id: policy.org_id.clone(),
                project_id: policy.project_id.clone(),
                policy_version: policy.policy_version + 1,
                document_json: document_json.clone(),
                version: policy.version + 1,
                created_by_user_id: policy.created_by_user_id.clone(),
                created_at: policy.created_at.clone(),
                updated_at: context.received_at.as_str().to_owned(),
            };
            let update = repository
                .update_tool_policy_statement(
                    &policy.tool_policy_id,
                    &org_id,
                    &document_json,
                    policy.version,
                    &context.received_at,
                )
                .map_err(|error| database_error(&context, error))?;
            let guard = repository
                .assert_tool_policy_version_statement(
                    &policy.tool_policy_id,
                    &org_id,
                    policy.version,
                )
                .map_err(|error| database_error(&context, error))?;
            (next, update, guard)
        }
        None => {
            if body.version != 0 {
                return Err(version_conflict(&context));
            }
            let document_json = serde_json::to_string(&layer).map_err(|_| {
                validation_error(&context, "policy_invalid", "The tool policy is invalid.")
            })?;
            let tool_policy_id = new_resource_id("tpol").as_str().to_owned();
            let next = ToolPolicyRecord {
                tool_policy_id: tool_policy_id.clone(),
                org_id: org_id.clone(),
                project_id: None,
                policy_version: 1,
                document_json: document_json.clone(),
                version: 1,
                created_by_user_id: access.principal.user_id.as_str().to_owned(),
                created_at: context.received_at.as_str().to_owned(),
                updated_at: context.received_at.as_str().to_owned(),
            };
            let insert = repository
                .insert_tool_policy_statement(
                    &tool_policy_id,
                    &org_id,
                    &document_json,
                    access.principal.user_id.as_str(),
                    &context.received_at,
                )
                .map_err(|error| database_error(&context, error))?;
            let guard = repository
                .assert_tool_policy_absent_statement(&org_id)
                .map_err(|error| database_error(&context, error))?;
            (next, insert, guard)
        }
    };
    let success = StoredSuccess::new(200, policy_json(&org_id, Some(&expected)))
        .map_err(|_| internal_error(&context))?;
    let event_metadata = json!({
        "scope": "organization",
        "policy_version": expected.policy_version,
        "default_posture": match layer.default_posture {
            PolicyPosture::Deny => "deny",
            PolicyPosture::Allow => "allow",
        },
        "default_approval_mode": layer.default_approval_mode.as_str(),
    });
    let security = session_security_event(
        database,
        &context,
        &access.principal,
        &org_id,
        "tool.policy_updated.v1",
        "tool_policy",
        &expected.tool_policy_id,
        "success",
        &event_metadata,
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "tool.catalog_updated.v1",
        &event_metadata,
    )?;
    let results = database
        .batch(vec![guard, write, security, outbox])
        .await
        .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[2]).unwrap_or_default() != 1 {
        return Err(version_conflict(&context));
    }
    Ok(replay_response(&success))
}

fn policy_json(org_id: &str, record: Option<&ToolPolicyRecord>) -> Value {
    let Some(record) = record else {
        return json!({
            "org_id": org_id,
            "project_id": Value::Null,
            "policy_version": 0,
            "version": 0,
            "policy_state": PolicyState::Missing.as_str(),
            "document": document_json(&ToolPolicyLayer::default()),
            "updated_at": Value::Null,
        });
    };
    match stored_layer(&record.document_json) {
        Some(layer) => json!({
            "org_id": record.org_id,
            "project_id": record.project_id,
            "policy_version": record.policy_version,
            "version": record.version,
            "policy_state": PolicyState::Ok.as_str(),
            "document": document_json(&layer),
            "updated_at": record.updated_at,
        }),
        None => json!({
            "org_id": record.org_id,
            "project_id": record.project_id,
            "policy_version": record.policy_version,
            "version": record.version,
            "policy_state": PolicyState::SchemaUnsupported.as_str(),
            "document": document_json(&ToolPolicyLayer::default()),
            "updated_at": record.updated_at,
        }),
    }
}

fn document_json(layer: &ToolPolicyLayer) -> Value {
    serde_json::to_value(layer).unwrap_or_else(|_| json!({}))
}

/// Parse a stored document. A P03 opaque `{"schema_version": 0}` placeholder and
/// any malformed or unsupported document both fail closed; the caller records
/// which case applied.
fn stored_layer(document: &str) -> Option<ToolPolicyLayer> {
    let value = serde_json::from_str::<Value>(document).ok()?;
    if snapshot_policy::is_opaque_placeholder(Some(&value)) {
        return None;
    }
    let layer = serde_json::from_value::<ToolPolicyLayer>(value).ok()?;
    layer.validate().then_some(layer)
}

// ---------------------------------------------------------------------------
// Device tool-decision broker
// ---------------------------------------------------------------------------

/// Everything the decision write needs, resolved from server state once.
struct DecisionInput<'a> {
    context: RequestContext,
    database: &'a crate::adapters::d1::D1Adapter,
    scope: RunToolScopeRecord,
    device: DeviceRecord,
    tool_call_id: String,
    tool_id: String,
    fingerprint: String,
    risk_class: String,
    /// The redacted, canonical argument summary the evaluator produced. Only
    /// this value is ever stored or compared.
    arguments_summary: String,
    existing_call: Option<ToolCallRefRecord>,
    existing_approval: Option<ApprovalRequestRecord>,
    reusable_session_approval: Option<ApprovalRequestRecord>,
    policy_state: PolicyState,
    policy_version: i64,
    decision: ToolDecision,
    /// Stable reason code reported with the decision.
    reason: &'static str,
    /// The run owner's current login session, for audit correlation.
    session_id: String,
}

/// `POST /api/v1/runs/{run_id}/tool-decisions`
///
/// The broker boundary. It authenticates the device, resolves the run, its
/// agent, and its organization from server state, evaluates current policy, and
/// records the decision, timeline event, and audit trail. It never executes the
/// tool, never resolves a secret, and never accepts a client decision.
#[worker::send]
pub async fn create_tool_decision(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
    Json(body): Json<ToolDecisionRequest>,
) -> Result<Response<Body>, ApiError> {
    if RunId::new(run_id.as_str()).is_err() {
        return Err(not_found(&context, "The run was not found."));
    }
    let tool_call_id = ToolCallId::new(body.tool_call_id.as_str())
        .map_err(|_| {
            validation_error(
                &context,
                "tool_call_id_invalid",
                "The tool call ID is invalid.",
            )
        })?
        .as_str()
        .to_owned();
    let tool_id = ToolId::new(body.tool_id.as_str())
        .map_err(|_| validation_error(&context, "tool_id_invalid", "The tool ID is invalid."))?
        .as_str()
        .to_owned();
    let fingerprint = fingerprint_value(&context, &body.tool_fingerprint)?;
    let claimed_risk_class = RiskClass::parse(&body.risk_class).ok_or_else(|| {
        validation_error(
            &context,
            "risk_class_invalid",
            "Choose a valid tool risk class.",
        )
    })?;
    let capability_ids = capability_id_set(&context, &body.capability_ids)?;
    let database = database(&state, &context)?;
    let device = require_device_token(&headers, &context, database).await?;
    let tools = ToolRepository::new(database);
    let approvals = ApprovalRepository::new(database);
    let runs = RunRepository::new(database);
    let scope = tools
        .find_run_tool_scope(&run_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context, "The run was not found."))?;
    if scope.device_id != device.device_id {
        return Err(domain_error(
            &context,
            ApiErrorCode::PermissionDenied,
            "device_not_approved",
            "The device is not approved for this run.",
        ));
    }
    if scope.org_id != device.org_id {
        return Err(not_found(&context, "The run was not found."));
    }
    if !run_can_request_tool_decision(&scope.state) {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            if is_terminal_run_state(&scope.state) {
                "run_terminal"
            } else {
                "invalid_run_transition"
            },
            "The run cannot request a tool decision in its current state.",
        ));
    }
    let session_id = authorize_device_run(database, &context, &scope).await?;
    let agent: Option<AgentDefinitionRecord> = runs
        .find_agent(&scope.org_id, &scope.agent_definition_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    let catalog = tools
        .find_tool(&tool_id, &scope.org_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    let registration = tools
        .find_mcp_registration_by_fingerprint(&scope.org_id, &fingerprint)
        .await
        .map_err(|error| database_error(&context, error))?;
    let capabilities = tools
        .list_capabilities(&scope.org_id, CAPABILITY_CATALOG_MAX)
        .await
        .map_err(|error| database_error(&context, error))?;
    let (organization_policy, project_policy, policy_state, policy_version) =
        effective_policy(database, &tools, &context, &scope.org_id, &scope.project_id).await?;
    let evaluation = PolicyEvaluationInput {
        mode: ExecutionMode::ManagedOrganization,
        // No platform hard-deny list is configured in this phase. The evaluator
        // still runs it first, so adding one later cannot be bypassed.
        platform: PlatformToolPolicy::default(),
        organization_policy,
        project_policy,
        agent: agent_policy(agent.as_ref()),
        runtime: runtime_capabilities(&device, catalog.as_ref(), &capability_ids),
        catalog: tool_catalog(
            &context,
            catalog.as_ref(),
            registration.as_ref(),
            &capability_definitions(&capabilities),
        )?,
        call: ToolCall {
            tool_call_id: tool_call_id.clone(),
            tool_id: tool_id.clone(),
            tool_fingerprint: fingerprint.clone(),
            capability_ids: capability_ids.clone(),
            risk_class: claimed_risk_class,
            arguments_summary: body.arguments_summary.clone(),
            browser_action: body.browser_action.clone(),
            computer_action: body.computer_action.clone(),
        },
        policy_version,
    };
    let decision = evaluate(&evaluation);
    let arguments_summary = decision.arguments_summary.clone().unwrap_or_default();
    let risk_class = evaluation.call.risk_class.as_str().to_owned();
    let mode = decision_approval_mode(decision.decision);
    let existing_call = tools
        .find_tool_call_ref(&scope.run_id, &tool_call_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    let existing_approval = approvals
        .find_approval_for_tool_call(&scope.run_id, &tool_call_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    let reusable_session_approval = if mode == Some(ApprovalMode::Session) {
        approvals
            .find_reusable_session_approval(
                &scope.run_id,
                &tool_id,
                &fingerprint,
                &arguments_summary,
                &context.received_at,
            )
            .await
            .map_err(|error| database_error(&context, error))?
    } else {
        None
    };
    let resolved = resolve_decision(DecisionInput {
        context: context.clone(),
        database,
        scope,
        device,
        tool_call_id,
        tool_id,
        fingerprint,
        risk_class,
        arguments_summary,
        existing_call,
        existing_approval,
        reusable_session_approval,
        policy_state,
        policy_version,
        decision: decision.decision,
        reason: decision.reason.code().as_str(),
        session_id,
    })
    .await?;
    Ok(Json(resolved).into_response())
}

/// Turn one evaluated decision into its durable form.
async fn resolve_decision(input: DecisionInput<'_>) -> Result<Value, ApiError> {
    let arguments_hash = sha256_hex(&input.arguments_summary)
        .await
        .map_err(|_| service_unavailable(&input.context))?;
    // A tool call ID is bound to one tool, fingerprint, and redacted argument
    // summary. Rebinding is refused instead of being silently reinterpreted.
    if let Some(existing) = input.existing_call.clone()
        && (existing.tool_id != input.tool_id
            || existing.tool_fingerprint != input.fingerprint
            || existing.arguments_summary != input.arguments_summary)
    {
        return persist_denial(
            input,
            DecisionReasonCode::ToolFingerprintChanged.as_str(),
            None,
        )
        .await;
    }
    // Current policy is re-evaluated at every sensitive tool use, so a denial
    // now beats an approval request that is still outstanding. A host that
    // re-checks after a policy change must see the denial, not a live gate.
    if input.decision == ToolDecision::Deny {
        let reason = input.reason;
        return persist_denial(input, reason, None).await;
    }
    // An approval for this exact call is authoritative and is never replaced. It
    // stays usable only while it still binds the same tool and fingerprint and
    // its window has not closed.
    if let Some(approval) = input.existing_approval.clone() {
        let bound = approval.tool_id == input.tool_id
            && approval.tool_fingerprint == input.fingerprint
            && approval.arguments_summary == input.arguments_summary;
        if !bound {
            return persist_denial(
                input,
                DecisionReasonCode::ToolFingerprintChanged.as_str(),
                None,
            )
            .await;
        }
        let live = approval.expires_at.as_str() > input.context.received_at.as_str();
        // A pending approval always replays as an approval requirement, using
        // the mode it was requested with. Replaying the freshly evaluated
        // decision could hand out an `allow` for a call nobody approved.
        let replayable = match approval.status.as_str() {
            "pending" => Some((
                match approval.approval_mode.as_str() {
                    "session" => ToolDecision::RequireSessionApproval,
                    _ => ToolDecision::RequirePerUseApproval,
                },
                DecisionReasonCode::ApprovalRequired.as_str(),
            )),
            "approved" if live => Some((
                ToolDecision::Allow,
                DecisionReasonCode::ApprovalRequired.as_str(),
            )),
            _ => None,
        };
        if let Some((decision, reason)) = replayable {
            return Ok(decision_body(
                &input,
                decision,
                Some(reason),
                Some(&approval.approval_id),
                Some(&approval.expires_at),
            ));
        }
        // An approval that was approved but has since expired, or that was
        // already denied or cancelled, cannot be reused for this call.
        let reason = if approval.status.as_str() == "approved" {
            REASON_APPROVAL_EXPIRED
        } else {
            REASON_APPROVAL_RESOLVED
        };
        return persist_denial(input, reason, None).await;
    }
    match input.decision {
        ToolDecision::Deny => {
            let reason = input.reason;
            persist_denial(input, reason, None).await
        }
        ToolDecision::Allow => {
            let writes = call_writes(&input, "allowed")?;
            persist_decision(
                input,
                ToolDecision::Allow,
                Some(DecisionReasonCode::PolicyAllowed.as_str()),
                None,
                None,
                RUN_EVENT_DECISION,
                "tool.decision_recorded.v1",
                "success",
                writes,
            )
            .await
        }
        ToolDecision::RequireSessionApproval | ToolDecision::RequirePerUseApproval => {
            let mode = decision_approval_mode(input.decision);
            // A session-scope grant may be reused by another call in the same run
            // only when the tool, fingerprint, and argument summary are identical.
            if let Some(reusable) = input.reusable_session_approval.clone() {
                let approval_id = new_resource_id("apr").as_str().to_owned();
                let expires_at = parse_timestamp(&input.context, &reusable.expires_at)?;
                let resolved_at = reusable
                    .resolved_at
                    .clone()
                    .unwrap_or_else(|| input.context.received_at.as_str().to_owned());
                let resolved_by = reusable
                    .resolved_by_principal_id
                    .clone()
                    .unwrap_or_else(|| input.scope.principal_user_id.clone());
                let inherited = ApprovalRepository::new(input.database)
                    .insert_inherited_statement(&InheritedApproval {
                        approval_id: &approval_id,
                        org_id: &input.scope.org_id,
                        project_id: &input.scope.project_id,
                        run_id: &input.scope.run_id,
                        agent_session_id: &input.scope.agent_session_id,
                        tool_call_id: &input.tool_call_id,
                        tool_id: &input.tool_id,
                        tool_fingerprint: &input.fingerprint,
                        arguments_hash: &arguments_hash,
                        requested_by_device_id: &input.device.device_id,
                        policy_snapshot_id: None,
                        policy_version: Some(input.policy_version),
                        risk_class: &input.risk_class,
                        approval_mode: ApprovalMode::Session.as_str(),
                        status: "approved",
                        arguments_summary: &input.arguments_summary,
                        requested_by_principal_id: &input.scope.principal_user_id,
                        requested_at: &input.context.received_at,
                        expires_at: &expires_at,
                        resolved_by_principal_id: &resolved_by,
                        resolved_at: &resolved_at,
                        resolution_reason: "session_scope_reuse",
                    })
                    .map_err(|error| database_error(&input.context, error))?;
                let mut writes = call_writes(&input, "allowed")?;
                writes.push(inherited);
                persist_decision(
                    input,
                    ToolDecision::Allow,
                    Some(DecisionReasonCode::ApprovalRequired.as_str()),
                    Some(approval_id.as_str()),
                    Some(expires_at.as_str()),
                    RUN_EVENT_DECISION,
                    "tool.decision_recorded.v1",
                    "success",
                    writes,
                )
                .await
            } else {
                let decision = input.decision;
                let reason = input.reason;
                let approval_id = new_resource_id("apr").as_str().to_owned();
                let expires_at = add_seconds(&input.context.received_at, APPROVAL_TTL_SECONDS)
                    .map_err(|_| service_unavailable(&input.context))?;
                let requested = ApprovalRepository::new(input.database)
                    .insert_statement(&NewApprovalRequest {
                        approval_id: &approval_id,
                        org_id: &input.scope.org_id,
                        project_id: &input.scope.project_id,
                        run_id: &input.scope.run_id,
                        agent_session_id: &input.scope.agent_session_id,
                        tool_call_id: &input.tool_call_id,
                        tool_id: &input.tool_id,
                        tool_fingerprint: &input.fingerprint,
                        arguments_hash: &arguments_hash,
                        requested_by_device_id: &input.device.device_id,
                        policy_snapshot_id: None,
                        policy_version: Some(input.policy_version),
                        risk_class: &input.risk_class,
                        approval_mode: mode.unwrap_or(ApprovalMode::PerUse).as_str(),
                        arguments_summary: &input.arguments_summary,
                        requested_by_principal_id: &input.scope.principal_user_id,
                        requested_at: &input.context.received_at,
                        expires_at: &expires_at,
                    })
                    .map_err(|error| database_error(&input.context, error))?;
                let mut writes = Vec::with_capacity(2);
                if input.existing_call.is_none() {
                    writes.extend(call_writes(&input, "requested")?);
                }
                writes.push(requested);
                persist_decision(
                    input,
                    decision,
                    Some(reason),
                    Some(approval_id.as_str()),
                    Some(expires_at.as_str()),
                    RUN_EVENT_APPROVAL_REQUESTED,
                    "approval.requested.v1",
                    "success",
                    writes,
                )
                .await
            }
        }
    }
}

/// Tool-call reference writes for one decision.
///
/// A call the broker has not seen becomes a new reference; an existing call is
/// advanced only while it is still `requested`, so a recorded allow or denial
/// is never overwritten.
fn call_writes(
    input: &DecisionInput<'_>,
    status: &str,
) -> Result<Vec<worker::d1::D1PreparedStatement>, ApiError> {
    let repository = ToolRepository::new(input.database);
    let statement = if input.existing_call.is_none() {
        repository.insert_tool_call_ref_statement(&NewToolCallRef {
            tool_call_id: &input.tool_call_id,
            org_id: &input.scope.org_id,
            project_id: &input.scope.project_id,
            run_id: &input.scope.run_id,
            tool_id: &input.tool_id,
            tool_fingerprint: &input.fingerprint,
            risk_class: &input.risk_class,
            arguments_summary: &input.arguments_summary,
            now: &input.context.received_at,
        })
    } else {
        repository.update_tool_call_status_statement(
            &input.scope.run_id,
            &input.tool_call_id,
            status,
            &input.context.received_at,
        )
    };
    Ok(vec![
        statement.map_err(|error| database_error(&input.context, error))?,
    ])
}

/// Persist one decision: timeline event, audit record, and domain event commit
/// with the business writes in a single D1 batch.
#[allow(clippy::too_many_arguments)]
async fn persist_decision(
    input: DecisionInput<'_>,
    decision: ToolDecision,
    reason: Option<&'static str>,
    approval_id: Option<&str>,
    approval_expires_at: Option<&str>,
    event_type: &str,
    audit_action: &str,
    audit_outcome: &str,
    business_writes: Vec<worker::d1::D1PreparedStatement>,
) -> Result<Value, ApiError> {
    let body = decision_body(&input, decision, reason, approval_id, approval_expires_at);
    let event = run_event_statement(&input, decision, reason, approval_id, event_type).await?;
    let security = device_security_event(
        input.database,
        &input.context,
        &input.scope,
        &input.device,
        &input.session_id,
        audit_action,
        "tool",
        Some(input.tool_call_id.as_str()),
        audit_outcome,
        json!({
            "decision": decision.as_str(),
            "reason": reason,
            "risk_class": input.risk_class,
            "policy_state": input.policy_state.as_str(),
            "approval_id": approval_id,
        }),
    )?;
    let outbox = outbox_statement(
        input.database,
        &input.context,
        None,
        Some(&input.scope.org_id),
        "tool.decision_recorded.v1",
        &json!({
            "run_id": input.scope.run_id,
            "tool_call_id": input.tool_call_id,
            "device_id": input.device.device_id,
            "decision": decision.as_str(),
            "reason": reason,
        }),
    )?;
    let mut statements = Vec::with_capacity(business_writes.len() + 3);
    statements.extend(business_writes);
    statements.push(event);
    statements.push(security);
    statements.push(outbox);
    input
        .database
        .batch(statements)
        .await
        .map_err(|error| database_error(&input.context, error))?;
    Ok(body)
}

/// Persist a denied decision with the same durability as an allow. The call
/// reference advances to `denied` so a later request for the same call cannot
/// present the call as still awaiting a decision.
async fn persist_denial(
    input: DecisionInput<'_>,
    reason: &'static str,
    approval_id: Option<&str>,
) -> Result<Value, ApiError> {
    let writes = call_writes(&input, "denied")?;
    persist_decision(
        input,
        ToolDecision::Deny,
        Some(reason),
        approval_id,
        None,
        RUN_EVENT_DENIED,
        "tool.denied.v1",
        "denied",
        writes,
    )
    .await
}

fn parse_timestamp(context: &RequestContext, value: &str) -> Result<Timestamp, ApiError> {
    Timestamp::new(value.to_owned()).map_err(|_| internal_error(context))
}

/// Append one bounded timeline record. Run-event persistence is owned by
/// `repositories::runs`; the payload carries decision metadata only.
async fn run_event_statement(
    input: &DecisionInput<'_>,
    decision: ToolDecision,
    reason: Option<&'static str>,
    approval_id: Option<&str>,
    event_type: &str,
) -> Result<worker::d1::D1PreparedStatement, ApiError> {
    let runs = RunRepository::new(input.database);
    let sequence = runs
        .next_event_sequence(&input.scope.org_id, &input.scope.run_id)
        .await
        .map_err(|error| database_error(&input.context, error))?;
    let payload = json!({
        "decision": decision.as_str(),
        "tool_id": input.tool_id,
        "risk_class": input.risk_class,
        "reason": reason,
    });
    runs.insert_event_statement(&NewRunEventInput {
        run_event_id: new_resource_id("rev").as_str(),
        run_id: &input.scope.run_id,
        sequence,
        event_type,
        occurred_at: &input.context.received_at,
        actor_type: "device",
        actor_id: Some(&input.device.device_id),
        correlation_id: input.context.correlation_id.as_str(),
        tool_call_id: Some(&input.tool_call_id),
        approval_id,
        payload: &payload,
    })
    .map_err(|error| database_error(&input.context, error))
}

/// Frozen broker response: the decision, its stable reason code, the exact tool
/// binding, and policy metadata. Never a secret, a URL, or an argument body.
fn decision_body(
    input: &DecisionInput<'_>,
    decision: ToolDecision,
    reason: Option<&'static str>,
    approval_id: Option<&str>,
    approval_expires_at: Option<&str>,
) -> Value {
    json!({
        "run_id": input.scope.run_id,
        "tool_call_id": input.tool_call_id,
        "tool_id": input.tool_id,
        "tool_fingerprint": input.fingerprint,
        "risk_class": input.risk_class,
        "decision": decision.as_str(),
        "approval_mode": decision_approval_mode(decision).map(ApprovalMode::as_str),
        "reason": reason,
        "approval_id": approval_id,
        "approval_expires_at": approval_expires_at,
        "policy_version": input.policy_version,
        "policy_state": input.policy_state.as_str(),
    })
}

fn is_terminal_run_state(state: &str) -> bool {
    matches!(state, "succeeded" | "failed" | "cancelled" | "timed_out")
}

fn run_can_request_tool_decision(state: &str) -> bool {
    matches!(
        state,
        "dispatching" | "running" | "waiting_user" | "waiting_approval"
    )
}

// ---------------------------------------------------------------------------
// Evaluation input assembly
// ---------------------------------------------------------------------------

/// Approval requirement implied by a decision, or `None` when the call is
/// allowed or denied.
fn decision_approval_mode(decision: ToolDecision) -> Option<ApprovalMode> {
    match decision {
        ToolDecision::RequireSessionApproval => Some(ApprovalMode::Session),
        ToolDecision::RequirePerUseApproval => Some(ApprovalMode::PerUse),
        ToolDecision::Allow | ToolDecision::Deny => None,
    }
}

/// Build the evaluator catalog from the tenant's current rows.
///
/// A tool whose stored source or risk class cannot be parsed is omitted rather
/// than downgraded: the evaluator then denies an unknown tool, which is the
/// fail-closed outcome. The MCP registration is resolved through the frozen
/// `tool_fingerprint` column, so a tool with no matching registration has no
/// `mcp_registration_id` and is denied as unreviewed.
fn tool_catalog(
    context: &RequestContext,
    tool: Option<&ToolDefinitionRecord>,
    registration: Option<&McpRegistrationRecord>,
    capability_definitions: &BTreeSet<String>,
) -> Result<ToolCatalog, ApiError> {
    let mut catalog = ToolCatalog::default();
    for capability_id in capability_definitions {
        catalog.capability_definitions.insert(
            capability_id.clone(),
            CapabilityDefinition {
                capability_id: capability_id.clone(),
                lifecycle: CapabilityLifecycle::Active,
            },
        );
    }
    if let Some(registration) = registration {
        let Some(source) = mcp_source(&registration.source) else {
            return Err(service_unavailable(context));
        };
        let Some(policy_status) = mcp_policy_status(&registration.policy_status) else {
            return Err(service_unavailable(context));
        };
        let mut current = BTreeSet::new();
        if let Some(fingerprint) = registration.tool_fingerprint.as_deref() {
            current.insert(fingerprint.to_owned());
        }
        for entry in string_array(&registration.tool_list_json) {
            current.insert(entry);
        }
        // A registration that is not approved has reviewed nothing; keeping the
        // reviewed set empty makes a fingerprint change force re-review.
        let reviewed = match policy_status {
            McpPolicyStatus::Approved => current.clone(),
            _ => BTreeSet::new(),
        };
        catalog.mcp_registrations.insert(
            registration.mcp_registration_id.clone(),
            McpRegistration {
                mcp_id: registration.mcp_registration_id.clone(),
                source,
                policy_status,
                current_tool_fingerprints: current,
                reviewed_tool_fingerprints: reviewed,
            },
        );
    }
    if let Some(tool) = tool {
        let Some(source) = tool_source(&tool.source) else {
            return Ok(catalog);
        };
        let Some(risk_class) = RiskClass::parse(&tool.risk_class) else {
            return Ok(catalog);
        };
        let Some(lifecycle) = tool_lifecycle(&tool.lifecycle) else {
            return Ok(catalog);
        };
        let mcp_registration_id = registration
            .map(|registration| registration.mcp_registration_id.clone())
            .filter(|_| source != ToolSource::BuiltIn);
        let definition = ToolDefinition {
            tool_id: tool.tool_id.clone(),
            name: tool.name.clone(),
            source,
            risk_class,
            capability_ids: string_list(&tool.capability_ids_json),
            fingerprint: tool.fingerprint.clone(),
            lifecycle,
            mcp_registration_id,
        };
        catalog.tools.insert(definition.tool_id.clone(), definition);
    }
    Ok(catalog)
}

/// Capability identity visible to the evaluator.
///
/// The catalog row carries both an opaque `cap_` identifier and a stable
/// `capability_key`. The evaluator injects the bare key (`browser`,
/// `computer`) for a browser- or computer-shaped call, so both spellings are
/// projected as identifiers of the same class. A key that collides with another
/// row's identifier is already the same class, so the set stays unambiguous.
fn capability_definitions(capabilities: &[CapabilityDefinitionRecord]) -> BTreeSet<String> {
    let mut resolved = BTreeSet::new();
    for capability in capabilities {
        resolved.insert(capability.capability_id.clone());
        resolved.insert(capability.capability_key.clone());
    }
    resolved
}

/// Agent-level intersection constraint. The agent's declared runtime
/// requirements are enforced by the execution host, not by the control-plane
/// tool gate, so only the tool allow-list is projected here.
fn agent_policy(agent: Option<&AgentDefinitionRecord>) -> AgentToolPolicy {
    AgentToolPolicy {
        allowed_tool_ids: agent
            .map(|agent| string_list(&agent.allowed_tool_ids_json))
            .unwrap_or_default(),
        // Agent runtime requirements are a host concern; the control plane does
        // not invent a capability contract for them.
        required_capability_ids: BTreeSet::new(),
    }
}

/// Translate the P03 device capability report into runtime capability support.
///
/// The P03 report is a fixed toggle set, so the supported set is exactly what
/// the device reported, plus the requested identifiers whose base capability the
/// device reported. A capability the device did not report is unsupported and
/// therefore denied, which is the fail-closed direction.
fn runtime_capabilities(
    device: &DeviceRecord,
    tool: Option<&ToolDefinitionRecord>,
    requested: &BTreeSet<String>,
) -> RuntimeCapabilities {
    let Some(raw) = device.capabilities.as_deref() else {
        return RuntimeCapabilities::default();
    };
    let Ok(report) = serde_json::from_str::<Value>(raw) else {
        return RuntimeCapabilities::default();
    };
    let mut reported: BTreeSet<String> = BTreeSet::new();
    for (key, capability) in [
        ("browser_use", "browser"),
        ("computer_use", "computer"),
        ("automation_eligible", "automation"),
        ("remote_environment", "environment"),
    ] {
        if report.get(key).and_then(Value::as_bool) == Some(true) {
            reported.insert(capability.to_owned());
            reported.insert(key.to_owned());
        }
    }
    // Mirror the requested identifiers that the device's toggles cover.
    for identifier in requested {
        let base = identifier.strip_prefix("cap_").unwrap_or(identifier);
        if reported.contains(base) {
            reported.insert(identifier.clone());
        }
    }
    if let Some(tool) = tool {
        for identifier in string_list(&tool.capability_ids_json) {
            let base = identifier.strip_prefix("cap_").unwrap_or(&identifier);
            if reported.contains(base) {
                reported.insert(identifier);
            }
        }
    }
    RuntimeCapabilities {
        supported_capability_ids: reported,
    }
}

/// Collect every applicable policy layer and the state to report with it.
///
/// The organization document is authoritative. The project document narrows it.
/// A published P03 snapshot section narrows both, because the snapshot is the
/// transport authority an execution host is evaluated against; a missing,
/// schema-0, or malformed section contributes nothing but is reported.
async fn effective_policy(
    database: &crate::adapters::d1::D1Adapter,
    repository: &ToolRepository<'_>,
    context: &RequestContext,
    org_id: &str,
    project_id: &str,
) -> Result<
    (
        Option<ToolPolicyLayer>,
        Option<ToolPolicyLayer>,
        PolicyState,
        i64,
    ),
    ApiError,
> {
    let organization_record = repository
        .find_tool_policy(org_id, None)
        .await
        .map_err(|error| database_error(context, error))?;
    let project_record = repository
        .find_tool_policy(org_id, Some(project_id))
        .await
        .map_err(|error| database_error(context, error))?;
    let organization = organization_record
        .as_ref()
        .and_then(|record| stored_layer(&record.document_json));
    let project = project_record
        .as_ref()
        .and_then(|record| stored_layer(&record.document_json));
    let mut version = organization_record
        .as_ref()
        .map_or(0, |record| record.policy_version)
        .max(
            project_record
                .as_ref()
                .map_or(0, |record| record.policy_version),
        );
    let mut unsupported = (organization_record.is_some() && organization.is_none())
        || (project_record.is_some() && project.is_none());
    // The P03 snapshot section narrows the authoritative document when one is
    // published. An opaque placeholder carries no authority, so it is reported
    // without narrowing.
    if let Ok(Some(record)) = PolicyRepository::new(database)
        .latest_snapshot(org_id)
        .await
        && let Ok(payload) = serde_json::from_str::<Value>(&record.payload)
    {
        match snapshot_policy::tool_policy(&payload) {
            Some(section) => {
                version = version.max(record.policy_version);
                if let Some(organization) = organization.as_ref() {
                    return Ok((
                        Some(narrow_with_snapshot(organization.clone(), &section)),
                        project,
                        PolicyState::Ok,
                        version,
                    ));
                }
            }
            None => {
                if !snapshot_policy::is_opaque_placeholder(payload.get("tools")) {
                    unsupported = true;
                }
            }
        }
    }
    // A managed organization with no usable document authorizes nothing, and the
    // evaluator denies that case on its own.
    let state = match (organization.is_some(), unsupported) {
        (true, _) => PolicyState::Ok,
        (false, true) => PolicyState::SchemaUnsupported,
        (false, false) => PolicyState::Missing,
    };
    Ok((organization, project, state, version))
}

/// Narrow an authoritative layer with a published snapshot section.
///
/// The snapshot cannot broaden the document: a tool the snapshot does not
/// authorize, a rule that denies it, or a rule whose `argument_scope` cannot be
/// verified from a redacted summary all remove the tool. A section that carries
/// any narrowing therefore also forces `default_posture: deny`, so an
/// organization-wide allow cannot survive alongside a scoped deny.
fn narrow_with_snapshot(layer: ToolPolicyLayer, section: &ToolPolicySection) -> ToolPolicyLayer {
    let mut narrowed = layer.clone();
    let mut denied: BTreeSet<String> = BTreeSet::new();
    let mut modes = std::collections::BTreeMap::new();
    for rule in &section.rules {
        match &rule.decision {
            PolicyDecision::Deny => {
                denied.insert(rule.tool_id.clone());
            }
            _ if !rule.argument_scope.is_empty() => {
                // A scoped rule cannot be evaluated from a redacted summary, so
                // the tool is held rather than approved under a wider rule.
                denied.insert(rule.tool_id.clone());
            }
            _ => {
                if let Some(mode) = policy_decision_mode(&rule.decision) {
                    modes.insert(rule.tool_id.clone(), mode);
                }
            }
        }
    }
    if !denied.is_empty() {
        narrowed.default_posture = PolicyPosture::Deny;
        narrowed
            .tool_ids
            .retain(|tool_id| !denied.contains(tool_id));
        narrowed
            .tool_approval_modes
            .retain(|tool_id, _| !denied.contains(tool_id));
    }
    if section.default_posture == snapshot_policy::DefaultPosture::Deny {
        narrowed
            .tool_ids
            .retain(|tool_id| section.tool_ids.contains(tool_id));
        narrowed
            .tool_approval_modes
            .retain(|tool_id, _| section.tool_ids.contains(tool_id));
    }
    for (tool_id, mode) in modes {
        // A snapshot rule may only raise the requirement, never lower it.
        let merged = narrowed
            .tool_approval_modes
            .get(&tool_id)
            .map_or(mode, |existing| existing.most_restrictive(mode));
        narrowed.tool_approval_modes.insert(tool_id, merged);
    }
    narrowed
}

fn policy_decision_mode(decision: &PolicyDecision) -> Option<ApprovalMode> {
    match decision {
        PolicyDecision::Allow => Some(ApprovalMode::None),
        PolicyDecision::RequireSessionApproval => Some(ApprovalMode::Session),
        PolicyDecision::RequirePerUseApproval => Some(ApprovalMode::PerUse),
        PolicyDecision::Deny => None,
    }
}

// ---------------------------------------------------------------------------
// Device authentication and central authorization for the broker
// ---------------------------------------------------------------------------

/// Authenticate a device-scoped call from `Authorization: DeviceToken <hex>`.
/// Token expiry and device revocation are both resolved server-side.
async fn require_device_token(
    headers: &HeaderMap,
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
) -> Result<DeviceRecord, ApiError> {
    let raw_token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("DeviceToken "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| device_token_error(context, "device_token_required"))?;
    if raw_token.len() > 256 || !raw_token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(device_token_error(context, "device_token_required"));
    }
    let token_hash = sha256_hex(raw_token)
        .await
        .map_err(|_| service_unavailable(context))?;
    ToolRepository::new(database)
        .find_device_for_token(&token_hash, &context.received_at)
        .await
        .map_err(|error| database_error(context, error))?
        .ok_or_else(|| device_token_error(context, "device_revoked"))
}

fn device_token_error(context: &RequestContext, reason: &'static str) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::AuthenticationRequired,
        "A valid device token is required.",
    )
    .with_detail("reason", json!(reason))
}

/// Authorize a device-scoped tool decision through the central decision path and
/// return the run owner's current session ID for audit correlation.
///
/// The device token is the authenticator. The principal only supplies the
/// identity the authorization service compares to current membership, so a
/// device call can never widen what its owner is allowed to do.
async fn authorize_device_run(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    scope: &RunToolScopeRecord,
) -> Result<String, ApiError> {
    let users = IdentityRepository::new(database);
    let user = users
        .find_user_by_id(&scope.principal_user_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .ok_or_else(|| not_found(context, "The run was not found."))?;
    let sessions = users
        .list_sessions(&scope.principal_user_id, &context.received_at, 1, 0)
        .await
        .map_err(|_| service_unavailable(context))?;
    let session_id = sessions
        .first()
        .map(|session| session.session_id.clone())
        .unwrap_or_else(|| "ses_00000000000000000000000000000000".to_owned());
    let principal = Principal::new(
        UserId::new(scope.principal_user_id.clone()).map_err(|_| {
            domain_error(
                context,
                ApiErrorCode::InternalError,
                "run_owner_unavailable",
                "The run owner could not be resolved.",
            )
        })?,
        crate::core::SessionId::new(session_id.clone()).map_err(|_| {
            domain_error(
                context,
                ApiErrorCode::InternalError,
                "run_owner_unavailable",
                "The run owner could not be resolved.",
            )
        })?,
        user.email,
        user.display_name,
        user.email_verified,
    );
    let organizations = OrganizationRepository::new(database);
    let organization: OrganizationRecord = organizations
        .find_organization(&scope.org_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .ok_or_else(|| not_found(context, "The run was not found."))?;
    let membership: MembershipRecord = organizations
        .find_membership(&scope.org_id, principal.user_id.as_str())
        .await
        .map_err(|_| service_unavailable(context))?
        .ok_or_else(|| not_found(context, "The run was not found."))?;
    let organization_context = OrganizationContext {
        organization_id: OrganizationId::new(&scope.org_id)
            .map_err(|_| service_unavailable(context))?,
        state: OrganizationState::parse(&organization.state)
            .ok_or_else(|| service_unavailable(context))?,
        version: organization.version,
    };
    let membership_snapshot = MembershipSnapshot {
        membership_id: crate::core::MembershipId::new(&membership.membership_id)
            .map_err(|_| service_unavailable(context))?,
        organization_id: organization_context.organization_id.clone(),
        user_id: principal.user_id.clone(),
        role: MembershipRole::parse(&membership.role)
            .ok_or_else(|| service_unavailable(context))?,
        status: MembershipStatus::parse(&membership.status)
            .ok_or_else(|| service_unavailable(context))?,
        version: membership.version,
    };
    let resource = ResourceContext {
        resource_type: "run".to_owned(),
        resource_id: scope.run_id.clone(),
        organization_id: organization_context.organization_id.clone(),
    };
    match authorize(
        Some(&principal),
        &organization_context,
        Some(&membership_snapshot),
        &Permission::RunsStart,
        Some(&resource),
    ) {
        AuthorizationDecision::Allow => Ok(session_id),
        AuthorizationDecision::Deny(reason) => Err(crate::routes::authorization::denial(
            context,
            match reason {
                DenyReason::AuthenticationRequired => DenyReason::MembershipRequired,
                other => other,
            },
        )),
    }
}

// ---------------------------------------------------------------------------
// Transport and storage helpers
// ---------------------------------------------------------------------------

fn generated_id(prefix: &str) -> String {
    new_resource_id(prefix).as_str().to_owned()
}

pub fn validation_error(context: &RequestContext, reason: &str, message: &str) -> ApiError {
    domain_error(context, ApiErrorCode::ValidationFailed, reason, message)
}

pub fn not_found(context: &RequestContext, message: &str) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::NotFound,
        "resource_not_found",
        message,
    )
}

pub fn service_unavailable(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::ServiceUnavailable,
        "The tool policy store is unavailable.",
    )
}

pub fn internal_error(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::InternalError,
        "internal_error",
        "The request could not be completed.",
    )
}

pub fn version_conflict(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::Conflict,
        "version_conflict",
        "The resource changed. Refresh and try again.",
    )
}

pub fn idempotency_conflict(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::IdempotencyConflict,
        "idempotency_conflict",
        "The Idempotency-Key was already used for a different request.",
    )
}

pub fn idempotency_in_progress(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::IdempotencyInProgress,
        "idempotency_in_progress",
        "A request with this Idempotency-Key is still in progress.",
    )
}

pub fn page_limit(value: Option<u16>) -> i32 {
    match value {
        None => PAGE_LIMIT_DEFAULT,
        Some(0) => PAGE_LIMIT_DEFAULT,
        Some(value) if i32::from(value) > PAGE_LIMIT_MAX => PAGE_LIMIT_MAX,
        Some(value) => i32::from(value),
    }
}

/// Keyset cursor for `(sort_timestamp, id)` descending pages. The encoding keeps
/// the value opaque to clients while remaining cheap to decode.
pub fn encode_page_cursor(timestamp: &str, id: &str) -> String {
    use std::fmt::Write;
    let raw = format!("{timestamp}|{id}");
    let mut encoded = String::with_capacity(raw.len() * 2);
    for byte in raw.as_bytes() {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

pub fn decode_page_cursor(
    raw: Option<&str>,
    context: &RequestContext,
) -> Result<Option<(String, String)>, ApiError> {
    let Some(raw) = raw.filter(|value| !value.is_empty() && value.len() <= CURSOR_MAX) else {
        return Ok(None);
    };
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
    let (timestamp, id) = text.split_once('|').ok_or_else(invalid)?;
    if timestamp.is_empty() || id.is_empty() || id.len() > 64 {
        return Err(invalid());
    }
    Ok(Some((timestamp.to_owned(), id.to_owned())))
}

/// Bound one repository page and produce the frozen
/// `{items, next_cursor, has_more}` shape.
pub fn finish_page<T>(
    rows: Vec<T>,
    limit: i32,
    project: impl Fn(&T) -> Value,
    last_key: Option<(String, String)>,
) -> Value {
    let has_more = i64::try_from(rows.len()).unwrap_or_default() > i64::from(limit);
    let items = rows
        .iter()
        .take(limit.max(0) as usize)
        .map(project)
        .collect::<Vec<_>>();
    page_body(items, last_key, has_more)
}

/// Assemble a page from already projected items. A caller that filters rows
/// after the repository page (for example by project visibility) uses this so
/// the cursor still advances by the fetched window.
pub fn page_body(items: Vec<Value>, last_key: Option<(String, String)>, has_more: bool) -> Value {
    let next_cursor = match (has_more, last_key) {
        (true, Some((timestamp, id))) => Some(encode_page_cursor(&timestamp, &id)),
        _ => None,
    };
    json!({
        "items": items,
        "next_cursor": next_cursor,
        "has_more": has_more,
    })
}

fn optional_filter(context: &RequestContext, value: Option<&str>) -> Result<String, ApiError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(String::new());
    };
    if value.len() > 32 || value.chars().any(char::is_control) {
        return Err(validation_error(
            context,
            "filter_invalid",
            "The filter value is invalid.",
        ));
    }
    Ok(value.to_owned())
}

fn bounded_name(context: &RequestContext, value: &str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 160 || trimmed.chars().any(char::is_control)
    {
        return Err(validation_error(
            context,
            "name_invalid",
            "Enter a valid name.",
        ));
    }
    Ok(trimmed.to_owned())
}

/// A fingerprint is a short opaque identifier, not a digest string. The rule
/// matches the evaluator's own bound and charset, so a stored fingerprint is
/// always one the policy layer can evaluate.
pub fn fingerprint_value(context: &RequestContext, value: &str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    let printable = trimmed
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
    if (4..=128).contains(&trimmed.len()) && printable {
        return Ok(trimmed.to_owned());
    }
    Err(validation_error(
        context,
        "fingerprint_invalid",
        "The tool fingerprint is invalid.",
    ))
}

fn capability_ids_value(context: &RequestContext, values: &[String]) -> Result<String, ApiError> {
    let invalid = || {
        validation_error(
            context,
            "capability_ids_invalid",
            "Choose valid capability references.",
        )
    };
    if values.len() > CAPABILITY_IDS_MAX {
        return Err(invalid());
    }
    let mut unique: Vec<String> = Vec::with_capacity(values.len());
    for value in values {
        let id = CapabilityId::new(value.as_str()).map_err(|_| invalid())?;
        let id = id.as_str().to_owned();
        if !unique.contains(&id) {
            unique.push(id);
        }
    }
    serde_json::to_string(&unique).map_err(|_| internal_error(context))
}

fn capability_id_set(
    context: &RequestContext,
    values: &[String],
) -> Result<BTreeSet<String>, ApiError> {
    let invalid = || {
        validation_error(
            context,
            "capability_ids_invalid",
            "Choose valid capability references.",
        )
    };
    if values.len() > CAPABILITY_IDS_MAX {
        return Err(invalid());
    }
    values
        .iter()
        .map(|value| CapabilityId::new(value.as_str()).map(|id| id.as_str().to_owned()))
        .collect::<Result<BTreeSet<String>, _>>()
        .map_err(|_| invalid())
}

fn metadata_value(context: &RequestContext, value: Option<&Value>) -> Result<String, ApiError> {
    let Some(value) = value else {
        return Ok("{}".to_owned());
    };
    let invalid = || {
        validation_error(
            context,
            "metadata_invalid",
            "Tool metadata must be a small object.",
        )
    };
    if !value.is_object() {
        return Err(invalid());
    }
    let encoded = serde_json::to_string(value).map_err(|_| invalid())?;
    if encoded.len() > METADATA_MAX {
        return Err(invalid());
    }
    Ok(encoded)
}

fn string_array(raw: &str) -> BTreeSet<String> {
    serde_json::from_str::<Vec<Value>>(raw)
        .unwrap_or_default()
        .iter()
        .map(|value| match value {
            Value::String(text) => text.clone(),
            other => other
                .get("fingerprint")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        })
        .filter(|value| !value.is_empty())
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McpTransport {
    Http,
    Sse,
    Stdio,
    Other,
}

impl McpTransport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Sse => "sse",
            Self::Stdio => "stdio",
            Self::Other => "other",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "http" => Some(Self::Http),
            "sse" => Some(Self::Sse),
            "stdio" => Some(Self::Stdio),
            "other" => Some(Self::Other),
            _ => None,
        }
    }

    const fn is_remote(self) -> bool {
        matches!(self, Self::Http | Self::Sse)
    }
}

fn transport_value(context: &RequestContext, value: &str) -> Result<McpTransport, ApiError> {
    McpTransport::parse(value).ok_or_else(|| {
        validation_error(
            context,
            "transport_invalid",
            "Choose a supported MCP transport.",
        )
    })
}

/// Validate non-secret transport metadata. Endpoint URLs pass the shared
/// provider SSRF guard, and command metadata is stored as inert text only.
fn transport_metadata(
    context: &RequestContext,
    state: &AppState,
    transport: McpTransport,
    endpoint: Option<&EndpointMetadata>,
    command: Option<&CommandMetadata>,
) -> Result<(String, String), ApiError> {
    let endpoint = endpoint.cloned().unwrap_or_default();
    let command = command.cloned().unwrap_or_default();
    let invalid =
        |reason: &'static str, message: &'static str| validation_error(context, reason, message);
    if let Some(url) = endpoint.url.as_deref() {
        if !transport.is_remote() {
            return Err(invalid(
                "endpoint_metadata_invalid",
                "Only HTTP and SSE transports accept an endpoint URL.",
            ));
        }
        crate::adapters::providers::validate_endpoint_url(
            url,
            &state.provider_allowlist,
            state.environment == "development",
        )
        .map_err(|_| {
            domain_error(
                context,
                ApiErrorCode::PermissionDenied,
                "ssrf_blocked",
                "The MCP endpoint is not allowed.",
            )
        })?;
    }
    if endpoint
        .display_name
        .as_ref()
        .is_some_and(|value| value.chars().count() > 160 || value.chars().any(char::is_control))
    {
        return Err(invalid(
            "endpoint_metadata_invalid",
            "The MCP endpoint metadata is invalid.",
        ));
    }
    if let Some(command_value) = command.command.as_deref() {
        let allowed_command = !command_value.is_empty()
            && command_value.len() <= 128
            && command_value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-/".contains(&byte));
        if !allowed_command || transport.is_remote() {
            return Err(invalid(
                "command_metadata_invalid",
                "The MCP command metadata is invalid.",
            ));
        }
    }
    if command.arguments.len() > 32
        || command.arguments.iter().any(|value| {
            value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
        })
        || command.working_directory.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > 255 || value.chars().any(char::is_control)
        })
    {
        return Err(invalid(
            "command_metadata_invalid",
            "The MCP command metadata is invalid.",
        ));
    }
    if transport == McpTransport::Stdio && command.command.is_none() {
        return Err(invalid(
            "command_metadata_required",
            "A stdio MCP transport requires command metadata.",
        ));
    }
    if transport.is_remote() && endpoint.url.is_none() {
        return Err(invalid(
            "endpoint_metadata_required",
            "An HTTP MCP transport requires an endpoint URL.",
        ));
    }
    let endpoint_json = serde_json::to_string(&endpoint).map_err(|_| internal_error(context))?;
    let command_json = serde_json::to_string(&command).map_err(|_| internal_error(context))?;
    Ok((endpoint_json, command_json))
}

fn origins_value(context: &RequestContext, values: &[String]) -> Result<String, ApiError> {
    if values.len() > LIST_MAX {
        return Err(validation_error(
            context,
            "allowed_origins_invalid",
            "The allowed origins are invalid.",
        ));
    }
    let mut unique: Vec<String> = Vec::with_capacity(values.len());
    for value in values {
        if !valid_origin(value) {
            return Err(validation_error(
                context,
                "allowed_origins_invalid",
                "The allowed origins are invalid.",
            ));
        }
        let value = value.trim().to_ascii_lowercase();
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    serde_json::to_string(&unique).map_err(|_| internal_error(context))
}

/// Origins are explicit `scheme://host[:port]` values. Wildcards are rejected so
/// one entry can never authorize arbitrary destinations.
fn valid_origin(value: &str) -> bool {
    if value.is_empty()
        || value.len() > ORIGIN_MAX
        || value != value.trim().to_ascii_lowercase()
        || value.chars().any(char::is_control)
        || value.contains('*')
    {
        return false;
    }
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    if !matches!(scheme, "https" | "http" | "wss" | "ws") {
        return false;
    }
    if rest.is_empty()
        || rest.contains('/')
        || rest.contains('@')
        || rest.contains('?')
        || rest.contains('#')
        || rest.contains(' ')
    {
        return false;
    }
    let host = rest.split(':').next().unwrap_or_default();
    !host.is_empty()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
}

/// Only opaque credential handles are accepted.
///
/// The stored value must be a P04 credential identifier, so secret material
/// cannot reach this column even by accident: a raw token is not a valid handle
/// and is rejected at the boundary (F13 FR-F13-008).
fn secret_handles_value(context: &RequestContext, values: &[String]) -> Result<String, ApiError> {
    let invalid = || {
        validation_error(
            context,
            "secret_handles_invalid",
            "The required secret handles are invalid.",
        )
    };
    if values.len() > CAPABILITY_IDS_MAX {
        return Err(invalid());
    }
    let mut unique: Vec<String> = Vec::with_capacity(values.len());
    for value in values {
        let trimmed = value.trim();
        if CredentialId::new(trimmed).is_err() {
            return Err(invalid());
        }
        let trimmed = trimmed.to_owned();
        if !unique.contains(&trimmed) {
            unique.push(trimmed);
        }
    }
    serde_json::to_string(&unique).map_err(|_| internal_error(context))
}

fn tool_list_value(
    context: &RequestContext,
    entries: &[ToolListEntry],
) -> Result<String, ApiError> {
    if entries.len() > LIST_MAX {
        return Err(validation_error(
            context,
            "tool_list_invalid",
            "The MCP tool list is invalid.",
        ));
    }
    for entry in entries {
        if ToolId::new(entry.tool_id.as_str()).is_err()
            || RiskClass::parse(&entry.risk_class).is_none()
            || fingerprint_value(context, &entry.fingerprint).is_err()
        {
            return Err(validation_error(
                context,
                "tool_list_invalid",
                "The MCP tool list is invalid.",
            ));
        }
    }
    serde_json::to_string(entries).map_err(|_| internal_error(context))
}

// ---------------------------------------------------------------------------
// Audit records
// ---------------------------------------------------------------------------

/// Append the F16 audit record for a browser-session mutation.
///
/// The shared helper only accepts bounded metadata and never serializes a
/// request body, credential, prompt, or response.
#[allow(clippy::too_many_arguments)]
pub fn session_security_event(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    principal: &Principal,
    organization_id: &str,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    outcome: &str,
    metadata: &Value,
) -> Result<worker::d1::D1PreparedStatement, ApiError> {
    let event_id = generated_id("sec");
    security_event_statement(
        database,
        context,
        Some(principal),
        Some(organization_id),
        &event_id,
        action,
        resource_type,
        Some(resource_id),
        outcome,
        metadata,
    )
}

/// Append the audit record for a device-initiated tool decision.
///
/// The audit taxonomy has no device actor, so the run owner is recorded as the
/// effective user while the device, run, agent session, and tool call are
/// recorded as the correlation columns. The bounded metadata marks the actor as
/// the device so the trail cannot be misread as a direct human action.
#[allow(clippy::too_many_arguments)]
fn device_security_event(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    scope: &RunToolScopeRecord,
    device: &DeviceRecord,
    session_id: &str,
    action: &str,
    resource_type: &str,
    resource_id: Option<&str>,
    outcome: &str,
    metadata: Value,
) -> Result<worker::d1::D1PreparedStatement, ApiError> {
    let event_id = generated_id("sec");
    let owner = audit_principal(context, scope, session_id);
    let mut metadata = metadata;
    if let Some(object) = metadata.as_object_mut() {
        object.insert("actor".to_owned(), json!("device"));
    }
    security_event_statement_with_context(
        database,
        context,
        Some(&owner),
        Some(&scope.org_id),
        &event_id,
        action,
        resource_type,
        resource_id,
        outcome,
        &metadata,
        Some(&device.device_id),
        Some(&scope.run_id),
        Some(&scope.agent_session_id),
        resource_id,
    )
}

/// The run owner identity used for audit correlation on a device-scoped call.
/// Only the identifier fields are used; a failure to build it must not widen the
/// call, so an unusable value yields an owner-less record.
fn audit_principal(
    context: &RequestContext,
    scope: &RunToolScopeRecord,
    session_id: &str,
) -> Principal {
    let user_id = UserId::new(scope.principal_user_id.clone()).unwrap_or_else(|_| {
        UserId::new("usr_00000000000000000000000000000000").expect("static user ID is valid")
    });
    let session = crate::core::SessionId::new(session_id.to_owned()).unwrap_or_else(|_| {
        crate::core::SessionId::new("ses_00000000000000000000000000000000")
            .expect("static session ID is valid")
    });
    let _ = context;
    Principal::new(
        user_id,
        session,
        scope.user_email.clone(),
        scope.user_display_name.clone(),
        scope.user_email_verified == 1,
    )
}

// ---------------------------------------------------------------------------
// Idempotency helpers shared with `routes::approvals`
// ---------------------------------------------------------------------------

pub struct PendingMutation {
    record: IdempotencyRecord,
    token: IdempotencyClaimToken,
}

pub enum MutationClaim {
    Replay(StoredSuccess),
    Pending(PendingMutation),
}

pub async fn commit_mutation(
    database: &crate::adapters::d1::D1Adapter,
    pending: &PendingMutation,
    now: &Timestamp,
    success: &StoredSuccess,
    business_writes: Vec<worker::d1::D1PreparedStatement>,
    outbox_insert: worker::d1::D1PreparedStatement,
) -> worker::Result<Vec<worker::d1::D1Result>> {
    let repository = IdempotencyRepository::new(database);
    let claim_statement = repository.claim_statement(&pending.record, &pending.token, now)?;
    let result = repository
        .commit_success(
            &pending.record,
            &pending.token,
            claim_statement,
            success,
            business_writes,
            outbox_insert,
        )
        .await;
    if result.is_err() {
        let _ = repository
            .release_pending_claim(&pending.record, &pending.token)
            .await;
    }
    result
}

pub fn replay_response(success: &StoredSuccess) -> Response<Body> {
    let status = StatusCode::from_u16(success.status).unwrap_or(StatusCode::OK);
    let body = serde_json::to_vec(&success.body).unwrap_or_else(|_| b"{}".to_vec());
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    response
}

#[allow(clippy::too_many_arguments)]
pub async fn begin_mutation(
    key: &str,
    user_id: &str,
    org_id: &str,
    method: &str,
    path: &str,
    fingerprint_input: &str,
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
) -> Result<MutationClaim, ApiError> {
    let record = idempotency_record(
        key,
        user_id,
        org_id,
        method,
        path,
        fingerprint_input,
        context,
    )
    .await?;
    let token = IdempotencyClaimToken::new(context.request_id.as_str())
        .map_err(|_| internal_error(context))?;
    let repository = IdempotencyRepository::new(database);
    match repository
        .lookup(
            &record.scope,
            &record.key_digest,
            &record.request_fingerprint,
            &context.received_at,
        )
        .await
        .map_err(|_| service_unavailable(context))?
    {
        IdempotencyLookup::Missing => {
            if !repository
                .claim(&record, &token, &context.received_at)
                .await
                .map_err(|_| service_unavailable(context))?
            {
                return Err(idempotency_in_progress(context));
            }
            Ok(MutationClaim::Pending(PendingMutation { record, token }))
        }
        IdempotencyLookup::InProgress => Err(idempotency_in_progress(context)),
        IdempotencyLookup::FingerprintConflict => Err(idempotency_conflict(context)),
        IdempotencyLookup::Replay(success) => Ok(MutationClaim::Replay(success)),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn lookup_mutation(
    key: &str,
    user_id: &str,
    org_id: &str,
    method: &str,
    path: &str,
    fingerprint_input: &str,
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
) -> Result<Option<StoredSuccess>, ApiError> {
    let record = idempotency_record(
        key,
        user_id,
        org_id,
        method,
        path,
        fingerprint_input,
        context,
    )
    .await?;
    let repository = IdempotencyRepository::new(database);
    match repository
        .lookup(
            &record.scope,
            &record.key_digest,
            &record.request_fingerprint,
            &context.received_at,
        )
        .await
        .map_err(|_| service_unavailable(context))?
    {
        IdempotencyLookup::Missing => Ok(None),
        IdempotencyLookup::InProgress => Err(idempotency_in_progress(context)),
        IdempotencyLookup::FingerprintConflict => Err(idempotency_conflict(context)),
        IdempotencyLookup::Replay(success) => Ok(Some(success)),
    }
}

#[allow(clippy::too_many_arguments)]
async fn idempotency_record(
    key: &str,
    user_id: &str,
    org_id: &str,
    method: &str,
    path: &str,
    fingerprint_input: &str,
    context: &RequestContext,
) -> Result<IdempotencyRecord, ApiError> {
    let key_digest = IdempotencyKeyDigest::new(format!(
        "sha256:{}",
        sha256_hex(key)
            .await
            .map_err(|_| service_unavailable(context))?
    ))
    .map_err(|_| internal_error(context))?;
    let request_fingerprint = RequestFingerprint::new(format!(
        "sha256:{}",
        sha256_hex(fingerprint_input)
            .await
            .map_err(|_| service_unavailable(context))?
    ))
    .map_err(|_| internal_error(context))?;
    let scope = IdempotencyScope::new(
        ActorId::new(user_id).map_err(|_| internal_error(context))?,
        Some(OrganizationId::new(org_id).map_err(|_| internal_error(context))?),
        method,
        path,
    )
    .map_err(|_| internal_error(context))?;
    let expires_at =
        add_seconds(&context.received_at, 86_400).map_err(|_| service_unavailable(context))?;
    Ok(IdempotencyRecord {
        scope,
        key_digest,
        request_fingerprint,
        expires_at,
        state: IdempotencyState::Pending,
    })
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolResultRequest {
    pub status: String,
    pub result_summary: Option<String>,
    pub error_code: Option<String>,
}

fn tool_call_result_json(call: &ToolCallRefRecord) -> Value {
    json!({
        "tool_call_id": call.tool_call_id,
        "org_id": call.org_id,
        "project_id": call.project_id,
        "run_id": call.run_id,
        "tool_id": call.tool_id,
        "tool_fingerprint": call.tool_fingerprint,
        "risk_class": call.risk_class,
        "arguments_summary": call.arguments_summary,
        "status": call.status,
        "created_at": call.created_at,
        "updated_at": call.updated_at,
    })
}

#[worker::send]
pub async fn record_tool_result(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((run_id, tool_call_id)): Path<(String, String)>,
    Json(body): Json<ToolResultRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_device(&state, &headers, &context).await?;
    if RunId::new(run_id.as_str()).is_err() || ToolCallId::new(tool_call_id.as_str()).is_err() {
        return Err(not_found(&context, "The tool call was not found."));
    }
    let status = match body.status.as_str() {
        "completed" | "failed" | "cancelled" => body.status.as_str(),
        _ => {
            return Err(validation_error(
                &context,
                "tool_result_status_invalid",
                "The tool result status is invalid.",
            ));
        }
    };
    let result_summary = body
        .result_summary
        .as_deref()
        .map(|value| {
            if value.len() > 2048 || value.chars().any(char::is_control) {
                Err(validation_error(
                    &context,
                    "tool_result_summary_invalid",
                    "The tool result summary is invalid.",
                ))
            } else {
                Ok(value.to_owned())
            }
        })
        .transpose()?;
    let error_code = body
        .error_code
        .as_deref()
        .map(|value| {
            if value.len() > 96 || value.chars().any(char::is_control) {
                Err(validation_error(
                    &context,
                    "tool_error_code_invalid",
                    "The tool error code is invalid.",
                ))
            } else {
                Ok(value.to_owned())
            }
        })
        .transpose()?;
    let key = idempotency_key(&headers, &context)?;
    let database = database(&state, &context)?;
    let run = RunRepository::new(database)
        .find_run(&access.device.org_id, &run_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context, "The run was not found."))?;
    if run.device_id != access.device.device_id {
        return Err(not_found(&context, "The run was not found."));
    }
    let tools = ToolRepository::new(database);
    let call = tools
        .find_tool_call_ref(&run_id, &tool_call_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context, "The tool call was not found."))?;
    if call.org_id != run.org_id || call.run_id != run.run_id {
        return Err(not_found(&context, "The tool call was not found."));
    }
    if call.status == status {
        return Ok(Json(tool_call_result_json(&call)).into_response());
    }
    if matches!(call.status.as_str(), "denied" | "failed" | "cancelled") {
        return Err(not_found(&context, "The tool call is already terminal."));
    }
    let approvals = ApprovalRepository::new(database);
    let approval = approvals
        .find_approval_for_tool_call(&run_id, &tool_call_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    let mut writes = Vec::new();
    if let Some(approval) = approval.as_ref() {
        match approval.status.as_str() {
            "pending" => {
                return Err(validation_error(
                    &context,
                    "approval_required",
                    "The tool call is waiting for approval.",
                ));
            }
            "approved" => {
                if approval.approval_mode == "per_use" {
                    writes.push(
                        approvals
                            .consume_approval_statement(
                                &approval.approval_id,
                                &access.device.org_id,
                                &tool_call_id,
                                &access.device.device_id,
                                &context.received_at,
                            )
                            .map_err(|error| database_error(&context, error))?,
                    );
                }
            }
            "denied" | "expired" | "cancelled" => {
                return Err(validation_error(
                    &context,
                    "tool_denied",
                    "The tool call was not approved.",
                ));
            }
            _ => {}
        }
    }
    writes.push(
        tools
            .update_tool_call_status_statement(&run_id, &tool_call_id, status, &context.received_at)
            .map_err(|error| database_error(&context, error))?,
    );
    let event_payload = json!({
        "tool_call_id": tool_call_id,
        "run_id": run_id,
        "status": status,
        "result_summary_present": result_summary.is_some(),
        "error_code_present": error_code.is_some(),
    });
    let security = security_event_statement_with_context(
        database,
        &context,
        None,
        Some(&access.device.org_id),
        new_resource_id("sec").as_str(),
        "tool.result.v1",
        "tool_call",
        Some(&tool_call_id),
        "success",
        &event_payload,
        Some(&access.device.device_id),
        Some(&run_id),
        Some(&run.agent_session_id),
        Some(&tool_call_id),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        None,
        Some(&access.device.org_id),
        "tool.result.v1",
        &event_payload,
    )?;
    writes.push(security);
    let body_value = serde_json::to_value(&body).map_err(|_| internal_error(&context))?;
    let claim = match prepare_scoped_mutation(
        database,
        &context,
        &access.device.device_id,
        &access.device.org_id,
        &key,
        "POST",
        &format!("/api/v1/devices/runs/{run_id}/tool-calls/{tool_call_id}/result"),
        &body_value,
    )
    .await?
    {
        crate::routes::usage::PreparedScopedMutation::Replay(success) => {
            return Ok(replay_response(&success));
        }
        crate::routes::usage::PreparedScopedMutation::Claim(claim) => claim,
    };
    let response = json!({
        "tool_call_id": call.tool_call_id,
        "run_id": run.run_id,
        "status": status,
        "updated_at": context.received_at,
    });
    let success =
        StoredSuccess::new(200, response.clone()).map_err(|_| internal_error(&context))?;
    match commit_scoped_mutation(database, &context, claim, success, writes, outbox).await? {
        ScopedMutationCommit::Replayed(success) => Ok(replay_response(&success)),
        ScopedMutationCommit::Committed => Ok(Json(response).into_response()),
        ScopedMutationCommit::Guarded => Err(validation_error(
            &context,
            "approval_already_resolved",
            "The approval was already consumed or resolved.",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOOL_ID: &str = "tool_0123456789abcdef0123456789abcdef";

    fn context() -> RequestContext {
        RequestContext::new(
            "req_0123456789abcdef0123456789abcdef".parse().unwrap(),
            "trace-1".parse().unwrap(),
            "2026-09-25T12:00:00.000Z".parse().unwrap(),
        )
    }

    #[test]
    fn stored_column_values_map_onto_domain_lifecycle_and_status() {
        assert_eq!(tool_lifecycle("active"), Some(ToolLifecycle::Active));
        assert_eq!(tool_lifecycle("review"), Some(ToolLifecycle::Review));
        assert_eq!(tool_lifecycle("disabled"), Some(ToolLifecycle::Disabled));
        assert_eq!(tool_lifecycle("archived"), None);
        assert_eq!(
            mcp_policy_status("pending_review"),
            Some(McpPolicyStatus::PendingReview)
        );
        assert_eq!(
            mcp_policy_status("disabled"),
            Some(McpPolicyStatus::Disabled)
        );
        assert_eq!(mcp_policy_status("blocked"), None);
        // Every stored value round-trips back to the same column value.
        assert_eq!(tool_lifecycle_text(ToolLifecycle::Active), Some("active"));
        assert_eq!(tool_lifecycle_text(ToolLifecycle::Review), Some("review"));
        assert_eq!(
            tool_lifecycle_text(ToolLifecycle::Disabled),
            Some("disabled")
        );
        // The frozen columns have no value for these states, so they are refused
        // instead of being coerced into a different meaning.
        assert_eq!(tool_lifecycle_text(ToolLifecycle::Deprecated), None);
        assert_eq!(mcp_policy_status_text(McpPolicyStatus::Revoked), None);
        assert_eq!(
            mcp_policy_status_text(McpPolicyStatus::Approved),
            Some("approved")
        );
    }

    #[test]
    fn opaque_and_unsupported_policy_documents_fail_closed() {
        assert!(stored_layer(r#"{"schema_version": 0}"#).is_none());
        assert!(stored_layer(r#"{"schema_version": 2}"#).is_none());
        assert!(stored_layer("not json").is_none());
        assert!(stored_layer(r#"{"default_posture": "allow"}"#).is_none());
        let document = ToolPolicyLayer {
            default_posture: PolicyPosture::Allow,
            tool_ids: [TOOL_ID.to_owned()].into_iter().collect(),
            ..ToolPolicyLayer::default()
        };
        let encoded = serde_json::to_string(&document).unwrap();
        let parsed = stored_layer(&encoded).expect("valid document");
        assert_eq!(parsed.default_posture, PolicyPosture::Allow);
        assert!(parsed.tool_ids.contains(TOOL_ID));
    }

    #[test]
    fn a_published_snapshot_section_can_only_narrow_the_document() {
        let document = ToolPolicyLayer {
            default_posture: PolicyPosture::Allow,
            tool_ids: [
                TOOL_ID.to_owned(),
                "tool_11111111111111111111111111111111".to_owned(),
            ]
            .into_iter()
            .collect(),
            mcp_ids: Default::default(),
            ..ToolPolicyLayer::default()
        };
        let section = ToolPolicySection {
            schema_version: 1,
            default_posture: snapshot_policy::DefaultPosture::Allow,
            tool_ids: [TOOL_ID.to_owned()].into_iter().collect(),
            mcp_ids: Default::default(),
            rules: vec![snapshot_policy::ToolPolicyRule {
                tool_id: "tool_11111111111111111111111111111111".to_owned(),
                capability_id: None,
                decision: PolicyDecision::Deny,
                argument_scope: Vec::new(),
            }],
            browser: Default::default(),
            computer: Default::default(),
        };
        let narrowed = narrow_with_snapshot(document.clone(), &section);
        assert!(
            !narrowed
                .tool_ids
                .contains("tool_11111111111111111111111111111111")
        );
        assert_eq!(narrowed.default_posture, PolicyPosture::Deny);
        assert!(narrowed.tool_ids.contains(TOOL_ID));
    }

    #[test]
    fn a_scoped_snapshot_rule_is_held_rather_than_approved_wider() {
        let document = ToolPolicyLayer {
            default_posture: PolicyPosture::Allow,
            tool_ids: [TOOL_ID.to_owned()].into_iter().collect(),
            ..ToolPolicyLayer::default()
        };
        let section = ToolPolicySection {
            schema_version: 1,
            default_posture: snapshot_policy::DefaultPosture::Allow,
            tool_ids: [TOOL_ID.to_owned()].into_iter().collect(),
            mcp_ids: Default::default(),
            rules: vec![snapshot_policy::ToolPolicyRule {
                tool_id: TOOL_ID.to_owned(),
                capability_id: None,
                decision: PolicyDecision::Allow,
                argument_scope: vec!["destination".to_owned()],
            }],
            browser: Default::default(),
            computer: Default::default(),
        };
        let narrowed = narrow_with_snapshot(document, &section);
        assert!(!narrowed.tool_ids.contains(TOOL_ID));
        assert_eq!(narrowed.default_posture, PolicyPosture::Deny);
    }

    #[test]
    fn bounded_input_rejects_unbounded_or_sensitive_values() {
        let context = context();
        assert!(fingerprint_value(&context, "ok").is_err());
        assert!(fingerprint_value(&context, "fingerprint-aa").is_ok());
        assert!(fingerprint_value(&context, "sha256:aa").is_err());
        assert!(fingerprint_value(&context, "has space").is_err());
        assert!(
            capability_ids_value(
                &context,
                &["cap_0123456789abcdef0123456789abcdef".to_owned()]
            )
            .is_ok()
        );
        assert!(capability_ids_value(&context, &["text".to_owned()]).is_err());
        assert!(
            secret_handles_value(
                &context,
                &["cred_0123456789abcdef0123456789abcdef".to_owned()]
            )
            .is_ok()
        );
        assert!(secret_handles_value(&context, &["sk-live-secret".to_owned()]).is_err());
    }

    #[test]
    fn origin_validation_rejects_wildcards_and_ambiguous_shapes() {
        assert!(valid_origin("https://mcp.example.test"));
        assert!(valid_origin("http://localhost:8080"));
        assert!(!valid_origin("https://*.example.test"));
        assert!(!valid_origin("https://example.test/path"));
        assert!(!valid_origin("file:///etc/passwd"));
        assert!(!valid_origin("https://user@example.test"));
        assert!(!valid_origin("HTTPS://example.test"));
    }

    #[test]
    fn only_run_states_that_can_execute_a_tool_may_request_a_decision() {
        for state in ["dispatching", "running", "waiting_user", "waiting_approval"] {
            assert!(run_can_request_tool_decision(state), "rejected {state}");
        }
        for state in ["queued", "succeeded", "failed", "cancelled", "timed_out"] {
            assert!(!run_can_request_tool_decision(state), "accepted {state}");
        }
        for state in ["succeeded", "failed", "cancelled", "timed_out"] {
            assert!(is_terminal_run_state(state));
        }
    }

    #[test]
    fn cursors_are_opaque_and_round_trip_through_the_keyset() {
        let context = context();
        let cursor = encode_page_cursor("2026-09-25T12:00:00.000Z", "tool_1");
        assert_eq!(cursor, CURSOR_FIXTURE);
        let decoded = decode_page_cursor(Some(&cursor), &context)
            .unwrap()
            .unwrap();
        assert_eq!(decoded.0, "2026-09-25T12:00:00.000Z");
        assert_eq!(decoded.1, "tool_1");
        assert!(decode_page_cursor(Some("not-hex!!"), &context).is_err());
        assert!(decode_page_cursor(Some(""), &context).unwrap().is_none());
        assert!(decode_page_cursor(None, &context).unwrap().is_none());
    }

    #[test]
    fn pages_bound_results_and_only_offer_a_cursor_when_more_exist() {
        let rows = vec![
            ("2026-09-25T12:00:00.000Z".to_owned(), "a".to_owned()),
            ("2026-09-25T11:00:00.000Z".to_owned(), "b".to_owned()),
        ];
        let page = finish_page(
            rows.clone(),
            1,
            |row| json!([row.0.clone(), row.1.clone()]),
            Some(rows[0].clone()),
        );
        assert_eq!(page["items"].as_array().unwrap().len(), 1);
        assert_eq!(page["has_more"], json!(true));
        assert_eq!(
            page["next_cursor"],
            json!(encode_page_cursor(&rows[0].0, &rows[0].1))
        );
        let page = finish_page(rows, 5, |row| json!([row.0.clone(), row.1.clone()]), None);
        assert_eq!(page["items"].as_array().unwrap().len(), 2);
        assert_eq!(page["has_more"], json!(false));
        assert_eq!(page["next_cursor"], json!(null));
    }

    const CURSOR_FIXTURE: &str = "323032362d30392d32355431323a30303a30302e3030305a7c746f6f6c5f31";
}
