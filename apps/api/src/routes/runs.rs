//! P05 run, timeline, and artifact HTTP surface.
//!
//! Run creation is control-plane bookkeeping only.  The Worker writes a
//! durable cancellation/dispatch signal to the outbox; the desktop/runtime is
//! the execution host and must perform inference, tools, and local file work.

use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, Response, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use worker::d1::D1PreparedStatement;

use crate::{
    app::AppState,
    core::{ApiError, ApiErrorCode, Principal, RequestContext, StoredSuccess},
    http::auth::require_csrf,
    modules::{
        authorization::Permission,
        runs::{RunState, SessionState, sanitize_run_event_payload},
    },
    repositories::{
        AgentDefinitionRecord, AgentSessionRecord, AiRepository, ArtifactRefRecord, DeviceRecord,
        DeviceRepository, PolicyRepository, ProjectRepository, RunEventRecord, RunRecord,
        RunRepository,
    },
    routes::{
        agents::{
            PreparedMutation, can_manage_projects, commit_mutation, decode_page_cursor, denied,
            ensure_project_access, generated_id, not_found, page_limit, prepare_mutation,
            replay_response, service_unavailable, validate_model_alias, validate_prefixed_id,
            validate_text,
        },
        authorization::authorize_org,
        support::{database, database_error, domain_error, idempotency_key, outbox_statement},
    },
};

pub const RUNS_PATH: &str = "/api/v1/orgs/{org_id}/runs";
#[allow(dead_code)]
pub const RUN_PATH: &str = "/api/v1/orgs/{org_id}/runs/{run_id}";

#[derive(Debug, Deserialize)]
pub struct RunListQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    pub project_id: Option<String>,
    pub session_id: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RunEventQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    pub after_sequence: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartRunRequest {
    pub agent_session_id: String,
    pub model_alias: Option<String>,
    pub input_ref: Option<String>,
    pub parent_run_id: Option<String>,
    /// Optional compatibility discriminator.  `local_only` never claims
    /// managed cloud authorization; omitted means managed when a model alias
    /// resolves, otherwise local-only bookkeeping.
    pub execution_mode: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRunRequest {
    pub version: i64,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetryRunRequest {
    pub version: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRequest {
    pub kind: String,
    pub content_ref: Option<String>,
    pub mime_type: Option<String>,
    pub size_bytes: Option<i64>,
    pub checksum: Option<String>,
    pub retention_policy: Option<String>,
}

/// Runtime correlation data for the P05 managed execution boundary.  This is
/// a serialization helper only: callers must obtain the records after the
/// control-plane authorization checks in this module.
#[allow(dead_code)]
#[derive(Clone, Debug, Serialize)]
pub struct ManagedRunContext {
    pub org_id: String,
    pub project_id: String,
    pub device_id: String,
    pub agent_session_id: String,
    pub run_id: String,
    pub agent_definition_id: String,
    pub agent_definition_version: i64,
    pub workspace_binding_id: Option<String>,
    pub policy_snapshot_id: Option<String>,
    pub policy_version: Option<i64>,
    pub request_id: String,
    pub execution_mode: String,
}

#[allow(dead_code)]
pub fn managed_run_context(
    run: &RunRecord,
    session: &AgentSessionRecord,
    execution_mode: impl Into<String>,
) -> ManagedRunContext {
    debug_assert_eq!(run.agent_session_id, session.agent_session_id);
    debug_assert_eq!(run.device_id, session.device_id);
    ManagedRunContext {
        org_id: run.org_id.clone(),
        project_id: run.project_id.clone(),
        device_id: run.device_id.clone(),
        agent_session_id: run.agent_session_id.clone(),
        run_id: run.run_id.clone(),
        agent_definition_id: run.agent_definition_id.clone(),
        agent_definition_version: run.agent_definition_version,
        workspace_binding_id: run.workspace_binding_id.clone(),
        policy_snapshot_id: run.policy_snapshot_id.clone(),
        policy_version: run.policy_version,
        request_id: run.request_id.clone().unwrap_or_default(),
        execution_mode: execution_mode.into(),
    }
}

struct RunScope {
    session: AgentSessionRecord,
    agent: AgentDefinitionRecord,
    project_id: String,
    device: DeviceRecord,
    model_alias: Option<String>,
    route_id: Option<String>,
    route_version_id: Option<String>,
    policy_snapshot_id: Option<String>,
    policy_version: Option<i64>,
    execution_mode: String,
}

pub(crate) fn run_json(run: &RunRecord) -> Value {
    json!({
        "id": run.run_id,
        "org_id": run.org_id,
        "project_id": run.project_id,
        "agent_session_id": run.agent_session_id,
        "parent_run_id": run.parent_run_id,
        "attempt": run.attempt,
        "agent_definition_id": run.agent_definition_id,
        "agent_definition_version": run.agent_definition_version,
        "principal_user_id": run.principal_user_id,
        "device_id": run.device_id,
        "model_alias": run.model_alias,
        "route_id": run.route_id,
        "route_version_id": run.route_version_id,
        "workspace_binding_id": run.workspace_binding_id,
        "policy_snapshot_id": run.policy_snapshot_id,
        "policy_version": run.policy_version,
        "cancel_requested_at": run.cancel_requested_at,
        "resumed_from_run_id": run.resumed_from_run_id,
        "state_version": run.state_version,
        "execution_mode": if run.model_alias.is_some() {
            "managed"
        } else {
            "local_only"
        },
        "state": run.state,
        "failure_code": run.failure_code,
        "request_id": run.request_id,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "version": run.version,
        "created_at": run.created_at,
        "updated_at": run.updated_at,
    })
}

fn artifact_json(artifact: &ArtifactRefRecord) -> Value {
    json!({
        "id": artifact.artifact_ref_id,
        "org_id": artifact.org_id,
        "project_id": artifact.project_id,
        "run_id": artifact.run_id,
        "kind": artifact.kind,
        "content_ref": artifact.content_ref,
        "mime_type": artifact.mime_type,
        "size_bytes": artifact.size_bytes,
        "checksum": artifact.checksum,
        "retention_policy": artifact.retention_policy,
        "created_at": artifact.created_at,
    })
}

fn retryable(state: &str) -> bool {
    RunState::parse(state).is_some_and(RunState::is_retryable)
}

fn valid_run_state(state: &str) -> bool {
    RunState::parse(state).is_some()
}

fn safe_event_payload(context: &RequestContext, raw: &str) -> Result<Value, ApiError> {
    let value = serde_json::from_str::<Value>(raw).map_err(|_| service_unavailable(context))?;
    let Some(object) = value.as_object() else {
        return Ok(json!({}));
    };
    const ALLOWED_KEYS: &[&str] = &[
        "risk_class",
        "arguments_summary",
        "tool_id",
        "tool_call_id",
        "approval_id",
        "state",
        "previous_state",
        "next_state",
        "attempt",
        "parent_run_id",
        "agent_session_id",
        "agent_definition_id",
        "agent_definition_version",
        "project_id",
        "device_id",
        "model_alias",
        "route_id",
        "route_version_id",
        "workspace_binding_id",
        "policy_snapshot_id",
        "policy_version",
        "state_version",
        "cancel_requested_at",
        "resumed_from_run_id",
        "kind",
        "artifact_id",
        "mime_type",
        "size_bytes",
        "reason_code",
        "reason_present",
        "reason",
        "decision",
        "approval_mode",
        "failure_code_present",
        "execution_mode",
        "input_ref_present",
        "execution_host_signal",
        "dispatch_signal",
        "version",
        "status",
    ];
    let mut safe = Map::new();
    for key in ALLOWED_KEYS {
        if let Some(value) = object.get(*key)
            && safe_metadata(value)
        {
            safe.insert((*key).to_owned(), value.clone());
        }
    }
    sanitize_run_event_payload(&Value::Object(safe)).map_err(|_| service_unavailable(context))
}

fn safe_metadata(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(_) => true,
        Value::Number(number) => number.as_f64().is_some_and(|value| value.is_finite()),
        Value::String(value) => value.len() <= 512 && !value.chars().any(char::is_control),
        Value::Array(values) => values.len() <= 16 && values.iter().all(safe_metadata),
        Value::Object(values) => {
            values.len() <= 16
                && values.iter().all(|(key, value)| {
                    key.len() <= 64 && !key.chars().any(char::is_control) && safe_metadata(value)
                })
        }
    }
}

fn event_json(context: &RequestContext, event: &RunEventRecord) -> Result<Value, ApiError> {
    Ok(json!({
        "id": event.run_event_id,
        "run_id": event.run_id,
        "org_id": event.org_id,
        "project_id": event.project_id,
        "request_id": event.request_id,
        "device_id": event.device_id,
        "agent_session_id": event.agent_session_id,
        "schema_version": event.schema_version,
        "sequence": event.sequence,
        "event_type": event.event_type,
        "occurred_at": event.occurred_at,
        "recorded_at": event.recorded_at,
        "actor_type": event.actor_type,
        "actor_id": event.actor_id,
        "correlation_id": event.correlation_id,
        "tool_call_id": event.tool_call_id,
        "approval_id": event.approval_id,
        "payload": safe_event_payload(context, &event.payload_json)?,
    }))
}

#[allow(clippy::too_many_arguments)]
fn run_security_statement(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    principal: &Principal,
    org_id: &str,
    device_id: Option<&str>,
    run_id: Option<&str>,
    agent_session_id: Option<&str>,
    event_id: &str,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    outcome: &str,
    metadata: &Value,
) -> Result<D1PreparedStatement, ApiError> {
    crate::routes::support::security_event_statement_with_context(
        database,
        context,
        Some(principal),
        Some(org_id),
        event_id,
        action,
        resource_type,
        Some(resource_id),
        outcome,
        metadata,
        device_id,
        run_id,
        agent_session_id,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_event_statement(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    principal: &Principal,
    org_id: &str,
    run_id: &str,
    event_id: &str,
    sequence: i64,
    event_type: &str,
    payload: &Value,
) -> Result<D1PreparedStatement, ApiError> {
    let safe_payload = sanitize_run_event_payload(payload).map_err(|_| {
        validation_error(
            context,
            "run_event_payload_invalid",
            "The run event metadata is invalid.",
        )
    })?;
    RunRepository::new(database)
        .insert_event_statement_for_org(
            org_id,
            context.request_id.as_str(),
            &crate::repositories::NewRunEventInput {
                run_event_id: event_id,
                run_id,
                sequence,
                event_type,
                occurred_at: &context.received_at,
                actor_type: "user",
                actor_id: Some(principal.user_id.as_str()),
                correlation_id: context.correlation_id.as_str(),
                tool_call_id: None,
                approval_id: None,
                payload: &safe_payload,
            },
        )
        .map_err(|error| database_error(context, error))
}

fn validate_execution_mode(
    context: &RequestContext,
    value: Option<&str>,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| {
            if matches!(value, "managed" | "local_only") {
                Ok(value.to_owned())
            } else {
                Err(validation_error(
                    context,
                    "execution_mode_invalid",
                    "The execution mode is invalid.",
                ))
            }
        })
        .transpose()
}

fn validation_error(context: &RequestContext, reason: &str, message: &str) -> ApiError {
    domain_error(context, ApiErrorCode::ValidationFailed, reason, message)
}

fn policy_denial(context: &RequestContext, reason: &str) -> ApiError {
    denied(
        context,
        ApiErrorCode::PermissionDenied,
        reason,
        "The current organization policy does not allow this run.",
    )
}

fn trusted_scope_matches(payload: &Value, key: &str, expected: &str) -> bool {
    if let Some(value) = payload.get(key) {
        return value.as_str() == Some(expected);
    }
    if key != "project_id" {
        // The P03 snapshot has no device claim; device ownership is resolved
        // from the active device row and workspace binding separately.
        return true;
    }
    let Some(bindings) = payload
        .get("projects")
        .and_then(|projects| projects.get("bindings"))
        .and_then(Value::as_array)
    else {
        // A project-scoped managed run must not treat a malformed or missing
        // project section as an org-wide allow decision.
        return false;
    };
    !bindings.is_empty()
        && bindings.iter().all(Value::is_string)
        && bindings
            .iter()
            .any(|value| value.as_str() == Some(expected))
}

#[allow(clippy::too_many_arguments)]
async fn load_scope(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    context: &RequestContext,
    principal: &Principal,
    org_id: &str,
    session_id: &str,
    requested_alias: Option<&str>,
    requested_mode: Option<&str>,
) -> Result<RunScope, ApiError> {
    let database = database(state, context)?;
    let manager = can_manage_projects(state, headers, context, org_id).await;
    let session = RunRepository::new(database)
        .find_session(org_id, session_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .ok_or_else(|| not_found(context, "session_not_found"))?;
    let project = ensure_project_access(
        database,
        context,
        org_id,
        &session.project_id,
        principal.user_id.as_str(),
        manager,
    )
    .await?;
    if project.archived_at.is_some() {
        return Err(denied(
            context,
            ApiErrorCode::Conflict,
            "project_archived",
            "Archived projects cannot start new runs.",
        ));
    }
    if !SessionState::parse(&session.lifecycle).is_some_and(SessionState::allows_new_runs) {
        return Err(denied(
            context,
            ApiErrorCode::Conflict,
            "session_closed",
            "Closed sessions cannot start new runs.",
        ));
    }
    let device = DeviceRepository::new(database)
        .find_device(&session.device_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .filter(|device: &DeviceRecord| device.org_id == org_id)
        .ok_or_else(|| not_found(context, "device_not_found"))?;
    if device.status != "active" {
        return Err(denied(
            context,
            ApiErrorCode::PermissionDenied,
            "device_revoked",
            "The execution device is not active.",
        ));
    }
    let agent = RunRepository::new(database)
        .find_agent(org_id, &session.agent_definition_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .ok_or_else(|| not_found(context, "agent_not_found"))?;
    if agent.lifecycle != "active"
        || agent
            .project_id
            .as_deref()
            .is_some_and(|value| value != session.project_id.as_str())
    {
        return Err(not_found(context, "agent_not_found"));
    }
    if let Some(binding_id) = session.workspace_binding_id.as_deref() {
        ProjectRepository::new(database)
            .find_binding(binding_id)
            .await
            .map_err(|_| service_unavailable(context))?
            .filter(|binding| {
                binding.org_id == org_id
                    && binding.project_id == session.project_id
                    && binding.device_id == session.device_id
            })
            .ok_or_else(|| not_found(context, "workspace_binding_not_found"))?;
    }
    let alias = if requested_mode == Some("local_only") {
        requested_alias
            .map(|value| validate_model_alias(context, value))
            .transpose()?
    } else {
        requested_alias
            .or(agent.default_model_alias.as_deref())
            .map(|value| validate_model_alias(context, value))
            .transpose()?
    };
    let mode = match requested_mode {
        Some("managed") => "managed".to_owned(),
        Some("local_only") => {
            if alias.is_some() {
                return Err(validation_error(
                    context,
                    "execution_mode_invalid",
                    "A local-only run cannot select a managed model alias.",
                ));
            }
            "local_only".to_owned()
        }
        Some(_) => {
            return Err(validation_error(
                context,
                "execution_mode_invalid",
                "The execution mode is invalid.",
            ));
        }
        None if alias.is_some() => "managed".to_owned(),
        None => "local_only".to_owned(),
    };
    let mut route_id = None;
    let mut route_version_id = None;
    let mut policy_snapshot_id = None;
    let mut policy_version = None;
    if mode == "managed" {
        let alias = alias.as_deref().ok_or_else(|| {
            validation_error(
                context,
                "model_alias_required",
                "A managed run requires a model alias.",
            )
        })?;
        let policy = AiRepository::new(database)
            .find_policy(org_id)
            .await
            .map_err(|error| database_error(context, error))?
            .ok_or_else(|| policy_denial(context, "model_not_allowed"))?;
        let allowed = serde_json::from_str::<Vec<String>>(&policy.allowed_aliases_json)
            .map_err(|_| policy_denial(context, "model_not_allowed"))?;
        if !policy.managed_route_enabled || !allowed.iter().any(|value| value == alias) {
            return Err(policy_denial(context, "model_not_allowed"));
        }
        let snapshot = PolicyRepository::new(database)
            .latest_snapshot(org_id)
            .await
            .map_err(|error| database_error(context, error))?
            .ok_or_else(|| policy_denial(context, "policy_state_unavailable"))?;
        if snapshot.org_id.as_str() != org_id
            || snapshot.policy_version <= 0
            || snapshot.expires_at.as_str() <= context.received_at.as_str()
        {
            return Err(policy_denial(context, "policy_state_unavailable"));
        }
        let payload = serde_json::from_str::<Value>(&snapshot.payload)
            .map_err(|_| policy_denial(context, "policy_state_unavailable"))?;
        if !trusted_scope_matches(&payload, "project_id", &session.project_id)
            || !trusted_scope_matches(&payload, "device_id", &session.device_id)
        {
            return Err(policy_denial(context, "resource_scope_mismatch"));
        }
        let route = AiRepository::new(database)
            .find_route_by_alias(org_id, alias)
            .await
            .map_err(|error| database_error(context, error))?
            .filter(|route| route.lifecycle == "published")
            .ok_or_else(|| policy_denial(context, "model_not_allowed"))?;
        let version_id = route
            .active_version_id
            .as_deref()
            .ok_or_else(|| policy_denial(context, "model_not_allowed"))?;
        let version = AiRepository::new(database)
            .find_route_version(org_id, version_id)
            .await
            .map_err(|error| database_error(context, error))?
            .filter(|version| version.route_id == route.route_id && version.published_at.is_some())
            .ok_or_else(|| policy_denial(context, "model_not_allowed"))?;
        route_id = Some(route.route_id);
        route_version_id = Some(version.route_version_id);
        policy_snapshot_id = Some(snapshot.policy_id.clone());
        policy_version = Some(snapshot.policy_version);
    }
    Ok(RunScope {
        session,
        agent,
        project_id: project.project_id,
        device,
        model_alias: alias,
        route_id,
        route_version_id,
        policy_snapshot_id,
        policy_version,
        execution_mode: mode,
    })
}

async fn load_run_for_scope(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    context: &RequestContext,
    principal: &Principal,
    org_id: &str,
    run_id: &str,
) -> Result<(RunRecord, bool), ApiError> {
    let database = database(state, context)?;
    let run = RunRepository::new(database)
        .find_run(org_id, run_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .ok_or_else(|| not_found(context, "run_not_found"))?;
    let manager = can_manage_projects(state, headers, context, org_id).await;
    ensure_project_access(
        database,
        context,
        org_id,
        &run.project_id,
        principal.user_id.as_str(),
        manager,
    )
    .await?;
    Ok((run, manager))
}

#[worker::send]
pub async fn list_runs(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<RunListQuery>,
    Path(org_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::RunsRead,
        Some("run"),
        None,
    )
    .await?;
    let limit = page_limit(query.limit);
    let cursor = query
        .cursor
        .as_deref()
        .map(|raw| decode_page_cursor(raw, &context))
        .transpose()?;
    if let Some(state_value) = query.state.as_deref()
        && !valid_run_state(state_value)
    {
        return Err(validation_error(
            &context,
            "run_state_invalid",
            "The run state filter is invalid.",
        ));
    }
    let project_id = query
        .project_id
        .as_deref()
        .map(|value| validate_prefixed_id(&context, value, "prj", "project_id_invalid"))
        .transpose()?;
    let session_id = query
        .session_id
        .as_deref()
        .map(|value| validate_prefixed_id(&context, value, "rse", "session_id_invalid"))
        .transpose()?;
    let database = database(&state, &context)?;
    let manager = can_manage_projects(&state, &headers, &context, &org_id).await;
    if let Some(project_id) = project_id.as_deref() {
        ensure_project_access(
            database,
            &context,
            &org_id,
            project_id,
            access.principal.user_id.as_str(),
            manager,
        )
        .await?;
    }
    let mut records = RunRepository::new(database)
        .list_runs(
            &org_id,
            access.principal.user_id.as_str(),
            manager,
            project_id.as_deref(),
            session_id.as_deref(),
            query.state.as_deref(),
            cursor
                .as_ref()
                .map(|(created, id)| (created.as_str(), id.as_str())),
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
            .map(|record| encode_run_page_cursor(&record.created_at, &record.run_id))
    } else {
        None
    };
    let items: Vec<Value> = records.iter().map(run_json).collect();
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

fn encode_run_page_cursor(created_at: &str, id: &str) -> String {
    // Reuse the agent/session cursor codec so all P05 collections have the
    // same opaque, keyset-paginated representation.
    super::agents::encode_page_cursor(created_at, id)
}

#[worker::send]
pub async fn get_run(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, run_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::RunsRead,
        Some("run"),
        Some(&run_id),
    )
    .await?;
    let (run, _) = load_run_for_scope(
        &state,
        &headers,
        &context,
        &access.principal,
        &org_id,
        &run_id,
    )
    .await?;
    Ok((StatusCode::OK, Json(run_json(&run))).into_response())
}

#[worker::send]
pub async fn start_run(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<StartRunRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::RunsStart,
        Some("run"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let session_id = validate_prefixed_id(
        &context,
        &body.agent_session_id,
        "rse",
        "agent_session_id_invalid",
    )?;
    let model_alias = body
        .model_alias
        .as_deref()
        .map(|value| validate_model_alias(&context, value))
        .transpose()?;
    let input_ref = body
        .input_ref
        .as_deref()
        .map(|value| {
            validate_text(
                &context,
                value,
                2_048,
                "input_ref_invalid",
                "The input reference is invalid.",
            )
        })
        .transpose()?;
    // The control plane validates and fingerprints this reference with the
    // idempotency body, but never persists or emits its target contents.
    let _ = input_ref;
    let parent_id = body
        .parent_run_id
        .as_deref()
        .map(|value| validate_prefixed_id(&context, value, "run", "parent_run_id_invalid"))
        .transpose()?;
    let execution_mode = validate_execution_mode(&context, body.execution_mode.as_deref())?;
    let parent = if let Some(parent_id) = parent_id.as_deref() {
        let (parent, _) = load_run_for_scope(
            &state,
            &headers,
            &context,
            &access.principal,
            &org_id,
            parent_id,
        )
        .await?;
        if parent.agent_session_id != session_id || !retryable(&parent.state) {
            return Err(denied(
                &context,
                ApiErrorCode::Conflict,
                "run_retry_not_allowed",
                "The parent run cannot be retried.",
            ));
        }
        Some(parent)
    } else {
        None
    };
    let requested_alias = model_alias
        .as_deref()
        .or_else(|| parent.as_ref().and_then(|run| run.model_alias.as_deref()));
    let requested_mode = execution_mode.as_deref().or_else(|| {
        parent.as_ref().map(|run| {
            if run.model_alias.is_some() {
                "managed"
            } else {
                "local_only"
            }
        })
    });
    let scope = load_scope(
        &state,
        &headers,
        &context,
        &access.principal,
        &org_id,
        &session_id,
        requested_alias,
        requested_mode,
    )
    .await?;
    let body_value = serde_json::to_value(&body).map_err(|_| service_unavailable(&context))?;
    let mutation = prepare_mutation(
        database(&state, &context)?,
        &context,
        &access.principal,
        &org_id,
        &key,
        "POST",
        RUNS_PATH,
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };
    let database = database(&state, &context)?;
    let run_id = generated_id("run");
    let parent_assertion = if let Some(parent) = parent.as_ref() {
        Some(
            RunRepository::new(database)
                .assert_run_state_version_statement(
                    &parent.run_id,
                    &org_id,
                    parent.version,
                    &parent.state,
                )
                .map_err(|error| database_error(&context, error))?,
        )
    } else {
        None
    };
    let attempt = if let Some(parent) = parent.as_ref() {
        RunRepository::new(database)
            .max_attempt(&org_id, &parent.run_id)
            .await
            .map_err(|error| database_error(&context, error))?
            .checked_add(1)
            .ok_or_else(|| {
                denied(
                    &context,
                    ApiErrorCode::Conflict,
                    "run_attempt_overflow",
                    "The run attempt limit has been reached.",
                )
            })?
    } else {
        1
    };
    let retry_attempt_assertion = parent
        .as_ref()
        .map(|parent| {
            RunRepository::new(database)
                .assert_retry_attempt_absent_statement(&org_id, &parent.run_id, attempt)
                .map_err(|error| database_error(&context, error))
        })
        .transpose()?;
    let record = RunRecord {
        run_id: run_id.clone(),
        org_id: org_id.clone(),
        project_id: scope.project_id.clone(),
        agent_session_id: scope.session.agent_session_id.clone(),
        parent_run_id: parent.as_ref().map(|run| run.run_id.clone()),
        attempt,
        agent_definition_id: scope.agent.agent_definition_id.clone(),
        agent_definition_version: scope.session.agent_definition_version,
        principal_user_id: access.principal.user_id.as_str().to_owned(),
        device_id: scope.device.device_id.clone(),
        model_alias: scope.model_alias.clone(),
        route_id: scope.route_id.clone(),
        route_version_id: scope.route_version_id.clone(),
        state_version: 1,
        cancel_requested_at: None,
        resumed_from_run_id: None,
        workspace_binding_id: scope.session.workspace_binding_id.clone(),
        policy_snapshot_id: scope.policy_snapshot_id.clone(),
        policy_version: scope.policy_version,
        state: "queued".to_owned(),
        failure_code: None,
        request_id: Some(context.request_id.as_str().to_owned()),
        started_at: None,
        finished_at: None,
        version: 1,
        created_at: context.received_at.as_str().to_owned(),
        updated_at: context.received_at.as_str().to_owned(),
    };
    let insert = RunRepository::new(database)
        .insert_run_statement(&crate::repositories::NewRunInput {
            run_id: &record.run_id,
            org_id: &record.org_id,
            project_id: &record.project_id,
            agent_session_id: &record.agent_session_id,
            parent_run_id: record.parent_run_id.as_deref(),
            attempt: record.attempt,
            agent_definition_id: &record.agent_definition_id,
            agent_definition_version: record.agent_definition_version,
            principal_user_id: &record.principal_user_id,
            device_id: &record.device_id,
            model_alias: record.model_alias.as_deref(),
            route_id: record.route_id.as_deref(),
            route_version_id: record.route_version_id.as_deref(),
            resumed_from_run_id: record.resumed_from_run_id.as_deref(),
            workspace_binding_id: record.workspace_binding_id.as_deref(),
            policy_snapshot_id: record.policy_snapshot_id.as_deref(),
            policy_version: record.policy_version,
            request_id: context.request_id.as_str(),
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let created_event_id = generated_id("rev");
    let created_payload = json!({
        "agent_session_id": record.agent_session_id,
        "project_id": record.project_id,
        "device_id": record.device_id,
        "agent_definition_id": record.agent_definition_id,
        "agent_definition_version": record.agent_definition_version,
        "model_alias": record.model_alias,
        "route_id": record.route_id,
        "route_version_id": record.route_version_id,
        "workspace_binding_id": record.workspace_binding_id,
        "policy_snapshot_id": record.policy_snapshot_id,
        "policy_version": scope.policy_version,
        "state_version": record.state_version,
        "execution_mode": scope.execution_mode,
        "input_ref_present": body.input_ref.is_some(),
        "dispatch_signal": "queued",
    });
    let created_event = run_event_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        &run_id,
        &created_event_id,
        1,
        "run.created.v1",
        &created_payload,
    )?;
    let mut writes = Vec::with_capacity(5);
    if let Some(parent_assertion) = parent_assertion {
        writes.push(parent_assertion);
    }
    if let Some(retry_attempt_assertion) = retry_attempt_assertion {
        writes.push(retry_attempt_assertion);
    }
    writes.push(insert);
    writes.push(created_event);
    let event_type = if parent.is_some() {
        writes.push(run_event_statement(
            database,
            &context,
            &access.principal,
            &org_id,
            &run_id,
            &generated_id("rev"),
            2,
            "run.retried.v1",
            &json!({
                "parent_run_id": parent.as_ref().map(|run| run.run_id.clone()),
                "attempt": record.attempt,
                "state_version": record.state_version,
                "execution_mode": scope.execution_mode,
            }),
        )?);
        "run.retried.v1"
    } else {
        "run.created.v1"
    };
    let security = run_security_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        Some(&record.device_id),
        Some(&record.run_id),
        Some(&record.agent_session_id),
        &generated_id("sec"),
        event_type,
        "run",
        &record.run_id,
        "success",
        &json!({
            "agent_session_id": record.agent_session_id,
            "project_id": record.project_id,
            "device_id": record.device_id,
            "parent_run_id": record.parent_run_id,
            "attempt": record.attempt,
            "execution_mode": scope.execution_mode,
            "policy_snapshot_id": record.policy_snapshot_id,
            "policy_version": scope.policy_version,
        }),
    )?;
    writes.push(security);
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        event_type,
        &json!({
            "run_id": record.run_id,
            "agent_session_id": record.agent_session_id,
            "project_id": record.project_id,
            "device_id": record.device_id,
            "parent_run_id": record.parent_run_id,
            "attempt": record.attempt,
            "execution_mode": scope.execution_mode,
            "dispatch_signal": "queued",
        }),
    )?;
    let success =
        StoredSuccess::new(201, run_json(&record)).map_err(|_| service_unavailable(&context))?;
    if let Some(replay) =
        commit_mutation(database, &context, claim, success.clone(), writes, outbox).await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::CREATED, Json(success.body)).into_response())
}

#[worker::send]
pub async fn cancel_run(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, run_id)): Path<(String, String)>,
    Json(body): Json<CancelRunRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::RunsCancel,
        Some("run"),
        Some(&run_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    if body.version <= 0 || body.version == i64::MAX {
        return Err(validation_error(
            &context,
            "version_invalid",
            "The resource version is invalid.",
        ));
    }
    let reason = body
        .reason
        .as_deref()
        .map(|value| {
            validate_text(
                &context,
                value,
                256,
                "cancel_reason_invalid",
                "The cancellation reason is invalid.",
            )
        })
        .transpose()?;
    let (run, _) = load_run_for_scope(
        &state,
        &headers,
        &context,
        &access.principal,
        &org_id,
        &run_id,
    )
    .await?;
    if run.state == "cancelled" {
        return Ok((StatusCode::OK, Json(run_json(&run))).into_response());
    }
    let current_state = RunState::parse(&run.state).ok_or_else(|| service_unavailable(&context))?;
    if current_state.is_terminal() {
        return Err(denied(
            &context,
            ApiErrorCode::Conflict,
            "run_terminal",
            "The run is already terminal.",
        ));
    }
    if !current_state.can_transition_to(RunState::Cancelled) {
        return Err(denied(
            &context,
            ApiErrorCode::Conflict,
            "run_cancel_not_allowed",
            "The run cannot be cancelled from its current state.",
        ));
    }
    if run.version != body.version {
        return Err(denied(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The run changed. Refresh and try again.",
        ));
    }
    let body_value = serde_json::to_value(&body).map_err(|_| service_unavailable(&context))?;
    let database = database(&state, &context)?;
    let mutation = prepare_mutation(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        "POST",
        &format!("/api/v1/orgs/{org_id}/runs/{run_id}/cancel"),
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };
    let update = RunRepository::new(database)
        .update_run_state_statement(
            &run_id,
            &org_id,
            "cancelled",
            Some("cancelled_by_user"),
            None,
            Some(context.received_at.as_str()),
            body.version,
            &run.state,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let assertion = RunRepository::new(database)
        .assert_run_state_version_statement(&run_id, &org_id, body.version, &run.state)
        .map_err(|error| database_error(&context, error))?;
    let sequence = RunRepository::new(database)
        .next_event_sequence(&org_id, &run_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    let next_state_version = run.state_version.checked_add(1).ok_or_else(|| {
        denied(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The run changed. Refresh and try again.",
        )
    })?;
    let event_payload = json!({
        "state": "cancelled",
        "previous_state": run.state,
        "state_version": next_state_version,
        "cancel_requested_at": context.received_at.as_str(),
        "device_id": run.device_id,
        "reason_present": reason.is_some(),
        "execution_host_signal": "cancel",
        "dispatch_signal": "cancel",
    });
    let event = run_event_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        &run_id,
        &generated_id("rev"),
        sequence,
        "run.cancelled.v1",
        &event_payload,
    )?;
    let security = run_security_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        Some(&run.device_id),
        Some(&run_id),
        Some(&run.agent_session_id),
        &generated_id("sec"),
        "run.cancelled.v1",
        "run",
        &run_id,
        "success",
        &json!({
            "agent_session_id": run.agent_session_id,
            "device_id": run.device_id,
            "version": body.version + 1,
        }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "run.cancelled.v1",
        &json!({
            "run_id": run_id,
            "agent_session_id": run.agent_session_id,
            "device_id": run.device_id,
            "execution_host_signal": "cancel",
        }),
    )?;
    let cancelled = RunRecord {
        state: "cancelled".to_owned(),
        failure_code: Some("cancelled_by_user".to_owned()),
        finished_at: Some(context.received_at.as_str().to_owned()),
        version: body.version + 1,
        state_version: next_state_version,
        cancel_requested_at: Some(
            run.cancel_requested_at
                .clone()
                .unwrap_or_else(|| context.received_at.as_str().to_owned()),
        ),
        updated_at: context.received_at.as_str().to_owned(),
        ..run
    };
    let success =
        StoredSuccess::new(200, run_json(&cancelled)).map_err(|_| service_unavailable(&context))?;
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![assertion, update, event, security],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::OK, Json(success.body)).into_response())
}

#[worker::send]
pub async fn retry_run(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, run_id)): Path<(String, String)>,
    Json(body): Json<RetryRunRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::RunsStart,
        Some("run"),
        Some(&run_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    if body.version <= 0 || body.version == i64::MAX {
        return Err(validation_error(
            &context,
            "version_invalid",
            "The resource version is invalid.",
        ));
    }
    let (parent, _) = load_run_for_scope(
        &state,
        &headers,
        &context,
        &access.principal,
        &org_id,
        &run_id,
    )
    .await?;
    if !retryable(&parent.state) {
        return Err(denied(
            &context,
            ApiErrorCode::Conflict,
            "run_retry_not_allowed",
            "The run cannot be retried from its current state.",
        ));
    }
    if parent.version != body.version {
        return Err(denied(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The run changed. Refresh and try again.",
        ));
    }
    let scope = load_scope(
        &state,
        &headers,
        &context,
        &access.principal,
        &org_id,
        &parent.agent_session_id,
        parent.model_alias.as_deref(),
        if parent.model_alias.is_some() {
            Some("managed")
        } else {
            Some("local_only")
        },
    )
    .await?;
    let body_value = serde_json::to_value(&body).map_err(|_| service_unavailable(&context))?;
    let database = database(&state, &context)?;
    let mutation = prepare_mutation(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        "POST",
        &format!("/api/v1/orgs/{org_id}/runs/{run_id}/retry"),
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };
    let new_run_id = generated_id("run");
    let parent_assertion = RunRepository::new(database)
        .assert_run_state_version_statement(&run_id, &org_id, parent.version, &parent.state)
        .map_err(|error| database_error(&context, error))?;
    let attempt = RunRepository::new(database)
        .max_attempt(&org_id, &run_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .checked_add(1)
        .ok_or_else(|| {
            denied(
                &context,
                ApiErrorCode::Conflict,
                "run_attempt_overflow",
                "The run attempt limit has been reached.",
            )
        })?;
    let retry_attempt_assertion = RunRepository::new(database)
        .assert_retry_attempt_absent_statement(&org_id, &run_id, attempt)
        .map_err(|error| database_error(&context, error))?;
    let record = RunRecord {
        run_id: new_run_id.clone(),
        org_id: org_id.clone(),
        project_id: scope.project_id.clone(),
        agent_session_id: scope.session.agent_session_id.clone(),
        parent_run_id: Some(parent.run_id.clone()),
        attempt,
        agent_definition_id: scope.agent.agent_definition_id.clone(),
        agent_definition_version: scope.session.agent_definition_version,
        principal_user_id: access.principal.user_id.as_str().to_owned(),
        device_id: scope.device.device_id.clone(),
        model_alias: scope.model_alias.clone(),
        route_id: scope.route_id.clone(),
        route_version_id: scope.route_version_id.clone(),
        state_version: 1,
        cancel_requested_at: None,
        resumed_from_run_id: None,
        workspace_binding_id: scope.session.workspace_binding_id.clone(),
        policy_snapshot_id: scope.policy_snapshot_id.clone(),
        policy_version: scope.policy_version,
        state: "queued".to_owned(),
        failure_code: None,
        request_id: Some(context.request_id.as_str().to_owned()),
        started_at: None,
        finished_at: None,
        version: 1,
        created_at: context.received_at.as_str().to_owned(),
        updated_at: context.received_at.as_str().to_owned(),
    };
    let insert = RunRepository::new(database)
        .insert_run_statement(&crate::repositories::NewRunInput {
            run_id: &record.run_id,
            org_id: &record.org_id,
            project_id: &record.project_id,
            agent_session_id: &record.agent_session_id,
            parent_run_id: record.parent_run_id.as_deref(),
            attempt: record.attempt,
            agent_definition_id: &record.agent_definition_id,
            agent_definition_version: record.agent_definition_version,
            principal_user_id: &record.principal_user_id,
            device_id: &record.device_id,
            model_alias: record.model_alias.as_deref(),
            route_id: record.route_id.as_deref(),
            route_version_id: record.route_version_id.as_deref(),
            resumed_from_run_id: record.resumed_from_run_id.as_deref(),
            workspace_binding_id: record.workspace_binding_id.as_deref(),
            policy_snapshot_id: record.policy_snapshot_id.as_deref(),
            policy_version: record.policy_version,
            request_id: context.request_id.as_str(),
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let created_event = run_event_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        &record.run_id,
        &generated_id("rev"),
        1,
        "run.created.v1",
        &json!({
            "agent_session_id": record.agent_session_id,
            "project_id": record.project_id,
            "device_id": record.device_id,
            "workspace_binding_id": record.workspace_binding_id,
            "policy_snapshot_id": record.policy_snapshot_id,
            "policy_version": record.policy_version,
            "parent_run_id": parent.run_id,
            "attempt": record.attempt,
            "state_version": record.state_version,
            "execution_mode": scope.execution_mode,
            "dispatch_signal": "queued",
        }),
    )?;
    let retry_event = run_event_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        &record.run_id,
        &generated_id("rev"),
        2,
        "run.retried.v1",
        &json!({
            "parent_run_id": parent.run_id,
            "attempt": record.attempt,
            "state_version": record.state_version,
            "workspace_binding_id": record.workspace_binding_id,
            "policy_snapshot_id": record.policy_snapshot_id,
            "policy_version": record.policy_version,
            "execution_mode": scope.execution_mode,
        }),
    )?;
    let security = run_security_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        Some(&record.device_id),
        Some(&record.run_id),
        Some(&record.agent_session_id),
        &generated_id("sec"),
        "run.retried.v1",
        "run",
        &record.run_id,
        "success",
        &json!({
            "parent_run_id": parent.run_id,
            "agent_session_id": record.agent_session_id,
            "device_id": record.device_id,
            "attempt": record.attempt,
        }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "run.retried.v1",
        &json!({
            "run_id": record.run_id,
            "parent_run_id": parent.run_id,
            "agent_session_id": record.agent_session_id,
            "project_id": record.project_id,
            "device_id": record.device_id,
            "attempt": record.attempt,
            "dispatch_signal": "queued",
        }),
    )?;
    let success =
        StoredSuccess::new(201, run_json(&record)).map_err(|_| service_unavailable(&context))?;
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![
            parent_assertion,
            retry_attempt_assertion,
            insert,
            created_event,
            retry_event,
            security,
        ],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::CREATED, Json(success.body)).into_response())
}

#[worker::send]
pub async fn list_run_events(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<RunEventQuery>,
    Path((org_id, run_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::RunsRead,
        Some("run"),
        Some(&run_id),
    )
    .await?;
    let after_sequence = query.after_sequence.unwrap_or(0);
    if after_sequence < 0 {
        return Err(validation_error(
            &context,
            "after_sequence_invalid",
            "The event sequence is invalid.",
        ));
    }
    let cursor = query
        .cursor
        .as_deref()
        .map(|raw| decode_page_cursor(raw, &context))
        .transpose()?
        .map(|(sequence, event_id)| {
            let sequence = sequence.parse::<i64>().map_err(|_| {
                validation_error(&context, "cursor_invalid", "The cursor is invalid.")
            })?;
            if sequence <= 0 {
                return Err(validation_error(
                    &context,
                    "cursor_invalid",
                    "The cursor is invalid.",
                ));
            }
            Ok((sequence, event_id))
        })
        .transpose()?;
    let (run, _) = load_run_for_scope(
        &state,
        &headers,
        &context,
        &access.principal,
        &org_id,
        &run_id,
    )
    .await?;
    let limit = page_limit(query.limit);
    let database = database(&state, &context)?;
    let mut events = RunRepository::new(database)
        .list_events(
            &org_id,
            &run.run_id,
            after_sequence,
            cursor
                .as_ref()
                .map(|(sequence, id)| (*sequence, id.as_str())),
            limit + 1,
        )
        .await
        .map_err(|error| database_error(&context, error))?;
    let has_more = events.len() > limit as usize;
    if has_more {
        events.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        events.last().map(|event| {
            super::agents::encode_page_cursor(&event.sequence.to_string(), &event.run_event_id)
        })
    } else {
        None
    };
    let items = events
        .iter()
        .map(|event| event_json(&context, event))
        .collect::<Result<Vec<_>, _>>()?;
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
pub async fn create_artifact(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, run_id)): Path<(String, String)>,
    Json(body): Json<ArtifactRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::RunsStart,
        Some("run"),
        Some(&run_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    if !matches!(
        body.kind.as_str(),
        "local_only" | "cloud_uploaded" | "external_link"
    ) {
        return Err(validation_error(
            &context,
            "artifact_kind_invalid",
            "The artifact kind is invalid.",
        ));
    }
    let content_ref = body
        .content_ref
        .as_deref()
        .map(|value| {
            validate_text(
                &context,
                value,
                2_048,
                "artifact_content_ref_invalid",
                "The artifact reference is invalid.",
            )
        })
        .transpose()?;
    if body.kind == "local_only" && content_ref.is_some() {
        return Err(validation_error(
            &context,
            "artifact_content_ref_invalid",
            "A local-only artifact cannot have a content reference.",
        ));
    }
    if body.kind != "local_only" && content_ref.is_none() {
        return Err(validation_error(
            &context,
            "artifact_content_ref_required",
            "A remote artifact requires a content reference.",
        ));
    }
    let mime_type = body
        .mime_type
        .as_deref()
        .map(|value| {
            validate_text(
                &context,
                value,
                160,
                "artifact_mime_type_invalid",
                "The artifact MIME type is invalid.",
            )
        })
        .transpose()?;
    if body
        .size_bytes
        .is_some_and(|value| !(0..=10_000_000_000).contains(&value))
    {
        return Err(validation_error(
            &context,
            "artifact_size_invalid",
            "The artifact size is invalid.",
        ));
    }
    let checksum = body
        .checksum
        .as_deref()
        .map(|value| {
            validate_text(
                &context,
                value,
                256,
                "artifact_checksum_invalid",
                "The artifact checksum is invalid.",
            )
        })
        .transpose()?;
    let retention_policy = body
        .retention_policy
        .as_deref()
        .map(|value| {
            validate_text(
                &context,
                value,
                96,
                "artifact_retention_invalid",
                "The artifact retention policy is invalid.",
            )
        })
        .transpose()?
        .unwrap_or_else(|| "organization_default".to_owned());
    let (run, _) = load_run_for_scope(
        &state,
        &headers,
        &context,
        &access.principal,
        &org_id,
        &run_id,
    )
    .await?;
    let body_value = serde_json::to_value(&body).map_err(|_| service_unavailable(&context))?;
    let database = database(&state, &context)?;
    let mutation = prepare_mutation(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        "POST",
        &format!("/api/v1/orgs/{org_id}/runs/{run_id}/artifacts"),
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };
    let artifact_id = generated_id("art");
    let artifact = ArtifactRefRecord {
        artifact_ref_id: artifact_id.clone(),
        org_id: org_id.clone(),
        project_id: run.project_id.clone(),
        run_id: run.run_id.clone(),
        kind: body.kind.clone(),
        content_ref: content_ref.clone(),
        mime_type: mime_type.clone(),
        size_bytes: body.size_bytes,
        checksum: checksum.clone(),
        retention_policy: retention_policy.clone(),
        created_by_user_id: access.principal.user_id.as_str().to_owned(),
        created_at: context.received_at.as_str().to_owned(),
    };
    let insert = RunRepository::new(database)
        .insert_artifact_statement(&crate::repositories::NewArtifactRefInput {
            artifact_ref_id: &artifact.artifact_ref_id,
            org_id: &artifact.org_id,
            project_id: &artifact.project_id,
            run_id: &artifact.run_id,
            kind: &artifact.kind,
            content_ref: artifact.content_ref.as_deref(),
            mime_type: artifact.mime_type.as_deref(),
            size_bytes: artifact.size_bytes,
            checksum: artifact.checksum.as_deref(),
            retention_policy: &artifact.retention_policy,
            created_by_user_id: &artifact.created_by_user_id,
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let sequence = RunRepository::new(database)
        .next_event_sequence(&org_id, &run.run_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    let event = run_event_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        &run.run_id,
        &generated_id("rev"),
        sequence,
        "artifact.created.v1",
        &json!({
            "artifact_id": artifact.artifact_ref_id,
            "kind": artifact.kind,
            "mime_type": artifact.mime_type,
            "size_bytes": artifact.size_bytes,
        }),
    )?;
    let security = run_security_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        Some(&run.device_id),
        Some(&run_id),
        Some(&run.agent_session_id),
        &generated_id("sec"),
        "artifact.created.v1",
        "artifact",
        &artifact.artifact_ref_id,
        "success",
        &json!({
            "run_id": run.run_id,
            "kind": artifact.kind,
            "size_bytes": artifact.size_bytes,
        }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "artifact.created.v1",
        &json!({
            "artifact_id": artifact.artifact_ref_id,
            "run_id": run.run_id,
            "project_id": run.project_id,
            "kind": artifact.kind,
        }),
    )?;
    let success = StoredSuccess::new(201, artifact_json(&artifact))
        .map_err(|_| service_unavailable(&context))?;
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![insert, event, security],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::CREATED, Json(success.body)).into_response())
}

#[worker::send]
pub async fn list_artifacts(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<RunEventQuery>,
    Path((org_id, run_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::RunsRead,
        Some("run"),
        Some(&run_id),
    )
    .await?;
    let (run, _) = load_run_for_scope(
        &state,
        &headers,
        &context,
        &access.principal,
        &org_id,
        &run_id,
    )
    .await?;
    let cursor = query
        .cursor
        .as_deref()
        .map(|raw| decode_page_cursor(raw, &context))
        .transpose()?;
    let limit = page_limit(query.limit);
    let database = database(&state, &context)?;
    let mut artifacts = RunRepository::new(database)
        .list_artifacts(
            &org_id,
            &run.run_id,
            cursor
                .as_ref()
                .map(|(created, id)| (created.as_str(), id.as_str())),
            limit + 1,
        )
        .await
        .map_err(|error| database_error(&context, error))?;
    let has_more = artifacts.len() > limit as usize;
    if has_more {
        artifacts.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        artifacts.last().map(|artifact| {
            super::agents::encode_page_cursor(&artifact.created_at, &artifact.artifact_ref_id)
        })
    } else {
        None
    };
    let items: Vec<Value> = artifacts.iter().map(artifact_json).collect();
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
