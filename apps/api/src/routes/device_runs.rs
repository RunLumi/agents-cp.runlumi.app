//! Device-token P05 run lifecycle.
//!
//! The device token is the only identity accepted by this module.  The
//! organization, project, enrolled principal, workspace binding, agent
//! definition, and policy context are resolved from server-owned rows before a
//! device can create or transition work.  The Worker does not execute local
//! tools or provider calls here; it records the managed lifecycle for the
//! desktop/runtime host.

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
    app::AppState,
    core::{ApiError, ApiErrorCode, RequestContext, StoredSuccess},
    modules::runs::RunState,
    repositories::{
        AgentSessionRecord, DeviceRecord, NewAgentSessionInput, NewRunEventInput, NewRunInput,
        ProjectRepository, RunRecord, RunRepository, WorkspaceBindingRecord,
    },
    routes::{
        agents::{decode_page_cursor, generated_id, page_limit, validation_error},
        authorization::DeviceAccess,
        authorization::authorize_device,
        support::{
            database, database_error, idempotency_key, outbox_statement,
            security_event_statement_with_context,
        },
        usage::{ScopedMutationCommit, commit_scoped_mutation, prepare_scoped_mutation},
    },
};

pub const DEVICE_SESSIONS_PATH: &str = "/api/v1/devices/sessions";
pub const DEVICE_SESSION_RUNS_PATH: &str = "/api/v1/devices/sessions/{agent_session_id}/runs";
#[allow(dead_code)]
pub const DEVICE_RUN_PATH: &str = "/api/v1/devices/runs/{run_id}";
#[allow(dead_code)]
pub const DEVICE_RUN_EVENTS_PATH: &str = "/api/v1/devices/runs/{run_id}/events";
#[allow(dead_code)]
pub const DEVICE_RUN_START_PATH: &str = "/api/v1/devices/runs/{run_id}/start";
#[allow(dead_code)]
pub const DEVICE_RUN_COMPLETE_PATH: &str = "/api/v1/devices/runs/{run_id}/complete";
#[allow(dead_code)]
pub const DEVICE_RUN_FAIL_PATH: &str = "/api/v1/devices/runs/{run_id}/fail";
#[allow(dead_code)]
pub const DEVICE_RUN_CANCEL_PATH: &str = "/api/v1/devices/runs/{run_id}/cancel";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDeviceSessionRequest {
    pub project_id: String,
    pub agent_definition_id: String,
    pub workspace_binding_id: Option<String>,
    pub external_id: Option<String>,
    pub title: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDeviceRunRequest {
    pub model_alias: Option<String>,
    pub input_ref: Option<String>,
    pub parent_run_id: Option<String>,
    pub execution_mode: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceVersionRequest {
    pub version: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceTerminalRequest {
    pub version: i64,
    pub failure_code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceEventQuery {
    pub limit: Option<i32>,
    pub after_sequence: Option<i64>,
    pub cursor: Option<String>,
}

fn service_unavailable(context: &RequestContext) -> ApiError {
    crate::routes::errors::api_error(
        context,
        ApiErrorCode::ServiceUnavailable,
        "The run store is unavailable.",
    )
}

fn denied(context: &RequestContext, reason: &str, message: &str) -> ApiError {
    crate::routes::errors::api_error(context, ApiErrorCode::PermissionDenied, message)
        .with_detail("reason", json!(reason))
}

fn conflict(context: &RequestContext, reason: &str, message: &str) -> ApiError {
    crate::routes::errors::api_error(context, ApiErrorCode::Conflict, message)
        .with_detail("reason", json!(reason))
}

fn validate_version(context: &RequestContext, value: i64) -> Result<(), ApiError> {
    if value <= 0 || value == i64::MAX {
        return Err(validation_error(
            context,
            "version_invalid",
            "The run version is invalid.",
        ));
    }
    Ok(())
}

fn session_json(session: &AgentSessionRecord) -> Value {
    json!({
        "id": session.agent_session_id,
        "agent_session_id": session.agent_session_id,
        "org_id": session.org_id,
        "project_id": session.project_id,
        "device_id": session.device_id,
        "workspace_binding_id": session.workspace_binding_id,
        "agent_definition_id": session.agent_definition_id,
        "agent_definition_version": session.agent_definition_version,
        "external_id": session.external_id,
        "title": session.title,
        "lifecycle": session.lifecycle,
        "version": session.version,
        "created_at": session.created_at,
        "updated_at": session.updated_at,
    })
}

async fn ensure_project_binding(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    access: &DeviceAccess,
    project_id: &str,
    workspace_binding_id: Option<&str>,
) -> Result<crate::repositories::ProjectRecord, ApiError> {
    let projects = ProjectRepository::new(database);
    let project = projects
        .find_project(project_id)
        .await
        .map_err(|error| database_error(context, error))?
        .ok_or_else(|| {
            denied(
                context,
                "project_access_denied",
                "The project is not available.",
            )
        })?;
    if project.org_id != access.device.org_id || project.archived_at.is_some() {
        return Err(denied(
            context,
            "project_access_denied",
            "The project is not available.",
        ));
    }
    if project.visibility == "restricted"
        && !projects
            .member_has_explicit_grant(
                project_id,
                &access.device.org_id,
                &access.device.enrolled_by_user_id,
            )
            .await
            .map_err(|error| database_error(context, error))?
    {
        return Err(denied(
            context,
            "project_access_denied",
            "The project is not available.",
        ));
    }
    if let Some(binding_id) = workspace_binding_id {
        let binding = projects
            .find_binding(binding_id)
            .await
            .map_err(|error| database_error(context, error))?
            .ok_or_else(|| {
                denied(
                    context,
                    "workspace_binding_required",
                    "The workspace binding is not available.",
                )
            })?;
        ensure_binding_matches(context, &binding, &access.device, project_id)?;
    }
    Ok(project)
}

fn ensure_binding_matches(
    context: &RequestContext,
    binding: &WorkspaceBindingRecord,
    device: &DeviceRecord,
    project_id: &str,
) -> Result<(), ApiError> {
    if binding.org_id != device.org_id
        || binding.device_id != device.device_id
        || binding.project_id != project_id
    {
        return Err(denied(
            context,
            "workspace_binding_mismatch",
            "The workspace binding is not valid.",
        ));
    }
    Ok(())
}

async fn ensure_agent(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    org_id: &str,
    agent_id: &str,
    project_id: &str,
) -> Result<crate::repositories::AgentDefinitionRecord, ApiError> {
    let agent = RunRepository::new(database)
        .find_agent(org_id, agent_id)
        .await
        .map_err(|error| database_error(context, error))?
        .ok_or_else(|| {
            denied(
                context,
                "agent_not_found",
                "The agent definition is not available.",
            )
        })?;
    if agent.lifecycle != "active"
        || agent
            .project_id
            .as_deref()
            .is_some_and(|value| value != project_id)
    {
        return Err(denied(
            context,
            "agent_not_found",
            "The agent definition is not available.",
        ));
    }
    Ok(agent)
}

async fn find_device_session(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    access: &DeviceAccess,
    session_id: &str,
) -> Result<AgentSessionRecord, ApiError> {
    let session = RunRepository::new(database)
        .find_session(&access.device.org_id, session_id)
        .await
        .map_err(|error| database_error(context, error))?
        .ok_or_else(|| {
            denied(
                context,
                "session_not_found",
                "The agent session is not available.",
            )
        })?;
    if session.device_id != access.device.device_id {
        return Err(denied(
            context,
            "session_not_found",
            "The agent session is not available.",
        ));
    }
    if session.lifecycle != "active" {
        return Err(conflict(
            context,
            "session_closed",
            "The agent session is closed.",
        ));
    }
    Ok(session)
}

fn event_statement(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    run: &RunRecord,
    sequence: i64,
    event_type: &str,
    payload: &Value,
) -> Result<D1PreparedStatement, ApiError> {
    RunRepository::new(database)
        .insert_event_statement_for_org(
            &run.org_id,
            context.request_id.as_str(),
            &NewRunEventInput {
                run_event_id: &generated_id("rev"),
                run_id: &run.run_id,
                sequence,
                event_type,
                occurred_at: &context.received_at,
                actor_type: "system",
                actor_id: None,
                correlation_id: context.correlation_id.as_str(),
                tool_call_id: None,
                approval_id: None,
                payload,
            },
        )
        .map_err(|error| database_error(context, error))
}

fn device_audit(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    access: &DeviceAccess,
    run: Option<&RunRecord>,
    action: &str,
    resource_id: &str,
    payload: &Value,
) -> Result<D1PreparedStatement, ApiError> {
    security_event_statement_with_context(
        database,
        context,
        None,
        Some(&access.device.org_id),
        &generated_id("sec"),
        action,
        "run",
        Some(resource_id),
        "success",
        payload,
        Some(&access.device.device_id),
        run.map(|value| value.run_id.as_str()),
        run.map(|value| value.agent_session_id.as_str()),
        None,
    )
}

fn device_outbox(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    access: &DeviceAccess,
    _run: &RunRecord,
    event_type: &str,
    payload: &Value,
) -> Result<D1PreparedStatement, ApiError> {
    outbox_statement(
        database,
        context,
        None,
        Some(&access.device.org_id),
        event_type,
        payload,
    )
}

#[allow(clippy::too_many_arguments)]
async fn commit_device_mutation(
    state: &Arc<AppState>,
    context: &RequestContext,
    access: &DeviceAccess,
    key: &str,
    method: &str,
    path: &str,
    body: &Value,
    writes: Vec<D1PreparedStatement>,
    outbox: D1PreparedStatement,
    status: StatusCode,
    response: Value,
) -> Result<Response<Body>, ApiError> {
    let database = database(state, context)?;
    let claim = match prepare_scoped_mutation(
        database,
        context,
        &access.device.device_id,
        &access.device.org_id,
        key,
        method,
        path,
        body,
    )
    .await?
    {
        crate::routes::usage::PreparedScopedMutation::Replay(success) => {
            return Ok(crate::routes::agents::replay_response(success));
        }
        crate::routes::usage::PreparedScopedMutation::Claim(claim) => claim,
    };
    let success = StoredSuccess::new(status.as_u16(), response.clone())
        .map_err(|_| service_unavailable(context))?;
    match commit_scoped_mutation(database, context, claim, success, writes, outbox).await? {
        ScopedMutationCommit::Replayed(success) => {
            Ok(crate::routes::agents::replay_response(success))
        }
        ScopedMutationCommit::Committed => Ok((status, Json(response)).into_response()),
        ScopedMutationCommit::Guarded => Err(conflict(
            context,
            "version_conflict",
            "The run changed. Refresh and try again.",
        )),
    }
}

#[worker::send]
pub async fn create_session(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<CreateDeviceSessionRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_device(&state, &headers, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let project_id = crate::routes::agents::validate_prefixed_id(
        &context,
        &body.project_id,
        "prj",
        "project_id_invalid",
    )?;
    let agent_id = crate::routes::agents::validate_prefixed_id(
        &context,
        &body.agent_definition_id,
        "agd",
        "agent_id_invalid",
    )?;
    let workspace_binding_id = body
        .workspace_binding_id
        .as_deref()
        .map(|value| {
            crate::routes::agents::validate_prefixed_id(
                &context,
                value,
                "wsb",
                "workspace_binding_id_invalid",
            )
        })
        .transpose()?;
    let database = database(&state, &context)?;
    let project = ensure_project_binding(
        &context,
        database,
        &access,
        &project_id,
        workspace_binding_id.as_deref(),
    )
    .await?;
    let agent = ensure_agent(
        &context,
        database,
        &access.device.org_id,
        &agent_id,
        &project.project_id,
    )
    .await?;
    let external_id = body
        .external_id
        .as_deref()
        .map(|value| {
            crate::routes::agents::validate_text(
                &context,
                value,
                256,
                "external_id_invalid",
                "The external session ID is invalid.",
            )
        })
        .transpose()?;
    let title = body
        .title
        .as_deref()
        .map(|value| {
            crate::routes::agents::validate_text(
                &context,
                value,
                200,
                "title_invalid",
                "The session title is invalid.",
            )
        })
        .transpose()?;
    let body_value = serde_json::to_value(&body).map_err(|_| service_unavailable(&context))?;
    let session_id = generated_id("rse");
    let session = AgentSessionRecord {
        agent_session_id: session_id.clone(),
        org_id: access.device.org_id.clone(),
        project_id: project.project_id.clone(),
        device_id: access.device.device_id.clone(),
        workspace_binding_id,
        agent_definition_id: agent.agent_definition_id.clone(),
        agent_definition_version: agent.version,
        external_id,
        title,
        lifecycle: "active".into(),
        version: 1,
        created_by_user_id: access.device.enrolled_by_user_id.clone(),
        created_at: context.received_at.as_str().into(),
        updated_at: context.received_at.as_str().into(),
    };
    let insert = RunRepository::new(database)
        .insert_session_statement(
            &NewAgentSessionInput {
                agent_session_id: &session.agent_session_id,
                org_id: &session.org_id,
                project_id: &session.project_id,
                device_id: &session.device_id,
                workspace_binding_id: session.workspace_binding_id.as_deref(),
                agent_definition_id: &session.agent_definition_id,
                agent_definition_version: session.agent_definition_version,
                external_id: session.external_id.as_deref(),
                title: session.title.as_deref(),
                created_by_user_id: &session.created_by_user_id,
            },
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let audit = security_event_statement_with_context(
        database,
        &context,
        None,
        Some(&access.device.org_id),
        &generated_id("sec"),
        "session.created.v1",
        "session",
        Some(&session_id),
        "success",
        &json!({"project_id": project.project_id, "agent_definition_id": agent.agent_definition_id}),
        Some(&access.device.device_id),
        None,
        Some(&session_id),
        None,
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        None,
        Some(&access.device.org_id),
        "session.created.v1",
        &json!({"agent_session_id": session_id, "device_id": access.device.device_id}),
    )?;
    commit_device_mutation(
        &state,
        &context,
        &access,
        &key,
        "POST",
        DEVICE_SESSIONS_PATH,
        &body_value,
        vec![insert, audit],
        outbox,
        StatusCode::CREATED,
        session_json(&session),
    )
    .await
}

#[worker::send]
pub async fn create_run(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Json(body): Json<CreateDeviceRunRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_device(&state, &headers, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let session_id = crate::routes::agents::validate_prefixed_id(
        &context,
        &session_id,
        "rse",
        "agent_session_id_invalid",
    )?;
    let database = database(&state, &context)?;
    let session = find_device_session(&context, database, &access, &session_id).await?;
    let project = ensure_project_binding(
        &context,
        database,
        &access,
        &session.project_id,
        session.workspace_binding_id.as_deref(),
    )
    .await?;
    let agent = ensure_agent(
        &context,
        database,
        &access.device.org_id,
        &session.agent_definition_id,
        &project.project_id,
    )
    .await?;
    let parent = if let Some(parent_id) = body.parent_run_id.as_deref() {
        let parent_id = crate::routes::agents::validate_prefixed_id(
            &context,
            parent_id,
            "run",
            "parent_run_id_invalid",
        )?;
        let parent_run = RunRepository::new(database)
            .find_run(&access.device.org_id, &parent_id)
            .await
            .map_err(|error| database_error(&context, error))?
            .ok_or_else(|| {
                denied(
                    &context,
                    "run_not_found",
                    "The parent run is not available.",
                )
            })?;
        if parent_run.agent_session_id != session.agent_session_id
            || parent_run.device_id != access.device.device_id
            || !RunState::parse(&parent_run.state).is_some_and(RunState::is_retryable)
        {
            return Err(conflict(
                &context,
                "run_retry_not_allowed",
                "The parent run cannot be retried by this device.",
            ));
        }
        Some(parent_run)
    } else {
        None
    };
    let attempt = if let Some(parent_run) = parent.as_ref() {
        RunRepository::new(database)
            .max_attempt(&access.device.org_id, &parent_run.run_id)
            .await
            .map_err(|error| database_error(&context, error))?
            .saturating_add(1)
    } else {
        1
    };
    let execution_mode = body
        .execution_mode
        .as_deref()
        .unwrap_or(if body.model_alias.is_some() {
            "managed"
        } else {
            "local_only"
        });
    if !matches!(execution_mode, "managed" | "local_only") {
        return Err(validation_error(
            &context,
            "execution_mode_invalid",
            "The execution mode is invalid.",
        ));
    }
    let model_alias = body
        .model_alias
        .as_deref()
        .or(agent.default_model_alias.as_deref())
        .map(|value| crate::routes::agents::validate_model_alias(&context, value))
        .transpose()?;
    if execution_mode == "managed" && model_alias.is_none() {
        return Err(validation_error(
            &context,
            "model_alias_required",
            "A managed run requires a model alias.",
        ));
    }
    let model_alias = if execution_mode == "managed" {
        model_alias
    } else {
        None
    };
    let body_value = serde_json::to_value(&body).map_err(|_| service_unavailable(&context))?;
    let run_id = generated_id("run");
    let run = RunRecord {
        run_id: run_id.clone(),
        org_id: access.device.org_id.clone(),
        project_id: project.project_id.clone(),
        agent_session_id: session.agent_session_id.clone(),
        parent_run_id: parent.as_ref().map(|run| run.run_id.clone()),
        attempt,
        agent_definition_id: agent.agent_definition_id.clone(),
        agent_definition_version: agent.version,
        principal_user_id: access.device.enrolled_by_user_id.clone(),
        device_id: access.device.device_id.clone(),
        model_alias: model_alias.clone(),
        route_id: None,
        route_version_id: None,
        state: "queued".into(),
        failure_code: None,
        request_id: Some(context.request_id.as_str().into()),
        started_at: None,
        finished_at: None,
        version: 1,
        state_version: 1,
        cancel_requested_at: None,
        resumed_from_run_id: None,
        workspace_binding_id: session.workspace_binding_id.clone(),
        policy_snapshot_id: None,
        policy_version: None,
        created_at: context.received_at.as_str().into(),
        updated_at: context.received_at.as_str().into(),
    };
    let parent_assertion = parent
        .as_ref()
        .map(|parent| {
            RunRepository::new(database)
                .assert_run_state_version_statement(
                    &parent.run_id,
                    &access.device.org_id,
                    parent.version,
                    &parent.state,
                )
                .map_err(|error| database_error(&context, error))
        })
        .transpose()?;
    let attempt_assertion = parent
        .as_ref()
        .map(|parent| {
            RunRepository::new(database)
                .assert_retry_attempt_absent_statement(
                    &access.device.org_id,
                    &parent.run_id,
                    attempt,
                )
                .map_err(|error| database_error(&context, error))
        })
        .transpose()?;
    let insert = RunRepository::new(database)
        .insert_run_statement(&NewRunInput {
            run_id: &run.run_id,
            org_id: &run.org_id,
            project_id: &run.project_id,
            agent_session_id: &run.agent_session_id,
            parent_run_id: run.parent_run_id.as_deref(),
            attempt,
            agent_definition_id: &run.agent_definition_id,
            agent_definition_version: run.agent_definition_version,
            principal_user_id: &run.principal_user_id,
            device_id: &run.device_id,
            model_alias: run.model_alias.as_deref(),
            route_id: None,
            route_version_id: None,
            resumed_from_run_id: None,
            workspace_binding_id: run.workspace_binding_id.as_deref(),
            policy_snapshot_id: None,
            policy_version: None,
            request_id: context.request_id.as_str(),
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let run_event_type = if parent.is_some() {
        "run.retried.v1"
    } else {
        "run.created.v1"
    };
    let event = event_statement(
        &context,
        database,
        &run,
        1,
        run_event_type,
        &json!({"agent_session_id": run.agent_session_id, "device_id": run.device_id, "model_alias": run.model_alias, "execution_mode": execution_mode, "dispatch_signal": "queued", "attempt": run.attempt, "parent_run_id": run.parent_run_id}),
    )?;
    let audit = device_audit(
        &context,
        database,
        &access,
        Some(&run),
        run_event_type,
        &run.run_id,
        &json!({"agent_session_id": run.agent_session_id, "device_id": run.device_id, "execution_mode": execution_mode, "attempt": run.attempt, "parent_run_id": run.parent_run_id}),
    )?;
    let outbox = device_outbox(
        &context,
        database,
        &access,
        &run,
        run_event_type,
        &json!({"run_id": run.run_id, "agent_session_id": run.agent_session_id, "device_id": run.device_id, "dispatch_signal": "queued", "attempt": run.attempt, "parent_run_id": run.parent_run_id}),
    )?;
    commit_device_mutation(
        &state,
        &context,
        &access,
        &key,
        "POST",
        DEVICE_SESSION_RUNS_PATH,
        &body_value,
        {
            let mut writes = Vec::new();
            if let Some(parent_assertion) = parent_assertion {
                writes.push(parent_assertion);
            }
            if let Some(attempt_assertion) = attempt_assertion {
                writes.push(attempt_assertion);
            }
            writes.extend([insert, event, audit]);
            writes
        },
        outbox,
        StatusCode::CREATED,
        super::runs::run_json(&run),
    )
    .await
}

#[worker::send]
pub async fn get_run(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_device(&state, &headers, &context).await?;
    let run = RunRepository::new(database(&state, &context)?)
        .find_run(&access.device.org_id, &run_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| denied(&context, "run_not_found", "The run is not available."))?;
    if run.device_id != access.device.device_id {
        return Err(denied(
            &context,
            "run_not_found",
            "The run is not available.",
        ));
    }
    Ok(Json(super::runs::run_json(&run)).into_response())
}

#[worker::send]
pub async fn list_events(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
    Query(query): Query<DeviceEventQuery>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_device(&state, &headers, &context).await?;
    let run = RunRepository::new(database(&state, &context)?)
        .find_run(&access.device.org_id, &run_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| denied(&context, "run_not_found", "The run is not available."))?;
    if run.device_id != access.device.device_id {
        return Err(denied(
            &context,
            "run_not_found",
            "The run is not available.",
        ));
    }
    let limit = page_limit(query.limit);
    let cursor = query
        .cursor
        .as_deref()
        .map(|raw| decode_page_cursor(raw, &context))
        .transpose()?;
    let events = RunRepository::new(database(&state, &context)?)
        .list_events(
            &access.device.org_id,
            &run.run_id,
            query.after_sequence.unwrap_or(0),
            cursor.as_ref().map(|(_, b)| (1, b.as_str())),
            limit + 1,
        )
        .await
        .map_err(|error| database_error(&context, error))?;
    let has_more = events.len() > limit as usize;
    let items = events.into_iter().take(limit as usize).map(|event| json!({"id": event.run_event_id, "run_id": event.run_id, "sequence": event.sequence, "event_type": event.event_type, "occurred_at": event.occurred_at, "payload": serde_json::from_str::<Value>(&event.payload_json).unwrap_or_else(|_| json!({}))})).collect::<Vec<_>>();
    Ok(
        Json(json!({"items": items, "next_cursor": Value::Null, "has_more": has_more}))
            .into_response(),
    )
}

#[allow(dead_code, clippy::too_many_arguments)]
async fn transition(
    state: &Arc<AppState>,
    context: &RequestContext,
    access: &DeviceAccess,
    run_id: &str,
    version: i64,
    next_state: RunState,
    failure_code: Option<&str>,
    event_type: &str,
) -> Result<Response<Body>, ApiError> {
    validate_version(context, version)?;
    let database = database(state, context)?;
    let repository = RunRepository::new(database);
    let run = repository
        .find_run(&access.device.org_id, run_id)
        .await
        .map_err(|error| database_error(context, error))?
        .ok_or_else(|| denied(context, "run_not_found", "The run is not available."))?;
    if run.device_id != access.device.device_id {
        return Err(denied(
            context,
            "run_not_found",
            "The run is not available.",
        ));
    }
    let current = RunState::parse(&run.state).ok_or_else(|| service_unavailable(context))?;
    if current == RunState::Cancelled && next_state == RunState::Cancelled {
        return Ok(Json(super::runs::run_json(&run)).into_response());
    }
    if current.is_terminal() || !current.can_transition_to(next_state) || run.version != version {
        return Err(conflict(
            context,
            "invalid_run_transition",
            "The run cannot make that transition.",
        ));
    }
    let key = idempotency_key_value(context)?;
    let body = json!({"version": version, "next_state": next_state.as_str()});
    let sequence = repository
        .next_event_sequence(&access.device.org_id, run_id)
        .await
        .map_err(|error| database_error(context, error))?;
    let started_at = if next_state == RunState::Running {
        Some(context.received_at.as_str())
    } else {
        None
    };
    let finished_at = if next_state.is_terminal() {
        Some(context.received_at.as_str())
    } else {
        None
    };
    let update = repository
        .update_run_state_statement(
            run_id,
            &access.device.org_id,
            next_state.as_str(),
            failure_code,
            started_at,
            finished_at,
            version,
            &run.state,
            &context.received_at,
        )
        .map_err(|error| database_error(context, error))?;
    let assertion = repository.assert_run_state_version_statement(
        run_id,
        &access.device.org_id,
        version,
        &run.state,
    );
    let mut next_run = run.clone();
    next_run.state = next_state.as_str().to_owned();
    next_run.failure_code = failure_code.map(str::to_owned);
    next_run.started_at = run
        .started_at
        .clone()
        .or_else(|| started_at.map(str::to_owned));
    next_run.finished_at = finished_at.map(str::to_owned);
    next_run.version = version + 1;
    next_run.state_version = run.state_version + 1;
    next_run.updated_at = context.received_at.as_str().to_owned();
    let event = event_statement(
        context,
        database,
        &next_run,
        sequence,
        event_type,
        &json!({"state": next_state.as_str(), "previous_state": run.state, "state_version": next_run.state_version, "device_id": next_run.device_id, "failure_code_present": failure_code.is_some()}),
    )?;
    let audit = device_audit(
        context,
        database,
        access,
        Some(&next_run),
        event_type,
        &next_run.run_id,
        &json!({"state": next_state.as_str(), "version": next_run.version, "device_id": next_run.device_id}),
    )?;
    let outbox = device_outbox(
        context,
        database,
        access,
        &next_run,
        event_type,
        &json!({"run_id": next_run.run_id, "state": next_state.as_str(), "device_id": next_run.device_id}),
    )?;
    commit_device_mutation(
        state,
        context,
        access,
        &key,
        "POST",
        &format!(
            "/api/v1/devices/runs/{run_id}/{}",
            event_type.trim_end_matches(".v1")
        ),
        &body,
        vec![
            assertion.map_err(|error| database_error(context, error))?,
            update,
            event,
            audit,
        ],
        outbox,
        StatusCode::OK,
        super::runs::run_json(&next_run),
    )
    .await
}

#[allow(dead_code)]
fn idempotency_key_value(context: &RequestContext) -> Result<String, ApiError> {
    // This compatibility helper is never used by the registered device routes;
    // transition handlers pass their already-validated header key directly.
    Err(validation_error(
        context,
        "idempotency_key_required",
        "Idempotency-Key is required for this mutation.",
    ))
}

#[worker::send]
pub async fn start_run(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
    Json(body): Json<DeviceVersionRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_device(&state, &headers, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let response =
        start_device_run_with_key(&state, &context, &access, &key, &run_id, body.version).await?;
    Ok(response)
}

#[worker::send]
pub async fn complete_run(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
    Json(body): Json<DeviceTerminalRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_device(&state, &headers, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    transition_with_key(
        &state,
        &context,
        &access,
        &key,
        &run_id,
        body.version,
        RunState::Succeeded,
        body.failure_code.as_deref(),
        "run.completed.v1",
    )
    .await
}

#[worker::send]
pub async fn fail_run(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
    Json(body): Json<DeviceTerminalRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_device(&state, &headers, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    transition_with_key(
        &state,
        &context,
        &access,
        &key,
        &run_id,
        body.version,
        RunState::Failed,
        Some(body.failure_code.as_deref().unwrap_or("runtime_failed")),
        "run.failed.v1",
    )
    .await
}

#[worker::send]
pub async fn cancel_run(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
    Json(body): Json<DeviceVersionRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_device(&state, &headers, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    transition_with_key(
        &state,
        &context,
        &access,
        &key,
        &run_id,
        body.version,
        RunState::Cancelled,
        Some("cancelled_by_device"),
        "run.cancelled.v1",
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn start_device_run_with_key(
    state: &Arc<AppState>,
    context: &RequestContext,
    access: &DeviceAccess,
    key: &str,
    run_id: &str,
    version: i64,
) -> Result<Response<Body>, ApiError> {
    let database = database(state, context)?;
    let repository = RunRepository::new(database);
    let run = repository
        .find_run(&access.device.org_id, run_id)
        .await
        .map_err(|error| database_error(context, error))?
        .ok_or_else(|| denied(context, "run_not_found", "The run is not available."))?;
    if run.device_id != access.device.device_id {
        return Err(denied(
            context,
            "run_not_found",
            "The run is not available.",
        ));
    }
    let current = RunState::parse(&run.state).ok_or_else(|| service_unavailable(context))?;
    if run.version != version || !matches!(current, RunState::Queued | RunState::Dispatching) {
        return Err(conflict(
            context,
            "invalid_run_transition",
            "The run cannot make that transition.",
        ));
    }
    let sequence = repository
        .next_event_sequence(&access.device.org_id, run_id)
        .await
        .map_err(|error| database_error(context, error))?;
    let now = context.received_at.as_str();
    let mut writes = Vec::new();
    let final_run = if current == RunState::Queued {
        let mut dispatching = run.clone();
        dispatching.state = RunState::Dispatching.as_str().to_owned();
        dispatching.version += 1;
        dispatching.state_version += 1;
        dispatching.updated_at = now.to_owned();
        let assertion = repository
            .assert_run_state_version_statement(run_id, &access.device.org_id, version, "queued")
            .map_err(|error| database_error(context, error))?;
        let update = repository
            .update_run_state_statement(
                run_id,
                &access.device.org_id,
                RunState::Dispatching.as_str(),
                None,
                None,
                None,
                version,
                "queued",
                &context.received_at,
            )
            .map_err(|error| database_error(context, error))?;
        let dispatch_event = event_statement(
            context,
            database,
            &dispatching,
            sequence,
            "run.state_changed.v1",
            &json!({"state": "dispatching", "previous_state": "queued", "state_version": dispatching.state_version, "device_id": dispatching.device_id}),
        )?;
        let mut running = dispatching.clone();
        running.state = RunState::Running.as_str().to_owned();
        running.version += 1;
        running.state_version += 1;
        running.started_at = Some(now.to_owned());
        running.updated_at = now.to_owned();
        let running_update = repository
            .update_run_state_statement(
                run_id,
                &access.device.org_id,
                RunState::Running.as_str(),
                None,
                Some(now),
                None,
                version + 1,
                RunState::Dispatching.as_str(),
                &context.received_at,
            )
            .map_err(|error| database_error(context, error))?;
        let started_event = event_statement(
            context,
            database,
            &running,
            sequence + 1,
            "run.started.v1",
            &json!({"state": "running", "previous_state": "dispatching", "state_version": running.state_version, "device_id": running.device_id}),
        )?;
        writes.extend([
            assertion,
            update,
            dispatch_event,
            running_update,
            started_event,
        ]);
        running
    } else {
        let mut running = run.clone();
        running.state = RunState::Running.as_str().to_owned();
        running.version += 1;
        running.state_version += 1;
        running.started_at = Some(now.to_owned());
        running.updated_at = now.to_owned();
        let assertion = repository
            .assert_run_state_version_statement(
                run_id,
                &access.device.org_id,
                version,
                RunState::Dispatching.as_str(),
            )
            .map_err(|error| database_error(context, error))?;
        let update = repository
            .update_run_state_statement(
                run_id,
                &access.device.org_id,
                RunState::Running.as_str(),
                None,
                Some(now),
                None,
                version,
                RunState::Dispatching.as_str(),
                &context.received_at,
            )
            .map_err(|error| database_error(context, error))?;
        let started_event = event_statement(
            context,
            database,
            &running,
            sequence,
            "run.started.v1",
            &json!({"state": "running", "previous_state": "dispatching", "state_version": running.state_version, "device_id": running.device_id}),
        )?;
        writes.extend([assertion, update, started_event]);
        running
    };
    let audit = device_audit(
        context,
        database,
        access,
        Some(&final_run),
        "run.started.v1",
        &final_run.run_id,
        &json!({"state": "running", "version": final_run.version, "device_id": final_run.device_id}),
    )?;
    let outbox = device_outbox(
        context,
        database,
        access,
        &final_run,
        "run.started.v1",
        &json!({"run_id": final_run.run_id, "state": "running", "device_id": final_run.device_id}),
    )?;
    writes.push(audit);
    commit_device_mutation(
        state,
        context,
        access,
        key,
        "POST",
        "/api/v1/devices/runs/{run_id}/start",
        &json!({"version": version}),
        writes,
        outbox,
        StatusCode::OK,
        super::runs::run_json(&final_run),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn transition_with_key(
    state: &Arc<AppState>,
    context: &RequestContext,
    access: &DeviceAccess,
    key: &str,
    run_id: &str,
    version: i64,
    next_state: RunState,
    failure_code: Option<&str>,
    event_type: &str,
) -> Result<Response<Body>, ApiError> {
    let database = database(state, context)?;
    let repository = RunRepository::new(database);
    let run = repository
        .find_run(&access.device.org_id, run_id)
        .await
        .map_err(|error| database_error(context, error))?
        .ok_or_else(|| denied(context, "run_not_found", "The run is not available."))?;
    if run.device_id != access.device.device_id {
        return Err(denied(
            context,
            "run_not_found",
            "The run is not available.",
        ));
    }
    let current = RunState::parse(&run.state).ok_or_else(|| service_unavailable(context))?;
    if current == next_state && next_state == RunState::Cancelled {
        return Ok(Json(super::runs::run_json(&run)).into_response());
    }
    if current.is_terminal() || !current.can_transition_to(next_state) || run.version != version {
        return Err(conflict(
            context,
            "invalid_run_transition",
            "The run cannot make that transition.",
        ));
    }
    let sequence = repository
        .next_event_sequence(&access.device.org_id, run_id)
        .await
        .map_err(|error| database_error(context, error))?;
    let started_at = if next_state == RunState::Running {
        Some(context.received_at.as_str())
    } else {
        None
    };
    let finished_at = if next_state.is_terminal() {
        Some(context.received_at.as_str())
    } else {
        None
    };
    let update = repository
        .update_run_state_statement(
            run_id,
            &access.device.org_id,
            next_state.as_str(),
            failure_code,
            started_at,
            finished_at,
            version,
            &run.state,
            &context.received_at,
        )
        .map_err(|error| database_error(context, error))?;
    let assertion = repository
        .assert_run_state_version_statement(run_id, &access.device.org_id, version, &run.state)
        .map_err(|error| database_error(context, error))?;
    let mut next_run = run.clone();
    next_run.state = next_state.as_str().to_owned();
    next_run.failure_code = failure_code.map(str::to_owned);
    next_run.started_at = run
        .started_at
        .clone()
        .or_else(|| started_at.map(str::to_owned));
    next_run.finished_at = finished_at.map(str::to_owned);
    next_run.version = version + 1;
    next_run.state_version = run.state_version + 1;
    next_run.updated_at = context.received_at.as_str().to_owned();
    let event = event_statement(
        context,
        database,
        &next_run,
        sequence,
        event_type,
        &json!({"state": next_state.as_str(), "previous_state": run.state, "state_version": next_run.state_version, "device_id": next_run.device_id, "failure_code_present": failure_code.is_some()}),
    )?;
    let audit = device_audit(
        context,
        database,
        access,
        Some(&next_run),
        event_type,
        &next_run.run_id,
        &json!({"state": next_state.as_str(), "version": next_run.version, "device_id": next_run.device_id}),
    )?;
    let outbox = device_outbox(
        context,
        database,
        access,
        &next_run,
        event_type,
        &json!({"run_id": next_run.run_id, "state": next_state.as_str(), "device_id": next_run.device_id}),
    )?;
    commit_device_mutation(
        state,
        context,
        access,
        key,
        "POST",
        &format!(
            "/api/v1/devices/runs/{run_id}/{}",
            event_type.trim_end_matches(".v1")
        ),
        &json!({"version": version, "next_state": next_state.as_str()}),
        vec![assertion, update, event, audit],
        outbox,
        StatusCode::OK,
        super::runs::run_json(&next_run),
    )
    .await
}
