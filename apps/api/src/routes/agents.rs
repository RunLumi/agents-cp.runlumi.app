//! P05 agent-definition and agent-session HTTP surface.
//!
//! This module owns only transport validation, current authorization, and
//! bounded idempotency orchestration.  State/persistence details live in the
//! run repository, and the Worker never becomes an execution host here.

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
    adapters::{add_idempotency_ttl, new_resource_id, sha256_hex},
    app::AppState,
    core::{
        ActorId, ApiError, ApiErrorCode, IdempotencyKeyDigest, IdempotencyRecord, IdempotencyScope,
        IdempotencyState, OrganizationId, Principal, RequestContext, RequestFingerprint,
        ResourceId, StoredSuccess,
    },
    http::auth::require_csrf,
    modules::{authorization::Permission, runs::SessionState},
    repositories::{
        AgentDefinitionRecord, AgentSessionRecord, DeviceRecord, DeviceRepository,
        IdempotencyClaimToken, IdempotencyLookup, IdempotencyRepository, ProjectRecord,
        ProjectRepository, RunRepository,
    },
    routes::{
        authorization::authorize_org,
        errors,
        support::{database, database_error, domain_error, idempotency_key, outbox_statement},
    },
};

pub(crate) const PAGE_LIMIT_DEFAULT: i32 = 50;
pub(crate) const PAGE_LIMIT_MAX: i32 = 100;

pub const AGENTS_PATH: &str = "/api/v1/orgs/{org_id}/agents";
#[allow(dead_code)]
pub const AGENT_PATH: &str = "/api/v1/orgs/{org_id}/agents/{agent_id}";
pub const SESSIONS_PATH: &str = "/api/v1/orgs/{org_id}/sessions";
#[allow(dead_code)]
pub const SESSION_PATH: &str = "/api/v1/orgs/{org_id}/sessions/{session_id}";

/// A prepared, server-owned idempotency claim.  The raw client key is never
/// retained; only the digest and request fingerprint enter D1.
pub(crate) struct MutationClaim {
    pub(crate) record: IdempotencyRecord,
    pub(crate) token: IdempotencyClaimToken,
    pub(crate) statement: D1PreparedStatement,
}

pub(crate) enum PreparedMutation {
    Replay(StoredSuccess),
    Claim(MutationClaim),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAgentRequest {
    pub name: String,
    pub description: Option<String>,
    pub instructions_ref: Option<String>,
    pub default_model_alias: Option<String>,
    pub required_capabilities: Option<Vec<String>>,
    pub allowed_tool_ids: Option<Vec<String>>,
    pub runtime_requirements: Option<Vec<String>>,
    pub project_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchAgentRequest {
    pub name: Option<String>,
    pub description: Option<Option<String>>,
    pub instructions_ref: Option<Option<String>>,
    pub default_model_alias: Option<Option<String>>,
    pub required_capabilities: Option<Vec<String>>,
    pub allowed_tool_ids: Option<Vec<String>>,
    pub runtime_requirements: Option<Vec<String>>,
    pub project_id: Option<Option<String>>,
    pub lifecycle: Option<String>,
    pub version: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSessionRequest {
    pub project_id: String,
    pub device_id: String,
    pub workspace_binding_id: Option<String>,
    pub agent_definition_id: String,
    pub agent_definition_version: Option<i64>,
    pub external_id: Option<String>,
    pub title: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloseSessionRequest {
    pub version: i64,
}

#[derive(Debug, Deserialize)]
pub struct AgentListQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    pub project_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SessionListQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    pub project_id: Option<String>,
    pub lifecycle: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PageResponse<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

pub(crate) fn validation_error(context: &RequestContext, reason: &str, message: &str) -> ApiError {
    domain_error(context, ApiErrorCode::ValidationFailed, reason, message)
}

pub(crate) fn service_unavailable(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::ServiceUnavailable,
        "The agent control-plane store is unavailable.",
    )
}

pub(crate) fn not_found(context: &RequestContext, reason: &str) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::NotFound,
        "The requested resource was not found.",
    )
    .with_detail("reason", json!(reason))
}

pub(crate) fn denied(
    context: &RequestContext,
    code: ApiErrorCode,
    reason: &str,
    message: &str,
) -> ApiError {
    errors::api_error(context, code, message).with_detail("reason", json!(reason))
}

pub(crate) fn page_limit(limit: Option<i32>) -> i32 {
    match limit {
        None => PAGE_LIMIT_DEFAULT,
        Some(value) if value <= 0 => PAGE_LIMIT_DEFAULT,
        Some(value) if value > PAGE_LIMIT_MAX => PAGE_LIMIT_MAX,
        Some(value) => value,
    }
}

/// Opaque keyset cursor used by the P05 collections.  The encoded value is
/// deliberately not a client-meaningful offset.
pub(crate) fn encode_page_cursor(created_at: &str, id: &str) -> String {
    use std::fmt::Write;
    let raw = format!("{created_at}|{id}");
    let mut encoded = String::with_capacity(raw.len() * 2);
    for byte in raw.as_bytes() {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

pub(crate) fn decode_page_cursor(
    raw: &str,
    context: &RequestContext,
) -> Result<(String, String), ApiError> {
    fn hex_value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }
    let invalid = || validation_error(context, "cursor_invalid", "The cursor is invalid.");
    let bytes = raw.as_bytes();
    if bytes.is_empty() || bytes.len() > 4_096 || !bytes.len().is_multiple_of(2) {
        return Err(invalid());
    }
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let high = hex_value(pair[0]).ok_or_else(invalid)?;
        let low = hex_value(pair[1]).ok_or_else(invalid)?;
        decoded.push(high << 4 | low);
    }
    let text = String::from_utf8(decoded).map_err(|_| invalid())?;
    let (created_at, id) = text.split_once('|').ok_or_else(invalid)?;
    if created_at.is_empty()
        || id.is_empty()
        || created_at.len() > 255
        || id.len() > 255
        || created_at.chars().any(char::is_control)
        || id.chars().any(char::is_control)
        || id.contains('|')
    {
        return Err(invalid());
    }
    Ok((created_at.to_owned(), id.to_owned()))
}

pub(crate) fn validate_prefixed_id(
    context: &RequestContext,
    value: &str,
    prefix: &str,
    reason: &str,
) -> Result<String, ApiError> {
    let id = ResourceId::new(value)
        .map_err(|_| validation_error(context, reason, "The resource ID is invalid."))?;
    if id.prefix() != prefix {
        return Err(validation_error(
            context,
            reason,
            "The resource ID is invalid.",
        ));
    }
    Ok(id.as_str().to_owned())
}

pub(crate) fn validate_text(
    context: &RequestContext,
    value: &str,
    max_chars: usize,
    reason: &str,
    message: &str,
) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.chars().count() > max_chars
        || trimmed.chars().any(char::is_control)
    {
        return Err(validation_error(context, reason, message));
    }
    Ok(trimmed.to_owned())
}

pub(crate) fn validate_optional_text(
    context: &RequestContext,
    value: Option<&str>,
    max_chars: usize,
    reason: &str,
    message: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| validate_text(context, value, max_chars, reason, message))
        .transpose()
}

pub(crate) fn validate_model_alias(
    context: &RequestContext,
    value: &str,
) -> Result<String, ApiError> {
    let value = value.trim();
    let valid = !value.is_empty()
        && value.len() <= 96
        && value == value.to_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if valid {
        Ok(value.to_owned())
    } else {
        Err(validation_error(
            context,
            "model_alias_invalid",
            "The model alias is invalid.",
        ))
    }
}

pub(crate) fn validate_string_list(
    context: &RequestContext,
    values: Option<&Vec<String>>,
    max_items: usize,
    max_chars: usize,
    reason: &str,
) -> Result<Vec<String>, ApiError> {
    let Some(values) = values else {
        return Ok(Vec::new());
    };
    if values.len() > max_items {
        return Err(validation_error(
            context,
            reason,
            "The configuration list is too large.",
        ));
    }
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        let value = validate_text(
            context,
            value,
            max_chars,
            reason,
            "The configuration list contains an invalid value.",
        )?;
        if !normalized.contains(&value) {
            normalized.push(value);
        }
    }
    Ok(normalized)
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

fn decode_array(context: &RequestContext, value: &str) -> Result<Value, ApiError> {
    decode_string_list(context, value).map(Value::from)
}

pub(crate) fn agent_json(
    context: &RequestContext,
    agent: &AgentDefinitionRecord,
) -> Result<Value, ApiError> {
    Ok(json!({
        "id": agent.agent_definition_id,
        "org_id": agent.org_id,
        "project_id": agent.project_id,
        "name": agent.name,
        "description": agent.description,
        "instructions_ref": agent.instructions_ref,
        "default_model_alias": agent.default_model_alias,
        "required_capabilities": decode_array(context, &agent.required_capabilities_json)?,
        "allowed_tool_ids": decode_array(context, &agent.allowed_tool_ids_json)?,
        "runtime_requirements": decode_array(context, &agent.runtime_requirements_json)?,
        "lifecycle": agent.lifecycle,
        "version": agent.version,
        "created_at": agent.created_at,
        "updated_at": agent.updated_at,
    }))
}

pub(crate) fn session_json(session: &AgentSessionRecord) -> Value {
    json!({
        "id": session.agent_session_id,
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

pub(crate) async fn ensure_project_access(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    org_id: &str,
    project_id: &str,
    user_id: &str,
    manager: bool,
) -> Result<ProjectRecord, ApiError> {
    let project = ProjectRepository::new(database)
        .find_project(project_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .filter(|project| project.org_id == org_id)
        .ok_or_else(|| not_found(context, "project_not_found"))?;
    if project.visibility == "restricted"
        && !manager
        && !ProjectRepository::new(database)
            .member_has_explicit_grant(project_id, org_id, user_id)
            .await
            .map_err(|_| service_unavailable(context))?
    {
        // Restricted-project existence is not an oracle for members without a
        // grant (F07-004/F04-002).
        return Err(not_found(context, "project_not_found"));
    }
    if project.visibility != "org" && project.visibility != "restricted" {
        return Err(service_unavailable(context));
    }
    Ok(project)
}

pub(crate) async fn can_manage_projects(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    context: &RequestContext,
    org_id: &str,
) -> bool {
    authorize_org(
        state,
        headers,
        context,
        org_id,
        Permission::ProjectsManage,
        Some("project"),
        None,
    )
    .await
    .is_ok()
}

fn agent_body_value<T: Serialize>(context: &RequestContext, body: &T) -> Result<Value, ApiError> {
    serde_json::to_value(body).map_err(|_| {
        errors::api_error(
            context,
            ApiErrorCode::InternalError,
            "The request could not be normalized.",
        )
    })
}

fn map_idempotency_lookup(
    context: &RequestContext,
    lookup: IdempotencyLookup,
) -> Result<Option<StoredSuccess>, ApiError> {
    match lookup {
        IdempotencyLookup::Missing => Err(domain_error(
            context,
            ApiErrorCode::Conflict,
            "conflict",
            "The request conflicts with current state.",
        )),
        IdempotencyLookup::InProgress => Err(errors::api_error(
            context,
            ApiErrorCode::IdempotencyInProgress,
            "A request with this Idempotency-Key is still in progress.",
        )),
        IdempotencyLookup::FingerprintConflict => Err(errors::api_error(
            context,
            ApiErrorCode::IdempotencyConflict,
            "This Idempotency-Key was already used for a different request.",
        )),
        IdempotencyLookup::Replay(success) => Ok(Some(success)),
    }
}

/// Look up/claim an idempotency key before a P05 side effect.  The request
/// fingerprint is derived from the normalized body, never from a raw body
/// string or a client-supplied resource ID as authority.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn prepare_mutation(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    principal: &Principal,
    org_id: &str,
    key: &str,
    method: &str,
    path: &str,
    body: &Value,
) -> Result<PreparedMutation, ApiError> {
    let scope = IdempotencyScope::new(
        ActorId::new(principal.user_id.as_str()).map_err(|_| service_unavailable(context))?,
        Some(OrganizationId::new(org_id).map_err(|_| service_unavailable(context))?),
        method,
        path,
    )
    .map_err(|_| service_unavailable(context))?;
    let canonical = serde_json::to_string(body).map_err(|_| service_unavailable(context))?;
    let key_digest = IdempotencyKeyDigest::new(format!(
        "sha256:{}",
        sha256_hex(key)
            .await
            .map_err(|_| service_unavailable(context))?
    ))
    .map_err(|_| service_unavailable(context))?;
    let request_fingerprint = RequestFingerprint::new(format!(
        "sha256:{}",
        sha256_hex(&format!("{method}\n{path}\n{canonical}"))
            .await
            .map_err(|_| service_unavailable(context))?
    ))
    .map_err(|_| service_unavailable(context))?;
    let repository = IdempotencyRepository::new(database);
    match repository
        .lookup(
            &scope,
            &key_digest,
            &request_fingerprint,
            &context.received_at,
        )
        .await
        .map_err(|_| service_unavailable(context))?
    {
        IdempotencyLookup::Replay(success) => return Ok(PreparedMutation::Replay(success)),
        IdempotencyLookup::InProgress => {
            return Err(errors::api_error(
                context,
                ApiErrorCode::IdempotencyInProgress,
                "A request with this Idempotency-Key is still in progress.",
            ));
        }
        IdempotencyLookup::FingerprintConflict => {
            return Err(errors::api_error(
                context,
                ApiErrorCode::IdempotencyConflict,
                "This Idempotency-Key was already used for a different request.",
            ));
        }
        IdempotencyLookup::Missing => {}
    }
    let token = IdempotencyClaimToken::new(context.request_id.as_str())
        .map_err(|_| service_unavailable(context))?;
    let record = IdempotencyRecord {
        scope,
        key_digest,
        request_fingerprint,
        expires_at: add_idempotency_ttl(&context.received_at)
            .map_err(|_| service_unavailable(context))?,
        state: IdempotencyState::Pending,
    };
    let statement = repository
        .claim_statement(&record, &token, &context.received_at)
        .map_err(|_| service_unavailable(context))?;
    Ok(PreparedMutation::Claim(MutationClaim {
        record,
        token,
        statement,
    }))
}

/// Commit the idempotency claim, business writes, audit/outbox rows, and saved
/// response as one D1 batch.  A failed batch is reclassified by a fresh
/// lookup so a concurrent identical request gets a replay/conflict rather than
/// a duplicate side effect.
pub(crate) async fn commit_mutation(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    claim: MutationClaim,
    success: StoredSuccess,
    business_writes: Vec<D1PreparedStatement>,
    outbox: D1PreparedStatement,
) -> Result<Option<StoredSuccess>, ApiError> {
    let record = claim.record;
    let token = claim.token;
    let result = IdempotencyRepository::new(database)
        .commit_success(
            &record,
            &token,
            claim.statement,
            &success,
            business_writes,
            outbox,
        )
        .await;
    if result.is_ok() {
        return Ok(None);
    }
    let repository = IdempotencyRepository::new(database);
    let lookup = repository
        .lookup(
            &record.scope,
            &record.key_digest,
            &record.request_fingerprint,
            &context.received_at,
        )
        .await
        .map_err(|_| service_unavailable(context))?;
    map_idempotency_lookup(context, lookup)
}

pub(crate) fn replay_response(success: StoredSuccess) -> Response<Body> {
    let status = StatusCode::from_u16(success.status).unwrap_or(StatusCode::OK);
    (status, Json(success.body)).into_response()
}

pub(crate) fn generated_id(prefix: &str) -> String {
    new_resource_id(prefix).as_str().to_owned()
}

#[allow(clippy::too_many_arguments)]
fn security_statement(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    principal: &Principal,
    org_id: &str,
    event_id: &str,
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
        event_id,
        action,
        resource_type,
        Some(resource_id),
        "success",
        metadata,
    )
}

#[allow(clippy::too_many_arguments)]
fn create_agent_record(
    id: String,
    org_id: &str,
    project_id: Option<String>,
    name: String,
    description: Option<String>,
    instructions_ref: Option<String>,
    default_model_alias: Option<String>,
    required_capabilities_json: String,
    allowed_tool_ids_json: String,
    runtime_requirements_json: String,
    created_by: &str,
    now: &str,
) -> AgentDefinitionRecord {
    AgentDefinitionRecord {
        agent_definition_id: id,
        org_id: org_id.to_owned(),
        project_id,
        name,
        description,
        instructions_ref,
        default_model_alias,
        required_capabilities_json,
        allowed_tool_ids_json,
        runtime_requirements_json,
        lifecycle: "active".to_owned(),
        version: 1,
        created_by_user_id: created_by.to_owned(),
        created_at: now.to_owned(),
        updated_at: now.to_owned(),
    }
}

#[worker::send]
pub async fn list_agents(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<AgentListQuery>,
    Path(org_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::AgentsRead,
        Some("agent_definition"),
        None,
    )
    .await?;
    let limit = page_limit(query.limit);
    let cursor = query
        .cursor
        .as_deref()
        .map(|raw| decode_page_cursor(raw, &context))
        .transpose()?;
    let database = database(&state, &context)?;
    let manager = can_manage_projects(&state, &headers, &context, &org_id).await;
    if let Some(project_id) = query.project_id.as_deref() {
        let project_id = validate_prefixed_id(&context, project_id, "prj", "project_id_invalid")?;
        ensure_project_access(
            database,
            &context,
            &org_id,
            &project_id,
            access.principal.user_id.as_str(),
            manager,
        )
        .await?;
    }
    let mut records = RunRepository::new(database)
        .list_agents(
            &org_id,
            access.principal.user_id.as_str(),
            manager,
            query.project_id.as_deref(),
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
            .map(|record| encode_page_cursor(&record.updated_at, &record.agent_definition_id))
    } else {
        None
    };
    let items = records
        .iter()
        .map(|record| agent_json(&context, record))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((
        StatusCode::OK,
        Json(PageResponse {
            items,
            next_cursor,
            has_more,
        }),
    )
        .into_response())
}

#[worker::send]
pub async fn create_agent(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<CreateAgentRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::AgentsManage,
        Some("agent_definition"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let name = validate_text(
        &context,
        &body.name,
        160,
        "agent_name_invalid",
        "Enter a valid agent name.",
    )?;
    let description = validate_optional_text(
        &context,
        body.description.as_deref(),
        2_000,
        "agent_description_invalid",
        "The agent description is invalid.",
    )?;
    let instructions_ref = validate_optional_text(
        &context,
        body.instructions_ref.as_deref(),
        2_048,
        "instructions_ref_invalid",
        "The instructions reference is invalid.",
    )?;
    let default_model_alias = body
        .default_model_alias
        .as_deref()
        .map(|value| validate_model_alias(&context, value))
        .transpose()?;
    let required_capabilities = validate_string_list(
        &context,
        body.required_capabilities.as_ref(),
        64,
        128,
        "required_capabilities_invalid",
    )?;
    let allowed_tool_ids = validate_string_list(
        &context,
        body.allowed_tool_ids.as_ref(),
        256,
        128,
        "allowed_tool_ids_invalid",
    )?;
    let runtime_requirements = validate_string_list(
        &context,
        body.runtime_requirements.as_ref(),
        64,
        128,
        "runtime_requirements_invalid",
    )?;
    let project_id = body
        .project_id
        .as_deref()
        .map(|value| validate_prefixed_id(&context, value, "prj", "project_id_invalid"))
        .transpose()?;
    let database = database(&state, &context)?;
    let manager = can_manage_projects(&state, &headers, &context, &org_id).await;
    if let Some(project_id) = project_id.as_deref() {
        let project = ensure_project_access(
            database,
            &context,
            &org_id,
            project_id,
            access.principal.user_id.as_str(),
            manager,
        )
        .await?;
        if project.archived_at.is_some() {
            return Err(denied(
                &context,
                ApiErrorCode::Conflict,
                "project_archived",
                "Archived projects cannot receive new agent definitions.",
            ));
        }
    }
    let body_value = agent_body_value(&context, &body)?;
    let mutation = prepare_mutation(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        "POST",
        AGENTS_PATH,
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };
    let agent_id = generated_id("agd");
    let now = context.received_at.as_str().to_owned();
    let required_json =
        serde_json::to_string(&required_capabilities).map_err(|_| service_unavailable(&context))?;
    let allowed_json =
        serde_json::to_string(&allowed_tool_ids).map_err(|_| service_unavailable(&context))?;
    let runtime_json =
        serde_json::to_string(&runtime_requirements).map_err(|_| service_unavailable(&context))?;
    let record = create_agent_record(
        agent_id.clone(),
        &org_id,
        project_id,
        name,
        description,
        instructions_ref,
        default_model_alias,
        required_json.clone(),
        allowed_json.clone(),
        runtime_json.clone(),
        access.principal.user_id.as_str(),
        &now,
    );
    let insert = RunRepository::new(database)
        .insert_agent_statement(
            &crate::repositories::NewAgentDefinitionInput {
                agent_definition_id: &record.agent_definition_id,
                org_id: &record.org_id,
                project_id: record.project_id.as_deref(),
                name: &record.name,
                description: record.description.as_deref(),
                instructions_ref: record.instructions_ref.as_deref(),
                default_model_alias: record.default_model_alias.as_deref(),
                required_capabilities_json: &required_json,
                allowed_tool_ids_json: &allowed_json,
                runtime_requirements_json: &runtime_json,
                created_by_user_id: &record.created_by_user_id,
            },
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let security = security_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        &generated_id("sec"),
        "agent_definition.created.v1",
        "agent_definition",
        &record.agent_definition_id,
        &json!({ "project_id": record.project_id }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "agent_definition.created.v1",
        &json!({
            "agent_definition_id": record.agent_definition_id,
            "project_id": record.project_id,
            "version": record.version,
        }),
    )?;
    let success = StoredSuccess::new(201, agent_json(&context, &record)?)
        .map_err(|_| service_unavailable(&context))?;
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![insert, security],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::CREATED, Json(success.body)).into_response())
}

#[worker::send]
pub async fn get_agent(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, agent_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::AgentsRead,
        Some("agent_definition"),
        Some(&agent_id),
    )
    .await?;
    let database = database(&state, &context)?;
    let manager = can_manage_projects(&state, &headers, &context, &org_id).await;
    let record = RunRepository::new(database)
        .find_agent(&org_id, &agent_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| not_found(&context, "agent_not_found"))?;
    if let Some(project_id) = record.project_id.as_deref() {
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
    Ok((StatusCode::OK, Json(agent_json(&context, &record)?)).into_response())
}

#[worker::send]
pub async fn patch_agent(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, agent_id)): Path<(String, String)>,
    Json(body): Json<PatchAgentRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::AgentsManage,
        Some("agent_definition"),
        Some(&agent_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    if body.version <= 0 || body.version == i64::MAX {
        return Err(validation_error(
            &context,
            "version_invalid",
            "The resource version is invalid.",
        ));
    }
    let database = database(&state, &context)?;
    let manager = can_manage_projects(&state, &headers, &context, &org_id).await;
    let existing = RunRepository::new(database)
        .find_agent(&org_id, &agent_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| not_found(&context, "agent_not_found"))?;
    if let Some(project_id) = existing.project_id.as_deref() {
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
    let project_id = match body.project_id {
        Some(value) => value
            .as_deref()
            .map(|value| validate_prefixed_id(&context, value, "prj", "project_id_invalid"))
            .transpose()?,
        None => existing.project_id.clone(),
    };
    if let Some(project_id) = project_id.as_deref() {
        let project = ensure_project_access(
            database,
            &context,
            &org_id,
            project_id,
            access.principal.user_id.as_str(),
            manager,
        )
        .await?;
        if project.archived_at.is_some() {
            return Err(denied(
                &context,
                ApiErrorCode::Conflict,
                "project_archived",
                "Archived projects cannot receive updated agent definitions.",
            ));
        }
    }
    let name = match body.name.as_deref() {
        Some(value) => validate_text(
            &context,
            value,
            160,
            "agent_name_invalid",
            "Enter a valid agent name.",
        )?,
        None => existing.name.clone(),
    };
    let description = match body.description {
        Some(None) => None,
        Some(Some(value)) => validate_optional_text(
            &context,
            Some(value.as_str()),
            2_000,
            "agent_description_invalid",
            "The agent description is invalid.",
        )?,
        None => existing.description.clone(),
    };
    let instructions_ref = match body.instructions_ref {
        Some(None) => None,
        Some(Some(value)) => validate_optional_text(
            &context,
            Some(value.as_str()),
            2_048,
            "instructions_ref_invalid",
            "The instructions reference is invalid.",
        )?,
        None => existing.instructions_ref.clone(),
    };
    let default_model_alias = match body.default_model_alias {
        Some(None) => None,
        Some(Some(value)) => Some(validate_model_alias(&context, &value)?),
        None => existing.default_model_alias.clone(),
    };
    let required = if let Some(values) = body.required_capabilities.as_ref() {
        validate_string_list(
            &context,
            Some(values),
            64,
            128,
            "required_capabilities_invalid",
        )?
    } else {
        decode_string_list(&context, &existing.required_capabilities_json)?
    };
    let allowed = if let Some(values) = body.allowed_tool_ids.as_ref() {
        validate_string_list(&context, Some(values), 256, 128, "allowed_tool_ids_invalid")?
    } else {
        decode_string_list(&context, &existing.allowed_tool_ids_json)?
    };
    let runtime = if let Some(values) = body.runtime_requirements.as_ref() {
        validate_string_list(
            &context,
            Some(values),
            64,
            128,
            "runtime_requirements_invalid",
        )?
    } else {
        decode_string_list(&context, &existing.runtime_requirements_json)?
    };
    let lifecycle = body
        .lifecycle
        .as_deref()
        .map(|value| {
            if matches!(value, "active" | "archived" | "disabled") {
                Ok(value.to_owned())
            } else {
                Err(validation_error(
                    &context,
                    "agent_lifecycle_invalid",
                    "The agent lifecycle is invalid.",
                ))
            }
        })
        .transpose()?
        .unwrap_or_else(|| existing.lifecycle.clone());
    let required_json =
        serde_json::to_string(&required).map_err(|_| service_unavailable(&context))?;
    let allowed_json =
        serde_json::to_string(&allowed).map_err(|_| service_unavailable(&context))?;
    let runtime_json =
        serde_json::to_string(&runtime).map_err(|_| service_unavailable(&context))?;
    let assertion = RunRepository::new(database)
        .assert_agent_version_statement(&agent_id, &org_id, body.version)
        .map_err(|error| database_error(&context, error))?;
    let update = RunRepository::new(database)
        .update_agent_statement(&crate::repositories::AgentDefinitionUpdateInput {
            agent_definition_id: &agent_id,
            org_id: &org_id,
            project_id: project_id.as_deref(),
            name: &name,
            description: description.as_deref(),
            instructions_ref: instructions_ref.as_deref(),
            default_model_alias: default_model_alias.as_deref(),
            required_capabilities_json: &required_json,
            allowed_tool_ids_json: &allowed_json,
            runtime_requirements_json: &runtime_json,
            lifecycle: &lifecycle,
            now: &context.received_at,
            expected_version: body.version,
        })
        .map_err(|error| database_error(&context, error))?;
    let security = security_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        &generated_id("sec"),
        "agent_definition.updated.v1",
        "agent_definition",
        &agent_id,
        &json!({ "version": body.version + 1, "lifecycle": lifecycle }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "agent_definition.updated.v1",
        &json!({
            "agent_definition_id": agent_id,
            "project_id": project_id,
            "version": body.version + 1,
        }),
    )?;
    let results = database
        .batch(vec![assertion, update, security, outbox])
        .await
        .map_err(|error| database_error(&context, error))?;
    if results.get(1).is_none_or(|result| {
        crate::adapters::d1::D1Adapter::changes(result).unwrap_or_default() != 1
    }) {
        return Err(denied(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The agent definition changed. Refresh and try again.",
        ));
    }
    let record = RunRepository::new(database)
        .find_agent(&org_id, &agent_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| service_unavailable(&context))?;
    Ok((StatusCode::OK, Json(agent_json(&context, &record)?)).into_response())
}

#[worker::send]
pub async fn list_sessions(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<SessionListQuery>,
    Path(org_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::SessionsRead,
        Some("agent_session"),
        None,
    )
    .await?;
    let limit = page_limit(query.limit);
    let cursor = query
        .cursor
        .as_deref()
        .map(|raw| decode_page_cursor(raw, &context))
        .transpose()?;
    if let Some(lifecycle) = query.lifecycle.as_deref()
        && !matches!(lifecycle, "active" | "closed" | "archived")
    {
        return Err(validation_error(
            &context,
            "session_lifecycle_invalid",
            "The session lifecycle is invalid.",
        ));
    }
    let database = database(&state, &context)?;
    let manager = can_manage_projects(&state, &headers, &context, &org_id).await;
    if let Some(project_id) = query.project_id.as_deref() {
        let project_id = validate_prefixed_id(&context, project_id, "prj", "project_id_invalid")?;
        ensure_project_access(
            database,
            &context,
            &org_id,
            &project_id,
            access.principal.user_id.as_str(),
            manager,
        )
        .await?;
    }
    let mut records = RunRepository::new(database)
        .list_sessions(
            &org_id,
            access.principal.user_id.as_str(),
            manager,
            query.lifecycle.as_deref(),
            query.project_id.as_deref(),
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
            .map(|record| encode_page_cursor(&record.updated_at, &record.agent_session_id))
    } else {
        None
    };
    let items = records.iter().map(session_json).collect();
    Ok((
        StatusCode::OK,
        Json(PageResponse {
            items,
            next_cursor,
            has_more,
        }),
    )
        .into_response())
}

#[worker::send]
pub async fn create_session(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<CreateSessionRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::SessionsManage,
        Some("agent_session"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let project_id = validate_prefixed_id(&context, &body.project_id, "prj", "project_id_invalid")?;
    let device_id = validate_prefixed_id(&context, &body.device_id, "dvc", "device_id_invalid")?;
    let agent_definition_id = validate_prefixed_id(
        &context,
        &body.agent_definition_id,
        "agd",
        "agent_definition_id_invalid",
    )?;
    let workspace_binding_id = body
        .workspace_binding_id
        .as_deref()
        .map(|value| validate_prefixed_id(&context, value, "wsb", "workspace_binding_id_invalid"))
        .transpose()?;
    let external_id = validate_optional_text(
        &context,
        body.external_id.as_deref(),
        256,
        "external_id_invalid",
        "The external session reference is invalid.",
    )?;
    let title = validate_optional_text(
        &context,
        body.title.as_deref(),
        200,
        "session_title_invalid",
        "The session title is invalid.",
    )?;
    if body
        .agent_definition_version
        .is_some_and(|version| version <= 0)
    {
        return Err(validation_error(
            &context,
            "agent_definition_version_invalid",
            "The agent definition version is invalid.",
        ));
    }
    let database = database(&state, &context)?;
    let manager = can_manage_projects(&state, &headers, &context, &org_id).await;
    let project = ensure_project_access(
        database,
        &context,
        &org_id,
        &project_id,
        access.principal.user_id.as_str(),
        manager,
    )
    .await?;
    if project.archived_at.is_some() {
        return Err(denied(
            &context,
            ApiErrorCode::Conflict,
            "project_archived",
            "Archived projects cannot start new agent sessions.",
        ));
    }
    let device = DeviceRepository::new(database)
        .find_device(&device_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .filter(|device: &DeviceRecord| device.org_id == org_id)
        .ok_or_else(|| not_found(&context, "device_not_found"))?;
    if device.status != "active" {
        return Err(denied(
            &context,
            ApiErrorCode::PermissionDenied,
            "device_revoked",
            "The device is not active.",
        ));
    }
    let agent = RunRepository::new(database)
        .find_agent(&org_id, &agent_definition_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| not_found(&context, "agent_not_found"))?;
    if agent.lifecycle != "active"
        || agent
            .project_id
            .as_deref()
            .is_some_and(|value| value != project_id.as_str())
    {
        return Err(not_found(&context, "agent_not_found"));
    }
    if let Some(binding_id) = workspace_binding_id.as_deref() {
        let binding = ProjectRepository::new(database)
            .find_binding(binding_id)
            .await
            .map_err(|_| service_unavailable(&context))?
            .filter(|binding| {
                binding.org_id == org_id
                    && binding.project_id == project_id
                    && binding.device_id == device_id
            })
            .ok_or_else(|| not_found(&context, "workspace_binding_not_found"))?;
        if binding.binding_id.is_empty() {
            return Err(service_unavailable(&context));
        }
    }
    let requested_agent_version = body.agent_definition_version.unwrap_or(agent.version);
    if requested_agent_version != agent.version {
        return Err(validation_error(
            &context,
            "agent_definition_version_invalid",
            "The agent definition version is no longer current.",
        ));
    }
    let body_value = agent_body_value(&context, &body)?;
    let mutation = prepare_mutation(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        "POST",
        SESSIONS_PATH,
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };
    let session_id = generated_id("rse");
    let agent_version = requested_agent_version;
    let record = AgentSessionRecord {
        agent_session_id: session_id.clone(),
        org_id: org_id.clone(),
        project_id: project_id.clone(),
        device_id: device_id.clone(),
        workspace_binding_id: workspace_binding_id.clone(),
        agent_definition_id: agent_definition_id.clone(),
        agent_definition_version: agent_version,
        external_id: external_id.clone(),
        title: title.clone(),
        lifecycle: "active".to_owned(),
        version: 1,
        created_by_user_id: access.principal.user_id.as_str().to_owned(),
        created_at: context.received_at.as_str().to_owned(),
        updated_at: context.received_at.as_str().to_owned(),
    };
    let insert = RunRepository::new(database)
        .insert_session_statement(
            &crate::repositories::NewAgentSessionInput {
                agent_session_id: &record.agent_session_id,
                org_id: &record.org_id,
                project_id: &record.project_id,
                device_id: &record.device_id,
                workspace_binding_id: record.workspace_binding_id.as_deref(),
                agent_definition_id: &record.agent_definition_id,
                agent_definition_version: record.agent_definition_version,
                external_id: record.external_id.as_deref(),
                title: record.title.as_deref(),
                created_by_user_id: &record.created_by_user_id,
            },
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let security = security_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        &generated_id("sec"),
        "session.created.v1",
        "agent_session",
        &record.agent_session_id,
        &json!({
            "project_id": record.project_id,
            "device_id": record.device_id,
            "agent_definition_id": record.agent_definition_id,
            "agent_definition_version": record.agent_definition_version,
        }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "session.created.v1",
        &json!({
            "agent_session_id": record.agent_session_id,
            "project_id": record.project_id,
            "device_id": record.device_id,
            "agent_definition_id": record.agent_definition_id,
            "agent_definition_version": record.agent_definition_version,
        }),
    )?;
    let success = StoredSuccess::new(201, session_json(&record))
        .map_err(|_| service_unavailable(&context))?;
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![insert, security],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::CREATED, Json(success.body)).into_response())
}

#[worker::send]
pub async fn get_session(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, session_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::SessionsRead,
        Some("agent_session"),
        Some(&session_id),
    )
    .await?;
    let database = database(&state, &context)?;
    let manager = can_manage_projects(&state, &headers, &context, &org_id).await;
    let record = RunRepository::new(database)
        .find_session(&org_id, &session_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| not_found(&context, "session_not_found"))?;
    ensure_project_access(
        database,
        &context,
        &org_id,
        &record.project_id,
        access.principal.user_id.as_str(),
        manager,
    )
    .await?;
    Ok((StatusCode::OK, Json(session_json(&record))).into_response())
}

#[worker::send]
pub async fn close_session(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, session_id)): Path<(String, String)>,
    Json(body): Json<CloseSessionRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::SessionsManage,
        Some("agent_session"),
        Some(&session_id),
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
    let database = database(&state, &context)?;
    let manager = can_manage_projects(&state, &headers, &context, &org_id).await;
    let record = RunRepository::new(database)
        .find_session(&org_id, &session_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| not_found(&context, "session_not_found"))?;
    ensure_project_access(
        database,
        &context,
        &org_id,
        &record.project_id,
        access.principal.user_id.as_str(),
        manager,
    )
    .await?;
    let lifecycle =
        SessionState::parse(&record.lifecycle).ok_or_else(|| service_unavailable(&context))?;
    if lifecycle.is_terminal() {
        return Ok((StatusCode::OK, Json(session_json(&record))).into_response());
    }
    if !lifecycle.can_transition_to(SessionState::Closed) {
        return Err(denied(
            &context,
            ApiErrorCode::Conflict,
            "invalid_session_transition",
            "The session cannot be closed from its current state.",
        ));
    }
    if record.version != body.version {
        return Err(denied(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The session changed. Refresh and try again.",
        ));
    }
    let body_value = agent_body_value(&context, &body)?;
    let mutation = prepare_mutation(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        "POST",
        &format!("/api/v1/orgs/{org_id}/sessions/{session_id}/close"),
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };
    let update = RunRepository::new(database)
        .update_session_lifecycle_statement(
            &session_id,
            &org_id,
            "closed",
            body.version,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let assertion = RunRepository::new(database)
        .assert_session_version_statement(&session_id, &org_id, body.version)
        .map_err(|error| database_error(&context, error))?;
    let security = security_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        &generated_id("sec"),
        "session.closed.v1",
        "agent_session",
        &session_id,
        &json!({ "version": body.version + 1 }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "session.closed.v1",
        &json!({ "agent_session_id": session_id, "version": body.version + 1 }),
    )?;
    let closed = AgentSessionRecord {
        lifecycle: "closed".to_owned(),
        version: body.version + 1,
        updated_at: context.received_at.as_str().to_owned(),
        ..record
    };
    let success = StoredSuccess::new(200, session_json(&closed))
        .map_err(|_| service_unavailable(&context))?;
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![assertion, update, security],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::OK, Json(success.body)).into_response())
}
