//! P03 project routes: org-scoped project CRUD with optimistic versioning,
//! restricted-access grants, workspace-binding visibility, and the read-only
//! policy inspector (F07, plan03 P03-FE-03 backend).

use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, Response, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    adapters::new_resource_id,
    app::AppState,
    core::{ApiError, ApiErrorCode, RequestContext},
    http::auth::require_csrf,
    modules::{
        authorization::Permission,
        projects::{
            ProjectVisibility, normalize_project_slug, validate_project_name,
            validate_project_version,
        },
    },
    repositories::{AiRepository, ProjectGrantRecord, ProjectRepository},
    routes::{
        ai_catalog,
        authorization::authorize_org,
        errors,
        support::{database, database_error, domain_error, idempotency_key, outbox_statement},
    },
};

const PAGE_LIMIT_DEFAULT: i32 = 50;
const PAGE_LIMIT_MAX: i32 = 100;

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
        "The project store is unavailable.",
    )
}

fn deny(context: &RequestContext, code: ApiErrorCode, reason: &str, message: &str) -> ApiError {
    errors::api_error(context, code, message).with_detail("reason", json!(reason))
}

fn page_limit(limit: Option<i32>) -> i32 {
    match limit {
        None => PAGE_LIMIT_DEFAULT,
        Some(0) => PAGE_LIMIT_DEFAULT,
        Some(value) if value > PAGE_LIMIT_MAX => PAGE_LIMIT_MAX,
        Some(value) => value,
    }
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

fn encode_page_cursor(created_at: &str, project_id: &str) -> String {
    use std::fmt::Write;
    let raw = format!("{created_at}|{project_id}");
    let mut encoded = String::with_capacity(raw.len() * 2);
    for byte in raw.as_bytes() {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn project_json(project: &crate::repositories::ProjectRecord) -> Value {
    json!({
        "id": project.project_id,
        "org_id": project.org_id,
        "name": project.name,
        "slug": project.slug,
        "visibility": project.visibility,
        "archived": project.archived_at.is_some(),
        "version": project.version,
        "created_by_user_id": project.created_by_user_id,
        "created_at": project.created_at,
        "updated_at": project.updated_at,
    })
}

fn grant_json(grant: &ProjectGrantRecord) -> Value {
    json!({
        "id": grant.grant_id,
        "project_id": grant.project_id,
        "member_id": grant.member_id,
        "team_id": grant.team_id,
        "created_at": grant.created_at,
    })
}

/// Resolve a project the caller may read: org visibility is open to active
/// members; restricted projects need an explicit grant or `projects.manage`.
async fn readable_project(
    state: &Arc<AppState>,
    context: &RequestContext,
    org_id: &str,
    project_id: &str,
    access: &crate::routes::authorization::OrgAccess,
    manage_allowed: bool,
) -> Result<crate::repositories::ProjectRecord, ApiError> {
    let database = database(state, context)?;
    let projects = ProjectRepository::new(database);
    let project = projects
        .find_project(project_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .filter(|project| project.org_id == org_id)
        .ok_or_else(|| {
            // Restricted projects never leak existence to outsiders (F07).
            deny(
                context,
                ApiErrorCode::NotFound,
                "not_found",
                "No such project.",
            )
        })?;
    let visibility = ProjectVisibility::parse(&project.visibility)
        .ok_or_else(|| service_unavailable(context))?;
    if visibility == ProjectVisibility::Restricted && !manage_allowed {
        let granted = projects
            .member_has_explicit_grant(project_id, org_id, access.principal.user_id.as_str())
            .await
            .map_err(|_| service_unavailable(context))?;
        if !granted {
            return Err(deny(
                context,
                ApiErrorCode::NotFound,
                "not_found",
                "No such project.",
            ));
        }
    }
    Ok(project)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateProjectRequest {
    pub name: String,
    pub slug: Option<String>,
    pub visibility: String,
}

#[worker::send]
pub async fn create_project(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<CreateProjectRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ProjectsManage,
        Some("project"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    idempotency_key(&headers, &context)?;
    let name = validate_project_name(&body.name).map_err(|_| {
        validation_error(
            &context,
            "project_name_invalid",
            "Enter a valid project name.",
        )
    })?;
    let visibility = ProjectVisibility::parse(&body.visibility).ok_or_else(|| {
        validation_error(
            &context,
            "project_visibility_invalid",
            "visibility must be org or restricted.",
        )
    })?;
    let slug = match body.slug.as_deref() {
        Some(slug) => normalize_project_slug(slug).map_err(|_| {
            validation_error(&context, "project_slug_invalid", "Enter a valid slug.")
        })?,
        None => normalize_project_slug(&name).map_err(|_| {
            validation_error(&context, "project_slug_invalid", "Enter a valid slug.")
        })?,
    };
    let database = database(&state, &context)?;
    if ProjectRepository::new(database)
        .project_slug_count(org_id.as_str(), &slug)
        .await
        .map_err(|error| database_error(&context, error))?
        > 0
    {
        return Err(deny(
            &context,
            ApiErrorCode::Conflict,
            "project_slug_conflict",
            "A project with this slug already exists.",
        ));
    }
    let project_id = generated_id("prj");
    let insert = ProjectRepository::new(database)
        .insert_project_statement(
            &crate::repositories::NewProjectInput {
                project_id: &project_id,
                org_id: org_id.as_str(),
                name: &name,
                slug: &slug,
                visibility: visibility.as_str(),
                created_by_user_id: access.principal.user_id.as_str(),
            },
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    database
        .batch(vec![insert])
        .await
        .map_err(|error| database_error(&context, error))?;
    let project = ProjectRepository::new(database)
        .find_project(&project_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| service_unavailable(&context))?;
    let event = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(org_id.as_str()),
        "project.created.v1",
        &json!({ "project_id": project_id, "visibility": visibility.as_str() }),
    )?;
    database
        .batch(vec![event])
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok((StatusCode::CREATED, Json(project_json(&project))).into_response())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectListQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
}

#[worker::send]
pub async fn list_projects(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<ProjectListQuery>,
    Path(org_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ProjectsRead,
        Some("project"),
        None,
    )
    .await?;
    let limit = page_limit(query.limit);
    let cursor = query
        .cursor
        .as_deref()
        .map(|raw| decode_page_cursor(raw, &context))
        .transpose()?;
    let cursor_ref = cursor
        .as_ref()
        .map(|(created_at, project_id)| (created_at.as_str(), project_id.as_str()));
    let database = database(&state, &context)?;
    let projects = ProjectRepository::new(database);
    // Managers see every project including restricted ones; members see org
    // visibility plus their explicit grants.
    let mut records = if authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ProjectsManage,
        Some("project"),
        None,
    )
    .await
    .is_ok()
    {
        unrestricted_project_page(database, &context, org_id.as_str(), cursor_ref, limit + 1)
            .await?
    } else {
        projects
            .list_projects_for_member(
                org_id.as_str(),
                access.principal.user_id.as_str(),
                cursor_ref,
                limit + 1,
            )
            .await
            .map_err(|error| database_error(&context, error))?
    };
    let has_more = records.len() > limit as usize;
    if has_more {
        records.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        records
            .last()
            .map(|project| encode_page_cursor(&project.created_at, &project.project_id))
    } else {
        None
    };
    let items: Vec<Value> = records.iter().map(project_json).collect();
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

async fn unrestricted_project_page(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    org_id: &str,
    cursor: Option<(&str, &str)>,
    limit: i32,
) -> Result<Vec<crate::repositories::ProjectRecord>, ApiError> {
    let projects = ProjectRepository::new(database);
    projects
        .list_projects_unrestricted(org_id, cursor, limit)
        .await
        .map_err(|error| database_error(context, error))
}

/// Single-project read with restricted-visibility enforcement: unauthorized
/// members get a 404 that does not leak metadata (F07 acceptance).
#[worker::send]
pub async fn get_project(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, project_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ProjectsRead,
        Some("project"),
        Some(&project_id),
    )
    .await?;
    let manage_allowed = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ProjectsManage,
        Some("project"),
        Some(&project_id),
    )
    .await
    .is_ok();
    let project = readable_project(
        &state,
        &context,
        &org_id,
        &project_id,
        &access,
        manage_allowed,
    )
    .await?;
    Ok((StatusCode::OK, Json(project_json(&project))).into_response())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchProjectRequest {
    pub name: String,
    pub visibility: String,
    pub archived: Option<bool>,
    pub version: i64,
}

/// Archive state flips through the same versioned mutation as rename and
/// visibility so every project change is a single optimistic write.
#[worker::send]
pub async fn patch_project(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, project_id)): Path<(String, String)>,
    Json(body): Json<PatchProjectRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ProjectsManage,
        Some("project"),
        Some(&project_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    validate_project_version(body.version).map_err(|_| {
        validation_error(
            &context,
            "project_version_invalid",
            "version must be positive.",
        )
    })?;
    let name = validate_project_name(&body.name).map_err(|_| {
        validation_error(
            &context,
            "project_name_invalid",
            "Enter a valid project name.",
        )
    })?;
    let visibility = ProjectVisibility::parse(&body.visibility).ok_or_else(|| {
        validation_error(
            &context,
            "project_visibility_invalid",
            "visibility must be org or restricted.",
        )
    })?;
    let database = database(&state, &context)?;
    let existing = ProjectRepository::new(database)
        .find_project(&project_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .filter(|project| project.org_id == org_id)
        .ok_or_else(|| {
            deny(
                &context,
                ApiErrorCode::NotFound,
                "not_found",
                "No such project.",
            )
        })?;
    let archiving = body.archived.unwrap_or(existing.archived_at.is_some());
    let archived_at = if archiving {
        existing
            .archived_at
            .clone()
            .unwrap_or_else(|| context.received_at.as_str().to_owned())
    } else {
        String::new()
    };
    let project = ProjectRepository::new(database)
        .update_project(&crate::repositories::ProjectUpdateInput {
            project_id: &project_id,
            org_id: org_id.as_str(),
            name: &name,
            visibility: visibility.as_str(),
            archived_at: if archiving {
                Some(archived_at.as_str())
            } else {
                None
            },
            now: &context.received_at,
            expected_version: body.version,
        })
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| {
            deny(
                &context,
                ApiErrorCode::Conflict,
                "version_conflict",
                "The project changed since you loaded it.",
            )
        })?;
    let action = if archiving && existing.archived_at.is_none() {
        "project.archived.v1"
    } else {
        "project.updated.v1"
    };
    let event = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(org_id.as_str()),
        action,
        &json!({ "project_id": project_id, "version": project.version }),
    )?;
    database
        .batch(vec![event])
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok((StatusCode::OK, Json(project_json(&project))).into_response())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    pub member_id: Option<String>,
    pub team_id: Option<String>,
}

#[worker::send]
pub async fn create_grant(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, project_id)): Path<(String, String)>,
    Json(body): Json<GrantRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ProjectsManage,
        Some("project"),
        Some(&project_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    match (&body.member_id, &body.team_id) {
        (Some(_), None) | (None, Some(_)) => {}
        _ => {
            return Err(validation_error(
                &context,
                "grant_invalid",
                "Provide exactly one of member_id or team_id.",
            ));
        }
    }
    let database = database(&state, &context)?;
    let project = ProjectRepository::new(database)
        .find_project(&project_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .filter(|project| project.org_id == org_id)
        .ok_or_else(|| {
            deny(
                &context,
                ApiErrorCode::NotFound,
                "not_found",
                "No such project.",
            )
        })?;
    if project.visibility != "restricted" {
        return Err(deny(
            &context,
            ApiErrorCode::Conflict,
            "project_not_restricted",
            "Only restricted projects accept access grants.",
        ));
    }
    let grant_id = generated_id("pag");
    ProjectRepository::new(database)
        .insert_grant(
            &grant_id,
            &project_id,
            org_id.as_str(),
            body.member_id.as_deref(),
            body.team_id.as_deref(),
            &context.received_at,
        )
        .await
        .map_err(|error| database_error(&context, error))?;
    let grant = ProjectRepository::new(database)
        .find_grant(&grant_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| service_unavailable(&context))?;
    Ok((StatusCode::CREATED, Json(grant_json(&grant))).into_response())
}

#[worker::send]
pub async fn list_grants(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, project_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ProjectsManage,
        Some("project"),
        Some(&project_id),
    )
    .await?;
    let database = database(&state, &context)?;
    let grants = ProjectRepository::new(database)
        .list_grants_by_project(&project_id, PAGE_LIMIT_MAX)
        .await
        .map_err(|error| database_error(&context, error))?;
    let items: Vec<Value> = grants.iter().map(grant_json).collect();
    Ok((
        StatusCode::OK,
        Json(json!({ "items": items, "next_cursor": Value::Null, "has_more": false })),
    )
        .into_response())
}

#[worker::send]
pub async fn delete_grant(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, project_id, grant_id)): Path<(String, String, String)>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ProjectsManage,
        Some("project"),
        Some(&project_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let database = database(&state, &context)?;
    let grant = ProjectRepository::new(database)
        .find_grant(&grant_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .filter(|grant| grant.project_id == project_id && grant.org_id == org_id)
        .ok_or_else(|| {
            deny(
                &context,
                ApiErrorCode::NotFound,
                "not_found",
                "No such grant.",
            )
        })?;
    ProjectRepository::new(database)
        .delete_grant(&grant.grant_id, &project_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[worker::send]
pub async fn list_project_bindings(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, project_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ProjectsRead,
        Some("project"),
        Some(&project_id),
    )
    .await?;
    let manage_allowed = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ProjectsManage,
        Some("project"),
        Some(&project_id),
    )
    .await
    .is_ok();
    let project = readable_project(
        &state,
        &context,
        &org_id,
        &project_id,
        &access,
        manage_allowed,
    )
    .await?;
    let database = database(&state, &context)?;
    let bindings = ProjectRepository::new(database)
        .list_bindings_by_project(&project.project_id, PAGE_LIMIT_MAX)
        .await
        .map_err(|error| database_error(&context, error))?;
    let items: Vec<Value> = bindings
        .iter()
        .map(|binding| {
            let mut value = json!({
                "id": binding.binding_id,
                "project_id": binding.project_id,
                "device_id": binding.device_id,
                "workspace_identity": binding.workspace_identity,
                "display_name": binding.display_name,
                "environment_type": binding.environment_type,
                "last_seen_at": binding.last_seen_at,
                "created_at": binding.created_at,
            });
            if manage_allowed {
                value["org_id"] = json!(binding.org_id);
            }
            value
        })
        .collect();
    Ok((
        StatusCode::OK,
        Json(json!({ "items": items, "next_cursor": Value::Null, "has_more": false })),
    )
        .into_response())
}

#[worker::send]
pub async fn delete_project_binding(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, project_id, binding_id)): Path<(String, String, String)>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ProjectsManage,
        Some("project"),
        Some(&project_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    idempotency_key(&headers, &context)?;
    let database = database(&state, &context)?;
    let binding = ProjectRepository::new(database)
        .find_binding(&binding_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .filter(|binding| binding.project_id == project_id && binding.org_id == org_id)
        .ok_or_else(|| {
            deny(
                &context,
                ApiErrorCode::NotFound,
                "not_found",
                "No such binding.",
            )
        })?;
    let deleted = ProjectRepository::new(database)
        .delete_binding(&binding.binding_id, &project_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    if !deleted {
        return Err(deny(
            &context,
            ApiErrorCode::NotFound,
            "not_found",
            "No such binding.",
        ));
    }
    let event = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(org_id.as_str()),
        "project.binding_removed.v1",
        &json!({ "binding_id": binding.binding_id, "project_id": project_id }),
    )?;
    database
        .batch(vec![event])
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Read-only effective policy inspector (plan03 P03-FE-03 backend).
#[worker::send]
pub async fn org_policy(
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
        Permission::ProjectsRead,
        Some("policy"),
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let snapshot = crate::repositories::PolicyRepository::new(database)
        .latest_snapshot(org_id.as_str())
        .await
        .map_err(|_| service_unavailable(&context))?;
    let model_policy = match AiRepository::new(database).find_policy(&org_id).await {
        Ok(Some(policy)) => ai_catalog::policy_json(&policy),
        Ok(None) => ai_catalog::default_policy_json(&org_id, &context),
        Err(_) => return Err(service_unavailable(&context)),
    };
    let mut response = if let Some(snapshot) = snapshot {
        json!({
            "policy_id": snapshot.policy_id,
            "org_id": snapshot.org_id,
            "policy_version": snapshot.policy_version,
            "issued_at": snapshot.issued_at,
            "expires_at": snapshot.expires_at,
            "signature": Value::Null,
            "payload": serde_json::from_str::<Value>(&snapshot.payload)
                .unwrap_or_else(|_| json!({})),
            "persisted": true,
        })
    } else {
        json!({
            "policy_id": Value::Null,
            "org_id": org_id,
            "policy_version": 0,
            "issued_at": context.received_at,
            "expires_at": context.received_at,
            "signature": Value::Null,
            "payload": {"models": {"schema_version": 0}},
            "persisted": false,
        })
    };
    if let Some(response) = response.as_object_mut() {
        response.insert("model_policy".to_owned(), model_policy.clone());
    }
    if let (Some(response), Some(model_policy)) =
        (response.as_object_mut(), model_policy.as_object())
    {
        for key in [
            "allowed_aliases",
            "allowed_models",
            "allowed_providers",
            "credential_mode",
            "managed_route_enabled",
            "version",
            "created_at",
            "updated_at",
        ] {
            if let Some(value) = model_policy.get(key) {
                response.insert(key.to_owned(), value.clone());
            }
        }
    }
    Ok((StatusCode::OK, Json(response)).into_response())
}
