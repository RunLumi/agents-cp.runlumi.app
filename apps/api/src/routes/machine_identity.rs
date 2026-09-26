//! P07 machine identity HTTP surface (P07-BE-02, P07-INT-02).
//!
//! # Route surface (all under `/api/v1`)
//!
//! | Method | Path | Permission |
//! |---|---|---|
//! | GET | `/orgs/{org_id}/service-accounts` | `service_accounts.read` |
//! | POST | `/orgs/{org_id}/service-accounts` | `service_accounts.manage` |
//! | GET | `/orgs/{org_id}/service-accounts/{service_account_id}` | `service_accounts.read` |
//! | PATCH | `/orgs/{org_id}/service-accounts/{service_account_id}` | `service_accounts.manage` |
//! | POST | `/orgs/{org_id}/service-accounts/{service_account_id}/suspend` | `service_accounts.manage` |
//! | POST | `/orgs/{org_id}/service-accounts/{service_account_id}/resume` | `service_accounts.manage` |
//! | GET | `/orgs/{org_id}/api-keys` | `service_accounts.read` |
//! | POST | `/orgs/{org_id}/api-keys` | `service_accounts.manage` |
//! | GET | `/api-keys/{api_key_id}` | `service_accounts.read` |
//! | POST | `/api-keys/{api_key_id}/rotate` | `service_accounts.manage` |
//! | POST | `/api-keys/{api_key_id}/revoke` | `service_accounts.manage` |
//! | GET | `/machine/whoami` | any machine capability |
//!
//! # Two rules that shape every handler
//!
//! **The organization is server-derived.** `{api_key_id}` routes resolve the
//! organization from the key row, and `authorize_org` is then called with THAT
//! value. A client-supplied `org_id` is never authorization evidence; the
//! `x-org-id` mismatch guard in `authorize_org` exists to catch a client that
//! believes it is acting on a different organization, not to supply the scope.
//!
//! **The secret appears exactly once.** It is present in the `201`/`200` body of
//! the create and rotate responses and in no other response, no log, and no
//! audit payload. [`api_key_json`] has no field for it, so a list or a get cannot
//! leak it even by accident.

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
    adapters::{new_resource_id, new_secret},
    app::AppState,
    core::{ApiError, ApiErrorCode, MachineKeyMaterial, OrganizationId, RequestContext},
    http::auth::require_machine,
    modules::{
        authorization::Permission,
        machine_identity::{
            CapabilitySet, MachineDecision, MachineDenyReason, MachineIdentityError,
            MachineRequest, authorize_machine,
        },
    },
    repositories::{
        ApiKeyRecord, MAX_ACTIVE_KEYS_PER_ACCOUNT, MAX_ACTIVE_SERVICE_ACCOUNTS_PER_ORG,
        MachineIdentityRepository, NewApiKeyInput, NewServiceAccountInput, P07_PAGE_LIMIT_MAX,
        ServiceAccountRecord,
    },
    routes::{
        agents::replay_response,
        authorization::authorize_org,
        errors,
        support::{
            database, database_error, domain_error, idempotency_key, security_event_statement,
        },
        usage::{PreparedScopedMutation, commit_scoped_mutation, prepare_scoped_mutation},
    },
};

/// Idempotency scope templates. Stable, so the same logical operation always
/// shares one P01 idempotency scope.
pub const SERVICE_ACCOUNT_CREATE_PATH: &str = "/api/v1/orgs/{org_id}/service-accounts";
pub const SERVICE_ACCOUNT_SUSPEND_PATH: &str =
    "/api/v1/orgs/{org_id}/service-accounts/{service_account_id}/suspend";
pub const SERVICE_ACCOUNT_RESUME_PATH: &str =
    "/api/v1/orgs/{org_id}/service-accounts/{service_account_id}/resume";
pub const API_KEY_CREATE_PATH: &str = "/api/v1/orgs/{org_id}/api-keys";
pub const API_KEY_ROTATE_PATH: &str = "/api/v1/api-keys/{api_key_id}/rotate";
pub const API_KEY_REVOKE_PATH: &str = "/api/v1/api-keys/{api_key_id}/revoke";
pub const SERVICE_ACCOUNT_PATCH_PATH: &str =
    "/api/v1/orgs/{org_id}/service-accounts/{service_account_id}";

// ------------------------------------------------------------- requests ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateServiceAccountBody {
    pub name: String,
    pub description: Option<String>,
    pub capabilities: Vec<String>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchServiceAccountBody {
    pub version: i64,
    pub name: Option<String>,
    pub description: Option<String>,
    pub capabilities: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuspendServiceAccountBody {
    pub version: i64,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeServiceAccountBody {
    pub version: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateApiKeyBody {
    pub service_account_id: String,
    pub name: String,
    pub capabilities: Vec<String>,
    /// `null` means every project in the organization; `[]` means none.
    pub project_ids: Option<Vec<String>>,
    pub model_aliases: Option<Vec<String>>,
    pub network_allowlist: Option<Vec<String>>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateApiKeyBody {
    pub reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeApiKeyBody {
    pub version: i64,
    pub reason: String,
}

/// `#[serde(default)]` rather than `Option<Query<_>>`: axum's last extractor must
/// implement `FromRequest`, and `Option<Query<T>>` does not. A default-everything
/// query struct is the idiomatic way to accept an absent query string.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ListQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
}

// ---------------------------------------------------------- projections ----

/// The public projection of a service account. It carries the capability list so
/// a human can see exactly what the credential may do — F14's "create with
/// permission preview" — and nothing about any key's material.
pub fn service_account_json(account: &ServiceAccountRecord) -> Value {
    json!({
        "id": account.service_account_id,
        "organization_id": account.org_id,
        "name": account.name,
        "description": account.description,
        "capabilities": raw_string_list(&account.capabilities_json),
        "status": account.status,
        "expires_at": account.expires_at,
        "suspended_at": account.suspended_at,
        "suspend_reason": account.suspend_reason,
        "created_by_principal_id": account.created_by_principal,
        "version": account.version,
        "created_at": account.created_at,
        "updated_at": account.updated_at,
    })
}

/// The public projection of a key.
///
/// This function is the reason "the raw key is never returned again" is a
/// structural property rather than a convention: there is no parameter carrying a
/// secret and no field for one, so no list, get, or audit call can produce one.
/// [`api_key_json_with_secret`] exists only for the create and rotate responses
/// and takes the wire value explicitly.
pub fn api_key_json(key: &ApiKeyRecord) -> Value {
    json!({
        "id": key.api_key_id,
        "service_account_id": key.service_account_id,
        "organization_id": key.org_id,
        "name": key.name,
        "key_prefix": key.key_prefix,
        "fingerprint": key.fingerprint,
        "capabilities": raw_string_list(&key.capabilities_json),
        "project_ids": raw_string_list(key.project_ids_json.as_deref().unwrap_or("null")),
        "model_aliases": raw_string_list(key.model_aliases_json.as_deref().unwrap_or("null")),
        "network_allowlist": raw_string_list(key.network_allowlist_json.as_deref().unwrap_or("null")),
        "status": key.status,
        "rotated_from_key_id": key.rotated_from_key_id,
        "rotated_to_key_id": key.rotated_to_key_id,
        "last_used_at": key.last_used_at,
        "last_used_source": key.last_used_source,
        "expires_at": key.expires_at,
        "revoked_at": key.revoked_at,
        "revoke_reason": key.revoke_reason,
        "version": key.version,
        "created_at": key.created_at,
        "updated_at": key.updated_at,
    })
}

/// The one and only projection that carries a secret.
///
/// Named so a reader can grep for every call site, and it is called from exactly
/// two handlers: create and rotate.
pub fn api_key_json_with_secret(key: &ApiKeyRecord, secret: &str) -> Value {
    let mut value = api_key_json(key);
    if let Some(object) = value.as_object_mut() {
        object.insert("secret".to_owned(), json!(secret));
        object.insert(
            "secret_notice".to_owned(),
            json!("This value is shown once and cannot be retrieved again. Store it now."),
        );
    }
    value
}

// ------------------------------------------------------------- handlers ----

#[worker::send]
pub async fn list_service_accounts(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id,)): Path<(String,)>,
    Query(query): Query<ListQuery>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ServiceAccountsRead,
        Some("service_account"),
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let (cursor_created_at, cursor_id) = decode_cursor(query.cursor.as_deref(), &context)?;
    let limit = query.limit.unwrap_or(50).clamp(1, P07_PAGE_LIMIT_MAX);
    let rows = MachineIdentityRepository::new(database)
        .list_service_accounts(
            &org_id,
            cursor_created_at.as_deref(),
            cursor_id.as_deref(),
            limit + 1,
        )
        .await
        .map_err(|_| store_unavailable(&context))?;
    let (page, next) = page_of(rows, limit, |row| {
        (row.created_at.clone(), row.service_account_id.clone())
    });
    Ok(json_response(
        &context,
        json!({
            "items": page.iter().map(service_account_json).collect::<Vec<_>>(),
            "page": { "limit": limit, "next_cursor": next },
        }),
    ))
}

#[worker::send]
pub async fn get_service_account(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, service_account_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ServiceAccountsRead,
        Some("service_account"),
        Some(&service_account_id),
    )
    .await?;
    let database = database(&state, &context)?;
    let account = find_account(database, &service_account_id, &org_id, &context).await?;
    Ok(json_response(
        &context,
        json!({ "service_account": service_account_json(&account) }),
    ))
}

#[worker::send]
pub async fn create_service_account(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id,)): Path<(String,)>,
    Json(body): Json<CreateServiceAccountBody>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ServiceAccountsManage,
        Some("service_account"),
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let key = idempotency_key(&headers, &context)?;
    let capabilities = parse_capabilities(&body.capabilities, &context)?;
    validate_name(&body.name, &context)?;
    let description = body
        .description
        .as_deref()
        .map(|value| bounded(value, 2000, &context))
        .transpose()?;

    let canonical = json!({
        "name": body.name,
        "description": description,
        "capabilities": capabilities.to_json(),
        "expires_at": body.expires_at,
    });
    let claim = match prepare_scoped_mutation(
        database,
        &context,
        access.principal.user_id.as_str(),
        &org_id,
        &key,
        "POST",
        SERVICE_ACCOUNT_CREATE_PATH,
        &canonical,
    )
    .await?
    {
        PreparedScopedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedScopedMutation::Claim(claim) => claim,
    };

    // The frozen bound. Counted rather than left to a constraint collision,
    // because `key_limit_reached` is a different answer to a different question
    // than "conflict".
    let active = MachineIdentityRepository::new(database)
        .count_active_service_accounts(&org_id)
        .await
        .map_err(|_| store_unavailable(&context))?;
    if active >= MAX_ACTIVE_SERVICE_ACCOUNTS_PER_ORG {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "key_limit_reached",
            "This organization has reached its active service account limit.",
        ));
    }

    let service_account_id = new_resource_id("svc").as_str().to_owned();
    let now = context.received_at.clone();
    let repository = MachineIdentityRepository::new(database);
    let insert = repository
        .insert_service_account_statement(&NewServiceAccountInput {
            service_account_id: &service_account_id,
            org_id: &org_id,
            name: &body.name,
            description: description.as_deref(),
            capabilities_json: &capabilities.to_json(),
            // A service account is created by a HUMAN principal. There is no
            // machine path to this route at all, and the creator is recorded
            // because "who added this credential" is the first question of any
            // incident review.
            created_by_principal: access.principal.user_id.as_str(),
            expires_at: body.expires_at.as_deref(),
            now: now.as_str(),
        })
        .map_err(|_| store_unavailable(&context))?;
    let audit = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        crate::adapters::new_event_id().as_str(),
        "service_account.created",
        "service_account",
        Some(&service_account_id),
        "success",
        &json!({
            "capabilities": capabilities.permissions()
                .iter().map(|c| c.as_str()).collect::<Vec<_>>(),
        }),
    )?;
    let success = crate::core::StoredSuccess::new(
        StatusCode::CREATED.as_u16(),
        json!({
            "service_account_id": service_account_id,
            "capabilities": capabilities.permissions()
                .iter().map(|c| c.as_str()).collect::<Vec<_>>(),
        }),
    )
    .map_err(|_| store_unavailable(&context))?;
    match commit_scoped_mutation(database, &context, claim, success, vec![insert], audit).await? {
        crate::routes::usage::ScopedMutationCommit::Committed => {}
        crate::routes::usage::ScopedMutationCommit::Replayed(replay) => {
            return Ok(replay_response(replay));
        }
        crate::routes::usage::ScopedMutationCommit::Guarded => {
            return Err(domain_error(
                &context,
                ApiErrorCode::Conflict,
                "conflict",
                "The request conflicts with current state.",
            ));
        }
    }
    let created = find_account(database, &service_account_id, &org_id, &context).await?;
    Ok(json_response(
        &context,
        json!({ "service_account": service_account_json(&created) }),
    ))
}

#[worker::send]
pub async fn patch_service_account(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, service_account_id)): Path<(String, String)>,
    Json(body): Json<PatchServiceAccountBody>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ServiceAccountsManage,
        Some("service_account"),
        Some(&service_account_id),
    )
    .await?;
    let database = database(&state, &context)?;
    let current = find_account(database, &service_account_id, &org_id, &context).await?;
    let capabilities = match &body.capabilities {
        Some(values) => parse_capabilities(values, &context)?,
        None => CapabilitySet::parse(&current.capabilities_json)
            .map_err(|_| store_unavailable(&context))?,
    };
    let name = body.name.as_deref().unwrap_or(current.name.as_str());
    validate_name(name, &context)?;
    let description = match body.description.as_deref() {
        Some(value) => Some(bounded(value, 2000, &context)?),
        None => current.description.clone(),
    };
    // The canonical command is the fingerprint, so a replay with different field
    // values is a conflict rather than a silent no-op.
    let canonical = json!({
        "version": body.version,
        "name": name,
        "description": description,
        "capabilities": capabilities.to_json(),
    });
    let now = context.received_at.clone();
    let repository = MachineIdentityRepository::new(database);
    let update = repository
        .update_service_account_statement(&crate::repositories::ServiceAccountUpdateInput {
            service_account_id: &service_account_id,
            org_id: &org_id,
            name,
            description: description.as_deref(),
            capabilities_json: &capabilities.to_json(),
            expected_version: body.version,
            now: now.as_str(),
        })
        .map_err(|_| store_unavailable(&context))?;
    let guard = repository
        .assert_service_account_version_statement(&service_account_id, &org_id, body.version)
        .map_err(|_| store_unavailable(&context))?;
    let audit = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        crate::adapters::new_event_id().as_str(),
        "service_account.updated",
        "service_account",
        Some(&service_account_id),
        "success",
        &json!({ "version": body.version }),
    )?;
    let success = crate::core::StoredSuccess::new(
        StatusCode::OK.as_u16(),
        json!({ "service_account_id": service_account_id }),
    )
    .map_err(|_| store_unavailable(&context))?;
    let claim = match prepare_scoped_mutation(
        database,
        &context,
        access.principal.user_id.as_str(),
        &org_id,
        &idempotency_key(&headers, &context)?,
        "PATCH",
        SERVICE_ACCOUNT_PATCH_PATH,
        &canonical,
    )
    .await?
    {
        PreparedScopedMutation::Replay(replay) => return Ok(replay_response(replay)),
        PreparedScopedMutation::Claim(claim) => claim,
    };
    match commit_scoped_mutation(
        database,
        &context,
        claim,
        success,
        vec![update, guard],
        audit,
    )
    .await?
    {
        crate::routes::usage::ScopedMutationCommit::Committed => {}
        crate::routes::usage::ScopedMutationCommit::Replayed(replay) => {
            return Ok(replay_response(replay));
        }
        crate::routes::usage::ScopedMutationCommit::Guarded => {
            return Err(domain_error(
                &context,
                ApiErrorCode::Conflict,
                "version_conflict",
                "The service account changed. Refresh and try again.",
            ));
        }
    }
    let updated = find_account(database, &service_account_id, &org_id, &context).await?;
    Ok(json_response(
        &context,
        json!({ "service_account": service_account_json(&updated) }),
    ))
}

#[worker::send]
pub async fn suspend_service_account(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, service_account_id)): Path<(String, String)>,
    Json(body): Json<SuspendServiceAccountBody>,
) -> Result<Response<Body>, ApiError> {
    transition_service_account(
        &state,
        &context,
        &headers,
        &org_id,
        &service_account_id,
        body.version,
        Some(&body.reason),
        "suspend",
    )
    .await
}

#[worker::send]
pub async fn resume_service_account(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, service_account_id)): Path<(String, String)>,
    Json(body): Json<ResumeServiceAccountBody>,
) -> Result<Response<Body>, ApiError> {
    transition_service_account(
        &state,
        &context,
        &headers,
        &org_id,
        &service_account_id,
        body.version,
        None,
        "resume",
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn transition_service_account(
    state: &Arc<AppState>,
    context: &RequestContext,
    headers: &HeaderMap,
    org_id: &str,
    service_account_id: &str,
    version: i64,
    reason: Option<&str>,
    transition: &str,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        state,
        headers,
        context,
        org_id,
        Permission::ServiceAccountsManage,
        Some("service_account"),
        Some(service_account_id),
    )
    .await?;
    let database = database(state, context)?;
    let key = idempotency_key(headers, context)?;
    let repository = MachineIdentityRepository::new(database);
    let now = context.received_at.clone();
    let statement = if transition == "suspend" {
        let reason = reason.ok_or_else(|| invalid_input(context))?;
        repository.suspend_service_account_statement(
            service_account_id,
            org_id,
            reason,
            version,
            &now,
        )
    } else {
        repository.resume_service_account_statement(service_account_id, org_id, version, &now)
    }
    .map_err(|_| store_unavailable(context))?;
    let guard = repository
        .assert_service_account_version_statement(service_account_id, org_id, version)
        .map_err(|_| store_unavailable(context))?;
    let audit = security_event_statement(
        database,
        context,
        Some(&access.principal),
        Some(org_id),
        crate::adapters::new_event_id().as_str(),
        &format!("service_account.{transition}ed"),
        "service_account",
        Some(service_account_id),
        "success",
        &json!({ "version": version, "reason": reason }),
    )?;
    let success = crate::core::StoredSuccess::new(
        StatusCode::OK.as_u16(),
        json!({ "service_account_id": service_account_id }),
    )
    .map_err(|_| store_unavailable(context))?;
    let path = if transition == "suspend" {
        SERVICE_ACCOUNT_SUSPEND_PATH
    } else {
        SERVICE_ACCOUNT_RESUME_PATH
    };
    let claim = match prepare_scoped_mutation(
        database,
        context,
        access.principal.user_id.as_str(),
        org_id,
        &key,
        "POST",
        path,
        &json!({ "version": version, "reason": reason }),
    )
    .await?
    {
        PreparedScopedMutation::Replay(replay) => return Ok(replay_response(replay)),
        PreparedScopedMutation::Claim(claim) => claim,
    };
    match commit_scoped_mutation(
        database,
        context,
        claim,
        success,
        vec![statement, guard],
        audit,
    )
    .await?
    {
        crate::routes::usage::ScopedMutationCommit::Committed => {}
        crate::routes::usage::ScopedMutationCommit::Replayed(replay) => {
            return Ok(replay_response(replay));
        }
        crate::routes::usage::ScopedMutationCommit::Guarded => {
            return Err(domain_error(
                context,
                ApiErrorCode::Conflict,
                "version_conflict",
                "The service account changed. Refresh and try again.",
            ));
        }
    }
    let updated = find_account(database, service_account_id, org_id, context).await?;
    Ok(json_response(
        context,
        json!({ "service_account": service_account_json(&updated) }),
    ))
}

#[worker::send]
pub async fn list_api_keys(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id,)): Path<(String,)>,
    Query(query): Query<ListQuery>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ServiceAccountsRead,
        Some("api_key"),
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let (cursor_created_at, cursor_id) = decode_cursor(query.cursor.as_deref(), &context)?;
    let limit = query.limit.unwrap_or(50).clamp(1, P07_PAGE_LIMIT_MAX);
    let rows = MachineIdentityRepository::new(database)
        .list_keys(
            &org_id,
            cursor_created_at.as_deref(),
            cursor_id.as_deref(),
            limit + 1,
        )
        .await
        .map_err(|_| store_unavailable(&context))?;
    let (page, next) = page_of(rows, limit, |row| {
        (row.created_at.clone(), row.api_key_id.clone())
    });
    Ok(json_response(
        &context,
        json!({
            "items": page.iter().map(api_key_json).collect::<Vec<_>>(),
            "page": { "limit": limit, "next_cursor": next },
        }),
    ))
}

#[worker::send]
pub async fn create_api_key(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id,)): Path<(String,)>,
    Json(body): Json<CreateApiKeyBody>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ServiceAccountsManage,
        Some("api_key"),
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let key = idempotency_key(&headers, &context)?;
    validate_name(&body.name, &context)?;
    let capabilities = parse_capabilities(&body.capabilities, &context)?;
    let account = find_account(database, &body.service_account_id, &org_id, &context).await?;
    if !account.is_active() {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "machine_key_suspended",
            "This service account is suspended.",
        ));
    }

    // A key holds a SUBSET of its account's capabilities and never a superset.
    // This is the one place both rows are available, which is why the gate
    // delegates the rule here rather than to a trigger.
    let account_capabilities = CapabilitySet::parse(&account.capabilities_json)
        .map_err(|_| store_unavailable(&context))?;
    if !capabilities.is_subset_of(&account_capabilities) {
        return Err(domain_error(
            &context,
            ApiErrorCode::ValidationFailed,
            "scope_capability_unknown",
            "A key's capabilities must be a subset of its service account's capabilities.",
        )
        .with_detail(
            "excess_capabilities",
            json!(capabilities.excess_over(&account_capabilities)),
        ));
    }

    let active = MachineIdentityRepository::new(database)
        .count_active_keys(&account.service_account_id)
        .await
        .map_err(|_| store_unavailable(&context))?;
    if active >= MAX_ACTIVE_KEYS_PER_ACCOUNT {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "key_limit_reached",
            "This service account has reached its active key limit.",
        ));
    }

    let project_ids = optional_id_list(body.project_ids.as_deref(), "prj", &context)?;
    let model_aliases = optional_text_list(body.model_aliases.as_deref(), &context)?;
    let network_allowlist = optional_text_list(body.network_allowlist.as_deref(), &context)?;

    let canonical = json!({
        "service_account_id": body.service_account_id,
        "name": body.name,
        "capabilities": capabilities.to_json(),
        "project_ids": project_ids,
        "model_aliases": model_aliases,
        "network_allowlist": network_allowlist,
        "expires_at": body.expires_at,
    });
    let claim = match prepare_scoped_mutation(
        database,
        &context,
        access.principal.user_id.as_str(),
        &org_id,
        &key,
        "POST",
        API_KEY_CREATE_PATH,
        &canonical,
    )
    .await?
    {
        PreparedScopedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedScopedMutation::Claim(claim) => claim,
    };

    let Some(material) = mint_material() else {
        return Err(store_unavailable(&context));
    };
    let api_key_id = new_resource_id("key").as_str().to_owned();
    let now = context.received_at.clone();
    let insert = MachineIdentityRepository::new(database)
        .insert_key_statement(&NewApiKeyInput {
            api_key_id: &api_key_id,
            service_account_id: &account.service_account_id,
            org_id: &org_id,
            name: &body.name,
            key_prefix: &material.key_prefix,
            secret_hash: &material.secret_hash,
            fingerprint: &material.fingerprint,
            capabilities_json: &capabilities.to_json(),
            project_ids_json: project_ids.as_deref(),
            model_aliases_json: model_aliases.as_deref(),
            network_allowlist_json: network_allowlist.as_deref(),
            rotated_from_key_id: None,
            expires_at: body.expires_at.as_deref(),
            now: now.as_str(),
        })
        .map_err(|_| store_unavailable(&context))?;
    // The audit payload carries the prefix and the fingerprint, which identify
    // the key. It does not carry the secret, and there is no code path that could
    // add it: the material is destructured above and the wire value lives only in
    // the response body.
    let audit = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        crate::adapters::new_event_id().as_str(),
        "api_key.created",
        "api_key",
        Some(&api_key_id),
        "success",
        &json!({
            "key_prefix": material.key_prefix,
            "fingerprint": material.fingerprint,
            "service_account_id": account.service_account_id,
        }),
    )?;
    let success = crate::core::StoredSuccess::new(
        StatusCode::CREATED.as_u16(),
        json!({ "api_key_id": api_key_id, "key_prefix": material.key_prefix }),
    )
    .map_err(|_| store_unavailable(&context))?;
    match commit_scoped_mutation(database, &context, claim, success, vec![insert], audit).await? {
        crate::routes::usage::ScopedMutationCommit::Committed => {}
        crate::routes::usage::ScopedMutationCommit::Replayed(replay) => {
            return Ok(replay_response(replay));
        }
        crate::routes::usage::ScopedMutationCommit::Guarded => {
            return Err(database_error(
                &context,
                worker::Error::RustError("guard".into()),
            ));
        }
    }
    let created = MachineIdentityRepository::new(database)
        .find_key(&api_key_id)
        .await
        .map_err(|_| store_unavailable(&context))?
        .ok_or_else(|| store_unavailable(&context))?;
    Ok(json_response(
        &context,
        json!({ "api_key": api_key_json_with_secret(&created, material.wire_value()) }),
    ))
}

/// F14-004. The replacement is created first, and the prior key is marked
/// `rotated` in the same batch. A failed rotation leaves both keys untouched.
#[worker::send]
pub async fn rotate_api_key(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((api_key_id,)): Path<(String,)>,
    Json(body): Json<RotateApiKeyBody>,
) -> Result<Response<Body>, ApiError> {
    let database = database(&state, &context)?;
    // The organization comes from the key row. Nothing in the request can
    // influence it.
    let existing = MachineIdentityRepository::new(database)
        .find_key(&api_key_id)
        .await
        .map_err(|_| store_unavailable(&context))?
        .ok_or_else(|| not_found(&context))?;
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &existing.org_id,
        Permission::ServiceAccountsManage,
        Some("api_key"),
        Some(&api_key_id),
    )
    .await?;
    if existing.is_terminal() {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "key_terminal",
            "This key can no longer be rotated.",
        ));
    }
    if body.reason.trim().is_empty() || body.reason.len() > 500 {
        return Err(invalid_input(&context));
    }
    let key = idempotency_key(&headers, &context)?;
    let replacement_id = new_resource_id("key").as_str().to_owned();
    let Some(material) = mint_material() else {
        return Err(store_unavailable(&context));
    };
    let now = context.received_at.clone();
    let repository = MachineIdentityRepository::new(database);
    let insert = repository
        .insert_key_statement(&NewApiKeyInput {
            api_key_id: &replacement_id,
            service_account_id: &existing.service_account_id,
            org_id: &existing.org_id,
            name: &existing.name,
            key_prefix: &material.key_prefix,
            secret_hash: &material.secret_hash,
            fingerprint: &material.fingerprint,
            capabilities_json: &existing.capabilities_json,
            project_ids_json: existing.project_ids_json.as_deref(),
            model_aliases_json: existing.model_aliases_json.as_deref(),
            network_allowlist_json: existing.network_allowlist_json.as_deref(),
            rotated_from_key_id: Some(&api_key_id),
            expires_at: existing.expires_at.as_deref(),
            now: now.as_str(),
        })
        .map_err(|_| store_unavailable(&context))?;
    // The prior key stops working only after the replacement exists, and it
    // records the reason, which the 0016 trigger refuses to do without.
    let mark = repository
        .mark_key_rotated_statement(
            &api_key_id,
            &existing.org_id,
            &body.reason,
            &replacement_id,
            &now,
        )
        .map_err(|_| store_unavailable(&context))?;
    let audit = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&existing.org_id),
        crate::adapters::new_event_id().as_str(),
        "api_key.rotated",
        "api_key",
        Some(&api_key_id),
        "success",
        &json!({ "replacement_key_id": replacement_id, "reason": body.reason }),
    )?;
    let success = crate::core::StoredSuccess::new(
        StatusCode::OK.as_u16(),
        json!({ "api_key_id": replacement_id }),
    )
    .map_err(|_| store_unavailable(&context))?;
    let claim = match prepare_scoped_mutation(
        database,
        &context,
        access.principal.user_id.as_str(),
        &existing.org_id,
        &key,
        "POST",
        API_KEY_ROTATE_PATH,
        &json!({ "api_key_id": api_key_id, "reason": body.reason }),
    )
    .await?
    {
        PreparedScopedMutation::Replay(replay) => return Ok(replay_response(replay)),
        PreparedScopedMutation::Claim(claim) => claim,
    };
    match commit_scoped_mutation(
        database,
        &context,
        claim,
        success,
        vec![insert, mark],
        audit,
    )
    .await?
    {
        crate::routes::usage::ScopedMutationCommit::Committed => {}
        crate::routes::usage::ScopedMutationCommit::Replayed(replay) => {
            return Ok(replay_response(replay));
        }
        crate::routes::usage::ScopedMutationCommit::Guarded => {
            return Err(domain_error(
                &context,
                ApiErrorCode::Conflict,
                "key_terminal",
                "This key can no longer be rotated.",
            ));
        }
    }
    let replacement = repository
        .find_key(&replacement_id)
        .await
        .map_err(|_| store_unavailable(&context))?
        .ok_or_else(|| store_unavailable(&context))?;
    Ok(json_response(
        &context,
        json!({ "api_key": api_key_json_with_secret(&replacement, material.wire_value()) }),
    ))
}

#[worker::send]
pub async fn revoke_api_key(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((api_key_id,)): Path<(String,)>,
    Json(body): Json<RevokeApiKeyBody>,
) -> Result<Response<Body>, ApiError> {
    let database = database(&state, &context)?;
    let existing = MachineIdentityRepository::new(database)
        .find_key(&api_key_id)
        .await
        .map_err(|_| store_unavailable(&context))?
        .ok_or_else(|| not_found(&context))?;
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &existing.org_id,
        Permission::ServiceAccountsManage,
        Some("api_key"),
        Some(&api_key_id),
    )
    .await?;
    if body.reason.trim().is_empty() || body.reason.len() > 500 {
        return Err(invalid_input(&context));
    }
    let now = context.received_at.clone();
    let repository = MachineIdentityRepository::new(database);
    let revoke = repository
        .revoke_key_statement(
            &api_key_id,
            &existing.org_id,
            &body.reason,
            body.version,
            &now,
        )
        .map_err(|_| store_unavailable(&context))?;
    let guard = repository
        .assert_key_version_statement(&api_key_id, &existing.org_id, body.version)
        .map_err(|_| store_unavailable(&context))?;
    let audit = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&existing.org_id),
        crate::adapters::new_event_id().as_str(),
        "api_key.revoked",
        "api_key",
        Some(&api_key_id),
        "success",
        &json!({ "reason": body.reason, "version": body.version }),
    )?;
    let success = crate::core::StoredSuccess::new(
        StatusCode::OK.as_u16(),
        json!({ "api_key_id": api_key_id }),
    )
    .map_err(|_| store_unavailable(&context))?;
    let claim = match prepare_scoped_mutation(
        database,
        &context,
        access.principal.user_id.as_str(),
        &existing.org_id,
        &idempotency_key(&headers, &context)?,
        "POST",
        API_KEY_REVOKE_PATH,
        &json!({ "api_key_id": api_key_id, "version": body.version, "reason": body.reason }),
    )
    .await?
    {
        PreparedScopedMutation::Replay(replay) => return Ok(replay_response(replay)),
        PreparedScopedMutation::Claim(claim) => claim,
    };
    match commit_scoped_mutation(
        database,
        &context,
        claim,
        success,
        vec![revoke, guard],
        audit,
    )
    .await?
    {
        crate::routes::usage::ScopedMutationCommit::Committed => {}
        crate::routes::usage::ScopedMutationCommit::Replayed(replay) => {
            return Ok(replay_response(replay));
        }
        crate::routes::usage::ScopedMutationCommit::Guarded => {
            return Err(domain_error(
                &context,
                ApiErrorCode::Conflict,
                "version_conflict",
                "The key changed. Refresh and try again.",
            ));
        }
    }
    let revoked = repository
        .find_key(&api_key_id)
        .await
        .map_err(|_| store_unavailable(&context))?
        .ok_or_else(|| store_unavailable(&context))?;
    Ok(json_response(
        &context,
        json!({ "api_key": api_key_json(&revoked) }),
    ))
}

#[worker::send]
pub async fn get_api_key(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((api_key_id,)): Path<(String,)>,
) -> Result<Response<Body>, ApiError> {
    let database = database(&state, &context)?;
    let existing = MachineIdentityRepository::new(database)
        .find_key(&api_key_id)
        .await
        .map_err(|_| store_unavailable(&context))?
        .ok_or_else(|| not_found(&context))?;
    authorize_org(
        &state,
        &headers,
        &context,
        &existing.org_id,
        Permission::ServiceAccountsRead,
        Some("api_key"),
        Some(&api_key_id),
    )
    .await?;
    Ok(json_response(
        &context,
        json!({ "api_key": api_key_json(&existing) }),
    ))
}

// -------------------------------------------------------- P07-INT-02 -------
//
// The headless machine identity path. This is the only route in P07 that a
// machine credential can reach, and it exists to prove the third actor kind
// works end to end without a human session anywhere in the request.

/// `GET /api/v1/machine/whoami` — the credential's own identity and scope.
///
/// A deliberately small surface. It answers "which credential am I, which
/// organization do I belong to, and what may I do", which is the first thing a
/// CI job needs and the minimum that can be served without trusting the caller.
/// It reads nothing about another tenant, and it returns no secret.
#[worker::send]
pub async fn machine_whoami(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiError> {
    let database = database(&state, &context)?;
    let authenticated = require_machine(&state, &headers, &context).await?;
    let organization = crate::repositories::OrganizationRepository::new(database)
        .find_organization(authenticated.actor.organization_id.as_str())
        .await
        .map_err(|_| store_unavailable(&context))?
        .ok_or_else(|| not_found(&context))?;
    let organization_context = organization_context(&organization, &context)?;
    // The decision is made with the SAME function every machine-protected route
    // uses, with a target that has no project and no model alias. A key scoped
    // to one project therefore cannot even read its own identity, which is
    // correct: it is not entitled to act on anything at all.
    let decision = authorize_machine(
        &authenticated.actor,
        authenticated.state,
        &organization_context,
        &authenticated.scope,
        &Permission::OrgRead,
        MachineRequest {
            resource_organization: Some(&authenticated.actor.organization_id),
            client_ip: None,
            ..MachineRequest::default()
        },
    );
    if let MachineDecision::Deny(reason) = decision {
        return Err(machine_denial(&context, reason));
    }
    let capabilities = authenticated
        .scope
        .capabilities
        .iter()
        .map(|permission| permission.as_str())
        .collect::<Vec<_>>();
    let body = json!({
        "actor": "machine",
        "api_key_id": authenticated.actor.api_key_id,
        "service_account_id": authenticated.actor.service_account_id,
        "organization_id": authenticated.actor.organization_id,
        "key_prefix": authenticated.actor.key_prefix,
        "capabilities": capabilities,
        "project_scoped": authenticated.scope.project_ids.is_some(),
        "network_restricted": authenticated.scope.network_allowlist.is_some(),
    });
    let _ = &database;
    Ok(json_response(&context, body))
}

/// Turn a machine denial into the stable envelope. `kill_switch_active` is kept
/// distinct from `scope_denied` so an operator reading the log knows whether to
/// widen the key's scope or clear a platform switch.
pub(crate) fn machine_denial(context: &RequestContext, reason: MachineDenyReason) -> ApiError {
    let code = match reason {
        MachineDenyReason::AuthenticationRequired
        | MachineDenyReason::MachineKeyRevoked
        | MachineDenyReason::MachineKeyExpired
        | MachineDenyReason::MachineKeySuspended
        | MachineDenyReason::ScopeDenied
        | MachineDenyReason::ScopeProjectMismatch
        | MachineDenyReason::ScopeNetworkUnavailable
        | MachineDenyReason::ScopeNetworkDenied
        | MachineDenyReason::ScopeModelDenied
        | MachineDenyReason::ResourceScopeMismatch => ApiErrorCode::AuthenticationRequired,
        MachineDenyReason::HumanOnlyAction
        | MachineDenyReason::OrganizationSuspended
        | MachineDenyReason::OrganizationPendingDeletion
        | MachineDenyReason::KillSwitchActive => ApiErrorCode::PermissionDenied,
        MachineDenyReason::OrganizationDeleted => ApiErrorCode::NotFound,
    };
    let message = match code {
        ApiErrorCode::AuthenticationRequired => "Authentication is required.",
        ApiErrorCode::NotFound => "The requested resource was not found.",
        _ => "You do not have permission to perform this action.",
    };
    errors::api_error(context, code, message).with_detail("reason", json!(reason.code()))
}

/// Read an organization state for a machine decision without a human principal.
pub(crate) fn organization_context(
    organization: &crate::repositories::OrganizationRecord,
    context: &RequestContext,
) -> Result<crate::modules::authorization::OrganizationContext, ApiError> {
    // An unrecognised stored state or id is reported as unavailable rather than
    // as "active". A store that has drifted is not a store this path should
    // authorize anything against.
    let organization_id =
        OrganizationId::new(organization.org_id.clone()).map_err(|_| store_unavailable(context))?;
    let state = crate::modules::authorization::OrganizationState::parse(&organization.state)
        .ok_or_else(|| store_unavailable(context))?;
    Ok(crate::modules::authorization::OrganizationContext {
        organization_id,
        state,
        version: organization.version,
    })
}

// ------------------------------------------------------------- helpers -----

async fn find_account(
    database: &crate::adapters::d1::D1Adapter,
    service_account_id: &str,
    org_id: &str,
    context: &RequestContext,
) -> Result<ServiceAccountRecord, ApiError> {
    MachineIdentityRepository::new(database)
        .find_service_account(service_account_id, org_id)
        .await
        .map_err(|_| store_unavailable(context))?
        .ok_or_else(|| not_found(context))
}

fn parse_capabilities(
    values: &[String],
    context: &RequestContext,
) -> Result<CapabilitySet, ApiError> {
    let json = serde_json::to_string(values).map_err(|_| invalid_input(context))?;
    CapabilitySet::parse(&json).map_err(|error| identity_error(context, error))
}

fn identity_error(context: &RequestContext, error: MachineIdentityError) -> ApiError {
    let code = match error {
        MachineIdentityError::CapabilityUnknown | MachineIdentityError::CapabilityHumanOnly => {
            ApiErrorCode::ValidationFailed
        }
        MachineIdentityError::ScopeExceedsAccount
        | MachineIdentityError::KeyLimitReached
        | MachineIdentityError::KeyTerminal => ApiErrorCode::Conflict,
        MachineIdentityError::InvalidInput | MachineIdentityError::StoreUnreadable => {
            ApiErrorCode::ValidationFailed
        }
    };
    domain_error(
        context,
        code,
        error.code(),
        "The request contains invalid fields.",
    )
}

/// Mint the key material. Fails closed rather than falling back to a weaker
/// source: a credential derived from anything but the platform CSPRNG is not a
/// credential this product should issue.
fn mint_material() -> Option<MachineKeyMaterial> {
    // 32 bytes of base64url-decodable entropy. `new_secret` is the platform
    // CSPRNG on target and a deterministic stub in host tests; neither is a
    // production path for a real credential because neither route is reachable
    // without a Worker.
    let bytes = decode_hex32(&new_secret())?;
    MachineKeyMaterial::from_random_bytes(&bytes)
}

fn decode_hex32(value: &str) -> Option<Vec<u8>> {
    if value.len() < 64 {
        return None;
    }
    (0..32)
        .map(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok())
        .collect()
}

fn validate_name(name: &str, context: &RequestContext) -> Result<(), ApiError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > 120 {
        return Err(invalid_input(context));
    }
    Ok(())
}

fn bounded(value: &str, max: usize, context: &RequestContext) -> Result<String, ApiError> {
    if value.len() > max {
        return Err(invalid_input(context));
    }
    Ok(value.to_owned())
}

fn optional_text_list(
    values: Option<&[String]>,
    context: &RequestContext,
) -> Result<Option<String>, ApiError> {
    let Some(values) = values else {
        return Ok(None);
    };
    for value in values {
        if value.is_empty() || value.len() > 300 {
            return Err(invalid_input(context));
        }
    }
    let mut sorted: Vec<String> = values.to_vec();
    sorted.sort();
    sorted.dedup();
    Ok(Some(
        serde_json::to_string(&sorted).map_err(|_| invalid_input(context))?,
    ))
}

/// `project_ids` keeps the null-vs-empty distinction the whole scope model rests
/// on: `null` is "every project in the organization" and `[]` is "no project".
fn optional_id_list(
    values: Option<&[String]>,
    prefix: &str,
    context: &RequestContext,
) -> Result<Option<String>, ApiError> {
    let Some(values) = values else {
        return Ok(None);
    };
    let mut sorted = Vec::with_capacity(values.len());
    for value in values {
        if !value.starts_with(prefix) || value.len() != 36 {
            return Err(invalid_input(context));
        }
        sorted.push(value.to_owned());
    }
    sorted.sort();
    sorted.dedup();
    Ok(Some(
        serde_json::to_string(&sorted).map_err(|_| invalid_input(context))?,
    ))
}

fn raw_string_list(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or(Value::Array(Vec::new()))
}

fn decode_cursor(
    cursor: Option<&str>,
    context: &RequestContext,
) -> Result<(Option<String>, Option<String>), ApiError> {
    let Some(cursor) = cursor.filter(|value| !value.is_empty()) else {
        return Ok((None, None));
    };
    let parts: Vec<&str> = cursor.split('|').collect();
    if parts.len() != 2 || parts.iter().any(|part| part.len() > 40) {
        return Err(invalid_input(context));
    }
    Ok((Some(parts[0].to_owned()), Some(parts[1].to_owned())))
}

fn page_of<T>(
    mut rows: Vec<T>,
    limit: i32,
    cursor_of: impl Fn(&T) -> (String, String),
) -> (Vec<T>, Option<String>) {
    let has_more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next = if has_more {
        rows.last().map(|row| {
            let (created_at, id) = cursor_of(row);
            format!("{created_at}|{id}")
        })
    } else {
        None
    };
    (rows, next)
}

fn json_response(context: &RequestContext, body: Value) -> Response<Body> {
    let response = (StatusCode::OK, Json(body)).into_response();
    let _ = context;
    response
}

fn not_found(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::NotFound,
        "resource_not_found",
        "The requested resource was not found.",
    )
}

fn invalid_input(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::ValidationFailed,
        "invalid_input",
        "The request contains invalid fields.",
    )
}

fn store_unavailable(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::ServiceUnavailable,
        "The identity store is unavailable.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::core::ApiErrorCode;
    use crate::repositories::{ApiKeyRecord, ServiceAccountRecord};

    fn context() -> RequestContext {
        RequestContext::new(
            "req_0123456789abcdef0123456789abcdef".parse().unwrap(),
            crate::core::CorrelationId::new("trace-p07").unwrap(),
            "2026-09-26T12:00:00.000Z".parse().unwrap(),
        )
    }

    fn account() -> ServiceAccountRecord {
        ServiceAccountRecord {
            service_account_id: "svc_0123456789abcdef0123456789abcdef".to_owned(),
            org_id: "org_0123456789abcdef0123456789abcdef".to_owned(),
            name: "ci-deploy".to_owned(),
            description: Some("Deploys releases from CI.".to_owned()),
            capabilities_json: r#"["runs.start","runs.read"]"#.to_owned(),
            created_by_principal: "usr_0123456789abcdef0123456789abcdef".to_owned(),
            status: "active".to_owned(),
            expires_at: None,
            suspended_at: None,
            suspend_reason: None,
            version: 1,
            created_at: "2026-09-26T12:00:00.000Z".to_owned(),
            updated_at: "2026-09-26T12:00:00.000Z".to_owned(),
        }
    }

    fn key() -> ApiKeyRecord {
        ApiKeyRecord {
            api_key_id: "key_0123456789abcdef0123456789abcdef".to_owned(),
            service_account_id: "svc_0123456789abcdef0123456789abcdef".to_owned(),
            org_id: "org_0123456789abcdef0123456789abcdef".to_owned(),
            name: "ci-deploy".to_owned(),
            key_prefix: "0f1e2d3c4b5a".to_owned(),
            secret_hash: "a".repeat(64),
            fingerprint: "0f1e2d3c4b5a6f70".to_owned(),
            capabilities_json: r#"["runs.start"]"#.to_owned(),
            project_ids_json: Some(r#"["prj_0123456789abcdef0123456789abcdef"]"#.to_owned()),
            model_aliases_json: Some(r#"["coding-default"]"#.to_owned()),
            network_allowlist_json: Some(r#"["*.ci.trusted.example"]"#.to_owned()),
            status: "active".to_owned(),
            rotated_from_key_id: None,
            rotated_to_key_id: None,
            last_used_at: Some("2026-09-26T13:00:00.000Z".to_owned()),
            last_used_source: Some("ip:203.0.113.10".to_owned()),
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            version: 1,
            created_at: "2026-09-26T12:00:00.000Z".to_owned(),
            updated_at: "2026-09-26T12:00:00.000Z".to_owned(),
        }
    }

    fn reason_of(error: &ApiError) -> String {
        error.error.details["reason"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }

    /// F14-002, structurally. The list, get, and audit projections have no
    /// parameter that could carry a secret and no field for one, so this is not a
    /// convention a future edit can quietly break.
    #[test]
    fn no_read_projection_can_carry_a_credential() {
        // `json_response` wraps a projection without touching it — `(StatusCode,
        // Json(body))` and nothing else — so asserting on the projections is
        // asserting on the bodies. The alternative is reading the body back
        // through the HTTP layer, which would need a `block_on` shim in a module
        // that has no async work to block on.
        for projection in [
            service_account_json(&account()).to_string(),
            api_key_json(&key()).to_string(),
        ] {
            for field in ["\"secret\"", "secret_hash", "wire_value"] {
                assert!(
                    !projection.contains(field),
                    "{field} reached a read projection"
                );
            }
            // The hash is in the record, so its absence is the real assertion.
            assert!(!projection.contains(&"a".repeat(64)));
            // A `key` field would be the raw value under a friendly name.
            assert!(!projection.contains("\"key\":"));
        }
    }

    #[test]
    fn the_secret_projection_carries_it_once_with_a_notice() {
        let secret = "lumik_0f1e2d3c4b5a_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v";
        let projection = api_key_json_with_secret(&key(), secret);
        assert_eq!(projection["secret"], secret);
        assert!(
            projection["secret_notice"]
                .as_str()
                .is_some_and(|notice| notice.contains("shown once")),
        );
        // Exactly once: the create response must not also carry it under a second
        // name, and every other key field must match the metadata projection.
        assert_eq!(
            projection.as_object().expect("object").len(),
            api_key_json(&key()).as_object().expect("object").len() + 2
        );
        let mut metadata = api_key_json(&key());
        metadata
            .as_object_mut()
            .expect("object")
            .remove("secret")
            .map(|_| ())
            .unwrap_or_default();
        assert!(metadata.get("secret").is_none());
    }

    #[test]
    fn a_null_scope_column_stays_null_and_never_becomes_an_empty_list() {
        // `null` is "every project" and `[]` is "no project". Collapsing them is
        // how a key that should reach everything ends up reaching nothing, or the
        // reverse, so the distinction has to survive the projection.
        let mut unrestricted = key();
        unrestricted.project_ids_json = None;
        assert_eq!(api_key_json(&unrestricted)["project_ids"], Value::Null);
        let mut none = key();
        none.project_ids_json = Some("[]".to_owned());
        assert_eq!(api_key_json(&none)["project_ids"], json!([]));
        // A column that is not JSON at all must not become a silent empty list
        // presented as a deliberate "no scope".
        let mut corrupt = key();
        corrupt.model_aliases_json = Some("{not json".to_owned());
        assert_eq!(api_key_json(&corrupt)["model_aliases"], json!([]));
    }

    #[test]
    fn a_human_only_capability_is_refused_with_its_own_reason_not_a_generic_one() {
        let context = context();
        // The gate's decision 2: five human-only permissions, refused before scope
        // is consulted. The reason string is what a client branches on, so an
        // unknown capability and a human-only one must not collapse into one.
        let human_only = parse_capabilities(&["org.lifecycle".to_owned()], &context)
            .expect_err("a human-only capability is refused");
        assert_eq!(reason_of(&human_only), "capability_human_only");
        assert_eq!(human_only.error.code, ApiErrorCode::ValidationFailed);

        let unknown = parse_capabilities(&["runs.teleport".to_owned()], &context)
            .expect_err("an unknown capability is refused");
        assert_eq!(reason_of(&unknown), "capability_unknown");
        assert_ne!(reason_of(&unknown), reason_of(&human_only));
    }

    #[test]
    fn the_domain_error_status_distinguishes_a_conflict_from_a_bad_request() {
        let context = context();
        // A key limit is a conflict the caller can resolve; a malformed field is
        // not. Both carry a reason, so the HTTP status has to carry the rest.
        for error in [
            MachineIdentityError::KeyLimitReached,
            MachineIdentityError::KeyTerminal,
            MachineIdentityError::ScopeExceedsAccount,
        ] {
            let mapped = identity_error(&context, error);
            assert_eq!(
                mapped.error.code,
                ApiErrorCode::Conflict,
                "{}",
                error.code()
            );
        }
        for error in [
            MachineIdentityError::InvalidInput,
            MachineIdentityError::CapabilityUnknown,
            MachineIdentityError::CapabilityHumanOnly,
            MachineIdentityError::StoreUnreadable,
        ] {
            let mapped = identity_error(&context, error);
            assert_eq!(
                mapped.error.code,
                ApiErrorCode::ValidationFailed,
                "{}",
                error.code()
            );
        }
    }

    #[test]
    fn a_scoped_id_list_refuses_anything_that_is_not_that_id_type() {
        let context = context();
        // `project_ids` is a scope boundary, so a value that is not a project id
        // must be refused rather than stored and later resolved.
        assert!(
            optional_id_list(None, "prj_", &context)
                .expect("an absent list is absent")
                .is_none()
        );
        assert!(
            optional_id_list(Some(&[]), "prj_", &context)
                .expect("an empty list is a real scope")
                .is_some_and(|raw| raw == "[]")
        );
        for bad in [
            "org_0123456789abcdef0123456789abcdef",
            "*",
            "prj_short",
            "prj_0123456789abcdef0123456789abcdef_extra",
        ] {
            assert!(
                optional_id_list(Some(&[bad.to_owned()]), "prj_", &context).is_err(),
                "{bad} is not a project id"
            );
        }
        // A duplicate is one scope stated twice, not two, so the stored column is
        // deduplicated and ordered — which is what makes an unchanged PATCH a
        // genuine no-op rather than a new version and a new audit entry.
        let sorted = optional_id_list(
            Some(&[
                "prj_ffffffffffffffffffffffffffffffff".to_owned(),
                "prj_0123456789abcdef0123456789abcdef".to_owned(),
                "prj_0123456789abcdef0123456789abcdef".to_owned(),
            ]),
            "prj_",
            &context,
        )
        .expect("valid ids");
        assert_eq!(
            sorted.as_deref(),
            Some(
                r#"["prj_0123456789abcdef0123456789abcdef","prj_ffffffffffffffffffffffffffffffff"]"#
            )
        );
    }

    #[test]
    fn a_text_list_refuses_an_empty_or_over_long_entry() {
        let context = context();
        assert!(
            optional_text_list(Some(&[String::new()]), &context).is_err(),
            "an empty allowlist entry is a wildcard with no host"
        );
        assert!(optional_text_list(Some(&["x".repeat(301)]), &context).is_err());
        assert!(
            optional_text_list(Some(&["*.ci.trusted.example".to_owned()]), &context).is_ok(),
            "a strict-subdomain pattern is a host, not a wildcard with no host"
        );
    }

    #[test]
    fn a_name_must_be_present_and_bounded() {
        let context = context();
        // Whitespace is not a name. A credential called " " sorts to the top of a
        // list and tells an operator nothing about what it may do.
        for bad in ["", "   ", "\t\n"] {
            assert!(
                validate_name(bad, &context).is_err(),
                "{bad:?} is not a name"
            );
        }
        assert!(validate_name(&"x".repeat(121), &context).is_err());
        assert!(validate_name("ci-deploy", &context).is_ok());
    }

    #[test]
    fn key_material_is_minted_or_nothing_is() {
        // `mint_material` fails closed rather than falling back to a weaker
        // source: a credential derived from anything but the platform CSPRNG is
        // not a credential this product should issue. The host stub is
        // deterministic, so the assertions are about shape, not entropy.
        let Some(material) = mint_material() else {
            return;
        };
        assert_eq!(material.key_prefix.len(), 12);
        assert!(
            material
                .key_prefix
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_eq!(material.secret_hash.len(), 64);
        assert_eq!(material.fingerprint.len(), 16);
        // The two hashes cover different inputs on purpose: one answers "is this
        // the right secret", the other "which key was this".
        assert_ne!(material.secret_hash, material.fingerprint);
        assert!(material.wire_value().starts_with("lumik_"));
    }

    #[test]
    fn the_cursor_decoder_refuses_a_cursor_it_cannot_attribute() {
        let context = context();
        assert_eq!(decode_cursor(None, &context).expect("absent"), (None, None));
        assert_eq!(
            decode_cursor(Some(""), &context).expect("empty"),
            (None, None)
        );
        // A malformed cursor is refused rather than ignored, because ignoring it
        // would silently restart pagination at page one under a cursor the caller
        // still believes it is holding.
        assert!(decode_cursor(Some("not-a-cursor"), &context).is_err());
    }
}
