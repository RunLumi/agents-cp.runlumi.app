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
        add_seconds,
        crypto::{CREDENTIAL_KEY_VERSION, encrypt_secret, fingerprint_secret, masked_fingerprint},
        new_resource_id, sha256_hex,
    },
    app::AppState,
    core::{
        ActorId, ApiError, ApiErrorCode, IdempotencyKeyDigest, IdempotencyRecord, IdempotencyScope,
        IdempotencyState, OrganizationId, RequestContext, RequestFingerprint, StoredSuccess,
        Timestamp,
    },
    http::auth::require_csrf,
    modules::{
        authorization::Permission,
        catalog::{
            CatalogLifecycle, CatalogPolicy, ModelCapabilities, ModelCapability, ModelDescriptor,
            ProviderDescriptor,
        },
        credentials::{CredentialMode, CredentialOwnerType, CredentialStatus},
        routing::{
            RouteConfig, RouteSelectionError, RouteStrategy, select_candidates,
            validate_route_config,
        },
    },
    repositories::{
        AiRepository, CredentialRecord, IdempotencyClaimToken, IdempotencyLookup,
        IdempotencyRepository, ModelRecord, PolicyRecord, ProviderRecord, RouteRecord,
        RouteVersionRecord,
    },
    routes::{
        authorization::authorize_org,
        errors,
        support::{
            database, database_error, deterministic_resource_id, domain_error, idempotency_key,
            outbox_statement, security_event_statement,
        },
    },
};

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<u16>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PageResponse<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Deserialize)]
pub struct CreateProviderRequest {
    pub provider_key: String,
    pub display_name: String,
    pub adapter: String,
    pub endpoint_url: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateModelRequest {
    pub provider_id: String,
    pub provider_model_id: String,
    pub display_name: String,
    pub capabilities: Vec<String>,
    pub max_input_tokens: Option<u32>,
    pub max_output_tokens: Option<u32>,
    pub pricing_version: Option<String>,
}

#[derive(Deserialize)]
pub struct LifecycleRequest {
    pub lifecycle: String,
    pub version: i64,
}

#[derive(Deserialize)]
pub struct PolicyRequest {
    pub allowed_aliases: Vec<String>,
    pub allowed_models: Vec<String>,
    pub allowed_providers: Vec<String>,
    pub credential_mode: String,
    pub managed_route_enabled: bool,
    pub version: i64,
}

#[derive(Deserialize)]
pub struct CreateCredentialRequest {
    pub provider_id: String,
    pub owner_type: String,
    pub label: String,
    pub secret: Option<String>,
}

#[derive(Deserialize)]
pub struct RotateCredentialRequest {
    pub label: Option<String>,
    pub secret: Option<String>,
}

#[derive(Deserialize)]
pub struct RevokeCredentialRequest {
    pub version: i64,
}

#[derive(Deserialize)]
pub struct CreateRouteRequest {
    pub alias: String,
    pub display_name: String,
    pub strategy: String,
    pub config: RouteConfig,
}

#[derive(Deserialize)]
pub struct PublishRouteRequest {
    pub version: i64,
    pub config: RouteConfig,
}

#[derive(Deserialize)]
pub struct RollbackRouteRequest {
    pub version: i64,
}

#[derive(Serialize)]
struct CredentialResponse {
    credential: Value,
    duplicate: bool,
}

#[derive(Serialize)]
struct RouteResponse {
    route: Value,
    version: Option<Value>,
    duplicate: bool,
}

#[worker::send]
pub async fn catalog(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    let _access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ModelsRead,
        Some("provider"),
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let repository = AiRepository::new(database);
    let mut providers = repository
        .list_providers(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    if state.environment != "development" {
        providers.retain(|provider| provider.adapter != "mock");
    }
    let mut models = repository
        .list_models(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    models.retain(|model| {
        providers
            .iter()
            .any(|provider| provider.provider_id == model.provider_id)
    });
    let aliases = repository
        .list_aliases()
        .await
        .map_err(|error| database_error(&context, error))?;
    let mut health = repository
        .list_health(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    health.retain(|record| {
        providers
            .iter()
            .any(|provider| provider.provider_id == record.provider_id)
    });
    Ok(Json(json!({
        "catalog_version": "p04-cg-v1",
        "providers": providers.iter().map(|provider| provider_json(provider, false)).collect::<Result<Vec<_>, _>>()?,
        "models": models.iter().map(|model| model_json(model, &context)).collect::<Result<Vec<_>, _>>()?,
        "aliases": aliases.iter().map(alias_json).collect::<Vec<_>>(),
        "health": health.iter().map(|record| json!({"provider_id": record.provider_id, "state": record.state, "cooldown_until": record.cooldown_until, "last_error_code": record.last_error_code, "success_count": record.success_count, "failure_count": record.failure_count, "timeout_count": record.timeout_count, "rate_limit_count": record.rate_limit_count, "sample_count": record.sample_count, "ttft_ms_total": record.ttft_ms_total, "completion_latency_ms_total": record.completion_latency_ms_total, "updated_at": record.updated_at})).collect::<Vec<_>>(),
    }))
    .into_response())
}

#[worker::send]
pub async fn get_policy(
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
        Permission::ModelsRead,
        Some("policy"),
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let policy = AiRepository::new(database)
        .find_policy(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(Json(policy.map_or_else(
        || default_policy_json(&org_id, &context),
        |value| policy_json(&value),
    ))
    .into_response())
}

#[worker::send]
pub async fn update_policy(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<PolicyRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ModelsManage,
        Some("policy"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    validate_policy_values(&body.allowed_aliases, &context, "alias")?;
    validate_policy_values(&body.allowed_models, &context, "model")?;
    validate_policy_values(&body.allowed_providers, &context, "provider")?;
    let mode = CredentialMode::parse(&body.credential_mode).ok_or_else(|| {
        validation_error(
            &context,
            "credential_mode_invalid",
            "Choose a valid credential mode.",
        )
    })?;
    if body.version < 0 {
        return Err(validation_error(
            &context,
            "version_invalid",
            "Reload the policy.",
        ));
    }
    let aliases_json = serde_json::to_string(&body.allowed_aliases)
        .map_err(|_| validation_error(&context, "policy_invalid", "The policy is invalid."))?;
    let models_json = serde_json::to_string(&body.allowed_models)
        .map_err(|_| validation_error(&context, "policy_invalid", "The policy is invalid."))?;
    let providers_json = serde_json::to_string(&body.allowed_providers)
        .map_err(|_| validation_error(&context, "policy_invalid", "The policy is invalid."))?;
    let fingerprint_input = format!(
        "PUT\\n/api/v1/orgs/{org_id}/policy\\n{}:{aliases_json}:{models_json}:{providers_json}:{}:{}",
        body.version,
        mode.as_str(),
        body.managed_route_enabled
    );
    let database = database(&state, &context)?;
    let policy_path = format!("/api/v1/orgs/{org_id}/policy");
    if let Some(success) = lookup_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "PUT",
        &policy_path,
        &fingerprint_input,
        database,
        &context,
    )
    .await?
    {
        return Ok(replay_response(&success));
    }
    let repository = AiRepository::new(database);
    let current = repository
        .find_policy(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    let expected_policy = current.as_ref().map_or_else(
        || PolicyRecord {
            org_id: org_id.clone(),
            policy_version: 1,
            allowed_aliases_json: aliases_json.clone(),
            allowed_models_json: models_json.clone(),
            allowed_providers_json: providers_json.clone(),
            credential_mode: mode.as_str().to_owned(),
            managed_route_enabled: body.managed_route_enabled,
            version: 1,
            created_at: context.received_at.as_str().to_owned(),
            updated_at: context.received_at.as_str().to_owned(),
        },
        |current| PolicyRecord {
            org_id: current.org_id.clone(),
            policy_version: current.policy_version + 1,
            allowed_aliases_json: aliases_json.clone(),
            allowed_models_json: models_json.clone(),
            allowed_providers_json: providers_json.clone(),
            credential_mode: mode.as_str().to_owned(),
            managed_route_enabled: body.managed_route_enabled,
            version: current.version + 1,
            created_at: current.created_at.clone(),
            updated_at: context.received_at.as_str().to_owned(),
        },
    );
    let statement = if let Some(current) = current.as_ref() {
        if body.version != current.version {
            return Err(domain_error(
                &context,
                ApiErrorCode::Conflict,
                "version_conflict",
                "The policy changed. Refresh and try again.",
            ));
        }
        repository
            .update_policy_statement(
                &org_id,
                body.version,
                &aliases_json,
                &models_json,
                &providers_json,
                mode.as_str(),
                body.managed_route_enabled,
                &context.received_at,
            )
            .map_err(|error| database_error(&context, error))?
    } else {
        if body.version != 0 {
            return Err(domain_error(
                &context,
                ApiErrorCode::Conflict,
                "version_conflict",
                "The policy changed. Refresh and try again.",
            ));
        }
        repository
            .insert_policy_statement(
                &org_id,
                &aliases_json,
                &models_json,
                &providers_json,
                mode.as_str(),
                body.managed_route_enabled,
                &context.received_at,
            )
            .map_err(|error| database_error(&context, error))?
    };
    let version_guard = if current.is_some() {
        repository
            .assert_policy_version_statement(&org_id, body.version)
            .map_err(|error| database_error(&context, error))?
    } else {
        repository
            .assert_policy_absent_statement(&org_id)
            .map_err(|error| database_error(&context, error))?
    };
    let mutation = begin_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "PUT",
        &policy_path,
        &fingerprint_input,
        database,
        &context,
    )
    .await?;
    let pending = match mutation {
        MutationClaim::Replay(success) => return Ok(replay_response(&success)),
        MutationClaim::Pending(pending) => pending,
    };
    let metadata = json!({"credential_mode": mode.as_str(), "managed_route_enabled": body.managed_route_enabled});
    let security = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        &generated_id("sec"),
        "model_policy.updated.v1",
        "policy",
        Some(&org_id),
        "success",
        &metadata,
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "model_policy.updated.v1",
        &metadata,
    )?;
    let success = StoredSuccess::new(200, policy_json(&expected_policy))
        .map_err(|_| internal_error(&context))?;
    let results = commit_mutation(
        database,
        &pending,
        &context.received_at,
        &success,
        vec![version_guard, statement, security],
        outbox,
    )
    .await
    .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[3]).unwrap_or_default() != 1 {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The policy changed. Refresh and try again.",
        ));
    }
    Ok(replay_response(&success))
}

#[worker::send]
pub async fn create_provider(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<CreateProviderRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ModelsManage,
        Some("provider"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let provider_key = normalize_key(&body.provider_key).ok_or_else(|| {
        validation_error(
            &context,
            "provider_key_invalid",
            "Choose a valid provider key.",
        )
    })?;
    let display_name = bounded_name(&body.display_name).ok_or_else(|| {
        validation_error(
            &context,
            "display_name_invalid",
            "Enter a valid provider name.",
        )
    })?;
    let adapter =
        crate::adapters::providers::AdapterKind::parse(&body.adapter).ok_or_else(|| {
            validation_error(
                &context,
                "adapter_invalid",
                "Choose a supported provider adapter.",
            )
        })?;
    let endpoint = body.endpoint_url.as_deref().ok_or_else(|| {
        validation_error(
            &context,
            "endpoint_required",
            "Configure a provider endpoint.",
        )
    })?;
    if adapter == crate::adapters::providers::AdapterKind::Mock
        && state.environment != "development"
    {
        return Err(validation_error(
            &context,
            "adapter_unavailable",
            "This provider adapter is unavailable.",
        ));
    }
    crate::adapters::providers::validate_endpoint_url(
        endpoint,
        &state.provider_allowlist,
        state.environment == "development",
    )
    .map_err(|_| {
        domain_error(
            &context,
            ApiErrorCode::PermissionDenied,
            "ssrf_blocked",
            "The provider endpoint is not allowed.",
        )
    })?;
    let database = database(&state, &context)?;
    let create_path = format!("/api/v1/orgs/{org_id}/catalog/providers");
    let fingerprint_input = format!(
        "POST\\n{create_path}\\n{provider_key}:{display_name}:{}:{endpoint}",
        body.adapter
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
    let provider_id = deterministic_resource_id(
        "prv",
        &key,
        &format!("provider:{org_id}:{provider_key}"),
        &context,
    )
    .await?;
    let endpoint_id = deterministic_resource_id(
        "pe",
        &key,
        &format!("provider-endpoint:{provider_id}"),
        &context,
    )
    .await?;
    let repository = AiRepository::new(database);
    if let Some(existing) = repository
        .find_provider(&provider_id, &org_id)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        if existing.provider_key != provider_key
            || existing.display_name != display_name
            || existing.adapter != body.adapter
            || existing.endpoint_url.as_deref() != Some(endpoint)
        {
            return Err(domain_error(
                &context,
                ApiErrorCode::Conflict,
                "idempotency_conflict",
                "The idempotency key was already used for a different request.",
            ));
        }
        return Ok((
            StatusCode::OK,
            Json(json!({"provider": provider_json(&existing, true)?})),
        )
            .into_response());
    }
    let expected = ProviderRecord {
        provider_id: provider_id.clone(),
        org_id: Some(org_id.clone()),
        provider_key: provider_key.clone(),
        display_name: display_name.clone(),
        adapter: body.adapter.clone(),
        lifecycle: "active".to_owned(),
        version: 1,
        created_by_user_id: Some(access.principal.user_id.as_str().to_owned()),
        created_at: context.received_at.as_str().to_owned(),
        updated_at: context.received_at.as_str().to_owned(),
        endpoint_id: Some(endpoint_id.clone()),
        endpoint_url: Some(endpoint.to_owned()),
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
    let success = StoredSuccess::new(201, json!({"provider": provider_json(&expected, true)?}))
        .map_err(|_| internal_error(&context))?;
    let event_id = generated_id("sec");
    let provider_statement = repository
        .insert_provider_statement(
            &provider_id,
            Some(&org_id),
            &provider_key,
            &display_name,
            &body.adapter,
            Some(access.principal.user_id.as_str()),
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let endpoint_statement = repository
        .insert_endpoint_statement(&endpoint_id, &provider_id, endpoint, &context.received_at)
        .map_err(|error| database_error(&context, error))?;
    let metadata = json!({"provider_key": provider_key, "adapter": body.adapter});
    let security = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        &event_id,
        "model_catalog.provider_created.v1",
        "provider",
        Some(&provider_id),
        "success",
        &metadata,
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "model_catalog.provider_created.v1",
        &metadata,
    )?;
    let results = commit_mutation(
        database,
        &pending,
        &context.received_at,
        &success,
        vec![provider_statement, endpoint_statement, security],
        outbox,
    )
    .await
    .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[2]).unwrap_or_default() != 1 {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "idempotency_conflict",
            "The provider could not be created.",
        ));
    }
    Ok(replay_response(&success))
}

#[worker::send]
pub async fn update_provider_lifecycle(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, provider_id)): Path<(String, String)>,
    Json(body): Json<LifecycleRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ModelsManage,
        Some("provider"),
        Some(&provider_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let lifecycle = CatalogLifecycle::parse(&body.lifecycle).ok_or_else(|| {
        validation_error(
            &context,
            "lifecycle_invalid",
            "Choose a valid provider lifecycle.",
        )
    })?;
    if body.version < 1 {
        return Err(validation_error(
            &context,
            "version_invalid",
            "Reload the provider.",
        ));
    }
    let database = database(&state, &context)?;
    let repository = AiRepository::new(database);
    let lifecycle_path = format!("/api/v1/orgs/{org_id}/catalog/providers/{provider_id}/lifecycle");
    let lifecycle_fingerprint = format!("provider:{}:{}", body.version, lifecycle.as_str());
    if let Some(success) = lookup_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &lifecycle_path,
        &lifecycle_fingerprint,
        database,
        &context,
    )
    .await?
    {
        return Ok(replay_response(&success));
    }
    let current = repository
        .find_provider(&provider_id, &org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .filter(|provider| provider.org_id.as_deref() == Some(org_id.as_str()))
        .ok_or_else(|| not_found(&context, "The provider was not found."))?;
    if body.version != current.version {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The provider changed. Refresh and try again.",
        ));
    }
    if current.lifecycle == "disabled" {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "lifecycle_terminal",
            "A disabled provider cannot be re-enabled.",
        ));
    }
    let mut expected = current.clone();
    expected.lifecycle = lifecycle.as_str().to_owned();
    expected.version += 1;
    expected.updated_at = context.received_at.as_str().to_owned();
    let version_guard = repository
        .assert_provider_version_statement(&provider_id, &org_id, body.version)
        .map_err(|error| database_error(&context, error))?;
    let mutation = begin_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &lifecycle_path,
        &lifecycle_fingerprint,
        database,
        &context,
    )
    .await?;
    let pending = match mutation {
        MutationClaim::Replay(success) => return Ok(replay_response(&success)),
        MutationClaim::Pending(pending) => pending,
    };
    let success = StoredSuccess::new(200, json!({"provider": provider_json(&expected, true)?}))
        .map_err(|_| internal_error(&context))?;
    let statement = repository
        .update_provider_lifecycle_statement(
            &provider_id,
            &org_id,
            lifecycle.as_str(),
            body.version,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let event_metadata = json!({"lifecycle": lifecycle.as_str()});
    let security = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        &generated_id("sec"),
        "model_catalog.provider_lifecycle_changed.v1",
        "provider",
        Some(&provider_id),
        "success",
        &event_metadata,
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "model_catalog.provider_lifecycle_changed.v1",
        &event_metadata,
    )?;
    let results = commit_mutation(
        database,
        &pending,
        &context.received_at,
        &success,
        vec![version_guard, statement, security],
        outbox,
    )
    .await
    .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[3]).unwrap_or_default() != 1 {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The provider changed. Refresh and try again.",
        ));
    }
    Ok(replay_response(&success))
}

#[worker::send]
pub async fn create_model(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<CreateModelRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ModelsManage,
        Some("model"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let database = database(&state, &context)?;
    let repository = AiRepository::new(database);
    let provider = repository
        .find_provider(&body.provider_id, &org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .filter(|provider| provider.org_id.as_deref() == Some(org_id.as_str()))
        .ok_or_else(|| not_found(&context, "The provider was not found."))?;
    let capabilities = parse_capabilities(&body.capabilities).map_err(|_| {
        validation_error(
            &context,
            "capabilities_invalid",
            "Choose valid model capabilities.",
        )
    })?;
    let descriptor = ModelDescriptor {
        model_id: body.provider_id.clone(),
        provider_id: body.provider_id.clone(),
        provider_model_id: body.provider_model_id.clone(),
        display_name: bounded_name(&body.display_name).ok_or_else(|| {
            validation_error(
                &context,
                "display_name_invalid",
                "Enter a valid model name.",
            )
        })?,
        capabilities: ModelCapabilities::new(capabilities.iter().copied()),
        max_input_tokens: body.max_input_tokens,
        max_output_tokens: body.max_output_tokens,
        lifecycle: CatalogLifecycle::Active,
        pricing_version: body.pricing_version.clone(),
    };
    if crate::modules::catalog::validate_model(&descriptor).is_err() {
        return Err(validation_error(
            &context,
            "model_invalid",
            "The model metadata is invalid.",
        ));
    }
    let capabilities_json =
        serde_json::to_string(&capabilities).map_err(|_| service_unavailable(&context))?;
    let create_path = format!("/api/v1/orgs/{org_id}/catalog/models");
    let fingerprint_input = format!(
        "POST\\n{create_path}\\n{}:{}:{}:{}:{}:{}",
        body.provider_id,
        body.provider_model_id,
        descriptor.display_name,
        capabilities_json,
        body.max_input_tokens.unwrap_or_default(),
        body.max_output_tokens.unwrap_or_default()
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
    let model_id = deterministic_resource_id(
        "mdl",
        &key,
        &format!(
            "model:{org_id}:{}:{}",
            provider.provider_id, body.provider_model_id
        ),
        &context,
    )
    .await?;
    if let Some(existing) = repository
        .find_model(&model_id, &org_id)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        if existing.provider_id != body.provider_id
            || existing.provider_model_id != body.provider_model_id
            || existing.display_name != descriptor.display_name
            || existing.capabilities_json != capabilities_json
            || existing.max_input_tokens != body.max_input_tokens.map(i64::from)
            || existing.max_output_tokens != body.max_output_tokens.map(i64::from)
            || existing.pricing_version != body.pricing_version
        {
            return Err(domain_error(
                &context,
                ApiErrorCode::Conflict,
                "idempotency_conflict",
                "The idempotency key was already used for a different request.",
            ));
        }
        return Ok((
            StatusCode::OK,
            Json(json!({"model": model_json(&existing, &context)?})),
        )
            .into_response());
    }
    let expected = ModelRecord {
        model_id: model_id.clone(),
        provider_id: body.provider_id.clone(),
        provider_model_id: body.provider_model_id.clone(),
        display_name: descriptor.display_name.clone(),
        capabilities_json: capabilities_json.clone(),
        max_input_tokens: body.max_input_tokens.map(i64::from),
        max_output_tokens: body.max_output_tokens.map(i64::from),
        lifecycle: "active".to_owned(),
        pricing_version: body.pricing_version.clone(),
        version: 1,
        created_by_user_id: Some(access.principal.user_id.as_str().to_owned()),
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
    let success = StoredSuccess::new(201, json!({"model": model_json(&expected, &context)?}))
        .map_err(|_| internal_error(&context))?;
    let statement = repository
        .insert_model_statement(
            &model_id,
            &body.provider_id,
            &body.provider_model_id,
            &descriptor.display_name,
            &capabilities_json,
            body.max_input_tokens.map(i64::from),
            body.max_output_tokens.map(i64::from),
            body.pricing_version.as_deref(),
            Some(access.principal.user_id.as_str()),
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let event_id = generated_id("sec");
    let metadata = json!({"provider_id": body.provider_id, "capabilities": capabilities});
    let security = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        &event_id,
        "model_catalog.model_created.v1",
        "model",
        Some(&model_id),
        "success",
        &metadata,
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "model_catalog.model_created.v1",
        &metadata,
    )?;
    let results = commit_mutation(
        database,
        &pending,
        &context.received_at,
        &success,
        vec![statement, security],
        outbox,
    )
    .await
    .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[2]).unwrap_or_default() != 1 {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "idempotency_conflict",
            "The model could not be created.",
        ));
    }
    Ok(replay_response(&success))
}

#[worker::send]
pub async fn update_model_lifecycle(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, model_id)): Path<(String, String)>,
    Json(body): Json<LifecycleRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ModelsManage,
        Some("model"),
        Some(&model_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let lifecycle = CatalogLifecycle::parse(&body.lifecycle).ok_or_else(|| {
        validation_error(
            &context,
            "lifecycle_invalid",
            "Choose a valid model lifecycle.",
        )
    })?;
    if body.version < 1 {
        return Err(validation_error(
            &context,
            "version_invalid",
            "Reload the model.",
        ));
    }
    let database = database(&state, &context)?;
    let repository = AiRepository::new(database);
    let lifecycle_path = format!("/api/v1/orgs/{org_id}/catalog/models/{model_id}/lifecycle");
    let lifecycle_fingerprint = format!("model:{}:{}", body.version, lifecycle.as_str());
    if let Some(success) = lookup_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &lifecycle_path,
        &lifecycle_fingerprint,
        database,
        &context,
    )
    .await?
    {
        return Ok(replay_response(&success));
    }
    let current = repository
        .find_model(&model_id, &org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context, "The model was not found."))?;
    let _provider = repository
        .find_provider(&current.provider_id, &org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .filter(|provider| provider.org_id.as_deref() == Some(org_id.as_str()))
        .ok_or_else(|| not_found(&context, "The model was not found."))?;
    if body.version != current.version {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The model changed. Refresh and try again.",
        ));
    }
    if current.lifecycle == "disabled" {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "lifecycle_terminal",
            "A disabled model cannot be re-enabled.",
        ));
    }
    let mut expected = current.clone();
    expected.lifecycle = lifecycle.as_str().to_owned();
    expected.version += 1;
    expected.updated_at = context.received_at.as_str().to_owned();
    let version_guard = repository
        .assert_model_version_statement(&model_id, &org_id, body.version)
        .map_err(|error| database_error(&context, error))?;
    let mutation = begin_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &lifecycle_path,
        &lifecycle_fingerprint,
        database,
        &context,
    )
    .await?;
    let pending = match mutation {
        MutationClaim::Replay(success) => return Ok(replay_response(&success)),
        MutationClaim::Pending(pending) => pending,
    };
    let success = StoredSuccess::new(200, json!({"model": model_json(&expected, &context)?}))
        .map_err(|_| internal_error(&context))?;
    let statement = repository
        .update_model_lifecycle_statement(
            &model_id,
            &org_id,
            lifecycle.as_str(),
            body.version,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let event_metadata =
        json!({"provider_id": current.provider_id, "lifecycle": lifecycle.as_str()});
    let security = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        &generated_id("sec"),
        "model_catalog.model_lifecycle_changed.v1",
        "model",
        Some(&model_id),
        "success",
        &event_metadata,
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "model_catalog.model_lifecycle_changed.v1",
        &event_metadata,
    )?;
    let results = commit_mutation(
        database,
        &pending,
        &context.received_at,
        &success,
        vec![version_guard, statement, security],
        outbox,
    )
    .await
    .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[3]).unwrap_or_default() != 1 {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The model changed. Refresh and try again.",
        ));
    }
    Ok(replay_response(&success))
}

#[worker::send]
pub async fn list_credentials(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Response<Body>, ApiError> {
    let offset = cursor_offset(&context, query.cursor.as_deref())?;
    let limit = page_limit(query.limit);
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::CredentialsRead,
        Some("credential"),
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let records = AiRepository::new(database)
        .list_credentials(&org_id, limit.saturating_add(1), offset)
        .await
        .map_err(|error| database_error(&context, error))?;
    let (window, next_cursor, has_more) = page_window(records, limit, offset);
    let items = window
        .iter()
        .map(|record| credential_json(record, &context))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(PageResponse {
        items,
        next_cursor,
        has_more,
    })
    .into_response())
}

#[worker::send]
pub async fn create_credential(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<CreateCredentialRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::CredentialsManage,
        Some("credential"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let database = database(&state, &context)?;
    let repository = AiRepository::new(database);
    let provider = repository
        .find_provider(&body.provider_id, &org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context, "The provider was not found."))?;
    let owner_type = CredentialOwnerType::parse(&body.owner_type).ok_or_else(|| {
        validation_error(
            &context,
            "owner_type_invalid",
            "Choose a valid credential owner.",
        )
    })?;
    if owner_type == CredentialOwnerType::Platform {
        return Err(validation_error(
            &context,
            "owner_type_unsupported",
            "Platform credentials are provisioned by the platform operator.",
        ));
    }
    let owner_user_id = if matches!(
        owner_type,
        CredentialOwnerType::User | CredentialOwnerType::ServiceAccount
    ) {
        Some(access.principal.user_id.as_str())
    } else {
        None
    };
    let label = bounded_name(&body.label).ok_or_else(|| {
        validation_error(&context, "label_invalid", "Enter a valid credential label.")
    })?;
    let local_only = owner_type == CredentialOwnerType::LocalOnly;
    let (ciphertext, nonce, key_version, fingerprint) = if local_only {
        if body.secret.is_some() {
            return Err(validation_error(
                &context,
                "secret_not_allowed",
                "Local-only credentials do not accept an uploaded secret.",
            ));
        }
        let digest = sha256_hex(&format!("local-only:{}:{}", org_id, provider.provider_id))
            .await
            .map_err(|_| service_unavailable(&context))?;
        (
            None,
            None,
            None,
            crate::modules::credentials::metadata_fingerprint(&digest)
                .ok_or_else(|| service_unavailable(&context))?,
        )
    } else {
        let secret = body
            .secret
            .as_deref()
            .filter(|value| valid_secret(value))
            .ok_or_else(|| {
                validation_error(&context, "secret_invalid", "Enter the provider secret.")
            })?;
        let key_value = state
            .credential_key
            .as_deref()
            .ok_or_else(|| service_unavailable(&context))?;
        let encrypted = encrypt_secret(key_value, secret)
            .await
            .map_err(|_| service_unavailable(&context))?;
        let fingerprint = fingerprint_secret(secret)
            .await
            .map_err(|_| service_unavailable(&context))?;
        (
            Some(encrypted.ciphertext),
            Some(encrypted.nonce),
            Some(CREDENTIAL_KEY_VERSION.to_owned()),
            fingerprint,
        )
    };
    let create_path = format!("/api/v1/orgs/{org_id}/credentials");
    let fingerprint_input = format!(
        "POST\\n{create_path}\\n{}:{}:{}:{}",
        provider.provider_id,
        owner_type.as_str(),
        label,
        fingerprint
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
    let credential_id = deterministic_resource_id(
        "cred",
        &key,
        &format!(
            "credential:{org_id}:{}:{:?}",
            provider.provider_id, owner_type
        ),
        &context,
    )
    .await?;
    if let Some(existing) = repository
        .find_credential_for_owner(&credential_id, &org_id, access.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?
    {
        if existing.provider_id != provider.provider_id
            || existing.label != label
            || existing.fingerprint != fingerprint
        {
            return Err(domain_error(
                &context,
                ApiErrorCode::Conflict,
                "idempotency_conflict",
                "The idempotency key was already used for a different request.",
            ));
        }
        return Ok((
            StatusCode::OK,
            Json(CredentialResponse {
                credential: credential_json(&existing, &context)?,
                duplicate: true,
            }),
        )
            .into_response());
    }
    let credential_org_id = if local_only {
        None
    } else {
        Some(org_id.as_str())
    };
    let expected_record = CredentialRecord {
        credential_id: credential_id.clone(),
        org_id: credential_org_id.map(str::to_owned),
        owner_type: owner_type.as_str().to_owned(),
        owner_user_id: owner_user_id.map(str::to_owned),
        provider_id: provider.provider_id.clone(),
        label: label.clone(),
        ciphertext: ciphertext.clone(),
        nonce: nonce.clone(),
        key_version: key_version.clone(),
        fingerprint: fingerprint.clone(),
        status: "active".to_owned(),
        version: 1,
        parent_credential_id: None,
        created_by_user_id: Some(access.principal.user_id.as_str().to_owned()),
        created_at: context.received_at.as_str().to_owned(),
        updated_at: context.received_at.as_str().to_owned(),
        last_used_at: None,
    };
    let mutation = begin_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &format!("/api/v1/orgs/{org_id}/credentials"),
        &fingerprint_input,
        database,
        &context,
    )
    .await?;
    let pending = match mutation {
        MutationClaim::Replay(success) => return Ok(replay_response(&success)),
        MutationClaim::Pending(pending) => pending,
    };
    let success = StoredSuccess::new(
        201,
        json!({"credential": credential_json(&expected_record, &context)?, "duplicate": false}),
    )
    .map_err(|_| internal_error(&context))?;
    let statement = repository
        .insert_credential_statement(
            &credential_id,
            credential_org_id,
            owner_type.as_str(),
            owner_user_id,
            &provider.provider_id,
            &label,
            ciphertext.as_deref(),
            nonce.as_deref(),
            key_version.as_deref(),
            &fingerprint,
            None,
            Some(access.principal.user_id.as_str()),
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let event_id = generated_id("sec");
    let metadata = json!({"provider_id": provider.provider_id, "owner_type": owner_type.as_str(), "label": label});
    let security = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        &event_id,
        "credential.created.v1",
        "credential",
        Some(&credential_id),
        "success",
        &metadata,
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "credential.created.v1",
        &metadata,
    )?;
    let results = commit_mutation(
        database,
        &pending,
        &context.received_at,
        &success,
        vec![statement, security],
        outbox,
    )
    .await
    .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[2]).unwrap_or_default() != 1 {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "idempotency_conflict",
            "The credential could not be created.",
        ));
    }
    Ok(replay_response(&success))
}

#[worker::send]
pub async fn rotate_credential(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, credential_id)): Path<(String, String)>,
    Json(body): Json<RotateCredentialRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::CredentialsManage,
        Some("credential"),
        Some(&credential_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let database = database(&state, &context)?;
    let repository = AiRepository::new(database);
    let current = repository
        .find_credential_for_owner(&credential_id, &org_id, access.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context, "The credential was not found."))?;
    let secret = body
        .secret
        .as_deref()
        .filter(|value| valid_secret(value))
        .ok_or_else(|| {
            validation_error(
                &context,
                "secret_invalid",
                "Enter the replacement provider secret.",
            )
        })?;
    let label = body
        .label
        .as_deref()
        .and_then(bounded_name)
        .unwrap_or_else(|| current.label.clone());
    let key_value = state
        .credential_key
        .as_deref()
        .ok_or_else(|| service_unavailable(&context))?;
    let encrypted = encrypt_secret(key_value, secret)
        .await
        .map_err(|_| service_unavailable(&context))?;
    let fingerprint = fingerprint_secret(secret)
        .await
        .map_err(|_| service_unavailable(&context))?;
    let next_id = deterministic_resource_id(
        "cred",
        &key,
        &format!("credential-rotation:{org_id}:{credential_id}"),
        &context,
    )
    .await?;
    let rotate_path = format!("/api/v1/orgs/{org_id}/credentials/{credential_id}/rotate");
    let fingerprint_input = format!("rotation:{}:{}:{}", current.provider_id, label, fingerprint);
    if let Some(success) = lookup_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &rotate_path,
        &fingerprint_input,
        database,
        &context,
    )
    .await?
    {
        return Ok(replay_response(&success));
    }
    if let Some(existing) = repository
        .find_credential_for_owner(&next_id, &org_id, access.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?
    {
        if existing.fingerprint != fingerprint || existing.label != label {
            return Err(domain_error(
                &context,
                ApiErrorCode::Conflict,
                "idempotency_conflict",
                "The idempotency key was already used for a different request.",
            ));
        }
        return Ok((
            StatusCode::OK,
            Json(CredentialResponse {
                credential: credential_json(&existing, &context)?,
                duplicate: true,
            }),
        )
            .into_response());
    }
    let owner_user_id = if matches!(current.owner_type.as_str(), "user" | "service_account") {
        current.owner_user_id.as_deref()
    } else {
        None
    };
    let expected_record = CredentialRecord {
        credential_id: next_id.clone(),
        org_id: current.org_id.clone(),
        owner_type: current.owner_type.clone(),
        owner_user_id: current.owner_user_id.clone(),
        provider_id: current.provider_id.clone(),
        label: label.clone(),
        ciphertext: Some(encrypted.ciphertext.clone()),
        nonce: Some(encrypted.nonce.clone()),
        key_version: Some(CREDENTIAL_KEY_VERSION.to_owned()),
        fingerprint: fingerprint.clone(),
        status: "active".to_owned(),
        version: 1,
        parent_credential_id: Some(credential_id.clone()),
        created_by_user_id: Some(access.principal.user_id.as_str().to_owned()),
        created_at: context.received_at.as_str().to_owned(),
        updated_at: context.received_at.as_str().to_owned(),
        last_used_at: None,
    };
    let mutation = begin_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &rotate_path,
        &fingerprint_input,
        database,
        &context,
    )
    .await?;
    let pending = match mutation {
        MutationClaim::Replay(success) => return Ok(replay_response(&success)),
        MutationClaim::Pending(pending) => pending,
    };
    let success = StoredSuccess::new(
        201,
        json!({"credential": credential_json(&expected_record, &context)?, "duplicate": false}),
    )
    .map_err(|_| internal_error(&context))?;
    let version_guard = repository
        .assert_credential_version_statement(&credential_id, &org_id, current.version)
        .map_err(|error| database_error(&context, error))?;
    let insert = repository
        .insert_credential_statement(
            &next_id,
            current.org_id.as_deref(),
            &current.owner_type,
            owner_user_id,
            &current.provider_id,
            &label,
            Some(&encrypted.ciphertext),
            Some(&encrypted.nonce),
            Some(CREDENTIAL_KEY_VERSION),
            &fingerprint,
            Some(&credential_id),
            Some(access.principal.user_id.as_str()),
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let revoke = repository
        .revoke_credential_statement(
            &credential_id,
            &org_id,
            current.version,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let event_id = generated_id("sec");
    let metadata =
        json!({"provider_id": current.provider_id, "parent_credential_id": credential_id});
    let security = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        &event_id,
        "credential.rotated.v1",
        "credential",
        Some(&next_id),
        "success",
        &metadata,
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "credential.rotated.v1",
        &metadata,
    )?;
    let results = commit_mutation(
        database,
        &pending,
        &context.received_at,
        &success,
        vec![version_guard, insert, revoke, security],
        outbox,
    )
    .await
    .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[4]).unwrap_or_default() != 1 {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The credential changed. Refresh and try again.",
        ));
    }
    Ok(replay_response(&success))
}

#[worker::send]
pub async fn revoke_credential(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, credential_id)): Path<(String, String)>,
    Json(body): Json<RevokeCredentialRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::CredentialsManage,
        Some("credential"),
        Some(&credential_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    if body.version < 1 {
        return Err(validation_error(
            &context,
            "version_invalid",
            "Reload the credential and try again.",
        ));
    }
    let database = database(&state, &context)?;
    let repository = AiRepository::new(database);
    let fingerprint_input = format!(
        "POST\\n/api/v1/orgs/{org_id}/credentials/{credential_id}/revoke\\n{}",
        body.version
    );
    let mutation = begin_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &format!("/api/v1/orgs/{org_id}/credentials/{credential_id}/revoke"),
        &fingerprint_input,
        database,
        &context,
    )
    .await?;
    let pending = match mutation {
        MutationClaim::Replay(success) => return Ok(replay_response(&success)),
        MutationClaim::Pending(pending) => pending,
    };
    let current = match repository
        .find_credential_for_owner(&credential_id, &org_id, access.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?
    {
        Some(current) => current,
        None => {
            let _ = IdempotencyRepository::new(database)
                .release_pending_claim(&pending.record, &pending.token)
                .await;
            return Err(not_found(&context, "The credential was not found."));
        }
    };
    if body.version != current.version {
        let _ = IdempotencyRepository::new(database)
            .release_pending_claim(&pending.record, &pending.token)
            .await;
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The credential changed. Refresh and try again.",
        ));
    }
    let mut expected = current.clone();
    expected.status = "revoked".to_owned();
    expected.version += 1;
    expected.updated_at = context.received_at.as_str().to_owned();
    let success = StoredSuccess::new(200, credential_json(&expected, &context)?)
        .map_err(|_| internal_error(&context))?;
    let version_guard = repository
        .assert_credential_version_statement(&credential_id, &org_id, body.version)
        .map_err(|error| database_error(&context, error))?;
    let statement = repository
        .revoke_credential_statement(&credential_id, &org_id, body.version, &context.received_at)
        .map_err(|error| database_error(&context, error))?;
    let event_id = generated_id("sec");
    let metadata = json!({"provider_id": current.provider_id, "status": "revoked"});
    let security = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        &event_id,
        "credential.revoked.v1",
        "credential",
        Some(&credential_id),
        "success",
        &metadata,
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "credential.revoked.v1",
        &metadata,
    )?;
    let results = commit_mutation(
        database,
        &pending,
        &context.received_at,
        &success,
        vec![version_guard, statement, security],
        outbox,
    )
    .await
    .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[3]).unwrap_or_default() != 1 {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The credential changed. Refresh and try again.",
        ));
    }
    Ok(replay_response(&success))
}

#[worker::send]
pub async fn list_routes(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Response<Body>, ApiError> {
    let offset = cursor_offset(&context, query.cursor.as_deref())?;
    let limit = page_limit(query.limit);
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::RoutesRead,
        Some("route"),
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let routes = AiRepository::new(database)
        .list_routes(&org_id, limit.saturating_add(1), offset)
        .await
        .map_err(|error| database_error(&context, error))?;
    let (window, next_cursor, has_more) = page_window(routes, limit, offset);
    let items = window
        .iter()
        .map(route_json)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(PageResponse {
        items,
        next_cursor,
        has_more,
    })
    .into_response())
}

#[worker::send]
pub async fn create_route(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<CreateRouteRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::RoutesManage,
        Some("route"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let alias = normalize_alias(&body.alias).ok_or_else(|| {
        validation_error(&context, "alias_invalid", "Choose a valid route alias.")
    })?;
    let display_name = bounded_name(&body.display_name).ok_or_else(|| {
        validation_error(
            &context,
            "display_name_invalid",
            "Enter a valid route name.",
        )
    })?;
    let strategy = RouteStrategy::parse(&body.strategy).ok_or_else(|| {
        validation_error(
            &context,
            "strategy_invalid",
            "Choose a valid routing strategy.",
        )
    })?;
    if body.config.strategy != strategy {
        return Err(validation_error(
            &context,
            "strategy_mismatch",
            "The route strategy does not match its configuration.",
        ));
    }
    validate_route_config(&body.config).map_err(|_| {
        validation_error(
            &context,
            "config_invalid",
            "The route configuration is invalid.",
        )
    })?;
    let database = database(&state, &context)?;
    let repository = AiRepository::new(database);
    let existing_alias = repository
        .find_alias(&alias)
        .await
        .map_err(|error| database_error(&context, error))?;
    let alias_id = if existing_alias.is_some() {
        None
    } else {
        Some(
            deterministic_resource_id(
                "mal",
                &key,
                &format!("model-alias:{org_id}:{alias}"),
                &context,
            )
            .await?,
        )
    };
    let policy_record = repository
        .find_policy(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    let policy = org_policy(policy_record.as_ref(), &state.environment);
    if !policy.allows_alias(&alias) {
        return Err(validation_error(
            &context,
            "model_not_allowed",
            "The alias is not allowed by organization policy.",
        ));
    }
    validate_config_references(
        &repository,
        &org_id,
        &body.config,
        &policy,
        state.environment == "development",
        &context,
    )
    .await?;
    let config_json =
        serde_json::to_string(&body.config).map_err(|_| service_unavailable(&context))?;
    let config_hash = sha256_hex(&config_json)
        .await
        .map_err(|_| service_unavailable(&context))?;
    let route_id =
        deterministic_resource_id("rte", &key, &format!("route:{org_id}:{alias}"), &context)
            .await?;
    let create_path = format!("/api/v1/orgs/{org_id}/routes");
    let fingerprint_input =
        format!("POST\\n{create_path}\\n{alias}:{display_name}:{strategy:?}:{config_json}");
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
    if let Some(existing) = repository
        .find_route(&org_id, &route_id)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        let version = repository
            .list_route_versions(&org_id, &route_id, 1, 0)
            .await
            .map_err(|error| database_error(&context, error))?
            .into_iter()
            .next();
        if existing.alias != alias
            || existing.display_name != display_name
            || existing.strategy != strategy.as_str()
            || version
                .as_ref()
                .is_none_or(|value| value.config_hash != config_hash)
        {
            return Err(domain_error(
                &context,
                ApiErrorCode::Conflict,
                "idempotency_conflict",
                "The idempotency key was already used for a different request.",
            ));
        }
        return Ok((
            StatusCode::OK,
            Json(RouteResponse {
                route: route_json(&existing)?,
                version: version
                    .as_ref()
                    .map(|value| route_version_json(value, &context))
                    .transpose()?,
                duplicate: true,
            }),
        )
            .into_response());
    }
    let version_id = deterministic_resource_id(
        "rtv",
        &key,
        &format!("route-version:{route_id}:1"),
        &context,
    )
    .await?;
    let expected_route = RouteRecord {
        route_id: route_id.clone(),
        org_id: org_id.clone(),
        alias: alias.clone(),
        display_name: display_name.clone(),
        strategy: strategy.as_str().to_owned(),
        lifecycle: "draft".to_owned(),
        active_version_id: None,
        version: 1,
        created_by_user_id: access.principal.user_id.as_str().to_owned(),
        created_at: context.received_at.as_str().to_owned(),
        updated_at: context.received_at.as_str().to_owned(),
    };
    let expected_version = RouteVersionRecord {
        route_version_id: version_id.clone(),
        route_id: route_id.clone(),
        org_id: org_id.clone(),
        version_number: 1,
        config_json: config_json.clone(),
        config_hash: config_hash.clone(),
        created_by_user_id: access.principal.user_id.as_str().to_owned(),
        created_at: context.received_at.as_str().to_owned(),
        published_at: None,
    };
    let mutation = begin_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &format!("/api/v1/orgs/{org_id}/routes"),
        &fingerprint_input,
        database,
        &context,
    )
    .await?;
    let pending = match mutation {
        MutationClaim::Replay(success) => return Ok(replay_response(&success)),
        MutationClaim::Pending(pending) => pending,
    };
    let success = StoredSuccess::new(
        201,
        json!({
            "route": route_json(&expected_route)?,
            "version": route_version_json(&expected_version, &context)?,
            "duplicate": false
        }),
    )
    .map_err(|_| internal_error(&context))?;
    let route_statement = repository
        .insert_route_statement(
            &route_id,
            &org_id,
            &alias,
            &display_name,
            strategy.as_str(),
            access.principal.user_id.as_str(),
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let version_statement = repository
        .insert_route_version_statement(
            &version_id,
            &route_id,
            &org_id,
            1,
            &config_json,
            &config_hash,
            access.principal.user_id.as_str(),
            None,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let alias_statement = alias_id
        .as_deref()
        .map(|id| {
            repository.insert_alias_statement(
                id,
                &alias,
                &display_name,
                Some("Managed route alias."),
                &context.received_at,
            )
        })
        .transpose()
        .map_err(|error| database_error(&context, error))?;
    let event_id = generated_id("sec");
    let metadata = json!({"alias": alias, "strategy": strategy.as_str(), "version": 1, "alias_created": alias_id.is_some()});
    let security = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        &event_id,
        "route.draft_created.v1",
        "route",
        Some(&route_id),
        "success",
        &metadata,
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "route.draft_created.v1",
        &metadata,
    )?;
    let mut business_writes = vec![route_statement, version_statement];
    if let Some(alias_statement) = alias_statement {
        business_writes.push(alias_statement);
    }
    business_writes.push(security);
    let results = commit_mutation(
        database,
        &pending,
        &context.received_at,
        &success,
        business_writes,
        outbox,
    )
    .await
    .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[2]).unwrap_or_default() != 1 {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "idempotency_conflict",
            "The route could not be created.",
        ));
    }
    Ok(replay_response(&success))
}

#[worker::send]
pub async fn publish_route(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, route_id)): Path<(String, String)>,
    Json(body): Json<PublishRouteRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::RoutesManage,
        Some("route"),
        Some(&route_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    if body.version < 1 {
        return Err(validation_error(
            &context,
            "version_invalid",
            "Reload the route and try again.",
        ));
    }
    validate_route_config(&body.config).map_err(|_| {
        validation_error(
            &context,
            "config_invalid",
            "The route configuration is invalid.",
        )
    })?;
    let database = database(&state, &context)?;
    let repository = AiRepository::new(database);
    let route = repository
        .find_route(&org_id, &route_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context, "The route was not found."))?;
    if body.config.strategy.as_str() != route.strategy {
        return Err(validation_error(
            &context,
            "strategy_mismatch",
            "The route strategy does not match its persisted configuration.",
        ));
    }
    let policy_record = repository
        .find_policy(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    let policy = org_policy(policy_record.as_ref(), &state.environment);
    if !policy.allows_alias(&route.alias) {
        return Err(validation_error(
            &context,
            "model_not_allowed",
            "The alias is not allowed by organization policy.",
        ));
    }
    validate_config_references(
        &repository,
        &org_id,
        &body.config,
        &policy,
        state.environment == "development",
        &context,
    )
    .await?;
    let config_json =
        serde_json::to_string(&body.config).map_err(|_| service_unavailable(&context))?;
    let config_hash = sha256_hex(&config_json)
        .await
        .map_err(|_| service_unavailable(&context))?;
    let publish_path = format!("/api/v1/orgs/{org_id}/routes/{route_id}/publish");
    let fingerprint_input = format!("POST\\n{publish_path}\\n{}:{config_hash}", body.version);
    if let Some(success) = lookup_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &publish_path,
        &fingerprint_input,
        database,
        &context,
    )
    .await?
    {
        return Ok(replay_response(&success));
    }
    if body.version != route.version {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The route changed. Refresh and try again.",
        ));
    }
    let existing_versions = repository
        .list_route_versions(&org_id, &route_id, 100, 0)
        .await
        .map_err(|error| database_error(&context, error))?;
    if let Some(existing) = existing_versions
        .iter()
        .find(|version| version.config_hash == config_hash && version.published_at.is_some())
    {
        if route.active_version_id.as_deref() == Some(existing.route_version_id.as_str()) {
            return Ok((
                StatusCode::OK,
                Json(RouteResponse {
                    route: route_json(&route)?,
                    version: Some(route_version_json(existing, &context)?),
                    duplicate: true,
                }),
            )
                .into_response());
        }
        let fingerprint_input = format!(
            "POST\\n/api/v1/orgs/{org_id}/routes/{route_id}/publish\\n{}:{config_hash}",
            body.version
        );
        let mutation = begin_mutation(
            &key,
            access.principal.user_id.as_str(),
            &org_id,
            "POST",
            &format!("/api/v1/orgs/{org_id}/routes/{route_id}/publish"),
            &fingerprint_input,
            database,
            &context,
        )
        .await?;
        let pending = match mutation {
            MutationClaim::Replay(success) => return Ok(replay_response(&success)),
            MutationClaim::Pending(pending) => pending,
        };
        let mut updated_route = route.clone();
        updated_route.active_version_id = Some(existing.route_version_id.clone());
        updated_route.lifecycle = "published".to_owned();
        updated_route.version += 1;
        updated_route.updated_at = context.received_at.as_str().to_owned();
        let success = StoredSuccess::new(
            200,
            json!({
                "route": route_json(&updated_route)?,
                "version": route_version_json(existing, &context)?,
                "duplicate": true
            }),
        )
        .map_err(|_| internal_error(&context))?;
        let version_guard = repository
            .assert_route_version_statement(&route_id, &org_id, body.version)
            .map_err(|error| database_error(&context, error))?;
        let publish_statement = repository
            .publish_route_statement(
                &route_id,
                &existing.route_version_id,
                &org_id,
                body.version,
                &context.received_at,
            )
            .map_err(|error| database_error(&context, error))?;
        let event_id = generated_id("sec");
        let metadata = json!({"alias": route.alias, "route_version": existing.version_number});
        let security = security_event_statement(
            database,
            &context,
            Some(&access.principal),
            Some(&org_id),
            &event_id,
            "route.published.v1",
            "route",
            Some(&route_id),
            "success",
            &metadata,
        )?;
        let outbox = outbox_statement(
            database,
            &context,
            Some(&access.principal),
            Some(&org_id),
            "route.published.v1",
            &metadata,
        )?;
        let results = commit_mutation(
            database,
            &pending,
            &context.received_at,
            &success,
            vec![version_guard, publish_statement, security],
            outbox,
        )
        .await
        .map_err(|error| database_error(&context, error))?;
        if crate::adapters::d1::D1Adapter::changes(&results[3]).unwrap_or_default() != 1 {
            return Err(domain_error(
                &context,
                ApiErrorCode::Conflict,
                "version_conflict",
                "The route changed. Refresh and try again.",
            ));
        }
        return Ok(replay_response(&success));
    }
    let next_number = existing_versions
        .iter()
        .map(|version| version.version_number)
        .max()
        .unwrap_or(0)
        + 1;
    let version_id = deterministic_resource_id(
        "rtv",
        &key,
        &format!("route-publish:{org_id}:{route_id}:{next_number}"),
        &context,
    )
    .await?;
    let fingerprint_input = format!(
        "POST\\n/api/v1/orgs/{org_id}/routes/{route_id}/publish\\n{}:{config_hash}",
        body.version
    );
    let mutation = begin_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &format!("/api/v1/orgs/{org_id}/routes/{route_id}/publish"),
        &fingerprint_input,
        database,
        &context,
    )
    .await?;
    let pending = match mutation {
        MutationClaim::Replay(success) => return Ok(replay_response(&success)),
        MutationClaim::Pending(pending) => pending,
    };
    let mut updated_route = route.clone();
    updated_route.active_version_id = Some(version_id.clone());
    updated_route.lifecycle = "published".to_owned();
    updated_route.version += 1;
    updated_route.updated_at = context.received_at.as_str().to_owned();
    let version_record = RouteVersionRecord {
        route_version_id: version_id.clone(),
        route_id: route_id.clone(),
        org_id: org_id.clone(),
        version_number: next_number,
        config_json: config_json.clone(),
        config_hash: config_hash.clone(),
        created_by_user_id: access.principal.user_id.as_str().to_owned(),
        created_at: context.received_at.as_str().to_owned(),
        published_at: Some(context.received_at.as_str().to_owned()),
    };
    let success = StoredSuccess::new(
        200,
        json!({
            "route": route_json(&updated_route)?,
            "version": route_version_json(&version_record, &context)?,
            "duplicate": false
        }),
    )
    .map_err(|_| internal_error(&context))?;
    let version_guard = repository
        .assert_route_version_statement(&route_id, &org_id, body.version)
        .map_err(|error| database_error(&context, error))?;
    let version_statement = repository
        .insert_route_version_statement(
            &version_id,
            &route_id,
            &org_id,
            next_number,
            &config_json,
            &config_hash,
            access.principal.user_id.as_str(),
            Some(context.received_at.as_str()),
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let publish_statement = repository
        .publish_route_statement(
            &route_id,
            &version_id,
            &org_id,
            body.version,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let event_id = generated_id("sec");
    let metadata = json!({"alias": route.alias, "route_version": next_number});
    let security = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        &event_id,
        "route.published.v1",
        "route",
        Some(&route_id),
        "success",
        &metadata,
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "route.published.v1",
        &metadata,
    )?;
    let results = commit_mutation(
        database,
        &pending,
        &context.received_at,
        &success,
        vec![
            version_guard,
            version_statement,
            publish_statement,
            security,
        ],
        outbox,
    )
    .await
    .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[4]).unwrap_or_default() != 1 {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The route changed. Refresh and try again.",
        ));
    }
    Ok(replay_response(&success))
}

#[worker::send]
pub async fn rollback_route(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, route_id)): Path<(String, String)>,
    Json(body): Json<RollbackRouteRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::RoutesManage,
        Some("route"),
        Some(&route_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    if body.version < 1 {
        return Err(validation_error(
            &context,
            "version_invalid",
            "Choose a valid route version.",
        ));
    }
    let database = database(&state, &context)?;
    let repository = AiRepository::new(database);
    let route = repository
        .find_route(&org_id, &route_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context, "The route was not found."))?;
    let target = repository
        .list_route_versions(&org_id, &route_id, 100, 0)
        .await
        .map_err(|error| database_error(&context, error))?
        .into_iter()
        .find(|version| version.version_number == body.version && version.published_at.is_some())
        .ok_or_else(|| not_found(&context, "The route version was not found."))?;
    if route.active_version_id.as_deref() == Some(target.route_version_id.as_str()) {
        return Ok(Json(RouteResponse {
            route: route_json(&route)?,
            version: Some(route_version_json(&target, &context)?),
            duplicate: true,
        })
        .into_response());
    }
    let fingerprint_input = format!(
        "POST\\n/api/v1/orgs/{org_id}/routes/{route_id}/rollback\\n{}",
        body.version
    );
    let mutation = begin_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &format!("/api/v1/orgs/{org_id}/routes/{route_id}/rollback"),
        &fingerprint_input,
        database,
        &context,
    )
    .await?;
    let pending = match mutation {
        MutationClaim::Replay(success) => return Ok(replay_response(&success)),
        MutationClaim::Pending(pending) => pending,
    };
    let mut updated_route = route.clone();
    updated_route.active_version_id = Some(target.route_version_id.clone());
    updated_route.lifecycle = "published".to_owned();
    updated_route.version += 1;
    updated_route.updated_at = context.received_at.as_str().to_owned();
    let success = StoredSuccess::new(
        200,
        json!({
            "route": route_json(&updated_route)?,
            "version": route_version_json(&target, &context)?,
            "duplicate": false
        }),
    )
    .map_err(|_| internal_error(&context))?;
    let version_guard = repository
        .assert_route_version_statement(&route_id, &org_id, route.version)
        .map_err(|error| database_error(&context, error))?;
    let statement = repository
        .rollback_route_statement(
            &route_id,
            &target.route_version_id,
            &org_id,
            route.version,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let event_id = generated_id("sec");
    let metadata = json!({"alias": route.alias, "route_version": body.version});
    let security = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        &event_id,
        "route.rolled_back.v1",
        "route",
        Some(&route_id),
        "success",
        &metadata,
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "route.rolled_back.v1",
        &metadata,
    )?;
    let results = commit_mutation(
        database,
        &pending,
        &context.received_at,
        &success,
        vec![version_guard, statement, security],
        outbox,
    )
    .await
    .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[3]).unwrap_or_default() != 1 {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The route changed. Refresh and try again.",
        ));
    }
    Ok(replay_response(&success))
}

#[worker::send]
pub async fn update_route_lifecycle(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, route_id)): Path<(String, String)>,
    Json(body): Json<LifecycleRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::RoutesManage,
        Some("route"),
        Some(&route_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    if !matches!(body.lifecycle.as_str(), "draft" | "published" | "disabled") {
        return Err(validation_error(
            &context,
            "lifecycle_invalid",
            "Choose a valid route lifecycle.",
        ));
    }
    if body.version < 1 {
        return Err(validation_error(
            &context,
            "version_invalid",
            "Reload the route.",
        ));
    }
    let database = database(&state, &context)?;
    let repository = AiRepository::new(database);
    let lifecycle_path = format!("/api/v1/orgs/{org_id}/routes/{route_id}/lifecycle");
    let lifecycle_fingerprint = format!("route:{}:{}", body.version, body.lifecycle);
    if let Some(success) = lookup_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &lifecycle_path,
        &lifecycle_fingerprint,
        database,
        &context,
    )
    .await?
    {
        return Ok(replay_response(&success));
    }
    let current = repository
        .find_route(&org_id, &route_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context, "The route was not found."))?;
    if body.version != current.version {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The route changed. Refresh and try again.",
        ));
    }
    if body.lifecycle == "published" && current.active_version_id.is_none() {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "version_required",
            "Publish a route version before publishing the route.",
        ));
    }
    if current.lifecycle == "disabled" {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "lifecycle_terminal",
            "A disabled route cannot be re-enabled.",
        ));
    }
    let mut expected = current.clone();
    expected.lifecycle = body.lifecycle.clone();
    expected.version += 1;
    expected.updated_at = context.received_at.as_str().to_owned();
    let version_guard = repository
        .assert_route_version_statement(&route_id, &org_id, body.version)
        .map_err(|error| database_error(&context, error))?;
    let mutation = begin_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &lifecycle_path,
        &lifecycle_fingerprint,
        database,
        &context,
    )
    .await?;
    let pending = match mutation {
        MutationClaim::Replay(success) => return Ok(replay_response(&success)),
        MutationClaim::Pending(pending) => pending,
    };
    let success =
        StoredSuccess::new(200, route_json(&expected)?).map_err(|_| internal_error(&context))?;
    let statement = repository
        .update_route_lifecycle_statement(
            &route_id,
            &org_id,
            &body.lifecycle,
            body.version,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let event_metadata = json!({"lifecycle": body.lifecycle});
    let security = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        &generated_id("sec"),
        "route.lifecycle_changed.v1",
        "route",
        Some(&route_id),
        "success",
        &event_metadata,
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "route.lifecycle_changed.v1",
        &event_metadata,
    )?;
    let results = commit_mutation(
        database,
        &pending,
        &context.received_at,
        &success,
        vec![version_guard, statement, security],
        outbox,
    )
    .await
    .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[3]).unwrap_or_default() != 1 {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The route changed. Refresh and try again.",
        ));
    }
    Ok(replay_response(&success))
}

#[worker::send]
pub async fn route_history(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, route_id)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Response<Body>, ApiError> {
    let offset = cursor_offset(&context, query.cursor.as_deref())?;
    let limit = page_limit(query.limit);
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::RoutesRead,
        Some("route"),
        Some(&route_id),
    )
    .await?;
    let database = database(&state, &context)?;
    let versions = AiRepository::new(database)
        .list_route_versions(&org_id, &route_id, limit.saturating_add(1), offset)
        .await
        .map_err(|error| database_error(&context, error))?;
    let (window, next_cursor, has_more) = page_window(versions, limit, offset);
    let items = window
        .iter()
        .map(|version| route_version_json(version, &context))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(PageResponse {
        items,
        next_cursor,
        has_more,
    })
    .into_response())
}

#[worker::send]
pub async fn usage(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Response<Body>, ApiError> {
    let offset = cursor_offset(&context, query.cursor.as_deref())?;
    let limit = page_limit(query.limit);
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::UsageRead,
        Some("usage"),
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let usage = AiRepository::new(database)
        .list_usage(&org_id, limit.saturating_add(1), offset)
        .await
        .map_err(|error| database_error(&context, error))?;
    let (window, next_cursor, has_more) = page_window(usage, limit, offset);
    let items = window
        .iter()
        .map(usage_json)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(PageResponse {
        items,
        next_cursor,
        has_more,
    })
    .into_response())
}

async fn validate_config_references(
    repository: &AiRepository<'_>,
    org_id: &str,
    config: &RouteConfig,
    policy: &CatalogPolicy,
    allow_mock: bool,
    context: &RequestContext,
) -> Result<(), ApiError> {
    let models = repository
        .list_models(org_id)
        .await
        .map_err(|error| database_error(context, error))?;
    let providers = repository
        .list_providers(org_id)
        .await
        .map_err(|error| database_error(context, error))?;
    if !allow_mock
        && config.candidates.iter().any(|candidate| {
            providers
                .iter()
                .find(|provider| provider.provider_id == candidate.provider_id)
                .is_some_and(|provider| provider.adapter == "mock")
        })
    {
        return Err(validation_error(
            context,
            "adapter_unavailable",
            "Development mock adapters are unavailable in this environment.",
        ));
    }
    let descriptors = models
        .iter()
        .filter_map(model_descriptor)
        .collect::<Vec<_>>();
    let provider_descriptors = providers
        .iter()
        .filter_map(provider_descriptor)
        .collect::<Vec<_>>();
    select_candidates(
        config,
        &descriptors,
        &provider_descriptors,
        policy,
        &[],
        &[],
        1,
    )
    .map_err(|error| {
        validation_error(
            context,
            route_error_reason(error),
            "One or more route candidates are not available.",
        )
    })?;
    for candidate in &config.candidates {
        if let Some(credential_id) = &candidate.credential_id
            && repository
                .find_credential_for_org(credential_id, org_id)
                .await
                .map_err(|error| database_error(context, error))?
                .is_none()
        {
            return Err(validation_error(
                context,
                "credential_not_found",
                "A route credential is outside this organization.",
            ));
        }
    }
    Ok(())
}

fn route_error_reason(error: RouteSelectionError) -> &'static str {
    match error {
        RouteSelectionError::UnsupportedCapability => "unsupported_capability",
        RouteSelectionError::NoAllowedCandidate
        | RouteSelectionError::NoCandidates
        | RouteSelectionError::InvalidConfig => "route_unavailable",
    }
}

fn model_descriptor(model: &ModelRecord) -> Option<ModelDescriptor> {
    let capabilities =
        serde_json::from_str::<Vec<ModelCapability>>(&model.capabilities_json).ok()?;
    Some(ModelDescriptor {
        model_id: model.model_id.clone(),
        provider_id: model.provider_id.clone(),
        provider_model_id: model.provider_model_id.clone(),
        display_name: model.display_name.clone(),
        capabilities: ModelCapabilities::new(capabilities),
        max_input_tokens: model
            .max_input_tokens
            .and_then(|value| u32::try_from(value).ok()),
        max_output_tokens: model
            .max_output_tokens
            .and_then(|value| u32::try_from(value).ok()),
        lifecycle: CatalogLifecycle::parse(&model.lifecycle)?,
        pricing_version: model.pricing_version.clone(),
    })
}

fn provider_descriptor(provider: &ProviderRecord) -> Option<ProviderDescriptor> {
    Some(ProviderDescriptor {
        provider_id: provider.provider_id.clone(),
        display_name: provider.display_name.clone(),
        adapter: provider.adapter.clone(),
        lifecycle: CatalogLifecycle::parse(&provider.lifecycle)?,
        endpoint_url: provider.endpoint_url.clone(),
    })
}

fn provider_json(provider: &ProviderRecord, include_endpoint: bool) -> Result<Value, ApiError> {
    Ok(json!({
        "provider_id": provider.provider_id,
        "provider_key": provider.provider_key,
        "display_name": provider.display_name,
        "adapter": provider.adapter,
        "lifecycle": provider.lifecycle,
        "version": provider.version,
        "endpoint_id": provider.endpoint_id,
        "endpoint_url": if include_endpoint { provider.endpoint_url.as_deref() } else { None },
        "created_at": provider.created_at,
        "updated_at": provider.updated_at,
    }))
}

fn model_json(model: &ModelRecord, context: &RequestContext) -> Result<Value, ApiError> {
    let capabilities = serde_json::from_str::<Vec<ModelCapability>>(&model.capabilities_json)
        .map_err(|_| service_unavailable(context))?;
    Ok(json!({
        "model_id": model.model_id,
        "provider_id": model.provider_id,
        "provider_model_id": model.provider_model_id,
        "display_name": model.display_name,
        "capabilities": capabilities,
        "max_input_tokens": model.max_input_tokens,
        "max_output_tokens": model.max_output_tokens,
        "lifecycle": model.lifecycle,
        "pricing_version": model.pricing_version,
        "version": model.version,
        "created_at": model.created_at,
        "updated_at": model.updated_at,
    }))
}

fn alias_json(alias: &crate::repositories::AliasRecord) -> Value {
    json!({"alias_id": alias.alias_id, "alias": alias.alias_key, "display_name": alias.display_name, "lifecycle": alias.lifecycle, "description": alias.description, "created_at": alias.created_at, "updated_at": alias.updated_at})
}

fn credential_json(record: &CredentialRecord, context: &RequestContext) -> Result<Value, ApiError> {
    let owner = CredentialOwnerType::parse(&record.owner_type)
        .ok_or_else(|| service_unavailable(context))?;
    let status =
        CredentialStatus::parse(&record.status).ok_or_else(|| service_unavailable(context))?;
    Ok(json!({
        "credential_id": record.credential_id,
        "org_id": record.org_id,
        "owner_type": owner,
        "owner_user_id": if owner == CredentialOwnerType::User { record.owner_user_id.as_deref() } else { None },
        "provider_id": record.provider_id,
        "label": record.label,
        "status": status,
        "version": record.version,
        "fingerprint": masked_fingerprint(&record.fingerprint),
        "key_version": record.key_version.as_deref(),
        "parent_credential_id": record.parent_credential_id,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "last_used_at": record.last_used_at,
        "has_secret": record.ciphertext.is_some(),
    }))
}

fn route_json(route: &RouteRecord) -> Result<Value, ApiError> {
    Ok(
        json!({"route_id": route.route_id, "org_id": route.org_id, "alias": route.alias, "display_name": route.display_name, "strategy": route.strategy, "lifecycle": route.lifecycle, "active_version_id": route.active_version_id, "version": route.version, "created_at": route.created_at, "updated_at": route.updated_at}),
    )
}

fn route_version_json(
    version: &RouteVersionRecord,
    context: &RequestContext,
) -> Result<Value, ApiError> {
    let config = serde_json::from_str::<Value>(&version.config_json)
        .map_err(|_| service_unavailable(context))?;
    Ok(
        json!({"route_version_id": version.route_version_id, "route_id": version.route_id, "version": version.version_number, "config": config, "config_hash": version.config_hash, "created_by_user_id": version.created_by_user_id, "created_at": version.created_at, "published_at": version.published_at}),
    )
}

fn usage_json(usage: &crate::repositories::UsageRecord) -> Result<Value, ApiError> {
    let provider_usage =
        serde_json::from_str::<Value>(&usage.provider_usage_json).unwrap_or_else(|_| json!({}));
    Ok(
        json!({"usage_event_id": usage.usage_event_id, "request_id": usage.request_id, "org_id": usage.org_id, "project_id": usage.project_id, "run_id": usage.run_id, "principal_user_id": usage.principal_user_id, "session_id": usage.session_id, "device_id": usage.device_id, "model_alias": usage.model_alias, "route_version_id": usage.route_version_id, "provider_id": usage.provider_id, "model_id": usage.model_id, "input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens, "cached_tokens": usage.cached_tokens, "provider_usage": provider_usage, "estimated_cost_minor": usage.estimated_cost_minor, "actual_cost_minor": usage.actual_cost_minor, "currency": usage.currency, "pricing_version": usage.pricing_version, "budget_decision": usage.budget_decision, "ttft_ms": usage.ttft_ms, "total_latency_ms": usage.total_latency_ms, "created_at": usage.created_at}),
    )
}

fn generated_id(prefix: &str) -> String {
    new_resource_id(prefix).as_str().to_owned()
}
fn bounded_name(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.chars().count() <= 160 && !value.chars().any(char::is_control))
        .then(|| value.to_owned())
}
fn normalize_key(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    (value.len() <= 64
        && !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        }))
    .then_some(value)
}
fn normalize_alias(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    (value.len() <= 96
        && !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        }))
    .then_some(value)
}
fn valid_secret(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control)
}
fn org_policy(record: Option<&PolicyRecord>, environment: &str) -> CatalogPolicy {
    let Some(record) = record else {
        return if environment == "development" {
            CatalogPolicy::default()
        } else {
            CatalogPolicy {
                allowed_aliases: Some(Default::default()),
                allowed_models: Some(Default::default()),
                allowed_providers: Some(Default::default()),
                enabled: false,
            }
        };
    };
    let parse = |value: &str| {
        serde_json::from_str::<Vec<String>>(value)
            .ok()
            .map(|items| items.into_iter().collect())
    };
    let allowed_aliases = parse(&record.allowed_aliases_json);
    let allowed_models = parse(&record.allowed_models_json);
    let allowed_providers = parse(&record.allowed_providers_json);
    let valid =
        allowed_aliases.is_some() && allowed_models.is_some() && allowed_providers.is_some();
    CatalogPolicy {
        allowed_aliases,
        allowed_models,
        allowed_providers,
        enabled: record.managed_route_enabled && valid,
    }
}

pub(crate) fn default_policy_json(org_id: &str, context: &RequestContext) -> Value {
    json!({
        "org_id": org_id,
        "policy_version": 0,
        "allowed_aliases": null,
        "allowed_models": null,
        "allowed_providers": null,
        "credential_mode": "platform_or_organization",
        "managed_route_enabled": true,
        "version": 0,
        "created_at": context.received_at,
        "updated_at": context.received_at
    })
}

pub(crate) fn policy_json(policy: &crate::repositories::PolicyRecord) -> Value {
    json!({
        "org_id": policy.org_id,
        "policy_version": policy.policy_version,
        "allowed_aliases": serde_json::from_str::<Vec<String>>(&policy.allowed_aliases_json).unwrap_or_default(),
        "allowed_models": serde_json::from_str::<Vec<String>>(&policy.allowed_models_json).unwrap_or_default(),
        "allowed_providers": serde_json::from_str::<Vec<String>>(&policy.allowed_providers_json).unwrap_or_default(),
        "credential_mode": policy.credential_mode,
        "managed_route_enabled": policy.managed_route_enabled,
        "version": policy.version,
        "created_at": policy.created_at,
        "updated_at": policy.updated_at
    })
}

fn validate_policy_values(
    values: &[String],
    context: &RequestContext,
    kind: &str,
) -> Result<(), ApiError> {
    if values.len() > 256
        || values.iter().any(|value| {
            value.is_empty() || value.len() > 255 || value.chars().any(char::is_control)
        })
    {
        return Err(validation_error(
            context,
            &format!("policy_{kind}_invalid"),
            "The policy allowlist is invalid.",
        ));
    }
    Ok(())
}

fn parse_capabilities(values: &[String]) -> Result<Vec<ModelCapability>, ()> {
    values
        .iter()
        .map(|value| ModelCapability::parse(value).ok_or(()))
        .collect()
}
struct PendingMutation {
    record: IdempotencyRecord,
    token: IdempotencyClaimToken,
}

enum MutationClaim {
    Replay(StoredSuccess),
    Pending(PendingMutation),
}

#[allow(clippy::too_many_arguments)]
async fn begin_mutation(
    key: &str,
    user_id: &str,
    org_id: &str,
    method: &str,
    path: &str,
    fingerprint_input: &str,
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
) -> Result<MutationClaim, ApiError> {
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
    let record = IdempotencyRecord {
        scope,
        key_digest,
        request_fingerprint,
        expires_at,
        state: IdempotencyState::Pending,
    };
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
async fn lookup_mutation(
    key: &str,
    user_id: &str,
    org_id: &str,
    method: &str,
    path: &str,
    fingerprint_input: &str,
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
) -> Result<Option<StoredSuccess>, ApiError> {
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
        IdempotencyLookup::Missing => Ok(None),
        IdempotencyLookup::InProgress => Err(idempotency_in_progress(context)),
        IdempotencyLookup::FingerprintConflict => Err(idempotency_conflict(context)),
        IdempotencyLookup::Replay(success) => Ok(Some(success)),
    }
}

async fn commit_mutation(
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

fn replay_response(success: &StoredSuccess) -> Response<Body> {
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

fn idempotency_conflict(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::IdempotencyConflict,
        "idempotency_conflict",
        "The Idempotency-Key was already used for a different request.",
    )
}

fn idempotency_in_progress(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::IdempotencyInProgress,
        "idempotency_in_progress",
        "A request with this Idempotency-Key is still in progress.",
    )
}

fn internal_error(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::InternalError,
        "internal_error",
        "The request could not be completed.",
    )
}

fn page_limit(value: Option<u16>) -> u16 {
    value.unwrap_or(50).clamp(1, 100)
}
fn cursor_offset(context: &RequestContext, cursor: Option<&str>) -> Result<u32, ApiError> {
    let Some(cursor) = cursor.filter(|value| !value.is_empty()) else {
        return Ok(0);
    };
    let offset = cursor.parse::<u32>().map_err(|_| {
        ApiError::new(
            ApiErrorCode::BadRequest,
            "The pagination cursor is invalid.",
            context.request_id.clone(),
        )
        .with_detail("reason", json!("invalid_cursor"))
    })?;
    if offset > 1_000_000 {
        return Err(ApiError::new(
            ApiErrorCode::BadRequest,
            "The pagination cursor is invalid.",
            context.request_id.clone(),
        )
        .with_detail("reason", json!("invalid_cursor")));
    }
    Ok(offset)
}

fn page_window<T>(mut records: Vec<T>, limit: u16, offset: u32) -> (Vec<T>, Option<String>, bool) {
    let has_more = records.len() > usize::from(limit);
    records.truncate(usize::from(limit));
    let next_cursor = has_more.then(|| offset.saturating_add(u32::from(limit)).to_string());
    (records, next_cursor, has_more)
}
fn validation_error(context: &RequestContext, reason: &str, message: &str) -> ApiError {
    domain_error(context, ApiErrorCode::ValidationFailed, reason, message)
}
fn not_found(context: &RequestContext, message: &str) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::NotFound,
        "resource_not_found",
        message,
    )
}
fn service_unavailable(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::ServiceUnavailable,
        "The AI platform store is unavailable.",
    )
}
