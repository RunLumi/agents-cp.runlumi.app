//! P06 data-governance, export, and deletion HTTP surface.
//!
//! This module owns transport validation, current authorization, and bounded
//! idempotency orchestration. Every decision it needs is already made by
//! `modules::data_governance` and by `DataGovernanceRepository`; the handler
//! does not compute a retention window, a state transition, or an export
//! category rule of its own.
//!
//! Rules this module is responsible for:
//!
//! * **Browser mutations** require a session, CSRF, an `Idempotency-Key`, and
//!   the current `version`.
//! * **Tenant scope is re-authorized on every call**, including the download.
//!   A `export_id` from another tenant produces the same non-disclosing
//!   `404 resource_not_found` as a missing one.
//! * **`ready` is the only state that mints a download grant**, and the grant
//!   is re-checked against the current principal, job scope, job state, and
//!   expiry before a single byte is streamed.
//! * **No handler returns export content, an object key, or a grant token in a
//!   body.** The raw grant token is returned once in a response header and only
//!   its fingerprint is persisted.
//! * **The organization deletion request stays in P02.** This module never
//!   exposes `POST /orgs/{org_id}/deletions`; the P02 route
//!   `POST /orgs/{org_id}/deletion` is the sole request and links one
//!   `DeletionJob` (P06-CR-003).
//! * **A pending-deletion organization still answers job status and resume.**
//!   The frozen gate gives those two operations an explicit deletion-job
//!   lifecycle exception; every other permission keeps the standard
//!   `organization_pending_deletion` denial.
//!
//! Route registration: the P06 coordinator adds the eleven routes below to
//! `app::router` and inserts the private R2 binding into the request
//! extensions. Until that wiring lands nothing in this module is reachable from
//! a route table, so the dead-code lint would fire on every handler. Delete this
//! `allow` in the same change that registers the routes.
#![allow(dead_code)]

use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{Extension, FromRequestParts, Path, Query, State},
    http::{HeaderMap, Response, StatusCode, request::Parts},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::{
        new_secret,
        r2::{ArtifactError, ExportArtifactStore, ObjectKey},
        sha256_hex,
    },
    app::AppState,
    core::{ApiError, ApiErrorCode, Principal, RequestContext, StoredSuccess},
    http::auth::{require_csrf, require_session},
    modules::{
        authorization::Permission,
        data_governance::{
            DeletionJobState, DownloadAuthorization, ExportCategory, ExportFormat, ExportJobState,
            ExportRequest, ExportScope, FencedWorkflow, LoggingMode, ResumeAuthorization,
            RetentionDuration, RetentionPolicy, TypedConfirmation, authorize_download, decide,
            decide_fence, deletion, evaluate_account_deletion_exit, export,
            verify_account_deletion_request,
        },
    },
    repositories::{
        AuditEventInput, AuditRepository, DataGovernancePolicyRecord, DataGovernanceRepository,
        DeletionCertificateRecord, DeletionJobRecord, DeletionTaskRecord, ExportArtifactRecord,
        ExportJobRecord, IdentityRepository, NewDeletionInput, NewDownloadGrantInput,
        NewExportInput, NewPolicyInput, PolicyUpdateInput, bounded_metadata,
    },
    routes::{
        agents::{
            PreparedMutation, commit_mutation, decode_page_cursor, encode_page_cursor,
            generated_id, not_found, page_limit, prepare_mutation, replay_response,
            service_unavailable, validate_prefixed_id,
        },
        authorization::{OrgAccess, authorize_org, denial},
        support::{database, database_error, domain_error, idempotency_key, outbox_statement},
    },
};

/// Frozen P06 route templates. The coordinator registers exactly these.
pub const DATA_POLICY_PATH: &str = "/api/v1/orgs/{org_id}/data-policy";
pub const EXPORTS_PATH: &str = "/api/v1/orgs/{org_id}/exports";
pub const EXPORT_PATH: &str = "/api/v1/orgs/{org_id}/exports/{export_id}";
pub const EXPORT_DOWNLOAD_PATH: &str = "/api/v1/orgs/{org_id}/exports/{export_id}/download";
pub const DELETIONS_PATH: &str = "/api/v1/orgs/{org_id}/deletions";
pub const DELETION_PATH: &str = "/api/v1/orgs/{org_id}/deletions/{deletion_id}";
pub const DELETION_RESUME_PATH: &str = "/api/v1/orgs/{org_id}/deletions/{deletion_id}/resume";
pub const ME_EXPORTS_PATH: &str = "/api/v1/me/data/exports";
pub const ME_EXPORT_DOWNLOAD_PATH: &str = "/api/v1/me/data/exports/{export_id}/download";
pub const ME_DELETION_PATH: &str = "/api/v1/me/data/deletion";
pub const ME_DELETION_CANCEL_PATH: &str = "/api/v1/me/data/deletion/cancel";

/// Response header carrying the one-time raw download grant token. The token is
/// returned exactly once, never in a body, and only its fingerprint is stored.
pub const DOWNLOAD_GRANT_HEADER: &str = "x-lumi-download-grant";
pub const DOWNLOAD_GRANT_ID_HEADER: &str = "x-lumi-download-grant-id";
pub const DOWNLOAD_GRANT_EXPIRES_HEADER: &str = "x-lumi-download-grant-expires-at";

/// Reauthentication purpose consumed by a personal export or account deletion.
///
/// The P02 reauthentication endpoint currently mints grants for
/// `ownership_transfer | identity_link | org_lifecycle | passkey_management |
/// password_change | account_recovery`. `org_lifecycle` is the existing
/// account-lifecycle purpose and is the only one a personal data action may
/// consume today; adding `account_data` is a one-line P02 change the
/// coordinator owns (see the handoff).
pub const REAUTH_PURPOSE: &str = "org_lifecycle";

/// Bounded personal-deletion grace window, in seconds.
///
/// The gate requires a "bounded grace-period cancel" without freezing a
/// number. Seven days is the documented P06-BE-04 choice: long enough to
/// transfer an organization, short enough that a user who asked to be removed
/// is not kept in `awaiting_grace` indefinitely.
pub const PERSONAL_DELETION_GRACE_SECONDS: u32 = 7 * 24 * 60 * 60;

/// Lifetime of a minted download grant, in seconds.
///
/// Bounded by the frozen `AccessGrant` baseline (15 minutes) and the
/// `ACCESS_GRANT_CEILING` (24 hours); the shorter value wins because a grant is
/// re-authorized on every use.
pub const DOWNLOAD_GRANT_TTL_SECONDS: u32 = 900;

/// Optional request extension extractor.
///
/// The private R2 binding is inserted into request extensions by the
/// coordinator (`app::router`). A missing binding must degrade to
/// `export_artifact_unavailable`, not to a 500, so this extractor is
/// deliberately optional rather than `axum::extract::Extension`.
pub(crate) struct MaybeExtension<T>(pub Option<T>);

impl<S, T> FromRequestParts<S> for MaybeExtension<T>
where
    S: Send + Sync,
    T: Clone + Send + Sync + 'static,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(MaybeExtension(parts.extensions.get::<T>().cloned()))
    }
}

// ------------------------------------------------------------ requests -----

#[derive(Debug, Deserialize)]
pub struct PageQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PatchDataPolicyRequest {
    pub version: i64,
    pub logging_mode: Option<String>,
    pub class_retention_overrides: Option<Map<String, Value>>,
    pub legal_hold: Option<bool>,
    pub legal_hold_reason: Option<String>,
    pub legal_hold_released_by: Option<String>,
    pub backup_lifecycle: Option<String>,
    pub provider_retention_disclosure: Option<String>,
    pub provider_retention_url: Option<String>,
    pub default_export_expiry_seconds: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateExportRequest {
    pub categories: Vec<String>,
    pub format: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePersonalExportRequest {
    pub categories: Vec<String>,
    pub format: Option<String>,
    pub confirmation: String,
    pub reauth_grant_id: String,
    pub reauth_token: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadRequest {
    /// An existing, still-valid grant token. Absent means "mint a new grant",
    /// which is the normal path; present means "reuse within its window, after
    /// re-authorization".
    pub grant_token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VersionRequest {
    pub version: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePersonalDeletionRequest {
    pub confirmation: String,
    pub reauth_grant_id: String,
    pub reauth_token: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancelPersonalDeletionRequest {
    pub reauth_grant_id: String,
    pub reauth_token: String,
}

// --------------------------------------------------------------- routes ----

#[worker::send]
pub async fn get_data_policy(
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
        Permission::DataRead,
        Some("data_policy"),
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let stored = DataGovernanceRepository::new(database)
        .find_policy(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    let policy = stored.unwrap_or_else(|| baseline_policy(&org_id, &context));
    Ok((StatusCode::OK, Json(policy_json(&context, &policy)?)).into_response())
}

#[worker::send]
pub async fn patch_data_policy(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<PatchDataPolicyRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::DataManage,
        Some("data_policy"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    if body.version <= 0 || body.version == i64::MAX {
        return Err(validation_error(
            &context,
            "data_policy_invalid",
            "The policy version is invalid.",
        ));
    }
    let database = database(&state, &context)?;
    let repository = DataGovernanceRepository::new(database);
    let current = repository
        .find_policy(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .unwrap_or_else(|| baseline_policy(&org_id, &context));
    if current.version != body.version {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "data_policy_version_conflict",
            "The data policy changed. Refresh and try again.",
        ));
    }

    let next = apply_policy_patch(&context, &current, &body)?;
    // A policy is only accepted if the frozen retention model accepts every
    // class it names. This is where "never extend beyond the legal maximum
    // without an audited override" is enforced for a browser caller, which
    // cannot supply one.
    validate_policy_retention(&context, &next)?;

    let body_value = serde_json::to_value(&body).map_err(|_| service_unavailable(&context))?;
    let mutation = prepare_mutation(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        "PATCH",
        DATA_POLICY_PATH,
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };

    let registry_seed = repository
        .registry_seed_statements(&context.received_at)
        .map_err(|error| database_error(&context, error))?;
    let (write, expected_version) = if current.policy_id.is_empty() {
        (
            repository
                .insert_policy_statement(&NewPolicyInput {
                    policy_id: &generated_id("dgp"),
                    org_id: &org_id,
                    logging_mode: &next.logging_mode,
                    overrides_json: &next.class_retention_overrides_json,
                    legal_hold: next.legal_hold_active(),
                    legal_hold_reason: next.legal_hold_reason.as_deref(),
                    legal_hold_placed_at: next.legal_hold_placed_at.as_deref(),
                    legal_hold_released_at: next.legal_hold_released_at.as_deref(),
                    legal_hold_released_by: next.legal_hold_released_by.as_deref(),
                    backup_lifecycle: &next.backup_lifecycle,
                    provider_retention_disclosure: &next.provider_retention_disclosure,
                    provider_retention_url: next.provider_retention_url.as_deref(),
                    default_export_expiry_seconds: next.default_export_expiry_seconds,
                    created_by_principal_id: access.principal.user_id.as_str(),
                    now: &context.received_at,
                })
                .map_err(|error| database_error(&context, error))?,
            0,
        )
    } else {
        (
            repository
                .update_policy_statement(&PolicyUpdateInput {
                    org_id: &org_id,
                    logging_mode: &next.logging_mode,
                    overrides_json: &next.class_retention_overrides_json,
                    legal_hold: next.legal_hold_active(),
                    legal_hold_reason: next.legal_hold_reason.as_deref(),
                    legal_hold_placed_at: next.legal_hold_placed_at.as_deref(),
                    legal_hold_released_at: next.legal_hold_released_at.as_deref(),
                    legal_hold_released_by: next.legal_hold_released_by.as_deref(),
                    backup_lifecycle: &next.backup_lifecycle,
                    provider_retention_disclosure: &next.provider_retention_disclosure,
                    provider_retention_url: next.provider_retention_url.as_deref(),
                    default_export_expiry_seconds: next.default_export_expiry_seconds,
                    expected_version: body.version,
                    now: &context.received_at,
                })
                .map_err(|error| database_error(&context, error))?,
            body.version,
        )
    };
    let assertion = repository
        .assert_policy_version_statement(&org_id, expected_version)
        .map_err(|error| database_error(&context, error))?;
    let changed = changed_policy_keys(&current, &next);
    let audit = audit_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        &generated_id("sec"),
        "data_policy.updated.v1",
        "data_policy",
        &next.policy_id,
        "success",
        &json!({
            "policy_id": next.policy_id,
            "version": body.version + 1,
            "changed_fields": changed,
            "legal_hold": next.legal_hold_active(),
            "logging_mode": next.logging_mode,
        }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "data_policy.updated.v1",
        &json!({
            "policy_id": next.policy_id,
            "org_id": org_id,
            "version": body.version + 1,
            "changed_fields": changed,
        }),
    )?;
    let stored = DataGovernancePolicyRecord {
        version: body.version + 1,
        updated_at: context.received_at.as_str().to_owned(),
        ..next
    };
    let success = StoredSuccess::new(200, policy_json(&context, &stored)?)
        .map_err(|_| service_unavailable(&context))?;
    let mut writes = registry_seed;
    writes.push(assertion);
    writes.push(write);
    writes.push(audit);
    if let Some(replay) =
        commit_mutation(database, &context, claim, success.clone(), writes, outbox).await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::OK, Json(success.body)).into_response())
}

#[worker::send]
pub async fn list_exports(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<PageQuery>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::DataRead,
        Some("export_job"),
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
    let mut records = DataGovernanceRepository::new(database)
        .list_exports_for_org(
            &org_id,
            cursor.as_ref().map(|(at, id)| (at.as_str(), id.as_str())),
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
            .map(|record| encode_page_cursor(&record.requested_at, &record.export_id))
    } else {
        None
    };
    let mut artifacts = Vec::with_capacity(records.len());
    for record in &records {
        artifacts.push(
            DataGovernanceRepository::new(database)
                .find_artifact(&record.export_id)
                .await
                .map_err(|error| database_error(&context, error))?,
        );
    }
    let items = export_page_items(&context, &records, &artifacts)?;
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
pub async fn create_export(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<CreateExportRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::DataExport,
        Some("export_job"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let categories = parse_categories(&context, &body.categories)?;
    let format = parse_format(&context, body.format.as_deref())?;
    let database = database(&state, &context)?;
    // A scope that is being deleted may not start new work: a delayed or
    // duplicated export must not resurrect data.
    refuse_fenced_scope(database, &context, &org_id).await?;
    let cutoff_at =
        crate::consumers::unix_seconds(context.received_at.as_str()).unwrap_or_default();

    let body_value = serde_json::to_value(&body).map_err(|_| service_unavailable(&context))?;
    let mutation = prepare_mutation(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        "POST",
        EXPORTS_PATH,
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };

    let repository = DataGovernanceRepository::new(database);
    let request = ExportRequest {
        requested_by: access.principal.user_id.as_str().to_owned(),
        scope: ExportScope::Organization(org_id.clone()),
        categories: categories.clone(),
        cutoff_at,
        format,
        confirmation: None,
    };
    let manifest = request.into_manifest(cutoff_at).map_err(|error| {
        domain_error(
            &context,
            ApiErrorCode::ValidationFailed,
            error.code(),
            export_message(error.code()),
        )
    })?;
    let categories_json = canonical_categories_json(&manifest.categories)
        .map_err(|_| service_unavailable(&context))?;
    let snapshot_cutoff_at = crate::consumers::unix_to_timestamp(manifest.cutoff_at)
        .ok_or_else(|| service_unavailable(&context))?;

    // A repeated request with the same frozen tuple returns the existing job
    // instead of forking a second one.
    if let Some(existing) = repository
        .find_export_by_dedupe(
            Some(&org_id),
            "organization",
            None,
            Some(&org_id),
            &categories_json,
            &snapshot_cutoff_at,
        )
        .await
        .map_err(|error| database_error(&context, error))?
    {
        let success = StoredSuccess::new(
            201,
            export_json(&context, &existing, None, EXPORT_DOWNLOAD_PATH)?,
        )
        .map_err(|_| service_unavailable(&context))?;
        return Ok((StatusCode::CREATED, Json(success.body)).into_response());
    }

    let export_id = generated_id("exp");
    let insert = repository
        .insert_export_statement(&NewExportInput {
            export_id: &export_id,
            org_id: Some(&org_id),
            scope_type: "organization",
            scope_user_id: None,
            scope_org_id: Some(&org_id),
            categories_json: &categories_json,
            format: format.as_str(),
            snapshot_cutoff_at: &snapshot_cutoff_at,
            requested_by_principal_id: access.principal.user_id.as_str(),
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let envelope = repository
        .insert_queue_envelope_statement(&crate::repositories::NewQueueEnvelopeInput {
            job_id: &generated_id("job"),
            job_type: "export.run",
            org_id: Some(&org_id),
            subject_type: "export_job",
            subject_id: &export_id,
            subject_version: Some(1),
            dedupe_key: &format!("export.run:{export_id}"),
            request_id: context.request_id.as_str(),
            correlation_id: context.correlation_id.as_str(),
            payload_ref: &format!("d1:export_jobs/{export_id}"),
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let audit = audit_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        &generated_id("sec"),
        "export.requested.v1",
        "export_job",
        &export_id,
        "success",
        &json!({
            "job_id": export_id,
            "scope_type": "organization",
            "scope_id": org_id,
            "state": "requested",
            "attempt": 0,
            "resource_version": 1,
        }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "export.requested.v1",
        &json!({
            "job_id": export_id,
            "scope_type": "organization",
            "scope_id": org_id,
            "state": "requested",
            "attempt": 0,
            "resource_version": 1,
            "categories": manifest.category_keys(),
            "snapshot_cutoff_at": snapshot_cutoff_at,
        }),
    )?;
    let stored = ExportJobRecord {
        export_id: export_id.clone(),
        org_id: Some(org_id.clone()),
        scope_type: "organization".to_owned(),
        scope_user_id: None,
        scope_org_id: Some(org_id.clone()),
        categories_json: categories_json.clone(),
        format: format.as_str().to_owned(),
        snapshot_cutoff_at: snapshot_cutoff_at.clone(),
        state: "requested".to_owned(),
        state_version: 1,
        attempt: 0,
        next_attempt_at: None,
        requested_by_principal_id: access.principal.user_id.as_str().to_owned(),
        requested_at: context.received_at.as_str().to_owned(),
        ready_at: None,
        finished_at: None,
        failure_code: None,
        version: 1,
        updated_at: context.received_at.as_str().to_owned(),
    };
    let success = StoredSuccess::new(
        201,
        export_json(&context, &stored, None, EXPORT_DOWNLOAD_PATH)?,
    )
    .map_err(|_| service_unavailable(&context))?;
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![insert, envelope, audit],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::CREATED, Json(success.body)).into_response())
}

#[worker::send]
pub async fn get_export(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, export_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::DataRead,
        Some("export_job"),
        Some(&export_id),
    )
    .await?;
    let export_id = validate_prefixed_id(&context, &export_id, "exp", "export_not_found")?;
    let database = database(&state, &context)?;
    let repository = DataGovernanceRepository::new(database);
    let job = repository
        .find_export_for_scope(&export_id, "organization", &org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context, "resource_not_found"))?;
    let artifact = repository
        .find_artifact(&export_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok((
        StatusCode::OK,
        Json(export_json(
            &context,
            &job,
            artifact.as_ref(),
            EXPORT_DOWNLOAD_PATH,
        )?),
    )
        .into_response())
}

#[worker::send]
pub async fn download_export(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    MaybeExtension(artifacts): MaybeExtension<ExportArtifactStore>,
    headers: HeaderMap,
    Path((org_id, export_id)): Path<(String, String)>,
    Json(body): Json<DownloadRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::DataExport,
        Some("export_job"),
        Some(&export_id),
    )
    .await?;
    let export_id = validate_prefixed_id(&context, &export_id, "exp", "resource_not_found")?;
    let Some(artifacts) = artifacts else {
        return Err(artifact_unavailable(&context));
    };
    let database = database(&state, &context)?;
    let repository = DataGovernanceRepository::new(database);
    let job = repository
        .find_export_for_scope(&export_id, "organization", &org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context, "resource_not_found"))?;
    stream_authorized_download(
        &context,
        &repository,
        &artifacts,
        &job,
        body.grant_token.as_deref(),
        &access.principal,
    )
    .await
}

#[worker::send]
pub async fn list_deletions(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<PageQuery>,
) -> Result<Response<Body>, ApiError> {
    // Explicit deletion-job lifecycle exception: a `pending_deletion`
    // organization must still be able to observe and resume its own job.
    authorize_deletion_job(&state, &headers, &context, &org_id, Permission::DataRead).await?;
    let limit = page_limit(query.limit);
    let cursor = query
        .cursor
        .as_deref()
        .map(|raw| decode_page_cursor(raw, &context))
        .transpose()?;
    let database = database(&state, &context)?;
    let mut records = DataGovernanceRepository::new(database)
        .list_deletions_for_org(
            &org_id,
            cursor.as_ref().map(|(at, id)| (at.as_str(), id.as_str())),
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
            .map(|record| encode_page_cursor(&record.created_at, &record.deletion_id))
    } else {
        None
    };
    let items: Vec<Value> = records
        .iter()
        .map(|record| deletion_json(&context, record))
        .collect::<Result<Vec<_>, ApiError>>()?;
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
pub async fn get_deletion(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, deletion_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    authorize_deletion_job(&state, &headers, &context, &org_id, Permission::DataRead).await?;
    let deletion_id = validate_prefixed_id(&context, &deletion_id, "del", "resource_not_found")?;
    let database = database(&state, &context)?;
    let repository = DataGovernanceRepository::new(database);
    let job = repository
        .find_deletion_for_scope(&deletion_id, "organization", &org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context, "resource_not_found"))?;
    let steps = repository
        .list_deletion_tasks(&deletion_id, 200)
        .await
        .map_err(|error| database_error(&context, error))?;
    let certificate = repository
        .find_certificate(&deletion_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    let body = deletion_detail_json(&context, &job, &steps, certificate.as_ref())?;
    Ok((StatusCode::OK, Json(body)).into_response())
}

#[worker::send]
pub async fn resume_deletion(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, deletion_id)): Path<(String, String)>,
    Json(body): Json<VersionRequest>,
) -> Result<Response<Body>, ApiError> {
    let access =
        authorize_deletion_job(&state, &headers, &context, &org_id, Permission::DataDelete).await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    if body.version <= 0 || body.version == i64::MAX {
        return Err(validation_error(
            &context,
            "deletion_not_resumable",
            "The deletion job version is invalid.",
        ));
    }
    let deletion_id = validate_prefixed_id(&context, &deletion_id, "del", "resource_not_found")?;
    let database = database(&state, &context)?;
    let repository = DataGovernanceRepository::new(database);
    let job = repository
        .find_deletion_for_scope(&deletion_id, "organization", &org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context, "resource_not_found"))?;
    if job.version != body.version {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The deletion job changed. Refresh and try again.",
        ));
    }
    let hold = active_hold(database, &context, &org_id).await?;
    let authorization = match &hold {
        Some(hold) => ResumeAuthorization::legal_hold_release(
            true,
            hold.released_at().is_some(),
            hold.released_by()
                .map(str::to_owned)
                .unwrap_or_else(|| access.principal.user_id.as_str().to_owned()),
        ),
        None => ResumeAuthorization::permitted(),
    };
    let current =
        DeletionJobState::parse(&job.state).ok_or_else(|| service_unavailable(&context))?;
    let next = current.resume(&authorization).map_err(|error| {
        domain_error(
            &context,
            ApiErrorCode::Conflict,
            error.code(),
            deletion_message(error.code()),
        )
    })?;

    let body_value = serde_json::to_value(&body).map_err(|_| service_unavailable(&context))?;
    let mutation = prepare_mutation(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        "POST",
        &format!("/api/v1/orgs/{org_id}/deletions/{deletion_id}/resume"),
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };

    let update = repository
        .update_deletion_state_statement(&crate::repositories::DeletionStateUpdateInput {
            deletion_id: &deletion_id,
            expected_version: job.version,
            next_state: next.as_str(),
            increment_attempt: false,
            next_attempt_at: None,
            // The parked failure reason is cleared by a successful resume so the
            // projection stops reporting a failure the job has left behind.
            failure_code: None,
            grace_expires_at: None,
            certificate_id: None,
            completed_at: None,
            expected_state: &job.state,
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let envelope = repository
        .insert_queue_envelope_statement(&crate::repositories::NewQueueEnvelopeInput {
            job_id: &generated_id("job"),
            job_type: "deletion.run",
            org_id: Some(&org_id),
            subject_type: "deletion_job",
            subject_id: &deletion_id,
            subject_version: Some(body.version + 1),
            // A resume keeps the same logical job, so the dedupe key is the same
            // and the unique index absorbs a duplicate resume.
            dedupe_key: &format!("deletion.run:{deletion_id}"),
            request_id: context.request_id.as_str(),
            correlation_id: context.correlation_id.as_str(),
            payload_ref: &format!("d1:deletion_jobs/{deletion_id}"),
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let audit = audit_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        &generated_id("sec"),
        "deletion.resumed.v1",
        "deletion_job",
        &deletion_id,
        "success",
        &json!({
            "job_id": deletion_id,
            "scope_type": "organization",
            "scope_id": org_id,
            "state": next.as_str(),
            "attempt": job.attempt,
            "resource_version": body.version + 1,
            "legal_hold_released": hold.is_none(),
        }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "deletion.resumed.v1",
        &json!({
            "job_id": deletion_id,
            "scope_type": "organization",
            "scope_id": org_id,
            "state": next.as_str(),
            "attempt": job.attempt,
            "resource_version": body.version + 1,
        }),
    )?;
    let stored = DeletionJobRecord {
        state: next.as_str().to_owned(),
        version: body.version + 1,
        failure_code: None,
        updated_at: context.received_at.as_str().to_owned(),
        ..job
    };
    let success = StoredSuccess::new(200, deletion_json(&context, &stored)?)
        .map_err(|_| service_unavailable(&context))?;
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![update, envelope, audit],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::OK, Json(success.body)).into_response())
}

#[worker::send]
pub async fn create_personal_export(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    MaybeExtension(artifacts): MaybeExtension<ExportArtifactStore>,
    headers: HeaderMap,
    Json(body): Json<CreatePersonalExportRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    if artifacts.is_none() {
        // Fail before creating a job that could never be packaged.
        return Err(artifact_unavailable(&context));
    }
    let categories = parse_categories(&context, &body.categories)?;
    let format = parse_format(&context, body.format.as_deref())?;
    let now_unix = crate::consumers::unix_seconds(context.received_at.as_str()).unwrap_or_default();
    consume_reauthentication(
        &state,
        &context,
        &authenticated.principal,
        &authenticated.session,
        &body.reauth_grant_id,
        &body.reauth_token,
    )
    .await?;
    let confirmation = TypedConfirmation::new(body.confirmation.clone(), now_unix);
    confirmation
        .verify(export::EXPORT_CONFIRMATION_PHRASE, now_unix)
        .map_err(|error| {
            domain_error(
                &context,
                ApiErrorCode::ValidationFailed,
                error.code(),
                "Type the export confirmation phrase to continue.",
            )
        })?;

    let database = database(&state, &context)?;
    let user_id = authenticated.principal.user_id.as_str().to_owned();
    let body_value = serde_json::to_value(&body).map_err(|_| service_unavailable(&context))?;
    let mutation = prepare_mutation(
        database,
        &context,
        &authenticated.principal,
        &user_id,
        &key,
        "POST",
        ME_EXPORTS_PATH,
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };

    let repository = DataGovernanceRepository::new(database);
    let request = ExportRequest {
        requested_by: user_id.clone(),
        scope: ExportScope::User(user_id.clone()),
        categories: categories.clone(),
        cutoff_at: now_unix,
        format,
        confirmation: Some(confirmation),
    };
    let manifest = request.into_manifest(now_unix).map_err(|error| {
        domain_error(
            &context,
            ApiErrorCode::ValidationFailed,
            error.code(),
            export_message(error.code()),
        )
    })?;
    let categories_json = canonical_categories_json(&manifest.categories)
        .map_err(|_| service_unavailable(&context))?;
    let snapshot_cutoff_at = crate::consumers::unix_to_timestamp(manifest.cutoff_at)
        .ok_or_else(|| service_unavailable(&context))?;
    let export_id = generated_id("exp");
    let insert = repository
        .insert_export_statement(&NewExportInput {
            export_id: &export_id,
            org_id: None,
            scope_type: "user",
            scope_user_id: Some(&user_id),
            scope_org_id: None,
            categories_json: &categories_json,
            format: format.as_str(),
            snapshot_cutoff_at: &snapshot_cutoff_at,
            requested_by_principal_id: &user_id,
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let envelope = repository
        .insert_queue_envelope_statement(&crate::repositories::NewQueueEnvelopeInput {
            job_id: &generated_id("job"),
            job_type: "export.run",
            org_id: None,
            subject_type: "export_job",
            subject_id: &export_id,
            subject_version: Some(1),
            dedupe_key: &format!("export.run:{export_id}"),
            request_id: context.request_id.as_str(),
            correlation_id: context.correlation_id.as_str(),
            payload_ref: &format!("d1:export_jobs/{export_id}"),
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let audit = audit_statement(
        database,
        &context,
        Some(&authenticated.principal),
        None,
        &generated_id("sec"),
        "export.requested.v1",
        "export_job",
        &export_id,
        "success",
        &json!({
            "job_id": export_id,
            "scope_type": "user",
            "scope_id": user_id,
            "state": "requested",
            "attempt": 0,
            "resource_version": 1,
        }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&authenticated.principal),
        None,
        "export.requested.v1",
        &json!({
            "job_id": export_id,
            "scope_type": "user",
            "scope_id": user_id,
            "state": "requested",
            "attempt": 0,
            "resource_version": 1,
            "categories": manifest.category_keys(),
            "snapshot_cutoff_at": snapshot_cutoff_at,
        }),
    )?;
    let stored = ExportJobRecord {
        export_id: export_id.clone(),
        org_id: None,
        scope_type: "user".to_owned(),
        scope_user_id: Some(user_id.clone()),
        scope_org_id: None,
        categories_json,
        format: format.as_str().to_owned(),
        snapshot_cutoff_at,
        state: "requested".to_owned(),
        state_version: 1,
        attempt: 0,
        next_attempt_at: None,
        requested_by_principal_id: user_id.clone(),
        requested_at: context.received_at.as_str().to_owned(),
        ready_at: None,
        finished_at: None,
        failure_code: None,
        version: 1,
        updated_at: context.received_at.as_str().to_owned(),
    };
    let success = StoredSuccess::new(
        201,
        export_json(&context, &stored, None, ME_EXPORT_DOWNLOAD_PATH)?,
    )
    .map_err(|_| service_unavailable(&context))?;
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![insert, envelope, audit],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::CREATED, Json(success.body)).into_response())
}

#[worker::send]
pub async fn list_personal_exports(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    let limit = page_limit(query.limit);
    let cursor = query
        .cursor
        .as_deref()
        .map(|raw| decode_page_cursor(raw, &context))
        .transpose()?;
    let database = database(&state, &context)?;
    let user_id = authenticated.principal.user_id.as_str();
    let mut records = DataGovernanceRepository::new(database)
        .list_exports_for_user(
            user_id,
            cursor.as_ref().map(|(at, id)| (at.as_str(), id.as_str())),
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
            .map(|record| encode_page_cursor(&record.requested_at, &record.export_id))
    } else {
        None
    };
    let mut artifacts = Vec::with_capacity(records.len());
    for record in &records {
        artifacts.push(
            DataGovernanceRepository::new(database)
                .find_artifact(&record.export_id)
                .await
                .map_err(|error| database_error(&context, error))?,
        );
    }
    let items = personal_export_page_items(&context, &records, &artifacts)?;
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
pub async fn download_personal_export(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    MaybeExtension(artifacts): MaybeExtension<ExportArtifactStore>,
    headers: HeaderMap,
    Path(export_id): Path<String>,
    Json(body): Json<DownloadRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    let export_id = validate_prefixed_id(&context, &export_id, "exp", "resource_not_found")?;
    let Some(artifacts) = artifacts else {
        return Err(artifact_unavailable(&context));
    };
    let database = database(&state, &context)?;
    let repository = DataGovernanceRepository::new(database);
    let user_id = authenticated.principal.user_id.as_str();
    let job = repository
        .find_export_for_scope(&export_id, "user", user_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context, "resource_not_found"))?;
    stream_authorized_download(
        &context,
        &repository,
        &artifacts,
        &job,
        body.grant_token.as_deref(),
        &authenticated.principal,
    )
    .await
}

#[worker::send]
pub async fn create_personal_deletion(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<CreatePersonalDeletionRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let database = database(&state, &context)?;
    let now_unix = crate::consumers::unix_seconds(context.received_at.as_str()).unwrap_or_default();
    consume_reauthentication(
        &state,
        &context,
        &authenticated.principal,
        &authenticated.session,
        &body.reauth_grant_id,
        &body.reauth_token,
    )
    .await?;
    let confirmation = TypedConfirmation::new(body.confirmation.clone(), now_unix);
    verify_account_deletion_request(&confirmation, now_unix).map_err(|error| {
        domain_error(
            &context,
            ApiErrorCode::ValidationFailed,
            error.code(),
            "Type the account-deletion confirmation phrase to continue.",
        )
    })?;

    let user_id = authenticated.principal.user_id.as_str().to_owned();
    // The organization-exit rule: a user who still actively owns or administers
    // an organization must leave or transfer out of it first.
    let memberships = crate::repositories::OrganizationRepository::new(database)
        .list_for_user(&user_id, 100, 0)
        .await
        .map_err(|error| database_error(&context, error))?;
    let references: Vec<deletion::OrgMembershipRef> = memberships
        .iter()
        .map(|summary| deletion::OrgMembershipRef {
            org_id: summary.organization.org_id.clone(),
            role: org_role(&summary.role),
            // The organization lifecycle will resolve this membership, so it does
            // not block the account deletion.
            exit_possible: summary.organization.state != "active" || summary.status != "active",
        })
        .collect();
    evaluate_account_deletion_exit(&references).map_err(|error| {
        domain_error(
            &context,
            ApiErrorCode::Conflict,
            error.code(),
            "Leave or transfer every organization you own or administer first.",
        )
    })?;

    let body_value = serde_json::to_value(&body).map_err(|_| service_unavailable(&context))?;
    let mutation = prepare_mutation(
        database,
        &context,
        &authenticated.principal,
        &user_id,
        &key,
        "POST",
        ME_DELETION_PATH,
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };

    let repository = DataGovernanceRepository::new(database);
    // A second account-deletion request must never fork a second job.
    if let Some(existing) = repository
        .find_deletion_for_target("user", &user_id)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        let success = StoredSuccess::new(200, deletion_json(&context, &existing)?)
            .map_err(|_| service_unavailable(&context))?;
        return Ok((StatusCode::OK, Json(success.body)).into_response());
    }
    let grace_expires_at =
        crate::adapters::add_seconds(&context.received_at, PERSONAL_DELETION_GRACE_SECONDS)
            .map_err(|_| service_unavailable(&context))?;
    let deletion_id = generated_id("del");
    let insert = repository
        .insert_deletion_statement(&NewDeletionInput {
            deletion_id: &deletion_id,
            org_id: None,
            target_type: "user",
            target_user_id: Some(&user_id),
            target_org_id: None,
            lifecycle_request_id: Some(context.request_id.as_str()),
            state: DeletionJobState::AwaitingGrace.as_str(),
            grace_expires_at: Some(grace_expires_at.as_str()),
            cutoff_at: Some(context.received_at.as_str()),
            fenced: true,
            legal_hold: false,
            requested_by_principal_id: &user_id,
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let envelope = repository
        .insert_queue_envelope_statement(&crate::repositories::NewQueueEnvelopeInput {
            job_id: &generated_id("job"),
            job_type: "deletion.run",
            org_id: None,
            subject_type: "deletion_job",
            subject_id: &deletion_id,
            subject_version: Some(1),
            dedupe_key: &format!("deletion.run:{deletion_id}"),
            request_id: context.request_id.as_str(),
            correlation_id: context.correlation_id.as_str(),
            payload_ref: &format!("d1:deletion_jobs/{deletion_id}"),
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let audit = audit_statement(
        database,
        &context,
        Some(&authenticated.principal),
        None,
        &generated_id("sec"),
        "deletion.requested.v1",
        "deletion_job",
        &deletion_id,
        "success",
        &json!({
            "job_id": deletion_id,
            "scope_type": "user",
            "scope_id": user_id,
            "state": DeletionJobState::AwaitingGrace.as_str(),
            "attempt": 0,
            "resource_version": 1,
        }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&authenticated.principal),
        None,
        "deletion.requested.v1",
        &json!({
            "job_id": deletion_id,
            "scope_type": "user",
            "scope_id": user_id,
            "state": DeletionJobState::AwaitingGrace.as_str(),
            "attempt": 0,
            "resource_version": 1,
            "grace_expires_at": grace_expires_at.as_str(),
        }),
    )?;
    let stored = DeletionJobRecord {
        deletion_id: deletion_id.clone(),
        org_id: None,
        target_type: "user".to_owned(),
        target_user_id: Some(user_id.clone()),
        target_org_id: None,
        lifecycle_request_id: Some(context.request_id.as_str().to_owned()),
        state: DeletionJobState::AwaitingGrace.as_str().to_owned(),
        state_version: 1,
        attempt: 0,
        next_attempt_at: None,
        grace_expires_at: Some(grace_expires_at.as_str().to_owned()),
        cutoff_at: Some(context.received_at.as_str().to_owned()),
        fenced: 1,
        legal_hold: 0,
        failure_code: None,
        certificate_id: None,
        requested_by_principal_id: user_id.clone(),
        created_at: context.received_at.as_str().to_owned(),
        updated_at: context.received_at.as_str().to_owned(),
        completed_at: None,
        version: 1,
    };
    let success = StoredSuccess::new(201, deletion_json(&context, &stored)?)
        .map_err(|_| service_unavailable(&context))?;
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![insert, envelope, audit],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::CREATED, Json(success.body)).into_response())
}

#[worker::send]
pub async fn get_personal_deletion(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    let database = database(&state, &context)?;
    let user_id = authenticated.principal.user_id.as_str();
    match DataGovernanceRepository::new(database)
        .find_deletion_for_target("user", user_id)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        Some(job) => {
            let steps = DataGovernanceRepository::new(database)
                .list_deletion_tasks(&job.deletion_id, 200)
                .await
                .map_err(|error| database_error(&context, error))?;
            let certificate = DataGovernanceRepository::new(database)
                .find_certificate(&job.deletion_id)
                .await
                .map_err(|error| database_error(&context, error))?;
            Ok((
                StatusCode::OK,
                Json(deletion_detail_json(
                    &context,
                    &job,
                    &steps,
                    certificate.as_ref(),
                )?),
            )
                .into_response())
        }
        None => Ok((
            StatusCode::OK,
            Json(json!({
                "state": "none",
                "grace_expires_at": Value::Null,
                "disclosures": crate::modules::data_governance::deletion::DISCLOSURES,
            })),
        )
            .into_response()),
    }
}

#[worker::send]
pub async fn cancel_personal_deletion(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<CancelPersonalDeletionRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let database = database(&state, &context)?;
    let now_unix = crate::consumers::unix_seconds(context.received_at.as_str()).unwrap_or_default();
    consume_reauthentication(
        &state,
        &context,
        &authenticated.principal,
        &authenticated.session,
        &body.reauth_grant_id,
        &body.reauth_token,
    )
    .await?;
    let user_id = authenticated.principal.user_id.as_str().to_owned();
    let repository = DataGovernanceRepository::new(database);
    let job = repository
        .find_deletion_for_target("user", &user_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context, "resource_not_found"))?;
    let state = DeletionJobState::parse(&job.state).ok_or_else(|| service_unavailable(&context))?;
    let grace_expires_at = job
        .grace_expires_at
        .as_deref()
        .and_then(crate::consumers::unix_seconds);
    if state == DeletionJobState::Cancelled {
        let success = StoredSuccess::new(200, deletion_json(&context, &job)?)
            .map_err(|_| service_unavailable(&context))?;
        return Ok((StatusCode::OK, Json(success.body)).into_response());
    }
    if !DeletionJobState::grace_cancel_allowed(state, now_unix, grace_expires_at) {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "deletion_not_resumable",
            "The account-deletion grace window has closed.",
        ));
    }
    let body_value = serde_json::to_value(&body).map_err(|_| service_unavailable(&context))?;
    let mutation = prepare_mutation(
        database,
        &context,
        &authenticated.principal,
        &user_id,
        &key,
        "POST",
        ME_DELETION_CANCEL_PATH,
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };
    let update = repository
        .update_deletion_state_statement(&crate::repositories::DeletionStateUpdateInput {
            deletion_id: &job.deletion_id,
            expected_version: job.version,
            next_state: DeletionJobState::Cancelled.as_str(),
            increment_attempt: false,
            next_attempt_at: None,
            failure_code: Some("cancelled_by_user"),
            grace_expires_at: None,
            certificate_id: None,
            completed_at: Some(context.received_at.as_str()),
            expected_state: &job.state,
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let audit = audit_statement(
        database,
        &context,
        Some(&authenticated.principal),
        None,
        &generated_id("sec"),
        "deletion.cancelled.v1",
        "deletion_job",
        &job.deletion_id,
        "success",
        &json!({
            "job_id": job.deletion_id,
            "scope_type": "user",
            "scope_id": user_id,
            "state": DeletionJobState::Cancelled.as_str(),
            "attempt": job.attempt,
            "resource_version": job.version + 1,
        }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&authenticated.principal),
        None,
        "deletion.failed.v1",
        &json!({
            "job_id": job.deletion_id,
            "scope_type": "user",
            "scope_id": user_id,
            "state": DeletionJobState::Cancelled.as_str(),
            "attempt": job.attempt,
            "resource_version": job.version + 1,
            "failure_code": "cancelled_by_user",
        }),
    )?;
    let stored = DeletionJobRecord {
        state: DeletionJobState::Cancelled.as_str().to_owned(),
        version: job.version + 1,
        failure_code: Some("cancelled_by_user".to_owned()),
        completed_at: Some(context.received_at.as_str().to_owned()),
        updated_at: context.received_at.as_str().to_owned(),
        ..job
    };
    let success = StoredSuccess::new(200, deletion_json(&context, &stored)?)
        .map_err(|_| service_unavailable(&context))?;
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![update, audit],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::OK, Json(success.body)).into_response())
}

// ------------------------------------------------------------- download ----

/// Re-authorize, mint (or reuse) a download grant, and stream the private object.
///
/// Order is the security contract: scope, state, expiry, and the current
/// principal are all re-checked here, and only then is the R2 body handed to
/// the runtime as a stream. The response never contains the object key, and the
/// raw grant token appears once, in a header.
async fn stream_authorized_download(
    context: &RequestContext,
    repository: &DataGovernanceRepository<'_>,
    artifacts: &ExportArtifactStore,
    job: &ExportJobRecord,
    supplied_grant: Option<&str>,
    principal: &Principal,
) -> Result<Response<Body>, ApiError> {
    let state = ExportJobState::parse(&job.state).ok_or_else(|| service_unavailable(context))?;
    if !state.can_mint_download_grant() {
        return Err(domain_error(
            context,
            ApiErrorCode::Conflict,
            "export_not_ready",
            "The export is not ready to download.",
        ));
    }
    let artifact = repository
        .find_artifact(&job.export_id)
        .await
        .map_err(|error| database_error(context, error))?
        .ok_or_else(|| {
            domain_error(
                context,
                ApiErrorCode::Conflict,
                "export_artifact_unavailable",
                "The export artifact is not available.",
            )
        })?;
    if artifact.deleted_at.is_some() {
        return Err(domain_error(
            context,
            ApiErrorCode::Conflict,
            "export_artifact_unavailable",
            "The export artifact is not available.",
        ));
    }
    let now_unix = crate::consumers::unix_seconds(context.received_at.as_str()).unwrap_or_default();
    // A legal hold keeps the artifact bytes for the audit trail but still blocks
    // a new grant, so the hold is read from the current policy here rather than
    // cached on the job row.
    let hold_active = match job.scope_org_id.as_deref() {
        Some(org_id) => active_hold(repository.database(), context, org_id)
            .await?
            .is_some_and(|hold| hold.is_active_flag()),
        None => false,
    };
    let _grant = authorize_download(
        &DownloadAuthorization {
            state,
            artifact_expires_at: crate::consumers::unix_seconds(&artifact.expires_at),
            grant_scope: scope_of(context, job)?,
            // The principal was re-authorized by the route immediately above.
            principal_reauthorized: true,
            legal_hold_active: hold_active,
        },
        now_unix,
    )
    .map_err(|error| {
        domain_error(
            context,
            ApiErrorCode::Conflict,
            error.code(),
            export_message(error.code()),
        )
    })?;

    // A grant token, when supplied, must match a stored grant for *this* export,
    // *this* principal, and the same snapshot cutoff, and must not be expired or
    // revoked. Anything else is refused; a token is never trusted on its own.
    if let Some(token) = supplied_grant {
        let fingerprint = format!("sha256:{}", sha256_hex(token).await.unwrap_or_default());
        let stored = repository
            .find_download_grant(&fingerprint)
            .await
            .map_err(|error| database_error(context, error))?
            .filter(|row| {
                row.export_id == job.export_id
                    && row.user_id == principal.user_id.as_str()
                    && row.revoked_at.is_none()
                    && crate::consumers::unix_seconds(&row.expires_at)
                        .is_some_and(|at| now_unix < at)
                    && row.job_scope_type == job.scope_type
                    && row.job_snapshot_cutoff_at == job.snapshot_cutoff_at
            })
            .ok_or_else(|| {
                domain_error(
                    context,
                    ApiErrorCode::PermissionDenied,
                    "permission_denied",
                    "The download grant is not valid for this export.",
                )
            })?;
        let touch = repository
            .touch_download_grant_statement(&stored.grant_id, context.received_at.as_str())
            .map_err(|error| database_error(context, error))?;
        repository
            .batch(vec![touch])
            .await
            .map_err(|error| database_error(context, error))?;
    } else {
        let token = new_secret();
        let fingerprint = format!("sha256:{}", sha256_hex(&token).await.unwrap_or_default());
        let grant_id = generated_id("grant");
        let expires_at =
            crate::adapters::add_seconds(&context.received_at, DOWNLOAD_GRANT_TTL_SECONDS)
                .map_err(|_| service_unavailable(context))?;
        let insert = repository
            .insert_download_grant_statement(&NewDownloadGrantInput {
                grant_id: &grant_id,
                export_id: &job.export_id,
                artifact_id: &artifact.artifact_id,
                org_id: job.org_id.as_deref(),
                user_id: principal.user_id.as_str(),
                token_fingerprint: &fingerprint,
                issued_at: context.received_at.as_str(),
                expires_at: expires_at.as_str(),
            })
            .map_err(|error| database_error(context, error))?;
        repository
            .batch(vec![insert])
            .await
            .map_err(|error| database_error(context, error))?;
        // The token is returned once, in a header, and is never persisted.
        return stream_object(
            context,
            artifacts,
            &artifact,
            job,
            Some((grant_id, token, expires_at.as_str().to_owned())),
        )
        .await;
    }
    stream_object(context, artifacts, &artifact, job, None).await
}

async fn stream_object(
    context: &RequestContext,
    artifacts: &ExportArtifactStore,
    artifact: &ExportArtifactRecord,
    job: &ExportJobRecord,
    grant: Option<(String, String, String)>,
) -> Result<Response<Body>, ApiError> {
    let key = ObjectKey::new(artifact.object_key.clone()).map_err(|_| {
        domain_error(
            context,
            ApiErrorCode::Conflict,
            "export_artifact_unavailable",
            "The export artifact is not available.",
        )
    })?;
    let descriptor = crate::consumers::stream_descriptor(&artifact.content_type, &job.export_id)
        .ok_or_else(|| {
            domain_error(
                context,
                ApiErrorCode::Conflict,
                "export_artifact_unavailable",
                "The export artifact format is not downloadable.",
            )
        })?;
    let download = artifacts.stream(&key, &descriptor).await.map_err(|error| {
        let reason = match error {
            ArtifactError::ObjectAbsent => "export_artifact_unavailable",
            _ => "export_artifact_unavailable",
        };
        domain_error(
            context,
            ApiErrorCode::Conflict,
            reason,
            "The export artifact is not available.",
        )
    })?;
    let mut response: axum::http::Response<Body> = download.into_response().into();
    if let Some((grant_id, token, expires_at)) = grant {
        let headers = response.headers_mut();
        if let Ok(value) = axum::http::HeaderValue::from_str(&token) {
            headers.insert(DOWNLOAD_GRANT_HEADER, value);
        }
        if let Ok(value) = axum::http::HeaderValue::from_str(&grant_id) {
            headers.insert(DOWNLOAD_GRANT_ID_HEADER, value);
        }
        if let Ok(value) = axum::http::HeaderValue::from_str(&expires_at) {
            headers.insert(DOWNLOAD_GRANT_EXPIRES_HEADER, value);
        }
    }
    Ok(response)
}

// ------------------------------------------------------- authorization -----

/// Authorize an operation against a `pending_deletion` organization.
///
/// The frozen gate grants the deletion-job status/resume endpoints an explicit
/// lifecycle exception so a user can still observe and finish their own
/// deletion. The exception is deliberately narrow: it applies only to a
/// `pending_deletion` organization, only to `data.read`/`data.delete`, and it
/// only re-maps the organization state for the permission decision. Role,
/// membership, and email verification are still checked centrally, and every
/// other permission keeps the standard `organization_pending_deletion` denial.
async fn authorize_deletion_job(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    context: &RequestContext,
    org_id: &str,
    permission: Permission,
) -> Result<OrgAccess, ApiError> {
    let authenticated = require_session(state, headers, context).await?;
    let database = database(state, context)?;
    let repository = crate::repositories::OrganizationRepository::new(database);
    let organization = repository
        .find_organization(org_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .ok_or_else(|| not_found(context, "resource_not_found"))?;
    let membership = repository
        .find_membership(org_id, authenticated.principal.user_id.as_str())
        .await
        .map_err(|_| service_unavailable(context))?
        .ok_or_else(|| not_found(context, "resource_not_found"))?;
    let stored_state = crate::modules::authorization::OrganizationState::parse(&organization.state)
        .ok_or_else(|| service_unavailable(context))?;
    let deletion_job_exception = stored_state
        == crate::modules::authorization::OrganizationState::PendingDeletion
        && matches!(permission, Permission::DataRead | Permission::DataDelete);
    let effective_state = if deletion_job_exception {
        crate::modules::authorization::OrganizationState::Active
    } else {
        stored_state
    };
    let role = crate::modules::authorization::MembershipRole::parse(&membership.role)
        .ok_or_else(|| service_unavailable(context))?;
    let status = crate::modules::authorization::MembershipStatus::parse(&membership.status)
        .ok_or_else(|| service_unavailable(context))?;
    let organization_context = crate::modules::authorization::OrganizationContext {
        organization_id: crate::core::OrganizationId::new(org_id)
            .map_err(|_| not_found(context, "resource_not_found"))?,
        state: effective_state,
        version: organization.version,
    };
    let membership_snapshot = crate::modules::authorization::MembershipSnapshot {
        membership_id: crate::core::MembershipId::new(&membership.membership_id)
            .map_err(|_| service_unavailable(context))?,
        organization_id: organization_context.organization_id.clone(),
        user_id: authenticated.principal.user_id.clone(),
        role,
        status,
        version: membership.version,
    };
    let resource = crate::modules::authorization::ResourceContext {
        resource_type: "deletion_job".to_owned(),
        resource_id: org_id.to_owned(),
        organization_id: organization_context.organization_id.clone(),
    };
    let decision = crate::modules::authorization::authorize(
        Some(&authenticated.principal),
        &organization_context,
        Some(&membership_snapshot),
        &permission,
        Some(&resource),
    );
    if let crate::modules::authorization::AuthorizationDecision::Deny(reason) = decision {
        return Err(denial(context, reason));
    }
    Ok(OrgAccess {
        principal: authenticated.principal,
        organization,
        membership,
        session: authenticated.session,
    })
}

/// Consume a P02 reauthentication grant for a personal data action.
async fn consume_reauthentication(
    state: &Arc<AppState>,
    context: &RequestContext,
    principal: &Principal,
    session: &crate::repositories::SessionRecord,
    grant_id: &str,
    token: &str,
) -> Result<(), ApiError> {
    let _ = state;
    let database = database(state, context)?;
    let token_hash = sha256_hex(token)
        .await
        .map_err(|_| service_unavailable(context))?;
    let consumed = IdentityRepository::new(database)
        .consume_reauth(
            grant_id,
            principal.user_id.as_str(),
            principal.session_id.as_str(),
            REAUTH_PURPOSE,
            &token_hash,
            &context.received_at,
        )
        .await
        .map_err(|error| database_error(context, error))?;
    let _ = session;
    if consumed {
        return Ok(());
    }
    Err(domain_error(
        context,
        ApiErrorCode::PermissionDenied,
        "deletion_reauth_required",
        "Complete a recent security check before continuing.",
    ))
}

/// Refuse new tenant work while the scope is being deleted.
async fn refuse_fenced_scope(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    org_id: &str,
) -> Result<(), ApiError> {
    let repository = DataGovernanceRepository::new(database);
    let now_unix = crate::consumers::unix_seconds(context.received_at.as_str()).unwrap_or_default();
    let deletion = repository
        .find_deletion_for_target("organization", org_id)
        .await
        .map_err(|error| database_error(context, error))?;
    let organization = crate::repositories::OrganizationRepository::new(database)
        .find_organization(org_id)
        .await
        .map_err(|error| database_error(context, error))?;
    let pending = organization
        .as_ref()
        .is_some_and(|record| record.state == "pending_deletion");
    let decision = decide_fence(
        FencedWorkflow::ExportCreation,
        deletion
            .as_ref()
            .and_then(|job| job.cutoff_at.as_deref())
            .and_then(crate::consumers::unix_seconds),
        pending,
        now_unix,
    );
    if decision.action.is_blocked() {
        return Err(domain_error(
            context,
            ApiErrorCode::Conflict,
            decision.reason,
            "This organization is being deleted; new data work is blocked.",
        ));
    }
    Ok(())
}

/// Read the current legal hold for a tenant, if any.
async fn active_hold(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    org_id: &str,
) -> Result<Option<crate::modules::data_governance::LegalHold>, ApiError> {
    let policy = DataGovernanceRepository::new(database)
        .find_policy(org_id)
        .await
        .map_err(|error| database_error(context, error))?;
    let Some(policy) = policy else {
        return Ok(None);
    };
    if !policy.legal_hold_active() {
        return Ok(None);
    }
    crate::modules::data_governance::LegalHold::new(
        true,
        crate::modules::data_governance::HoldScope::All,
        crate::consumers::unix_seconds(
            policy
                .legal_hold_placed_at
                .as_deref()
                .unwrap_or(&policy.created_at),
        )
        .unwrap_or_default(),
        policy
            .legal_hold_released_at
            .as_deref()
            .and_then(crate::consumers::unix_seconds),
        policy.legal_hold_released_by.clone(),
        policy
            .legal_hold_reason
            .clone()
            .unwrap_or_else(|| "legal hold recorded".to_owned()),
    )
    .map(Some)
    .map_err(|_| {
        domain_error(
            context,
            ApiErrorCode::Conflict,
            "deletion_legal_hold",
            "A legal hold blocks this deletion.",
        )
    })
}

// ------------------------------------------------------------- policies ----

/// The gate's `DataGovernancePolicy` baseline for an organization with no
/// persisted row yet. `metadata_only` is the default, and the version is `1` so
/// a client can read `1` and PATCH against `1` without a separate create call.
fn baseline_policy(org_id: &str, context: &RequestContext) -> DataGovernancePolicyRecord {
    DataGovernancePolicyRecord {
        policy_id: String::new(),
        org_id: org_id.to_owned(),
        project_id: None,
        logging_mode: LoggingMode::MetadataOnly.as_str().to_owned(),
        class_retention_overrides_json: "{}".to_owned(),
        legal_hold: 0,
        legal_hold_reason: None,
        legal_hold_placed_at: None,
        legal_hold_released_at: None,
        legal_hold_released_by: None,
        backup_lifecycle: crate::modules::data_governance::BackupLifecycle::PlatformExpiry
            .as_str()
            .to_owned(),
        provider_retention_disclosure: "external_policy".to_owned(),
        provider_retention_url: None,
        default_export_expiry_seconds: 86_400,
        version: 1,
        created_by_principal_id: String::new(),
        created_at: context.received_at.as_str().to_owned(),
        updated_at: context.received_at.as_str().to_owned(),
    }
}

fn apply_policy_patch(
    context: &RequestContext,
    current: &DataGovernancePolicyRecord,
    body: &PatchDataPolicyRequest,
) -> Result<DataGovernancePolicyRecord, ApiError> {
    let mut next = current.clone();
    if next.policy_id.is_empty() {
        next.policy_id = generated_id("dgp");
        next.created_by_principal_id = "usr_00000000000000000000000000000000".to_owned();
    }
    if let Some(mode) = body.logging_mode.as_deref() {
        let parsed = LoggingMode::parse(mode).ok_or_else(|| {
            domain_error(
                context,
                ApiErrorCode::ValidationFailed,
                "data_policy_invalid",
                "Choose metadata-only or redacted content logging.",
            )
        })?;
        if parsed == LoggingMode::FullContent {
            // `full_content` is an audited, time-bounded diagnostic setting. The
            // policy row has no window column, so persisting it would create a
            // standing diagnostic capability the domain forbids. Persisting it
            // needs a migration; until then the setting fails closed.
            return Err(domain_error(
                context,
                ApiErrorCode::ValidationFailed,
                "data_policy_invalid",
                "Full-content logging is not available on this policy surface.",
            ));
        }
        next.logging_mode = parsed.as_str().to_owned();
    }
    if let Some(overrides) = body.class_retention_overrides.as_ref() {
        if overrides.len() > RetentionPolicy::MAX_OVERRIDDEN_CLASSES {
            return Err(policy_invalid(
                context,
                "The retention override list is too large.",
            ));
        }
        let mut normalized = Map::new();
        for (class, seconds) in overrides {
            let parsed = seconds.as_u64().ok_or_else(|| {
                policy_invalid(
                    context,
                    "A retention override must be a whole number of seconds.",
                )
            })?;
            let duration = RetentionDuration::new(parsed)
                .map_err(|_| policy_invalid(context, "A retention override is out of range."))?;
            normalized.insert(class.clone(), json!(duration.seconds()));
        }
        next.class_retention_overrides_json =
            serde_json::to_string(&normalized).map_err(|_| service_unavailable(context))?;
    }
    if let Some(hold) = body.legal_hold {
        if hold {
            let reason = body
                .legal_hold_reason
                .as_deref()
                .ok_or_else(|| policy_invalid(context, "A legal hold requires a reason."))?;
            if reason.trim().is_empty() || reason.len() > 2_000 {
                return Err(policy_invalid(context, "The legal-hold reason is invalid."));
            }
            next.legal_hold = 1;
            next.legal_hold_reason = Some(reason.trim().to_owned());
            next.legal_hold_placed_at = Some(context.received_at.as_str().to_owned());
            next.legal_hold_released_at = None;
            next.legal_hold_released_by = None;
        } else {
            let released_by = body.legal_hold_released_by.clone().ok_or_else(|| {
                policy_invalid(
                    context,
                    "Releasing a legal hold requires an attributed principal.",
                )
            })?;
            if released_by.trim().is_empty() || released_by.len() > 64 {
                return Err(policy_invalid(
                    context,
                    "The releasing principal is invalid.",
                ));
            }
            next.legal_hold = 0;
            next.legal_hold_released_at = Some(context.received_at.as_str().to_owned());
            next.legal_hold_released_by = Some(released_by.trim().to_owned());
        }
    }
    if let Some(lifecycle) = body.backup_lifecycle.as_deref() {
        let parsed = crate::modules::data_governance::BackupLifecycle::parse(lifecycle)
            .ok_or_else(|| policy_invalid(context, "The backup lifecycle is invalid."))?;
        next.backup_lifecycle = parsed.as_str().to_owned();
    }
    if let Some(disclosure) = body.provider_retention_disclosure.as_deref() {
        if !matches!(disclosure, "external_policy" | "linked_policy") {
            return Err(policy_invalid(
                context,
                "The provider-retention disclosure is invalid.",
            ));
        }
        next.provider_retention_disclosure = disclosure.to_owned();
    }
    if body.provider_retention_url.is_some() {
        let url = body
            .provider_retention_url
            .as_deref()
            .ok_or_else(|| policy_invalid(context, "The provider-retention URL is invalid."))?;
        if url.is_empty() || url.len() > 2_048 || !url.starts_with("https://") {
            return Err(policy_invalid(
                context,
                "The provider-retention URL must be an https URL.",
            ));
        }
        next.provider_retention_url = Some(url.to_owned());
    }
    if let Some(seconds) = body.default_export_expiry_seconds {
        if !(300..=604_800).contains(&seconds) {
            return Err(policy_invalid(
                context,
                "The default export expiry is between 5 minutes and 7 days.",
            ));
        }
        next.default_export_expiry_seconds = seconds;
    }
    Ok(next)
}

/// Reject any override the frozen retention model refuses. A browser caller has
/// no audited-override input, so an out-of-window value is simply refused.
fn validate_policy_retention(
    context: &RequestContext,
    policy: &DataGovernancePolicyRecord,
) -> Result<(), ApiError> {
    let parsed: Map<String, Value> = serde_json::from_str(&policy.class_retention_overrides_json)
        .map_err(|_| service_unavailable(context))?;
    let mut retention = RetentionPolicy::new();
    for (class, seconds) in &parsed {
        let Some(seconds) = seconds.as_u64() else {
            return Err(policy_invalid(context, "A retention override is invalid."));
        };
        let duration = RetentionDuration::new(seconds)
            .map_err(|_| policy_invalid(context, "A retention override is out of range."))?;
        let data_class =
            crate::modules::data_governance::DataClass::new(class.as_str()).map_err(|_| {
                policy_invalid(context, "A retention override names an unknown data class.")
            })?;
        if crate::modules::data_governance::lookup(&data_class).is_none() {
            return Err(policy_invalid(
                context,
                "A retention override names an undeclared data class.",
            ));
        }
        retention
            .set_override(
                data_class,
                crate::modules::data_governance::RetentionOverride::shorten_to(
                    crate::modules::data_governance::RetentionWindow::Bounded(duration),
                ),
            )
            .map_err(|_| policy_invalid(context, "Too many retention overrides."))?;
    }
    let now = crate::consumers::unix_seconds(context.received_at.as_str()).unwrap_or_default();
    for record in crate::modules::data_governance::registry() {
        decide(&record, &retention, now, Some(now), None).map_err(|error| {
            domain_error(
                context,
                ApiErrorCode::ValidationFailed,
                error.code(),
                "A retention override exceeds the class legal maximum.",
            )
        })?;
    }
    Ok(())
}

fn changed_policy_keys(
    current: &DataGovernancePolicyRecord,
    next: &DataGovernancePolicyRecord,
) -> Vec<&'static str> {
    let mut changed = Vec::new();
    if current.logging_mode != next.logging_mode {
        changed.push("logging_mode");
    }
    if current.class_retention_overrides_json != next.class_retention_overrides_json {
        changed.push("class_retention_overrides");
    }
    if current.legal_hold != next.legal_hold {
        changed.push("legal_hold");
    }
    if current.backup_lifecycle != next.backup_lifecycle {
        changed.push("backup_lifecycle");
    }
    if current.provider_retention_disclosure != next.provider_retention_disclosure {
        changed.push("provider_retention_disclosure");
    }
    if current.provider_retention_url != next.provider_retention_url {
        changed.push("provider_retention_url");
    }
    if current.default_export_expiry_seconds != next.default_export_expiry_seconds {
        changed.push("default_export_expiry_seconds");
    }
    changed
}

// ----------------------------------------------------------- projections ---

fn policy_json(
    context: &RequestContext,
    policy: &DataGovernancePolicyRecord,
) -> Result<Value, ApiError> {
    let overrides: Value = serde_json::from_str(&policy.class_retention_overrides_json)
        .map_err(|_| service_unavailable(context))?;
    Ok(json!({
        "policy_id": if policy.policy_id.is_empty() {
            Value::Null
        } else {
            json!(policy.policy_id)
        },
        "persisted": !policy.policy_id.is_empty(),
        "org_id": policy.org_id,
        "project_id": policy.project_id,
        "logging_mode": policy.logging_mode,
        "class_retention_overrides": overrides,
        "legal_hold": policy.legal_hold_active(),
        "legal_hold_reason": policy.legal_hold_reason,
        "legal_hold_placed_at": policy.legal_hold_placed_at,
        "legal_hold_released_at": policy.legal_hold_released_at,
        "legal_hold_released_by": policy.legal_hold_released_by,
        "backup_lifecycle": policy.backup_lifecycle,
        "provider_retention_disclosure": policy.provider_retention_disclosure,
        "provider_retention_url": policy.provider_retention_url,
        "default_export_expiry_seconds": policy.default_export_expiry_seconds,
        "version": policy.version,
        "created_at": policy.created_at,
        "updated_at": policy.updated_at,
    }))
}

fn export_json(
    context: &RequestContext,
    job: &ExportJobRecord,
    artifact: Option<&ExportArtifactRecord>,
    download_path: &str,
) -> Result<Value, ApiError> {
    let categories: Value =
        serde_json::from_str(&job.categories_json).map_err(|_| service_unavailable(context))?;
    let state = ExportJobState::parse(&job.state).unwrap_or_default();
    let artifact_json = artifact.and_then(|record| {
        (record.deleted_at.is_none()).then(|| {
            json!({
                "content_type": record.content_type,
                "size_bytes": record.size_bytes,
                "expires_at": record.expires_at,
                // The Worker-mediated route, never an object URL and never the
                // opaque key.
                "download_path": download_path.replace("{export_id}", &job.export_id),
            })
        })
    });
    Ok(json!({
        "id": job.export_id,
        "org_id": job.org_id,
        "scope_type": job.scope_type,
        "scope_id": job.scope_id(),
        "categories": categories,
        "format": job.format,
        "snapshot_cutoff_at": job.snapshot_cutoff_at,
        "state": job.state,
        "state_version": job.state_version,
        "attempt": job.attempt,
        "next_attempt_at": job.next_attempt_at,
        "requested_by": job.requested_by_principal_id,
        "requested_at": job.requested_at,
        "ready_at": job.ready_at,
        "finished_at": job.finished_at,
        "failure_code": job.failure_code,
        "downloadable": state.can_mint_download_grant() && artifact_json.is_some(),
        "artifact": artifact_json,
        "version": job.version,
        "updated_at": job.updated_at,
        "disclosures": crate::modules::data_governance::deletion::DISCLOSURES,
    }))
}

fn export_page_items(
    context: &RequestContext,
    jobs: &[ExportJobRecord],
    artifacts: &[Option<ExportArtifactRecord>],
) -> Result<Vec<Value>, ApiError> {
    jobs.iter()
        .enumerate()
        .map(|(index, job)| {
            export_json(
                context,
                job,
                artifacts.get(index).and_then(|value| value.as_ref()),
                EXPORT_DOWNLOAD_PATH,
            )
        })
        .collect()
}

fn personal_export_page_items(
    context: &RequestContext,
    jobs: &[ExportJobRecord],
    artifacts: &[Option<ExportArtifactRecord>],
) -> Result<Vec<Value>, ApiError> {
    jobs.iter()
        .enumerate()
        .map(|(index, job)| {
            export_json(
                context,
                job,
                artifacts.get(index).and_then(|value| value.as_ref()),
                ME_EXPORT_DOWNLOAD_PATH,
            )
        })
        .collect()
}

fn deletion_json(_context: &RequestContext, job: &DeletionJobRecord) -> Result<Value, ApiError> {
    let state = DeletionJobState::parse(&job.state).unwrap_or_default();
    Ok(json!({
        "id": job.deletion_id,
        "org_id": job.org_id,
        "target_type": job.target_type,
        "target_id": job.target_id(),
        "state": job.state,
        "state_version": job.state_version,
        "attempt": job.attempt,
        "next_attempt_at": job.next_attempt_at,
        "grace_expires_at": job.grace_expires_at,
        "cutoff_at": job.cutoff_at,
        "fenced": job.is_fenced(),
        "legal_hold": job.legal_hold_active(),
        "failure_code": job.failure_code,
        "certificate_id": job.certificate_id,
        "resumable": state.is_resumable(),
        "requested_by": job.requested_by_principal_id,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "completed_at": job.completed_at,
        "version": job.version,
        "disclosures": crate::modules::data_governance::deletion::DISCLOSURES,
    }))
}

fn deletion_detail_json(
    context: &RequestContext,
    job: &DeletionJobRecord,
    steps: &[DeletionTaskRecord],
    certificate: Option<&DeletionCertificateRecord>,
) -> Result<Value, ApiError> {
    let base = deletion_json(context, job)?;
    let mut value = base.as_object().cloned().unwrap_or_default();
    value.insert(
        "steps".to_owned(),
        Value::Array(
            steps
                .iter()
                .map(|task| {
                    json!({
                        "id": task.task_id,
                        "data_class": task.data_class,
                        "reference_kind": task.reference_kind,
                        "object_reference": task.object_reference,
                        "state": task.state,
                        "attempt": task.attempt,
                        "failure_code": task.failure_code,
                        "skip_reason": task.skip_reason,
                        "completed_at": task.completed_at,
                    })
                })
                .collect(),
        ),
    );
    if let Some(certificate) = certificate {
        let results: Value =
            serde_json::from_str(&certificate.class_results_json).unwrap_or(Value::Null);
        let retained: Value =
            serde_json::from_str(&certificate.retained_legal_classes_json).unwrap_or(Value::Null);
        value.insert(
            "certificate".to_owned(),
            json!({
                "id": certificate.certificate_id,
                "scope_type": certificate.scope_type,
                "scope_id": certificate.scope_id,
                "class_results": results,
                "retained_legal_classes": retained,
                "completed_at": certificate.completed_at,
                "expires_at": certificate.expires_at,
            }),
        );
    }
    Ok(Value::Object(value))
}

// -------------------------------------------------------------- helpers ----

/// Rebuild the download grant's scope binding from the job row. A stored scope
/// the domain rejects is a store problem, not a client answer.
fn scope_of(context: &RequestContext, job: &ExportJobRecord) -> Result<ExportScope, ApiError> {
    ExportScope::new(&job.scope_type, job.scope_id().unwrap_or_default())
        .map_err(|_| service_unavailable(context))
}

/// The canonical, sorted category manifest. Delegates to the repository so the
/// route and the worker serialize a manifest identically.
fn canonical_categories_json(categories: &[ExportCategory]) -> Result<String, serde_json::Error> {
    crate::repositories::data_governance::canonical_categories_json(categories)
}

fn parse_categories(
    context: &RequestContext,
    values: &[String],
) -> Result<Vec<ExportCategory>, ApiError> {
    if values.is_empty() {
        return Err(domain_error(
            context,
            ApiErrorCode::ValidationFailed,
            "export_category_invalid",
            "Select at least one export category.",
        ));
    }
    if values.len() > crate::modules::data_governance::export::MAX_EXPORT_CATEGORIES {
        return Err(domain_error(
            context,
            ApiErrorCode::ValidationFailed,
            "export_category_invalid",
            "The export category list is too large.",
        ));
    }
    values
        .iter()
        .map(|value| {
            ExportCategory::parse(value).ok_or_else(|| {
                domain_error(
                    context,
                    ApiErrorCode::ValidationFailed,
                    "export_category_invalid",
                    "The export category list contains an unknown category.",
                )
            })
        })
        .collect()
}

fn parse_format(context: &RequestContext, value: Option<&str>) -> Result<ExportFormat, ApiError> {
    match value {
        None => Ok(ExportFormat::Json),
        Some(value) => ExportFormat::parse(value).ok_or_else(|| {
            domain_error(
                context,
                ApiErrorCode::ValidationFailed,
                "export_category_invalid",
                "The export format is invalid.",
            )
        }),
    }
}

fn org_role(value: &str) -> crate::modules::data_governance::OrgRole {
    match value {
        "owner" => crate::modules::data_governance::OrgRole::Owner,
        "admin" => crate::modules::data_governance::OrgRole::Admin,
        "viewer" => crate::modules::data_governance::OrgRole::Viewer,
        _ => crate::modules::data_governance::OrgRole::Member,
    }
}

fn validation_error(context: &RequestContext, reason: &str, message: &str) -> ApiError {
    domain_error(context, ApiErrorCode::ValidationFailed, reason, message)
}

fn policy_invalid(context: &RequestContext, message: &str) -> ApiError {
    validation_error(context, "data_policy_invalid", message)
}

fn artifact_unavailable(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::Conflict,
        "export_artifact_unavailable",
        "Export artifact storage is not available.",
    )
}

/// Stable, user-facing copy per frozen reason code. No provider string, no SQL,
/// no object key.
fn export_message(code: &str) -> &'static str {
    match code {
        "export_category_invalid" => {
            "The requested export categories are not available for this scope."
        }
        "export_not_ready" => "The export is not ready yet.",
        "export_expired" => "The export artifact has expired.",
        "export_artifact_unavailable" => "The export artifact is not available.",
        "deletion_legal_hold" => "A legal hold blocks this export.",
        "deletion_reauth_required" => "Complete a recent security check before continuing.",
        _ => "The export request is invalid.",
    }
}

fn deletion_message(code: &str) -> &'static str {
    match code {
        "deletion_not_resumable" => "This deletion job is not resumable.",
        "deletion_legal_hold" => "A legal hold blocks this deletion job.",
        "permission_denied" => "You do not have permission to resume this deletion job.",
        "deletion_scope_conflict" => "A deletion job already exists for this scope.",
        "deletion_requires_org_exit" => {
            "Leave or transfer every organization you administer first."
        }
        _ => "The deletion job cannot make that transition.",
    }
}

#[allow(clippy::too_many_arguments)]
fn audit_statement(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    principal: Option<&Principal>,
    organization_id: Option<&str>,
    event_id: &str,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    outcome: &str,
    metadata: &Value,
) -> Result<D1PreparedStatement, ApiError> {
    match organization_id {
        Some(organization_id) => AuditRepository::new(database)
            .insert_statement(&AuditEventInput {
                event_id,
                organization_id,
                actor_type: if principal.is_some() {
                    "user"
                } else {
                    "system"
                },
                actor_id: principal.map(|value| value.user_id.as_str()),
                effective_user_id: principal.map(|value| value.user_id.as_str()),
                session_id: principal.map(|value| value.session_id.as_str()),
                device_id: None,
                run_id: None,
                agent_session_id: None,
                tool_call_id: None,
                action,
                resource_type,
                resource_id: Some(resource_id),
                outcome,
                reason: None,
                metadata: &bounded_metadata(metadata),
                request_id: context.request_id.as_str(),
                correlation_id: context.correlation_id.as_str(),
                created_at: &context.received_at,
            })
            .map_err(|_| service_unavailable(context)),
        // A personal action has no organization, so the F16 row is tenant-less.
        // The metadata is still bounded by the shared allow-list.
        None => crate::routes::support::security_event_statement(
            database,
            context,
            principal,
            None,
            event_id,
            action,
            resource_type,
            Some(resource_id),
            outcome,
            &bounded_metadata(metadata),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> RequestContext {
        RequestContext::new(
            "req_0123456789abcdef0123456789abcdef".parse().unwrap(),
            crate::core::CorrelationId::new("trace-p06").unwrap(),
            "2026-09-25T12:00:00.000Z".parse().unwrap(),
        )
    }

    const ORG_ID: &str = "org_0123456789abcdef0123456789abcdef";
    const EXPORT_ID: &str = "exp_0123456789abcdef0123456789abcdef";
    const DELETION_ID: &str = "del_0123456789abcdef0123456789abcdef";

    #[test]
    fn baseline_policy_is_the_frozen_wire_shape() {
        let policy = baseline_policy(ORG_ID, &context());
        assert_eq!(policy.logging_mode, "metadata_only");
        assert_eq!(policy.backup_lifecycle, "platform_35_day_expiry");
        assert_eq!(policy.provider_retention_disclosure, "external_policy");
        assert_eq!(policy.default_export_expiry_seconds, 86_400);
        assert!(!policy.legal_hold_active());
        let json = policy_json(&context(), &policy).unwrap();
        assert_eq!(json["logging_mode"], "metadata_only");
        assert_eq!(json["class_retention_overrides"], json!({}));
        assert_eq!(json["legal_hold"], json!(false));
        assert_eq!(json["policy_id"], Value::Null);
        assert_eq!(json["persisted"], json!(false));
        assert_eq!(json["version"], 1);
    }

    #[test]
    fn policy_patch_rejects_full_content_logging() {
        let current = baseline_policy(ORG_ID, &context());
        let body = PatchDataPolicyRequest {
            version: 1,
            logging_mode: Some("full_content".to_owned()),
            class_retention_overrides: None,
            legal_hold: None,
            legal_hold_reason: None,
            legal_hold_released_by: None,
            backup_lifecycle: None,
            provider_retention_disclosure: None,
            provider_retention_url: None,
            default_export_expiry_seconds: None,
        };
        let error = apply_policy_patch(&context(), &current, &body).unwrap_err();
        assert_eq!(
            error.error.details.get("reason"),
            Some(&json!("data_policy_invalid"))
        );
    }

    #[test]
    fn policy_patch_accepts_the_two_persistable_logging_modes() {
        let current = baseline_policy(ORG_ID, &context());
        for mode in ["metadata_only", "redacted_content"] {
            let body = PatchDataPolicyRequest {
                version: 1,
                logging_mode: Some(mode.to_owned()),
                class_retention_overrides: None,
                legal_hold: None,
                legal_hold_reason: None,
                legal_hold_released_by: None,
                backup_lifecycle: None,
                provider_retention_disclosure: None,
                provider_retention_url: None,
                default_export_expiry_seconds: None,
            };
            let next = apply_policy_patch(&context(), &current, &body).unwrap();
            assert_eq!(next.logging_mode, mode);
        }
    }

    #[test]
    fn legal_hold_placement_and_release_are_both_attributed() {
        let current = baseline_policy(ORG_ID, &context());
        let place = PatchDataPolicyRequest {
            version: 1,
            logging_mode: None,
            class_retention_overrides: None,
            legal_hold: Some(true),
            legal_hold_reason: Some("litigation hold".to_owned()),
            legal_hold_released_by: None,
            backup_lifecycle: None,
            provider_retention_disclosure: None,
            provider_retention_url: None,
            default_export_expiry_seconds: None,
        };
        let held = apply_policy_patch(&context(), &current, &place).unwrap();
        assert!(held.legal_hold_active());
        assert_eq!(held.legal_hold_reason.as_deref(), Some("litigation hold"));

        let missing_reason = PatchDataPolicyRequest {
            legal_hold_reason: None,
            ..place.clone()
        };
        assert!(apply_policy_patch(&context(), &current, &missing_reason).is_err());

        let release = PatchDataPolicyRequest {
            version: 1,
            logging_mode: None,
            class_retention_overrides: None,
            legal_hold: Some(false),
            legal_hold_reason: None,
            legal_hold_released_by: Some("usr_0123456789abcdef0123456789abcdef".to_owned()),
            backup_lifecycle: None,
            provider_retention_disclosure: None,
            provider_retention_url: None,
            default_export_expiry_seconds: None,
        };
        let released = apply_policy_patch(&context(), &held, &release).unwrap();
        assert!(!released.legal_hold_active());
        assert!(released.legal_hold_released_by.is_some());
        assert!(released.legal_hold_released_at.is_some());

        let unattributed = PatchDataPolicyRequest {
            legal_hold_released_by: None,
            ..release
        };
        assert!(apply_policy_patch(&context(), &held, &unattributed).is_err());
    }

    #[test]
    fn retention_overrides_are_refused_past_the_legal_maximum() {
        let mut policy = baseline_policy(ORG_ID, &context());
        // A legal shortening is accepted.
        policy.class_retention_overrides_json = json!({"notification": 604_800}).to_string();
        assert!(validate_policy_retention(&context(), &policy).is_ok());
        // An unknown class fails closed.
        policy.class_retention_overrides_json = json!({"not_a_class": 60}).to_string();
        assert!(validate_policy_retention(&context(), &policy).is_err());
        // Extending a bounded class past its legal maximum is refused.
        policy.class_retention_overrides_json = json!({"notification": 99_999_999}).to_string();
        let error = validate_policy_retention(&context(), &policy).unwrap_err();
        assert_eq!(
            error.error.details.get("reason"),
            Some(&json!("data_policy_retention_over_legal_maximum"))
        );
    }

    #[test]
    fn provider_retention_url_must_be_https() {
        let current = baseline_policy(ORG_ID, &context());
        let insecure = PatchDataPolicyRequest {
            version: 1,
            logging_mode: None,
            class_retention_overrides: None,
            legal_hold: None,
            legal_hold_reason: None,
            legal_hold_released_by: None,
            backup_lifecycle: None,
            provider_retention_disclosure: None,
            provider_retention_url: Some("http://provider.example/policy".to_owned()),
            default_export_expiry_seconds: None,
        };
        assert!(apply_policy_patch(&context(), &current, &insecure).is_err());
    }

    #[test]
    fn changed_keys_are_reported_for_the_frozen_event_payload() {
        let current = baseline_policy(ORG_ID, &context());
        let mut next = current.clone();
        next.logging_mode = "redacted_content".to_owned();
        next.legal_hold = 1;
        assert_eq!(
            changed_policy_keys(&current, &next),
            vec!["logging_mode", "legal_hold"]
        );
        assert!(changed_policy_keys(&current, &current).is_empty());
    }

    #[test]
    fn categories_are_bounded_and_known() {
        let context = context();
        assert!(parse_categories(&context, &[]).is_err());
        assert!(parse_categories(&context, &["secrets".to_owned()]).is_err());
        assert!(
            parse_categories(
                &context,
                &["identity".to_owned(), "notifications".to_owned()]
            )
            .is_ok()
        );
        let too_many: Vec<String> = (0..9).map(|_| "identity".to_owned()).collect();
        assert!(parse_categories(&context, &too_many).is_err());
    }

    #[test]
    fn formats_are_bounded_and_known() {
        let context = context();
        assert_eq!(parse_format(&context, None).unwrap(), ExportFormat::Json);
        assert_eq!(
            parse_format(&context, Some("jsonl")).unwrap(),
            ExportFormat::Jsonl
        );
        assert!(parse_format(&context, Some("tar")).is_err());
    }

    fn export_job(state: &str) -> ExportJobRecord {
        ExportJobRecord {
            export_id: EXPORT_ID.to_owned(),
            org_id: Some(ORG_ID.to_owned()),
            scope_type: "organization".to_owned(),
            scope_user_id: None,
            scope_org_id: Some(ORG_ID.to_owned()),
            categories_json: "[\"identity\"]".to_owned(),
            format: "json".to_owned(),
            snapshot_cutoff_at: "2026-09-25T12:00:00.000Z".to_owned(),
            state: state.to_owned(),
            state_version: 1,
            attempt: 0,
            next_attempt_at: None,
            requested_by_principal_id: "usr_0123456789abcdef0123456789abcdef".to_owned(),
            requested_at: "2026-09-25T12:00:00.000Z".to_owned(),
            ready_at: None,
            finished_at: None,
            failure_code: None,
            version: 1,
            updated_at: "2026-09-25T12:00:00.000Z".to_owned(),
        }
    }

    #[test]
    fn export_projection_never_exposes_a_key_or_a_url() {
        let artifact = ExportArtifactRecord {
            artifact_id: "art_0123456789abcdef0123456789abcdef".to_owned(),
            export_id: EXPORT_ID.to_owned(),
            org_id: Some(ORG_ID.to_owned()),
            object_key: "exports/org_1/exp_1/0123456789abcdef0123456789abcdef".to_owned(),
            bucket_name: "lumi-export-artifacts".to_owned(),
            content_type: "application/json".to_owned(),
            size_bytes: Some(42),
            checksum_sha256: Some("a".repeat(64)),
            created_at: "2026-09-25T12:00:00.000Z".to_owned(),
            expires_at: "2026-09-26T12:00:00.000Z".to_owned(),
            deleted_at: None,
        };
        let value = export_json(
            &context(),
            &export_job("ready"),
            Some(&artifact),
            EXPORT_DOWNLOAD_PATH,
        )
        .unwrap();
        let rendered = value.to_string();
        assert!(value.get("object_key").is_none());
        assert!(!rendered.contains("exports/org_1/exp_1/"));
        assert!(!rendered.contains("lumi-export-artifacts"));
        assert!(!rendered.contains("http"));
        assert_eq!(value["downloadable"], json!(true));
        // The Worker-mediated route with the job id resolved, never an object URL.
        assert_eq!(
            value["artifact"]["download_path"],
            json!(format!(
                "/api/v1/orgs/{{org_id}}/exports/{EXPORT_ID}/download"
            ))
        );
        assert_eq!(value["state"], "ready");
    }

    #[test]
    fn export_projection_reports_downloadable_only_when_ready() {
        for state in [
            "requested",
            "queued",
            "collecting",
            "packaging",
            "verifying",
            "retry_wait",
        ] {
            let value =
                export_json(&context(), &export_job(state), None, EXPORT_DOWNLOAD_PATH).unwrap();
            assert_eq!(value["downloadable"], json!(false), "{state}");
        }
        let value =
            export_json(&context(), &export_job("ready"), None, EXPORT_DOWNLOAD_PATH).unwrap();
        assert_eq!(value["downloadable"], json!(false), "no artifact row");
    }

    #[test]
    fn deleted_artifact_is_not_advertised() {
        let artifact = ExportArtifactRecord {
            artifact_id: "art_0123456789abcdef0123456789abcdef".to_owned(),
            export_id: EXPORT_ID.to_owned(),
            org_id: Some(ORG_ID.to_owned()),
            object_key: "exports/org_1/exp_1/0123456789abcdef0123456789abcdef".to_owned(),
            bucket_name: "lumi-export-artifacts".to_owned(),
            content_type: "application/json".to_owned(),
            size_bytes: Some(42),
            checksum_sha256: None,
            created_at: "2026-09-25T12:00:00.000Z".to_owned(),
            expires_at: "2026-09-26T12:00:00.000Z".to_owned(),
            deleted_at: Some("2026-09-25T13:00:00.000Z".to_owned()),
        };
        let value = export_json(
            &context(),
            &export_job("ready"),
            Some(&artifact),
            EXPORT_DOWNLOAD_PATH,
        )
        .unwrap();
        assert_eq!(value["downloadable"], json!(false));
        assert_eq!(value["artifact"], Value::Null);
    }

    fn deletion_job(state: &str) -> DeletionJobRecord {
        DeletionJobRecord {
            deletion_id: DELETION_ID.to_owned(),
            org_id: Some(ORG_ID.to_owned()),
            target_type: "organization".to_owned(),
            target_user_id: None,
            target_org_id: Some(ORG_ID.to_owned()),
            lifecycle_request_id: Some("req_0123456789abcdef0123456789abcdef".to_owned()),
            state: state.to_owned(),
            state_version: 1,
            attempt: 1,
            next_attempt_at: None,
            grace_expires_at: None,
            cutoff_at: Some("2026-09-25T12:00:00.000Z".to_owned()),
            fenced: 1,
            legal_hold: 0,
            failure_code: Some("deletion_executor_unavailable".to_owned()),
            certificate_id: None,
            requested_by_principal_id: "usr_0123456789abcdef0123456789abcdef".to_owned(),
            created_at: "2026-09-25T12:00:00.000Z".to_owned(),
            updated_at: "2026-09-25T12:00:00.000Z".to_owned(),
            completed_at: None,
            version: 1,
        }
    }

    #[test]
    fn deletion_projection_reports_resumability_and_never_over_claims() {
        let parked = deletion_json(&context(), &deletion_job("needs_attention")).unwrap();
        assert_eq!(parked["resumable"], json!(true));
        assert_eq!(parked["fenced"], json!(true));
        assert_eq!(parked["state"], "needs_attention");
        let running = deletion_json(&context(), &deletion_job("deleting")).unwrap();
        assert_eq!(running["resumable"], json!(false));
        // The disclosures are always present: a deletion result never claims
        // local ZCode or upstream provider data.
        assert_eq!(
            parked["disclosures"],
            json!(crate::modules::data_governance::deletion::DISCLOSURES)
        );
    }

    #[test]
    fn deletion_detail_includes_steps_and_the_certificate() {
        let steps = vec![DeletionTaskRecord {
            task_id: "dts_0123456789abcdef0123456789abcdef".to_owned(),
            deletion_id: DELETION_ID.to_owned(),
            org_id: Some(ORG_ID.to_owned()),
            data_class: "upstream_provider_data".to_owned(),
            reference_kind: "upstream_provider_data".to_owned(),
            object_reference: "upstream_provider:org_1".to_owned(),
            state: "skipped".to_owned(),
            attempt: 0,
            failure_code: None,
            skip_reason: Some("deletion_not_lumi_owned".to_owned()),
            started_at: None,
            completed_at: Some("2026-09-25T12:00:00.000Z".to_owned()),
            created_at: "2026-09-25T12:00:00.000Z".to_owned(),
            updated_at: "2026-09-25T12:00:00.000Z".to_owned(),
        }];
        let certificate = DeletionCertificateRecord {
            certificate_id: "delc_0123456789abcdef0123456789abcdef".to_owned(),
            deletion_id: DELETION_ID.to_owned(),
            org_id: Some(ORG_ID.to_owned()),
            scope_type: "organization".to_owned(),
            scope_id: ORG_ID.to_owned(),
            class_results_json: "{\"reference_coverage\":{\"pending\":[\"cache\"]}}".to_owned(),
            retained_legal_classes_json: "[\"audit_security_event\"]".to_owned(),
            completed_at: "2026-09-25T12:00:00.000Z".to_owned(),
            expires_at: "2027-09-25T12:00:00.000Z".to_owned(),
            created_at: "2026-09-25T12:00:00.000Z".to_owned(),
        };
        let value = deletion_detail_json(
            &context(),
            &deletion_job("completed"),
            &steps,
            Some(&certificate),
        )
        .unwrap();
        assert_eq!(value["steps"][0]["skip_reason"], "deletion_not_lumi_owned");
        assert_eq!(
            value["certificate"]["retained_legal_classes"],
            json!(["audit_security_event"])
        );
        assert_eq!(
            value["certificate"]["class_results"]["reference_coverage"]["pending"],
            json!(["cache"])
        );
    }

    #[test]
    fn stable_messages_cover_every_frozen_code_the_routes_can_return() {
        for code in [
            "export_category_invalid",
            "export_not_ready",
            "export_expired",
            "export_artifact_unavailable",
            "deletion_legal_hold",
            "deletion_reauth_required",
        ] {
            assert!(!export_message(code).is_empty(), "{code}");
        }
        for code in [
            "deletion_not_resumable",
            "deletion_legal_hold",
            "permission_denied",
            "deletion_scope_conflict",
            "deletion_requires_org_exit",
        ] {
            assert!(!deletion_message(code).is_empty(), "{code}");
        }
    }

    #[test]
    fn grant_and_grace_windows_are_bounded() {
        assert!(
            u64::from(DOWNLOAD_GRANT_TTL_SECONDS)
                <= crate::modules::data_governance::retention::ACCESS_GRANT_CEILING.seconds()
        );
        assert_eq!(PERSONAL_DELETION_GRACE_SECONDS, 604_800);
        assert!(u64::from(DOWNLOAD_GRANT_TTL_SECONDS) < 3_600);
    }

    #[test]
    fn reauth_purpose_is_an_existing_p02_purpose() {
        // `POST /api/v1/account/reauth` accepts this purpose today.
        assert!(matches!(
            REAUTH_PURPOSE,
            "ownership_transfer"
                | "identity_link"
                | "org_lifecycle"
                | "passkey_management"
                | "password_change"
                | "account_recovery"
        ));
    }

    #[test]
    fn organization_deletion_request_is_not_exposed_by_this_module() {
        // P06-CR-003: the P02 route is the sole request. This module must not
        // declare a `/deletions` POST.
        assert!(!DELETIONS_PATH.ends_with("/deletions/{deletion_id}"));
        assert!(DELETION_RESUME_PATH.ends_with("/resume"));
        assert!(!DELETIONS_PATH.contains("{deletion_id}"));
    }

    #[test]
    fn roles_map_onto_the_deletion_exit_rule() {
        assert!(org_role("owner").blocks_account_deletion());
        assert!(org_role("admin").blocks_account_deletion());
        assert!(!org_role("member").blocks_account_deletion());
        assert!(!org_role("viewer").blocks_account_deletion());
    }

    #[test]
    fn account_deletion_exit_requires_leaving_or_transferring() {
        let blocked = vec![deletion::OrgMembershipRef {
            org_id: ORG_ID.to_owned(),
            role: org_role("owner"),
            exit_possible: false,
        }];
        assert_eq!(
            evaluate_account_deletion_exit(&blocked).unwrap_err().code(),
            "deletion_requires_org_exit"
        );
        let transferring = vec![deletion::OrgMembershipRef {
            org_id: ORG_ID.to_owned(),
            role: org_role("owner"),
            exit_possible: true,
        }];
        assert!(evaluate_account_deletion_exit(&transferring).is_ok());
        let member = vec![deletion::OrgMembershipRef {
            org_id: ORG_ID.to_owned(),
            role: org_role("member"),
            exit_possible: false,
        }];
        assert!(evaluate_account_deletion_exit(&member).is_ok());
    }

    #[test]
    fn only_ready_may_mint_a_download_grant() {
        for state in ExportJobState::ALL {
            assert_eq!(
                state.can_mint_download_grant(),
                state == ExportJobState::Ready,
                "{state}"
            );
        }
    }
}
