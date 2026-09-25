//! P05 usage, cost-reconciliation, and dashboard-read HTTP surface.
//!
//! Reads are ordinary org-scoped `usage.read` queries with opaque keyset
//! cursors.  Reconciliation is **not** a browser mutation: P05-CR-002 §6 makes
//! authoritative cost a server-owned value, so the ingest/reconcile operation
//! requires a machine identity (an active device token) whose device owns the
//! correlated run or usage event.  A browser session is rejected outright.
//!
//! Raw usage and cost rows are append-only.  Nothing here updates
//! `usage_events`, `run_usage_events`, `cost_records`, or `run_cost_records`;
//! a later or corrected number is a *new* cost record and a conflict is
//! surfaced, never silently overwritten.

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
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::{add_idempotency_ttl, new_event_id, sha256_hex},
    app::AppState,
    core::{
        ActorContext, ActorId, ActorType, ApiError, ApiErrorCode, EventEnvelope, EventType,
        IdempotencyKeyDigest, IdempotencyRecord, IdempotencyScope, IdempotencyState,
        OrganizationId, RequestContext, RequestFingerprint, StoredSuccess,
    },
    modules::{
        authorization::Permission,
        usage::{BoundedPayload, CostRecord, CostRecordDraft, ReconciliationIdentity, UsageSource},
    },
    repositories::{
        CostRecordRow, DeviceRecord, IdempotencyClaimToken, IdempotencyLookup,
        IdempotencyRepository, NewCostRecordInput, OutboxRepository, RunCostRecordRow,
        RunRepository, UsageEventRecord, UsageQuery, UsageRepository,
    },
    routes::{
        agents::{
            PageResponse, can_manage_projects, decode_page_cursor, encode_page_cursor,
            ensure_project_access, generated_id, page_limit, replay_response, validate_prefixed_id,
            validation_error,
        },
        authorization::{authorize_device, authorize_org},
        errors,
        support::{
            database, database_error, domain_error, idempotency_key,
            security_event_statement_with_context,
        },
    },
};

/// Idempotency scope path for the machine-issued reconciliation command.  The
/// stored path is a stable template so the same logical operation always shares
/// one key scope.
pub const USAGE_RECONCILE_PATH: &str = "/api/v1/orgs/{org_id}/usage/reconcile";
const MAX_SAFE_COST_MINOR: i64 = 9_000_000_000_000_000;

/// Reconciliation is a machine operation.  Accepting a browser cookie here
/// would let a client assert authoritative cost, which P05-CR-002 forbids.
pub(crate) async fn require_accounting_service(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    context: &RequestContext,
    org_id: &str,
) -> Result<DeviceRecord, ApiError> {
    let access = authorize_device(state, headers, context).await?;
    if access.device.org_id != org_id {
        // An inaccessible tenant must not be distinguishable from a missing
        // one through an accounting endpoint.
        return Err(not_found(context, "resource_not_found"));
    }
    Ok(access.device)
}

/// A prepared idempotency claim owned by one identity.  The scope actor is a
/// user ID for an authorized browser mutation and a device ID for a machine
/// accounting mutation, so a browser key can never replay or block a device
/// accounting write and vice versa.
pub(crate) struct ScopedMutationClaim {
    record: IdempotencyRecord,
    token: IdempotencyClaimToken,
    statement: D1PreparedStatement,
}

pub(crate) enum PreparedScopedMutation {
    Replay(StoredSuccess),
    Claim(ScopedMutationClaim),
}

/// Look up/claim an idempotency key for a tenant-scoped mutation.  The
/// fingerprint is derived from the normalized command, never from a raw body.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn prepare_scoped_mutation(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    scope_actor: &str,
    org_id: &str,
    key: &str,
    method: &str,
    path: &str,
    body: &Value,
) -> Result<PreparedScopedMutation, ApiError> {
    let scope = IdempotencyScope::new(
        ActorId::new(scope_actor).map_err(|_| service_unavailable(context))?,
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
    let record = IdempotencyRecord {
        scope,
        key_digest,
        request_fingerprint,
        expires_at: add_idempotency_ttl(&context.received_at)
            .map_err(|_| service_unavailable(context))?,
        state: IdempotencyState::Pending,
    };
    let token = IdempotencyClaimToken::new(context.request_id.as_str())
        .map_err(|_| service_unavailable(context))?;
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
        IdempotencyLookup::Replay(success) => {
            return Ok(PreparedScopedMutation::Replay(success));
        }
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
    let statement = repository
        .claim_statement(&record, &token, &context.received_at)
        .map_err(|_| service_unavailable(context))?;
    Ok(PreparedScopedMutation::Claim(ScopedMutationClaim {
        record,
        token,
        statement,
    }))
}

/// Result of one tenant-scoped mutation batch.
pub(crate) enum ScopedMutationCommit {
    /// The batch committed; `StoredSuccess` is now replayable.
    Committed,
    /// An identical completed command already exists.
    Replayed(StoredSuccess),
    /// A guard statement in the batch failed, so D1 rolled the whole batch
    /// back.  The caller re-reads authoritative state to decide the outcome.
    Guarded,
}

/// Commit the claim, business writes, audit/outbox rows, and the replayable
/// response as one D1 batch.  A failed batch is reclassified: a guard
/// violation is reported as [`ScopedMutationCommit::Guarded`], and anything
/// else is reclassified by a fresh lookup so a concurrent identical command
/// replays instead of writing twice.
pub(crate) async fn commit_scoped_mutation(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    claim: ScopedMutationClaim,
    success: StoredSuccess,
    business_writes: Vec<D1PreparedStatement>,
    outbox: D1PreparedStatement,
) -> Result<ScopedMutationCommit, ApiError> {
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
    match result {
        Ok(_) => Ok(ScopedMutationCommit::Committed),
        Err(error) if is_guard_violation(&error) => Ok(ScopedMutationCommit::Guarded),
        Err(_) => {
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
            match lookup {
                IdempotencyLookup::Replay(success) => Ok(ScopedMutationCommit::Replayed(success)),
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
                IdempotencyLookup::Missing => Err(service_unavailable(context)),
            }
        }
    }
}

/// A guard statement aborts a D1 batch by violating a table constraint, so the
/// batch error text is the only signal that the write was refused on purpose.
fn is_guard_violation(error: &worker::Error) -> bool {
    let detail = format!("{error:?}");
    detail.contains("NOT NULL") || detail.contains("constraint")
}

fn not_found(context: &RequestContext, reason: &str) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::NotFound,
        "The requested resource was not found.",
    )
    .with_detail("reason", json!(reason))
}

fn service_unavailable(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::ServiceUnavailable,
        "The usage store is unavailable.",
    )
}

fn budget_state_unavailable(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::ServiceUnavailable,
        "The authoritative budget state is unavailable.",
    )
    .with_detail("reason", json!("budget_state_unavailable"))
}

fn reconciliation_conflict(context: &RequestContext, reason: &str) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::Conflict,
        "usage_reconciliation_conflict",
        "The usage reconciliation conflicts with the recorded cost.",
    )
    .with_detail("conflict", json!(reason))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageListQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    pub project_id: Option<String>,
    pub run_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageRangeQuery {
    pub project_id: Option<String>,
    pub run_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageRollupQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    pub project_id: Option<String>,
    pub principal_user_id: Option<String>,
    pub model_alias: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageDenialQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

/// Machine-issued reconciliation command.  `actual_cost_minor` and
/// `provider_usage` are only accepted from a service identity; a browser
/// caller never reaches this handler.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileUsageRequest {
    pub request_id: Option<String>,
    pub run_id: Option<String>,
    pub external_id: Option<String>,
    pub actual_cost_minor: Option<i64>,
    pub provider_usage: Option<Value>,
}

fn usage_event_json(record: &UsageEventRecord) -> Value {
    json!({
        "id": record.event_id,
        "usage_event_id": record.event_id,
        "source": record.source,
        "request_id": record.request_id,
        "run_id": record.run_id,
        "org_id": record.org_id,
        "project_id": record.project_id,
        "principal_user_id": record.principal_user_id,
        "session_id": record.session_id,
        "device_id": record.device_id,
        "external_id": record.external_id,
        "reconciliation_status": record.reconciliation_status,
        "model_alias": record.model_alias,
        "input_tokens": record.input_tokens,
        "output_tokens": record.output_tokens,
        "cached_tokens": record.cached_tokens,
        "estimated_cost_minor": record.estimated_cost_minor,
        "actual_cost_minor": record.actual_cost_minor,
        "currency": record.currency,
        "pricing_version": record.pricing_version,
        "budget_decision": record.budget_decision,
        "route_version_id": record.route_version_id,
        "provider_id": record.provider_id,
        "model_id": record.model_id,
        "ttft_ms": record.ttft_ms,
        "total_latency_ms": record.total_latency_ms,
        "created_at": record.created_at,
    })
}

fn cost_record_json(record: &CostRecordRow) -> Value {
    json!({
        "id": record.cost_record_id,
        "usage_event_id": record.usage_event_id,
        "org_id": record.org_id,
        "project_id": record.project_id,
        "run_id": record.run_id,
        "pricing_source": record.pricing_source,
        "pricing_version": record.pricing_version,
        "pricing_effective_at": record.pricing_effective_at,
        "calculation_kind": record.calculation_kind,
        "input_tokens": record.input_tokens,
        "output_tokens": record.output_tokens,
        "cached_tokens": record.cached_tokens,
        "cost_minor": record.cost_minor,
        "currency": record.currency,
        "created_at": record.created_at,
    })
}

fn run_cost_record_json(record: &RunCostRecordRow) -> Value {
    json!({
        "id": record.run_cost_record_id,
        "usage_event_id": record.run_usage_event_id,
        "org_id": record.org_id,
        "project_id": record.project_id,
        "run_id": record.run_id,
        "pricing_source": record.pricing_source,
        "pricing_version": record.pricing_version,
        "pricing_effective_at": record.pricing_effective_at,
        "calculation_kind": record.calculation_kind,
        "input_tokens": record.input_tokens,
        "output_tokens": record.output_tokens,
        "cached_tokens": record.cached_tokens,
        "cost_minor": record.cost_minor,
        "currency": record.currency,
        "created_at": record.created_at,
    })
}

fn denial_json(record: &crate::repositories::UsageDenialRecord) -> Value {
    let metadata = serde_json::from_str::<Value>(&record.metadata_json).ok();
    let reason = record.reason.clone().or_else(|| {
        metadata.as_ref().and_then(|value| {
            value
                .get("reason")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
    });
    let metadata_string = |key: &str| {
        metadata
            .as_ref()
            .and_then(|value| value.get(key))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let limit_type = if record.action.starts_with("rate_limit.") {
        "rate_limit"
    } else {
        "budget"
    };
    json!({
        "id": record.event_id,
        "denial_id": record.event_id,
        "org_id": record.org_id,
        "code": reason.clone().unwrap_or_else(|| record.action.clone()),
        "action": record.action,
        "resource_type": record.resource_type,
        "resource_id": record.resource_id,
        "outcome": record.outcome,
        "reason": reason,
        "request_id": record.request_id,
        "correlation_id": record.correlation_id,
        "run_id": record.run_id,
        "agent_session_id": record.agent_session_id,
        "project_id": metadata_string("project_id"),
        "scope_type": metadata_string("scope_type"),
        "scope_id": metadata_string("scope_id"),
        "model_alias": metadata_string("model_alias"),
        "limit_type": limit_type,
        "retry_after_seconds": metadata
            .as_ref()
            .and_then(|value| value.get("retry_after_seconds"))
            .and_then(Value::as_u64),
        "created_at": record.created_at,
    })
}

fn decode_usage_cursor(context: &RequestContext, raw: &str) -> Result<(String, String), ApiError> {
    if raw.len() > 1024 {
        return Err(validation_error(
            context,
            "cursor_invalid",
            "The cursor is invalid.",
        ));
    }
    let (timestamp, id) = decode_page_cursor(raw, context)?;
    if timestamp.len() != 24
        || crate::core::Timestamp::new(&timestamp).is_err()
        || crate::core::ResourceId::new(&id).is_err()
    {
        return Err(validation_error(
            context,
            "cursor_invalid",
            "The cursor is invalid.",
        ));
    }
    Ok((timestamp, id))
}

fn validate_range(
    context: &RequestContext,
    from: Option<&str>,
    to: Option<&str>,
) -> Result<(Option<String>, Option<String>), ApiError> {
    let from = from
        .map(|value| {
            crate::core::Timestamp::new(value)
                .map(|value| value.as_str().to_owned())
                .map_err(|_| {
                    validation_error(
                        context,
                        "from_invalid",
                        "The start of the range is invalid.",
                    )
                })
        })
        .transpose()?;
    let to = to
        .map(|value| {
            crate::core::Timestamp::new(value)
                .map(|value| value.as_str().to_owned())
                .map_err(|_| {
                    validation_error(context, "to_invalid", "The end of the range is invalid.")
                })
        })
        .transpose()?;
    if let (Some(from), Some(to)) = (from.as_deref(), to.as_deref())
        && from >= to
    {
        return Err(validation_error(
            context,
            "range_invalid",
            "The range is invalid.",
        ));
    }
    Ok((from, to))
}

/// A `usage.read` collection over both usage sources.  P05-CR-002 §7 keeps one
/// read shape for the P04 inference source and the additive run source.
#[worker::send]
pub async fn list_usage(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<UsageListQuery>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::UsageRead,
        Some("usage"),
        None,
    )
    .await?;
    let limit = page_limit(query.limit);
    let cursor = query
        .cursor
        .as_deref()
        .map(|raw| decode_usage_cursor(&context, raw))
        .transpose()?;
    let (from, to) = validate_range(&context, query.from.as_deref(), query.to.as_deref())?;
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
    let run_id = query
        .run_id
        .as_deref()
        .map(|value| validate_prefixed_id(&context, value, "run", "run_id_invalid"))
        .transpose()?;
    let mut records = UsageRepository::new(database)
        .list_usage(
            &org_id,
            UsageQuery {
                project_id: query.project_id.as_deref(),
                run_id: run_id.as_deref(),
                from: from.as_deref(),
                to: to.as_deref(),
                cursor: cursor
                    .as_ref()
                    .map(|(created, id)| (created.as_str(), id.as_str())),
                limit: limit + 1,
            },
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
            .map(|record| encode_page_cursor(&record.created_at, &record.event_id))
    } else {
        None
    };
    Ok((
        StatusCode::OK,
        Json(PageResponse {
            items: records.iter().map(usage_event_json).collect::<Vec<_>>(),
            next_cursor,
            has_more,
        }),
    )
        .into_response())
}

/// Derived totals for the same filters as the collection read.  The aggregate
/// is rebuildable; raw usage events stay the reconciliation source.
#[worker::send]
pub async fn usage_summary(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<UsageRangeQuery>,
) -> Result<Response<Body>, ApiError> {
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
    let (from, to) = validate_range(&context, query.from.as_deref(), query.to.as_deref())?;
    let database = database(&state, &context)?;
    let summary = UsageRepository::new(database)
        .summarize_usage(
            &org_id,
            query.project_id.as_deref(),
            query.run_id.as_deref(),
            from.as_deref(),
            to.as_deref(),
        )
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "org_id": org_id,
            "project_id": query.project_id,
            "run_id": query.run_id,
            "from": from,
            "to": to,
            "event_count": summary.event_count,
            "input_tokens": summary.input_tokens,
            "output_tokens": summary.output_tokens,
            "cached_tokens": summary.cached_tokens,
            "cost_minor": summary.cost_minor,
        })),
    )
        .into_response())
}

/// Derived rollup buckets for dashboards.  Rollups are rebuildable and never
/// replace raw usage.
#[worker::send]
pub async fn usage_rollups(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<UsageRollupQuery>,
) -> Result<Response<Body>, ApiError> {
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
    let limit = page_limit(query.limit);
    let cursor = query
        .cursor
        .as_deref()
        .map(|raw| decode_usage_cursor(&context, raw))
        .transpose()?;
    let (from, to) = validate_range(&context, query.from.as_deref(), query.to.as_deref())?;
    let database = database(&state, &context)?;
    let mut records = UsageRepository::new(database)
        .list_rollups(
            &org_id,
            query.project_id.as_deref(),
            query.principal_user_id.as_deref(),
            query.model_alias.as_deref(),
            from.as_deref(),
            to.as_deref(),
            cursor
                .as_ref()
                .map(|(bucket, id)| (bucket.as_str(), id.as_str())),
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
            .map(|record| encode_page_cursor(&record.bucket_start, &record.usage_rollup_id))
    } else {
        None
    };
    Ok((
        StatusCode::OK,
        Json(PageResponse {
            items: records
                .iter()
                .map(|record| {
                    json!({
                        "id": record.usage_rollup_id,
                        "org_id": record.org_id,
                        "project_id": record.project_id,
                        "principal_user_id": record.principal_user_id,
                        "model_alias": record.model_alias,
                        "bucket_start": record.bucket_start,
                        "bucket_end": record.bucket_end,
                        "input_tokens": record.input_tokens,
                        "output_tokens": record.output_tokens,
                        "cached_tokens": record.cached_tokens,
                        "cost_minor": record.cost_minor,
                        "usage_event_count": record.usage_event_count,
                        "updated_at": record.updated_at,
                    })
                })
                .collect::<Vec<_>>(),
            next_cursor,
            has_more,
        }),
    )
        .into_response())
}

/// Immutable budget/rate denial audit rows, newest first.
#[worker::send]
pub async fn usage_denials(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<UsageDenialQuery>,
) -> Result<Response<Body>, ApiError> {
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
    let limit = page_limit(query.limit);
    let cursor = query
        .cursor
        .as_deref()
        .map(|raw| decode_usage_cursor(&context, raw))
        .transpose()?;
    let (from, to) = validate_range(&context, query.from.as_deref(), query.to.as_deref())?;
    let database = database(&state, &context)?;
    let mut records = UsageRepository::new(database)
        .list_denials(
            &org_id,
            from.as_deref(),
            to.as_deref(),
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
            .map(|record| encode_page_cursor(&record.created_at, &record.event_id))
    } else {
        None
    };
    Ok((
        StatusCode::OK,
        Json(PageResponse {
            items: records.iter().map(denial_json).collect::<Vec<_>>(),
            next_cursor,
            has_more,
        }),
    )
        .into_response())
}

/// Append the authoritative actual cost for one usage event.
///
/// * machine identity only (device token, never a browser session);
/// * tenant-scoped lookup of the immutable usage event;
/// * the device must own the correlated run or usage event;
/// * the write is a conditional insert, so a replay returns the same cost row
///   and a contradicting actual is reported as a conflict instead of
///   overwriting history.
#[worker::send]
pub async fn reconcile_usage(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<ReconcileUsageRequest>,
) -> Result<Response<Body>, ApiError> {
    let device = require_accounting_service(&state, &headers, &context, &org_id).await?;
    let key = idempotency_key(&headers, &context)?;
    let request_id = body
        .request_id
        .as_deref()
        .map(|value| validate_prefixed_id(&context, value, "req", "request_id_invalid"))
        .transpose()?;
    let run_id = body
        .run_id
        .as_deref()
        .map(|value| validate_prefixed_id(&context, value, "run", "run_id_invalid"))
        .transpose()?;
    if request_id.is_some() == run_id.is_some() {
        return Err(validation_error(
            &context,
            "reconciliation_identity_invalid",
            "Provide exactly one of request_id or run_id.",
        ));
    }
    let external_id = body.external_id.as_deref().map(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.len() > 255 || trimmed.chars().any(char::is_control) {
            return Err(validation_error(
                &context,
                "external_id_invalid",
                "The external identifier is invalid.",
            ));
        }
        Ok(trimmed.to_owned())
    });
    let external_id = external_id.transpose()?;
    let provider_usage = match body.provider_usage.as_ref() {
        Some(value) => Some(
            crate::modules::usage::redact_provider_usage(value).map_err(|_| {
                validation_error(
                    &context,
                    "provider_usage_invalid",
                    "The provider usage report is invalid.",
                )
            })?,
        ),
        None => None,
    };
    if let Some(actual) = body.actual_cost_minor
        && !(0..=MAX_SAFE_COST_MINOR).contains(&actual)
    {
        return Err(validation_error(
            &context,
            "actual_cost_invalid",
            "The reported cost is invalid.",
        ));
    }
    let database = database(&state, &context)?;
    let repository = UsageRepository::new(database);
    let event = match (request_id.as_deref(), run_id.as_deref()) {
        (Some(request_id), _) => repository
            .find_usage_event_by_request(&org_id, request_id)
            .await
            .map_err(|error| database_error(&context, error))?,
        (None, Some(run_id)) => repository
            .find_usage_event_by_run(&org_id, run_id)
            .await
            .map_err(|error| database_error(&context, error))?,
        _ => None,
    }
    .ok_or_else(|| not_found(&context, "resource_not_found"))?;
    ensure_usage_device_scope(&context, database, &event, &device).await?;

    // The pricing identity is derived from the immutable usage event, never
    // from the caller, so a reconciliation cannot relabel historical price.
    let pricing_version = event
        .pricing_version
        .clone()
        .unwrap_or_else(|| "unversioned".to_owned());
    let pricing_source = if event.pricing_version.is_some() {
        "provider_reported"
    } else {
        "unversioned_provider_report"
    };
    let currency = event.currency.clone().unwrap_or_else(|| "USD".to_owned());
    let source = if event.is_run_source() {
        UsageSource::Run
    } else {
        UsageSource::Inference
    };
    // The recorded identity must be well formed, and every correlation the
    // caller supplied must match it.  A caller can therefore never point a
    // reconciliation at a different request, run, or external record.
    ReconciliationIdentity::new(
        source,
        event.request_id.clone(),
        event.run_id.clone(),
        event.external_id.clone(),
    )
    .map_err(|_| model_error(&context))?;
    if request_id
        .as_deref()
        .is_some_and(|value| event.request_id.as_deref() != Some(value))
        || run_id
            .as_deref()
            .is_some_and(|value| event.run_id.as_deref() != Some(value))
        || external_id
            .as_deref()
            .is_some_and(|value| event.external_id.as_deref() != Some(value))
    {
        return Err(reconciliation_conflict(&context, "identity_mismatch"));
    }
    let cost_minor = body.actual_cost_minor.unwrap_or_default();
    let cost = CostRecord::actual(CostRecordDraft {
        cost_record_id: generated_id(if event.is_run_source() {
            "rcost"
        } else {
            "cost"
        }),
        usage_event_id: event.event_id.clone(),
        org_id: event.org_id.clone(),
        pricing: crate::modules::usage::PricingVersion::new(
            pricing_source,
            pricing_version.clone(),
            event.created_at.clone(),
        )
        .map_err(|_| model_error(&context))?,
        input_tokens: event.input_tokens,
        output_tokens: event.output_tokens,
        cached_tokens: event.cached_tokens,
        cost_minor,
        currency: currency.clone(),
        calculation_kind: crate::modules::usage::CostCalculationKind::Actual,
        recalculated_from_cost_record_id: None,
        created_at: context.received_at.as_str().to_owned(),
    })
    .map_err(|_| model_error(&context))?;

    let body_value = json!({
        "request_id": request_id.clone(),
        "run_id": run_id.clone(),
        "external_id": external_id.clone(),
        "actual_cost_minor": body.actual_cost_minor,
        "provider_usage": provider_usage.as_ref().map(BoundedPayload::as_value),
    });
    let mutation = prepare_scoped_mutation(
        database,
        &context,
        device.device_id.as_str(),
        &org_id,
        &key,
        "POST",
        USAGE_RECONCILE_PATH,
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedScopedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedScopedMutation::Claim(claim) => claim,
    };
    let input = NewCostRecordInput {
        cost_record_id: &cost.cost_record_id,
        usage_event_id: &cost.usage_event_id,
        org_id: &cost.org_id,
        project_id: event.project_id.as_deref(),
        run_id: event.run_id.as_deref(),
        pricing_source: &cost.pricing_source,
        pricing_version: &cost.pricing_version,
        pricing_effective_at: &cost.pricing_effective_at,
        calculation_kind: cost.calculation_kind.as_str(),
        input_tokens: cost.input_tokens,
        output_tokens: cost.output_tokens,
        cached_tokens: cost.cached_tokens,
        cost_minor: cost.cost_minor,
        currency: &cost.currency,
        created_at: &cost.created_at,
    };
    let insert = if event.is_run_source() {
        repository
            .insert_run_cost_record_statement(&input)
            .map_err(|error| database_error(&context, error))?
    } else {
        repository
            .insert_cost_record_statement(&input)
            .map_err(|error| database_error(&context, error))?
    };
    let cost_guard = if event.is_run_source() {
        repository
            .assert_run_cost_record_statement(&input)
            .map_err(|error| database_error(&context, error))?
    } else {
        repository
            .assert_cost_record_statement(&input)
            .map_err(|error| database_error(&context, error))?
    };
    let audit = audit_statement(
        database,
        &context,
        &org_id,
        &generated_id("sec"),
        "usage.reconciled.v1",
        "usage_event",
        &event.event_id,
        Some(&device),
        event.run_id.as_deref(),
        &json!({
            "source": event.source,
            "calculation_kind": cost.calculation_kind.as_str(),
            "pricing_source": cost.pricing_source,
            "pricing_version": cost.pricing_version,
            "currency": cost.currency,
            "provider_usage_present": provider_usage.is_some(),
        }),
    )?;
    let outbox = system_outbox_statement_for_device(
        database,
        &context,
        &org_id,
        "usage.reconciled.v1",
        device.device_id.as_str(),
        &json!({
            "usage_event_id": cost.usage_event_id,
            "cost_record_id": cost.cost_record_id,
            "run_id": event.run_id,
            "request_id": event.request_id,
            "calculation_kind": cost.calculation_kind.as_str(),
        }),
    )?;
    let success = StoredSuccess::new(
        200,
        json!({
            "usage_event": usage_event_json(&event),
            "cost_record": if event.is_run_source() {
                run_cost_record_json(&RunCostRecordRow {
                    run_cost_record_id: cost.cost_record_id.clone(),
                    run_usage_event_id: cost.usage_event_id.clone(),
                    org_id: cost.org_id.clone(),
                    project_id: event.project_id.clone(),
                    run_id: event.run_id.clone(),
                    pricing_source: cost.pricing_source.clone(),
                    pricing_version: cost.pricing_version.clone(),
                    pricing_effective_at: cost.pricing_effective_at.clone(),
                    calculation_kind: cost.calculation_kind.as_str().to_owned(),
                    input_tokens: cost.input_tokens,
                    output_tokens: cost.output_tokens,
                    cached_tokens: cost.cached_tokens,
                    cost_minor: cost.cost_minor,
                    currency: cost.currency.clone(),
                    created_at: cost.created_at.clone(),
                })
            } else {
                cost_record_json(&CostRecordRow {
                    cost_record_id: cost.cost_record_id.clone(),
                    usage_event_id: cost.usage_event_id.clone(),
                    org_id: cost.org_id.clone(),
                    project_id: event.project_id.clone(),
                    run_id: event.run_id.clone(),
                    pricing_source: cost.pricing_source.clone(),
                    pricing_version: cost.pricing_version.clone(),
                    pricing_effective_at: cost.pricing_effective_at.clone(),
                    calculation_kind: cost.calculation_kind.as_str().to_owned(),
                    input_tokens: cost.input_tokens,
                    output_tokens: cost.output_tokens,
                    cached_tokens: cost.cached_tokens,
                    cost_minor: cost.cost_minor,
                    currency: cost.currency.clone(),
                    created_at: cost.created_at.clone(),
                })
            },
        }),
    )
    .map_err(|_| service_unavailable(&context))?;
    match commit_scoped_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![insert, cost_guard, audit],
        outbox,
    )
    .await?
    {
        ScopedMutationCommit::Replayed(replay) => return Ok(replay_response(replay)),
        ScopedMutationCommit::Committed | ScopedMutationCommit::Guarded => {}
    }
    // Re-read the immutable row: the conditional insert either wrote this exact
    // fact, found an identical earlier fact, or was refused because a
    // contradicting actual already exists.
    let recorded = if event.is_run_source() {
        repository
            .find_run_cost_record(
                &org_id,
                &event.event_id,
                cost.calculation_kind.as_str(),
                &cost.pricing_version,
            )
            .await
            .map_err(|error| database_error(&context, error))?
            .map(|row| row.states_same_cost(cost.cost_minor, &cost.pricing_version, &cost.currency))
    } else {
        repository
            .find_cost_record(
                &org_id,
                &event.event_id,
                cost.calculation_kind.as_str(),
                &cost.pricing_version,
            )
            .await
            .map_err(|error| database_error(&context, error))?
            .map(|row| row.states_same_cost(cost.cost_minor, &cost.pricing_version, &cost.currency))
    };
    match recorded {
        Some(true) => Ok((StatusCode::OK, Json(success.body)).into_response()),
        Some(false) => Err(reconciliation_conflict(&context, "actual_cost_mismatch")),
        None => Err(reconciliation_conflict(&context, "usage_event_mismatch")),
    }
}

/// A machine may reconcile only usage it produced: the usage event's device,
/// or the device that owns the correlated managed run.
#[allow(clippy::too_many_arguments)]
async fn ensure_usage_device_scope(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    event: &UsageEventRecord,
    device: &DeviceRecord,
) -> Result<(), ApiError> {
    if let Some(device_id) = event.device_id.as_deref() {
        if device_id == device.device_id {
            return Ok(());
        }
        return Err(not_found(context, "resource_not_found"));
    }
    if let Some(run_id) = event.run_id.as_deref() {
        let run = RunRepository::new(database)
            .find_run(&event.org_id, run_id)
            .await
            .map_err(|_| service_unavailable(context))?;
        if let Some(run) = run
            && run.device_id == device.device_id
        {
            return Ok(());
        }
    }
    Err(not_found(context, "resource_not_found"))
}

fn model_error(context: &RequestContext) -> ApiError {
    validation_error(
        context,
        "usage_model_invalid",
        "The usage accounting request is invalid.",
    )
}

#[allow(clippy::too_many_arguments)]
fn audit_statement(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    org_id: &str,
    event_id: &str,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    device: Option<&DeviceRecord>,
    run_id: Option<&str>,
    metadata: &Value,
) -> Result<D1PreparedStatement, ApiError> {
    security_event_statement_with_context(
        database,
        context,
        None,
        Some(org_id),
        event_id,
        action,
        resource_type,
        Some(resource_id),
        "success",
        metadata,
        device.map(|device| device.device_id.as_str()),
        run_id,
        None,
        None,
    )
}

/// Device-originated outbox event.  The actor is `system` plus the device ID
/// rather than an anonymous or user actor, per P05-CR-002 §8.
pub(crate) fn system_outbox_statement_for_device(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    org_id: &str,
    event_type: &str,
    device_id: &str,
    payload: &Value,
) -> Result<D1PreparedStatement, ApiError> {
    let mut event_payload = payload.as_object().cloned().unwrap_or_default();
    event_payload.insert("device_id".to_owned(), json!(device_id));
    let event = EventEnvelope {
        event_id: new_event_id(),
        event_type: EventType::new(event_type).map_err(|_| {
            errors::api_error(
                context,
                ApiErrorCode::InternalError,
                "The event type is invalid.",
            )
        })?,
        occurred_at: context.received_at.clone(),
        request_id: context.request_id.clone(),
        correlation_id: context.correlation_id.clone(),
        actor: ActorContext {
            actor_type: ActorType::System,
            actor_id: None,
            effective_user_id: None,
        },
        organization_id: Some(OrganizationId::new(org_id).map_err(|_| {
            errors::api_error(
                context,
                ApiErrorCode::InternalError,
                "The event scope is invalid.",
            )
        })?),
        payload: Value::Object(event_payload),
    };
    OutboxRepository::new(database)
        .insert_statement(&event)
        .map_err(|_| service_unavailable(context))
}

/// Keep the fail-closed reason visible to callers of the accounting surface.
pub(crate) fn fail_closed_budget_state(context: &RequestContext) -> ApiError {
    budget_state_unavailable(context)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> RequestContext {
        RequestContext::new(
            "req_0123456789abcdef0123456789abcdef".parse().unwrap(),
            "req_0123456789abcdef0123456789abcdef".parse().unwrap(),
            "2026-09-25T12:00:00.000Z".parse().unwrap(),
        )
    }

    #[test]
    fn an_inverted_or_unparsable_range_is_rejected() {
        let context = context();
        assert!(
            validate_range(
                &context,
                Some("2026-09-01T00:00:00.000Z"),
                Some("2026-09-30T00:00:00.000Z")
            )
            .is_ok()
        );
        assert!(
            validate_range(
                &context,
                Some("2026-09-30T00:00:00.000Z"),
                Some("2026-09-01T00:00:00.000Z")
            )
            .is_err()
        );
        assert!(validate_range(&context, Some("not-a-time"), None).is_err());
        assert!(validate_range(&context, None, Some("2026-09-01T00:00:00.000Z")).is_ok());
    }

    #[test]
    fn budget_state_failure_is_fail_closed_for_cloud_accounting() {
        let error = fail_closed_budget_state(&context());
        assert_eq!(error.error.code, ApiErrorCode::ServiceUnavailable);
        assert_eq!(
            error.error.details.get("reason"),
            Some(&json!("budget_state_unavailable"))
        );
    }

    #[test]
    fn reconciliation_conflicts_expose_a_stable_reason() {
        let error = reconciliation_conflict(&context(), "actual_cost_mismatch");
        assert_eq!(error.error.code, ApiErrorCode::Conflict);
        assert_eq!(
            error.error.details.get("reason"),
            Some(&json!("usage_reconciliation_conflict"))
        );
        assert_eq!(
            error.error.details.get("conflict"),
            Some(&json!("actual_cost_mismatch"))
        );
    }

    #[test]
    fn usage_rows_expose_source_and_reconciliation_state() {
        let record = UsageEventRecord {
            event_id: "use_1".to_owned(),
            request_id: Some("req_1".to_owned()),
            run_id: None,
            org_id: "org_1".to_owned(),
            project_id: None,
            principal_user_id: "usr_1".to_owned(),
            session_id: None,
            device_id: Some("dvc_1".to_owned()),
            source: "inference".to_owned(),
            external_id: None,
            reconciliation_status: "recorded".to_owned(),
            model_alias: Some("coding-default".to_owned()),
            input_tokens: Some(3),
            output_tokens: Some(4),
            cached_tokens: None,
            provider_usage_json: "{}".to_owned(),
            estimated_cost_minor: Some(10),
            actual_cost_minor: None,
            currency: Some("USD".to_owned()),
            pricing_version: Some("2026-09".to_owned()),
            budget_decision: "allow".to_owned(),
            route_version_id: Some("rtv_1".to_owned()),
            provider_id: Some("prv_1".to_owned()),
            model_id: Some("mdl_1".to_owned()),
            ttft_ms: Some(10),
            total_latency_ms: Some(20),
            created_at: "2026-09-25T12:00:00.000Z".to_owned(),
        };
        let value = usage_event_json(&record);
        assert_eq!(value.get("source"), Some(&json!("inference")));
        assert_eq!(value.get("reconciliation_status"), Some(&json!("recorded")));
        assert!(value.get("request_id").is_some());
        // Provider usage is bounded/redacted metadata and is never echoed.
        assert!(value.get("provider_usage").is_none());
    }
}
