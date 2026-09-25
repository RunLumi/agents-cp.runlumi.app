//! P05 budget, reservation, and rate/concurrency policy HTTP surface.
//!
//! Budget and rate-policy configuration is an ordinary `budgets.manage`
//! browser mutation: CSRF, `Idempotency-Key`, and optimistic `version` are all
//! required and the tenant comes from the authorized organization context.
//!
//! Reservation creation and reservation reconciliation are **server-owned**
//! money operations (P05-CR-002 §6).  Those handlers require a machine
//! identity, so no browser session can assert a hold, an amount, or a status.
//!
//! The hard-budget gate is the single conditional D1 insert in
//! `repositories::budgets`.  Nothing here pre-checks a budget and then writes,
//! because that stale-read pattern is what the contract forbids; a guard
//! statement in the same batch rolls back the claim, audit, and outbox rows
//! when the gate refuses, and the handler re-reads authoritative state to
//! choose between an idempotent replay and a stable denial.

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
    adapters::add_seconds,
    app::AppState,
    core::{ApiError, ApiErrorCode, RequestContext, StoredSuccess, Timestamp},
    http::auth::require_csrf,
    modules::{
        authorization::Permission,
        budget_p05::{BudgetScope, MAX_RESERVATION_TTL_SECONDS, ScopeType},
    },
    repositories::{
        BudgetRecord, BudgetRepository, BudgetReservationRecord, BudgetUpdateInput, NewBudgetInput,
        NewReservationInput, OrganizationRepository, ProjectRepository, RateLimitPolicyRecord,
        ReservationReconcileInput, RunRepository, UpsertRateLimitInput,
    },
    routes::{
        agents::{
            PageResponse, decode_page_cursor, denied, encode_page_cursor, generated_id, page_limit,
            replay_response, validate_prefixed_id, validate_text, validation_error,
        },
        authorization::authorize_org,
        errors,
        support::{
            database, database_error, domain_error, idempotency_key, outbox_statement,
            security_event_statement_with_context,
        },
        usage::{
            PreparedScopedMutation, ScopedMutationCommit, commit_scoped_mutation,
            prepare_scoped_mutation, require_accounting_service,
            system_outbox_statement_for_device,
        },
    },
};

/// Idempotency scope paths for the mutations that accept `Idempotency-Key`.
pub const BUDGETS_PATH: &str = "/api/v1/orgs/{org_id}/budgets";
pub const BUDGET_PATH: &str = "/api/v1/orgs/{org_id}/budgets/{budget_id}";
pub const RESERVATIONS_PATH: &str = "/api/v1/orgs/{org_id}/budgets/{budget_id}/reservations";
pub const RECONCILE_RESERVATION_PATH: &str =
    "/api/v1/orgs/{org_id}/budgets/{budget_id}/reservations/{reservation_id}/reconcile";
#[allow(dead_code)]
pub const RATE_LIMITS_PATH: &str = "/api/v1/orgs/{org_id}/rate-limits";
pub const RATE_LIMIT_PATH: &str = "/api/v1/orgs/{org_id}/rate-limits/{scope_type}/{scope_id}";

/// Scope types the frozen rate-limit route can address.  The route always
/// carries a `{scope_id}` segment, so an organization policy is addressed by
/// its own organization ID and stored with a NULL scope ID.
const ADDRESSABLE_RATE_SCOPES: [&str; 5] = [
    "organization",
    "project",
    "user",
    "service_account",
    "model_alias",
];

/// D1 binds integer values through JavaScript numbers; keep authoritative
/// money below the exact-integer range even though SQLite stores an i64.
const MAX_SAFE_MONEY_MINOR: u64 = 9_000_000_000_000_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetListQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    pub scope_type: Option<String>,
    pub scope_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateBudgetRequest {
    pub scope_type: String,
    pub scope_id: Option<String>,
    pub period_start: String,
    pub period_end: String,
    pub limit_minor: i64,
    pub currency: String,
    pub hard: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchBudgetRequest {
    pub limit_minor: Option<i64>,
    pub period_start: Option<String>,
    pub period_end: Option<String>,
    pub currency: Option<String>,
    pub hard: Option<bool>,
    pub version: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateReservationRequest {
    pub request_id: String,
    pub run_id: Option<String>,
    pub reserved_minor: i64,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileReservationRequest {
    pub actual_minor: Option<i64>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitListQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    pub scope_type: Option<String>,
    pub scope_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutRateLimitRequest {
    pub requests_per_minute: Option<i64>,
    pub tokens_per_minute: Option<i64>,
    pub max_concurrent_requests: Option<i64>,
    pub version: i64,
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
        "The budget store is unavailable.",
    )
}

/// Fail-closed reason for a managed cloud dispatch whose authoritative budget
/// state cannot be read.  Local-only execution is never failed for this.
fn budget_state_unavailable(context: &RequestContext) -> ApiError {
    crate::routes::usage::fail_closed_budget_state(context)
}

/// Mirrors the frozen P04 mapping so a blocked dispatch keeps one stable shape.
fn budget_exceeded(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::PermissionDenied,
        "The organization budget does not allow this request.",
    )
    .with_detail("reason", json!("budget_exceeded"))
}

fn reservation_not_found(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::NotFound,
        "The requested resource was not found.",
    )
    .with_detail("reason", json!("reservation_not_found"))
}

fn reservation_already_reconciled(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::Conflict,
        "reservation_already_reconciled",
        "The reservation was already reconciled.",
    )
}

fn reservation_conflict(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::Conflict,
        "reservation_conflict",
        "A different reservation already exists for this request.",
    )
}

fn version_conflict(context: &RequestContext) -> ApiError {
    denied(
        context,
        ApiErrorCode::Conflict,
        "version_conflict",
        "The resource changed. Refresh and try again.",
    )
}

/// Normalize an RFC 3339 UTC instant to fixed millisecond precision so stored
/// values compare correctly as text in both SQL and Rust.  Budget periods and
/// reservation expiries are compared with `<`/`>` on their stored text, so a
/// mixed-precision value would otherwise order incorrectly.
fn canonical_instant(value: &Timestamp) -> Option<String> {
    let raw = value.as_str();
    if raw.len() == 24 {
        return Some(raw.to_owned());
    }
    // 19 characters cover `YYYY-MM-DDTHH:MM:SS`; the remainder is either `Z`
    // or `.` plus the fractional digits and `Z`.
    let (head, tail) = raw.split_at(19);
    match tail {
        "Z" => Some(format!("{head}.000Z")),
        fraction => {
            let digits = fraction
                .strip_prefix('.')
                .and_then(|value| value.strip_suffix('Z'))?;
            if digits.len() >= 3 {
                return Some(format!("{head}.{}Z", &digits[..3]));
            }
            Some(format!("{head}.{:0<3}Z", digits))
        }
    }
}

fn parse_instant(
    context: &RequestContext,
    value: &str,
    reason: &str,
    message: &str,
) -> Result<String, ApiError> {
    let parsed = Timestamp::new(value).map_err(|_| validation_error(context, reason, message))?;
    canonical_instant(&parsed).ok_or_else(|| validation_error(context, reason, message))
}

fn validate_currency(context: &RequestContext, value: &str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    let valid = trimmed.len() >= 3
        && trimmed.len() <= 12
        && trimmed.bytes().all(|byte| byte.is_ascii_uppercase());
    if valid {
        Ok(trimmed.to_owned())
    } else {
        Err(validation_error(
            context,
            "currency_invalid",
            "The currency code is invalid.",
        ))
    }
}

/// Parse a budget scope using the shared P04/P05 vocabulary.  `BudgetScope`
/// enforces that only an organization scope may omit its scope ID.
fn parse_scope_type(context: &RequestContext, scope_type: &str) -> Result<ScopeType, ApiError> {
    ScopeType::parse(scope_type.trim()).ok_or_else(|| {
        validation_error(
            context,
            "scope_type_invalid",
            "Choose a valid budget scope type.",
        )
    })
}

fn validate_scope_id(context: &RequestContext, scope_id: &str) -> Result<String, ApiError> {
    validate_text(
        context,
        scope_id,
        128,
        "scope_id_invalid",
        "The scope identifier is invalid.",
    )
}

/// Validate a budget scope, returning the stored scope ID (`None` only for an
/// organization scope).
fn validate_budget_scope(
    context: &RequestContext,
    org_id: &str,
    scope_type: &str,
    scope_id: Option<&str>,
) -> Result<(ScopeType, Option<String>), ApiError> {
    let parsed = parse_scope_type(context, scope_type)?;
    let scope_id = match scope_id {
        Some(value) if !value.trim().is_empty() => {
            if parsed == ScopeType::Organization {
                return Err(validation_error(
                    context,
                    "scope_id_invalid",
                    "An organization budget has no scope identifier.",
                ));
            }
            Some(validate_scope_id(context, value)?)
        }
        _ => None,
    };
    BudgetScope::new(parsed, org_id, scope_id.clone())
        .map_err(|error| validation_error(context, error.code(), "The budget scope is invalid."))?;
    Ok((parsed, scope_id))
}

async fn ensure_scope_resource(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    org_id: &str,
    scope_type: ScopeType,
    scope_id: Option<&str>,
) -> Result<(), ApiError> {
    match (scope_type, scope_id) {
        (ScopeType::Project, Some(project_id)) => ProjectRepository::new(database)
            .find_project(project_id)
            .await
            .map_err(|_| service_unavailable(context))?
            .filter(|project| project.org_id == org_id)
            .map(|_| ())
            .ok_or_else(|| not_found(context, "project_not_found")),
        (ScopeType::User, Some(user_id)) => OrganizationRepository::new(database)
            .find_membership(org_id, user_id)
            .await
            .map_err(|_| service_unavailable(context))?
            .filter(|membership| membership.status == "active")
            .map(|_| ())
            .ok_or_else(|| not_found(context, "user_not_found")),
        _ => Ok(()),
    }
}

fn scope_id_filter(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn budget_json(record: &BudgetRecord) -> Value {
    json!({
        "budget_id": record.budget_id,
        "id": record.budget_id,
        "org_id": record.org_id,
        "scope_type": record.scope_type,
        "scope_id": record.scope_id,
        "period_start": record.period_start,
        "period_end": record.period_end,
        "limit_minor": record.limit_minor,
        "currency": record.currency,
        "hard": record.hard,
        "lifecycle": "active",
        "state": "active",
        "spent_minor": Value::Null,
        "used_minor": Value::Null,
        "reserved_minor": Value::Null,
        "version": record.version,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    })
}

fn reservation_json(record: &BudgetReservationRecord) -> Value {
    json!({
        "reservation_id": record.reservation_id,
        "id": record.reservation_id,
        "request_id": record.request_id,
        "org_id": record.org_id,
        "run_id": record.run_id,
        "budget_id": record.budget_id,
        "reserved_minor": record.reserved_minor,
        "committed_minor": record.committed_minor,
        "status": record.status,
        "currency": record.currency,
        "expires_at": record.expires_at,
        "reconciled_at": record.reconciled_at,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    })
}

fn rate_limit_json(record: &RateLimitPolicyRecord) -> Value {
    json!({
        "rate_limit_policy_id": record.rate_limit_policy_id,
        "id": record.rate_limit_policy_id,
        "org_id": record.org_id,
        "scope_type": record.scope_type,
        "scope_id": record.scope_id,
        "requests_per_minute": record.requests_per_minute,
        "tokens_per_minute": record.tokens_per_minute,
        "max_concurrent_requests": record.max_concurrent_requests,
        "applicable_model_aliases": if record.scope_type == "model_alias" {
            record.scope_id.clone().into_iter().collect::<Vec<_>>()
        } else {
            Vec::<String>::new()
        },
        "status": if record.has_limits() { "healthy" } else { "disabled" },
        "enabled": record.has_limits(),
        "version": record.version,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    })
}

#[allow(clippy::too_many_arguments)]
fn budget_audit(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    org_id: &str,
    principal: Option<&crate::core::Principal>,
    action: &str,
    resource_id: &str,
    outcome: &str,
    metadata: &Value,
) -> Result<D1PreparedStatement, ApiError> {
    security_event_statement_with_context(
        database,
        context,
        principal,
        Some(org_id),
        &generated_id("sec"),
        action,
        "budget",
        Some(resource_id),
        outcome,
        metadata,
        None,
        None,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn device_audit(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    org_id: &str,
    device_id: &str,
    run_id: Option<&str>,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    outcome: &str,
    metadata: &Value,
) -> Result<D1PreparedStatement, ApiError> {
    security_event_statement_with_context(
        database,
        context,
        None,
        Some(org_id),
        &generated_id("sec"),
        action,
        resource_type,
        Some(resource_id),
        outcome,
        metadata,
        Some(device_id),
        run_id,
        None,
        None,
    )
}

/// `budgets.read` collection with an opaque keyset cursor.
#[worker::send]
pub async fn list_budgets(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<BudgetListQuery>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::BudgetsRead,
        Some("budget"),
        None,
    )
    .await?;
    let limit = page_limit(query.limit);
    let cursor = query
        .cursor
        .as_deref()
        .map(|raw| decode_page_cursor(raw, &context))
        .transpose()?;
    if let Some(scope_type) = query.scope_type.as_deref() {
        parse_scope_type(&context, scope_type)?;
    }
    let database = database(&state, &context)?;
    let mut records = BudgetRepository::new(database)
        .list_budgets(
            &org_id,
            query.scope_type.as_deref(),
            scope_id_filter(query.scope_id.as_deref()),
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
            .map(|record| encode_page_cursor(&record.created_at, &record.budget_id))
    } else {
        None
    };
    Ok((
        StatusCode::OK,
        Json(PageResponse {
            items: records.iter().map(budget_json).collect::<Vec<_>>(),
            next_cursor,
            has_more,
        }),
    )
        .into_response())
}

/// `budgets.manage` create.  A duplicate scope/period aborts the batch through
/// the guard statement, so the caller sees a conflict instead of a 500.
#[worker::send]
pub async fn create_budget(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<CreateBudgetRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::BudgetsManage,
        Some("budget"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let (scope_type, scope_id) = validate_budget_scope(
        &context,
        &org_id,
        &body.scope_type,
        body.scope_id.as_deref(),
    )?;
    let period_start = parse_instant(
        &context,
        &body.period_start,
        "period_start_invalid",
        "The budget period start is invalid.",
    )?;
    let period_end = parse_instant(
        &context,
        &body.period_end,
        "period_end_invalid",
        "The budget period end is invalid.",
    )?;
    if period_start >= period_end {
        return Err(validation_error(
            &context,
            "period_invalid",
            "The budget period is invalid.",
        ));
    }
    if body.limit_minor < 0
        || u64::try_from(body.limit_minor).map_or(true, |value| value > MAX_SAFE_MONEY_MINOR)
    {
        return Err(validation_error(
            &context,
            "limit_minor_invalid",
            "The budget limit is invalid.",
        ));
    }
    let currency = validate_currency(&context, &body.currency)?;
    let database = database(&state, &context)?;
    ensure_scope_resource(database, &context, &org_id, scope_type, scope_id.as_deref()).await?;
    let body_value = json!({
        "scope_type": body.scope_type.clone(),
        "scope_id": body.scope_id.clone(),
        "period_start": body.period_start.clone(),
        "period_end": body.period_end.clone(),
        "limit_minor": body.limit_minor,
        "currency": body.currency.clone(),
        "hard": body.hard,
    });
    let mutation = prepare_scoped_mutation(
        database,
        &context,
        access.principal.user_id.as_str(),
        &org_id,
        &key,
        "POST",
        BUDGETS_PATH,
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedScopedMutation::Replay(success) => {
            let _ =
                crate::routes::devices::refresh_policy_snapshot(database, &context, &org_id, None)
                    .await;
            return Ok(replay_response(success));
        }
        PreparedScopedMutation::Claim(claim) => claim,
    };
    let now =
        canonical_instant(&context.received_at).ok_or_else(|| service_unavailable(&context))?;
    let record = BudgetRecord {
        budget_id: generated_id("bud"),
        org_id: org_id.clone(),
        scope_type: scope_type.as_str().to_owned(),
        scope_id,
        period_start: period_start.clone(),
        period_end: period_end.clone(),
        limit_minor: body.limit_minor,
        hard: body.hard,
        version: 1,
        currency: currency.clone(),
        created_at: now.clone(),
        updated_at: now,
    };
    let repository = BudgetRepository::new(database);
    let absent = repository
        .assert_budget_absent_statement(
            &org_id,
            &record.scope_type,
            record.scope_id.as_deref(),
            &period_start,
            &period_end,
        )
        .map_err(|error| database_error(&context, error))?;
    let insert = repository
        .insert_budget_statement(&NewBudgetInput {
            budget_id: &record.budget_id,
            org_id: &record.org_id,
            scope_type: &record.scope_type,
            scope_id: record.scope_id.as_deref(),
            period_start: &record.period_start,
            period_end: &record.period_end,
            limit_minor: record.limit_minor,
            hard: record.hard,
            currency: &record.currency,
            created_at: &record.created_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let audit = budget_audit(
        database,
        &context,
        &org_id,
        Some(&access.principal),
        "budget.created.v1",
        &record.budget_id,
        "success",
        &json!({
            "scope_type": record.scope_type,
            "scope_id": record.scope_id,
            "hard": record.hard,
            "limit_minor": record.limit_minor,
            "currency": record.currency,
        }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "budget.created.v1",
        &json!({
            "budget_id": record.budget_id,
            "scope_type": record.scope_type,
            "scope_id": record.scope_id,
            "hard": record.hard,
            "version": record.version,
        }),
    )?;
    let success =
        StoredSuccess::new(201, budget_json(&record)).map_err(|_| service_unavailable(&context))?;
    match commit_scoped_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![absent, insert, audit],
        outbox,
    )
    .await?
    {
        ScopedMutationCommit::Replayed(replay) => return Ok(replay_response(replay)),
        ScopedMutationCommit::Committed => {
            let _ =
                crate::routes::devices::refresh_policy_snapshot(database, &context, &org_id, None)
                    .await;
            return Ok((StatusCode::CREATED, Json(success.body)).into_response());
        }
        ScopedMutationCommit::Guarded => {}
    }
    Err(denied(
        &context,
        ApiErrorCode::Conflict,
        "budget_conflict",
        "A budget already exists for this scope and period.",
    ))
}

/// `budgets.read` single budget.  A budget outside the authorized organization
/// reads as missing, never as forbidden.
#[worker::send]
pub async fn get_budget(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, budget_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::BudgetsRead,
        Some("budget"),
        Some(&budget_id),
    )
    .await?;
    let budget_id = validate_prefixed_id(&context, &budget_id, "bud", "budget_id_invalid")?;
    let database = database(&state, &context)?;
    let record = BudgetRepository::new(database)
        .find_budget(&org_id, &budget_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context, "budget_not_found"))?;
    let scope_type = parse_scope_type(&context, &record.scope_type)?;
    ensure_scope_resource(
        database,
        &context,
        &org_id,
        scope_type,
        record.scope_id.as_deref(),
    )
    .await?;
    Ok((StatusCode::OK, Json(budget_json(&record))).into_response())
}

/// `budgets.manage` update with optimistic `version`.  The batch aborts when
/// the version predicate fails, so no stale write can commit.
#[worker::send]
pub async fn patch_budget(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, budget_id)): Path<(String, String)>,
    Json(body): Json<PatchBudgetRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::BudgetsManage,
        Some("budget"),
        Some(&budget_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    if body.version <= 0 {
        return Err(validation_error(
            &context,
            "version_invalid",
            "The resource version is invalid.",
        ));
    }
    let budget_id = validate_prefixed_id(&context, &budget_id, "bud", "budget_id_invalid")?;
    let database = database(&state, &context)?;
    let repository = BudgetRepository::new(database);
    let existing = repository
        .find_budget(&org_id, &budget_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context, "budget_not_found"))?;
    if existing.version != body.version {
        return Err(version_conflict(&context));
    }
    let existing_scope_type = parse_scope_type(&context, &existing.scope_type)?;
    ensure_scope_resource(
        database,
        &context,
        &org_id,
        existing_scope_type,
        existing.scope_id.as_deref(),
    )
    .await?;
    let limit_minor = body.limit_minor.unwrap_or(existing.limit_minor);
    if limit_minor < 0 {
        return Err(validation_error(
            &context,
            "limit_minor_invalid",
            "The budget limit is invalid.",
        ));
    }
    let period_start = match body.period_start.as_deref() {
        Some(value) => parse_instant(
            &context,
            value,
            "period_start_invalid",
            "The budget period start is invalid.",
        )?,
        None => existing.period_start.clone(),
    };
    let period_end = match body.period_end.as_deref() {
        Some(value) => parse_instant(
            &context,
            value,
            "period_end_invalid",
            "The budget period end is invalid.",
        )?,
        None => existing.period_end.clone(),
    };
    if period_start >= period_end {
        return Err(validation_error(
            &context,
            "period_invalid",
            "The budget period is invalid.",
        ));
    }
    if period_end < existing.period_end || period_start > existing.period_start {
        return Err(validation_error(
            &context,
            "period_immutable",
            "The budget period cannot be moved behind recorded spend.",
        ));
    }
    let currency = match body.currency.as_deref() {
        Some(value) => validate_currency(&context, value)?,
        None => existing.currency.clone(),
    };
    let hard = body.hard.unwrap_or(existing.hard);
    let now =
        canonical_instant(&context.received_at).ok_or_else(|| service_unavailable(&context))?;
    let mutation = prepare_scoped_mutation(
        database,
        &context,
        access.principal.user_id.as_str(),
        &org_id,
        &key,
        "PATCH",
        BUDGET_PATH,
        &json!({
            "budget_id": budget_id,
            "version": body.version,
            "limit_minor": limit_minor,
            "period_start": period_start,
            "period_end": period_end,
            "currency": currency,
            "hard": hard,
        }),
    )
    .await?;
    let claim = match mutation {
        PreparedScopedMutation::Replay(success) => {
            let _ =
                crate::routes::devices::refresh_policy_snapshot(database, &context, &org_id, None)
                    .await;
            return Ok(replay_response(success));
        }
        PreparedScopedMutation::Claim(claim) => claim,
    };
    let assertion = repository
        .assert_budget_version_statement(&budget_id, &org_id, body.version)
        .map_err(|error| database_error(&context, error))?;
    let update = repository
        .update_budget_statement(&BudgetUpdateInput {
            budget_id: &budget_id,
            org_id: &org_id,
            expected_version: body.version,
            limit_minor,
            hard,
            period_start: &period_start,
            period_end: &period_end,
            currency: &currency,
            updated_at: &now,
        })
        .map_err(|error| database_error(&context, error))?;
    let audit = budget_audit(
        database,
        &context,
        &org_id,
        Some(&access.principal),
        "budget.updated.v1",
        &budget_id,
        "success",
        &json!({
            "version": body.version + 1,
            "hard": hard,
            "limit_minor": limit_minor,
            "currency": currency,
        }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "budget.updated.v1",
        &json!({
            "budget_id": budget_id,
            "version": body.version + 1,
            "hard": hard,
        }),
    )?;
    let expected = BudgetRecord {
        budget_id: budget_id.clone(),
        org_id: org_id.clone(),
        scope_type: existing.scope_type.clone(),
        scope_id: existing.scope_id.clone(),
        period_start: period_start.clone(),
        period_end: period_end.clone(),
        limit_minor,
        hard,
        version: existing.version + 1,
        currency: currency.clone(),
        created_at: existing.created_at.clone(),
        updated_at: now.clone(),
    };
    let success = StoredSuccess::new(200, budget_json(&expected))
        .map_err(|_| service_unavailable(&context))?;
    match commit_scoped_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![assertion, update, audit],
        outbox,
    )
    .await?
    {
        ScopedMutationCommit::Replayed(replay) => return Ok(replay_response(replay)),
        ScopedMutationCommit::Committed => {
            let _ =
                crate::routes::devices::refresh_policy_snapshot(database, &context, &org_id, None)
                    .await;
            return Ok((StatusCode::OK, Json(success.body)).into_response());
        }
        ScopedMutationCommit::Guarded => return Err(version_conflict(&context)),
    }
}

/// Machine-only reservation admission.
///
/// The hold is created by one conditional D1 insert that re-checks committed
/// usage plus live reservations inside the same statement, so concurrent
/// eligible requests cannot both slip past a hard limit.  A guard statement in
/// the same batch rolls everything back when no hold is granted, which is how a
/// denial stays atomic with its claim, audit, and outbox rows.
#[worker::send]
pub async fn create_reservation(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, budget_id)): Path<(String, String)>,
    Json(body): Json<CreateReservationRequest>,
) -> Result<Response<Body>, ApiError> {
    let device = require_accounting_service(&state, &headers, &context, &org_id).await?;
    let key = idempotency_key(&headers, &context)?;
    let budget_id = validate_prefixed_id(&context, &budget_id, "bud", "budget_id_invalid")?;
    let request_id = validate_prefixed_id(&context, &body.request_id, "req", "request_id_invalid")?;
    let run_id = body
        .run_id
        .as_deref()
        .map(|value| validate_prefixed_id(&context, value, "run", "run_id_invalid"))
        .transpose()?;
    let reserved_minor = match u64::try_from(body.reserved_minor) {
        Ok(amount) if amount > 0 && amount <= MAX_SAFE_MONEY_MINOR => amount,
        _ => {
            return Err(validation_error(
                &context,
                "reserved_minor_invalid",
                "The reserved amount is invalid.",
            ));
        }
    };
    let now = canonical_instant(&context.received_at)
        .ok_or_else(|| budget_state_unavailable(&context))?;
    let expires_at = parse_instant(
        &context,
        &body.expires_at,
        "expires_at_invalid",
        "The reservation expiry is invalid.",
    )?;
    if expires_at <= now {
        return Err(validation_error(
            &context,
            "expires_at_invalid",
            "The reservation expiry must be in the future.",
        ));
    }
    let latest_expiry = add_seconds(&context.received_at, MAX_RESERVATION_TTL_SECONDS as u32)
        .map_err(|_| budget_state_unavailable(&context))
        .and_then(|value| {
            canonical_instant(&value).ok_or_else(|| budget_state_unavailable(&context))
        })?;
    if expires_at > latest_expiry {
        return Err(validation_error(
            &context,
            "expires_at_invalid",
            "The reservation expiry is too far in the future.",
        ));
    }
    let database = database(&state, &context)?;
    let repository = BudgetRepository::new(database);
    // A budget from another tenant is indistinguishable from a missing one.
    let budget = repository
        .find_budget(&org_id, &budget_id)
        .await
        .map_err(|_| budget_state_unavailable(&context))?
        .ok_or_else(|| not_found(&context, "budget_not_found"))?;
    if !budget.hard || budget.period_start > now || budget.period_end <= now {
        return Err(validation_error(
            &context,
            "reservation_budget_invalid",
            "Reservations require an active hard budget.",
        ));
    }
    let inference = repository
        .find_inference_request_scope(&org_id, &request_id)
        .await
        .map_err(|_| budget_state_unavailable(&context))?
        .ok_or_else(|| not_found(&context, "resource_not_found"))?;
    if run_id.as_deref().is_some() && run_id.as_deref() != inference.run_id.as_deref() {
        return Err(not_found(&context, "resource_not_found"));
    }
    // The request row is the authoritative optional run correlation.  A
    // client may omit it, but the stored reservation never loses the link.
    let run_id = run_id.or(inference.run_id.clone());
    let scope_matches = match budget.scope_type.as_str() {
        "organization" => true,
        "project" => budget.scope_id.as_deref() == inference.project_id.as_deref(),
        "user" => budget.scope_id.as_deref() == Some(inference.principal_user_id.as_str()),
        "service_account" => false,
        "model_alias" => budget.scope_id.as_deref() == Some(inference.model_alias.as_str()),
        _ => false,
    };
    if !scope_matches {
        return Err(not_found(&context, "resource_not_found"));
    }
    // The hold belongs to the execution host that produced the request.
    if inference.device_id.as_deref() != Some(device.device_id.as_str()) {
        return Err(not_found(&context, "resource_not_found"));
    }
    if let Some(run_id) = run_id.as_deref() {
        let run = RunRepository::new(database)
            .find_run(&org_id, run_id)
            .await
            .map_err(|_| service_unavailable(&context))?
            .ok_or_else(|| not_found(&context, "resource_not_found"))?;
        if run.device_id != device.device_id {
            return Err(not_found(&context, "resource_not_found"));
        }
    }
    let body_value = json!({
        "request_id": request_id.clone(),
        "run_id": run_id.clone(),
        "reserved_minor": reserved_minor,
        "expires_at": expires_at.clone(),
        "budget_id": budget.budget_id.clone(),
    });
    let mutation = prepare_scoped_mutation(
        database,
        &context,
        device.device_id.as_str(),
        &org_id,
        &key,
        "POST",
        RESERVATIONS_PATH,
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedScopedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedScopedMutation::Claim(claim) => claim,
    };
    let reservation_id = generated_id("bud");
    let insert = repository
        .insert_reservation_if_available_statement(&NewReservationInput {
            reservation_id: &reservation_id,
            request_id: &request_id,
            org_id: &org_id,
            reserved_minor: reserved_minor as i64,
            expires_at: &expires_at,
            now: &now,
            run_id: run_id.as_deref(),
            budget_id: Some(&budget.budget_id),
            currency: &budget.currency,
        })
        .map_err(|error| database_error(&context, error))?;
    let guard = repository
        .assert_reservation_created_statement(&reservation_id, &org_id, &request_id)
        .map_err(|error| database_error(&context, error))?;
    let audit = device_audit(
        database,
        &context,
        &org_id,
        &device.device_id,
        run_id.as_deref(),
        "budget.reserved.v1",
        "budget_reservation",
        &reservation_id,
        "success",
        &json!({
            "request_id": request_id,
            "budget_id": budget.budget_id,
            "reserved_minor": reserved_minor,
            "currency": budget.currency,
            "expires_at": expires_at,
        }),
    )?;
    let outbox = system_outbox_statement_for_device(
        database,
        &context,
        &org_id,
        "budget.reserved.v1",
        &device.device_id,
        &json!({
            "reservation_id": reservation_id,
            "request_id": request_id,
            "run_id": run_id,
            "reserved_minor": reserved_minor,
        }),
    )?;
    let expected = BudgetReservationRecord {
        reservation_id: reservation_id.clone(),
        request_id: request_id.clone(),
        org_id: org_id.clone(),
        reserved_minor: reserved_minor as i64,
        committed_minor: None,
        status: "reserved".to_owned(),
        expires_at: expires_at.clone(),
        created_at: now.clone(),
        updated_at: now,
        run_id: run_id.clone(),
        budget_id: Some(budget.budget_id.clone()),
        currency: budget.currency.clone(),
        reconciled_at: None,
        reconciliation_reason: None,
    };
    let success = StoredSuccess::new(201, reservation_json(&expected))
        .map_err(|_| service_unavailable(&context))?;
    match commit_scoped_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![insert, guard, audit],
        outbox,
    )
    .await?
    {
        ScopedMutationCommit::Replayed(replay) => return Ok(replay_response(replay)),
        ScopedMutationCommit::Committed => {
            return Ok((StatusCode::CREATED, Json(success.body)).into_response());
        }
        ScopedMutationCommit::Guarded => {}
    }
    // The guard rolled the batch back: no hold was granted.  Either this
    // request already holds one (idempotent replay) or a hard budget refused.
    match repository
        .find_reservation_by_request(&org_id, &request_id)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        Some(existing) if existing.status != "reserved" => {
            Err(reservation_already_reconciled(&context))
        }
        Some(existing)
            if existing.reserved_minor != reserved_minor as i64
                || existing.run_id.as_deref() != run_id.as_deref()
                || existing.budget_id.as_deref() != Some(budget_id.as_str()) =>
        {
            Err(reservation_conflict(&context))
        }
        Some(existing) => Ok((StatusCode::OK, Json(reservation_json(&existing))).into_response()),
        None => {
            record_budget_denial(
                database,
                &context,
                &org_id,
                &device.device_id,
                run_id.as_deref(),
                "budget.denied.v1",
                &budget.budget_id,
                "budget_exceeded",
                &json!({
                    "request_id": request_id,
                    "reserved_minor": reserved_minor,
                    "currency": budget.currency,
                }),
            )
            .await;
            Err(budget_exceeded(&context))
        }
    }
}

/// Machine-only terminal reservation transition.
///
/// Only `reserved -> committed|released|expired` is reachable, the update is
/// conditional on the live hold and its request identity, and a commit above
/// the original hold re-checks the hard budget for the overage.
#[worker::send]
pub async fn reconcile_reservation(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, budget_id, reservation_id)): Path<(String, String, String)>,
    Json(body): Json<ReconcileReservationRequest>,
) -> Result<Response<Body>, ApiError> {
    let device = require_accounting_service(&state, &headers, &context, &org_id).await?;
    let key = idempotency_key(&headers, &context)?;
    let budget_id = validate_prefixed_id(&context, &budget_id, "bud", "budget_id_invalid")?;
    let reservation_id =
        validate_prefixed_id(&context, &reservation_id, "bud", "reservation_id_invalid")?;
    let status = match body.status.trim() {
        "committed" => "committed",
        "released" => "released",
        "expired" => "expired",
        _ => {
            return Err(validation_error(
                &context,
                "reservation_status_invalid",
                "The reservation status is invalid.",
            ));
        }
    };
    let actual_minor = body.actual_minor.unwrap_or_default();
    if actual_minor < 0
        || u64::try_from(actual_minor).map_or(true, |value| value > MAX_SAFE_MONEY_MINOR)
    {
        return Err(validation_error(
            &context,
            "actual_minor_invalid",
            "The reconciled amount is invalid.",
        ));
    }
    if status != "committed" && actual_minor > 0 {
        return Err(validation_error(
            &context,
            "actual_minor_invalid",
            "Only a committed reservation may report an amount.",
        ));
    }
    let database = database(&state, &context)?;
    let repository = BudgetRepository::new(database);
    let existing = repository
        .find_reservation(&org_id, &reservation_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .filter(|row| row.budget_id.as_deref() == Some(budget_id.as_str()))
        .ok_or_else(|| reservation_not_found(&context))?;
    // Bind settlement to the immutable request identity as well as the device;
    // a guessed run ID or a browser-selected reservation cannot settle a hold.
    let inference = repository
        .find_inference_request_scope(&org_id, &existing.request_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| reservation_not_found(&context))?;
    if inference.device_id.as_deref() != Some(device.device_id.as_str())
        || inference.run_id.as_deref() != existing.run_id.as_deref()
    {
        return Err(reservation_not_found(&context));
    }
    // Only the device that owns the correlated run may settle its hold.
    let run = match existing.run_id.as_deref() {
        Some(run_id) => RunRepository::new(database)
            .find_run(&org_id, run_id)
            .await
            .map_err(|_| service_unavailable(&context))?,
        None => None,
    };
    if run
        .as_ref()
        .is_some_and(|run| run.device_id != device.device_id)
    {
        return Err(reservation_not_found(&context));
    }
    if existing.status == status
        && (status != "committed" || existing.committed_minor == Some(actual_minor))
    {
        return Ok((StatusCode::OK, Json(reservation_json(&existing))).into_response());
    }
    if existing.status != "reserved" {
        return Err(reservation_already_reconciled(&context));
    }
    let body_value = json!({
        "reservation_id": reservation_id.clone(),
        "actual_minor": actual_minor,
        "status": status,
    });
    let mutation = prepare_scoped_mutation(
        database,
        &context,
        device.device_id.as_str(),
        &org_id,
        &key,
        "POST",
        RECONCILE_RESERVATION_PATH,
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedScopedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedScopedMutation::Claim(claim) => claim,
    };
    let now =
        canonical_instant(&context.received_at).ok_or_else(|| service_unavailable(&context))?;
    let update = repository
        .reconcile_reservation_statement(&ReservationReconcileInput {
            reservation_id: &reservation_id,
            org_id: &org_id,
            request_id: &existing.request_id,
            reconciled_at: &now,
            committed_minor: (status == "committed").then_some(actual_minor),
            status,
            reason: None,
            budget_id: Some(&budget_id),
        })
        .map_err(|error| database_error(&context, error))?;
    let guard = repository
        .assert_reservation_reconciled_statement(
            &reservation_id,
            &existing.request_id,
            &org_id,
            status,
        )
        .map_err(|error| database_error(&context, error))?;
    let audit = device_audit(
        database,
        &context,
        &org_id,
        &device.device_id,
        existing.run_id.as_deref(),
        "budget.reconciled.v1",
        "budget_reservation",
        &reservation_id,
        "success",
        &json!({
            "status": status,
            "committed_minor": (status == "committed").then_some(actual_minor),
            "reserved_minor": existing.reserved_minor,
            "request_id": existing.request_id,
        }),
    )?;
    let outbox = system_outbox_statement_for_device(
        database,
        &context,
        &org_id,
        "budget.reconciled.v1",
        &device.device_id,
        &json!({
            "reservation_id": reservation_id,
            "request_id": existing.request_id,
            "run_id": existing.run_id,
            "status": status,
        }),
    )?;
    let mut expected = existing.clone();
    expected.status = status.to_owned();
    if status == "committed" {
        expected.committed_minor = Some(actual_minor);
    }
    expected.reconciled_at = Some(now.clone());
    expected.updated_at = now;
    let success = StoredSuccess::new(200, reservation_json(&expected))
        .map_err(|_| service_unavailable(&context))?;
    match commit_scoped_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![update, guard, audit],
        outbox,
    )
    .await?
    {
        ScopedMutationCommit::Replayed(replay) => return Ok(replay_response(replay)),
        ScopedMutationCommit::Committed => {
            return Ok((StatusCode::OK, Json(success.body)).into_response());
        }
        ScopedMutationCommit::Guarded => {}
    }
    // The transition was refused.  Replay the stored projection when it already
    // states this fact, otherwise the hold is still live and the overage no
    // longer fits a hard budget.
    let current = repository
        .find_reservation(&org_id, &reservation_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| reservation_not_found(&context))?;
    if current.status == status && current.committed_minor == expected.committed_minor {
        return Ok((StatusCode::OK, Json(reservation_json(&current))).into_response());
    }
    if current.status == "reserved" {
        record_budget_denial(
            database,
            &context,
            &org_id,
            &device.device_id,
            current.run_id.as_deref(),
            "budget.denied.v1",
            &budget_id,
            "budget_exceeded",
            &json!({
                "reservation_id": reservation_id,
                "status": status,
                "committed_minor": actual_minor,
            }),
        )
        .await;
        return Err(budget_exceeded(&context));
    }
    Err(reservation_already_reconciled(&context))
}

/// `budgets.read` rate/concurrency policy collection.
#[worker::send]
pub async fn list_rate_limits(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<RateLimitListQuery>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::BudgetsRead,
        Some("rate_limit_policy"),
        None,
    )
    .await?;
    let limit = page_limit(query.limit);
    let cursor = query
        .cursor
        .as_deref()
        .map(|raw| decode_page_cursor(raw, &context))
        .transpose()?;
    if let Some(scope_type) = query.scope_type.as_deref() {
        parse_scope_type(&context, scope_type)?;
    }
    let database = database(&state, &context)?;
    let mut records = BudgetRepository::new(database)
        .list_rate_limit_policies(
            &org_id,
            query.scope_type.as_deref(),
            scope_id_filter(query.scope_id.as_deref()),
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
            .map(|record| encode_page_cursor(&record.updated_at, &record.rate_limit_policy_id))
    } else {
        None
    };
    Ok((
        StatusCode::OK,
        Json(PageResponse {
            items: records.iter().map(rate_limit_json).collect::<Vec<_>>(),
            next_cursor,
            has_more,
        }),
    )
        .into_response())
}

/// `budgets.manage` create-or-update of one scoped rate/concurrency policy.
///
/// The unique scope index makes the write a single atomic upsert, and the
/// version guard rejects a stale overwrite.  An organization policy is
/// addressed as `rate-limits/organization/{org_id}` and stored with a NULL
/// scope ID, because the frozen route always carries a scope segment.
#[worker::send]
pub async fn put_rate_limit(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, scope_type, scope_id)): Path<(String, String, String)>,
    Json(body): Json<PutRateLimitRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::BudgetsManage,
        Some("rate_limit_policy"),
        Some(&scope_type),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    if body.version < 0 {
        return Err(validation_error(
            &context,
            "version_invalid",
            "The resource version is invalid.",
        ));
    }
    let scope = parse_scope_type(&context, &scope_type)?;
    if !ADDRESSABLE_RATE_SCOPES.contains(&scope.as_str()) {
        return Err(validation_error(
            &context,
            "scope_type_invalid",
            "Choose a valid rate limit scope type.",
        ));
    }
    let stored_scope_id = if scope == ScopeType::Organization {
        if scope_id.trim() != org_id {
            return Err(validation_error(
                &context,
                "scope_id_invalid",
                "An organization rate limit is addressed by its organization ID.",
            ));
        }
        None
    } else {
        Some(validate_scope_id(&context, &scope_id)?)
    };
    if BudgetScope::new(scope, &org_id, stored_scope_id.clone()).is_err() {
        return Err(validation_error(
            &context,
            "scope_id_invalid",
            "The rate limit scope is invalid.",
        ));
    }
    let database = database(&state, &context)?;
    ensure_scope_resource(
        database,
        &context,
        &org_id,
        scope,
        stored_scope_id.as_deref(),
    )
    .await?;
    for (value, reason) in [
        (body.requests_per_minute, "requests_per_minute_invalid"),
        (body.tokens_per_minute, "tokens_per_minute_invalid"),
        (
            body.max_concurrent_requests,
            "max_concurrent_requests_invalid",
        ),
    ] {
        if value.is_some_and(|value| value <= 0) {
            return Err(validation_error(
                &context,
                reason,
                "The rate limit is invalid.",
            ));
        }
    }
    if body.requests_per_minute.is_none()
        && body.tokens_per_minute.is_none()
        && body.max_concurrent_requests.is_none()
    {
        return Err(validation_error(
            &context,
            "rate_limit_empty",
            "Set at least one rate limit.",
        ));
    }
    let repository = BudgetRepository::new(database);
    let existing = repository
        .find_rate_limit_policy(&org_id, scope.as_str(), stored_scope_id.as_deref())
        .await
        .map_err(|error| database_error(&context, error))?;
    let expected_version = match (existing.as_ref(), body.version) {
        (Some(current), version) if version == current.version => Some(current.version),
        (None, 0) => None,
        _ => return Err(version_conflict(&context)),
    };
    let now =
        canonical_instant(&context.received_at).ok_or_else(|| service_unavailable(&context))?;
    let mutation = prepare_scoped_mutation(
        database,
        &context,
        access.principal.user_id.as_str(),
        &org_id,
        &key,
        "PUT",
        RATE_LIMIT_PATH,
        &json!({
            "scope_type": scope.as_str(),
            "scope_id": stored_scope_id,
            "version": body.version,
            "requests_per_minute": body.requests_per_minute,
            "tokens_per_minute": body.tokens_per_minute,
            "max_concurrent_requests": body.max_concurrent_requests,
        }),
    )
    .await?;
    let claim = match mutation {
        PreparedScopedMutation::Replay(success) => {
            let _ =
                crate::routes::devices::refresh_policy_snapshot(database, &context, &org_id, None)
                    .await;
            return Ok(replay_response(success));
        }
        PreparedScopedMutation::Claim(claim) => claim,
    };
    let policy_id = existing.as_ref().map_or_else(
        || generated_id("rlp"),
        |current| current.rate_limit_policy_id.clone(),
    );
    let guard = match expected_version {
        Some(version) => repository
            .assert_rate_limit_version_statement(&policy_id, &org_id, version)
            .map_err(|error| database_error(&context, error))?,
        None => repository
            .assert_rate_limit_absent_statement(&org_id, scope.as_str(), stored_scope_id.as_deref())
            .map_err(|error| database_error(&context, error))?,
    };
    let upsert = repository
        .upsert_rate_limit_policy_statement(&UpsertRateLimitInput {
            rate_limit_policy_id: &policy_id,
            org_id: &org_id,
            scope_type: scope.as_str(),
            scope_id: stored_scope_id.as_deref(),
            requests_per_minute: body.requests_per_minute,
            tokens_per_minute: body.tokens_per_minute,
            max_concurrent_requests: body.max_concurrent_requests,
            created_by_user_id: access.principal.user_id.as_str(),
            now: &now,
            expected_version,
        })
        .map_err(|error| database_error(&context, error))?;
    let audit = security_event_statement_with_context(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        &generated_id("sec"),
        "rate_limit_policy.updated.v1",
        "rate_limit_policy",
        Some(&policy_id),
        "success",
        &json!({
            "scope_type": scope.as_str(),
            "scope_id": stored_scope_id,
            "requests_per_minute": body.requests_per_minute,
            "tokens_per_minute": body.tokens_per_minute,
            "max_concurrent_requests": body.max_concurrent_requests,
        }),
        None,
        None,
        None,
        None,
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "rate_limit_policy.updated.v1",
        &json!({
            "rate_limit_policy_id": policy_id,
            "scope_type": scope.as_str(),
            "scope_id": stored_scope_id,
        }),
    )?;
    let record = match existing {
        Some(current) => RateLimitPolicyRecord {
            requests_per_minute: body.requests_per_minute,
            tokens_per_minute: body.tokens_per_minute,
            max_concurrent_requests: body.max_concurrent_requests,
            version: current.version + 1,
            updated_at: now.clone(),
            ..current
        },
        None => RateLimitPolicyRecord {
            rate_limit_policy_id: policy_id.clone(),
            org_id: org_id.clone(),
            scope_type: scope.as_str().to_owned(),
            scope_id: stored_scope_id.clone(),
            requests_per_minute: body.requests_per_minute,
            tokens_per_minute: body.tokens_per_minute,
            max_concurrent_requests: body.max_concurrent_requests,
            version: 1,
            created_by_user_id: access.principal.user_id.as_str().to_owned(),
            created_at: now.clone(),
            updated_at: now.clone(),
        },
    };
    let success = StoredSuccess::new(200, rate_limit_json(&record))
        .map_err(|_| service_unavailable(&context))?;
    match commit_scoped_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![guard, upsert, audit],
        outbox,
    )
    .await?
    {
        ScopedMutationCommit::Replayed(replay) => return Ok(replay_response(replay)),
        ScopedMutationCommit::Committed => {
            let _ =
                crate::routes::devices::refresh_policy_snapshot(database, &context, &org_id, None)
                    .await;
            return Ok((StatusCode::OK, Json(success.body)).into_response());
        }
        ScopedMutationCommit::Guarded => return Err(version_conflict(&context)),
    }
}

/// Compatibility entry point for the coordinator's shared router name.
#[worker::send]
pub async fn update_budget(
    state: State<Arc<AppState>>,
    context: Extension<RequestContext>,
    headers: HeaderMap,
    path: Path<(String, String)>,
    body: Json<PatchBudgetRequest>,
) -> Result<Response<Body>, ApiError> {
    patch_budget(state, context, headers, path, body).await
}

/// Compatibility entry point for the coordinator's shared router name.
#[worker::send]
pub async fn update_rate_limit(
    state: State<Arc<AppState>>,
    context: Extension<RequestContext>,
    headers: HeaderMap,
    path: Path<(String, String, String)>,
    body: Json<PutRateLimitRequest>,
) -> Result<Response<Body>, ApiError> {
    put_rate_limit(state, context, headers, path, body).await
}

/// Append an immutable denial record for a blocked dispatch.  The denial is the
/// safe outcome, so a secondary write failure must not change the response; the
/// row carries only bounded, non-sensitive metadata.
#[allow(clippy::too_many_arguments)]
async fn record_budget_denial(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    org_id: &str,
    device_id: &str,
    run_id: Option<&str>,
    action: &str,
    resource_id: &str,
    reason: &str,
    metadata: &Value,
) {
    if let (Ok(audit), Ok(outbox)) = (
        security_event_statement_with_context(
            database,
            context,
            None,
            Some(org_id),
            &generated_id("sec"),
            action,
            "budget",
            Some(resource_id),
            "denied",
            &json!({ "reason": reason, "details": metadata.clone() }),
            Some(device_id),
            run_id,
            None,
            None,
        ),
        system_outbox_statement_for_device(
            database,
            context,
            org_id,
            action,
            device_id,
            &json!({
                "resource_id": resource_id,
                "run_id": run_id,
                "reason": reason,
                "details": metadata.clone(),
            }),
        ),
    ) {
        let _ = database.batch(vec![audit, outbox]).await;
    }
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
    fn instants_normalize_to_comparable_millisecond_text() {
        let parse = |value: &str| canonical_instant(&Timestamp::new(value).unwrap()).unwrap();
        assert_eq!(parse("2026-09-25T12:00:00Z"), "2026-09-25T12:00:00.000Z");
        assert_eq!(parse("2026-09-25T12:00:00.5Z"), "2026-09-25T12:00:00.500Z");
        assert_eq!(
            parse("2026-09-25T12:00:00.500Z"),
            "2026-09-25T12:00:00.500Z"
        );
        // Ordering must hold across the mixed-precision forms, otherwise a
        // budget period or reservation expiry would compare incorrectly.
        assert!(parse("2026-09-25T12:00:00Z") < parse("2026-09-25T12:00:01Z"));
        assert!(parse("2026-09-25T12:00:00.250Z") < parse("2026-09-25T12:00:00.500Z"));
    }

    #[test]
    fn budget_denials_keep_the_frozen_p04_status_mapping() {
        let error = budget_exceeded(&context());
        assert_eq!(error.error.code, ApiErrorCode::PermissionDenied);
        assert_eq!(
            error.error.details.get("reason"),
            Some(&json!("budget_exceeded"))
        );
    }

    #[test]
    fn an_unreadable_budget_state_fails_closed() {
        let error = budget_state_unavailable(&context());
        assert_eq!(error.error.code, ApiErrorCode::ServiceUnavailable);
        assert_eq!(
            error.error.details.get("reason"),
            Some(&json!("budget_state_unavailable"))
        );
    }

    #[test]
    fn reservation_failures_have_stable_reasons() {
        for (error, reason) in [
            (
                reservation_already_reconciled(&context()),
                "reservation_already_reconciled",
            ),
            (reservation_conflict(&context()), "reservation_conflict"),
            (reservation_not_found(&context()), "reservation_not_found"),
        ] {
            assert_eq!(error.error.details.get("reason"), Some(&json!(reason)));
        }
    }

    #[test]
    fn only_an_organization_scope_may_omit_its_scope_id() {
        let context = context();
        let org = "org_0123456789abcdef0123456789abcdef";
        assert!(validate_budget_scope(&context, org, "organization", None).is_ok());
        assert!(validate_budget_scope(&context, org, "organization", Some("prj_1")).is_err());
        assert!(validate_budget_scope(&context, org, "project", None).is_err());
        assert!(validate_budget_scope(&context, org, "project", Some("prj_1")).is_ok());
        assert!(validate_budget_scope(&context, org, "team", Some("tmem_1")).is_err());
    }
}
