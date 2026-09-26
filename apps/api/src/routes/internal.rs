//! P07 platform-operations HTTP surface (P07-BE-03).
//!
//! # Route surface (all under `/api/v1`)
//!
//! | Method | Path | StaffPermission |
//! |---|---|---|
//! | GET | `/internal/feature-flags` | `feature_flag.read` |
//! | POST | `/internal/feature-flags` | `feature_flag.manage` |
//! | PATCH | `/internal/feature-flags/{flag_key}` | `feature_flag.manage` |
//! | GET | `/internal/kill-switches` | `kill_switch.read` |
//! | POST | `/internal/kill-switches` | `kill_switch.operate` |
//! | POST | `/internal/kill-switches/{kill_switch_id}/lift` | `kill_switch.operate` |
//! | GET | `/internal/support-grants` | `support_grant.revoke` |
//! | POST | `/internal/support-grants` | `support_grant.create` |
//! | POST | `/internal/support-grants/{grant_id}/revoke` | `support_grant.revoke` |
//!
//! # Why this file cannot be reached by a customer
//!
//! Every handler calls `require_staff` first. There is no `authorize_org` call
//! anywhere in this module, and there is no path that accepts a `Principal`. An
//! organization session is therefore refused here as a staff authentication
//! failure, and an API key is refused as a staff authentication failure — not
//! reinterpreted, because `lumi_staff_` and `lumik_` cannot parse as one another.
//!
//! # Grants are created and revoked here, and consumed nowhere
//!
//! That is deliberate and it is the strongest statement in F24-003. No route in
//! P07 accepts a grant, resolves a `Principal` from one, or impersonates anyone.
//! The audit trail is written on issuance and on revocation, so a future support
//! console that DOES consume grants inherits the boundary rather than inventing
//! it.

use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    adapters::{add_seconds, new_resource_id},
    app::AppState,
    core::{ApiError, ApiErrorCode, OrganizationId, RequestContext},
    http::auth::require_staff,
    modules::{
        rollouts::{
            FlagCohort, FlagError, KillSwitchError, KillSwitchScope, KillSwitchTargetClass,
            validate_flag_input, validate_kill_switch_input,
        },
        staff::{
            MAX_SUPPORT_GRANT_TTL_SECONDS, StaffDenyReason, StaffPermission, StaffRequest,
            authorize_staff, validate_grant_input,
        },
    },
    repositories::{
        FeatureFlagUpdateInput, NewFeatureFlagInput, NewKillSwitchInput, NewSupportGrantInput,
        PlatformOperationsRepository, staff_capabilities_json,
    },
    routes::{
        agents::replay_response,
        errors,
        support::{database, domain_error, idempotency_key},
        usage::{
            PreparedScopedMutation, ScopedMutationCommit, commit_scoped_mutation,
            prepare_scoped_mutation,
        },
    },
};

pub const FLAG_CREATE_PATH: &str = "/api/v1/internal/feature-flags";
pub const FLAG_PATCH_PATH: &str = "/api/v1/internal/feature-flags/{flag_key}";
pub const KILL_SWITCH_CREATE_PATH: &str = "/api/v1/internal/kill-switches";
pub const KILL_SWITCH_LIFT_PATH: &str = "/api/v1/internal/kill-switches/{kill_switch_id}/lift";
pub const GRANT_CREATE_PATH: &str = "/api/v1/internal/support-grants";
pub const GRANT_REVOKE_PATH: &str = "/api/v1/internal/support-grants/{grant_id}/revoke";

// ------------------------------------------------------------- requests ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateFlagBody {
    pub flag_key: String,
    pub enabled: Option<bool>,
    pub rollout_percentage: Option<i64>,
    pub org_allowlist: Option<Vec<String>>,
    pub cohort: Option<String>,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchFlagBody {
    pub version: i64,
    pub enabled: Option<bool>,
    pub rollout_percentage: Option<i64>,
    pub org_allowlist: Option<Vec<String>>,
    pub cohort: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateKillSwitchBody {
    pub target_class: String,
    pub target_ref: String,
    pub scope: String,
    pub organization_id: Option<String>,
    pub reason: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiftKillSwitchBody {
    pub version: i64,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateGrantBody {
    pub organization_id: String,
    pub reason: String,
    pub ticket_reference: String,
    pub ttl_seconds: u32,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeGrantBody {
    pub version: i64,
    pub reason: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ListQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
}

// ---------------------------------------------------------- projections ----

fn flag_json(record: &crate::repositories::FeatureFlagRecord) -> Value {
    json!({
        "flag_key": record.flag_key,
        "enabled": record.enabled != 0,
        "rollout_percentage": record.rollout_percentage,
        "org_allowlist": serde_json::from_str::<Value>(&record.org_allowlist_json)
            .unwrap_or(Value::Array(Vec::new())),
        "cohort": record.cohort,
        // F24-006: an expiry is mandatory, and an expired flag resolves off. The
        // response carries the value so an operator can see WHY.
        "expires_at": record.expires_at,
        "owner_staff_principal_id": record.owner_staff_principal_id,
        "updated_by": record.updated_by,
        "version": record.version,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    })
}

fn kill_switch_json(record: &crate::repositories::KillSwitchRecord) -> Value {
    json!({
        "kill_switch_id": record.kill_switch_id,
        "target_class": record.target_class,
        "target_ref": record.target_ref,
        "scope": record.scope,
        "organization_id": record.organization_id,
        "reason": record.reason,
        "engaged_by_staff_principal_id": record.engaged_by_staff_principal_id,
        "engaged_at": record.engaged_at,
        "expires_at": record.expires_at,
        "state": record.state,
        "lifted_at": record.lifted_at,
        "lifted_by": record.lifted_by,
        "lift_reason": record.lift_reason,
        "version": record.version,
    })
}

fn grant_json(record: &crate::repositories::SupportGrantRecord) -> Value {
    json!({
        "grant_id": record.grant_id,
        "staff_principal_id": record.staff_principal_id,
        "organization_id": record.organization_id,
        "reason": record.reason,
        "ticket_reference": record.ticket_reference,
        "capabilities": serde_json::from_str::<Value>(&record.capabilities_json)
            .unwrap_or(Value::Array(Vec::new())),
        "issued_at": record.issued_at,
        "expires_at": record.expires_at,
        "revoked_at": record.revoked_at,
        "revoke_reason": record.revoke_reason,
        "version": record.version,
    })
}

// ------------------------------------------------------------- handlers ----

#[worker::send]
pub async fn list_flags(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Response<Body>, ApiError> {
    authorize_staff_route(&state, &headers, &context, StaffPermission::FeatureFlagRead).await?;
    let database = database(&state, &context)?;
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let mut rows = PlatformOperationsRepository::new(database)
        .list_flags(query.cursor.as_deref(), limit + 1)
        .await
        .map_err(|_| store_unavailable(&context))?;
    let has_more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next = if has_more {
        rows.last().map(|row| row.flag_key.clone())
    } else {
        None
    };
    Ok(json_response(json!({
        "items": rows.iter().map(flag_json).collect::<Vec<_>>(),
        "page": { "limit": limit, "next_cursor": next },
    })))
}

#[worker::send]
pub async fn create_flag(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<CreateFlagBody>,
) -> Result<Response<Body>, ApiError> {
    let staff = authorize_staff_route(
        &state,
        &headers,
        &context,
        StaffPermission::FeatureFlagManage,
    )
    .await?;
    let database = database(&state, &context)?;
    validate_flag_input(
        &body.flag_key,
        body.rollout_percentage.unwrap_or(0),
        Some(body.expires_at.as_str()),
    )
    .map_err(|error| flag_error(&context, error))?;
    let allowlist = allowlist_json(body.org_allowlist.as_deref(), &context)?;
    let cohort = match body.cohort.as_deref() {
        Some(value) => FlagCohort::parse(value).ok_or_else(|| invalid_input(&context))?,
        None => FlagCohort::None,
    }
    .as_str();
    let idempotency = idempotency_key(&headers, &context)?;
    let claim = match prepare_scoped_mutation(
        database,
        &context,
        staff.actor.staff_principal_id.as_str(),
        "",
        &idempotency,
        "POST",
        FLAG_CREATE_PATH,
        &json!({ "flag_key": body.flag_key, "expires_at": body.expires_at }),
    )
    .await?
    {
        PreparedScopedMutation::Replay(replay) => return Ok(replay_response(replay)),
        PreparedScopedMutation::Claim(claim) => claim,
    };
    let now = context.received_at.clone();
    let insert = PlatformOperationsRepository::new(database)
        .insert_flag_statement(&NewFeatureFlagInput {
            flag_key: &body.flag_key,
            enabled: body.enabled.unwrap_or(false),
            rollout_percentage: body.rollout_percentage.unwrap_or(0),
            org_allowlist_json: &allowlist,
            cohort,
            expires_at: &body.expires_at,
            owner_staff_principal_id: staff.actor.staff_principal_id.as_str(),
            now: now.as_str(),
        })
        .map_err(|_| store_unavailable(&context))?;
    let audit = staff_audit(
        database,
        &context,
        staff.actor.staff_principal_id.as_str(),
        "feature_flag.created",
        "feature_flag",
        Some(&body.flag_key),
        &json!({ "expires_at": body.expires_at }),
    )?;
    let success = crate::core::StoredSuccess::new(
        StatusCode::CREATED.as_u16(),
        json!({ "flag_key": body.flag_key }),
    )
    .map_err(|_| store_unavailable(&context))?;
    match commit_scoped_mutation(database, &context, claim, success, vec![insert], audit).await? {
        ScopedMutationCommit::Committed => {}
        ScopedMutationCommit::Replayed(replay) => return Ok(replay_response(replay)),
        ScopedMutationCommit::Guarded => {
            return Err(domain_error(
                &context,
                ApiErrorCode::Conflict,
                "conflict",
                "The request conflicts with current state.",
            ));
        }
    }
    let created = PlatformOperationsRepository::new(database)
        .find_flag(&body.flag_key)
        .await
        .map_err(|_| store_unavailable(&context))?
        .ok_or_else(|| store_unavailable(&context))?;
    Ok(json_response(
        json!({ "feature_flag": flag_json(&created) }),
    ))
}

#[worker::send]
pub async fn patch_flag(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((flag_key,)): Path<(String,)>,
    Json(body): Json<PatchFlagBody>,
) -> Result<Response<Body>, ApiError> {
    let staff = authorize_staff_route(
        &state,
        &headers,
        &context,
        StaffPermission::FeatureFlagManage,
    )
    .await?;
    let database = database(&state, &context)?;
    let repository = PlatformOperationsRepository::new(database);
    let current = repository
        .find_flag(&flag_key)
        .await
        .map_err(|_| store_unavailable(&context))?
        .ok_or_else(|| not_found(&context))?;
    let expires_at = body
        .expires_at
        .clone()
        .unwrap_or(current.expires_at.clone());
    let rollout = body
        .rollout_percentage
        .unwrap_or(current.rollout_percentage);
    validate_flag_input(&flag_key, rollout, Some(expires_at.as_str()))
        .map_err(|error| flag_error(&context, error))?;
    let allowlist = match body.org_allowlist.as_deref() {
        Some(values) => allowlist_json(Some(values), &context)?,
        None => current.org_allowlist_json.clone(),
    };
    let cohort = match body.cohort.as_deref() {
        Some(value) => FlagCohort::parse(value)
            .ok_or_else(|| invalid_input(&context))?
            .as_str(),
        None => current.cohort.as_str(),
    };
    let idempotency = idempotency_key(&headers, &context)?;
    let claim = match prepare_scoped_mutation(
        database,
        &context,
        staff.actor.staff_principal_id.as_str(),
        "",
        &idempotency,
        "PATCH",
        FLAG_PATCH_PATH,
        &json!({ "flag_key": flag_key, "version": body.version }),
    )
    .await?
    {
        PreparedScopedMutation::Replay(replay) => return Ok(replay_response(replay)),
        PreparedScopedMutation::Claim(claim) => claim,
    };
    let now = context.received_at.clone();
    let update = repository
        .update_flag_statement(&FeatureFlagUpdateInput {
            flag_key: &flag_key,
            enabled: body.enabled.unwrap_or(current.enabled != 0),
            rollout_percentage: rollout,
            org_allowlist_json: &allowlist,
            cohort,
            expires_at: &expires_at,
            owner_staff_principal_id: staff.actor.staff_principal_id.as_str(),
            updated_by: staff.actor.staff_principal_id.as_str(),
            expected_version: body.version,
            now: now.as_str(),
        })
        .map_err(|_| store_unavailable(&context))?;
    let guard = repository
        .assert_flag_version_statement(&flag_key, body.version)
        .map_err(|_| store_unavailable(&context))?;
    let audit = staff_audit(
        database,
        &context,
        staff.actor.staff_principal_id.as_str(),
        "feature_flag.updated",
        "feature_flag",
        Some(&flag_key),
        &json!({ "version": body.version, "expires_at": expires_at }),
    )?;
    let success =
        crate::core::StoredSuccess::new(StatusCode::OK.as_u16(), json!({ "flag_key": flag_key }))
            .map_err(|_| store_unavailable(&context))?;
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
        ScopedMutationCommit::Committed => {}
        ScopedMutationCommit::Replayed(replay) => return Ok(replay_response(replay)),
        ScopedMutationCommit::Guarded => {
            return Err(domain_error(
                &context,
                ApiErrorCode::Conflict,
                "version_conflict",
                "The feature flag changed. Refresh and try again.",
            ));
        }
    }
    let updated = repository
        .find_flag(&flag_key)
        .await
        .map_err(|_| store_unavailable(&context))?
        .ok_or_else(|| store_unavailable(&context))?;
    Ok(json_response(
        json!({ "feature_flag": flag_json(&updated) }),
    ))
}

#[worker::send]
pub async fn list_kill_switches(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Response<Body>, ApiError> {
    authorize_staff_route(&state, &headers, &context, StaffPermission::KillSwitchRead).await?;
    let database = database(&state, &context)?;
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let (created_at, id) = decode_cursor(query.cursor.as_deref(), &context)?;
    let mut rows = PlatformOperationsRepository::new(database)
        .list_kill_switches(created_at.as_deref(), id.as_deref(), limit + 1)
        .await
        .map_err(|_| store_unavailable(&context))?;
    let has_more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next = if has_more {
        rows.last()
            .map(|row| format!("{}|{}", row.created_at, row.kill_switch_id))
    } else {
        None
    };
    Ok(json_response(json!({
        "items": rows.iter().map(kill_switch_json).collect::<Vec<_>>(),
        "page": { "limit": limit, "next_cursor": next },
    })))
}

#[worker::send]
pub async fn create_kill_switch(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<CreateKillSwitchBody>,
) -> Result<Response<Body>, ApiError> {
    let staff = authorize_staff_route(
        &state,
        &headers,
        &context,
        StaffPermission::KillSwitchOperate,
    )
    .await?;
    let database = database(&state, &context)?;
    let target_class = KillSwitchTargetClass::parse(&body.target_class)
        .ok_or_else(|| kill_switch_error(&context, KillSwitchError::TargetUnknown))?;
    let scope = KillSwitchScope::parse(&body.scope)
        .ok_or_else(|| kill_switch_error(&context, KillSwitchError::ScopeOrganizationMismatch))?;
    let organization = match &body.organization_id {
        Some(value) => {
            Some(OrganizationId::new(value.as_str()).map_err(|_| invalid_input(&context))?)
        }
        None => None,
    };
    validate_kill_switch_input(
        target_class,
        &body.target_ref,
        scope,
        organization.as_ref(),
        &body.reason,
        body.expires_at.as_deref(),
    )
    .map_err(|error| kill_switch_error(&context, error))?;
    // An expiry must be in the future, or the switch is born dead while looking
    // engaged in a list.
    if let Some(expiry) = body.expires_at.as_deref()
        && expiry <= context.received_at.as_str()
    {
        return Err(kill_switch_error(&context, KillSwitchError::InvalidExpiry));
    }
    let idempotency = idempotency_key(&headers, &context)?;
    let kill_switch_id = new_resource_id("ksw").as_str().to_owned();
    let claim = match prepare_scoped_mutation(
        database,
        &context,
        staff.actor.staff_principal_id.as_str(),
        "",
        &idempotency,
        "POST",
        KILL_SWITCH_CREATE_PATH,
        &json!({ "target_class": body.target_class, "target_ref": body.target_ref, "scope": body.scope }),
    )
    .await?
    {
        PreparedScopedMutation::Replay(replay) => return Ok(replay_response(replay)),
        PreparedScopedMutation::Claim(claim) => claim,
    };
    let now = context.received_at.clone();
    let insert = PlatformOperationsRepository::new(database)
        .insert_kill_switch_statement(&NewKillSwitchInput {
            kill_switch_id: &kill_switch_id,
            target_class: target_class.as_str(),
            target_ref: &body.target_ref,
            scope: scope.as_str(),
            organization_id: organization.as_ref().map(|id| id.as_str()),
            reason: &body.reason,
            engaged_by_staff_principal_id: staff.actor.staff_principal_id.as_str(),
            engaged_at: now.as_str(),
            expires_at: body.expires_at.as_deref(),
        })
        .map_err(|_| store_unavailable(&context))?;
    let audit = staff_audit(
        database,
        &context,
        staff.actor.staff_principal_id.as_str(),
        "kill_switch.engaged",
        "kill_switch",
        Some(&kill_switch_id),
        &json!({
            "target_class": target_class.as_str(),
            "target_ref": body.target_ref,
            "scope": scope.as_str(),
            "organization_id": body.organization_id,
            "reason": body.reason,
        }),
    )?;
    let success = crate::core::StoredSuccess::new(
        StatusCode::CREATED.as_u16(),
        json!({ "kill_switch_id": kill_switch_id }),
    )
    .map_err(|_| store_unavailable(&context))?;
    match commit_scoped_mutation(database, &context, claim, success, vec![insert], audit).await? {
        ScopedMutationCommit::Committed => {}
        ScopedMutationCommit::Replayed(replay) => return Ok(replay_response(replay)),
        ScopedMutationCommit::Guarded => {
            return Err(kill_switch_error(
                &context,
                KillSwitchError::ScopeOrganizationMismatch,
            ));
        }
    }
    let created = PlatformOperationsRepository::new(database)
        .find_kill_switch(&kill_switch_id)
        .await
        .map_err(|_| store_unavailable(&context))?
        .ok_or_else(|| store_unavailable(&context))?;
    Ok(json_response(
        json!({ "kill_switch": kill_switch_json(&created) }),
    ))
}

#[worker::send]
pub async fn lift_kill_switch(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((kill_switch_id,)): Path<(String,)>,
    Json(body): Json<LiftKillSwitchBody>,
) -> Result<Response<Body>, ApiError> {
    let staff = authorize_staff_route(
        &state,
        &headers,
        &context,
        StaffPermission::KillSwitchOperate,
    )
    .await?;
    let database = database(&state, &context)?;
    if body.reason.trim().is_empty() || body.reason.len() > 500 {
        return Err(invalid_input(&context));
    }
    let repository = PlatformOperationsRepository::new(database);
    let now = context.received_at.clone();
    let idempotency = idempotency_key(&headers, &context)?;
    let claim = match prepare_scoped_mutation(
        database,
        &context,
        staff.actor.staff_principal_id.as_str(),
        "",
        &idempotency,
        "POST",
        KILL_SWITCH_LIFT_PATH,
        &json!({ "kill_switch_id": kill_switch_id, "version": body.version, "reason": body.reason }),
    )
    .await?
    {
        PreparedScopedMutation::Replay(replay) => return Ok(replay_response(replay)),
        PreparedScopedMutation::Claim(claim) => claim,
    };
    let lift = repository
        .lift_kill_switch_statement(
            &kill_switch_id,
            body.version,
            staff.actor.staff_principal_id.as_str(),
            &body.reason,
            &now,
        )
        .map_err(|_| store_unavailable(&context))?;
    let guard = repository
        .assert_kill_switch_version_statement(&kill_switch_id, body.version)
        .map_err(|_| store_unavailable(&context))?;
    // The lift is its own audited event, and the engage row is never deleted.
    let audit = staff_audit(
        database,
        &context,
        staff.actor.staff_principal_id.as_str(),
        "kill_switch.lifted",
        "kill_switch",
        Some(&kill_switch_id),
        &json!({ "reason": body.reason, "version": body.version }),
    )?;
    let success = crate::core::StoredSuccess::new(
        StatusCode::OK.as_u16(),
        json!({ "kill_switch_id": kill_switch_id }),
    )
    .map_err(|_| store_unavailable(&context))?;
    match commit_scoped_mutation(database, &context, claim, success, vec![lift, guard], audit)
        .await?
    {
        ScopedMutationCommit::Committed => {}
        ScopedMutationCommit::Replayed(replay) => return Ok(replay_response(replay)),
        ScopedMutationCommit::Guarded => {
            return Err(domain_error(
                &context,
                ApiErrorCode::Conflict,
                "version_conflict",
                "The kill switch changed. Refresh and try again.",
            ));
        }
    }
    let lifted = repository
        .find_kill_switch(&kill_switch_id)
        .await
        .map_err(|_| store_unavailable(&context))?
        .ok_or_else(|| store_unavailable(&context))?;
    Ok(json_response(
        json!({ "kill_switch": kill_switch_json(&lifted) }),
    ))
}

#[worker::send]
pub async fn list_grants(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Response<Body>, ApiError> {
    // `support_grant.revoke` reads the grant list, which is the same authority:
    // whoever may end an access may see what access exists.
    authorize_staff_route(
        &state,
        &headers,
        &context,
        StaffPermission::SupportGrantRevoke,
    )
    .await?;
    let database = database(&state, &context)?;
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let (issued_at, id) = decode_cursor(query.cursor.as_deref(), &context)?;
    let mut rows = PlatformOperationsRepository::new(database)
        .list_grants(issued_at.as_deref(), id.as_deref(), limit + 1)
        .await
        .map_err(|_| store_unavailable(&context))?;
    let has_more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next = if has_more {
        rows.last()
            .map(|row| format!("{}|{}", row.issued_at, row.grant_id))
    } else {
        None
    };
    Ok(json_response(json!({
        "items": rows.iter().map(grant_json).collect::<Vec<_>>(),
        "page": { "limit": limit, "next_cursor": next },
        "max_ttl_seconds": MAX_SUPPORT_GRANT_TTL_SECONDS,
    })))
}

#[worker::send]
pub async fn create_grant(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<CreateGrantBody>,
) -> Result<Response<Body>, ApiError> {
    let staff = authorize_staff_route(
        &state,
        &headers,
        &context,
        StaffPermission::SupportGrantCreate,
    )
    .await?;
    let database = database(&state, &context)?;
    let organization =
        OrganizationId::new(body.organization_id.as_str()).map_err(|_| invalid_input(&context))?;
    // Every role may create a grant, and the issuer's own role bounds what the
    // grant may contain. A grant is a subset, so this is the same check the
    // decision path would apply, run before the write.
    validate_grant_input(
        &body.reason,
        &body.ticket_reference,
        body.ttl_seconds,
        &parse_capabilities(&body.capabilities, &context)?,
        staff.staff_role,
    )
    .map_err(|error| staff_error(&context, error))?;
    let capabilities = parse_capabilities(&body.capabilities, &context)?;
    let capabilities_json = staff_capabilities_json(&capabilities);
    let issued_at = context.received_at.clone();
    let expires_at =
        add_seconds(&issued_at, body.ttl_seconds).map_err(|_| invalid_input(&context))?;
    let idempotency = idempotency_key(&headers, &context)?;
    let grant_id = new_resource_id("sgr").as_str().to_owned();
    let claim = match prepare_scoped_mutation(
        database,
        &context,
        staff.actor.staff_principal_id.as_str(),
        organization.as_str(),
        &idempotency,
        "POST",
        GRANT_CREATE_PATH,
        &json!({
            "organization_id": organization.as_str(),
            "reason": body.reason,
            "ticket_reference": body.ticket_reference,
            "ttl_seconds": body.ttl_seconds,
        }),
    )
    .await?
    {
        PreparedScopedMutation::Replay(replay) => return Ok(replay_response(replay)),
        PreparedScopedMutation::Claim(claim) => claim,
    };
    let insert = PlatformOperationsRepository::new(database)
        .insert_grant_statement(&NewSupportGrantInput {
            grant_id: &grant_id,
            staff_principal_id: staff.actor.staff_principal_id.as_str(),
            organization_id: organization.as_str(),
            reason: &body.reason,
            ticket_reference: &body.ticket_reference,
            capabilities_json: &capabilities_json,
            issued_at: issued_at.as_str(),
            expires_at: expires_at.as_str(),
        })
        .map_err(|_| store_unavailable(&context))?;
    // F24-003: a grant creates a CUSTOMER-VISIBLE event, not only a platform one.
    // The customer's own audit view is what makes a support session
    // reconstructable without trusting platform logs, so the row is written with
    // the organization's scope.
    let audit = crate::routes::support::security_event_statement(
        database,
        &context,
        None,
        Some(organization.as_str()),
        crate::adapters::new_event_id().as_str(),
        "support_grant.issued",
        "support_grant",
        Some(&grant_id),
        "success",
        &json!({
            "staff_principal_id": staff.actor.staff_principal_id.as_str(),
            "reason": body.reason,
            "ticket_reference": body.ticket_reference,
            "expires_at": expires_at.as_str(),
            "capabilities": capabilities_json,
        }),
    )?;
    let success = crate::core::StoredSuccess::new(
        StatusCode::CREATED.as_u16(),
        json!({ "grant_id": grant_id, "expires_at": expires_at.as_str() }),
    )
    .map_err(|_| store_unavailable(&context))?;
    match commit_scoped_mutation(database, &context, claim, success, vec![insert], audit).await? {
        ScopedMutationCommit::Committed => {}
        ScopedMutationCommit::Replayed(replay) => return Ok(replay_response(replay)),
        ScopedMutationCommit::Guarded => {
            return Err(domain_error(
                &context,
                ApiErrorCode::Conflict,
                "conflict",
                "The request conflicts with current state.",
            ));
        }
    }
    let created = PlatformOperationsRepository::new(database)
        .find_grant(&grant_id)
        .await
        .map_err(|_| store_unavailable(&context))?
        .ok_or_else(|| store_unavailable(&context))?;
    Ok(json_response(
        json!({ "support_grant": grant_json(&created) }),
    ))
}

#[worker::send]
pub async fn revoke_grant(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((grant_id,)): Path<(String,)>,
    Json(body): Json<RevokeGrantBody>,
) -> Result<Response<Body>, ApiError> {
    let staff = authorize_staff_route(
        &state,
        &headers,
        &context,
        StaffPermission::SupportGrantRevoke,
    )
    .await?;
    let database = database(&state, &context)?;
    if body.reason.trim().is_empty() || body.reason.len() > 500 {
        return Err(invalid_input(&context));
    }
    let repository = PlatformOperationsRepository::new(database);
    let existing = repository
        .find_grant(&grant_id)
        .await
        .map_err(|_| store_unavailable(&context))?
        .ok_or_else(|| not_found(&context))?;
    let now = context.received_at.clone();
    let idempotency = idempotency_key(&headers, &context)?;
    let claim = match prepare_scoped_mutation(
        database,
        &context,
        staff.actor.staff_principal_id.as_str(),
        &existing.organization_id,
        &idempotency,
        "POST",
        GRANT_REVOKE_PATH,
        &json!({ "grant_id": grant_id, "version": body.version, "reason": body.reason }),
    )
    .await?
    {
        PreparedScopedMutation::Replay(replay) => return Ok(replay_response(replay)),
        PreparedScopedMutation::Claim(claim) => claim,
    };
    let revoke = repository
        .revoke_grant_statement(
            &grant_id,
            staff.actor.staff_principal_id.as_str(),
            &body.reason,
            body.version,
            &now,
        )
        .map_err(|_| store_unavailable(&context))?;
    let audit = crate::routes::support::security_event_statement(
        database,
        &context,
        None,
        Some(existing.organization_id.as_str()),
        crate::adapters::new_event_id().as_str(),
        "support_grant.revoked",
        "support_grant",
        Some(&grant_id),
        "success",
        &json!({
            "staff_principal_id": staff.actor.staff_principal_id.as_str(),
            "reason": body.reason,
        }),
    )?;
    let success =
        crate::core::StoredSuccess::new(StatusCode::OK.as_u16(), json!({ "grant_id": grant_id }))
            .map_err(|_| store_unavailable(&context))?;
    match commit_scoped_mutation(database, &context, claim, success, vec![revoke], audit).await? {
        ScopedMutationCommit::Committed => {}
        ScopedMutationCommit::Replayed(replay) => return Ok(replay_response(replay)),
        ScopedMutationCommit::Guarded => {
            return Err(domain_error(
                &context,
                ApiErrorCode::Conflict,
                "version_conflict",
                "The support grant changed. Refresh and try again.",
            ));
        }
    }
    let revoked = repository
        .find_grant(&grant_id)
        .await
        .map_err(|_| store_unavailable(&context))?
        .ok_or_else(|| store_unavailable(&context))?;
    Ok(json_response(
        json!({ "support_grant": grant_json(&revoked) }),
    ))
}

/// Resolve a staff caller and make ONE decision.
///
/// `authorize_staff` is the same function the domain tests pin, and it is called
/// with a `StaffRequest` that names no organization and carries no grant — so a
/// permission that requires customer context is refused here with
/// `staff_grant_required` rather than being allowed through a platform route. The
/// `/internal` surface in P07 does not read customer data at all, so no route in
/// this file passes an organization.
async fn authorize_staff_route(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    context: &RequestContext,
    permission: StaffPermission,
) -> Result<crate::http::auth::StaffAuthenticated, ApiError> {
    let staff = require_staff(state, headers, context).await?;
    let decision = authorize_staff(
        &staff.actor,
        permission,
        StaffRequest {
            organization: None,
            grant: None,
            principal_suspended: false,
        },
    );
    if let crate::modules::staff::StaffDecision::Deny(reason) = decision {
        return Err(staff_error(context, reason));
    }
    Ok(staff)
}

/// A staff-actor security event. Written with the staff principal as the actor
/// and NO organization, because a platform action is not a customer's action.
/// The customer-visible counterpart is written separately for grants.
fn staff_audit(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    staff_principal_id: &str,
    action: &str,
    resource_type: &str,
    resource_id: Option<&str>,
    metadata: &Value,
) -> Result<worker::d1::D1PreparedStatement, ApiError> {
    let metadata = serde_json::to_string(metadata).map_err(|_| store_unavailable(context))?;
    database
        .prepare(
            "INSERT INTO security_events (event_id, org_id, actor_type, actor_id, effective_user_id, session_id, device_id, run_id, agent_session_id, tool_call_id, action, resource_type, resource_id, outcome, reason, metadata_json, request_id, correlation_id, created_at) VALUES (?1, NULL, 'staff', ?2, NULL, NULL, NULL, NULL, NULL, NULL, ?3, ?4, ?5, 'success', NULL, ?6, ?7, ?8, ?9)",
            &[
                crate::adapters::d1::BindValue::Text(crate::adapters::new_event_id().as_str()),
                crate::adapters::d1::BindValue::Text(staff_principal_id),
                crate::adapters::d1::BindValue::Text(action),
                crate::adapters::d1::BindValue::Text(resource_type),
                resource_id.map_or(crate::adapters::d1::BindValue::Null, crate::adapters::d1::BindValue::Text),
                crate::adapters::d1::BindValue::Text(&metadata),
                crate::adapters::d1::BindValue::Text(context.request_id.as_str()),
                crate::adapters::d1::BindValue::Text(context.correlation_id.as_str()),
                crate::adapters::d1::BindValue::Text(context.received_at.as_str()),
            ],
        )
        .map_err(|_| store_unavailable(context))
}

fn parse_capabilities(
    values: &[String],
    context: &RequestContext,
) -> Result<Vec<StaffPermission>, ApiError> {
    if values.is_empty() || values.len() > 32 {
        return Err(invalid_input(context));
    }
    let mut capabilities = Vec::with_capacity(values.len());
    for value in values {
        if value == "*" {
            return Err(staff_error(context, StaffDenyReason::PermissionDenied));
        }
        capabilities.push(StaffPermission::parse(value).ok_or_else(|| invalid_input(context))?);
    }
    Ok(capabilities)
}

fn allowlist_json(values: Option<&[String]>, context: &RequestContext) -> Result<String, ApiError> {
    let Some(values) = values else {
        return Ok("[]".to_owned());
    };
    let mut sorted: Vec<String> = Vec::with_capacity(values.len());
    for value in values {
        // The 0018 trigger refuses a wildcard, but a bounded validation here
        // turns it into `invalid_input` rather than a constraint collision.
        if value == "*" {
            return Err(invalid_input(context));
        }
        if OrganizationId::new(value.as_str()).is_err() {
            return Err(invalid_input(context));
        }
        sorted.push(value.clone());
    }
    sorted.sort();
    sorted.dedup();
    serde_json::to_string(&sorted).map_err(|_| invalid_input(context))
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

fn flag_error(context: &RequestContext, error: FlagError) -> ApiError {
    let message = match error {
        // F24-006: not a permanent configuration store.
        FlagError::ExpiryRequired => "A feature flag must expire.",
        FlagError::InvalidFlagKey => "The flag key is invalid.",
        FlagError::InvalidPercentage => "The rollout percentage must be between 0 and 100.",
    };
    domain_error(
        context,
        ApiErrorCode::ValidationFailed,
        error.code(),
        message,
    )
}

fn kill_switch_error(context: &RequestContext, error: KillSwitchError) -> ApiError {
    let message = match error {
        KillSwitchError::TargetUnknown => "The kill switch target is not valid.",
        KillSwitchError::TooBroad => "A kill switch must name exactly one target.",
        KillSwitchError::ReasonRequired => "A reason is required.",
        KillSwitchError::ScopeOrganizationMismatch => {
            "The organization must be present exactly at organization scope."
        }
        KillSwitchError::InvalidExpiry => "The expiry is not valid.",
    };
    domain_error(
        context,
        ApiErrorCode::ValidationFailed,
        error.code(),
        message,
    )
}

fn staff_error(context: &RequestContext, reason: StaffDenyReason) -> ApiError {
    let code = match reason {
        StaffDenyReason::AuthenticationRequired => ApiErrorCode::AuthenticationRequired,
        StaffDenyReason::PermissionDenied => ApiErrorCode::PermissionDenied,
        StaffDenyReason::StaffPrincipalSuspended => ApiErrorCode::PermissionDenied,
        StaffDenyReason::SupportGrantRequired => ApiErrorCode::PermissionDenied,
        _ => ApiErrorCode::ValidationFailed,
    };
    let message = match reason {
        StaffDenyReason::AuthenticationRequired => "Authentication is required.",
        StaffDenyReason::PermissionDenied => "You do not have permission to perform this action.",
        StaffDenyReason::StaffPrincipalSuspended => "This staff principal is suspended.",
        StaffDenyReason::SupportGrantRequired => {
            "A support grant is required for customer context."
        }
        StaffDenyReason::SupportGrantExpired => "The support grant has expired.",
        StaffDenyReason::SupportGrantRevoked => "The support grant has been revoked.",
        StaffDenyReason::SupportGrantOrganizationMismatch => {
            "The support grant does not name this organization."
        }
        StaffDenyReason::SupportGrantReasonRequired => {
            "A reason and a ticket reference are required."
        }
        StaffDenyReason::SupportGrantTtlInvalid => "The grant TTL is outside the allowed range.",
    };
    domain_error(context, code, reason.code(), message)
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

fn json_response(body: Value) -> Response<Body> {
    (StatusCode::OK, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    use crate::repositories::{FeatureFlagRecord, KillSwitchRecord, SupportGrantRecord};

    const FIXTURE: &str =
        include_str!("../../../../docs/implementation/fixtures/p07-contracts-v1.json");

    fn context() -> RequestContext {
        RequestContext::new(
            "req_0123456789abcdef0123456789abcdef".parse().unwrap(),
            crate::core::CorrelationId::new("trace-p07").unwrap(),
            "2026-09-26T12:00:00.000Z".parse().unwrap(),
        )
    }

    fn fixture() -> Value {
        serde_json::from_str(FIXTURE).expect("the frozen fixture is valid JSON")
    }

    fn keys(value: &Value) -> BTreeSet<String> {
        value
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect()
    }

    fn reason_of(error: &ApiError) -> String {
        error.error.details["reason"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }

    /// There is no web client for `/internal/*` — the gate's decision 4 puts the
    /// staff console out of P07's scope — so nothing else pins these three
    /// projections. They are the platform's own record of what a staff principal
    /// did and why, and they are the surface an incident review reads.
    #[test]
    fn the_flag_projection_is_the_frozen_field_set() {
        let frozen = &fixture()["feature_flag_with_a_percentage"];
        let record = FeatureFlagRecord {
            flag_key: frozen["flag_key"].as_str().expect("key").to_owned(),
            enabled: 1,
            rollout_percentage: frozen["rollout_percentage"].as_i64().expect("number"),
            org_allowlist_json: r#"[]"#.to_owned(),
            cohort: frozen["cohort"].as_str().expect("cohort").to_owned(),
            expires_at: frozen["expires_at"].as_str().expect("expiry").to_owned(),
            owner_staff_principal_id: frozen["owner_staff_principal_id"]
                .as_str()
                .expect("owner")
                .to_owned(),
            updated_by: frozen["updated_by"]
                .as_str()
                .expect("updated_by")
                .to_owned(),
            version: frozen["version"].as_i64().expect("version"),
            created_at: "2026-09-26T12:00:00.000Z".to_owned(),
            updated_at: "2026-09-26T12:00:00.000Z".to_owned(),
        };
        let projection = flag_json(&record);
        // The expiry travels with the flag, because an expired flag resolves OFF
        // and an operator who cannot see why will re-enable it.
        assert_eq!(projection["expires_at"], frozen["expires_at"]);
        // SQLite has no boolean; the wire does, because a client that has to
        // remember that 0 means false will get it wrong on the row that matters.
        assert_eq!(projection["enabled"], true);
        let mut expected: BTreeSet<String> = keys(frozen)
            .into_iter()
            .filter(|key| !key.starts_with('_'))
            .collect();
        expected.insert("created_at".to_owned());
        expected.insert("updated_at".to_owned());
        assert_eq!(keys(&projection), expected);
    }

    #[test]
    fn the_kill_switch_projection_carries_both_engagement_and_lifting() {
        // A switch that cannot be read as lifted is a switch nobody trusts to
        // have been lifted, so `lifted_at`, `lifted_by`, and `lift_reason` are as
        // load-bearing as `engaged_at` and the reason.
        let record = KillSwitchRecord {
            kill_switch_id: "ksw_0123456789abcdef0123456789abcdef".to_owned(),
            target_class: "plugin_version".to_owned(),
            target_ref: "pkg_0123456789abcdef0123456789abcdef@1.0.0".to_owned(),
            scope: "organization".to_owned(),
            organization_id: Some("org_0123456789abcdef0123456789abcdef".to_owned()),
            reason: "CVE-2026-0001 in 1.0.0".to_owned(),
            engaged_by_staff_principal_id: "stf_0123456789abcdef0123456789abcdef".to_owned(),
            engaged_at: "2026-09-26T12:00:00.000Z".to_owned(),
            expires_at: None,
            state: "lifted".to_owned(),
            lifted_at: Some("2026-09-26T14:00:00.000Z".to_owned()),
            lifted_by: Some("stf_0123456789abcdef0123456789abcdef".to_owned()),
            lift_reason: Some("upstream fix released".to_owned()),
            version: 2,
            created_at: "2026-09-26T12:00:00.000Z".to_owned(),
            updated_at: "2026-09-26T14:00:00.000Z".to_owned(),
        };
        let projection = kill_switch_json(&record);
        for field in [
            "kill_switch_id",
            "target_class",
            "target_ref",
            "scope",
            "organization_id",
            "reason",
            "engaged_by_staff_principal_id",
            "engaged_at",
            "expires_at",
            "state",
            "lifted_at",
            "lifted_by",
            "lift_reason",
            "version",
        ] {
            assert!(
                projection.as_object().expect("object").contains_key(field),
                "{field} is part of the platform's own record"
            );
        }
        assert_eq!(projection["lift_reason"], "upstream fix released");
        // A global switch carries no organization, and the null is load-bearing:
        // it is how a caller tells a global row from an organization row. The
        // FIELD is present either way, so the shape does not change with scope.
        assert!(keys(&projection).contains("organization_id"));
        let mut global = record;
        global.scope = "global".to_owned();
        global.organization_id = None;
        assert!(kill_switch_json(&global)["organization_id"].is_null());
    }

    #[test]
    fn the_grant_projection_is_the_frozen_field_set() {
        for key in ["support_grant_expired", "support_grant_revoked"] {
            let frozen = &fixture()[key];
            let record = SupportGrantRecord {
                grant_id: frozen["grant_id"].as_str().expect("id").to_owned(),
                staff_principal_id: frozen["staff_principal_id"]
                    .as_str()
                    .expect("staff")
                    .to_owned(),
                organization_id: frozen["organization_id"].as_str().expect("org").to_owned(),
                reason: frozen["reason"].as_str().expect("reason").to_owned(),
                ticket_reference: frozen["ticket_reference"]
                    .as_str()
                    .expect("ticket")
                    .to_owned(),
                capabilities_json: serde_json::to_string(&frozen["capabilities_json"])
                    .expect("json"),
                issued_at: frozen["issued_at"].as_str().expect("issued").to_owned(),
                expires_at: frozen["expires_at"].as_str().expect("expires").to_owned(),
                revoked_at: frozen["revoked_at"].as_str().map(str::to_owned),
                revoke_reason: frozen["revoke_reason"].as_str().map(str::to_owned),
                version: frozen["version"].as_i64().expect("version"),
                created_at: "2026-09-26T09:00:00.000Z".to_owned(),
                updated_at: "2026-09-26T09:00:00.000Z".to_owned(),
            };
            let projection = grant_json(&record);
            // `issued_at` IS the grant's creation time, so there is no separate
            // `created_at` to project. The wire field is `capabilities`, not the
            // stored column name `capabilities_json`: a client should not have to
            // know the column name.
            let expected: BTreeSet<String> = keys(frozen)
                .into_iter()
                .filter(|key| !key.starts_with('_') && key != "capabilities_json")
                .chain(std::iter::once("capabilities".to_owned()))
                .collect();
            assert_eq!(keys(&projection), expected, "{key}");
            assert_eq!(projection["capabilities"], frozen["capabilities_json"]);
            // A grant is not a credential and carries none: no token, no secret,
            // nothing that could be replayed against a customer.
            for absent in ["token", "secret", "access_token", "api_key"] {
                assert!(
                    !projection.as_object().expect("object").contains_key(absent),
                    "a support grant must not carry {absent}"
                );
            }
        }
    }

    /// A support grant is scoped to NAMED permissions. A wildcard would make the
    /// grant a standing superuser pass, which is the one thing F24-003's "default
    /// mode is metadata, not impersonation" exists to prevent.
    #[test]
    fn a_support_grant_cannot_be_a_wildcard_or_an_empty_set() {
        let context = context();
        let error =
            parse_capabilities(&["*".to_owned()], &context).expect_err("a wildcard is refused");
        // Refused as a PERMISSION decision, not as malformed input, so a client
        // can tell "you may not hold that" from "you sent that wrong".
        assert_eq!(error.error.code, ApiErrorCode::PermissionDenied);
        assert!(
            parse_capabilities(&[], &context).is_err(),
            "a grant with no capability grants nothing and should not exist"
        );
        assert!(
            parse_capabilities(&vec!["org.lookup".to_owned(); 33], &context).is_err(),
            "a grant is bounded"
        );
        assert!(
            parse_capabilities(&["org.not_a_permission".to_owned()], &context).is_err(),
            "an unknown permission is not grantable"
        );
        assert_eq!(
            parse_capabilities(&["org.lookup".to_owned()], &context)
                .expect("a known permission")
                .len(),
            1
        );
    }

    #[test]
    fn an_allowlist_entry_must_be_an_organization_and_never_a_wildcard() {
        let context = context();
        // An absent allowlist and an empty one mean the same thing for a flag, and
        // both are stored as `[]`, so the two forms are not distinguishable later.
        assert_eq!(allowlist_json(None, &context).expect("absent"), "[]");
        assert_eq!(allowlist_json(Some(&[]), &context).expect("empty"), "[]");
        for bad in ["*", "org_*", "org_short", "not-an-org-id", ""] {
            assert!(
                allowlist_json(Some(&[bad.to_owned()]), &context).is_err(),
                "{bad:?} is not an organization"
            );
        }
        // Sorted and deduplicated, so a re-PATCH with the same set is a no-op
        // rather than a new version and a new audit entry.
        assert_eq!(
            allowlist_json(
                Some(&[
                    "org_ffffffffffffffffffffffffffffffff".to_owned(),
                    "org_0123456789abcdef0123456789abcdef".to_owned(),
                    "org_0123456789abcdef0123456789abcdef".to_owned(),
                ]),
                &context
            )
            .expect("valid ids"),
            r#"["org_0123456789abcdef0123456789abcdef","org_ffffffffffffffffffffffffffffffff"]"#
        );
    }

    /// Expiry, revocation, and organization mismatch are three different
    /// conversations with the person holding the grant, so three codes. A client
    /// that treats them as one cannot tell an operator to ask for a new grant
    /// versus to stop asking.
    #[test]
    fn the_staff_error_statuses_and_codes_stay_distinct() {
        let context = context();
        let expected = [
            (
                StaffDenyReason::AuthenticationRequired,
                ApiErrorCode::AuthenticationRequired,
            ),
            (
                StaffDenyReason::PermissionDenied,
                ApiErrorCode::PermissionDenied,
            ),
            (
                StaffDenyReason::StaffPrincipalSuspended,
                ApiErrorCode::PermissionDenied,
            ),
            (
                StaffDenyReason::SupportGrantRequired,
                ApiErrorCode::PermissionDenied,
            ),
            (
                StaffDenyReason::SupportGrantExpired,
                ApiErrorCode::ValidationFailed,
            ),
            (
                StaffDenyReason::SupportGrantRevoked,
                ApiErrorCode::ValidationFailed,
            ),
            (
                StaffDenyReason::SupportGrantOrganizationMismatch,
                ApiErrorCode::ValidationFailed,
            ),
            (
                StaffDenyReason::SupportGrantReasonRequired,
                ApiErrorCode::ValidationFailed,
            ),
            (
                StaffDenyReason::SupportGrantTtlInvalid,
                ApiErrorCode::ValidationFailed,
            ),
        ];
        let mut codes: BTreeSet<String> = BTreeSet::new();
        for (reason, status) in expected {
            let error = staff_error(&context, reason);
            assert_eq!(error.error.code, status, "{}", reason.code());
            let code = reason_of(&error);
            assert!(!code.is_empty(), "{reason:?} must carry a code");
            assert!(
                codes.insert(code),
                "{reason:?} reuses another reason's code"
            );
        }
        assert_eq!(codes.len(), expected.len());
    }

    #[test]
    fn a_flag_and_a_kill_switch_refusal_each_carry_their_own_code() {
        let context = context();
        for error in [
            FlagError::ExpiryRequired,
            FlagError::InvalidFlagKey,
            FlagError::InvalidPercentage,
        ] {
            let mapped = flag_error(&context, error);
            assert_eq!(mapped.error.code, ApiErrorCode::ValidationFailed);
            assert_eq!(reason_of(&mapped), error.code());
        }
        for error in [
            KillSwitchError::TargetUnknown,
            KillSwitchError::TooBroad,
            KillSwitchError::ReasonRequired,
            KillSwitchError::ScopeOrganizationMismatch,
            KillSwitchError::InvalidExpiry,
        ] {
            let mapped = kill_switch_error(&context, error);
            assert_eq!(mapped.error.code, ApiErrorCode::ValidationFailed);
            assert_eq!(reason_of(&mapped), error.code());
        }
        // The two namespaces must not overlap, so a client branching on the code
        // cannot read a kill-switch refusal as a flag refusal.
        for flag in [
            FlagError::ExpiryRequired,
            FlagError::InvalidFlagKey,
            FlagError::InvalidPercentage,
        ] {
            for switch in [
                KillSwitchError::TargetUnknown,
                KillSwitchError::TooBroad,
                KillSwitchError::ReasonRequired,
            ] {
                assert_ne!(flag.code(), switch.code());
            }
        }
    }

    #[test]
    fn a_cursor_it_cannot_attribute_is_refused_rather_than_ignored() {
        let context = context();
        assert_eq!(decode_cursor(None, &context).expect("absent"), (None, None));
        assert_eq!(
            decode_cursor(Some(""), &context).expect("empty"),
            (None, None)
        );
        assert_eq!(
            decode_cursor(Some("2026-09-26T12:00:00.000Z|abc"), &context).expect("a pair"),
            (
                Some("2026-09-26T12:00:00.000Z".to_owned()),
                Some("abc".to_owned())
            )
        );
        for bad in [
            "one-part",
            "a|b|c",
            &format!("{}|{}", "x".repeat(41), "abc"),
        ] {
            assert!(
                decode_cursor(Some(bad), &context).is_err(),
                "{bad} is not a cursor this service issued"
            );
        }
    }
}
