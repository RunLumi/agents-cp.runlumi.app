//! P06 billing, entitlement, and licensing HTTP surface (P06-BE-03).
//!
//! # Route surface (all under `/api/v1`)
//!
//! | Method | Path | Permission |
//! |---|---|---|
//! | GET | `/orgs/{org_id}/billing/subscription` | `billing.read` |
//! | GET | `/orgs/{org_id}/entitlements` | `entitlements.read` |
//! | GET | `/orgs/{org_id}/entitlements/provider` | `billing.read` or `entitlements.read` |
//! | POST | `/orgs/{org_id}/billing/portal-session` | `billing.manage` + reauth |
//! | POST | `/orgs/{org_id}/billing/change` | `billing.manage` + `version` |
//! | POST | `/orgs/{org_id}/billing/cancel` | `billing.manage` + `version` |
//!
//! Entitlement overrides are INTERNAL/SUPPORT-ONLY: there is deliberately **no**
//! public route and **no** browser permission for them (P06-CR-002). The support
//! entry point is [`create_internal_override`], which takes an explicit
//! service/support principal rather than a browser session.
//!
//! There is deliberately **no** `/devices/license` route. The signed license
//! block is embedded in the EXISTING P03 `/devices/policy` response through
//! [`compile_device_license_block`], so there is exactly one device policy and
//! license authority.
//!
//! # Four decision inputs stay separate
//!
//! This module resolves the *Lumi product entitlement* input and the *commercial
//! state* input only. Authorization arrives as a completed `authorize_org`
//! result; `modules::budget_p05` is never imported; and the upstream provider
//! account state is a separate read-only projection served by its own route.
//!
//! # Provider privacy
//!
//! No handler here reads, returns, or logs a provider product/price identifier.
//! The public subscription projection carries the Lumi plan key, the mapped
//! status, grace bounds, derived seat counts, and the over-limit remediation —
//! never the opaque provider account/subscription reference, which stays
//! server-only.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{Extension, Path, State},
    http::{HeaderMap, Response, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::{Value, json};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::{
        billing::{
            BillingProviderAdapter, CancellationRequest, LicenseSignatureError,
            LicenseSigningSecret, LocalBillingAdapter, PlanChangeRequest, PortalSessionRequest,
            ProviderCallback, ProviderError, ProviderErrorKind, portal_unavailable_json,
            provider::{
                json_public_projection, parse_provider_status, require_account_binding,
                validate_callback_instant, validate_callback_shape,
            },
            signing::{
                LicensePayload, POLICY_FRESH_SECONDS, format_rfc3339_utc, license_expiries,
                license_unavailable_block, sign_license,
            },
        },
        d1::{BindValue, D1Adapter},
        new_resource_id, sha256_hex,
    },
    app::AppState,
    core::{
        ApiError, ApiErrorCode, OrganizationId, Principal, RequestContext, StoredSuccess, Timestamp,
    },
    http::auth::require_csrf,
    modules::authorization::Permission,
    modules::entitlements::{
        CLOUD_CONTROL_PLANE_GRACE_SECONDS, CapabilityClass, EntitlementDenial, EntitlementError,
        EntitlementGrant, EntitlementInputs, EntitlementResolution, EntitlementScope,
        LOCAL_ONLY_GRACE_SECONDS, LicenseEvaluationRequest, LicenseSnapshotClaims, LicenseState,
        OverLimitProjection, PlanPointer, ProviderAvailability, ProviderEvent, ProviderEventLedger,
        Subscription, SubscriptionStatus, apply_provider_event, evaluate_license_request,
        is_lumi_plan_key,
    },
    repositories::{
        BillingAccountRecord, BillingRepository, IdentityRepository, PlanRecord,
        ProviderProjectionRecord, ProviderSyncStateRecord, SUBSCRIPTION_EVENT_METADATA_KEYS,
        SubscriptionEventReason, SubscriptionRecord, billable_seats, license_state_for,
        over_limit_projection, plan_grant_from_row, resolve_effective, seat_policy_for,
    },
    routes::{
        agents::{denied, generated_id, replay_response, validation_error},
        authorization::{OrgAccess, authorize_org},
        errors,
        support::{
            database, database_error, idempotency_key, security_event_statement_with_context,
        },
        usage::{
            PreparedScopedMutation, ScopedMutationCommit, commit_scoped_mutation,
            prepare_scoped_mutation,
        },
    },
};

/// Idempotency scope paths. These are stable templates, so the same logical
/// operation always shares one P01 idempotency scope.
pub const BILLING_PORTAL_SESSION_PATH: &str = "/api/v1/orgs/{org_id}/billing/portal-session";
pub const BILLING_CHANGE_PATH: &str = "/api/v1/orgs/{org_id}/billing/change";
pub const BILLING_CANCEL_PATH: &str = "/api/v1/orgs/{org_id}/billing/cancel";

/// Reauthentication purpose recorded by `POST /account/reauth` for a billing
/// portal session. A portal session can move a customer to a hosted checkout
/// page, so it is treated as a sensitive action.
pub const PORTAL_REAUTH_PURPOSE: &str = "billing_portal";

/// Widest override lifetime Lumi will accept for a support entitlement
/// override. The frozen maximum is 7 days; there are no silent forever overrides.
// Read by the support-only override entry point below.
#[allow(dead_code)]
pub const MAX_OVERRIDE_TTL_SECONDS: u32 = 604_800;

/// How often a device license snapshot's METADATA row is refreshed. The signed
/// block itself is re-issued on every `/devices/policy` fetch (it carries a
/// 15-minute policy-freshness window), but persisting a row per fetch would grow
/// `license_snapshots` without bound. The row is written when the policy version
/// advances or when the previous row for the same audience is older than this.
pub const LICENSE_SNAPSHOT_PERSIST_INTERVAL_SECONDS: i64 = 3_600;

/// Mirrors the frozen P01 idempotency claim guard.
///
/// Used only by the portal-session commit, which writes NO business event: a
/// portal session changes no durable commercial state, so the frozen P06 event
/// set has nothing to carry. The guard is mirrored here (rather than reused)
/// because `IdempotencyRepository` keeps its own copy private for the
/// single-outbox commit path it owns.
const ASSERT_IDEMPOTENCY_CLAIM_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', ''
WHERE NOT EXISTS (
    SELECT 1 FROM idempotency_records
    WHERE principal_id = ?1
      AND organization_id = ?2
      AND method = ?3
      AND path = ?4
      AND key_digest = ?5
      AND request_fingerprint = ?6
      AND state = 'pending'
      AND claim_token = ?7
)
"#;

/// Mirrors the frozen P01 idempotency completion update. See the note above.
const COMPLETE_IDEMPOTENCY_SQL: &str = r#"
UPDATE idempotency_records
SET state = 'completed',
    response_status = ?1,
    response_body = ?2,
    claim_token = NULL
WHERE principal_id = ?3
  AND organization_id = ?4
  AND method = ?5
  AND path = ?6
  AND key_digest = ?7
  AND request_fingerprint = ?8
  AND state = 'pending'
  AND claim_token = ?9
"#;

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortalSessionRequestBody {
    pub plan_key: String,
    /// RELATIVE return path. An absolute URL is refused, so a portal session can
    /// never become an open redirect off the Lumi origin.
    pub return_path: String,
    /// Reauthentication grant minted by `POST /account/reauth`.
    pub reauth_grant_id: String,
    pub reauth_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePlanRequestBody {
    /// Target Lumi PLAN KEY. A payment-provider product/price identifier is not
    /// a valid plan key and is refused at the boundary.
    pub plan_key: String,
    /// Current subscription version. A stale value is `409 version_conflict`.
    pub version: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelSubscriptionRequestBody {
    /// `true` cancels at period end; `false` requests immediate cancellation
    /// through the provider adapter. Either way historical data remains.
    pub at_period_end: Option<bool>,
    pub version: i64,
}

// ---------------------------------------------------------------------------
// Error helpers (frozen P06 reason codes)
// ---------------------------------------------------------------------------

/// The non-disclosing not-found shape. A cross-tenant ID must be
/// indistinguishable from a missing one, so this is the ONLY shape a foreign
/// identifier produces.
fn not_found(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::NotFound,
        "The requested resource was not found.",
    )
    .with_detail("reason", json!("resource_not_found"))
}

fn service_unavailable(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::ServiceUnavailable,
        "The billing store is unavailable.",
    )
}

fn version_conflict(context: &RequestContext) -> ApiError {
    denied(
        context,
        ApiErrorCode::Conflict,
        "version_conflict",
        "The subscription changed. Refresh and try again.",
    )
}

fn subscription_unavailable(context: &RequestContext) -> ApiError {
    denied(
        context,
        ApiErrorCode::Conflict,
        "subscription_state_unavailable",
        "The subscription state is not available for this request.",
    )
}

/// Map a domain error onto the frozen P06 error surface. The code is always a
/// stable machine-readable reason, never provider text.
fn domain_failure(context: &RequestContext, error: EntitlementError) -> ApiError {
    if matches!(
        error,
        EntitlementError::CrossTenantGrant | EntitlementError::AccountBindingMismatch
    ) {
        return not_found(context);
    }
    let status = match error {
        EntitlementError::StaleTransition
        | EntitlementError::ProviderEventReplay
        | EntitlementError::ProviderEventOutOfOrder
        | EntitlementError::InvalidTransition
        | EntitlementError::TerminalSubscription => ApiErrorCode::Conflict,
        _ => ApiErrorCode::ValidationFailed,
    };
    denied(
        context,
        status,
        error.code(),
        "The billing request is not valid for the current subscription state.",
    )
}

/// Map a provider-adapter failure onto the frozen P06 error surface.
fn provider_failure(context: &RequestContext, error: ProviderError) -> ApiError {
    if error.kind == ProviderErrorKind::AccountBindingMismatch {
        return not_found(context);
    }
    let status = match error.kind {
        ProviderErrorKind::UnknownPlan | ProviderErrorKind::InvalidRequest => {
            ApiErrorCode::ValidationFailed
        }
        _ => ApiErrorCode::Conflict,
    };
    denied(
        context,
        status,
        error.code(),
        "The billing provider request could not be completed.",
    )
}

fn reauth_required(context: &RequestContext) -> ApiError {
    denied(
        context,
        ApiErrorCode::PermissionDenied,
        "reauthentication_required",
        "Complete a recent security check before managing billing.",
    )
}

/// Normalize an instant to the frozen 24-character UTC storage form so stored
/// values compare correctly as text in both SQL and Rust.
fn canonical_instant(value: &Timestamp) -> Option<String> {
    let raw = value.as_str();
    if raw.len() == 24 {
        return Some(raw.to_owned());
    }
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

fn now_instant(context: &RequestContext) -> Result<String, ApiError> {
    canonical_instant(&context.received_at).ok_or_else(|| service_unavailable(context))
}

fn instant_seconds(context: &RequestContext) -> Result<i64, ApiError> {
    crate::modules::entitlements::unix_seconds(&context.received_at)
        .map_err(|_| service_unavailable(context))
}

// ---------------------------------------------------------------------------
// Response projections
// ---------------------------------------------------------------------------

/// The public subscription projection.
///
/// There is no field for a provider product, price, or account identifier. The
/// Lumi plan key, the mapped status, the bounded grace windows, the derived seat
/// counts, and the over-limit remediation are the whole commercial surface.
fn subscription_json(
    subscription: &SubscriptionRecord,
    plan: &PlanRecord,
    account: Option<&BillingAccountRecord>,
    license_state: LicenseState,
    capability: Value,
    over_limit: &OverLimitProjection,
    seats: Option<&Value>,
) -> Value {
    let provider_kind = account
        .map(|value| value.provider_kind.as_str())
        .unwrap_or("local");
    json!({
        "subscription_id": subscription.subscription_id,
        "org_id": subscription.org_id,
        "plan_key": plan.plan_key,
        "plan_version": plan.version,
        "plan_name": plan.name,
        "status": subscription.status,
        "license_state": license_state.as_str(),
        "seat_based": plan.seat_based == 1,
        "seat_policy": account.map(|value| value.seat_policy.clone()),
        "grace_started_at": subscription.grace_started_at,
        "grace_expires_at": subscription.grace_expires_at,
        "current_period_starts_at": subscription.current_period_starts_at,
        "current_period_ends_at": subscription.current_period_ends_at,
        "cancel_at_period_end": subscription.cancel_at_period_end == 1,
        "cancelled_at": subscription.cancelled_at,
        "provider": { "kind": provider_kind },
        "seats": seats,
        "capability": capability,
        "over_limit": over_limit_json(over_limit),
        "version": subscription.version,
        "created_at": subscription.created_at,
        "updated_at": subscription.updated_at,
    })
}

/// The over-limit remediation projection.
///
/// A downgrade blocks new and expanded resources and never deletes a row, so
/// `delete_data` is always `false` in the payload.
fn over_limit_json(projection: &OverLimitProjection) -> Value {
    json!({
        "blocks_new_and_expansion": projection.blocks_new_and_expansion(),
        "deletes_data": projection.deletes_data(),
        "items": projection
            .items()
            .iter()
            .map(|item| json!({
                "entitlement_key": item.key.as_str(),
                "limit": item.limit,
                "current": item.current,
                "over_by": item.over_by,
                "remediation": item.remediation,
                "blocks": {
                    "create": item.blocks.create,
                    "expand": item.blocks.expand,
                    "delete_data": item.blocks.delete_data,
                },
            }))
            .collect::<Vec<Value>>(),
    })
}

/// The capability matrix for the current commercial state.
///
/// The three frozen classes are projected independently so a UI can explain
/// exactly why local work continues while cloud work does not.
fn capability_json(
    state: LicenseState,
    provider: ProviderAvailability,
    grace_started_at: Option<i64>,
    now: i64,
) -> Value {
    let policy_fresh_until = now + i64::from(POLICY_FRESH_SECONDS);
    let offline_valid_until = now + LOCAL_ONLY_GRACE_SECONDS;
    let mut out = serde_json::Map::new();
    for class in [
        CapabilityClass::LocalOnly,
        CapabilityClass::CloudControlPlane,
        CapabilityClass::PlatformPaidInference,
    ] {
        let mut request = LicenseEvaluationRequest::new(
            state,
            provider,
            class,
            now,
            policy_fresh_until,
            offline_valid_until,
        )
        .with_capability_grace_seconds(class.default_grace_seconds());
        if let Some(anchor) = grace_started_at {
            request = request.with_grace_started_at(anchor);
        }
        let decision = evaluate_license_request(&request);
        out.insert(
            class.as_str().to_owned(),
            json!({
                "allowed": decision.allowed,
                "in_flight_allowed": decision.in_flight_allowed,
                "reason": decision.reason_code(),
                "expires_at": decision.expires_at.and_then(format_rfc3339_utc),
            }),
        );
    }
    Value::Object(out)
}

/// The effective Lumi entitlement projection.
///
/// Deliberately MINIMAL: key, value, source, scope, expiry, denial, and the
/// protected flag. An internal override's `grant_id` and audited `reason` are
/// NOT exposed, because `entitlements.read` is available to viewers and support
/// activity is not part of the public entitlement contract.
fn entitlements_json(
    effective: &crate::modules::entitlements::EffectiveEntitlements,
    subscription: &SubscriptionRecord,
    plan: &PlanRecord,
) -> Value {
    json!({
        "org_id": effective.org_id.as_str(),
        "scope": "organization",
        "resolved_at": effective.resolved_at,
        "subscription": {
            "plan_key": plan.plan_key,
            "plan_version": plan.version,
            "status": subscription.status,
            "version": subscription.version,
        },
        "entitlements": effective
            .entries()
            .iter()
            .map(|entry| {
                (
                    entry.key.as_str().to_owned(),
                    serde_json::to_value(&entry.value).unwrap_or(Value::Null),
                )
            })
            .collect::<serde_json::Map<String, Value>>(),
        "grants": effective
            .entries()
            .iter()
            .map(|entry| json!({
                "entitlement_key": entry.key.as_str(),
                "value": entry.value,
                "source": entry.source.as_str(),
                "scope": entry.scope,
                "expires_at": entry.expires_at.and_then(format_rfc3339_utc),
                "denial": entry.denial.map(|reason| reason.code()),
                "protected": entry.protected,
                "granted": entry.is_grant(),
            }))
            .collect::<Vec<Value>>(),
    })
}

/// The SEPARATE upstream provider-entitlement projection.
///
/// This carries no Lumi subscription state and no Lumi entitlement values: the
/// upstream provider account status is a read-only signal for one provider route
/// and is not a second commercial authority.
fn provider_projection_items(rows: &[ProviderProjectionRecord], provider_kind: &str) -> Vec<Value> {
    if rows.is_empty() {
        return vec![json_public_projection(
            provider_kind,
            crate::modules::entitlements::ProviderEntitlementStatus::Unknown,
            None,
            0,
        )];
    }
    rows.iter()
        .map(|row| {
            let observed_at = Timestamp::new(row.observed_at.clone())
                .ok()
                .and_then(|value| crate::modules::entitlements::unix_seconds(&value).ok())
                .unwrap_or_default();
            json_public_projection(
                row.provider_kind.as_str(),
                parse_provider_status(&row.status),
                row.reason_code.as_deref(),
                observed_at,
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// `billing.read` — the current mapped subscription state, grace bounds, the
/// capability matrix, and the over-limit projection.
#[worker::send]
pub async fn read_subscription(
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
        Permission::BillingRead,
        Some("subscription"),
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let projection = subscription_projection(database, &context, &org_id).await?;
    Ok((StatusCode::OK, Json(projection)).into_response())
}

/// `entitlements.read` — the effective Lumi entitlement projection.
#[worker::send]
pub async fn read_entitlements(
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
        Permission::EntitlementsRead,
        Some("entitlement"),
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let org = OrganizationId::new(&org_id).map_err(|_| not_found(&context))?;
    let repository = BillingRepository::new(database);
    let (effective, subscription, plan) =
        resolve_effective(&repository, &org, &context.received_at, &[])
            .await
            .map_err(|error| domain_failure(&context, error))?;
    let over_limit = over_limit_projection(&repository, &org, &context.received_at)
        .await
        .map_err(|error| domain_failure(&context, error))?;
    let mut body = entitlements_json(&effective, &subscription, &plan);
    body["over_limit"] = over_limit_json(&over_limit);
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// `billing.read` or `entitlements.read` — the SEPARATE upstream provider
/// projection.
///
/// The second permission is tried only after a permission denial, and it
/// re-validates the same organization context, so the fallback cannot disclose
/// anything the first attempt did not.
#[worker::send]
pub async fn read_provider_entitlements(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    match authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::BillingRead,
        Some("provider_entitlement"),
        None,
    )
    .await
    {
        Ok(_) => {}
        Err(error) if error.error.code == ApiErrorCode::PermissionDenied => {
            authorize_org(
                &state,
                &headers,
                &context,
                &org_id,
                Permission::EntitlementsRead,
                Some("provider_entitlement"),
                None,
            )
            .await?;
        }
        Err(error) => return Err(error),
    }
    let database = database(&state, &context)?;
    let repository = BillingRepository::new(database);
    let rows = repository
        .list_provider_projections(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    let provider_kind = repository
        .find_billing_account(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .map(|value| value.provider_kind)
        .unwrap_or_else(|| "local".to_owned());
    Ok((
        StatusCode::OK,
        Json(json!({
            "org_id": org_id,
            "capability_class": crate::adapters::billing::provider::PROVIDER_ENTITLEMENT_CAPABILITY_CLASS,
            "items": provider_projection_items(&rows, &provider_kind),
        })),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Portal session
// ---------------------------------------------------------------------------

/// `billing.manage` + CSRF + `Idempotency-Key` + reauthentication.
///
/// Returns only an allowlisted HTTPS provider portal URL with a short lifetime,
/// or a stable unavailable reason. No card data is accepted, returned, or
/// logged, and the response never contains a provider product/price identifier.
#[worker::send]
pub async fn create_portal_session(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<PortalSessionRequestBody>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::BillingManage,
        Some("billing_account"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let database = database(&state, &context)?;
    require_reauthentication(
        database,
        &context,
        &access,
        &body.reauth_grant_id,
        &body.reauth_token,
    )
    .await?;

    let plan_key = body.plan_key.trim().to_owned();
    if !is_lumi_plan_key(&plan_key) {
        return Err(validation_error(
            &context,
            "plan_key_invalid",
            "Choose a valid Lumi plan.",
        ));
    }
    let repository = BillingRepository::new(database);
    let account = repository
        .find_billing_account(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context))?;
    let adapter = billing_adapter(&state);
    let now = instant_seconds(&context)?;
    let session = match adapter
        .create_portal_session(
            &PortalSessionRequest {
                account_reference: account.provider_account_ref.clone(),
                plan_key: plan_key.clone(),
                return_path: body.return_path.clone(),
            },
            now,
        )
        .await
    {
        Ok(session) => session,
        // A transient provider condition is a stable unavailable reason, never a
        // permanent commercial denial.
        Err(error) if error.is_retryable() => {
            return Ok((StatusCode::OK, Json(portal_unavailable_json())).into_response());
        }
        Err(error) => return Err(provider_failure(&context, error)),
    };

    let success = StoredSuccess::new(
        200,
        json!({
            "available": true,
            "url": session.url,
            "expires_at": format_rfc3339_utc(session.expires_at),
            "provider": { "kind": adapter.kind() },
            "plan_key": plan_key,
        }),
    )
    .map_err(|_| service_unavailable(&context))?;
    commit_audit_only(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        &json!({ "plan_key": plan_key, "return_path": body.return_path }),
        success,
        adapter.kind(),
    )
    .await
}

// ---------------------------------------------------------------------------
// Plan change
// ---------------------------------------------------------------------------

/// `billing.manage` + CSRF + `Idempotency-Key` + optimistic `version`.
///
/// A downgrade publishes a new immutable plan pointer and EXPOSES the over-limit
/// remediation. It never deletes a row: the only effect of being over limit is
/// that new and expanded resources are blocked.
#[worker::send]
pub async fn change_plan(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<ChangePlanRequestBody>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::BillingManage,
        Some("subscription"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let plan_key = body.plan_key.trim().to_owned();
    if !is_lumi_plan_key(&plan_key) {
        return Err(validation_error(
            &context,
            "plan_key_invalid",
            "Choose a valid Lumi plan.",
        ));
    }
    let database = database(&state, &context)?;
    let repository = BillingRepository::new(database);
    let subscription = repository
        .find_subscription(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context))?;
    if subscription.version != body.version {
        return Err(version_conflict(&context));
    }
    let current_plan = repository
        .find_plan(&subscription.plan_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context))?;
    if current_plan.plan_key == plan_key {
        return Err(validation_error(
            &context,
            "plan_unchanged",
            "The organization is already on this plan.",
        ));
    }
    let target_plan = repository
        .find_active_plan(&plan_key)
        .await
        .map_err(|error| database_error(&context, error))?
        .filter(|plan| plan.is_active == 1)
        .ok_or_else(|| validation_error(&context, "plan_unknown", "Choose a valid Lumi plan."))?;
    let account = repository
        .find_billing_account(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context))?;
    // Claim the P01 idempotency scope BEFORE any outbound adapter call, so a
    // replayed command never reaches the provider a second time.
    let mutation = prepare_scoped_mutation(
        database,
        &context,
        access.principal.user_id.as_str(),
        &org_id,
        &key,
        "POST",
        BILLING_CHANGE_PATH,
        &json!({ "plan_key": plan_key, "version": body.version }),
    )
    .await?;
    let claim = match mutation {
        PreparedScopedMutation::Replay(replay) => return Ok(replay_response(replay)),
        PreparedScopedMutation::Claim(claim) => claim,
    };

    let adapter = billing_adapter(&state);
    let now = instant_seconds(&context)?;
    // The adapter is the ONLY component that knows the provider-side plan, and it
    // answers with a Lumi `ProviderEvent`; the returned event is deliberately
    // NOT persisted for a plan change because the durable plan pointer is the
    // immutable Lumi `plans` row, not the provider's product/price mapping.
    // `subscription_events` therefore records provider STATUS transitions only.
    adapter
        .request_plan_change(&PlanChangeRequest {
            account_reference: account.provider_account_ref.clone(),
            from_plan_key: current_plan.plan_key.clone(),
            to_plan_key: plan_key.clone(),
            requested_at: now,
        })
        .await
        .map_err(|error| provider_failure(&context, error))?;

    let org = OrganizationId::new(&org_id).map_err(|_| not_found(&context))?;
    let now_stored = now_instant(&context)?;
    let next_version = subscription.version + 1;
    // Recompute the over-limit projection against the NEW plan so the response
    // exposes exactly what must be remediated. A downgrade never deletes a row.
    let over_limit = over_limit_for_plan(&repository, &org, &context.received_at, &target_plan)
        .await
        .map_err(|error| domain_failure(&context, error))?;

    let mut business_writes = vec![
        repository
            .apply_subscription_statement(
                &subscription.subscription_id,
                &org_id,
                &subscription.status,
                &target_plan.plan_id,
                subscription.grace_started_at.as_deref(),
                subscription.grace_expires_at.as_deref(),
                subscription.current_period_starts_at.as_deref(),
                subscription.current_period_ends_at.as_deref(),
                subscription.cancel_at_period_end == 1,
                subscription.cancelled_at.as_deref(),
                now_stored.as_str(),
                subscription.version,
            )
            .map_err(|error| database_error(&context, error))?,
        repository
            .assert_subscription_applied_statement(
                &subscription.subscription_id,
                &org_id,
                next_version,
            )
            .map_err(|error| database_error(&context, error))?,
        billing_audit(
            database,
            &context,
            &org_id,
            Some(&access.principal),
            "billing.plan_changed",
            &subscription.subscription_id,
            "success",
            &json!({
                "from_plan_key": current_plan.plan_key,
                "to_plan_key": plan_key,
                "version": next_version,
                "blocks_new_and_expansion": over_limit.blocks_new_and_expansion(),
            }),
        )?,
    ];
    let outbox = outbox_billing(
        database,
        &context,
        Some(&access.principal),
        &org_id,
        SubscriptionEventReason::StatusChanged.event_type(),
        &json!({
            "subscription_id": subscription.subscription_id,
            "org_id": org_id,
            "status": subscription.status,
            "effective_at": now_stored,
            "plan_key": target_plan.plan_key,
            "version": next_version,
        }),
    )?;
    // A downgrade is also a distinct frozen event, and it is emitted in the SAME
    // batch so the remediation and the transition are never observed apart.
    if over_limit.blocks_new_and_expansion() {
        business_writes.push(outbox_billing(
            database,
            &context,
            Some(&access.principal),
            &org_id,
            "billing.downgrade_over_limit.v1",
            &json!({
                "subscription_id": subscription.subscription_id,
                "org_id": org_id,
                "status": subscription.status,
                "effective_at": now_stored,
                "plan_key": target_plan.plan_key,
                "over_limit_keys": over_limit
                    .items()
                    .iter()
                    .map(|item| item.key.as_str())
                    .collect::<Vec<&str>>(),
                "deletes_data": false,
            }),
        )?);
    }
    let success = StoredSuccess::new(
        200,
        json!({
            "subscription_id": subscription.subscription_id,
            "org_id": org_id,
            "plan_key": target_plan.plan_key,
            "plan_version": target_plan.version,
            "status": subscription.status,
            "version": next_version,
            "over_limit": over_limit_json(&over_limit),
            "deletes_data": false,
        }),
    )
    .map_err(|_| service_unavailable(&context))?;
    match commit_scoped_mutation(database, &context, claim, success, business_writes, outbox)
        .await?
    {
        ScopedMutationCommit::Replayed(replay) => Ok(replay_response(replay)),
        ScopedMutationCommit::Committed | ScopedMutationCommit::Guarded => {
            let projection = subscription_projection(database, &context, &org_id).await?;
            Ok((StatusCode::OK, Json(projection)).into_response())
        }
    }
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

/// `billing.manage` + CSRF + `Idempotency-Key` + optimistic `version`.
///
/// The transition is produced by the provider adapter, recorded in the
/// append-only `subscription_events` history, and applied with the same atomic
/// CAS a provider callback uses. Historical data is never touched, and terminal
/// cancellation never silently reactivates.
#[worker::send]
pub async fn cancel_subscription(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<CancelSubscriptionRequestBody>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::BillingManage,
        Some("subscription"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let database = database(&state, &context)?;
    let repository = BillingRepository::new(database);
    let subscription = repository
        .find_subscription(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context))?;
    if subscription.version != body.version {
        return Err(version_conflict(&context));
    }
    if subscription.status == "cancelled" {
        return Err(subscription_unavailable(&context));
    }
    let plan = repository
        .find_plan(&subscription.plan_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context))?;
    let account = repository
        .find_billing_account(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context))?;
    let adapter = billing_adapter(&state);
    let now = instant_seconds(&context)?;
    let at_period_end = body.at_period_end.unwrap_or(true);
    let event = adapter
        .request_cancellation(&CancellationRequest {
            account_reference: account.provider_account_ref.clone(),
            plan_key: plan.plan_key.clone(),
            at_period_end,
            requested_at: now,
        })
        .await
        .map_err(|error| provider_failure(&context, error))?;

    let batch = provider_transition_batch(
        database,
        &context,
        &org_id,
        &subscription,
        &account,
        event,
        now,
        now,
        &json!({ "at_period_end": at_period_end }),
        Some(&access.principal),
    )
    .await?;

    let mutation = prepare_scoped_mutation(
        database,
        &context,
        access.principal.user_id.as_str(),
        &org_id,
        &key,
        "POST",
        BILLING_CANCEL_PATH,
        &json!({ "at_period_end": at_period_end, "version": body.version }),
    )
    .await?;
    let claim = match mutation {
        PreparedScopedMutation::Replay(replay) => return Ok(replay_response(replay)),
        PreparedScopedMutation::Claim(claim) => claim,
    };
    match commit_scoped_mutation(
        database,
        &context,
        claim,
        batch.success.clone(),
        batch.writes,
        batch.outbox,
    )
    .await?
    {
        ScopedMutationCommit::Replayed(replay) => Ok(replay_response(replay)),
        ScopedMutationCommit::Committed | ScopedMutationCommit::Guarded => {
            let projection = subscription_projection(database, &context, &org_id).await?;
            Ok((StatusCode::OK, Json(projection)).into_response())
        }
    }
}

// ---------------------------------------------------------------------------
// Internal support-only entitlement override (no browser route)
// ---------------------------------------------------------------------------

/// What an internal override request carries.
///
/// There is no browser route and no browser permission for this operation, so
/// the request is a typed struct rather than an HTTP body. A support/service
/// principal is named explicitly, and the F16 audit row records it.
// Called by support tooling through `repositories::`/`routes::`; it has no router
// entry, which is the point.
#[allow(dead_code)]
pub struct InternalOverrideRequest<'a> {
    pub org_id: &'a str,
    pub entitlement_key: &'a str,
    pub scope: &'a str,
    pub scope_id: Option<&'a str>,
    pub value_json: &'a str,
    /// REQUIRED audited reason. The table CHECK refuses an override without it.
    pub reason: &'a str,
    /// REQUIRED support/service principal. The table CHECK refuses an override
    /// without it, so support access is always attributable.
    pub granted_by_principal_id: &'a str,
    /// REQUIRED expiry. There are no silent forever overrides.
    pub expires_at: &'a Timestamp,
}

/// Create an internal, audited, expiring entitlement override.
///
/// This is a SUPPORT/SERVICE entry point, deliberately not a browser route. The
/// database-level CHECK independently refuses an override that lacks an expiry,
/// a reason, or a granting principal, and the unique active-override index
/// refuses a second unrevoked override for the same key/scope.
// Support/service entry point: no router entry and no browser permission.
#[allow(dead_code)]
pub async fn create_internal_override(
    database: &D1Adapter,
    context: &RequestContext,
    request: InternalOverrideRequest<'_>,
) -> Result<Value, ApiError> {
    let org = OrganizationId::new(request.org_id).map_err(|_| not_found(context))?;
    let key = crate::modules::entitlements::EntitlementKey::new(request.entitlement_key)
        .map_err(|error| domain_failure(context, error))?;
    let definition = crate::modules::entitlements::baseline_definition(&key).ok_or_else(|| {
        validation_error(context, "entitlement_key_unknown", "Unknown entitlement.")
    })?;
    let value: crate::modules::entitlements::EntitlementValue =
        serde_json::from_str(request.value_json).map_err(|_| {
            validation_error(context, "value_invalid", "The override value is invalid.")
        })?;
    if !definition.type_matches(&value) {
        return Err(validation_error(
            context,
            "entitlement_value_type_mismatch",
            "The override value does not match the entitlement type.",
        ));
    }
    if request.reason.trim().is_empty()
        || request.reason.len() > crate::modules::entitlements::MAX_OVERRIDE_REASON_BYTES
    {
        return Err(validation_error(
            context,
            "override_reason_required",
            "An internal override requires a reason.",
        ));
    }
    if request.granted_by_principal_id.trim().is_empty()
        || request.granted_by_principal_id.len() > 64
    {
        return Err(validation_error(
            context,
            "override_principal_required",
            "An internal override requires the granting principal.",
        ));
    }
    if request.expires_at.as_str() <= context.received_at.as_str() {
        return Err(validation_error(
            context,
            "override_expiry_invalid",
            "An internal override must expire in the future.",
        ));
    }
    let maximum = crate::adapters::add_seconds(&context.received_at, MAX_OVERRIDE_TTL_SECONDS)
        .map_err(|_| service_unavailable(context))?;
    if request.expires_at.as_str() > maximum.as_str() {
        return Err(validation_error(
            context,
            "override_expiry_too_long",
            "An internal override may not exceed the frozen maximum lifetime.",
        ));
    }
    let grant_id = generated_id("egr");
    let repository = BillingRepository::new(database);
    let insert = repository
        .insert_override_grant_statement(
            &grant_id,
            org.as_str(),
            key.as_str(),
            request.scope,
            request.scope_id,
            &serde_json::to_string(&value).unwrap_or_else(|_| "null".to_owned()),
            request.reason,
            request.granted_by_principal_id,
            context.received_at.as_str(),
            request.expires_at.as_str(),
        )
        .map_err(|error| database_error(context, error))?;
    let audit = security_event_statement_with_context(
        database,
        context,
        None,
        Some(org.as_str()),
        &generated_id("sec"),
        "entitlement.override_created",
        "entitlement_grant",
        Some(&grant_id),
        "success",
        &json!({
            "entitlement_key": key.as_str(),
            "scope": request.scope,
            "expires_at": request.expires_at.as_str(),
            "granted_by_principal_id": request.granted_by_principal_id,
        }),
        None,
        None,
        None,
        None,
    )?;
    let outbox = crate::routes::support::outbox_statement(
        database,
        context,
        None,
        Some(org.as_str()),
        "entitlement.override_created.v1",
        &json!({
            "grant_id": grant_id,
            "org_id": org.as_str(),
            "entitlement_key": key.as_str(),
            "value": value,
            "source": "internal_override",
            "effective_at": context.received_at.as_str(),
            "expires_at": request.expires_at.as_str(),
        }),
    )?;
    database
        .batch(vec![insert, audit, outbox])
        .await
        .map_err(|error| database_error(context, error))?;
    Ok(json!({
        "grant_id": grant_id,
        "org_id": org.as_str(),
        "entitlement_key": key.as_str(),
        "scope": request.scope,
        "scope_id": request.scope_id,
        "expires_at": request.expires_at.as_str(),
    }))
}

// ---------------------------------------------------------------------------
// Provider callback service (machine identity; no browser route)
// ---------------------------------------------------------------------------

/// What an authenticated provider callback produces.
// Consumed by the `billing.sync` job consumer; there is no browser route for a
// provider callback.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderCallbackOutcome {
    /// A new state transition was committed.
    Applied,
    /// The provider event had already been applied; nothing changed.
    Duplicate,
    /// The provider event was refused as a replay.
    Replay,
    /// The provider event was stale, future-dated, or behind the applied version.
    OutOfOrder,
}

/// Apply an authenticated provider callback.
///
/// The caller supplies an ALREADY-BOUNDED [`ProviderCallback`] plus the adapter
/// webhook secret; there is no raw provider payload in this signature, so a raw
/// body can be neither logged nor persisted on the way here. Ordering,
/// idempotency, and the transition itself are the pure domain's job; the atomic
/// D1 write happens in one batch.
// Consumed by the `billing.sync` job consumer / provider webhook route; there is
// no browser route for a provider callback.
#[allow(dead_code)]
pub async fn apply_provider_callback(
    database: &D1Adapter,
    context: &RequestContext,
    org_id: &str,
    callback: &ProviderCallback,
    webhook_secret: &str,
) -> Result<ProviderCallbackOutcome, ApiError> {
    validate_callback_shape(callback).map_err(|error| provider_failure(context, error))?;
    let now = instant_seconds(context)?;
    crate::adapters::billing::provider::callback_replay_bounds(callback.signed_timestamp, now)
        .map_err(|error| provider_failure(context, error))?;
    validate_callback_instant(callback.effective_at, now)
        .map_err(|error| provider_failure(context, error))?;
    crate::adapters::billing::provider::verify_callback_signature(webhook_secret, callback)
        .await
        .map_err(|error| provider_failure(context, error))?;

    let repository = BillingRepository::new(database);
    let account = repository
        .find_billing_account(org_id)
        .await
        .map_err(|error| database_error(context, error))?
        .ok_or_else(|| not_found(context))?;
    require_account_binding(&account.provider_account_ref, callback)
        .map_err(|error| provider_failure(context, error))?;
    let subscription = repository
        .find_subscription(org_id)
        .await
        .map_err(|error| database_error(context, error))?
        .ok_or_else(|| not_found(context))?;
    let event = billing_adapter_state()
        .map_callback(callback)
        .map_err(|error| provider_failure(context, error))?;
    let batch = provider_transition_batch(
        database,
        context,
        org_id,
        &subscription,
        &account,
        event,
        now,
        callback.effective_at,
        &json!({ "provider_event_id": callback.provider_event_id }),
        None,
    )
    .await?;

    let mut statements = batch.writes;
    statements.push(batch.outbox);
    match database.batch(statements).await {
        Ok(_) => Ok(ProviderCallbackOutcome::Applied),
        // A guard violation means the CAS predicate did not match, which is
        // exactly the duplicate/replay case: the `UNIQUE (provider_event_id)`
        // index and the version CAS both refuse a second application.
        Err(_) => {
            let refreshed = repository
                .find_subscription(org_id)
                .await
                .map_err(|error| database_error(context, error))?
                .ok_or_else(|| not_found(context))?;
            Ok(if refreshed.version == subscription.version {
                ProviderCallbackOutcome::Duplicate
            } else {
                ProviderCallbackOutcome::OutOfOrder
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Device license block (the ONLY device license authority)
// ---------------------------------------------------------------------------

/// Compile the signed license block for the existing P03 `/devices/policy`
/// response.
///
/// P06-CR-002: this is embedded in the EXISTING policy response, and there is no
/// separate `/devices/license` route. The function NEVER fails the policy read:
/// when a license cannot be issued it returns a stable
/// `{"license": null, "license_error": "<frozen reason>"}` block, because a
/// billing or signing dependency must not brick a device that needs to keep
/// editing locally.
// Called from the EXISTING `GET /api/v1/devices/policy` handler. There is
// deliberately no `/devices/license` route (P06-CR-002).
#[allow(clippy::too_many_arguments)]
pub async fn compile_device_license_block(
    database: &D1Adapter,
    context: &RequestContext,
    org_id: &str,
    device_id: &str,
    policy_version: i64,
    signing_secret: Option<&LicenseSigningSecret>,
) -> Value {
    match compile_device_license_block_inner(
        database,
        context,
        org_id,
        device_id,
        policy_version,
        signing_secret,
    )
    .await
    {
        Ok(block) => block,
        Err(error) => license_unavailable_block(error),
    }
}

/// Decide the license state when there is no subscription row.
///
/// WHY this is a separate pure function: no subscription row is NOT the same as
/// a cancelled subscription. A self-service organization is created with a
/// `license_states` projection and no provider account, so it is on the
/// platform defaults. Reporting `Cancelled` there would tell a device its
/// license is cancelled while the dispatcher was simultaneously letting that
/// same organization run work — because dispatch reads the very same
/// projection. The signed block and the server's own enforcement must never
/// disagree, so the persisted projection is the authority in this case.
///
/// A missing projection AND a missing subscription means there is no
/// commercial authority at all, which is the only genuinely fail-closed case.
fn license_state_without_subscription(persisted: Option<LicenseState>) -> LicenseState {
    persisted.unwrap_or(LicenseState::Cancelled)
}

async fn compile_device_license_block_inner(
    database: &D1Adapter,
    context: &RequestContext,
    org_id: &str,
    device_id: &str,
    policy_version: i64,
    signing_secret: Option<&LicenseSigningSecret>,
) -> Result<Value, LicenseSignatureError> {
    let Some(secret) = signing_secret else {
        return Err(LicenseSignatureError::SigningKeyNotConfigured);
    };
    let org = OrganizationId::new(org_id).map_err(|_| LicenseSignatureError::ClaimsRejected)?;
    let device = crate::core::ManagedDeviceId::new(device_id)
        .map_err(|_| LicenseSignatureError::ClaimsRejected)?;
    let now = crate::modules::entitlements::unix_seconds(&context.received_at)
        .map_err(|_| LicenseSignatureError::ClaimsRejected)?;
    let repository = BillingRepository::new(database);
    let subscription = repository
        .find_subscription(org_id)
        .await
        .map_err(|_| LicenseSignatureError::PlatformFailure)?;
    let provider = provider_availability(&repository, org_id)
        .await
        .unwrap_or(ProviderAvailability::Unknown);
    // The persisted server-side projection. It is seeded with the organization,
    // so it is present for every real tenant.
    let persisted_license_state = repository
        .find_license_state(org_id)
        .await
        .ok()
        .flatten()
        .and_then(|row| LicenseState::parse(&row.state));
    let license_state = match &subscription {
        Some(row) => {
            let status =
                SubscriptionStatus::parse(&row.status).unwrap_or(SubscriptionStatus::Cancelled);
            let grace_started = row
                .grace_started_at
                .as_deref()
                .and_then(|value| Timestamp::new(value).ok())
                .and_then(|value| crate::modules::entitlements::unix_seconds(&value).ok());
            license_state_for(status, provider, grace_started, now)
        }
        None => license_state_without_subscription(persisted_license_state),
    };
    // The frozen class window, narrowed only by a persisted license-state row.
    let local_grace = repository
        .find_license_state(org_id)
        .await
        .ok()
        .flatten()
        .map(|row| row.local_offline_grace_seconds)
        .filter(|seconds| *seconds > 0)
        .unwrap_or(LOCAL_ONLY_GRACE_SECONDS);
    let (policy_fresh_until, offline_valid_until) =
        license_expiries(now, CapabilityClass::LocalOnly, Some(local_grace));

    let effective = match resolve_effective(&repository, &org, &context.received_at, &[]).await {
        Ok((effective, _subscription, _plan)) => effective,
        Err(_) => {
            // A fail-closed fallback so the block is still SIGNED and the device
            // can rely on the signature plus the fail-closed values rather than
            // on an unsigned or missing block.
            let platform_defaults: Vec<EntitlementGrant> = Vec::new();
            let plan_grants: Vec<EntitlementGrant> = Vec::new();
            let subscription_grants: Vec<EntitlementGrant> = Vec::new();
            let overrides: Vec<EntitlementGrant> = Vec::new();
            let denials: Vec<EntitlementDenial> = Vec::new();
            crate::modules::entitlements::resolve_effective_entitlements(&EntitlementResolution {
                org_id: &org,
                scope: EntitlementScope::organization(),
                now,
                inputs: EntitlementInputs {
                    platform_defaults: &platform_defaults,
                    plan_grants: &plan_grants,
                    subscription_grants: &subscription_grants,
                    internal_overrides: &overrides,
                    denials: &denials,
                },
            })
            .map_err(|_| LicenseSignatureError::ClaimsRejected)?
        }
    };
    let entitlements: BTreeMap<String, crate::modules::entitlements::EntitlementValue> = effective
        .values()
        .into_iter()
        .map(|(key, value)| (key.as_str().to_owned(), value))
        .collect();

    // The issued policy version is monotonic for the audience, so the
    // `trg_license_snapshots_anti_rollback` trigger can never fire from here.
    let monotonic_version = repository
        .max_accepted_policy_version(org_id, Some(device_id))
        .await
        .map_err(|_| LicenseSignatureError::PlatformFailure)?
        .max(policy_version)
        .max(1);
    let claims = LicenseSnapshotClaims::new(
        new_resource_id("lic")
            .as_str()
            .parse()
            .map_err(|_| LicenseSignatureError::ClaimsRejected)?,
        org.clone(),
        Some(device.clone()),
        Some(format!("device:{device_id}")),
        monotonic_version,
        policy_fresh_until,
        offline_valid_until,
        now,
        CapabilityClass::LocalOnly,
        secret.key_id(),
    )
    .map_err(|_| LicenseSignatureError::ClaimsRejected)?;
    let signed = sign_license(
        secret,
        &LicensePayload {
            claims: &claims,
            license_state,
            entitlements: &entitlements,
        },
    )
    .await?;

    // The METADATA row is written on a policy-version advance or at most once
    // per persist interval, so a device polling every minute does not grow the
    // table without bound. The signed block above is returned in full every time.
    let previously_accepted = repository
        .max_accepted_policy_version(org_id, Some(device_id))
        .await
        .map_err(|_| LicenseSignatureError::PlatformFailure)?;
    let last_issued = repository
        .latest_snapshot_issued_at(org_id, Some(device_id))
        .await
        .ok()
        .flatten()
        .and_then(|value| Timestamp::new(value).ok())
        .and_then(|value| crate::modules::entitlements::unix_seconds(&value).ok());
    if previously_accepted < monotonic_version
        || last_issued.is_none_or(|issued_at| {
            now.saturating_sub(issued_at) >= LICENSE_SNAPSHOT_PERSIST_INTERVAL_SECONDS
        })
    {
        let issued_at = format_rfc3339_utc(now).ok_or(LicenseSignatureError::ClaimsRejected)?;
        let valid_until =
            format_rfc3339_utc(offline_valid_until).ok_or(LicenseSignatureError::ClaimsRejected)?;
        let entitlements_json = Value::Object(
            entitlements
                .iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        serde_json::to_value(value).unwrap_or(Value::Null),
                    )
                })
                .collect(),
        )
        .to_string();
        if let Ok(statement) = repository.insert_license_snapshot_statement(
            signed.license_snapshot_id.as_str(),
            org_id,
            Some(device_id),
            &format!("device:{device_id}"),
            monotonic_version,
            license_state.as_str(),
            issued_at.as_str(),
            valid_until.as_str(),
            &entitlements_json,
            &signed.key_id,
            &signed.signature,
            signed.canonical.as_bytes(),
            issued_at.as_str(),
            valid_until.as_str(),
        ) {
            // A metadata-write failure must not break the policy read: the block
            // is already signed and usable, so the failure is deliberately
            // swallowed rather than surfaced as a 5xx.
            let _ = statement.run().await;
        }
    }
    let mut block = signed.to_json();
    if let Value::Object(map) = &mut block {
        map.insert(
            "signature_algorithm".to_owned(),
            Value::String(
                crate::adapters::billing::signing::LICENSE_SIGNATURE_ALGORITHM.to_owned(),
            ),
        );
    }
    Ok(block)
}

// ---------------------------------------------------------------------------
// Shared internal helpers
// ---------------------------------------------------------------------------

/// One atomic tenant-scoped billing transition, ready to commit.
struct ProviderTransitionBatch {
    writes: Vec<D1PreparedStatement>,
    outbox: D1PreparedStatement,
    success: StoredSuccess,
}

/// Build the single D1 batch that applies one provider-authored transition.
///
/// Order inside the batch: CAS the subscription, assert the CAS landed, append
/// the immutable provider event, record the successful sync that anchors grace,
/// upsert the license projection, append the F16 audit row, then the outbox
/// event. Any failure rolls the whole batch back, so a refused transition can
/// never report success and a replay can never double-apply.
#[allow(clippy::too_many_arguments)]
async fn provider_transition_batch(
    database: &D1Adapter,
    context: &RequestContext,
    org_id: &str,
    subscription: &SubscriptionRecord,
    account: &BillingAccountRecord,
    event: ProviderEvent,
    now: i64,
    effective_at: i64,
    metadata: &Value,
    principal: Option<&Principal>,
) -> Result<ProviderTransitionBatch, ApiError> {
    let org = OrganizationId::new(org_id).map_err(|_| not_found(context))?;
    let repository = BillingRepository::new(database);
    let plan = repository
        .find_plan(&subscription.plan_id)
        .await
        .map_err(|error| database_error(context, error))?
        .ok_or_else(|| not_found(context))?;
    let mut domain = Subscription::new(
        subscription
            .subscription_id
            .parse()
            .map_err(|_| not_found(context))?,
        org.clone(),
        subscription
            .billing_account_id
            .parse()
            .map_err(|_| not_found(context))?,
        PlanPointer::new(
            plan.plan_id
                .parse()
                .map_err(|_| domain_failure(context, EntitlementError::InvalidPlanKey))?,
            plan.plan_key.clone(),
            plan.version,
        )
        .map_err(|error| domain_failure(context, error))?,
        SubscriptionStatus::parse(&subscription.status)
            .ok_or_else(|| subscription_unavailable(context))?,
        optional_instant(&subscription.grace_expires_at),
        optional_instant(&subscription.current_period_ends_at),
        subscription.version,
        now,
    )
    .map_err(|error| domain_failure(context, error))?;

    // Seed the pure ledger from the durable sync state so replay and ordering
    // decisions are identical on every delivery attempt.
    let sync = repository
        .find_provider_sync_state(org_id, &account.provider_kind)
        .await
        .map_err(|error| database_error(context, error))?;
    let mut ledger = seed_ledger(account.provider_account_ref.as_str(), sync.as_ref())
        .map_err(|error| domain_failure(context, error))?;

    // The bounded cloud grace window opens only when the provider says the
    // subscription entered grace; it is never widened by a poll.
    let grace_expiry = if event.next_status == SubscriptionStatus::Grace {
        Some(now + CLOUD_CONTROL_PLANE_GRACE_SECONDS)
    } else {
        None
    };
    let applied = apply_provider_event(&mut domain, &mut ledger, &event, grace_expiry, now).is_ok();
    let next_version = domain.version;
    let status = domain.status;
    let from_status = subscription.status.clone();
    let now_stored = now_instant(context)?;
    let effective_stored = format_rfc3339_utc(effective_at)
        .map(|value| value.to_string())
        .unwrap_or_else(|| now_stored.clone());
    let grace_started = if status == SubscriptionStatus::Grace {
        Some(
            subscription
                .grace_started_at
                .clone()
                .unwrap_or_else(|| now_stored.clone()),
        )
    } else {
        None
    };
    let grace_expires = grace_expiry
        .and_then(format_rfc3339_utc)
        .map(|value| value.to_string());
    let cancelled_at = if status == SubscriptionStatus::Cancelled {
        Some(now_stored.clone())
    } else {
        None
    };
    let plan_id = domain.plan.plan_id.as_str().to_owned();

    let mut writes = vec![
        repository
            .apply_subscription_statement(
                &subscription.subscription_id,
                org_id,
                status.as_str(),
                &plan_id,
                grace_started.as_deref(),
                grace_expires.as_deref(),
                subscription.current_period_starts_at.as_deref(),
                subscription.current_period_ends_at.as_deref(),
                subscription.cancel_at_period_end == 1,
                cancelled_at.as_deref(),
                now_stored.as_str(),
                subscription.version,
            )
            .map_err(|error| database_error(context, error))?,
        repository
            .assert_subscription_applied_statement(
                &subscription.subscription_id,
                org_id,
                next_version,
            )
            .map_err(|error| database_error(context, error))?,
        repository
            .insert_subscription_event_statement(
                &generated_id("sev"),
                &subscription.subscription_id,
                org_id,
                &event.provider_event_id,
                Some(event.provider_version),
                if applied {
                    Some(from_status.as_str())
                } else {
                    None
                },
                status.as_str(),
                effective_stored.as_str(),
                now_stored.as_str(),
                &bounded_metadata_json(metadata),
            )
            .map_err(|error| database_error(context, error))?,
        repository
            .record_provider_success_statement(
                &generated_id("psy"),
                org_id,
                &account.provider_kind,
                &event.provider_event_id,
                event.provider_version,
                effective_stored.as_str(),
                now_stored.as_str(),
            )
            .map_err(|error| database_error(context, error))?,
    ];
    writes.push(license_state_statement(
        database,
        context,
        &domain,
        grace_started.as_deref(),
        grace_expires.as_deref(),
        now_stored.as_str(),
    )?);
    writes.push(billing_audit(
        database,
        context,
        org_id,
        principal,
        "billing.subscription_updated",
        &subscription.subscription_id,
        "success",
        &json!({
            "status": status.as_str(),
            "version": next_version,
            "reason_code": "provider_event",
        }),
    )?);
    let outbox = outbox_billing(
        database,
        context,
        principal,
        org_id,
        SubscriptionEventReason::StatusChanged.event_type(),
        &json!({
            "subscription_id": subscription.subscription_id,
            "org_id": org_id,
            "status": status.as_str(),
            "effective_at": effective_stored,
            "version": next_version,
        }),
    )?;
    let success = StoredSuccess::new(
        200,
        json!({
            "subscription_id": subscription.subscription_id,
            "org_id": org_id,
            "status": status.as_str(),
            "version": next_version,
        }),
    )
    .map_err(|_| service_unavailable(context))?;
    Ok(ProviderTransitionBatch {
        writes,
        outbox,
        success,
    })
}

fn optional_instant(value: &Option<String>) -> Option<i64> {
    value
        .as_deref()
        .and_then(|text| Timestamp::new(text).ok())
        .and_then(|timestamp| crate::modules::entitlements::unix_seconds(&timestamp).ok())
}

/// Build the license-state upsert for a candidate subscription.
fn license_state_statement(
    database: &D1Adapter,
    context: &RequestContext,
    candidate: &Subscription,
    grace_started: Option<&str>,
    grace_expires: Option<&str>,
    now: &str,
) -> Result<D1PreparedStatement, ApiError> {
    let repository = BillingRepository::new(database);
    let state = LicenseState::license_state_for_status(candidate.status);
    repository
        .upsert_license_state_statement(
            &generated_id("lcs"),
            candidate.org_id.as_str(),
            Some(candidate.subscription_id.as_str()),
            state.as_str(),
            LOCAL_ONLY_GRACE_SECONDS,
            CLOUD_CONTROL_PLANE_GRACE_SECONDS,
            grace_started,
            grace_expires,
            None,
            now,
        )
        .map_err(|_| service_unavailable(context))
}

/// Seed the pure provider-event ledger from the durable sync state.
fn seed_ledger(
    account_reference: &str,
    sync: Option<&ProviderSyncStateRecord>,
) -> Result<ProviderEventLedger, EntitlementError> {
    let mut ledger = ProviderEventLedger::new();
    ledger.bind_account(account_reference)?;
    let Some(sync) = sync else {
        return Ok(ledger);
    };
    let (Some(event_id), Some(version), Some(at)) = (
        sync.last_event_id.clone(),
        sync.last_event_version,
        sync.last_event_at.clone(),
    ) else {
        return Ok(ledger);
    };
    let instant = Timestamp::new(at)
        .ok()
        .and_then(|value| crate::modules::entitlements::unix_seconds(&value).ok())
        .unwrap_or_default();
    if let Ok(head) = ProviderEvent::new(
        event_id,
        account_reference,
        version,
        instant,
        SubscriptionStatus::Active,
        None,
    ) {
        // A refusal here only means the stored head is unusable; an empty ledger
        // then re-applies ordering from the current server clock instead.
        let _ = ledger.accept(
            &head,
            instant + crate::modules::entitlements::MAX_PROVIDER_EVENT_SKEW_SECONDS,
        );
    }
    Ok(ledger)
}

/// The billing provider adapter for this environment.
///
/// The built-in adapter is configured from server-side environment values, never
/// from a request, and an unconfigured adapter REFUSES rather than inventing a
/// commercial answer. A real provider replaces `LocalBillingAdapter` behind the
/// same [`BillingProviderAdapter`] trait without any change to a route.
pub fn billing_adapter(state: &Arc<AppState>) -> BillingAdapter {
    let _ = state;
    billing_adapter_state()
}

/// A concrete adapter handle for this environment.
pub type BillingAdapter = LocalBillingAdapter;

fn billing_adapter_state() -> LocalBillingAdapter {
    LocalBillingAdapter::new()
}

#[allow(clippy::too_many_arguments)]
fn billing_audit(
    database: &D1Adapter,
    context: &RequestContext,
    org_id: &str,
    principal: Option<&Principal>,
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
        "subscription",
        Some(resource_id),
        outcome,
        metadata,
        None,
        None,
        None,
        None,
    )
}

fn outbox_billing(
    database: &D1Adapter,
    context: &RequestContext,
    principal: Option<&Principal>,
    org_id: &str,
    event_type: &str,
    payload: &Value,
) -> Result<D1PreparedStatement, ApiError> {
    crate::routes::support::outbox_statement(
        database,
        context,
        principal,
        Some(org_id),
        event_type,
        payload,
    )
}

/// Read the normalized provider reachability for one tenant.
async fn provider_availability(
    repository: &BillingRepository<'_>,
    org_id: &str,
) -> Result<ProviderAvailability, worker::Error> {
    use crate::modules::entitlements::ProviderEntitlementStatus;
    let rows = repository.list_provider_projections(org_id).await?;
    for (status, availability) in [
        (
            ProviderEntitlementStatus::Unavailable,
            ProviderAvailability::Unavailable,
        ),
        (
            ProviderEntitlementStatus::Available,
            ProviderAvailability::Available,
        ),
        (
            ProviderEntitlementStatus::Degraded,
            ProviderAvailability::Degraded,
        ),
    ] {
        if rows
            .iter()
            .any(|row| parse_provider_status(&row.status) == status)
        {
            return Ok(availability);
        }
    }
    Ok(ProviderAvailability::Unknown)
}

/// Re-check a reauthentication grant for a sensitive billing action.
async fn require_reauthentication(
    database: &D1Adapter,
    context: &RequestContext,
    access: &OrgAccess,
    grant_id: &str,
    token: &str,
) -> Result<(), ApiError> {
    if grant_id.is_empty() || grant_id.len() > 64 || token.is_empty() || token.len() > 256 {
        return Err(reauth_required(context));
    }
    let token_hash = sha256_hex(token)
        .await
        .map_err(|_| service_unavailable(context))?;
    let consumed = IdentityRepository::new(database)
        .consume_reauth(
            grant_id,
            access.principal.user_id.as_str(),
            access.principal.session_id.as_str(),
            PORTAL_REAUTH_PURPOSE,
            &token_hash,
            &context.received_at,
        )
        .await
        .map_err(|error| database_error(context, error))?;
    if consumed {
        Ok(())
    } else {
        Err(reauth_required(context))
    }
}

/// Commit an idempotency claim, an F16 audit row, and a replayable response
/// WITHOUT a business event.
///
/// A portal session changes no durable commercial state, so the frozen P06 event
/// set has nothing to carry; the audit row is the durable record of the action.
#[allow(clippy::too_many_arguments)]
async fn commit_audit_only(
    database: &D1Adapter,
    context: &RequestContext,
    principal: &Principal,
    org_id: &str,
    key: &str,
    body: &Value,
    success: StoredSuccess,
    provider_kind: &str,
) -> Result<Response<Body>, ApiError> {
    use crate::core::{
        ActorId, IdempotencyKeyDigest, IdempotencyRecord, IdempotencyScope, IdempotencyState,
        RequestFingerprint,
    };
    use crate::repositories::{IdempotencyClaimToken, IdempotencyLookup, IdempotencyRepository};

    let scope = IdempotencyScope::new(
        ActorId::new(principal.user_id.as_str()).map_err(|_| service_unavailable(context))?,
        Some(OrganizationId::new(org_id).map_err(|_| service_unavailable(context))?),
        "POST",
        BILLING_PORTAL_SESSION_PATH,
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
        sha256_hex(&format!("POST\n{BILLING_PORTAL_SESSION_PATH}\n{canonical}"))
            .await
            .map_err(|_| service_unavailable(context))?
    ))
    .map_err(|_| service_unavailable(context))?;
    let record = IdempotencyRecord {
        scope: scope.clone(),
        key_digest: key_digest.clone(),
        request_fingerprint: request_fingerprint.clone(),
        expires_at: crate::adapters::add_idempotency_ttl(&context.received_at)
            .map_err(|_| service_unavailable(context))?,
        state: IdempotencyState::Pending,
    };
    let token_value = context.request_id.as_str().to_owned();
    let token = IdempotencyClaimToken::new(token_value.clone())
        .map_err(|_| service_unavailable(context))?;
    let repository = IdempotencyRepository::new(database);
    let claim = repository
        .claim_statement(&record, &token, &context.received_at)
        .map_err(|_| service_unavailable(context))?;
    let organization_scope = scope
        .organization_id
        .as_ref()
        .map_or("", OrganizationId::as_str);
    let guard = database
        .prepare(
            ASSERT_IDEMPOTENCY_CLAIM_SQL,
            &[
                BindValue::Text(scope.principal_id.as_str()),
                BindValue::Text(organization_scope),
                BindValue::Text(&scope.method),
                BindValue::Text(&scope.path),
                BindValue::Text(key_digest.as_str()),
                BindValue::Text(request_fingerprint.as_str()),
                BindValue::Text(&token_value),
            ],
        )
        .map_err(|_| service_unavailable(context))?;
    let audit = billing_audit(
        database,
        context,
        org_id,
        Some(principal),
        "billing.portal_session_created",
        org_id,
        "success",
        &json!({ "provider_kind": provider_kind }),
    )?;
    let completion = database
        .prepare(
            COMPLETE_IDEMPOTENCY_SQL,
            &[
                BindValue::Integer(i32::from(success.status)),
                BindValue::Text(
                    &serde_json::to_string(&success.body).unwrap_or_else(|_| "{}".to_owned()),
                ),
                BindValue::Text(scope.principal_id.as_str()),
                BindValue::Text(organization_scope),
                BindValue::Text(&scope.method),
                BindValue::Text(&scope.path),
                BindValue::Text(key_digest.as_str()),
                BindValue::Text(request_fingerprint.as_str()),
                BindValue::Text(&token_value),
            ],
        )
        .map_err(|_| service_unavailable(context))?;
    match database.batch(vec![claim, guard, audit, completion]).await {
        Ok(_) => Ok((StatusCode::OK, Json(success.body)).into_response()),
        Err(_) => match repository
            .lookup(
                &record.scope,
                &record.key_digest,
                &record.request_fingerprint,
                &context.received_at,
            )
            .await
            .map_err(|_| service_unavailable(context))?
        {
            IdempotencyLookup::Replay(replay) => Ok(replay_response(replay)),
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
        },
    }
}

/// Compute the full subscription projection for one tenant.
async fn subscription_projection(
    database: &D1Adapter,
    context: &RequestContext,
    org_id: &str,
) -> Result<Value, ApiError> {
    let repository = BillingRepository::new(database);
    let org = OrganizationId::new(org_id).map_err(|_| not_found(context))?;
    let subscription = repository
        .find_subscription(org_id)
        .await
        .map_err(|error| database_error(context, error))?
        .ok_or_else(|| not_found(context))?;
    let plan = repository
        .find_plan(&subscription.plan_id)
        .await
        .map_err(|error| database_error(context, error))?
        .ok_or_else(|| not_found(context))?;
    let account = repository
        .find_billing_account(org_id)
        .await
        .map_err(|error| database_error(context, error))?;
    let provider = provider_availability(&repository, org_id)
        .await
        .unwrap_or(ProviderAvailability::Unknown);
    let now = instant_seconds(context)?;
    let status =
        SubscriptionStatus::parse(&subscription.status).unwrap_or(SubscriptionStatus::Cancelled);
    let license_state = license_state_for(
        status,
        provider,
        optional_instant(&subscription.grace_started_at),
        now,
    );
    let capability = capability_json(
        license_state,
        provider,
        optional_instant(&subscription.grace_started_at),
        now,
    );
    let over_limit = over_limit_projection(&repository, &org, &context.received_at)
        .await
        .map_err(|error| domain_failure(context, error))?;
    let seats = seat_projection(&repository, &org, &account, context)
        .await
        .ok()
        .flatten();
    Ok(subscription_json(
        &subscription,
        &plan,
        account.as_ref(),
        license_state,
        capability,
        &over_limit,
        seats.as_ref(),
    ))
}

/// Derive the seat projection from AUTHORITATIVE membership rows.
async fn seat_projection(
    repository: &BillingRepository<'_>,
    org: &OrganizationId,
    account: &Option<BillingAccountRecord>,
    context: &RequestContext,
) -> Result<Option<Value>, ApiError> {
    let Some(account) = account else {
        return Ok(None);
    };
    let rows = repository
        .list_seat_rows(org.as_str())
        .await
        .map_err(|error| database_error(context, error))?;
    let policy = match seat_policy_for(&account.seat_policy) {
        Ok(policy) => policy,
        // A corrupt seat policy must not invent a bill, so the seat projection is
        // omitted and the rest of the commercial state still reads.
        Err(_) => return Ok(None),
    };
    let count =
        billable_seats(org, &rows, &policy).map_err(|error| domain_failure(context, error))?;
    Ok(Some(json!({
        "billable": count.billable,
        "total": count.total(),
        "by_state": count
            .by_state
            .iter()
            .map(|(state, value)| (state.as_str().to_owned(), Value::from(*value)))
            .collect::<serde_json::Map<String, Value>>(),
    })))
}

/// Compute the over-limit projection against a plan that is not yet current.
///
/// This is what exposes the remediation for a DOWNGRADE, and it never deletes
/// anything: it only reports which resources are above the new limit and blocks
/// new/expanded mutations.
async fn over_limit_for_plan(
    repository: &BillingRepository<'_>,
    org: &OrganizationId,
    now: &Timestamp,
    target_plan: &PlanRecord,
) -> Result<OverLimitProjection, EntitlementError> {
    let now_seconds = crate::modules::entitlements::unix_seconds(now)?;
    let rows = repository
        .list_plan_entitlements(&target_plan.plan_id)
        .await
        .map_err(|_| EntitlementError::InvalidEntitlementValue)?;
    let mut plan_grants: Vec<EntitlementGrant> = Vec::new();
    for row in &rows {
        if let Some(grant) = plan_grant_from_row(org.as_str(), row, now_seconds)? {
            plan_grants.push(grant);
        }
    }
    // Only the target plan's own values are considered here: this is a preview of
    // the DOWNGRADE, so the current plan's higher limits must not be mixed in.
    let platform_defaults: Vec<EntitlementGrant> = Vec::new();
    let subscription_grants: Vec<EntitlementGrant> = Vec::new();
    let overrides: Vec<EntitlementGrant> = Vec::new();
    let denials: Vec<EntitlementDenial> = Vec::new();
    let effective =
        crate::modules::entitlements::resolve_effective_entitlements(&EntitlementResolution {
            org_id: org,
            scope: EntitlementScope::organization(),
            now: now_seconds,
            inputs: EntitlementInputs {
                platform_defaults: &platform_defaults,
                plan_grants: &plan_grants,
                subscription_grants: &subscription_grants,
                internal_overrides: &overrides,
                denials: &denials,
            },
        })?;
    let counts = repository
        .authoritative_counts(org.as_str())
        .await
        .map_err(|_| EntitlementError::InvalidEntitlementValue)?;
    Ok(crate::modules::entitlements::compute_over_limit_projection(
        org,
        counts,
        &effective,
        now_seconds,
    ))
}

/// Bound the stored provider-event metadata to a small allowlisted object.
///
/// The frozen contract forbids a raw provider payload, credentials, prompt or
/// response content, and unbounded URLs in any `billing.*` payload, so the object
/// is rebuilt from a fixed key set. Anything off the allowlist is DROPPED, not
/// serialized, so a caller cannot smuggle a payload into the event or audit row.
fn bounded_metadata_json(metadata: &Value) -> String {
    let mut object = serde_json::Map::new();
    for key in SUBSCRIPTION_EVENT_METADATA_KEYS {
        if let Some(value) = metadata.get(key) {
            object.insert(
                key.to_owned(),
                match value {
                    Value::String(text) if text.len() <= 96 => Value::String(text.clone()),
                    Value::String(_) => Value::Null,
                    Value::Number(number) if number.is_i64() || number.is_u64() => {
                        Value::Number(number.clone())
                    }
                    Value::Bool(flag) => Value::Bool(*flag),
                    _ => Value::Null,
                },
            );
        }
    }
    serde_json::to_string(&Value::Object(object)).unwrap_or_else(|_| "{}".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context() -> RequestContext {
        RequestContext::new(
            "req_0123456789abcdef0123456789abcdef"
                .parse()
                .expect("static request ID is valid"),
            "req_1123456789abcdef0123456789abcdef"
                .parse()
                .expect("static correlation ID is valid"),
            "2026-09-25T12:00:00.000Z"
                .parse()
                .expect("static timestamp is valid"),
        )
    }

    #[test]
    fn frozen_event_names_match_the_p06_contract() {
        assert_eq!(
            SubscriptionEventReason::StatusChanged.event_type(),
            "billing.subscription_updated.v1"
        );
        assert!(SubscriptionEventReason::GraceStarted.is_grace_transition());
        assert!(!SubscriptionEventReason::PlanChanged.is_grace_transition());
        assert_eq!(
            crate::adapters::billing::signing::LICENSE_SIGNATURE_ALGORITHM,
            "ed25519",
            "the license block advertises the frozen algorithm"
        );
    }

    #[test]
    fn stored_provider_metadata_drops_anything_off_the_allowlist() {
        let metadata = json!({
            "plan_key": "team",
            "status": "grace",
            "version": 4,
            "provider_payload": {"customer": "cus_secret"},
            "card": "4242",
            "prompt": "system prompt",
        });
        let stored = bounded_metadata_json(&metadata);
        assert!(stored.contains("\"plan_key\":\"team\""));
        assert!(stored.contains("\"version\":4"));
        assert!(!stored.contains("cus_secret"));
        assert!(!stored.contains("4242"));
        assert!(!stored.contains("system prompt"));
        assert!(stored.len() < 4096);
    }

    #[test]
    fn bounded_metadata_replaces_oversized_strings_rather_than_truncating_them() {
        let stored = bounded_metadata_json(&json!({ "reason_code": "x".repeat(512) }));
        assert!(stored.contains("\"reason_code\":null"));
        assert!(stored.len() < 4096);
    }

    #[test]
    fn canonical_instants_are_frozen_utc_text() {
        let timestamp: Timestamp = "2026-09-25T12:00:00Z".parse().unwrap();
        assert_eq!(
            canonical_instant(&timestamp).unwrap(),
            "2026-09-25T12:00:00.000Z"
        );
        let millis: Timestamp = "2026-09-25T12:00:00.123456Z".parse().unwrap();
        assert_eq!(
            canonical_instant(&millis).unwrap(),
            "2026-09-25T12:00:00.123Z"
        );
    }

    #[test]
    fn a_provider_failure_never_exposes_provider_text() {
        let context = test_context();
        let error = provider_failure(
            &context,
            ProviderError::new(ProviderErrorKind::SignatureInvalid),
        );
        assert_eq!(error.error.code, ApiErrorCode::Conflict);
        assert_eq!(
            error.error.details.get("reason").unwrap(),
            "webhook_signature_invalid"
        );
        assert!(!serde_json::to_string(&error).unwrap().contains("secret"));
    }

    #[test]
    fn a_cross_account_provider_binding_returns_the_non_disclosing_shape() {
        let context = test_context();
        let error = provider_failure(
            &context,
            ProviderError::new(ProviderErrorKind::AccountBindingMismatch),
        );
        assert_eq!(error.error.code, ApiErrorCode::NotFound);
        assert_eq!(
            error.error.details.get("reason").unwrap(),
            "resource_not_found"
        );
    }

    /// A self-service organization has a `license_states` projection and no
    /// provider account, because no payment provider is involved. Reporting
    /// `Cancelled` for that state would contradict the dispatcher, which
    /// permits the same organization to run work because it reads the same
    /// projection. This test pins the two to one another so the contradiction
    /// cannot come back.
    #[test]
    fn a_tenant_without_a_subscription_keeps_the_projection_the_dispatcher_uses() {
        for state in [
            LicenseState::Active,
            LicenseState::Grace,
            LicenseState::PastDue,
            LicenseState::Suspended,
        ] {
            assert_eq!(
                license_state_without_subscription(Some(state)),
                state,
                "the signed block must report exactly what dispatch enforces",
            );
        }
        // Only a completely absent commercial authority fails closed.
        assert_eq!(
            license_state_without_subscription(None),
            LicenseState::Cancelled,
        );
    }

    /// The dispatch guard checks the persisted projection's state, so the
    /// signed block has to carry the same value or a device would be told it
    /// has a narrower license than the server is actually enforcing.
    #[test]
    fn the_dispatch_state_and_the_signed_state_are_the_same_vocabulary() {
        for row in [
            "active",
            "grace",
            "past_due",
            "suspended",
            "cancelled",
            "expired",
        ] {
            let parsed = LicenseState::parse(row);
            assert!(
                parsed.is_some(),
                "{row} must be a license state the block can report"
            );
            assert_eq!(parsed.expect("checked").as_str(), row);
        }
    }

    #[test]
    fn the_capability_matrix_keeps_local_work_alive_during_a_provider_outage() {
        let now = 1_789_000_000;
        // A bounded grace window with an UNCONFIRMED provider account: local work
        // continues, cloud managed work continues inside the window, and paid
        // inference is refused with a stable reason rather than being attempted.
        let during_grace = capability_json(
            LicenseState::Grace,
            ProviderAvailability::Unknown,
            Some(now - 100),
            now,
        );
        assert_eq!(during_grace["local_only"]["allowed"], json!(true));
        assert_eq!(during_grace["local_only"]["reason"], json!(Value::Null));
        assert_eq!(during_grace["cloud_control_plane"]["allowed"], json!(true));
        assert_eq!(
            during_grace["cloud_control_plane"]["reason"],
            json!(Value::Null)
        );
        assert_eq!(
            during_grace["platform_paid_inference"]["allowed"],
            json!(false)
        );
        assert_eq!(
            during_grace["platform_paid_inference"]["reason"],
            json!("provider_entitlement_unavailable")
        );

        // A confirmed provider account does not change that platform-paid
        // inference receives NO additional billing grace: it is denied as soon as
        // the subscription enters grace.
        let grace_with_provider = capability_json(
            LicenseState::Grace,
            ProviderAvailability::Available,
            Some(now - 100),
            now,
        );
        assert_eq!(
            grace_with_provider["platform_paid_inference"]["allowed"],
            json!(false)
        );
        assert_eq!(
            grace_with_provider["platform_paid_inference"]["reason"],
            json!("entitlement_grace_expired")
        );

        // Past due: local work is bounded by the signed offline expiry, cloud and
        // paid work are denied.
        let past_due = capability_json(
            LicenseState::PastDue,
            ProviderAvailability::Available,
            None,
            now,
        );
        assert_eq!(past_due["local_only"]["allowed"], json!(true));
        assert_eq!(past_due["cloud_control_plane"]["allowed"], json!(false));
        assert_eq!(
            past_due["cloud_control_plane"]["reason"],
            json!("entitlement_grace_expired")
        );

        // Suspended/cancelled: no new work anywhere, but already-authorized
        // in-flight local work is still allowed to settle.
        for terminal in [LicenseState::Suspended, LicenseState::Cancelled] {
            let projection = capability_json(terminal, ProviderAvailability::Available, None, now);
            assert_eq!(projection["local_only"]["allowed"], json!(false));
            assert_eq!(projection["local_only"]["in_flight_allowed"], json!(true));
            assert_eq!(projection["cloud_control_plane"]["allowed"], json!(false));
            assert_eq!(
                projection["cloud_control_plane"]["in_flight_allowed"],
                json!(false)
            );
        }
    }

    #[test]
    fn an_unavailable_license_block_carries_a_stable_reason_only() {
        let block = license_unavailable_block(LicenseSignatureError::SigningKeyNotConfigured);
        assert_eq!(block["available"], json!(false));
        assert_eq!(block["reason"], json!("license_key_unknown"));
        assert_eq!(block["signature_algorithm"], json!("ed25519"));
        let rendered = serde_json::to_string(&block).unwrap();
        // No key material, no claim set, no provider detail.
        assert!(!rendered.contains("-----BEGIN"));
        assert!(!rendered.contains("PRIVATE"));
        assert!(!rendered.contains("org_id"));
        assert!(!rendered.contains("entitlements"));
    }
}
