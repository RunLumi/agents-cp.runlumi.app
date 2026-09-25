//! P06 browser HTTP surface: webhook endpoints, signed delivery history, and
//! the notification center.
//!
//! Every handler is thin: it validates bounded input, resolves current
//! authorization through the central path, prepares a P01 idempotency claim,
//! and commits the business rows, the F16 audit row, and the frozen P01 event in
//! ONE D1 batch. A destination that is down never fails the business mutation:
//! the delivery row is durable before the queue is involved.
//!
//! Foreign IDs return the same non-disclosing `resource_not_found` shape, and
//! notification reads filter by the authenticated principal. A plaintext webhook
//! secret is returned exactly once, in the creation or rotation response, and
//! is never persisted, logged, or returned again.

// The coordinator owns `app.rs` and `lib.rs`, so the router entries and the
// `JOBS_QUEUE` handler that reference this module are not wired yet. Until they
// are, every item below is unreachable and `dead_code` would fire on the whole
// public surface. Remove this allow in the same change that adds the routes.
#![allow(dead_code)]

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
        new_resource_id, new_secret,
        webhooks::{
            outbound::{body_hash, secret_fingerprint},
            validate_endpoint_url,
        },
    },
    app::AppState,
    core::{ApiError, ApiErrorCode, EventId, EventType, Principal, RequestContext, StoredSuccess},
    http::auth::{require_csrf, require_session},
    modules::authorization::Permission,
    repositories::{
        DeliveryPageCursor, NOTIFICATION_CATEGORIES, NOTIFICATION_CHANNELS,
        NewWebhookDeliveryInput, NewWebhookEndpointInput, NewWebhookSecretInput,
        NotificationFilters, NotificationPreferenceUpdate, WebhookDeliveryState,
        WebhookEndpointRecord, WebhookRepository,
    },
    routes::{
        agents::{
            PreparedMutation, commit_mutation, decode_page_cursor, encode_page_cursor, page_limit,
            validation_error,
        },
        authorization::authorize_org,
        errors,
        support::{
            database, database_error, idempotency_key, outbox_statement, security_event_statement,
        },
    },
};

pub const WEBHOOKS_PATH: &str = "/api/v1/orgs/{org_id}/webhooks";
pub const WEBHOOK_PATH: &str = "/api/v1/orgs/{org_id}/webhooks/{endpoint_id}";
pub const WEBHOOK_ROTATE_PATH: &str = "/api/v1/orgs/{org_id}/webhooks/{endpoint_id}/rotate-secret";
pub const WEBHOOK_TEST_PATH: &str = "/api/v1/orgs/{org_id}/webhooks/{endpoint_id}/test";
pub const WEBHOOK_DELIVERIES_PATH: &str = "/api/v1/orgs/{org_id}/webhooks/{endpoint_id}/deliveries";
pub const WEBHOOK_REPLAY_PATH: &str =
    "/api/v1/orgs/{org_id}/webhooks/deliveries/{delivery_id}/replay";
pub const ORG_PREFERENCES_PATH: &str = "/api/v1/orgs/{org_id}/notification-preferences";
pub const NOTIFICATIONS_PATH: &str = "/api/v1/notifications";
pub const NOTIFICATION_READ_PATH: &str = "/api/v1/notifications/{notification_id}/read";
pub const MY_PREFERENCES_PATH: &str = "/api/v1/me/notification-preferences";

/// Frozen P06 event names an endpoint may subscribe to.
///
/// Names outside this list are accepted only when they satisfy the P01
/// `EventType` grammar (lowercase dotted segments plus an integer version),
/// which is the same exact-match rule the SQL fan-out applies. Wildcards can
/// never pass either check. The coordinator should replace the grammar branch
/// with the coordinator-owned `consumers::outbox` registry once it is public.
pub const P06_EVENT_TYPES: &[&str] = &[
    "automation.definition.created.v1",
    "automation.definition.updated.v1",
    "automation.definition.paused.v1",
    "automation.definition.resumed.v1",
    "automation.definition.deleted.v1",
    "automation.occurrence.created.v1",
    "automation.occurrence.dispatched.v1",
    "automation.occurrence.started.v1",
    "automation.occurrence.completed.v1",
    "automation.occurrence.failed.v1",
    "automation.occurrence.skipped.v1",
    "automation.occurrence.missed.v1",
    "automation.occurrence.lease_expired.v1",
    "automation.occurrence.ambiguous.v1",
    "webhook.endpoint_created.v1",
    "webhook.endpoint_updated.v1",
    "webhook.endpoint_rotated.v1",
    "webhook.endpoint_disabled.v1",
    "webhook.test.v1",
    "webhook.delivery_succeeded.v1",
    "webhook.delivery_retry_scheduled.v1",
    "webhook.delivery_dead_lettered.v1",
    "webhook.delivery_replayed.v1",
    "notification.created.v1",
    "notification.delivery_succeeded.v1",
    "notification.delivery_retry_scheduled.v1",
    "notification.delivery_dead_lettered.v1",
    "billing.subscription_updated.v1",
    "billing.grace_started.v1",
    "billing.grace_ended.v1",
    "entitlement.granted.v1",
    "entitlement.revoked.v1",
    "entitlement.override_created.v1",
    "entitlement.override_expired.v1",
    "license.snapshot_issued.v1",
    "billing.downgrade_over_limit.v1",
    "data_policy.updated.v1",
    "export.requested.v1",
    "export.started.v1",
    "export.completed.v1",
    "export.failed.v1",
    "export.expired.v1",
    "deletion.requested.v1",
    "deletion.started.v1",
    "deletion.step_completed.v1",
    "deletion.failed.v1",
    "deletion.resumed.v1",
    "deletion.completed.v1",
];

/// Event families that can never be fanned out to a webhook endpoint. These
/// match `trg_webhook_deliveries_no_recursive_fanout` exactly, and the gate
/// forbids recursive delivery loops.
const RECURSIVE_EVENT_PREFIXES: &[&str] = &[
    "webhook.delivery_",
    "webhook.endpoint_",
    "notification.delivery_",
];

/// The frozen P01-P05 business event names an endpoint may subscribe to.
///
/// This mirrors the coordinator-owned `consumers::outbox::SUPPORTED_EVENT_TYPES`
/// registry, which is private to that module. When the coordinator makes the
/// registry public, this list should be replaced by a direct reference so the
/// two can never drift; `all_subscribable_event_types` is the single join point
/// used by the validator and its test.
const P01_P05_EVENT_TYPES: &[&str] = &[
    "foundation.check.requested.v1",
    "identity.created.v1",
    "identity.verified.v1",
    "identity.linked.v1",
    "identity.link_started.v1",
    "auth.login.completed.v1",
    "auth.logout.v1",
    "auth.session.rotated.v1",
    "organization.created.v1",
    "organization.updated.v1",
    "organization.ownership_transferred.v1",
    "organization.suspended.v1",
    "organization.resumed.v1",
    "organization.deletion_started.v1",
    "membership.invited.v1",
    "membership.accepted.v1",
    "membership.role_changed.v1",
    "membership.removed.v1",
    "membership.left.v1",
    "membership.invitation_revoked.v1",
    "membership.invitation_resent.v1",
    "team.created.v1",
    "team.member_removed.v1",
    "session.revoked.v1",
    "session.revoked_all.v1",
    "reauthentication.granted.v1",
    "device_code.approved.v1",
    "model_policy.updated.v1",
    "model_catalog.provider_created.v1",
    "model_catalog.provider_lifecycle_changed.v1",
    "model_catalog.model_created.v1",
    "model_catalog.model_lifecycle_changed.v1",
    "credential.created.v1",
    "credential.rotated.v1",
    "credential.revoked.v1",
    "route.draft_created.v1",
    "route.published.v1",
    "route.rolled_back.v1",
    "route.lifecycle_changed.v1",
    "inference.requested.v1",
    "inference.completed.v1",
    "inference.failed.v1",
    "usage.recorded.v1",
    "project.created.v1",
    "project.updated.v1",
    "project.archived.v1",
    "device.enrollment.approved.v1",
    "device.revoked.v1",
    "agent_definition.created.v1",
    "agent_definition.updated.v1",
    "session.created.v1",
    "session.closed.v1",
    "run.created.v1",
    "run.retried.v1",
    "run.state_changed.v1",
    "run.started.v1",
    "run.completed.v1",
    "run.failed.v1",
    "run.cancelled.v1",
    "run.event_appended.v1",
    "tool.catalog_updated.v1",
    "tool.mcp_registration_changed.v1",
    "tool.decision_recorded.v1",
    "tool.denied.v1",
    "tool.result.v1",
    "tool.approval_requested.v1",
    "approval.requested.v1",
    "approval.resolved.v1",
    "usage.reconciled.v1",
    "budget.reserved.v1",
    "budget.reconciled.v1",
    "budget.denied.v1",
    "rate_limit.denied.v1",
    "artifact.created.v1",
    "tool.policy_updated.v1",
    "rate_limit_policy.updated.v1",
];

/// Mandatory security families. Informational preferences may never opt out of
/// them; the `0012` trigger enforces the same rule in D1.
const MANDATORY_EVENT_FRAGMENTS: &[&str] = &["auth.", "device.revoked", "organization.suspended"];

/// P06 browser permissions.
///
/// `modules::authorization` is coordinator-owned and does not yet carry the P06
/// variants, so each P06 permission maps to the central permission whose role
/// band is identical under the current matrix: owner/admin for mutations, and
/// every active role for reads. The mapping keeps session resolution, current
/// organization state, membership, email verification, and resource scope inside
/// the single central decision path. The coordinator should add the P06 variants
/// and replace `central_permission` with a direct pass-through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum P06Permission {
    WebhooksRead,
    WebhooksManage,
    NotificationsRead,
    NotificationsManage,
}

impl P06Permission {
    const fn central_permission(self) -> Permission {
        match self {
            Self::WebhooksRead | Self::NotificationsRead => Permission::OrgRead,
            Self::WebhooksManage | Self::NotificationsManage => Permission::OrgManage,
        }
    }

    const fn resource_type(self) -> &'static str {
        match self {
            Self::WebhooksRead | Self::WebhooksManage => "webhook_endpoint",
            Self::NotificationsRead | Self::NotificationsManage => "notification",
        }
    }
}

// -----------------------------------------------------------------------------
// Request and response shapes
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateWebhookRequest {
    pub name: String,
    pub description: Option<String>,
    pub url: String,
    pub subscribed_event_types: Vec<String>,
    pub enabled: Option<bool>,
    pub max_attempts: Option<i64>,
    pub base_delay_seconds: Option<i64>,
    pub max_delay_seconds: Option<i64>,
    pub replay_window_seconds: Option<i64>,
    pub auto_disable_enabled: Option<bool>,
    pub auto_disable_threshold: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PatchWebhookRequest {
    pub name: Option<String>,
    pub description: Option<Option<String>>,
    pub url: Option<String>,
    pub subscribed_event_types: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub max_attempts: Option<i64>,
    pub base_delay_seconds: Option<i64>,
    pub max_delay_seconds: Option<i64>,
    pub replay_window_seconds: Option<i64>,
    pub auto_disable_enabled: Option<bool>,
    pub auto_disable_threshold: Option<i64>,
    pub version: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisableWebhookRequest {
    pub version: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayDeliveryRequest {
    pub version: i64,
}

#[derive(Debug, Deserialize)]
pub struct WebhookListQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    pub include_disabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct DeliveryListQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NotificationListQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    pub unread: Option<bool>,
    pub category: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PatchPreferenceRequest {
    pub channel: String,
    /// Current row version. `0` means the row must not exist yet.
    pub version: i64,
    pub disabled_event_types: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PageResponse<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

// -----------------------------------------------------------------------------
// Shared helpers
// -----------------------------------------------------------------------------

fn service_unavailable(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::ServiceUnavailable,
        "The notification store is unavailable.",
    )
}

fn not_found(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::NotFound,
        "The requested resource was not found.",
    )
    .with_detail("reason", json!("resource_not_found"))
}

fn denied(context: &RequestContext, code: ApiErrorCode, reason: &str, message: &str) -> ApiError {
    errors::api_error(context, code, message).with_detail("reason", json!(reason))
}

/// Validate the endpoint URL and normalize it. Every SSRF rejection surfaces a
/// frozen P06 reason and never echoes the URL back to the client.
fn normalize_url(context: &RequestContext, value: &str) -> Result<String, ApiError> {
    validate_endpoint_url(value)
        .map(|target| target.url().to_owned())
        .map_err(|rejection| {
            validation_error(
                context,
                rejection.reason(),
                "The webhook URL is not allowed.",
            )
        })
}

fn validate_name(context: &RequestContext, value: &str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 160 || trimmed.chars().any(char::is_control)
    {
        return Err(validation_error(
            context,
            "webhook_endpoint_invalid",
            "Enter a valid endpoint name.",
        ));
    }
    Ok(trimmed.to_owned())
}

fn validate_description(
    context: &RequestContext,
    value: Option<&str>,
) -> Result<Option<String>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.chars().count() > 2_000 {
        return Err(validation_error(
            context,
            "webhook_endpoint_invalid",
            "The description is too long.",
        ));
    }
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.chars().any(char::is_control) {
        return Err(validation_error(
            context,
            "webhook_endpoint_invalid",
            "The description contains invalid characters.",
        ));
    }
    Ok(Some(trimmed.to_owned()))
}

/// Validate a bounded, exact, wildcard-free subscription list.
fn validate_subscriptions(
    context: &RequestContext,
    values: &[String],
) -> Result<Vec<String>, ApiError> {
    if values.is_empty() || values.len() > crate::repositories::MAX_SUBSCRIPTION_EVENT_TYPES {
        return Err(validation_error(
            context,
            "webhook_endpoint_invalid",
            "Select at least one event type and no more than 64.",
        ));
    }
    let mut normalized: Vec<String> = Vec::with_capacity(values.len());
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.chars().count() > 96 {
            return Err(validation_error(
                context,
                "webhook_endpoint_invalid",
                "An event type in the subscription list is invalid.",
            ));
        }
        let known = is_subscribable_event_type(trimmed);
        let recursive = trimmed == "webhook.test.v1"
            || RECURSIVE_EVENT_PREFIXES
                .iter()
                .any(|prefix| trimmed.starts_with(prefix));
        if !known {
            return Err(validation_error(
                context,
                "webhook_endpoint_invalid",
                "An event type in the subscription list is not a supported event.",
            ));
        }
        if recursive {
            return Err(validation_error(
                context,
                "webhook_endpoint_invalid",
                "Delivery and endpoint events cannot be subscribed to.",
            ));
        }
        if !normalized.contains(&trimmed.to_owned()) {
            normalized.push(trimmed.to_owned());
        }
    }
    normalized.sort();
    Ok(normalized)
}

/// Exact frozen-name membership. A wildcard can never match, and a
/// well-formed but unregistered name is not silently accepted.
fn is_subscribable_event_type(value: &str) -> bool {
    P06_EVENT_TYPES.contains(&value) || P01_P05_EVENT_TYPES.contains(&value)
}

fn validate_bounded(
    context: &RequestContext,
    value: Option<i64>,
    default: i64,
    min: i64,
    max: i64,
    reason: &'static str,
) -> Result<i64, ApiError> {
    let value = value.unwrap_or(default);
    if !(min..=max).contains(&value) {
        return Err(validation_error(
            context,
            reason,
            "A delivery setting is out of range.",
        ));
    }
    Ok(value)
}

fn endpoint_json(
    context: &RequestContext,
    endpoint: &WebhookEndpointRecord,
) -> Result<Value, ApiError> {
    let subscriptions: Vec<String> = serde_json::from_str(&endpoint.subscribed_event_types_json)
        .map_err(|_| service_unavailable(context))?;
    Ok(json!({
        "endpoint_id": endpoint.endpoint_id,
        "org_id": endpoint.org_id,
        "name": endpoint.name,
        "description": endpoint.description,
        "url": endpoint.url,
        "subscribed_event_types": subscriptions,
        "secret_version_id": endpoint.current_secret_version_id,
        "enabled": endpoint.enabled,
        "max_attempts": endpoint.max_attempts,
        "base_delay_seconds": endpoint.base_delay_seconds,
        "max_delay_seconds": endpoint.max_delay_seconds,
        "replay_window_seconds": endpoint.replay_window_seconds,
        "auto_disable_enabled": endpoint.auto_disable_enabled,
        "auto_disable_threshold": endpoint.auto_disable_threshold,
        "consecutive_terminal_failures": endpoint.consecutive_terminal_failures,
        "version": endpoint.version,
        "created_at": endpoint.created_at,
        "updated_at": endpoint.updated_at,
    }))
}

async fn load_endpoint(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    org_id: &str,
    endpoint_id: &str,
) -> Result<WebhookEndpointRecord, ApiError> {
    let endpoint_id = validate_prefixed(context, endpoint_id, "whe", "webhook_endpoint_invalid")?;
    WebhookRepository::new(database)
        .find_endpoint(org_id, &endpoint_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .ok_or_else(|| not_found(context))
}

fn validate_prefixed(
    context: &RequestContext,
    value: &str,
    prefix: &str,
    reason: &'static str,
) -> Result<String, ApiError> {
    let id = crate::core::ResourceId::new(value)
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

/// Mint a new secret, encrypt it, and return the single response that contains
/// the plaintext. The plaintext is never bound into a statement, logged, or
/// returned by any later read.
async fn mint_secret(
    state: &Arc<AppState>,
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    endpoint_id: &str,
    org_id: &str,
    rotate: bool,
) -> Result<(String, String, worker::d1::D1PreparedStatement), ApiError> {
    let key = state.credential_key.as_deref().ok_or_else(|| {
        errors::api_error(
            context,
            ApiErrorCode::ServiceUnavailable,
            "The secret store is unavailable.",
        )
    })?;
    let plaintext = new_secret();
    let encrypted = crate::adapters::crypto::encrypt_secret(key, &plaintext)
        .await
        .map_err(|_| {
            errors::api_error(
                context,
                ApiErrorCode::ServiceUnavailable,
                "The secret store is unavailable.",
            )
        })?;
    let secret_version_id = new_resource_id("whs").as_str().to_owned();
    let version = WebhookRepository::new(database)
        .next_secret_version(endpoint_id)
        .await
        .map_err(|_| service_unavailable(context))?;
    let fingerprint = secret_fingerprint(&plaintext);
    let rotated_at = rotate.then(|| context.received_at.as_str().to_owned());
    let statement = WebhookRepository::new(database)
        .insert_secret_statement(&NewWebhookSecretInput {
            secret_version_id: &secret_version_id,
            endpoint_id,
            org_id,
            ciphertext_base64: &encrypted.ciphertext,
            nonce_base64: &encrypted.nonce,
            fingerprint: &fingerprint,
            version,
            rotated_at: rotated_at.as_deref(),
            now: &context.received_at,
        })
        .map_err(|error| database_error(context, error))?;
    Ok((secret_version_id, plaintext, statement))
}

fn audit_statement(
    database: &crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    principal: &Principal,
    org_id: &str,
    action: &str,
    resource_id: &str,
    metadata: &Value,
) -> Result<worker::d1::D1PreparedStatement, ApiError> {
    security_event_statement(
        database,
        context,
        Some(principal),
        Some(org_id),
        new_resource_id("sec").as_str(),
        action,
        "webhook_endpoint",
        Some(resource_id),
        "success",
        metadata,
    )
}

fn body_value<T: Serialize>(context: &RequestContext, body: &T) -> Result<Value, ApiError> {
    serde_json::to_value(body).map_err(|_| {
        errors::api_error(
            context,
            ApiErrorCode::InternalError,
            "The request could not be normalized.",
        )
    })
}

// -----------------------------------------------------------------------------
// Webhook endpoints
// -----------------------------------------------------------------------------

#[worker::send]
pub async fn list_webhooks(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<WebhookListQuery>,
    Path(org_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        P06Permission::WebhooksRead.central_permission(),
        Some(P06Permission::WebhooksRead.resource_type()),
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
    let mut records = WebhookRepository::new(database)
        .list_endpoints(
            &org_id,
            query.include_disabled.unwrap_or(false),
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
            .map(|record| encode_page_cursor(&record.updated_at, &record.endpoint_id))
    } else {
        None
    };
    let items = records
        .iter()
        .map(|record| endpoint_json(&context, record))
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
pub async fn create_webhook(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<CreateWebhookRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        P06Permission::WebhooksManage.central_permission(),
        Some(P06Permission::WebhooksManage.resource_type()),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let name = validate_name(&context, &body.name)?;
    let description = validate_description(&context, body.description.as_deref())?;
    let url = normalize_url(&context, &body.url)?;
    let subscriptions = validate_subscriptions(&context, &body.subscribed_event_types)?;
    let max_attempts = validate_bounded(
        &context,
        body.max_attempts,
        8,
        1,
        8,
        "webhook_endpoint_invalid",
    )?;
    let base_delay_seconds = validate_bounded(
        &context,
        body.base_delay_seconds,
        30,
        1,
        3_600,
        "webhook_endpoint_invalid",
    )?;
    let max_delay_seconds = validate_bounded(
        &context,
        body.max_delay_seconds,
        86_400,
        1,
        86_400,
        "webhook_endpoint_invalid",
    )?;
    if max_delay_seconds < base_delay_seconds {
        return Err(validation_error(
            &context,
            "webhook_endpoint_invalid",
            "The maximum delay must not be shorter than the base delay.",
        ));
    }
    let replay_window_seconds = validate_bounded(
        &context,
        body.replay_window_seconds,
        300,
        30,
        3_600,
        "webhook_endpoint_invalid",
    )?;
    let auto_disable_enabled = body.auto_disable_enabled.unwrap_or(false);
    let auto_disable_threshold = validate_bounded(
        &context,
        body.auto_disable_threshold,
        10,
        10,
        100,
        "webhook_endpoint_invalid",
    )?;
    let body_value = body_value(&context, &body)?;
    let database = database(&state, &context)?;
    let mutation = crate::routes::agents::prepare_mutation(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        "POST",
        WEBHOOKS_PATH,
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };
    let endpoint_id = new_resource_id("whe").as_str().to_owned();
    let subscriptions_json =
        serde_json::to_string(&subscriptions).map_err(|_| service_unavailable(&context))?;
    let enabled = body.enabled.unwrap_or(true);
    let insert = WebhookRepository::new(database)
        .insert_endpoint_statement(&NewWebhookEndpointInput {
            endpoint_id: &endpoint_id,
            org_id: &org_id,
            name: &name,
            description: description.as_deref(),
            url: &url,
            subscribed_event_types_json: &subscriptions_json,
            max_attempts,
            base_delay_seconds,
            max_delay_seconds,
            replay_window_seconds,
            auto_disable_enabled,
            auto_disable_threshold,
            created_by_user_id: access.principal.user_id.as_str(),
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let (secret_version_id, plaintext, secret) =
        mint_secret(&state, &context, database, &endpoint_id, &org_id, false).await?;
    let audit = audit_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        "webhook.endpoint_created.v1",
        &endpoint_id,
        &json!({
            "endpoint_id": endpoint_id,
            "version": 1,
            "enabled": enabled,
            "subscribed_event_types": subscriptions,
            "secret_version_id": secret_version_id,
        }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "webhook.endpoint_created.v1",
        &json!({
            "endpoint_id": endpoint_id,
            "version": 1,
            "enabled": enabled,
            "subscribed_event_types": subscriptions,
        }),
    )?;
    let response = json!({
        "endpoint": {
            "endpoint_id": endpoint_id,
            "org_id": org_id,
            "name": name,
            "description": description,
            "url": url,
            "subscribed_event_types": subscriptions,
            "secret_version_id": secret_version_id,
            "enabled": enabled,
            "max_attempts": max_attempts,
            "base_delay_seconds": base_delay_seconds,
            "max_delay_seconds": max_delay_seconds,
            "replay_window_seconds": replay_window_seconds,
            "auto_disable_enabled": auto_disable_enabled,
            "auto_disable_threshold": auto_disable_threshold,
            "consecutive_terminal_failures": 0,
            "version": 1,
            "created_at": context.received_at.as_str(),
            "updated_at": context.received_at.as_str(),
        },
        "secret": plaintext,
    });
    let success =
        StoredSuccess::new(201, response.clone()).map_err(|_| service_unavailable(&context))?;
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![insert, secret, audit],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

#[worker::send]
pub async fn patch_webhook(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, endpoint_id)): Path<(String, String)>,
    Json(body): Json<PatchWebhookRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        P06Permission::WebhooksManage.central_permission(),
        Some(P06Permission::WebhooksManage.resource_type()),
        Some(&endpoint_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    validate_version(&context, body.version)?;
    let database = database(&state, &context)?;
    let repository = WebhookRepository::new(database);
    let existing = load_endpoint(&context, database, &org_id, &endpoint_id).await?;
    if existing.version != body.version {
        return Err(version_conflict(&context));
    }
    let name = match body.name.as_deref() {
        Some(value) => validate_name(&context, value)?,
        None => existing.name.clone(),
    };
    let description = match body.description {
        Some(None) => None,
        Some(Some(value)) => validate_description(&context, Some(value.as_str()))?,
        None => existing.description.clone(),
    };
    let url = match body.url.as_deref() {
        Some(value) => normalize_url(&context, value)?,
        None => existing.url.clone(),
    };
    let subscriptions = match body.subscribed_event_types.as_ref() {
        Some(values) => validate_subscriptions(&context, values)?,
        None => serde_json::from_str::<Vec<String>>(&existing.subscribed_event_types_json)
            .map_err(|_| service_unavailable(&context))?,
    };
    let max_attempts = validate_bounded(
        &context,
        body.max_attempts,
        existing.max_attempts,
        1,
        8,
        "webhook_endpoint_invalid",
    )?;
    let base_delay_seconds = validate_bounded(
        &context,
        body.base_delay_seconds,
        existing.base_delay_seconds,
        1,
        3_600,
        "webhook_endpoint_invalid",
    )?;
    let max_delay_seconds = validate_bounded(
        &context,
        body.max_delay_seconds,
        existing.max_delay_seconds,
        1,
        86_400,
        "webhook_endpoint_invalid",
    )?;
    if max_delay_seconds < base_delay_seconds {
        return Err(validation_error(
            &context,
            "webhook_endpoint_invalid",
            "The maximum delay must not be shorter than the base delay.",
        ));
    }
    let replay_window_seconds = validate_bounded(
        &context,
        body.replay_window_seconds,
        existing.replay_window_seconds,
        30,
        3_600,
        "webhook_endpoint_invalid",
    )?;
    let auto_disable_enabled = body
        .auto_disable_enabled
        .unwrap_or(existing.auto_disable_enabled);
    let auto_disable_threshold = validate_bounded(
        &context,
        body.auto_disable_threshold,
        existing.auto_disable_threshold,
        10,
        100,
        "webhook_endpoint_invalid",
    )?;
    let enabled = body.enabled.unwrap_or(existing.enabled);
    let subscriptions_json =
        serde_json::to_string(&subscriptions).map_err(|_| service_unavailable(&context))?;
    let assertion = repository
        .assert_endpoint_version_statement(&existing.endpoint_id, &org_id, body.version)
        .map_err(|error| database_error(&context, error))?;
    let update = repository
        .update_endpoint_statement(&crate::repositories::WebhookEndpointUpdateInput {
            endpoint_id: &existing.endpoint_id,
            org_id: &org_id,
            name: &name,
            description: description.as_deref(),
            url: &url,
            subscribed_event_types_json: &subscriptions_json,
            enabled,
            max_attempts,
            base_delay_seconds,
            max_delay_seconds,
            replay_window_seconds,
            auto_disable_enabled,
            auto_disable_threshold,
            expected_version: body.version,
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let audit = audit_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        "webhook.endpoint_updated.v1",
        &existing.endpoint_id,
        &json!({
            "endpoint_id": existing.endpoint_id,
            "version": body.version + 1,
            "enabled": enabled,
        }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "webhook.endpoint_updated.v1",
        &json!({
            "endpoint_id": existing.endpoint_id,
            "version": body.version + 1,
            "enabled": enabled,
            "subscribed_event_types": subscriptions,
        }),
    )?;
    // The idempotency fingerprint covers the normalized request, not the raw
    // body, so an equivalent retry is recognized as a replay.
    let body_value = json!({
        "endpoint_id": existing.endpoint_id,
        "name": name,
        "description": description,
        "url": url,
        "subscribed_event_types": subscriptions,
        "enabled": enabled,
        "max_attempts": max_attempts,
        "base_delay_seconds": base_delay_seconds,
        "max_delay_seconds": max_delay_seconds,
        "replay_window_seconds": replay_window_seconds,
        "auto_disable_enabled": auto_disable_enabled,
        "auto_disable_threshold": auto_disable_threshold,
        "version": body.version,
    });
    let mutation = crate::routes::agents::prepare_mutation(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        "PATCH",
        WEBHOOK_PATH,
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedMutation::Replay(stored) => return Ok(replay_response(stored)),
        PreparedMutation::Claim(claim) => claim,
    };
    // The pre-check above returns the exact `version_conflict` reason; the
    // assertion statement closes the remaining race window by aborting the
    // whole batch when a concurrent writer moved the version. The stored success
    // body is the post-commit projection, so a replay returns the same version
    // the original caller saw.
    let success = StoredSuccess::new(
        200,
        json!({
            "endpoint_id": existing.endpoint_id,
            "org_id": org_id,
            "name": name,
            "description": description,
            "url": url,
            "subscribed_event_types": subscriptions,
            "secret_version_id": existing.current_secret_version_id,
            "enabled": enabled,
            "max_attempts": max_attempts,
            "base_delay_seconds": base_delay_seconds,
            "max_delay_seconds": max_delay_seconds,
            "replay_window_seconds": replay_window_seconds,
            "auto_disable_enabled": auto_disable_enabled,
            "auto_disable_threshold": auto_disable_threshold,
            "consecutive_terminal_failures": existing.consecutive_terminal_failures,
            "version": body.version + 1,
            "created_at": existing.created_at,
            "updated_at": context.received_at.as_str(),
        }),
    )
    .map_err(|_| service_unavailable(&context))?;
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![assertion, update, audit],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::OK, Json(success.body)).into_response())
}

#[worker::send]
pub async fn disable_webhook(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, endpoint_id)): Path<(String, String)>,
    Json(body): Json<DisableWebhookRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        P06Permission::WebhooksManage.central_permission(),
        Some(P06Permission::WebhooksManage.resource_type()),
        Some(&endpoint_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    validate_version(&context, body.version)?;
    let database = database(&state, &context)?;
    let repository = WebhookRepository::new(database);
    let existing = load_endpoint(&context, database, &org_id, &endpoint_id).await?;
    if existing.version != body.version {
        return Err(version_conflict(&context));
    }
    if !existing.enabled {
        // Disabling twice is a confirmed no-op, never a version conflict.
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    let assertion = repository
        .assert_endpoint_version_statement(&existing.endpoint_id, &org_id, body.version)
        .map_err(|error| database_error(&context, error))?;
    let disable = repository
        .disable_endpoint_statement(
            &existing.endpoint_id,
            &org_id,
            body.version,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    // Disabling cancels pending deliveries but keeps delivered/dead-letter
    // history.
    let cancel = repository
        .cancel_endpoint_deliveries_statement(&existing.endpoint_id, &context.received_at)
        .map_err(|error| database_error(&context, error))?;
    let audit = audit_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        "webhook.endpoint_disabled.v1",
        &existing.endpoint_id,
        &json!({ "endpoint_id": existing.endpoint_id, "version": body.version + 1 }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "webhook.endpoint_disabled.v1",
        &json!({
            "endpoint_id": existing.endpoint_id,
            "version": body.version + 1,
        }),
    )?;
    let success = StoredSuccess::new(204, json!({})).map_err(|_| service_unavailable(&context))?;
    let body_value = json!({ "endpoint_id": existing.endpoint_id, "version": body.version });
    let mutation = crate::routes::agents::prepare_mutation(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        "DELETE",
        WEBHOOK_PATH,
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedMutation::Replay(stored) => return Ok(replay_response(stored)),
        PreparedMutation::Claim(claim) => claim,
    };
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success,
        vec![assertion, disable, cancel, audit],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[worker::send]
pub async fn rotate_webhook_secret(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, endpoint_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        P06Permission::WebhooksManage.central_permission(),
        Some(P06Permission::WebhooksManage.resource_type()),
        Some(&endpoint_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let database = database(&state, &context)?;
    let existing = load_endpoint(&context, database, &org_id, &endpoint_id).await?;
    let body_value = json!({ "endpoint_id": existing.endpoint_id });
    let mutation = crate::routes::agents::prepare_mutation(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        "POST",
        WEBHOOK_ROTATE_PATH,
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };
    let (secret_version_id, plaintext, secret) = mint_secret(
        &state,
        &context,
        database,
        &existing.endpoint_id,
        &org_id,
        true,
    )
    .await?;
    let audit = audit_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        "webhook.endpoint_rotated.v1",
        &existing.endpoint_id,
        &json!({
            "endpoint_id": existing.endpoint_id,
            "secret_version_id": secret_version_id,
        }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "webhook.endpoint_rotated.v1",
        &json!({
            "endpoint_id": existing.endpoint_id,
            "secret_version_id": secret_version_id,
        }),
    )?;
    // `trg_webhook_secrets_set_current` repoints the endpoint in the same batch.
    let success = StoredSuccess::new(
        200,
        json!({
            "endpoint_id": existing.endpoint_id,
            "secret_version_id": secret_version_id,
            "secret": plaintext,
        }),
    )
    .map_err(|_| service_unavailable(&context))?;
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![secret, audit],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::OK, Json(success.body)).into_response())
}

#[worker::send]
pub async fn test_webhook(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, endpoint_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        P06Permission::WebhooksManage.central_permission(),
        Some(P06Permission::WebhooksManage.resource_type()),
        Some(&endpoint_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let database = database(&state, &context)?;
    let repository = WebhookRepository::new(database);
    let existing = load_endpoint(&context, database, &org_id, &endpoint_id).await?;
    if !existing.enabled {
        return Err(denied(
            &context,
            ApiErrorCode::Conflict,
            "webhook_endpoint_invalid",
            "The endpoint is disabled.",
        ));
    }
    // A test delivery uses the same tenant, SSRF, and signature path as a real
    // delivery, so the URL is revalidated here and again at delivery time.
    normalize_url(&context, &existing.url)?;
    let secret_version_id = existing.current_secret_version_id.clone().ok_or_else(|| {
        denied(
            &context,
            ApiErrorCode::Conflict,
            "webhook_endpoint_invalid",
            "The endpoint has no signing secret.",
        )
    })?;
    let body_value = json!({ "endpoint_id": existing.endpoint_id });
    let mutation = crate::routes::agents::prepare_mutation(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        "POST",
        WEBHOOK_TEST_PATH,
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };
    let delivery_id = new_resource_id("whd").as_str().to_owned();
    let event = test_event(&context, &access.principal, &org_id, &existing.endpoint_id);
    let serialized = serde_json::to_string(&event).map_err(|_| service_unavailable(&context))?;
    let insert = repository
        .insert_test_delivery_statement(&NewWebhookDeliveryInput {
            delivery_id: &delivery_id,
            endpoint_id: &existing.endpoint_id,
            org_id: &org_id,
            event_id: &event.event_id,
            event_type: crate::repositories::WEBHOOK_TEST_EVENT_TYPE,
            body: &serialized,
            body_hash: &body_hash(&serialized),
            secret_version_id: &secret_version_id,
            replay_of_delivery_id: None,
            replay_generation: 0,
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    // The job row is the queue hand-off; the delivery advances `pending ->
    // queued` in the same batch so the history never shows a delivery stuck
    // after its job exists.
    let queued = repository
        .mark_delivery_queued_statement(
            &delivery_id,
            WebhookDeliveryState::Pending,
            1,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let job = repository
        .insert_queue_job_statement(&crate::repositories::NewQueueJobInput {
            job_id: new_resource_id("job").as_str(),
            job_type: crate::repositories::JobType::WebhookDeliver,
            org_id: Some(&org_id),
            subject_type: "webhook_delivery",
            subject_id: &delivery_id,
            subject_version: None,
            dedupe_key: &format!("webhook.deliver:{delivery_id}"),
            event_id: Some(event.event_id.as_str()),
            request_id: Some(context.request_id.as_str()),
            correlation_id: Some(context.correlation_id.as_str()),
            payload_ref: Some(&format!("d1:webhook_deliveries/{delivery_id}")),
            next_attempt_at: None,
            replay_of_job_id: None,
            generation: 0,
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let audit = audit_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        "webhook.test.v1",
        &existing.endpoint_id,
        &json!({ "endpoint_id": existing.endpoint_id, "delivery_id": delivery_id }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "webhook.test.v1",
        &json!({
            "endpoint_id": existing.endpoint_id,
            "delivery_id": delivery_id,
        }),
    )?;
    let success = StoredSuccess::new(
        202,
        json!({
            "delivery_id": delivery_id,
            "endpoint_id": existing.endpoint_id,
            "event_id": event.event_id.as_str(),
            "state": "pending",
        }),
    )
    .map_err(|_| service_unavailable(&context))?;
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![insert, queued, job, audit],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::ACCEPTED, Json(success.body)).into_response())
}

#[worker::send]
pub async fn list_webhook_deliveries(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<DeliveryListQuery>,
    Path((org_id, endpoint_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        P06Permission::WebhooksRead.central_permission(),
        Some(P06Permission::WebhooksRead.resource_type()),
        Some(&endpoint_id),
    )
    .await?;
    if let Some(state_filter) = query.state.as_deref()
        && WebhookDeliveryState::parse(state_filter).is_none()
    {
        return Err(validation_error(
            &context,
            "webhook_endpoint_invalid",
            "The delivery state filter is invalid.",
        ));
    }
    let limit = page_limit(query.limit);
    let decoded = query
        .cursor
        .as_deref()
        .map(|raw| decode_page_cursor(raw, &context))
        .transpose()?;
    let (cursor_created, cursor_id) = decoded
        .as_ref()
        .map_or(("", ""), |(created, id)| (created.as_str(), id.as_str()));
    let database = database(&state, &context)?;
    let endpoint = load_endpoint(&context, database, &org_id, &endpoint_id).await?;
    let mut records = WebhookRepository::new(database)
        .list_deliveries(
            &org_id,
            &endpoint.endpoint_id,
            query.state.as_deref(),
            Some(DeliveryPageCursor {
                created_at: cursor_created,
                delivery_id: cursor_id,
            }),
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
            .map(|record| encode_page_cursor(&record.created_at, &record.delivery_id))
    } else {
        None
    };
    let items = records
        .iter()
        .map(|record| {
            json!({
                "delivery_id": record.delivery_id,
                "endpoint_id": record.endpoint_id,
                "event_id": record.event_id,
                "event_type": record.event_type,
                "body_hash": record.body_hash,
                "secret_version_id": record.secret_version_id,
                "signature_key_id": record.signature_key_id,
                "state": record.state,
                "attempt_count": record.attempt_count,
                "next_attempt_at": record.next_attempt_at,
                "delivered_at": record.delivered_at,
                "last_error_code": record.last_error_code,
                "replay_of_delivery_id": record.replay_of_delivery_id,
                "replay_generation": record.replay_generation,
                "version": record.version,
                "created_at": record.created_at,
                "updated_at": record.updated_at,
            })
        })
        .collect::<Vec<_>>();
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
pub async fn replay_webhook_delivery(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, delivery_id)): Path<(String, String)>,
    Json(body): Json<ReplayDeliveryRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        P06Permission::WebhooksManage.central_permission(),
        Some(P06Permission::WebhooksManage.resource_type()),
        Some(&delivery_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    validate_version(&context, body.version)?;
    let database = database(&state, &context)?;
    let repository = WebhookRepository::new(database);
    let delivery_id = validate_prefixed(&context, &delivery_id, "whd", "webhook_endpoint_invalid")?;
    let existing = repository
        .find_delivery(&org_id, &delivery_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context))?;
    if existing.version != body.version {
        return Err(version_conflict(&context));
    }
    let endpoint = load_endpoint(&context, database, &org_id, &existing.endpoint_id).await?;
    // A replay after rotation uses the CURRENT endpoint secret version.
    let secret_version_id = endpoint.current_secret_version_id.clone().ok_or_else(|| {
        denied(
            &context,
            ApiErrorCode::Conflict,
            "webhook_endpoint_invalid",
            "The endpoint has no signing secret.",
        )
    })?;
    normalize_url(&context, &endpoint.url)?;
    let successor_id = new_resource_id("whd").as_str().to_owned();
    let successor_generation = existing.replay_generation + 1;
    let job_id = new_resource_id("job").as_str().to_owned();
    let body_value = json!({ "delivery_id": existing.delivery_id, "version": body.version });
    let mutation = crate::routes::agents::prepare_mutation(
        database,
        &context,
        &access.principal,
        &org_id,
        &key,
        "POST",
        WEBHOOK_REPLAY_PATH,
        &body_value,
    )
    .await?;
    let claim = match mutation {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(claim) => claim,
    };
    let replayed_event_id = EventId::new(&existing.event_id).map_err(|_| {
        validation_error(
            &context,
            "webhook_endpoint_invalid",
            "The delivery is invalid.",
        )
    })?;
    // A replay always creates a SUCCESSOR logical delivery with the same event
    // ID and the same exact body. The original is never edited or reset.
    let insert = repository
        .insert_replay_delivery_statement(&NewWebhookDeliveryInput {
            delivery_id: &successor_id,
            endpoint_id: &existing.endpoint_id,
            org_id: &existing.org_id,
            event_id: &replayed_event_id,
            event_type: &existing.event_type,
            body: &existing.body,
            body_hash: &existing.body_hash,
            secret_version_id: &secret_version_id,
            replay_of_delivery_id: Some(&existing.delivery_id),
            replay_generation: successor_generation,
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let queued = repository
        .mark_delivery_queued_statement(
            &successor_id,
            WebhookDeliveryState::Pending,
            1,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let job = repository
        .insert_queue_job_statement(&crate::repositories::NewQueueJobInput {
            job_id: &job_id,
            job_type: crate::repositories::JobType::WebhookDeliver,
            org_id: Some(&org_id),
            subject_type: "webhook_delivery",
            subject_id: &successor_id,
            subject_version: None,
            dedupe_key: &format!("webhook.deliver:{successor_id}"),
            event_id: Some(&existing.event_id),
            request_id: Some(context.request_id.as_str()),
            correlation_id: Some(context.correlation_id.as_str()),
            payload_ref: Some(&format!("d1:webhook_deliveries/{successor_id}")),
            next_attempt_at: None,
            replay_of_job_id: None,
            generation: successor_generation,
            now: &context.received_at,
        })
        .map_err(|error| database_error(&context, error))?;
    let audit = audit_statement(
        database,
        &context,
        &access.principal,
        &org_id,
        "webhook.delivery_replayed.v1",
        &existing.delivery_id,
        &json!({
            "endpoint_id": existing.endpoint_id,
            "delivery_id": existing.delivery_id,
            "successor_delivery_id": successor_id,
        }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "webhook.delivery_replayed.v1",
        &json!({
            "endpoint_id": existing.endpoint_id,
            "delivery_id": existing.delivery_id,
            "successor_delivery_id": successor_id,
        }),
    )?;
    let success = StoredSuccess::new(
        201,
        json!({
            "delivery_id": successor_id,
            "replay_of_delivery_id": existing.delivery_id,
            "replay_generation": successor_generation,
            "event_id": existing.event_id,
            "body_hash": existing.body_hash,
            "secret_version_id": secret_version_id,
            "state": "pending",
        }),
    )
    .map_err(|_| service_unavailable(&context))?;
    if let Some(replay) = commit_mutation(
        database,
        &context,
        claim,
        success.clone(),
        vec![insert, queued, job, audit],
        outbox,
    )
    .await?
    {
        return Ok(replay_response(replay));
    }
    Ok((StatusCode::CREATED, Json(success.body)).into_response())
}

// -----------------------------------------------------------------------------
// Notification preferences
// -----------------------------------------------------------------------------

#[worker::send]
pub async fn get_notification_preferences(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        P06Permission::NotificationsRead.central_permission(),
        Some(P06Permission::NotificationsRead.resource_type()),
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let preferences = WebhookRepository::new(database)
        .list_preferences(Some(&org_id), access.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok((
        StatusCode::OK,
        Json(preferences_json(&context, preferences)?),
    )
        .into_response())
}

#[worker::send]
pub async fn patch_notification_preferences(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<PatchPreferenceRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        P06Permission::NotificationsManage.central_permission(),
        Some(P06Permission::NotificationsManage.resource_type()),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let database = database(&state, &context)?;
    patch_preference(
        &context,
        database,
        Some(&org_id),
        &access.principal,
        &key,
        ORG_PREFERENCES_PATH,
        body,
    )
    .await
}

#[worker::send]
pub async fn get_my_notification_preferences(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    let database = database(&state, &context)?;
    let preferences = WebhookRepository::new(database)
        .list_preferences(None, authenticated.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok((
        StatusCode::OK,
        Json(preferences_json(&context, preferences)?),
    )
        .into_response())
}

#[worker::send]
pub async fn patch_my_notification_preferences(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<PatchPreferenceRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    let database = database(&state, &context)?;
    patch_preference(
        &context,
        database,
        None,
        &authenticated.principal,
        &key,
        MY_PREFERENCES_PATH,
        body,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn patch_preference(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    org_id: Option<&str>,
    principal: &Principal,
    key: &str,
    path: &str,
    body: PatchPreferenceRequest,
) -> Result<Response<Body>, ApiError> {
    if !NOTIFICATION_CHANNELS.contains(&body.channel.as_str()) {
        return Err(validation_error(
            context,
            "notification_preference_invalid",
            "The notification channel is invalid.",
        ));
    }
    if body.version < 0 {
        return Err(validation_error(
            context,
            "notification_preference_invalid",
            "The resource version is invalid.",
        ));
    }
    let disabled = validate_disabled_event_types(context, &body.disabled_event_types)?;
    let repository = WebhookRepository::new(database);
    let existing = repository
        .find_preference(org_id, principal.user_id.as_str(), &body.channel)
        .await
        .map_err(|error| database_error(context, error))?;
    let expected_version = body.version;
    if existing.is_some() != (body.version > 0) {
        return Err(version_conflict(context));
    }
    if let Some(existing) = &existing
        && existing.version != body.version
    {
        return Err(version_conflict(context));
    }
    let next_version = existing.as_ref().map_or(1, |row| row.version + 1);
    let preference_id = new_resource_id("ntp").as_str().to_owned();
    let disabled_json =
        serde_json::to_string(&disabled).map_err(|_| service_unavailable(context))?;
    let assertion = repository
        .assert_preference_version_statement(
            org_id,
            principal.user_id.as_str(),
            &body.channel,
            expected_version,
        )
        .map_err(|error| database_error(context, error))?;
    let upsert = repository
        .upsert_preference_statement(&NotificationPreferenceUpdate {
            preference_id: &preference_id,
            org_id,
            user_id: principal.user_id.as_str(),
            channel: &body.channel,
            disabled_event_types_json: &disabled_json,
            expected_version,
            next_version,
            now: &context.received_at,
        })
        .map_err(|error| database_error(context, error))?;
    let audit = security_event_statement(
        database,
        context,
        Some(principal),
        org_id,
        new_resource_id("sec").as_str(),
        "notification.preference_updated.v1",
        "notification_preference",
        Some(&body.channel),
        "success",
        &json!({ "channel": body.channel, "version": next_version }),
    )?;
    let body_value = body_value(context, &body)?;
    // The P01 scope is used for replay and fingerprint-conflict detection. The
    // preference row's own `version` is the concurrency guard, so the claim
    // statement itself is intentionally not executed.
    match crate::routes::agents::prepare_mutation(
        database,
        context,
        principal,
        org_id.unwrap_or(""),
        key,
        "PATCH",
        path,
        &body_value,
    )
    .await?
    {
        PreparedMutation::Replay(success) => return Ok(replay_response(success)),
        PreparedMutation::Claim(_) => {}
    }
    let success = StoredSuccess::new(
        200,
        json!({
            "channel": body.channel,
            "disabled_event_types": disabled,
            "version": next_version,
            "updated_at": context.received_at.as_str(),
        }),
    )
    .map_err(|_| service_unavailable(context))?;
    // The preference PATCH has no frozen P01 event, so the batch commits the
    // version assertion, the upsert, the F16 audit row, and the idempotency
    // completion without an outbox row.
    let results = database
        .batch(vec![assertion, upsert, audit])
        .await
        .map_err(|error| database_error(context, error))?;
    if results.get(1).is_none_or(|result| {
        crate::adapters::d1::D1Adapter::changes(result).unwrap_or_default() != 1
    }) {
        return Err(version_conflict(context));
    }
    Ok((StatusCode::OK, Json(success.body)).into_response())
}

fn validate_disabled_event_types(
    context: &RequestContext,
    values: &[String],
) -> Result<Vec<String>, ApiError> {
    if values.len() > crate::repositories::MAX_SUBSCRIPTION_EVENT_TYPES {
        return Err(validation_error(
            context,
            "notification_preference_invalid",
            "The opt-out list is too large.",
        ));
    }
    let mut normalized: Vec<String> = Vec::with_capacity(values.len());
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.chars().count() > 96 {
            return Err(validation_error(
                context,
                "notification_preference_invalid",
                "An event type in the opt-out list is invalid.",
            ));
        }
        if EventType::new(trimmed).is_err() {
            return Err(validation_error(
                context,
                "notification_preference_invalid",
                "An event type in the opt-out list is not a supported event.",
            ));
        }
        // Mandatory security events cannot be opted out. The `0012` trigger
        // enforces the same rule, so the request is rejected before D1.
        if MANDATORY_EVENT_FRAGMENTS
            .iter()
            .any(|fragment| trimmed.contains(fragment))
        {
            return Err(denied(
                context,
                ApiErrorCode::PermissionDenied,
                "notification_preference_mandatory",
                "Security notifications cannot be disabled.",
            ));
        }
        if !normalized.contains(&trimmed.to_owned()) {
            normalized.push(trimmed.to_owned());
        }
    }
    normalized.sort();
    Ok(normalized)
}

fn preferences_json(
    context: &RequestContext,
    rows: Vec<crate::repositories::NotificationPreferenceRecord>,
) -> Result<Value, ApiError> {
    let mut items: Vec<Value> = Vec::new();
    for channel in NOTIFICATION_CHANNELS {
        let row = rows.iter().find(|row| row.channel == channel);
        let disabled: Vec<String> = match row {
            Some(row) => serde_json::from_str(&row.disabled_event_types_json)
                .map_err(|_| service_unavailable(context))?,
            None => Vec::new(),
        };
        items.push(json!({
            "channel": channel,
            "disabled_event_types": disabled,
            "version": row.map_or(0, |row| row.version),
            "updated_at": row.map(|row| row.updated_at.as_str()),
        }));
    }
    Ok(json!({ "preferences": items }))
}

// -----------------------------------------------------------------------------
// Notification center
// -----------------------------------------------------------------------------

#[worker::send]
pub async fn list_notifications(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<NotificationListQuery>,
) -> Result<Response<Body>, ApiError> {
    // The notification center is principal-scoped: the recipient is resolved
    // from the authenticated session, never from a path or body value.
    let authenticated = require_session(&state, &headers, &context).await?;
    if let Some(category) = query.category.as_deref()
        && !NOTIFICATION_CATEGORIES.contains(&category)
    {
        return Err(validation_error(
            &context,
            "notification_category_invalid",
            "The notification category is invalid.",
        ));
    }
    let limit = page_limit(query.limit);
    let cursor = query
        .cursor
        .as_deref()
        .map(|raw| decode_page_cursor(raw, &context))
        .transpose()?;
    let database = database(&state, &context)?;
    let mut records = WebhookRepository::new(database)
        .list_notifications(&NotificationFilters {
            user_id: authenticated.principal.user_id.as_str(),
            unread_only: query.unread.unwrap_or(false),
            category: query.category.as_deref(),
            cursor: cursor
                .as_ref()
                .map(|(created, id)| (created.as_str(), id.as_str())),
            limit: limit + 1,
        })
        .await
        .map_err(|error| database_error(&context, error))?;
    let has_more = records.len() > limit as usize;
    if has_more {
        records.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        records
            .last()
            .map(|record| encode_page_cursor(&record.created_at, &record.notification_id))
    } else {
        None
    };
    let items = records
        .iter()
        .map(|record| notification_json(&context, record))
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
pub async fn mark_notification_read(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(notification_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    let notification_id =
        validate_prefixed(&context, &notification_id, "ntf", "notification_id_invalid")?;
    let database = database(&state, &context)?;
    let repository = WebhookRepository::new(database);
    // A foreign notification ID returns the same non-disclosing not-found shape.
    let notification = repository
        .find_notification(authenticated.principal.user_id.as_str(), &notification_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context))?;
    let mark = repository
        .mark_notification_read_statement(
            authenticated.principal.user_id.as_str(),
            &notification.notification_id,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let audit = security_event_statement(
        database,
        &context,
        Some(&authenticated.principal),
        notification.org_id.as_deref(),
        new_resource_id("sec").as_str(),
        "notification.read.v1",
        "notification",
        Some(&notification.notification_id),
        "success",
        &json!({ "notification_id": notification.notification_id }),
    )?;
    // Marking read is idempotent, so no idempotency key is required: a repeat
    // touches zero rows and returns the same projection.
    database
        .batch(vec![mark, audit])
        .await
        .map_err(|error| database_error(&context, error))?;
    let refreshed = repository
        .find_notification(
            authenticated.principal.user_id.as_str(),
            &notification.notification_id,
        )
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| not_found(&context))?;
    Ok((
        StatusCode::OK,
        Json(notification_json(&context, &refreshed)?),
    )
        .into_response())
}

fn notification_json(
    context: &RequestContext,
    record: &crate::repositories::NotificationRecord,
) -> Result<Value, ApiError> {
    let body: Value =
        serde_json::from_str(&record.body_json).map_err(|_| service_unavailable(context))?;
    if serde_json::to_vec(&body)
        .map(|bytes| bytes.len() > crate::repositories::MAX_NOTIFICATION_BODY_BYTES)
        .unwrap_or(true)
    {
        return Err(service_unavailable(context));
    }
    Ok(json!({
        "notification_id": record.notification_id,
        "org_id": record.org_id,
        "event_id": record.event_id,
        "event_type": record.event_type,
        "category": record.category,
        "mandatory": record.mandatory,
        "state": record.state,
        "read_at": record.read_at,
        "body": body,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    }))
}

// -----------------------------------------------------------------------------
// Local helpers
// -----------------------------------------------------------------------------

fn validate_version(context: &RequestContext, version: i64) -> Result<(), ApiError> {
    if version <= 0 || version == i64::MAX {
        return Err(validation_error(
            context,
            "version_invalid",
            "The resource version is invalid.",
        ));
    }
    Ok(())
}

fn version_conflict(context: &RequestContext) -> ApiError {
    denied(
        context,
        ApiErrorCode::Conflict,
        "version_conflict",
        "The resource changed. Refresh and try again.",
    )
}

fn replay_response(success: StoredSuccess) -> Response<Body> {
    let status = StatusCode::from_u16(success.status).unwrap_or(StatusCode::OK);
    if status == StatusCode::NO_CONTENT {
        return status.into_response();
    }
    (status, Json(success.body)).into_response()
}

/// Build the dedicated, bounded `webhook.test.v1` envelope. It carries only the
/// endpoint identity, never a payload, prompt, credential, or secret.
fn test_event(
    context: &RequestContext,
    principal: &Principal,
    org_id: &str,
    endpoint_id: &str,
) -> crate::core::EventEnvelope {
    crate::core::EventEnvelope {
        event_id: crate::adapters::new_event_id(),
        event_type: EventType::new(crate::repositories::WEBHOOK_TEST_EVENT_TYPE)
            .expect("frozen P06 event type is valid"),
        occurred_at: context.received_at.clone(),
        request_id: context.request_id.clone(),
        correlation_id: context.correlation_id.clone(),
        actor: crate::core::ActorContext {
            actor_type: crate::core::ActorType::User,
            actor_id: Some(
                crate::core::ActorId::new(principal.user_id.as_str())
                    .expect("authenticated principal is a valid actor"),
            ),
            effective_user_id: Some(
                crate::core::ActorId::new(principal.user_id.as_str())
                    .expect("authenticated principal is a valid actor"),
            ),
        },
        organization_id: Some(
            crate::core::OrganizationId::new(org_id).expect("path organization is validated"),
        ),
        payload: json!({
            "schema_version": 1,
            "subject_type": "webhook_endpoint",
            "subject_id": endpoint_id,
            "resource_version": 1,
            "state": "test",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> RequestContext {
        RequestContext::new(
            "req_0123456789abcdef0123456789abcdef".parse().unwrap(),
            crate::core::CorrelationId::new("req_0123456789abcdef0123456789abcdef").unwrap(),
            "2026-09-25T16:00:00.000Z".parse().unwrap(),
        )
    }

    fn reason(error: &ApiError) -> String {
        error
            .error
            .details
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    }

    #[test]
    fn subscriptions_reject_wildcards_prefixes_and_unknown_names() {
        let context = context();
        assert!(
            validate_subscriptions(
                &context,
                &[
                    "run.completed.v1".to_owned(),
                    "auth.login.completed.v1".to_owned()
                ]
            )
            .is_ok()
        );
        for rejected in [
            vec![],
            vec!["*".to_owned()],
            vec!["run.*".to_owned()],
            vec!["run.".to_owned()],
            vec!["Run.Completed.v1".to_owned()],
            vec!["run.completed".to_owned()],
            vec!["made.up.event.v1".to_owned()],
            vec!["run.completed.v2".to_owned()],
            vec!["notifications.created.v1".to_owned()],
            vec!["run.completed.v1".to_owned(); 65],
        ] {
            let error = validate_subscriptions(&context, &rejected)
                .expect_err(&format!("accepted {rejected:?}"));
            assert_eq!(reason(&error), "webhook_endpoint_invalid");
        }
    }

    #[test]
    fn subscriptions_reject_the_recursive_delivery_and_endpoint_families() {
        let context = context();
        for rejected in [
            "webhook.test.v1",
            "webhook.delivery_succeeded.v1",
            "webhook.delivery_dead_lettered.v1",
            "webhook.endpoint_created.v1",
            "webhook.endpoint_rotated.v1",
            "notification.delivery_succeeded.v1",
        ] {
            let error =
                validate_subscriptions(&context, &[rejected.to_owned()]).expect_err(rejected);
            assert_eq!(reason(&error), "webhook_endpoint_invalid", "{rejected}");
        }
    }

    #[test]
    fn subscriptions_are_deduplicated_and_deterministically_ordered() {
        let context = context();
        let normalized = validate_subscriptions(
            &context,
            &[
                "run.completed.v1".to_owned(),
                "agent_definition.created.v1".to_owned(),
                "run.completed.v1".to_owned(),
            ],
        )
        .unwrap();
        assert_eq!(
            normalized,
            vec![
                "agent_definition.created.v1".to_owned(),
                "run.completed.v1".to_owned()
            ]
        );
    }

    #[test]
    fn url_validation_surfaces_the_frozen_p06_reasons() {
        let context = context();
        assert_eq!(
            reason(&normalize_url(&context, "http://hooks.example.com/x").unwrap_err()),
            "webhook_https_required"
        );
        for blocked in [
            "https://127.0.0.1/x",
            "https://10.0.0.1/x",
            "https://169.254.169.254/latest/meta-data",
            "https://user:pass@hooks.example.com/x",
            "https://hooks.example.com:8080/x",
        ] {
            assert_eq!(
                reason(&normalize_url(&context, blocked).unwrap_err()),
                "webhook_url_blocked",
                "{blocked}"
            );
        }
        assert_eq!(
            reason(&normalize_url(&context, "not a url").unwrap_err()),
            "webhook_endpoint_invalid"
        );
        assert_eq!(
            normalize_url(&context, "https://hooks.example.com/events").unwrap(),
            "https://hooks.example.com/events"
        );
    }

    #[test]
    fn mandatory_security_events_cannot_be_opted_out_of() {
        let context = context();
        for mandatory in [
            "auth.login.completed.v1",
            "device.revoked.v1",
            "organization.suspended.v1",
        ] {
            let error = validate_disabled_event_types(&context, &[mandatory.to_owned()])
                .expect_err(mandatory);
            assert_eq!(
                reason(&error),
                "notification_preference_mandatory",
                "{mandatory}"
            );
        }
        assert_eq!(
            validate_disabled_event_types(
                &context,
                &["billing.subscription_updated.v1".to_owned()]
            )
            .unwrap(),
            vec!["billing.subscription_updated.v1".to_owned()]
        );
        assert_eq!(
            reason(
                &validate_disabled_event_types(&context, &["not-an-event".to_owned()]).unwrap_err()
            ),
            "notification_preference_invalid"
        );
    }

    #[test]
    fn p06_permissions_map_to_the_central_role_bands() {
        // Mutations are owner/admin only; reads are available to every active role.
        assert!(matches!(
            P06Permission::WebhooksManage.central_permission(),
            Permission::OrgManage
        ));
        assert!(matches!(
            P06Permission::NotificationsManage.central_permission(),
            Permission::OrgManage
        ));
        assert!(matches!(
            P06Permission::WebhooksRead.central_permission(),
            Permission::OrgRead
        ));
        assert!(matches!(
            P06Permission::NotificationsRead.central_permission(),
            Permission::OrgRead
        ));
        assert_eq!(
            P06Permission::WebhooksManage.resource_type(),
            "webhook_endpoint"
        );
        assert_eq!(
            P06Permission::NotificationsManage.resource_type(),
            "notification"
        );
    }

    #[test]
    fn frozen_p06_event_list_is_complete_and_contains_no_wildcard() {
        assert_eq!(P06_EVENT_TYPES.len(), 48);
        for event in P06_EVENT_TYPES {
            assert!(EventType::new(*event).is_ok(), "{event}");
            assert!(!event.contains('*'), "{event}");
        }
        // Every frozen name in either registry is subscribable, and a
        // well-formed name outside both registries is not.
        for event in P06_EVENT_TYPES.iter().chain(P01_P05_EVENT_TYPES) {
            assert!(is_subscribable_event_type(event), "{event}");
        }
        assert!(!is_subscribable_event_type("made.up.event.v1"));
        assert!(!is_subscribable_event_type("run.completed.v2"));
        assert!(!is_subscribable_event_type("*"));
        // Every fan-out-excluded family is still a real frozen name.
        for event in [
            "webhook.endpoint_created.v1",
            "webhook.test.v1",
            "webhook.delivery_replayed.v1",
            "notification.delivery_succeeded.v1",
        ] {
            assert!(P06_EVENT_TYPES.contains(&event), "missing {event}");
        }
    }

    #[test]
    fn delivery_and_version_bounds_match_the_frozen_schema() {
        let context = context();
        for invalid in [0, -1, i64::MAX] {
            assert_eq!(
                reason(&validate_version(&context, invalid).unwrap_err()),
                "version_invalid"
            );
        }
        assert!(validate_version(&context, 1).is_ok());
        assert!(matches!(
            WebhookDeliveryState::parse("delivered"),
            Some(WebhookDeliveryState::Delivered)
        ));
        assert!(WebhookDeliveryState::parse("queued-typo").is_none());
    }
}
