//! P05 event registry and queue handlers.
//!
//! P05 domain transactions own the authoritative state transition and may
//! append their F16 security row in the same D1 batch.  Queue delivery is
//! still at-least-once, so this module provides two safe layers:
//!
//! * [`P05EventHandler`] validates the frozen event registry and redacts any
//!   payload before it can reach a side effect or diagnostic.
//! * [`P05AuditEventHandler`] is an optional durable projection for callers
//!   that intentionally want the queue to append the security-event row.  Its
//!   insert is idempotent by the immutable outbox event ID.
//!
//! The existing outbox consumer remains the source of retry, dead-letter, and
//! duplicate-delivery state transitions.  No payload is formatted into a
//! failure or debug record here.

use std::fmt;

use serde_json::{Map, Value};

use super::outbox::ProductEventHandler;

use crate::{
    adapters::{d1::D1Adapter, queues::consume_queue_batch},
    core::{
        ActorContext, ActorType, AgentSessionId, EventEnvelope, ManagedDeviceId, ProjectId,
        ResourceId, RunId, SecurityEventId, SessionId, Timestamp, ToolCallId,
    },
    modules::outbox::{EventHandler, FailureCode, HandlerFailure, OutboxStore, RetryPolicy},
    repositories::{AuditAppendOutcome, AuditEventInput, AuditRepository, bounded_metadata},
};

/// Maximum raw envelope payload accepted before projection. The persisted
/// audit metadata is bounded more tightly by `bounded_metadata`.
pub const MAX_P05_PAYLOAD_BYTES: usize = 64 * 1024;

/// Every event name frozen by `P05-CG` for the managed run control loop.
/// Unlisted names are intentionally permanent handler failures; adding an
/// event name requires the contract/change-request path rather than silently
/// acknowledging an unknown operational message.
pub const P05_EVENT_TYPES: &[&str] = &[
    "agent_definition.created.v1",
    "agent_definition.updated.v1",
    "session.created.v1",
    "session.closed.v1",
    "run.created.v1",
    "run.state_changed.v1",
    "run.started.v1",
    "run.completed.v1",
    "run.failed.v1",
    "run.cancelled.v1",
    "run.retried.v1",
    "run.event_appended.v1",
    "tool.catalog_updated.v1",
    "tool.mcp_registration_changed.v1",
    "tool.decision_recorded.v1",
    "tool.result.v1",
    "tool.denied.v1",
    "tool.approval_requested.v1",
    "approval.requested.v1",
    "approval.resolved.v1",
    "usage.reconciled.v1",
    "budget.reserved.v1",
    "budget.reconciled.v1",
    "budget.denied.v1",
    "rate_limit.denied.v1",
    "artifact.created.v1",
];

/// Explicit registry aliases for coordinator-owned integration code.
pub const P05_EVENT_REGISTRY: &[&str] = P05_EVENT_TYPES;
#[allow(dead_code)]
pub const P05_SUPPORTED_EVENT_TYPES: &[&str] = P05_EVENT_TYPES;

pub fn is_p05_event_type(event_type: &str) -> bool {
    P05_EVENT_REGISTRY.contains(&event_type)
}

/// Map a P05 event type to its stable audit resource shape.  The mapping is
/// deliberately explicit: adding a new event name requires a contract review
/// rather than silently turning arbitrary payload fields into a resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P05EventDescriptor {
    pub event_type: &'static str,
    pub resource_type: &'static str,
    pub resource_keys: &'static [&'static str],
    pub default_outcome: &'static str,
    pub default_reason: Option<&'static str>,
}

const RUN_KEYS: &[&str] = &["run_id", "resource_id"];
const AGENT_KEYS: &[&str] = &["agent_definition_id", "agent_id", "resource_id"];
const SESSION_KEYS: &[&str] = &["agent_session_id", "resource_id"];
const TOOL_CALL_KEYS: &[&str] = &["tool_call_id", "resource_id"];
const APPROVAL_KEYS: &[&str] = &["approval_id", "resource_id"];
const USAGE_KEYS: &[&str] = &["usage_event_id", "resource_id"];
const BUDGET_KEYS: &[&str] = &["budget_id", "reservation_id", "resource_id"];
const RATE_KEYS: &[&str] = &["scope_id", "rate_limit_policy_id", "resource_id"];
const TOOL_CATALOG_KEYS: &[&str] = &["tool_id", "resource_id"];
const MCP_KEYS: &[&str] = &["mcp_id", "resource_id"];
const ARTIFACT_KEYS: &[&str] = &["artifact_id", "resource_id"];

pub fn descriptor_for(event_type: &str) -> Option<P05EventDescriptor> {
    let (resource_type, resource_keys, default_outcome, default_reason) = match event_type {
        "agent_definition.created.v1" | "agent_definition.updated.v1" => {
            ("agent_definition", AGENT_KEYS, "success", None)
        }
        "session.created.v1" | "session.closed.v1" => {
            ("agent_session", SESSION_KEYS, "success", None)
        }
        "run.created.v1"
        | "run.state_changed.v1"
        | "run.started.v1"
        | "run.completed.v1"
        | "run.failed.v1"
        | "run.cancelled.v1"
        | "run.retried.v1"
        | "run.event_appended.v1" => ("run", RUN_KEYS, "success", None),
        "tool.catalog_updated.v1" => ("tool_catalog", TOOL_CATALOG_KEYS, "success", None),
        "tool.mcp_registration_changed.v1" => ("mcp_registration", MCP_KEYS, "success", None),
        "tool.decision_recorded.v1" | "tool.result.v1" => {
            ("tool_call", TOOL_CALL_KEYS, "success", None)
        }
        "tool.denied.v1" => ("tool_call", TOOL_CALL_KEYS, "denied", Some("tool_denied")),
        "tool.approval_requested.v1" | "approval.requested.v1" => {
            ("approval", APPROVAL_KEYS, "success", None)
        }
        "approval.resolved.v1" => ("approval", APPROVAL_KEYS, "success", None),
        "usage.reconciled.v1" => ("usage_event", USAGE_KEYS, "success", None),
        "budget.reserved.v1" | "budget.reconciled.v1" => {
            ("budget_reservation", BUDGET_KEYS, "success", None)
        }
        "budget.denied.v1" => ("budget", BUDGET_KEYS, "denied", Some("budget_exceeded")),
        "rate_limit.denied.v1" => (
            "rate_limit",
            RATE_KEYS,
            "denied",
            Some("rate_limit_exceeded"),
        ),
        "artifact.created.v1" => ("artifact", ARTIFACT_KEYS, "success", None),
        _ => return None,
    };
    Some(P05EventDescriptor {
        event_type: P05_EVENT_TYPES
            .iter()
            .copied()
            .find(|candidate| *candidate == event_type)?,
        resource_type,
        resource_keys,
        default_outcome,
        default_reason,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P05EventError {
    UnsupportedEventType,
    MissingOrganization,
    InvalidPayload,
    CrossTenantPayload,
    PayloadTooLarge,
    InvalidEventId,
}

impl fmt::Display for P05EventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedEventType => "unsupported P05 event type",
            Self::MissingOrganization => "P05 event is missing organization scope",
            Self::InvalidPayload => "P05 event payload is invalid",
            Self::CrossTenantPayload => "P05 event payload crosses organization scope",
            Self::PayloadTooLarge => "P05 event payload is too large",
            Self::InvalidEventId => "P05 event ID is invalid",
        };
        f.write_str(message)
    }
}

impl std::error::Error for P05EventError {}

/// Owned, redacted projection used by the optional durable audit handler.
/// The raw event payload is never retained in this value.
#[derive(Clone)]
pub struct P05AuditProjection {
    pub event_id: String,
    pub organization_id: String,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub effective_user_id: Option<String>,
    pub session_id: Option<String>,
    pub device_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub outcome: String,
    pub reason: Option<String>,
    pub metadata: Value,
    pub request_id: String,
    pub correlation_id: String,
    pub run_id: Option<String>,
    pub agent_session_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub project_id: Option<String>,
    pub created_at: Timestamp,
}

impl fmt::Debug for P05AuditProjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("P05AuditProjection")
            .field("event_id", &self.event_id)
            .field("organization_id", &self.organization_id)
            .field("actor_type", &self.actor_type)
            .field("actor_id", &self.actor_id.as_ref().map(|_| "[redacted]"))
            .field(
                "effective_user_id",
                &self.effective_user_id.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "session_id",
                &self.session_id.as_ref().map(|_| "[redacted]"),
            )
            .field("device_id", &self.device_id.as_ref().map(|_| "[redacted]"))
            .field("action", &self.action)
            .field("resource_type", &self.resource_type)
            .field("resource_id", &self.resource_id)
            .field("outcome", &self.outcome)
            .field("reason", &self.reason)
            .field("metadata", &"[redacted]")
            .field("request_id", &self.request_id)
            .field("correlation_id", &self.correlation_id)
            .field("run_id", &self.run_id)
            .field("agent_session_id", &self.agent_session_id)
            .field("tool_call_id", &self.tool_call_id)
            .field("project_id", &self.project_id)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl P05AuditProjection {
    pub fn from_event(event: &EventEnvelope) -> Result<Self, P05EventError> {
        let descriptor =
            descriptor_for(event.event_type.as_str()).ok_or(P05EventError::UnsupportedEventType)?;
        if serde_json::to_vec(&event.payload)
            .map(|bytes| bytes.len() > MAX_P05_PAYLOAD_BYTES)
            .unwrap_or(true)
        {
            return Err(P05EventError::PayloadTooLarge);
        }
        let organization_id = event
            .organization_id
            .as_ref()
            .ok_or(P05EventError::MissingOrganization)?
            .as_str()
            .to_owned();
        let payload = event
            .payload
            .as_object()
            .ok_or(P05EventError::InvalidPayload)?;
        for key in ["org_id", "organization_id"] {
            if let Some(value) = payload.get(key) {
                let value = value.as_str().ok_or(P05EventError::InvalidPayload)?;
                if value != organization_id {
                    return Err(P05EventError::CrossTenantPayload);
                }
            }
        }

        let run_id = payload_string(payload, &["run_id"])?;
        let agent_session_id = payload_string(payload, &["agent_session_id"])?;
        let tool_call_id = payload_string(payload, &["tool_call_id"])?;
        if run_id
            .as_deref()
            .is_some_and(|value| RunId::new(value).is_err())
            || agent_session_id
                .as_deref()
                .is_some_and(|value| AgentSessionId::new(value).is_err())
            || tool_call_id
                .as_deref()
                .is_some_and(|value| ToolCallId::new(value).is_err())
        {
            return Err(P05EventError::InvalidPayload);
        }
        let project_id = payload_string(payload, &["project_id"])?;
        if project_id
            .as_deref()
            .is_some_and(|value| ProjectId::new(value).is_err())
        {
            return Err(P05EventError::InvalidPayload);
        }
        let device_id = payload_string(payload, &["device_id"])?.or_else(|| {
            event
                .actor
                .actor_id
                .as_ref()
                .filter(|id| id.as_str().starts_with("dvc_"))
                .map(|id| id.as_str().to_owned())
        });
        if device_id
            .as_deref()
            .is_some_and(|value| ManagedDeviceId::new(value).is_err())
        {
            return Err(P05EventError::InvalidPayload);
        }
        let session_id = payload_string(payload, &["login_session_id"])?.or_else(|| {
            payload
                .get("session_id")
                .and_then(Value::as_str)
                .filter(|value| value.starts_with("ses_"))
                .map(str::to_owned)
        });
        if session_id
            .as_deref()
            .is_some_and(|value| SessionId::new(value).is_err())
        {
            return Err(P05EventError::InvalidPayload);
        }
        let resource_id = payload_string(payload, descriptor.resource_keys)?;
        if resource_id
            .as_deref()
            .is_some_and(|value| ResourceId::new(value).is_err())
        {
            return Err(P05EventError::InvalidPayload);
        }
        let outcome = outcome_for(descriptor, payload)?;
        let reason = reason_for(descriptor, payload, &outcome);
        let actor_type = actor_type_for(&event.actor, device_id.as_deref());
        let actor_kind = actor_kind_for(&event.actor, device_id.as_deref());
        let mut metadata = match bounded_metadata(&event.payload) {
            Value::Object(value) => value,
            _ => Map::new(),
        };
        insert_metadata_string(&mut metadata, "event_type", Some(descriptor.event_type));
        insert_metadata_string(&mut metadata, "request_id", Some(event.request_id.as_str()));
        insert_metadata_string(
            &mut metadata,
            "correlation_id",
            Some(event.correlation_id.as_str()),
        );
        insert_metadata_string(&mut metadata, "actor_kind", Some(actor_kind));
        insert_metadata_string(&mut metadata, "run_id", run_id.as_deref());
        insert_metadata_string(
            &mut metadata,
            "agent_session_id",
            agent_session_id.as_deref(),
        );
        insert_metadata_string(&mut metadata, "tool_call_id", tool_call_id.as_deref());
        insert_metadata_string(&mut metadata, "project_id", project_id.as_deref());
        insert_metadata_string(&mut metadata, "device_id", device_id.as_deref());
        insert_metadata_string(&mut metadata, "login_session_id", session_id.as_deref());
        let metadata = bounded_metadata(&Value::Object(metadata));
        let event_id = p05_audit_event_id(event.event_id.as_str())?;
        let actor_id = event
            .actor
            .actor_id
            .as_ref()
            .map(|value| value.as_str().to_owned());
        let effective_user_id = event
            .actor
            .effective_user_id
            .as_ref()
            .map(|value| value.as_str().to_owned());

        Ok(Self {
            event_id,
            organization_id,
            actor_type,
            actor_id,
            effective_user_id,
            session_id,
            device_id,
            run_id,
            agent_session_id,
            tool_call_id,
            action: descriptor.event_type.to_owned(),
            resource_type: descriptor.resource_type.to_owned(),
            resource_id,
            outcome,
            reason,
            metadata,
            request_id: event.request_id.as_str().to_owned(),
            correlation_id: event.correlation_id.as_str().to_owned(),
            project_id,
            created_at: event.occurred_at.clone(),
        })
    }
}

/// Derive the stable F16 `sec_` identifier from an immutable `evt_` outbox
/// identifier.  The same event therefore maps to one audit primary key on
/// every Queue redelivery.
pub fn p05_audit_event_id(event_id: &str) -> Result<String, P05EventError> {
    let suffix = event_id
        .strip_prefix("evt_")
        .ok_or(P05EventError::InvalidEventId)?;
    let value = format!("sec_{suffix}");
    SecurityEventId::new(value.clone())
        .map(|_| value)
        .map_err(|_| P05EventError::InvalidEventId)
}

/// Registry-only handler.  It is intentionally side-effect free: the domain
/// transaction can append its audit row atomically, and the existing outbox
/// consumer still owns durable duplicate/ retry / dead-letter transitions.
#[derive(Clone, Copy, Debug, Default)]
pub struct P05EventHandler;

impl EventHandler for P05EventHandler {
    async fn handle_once(&self, event: &EventEnvelope) -> Result<(), HandlerFailure> {
        P05AuditProjection::from_event(event)
            .map(|_| ())
            .map_err(event_failure)
    }
}

/// All-event handler that leaves the existing P01-P04 registry authoritative
/// while routing the frozen P05 names through the P05 validator. This lets the
/// coordinator wire one queue handler without editing the legacy handler's
/// private registry in this packet.
#[derive(Clone, Copy, Debug, Default)]
#[allow(dead_code)]
pub struct P05AwareEventHandler;

impl EventHandler for P05AwareEventHandler {
    async fn handle_once(&self, event: &EventEnvelope) -> Result<(), HandlerFailure> {
        if is_p05_event_type(event.event_type.as_str()) {
            P05EventHandler.handle_once(event).await
        } else {
            ProductEventHandler.handle_once(event).await
        }
    }
}

/// Optional queue-side audit projection. Use this only when a producer cannot
/// write the F16 row in its business transaction; do not enable it alongside a
/// producer that already appends the same event. `append_idempotent` is an
/// atomic insert-or-duplicate operation, so retries cannot duplicate history.
pub struct P05AuditEventHandler<'a> {
    repository: AuditRepository<'a>,
}

impl<'a> P05AuditEventHandler<'a> {
    pub const fn new(database: &'a D1Adapter) -> Self {
        Self {
            repository: AuditRepository::new(database),
        }
    }
}

impl EventHandler for P05AuditEventHandler<'_> {
    async fn handle_once(&self, event: &EventEnvelope) -> Result<(), HandlerFailure> {
        let projection = P05AuditProjection::from_event(event).map_err(event_failure)?;
        let input = AuditEventInput {
            event_id: &projection.event_id,
            organization_id: &projection.organization_id,
            actor_type: &projection.actor_type,
            actor_id: projection.actor_id.as_deref(),
            effective_user_id: projection.effective_user_id.as_deref(),
            session_id: projection.session_id.as_deref(),
            device_id: projection.device_id.as_deref(),
            run_id: projection.run_id.as_deref(),
            agent_session_id: projection.agent_session_id.as_deref(),
            tool_call_id: projection.tool_call_id.as_deref(),
            action: &projection.action,
            resource_type: &projection.resource_type,
            resource_id: projection.resource_id.as_deref(),
            outcome: &projection.outcome,
            reason: projection.reason.as_deref(),
            metadata: &projection.metadata,
            request_id: &projection.request_id,
            correlation_id: &projection.correlation_id,
            created_at: &projection.created_at,
        };
        match self.repository.append_idempotent(&input).await {
            Ok(AuditAppendOutcome::Inserted | AuditAppendOutcome::Duplicate) => Ok(()),
            Err(_) => Err(HandlerFailure::retryable(
                FailureCode::new("audit_store_unavailable")
                    .expect("static P05 failure code is valid"),
            )),
        }
    }
}

/// Consume only P05 registry events.  The coordinator can use this wrapper
/// when a dedicated queue is configured, or merge [`P05EventHandler`] into
/// the existing all-event handler in `consumers/outbox.rs`.
#[allow(dead_code)]
pub async fn consume_p05_batch<S>(
    batch: &worker::MessageBatch<serde_json::Value>,
    store: &S,
    now: &Timestamp,
    retry_policy: RetryPolicy,
    dead_letter_queue: &str,
) -> worker::Result<()>
where
    S: OutboxStore,
{
    let handler = P05EventHandler;
    consume_queue_batch(batch, store, &handler, now, retry_policy, dead_letter_queue).await
}

/// Consume the existing P01-P04 stream plus the frozen P05 registry with one
/// handler. The shared outbox store still owns duplicate/retry transitions.
#[allow(dead_code)]
pub async fn consume_p05_aware_batch<S>(
    batch: &worker::MessageBatch<serde_json::Value>,
    store: &S,
    now: &Timestamp,
    retry_policy: RetryPolicy,
    dead_letter_queue: &str,
) -> worker::Result<()>
where
    S: OutboxStore,
{
    let handler = P05AwareEventHandler;
    consume_queue_batch(batch, store, &handler, now, retry_policy, dead_letter_queue).await
}

/// Queue-side variant for deployments that intentionally use asynchronous
/// audit projection.  It preserves the same OutboxConsumer retry and
/// dead-letter behavior as the registry-only wrapper.
#[allow(dead_code)]
pub async fn consume_p05_audit_batch<S>(
    batch: &worker::MessageBatch<serde_json::Value>,
    store: &S,
    database: &D1Adapter,
    now: &Timestamp,
    retry_policy: RetryPolicy,
    dead_letter_queue: &str,
) -> worker::Result<()>
where
    S: OutboxStore,
{
    let handler = P05AuditEventHandler::new(database);
    consume_queue_batch(batch, store, &handler, now, retry_policy, dead_letter_queue).await
}

fn event_failure(error: P05EventError) -> HandlerFailure {
    let code = match error {
        P05EventError::UnsupportedEventType => "unsupported_event_type",
        P05EventError::MissingOrganization => "p05_event_scope_missing",
        P05EventError::InvalidPayload => "p05_event_payload_invalid",
        P05EventError::CrossTenantPayload => "p05_event_scope_mismatch",
        P05EventError::PayloadTooLarge => "p05_event_payload_too_large",
        P05EventError::InvalidEventId => "p05_event_id_invalid",
    };
    HandlerFailure::permanent(FailureCode::new(code).expect("static P05 failure code is valid"))
}

fn actor_type_for(actor: &ActorContext, device_id: Option<&str>) -> String {
    if actor
        .actor_id
        .as_ref()
        .is_some_and(|id| id.as_str().starts_with("dvc_"))
        || (matches!(actor.actor_type, ActorType::Anonymous) && device_id.is_some())
    {
        return "system".to_owned();
    }
    match actor.actor_type {
        ActorType::User => "user",
        ActorType::ServiceAccount => "service_account",
        ActorType::Support => "support",
        ActorType::System => "system",
        ActorType::Anonymous => "anonymous",
    }
    .to_owned()
}

fn actor_kind_for(actor: &ActorContext, device_id: Option<&str>) -> &'static str {
    if actor
        .actor_id
        .as_ref()
        .is_some_and(|id| id.as_str().starts_with("dvc_"))
        || (matches!(actor.actor_type, ActorType::Anonymous) && device_id.is_some())
    {
        return "device";
    }
    match actor.actor_type {
        ActorType::User => "user",
        ActorType::ServiceAccount => "service_account",
        ActorType::Support => "support",
        ActorType::System => "system",
        ActorType::Anonymous => "anonymous",
    }
}

fn payload_string(
    payload: &Map<String, Value>,
    keys: &[&str],
) -> Result<Option<String>, P05EventError> {
    for key in keys {
        let Some(value) = payload.get(*key) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        let value = value.as_str().ok_or(P05EventError::InvalidPayload)?;
        if value.is_empty() || value.chars().count() > 255 || value.chars().any(char::is_control) {
            return Err(P05EventError::InvalidPayload);
        }
        return Ok(Some(value.to_owned()));
    }
    Ok(None)
}

fn outcome_for(
    descriptor: P05EventDescriptor,
    payload: &Map<String, Value>,
) -> Result<String, P05EventError> {
    if let Some(value) = payload.get("outcome") {
        let value = value.as_str().ok_or(P05EventError::InvalidPayload)?;
        if !matches!(value, "success" | "denied" | "failure") {
            return Err(P05EventError::InvalidPayload);
        }
        if descriptor.default_outcome == "denied" {
            return Ok("denied".to_owned());
        }
        return Ok(value.to_owned());
    }
    if let Some(value) = payload.get("decision") {
        let value = value.as_str().ok_or(P05EventError::InvalidPayload)?;
        if value == "deny" || value == "denied" {
            return Ok("denied".to_owned());
        }
    }
    Ok(descriptor.default_outcome.to_owned())
}

fn reason_for(
    descriptor: P05EventDescriptor,
    payload: &Map<String, Value>,
    outcome: &str,
) -> Option<String> {
    let candidate = ["reason", "reason_code", "failure_code", "error_code"]
        .into_iter()
        .find_map(|key| payload.get(key).and_then(Value::as_str));
    if let Some(candidate) = candidate
        && is_stable_code(candidate)
    {
        return Some(candidate.to_owned());
    }
    if outcome == "denied" {
        return descriptor.default_reason.map(str::to_owned).or_else(|| {
            Some(
                match descriptor.resource_type {
                    "tool_call" => "tool_denied",
                    "approval" => "approval_denied",
                    "run" => "run_denied",
                    "usage_event" => "usage_reconciliation_conflict",
                    "budget" | "budget_reservation" => "budget_denied",
                    "rate_limit" => "rate_limit_denied",
                    _ => "operation_denied",
                }
                .to_owned(),
            )
        });
    }
    if outcome == "failure" {
        return Some(
            match descriptor.resource_type {
                "run" => "run_failed",
                "usage_event" => "usage_reconciliation_conflict",
                "budget" | "budget_reservation" => "budget_reconciliation_failed",
                "approval" => "approval_failed",
                "tool_call" => "tool_failed",
                _ => "operation_failed",
            }
            .to_owned(),
        );
    }
    None
}

fn is_stable_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

fn insert_metadata_string(map: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        map.insert(key.to_owned(), Value::String(value.to_owned()));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::core::{ActorId, CorrelationId, EventType, OrganizationId};

    fn event(event_type: &str, payload: Value) -> EventEnvelope {
        EventEnvelope {
            event_id: "evt_0123456789abcdef0123456789abcdef".parse().unwrap(),
            event_type: EventType::new(event_type).unwrap(),
            occurred_at: "2026-09-25T12:00:00.000Z".parse().unwrap(),
            request_id: "req_0123456789abcdef0123456789abcdef".parse().unwrap(),
            correlation_id: CorrelationId::new("trace-p05").unwrap(),
            actor: ActorContext {
                actor_type: ActorType::User,
                actor_id: Some(ActorId::new("usr_0123456789abcdef0123456789abcdef").unwrap()),
                effective_user_id: Some(
                    ActorId::new("usr_0123456789abcdef0123456789abcdef").unwrap(),
                ),
            },
            organization_id: Some(
                OrganizationId::new("org_0123456789abcdef0123456789abcdef").unwrap(),
            ),
            payload,
        }
    }

    #[test]
    fn registry_contains_every_frozen_p05_event_exactly_once() {
        for event_type in P05_EVENT_TYPES {
            assert!(is_p05_event_type(event_type));
            assert!(descriptor_for(event_type).is_some());
        }
        assert_eq!(P05_EVENT_TYPES.len(), 26);
        assert!(!is_p05_event_type("run.unknown.v1"));
    }

    #[test]
    fn projection_keeps_correlation_and_run_but_drops_raw_content() {
        let projection = P05AuditProjection::from_event(&event(
            "run.created.v1",
            json!({
                "run_id": "run_0123456789abcdef0123456789abcdef",
                "agent_session_id": "rse_0123456789abcdef0123456789abcdef",
                "project_id": "prj_0123456789abcdef0123456789abcdef",
                "prompt": "private prompt",
                "response": "private response",
                "tool_arguments": {"secret": "private"},
                "model_alias": "coding-default"
            }),
        ))
        .unwrap();
        assert_eq!(projection.action, "run.created.v1");
        assert_eq!(
            projection.resource_id.as_deref(),
            Some("run_0123456789abcdef0123456789abcdef")
        );
        assert_eq!(
            projection.run_id.as_deref(),
            Some("run_0123456789abcdef0123456789abcdef")
        );
        assert_eq!(
            projection.metadata["request_id"],
            "req_0123456789abcdef0123456789abcdef"
        );
        assert_eq!(projection.metadata["correlation_id"], "trace-p05");
        assert!(projection.metadata.get("prompt").is_none());
        assert!(projection.metadata.get("response").is_none());
        assert!(projection.metadata.get("tool_arguments").is_none());
    }

    #[test]
    fn cross_tenant_payload_is_rejected_before_any_side_effect() {
        let mut envelope = event(
            "run.created.v1",
            json!({"org_id": "org_1123456789abcdef0123456789abcdef"}),
        );
        let error = P05AuditProjection::from_event(&envelope).unwrap_err();
        assert_eq!(error, P05EventError::CrossTenantPayload);
        envelope.organization_id = None;
        assert_eq!(
            P05AuditProjection::from_event(&envelope).unwrap_err(),
            P05EventError::MissingOrganization
        );
    }

    #[test]
    fn device_actor_is_normalized_to_system_with_device_correlation() {
        let mut envelope = event("run.created.v1", json!({}));
        envelope.actor = ActorContext {
            actor_type: ActorType::ServiceAccount,
            actor_id: Some(ActorId::new("dvc_0123456789abcdef0123456789abcdef").unwrap()),
            effective_user_id: None,
        };
        let projection = P05AuditProjection::from_event(&envelope).unwrap();
        assert_eq!(projection.actor_type, "system");
        assert_eq!(projection.metadata["actor_kind"], "device");
        assert_eq!(
            projection.device_id.as_deref(),
            Some("dvc_0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn anonymous_device_payload_is_recorded_as_a_system_actor() {
        let mut envelope = event(
            "run.created.v1",
            json!({"device_id": "dvc_0123456789abcdef0123456789abcdef"}),
        );
        envelope.actor = ActorContext::anonymous();
        let projection = P05AuditProjection::from_event(&envelope).unwrap();
        assert_eq!(projection.actor_type, "system");
        assert_eq!(projection.metadata["actor_kind"], "device");
        assert_eq!(projection.actor_id, None);
    }

    #[test]
    fn event_id_mapping_is_stable_and_prefix_checked() {
        assert_eq!(
            p05_audit_event_id("evt_0123456789abcdef0123456789abcdef").unwrap(),
            "sec_0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            p05_audit_event_id("evt_bad").unwrap_err(),
            P05EventError::InvalidEventId
        );
    }

    #[test]
    fn denied_events_have_stable_reason_without_error_text() {
        let projection = P05AuditProjection::from_event(&event(
            "budget.denied.v1",
            json!({
                "budget_id": "bud_0123456789abcdef0123456789abcdef",
                "error": "database password should never be logged"
            }),
        ))
        .unwrap();
        assert_eq!(projection.outcome, "denied");
        assert_eq!(projection.reason.as_deref(), Some("budget_exceeded"));
        assert!(!format!("{projection:?}").contains("password"));
    }
}
