//! Typed P06 job-queue consumer for `webhook.deliver` and `notification.deliver`.
//!
//! P06 job messages travel on a separate `JOBS_QUEUE`/`JOBS_DLQ` binding and are
//! decoded into [`QueueJobEnvelope`]. They are never decoded as an
//! `EventEnvelope` union, and a webhook retry never mutates the P01 business
//! event or reuses `outbox_events.delivery_status` as delivery state.
//!
//! Duplicate delivery is a no-op: the durable job claim
//! (`queued | retry_wait -> running`) and the durable delivery claim
//! (`pending | queued | retry_wait -> delivering`) are both compare-and-set, so
//! a redelivered message either finds the job already terminal or loses the
//! claim race. The tenant scope always comes from the persisted delivery row,
//! never from the queue message's untrusted `tenant_scope`.
//!
//! Nothing here formats a stored body, a response body, a decrypted secret, a
//! notification body, or a raw platform error into a diagnostic. Failures carry
//! a stable [`FailureCode`] only.

use std::{fmt, net::IpAddr};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::{
        d1::D1Adapter,
        new_resource_id,
        webhooks::{
            AUTO_DISABLED_REASON, CloudflareDnsResolver, DeliveryAction, DeliveryPolicy,
            DnsResolver, EmailTransport, NotificationMessage, OutboundRequest, RetryAfter,
            SsrfRejection, StaticDnsResolver, TransportOutcome,
            delivery::decide,
            outbound::{
                classify_status, post_signed, signature_header, unix_seconds, validate_endpoint_url,
            },
            should_auto_disable,
        },
    },
    core::{ActorContext, CorrelationId, EventEnvelope, EventId, EventType, RequestId, Timestamp},
    modules::outbox::{FailureCode, FailureDisposition, HandlerFailure, RetryPolicy},
    repositories::{
        IdentityRepository, JobType, NotificationDeliveryRecord, NotificationDeliveryState,
        NotificationRecord, OutboxRepository, QueueJobRecord, QueueJobState, WebhookDeliveryRecord,
        WebhookDeliveryState, WebhookEndpointRecord, WebhookRepository,
    },
};

/// Maximum serialized size of the bounded metadata-only job payload.
pub const MAX_JOB_PAYLOAD_BYTES: usize = 2 * 1024;
/// Maximum number of keys accepted in a job payload object.
pub const MAX_JOB_PAYLOAD_KEYS: usize = 8;
/// Maximum characters accepted in one job payload string value.
pub const MAX_JOB_PAYLOAD_STRING_CHARS: usize = 128;
/// The only accepted envelope schema version.
pub const JOB_SCHEMA_VERSION: i64 = 1;
/// Bounded backoff for `notification.deliver`. Notification delivery is not an
/// endpoint policy, so it uses a fixed conservative schedule.
pub const NOTIFICATION_RETRY_POLICY: RetryPolicy = match RetryPolicy::new(4, 60, 3_600, 20) {
    Some(policy) => policy,
    None => panic!("static notification retry policy is valid"),
};
/// Lease granted to one running job.
pub const JOB_LEASE_SECONDS: u32 = 120;
/// Bounded read of a user's email address for a notification.
const MAX_RECIPIENT_CHARS: usize = 254;
/// Frozen event name emitted when auto-disable switches an endpoint off.
pub const ENDPOINT_DISABLED_EVENT: &str = "webhook.endpoint_disabled.v1";
/// Frozen event names emitted for a completed, retried, or dead-lettered
/// delivery.
pub const DELIVERY_SUCCEEDED_EVENT: &str = "webhook.delivery_succeeded.v1";
pub const DELIVERY_RETRY_EVENT: &str = "webhook.delivery_retry_scheduled.v1";
pub const DELIVERY_DEAD_LETTER_EVENT: &str = "webhook.delivery_dead_lettered.v1";

// -----------------------------------------------------------------------------
// Queue job envelope
// -----------------------------------------------------------------------------

/// The tenant scope carried by a queue message.
///
/// It is treated as an untrusted hint: the consumer always re-derives the
/// authoritative tenant from the persisted delivery row and rejects a mismatch.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JobTenantScope {
    pub org_id: Option<String>,
}

/// The frozen P06 `QueueJobEnvelope`. Unknown fields are rejected before any
/// domain dispatch, and the payload is bounded metadata only: it can never carry
/// a prompt, response, tool argument, credential, lease token, or secret.
#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QueueJobEnvelope {
    pub job_id: String,
    pub job_type: String,
    pub schema_version: i64,
    pub dedupe_key: String,
    pub event_id: Option<String>,
    pub occurred_at: Timestamp,
    pub attempt: i64,
    pub correlation_id: Option<String>,
    pub tenant_scope: JobTenantScope,
    pub payload_ref: Option<String>,
    #[serde(default)]
    pub payload: Option<Value>,
}

impl fmt::Debug for QueueJobEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueueJobEnvelope")
            .field("job_id", &self.job_id)
            .field("job_type", &self.job_type)
            .field("schema_version", &self.schema_version)
            .field("dedupe_key", &self.dedupe_key)
            .field("event_id", &self.event_id)
            .field("occurred_at", &self.occurred_at)
            .field("attempt", &self.attempt)
            .field("correlation_id", &self.correlation_id)
            .field("tenant_scope", &self.tenant_scope)
            .field("payload_ref", &self.payload_ref)
            .field("payload", &"[redacted]")
            .finish()
    }
}

/// Why an envelope was rejected before domain dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    Malformed,
    UnknownJobType,
    UnsupportedJobType,
    PayloadTooLarge,
    ScopeMismatch,
    MissingReference,
}

impl EnvelopeError {
    const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "queue_job_envelope_invalid",
            Self::UnknownJobType => "queue_job_type_unknown",
            Self::UnsupportedJobType => "queue_job_type_unsupported",
            Self::PayloadTooLarge => "queue_job_payload_too_large",
            Self::ScopeMismatch => "queue_job_scope_mismatch",
            Self::MissingReference => "queue_job_reference_missing",
        }
    }
}

impl QueueJobEnvelope {
    /// Reject unbounded or malformed messages before any side effect.
    pub fn validate(&self) -> Result<JobType, EnvelopeError> {
        if crate::core::ResourceId::new(&self.job_id)
            .map(|id| id.prefix() != "job")
            .unwrap_or(true)
            || self.schema_version != JOB_SCHEMA_VERSION
            || self.dedupe_key.is_empty()
            || self.dedupe_key.chars().count() > 255
            || self.attempt <= 0
        {
            return Err(EnvelopeError::Malformed);
        }
        if let Some(event_id) = &self.event_id
            && EventId::new(event_id.as_str()).is_err()
        {
            return Err(EnvelopeError::Malformed);
        }
        if let Some(correlation_id) = &self.correlation_id
            && CorrelationId::new(correlation_id.as_str()).is_err()
        {
            return Err(EnvelopeError::Malformed);
        }
        if let Some(payload_ref) = &self.payload_ref
            && payload_ref.chars().count() > 255
        {
            return Err(EnvelopeError::Malformed);
        }
        let job_type = JobType::parse(&self.job_type).ok_or(EnvelopeError::UnknownJobType)?;
        if !job_type.is_event_delivery() {
            return Err(EnvelopeError::UnsupportedJobType);
        }
        if let Some(org_id) = &self.tenant_scope.org_id
            && crate::core::OrganizationId::new(org_id.as_str()).is_err()
        {
            return Err(EnvelopeError::Malformed);
        }
        if let Some(payload) = &self.payload {
            if serde_json::to_vec(payload)
                .map(|bytes| bytes.len() > MAX_JOB_PAYLOAD_BYTES)
                .unwrap_or(true)
            {
                return Err(EnvelopeError::PayloadTooLarge);
            }
            let object: &Map<String, Value> =
                payload.as_object().ok_or(EnvelopeError::Malformed)?;
            if object.len() > MAX_JOB_PAYLOAD_KEYS {
                return Err(EnvelopeError::PayloadTooLarge);
            }
            if object
                .values()
                .any(|value| !is_bounded_payload_value(value))
            {
                return Err(EnvelopeError::PayloadTooLarge);
            }
        }
        Ok(job_type)
    }

    /// Read one bounded reference identifier from the payload.
    pub fn payload_reference(&self, key: &str, prefix: &str) -> Result<String, EnvelopeError> {
        let raw = self
            .payload
            .as_ref()
            .and_then(|payload| payload.get(key))
            .and_then(Value::as_str)
            .ok_or(EnvelopeError::MissingReference)?;
        let id = crate::core::ResourceId::new(raw).map_err(|_| EnvelopeError::MissingReference)?;
        if id.prefix() != prefix {
            return Err(EnvelopeError::MissingReference);
        }
        Ok(id.as_str().to_owned())
    }

    /// The untrusted tenant hint, normalized to an optional organization ID.
    pub fn tenant_org_id(&self) -> Option<&str> {
        self.tenant_scope.org_id.as_deref()
    }
}

fn is_bounded_payload_value(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
        Value::String(text) => text.chars().count() <= MAX_JOB_PAYLOAD_STRING_CHARS,
        Value::Array(items) => {
            items.len() <= MAX_JOB_PAYLOAD_KEYS && items.iter().all(is_bounded_payload_value)
        }
        Value::Object(fields) => {
            fields.len() <= MAX_JOB_PAYLOAD_KEYS
                && fields.iter().all(|(key, value)| {
                    key.chars().count() <= 64 && is_bounded_payload_value(value)
                })
        }
    }
}

// -----------------------------------------------------------------------------
// Handler contract
// -----------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobOutcome {
    /// The side effect completed and the durable state is terminal.
    Delivered,
    /// The job was already terminal, or another worker won the claim.
    Duplicate,
    /// A retry is durably scheduled.
    RetryScheduled,
    /// The job reached a terminal failure.
    DeadLettered,
    /// The job belongs to another P06 packet.
    NotOwned,
}

/// Contract implemented by the typed P06 job handlers. The Worker path is
/// statically dispatched and never requires a trait object.
#[allow(async_fn_in_trait)]
pub trait JobHandler {
    /// Handle one envelope. An `Err` means the queue must retry; every `Ok`
    /// outcome is durably recorded first.
    async fn run(
        &self,
        envelope: &QueueJobEnvelope,
        now: &Timestamp,
    ) -> Result<JobOutcome, HandlerFailure>;
}

fn permanent(code: &'static str) -> HandlerFailure {
    HandlerFailure::permanent(FailureCode::new(code).expect("static P06 failure code is valid"))
}

fn retryable(code: &'static str) -> HandlerFailure {
    HandlerFailure::retryable(FailureCode::new(code).expect("static P06 failure code is valid"))
}

fn envelope_failure(error: EnvelopeError) -> HandlerFailure {
    permanent(error.code())
}

// -----------------------------------------------------------------------------
// `webhook.deliver`
// -----------------------------------------------------------------------------

/// Everything the durable state machine needs from one outbound attempt.
struct AttemptResult {
    outcome: TransportOutcome,
    retry_after: RetryAfter,
    http_status: Option<i64>,
    latency_ms: Option<i64>,
}

/// Handler for one `webhook.deliver` job.
///
/// `R` is statically dispatched: an `async fn` trait cannot be used as `dyn`
/// without an object-safe future indirection, and the Worker path never needs
/// dynamic dispatch here.
pub struct WebhookDeliveryJobHandler<'a, R: DnsResolver + ?Sized> {
    database: &'a D1Adapter,
    encryption_key: Option<String>,
    resolver: &'a R,
}

impl<'a, R: DnsResolver + ?Sized> WebhookDeliveryJobHandler<'a, R> {
    pub const fn new(
        database: &'a D1Adapter,
        encryption_key: Option<String>,
        resolver: &'a R,
    ) -> Self {
        Self {
            database,
            encryption_key,
            resolver,
        }
    }
}

#[allow(async_fn_in_trait)]
impl<R: DnsResolver + ?Sized> JobHandler for WebhookDeliveryJobHandler<'_, R> {
    async fn run(
        &self,
        envelope: &QueueJobEnvelope,
        now: &Timestamp,
    ) -> Result<JobOutcome, HandlerFailure> {
        envelope.validate().map_err(envelope_failure)?;
        let repository = WebhookRepository::new(self.database);
        let job = load_job(&repository, &envelope.job_id).await?;
        if let Some(outcome) = terminal_job_outcome(&job) {
            return Ok(outcome);
        }
        if let Some(outcome) = claim_job(&repository, &job, now).await? {
            return Ok(outcome);
        }

        let delivery_id = envelope
            .payload_reference("delivery_id", "whd")
            .map_err(envelope_failure)?;
        let Some(delivery) = repository
            .find_delivery(job.org_id.as_deref().unwrap_or(""), &delivery_id)
            .await
            .map_err(|_| retryable("webhook_delivery_store_unavailable"))?
        else {
            return dead_letter_job(&repository, &job, "webhook_delivery_missing", now).await;
        };
        if delivery.org_id != job.org_id.clone().unwrap_or_default()
            || envelope
                .tenant_org_id()
                .is_some_and(|org_id| org_id != delivery.org_id)
        {
            return dead_letter_job(&repository, &job, EnvelopeError::ScopeMismatch.code(), now)
                .await;
        }
        let state = WebhookDeliveryState::parse(&delivery.state)
            .ok_or_else(|| permanent("webhook_delivery_state_invalid"))?;
        if state.is_terminal() {
            complete_job(&repository, &job, QueueJobState::Succeeded, None, None, now).await?;
            return Ok(JobOutcome::Duplicate);
        }

        let endpoint = repository
            .find_endpoint(&delivery.org_id, &delivery.endpoint_id)
            .await
            .map_err(|_| retryable("webhook_delivery_store_unavailable"))?
            .ok_or_else(|| permanent("webhook_endpoint_missing"))?;
        if !endpoint.enabled {
            complete_job(&repository, &job, QueueJobState::Cancelled, None, None, now).await?;
            return Ok(JobOutcome::Duplicate);
        }

        let event_id = EventId::new(delivery.event_id.as_str())
            .map_err(|_| permanent("webhook_event_id_invalid"))?;
        // Durable idempotency gate: exactly one worker may make the request.
        let claimed = repository
            .apply(
                repository
                    .mark_delivery_delivering_statement(
                        &delivery.delivery_id,
                        state,
                        delivery.version,
                        now,
                    )
                    .map_err(|_| retryable("webhook_delivery_store_unavailable"))?,
            )
            .await
            .map_err(|_| retryable("webhook_delivery_store_unavailable"))?;
        if !claimed {
            complete_job(&repository, &job, QueueJobState::Succeeded, None, None, now).await?;
            return Ok(JobOutcome::Duplicate);
        }

        let expected_version = delivery.version + 1;
        let attempt_number = delivery.attempt_count + 1;
        let policy = endpoint_policy(&endpoint);
        let result = self
            .attempt(&repository, &endpoint, &delivery, now, policy)
            .await;
        let action = decide(
            policy,
            &event_id,
            u32::try_from(attempt_number).unwrap_or(u32::MAX),
            result.outcome,
            result.retry_after,
        );
        self.persist(
            &repository,
            envelope,
            &job,
            &endpoint,
            &delivery,
            &result,
            action,
            attempt_number,
            expected_version,
            now,
        )
        .await
    }
}

impl<R: DnsResolver + ?Sized> WebhookDeliveryJobHandler<'_, R> {
    #[allow(clippy::too_many_arguments)]
    async fn attempt(
        &self,
        repository: &WebhookRepository<'_>,
        endpoint: &WebhookEndpointRecord,
        delivery: &WebhookDeliveryRecord,
        now: &Timestamp,
        policy: DeliveryPolicy,
    ) -> AttemptResult {
        let target = match validate_endpoint_url(&endpoint.url) {
            Ok(target) => target,
            Err(rejection) => return rejection_result(rejection),
        };
        let timestamp_seconds = match unix_seconds(now) {
            Ok(value) => value,
            Err(rejection) => return rejection_result(rejection),
        };
        let secret = match self
            .plaintext_secret(
                repository,
                &delivery.org_id,
                &delivery.endpoint_id,
                &delivery.secret_version_id,
            )
            .await
        {
            Ok(secret) => secret,
            Err(failure) => {
                let code = stable_code(failure.code.as_str());
                return AttemptResult {
                    outcome: if failure.retryable {
                        TransportOutcome::Retryable(code)
                    } else {
                        TransportOutcome::Terminal(code)
                    },
                    retry_after: RetryAfter::Rejected,
                    http_status: None,
                    latency_ms: None,
                };
            }
        };
        // The exact stored body is reused byte-for-byte, so the signature stays
        // verifiable and a retry carries identical content.
        let request = OutboundRequest {
            endpoint: target,
            event_id: delivery.event_id.clone(),
            signature_key_id: delivery.signature_key_id.clone(),
            signature: signature_header(
                &secret,
                timestamp_seconds,
                &delivery.event_id,
                &delivery.body,
            ),
            timestamp_seconds,
            body: delivery.body.clone(),
        };
        // A timeout may produce a duplicate request; consumers deduplicate by
        // the stable event ID that is repeated in the header and the body.
        match post_signed(&request, self.resolver).await {
            Ok(response) => AttemptResult {
                outcome: classify_status(response.status, policy.retry_conflict),
                retry_after: response.retry_after,
                http_status: Some(i64::from(response.status)),
                latency_ms: Some(0),
            },
            Err(rejection) => rejection_result(rejection),
        }
    }

    /// Decrypt the secret version captured when the logical delivery was
    /// created. The plaintext exists only inside this call and the derived
    /// signature; it is never persisted, returned, or logged.
    async fn plaintext_secret(
        &self,
        repository: &WebhookRepository<'_>,
        org_id: &str,
        endpoint_id: &str,
        secret_version_id: &str,
    ) -> Result<String, HandlerFailure> {
        let key = self
            .encryption_key
            .as_deref()
            .ok_or_else(|| permanent("webhook_secret_key_unavailable"))?;
        let secret = repository
            .find_secret(org_id, endpoint_id, secret_version_id)
            .await
            .map_err(|_| retryable("webhook_delivery_store_unavailable"))?
            .ok_or_else(|| permanent("webhook_secret_version_missing"))?;
        crate::adapters::crypto::decrypt_secret(key, &secret.ciphertext, &secret.nonce)
            .await
            .map_err(|_| permanent("webhook_secret_decrypt_failed"))
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    async fn persist(
        &self,
        repository: &WebhookRepository<'_>,
        envelope: &QueueJobEnvelope,
        job: &QueueJobRecord,
        endpoint: &WebhookEndpointRecord,
        delivery: &WebhookDeliveryRecord,
        result: &AttemptResult,
        action: DeliveryAction,
        attempt_number: i64,
        expected_version: i64,
        now: &Timestamp,
    ) -> Result<JobOutcome, HandlerFailure> {
        let error_code = action.error_code();
        let (delivery_state, job_state, delay_seconds) = match action {
            DeliveryAction::Delivered => (
                WebhookDeliveryState::Delivered,
                QueueJobState::Succeeded,
                None,
            ),
            DeliveryAction::Retry { delay_seconds, .. } => (
                WebhookDeliveryState::RetryWait,
                QueueJobState::RetryWait,
                Some(delay_seconds),
            ),
            DeliveryAction::DeadLetter { .. } => (
                WebhookDeliveryState::DeadLetter,
                QueueJobState::DeadLetter,
                None,
            ),
        };

        let attempt_row = repository
            .insert_attempt_statement(&crate::repositories::NewDeliveryAttemptInput {
                attempt_id: new_resource_id("wha").as_str(),
                delivery_id: &delivery.delivery_id,
                org_id: &delivery.org_id,
                attempt_number,
                job_id: Some(&job.job_id),
                outcome: attempt_outcome(delivery_state),
                http_status: result.http_status,
                stable_error_code: error_code,
                latency_ms: result.latency_ms,
                started_at: now.as_str(),
                completed_at: Some(now.as_str()),
            })
            .map_err(|_| retryable("webhook_delivery_store_unavailable"))?;

        let transition = match delivery_state {
            WebhookDeliveryState::Delivered => repository
                .mark_delivery_delivered_statement(&delivery.delivery_id, expected_version, now)
                .map_err(|_| retryable("webhook_delivery_store_unavailable"))?,
            WebhookDeliveryState::RetryWait => repository
                .mark_delivery_retry_statement(
                    &delivery.delivery_id,
                    now,
                    delay_seconds.unwrap_or(1),
                    error_code.unwrap_or("webhook_server_error"),
                    expected_version,
                )
                .map_err(|_| retryable("webhook_delivery_store_unavailable"))?,
            _ => repository
                .mark_delivery_dead_letter_statement(
                    &delivery.delivery_id,
                    error_code.unwrap_or("webhook_delivery_dead"),
                    expected_version,
                    now,
                )
                .map_err(|_| retryable("webhook_delivery_store_unavailable"))?,
        };

        // Terminal-failure bookkeeping and the optional auto-disable audit row
        // share the same batch as the attempt and the delivery transition.
        let mut statements: Vec<D1PreparedStatement> = vec![attempt_row, transition];
        let auto_disable = matches!(delivery_state, WebhookDeliveryState::DeadLetter)
            && should_auto_disable(
                endpoint_policy(endpoint),
                endpoint.consecutive_terminal_failures + 1,
            );
        if delivery_state == WebhookDeliveryState::Delivered {
            statements.push(
                repository
                    .reset_terminal_failures_statement(&endpoint.endpoint_id, now)
                    .map_err(|_| retryable("webhook_delivery_store_unavailable"))?,
            );
        } else if delivery_state == WebhookDeliveryState::DeadLetter {
            statements.push(
                repository
                    .record_terminal_failure_statement(&endpoint.endpoint_id, auto_disable, now)
                    .map_err(|_| retryable("webhook_delivery_store_unavailable"))?,
            );
            if auto_disable
                && let Some(statement) =
                    endpoint_disabled_outbox(repository, envelope, endpoint, now)
            {
                statements.push(statement);
            }
        }

        let next_attempt_at = delay_seconds
            .and_then(|seconds| crate::adapters::add_seconds(now, seconds).ok())
            .map(|value| value.as_str().to_owned());
        statements.push(
            repository
                .complete_job_statement(
                    &job.job_id,
                    job_state,
                    next_attempt_at.as_deref(),
                    error_code,
                    job.lease_version,
                    now,
                )
                .map_err(|_| retryable("webhook_delivery_store_unavailable"))?,
        );
        // The frozen `webhook.delivery_*` events make every terminal outcome and
        // every scheduled retry auditable. They are metadata only, and the
        // `0012` fan-out trigger guarantees they are never fanned out again.
        if let Some(statement) = delivery_outcome_outbox(
            repository,
            envelope,
            delivery,
            delivery_state,
            attempt_number,
            result.http_status,
            result.latency_ms,
            error_code,
            now,
        ) {
            statements.push(statement);
        }

        // The attempt row, the delivery transition, the endpoint bookkeeping,
        // the job transition, and the audit event commit together, so a crash
        // can never leave a recorded attempt with no matching delivery state.
        self.database
            .batch(statements)
            .await
            .map_err(|_| retryable("webhook_delivery_store_unavailable"))?;

        Ok(match job_state {
            QueueJobState::Succeeded => JobOutcome::Delivered,
            QueueJobState::RetryWait => JobOutcome::RetryScheduled,
            _ => JobOutcome::DeadLettered,
        })
    }
}

/// Map a bounded internal failure code onto one of the frozen static codes.
/// A worker never forwards an arbitrary string into a durable column.
fn stable_code(code: &str) -> &'static str {
    match code {
        "webhook_secret_key_unavailable" => "webhook_secret_key_unavailable",
        "webhook_secret_version_missing" => "webhook_secret_version_missing",
        "webhook_secret_decrypt_failed" => "webhook_secret_decrypt_failed",
        "notification_provider_unavailable" => "notification_provider_unavailable",
        "notification_recipient_invalid" => "notification_recipient_invalid",
        _ => "webhook_delivery_store_unavailable",
    }
}

fn rejection_result(rejection: SsrfRejection) -> AttemptResult {
    AttemptResult {
        outcome: if rejection.retryable() {
            TransportOutcome::Retryable(rejection.reason())
        } else {
            TransportOutcome::Terminal(rejection.reason())
        },
        retry_after: RetryAfter::Rejected,
        http_status: None,
        latency_ms: None,
    }
}

fn attempt_outcome(state: WebhookDeliveryState) -> &'static str {
    match state {
        WebhookDeliveryState::Delivered => "delivered",
        WebhookDeliveryState::RetryWait => "retry_scheduled",
        WebhookDeliveryState::DeadLetter => "dead_lettered",
        WebhookDeliveryState::Cancelled => "cancelled",
        _ => "delivering",
    }
}

fn endpoint_policy(endpoint: &WebhookEndpointRecord) -> DeliveryPolicy {
    crate::adapters::webhooks::delivery::policy_from_row(
        endpoint.max_attempts,
        endpoint.base_delay_seconds,
        endpoint.max_delay_seconds,
        endpoint.replay_window_seconds,
        endpoint.auto_disable_enabled,
        endpoint.auto_disable_threshold,
    )
    .unwrap_or_default()
}

/// Emit the frozen `webhook.endpoint_disabled.v1` outbox row for an auto-disable.
///
/// A worker has no `RequestContext`, so the row reuses the job's correlation ID
/// as the request ID. When the message does not carry a usable `req_` value the
/// disable still lands and only the event row is omitted; the next mutation
/// re-asserts the state in the UI.
fn endpoint_disabled_outbox(
    repository: &WebhookRepository<'_>,
    envelope: &QueueJobEnvelope,
    endpoint: &WebhookEndpointRecord,
    now: &Timestamp,
) -> Option<D1PreparedStatement> {
    outbox_statement(
        repository,
        envelope,
        now,
        ENDPOINT_DISABLED_EVENT,
        &endpoint.org_id,
        &serde_json::json!({
            "endpoint_id": endpoint.endpoint_id,
            "org_id": endpoint.org_id,
            "version": endpoint.version + 1,
            "reason": AUTO_DISABLED_REASON,
            "consecutive_terminal_failures": endpoint.consecutive_terminal_failures + 1,
        }),
    )
}

/// Emit the frozen delivery-outcome event so a delivery, a scheduled retry, and
/// a dead-letter are all auditable. Only the terminal outcomes and the scheduled
/// retry are announced; an in-flight `delivering` state is not.
#[allow(clippy::too_many_arguments)]
fn delivery_outcome_outbox(
    repository: &WebhookRepository<'_>,
    envelope: &QueueJobEnvelope,
    delivery: &WebhookDeliveryRecord,
    state: WebhookDeliveryState,
    attempt_number: i64,
    http_status: Option<i64>,
    latency_ms: Option<i64>,
    error_code: Option<&'static str>,
    now: &Timestamp,
) -> Option<D1PreparedStatement> {
    let event_type = delivery_outcome_event(state)?;
    let mut metadata = serde_json::Map::new();
    metadata.insert(
        "delivery_id".to_owned(),
        serde_json::json!(delivery.delivery_id),
    );
    metadata.insert(
        "endpoint_id".to_owned(),
        serde_json::json!(delivery.endpoint_id),
    );
    metadata.insert("event_id".to_owned(), serde_json::json!(delivery.event_id));
    metadata.insert(
        "event_type".to_owned(),
        serde_json::json!(delivery.event_type),
    );
    metadata.insert("state".to_owned(), serde_json::json!(state.as_str()));
    metadata.insert("attempt".to_owned(), serde_json::json!(attempt_number));
    metadata.insert(
        "replay_generation".to_owned(),
        serde_json::json!(delivery.replay_generation),
    );
    if let Some(status) = http_status {
        metadata.insert("http_status".to_owned(), serde_json::json!(status));
    }
    if let Some(latency) = latency_ms {
        metadata.insert("latency_ms".to_owned(), serde_json::json!(latency));
    }
    if let Some(code) = error_code {
        metadata.insert("error_code".to_owned(), serde_json::json!(code));
    }
    outbox_statement(
        repository,
        envelope,
        now,
        event_type,
        &delivery.org_id,
        &Value::Object(metadata),
    )
}

/// The frozen event name announced for a delivery state, or `None` for a
/// non-terminal state that must not be announced.
const fn delivery_outcome_event(state: WebhookDeliveryState) -> Option<&'static str> {
    match state {
        WebhookDeliveryState::Delivered => Some(DELIVERY_SUCCEEDED_EVENT),
        WebhookDeliveryState::RetryWait => Some(DELIVERY_RETRY_EVENT),
        WebhookDeliveryState::DeadLetter => Some(DELIVERY_DEAD_LETTER_EVENT),
        _ => None,
    }
}

/// Build one worker-emitted P01 event.
///
/// A worker has no `RequestContext`, so the job's correlation ID is reused as
/// the request ID. Without a usable `req_` value the durable delivery state
/// still lands and only the event row is skipped.
fn outbox_statement(
    repository: &WebhookRepository<'_>,
    envelope: &QueueJobEnvelope,
    now: &Timestamp,
    event_type: &str,
    org_id: &str,
    payload: &Value,
) -> Option<D1PreparedStatement> {
    let request_id = RequestId::new(envelope.correlation_id.as_deref()?).ok()?;
    let correlation_id = CorrelationId::new(envelope.correlation_id.as_deref()?).ok()?;
    let event = EventEnvelope {
        event_id: new_resource_id("evt").as_str().parse().unwrap_or_else(|_| {
            "evt_00000000000000000000000000000000"
                .parse()
                .expect("fallback event ID is valid")
        }),
        event_type: EventType::new(event_type).expect("frozen P06 event type is valid"),
        occurred_at: now.clone(),
        request_id,
        correlation_id,
        actor: ActorContext::system(),
        organization_id: Some(crate::core::OrganizationId::new(org_id).ok()?),
        payload: payload.clone(),
    };
    OutboxRepository::new(repository.database())
        .insert_statement(&event)
        .ok()
}

// -----------------------------------------------------------------------------
// `notification.deliver`
// -----------------------------------------------------------------------------

/// Handler for one `notification.deliver` job. `E` is statically dispatched.
pub struct NotificationDeliveryJobHandler<'a, E: EmailTransport + ?Sized> {
    database: &'a D1Adapter,
    email: &'a E,
}

impl<'a, E: EmailTransport + ?Sized> NotificationDeliveryJobHandler<'a, E> {
    pub const fn new(database: &'a D1Adapter, email: &'a E) -> Self {
        Self { database, email }
    }
}

#[allow(async_fn_in_trait)]
impl<E: EmailTransport + ?Sized> JobHandler for NotificationDeliveryJobHandler<'_, E> {
    async fn run(
        &self,
        envelope: &QueueJobEnvelope,
        now: &Timestamp,
    ) -> Result<JobOutcome, HandlerFailure> {
        envelope.validate().map_err(envelope_failure)?;
        let repository = WebhookRepository::new(self.database);
        let job = load_job(&repository, &envelope.job_id).await?;
        if let Some(outcome) = terminal_job_outcome(&job) {
            return Ok(outcome);
        }
        if let Some(outcome) = claim_job(&repository, &job, now).await? {
            return Ok(outcome);
        }

        let delivery_id = envelope
            .payload_reference("delivery_id", "ndl")
            .map_err(envelope_failure)?;
        let Some(delivery) = repository
            .find_notification_delivery(&delivery_id)
            .await
            .map_err(|_| retryable("notification_store_unavailable"))?
        else {
            return dead_letter_job(&repository, &job, "notification_delivery_missing", now).await;
        };
        if delivery.user_id != job.subject_id
            || envelope
                .tenant_org_id()
                .is_some_and(|org_id| Some(org_id.to_owned()) != delivery.org_id)
        {
            return dead_letter_job(&repository, &job, EnvelopeError::ScopeMismatch.code(), now)
                .await;
        }
        let state = NotificationDeliveryState::parse(&delivery.state)
            .ok_or_else(|| permanent("notification_delivery_state_invalid"))?;
        if matches!(
            state,
            NotificationDeliveryState::Delivered
                | NotificationDeliveryState::DeadLetter
                | NotificationDeliveryState::Cancelled
        ) {
            complete_job(&repository, &job, QueueJobState::Succeeded, None, None, now).await?;
            return Ok(JobOutcome::Duplicate);
        }

        let notification = repository
            .find_notification(&delivery.user_id, &delivery.notification_id)
            .await
            .map_err(|_| retryable("notification_store_unavailable"))?
            .ok_or_else(|| permanent("notification_missing"))?;

        match self.deliver(&delivery, &notification).await {
            Ok(()) => {
                finish_notification(
                    &repository,
                    &job,
                    &delivery,
                    state,
                    NotificationDeliveryState::Delivered,
                    None,
                    None,
                    now,
                )
                .await
            }
            Err(failure) if failure.retryable => {
                let attempt = u32::try_from(delivery.attempt_count + 1).unwrap_or(u32::MAX);
                let (next_state, delay) = match NOTIFICATION_RETRY_POLICY
                    .after_failure(attempt, &event_id(&notification))
                {
                    FailureDisposition::Retry { delay_seconds } => {
                        (NotificationDeliveryState::RetryWait, Some(delay_seconds))
                    }
                    FailureDisposition::DeadLetter => (NotificationDeliveryState::DeadLetter, None),
                };
                finish_notification(
                    &repository,
                    &job,
                    &delivery,
                    state,
                    next_state,
                    delay,
                    Some(stable_code(failure.code.as_str())),
                    now,
                )
                .await
            }
            Err(failure) => {
                finish_notification(
                    &repository,
                    &job,
                    &delivery,
                    state,
                    NotificationDeliveryState::DeadLetter,
                    None,
                    Some(stable_code(failure.code.as_str())),
                    now,
                )
                .await
            }
        }
    }
}

impl<E: EmailTransport + ?Sized> NotificationDeliveryJobHandler<'_, E> {
    /// `in_app` needs no external provider: the durable projection already
    /// exists, so the delivery records completion. `email` goes through the
    /// adapter, and an unavailable provider becomes a retryable state. The
    /// business mutation that produced the notification is never rolled back.
    async fn deliver(
        &self,
        delivery: &NotificationDeliveryRecord,
        notification: &NotificationRecord,
    ) -> Result<(), HandlerFailure> {
        if delivery.channel == "in_app" {
            return Ok(());
        }
        if delivery.channel != "email" {
            return Err(permanent("notification_channel_unsupported"));
        }
        let recipient = IdentityRepository::new(self.database)
            .find_user_by_id(&delivery.user_id)
            .await
            .map_err(|_| retryable("notification_store_unavailable"))?
            .filter(|user| user.email_verified)
            .map(|user| user.email)
            .filter(|email| email.len() <= MAX_RECIPIENT_CHARS)
            .ok_or_else(|| permanent("notification_recipient_invalid"))?;
        self.email
            .send(&notification_message(notification, &recipient))
            .await
            .map_err(|error| {
                if error.retryable() {
                    retryable(error.reason())
                } else {
                    permanent(error.reason())
                }
            })
    }
}

/// Build a bounded, metadata-only message. The durable projection is the only
/// input, and it never contains a prompt, response, tool argument, or secret.
fn notification_message(notification: &NotificationRecord, recipient: &str) -> NotificationMessage {
    let subject = format!("Lumi Agents: {} update", notification.category);
    let body = format!(
        "A {} event was recorded in your Lumi Agents organization.\n\nEvent: {}\nRecorded: {}\n\nSign in to review the details.",
        notification.category, notification.event_type, notification.created_at
    );
    NotificationMessage {
        recipient: recipient.to_owned(),
        subject,
        body,
    }
}

fn event_id(notification: &NotificationRecord) -> EventId {
    EventId::new(&notification.event_id).unwrap_or_else(|_| {
        EventId::new("evt_00000000000000000000000000000000").expect("fallback event ID is valid")
    })
}

// -----------------------------------------------------------------------------
// Shared job plumbing
// -----------------------------------------------------------------------------

async fn load_job(
    repository: &WebhookRepository<'_>,
    job_id: &str,
) -> Result<QueueJobRecord, HandlerFailure> {
    repository
        .find_job(job_id)
        .await
        .map_err(|_| retryable("queue_job_store_unavailable"))?
        .ok_or_else(|| permanent("queue_job_missing"))
}

fn terminal_job_outcome(job: &QueueJobRecord) -> Option<JobOutcome> {
    QueueJobState::parse(&job.state)
        .is_some_and(|state| state.is_terminal())
        .then_some(JobOutcome::Duplicate)
}

/// Atomic `queued | retry_wait -> running` claim. A claim miss means another
/// worker owns the job, which is a normal at-least-once outcome.
async fn claim_job(
    repository: &WebhookRepository<'_>,
    job: &QueueJobRecord,
    now: &Timestamp,
) -> Result<Option<JobOutcome>, HandlerFailure> {
    let state =
        QueueJobState::parse(&job.state).ok_or_else(|| permanent("queue_job_state_invalid"))?;
    if !matches!(state, QueueJobState::Queued | QueueJobState::RetryWait) {
        return Ok(Some(JobOutcome::Duplicate));
    }
    let lease = crate::adapters::add_seconds(now, JOB_LEASE_SECONDS)
        .map_err(|_| retryable("queue_job_store_unavailable"))?;
    let claimed = repository
        .apply(
            repository
                .claim_job_statement(&job.job_id, job.attempt, state, job.lease_version, &lease)
                .map_err(|_| retryable("queue_job_store_unavailable"))?,
        )
        .await
        .map_err(|_| retryable("queue_job_store_unavailable"))?;
    Ok(if claimed {
        None
    } else {
        Some(JobOutcome::Duplicate)
    })
}

async fn complete_job(
    repository: &WebhookRepository<'_>,
    job: &QueueJobRecord,
    next_state: QueueJobState,
    next_attempt_at: Option<&str>,
    error_code: Option<&'static str>,
    now: &Timestamp,
) -> Result<(), HandlerFailure> {
    repository
        .apply(
            repository
                .complete_job_statement(
                    &job.job_id,
                    next_state,
                    next_attempt_at,
                    error_code,
                    job.lease_version,
                    now,
                )
                .map_err(|_| retryable("queue_job_store_unavailable"))?,
        )
        .await
        .map_err(|_| retryable("queue_job_store_unavailable"))?;
    Ok(())
}

/// Record a terminal job failure without performing the domain side effect.
async fn dead_letter_job(
    repository: &WebhookRepository<'_>,
    job: &QueueJobRecord,
    error_code: &'static str,
    now: &Timestamp,
) -> Result<JobOutcome, HandlerFailure> {
    complete_job(
        repository,
        job,
        QueueJobState::DeadLetter,
        None,
        Some(error_code),
        now,
    )
    .await?;
    Ok(JobOutcome::DeadLettered)
}

#[allow(clippy::too_many_arguments)]
async fn finish_notification(
    repository: &WebhookRepository<'_>,
    job: &QueueJobRecord,
    delivery: &NotificationDeliveryRecord,
    expected_state: NotificationDeliveryState,
    next_state: NotificationDeliveryState,
    delay_seconds: Option<u32>,
    error_code: Option<&'static str>,
    now: &Timestamp,
) -> Result<JobOutcome, HandlerFailure> {
    let next_attempt_at = delay_seconds
        .and_then(|seconds| crate::adapters::add_seconds(now, seconds).ok())
        .map(|value| value.as_str().to_owned());
    let delivered_at =
        (next_state == NotificationDeliveryState::Delivered).then(|| now.as_str().to_owned());
    let attempt_count = delivery.attempt_count + i64::from(delivered_at.is_some());
    let job_state = match next_state {
        NotificationDeliveryState::Delivered => QueueJobState::Succeeded,
        NotificationDeliveryState::RetryWait => QueueJobState::RetryWait,
        _ => QueueJobState::DeadLetter,
    };
    repository
        .apply(
            repository
                .mark_notification_delivery_statement(
                    &delivery.delivery_id,
                    next_state,
                    attempt_count,
                    next_attempt_at.as_deref(),
                    delivered_at.as_deref(),
                    error_code,
                    expected_state,
                    delivery.version,
                    now,
                )
                .map_err(|_| retryable("notification_store_unavailable"))?,
        )
        .await
        .map_err(|_| retryable("notification_store_unavailable"))?;
    complete_job(
        repository,
        job,
        job_state,
        next_attempt_at.as_deref(),
        error_code,
        now,
    )
    .await?;
    Ok(match job_state {
        QueueJobState::Succeeded => JobOutcome::Delivered,
        QueueJobState::RetryWait => JobOutcome::RetryScheduled,
        _ => JobOutcome::DeadLettered,
    })
}

// -----------------------------------------------------------------------------
// Batch entry points for the coordinator's Worker wiring
// -----------------------------------------------------------------------------

/// Consume a batch from `JOBS_QUEUE` (or its `JOBS_DLQ`).
///
/// Every message is acknowledged only after its durable transition. A store or
/// platform failure uses the queue's bounded retry and never logs a body.
pub async fn consume_jobs_batch<W, N>(
    batch: &worker::MessageBatch<QueueJobEnvelope>,
    webhooks: &W,
    notifications: &N,
    now: &Timestamp,
    is_dead_letter_queue: bool,
) -> worker::Result<()>
where
    W: JobHandler,
    N: JobHandler,
{
    use worker::MessageExt;

    let messages = match batch.messages() {
        Ok(messages) => messages,
        Err(_) => {
            batch.retry_all_with_options(&retry_options());
            return Ok(());
        }
    };
    for message in messages {
        let envelope = message.body();
        if is_dead_letter_queue {
            // The domain job and its durable side effect are already recorded;
            // the Queue DLQ is only a platform-level fallback.
            message.ack();
            continue;
        }
        match webhooks.run(envelope, now).await {
            Ok(JobOutcome::NotOwned) => match notifications.run(envelope, now).await {
                Ok(_) => message.ack(),
                Err(failure) if failure.retryable => message.retry_with_options(&retry_options()),
                Err(_) => message.ack(),
            },
            Ok(_) => message.ack(),
            Err(failure) if failure.retryable => message.retry_with_options(&retry_options()),
            Err(_) => message.ack(),
        }
    }
    Ok(())
}

fn retry_options() -> worker::QueueRetryOptions {
    worker::QueueRetryOptionsBuilder::new()
        .with_delay_seconds(30)
        .build()
}

/// The production resolver. Kept as a function so the coordinator's Worker
/// wiring never constructs a test resolver by accident.
#[allow(dead_code)]
pub fn production_resolver() -> CloudflareDnsResolver {
    CloudflareDnsResolver
}

/// The explicit test resolver for a local fixture endpoint. No production route
/// calls this.
#[allow(dead_code)]
pub fn test_resolver(entries: Vec<(String, Vec<IpAddr>)>) -> StaticDnsResolver {
    StaticDnsResolver::new(entries)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn envelope(job_type: &str, payload: Value) -> QueueJobEnvelope {
        QueueJobEnvelope {
            job_id: "job_0123456789abcdef0123456789abcdef".to_owned(),
            job_type: job_type.to_owned(),
            schema_version: 1,
            dedupe_key: "webhook.deliver:whd_0123456789abcdef0123456789abcdef".to_owned(),
            event_id: Some("evt_0123456789abcdef0123456789abcdef".to_owned()),
            occurred_at: "2026-09-25T16:00:00.000Z".parse().unwrap(),
            attempt: 1,
            correlation_id: Some("req_0123456789abcdef0123456789abcdef".to_owned()),
            tenant_scope: JobTenantScope {
                org_id: Some("org_0123456789abcdef0123456789abcdef".to_owned()),
            },
            payload_ref: Some(
                "d1:webhook_deliveries/whd_0123456789abcdef0123456789abcdef".to_owned(),
            ),
            payload: Some(payload),
        }
    }

    #[test]
    fn frozen_webhook_job_envelopes_validate() {
        let job = envelope(
            "webhook.deliver",
            json!({ "delivery_id": "whd_0123456789abcdef0123456789abcdef" }),
        );
        assert_eq!(job.validate().unwrap(), JobType::WebhookDeliver);
        assert_eq!(
            job.payload_reference("delivery_id", "whd").unwrap(),
            "whd_0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            job.tenant_org_id(),
            Some("org_0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn frozen_notification_job_envelopes_validate() {
        let job = envelope(
            "notification.deliver",
            json!({ "delivery_id": "ndl_0123456789abcdef0123456789abcdef" }),
        );
        assert_eq!(job.validate().unwrap(), JobType::NotificationDeliver);
        assert_eq!(
            job.payload_reference("delivery_id", "ndl").unwrap(),
            "ndl_0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn unknown_and_unowned_job_types_are_permanent_rejections() {
        assert_eq!(
            envelope("webhook.deliver.v2", json!({})).validate(),
            Err(EnvelopeError::UnknownJobType)
        );
        for other in [
            "automation.generate_occurrence",
            "automation.dispatch",
            "automation.expire_lease",
            "billing.sync",
            "license.issue",
            "export.run",
            "deletion.run",
        ] {
            assert_eq!(
                envelope(other, json!({})).validate(),
                Err(EnvelopeError::UnsupportedJobType),
                "accepted {other}"
            );
        }
    }

    #[test]
    fn malformed_and_unbounded_envelopes_are_rejected_before_dispatch() {
        let mut invalid = envelope("webhook.deliver", json!({}));
        invalid.job_id = "not-a-job-id".to_owned();
        assert_eq!(invalid.validate(), Err(EnvelopeError::Malformed));

        let mut invalid = envelope("webhook.deliver", json!({}));
        invalid.schema_version = 2;
        assert_eq!(invalid.validate(), Err(EnvelopeError::Malformed));

        let mut invalid = envelope("webhook.deliver", json!({}));
        invalid.attempt = 0;
        assert_eq!(invalid.validate(), Err(EnvelopeError::Malformed));

        let mut invalid = envelope("webhook.deliver", json!({}));
        invalid.dedupe_key = "x".repeat(256);
        assert_eq!(invalid.validate(), Err(EnvelopeError::Malformed));

        let mut invalid = envelope("webhook.deliver", json!({}));
        invalid.event_id = Some("req_0123456789abcdef0123456789abcdef".to_owned());
        assert_eq!(invalid.validate(), Err(EnvelopeError::Malformed));

        let mut invalid = envelope("webhook.deliver", json!({}));
        invalid.correlation_id = Some("contains space".to_owned());
        assert_eq!(invalid.validate(), Err(EnvelopeError::Malformed));

        let mut invalid = envelope("webhook.deliver", json!({}));
        invalid.tenant_scope.org_id = Some("org_nope".to_owned());
        assert_eq!(invalid.validate(), Err(EnvelopeError::Malformed));

        let mut invalid = envelope("webhook.deliver", json!({}));
        invalid.payload = Some(json!({ "a": "x".repeat(4_096) }));
        assert_eq!(invalid.validate(), Err(EnvelopeError::PayloadTooLarge));

        let mut invalid = envelope("webhook.deliver", json!({}));
        invalid.payload = Some(Value::String("scalar".to_owned()));
        assert_eq!(invalid.validate(), Err(EnvelopeError::Malformed));
    }

    #[test]
    fn payload_references_must_carry_the_expected_prefix() {
        assert_eq!(
            envelope("webhook.deliver", json!({})).payload_reference("delivery_id", "whd"),
            Err(EnvelopeError::MissingReference)
        );
        let cross = envelope(
            "webhook.deliver",
            json!({ "delivery_id": "ndl_0123456789abcdef0123456789abcdef" }),
        );
        assert_eq!(
            cross.payload_reference("delivery_id", "whd"),
            Err(EnvelopeError::MissingReference)
        );
    }

    #[test]
    fn envelope_deserialization_rejects_unknown_fields() {
        let value = json!({
            "job_id": "job_0123456789abcdef0123456789abcdef",
            "job_type": "webhook.deliver",
            "schema_version": 1,
            "dedupe_key": "webhook.deliver:whd_0123456789abcdef0123456789abcdef",
            "event_id": "evt_0123456789abcdef0123456789abcdef",
            "occurred_at": "2026-09-25T16:00:00.000Z",
            "attempt": 1,
            "correlation_id": "req_0123456789abcdef0123456789abcdef",
            "tenant_scope": { "org_id": "org_0123456789abcdef0123456789abcdef" },
            "payload_ref": "d1:webhook_deliveries/whd_0123456789abcdef0123456789abcdef",
            "payload": { "delivery_id": "whd_0123456789abcdef0123456789abcdef" },
            "prompt": "must never be accepted"
        });
        assert!(serde_json::from_value::<QueueJobEnvelope>(value).is_err());
    }

    #[test]
    fn envelope_debug_never_prints_the_payload() {
        let job = envelope(
            "webhook.deliver",
            json!({ "delivery_id": "whd_0123456789abcdef0123456789abcdef", "note": "private" }),
        );
        let debug = format!("{job:?}");
        assert!(!debug.contains("private"));
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn notification_message_is_metadata_only() {
        let notification = NotificationRecord {
            notification_id: "ntf_0123456789abcdef0123456789abcdef".to_owned(),
            org_id: Some("org_0123456789abcdef0123456789abcdef".to_owned()),
            user_id: "usr_0123456789abcdef0123456789abcdef".to_owned(),
            event_id: "evt_0123456789abcdef0123456789abcdef".to_owned(),
            event_type: "device.revoked.v1".to_owned(),
            category: "security".to_owned(),
            mandatory: true,
            body_json: "{}".to_owned(),
            dedupe_key: "device.revoked:evt_0123456789abcdef0123456789abcdef".to_owned(),
            state: "unread".to_owned(),
            read_at: None,
            created_at: "2026-09-25T16:00:00.000Z".to_owned(),
            updated_at: "2026-09-25T16:00:00.000Z".to_owned(),
        };
        let message = notification_message(&notification, "person@example.com");
        assert!(message.subject.contains("security"));
        assert!(message.body.contains("device.revoked.v1"));
        assert!(!message.body.contains("person@example.com"));
        assert_eq!(
            event_id(&notification).as_str(),
            "evt_0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn notification_retry_policy_is_bounded() {
        assert_eq!(NOTIFICATION_RETRY_POLICY.max_attempts(), 4);
        let event = EventId::new("evt_0123456789abcdef0123456789abcdef").unwrap();
        assert!(matches!(
            NOTIFICATION_RETRY_POLICY.after_failure(1, &event),
            FailureDisposition::Retry { .. }
        ));
        assert_eq!(
            NOTIFICATION_RETRY_POLICY.after_failure(4, &event),
            FailureDisposition::DeadLetter
        );
    }

    #[test]
    fn only_terminal_delivery_states_emit_a_frozen_audit_event() {
        assert_eq!(
            delivery_outcome_event(WebhookDeliveryState::Delivered),
            Some("webhook.delivery_succeeded.v1")
        );
        assert_eq!(
            delivery_outcome_event(WebhookDeliveryState::RetryWait),
            Some("webhook.delivery_retry_scheduled.v1")
        );
        assert_eq!(
            delivery_outcome_event(WebhookDeliveryState::DeadLetter),
            Some("webhook.delivery_dead_lettered.v1")
        );
        for in_flight in [
            WebhookDeliveryState::Pending,
            WebhookDeliveryState::Queued,
            WebhookDeliveryState::Delivering,
        ] {
            assert_eq!(delivery_outcome_event(in_flight), None);
        }
        // Every emitted name must be a real versioned P06 event name.
        for state in [
            WebhookDeliveryState::Delivered,
            WebhookDeliveryState::RetryWait,
            WebhookDeliveryState::DeadLetter,
        ] {
            let name = delivery_outcome_event(state).expect("terminal state emits an event");
            assert!(EventType::new(name).is_ok(), "{name}");
            assert!(name.starts_with("webhook.delivery_"), "{name}");
        }
        assert!(EventType::new(ENDPOINT_DISABLED_EVENT).is_ok());
    }

    #[test]
    fn endpoint_policy_falls_back_to_the_frozen_default_for_a_bad_row() {
        let endpoint = WebhookEndpointRecord {
            endpoint_id: "whe_0123456789abcdef0123456789abcdef".to_owned(),
            org_id: "org_0123456789abcdef0123456789abcdef".to_owned(),
            name: "hook".to_owned(),
            description: None,
            url: "https://hooks.example.com/events".to_owned(),
            subscribed_event_types_json: "[]".to_owned(),
            current_secret_version_id: None,
            enabled: true,
            max_attempts: 99,
            base_delay_seconds: 30,
            max_delay_seconds: 86_400,
            replay_window_seconds: 300,
            auto_disable_enabled: false,
            auto_disable_threshold: 10,
            consecutive_terminal_failures: 0,
            version: 1,
            created_by_user_id: "usr_0123456789abcdef0123456789abcdef".to_owned(),
            created_at: "2026-09-25T16:00:00.000Z".to_owned(),
            updated_at: "2026-09-25T16:00:00.000Z".to_owned(),
        };
        assert_eq!(endpoint_policy(&endpoint), DeliveryPolicy::default());
    }
}
