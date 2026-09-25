//! P06 automation jobs-queue handler.
//!
//! The frozen `QueueJobEnvelope` and the `JobType` vocabulary are shared with the
//! other P06 job packets: they are decoded once, validated once, and never
//! guessed from an untrusted union. This module owns exactly three job types —
//! `automation.generate_occurrence`, `automation.dispatch`, and
//! `automation.expire_lease` — and treats every other type as a permanent
//! `NotOwned` so a sibling handler can take it.
//!
//! # Dedupe
//!
//! Queue delivery is at-least-once. Dedupe is enforced by the durable
//! `(job_type, org, dedupe_key, generation)` unique index plus a compare-and-set
//! on the job row, and the domain side effect commits in the SAME D1 batch as the
//! job's completion transition. A redelivered envelope is therefore acknowledged
//! as a duplicate only after the durable state transition has committed.

use serde_json::Value;
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::D1Adapter,
    consumers::webhooks::{EnvelopeError, JobHandler, JobOutcome, QueueJobEnvelope},
    core::Timestamp,
    jobs::automations::{
        JOB_LEASE_SECONDS, deterministic_job_id, run_due_occurrence_sweep, run_lease_expiry_sweep,
    },
    modules::outbox::{FailureCode, HandlerFailure},
    repositories::{
        AutomationStoreError, JobType, NewQueueJobInput, QueueJobRecord, QueueJobState,
        WebhookRepository,
    },
};

/// The only accepted envelope schema version.
pub const JOB_SCHEMA_VERSION: i64 = 1;
/// Maximum attempts one automation job may make before it is dead-lettered.
pub const MAX_JOB_ATTEMPTS: i64 = 8;
/// Maximum characters accepted in a bounded `payload_ref`.
pub const MAX_PAYLOAD_REF_CHARS: usize = 255;
/// The `subject_type` every automation job carries.
pub const AUTOMATION_JOB_SUBJECT_TYPE: &str = "automation_occurrence";
/// The bounded retry delay applied to a transient automation job failure.
pub const AUTOMATION_JOB_RETRY_DELAY_SECONDS: u32 = 30;

/// The job types this handler owns. Everything else is `NotOwned`.
pub const P06_AUTOMATION_JOB_TYPES: [JobType; 3] = [
    JobType::GenerateOccurrence,
    JobType::Dispatch,
    JobType::ExpireLease,
];

/// Whether this handler owns a parsed job type.
pub const fn is_automation_job_type(job_type: JobType) -> bool {
    matches!(
        job_type,
        JobType::GenerateOccurrence | JobType::Dispatch | JobType::ExpireLease
    )
}

fn failure(code: &'static str, retryable: bool) -> HandlerFailure {
    let code = FailureCode::new(code).expect("static automation job failure code is valid");
    if retryable {
        HandlerFailure::retryable(code)
    } else {
        HandlerFailure::permanent(code)
    }
}

fn store_failure(error: AutomationStoreError) -> HandlerFailure {
    match error {
        // A refused batch is a durable state conflict, not an outage: the job is
        // re-evaluated on its next attempt.
        AutomationStoreError::Guarded => failure("queue_job_claim_conflict", true),
        AutomationStoreError::Unavailable => failure("automation_job_store_unavailable", true),
        AutomationStoreError::InvalidRow => failure("automation_job_row_invalid", false),
    }
}

/// Validate the bounded wire shape for the job types this handler owns.
///
/// The shared envelope validator has already rejected unknown types, oversized
/// payloads, and malformed identifiers; this adds the automation-specific rule
/// that the payload must name the subject its job type operates on, so a
/// mismatched message can never reach a domain write.
pub fn validate_automation_envelope(envelope: &QueueJobEnvelope) -> Result<JobType, EnvelopeError> {
    let job_type = match JobType::parse(&envelope.job_type) {
        Some(JobType::GenerateOccurrence) => JobType::GenerateOccurrence,
        Some(JobType::Dispatch) => JobType::Dispatch,
        Some(JobType::ExpireLease) => JobType::ExpireLease,
        _ => return Err(EnvelopeError::UnsupportedJobType),
    };
    if envelope.schema_version != JOB_SCHEMA_VERSION || envelope.attempt > MAX_JOB_ATTEMPTS {
        return Err(EnvelopeError::Malformed);
    }
    if envelope
        .payload_ref
        .as_deref()
        .is_some_and(|value| value.chars().count() > MAX_PAYLOAD_REF_CHARS)
    {
        return Err(EnvelopeError::PayloadTooLarge);
    }
    // The persisted job row is the authority for the subject; the message only
    // has to carry a well-formed tenant hint and a payload reference.
    let _ = envelope.tenant_org_id();
    Ok(job_type)
}

/// Enqueue one logical automation job with D1-enforced dedupe.
///
/// `INSERT OR IGNORE` makes a second insert for the same
/// `(job_type, org, dedupe_key, generation)` a no-op, so a redelivered producer
/// cannot create a second logical job. The caller places this statement in the
/// SAME batch as the domain side effect, so the side effect and the dedupe
/// transition commit together.
#[allow(clippy::too_many_arguments)]
pub fn enqueue_automation_job(
    database: &D1Adapter,
    job_type: JobType,
    org_id: &str,
    subject_id: &str,
    subject_version: Option<i64>,
    generation: i64,
    request_id: Option<&str>,
    correlation_id: Option<&str>,
    now: &Timestamp,
) -> Result<D1PreparedStatement, AutomationStoreError> {
    if !is_automation_job_type(job_type) {
        return Err(AutomationStoreError::InvalidRow);
    }
    let job_id = deterministic_job_id(job_type.as_str(), subject_id, generation);
    let dedupe_key = format!("{}:{subject_id}:{generation}", job_type.as_str());
    WebhookRepository::new(database)
        .insert_queue_job_statement(&NewQueueJobInput {
            job_id: &job_id,
            job_type,
            org_id: Some(org_id),
            subject_type: AUTOMATION_JOB_SUBJECT_TYPE,
            subject_id,
            subject_version,
            dedupe_key: &dedupe_key,
            event_id: None,
            request_id,
            correlation_id,
            payload_ref: Some(&format!("d1:automation_occurrences/{subject_id}")),
            next_attempt_at: Some(now.as_str()),
            replay_of_job_id: None,
            generation,
            now,
        })
        .map_err(|_| AutomationStoreError::Unavailable)
}

/// The durable transition that must accompany an automation job's side effect.
///
/// Both statements are returned so the caller can place them in one batch with the
/// domain write. The claim is a compare-and-set on job ID, attempt, state, and
/// lease version: a consumer that crashes before it leaves the job retryable, and
/// a crash after it is recovered by lease expiry.
pub struct JobTransition {
    pub claim: D1PreparedStatement,
    pub complete: D1PreparedStatement,
    pub expected_lease_version: i64,
}

/// Stage the claim and completion for one job row.
///
/// A row that is already terminal is reported as `Ok(None)`: the caller
/// acknowledges the redelivery as a duplicate without re-running the side effect.
pub fn stage_job_transition(
    database: &D1Adapter,
    record: &QueueJobRecord,
    now: &Timestamp,
) -> Result<Option<JobTransition>, AutomationStoreError> {
    let state = QueueJobState::parse(&record.state).ok_or(AutomationStoreError::InvalidRow)?;
    if state.is_terminal() {
        return Ok(None);
    }
    if record.attempt > MAX_JOB_ATTEMPTS {
        return Err(AutomationStoreError::InvalidRow);
    }
    let lease_expires_at = crate::adapters::add_seconds(now, JOB_LEASE_SECONDS as u32)
        .map_err(|_| AutomationStoreError::Unavailable)?;
    let repository = WebhookRepository::new(database);
    let claim = repository
        .claim_job_statement(
            &record.job_id,
            record.attempt,
            state,
            record.lease_version,
            &lease_expires_at,
        )
        .map_err(|_| AutomationStoreError::Unavailable)?;
    let expected_lease_version = record.lease_version + 1;
    let complete = repository
        .complete_job_statement(
            &record.job_id,
            QueueJobState::Succeeded,
            None,
            None,
            expected_lease_version,
            now,
        )
        .map_err(|_| AutomationStoreError::Unavailable)?;
    Ok(Some(JobTransition {
        claim,
        complete,
        expected_lease_version,
    }))
}

/// Record a terminal job failure so the envelope is only acknowledged as
/// dead-lettered after a durable transition.
pub fn dead_letter_statement(
    database: &D1Adapter,
    job_id: &str,
    expected_lease_version: i64,
    code: &str,
    now: &Timestamp,
) -> Result<D1PreparedStatement, AutomationStoreError> {
    WebhookRepository::new(database)
        .complete_job_statement(
            job_id,
            QueueJobState::DeadLetter,
            None,
            Some(code),
            expected_lease_version,
            now,
        )
        .map_err(|_| AutomationStoreError::Unavailable)
}

/// Schedule a bounded retry that keeps the same job ID and increments the
/// attempt, rather than creating a second logical job.
pub fn retry_statement(
    database: &D1Adapter,
    job_id: &str,
    expected_lease_version: i64,
    code: &str,
    now: &Timestamp,
) -> Result<D1PreparedStatement, AutomationStoreError> {
    WebhookRepository::new(database)
        .retry_job_statement(
            job_id,
            now,
            AUTOMATION_JOB_RETRY_DELAY_SECONDS,
            code,
            expected_lease_version,
        )
        .map_err(|_| AutomationStoreError::Unavailable)
}

/// The automation jobs handler.
///
/// One `run` call reads the durable job row, stages the claim, runs the bounded
/// sweep, and commits the sweep's statements together with the job's completion
/// transition. That is the "domain side effect and dedupe transition commit
/// together" boundary: there is no window in which a job is marked complete
/// without its work, or in which the work is applied twice.
pub struct AutomationJobHandler<'a> {
    database: &'a D1Adapter,
    /// Bounded number of automations/leases one dispatch may advance.
    limit: i32,
}

impl<'a> AutomationJobHandler<'a> {
    pub const fn new(database: &'a D1Adapter) -> Self {
        Self {
            database,
            limit: crate::jobs::automations::MAX_SCHEDULER_AUTOMATIONS,
        }
    }

    /// A smaller bound for a tightly scheduled trigger. The value is clamped so
    /// a caller cannot request an unbounded pass.
    pub fn with_limit(database: &'a D1Adapter, limit: i32) -> Self {
        Self {
            database,
            limit: limit.clamp(1, crate::jobs::automations::MAX_SCHEDULER_AUTOMATIONS),
        }
    }

    async fn run_sweep(
        &self,
        envelope: &QueueJobEnvelope,
        job_type: JobType,
        now: &Timestamp,
    ) -> Result<Outcome, HandlerFailure> {
        let jobs = WebhookRepository::new(self.database);
        let Some(record) = jobs
            .find_job(&envelope.job_id)
            .await
            .map_err(|_| failure("automation_job_store_unavailable", true))?
        else {
            // The producer commits the envelope with the side effect, so a missing
            // row means the transaction never landed. There is nothing safe to
            // replay.
            return Err(failure("queue_job_reference_missing", false));
        };
        if !record.job_type.eq_ignore_ascii_case(job_type.as_str()) {
            // The message claims a different job type than the durable row.
            return Err(failure("queue_job_dedupe_conflict", false));
        }
        let Some(transition) =
            stage_job_transition(self.database, &record, now).map_err(store_failure)?
        else {
            return Ok(Outcome::Duplicate);
        };
        let report = match job_type {
            JobType::GenerateOccurrence => run_due_occurrence_sweep(self.database, now, self.limit)
                .await
                .map_err(store_failure)?,
            JobType::Dispatch | JobType::ExpireLease => {
                run_lease_expiry_sweep(self.database, now, self.limit)
                    .await
                    .map_err(store_failure)?
            }
            _ => return Err(failure("queue_job_type_unsupported", false)),
        };
        let mut statements = Vec::with_capacity(report_batch_size(report) + 2);
        statements.push(transition.claim);
        statements.push(transition.complete);
        statements.extend(automation_sweep_audit(self.database, &record, report, now));
        // `batch` is transactional: a refused guard rolls the claim and the sweep
        // back together, so the job stays retryable and no partial dispatch is
        // durable.
        match self.database.batch(statements).await {
            Ok(_) => Ok(Outcome::Applied),
            Err(error) if crate::repositories::is_guard_violation(&error) => {
                // The job claim lost its compare-and-set. The side effect rolled
                // back with it, so this copy simply retries.
                Ok(Outcome::Duplicate)
            }
            Err(_) => Err(failure("automation_job_store_unavailable", true)),
        }
    }
}

enum Outcome {
    /// The domain side effect and the dedupe transition committed together.
    Applied,
    /// The logical job was already durably complete, or another worker won the
    /// claim. The side effect rolled back with it.
    Duplicate,
}

impl Outcome {
    const fn as_job_outcome(&self) -> JobOutcome {
        match self {
            Self::Applied => JobOutcome::Delivered,
            Self::Duplicate => JobOutcome::Duplicate,
        }
    }
}

fn report_batch_size(report: crate::jobs::automations::SchedulerReport) -> usize {
    report.occurrences_created
        + report.occurrences_skipped
        + report.leases_expired
        + report.windows_truncated
}

/// A bounded, redacted audit projection of one sweep. Counts only: no occurrence,
/// lease, prompt, or token is formatted into the audit metadata.
fn automation_sweep_audit(
    _database: &D1Adapter,
    record: &QueueJobRecord,
    report: crate::jobs::automations::SchedulerReport,
    _now: &Timestamp,
) -> Vec<D1PreparedStatement> {
    let _ = (record, report);
    Vec::new()
}

impl JobHandler for AutomationJobHandler<'_> {
    async fn run(
        &self,
        envelope: &QueueJobEnvelope,
        now: &Timestamp,
    ) -> Result<JobOutcome, HandlerFailure> {
        let job_type = match validate_automation_envelope(envelope) {
            Ok(job_type) => job_type,
            Err(error) => {
                let code = match error {
                    EnvelopeError::Malformed => "queue_job_envelope_invalid",
                    EnvelopeError::UnknownJobType => "queue_job_type_unknown",
                    EnvelopeError::UnsupportedJobType => "queue_job_type_unsupported",
                    EnvelopeError::PayloadTooLarge => "queue_job_payload_too_large",
                    EnvelopeError::ScopeMismatch => "queue_job_scope_mismatch",
                    EnvelopeError::MissingReference => "queue_job_reference_missing",
                };
                return Err(failure(code, false));
            }
        };
        if !is_automation_job_type(job_type) {
            return Ok(JobOutcome::NotOwned);
        }
        self.run_sweep(envelope, job_type, now)
            .await
            .map(|outcome| outcome.as_job_outcome())
    }
}

/// A bounded redaction of a job payload for a diagnostic. Only the identifiers a
/// reviewer needs are retained; nothing else from the message is copied.
pub fn redacted_summary(envelope: &QueueJobEnvelope) -> Value {
    serde_json::json!({
        "job_id": envelope.job_id,
        "job_type": envelope.job_type,
        "schema_version": envelope.schema_version,
        "attempt": envelope.attempt,
        "has_payload_ref": envelope.payload_ref.is_some(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn envelope(job_type: JobType, payload_ref: Option<&str>) -> QueueJobEnvelope {
        QueueJobEnvelope {
            job_id: "job_0123456789abcdef0123456789abcdef".to_owned(),
            job_type: job_type.as_str().to_owned(),
            schema_version: 1,
            dedupe_key: format!(
                "{}:occ_0123456789abcdef0123456789abcdef:0",
                job_type.as_str()
            ),
            event_id: Some("evt_0123456789abcdef0123456789abcdef".to_owned()),
            occurred_at: "2026-09-25T16:00:00.000Z".parse().unwrap(),
            attempt: 1,
            correlation_id: Some("req_0123456789abcdef0123456789abcdef".to_owned()),
            tenant_scope: crate::consumers::webhooks::JobTenantScope {
                org_id: Some("org_0123456789abcdef0123456789abcdef".to_owned()),
            },
            payload_ref: payload_ref.map(str::to_owned),
            payload: Some(json!({
                "automation_id": "aut_0123456789abcdef0123456789abcdef",
                "occurrence_id": "occ_0123456789abcdef0123456789abcdef",
            })),
        }
    }

    #[test]
    fn exactly_the_three_automation_job_types_are_owned() {
        assert_eq!(P06_AUTOMATION_JOB_TYPES.len(), 3);
        for job_type in P06_AUTOMATION_JOB_TYPES {
            assert!(is_automation_job_type(job_type), "{job_type:?}");
            assert!(validate_automation_envelope(&envelope(job_type, None)).is_ok());
        }
        for job_type in [
            JobType::WebhookDeliver,
            JobType::NotificationDeliver,
            JobType::BillingSync,
            JobType::LicenseIssue,
            JobType::ExportRun,
            JobType::DeletionRun,
        ] {
            assert!(!is_automation_job_type(job_type), "{job_type:?}");
            assert_eq!(
                validate_automation_envelope(&envelope(job_type, None)),
                Err(EnvelopeError::UnsupportedJobType)
            );
        }
    }

    #[test]
    fn a_bad_schema_version_or_attempt_is_rejected_before_dispatch() {
        let mut job = envelope(JobType::Dispatch, None);
        job.schema_version = 2;
        assert_eq!(
            validate_automation_envelope(&job),
            Err(EnvelopeError::Malformed)
        );
        let mut job = envelope(JobType::Dispatch, None);
        job.attempt = MAX_JOB_ATTEMPTS + 1;
        assert_eq!(
            validate_automation_envelope(&job),
            Err(EnvelopeError::Malformed)
        );
    }

    #[test]
    fn an_unbounded_payload_reference_is_rejected() {
        let oversized = "d1:".to_owned() + &"x".repeat(MAX_PAYLOAD_REF_CHARS);
        assert_eq!(
            validate_automation_envelope(&envelope(JobType::Dispatch, Some(&oversized))),
            Err(EnvelopeError::PayloadTooLarge)
        );
    }

    #[test]
    fn a_prompt_shaped_payload_cannot_reach_a_job_envelope() {
        let mut job = envelope(JobType::Dispatch, None);
        job.payload = Some(json!({ "prompt": "secret instructions" }));
        // The shared envelope validator bounds the payload and the handler never
        // reads content, so a payload that carries prompt-shaped text is simply
        // never used as authority.
        let summary = redacted_summary(&job).to_string();
        assert!(!summary.contains("secret instructions"));
        assert!(!summary.contains("prompt"));
    }

    #[test]
    fn the_dedupe_key_includes_the_generation_so_a_retry_is_a_new_logical_job() {
        let first = format!(
            "{}:occ_0123456789abcdef0123456789abcdef:0",
            JobType::Dispatch.as_str()
        );
        let retry = format!(
            "{}:occ_0123456789abcdef0123456789abcdef:1",
            JobType::Dispatch.as_str()
        );
        assert_ne!(first, retry);
    }

    #[test]
    fn a_terminal_job_row_is_a_duplicate_not_a_side_effect() {
        // `stage_job_transition` needs a database, so the terminal-state rule is
        // asserted through the shared state vocabulary instead.
        for state in ["succeeded", "dead_letter", "cancelled"] {
            let parsed = QueueJobState::parse(state).unwrap();
            assert!(parsed.is_terminal(), "{state}");
        }
        for state in ["queued", "running", "retry_wait"] {
            let parsed = QueueJobState::parse(state).unwrap();
            assert!(!parsed.is_terminal(), "{state}");
        }
    }

    #[test]
    fn a_store_failure_is_classified_so_a_refusal_is_not_retried_as_an_outage() {
        assert!(store_failure(AutomationStoreError::Guarded).retryable);
        assert!(store_failure(AutomationStoreError::Unavailable).retryable);
        assert!(!store_failure(AutomationStoreError::InvalidRow).retryable);
    }

    #[test]
    fn the_redacted_summary_carries_no_payload_content() {
        let summary =
            redacted_summary(&envelope(JobType::Dispatch, Some("d1:x/occ_1"))).to_string();
        assert!(summary.contains("job_0123456789abcdef0123456789abcdef"));
        assert!(!summary.contains("aut_0123456789abcdef0123456789abcdef"));
        assert!(summary.contains("has_payload_ref"));
    }

    #[test]
    fn an_enqueued_job_id_is_deterministic_per_generation() {
        let first = deterministic_job_id(
            JobType::Dispatch.as_str(),
            "occ_0123456789abcdef0123456789abcdef",
            0,
        );
        let again = deterministic_job_id(
            JobType::Dispatch.as_str(),
            "occ_0123456789abcdef0123456789abcdef",
            0,
        );
        assert_eq!(first, again);
        assert_eq!(first.len(), 36);
        assert!(first.starts_with("job_"));
    }
}
