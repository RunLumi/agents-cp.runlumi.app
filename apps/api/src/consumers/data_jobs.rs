//! P06 `export.run` / `deletion.run` queue consumers.
//!
//! The durable job state lives in D1 (`export_jobs`, `deletion_jobs`); the queue
//! is only transport. That split is what makes the consumers safe under
//! at-least-once delivery:
//!
//! * the `queue_job_envelopes` unique `(job_type, org, dedupe_key, generation)`
//!   constraint plus an atomic `queued|retry_wait → running` claim means a
//!   redelivered envelope either finds nothing to do or loses the claim race;
//! * every export/deletion state move is a compare-and-set on
//!   `(version, current state)`, so a duplicate delivery cannot corrupt a job
//!   or double-count an attempt;
//! * a duplicate delivery *after* durable completion is a no-op: never a second
//!   artifact, never a second certificate.
//!
//! After each transition the runner **re-reads** the job rather than mutating a
//! local copy. That is what keeps the compare-and-set predicate honest across a
//! multi-step pipeline.
//!
//! Nothing here logs or formats export content, a prompt, a credential, or a
//! provider payload. The only payload a message may carry is the two opaque
//! subject IDs; the manifest, cutoff, and job state are read from D1.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::{
    adapters::{
        d1::D1Adapter,
        r2::{ArtifactError, ExportArtifactStore, ObjectKey, StreamDescriptor, build_object_key},
        sha256_hex,
    },
    core::Timestamp,
    modules::data_governance::{
        DeletionInventoryEntry, DeletionJobState, DeletionPlan, DeletionPlanner,
        DeletionSkipReason, DeletionStepState, DeletionTarget, ExportCategory, ExportJobState,
        ExportManifest, ExportScope, FenceDecision, FencedWorkflow, HoldScope, LegalHold,
        ReferenceKind, RetentionError, RetentionPolicy, decide, decide_fence, deletion,
        manifest_is_stable, reference_coverage, registry,
    },
    repositories::{
        DataGovernancePolicyRecord, DataGovernanceRepository, DeletionJobRecord,
        DeletionTaskRecord, ExportJobRecord, NewArtifactInput, NewCertificateInput,
        NewDeletionTaskInput, RowOutcome, database_row_executor, format_content_type,
        parse_deletion_state, parse_deletion_step_state, parse_export_format, parse_export_state,
    },
};

/// The frozen `job_type` values this consumer owns. `0012` lists the same two
/// names in the `queue_job_envelopes` check constraint, so an unknown type is a
/// permanent failure rather than a silently acknowledged message.
pub const DATA_JOB_TYPES: [&str; 2] = ["export.run", "deletion.run"];

/// The frozen P06 data-governance business event names.
///
/// The coordinator must add these to the outbox consumer registry
/// (`consumers/outbox.rs`) or route them through the P06 event registry; until
/// one of those happens the existing `ProductEventHandler` rejects them as
/// `unsupported_event_type`, so a P06 `export.*`/`deletion.*` outbox row would
/// be dead-lettered.
pub const P06_DATA_EVENT_TYPES: [&str; 12] = [
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

/// Most bytes a job message may carry. The envelope is metadata-only, so a
/// larger message is rejected before it can reach a domain decision.
pub const MAX_JOB_MESSAGE_BYTES: usize = 4 * 1024;

/// Most collection rows one packaged artifact may contain per category.
pub const EXPORT_ROW_LIMIT: i32 = 1_000;

/// Attempts before a job is parked for a human instead of retrying forever.
pub const MAX_JOB_ATTEMPTS: i64 = 5;

/// Deterministic, bounded retry backoff. Queue transport is never treated as
/// delivery authority, so the retry decision stays a domain decision.
pub const RETRY_BASE_SECONDS: u32 = 30;
pub const RETRY_MAX_SECONDS: u32 = 900;

/// Job lease length. A crash after the claim is recovered by lease expiry.
pub const JOB_LEASE_SECONDS: u32 = 300;

/// The versioned P06 job envelope.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DataJobEnvelope {
    pub job_id: String,
    pub job_type: String,
    pub schema_version: u32,
    pub dedupe_key: String,
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub correlation_id: Option<String>,
    #[serde(default = "one")]
    pub attempt: u32,
    #[serde(default)]
    pub tenant_scope: TenantScope,
    #[serde(default)]
    pub payload_ref: Option<String>,
    pub payload: DataJobPayload,
}

fn one() -> u32 {
    1
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TenantScope {
    #[serde(default)]
    pub org_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DataJobPayload {
    #[serde(default)]
    pub export_id: Option<String>,
    #[serde(default)]
    pub deletion_id: Option<String>,
}

/// Stable failure codes. None carries a message body, a provider string, or an
/// object key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataJobError {
    UnknownJobType,
    InvalidEnvelope,
    MessageTooLarge,
    ClaimConflict,
    LeaseExpired,
    ExportNotFound,
    ExportTerminal,
    ExportFenced,
    ExportArtifactUnavailable,
    ExportManifestDrifted,
    DeletionNotFound,
    DeletionTerminal,
    DeletionBlocked,
    StepExecutorUnavailable,
    StepFailed,
    ObjectAbsent,
    StoreUnavailable,
}

impl DataJobError {
    /// Retryable failures leave the envelope in `retry_wait`; everything else is
    /// a permanent failure. This is the difference between "the database was
    /// busy" and "this message can never be right".
    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::StoreUnavailable
                | Self::LeaseExpired
                | Self::ExportArtifactUnavailable
                | Self::ObjectAbsent
                | Self::StepFailed
        )
    }

    pub const fn code(self) -> &'static str {
        match self {
            Self::UnknownJobType => "unsupported_event_type",
            Self::InvalidEnvelope | Self::MessageTooLarge => "queue_job_envelope_invalid",
            Self::ClaimConflict => "queue_job_claim_conflict",
            Self::LeaseExpired => "queue_job_lease_expired",
            Self::ExportNotFound | Self::DeletionNotFound => "resource_not_found",
            Self::ExportTerminal | Self::DeletionTerminal => "queue_job_dedupe_conflict",
            Self::ExportFenced => "deletion_cutoff_reached",
            Self::ExportManifestDrifted => "export_category_invalid",
            Self::ExportArtifactUnavailable | Self::ObjectAbsent => "export_artifact_unavailable",
            Self::DeletionBlocked => "deletion_legal_hold",
            Self::StepExecutorUnavailable => "deletion_executor_unavailable",
            Self::StepFailed => "deletion_step_failed",
            Self::StoreUnavailable => "store_unavailable",
        }
    }
}

impl fmt::Display for DataJobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for DataJobError {}

/// Deterministic backoff for `attempt`, bounded by [`RETRY_MAX_SECONDS`].
pub fn retry_delay_seconds(attempt: u32) -> u32 {
    let exponent = if attempt > 5 { 5 } else { attempt };
    let shifted = RETRY_BASE_SECONDS.saturating_mul(1u32 << exponent);
    if shifted > RETRY_MAX_SECONDS {
        RETRY_MAX_SECONDS
    } else {
        shifted
    }
}

/// The dedupe key for one logical job. Derived from the frozen subject, never
/// from a request body, so a retry of the same job resolves to the same
/// envelope row.
pub fn dedupe_key(job_type: &str, subject_id: &str) -> String {
    format!("{job_type}:{subject_id}")
}

impl DataJobEnvelope {
    /// Bounded, prefix-checked parse. An unparsable or oversized message is
    /// rejected before it reaches a domain decision.
    pub fn parse(raw: &str) -> Result<Self, DataJobError> {
        if raw.is_empty() || raw.len() > MAX_JOB_MESSAGE_BYTES {
            return Err(DataJobError::MessageTooLarge);
        }
        let envelope: Self =
            serde_json::from_str(raw).map_err(|_| DataJobError::InvalidEnvelope)?;
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<(), DataJobError> {
        if !DATA_JOB_TYPES.contains(&self.job_type.as_str()) {
            return Err(DataJobError::UnknownJobType);
        }
        if self.schema_version != 1
            || !valid_id(&self.job_id, "job_")
            || self.dedupe_key.is_empty()
            || self.dedupe_key.len() > 255
        {
            return Err(DataJobError::InvalidEnvelope);
        }
        if let Some(org_id) = self.tenant_scope.org_id.as_deref()
            && !valid_id(org_id, "org_")
        {
            return Err(DataJobError::InvalidEnvelope);
        }
        match self.job_type.as_str() {
            "export.run" => {
                if !self
                    .payload
                    .export_id
                    .as_deref()
                    .is_some_and(|value| valid_id(value, "exp_"))
                    || self.payload.deletion_id.is_some()
                {
                    return Err(DataJobError::InvalidEnvelope);
                }
            }
            "deletion.run" => {
                if !self
                    .payload
                    .deletion_id
                    .as_deref()
                    .is_some_and(|value| valid_id(value, "del_"))
                    || self.payload.export_id.is_some()
                {
                    return Err(DataJobError::InvalidEnvelope);
                }
            }
            _ => return Err(DataJobError::UnknownJobType),
        }
        Ok(())
    }

    /// The durable subject this message names.
    pub fn subject_id(&self) -> Result<(&'static str, &str), DataJobError> {
        match self.job_type.as_str() {
            "export.run" => Ok((
                "export_job",
                self.payload
                    .export_id
                    .as_deref()
                    .ok_or(DataJobError::InvalidEnvelope)?,
            )),
            "deletion.run" => Ok((
                "deletion_job",
                self.payload
                    .deletion_id
                    .as_deref()
                    .ok_or(DataJobError::InvalidEnvelope)?,
            )),
            _ => Err(DataJobError::UnknownJobType),
        }
    }
}

/// `<prefix>_<32 lowercase hex>`. The prefix itself is not hex, so the check
/// applies to the suffix only.
fn valid_id(value: &str, prefix: &str) -> bool {
    value.len() == 36
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Which of the six fenced workflows a scope is currently blocking.
///
/// The certificate and the job projection record this so a reader can tell
/// "the job did not touch webhook fan-out because it was fenced" from "the job
/// never looked".
pub fn fence_report(
    cutoff_at: Option<u64>,
    organization_pending_deletion: bool,
    now: u64,
) -> Vec<FenceDecision> {
    [
        FencedWorkflow::AutomationDispatch,
        FencedWorkflow::WebhookFanOut,
        FencedWorkflow::NotificationFanOut,
        FencedWorkflow::BillingWrites,
        FencedWorkflow::ExportCreation,
        FencedWorkflow::DeletionRetry,
    ]
    .into_iter()
    .map(|workflow| decide_fence(workflow, cutoff_at, organization_pending_deletion, now))
    .collect()
}

// ------------------------------------------------------------- export ------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportOutcome {
    /// Durable completion. A redelivery returns this again and changes nothing.
    Ready,
    /// The job was already terminal when the message arrived.
    AlreadyTerminal,
    /// Partial failure. The same manifest and cutoff are reused on the retry.
    RetryScheduled,
    /// Fenced by a deletion cutoff: a delayed job may not resurrect data.
    Fenced,
}

pub struct ExportRunner<'a> {
    database: &'a D1Adapter,
    artifacts: Option<ExportArtifactStore>,
    now: &'a Timestamp,
}

impl<'a> ExportRunner<'a> {
    pub fn new(
        database: &'a D1Adapter,
        artifacts: Option<ExportArtifactStore>,
        now: &'a Timestamp,
    ) -> Self {
        Self {
            database,
            artifacts,
            now,
        }
    }

    /// Run one `export.run` delivery to a durable decision.
    pub async fn run(&self, export_id: &str) -> Result<ExportOutcome, DataJobError> {
        let repository = DataGovernanceRepository::new(self.database);
        let job = self.load_export(&repository, export_id).await?;
        let state = parse_export_state(&job.state).ok_or(DataJobError::StoreUnavailable)?;

        if state.is_terminal() {
            return Ok(ExportOutcome::AlreadyTerminal);
        }
        if state == ExportJobState::Ready {
            return Ok(ExportOutcome::Ready);
        }

        // A delayed export must not resurrect data for a scope that is being
        // deleted. `decide_fence` is the single source of that rule, and it
        // reads the *deletion* cutoff, not the export's snapshot cutoff.
        if self.scope_is_fenced(&repository, &job).await? {
            self.transition(
                &repository,
                &job,
                ExportJobState::Failed,
                Some("deletion_cutoff_reached"),
                false,
            )
            .await?;
            return Ok(ExportOutcome::Fenced);
        }

        // 1. requested -> queued -> collecting. A retry re-enters `collecting`
        //    with the same frozen manifest and cutoff.
        let job = self.enter_collecting(&job, state).await?;
        let manifest = frozen_manifest(&job)?;

        // 2. Collect the frozen categories as a consistent snapshot. A manifest
        //    that is not the frozen canonical form is a hard failure: a retry
        //    must never widen or re-order the request.
        let document = self
            .collect(&repository, &manifest)
            .await
            .map_err(|_| DataJobError::StoreUnavailable)?;
        self.store_artifact(&repository, &job, &manifest, &document)
            .await?;
        Ok(ExportOutcome::Ready)
    }

    /// Package, store, verify, and mark `ready`. Split out so each stage has one
    /// failure mode and one retry decision.
    async fn store_artifact(
        &self,
        repository: &DataGovernanceRepository<'_>,
        job: &ExportJobRecord,
        manifest: &ExportManifest,
        document: &Value,
    ) -> Result<(), DataJobError> {
        let Some(artifacts) = self.artifacts.as_ref() else {
            self.schedule_retry(repository, job, "export_artifact_unavailable")
                .await?;
            return Ok(());
        };
        let body =
            serde_json::to_string(document).map_err(|_| DataJobError::ExportManifestDrifted)?;
        let digest = sha256_hex(&body)
            .await
            .map_err(|_| DataJobError::StoreUnavailable)?;
        let key = build_object_key(
            manifest.scope.scope_id(),
            &job.export_id,
            &digest_opaque(&digest),
        )
        .map_err(|_| DataJobError::ExportArtifactUnavailable)?;
        let format = parse_export_format(&job.format).ok_or(DataJobError::StoreUnavailable)?;
        let stored = artifacts
            .put(crate::adapters::r2::PutArtifact {
                key: &key,
                body: body.into_bytes(),
                content_type: format_content_type(format),
                sha256_hex: &digest,
            })
            .await;
        let stored = match stored {
            Ok(stored) => stored,
            Err(ArtifactError::BodyTooLarge | ArtifactError::InvalidKey) => {
                // Not retryable: a larger body or a bad key is a policy problem.
                self.transition(
                    repository,
                    job,
                    ExportJobState::Failed,
                    Some("export_artifact_unavailable"),
                    false,
                )
                .await?;
                return Err(DataJobError::ExportArtifactUnavailable);
            }
            Err(_) => {
                self.schedule_retry(repository, job, "export_artifact_store_failed")
                    .await?;
                return Ok(());
            }
        };

        // Verify before `ready`. A `ready` job with an absent or mismatched
        // object would mint a download grant for nothing.
        let head = match artifacts.head(&key).await {
            Ok(Some(head)) => head,
            Ok(None) => {
                self.schedule_retry(repository, job, "export_artifact_verify_failed")
                    .await?;
                return Ok(());
            }
            Err(_) => {
                self.schedule_retry(repository, job, "export_artifact_verify_failed")
                    .await?;
                return Ok(());
            }
        };
        if head.size_bytes != stored.size_bytes
            || head.sha256_hex.as_deref() != stored.sha256_hex.as_deref()
        {
            self.schedule_retry(repository, job, "export_artifact_verify_failed")
                .await?;
            return Ok(());
        }

        let expires_at = crate::adapters::add_seconds(self.now, artifact_ttl_seconds())
            .map_err(|_| DataJobError::StoreUnavailable)?;
        let statement = repository
            .insert_artifact_statement(&NewArtifactInput {
                artifact_id: &generated_id("art"),
                export_id: &job.export_id,
                org_id: job.org_id.as_deref(),
                object_key: key.as_str(),
                bucket_name: crate::adapters::r2::ARTIFACT_BINDING,
                content_type: format_content_type(format),
                size_bytes: i64::try_from(head.size_bytes).unwrap_or(i64::MAX),
                checksum_sha256: &digest,
                created_at: self.now.as_str(),
                expires_at: expires_at.as_str(),
            })
            .map_err(|_| DataJobError::StoreUnavailable)?;
        self.database
            .batch(vec![statement])
            .await
            .map_err(|_| DataJobError::StoreUnavailable)?;
        self.transition(repository, job, ExportJobState::Ready, None, false)
            .await
    }

    async fn scope_is_fenced(
        &self,
        repository: &DataGovernanceRepository<'_>,
        job: &ExportJobRecord,
    ) -> Result<bool, DataJobError> {
        let Some(org_id) = job.scope_org_id.as_deref() else {
            // A personal export is not tenant data, so the tenant deletion fence
            // does not apply to it. A personal *deletion* fence is checked by the
            // personal deletion job itself.
            return Ok(false);
        };
        let Some(deletion) = repository
            .find_deletion_for_target("organization", org_id)
            .await
            .map_err(|_| DataJobError::StoreUnavailable)?
        else {
            return Ok(false);
        };
        let pending = deletion.state == "queued"
            || deletion.state == "planning"
            || deletion.state == "deleting"
            || deletion.state == "verifying"
            || deletion.state == "needs_attention";
        let decision = decide_fence(
            FencedWorkflow::ExportCreation,
            deletion.cutoff_at.as_deref().and_then(unix_seconds),
            pending,
            unix_seconds(self.now.as_str()).unwrap_or_default(),
        );
        Ok(decision.action.is_blocked() && !deletion.certificate_id.is_some())
    }

    async fn enter_collecting(
        &self,
        job: &ExportJobRecord,
        state: ExportJobState,
    ) -> Result<ExportJobRecord, DataJobError> {
        let repository = DataGovernanceRepository::new(self.database);
        let mut current = job.clone();
        if state == ExportJobState::Requested {
            self.transition(&repository, &current, ExportJobState::Queued, None, false)
                .await?;
            current = self.load_export(&repository, &job.export_id).await?;
        }
        let state = parse_export_state(&current.state).ok_or(DataJobError::StoreUnavailable)?;
        if state == ExportJobState::Queued {
            self.transition(
                &repository,
                &current,
                ExportJobState::Collecting,
                None,
                false,
            )
            .await?;
            current = self.load_export(&repository, &job.export_id).await?;
        }
        Ok(current)
    }

    async fn load_export(
        &self,
        repository: &DataGovernanceRepository<'_>,
        export_id: &str,
    ) -> Result<ExportJobRecord, DataJobError> {
        repository
            .find_export(export_id)
            .await
            .map_err(|_| DataJobError::StoreUnavailable)?
            .ok_or(DataJobError::ExportNotFound)
    }

    /// One compare-and-set export state move, followed by a re-read so the next
    /// call always sees the durable state.
    async fn transition(
        &self,
        repository: &DataGovernanceRepository<'_>,
        job: &ExportJobRecord,
        next: ExportJobState,
        failure_code: Option<&str>,
        retry: bool,
    ) -> Result<(), DataJobError> {
        parse_export_state(&job.state)
            .ok_or(DataJobError::StoreUnavailable)?
            .transition(next)
            .map_err(|_| DataJobError::ExportTerminal)?;
        let next_attempt_at = if retry {
            let delay = retry_delay_seconds(job.attempt.clamp(0, 5) as u32);
            Some(
                crate::adapters::add_seconds(self.now, delay)
                    .map_err(|_| DataJobError::StoreUnavailable)?,
            )
        } else {
            None
        };
        let statement = repository
            .update_export_state_statement(&crate::repositories::ExportStateUpdateInput {
                export_id: &job.export_id,
                expected_version: job.version,
                next_state: next.as_str(),
                increment_attempt: next.is_retry(),
                next_attempt_at: next_attempt_at.as_ref().map(|value| value.as_str()),
                failure_code,
                ready_at: (next == ExportJobState::Ready).then_some(self.now.as_str()),
                finished_at: next.is_terminal().then_some(self.now.as_str()),
                expected_state: &job.state,
                now: self.now,
            })
            .map_err(|_| DataJobError::StoreUnavailable)?;
        self.database
            .batch(vec![statement])
            .await
            .map_err(|_| DataJobError::StoreUnavailable)?;
        Ok(())
    }

    async fn schedule_retry(
        &self,
        repository: &DataGovernanceRepository<'_>,
        job: &ExportJobRecord,
        code: &str,
    ) -> Result<(), DataJobError> {
        if job.attempt + 1 >= MAX_JOB_ATTEMPTS {
            return self
                .transition(repository, job, ExportJobState::Failed, Some(code), false)
                .await;
        }
        self.transition(repository, job, ExportJobState::RetryWait, Some(code), true)
            .await
    }

    /// Collect the frozen manifest.
    ///
    /// The document is bounded metadata: identifiers, states, counts, versions,
    /// and timestamps. No prompt, response, tool argument, credential, or secret
    /// has a column in any collection statement, so a category cannot leak
    /// content by configuration.
    async fn collect(
        &self,
        repository: &DataGovernanceRepository<'_>,
        manifest: &ExportManifest,
    ) -> Result<Value, DataJobError> {
        let cutoff_at =
            unix_to_timestamp(manifest.cutoff_at).ok_or(DataJobError::ExportManifestDrifted)?;
        let mut categories = Map::new();
        for category in &manifest.categories {
            let rows = repository
                .collect_category(*category, &manifest.scope, &cutoff_at, EXPORT_ROW_LIMIT)
                .await
                .map_err(|_| DataJobError::StoreUnavailable)?;
            categories.insert((*category).as_str().to_owned(), Value::Array(rows));
        }
        Ok(json!({
            "schema": "lumi.data_export.v1",
            "scope_type": manifest.scope.scope_type(),
            "scope_id": manifest.scope.scope_id(),
            "format": manifest.format.as_str(),
            "snapshot_cutoff_at": cutoff_at,
            "row_limit_per_category": EXPORT_ROW_LIMIT,
            "categories": Value::Object(categories),
            "disclosures": deletion::DISCLOSURES,
        }))
    }
}

/// Rebuild the frozen manifest from the job row and prove it is the stored one.
///
/// The stored `categories_json` and `snapshot_cutoff_at` are the request-time
/// contract. Re-serializing the parsed categories and comparing with the stored
/// document is what makes "a retry reuses the same manifest and cutoff" a
/// checked property rather than a comment.
pub fn frozen_manifest(job: &ExportJobRecord) -> Result<ExportManifest, DataJobError> {
    let categories: Vec<ExportCategory> = serde_json::from_str(&job.categories_json)
        .map_err(|_| DataJobError::ExportManifestDrifted)?;
    if categories.is_empty() || categories.len() > 8 {
        return Err(DataJobError::ExportManifestDrifted);
    }
    let scope = ExportScope::new(&job.scope_type, job.scope_id().unwrap_or_default())
        .map_err(|_| DataJobError::ExportManifestDrifted)?;
    for category in &categories {
        if !scope.allows(*category) {
            return Err(DataJobError::ExportManifestDrifted);
        }
    }
    let format = parse_export_format(&job.format).ok_or(DataJobError::ExportManifestDrifted)?;
    let cutoff_at =
        unix_seconds(&job.snapshot_cutoff_at).ok_or(DataJobError::ExportManifestDrifted)?;
    let manifest = ExportManifest::new(scope, categories, cutoff_at, format);
    if !is_canonical(&manifest, &job.categories_json) {
        return Err(DataJobError::ExportManifestDrifted);
    }
    Ok(manifest)
}

/// The stored manifest must already be the canonical (sorted, deduplicated) form
/// the request froze. A drifted document is refused rather than repaired,
/// because repairing it would silently change which rows a retry collects.
pub fn is_canonical(manifest: &ExportManifest, stored_json: &str) -> bool {
    let Ok(categories) = serde_json::from_str::<Vec<ExportCategory>>(stored_json) else {
        return false;
    };
    let Ok(canonical) = serde_json::to_string(&manifest.categories) else {
        return false;
    };
    let Ok(original) = serde_json::to_string(&categories) else {
        return false;
    };
    canonical == original && manifest_is_stable(manifest, manifest)
}

/// Default artifact lifetime: the frozen `default_export_expiry_seconds`
/// baseline, well inside the seven-day ceiling ADR 0006 allows.
pub const fn artifact_ttl_seconds() -> u32 {
    86_400
}

/// The opaque object segment, derived from the content digest so a retry writes
/// the same key. Combined with the `export_id` segment, two scopes can never
/// produce the same key.
fn digest_opaque(digest: &str) -> String {
    let mut opaque = String::with_capacity(32);
    for byte in digest.as_bytes().iter().take(16) {
        use std::fmt::Write as _;
        let _ = write!(opaque, "{byte:02x}");
    }
    opaque
}

fn generated_id(prefix: &str) -> String {
    crate::adapters::new_resource_id(prefix).as_str().to_owned()
}

// ----------------------------------------------------------- deletion ------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeletionOutcome {
    Completed,
    AlreadyTerminal,
    RetryScheduled,
    NeedsAttention,
    Cancelled,
}

pub struct DeletionRunner<'a> {
    database: &'a D1Adapter,
    artifacts: Option<ExportArtifactStore>,
    now: &'a Timestamp,
}

impl<'a> DeletionRunner<'a> {
    pub fn new(
        database: &'a D1Adapter,
        artifacts: Option<ExportArtifactStore>,
        now: &'a Timestamp,
    ) -> Self {
        Self {
            database,
            artifacts,
            now,
        }
    }

    pub async fn run(&self, deletion_id: &str) -> Result<DeletionOutcome, DataJobError> {
        let repository = DataGovernanceRepository::new(self.database);
        let job = self.load(&repository, deletion_id).await?;
        let state = parse_deletion_state(&job.state).ok_or(DataJobError::StoreUnavailable)?;
        if state.is_terminal() {
            return Ok(DeletionOutcome::AlreadyTerminal);
        }
        if state == DeletionJobState::NeedsAttention {
            // The only way out of `needs_attention` is an authorized resume
            // through the HTTP route. A queue redelivery must not be that.
            return Ok(DeletionOutcome::NeedsAttention);
        }

        let job = self.leave_grace(&repository, &job).await?;
        let job = self.plan(&repository, &job).await?;
        let job = self.execute(&repository, &job).await?;
        self.verify(&repository, &job).await?;
        Ok(DeletionOutcome::Completed)
    }

    async fn load(
        &self,
        repository: &DataGovernanceRepository<'_>,
        deletion_id: &str,
    ) -> Result<DeletionJobRecord, DataJobError> {
        repository
            .find_deletion(deletion_id)
            .await
            .map_err(|_| DataJobError::StoreUnavailable)?
            .ok_or(DataJobError::DeletionNotFound)
    }

    /// `requested → awaiting_grace → queued` for a personal job. A bridged
    /// organization job starts in `queued` because P02 owns its window.
    async fn leave_grace(
        &self,
        repository: &DataGovernanceRepository<'_>,
        job: &DeletionJobRecord,
    ) -> Result<DeletionJobRecord, DataJobError> {
        let state = parse_deletion_state(&job.state).ok_or(DataJobError::StoreUnavailable)?;
        if state == DeletionJobState::Requested {
            self.transition(
                repository,
                job,
                DeletionJobState::AwaitingGrace,
                None,
                false,
            )
            .await?;
            let current = self.load(repository, &job.deletion_id).await?;
            return Box::pin(self.leave_grace(repository, &current)).await;
        }
        if state == DeletionJobState::AwaitingGrace {
            let now_unix = unix_seconds(self.now.as_str()).unwrap_or_default();
            let grace_expires_at = job.grace_expires_at.as_deref().and_then(unix_seconds);
            if DeletionJobState::grace_cancel_allowed(state, now_unix, grace_expires_at) {
                // Still inside the bounded window: the job waits, and the user
                // may still cancel.
                return Ok(job.clone());
            }
            self.transition(repository, job, DeletionJobState::Queued, None, false)
                .await?;
            return self.load(repository, &job.deletion_id).await;
        }
        Ok(job.clone())
    }

    /// Plan the deletion from a real inventory and persist the steps.
    async fn plan(
        &self,
        repository: &DataGovernanceRepository<'_>,
        job: &DeletionJobRecord,
    ) -> Result<DeletionJobRecord, DataJobError> {
        let state = parse_deletion_state(&job.state).ok_or(DataJobError::StoreUnavailable)?;
        if state != DeletionJobState::Queued {
            return Ok(job.clone());
        }
        self.transition(repository, job, DeletionJobState::Planning, None, false)
            .await?;
        let planning = self.load(repository, &job.deletion_id).await?;
        let target = DeletionTarget::new(
            &planning.target_type,
            planning.target_id().unwrap_or_default(),
        )
        .map_err(|_| DataJobError::DeletionNotFound)?;
        let inventory = repository
            .deletion_inventory(&target, 1_024)
            .await
            .map_err(|_| DataJobError::StoreUnavailable)?;
        if inventory.is_empty() {
            // Nothing to traverse means the planner cannot produce a plan, and a
            // deletion must never be "completed" from an empty walk.
            self.park(repository, &planning, "deletion_reference_system_absent")
                .await?;
            return self.load(repository, &planning.deletion_id).await;
        }
        let hold = self.legal_hold(&planning).await?;
        let plan = DeletionPlanner::plan(
            target,
            &inventory,
            hold.as_ref(),
            unix_seconds(self.now.as_str()).unwrap_or_default(),
        )
        .map_err(|_| DataJobError::DeletionBlocked)?;
        self.persist_plan(repository, &planning, &plan).await?;
        if plan.legal_hold_blocks {
            self.park(
                repository,
                &planning,
                DeletionSkipReason::LegalHold.as_str(),
            )
            .await?;
            return self.load(repository, &planning.deletion_id).await;
        }
        self.transition(
            repository,
            &planning,
            DeletionJobState::Deleting,
            None,
            false,
        )
        .await?;
        self.load(repository, &planning.deletion_id).await
    }

    async fn persist_plan(
        &self,
        repository: &DataGovernanceRepository<'_>,
        job: &DeletionJobRecord,
        plan: &DeletionPlan,
    ) -> Result<(), DataJobError> {
        // `deletion_tasks.data_class` has a foreign key onto the F20 declaration
        // table, so the frozen registry is seeded (idempotently) in the same
        // transaction as the steps. Without it a plan could not be persisted at
        // all, and a job that cannot record a step must never claim success.
        let mut statements = repository
            .registry_seed_statements(self.now)
            .map_err(|_| DataJobError::StoreUnavailable)?;
        statements.reserve(plan.steps.len());
        for step in &plan.steps {
            let completed_at = step.completed_at.and_then(unix_to_timestamp);
            statements.push(
                repository
                    .insert_deletion_task_statement(&NewDeletionTaskInput {
                        task_id: &generated_id("dts"),
                        deletion_id: &job.deletion_id,
                        org_id: job.org_id.as_deref(),
                        data_class: step.data_class.as_str(),
                        reference_kind: step.reference_kind.as_str(),
                        object_reference: &step.object_reference,
                        state: step.state.as_str(),
                        attempt: i64::from(step.attempt),
                        skip_reason: step.skip_reason.map(|reason| reason.as_str()),
                        started_at: None,
                        completed_at: completed_at.as_deref(),
                        now: self.now,
                    })
                    .map_err(|_| DataJobError::StoreUnavailable)?,
            );
        }
        self.database
            .batch(statements)
            .await
            .map_err(|_| DataJobError::StoreUnavailable)?;
        Ok(())
    }

    /// Execute the planned steps Lumi owns, idempotently.
    async fn execute(
        &self,
        repository: &DataGovernanceRepository<'_>,
        job: &DeletionJobRecord,
    ) -> Result<DeletionJobRecord, DataJobError> {
        let state = parse_deletion_state(&job.state).ok_or(DataJobError::StoreUnavailable)?;
        if state != DeletionJobState::Deleting {
            return Ok(job.clone());
        }
        let tasks = repository
            .list_pending_deletion_tasks(&job.deletion_id, 200)
            .await
            .map_err(|_| DataJobError::StoreUnavailable)?;
        for task in tasks {
            if self.execute_step(repository, &task).await.is_err() {
                // The class is actionable but this control plane cannot perform
                // it. Park instead of claiming a deletion that did not happen.
                self.park_step(repository, &task).await?;
                self.park(
                    repository,
                    job,
                    DataJobError::StepExecutorUnavailable.code(),
                )
                .await?;
                return self.load(repository, &job.deletion_id).await;
            }
        }
        self.transition(repository, job, DeletionJobState::Verifying, None, false)
            .await?;
        self.load(repository, &job.deletion_id).await
    }

    async fn execute_step(
        &self,
        repository: &DataGovernanceRepository<'_>,
        task: &DeletionTaskRecord,
    ) -> Result<(), DataJobError> {
        let kind = ReferenceKind::parse(&task.reference_kind).ok_or(DataJobError::StepFailed)?;
        match kind {
            // Lumi does not own these. The planner records them as skipped, so a
            // step reaching execution for one of them is a defect and must never
            // be reported as a deletion.
            ReferenceKind::LocalDeviceData | ReferenceKind::UpstreamProviderData => {
                Err(DataJobError::StepExecutorUnavailable)
            }
            ReferenceKind::R2Object => {
                let artifacts = self
                    .artifacts
                    .as_ref()
                    .ok_or(DataJobError::StoreUnavailable)?;
                let key = ObjectKey::new(task.object_reference.clone())
                    .map_err(|_| DataJobError::StepFailed)?;
                artifacts
                    .delete(&key)
                    .await
                    .map_err(|_| DataJobError::StoreUnavailable)?;
                // A certificate may only claim absence after a real probe; D1
                // metadata is not sufficient evidence (ADR 0006, F20-007).
                if !artifacts
                    .is_absent(&key)
                    .await
                    .map_err(|_| DataJobError::StoreUnavailable)?
                {
                    return Err(DataJobError::ObjectAbsent);
                }
                self.complete_step(repository, task).await
            }
            ReferenceKind::DatabaseRow => {
                let class = crate::modules::data_governance::DataClass::new(&task.data_class)
                    .map_err(|_| DataJobError::StepFailed)?;
                let executor = database_row_executor(&class, kind)
                    .ok_or(DataJobError::StepExecutorUnavailable)?;
                let mut values: Vec<crate::adapters::d1::BindValue<'_>> =
                    vec![crate::adapters::d1::BindValue::Text(&task.object_reference)];
                if executor.outcome == RowOutcome::Revoke {
                    values.push(crate::adapters::d1::BindValue::Text(self.now.as_str()));
                }
                let statement = self
                    .database
                    .prepare(executor.statement, &values)
                    .map_err(|_| DataJobError::StoreUnavailable)?;
                self.database
                    .batch(vec![statement])
                    .await
                    .map_err(|_| DataJobError::StepFailed)?;
                self.complete_step(repository, task).await
            }
        }
    }

    async fn complete_step(
        &self,
        repository: &DataGovernanceRepository<'_>,
        task: &DeletionTaskRecord,
    ) -> Result<(), DataJobError> {
        let statement = repository
            .update_deletion_task_statement(&crate::repositories::DeletionTaskUpdateInput {
                deletion_id: &task.deletion_id,
                data_class: &task.data_class,
                reference_kind: &task.reference_kind,
                object_reference: &task.object_reference,
                next_state: DeletionStepState::Succeeded.as_str(),
                increment_attempt: false,
                failure_code: None,
                skip_reason: None,
                started_at: None,
                completed_at: Some(self.now.as_str()),
                expected_state: &task.state,
                now: self.now,
            })
            .map_err(|_| DataJobError::StoreUnavailable)?;
        self.database
            .batch(vec![statement])
            .await
            .map_err(|_| DataJobError::StoreUnavailable)?;
        Ok(())
    }

    async fn park_step(
        &self,
        repository: &DataGovernanceRepository<'_>,
        task: &DeletionTaskRecord,
    ) -> Result<(), DataJobError> {
        let statement = repository
            .update_deletion_task_statement(&crate::repositories::DeletionTaskUpdateInput {
                deletion_id: &task.deletion_id,
                data_class: &task.data_class,
                reference_kind: &task.reference_kind,
                object_reference: &task.object_reference,
                next_state: DeletionStepState::NeedsAttention.as_str(),
                increment_attempt: false,
                failure_code: Some(DataJobError::StepExecutorUnavailable.code()),
                skip_reason: None,
                started_at: None,
                completed_at: None,
                expected_state: &task.state,
                now: self.now,
            })
            .map_err(|_| DataJobError::StoreUnavailable)?;
        self.database
            .batch(vec![statement])
            .await
            .map_err(|_| DataJobError::StoreUnavailable)?;
        Ok(())
    }

    /// Verify the traversal, then write the certificate.
    ///
    /// Completion is only claimed when the reference traversal is done, every
    /// R2 object is proven absent, and every planned step reached a terminal
    /// state. The certificate states which reference systems were traversed and
    /// which do not exist yet, so it reports coverage instead of implying it.
    async fn verify(
        &self,
        repository: &DataGovernanceRepository<'_>,
        job: &DeletionJobRecord,
    ) -> Result<(), DataJobError> {
        let state = parse_deletion_state(&job.state).ok_or(DataJobError::StoreUnavailable)?;
        if state != DeletionJobState::Verifying {
            return Ok(());
        }
        let tasks = repository
            .list_deletion_tasks(&job.deletion_id, 1_000)
            .await
            .map_err(|_| DataJobError::StoreUnavailable)?;
        if tasks.is_empty() {
            return Err(DataJobError::DeletionBlocked);
        }
        if tasks.iter().any(|task| !is_terminal_step(&task.state)) {
            self.park(repository, job, "deletion_steps_unresolved")
                .await?;
            return Ok(());
        }
        if let Some(artifacts) = self.artifacts.as_ref() {
            for task in tasks
                .iter()
                .filter(|task| task.reference_kind == ReferenceKind::R2Object.as_str())
            {
                if let Ok(key) = ObjectKey::new(task.object_reference.clone())
                    && !artifacts
                        .is_absent(&key)
                        .await
                        .map_err(|_| DataJobError::StoreUnavailable)?
                {
                    return Err(DataJobError::ObjectAbsent);
                }
            }
        }

        let coverage = reference_coverage();
        let results = serde_json::to_string(&certificate_class_results(&tasks, &coverage))
            .map_err(|_| DataJobError::StoreUnavailable)?;
        let retained = serde_json::to_string(&retained_legal_classes(&tasks))
            .map_err(|_| DataJobError::StoreUnavailable)?;
        let certificate_id = generated_id("delc");
        let now_unix = unix_seconds(self.now.as_str()).unwrap_or_default();
        let certificate_expires = certificate_expiry(now_unix);
        let statement = repository
            .insert_certificate_statement(&NewCertificateInput {
                certificate_id: &certificate_id,
                deletion_id: &job.deletion_id,
                org_id: job.org_id.as_deref(),
                scope_type: &job.target_type,
                scope_id: job.target_id().unwrap_or_default(),
                class_results_json: &results,
                retained_legal_classes_json: &retained,
                completed_at: self.now.as_str(),
                expires_at: &certificate_expires,
                now: self.now,
            })
            .map_err(|_| DataJobError::StoreUnavailable)?;
        self.database
            .batch(vec![statement])
            .await
            .map_err(|_| DataJobError::StoreUnavailable)?;
        // Link the certificate before the terminal transition so a reader of a
        // `completed` job always finds its certificate.
        repository
            .update_deletion_state_statement(&crate::repositories::DeletionStateUpdateInput {
                deletion_id: &job.deletion_id,
                expected_version: job.version,
                next_state: DeletionJobState::Completed.as_str(),
                increment_attempt: false,
                next_attempt_at: None,
                failure_code: None,
                grace_expires_at: None,
                certificate_id: Some(&certificate_id),
                completed_at: Some(self.now.as_str()),
                expected_state: &job.state,
                now: self.now,
            })
            .map_err(|_| DataJobError::StoreUnavailable)?
            .run()
            .await
            .map_err(|_| DataJobError::StoreUnavailable)?;
        Ok(())
    }

    async fn park(
        &self,
        repository: &DataGovernanceRepository<'_>,
        job: &DeletionJobRecord,
        code: &str,
    ) -> Result<(), DataJobError> {
        self.transition(
            repository,
            job,
            DeletionJobState::NeedsAttention,
            Some(code),
            false,
        )
        .await
    }

    async fn legal_hold(&self, job: &DeletionJobRecord) -> Result<Option<LegalHold>, DataJobError> {
        if !job.legal_hold_active() {
            return Ok(None);
        }
        let Some(policy) = self.policy(job).await? else {
            return Ok(None);
        };
        if !policy.legal_hold_active() {
            return Ok(None);
        }
        LegalHold::scope_wide(
            unix_seconds(
                policy
                    .legal_hold_placed_at
                    .as_deref()
                    .unwrap_or(&policy.created_at),
            )
            .unwrap_or_default(),
            policy
                .legal_hold_reason
                .as_deref()
                .unwrap_or("legal hold recorded"),
        )
        .map(Some)
        .map_err(|_| DataJobError::DeletionBlocked)
    }

    async fn policy(
        &self,
        job: &DeletionJobRecord,
    ) -> Result<Option<DataGovernancePolicyRecord>, DataJobError> {
        let Some(org_id) = job.org_id.as_deref() else {
            return Ok(None);
        };
        DataGovernanceRepository::new(self.database)
            .find_policy(org_id)
            .await
            .map_err(|_| DataJobError::StoreUnavailable)
    }

    async fn transition(
        &self,
        repository: &DataGovernanceRepository<'_>,
        job: &DeletionJobRecord,
        next: DeletionJobState,
        failure_code: Option<&str>,
        retry: bool,
    ) -> Result<(), DataJobError> {
        parse_deletion_state(&job.state)
            .ok_or(DataJobError::StoreUnavailable)?
            .transition(next)
            .map_err(|_| DataJobError::DeletionTerminal)?;
        let next_attempt_at = if retry {
            let delay = retry_delay_seconds(job.attempt.clamp(0, 5) as u32);
            Some(
                crate::adapters::add_seconds(self.now, delay)
                    .map_err(|_| DataJobError::StoreUnavailable)?,
            )
        } else {
            None
        };
        let statement = repository
            .update_deletion_state_statement(&crate::repositories::DeletionStateUpdateInput {
                deletion_id: &job.deletion_id,
                expected_version: job.version,
                next_state: next.as_str(),
                increment_attempt: next == DeletionJobState::RetryWait,
                next_attempt_at: next_attempt_at.as_ref().map(|value| value.as_str()),
                failure_code,
                grace_expires_at: None,
                certificate_id: None,
                completed_at: (next == DeletionJobState::Completed).then_some(self.now.as_str()),
                expected_state: &job.state,
                now: self.now,
            })
            .map_err(|_| DataJobError::StoreUnavailable)?;
        self.database
            .batch(vec![statement])
            .await
            .map_err(|_| DataJobError::StoreUnavailable)?;
        Ok(())
    }
}

fn is_terminal_step(state: &str) -> bool {
    parse_deletion_step_state(state).is_some_and(DeletionStepState::is_terminal)
}

/// Per-class outcome summary for the certificate.
///
/// Tombstoned references only: a class, its step states, and a count, plus the
/// reference-coverage statement. No deleted content, credential, or secret.
pub fn certificate_class_results(
    tasks: &[DeletionTaskRecord],
    coverage: &crate::modules::data_governance::ReferenceCoverage,
) -> Value {
    let mut classes: std::collections::BTreeMap<&str, std::collections::BTreeMap<&str, i64>> =
        std::collections::BTreeMap::new();
    for task in tasks {
        *classes
            .entry(task.data_class.as_str())
            .or_default()
            .entry(task.state.as_str())
            .or_default() += 1;
    }
    let mut out = Map::new();
    for (class, states) in classes {
        let mut summary = Map::new();
        for (state, count) in states {
            summary.insert(state.to_owned(), json!(count));
        }
        out.insert(class.to_owned(), Value::Object(summary));
    }
    out.insert(
        "reference_coverage".to_owned(),
        json!({
            "traversed": coverage.traversed,
            "pending": coverage.pending,
            "absent_reason": coverage.absent_reason(),
        }),
    );
    out.insert("disclosures".to_owned(), json!(deletion::DISCLOSURES));
    out.insert(
        "organization_row".to_owned(),
        json!("deletion_org_row_managed_by_lifecycle"),
    );
    Value::Object(out)
}

/// Classes the certificate must report as deliberately retained.
pub fn retained_legal_classes(tasks: &[DeletionTaskRecord]) -> Vec<String> {
    let mut retained: Vec<String> = tasks
        .iter()
        .filter(|task| {
            task.state == DeletionStepState::Skipped.as_str()
                && task.skip_reason.as_deref().is_some_and(|reason| {
                    reason == DeletionSkipReason::RetainedLegalOnly.as_str()
                        || reason == DeletionSkipReason::LegalHold.as_str()
                })
        })
        .map(|task| task.data_class.clone())
        .collect();
    retained.sort();
    retained.dedup();
    retained
}

/// Reference systems the control plane cannot traverse yet. The certificate
/// states them instead of implying full coverage (F20-007).
pub fn pending_reference_systems() -> Vec<&'static str> {
    deletion::PENDING_REFERENCE_SYSTEMS.to_vec()
}

/// Certificate retention: 365 days from completion, per the frozen gate.
pub const fn certificate_retention_days() -> u64 {
    365
}

fn certificate_expiry(now_unix: u64) -> String {
    let seconds = now_unix.saturating_add(certificate_retention_days() * 86_400);
    unix_to_timestamp(seconds).unwrap_or_default()
}

/// Parse a stored RFC 3339 UTC timestamp into Unix seconds.
///
/// A stored timestamp always has the frozen `YYYY-MM-DDTHH:MM:SS.mmmZ` shape,
/// so the conversion is fixed-offset arithmetic and never a local-timezone read.
pub fn unix_seconds(value: &str) -> Option<u64> {
    if value.len() < 20 {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<u64> {
        let slice = value.get(range)?;
        if !slice.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        slice.parse::<u64>().ok()
    };
    let year = number(0..4)?;
    let month = number(5..7)?;
    let day = number(8..10)?;
    let hour = number(11..13)?;
    let minute = number(14..16)?;
    let second = number(17..19)?;
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Format Unix seconds as the frozen `YYYY-MM-DDTHH:MM:SS.mmmZ` shape.
pub fn unix_to_timestamp(seconds: u64) -> Option<String> {
    let days = seconds / 86_400;
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour_out_of_range(rest) {
        return None;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z",
        rest / 3_600,
        (rest % 3_600) / 60,
        rest % 60
    ))
}

fn hour_out_of_range(rest: u64) -> bool {
    rest / 3_600 > 23
}

/// Howard Hinnant's `days_from_civil`: a proleptic Gregorian day count, exact
/// and independent of any host calendar or timezone database.
const fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

const fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

// ------------------------------------------------------ envelope driver ----

/// Durable decision for one delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataJobOutcome {
    Ready,
    Completed,
    /// The envelope was already durably complete; this delivery changed nothing.
    AlreadyComplete,
    RetryScheduled,
    NeedsAttention,
    Failed,
}

impl DataJobOutcome {
    fn from_export(outcome: ExportOutcome) -> Self {
        match outcome {
            ExportOutcome::Ready | ExportOutcome::AlreadyTerminal => Self::Ready,
            ExportOutcome::RetryScheduled => Self::RetryScheduled,
            ExportOutcome::Fenced => Self::Failed,
        }
    }

    fn from_deletion(outcome: DeletionOutcome) -> Self {
        match outcome {
            DeletionOutcome::Completed | DeletionOutcome::AlreadyTerminal => Self::Completed,
            DeletionOutcome::RetryScheduled => Self::RetryScheduled,
            DeletionOutcome::NeedsAttention => Self::NeedsAttention,
            DeletionOutcome::Cancelled => Self::Failed,
        }
    }
}

/// Handle one decoded job message.
///
/// The caller owns the D1 and R2 bindings; this function owns the durable
/// transitions. A duplicate delivery after durable completion is a no-op.
pub async fn handle_data_job(
    database: &D1Adapter,
    artifacts: Option<ExportArtifactStore>,
    now: &Timestamp,
    envelope: &DataJobEnvelope,
) -> Result<DataJobOutcome, DataJobError> {
    envelope.validate()?;
    let (_, subject_id) = envelope.subject_id()?;
    let org_id = envelope.tenant_scope.org_id.clone();
    let key = dedupe_key(&envelope.job_type, subject_id);

    let repository = DataGovernanceRepository::new(database);
    let Some(record) = repository
        .find_queue_envelope(&envelope.job_type, org_id.as_deref(), &key, 0)
        .await
        .map_err(|_| DataJobError::StoreUnavailable)?
    else {
        return Err(DataJobError::ClaimConflict);
    };
    if record.state == "succeeded" || record.state == "cancelled" {
        return Ok(DataJobOutcome::AlreadyComplete);
    }

    let lease_expires_at = crate::adapters::add_seconds(now, JOB_LEASE_SECONDS)
        .map_err(|_| DataJobError::StoreUnavailable)?;
    let claim = repository
        .claim_queue_envelope_statement(
            &record.job_id,
            lease_expires_at.as_str(),
            record.version,
            now,
        )
        .map_err(|_| DataJobError::StoreUnavailable)?;
    let claimed = database
        .batch(vec![claim])
        .await
        .map_err(|_| DataJobError::StoreUnavailable)?;
    let changes = match claimed.first() {
        Some(result) => D1Adapter::changes(result).map_err(|_| DataJobError::StoreUnavailable)?,
        None => return Err(DataJobError::StoreUnavailable),
    };
    if changes == 0 {
        return Err(DataJobError::ClaimConflict);
    }

    let running = record.version + 1;
    let (outcome, error) = match envelope.job_type.as_str() {
        "export.run" => match ExportRunner::new(database, artifacts, now)
            .run(subject_id)
            .await
        {
            Ok(outcome) => (DataJobOutcome::from_export(outcome), None),
            Err(error) => (DataJobOutcome::Failed, Some(error)),
        },
        "deletion.run" => {
            match DeletionRunner::new(database, artifacts, now)
                .run(subject_id)
                .await
            {
                Ok(outcome) => (DataJobOutcome::from_deletion(outcome), None),
                Err(error) => (DataJobOutcome::Failed, Some(error)),
            }
        }
        _ => return Err(DataJobError::UnknownJobType),
    };

    let (settle_state, next_attempt_at, error_code) = match error {
        None => ("succeeded", None, None),
        Some(error) if error.is_retryable() => (
            "retry_wait",
            crate::adapters::add_seconds(now, retry_delay_seconds(record.attempt as u32))
                .ok()
                .map(|value| value.as_str().to_owned()),
            Some(error.code().to_owned()),
        ),
        Some(error) => ("dead_letter", None, Some(error.code().to_owned())),
    };
    let settle = repository
        .settle_queue_envelope_statement(
            &record.job_id,
            running,
            settle_state,
            next_attempt_at.as_deref(),
            error_code.as_deref(),
            now,
        )
        .map_err(|_| DataJobError::StoreUnavailable)?;
    database
        .batch(vec![settle])
        .await
        .map_err(|_| DataJobError::StoreUnavailable)?;
    Ok(outcome)
}

/// `StreamDescriptor` for one download, built from the stored artifact metadata.
pub fn stream_descriptor(content_type: &str, export_id: &str) -> Option<StreamDescriptor> {
    let extension = if content_type == "application/x-ndjson" {
        "jsonl"
    } else if content_type == "text/csv" {
        "csv"
    } else {
        "json"
    };
    StreamDescriptor::new(content_type, &format!("{export_id}.{extension}")).ok()
}

/// Effective expiry for one class under the current policy. Exposed so the
/// scheduled expiry sweep and the deletion planner agree on one decision.
pub fn effective_retention(
    policy: &RetentionPolicy,
    class: &str,
    anchor: Option<u64>,
    now: u64,
    hold: Option<&LegalHold>,
) -> Result<u64, RetentionError> {
    let record = crate::modules::data_governance::lookup_by_key(class)
        .map_err(|_| RetentionError::TooManyOverrides)?;
    decide(&record, policy, now, anchor, hold)
        .map(|decision| decision.expire_at.unwrap_or(u64::MAX))
}

/// Every registered class, in frozen declaration order. The expiry sweep walks
/// this list rather than a hand-maintained one.
pub fn governed_classes() -> Vec<String> {
    registry()
        .into_iter()
        .map(|record| record.class.as_str().to_owned())
        .collect()
}

/// `HoldScope::All` is what a policy-level hold means. Re-exported so the
/// routes do not need to name the retention module for one variant.
pub const fn hold_scope_all() -> HoldScope {
    HoldScope::All
}

/// Type-erased inventory re-export so the routes can build a resume view without
/// naming the deletion module.
pub type InventoryEntry = DeletionInventoryEntry;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::data_governance::ReferenceCoverage;

    const EXPORT_ID: &str = "exp_0123456789abcdef0123456789abcdef";
    const DELETION_ID: &str = "del_0123456789abcdef0123456789abcdef";
    const ORG_ID: &str = "org_0123456789abcdef0123456789abcdef";
    const USER_ID: &str = "usr_0123456789abcdef0123456789abcdef";

    /// The stored manifest is canonical, so the categories are in sorted order.
    const CANONICAL_CATEGORIES: &str = "[\"identity\",\"devices\"]";

    fn envelope(job_type: &str) -> DataJobEnvelope {
        DataJobEnvelope {
            job_id: "job_0123456789abcdef0123456789abcdef".to_owned(),
            job_type: job_type.to_owned(),
            schema_version: 1,
            dedupe_key: format!("{job_type}:{EXPORT_ID}"),
            event_id: None,
            request_id: None,
            correlation_id: None,
            attempt: 1,
            tenant_scope: TenantScope {
                org_id: Some(ORG_ID.to_owned()),
            },
            payload_ref: None,
            payload: DataJobPayload {
                export_id: Some(EXPORT_ID.to_owned()),
                deletion_id: None,
            },
        }
    }

    fn deletion_envelope() -> DataJobEnvelope {
        DataJobEnvelope {
            job_type: "deletion.run".to_owned(),
            dedupe_key: format!("deletion.run:{DELETION_ID}"),
            payload: DataJobPayload {
                export_id: None,
                deletion_id: Some(DELETION_ID.to_owned()),
            },
            ..envelope("deletion.run")
        }
    }

    fn export_job() -> ExportJobRecord {
        ExportJobRecord {
            export_id: EXPORT_ID.to_owned(),
            org_id: Some(ORG_ID.to_owned()),
            scope_type: "organization".to_owned(),
            scope_user_id: None,
            scope_org_id: Some(ORG_ID.to_owned()),
            categories_json: CANONICAL_CATEGORIES.to_owned(),
            format: "json".to_owned(),
            snapshot_cutoff_at: "2026-09-25T12:00:00.000Z".to_owned(),
            state: "collecting".to_owned(),
            state_version: 3,
            attempt: 0,
            next_attempt_at: None,
            requested_by_principal_id: USER_ID.to_owned(),
            requested_at: "2026-09-25T12:00:00.000Z".to_owned(),
            ready_at: None,
            finished_at: None,
            failure_code: None,
            version: 3,
            updated_at: "2026-09-25T12:00:00.000Z".to_owned(),
        }
    }

    #[test]
    fn envelope_accepts_only_the_frozen_job_types_and_its_own_payload() {
        assert!(envelope("export.run").validate().is_ok());
        assert!(deletion_envelope().validate().is_ok());

        let mut crossed = deletion_envelope();
        crossed.payload.export_id = Some(EXPORT_ID.to_owned());
        assert_eq!(crossed.validate(), Err(DataJobError::InvalidEnvelope));

        let mut unknown = envelope("export.run");
        unknown.job_type = "automation.dispatch".to_owned();
        assert_eq!(unknown.validate(), Err(DataJobError::UnknownJobType));

        let mut versioned = envelope("export.run");
        versioned.schema_version = 2;
        assert_eq!(versioned.validate(), Err(DataJobError::InvalidEnvelope));

        let mut wrong_job_id = envelope("export.run");
        wrong_job_id.job_id = "exp_0123456789abcdef0123456789abcdef".to_owned();
        assert_eq!(wrong_job_id.validate(), Err(DataJobError::InvalidEnvelope));
    }

    #[test]
    fn envelope_rejects_a_malformed_tenant_scope() {
        let mut foreign = envelope("export.run");
        foreign.tenant_scope.org_id = Some("not-an-org".to_owned());
        assert_eq!(foreign.validate(), Err(DataJobError::InvalidEnvelope));
        foreign.tenant_scope.org_id = None;
        assert!(
            foreign.validate().is_ok(),
            "a personal job has no org scope"
        );
    }

    #[test]
    fn envelope_parse_is_bounded_and_never_decodes_an_unbounded_message() {
        assert_eq!(
            DataJobEnvelope::parse("").unwrap_err(),
            DataJobError::MessageTooLarge
        );
        let huge = format!("{{\"padding\":\"{}\"}}", "x".repeat(MAX_JOB_MESSAGE_BYTES));
        assert_eq!(
            DataJobEnvelope::parse(&huge).unwrap_err(),
            DataJobError::MessageTooLarge
        );
        assert_eq!(
            DataJobEnvelope::parse("not json").unwrap_err(),
            DataJobError::InvalidEnvelope
        );
    }

    #[test]
    fn envelope_subject_is_derived_from_the_job_type() {
        assert_eq!(
            envelope("export.run").subject_id().unwrap(),
            ("export_job", EXPORT_ID)
        );
        assert_eq!(
            deletion_envelope().subject_id().unwrap(),
            ("deletion_job", DELETION_ID)
        );
    }

    #[test]
    fn retry_backoff_is_deterministic_and_bounded() {
        assert_eq!(retry_delay_seconds(0), 30);
        assert_eq!(retry_delay_seconds(1), 60);
        assert_eq!(retry_delay_seconds(5), RETRY_MAX_SECONDS);
        assert_eq!(retry_delay_seconds(200), RETRY_MAX_SECONDS);
    }

    #[test]
    fn dedupe_key_is_derived_from_the_frozen_subject() {
        assert_eq!(
            dedupe_key("export.run", EXPORT_ID),
            format!("export.run:{EXPORT_ID}")
        );
        assert_ne!(
            dedupe_key("export.run", EXPORT_ID),
            dedupe_key("export.run", "exp_1123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn retryable_and_permanent_failures_are_distinguished() {
        assert!(DataJobError::StoreUnavailable.is_retryable());
        assert!(DataJobError::ObjectAbsent.is_retryable());
        assert!(!DataJobError::UnknownJobType.is_retryable());
        assert!(!DataJobError::ExportManifestDrifted.is_retryable());
        assert!(!DataJobError::ClaimConflict.is_retryable());
        for error in [
            DataJobError::UnknownJobType,
            DataJobError::InvalidEnvelope,
            DataJobError::ClaimConflict,
            DataJobError::LeaseExpired,
            DataJobError::ExportFenced,
            DataJobError::StoreUnavailable,
        ] {
            assert_eq!(error.code(), error.code().to_lowercase());
        }
    }

    #[test]
    fn frozen_manifest_must_equal_its_stored_canonical_form() {
        let job = export_job();
        let manifest = frozen_manifest(&job).unwrap();
        assert_eq!(manifest.categories.len(), 2);
        assert!(is_canonical(&manifest, &job.categories_json));

        // A non-canonical stored document is refused, not repaired: repairing it
        // would silently change which rows a retry collects.
        let mut drifted = job.clone();
        drifted.categories_json = "[\"devices\",\"identity\"]".to_owned();
        assert!(!is_canonical(&manifest, &drifted.categories_json));
    }

    #[test]
    fn frozen_manifest_refuses_a_category_the_scope_cannot_reach() {
        let mut cross_scope = export_job();
        cross_scope.scope_type = "user".to_owned();
        cross_scope.scope_user_id = Some(USER_ID.to_owned());
        cross_scope.scope_org_id = None;
        cross_scope.org_id = None;
        assert_eq!(
            frozen_manifest(&cross_scope).unwrap_err(),
            DataJobError::ExportManifestDrifted
        );
    }

    #[test]
    fn frozen_manifest_refuses_an_unknown_format_or_cutoff() {
        let mut job = export_job();
        job.format = "tar".to_owned();
        assert_eq!(
            frozen_manifest(&job).unwrap_err(),
            DataJobError::ExportManifestDrifted
        );
        let mut job = export_job();
        job.snapshot_cutoff_at = "yesterday".to_owned();
        assert_eq!(
            frozen_manifest(&job).unwrap_err(),
            DataJobError::ExportManifestDrifted
        );
    }

    #[test]
    fn unix_second_conversion_round_trips() {
        assert_eq!(unix_seconds("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(
            unix_seconds("2026-09-25T12:00:00.000Z"),
            Some(1_790_337_600)
        );
        assert_eq!(
            unix_seconds("2024-02-29T23:59:59.000Z"),
            Some(1_709_251_199)
        );
        assert_eq!(unix_seconds("nope"), None);
        assert_eq!(unix_seconds(""), None);
        assert_eq!(
            unix_to_timestamp(0).as_deref(),
            Some("1970-01-01T00:00:00.000Z")
        );
        assert_eq!(
            unix_to_timestamp(1_790_337_600).as_deref(),
            Some("2026-09-25T12:00:00.000Z")
        );
        for stamp in [
            "1970-01-01T00:00:00.000Z",
            "2024-02-29T23:59:59.000Z",
            "2026-09-25T12:00:00.000Z",
            "2099-12-31T23:59:59.000Z",
        ] {
            assert_eq!(
                unix_to_timestamp(unix_seconds(stamp).unwrap()).as_deref(),
                Some(stamp)
            );
        }
    }

    #[test]
    fn certificate_expiry_is_365_days_after_completion() {
        let now = unix_seconds("2026-09-25T12:00:00.000Z").unwrap();
        assert_eq!(certificate_expiry(now), "2027-09-25T12:00:00.000Z");
        assert_eq!(certificate_retention_days(), 365);
    }

    #[test]
    fn fence_report_states_every_blocked_workflow() {
        let now = unix_seconds("2026-09-25T12:00:00.000Z").unwrap();
        // A cutoff in the future is not yet in force.
        let before = fence_report(Some(now + 60), false, now);
        assert!(before.iter().all(|decision| !decision.is_blocked()));
        assert!(
            before
                .iter()
                .all(|decision| decision.reason == "deletion_fence_not_applied")
        );
        let after = fence_report(Some(now), true, now);
        assert!(after.iter().all(|decision| decision.is_blocked()));
        assert!(
            after
                .iter()
                .all(|decision| decision.reason == "deletion_cutoff_reached")
        );
        assert!(
            after
                .iter()
                .any(|decision| decision.workflow == FencedWorkflow::DeletionRetry)
        );
    }

    #[test]
    fn certificate_reports_states_coverage_and_retained_classes() {
        let tasks = vec![
            task("export_artifact", "r2_object", "succeeded", None),
            task(
                "audit_security_event",
                "database_row",
                "skipped",
                Some("retained_legal_only"),
            ),
            task(
                "upstream_provider_data",
                "upstream_provider_data",
                "skipped",
                Some("deletion_not_lumi_owned"),
            ),
        ];
        let coverage: ReferenceCoverage = reference_coverage();
        let results = certificate_class_results(&tasks, &coverage);
        assert_eq!(results["export_artifact"]["succeeded"], 1);
        assert_eq!(results["audit_security_event"]["skipped"], 1);
        // Coverage is stated, never implied.
        assert_eq!(
            results["reference_coverage"]["pending"],
            json!(["cache", "search_index"])
        );
        assert_eq!(
            results["reference_coverage"]["absent_reason"],
            json!("deletion_reference_system_absent")
        );
        assert_eq!(results["disclosures"], json!(deletion::DISCLOSURES));
        // A reference Lumi does not own is recorded, never claimed as deleted.
        assert_eq!(
            retained_legal_classes(&tasks),
            vec!["audit_security_event".to_owned()]
        );
        assert_eq!(
            pending_reference_systems(),
            deletion::PENDING_REFERENCE_SYSTEMS
        );
    }

    #[test]
    fn every_step_state_is_known_to_the_certificate_gate() {
        for state in [
            "pending",
            "running",
            "retry_wait",
            "needs_attention",
            "succeeded",
            "failed",
            "skipped",
        ] {
            assert_eq!(
                is_terminal_step(state),
                matches!(state, "succeeded" | "failed" | "skipped")
            );
        }
    }

    fn task(
        data_class: &str,
        reference_kind: &str,
        state: &str,
        skip_reason: Option<&str>,
    ) -> DeletionTaskRecord {
        DeletionTaskRecord {
            task_id: "dts_0123456789abcdef0123456789abcdef".to_owned(),
            deletion_id: DELETION_ID.to_owned(),
            org_id: Some(ORG_ID.to_owned()),
            data_class: data_class.to_owned(),
            reference_kind: reference_kind.to_owned(),
            object_reference: "exports/x".to_owned(),
            state: state.to_owned(),
            attempt: 1,
            failure_code: None,
            skip_reason: skip_reason.map(str::to_owned),
            started_at: None,
            completed_at: None,
            created_at: "2026-09-25T12:00:00.000Z".to_owned(),
            updated_at: "2026-09-25T12:00:00.000Z".to_owned(),
        }
    }

    #[test]
    fn object_segment_is_derived_from_the_content_digest() {
        let digest = "a".repeat(64);
        let opaque = digest_opaque(&digest);
        assert_eq!(opaque.len(), 32);
        assert!(opaque.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(opaque, digest_opaque(&digest));
        assert_ne!(opaque, digest_opaque(&"b".repeat(64)));
    }

    #[test]
    fn stream_descriptor_maps_every_stored_content_type() {
        for content_type in crate::adapters::r2::ARTIFACT_CONTENT_TYPES {
            let descriptor = stream_descriptor(content_type, EXPORT_ID)
                .expect("a stored content type is servable");
            assert!(descriptor.filename.starts_with(EXPORT_ID));
        }
        assert!(stream_descriptor("text/html", EXPORT_ID).is_none());
    }

    #[test]
    fn governed_classes_covers_the_whole_frozen_registry() {
        let classes = governed_classes();
        assert_eq!(classes.len(), crate::modules::data_governance::CLASS_COUNT);
        assert!(
            classes
                .iter()
                .any(|class| class == "upstream_provider_data")
        );
        assert!(classes.iter().any(|class| class == "export_artifact"));
    }

    #[test]
    fn artifact_ttl_is_the_frozen_24_hour_baseline() {
        assert_eq!(artifact_ttl_seconds(), 86_400);
        assert!(
            u64::from(artifact_ttl_seconds())
                <= crate::modules::data_governance::export::MAX_EXPORT_EXPIRY_SECONDS
        );
    }

    #[test]
    fn exported_event_names_are_the_frozen_p06_vocabulary() {
        for event in [
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
        ] {
            assert!(P06_DATA_EVENT_TYPES.contains(&event), "missing {event}");
        }
        assert_eq!(P06_DATA_EVENT_TYPES.len(), 12);
    }

    #[test]
    fn hold_scope_alias_is_the_scope_wide_variant() {
        assert!(matches!(hold_scope_all(), HoldScope::All));
    }
}
