//! D1 persistence for the P06 data-governance contract (`0014_p06_data_governance.sql`).
//!
//! Scope: the data-class registry, the org data-governance policy, export jobs
//! and their private-artifact/download-grant metadata, deletion jobs/steps/
//! certificates, and the `export.run`/`deletion.run` queue envelopes this
//! packet consumes.
//!
//! Design rules, in the order they matter:
//!
//! 1. **Tenant scope is a SQL predicate, not a post-filter.** Every read for a
//!    tenant-owned resource binds the tenant in the `WHERE` clause, so a
//!    cross-tenant identifier returns the same empty result as a missing one
//!    and cannot become an existence oracle.
//! 2. **The frozen manifest is never recomputed.** `categories_json` and
//!    `snapshot_cutoff_at` are written once at request time; a retry reads them
//!    back and re-asserts `manifest_is_stable` instead of re-deriving them.
//! 3. **State moves only by compare-and-set.** Every state update binds the
//!    expected `version` and the expected current `state`, so an at-least-once
//!    delivery cannot corrupt a job or double-count an attempt.
//! 4. **No content, ever.** This repository has no column for export content,
//!    a prompt, a response, a tool argument, or a secret. The only free-form
//!    text it stores is a bounded reason/failure code and the opaque R2 key.
//! 5. **`upstream_provider_data` is always skipped.** The plan records the
//!    reference; it never claims Lumi deleted data it does not own.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::Timestamp,
    modules::data_governance::{
        DataClass, DeletionInventoryEntry, DeletionJobState, DeletionStepState, DeletionTarget,
        ExportCategory, ExportFormat, ExportJobState, ExportScope, ReferenceKind, registry,
    },
};

/// Most rows one list page or one deletion-step page may return. Every P06
/// collection is keyset-paginated and bounded; nothing here can page a table
/// into Worker memory.
pub const PAGE_LIMIT_DEFAULT: i32 = 50;
pub const PAGE_LIMIT_MAX: i32 = 100;

/// Most collection rows one packaged export may contain per category. The
/// artifact stays small enough to stream and a scope that exceeds this is
/// reported as truncated metadata rather than silently dropped.
pub const EXPORT_ROW_LIMIT: i32 = 1_000;

// ---------------------------------------------------------------- SQL ------

const POLICY_BY_ORG_SQL: &str = r#"
SELECT policy_id, org_id, project_id, logging_mode, class_retention_overrides_json,
       legal_hold, legal_hold_reason, legal_hold_placed_at, legal_hold_released_at,
       legal_hold_released_by, backup_lifecycle, provider_retention_disclosure,
       provider_retention_url, default_export_expiry_seconds, version,
       created_by_principal_id, created_at, updated_at
FROM data_governance_policies
WHERE org_id = ?1 AND project_id IS NULL
LIMIT 1
"#;

const INSERT_POLICY_SQL: &str = r#"
INSERT INTO data_governance_policies (
    policy_id, org_id, project_id, logging_mode, class_retention_overrides_json,
    legal_hold, legal_hold_reason, legal_hold_placed_at, legal_hold_released_at,
    legal_hold_released_by, backup_lifecycle, provider_retention_disclosure,
    provider_retention_url, default_export_expiry_seconds, version,
    created_by_principal_id, created_at, updated_at
) VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 1, ?14, ?15, ?15)
"#;

const UPDATE_POLICY_SQL: &str = r#"
UPDATE data_governance_policies
SET logging_mode = ?3,
    class_retention_overrides_json = ?4,
    legal_hold = ?5,
    legal_hold_reason = ?6,
    legal_hold_placed_at = ?7,
    legal_hold_released_at = ?8,
    legal_hold_released_by = ?9,
    backup_lifecycle = ?10,
    provider_retention_disclosure = ?11,
    provider_retention_url = ?12,
    default_export_expiry_seconds = ?13,
    version = version + 1,
    updated_at = ?14
WHERE org_id = ?1 AND project_id IS NULL AND version = ?15
"#;

const ASSERT_POLICY_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest,
    request_fingerprint, state, response_status, response_body, expires_at,
    claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM data_governance_policies
    WHERE org_id = ?1 AND project_id IS NULL AND version = ?2
)
"#;

const INSERT_REGISTRY_ROW_SQL: &str = r#"
INSERT OR IGNORE INTO data_class_registry (
    data_class, sensitivity, owner_scope, default_retention_seconds,
    export_behavior, deletion_behavior, logging, description, version, created_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9)
"#;

const EXPORT_BY_ID_SQL: &str = r#"
SELECT export_id, org_id, scope_type, scope_user_id, scope_org_id, categories_json,
       format, snapshot_cutoff_at, state, state_version, attempt, next_attempt_at,
       requested_by_principal_id, requested_at, ready_at, finished_at, failure_code,
       version, updated_at
FROM export_jobs
WHERE export_id = ?1
LIMIT 1
"#;

/// Tenant-scoped read. The scope columns are part of the predicate so a foreign
/// export id is indistinguishable from a missing one.
const EXPORT_BY_ID_FOR_SCOPE_SQL: &str = r#"
SELECT export_id, org_id, scope_type, scope_user_id, scope_org_id, categories_json,
       format, snapshot_cutoff_at, state, state_version, attempt, next_attempt_at,
       requested_by_principal_id, requested_at, ready_at, finished_at, failure_code,
       version, updated_at
FROM export_jobs
WHERE export_id = ?1
  AND (CASE WHEN ?2 = 'user' THEN scope_type = 'user' AND scope_user_id = ?3
            ELSE scope_type = 'organization' AND scope_org_id = ?3 END)
LIMIT 1
"#;

const EXPORT_BY_DEDUPE_SQL: &str = r#"
SELECT export_id, org_id, scope_type, scope_user_id, scope_org_id, categories_json,
       format, snapshot_cutoff_at, state, state_version, attempt, next_attempt_at,
       requested_by_principal_id, requested_at, ready_at, finished_at, failure_code,
       version, updated_at
FROM export_jobs
WHERE COALESCE(org_id, '') = COALESCE(?1, '')
  AND scope_type = ?2
  AND COALESCE(scope_user_id, '') = COALESCE(?3, '')
  AND COALESCE(scope_org_id, '') = COALESCE(?4, '')
  AND categories_json = ?5
  AND snapshot_cutoff_at = ?6
LIMIT 1
"#;

const EXPORTS_PAGE_FOR_ORG_SQL: &str = r#"
SELECT export_id, org_id, scope_type, scope_user_id, scope_org_id, categories_json,
       format, snapshot_cutoff_at, state, state_version, attempt, next_attempt_at,
       requested_by_principal_id, requested_at, ready_at, finished_at, failure_code,
       version, updated_at
FROM export_jobs
WHERE scope_type = 'organization' AND scope_org_id = ?1
  AND (?2 = '' OR (requested_at, export_id) < (?2, ?3))
ORDER BY requested_at DESC, export_id DESC
LIMIT ?4
"#;

const EXPORTS_PAGE_FOR_USER_SQL: &str = r#"
SELECT export_id, org_id, scope_type, scope_user_id, scope_org_id, categories_json,
       format, snapshot_cutoff_at, state, state_version, attempt, next_attempt_at,
       requested_by_principal_id, requested_at, ready_at, finished_at, failure_code,
       version, updated_at
FROM export_jobs
WHERE scope_type = 'user' AND scope_user_id = ?1
  AND (?2 = '' OR (requested_at, export_id) < (?2, ?3))
ORDER BY requested_at DESC, export_id DESC
LIMIT ?4
"#;

const INSERT_EXPORT_SQL: &str = r#"
INSERT INTO export_jobs (
    export_id, org_id, scope_type, scope_user_id, scope_org_id, categories_json,
    format, snapshot_cutoff_at, state, state_version, attempt, next_attempt_at,
    requested_by_principal_id, requested_at, ready_at, finished_at, failure_code,
    version, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'requested', 1, 0, NULL, ?9, ?10, NULL, NULL, NULL, 1, ?10)
"#;

const UPDATE_EXPORT_STATE_SQL: &str = r#"
UPDATE export_jobs
SET state = ?3,
    state_version = state_version + 1,
    version = version + 1,
    attempt = attempt + ?4,
    next_attempt_at = ?5,
    failure_code = ?6,
    ready_at = COALESCE(ready_at, ?7),
    finished_at = ?8,
    updated_at = ?9
WHERE export_id = ?1 AND version = ?2 AND state = ?10
"#;

const INSERT_ARTIFACT_SQL: &str = r#"
INSERT INTO export_artifacts (
    artifact_id, export_id, org_id, object_key, bucket_name, content_type,
    size_bytes, checksum_sha256, created_at, expires_at, deleted_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL)
ON CONFLICT(export_id) DO UPDATE SET
    object_key = excluded.object_key,
    bucket_name = excluded.bucket_name,
    content_type = excluded.content_type,
    size_bytes = excluded.size_bytes,
    checksum_sha256 = excluded.checksum_sha256,
    created_at = excluded.created_at,
    expires_at = excluded.expires_at,
    deleted_at = NULL
"#;

const ARTIFACT_BY_EXPORT_SQL: &str = r#"
SELECT artifact_id, export_id, org_id, object_key, bucket_name, content_type,
       size_bytes, checksum_sha256, created_at, expires_at, deleted_at
FROM export_artifacts
WHERE export_id = ?1
LIMIT 1
"#;

const MARK_ARTIFACT_DELETED_SQL: &str = r#"
UPDATE export_artifacts
SET deleted_at = ?2
WHERE export_id = ?1 AND deleted_at IS NULL
"#;

const INSERT_GRANT_SQL: &str = r#"
INSERT INTO export_download_grants (
    grant_id, export_id, artifact_id, org_id, user_id, token_fingerprint,
    issued_at, expires_at, revoked_at, use_count
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, 0)
"#;

const GRANT_BY_FINGERPRINT_SQL: &str = r#"
SELECT g.grant_id, g.export_id, g.artifact_id, g.org_id, g.user_id, g.token_fingerprint,
       g.issued_at, g.expires_at, g.revoked_at, g.use_count,
       j.scope_type AS job_scope_type,
       COALESCE(j.scope_user_id, '') AS job_scope_user_id,
       COALESCE(j.scope_org_id, '') AS job_scope_org_id,
       j.snapshot_cutoff_at AS job_snapshot_cutoff_at,
       j.state AS job_state
FROM export_download_grants g
JOIN export_jobs j ON j.export_id = g.export_id
WHERE g.token_fingerprint = ?1
LIMIT 1
"#;

const TOUCH_GRANT_SQL: &str = r#"
UPDATE export_download_grants
SET use_count = use_count + 1
WHERE grant_id = ?1 AND revoked_at IS NULL AND expires_at > ?2
"#;

const REVOKE_GRANTS_FOR_EXPORT_SQL: &str = r#"
UPDATE export_download_grants
SET revoked_at = ?2
WHERE export_id = ?1 AND revoked_at IS NULL
"#;

const DELETION_BY_ID_FOR_SCOPE_SQL: &str = r#"
SELECT deletion_id, org_id, target_type, target_user_id, target_org_id,
       lifecycle_request_id, state, state_version, attempt, next_attempt_at,
       grace_expires_at, cutoff_at, fenced, legal_hold, failure_code,
       certificate_id, requested_by_principal_id, created_at, updated_at,
       completed_at, version
FROM deletion_jobs
WHERE deletion_id = ?1
  AND (CASE WHEN ?2 = 'user' THEN target_type = 'user' AND target_user_id = ?3
            ELSE target_type = 'organization' AND target_org_id = ?3 END)
LIMIT 1
"#;

const DELETION_BY_ID_SQL: &str = r#"
SELECT deletion_id, org_id, target_type, target_user_id, target_org_id,
       lifecycle_request_id, state, state_version, attempt, next_attempt_at,
       grace_expires_at, cutoff_at, fenced, legal_hold, failure_code,
       certificate_id, requested_by_principal_id, created_at, updated_at,
       completed_at, version
FROM deletion_jobs
WHERE deletion_id = ?1
LIMIT 1
"#;

const DELETION_BY_TARGET_SQL: &str = r#"
SELECT deletion_id, org_id, target_type, target_user_id, target_org_id,
       lifecycle_request_id, state, state_version, attempt, next_attempt_at,
       grace_expires_at, cutoff_at, fenced, legal_hold, failure_code,
       certificate_id, requested_by_principal_id, created_at, updated_at,
       completed_at, version
FROM deletion_jobs
WHERE (CASE WHEN ?1 = 'user' THEN target_type = 'user' AND target_user_id = ?2
            ELSE target_type = 'organization' AND target_org_id = ?2 END)
LIMIT 1
"#;

const DELETIONS_PAGE_FOR_ORG_SQL: &str = r#"
SELECT deletion_id, org_id, target_type, target_user_id, target_org_id,
       lifecycle_request_id, state, state_version, attempt, next_attempt_at,
       grace_expires_at, cutoff_at, fenced, legal_hold, failure_code,
       certificate_id, requested_by_principal_id, created_at, updated_at,
       completed_at, version
FROM deletion_jobs
WHERE target_type = 'organization' AND target_org_id = ?1
  AND (?2 = '' OR (created_at, deletion_id) < (?2, ?3))
ORDER BY created_at DESC, deletion_id DESC
LIMIT ?4
"#;

const DELETIONS_PAGE_FOR_USER_SQL: &str = r#"
SELECT deletion_id, org_id, target_type, target_user_id, target_org_id,
       lifecycle_request_id, state, state_version, attempt, next_attempt_at,
       grace_expires_at, cutoff_at, fenced, legal_hold, failure_code,
       certificate_id, requested_by_principal_id, created_at, updated_at,
       completed_at, version
FROM deletion_jobs
WHERE target_type = 'user' AND target_user_id = ?1
  AND (?2 = '' OR (created_at, deletion_id) < (?2, ?3))
ORDER BY created_at DESC, deletion_id DESC
LIMIT ?4
"#;

const INSERT_DELETION_SQL: &str = r#"
INSERT INTO deletion_jobs (
    deletion_id, org_id, target_type, target_user_id, target_org_id,
    lifecycle_request_id, state, state_version, attempt, next_attempt_at,
    grace_expires_at, cutoff_at, fenced, legal_hold, failure_code,
    certificate_id, requested_by_principal_id, created_at, updated_at,
    completed_at, version
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, 0, NULL, ?8, ?9, ?10, ?11, NULL, NULL, ?12, ?13, ?13, NULL, 1)
"#;

/// P06-CR-003 bridge. One organization may only ever have one deletion job, so
/// a repeated lifecycle request is absorbed instead of forking a second job.
const LINK_DELETION_JOB_SQL: &str = r#"
INSERT INTO deletion_jobs (
    deletion_id, org_id, target_type, target_user_id, target_org_id,
    lifecycle_request_id, state, state_version, attempt, next_attempt_at,
    grace_expires_at, cutoff_at, fenced, legal_hold, failure_code,
    certificate_id, requested_by_principal_id, created_at, updated_at,
    completed_at, version
) VALUES (?1, ?2, 'organization', NULL, ?2, ?3, 'queued', 1, 0, NULL, NULL, ?4, 1, ?5, NULL, NULL, ?6, ?7, ?7, NULL, 1)
ON CONFLICT (target_org_id) WHERE target_type = 'organization' DO NOTHING
"#;

const UPDATE_DELETION_STATE_SQL: &str = r#"
UPDATE deletion_jobs
SET state = ?3,
    state_version = state_version + 1,
    version = version + 1,
    attempt = attempt + ?4,
    next_attempt_at = ?5,
    failure_code = ?6,
    grace_expires_at = ?7,
    certificate_id = ?8,
    completed_at = ?9,
    updated_at = ?10
WHERE deletion_id = ?1 AND version = ?2 AND state = ?11
"#;

const SET_DELETION_CUTOFF_SQL: &str = r#"
UPDATE deletion_jobs
SET cutoff_at = ?2,
    fenced = 1,
    version = version + 1,
    updated_at = ?3
WHERE deletion_id = ?1 AND (cutoff_at IS NULL OR cutoff_at > ?2)
"#;

const INSERT_DELETION_TASK_SQL: &str = r#"
INSERT INTO deletion_tasks (
    task_id, deletion_id, org_id, data_class, reference_kind, object_reference,
    state, attempt, failure_code, skip_reason, started_at, completed_at,
    created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9, ?10, ?11, ?12, ?12)
ON CONFLICT (deletion_id, data_class, reference_kind, object_reference) DO NOTHING
"#;

const UPDATE_DELETION_TASK_SQL: &str = r#"
UPDATE deletion_tasks
SET state = ?5,
    attempt = attempt + ?6,
    failure_code = ?7,
    skip_reason = ?8,
    started_at = ?9,
    completed_at = ?10,
    updated_at = ?11
WHERE deletion_id = ?1
  AND data_class = ?2
  AND reference_kind = ?3
  AND object_reference = ?4
  AND state = ?12
  AND state NOT IN ('succeeded', 'failed', 'skipped')
"#;

const DELETION_TASKS_SQL: &str = r#"
SELECT task_id, deletion_id, org_id, data_class, reference_kind, object_reference,
       state, attempt, failure_code, skip_reason, started_at, completed_at,
       created_at, updated_at
FROM deletion_tasks
WHERE deletion_id = ?1
ORDER BY created_at ASC, task_id ASC
LIMIT ?2
"#;

const PENDING_DELETION_TASKS_SQL: &str = r#"
SELECT task_id, deletion_id, org_id, data_class, reference_kind, object_reference,
       state, attempt, failure_code, skip_reason, started_at, completed_at,
       created_at, updated_at
FROM deletion_tasks
WHERE deletion_id = ?1 AND state IN ('pending', 'running', 'retry_wait')
ORDER BY created_at ASC, task_id ASC
LIMIT ?2
"#;

const INSERT_CERTIFICATE_SQL: &str = r#"
INSERT INTO deletion_certificates (
    certificate_id, deletion_id, org_id, scope_type, scope_id, class_results_json,
    retained_legal_classes_json, completed_at, expires_at, created_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
ON CONFLICT (deletion_id) DO NOTHING
"#;

const CERTIFICATE_BY_DELETION_SQL: &str = r#"
SELECT certificate_id, deletion_id, org_id, scope_type, scope_id,
       class_results_json, retained_legal_classes_json, completed_at,
       expires_at, created_at
FROM deletion_certificates
WHERE deletion_id = ?1
LIMIT 1
"#;

const QUEUE_ENVELOPE_BY_DEDUPE_SQL: &str = r#"
SELECT job_id, job_type, schema_version, org_id, subject_type, subject_id,
       subject_version, dedupe_key, state, attempt, generation, version
FROM queue_job_envelopes
WHERE job_type = ?1
  AND COALESCE(org_id, '') = COALESCE(?2, '')
  AND dedupe_key = ?3
  AND generation = ?4
LIMIT 1
"#;

const INSERT_QUEUE_ENVELOPE_SQL: &str = r#"
INSERT INTO queue_job_envelopes (
    job_id, job_type, schema_version, org_id, subject_type, subject_id,
    subject_version, dedupe_key, event_id, request_id, correlation_id,
    payload_ref, state, attempt, lease_version, lease_expires_at,
    next_attempt_at, last_error_code, replay_of_job_id, generation,
    version, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9, ?10, ?11, 'queued', 1, 0, NULL, ?11, NULL, NULL, 0, 1, ?11, ?11)
ON CONFLICT DO NOTHING
"#;

const CLAIM_QUEUE_ENVELOPE_SQL: &str = r#"
UPDATE queue_job_envelopes
SET state = 'running',
    attempt = attempt + 1,
    lease_version = lease_version + 1,
    lease_expires_at = ?2,
    version = version + 1,
    updated_at = ?3
WHERE job_id = ?1 AND state IN ('queued', 'retry_wait') AND version = ?4
"#;

const SETTLE_QUEUE_ENVELOPE_SQL: &str = r#"
UPDATE queue_job_envelopes
SET state = ?3,
    lease_version = lease_version + 1,
    lease_expires_at = NULL,
    next_attempt_at = ?4,
    last_error_code = ?5,
    version = version + 1,
    updated_at = ?6
WHERE job_id = ?1 AND state = 'running' AND version = ?2
"#;

/// A delete statement the deletion worker may execute for one data class.
///
/// The list is closed on purpose: a step whose class has no executor must park
/// in `needs_attention` so the job never claims it deleted a row it did not
/// actually delete. Each statement takes exactly one bound parameter, the
/// object reference the planner emitted.
pub struct DatabaseRowExecutor {
    pub data_class: &'static str,
    pub reference_kind: ReferenceKind,
    pub statement: &'static str,
    /// `revoke` keeps the row and disables the capability (devices,
    /// enrollments); `delete` removes the row and everything it owns.
    pub outcome: RowOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowOutcome {
    Delete,
    Revoke,
}

/// The only `database_row` deletions this control plane can actually perform.
///
/// Deliberately absent: `run`, `run_event`, `usage_event`, `cost_record`,
/// `audit_security_event`, `outbox_event`, and every P06 projection. Those rows
/// are immutable, have dependents, or need a tombstone column this packet does
/// not own, so a plan step for them parks with
/// `deletion_executor_unavailable` instead of silently reporting success.
pub const DATABASE_ROW_EXECUTORS: &[DatabaseRowExecutor] = &[
    DatabaseRowExecutor {
        data_class: "login_session",
        reference_kind: ReferenceKind::DatabaseRow,
        statement: "DELETE FROM login_sessions WHERE session_id = ?1",
        outcome: RowOutcome::Delete,
    },
    DatabaseRowExecutor {
        data_class: "passkey_authenticator",
        reference_kind: ReferenceKind::DatabaseRow,
        statement: "DELETE FROM passkey_credentials WHERE credential_id = ?1",
        outcome: RowOutcome::Delete,
    },
    DatabaseRowExecutor {
        data_class: "membership",
        reference_kind: ReferenceKind::DatabaseRow,
        statement: "DELETE FROM memberships WHERE membership_id = ?1",
        outcome: RowOutcome::Delete,
    },
    DatabaseRowExecutor {
        data_class: "invitation",
        reference_kind: ReferenceKind::DatabaseRow,
        statement: "DELETE FROM invitations WHERE invitation_id = ?1",
        outcome: RowOutcome::Delete,
    },
    DatabaseRowExecutor {
        data_class: "team",
        reference_kind: ReferenceKind::DatabaseRow,
        statement: "DELETE FROM teams WHERE team_id = ?1",
        outcome: RowOutcome::Delete,
    },
    DatabaseRowExecutor {
        data_class: "workspace_binding",
        reference_kind: ReferenceKind::DatabaseRow,
        statement: "DELETE FROM workspace_bindings WHERE binding_id = ?1",
        outcome: RowOutcome::Delete,
    },
    DatabaseRowExecutor {
        data_class: "device",
        reference_kind: ReferenceKind::DatabaseRow,
        statement: "UPDATE devices SET status = 'revoked', revoked_at = ?2, revoked_by_user_id = ?3 WHERE device_id = ?1",
        outcome: RowOutcome::Revoke,
    },
    DatabaseRowExecutor {
        data_class: "device_enrollment",
        reference_kind: ReferenceKind::DatabaseRow,
        statement: "UPDATE device_enrollments SET status = 'revoked', revoked_at = ?2 WHERE enrollment_id = ?1",
        outcome: RowOutcome::Revoke,
    },
];

/// Find the executor for one planned step, or `None` when the class has no
/// executor today.
pub fn database_row_executor(
    data_class: &DataClass,
    reference_kind: ReferenceKind,
) -> Option<&'static DatabaseRowExecutor> {
    DATABASE_ROW_EXECUTORS.iter().find(|executor| {
        executor.data_class == data_class.as_str() && executor.reference_kind == reference_kind
    })
}

// ------------------------------------------------------------- records -----

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DataGovernancePolicyRecord {
    pub policy_id: String,
    pub org_id: String,
    pub project_id: Option<String>,
    pub logging_mode: String,
    pub class_retention_overrides_json: String,
    pub legal_hold: i64,
    pub legal_hold_reason: Option<String>,
    pub legal_hold_placed_at: Option<String>,
    pub legal_hold_released_at: Option<String>,
    pub legal_hold_released_by: Option<String>,
    pub backup_lifecycle: String,
    pub provider_retention_disclosure: String,
    pub provider_retention_url: Option<String>,
    pub default_export_expiry_seconds: i64,
    pub version: i64,
    pub created_by_principal_id: String,
    pub created_at: String,
    pub updated_at: String,
}

impl DataGovernancePolicyRecord {
    /// The schema stores the hold as an integer; the wire and domain forms use
    /// a boolean so a caller cannot read `1` and wonder whether it is a flag.
    pub fn legal_hold_active(&self) -> bool {
        self.legal_hold != 0
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ExportJobRecord {
    pub export_id: String,
    pub org_id: Option<String>,
    pub scope_type: String,
    pub scope_user_id: Option<String>,
    pub scope_org_id: Option<String>,
    pub categories_json: String,
    pub format: String,
    pub snapshot_cutoff_at: String,
    pub state: String,
    pub state_version: i64,
    pub attempt: i64,
    pub next_attempt_at: Option<String>,
    pub requested_by_principal_id: String,
    pub requested_at: String,
    pub ready_at: Option<String>,
    pub finished_at: Option<String>,
    pub failure_code: Option<String>,
    pub version: i64,
    pub updated_at: String,
}

impl ExportJobRecord {
    /// `org_id` is set only for organization-scoped jobs. A personal job has no
    /// org at all, which is what keeps a personal export from ever reading a
    /// tenant's rows.
    pub fn scope_id(&self) -> Option<&str> {
        match self.scope_type.as_str() {
            "user" => self.scope_user_id.as_deref(),
            _ => self.scope_org_id.as_deref(),
        }
    }

    pub fn is_personal(&self) -> bool {
        self.scope_type == "user"
    }
}

impl fmt::Debug for ExportJobRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExportJobRecord")
            .field("export_id", &self.export_id)
            .field("org_id", &self.org_id)
            .field("scope_type", &self.scope_type)
            .field("categories_json", &self.categories_json)
            .field("format", &self.format)
            .field("snapshot_cutoff_at", &self.snapshot_cutoff_at)
            .field("state", &self.state)
            .field("attempt", &self.attempt)
            .field("failure_code", &self.failure_code)
            .field("version", &self.version)
            .finish()
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ExportArtifactRecord {
    pub artifact_id: String,
    pub export_id: String,
    pub org_id: Option<String>,
    /// Opaque R2 key. Never a URL. Redacted in `Debug` so a diagnostic line
    /// cannot be used as a shortcut to the object.
    pub object_key: String,
    pub bucket_name: String,
    pub content_type: String,
    pub size_bytes: Option<i64>,
    pub checksum_sha256: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub deleted_at: Option<String>,
}

impl fmt::Debug for ExportArtifactRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExportArtifactRecord")
            .field("artifact_id", &self.artifact_id)
            .field("export_id", &self.export_id)
            .field("org_id", &self.org_id)
            .field("object_key", &"[redacted]")
            .field("bucket_name", &self.bucket_name)
            .field("content_type", &self.content_type)
            .field("size_bytes", &self.size_bytes)
            .field("checksum_sha256", &self.checksum_sha256)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("deleted_at", &self.deleted_at)
            .finish()
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct DownloadGrantRecord {
    pub grant_id: String,
    pub export_id: String,
    pub artifact_id: String,
    pub org_id: Option<String>,
    pub user_id: String,
    pub token_fingerprint: String,
    pub issued_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub use_count: i64,
    pub job_scope_type: String,
    pub job_scope_user_id: String,
    pub job_scope_org_id: String,
    pub job_snapshot_cutoff_at: String,
    pub job_state: String,
}

impl fmt::Debug for DownloadGrantRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DownloadGrantRecord")
            .field("grant_id", &self.grant_id)
            .field("export_id", &self.export_id)
            .field("artifact_id", &self.artifact_id)
            .field("org_id", &self.org_id)
            .field("user_id", &self.user_id)
            .field("token_fingerprint", &"[redacted]")
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("revoked_at", &self.revoked_at)
            .field("use_count", &self.use_count)
            .field("job_scope_type", &self.job_scope_type)
            .field("job_state", &self.job_state)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeletionJobRecord {
    pub deletion_id: String,
    pub org_id: Option<String>,
    pub target_type: String,
    pub target_user_id: Option<String>,
    pub target_org_id: Option<String>,
    pub lifecycle_request_id: Option<String>,
    pub state: String,
    pub state_version: i64,
    pub attempt: i64,
    pub next_attempt_at: Option<String>,
    pub grace_expires_at: Option<String>,
    pub cutoff_at: Option<String>,
    pub fenced: i64,
    pub legal_hold: i64,
    pub failure_code: Option<String>,
    pub certificate_id: Option<String>,
    pub requested_by_principal_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
    pub version: i64,
}

impl DeletionJobRecord {
    pub fn target_id(&self) -> Option<&str> {
        match self.target_type.as_str() {
            "user" => self.target_user_id.as_deref(),
            _ => self.target_org_id.as_deref(),
        }
    }

    pub fn is_fenced(&self) -> bool {
        self.fenced != 0
    }

    pub fn legal_hold_active(&self) -> bool {
        self.legal_hold != 0
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct DeletionTaskRecord {
    pub task_id: String,
    pub deletion_id: String,
    pub org_id: Option<String>,
    pub data_class: String,
    pub reference_kind: String,
    pub object_reference: String,
    pub state: String,
    pub attempt: i64,
    pub failure_code: Option<String>,
    pub skip_reason: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl fmt::Debug for DeletionTaskRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeletionTaskRecord")
            .field("task_id", &self.task_id)
            .field("deletion_id", &self.deletion_id)
            .field("org_id", &self.org_id)
            .field("data_class", &self.data_class)
            .field("reference_kind", &self.reference_kind)
            // An object reference is an opaque key or a row ID, never content.
            .field("object_reference", &self.object_reference)
            .field("state", &self.state)
            .field("attempt", &self.attempt)
            .field("failure_code", &self.failure_code)
            .field("skip_reason", &self.skip_reason)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeletionCertificateRecord {
    pub certificate_id: String,
    pub deletion_id: String,
    pub org_id: Option<String>,
    pub scope_type: String,
    pub scope_id: String,
    pub class_results_json: String,
    pub retained_legal_classes_json: String,
    pub completed_at: String,
    pub expires_at: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QueueEnvelopeRecord {
    pub job_id: String,
    pub job_type: String,
    pub schema_version: i64,
    pub org_id: Option<String>,
    pub subject_type: String,
    pub subject_id: String,
    pub subject_version: Option<i64>,
    pub dedupe_key: String,
    pub state: String,
    pub attempt: i64,
    pub generation: i64,
    pub version: i64,
}

/// Inputs for one mutation. Borrowed so no request body is retained past the
/// statement it produced.
pub struct NewPolicyInput<'a> {
    pub policy_id: &'a str,
    pub org_id: &'a str,
    pub logging_mode: &'a str,
    pub overrides_json: &'a str,
    pub legal_hold: bool,
    pub legal_hold_reason: Option<&'a str>,
    pub legal_hold_placed_at: Option<&'a str>,
    pub legal_hold_released_at: Option<&'a str>,
    pub legal_hold_released_by: Option<&'a str>,
    pub backup_lifecycle: &'a str,
    pub provider_retention_disclosure: &'a str,
    pub provider_retention_url: Option<&'a str>,
    pub default_export_expiry_seconds: i64,
    pub created_by_principal_id: &'a str,
    pub now: &'a Timestamp,
}

pub struct PolicyUpdateInput<'a> {
    pub org_id: &'a str,
    pub logging_mode: &'a str,
    pub overrides_json: &'a str,
    pub legal_hold: bool,
    pub legal_hold_reason: Option<&'a str>,
    pub legal_hold_placed_at: Option<&'a str>,
    pub legal_hold_released_at: Option<&'a str>,
    pub legal_hold_released_by: Option<&'a str>,
    pub backup_lifecycle: &'a str,
    pub provider_retention_disclosure: &'a str,
    pub provider_retention_url: Option<&'a str>,
    pub default_export_expiry_seconds: i64,
    pub expected_version: i64,
    pub now: &'a Timestamp,
}

pub struct NewExportInput<'a> {
    pub export_id: &'a str,
    pub org_id: Option<&'a str>,
    pub scope_type: &'a str,
    pub scope_user_id: Option<&'a str>,
    pub scope_org_id: Option<&'a str>,
    pub categories_json: &'a str,
    pub format: &'a str,
    pub snapshot_cutoff_at: &'a str,
    pub requested_by_principal_id: &'a str,
    pub now: &'a Timestamp,
}

pub struct NewArtifactInput<'a> {
    pub artifact_id: &'a str,
    pub export_id: &'a str,
    pub org_id: Option<&'a str>,
    pub object_key: &'a str,
    pub bucket_name: &'a str,
    pub content_type: &'a str,
    pub size_bytes: i64,
    pub checksum_sha256: &'a str,
    pub created_at: &'a str,
    pub expires_at: &'a str,
}

pub struct NewDownloadGrantInput<'a> {
    pub grant_id: &'a str,
    pub export_id: &'a str,
    pub artifact_id: &'a str,
    pub org_id: Option<&'a str>,
    pub user_id: &'a str,
    pub token_fingerprint: &'a str,
    pub issued_at: &'a str,
    pub expires_at: &'a str,
}

pub struct NewDeletionInput<'a> {
    pub deletion_id: &'a str,
    pub org_id: Option<&'a str>,
    pub target_type: &'a str,
    pub target_user_id: Option<&'a str>,
    pub target_org_id: Option<&'a str>,
    pub lifecycle_request_id: Option<&'a str>,
    pub state: &'a str,
    pub grace_expires_at: Option<&'a str>,
    pub cutoff_at: Option<&'a str>,
    pub fenced: bool,
    pub legal_hold: bool,
    pub requested_by_principal_id: &'a str,
    pub now: &'a Timestamp,
}

pub struct NewDeletionTaskInput<'a> {
    pub task_id: &'a str,
    pub deletion_id: &'a str,
    pub org_id: Option<&'a str>,
    pub data_class: &'a str,
    pub reference_kind: &'a str,
    pub object_reference: &'a str,
    pub state: &'a str,
    pub attempt: i64,
    pub skip_reason: Option<&'a str>,
    pub started_at: Option<&'a str>,
    pub completed_at: Option<&'a str>,
    pub now: &'a Timestamp,
}

pub struct NewCertificateInput<'a> {
    pub certificate_id: &'a str,
    pub deletion_id: &'a str,
    pub org_id: Option<&'a str>,
    pub scope_type: &'a str,
    pub scope_id: &'a str,
    pub class_results_json: &'a str,
    pub retained_legal_classes_json: &'a str,
    pub completed_at: &'a str,
    pub expires_at: &'a str,
    pub now: &'a Timestamp,
}

/// Compare-and-set an export state move.
///
/// Grouped into one struct because the argument list is a state-machine
/// transition: expected state, expected version, next state, and the bounded
/// fields that move with it. Passing them separately is how a caller ends up
/// applying `finished_at` to a retry.
pub struct ExportStateUpdateInput<'a> {
    pub export_id: &'a str,
    pub expected_version: i64,
    pub next_state: &'a str,
    /// `true` only when entering `retry_wait`, so a resumed collection is a new
    /// attempt and a redelivered message is not.
    pub increment_attempt: bool,
    pub next_attempt_at: Option<&'a str>,
    pub failure_code: Option<&'a str>,
    pub ready_at: Option<&'a str>,
    pub finished_at: Option<&'a str>,
    pub expected_state: &'a str,
    pub now: &'a Timestamp,
}

/// Compare-and-set a deletion state move.
pub struct DeletionStateUpdateInput<'a> {
    pub deletion_id: &'a str,
    pub expected_version: i64,
    pub next_state: &'a str,
    pub increment_attempt: bool,
    pub next_attempt_at: Option<&'a str>,
    pub failure_code: Option<&'a str>,
    pub grace_expires_at: Option<&'a str>,
    pub certificate_id: Option<&'a str>,
    pub completed_at: Option<&'a str>,
    pub expected_state: &'a str,
    pub now: &'a Timestamp,
}

/// The P06-CR-003 organization lifecycle bridge.
pub struct DeletionJobLinkInput<'a> {
    pub deletion_id: &'a str,
    pub org_id: &'a str,
    pub lifecycle_request_id: &'a str,
    pub cutoff_at: &'a str,
    pub legal_hold: bool,
    pub requested_by_principal_id: &'a str,
    pub now: &'a Timestamp,
}

/// Compare-and-set one deletion step.
pub struct DeletionTaskUpdateInput<'a> {
    pub deletion_id: &'a str,
    pub data_class: &'a str,
    pub reference_kind: &'a str,
    pub object_reference: &'a str,
    pub next_state: &'a str,
    pub increment_attempt: bool,
    pub failure_code: Option<&'a str>,
    pub skip_reason: Option<&'a str>,
    pub started_at: Option<&'a str>,
    pub completed_at: Option<&'a str>,
    pub expected_state: &'a str,
    pub now: &'a Timestamp,
}

pub struct NewQueueEnvelopeInput<'a> {
    pub job_id: &'a str,
    pub job_type: &'a str,
    pub org_id: Option<&'a str>,
    pub subject_type: &'a str,
    pub subject_id: &'a str,
    pub subject_version: Option<i64>,
    pub dedupe_key: &'a str,
    pub request_id: &'a str,
    pub correlation_id: &'a str,
    pub payload_ref: &'a str,
    pub now: &'a Timestamp,
}

// ------------------------------------------------ artifact collection ------

/// `identity` for a user scope: the requester's own account row.
const COLLECT_IDENTITY_USER_SQL: &str = r#"
SELECT user_id, email, display_name, email_verified, created_at
FROM users
WHERE user_id = ?1 AND created_at <= ?2
ORDER BY created_at ASC
LIMIT ?3
"#;

/// `identity` for an organization scope: the members' identity projection.
/// Never credentials, authenticator material, or session references.
const COLLECT_IDENTITY_ORG_SQL: &str = r#"
SELECT m.user_id AS user_id, m.role AS role, m.status AS status, m.joined_at AS joined_at,
       u.email AS email, u.display_name AS display_name,
       u.email_verified AS email_verified, u.created_at AS created_at
FROM memberships m
JOIN users u ON u.user_id = m.user_id
WHERE m.org_id = ?1 AND u.created_at <= ?2
ORDER BY u.created_at ASC, m.user_id ASC
LIMIT ?3
"#;

const COLLECT_ORGANIZATION_SQL: &str = r#"
SELECT org_id, display_name, slug, state, version, created_by_user_id, created_at, updated_at
FROM organizations
WHERE org_id = ?1 AND created_at <= ?2
ORDER BY created_at ASC
LIMIT 1
"#;

const COLLECT_ORGANIZATION_MEMBERSHIPS_SQL: &str = r#"
SELECT membership_id, user_id, role, status, invited_by_user_id, joined_at, created_at, updated_at
FROM memberships
WHERE org_id = ?1 AND created_at <= ?2
ORDER BY created_at ASC, membership_id ASC
LIMIT ?3
"#;

const COLLECT_ORGANIZATION_TEAMS_SQL: &str = r#"
SELECT t.team_id AS team_id, t.name AS name, t.created_at AS created_at,
       tm.team_member_id AS team_member_id, tm.user_id AS user_id, tm.role AS member_role
FROM teams t
LEFT JOIN team_members tm ON tm.team_id = t.team_id
WHERE t.org_id = ?1 AND t.created_at <= ?2
ORDER BY t.created_at ASC, t.team_id ASC, tm.team_member_id ASC
LIMIT ?3
"#;

const COLLECT_DEVICES_SQL: &str = r#"
SELECT device_id, org_id, name, platform, app_version, status,
       enrolled_by_user_id, capability_reported_at, last_seen_at, revoked_at, created_at
FROM devices
WHERE org_id = ?1 AND created_at <= ?2
ORDER BY created_at ASC, device_id ASC
LIMIT ?3
"#;

const COLLECT_RUNS_SQL: &str = r#"
SELECT run_id, project_id, agent_session_id, agent_definition_id, agent_definition_version,
       principal_user_id, device_id, model_alias, state, attempt, failure_code,
       started_at, finished_at, created_at, updated_at
FROM runs
WHERE org_id = ?1 AND created_at <= ?2
ORDER BY created_at ASC, run_id ASC
LIMIT ?3
"#;

const COLLECT_USAGE_SQL: &str = r#"
SELECT usage_rollup_id, project_id, principal_user_id, model_alias,
       bucket_start, bucket_end, input_tokens, output_tokens, cached_tokens,
       cost_minor, usage_event_count, updated_at
FROM usage_rollups
WHERE org_id = ?1 AND bucket_end <= ?2
ORDER BY bucket_start ASC, usage_rollup_id ASC
LIMIT ?3
"#;

/// `audit_redacted`: identifiers, action, outcome, and a bounded reason. Actor,
/// session, and device identifiers and the metadata document are dropped, and
/// the row is never physically deleted (F20-006 / P06-CR-003).
const COLLECT_AUDIT_SQL: &str = r#"
SELECT event_id, action, resource_type, resource_id, outcome, reason, created_at
FROM security_events
WHERE org_id = ?1 AND created_at <= ?2
ORDER BY created_at ASC, event_id ASC
LIMIT ?3
"#;

const COLLECT_NOTIFICATIONS_USER_SQL: &str = r#"
SELECT notification_id, event_id, event_type, category, mandatory, state, read_at, created_at
FROM notifications
WHERE user_id = ?1 AND created_at <= ?2
ORDER BY created_at ASC, notification_id ASC
LIMIT ?3
"#;

const COLLECT_NOTIFICATIONS_ORG_SQL: &str = r#"
SELECT n.notification_id, n.user_id, n.event_id, n.event_type, n.category, n.mandatory,
       n.state, n.read_at, n.created_at
FROM notifications n
WHERE n.org_id = ?1 AND n.created_at <= ?2
ORDER BY n.created_at ASC, n.notification_id ASC
LIMIT ?3
"#;

const COLLECT_POLICY_SQL: &str = r#"
SELECT policy_id, org_id, logging_mode, class_retention_overrides_json, legal_hold,
       backup_lifecycle, provider_retention_disclosure, provider_retention_url,
       default_export_expiry_seconds, version, updated_at
FROM data_governance_policies
WHERE org_id = ?1 AND project_id IS NULL AND created_at <= ?2
ORDER BY created_at ASC
LIMIT 1
"#;

const DECLARATIONS_USER_SQL: &str = r#"
SELECT data_class, sensitivity, default_retention_seconds, export_behavior,
       deletion_behavior, logging, description
FROM data_class_registry
WHERE owner_scope = 'user'
ORDER BY data_class ASC
LIMIT ?1
"#;

const DECLARATIONS_ORG_SQL: &str = r#"
SELECT data_class, sensitivity, default_retention_seconds, export_behavior,
       deletion_behavior, logging, description
FROM data_class_registry
WHERE owner_scope IN ('organization', 'project', 'device')
ORDER BY data_class ASC
LIMIT ?1
"#;

// ------------------------------------------- deletion reference traversal --

const INVENTORY_EXPORT_OBJECTS_SQL: &str = r#"
SELECT a.object_key
FROM export_artifacts a
JOIN export_jobs j ON j.export_id = a.export_id
WHERE a.org_id = ?1 AND a.deleted_at IS NULL
ORDER BY a.artifact_id ASC
LIMIT ?2
"#;

const INVENTORY_USER_EXPORT_OBJECTS_SQL: &str = r#"
SELECT a.object_key
FROM export_artifacts a
JOIN export_jobs j ON j.export_id = a.export_id
WHERE j.scope_type = 'user' AND j.scope_user_id = ?1 AND a.deleted_at IS NULL
ORDER BY a.artifact_id ASC
LIMIT ?2
"#;

const INVENTORY_LOGIN_SESSIONS_SQL: &str = r#"
SELECT session_id
FROM login_sessions
WHERE user_id = ?1
ORDER BY session_id ASC
LIMIT ?2
"#;

const INVENTORY_PASSKEYS_SQL: &str = r#"
SELECT credential_id
FROM passkey_credentials
WHERE user_id = ?1
ORDER BY credential_id ASC
LIMIT ?2
"#;

const INVENTORY_MEMBERSHIPS_USER_SQL: &str = r#"
SELECT membership_id
FROM memberships
WHERE user_id = ?1
ORDER BY membership_id ASC
LIMIT ?2
"#;

const INVENTORY_MEMBERSHIPS_ORG_SQL: &str = r#"
SELECT membership_id
FROM memberships
WHERE org_id = ?1
ORDER BY membership_id ASC
LIMIT ?2
"#;

const INVENTORY_DEVICES_ORG_SQL: &str = r#"
SELECT device_id
FROM devices
WHERE org_id = ?1
ORDER BY device_id ASC
LIMIT ?2
"#;

const INVENTORY_DEVICES_USER_SQL: &str = r#"
SELECT d.device_id
FROM devices d
JOIN memberships m ON m.org_id = d.org_id AND m.user_id = ?1
WHERE d.status = 'active'
ORDER BY d.device_id ASC
LIMIT ?2
"#;

const INVENTORY_ENROLLMENTS_USER_SQL: &str = r#"
SELECT e.enrollment_id
FROM device_enrollments e
JOIN devices d ON d.device_id = e.device_id
JOIN memberships m ON m.org_id = d.org_id AND m.user_id = ?1
WHERE e.status <> 'revoked'
ORDER BY e.enrollment_id ASC
LIMIT ?2
"#;

const INVENTORY_ENROLLMENTS_ORG_SQL: &str = r#"
SELECT enrollment_id
FROM device_enrollments
WHERE org_id = ?1
ORDER BY enrollment_id ASC
LIMIT ?2
"#;

const INVENTORY_WORKSPACE_BINDINGS_USER_SQL: &str = r#"
SELECT DISTINCT w.binding_id
FROM workspace_bindings w
JOIN devices d ON d.device_id = w.device_id
JOIN memberships m ON m.org_id = d.org_id AND m.user_id = ?1
ORDER BY w.binding_id ASC
LIMIT ?2
"#;

const INVENTORY_INVITATIONS_USER_SQL: &str = r#"
SELECT invitation_id
FROM invitations
WHERE invited_by_user_id = ?1
ORDER BY invitation_id ASC
LIMIT ?2
"#;

const INVENTORY_INVITATIONS_ORG_SQL: &str = r#"
SELECT invitation_id
FROM invitations
WHERE org_id = ?1
ORDER BY invitation_id ASC
LIMIT ?2
"#;

pub struct DataGovernanceRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> DataGovernanceRepository<'a> {
    pub const fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    /// The bound D1 handle, so a caller that already has a repository does not
    /// have to keep a second reference to run an extra statement.
    pub const fn database(&self) -> &'a D1Adapter {
        self.database
    }

    /// Run one transactional batch. D1 rolls the whole batch back when any
    /// statement fails, which is what makes a job mutation, its audit row, and
    /// its outbox row one atomic fact.
    pub async fn batch(
        &self,
        statements: Vec<D1PreparedStatement>,
    ) -> worker::Result<Vec<worker::d1::D1Result>> {
        self.database.batch(statements).await
    }

    // ------------------------------------------------------------ policy ---

    pub async fn find_policy(
        &self,
        org_id: &str,
    ) -> worker::Result<Option<DataGovernancePolicyRecord>> {
        self.database
            .prepare(POLICY_BY_ORG_SQL, &[BindValue::Text(org_id)])?
            .first::<DataGovernancePolicyRecord>(None)
            .await
    }

    pub fn insert_policy_statement(
        &self,
        input: &NewPolicyInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_POLICY_SQL,
            &[
                BindValue::Text(input.policy_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.logging_mode),
                BindValue::Text(input.overrides_json),
                BindValue::Integer(i32::from(input.legal_hold)),
                optional_text(input.legal_hold_reason),
                optional_text(input.legal_hold_placed_at),
                optional_text(input.legal_hold_released_at),
                optional_text(input.legal_hold_released_by),
                BindValue::Text(input.backup_lifecycle),
                BindValue::Text(input.provider_retention_disclosure),
                optional_text(input.provider_retention_url),
                BindValue::Int64(input.default_export_expiry_seconds),
                BindValue::Text(input.created_by_principal_id),
                BindValue::Text(input.now.as_str()),
            ],
        )
    }

    pub fn update_policy_statement(
        &self,
        input: &PolicyUpdateInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_POLICY_SQL,
            &[
                BindValue::Text(input.org_id),
                BindValue::Text(input.logging_mode),
                BindValue::Text(input.overrides_json),
                BindValue::Integer(i32::from(input.legal_hold)),
                optional_text(input.legal_hold_reason),
                optional_text(input.legal_hold_placed_at),
                optional_text(input.legal_hold_released_at),
                optional_text(input.legal_hold_released_by),
                BindValue::Text(input.backup_lifecycle),
                BindValue::Text(input.provider_retention_disclosure),
                optional_text(input.provider_retention_url),
                BindValue::Int64(input.default_export_expiry_seconds),
                BindValue::Text(input.now.as_str()),
                BindValue::Int64(input.expected_version),
            ],
        )
    }

    /// Fails the surrounding D1 batch when the policy version is stale, so a
    /// concurrent PATCH cannot slip between the read and the write.
    pub fn assert_policy_version_statement(
        &self,
        org_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_POLICY_VERSION_SQL,
            &[BindValue::Text(org_id), BindValue::Int64(expected_version)],
        )
    }

    /// Seed the F20-001 declaration table from the compiled-in registry.
    ///
    /// The registry is a frozen `const` table in the domain module, so this is
    /// the only way a `deletion_tasks.data_class` value can satisfy the
    /// `data_class_registry` foreign key. `INSERT OR IGNORE` keeps an
    /// operator-applied description or a future registry bump from being
    /// silently reverted by a Worker deploy.
    pub fn registry_seed_statements(
        &self,
        now: &Timestamp,
    ) -> worker::Result<Vec<D1PreparedStatement>> {
        registry()
            .into_iter()
            .map(|record| {
                self.database.prepare(
                    INSERT_REGISTRY_ROW_SQL,
                    &[
                        BindValue::Text(record.class.as_str()),
                        BindValue::Text(record.sensitivity().as_str()),
                        BindValue::Text(record.owner_scope().as_str()),
                        BindValue::Int64(
                            i64::try_from(record.default_retention().bound_seconds().unwrap_or(0))
                                .unwrap_or(0),
                        ),
                        BindValue::Text(record.export_behavior().as_str()),
                        BindValue::Text(record.deletion_behavior().as_str()),
                        BindValue::Text(record.logging().as_str()),
                        BindValue::Text(record.description()),
                        BindValue::Text(now.as_str()),
                    ],
                )
            })
            .collect()
    }

    // ------------------------------------------------------------ export ---

    /// Worker-side read. The caller is the queue consumer, which already holds
    /// the subject id from a durable envelope; nothing here is browser input.
    pub async fn find_export(&self, export_id: &str) -> worker::Result<Option<ExportJobRecord>> {
        self.database
            .prepare(EXPORT_BY_ID_SQL, &[BindValue::Text(export_id)])?
            .first::<ExportJobRecord>(None)
            .await
    }

    /// Tenant-scoped read used by every browser route.
    pub async fn find_export_for_scope(
        &self,
        export_id: &str,
        scope_type: &str,
        scope_id: &str,
    ) -> worker::Result<Option<ExportJobRecord>> {
        self.database
            .prepare(
                EXPORT_BY_ID_FOR_SCOPE_SQL,
                &[
                    BindValue::Text(export_id),
                    BindValue::Text(scope_type),
                    BindValue::Text(scope_id),
                ],
            )?
            .first::<ExportJobRecord>(None)
            .await
    }

    /// Find the job an identical request already created.
    ///
    /// The unique index on `(org, scope, categories, cutoff)` is the durable
    /// guarantee; this read turns the resulting constraint violation into a
    /// normal replay instead of a 409.
    pub async fn find_export_by_dedupe(
        &self,
        org_id: Option<&str>,
        scope_type: &str,
        scope_user_id: Option<&str>,
        scope_org_id: Option<&str>,
        categories_json: &str,
        snapshot_cutoff_at: &str,
    ) -> worker::Result<Option<ExportJobRecord>> {
        self.database
            .prepare(
                EXPORT_BY_DEDUPE_SQL,
                &[
                    optional_text(org_id),
                    BindValue::Text(scope_type),
                    optional_text(scope_user_id),
                    optional_text(scope_org_id),
                    BindValue::Text(categories_json),
                    BindValue::Text(snapshot_cutoff_at),
                ],
            )?
            .first::<ExportJobRecord>(None)
            .await
    }

    pub async fn list_exports_for_org(
        &self,
        org_id: &str,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<ExportJobRecord>> {
        let (cursor_at, cursor_id) = cursor.unwrap_or(("", ""));
        self.database
            .prepare(
                EXPORTS_PAGE_FOR_ORG_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(cursor_at),
                    BindValue::Text(cursor_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<ExportJobRecord>()
    }

    pub async fn list_exports_for_user(
        &self,
        user_id: &str,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<ExportJobRecord>> {
        let (cursor_at, cursor_id) = cursor.unwrap_or(("", ""));
        self.database
            .prepare(
                EXPORTS_PAGE_FOR_USER_SQL,
                &[
                    BindValue::Text(user_id),
                    BindValue::Text(cursor_at),
                    BindValue::Text(cursor_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<ExportJobRecord>()
    }

    pub fn insert_export_statement(
        &self,
        input: &NewExportInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_EXPORT_SQL,
            &[
                BindValue::Text(input.export_id),
                optional_text(input.org_id),
                BindValue::Text(input.scope_type),
                optional_text(input.scope_user_id),
                optional_text(input.scope_org_id),
                BindValue::Text(input.categories_json),
                BindValue::Text(input.format),
                BindValue::Text(input.snapshot_cutoff_at),
                BindValue::Text(input.requested_by_principal_id),
                BindValue::Text(input.now.as_str()),
            ],
        )
    }

    /// Compare-and-set the export state machine.
    ///
    /// `attempt` increments only when entering `retry_wait`, so a resumed
    /// collection is visibly a new attempt and a redelivered message is not.
    pub fn update_export_state_statement(
        &self,
        input: &ExportStateUpdateInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_EXPORT_STATE_SQL,
            &[
                BindValue::Text(input.export_id),
                BindValue::Int64(input.expected_version),
                BindValue::Text(input.next_state),
                BindValue::Integer(i32::from(input.increment_attempt)),
                optional_text(input.next_attempt_at),
                optional_text(input.failure_code),
                optional_text(input.ready_at),
                optional_text(input.finished_at),
                BindValue::Text(input.now.as_str()),
                BindValue::Text(input.expected_state),
            ],
        )
    }

    pub fn insert_artifact_statement(
        &self,
        input: &NewArtifactInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_ARTIFACT_SQL,
            &[
                BindValue::Text(input.artifact_id),
                BindValue::Text(input.export_id),
                optional_text(input.org_id),
                BindValue::Text(input.object_key),
                BindValue::Text(input.bucket_name),
                BindValue::Text(input.content_type),
                BindValue::Int64(input.size_bytes),
                BindValue::Text(input.checksum_sha256),
                BindValue::Text(input.created_at),
                BindValue::Text(input.expires_at),
            ],
        )
    }

    pub async fn find_artifact(
        &self,
        export_id: &str,
    ) -> worker::Result<Option<ExportArtifactRecord>> {
        self.database
            .prepare(ARTIFACT_BY_EXPORT_SQL, &[BindValue::Text(export_id)])?
            .first::<ExportArtifactRecord>(None)
            .await
    }

    pub fn mark_artifact_deleted_statement(
        &self,
        export_id: &str,
        deleted_at: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            MARK_ARTIFACT_DELETED_SQL,
            &[BindValue::Text(export_id), BindValue::Text(deleted_at)],
        )
    }

    pub fn insert_download_grant_statement(
        &self,
        input: &NewDownloadGrantInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_GRANT_SQL,
            &[
                BindValue::Text(input.grant_id),
                BindValue::Text(input.export_id),
                BindValue::Text(input.artifact_id),
                optional_text(input.org_id),
                BindValue::Text(input.user_id),
                BindValue::Text(input.token_fingerprint),
                BindValue::Text(input.issued_at),
                BindValue::Text(input.expires_at),
            ],
        )
    }

    pub async fn find_download_grant(
        &self,
        token_fingerprint: &str,
    ) -> worker::Result<Option<DownloadGrantRecord>> {
        self.database
            .prepare(
                GRANT_BY_FINGERPRINT_SQL,
                &[BindValue::Text(token_fingerprint)],
            )?
            .first::<DownloadGrantRecord>(None)
            .await
    }

    pub fn touch_download_grant_statement(
        &self,
        grant_id: &str,
        now: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            TOUCH_GRANT_SQL,
            &[BindValue::Text(grant_id), BindValue::Text(now)],
        )
    }

    pub fn revoke_grants_statement(
        &self,
        export_id: &str,
        revoked_at: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            REVOKE_GRANTS_FOR_EXPORT_SQL,
            &[BindValue::Text(export_id), BindValue::Text(revoked_at)],
        )
    }

    // ----------------------------------------------------------- deletion ---

    pub async fn find_deletion_for_scope(
        &self,
        deletion_id: &str,
        target_type: &str,
        target_id: &str,
    ) -> worker::Result<Option<DeletionJobRecord>> {
        self.database
            .prepare(
                DELETION_BY_ID_FOR_SCOPE_SQL,
                &[
                    BindValue::Text(deletion_id),
                    BindValue::Text(target_type),
                    BindValue::Text(target_id),
                ],
            )?
            .first::<DeletionJobRecord>(None)
            .await
    }

    pub async fn find_deletion(
        &self,
        deletion_id: &str,
    ) -> worker::Result<Option<DeletionJobRecord>> {
        self.database
            .prepare(DELETION_BY_ID_SQL, &[BindValue::Text(deletion_id)])?
            .first::<DeletionJobRecord>(None)
            .await
    }

    pub async fn find_deletion_for_target(
        &self,
        target_type: &str,
        target_id: &str,
    ) -> worker::Result<Option<DeletionJobRecord>> {
        self.database
            .prepare(
                DELETION_BY_TARGET_SQL,
                &[BindValue::Text(target_type), BindValue::Text(target_id)],
            )?
            .first::<DeletionJobRecord>(None)
            .await
    }

    pub async fn list_deletions_for_org(
        &self,
        org_id: &str,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<DeletionJobRecord>> {
        let (cursor_at, cursor_id) = cursor.unwrap_or(("", ""));
        self.database
            .prepare(
                DELETIONS_PAGE_FOR_ORG_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(cursor_at),
                    BindValue::Text(cursor_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<DeletionJobRecord>()
    }

    pub async fn list_deletions_for_user(
        &self,
        user_id: &str,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<DeletionJobRecord>> {
        let (cursor_at, cursor_id) = cursor.unwrap_or(("", ""));
        self.database
            .prepare(
                DELETIONS_PAGE_FOR_USER_SQL,
                &[
                    BindValue::Text(user_id),
                    BindValue::Text(cursor_at),
                    BindValue::Text(cursor_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<DeletionJobRecord>()
    }

    pub fn insert_deletion_statement(
        &self,
        input: &NewDeletionInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_DELETION_SQL,
            &[
                BindValue::Text(input.deletion_id),
                optional_text(input.org_id),
                BindValue::Text(input.target_type),
                optional_text(input.target_user_id),
                optional_text(input.target_org_id),
                optional_text(input.lifecycle_request_id),
                BindValue::Text(input.state),
                optional_text(input.grace_expires_at),
                optional_text(input.cutoff_at),
                BindValue::Integer(i32::from(input.fenced)),
                BindValue::Integer(i32::from(input.legal_hold)),
                BindValue::Text(input.requested_by_principal_id),
                BindValue::Text(input.now.as_str()),
            ],
        )
    }

    /// P06-CR-003 bridge statement, called by the existing P02 organization
    /// lifecycle route. `ON CONFLICT (target_org_id)` means a repeated lifecycle
    /// request cannot fork a second job; the caller reads the winning row back
    /// with [`Self::find_deletion_for_target`].
    pub fn link_organization_deletion_job_statement(
        &self,
        input: &DeletionJobLinkInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            LINK_DELETION_JOB_SQL,
            &[
                BindValue::Text(input.deletion_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.lifecycle_request_id),
                BindValue::Text(input.cutoff_at),
                BindValue::Integer(i32::from(input.legal_hold)),
                BindValue::Text(input.requested_by_principal_id),
                BindValue::Text(input.now.as_str()),
            ],
        )
    }

    pub fn update_deletion_state_statement(
        &self,
        input: &DeletionStateUpdateInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_DELETION_STATE_SQL,
            &[
                BindValue::Text(input.deletion_id),
                BindValue::Int64(input.expected_version),
                BindValue::Text(input.next_state),
                BindValue::Integer(i32::from(input.increment_attempt)),
                optional_text(input.next_attempt_at),
                optional_text(input.failure_code),
                optional_text(input.grace_expires_at),
                optional_text(input.certificate_id),
                optional_text(input.completed_at),
                BindValue::Text(input.now.as_str()),
                BindValue::Text(input.expected_state),
            ],
        )
    }

    pub fn set_deletion_cutoff_statement(
        &self,
        deletion_id: &str,
        cutoff_at: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            SET_DELETION_CUTOFF_SQL,
            &[
                BindValue::Text(deletion_id),
                BindValue::Text(cutoff_at),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    /// Insert a planned step. `ON CONFLICT` on the
    /// `(deletion, class, kind, reference)` tuple makes re-planning idempotent,
    /// so a resumed job cannot create a second step for one reference.
    pub fn insert_deletion_task_statement(
        &self,
        input: &NewDeletionTaskInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_DELETION_TASK_SQL,
            &[
                BindValue::Text(input.task_id),
                BindValue::Text(input.deletion_id),
                optional_text(input.org_id),
                BindValue::Text(input.data_class),
                BindValue::Text(input.reference_kind),
                BindValue::Text(input.object_reference),
                BindValue::Text(input.state),
                BindValue::Int64(input.attempt),
                optional_text(input.skip_reason),
                optional_text(input.started_at),
                optional_text(input.completed_at),
                BindValue::Text(input.now.as_str()),
            ],
        )
    }

    pub fn update_deletion_task_statement(
        &self,
        input: &DeletionTaskUpdateInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_DELETION_TASK_SQL,
            &[
                BindValue::Text(input.deletion_id),
                BindValue::Text(input.data_class),
                BindValue::Text(input.reference_kind),
                BindValue::Text(input.object_reference),
                BindValue::Text(input.next_state),
                BindValue::Integer(i32::from(input.increment_attempt)),
                optional_text(input.failure_code),
                optional_text(input.skip_reason),
                optional_text(input.started_at),
                optional_text(input.completed_at),
                BindValue::Text(input.now.as_str()),
                BindValue::Text(input.expected_state),
            ],
        )
    }

    pub async fn list_deletion_tasks(
        &self,
        deletion_id: &str,
        limit: i32,
    ) -> worker::Result<Vec<DeletionTaskRecord>> {
        self.database
            .prepare(
                DELETION_TASKS_SQL,
                &[
                    BindValue::Text(deletion_id),
                    BindValue::Integer(limit.clamp(1, PAGE_LIMIT_MAX * 10)),
                ],
            )?
            .all()
            .await?
            .results::<DeletionTaskRecord>()
    }

    pub async fn list_pending_deletion_tasks(
        &self,
        deletion_id: &str,
        limit: i32,
    ) -> worker::Result<Vec<DeletionTaskRecord>> {
        self.database
            .prepare(
                PENDING_DELETION_TASKS_SQL,
                &[
                    BindValue::Text(deletion_id),
                    BindValue::Integer(limit.clamp(1, 500)),
                ],
            )?
            .all()
            .await?
            .results::<DeletionTaskRecord>()
    }

    pub fn insert_certificate_statement(
        &self,
        input: &NewCertificateInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_CERTIFICATE_SQL,
            &[
                BindValue::Text(input.certificate_id),
                BindValue::Text(input.deletion_id),
                optional_text(input.org_id),
                BindValue::Text(input.scope_type),
                BindValue::Text(input.scope_id),
                BindValue::Text(input.class_results_json),
                BindValue::Text(input.retained_legal_classes_json),
                BindValue::Text(input.completed_at),
                BindValue::Text(input.expires_at),
                BindValue::Text(input.now.as_str()),
            ],
        )
    }

    pub async fn find_certificate(
        &self,
        deletion_id: &str,
    ) -> worker::Result<Option<DeletionCertificateRecord>> {
        self.database
            .prepare(CERTIFICATE_BY_DELETION_SQL, &[BindValue::Text(deletion_id)])?
            .first::<DeletionCertificateRecord>(None)
            .await
    }

    // ----------------------------------------------------- queue envelope ---

    pub async fn find_queue_envelope(
        &self,
        job_type: &str,
        org_id: Option<&str>,
        dedupe_key: &str,
        generation: i64,
    ) -> worker::Result<Option<QueueEnvelopeRecord>> {
        self.database
            .prepare(
                QUEUE_ENVELOPE_BY_DEDUPE_SQL,
                &[
                    BindValue::Text(job_type),
                    optional_text(org_id),
                    BindValue::Text(dedupe_key),
                    BindValue::Int64(generation),
                ],
            )?
            .first::<QueueEnvelopeRecord>(None)
            .await
    }

    /// Enqueue. `ON CONFLICT DO NOTHING` plus the unique
    /// `(job_type, org, dedupe_key, generation)` index is the durable dedupe:
    /// a retried request cannot create a second envelope for one logical job.
    pub fn insert_queue_envelope_statement(
        &self,
        input: &NewQueueEnvelopeInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_QUEUE_ENVELOPE_SQL,
            &[
                BindValue::Text(input.job_id),
                BindValue::Text(input.job_type),
                BindValue::Int64(1),
                optional_text(input.org_id),
                BindValue::Text(input.subject_type),
                BindValue::Text(input.subject_id),
                match input.subject_version {
                    Some(version) => BindValue::Int64(version),
                    None => BindValue::Null,
                },
                BindValue::Text(input.dedupe_key),
                BindValue::Text(input.request_id),
                BindValue::Text(input.correlation_id),
                BindValue::Text(input.payload_ref),
                BindValue::Text(input.now.as_str()),
            ],
        )
    }

    /// Atomic `queued|retry_wait → running` claim on job id, state, and version.
    /// A crash before this leaves the job retryable; a crash after it is
    /// recovered by lease expiry.
    pub fn claim_queue_envelope_statement(
        &self,
        job_id: &str,
        lease_expires_at: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            CLAIM_QUEUE_ENVELOPE_SQL,
            &[
                BindValue::Text(job_id),
                BindValue::Text(lease_expires_at),
                BindValue::Text(now.as_str()),
                BindValue::Int64(expected_version),
            ],
        )
    }

    pub fn settle_queue_envelope_statement(
        &self,
        job_id: &str,
        expected_version: i64,
        next_state: &str,
        next_attempt_at: Option<&str>,
        error_code: Option<&str>,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            SETTLE_QUEUE_ENVELOPE_SQL,
            &[
                BindValue::Text(job_id),
                BindValue::Int64(expected_version),
                BindValue::Text(next_state),
                optional_text(next_attempt_at),
                optional_text(error_code),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    // ------------------------------------------------ artifact collection --

    /// Collect one frozen export category for one scope at one cutoff.
    ///
    /// Every statement is bounded, ordered, and filtered by the frozen
    /// `snapshot_cutoff_at`, which is what makes the packaged artifact a
    /// consistent snapshot rather than a moving target. None of the projections
    /// includes a prompt, response, tool argument, credential, secret, session
    /// reference, or private key: the column lists are the redaction.
    pub async fn collect_category(
        &self,
        category: ExportCategory,
        scope: &ExportScope,
        cutoff_at: &str,
        limit: i32,
    ) -> worker::Result<Vec<Value>> {
        let limit = limit.clamp(1, EXPORT_ROW_LIMIT);
        let scope_id = scope.scope_id();
        let personal = scope.is_personal();
        let (sql, scope_param) = match (category, personal) {
            (ExportCategory::Identity, true) => (COLLECT_IDENTITY_USER_SQL, scope_id),
            (ExportCategory::Identity, false) => (COLLECT_IDENTITY_ORG_SQL, scope_id),
            (ExportCategory::Organization, true) => (COLLECT_ORGANIZATION_SQL, ""),
            (ExportCategory::Organization, false) => (COLLECT_ORGANIZATION_SQL, scope_id),
            (ExportCategory::Devices, true) => (COLLECT_DEVICES_SQL, ""),
            (ExportCategory::Devices, false) => (COLLECT_DEVICES_SQL, scope_id),
            (ExportCategory::RunsMetadata, true) => (COLLECT_RUNS_SQL, ""),
            (ExportCategory::RunsMetadata, false) => (COLLECT_RUNS_SQL, scope_id),
            (ExportCategory::UsageBilling, true) => (COLLECT_USAGE_SQL, ""),
            (ExportCategory::UsageBilling, false) => (COLLECT_USAGE_SQL, scope_id),
            (ExportCategory::AuditRedacted, true) => (COLLECT_AUDIT_SQL, ""),
            (ExportCategory::AuditRedacted, false) => (COLLECT_AUDIT_SQL, scope_id),
            (ExportCategory::Notifications, true) => (COLLECT_NOTIFICATIONS_USER_SQL, scope_id),
            (ExportCategory::Notifications, false) => (COLLECT_NOTIFICATIONS_ORG_SQL, scope_id),
            (ExportCategory::DataGovernance, true) => (DECLARATIONS_USER_SQL, ""),
            (ExportCategory::DataGovernance, false) => (DECLARATIONS_ORG_SQL, ""),
        };
        let bindings = if sql == DECLARATIONS_USER_SQL || sql == DECLARATIONS_ORG_SQL {
            vec![BindValue::Integer(limit)]
        } else {
            vec![
                BindValue::Text(scope_param),
                BindValue::Text(cutoff_at),
                BindValue::Integer(limit),
            ]
        };
        let mut collected = self
            .database
            .prepare(sql, &bindings)?
            .all()
            .await?
            .results::<Value>()?;
        if category == ExportCategory::Organization && !personal {
            // An organization export is more than its own row: the members and
            // the teams are the organization's data, so the category carries
            // them.
            for extra in [
                COLLECT_ORGANIZATION_MEMBERSHIPS_SQL,
                COLLECT_ORGANIZATION_TEAMS_SQL,
            ] {
                collected.extend(
                    self.database
                        .prepare(
                            extra,
                            &[
                                BindValue::Text(scope_id),
                                BindValue::Text(cutoff_at),
                                BindValue::Integer(limit),
                            ],
                        )?
                        .all()
                        .await?
                        .results::<Value>()?,
                );
            }
        }
        if category == ExportCategory::DataGovernance && !personal {
            let policy = self
                .database
                .prepare(
                    COLLECT_POLICY_SQL,
                    &[BindValue::Text(scope_id), BindValue::Text(cutoff_at)],
                )?
                .all()
                .await?
                .results::<Value>()?;
            collected.splice(0..0, policy);
        }
        Ok(collected)
    }

    // -------------------------------------------- deletion reference walk ---

    /// Every reference the deletion planner must act on for one scope.
    ///
    /// The walk is a closed set of statements over the tables Lumi owns. A
    /// reference system the control plane does not have is not invented here:
    /// `reference_coverage()` reports `cache` and `search_index` as pending and
    /// the certificate says so.
    pub async fn deletion_inventory(
        &self,
        target: &DeletionTarget,
        limit: i32,
    ) -> worker::Result<Vec<DeletionInventoryEntry>> {
        let limit = limit.clamp(1, 1_024);
        let scope_id = target.target_id();
        let personal = target.is_personal();
        let mut inventory: Vec<DeletionInventoryEntry> = Vec::new();
        let mut push = |class: &str, kind: ReferenceKind, reference: String| {
            if let Ok(data_class) = DataClass::new(class) {
                inventory.push(DeletionInventoryEntry::new(data_class, kind, reference));
            }
        };

        // 1. Private R2 export objects. D1 metadata is not sufficient evidence of
        //    absence, so every object is a real traversal step.
        let object_sql = if personal {
            INVENTORY_USER_EXPORT_OBJECTS_SQL
        } else {
            INVENTORY_EXPORT_OBJECTS_SQL
        };
        for key in self.references(object_sql, scope_id, limit).await? {
            push("export_artifact", ReferenceKind::R2Object, key);
        }

        // 2. The two references Lumi does not own are always recorded, so a
        //    certificate can state that it never claimed them.
        push(
            "upstream_provider_data",
            ReferenceKind::UpstreamProviderData,
            format!("upstream_provider:{scope_id}"),
        );
        push(
            "run",
            ReferenceKind::LocalDeviceData,
            format!("local_device_data:{scope_id}"),
        );

        if personal {
            for (sql, class) in [
                (INVENTORY_LOGIN_SESSIONS_SQL, "login_session"),
                (INVENTORY_PASSKEYS_SQL, "passkey_authenticator"),
                (INVENTORY_MEMBERSHIPS_USER_SQL, "membership"),
                (INVENTORY_WORKSPACE_BINDINGS_USER_SQL, "workspace_binding"),
                (INVENTORY_INVITATIONS_USER_SQL, "invitation"),
                (INVENTORY_DEVICES_USER_SQL, "device"),
                (INVENTORY_ENROLLMENTS_USER_SQL, "device_enrollment"),
            ] {
                for reference in self.references(sql, scope_id, limit).await? {
                    push(class, ReferenceKind::DatabaseRow, reference);
                }
            }
        } else {
            for (sql, class) in [
                (INVENTORY_MEMBERSHIPS_ORG_SQL, "membership"),
                (INVENTORY_INVITATIONS_ORG_SQL, "invitation"),
                (INVENTORY_DEVICES_ORG_SQL, "device"),
                (INVENTORY_ENROLLMENTS_ORG_SQL, "device_enrollment"),
            ] {
                for reference in self.references(sql, scope_id, limit).await? {
                    push(class, ReferenceKind::DatabaseRow, reference);
                }
            }
        }
        Ok(inventory)
    }

    /// Read one bounded single-column reference list. Used only for reference
    /// traversal, where the value is an opaque key or a row ID.
    async fn references(&self, sql: &str, value: &str, limit: i32) -> worker::Result<Vec<String>> {
        #[derive(Deserialize)]
        struct ReferenceRow {
            #[serde(alias = "object_key", alias = "session_id", alias = "credential_id")]
            #[serde(alias = "membership_id", alias = "grant_id", alias = "device_id")]
            #[serde(
                alias = "enrollment_id",
                alias = "team_member_id",
                alias = "binding_id"
            )]
            #[serde(alias = "invitation_id")]
            reference: String,
        }
        let rows = self
            .database
            .prepare(sql, &[BindValue::Text(value), BindValue::Integer(limit)])?
            .all()
            .await?
            .results::<ReferenceRow>()?;
        Ok(rows.into_iter().map(|row| row.reference).collect())
    }
}

fn optional_text(value: Option<&str>) -> BindValue<'_> {
    value.map_or(BindValue::Null, BindValue::Text)
}

// ------------------------------------------------------------- helpers -----

/// Canonical, sorted JSON category manifest. This exact string is the frozen
/// manifest a retry reuses; a request that submits the same categories in a
/// different order produces the same manifest and therefore the same job.
pub fn canonical_categories_json(
    categories: &[ExportCategory],
) -> Result<String, serde_json::Error> {
    let unique: std::collections::BTreeSet<ExportCategory> = categories.iter().copied().collect();
    serde_json::to_string(&unique.into_iter().collect::<Vec<_>>())
}

/// Content type for a packaged artifact format. `ExportFormat` and the R2
/// adapter's allow-list stay in one place so a format can never be stored with
/// a content type the download route would refuse to serve.
pub const fn format_content_type(format: ExportFormat) -> &'static str {
    match format {
        ExportFormat::Json => "application/json",
        ExportFormat::Jsonl => "application/x-ndjson",
        ExportFormat::Csv => "text/csv",
    }
}

/// Parse a stored `format` column, failing closed on an unknown value.
pub fn parse_export_format(value: &str) -> Option<ExportFormat> {
    ExportFormat::parse(value)
}

/// Parse a stored export state, failing closed.
pub fn parse_export_state(value: &str) -> Option<ExportJobState> {
    ExportJobState::parse(value)
}

/// Parse a stored deletion state, failing closed.
pub fn parse_deletion_state(value: &str) -> Option<DeletionJobState> {
    DeletionJobState::parse(value)
}

/// Parse a stored deletion step state, failing closed.
pub fn parse_deletion_step_state(value: &str) -> Option<DeletionStepState> {
    DeletionStepState::parse(value)
}

/// Read one bounded JSON document out of a row, failing closed. A malformed
/// governance document is a store problem, never a permissive default.
pub fn decode_json_document(value: &str) -> Option<Value> {
    serde_json::from_str::<Value>(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::data_governance::DataClass;

    #[test]
    fn canonical_manifest_is_order_independent() {
        let forward =
            canonical_categories_json(&[ExportCategory::Identity, ExportCategory::Devices])
                .unwrap();
        let reversed =
            canonical_categories_json(&[ExportCategory::Devices, ExportCategory::Identity])
                .unwrap();
        assert_eq!(forward, reversed);
        // The frozen order is the category declaration order, not lexical.
        assert_eq!(forward, "[\"identity\",\"devices\"]");
        // A duplicated submission is the same request, not a wider one.
        assert_eq!(
            canonical_categories_json(&[
                ExportCategory::Identity,
                ExportCategory::Identity,
                ExportCategory::Devices
            ])
            .unwrap(),
            forward
        );
    }

    #[test]
    fn content_types_cover_every_export_format_and_nothing_else() {
        for (format, content_type) in [
            (ExportFormat::Json, "application/json"),
            (ExportFormat::Jsonl, "application/x-ndjson"),
            (ExportFormat::Csv, "text/csv"),
        ] {
            assert_eq!(format_content_type(format), content_type);
            assert!(crate::adapters::r2::ARTIFACT_CONTENT_TYPES.contains(&content_type));
        }
    }

    #[test]
    fn stored_states_fail_closed_on_unknown_values() {
        assert_eq!(parse_export_state("ready"), Some(ExportJobState::Ready));
        assert_eq!(parse_export_state("nonsense"), None);
        assert_eq!(
            parse_deletion_state("needs_attention"),
            Some(DeletionJobState::NeedsAttention)
        );
        assert_eq!(parse_deletion_state("nonsense"), None);
        assert_eq!(
            parse_deletion_step_state("skipped"),
            Some(DeletionStepState::Skipped)
        );
        assert_eq!(parse_deletion_step_state("nonsense"), None);
        assert_eq!(parse_export_format("jsonl"), Some(ExportFormat::Jsonl));
        assert_eq!(parse_export_format("tar"), None);
    }

    #[test]
    fn every_database_row_executor_names_a_registered_class_and_one_bound_parameter() {
        assert!(!DATABASE_ROW_EXECUTORS.is_empty());
        for executor in DATABASE_ROW_EXECUTORS {
            let class = DataClass::new(executor.data_class).expect("executor class is snake_case");
            assert!(
                crate::modules::data_governance::lookup(&class).is_some(),
                "{} is not a registered data class",
                executor.data_class
            );
            assert_eq!(executor.reference_kind, ReferenceKind::DatabaseRow);
            assert!(executor.statement.contains("?1"));
            assert!(!executor.statement.contains("?2") || executor.outcome == RowOutcome::Revoke);
        }
        let duplicates: Vec<&str> = DATABASE_ROW_EXECUTORS
            .iter()
            .map(|executor| executor.data_class)
            .collect();
        let mut unique = duplicates.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), duplicates.len(), "duplicate executor class");
    }

    #[test]
    fn every_actionable_declared_class_is_either_executable_or_known_gap() {
        // A class that is actionable but has no executor parks in
        // `needs_attention` instead of being reported as deleted. Naming the
        // gap here is what keeps the gap visible: F20-001 requires a declaration
        // and an executable, and this list is where the second is missing.
        const KNOWN_GAPS: &[&str] = &[
            "agent_definition",
            "agent_session",
            "approval_request",
            "artifact",
            "artifact_ref",
            "automation_definition",
            "automation_run_link",
            "billing_account",
            "budget",
            "cost_record",
            "credential",
            "data_governance_policy",
            "deletion_job",
            "deletion_step",
            "entitlement_grant",
            "execution_lease",
            "export_artifact",
            "export_download_grant",
            "export_job",
            "idempotency_record",
            "identity",
            "inference_request",
            "license_snapshot",
            "license_state",
            "model_route",
            "notification",
            "notification_delivery",
            "notification_preference",
            "occurrence",
            "occurrence_attempt",
            "organization",
            "outbox_event",
            "policy_ack",
            "policy_snapshot",
            "provider_entitlement_projection",
            "provider_sync_state",
            "queue_job_envelope",
            "rate_limit_policy",
            "run",
            "run_event",
            "schedule_rule",
            "secret",
            "subscription",
            "subscription_event",
            "tool_call",
            "tool_policy",
            "usage_event",
            "webhook_delivery",
            "webhook_delivery_attempt",
            "webhook_endpoint",
            "webhook_secret",
            // F20-001 gap: both are declared in the data-class registry with a
            // `Tombstone` deletion behavior, but no tombstone executor exists
            // for them yet. They park in `needs_attention` with
            // `deletion_executor_unavailable` rather than being silently
            // reported as deleted. Declaring them is honest; claiming the
            // deletion would not be.
            "project_access_grant",
            "team_member",
        ];
        for class in crate::modules::data_governance::deletion_reachable_classes() {
            let executable = database_row_executor(&class, ReferenceKind::DatabaseRow).is_some();
            if !executable {
                assert!(
                    KNOWN_GAPS.contains(&class.as_str()),
                    "{} is actionable with no executor and is not a declared gap",
                    class
                );
            }
        }
    }

    #[test]
    fn upstream_provider_data_has_no_executor_ever() {
        for kind in [
            ReferenceKind::DatabaseRow,
            ReferenceKind::R2Object,
            ReferenceKind::LocalDeviceData,
            ReferenceKind::UpstreamProviderData,
        ] {
            let class = DataClass::new("upstream_provider_data").unwrap();
            assert!(
                database_row_executor(&class, kind).is_none(),
                "an executor exists for a non-Lumi-owned reference"
            );
        }
    }

    #[test]
    fn every_registry_class_yields_exactly_one_seed_row() {
        // The seed is a 1:1 map of the frozen table, so a class that reached D1
        // twice would make `deletion_tasks.data_class` ambiguous.
        let classes = crate::modules::data_governance::all_classes();
        assert_eq!(classes.len(), crate::modules::data_governance::CLASS_COUNT);
        let mut keys: Vec<&str> = classes.iter().map(|class| class.as_str()).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(keys.len(), before, "duplicate data class key");
    }
}
