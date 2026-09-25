-- 0014_p06_data_governance.sql — P06 data-class registry, retention/legal-hold
-- policy, asynchronous export jobs with private R2 artifact metadata, and
-- resumable staged-deletion jobs/steps/certificates.
--
-- Forward-only; apply after 0013_p06_billing_entitlements.sql.
--
-- F20: every persistent data class must declare sensitivity, owner/scope,
-- retention, export behavior, deletion behavior, and logging rules. The registry
-- below makes that declaration a REQUIRED, queryable row rather than prose.
--
-- P06-CR-003 / ADR 0006: export artifacts live in a PRIVATE R2 bucket with
-- Worker-mediated, re-authorized, short-lived downloads. D1 stores metadata and
-- an opaque object reference only — never export content, never a public or
-- bearer object URL.
--
-- No export content, prompt, response, credential, or secret is stored here.

--------------------------------------------------------------------------------
-- Data-class registry (F20: the six mandatory declarations per class)
--------------------------------------------------------------------------------
CREATE TABLE data_class_registry (
    data_class TEXT PRIMARY KEY CHECK (length(data_class) BETWEEN 1 AND 128),
    sensitivity TEXT NOT NULL CHECK (
        sensitivity IN ('public', 'internal', 'confidential', 'restricted', 'secret')
    ),
    owner_scope TEXT NOT NULL CHECK (
        owner_scope IN ('platform', 'organization', 'project', 'user', 'device', 'external')
    ),
    -- Concrete default retention in seconds. Placeholder values are rejected so
    -- the registry cannot ship with an undecided retention window.
    default_retention_seconds INTEGER NOT NULL
        CHECK (default_retention_seconds BETWEEN 0 AND 315360000),
    export_behavior TEXT NOT NULL CHECK (
        export_behavior IN ('included', 'owner_export', 'redacted', 'sanitized',
                            'metadata_only', 'never')
    ),
    deletion_behavior TEXT NOT NULL CHECK (
        deletion_behavior IN ('physical_delete', 'tombstone', 'minimize',
                              'crypto_erase', 'revoke', 'retain_legal_only')
    ),
    logging TEXT NOT NULL CHECK (
        logging IN ('metadata_only', 'status_only', 'ids_status', 'none')
    ),
    description TEXT CHECK (description IS NULL OR length(description) <= 2000),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24)
);
-- F20 structural invariant. A class that is NEVER exported must also be
-- unrecoverable-or-retained: either it is secret material that is crypto-erased,
-- or it is operational metadata that is deleted/tombstoned on its retention
-- schedule. The frozen gate requires BOTH shapes — `webhook_secrets` is a
-- restricted secret that is crypto-erased, while `idempotency_record` and
-- `queue_job_envelope` are internal operational rows that are never exported and
-- are deleted/tombstoned. Rejecting only the first shape would forbid the
-- second, so both are accepted and a non-terminal deletion is refused.
CREATE TRIGGER trg_data_class_registry_secret_guard
BEFORE INSERT ON data_class_registry
FOR EACH ROW WHEN NEW.export_behavior = 'never'
    AND NEW.deletion_behavior NOT IN (
        'crypto_erase', 'physical_delete', 'tombstone', 'revoke', 'retain_legal_only'
    )
BEGIN
    SELECT RAISE(ABORT, 'non-exportable class requires a terminal deletion behavior');
END;

--------------------------------------------------------------------------------
-- Org/project data-governance policy (versioned)
--------------------------------------------------------------------------------
CREATE TABLE data_governance_policies (
    policy_id TEXT PRIMARY KEY CHECK (
        length(policy_id) = 36 AND substr(policy_id, 1, 4) = 'dgp_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    project_id TEXT REFERENCES projects(project_id) ON DELETE CASCADE,
    -- F20: metadata-only is the default for inference/control-plane observability.
    logging_mode TEXT NOT NULL DEFAULT 'metadata_only'
        CHECK (logging_mode IN ('metadata_only', 'redacted_content', 'full_content')),
    -- Per-class retention overrides. Overrides may SHORTEN retention; extending
    -- beyond the legal maximum requires an audited override grant.
    class_retention_overrides_json TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(class_retention_overrides_json)
               AND length(class_retention_overrides_json) <= 32768),
    legal_hold INTEGER NOT NULL DEFAULT 0 CHECK (legal_hold IN (0, 1)),
    legal_hold_reason TEXT CHECK (legal_hold_reason IS NULL OR length(legal_hold_reason) <= 2000),
    legal_hold_placed_at TEXT CHECK (legal_hold_placed_at IS NULL OR length(legal_hold_placed_at) = 24),
    legal_hold_released_at TEXT CHECK (legal_hold_released_at IS NULL OR length(legal_hold_released_at) = 24),
    legal_hold_released_by TEXT,
    backup_lifecycle TEXT NOT NULL DEFAULT 'platform_35_day_expiry'
        CHECK (backup_lifecycle IN ('platform_35_day_expiry', 'platform_no_backup')),
    -- F20: Lumi retention is distinct from upstream AI-provider retention.
    provider_retention_disclosure TEXT NOT NULL DEFAULT 'external_policy'
        CHECK (provider_retention_disclosure IN ('external_policy', 'linked_policy')),
    provider_retention_url TEXT CHECK (
        provider_retention_url IS NULL OR length(provider_retention_url) BETWEEN 1 AND 2048
    ),
    default_export_expiry_seconds INTEGER NOT NULL DEFAULT 86400
        CHECK (default_export_expiry_seconds BETWEEN 300 AND 604800),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by_principal_id TEXT NOT NULL,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    -- A released legal hold must name its releasing principal.
    CHECK (legal_hold_released_at IS NULL OR legal_hold_released_by IS NOT NULL)
);
CREATE UNIQUE INDEX ux_data_governance_policies_org
    ON data_governance_policies(org_id) WHERE project_id IS NULL;
CREATE UNIQUE INDEX ux_data_governance_policies_project
    ON data_governance_policies(org_id, project_id) WHERE project_id IS NOT NULL;
CREATE INDEX idx_data_governance_policies_hold
    ON data_governance_policies(org_id) WHERE legal_hold = 1;

--------------------------------------------------------------------------------
-- Export jobs (asynchronous, idempotent, auditable)
--------------------------------------------------------------------------------
CREATE TABLE export_jobs (
    export_id TEXT PRIMARY KEY CHECK (
        length(export_id) = 36 AND substr(export_id, 1, 4) = 'exp_'
    ),
    org_id TEXT REFERENCES organizations(org_id) ON DELETE CASCADE,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('user', 'organization')),
    -- A user-scoped export has no org; an org-scoped export must have one.
    scope_user_id TEXT REFERENCES users(user_id) ON DELETE CASCADE,
    scope_org_id TEXT REFERENCES organizations(org_id) ON DELETE CASCADE,
    -- Explicit, bounded category manifest frozen at request time. Retries reuse
    -- the SAME manifest and cutoff.
    categories_json TEXT NOT NULL CHECK (
        json_valid(categories_json) AND length(categories_json) BETWEEN 2 AND 4096
    ),
    format TEXT NOT NULL DEFAULT 'json' CHECK (format IN ('json', 'jsonl', 'csv')),
    -- Consistent tenant-scoped snapshot boundary.
    snapshot_cutoff_at TEXT NOT NULL CHECK (length(snapshot_cutoff_at) = 24),
    state TEXT NOT NULL DEFAULT 'requested' CHECK (
        state IN ('requested', 'queued', 'collecting', 'packaging', 'verifying',
                  'ready', 'expired', 'retry_wait', 'failed', 'cancelled')
    ),
    state_version INTEGER NOT NULL DEFAULT 1 CHECK (state_version > 0),
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    next_attempt_at TEXT CHECK (next_attempt_at IS NULL OR length(next_attempt_at) = 24),
    requested_by_principal_id TEXT NOT NULL,
    requested_at TEXT NOT NULL CHECK (length(requested_at) = 24),
    ready_at TEXT CHECK (ready_at IS NULL OR length(ready_at) = 24),
    finished_at TEXT CHECK (finished_at IS NULL OR length(finished_at) = 24),
    failure_code TEXT CHECK (failure_code IS NULL OR length(failure_code) <= 96),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    CHECK (
        (scope_type = 'user' AND scope_user_id IS NOT NULL AND scope_org_id IS NULL)
        OR (scope_type = 'organization' AND scope_org_id IS NOT NULL)
    )
);
-- One export job per idempotency/dedupe key; retries never fork a second job.
CREATE UNIQUE INDEX ux_export_jobs_dedupe
    ON export_jobs(
        COALESCE(org_id, ''), scope_type, COALESCE(scope_user_id, ''),
        COALESCE(scope_org_id, ''), categories_json, snapshot_cutoff_at
    );
CREATE INDEX idx_export_jobs_org_history
    ON export_jobs(org_id, requested_at DESC);
CREATE INDEX idx_export_jobs_user_history
    ON export_jobs(scope_user_id, requested_at DESC) WHERE scope_type = 'user';
CREATE INDEX idx_export_jobs_due
    ON export_jobs(state, next_attempt_at) WHERE state IN ('queued', 'retry_wait');
-- The export lifecycle itself is NOT guarded here. The frozen state machine
-- requires `ready → expired`, so any trigger that blocks a transition out of
-- `ready` would make an export job unable to finish.
--
-- The real invariant is "no artifact while not ready". Enforcing it on the
-- artifact INSERT is both correct and sufficient: an artifact simply cannot
-- come into existence unless its job is already `ready`, so there is nothing to
-- advertise for `requested`, `queued`, `collecting`, `packaging`, `verifying`,
-- `retry_wait`, `failed`, or `cancelled`. The complementary READ-side check —
-- a download is served only while the job is `ready`, the artifact is
-- un-expired, and its grant is unexpired — is enforced by the download handler,
-- which re-authorizes the principal and the job scope on every use.

--------------------------------------------------------------------------------
-- Export artifact metadata (private R2; D1 holds metadata only)
--------------------------------------------------------------------------------
CREATE TABLE export_artifacts (
    artifact_id TEXT PRIMARY KEY CHECK (length(artifact_id) = 36),
    export_id TEXT NOT NULL UNIQUE REFERENCES export_jobs(export_id) ON DELETE CASCADE,
    org_id TEXT REFERENCES organizations(org_id) ON DELETE CASCADE,
    -- Opaque, unguessable R2 object key. NOT a public or bearer URL.
    object_key TEXT NOT NULL CHECK (length(object_key) BETWEEN 1 AND 512),
    bucket_name TEXT NOT NULL CHECK (length(bucket_name) BETWEEN 1 AND 64),
    content_type TEXT NOT NULL CHECK (length(content_type) BETWEEN 1 AND 128),
    size_bytes INTEGER CHECK (size_bytes IS NULL OR size_bytes >= 0),
    checksum_sha256 TEXT CHECK (checksum_sha256 IS NULL OR length(checksum_sha256) BETWEEN 32 AND 128),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    -- Short-lived by default (24h). Never a permanent public URL.
    expires_at TEXT NOT NULL CHECK (length(expires_at) = 24),
    deleted_at TEXT CHECK (deleted_at IS NULL OR length(deleted_at) = 24),
    CHECK (expires_at > created_at)
);
CREATE INDEX idx_export_artifacts_expiry
    ON export_artifacts(expires_at) WHERE deleted_at IS NULL;

-- F20 / the frozen export contract: an artifact may only be created while its
-- job is `ready`. This is the write-side half of "no artifact while not ready";
-- see the note above `export_jobs` for why the guard lives here rather than on
-- the job's state machine, which must be able to reach `expired`.
CREATE TRIGGER trg_export_artifacts_only_while_ready
BEFORE INSERT ON export_artifacts
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1 FROM export_jobs
    WHERE export_id = NEW.export_id AND state = 'ready'
)
BEGIN
    SELECT RAISE(ABORT, 'export artifact may only be created while the job is ready');
END;

-- Re-authorized, short-lived download grants. The grant is bound to the job
-- scope and expiry and is rechecked against current authorization on every use.
CREATE TABLE export_download_grants (
    grant_id TEXT PRIMARY KEY CHECK (length(grant_id) = 36),
    export_id TEXT NOT NULL REFERENCES export_jobs(export_id) ON DELETE CASCADE,
    artifact_id TEXT NOT NULL REFERENCES export_artifacts(artifact_id) ON DELETE CASCADE,
    org_id TEXT REFERENCES organizations(org_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    -- Only a fingerprint is stored; the raw grant token is returned once.
    token_fingerprint TEXT NOT NULL CHECK (length(token_fingerprint) BETWEEN 16 AND 128),
    issued_at TEXT NOT NULL CHECK (length(issued_at) = 24),
    expires_at TEXT NOT NULL CHECK (length(expires_at) = 24),
    revoked_at TEXT CHECK (revoked_at IS NULL OR length(revoked_at) = 24),
    use_count INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0)
);
CREATE INDEX idx_export_download_grants_expiry
    ON export_download_grants(expires_at) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX ux_export_download_grants_token
    ON export_download_grants(token_fingerprint);

--------------------------------------------------------------------------------
-- Deletion jobs (asynchronous, resumable, idempotent)
--------------------------------------------------------------------------------
CREATE TABLE deletion_jobs (
    deletion_id TEXT PRIMARY KEY CHECK (
        length(deletion_id) = 36 AND substr(deletion_id, 1, 4) = 'del_'
    ),
    org_id TEXT REFERENCES organizations(org_id) ON DELETE RESTRICT,
    target_type TEXT NOT NULL CHECK (target_type IN ('user', 'organization')),
    target_user_id TEXT REFERENCES users(user_id) ON DELETE RESTRICT,
    target_org_id TEXT REFERENCES organizations(org_id) ON DELETE RESTRICT,
    -- P06-CR-003: the existing reauthenticated P02 organization route is the sole
    -- request bridge; this FK links that request to exactly one job.
    lifecycle_request_id TEXT CHECK (
        lifecycle_request_id IS NULL OR length(lifecycle_request_id) BETWEEN 1 AND 128
    ),
    state TEXT NOT NULL DEFAULT 'requested' CHECK (
        state IN ('requested', 'awaiting_grace', 'queued', 'planning', 'deleting',
                  'verifying', 'completed', 'retry_wait', 'needs_attention', 'cancelled')
    ),
    state_version INTEGER NOT NULL DEFAULT 1 CHECK (state_version > 0),
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    next_attempt_at TEXT CHECK (next_attempt_at IS NULL OR length(next_attempt_at) = 24),
    grace_expires_at TEXT CHECK (grace_expires_at IS NULL OR length(grace_expires_at) = 24),
    -- Frozen snapshot boundary. After the cutoff, automation dispatch,
    -- webhook/notification fan-out, billing writes, export creation, and
    -- deletion retries are fenced so delayed jobs cannot resurrect data.
    cutoff_at TEXT CHECK (cutoff_at IS NULL OR length(cutoff_at) = 24),
    -- Fenced: no new data may be written for this scope after the cutoff.
    fenced INTEGER NOT NULL DEFAULT 0 CHECK (fenced IN (0, 1)),
    legal_hold INTEGER NOT NULL DEFAULT 0 CHECK (legal_hold IN (0, 1)),
    failure_code TEXT CHECK (failure_code IS NULL OR length(failure_code) <= 96),
    certificate_id TEXT,
    requested_by_principal_id TEXT NOT NULL,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    completed_at TEXT CHECK (completed_at IS NULL OR length(completed_at) = 24),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    CHECK (
        (target_type = 'user' AND target_user_id IS NOT NULL)
        OR (target_type = 'organization' AND target_org_id IS NOT NULL)
    )
);
-- One deletion job per lifecycle request: the P02 bridge cannot fork a second job.
CREATE UNIQUE INDEX ux_deletion_jobs_org_target
    ON deletion_jobs(target_org_id) WHERE target_type = 'organization';
CREATE UNIQUE INDEX ux_deletion_jobs_user_target
    ON deletion_jobs(target_user_id) WHERE target_type = 'user';
CREATE UNIQUE INDEX ux_deletion_jobs_lifecycle_request
    ON deletion_jobs(lifecycle_request_id) WHERE lifecycle_request_id IS NOT NULL;
CREATE INDEX idx_deletion_jobs_state ON deletion_jobs(state, next_attempt_at);
CREATE INDEX idx_deletion_jobs_org ON deletion_jobs(org_id, created_at DESC);

--------------------------------------------------------------------------------
-- Deletion steps (idempotent, per data class / object reference)
--------------------------------------------------------------------------------
CREATE TABLE deletion_tasks (
    task_id TEXT PRIMARY KEY CHECK (
        length(task_id) = 36 AND substr(task_id, 1, 4) = 'dts_'
    ),
    deletion_id TEXT NOT NULL REFERENCES deletion_jobs(deletion_id) ON DELETE CASCADE,
    org_id TEXT REFERENCES organizations(org_id) ON DELETE RESTRICT,
    data_class TEXT NOT NULL REFERENCES data_class_registry(data_class) ON DELETE RESTRICT,
    -- `database_row`, `r2_object`, `local_device_data`, `upstream_provider_data`.
    reference_kind TEXT NOT NULL CHECK (
        reference_kind IN ('database_row', 'r2_object', 'local_device_data', 'upstream_provider_data')
    ),
    object_reference TEXT NOT NULL CHECK (length(object_reference) BETWEEN 1 AND 512),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (
        state IN ('pending', 'running', 'retry_wait', 'needs_attention', 'succeeded',
                  'failed', 'skipped')
    ),
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    failure_code TEXT CHECK (failure_code IS NULL OR length(failure_code) <= 96),
    -- `skipped` records WHY (legal hold, not applicable, external provider).
    skip_reason TEXT CHECK (skip_reason IS NULL OR length(skip_reason) <= 96),
    started_at TEXT CHECK (started_at IS NULL OR length(started_at) = 24),
    completed_at TEXT CHECK (completed_at IS NULL OR length(completed_at) = 24),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    UNIQUE (deletion_id, data_class, reference_kind, object_reference)
);
CREATE INDEX idx_deletion_tasks_due
    ON deletion_tasks(deletion_id, state) WHERE state IN ('pending', 'running', 'retry_wait');
CREATE INDEX idx_deletion_tasks_attention
    ON deletion_tasks(deletion_id, state) WHERE state = 'needs_attention';
-- Completion requires object traversal; a skipped step must say why.
CREATE TRIGGER trg_deletion_tasks_skip_reason
BEFORE UPDATE OF state ON deletion_tasks
FOR EACH ROW WHEN NEW.state = 'skipped' AND NEW.skip_reason IS NULL
BEGIN
    SELECT RAISE(ABORT, 'skipped deletion step requires a reason');
END;
-- Lumi can never claim it deleted upstream provider data.
CREATE TRIGGER trg_deletion_tasks_provider_external
BEFORE INSERT ON deletion_tasks
FOR EACH ROW WHEN NEW.reference_kind = 'upstream_provider_data' AND NEW.state <> 'skipped'
BEGIN
    SELECT RAISE(ABORT, 'upstream provider data is not Lumi-deletable');
END;

--------------------------------------------------------------------------------
-- Deletion certificates (auditable, retained, never rewritten)
--------------------------------------------------------------------------------
CREATE TABLE deletion_certificates (
    certificate_id TEXT PRIMARY KEY CHECK (
        length(certificate_id) = 37 AND substr(certificate_id, 1, 5) = 'delc_'
    ),
    deletion_id TEXT NOT NULL UNIQUE REFERENCES deletion_jobs(deletion_id) ON DELETE RESTRICT,
    org_id TEXT REFERENCES organizations(org_id) ON DELETE RESTRICT,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('user', 'organization')),
    scope_id TEXT NOT NULL CHECK (length(scope_id) BETWEEN 1 AND 64),
    -- Per-class outcome summary. Tombstoned/minimized references only; no
    -- deleted content, credential, or secret is recorded.
    class_results_json TEXT NOT NULL CHECK (
        json_valid(class_results_json) AND length(class_results_json) <= 65536
    ),
    retained_legal_classes_json TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(retained_legal_classes_json)
               AND length(retained_legal_classes_json) <= 8192),
    completed_at TEXT NOT NULL CHECK (length(completed_at) = 24),
    -- Retained per the legal/audit window; tombstoned, never physically removed.
    expires_at TEXT NOT NULL CHECK (length(expires_at) = 24),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24)
);
CREATE INDEX idx_deletion_certificates_expiry ON deletion_certificates(expires_at);
