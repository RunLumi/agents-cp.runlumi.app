-- 0011_p06_automations.sql — P06 scheduled/off-peak automation definitions,
-- canonical schedule-rule revisions, logical occurrences, execution leases,
-- attempt history, and the additive P05 run correlation columns.
--
-- Forward-only; apply after 0010_p05_runs_tools_usage_control.sql.
--
-- P06-CR-001: at most one current server-authorized lease per occurrence. A
-- lease lost after execution may have begun moves the occurrence to the
-- terminal `ambiguous` reconciliation state and is NEVER automatically
-- re-dispatched. Only a provably-not-started lease may return to `pending`.
--
-- P06-CR-001: off-peak is a distinct execution class (provider-ticket or
-- org-window eligibility), never a cron window.
--
-- No prompt, response, credential, lease token, or secret material is stored
-- in this schema. Lease tokens are stored only as SHA-256 fingerprints.

--------------------------------------------------------------------------------
-- Canonical schedule-rule revisions (immutable)
--------------------------------------------------------------------------------
CREATE TABLE automation_schedule_rules (
    schedule_rule_id TEXT PRIMARY KEY CHECK (
        length(schedule_rule_id) = 36 AND substr(schedule_rule_id, 1, 4) = 'sch_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('one_time', 'cron', 'interval', 'manual')),
    -- Canonical normalized semantics, not a display string. `expression` is the
    -- display cron text; `canonical_json` is the authoritative normalized rule.
    expression TEXT,
    timezone TEXT,
    dom_dow_mode TEXT CHECK (dom_dow_mode IS NULL OR dom_dow_mode IN ('or', 'and')),
    dst_policy TEXT CHECK (
        dst_policy IS NULL OR dst_policy IN ('skip_duplicate', 'run_first', 'run_both')
    ),
    interval_every INTEGER CHECK (interval_every IS NULL OR interval_every BETWEEN 1 AND 200),
    interval_unit TEXT CHECK (
        interval_unit IS NULL
        OR interval_unit IN ('minutes', 'hours', 'days', 'weeks', 'months', 'years')
    ),
    anchor_at TEXT CHECK (anchor_at IS NULL OR length(anchor_at) = 24),
    scheduled_at TEXT CHECK (scheduled_at IS NULL OR length(scheduled_at) = 24),
    by_weekday_json TEXT CHECK (by_weekday_json IS NULL OR json_valid(by_weekday_json)),
    by_monthday_json TEXT CHECK (by_monthday_json IS NULL OR json_valid(by_monthday_json)),
    by_month_json TEXT CHECK (by_month_json IS NULL OR json_valid(by_month_json)),
    overlap_policy TEXT NOT NULL DEFAULT 'skip' CHECK (
        overlap_policy IN ('allow', 'skip', 'queue_one', 'cancel_previous')
    ),
    missed_policy TEXT NOT NULL DEFAULT 'run_once' CHECK (
        missed_policy IN ('skip', 'run_once', 'catch_up')
    ),
    catch_up_limit INTEGER CHECK (
        catch_up_limit IS NULL
        OR (missed_policy = 'catch_up' AND catch_up_limit BETWEEN 1 AND 20)
    ),
    canonical_json TEXT NOT NULL CHECK (json_valid(canonical_json)),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    -- Schedule revisions are immutable history: there is deliberately no
    -- updated_at and no UPDATE path in the domain module.
    CHECK (
        (kind = 'one_time' AND scheduled_at IS NOT NULL)
        OR (kind = 'cron' AND expression IS NOT NULL AND timezone IS NOT NULL)
        OR (kind = 'interval' AND interval_every IS NOT NULL
            AND interval_unit IS NOT NULL AND anchor_at IS NOT NULL AND timezone IS NOT NULL)
        OR (kind = 'manual')
    )
);
CREATE INDEX idx_automation_schedule_rules_org ON automation_schedule_rules(org_id, kind, created_at DESC);

--------------------------------------------------------------------------------
-- Automation definitions
--------------------------------------------------------------------------------
CREATE TABLE automation_definitions (
    automation_id TEXT PRIMARY KEY CHECK (
        length(automation_id) = 36 AND substr(automation_id, 1, 4) = 'aut_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    project_id TEXT REFERENCES projects(project_id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 160),
    description TEXT CHECK (description IS NULL OR length(description) <= 2000),
    agent_definition_id TEXT REFERENCES agent_definitions(agent_definition_id) ON DELETE RESTRICT,
    schedule_rule_id TEXT NOT NULL REFERENCES automation_schedule_rules(schedule_rule_id) ON DELETE RESTRICT,
    -- Discriminated execution principal, server-resolved at dispatch. The P06
    -- MVP accepts `user`; `service_account` is reserved for F14 and must fail
    -- closed until a P05-compatible service principal exists.
    execution_principal_kind TEXT NOT NULL DEFAULT 'user'
        CHECK (execution_principal_kind IN ('user', 'service_account')),
    execution_principal_id TEXT NOT NULL CHECK (length(execution_principal_id) BETWEEN 1 AND 64),
    target_kind TEXT NOT NULL CHECK (
        target_kind IN ('eligible_device', 'specific_device', 'remote_workspace', 'server_runner')
    ),
    target_device_id TEXT REFERENCES devices(device_id) ON DELETE RESTRICT,
    target_workspace_binding_id TEXT REFERENCES workspace_bindings(binding_id) ON DELETE RESTRICT,
    required_capabilities_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(required_capabilities_json)),
    -- Execution policy fields are CONSTRAINTS, not authority. A NULL value means
    -- inherit the agent/project default; a supplied value may only narrow or
    -- select an already-authorized route.
    execution_model_alias TEXT,
    execution_budget_id TEXT REFERENCES budgets(budget_id) ON DELETE RESTRICT,
    tool_policy_scope TEXT NOT NULL DEFAULT 'project'
        CHECK (tool_policy_scope IN ('project', 'organization', 'agent')),
    required_policy_version INTEGER CHECK (required_policy_version IS NULL OR required_policy_version > 0),
    -- P06-CR-001: off-peak is a distinct execution class, not a cron window.
    off_peak_eligibility_source TEXT CHECK (
        off_peak_eligibility_source IS NULL OR off_peak_eligibility_source IN ('provider_ticket', 'org_window')
    ),
    off_peak_allowed_route_aliases_json TEXT
        CHECK (off_peak_allowed_route_aliases_json IS NULL
               OR json_valid(off_peak_allowed_route_aliases_json)),
    off_peak_deny_automation_mutation INTEGER NOT NULL DEFAULT 1
        CHECK (off_peak_deny_automation_mutation IN (0, 1)),
    off_peak_deny_recursive_off_peak INTEGER NOT NULL DEFAULT 1
        CHECK (off_peak_deny_recursive_off_peak IN (0, 1)),
    off_peak_allow_background_processes INTEGER NOT NULL DEFAULT 0
        CHECK (off_peak_allow_background_processes IN (0, 1)),
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'paused', 'suspended', 'completed', 'failed', 'deleted')),
    -- Bounded execution-retry settings (frozen bounds).
    max_start_attempts INTEGER NOT NULL DEFAULT 2 CHECK (max_start_attempts BETWEEN 1 AND 3),
    lease_ttl_seconds INTEGER NOT NULL DEFAULT 300 CHECK (lease_ttl_seconds BETWEEN 30 AND 3600),
    heartbeat_interval_seconds INTEGER NOT NULL DEFAULT 30
        CHECK (heartbeat_interval_seconds BETWEEN 10 AND 60),
    -- Authoritative server-side schedule cursor. Advanced transactionally with
    -- due-occurrence generation; never inferred from a device's last run.
    schedule_cursor_at TEXT CHECK (schedule_cursor_at IS NULL OR length(schedule_cursor_at) = 24),
    next_run_at TEXT CHECK (next_run_at IS NULL OR length(next_run_at) = 24),
    last_run_at TEXT CHECK (last_run_at IS NULL OR length(last_run_at) = 24),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    -- `queue_one` successor bound so a queued successor can never block forever.
    queued_successor_max_age_seconds INTEGER NOT NULL DEFAULT 86400
        CHECK (queued_successor_max_age_seconds BETWEEN 60 AND 604800),
    CHECK (target_kind <> 'specific_device' OR target_device_id IS NOT NULL)
);
-- One unique active automation name per org/project scope.
CREATE UNIQUE INDEX ux_automation_definitions_name
    ON automation_definitions(org_id, COALESCE(project_id, ''), name)
    WHERE status NOT IN ('deleted', 'completed');
CREATE INDEX idx_automation_definitions_due
    ON automation_definitions(org_id, status, next_run_at);
CREATE INDEX idx_automation_definitions_project
    ON automation_definitions(project_id, status, updated_at DESC);

--------------------------------------------------------------------------------
-- Logical occurrences (append-only history + current projection)
--------------------------------------------------------------------------------
CREATE TABLE automation_occurrences (
    occurrence_id TEXT PRIMARY KEY CHECK (
        length(occurrence_id) = 36 AND substr(occurrence_id, 1, 4) = 'occ_'
    ),
    automation_id TEXT NOT NULL REFERENCES automation_definitions(automation_id) ON DELETE RESTRICT,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE RESTRICT,
    project_id TEXT REFERENCES projects(project_id) ON DELETE RESTRICT,
    schedule_rule_id TEXT NOT NULL REFERENCES automation_schedule_rules(schedule_rule_id) ON DELETE RESTRICT,
    -- `scheduled` occurrences are UNIQUE(automation, schedule_rule, instant).
    -- `manual` occurrences are UNIQUE(automation, trigger_key_digest) where the
    -- digest references the P01 idempotency record. A scheduled row therefore
    -- must NOT carry a trigger key, and vice versa.
    kind TEXT NOT NULL CHECK (kind IN ('scheduled', 'manual', 'off_peak')),
    scheduled_for_utc TEXT CHECK (scheduled_for_utc IS NULL OR length(scheduled_for_utc) = 24),
    trigger_key_digest TEXT,
    execution_principal_kind TEXT NOT NULL CHECK (
        execution_principal_kind IN ('user', 'service_account')
    ),
    execution_principal_id TEXT NOT NULL CHECK (length(execution_principal_id) BETWEEN 1 AND 64),
    off_peak_mode TEXT NOT NULL DEFAULT 'normal' CHECK (off_peak_mode IN ('normal', 'off_peak')),
    policy_snapshot_id TEXT REFERENCES policy_snapshots(policy_id) ON DELETE RESTRICT,
    policy_version INTEGER CHECK (policy_version IS NULL OR policy_version > 0),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (
        state IN ('pending', 'dispatching', 'leased', 'started', 'succeeded',
                  'failed', 'cancelled', 'missed', 'skipped', 'ambiguous')
    ),
    state_version INTEGER NOT NULL DEFAULT 1 CHECK (state_version > 0),
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    reason_code TEXT CHECK (reason_code IS NULL OR length(reason_code) <= 96),
    run_id TEXT,
    blocked_by_occurrence_id TEXT REFERENCES automation_occurrences(occurrence_id) ON DELETE RESTRICT,
    lease_expires_at TEXT CHECK (lease_expires_at IS NULL OR length(lease_expires_at) = 24),
    queued_at TEXT CHECK (queued_at IS NULL OR length(queued_at) = 24),
    started_at TEXT CHECK (started_at IS NULL OR length(started_at) = 24),
    finished_at TEXT CHECK (finished_at IS NULL OR length(finished_at) = 24),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    CHECK (
        (kind = 'scheduled' AND scheduled_for_utc IS NOT NULL AND trigger_key_digest IS NULL)
        OR (kind = 'manual' AND trigger_key_digest IS NOT NULL AND scheduled_for_utc IS NULL)
        OR (kind = 'off_peak' AND trigger_key_digest IS NOT NULL AND scheduled_for_utc IS NULL)
    )
);
-- P06-CR-001: a redelivery, reconnect, or second claim cannot mint a second
-- logical occurrence for the same revision/instant.
CREATE UNIQUE INDEX ux_automation_occurrences_scheduled
    ON automation_occurrences(automation_id, schedule_rule_id, scheduled_for_utc)
    WHERE kind = 'scheduled';
CREATE UNIQUE INDEX ux_automation_occurrences_manual
    ON automation_occurrences(automation_id, trigger_key_digest)
    WHERE kind IN ('manual', 'off_peak');
CREATE INDEX idx_automation_occurrences_state ON automation_occurrences(org_id, state, updated_at DESC);
CREATE INDEX idx_automation_occurrences_automation
    ON automation_occurrences(automation_id, created_at DESC);
CREATE INDEX idx_automation_occurrences_dispatch
    ON automation_occurrences(state, scheduled_for_utc)
    WHERE state IN ('pending', 'dispatching');

--------------------------------------------------------------------------------
-- Execution leases (at most one current lease per occurrence)
--------------------------------------------------------------------------------
CREATE TABLE automation_leases (
    lease_id TEXT PRIMARY KEY CHECK (
        length(lease_id) = 36 AND substr(lease_id, 1, 4) = 'lse_'
    ),
    occurrence_id TEXT NOT NULL REFERENCES automation_occurrences(occurrence_id) ON DELETE RESTRICT,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE RESTRICT,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    state TEXT NOT NULL DEFAULT 'active' CHECK (
        state IN ('active', 'released', 'expired', 'revoked')
    ),
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    -- Raw lease tokens are NEVER stored. Only a SHA-256 fingerprint.
    lease_token_fingerprint TEXT NOT NULL CHECK (length(lease_token_fingerprint) BETWEEN 16 AND 128),
    -- Monotonic fence: every claim/renew/start/settle must present the current
    -- version so a stale device cannot settle a superseded attempt.
    lease_version INTEGER NOT NULL DEFAULT 1 CHECK (lease_version > 0),
    lease_fence INTEGER NOT NULL DEFAULT 1 CHECK (lease_fence > 0),
    claimed_at TEXT NOT NULL CHECK (length(claimed_at) = 24),
    expires_at TEXT NOT NULL CHECK (length(expires_at) = 24),
    released_at TEXT CHECK (released_at IS NULL OR length(released_at) = 24),
    completed_at TEXT CHECK (completed_at IS NULL OR length(completed_at) = 24),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    CHECK (expires_at > claimed_at)
);
-- P06-CR-001: one ACTIVE lease per occurrence. Terminal leases are retained as
-- attempt history, so the uniqueness is partial.
CREATE UNIQUE INDEX ux_automation_leases_active
    ON automation_leases(occurrence_id) WHERE state = 'active';
CREATE UNIQUE INDEX ux_automation_leases_occurrence_attempt
    ON automation_leases(occurrence_id, attempt);
CREATE INDEX idx_automation_leases_expiry
    ON automation_leases(state, expires_at) WHERE state = 'active';

--------------------------------------------------------------------------------
-- Append-only attempt history (auditable "one logical occurrence")
--------------------------------------------------------------------------------
CREATE TABLE automation_occurrence_attempts (
    attempt_id TEXT PRIMARY KEY CHECK (length(attempt_id) = 36),
    occurrence_id TEXT NOT NULL REFERENCES automation_occurrences(occurrence_id) ON DELETE RESTRICT,
    lease_id TEXT REFERENCES automation_leases(lease_id) ON DELETE RESTRICT,
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    outcome TEXT NOT NULL CHECK (
        outcome IN ('claimed', 'started', 'succeeded', 'failed', 'cancelled',
                    'released', 'expired', 'ambiguous', 'skipped')
    ),
    run_id TEXT,
    reason_code TEXT CHECK (reason_code IS NULL OR length(reason_code) <= 96),
    lease_version INTEGER CHECK (lease_version IS NULL OR lease_version > 0),
    lease_fence INTEGER CHECK (lease_fence IS NULL OR lease_fence > 0),
    recorded_at TEXT NOT NULL CHECK (length(recorded_at) = 24)
);
CREATE UNIQUE INDEX ux_automation_occurrence_attempts
    ON automation_occurrence_attempts(occurrence_id, attempt, outcome);
CREATE INDEX idx_automation_occurrence_attempts_occurrence
    ON automation_occurrence_attempts(occurrence_id, recorded_at);

--------------------------------------------------------------------------------
-- Additive P05 run correlation. P06 does NOT add a parallel run lifecycle:
-- P05 `runs` remains the sole execution state machine.
--------------------------------------------------------------------------------
ALTER TABLE runs ADD COLUMN automation_occurrence_id TEXT;
ALTER TABLE runs ADD COLUMN automation_lease_id TEXT;
CREATE INDEX idx_runs_automation_occurrence ON runs(automation_occurrence_id);

CREATE TABLE automation_run_links (
    link_id TEXT PRIMARY KEY CHECK (length(link_id) = 36),
    occurrence_id TEXT NOT NULL REFERENCES automation_occurrences(occurrence_id) ON DELETE RESTRICT,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,
    lease_id TEXT NOT NULL REFERENCES automation_leases(lease_id) ON DELETE RESTRICT,
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    state TEXT NOT NULL DEFAULT 'linked'
        CHECK (state IN ('linked', 'started', 'settled', 'ambiguous')),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
-- P06-CR-001: one P05 run link per (occurrence, attempt). A pre-start expiry may
-- create a later attempt; a started/ambiguous occurrence is never reissued.
CREATE UNIQUE INDEX ux_automation_run_links_occurrence_attempt
    ON automation_run_links(occurrence_id, attempt);
CREATE UNIQUE INDEX ux_automation_run_links_run ON automation_run_links(run_id);
CREATE INDEX idx_automation_run_links_lease ON automation_run_links(lease_id);
