-- 0010_p05_runs_tools_usage_control.sql — P05 managed run timeline,
-- tool/policy/approval state, usage reconciliation, and budget/rate controls.
-- Forward-only; apply after 0009_p04_ai_platform.sql. No prompt, response,
-- credential, or secret material is stored in this schema.

CREATE TABLE agent_definitions (
    agent_definition_id TEXT PRIMARY KEY CHECK (
        length(agent_definition_id) = 36 AND substr(agent_definition_id, 1, 4) = 'agd_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    project_id TEXT REFERENCES projects(project_id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 160),
    description TEXT CHECK (description IS NULL OR length(description) <= 2000),
    instructions_ref TEXT CHECK (instructions_ref IS NULL OR length(instructions_ref) <= 2048),
    default_model_alias TEXT,
    required_capabilities_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(required_capabilities_json)),
    allowed_tool_ids_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(allowed_tool_ids_json)),
    runtime_requirements_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(runtime_requirements_json)),
    lifecycle TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active', 'archived', 'disabled')),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
CREATE INDEX idx_agent_definitions_org_project
    ON agent_definitions(org_id, project_id, lifecycle, updated_at);
CREATE UNIQUE INDEX ux_agent_definitions_org_project_name
    ON agent_definitions(org_id, COALESCE(project_id, ''), name)
    WHERE lifecycle <> 'disabled';

CREATE TABLE agent_sessions (
    agent_session_id TEXT PRIMARY KEY CHECK (
        length(agent_session_id) = 36 AND substr(agent_session_id, 1, 4) = 'rse_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE RESTRICT,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    workspace_binding_id TEXT REFERENCES workspace_bindings(binding_id) ON DELETE SET NULL,
    agent_definition_id TEXT NOT NULL REFERENCES agent_definitions(agent_definition_id) ON DELETE RESTRICT,
    agent_definition_version INTEGER NOT NULL CHECK (agent_definition_version > 0),
    external_id TEXT,
    title TEXT CHECK (title IS NULL OR length(title) <= 200),
    lifecycle TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active', 'closed', 'archived')),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
CREATE INDEX idx_agent_sessions_org_project
    ON agent_sessions(org_id, project_id, lifecycle, updated_at);
CREATE UNIQUE INDEX ux_agent_sessions_external
    ON agent_sessions(org_id, device_id, external_id)
    WHERE external_id IS NOT NULL;

CREATE TABLE runs (
    run_id TEXT PRIMARY KEY CHECK (
        length(run_id) = 36 AND substr(run_id, 1, 4) = 'run_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE RESTRICT,
    agent_session_id TEXT NOT NULL REFERENCES agent_sessions(agent_session_id) ON DELETE RESTRICT,
    parent_run_id TEXT REFERENCES runs(run_id) ON DELETE RESTRICT,
    resumed_from_run_id TEXT REFERENCES runs(run_id) ON DELETE RESTRICT,
    workspace_binding_id TEXT REFERENCES workspace_bindings(binding_id) ON DELETE RESTRICT,
    policy_snapshot_id TEXT REFERENCES policy_snapshots(policy_id) ON DELETE RESTRICT,
    policy_version INTEGER CHECK (policy_version IS NULL OR policy_version > 0),
    cancel_requested_at TEXT,
    attempt INTEGER NOT NULL DEFAULT 1 CHECK (attempt > 0),
    agent_definition_id TEXT NOT NULL REFERENCES agent_definitions(agent_definition_id) ON DELETE RESTRICT,
    agent_definition_version INTEGER NOT NULL CHECK (agent_definition_version > 0),
    principal_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    model_alias TEXT,
    route_id TEXT REFERENCES routes(route_id) ON DELETE RESTRICT,
    route_version_id TEXT REFERENCES route_versions(route_version_id) ON DELETE RESTRICT,
    state TEXT NOT NULL DEFAULT 'queued' CHECK (
        state IN ('queued', 'dispatching', 'running', 'waiting_user', 'waiting_approval',
                  'succeeded', 'failed', 'cancelled', 'timed_out')
    ),
    state_version INTEGER NOT NULL DEFAULT 1 CHECK (state_version > 0),
    failure_code TEXT CHECK (failure_code IS NULL OR length(failure_code) <= 96),
    request_id TEXT,
    started_at TEXT,
    finished_at TEXT,
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    CHECK ((parent_run_id IS NULL AND attempt = 1) OR (parent_run_id IS NOT NULL AND attempt > 1)),
    CHECK ((state IN ('succeeded', 'failed', 'cancelled', 'timed_out') AND finished_at IS NOT NULL)
           OR (state NOT IN ('succeeded', 'failed', 'cancelled', 'timed_out') AND finished_at IS NULL))
);
CREATE INDEX idx_runs_org_project_state ON runs(org_id, project_id, state, created_at DESC);
CREATE INDEX idx_runs_session_time ON runs(agent_session_id, created_at DESC);
CREATE INDEX idx_runs_parent ON runs(parent_run_id, attempt);

CREATE TABLE run_events (
    run_event_id TEXT PRIMARY KEY CHECK (
        length(run_event_id) = 36 AND substr(run_event_id, 1, 4) = 'rev_'
    ),
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE RESTRICT,
    request_id TEXT NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    agent_session_id TEXT NOT NULL REFERENCES agent_sessions(agent_session_id) ON DELETE RESTRICT,
    schema_version INTEGER NOT NULL DEFAULT 1 CHECK (schema_version > 0),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 96),
    occurred_at TEXT NOT NULL CHECK (length(occurred_at) = 24),
    recorded_at TEXT NOT NULL CHECK (length(recorded_at) = 24),
    actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'device', 'service_account', 'system')),
    actor_id TEXT,
    correlation_id TEXT NOT NULL,
    tool_call_id TEXT,
    approval_id TEXT,
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK (
        json_valid(payload_json) AND length(payload_json) <= 32768
    ),
    UNIQUE(run_id, sequence)
);
CREATE INDEX idx_run_events_run_time ON run_events(run_id, sequence);
CREATE INDEX idx_run_events_type_time ON run_events(event_type, occurred_at DESC);
CREATE TRIGGER run_events_no_update BEFORE UPDATE ON run_events
BEGIN
    SELECT RAISE(ABORT, 'run events are immutable');
END;
CREATE TRIGGER run_events_no_delete BEFORE DELETE ON run_events
BEGIN
    SELECT RAISE(ABORT, 'run events are immutable');
END;

CREATE TABLE artifact_refs (
    artifact_ref_id TEXT PRIMARY KEY CHECK (
        length(artifact_ref_id) = 36 AND substr(artifact_ref_id, 1, 4) = 'art_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,
    kind TEXT NOT NULL CHECK (kind IN ('local_only', 'cloud_uploaded', 'external_link')),
    content_ref TEXT,
    mime_type TEXT CHECK (mime_type IS NULL OR length(mime_type) <= 160),
    size_bytes INTEGER CHECK (size_bytes IS NULL OR size_bytes >= 0),
    checksum TEXT CHECK (checksum IS NULL OR length(checksum) <= 256),
    retention_policy TEXT NOT NULL DEFAULT 'organization_default',
    created_by_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    CHECK ((kind = 'local_only' AND content_ref IS NULL) OR (kind <> 'local_only' AND content_ref IS NOT NULL))
);
CREATE INDEX idx_artifact_refs_run ON artifact_refs(run_id, created_at);

CREATE TABLE tool_call_refs (
    tool_call_id TEXT PRIMARY KEY CHECK (
        length(tool_call_id) = 37 AND substr(tool_call_id, 1, 5) = 'tcl_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,
    tool_id TEXT NOT NULL,
    tool_fingerprint TEXT NOT NULL CHECK (length(tool_fingerprint) BETWEEN 4 AND 256),
    risk_class TEXT NOT NULL,
    arguments_summary TEXT NOT NULL CHECK (length(arguments_summary) <= 2048),
    status TEXT NOT NULL DEFAULT 'requested' CHECK (status IN ('requested', 'allowed', 'denied', 'completed', 'failed', 'cancelled')),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
CREATE INDEX idx_tool_call_refs_run ON tool_call_refs(run_id, created_at);
CREATE UNIQUE INDEX ux_tool_call_refs_run_call ON tool_call_refs(run_id, tool_call_id);

CREATE TABLE capability_definitions (
    capability_id TEXT PRIMARY KEY CHECK (
        length(capability_id) = 36 AND substr(capability_id, 1, 4) = 'cap_'
    ),
    org_id TEXT REFERENCES organizations(org_id) ON DELETE CASCADE,
    capability_key TEXT NOT NULL CHECK (
        length(capability_key) BETWEEN 1 AND 96
        AND capability_key = lower(trim(capability_key))
        AND capability_key NOT GLOB '*[^a-z0-9._-]*'
    ),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 160),
    risk_class TEXT NOT NULL CHECK (
        risk_class IN ('read_only', 'filesystem_write', 'process_execution', 'network', 'mcp',
                       'browser', 'computer', 'credential_bearing', 'external_side_effect', 'destructive')
    ),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
CREATE UNIQUE INDEX ux_capability_definitions_platform_key
    ON capability_definitions(capability_key) WHERE org_id IS NULL;
CREATE UNIQUE INDEX ux_capability_definitions_org_key
    ON capability_definitions(org_id, capability_key) WHERE org_id IS NOT NULL;

CREATE TABLE tool_definitions (
    tool_id TEXT PRIMARY KEY CHECK (
        length(tool_id) = 37 AND substr(tool_id, 1, 5) = 'tool_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 160),
    source TEXT NOT NULL CHECK (source IN ('built_in', 'plugin', 'custom')),
    risk_class TEXT NOT NULL CHECK (
        risk_class IN ('read_only', 'filesystem_write', 'process_execution', 'network', 'mcp',
                       'browser', 'computer', 'credential_bearing', 'external_side_effect', 'destructive')
    ),
    capability_ids_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(capability_ids_json)),
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) BETWEEN 4 AND 256),
    lifecycle TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active', 'review', 'disabled')),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
CREATE INDEX idx_tool_definitions_org_state ON tool_definitions(org_id, lifecycle, updated_at);
CREATE UNIQUE INDEX ux_tool_definitions_org_fingerprint ON tool_definitions(org_id, fingerprint);

CREATE TABLE mcp_registrations (
    mcp_registration_id TEXT PRIMARY KEY CHECK (
        length(mcp_registration_id) = 36 AND substr(mcp_registration_id, 1, 4) = 'mcp_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    source TEXT NOT NULL CHECK (source IN ('built_in', 'plugin', 'custom')),
    transport TEXT NOT NULL CHECK (transport IN ('http', 'sse', 'stdio', 'other')),
    endpoint_metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(endpoint_metadata_json)),
    command_metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(command_metadata_json)),
    allowed_origins_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(allowed_origins_json)),
    required_secret_handles_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(required_secret_handles_json)),
    tool_fingerprint TEXT,
    tool_list_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(tool_list_json)),
    policy_status TEXT NOT NULL DEFAULT 'pending_review' CHECK (policy_status IN ('approved', 'pending_review', 'denied', 'disabled')),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
CREATE INDEX idx_mcp_registrations_org_state ON mcp_registrations(org_id, policy_status, updated_at);

CREATE TABLE tool_policies (
    tool_policy_id TEXT PRIMARY KEY CHECK (
        length(tool_policy_id) = 37 AND substr(tool_policy_id, 1, 5) = 'tpol_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    project_id TEXT REFERENCES projects(project_id) ON DELETE CASCADE,
    policy_version INTEGER NOT NULL DEFAULT 1 CHECK (policy_version > 0),
    document_json TEXT NOT NULL CHECK (json_valid(document_json) AND length(document_json) <= 65536),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
CREATE UNIQUE INDEX ux_tool_policies_scope ON tool_policies(org_id, COALESCE(project_id, ''));

CREATE TABLE approval_requests (
    approval_id TEXT PRIMARY KEY CHECK (
        length(approval_id) = 36 AND substr(approval_id, 1, 4) = 'apr_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,
    agent_session_id TEXT NOT NULL REFERENCES agent_sessions(agent_session_id) ON DELETE RESTRICT,
    tool_call_id TEXT NOT NULL REFERENCES tool_call_refs(tool_call_id) ON DELETE RESTRICT,
    tool_id TEXT NOT NULL,
    tool_fingerprint TEXT NOT NULL CHECK (length(tool_fingerprint) BETWEEN 4 AND 256),
    arguments_hash TEXT NOT NULL CHECK (length(arguments_hash) BETWEEN 32 AND 128),
    policy_snapshot_id TEXT REFERENCES policy_snapshots(policy_id) ON DELETE RESTRICT,
    policy_version INTEGER CHECK (policy_version IS NULL OR policy_version > 0),
    requested_by_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    risk_class TEXT NOT NULL,
    approval_mode TEXT NOT NULL CHECK (approval_mode IN ('session', 'per_use')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'cancelled')),
    decision TEXT CHECK (decision IS NULL OR decision IN ('approved', 'denied')),
    arguments_summary TEXT NOT NULL CHECK (length(arguments_summary) <= 2048),
    requested_by_principal_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    requested_at TEXT NOT NULL CHECK (length(requested_at) = 24),
    expires_at TEXT NOT NULL CHECK (length(expires_at) = 24),
    resolved_by_principal_id TEXT REFERENCES users(user_id) ON DELETE RESTRICT,
    resolved_at TEXT,
    resolution_reason TEXT,
    consumed_at TEXT,
    consumed_by_device_id TEXT REFERENCES devices(device_id) ON DELETE RESTRICT,
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    UNIQUE(run_id, tool_call_id),
    CHECK ((status = 'pending' AND resolved_by_principal_id IS NULL AND resolved_at IS NULL)
           OR (status <> 'pending' AND resolved_by_principal_id IS NOT NULL AND resolved_at IS NOT NULL))
);
CREATE INDEX idx_approval_requests_org_status ON approval_requests(org_id, status, requested_at DESC);
CREATE INDEX idx_approval_requests_run ON approval_requests(run_id, status);

CREATE TABLE cost_records (
    cost_record_id TEXT PRIMARY KEY CHECK (
        length(cost_record_id) = 37 AND substr(cost_record_id, 1, 5) = 'cost_'
    ),
    usage_event_id TEXT NOT NULL REFERENCES usage_events(usage_event_id) ON DELETE RESTRICT,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE RESTRICT,
    project_id TEXT,
    run_id TEXT,
    pricing_source TEXT NOT NULL CHECK (length(pricing_source) BETWEEN 1 AND 128),
    pricing_version TEXT NOT NULL CHECK (length(pricing_version) BETWEEN 1 AND 128),
    pricing_effective_at TEXT NOT NULL CHECK (length(pricing_effective_at) = 24),
    calculation_kind TEXT NOT NULL CHECK (calculation_kind IN ('estimated', 'actual', 'recalculated')),
    input_tokens INTEGER CHECK (input_tokens IS NULL OR input_tokens >= 0),
    output_tokens INTEGER CHECK (output_tokens IS NULL OR output_tokens >= 0),
    cached_tokens INTEGER CHECK (cached_tokens IS NULL OR cached_tokens >= 0),
    cost_minor INTEGER NOT NULL CHECK (cost_minor >= 0),
    currency TEXT NOT NULL CHECK (length(currency) BETWEEN 3 AND 12),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24)
);
CREATE UNIQUE INDEX ux_cost_records_usage_kind ON cost_records(usage_event_id, calculation_kind, pricing_version);
CREATE INDEX idx_cost_records_org_time ON cost_records(org_id, created_at DESC);
CREATE TRIGGER cost_records_no_update BEFORE UPDATE ON cost_records
BEGIN
    SELECT RAISE(ABORT, 'cost records are immutable');
END;
CREATE TRIGGER cost_records_no_delete BEFORE DELETE ON cost_records
BEGIN
    SELECT RAISE(ABORT, 'cost records are immutable');
END;

CREATE TABLE usage_rollups (
    usage_rollup_id TEXT PRIMARY KEY CHECK (
        length(usage_rollup_id) = 36 AND substr(usage_rollup_id, 1, 4) = 'url_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    project_id TEXT,
    principal_user_id TEXT,
    model_alias TEXT,
    bucket_start TEXT NOT NULL CHECK (length(bucket_start) = 24),
    bucket_end TEXT NOT NULL CHECK (length(bucket_end) = 24),
    input_tokens INTEGER NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens INTEGER NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    cached_tokens INTEGER NOT NULL DEFAULT 0 CHECK (cached_tokens >= 0),
    cost_minor INTEGER NOT NULL DEFAULT 0 CHECK (cost_minor >= 0),
    usage_event_count INTEGER NOT NULL DEFAULT 0 CHECK (usage_event_count >= 0),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
CREATE UNIQUE INDEX ux_usage_rollups_scope_bucket
    ON usage_rollups(org_id, COALESCE(project_id, ''), COALESCE(principal_user_id, ''), COALESCE(model_alias, ''), bucket_start);
CREATE INDEX idx_usage_rollups_org_bucket ON usage_rollups(org_id, bucket_start DESC);

-- Non-inference run usage is an additive source projection. P04
-- usage_events remains the immutable request-scoped inference source.
CREATE TABLE run_usage_events (
    run_usage_event_id TEXT PRIMARY KEY CHECK (
        length(run_usage_event_id) = 36 AND substr(run_usage_event_id, 1, 4) = 'rue_'
    ),
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE RESTRICT,
    principal_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    model_alias TEXT,
    input_tokens INTEGER CHECK (input_tokens IS NULL OR input_tokens >= 0),
    output_tokens INTEGER CHECK (output_tokens IS NULL OR output_tokens >= 0),
    cached_tokens INTEGER CHECK (cached_tokens IS NULL OR cached_tokens >= 0),
    provider_usage_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(provider_usage_json)),
    estimated_cost_minor INTEGER CHECK (estimated_cost_minor IS NULL OR estimated_cost_minor >= 0),
    actual_cost_minor INTEGER CHECK (actual_cost_minor IS NULL OR actual_cost_minor >= 0),
    currency TEXT,
    pricing_version TEXT,
    reconciliation_status TEXT NOT NULL DEFAULT 'recorded' CHECK (reconciliation_status IN ('recorded', 'pending', 'reconciled', 'conflict')),
    external_id TEXT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24)
);
CREATE UNIQUE INDEX ux_run_usage_events_external ON run_usage_events(org_id, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX idx_run_usage_events_run_time ON run_usage_events(run_id, created_at DESC);
CREATE TRIGGER run_usage_events_no_update BEFORE UPDATE ON run_usage_events
BEGIN
    SELECT RAISE(ABORT, 'run usage events are immutable');
END;
CREATE TRIGGER run_usage_events_no_delete BEFORE DELETE ON run_usage_events
BEGIN
    SELECT RAISE(ABORT, 'run usage events are immutable');
END;

CREATE TABLE run_cost_records (
    run_cost_record_id TEXT PRIMARY KEY CHECK (
        length(run_cost_record_id) = 38 AND substr(run_cost_record_id, 1, 5) = 'rcost'
    ),
    run_usage_event_id TEXT NOT NULL REFERENCES run_usage_events(run_usage_event_id) ON DELETE RESTRICT,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,
    pricing_source TEXT NOT NULL CHECK (length(pricing_source) BETWEEN 1 AND 128),
    pricing_version TEXT NOT NULL CHECK (length(pricing_version) BETWEEN 1 AND 128),
    pricing_effective_at TEXT NOT NULL CHECK (length(pricing_effective_at) = 24),
    calculation_kind TEXT NOT NULL CHECK (calculation_kind IN ('estimated', 'actual', 'recalculated')),
    input_tokens INTEGER CHECK (input_tokens IS NULL OR input_tokens >= 0),
    output_tokens INTEGER CHECK (output_tokens IS NULL OR output_tokens >= 0),
    cached_tokens INTEGER CHECK (cached_tokens IS NULL OR cached_tokens >= 0),
    cost_minor INTEGER NOT NULL CHECK (cost_minor >= 0),
    currency TEXT NOT NULL CHECK (length(currency) BETWEEN 3 AND 12),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24)
);
CREATE UNIQUE INDEX ux_run_cost_records_usage_kind ON run_cost_records(run_usage_event_id, calculation_kind, pricing_version);
CREATE TRIGGER run_cost_records_no_update BEFORE UPDATE ON run_cost_records
BEGIN
    SELECT RAISE(ABORT, 'run cost records are immutable');
END;
CREATE TRIGGER run_cost_records_no_delete BEFORE DELETE ON run_cost_records
BEGIN
    SELECT RAISE(ABORT, 'run cost records are immutable');
END;

CREATE TABLE rate_limit_policies (
    rate_limit_policy_id TEXT PRIMARY KEY CHECK (
        length(rate_limit_policy_id) = 36 AND substr(rate_limit_policy_id, 1, 4) = 'rlp_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('organization', 'project', 'user', 'service_account', 'model_alias')),
    scope_id TEXT,
    requests_per_minute INTEGER CHECK (requests_per_minute IS NULL OR requests_per_minute > 0),
    tokens_per_minute INTEGER CHECK (tokens_per_minute IS NULL OR tokens_per_minute > 0),
    max_concurrent_requests INTEGER CHECK (max_concurrent_requests IS NULL OR max_concurrent_requests > 0),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
CREATE UNIQUE INDEX ux_rate_limit_policies_scope
    ON rate_limit_policies(org_id, scope_type, COALESCE(scope_id, ''));
CREATE INDEX idx_rate_limit_policies_org_scope ON rate_limit_policies(org_id, scope_type, scope_id);

-- P04 inference/usage rows remain canonical. These additive columns allow a
-- managed run to correlate the inference and preserve reconciliation state.
ALTER TABLE inference_requests ADD COLUMN agent_session_id TEXT;
ALTER TABLE inference_requests ADD COLUMN agent_definition_id TEXT;
ALTER TABLE inference_requests ADD COLUMN agent_definition_version INTEGER;
ALTER TABLE inference_requests ADD COLUMN source TEXT NOT NULL DEFAULT 'inference' CHECK (source IN ('inference', 'run'));
ALTER TABLE usage_events ADD COLUMN source TEXT NOT NULL DEFAULT 'inference' CHECK (source IN ('inference', 'run'));
ALTER TABLE usage_events ADD COLUMN external_id TEXT;
ALTER TABLE usage_events ADD COLUMN reconciliation_status TEXT NOT NULL DEFAULT 'recorded' CHECK (reconciliation_status IN ('recorded', 'pending', 'reconciled', 'conflict'));
ALTER TABLE budget_reservations ADD COLUMN run_id TEXT;
ALTER TABLE budget_reservations ADD COLUMN budget_id TEXT;
ALTER TABLE budget_reservations ADD COLUMN currency TEXT NOT NULL DEFAULT 'USD';
ALTER TABLE budget_reservations ADD COLUMN reconciled_at TEXT;
ALTER TABLE budget_reservations ADD COLUMN reconciliation_reason TEXT;
ALTER TABLE budgets ADD COLUMN currency TEXT NOT NULL DEFAULT 'USD';
ALTER TABLE security_events ADD COLUMN run_id TEXT;
ALTER TABLE security_events ADD COLUMN agent_session_id TEXT;
ALTER TABLE security_events ADD COLUMN tool_call_id TEXT;
CREATE INDEX idx_security_events_run ON security_events(org_id, run_id, created_at DESC);
CREATE INDEX idx_inference_requests_run_session ON inference_requests(run_id, agent_session_id);
CREATE INDEX idx_usage_events_run_source ON usage_events(run_id, source, created_at DESC);
CREATE INDEX idx_budget_reservations_run ON budget_reservations(run_id, status, expires_at);
