-- P04 model catalog, encrypted credential metadata, immutable routes, and
-- inference accounting. Plaintext secrets are never stored in this schema.
-- The migration runner owns the migration ledger; rollback is a forward fix.

CREATE TABLE providers (
    provider_id TEXT PRIMARY KEY CHECK (
        length(provider_id) = 36 AND substr(provider_id, 1, 4) = 'prv_'
    ),
    org_id TEXT REFERENCES organizations(org_id) ON DELETE CASCADE,
    provider_key TEXT NOT NULL CHECK (
        length(provider_key) BETWEEN 1 AND 64
        AND provider_key = lower(trim(provider_key))
        AND provider_key NOT GLOB '*[^a-z0-9._-]*'
    ),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 160),
    adapter TEXT NOT NULL CHECK (adapter IN ('openai_compatible', 'anthropic', 'mock')),
    lifecycle TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active', 'deprecated', 'disabled')),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by_user_id TEXT REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);

CREATE UNIQUE INDEX ux_providers_platform_key
    ON providers(provider_key) WHERE org_id IS NULL;
CREATE UNIQUE INDEX ux_providers_org_key
    ON providers(org_id, provider_key) WHERE org_id IS NOT NULL;
CREATE INDEX idx_providers_org_lifecycle
    ON providers(org_id, lifecycle, provider_id);

CREATE TABLE provider_endpoints (
    endpoint_id TEXT PRIMARY KEY CHECK (
        length(endpoint_id) = 35 AND substr(endpoint_id, 1, 3) = 'pe_'
    ),
    provider_id TEXT NOT NULL REFERENCES providers(provider_id) ON DELETE CASCADE,
    endpoint_url TEXT NOT NULL CHECK (length(endpoint_url) BETWEEN 1 AND 2048),
    lifecycle TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active', 'deprecated', 'disabled')),
    is_default INTEGER NOT NULL DEFAULT 1 CHECK (is_default IN (0, 1)),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);

CREATE UNIQUE INDEX ux_provider_endpoints_default
    ON provider_endpoints(provider_id) WHERE is_default = 1;
CREATE INDEX idx_provider_endpoints_provider
    ON provider_endpoints(provider_id, lifecycle);

CREATE TABLE models (
    model_id TEXT PRIMARY KEY CHECK (
        length(model_id) = 36 AND substr(model_id, 1, 4) = 'mdl_'
    ),
    provider_id TEXT NOT NULL REFERENCES providers(provider_id) ON DELETE CASCADE,
    provider_model_id TEXT NOT NULL CHECK (length(provider_model_id) BETWEEN 1 AND 255),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 160),
    capabilities_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(capabilities_json)),
    max_input_tokens INTEGER CHECK (max_input_tokens IS NULL OR max_input_tokens > 0),
    max_output_tokens INTEGER CHECK (max_output_tokens IS NULL OR max_output_tokens > 0),
    lifecycle TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active', 'deprecated', 'disabled')),
    pricing_version TEXT,
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by_user_id TEXT REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    UNIQUE(provider_id, provider_model_id)
);

CREATE INDEX idx_models_provider_lifecycle ON models(provider_id, lifecycle, model_id);

CREATE TABLE model_aliases (
    alias_id TEXT PRIMARY KEY CHECK (
        length(alias_id) = 36 AND substr(alias_id, 1, 4) = 'mal_'
    ),
    alias_key TEXT NOT NULL UNIQUE CHECK (
        length(alias_key) BETWEEN 1 AND 96
        AND alias_key = lower(trim(alias_key))
        AND alias_key NOT GLOB '*[^a-z0-9._-]*'
    ),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 160),
    lifecycle TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active', 'deprecated', 'disabled')),
    description TEXT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);

CREATE TABLE org_model_policies (
    org_id TEXT PRIMARY KEY REFERENCES organizations(org_id) ON DELETE CASCADE,
    policy_version INTEGER NOT NULL DEFAULT 1 CHECK (policy_version > 0),
    allowed_aliases_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(allowed_aliases_json)),
    allowed_models_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(allowed_models_json)),
    allowed_providers_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(allowed_providers_json)),
    credential_mode TEXT NOT NULL DEFAULT 'platform_or_organization' CHECK (
        credential_mode IN (
            'platform_only', 'organization_only', 'user_allowed',
            'platform_or_organization', 'local_direct', 'ordered_fallback'
        )
    ),
    managed_route_enabled INTEGER NOT NULL DEFAULT 1 CHECK (managed_route_enabled IN (0, 1)),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);

CREATE TABLE credentials (
    credential_id TEXT PRIMARY KEY CHECK (
        length(credential_id) = 37 AND substr(credential_id, 1, 5) = 'cred_'
    ),
    org_id TEXT REFERENCES organizations(org_id) ON DELETE CASCADE,
    owner_type TEXT NOT NULL CHECK (owner_type IN ('platform', 'organization', 'user', 'service_account', 'local_only')),
    owner_user_id TEXT REFERENCES users(user_id) ON DELETE SET NULL,
    provider_id TEXT NOT NULL REFERENCES providers(provider_id) ON DELETE RESTRICT,
    label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 120),
    ciphertext TEXT,
    nonce TEXT,
    key_version TEXT,
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) BETWEEN 4 AND 128),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'rotating', 'revoked')),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    parent_credential_id TEXT REFERENCES credentials(credential_id) ON DELETE SET NULL,
    created_by_user_id TEXT REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    last_used_at TEXT,
    CHECK (
        (owner_type = 'local_only' AND ciphertext IS NULL AND nonce IS NULL AND key_version IS NULL)
        OR
        (owner_type <> 'local_only' AND ciphertext IS NOT NULL AND nonce IS NOT NULL AND key_version IS NOT NULL)
    ),
    CHECK (
        (owner_type IN ('platform', 'local_only') AND org_id IS NULL)
        OR (owner_type IN ('organization', 'user', 'service_account') AND org_id IS NOT NULL)
    ),
    CHECK (
        (owner_type IN ('user', 'service_account') AND owner_user_id IS NOT NULL)
        OR (owner_type NOT IN ('user', 'service_account') AND owner_user_id IS NULL)
    )
);

CREATE INDEX idx_credentials_org_provider_status
    ON credentials(org_id, provider_id, status, owner_type);
CREATE INDEX idx_credentials_owner
    ON credentials(owner_user_id, provider_id, status);

CREATE TABLE routes (
    route_id TEXT PRIMARY KEY CHECK (
        length(route_id) = 36 AND substr(route_id, 1, 4) = 'rte_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    alias TEXT NOT NULL CHECK (
        length(alias) BETWEEN 1 AND 96
        AND alias = lower(trim(alias))
        AND alias NOT GLOB '*[^a-z0-9._-]*'
    ),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 160),
    strategy TEXT NOT NULL CHECK (strategy IN ('fixed', 'ordered_fallback', 'weighted_health_aware')),
    lifecycle TEXT NOT NULL DEFAULT 'draft' CHECK (lifecycle IN ('draft', 'published', 'disabled')),
    active_version_id TEXT,
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    UNIQUE(org_id, alias),
    UNIQUE(org_id, route_id)
);

CREATE INDEX idx_routes_org_lifecycle ON routes(org_id, lifecycle, alias);

CREATE TABLE route_versions (
    route_version_id TEXT PRIMARY KEY CHECK (
        length(route_version_id) = 36 AND substr(route_version_id, 1, 4) = 'rtv_'
    ),
    route_id TEXT NOT NULL REFERENCES routes(route_id) ON DELETE CASCADE,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL CHECK (version_number > 0),
    config_json TEXT NOT NULL CHECK (json_valid(config_json)),
    config_hash TEXT NOT NULL CHECK (length(config_hash) BETWEEN 64 AND 128),
    created_by_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    published_at TEXT,
    UNIQUE(route_id, version_number),
    FOREIGN KEY (org_id, route_id) REFERENCES routes(org_id, route_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX ux_route_versions_active_candidate
    ON route_versions(route_id, config_hash) WHERE published_at IS NOT NULL;
CREATE INDEX idx_route_versions_route_time
    ON route_versions(org_id, route_id, version_number DESC);

CREATE TRIGGER route_versions_no_update
BEFORE UPDATE ON route_versions
BEGIN
    SELECT RAISE(ABORT, 'route versions are immutable');
END;

CREATE TRIGGER route_versions_no_delete
BEFORE DELETE ON route_versions
BEGIN
    SELECT RAISE(ABORT, 'route versions are immutable');
END;

CREATE TABLE provider_health (
    provider_id TEXT NOT NULL REFERENCES providers(provider_id) ON DELETE CASCADE,
    org_id TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'ready' CHECK (state IN ('ready', 'degraded', 'cooldown')),
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    cooldown_until TEXT,
    last_success_at TEXT,
    last_failure_at TEXT,
    last_error_code TEXT,
    success_count INTEGER NOT NULL DEFAULT 0 CHECK (success_count >= 0),
    failure_count INTEGER NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    timeout_count INTEGER NOT NULL DEFAULT 0 CHECK (timeout_count >= 0),
    rate_limit_count INTEGER NOT NULL DEFAULT 0 CHECK (rate_limit_count >= 0),
    sample_count INTEGER NOT NULL DEFAULT 0 CHECK (sample_count >= 0),
    ttft_ms_total INTEGER NOT NULL DEFAULT 0 CHECK (ttft_ms_total >= 0),
    completion_latency_ms_total INTEGER NOT NULL DEFAULT 0 CHECK (completion_latency_ms_total >= 0),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    PRIMARY KEY(provider_id, org_id)
);

CREATE INDEX idx_provider_health_selection
    ON provider_health(org_id, provider_id, state, cooldown_until);

CREATE TABLE inference_requests (
    request_id TEXT PRIMARY KEY CHECK (
        length(request_id) = 36 AND substr(request_id, 1, 4) = 'req_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE RESTRICT,
    project_id TEXT,
    run_id TEXT,
    principal_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    session_id TEXT REFERENCES login_sessions(session_id) ON DELETE SET NULL,
    device_id TEXT,
    model_alias TEXT NOT NULL,
    route_id TEXT NOT NULL REFERENCES routes(route_id) ON DELETE RESTRICT,
    route_version_id TEXT NOT NULL REFERENCES route_versions(route_version_id) ON DELETE RESTRICT,
    provider_id TEXT,
    model_id TEXT,
    credential_id TEXT,
    response_state TEXT NOT NULL DEFAULT 'not_dispatched' CHECK (
        response_state IN ('not_dispatched', 'dispatched_no_output', 'stream_committed', 'completed', 'failed')
    ),
    fallback_count INTEGER NOT NULL DEFAULT 0 CHECK (fallback_count >= 0),
    started_at TEXT NOT NULL CHECK (length(started_at) = 24),
    first_output_at TEXT,
    completed_at TEXT,
    error_code TEXT,
    CHECK ((response_state = 'completed' AND completed_at IS NOT NULL) OR response_state <> 'completed')
);

CREATE INDEX idx_inference_requests_org_time
    ON inference_requests(org_id, started_at DESC, request_id);
CREATE INDEX idx_inference_requests_state
    ON inference_requests(response_state, started_at);

CREATE TABLE usage_events (
    usage_event_id TEXT PRIMARY KEY CHECK (
        length(usage_event_id) = 36 AND substr(usage_event_id, 1, 4) = 'use_'
    ),
    request_id TEXT NOT NULL UNIQUE REFERENCES inference_requests(request_id) ON DELETE RESTRICT,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE RESTRICT,
    project_id TEXT,
    run_id TEXT,
    principal_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    session_id TEXT,
    device_id TEXT,
    model_alias TEXT NOT NULL,
    route_version_id TEXT NOT NULL REFERENCES route_versions(route_version_id) ON DELETE RESTRICT,
    provider_id TEXT NOT NULL REFERENCES providers(provider_id) ON DELETE RESTRICT,
    model_id TEXT NOT NULL REFERENCES models(model_id) ON DELETE RESTRICT,
    credential_id TEXT,
    input_tokens INTEGER,
    output_tokens INTEGER,
    cached_tokens INTEGER,
    provider_usage_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(provider_usage_json)),
    estimated_cost_minor INTEGER,
    actual_cost_minor INTEGER,
    currency TEXT,
    pricing_version TEXT,
    budget_decision TEXT NOT NULL,
    ttft_ms INTEGER,
    total_latency_ms INTEGER,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    CHECK (input_tokens IS NULL OR input_tokens >= 0),
    CHECK (output_tokens IS NULL OR output_tokens >= 0),
    CHECK (cached_tokens IS NULL OR cached_tokens >= 0),
    CHECK (estimated_cost_minor IS NULL OR estimated_cost_minor >= 0),
    CHECK (actual_cost_minor IS NULL OR actual_cost_minor >= 0)
);

CREATE INDEX idx_usage_events_org_time ON usage_events(org_id, created_at DESC, request_id);
CREATE INDEX idx_usage_events_principal_time ON usage_events(principal_user_id, created_at DESC);

CREATE TRIGGER usage_events_no_update
BEFORE UPDATE ON usage_events
BEGIN
    SELECT RAISE(ABORT, 'usage events are immutable');
END;

CREATE TRIGGER usage_events_no_delete
BEFORE DELETE ON usage_events
BEGIN
    SELECT RAISE(ABORT, 'usage events are immutable');
END;

CREATE TABLE budgets (
    budget_id TEXT PRIMARY KEY CHECK (
        length(budget_id) = 36 AND substr(budget_id, 1, 4) = 'bud_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('organization', 'project', 'user', 'service_account', 'model_alias')),
    scope_id TEXT,
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    limit_minor INTEGER NOT NULL CHECK (limit_minor >= 0),
    hard INTEGER NOT NULL DEFAULT 1 CHECK (hard IN (0, 1)),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(org_id, scope_type, scope_id, period_start, period_end)
);

CREATE INDEX idx_budgets_scope ON budgets(org_id, scope_type, scope_id, period_end);

CREATE TABLE budget_reservations (
    reservation_id TEXT PRIMARY KEY CHECK (
        length(reservation_id) = 36 AND substr(reservation_id, 1, 4) = 'bud_'
    ),
    request_id TEXT NOT NULL UNIQUE REFERENCES inference_requests(request_id) ON DELETE RESTRICT,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE RESTRICT,
    reserved_minor INTEGER NOT NULL CHECK (reserved_minor >= 0),
    committed_minor INTEGER,
    status TEXT NOT NULL DEFAULT 'reserved' CHECK (status IN ('reserved', 'committed', 'released', 'expired')),
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_budget_reservations_expiry ON budget_reservations(status, expires_at);

-- Development fixtures are deliberately provider-neutral mock endpoints. The
-- adapter is rejected in production; the rows make local streaming/fallback
-- tests deterministic without any real vendor credential.
INSERT INTO providers (
    provider_id, org_id, provider_key, display_name, adapter, lifecycle,
    version, created_by_user_id, created_at, updated_at
) VALUES
    ('prv_00000000000000000000000000000001', NULL, 'mock-fail', 'Mock failing provider', 'mock', 'active', 1, NULL, '2026-09-24T00:00:00.000Z', '2026-09-24T00:00:00.000Z'),
    ('prv_00000000000000000000000000000002', NULL, 'mock-success', 'Mock success provider', 'mock', 'active', 1, NULL, '2026-09-24T00:00:00.000Z', '2026-09-24T00:00:00.000Z'),
    ('prv_00000000000000000000000000000003', NULL, 'mock-post-output-failure', 'Mock post-output failing provider', 'mock', 'active', 1, NULL, '2026-09-24T00:00:00.000Z', '2026-09-24T00:00:00.000Z'),
    ('prv_00000000000000000000000000000004', NULL, 'mock-timeout', 'Mock timeout provider', 'mock', 'active', 1, NULL, '2026-09-24T00:00:00.000Z', '2026-09-24T00:00:00.000Z');

INSERT INTO provider_endpoints (
    endpoint_id, provider_id, endpoint_url, lifecycle, is_default, created_at, updated_at
) VALUES
    ('pe_00000000000000000000000000000001', 'prv_00000000000000000000000000000001', 'mock://lumi-fail', 'active', 1, '2026-09-24T00:00:00.000Z', '2026-09-24T00:00:00.000Z'),
    ('pe_00000000000000000000000000000002', 'prv_00000000000000000000000000000002', 'mock://lumi-success', 'active', 1, '2026-09-24T00:00:00.000Z', '2026-09-24T00:00:00.000Z'),
    ('pe_00000000000000000000000000000003', 'prv_00000000000000000000000000000003', 'mock://lumi-post-output-failure', 'active', 1, '2026-09-24T00:00:00.000Z', '2026-09-24T00:00:00.000Z'),
    ('pe_00000000000000000000000000000004', 'prv_00000000000000000000000000000004', 'mock://lumi-timeout', 'active', 1, '2026-09-24T00:00:00.000Z', '2026-09-24T00:00:00.000Z');

INSERT INTO models (
    model_id, provider_id, provider_model_id, display_name, capabilities_json,
    max_input_tokens, max_output_tokens, lifecycle, pricing_version, version,
    created_by_user_id, created_at, updated_at
) VALUES
    ('mdl_00000000000000000000000000000001', 'prv_00000000000000000000000000000001', 'mock-fail', 'Mock failing model', '["text"]', 8000, 2000, 'active', 'mock-v1', 1, NULL, '2026-09-24T00:00:00.000Z', '2026-09-24T00:00:00.000Z'),
    ('mdl_00000000000000000000000000000002', 'prv_00000000000000000000000000000002', 'mock-success', 'Mock success model', '["text","tools"]', 8000, 2000, 'active', 'mock-v1', 1, NULL, '2026-09-24T00:00:00.000Z', '2026-09-24T00:00:00.000Z'),
    ('mdl_00000000000000000000000000000003', 'prv_00000000000000000000000000000003', 'mock-post-output-failure', 'Mock post-output failing model', '["text"]', 8000, 2000, 'active', 'mock-v1', 1, NULL, '2026-09-24T00:00:00.000Z', '2026-09-24T00:00:00.000Z'),
    ('mdl_00000000000000000000000000000004', 'prv_00000000000000000000000000000004', 'mock-timeout', 'Mock timeout model', '["text"]', 8000, 2000, 'active', 'mock-v1', 1, NULL, '2026-09-24T00:00:00.000Z', '2026-09-24T00:00:00.000Z');

INSERT INTO model_aliases (alias_id, alias_key, display_name, lifecycle, description, created_at, updated_at)
VALUES
    ('mal_00000000000000000000000000000001', 'coding-default', 'Coding default', 'active', 'Stable default coding route.', '2026-09-24T00:00:00.000Z', '2026-09-24T00:00:00.000Z'),
    ('mal_00000000000000000000000000000002', 'coding-fast', 'Coding fast', 'active', 'Stable fast coding route.', '2026-09-24T00:00:00.000Z', '2026-09-24T00:00:00.000Z'),
    ('mal_00000000000000000000000000000003', 'post-output-failure', 'Post-output failure', 'active', 'Development fixture for the no-fallback commitment boundary.', '2026-09-24T00:00:00.000Z', '2026-09-24T00:00:00.000Z');
