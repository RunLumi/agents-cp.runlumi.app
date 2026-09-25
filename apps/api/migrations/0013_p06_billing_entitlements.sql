-- 0013_p06_billing_entitlements.sql — P06 commercial plans, subscriptions,
-- entitlement definitions/grants, provider-entitlement projections, and the
-- short-lived signed license-snapshot metadata.
--
-- Forward-only; apply after 0012_p06_event_delivery.sql.
--
-- F18 / P06-CR-002: product logic consumes ONLY stable Lumi entitlement keys.
-- Payment-provider product/price IDs are adapter-private and are NEVER stored
-- in a public/product column, referenced by authorization, or used as a
-- feature gate. Provider account references are opaque adapter-private values.
--
-- F18: authorization permission, Lumi product entitlement, usage budget, and
-- upstream provider account entitlement remain FOUR DISTINCT decision inputs.
-- This schema stores commercial/entitlement state only; it is not an
-- authorization or usage-budget table.

--------------------------------------------------------------------------------
-- Versioned Lumi product plans (immutable versions)
--------------------------------------------------------------------------------
CREATE TABLE plans (
    plan_id TEXT PRIMARY KEY CHECK (
        length(plan_id) = 37 AND substr(plan_id, 1, 5) = 'plan_'
    ),
    -- Stable Lumi plan key, NOT a payment-provider product/price ID.
    plan_key TEXT NOT NULL CHECK (length(plan_key) BETWEEN 1 AND 64),
    version INTEGER NOT NULL CHECK (version > 0),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 160),
    description TEXT CHECK (description IS NULL OR length(description) <= 2000),
    seat_based INTEGER NOT NULL DEFAULT 0 CHECK (seat_based IN (0, 1)),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    UNIQUE (plan_key, version)
);
CREATE INDEX idx_plans_key ON plans(plan_key, version DESC);

--------------------------------------------------------------------------------
-- Immutable plan entitlement values
--------------------------------------------------------------------------------
CREATE TABLE plan_entitlements (
    plan_entitlement_id TEXT PRIMARY KEY CHECK (length(plan_entitlement_id) = 36),
    plan_id TEXT NOT NULL REFERENCES plans(plan_id) ON DELETE CASCADE,
    entitlement_key TEXT NOT NULL CHECK (length(entitlement_key) BETWEEN 1 AND 128),
    value_type TEXT NOT NULL CHECK (value_type IN ('boolean', 'integer', 'string')),
    value_json TEXT NOT NULL CHECK (json_valid(value_json) AND length(value_json) <= 1024),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    UNIQUE (plan_id, entitlement_key)
);
CREATE INDEX idx_plan_entitlements_key ON plan_entitlements(entitlement_key);

--------------------------------------------------------------------------------
-- Adapter-owned billing account (opaque provider refs only)
--------------------------------------------------------------------------------
CREATE TABLE billing_accounts (
    billing_account_id TEXT PRIMARY KEY CHECK (
        length(billing_account_id) = 36 AND substr(billing_account_id, 1, 4) = 'bac_'
    ),
    org_id TEXT NOT NULL UNIQUE REFERENCES organizations(org_id) ON DELETE CASCADE,
    -- Opaque adapter-private provider customer reference. NEVER a product/price
    -- ID and never exposed through a public product contract.
    provider_account_ref TEXT NOT NULL CHECK (length(provider_account_ref) BETWEEN 1 AND 255),
    provider_kind TEXT NOT NULL CHECK (length(provider_kind) BETWEEN 1 AND 64),
    status TEXT NOT NULL DEFAULT 'active' CHECK (
        status IN ('active', 'restricted', 'closed', 'unavailable')
    ),
    seat_policy TEXT NOT NULL DEFAULT 'per_active_member'
        CHECK (seat_policy IN ('per_active_member', 'flat', 'custom')),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);

--------------------------------------------------------------------------------
-- Upstream AI-provider entitlement projection (read-only, never Lumi state)
--------------------------------------------------------------------------------
CREATE TABLE provider_entitlement_projections (
    projection_id TEXT PRIMARY KEY CHECK (
        length(projection_id) = 36 AND substr(projection_id, 1, 4) = 'pep_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    provider_kind TEXT NOT NULL CHECK (length(provider_kind) BETWEEN 1 AND 64),
    capability_class TEXT NOT NULL DEFAULT 'provider_managed_inference'
        CHECK (length(capability_class) BETWEEN 1 AND 64),
    -- Normalized, provider-agnostic status. The public projection exposes only
    -- this status + reason; provider product/plan/price IDs are never exposed.
    status TEXT NOT NULL DEFAULT 'unknown'
        CHECK (status IN ('available', 'degraded', 'unavailable', 'unknown')),
    reason_code TEXT CHECK (reason_code IS NULL OR length(reason_code) <= 96),
    observed_at TEXT NOT NULL CHECK (length(observed_at) = 24),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    UNIQUE (org_id, provider_kind, capability_class)
);
CREATE INDEX idx_provider_entitlement_projections_org
    ON provider_entitlement_projections(org_id, status);

-- Provider sync bookkeeping: idempotency, ordering, and the last successful
-- sync that anchors the grace window. Raw provider payloads are never stored.
CREATE TABLE provider_sync_state (
    provider_sync_id TEXT PRIMARY KEY CHECK (length(provider_sync_id) = 36),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    provider_kind TEXT NOT NULL CHECK (length(provider_kind) BETWEEN 1 AND 64),
    last_event_id TEXT,
    last_event_version INTEGER CHECK (last_event_version IS NULL OR last_event_version > 0),
    last_event_at TEXT CHECK (last_event_at IS NULL OR length(last_event_at) = 24),
    -- Grace anchors to the last ACCEPTED transition / last SUCCESSFUL sync and is
    -- never extended by repeated failed polling.
    last_success_at TEXT CHECK (last_success_at IS NULL OR length(last_success_at) = 24),
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    last_error_code TEXT CHECK (last_error_code IS NULL OR length(last_error_code) <= 96),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    UNIQUE (org_id, provider_kind)
);

--------------------------------------------------------------------------------
-- Subscriptions (current state) and append-only provider event history
--------------------------------------------------------------------------------
CREATE TABLE subscriptions (
    subscription_id TEXT PRIMARY KEY CHECK (
        length(subscription_id) = 36 AND substr(subscription_id, 1, 4) = 'sub_'
    ),
    org_id TEXT NOT NULL UNIQUE REFERENCES organizations(org_id) ON DELETE RESTRICT,
    billing_account_id TEXT NOT NULL REFERENCES billing_accounts(billing_account_id) ON DELETE RESTRICT,
    plan_id TEXT NOT NULL REFERENCES plans(plan_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (
        status IN ('trialing', 'active', 'grace', 'past_due', 'suspended', 'cancelled')
    ),
    -- Opaque adapter-private provider subscription reference. Never a
    -- product/price ID in product logic.
    provider_subscription_ref TEXT CHECK (
        provider_subscription_ref IS NULL OR length(provider_subscription_ref) BETWEEN 1 AND 255
    ),
    -- Grace begins at the first accepted provider transition / last successful
    -- sync and is NOT extended by repeated failed polling.
    grace_started_at TEXT CHECK (grace_started_at IS NULL OR length(grace_started_at) = 24),
    grace_expires_at TEXT CHECK (grace_expires_at IS NULL OR length(grace_expires_at) = 24),
    current_period_starts_at TEXT CHECK (
        current_period_starts_at IS NULL OR length(current_period_starts_at) = 24
    ),
    current_period_ends_at TEXT CHECK (
        current_period_ends_at IS NULL OR length(current_period_ends_at) = 24
    ),
    cancel_at_period_end INTEGER NOT NULL DEFAULT 0 CHECK (cancel_at_period_end IN (0, 1)),
    cancelled_at TEXT CHECK (cancelled_at IS NULL OR length(cancelled_at) = 24),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    -- Terminal cancellation records a timestamp and never silently reactivates.
    CHECK (status <> 'cancelled' OR cancelled_at IS NOT NULL)
);
CREATE INDEX idx_subscriptions_status ON subscriptions(status, grace_expires_at);
CREATE INDEX idx_subscriptions_plan ON subscriptions(plan_id, status);

-- Append-only provider event history. A terminal subscription is superseded by a
-- NEW subscription row, so history is never rewritten.
CREATE TABLE subscription_events (
    subscription_event_id TEXT PRIMARY KEY CHECK (length(subscription_event_id) = 36),
    subscription_id TEXT NOT NULL REFERENCES subscriptions(subscription_id) ON DELETE RESTRICT,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE RESTRICT,
    -- Stable provider event ID makes provider callbacks idempotent.
    provider_event_id TEXT NOT NULL CHECK (length(provider_event_id) BETWEEN 1 AND 255),
    provider_version INTEGER CHECK (provider_version IS NULL OR provider_version > 0),
    from_status TEXT CHECK (from_status IS NULL OR length(from_status) <= 32),
    to_status TEXT NOT NULL CHECK (length(to_status) <= 32),
    effective_at TEXT NOT NULL CHECK (length(effective_at) = 24),
    received_at TEXT NOT NULL CHECK (length(received_at) = 24),
    -- Bounded metadata only. Raw provider payloads are never stored or logged.
    metadata_json TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(metadata_json) AND length(metadata_json) <= 4096)
);
CREATE UNIQUE INDEX ux_subscription_events_provider_event
    ON subscription_events(provider_event_id);
CREATE INDEX idx_subscription_events_subscription
    ON subscription_events(subscription_id, effective_at DESC);
CREATE INDEX idx_subscription_events_org ON subscription_events(org_id, received_at DESC);

--------------------------------------------------------------------------------
-- Stable Lumi entitlement definitions (never provider product/price IDs)
--------------------------------------------------------------------------------
CREATE TABLE entitlement_definitions (
    entitlement_definition_id TEXT PRIMARY KEY CHECK (
        length(entitlement_definition_id) = 36
        AND substr(entitlement_definition_id, 1, 4) = 'ent_'
    ),
    -- The public identity of an entitlement is its stable dotted Lumi key.
    entitlement_key TEXT NOT NULL UNIQUE CHECK (
        length(entitlement_key) BETWEEN 1 AND 128
        AND entitlement_key NOT LIKE '% %'
    ),
    value_type TEXT NOT NULL CHECK (value_type IN ('boolean', 'integer', 'string')),
    scope TEXT NOT NULL CHECK (scope IN ('platform', 'organization', 'project', 'user')),
    default_value_json TEXT CHECK (
        default_value_json IS NULL OR (json_valid(default_value_json) AND length(default_value_json) <= 1024)
    ),
    unit TEXT CHECK (unit IS NULL OR length(unit) <= 32),
    description TEXT CHECK (description IS NULL OR length(description) <= 2000),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);

-- Structural guard: a payment-provider product/price ID can never be a valid
-- Lumi entitlement key. Provider IDs are never lower-dotted keys of this shape.
CREATE TRIGGER trg_entitlement_definitions_no_provider_id
BEFORE INSERT ON entitlement_definitions
FOR EACH ROW WHEN NEW.entitlement_key GLOB '*[#$%&()*+,/:;<=>?@[]^`{|}~]*'
    OR NEW.entitlement_key LIKE 'prod_%'
    OR NEW.entitlement_key LIKE 'price_%'
    OR NEW.entitlement_key LIKE 'product_%'
BEGIN
    SELECT RAISE(ABORT, 'provider product/price id rejected as entitlement key');
END;

--------------------------------------------------------------------------------
-- Entitlement grants (plan-derived + internal expiring overrides)
--------------------------------------------------------------------------------
CREATE TABLE entitlement_grants (
    grant_id TEXT PRIMARY KEY CHECK (
        length(grant_id) = 36 AND substr(grant_id, 1, 4) = 'egr_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    entitlement_key TEXT NOT NULL REFERENCES entitlement_definitions(entitlement_key)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    scope TEXT NOT NULL CHECK (scope IN ('organization', 'project', 'user')),
    scope_id TEXT CHECK (scope_id IS NULL OR length(scope_id) BETWEEN 1 AND 64),
    value_json TEXT NOT NULL CHECK (json_valid(value_json) AND length(value_json) <= 1024),
    -- `plan` grants derive from the subscription plan pointer; `internal_override`
    -- grants are support-only, audited, and MUST carry an expiry and reason.
    source TEXT NOT NULL CHECK (source IN ('plan', 'subscription', 'internal_override')),
    subscription_id TEXT REFERENCES subscriptions(subscription_id) ON DELETE CASCADE,
    reason TEXT CHECK (reason IS NULL OR length(reason) <= 2000),
    granted_by_principal_id TEXT,
    effective_at TEXT NOT NULL CHECK (length(effective_at) = 24),
    expires_at TEXT CHECK (expires_at IS NULL OR length(expires_at) = 24),
    revoked_at TEXT CHECK (revoked_at IS NULL OR length(revoked_at) = 24),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    -- F18: there are no silent forever internal overrides. Every override must
    -- expire, carry a reason, and name the granting principal.
    CHECK (
        source <> 'internal_override'
        OR (expires_at IS NOT NULL AND reason IS NOT NULL AND granted_by_principal_id IS NOT NULL)
    )
);
CREATE INDEX idx_entitlement_grants_effective
    ON entitlement_grants(org_id, entitlement_key, scope, scope_id, effective_at);
CREATE UNIQUE INDEX ux_entitlement_grants_override_active
    ON entitlement_grants(org_id, entitlement_key, scope, COALESCE(scope_id, ''))
    WHERE source = 'internal_override' AND revoked_at IS NULL;

--------------------------------------------------------------------------------
-- Server-side license state projection
--------------------------------------------------------------------------------
CREATE TABLE license_states (
    license_state_id TEXT PRIMARY KEY CHECK (length(license_state_id) = 36),
    org_id TEXT NOT NULL UNIQUE REFERENCES organizations(org_id) ON DELETE CASCADE,
    subscription_id TEXT REFERENCES subscriptions(subscription_id) ON DELETE RESTRICT,
    -- F18: the capability matrix. Local-only work may use a signed snapshot for
    -- up to 7 days, cloud control-plane managed work for 24h, and platform-paid
    -- inference receives no additional billing grace.
    state TEXT NOT NULL CHECK (
        state IN ('active', 'grace', 'past_due', 'suspended', 'cancelled', 'expired',
                  'provider_unavailable')
    ),
    local_offline_grace_seconds INTEGER NOT NULL DEFAULT 604800
        CHECK (local_offline_grace_seconds BETWEEN 0 AND 604800),
    cloud_control_plane_grace_seconds INTEGER NOT NULL DEFAULT 86400
        CHECK (cloud_control_plane_grace_seconds BETWEEN 0 AND 86400),
    platform_paid_inference_grace_seconds INTEGER NOT NULL DEFAULT 0
        CHECK (platform_paid_inference_grace_seconds BETWEEN 0 AND 0),
    grace_started_at TEXT CHECK (grace_started_at IS NULL OR length(grace_started_at) = 24),
    grace_expires_at TEXT CHECK (grace_expires_at IS NULL OR length(grace_expires_at) = 24),
    reason_code TEXT CHECK (reason_code IS NULL OR length(reason_code) <= 96),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
CREATE INDEX idx_license_states_state ON license_states(state, grace_expires_at);

--------------------------------------------------------------------------------
-- Short-lived signed license snapshots (carried in /devices/policy)
--------------------------------------------------------------------------------
CREATE TABLE license_snapshots (
    license_snapshot_id TEXT PRIMARY KEY CHECK (
        length(license_snapshot_id) = 36 AND substr(license_snapshot_id, 1, 4) = 'lic_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    device_id TEXT REFERENCES devices(device_id) ON DELETE CASCADE,
    -- Audience binding prevents an Org A snapshot being replayed as Org B or
    -- copied between devices.
    audience TEXT NOT NULL CHECK (length(audience) BETWEEN 1 AND 128),
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    license_state TEXT NOT NULL CHECK (
        license_state IN ('active', 'grace', 'past_due', 'suspended', 'cancelled',
                          'expired', 'provider_unavailable')
    ),
    -- Managed cloud work requires a fresh policy; local-only work may use the
    -- snapshot until the class-specific offline expiry.
    policy_fresh_until TEXT NOT NULL CHECK (length(policy_fresh_until) = 24),
    offline_valid_until TEXT NOT NULL CHECK (length(offline_valid_until) = 24),
    -- Bounded entitlement value projection. Never a provider product/price ID.
    entitlements_json TEXT NOT NULL CHECK (
        json_valid(entitlements_json) AND length(entitlements_json) <= 16384
    ),
    -- Signing key metadata. Key material lives in Wrangler secrets, never here.
    key_id TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 128),
    signature BLOB NOT NULL,
    canonical_bytes BLOB NOT NULL,
    issued_at TEXT NOT NULL CHECK (length(issued_at) = 24),
    revoked_at TEXT CHECK (revoked_at IS NULL OR length(revoked_at) = 24),
    -- Key rotation retains a bounded verification overlap; old keys never grant
    -- NEW work after their expiry.
    valid_until TEXT NOT NULL CHECK (length(valid_until) = 24),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    CHECK (offline_valid_until > policy_fresh_until)
);
CREATE INDEX idx_license_snapshots_device
    ON license_snapshots(org_id, device_id, issued_at DESC);
CREATE INDEX idx_license_snapshots_fresh
    ON license_snapshots(policy_fresh_until) WHERE revoked_at IS NULL;

-- Anti-rollback: a device may never accept an older policy version than the
-- highest one it has already observed.
CREATE TRIGGER trg_license_snapshots_anti_rollback
BEFORE INSERT ON license_snapshots
FOR EACH ROW WHEN EXISTS (
    SELECT 1 FROM license_snapshots previous
    WHERE previous.org_id = NEW.org_id
      AND (previous.device_id IS NEW.device_id OR previous.audience = NEW.audience)
      AND previous.policy_version > NEW.policy_version
      AND previous.revoked_at IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'license snapshot policy rollback rejected');
END;

-- Signing key metadata (key material is a Wrangler secret, never persisted).
CREATE TABLE license_signing_keys (
    key_id TEXT PRIMARY KEY CHECK (length(key_id) BETWEEN 1 AND 128),
    algorithm TEXT NOT NULL DEFAULT 'ed25519' CHECK (algorithm = 'ed25519'),
    -- Public verification key only. Private material is a Wrangler secret.
    public_key BLOB NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    not_before TEXT NOT NULL CHECK (length(not_before) = 24),
    -- Bounded verification overlap during rotation.
    verify_until TEXT NOT NULL CHECK (length(verify_until) = 24),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24)
);
