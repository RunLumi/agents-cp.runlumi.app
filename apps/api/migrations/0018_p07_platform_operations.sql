-- 0018_p07_platform_operations.sql — P07 internal staff, support grants,
-- feature flags, and kill switches.
--
-- Forward-only; apply after 0017_p07_plugin_governance.sql.
--
-- Everything here is PLATFORM state. None of it is reachable with a customer
-- session, and none of it is reachable with an organization API key: the
-- credential scheme is `lumi_staff_`, the role is a `StaffRole`, and the
-- permission set is a `StaffPermission`. `MembershipRole::Admin` confers no
-- authority over any table in this file, and no table in this file is scoped by
-- a `user_id` — because there is no customer user behind a staff principal
-- (ADR 0007, F24-001).
--
-- The security properties that matter, and where each one is proven:
--
--   * Staff identity is NAMED and credentialed. `staff_principals` carries its
--     own hashed credential rather than sharing a session with a customer user,
--     which is what makes F24-001's "no shared admin account" a storage fact.
--   * A support grant cannot exist without a reason, a ticket reference, and a
--     bounded expiry. There is no column for a grant with no TTL, so
--     "permanent support access" is not representable.
--   * A feature flag cannot exist without an expiry. F24-006 says not to use
--     flags as a permanent configuration store; making `expires_at` NOT NULL is
--     the difference between that being true and that being a review note.
--   * A kill switch names exactly one target and one scope, and `organization_id`
--     is present exactly when the scope is `organization`. A global switch that
--     carried an org, or an org switch without one, would under-apply a safety
--     control while looking engaged.
--   * Engaging and lifting a kill switch are separate audited facts. The engage
--     is never deleted, and a lift requires its own reason.

--------------------------------------------------------------------------------
-- Staff principals
--------------------------------------------------------------------------------
CREATE TABLE staff_principals (
    staff_principal_id TEXT PRIMARY KEY CHECK (
        length(staff_principal_id) = 36 AND substr(staff_principal_id, 1, 4) = 'stf_'
    ),
    -- A named internal identity. Not a `user_id`: there is deliberately no row in
    -- `users` for a staff principal, so no code path can treat a staff actor as
    -- a customer user (F24-001, ADR 0007).
    email TEXT NOT NULL CHECK (length(email) BETWEEN 3 AND 320),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 120),
    -- F24-002. `support`, `finance`, `security`, `engineering`. A `StaffRole`
    -- without a matching `StaffPermission` set is a contract change, not an
    -- implementation detail, and the domain layer owns the pairing.
    staff_role TEXT NOT NULL
        CHECK (staff_role IN ('support', 'finance', 'security', 'engineering')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    -- The staff credential. The `lumi_staff_` scheme is disjoint from the human
    -- session bearer and from `lumik_`, so a staff token presented on an org
    -- route is a boundary violation rather than an authentication attempt, and a
    -- machine key can never be parsed as staff.
    --
    -- Same rule as `api_keys`: the raw value is shown once and never stored. The
    -- 64-char hex CHECK on `credential_hash` means the presented token cannot be
    -- written there even by a future mistake.
    credential_prefix TEXT NOT NULL CHECK (length(credential_prefix) = 16
        AND credential_prefix = lower(credential_prefix)
        AND credential_prefix NOT GLOB '*[^0-9a-f]*'),
    credential_hash TEXT NOT NULL CHECK (length(credential_hash) = 64
        AND credential_hash = lower(credential_hash)
        AND credential_hash NOT GLOB '*[^0-9a-f]*'),
    credential_fingerprint TEXT NOT NULL CHECK (length(credential_fingerprint) BETWEEN 16 AND 64
        AND credential_fingerprint = lower(credential_fingerprint)
        AND credential_fingerprint NOT GLOB '*[^0-9a-f]*'),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
CREATE UNIQUE INDEX ux_staff_principals_email ON staff_principals(email);
CREATE UNIQUE INDEX ux_staff_principals_credential_prefix
    ON staff_principals(credential_prefix);
CREATE INDEX idx_staff_principals_role ON staff_principals(staff_role, status);

-- A suspended staff principal must keep its credential columns populated: nulling
-- them would turn "suspended" into "deleted" without any record that the person
-- ever existed, and F24's audit requirement survives a departure.
CREATE TRIGGER trg_staff_principals_credential_is_required
BEFORE UPDATE OF credential_prefix, credential_hash ON staff_principals
FOR EACH ROW WHEN NEW.credential_prefix IS NULL
    OR NEW.credential_prefix = ''
    OR NEW.credential_hash IS NULL
    OR NEW.credential_hash = ''
BEGIN
    SELECT RAISE(ABORT, 'a staff principal must retain a credential reference');
END;

--------------------------------------------------------------------------------
-- Support grants
--------------------------------------------------------------------------------
-- F24-003 / F24-008. Time-bounded, reasoned, audited access to ONE customer
-- organization, checked on every request that relies on it rather than only at
-- creation.
CREATE TABLE support_grants (
    grant_id TEXT PRIMARY KEY CHECK (
        length(grant_id) = 36 AND substr(grant_id, 1, 4) = 'sgr_'
    ),
    staff_principal_id TEXT NOT NULL
        REFERENCES staff_principals(staff_principal_id) ON DELETE RESTRICT,
    organization_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    -- Both are NOT NULL, not merely conventionally filled. A grant with no
    -- reason is the artifact a post-incident reviewer reads first, and a grant
    -- with no ticket cannot be tied to a request for help.
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    ticket_reference TEXT NOT NULL CHECK (length(ticket_reference) BETWEEN 1 AND 120),
    -- An explicit capability subset, never a wildcard and never a staff role.
    -- A grant cannot widen what its holder's `StaffRole` already allows; the
    -- domain layer is where both sets are available to compare.
    capabilities_json TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(capabilities_json) AND json_type(capabilities_json) = 'array'),
    issued_at TEXT NOT NULL CHECK (length(issued_at) = 24),
    -- F24-008: short TTL, mandatory. The frozen gate bounds it to 1..604800
    -- seconds, so the widest grant is seven days and there is no representable
    -- "permanent" support access. The fixed 24-character UTC form makes a
    -- lexicographic comparison equivalent to a chronological one, which is how
    -- the "expires after it was issued" rule below is checkable in SQL.
    expires_at TEXT NOT NULL CHECK (length(expires_at) = 24),
    revoked_at TEXT CHECK (revoked_at IS NULL OR length(revoked_at) = 24),
    revoke_reason TEXT CHECK (revoke_reason IS NULL OR length(revoke_reason) <= 500),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
CREATE INDEX idx_support_grants_org ON support_grants(organization_id, expires_at);
CREATE INDEX idx_support_grants_staff ON support_grants(staff_principal_id, expires_at);

-- A grant that expires before it was issued is either a clock bug or an attempt
-- to hold an indefinitely-valid grant behind an expiry that has already passed.
CREATE TRIGGER trg_support_grants_expiry_after_issue
BEFORE INSERT ON support_grants
FOR EACH ROW WHEN NEW.expires_at <= NEW.issued_at
BEGIN
    SELECT RAISE(ABORT, 'support grant expiry must be after its issue time');
END;

-- Revoking is audited, so it carries a reason, and the reason is as durable as
-- the revocation itself. Watching BOTH columns matters: on an already-revoked
-- row, `UPDATE ... SET revoke_reason = NULL` never mentions `revoked_at`, so a
-- trigger on `revoked_at` alone would let the recorded cause be erased after the
-- fact.
CREATE TRIGGER trg_support_grants_revoked_requires_reason
BEFORE UPDATE OF revoked_at, revoke_reason ON support_grants
FOR EACH ROW WHEN NEW.revoked_at IS NOT NULL AND (NEW.revoke_reason IS NULL OR NEW.revoke_reason = '')
BEGIN
    SELECT RAISE(ABORT, 'revoking a support grant requires a reason');
END;

-- Revocation is terminal. A grant that can be un-revoked is a grant whose
-- revocation was not a revocation.
CREATE TRIGGER trg_support_grants_revocation_is_terminal
BEFORE UPDATE OF revoked_at ON support_grants
FOR EACH ROW WHEN OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'a revoked support grant cannot be restored in place');
END;

-- A wildcard capability would make the grant's explicit subset meaningless, and
-- it is the same implicit-authority failure F14-001 forbids one layer down.
CREATE TRIGGER trg_support_grants_no_wildcard
BEFORE INSERT ON support_grants
FOR EACH ROW WHEN NEW.capabilities_json LIKE '%"*"%'
BEGIN
    SELECT RAISE(ABORT, 'support grant capabilities must not contain a wildcard');
END;

CREATE TRIGGER trg_support_grants_capabilities_are_strings
BEFORE INSERT ON support_grants
FOR EACH ROW WHEN EXISTS (
    SELECT 1 FROM json_each(NEW.capabilities_json) WHERE json_each.type != 'text'
)
BEGIN
    SELECT RAISE(ABORT, 'support grant capabilities must be strings');
END;

--------------------------------------------------------------------------------
-- Feature flags
--------------------------------------------------------------------------------
-- F24-006. A rollout lever, not a plan entitlement: P06 owns entitlements, and
-- a flag may not grant a capability the entitlement projection denies.
CREATE TABLE feature_flags (
    flag_key TEXT PRIMARY KEY CHECK (
        length(flag_key) BETWEEN 3 AND 64
        AND flag_key NOT GLOB '*[^a-z0-9._-]*'
    ),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    rollout_percentage INTEGER NOT NULL DEFAULT 0
        CHECK (rollout_percentage BETWEEN 0 AND 100),
    org_allowlist_json TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(org_allowlist_json) AND json_type(org_allowlist_json) = 'array'),
    cohort TEXT NOT NULL DEFAULT 'none' CHECK (cohort IN ('user', 'device', 'none')),
    -- NOT NULL, deliberately. F24-006 says not to use flags as a permanent
    -- configuration store, and a nullable expiry is a permanent store waiting to
    -- happen. An expired flag resolves OFF and is reported as expired rather
    -- than silently ignored.
    expires_at TEXT NOT NULL CHECK (length(expires_at) = 24),
    owner_staff_principal_id TEXT NOT NULL CHECK (length(owner_staff_principal_id) = 36),
    updated_by TEXT NOT NULL CHECK (length(updated_by) = 36),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
CREATE INDEX idx_feature_flags_expiry ON feature_flags(expires_at);

-- A `*` org allowlist entry would be a permanent, invisible grant to everyone,
-- which is the same shape as the wildcard capability F14-001 forbids.
CREATE TRIGGER trg_feature_flags_no_wildcard
BEFORE INSERT ON feature_flags
FOR EACH ROW WHEN NEW.org_allowlist_json LIKE '%"*"%'
BEGIN
    SELECT RAISE(ABORT, 'feature flag org allowlist must not contain a wildcard');
END;

CREATE TRIGGER trg_feature_flags_no_wildcard_update
BEFORE UPDATE OF org_allowlist_json ON feature_flags
FOR EACH ROW WHEN NEW.org_allowlist_json LIKE '%"*"%'
BEGIN
    SELECT RAISE(ABORT, 'feature flag org allowlist must not contain a wildcard');
END;

-- `rollout_percentage` and the allowlist are two different mechanisms expressing
-- one intent. A flag that is on for the whole allowlist AND claims a 30% rollout
-- has no single answer for a tenant on the list, and an operator reading the row
-- cannot tell which rule applied.
CREATE TRIGGER trg_feature_flags_no_ambiguous_rollout
BEFORE INSERT ON feature_flags
FOR EACH ROW WHEN NEW.enabled = 1
    AND json_array_length(NEW.org_allowlist_json) > 0
    AND NEW.rollout_percentage NOT IN (0, 100)
BEGIN
    SELECT RAISE(ABORT, 'feature flag combines an org allowlist with a partial rollout');
END;

--------------------------------------------------------------------------------
-- Kill switches
--------------------------------------------------------------------------------
-- F24-007. Narrow by construction: exactly one `target_class` and one
-- `target_ref`. There is no "disable all plugins" form and no "disable
-- everything for this tenant" form, because F24-007 and the goal both require a
-- switch to be narrow and reversible.
CREATE TABLE kill_switches (
    kill_switch_id TEXT PRIMARY KEY CHECK (
        length(kill_switch_id) = 36 AND substr(kill_switch_id, 1, 4) = 'ksw_'
    ),
    target_class TEXT NOT NULL CHECK (
        target_class IN ('inference_provider', 'model_route', 'mcp_server',
                         'plugin_version', 'computer_use', 'client_version')
    ),
    target_ref TEXT NOT NULL CHECK (length(target_ref) BETWEEN 1 AND 200),
    scope TEXT NOT NULL CHECK (scope IN ('global', 'organization')),
    -- INVARIANT 7 of the frozen gate: `organization_id` is present exactly when
    -- the scope is `organization`. Both halves are enforced because a global
    -- switch carrying an org, or an org switch without one, silently under-
    -- applies a safety control while still looking engaged.
    organization_id TEXT,
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    engaged_by_staff_principal_id TEXT NOT NULL CHECK (length(engaged_by_staff_principal_id) = 36),
    engaged_at TEXT NOT NULL CHECK (length(engaged_at) = 24),
    -- NULL means "until lifted". An expiry here is a safety control that silently
    -- stops applying, which is worse than no control, so an expired switch
    -- resolves to NOT engaged and says so; re-engagement is an explicit act.
    expires_at TEXT CHECK (expires_at IS NULL OR length(expires_at) = 24),
    state TEXT NOT NULL DEFAULT 'engaged' CHECK (state IN ('engaged', 'lifted')),
    lifted_at TEXT CHECK (lifted_at IS NULL OR length(lifted_at) = 24),
    lifted_by TEXT CHECK (lifted_by IS NULL OR length(lifted_by) = 36),
    lift_reason TEXT CHECK (lift_reason IS NULL OR length(lift_reason) <= 500),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
CREATE INDEX idx_kill_switches_target ON kill_switches(target_class, target_ref, state);
CREATE INDEX idx_kill_switches_scope ON kill_switches(scope, organization_id, state);

CREATE TRIGGER trg_kill_switches_scope_matches_org
BEFORE INSERT ON kill_switches
FOR EACH ROW WHEN (NEW.scope = 'organization' AND NEW.organization_id IS NULL)
    OR (NEW.scope = 'global' AND NEW.organization_id IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'kill switch organization_id must be present exactly at organization scope');
END;

CREATE TRIGGER trg_kill_switches_scope_matches_org_update
BEFORE UPDATE OF scope, organization_id ON kill_switches
FOR EACH ROW WHEN (NEW.scope = 'organization' AND NEW.organization_id IS NULL)
    OR (NEW.scope = 'global' AND NEW.organization_id IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'kill switch organization_id must be present exactly at organization scope');
END;

-- Lifting is an audited event of its own, so it carries its own reason. The
-- engage row is never deleted, and the lift does not erase it.
CREATE TRIGGER trg_kill_switches_lift_requires_reason
BEFORE UPDATE OF state, lift_reason ON kill_switches
FOR EACH ROW WHEN NEW.state = 'lifted' AND (NEW.lift_reason IS NULL OR NEW.lift_reason = '')
BEGIN
    SELECT RAISE(ABORT, 'lifting a kill switch requires a reason');
END;

-- `lifted` is terminal. Re-engaging in place would erase the fact that the
-- switch was lifted, so a re-engagement is a NEW row and the history reads
-- chronologically.
CREATE TRIGGER trg_kill_switches_lift_is_terminal
BEFORE UPDATE OF state ON kill_switches
FOR EACH ROW WHEN OLD.state = 'lifted' AND NEW.state = 'engaged'
BEGIN
    SELECT RAISE(ABORT, 'a lifted kill switch cannot be re-engaged in place; create a new one');
END;

-- An expiry must be in the future of the engage. A switch that is born expired
-- looks engaged in a list and denies nothing.
CREATE TRIGGER trg_kill_switches_expiry_after_engage
BEFORE INSERT ON kill_switches
FOR EACH ROW WHEN NEW.expires_at IS NOT NULL AND NEW.expires_at <= NEW.engaged_at
BEGIN
    SELECT RAISE(ABORT, 'kill switch expiry must be after its engage time');
END;
