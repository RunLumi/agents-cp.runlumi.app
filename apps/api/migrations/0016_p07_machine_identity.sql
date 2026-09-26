-- 0016_p07_machine_identity.sql — P07 service accounts and scoped API keys.
--
-- Forward-only; apply after 0015_p06_baseline_seed.sql.
--
-- F14: a machine must reach the control plane "without pretending to be a
-- human user". Nothing in this file is a session, and nothing here is a
-- MembershipRole. A key's authority is its own capability set, which is why
-- FR-F14-001 ("MUST NOT inherit an owner's permissions implicitly") can be
-- enforced as a storage invariant rather than a convention: there is no column
-- in which an inherited role could be recorded.
--
-- The raw key NEVER reaches D1. The client sends `lumik_<prefix>_<secret>`; the
-- server keeps `key_prefix` (a non-secret lookup index), `secret_hash` (SHA-256
-- hex), and `fingerprint` (a truncated hash used to identify a key in the UI
-- and in audit without revealing it). A compromise of this table alone yields
-- no usable credential, which is F14's first acceptance criterion.
--
-- These are organization-scoped HUMAN-MANAGED resources: creation requires a
-- human principal, because a machine must not be able to mint another machine.

--------------------------------------------------------------------------------
-- Service accounts
--------------------------------------------------------------------------------
CREATE TABLE service_accounts (
    service_account_id TEXT PRIMARY KEY CHECK (
        length(service_account_id) = 36 AND substr(service_account_id, 1, 4) = 'svc_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    description TEXT CHECK (description IS NULL OR length(description) <= 2000),
    -- Explicit capability allowlist. A JSON array of Permission strings, never
    -- a wildcard and never a role. See the triggers below.
    capabilities_json TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(capabilities_json) AND json_type(capabilities_json) = 'array'),
    -- A service account is a machine, so it is not a person. This is the actor
    -- that created it, recorded because "who added this credential" is the
    -- first question of any incident review. It is a principal id, not an
    -- email, so deleting the user does not rewrite accountability.
    created_by_principal TEXT NOT NULL CHECK (length(created_by_principal) = 36),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    expires_at TEXT CHECK (expires_at IS NULL OR length(expires_at) = 24),
    suspended_at TEXT CHECK (suspended_at IS NULL OR length(suspended_at) = 24),
    suspend_reason TEXT CHECK (suspend_reason IS NULL OR length(suspend_reason) <= 500),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
CREATE UNIQUE INDEX ux_service_accounts_org_name
    ON service_accounts(org_id, name);
CREATE INDEX idx_service_accounts_org_status
    ON service_accounts(org_id, status);

-- A wildcard capability would silently mean "everything", which is exactly the
-- implicit owner inheritance F14-001 forbids. Rejected in storage so a future
-- writer cannot introduce it by accident.
CREATE TRIGGER trg_service_accounts_no_wildcard
BEFORE INSERT ON service_accounts
FOR EACH ROW WHEN NEW.capabilities_json LIKE '%"*"%'
BEGIN
    SELECT RAISE(ABORT, 'service account capabilities must not contain a wildcard');
END;

CREATE TRIGGER trg_service_accounts_no_wildcard_update
BEFORE UPDATE OF capabilities_json ON service_accounts
FOR EACH ROW WHEN NEW.capabilities_json LIKE '%"*"%'
BEGIN
    SELECT RAISE(ABORT, 'service account capabilities must not contain a wildcard');
END;

-- F14-007: machine identities cannot perform human-only actions "unless
-- explicitly designed and strongly justified". No such justification exists
-- in P07, so these five are structurally unavailable. Enforced on the stored
-- set as well as in `authorize_machine`, because a row that could hold an
-- owner-equivalent capability is a latent escalation even if every call site
-- happens to check first.
CREATE TRIGGER trg_service_accounts_no_human_only
BEFORE INSERT ON service_accounts
FOR EACH ROW WHEN EXISTS (
    SELECT 1 FROM json_each(NEW.capabilities_json)
    WHERE json_each.value IN (
        'org.ownership_transfer', 'org.lifecycle', 'org.leave',
        'billing.manage', 'data.delete'
    )
)
BEGIN
    SELECT RAISE(ABORT, 'capability is human-only and cannot be granted to a machine');
END;

CREATE TRIGGER trg_service_accounts_no_human_only_update
BEFORE UPDATE OF capabilities_json ON service_accounts
FOR EACH ROW WHEN EXISTS (
    SELECT 1 FROM json_each(NEW.capabilities_json)
    WHERE json_each.value IN (
        'org.ownership_transfer', 'org.lifecycle', 'org.leave',
        'billing.manage', 'data.delete'
    )
)
BEGIN
    SELECT RAISE(ABORT, 'capability is human-only and cannot be granted to a machine');
END;

-- Every capability must be a string. A nested object or number would be
-- unreadable by the domain evaluator and would fail open or closed depending
-- on the implementation, so it is rejected here instead.
CREATE TRIGGER trg_service_accounts_capabilities_are_strings
BEFORE INSERT ON service_accounts
FOR EACH ROW WHEN EXISTS (
    SELECT 1 FROM json_each(NEW.capabilities_json) WHERE json_each.type != 'text'
)
BEGIN
    SELECT RAISE(ABORT, 'service account capabilities must be strings');
END;

CREATE TRIGGER trg_service_accounts_capabilities_are_strings_update
BEFORE UPDATE OF capabilities_json ON service_accounts
FOR EACH ROW WHEN EXISTS (
    SELECT 1 FROM json_each(NEW.capabilities_json) WHERE json_each.type != 'text'
)
BEGIN
    SELECT RAISE(ABORT, 'service account capabilities must be strings');
END;

--------------------------------------------------------------------------------
-- API keys
--------------------------------------------------------------------------------
CREATE TABLE api_keys (
    api_key_id TEXT PRIMARY KEY CHECK (
        length(api_key_id) = 36 AND substr(api_key_id, 1, 4) = 'key_'
    ),
    service_account_id TEXT NOT NULL
        REFERENCES service_accounts(service_account_id) ON DELETE CASCADE,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    -- NON-SECRET. The public lookup index, shown in the UI so a human can
    -- identify a key. Uniqueness is what makes lookup a single-row read, and a
    -- collision would let one key authenticate as another.
    key_prefix TEXT NOT NULL CHECK (length(key_prefix) = 12
        AND key_prefix = lower(key_prefix)
        AND key_prefix NOT GLOB '*[^0-9a-f]*'),
    -- The secret half only ever exists as this hash. The 64-char hex CHECK is
    -- what guarantees a raw key cannot be written here even by a future
    -- mistake: `lumik_...` and the base64url secret are both longer and
    -- contain characters outside [0-9a-f].
    secret_hash TEXT NOT NULL CHECK (length(secret_hash) = 64
        AND secret_hash = lower(secret_hash)
        AND secret_hash NOT GLOB '*[^0-9a-f]*'),
    -- Truncated SHA-256 of the whole presented key. Safe to show in the UI
    -- and in audit; cannot be reversed into a usable credential.
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) BETWEEN 16 AND 64
        AND fingerprint = lower(fingerprint)
        AND fingerprint NOT GLOB '*[^0-9a-f]*'),
    capabilities_json TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(capabilities_json) AND json_type(capabilities_json) = 'array'),
    -- NULL means every project in the organization. A non-null list is an
    -- explicit allow-list; an empty list means NO project, which is why this
    -- is null-vs-list rather than a boolean.
    project_ids_json TEXT CHECK (
        project_ids_json IS NULL
        OR (json_valid(project_ids_json) AND json_type(project_ids_json) = 'array')
    ),
    -- NULL means no model restriction. Aliases, never raw provider model ids.
    model_aliases_json TEXT CHECK (
        model_aliases_json IS NULL
        OR (json_valid(model_aliases_json) AND json_type(model_aliases_json) = 'array')
    ),
    -- F14-003 allows network restrictions "where reliable". Stored and enforced
    -- when present; when the edge IP is unavailable the request DENIES rather
    -- than allowing, because a control that fails open is decoration.
    network_allowlist_json TEXT CHECK (
        network_allowlist_json IS NULL
        OR (json_valid(network_allowlist_json) AND json_type(network_allowlist_json) = 'array')
    ),
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked', 'rotated', 'expired')),
    -- F14-004 rotation: the replacement exists before the prior key stops
    -- working, and the link records which key superseded which.
    rotated_from_key_id TEXT REFERENCES api_keys(api_key_id) ON DELETE RESTRICT,
    rotated_to_key_id TEXT REFERENCES api_keys(api_key_id) ON DELETE RESTRICT,
    -- F14-005. A timestamp and a bounded source hint. No request payload, no
    -- header bag, no URL query string is ever stored here.
    last_used_at TEXT CHECK (last_used_at IS NULL OR length(last_used_at) = 24),
    last_used_source TEXT CHECK (last_used_source IS NULL OR length(last_used_source) <= 200),
    expires_at TEXT CHECK (expires_at IS NULL OR length(expires_at) = 24),
    revoked_at TEXT CHECK (revoked_at IS NULL OR length(revoked_at) = 24),
    revoke_reason TEXT CHECK (revoke_reason IS NULL OR length(revoke_reason) <= 500),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
-- A prefix collision would make one key authenticate as another.
CREATE UNIQUE INDEX ux_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX idx_api_keys_service_account ON api_keys(service_account_id, status);
CREATE INDEX idx_api_keys_org ON api_keys(org_id, status);

-- Rotation must be a chain, never a self-reference.
CREATE TRIGGER trg_api_keys_no_self_rotation
BEFORE INSERT ON api_keys
FOR EACH ROW WHEN NEW.rotated_from_key_id = NEW.api_key_id
    OR NEW.rotated_to_key_id = NEW.api_key_id
BEGIN
    SELECT RAISE(ABORT, 'api key rotation cannot reference itself');
END;

-- A key's own organization must match its service account's organization.
-- Without this, a row could claim one org while pointing at an account in
-- another, and every downstream scope check that trusted `org_id` would be
-- reading a lie.
CREATE TRIGGER trg_api_keys_org_matches_account
BEFORE INSERT ON api_keys
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1 FROM service_accounts
    WHERE service_account_id = NEW.service_account_id
      AND org_id = NEW.org_id
)
BEGIN
    SELECT RAISE(ABORT, 'api key organization must match its service account');
END;

-- Same wildcard and human-only prohibitions as the service account, because a
-- key is what actually authenticates. A key may hold a SUBSET of its account's
-- capabilities and never a superset; that subset rule is enforced by the
-- domain layer, which is the only place that can read both rows cheaply and
-- explain the difference to the caller.
CREATE TRIGGER trg_api_keys_no_wildcard
BEFORE INSERT ON api_keys
FOR EACH ROW WHEN NEW.capabilities_json LIKE '%"*"%'
BEGIN
    SELECT RAISE(ABORT, 'api key capabilities must not contain a wildcard');
END;

CREATE TRIGGER trg_api_keys_no_human_only
BEFORE INSERT ON api_keys
FOR EACH ROW WHEN EXISTS (
    SELECT 1 FROM json_each(NEW.capabilities_json)
    WHERE json_each.value IN (
        'org.ownership_transfer', 'org.lifecycle', 'org.leave',
        'billing.manage', 'data.delete'
    )
)
BEGIN
    SELECT RAISE(ABORT, 'capability is human-only and cannot be granted to a machine');
END;

-- `revoked` and `rotated` are the two states that must carry their reason: a
-- credential that stopped working with no recorded cause is exactly the case
-- an operator cannot explain during an incident.
--
-- The trigger watches BOTH `status` and `revoke_reason`, not just `status`.
-- Watching only `status` left a real hole, found by
-- `apps/api/scripts/p07-schema-invariants.mjs`: on an already-revoked row the
-- statement `UPDATE ... SET revoke_reason = NULL` never mentions `status`, so an
-- `UPDATE OF status` trigger does not fire and the recorded reason can be erased
-- after the fact. The reason for a revocation is the first thing an incident
-- review asks for, so it must be as immutable as the state it explains.
CREATE TRIGGER trg_api_keys_revoked_requires_reason
BEFORE UPDATE OF status, revoke_reason ON api_keys
FOR EACH ROW WHEN NEW.status IN ('revoked', 'rotated') AND NEW.revoke_reason IS NULL
BEGIN
    SELECT RAISE(ABORT, 'revoking or rotating an api key requires a reason');
END;

-- Terminal states are terminal. F14-004 rotation revokes the prior key once
-- the replacement exists; nothing may then resurrect it, because a key that
-- can be reactivated is a key whose revocation was not a revocation.
CREATE TRIGGER trg_api_keys_terminal_is_terminal
BEFORE UPDATE OF status ON api_keys
FOR EACH ROW WHEN OLD.status IN ('revoked', 'rotated', 'expired')
    AND NEW.status != OLD.status
BEGIN
    SELECT RAISE(ABORT, 'api key status is terminal and cannot change');
END;
