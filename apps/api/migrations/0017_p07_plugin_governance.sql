-- 0017_p07_plugin_governance.sql — P07 plugin package catalog and org policy.
--
-- Forward-only; apply after 0016_p07_machine_identity.sql.
--
-- F25's acceptance criteria are two sentences long and both are supply-chain
-- claims:
--
--   * "Plugin update cannot silently gain network/secret/tool capability."
--   * "Blocked version cannot execute for managed org even if still present on
--     disk."
--
-- Neither is satisfiable by a code path alone, so the structure that makes them
-- true is in this file:
--
--   * A published `plugin_versions` row is IMMUTABLE. Capability lives in
--     `manifest_json`, and a version is the unit an organization approves. If a
--     manifest could be edited in place, every existing approval would silently
--     mean something new and no permission diff would be trustworthy. The
--     immutability trigger below is what makes the diff a function of two stored
--     facts rather than a comparison against a moving target.
--   * `package_id` is a stable identity independent of display name and version
--     (F25-001). It is a TEXT primary key, not a UUID minted per install, so a
--     rename cannot orphan an install or an org policy row.
--   * `plugin_installs` is UNIQUE `(org_id, package_id)`: exactly ONE review
--     state per package per organization. A second row would be a second
--     approval state, and which one governs would be a race.
--   * `plugin_quarantines` has NO DELETE path. A quarantine is a security action;
--     erasing the row erases the evidence that it happened, which is the
--     "hard to audit" failure F24 is written against. It is lifted, and the lift
--     is its own audited row.
--
-- What is deliberately NOT in this file: a `blocked` flag on the package, and a
-- "global kill" row. Blocking is an ORG decision expressed through
-- `plugin_policies`; quarantining a specific `package@version` is a PLATFORM
-- decision. Merging them would let a customer lift a platform quarantine, or let
-- a platform quarantine silently rewrite a customer's policy.

--------------------------------------------------------------------------------
-- Publishers
--------------------------------------------------------------------------------
-- F25 names PluginPublisher as a concept and org policy may allowlist
-- publishers, so a publisher is a first-class row rather than a free-text
-- column. It is platform-owned: a publisher identity is never organization data.
CREATE TABLE plugin_publishers (
    publisher_id TEXT PRIMARY KEY CHECK (
        length(publisher_id) = 36 AND substr(publisher_id, 1, 4) = 'pub_'
    ),
    -- Display identity only. `official_only` publisher_mode keys off `official`,
    -- never off the name.
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 120),
    official INTEGER NOT NULL DEFAULT 0 CHECK (official IN (0, 1)),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
CREATE UNIQUE INDEX ux_plugin_publishers_name
    ON plugin_publishers(display_name);

--------------------------------------------------------------------------------
-- Packages
--------------------------------------------------------------------------------
CREATE TABLE plugin_packages (
    -- Stable identity (F25-001). Deliberately not derived from display_name or
    -- version: renaming a plugin must never orphan an install, a tool
    -- registration, or an org's allow/block/pin policy.
    package_id TEXT PRIMARY KEY CHECK (
        length(package_id) = 36 AND substr(package_id, 1, 4) = 'pkg_'
    ),
    publisher_id TEXT NOT NULL REFERENCES plugin_publishers(publisher_id) ON DELETE RESTRICT,
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 120),
    summary TEXT CHECK (summary IS NULL OR length(summary) <= 2000),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'delisted')),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
CREATE INDEX idx_plugin_packages_publisher ON plugin_packages(publisher_id, status);

--------------------------------------------------------------------------------
-- Versions
--------------------------------------------------------------------------------
-- One immutable published version. `manifest_json` is the declared capability
-- set (F25-002) and is the input to every permission diff.
CREATE TABLE plugin_versions (
    plugin_version_id TEXT PRIMARY KEY CHECK (
        length(plugin_version_id) = 36 AND substr(plugin_version_id, 1, 4) = 'pvr_'
    ),
    package_id TEXT NOT NULL REFERENCES plugin_packages(package_id) ON DELETE RESTRICT,
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 64),
    -- Bounded host-agent compatibility range. A version whose range excludes the
    -- reporting host cannot be installed (`plugin_incompatible`), so the range
    -- is a gate, not documentation.
    runtime_min TEXT NOT NULL CHECK (length(runtime_min) BETWEEN 1 AND 32),
    runtime_max TEXT NOT NULL CHECK (length(runtime_max) BETWEEN 1 AND 32),
    -- F25-005 integrity metadata, carried in the trusted distribution manifest.
    -- Lumi verifies the digest before recording an install; a mismatch denies
    -- `plugin_integrity_failed` and is audited as a security event.
    content_digest TEXT NOT NULL CHECK (length(content_digest) = 64
        AND content_digest = lower(content_digest)
        AND content_digest NOT GLOB '*[^0-9a-f]*'),
    signature TEXT NOT NULL CHECK (length(signature) BETWEEN 32 AND 512),
    manifest_json TEXT NOT NULL
        CHECK (json_valid(manifest_json) AND json_type(manifest_json) = 'object'),
    published_at TEXT NOT NULL CHECK (length(published_at) = 24),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24)
);
CREATE UNIQUE INDEX ux_plugin_versions_package_version
    ON plugin_versions(package_id, version);
CREATE INDEX idx_plugin_versions_package ON plugin_versions(package_id, published_at);

-- A published version is never edited (F25-002 + the F25 acceptance criterion).
-- A capability change is a NEW version, which produces a diff, which is what
-- triggers renewed review in managed mode. Editing the manifest in place would
-- make "the org approved 2.3.0" mean "the org approved whatever 2.3.0 contains
-- today", which is exactly the silent capability gain F25 forbids.
--
-- The trigger watches the identity and integrity columns as well as the
-- manifest: a row that could be re-pointed at another package or have its digest
-- swapped is a row whose approval cannot be reasoned about.
CREATE TRIGGER trg_plugin_versions_immutable
BEFORE UPDATE ON plugin_versions
FOR EACH ROW WHEN NEW.package_id != OLD.package_id
    OR NEW.version != OLD.version
    OR NEW.manifest_json != OLD.manifest_json
    OR NEW.content_digest != OLD.content_digest
    OR NEW.signature != OLD.signature
    OR NEW.runtime_min != OLD.runtime_min
    OR NEW.runtime_max != OLD.runtime_max
    OR NEW.published_at != OLD.published_at
BEGIN
    SELECT RAISE(ABORT, 'published plugin version is immutable; publish a new version');
END;

-- The manifest's capability fields are closed finite sets (F25-002). A wildcard
-- in `tools` or `network_destinations` would be the same implicit-inheritance
-- failure F14-001 forbids for API keys, expressed one layer up, so it is refused
-- in storage.
CREATE TRIGGER trg_plugin_versions_no_wildcard_manifest
BEFORE INSERT ON plugin_versions
FOR EACH ROW WHEN NEW.manifest_json LIKE '%"*"%'
BEGIN
    SELECT RAISE(ABORT, 'plugin manifest must not contain a wildcard capability');
END;

-- A manifest that omits a required capability field would make the diff
-- under-report an expansion: an absent `network_destinations` compared as "none"
-- against a previous "one entry" reads as a contraction when it is really an
-- undeclared field. Refused at insert so every diff has a complete left side.
CREATE TRIGGER trg_plugin_versions_manifest_is_complete
BEFORE INSERT ON plugin_versions
FOR EACH ROW WHEN json_extract(NEW.manifest_json, '$.tools') IS NULL
    OR json_extract(NEW.manifest_json, '$.network_destinations') IS NULL
    OR json_extract(NEW.manifest_json, '$.secret_handles') IS NULL
    OR json_extract(NEW.manifest_json, '$.browser_capability') IS NULL
    OR json_extract(NEW.manifest_json, '$.external_data_handling') IS NULL
    OR json_extract(NEW.manifest_json, '$.filesystem_scopes') IS NULL
    OR json_extract(NEW.manifest_json, '$.mcp_servers') IS NULL
    OR json_extract(NEW.manifest_json, '$.process_spawn') IS NULL
BEGIN
    SELECT RAISE(ABORT, 'plugin manifest is missing a required capability field');
END;

--------------------------------------------------------------------------------
-- Organization policy
--------------------------------------------------------------------------------
-- F25-004. `blocked_packages` WINS over `allowed_packages`, and a package on
-- both lists is reported as `policy_conflict` rather than silently resolved —
-- so the conflicting state is storable on purpose, and no trigger forbids it.
CREATE TABLE plugin_policies (
    org_id TEXT PRIMARY KEY REFERENCES organizations(org_id) ON DELETE CASCADE,
    publisher_mode TEXT NOT NULL DEFAULT 'official_only'
        CHECK (publisher_mode IN ('official_only', 'approved_publishers', 'any')),
    approved_publishers_json TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(approved_publishers_json)
               AND json_type(approved_publishers_json) = 'array'),
    allowed_packages_json TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(allowed_packages_json)
               AND json_type(allowed_packages_json) = 'array'),
    blocked_packages_json TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(blocked_packages_json)
               AND json_type(blocked_packages_json) = 'array'),
    -- A map, not a list: `{ package_id: version }`. A list of pairs would admit
    -- two entries for one package, and then "is it pinned" would have two
    -- answers.
    pinned_versions_json TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(pinned_versions_json)
               AND json_type(pinned_versions_json) = 'object'),
    auto_update TEXT NOT NULL DEFAULT 'off' CHECK (auto_update IN ('on', 'off')),
    -- `managed` is what makes F25-003's renewed-approval rule bind.
    update_mode TEXT NOT NULL DEFAULT 'managed' CHECK (update_mode IN ('managed', 'direct')),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);

-- The lists are package/publisher ids, so a bare `*` would mean "everything",
-- and F25-004's whole point is that an org states its policy explicitly.
CREATE TRIGGER trg_plugin_policies_no_wildcard
BEFORE INSERT ON plugin_policies
FOR EACH ROW WHEN NEW.allowed_packages_json LIKE '%"*"%'
    OR NEW.blocked_packages_json LIKE '%"*"%'
    OR NEW.approved_publishers_json LIKE '%"*"%'
    OR NEW.pinned_versions_json LIKE '%"*"%'
BEGIN
    SELECT RAISE(ABORT, 'plugin policy must not contain a wildcard entry');
END;

CREATE TRIGGER trg_plugin_policies_no_wildcard_update
BEFORE UPDATE OF allowed_packages_json, blocked_packages_json,
                    approved_publishers_json, pinned_versions_json
ON plugin_policies
FOR EACH ROW WHEN NEW.allowed_packages_json LIKE '%"*"%'
    OR NEW.blocked_packages_json LIKE '%"*"%'
    OR NEW.approved_publishers_json LIKE '%"*"%'
    OR NEW.pinned_versions_json LIKE '%"*"%'
BEGIN
    SELECT RAISE(ABORT, 'plugin policy must not contain a wildcard entry');
END;

--------------------------------------------------------------------------------
-- Installs
--------------------------------------------------------------------------------
CREATE TABLE plugin_installs (
    install_id TEXT PRIMARY KEY CHECK (
        length(install_id) = 36 AND substr(install_id, 1, 4) = 'pil_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    package_id TEXT NOT NULL REFERENCES plugin_packages(package_id) ON DELETE RESTRICT,
    -- The version currently INSTALLED. `pending_review_version` is a candidate
    -- that was refused; the two are separate columns precisely so a refused
    -- update never overwrites what is running.
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 64),
    pending_review_version TEXT CHECK (
        pending_review_version IS NULL OR length(pending_review_version) BETWEEN 1 AND 64
    ),
    review_state TEXT NOT NULL DEFAULT 'approved'
        CHECK (review_state IN ('unreviewed', 'approved', 'pending_review', 'blocked')),
    -- F25-009. The refusal reason is written when a managed-mode expansion is
    -- detected, so the org can see WHY a version is waiting.
    review_reason TEXT CHECK (review_reason IS NULL OR length(review_reason) <= 500),
    approved_by TEXT CHECK (approved_by IS NULL OR length(approved_by) = 36),
    approved_at TEXT CHECK (approved_at IS NULL OR length(approved_at) = 24),
    blocked_reason TEXT CHECK (blocked_reason IS NULL OR length(blocked_reason) <= 500),
    version_counter INTEGER NOT NULL DEFAULT 1 CHECK (version_counter > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
-- One install row per package per organization: exactly one review state.
CREATE UNIQUE INDEX ux_plugin_installs_org_package
    ON plugin_installs(org_id, package_id);
CREATE INDEX idx_plugin_installs_package ON plugin_installs(package_id, review_state);

-- A `pending_review` row is a REFUSAL, so it must explain itself. Without this
-- the org sees a version that is neither installed nor allowed and no reason.
CREATE TRIGGER trg_plugin_installs_pending_review_is_explained
BEFORE INSERT ON plugin_installs
FOR EACH ROW WHEN NEW.review_state = 'pending_review' AND NEW.review_reason IS NULL
BEGIN
    SELECT RAISE(ABORT, 'a pending_review plugin install must record why');
END;

CREATE TRIGGER trg_plugin_installs_pending_review_is_explained_update
BEFORE UPDATE OF review_state, review_reason ON plugin_installs
FOR EACH ROW WHEN NEW.review_state = 'pending_review' AND NEW.review_reason IS NULL
BEGIN
    SELECT RAISE(ABORT, 'a pending_review plugin install must record why');
END;

-- A blocked install is an org decision, and the reason is the first thing a
-- later reviewer asks for.
CREATE TRIGGER trg_plugin_installs_blocked_is_explained
BEFORE UPDATE OF review_state, blocked_reason ON plugin_installs
FOR EACH ROW WHEN NEW.review_state = 'blocked' AND NEW.blocked_reason IS NULL
BEGIN
    SELECT RAISE(ABORT, 'a blocked plugin install must record a reason');
END;

-- The installed version must exist as a published version of THIS package. A
-- row pointing at an unknown version would make the permission diff
-- unresolvable, and an install that cannot be diffed is an install nobody
-- reviewed.
CREATE TRIGGER trg_plugin_installs_version_exists
BEFORE INSERT ON plugin_installs
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1 FROM plugin_versions
    WHERE package_id = NEW.package_id AND version = NEW.version
)
BEGIN
    SELECT RAISE(ABORT, 'plugin install requires a published version of its package');
END;

-- A pending candidate must also be a published version of the same package, for
-- the same reason.
CREATE TRIGGER trg_plugin_installs_pending_version_exists
BEFORE INSERT ON plugin_installs
FOR EACH ROW WHEN NEW.pending_review_version IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM plugin_versions
    WHERE package_id = NEW.package_id AND version = NEW.pending_review_version
)
BEGIN
    SELECT RAISE(ABORT, 'pending review version must be a published version of the package');
END;

--------------------------------------------------------------------------------
-- Tool registrations
--------------------------------------------------------------------------------
-- F25-007 + F13 default-deny. A tool is usable by an org only when a
-- registration exists for `(org_id, package_id, version, tool_id)`. A tool in a
-- manifest with no registration denies with `plugin_tool_unregistered`; this
-- table is the only thing that can make one usable.
CREATE TABLE plugin_tool_registrations (
    registration_id TEXT PRIMARY KEY CHECK (
        length(registration_id) = 36 AND substr(registration_id, 1, 4) = 'ptr_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    package_id TEXT NOT NULL REFERENCES plugin_packages(package_id) ON DELETE RESTRICT,
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 64),
    tool_id TEXT NOT NULL CHECK (length(tool_id) BETWEEN 1 AND 120),
    approved_by TEXT NOT NULL CHECK (length(approved_by) = 36),
    approved_at TEXT NOT NULL CHECK (length(approved_at) = 24),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24)
);
CREATE UNIQUE INDEX ux_plugin_tool_registrations_scope
    ON plugin_tool_registrations(org_id, package_id, version, tool_id);
CREATE INDEX idx_plugin_tool_registrations_tool ON plugin_tool_registrations(tool_id);

-- A registration must name a tool the version actually declares. Registering a
-- tool that is not in the manifest would let an org authorize capability the
-- publisher never requested, which is a governance record that lies.
CREATE TRIGGER trg_plugin_tool_registrations_tool_in_manifest
BEFORE INSERT ON plugin_tool_registrations
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1 FROM plugin_versions pv
    WHERE pv.package_id = NEW.package_id
      AND pv.version = NEW.version
      AND EXISTS (
          SELECT 1 FROM json_each(pv.manifest_json, '$.tools') AS tool
          WHERE tool.value = NEW.tool_id
      )
)
BEGIN
    SELECT RAISE(ABORT, 'tool registration must name a tool declared in the version manifest');
END;

--------------------------------------------------------------------------------
-- Quarantine
--------------------------------------------------------------------------------
-- Platform decision against one exact `package@version` (F25-008). It denies NEW
-- executions server-side; it does not delete the artifact from disk, because a
-- managed org must not be able to execute a quarantined version even if the
-- files are still present.
CREATE TABLE plugin_quarantines (
    quarantine_id TEXT PRIMARY KEY CHECK (
        length(quarantine_id) = 36 AND substr(quarantine_id, 1, 4) = 'pqr_'
    ),
    package_id TEXT NOT NULL REFERENCES plugin_packages(package_id) ON DELETE RESTRICT,
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 64),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    engaged_by_staff_principal_id TEXT NOT NULL CHECK (length(engaged_by_staff_principal_id) = 36),
    engaged_at TEXT NOT NULL CHECK (length(engaged_at) = 24),
    lifted_at TEXT CHECK (lifted_at IS NULL OR length(lifted_at) = 24),
    lifted_by TEXT CHECK (lifted_by IS NULL OR length(lifted_by) = 36),
    lift_reason TEXT CHECK (lift_reason IS NULL OR length(lift_reason) <= 500)
);
-- At most ONE active quarantine per version. Two active rows would make "is
-- this version quarantined" ambiguous, and the ambiguity is exploitable: a
-- caller that finds one lifted row could argue the version is clean.
CREATE UNIQUE INDEX ux_plugin_quarantines_active
    ON plugin_quarantines(package_id, version) WHERE lifted_at IS NULL;
CREATE INDEX idx_plugin_quarantines_package ON plugin_quarantines(package_id, version);

-- A quarantine is LIFTED, never erased. Deleting the row would destroy the
-- evidence that a security action happened, which is precisely the failure F24
-- ("without creating a privileged backdoor that is hard to audit") is about.
CREATE TRIGGER trg_plugin_quarantines_no_delete
BEFORE DELETE ON plugin_quarantines
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'plugin quarantine cannot be deleted; lift it instead');
END;

-- Lifting requires a reason, for the same reason revoking a key does.
CREATE TRIGGER trg_plugin_quarantines_lift_requires_reason
BEFORE UPDATE OF lifted_at ON plugin_quarantines
FOR EACH ROW WHEN NEW.lifted_at IS NOT NULL AND (NEW.lift_reason IS NULL OR NEW.lift_reason = '')
BEGIN
    SELECT RAISE(ABORT, 'lifting a plugin quarantine requires a reason');
END;

-- A lifted quarantine is terminal. Re-engaging the same row would erase the fact
-- that it was ever lifted, so a new quarantine is a new row.
CREATE TRIGGER trg_plugin_quarantines_lift_is_terminal
BEFORE UPDATE OF lifted_at ON plugin_quarantines
FOR EACH ROW WHEN OLD.lifted_at IS NOT NULL AND NEW.lifted_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'a lifted plugin quarantine cannot be re-engaged in place');
END;
