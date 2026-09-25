-- 0007_p03_devices_projects_policy.sql — P03 managed devices, projects,
-- workspace bindings, and versioned policy snapshots (P03-CG p03-cg-v1).
-- Forward-only; applied via `wrangler d1 migrations apply DB --local|--remote`.

CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations (org_id),
    enrolled_by_user_id TEXT NOT NULL REFERENCES users (user_id),
    name TEXT NOT NULL,
    platform TEXT NOT NULL,
    app_version TEXT NOT NULL,
    public_key TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    capabilities TEXT,
    capability_reported_at TEXT,
    last_seen_at TEXT,
    revoked_at TEXT,
    revoked_by_user_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX ux_devices_org_fingerprint ON devices (org_id, key_fingerprint);
CREATE INDEX idx_devices_org_status ON devices (org_id, status, created_at);

CREATE TABLE device_enrollments (
    enrollment_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations (org_id),
    code_hash TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    device_name TEXT NOT NULL,
    platform TEXT NOT NULL,
    app_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'expired', 'denied')),
    challenge TEXT,
    device_id TEXT REFERENCES devices (device_id),
    approved_by_user_id TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_device_enrollments_org_status ON device_enrollments (org_id, status, expires_at);

CREATE TABLE device_tokens (
    token_hash TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices (device_id),
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_device_tokens_device ON device_tokens (device_id, expires_at);

CREATE TABLE projects (
    project_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations (org_id),
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    visibility TEXT NOT NULL CHECK (visibility IN ('org', 'restricted')),
    archived_at TEXT,
    default_model_route TEXT,
    version INTEGER NOT NULL CHECK (version > 0),
    created_by_user_id TEXT NOT NULL REFERENCES users (user_id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX ux_projects_org_slug ON projects (org_id, slug);
CREATE INDEX idx_projects_org_created ON projects (org_id, archived_at, created_at);

CREATE TABLE project_access_grants (
    grant_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects (project_id),
    org_id TEXT NOT NULL REFERENCES organizations (org_id),
    member_id TEXT REFERENCES memberships (membership_id),
    team_id TEXT REFERENCES teams (team_id),
    created_at TEXT NOT NULL,
    CHECK (
        (member_id IS NULL AND team_id IS NOT NULL)
        OR (member_id IS NOT NULL AND team_id IS NULL)
    )
);

CREATE UNIQUE INDEX ux_project_grants_member ON project_access_grants (project_id, member_id)
WHERE member_id IS NOT NULL;
CREATE UNIQUE INDEX ux_project_grants_team ON project_access_grants (project_id, team_id)
WHERE team_id IS NOT NULL;
CREATE INDEX idx_project_grants_member ON project_access_grants (member_id);
CREATE INDEX idx_project_grants_team ON project_access_grants (team_id);

CREATE TABLE workspace_bindings (
    binding_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations (org_id),
    project_id TEXT NOT NULL REFERENCES projects (project_id),
    device_id TEXT NOT NULL REFERENCES devices (device_id),
    workspace_identity TEXT NOT NULL,
    display_name TEXT NOT NULL,
    environment_type TEXT NOT NULL CHECK (environment_type IN ('local', 'ssh', 'wsl', 'docker', 'remote')),
    last_seen_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX ux_workspace_bindings_device_identity ON workspace_bindings (device_id, workspace_identity);
CREATE INDEX idx_workspace_bindings_project ON workspace_bindings (project_id, created_at);

CREATE TABLE policy_snapshots (
    policy_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations (org_id),
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    payload TEXT NOT NULL CHECK (length(payload) <= 65536),
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX ux_policy_snapshots_org_version ON policy_snapshots (org_id, policy_version);

CREATE TABLE policy_acks (
    ack_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations (org_id),
    device_id TEXT NOT NULL REFERENCES devices (device_id),
    policy_version INTEGER NOT NULL,
    acked_at TEXT NOT NULL
);

CREATE UNIQUE INDEX ux_policy_acks_device_version ON policy_acks (device_id, policy_version);

-- P03-CR-001: authoritative per-org minimum client version used by the
-- device token exchange (F19-008). NULL disables the check.
CREATE TABLE org_device_policy_settings (
    org_id TEXT PRIMARY KEY REFERENCES organizations (org_id),
    min_client_version TEXT,
    updated_at TEXT NOT NULL
);
