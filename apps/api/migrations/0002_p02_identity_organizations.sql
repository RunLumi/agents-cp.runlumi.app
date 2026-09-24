-- P02 identity, organization, membership, authorization, and audit state.
-- All mutable tenant rows carry an immutable organization scope. Secret values
-- are represented only by hashes; product handlers never receive raw rows.

CREATE TABLE users (
    user_id TEXT PRIMARY KEY CHECK (
        length(user_id) = 36 AND substr(user_id, 1, 4) = 'usr_'
    ),
    email TEXT NOT NULL CHECK (
        length(email) BETWEEN 3 AND 320
        AND email = lower(trim(email))
        AND instr(email, '@') > 1
    ),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 120),
    email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24 AND created_at GLOB '????-??-??T??:??:??.???Z'),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24 AND updated_at GLOB '????-??-??T??:??:??.???Z')
);

CREATE UNIQUE INDEX ux_users_normalized_email ON users (email);

CREATE TABLE identities (
    identity_id TEXT PRIMARY KEY CHECK (
        length(identity_id) = 36 AND substr(identity_id, 1, 4) = 'idn_'
    ),
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 64),
    provider_subject TEXT NOT NULL CHECK (length(provider_subject) BETWEEN 1 AND 320),
    email TEXT NOT NULL CHECK (length(email) BETWEEN 3 AND 320 AND email = lower(trim(email))),
    email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    CONSTRAINT uq_identities_provider_subject UNIQUE (provider, provider_subject),
    CONSTRAINT uq_identities_user_provider UNIQUE (user_id, provider)
);

CREATE INDEX idx_identities_user_id ON identities (user_id);
CREATE INDEX idx_identities_email ON identities (email);

CREATE TABLE auth_challenges (
    challenge_id TEXT PRIMARY KEY CHECK (
        length(challenge_id) = 36 AND substr(challenge_id, 1, 4) = 'idn_'
    ),
    user_id TEXT REFERENCES users(user_id) ON DELETE CASCADE,
    email TEXT NOT NULL CHECK (length(email) BETWEEN 3 AND 320 AND email = lower(trim(email))),
    kind TEXT NOT NULL CHECK (kind IN ('verification', 'login')),
    code_hash TEXT NOT NULL CHECK (length(code_hash) BETWEEN 1 AND 128),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'consumed', 'expired', 'revoked')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0 AND attempts <= 10),
    expires_at TEXT NOT NULL CHECK (length(expires_at) = 24),
    consumed_at TEXT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    CHECK (
        (status = 'consumed' AND consumed_at IS NOT NULL)
        OR (status <> 'consumed' AND consumed_at IS NULL)
    )
);

CREATE UNIQUE INDEX ux_auth_challenges_code_hash ON auth_challenges (code_hash);
CREATE INDEX idx_auth_challenges_lookup ON auth_challenges (email, kind, status, expires_at);

CREATE TABLE login_sessions (
    session_id TEXT PRIMARY KEY CHECK (
        length(session_id) = 36 AND substr(session_id, 1, 4) = 'ses_'
    ),
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL CHECK (length(token_hash) BETWEEN 1 AND 128),
    csrf_hash TEXT NOT NULL CHECK (length(csrf_hash) BETWEEN 1 AND 128),
    device_label TEXT NOT NULL CHECK (length(device_label) BETWEEN 1 AND 120),
    platform TEXT NOT NULL CHECK (length(platform) BETWEEN 1 AND 120),
    expires_at TEXT NOT NULL CHECK (length(expires_at) = 24),
    last_seen_at TEXT NOT NULL CHECK (length(last_seen_at) = 24),
    revoked_at TEXT,
    revoked_reason TEXT CHECK (revoked_reason IS NULL OR length(revoked_reason) <= 64),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    CHECK ((revoked_at IS NULL AND revoked_reason IS NULL) OR (revoked_at IS NOT NULL AND revoked_reason IS NOT NULL))
);

CREATE UNIQUE INDEX ux_login_sessions_token_hash ON login_sessions (token_hash);
CREATE INDEX idx_login_sessions_user_state ON login_sessions (user_id, revoked_at, expires_at);

CREATE TABLE organizations (
    org_id TEXT PRIMARY KEY CHECK (
        length(org_id) = 36 AND substr(org_id, 1, 4) = 'org_'
    ),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 120),
    slug TEXT NOT NULL CHECK (
        length(slug) BETWEEN 3 AND 63
        AND slug = lower(trim(slug))
        AND slug NOT GLOB '*[^a-z0-9-]*'
        AND substr(slug, 1, 1) != '-'
        AND substr(slug, -1, 1) != '-'
    ),
    state TEXT NOT NULL DEFAULT 'active' CHECK (
        state IN ('active', 'suspended', 'pending_deletion', 'deleted')
    ),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);

CREATE UNIQUE INDEX ux_organizations_live_slug ON organizations (slug) WHERE state <> 'deleted';
CREATE INDEX idx_organizations_state ON organizations (state);

CREATE TABLE memberships (
    membership_id TEXT PRIMARY KEY CHECK (
        length(membership_id) = 36 AND substr(membership_id, 1, 4) = 'mem_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'removed')),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    invited_by_user_id TEXT REFERENCES users(user_id) ON DELETE SET NULL,
    joined_at TEXT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    CONSTRAINT uq_memberships_org_user UNIQUE (org_id, user_id),
    CONSTRAINT uq_memberships_org_membership UNIQUE (org_id, membership_id)
);

CREATE INDEX idx_memberships_org_status ON memberships (org_id, status, role);
CREATE INDEX idx_memberships_user_status ON memberships (user_id, status);

CREATE TABLE invitations (
    invitation_id TEXT PRIMARY KEY CHECK (
        length(invitation_id) = 36 AND substr(invitation_id, 1, 4) = 'inv_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    email TEXT NOT NULL CHECK (length(email) BETWEEN 3 AND 320 AND email = lower(trim(email))),
    role TEXT NOT NULL CHECK (role IN ('admin', 'member', 'viewer')),
    invited_by_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    token_hash TEXT NOT NULL CHECK (length(token_hash) BETWEEN 1 AND 128),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'expired', 'revoked')),
    expires_at TEXT NOT NULL CHECK (length(expires_at) = 24),
    accepted_by_user_id TEXT REFERENCES users(user_id) ON DELETE SET NULL,
    accepted_at TEXT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    CONSTRAINT uq_invitations_token_hash UNIQUE (token_hash),
    CHECK ((status = 'accepted' AND accepted_by_user_id IS NOT NULL AND accepted_at IS NOT NULL) OR (status <> 'accepted' AND accepted_by_user_id IS NULL AND accepted_at IS NULL))
);

CREATE UNIQUE INDEX ux_invitations_pending_target ON invitations (org_id, email) WHERE status = 'pending';
CREATE INDEX idx_invitations_org_status ON invitations (org_id, status, expires_at);

CREATE TABLE teams (
    team_id TEXT PRIMARY KEY CHECK (
        length(team_id) = 36 AND substr(team_id, 1, 4) = 'team'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 120),
    slug TEXT NOT NULL CHECK (length(slug) BETWEEN 1 AND 63 AND slug = lower(trim(slug))),
    created_by_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    CONSTRAINT uq_teams_org_slug UNIQUE (org_id, slug),
    CONSTRAINT uq_teams_org_team UNIQUE (org_id, team_id)
);

CREATE INDEX idx_teams_org_id ON teams (org_id, created_at);

CREATE TABLE team_members (
    team_member_id TEXT PRIMARY KEY CHECK (
        length(team_member_id) = 36 AND substr(team_member_id, 1, 5) = 'tmem_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    team_id TEXT NOT NULL REFERENCES teams(team_id) ON DELETE CASCADE,
    membership_id TEXT NOT NULL,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    FOREIGN KEY (org_id, team_id) REFERENCES teams(org_id, team_id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, membership_id) REFERENCES memberships(org_id, membership_id) ON DELETE CASCADE,
    CONSTRAINT uq_team_members_team_membership UNIQUE (team_id, membership_id)
);

CREATE INDEX idx_team_members_org_id ON team_members (org_id, team_id);

CREATE TABLE reauthentication_grants (
    grant_id TEXT PRIMARY KEY CHECK (
        length(grant_id) = 36 AND substr(grant_id, 1, 4) = 'rag_'
    ),
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES login_sessions(session_id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (length(purpose) BETWEEN 1 AND 64),
    token_hash TEXT NOT NULL CHECK (length(token_hash) BETWEEN 1 AND 128),
    expires_at TEXT NOT NULL CHECK (length(expires_at) = 24),
    consumed_at TEXT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    CONSTRAINT uq_reauthentication_grants_token UNIQUE (token_hash)
);

CREATE INDEX idx_reauthentication_grants_user_state ON reauthentication_grants (user_id, session_id, consumed_at, expires_at);

CREATE TABLE device_authorizations (
    device_authorization_id TEXT PRIMARY KEY CHECK (
        length(device_authorization_id) = 36 AND substr(device_authorization_id, 1, 4) = 'dev_'
    ),
    user_code_hash TEXT NOT NULL CHECK (length(user_code_hash) BETWEEN 1 AND 128),
    device_code_hash TEXT NOT NULL CHECK (length(device_code_hash) BETWEEN 1 AND 128),
    code_challenge TEXT NOT NULL CHECK (length(code_challenge) BETWEEN 43 AND 128),
    code_challenge_method TEXT NOT NULL CHECK (code_challenge_method = 'S256'),
    device_label TEXT NOT NULL CHECK (length(device_label) BETWEEN 1 AND 120),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'consumed', 'expired', 'revoked')),
    user_id TEXT REFERENCES users(user_id) ON DELETE SET NULL,
    session_id TEXT REFERENCES login_sessions(session_id) ON DELETE SET NULL,
    expires_at TEXT NOT NULL CHECK (length(expires_at) = 24),
    approved_at TEXT,
    consumed_at TEXT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    CONSTRAINT uq_device_authorizations_user_code UNIQUE (user_code_hash),
    CONSTRAINT uq_device_authorizations_device_code UNIQUE (device_code_hash),
    CHECK ((status = 'approved' AND user_id IS NOT NULL AND approved_at IS NOT NULL) OR (status <> 'approved' AND user_id IS NULL AND approved_at IS NULL))
);

CREATE INDEX idx_device_authorizations_status_expiry ON device_authorizations (status, expires_at);

CREATE TABLE security_events (
    event_id TEXT PRIMARY KEY CHECK (
        length(event_id) = 36 AND substr(event_id, 1, 4) = 'sec_'
    ),
    org_id TEXT REFERENCES organizations(org_id) ON DELETE SET NULL,
    actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'service_account', 'support', 'system', 'anonymous')),
    actor_id TEXT,
    effective_user_id TEXT,
    session_id TEXT,
    device_id TEXT,
    action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 128),
    resource_type TEXT NOT NULL CHECK (length(resource_type) BETWEEN 1 AND 64),
    resource_id TEXT,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
    reason TEXT CHECK (reason IS NULL OR length(reason) <= 96),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 255),
    correlation_id TEXT NOT NULL CHECK (length(correlation_id) BETWEEN 1 AND 255),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24)
);

CREATE INDEX idx_security_events_org_time ON security_events (org_id, created_at DESC);
CREATE INDEX idx_security_events_actor_time ON security_events (actor_id, created_at DESC);
CREATE INDEX idx_security_events_action_time ON security_events (action, created_at DESC);

CREATE TRIGGER security_events_no_update
BEFORE UPDATE ON security_events
BEGIN
    SELECT RAISE(ABORT, 'security events are immutable');
END;

CREATE TRIGGER security_events_no_delete
BEFORE DELETE ON security_events
BEGIN
    SELECT RAISE(ABORT, 'security events are immutable');
END;
