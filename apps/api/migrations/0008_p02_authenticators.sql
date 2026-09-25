-- P02-CR-002 additive authenticator credentials and recovery state.
-- Identity remains the email/provider boundary; passkeys and passwords are
-- separate credentials. No private key, raw password, or raw recovery token is
-- stored in these tables.

CREATE TABLE passkey_credentials (
    passkey_id TEXT PRIMARY KEY CHECK (
        length(passkey_id) = 36 AND substr(passkey_id, 1, 4) = 'psk_'
    ),
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL CHECK (length(credential_id) BETWEEN 1 AND 2048),
    public_key_cose TEXT NOT NULL CHECK (length(public_key_cose) BETWEEN 1 AND 4096),
    sign_count INTEGER NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    transports_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(transports_json)),
    backup_eligible INTEGER CHECK (backup_eligible IS NULL OR backup_eligible IN (0, 1)),
    backup_state INTEGER CHECK (backup_state IS NULL OR backup_state IN (0, 1)),
    label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 120),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    last_used_at TEXT,
    revoked_at TEXT,
    CONSTRAINT uq_passkey_credentials_credential_id UNIQUE (credential_id)
);

CREATE INDEX idx_passkey_credentials_user_state
    ON passkey_credentials(user_id, revoked_at, created_at DESC);
CREATE INDEX idx_passkey_credentials_credential
    ON passkey_credentials(credential_id);

CREATE TABLE webauthn_ceremonies (
    ceremony_id TEXT PRIMARY KEY CHECK (
        length(ceremony_id) = 36 AND substr(ceremony_id, 1, 4) = 'cer_'
    ),
    kind TEXT NOT NULL CHECK (
        kind IN ('passkey_signup', 'passkey_login', 'passkey_add', 'reauthenticate')
    ),
    user_id TEXT REFERENCES users(user_id) ON DELETE CASCADE,
    pending_user_id TEXT,
    email TEXT,
    display_name TEXT,
    session_id TEXT REFERENCES login_sessions(session_id) ON DELETE CASCADE,
    state_json TEXT NOT NULL CHECK (json_valid(state_json)),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'consumed', 'expired', 'revoked')
    ),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0 AND attempts <= 10),
    expires_at TEXT NOT NULL CHECK (length(expires_at) = 24),
    consumed_at TEXT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    CHECK (
        (status = 'consumed' AND consumed_at IS NOT NULL)
        OR (status <> 'consumed' AND consumed_at IS NULL)
    ),
    CHECK (
        (kind = 'passkey_signup' AND pending_user_id IS NOT NULL AND user_id IS NULL)
        OR (kind = 'passkey_login' AND pending_user_id IS NULL)
        OR (kind IN ('passkey_add', 'reauthenticate') AND user_id IS NOT NULL AND pending_user_id IS NULL)
    )
);

CREATE INDEX idx_webauthn_ceremonies_state
    ON webauthn_ceremonies(status, expires_at, created_at DESC);
CREATE INDEX idx_webauthn_ceremonies_user
    ON webauthn_ceremonies(user_id, kind, status, expires_at);

CREATE TABLE password_credentials (
    user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    encoded_hash TEXT NOT NULL CHECK (length(encoded_hash) BETWEEN 32 AND 512),
    algorithm TEXT NOT NULL CHECK (algorithm = 'argon2id'),
    memory_kib INTEGER NOT NULL CHECK (memory_kib >= 19456),
    time_cost INTEGER NOT NULL CHECK (time_cost >= 2),
    parallelism INTEGER NOT NULL CHECK (parallelism = 1),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);

CREATE TABLE password_recovery_challenges (
    challenge_id TEXT PRIMARY KEY CHECK (
        length(challenge_id) = 36 AND substr(challenge_id, 1, 4) = 'rec_'
    ),
    user_id TEXT REFERENCES users(user_id) ON DELETE CASCADE,
    email TEXT NOT NULL CHECK (length(email) BETWEEN 3 AND 320 AND email = lower(trim(email))),
    code_hash TEXT NOT NULL CHECK (length(code_hash) BETWEEN 1 AND 128),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'consumed', 'expired', 'revoked')
    ),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0 AND attempts <= 10),
    expires_at TEXT NOT NULL CHECK (length(expires_at) = 24),
    consumed_at TEXT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    CHECK (
        (status = 'consumed' AND consumed_at IS NOT NULL)
        OR (status <> 'consumed' AND consumed_at IS NULL)
    )
);

CREATE INDEX idx_password_recovery_state
    ON password_recovery_challenges(status, expires_at, created_at DESC);
CREATE INDEX idx_password_recovery_user
    ON password_recovery_challenges(user_id, status, expires_at);
