-- A consumed device authorization retains the approved user/session binding for
-- audit and replay diagnostics. The original check only allowed user_id on
-- the approved state, making the atomic consume transition fail.
CREATE TABLE device_authorizations_new (
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
    CHECK (
        (status IN ('approved', 'consumed') AND user_id IS NOT NULL AND approved_at IS NOT NULL)
        OR (status IN ('pending', 'expired', 'revoked') AND user_id IS NULL AND approved_at IS NULL)
    )
);

INSERT INTO device_authorizations_new (
    device_authorization_id, user_code_hash, device_code_hash, code_challenge,
    code_challenge_method, device_label, status, user_id, session_id,
    expires_at, approved_at, consumed_at, created_at
)
SELECT device_authorization_id, user_code_hash, device_code_hash, code_challenge,
       code_challenge_method, device_label, status, user_id, session_id,
       expires_at, approved_at, consumed_at, created_at
FROM device_authorizations;

DROP TABLE device_authorizations;
ALTER TABLE device_authorizations_new RENAME TO device_authorizations;

CREATE INDEX idx_device_authorizations_status_expiry ON device_authorizations (status, expires_at);
