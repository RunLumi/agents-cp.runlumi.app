-- Add the one-time challenge kind used to prove ownership of a new email
-- identity before linking it. This is a forward migration because 0002 may
-- already be applied in development or preview environments.
CREATE TABLE auth_challenges_new (
    challenge_id TEXT PRIMARY KEY CHECK (
        length(challenge_id) = 36 AND substr(challenge_id, 1, 4) = 'idn_'
    ),
    user_id TEXT REFERENCES users(user_id) ON DELETE CASCADE,
    email TEXT NOT NULL CHECK (length(email) BETWEEN 3 AND 320 AND email = lower(trim(email))),
    kind TEXT NOT NULL CHECK (kind IN ('verification', 'login', 'identity_link')),
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

INSERT INTO auth_challenges_new (
    challenge_id, user_id, email, kind, code_hash, status,
    attempts, expires_at, consumed_at, created_at
)
SELECT
    challenge_id, user_id, email, kind, code_hash, status,
    attempts, expires_at, consumed_at, created_at
FROM auth_challenges;

DROP TABLE auth_challenges;
ALTER TABLE auth_challenges_new RENAME TO auth_challenges;

CREATE UNIQUE INDEX ux_auth_challenges_code_hash ON auth_challenges (code_hash);
CREATE INDEX idx_auth_challenges_lookup ON auth_challenges (email, kind, status, expires_at);
