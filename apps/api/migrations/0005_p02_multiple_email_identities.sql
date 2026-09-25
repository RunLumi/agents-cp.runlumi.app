-- Allow one user to attach multiple verified email identities. The provider
-- subject remains globally unique, while the old user/provider constraint
-- incorrectly limited every account to one email address.
CREATE TABLE identities_new (
    identity_id TEXT PRIMARY KEY CHECK (
        length(identity_id) = 36 AND substr(identity_id, 1, 4) = 'idn_'
    ),
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 64),
    provider_subject TEXT NOT NULL CHECK (length(provider_subject) BETWEEN 1 AND 320),
    email TEXT NOT NULL CHECK (length(email) BETWEEN 3 AND 320 AND email = lower(trim(email))),
    email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    CONSTRAINT uq_identities_provider_subject UNIQUE (provider, provider_subject)
);

INSERT INTO identities_new (
    identity_id, user_id, provider, provider_subject, email, email_verified, created_at
)
SELECT identity_id, user_id, provider, provider_subject, email, email_verified, created_at
FROM identities;

DROP TABLE identities;
ALTER TABLE identities_new RENAME TO identities;

CREATE INDEX idx_identities_user_id ON identities (user_id);
CREATE INDEX idx_identities_email ON identities (email);
