-- Bounded authentication rate-limit buckets. The key is a server-side digest;
-- raw email addresses and IP addresses are not persisted by this table.
CREATE TABLE auth_rate_limits (
    bucket_key TEXT PRIMARY KEY CHECK (length(bucket_key) BETWEEN 1 AND 128),
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    window_started_at TEXT NOT NULL CHECK (length(window_started_at) = 24),
    expires_at TEXT NOT NULL CHECK (length(expires_at) = 24)
);

CREATE INDEX idx_auth_rate_limits_expiry ON auth_rate_limits (expires_at);
