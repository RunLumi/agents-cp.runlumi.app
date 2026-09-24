-- Initial P01 infrastructure schema. Wrangler owns its own migration ledger.
-- Non-organization operations use an empty organization_id sentinel so the
-- uniqueness constraint also applies when organization_id is absent.
CREATE TABLE idempotency_records (
    principal_id TEXT NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 255),
    organization_id TEXT NOT NULL DEFAULT '' CHECK (length(organization_id) <= 255),
    method TEXT NOT NULL CHECK (
        length(method) BETWEEN 1 AND 16
        AND method = upper(method)
    ),
    path TEXT NOT NULL CHECK (
        length(path) BETWEEN 1 AND 2048
        AND substr(path, 1, 1) = '/'
    ),
    key_digest TEXT NOT NULL CHECK (length(key_digest) BETWEEN 1 AND 128),
    request_fingerprint TEXT NOT NULL CHECK (length(request_fingerprint) BETWEEN 1 AND 128),
    state TEXT NOT NULL CHECK (state IN ('pending', 'completed')),
    response_status INTEGER,
    response_body TEXT,
    expires_at TEXT NOT NULL CHECK (
        length(expires_at) = 24
        AND expires_at GLOB '????-??-??T??:??:??.???Z'
    ),
    claim_token TEXT,
    CONSTRAINT uq_idempotency_records_principal_organization_method_path_key_digest
        UNIQUE (principal_id, organization_id, method, path, key_digest),
    CHECK (
        (state = 'pending'
            AND response_status IS NULL
            AND response_body IS NULL
            AND claim_token IS NOT NULL
            AND length(claim_token) BETWEEN 1 AND 255)
        OR
        (state = 'completed'
            AND response_status BETWEEN 200 AND 299
            AND response_body IS NOT NULL
            AND json_valid(response_body)
            AND claim_token IS NULL)
    )
);

CREATE INDEX idx_idempotency_records_expires_at
    ON idempotency_records (expires_at);

CREATE TABLE outbox_events (
    event_id TEXT PRIMARY KEY CHECK (
        length(event_id) = 36
        AND substr(event_id, 1, 4) = 'evt_'
    ),
    event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 255),
    occurred_at TEXT NOT NULL CHECK (
        length(occurred_at) = 24
        AND occurred_at GLOB '????-??-??T??:??:??.???Z'
    ),
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 255),
    correlation_id TEXT NOT NULL CHECK (length(correlation_id) BETWEEN 1 AND 255),
    organization_id TEXT NOT NULL DEFAULT '' CHECK (length(organization_id) <= 255),
    envelope_json TEXT NOT NULL CHECK (
        json_valid(envelope_json)
        AND json_extract(envelope_json, '$.event_id') = event_id
        AND json_extract(envelope_json, '$.event_type') = event_type
    ),
    delivery_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (delivery_status IN ('pending', 'queued', 'delivered', 'dead_letter')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at TEXT,
    last_error_code TEXT CHECK (last_error_code IS NULL OR length(last_error_code) <= 128),
    queued_at TEXT,
    delivered_at TEXT,
    CONSTRAINT chk_outbox_events_delivery_state CHECK (
        (delivery_status = 'pending' AND next_attempt_at IS NOT NULL AND delivered_at IS NULL)
        OR (delivery_status = 'queued' AND next_attempt_at IS NULL AND delivered_at IS NULL)
        OR (delivery_status = 'delivered' AND next_attempt_at IS NULL AND delivered_at IS NOT NULL)
        OR (delivery_status = 'dead_letter' AND next_attempt_at IS NULL AND delivered_at IS NULL)
    )
);

CREATE INDEX idx_outbox_events_delivery_status_next_attempt_at
    ON outbox_events (delivery_status, next_attempt_at);
