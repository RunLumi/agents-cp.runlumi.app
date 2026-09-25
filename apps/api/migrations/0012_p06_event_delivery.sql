-- 0012_p06_event_delivery.sql — P06 durable webhook endpoints and signed
-- delivery, notification projections/preferences/delivery, and the typed P06
-- job queue envelope.
--
-- Forward-only; apply after 0011_p06_automations.sql.
--
-- F17/P06: delivery is AT-LEAST-ONCE with a stable event ID. A retry keeps the
-- same logical delivery and event ID but appends a new attempt. An authorized
-- replay creates a SUCCESSOR logical delivery linked by replay_of_delivery_id;
-- it never edits or resets the original.
--
-- The P01 `outbox_events.delivery_status` describes the SOURCE BUSINESS EVENT
-- and is never reused as per-endpoint webhook delivery state.
--
-- No plaintext secret, provider credential, prompt, response, or raw tool
-- argument is stored here. Webhook secrets are encrypted ciphertext; the
-- plaintext is returned once at creation/rotation and never persisted.

--------------------------------------------------------------------------------
-- Webhook endpoints
--------------------------------------------------------------------------------
CREATE TABLE webhook_endpoints (
    endpoint_id TEXT PRIMARY KEY CHECK (
        length(endpoint_id) = 36 AND substr(endpoint_id, 1, 4) = 'whe_'
    ),
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 160),
    description TEXT CHECK (description IS NULL OR length(description) <= 2000),
    -- SSRF-validated HTTPS destination. Ports/userinfo/private ranges are
    -- rejected at creation, update, test, and delivery time.
    url TEXT NOT NULL CHECK (length(url) BETWEEN 1 AND 2048),
    -- Exact finite set of subscribed event types. Wildcards are NOT accepted.
    subscribed_event_types_json TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(subscribed_event_types_json) AND json_valid(subscribed_event_types_json) = 1),
    current_secret_version_id TEXT,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    max_attempts INTEGER NOT NULL DEFAULT 8 CHECK (max_attempts BETWEEN 1 AND 8),
    base_delay_seconds INTEGER NOT NULL DEFAULT 30 CHECK (base_delay_seconds BETWEEN 1 AND 3600),
    max_delay_seconds INTEGER NOT NULL DEFAULT 86400 CHECK (max_delay_seconds BETWEEN 1 AND 86400),
    replay_window_seconds INTEGER NOT NULL DEFAULT 300
        CHECK (replay_window_seconds BETWEEN 30 AND 3600),
    auto_disable_enabled INTEGER NOT NULL DEFAULT 0 CHECK (auto_disable_enabled IN (0, 1)),
    auto_disable_threshold INTEGER NOT NULL DEFAULT 10
        CHECK (auto_disable_threshold BETWEEN 10 AND 100),
    consecutive_terminal_failures INTEGER NOT NULL DEFAULT 0
        CHECK (consecutive_terminal_failures >= 0),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    CHECK (max_delay_seconds >= base_delay_seconds)
);
CREATE INDEX idx_webhook_endpoints_org ON webhook_endpoints(org_id, enabled, updated_at DESC);
CREATE INDEX idx_webhook_endpoints_auto_disable
    ON webhook_endpoints(consecutive_terminal_failures)
    WHERE enabled = 1 AND auto_disable_enabled = 1;

-- Guard against wildcard subscription (bounded exact-match dotted names only).
CREATE TRIGGER trg_webhook_endpoints_no_wildcard
BEFORE INSERT ON webhook_endpoints
FOR EACH ROW WHEN NEW.subscribed_event_types_json LIKE '%*%'
BEGIN
    SELECT RAISE(ABORT, 'webhook subscription wildcard rejected');
END;
CREATE TRIGGER trg_webhook_endpoints_no_wildcard_update
BEFORE UPDATE OF subscribed_event_types_json ON webhook_endpoints
FOR EACH ROW WHEN NEW.subscribed_event_types_json LIKE '%*%'
BEGIN
    SELECT RAISE(ABORT, 'webhook subscription wildcard rejected');
END;

--------------------------------------------------------------------------------
-- Encrypted webhook secret versions (plaintext is never persisted)
--------------------------------------------------------------------------------
CREATE TABLE webhook_secrets (
    secret_version_id TEXT PRIMARY KEY CHECK (
        length(secret_version_id) = 36 AND substr(secret_version_id, 1, 4) = 'whs_'
    ),
    endpoint_id TEXT NOT NULL REFERENCES webhook_endpoints(endpoint_id) ON DELETE CASCADE,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    -- AES-GCM ciphertext + nonce. The plaintext exists only in the creation/
    -- rotation response and is never written to D1.
    ciphertext BLOB NOT NULL,
    nonce BLOB NOT NULL,
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) BETWEEN 16 AND 128),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    rotated_at TEXT CHECK (rotated_at IS NULL OR length(rotated_at) = 24),
    revoked_at TEXT CHECK (revoked_at IS NULL OR length(revoked_at) = 24)
);
CREATE UNIQUE INDEX ux_webhook_secrets_endpoint_version
    ON webhook_secrets(endpoint_id, version);
CREATE INDEX idx_webhook_secrets_endpoint ON webhook_secrets(endpoint_id, revoked_at);
-- Backfill the endpoint's current secret pointer once the secret exists.
CREATE TRIGGER trg_webhook_secrets_set_current
AFTER INSERT ON webhook_secrets
FOR EACH ROW
BEGIN
    UPDATE webhook_endpoints
    SET current_secret_version_id = NEW.secret_version_id
    WHERE endpoint_id = NEW.endpoint_id;
END;

--------------------------------------------------------------------------------
-- Logical webhook deliveries (stable event ID, at-least-once)
--------------------------------------------------------------------------------
CREATE TABLE webhook_deliveries (
    delivery_id TEXT PRIMARY KEY CHECK (
        length(delivery_id) = 36 AND substr(delivery_id, 1, 4) = 'whd_'
    ),
    endpoint_id TEXT NOT NULL REFERENCES webhook_endpoints(endpoint_id) ON DELETE RESTRICT,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE RESTRICT,
    -- The stable P01 event ID is REPEATED across every retry and replay.
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 96),
    -- The exact serialized UTF-8 body is stored ONCE per logical delivery and
    -- reused byte-for-byte for every attempt so signatures stay verifiable.
    body BLOB NOT NULL,
    body_hash TEXT NOT NULL CHECK (length(body_hash) BETWEEN 16 AND 128),
    -- Secret version captured when the logical delivery was created. Retries use
    -- it; an explicit replay after rotation creates a successor with the
    -- CURRENT endpoint secret version.
    secret_version_id TEXT NOT NULL REFERENCES webhook_secrets(secret_version_id) ON DELETE RESTRICT,
    signature_key_id TEXT NOT NULL CHECK (length(signature_key_id) BETWEEN 1 AND 128),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (
        state IN ('pending', 'queued', 'delivering', 'delivered', 'retry_wait',
                  'dead_letter', 'cancelled')
    ),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at TEXT CHECK (next_attempt_at IS NULL OR length(next_attempt_at) = 24),
    delivered_at TEXT CHECK (delivered_at IS NULL OR length(delivered_at) = 24),
    last_error_code TEXT CHECK (last_error_code IS NULL OR length(last_error_code) <= 96),
    -- An authorized replay always creates a SUCCEESSOR logical delivery.
    replay_of_delivery_id TEXT REFERENCES webhook_deliveries(delivery_id) ON DELETE RESTRICT,
    replay_generation INTEGER NOT NULL DEFAULT 0 CHECK (replay_generation >= 0),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
-- One logical delivery per endpoint/event/replay generation.
CREATE UNIQUE INDEX ux_webhook_deliveries_endpoint_event_gen
    ON webhook_deliveries(endpoint_id, event_id, replay_generation);
CREATE INDEX idx_webhook_deliveries_due
    ON webhook_deliveries(state, next_attempt_at)
    WHERE state IN ('pending', 'queued', 'retry_wait');
CREATE INDEX idx_webhook_deliveries_endpoint_history
    ON webhook_deliveries(endpoint_id, created_at DESC);
CREATE INDEX idx_webhook_deliveries_org_state ON webhook_deliveries(org_id, state, created_at DESC);
-- Recursive-delivery guard: delivery/endpoint/notification-delivery events are
-- never fanned out to the same webhook endpoint.
CREATE TRIGGER trg_webhook_deliveries_no_recursive_fanout
BEFORE INSERT ON webhook_deliveries
FOR EACH ROW WHEN
    NEW.event_type LIKE 'webhook.delivery_%'
    OR NEW.event_type LIKE 'webhook.endpoint_%'
    OR NEW.event_type LIKE 'notification.delivery_%'
    OR NEW.event_type = 'webhook.test.v1'
BEGIN
    SELECT RAISE(ABORT, 'recursive webhook fanout rejected');
END;

--------------------------------------------------------------------------------
-- Append-only delivery attempts
--------------------------------------------------------------------------------
CREATE TABLE webhook_delivery_attempts (
    attempt_id TEXT PRIMARY KEY CHECK (
        length(attempt_id) = 36 AND substr(attempt_id, 1, 4) = 'wha_'
    ),
    delivery_id TEXT NOT NULL REFERENCES webhook_deliveries(delivery_id) ON DELETE RESTRICT,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE RESTRICT,
    attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
    job_id TEXT,
    outcome TEXT NOT NULL CHECK (
        outcome IN ('delivering', 'delivered', 'retry_scheduled', 'dead_lettered', 'cancelled')
    ),
    http_status INTEGER CHECK (http_status IS NULL OR http_status BETWEEN 100 AND 599),
    stable_error_code TEXT CHECK (stable_error_code IS NULL OR length(stable_error_code) <= 96),
    latency_ms INTEGER CHECK (latency_ms IS NULL OR latency_ms >= 0),
    started_at TEXT NOT NULL CHECK (length(started_at) = 24),
    completed_at TEXT CHECK (completed_at IS NULL OR length(completed_at) = 24)
);
CREATE UNIQUE INDEX ux_webhook_delivery_attempts_number
    ON webhook_delivery_attempts(delivery_id, attempt_number);
CREATE INDEX idx_webhook_delivery_attempts_delivery
    ON webhook_delivery_attempts(delivery_id, started_at DESC);

--------------------------------------------------------------------------------
-- Notification preferences (informational only; security events are mandatory)
--------------------------------------------------------------------------------
CREATE TABLE notification_preferences (
    preference_id TEXT PRIMARY KEY CHECK (length(preference_id) = 36),
    org_id TEXT REFERENCES organizations(org_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    channel TEXT NOT NULL CHECK (channel IN ('in_app', 'email')),
    -- Exact event-type opt-outs. Mandatory security event families are rejected.
    disabled_event_types_json TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(disabled_event_types_json)),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    UNIQUE (org_id, user_id, channel)
);
CREATE UNIQUE INDEX ux_notification_preferences_user_channel
    ON notification_preferences(user_id, channel) WHERE org_id IS NULL;
-- F17: critical security events may be mandatory and cannot be fully disabled.
CREATE TRIGGER trg_notification_preferences_no_security_optout
BEFORE INSERT ON notification_preferences
FOR EACH ROW WHEN
    NEW.disabled_event_types_json LIKE '%auth.%'
    OR NEW.disabled_event_types_json LIKE '%device.revoked%'
    OR NEW.disabled_event_types_json LIKE '%organization.suspended%'
BEGIN
    SELECT RAISE(ABORT, 'mandatory security notification opt-out rejected');
END;
CREATE TRIGGER trg_notification_preferences_no_security_optout_update
BEFORE UPDATE OF disabled_event_types_json ON notification_preferences
FOR EACH ROW WHEN
    NEW.disabled_event_types_json LIKE '%auth.%'
    OR NEW.disabled_event_types_json LIKE '%device.revoked%'
    OR NEW.disabled_event_types_json LIKE '%organization.suspended%'
BEGIN
    SELECT RAISE(ABORT, 'mandatory security notification opt-out rejected');
END;

--------------------------------------------------------------------------------
-- Durable in-app notification projections
--------------------------------------------------------------------------------
CREATE TABLE notifications (
    notification_id TEXT PRIMARY KEY CHECK (
        length(notification_id) = 36 AND substr(notification_id, 1, 4) = 'ntf_'
    ),
    org_id TEXT REFERENCES organizations(org_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 96),
    category TEXT NOT NULL CHECK (
        category IN ('security', 'billing', 'automation', 'policy', 'operational')
    ),
    mandatory INTEGER NOT NULL DEFAULT 0 CHECK (mandatory IN (0, 1)),
    -- Bounded rendered metadata only. Raw prompts/responses/arguments/secrets
    -- are prohibited regardless of the content logging mode.
    body_json TEXT NOT NULL CHECK (json_valid(body_json) AND length(body_json) <= 32768),
    dedupe_key TEXT NOT NULL CHECK (length(dedupe_key) BETWEEN 1 AND 255),
    state TEXT NOT NULL DEFAULT 'unread' CHECK (state IN ('unread', 'read', 'archived')),
    read_at TEXT CHECK (read_at IS NULL OR length(read_at) = 24),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
CREATE UNIQUE INDEX ux_notifications_dedupe ON notifications(user_id, dedupe_key);
-- Cursor pagination keyset: (created_at, notification_id) DESC.
CREATE INDEX idx_notifications_inbox ON notifications(user_id, created_at DESC, notification_id DESC);
CREATE INDEX idx_notifications_unread ON notifications(user_id, created_at DESC) WHERE state = 'unread';

--------------------------------------------------------------------------------
-- Notification channel delivery state (email/in-app)
--------------------------------------------------------------------------------
CREATE TABLE notification_deliveries (
    delivery_id TEXT PRIMARY KEY CHECK (
        length(delivery_id) = 36 AND substr(delivery_id, 1, 4) = 'ndl_'
    ),
    notification_id TEXT NOT NULL REFERENCES notifications(notification_id) ON DELETE CASCADE,
    org_id TEXT REFERENCES organizations(org_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    channel TEXT NOT NULL CHECK (channel IN ('in_app', 'email')),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (
        state IN ('pending', 'queued', 'delivered', 'retry_wait', 'dead_letter', 'cancelled')
    ),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at TEXT CHECK (next_attempt_at IS NULL OR length(next_attempt_at) = 24),
    delivered_at TEXT CHECK (delivered_at IS NULL OR length(delivered_at) = 24),
    last_error_code TEXT CHECK (last_error_code IS NULL OR length(last_error_code) <= 96),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24),
    UNIQUE (notification_id, channel)
);
CREATE INDEX idx_notification_deliveries_due
    ON notification_deliveries(state, next_attempt_at)
    WHERE state IN ('pending', 'queued', 'retry_wait');

--------------------------------------------------------------------------------
-- P06 typed job queue envelope with D1-enforced dedupe (separate from outbox)
--------------------------------------------------------------------------------
CREATE TABLE queue_job_envelopes (
    job_id TEXT PRIMARY KEY CHECK (
        length(job_id) = 36 AND substr(job_id, 1, 4) = 'job_'
    ),
    job_type TEXT NOT NULL CHECK (
        job_type IN ('automation.generate_occurrence', 'automation.dispatch',
                     'automation.expire_lease', 'webhook.deliver', 'notification.deliver',
                     'billing.sync', 'license.issue', 'export.run', 'deletion.run')
    ),
    schema_version INTEGER NOT NULL DEFAULT 1 CHECK (schema_version > 0),
    -- org_id may be NULL only for platform jobs.
    org_id TEXT REFERENCES organizations(org_id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL CHECK (length(subject_type) BETWEEN 1 AND 64),
    subject_id TEXT NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 64),
    subject_version INTEGER CHECK (subject_version IS NULL OR subject_version > 0),
    dedupe_key TEXT NOT NULL CHECK (length(dedupe_key) BETWEEN 1 AND 255),
    event_id TEXT,
    request_id TEXT,
    correlation_id TEXT,
    -- Bounded metadata-only payload reference. NEVER a prompt, secret, lease
    -- token, provider payload, or unbounded content.
    payload_ref TEXT,
    state TEXT NOT NULL DEFAULT 'queued' CHECK (
        state IN ('queued', 'running', 'retry_wait', 'succeeded', 'dead_letter', 'cancelled')
    ),
    attempt INTEGER NOT NULL DEFAULT 1 CHECK (attempt > 0),
    lease_version INTEGER NOT NULL DEFAULT 0 CHECK (lease_version >= 0),
    lease_expires_at TEXT CHECK (lease_expires_at IS NULL OR length(lease_expires_at) = 24),
    next_attempt_at TEXT CHECK (next_attempt_at IS NULL OR length(next_attempt_at) = 24),
    last_error_code TEXT CHECK (last_error_code IS NULL OR length(last_error_code) <= 96),
    replay_of_job_id TEXT REFERENCES queue_job_envelopes(job_id) ON DELETE RESTRICT,
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 24)
);
-- Dedupe is enforced by this unique constraint plus a durable side-effect CAS,
-- NOT by Cloudflare Queue delivery guarantees.
CREATE UNIQUE INDEX ux_queue_job_envelopes_dedupe
    ON queue_job_envelopes(job_type, COALESCE(org_id, ''), dedupe_key, generation);
CREATE INDEX idx_queue_job_envelopes_due
    ON queue_job_envelopes(state, next_attempt_at)
    WHERE state IN ('queued', 'retry_wait');
CREATE INDEX idx_queue_job_envelopes_lease
    ON queue_job_envelopes(state, lease_expires_at) WHERE state = 'running';
CREATE INDEX idx_queue_job_envelopes_org ON queue_job_envelopes(org_id, created_at DESC);
