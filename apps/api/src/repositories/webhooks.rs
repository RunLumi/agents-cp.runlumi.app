//! D1 persistence for the frozen P06 `0012_p06_event_delivery.sql` schema.
//!
//! Layering follows `repositories/runs.rs`: this module owns SQL and row
//! mapping, binds every dynamic value, and accepts only trusted values from the
//! HTTP/domain boundary. Authorization stays outside it.
//!
//! Invariants this repository exists to make impossible to get wrong:
//!
//! * Fan-out requires `event.organization_id == endpoint.org_id` and an exact
//!   subscribed event type. There is no wildcard path.
//! * A logical delivery keeps one stable P01 `event_id` and one exact body
//!   across every retry. `ux_webhook_deliveries_endpoint_event_gen` makes a
//!   replay idempotent.
//! * Every delivery state change is a compare-and-set on
//!   `(delivery_id, state, version)`. A concurrent worker cannot overwrite a
//!   newer transition.
//! * Job claiming is an atomic CAS on job ID + attempt + state + lease version,
//!   and `ux_queue_job_envelopes_dedupe` is the D1-level dedupe.
//! * The plaintext webhook secret is never persisted. Only AES-GCM ciphertext,
//!   its nonce, and a non-reversible fingerprint reach D1.
//!
//! Binary columns: `0012` declares `body`, `ciphertext`, and `nonce` with BLOB
//! affinity. The shared `adapters::d1::BindValue` cannot bind an `ArrayBuffer`,
//! so `body` holds its exact UTF-8 JSON text and `ciphertext`/`nonce` hold
//! base64. Both round-trip byte-exactly. See the P06-BE-02 handoff for the
//! optional `BindValue::Blob` upgrade.

use std::fmt;

use serde::{Deserialize, Serialize};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::{EventId, Timestamp},
};

pub const WEBHOOK_TEST_EVENT_TYPE: &str = "webhook.test.v1";
pub const MAX_SUBSCRIPTION_EVENT_TYPES: usize = 64;
pub const MAX_NOTIFICATION_BODY_BYTES: usize = 32 * 1024;
pub const MAX_JOB_PAYLOAD_REF_CHARS: usize = 255;
pub const MAX_DEDUPE_KEY_CHARS: usize = 255;

// -----------------------------------------------------------------------------
// States
// -----------------------------------------------------------------------------

/// `webhook_deliveries.state`. `Pending` is created by fan-out, `Queued` once a
/// `webhook.deliver` job row exists, `Delivering` while an attempt is in
/// flight, and the remaining values are terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebhookDeliveryState {
    Pending,
    Queued,
    Delivering,
    Delivered,
    RetryWait,
    DeadLetter,
    Cancelled,
}

impl WebhookDeliveryState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Queued => "queued",
            Self::Delivering => "delivering",
            Self::Delivered => "delivered",
            Self::RetryWait => "retry_wait",
            Self::DeadLetter => "dead_letter",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "queued" => Some(Self::Queued),
            "delivering" => Some(Self::Delivering),
            "delivered" => Some(Self::Delivered),
            "retry_wait" => Some(Self::RetryWait),
            "dead_letter" => Some(Self::DeadLetter),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }

    /// Terminal rows are immutable history. A replay creates a successor
    /// instead of editing one.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Delivered | Self::DeadLetter | Self::Cancelled)
    }

    /// States a `webhook.deliver` job may still claim.
    pub const fn is_claimable(self) -> bool {
        matches!(self, Self::Pending | Self::Queued | Self::RetryWait)
    }
}

/// `queue_job_envelopes.state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueJobState {
    Queued,
    Running,
    RetryWait,
    Succeeded,
    DeadLetter,
    Cancelled,
}

impl QueueJobState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::RetryWait => "retry_wait",
            Self::Succeeded => "succeeded",
            Self::DeadLetter => "dead_letter",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "queued" => Some(Self::Queued),
            "running" => Some(Self::Running),
            "retry_wait" => Some(Self::RetryWait),
            "succeeded" => Some(Self::Succeeded),
            "dead_letter" => Some(Self::DeadLetter),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::DeadLetter | Self::Cancelled)
    }
}

/// The frozen `queue_job_envelopes.job_type` vocabulary. A name outside this
/// list is a permanent failure, never a silently acknowledged message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobType {
    GenerateOccurrence,
    Dispatch,
    ExpireLease,
    WebhookDeliver,
    NotificationDeliver,
    BillingSync,
    LicenseIssue,
    ExportRun,
    DeletionRun,
}

impl JobType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GenerateOccurrence => "automation.generate_occurrence",
            Self::Dispatch => "automation.dispatch",
            Self::ExpireLease => "automation.expire_lease",
            Self::WebhookDeliver => "webhook.deliver",
            Self::NotificationDeliver => "notification.deliver",
            Self::BillingSync => "billing.sync",
            Self::LicenseIssue => "license.issue",
            Self::ExportRun => "export.run",
            Self::DeletionRun => "deletion.run",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "automation.generate_occurrence" => Some(Self::GenerateOccurrence),
            "automation.dispatch" => Some(Self::Dispatch),
            "automation.expire_lease" => Some(Self::ExpireLease),
            "webhook.deliver" => Some(Self::WebhookDeliver),
            "notification.deliver" => Some(Self::NotificationDeliver),
            "billing.sync" => Some(Self::BillingSync),
            "license.issue" => Some(Self::LicenseIssue),
            "export.run" => Some(Self::ExportRun),
            "deletion.run" => Some(Self::DeletionRun),
            _ => None,
        }
    }

    /// The two job types this packet consumes. Everything else is owned by
    /// another P06 packet and is acknowledged as unsupported here.
    pub const fn is_event_delivery(self) -> bool {
        matches!(self, Self::WebhookDeliver | Self::NotificationDeliver)
    }
}

/// `notifications.state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotificationState {
    Unread,
    Read,
    Archived,
}

impl NotificationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unread => "unread",
            Self::Read => "read",
            Self::Archived => "archived",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "unread" => Some(Self::Unread),
            "read" => Some(Self::Read),
            "archived" => Some(Self::Archived),
            _ => None,
        }
    }
}

/// `notification_deliveries.state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotificationDeliveryState {
    Pending,
    Queued,
    Delivered,
    RetryWait,
    DeadLetter,
    Cancelled,
}

impl NotificationDeliveryState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Queued => "queued",
            Self::Delivered => "delivered",
            Self::RetryWait => "retry_wait",
            Self::DeadLetter => "dead_letter",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "queued" => Some(Self::Queued),
            "delivered" => Some(Self::Delivered),
            "retry_wait" => Some(Self::RetryWait),
            "dead_letter" => Some(Self::DeadLetter),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }
}

/// The frozen `notifications.category` vocabulary.
pub const NOTIFICATION_CATEGORIES: [&str; 5] =
    ["security", "billing", "automation", "policy", "operational"];
/// The frozen channel vocabulary. Slack/Teams are explicitly out of contract.
pub const NOTIFICATION_CHANNELS: [&str; 2] = ["in_app", "email"];

// -----------------------------------------------------------------------------
// Records
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebhookEndpointRecord {
    pub endpoint_id: String,
    pub org_id: String,
    pub name: String,
    pub description: Option<String>,
    pub url: String,
    pub subscribed_event_types_json: String,
    pub current_secret_version_id: Option<String>,
    pub enabled: bool,
    pub max_attempts: i64,
    pub base_delay_seconds: i64,
    pub max_delay_seconds: i64,
    pub replay_window_seconds: i64,
    pub auto_disable_enabled: bool,
    pub auto_disable_threshold: i64,
    pub consecutive_terminal_failures: i64,
    pub version: i64,
    pub created_by_user_id: String,
    pub created_at: String,
    pub updated_at: String,
}

/// A secret version projection. `ciphertext` and `nonce` are base64 AES-GCM
/// material; the plaintext is never available to this layer at all.
#[derive(Clone, Deserialize, Serialize)]
pub struct WebhookSecretRecord {
    pub secret_version_id: String,
    pub endpoint_id: String,
    pub org_id: String,
    pub ciphertext: String,
    pub nonce: String,
    pub fingerprint: String,
    pub version: i64,
    pub created_at: String,
    pub rotated_at: Option<String>,
    pub revoked_at: Option<String>,
}

impl fmt::Debug for WebhookSecretRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookSecretRecord")
            .field("secret_version_id", &self.secret_version_id)
            .field("endpoint_id", &self.endpoint_id)
            .field("org_id", &self.org_id)
            .field("ciphertext", &"[redacted]")
            .field("nonce", &"[redacted]")
            .field("fingerprint", &self.fingerprint)
            .field("version", &self.version)
            .field("created_at", &self.created_at)
            .field("rotated_at", &self.rotated_at)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct WebhookDeliveryRecord {
    pub delivery_id: String,
    pub endpoint_id: String,
    pub org_id: String,
    pub event_id: String,
    pub event_type: String,
    /// The exact serialized P01 `EventEnvelope`. Metadata only by construction.
    pub body: String,
    pub body_hash: String,
    pub secret_version_id: String,
    pub signature_key_id: String,
    pub state: String,
    pub attempt_count: i64,
    pub next_attempt_at: Option<String>,
    pub delivered_at: Option<String>,
    pub last_error_code: Option<String>,
    pub replay_of_delivery_id: Option<String>,
    pub replay_generation: i64,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl fmt::Debug for WebhookDeliveryRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookDeliveryRecord")
            .field("delivery_id", &self.delivery_id)
            .field("endpoint_id", &self.endpoint_id)
            .field("org_id", &self.org_id)
            .field("event_id", &self.event_id)
            .field("event_type", &self.event_type)
            .field("body", &"[redacted]")
            .field("body_hash", &self.body_hash)
            .field("secret_version_id", &self.secret_version_id)
            .field("signature_key_id", &self.signature_key_id)
            .field("state", &self.state)
            .field("attempt_count", &self.attempt_count)
            .field("next_attempt_at", &self.next_attempt_at)
            .field("delivered_at", &self.delivered_at)
            .field("last_error_code", &self.last_error_code)
            .field("replay_of_delivery_id", &self.replay_of_delivery_id)
            .field("replay_generation", &self.replay_generation)
            .field("version", &self.version)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebhookDeliveryAttemptRecord {
    pub attempt_id: String,
    pub delivery_id: String,
    pub org_id: String,
    pub attempt_number: i64,
    pub job_id: Option<String>,
    pub outcome: String,
    pub http_status: Option<i64>,
    pub stable_error_code: Option<String>,
    pub latency_ms: Option<i64>,
    pub started_at: String,
    pub completed_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QueueJobRecord {
    pub job_id: String,
    pub job_type: String,
    pub schema_version: i64,
    pub org_id: Option<String>,
    pub subject_type: String,
    pub subject_id: String,
    pub subject_version: Option<i64>,
    pub dedupe_key: String,
    pub event_id: Option<String>,
    pub request_id: Option<String>,
    pub correlation_id: Option<String>,
    pub payload_ref: Option<String>,
    pub state: String,
    pub attempt: i64,
    pub lease_version: i64,
    pub lease_expires_at: Option<String>,
    pub next_attempt_at: Option<String>,
    pub last_error_code: Option<String>,
    pub replay_of_job_id: Option<String>,
    pub generation: i64,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NotificationRecord {
    pub notification_id: String,
    pub org_id: Option<String>,
    pub user_id: String,
    pub event_id: String,
    pub event_type: String,
    pub category: String,
    pub mandatory: bool,
    pub body_json: String,
    pub dedupe_key: String,
    pub state: String,
    pub read_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NotificationPreferenceRecord {
    pub preference_id: String,
    pub org_id: Option<String>,
    pub user_id: String,
    pub channel: String,
    pub disabled_event_types_json: String,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NotificationDeliveryRecord {
    pub delivery_id: String,
    pub notification_id: String,
    pub org_id: Option<String>,
    pub user_id: String,
    pub channel: String,
    pub state: String,
    pub attempt_count: i64,
    pub next_attempt_at: Option<String>,
    pub delivered_at: Option<String>,
    pub last_error_code: Option<String>,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

// -----------------------------------------------------------------------------
// Inputs
// -----------------------------------------------------------------------------

pub struct NewWebhookEndpointInput<'a> {
    pub endpoint_id: &'a str,
    pub org_id: &'a str,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub url: &'a str,
    pub subscribed_event_types_json: &'a str,
    pub max_attempts: i64,
    pub base_delay_seconds: i64,
    pub max_delay_seconds: i64,
    pub replay_window_seconds: i64,
    pub auto_disable_enabled: bool,
    pub auto_disable_threshold: i64,
    pub created_by_user_id: &'a str,
    pub now: &'a Timestamp,
}

#[allow(clippy::too_many_arguments)]
pub struct WebhookEndpointUpdateInput<'a> {
    pub endpoint_id: &'a str,
    pub org_id: &'a str,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub url: &'a str,
    pub subscribed_event_types_json: &'a str,
    pub enabled: bool,
    pub max_attempts: i64,
    pub base_delay_seconds: i64,
    pub max_delay_seconds: i64,
    pub replay_window_seconds: i64,
    pub auto_disable_enabled: bool,
    pub auto_disable_threshold: i64,
    pub expected_version: i64,
    pub now: &'a Timestamp,
}

pub struct NewWebhookSecretInput<'a> {
    pub secret_version_id: &'a str,
    pub endpoint_id: &'a str,
    pub org_id: &'a str,
    /// Base64 AES-GCM ciphertext. Never the plaintext.
    pub ciphertext_base64: &'a str,
    pub nonce_base64: &'a str,
    pub fingerprint: &'a str,
    pub version: i64,
    pub rotated_at: Option<&'a str>,
    pub now: &'a Timestamp,
}

pub struct NewWebhookDeliveryInput<'a> {
    pub delivery_id: &'a str,
    pub endpoint_id: &'a str,
    pub org_id: &'a str,
    pub event_id: &'a EventId,
    pub event_type: &'a str,
    pub body: &'a str,
    pub body_hash: &'a str,
    pub secret_version_id: &'a str,
    pub replay_of_delivery_id: Option<&'a str>,
    pub replay_generation: i64,
    pub now: &'a Timestamp,
}

pub struct NewDeliveryAttemptInput<'a> {
    pub attempt_id: &'a str,
    pub delivery_id: &'a str,
    pub org_id: &'a str,
    pub attempt_number: i64,
    pub job_id: Option<&'a str>,
    pub outcome: &'a str,
    pub http_status: Option<i64>,
    pub stable_error_code: Option<&'a str>,
    pub latency_ms: Option<i64>,
    pub started_at: &'a str,
    pub completed_at: Option<&'a str>,
}

pub struct NewQueueJobInput<'a> {
    pub job_id: &'a str,
    pub job_type: JobType,
    pub org_id: Option<&'a str>,
    pub subject_type: &'a str,
    pub subject_id: &'a str,
    pub subject_version: Option<i64>,
    pub dedupe_key: &'a str,
    pub event_id: Option<&'a str>,
    pub request_id: Option<&'a str>,
    pub correlation_id: Option<&'a str>,
    pub payload_ref: Option<&'a str>,
    pub next_attempt_at: Option<&'a str>,
    pub replay_of_job_id: Option<&'a str>,
    pub generation: i64,
    pub now: &'a Timestamp,
}

pub struct NewNotificationInput<'a> {
    pub notification_id: &'a str,
    pub org_id: Option<&'a str>,
    pub user_id: &'a str,
    pub event_id: &'a str,
    pub event_type: &'a str,
    pub category: &'a str,
    pub mandatory: bool,
    pub body_json: &'a str,
    pub dedupe_key: &'a str,
    pub now: &'a Timestamp,
}

pub struct NotificationDeliverySeed<'a> {
    pub delivery_id: &'a str,
    pub notification_id: &'a str,
    pub org_id: Option<&'a str>,
    pub user_id: &'a str,
    pub channel: &'a str,
    pub now: &'a Timestamp,
}

pub struct NotificationPreferenceUpdate<'a> {
    pub preference_id: &'a str,
    pub org_id: Option<&'a str>,
    pub user_id: &'a str,
    pub channel: &'a str,
    pub disabled_event_types_json: &'a str,
    pub expected_version: i64,
    pub next_version: i64,
    pub now: &'a Timestamp,
}

/// Keyset page bounds for the delivery history.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeliveryPageCursor<'a> {
    pub created_at: &'a str,
    pub delivery_id: &'a str,
}

/// Bounded filters for the notification center.
#[derive(Clone, Copy, Debug, Default)]
pub struct NotificationFilters<'a> {
    pub user_id: &'a str,
    pub unread_only: bool,
    pub category: Option<&'a str>,
    pub cursor: Option<(&'a str, &'a str)>,
    pub limit: i32,
}

// -----------------------------------------------------------------------------
// SQL
// -----------------------------------------------------------------------------

const ENDPOINT_BY_ID_SQL: &str = r#"
SELECT endpoint_id, org_id, name, description, url, subscribed_event_types_json,
       current_secret_version_id, enabled, max_attempts, base_delay_seconds,
       max_delay_seconds, replay_window_seconds, auto_disable_enabled,
       auto_disable_threshold, consecutive_terminal_failures, version,
       created_by_user_id, created_at, updated_at
FROM webhook_endpoints
WHERE org_id = ?1 AND endpoint_id = ?2
LIMIT 1
"#;

const ENDPOINTS_PAGE_SQL: &str = r#"
SELECT endpoint_id, org_id, name, description, url, subscribed_event_types_json,
       current_secret_version_id, enabled, max_attempts, base_delay_seconds,
       max_delay_seconds, replay_window_seconds, auto_disable_enabled,
       auto_disable_threshold, consecutive_terminal_failures, version,
       created_by_user_id, created_at, updated_at
FROM webhook_endpoints
WHERE org_id = ?1
  AND (?2 = 1 OR enabled = 1)
  AND (?3 = '' OR (updated_at, endpoint_id) < (?3, ?4))
ORDER BY updated_at DESC, endpoint_id DESC
LIMIT ?5
"#;

const INSERT_ENDPOINT_SQL: &str = r#"
INSERT INTO webhook_endpoints (
    endpoint_id, org_id, name, description, url, subscribed_event_types_json,
    current_secret_version_id, enabled, max_attempts, base_delay_seconds,
    max_delay_seconds, replay_window_seconds, auto_disable_enabled,
    auto_disable_threshold, consecutive_terminal_failures, version,
    created_by_user_id, created_at, updated_at
) VALUES (
    ?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 0, 1, ?14, ?15, ?15
)
"#;

const UPDATE_ENDPOINT_SQL: &str = r#"
UPDATE webhook_endpoints
SET name = ?3,
    description = ?4,
    url = ?5,
    subscribed_event_types_json = ?6,
    enabled = ?7,
    max_attempts = ?8,
    base_delay_seconds = ?9,
    max_delay_seconds = ?10,
    replay_window_seconds = ?11,
    auto_disable_enabled = ?12,
    auto_disable_threshold = ?13,
    version = version + 1,
    updated_at = ?14
WHERE endpoint_id = ?1 AND org_id = ?2 AND version = ?15
"#;

const DISABLE_ENDPOINT_SQL: &str = r#"
UPDATE webhook_endpoints
SET enabled = 0, version = version + 1, updated_at = ?3
WHERE endpoint_id = ?1 AND org_id = ?2 AND version = ?4
"#;

const RECORD_TERMINAL_FAILURE_SQL: &str = r#"
UPDATE webhook_endpoints
SET consecutive_terminal_failures = consecutive_terminal_failures + 1,
    enabled = CASE WHEN ?2 = 1 THEN 0 ELSE enabled END,
    version = version + 1,
    updated_at = ?3
WHERE endpoint_id = ?1
"#;

const RESET_TERMINAL_FAILURES_SQL: &str = r#"
UPDATE webhook_endpoints
SET consecutive_terminal_failures = 0, version = version + 1, updated_at = ?2
WHERE endpoint_id = ?1 AND consecutive_terminal_failures > 0
"#;

const INSERT_SECRET_SQL: &str = r#"
INSERT INTO webhook_secrets (
    secret_version_id, endpoint_id, org_id, ciphertext, nonce, fingerprint,
    version, created_at, rotated_at, revoked_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)
"#;

const SECRET_BY_ID_SQL: &str = r#"
SELECT secret_version_id, endpoint_id, org_id, ciphertext, nonce, fingerprint,
       version, created_at, rotated_at, revoked_at
FROM webhook_secrets
WHERE secret_version_id = ?1 AND endpoint_id = ?2 AND org_id = ?3
LIMIT 1
"#;

const NEXT_SECRET_VERSION_SQL: &str = r#"
SELECT COALESCE(MAX(version), 0) + 1 AS next_version
FROM webhook_secrets
WHERE endpoint_id = ?1
"#;

/// Set-based fan-out.
///
/// The tenant check (`e.org_id = ?event_org`) and the exact-match subscription
/// check (`json_each` value equality, never a `LIKE`) are both in SQL, so a
/// caller cannot widen the fan-out by passing a different organization. The
/// four recursive-event guards mirror `trg_webhook_deliveries_no_recursive_fanout`
/// so the batch is never aborted by the trigger.
const FAN_OUT_DELIVERIES_SQL: &str = r#"
INSERT OR IGNORE INTO webhook_deliveries (
    delivery_id, endpoint_id, org_id, event_id, event_type, body, body_hash,
    secret_version_id, signature_key_id, state, attempt_count, next_attempt_at,
    replay_of_delivery_id, replay_generation, version, created_at, updated_at
)
SELECT
    'whd_' || lower(hex(randomblob(16))),
    e.endpoint_id,
    e.org_id,
    ?2,
    ?3,
    ?4,
    ?5,
    e.current_secret_version_id,
    e.current_secret_version_id,
    'pending',
    0,
    ?6,
    NULL,
    0,
    1,
    ?6,
    ?6
FROM webhook_endpoints e
WHERE e.org_id = ?1
  AND e.enabled = 1
  AND e.current_secret_version_id IS NOT NULL
  AND EXISTS (
      SELECT 1 FROM json_each(e.subscribed_event_types_json) subscribed
      WHERE subscribed.value = ?3
  )
  AND ?3 NOT LIKE 'webhook.delivery_%'
  AND ?3 NOT LIKE 'webhook.endpoint_%'
  AND ?3 NOT LIKE 'notification.delivery_%'
  AND ?3 <> 'webhook.test.v1'
"#;

/// Single explicit delivery row for the dedicated `webhook.test.v1` event.
const INSERT_TEST_DELIVERY_SQL: &str = r#"
INSERT OR IGNORE INTO webhook_deliveries (
    delivery_id, endpoint_id, org_id, event_id, event_type, body, body_hash,
    secret_version_id, signature_key_id, state, attempt_count, next_attempt_at,
    replay_of_delivery_id, replay_generation, version, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, 'pending', 0, ?9, NULL, 0, 1, ?9, ?9)
"#;

/// An authorized replay always inserts a SUCCESSOR logical delivery with the
/// same event ID and the same exact body, using the CURRENT secret version.
const INSERT_REPLAY_DELIVERY_SQL: &str = r#"
INSERT OR IGNORE INTO webhook_deliveries (
    delivery_id, endpoint_id, org_id, event_id, event_type, body, body_hash,
    secret_version_id, signature_key_id, state, attempt_count, next_attempt_at,
    replay_of_delivery_id, replay_generation, version, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, 'pending', 0, ?9, ?10, ?11, 1, ?9, ?9)
"#;

const DELIVERY_BY_ID_SQL: &str = r#"
SELECT delivery_id, endpoint_id, org_id, event_id, event_type, body, body_hash,
       secret_version_id, signature_key_id, state, attempt_count, next_attempt_at,
       delivered_at, last_error_code, replay_of_delivery_id, replay_generation,
       version, created_at, updated_at
FROM webhook_deliveries
WHERE delivery_id = ?1 AND org_id = ?2
LIMIT 1
"#;

const DELIVERIES_PAGE_SQL: &str = r#"
SELECT delivery_id, endpoint_id, org_id, event_id, event_type, body, body_hash,
       secret_version_id, signature_key_id, state, attempt_count, next_attempt_at,
       delivered_at, last_error_code, replay_of_delivery_id, replay_generation,
       version, created_at, updated_at
FROM webhook_deliveries
WHERE org_id = ?1 AND endpoint_id = ?2
  AND (?3 = '' OR state = ?3)
  AND (?4 = '' OR (created_at, delivery_id) < (?4, ?5))
ORDER BY created_at DESC, delivery_id DESC
LIMIT ?6
"#;

const MARK_DELIVERY_QUEUED_SQL: &str = r#"
UPDATE webhook_deliveries
SET state = 'queued', next_attempt_at = NULL, version = version + 1, updated_at = ?3
WHERE delivery_id = ?1 AND state = ?2 AND version = ?4
"#;

const MARK_DELIVERY_DELIVERING_SQL: &str = r#"
UPDATE webhook_deliveries
SET state = 'delivering',
    attempt_count = attempt_count + 1,
    version = version + 1,
    updated_at = ?2
WHERE delivery_id = ?1 AND state = ?3 AND version = ?4
"#;

const MARK_DELIVERY_DELIVERED_SQL: &str = r#"
UPDATE webhook_deliveries
SET state = 'delivered',
    delivered_at = ?2,
    next_attempt_at = NULL,
    last_error_code = NULL,
    version = version + 1,
    updated_at = ?2
WHERE delivery_id = ?1 AND state = 'delivering' AND version = ?3
"#;

const MARK_DELIVERY_RETRY_SQL: &str = r#"
UPDATE webhook_deliveries
SET state = 'retry_wait',
    next_attempt_at = strftime('%Y-%m-%dT%H:%M:%fZ', ?2, printf('+%d seconds', ?3)),
    last_error_code = ?4,
    version = version + 1,
    updated_at = ?2
WHERE delivery_id = ?1 AND state = 'delivering' AND version = ?5
"#;

const MARK_DELIVERY_DEAD_LETTER_SQL: &str = r#"
UPDATE webhook_deliveries
SET state = 'dead_letter',
    next_attempt_at = NULL,
    last_error_code = ?2,
    version = version + 1,
    updated_at = ?3
WHERE delivery_id = ?1 AND state = 'delivering' AND version = ?4
"#;

const CANCEL_ENDPOINT_DELIVERIES_SQL: &str = r#"
UPDATE webhook_deliveries
SET state = 'cancelled', next_attempt_at = NULL, version = version + 1, updated_at = ?2
WHERE endpoint_id = ?1 AND state IN ('pending', 'queued', 'retry_wait')
"#;

const INSERT_ATTEMPT_SQL: &str = r#"
INSERT OR IGNORE INTO webhook_delivery_attempts (
    attempt_id, delivery_id, org_id, attempt_number, job_id, outcome,
    http_status, stable_error_code, latency_ms, started_at, completed_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
"#;

const ATTEMPTS_FOR_DELIVERY_SQL: &str = r#"
SELECT attempt_id, delivery_id, org_id, attempt_number, job_id, outcome,
       http_status, stable_error_code, latency_ms, started_at, completed_at
FROM webhook_delivery_attempts
WHERE delivery_id = ?1 AND org_id = ?2
ORDER BY attempt_number ASC
LIMIT ?3
"#;

/// `INSERT OR IGNORE` is the D1 half of the dedupe contract: the unique
/// `(job_type, tenant, dedupe_key, generation)` index rejects a duplicate
/// logical job, and the caller treats a second insert as a duplicate.
const INSERT_QUEUE_JOB_SQL: &str = r#"
INSERT OR IGNORE INTO queue_job_envelopes (
    job_id, job_type, schema_version, org_id, subject_type, subject_id,
    subject_version, dedupe_key, event_id, request_id, correlation_id,
    payload_ref, state, attempt, lease_version, lease_expires_at,
    next_attempt_at, last_error_code, replay_of_job_id, generation, version,
    created_at, updated_at
) VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'queued', 1, 0, NULL, ?12, NULL, ?13, ?14, 1, ?15, ?15)
"#;

const JOB_BY_ID_SQL: &str = r#"
SELECT job_id, job_type, schema_version, org_id, subject_type, subject_id,
       subject_version, dedupe_key, event_id, request_id, correlation_id,
       payload_ref, state, attempt, lease_version, lease_expires_at,
       next_attempt_at, last_error_code, replay_of_job_id, generation, version,
       created_at, updated_at
FROM queue_job_envelopes
WHERE job_id = ?1
LIMIT 1
"#;

const CLAIM_JOB_SQL: &str = r#"
UPDATE queue_job_envelopes
SET state = 'running',
    lease_version = lease_version + 1,
    lease_expires_at = ?1,
    updated_at = ?1
WHERE job_id = ?2
  AND attempt = ?3
  AND state = ?4
  AND lease_version = ?5
"#;

const COMPLETE_JOB_SQL: &str = r#"
UPDATE queue_job_envelopes
SET state = ?2,
    lease_version = lease_version + 1,
    lease_expires_at = NULL,
    next_attempt_at = ?3,
    last_error_code = ?4,
    updated_at = ?5
WHERE job_id = ?1 AND state = 'running' AND lease_version = ?6
"#;

const RETRY_JOB_SQL: &str = r#"
UPDATE queue_job_envelopes
SET state = 'retry_wait',
    attempt = attempt + 1,
    next_attempt_at = strftime('%Y-%m-%dT%H:%M:%fZ', ?2, printf('+%d seconds', ?3)),
    last_error_code = ?4,
    lease_version = lease_version + 1,
    lease_expires_at = NULL,
    updated_at = ?2
WHERE job_id = ?1 AND state = 'running' AND lease_version = ?5
"#;

const INSERT_NOTIFICATION_SQL: &str = r#"
INSERT OR IGNORE INTO notifications (
    notification_id, org_id, user_id, event_id, event_type, category,
    mandatory, body_json, dedupe_key, state, read_at, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'unread', NULL, ?10, ?10)
"#;

const NOTIFICATION_BY_ID_SQL: &str = r#"
SELECT notification_id, org_id, user_id, event_id, event_type, category,
       mandatory, body_json, dedupe_key, state, read_at, created_at, updated_at
FROM notifications
WHERE notification_id = ?1 AND user_id = ?2
LIMIT 1
"#;

const NOTIFICATIONS_PAGE_SQL: &str = r#"
SELECT notification_id, org_id, user_id, event_id, event_type, category,
       mandatory, body_json, dedupe_key, state, read_at, created_at, updated_at
FROM notifications
WHERE user_id = ?1
  AND (?2 = 0 OR state = 'unread')
  AND (?3 = '' OR category = ?3)
  AND (?4 = '' OR (created_at, notification_id) < (?4, ?5))
ORDER BY created_at DESC, notification_id DESC
LIMIT ?6
"#;

const MARK_NOTIFICATION_READ_SQL: &str = r#"
UPDATE notifications
SET state = 'read', read_at = COALESCE(read_at, ?2), updated_at = ?2
WHERE notification_id = ?1 AND user_id = ?3 AND state = 'unread'
"#;

const INSERT_NOTIFICATION_DELIVERY_SQL: &str = r#"
INSERT OR IGNORE INTO notification_deliveries (
    delivery_id, notification_id, org_id, user_id, channel, state,
    attempt_count, next_attempt_at, delivered_at, last_error_code, version,
    created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6, NULL, NULL, 1, ?6, ?6)
"#;

const NOTIFICATION_DELIVERY_BY_ID_SQL: &str = r#"
SELECT delivery_id, notification_id, org_id, user_id, channel, state,
       attempt_count, next_attempt_at, delivered_at, last_error_code, version,
       created_at, updated_at
FROM notification_deliveries
WHERE delivery_id = ?1
LIMIT 1
"#;

const MARK_NOTIFICATION_DELIVERY_SQL: &str = r#"
UPDATE notification_deliveries
SET state = ?2,
    attempt_count = ?3,
    next_attempt_at = ?4,
    delivered_at = ?5,
    last_error_code = ?6,
    version = version + 1,
    updated_at = ?7
WHERE delivery_id = ?1 AND state = ?8 AND version = ?9
"#;

const PREFERENCE_BY_SCOPE_SQL: &str = r#"
SELECT preference_id, org_id, user_id, channel, disabled_event_types_json,
       version, created_at, updated_at
FROM notification_preferences
WHERE user_id = ?1 AND channel = ?2
  AND ((?3 = '' AND org_id IS NULL) OR org_id = ?3)
LIMIT 1
"#;

const UPSERT_PREFERENCE_SQL: &str = r#"
INSERT INTO notification_preferences (
    preference_id, org_id, user_id, channel, disabled_event_types_json,
    version, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
ON CONFLICT (org_id, user_id, channel) DO UPDATE SET
    disabled_event_types_json = excluded.disabled_event_types_json,
    version = excluded.version,
    updated_at = excluded.updated_at
WHERE notification_preferences.version = ?8
"#;

const PREFERENCES_BY_SCOPE_SQL: &str = r#"
SELECT preference_id, org_id, user_id, channel, disabled_event_types_json,
       version, created_at, updated_at
FROM notification_preferences
WHERE user_id = ?1
  AND ((?2 = '' AND org_id IS NULL) OR org_id = ?2)
ORDER BY channel ASC
LIMIT 2
"#;

/* An endpoint version assertion that intentionally violates a NOT NULL
 * idempotency constraint. D1 batches are transactional, so this aborts the
 * surrounding endpoint mutation before it can commit with a stale version. */
const ASSERT_ENDPOINT_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest,
    request_fingerprint, state, response_status, response_body, expires_at,
    claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM webhook_endpoints
    WHERE endpoint_id = ?1 AND org_id = ?2 AND version = ?3
)
"#;

/* A version assertion that intentionally violates a NOT NULL idempotency
 * constraint. D1 batches are transactional, so this aborts the surrounding
 * preference mutation before it can commit with a stale version. */
const ASSERT_PREFERENCE_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest,
    request_fingerprint, state, response_status, response_body, expires_at,
    claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE ?3 = 0
   OR NOT EXISTS (
    SELECT 1 FROM notification_preferences
    WHERE user_id = ?1 AND channel = ?2
      AND ((?4 = '' AND org_id IS NULL) OR org_id = ?4)
      AND version = ?3
  )
"#;

// -----------------------------------------------------------------------------
// Repository
// -----------------------------------------------------------------------------

/// Durable P06 event-delivery persistence.
pub struct WebhookRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> WebhookRepository<'a> {
    pub const fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    /// The underlying adapter, so a caller composing a larger D1 batch can
    /// reach [`D1Adapter::batch`] without a second handle.
    pub const fn database(&self) -> &'a D1Adapter {
        self.database
    }

    // -- webhook endpoints --------------------------------------------------

    pub async fn find_endpoint(
        &self,
        org_id: &str,
        endpoint_id: &str,
    ) -> worker::Result<Option<WebhookEndpointRecord>> {
        self.database
            .prepare(
                ENDPOINT_BY_ID_SQL,
                &[BindValue::Text(endpoint_id), BindValue::Text(org_id)],
            )?
            .first::<WebhookEndpointRecord>(None)
            .await
    }

    pub async fn list_endpoints(
        &self,
        org_id: &str,
        include_disabled: bool,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<WebhookEndpointRecord>> {
        let (cursor_updated, cursor_id) = cursor.unwrap_or(("", ""));
        self.database
            .prepare(
                ENDPOINTS_PAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Integer(i32::from(include_disabled)),
                    BindValue::Text(cursor_updated),
                    BindValue::Text(cursor_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<WebhookEndpointRecord>()
    }

    pub fn insert_endpoint_statement(
        &self,
        input: &NewWebhookEndpointInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_ENDPOINT_SQL,
            &[
                BindValue::Text(input.endpoint_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.name),
                input.description.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.url),
                BindValue::Text(input.subscribed_event_types_json),
                BindValue::Integer(1),
                BindValue::Int64(input.max_attempts),
                BindValue::Int64(input.base_delay_seconds),
                BindValue::Int64(input.max_delay_seconds),
                BindValue::Int64(input.replay_window_seconds),
                BindValue::Integer(i32::from(input.auto_disable_enabled)),
                BindValue::Int64(input.auto_disable_threshold),
                BindValue::Text(input.created_by_user_id),
                BindValue::Text(input.now.as_str()),
            ],
        )
    }

    pub fn update_endpoint_statement(
        &self,
        input: &WebhookEndpointUpdateInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_ENDPOINT_SQL,
            &[
                BindValue::Text(input.endpoint_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.name),
                input.description.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.url),
                BindValue::Text(input.subscribed_event_types_json),
                BindValue::Integer(i32::from(input.enabled)),
                BindValue::Int64(input.max_attempts),
                BindValue::Int64(input.base_delay_seconds),
                BindValue::Int64(input.max_delay_seconds),
                BindValue::Int64(input.replay_window_seconds),
                BindValue::Integer(i32::from(input.auto_disable_enabled)),
                BindValue::Int64(input.auto_disable_threshold),
                BindValue::Text(input.now.as_str()),
                BindValue::Int64(input.expected_version),
            ],
        )
    }

    /// Abort the surrounding batch unless the endpoint row still carries the
    /// version the caller observed.
    pub fn assert_endpoint_version_statement(
        &self,
        endpoint_id: &str,
        org_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_ENDPOINT_VERSION_SQL,
            &[
                BindValue::Text(endpoint_id),
                BindValue::Text(org_id),
                BindValue::Int64(expected_version),
            ],
        )
    }

    pub fn disable_endpoint_statement(
        &self,
        endpoint_id: &str,
        org_id: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            DISABLE_ENDPOINT_SQL,
            &[
                BindValue::Text(endpoint_id),
                BindValue::Text(org_id),
                BindValue::Text(now.as_str()),
                BindValue::Int64(expected_version),
            ],
        )
    }

    /// Disabling cancels pending work but never erases delivered or dead-letter
    /// history.
    pub fn cancel_endpoint_deliveries_statement(
        &self,
        endpoint_id: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            CANCEL_ENDPOINT_DELIVERIES_SQL,
            &[BindValue::Text(endpoint_id), BindValue::Text(now.as_str())],
        )
    }

    pub fn record_terminal_failure_statement(
        &self,
        endpoint_id: &str,
        auto_disable: bool,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            RECORD_TERMINAL_FAILURE_SQL,
            &[
                BindValue::Text(endpoint_id),
                BindValue::Integer(i32::from(auto_disable)),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub fn reset_terminal_failures_statement(
        &self,
        endpoint_id: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            RESET_TERMINAL_FAILURES_SQL,
            &[BindValue::Text(endpoint_id), BindValue::Text(now.as_str())],
        )
    }

    // -- webhook secrets ----------------------------------------------------

    pub fn insert_secret_statement(
        &self,
        input: &NewWebhookSecretInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_SECRET_SQL,
            &[
                BindValue::Text(input.secret_version_id),
                BindValue::Text(input.endpoint_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.ciphertext_base64),
                BindValue::Text(input.nonce_base64),
                BindValue::Text(input.fingerprint),
                BindValue::Int64(input.version),
                BindValue::Text(input.now.as_str()),
                input.rotated_at.map_or(BindValue::Null, BindValue::Text),
            ],
        )
    }

    pub async fn find_secret(
        &self,
        org_id: &str,
        endpoint_id: &str,
        secret_version_id: &str,
    ) -> worker::Result<Option<WebhookSecretRecord>> {
        self.database
            .prepare(
                SECRET_BY_ID_SQL,
                &[
                    BindValue::Text(secret_version_id),
                    BindValue::Text(endpoint_id),
                    BindValue::Text(org_id),
                ],
            )?
            .first::<WebhookSecretRecord>(None)
            .await
    }

    pub async fn next_secret_version(&self, endpoint_id: &str) -> worker::Result<i64> {
        let row = self
            .database
            .prepare(NEXT_SECRET_VERSION_SQL, &[BindValue::Text(endpoint_id)])?
            .first::<NextVersionRow>(None)
            .await?
            .ok_or_else(invalid_row)?;
        if row.next_version <= 0 || row.next_version == i64::MAX {
            return Err(invalid_row());
        }
        Ok(row.next_version)
    }

    // -- webhook deliveries -------------------------------------------------

    /// Fan one committed business event out to every enabled endpoint in the
    /// SAME organization that subscribes to the exact event type.
    ///
    /// The caller passes the `EventEnvelope` that is being written to
    /// `outbox_events` in the same D1 batch, so the body serialized here is
    /// byte-for-byte the body persisted with the event. Add this statement to a
    /// business transaction; the tenant check and the exact-match subscription
    /// check both live in SQL and cannot be widened by a caller.
    pub fn fan_out_event_statement(
        &self,
        event: &crate::core::EventEnvelope,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        let body = serde_json::to_string(event)
            .map_err(|_| worker::Error::RustError("webhook event body is invalid".into()))?;
        let event_type = event.event_type.as_str();
        if event_type.len() > 96 {
            return Err(worker::Error::RustError(
                "webhook event type is out of bounds".into(),
            ));
        }
        self.fan_out_deliveries_statement(
            event.organization_id.as_ref().map_or("", |id| id.as_str()),
            &event.event_id,
            event_type,
            &body,
            &crate::adapters::webhooks::outbound::body_hash(&body),
            now,
        )
    }

    /// Fan one committed business event out to every enabled endpoint in the
    /// SAME organization that subscribes to the exact event type.
    pub fn fan_out_deliveries_statement(
        &self,
        event_organization_id: &str,
        event: &EventId,
        event_type: &str,
        body: &str,
        body_hash: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            FAN_OUT_DELIVERIES_SQL,
            &[
                BindValue::Text(event_organization_id),
                BindValue::Text(event.as_str()),
                BindValue::Text(event_type),
                BindValue::Text(body),
                BindValue::Text(body_hash),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub fn insert_test_delivery_statement(
        &self,
        input: &NewWebhookDeliveryInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_TEST_DELIVERY_SQL,
            &[
                BindValue::Text(input.delivery_id),
                BindValue::Text(input.endpoint_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.event_id.as_str()),
                BindValue::Text(input.event_type),
                BindValue::Text(input.body),
                BindValue::Text(input.body_hash),
                BindValue::Text(input.secret_version_id),
                BindValue::Text(input.now.as_str()),
            ],
        )
    }

    /// Insert the successor logical delivery created by an authorized replay.
    pub fn insert_replay_delivery_statement(
        &self,
        input: &NewWebhookDeliveryInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_REPLAY_DELIVERY_SQL,
            &[
                BindValue::Text(input.delivery_id),
                BindValue::Text(input.endpoint_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.event_id.as_str()),
                BindValue::Text(input.event_type),
                BindValue::Text(input.body),
                BindValue::Text(input.body_hash),
                BindValue::Text(input.secret_version_id),
                BindValue::Text(input.now.as_str()),
                input
                    .replay_of_delivery_id
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Int64(input.replay_generation),
            ],
        )
    }

    pub async fn find_delivery(
        &self,
        org_id: &str,
        delivery_id: &str,
    ) -> worker::Result<Option<WebhookDeliveryRecord>> {
        self.database
            .prepare(
                DELIVERY_BY_ID_SQL,
                &[BindValue::Text(delivery_id), BindValue::Text(org_id)],
            )?
            .first::<WebhookDeliveryRecord>(None)
            .await
    }

    pub async fn list_deliveries(
        &self,
        org_id: &str,
        endpoint_id: &str,
        state: Option<&str>,
        cursor: Option<DeliveryPageCursor<'_>>,
        limit: i32,
    ) -> worker::Result<Vec<WebhookDeliveryRecord>> {
        let cursor = cursor.unwrap_or_default();
        self.database
            .prepare(
                DELIVERIES_PAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(endpoint_id),
                    BindValue::Text(state.unwrap_or("")),
                    BindValue::Text(cursor.created_at),
                    BindValue::Text(cursor.delivery_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<WebhookDeliveryRecord>()
    }

    pub fn mark_delivery_queued_statement(
        &self,
        delivery_id: &str,
        expected_state: WebhookDeliveryState,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            MARK_DELIVERY_QUEUED_SQL,
            &[
                BindValue::Text(delivery_id),
                BindValue::Text(expected_state.as_str()),
                BindValue::Text(now.as_str()),
                BindValue::Int64(expected_version),
            ],
        )
    }

    /// Claim one delivery for an attempt. This is the CAS that makes a duplicate
    /// queue delivery a no-op after durable completion.
    pub fn mark_delivery_delivering_statement(
        &self,
        delivery_id: &str,
        expected_state: WebhookDeliveryState,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            MARK_DELIVERY_DELIVERING_SQL,
            &[
                BindValue::Text(delivery_id),
                BindValue::Text(now.as_str()),
                BindValue::Text(expected_state.as_str()),
                BindValue::Int64(expected_version),
            ],
        )
    }

    pub fn mark_delivery_delivered_statement(
        &self,
        delivery_id: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            MARK_DELIVERY_DELIVERED_SQL,
            &[
                BindValue::Text(delivery_id),
                BindValue::Text(now.as_str()),
                BindValue::Int64(expected_version),
            ],
        )
    }

    pub fn mark_delivery_retry_statement(
        &self,
        delivery_id: &str,
        now: &Timestamp,
        delay_seconds: u32,
        error_code: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            MARK_DELIVERY_RETRY_SQL,
            &[
                BindValue::Text(delivery_id),
                BindValue::Text(now.as_str()),
                BindValue::Integer(i32::try_from(delay_seconds).map_err(|_| invalid_input())?),
                BindValue::Text(error_code),
                BindValue::Int64(expected_version),
            ],
        )
    }

    pub fn mark_delivery_dead_letter_statement(
        &self,
        delivery_id: &str,
        error_code: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            MARK_DELIVERY_DEAD_LETTER_SQL,
            &[
                BindValue::Text(delivery_id),
                BindValue::Text(error_code),
                BindValue::Text(now.as_str()),
                BindValue::Int64(expected_version),
            ],
        )
    }

    // -- webhook delivery attempts -----------------------------------------

    pub fn insert_attempt_statement(
        &self,
        input: &NewDeliveryAttemptInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_ATTEMPT_SQL,
            &[
                BindValue::Text(input.attempt_id),
                BindValue::Text(input.delivery_id),
                BindValue::Text(input.org_id),
                BindValue::Int64(input.attempt_number),
                input.job_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.outcome),
                input.http_status.map_or(BindValue::Null, BindValue::Int64),
                input
                    .stable_error_code
                    .map_or(BindValue::Null, BindValue::Text),
                input.latency_ms.map_or(BindValue::Null, BindValue::Int64),
                BindValue::Text(input.started_at),
                input.completed_at.map_or(BindValue::Null, BindValue::Text),
            ],
        )
    }

    pub async fn list_attempts(
        &self,
        org_id: &str,
        delivery_id: &str,
        limit: i32,
    ) -> worker::Result<Vec<WebhookDeliveryAttemptRecord>> {
        self.database
            .prepare(
                ATTEMPTS_FOR_DELIVERY_SQL,
                &[
                    BindValue::Text(delivery_id),
                    BindValue::Text(org_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<WebhookDeliveryAttemptRecord>()
    }

    // -- queue job envelopes ------------------------------------------------

    pub fn insert_queue_job_statement(
        &self,
        input: &NewQueueJobInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        if input.dedupe_key.is_empty() || input.dedupe_key.chars().count() > MAX_DEDUPE_KEY_CHARS {
            return Err(invalid_input());
        }
        if let Some(payload_ref) = input.payload_ref
            && payload_ref.chars().count() > MAX_JOB_PAYLOAD_REF_CHARS
        {
            return Err(invalid_input());
        }
        self.database.prepare(
            INSERT_QUEUE_JOB_SQL,
            &[
                BindValue::Text(input.job_id),
                BindValue::Text(input.job_type.as_str()),
                input.org_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.subject_type),
                BindValue::Text(input.subject_id),
                input
                    .subject_version
                    .map_or(BindValue::Null, BindValue::Int64),
                BindValue::Text(input.dedupe_key),
                input.event_id.map_or(BindValue::Null, BindValue::Text),
                input.request_id.map_or(BindValue::Null, BindValue::Text),
                input
                    .correlation_id
                    .map_or(BindValue::Null, BindValue::Text),
                input.payload_ref.map_or(BindValue::Null, BindValue::Text),
                input
                    .next_attempt_at
                    .map_or(BindValue::Text(input.now.as_str()), BindValue::Text),
                input
                    .replay_of_job_id
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Int64(input.generation),
                BindValue::Text(input.now.as_str()),
            ],
        )
    }

    pub async fn find_job(&self, job_id: &str) -> worker::Result<Option<QueueJobRecord>> {
        self.database
            .prepare(JOB_BY_ID_SQL, &[BindValue::Text(job_id)])?
            .first::<QueueJobRecord>(None)
            .await
    }

    /// Atomic `queued | retry_wait -> running` claim. The CAS covers the job
    /// ID, attempt, state, and lease version, so a consumer crash before the
    /// claim leaves the job retryable while a crash after it is recovered by
    /// lease expiry.
    pub fn claim_job_statement(
        &self,
        job_id: &str,
        expected_attempt: i64,
        expected_state: QueueJobState,
        expected_lease_version: i64,
        lease_expires_at: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            CLAIM_JOB_SQL,
            &[
                BindValue::Text(lease_expires_at.as_str()),
                BindValue::Text(job_id),
                BindValue::Int64(expected_attempt),
                BindValue::Text(expected_state.as_str()),
                BindValue::Int64(expected_lease_version),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn complete_job_statement(
        &self,
        job_id: &str,
        next_state: QueueJobState,
        next_attempt_at: Option<&str>,
        error_code: Option<&str>,
        expected_lease_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            COMPLETE_JOB_SQL,
            &[
                BindValue::Text(job_id),
                BindValue::Text(next_state.as_str()),
                next_attempt_at.map_or(BindValue::Null, BindValue::Text),
                error_code.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(now.as_str()),
                BindValue::Int64(expected_lease_version),
            ],
        )
    }

    pub fn retry_job_statement(
        &self,
        job_id: &str,
        now: &Timestamp,
        delay_seconds: u32,
        error_code: &str,
        expected_lease_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            RETRY_JOB_SQL,
            &[
                BindValue::Text(job_id),
                BindValue::Text(now.as_str()),
                BindValue::Integer(i32::try_from(delay_seconds).map_err(|_| invalid_input())?),
                BindValue::Text(error_code),
                BindValue::Int64(expected_lease_version),
            ],
        )
    }

    // -- notifications ------------------------------------------------------

    pub fn insert_notification_statement(
        &self,
        input: &NewNotificationInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        if input.body_json.len() > MAX_NOTIFICATION_BODY_BYTES
            || input.dedupe_key.is_empty()
            || input.dedupe_key.chars().count() > 255
            || !NOTIFICATION_CATEGORIES.contains(&input.category)
        {
            return Err(invalid_input());
        }
        self.database.prepare(
            INSERT_NOTIFICATION_SQL,
            &[
                BindValue::Text(input.notification_id),
                input.org_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.user_id),
                BindValue::Text(input.event_id),
                BindValue::Text(input.event_type),
                BindValue::Text(input.category),
                BindValue::Integer(i32::from(input.mandatory)),
                BindValue::Text(input.body_json),
                BindValue::Text(input.dedupe_key),
                BindValue::Text(input.now.as_str()),
            ],
        )
    }

    pub fn insert_notification_delivery_statement(
        &self,
        seed: &NotificationDeliverySeed<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        if !NOTIFICATION_CHANNELS.contains(&seed.channel) {
            return Err(invalid_input());
        }
        self.database.prepare(
            INSERT_NOTIFICATION_DELIVERY_SQL,
            &[
                BindValue::Text(seed.delivery_id),
                BindValue::Text(seed.notification_id),
                seed.org_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(seed.user_id),
                BindValue::Text(seed.channel),
                BindValue::Text(seed.now.as_str()),
            ],
        )
    }

    pub async fn find_notification(
        &self,
        user_id: &str,
        notification_id: &str,
    ) -> worker::Result<Option<NotificationRecord>> {
        self.database
            .prepare(
                NOTIFICATION_BY_ID_SQL,
                &[BindValue::Text(notification_id), BindValue::Text(user_id)],
            )?
            .first::<NotificationRecord>(None)
            .await
    }

    pub async fn list_notifications(
        &self,
        filters: &NotificationFilters<'_>,
    ) -> worker::Result<Vec<NotificationRecord>> {
        // `101` is the internal over-fetch used to compute `has_more`; the HTTP
        // surface still caps a client page at 100.
        if filters.user_id.is_empty() || !(1..=101).contains(&filters.limit) {
            return Err(invalid_input());
        }
        if let Some(category) = filters.category
            && !NOTIFICATION_CATEGORIES.contains(&category)
        {
            return Err(invalid_input());
        }
        let (cursor_created, cursor_id) = filters.cursor.unwrap_or(("", ""));
        self.database
            .prepare(
                NOTIFICATIONS_PAGE_SQL,
                &[
                    BindValue::Text(filters.user_id),
                    BindValue::Integer(i32::from(filters.unread_only)),
                    BindValue::Text(filters.category.unwrap_or("")),
                    BindValue::Text(cursor_created),
                    BindValue::Text(cursor_id),
                    BindValue::Integer(filters.limit),
                ],
            )?
            .all()
            .await?
            .results::<NotificationRecord>()
    }

    pub fn mark_notification_read_statement(
        &self,
        user_id: &str,
        notification_id: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            MARK_NOTIFICATION_READ_SQL,
            &[
                BindValue::Text(notification_id),
                BindValue::Text(now.as_str()),
                BindValue::Text(user_id),
            ],
        )
    }

    pub async fn find_notification_delivery(
        &self,
        delivery_id: &str,
    ) -> worker::Result<Option<NotificationDeliveryRecord>> {
        self.database
            .prepare(
                NOTIFICATION_DELIVERY_BY_ID_SQL,
                &[BindValue::Text(delivery_id)],
            )?
            .first::<NotificationDeliveryRecord>(None)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mark_notification_delivery_statement(
        &self,
        delivery_id: &str,
        next_state: NotificationDeliveryState,
        attempt_count: i64,
        next_attempt_at: Option<&str>,
        delivered_at: Option<&str>,
        last_error_code: Option<&str>,
        expected_state: NotificationDeliveryState,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            MARK_NOTIFICATION_DELIVERY_SQL,
            &[
                BindValue::Text(delivery_id),
                BindValue::Text(next_state.as_str()),
                BindValue::Int64(attempt_count),
                next_attempt_at.map_or(BindValue::Null, BindValue::Text),
                delivered_at.map_or(BindValue::Null, BindValue::Text),
                last_error_code.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(now.as_str()),
                BindValue::Text(expected_state.as_str()),
                BindValue::Int64(expected_version),
            ],
        )
    }

    // -- notification preferences ------------------------------------------

    pub async fn find_preference(
        &self,
        org_id: Option<&str>,
        user_id: &str,
        channel: &str,
    ) -> worker::Result<Option<NotificationPreferenceRecord>> {
        self.database
            .prepare(
                PREFERENCE_BY_SCOPE_SQL,
                &[
                    BindValue::Text(user_id),
                    BindValue::Text(channel),
                    BindValue::Text(org_id.unwrap_or("")),
                ],
            )?
            .first::<NotificationPreferenceRecord>(None)
            .await
    }

    pub async fn list_preferences(
        &self,
        org_id: Option<&str>,
        user_id: &str,
    ) -> worker::Result<Vec<NotificationPreferenceRecord>> {
        self.database
            .prepare(
                PREFERENCES_BY_SCOPE_SQL,
                &[
                    BindValue::Text(user_id),
                    BindValue::Text(org_id.unwrap_or("")),
                ],
            )?
            .all()
            .await?
            .results::<NotificationPreferenceRecord>()
    }

    pub fn upsert_preference_statement(
        &self,
        update: &NotificationPreferenceUpdate<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        if !NOTIFICATION_CHANNELS.contains(&update.channel)
            || update.next_version <= 0
            || update.expected_version < 0
        {
            return Err(invalid_input());
        }
        self.database.prepare(
            UPSERT_PREFERENCE_SQL,
            &[
                BindValue::Text(update.preference_id),
                update.org_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(update.user_id),
                BindValue::Text(update.channel),
                BindValue::Text(update.disabled_event_types_json),
                BindValue::Int64(update.next_version),
                BindValue::Text(update.now.as_str()),
                BindValue::Int64(update.expected_version),
            ],
        )
    }

    /// Abort the surrounding batch unless the preference row still carries the
    /// version the caller observed. `create = true` (expected version `0`)
    /// requires the row to be absent.
    pub fn assert_preference_version_statement(
        &self,
        org_id: Option<&str>,
        user_id: &str,
        channel: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        if !NOTIFICATION_CHANNELS.contains(&channel) {
            return Err(invalid_input());
        }
        self.database.prepare(
            ASSERT_PREFERENCE_VERSION_SQL,
            &[
                BindValue::Text(user_id),
                BindValue::Text(channel),
                BindValue::Int64(expected_version),
                BindValue::Text(org_id.unwrap_or("")),
            ],
        )
    }

    // -- transitions --------------------------------------------------------

    /// Run a CAS statement and classify the affected-row count.
    pub async fn apply(&self, statement: D1PreparedStatement) -> worker::Result<bool> {
        let result = statement.run().await?;
        Ok(D1Adapter::changes(&result)? > 0)
    }

    /// Number of delivery rows created (or replayed) by one fan-out statement.
    pub async fn fan_out_count(&self, statement: D1PreparedStatement) -> worker::Result<usize> {
        let result = statement.run().await?;
        D1Adapter::changes(&result)
    }
}

#[derive(Deserialize)]
struct NextVersionRow {
    next_version: i64,
}

fn invalid_input() -> worker::Error {
    worker::Error::RustError("invalid P06 event-delivery input".into())
}

fn invalid_row() -> worker::Error {
    worker::Error::RustError("invalid P06 event-delivery row".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_states_round_trip_through_the_frozen_wire_names() {
        for state in [
            WebhookDeliveryState::Pending,
            WebhookDeliveryState::Queued,
            WebhookDeliveryState::Delivering,
            WebhookDeliveryState::Delivered,
            WebhookDeliveryState::RetryWait,
            WebhookDeliveryState::DeadLetter,
            WebhookDeliveryState::Cancelled,
        ] {
            assert_eq!(WebhookDeliveryState::parse(state.as_str()), Some(state));
        }
        assert_eq!(WebhookDeliveryState::parse("unknown"), None);
        assert!(WebhookDeliveryState::Delivered.is_terminal());
        assert!(WebhookDeliveryState::DeadLetter.is_terminal());
        assert!(WebhookDeliveryState::Cancelled.is_terminal());
        assert!(!WebhookDeliveryState::Delivering.is_terminal());
        assert!(WebhookDeliveryState::Pending.is_claimable());
        assert!(WebhookDeliveryState::Queued.is_claimable());
        assert!(WebhookDeliveryState::RetryWait.is_claimable());
        assert!(!WebhookDeliveryState::Delivering.is_claimable());
    }

    #[test]
    fn job_type_vocabulary_matches_the_frozen_list_exactly() {
        let expected = [
            "automation.generate_occurrence",
            "automation.dispatch",
            "automation.expire_lease",
            "webhook.deliver",
            "notification.deliver",
            "billing.sync",
            "license.issue",
            "export.run",
            "deletion.run",
        ];
        for value in expected {
            let parsed = JobType::parse(value).expect("frozen job type parses");
            assert_eq!(parsed.as_str(), value);
        }
        assert!(JobType::parse("webhook.deliver.v2").is_none());
        assert!(JobType::parse("unknown.job").is_none());
        assert_eq!(expected.len(), 9);
    }

    #[test]
    fn only_event_delivery_job_types_are_owned_by_this_packet() {
        assert!(JobType::WebhookDeliver.is_event_delivery());
        assert!(JobType::NotificationDeliver.is_event_delivery());
        for other in [
            JobType::GenerateOccurrence,
            JobType::Dispatch,
            JobType::ExpireLease,
            JobType::BillingSync,
            JobType::LicenseIssue,
            JobType::ExportRun,
            JobType::DeletionRun,
        ] {
            assert!(!other.is_event_delivery());
        }
    }

    #[test]
    fn fan_out_requires_exact_event_match_and_excludes_recursive_families() {
        let sql = FAN_OUT_DELIVERIES_SQL;
        assert!(sql.contains("e.org_id = ?1"));
        assert!(sql.contains("subscribed.value = ?3"));
        // A wildcard subscription must never be able to match.
        assert!(!sql.contains("LIKE '%'"));
        assert!(sql.contains("?3 NOT LIKE 'webhook.delivery_%'"));
        assert!(sql.contains("?3 NOT LIKE 'webhook.endpoint_%'"));
        assert!(sql.contains("?3 NOT LIKE 'notification.delivery_%'"));
        assert!(sql.contains("?3 <> 'webhook.test.v1'"));
        assert!(sql.contains("e.current_secret_version_id IS NOT NULL"));
        assert!(sql.contains("INSERT OR IGNORE INTO webhook_deliveries"));
    }

    #[test]
    fn replay_creates_a_linked_successor_and_never_edits_the_original() {
        assert!(INSERT_REPLAY_DELIVERY_SQL.contains("replay_of_delivery_id"));
        assert!(!INSERT_REPLAY_DELIVERY_SQL.contains("UPDATE"));
        // A fresh version and generation on the successor row.
        assert!(INSERT_REPLAY_DELIVERY_SQL.contains("'pending', 0, ?9, ?10, ?11, 1, ?9, ?9"));
    }

    #[test]
    fn delivery_transitions_are_compare_and_set_on_state_and_version() {
        for sql in [
            MARK_DELIVERY_QUEUED_SQL,
            MARK_DELIVERY_DELIVERING_SQL,
            MARK_DELIVERY_DELIVERED_SQL,
            MARK_DELIVERY_RETRY_SQL,
            MARK_DELIVERY_DEAD_LETTER_SQL,
        ] {
            assert!(sql.contains("version = version + 1"), "{sql}");
        }
        assert!(MARK_DELIVERY_DELIVERING_SQL.contains("AND state = ?3 AND version = ?4"));
        assert!(MARK_DELIVERY_DELIVERED_SQL.contains("AND state = 'delivering' AND version = ?3"));
        assert!(MARK_DELIVERY_RETRY_SQL.contains("AND state = 'delivering' AND version = ?5"));
        assert!(
            MARK_DELIVERY_DEAD_LETTER_SQL.contains("AND state = 'delivering' AND version = ?4")
        );
        // attempt_count is incremented exactly once, by the claim.
        assert!(MARK_DELIVERY_DELIVERING_SQL.contains("attempt_count = attempt_count + 1"));
    }

    #[test]
    fn disabling_cancels_only_non_terminal_deliveries() {
        assert!(
            CANCEL_ENDPOINT_DELIVERIES_SQL.contains("state IN ('pending', 'queued', 'retry_wait')")
        );
        assert!(!CANCEL_ENDPOINT_DELIVERIES_SQL.contains("'delivered'"));
        assert!(!CANCEL_ENDPOINT_DELIVERIES_SQL.contains("'dead_letter'"));
    }

    #[test]
    fn job_claim_is_a_cas_over_id_attempt_state_and_lease_version() {
        assert!(CLAIM_JOB_SQL.contains("AND attempt = ?3"));
        assert!(CLAIM_JOB_SQL.contains("AND state = ?4"));
        assert!(CLAIM_JOB_SQL.contains("AND lease_version = ?5"));
        assert!(CLAIM_JOB_SQL.contains("lease_version = lease_version + 1"));
        // The unique dedupe index is the D1 half of the dedupe contract.
        assert!(
            INSERT_QUEUE_JOB_SQL
                .trim_start()
                .starts_with("INSERT OR IGNORE INTO queue_job_envelopes")
        );
    }

    #[test]
    fn notification_reads_are_scoped_to_the_authenticated_principal() {
        assert!(NOTIFICATION_BY_ID_SQL.contains("AND user_id = ?2"));
        assert!(NOTIFICATIONS_PAGE_SQL.contains("WHERE user_id = ?1"));
        assert!(MARK_NOTIFICATION_READ_SQL.contains("AND user_id = ?3"));
        // Marking read is idempotent: only an unread row is touched.
        assert!(MARK_NOTIFICATION_READ_SQL.contains("AND state = 'unread'"));
        assert!(MARK_NOTIFICATION_READ_SQL.contains("COALESCE(read_at, ?2)"));
    }

    #[test]
    fn notification_inbox_is_keyset_paginated_in_descending_order() {
        assert!(NOTIFICATIONS_PAGE_SQL.contains("(created_at, notification_id) < (?4, ?5)"));
        assert!(NOTIFICATIONS_PAGE_SQL.contains("ORDER BY created_at DESC, notification_id DESC"));
    }

    #[test]
    fn delivery_history_is_keyset_paginated_per_endpoint() {
        assert!(DELIVERIES_PAGE_SQL.contains("WHERE org_id = ?1 AND endpoint_id = ?2"));
        assert!(DELIVERIES_PAGE_SQL.contains("(created_at, delivery_id) < (?4, ?5)"));
        assert!(DELIVERIES_PAGE_SQL.contains("ORDER BY created_at DESC, delivery_id DESC"));
    }

    #[test]
    fn preference_versions_are_asserted_before_the_upsert_commits() {
        assert!(UPSERT_PREFERENCE_SQL.contains("WHERE notification_preferences.version = ?8"));
        assert!(ASSERT_PREFERENCE_VERSION_SQL.contains("version = ?3"));
        assert!(ASSERT_PREFERENCE_VERSION_SQL.contains("SELECT NULL, '', '', '', '', ''"));
    }

    #[test]
    fn notification_and_preference_vocabularies_are_frozen() {
        assert_eq!(NOTIFICATION_CATEGORIES.len(), 5);
        assert!(NOTIFICATION_CATEGORIES.contains(&"security"));
        assert_eq!(NOTIFICATION_CHANNELS, ["in_app", "email"]);
        for state in [
            NotificationState::Unread,
            NotificationState::Read,
            NotificationState::Archived,
        ] {
            assert_eq!(NotificationState::parse(state.as_str()), Some(state));
        }
        for state in [
            NotificationDeliveryState::Pending,
            NotificationDeliveryState::Queued,
            NotificationDeliveryState::Delivered,
            NotificationDeliveryState::RetryWait,
            NotificationDeliveryState::DeadLetter,
            NotificationDeliveryState::Cancelled,
        ] {
            assert_eq!(
                NotificationDeliveryState::parse(state.as_str()),
                Some(state)
            );
        }
    }

    #[test]
    fn records_never_debug_print_the_stored_body_or_secret_material() {
        let delivery = WebhookDeliveryRecord {
            delivery_id: "whd_0123456789abcdef0123456789abcdef".to_owned(),
            endpoint_id: "whe_0123456789abcdef0123456789abcdef".to_owned(),
            org_id: "org_0123456789abcdef0123456789abcdef".to_owned(),
            event_id: "evt_0123456789abcdef0123456789abcdef".to_owned(),
            event_type: "run.completed.v1".to_owned(),
            body: "{\"private\":\"body\"}".to_owned(),
            body_hash: "sha256:abc".to_owned(),
            secret_version_id: "whs_0123456789abcdef0123456789abcdef".to_owned(),
            signature_key_id: "whs_0123456789abcdef0123456789abcdef".to_owned(),
            state: "delivered".to_owned(),
            attempt_count: 1,
            next_attempt_at: None,
            delivered_at: Some("2026-09-25T16:00:00.000Z".to_owned()),
            last_error_code: None,
            replay_of_delivery_id: None,
            replay_generation: 0,
            version: 1,
            created_at: "2026-09-25T16:00:00.000Z".to_owned(),
            updated_at: "2026-09-25T16:00:00.000Z".to_owned(),
        };
        assert!(!format!("{delivery:?}").contains("private"));

        let secret = WebhookSecretRecord {
            secret_version_id: "whs_0123456789abcdef0123456789abcdef".to_owned(),
            endpoint_id: "whe_0123456789abcdef0123456789abcdef".to_owned(),
            org_id: "org_0123456789abcdef0123456789abcdef".to_owned(),
            ciphertext: "ciphertext-value".to_owned(),
            nonce: "nonce-value".to_owned(),
            fingerprint: "0123456789abcdef".to_owned(),
            version: 1,
            created_at: "2026-09-25T16:00:00.000Z".to_owned(),
            rotated_at: None,
            revoked_at: None,
        };
        let debug = format!("{secret:?}");
        assert!(!debug.contains("ciphertext-value"));
        assert!(!debug.contains("nonce-value"));
    }
}
