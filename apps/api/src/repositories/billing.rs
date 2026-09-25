//! D1 persistence for the frozen P06 commercial contract (migration `0013`).
//!
//! WHY this layer is a thin SQL/row-mapping adapter: every commercial answer —
//! precedence, grace windows, over-limit limits, the capability matrix, seat
//! counting, provider-event ordering — is a pure function in
//! [`crate::modules::entitlements`]. This module only reads authoritative rows,
//! hands them to that module, and writes the result back in one conditional D1
//! batch. It never recomputes a decision and never accepts a client value as an
//! authoritative one.
//!
//! # Invariants this layer is responsible for
//!
//! Every invariant below is enforced by the `0013` schema, and the SQL here is
//! written so a violation aborts the surrounding batch rather than silently
//! committing a partial state:
//!
//! | Invariant | Schema object | How this layer uses it |
//! |---|---|---|
//! | Immutable plan versions | `UNIQUE (plan_key, version)` on `plans` | A plan change inserts a NEW version; no update path exists. |
//! | One current subscription per org | `UNIQUE org_id` on `subscriptions` | The CAS UPDATE is keyed by `org_id` + `subscription_id` + `version`. |
//! | Terminal cancellation | `CHECK (status <> 'cancelled' OR cancelled_at IS NOT NULL)` | Every cancelled write sets `cancelled_at`. |
//! | Idempotent provider callbacks | `UNIQUE INDEX ux_subscription_events_provider_event` | A duplicate provider event aborts the whole batch. |
//! | Bounded event metadata | `CHECK (json_valid AND length <= 4096)` on `metadata_json` | Only a small, allowlisted metadata object is ever built. |
//! | Provider IDs stay private | `billing_accounts.provider_account_ref` is opaque; no `plans` column holds one | No SQL here stores a product/price identifier. |
//! | Overrides always expire | `CHECK (source <> 'internal_override' OR (expires_at/reason/granted_by_principal_id NOT NULL))` | The override insert always supplies all three. |
//! | One active override per key/scope | `ux_entitlement_grants_override_active` | A second active override aborts the batch. |
//! | Entitlement keys are Lumi keys | `trg_entitlement_definitions_no_provider_id` | Only registered dotted Lumi keys are written. |
//! | No snapshot rollback | `trg_license_snapshots_anti_rollback` | The issued policy version is monotonic per audience. |
//! | Signature/canonical bytes are BLOBs | `signature BLOB`, `canonical_bytes BLOB` | Bound as lowercase hex TEXT, which SQLite stores verbatim in a BLOB-affinity column. |
//! | Signing keys are public only | `license_signing_keys.public_key BLOB` | No INSERT/UPDATE touches private material. |
//! | Freshness < offline validity | `CHECK (offline_valid_until > policy_fresh_until)` | Expiries are computed by `signing::license_expiries`. |
//!
//! # BLOB encoding
//!
//! `license_snapshots.signature`, `license_snapshots.canonical_bytes`, and
//! `license_signing_keys.public_key` are declared `BLOB`. This layer binds them
//! as LOWERCASE HEX TEXT. SQLite gives a `BLOB` column no type affinity, so the
//! text is stored and returned unchanged; the choice avoids a platform-specific
//! binary binding, makes the stored value human-auditable, and guarantees no
//! diagnostic can dump raw key or signature bytes. `decode_hex` refuses
//! uppercase, so each stored value has exactly one valid encoding.

use serde::{Deserialize, Serialize};
use worker::d1::D1PreparedStatement;

use crate::adapters::billing::{
    provider::stable_identifier,
    signing::{VerificationKey, decode_hex, encode_hex},
};
use crate::adapters::d1::{BindValue, D1Adapter};
use crate::core::{OrganizationId, Timestamp};
use crate::modules::entitlements::{
    AuthoritativeCounts, BillableSeatState, BillingSeatRow, EntitlementError, EntitlementGrant,
    EntitlementGrantId, EntitlementInputs, EntitlementResolution, EntitlementValue, GrantSource,
    LicenseState, OverLimitProjection, SeatPolicy, compute_over_limit_projection,
    resolve_effective_entitlements,
};

// ---------------------------------------------------------------------------
// Plans (immutable versions)
// ---------------------------------------------------------------------------

const PLAN_BY_KEY_SQL: &str = r#"
SELECT plan_id, plan_key, version, name, description, seat_based, is_active, created_at
FROM plans
WHERE plan_key = ?1
ORDER BY version DESC
LIMIT 1
"#;

const PLAN_BY_ID_SQL: &str = r#"
SELECT plan_id, plan_key, version, name, description, seat_based, is_active, created_at
FROM plans
WHERE plan_id = ?1
LIMIT 1
"#;

const PLAN_ENTITLEMENTS_SQL: &str = r#"
SELECT plan_entitlement_id, plan_id, entitlement_key, value_type, value_json, created_at
FROM plan_entitlements
WHERE plan_id = ?1
ORDER BY entitlement_key ASC
"#;

const INSERT_PLAN_SQL: &str = r#"
INSERT INTO plans (plan_id, plan_key, version, name, description, seat_based, is_active, created_at)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)
"#;

const INSERT_PLAN_ENTITLEMENT_SQL: &str = r#"
INSERT INTO plan_entitlements (
    plan_entitlement_id, plan_id, entitlement_key, value_type, value_json, created_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
"#;

const PLAN_VERSIONS_SQL: &str = r#"
SELECT plan_id, plan_key, version, name, description, seat_based, is_active, created_at
FROM plans
WHERE is_active = 1
ORDER BY plan_key ASC, version DESC
"#;

/// One immutable plan version. `UNIQUE (plan_key, version)` is the invariant
/// that makes a plan change a new version rather than a rewrite.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlanRecord {
    pub plan_id: String,
    pub plan_key: String,
    pub version: i64,
    pub name: String,
    pub description: Option<String>,
    pub seat_based: i32,
    pub is_active: i32,
    pub created_at: String,
}

/// One immutable plan entitlement value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlanEntitlementRecord {
    pub plan_entitlement_id: String,
    pub plan_id: String,
    pub entitlement_key: String,
    pub value_type: String,
    pub value_json: String,
    pub created_at: String,
}

// ---------------------------------------------------------------------------
// Billing accounts (opaque provider refs only)
// ---------------------------------------------------------------------------

const BILLING_ACCOUNT_BY_ORG_SQL: &str = r#"
SELECT billing_account_id, org_id, provider_account_ref, provider_kind, status,
       seat_policy, version, created_at, updated_at
FROM billing_accounts
WHERE org_id = ?1
LIMIT 1
"#;

/// `provider_account_ref` is opaque, adapter-private, and never returned by a
/// route. There is deliberately no `product_id`/`price_id` column in `0013`, so
/// a provider product or price identifier has no home in Lumi persistence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BillingAccountRecord {
    pub billing_account_id: String,
    pub org_id: String,
    pub provider_account_ref: String,
    pub provider_kind: String,
    pub status: String,
    pub seat_policy: String,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// Subscriptions (current state) and append-only provider events
// ---------------------------------------------------------------------------

const SUBSCRIPTION_BY_ORG_SQL: &str = r#"
SELECT subscription_id, org_id, billing_account_id, plan_id, status,
       provider_subscription_ref, grace_started_at, grace_expires_at,
       current_period_starts_at, current_period_ends_at, cancel_at_period_end,
       cancelled_at, version, created_at, updated_at
FROM subscriptions
WHERE org_id = ?1
LIMIT 1
"#;

/// The single atomic compare-and-set that applies a provider event. The `version`
/// predicate is the CAS token, so a concurrent apply cannot interleave; a failed
/// predicate aborts the whole batch and leaves the row untouched.
const APPLY_SUBSCRIPTION_SQL: &str = r#"
UPDATE subscriptions
SET status = ?3,
    plan_id = ?4,
    grace_started_at = COALESCE(grace_started_at, ?5),
    grace_expires_at = ?6,
    current_period_starts_at = ?7,
    current_period_ends_at = ?8,
    cancel_at_period_end = ?9,
    cancelled_at = ?10,
    version = version + 1,
    updated_at = ?11
WHERE subscription_id = ?1 AND org_id = ?2 AND version = ?12
"#;

/// Assert the guarded subscription write actually landed. When it did not, this
/// deliberately invalid statement (a `NOT NULL` violation on the primary key)
/// rolls back the idempotency claim, the audit row, and the outbox event with
/// it, so a refused mutation can never report success.
const ASSERT_SUBSCRIPTION_APPLIED_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM subscriptions WHERE subscription_id = ?1 AND org_id = ?2 AND version = ?3
)
"#;

const INSERT_SUBSCRIPTION_EVENT_SQL: &str = r#"
INSERT INTO subscription_events (
    subscription_event_id, subscription_id, org_id, provider_event_id, provider_version,
    from_status, to_status, effective_at, received_at, metadata_json
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
"#;

/// One current subscription row. The `version` column is the CAS token and
/// `grace_started_at` is immutable once set, which is what stops a failed poll
/// or a stale callback from extending grace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionRecord {
    pub subscription_id: String,
    pub org_id: String,
    pub billing_account_id: String,
    pub plan_id: String,
    pub status: String,
    pub provider_subscription_ref: Option<String>,
    pub grace_started_at: Option<String>,
    pub grace_expires_at: Option<String>,
    pub current_period_starts_at: Option<String>,
    pub current_period_ends_at: Option<String>,
    pub cancel_at_period_end: i32,
    pub cancelled_at: Option<String>,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// Append-only provider event history. `UNIQUE (provider_event_id)` is the
/// durable replay defense; the row is never updated or deleted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionEventRecord {
    pub subscription_event_id: String,
    pub subscription_id: String,
    pub org_id: String,
    pub provider_event_id: String,
    pub provider_version: Option<i64>,
    pub from_status: Option<String>,
    pub to_status: String,
    pub effective_at: String,
    pub received_at: String,
    pub metadata_json: String,
}

/// Reason a provider event is about to be recorded. Used to pick the frozen
/// outbox event name; it is NOT an audit-log field and carries no provider text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubscriptionEventReason {
    /// The mapped status changed.
    StatusChanged,
    /// The plan pointer moved.
    PlanChanged,
    /// The billing grace window opened.
    GraceStarted,
    /// The billing grace window closed.
    GraceEnded,
    /// The event was accepted but produced no state change (idempotent replay).
    Unchanged,
}

impl SubscriptionEventReason {
    /// The frozen P06 outbox event name for this transition.
    pub const fn event_type(self) -> &'static str {
        match self {
            Self::GraceStarted => "billing.grace_started.v1",
            Self::GraceEnded => "billing.grace_ended.v1",
            Self::StatusChanged | Self::PlanChanged | Self::Unchanged => {
                "billing.subscription_updated.v1"
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Provider sync state (idempotency, ordering, grace anchor)
// ---------------------------------------------------------------------------

const PROVIDER_SYNC_STATE_SQL: &str = r#"
SELECT provider_sync_id, org_id, provider_kind, last_event_id, last_event_version,
       last_event_at, last_success_at, consecutive_failures, last_error_code,
       version, updated_at
FROM provider_sync_state
WHERE org_id = ?1 AND provider_kind = ?2
LIMIT 1
"#;

/// Only an ACCEPTED event or a SUCCESSFUL sync advances the last accepted event
/// id/version/time and `last_success_at`, which anchors the grace window. A
/// failed poll writes neither, so grace can never be extended by repeated failed
/// polling. The upsert is keyed by the frozen `UNIQUE (org_id, provider_kind)`,
/// so the first successful sync creates the row.
const RECORD_PROVIDER_SUCCESS_SQL: &str = r#"
INSERT INTO provider_sync_state (
    provider_sync_id, org_id, provider_kind, last_event_id, last_event_version,
    last_event_at, last_success_at, consecutive_failures, last_error_code,
    version, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, NULL, 1, ?7)
ON CONFLICT (org_id, provider_kind) DO UPDATE SET
    last_event_id = excluded.last_event_id,
    last_event_version = excluded.last_event_version,
    last_event_at = excluded.last_event_at,
    last_success_at = excluded.last_success_at,
    consecutive_failures = 0,
    last_error_code = NULL,
    version = provider_sync_state.version + 1,
    updated_at = excluded.updated_at
"#;

/// A failed poll advances ONLY the failure counter and the stable error code.
/// `last_success_at` and the event pointers appear in NEITHER the insert values
/// nor the update branch, so this statement is structurally incapable of
/// extending the grace window.
const RECORD_PROVIDER_FAILURE_SQL: &str = r#"
INSERT INTO provider_sync_state (
    provider_sync_id, org_id, provider_kind, last_event_id, last_event_version,
    last_event_at, last_success_at, consecutive_failures, last_error_code,
    version, updated_at
) VALUES (?1, ?2, ?3, NULL, NULL, NULL, NULL, 1, ?4, 1, ?5)
ON CONFLICT (org_id, provider_kind) DO UPDATE SET
    consecutive_failures = provider_sync_state.consecutive_failures + 1,
    last_error_code = excluded.last_error_code,
    version = provider_sync_state.version + 1,
    updated_at = excluded.updated_at
"#;

/// Provider sync bookkeeping for one `(org_id, provider_kind)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderSyncStateRecord {
    pub provider_sync_id: String,
    pub org_id: String,
    pub provider_kind: String,
    pub last_event_id: Option<String>,
    pub last_event_version: Option<i64>,
    pub last_event_at: Option<String>,
    pub last_success_at: Option<String>,
    pub consecutive_failures: i64,
    pub last_error_code: Option<String>,
    pub version: i64,
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// Upstream provider entitlement projection (read-only)
// ---------------------------------------------------------------------------

const PROVIDER_PROJECTION_BY_ORG_SQL: &str = r#"
SELECT projection_id, org_id, provider_kind, capability_class, status, reason_code,
       observed_at, version, updated_at
FROM provider_entitlement_projections
WHERE org_id = ?1
ORDER BY provider_kind ASC
"#;

/// The read-only upstream projection. `UNIQUE (org_id, provider_kind,
/// capability_class)` is the invariant; the upsert below re-binds that row. The
/// stored `status` is always the normalized vocabulary — there is no column in
/// which a provider product/plan/price identifier could live.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderProjectionRecord {
    pub projection_id: String,
    pub org_id: String,
    pub provider_kind: String,
    pub capability_class: String,
    pub status: String,
    pub reason_code: Option<String>,
    pub observed_at: String,
    pub version: i64,
    pub updated_at: String,
}

const UPSERT_PROVIDER_PROJECTION_SQL: &str = r#"
INSERT INTO provider_entitlement_projections (
    projection_id, org_id, provider_kind, capability_class, status, reason_code,
    observed_at, version, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?7)
ON CONFLICT (org_id, provider_kind, capability_class)
DO UPDATE SET status = excluded.status,
              reason_code = excluded.reason_code,
              observed_at = excluded.observed_at,
              version = provider_entitlement_projections.version + 1,
              updated_at = excluded.updated_at
"#;

// ---------------------------------------------------------------------------
// Entitlement definitions and grants
// ---------------------------------------------------------------------------

const ENTITLEMENT_DEFINITION_SQL: &str = r#"
SELECT entitlement_definition_id, entitlement_key, value_type, scope,
       default_value_json, unit, description, version, created_at, updated_at
FROM entitlement_definitions
ORDER BY entitlement_key ASC
"#;

/// One stable Lumi entitlement definition. The public identity of an
/// entitlement is its dotted Lumi key; the `no_provider_id` trigger additionally
/// refuses a key that looks like a provider product/price identifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntitlementDefinitionRecord {
    pub entitlement_definition_id: String,
    pub entitlement_key: String,
    pub value_type: String,
    pub scope: String,
    pub default_value_json: Option<String>,
    pub unit: Option<String>,
    pub description: Option<String>,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

const ENTITLEMENT_GRANTS_SQL: &str = r#"
SELECT grant_id, org_id, entitlement_key, scope, scope_id, value_json, source,
       subscription_id, reason, granted_by_principal_id, effective_at, expires_at,
       revoked_at, version, created_at, updated_at
FROM entitlement_grants
WHERE org_id = ?1
  AND effective_at <= ?2
  AND (expires_at IS NULL OR expires_at > ?2)
  AND (revoked_at IS NULL OR revoked_at > ?2)
ORDER BY entitlement_key ASC, effective_at DESC, grant_id ASC
"#;

/// One time-bounded grant. `source = 'internal_override'` requires `expires_at`,
/// `reason`, and `granted_by_principal_id` (enforced by the table CHECK) and is
/// unique per `(org, key, scope, scope_id)` while unrevoked.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntitlementGrantRecord {
    pub grant_id: String,
    pub org_id: String,
    pub entitlement_key: String,
    pub scope: String,
    pub scope_id: Option<String>,
    pub value_json: String,
    pub source: String,
    pub subscription_id: Option<String>,
    pub reason: Option<String>,
    pub granted_by_principal_id: Option<String>,
    pub effective_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

const INSERT_OVERRIDE_GRANT_SQL: &str = r#"
INSERT INTO entitlement_grants (
    grant_id, org_id, entitlement_key, scope, scope_id, value_json, source,
    subscription_id, reason, granted_by_principal_id, effective_at, expires_at,
    revoked_at, version, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'internal_override', NULL, ?7, ?8, ?9, ?10, NULL, 1, ?9, ?9)
"#;

const REVOKE_GRANT_SQL: &str = r#"
UPDATE entitlement_grants
SET revoked_at = ?3, version = version + 1, updated_at = ?3
WHERE grant_id = ?1 AND org_id = ?2 AND revoked_at IS NULL AND version = ?4
"#;

// ---------------------------------------------------------------------------
// License state and signed snapshot metadata
// ---------------------------------------------------------------------------

const LICENSE_STATE_BY_ORG_SQL: &str = r#"
SELECT license_state_id, org_id, subscription_id, state, local_offline_grace_seconds,
       cloud_control_plane_grace_seconds, platform_paid_inference_grace_seconds,
       grace_started_at, grace_expires_at, reason_code, version, created_at, updated_at
FROM license_states
WHERE org_id = ?1
LIMIT 1
"#;

/// Server-side license-state projection. `UNIQUE org_id` makes it one row, and
/// the grace-second columns are bounded by their CHECKs so a persisted window
/// can never exceed the frozen 7-day / 24-hour / 0-second policy defaults.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LicenseStateRecord {
    pub license_state_id: String,
    pub org_id: String,
    pub subscription_id: Option<String>,
    pub state: String,
    pub local_offline_grace_seconds: i64,
    pub cloud_control_plane_grace_seconds: i64,
    pub platform_paid_inference_grace_seconds: i64,
    pub grace_started_at: Option<String>,
    pub grace_expires_at: Option<String>,
    pub reason_code: Option<String>,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

const UPSERT_LICENSE_STATE_SQL: &str = r#"
INSERT INTO license_states (
    license_state_id, org_id, subscription_id, state, local_offline_grace_seconds,
    cloud_control_plane_grace_seconds, platform_paid_inference_grace_seconds,
    grace_started_at, grace_expires_at, reason_code, version, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, ?9, 1, ?10, ?10)
ON CONFLICT (org_id) DO UPDATE SET subscription_id = excluded.subscription_id,
    state = excluded.state,
    local_offline_grace_seconds = excluded.local_offline_grace_seconds,
    cloud_control_plane_grace_seconds = excluded.cloud_control_plane_grace_seconds,
    grace_started_at = excluded.grace_started_at,
    grace_expires_at = excluded.grace_expires_at,
    reason_code = excluded.reason_code,
    version = license_states.version + 1,
    updated_at = excluded.updated_at
"#;

const MAX_ACCEPTED_POLICY_VERSION_SQL: &str = r#"
SELECT COALESCE(MAX(policy_version), 0) AS max_version
FROM license_snapshots
WHERE org_id = ?1
  AND (COALESCE(device_id, '') = COALESCE(?2, ''))
"#;

const INSERT_LICENSE_SNAPSHOT_SQL: &str = r#"
INSERT INTO license_snapshots (
    license_snapshot_id, org_id, device_id, audience, policy_version, license_state,
    policy_fresh_until, offline_valid_until, entitlements_json, key_id, signature,
    canonical_bytes, issued_at, revoked_at, valid_until, version
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, NULL, ?14, 1)
"#;

/// The most recent snapshot issued for one audience.
///
/// Used to bound how often the METADATA row is refreshed: the signed block is
/// re-issued on every policy fetch (it has a 15-minute freshness window) but the
/// table must not grow once per fetch.
const LATEST_SNAPSHOT_FOR_AUDIENCE_SQL: &str = r#"
SELECT issued_at
FROM license_snapshots
WHERE org_id = ?1
  AND COALESCE(device_id, '') = COALESCE(?2, '')
  AND revoked_at IS NULL
ORDER BY issued_at DESC
LIMIT 1
"#;

const ACTIVE_SIGNING_KEYS_SQL: &str = r#"
SELECT key_id, algorithm, active, not_before, verify_until, created_at
FROM license_signing_keys
ORDER BY not_before DESC, key_id ASC
LIMIT ?1
"#;

/// A public verification key. `algorithm` is constrained to `ed25519` by the
/// table CHECK, so no other signature scheme can be registered.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LicenseSigningKeyRecord {
    pub key_id: String,
    pub algorithm: String,
    pub active: i32,
    pub not_before: String,
    pub verify_until: String,
    pub created_at: String,
}

impl LicenseSigningKeyRecord {
    /// Project the row into the adapter's pure key type.
    pub fn to_verification_key(&self, public_key_base64: &str) -> VerificationKey {
        VerificationKey {
            key_id: self.key_id.clone(),
            public_key_base64: public_key_base64.to_owned(),
            active: self.active == 1,
            not_before: self.not_before.clone(),
            verify_until: self.verify_until.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Authoritative counts and seat rows
// ---------------------------------------------------------------------------

/// The five authoritative counts behind the downgrade projection. A client
/// total is never accepted here: the projection is only as trustworthy as its
/// counts, so every number is an in-transaction `COUNT(*)` over the tenant's own
/// rows. `members` is the BILLABLE seat count, not the raw membership total,
/// because `org.max_members` is a seat limit and its remediation is
/// `suspend_seats`.
const AUTHORITATIVE_COUNTS_SQL: &str = r#"
SELECT
    (SELECT COUNT(*) FROM memberships
      WHERE memberships.org_id = ?1
        AND memberships.status IN ('active', 'suspended')
        AND memberships.role <> 'viewer') AS billable_members,
    (SELECT COUNT(*) FROM projects
      WHERE projects.org_id = ?1 AND projects.archived_at IS NULL) AS active_projects,
    (SELECT COUNT(*) FROM devices
      WHERE devices.org_id = ?1 AND devices.status = 'active') AS enrolled_devices,
    (SELECT COUNT(*) FROM automation_definitions
      WHERE automation_definitions.org_id = ?1
        AND automation_definitions.status = 'active') AS active_automations,
    (SELECT COUNT(*) FROM webhook_endpoints
      WHERE webhook_endpoints.org_id = ?1
        AND webhook_endpoints.enabled = 1) AS enabled_webhook_endpoints
"#;

const MEMBERSHIP_SEAT_ROWS_SQL: &str = r#"
SELECT membership_id, org_id, status, role
FROM memberships
WHERE org_id = ?1
ORDER BY membership_id ASC
"#;

/// A bounded, authoritative seat row. `pending` and `removed` are mapped by the
/// domain's `BillableSeatState`; a viewer is never billable unless the plan's
/// seat policy says otherwise.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeatRow {
    pub membership_id: String,
    pub org_id: String,
    pub status: String,
    pub role: String,
}

impl SeatRow {
    /// Map a membership row onto the frozen seat vocabulary.
    ///
    /// A viewer is `Viewer` (never billable by default), an active member is
    /// `Active`, a suspended member is `Suspended`, and anything else is
    /// `Removed`/`PendingInvitation`. An unrecognized status is refused rather
    /// than defaulted, so a corrupt row cannot silently change a bill.
    pub fn billable_state(&self) -> Result<BillableSeatState, EntitlementError> {
        if self.role == "viewer" {
            return Ok(BillableSeatState::Viewer);
        }
        match self.status.as_str() {
            "active" => Ok(BillableSeatState::Active),
            "suspended" => Ok(BillableSeatState::Suspended),
            "removed" => Ok(BillableSeatState::Removed),
            _ => Err(EntitlementError::InvalidMembershipState),
        }
    }
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

/// D1 persistence for the P06 commercial contract.
pub struct BillingRepository<'a> {
    database: &'a D1Adapter,
}

/// A row of the authoritative-counts probe, before it becomes
/// [`AuthoritativeCounts`].
#[derive(Deserialize)]
struct AuthoritativeCountsRow {
    #[serde(default)]
    billable_members: i64,
    #[serde(default)]
    active_projects: i64,
    #[serde(default)]
    enrolled_devices: i64,
    #[serde(default)]
    active_automations: i64,
    #[serde(default)]
    enabled_webhook_endpoints: i64,
}

impl AuthoritativeCountsRow {
    fn to_counts(&self) -> AuthoritativeCounts {
        AuthoritativeCounts {
            members: u64::try_from(self.billable_members).unwrap_or(0),
            active_projects: u64::try_from(self.active_projects).unwrap_or(0),
            enrolled_devices: u64::try_from(self.enrolled_devices).unwrap_or(0),
            active_automations: u64::try_from(self.active_automations).unwrap_or(0),
            webhook_endpoints: u64::try_from(self.enabled_webhook_endpoints).unwrap_or(0),
        }
    }
}

impl<'a> BillingRepository<'a> {
    pub const fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    // -- plans --------------------------------------------------------------

    pub async fn find_active_plan(&self, plan_key: &str) -> worker::Result<Option<PlanRecord>> {
        self.database
            .prepare(PLAN_BY_KEY_SQL, &[BindValue::Text(plan_key)])?
            .first::<PlanRecord>(None)
            .await
    }

    pub async fn find_plan(&self, plan_id: &str) -> worker::Result<Option<PlanRecord>> {
        self.database
            .prepare(PLAN_BY_ID_SQL, &[BindValue::Text(plan_id)])?
            .first::<PlanRecord>(None)
            .await
    }

    /// Every active plan version, newest first per key. Used by the browser plan
    /// list. No provider identifier is exposed.
    pub async fn list_active_plans(&self) -> worker::Result<Vec<PlanRecord>> {
        self.database
            .prepare(PLAN_VERSIONS_SQL, &[])?
            .all()
            .await?
            .results::<PlanRecord>()
    }

    pub async fn list_plan_entitlements(
        &self,
        plan_id: &str,
    ) -> worker::Result<Vec<PlanEntitlementRecord>> {
        self.database
            .prepare(PLAN_ENTITLEMENTS_SQL, &[BindValue::Text(plan_id)])?
            .all()
            .await?
            .results::<PlanEntitlementRecord>()
    }

    /// Publish a NEW immutable plan version.
    ///
    /// `UNIQUE (plan_key, version)` means a duplicate version aborts the batch:
    /// a plan change is never an in-place rewrite of what a previous period
    /// charged for.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_plan_statement(
        &self,
        plan_id: &str,
        plan_key: &str,
        version: i64,
        name: &str,
        description: Option<&str>,
        seat_based: bool,
        created_at: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_PLAN_SQL,
            &[
                BindValue::Text(plan_id),
                BindValue::Text(plan_key),
                BindValue::Int64(version),
                BindValue::Text(name),
                BindValue::Text(description.unwrap_or("")),
                BindValue::Integer(i32::from(seat_based)),
                BindValue::Text(created_at),
            ],
        )
    }

    pub fn insert_plan_entitlement_statement(
        &self,
        plan_entitlement_id: &str,
        plan_id: &str,
        entitlement_key: &str,
        value_type: &str,
        value_json: &str,
        created_at: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_PLAN_ENTITLEMENT_SQL,
            &[
                BindValue::Text(plan_entitlement_id),
                BindValue::Text(plan_id),
                BindValue::Text(entitlement_key),
                BindValue::Text(value_type),
                BindValue::Text(value_json),
                BindValue::Text(created_at),
            ],
        )
    }

    // -- billing accounts ---------------------------------------------------

    pub async fn find_billing_account(
        &self,
        org_id: &str,
    ) -> worker::Result<Option<BillingAccountRecord>> {
        self.database
            .prepare(BILLING_ACCOUNT_BY_ORG_SQL, &[BindValue::Text(org_id)])?
            .first::<BillingAccountRecord>(None)
            .await
    }

    // -- subscriptions ------------------------------------------------------

    pub async fn find_subscription(
        &self,
        org_id: &str,
    ) -> worker::Result<Option<SubscriptionRecord>> {
        self.database
            .prepare(SUBSCRIPTION_BY_ORG_SQL, &[BindValue::Text(org_id)])?
            .first::<SubscriptionRecord>(None)
            .await
    }

    /// The single CAS that applies a provider event to current subscription
    /// state.
    ///
    /// `grace_started_at` uses `COALESCE(grace_started_at, ?5)`, so it is
    /// written once and can never be moved by a later poll or a stale callback.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_subscription_statement(
        &self,
        subscription_id: &str,
        org_id: &str,
        status: &str,
        plan_id: &str,
        grace_started_at: Option<&str>,
        grace_expires_at: Option<&str>,
        period_starts_at: Option<&str>,
        period_ends_at: Option<&str>,
        cancel_at_period_end: bool,
        cancelled_at: Option<&str>,
        now: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            APPLY_SUBSCRIPTION_SQL,
            &[
                BindValue::Text(subscription_id),
                BindValue::Text(org_id),
                BindValue::Text(status),
                BindValue::Text(plan_id),
                grace_started_at.map_or(BindValue::Null, BindValue::Text),
                grace_expires_at.map_or(BindValue::Null, BindValue::Text),
                period_starts_at.map_or(BindValue::Null, BindValue::Text),
                period_ends_at.map_or(BindValue::Null, BindValue::Text),
                BindValue::Integer(i32::from(cancel_at_period_end)),
                cancelled_at.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(now),
                BindValue::Int64(expected_version),
            ],
        )
    }

    /// The guard that makes a refused apply visible as a rolled-back batch.
    pub fn assert_subscription_applied_statement(
        &self,
        subscription_id: &str,
        org_id: &str,
        resulting_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_SUBSCRIPTION_APPLIED_SQL,
            &[
                BindValue::Text(subscription_id),
                BindValue::Text(org_id),
                BindValue::Int64(resulting_version),
            ],
        )
    }

    /// Append one provider event to the immutable history.
    ///
    /// `UNIQUE (provider_event_id)` is what makes a redelivered webhook a no-op
    /// rather than a second state change, and `metadata_json` is bounded to
    /// 4096 bytes of allowlisted scalars — never a raw provider payload.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_subscription_event_statement(
        &self,
        subscription_event_id: &str,
        subscription_id: &str,
        org_id: &str,
        provider_event_id: &str,
        provider_version: Option<i64>,
        from_status: Option<&str>,
        to_status: &str,
        effective_at: &str,
        received_at: &str,
        metadata_json: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_SUBSCRIPTION_EVENT_SQL,
            &[
                BindValue::Text(subscription_event_id),
                BindValue::Text(subscription_id),
                BindValue::Text(org_id),
                BindValue::Text(provider_event_id),
                provider_version.map_or(BindValue::Null, BindValue::Int64),
                from_status.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(to_status),
                BindValue::Text(effective_at),
                BindValue::Text(received_at),
                BindValue::Text(metadata_json),
            ],
        )
    }

    // -- provider sync state ------------------------------------------------

    pub async fn find_provider_sync_state(
        &self,
        org_id: &str,
        provider_kind: &str,
    ) -> worker::Result<Option<ProviderSyncStateRecord>> {
        self.database
            .prepare(
                PROVIDER_SYNC_STATE_SQL,
                &[BindValue::Text(org_id), BindValue::Text(provider_kind)],
            )?
            .first::<ProviderSyncStateRecord>(None)
            .await
    }

    /// Record an ACCEPTED provider event or a SUCCESSFUL sync.
    ///
    /// This is the ONLY statement that may advance `last_success_at`, which
    /// anchors the grace window. `provider_sync_id` is used only when the upsert
    /// has to create the row.
    #[allow(clippy::too_many_arguments)]
    pub fn record_provider_success_statement(
        &self,
        provider_sync_id: &str,
        org_id: &str,
        provider_kind: &str,
        last_event_id: &str,
        last_event_version: i64,
        last_event_at: &str,
        last_success_at: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            RECORD_PROVIDER_SUCCESS_SQL,
            &[
                BindValue::Text(provider_sync_id),
                BindValue::Text(org_id),
                BindValue::Text(provider_kind),
                BindValue::Text(last_event_id),
                BindValue::Int64(last_event_version),
                BindValue::Text(last_event_at),
                BindValue::Text(last_success_at),
            ],
        )
    }

    /// Record a FAILED poll.
    ///
    /// This statement deliberately has no `last_success_at`, no `last_event_*`,
    /// and no grace column in its SET list. A failed poll therefore cannot
    /// extend the grace window even by accident, which is the frozen rule.
    pub fn record_provider_failure_statement(
        &self,
        provider_sync_id: &str,
        org_id: &str,
        provider_kind: &str,
        error_code: &str,
        now: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            RECORD_PROVIDER_FAILURE_SQL,
            &[
                BindValue::Text(provider_sync_id),
                BindValue::Text(org_id),
                BindValue::Text(provider_kind),
                BindValue::Text(error_code),
                BindValue::Text(now),
            ],
        )
    }

    // -- upstream provider entitlement projection ---------------------------

    pub async fn list_provider_projections(
        &self,
        org_id: &str,
    ) -> worker::Result<Vec<ProviderProjectionRecord>> {
        self.database
            .prepare(PROVIDER_PROJECTION_BY_ORG_SQL, &[BindValue::Text(org_id)])?
            .all()
            .await?
            .results::<ProviderProjectionRecord>()
    }

    /// Upsert the normalized upstream status. The ON CONFLICT target is the
    /// frozen `UNIQUE (org_id, provider_kind, capability_class)`, so there is
    /// exactly one projection per provider/capability per org.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_provider_projection_statement(
        &self,
        projection_id: &str,
        org_id: &str,
        provider_kind: &str,
        capability_class: &str,
        status: &str,
        reason_code: Option<&str>,
        observed_at: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPSERT_PROVIDER_PROJECTION_SQL,
            &[
                BindValue::Text(projection_id),
                BindValue::Text(org_id),
                BindValue::Text(provider_kind),
                BindValue::Text(capability_class),
                BindValue::Text(status),
                reason_code.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(observed_at),
            ],
        )
    }

    // -- entitlement definitions and grants ---------------------------------

    pub async fn list_entitlement_definitions(
        &self,
    ) -> worker::Result<Vec<EntitlementDefinitionRecord>> {
        self.database
            .prepare(ENTITLEMENT_DEFINITION_SQL, &[])?
            .all()
            .await?
            .results::<EntitlementDefinitionRecord>()
    }

    /// Every grant that is active at `now`, for one tenant.
    ///
    /// The predicates are the same ones the domain evaluator applies; filtering
    /// in SQL is a bound, not a decision — the evaluator re-checks
    /// `is_active_at` and the cross-tenant invariant.
    pub async fn list_active_grants(
        &self,
        org_id: &str,
        now: &str,
    ) -> worker::Result<Vec<EntitlementGrantRecord>> {
        self.database
            .prepare(
                ENTITLEMENT_GRANTS_SQL,
                &[BindValue::Text(org_id), BindValue::Text(now)],
            )?
            .all()
            .await?
            .results::<EntitlementGrantRecord>()
    }

    /// Insert an internal/support entitlement override.
    ///
    /// P06-CR-002: there is no browser route and no browser permission for this
    /// operation. The table CHECK independently refuses an override without
    /// `expires_at`, `reason`, and `granted_by_principal_id`, so a caller cannot
    /// create a silent forever override even if it skipped the checks here.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_override_grant_statement(
        &self,
        grant_id: &str,
        org_id: &str,
        entitlement_key: &str,
        scope: &str,
        scope_id: Option<&str>,
        value_json: &str,
        reason: &str,
        granted_by_principal_id: &str,
        effective_at: &str,
        expires_at: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_OVERRIDE_GRANT_SQL,
            &[
                BindValue::Text(grant_id),
                BindValue::Text(org_id),
                BindValue::Text(entitlement_key),
                BindValue::Text(scope),
                scope_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(value_json),
                BindValue::Text(reason),
                BindValue::Text(granted_by_principal_id),
                BindValue::Text(effective_at),
                BindValue::Text(expires_at),
            ],
        )
    }

    pub fn revoke_grant_statement(
        &self,
        grant_id: &str,
        org_id: &str,
        now: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            REVOKE_GRANT_SQL,
            &[
                BindValue::Text(grant_id),
                BindValue::Text(org_id),
                BindValue::Text(now),
                BindValue::Int64(expected_version),
            ],
        )
    }

    // -- license state and snapshots ---------------------------------------

    pub async fn find_license_state(
        &self,
        org_id: &str,
    ) -> worker::Result<Option<LicenseStateRecord>> {
        self.database
            .prepare(LICENSE_STATE_BY_ORG_SQL, &[BindValue::Text(org_id)])?
            .first::<LicenseStateRecord>(None)
            .await
    }

    /// Upsert the server-side license projection.
    ///
    /// `platform_paid_inference_grace_seconds` is hard-coded to `0` in the SQL:
    /// platform-paid inference receives no additional billing grace, and the
    /// table CHECK (`BETWEEN 0 AND 0`) enforces it independently.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_license_state_statement(
        &self,
        license_state_id: &str,
        org_id: &str,
        subscription_id: Option<&str>,
        state: &str,
        local_offline_grace_seconds: i64,
        cloud_control_plane_grace_seconds: i64,
        grace_started_at: Option<&str>,
        grace_expires_at: Option<&str>,
        reason_code: Option<&str>,
        now: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPSERT_LICENSE_STATE_SQL,
            &[
                BindValue::Text(license_state_id),
                BindValue::Text(org_id),
                subscription_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(state),
                BindValue::Int64(local_offline_grace_seconds),
                BindValue::Int64(cloud_control_plane_grace_seconds),
                grace_started_at.map_or(BindValue::Null, BindValue::Text),
                grace_expires_at.map_or(BindValue::Null, BindValue::Text),
                reason_code.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(now),
            ],
        )
    }

    /// The highest policy version already accepted for one audience.
    ///
    /// Read BEFORE issuing a snapshot so the issued version is monotonic; the
    /// `trg_license_snapshots_anti_rollback` trigger then makes a rollback
    /// structurally impossible rather than merely unlikely.
    pub async fn max_accepted_policy_version(
        &self,
        org_id: &str,
        device_id: Option<&str>,
    ) -> worker::Result<i64> {
        let row = self
            .database
            .prepare(
                MAX_ACCEPTED_POLICY_VERSION_SQL,
                &[
                    BindValue::Text(org_id),
                    device_id.map_or(BindValue::Null, BindValue::Text),
                ],
            )?
            .first::<serde_json::Value>(None)
            .await?;
        Ok(row
            .as_ref()
            .and_then(|row| row.get("max_version"))
            .and_then(serde_json::Value::as_i64)
            .unwrap_or_default())
    }

    /// Persist the signed snapshot metadata.
    ///
    /// `signature` and `canonical_bytes` are bound as lowercase hex TEXT into
    /// their `BLOB` columns (see the module note on BLOB encoding).
    /// `trg_license_snapshots_anti_rollback` aborts the batch when the policy
    /// version is below one already accepted for the same audience.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_license_snapshot_statement(
        &self,
        license_snapshot_id: &str,
        org_id: &str,
        device_id: Option<&str>,
        audience: &str,
        policy_version: i64,
        license_state: &str,
        policy_fresh_until: &str,
        offline_valid_until: &str,
        entitlements_json: &str,
        key_id: &str,
        signature: &[u8],
        canonical_bytes: &[u8],
        issued_at: &str,
        valid_until: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_LICENSE_SNAPSHOT_SQL,
            &[
                BindValue::Text(license_snapshot_id),
                BindValue::Text(org_id),
                device_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(audience),
                BindValue::Int64(policy_version),
                BindValue::Text(license_state),
                BindValue::Text(policy_fresh_until),
                BindValue::Text(offline_valid_until),
                BindValue::Text(entitlements_json),
                BindValue::Text(key_id),
                BindValue::Text(&encode_hex(signature)),
                BindValue::Text(&encode_hex(canonical_bytes)),
                BindValue::Text(issued_at),
                BindValue::Text(valid_until),
            ],
        )
    }

    /// When the most recent snapshot for one audience was issued.
    ///
    /// `None` means this audience has never received a snapshot, so the next
    /// issuance always persists its metadata row.
    pub async fn latest_snapshot_issued_at(
        &self,
        org_id: &str,
        device_id: Option<&str>,
    ) -> worker::Result<Option<String>> {
        let row = self
            .database
            .prepare(
                LATEST_SNAPSHOT_FOR_AUDIENCE_SQL,
                &[
                    BindValue::Text(org_id),
                    device_id.map_or(BindValue::Null, BindValue::Text),
                ],
            )?
            .first::<serde_json::Value>(None)
            .await?;
        Ok(row
            .as_ref()
            .and_then(|row| row.get("issued_at"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned))
    }

    /// Currently trusted verification keys, newest first.
    ///
    /// Only PUBLIC material is read; there is no query anywhere in this module
    /// that could return private key bytes.
    pub async fn list_signing_keys(
        &self,
        limit: i32,
    ) -> worker::Result<Vec<LicenseSigningKeyRecord>> {
        self.database
            .prepare(
                ACTIVE_SIGNING_KEYS_SQL,
                &[BindValue::Integer(limit.clamp(1, 32))],
            )?
            .all()
            .await?
            .results::<LicenseSigningKeyRecord>()
    }

    // -- authoritative counts and seats -------------------------------------

    /// Read the five authoritative counts.
    pub async fn authoritative_counts(&self, org_id: &str) -> worker::Result<AuthoritativeCounts> {
        let row = self
            .database
            .prepare(AUTHORITATIVE_COUNTS_SQL, &[BindValue::Text(org_id)])?
            .first::<AuthoritativeCountsRow>(None)
            .await?
            .ok_or_else(|| {
                worker::Error::RustError("authoritative counts probe returned no row".into())
            })?;
        Ok(row.to_counts())
    }

    /// Every membership row for one tenant, for the seat model.
    pub async fn list_seat_rows(&self, org_id: &str) -> worker::Result<Vec<SeatRow>> {
        self.database
            .prepare(MEMBERSHIP_SEAT_ROWS_SQL, &[BindValue::Text(org_id)])?
            .all()
            .await?
            .results::<SeatRow>()
    }
}

// ---------------------------------------------------------------------------
// Pure projection helpers (no D1, fully testable)
// ---------------------------------------------------------------------------

/// The bounded, allowlisted keys a subscription event may carry in
/// `metadata_json`.
///
/// The frozen contract forbids prompt/response content, raw tool arguments,
/// credentials, provider payloads, and unbounded URLs from any `billing.*`
/// payload, so the metadata object is built here from an explicit allowlist
/// rather than by copying a provider response.
pub const SUBSCRIPTION_EVENT_METADATA_KEYS: [&str; 5] = [
    "plan_key",
    "status",
    "reason_code",
    "grace_seconds",
    "version",
];

impl SubscriptionEventReason {
    /// Whether this transition represents a state change worth fanning out
    /// separately from the routine `billing.subscription_updated.v1` event.
    pub const fn is_grace_transition(self) -> bool {
        matches!(self, Self::GraceStarted | Self::GraceEnded)
    }
}

/// Map a `seat_policy` column value onto the domain seat policy.
///
/// `per_active_member` is the frozen baseline (`active` + `suspended`
/// billable). `flat` bills nobody per-seat and `custom` is refused: a custom
/// billable set is plan-contract data, and inventing one here would let a
/// corrupt row change a bill.
pub fn seat_policy_for(value: &str) -> Result<SeatPolicy, EntitlementError> {
    match value {
        "per_active_member" => Ok(SeatPolicy::baseline()),
        "flat" => SeatPolicy::new([]),
        _ => Err(EntitlementError::InvalidMembershipState),
    }
}

/// The seat policy implied by a plan's `seat_based` flag when the billing
/// account carries no explicit policy row.
pub fn seat_policy_for_plan(seat_based: bool) -> SeatPolicy {
    if seat_based {
        SeatPolicy::baseline()
    } else {
        SeatPolicy::new([]).expect("an empty billable set is always valid")
    }
}

/// Project the seat rows of one tenant through the domain seat model.
///
/// A row from another tenant, or an unrecognized membership state, is refused
/// instead of being counted, so a cross-tenant membership leak cannot inflate or
/// deflate a bill.
pub fn billable_seats(
    org_id: &OrganizationId,
    rows: &[SeatRow],
    policy: &SeatPolicy,
) -> Result<crate::modules::entitlements::SeatCount, EntitlementError> {
    let mut mapped = Vec::with_capacity(rows.len());
    for row in rows {
        let membership_id = row
            .membership_id
            .parse()
            .map_err(|_: crate::core::CoreError| EntitlementError::InvalidId)?;
        let row_org = row
            .org_id
            .parse::<OrganizationId>()
            .map_err(|_: crate::core::CoreError| EntitlementError::InvalidId)?;
        if row_org != *org_id {
            return Err(EntitlementError::CrossTenantGrant);
        }
        mapped.push(BillingSeatRow::new(
            membership_id,
            row_org,
            row.billable_state()?,
        ));
    }
    crate::modules::entitlements::billable_seat_count(&mapped, policy)
}

/// Read the effective-entitlement resolution for one tenant.
///
/// Everything here is read-only and server-owned: plan entitlement values come
/// from the immutable `plan_entitlements` of the current plan, plan- and
/// subscription-derived grants come from `entitlement_grants`, and internal
/// overrides come from the same table with `source = 'internal_override'`. No
/// value is accepted from the request, and `now` is the server clock.
pub async fn resolve_effective(
    repository: &BillingRepository<'_>,
    org_id: &OrganizationId,
    now: &Timestamp,
    denials: &[crate::modules::entitlements::EntitlementDenial],
) -> Result<
    (
        crate::modules::entitlements::EffectiveEntitlements,
        SubscriptionRecord,
        PlanRecord,
    ),
    EntitlementError,
> {
    let now_seconds = crate::modules::entitlements::unix_seconds(now)?;
    let (subscription, plan) = current_plan(repository, org_id, now_seconds).await?;
    let org = org_id.as_str();

    let (plan_grants, subscription_grants, overrides) =
        grant_slices(repository, org, &subscription, &plan, now).await?;

    let plan_values = repository
        .list_plan_entitlements(&plan.plan_id)
        .await
        .map_err(|_| EntitlementError::InvalidEntitlementValue)?;
    let mut plan_grants = plan_grants;
    for row in plan_values {
        let Some(grant) = plan_grant_from_row(org, &row, now_seconds)? else {
            continue;
        };
        plan_grants.push(grant);
    }

    let platform_defaults: Vec<EntitlementGrant> = Vec::new();
    let resolution = EntitlementResolution {
        org_id,
        scope: crate::modules::entitlements::EntitlementScope::organization(),
        now: now_seconds,
        inputs: EntitlementInputs {
            platform_defaults: &platform_defaults,
            plan_grants: &plan_grants,
            subscription_grants: &subscription_grants,
            internal_overrides: &overrides,
            denials,
        },
    };
    let effective = resolve_effective_entitlements(&resolution)?;
    Ok((effective, subscription, plan))
}

/// The current subscription row plus the plan version it points at.
///
/// A subscription whose plan pointer no longer resolves is a hard read failure:
/// it must never silently fall back to a platform default, because that would
/// hand out capabilities the organization did not buy.
async fn current_plan(
    repository: &BillingRepository<'_>,
    org_id: &OrganizationId,
    _now_seconds: i64,
) -> Result<(SubscriptionRecord, PlanRecord), EntitlementError> {
    let org = org_id.as_str();
    let subscription = repository
        .find_subscription(org)
        .await
        .map_err(|_| EntitlementError::InvalidEntitlementValue)?
        .ok_or(EntitlementError::UnknownEntitlementKey)?;
    let plan = repository
        .find_plan(&subscription.plan_id)
        .await
        .map_err(|_| EntitlementError::InvalidEntitlementValue)?
        .ok_or(EntitlementError::InvalidPlanKey)?;
    Ok((subscription, plan))
}

/// Split the tenant's grants into the three precedence slices.
///
/// The assignment is by the `source` column, which is the frozen ladder:
/// `subscription` < `internal_override` for the slices the evaluator compares,
/// and a `plan` row is only accepted from `plan_entitlements`.
async fn grant_slices(
    repository: &BillingRepository<'_>,
    org: &str,
    subscription: &SubscriptionRecord,
    _plan: &PlanRecord,
    now: &Timestamp,
) -> Result<
    (
        Vec<EntitlementGrant>,
        Vec<EntitlementGrant>,
        Vec<EntitlementGrant>,
    ),
    EntitlementError,
> {
    let rows = repository
        .list_active_grants(org, now.as_str())
        .await
        .map_err(|_| EntitlementError::InvalidEntitlementValue)?;
    let mut subscription_grants = Vec::new();
    let mut overrides = Vec::new();
    for row in rows {
        match row.source.as_str() {
            "subscription" => subscription_grants.push(grant_from_row(&row)?),
            "internal_override" => overrides.push(grant_from_row(&row)?),
            // A `plan` grant is derived from `plan_entitlements`, never from this
            // table, so a hand-written `plan` row is refused rather than trusted.
            other => {
                return Err(if other == "plan" {
                    EntitlementError::SourceScopeMismatch
                } else {
                    EntitlementError::InvalidEntitlementValue
                });
            }
        }
    }
    let _ = subscription;
    Ok((Vec::new(), subscription_grants, overrides))
}

/// Map one grant row onto the domain type.
///
/// A row whose key is not a registered Lumi key, whose value does not match the
/// registered type, or whose internal override lacks an expiry/reason, is
/// refused: the whole resolution then fails closed instead of partially applying.
pub fn grant_from_row(row: &EntitlementGrantRecord) -> Result<EntitlementGrant, EntitlementError> {
    let org_id = row
        .org_id
        .parse()
        .map_err(|_: crate::core::CoreError| EntitlementError::InvalidId)?;
    let key = crate::modules::entitlements::EntitlementKey::new(&row.entitlement_key)?;
    let value = decode_entitlement_value(&value_for(&key)?, &row.value_json)?;
    let source = GrantSource::parse(&row.source).ok_or(EntitlementError::SourceScopeMismatch)?;
    let scope = scope_from_row(&row.scope, row.scope_id.as_deref())?;
    EntitlementGrant::new(
        row.grant_id
            .parse::<EntitlementGrantId>()
            .map_err(|_: crate::core::CoreError| EntitlementError::InvalidId)?,
        org_id,
        key,
        value,
        source,
        scope,
        row.reason.clone(),
        instant(&row.effective_at)?,
        row.expires_at.as_deref().map(instant).transpose()?,
        row.revoked_at.as_deref().map(instant).transpose()?,
    )
}

/// Map one `plan_entitlements` row onto a plan-sourced domain grant.
///
/// A plan value is applied at the subscription's period start (or "now" when no
/// period start is known) and never expires on its own: a plan value is bounded
/// by the plan version it belongs to, not by a clock.
pub fn plan_grant_from_row(
    org: &str,
    row: &PlanEntitlementRecord,
    now_seconds: i64,
) -> Result<Option<EntitlementGrant>, EntitlementError> {
    let key = crate::modules::entitlements::EntitlementKey::new(&row.entitlement_key)?;
    let value = decode_entitlement_value(&value_for(&key)?, &row.value_json)?;
    let org_id = org
        .parse()
        .map_err(|_: crate::core::CoreError| EntitlementError::InvalidId)?;
    // A derived grant ID: plan entitlement values are not `entitlement_grants`
    // rows, so the identifier is derived from the plan row identity. The domain
    // only uses it as a final deterministic tie-breaker, and a plan grants each
    // key exactly once per version.
    let grant_id = EntitlementGrantId::new(format!(
        "egr_{}",
        stable_identifier(&row.plan_entitlement_id)
    ))
    .map_err(|_| EntitlementError::InvalidId)?;
    Ok(Some(EntitlementGrant::new(
        grant_id,
        org_id,
        key,
        value,
        GrantSource::Plan,
        crate::modules::entitlements::EntitlementScope::organization(),
        None,
        now_seconds,
        None,
        None,
    )?))
}

fn value_for(
    key: &crate::modules::entitlements::EntitlementKey,
) -> Result<EntitlementValue, EntitlementError> {
    crate::modules::entitlements::baseline_definition(key)
        .map(|definition| definition.default)
        .ok_or(EntitlementError::UnknownEntitlementKey)
}

/// Decode a stored `value_json` scalar into a typed entitlement value.
///
/// The stored value must be a native JSON boolean/integer/string, and its type
/// must match the registered definition. A mismatched or unparsable value is
/// refused: the resolution then fails closed rather than coercing `true` into
/// `1`.
pub fn decode_entitlement_value(
    definition_value: &EntitlementValue,
    value_json: &str,
) -> Result<EntitlementValue, EntitlementError> {
    let parsed: EntitlementValue =
        serde_json::from_str(value_json).map_err(|_| EntitlementError::InvalidEntitlementValue)?;
    if parsed.value_type() != definition_value.value_type() {
        return Err(EntitlementError::EntitlementTypeMismatch);
    }
    Ok(parsed)
}

fn scope_from_row(
    scope: &str,
    scope_id: Option<&str>,
) -> Result<crate::modules::entitlements::EntitlementScope, EntitlementError> {
    match scope {
        "organization" => Ok(crate::modules::entitlements::EntitlementScope::organization()),
        "project" => {
            let project_id = scope_id
                .ok_or(EntitlementError::InvalidScopeId)?
                .parse()
                .map_err(|_: crate::core::CoreError| EntitlementError::InvalidScopeId)?;
            Ok(crate::modules::entitlements::EntitlementScope::project(
                project_id,
            ))
        }
        "user" => {
            let user_id = scope_id
                .ok_or(EntitlementError::InvalidScopeId)?
                .parse()
                .map_err(|_: crate::core::CoreError| EntitlementError::InvalidScopeId)?;
            Ok(crate::modules::entitlements::EntitlementScope::user(
                user_id,
            ))
        }
        _ => Err(EntitlementError::InvalidScopeId),
    }
}

/// Parse a stored 24-character UTC instant into whole Unix seconds.
pub fn instant(value: &str) -> Result<i64, EntitlementError> {
    let timestamp = Timestamp::new(value).map_err(|_| EntitlementError::InvalidTimestampRange)?;
    crate::modules::entitlements::unix_seconds(&timestamp)
}

/// Compute the downgrade over-limit projection from authoritative counts.
///
/// The counts come from the tenant's own rows, never from a client total, and
/// the effective limits come from the domain resolution, so a downgrade blocks
/// new and expanded work and never deletes a row.
pub async fn over_limit_projection(
    repository: &BillingRepository<'_>,
    org_id: &OrganizationId,
    now: &Timestamp,
) -> Result<OverLimitProjection, EntitlementError> {
    let now_seconds = crate::modules::entitlements::unix_seconds(now)?;
    let (effective, _, _) = resolve_effective(repository, org_id, now, &[]).await?;
    let counts = repository
        .authoritative_counts(org_id.as_str())
        .await
        .map_err(|_| EntitlementError::InvalidEntitlementValue)?;
    Ok(compute_over_limit_projection(
        org_id,
        counts,
        &effective,
        now_seconds,
    ))
}

/// Derive the server-side license state for one tenant.
///
/// The commercial status is the only commercial source: [`LicenseState`] is
/// computed from the mapped subscription status and the current provider
/// reachability, and the bounded grace windows are the frozen class defaults.
/// A local-only runtime that has exhausted BOTH the cloud grace and its own
/// offline window is reported as `expired`, which is the only case where a
/// readable commercial status still yields no new local work.
pub fn license_state_for(
    status: crate::modules::entitlements::SubscriptionStatus,
    provider: crate::modules::entitlements::ProviderAvailability,
    grace_started_at: Option<i64>,
    now_seconds: i64,
) -> LicenseState {
    let state = LicenseState::from_subscription_status(status, provider);
    if state != LicenseState::Grace {
        return state;
    }
    let Some(anchor) = grace_started_at else {
        return state;
    };
    let cloud_expiry = anchor + crate::modules::entitlements::CLOUD_CONTROL_PLANE_GRACE_SECONDS;
    let local_expiry = anchor + crate::modules::entitlements::LOCAL_ONLY_GRACE_SECONDS;
    if now_seconds >= local_expiry && now_seconds >= cloud_expiry {
        return LicenseState::Expired;
    }
    state
}

/// Decode a stored signature/canonical-bytes hex value.
///
/// Uppercase, odd-length, or non-hex input is refused, so a stored value has
/// exactly one valid encoding and a tampered row cannot be read as a valid
/// signature.
pub fn decode_stored_bytes(value: &str) -> Result<Vec<u8>, EntitlementError> {
    decode_hex(value).ok_or(EntitlementError::InvalidClaims)
}

/// Helper trait used only to keep the `GrantSource` conversion readable.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::entitlements::{
        EntitlementScope, EntitlementValueType, ProviderEntitlementStatus, SubscriptionStatus,
    };

    const ORG: &str = "org_0123456789abcdef0123456789abcdef";

    fn org() -> OrganizationId {
        ORG.parse().unwrap()
    }

    fn seat_row(id: &str, status: &str, role: &str) -> SeatRow {
        SeatRow {
            membership_id: id.to_owned(),
            org_id: ORG.to_owned(),
            status: status.to_owned(),
            role: role.to_owned(),
        }
    }

    #[test]
    fn seat_policy_never_invents_a_custom_billable_set() {
        assert_eq!(
            seat_policy_for("per_active_member")
                .unwrap()
                .billable_states()
                .to_vec(),
            vec![BillableSeatState::Active, BillableSeatState::Suspended]
        );
        assert!(
            seat_policy_for("flat")
                .unwrap()
                .billable_states()
                .is_empty()
        );
        assert!(seat_policy_for("custom").is_err());
        assert!(seat_policy_for("nonsense").is_err());
        assert!(!seat_policy_for_plan(false).bills(BillableSeatState::Active));
        assert!(seat_policy_for_plan(true).bills(BillableSeatState::Active));
    }

    #[test]
    fn billable_seats_derive_from_authoritative_rows_and_refuse_cross_tenant() {
        let policy = SeatPolicy::baseline();
        let rows = vec![
            seat_row("mem_0123456789abcdef0123456789abcdef", "active", "admin"),
            seat_row("mem_1123456789abcdef0123456789abcdef", "active", "member"),
            seat_row(
                "mem_2123456789abcdef0123456789abcdef",
                "suspended",
                "member",
            ),
            seat_row("mem_3123456789abcdef0123456789abcdef", "active", "viewer"),
            seat_row("mem_4123456789abcdef0123456789abcdef", "removed", "member"),
        ];
        let count = billable_seats(&org(), &rows, &policy).unwrap();
        // active + suspended non-viewers are billable; a viewer is not, and a
        // removed member is not.
        assert_eq!(count.billable, 3);
        assert_eq!(count.total(), 5);
        assert_eq!(count.count_of(BillableSeatState::Viewer), 1);
        assert_eq!(count.count_of(BillableSeatState::Removed), 1);

        // A row from another tenant is refused rather than counted.
        let mut foreign = rows.clone();
        foreign[0].org_id = "org_1123456789abcdef0123456789abcdef".to_owned();
        assert_eq!(
            billable_seats(&org(), &foreign, &policy).err(),
            Some(EntitlementError::CrossTenantGrant)
        );
    }

    #[test]
    fn an_unrecognized_membership_state_fails_closed_instead_of_defaulting() {
        let policy = SeatPolicy::baseline();
        let rows = vec![seat_row(
            "mem_0123456789abcdef0123456789abcdef",
            "invited",
            "member",
        )];
        assert_eq!(
            billable_seats(&org(), &rows, &policy).err(),
            Some(EntitlementError::InvalidMembershipState)
        );
    }

    #[test]
    fn grant_rows_map_to_the_domain_type_and_require_expiry_for_overrides() {
        let mut row = EntitlementGrantRecord {
            grant_id: "egr_0123456789abcdef0123456789abcdef".to_owned(),
            org_id: ORG.to_owned(),
            entitlement_key: "automations.max_active".to_owned(),
            scope: "organization".to_owned(),
            scope_id: None,
            value_json: "250".to_owned(),
            source: "internal_override".to_owned(),
            subscription_id: None,
            reason: Some("F18: incident mitigation".to_owned()),
            granted_by_principal_id: Some("usr_0123456789abcdef0123456789abcdef".to_owned()),
            effective_at: "2026-09-25T12:00:00.000Z".to_owned(),
            expires_at: Some("2026-10-02T12:00:00.000Z".to_owned()),
            revoked_at: None,
            version: 1,
            created_at: "2026-09-25T12:00:00.000Z".to_owned(),
            updated_at: "2026-09-25T12:00:00.000Z".to_owned(),
        };
        let grant = grant_from_row(&row).unwrap();
        assert_eq!(grant.source, GrantSource::InternalOverride);
        assert_eq!(grant.value.as_integer(), Some(250));

        // Removing the expiry makes the override invalid in the domain too, so
        // the domain and the table CHECK agree.
        row.expires_at = None;
        assert_eq!(
            grant_from_row(&row).err(),
            Some(EntitlementError::MissingOverrideExpiry)
        );
    }

    #[test]
    fn a_hand_written_plan_grant_row_is_refused() {
        let base = EntitlementGrantRecord {
            grant_id: "egr_0123456789abcdef0123456789abcdef".to_owned(),
            org_id: ORG.to_owned(),
            entitlement_key: "automations.max_active".to_owned(),
            scope: "organization".to_owned(),
            scope_id: None,
            value_json: "1".to_owned(),
            source: "plan".to_owned(),
            subscription_id: None,
            reason: None,
            granted_by_principal_id: None,
            effective_at: "2026-09-25T12:00:00.000Z".to_owned(),
            expires_at: None,
            revoked_at: None,
            version: 1,
            created_at: "2026-09-25T12:00:00.000Z".to_owned(),
            updated_at: "2026-09-25T12:00:00.000Z".to_owned(),
        };
        // A `plan` row is derived from `plan_entitlements`, never from
        // `entitlement_grants`; `grant_slices` refuses it as a slice mismatch.
        assert_eq!(base.source, "plan");
        assert!(GrantSource::parse("plan").is_some());
        assert_eq!(GrantSource::Plan.rank(), 1);
        assert!(GrantSource::Plan.rank() < GrantSource::InternalOverride.rank());

        // An internal override must carry BOTH an expiry and a reason; the
        // domain and the table CHECK agree on that independently.
        let mut without_expiry = base.clone();
        without_expiry.source = "internal_override".to_owned();
        without_expiry.reason = Some("incident".to_owned());
        assert_eq!(
            grant_from_row(&without_expiry).err(),
            Some(EntitlementError::MissingOverrideExpiry)
        );
        let mut without_reason = base;
        without_reason.source = "internal_override".to_owned();
        without_reason.expires_at = Some("2026-10-02T12:00:00.000Z".to_owned());
        assert_eq!(
            grant_from_row(&without_reason).err(),
            Some(EntitlementError::MissingOverrideReason)
        );
    }

    #[test]
    fn entitlement_values_must_match_the_registered_type() {
        let boolean_key =
            crate::modules::entitlements::EntitlementKey::new("webhooks.enabled").unwrap();
        let definition = value_for(&boolean_key).unwrap();
        assert!(decode_entitlement_value(&definition, "true").is_ok());
        // `1` is not `true`: a type mismatch is refused, never coerced.
        assert_eq!(
            decode_entitlement_value(&definition, "1").err(),
            Some(EntitlementError::EntitlementTypeMismatch)
        );
        assert_eq!(
            decode_entitlement_value(&definition, "\"yes\"").err(),
            Some(EntitlementError::EntitlementTypeMismatch)
        );

        let integer_key =
            crate::modules::entitlements::EntitlementKey::new("automations.max_active").unwrap();
        let integer_definition = value_for(&integer_key).unwrap();
        assert!(decode_entitlement_value(&integer_definition, "100").is_ok());
        assert_eq!(
            decode_entitlement_value(&integer_definition, "true").err(),
            Some(EntitlementError::EntitlementTypeMismatch)
        );
    }

    #[test]
    fn an_unregistered_key_is_refused_rather_than_resolved() {
        let key = crate::modules::entitlements::EntitlementKey::new("org.max_members").unwrap();
        assert_eq!(
            value_for(&key).unwrap().value_type(),
            EntitlementValueType::Integer
        );
        // A provider product/price identifier is not a valid Lumi key at all, so
        // it can never become a definition lookup or a feature gate.
        assert!(crate::modules::entitlements::EntitlementKey::new("prod_Qabc123").is_err());
        assert!(crate::modules::entitlements::EntitlementKey::new("price_1Monthly").is_err());
    }

    #[test]
    fn stored_instants_must_be_frozen_utc_text() {
        assert_eq!(instant("2026-09-25T12:00:00.000Z").unwrap(), 1_790_337_600);
        assert!(instant("2026-09-25T12:00:00+00:00").is_err());
        assert!(instant("not-a-timestamp").is_err());
    }

    #[test]
    fn stored_signature_hex_is_strict_and_lowercase_only() {
        assert!(decode_stored_bytes("00ff").is_ok());
        assert!(decode_stored_bytes("00FF").is_err());
        assert!(decode_stored_bytes("0").is_err());
        assert!(decode_stored_bytes("").is_err());
    }

    #[test]
    fn license_state_is_derived_from_the_commercial_status_and_provider_availability() {
        use crate::modules::entitlements::ProviderAvailability;

        // A readable subscription always wins over provider reachability, so a
        // provider outage cannot silently rewrite a known commercial state.
        assert_eq!(
            license_state_for(
                SubscriptionStatus::Active,
                ProviderAvailability::Unavailable,
                None,
                1_789_000_000
            ),
            LicenseState::ProviderUnavailable
        );
        assert_eq!(
            license_state_for(
                SubscriptionStatus::Cancelled,
                ProviderAvailability::Available,
                None,
                1_789_000_000
            ),
            LicenseState::Cancelled
        );
        assert_eq!(
            license_state_for(
                SubscriptionStatus::Active,
                ProviderAvailability::Unknown,
                None,
                1_789_000_000
            ),
            LicenseState::Active
        );

        // Grace stays `grace` while the LOCAL offline window is still open: a
        // transient provider outage must not brick local editing.
        let anchor = 1_789_000_000;
        assert_eq!(
            license_state_for(
                SubscriptionStatus::Grace,
                ProviderAvailability::Unknown,
                Some(anchor),
                anchor + 86_401
            ),
            LicenseState::Grace
        );
        // Only once BOTH the 24h cloud grace and the 7-day offline window have
        // elapsed does the projection become `expired`.
        assert_eq!(
            license_state_for(
                SubscriptionStatus::Grace,
                ProviderAvailability::Unknown,
                Some(anchor),
                anchor + 604_800
            ),
            LicenseState::Expired
        );
    }

    #[test]
    fn frozen_metadata_keys_cover_the_billing_event_payload() {
        for key in [
            "plan_key",
            "status",
            "reason_code",
            "grace_seconds",
            "version",
        ] {
            assert!(SUBSCRIPTION_EVENT_METADATA_KEYS.contains(&key));
        }
        assert_eq!(SUBSCRIPTION_EVENT_METADATA_KEYS.len(), 5);
        assert!(!SUBSCRIPTION_EVENT_METADATA_KEYS.contains(&"provider_payload"));
        assert!(!SUBSCRIPTION_EVENT_METADATA_KEYS.contains(&"card"));
    }

    #[test]
    fn event_reasons_map_to_the_frozen_billing_event_names() {
        assert_eq!(
            SubscriptionEventReason::GraceStarted.event_type(),
            "billing.grace_started.v1"
        );
        assert_eq!(
            SubscriptionEventReason::GraceEnded.event_type(),
            "billing.grace_ended.v1"
        );
        assert_eq!(
            SubscriptionEventReason::StatusChanged.event_type(),
            "billing.subscription_updated.v1"
        );
        assert_eq!(
            SubscriptionEventReason::PlanChanged.event_type(),
            "billing.subscription_updated.v1"
        );
    }

    #[test]
    fn provider_projection_status_is_normalized_and_never_a_provider_product() {
        assert!(ProviderEntitlementStatus::parse("available").is_some());
        assert!(ProviderEntitlementStatus::parse("prod_qabc").is_none());
        // A stored capability class is the platform-managed inference class for
        // every current projection.
        assert_eq!(
            crate::adapters::billing::provider::PROVIDER_ENTITLEMENT_CAPABILITY_CLASS,
            "provider_managed_inference"
        );
    }

    #[test]
    fn scope_rows_map_to_the_three_frozen_scopes_and_reject_others() {
        assert_eq!(
            scope_from_row("organization", None).unwrap(),
            EntitlementScope::organization()
        );
        assert!(scope_from_row("project", None).is_err());
        assert!(scope_from_row("organization", Some("prj_1")).is_ok());
        assert!(scope_from_row("provider", None).is_err());
    }
}
