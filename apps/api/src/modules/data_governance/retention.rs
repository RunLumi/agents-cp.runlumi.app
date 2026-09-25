//! Concrete retention windows, legal holds, and the pure expiry decision.
//!
//! Why a pure decision function: the gate freezes *numbers* (90 days, 30 days,
//! 24 hours, 2555 days) but the Worker must never compute them from a request
//! body, a client-supplied retention value, or a wall-clock read inside a
//! handler. `decide` therefore takes an explicit [`DataClassRecord`], an
//! explicit [`RetentionPolicy`], an explicit logical time in Unix seconds, the
//! anchor instant the record's window is measured from, and an optional
//! [`LegalHold`]. It returns an absolute expiry decision, never a side effect.
//!
//! The two rules this module exists to enforce:
//!
//! 1. A policy may SHORTEN a baseline retention window, and may extend it only
//!    up to the per-class legal maximum. Going past the legal maximum requires
//!    an audited override that names both a principal and an audit correlation;
//!    without one the decision fails closed instead of silently keeping data.
//! 2. A legal hold suspends expiry for the classes it covers until an audited
//!    support/legal release. A released hold has no retroactive effect, so the
//!    decision is always recomputed from current state rather than from a
//!    remembered expiry.
//!
//! Audit, security, billing, and certificate records are `Minimize`,
//! `Tombstone`, or `RetainLegalOnly` in [`crate::modules::data_governance::registry`].
//! This module never turns "legally retained" into "expires at zero": a legal
//! record outlives its subject by design, and the record says so explicitly.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::registry::DataClass;

/// Hard ceiling for any single retention window. Ten years covers the longest
/// statutory retention the contract names (seven years for financial records)
/// with headroom, and it is the same ceiling the persistence layer enforces, so
/// a value that passes here cannot be rejected only at the database boundary.
pub const MAX_RETENTION_SECONDS: u64 = 315_360_000;

/// Longest legal retention window for financial/accounting records (audit,
/// security, usage, cost, subscription, deletion certificates). Extending past
/// this point is not a tenant policy decision at all.
pub const FINANCIAL_RECORD_CEILING: RetentionDuration =
    RetentionDuration::from_days_unchecked(3_650);

/// Longest window a tenant may set on bounded job/delivery projections
/// (occurrences, leases, queue jobs, export job metadata, provider sync state)
/// before an audited override is required. One year of operational debugging
/// history is the documented ceiling; the gate baseline is much shorter.
pub const OPERATIONAL_PROJECTION_CEILING: RetentionDuration =
    RetentionDuration::from_days_unchecked(365);

/// Ceiling for short-lived sensitive projections: notifications, notification
/// and webhook deliveries, notification preferences, provider entitlement
/// projections.
pub const SENSITIVE_PROJECTION_CEILING: RetentionDuration =
    RetentionDuration::from_days_unchecked(90);

/// Ceiling for an export artifact object. Matches the largest
/// `default_export_expiry_seconds` the persistence layer accepts (seven days);
/// ADR 0006 requires a short-lived object and forbids a permanent URL, so a
/// tenant cannot turn a 24-hour default into an archive.
pub const EXPORT_ARTIFACT_CEILING: RetentionDuration =
    RetentionDuration::from_seconds_unchecked(604_800);

/// Ceiling for a re-authorized download/access grant. Grants are re-checked on
/// every use, so even a day-long grant is already a long-lived capability.
pub const ACCESS_GRANT_CEILING: RetentionDuration =
    RetentionDuration::from_seconds_unchecked(86_400);

/// Ceiling for the P01 idempotency retry/claim window. Replay protection may
/// not become a long-term request archive.
pub const IDEMPOTENCY_CEILING: RetentionDuration = RetentionDuration::from_days_unchecked(7);

/// Longest text a legal-hold reason or audit justification may carry.
pub const MAX_HOLD_REASON_LEN: usize = 2_000;

/// Most classes one scoped legal hold may name. A hold is a deliberate,
/// reviewed act; an unbounded list is a bulk-release waiting to happen.
pub const MAX_HOLD_SCOPE_CLASSES: usize = 64;

/// A bounded retention window in seconds.
///
/// `from_days_unchecked`/`from_seconds_unchecked` exist for `const` baselines
/// that the compiler already proves in-range. Anything that arrives from a
/// request, D1 row, or policy document must go through [`RetentionDuration::new`].
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct RetentionDuration {
    seconds: u64,
}

impl RetentionDuration {
    /// `const` constructor for contract-frozen baselines. Values in this
    /// module are literals below `MAX_RETENTION_SECONDS`.
    pub const fn from_seconds_unchecked(seconds: u64) -> Self {
        Self { seconds }
    }

    /// `const` constructor for contract-frozen baselines in days.
    pub const fn from_days_unchecked(days: u64) -> Self {
        Self {
            seconds: days * Self::SECONDS_PER_DAY,
        }
    }

    pub const SECONDS_PER_MINUTE: u64 = 60;
    pub const SECONDS_PER_HOUR: u64 = 3_600;
    pub const SECONDS_PER_DAY: u64 = 86_400;
    pub const SECONDS_PER_YEAR: u64 = 365 * Self::SECONDS_PER_DAY;

    /// Validating constructor for any untrusted duration.
    pub fn new(seconds: u64) -> Result<Self, RetentionError> {
        if seconds > MAX_RETENTION_SECONDS {
            return Err(RetentionError::DurationOutOfRange);
        }
        Ok(Self { seconds })
    }

    pub const fn seconds(&self) -> u64 {
        self.seconds
    }

    pub const fn is_zero(&self) -> bool {
        self.seconds == 0
    }
}

impl fmt::Display for RetentionDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}s", self.seconds)
    }
}

/// The instant a retention window is measured from.
///
/// Anchors exist because the gate phrases most windows relative to a
/// lifecycle event: "90 days after terminal", "30 days after last observation",
/// "`offline_valid_until` + 30 days". Making the anchor explicit keeps a
/// missing terminal timestamp from silently becoming "now".
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionAnchor {
    /// Terminal state of the record's own lifecycle: occurrence, lease, run
    /// link, occurrence attempt, queue job, or dead-letter row.
    TerminalState,
    /// `offline_valid_until` on a signed license snapshot.
    LicenseOfflineValidUntil,
    /// Expiry of the entitlement grant that authorized the work.
    EntitlementGrantExpiry,
    /// Last successful observation of an upstream provider account.
    LastObservation,
    /// Creation of the export artifact object.
    ArtifactCreatedAt,
    /// Issuance of a short-lived download/access grant.
    AccessGrantIssued,
    /// Completion of the owning deletion job.
    DeletionJobCompleted,
    /// Issue time of a deletion certificate.
    CertificateIssued,
    /// Completion of a webhook or notification delivery attempt.
    DeliveryCompleted,
    /// Acceptance of the recorded request (idempotency retry window).
    RequestAccepted,
}

impl RetentionAnchor {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TerminalState => "terminal_state",
            Self::LicenseOfflineValidUntil => "license_offline_valid_until",
            Self::EntitlementGrantExpiry => "entitlement_grant_expiry",
            Self::LastObservation => "last_observation",
            Self::ArtifactCreatedAt => "artifact_created_at",
            Self::AccessGrantIssued => "access_grant_issued",
            Self::DeletionJobCompleted => "deletion_job_completed",
            Self::CertificateIssued => "certificate_issued",
            Self::DeliveryCompleted => "delivery_completed",
            Self::RequestAccepted => "request_accepted",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "terminal_state" => Some(Self::TerminalState),
            "license_offline_valid_until" => Some(Self::LicenseOfflineValidUntil),
            "entitlement_grant_expiry" => Some(Self::EntitlementGrantExpiry),
            "last_observation" => Some(Self::LastObservation),
            "artifact_created_at" => Some(Self::ArtifactCreatedAt),
            "access_grant_issued" => Some(Self::AccessGrantIssued),
            "deletion_job_completed" => Some(Self::DeletionJobCompleted),
            "certificate_issued" => Some(Self::CertificateIssued),
            "delivery_completed" => Some(Self::DeliveryCompleted),
            "request_accepted" => Some(Self::RequestAccepted),
            _ => None,
        }
    }
}

/// A declared retention window for one data class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum RetentionWindow {
    /// No expiry: the record lives until its own lifecycle deletion. This is
    /// the gate's "until deletion" / "endpoint lifetime" / "immutable plan
    /// history", and it is deliberately not the same as a very long window.
    Lifecycle,
    /// A concrete bounded window measured from the record's creation/acceptance.
    Bounded(RetentionDuration),
    /// A grace window measured from a lifecycle anchor.
    AfterAnchor {
        anchor: RetentionAnchor,
        grace: RetentionDuration,
    },
}

impl RetentionWindow {
    pub const fn is_lifecycle(&self) -> bool {
        matches!(self, Self::Lifecycle)
    }

    /// Bounded length of the window, or `None` for a lifecycle window.
    pub const fn bound_seconds(&self) -> Option<u64> {
        match self {
            Self::Lifecycle => None,
            Self::Bounded(duration) => Some(duration.seconds()),
            Self::AfterAnchor { grace, .. } => Some(grace.seconds()),
        }
    }

    /// Total ordering used for the "may shorten, never extend past the legal
    /// maximum" rule. A lifecycle window outlives every bounded window.
    pub fn exceeds(&self, other: &Self) -> bool {
        match (self.bound_seconds(), other.bound_seconds()) {
            (None, None) => false,
            (None, Some(_)) => true,
            (Some(_), None) => false,
            (Some(left), Some(right)) => left > right,
        }
    }

    /// Resolve the absolute expiry instant. `None` means "no expiry".
    pub fn expire_at(&self, anchor: Option<u64>) -> Result<Option<u64>, RetentionError> {
        match self {
            Self::Lifecycle => Ok(None),
            Self::Bounded(duration) => {
                Ok(anchor.map(|start| start.saturating_add(duration.seconds())))
            }
            Self::AfterAnchor {
                anchor: kind,
                grace,
            } => {
                let start = anchor.ok_or(RetentionError::MissingAnchor(*kind))?;
                Ok(Some(start.saturating_add(grace.seconds())))
            }
        }
    }
}

/// Which concrete baseline the gate freezes. Every value here appears verbatim
/// in `P06-CG.md`; there is no "product default" that is not one of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineRetention {
    /// Occurrence/lease/automation-run links: 90 days after terminal.
    AutomationProjection,
    /// Webhook delivery attempts and notification deliveries: 30 days.
    DeliveryProjection,
    /// Queue job/dead-letter rows: 90 days after terminal.
    QueueJobProjection,
    /// Export job metadata: 90 days.
    ExportJobMetadata,
    /// Export artifacts: 24 hours by default.
    ExportArtifact,
    /// License/entitlement metadata: `offline_valid_until` + 30 days.
    LicenseEntitlementMetadata,
    /// Deletion step rows: 90 days.
    DeletionStep,
    /// Deletion certificates: 365 days.
    DeletionCertificate,
    /// Operational logs/traces: 30 days.
    OperationalLog,
    /// Platform backups: 35-day lifecycle.
    BackupLifecycle,
    /// Audit/security events: 365 days.
    AuditSecurityEvent,
    /// Usage/cost/subscription: seven years (2555 days).
    FinancialRecord,
    /// P01 idempotency claim/retry window: 24 hours.
    IdempotencyRecord,
    /// Short-lived download/access grant: 15 minutes.
    AccessGrant,
}

impl BaselineRetention {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutomationProjection => "automation_projection",
            Self::DeliveryProjection => "delivery_projection",
            Self::QueueJobProjection => "queue_job_projection",
            Self::ExportJobMetadata => "export_job_metadata",
            Self::ExportArtifact => "export_artifact",
            Self::LicenseEntitlementMetadata => "license_entitlement_metadata",
            Self::DeletionStep => "deletion_step",
            Self::DeletionCertificate => "deletion_certificate",
            Self::OperationalLog => "operational_log",
            Self::BackupLifecycle => "backup_lifecycle",
            Self::AuditSecurityEvent => "audit_security_event",
            Self::FinancialRecord => "financial_record",
            Self::IdempotencyRecord => "idempotency_record",
            Self::AccessGrant => "access_grant",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [
            Self::AutomationProjection,
            Self::DeliveryProjection,
            Self::QueueJobProjection,
            Self::ExportJobMetadata,
            Self::ExportArtifact,
            Self::LicenseEntitlementMetadata,
            Self::DeletionStep,
            Self::DeletionCertificate,
            Self::OperationalLog,
            Self::BackupLifecycle,
            Self::AuditSecurityEvent,
            Self::FinancialRecord,
            Self::IdempotencyRecord,
            Self::AccessGrant,
        ]
        .into_iter()
        .find(|candidate| candidate.as_str() == value)
    }
}

/// Frozen baseline windows. These are the numbers the gate freezes; every
/// registry row's default is one of them or an explicit lifecycle window.
pub const BASELINE_AUTOMATION_PROJECTION: RetentionDuration =
    RetentionDuration::from_days_unchecked(90);
pub const BASELINE_DELIVERY_PROJECTION: RetentionDuration =
    RetentionDuration::from_days_unchecked(30);
pub const BASELINE_QUEUE_JOB_PROJECTION: RetentionDuration =
    RetentionDuration::from_days_unchecked(90);
pub const BASELINE_EXPORT_JOB_METADATA: RetentionDuration =
    RetentionDuration::from_days_unchecked(90);
pub const BASELINE_EXPORT_ARTIFACT: RetentionDuration =
    RetentionDuration::from_seconds_unchecked(86_400);
pub const BASELINE_LICENSE_ENTITLEMENT_GRACE: RetentionDuration =
    RetentionDuration::from_days_unchecked(30);
pub const BASELINE_DELETION_STEP: RetentionDuration = RetentionDuration::from_days_unchecked(90);
pub const BASELINE_DELETION_CERTIFICATE: RetentionDuration =
    RetentionDuration::from_days_unchecked(365);
pub const BASELINE_OPERATIONAL_LOG: RetentionDuration = RetentionDuration::from_days_unchecked(30);
pub const BASELINE_BACKUP_LIFECYCLE: RetentionDuration = RetentionDuration::from_days_unchecked(35);
pub const BASELINE_AUDIT_SECURITY_EVENT: RetentionDuration =
    RetentionDuration::from_days_unchecked(365);
pub const BASELINE_FINANCIAL_RECORD: RetentionDuration =
    RetentionDuration::from_days_unchecked(2_555);
pub const BASELINE_IDEMPOTENCY_RECORD: RetentionDuration =
    RetentionDuration::from_seconds_unchecked(86_400);
pub const BASELINE_ACCESS_GRANT: RetentionDuration = RetentionDuration::from_seconds_unchecked(900);

/// Resolve a frozen baseline into the window a registry row declares.
pub const fn baseline_retention(kind: BaselineRetention) -> RetentionWindow {
    match kind {
        BaselineRetention::AutomationProjection => RetentionWindow::AfterAnchor {
            anchor: RetentionAnchor::TerminalState,
            grace: BASELINE_AUTOMATION_PROJECTION,
        },
        BaselineRetention::DeliveryProjection => RetentionWindow::AfterAnchor {
            anchor: RetentionAnchor::DeliveryCompleted,
            grace: BASELINE_DELIVERY_PROJECTION,
        },
        BaselineRetention::QueueJobProjection => RetentionWindow::AfterAnchor {
            anchor: RetentionAnchor::TerminalState,
            grace: BASELINE_QUEUE_JOB_PROJECTION,
        },
        BaselineRetention::ExportJobMetadata => {
            RetentionWindow::Bounded(BASELINE_EXPORT_JOB_METADATA)
        }
        BaselineRetention::ExportArtifact => RetentionWindow::Bounded(BASELINE_EXPORT_ARTIFACT),
        BaselineRetention::LicenseEntitlementMetadata => RetentionWindow::AfterAnchor {
            anchor: RetentionAnchor::LicenseOfflineValidUntil,
            grace: BASELINE_LICENSE_ENTITLEMENT_GRACE,
        },
        BaselineRetention::DeletionStep => RetentionWindow::AfterAnchor {
            anchor: RetentionAnchor::DeletionJobCompleted,
            grace: BASELINE_DELETION_STEP,
        },
        BaselineRetention::DeletionCertificate => {
            RetentionWindow::Bounded(BASELINE_DELETION_CERTIFICATE)
        }
        BaselineRetention::OperationalLog => RetentionWindow::Bounded(BASELINE_OPERATIONAL_LOG),
        BaselineRetention::BackupLifecycle => RetentionWindow::Bounded(BASELINE_BACKUP_LIFECYCLE),
        BaselineRetention::AuditSecurityEvent => {
            RetentionWindow::Bounded(BASELINE_AUDIT_SECURITY_EVENT)
        }
        BaselineRetention::FinancialRecord => RetentionWindow::Bounded(BASELINE_FINANCIAL_RECORD),
        BaselineRetention::IdempotencyRecord => {
            RetentionWindow::Bounded(BASELINE_IDEMPOTENCY_RECORD)
        }
        BaselineRetention::AccessGrant => RetentionWindow::Bounded(BASELINE_ACCESS_GRANT),
    }
}

/// Backup lifecycle. F20-008 is explicit that backups are not selectively
/// rewritten for an active deletion; the platform lifecycle is the only
/// mechanism, so the policy records which one applies instead of pretending an
/// export or deletion job can reach into backup storage.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupLifecycle {
    /// Platform-managed backups expire on a 35-day lifecycle.
    #[default]
    PlatformExpiry,
    /// Backups are not taken for this scope.
    PlatformNoBackup,
}

impl BackupLifecycle {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlatformExpiry => "platform_35_day_expiry",
            Self::PlatformNoBackup => "platform_no_backup",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "platform_35_day_expiry" => Some(Self::PlatformExpiry),
            "platform_no_backup" => Some(Self::PlatformNoBackup),
            _ => None,
        }
    }

    /// When platform backups for this scope disappear.
    pub const fn retention(&self) -> RetentionWindow {
        RetentionWindow::Bounded(BASELINE_BACKUP_LIFECYCLE)
    }
}

impl fmt::Display for RetentionWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lifecycle => f.write_str("lifecycle"),
            Self::Bounded(duration) => write!(f, "bounded({duration})"),
            Self::AfterAnchor { anchor, grace } => write!(f, "{anchor:?}+{grace}"),
        }
    }
}

/// Which classes a legal hold covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HoldScope {
    /// Every class in the policy's scope.
    All,
    /// An explicit, bounded class list.
    Classes(Vec<DataClass>),
}

impl HoldScope {
    pub fn covers(&self, class: &DataClass) -> bool {
        match self {
            Self::All => true,
            Self::Classes(classes) => classes.contains(class),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::All => 1,
            Self::Classes(classes) => classes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Classes(classes) if classes.is_empty())
    }
}

/// An active or released legal hold.
///
/// The gate requires an "audited support/legal release", so a release must name
/// the releasing principal; [`LegalHold::new`] rejects a released hold without
/// one. A hold blocks expiry *and* deletion, which is why both the retention
/// decision and the deletion planner consult it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegalHold {
    active: bool,
    scope: HoldScope,
    placed_at: u64,
    released_at: Option<u64>,
    released_by: Option<String>,
    reason: String,
}

impl LegalHold {
    /// Build a hold. `released_at`/`released_by` are both required together:
    /// an unowned release is never an audited release.
    pub fn new(
        active: bool,
        scope: HoldScope,
        placed_at: u64,
        released_at: Option<u64>,
        released_by: Option<String>,
        reason: impl Into<String>,
    ) -> Result<Self, RetentionError> {
        let reason = reason.into();
        let trimmed = reason.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_HOLD_REASON_LEN {
            return Err(RetentionError::InvalidHoldReason);
        }
        if let Some(at) = released_at
            && at < placed_at
        {
            return Err(RetentionError::HoldReleaseBeforePlacement);
        }
        if released_at.is_some() && released_by.as_deref().is_none_or(str::is_empty) {
            return Err(RetentionError::HoldReleaseUnattributed);
        }
        match &scope {
            HoldScope::All => {}
            HoldScope::Classes(classes) => {
                if classes.is_empty() {
                    return Err(RetentionError::EmptyHoldScope);
                }
                if classes.len() > MAX_HOLD_SCOPE_CLASSES {
                    return Err(RetentionError::HoldScopeTooLarge);
                }
            }
        }
        Ok(Self {
            active,
            scope,
            placed_at,
            released_at,
            released_by,
            reason,
        })
    }

    /// A scope-wide hold placed now, with no release yet.
    pub fn scope_wide(placed_at: u64, reason: impl Into<String>) -> Result<Self, RetentionError> {
        Self::new(true, HoldScope::All, placed_at, None, None, reason)
    }

    pub const fn is_active_flag(&self) -> bool {
        self.active
    }

    pub const fn scope(&self) -> &HoldScope {
        &self.scope
    }

    pub const fn placed_at(&self) -> u64 {
        self.placed_at
    }

    pub const fn released_at(&self) -> Option<u64> {
        self.released_at
    }

    pub fn released_by(&self) -> Option<&str> {
        self.released_by.as_deref()
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// A hold is in force only after it was placed and while it has not been
    /// released. A not-yet-placed or already-released hold blocks nothing.
    pub fn is_active_at(&self, now: u64) -> bool {
        self.active
            && now >= self.placed_at
            && self.released_at.is_none_or(|released| now < released)
    }

    pub fn covers_at(&self, class: &DataClass, now: u64) -> bool {
        self.is_active_at(now) && self.scope.covers(class)
    }
}

/// An audited permission to exceed the per-class legal maximum. Both the
/// principal and the audit correlation are required: an override nobody can
/// attribute is not an override.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditedOverride {
    pub principal_id: String,
    pub audit_correlation_id: String,
}

impl AuditedOverride {
    pub fn new(
        principal_id: impl Into<String>,
        audit_correlation_id: impl Into<String>,
    ) -> Result<Self, RetentionError> {
        let principal_id = principal_id.into();
        let audit_correlation_id = audit_correlation_id.into();
        if principal_id.trim().is_empty() || principal_id.len() > MAX_HOLD_REASON_LEN {
            return Err(RetentionError::InvalidOverridePrincipal);
        }
        if audit_correlation_id.trim().is_empty()
            || audit_correlation_id.len() > MAX_HOLD_REASON_LEN
        {
            return Err(RetentionError::InvalidOverrideCorrelation);
        }
        Ok(Self {
            principal_id,
            audit_correlation_id,
        })
    }
}

/// A tenant's per-class retention choice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionOverride {
    pub window: RetentionWindow,
    /// Present only when the window reaches or passes the legal maximum.
    pub audited_override: Option<AuditedOverride>,
}

impl RetentionOverride {
    /// A plain shortening: no audit trail is needed to keep less data.
    pub fn shorten_to(window: RetentionWindow) -> Self {
        Self {
            window,
            audited_override: None,
        }
    }

    pub fn audited(window: RetentionWindow, override_grant: AuditedOverride) -> Self {
        Self {
            window,
            audited_override: Some(override_grant),
        }
    }
}

/// The pure input to [`decide`]: the tenant's data-governance policy as it
/// applies to retention. This is a projection of the persisted
/// `DataGovernancePolicy`; it is not an authorization or persistence layer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub overrides: BTreeMap<DataClass, RetentionOverride>,
    pub backup_lifecycle: BackupLifecycle,
}

impl RetentionPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Most classes one policy may override. A policy document that can address
    /// an unbounded number of classes is a bulk-retention decision without the
    /// review a legal hold requires.
    pub const MAX_OVERRIDDEN_CLASSES: usize = 256;

    pub fn set_override(
        &mut self,
        class: DataClass,
        retention_override: RetentionOverride,
    ) -> Result<(), RetentionError> {
        if self.overrides.len() >= Self::MAX_OVERRIDDEN_CLASSES
            && !self.overrides.contains_key(&class)
        {
            return Err(RetentionError::TooManyOverrides);
        }
        self.overrides.insert(class, retention_override);
        Ok(())
    }

    pub fn override_for(&self, class: &DataClass) -> Option<&RetentionOverride> {
        self.overrides.get(class)
    }

    pub fn backup_lifecycle(&self) -> BackupLifecycle {
        self.backup_lifecycle
    }
}

/// Where the effective window came from. Recorded on every decision so an
/// audit can distinguish a baseline from a tenant shortening from an audited
/// extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionSource {
    /// The frozen gate baseline for the class.
    Default,
    /// A tenant policy override.
    PolicyOverride,
    /// A tenant policy override carrying an audited grant.
    AuditedPolicyOverride,
    /// A legal hold suspended the window.
    LegalHold,
}

impl RetentionSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::PolicyOverride => "policy_override",
            Self::AuditedPolicyOverride => "audited_policy_override",
            Self::LegalHold => "legal_hold",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "default" => Some(Self::Default),
            "policy_override" => Some(Self::PolicyOverride),
            "audited_policy_override" => Some(Self::AuditedPolicyOverride),
            "legal_hold" => Some(Self::LegalHold),
            _ => None,
        }
    }
}

/// Stable reason codes for a retention decision. These are safe to log: none
/// of them carries a record body, a subject identifier, or a class value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionReason {
    /// Gate baseline window, measured from the record's own start.
    DefaultWindow,
    /// Gate baseline window, measured from a lifecycle anchor.
    DefaultWindowAfterAnchor,
    /// A lifecycle class: no expiry, deleted by its own lifecycle request.
    LifecycleRetention,
    /// A tenant policy shortened the window.
    PolicyShortened,
    /// An audited override extended the window inside the legal maximum.
    PolicyExtendedAudited,
    /// A legal hold suspends expiry for this class.
    LegalHoldApplied,
}

impl RetentionReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DefaultWindow => "retention_default_window",
            Self::DefaultWindowAfterAnchor => "retention_default_window_after_anchor",
            Self::LifecycleRetention => "retention_lifecycle",
            Self::PolicyShortened => "retention_policy_shortened",
            Self::PolicyExtendedAudited => "retention_policy_extended_audited",
            Self::LegalHoldApplied => "retention_legal_hold",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [
            Self::DefaultWindow,
            Self::DefaultWindowAfterAnchor,
            Self::LifecycleRetention,
            Self::PolicyShortened,
            Self::PolicyExtendedAudited,
            Self::LegalHoldApplied,
        ]
        .into_iter()
        .find(|candidate| candidate.as_str() == value)
    }
}

/// The result of [`decide`].
///
/// `expire_at` is `None` for a lifecycle window *and* for a suspended hold: in
/// both cases there is currently no expiry, and the caller must not confuse
/// "no expiry by policy" with "expiry blocked pending an audited release".
/// `hold_applies` distinguishes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionDecision {
    pub expire_at: Option<u64>,
    pub hold_applies: bool,
    pub reason: RetentionReason,
    pub source: RetentionSource,
    pub window: RetentionWindow,
}

impl RetentionDecision {
    /// True when the record may be expired right now.
    pub fn is_expired_at(&self, now: u64) -> bool {
        !self.hold_applies && self.expire_at.is_some_and(|expire| now >= expire)
    }
}

/// Decide the effective retention window for one data class.
///
/// Order matters and is fixed:
///
/// 1. start from the frozen registry baseline;
/// 2. apply the tenant override, if any;
/// 3. fail closed if the effective window passes the class legal maximum
///    without an audited override;
/// 4. suspend expiry entirely if a legal hold covers the class right now.
///
/// `anchor` is the instant the window is measured from. It is required for a
/// bounded window (the record's own start) and for an anchored window (the
/// lifecycle instant); omitting it is an error rather than a silent "now".
pub fn decide(
    record: &super::registry::DataClassRecord,
    policy: &RetentionPolicy,
    now: u64,
    anchor: Option<u64>,
    hold: Option<&LegalHold>,
) -> Result<RetentionDecision, RetentionError> {
    let baseline = record.default_retention;
    let effective = match policy.override_for(&record.class) {
        None => RetentionSource::Default,
        Some(retention_override) => {
            let maximum = record.legal_maximum;
            if retention_override.window.exceeds(&maximum) {
                // Beyond the legal maximum there is no tenant decision left to
                // make: only an audited override can keep the data.
                if retention_override.audited_override.is_none() {
                    return Err(RetentionError::OverLegalMaximum);
                }
                RetentionSource::AuditedPolicyOverride
            } else if retention_override.window.exceeds(&baseline) {
                RetentionSource::AuditedPolicyOverride
            } else {
                RetentionSource::PolicyOverride
            }
        }
    };
    let window = match effective {
        RetentionSource::Default => baseline,
        _ => policy
            .override_for(&record.class)
            .map_or(baseline, |retention_override| retention_override.window),
    };

    // A hold blocks expiry and deletion. It is evaluated last so a tenant
    // cannot shorten its way out of a hold it does not own.
    if hold.is_some_and(|legal| legal.covers_at(&record.class, now)) {
        return Ok(RetentionDecision {
            expire_at: None,
            hold_applies: true,
            reason: RetentionReason::LegalHoldApplied,
            source: RetentionSource::LegalHold,
            window,
        });
    }

    let reason = match (effective, window) {
        (RetentionSource::Default, RetentionWindow::Lifecycle) => {
            RetentionReason::LifecycleRetention
        }
        (RetentionSource::Default, RetentionWindow::AfterAnchor { .. }) => {
            RetentionReason::DefaultWindowAfterAnchor
        }
        (RetentionSource::Default, RetentionWindow::Bounded(_)) => RetentionReason::DefaultWindow,
        (RetentionSource::PolicyOverride, _) => RetentionReason::PolicyShortened,
        (RetentionSource::AuditedPolicyOverride, _) => RetentionReason::PolicyExtendedAudited,
        (RetentionSource::LegalHold, _) => RetentionReason::LegalHoldApplied,
    };

    Ok(RetentionDecision {
        expire_at: window.expire_at(anchor)?,
        hold_applies: false,
        reason,
        source: effective,
        window,
    })
}

/// Pure validation failures. Each variant carries a stable `code()` so a route
/// can map it onto the frozen error vocabulary without parsing a message, and
/// no variant carries the rejected value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RetentionError {
    DurationOutOfRange,
    MissingAnchor(RetentionAnchor),
    OverLegalMaximum,
    TooManyOverrides,
    InvalidHoldReason,
    EmptyHoldScope,
    HoldScopeTooLarge,
    HoldReleaseBeforePlacement,
    HoldReleaseUnattributed,
    InvalidOverridePrincipal,
    InvalidOverrideCorrelation,
}

impl RetentionError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::DurationOutOfRange => "data_policy_retention_out_of_range",
            Self::MissingAnchor(_) => "data_policy_retention_anchor_missing",
            Self::OverLegalMaximum => "data_policy_retention_over_legal_maximum",
            Self::TooManyOverrides => "data_policy_invalid",
            Self::InvalidHoldReason
            | Self::EmptyHoldScope
            | Self::HoldScopeTooLarge
            | Self::HoldReleaseBeforePlacement
            | Self::HoldReleaseUnattributed => "data_policy_invalid",
            Self::InvalidOverridePrincipal | Self::InvalidOverrideCorrelation => {
                "data_policy_override_unattributed"
            }
        }
    }

    /// True when the failure is the gate's legal-hold reason rather than a
    /// validation failure, so a deletion job can park in `needs_attention`
    /// with `deletion_legal_hold` instead of reporting a policy bug.
    pub const fn is_legal_hold(self) -> bool {
        matches!(self, Self::MissingAnchor(_))
    }
}

impl fmt::Display for RetentionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAnchor(anchor) => {
                write!(f, "retention window needs the {anchor:?} anchor")
            }
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for RetentionError {}
