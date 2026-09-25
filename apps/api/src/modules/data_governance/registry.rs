//! The P06 data-class registry: the machine-readable form of F20-001.
//!
//! F20-001 says "every new persistent data type MUST declare owner/scope,
//! sensitivity, default retention, deletion behavior, export behavior, and
//! whether it may appear in logs". `docs/specs/` is prose, so it cannot fail a
//! build. This module turns that requirement into a table that cannot describe a
//! class incompletely: [`DataClassRecord`] has no optional attribute, so a class
//! that reaches the registry has already declared all six, and
//! [`DataClassRecord::validate`] re-checks the cross-attribute rules that a
//! type alone cannot express.
//!
//! The table covers every class named by the `P06-CG.md` governance matrices —
//! all P06 projections plus the existing P01–P05 classes. Two cross-attribute
//! rules are load-bearing and have dedicated tests:
//!
//! * secret material is never exported and is crypto-erased, so a leaked
//!   ciphertext is useless without the key; and
//! * Lumi never claims to delete data it does not own. Every
//!   `external` owner-scope class and every upstream-provider reference is
//!   retained or skipped, never "deleted".
//!
//! Mapping notes, so the table is auditable against the gate:
//!
//! * The gate writes deletion as "delete/tombstone" for most rows. That maps to
//!   [`DeletionBehavior::Tombstone`]: the row loses its personal content and
//!   keeps a tombstone, which is what F20-006 and P06-CR-003 require for
//!   immutable audit/usage history. Rows the gate describes as object or
//!   backup removal map to [`DeletionBehavior::PhysicalDelete`].
//! * The gate's "Logging" column ("IDs/status only", "state/reason", "never
//!   secret") is a per-class ceiling, [`LoggingRule`], not a tenant
//!   [`LoggingMode`](super::logging::LoggingMode). A class's rule is the widest
//!   mode it may ever be logged under; the tenant mode only ever sits above it.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::logging::LoggingRule;
use super::retention::{
    ACCESS_GRANT_CEILING, BaselineRetention, EXPORT_ARTIFACT_CEILING, FINANCIAL_RECORD_CEILING,
    IDEMPOTENCY_CEILING, OPERATIONAL_PROJECTION_CEILING, RetentionDuration, RetentionWindow,
    SENSITIVE_PROJECTION_CEILING, baseline_retention,
};

/// Registry rows are keyed by a bounded snake_case identifier. The bound
/// matches the persistence layer's `data_class_registry` key so a class that
/// validates here is never rejected only at the database boundary.
pub const MAX_DATA_CLASS_LEN: usize = 128;

/// How sensitive a class is. This drives redaction defaults, support access,
/// and the prohibition on physical deletion of the highest classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    Internal,
    Confidential,
    Restricted,
    Secret,
}

impl Sensitivity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Confidential => "confidential",
            Self::Restricted => "restricted",
            Self::Secret => "secret",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "public" => Some(Self::Public),
            "internal" => Some(Self::Internal),
            "confidential" => Some(Self::Confidential),
            "restricted" => Some(Self::Restricted),
            "secret" => Some(Self::Secret),
            _ => None,
        }
    }

    /// True when the class is credential/key material or derived from it.
    pub const fn is_secret_material(self) -> bool {
        matches!(self, Self::Secret)
    }
}

/// Who owns a class, and therefore whose deletion request reaches it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerScope {
    /// Lumi platform data (plans, entitlement definitions, audit rows).
    Platform,
    /// Tenant-owned; an organization deletion request reaches it.
    Organization,
    /// Project-owned inside an organization.
    Project,
    /// User-owned; a personal data request reaches it.
    User,
    /// Device/enrollment state.
    Device,
    /// Owned by an upstream AI provider, not by Lumi.
    External,
}

impl OwnerScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::Organization => "organization",
            Self::Project => "project",
            Self::User => "user",
            Self::Device => "device",
            Self::External => "external",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "platform" => Some(Self::Platform),
            "organization" => Some(Self::Organization),
            "project" => Some(Self::Project),
            "user" => Some(Self::User),
            "device" => Some(Self::Device),
            "external" => Some(Self::External),
            _ => None,
        }
    }

    /// True when an organization or personal deletion request can reach a class
    /// with this owner scope. `External` and `Platform` are out of reach: the
    /// first is not Lumi's data, the second outlives any tenant.
    pub const fn is_deletion_reachable(self) -> bool {
        matches!(
            self,
            Self::Organization | Self::Project | Self::User | Self::Device
        )
    }
}

/// How a class may appear in an export artifact.
///
/// `Never` is a real declaration, not a placeholder: operational queue/outbox
/// rows, login sessions, and stored secret material are excluded from every
/// export, in both personal and organization scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportBehavior {
    /// Included as-is under an authorized scope.
    Included,
    /// Included in its owner's personal export only.
    OwnerExport,
    /// Included with sensitive fields removed.
    Redacted,
    /// Included as a sanitized status/label projection.
    Sanitized,
    /// Only non-content metadata (identifiers, versions, state) is included.
    MetadataOnly,
    /// Never included in any export.
    Never,
}

impl ExportBehavior {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Included => "included",
            Self::OwnerExport => "owner_export",
            Self::Redacted => "redacted",
            Self::Sanitized => "sanitized",
            Self::MetadataOnly => "metadata_only",
            Self::Never => "never",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "included" => Some(Self::Included),
            "owner_export" => Some(Self::OwnerExport),
            "redacted" => Some(Self::Redacted),
            "sanitized" => Some(Self::Sanitized),
            "metadata_only" => Some(Self::MetadataOnly),
            "never" => Some(Self::Never),
            _ => None,
        }
    }

    /// True when the class may be referenced by an export manifest.
    pub const fn is_exportable(self) -> bool {
        !matches!(self, Self::Never)
    }
}

/// What deletion of a class actually does.
///
/// F20-006 and P06-CR-003 are the reason most classes tombstone rather than
/// drop: immutable audit, usage, and cost rows have dependents and legal
/// weight, so the personal content is minimized away and a tombstoned
/// identifier is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionBehavior {
    /// Row and its owned copies are removed.
    PhysicalDelete,
    /// Row is removed of personal content and kept as a tombstone.
    Tombstone,
    /// Row is kept with personal content minimized to what the law needs.
    Minimize,
    /// Ciphertext and key references are destroyed; the row survives as metadata.
    CryptoErase,
    /// Capability is revoked (credential, entitlement grant) and the row survives.
    Revoke,
    /// The record is deliberately kept because a legal/security duty requires it.
    RetainLegalOnly,
}

impl DeletionBehavior {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PhysicalDelete => "physical_delete",
            Self::Tombstone => "tombstone",
            Self::Minimize => "minimize",
            Self::CryptoErase => "crypto_erase",
            Self::Revoke => "revoke",
            Self::RetainLegalOnly => "retain_legal_only",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "physical_delete" => Some(Self::PhysicalDelete),
            "tombstone" => Some(Self::Tombstone),
            "minimize" => Some(Self::Minimize),
            "crypto_erase" => Some(Self::CryptoErase),
            "revoke" => Some(Self::Revoke),
            "retain_legal_only" => Some(Self::RetainLegalOnly),
            _ => None,
        }
    }

    /// True when a deletion request should still act on the class. A
    /// `retain_legal_only` class is deliberately left in place and reported as
    /// retained in the deletion certificate.
    pub const fn is_actionable(self) -> bool {
        !matches!(self, Self::RetainLegalOnly)
    }

    /// True when the behavior still leaves a record behind.
    pub const fn retains_record(self) -> bool {
        !matches!(self, Self::PhysicalDelete)
    }
}

/// A stable, validated identifier for one persistent data class.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DataClass(String);

impl DataClass {
    /// Validating constructor. Only lowercase `snake_case` is accepted so a
    /// class key can be used verbatim as a `deletion_tasks.data_class` value
    /// and in a stable reason/log line.
    pub fn new(value: impl Into<String>) -> Result<Self, RegistryError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_DATA_CLASS_LEN || !is_snake_case(&value) {
            return Err(RegistryError::InvalidDataClass);
        }
        Ok(Self(value))
    }

    /// Parse a class key. Present so callers migrating a stored value have the
    /// same `as_str`/`parse` pairing as every other identifier in the API.
    pub fn parse(value: &str) -> Result<Self, RegistryError> {
        Self::new(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Declaration order index, used to make deletion plans deterministic.
    pub(crate) fn declaration_index(&self) -> Option<usize> {
        DEFINITIONS
            .iter()
            .position(|definition| definition.class == self.0)
    }
}

impl fmt::Debug for DataClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DataClass").field(&self.0).finish()
    }
}

impl fmt::Display for DataClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for DataClass {
    type Err = RegistryError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

fn is_snake_case(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.first().is_some_and(u8::is_ascii_uppercase) {
        return false;
    }
    let mut previous_underscore = true;
    for byte in bytes {
        match byte {
            b'_' => {
                if previous_underscore {
                    return false;
                }
                previous_underscore = true;
            }
            _ if byte.is_ascii_lowercase() || byte.is_ascii_digit() => previous_underscore = false,
            _ => return false,
        }
    }
    !previous_underscore
}

/// One complete governance declaration for one persistent data class.
///
/// Every attribute is required — there is no `Option` and no default — so
/// "declared" is a property of the type, not a review convention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataClassRecord {
    pub class: DataClass,
    pub sensitivity: Sensitivity,
    pub owner_scope: OwnerScope,
    pub default_retention: RetentionWindow,
    /// The longest window a tenant policy may set. Going past it needs an
    /// audited override, which `retention::decide` enforces.
    pub legal_maximum: RetentionWindow,
    pub export_behavior: ExportBehavior,
    pub deletion_behavior: DeletionBehavior,
    pub logging: LoggingRule,
    pub description: &'static str,
}

impl DataClassRecord {
    pub const fn class(&self) -> &DataClass {
        &self.class
    }

    pub const fn sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }

    pub const fn owner_scope(&self) -> OwnerScope {
        self.owner_scope
    }

    pub const fn default_retention(&self) -> RetentionWindow {
        self.default_retention
    }

    pub const fn legal_maximum(&self) -> RetentionWindow {
        self.legal_maximum
    }

    pub const fn export_behavior(&self) -> ExportBehavior {
        self.export_behavior
    }

    pub const fn deletion_behavior(&self) -> DeletionBehavior {
        self.deletion_behavior
    }

    pub const fn logging(&self) -> LoggingRule {
        self.logging
    }

    pub const fn description(&self) -> &'static str {
        self.description
    }

    /// True when an export manifest may reference this class.
    pub const fn is_exportable(&self) -> bool {
        self.export_behavior.is_exportable()
    }

    /// True when a tenant deletion request acts on this class at all.
    pub const fn is_deletion_actionable(&self) -> bool {
        self.deletion_behavior.is_actionable()
    }

    /// True when a legal/security duty keeps the record after deletion.
    pub const fn is_legally_retained(&self) -> bool {
        matches!(self.deletion_behavior, DeletionBehavior::RetainLegalOnly)
            || !self.owner_scope.is_deletion_reachable()
    }

    /// Cross-attribute invariants. A single attribute can be right while the
    /// combination is dangerous, so these are checked explicitly.
    pub fn validate(&self) -> Result<(), RegistryError> {
        if self.class.as_str().is_empty() || self.class.as_str().len() > MAX_DATA_CLASS_LEN {
            return Err(RegistryError::IncompleteDeclaration);
        }
        if self.description.trim().is_empty() {
            return Err(RegistryError::IncompleteDeclaration);
        }
        // Secret material is never exportable, and losing it means destroying
        // the ciphertext rather than tombstoning a row that still decrypts.
        if self.sensitivity.is_secret_material()
            && (self.export_behavior != ExportBehavior::Never
                || self.deletion_behavior != DeletionBehavior::CryptoErase)
        {
            return Err(RegistryError::SecretExportOrDeletion);
        }
        // A secret class must never reach a content ceiling. The gate allows
        // "key ID only" for secret material, so `ids_status` is correct, but
        // `metadata_only` would also admit a redacted excerpt and is refused.
        if self.sensitivity.is_secret_material()
            && !matches!(
                self.logging,
                LoggingRule::StatusOnly | LoggingRule::IdsStatus | LoggingRule::None
            )
        {
            return Err(RegistryError::SecretLoggable);
        }
        // Lumi does not delete other people's data.
        if self.owner_scope == OwnerScope::External
            && self.deletion_behavior.is_actionable()
            && self.deletion_behavior != DeletionBehavior::Minimize
        {
            return Err(RegistryError::ExternalDataDeletable);
        }
        // The default must be a declared window within its own legal maximum.
        if self.default_retention.exceeds(&self.legal_maximum) {
            return Err(RegistryError::DefaultExceedsLegalMaximum);
        }
        if self
            .default_retention
            .bound_seconds()
            .is_some_and(|seconds| seconds > super::retention::MAX_RETENTION_SECONDS)
        {
            return Err(RegistryError::DefaultExceedsLegalMaximum);
        }
        Ok(())
    }
}

/// One row of the frozen table. `const` so the registry is compiled into the
/// binary rather than read from configuration, and so a malformed row is a
/// compile-time-visible literal rather than a runtime surprise.
struct Definition {
    class: &'static str,
    sensitivity: Sensitivity,
    owner_scope: OwnerScope,
    retention: RetentionWindow,
    legal_maximum: RetentionWindow,
    export: ExportBehavior,
    deletion: DeletionBehavior,
    logging: LoggingRule,
    description: &'static str,
}

impl Definition {
    fn record(&self) -> DataClassRecord {
        DataClassRecord {
            // Safe: every key is a snake_case literal in this module, and the
            // coverage test re-validates every constructed record.
            class: DataClass::new(self.class).expect("registry class key is snake_case"),
            sensitivity: self.sensitivity,
            owner_scope: self.owner_scope,
            default_retention: self.retention,
            legal_maximum: self.legal_maximum,
            export_behavior: self.export,
            deletion_behavior: self.deletion,
            logging: self.logging,
            description: self.description,
        }
    }
}

/// Shorthand for a frozen gate baseline.
const fn baseline(kind: BaselineRetention) -> RetentionWindow {
    baseline_retention(kind)
}

const fn bounded(duration: RetentionDuration) -> RetentionWindow {
    RetentionWindow::Bounded(duration)
}

const fn anchored(
    anchor: super::retention::RetentionAnchor,
    duration: RetentionDuration,
) -> RetentionWindow {
    RetentionWindow::AfterAnchor {
        anchor,
        grace: duration,
    }
}

use super::retention::RetentionAnchor as Anchor;

const OPERATIONAL_CEILING: RetentionWindow = bounded(OPERATIONAL_PROJECTION_CEILING);
const SENSITIVE_CEILING: RetentionWindow = bounded(SENSITIVE_PROJECTION_CEILING);
const FINANCIAL_CEILING: RetentionWindow = bounded(FINANCIAL_RECORD_CEILING);

/// The frozen data-class table.
///
/// P06 projections come first, then the existing P01–P05 classes, then the
/// cross-cutting operational class the retention baseline names. Declaration
/// order is meaningful: the deletion planner walks it in this order so a plan
/// is deterministic and reviewable.
const DEFINITIONS: &[Definition] = &[
    // ---------------------------------------------------------------- P06 --
    Definition {
        class: "automation_definition",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Organization,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Included,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::MetadataOnly,
        description: "Org/project automation definition: trigger, schedule, target, and execution policy constraints.",
    },
    Definition {
        class: "schedule_rule",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Organization,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Included,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::MetadataOnly,
        description: "Immutable schedule revision. History is retained; labels are tombstoned rather than edited.",
    },
    Definition {
        class: "occurrence",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Organization,
        retention: baseline(BaselineRetention::AutomationProjection),
        legal_maximum: OPERATIONAL_CEILING,
        export: ExportBehavior::Included,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Logical scheduled occurrence: state, attempt count, and a bounded reason code. 90 days after terminal.",
    },
    Definition {
        class: "execution_lease",
        sensitivity: Sensitivity::Restricted,
        owner_scope: OwnerScope::Device,
        retention: baseline(BaselineRetention::AutomationProjection),
        legal_maximum: OPERATIONAL_CEILING,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Time-bounded execution claim. Only state and fence metadata; the raw lease token is never stored or logged.",
    },
    Definition {
        class: "occurrence_attempt",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Organization,
        retention: baseline(BaselineRetention::AutomationProjection),
        legal_maximum: OPERATIONAL_CEILING,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Append-only lease attempt history, tombstoned after a deletion certificate is issued.",
    },
    Definition {
        class: "automation_run_link",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Organization,
        retention: baseline(BaselineRetention::AutomationProjection),
        legal_maximum: OPERATIONAL_CEILING,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::IdsStatus,
        description: "Correlation from one occurrence attempt to one existing P05 run. Never a second run authority.",
    },
    Definition {
        class: "webhook_endpoint",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Organization,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Sanitized,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Secret-bearing endpoint configuration. Exports carry a sanitized projection, never the secret.",
    },
    Definition {
        class: "webhook_secret",
        sensitivity: Sensitivity::Secret,
        owner_scope: OwnerScope::Organization,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Never,
        deletion: DeletionBehavior::CryptoErase,
        logging: LoggingRule::IdsStatus,
        description: "Encrypted webhook secret version. Only the key ID is ever logged; the plaintext is shown once at creation.",
    },
    Definition {
        class: "webhook_delivery",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Organization,
        retention: baseline(BaselineRetention::DeliveryProjection),
        legal_maximum: SENSITIVE_CEILING,
        export: ExportBehavior::Sanitized,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "One retryable logical delivery row per stable event and endpoint. 30 days.",
    },
    Definition {
        class: "webhook_delivery_attempt",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Organization,
        retention: baseline(BaselineRetention::DeliveryProjection),
        legal_maximum: SENSITIVE_CEILING,
        export: ExportBehavior::Sanitized,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Append-only attempt history for one delivery. Response bodies are never stored or logged.",
    },
    Definition {
        class: "notification_preference",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::User,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::OwnerExport,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Channel preferences. Mandatory security events are not disableable here.",
    },
    Definition {
        class: "notification",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::User,
        retention: baseline(BaselineRetention::DeliveryProjection),
        legal_maximum: SENSITIVE_CEILING,
        export: ExportBehavior::OwnerExport,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::MetadataOnly,
        description: "Durable in-app notification with bounded rendered metadata. 30 days.",
    },
    Definition {
        class: "notification_delivery",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::User,
        retention: baseline(BaselineRetention::DeliveryProjection),
        legal_maximum: SENSITIVE_CEILING,
        export: ExportBehavior::OwnerExport,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Channel delivery attempt for a notification. 30 days.",
    },
    Definition {
        class: "plan",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Platform,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Sanitized,
        deletion: DeletionBehavior::RetainLegalOnly,
        logging: LoggingRule::StatusOnly,
        description: "Lumi product plan. Provider product/price IDs are adapter-private and never appear here.",
    },
    Definition {
        class: "plan_entitlement",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Platform,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Sanitized,
        deletion: DeletionBehavior::RetainLegalOnly,
        logging: LoggingRule::StatusOnly,
        description: "Versioned limit attached to a plan. Plan history is immutable and retained.",
    },
    Definition {
        class: "billing_account",
        sensitivity: Sensitivity::Restricted,
        owner_scope: OwnerScope::Organization,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Adapter-owned billing projection. Deletion tombstones the provider reference, never the seat history.",
    },
    Definition {
        class: "subscription",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Organization,
        retention: baseline(BaselineRetention::FinancialRecord),
        legal_maximum: FINANCIAL_CEILING,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::Minimize,
        logging: LoggingRule::StatusOnly,
        description: "Mapped commercial state. Seven-year financial baseline; user reference is tombstoned and state retained.",
    },
    Definition {
        class: "subscription_event",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Organization,
        retention: baseline(BaselineRetention::FinancialRecord),
        legal_maximum: FINANCIAL_CEILING,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::Minimize,
        logging: LoggingRule::StatusOnly,
        description: "Append-only provider billing event. History is never rewritten by a downgrade or deletion.",
    },
    Definition {
        class: "provider_entitlement_projection",
        sensitivity: Sensitivity::Internal,
        // Lumi owns this row; it is a projection of provider state, not the
        // provider's data. Deleting it removes Lumi's copy, nothing else.
        owner_scope: OwnerScope::Organization,
        retention: anchored(
            Anchor::LastObservation,
            RetentionDuration::from_days_unchecked(30),
        ),
        legal_maximum: SENSITIVE_CEILING,
        export: ExportBehavior::Sanitized,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Read-only upstream provider account status. It never changes Lumi entitlement, authorization, or budget.",
    },
    Definition {
        class: "entitlement_definition",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Platform,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Sanitized,
        deletion: DeletionBehavior::Revoke,
        logging: LoggingRule::StatusOnly,
        description: "Stable Lumi entitlement key, value type, and limit. Product code consumes only Lumi keys.",
    },
    Definition {
        class: "entitlement_grant",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Organization,
        retention: anchored(
            Anchor::EntitlementGrantExpiry,
            RetentionDuration::from_days_unchecked(30),
        ),
        legal_maximum: SENSITIVE_CEILING,
        export: ExportBehavior::Sanitized,
        deletion: DeletionBehavior::Revoke,
        logging: LoggingRule::StatusOnly,
        description: "Time-bounded plan or audited override grant. Revoked, never silently extended.",
    },
    Definition {
        class: "license_snapshot",
        sensitivity: Sensitivity::Restricted,
        owner_scope: OwnerScope::Organization,
        retention: baseline(BaselineRetention::LicenseEntitlementMetadata),
        legal_maximum: SENSITIVE_CEILING,
        export: ExportBehavior::Sanitized,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Signed entitlement/offline snapshot metadata. `offline_valid_until` plus 30 days.",
    },
    Definition {
        class: "license_state",
        sensitivity: Sensitivity::Restricted,
        owner_scope: OwnerScope::Organization,
        retention: baseline(BaselineRetention::LicenseEntitlementMetadata),
        legal_maximum: SENSITIVE_CEILING,
        export: ExportBehavior::Sanitized,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Server-side capability matrix projection. Not a second authority and not a public route.",
    },
    Definition {
        class: "license_signing_key",
        sensitivity: Sensitivity::Restricted,
        owner_scope: OwnerScope::Platform,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Sanitized,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::IdsStatus,
        description: "Signing key ID and verification window. Private key material is a Worker secret, never a row.",
    },
    Definition {
        class: "data_governance_policy",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Organization,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Included,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::MetadataOnly,
        description: "Org/project logging mode, retention overrides, export expiry, and legal-hold state.",
    },
    Definition {
        class: "data_class_registry",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Platform,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Included,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::MetadataOnly,
        description: "The governance declaration table itself, versioned with only changed keys logged.",
    },
    Definition {
        class: "export_job",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Organization,
        retention: baseline(BaselineRetention::ExportJobMetadata),
        legal_maximum: OPERATIONAL_CEILING,
        export: ExportBehavior::MetadataOnly,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Sensitive pointer to an export request: scope, category manifest, and cutoff. 90 days.",
    },
    Definition {
        class: "export_artifact",
        sensitivity: Sensitivity::Restricted,
        owner_scope: OwnerScope::Organization,
        retention: baseline(BaselineRetention::ExportArtifact),
        legal_maximum: bounded(EXPORT_ARTIFACT_CEILING),
        export: ExportBehavior::Sanitized,
        deletion: DeletionBehavior::PhysicalDelete,
        logging: LoggingRule::StatusOnly,
        description: "Private R2 object metadata. Content is delivered only through a re-authorized expiring download, never a public URL.",
    },
    Definition {
        class: "export_download_grant",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::User,
        retention: baseline(BaselineRetention::AccessGrant),
        legal_maximum: bounded(ACCESS_GRANT_CEILING),
        export: ExportBehavior::MetadataOnly,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Short-lived re-authorized download grant. Only a fingerprint is stored; the raw token is returned once.",
    },
    Definition {
        class: "deletion_job",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Organization,
        retention: baseline(BaselineRetention::ExportJobMetadata),
        legal_maximum: OPERATIONAL_CEILING,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Resumable deletion workflow state. Tombstoned only after a deletion certificate is issued.",
    },
    Definition {
        class: "deletion_step",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Organization,
        retention: baseline(BaselineRetention::DeletionStep),
        legal_maximum: OPERATIONAL_CEILING,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Per data class / object reference deletion step. 90 days after the job completes.",
    },
    Definition {
        class: "deletion_certificate",
        sensitivity: Sensitivity::Restricted,
        owner_scope: OwnerScope::Organization,
        retention: baseline(BaselineRetention::DeletionCertificate),
        legal_maximum: FINANCIAL_CEILING,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::RetainLegalOnly,
        logging: LoggingRule::StatusOnly,
        description: "Final audited result. Retained for 365 days and never physically removed.",
    },
    Definition {
        class: "queue_job_envelope",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Organization,
        retention: baseline(BaselineRetention::QueueJobProjection),
        legal_maximum: OPERATIONAL_CEILING,
        export: ExportBehavior::Never,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Versioned, deduplicated worker envelope. Metadata only; never carries a secret or raw content.",
    },
    Definition {
        class: "provider_sync_state",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Organization,
        retention: anchored(
            Anchor::RequestAccepted,
            RetentionDuration::from_seconds_unchecked(86_400),
        ),
        legal_maximum: bounded(IDEMPOTENCY_CEILING),
        export: ExportBehavior::MetadataOnly,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Upstream sync cursor and last-observed state. Metadata only; a raw provider payload is never stored or exported.",
    },
    Definition {
        class: "idempotency_record",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Organization,
        retention: anchored(
            Anchor::RequestAccepted,
            RetentionDuration::from_seconds_unchecked(86_400),
        ),
        legal_maximum: bounded(IDEMPOTENCY_CEILING),
        export: ExportBehavior::Never,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Replay-protection claim/response record. Bounded retry TTL; a stored response body is never exported.",
    },
    // ------------------------------------------------------------ P01–P05 --
    Definition {
        class: "identity",
        sensitivity: Sensitivity::Restricted,
        owner_scope: OwnerScope::User,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::OwnerExport,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::IdsStatus,
        description: "Account identity. Tombstoned where legal retention requires; codes, tokens, and key material are never logged.",
    },
    Definition {
        class: "login_session",
        sensitivity: Sensitivity::Restricted,
        owner_scope: OwnerScope::User,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Never,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::IdsStatus,
        description: "Browser session bearer reference. Revoked and deleted with the account; never exportable content.",
    },
    Definition {
        class: "passkey_authenticator",
        sensitivity: Sensitivity::Restricted,
        owner_scope: OwnerScope::User,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::OwnerExport,
        deletion: DeletionBehavior::CryptoErase,
        logging: LoggingRule::IdsStatus,
        description: "Passkey/authenticator metadata. Deletion destroys the key reference; the private key never enters a row.",
    },
    Definition {
        class: "organization",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Organization,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Included,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::MetadataOnly,
        description: "Tenant record and lifecycle state, including `pending_deletion` as the P02 bridge.",
    },
    Definition {
        class: "membership",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Organization,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Included,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Org membership and role. Seat counts are derived from these rows, not from client totals.",
    },
    Definition {
        class: "invitation",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Organization,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Included,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Pending invitation. Not billable, and never counted as an active member.",
    },
    Definition {
        class: "team",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Organization,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Included,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::MetadataOnly,
        description: "Team grouping inside an organization.",
    },
    Definition {
        class: "device_enrollment",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Device,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::IdsStatus,
        description: "Device enrollment attestation state. Revoked devices keep only tombstoned audit correlation.",
    },
    Definition {
        class: "device",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Device,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::IdsStatus,
        description: "Managed device capability and health metadata. IDs, capability, and status only.",
    },
    Definition {
        class: "workspace_binding",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Device,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::IdsStatus,
        description: "Device/workspace binding. Server-side authority for which project a device may act in.",
    },
    Definition {
        class: "provider",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Platform,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Sanitized,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Upstream provider configuration and status. Provider product/price IDs stay adapter-private.",
    },
    Definition {
        class: "model",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Platform,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Included,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Model catalog entry and capability flags.",
    },
    Definition {
        class: "model_route",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Organization,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Model alias to provider route. URL-embedded secrets are never stored or logged.",
    },
    Definition {
        class: "credential",
        sensitivity: Sensitivity::Restricted,
        owner_scope: OwnerScope::Organization,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::Revoke,
        logging: LoggingRule::IdsStatus,
        description: "Credential metadata only. The value itself is `secret` material; deletion revokes it.",
    },
    Definition {
        class: "policy_snapshot",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Organization,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Immutable versioned policy projection. Snapshot version is never inferred from a device.",
    },
    Definition {
        class: "policy_ack",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Device,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Device acknowledgement of a policy snapshot version.",
    },
    Definition {
        class: "tool_policy",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Organization,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "P05 tool/capability policy rules. Keys, version, and status only; no tool arguments.",
    },
    Definition {
        class: "inference_request",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Project,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::Minimize,
        logging: LoggingRule::StatusOnly,
        description: "Inference request metadata. Prompt/response bodies are never stored in this projection.",
    },
    Definition {
        class: "usage_event",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Project,
        retention: baseline(BaselineRetention::FinancialRecord),
        legal_maximum: FINANCIAL_CEILING,
        export: ExportBehavior::Included,
        deletion: DeletionBehavior::Minimize,
        logging: LoggingRule::StatusOnly,
        description: "Metered usage counts. Seven-year billing baseline, minimized rather than rewritten.",
    },
    Definition {
        class: "cost_record",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Organization,
        retention: baseline(BaselineRetention::FinancialRecord),
        legal_maximum: FINANCIAL_CEILING,
        export: ExportBehavior::Included,
        deletion: DeletionBehavior::Minimize,
        logging: LoggingRule::StatusOnly,
        description: "Cost and accounting record. History is immutable for audit; only personal content is minimized.",
    },
    Definition {
        class: "budget",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Project,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Included,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Budget limits and policy. A downgrade blocks new work and never deletes data.",
    },
    Definition {
        class: "rate_limit_policy",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Organization,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Included,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Rate-limit configuration. Counter rows are operational and bounded separately.",
    },
    Definition {
        class: "agent_definition",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Project,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Included,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::MetadataOnly,
        description: "Agent definition and configuration. No prompt, response, or raw tool argument is ever stored here.",
    },
    Definition {
        class: "agent_session",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Project,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Included,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::MetadataOnly,
        description: "Agent session metadata. Content references follow the content class retention, not this row.",
    },
    Definition {
        class: "run",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Project,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Included,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::MetadataOnly,
        description: "P05 run state. The only execution state machine; P06 adds correlation, not a parallel run.",
    },
    Definition {
        class: "run_event",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Project,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Included,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::MetadataOnly,
        description: "Append-only run timeline event with bounded payload metadata.",
    },
    Definition {
        class: "tool_call",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Project,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Tool call metadata and argument summary. Raw arguments are never exported or logged.",
    },
    Definition {
        class: "approval_request",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Project,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Human approval state bound to a tool argument fingerprint.",
    },
    Definition {
        class: "artifact_ref",
        sensitivity: Sensitivity::Restricted,
        owner_scope: OwnerScope::Project,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Sanitized,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Opaque reference to an object-backed artifact. References and checksums only.",
    },
    Definition {
        class: "artifact",
        sensitivity: Sensitivity::Restricted,
        owner_scope: OwnerScope::Project,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Sanitized,
        deletion: DeletionBehavior::PhysicalDelete,
        logging: LoggingRule::StatusOnly,
        description: "Object-backed artifact content. Deleting the row is insufficient; the object and derived copies go too.",
    },
    Definition {
        class: "audit_security_event",
        sensitivity: Sensitivity::Restricted,
        owner_scope: OwnerScope::Platform,
        retention: baseline(BaselineRetention::AuditSecurityEvent),
        legal_maximum: FINANCIAL_CEILING,
        export: ExportBehavior::Redacted,
        deletion: DeletionBehavior::RetainLegalOnly,
        logging: LoggingRule::IdsStatus,
        description: "Immutable audit/security history. Retained and tombstoned when legally required, never physically deleted.",
    },
    Definition {
        class: "outbox_event",
        sensitivity: Sensitivity::Internal,
        owner_scope: OwnerScope::Organization,
        retention: baseline(BaselineRetention::QueueJobProjection),
        legal_maximum: OPERATIONAL_CEILING,
        export: ExportBehavior::Never,
        deletion: DeletionBehavior::Tombstone,
        logging: LoggingRule::StatusOnly,
        description: "Business outbox row. Not user content; deleted or tombstoned after bounded delivery retention.",
    },
    Definition {
        class: "upstream_provider_data",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::External,
        retention: anchored(
            Anchor::LastObservation,
            RetentionDuration::from_days_unchecked(30),
        ),
        legal_maximum: SENSITIVE_CEILING,
        export: ExportBehavior::Sanitized,
        deletion: DeletionBehavior::RetainLegalOnly,
        logging: LoggingRule::StatusOnly,
        description: "Data held by an upstream AI provider. Lumi records status/reference only and never claims deletion.",
    },
    Definition {
        class: "secret",
        sensitivity: Sensitivity::Secret,
        owner_scope: OwnerScope::Organization,
        retention: RetentionWindow::Lifecycle,
        legal_maximum: RetentionWindow::Lifecycle,
        export: ExportBehavior::Never,
        deletion: DeletionBehavior::CryptoErase,
        logging: LoggingRule::None,
        description: "Secret and encrypted key material. Never exported, never logged, never included in an error.",
    },
    // ------------------------------------------------------- cross-cutting --
    Definition {
        class: "operational_log",
        sensitivity: Sensitivity::Confidential,
        owner_scope: OwnerScope::Platform,
        retention: baseline(BaselineRetention::OperationalLog),
        legal_maximum: SENSITIVE_CEILING,
        export: ExportBehavior::Never,
        deletion: DeletionBehavior::PhysicalDelete,
        logging: LoggingRule::MetadataOnly,
        description: "Operational log/trace line. 30 days; backups expire on the 35-day platform lifecycle.",
    },
];

/// Number of classes in the frozen table. Exposed so a coverage test can
/// assert the expected size without hard-coding it in two places.
pub const CLASS_COUNT: usize = DEFINITIONS.len();

/// Every registered class, in frozen declaration order.
///
/// The table is small and immutable, so it is rebuilt per call rather than
/// cached in process-global state: the Worker must not hold mutable or lazily
/// initialised global state across requests.
pub fn registry() -> Vec<DataClassRecord> {
    DEFINITIONS.iter().map(Definition::record).collect()
}

/// Every registered class key, in frozen declaration order.
pub fn all_classes() -> Vec<DataClass> {
    registry().into_iter().map(|record| record.class).collect()
}

/// Every registered class key as a set, for scope membership checks.
pub fn class_set() -> BTreeSet<DataClass> {
    all_classes().into_iter().collect()
}

/// Look up one class by key. Unknown keys return `None`; callers that require a
/// declaration should use [`lookup_by_key`], which fails closed.
pub fn lookup(class: &DataClass) -> Option<DataClassRecord> {
    DEFINITIONS
        .iter()
        .find(|definition| definition.class == class.as_str())
        .map(Definition::record)
}

/// Look up one class by wire key, failing closed on an undeclared class.
pub fn lookup_by_key(key: &str) -> Result<DataClassRecord, RegistryError> {
    let class = DataClass::parse(key)?;
    lookup(&class).ok_or(RegistryError::UndeclaredDataClass)
}

/// True when the key names a registered class.
pub fn is_registered(key: &str) -> bool {
    DataClass::parse(key).is_ok_and(|class| lookup(&class).is_some())
}

/// Every registered class a tenant deletion request can act on.
pub fn deletion_reachable_classes() -> Vec<DataClass> {
    registry()
        .into_iter()
        .filter(|record| {
            record.owner_scope.is_deletion_reachable() && record.deletion_behavior.is_actionable()
        })
        .map(|record| record.class)
        .collect()
}

/// Every registered class that may be named in an export manifest.
pub fn exportable_classes() -> Vec<DataClass> {
    registry()
        .into_iter()
        .filter(|record| record.is_exportable())
        .map(|record| record.class)
        .collect()
}

/// Registry validation failures. No variant carries the rejected value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RegistryError {
    /// A class key that is not bounded lowercase `snake_case`.
    InvalidDataClass,
    /// A class that does not declare every F20-001 attribute.
    IncompleteDeclaration,
    /// A well-formed key with no governance declaration.
    UndeclaredDataClass,
    /// Secret material that is exportable or not crypto-erased.
    SecretExportOrDeletion,
    /// Secret material with a logging rule that is not `none`.
    SecretLoggable,
    /// A non-Lumi-owned class claiming an Lumi deletion behavior.
    ExternalDataDeletable,
    /// A default retention longer than the class's own legal maximum.
    DefaultExceedsLegalMaximum,
}

impl RegistryError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidDataClass | Self::IncompleteDeclaration => "data_policy_invalid",
            Self::UndeclaredDataClass => "data_class_undeclared",
            Self::SecretExportOrDeletion | Self::SecretLoggable => "data_policy_invalid",
            Self::ExternalDataDeletable => "data_policy_invalid",
            Self::DefaultExceedsLegalMaximum => "data_policy_retention_over_legal_maximum",
        }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for RegistryError {}
