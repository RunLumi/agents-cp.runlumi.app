//! P06 commercial entitlement, licensing, and subscription domain decisions.
//!
//! WHY this module is pure: `p06-cg-v1` and P06-CR-002 freeze a deterministic
//! precedence chain, bounded grace windows, and downgrade limits. Reproducing
//! those answers from a D1 read, a payment-provider call, or a device clock
//! would make the commercial decision path non-deterministic and untestable.
//! Everything below is therefore a total function of its arguments: the
//! persistence adapter, the `billing.sync` job consumer, and the device-policy
//! compiler all reach the same answer for the same authoritative facts.
//!
//! # Decision input separation
//!
//! P06-CG freezes four INDEPENDENT decision inputs. This module owns exactly
//! one of them and has no compile-time dependency on the other two owned
//! modules:
//!
//! | Decision input | Owner | This module |
//! |---|---|---|
//! | authorization permission | `modules::authorization` | never imports or reads it |
//! | Lumi product entitlement | this module | evaluated here |
//! | usage budget | `modules::budget_p05` | never imports or reads it |
//! | upstream provider account entitlement | `ProviderEntitlementProjection` | read-only status |
//!
//! `ProviderEntitlementProjection` carries no mutation API. It can gate or
//! degrade one provider route, and it can never produce an
//! [`EffectiveEntitlements`], a [`LicenseState`], or a subscription transition.
//!
//! # No provider product/price IDs
//!
//! Payment-provider product/price IDs are adapter-private (P06-CR-002). The
//! registry in [`keys`] only accepts lowercase dotted Lumi keys, and a plan
//! pointer only accepts a kebab-case Lumi key, so a provider identifier cannot
//! become a product concept even by accident. There is deliberately no
//! "provider price" field anywhere in this module.
//!
//! # Time
//!
//! All commercial arithmetic uses whole Unix seconds. [`Timestamp`] preserves
//! the exact wire text used for canonical signed bytes, but its lexicographic
//! ordering is not a valid instant ordering when precisions differ
//! (`...:00Z` vs `...:00.000Z`), so every comparison and every grace-window
//! computation goes through [`unix_seconds`].
//!
//! # Submodules
//!
//! - `keys`: stable Lumi entitlement key registry and typed bounded values.
//! - `evaluator`: effective-entitlement precedence and downgrade limits.
//! - `license`: `LicenseState` capability matrix and snapshot validation.
//! - `subscription`: subscription state machine, provider-event ledger, seats.

use std::fmt;

use crate::core::Timestamp;

mod evaluator;
mod keys;
mod license;
mod subscription;

#[cfg(test)]
mod tests;

pub use evaluator::{
    AuthoritativeCounts, DOWNGRADE_DELETES_DATA, EffectiveEntitlement, EffectiveEntitlements,
    EntitlementDecision, EntitlementDenial, EntitlementDenialReason, EntitlementGrant,
    EntitlementInputs, EntitlementResolution, GrantSource, MAX_OVERRIDE_REASON_BYTES,
    MutationBlock, OverLimitItem, OverLimitProjection, OverLimitRemediation,
    ProviderEntitlementProjection, ProviderEntitlementStatus, compute_over_limit_projection,
    organization_resolution, project_resolution, resolve_effective_entitlements,
};
pub use keys::{
    AUDIT_RETENTION_DAYS, AUTOMATIONS_MAX_ACTIVE, AUTOMATIONS_MAX_CONCURRENT,
    AUTOMATIONS_OFF_PEAK_ENABLED, BASELINE_ENTITLEMENT_KEY_COUNT, DATA_DELETION_SELF_SERVICE,
    DATA_EXPORT_ENABLED, DELETION_SELF_SERVICE, DEVICES_MAX_ENROLLED, EXPORTS_ENABLED,
    EntitlementDefinition, EntitlementKey, EntitlementScope, EntitlementValue,
    EntitlementValueType, INFERENCE_BYOK, INFERENCE_PLATFORM_MANAGED,
    MAX_BOUNDED_STRING_VALUE_BYTES, MAX_ENTITLEMENT_DESCRIPTION_BYTES, MAX_ENTITLEMENT_KEY_BYTES,
    MAX_ENTITLEMENT_KEY_SEGMENT_BYTES, MAX_ENTITLEMENT_KEY_SEGMENTS,
    MAX_ENTITLEMENT_SCOPE_ID_BYTES, MAX_ENTITLEMENT_UNIT_BYTES, MAX_ENTITLEMENT_VALUE_INTEGER,
    MIN_ENTITLEMENT_VALUE_INTEGER, NOTIFICATIONS_EMAIL_ENABLED, NOTIFICATIONS_IN_APP_ENABLED,
    ORG_MAX_MEMBERS, PROJECTS_MAX_ACTIVE, SCIM_ENABLED, SSO_ENABLED, WEBHOOKS_ENABLED,
    WEBHOOKS_MAX_ENDPOINTS, all_baseline_definitions, baseline_definition, baseline_value_type,
    is_baseline_key,
};
pub use license::{
    CLOUD_CONTROL_PLANE_GRACE_SECONDS, CapabilityClass, LICENSE_SNAPSHOT_SCHEMA_VERSION,
    LOCAL_ONLY_GRACE_SECONDS, LicenseDecision, LicenseEvaluationRequest, LicenseReason,
    LicenseSnapshotClaims, LicenseSnapshotContext, LicenseState, MAX_CLOCK_SKEW_SECONDS,
    MAX_LICENSE_AUDIENCE_BYTES, MAX_LICENSE_KEY_ID_BYTES, PLATFORM_PAID_INFERENCE_GRACE_SECONDS,
    ProviderAvailability, evaluate_license, evaluate_license_request, validate_license_snapshot,
};
pub use subscription::{
    BillableSeatState, BillingAccount, BillingSeatRow, GraceAnchor, GraceAnchorOutcome,
    GraceAnchorSource, GraceWindow, MAX_GRACE_WINDOW_SECONDS, MAX_LEDGER_EVENT_IDS,
    MAX_PLAN_KEY_BYTES, MAX_PROVIDER_EVENT_ID_BYTES, MAX_PROVIDER_EVENT_SKEW_SECONDS,
    MAX_PROVIDER_REFERENCE_BYTES, PlanChange, PlanPointer, ProviderEvent, ProviderEventLedger,
    ProviderEventOutcome, SeatCount, SeatPolicy, Subscription, SubscriptionStatus,
    SubscriptionTransition, apply_provider_event, billable_seat_count, is_lumi_plan_key,
};

/// Seconds in one calendar-independent day, used only for exact instant math.
pub const SECONDS_PER_DAY: i64 = 86_400;

/// Earliest instant this module will decode. The Unix epoch is the floor for
/// commercial state; a zero/absent time is never treated as "now".
pub const MIN_TIMESTAMP_UNIX_SECONDS: i64 = 0;

/// Latest instant this module will decode, pinned to `3000-01-01T00:00:00Z`.
/// A corrupt or absurd wire timestamp fails closed here instead of wrapping
/// through `i64` arithmetic and silently reordering decisions.
pub const MAX_TIMESTAMP_UNIX_SECONDS: i64 = 32_503_680_000;

/// Domain validation failures for the P06 commercial path.
///
/// `code()` returns a reason from the frozen P06-CG error list (or the P01
/// `validation_failed` / `version_conflict` / `resource_not_found` codes) so a
/// route handler never has to invent or parse a string. No variant carries the
/// rejected input, so formatting or logging an error cannot leak a provider
/// payload, a card reference, or a client snapshot body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntitlementError {
    /// An identifier did not match the frozen P06 `<prefix>_<32 hex>` shape.
    InvalidId,
    /// A key was not a lowercase dotted Lumi identifier.
    InvalidEntitlementKey,
    /// A key exceeded the bounded key length.
    EntitlementKeyTooLong,
    /// A key used more dotted segments than the registry allows.
    EntitlementKeyTooManySegments,
    /// A key is well formed but is not in the platform registry.
    UnknownEntitlementKey,
    /// A value could not be represented by the frozen value types.
    InvalidEntitlementValue,
    /// A bounded string value exceeded its ceiling.
    EntitlementValueTooLong,
    /// An integer value fell outside the bounded entitlement range.
    EntitlementValueOutOfRange,
    /// A value's type did not match the registered definition.
    EntitlementTypeMismatch,
    /// A scope identifier was empty, oversized, or contained control bytes.
    InvalidScopeId,
    /// A grant tried to widen a definition's scope instead of narrowing it.
    ScopeNotWithinDefinition,
    /// An internal override had no expiry, so it could become permanent.
    MissingOverrideExpiry,
    /// An internal override had no reason, so it could not be audited.
    MissingOverrideReason,
    /// A timestamp could not be decoded into the supported instant range.
    InvalidTimestampRange,
    /// An expiry was not strictly after its effective instant.
    InvalidPeriod,
    /// A grant or membership row belonged to another tenant.
    CrossTenantGrant,
    /// A grant was supplied through the wrong precedence slice.
    SourceScopeMismatch,
    /// A plan pointer did not use the kebab-case Lumi plan key shape.
    InvalidPlanKey,
    /// A provider event identifier or account reference was malformed.
    InvalidProviderReference,
    /// A provider event identifier had already been applied.
    ProviderEventReplay,
    /// A provider event was stale, future-dated, or behind the applied version.
    ProviderEventOutOfOrder,
    /// The subscription cannot make the requested transition.
    InvalidTransition,
    /// A cancelled subscription cannot silently reactivate.
    TerminalSubscription,
    /// The provider event was not bound to the expected adapter account.
    AccountBindingMismatch,
    /// A billing seat row could not be interpreted.
    InvalidMembershipState,
    /// A plan named the same billable seat state twice.
    DuplicateBillableState,
    /// A plan named more billable seat states than the registry allows.
    TooManyBillableStates,
    /// Seat accounting would overflow its bounded representation.
    SeatCountOverflow,
    /// A license snapshot claim set was malformed and grants nothing.
    InvalidClaims,
    /// An internal state change carried an effective time before the last one.
    StaleTransition,
    /// Grace state was entered without a bounded expiry.
    MissingGraceExpiry,
}

impl EntitlementError {
    /// Stable machine-readable reason from the frozen P06 error surface.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidId
            | Self::InvalidEntitlementKey
            | Self::EntitlementKeyTooLong
            | Self::EntitlementKeyTooManySegments
            | Self::InvalidEntitlementValue
            | Self::EntitlementValueTooLong
            | Self::EntitlementValueOutOfRange
            | Self::EntitlementTypeMismatch
            | Self::InvalidScopeId
            | Self::ScopeNotWithinDefinition
            | Self::MissingOverrideExpiry
            | Self::MissingOverrideReason
            | Self::InvalidTimestampRange
            | Self::InvalidPeriod
            | Self::SourceScopeMismatch
            | Self::InvalidPlanKey
            | Self::InvalidProviderReference
            | Self::InvalidMembershipState
            | Self::DuplicateBillableState
            | Self::TooManyBillableStates => "validation_failed",
            Self::UnknownEntitlementKey | Self::MissingGraceExpiry | Self::InvalidClaims => {
                "entitlement_not_granted"
            }
            Self::CrossTenantGrant | Self::AccountBindingMismatch => "resource_not_found",
            Self::ProviderEventReplay => "provider_event_replay",
            Self::ProviderEventOutOfOrder => "provider_event_out_of_order",
            Self::InvalidTransition | Self::TerminalSubscription => {
                "subscription_state_unavailable"
            }
            Self::SeatCountOverflow => "entitlement_limit_exceeded",
            Self::StaleTransition => "version_conflict",
        }
    }
}

impl fmt::Display for EntitlementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for EntitlementError {}

/// Decode an RFC 3339 UTC instant into whole Unix seconds.
///
/// Sub-second precision is truncated: every commercial decision in P06 is
/// expressed in whole seconds, and the exact wire text is preserved separately
/// for the canonical signed license bytes. A validated leap second (`:60`) maps
/// onto the same Unix second rather than onto the following minute.
pub fn unix_seconds(value: &Timestamp) -> Result<i64, EntitlementError> {
    let text = value.as_str().as_bytes();
    let year = decimal(text, 0, 4)?;
    let month = decimal(text, 5, 2)?;
    let day = decimal(text, 8, 2)?;
    let hour = decimal(text, 11, 2)?;
    let minute = decimal(text, 14, 2)?;
    let second = decimal(text, 17, 2)?.min(59);

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return Err(EntitlementError::InvalidTimestampRange);
    }

    let instant = days_from_civil(year, month, day)
        .checked_mul(SECONDS_PER_DAY)
        .and_then(|days| {
            days.checked_add(
                hour.checked_mul(3600)?
                    .checked_add(minute.checked_mul(60)?)?
                    .checked_add(second)?,
            )
        })
        .ok_or(EntitlementError::InvalidTimestampRange)?;

    if !(MIN_TIMESTAMP_UNIX_SECONDS..=MAX_TIMESTAMP_UNIX_SECONDS).contains(&instant) {
        return Err(EntitlementError::InvalidTimestampRange);
    }
    Ok(instant)
}

fn decimal(bytes: &[u8], start: usize, width: usize) -> Result<i64, EntitlementError> {
    let slice = bytes
        .get(start..start + width)
        .ok_or(EntitlementError::InvalidTimestampRange)?;
    if !slice.iter().all(u8::is_ascii_digit) {
        return Err(EntitlementError::InvalidTimestampRange);
    }
    Ok(slice
        .iter()
        .fold(0_i64, |value, digit| value * 10 + i64::from(digit - b'0')))
}

/// Days since `1970-01-01` for a proleptic Gregorian calendar date.
///
/// Pure arithmetic (no clock, no dependency, no I/O) so license and grace
/// arithmetic is byte-for-byte reproducible on the Worker WASM target.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let shifted_year = year - i64::from(month <= 2);
    let era = shifted_year.div_euclid(400);
    let year_of_era = shifted_year - era * 400;
    let month_shift = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_shift + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Typed P06 commercial identifiers come from [`crate::core::identifiers`],
/// the single canonical home for every typed resource ID in this Worker. The
/// frozen P06 prefixes (`plan_`, `bac_`, `pep_`, `sub_`, `ent_`, `egr_`,
/// `lic_`) are declared there, so a P05 `run_`/`rse_` or P02 `ses_` identifier
/// can never be passed to a commercial function and a payment-provider product
/// or price ID can never be spelled as one of these types.
///
/// They are re-exported here so a route or repository can use the commercial
/// identifiers without a second import path. The prefix is a wire namespace
/// only and is never an authorization signal.
pub use crate::core::{
    BillingAccountId, EntitlementDefinitionId, EntitlementGrantId, LicenseSnapshotId, PlanId,
    ProviderEntitlementProjectionId, SubscriptionId,
};

/// Bridge the core identifier validator into this module's error domain so a
/// malformed commercial ID is reported as the stable `entitlement_not_granted`
/// reason rather than leaking a `CoreError` string to a route handler.
impl From<crate::core::CoreError> for EntitlementError {
    fn from(_: crate::core::CoreError) -> Self {
        Self::InvalidId
    }
}
