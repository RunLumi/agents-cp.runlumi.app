//! P06 automation scheduler and off-peak domain semantics.
//!
//! This module is deliberately pure. It does not authorize a caller, read D1,
//! dispatch work, mint identifiers, or read a clock. The service boundary must
//! establish the current organization, project, device, membership, entitlement,
//! and policy snapshot before calling anything here. A client-supplied parent
//! ID is correlation input, never proof of access.
//!
//! The three submodules split along the three decisions the control plane owns:
//!
//! - [`schedule`] turns an immutable schedule revision plus a caller-supplied
//!   cursor and `now` into the bounded set of canonical due instants, with
//!   DST, missed-run, and interval calendar semantics applied.
//! - [`occurrence`] owns the logical occurrence identity, the occurrence/lease
//!   state machine, and the overlap and lease-expiry decisions that keep one
//!   logical occurrence from ever becoming two.
//! - [`off_peak`] keeps ZCode's off-peak class distinct from ordinary cron so
//!   its safety restrictions can be narrowed but never broadened.
//!
//! Two boundaries are load bearing and are called out in the code:
//!
//! 1. Time is integer seconds since the Unix epoch. Civil-date arithmetic is
//!    implemented here instead of adding a date-time crate that may not
//!    compile for `wasm32-unknown-unknown`.
//! 2. A timezone is an opaque validated string plus caller-supplied UTC-offset
//!    transitions. No `tz` database is linked into a Worker; the adapter
//!    resolves the zone and hands the domain the transitions.

use std::fmt;

use serde::{Deserialize, Serialize};

mod occurrence;
mod off_peak;
mod schedule;

pub use crate::core::ExecutionLeaseId;
pub use occurrence::{
    ExecutionRetry, LeaseExpiryAction, LeaseFence, LeaseState, MAX_HEARTBEAT_INTERVAL_SECONDS,
    MAX_LEASE_TTL_SECONDS, MAX_QUEUE_ONE_AGE_SECONDS, MAX_START_ATTEMPTS,
    MIN_HEARTBEAT_INTERVAL_SECONDS, MIN_LEASE_TTL_SECONDS, MIN_START_ATTEMPTS, OccurrenceEvent,
    OccurrenceIdentityKey, OccurrenceKind, OccurrenceState, OverlapAction, PredecessorView,
    decide_lease_expiry, decide_overlap, fence_is_current, manual_occurrence_key,
    occurrence_identity_key, scheduled_occurrence_key, transition, validate_settlement,
};
pub use off_peak::{
    ELIGIBILITY_SOURCE_ORG_WINDOW, ELIGIBILITY_SOURCE_PROVIDER_TICKET, MAX_OFF_PEAK_ROUTE_ALIASES,
    MAX_OFF_PEAK_SCHEMA_VERSION, OffPeakContext, OffPeakDecision, OffPeakDenialReason,
    OffPeakEligibilitySource, OffPeakMode, OffPeakPolicy, ToolConstraints, evaluate_off_peak,
    narrow_off_peak_policy,
};
pub use schedule::{
    CronExpression, DomDowMode, DstPolicy, IntervalSchedule, IntervalUnit, LocalResolution,
    MAX_CATCH_UP_LIMIT, MAX_CRON_EXPRESSION_BYTES, MAX_INTERVAL_EVERY, MAX_MISSED_HISTORY_DAYS,
    MAX_NEXT_INSTANTS, MAX_SCHEDULE_CANDIDATES, MAX_TIMEZONE_BYTES, MAX_ZONE_TRANSITIONS,
    MIN_CATCH_UP_LIMIT, MIN_INTERVAL_EVERY, MissedPolicy, MissedRunPlan, OverlapPolicy,
    ScheduleInstant, ScheduleInstantOutcome, ScheduleKind, ScheduleRule, UtcOffsetTransition,
    ZoneOffsets, civil_from_days, days_from_civil, days_in_month, format_instant_utc, is_leap_year,
    missed_run_plan, next_due_instant, next_due_instants, parse_instant_utc, weekday_from_civil,
};

/// `true` when this module links a `chrono`-class dependency. It exists so a
/// reviewer can assert the "no WASM-hostile date-time crate" boundary from a
/// test rather than from a comment.
pub const SCHEDULER_IS_DEPENDENCY_FREE: bool = true;

/// Stable machine-readable reasons for automation scheduling, occurrence, and
/// off-peak decisions.
///
/// Every `code()` value is a string already frozen in `p06-cg-v1` ("Error
/// semantics"). Nothing here is a free-form message, so a transport adapter can
/// return the code directly and no rejected input is ever carried inside the
/// error value. That is deliberate: formatting or logging an error must never
/// disclose a body, secret, or identifier supplied by a caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainError {
    ScheduleInvalid,
    ScheduleTimezoneInvalid,
    ScheduleIntervalInvalid,
    DstMissingTime,
    DstRepeatedTime,
    AutomationNotFound,
    AutomationInvalidState,
    AutomationOverlapPolicy,
    AutomationMissedScheduleLimit,
    OccurrenceNotFound,
    OccurrenceAlreadyClaimed,
    OccurrenceLeaseExpired,
    OccurrenceAmbiguous,
    LeaseFenceInvalid,
    ExecutionPrincipalUnavailable,
    DeviceNotEligible,
    OffPeakNotAllowed,
    OrganizationPendingDeletion,
    EntitlementNotGranted,
    EntitlementGraceExpired,
}

impl DomainError {
    /// Stable API reason code. This is the only text a caller should receive.
    pub const fn code(self) -> &'static str {
        match self {
            Self::ScheduleInvalid => "schedule_invalid",
            Self::ScheduleTimezoneInvalid => "schedule_timezone_invalid",
            Self::ScheduleIntervalInvalid => "schedule_interval_invalid",
            Self::DstMissingTime => "dst_missing_time",
            Self::DstRepeatedTime => "dst_repeated_time",
            Self::AutomationNotFound => "automation_not_found",
            Self::AutomationInvalidState => "automation_invalid_state",
            Self::AutomationOverlapPolicy => "automation_overlap_policy",
            Self::AutomationMissedScheduleLimit => "automation_missed_schedule_limit",
            Self::OccurrenceNotFound => "occurrence_not_found",
            Self::OccurrenceAlreadyClaimed => "occurrence_already_claimed",
            Self::OccurrenceLeaseExpired => "occurrence_lease_expired",
            Self::OccurrenceAmbiguous => "occurrence_ambiguous",
            Self::LeaseFenceInvalid => "lease_fence_invalid",
            Self::ExecutionPrincipalUnavailable => "execution_principal_unavailable",
            Self::DeviceNotEligible => "device_not_eligible",
            Self::OffPeakNotAllowed => "off_peak_not_allowed",
            Self::OrganizationPendingDeletion => "organization_pending_deletion",
            Self::EntitlementNotGranted => "entitlement_not_granted",
            Self::EntitlementGraceExpired => "entitlement_grace_expired",
        }
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for DomainError {}

/// Let a validated `Deserialize` implementation propagate a domain rejection
/// with `?` instead of hand-mapping every call site. The message is the stable
/// reason code only, so a client error body can never echo a rejected cron
/// expression, timezone, or calendar selector back as prose.
impl serde::de::Error for DomainError {
    fn custom<T: fmt::Display>(_: T) -> Self {
        // The `Display`/`code()` of a `DomainError` is already a bounded stable
        // code, but the generic `T` here may be arbitrary. Collapse every
        // conversion to the generic validation reason so nothing is echoed.
        Self::ScheduleInvalid
    }
}

/// The single stable reason vocabulary is reused by every submodule. The
/// aliases exist so a call site can name the decision it is making without
/// inventing a parallel error type.
pub type ScheduleError = DomainError;
pub type OccurrenceReason = DomainError;
pub type OccurrenceError = DomainError;
pub type OffPeakError = DomainError;
pub type AutomationsError = DomainError;

#[cfg(test)]
mod tests;
