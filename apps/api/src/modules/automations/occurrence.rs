//! P06 logical occurrence identity, the occurrence/lease state machine, and the
//! overlap and lease-expiry decisions that keep ONE logical occurrence from ever
//! becoming two.
//!
//! WHY this module is pure: P06-CR-001 replaces the impossible "two devices can
//! never execute the same occurrence" promise with the boundary the Worker can
//! actually enforce — **at most one current server-authorized lease**. A lease
//! that is lost after execution may have begun cannot be proven safe, so the
//! occurrence becomes `ambiguous`, which is terminal and is NEVER automatically
//! re-dispatched. Only a provably-not-started lease may return to `pending`.
//!
//! Everything here is a total function of its arguments. The adapter supplies
//! the clock, the D1 row, and the device's presented fencing context; this module
//! decides, and the adapter performs the compare-and-set.
//!
//! # Identity
//!
//! The identity KEY is a canonical string, not a hash. Web Crypto is async and
//! unavailable to native domain tests, so the adapter hashes this key when it
//! needs a digest. Two occurrences collide only when the automation, the
//! immutable schedule revision, and the canonical UTC instant are all equal —
//! which is precisely the "one logical occurrence" rule.
//!
//! # Fencing
//!
//! A device that claimed attempt 1 must not be able to settle after the server
//! re-leased the occurrence to attempt 2. [`LeaseFence`] makes that structural:
//! a settlement is valid only when the presented lease ID, version, and fence
//! all match the current lease.

use serde::{Deserialize, Serialize};

use super::DomainError;
use crate::core::{ExecutionLeaseId, ScheduleRuleId};

/// Maximum number of times execution may be started for one occurrence.
pub const MIN_START_ATTEMPTS: u8 = 1;
pub const MAX_START_ATTEMPTS: u8 = 3;

/// Bounds on a lease's time-to-live and its heartbeat cadence.
pub const MIN_LEASE_TTL_SECONDS: u32 = 30;
pub const MAX_LEASE_TTL_SECONDS: u32 = 3600;
pub const MIN_HEARTBEAT_INTERVAL_SECONDS: u32 = 10;
pub const MAX_HEARTBEAT_INTERVAL_SECONDS: u32 = 60;

/// A `queue_one` successor that waits longer than this is skipped rather than
/// blocking its automation forever.
pub const MAX_QUEUE_ONE_AGE_SECONDS: i64 = 86_400;

/// The lifecycle state of a logical occurrence.
///
/// `Ambiguous` is the load-bearing state: it means the server lost authority
/// after execution may have begun, so it can neither be retried automatically
/// nor be treated as safe to overlap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OccurrenceState {
    Pending,
    Dispatching,
    Leased,
    Started,
    Succeeded,
    Failed,
    Cancelled,
    Missed,
    Skipped,
    Ambiguous,
}

impl OccurrenceState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Dispatching => "dispatching",
            Self::Leased => "leased",
            Self::Started => "started",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Missed => "missed",
            Self::Skipped => "skipped",
            Self::Ambiguous => "ambiguous",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "pending" => Self::Pending,
            "dispatching" => Self::Dispatching,
            "leased" => Self::Leased,
            "started" => Self::Started,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            "missed" => Self::Missed,
            "skipped" => Self::Skipped,
            "ambiguous" => Self::Ambiguous,
            _ => return None,
        })
    }

    /// Whether the occurrence has reached a state it can never leave.
    ///
    /// `ambiguous` IS terminal: P06-CR-001 forbids automatic re-dispatch, and
    /// the only exit is an audited operator reconciliation recorded outside this
    /// state machine.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Cancelled
                | Self::Missed
                | Self::Skipped
                | Self::Ambiguous
        )
    }

    /// Whether a device has begun executing, so a lost lease is unsafe to retry.
    pub const fn execution_may_have_begun(self) -> bool {
        matches!(self, Self::Started | Self::Ambiguous)
    }
}

/// The lifecycle of one execution lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    Active,
    Released,
    Expired,
    Revoked,
}

impl LeaseState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "active" => Self::Active,
            "released" => Self::Released,
            "expired" => Self::Expired,
            "revoked" => Self::Revoked,
            _ => return None,
        })
    }

    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Active)
    }
}

/// Whether an occurrence came from the schedule, a user action, or the
/// provider-ticket off-peak class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OccurrenceKind {
    Scheduled,
    Manual,
    OffPeak,
}

impl OccurrenceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Manual => "manual",
            Self::OffPeak => "off_peak",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "scheduled" => Self::Scheduled,
            "manual" => Self::Manual,
            "off_peak" => Self::OffPeak,
            _ => return None,
        })
    }
}

/// The inputs a caller must present to drive one occurrence transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OccurrenceEvent {
    /// The dispatcher selected the occurrence and is preparing a lease.
    Dispatch,
    /// A device atomically won the lease.
    Claimed,
    /// A device reported the lease alive.
    Renewed,
    /// The server durably created/discovered the P05 run link.
    Started,
    /// The host settled the run.
    Succeeded,
    /// The run failed.
    Failed,
    /// An operator or the owner cancelled it.
    Cancelled,
    /// The slot was inside the missed window and produced no occurrence.
    Missed,
    /// Overlap/missed policy deliberately produced no execution.
    Skipped(DomainError),
    /// The lease was lost. `proved_not_started` is the caller's proof that no
    /// run link exists, and it is the ONLY way to return to `pending`.
    LeaseLost { proved_not_started: bool },
    /// An audited reconciliation resolved an `ambiguous` occurrence.
    Reconciled { to: OccurrenceState },
}

/// Apply one transition to the frozen occurrence state machine.
///
/// The frozen transition table:
///
/// ```text
/// pending → dispatching → leased → started → succeeded
/// pending|dispatching|leased → skipped
/// pending|dispatching|leased|started → failed
/// pending|dispatching|leased|started → cancelled
/// pending|dispatching|leased → missed
/// leased → pending        (only when execution provably never started)
/// leased|started → ambiguous
/// ambiguous → no automatic re-dispatch
/// ```
pub fn transition(
    current: OccurrenceState,
    event: OccurrenceEvent,
) -> Result<OccurrenceState, DomainError> {
    // A terminal state accepts nothing except an audited reconciliation of an
    // ambiguous occurrence. Everything else is refused so a late redelivery
    // cannot rewrite settled history.
    if current.is_terminal() {
        return match (current, event) {
            (OccurrenceState::Ambiguous, OccurrenceEvent::Reconciled { to }) => Ok(to),
            _ => Err(DomainError::AutomationInvalidState),
        };
    }

    Ok(match (current, event) {
        (OccurrenceState::Pending, OccurrenceEvent::Dispatch) => OccurrenceState::Dispatching,
        (OccurrenceState::Pending, OccurrenceEvent::Skipped(_))
        | (OccurrenceState::Pending, OccurrenceEvent::Missed) => current,
        (OccurrenceState::Dispatching, OccurrenceEvent::Claimed) => OccurrenceState::Leased,
        (OccurrenceState::Dispatching, OccurrenceEvent::Skipped(_)) => OccurrenceState::Skipped,
        (OccurrenceState::Dispatching, OccurrenceEvent::Missed) => OccurrenceState::Missed,
        (OccurrenceState::Leased, OccurrenceEvent::Started) => OccurrenceState::Started,
        (OccurrenceState::Leased, OccurrenceEvent::Renewed) => current,
        (OccurrenceState::Leased, OccurrenceEvent::Skipped(_)) => OccurrenceState::Skipped,
        (OccurrenceState::Leased, OccurrenceEvent::Missed) => OccurrenceState::Missed,
        (OccurrenceState::Leased, OccurrenceEvent::Succeeded) => OccurrenceState::Succeeded,
        (OccurrenceState::Leased, OccurrenceEvent::Failed) => OccurrenceState::Failed,
        (OccurrenceState::Leased, OccurrenceEvent::Cancelled) => OccurrenceState::Cancelled,
        // P06-CR-001: only a PROVEN not-started lease may requeue. Anything
        // else is ambiguous and must never be handed to another device.
        (
            OccurrenceState::Leased,
            OccurrenceEvent::LeaseLost {
                proved_not_started: true,
            },
        ) => OccurrenceState::Pending,
        (
            OccurrenceState::Leased,
            OccurrenceEvent::LeaseLost {
                proved_not_started: false,
            },
        )
        | (OccurrenceState::Started, OccurrenceEvent::LeaseLost { .. }) => {
            OccurrenceState::Ambiguous
        }
        (OccurrenceState::Started, OccurrenceEvent::Succeeded) => OccurrenceState::Succeeded,
        (OccurrenceState::Started, OccurrenceEvent::Failed) => OccurrenceState::Failed,
        (OccurrenceState::Started, OccurrenceEvent::Cancelled) => OccurrenceState::Cancelled,
        _ => return Err(DomainError::AutomationInvalidState),
    })
}

/// The stable identity key for one logical occurrence.
///
/// Scheduled work is keyed by automation + IMMUTABLE schedule revision +
/// canonical UTC instant, matching the database's
/// `UNIQUE(automation_id, schedule_rule_id, scheduled_for_utc)`. An edit mints a
/// new revision, so an edit cannot silently collide with — or silently fork —
/// an existing slot.
pub fn scheduled_occurrence_key(
    automation_id: &str,
    schedule_rule_id: &ScheduleRuleId,
    scheduled_for_utc: &str,
) -> Result<String, DomainError> {
    if automation_id.is_empty() || scheduled_for_utc.is_empty() {
        return Err(DomainError::ScheduleInvalid);
    }
    Ok(format!(
        "scheduled:{}:{}:{}",
        automation_id,
        schedule_rule_id.as_str(),
        scheduled_for_utc
    ))
}

/// The stable identity key for a manual or provider-ticket off-peak run.
///
/// `trigger_key_digest` references the P01 idempotency record, never the raw
/// client key, so the idempotency secret is not persisted in the occurrence
/// projection.
pub fn manual_occurrence_key(
    automation_id: &str,
    trigger_key_digest: &str,
) -> Result<String, DomainError> {
    if automation_id.is_empty() || trigger_key_digest.is_empty() {
        return Err(DomainError::ScheduleInvalid);
    }
    Ok(format!("manual:{}:{}", automation_id, trigger_key_digest))
}

/// The parsed form of a stored identity key, used when the adapter must decide
/// whether an incoming occurrence is the one it already recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OccurrenceIdentityKey {
    pub kind: OccurrenceKind,
    pub automation_id: String,
    pub schedule_rule_id: Option<String>,
    pub scheduled_for_utc: Option<String>,
    pub trigger_key_digest: Option<String>,
}

/// Parse a key produced by [`scheduled_occurrence_key`] or
/// [`manual_occurrence_key`].
pub fn occurrence_identity_key(key: &str) -> Result<OccurrenceIdentityKey, DomainError> {
    let mut parts = key.splitn(3, ':');
    let kind = match parts.next() {
        Some("scheduled") => OccurrenceKind::Scheduled,
        Some("manual") => OccurrenceKind::Manual,
        _ => return Err(DomainError::ScheduleInvalid),
    };
    let automation_id = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or(DomainError::ScheduleInvalid)?
        .to_owned();
    let rest = parts.next().ok_or(DomainError::ScheduleInvalid)?;
    if kind == OccurrenceKind::Scheduled {
        let (rule, instant) = rest.split_once(':').ok_or(DomainError::ScheduleInvalid)?;
        Ok(OccurrenceIdentityKey {
            kind,
            automation_id,
            schedule_rule_id: Some(rule.to_owned()),
            scheduled_for_utc: Some(instant.to_owned()),
            trigger_key_digest: None,
        })
    } else {
        Ok(OccurrenceIdentityKey {
            kind,
            automation_id,
            schedule_rule_id: None,
            scheduled_for_utc: None,
            trigger_key_digest: Some(rest.to_owned()),
        })
    }
}

/// Monotonic fencing context for one lease attempt.
///
/// Every device-authoritative call presents all three parts. A device that lost
/// a renewal, or that is settling a superseded attempt, is rejected with
/// `lease_fence_invalid` instead of overwriting a newer state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseFence {
    pub lease_id: ExecutionLeaseId,
    pub version: i64,
    pub fence: i64,
}

impl LeaseFence {
    pub fn new(lease_id: ExecutionLeaseId, version: i64, fence: i64) -> Self {
        Self {
            lease_id,
            version,
            fence,
        }
    }
}

/// Whether a presented fence still matches the server's current lease.
///
/// A higher presented fence is just as invalid as a lower one: it means the
/// device is speaking for a lease the server no longer recognizes.
pub fn fence_is_current(presented: &LeaseFence, current: &LeaseFence) -> bool {
    presented.lease_id == current.lease_id
        && presented.version == current.version
        && presented.fence == current.fence
}

/// Validate a settlement against the current lease and occurrence state.
pub fn validate_settlement(
    occurrence: OccurrenceState,
    presented: &LeaseFence,
    current: &LeaseFence,
) -> Result<(), DomainError> {
    // Report the specific ambiguity reason BEFORE the generic terminal check:
    // `ambiguous` is terminal but has a distinct, more actionable stable code,
    // and a caller that only sees `automation_invalid_state` cannot tell a
    // settled success from an occurrence awaiting reconciliation.
    if occurrence == OccurrenceState::Ambiguous {
        return Err(DomainError::OccurrenceAmbiguous);
    }
    if occurrence.is_terminal() {
        return Err(DomainError::AutomationInvalidState);
    }
    if !fence_is_current(presented, current) {
        return Err(DomainError::LeaseFenceInvalid);
    }
    if !matches!(
        occurrence,
        OccurrenceState::Leased | OccurrenceState::Started
    ) {
        return Err(DomainError::AutomationInvalidState);
    }
    Ok(())
}

/// Bounded execution-retry settings carried on the automation definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRetry {
    pub max_start_attempts: u8,
    pub lease_ttl_seconds: u32,
    pub heartbeat_interval_seconds: u32,
}

impl ExecutionRetry {
    pub const fn new(
        max_start_attempts: u8,
        lease_ttl_seconds: u32,
        heartbeat_interval_seconds: u32,
    ) -> Self {
        Self {
            max_start_attempts,
            lease_ttl_seconds,
            heartbeat_interval_seconds,
        }
    }

    /// The frozen P06 defaults.
    pub const fn default_policy() -> Self {
        Self {
            max_start_attempts: 2,
            lease_ttl_seconds: 300,
            heartbeat_interval_seconds: 30,
        }
    }

    pub fn validate(self) -> Result<Self, DomainError> {
        if !(MIN_START_ATTEMPTS..=MAX_START_ATTEMPTS).contains(&self.max_start_attempts) {
            return Err(DomainError::AutomationInvalidState);
        }
        if !(MIN_LEASE_TTL_SECONDS..=MAX_LEASE_TTL_SECONDS).contains(&self.lease_ttl_seconds) {
            return Err(DomainError::AutomationInvalidState);
        }
        if !(MIN_HEARTBEAT_INTERVAL_SECONDS..=MAX_HEARTBEAT_INTERVAL_SECONDS)
            .contains(&self.heartbeat_interval_seconds)
        {
            return Err(DomainError::AutomationInvalidState);
        }
        if self.heartbeat_interval_seconds >= self.lease_ttl_seconds {
            return Err(DomainError::AutomationInvalidState);
        }
        Ok(self)
    }
}

/// What the expiry sweep must do with a lease that has run out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseExpiryAction {
    /// Provably never started: return the occurrence to `pending` so a device
    /// may claim it again, provided the attempt budget allows.
    Requeue,
    /// Execution may have begun: mark the occurrence `ambiguous`. This is
    /// terminal and is never handed to another device.
    MarkAmbiguous,
    /// The attempt budget is exhausted, so the occurrence fails rather than
    /// requeueing indefinitely.
    FailExhausted,
}

/// Decide what an expired lease means.
///
/// `run_link_exists` is the server's durable proof that a P05 run was created
/// for this attempt. It is the ONLY evidence that distinguishes a safe requeue
/// from an ambiguous result; wall-clock time and a missing heartbeat are not
/// proof, because a partitioned host may have executed a tool anyway.
pub fn decide_lease_expiry(
    occurrence: OccurrenceState,
    attempt: u8,
    retry: &ExecutionRetry,
    run_link_exists: bool,
) -> LeaseExpiryAction {
    if occurrence.execution_may_have_begun() || run_link_exists {
        return LeaseExpiryAction::MarkAmbiguous;
    }
    if attempt >= retry.max_start_attempts {
        return LeaseExpiryAction::FailExhausted;
    }
    LeaseExpiryAction::Requeue
}

/// What a newly due slot should do about the occurrence already running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverlapAction {
    /// Dispatch normally.
    Allow,
    /// Record a terminal `skipped` occurrence.
    Skip(DomainError),
    /// Hold at most one successor until the predecessor is terminal.
    QueueOne,
    /// Cancel the predecessor, but do NOT start the successor until the
    /// predecessor is terminal or an audited reconciliation resolves it.
    CancelPrevious,
}

/// The predecessor's state as the dispatcher sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PredecessorView {
    pub state: OccurrenceState,
    /// Seconds the successor has already waited under `queue_one`.
    pub queued_age_seconds: i64,
    pub now: i64,
}

/// Decide the overlap action for a newly due slot.
///
/// An `ambiguous` predecessor is NEVER treated as safe to overlap: the server
/// cannot prove the disconnected host stopped, so the successor waits.
pub fn decide_overlap(
    policy: super::schedule::OverlapPolicy,
    predecessor: Option<PredecessorView>,
    queued_successor_max_age_seconds: i64,
) -> OverlapAction {
    let Some(predecessor) = predecessor else {
        return OverlapAction::Allow;
    };
    // P06-CR-001 and the frozen gate: "an ambiguous predecessor is never treated
    // as safe to overlap". This is UNCONDITIONAL — including under the `allow`
    // policy, which governs the ordinary case where the server can see that a
    // predecessor is still running. `ambiguous` is different: the server cannot
    // prove a disconnected host stopped, so handing the slot to a second device
    // could duplicate side effects the first host already performed. The
    // successor therefore always takes the policy's own non-permissive action.
    if predecessor.state == OccurrenceState::Ambiguous {
        return match policy {
            super::schedule::OverlapPolicy::Allow
            | super::schedule::OverlapPolicy::CancelPrevious => OverlapAction::CancelPrevious,
            super::schedule::OverlapPolicy::Skip => {
                OverlapAction::Skip(DomainError::AutomationOverlapPolicy)
            }
            super::schedule::OverlapPolicy::QueueOne => {
                if predecessor.queued_age_seconds >= queued_successor_max_age_seconds
                    || queued_successor_max_age_seconds > MAX_QUEUE_ONE_AGE_SECONDS
                {
                    OverlapAction::Skip(DomainError::AutomationOverlapPolicy)
                } else {
                    OverlapAction::QueueOne
                }
            }
        };
    }
    if predecessor.state.is_terminal() {
        return OverlapAction::Allow;
    }
    match policy {
        super::schedule::OverlapPolicy::Allow => OverlapAction::Allow,
        super::schedule::OverlapPolicy::Skip => {
            OverlapAction::Skip(DomainError::AutomationOverlapPolicy)
        }
        super::schedule::OverlapPolicy::QueueOne => {
            if predecessor.queued_age_seconds >= queued_successor_max_age_seconds
                || queued_successor_max_age_seconds > MAX_QUEUE_ONE_AGE_SECONDS
            {
                // A successor must never block its automation forever.
                OverlapAction::Skip(DomainError::AutomationOverlapPolicy)
            } else {
                OverlapAction::QueueOne
            }
        }
        super::schedule::OverlapPolicy::CancelPrevious => OverlapAction::CancelPrevious,
    }
}
