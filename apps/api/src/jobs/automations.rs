//! P06 automation scheduler: due-occurrence generation, overlap resolution, and
//! the lease-expiry sweep.
//!
//! Everything that DECIDES lives in `modules::automations` and is re-exported
//! here unchanged. This file owns only the adapter concerns: reading current
//! state, bounding a pass, and assembling the D1 statements that commit a
//! decision together with its durable side effect.
//!
//! Three invariants the sweeps must preserve:
//!
//! 1. **The cursor is the authority.** A generation pass reads
//!    `schedule_cursor_at`, plans the bounded window, and
//!    advances the cursor in the SAME batch as the occurrences it creates. A
//!    second concurrent pass loses the cursor compare-and-set and commits
//!    nothing, so a redelivery or a device reconnect can never fork a second
//!    logical occurrence.
//! 2. **An ambiguous predecessor blocks.** `decide_overlap` is consulted on
//!    every slot, and its `ambiguous` branch is unconditional.
//! 3. **Only proven-not-started work requeues.** A post-start lease loss is
//!    `ambiguous` and is never handed to another device.

use serde_json::{Value, json};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::Timestamp,
    modules::automations::{
        DomainError, ExecutionRetry, LeaseExpiryAction, MissedPolicy, OccurrenceEvent,
        OccurrenceKind, OccurrenceState, PredecessorView, ScheduleInstant, ScheduleInstantOutcome,
        ScheduleRule, ZoneOffsets, format_instant_utc, next_due_instant, next_due_instants,
        parse_instant_utc, transition,
    },
    repositories::{
        AUTOMATION_EVENT_TYPES, AutomationDefinitionRecord, AutomationOccurrenceRecord,
        AutomationStoreError, AutomationsRepository, DispatchEligibility, DueOccurrenceRecord,
        EVENT_OCCURRENCE_AMBIGUOUS, EVENT_OCCURRENCE_DISPATCHED, EVENT_OCCURRENCE_FAILED,
        EVENT_OCCURRENCE_LEASE_EXPIRED, EVENT_OCCURRENCE_SKIPPED, ExecutionLeaseRecord, JobType,
        NewAttemptInput, NewOccurrenceInput, NewQueueJobInput, OccurrenceTransition,
        OutboxRepository, StoredScheduleRevision, WebhookRepository, is_guard_violation,
        missed_target_state, predecessor_view, skip_target_state,
    },
};

/// Maximum automations one generation pass may advance.
pub const MAX_SCHEDULER_AUTOMATIONS: i32 = 50;
/// Maximum leases one expiry invocation may resolve. A sweep is a bounded unit
/// of work so a scheduled handler cannot spin.
pub const MAX_LEASE_EXPIRY_BATCH: i32 = 50;
/// Maximum occurrences a single generation pass may create.
pub const MAX_GENERATED_OCCURRENCES: usize = 20;
/// Maximum page size for a browser occurrence-history request.
pub const MAX_OCCURRENCE_PAGE: i32 = 100;
/// Maximum items a device due-work response may carry.
pub const MAX_DUE_OCCURRENCES: i32 = 20;
/// The `QueueJobEnvelope` job-lease duration. A consumer that crashes after
/// claiming leaves the job recoverable by this bound.
pub const JOB_LEASE_SECONDS: i64 = 120;
/// The frozen entitlement key that bounds active automations per organization.
pub const ENTITLEMENT_MAX_ACTIVE_AUTOMATIONS: &str = "automations.max_active";
/// Stable, bounded reasons this adapter records on a lease transition. They are
/// frozen codes, never caller text.
pub const REASON_LEASE_EXPIRED_PRE_START: &str = "lease_expired_pre_start";
pub const REASON_LEASE_EXPIRED_AFTER_START: &str = "lease_expired_after_start";
pub const REASON_LEASE_EXPIRED_RETRY_EXHAUSTED: &str = "lease_expired_retry_exhausted";
pub const REASON_CANCEL_PREVIOUS: &str = "cancel_previous";

/// A bounded outcome of one sweep. Counts are the only values a diagnostic
/// needs; no identifier, prompt, or token is ever formatted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SchedulerReport {
    pub automations_examined: usize,
    pub occurrences_created: usize,
    pub occurrences_skipped: usize,
    pub windows_truncated: usize,
    pub leases_expired: usize,
    pub leases_requeued: usize,
    pub leases_ambiguous: usize,
    pub leases_failed: usize,
    pub jobs_enqueued: usize,
    pub duplicates_ignored: usize,
}

impl SchedulerReport {
    pub fn merge(&mut self, other: SchedulerReport) {
        self.automations_examined += other.automations_examined;
        self.occurrences_created += other.occurrences_created;
        self.occurrences_skipped += other.occurrences_skipped;
        self.windows_truncated += other.windows_truncated;
        self.leases_expired += other.leases_expired;
        self.leases_requeued += other.leases_requeued;
        self.leases_ambiguous += other.leases_ambiguous;
        self.leases_failed += other.leases_failed;
        self.jobs_enqueued += other.jobs_enqueued;
        self.duplicates_ignored += other.duplicates_ignored;
    }
}

/// Why an occurrence is not claimable right now, before the overlap policy is
/// even consulted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchBlock {
    /// Current organization, membership, entitlement, or license state forbids
    /// new work.
    Authorization(DomainError),
    /// A stable code from the frozen P01/P06 vocabulary that the domain reason
    /// list does not model.
    Reason(&'static str),
}

impl DispatchBlock {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Authorization(error) => error.code(),
            Self::Reason(code) => code,
        }
    }
}

/// A planned occurrence: what the domain decided, before D1 knows about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedOccurrence {
    pub scheduled_for_utc: String,
    pub outcome: OccurrencePlanOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OccurrencePlanOutcome {
    /// Create a claimable occurrence.
    Dispatchable,
    /// Persist the slot directly in its terminal state with this stable reason.
    Skipped(&'static str),
}

/// What the dispatcher should do with one persisted occurrence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DispatchPlan {
    /// Move the occurrence to `dispatching` so a device may claim it.
    Dispatch,
    /// Hold it as a `queue_one` successor behind this predecessor.
    QueueOne { predecessor_id: String },
    /// Record a terminal `skipped` occurrence with this stable reason.
    Skip(&'static str),
    /// Cancel the predecessor and keep the successor queued behind it.
    CancelPrevious { predecessor_id: String },
    /// Blocked by current organization, membership, entitlement, or policy
    /// state; record a terminal `skipped` occurrence with this stable reason.
    Blocked(&'static str),
    /// The slot passed its bounded missed window without becoming dispatchable.
    /// The occurrence is recorded as `missed` so the gap is visible and
    /// deterministic instead of silently disappearing.
    Missed,
}

// -----------------------------------------------------------------------------
// Pure planning
// -----------------------------------------------------------------------------

/// A bounded generation plan for one automation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationPlan {
    /// Slots to persist, ascending by canonical UTC instant. A deliberate skip is
    /// already in its terminal form; a due slot becomes a claimable occurrence.
    pub instants: Vec<ScheduleInstant>,
    /// The authoritative cursor to persist atomically with `instants`. Always the
    /// supplied `now`: planning has considered every slot up to it.
    pub cursor_after: i64,
    /// `true` when the seven-day history window clamped the scan, when the
    /// `catch_up_limit` dropped older due slots, or when the adapter's step budget
    /// ran out. The caller surfaces it as `automation_missed_schedule_limit`.
    pub truncated: bool,
    /// How many due slots the window contained, including any the policy dropped.
    pub missed_slots: usize,
}

/// Upper bound on the slots one generation pass may enumerate. The domain's own
/// missed-history window and cron search budget are the real bounds; this keeps
/// the adapter's own bookkeeping finite as well.
pub const MAX_WINDOW_INSTANTS: usize = 64;

/// Plan every slot between the authoritative cursor and `now`.
///
/// # Why the adapter enumerates instead of calling `missed_run_plan`
///
/// `modules::automations::missed_run_plan` coalesces a ring while scanning
/// FORWARD from the cursor and never stops at `now`, so for a bounded past window
/// it returns the last slot it scanned — for a daily cron that is years in the
/// future. Persisting that would mint an occurrence scheduled decades ahead, and
/// filtering it afterwards would silently drop a genuinely due slot.
///
/// The adapter therefore drives the domain's own bounded primitive,
/// [`next_due_instants`], over `(cursor, now]` and applies the policy the rule
/// already carries ([`ScheduleRule::missed_policy`] and
/// [`ScheduleRule::catch_up_limit`]). Every per-slot decision — cron matching,
/// interval calendar arithmetic, DST skips and repeats, and their stable reasons —
/// still comes from `modules::automations`; only the bounded selection of which
/// enumerated slots to keep lives here. This is flagged to P06-MOD-01 as a domain
/// defect.
pub fn plan_due_occurrences(
    rule: &ScheduleRule,
    zone: &ZoneOffsets,
    cursor_epoch_seconds: i64,
    now_epoch_seconds: i64,
) -> Result<GenerationPlan, DomainError> {
    if now_epoch_seconds < cursor_epoch_seconds {
        // A regressed cursor or clock is not a decision the adapter may guess at.
        return Err(DomainError::ScheduleInvalid);
    }
    if !rule.produces_scheduled_instants() {
        return Ok(GenerationPlan {
            instants: Vec::new(),
            cursor_after: now_epoch_seconds,
            truncated: false,
            missed_slots: 0,
        });
    }
    let window_start = now_epoch_seconds
        .saturating_sub(crate::modules::automations::MAX_MISSED_HISTORY_DAYS * 86_400);
    let mut truncated = cursor_epoch_seconds < window_start;
    let mut instants: Vec<ScheduleInstant> = Vec::new();
    let mut step = cursor_epoch_seconds;
    loop {
        let batch = next_due_instants(
            rule,
            zone,
            step,
            crate::modules::automations::MAX_NEXT_INSTANTS,
        )?;
        let Some(last) = batch.last().copied() else {
            break;
        };
        let mut advanced = false;
        for instant in batch {
            if instant.scheduled_for_utc > now_epoch_seconds {
                break;
            }
            if instants.len() == MAX_WINDOW_INSTANTS {
                truncated = true;
                break;
            }
            instants.push(instant);
            advanced = true;
        }
        if !advanced || last.scheduled_for_utc <= step {
            // The window is exhausted, or the rule produced nothing new.
            break;
        }
        step = last.scheduled_for_utc;
        if last.scheduled_for_utc >= now_epoch_seconds {
            break;
        }
    }

    let due: Vec<ScheduleInstant> = instants
        .iter()
        .copied()
        .filter(ScheduleInstant::is_due)
        .collect();
    let missed_slots = due.len();
    // `skip` produces no occurrence. A DST-skipped slot is an explicit decision
    // about a slot that exists, so it is always recorded.
    let keep = match rule.missed_policy() {
        MissedPolicy::Skip => 0,
        MissedPolicy::RunOnce => 1,
        MissedPolicy::CatchUp => usize::from(
            rule.catch_up_limit()
                .unwrap_or(crate::modules::automations::MAX_CATCH_UP_LIMIT)
                .clamp(
                    crate::modules::automations::MIN_CATCH_UP_LIMIT,
                    crate::modules::automations::MAX_CATCH_UP_LIMIT,
                ),
        ),
    };
    if missed_slots > keep {
        truncated = true;
    }
    let coalesced = if due.len() > keep {
        &due[due.len() - keep..]
    } else {
        &due[..]
    };
    let mut selected: Vec<ScheduleInstant> = instants
        .iter()
        .copied()
        .filter(|instant| !instant.is_due())
        .chain(coalesced.iter().copied())
        .collect();
    selected.sort_by_key(|instant| instant.scheduled_for_utc);
    selected.truncate(MAX_WINDOW_INSTANTS);
    Ok(GenerationPlan {
        instants: selected,
        cursor_after: now_epoch_seconds,
        truncated,
        missed_slots,
    })
}

/// The first instant strictly after `now`, used to set `next_run_at` when a
/// definition is created or a schedule revision is minted.
pub fn plan_next_run(
    rule: &ScheduleRule,
    zone: &ZoneOffsets,
    now_epoch_seconds: i64,
) -> Result<Option<String>, DomainError> {
    if !rule.produces_scheduled_instants() {
        return Ok(None);
    }
    Ok(next_due_instant(rule, zone, now_epoch_seconds)?
        .and_then(|instant| instant.scheduled_for().ok()))
}

/// Project a plan into the rows the caller will persist. Slots the domain
/// deliberately skipped are persisted directly in their terminal state: they
/// never occupy a non-terminal state, so no state-machine transition is possible
/// or needed for them.
pub fn project_plan(plan: &GenerationPlan) -> Result<Vec<PlannedOccurrence>, DomainError> {
    plan.instants
        .iter()
        .map(|instant| {
            Ok(PlannedOccurrence {
                scheduled_for_utc: instant.scheduled_for()?,
                outcome: match instant.outcome {
                    ScheduleInstantOutcome::Due => OccurrencePlanOutcome::Dispatchable,
                    ScheduleInstantOutcome::Skipped(reason) => {
                        OccurrencePlanOutcome::Skipped(reason.code())
                    }
                },
            })
        })
        .collect()
}

/// The dispatch-time recheck. Values captured when the schedule was created are
/// never authority: the caller re-reads organization state, principal
/// membership, the published policy version, the license state, and the
/// effective `automations.max_active` entitlement, and every answer must be
/// current at the moment of the decision.
pub fn dispatch_block(
    automation: &AutomationDefinitionRecord,
    eligibility: &DispatchEligibility,
) -> Option<DispatchBlock> {
    match eligibility.organization_state.as_deref() {
        Some("active") => {}
        Some("pending_deletion") => {
            return Some(DispatchBlock::Authorization(
                DomainError::OrganizationPendingDeletion,
            ));
        }
        Some(_) => return Some(DispatchBlock::Reason("organization_suspended")),
        None => return Some(DispatchBlock::Reason("organization_not_found")),
    }
    if !eligibility.principal_membership_active {
        return Some(DispatchBlock::Authorization(
            DomainError::ExecutionPrincipalUnavailable,
        ));
    }
    if let Some(required) = automation.required_policy_version
        && eligibility.current_policy_version < required
    {
        return Some(DispatchBlock::Reason("policy_snapshot_stale"));
    }
    // A protected capability fails closed: a missing license projection denies
    // new managed work rather than assuming an active subscription.
    let within_grace = || {
        eligibility
            .license_grace_expires_at
            .as_deref()
            .zip(eligibility.now.as_deref())
            .and_then(|(grace, now)| {
                parse_instant_utc(grace)
                    .ok()
                    .zip(parse_instant_utc(now).ok())
            })
            .is_some_and(|(grace, now)| grace > now)
    };
    match eligibility.license_state.as_deref() {
        Some("active") => {}
        Some("grace") if within_grace() => {}
        Some("grace") => {
            return Some(DispatchBlock::Authorization(
                DomainError::EntitlementGraceExpired,
            ));
        }
        Some(_) => {
            return Some(DispatchBlock::Authorization(
                DomainError::EntitlementNotGranted,
            ));
        }
        None => {
            return Some(DispatchBlock::Authorization(
                DomainError::EntitlementNotGranted,
            ));
        }
    }
    match eligibility.max_active_automations {
        Some(limit) if eligibility.active_automation_count > limit => {
            Some(DispatchBlock::Reason("entitlement_limit_exceeded"))
        }
        Some(_) => None,
        None => Some(DispatchBlock::Authorization(
            DomainError::EntitlementNotGranted,
        )),
    }
}

/// Whether a `pending` occurrence has passed the bounded missed window and can
/// no longer be dispatched.
///
/// The window is the domain's own seven-day missed-history bound: after it, a
/// slot is not evidence that the schedule still exists, so the occurrence is
/// recorded as `missed` rather than dispatched much later. This keeps a missed
/// schedule deterministic and visible instead of an unbounded backlog.
pub fn plan_missed_window(occurrence: &AutomationOccurrenceRecord, now_epoch_seconds: i64) -> bool {
    occurrence
        .scheduled_for_utc
        .as_deref()
        .and_then(|value| parse_instant_utc(value).ok())
        .is_some_and(|slot| {
            now_epoch_seconds.saturating_sub(slot)
                >= crate::modules::automations::MAX_MISSED_HISTORY_DAYS * 86_400
        })
}

/// Decide the overlap action for one slot, consulting the frozen domain
/// decision without re-implementing it.
///
/// The policy lives on the IMMUTABLE schedule revision, not on the mutable
/// definition, so a policy change is a new revision and a new logical slot.
pub fn plan_overlap(
    rule: &ScheduleRule,
    queued_successor_max_age_seconds: i64,
    predecessor: Option<&AutomationOccurrenceRecord>,
    existing_successor: Option<&AutomationOccurrenceRecord>,
    now_epoch_seconds: i64,
) -> Result<DispatchPlan, DomainError> {
    let policy = rule.overlap_policy();
    // A queued successor that reached its bounded age is skipped rather than
    // blocking its automation forever. The bound is checked before the policy so
    // `cancel_previous` cannot keep a successor queued forever either.
    if let Some(successor) = existing_successor
        && let Some(queued_at) = successor.queued_at.as_deref()
        && let Ok(queued_epoch) = parse_instant_utc(queued_at)
        && now_epoch_seconds.saturating_sub(queued_epoch) >= queued_successor_max_age_seconds
    {
        return Ok(DispatchPlan::Skip(
            DomainError::AutomationOverlapPolicy.code(),
        ));
    }
    // `queue_one` allows at most ONE open successor.
    if matches!(policy, crate::modules::automations::OverlapPolicy::QueueOne)
        && existing_successor.is_some()
    {
        return Ok(DispatchPlan::Skip(
            DomainError::AutomationOverlapPolicy.code(),
        ));
    }
    let view: Option<PredecessorView> = match predecessor {
        Some(predecessor) => Some(predecessor_view(predecessor, now_epoch_seconds)?),
        None => None,
    };
    let predecessor_id = predecessor
        .map(|record| record.occurrence_id.clone())
        .unwrap_or_default();
    Ok(
        match crate::modules::automations::decide_overlap(
            policy,
            view,
            queued_successor_max_age_seconds,
        ) {
            crate::modules::automations::OverlapAction::Allow => DispatchPlan::Dispatch,
            crate::modules::automations::OverlapAction::Skip(reason) => {
                DispatchPlan::Skip(reason.code())
            }
            crate::modules::automations::OverlapAction::QueueOne => {
                DispatchPlan::QueueOne { predecessor_id }
            }
            crate::modules::automations::OverlapAction::CancelPrevious => {
                DispatchPlan::CancelPrevious { predecessor_id }
            }
        },
    )
}

/// What the sweep must do with one expired lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseExpiryPlan {
    /// Provably never started: the occurrence returns to `pending` and a new
    /// dispatch job is enqueued, bounded by `max_start_attempts`.
    Requeue { attempt: i64 },
    /// Execution may have begun: the occurrence becomes `ambiguous` and is never
    /// handed to another device.
    MarkAmbiguous,
    /// The attempt budget is exhausted, so the occurrence fails.
    FailExhausted,
}

/// Resolve one expired lease with the frozen domain decision.
///
/// `run_link_exists` is the server's durable proof that a P05 run was created for
/// this attempt. It is the ONLY evidence that distinguishes a safe requeue from
/// an ambiguous result; a missing heartbeat is not proof, because a partitioned
/// host may have executed a tool anyway.
pub fn plan_lease_expiry(
    occurrence: &AutomationOccurrenceRecord,
    retry: &ExecutionRetry,
    run_link_exists: bool,
) -> Result<LeaseExpiryPlan, DomainError> {
    let state = occurrence.state()?;
    let attempt =
        u8::try_from(occurrence.attempt).map_err(|_| DomainError::AutomationInvalidState)?;
    Ok(
        match crate::modules::automations::decide_lease_expiry(
            state,
            attempt,
            retry,
            run_link_exists,
        ) {
            LeaseExpiryAction::Requeue => LeaseExpiryPlan::Requeue {
                attempt: i64::from(attempt) + 1,
            },
            LeaseExpiryAction::MarkAmbiguous => LeaseExpiryPlan::MarkAmbiguous,
            LeaseExpiryAction::FailExhausted => LeaseExpiryPlan::FailExhausted,
        },
    )
}

/// The frozen `automation.occurrence.*` event name for an occurrence state that
/// the dispatcher itself moved. `leased` is deliberately absent: a claim has no
/// frozen event name and is recorded as attempt history plus an F16 audit row.
pub fn occurrence_event_type(state: &str) -> Option<&'static str> {
    Some(match state {
        "dispatching" => EVENT_OCCURRENCE_DISPATCHED,
        "started" => crate::repositories::EVENT_OCCURRENCE_STARTED,
        "succeeded" => crate::repositories::EVENT_OCCURRENCE_COMPLETED,
        "failed" => EVENT_OCCURRENCE_FAILED,
        "skipped" => EVENT_OCCURRENCE_SKIPPED,
        "missed" => crate::repositories::EVENT_OCCURRENCE_MISSED,
        _ => return None,
    })
}

// -----------------------------------------------------------------------------
// Identifiers
// -----------------------------------------------------------------------------

/// A deterministic occurrence ID for a scheduled slot. The slot identity is the
/// `(automation, schedule revision, canonical UTC instant)` triple, so a
/// redelivered generation pass derives the same ID instead of a second row.
pub fn deterministic_occurrence_id(
    automation_id: &str,
    schedule_rule_id: &str,
    scheduled_for_utc: &str,
) -> String {
    let digest = stable_digest(&format!(
        "scheduled:{automation_id}:{schedule_rule_id}:{scheduled_for_utc}"
    ));
    format!("occ_{digest}")
}

/// The manual counterpart. The digest component is the P01 idempotency key
/// digest, never the raw client key.
pub fn deterministic_manual_occurrence_id(automation_id: &str, trigger_key_digest: &str) -> String {
    let digest = stable_digest(&format!("manual:{automation_id}:{trigger_key_digest}"));
    format!("occ_{digest}")
}

/// A deterministic job ID for a logical job generation. The queue message
/// carries the same value, so a redelivered envelope maps to the same row.
pub fn deterministic_job_id(job_type: &str, subject_id: &str, generation: i64) -> String {
    let digest = stable_digest(&format!("{job_type}:{subject_id}:{generation}"));
    format!("job_{digest}")
}

/// A small, non-cryptographic digest used only to derive a deterministic
/// resource ID from a canonical identity string. It is not a security boundary:
/// the real uniqueness boundary is the D1 unique index on the identity columns,
/// and the lease token's fingerprint is a separate SHA-256.
fn stable_digest(value: &str) -> String {
    // FNV-1a (64-bit) over the even and odd byte positions, folded into 32
    // lowercase hex characters. No dependency, no randomness, stable across runs.
    let mut low = 0xcbf2_9ce4_8422_2325_u64;
    let mut high = 0x9e37_79b9_7f4a_7c15_u64;
    for (index, byte) in value.as_bytes().iter().enumerate() {
        if index % 2 == 0 {
            low ^= u64::from(*byte);
            low = low.wrapping_mul(0x0000_0100_0000_01b3);
        } else {
            high ^= u64::from(*byte);
            high = high.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    format!("{low:016x}{high:016x}")
}

// -----------------------------------------------------------------------------
// Outbox
// -----------------------------------------------------------------------------

/// The frozen occurrence lifecycle insert. The payload carries the required
/// identifiers and bounded metadata only: no prompt, response, raw tool
/// argument, credential, or unbounded URL can reach it.
#[allow(clippy::too_many_arguments)]
pub fn occurrence_outbox_statement(
    database: &D1Adapter,
    event_type: &str,
    org_id: &str,
    project_id: Option<&str>,
    occurrence_id: &str,
    automation_id: &str,
    attempt: i64,
    resource_version: i64,
    state: &str,
    reason_code: &str,
    run_id: Option<&str>,
    now: &Timestamp,
) -> Result<D1PreparedStatement, AutomationStoreError> {
    if !AUTOMATION_EVENT_TYPES.contains(&event_type) {
        return Err(AutomationStoreError::InvalidRow);
    }
    let request_id = crate::core::RequestId::new(format!("req_{}", stable_digest(occurrence_id)))
        .map_err(|_| AutomationStoreError::InvalidRow)?;
    let event = crate::core::EventEnvelope {
        event_id: crate::adapters::new_event_id(),
        event_type: crate::core::EventType::new(event_type)
            .map_err(|_| AutomationStoreError::InvalidRow)?,
        occurred_at: now.clone(),
        request_id: request_id.clone(),
        correlation_id: crate::core::CorrelationId::new(request_id.as_str())
            .map_err(|_| AutomationStoreError::InvalidRow)?,
        actor: crate::core::ActorContext::anonymous(),
        organization_id: Some(
            crate::core::OrganizationId::new(org_id)
                .map_err(|_| AutomationStoreError::InvalidRow)?,
        ),
        payload: occurrence_event_payload(
            occurrence_id,
            automation_id,
            project_id,
            attempt,
            resource_version,
            state,
            reason_code,
            run_id,
        ),
    };
    OutboxRepository::new(database)
        .insert_statement(&event)
        .map_err(|_| AutomationStoreError::Unavailable)
}

#[allow(clippy::too_many_arguments)]
fn occurrence_event_payload(
    occurrence_id: &str,
    automation_id: &str,
    project_id: Option<&str>,
    attempt: i64,
    resource_version: i64,
    state: &str,
    reason_code: &str,
    run_id: Option<&str>,
) -> Value {
    json!({
        "schema_version": 1,
        "subject_type": "automation_occurrence",
        "subject_id": occurrence_id,
        "occurrence_id": occurrence_id,
        "automation_id": automation_id,
        "project_id": project_id,
        "attempt": attempt,
        "state": state,
        "resource_version": resource_version,
        "run_id": run_id,
        "reason_code": if reason_code.is_empty() {
            Value::Null
        } else {
            json!(reason_code)
        },
    })
}

// -----------------------------------------------------------------------------
// Generation sweep
// -----------------------------------------------------------------------------

/// Advance due automations by one bounded generation pass.
///
/// For each selected automation the pass plans the bounded missed window, builds
/// the occurrence rows, and appends the cursor compare-and-set, the dispatch job
/// envelope, and the occurrence lifecycle events. A batch that a cursor guard
/// refuses is reported as a duplicate and never partially applied, because D1
/// rolls the whole batch back.
pub async fn run_due_occurrence_sweep(
    database: &D1Adapter,
    now: &Timestamp,
    limit: i32,
) -> Result<SchedulerReport, AutomationStoreError> {
    let repository = AutomationsRepository::new(database);
    let limit = limit.clamp(1, MAX_SCHEDULER_AUTOMATIONS);
    let automations = repository
        .list_due_automations(now.as_str(), limit)
        .await
        .map_err(|_| AutomationStoreError::Unavailable)?;
    let mut report = SchedulerReport {
        automations_examined: automations.len(),
        ..SchedulerReport::default()
    };
    for automation in &automations {
        if report.occurrences_created >= MAX_GENERATED_OCCURRENCES {
            break;
        }
        match generate_for_automation(database, automation, now).await {
            Ok(single) => report.merge(single),
            Err(AutomationStoreError::Guarded) => report.duplicates_ignored += 1,
            Err(error) => return Err(error),
        }
    }
    Ok(report)
}

async fn generate_for_automation(
    database: &D1Adapter,
    automation: &AutomationDefinitionRecord,
    now: &Timestamp,
) -> Result<SchedulerReport, AutomationStoreError> {
    let repository = AutomationsRepository::new(database);
    let revision = load_revision(&repository, automation).await?;
    let now_epoch = epoch(now)?;
    // The authoritative cursor. A definition that has never generated work starts
    // its window at the current instant, so creation cannot back-fill history.
    let cursor_text = automation.schedule_cursor_at.clone().unwrap_or_else(|| {
        format_instant_utc(now_epoch).unwrap_or_else(|_| now.as_str().to_owned())
    });
    let cursor_epoch = parse_instant_utc(&cursor_text).unwrap_or(now_epoch);
    let plan = plan_due_occurrences(&revision.rule, &revision.zone, cursor_epoch, now_epoch)
        .map_err(|_| AutomationStoreError::InvalidRow)?;
    let planned = project_plan(&plan).map_err(|_| AutomationStoreError::InvalidRow)?;
    let next_run = plan_next_run(&revision.rule, &revision.zone, plan.cursor_after)
        .map_err(|_| AutomationStoreError::InvalidRow)?;
    let last_run = planned
        .iter()
        .rev()
        .find(|slot| slot.outcome == OccurrencePlanOutcome::Dispatchable)
        .map(|slot| slot.scheduled_for_utc.clone());
    let new_cursor =
        format_instant_utc(plan.cursor_after).map_err(|_| AutomationStoreError::InvalidRow)?;

    let mut statements: Vec<D1PreparedStatement> = Vec::with_capacity(planned.len() * 2 + 2);
    // The cursor guard is first, so a concurrent pass commits nothing at all.
    statements.push(
        repository
            .assert_schedule_cursor_statement(
                &automation.automation_id,
                &automation.org_id,
                &cursor_text,
            )
            .map_err(|_| AutomationStoreError::Unavailable)?,
    );
    let mut created = 0_usize;
    let mut skipped = 0_usize;
    for slot in &planned {
        let occurrence_id = deterministic_occurrence_id(
            &automation.automation_id,
            &automation.schedule_rule_id,
            &slot.scheduled_for_utc,
        );
        let (state, reason_code) = match slot.outcome {
            OccurrencePlanOutcome::Dispatchable => ("pending", None),
            OccurrencePlanOutcome::Skipped(reason) => ("skipped", Some(reason)),
        };
        statements.push(
            repository
                .insert_occurrence_statement(&NewOccurrenceInput {
                    occurrence_id: &occurrence_id,
                    automation_id: &automation.automation_id,
                    org_id: &automation.org_id,
                    project_id: automation.project_id.as_deref(),
                    schedule_rule_id: &automation.schedule_rule_id,
                    kind: OccurrenceKind::Scheduled.as_str(),
                    scheduled_for_utc: Some(&slot.scheduled_for_utc),
                    trigger_key_digest: None,
                    execution_principal_kind: &automation.execution_principal_kind,
                    execution_principal_id: &automation.execution_principal_id,
                    off_peak_mode: "normal",
                    policy_snapshot_id: None,
                    policy_version: None,
                    state,
                    attempt: 0,
                    reason_code,
                    blocked_by_occurrence_id: None,
                    queued_at: None,
                    now,
                })
                .map_err(|_| AutomationStoreError::Unavailable)?,
        );
        match slot.outcome {
            OccurrencePlanOutcome::Dispatchable => {
                created += 1;
                statements.push(
                    dispatch_job_statement(
                        database,
                        automation,
                        &occurrence_id,
                        automation.version,
                        0,
                        now,
                    )
                    .map_err(|_| AutomationStoreError::Unavailable)?,
                );
            }
            OccurrencePlanOutcome::Skipped(reason) => {
                skipped += 1;
                statements.push(
                    occurrence_outbox_statement(
                        database,
                        EVENT_OCCURRENCE_SKIPPED,
                        &automation.org_id,
                        automation.project_id.as_deref(),
                        &occurrence_id,
                        &automation.automation_id,
                        0,
                        1,
                        "skipped",
                        reason,
                        None,
                        now,
                    )
                    .map_err(|_| AutomationStoreError::Unavailable)?,
                );
            }
        }
    }
    statements.push(
        repository
            .advance_schedule_cursor_statement(
                &automation.automation_id,
                &automation.org_id,
                &new_cursor,
                next_run.as_deref(),
                last_run.as_deref(),
                now,
                &cursor_text,
            )
            .map_err(|_| AutomationStoreError::Unavailable)?,
    );
    match database.batch(statements).await {
        Ok(_) => Ok(SchedulerReport {
            occurrences_created: created,
            occurrences_skipped: skipped,
            windows_truncated: usize::from(plan.truncated),
            jobs_enqueued: created,
            ..SchedulerReport::default()
        }),
        Err(error) if is_guard_violation(&error) => Ok(SchedulerReport {
            duplicates_ignored: 1,
            ..SchedulerReport::default()
        }),
        Err(_) => Err(AutomationStoreError::Unavailable),
    }
}

/// Load and rehydrate a definition's immutable schedule revision.
pub async fn load_revision(
    repository: &AutomationsRepository<'_>,
    automation: &AutomationDefinitionRecord,
) -> Result<StoredScheduleRevision, AutomationStoreError> {
    let row = repository
        .find_schedule_rule(&automation.org_id, &automation.schedule_rule_id)
        .await
        .map_err(|_| AutomationStoreError::Unavailable)?
        .ok_or(AutomationStoreError::InvalidRow)?;
    StoredScheduleRevision::from_canonical_json(&row.canonical_json)
        .map_err(|_| AutomationStoreError::InvalidRow)
}

/// Enqueue the bounded dispatch job for one occurrence. The dedupe key is the
/// occurrence plus its generation, so a redelivery cannot enqueue the same
/// logical dispatch twice while a genuine retry generation still can.
pub fn dispatch_job_statement(
    database: &D1Adapter,
    automation: &AutomationDefinitionRecord,
    occurrence_id: &str,
    subject_version: i64,
    generation: i64,
    now: &Timestamp,
) -> Result<D1PreparedStatement, AutomationStoreError> {
    let job_id = deterministic_job_id(JobType::Dispatch.as_str(), occurrence_id, generation);
    let dedupe_key = format!(
        "{}:{occurrence_id}:{generation}",
        JobType::Dispatch.as_str()
    );
    // `INSERT OR IGNORE` is the D1 half of the dedupe contract: the unique
    // `(job_type, org, dedupe_key, generation)` index rejects a duplicate
    // logical job, so a redelivery cannot enqueue the same work twice while a
    // genuine retry generation still can.
    WebhookRepository::new(database)
        .insert_queue_job_statement(&NewQueueJobInput {
            job_id: &job_id,
            job_type: JobType::Dispatch,
            org_id: Some(&automation.org_id),
            subject_type: "automation_occurrence",
            subject_id: occurrence_id,
            subject_version: Some(subject_version),
            dedupe_key: &dedupe_key,
            event_id: None,
            request_id: None,
            correlation_id: None,
            payload_ref: Some(&format!("d1:automation_occurrences/{occurrence_id}")),
            next_attempt_at: Some(now.as_str()),
            replay_of_job_id: None,
            generation,
            now,
        })
        .map_err(|_| AutomationStoreError::Unavailable)
}

// -----------------------------------------------------------------------------
// Dispatch-time eligibility
// -----------------------------------------------------------------------------

/// Re-read the dispatch-time facts for one automation. Nothing here trusts a
/// value captured when the schedule was created.
pub async fn read_dispatch_eligibility(
    database: &D1Adapter,
    automation: &AutomationDefinitionRecord,
    now: &Timestamp,
) -> Result<DispatchEligibility, AutomationStoreError> {
    let repository = AutomationsRepository::new(database);
    let organizations = crate::repositories::OrganizationRepository::new(database);
    let organization_state = organizations
        .find_organization(&automation.org_id)
        .await
        .map_err(|_| AutomationStoreError::Unavailable)?
        .map(|organization| organization.state);
    let principal_membership_active = repository
        .principal_membership_active(&automation.org_id, &automation.execution_principal_id)
        .await
        .map_err(|_| AutomationStoreError::Unavailable)?;
    let current_policy_version = repository
        .current_policy_version(&automation.org_id)
        .await
        .map_err(|_| AutomationStoreError::Unavailable)?;
    let (license_state, license_grace_expires_at) = match repository
        .license_state(&automation.org_id)
        .await
        .map_err(|_| AutomationStoreError::Unavailable)?
    {
        Some((state, grace)) => (Some(state), grace),
        None => (None, None),
    };
    let max_active_automations = repository
        .effective_integer_entitlement(
            &automation.org_id,
            ENTITLEMENT_MAX_ACTIVE_AUTOMATIONS,
            now.as_str(),
        )
        .await
        .map_err(|_| AutomationStoreError::Unavailable)?;
    let active_automation_count = repository
        .active_automation_count(&automation.org_id)
        .await
        .map_err(|_| AutomationStoreError::Unavailable)?;
    Ok(DispatchEligibility {
        organization_state,
        principal_membership_active,
        current_policy_version,
        license_state,
        license_grace_expires_at,
        max_active_automations,
        active_automation_count,
        now: Some(now.as_str().to_owned()),
    })
}

/// Decide what the dispatcher should do with one persisted occurrence.
///
/// The order is deliberate: a slot that already passed its bounded missed window
/// becomes `missed` first, then the dispatch-time recheck blocks new work, then
/// the overlap policy is consulted. Every answer comes from the frozen domain.
pub async fn resolve_dispatch_plan(
    repository: &AutomationsRepository<'_>,
    automation: &AutomationDefinitionRecord,
    occurrence: &AutomationOccurrenceRecord,
    revision: &StoredScheduleRevision,
    eligibility: &DispatchEligibility,
    now: &Timestamp,
) -> Result<DispatchPlan, AutomationStoreError> {
    let now_epoch = epoch(now)?;
    let state = occurrence
        .state()
        .map_err(|_| AutomationStoreError::InvalidRow)?;
    if state == OccurrenceState::Pending && plan_missed_window(occurrence, now_epoch) {
        return Ok(DispatchPlan::Missed);
    }
    if let Some(block) = dispatch_block(automation, eligibility) {
        return Ok(DispatchPlan::Blocked(block.code()));
    }
    let predecessor = repository
        .find_predecessor(&occurrence.automation_id, &occurrence.occurrence_id)
        .await
        .map_err(|_| AutomationStoreError::Unavailable)?;
    let successor = repository
        .find_open_queued_successor(&occurrence.automation_id, &occurrence.occurrence_id)
        .await
        .map_err(|_| AutomationStoreError::Unavailable)?;
    plan_overlap(
        &revision.rule,
        automation.queued_successor_max_age_seconds(),
        predecessor.as_ref(),
        successor.as_ref(),
        now_epoch,
    )
    .map_err(|_| AutomationStoreError::InvalidRow)
}

/// Build the statements that move one persisted occurrence to `dispatching`, or
/// record the terminal state the decision produced. Every statement is bound to
/// the occurrence's current `state_version`, and the dispatch-time recheck
/// commits in the same batch, so a dispatch can never commit against state the
/// caller read earlier.
pub async fn dispatch_occurrence_statements(
    database: &D1Adapter,
    repository: &AutomationsRepository<'_>,
    automation: &AutomationDefinitionRecord,
    occurrence: &AutomationOccurrenceRecord,
    plan: DispatchPlan,
    eligibility: &DispatchEligibility,
    now: &Timestamp,
) -> Result<Vec<D1PreparedStatement>, AutomationStoreError> {
    let current = occurrence
        .state()
        .map_err(|_| AutomationStoreError::InvalidRow)?;
    let mut statements = vec![
        repository
            .assert_occurrence_state_statement(
                &occurrence.occurrence_id,
                &occurrence.org_id,
                current.as_str(),
                occurrence.state_version,
            )
            .map_err(|_| AutomationStoreError::Unavailable)?,
    ];
    if let Some(license_state) = eligibility.license_state.as_deref() {
        statements.push(
            repository
                .assert_dispatch_eligible_statement(
                    &occurrence.org_id,
                    &occurrence.execution_principal_id,
                    now.as_str(),
                    license_state,
                )
                .map_err(|_| AutomationStoreError::Unavailable)?,
        );
    }

    let effective = match plan {
        DispatchPlan::Dispatch => match dispatch_block(automation, eligibility) {
            Some(block) => DispatchPlan::Blocked(block.code()),
            None => DispatchPlan::Dispatch,
        },
        other => other,
    };

    match effective {
        DispatchPlan::Dispatch => {
            let next = transition(current, OccurrenceEvent::Dispatch)
                .map_err(|_| AutomationStoreError::InvalidRow)?;
            statements.push(occurrence_transition(
                repository, occurrence, next, None, None, None, None, now,
            )?);
            statements.push(occurrence_lifecycle_event(
                database, automation, occurrence, next, None, None, now,
            )?);
        }
        DispatchPlan::QueueOne { predecessor_id } => {
            // The successor waits without becoming claimable: it keeps `pending`
            // with a bounded `queued_at` and the blocking predecessor recorded.
            statements.push(occurrence_transition(
                repository,
                occurrence,
                OccurrenceState::Pending,
                None,
                None,
                Some(now.as_str()),
                Some(predecessor_id.as_str()),
                now,
            )?);
        }
        DispatchPlan::CancelPrevious { predecessor_id } => {
            if !predecessor_id.is_empty() {
                statements.push(cancel_predecessor_statement(
                    database,
                    automation,
                    &predecessor_id,
                    now,
                )?);
            }
            // The successor stays queued until the predecessor is terminal or an
            // audited reconciliation resolves `ambiguous`.
            statements.push(occurrence_transition(
                repository,
                occurrence,
                OccurrenceState::Pending,
                None,
                None,
                Some(now.as_str()),
                Some(predecessor_id.as_str()),
                now,
            )?);
        }
        DispatchPlan::Skip(reason) | DispatchPlan::Blocked(reason) => {
            let next = skip_target_state(current).map_err(|_| AutomationStoreError::InvalidRow)?;
            statements.push(occurrence_transition(
                repository,
                occurrence,
                next,
                Some(reason),
                None,
                None,
                None,
                now,
            )?);
            statements.push(occurrence_lifecycle_event(
                database,
                automation,
                occurrence,
                next,
                Some(reason),
                None,
                now,
            )?);
        }
        DispatchPlan::Missed => {
            let next =
                missed_target_state(current).map_err(|_| AutomationStoreError::InvalidRow)?;
            statements.push(occurrence_transition(
                repository,
                occurrence,
                next,
                Some(DomainError::AutomationMissedScheduleLimit.code()),
                None,
                None,
                None,
                now,
            )?);
            statements.push(occurrence_lifecycle_event(
                database,
                automation,
                occurrence,
                next,
                Some(DomainError::AutomationMissedScheduleLimit.code()),
                None,
                now,
            )?);
        }
    }
    Ok(statements)
}

/// `cancel_previous` records the cancellation reason on the predecessor in the
/// same batch that queues the successor, so a cancellation is never an
/// unexplained state change.
fn cancel_predecessor_statement(
    database: &D1Adapter,
    automation: &AutomationDefinitionRecord,
    predecessor_id: &str,
    now: &Timestamp,
) -> Result<D1PreparedStatement, AutomationStoreError> {
    const CANCEL_PREDECESSOR_SQL: &str = r#"
UPDATE automation_occurrences
SET state = 'cancelled',
    reason_code = ?3,
    state_version = state_version + 1,
    finished_at = ?4,
    updated_at = ?4
WHERE occurrence_id = ?1 AND automation_id = ?2
  AND state IN ('pending', 'dispatching', 'leased', 'started')
"#;
    database
        .prepare(
            CANCEL_PREDECESSOR_SQL,
            &[
                BindValue::Text(predecessor_id),
                BindValue::Text(&automation.automation_id),
                BindValue::Text(REASON_CANCEL_PREVIOUS),
                BindValue::Text(now.as_str()),
            ],
        )
        .map_err(|_| AutomationStoreError::Unavailable)
}

#[allow(clippy::too_many_arguments)]
fn occurrence_transition(
    repository: &AutomationsRepository<'_>,
    occurrence: &AutomationOccurrenceRecord,
    next: OccurrenceState,
    reason_code: Option<&str>,
    run_id: Option<&str>,
    queued_at: Option<&str>,
    blocked_by: Option<&str>,
    now: &Timestamp,
) -> Result<D1PreparedStatement, AutomationStoreError> {
    let finished_at = next.is_terminal().then_some(now.as_str());
    let started_at = (next == OccurrenceState::Started).then_some(now.as_str());
    repository
        .transition_occurrence_statement(&OccurrenceTransition {
            occurrence_id: &occurrence.occurrence_id,
            org_id: &occurrence.org_id,
            next_state: next.as_str(),
            reason_code,
            run_id,
            lease_expires_at: None,
            queued_at,
            blocked_by_occurrence_id: blocked_by,
            started_at,
            finished_at,
            now,
            expected_state: occurrence.state.as_str(),
            expected_state_version: occurrence.state_version,
        })
        .map_err(|_| AutomationStoreError::Unavailable)
}

fn occurrence_lifecycle_event(
    database: &D1Adapter,
    automation: &AutomationDefinitionRecord,
    occurrence: &AutomationOccurrenceRecord,
    next: OccurrenceState,
    reason_code: Option<&str>,
    run_id: Option<&str>,
    now: &Timestamp,
) -> Result<D1PreparedStatement, AutomationStoreError> {
    let event_type =
        occurrence_event_type(next.as_str()).ok_or(AutomationStoreError::InvalidRow)?;
    occurrence_outbox_statement(
        database,
        event_type,
        &automation.org_id,
        automation.project_id.as_deref(),
        &occurrence.occurrence_id,
        &occurrence.automation_id,
        occurrence.attempt,
        occurrence.state_version + 1,
        next.as_str(),
        reason_code.unwrap_or(""),
        run_id,
        now,
    )
}

// -----------------------------------------------------------------------------
// Lease-expiry sweep
// -----------------------------------------------------------------------------

/// Run the bounded lease-expiry sweep. Each resolved lease commits its lease
/// state, occurrence transition, attempt history, and lifecycle events in one
/// batch. An `ambiguous` outcome is terminal by construction: no dispatch job is
/// enqueued for it.
pub async fn run_lease_expiry_sweep(
    database: &D1Adapter,
    now: &Timestamp,
    limit: i32,
) -> Result<SchedulerReport, AutomationStoreError> {
    let repository = AutomationsRepository::new(database);
    let limit = limit.clamp(1, MAX_LEASE_EXPIRY_BATCH);
    let leases = repository
        .list_expired_leases(now.as_str(), limit)
        .await
        .map_err(|_| AutomationStoreError::Unavailable)?;
    let mut report = SchedulerReport::default();
    for lease in &leases {
        let Some(occurrence) = repository
            .find_occurrence(&lease.org_id, &lease.occurrence_id)
            .await
            .map_err(|_| AutomationStoreError::Unavailable)?
        else {
            report.duplicates_ignored += 1;
            continue;
        };
        let Some(automation) = repository
            .find_automation(&occurrence.org_id, &occurrence.automation_id)
            .await
            .map_err(|_| AutomationStoreError::Unavailable)?
        else {
            report.duplicates_ignored += 1;
            continue;
        };
        let Ok(retry) = automation.execution_retry() else {
            return Err(AutomationStoreError::InvalidRow);
        };
        let run_link_exists = repository
            .run_link_exists(&occurrence.occurrence_id, lease.attempt)
            .await
            .map_err(|_| AutomationStoreError::Unavailable)?;
        let plan = plan_lease_expiry(&occurrence, &retry, run_link_exists)
            .map_err(|_| AutomationStoreError::InvalidRow)?;
        report.merge(
            expire_lease(
                database,
                &repository,
                &automation,
                &occurrence,
                lease,
                plan,
                now,
            )
            .await?,
        );
    }
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
async fn expire_lease(
    database: &D1Adapter,
    repository: &AutomationsRepository<'_>,
    automation: &AutomationDefinitionRecord,
    occurrence: &AutomationOccurrenceRecord,
    lease: &ExecutionLeaseRecord,
    plan: LeaseExpiryPlan,
    now: &Timestamp,
) -> Result<SchedulerReport, AutomationStoreError> {
    let current = occurrence
        .state()
        .map_err(|_| AutomationStoreError::InvalidRow)?;
    let (next, reason_code, requeue) = match plan {
        LeaseExpiryPlan::Requeue { .. } => (
            transition(
                current,
                OccurrenceEvent::LeaseLost {
                    proved_not_started: true,
                },
            )
            .map_err(|_| AutomationStoreError::InvalidRow)?,
            Some(REASON_LEASE_EXPIRED_PRE_START),
            Some(plan),
        ),
        LeaseExpiryPlan::MarkAmbiguous => (
            transition(
                current,
                OccurrenceEvent::LeaseLost {
                    proved_not_started: false,
                },
            )
            .map_err(|_| AutomationStoreError::InvalidRow)?,
            Some(REASON_LEASE_EXPIRED_AFTER_START),
            None,
        ),
        LeaseExpiryPlan::FailExhausted => (
            transition(current, OccurrenceEvent::Failed)
                .map_err(|_| AutomationStoreError::InvalidRow)?,
            Some(REASON_LEASE_EXPIRED_RETRY_EXHAUSTED),
            None,
        ),
    };
    let mut statements = vec![
        repository
            .assert_lease_current_statement(
                &lease.lease_id,
                &occurrence.occurrence_id,
                &lease.org_id,
                "active",
                lease.lease_version,
                lease.lease_fence,
            )
            .map_err(|_| AutomationStoreError::Unavailable)?,
        repository
            .assert_occurrence_state_statement(
                &occurrence.occurrence_id,
                &occurrence.org_id,
                current.as_str(),
                occurrence.state_version,
            )
            .map_err(|_| AutomationStoreError::Unavailable)?,
        repository
            .close_lease_statement(
                &lease.lease_id,
                &occurrence.occurrence_id,
                &lease.org_id,
                "expired",
                now.as_str(),
                lease.lease_version,
                lease.lease_fence,
            )
            .map_err(|_| AutomationStoreError::Unavailable)?,
        occurrence_transition(
            repository,
            occurrence,
            next,
            reason_code,
            None,
            None,
            None,
            now,
        )?,
        repository
            .insert_attempt_statement(&NewAttemptInput {
                attempt_id: &deterministic_job_id("attempt", &lease.lease_id, lease.attempt),
                occurrence_id: &occurrence.occurrence_id,
                lease_id: Some(&lease.lease_id),
                attempt: lease.attempt,
                outcome: "expired",
                run_id: None,
                reason_code,
                lease_version: Some(lease.lease_version),
                lease_fence: Some(lease.lease_fence),
                recorded_at: now.as_str(),
            })
            .map_err(|_| AutomationStoreError::Unavailable)?,
        occurrence_outbox_statement(
            database,
            EVENT_OCCURRENCE_LEASE_EXPIRED,
            &automation.org_id,
            automation.project_id.as_deref(),
            &occurrence.occurrence_id,
            &occurrence.automation_id,
            occurrence.attempt,
            occurrence.state_version + 1,
            next.as_str(),
            reason_code.unwrap_or(""),
            occurrence.run_id.as_deref(),
            now,
        )
        .map_err(|_| AutomationStoreError::Unavailable)?,
    ];
    if next == OccurrenceState::Ambiguous {
        // `ambiguous` is terminal and is never handed to another device. The
        // only exit is an audited reconciliation outside this state machine.
        statements.push(
            occurrence_outbox_statement(
                database,
                EVENT_OCCURRENCE_AMBIGUOUS,
                &automation.org_id,
                automation.project_id.as_deref(),
                &occurrence.occurrence_id,
                &occurrence.automation_id,
                occurrence.attempt,
                occurrence.state_version + 1,
                OccurrenceState::Ambiguous.as_str(),
                reason_code.unwrap_or(""),
                occurrence.run_id.as_deref(),
                now,
            )
            .map_err(|_| AutomationStoreError::Unavailable)?,
        );
        statements.push(
            repository
                .insert_attempt_statement(&NewAttemptInput {
                    attempt_id: &deterministic_job_id("ambiguous", &lease.lease_id, lease.attempt),
                    occurrence_id: &occurrence.occurrence_id,
                    lease_id: Some(&lease.lease_id),
                    attempt: lease.attempt,
                    outcome: "ambiguous",
                    run_id: occurrence.run_id.as_deref(),
                    reason_code,
                    lease_version: Some(lease.lease_version),
                    lease_fence: Some(lease.lease_fence),
                    recorded_at: now.as_str(),
                })
                .map_err(|_| AutomationStoreError::Unavailable)?,
        );
    }
    if let Some(LeaseExpiryPlan::Requeue { attempt }) = requeue {
        statements.push(dispatch_job_statement(
            database,
            automation,
            &occurrence.occurrence_id,
            occurrence.state_version + 1,
            attempt,
            now,
        )?);
    }
    match database.batch(statements).await {
        Ok(_) => Ok(SchedulerReport {
            leases_expired: 1,
            leases_requeued: usize::from(requeue.is_some()),
            leases_ambiguous: usize::from(next == OccurrenceState::Ambiguous),
            leases_failed: usize::from(next == OccurrenceState::Failed),
            jobs_enqueued: usize::from(requeue.is_some()),
            ..SchedulerReport::default()
        }),
        Err(error) if is_guard_violation(&error) => Ok(SchedulerReport {
            duplicates_ignored: 1,
            ..SchedulerReport::default()
        }),
        Err(_) => Err(AutomationStoreError::Unavailable),
    }
}

// -----------------------------------------------------------------------------
// Device projections
// -----------------------------------------------------------------------------

/// The device due-work projection. A device learns the minimum it needs to
/// claim; authoritative execution context comes from the `start` call.
pub fn due_projection(due: &DueOccurrenceRecord) -> Value {
    json!({
        "occurrence_id": due.occurrence_id,
        "automation_id": due.automation_id,
        "project_id": due.project_id,
        "schedule_rule_id": due.schedule_rule_id,
        "kind": due.kind,
        "off_peak_mode": due.off_peak_mode,
        "policy_snapshot_id": due.policy_snapshot_id,
        "policy_version": due.policy_version,
        "attempt": due.attempt,
        "scheduled_for_utc": due.scheduled_for_utc,
        "state": due.state,
        "lease_ttl_seconds": due.lease_ttl_seconds,
        "heartbeat_interval_seconds": due.heartbeat_interval_seconds,
        "required_capabilities": safe_string_list(&due.required_capabilities_json),
        "execution_policy": {
            "model_alias": due.execution_model_alias,
            "budget_id": due.execution_budget_id,
            "tool_policy_scope": due.tool_policy_scope,
        },
    })
}

fn safe_string_list(value: &str) -> Value {
    if value.len() > 64 * 1024 {
        return json!([]);
    }
    serde_json::from_str::<Vec<String>>(value).map_or_else(
        |_| json!([]),
        |values| {
            json!(
                values
                    .into_iter()
                    .filter(|value| !value.is_empty() && value.len() <= 128)
                    .take(16)
                    .collect::<Vec<String>>()
            )
        },
    )
}

fn epoch(now: &Timestamp) -> Result<i64, AutomationStoreError> {
    parse_instant_utc(now.as_str()).map_err(|_| AutomationStoreError::InvalidRow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::automations::{
        DomDowMode, DstPolicy, MissedPolicy, OverlapPolicy, ScheduleKind,
    };
    use crate::repositories::claim_target_state;

    /// Every test automation uses the frozen `automations.max_active` budget and
    /// a `queue_one`-free policy unless the test names one explicitly.
    fn automation() -> AutomationDefinitionRecord {
        AutomationDefinitionRecord {
            automation_id: "aut_0123456789abcdef0123456789abcdef".into(),
            org_id: "org_0123456789abcdef0123456789abcdef".into(),
            project_id: Some("prj_0123456789abcdef0123456789abcdef".into()),
            name: "weekday review".into(),
            description: None,
            agent_definition_id: Some("agd_0123456789abcdef0123456789abcdef".into()),
            schedule_rule_id: "sch_0123456789abcdef0123456789abcdef".into(),
            execution_principal_kind: "user".into(),
            execution_principal_id: "usr_0123456789abcdef0123456789abcdef".into(),
            target_kind: "eligible_device".into(),
            target_device_id: None,
            target_workspace_binding_id: None,
            required_capabilities_json: "[]".into(),
            execution_model_alias: None,
            execution_budget_id: None,
            tool_policy_scope: "project".into(),
            required_policy_version: None,
            off_peak_eligibility_source: None,
            off_peak_allowed_route_aliases_json: None,
            off_peak_deny_automation_mutation: 1,
            off_peak_deny_recursive_off_peak: 1,
            off_peak_allow_background_processes: 0,
            status: "active".into(),
            max_start_attempts: 2,
            lease_ttl_seconds: 300,
            heartbeat_interval_seconds: 30,
            schedule_cursor_at: Some("2026-09-25T16:00:00.000Z".into()),
            next_run_at: Some("2026-09-25T16:00:00.000Z".into()),
            last_run_at: None,
            version: 3,
            created_by_user_id: "usr_0123456789abcdef0123456789abcdef".into(),
            created_at: "2026-09-25T12:00:00.000Z".into(),
            updated_at: "2026-09-25T15:59:59.000Z".into(),
            queued_successor_max_age_seconds: 86_400,
        }
    }

    fn rule(overlap: OverlapPolicy) -> ScheduleRule {
        ScheduleRule::cron(
            "0 9 * * 1-5",
            "America/Los_Angeles",
            DomDowMode::Or,
            DstPolicy::SkipDuplicate,
            overlap,
            MissedPolicy::RunOnce,
            None,
        )
        .unwrap()
    }

    fn occurrence(state: OccurrenceState, attempt: i64) -> AutomationOccurrenceRecord {
        AutomationOccurrenceRecord {
            occurrence_id: "occ_0123456789abcdef0123456789abcdef".into(),
            automation_id: "aut_0123456789abcdef0123456789abcdef".into(),
            org_id: "org_0123456789abcdef0123456789abcdef".into(),
            project_id: Some("prj_0123456789abcdef0123456789abcdef".into()),
            schedule_rule_id: "sch_0123456789abcdef0123456789abcdef".into(),
            kind: "scheduled".into(),
            scheduled_for_utc: Some("2026-09-25T16:00:00.000Z".into()),
            trigger_key_digest: None,
            execution_principal_kind: "user".into(),
            execution_principal_id: "usr_0123456789abcdef0123456789abcdef".into(),
            off_peak_mode: "normal".into(),
            policy_snapshot_id: None,
            policy_version: None,
            state: state.as_str().into(),
            state_version: 1,
            attempt,
            reason_code: None,
            run_id: None,
            blocked_by_occurrence_id: None,
            lease_expires_at: None,
            queued_at: None,
            started_at: None,
            finished_at: None,
            created_at: "2026-09-25T15:59:59.000Z".into(),
            updated_at: "2026-09-25T15:59:59.000Z".into(),
            schedule_rule_version: 3,
        }
    }

    fn open_successor(queued_at: &str) -> AutomationOccurrenceRecord {
        let mut successor = occurrence(OccurrenceState::Pending, 0);
        successor.occurrence_id = "occ_1123456789abcdef0123456789abcdef".into();
        successor.queued_at = Some(queued_at.to_owned());
        successor
    }

    fn eligibility() -> DispatchEligibility {
        DispatchEligibility {
            organization_state: Some("active".into()),
            principal_membership_active: true,
            current_policy_version: 4,
            license_state: Some("active".into()),
            license_grace_expires_at: None,
            max_active_automations: Some(100),
            active_automation_count: 7,
            now: Some("2026-09-25T16:00:00.000Z".into()),
        }
    }

    fn epoch(value: &str) -> i64 {
        parse_instant_utc(value).unwrap()
    }

    #[test]
    fn a_due_slot_projects_to_one_dispatchable_occurrence() {
        // 09:00 at a -8h offset is 17:00 UTC, and occurrence identity is the
        // CANONICAL UTC instant, not the local civil time. A slot AFTER `now` is
        // not yet due and is never minted early.
        let zone = ZoneOffsets::fixed(-28_800).unwrap();
        let due_at = epoch("2026-09-25T17:00:00.000Z");
        let early = plan_due_occurrences(&rule(OverlapPolicy::Skip), &zone, due_at - 1, due_at - 1)
            .unwrap();
        assert!(
            early.instants.is_empty(),
            "a future slot must not be minted early"
        );
        let plan =
            plan_due_occurrences(&rule(OverlapPolicy::Skip), &zone, due_at - 1, due_at).unwrap();
        assert_eq!(
            project_plan(&plan).unwrap(),
            vec![PlannedOccurrence {
                scheduled_for_utc: "2026-09-25T17:00:00.000Z".into(),
                outcome: OccurrencePlanOutcome::Dispatchable,
            }]
        );
        assert_eq!(plan.cursor_after, due_at);
        assert!(!plan.truncated);
        assert_eq!(plan.missed_slots, 1);
    }

    #[test]
    fn a_long_offline_window_is_bounded_and_coalesces_forward() {
        // 09:00 UTC at a zero offset, so the expected slot is the same hour.
        let zone = ZoneOffsets::fixed(0).unwrap();
        let now = epoch("2026-09-25T16:00:00.000Z");
        let plan = plan_due_occurrences(&rule(OverlapPolicy::Skip), &zone, now - 400 * 86_400, now)
            .unwrap();
        assert!(
            plan.truncated,
            "an unbounded window must be reported truncated"
        );
        // `run_once` coalesces forward to the most recent slot, never a burst.
        assert!(plan.missed_slots > 1, "the window contained several slots");
        assert_eq!(
            plan.instants
                .iter()
                .filter(|instant| instant.is_due())
                .count(),
            1
        );
        // Every persisted slot is inside the bounded past window.
        assert!(
            plan.instants
                .iter()
                .all(|instant| instant.scheduled_for_utc <= now)
        );
    }

    #[test]
    fn catch_up_is_bounded_by_the_frozen_limit() {
        let zone = ZoneOffsets::fixed(0).unwrap();
        let now = epoch("2026-09-25T16:00:00.000Z");
        let bounded = ScheduleRule::cron(
            "0 9 * * 1-5",
            "America/Los_Angeles",
            DomDowMode::Or,
            DstPolicy::SkipDuplicate,
            OverlapPolicy::Skip,
            MissedPolicy::CatchUp,
            Some(3),
        )
        .unwrap();
        let plan = plan_due_occurrences(&bounded, &zone, now - 20 * 86_400, now).unwrap();
        assert!(
            plan.instants
                .iter()
                .filter(|instant| instant.is_due())
                .count()
                <= 3
        );
    }

    #[test]
    fn a_manual_rule_never_produces_scheduled_instants() {
        let manual = ScheduleRule::manual(OverlapPolicy::Skip, MissedPolicy::Skip, None).unwrap();
        let now = epoch("2026-09-25T16:00:00.000Z");
        assert!(!manual.produces_scheduled_instants());
        assert_eq!(
            plan_next_run(&manual, &ZoneOffsets::utc(), now).unwrap(),
            None
        );
        assert!(
            plan_due_occurrences(&manual, &ZoneOffsets::utc(), now, now)
                .unwrap()
                .instants
                .is_empty()
        );
    }

    #[test]
    fn a_catch_up_rule_without_a_limit_is_rejected_at_the_boundary() {
        // `catch_up` requires a bounded positive limit; the wire path enforces it.
        let invalid = ScheduleRule::cron(
            "0 9 * * 1-5",
            "America/Los_Angeles",
            DomDowMode::Or,
            DstPolicy::SkipDuplicate,
            OverlapPolicy::Skip,
            MissedPolicy::CatchUp,
            None,
        );
        assert!(invalid.is_err(), "an unbounded catch_up was accepted");
    }

    #[test]
    fn the_frozen_schedule_kinds_are_the_only_persisted_ones() {
        for kind in ["one_time", "cron", "interval", "manual"] {
            assert!(ScheduleKind::parse(kind).is_some(), "{kind}");
        }
        assert!(ScheduleKind::parse("weekly").is_none());
    }

    #[test]
    fn dispatch_recheck_fails_closed_for_a_missing_license_projection() {
        let mut facts = eligibility();
        facts.license_state = None;
        assert_eq!(
            dispatch_block(&automation(), &facts),
            Some(DispatchBlock::Authorization(
                DomainError::EntitlementNotGranted
            ))
        );
    }

    #[test]
    fn dispatch_recheck_refuses_membership_loss_and_org_state() {
        let mut facts = eligibility();
        facts.principal_membership_active = false;
        assert_eq!(
            dispatch_block(&automation(), &facts),
            Some(DispatchBlock::Authorization(
                DomainError::ExecutionPrincipalUnavailable
            ))
        );
        facts = eligibility();
        facts.organization_state = Some("pending_deletion".into());
        assert_eq!(
            dispatch_block(&automation(), &facts),
            Some(DispatchBlock::Authorization(
                DomainError::OrganizationPendingDeletion
            ))
        );
        facts = eligibility();
        facts.organization_state = Some("suspended".into());
        assert_eq!(
            dispatch_block(&automation(), &facts).map(DispatchBlock::code),
            Some("organization_suspended")
        );
    }

    #[test]
    fn dispatch_recheck_refuses_an_expired_grace_and_a_stale_policy() {
        let mut facts = eligibility();
        facts.license_state = Some("grace".into());
        facts.license_grace_expires_at = Some("2026-09-20T00:00:00.000Z".into());
        assert_eq!(
            dispatch_block(&automation(), &facts),
            Some(DispatchBlock::Authorization(
                DomainError::EntitlementGraceExpired
            ))
        );
        facts = eligibility();
        facts.license_state = Some("grace".into());
        facts.license_grace_expires_at = Some("2026-09-26T00:00:00.000Z".into());
        assert_eq!(dispatch_block(&automation(), &facts), None);

        let mut stale = automation();
        stale.required_policy_version = Some(9);
        let mut facts = eligibility();
        facts.current_policy_version = 4;
        assert_eq!(
            dispatch_block(&stale, &facts).map(DispatchBlock::code),
            Some("policy_snapshot_stale")
        );
    }

    #[test]
    fn dispatch_recheck_enforces_the_active_automation_entitlement() {
        let mut facts = eligibility();
        facts.max_active_automations = Some(3);
        facts.active_automation_count = 7;
        assert_eq!(
            dispatch_block(&automation(), &facts).map(DispatchBlock::code),
            Some("entitlement_limit_exceeded")
        );
        facts.active_automation_count = 3;
        assert_eq!(dispatch_block(&automation(), &facts), None);
        facts.max_active_automations = None;
        assert_eq!(
            dispatch_block(&automation(), &facts),
            Some(DispatchBlock::Authorization(
                DomainError::EntitlementNotGranted
            ))
        );
    }

    #[test]
    fn an_ambiguous_predecessor_never_dispatches_under_any_policy() {
        let now = epoch("2026-09-25T16:00:00.000Z");
        let predecessor = occurrence(OccurrenceState::Ambiguous, 1);
        for policy in [
            OverlapPolicy::Allow,
            OverlapPolicy::Skip,
            OverlapPolicy::QueueOne,
            OverlapPolicy::CancelPrevious,
        ] {
            let plan = plan_overlap(&rule(policy), 86_400, Some(&predecessor), None, now).unwrap();
            assert!(
                !matches!(plan, DispatchPlan::Dispatch),
                "{policy:?} dispatched over an ambiguous predecessor"
            );
        }
    }

    #[test]
    fn a_terminal_predecessor_always_allows_the_next_slot() {
        let now = epoch("2026-09-25T16:00:00.000Z");
        for state in [
            OccurrenceState::Succeeded,
            OccurrenceState::Failed,
            OccurrenceState::Cancelled,
            OccurrenceState::Missed,
            OccurrenceState::Skipped,
        ] {
            for policy in [
                OverlapPolicy::Allow,
                OverlapPolicy::Skip,
                OverlapPolicy::QueueOne,
                OverlapPolicy::CancelPrevious,
            ] {
                assert_eq!(
                    plan_overlap(
                        &rule(policy),
                        86_400,
                        Some(&occurrence(state, 1)),
                        None,
                        now
                    )
                    .unwrap(),
                    DispatchPlan::Dispatch,
                    "{state:?}/{policy:?} blocked a slot"
                );
            }
        }
    }

    #[test]
    fn no_predecessor_always_dispatches() {
        let now = epoch("2026-09-25T16:00:00.000Z");
        for policy in [
            OverlapPolicy::Allow,
            OverlapPolicy::Skip,
            OverlapPolicy::QueueOne,
            OverlapPolicy::CancelPrevious,
        ] {
            assert_eq!(
                plan_overlap(&rule(policy), 86_400, None, None, now).unwrap(),
                DispatchPlan::Dispatch
            );
        }
    }

    #[test]
    fn queue_one_allows_at_most_one_open_successor() {
        let now = epoch("2026-09-25T16:00:00.000Z");
        let predecessor = occurrence(OccurrenceState::Leased, 1);
        let successor = open_successor("2026-09-25T16:00:00.000Z");
        assert_eq!(
            plan_overlap(
                &rule(OverlapPolicy::QueueOne),
                86_400,
                Some(&predecessor),
                Some(&successor),
                now,
            )
            .unwrap(),
            DispatchPlan::Skip("automation_overlap_policy")
        );
        assert!(matches!(
            plan_overlap(
                &rule(OverlapPolicy::QueueOne),
                86_400,
                Some(&predecessor),
                None,
                now
            )
            .unwrap(),
            DispatchPlan::QueueOne { .. }
        ));
    }

    #[test]
    fn a_queued_successor_past_its_bounded_age_is_skipped() {
        let now = epoch("2026-09-26T16:00:00.000Z");
        let predecessor = occurrence(OccurrenceState::Leased, 1);
        let successor = open_successor("2026-09-25T00:00:00.000Z");
        for policy in [OverlapPolicy::QueueOne, OverlapPolicy::CancelPrevious] {
            assert_eq!(
                plan_overlap(
                    &rule(policy),
                    86_400,
                    Some(&predecessor),
                    Some(&successor),
                    now,
                )
                .unwrap(),
                DispatchPlan::Skip("automation_overlap_policy"),
                "{policy:?} kept a successor queued forever"
            );
        }
    }

    #[test]
    fn cancel_previous_keeps_the_successor_queued_behind_its_predecessor() {
        let now = epoch("2026-09-25T16:00:00.000Z");
        assert_eq!(
            plan_overlap(
                &rule(OverlapPolicy::CancelPrevious),
                86_400,
                Some(&occurrence(OccurrenceState::Started, 1)),
                None,
                now,
            )
            .unwrap(),
            DispatchPlan::CancelPrevious {
                predecessor_id: "occ_0123456789abcdef0123456789abcdef".into(),
            }
        );
    }

    #[test]
    fn a_pre_start_expiry_requeues_but_a_post_start_expiry_is_ambiguous() {
        let retry = ExecutionRetry::default_policy();
        assert_eq!(
            plan_lease_expiry(&occurrence(OccurrenceState::Leased, 1), &retry, false).unwrap(),
            LeaseExpiryPlan::Requeue { attempt: 2 }
        );
        // A durable run link is proof execution may have begun, whatever the
        // occurrence state says.
        assert_eq!(
            plan_lease_expiry(&occurrence(OccurrenceState::Leased, 1), &retry, true).unwrap(),
            LeaseExpiryPlan::MarkAmbiguous
        );
        assert_eq!(
            plan_lease_expiry(&occurrence(OccurrenceState::Started, 1), &retry, false).unwrap(),
            LeaseExpiryPlan::MarkAmbiguous
        );
    }

    #[test]
    fn the_attempt_budget_fails_an_exhausted_occurrence_instead_of_looping() {
        let retry = ExecutionRetry::default_policy();
        assert_eq!(
            plan_lease_expiry(&occurrence(OccurrenceState::Leased, 2), &retry, false).unwrap(),
            LeaseExpiryPlan::FailExhausted
        );
        // A larger budget requeues one more time.
        let generous = ExecutionRetry::new(3, 300, 30).validate().unwrap();
        assert_eq!(
            plan_lease_expiry(&occurrence(OccurrenceState::Leased, 2), &generous, false).unwrap(),
            LeaseExpiryPlan::Requeue { attempt: 3 }
        );
    }

    #[test]
    fn occurrence_event_names_cover_every_dispatcher_moved_state_but_the_claim() {
        for state in [
            "dispatching",
            "started",
            "succeeded",
            "failed",
            "skipped",
            "missed",
        ] {
            assert!(
                occurrence_event_type(state)
                    .is_some_and(|name| AUTOMATION_EVENT_TYPES.contains(&name)),
                "{state} has no frozen event name"
            );
        }
        // A claim has no frozen `automation.occurrence.*` name.
        assert_eq!(occurrence_event_type("leased"), None);
        // `ambiguous` and `lease_expired` are emitted as their own events.
        assert_eq!(occurrence_event_type("ambiguous"), None);
        assert!(AUTOMATION_EVENT_TYPES.contains(&EVENT_OCCURRENCE_AMBIGUOUS));
        assert!(AUTOMATION_EVENT_TYPES.contains(&EVENT_OCCURRENCE_LEASE_EXPIRED));
    }

    #[test]
    fn deterministic_ids_are_stable_and_distinct_per_slot() {
        let first = deterministic_occurrence_id(
            "aut_0123456789abcdef0123456789abcdef",
            "sch_0123456789abcdef0123456789abcdef",
            "2026-09-25T16:00:00.000Z",
        );
        let again = deterministic_occurrence_id(
            "aut_0123456789abcdef0123456789abcdef",
            "sch_0123456789abcdef0123456789abcdef",
            "2026-09-25T16:00:00.000Z",
        );
        let other_slot = deterministic_occurrence_id(
            "aut_0123456789abcdef0123456789abcdef",
            "sch_0123456789abcdef0123456789abcdef",
            "2026-09-25T17:00:00.000Z",
        );
        let other_kind = deterministic_manual_occurrence_id(
            "aut_0123456789abcdef0123456789abcdef",
            "sha256:key",
        );
        assert_eq!(
            first, again,
            "a redelivery must derive the same occurrence ID"
        );
        assert_ne!(first, other_slot);
        assert_ne!(first, other_kind);
        for id in [first, other_slot, other_kind] {
            assert_eq!(id.len(), 36, "{id}");
            assert!(id.starts_with("occ_"));
            assert!(
                id[4..]
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            );
        }
        let job = deterministic_job_id(
            JobType::Dispatch.as_str(),
            "occ_0123456789abcdef0123456789abcdef",
            0,
        );
        assert_eq!(job.len(), 36);
        assert!(job.starts_with("job_"));
        // A new generation is a new logical job, so a genuine retry still runs.
        assert_ne!(
            job,
            deterministic_job_id(
                JobType::Dispatch.as_str(),
                "occ_0123456789abcdef0123456789abcdef",
                1
            )
        );
    }

    #[test]
    fn the_due_projection_never_leaks_an_idempotency_digest_or_bad_json() {
        let mut due = DueOccurrenceRecord {
            occurrence_id: "occ_0123456789abcdef0123456789abcdef".into(),
            automation_id: "aut_0123456789abcdef0123456789abcdef".into(),
            org_id: "org_0123456789abcdef0123456789abcdef".into(),
            project_id: None,
            schedule_rule_id: "sch_0123456789abcdef0123456789abcdef".into(),
            kind: "scheduled".into(),
            scheduled_for_utc: Some("2026-09-25T16:00:00.000Z".into()),
            execution_principal_kind: "user".into(),
            execution_principal_id: "usr_0123456789abcdef0123456789abcdef".into(),
            off_peak_mode: "normal".into(),
            policy_snapshot_id: None,
            policy_version: None,
            state: "dispatching".into(),
            state_version: 1,
            attempt: 0,
            reason_code: None,
            run_id: None,
            blocked_by_occurrence_id: None,
            lease_expires_at: None,
            queued_at: None,
            started_at: None,
            finished_at: None,
            created_at: "2026-09-25T15:59:59.000Z".into(),
            updated_at: "2026-09-25T15:59:59.000Z".into(),
            lease_ttl_seconds: 300,
            heartbeat_interval_seconds: 30,
            required_capabilities_json: "[\"text\"]".into(),
            execution_model_alias: Some("coding-default".into()),
            execution_budget_id: None,
            tool_policy_scope: "project".into(),
        };
        let projection = due_projection(&due).to_string();
        assert!(projection.contains("text"));
        // The due row carries no trigger key digest, so a manual idempotency
        // secret cannot reach a device.
        assert!(!projection.contains("trigger_key_digest"));
        due.required_capabilities_json = "not json".into();
        assert_eq!(due_projection(&due)["required_capabilities"], json!([]));
        due.required_capabilities_json = "[]".into();
        assert_eq!(
            due_projection(&due)["execution_policy"]["tool_policy_scope"],
            "project"
        );
    }

    #[test]
    fn the_occurrence_payload_is_bounded_metadata_only() {
        let payload = occurrence_event_payload(
            "occ_0123456789abcdef0123456789abcdef",
            "aut_0123456789abcdef0123456789abcdef",
            Some("prj_0123456789abcdef0123456789abcdef"),
            2,
            7,
            "skipped",
            "automation_overlap_policy",
            None,
        );
        assert_eq!(
            payload["occurrence_id"],
            "occ_0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            payload["automation_id"],
            "aut_0123456789abcdef0123456789abcdef"
        );
        assert_eq!(payload["resource_version"], 7);
        assert_eq!(payload["reason_code"], "automation_overlap_policy");
        assert!(payload["run_id"].is_null());
        let empty = occurrence_event_payload(
            "occ_0123456789abcdef0123456789abcdef",
            "aut_0123456789abcdef0123456789abcdef",
            None,
            0,
            1,
            "succeeded",
            "",
            Some("run_0123456789abcdef0123456789abcdef"),
        );
        assert!(empty["reason_code"].is_null());
        assert_eq!(empty["run_id"], "run_0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn retry_settings_round_trip_through_the_bounded_domain_policy() {
        assert!(ExecutionRetry::new(1, 30, 10).validate().is_ok());
        assert!(ExecutionRetry::new(0, 30, 10).validate().is_err());
        assert!(ExecutionRetry::new(4, 30, 10).validate().is_err());
        assert!(ExecutionRetry::new(1, 29, 10).validate().is_err());
        assert!(ExecutionRetry::new(1, 3601, 10).validate().is_err());
        assert!(ExecutionRetry::new(1, 30, 30).validate().is_err());
        assert_eq!(
            automation().execution_retry().unwrap(),
            ExecutionRetry::default_policy()
        );
    }

    #[test]
    fn predecessor_view_uses_the_predecessor_queued_age() {
        let now = epoch("2026-09-25T16:00:00.000Z");
        let mut predecessor = occurrence(OccurrenceState::Leased, 1);
        assert_eq!(
            predecessor_view(&predecessor, now).unwrap(),
            PredecessorView {
                state: OccurrenceState::Leased,
                queued_age_seconds: 0,
                now,
            }
        );
        predecessor.queued_at = Some("2026-09-25T12:00:00.000Z".into());
        assert_eq!(
            predecessor_view(&predecessor, now)
                .unwrap()
                .queued_age_seconds,
            14_400
        );
    }

    #[test]
    fn a_claim_normalizes_pending_through_the_dispatch_edge() {
        assert_eq!(
            claim_target_state(OccurrenceState::Pending).unwrap(),
            OccurrenceState::Leased
        );
        assert_eq!(
            claim_target_state(OccurrenceState::Dispatching).unwrap(),
            OccurrenceState::Leased
        );
    }

    #[test]
    fn a_missed_slot_never_stays_pending() {
        assert_eq!(
            missed_target_state(OccurrenceState::Pending).unwrap(),
            OccurrenceState::Missed
        );
        assert_eq!(
            missed_target_state(OccurrenceState::Dispatching).unwrap(),
            OccurrenceState::Missed
        );
        assert_eq!(
            missed_target_state(OccurrenceState::Leased).unwrap(),
            OccurrenceState::Missed
        );
    }

    #[test]
    fn the_report_totals_are_additive() {
        let mut report = SchedulerReport {
            occurrences_created: 2,
            jobs_enqueued: 2,
            ..SchedulerReport::default()
        };
        report.merge(SchedulerReport {
            occurrences_created: 1,
            leases_ambiguous: 1,
            ..SchedulerReport::default()
        });
        assert_eq!(report.occurrences_created, 3);
        assert_eq!(report.jobs_enqueued, 2);
        assert_eq!(report.leases_ambiguous, 1);
    }
}
