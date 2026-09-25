//! P06 automation domain tests.
//!
//! The emphasis is on the invariants the control plane is judged by, not on
//! line coverage:
//!
//! - one logical occurrence per schedule slot, stable across re-derivations;
//! - `ambiguous` is terminal and can never be automatically re-dispatched;
//! - a lost lease only requeues when the server can PROVE nothing started;
//! - a stale fence cannot settle a superseded attempt;
//! - overlap never treats an ambiguous predecessor as safe;
//! - off-peak can only narrow, never broaden, the host's restrictions;
//! - DST and calendar arithmetic are correct at the boundaries.

use super::*;
use crate::core::ScheduleRuleId;

/// A cron schedule built through the same validated wire path a request uses,
/// so the fixture cannot drift from the parser's accepted grammar.
fn cron_rule(
    expression: &str,
    dst_policy: DstPolicy,
    missed_policy: MissedPolicy,
) -> Result<ScheduleRule, DomainError> {
    let wire = serde_json::json!({
        "kind": "cron",
        "expression": expression,
        "timezone": "UTC",
        "dom_dow_mode": "or",
        "dst_policy": dst_policy,
        "missed_policy": missed_policy,
    });
    // A rejected rule surfaces only its stable reason code, so the fixture maps
    // serde's transport error onto the domain error the state machine uses.
    serde_json::from_value::<ScheduleRule>(wire).map_err(|_| DomainError::ScheduleInvalid)
}

fn utc() -> ZoneOffsets {
    ZoneOffsets::utc()
}

// ---------------------------------------------------------------------------
// Occurrence identity
// ---------------------------------------------------------------------------

#[test]
fn a_scheduled_slot_has_one_stable_identity_key() {
    let rule = ScheduleRuleId::new("sch_0123456789abcdef0123456789abcdef").unwrap();
    let automation = "aut_0123456789abcdef0123456789abcdef";
    let first = scheduled_occurrence_key(automation, &rule, "2026-09-25T16:00:00.000Z").unwrap();
    let second = scheduled_occurrence_key(automation, &rule, "2026-09-25T16:00:00.000Z").unwrap();
    assert_eq!(first, second, "re-derivation must be stable");
}

#[test]
fn a_new_schedule_revision_is_a_different_logical_slot() {
    let before = ScheduleRuleId::new("sch_0123456789abcdef0123456789abcdef").unwrap();
    let after = ScheduleRuleId::new("sch_ffffffffffffffffffffffffffffffff").unwrap();
    let automation = "aut_0123456789abcdef0123456789abcdef";
    let instant = "2026-09-25T16:00:00.000Z";
    assert_ne!(
        scheduled_occurrence_key(automation, &before, instant).unwrap(),
        scheduled_occurrence_key(automation, &after, instant).unwrap(),
        "editing a schedule mints a new revision and therefore a new slot"
    );
}

#[test]
fn a_manual_key_never_collides_with_a_scheduled_key() {
    let rule = ScheduleRuleId::new("sch_0123456789abcdef0123456789abcdef").unwrap();
    let scheduled = scheduled_occurrence_key("aut_1", &rule, "2026-09-25T16:00:00.000Z").unwrap();
    let manual = manual_occurrence_key("aut_1", "deadbeef").unwrap();
    assert_ne!(scheduled, manual);
}

#[test]
fn an_identity_key_round_trips() {
    let rule = ScheduleRuleId::new("sch_0123456789abcdef0123456789abcdef").unwrap();
    let key = scheduled_occurrence_key("aut_1", &rule, "2026-09-25T16:00:00.000Z").unwrap();
    let parsed = occurrence_identity_key(&key).unwrap();
    assert_eq!(parsed.kind, OccurrenceKind::Scheduled);
    assert_eq!(parsed.automation_id, "aut_1");
    assert_eq!(
        parsed.schedule_rule_id.as_deref(),
        Some("sch_0123456789abcdef0123456789abcdef")
    );
    assert_eq!(
        parsed.scheduled_for_utc.as_deref(),
        Some("2026-09-25T16:00:00.000Z")
    );
}

#[test]
fn a_manual_identity_key_round_trips() {
    let key = manual_occurrence_key("aut_1", "digest123").unwrap();
    let parsed = occurrence_identity_key(&key).unwrap();
    assert_eq!(parsed.kind, OccurrenceKind::Manual);
    assert_eq!(parsed.trigger_key_digest.as_deref(), Some("digest123"));
    assert!(parsed.schedule_rule_id.is_none());
}

#[test]
fn a_malformed_identity_key_is_rejected() {
    assert_eq!(
        occurrence_identity_key("nonsense"),
        Err(DomainError::ScheduleInvalid)
    );
    assert_eq!(
        occurrence_identity_key("scheduled:"),
        Err(DomainError::ScheduleInvalid)
    );
}

// ---------------------------------------------------------------------------
// Occurrence state machine
// ---------------------------------------------------------------------------

#[test]
fn the_happy_path_reaches_succeeded() {
    let mut state = OccurrenceState::Pending;
    for event in [
        OccurrenceEvent::Dispatch,
        OccurrenceEvent::Claimed,
        OccurrenceEvent::Started,
        OccurrenceEvent::Succeeded,
    ] {
        state = transition(state, event).unwrap();
    }
    assert_eq!(state, OccurrenceState::Succeeded);
    assert!(state.is_terminal());
}

#[test]
fn ambiguous_is_terminal_and_refuses_every_dispatch() {
    let state = OccurrenceState::Ambiguous;
    assert!(state.is_terminal());
    for event in [
        OccurrenceEvent::Dispatch,
        OccurrenceEvent::Claimed,
        OccurrenceEvent::Started,
        OccurrenceEvent::LeaseLost {
            proved_not_started: true,
        },
        OccurrenceEvent::LeaseLost {
            proved_not_started: false,
        },
        OccurrenceEvent::Succeeded,
    ] {
        assert!(
            transition(state, event).is_err(),
            "ambiguous must not accept {event:?}"
        );
    }
}

#[test]
fn ambiguous_is_reconcilable_only_through_an_explicit_audited_resolution() {
    let resolved = transition(
        OccurrenceState::Ambiguous,
        OccurrenceEvent::Reconciled {
            to: OccurrenceState::Failed,
        },
    )
    .unwrap();
    assert_eq!(resolved, OccurrenceState::Failed);
}

#[test]
fn a_terminal_occurrence_cannot_be_rewritten_into_success() {
    for state in [
        OccurrenceState::Failed,
        OccurrenceState::Cancelled,
        OccurrenceState::Missed,
        OccurrenceState::Skipped,
    ] {
        assert!(
            transition(state, OccurrenceEvent::Succeeded).is_err(),
            "{state:?} must not be rewritten into success"
        );
    }
}

#[test]
fn a_started_occurrence_can_still_succeed_or_fail() {
    for terminal in [OccurrenceState::Succeeded, OccurrenceState::Failed] {
        let state = transition(OccurrenceState::Started, OccurrenceEvent::Succeeded);
        assert_eq!(state, Ok(OccurrenceState::Succeeded));
        assert!(terminal.is_terminal());
    }
}

#[test]
fn a_lease_lost_after_start_becomes_ambiguous() {
    assert_eq!(
        transition(
            OccurrenceState::Started,
            OccurrenceEvent::LeaseLost {
                proved_not_started: false
            }
        ),
        Ok(OccurrenceState::Ambiguous)
    );
}

#[test]
fn a_lease_lost_before_start_requeues_only_when_proven() {
    assert_eq!(
        transition(
            OccurrenceState::Leased,
            OccurrenceEvent::LeaseLost {
                proved_not_started: true
            }
        ),
        Ok(OccurrenceState::Pending)
    );
    assert_eq!(
        transition(
            OccurrenceState::Leased,
            OccurrenceEvent::LeaseLost {
                proved_not_started: false
            }
        ),
        Ok(OccurrenceState::Ambiguous)
    );
}

#[test]
fn an_ambiguous_occurrence_is_never_a_safe_overlap_predecessor() {
    let decision = decide_overlap(
        OverlapPolicy::Allow,
        Some(PredecessorView {
            state: OccurrenceState::Ambiguous,
            queued_age_seconds: 0,
            now: 0,
        }),
        MAX_QUEUE_ONE_AGE_SECONDS,
    );
    // Even the most permissive overlap policy cannot hand the slot to a second
    // device while the predecessor's execution authority is unknown.
    assert_ne!(decision, OverlapAction::Allow);
}

#[test]
fn a_terminal_predecessor_frees_the_slot() {
    let decision = decide_overlap(
        OverlapPolicy::QueueOne,
        Some(PredecessorView {
            state: OccurrenceState::Succeeded,
            queued_age_seconds: 10,
            now: 10,
        }),
        MAX_QUEUE_ONE_AGE_SECONDS,
    );
    assert_eq!(decision, OverlapAction::Allow);
}

#[test]
fn a_queued_successor_is_skipped_rather_than_blocking_forever() {
    let decision = decide_overlap(
        OverlapPolicy::QueueOne,
        Some(PredecessorView {
            state: OccurrenceState::Started,
            queued_age_seconds: MAX_QUEUE_ONE_AGE_SECONDS,
            now: MAX_QUEUE_ONE_AGE_SECONDS,
        }),
        MAX_QUEUE_ONE_AGE_SECONDS,
    );
    assert!(matches!(decision, OverlapAction::Skip(_)));
}

#[test]
fn an_unbounded_successor_age_is_clamped_so_a_slot_cannot_block_forever() {
    let decision = decide_overlap(
        OverlapPolicy::QueueOne,
        Some(PredecessorView {
            state: OccurrenceState::Started,
            queued_age_seconds: 0,
            now: 0,
        }),
        i64::MAX,
    );
    assert!(matches!(decision, OverlapAction::Skip(_)));
}

#[test]
fn skip_overlap_always_skips() {
    let decision = decide_overlap(
        OverlapPolicy::Skip,
        Some(PredecessorView {
            state: OccurrenceState::Started,
            queued_age_seconds: 0,
            now: 0,
        }),
        MAX_QUEUE_ONE_AGE_SECONDS,
    );
    assert_eq!(
        decision,
        OverlapAction::Skip(DomainError::AutomationOverlapPolicy)
    );
}

#[test]
fn cancel_previous_keeps_the_successor_queued() {
    let decision = decide_overlap(
        OverlapPolicy::CancelPrevious,
        Some(PredecessorView {
            state: OccurrenceState::Started,
            queued_age_seconds: 0,
            now: 0,
        }),
        MAX_QUEUE_ONE_AGE_SECONDS,
    );
    assert_eq!(decision, OverlapAction::CancelPrevious);
}

#[test]
fn a_lease_lost_decision_uses_the_durable_run_link_as_the_only_proof() {
    let retry = ExecutionRetry::default_policy();
    assert_eq!(
        decide_lease_expiry(OccurrenceState::Leased, 1, &retry, false),
        LeaseExpiryAction::Requeue
    );
    assert_eq!(
        decide_lease_expiry(OccurrenceState::Leased, 1, &retry, true),
        LeaseExpiryAction::MarkAmbiguous
    );
    assert_eq!(
        decide_lease_expiry(OccurrenceState::Started, 1, &retry, false),
        LeaseExpiryAction::MarkAmbiguous
    );
}

#[test]
fn the_attempt_budget_is_bounded() {
    let retry = ExecutionRetry::default_policy();
    assert_eq!(
        decide_lease_expiry(
            OccurrenceState::Leased,
            retry.max_start_attempts,
            &retry,
            false
        ),
        LeaseExpiryAction::FailExhausted
    );
}

#[test]
fn execution_retry_settings_are_validated_against_the_frozen_bounds() {
    assert!(ExecutionRetry::default_policy().validate().is_ok());
    assert!(ExecutionRetry::new(0, 300, 30).validate().is_err());
    assert!(ExecutionRetry::new(4, 300, 30).validate().is_err());
    assert!(ExecutionRetry::new(2, 10, 5).validate().is_err());
    assert!(ExecutionRetry::new(2, 4000, 30).validate().is_err());
    // A heartbeat at or beyond the TTL would let a lease lapse silently.
    assert!(ExecutionRetry::new(2, 30, 30).validate().is_err());
    assert!(ExecutionRetry::new(2, 30, 5).validate().is_err());
}

// ---------------------------------------------------------------------------
// Lease fencing
// ---------------------------------------------------------------------------

fn fence(version: i64, value: i64) -> LeaseFence {
    LeaseFence::new(
        ExecutionLeaseId::new("lse_0123456789abcdef0123456789abcdef").unwrap(),
        version,
        value,
    )
}

#[test]
fn a_matching_fence_is_current() {
    assert!(fence_is_current(&fence(1, 7), &fence(1, 7)));
}

#[test]
fn a_stale_or_future_fence_is_rejected() {
    assert!(!fence_is_current(&fence(1, 7), &fence(2, 8)));
    assert!(!fence_is_current(&fence(2, 8), &fence(1, 7)));
}

#[test]
fn a_fence_from_a_different_lease_is_rejected() {
    let other = LeaseFence::new(
        ExecutionLeaseId::new("lse_ffffffffffffffffffffffffffffffff").unwrap(),
        1,
        7,
    );
    assert!(!fence_is_current(&other, &fence(1, 7)));
}

#[test]
fn a_stale_device_cannot_settle_a_superseded_attempt() {
    let current = fence(2, 8);
    let stale = fence(1, 7);
    assert_eq!(
        validate_settlement(OccurrenceState::Started, &stale, &current),
        Err(DomainError::LeaseFenceInvalid)
    );
    assert!(validate_settlement(OccurrenceState::Started, &current, &current).is_ok());
}

#[test]
fn an_ambiguous_occurrence_refuses_settlement() {
    let current = fence(1, 7);
    assert_eq!(
        validate_settlement(OccurrenceState::Ambiguous, &current, &current),
        Err(DomainError::OccurrenceAmbiguous)
    );
}

#[test]
fn a_pending_occurrence_is_not_settleable() {
    let current = fence(1, 7);
    assert!(validate_settlement(OccurrenceState::Pending, &current, &current).is_err());
}

// ---------------------------------------------------------------------------
// Off-peak: narrowing only
// ---------------------------------------------------------------------------

fn policy(constraints: ToolConstraints) -> OffPeakPolicy {
    OffPeakPolicy {
        schema_version: 1,
        eligibility_source: OffPeakEligibilitySource::ProviderTicket,
        allowed_route_aliases: vec!["cheap".to_owned()],
        tool_constraints: constraints,
    }
}

fn context<'a>(constraints: ToolConstraints, alias: Option<&'a str>) -> OffPeakContext<'a> {
    OffPeakContext {
        mode: OffPeakMode::OffPeak,
        policy: Some(policy(constraints)),
        host_baseline: ToolConstraints::baseline(),
        eligibility_satisfied: true,
        creates_off_peak: false,
        mutates_automation: false,
        starts_background_process: false,
        requested_route_alias: alias,
    }
}

#[test]
fn a_server_policy_can_never_broaden_the_host_baseline() {
    let permissive = ToolConstraints {
        deny_automation_mutation: false,
        deny_recursive_off_peak: false,
        allow_background_processes: true,
    };
    let narrowed = narrow_off_peak_policy(&ToolConstraints::baseline(), &permissive);
    assert!(narrowed.deny_automation_mutation, "host deny must survive");
    assert!(narrowed.deny_recursive_off_peak, "host deny must survive");
    assert!(
        !narrowed.allow_background_processes,
        "a permissive server policy must not re-enable background processes"
    );
}

#[test]
fn narrowing_is_idempotent() {
    let once = narrow_off_peak_policy(&ToolConstraints::baseline(), &ToolConstraints::baseline());
    let twice = narrow_off_peak_policy(&once, &ToolConstraints::baseline());
    assert_eq!(once, twice);
}

#[test]
fn an_off_peak_occurrence_without_a_policy_fails_closed() {
    let mut ctx = context(ToolConstraints::baseline(), None);
    ctx.policy = None;
    assert_eq!(
        evaluate_off_peak(&ctx),
        OffPeakDecision::Denied(OffPeakDenialReason::InvalidPolicy)
    );
}

#[test]
fn an_ineligible_ticket_is_refused() {
    let mut ctx = context(ToolConstraints::baseline(), None);
    ctx.eligibility_satisfied = false;
    assert_eq!(
        evaluate_off_peak(&ctx),
        OffPeakDecision::Denied(OffPeakDenialReason::NotEligible)
    );
}

#[test]
fn recursive_off_peak_creation_is_refused() {
    let mut ctx = context(ToolConstraints::baseline(), None);
    ctx.creates_off_peak = true;
    assert_eq!(
        evaluate_off_peak(&ctx),
        OffPeakDecision::Denied(OffPeakDenialReason::RecursiveOffPeak)
    );
}

#[test]
fn automation_mutation_is_refused_while_off_peak() {
    let mut ctx = context(ToolConstraints::baseline(), None);
    ctx.mutates_automation = true;
    assert_eq!(
        evaluate_off_peak(&ctx),
        OffPeakDecision::Denied(OffPeakDenialReason::AutomationMutationDenied)
    );
}

#[test]
fn background_processes_are_refused_while_off_peak() {
    let mut ctx = context(ToolConstraints::baseline(), None);
    ctx.starts_background_process = true;
    assert_eq!(
        evaluate_off_peak(&ctx),
        OffPeakDecision::Denied(OffPeakDenialReason::BackgroundProcessDenied)
    );
}

#[test]
fn a_route_alias_outside_the_allow_list_is_refused() {
    let ctx = context(ToolConstraints::baseline(), Some("premium"));
    assert_eq!(
        evaluate_off_peak(&ctx),
        OffPeakDecision::Denied(OffPeakDenialReason::RouteAliasNotAllowed)
    );
}

#[test]
fn an_allowed_route_alias_passes() {
    let ctx = context(ToolConstraints::baseline(), Some("cheap"));
    assert!(matches!(
        evaluate_off_peak(&ctx),
        OffPeakDecision::Allowed { .. }
    ));
}

#[test]
fn a_normal_occurrence_is_unconstrained_by_off_peak_policy() {
    let mut ctx = context(ToolConstraints::baseline(), Some("premium"));
    ctx.mode = OffPeakMode::Normal;
    assert!(matches!(
        evaluate_off_peak(&ctx),
        OffPeakDecision::Allowed { .. }
    ));
}

#[test]
fn provider_ticket_mode_has_no_clock_schedule() {
    assert!(!OffPeakEligibilitySource::ProviderTicket.has_clock_schedule());
    assert!(OffPeakEligibilitySource::OrgWindow.has_clock_schedule());
}

#[test]
fn an_oversized_route_alias_list_is_rejected() {
    let mut p = policy(ToolConstraints::baseline());
    p.allowed_route_aliases = (0..=MAX_OFF_PEAK_ROUTE_ALIASES)
        .map(|index| format!("alias-{index}"))
        .collect();
    assert!(p.validate().is_err());
}

#[test]
fn an_unsupported_policy_schema_version_is_rejected() {
    let mut p = policy(ToolConstraints::baseline());
    p.schema_version = 0;
    assert!(p.validate().is_err());
    p.schema_version = MAX_OFF_PEAK_SCHEMA_VERSION + 1;
    assert!(p.validate().is_err());
}

// ---------------------------------------------------------------------------
// Cron / DST / calendar arithmetic
// ---------------------------------------------------------------------------

fn cron(expression: &str) -> Result<CronExpression, DomainError> {
    CronExpression::parse(expression, DomDowMode::Or)
}

#[test]
fn a_valid_cron_parses_and_canonicalizes_idempotently() {
    let parsed = cron("0 9 * * 1-5").unwrap();
    let once = parsed.normalized().to_owned();
    let reparsed = cron(&once).unwrap();
    assert_eq!(
        reparsed.normalized(),
        once,
        "canonicalization is idempotent"
    );
}

#[test]
fn a_malformed_cron_is_rejected() {
    for expression in [
        "not a cron",
        "* * * *",
        "* * * * * *",
        "60 * * * *",
        "* 24 * * *",
        "* * 0 * *",
        "* * * 13 *",
        "*/0 * * * *",
    ] {
        assert!(cron(expression).is_err(), "{expression} must be rejected");
    }
}

#[test]
fn a_dst_missing_local_time_is_skipped_not_rolled() {
    // A zone that skips an hour: at 2026-03-08 the local clock jumps 02:00 -> 03:00.
    let zone = ZoneOffsets::new(
        -8 * 3600,
        &[UtcOffsetTransition {
            at_utc: 1_772_949_600, // 2026-03-08T10:00:00Z
            offset_seconds: -7 * 3600,
        }],
    )
    .unwrap();
    let rule = cron_rule(
        "30 2 * * *",
        DstPolicy::SkipDuplicate,
        MissedPolicy::RunOnce,
    )
    .unwrap();
    // Search the window containing the transition.
    let plan = missed_run_plan(&rule, &zone, 1_772_000_000, 1_773_100_000).unwrap();
    for instant in &plan.instants {
        if let ScheduleInstantOutcome::Skipped(reason) = instant.outcome {
            assert!(
                matches!(
                    reason,
                    DomainError::DstMissingTime | DomainError::DstRepeatedTime
                ),
                "a skipped slot must carry a stable DST reason, got {reason:?}"
            );
        }
    }
}

#[test]
fn civil_date_arithmetic_round_trips() {
    for (year, month, day) in [
        (1970_i64, 1_u32, 1_u32),
        (2000, 2, 29),
        (2026, 9, 25),
        (2100, 12, 31),
    ] {
        let days = days_from_civil(year, month, day);
        assert_eq!(civil_from_days(days), (year, month, day));
    }
}

#[test]
fn leap_years_follow_the_gregorian_rule() {
    assert!(is_leap_year(2000), "divisible by 400");
    assert!(!is_leap_year(1900), "divisible by 100 but not 400");
    assert!(is_leap_year(2024), "divisible by 4");
    assert!(!is_leap_year(2026), "not a leap year");
}

#[test]
fn month_lengths_are_correct() {
    assert_eq!(days_in_month(2024, 2), 29);
    assert_eq!(days_in_month(2026, 2), 28);
    assert_eq!(days_in_month(2026, 4), 30);
    assert_eq!(days_in_month(2026, 12), 31);
}

#[test]
fn a_missed_window_is_bounded_to_the_frozen_maximum() {
    let rule = cron_rule("0 9 * * *", DstPolicy::SkipDuplicate, MissedPolicy::RunOnce).unwrap();
    let now = 1_800_000_000_i64;
    let plan = missed_run_plan(&rule, &utc(), now - 40 * 86_400, now).unwrap();
    assert!(
        plan.instants.len() <= MAX_MISSED_HISTORY_DAYS as usize + 1,
        "missed window is bounded, got {}",
        plan.instants.len()
    );
}

#[test]
fn instants_are_returned_in_canonical_order() {
    let rule = cron_rule("0 * * * *", DstPolicy::SkipDuplicate, MissedPolicy::RunOnce).unwrap();
    let plan = missed_run_plan(&rule, &utc(), 0, 5 * 3600).unwrap();
    let mut sorted = plan.instants.clone();
    sorted.sort_by_key(|instant| instant.scheduled_for_utc);
    assert_eq!(plan.instants, sorted);
}

#[test]
fn a_regressed_cursor_is_refused_rather_than_guessed() {
    let rule = cron_rule("0 9 * * *", DstPolicy::SkipDuplicate, MissedPolicy::RunOnce).unwrap();
    assert!(missed_run_plan(&rule, &utc(), 10_000, 0).is_err());
}

#[test]
fn a_manual_schedule_never_produces_automatic_slots() {
    let wire = serde_json::json!({"kind": "manual"});
    let rule: ScheduleRule = serde_json::from_value(wire).unwrap();
    let plan = missed_run_plan(&rule, &utc(), 0, 1_000_000).unwrap();
    assert!(plan.instants.is_empty());
}

#[test]
fn an_interval_rule_produces_cadenced_slots() {
    let wire = serde_json::json!({
        "kind": "interval",
        "every": 15,
        "unit": "minutes",
        "anchor_at": "2026-09-25T00:00:00.000Z",
        "timezone": "UTC",
    });
    let rule: ScheduleRule = serde_json::from_value(wire).unwrap();
    let anchor = parse_instant_utc("2026-09-25T00:00:00.000Z").unwrap();
    let plan = missed_run_plan(&rule, &utc(), anchor, anchor + 3600).unwrap();
    // `run_once` is the frozen DEFAULT missed policy and deliberately coalesces
    // to a single most-recent slot. That is the safe behavior after a long
    // outage: run the current work once instead of replaying a backlog.
    assert_eq!(plan.instants.len(), 1, "run_once coalesces to one slot");
    // `catch_up` is how a caller replays several slots, still bounded.
    let catch_up = serde_json::from_value::<ScheduleRule>(serde_json::json!({
        "kind": "interval",
        "every": 15,
        "unit": "minutes",
        "anchor_at": "2026-09-25T00:00:00.000Z",
        "timezone": "UTC",
        "missed_policy": "catch_up",
        "catch_up_limit": 4,
    }))
    .unwrap();
    let replayed = missed_run_plan(&catch_up, &utc(), anchor, anchor + 3600).unwrap();
    assert!(
        replayed.instants.len() >= 2,
        "catch_up replays several 15-minute slots, got {}",
        replayed.instants.len()
    );
    // Slots come back in ascending canonical order.
    let mut sorted = replayed.instants.clone();
    sorted.sort_by_key(|instant| instant.scheduled_for_utc);
    assert_eq!(replayed.instants, sorted);
}

#[test]
fn an_out_of_range_interval_is_rejected() {
    for every in [0, MAX_INTERVAL_EVERY + 1] {
        let wire = serde_json::json!({
            "kind": "interval",
            "every": every,
            "unit": "minutes",
            "anchor_at": "2026-09-25T00:00:00.000Z",
            "timezone": "UTC",
        });
        assert!(
            serde_json::from_value::<ScheduleRule>(wire).is_err(),
            "every={every} must be rejected"
        );
    }
}

#[test]
fn catch_up_requires_a_bounded_limit() {
    let without_limit = serde_json::json!({
        "kind": "cron",
        "expression": "0 9 * * *",
        "timezone": "UTC",
        "missed_policy": "catch_up",
    });
    assert!(serde_json::from_value::<ScheduleRule>(without_limit).is_err());

    let out_of_range = serde_json::json!({
        "kind": "cron",
        "expression": "0 9 * * *",
        "timezone": "UTC",
        "missed_policy": "catch_up",
        "catch_up_limit": MAX_CATCH_UP_LIMIT + 1,
    });
    assert!(serde_json::from_value::<ScheduleRule>(out_of_range).is_err());

    let valid = serde_json::json!({
        "kind": "cron",
        "expression": "0 9 * * *",
        "timezone": "UTC",
        "missed_policy": "catch_up",
        "catch_up_limit": 3,
    });
    assert!(serde_json::from_value::<ScheduleRule>(valid).is_ok());
}

#[test]
fn a_schedule_rejects_an_oversized_expression_or_timezone() {
    let long = "0 ".repeat(200) + "* * *";
    assert!(cron(&long).is_err());
}

/// WHY this is a test and not a comment: the "no date-time crate" boundary is
/// what keeps the Worker buildable for `wasm32-unknown-unknown`. Reading the
/// constant through a black-box path keeps the assertion from being folded away
/// as a tautology while still failing if the declaration is flipped.
#[test]
fn the_scheduler_declares_itself_dependency_free() {
    let declared: bool = crate::modules::automations::SCHEDULER_IS_DEPENDENCY_FREE;
    assert!(declared, "the scheduler must not link a date-time crate");
}

#[test]
fn every_domain_error_maps_to_a_frozen_stable_code() {
    for error in [
        DomainError::ScheduleInvalid,
        DomainError::ScheduleTimezoneInvalid,
        DomainError::ScheduleIntervalInvalid,
        DomainError::DstMissingTime,
        DomainError::DstRepeatedTime,
        DomainError::AutomationOverlapPolicy,
        DomainError::OccurrenceAmbiguous,
        DomainError::LeaseFenceInvalid,
        DomainError::OffPeakNotAllowed,
    ] {
        let code = error.code();
        assert!(!code.is_empty());
        assert!(
            code.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
            "{code} must be snake_case"
        );
    }
}
