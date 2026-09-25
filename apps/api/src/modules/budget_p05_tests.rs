use crate::modules::budget_p05::{
    BudgetDecision, BudgetDecisionReason, BudgetEvaluationRequest, BudgetLedger, BudgetPolicy,
    BudgetReservation, BudgetScope, BudgetSnapshot, MAX_RESERVATION_MINOR, ReservationAdmission,
    ReservationError, ReservationReconciliation, ReservationState, ReservationTransition,
    ScopeContext, TokenPricing, calculate_reservation_minor, can_reserve_all,
    evaluate_budget_request, evaluate_budgets, scope_matches,
};
use crate::modules::rate_limits::{
    RATE_WINDOW_SECONDS, RateLimitBucket, RateLimitDecision, RateLimitDimension, RateLimitPolicy,
    RateLimitPolicyState, RateLimitRequest, RateLimitUsage, evaluate_rate_limit_request,
    evaluate_rate_limit_states, evaluate_rate_limits,
};

const ORG: &str = "org_fixture";
const PROJECT: &str = "prj_fixture";
const USER: &str = "usr_fixture";
const SERVICE: &str = "svc_fixture";
const ALIAS: &str = "coding-default";

fn user_context() -> ScopeContext {
    ScopeContext::user(ORG, Some(PROJECT.to_owned()), USER, ALIAS)
}

fn service_context() -> ScopeContext {
    ScopeContext::service_account(ORG, Some(PROJECT.to_owned()), SERVICE, ALIAS)
}

fn org_scope() -> BudgetScope {
    BudgetScope::organization(ORG).unwrap()
}

#[test]
fn scopes_are_exact_and_tenant_bound() {
    let context = user_context();
    let organization = org_scope();
    let project = BudgetScope::project(ORG, PROJECT).unwrap();
    let user = BudgetScope::user(ORG, USER).unwrap();
    let service = BudgetScope::service_account(ORG, SERVICE).unwrap();
    let model = BudgetScope::model_alias(ORG, ALIAS).unwrap();

    assert!(scope_matches(&organization, &context));
    assert!(scope_matches(&project, &context));
    assert!(scope_matches(&user, &context));
    assert!(!scope_matches(&service, &context));
    assert!(scope_matches(&model, &context));
    assert!(!scope_matches(
        &BudgetScope::project("org_other", PROJECT).unwrap(),
        &context
    ));
    assert!(!scope_matches(
        &BudgetScope::project(ORG, "prj_other").unwrap(),
        &context
    ));
    assert!(!scope_matches(
        &BudgetScope::model_alias(ORG, "other").unwrap(),
        &context
    ));
    assert!(!scope_matches(
        &BudgetScope::user(ORG, SERVICE).unwrap(),
        &context
    ));
    assert!(scope_matches(
        &BudgetScope::service_account(ORG, SERVICE).unwrap(),
        &service_context()
    ));
}

#[test]
fn all_applicable_budget_scopes_are_considered_and_most_restrictive_wins() {
    let context = user_context();
    let policies = [
        BudgetPolicy::soft(org_scope(), 1_000).with_usage(900, 0),
        BudgetPolicy::hard(org_scope(), 1_000).with_usage(950, 0),
        BudgetPolicy::hard(BudgetScope::project(ORG, PROJECT).unwrap(), 100).with_usage(99, 0),
        BudgetPolicy::hard(BudgetScope::user(ORG, "usr_other").unwrap(), 1),
    ];

    let evaluation = evaluate_budgets(&context, &policies, 2, true, 100);
    assert_eq!(evaluation.decision, BudgetDecision::Deny);
    assert_eq!(evaluation.reason, BudgetDecisionReason::HardLimitExceeded);
    assert_eq!(
        evaluation.matched_scope,
        Some(BudgetScope::project(ORG, PROJECT).unwrap())
    );
    assert_eq!(evaluation.considered_policies, 3);
}

#[test]
fn soft_limit_notifies_but_hard_and_unavailable_are_closed() {
    let context = user_context();
    let soft = evaluate_budgets(
        &context,
        &[BudgetPolicy::soft(org_scope(), 100).with_usage(95, 0)],
        5,
        true,
        10,
    );
    assert_eq!(soft.decision, BudgetDecision::SoftLimit);
    assert!(soft.is_allowed());

    let hard = evaluate_budgets(
        &context,
        &[BudgetPolicy::hard(org_scope(), 100).with_usage(96, 0)],
        5,
        true,
        10,
    );
    assert_eq!(hard.decision, BudgetDecision::Deny);

    let unavailable = evaluate_budgets(
        &context,
        &[BudgetPolicy::hard(org_scope(), 100).unavailable()],
        1,
        true,
        10,
    );
    assert_eq!(unavailable.decision, BudgetDecision::Unavailable);
    assert_eq!(
        unavailable.reason,
        BudgetDecisionReason::BudgetStateUnavailable
    );
}

#[test]
fn unavailable_hard_state_does_not_fail_local_only_work() {
    let context = user_context();
    let policies = [BudgetPolicy::hard(org_scope(), 100).unavailable()];
    let cloud = evaluate_budgets(&context, &policies, 1, true, 10);
    let local = evaluate_budgets(&context, &policies, 1, false, 10);
    assert_eq!(cloud.decision, BudgetDecision::Unavailable);
    assert_eq!(local.decision, BudgetDecision::Allow);
    assert_eq!(local.reason, BudgetDecisionReason::LocalOnly);
}

#[test]
fn active_period_and_soft_state_unavailable_are_not_authority_to_allow_hard_work() {
    let context = user_context();
    let expired_hard = BudgetPolicy::hard(org_scope(), 100)
        .with_usage(0, 0)
        .try_with_period(0, 10)
        .unwrap();
    let decision = evaluate_budget_request(
        &BudgetEvaluationRequest::new(context.clone(), 1, true, 10),
        &[expired_hard],
    );
    assert_eq!(decision.decision, BudgetDecision::Allow);
    assert_eq!(decision.considered_policies, 0);

    let soft_unavailable = BudgetPolicy::soft(org_scope(), 100).unavailable();
    let decision = evaluate_budgets(&context, &[soft_unavailable], 1, true, 10);
    assert_eq!(decision.decision, BudgetDecision::Allow);
    assert_eq!(
        decision.reason,
        BudgetDecisionReason::SoftBudgetStateUnavailable
    );
}

#[test]
fn reservation_amount_and_expiry_are_bounded() {
    assert!(BudgetReservation::new("res-1", "req-1", ORG, None, 0, 20, 10).is_err());
    assert!(
        BudgetReservation::new(
            "res-1",
            "req-1",
            ORG,
            None,
            MAX_RESERVATION_MINOR + 1,
            20,
            10,
        )
        .is_err()
    );
    assert!(BudgetReservation::new("res-1", "req-1", ORG, None, 1, 10, 10).is_err());
    assert!(
        BudgetReservation::new("res-1", "req-1", ORG, None, 1, 10 + 24 * 60 * 60 + 1, 10,).is_err()
    );
}

#[test]
fn reservation_estimate_uses_integer_rounding_and_rejects_unbounded_totals() {
    let pricing = TokenPricing::new(2_000, 3_500);
    assert_eq!(pricing.estimate_minor(1, 1, 100).unwrap(), 2);
    assert_eq!(
        calculate_reservation_minor(1_000_001, 1, 2_000, 0, 10_000).unwrap(),
        2_001
    );
    assert_eq!(calculate_reservation_minor(1, 1, 0, 0, 0).unwrap(), 0);
    assert_eq!(
        calculate_reservation_minor(u64::MAX, 1, u64::MAX, 0, u64::MAX),
        Err(crate::modules::budget_p05::BudgetError::ReservationTooLarge)
    );
}

#[test]
fn late_commit_cannot_bypass_reservation_expiry() {
    let mut reservation =
        BudgetReservation::new("res-late", "req-late", ORG, None, 10, 20, 10).unwrap();
    assert_eq!(
        reservation.commit(1, 20),
        Err(ReservationError::ReservationExpired)
    );
    assert_eq!(reservation.state(), ReservationState::Expired);
    assert_eq!(reservation.committed_minor, 0);
}

#[test]
fn reservation_commit_release_and_expire_are_monotonic_and_idempotent() {
    let mut reservation =
        BudgetReservation::new("res-1", "req-1", ORG, Some("run-1".to_owned()), 100, 20, 10)
            .unwrap();

    assert_eq!(reservation.state(), ReservationState::Reserved);
    assert!(reservation.commit(101, 11).is_err());
    let committed = reservation.commit(80, 11).unwrap();
    assert!(committed.changed());
    assert_eq!(committed.state(), ReservationState::Committed);
    assert_eq!(reservation.committed_minor, 80);
    assert_eq!(
        reservation.commit(80, 12).unwrap(),
        ReservationTransition::Unchanged {
            state: ReservationState::Committed
        }
    );
    assert!(reservation.release(13).is_err());
    assert!(reservation.expire(20).is_ok());

    let mut released = BudgetReservation::new("res-2", "req-2", ORG, None, 10, 20, 10).unwrap();
    assert!(released.release(11).unwrap().changed());
    assert_eq!(
        released.release(12).unwrap(),
        ReservationTransition::Unchanged {
            state: ReservationState::Released
        }
    );
    assert!(released.expire(20).is_ok());

    let mut expired = BudgetReservation::new("res-3", "req-3", ORG, None, 10, 20, 10).unwrap();
    let transition = expired.expire(20).unwrap();
    assert!(transition.changed());
    assert_eq!(transition.state(), ReservationState::Expired);
    assert_eq!(
        expired.expire(21).unwrap().state(),
        ReservationState::Expired
    );
    assert!(expired.commit(1, 21).is_err());
}

#[test]
fn reservation_reconciliation_is_idempotent_and_rejects_conflicting_replay() {
    let mut reservation = BudgetReservation::new("res-1", "req-1", ORG, None, 20, 100, 10).unwrap();
    assert!(
        reservation
            .reconcile(15, ReservationReconciliation::Commit, 20)
            .unwrap()
            .changed()
    );
    assert_eq!(
        reservation
            .reconcile(15, ReservationReconciliation::Commit, 21)
            .unwrap(),
        ReservationTransition::Unchanged {
            state: ReservationState::Committed
        }
    );
    assert_eq!(
        reservation.reconcile(16, ReservationReconciliation::Commit, 22),
        Err(ReservationError::AlreadyReconciled)
    );
}

#[test]
fn all_hard_scope_snapshots_must_admit_one_reservation() {
    let snapshots = [
        BudgetSnapshot {
            limit_minor: 100,
            spent_minor: 20,
            live_reserved_minor: 20,
            max_reservation_minor: 100,
            observed_at: 10,
        },
        BudgetSnapshot {
            limit_minor: 50,
            spent_minor: 45,
            live_reserved_minor: 0,
            max_reservation_minor: 100,
            observed_at: 10,
        },
    ];
    assert!(!can_reserve_all(&snapshots, 6));
    assert!(can_reserve_all(&snapshots[..1], 60));
    assert!(!can_reserve_all(&snapshots, 0));
}

#[test]
fn ledger_rechecks_capacity_after_a_stale_preflight() {
    let mut ledger = BudgetLedger::new(100);
    let stale_a = ledger.snapshot(10);
    let stale_b = ledger.snapshot(10);
    assert!(stale_a.can_reserve(60));
    assert!(stale_b.can_reserve(60));

    let first = ledger
        .reserve("res-a", "req-a", ORG, None, 60, 70, 10)
        .unwrap();
    let second = ledger.reserve("res-b", "req-b", ORG, None, 60, 70, 10);
    assert!(matches!(first, ReservationAdmission::Created(_)));
    assert_eq!(
        second,
        Err(crate::modules::budget_p05::BudgetError::CapacityExceeded)
    );
    assert_eq!(ledger.live_reserved_minor(10), 60);
    assert_eq!(ledger.available_minor(10), 40);
}

#[test]
fn ledger_reservation_replay_is_idempotent_but_identity_conflicts_fail() {
    let mut ledger = BudgetLedger::new(100);
    ledger
        .reserve(
            "res-replay",
            "req-replay",
            ORG,
            Some("run-replay".to_owned()),
            40,
            70,
            10,
        )
        .unwrap();
    let replay = ledger
        .reserve(
            "res-new-id",
            "req-replay",
            ORG,
            Some("run-replay".to_owned()),
            40,
            70,
            10,
        )
        .unwrap();
    assert!(!replay.was_created());
    assert!(
        ledger
            .reserve(
                "res-conflict",
                "req-replay",
                ORG,
                Some("run-replay".to_owned()),
                41,
                70,
                10
            )
            .is_err()
    );
}

#[test]
fn ledger_identity_is_tenant_scoped() {
    let mut ledger = BudgetLedger::new(200);
    ledger
        .reserve("res-shared", "req-shared", ORG, None, 60, 70, 10)
        .unwrap();
    let other = ledger
        .reserve("res-shared", "req-shared", "org_other", None, 60, 70, 10)
        .unwrap();
    assert!(other.was_created());
    assert_eq!(ledger.reservations().len(), 2);
}

#[test]
fn ledger_expiry_releases_capacity_and_commit_accounts_actual_once() {
    let mut ledger = BudgetLedger::new(100);
    ledger
        .reserve("res-a", "req-a", ORG, None, 80, 20, 10)
        .unwrap();
    assert_eq!(ledger.live_reserved_minor(19), 80);
    assert_eq!(ledger.expire_due(20), 1);
    assert_eq!(ledger.live_reserved_minor(20), 0);
    assert!(
        ledger
            .reserve("res-b", "req-b", ORG, None, 100, 30, 20)
            .is_ok()
    );

    let mut committed_ledger = BudgetLedger::new(100);
    committed_ledger
        .reserve("res-c", "req-c", ORG, None, 80, 100, 10)
        .unwrap();
    assert!(
        committed_ledger
            .commit(ORG, "req-c", 60, 20)
            .unwrap()
            .changed()
    );
    assert_eq!(committed_ledger.spent_minor(), 60);
    assert_eq!(committed_ledger.live_reserved_minor(20), 0);
    assert_eq!(
        committed_ledger.commit(ORG, "req-c", 60, 21).unwrap(),
        ReservationTransition::Unchanged {
            state: ReservationState::Committed
        }
    );
    assert_eq!(committed_ledger.spent_minor(), 60);
}

#[test]
fn request_token_and_concurrency_policies_stack_by_scope() {
    let context = user_context();
    let org = RateLimitPolicy::new(org_scope()).with_requests_per_minute(2);
    let project = RateLimitPolicy::new(BudgetScope::project(ORG, PROJECT).unwrap())
        .with_tokens_per_minute(10);
    let user = RateLimitPolicy::new(BudgetScope::user(ORG, USER).unwrap()).with_max_concurrency(1);
    let policies = [org, project, user];

    let request = RateLimitRequest::new(1, 11, 1);
    let denied = evaluate_rate_limit_request(
        &context,
        &policies,
        RateLimitUsage::new(0, 0, 0, 0),
        request,
        1,
    );
    assert!(matches!(denied.decision, RateLimitDecision::Deny(_)));
    let RateLimitDecision::Deny(violation) = denied.decision else {
        panic!("expected a denial");
    };
    assert_eq!(violation.dimension, RateLimitDimension::Tokens);

    let allowed = evaluate_rate_limit_request(
        &context,
        &policies,
        RateLimitUsage::new(0, 0, 0, 0),
        RateLimitRequest::new(1, 10, 1),
        1,
    );
    assert!(allowed.is_allowed());
}

#[test]
fn stacked_rate_scopes_use_independent_counter_projections() {
    let context = user_context();
    let states = [
        RateLimitPolicyState::new(
            RateLimitPolicy::new(org_scope()).with_requests_per_minute(9),
            RateLimitUsage::new(0, 9, 0, 0),
        ),
        RateLimitPolicyState::new(
            RateLimitPolicy::new(BudgetScope::project(ORG, PROJECT).unwrap())
                .with_requests_per_minute(9),
            RateLimitUsage::new(0, 0, 0, 0),
        ),
    ];
    let denied = evaluate_rate_limit_states(&context, &states, RateLimitRequest::one(1), 1);
    assert!(matches!(denied.decision, RateLimitDecision::Deny(_)));
    let allowed = evaluate_rate_limit_states(
        &context,
        &[
            RateLimitPolicyState::new(states[0].policy.clone(), RateLimitUsage::new(0, 0, 0, 0)),
            states[1].clone(),
        ],
        RateLimitRequest::one(1),
        1,
    );
    assert!(allowed.is_allowed());
}

#[test]
fn rate_window_resets_request_and_token_counters_but_not_concurrency() {
    let context = user_context();
    let policy = RateLimitPolicy::new(org_scope())
        .with_requests_per_minute(1)
        .with_tokens_per_minute(5)
        .with_max_concurrency(1);
    let usage = RateLimitUsage::new(0, 1, 5, 1);
    let denied = evaluate_rate_limit_request(
        &context,
        std::slice::from_ref(&policy),
        usage,
        RateLimitRequest::one(1),
        1,
    );
    assert!(denied.decision.is_denial());

    let reset = evaluate_rate_limit_request(
        &context,
        std::slice::from_ref(&policy),
        usage,
        RateLimitRequest::one(1),
        RATE_WINDOW_SECONDS,
    );
    assert!(reset.decision.is_denial());

    let released_usage = RateLimitUsage::new(0, 1, 5, 0);
    let reset = evaluate_rate_limit_request(
        &context,
        std::slice::from_ref(&policy),
        released_usage,
        RateLimitRequest::one(1),
        RATE_WINDOW_SECONDS,
    );
    assert!(reset.is_allowed());
}

#[test]
fn rate_bucket_acquires_and_releases_concurrency_deterministically() {
    let context = user_context();
    let policy = RateLimitPolicy::new(org_scope()).with_max_concurrency(1);
    let mut bucket = RateLimitBucket::new(0);
    assert_eq!(
        bucket
            .acquire(&context, &policy, RateLimitRequest::one(1), 1)
            .unwrap(),
        RateLimitDecision::Allow
    );
    assert!(
        bucket
            .acquire(&context, &policy, RateLimitRequest::one(1), 2)
            .unwrap()
            .is_denial()
    );
    bucket.release(3).unwrap();
    assert!(
        bucket
            .acquire(&context, &policy, RateLimitRequest::one(1), 4)
            .unwrap()
            .is_allowed()
    );
}

#[test]
fn rate_counter_overflow_fails_closed() {
    let context = user_context();
    let policy = RateLimitPolicy::new(org_scope()).with_requests_per_minute(u64::MAX);
    let usage = RateLimitUsage::new(0, u64::MAX, 0, 0);
    let decision = evaluate_rate_limit_request(
        &context,
        std::slice::from_ref(&policy),
        usage,
        RateLimitRequest::new(1, 0, 0),
        1,
    );
    assert_eq!(decision.decision, RateLimitDecision::Unavailable);
}

#[test]
fn rate_evaluation_does_not_apply_other_tenant_or_principal_scopes() {
    let context = user_context();
    let other_tenant = RateLimitPolicy::new(BudgetScope::organization("org_other").unwrap())
        .with_requests_per_minute(0);
    let service_policy = RateLimitPolicy::new(BudgetScope::service_account(ORG, SERVICE).unwrap())
        .with_max_concurrency(0);
    let usage = RateLimitUsage::new(0, 0, 0, 0);
    let decision = evaluate_rate_limits(&context, &[other_tenant, service_policy], usage, 1, 1);
    assert_eq!(decision, RateLimitDecision::Allow);
}
