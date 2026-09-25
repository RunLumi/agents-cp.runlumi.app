//! P05 request/token/concurrency rate-limit evaluation.
//!
//! Rate policies use the same tenant scope vocabulary as budgets. This module
//! is pure: a D1 adapter must atomically increment the counters after this
//! decision, and must release the concurrency count on every terminal path.

use std::{cmp::Ordering, fmt};

use serde::{Deserialize, Serialize};

use super::budget_p05::{BudgetScope, ScopeContext, scope_matches};

pub const RATE_WINDOW_SECONDS: u64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitDimension {
    Requests,
    Tokens,
    Concurrency,
}

impl RateLimitDimension {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requests => "requests_per_minute",
            Self::Tokens => "tokens_per_minute",
            Self::Concurrency => "concurrent_inferences",
        }
    }

    const fn tie_break_rank(self) -> u8 {
        match self {
            Self::Requests => 1,
            Self::Tokens => 2,
            Self::Concurrency => 3,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    pub scope: BudgetScope,
    /// `None` means this dimension is unlimited for this scope.
    pub requests_per_minute: Option<u64>,
    /// `None` means this dimension is unlimited for this scope.
    pub tokens_per_minute: Option<u64>,
    /// Maximum number of active inference requests, not a rate-window count.
    pub max_concurrency: Option<u32>,
    pub enabled: bool,
}

impl RateLimitPolicy {
    pub fn new(scope: BudgetScope) -> Self {
        Self {
            scope,
            requests_per_minute: None,
            tokens_per_minute: None,
            max_concurrency: None,
            enabled: true,
        }
    }

    pub fn from_parts(
        scope_type: &str,
        organization_id: &str,
        scope_id: Option<&str>,
        requests_per_minute: Option<u64>,
        tokens_per_minute: Option<u64>,
        max_concurrency: Option<u32>,
        enabled: bool,
    ) -> Result<Self, RateLimitError> {
        let scope = BudgetScope::from_parts(scope_type, organization_id, scope_id)
            .map_err(|_| RateLimitError::InvalidPolicy)?;
        let policy = Self {
            scope,
            requests_per_minute,
            tokens_per_minute,
            max_concurrency,
            enabled,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn with_requests_per_minute(mut self, limit: u64) -> Self {
        self.requests_per_minute = Some(limit);
        self
    }

    pub fn with_tokens_per_minute(mut self, limit: u64) -> Self {
        self.tokens_per_minute = Some(limit);
        self
    }

    pub fn with_max_concurrency(mut self, limit: u32) -> Self {
        self.max_concurrency = Some(limit);
        self
    }

    pub fn with_max_concurrent_requests(self, limit: u32) -> Self {
        self.with_max_concurrency(limit)
    }

    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn has_limits(&self) -> bool {
        self.requests_per_minute.is_some()
            || self.tokens_per_minute.is_some()
            || self.max_concurrency.is_some()
    }

    pub const fn max_concurrent_requests(&self) -> Option<u32> {
        self.max_concurrency
    }

    pub fn validate(&self) -> Result<(), RateLimitError> {
        self.scope
            .validate()
            .map_err(|_| RateLimitError::InvalidPolicy)?;
        Ok(())
    }

    pub fn matches(&self, context: &ScopeContext) -> bool {
        self.enabled && scope_matches(&self.scope, context)
    }
}

/// A persisted bucket projection. `minute_started_at` is Unix seconds. The
/// request/token counters reset after a complete minute; active inference
/// count is independent of that window and must be released separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitUsage {
    pub minute_started_at: u64,
    pub requests: u64,
    pub tokens: u64,
    pub active_inferences: u32,
}

impl RateLimitUsage {
    pub fn new(minute_started_at: u64, requests: u64, tokens: u64, active_inferences: u32) -> Self {
        Self {
            minute_started_at,
            requests,
            tokens,
            active_inferences,
        }
    }

    pub fn empty(now: u64) -> Self {
        Self::new(now, 0, 0, 0)
    }

    /// Return the counters visible at `now` without mutating the projection.
    /// A future `minute_started_at` is retained rather than reset, which
    /// fails closed during clock skew.
    pub fn normalized(self, now: u64) -> Self {
        if now >= self.minute_started_at && now - self.minute_started_at >= RATE_WINDOW_SECONDS {
            Self {
                minute_started_at: now,
                requests: 0,
                tokens: 0,
                active_inferences: self.active_inferences,
            }
        } else {
            self
        }
    }

    pub fn is_window_current(self, now: u64) -> bool {
        now < self.minute_started_at.saturating_add(RATE_WINDOW_SECONDS)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitRequest {
    pub requests: u64,
    pub tokens: u64,
    pub inferences: u32,
}

impl RateLimitRequest {
    pub fn new(requests: u64, tokens: u64, inferences: u32) -> Self {
        Self {
            requests,
            tokens,
            inferences,
        }
    }

    pub fn one(tokens: u64) -> Self {
        Self::new(1, tokens, 1)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitViolation {
    pub dimension: RateLimitDimension,
    pub limit: u64,
    pub observed: u64,
    pub scope: BudgetScope,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitDecision {
    Allow,
    Deny(RateLimitViolation),
    /// The scope/usage projection is malformed or cannot be safely
    /// incremented. Managed inference must not proceed.
    Unavailable,
}

impl RateLimitDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny(violation) if violation.dimension == RateLimitDimension::Concurrency => {
                "concurrency_limit_exceeded"
            }
            Self::Deny(_) => "rate_limit_exceeded",
            Self::Unavailable => "rate_limit_state_unavailable",
        }
    }

    /// Stable API reason code for a rate decision.
    pub fn code(&self) -> &'static str {
        self.as_str()
    }

    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    pub const fn is_denial(&self) -> bool {
        matches!(self, Self::Deny(_) | Self::Unavailable)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimitEvaluation {
    pub decision: RateLimitDecision,
    pub considered_policies: usize,
}

impl RateLimitEvaluation {
    pub const fn is_allowed(&self) -> bool {
        self.decision.is_allowed()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitError {
    InvalidContext,
    InvalidPolicy,
    ScopeNotApplicable,
    CounterOverflow,
    TimeWentBackwards,
    NoActiveInference,
}

impl RateLimitError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidContext => "invalid_rate_limit_context",
            Self::InvalidPolicy => "invalid_rate_limit_policy",
            Self::ScopeNotApplicable => "rate_limit_scope_not_applicable",
            Self::CounterOverflow => "rate_limit_counter_overflow",
            Self::TimeWentBackwards => "rate_limit_time_went_backwards",
            Self::NoActiveInference => "no_active_inference",
        }
    }
}

impl fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for RateLimitError {}

/// A policy paired with the current counter projection for that policy's
/// scope. Stacked scopes have independent buckets, so persistence adapters
/// should pass one state per applicable policy rather than reusing a single
/// usage row for every scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimitPolicyState {
    pub policy: RateLimitPolicy,
    pub usage: RateLimitUsage,
}

impl RateLimitPolicyState {
    pub fn new(policy: RateLimitPolicy, usage: RateLimitUsage) -> Self {
        Self { policy, usage }
    }
}

/// Descriptive alias for adapters that call the policy plus usage row a
/// snapshot.
pub type RateLimitPolicySnapshot = RateLimitPolicyState;

/// Evaluate all enabled policies and their independent usage projections. A
/// denial is selected deterministically by pressure, then dimension, then
/// scope. The caller still has to perform every counter increment
/// conditionally in one persistence operation (or an equivalent transaction).
pub fn evaluate_rate_limit_states(
    context: &ScopeContext,
    states: &[RateLimitPolicyState],
    request: RateLimitRequest,
    now: u64,
) -> RateLimitEvaluation {
    if context.validate().is_err() {
        return RateLimitEvaluation {
            decision: RateLimitDecision::Unavailable,
            considered_policies: 0,
        };
    }

    let mut considered_policies = 0_usize;
    let mut best: Option<RateLimitViolation> = None;
    let mut counter_overflow = false;

    for state in states {
        let policy = &state.policy;
        if !policy.enabled {
            continue;
        }
        if policy.scope.organization_id == context.organization_id
            && policy.scope.validate().is_err()
        {
            return RateLimitEvaluation {
                decision: RateLimitDecision::Unavailable,
                considered_policies,
            };
        }
        if !policy.matches(context) {
            continue;
        }
        considered_policies += 1;
        let usage = state.usage.normalized(now);

        if let Some(limit) = policy.requests_per_minute {
            let Some(observed) = usage.requests.checked_add(request.requests) else {
                counter_overflow = true;
                continue;
            };
            if observed > limit {
                consider_violation(
                    &mut best,
                    RateLimitViolation {
                        dimension: RateLimitDimension::Requests,
                        limit,
                        observed,
                        scope: policy.scope.clone(),
                    },
                );
            }
        }

        if let Some(limit) = policy.tokens_per_minute {
            let Some(observed) = usage.tokens.checked_add(request.tokens) else {
                counter_overflow = true;
                continue;
            };
            if observed > limit {
                consider_violation(
                    &mut best,
                    RateLimitViolation {
                        dimension: RateLimitDimension::Tokens,
                        limit,
                        observed,
                        scope: policy.scope.clone(),
                    },
                );
            }
        }

        if let Some(limit) = policy.max_concurrency {
            let Some(observed) = usage.active_inferences.checked_add(request.inferences) else {
                counter_overflow = true;
                continue;
            };
            if observed > limit {
                consider_violation(
                    &mut best,
                    RateLimitViolation {
                        dimension: RateLimitDimension::Concurrency,
                        limit: u64::from(limit),
                        observed: u64::from(observed),
                        scope: policy.scope.clone(),
                    },
                );
            }
        }
    }

    if counter_overflow {
        return RateLimitEvaluation {
            decision: RateLimitDecision::Unavailable,
            considered_policies,
        };
    }

    RateLimitEvaluation {
        decision: best
            .map(RateLimitDecision::Deny)
            .unwrap_or(RateLimitDecision::Allow),
        considered_policies,
    }
}

/// Evaluate policies against one shared usage projection. This convenience
/// form is useful for a single bucket; use [`evaluate_rate_limit_states`] for
/// stacked scopes with independent counters.
pub fn evaluate_rate_limit_request(
    context: &ScopeContext,
    policies: &[RateLimitPolicy],
    usage: RateLimitUsage,
    request: RateLimitRequest,
    now: u64,
) -> RateLimitEvaluation {
    let states: Vec<RateLimitPolicyState> = policies
        .iter()
        .cloned()
        .map(|policy| RateLimitPolicyState::new(policy, usage))
        .collect();
    evaluate_rate_limit_states(context, &states, request, now)
}

/// Convenience wrapper for one inference request carrying a token estimate.
pub fn evaluate_rate_limits(
    context: &ScopeContext,
    policies: &[RateLimitPolicy],
    usage: RateLimitUsage,
    requested_tokens: u64,
    now: u64,
) -> RateLimitDecision {
    evaluate_rate_limit_request(
        context,
        policies,
        usage,
        RateLimitRequest::one(requested_tokens),
        now,
    )
    .decision
}

fn consider_violation(best: &mut Option<RateLimitViolation>, candidate: RateLimitViolation) {
    let replace = match best {
        None => true,
        Some(current) => violation_is_more_restrictive(&candidate, current),
    };
    if replace {
        *best = Some(candidate);
    }
}

fn violation_is_more_restrictive(
    candidate: &RateLimitViolation,
    current: &RateLimitViolation,
) -> bool {
    pressure_order(candidate, current)
        .then_with(|| {
            candidate
                .dimension
                .tie_break_rank()
                .cmp(&current.dimension.tie_break_rank())
        })
        .then_with(|| candidate.limit.cmp(&current.limit))
        .then_with(|| {
            candidate
                .scope
                .specificity()
                .cmp(&current.scope.specificity())
        })
        .then_with(|| scope_key(&candidate.scope).cmp(&scope_key(&current.scope)))
        == Ordering::Greater
}

fn pressure_order(left: &RateLimitViolation, right: &RateLimitViolation) -> Ordering {
    let left_value = if left.limit == 0 {
        u128::MAX
    } else {
        u128::from(left.observed) * u128::from(right.limit)
    };
    let right_value = if right.limit == 0 {
        u128::MAX
    } else {
        u128::from(right.observed) * u128::from(left.limit)
    };
    left_value.cmp(&right_value)
}

fn scope_key(scope: &BudgetScope) -> (&str, &str, Option<&str>) {
    (
        scope.organization_id.as_str(),
        scope.scope_type.as_str(),
        scope.scope_id.as_deref(),
    )
}

/// A small mutable model for testing atomic acquire/release behavior. It is
/// intentionally not a replacement for a D1 conditional update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitBucket {
    pub usage: RateLimitUsage,
}

impl RateLimitBucket {
    pub fn new(now: u64) -> Self {
        Self {
            usage: RateLimitUsage::empty(now),
        }
    }

    pub fn from_usage(usage: RateLimitUsage) -> Self {
        Self { usage }
    }

    pub fn acquire(
        &mut self,
        context: &ScopeContext,
        policy: &RateLimitPolicy,
        request: RateLimitRequest,
        now: u64,
    ) -> Result<RateLimitDecision, RateLimitError> {
        if context.validate().is_err() {
            return Err(RateLimitError::InvalidContext);
        }
        policy.validate()?;
        if !policy.matches(context) {
            return Err(RateLimitError::ScopeNotApplicable);
        }
        if now < self.usage.minute_started_at {
            return Err(RateLimitError::TimeWentBackwards);
        }
        let normalized = self.usage.normalized(now);
        let decision = evaluate_rate_limit_request(
            context,
            std::slice::from_ref(policy),
            normalized,
            request,
            now,
        )
        .decision;
        if !decision.is_allowed() {
            return Ok(decision);
        }

        let requests = normalized
            .requests
            .checked_add(request.requests)
            .ok_or(RateLimitError::CounterOverflow)?;
        let tokens = normalized
            .tokens
            .checked_add(request.tokens)
            .ok_or(RateLimitError::CounterOverflow)?;
        let active = normalized
            .active_inferences
            .checked_add(request.inferences)
            .ok_or(RateLimitError::CounterOverflow)?;
        self.usage = RateLimitUsage {
            minute_started_at: normalized.minute_started_at,
            requests,
            tokens,
            active_inferences: active,
        };
        Ok(RateLimitDecision::Allow)
    }

    pub fn release(&mut self, now: u64) -> Result<(), RateLimitError> {
        if now < self.usage.minute_started_at {
            return Err(RateLimitError::TimeWentBackwards);
        }
        if self.usage.active_inferences == 0 {
            // Terminal cleanup can be delivered more than once; releasing an
            // already-released slot is an idempotent no-op.
            return Ok(());
        }
        self.usage.active_inferences -= 1;
        Ok(())
    }
}

/// Re-exported scope types make this module convenient for BE adapters while
/// keeping one canonical scope representation in `budget_p05`.
pub use super::budget_p05::{BudgetScope as RateLimitScope, PrincipalKind as RatePrincipalKind};
