//! P05 budget decisions, reservations, and the pure race model used by the
//! persistence adapter.
//!
//! This module deliberately contains no D1, HTTP, or clock code. Callers pass
//! an explicit scope, a bounded integer amount, and a caller-supplied logical
//! time. The D1 adapter must perform the final capacity check and write in one
//! conditional transaction; [`BudgetLedger`] models that check for unit tests
//! and integration review, but is not an authorization or persistence layer.

use std::{cmp::Ordering, fmt};

use serde::{Deserialize, Serialize};

/// The largest amount that can be represented by the signed integer column
/// used by the existing P04 reservation table.
pub const MAX_RESERVATION_MINOR: u64 = i64::MAX as u64;

/// Reservations are leases, not open-ended holds. A persistence adapter may
/// choose a shorter product limit; this is only the safety ceiling for the
/// default pure model.
pub const MAX_RESERVATION_TTL_SECONDS: u64 = 24 * 60 * 60;
pub const TOKENS_PER_MILLION: u128 = 1_000_000;
const MAX_SCOPE_VALUE_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeType {
    Organization,
    Project,
    User,
    ServiceAccount,
    ModelAlias,
}

impl ScopeType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Organization => "organization",
            Self::Project => "project",
            Self::User => "user",
            Self::ServiceAccount => "service_account",
            Self::ModelAlias => "model_alias",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "organization" => Some(Self::Organization),
            "project" => Some(Self::Project),
            "user" => Some(Self::User),
            "service_account" => Some(Self::ServiceAccount),
            "model_alias" => Some(Self::ModelAlias),
            _ => None,
        }
    }

    pub const fn requires_scope_id(self) -> bool {
        !matches!(self, Self::Organization)
    }

    /// Higher values are more specific when two decisions have equal
    /// restrictiveness. Specificity is only a deterministic tie-breaker;
    /// the decision evaluator still checks every applicable hard policy.
    pub const fn specificity(self) -> u8 {
        match self {
            Self::Organization => 0,
            Self::Project => 1,
            Self::User | Self::ServiceAccount => 2,
            Self::ModelAlias => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    User,
    ServiceAccount,
}

impl PrincipalKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::ServiceAccount => "service_account",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "service_account" => Some(Self::ServiceAccount),
            _ => None,
        }
    }
}

/// Compatibility name for callers that use "principal type" terminology.
pub type PrincipalType = PrincipalKind;

/// The trusted request facts used to match a budget or rate-limit scope.
///
/// These values must come from the authenticated request context. The pure
/// matcher never treats a client-supplied role, credential, or policy claim
/// as authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeContext {
    pub organization_id: String,
    pub project_id: Option<String>,
    pub principal_id: String,
    pub principal_kind: PrincipalKind,
    pub model_alias: String,
}

impl ScopeContext {
    pub fn new(
        organization_id: impl Into<String>,
        project_id: Option<String>,
        principal_id: impl Into<String>,
        principal_kind: PrincipalKind,
        model_alias: impl Into<String>,
    ) -> Self {
        Self {
            organization_id: organization_id.into(),
            project_id,
            principal_id: principal_id.into(),
            principal_kind,
            model_alias: model_alias.into(),
        }
    }

    pub fn user(
        organization_id: impl Into<String>,
        project_id: Option<String>,
        principal_id: impl Into<String>,
        model_alias: impl Into<String>,
    ) -> Self {
        Self::new(
            organization_id,
            project_id,
            principal_id,
            PrincipalKind::User,
            model_alias,
        )
    }

    pub fn service_account(
        organization_id: impl Into<String>,
        project_id: Option<String>,
        principal_id: impl Into<String>,
        model_alias: impl Into<String>,
    ) -> Self {
        Self::new(
            organization_id,
            project_id,
            principal_id,
            PrincipalKind::ServiceAccount,
            model_alias,
        )
    }

    pub fn validate(&self) -> Result<(), ScopeError> {
        if !valid_scope_value(&self.organization_id) {
            return Err(ScopeError::InvalidOrganization);
        }
        if self
            .project_id
            .as_deref()
            .is_some_and(|value| !valid_scope_value(value))
        {
            return Err(ScopeError::InvalidProject);
        }
        if !valid_scope_value(&self.principal_id) {
            return Err(ScopeError::InvalidPrincipal);
        }
        if !valid_scope_value(&self.model_alias) {
            return Err(ScopeError::InvalidModelAlias);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeError {
    InvalidScopeType,
    InvalidOrganization,
    InvalidProject,
    InvalidPrincipal,
    InvalidModelAlias,
    MissingScopeId,
    UnexpectedScopeId,
}

impl ScopeError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidScopeType => "invalid_scope_type",
            Self::InvalidOrganization => "invalid_organization_scope",
            Self::InvalidProject => "invalid_project_scope",
            Self::InvalidPrincipal => "invalid_principal_scope",
            Self::InvalidModelAlias => "invalid_model_alias_scope",
            Self::MissingScopeId => "missing_scope_id",
            Self::UnexpectedScopeId => "unexpected_scope_id",
        }
    }
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ScopeError {}

/// A tenant-owned budget scope. `scope_id` is `None` only for an organization
/// scope; all other scope types require an exact, opaque scope ID.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BudgetScope {
    pub scope_type: ScopeType,
    pub organization_id: String,
    #[serde(default)]
    pub scope_id: Option<String>,
}

impl BudgetScope {
    pub fn new(
        scope_type: ScopeType,
        organization_id: impl Into<String>,
        scope_id: Option<String>,
    ) -> Result<Self, ScopeError> {
        let organization_id = organization_id.into();
        if !valid_scope_value(&organization_id) {
            return Err(ScopeError::InvalidOrganization);
        }
        if scope_type.requires_scope_id() {
            let Some(scope_id) = scope_id else {
                return Err(ScopeError::MissingScopeId);
            };
            if !valid_scope_value(&scope_id) {
                return Err(match scope_type {
                    ScopeType::Project => ScopeError::InvalidProject,
                    ScopeType::User | ScopeType::ServiceAccount => ScopeError::InvalidPrincipal,
                    ScopeType::ModelAlias => ScopeError::InvalidModelAlias,
                    ScopeType::Organization => ScopeError::UnexpectedScopeId,
                });
            }
            Ok(Self {
                scope_type,
                organization_id,
                scope_id: Some(scope_id),
            })
        } else if scope_id.is_some() {
            Err(ScopeError::UnexpectedScopeId)
        } else {
            Ok(Self {
                scope_type,
                organization_id,
                scope_id: None,
            })
        }
    }

    pub fn from_parts(
        scope_type: &str,
        organization_id: &str,
        scope_id: Option<&str>,
    ) -> Result<Self, ScopeError> {
        let scope_type = ScopeType::parse(scope_type).ok_or(ScopeError::InvalidScopeType)?;
        Self::new(scope_type, organization_id, scope_id.map(str::to_owned))
    }

    pub fn organization(organization_id: impl Into<String>) -> Result<Self, ScopeError> {
        Self::new(ScopeType::Organization, organization_id, None)
    }

    pub fn project(
        organization_id: impl Into<String>,
        project_id: impl Into<String>,
    ) -> Result<Self, ScopeError> {
        Self::new(ScopeType::Project, organization_id, Some(project_id.into()))
    }

    pub fn user(
        organization_id: impl Into<String>,
        user_id: impl Into<String>,
    ) -> Result<Self, ScopeError> {
        Self::new(ScopeType::User, organization_id, Some(user_id.into()))
    }

    pub fn service_account(
        organization_id: impl Into<String>,
        service_account_id: impl Into<String>,
    ) -> Result<Self, ScopeError> {
        Self::new(
            ScopeType::ServiceAccount,
            organization_id,
            Some(service_account_id.into()),
        )
    }

    pub fn model_alias(
        organization_id: impl Into<String>,
        model_alias: impl Into<String>,
    ) -> Result<Self, ScopeError> {
        Self::new(
            ScopeType::ModelAlias,
            organization_id,
            Some(model_alias.into()),
        )
    }

    pub fn validate(&self) -> Result<(), ScopeError> {
        if !valid_scope_value(&self.organization_id) {
            return Err(ScopeError::InvalidOrganization);
        }
        match (
            self.scope_type.requires_scope_id(),
            self.scope_id.as_deref(),
        ) {
            (true, Some(scope_id)) if valid_scope_value(scope_id) => Ok(()),
            (true, Some(_)) => Err(match self.scope_type {
                ScopeType::Project => ScopeError::InvalidProject,
                ScopeType::User | ScopeType::ServiceAccount => ScopeError::InvalidPrincipal,
                ScopeType::ModelAlias => ScopeError::InvalidModelAlias,
                ScopeType::Organization => ScopeError::UnexpectedScopeId,
            }),
            (true, None) => Err(ScopeError::MissingScopeId),
            (false, None) => Ok(()),
            (false, Some(_)) => Err(ScopeError::UnexpectedScopeId),
        }
    }

    pub fn matches(&self, context: &ScopeContext) -> bool {
        scope_matches(self, context)
    }

    pub const fn specificity(&self) -> u8 {
        self.scope_type.specificity()
    }
}

/// Match a policy scope against trusted request facts. Exact organization
/// matching is always required; a scope from another tenant can never apply.
pub fn scope_matches(scope: &BudgetScope, context: &ScopeContext) -> bool {
    if context.validate().is_err()
        || scope.validate().is_err()
        || scope.organization_id != context.organization_id
    {
        return false;
    }

    match scope.scope_type {
        ScopeType::Organization => {
            scope.scope_id.is_none() && valid_scope_value(&scope.organization_id)
        }
        ScopeType::Project => {
            context.project_id.as_deref().is_some_and(valid_scope_value)
                && context.project_id.as_deref() == scope.scope_id.as_deref()
                && scope.scope_id.as_deref().is_some_and(valid_scope_value)
        }
        ScopeType::User => {
            context.principal_kind == PrincipalKind::User
                && valid_scope_value(&context.principal_id)
                && context.principal_id == scope.scope_id.as_deref().unwrap_or_default()
                && scope.scope_id.as_deref().is_some_and(valid_scope_value)
        }
        ScopeType::ServiceAccount => {
            context.principal_kind == PrincipalKind::ServiceAccount
                && valid_scope_value(&context.principal_id)
                && context.principal_id == scope.scope_id.as_deref().unwrap_or_default()
                && scope.scope_id.as_deref().is_some_and(valid_scope_value)
        }
        ScopeType::ModelAlias => {
            valid_scope_value(&context.model_alias)
                && context.model_alias == scope.scope_id.as_deref().unwrap_or_default()
                && scope.scope_id.as_deref().is_some_and(valid_scope_value)
        }
    }
}

/// Return the applicable scopes in a deterministic order. The evaluator
/// itself does not rely on this order for hard-limit correctness.
pub fn matching_scopes<'a>(
    context: &ScopeContext,
    scopes: &'a [BudgetScope],
) -> Vec<&'a BudgetScope> {
    let mut matching: Vec<&BudgetScope> = scopes
        .iter()
        .filter(|scope| scope.matches(context))
        .collect();
    matching.sort_by(|left, right| scope_order(left, right));
    matching
}

fn scope_order(left: &BudgetScope, right: &BudgetScope) -> Ordering {
    right
        .specificity()
        .cmp(&left.specificity())
        .then_with(|| left.scope_type.as_str().cmp(right.scope_type.as_str()))
        .then_with(|| left.scope_id.cmp(&right.scope_id))
        .then_with(|| left.organization_id.cmp(&right.organization_id))
}

fn valid_scope_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SCOPE_VALUE_BYTES
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetKind {
    Soft,
    Hard,
}

impl BudgetKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Soft => "soft",
            Self::Hard => "hard",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "soft" => Some(Self::Soft),
            "hard" => Some(Self::Hard),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetAvailability {
    Available,
    Unavailable,
}

impl BudgetAvailability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unavailable => "unavailable",
        }
    }

    pub const fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }
}

/// Alias used by persistence adapters when they pass a state read result.
pub type BudgetState = BudgetAvailability;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetError {
    InvalidScope,
    InvalidContext,
    InvalidAmount,
    ReservationTooLarge,
    InvalidExpiry,
    ReservationTtlTooLong,
    CapacityExceeded,
    ArithmeticOverflow,
    InvalidPeriod,
    IdentityConflict,
    ReservationNotFound,
    ReservationNotReserved,
    ReservationExpired,
    AlreadyReconciled,
    ActualExceedsReservation,
    InvalidReconciliation,
    TimeWentBackwards,
}

impl BudgetError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidScope => "invalid_budget_scope",
            Self::InvalidContext => "invalid_budget_context",
            Self::InvalidAmount => "invalid_reservation_amount",
            Self::ReservationTooLarge => "reservation_too_large",
            Self::InvalidExpiry => "invalid_reservation_expiry",
            Self::ReservationTtlTooLong => "reservation_ttl_too_long",
            Self::CapacityExceeded => "budget_exceeded",
            Self::ArithmeticOverflow => "budget_arithmetic_overflow",
            Self::InvalidPeriod => "invalid_budget_period",
            Self::IdentityConflict => "reservation_identity_conflict",
            Self::ReservationNotFound => "reservation_not_found",
            Self::ReservationNotReserved => "reservation_not_reserved",
            Self::ReservationExpired => "reservation_expired",
            Self::AlreadyReconciled => "reservation_already_reconciled",
            Self::ActualExceedsReservation => "actual_cost_exceeds_reservation",
            Self::InvalidReconciliation => "invalid_reservation_reconciliation",
            Self::TimeWentBackwards => "reservation_time_went_backwards",
        }
    }
}

impl fmt::Display for BudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for BudgetError {}

/// Integer pricing inputs used to produce a bounded reservation estimate.
/// Rates are minor units per million tokens; no floating-point money is
/// accepted by this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenPricing {
    pub input_minor_per_million: u64,
    pub output_minor_per_million: u64,
}

impl TokenPricing {
    pub const fn new(input_minor_per_million: u64, output_minor_per_million: u64) -> Self {
        Self {
            input_minor_per_million,
            output_minor_per_million,
        }
    }

    pub fn estimate_minor(
        self,
        input_tokens: u64,
        output_tokens: u64,
        max_minor: u64,
    ) -> Result<u64, BudgetError> {
        calculate_reservation_minor(
            input_tokens,
            output_tokens,
            self.input_minor_per_million,
            self.output_minor_per_million,
            max_minor,
        )
    }
}

/// Calculate a conservative integer reservation estimate. Each token bucket
/// is rounded up independently, so the result never under-reserves a bounded
/// estimate. Intermediate arithmetic uses `u128`, and the result is checked
/// against both the signed D1 ceiling and the caller's product bound.
pub fn calculate_reservation_minor(
    input_tokens: u64,
    output_tokens: u64,
    input_minor_per_million: u64,
    output_minor_per_million: u64,
    max_minor: u64,
) -> Result<u64, BudgetError> {
    let input_minor = ceil_token_cost(input_tokens, input_minor_per_million)?;
    let output_minor = ceil_token_cost(output_tokens, output_minor_per_million)?;
    let total = input_minor
        .checked_add(output_minor)
        .ok_or(BudgetError::ArithmeticOverflow)?;
    if total > max_minor || total > MAX_RESERVATION_MINOR {
        return Err(BudgetError::ReservationTooLarge);
    }
    Ok(total)
}

/// Compatibility alias for adapters that use "estimate" terminology.
pub fn estimate_reservation_minor(
    input_tokens: u64,
    output_tokens: u64,
    input_minor_per_million: u64,
    output_minor_per_million: u64,
    max_minor: u64,
) -> Result<u64, BudgetError> {
    calculate_reservation_minor(
        input_tokens,
        output_tokens,
        input_minor_per_million,
        output_minor_per_million,
        max_minor,
    )
}

fn ceil_token_cost(tokens: u64, rate_minor_per_million: u64) -> Result<u64, BudgetError> {
    let whole_tokens = u128::from(tokens / 1_000_000);
    let remainder_tokens = u128::from(tokens % 1_000_000);
    let whole_minor = whole_tokens
        .checked_mul(u128::from(rate_minor_per_million))
        .ok_or(BudgetError::ArithmeticOverflow)?;
    let partial_numerator = remainder_tokens
        .checked_mul(u128::from(rate_minor_per_million))
        .and_then(|value| value.checked_add(TOKENS_PER_MILLION - 1))
        .ok_or(BudgetError::ArithmeticOverflow)?;
    let total_minor = whole_minor
        .checked_add(partial_numerator / TOKENS_PER_MILLION)
        .ok_or(BudgetError::ArithmeticOverflow)?;
    u64::try_from(total_minor).map_err(|_| BudgetError::ReservationTooLarge)
}

/// Compatibility alias for callers that reserve the state-transition error
/// type under its domain-specific name.
pub type ReservationError = BudgetError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDecision {
    /// Eligible work may dispatch without crossing a configured threshold.
    Allow,
    /// A soft threshold was reached; dispatch remains eligible.
    SoftLimit,
    /// A hard threshold would be crossed, or the request cannot be safely
    /// admitted because its amount is invalid.
    Deny,
    /// Authoritative hard-budget state was unavailable. Managed cloud work
    /// fails closed; local-only work may be represented separately by the
    /// caller.
    Unavailable,
}

impl BudgetDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::SoftLimit => "soft_limit",
            Self::Deny => "deny",
            Self::Unavailable => "unavailable",
        }
    }

    /// Stable API reason code for a budget decision.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::SoftLimit => "soft_limit_reached",
            Self::Deny => "budget_exceeded",
            Self::Unavailable => "budget_state_unavailable",
        }
    }

    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allow | Self::SoftLimit)
    }

    pub const fn blocks_cloud_dispatch(self) -> bool {
        matches!(self, Self::Deny | Self::Unavailable)
    }

    /// Short aliases make call sites read naturally without creating a
    /// second decision vocabulary.
    pub const SOFT: Self = Self::SoftLimit;
    pub const HARD: Self = Self::Deny;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDecisionReason {
    NoApplicablePolicy,
    WithinLimit,
    SoftLimitReached,
    HardLimitExceeded,
    BudgetStateUnavailable,
    SoftBudgetStateUnavailable,
    LocalOnly,
    InvalidAmount,
    InvalidContext,
    InvalidPeriod,
}

impl BudgetDecisionReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoApplicablePolicy => "no_applicable_budget",
            Self::WithinLimit => "within_budget",
            Self::SoftLimitReached => "soft_limit_reached",
            Self::HardLimitExceeded => "budget_exceeded",
            Self::BudgetStateUnavailable => "budget_state_unavailable",
            Self::SoftBudgetStateUnavailable => "soft_budget_state_unavailable",
            Self::LocalOnly => "local_only_execution",
            Self::InvalidAmount => "invalid_reservation_amount",
            Self::InvalidContext => "invalid_budget_context",
            Self::InvalidPeriod => "invalid_budget_period",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetEvaluation {
    pub decision: BudgetDecision,
    pub reason: BudgetDecisionReason,
    pub matched_scope: Option<BudgetScope>,
    pub considered_policies: usize,
    pub eligible_cloud: bool,
}

impl BudgetEvaluation {
    pub const fn is_allowed(&self) -> bool {
        self.decision.is_allowed()
    }

    pub const fn blocks_cloud_dispatch(&self) -> bool {
        self.decision.blocks_cloud_dispatch()
    }
}

/// A current policy projection. Period fields are optional because a D1
/// adapter normally filters to the active row; when present they are checked
/// again in the pure evaluator so a stale caller cannot broaden a period.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetPolicy {
    pub scope: BudgetScope,
    pub kind: BudgetKind,
    pub limit_minor: u64,
    pub committed_minor: u64,
    /// Outstanding hold only (`reserved_minor - committed_minor` in the
    /// persistence row); terminal reservations must not be counted again.
    pub reserved_minor: u64,
    pub availability: BudgetAvailability,
    pub active: bool,
    pub period_start: Option<u64>,
    pub period_end: Option<u64>,
}

impl BudgetPolicy {
    pub fn new(scope: BudgetScope, kind: BudgetKind, limit_minor: u64) -> Self {
        Self {
            scope,
            kind,
            limit_minor,
            committed_minor: 0,
            reserved_minor: 0,
            availability: BudgetAvailability::Available,
            active: true,
            period_start: None,
            period_end: None,
        }
    }

    pub fn soft(scope: BudgetScope, limit_minor: u64) -> Self {
        Self::new(scope, BudgetKind::Soft, limit_minor)
    }

    pub fn hard(scope: BudgetScope, limit_minor: u64) -> Self {
        Self::new(scope, BudgetKind::Hard, limit_minor)
    }

    pub fn with_usage(mut self, committed_minor: u64, reserved_minor: u64) -> Self {
        self.committed_minor = committed_minor;
        self.reserved_minor = reserved_minor;
        self
    }

    pub fn unavailable(mut self) -> Self {
        self.availability = BudgetAvailability::Unavailable;
        self
    }

    pub fn with_active(mut self, active: bool) -> Self {
        self.active = active;
        self
    }

    pub fn try_with_period(
        mut self,
        period_start: u64,
        period_end: u64,
    ) -> Result<Self, BudgetError> {
        if period_end <= period_start {
            return Err(BudgetError::InvalidPeriod);
        }
        self.period_start = Some(period_start);
        self.period_end = Some(period_end);
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), BudgetError> {
        self.scope
            .validate()
            .map_err(|_| BudgetError::InvalidScope)?;
        match (self.period_start, self.period_end) {
            (None, None) => {}
            (Some(start), Some(end)) if start < end => {}
            _ => return Err(BudgetError::InvalidPeriod),
        }
        if self.kind == BudgetKind::Hard
            && (self.limit_minor > MAX_RESERVATION_MINOR
                || self.committed_minor > MAX_RESERVATION_MINOR
                || self.reserved_minor > MAX_RESERVATION_MINOR)
        {
            return Err(BudgetError::ReservationTooLarge);
        }
        Ok(())
    }

    pub fn applies_at(&self, context: &ScopeContext, now: u64) -> bool {
        if !self.active || !self.scope.matches(context) {
            return false;
        }
        match (self.period_start, self.period_end) {
            (None, None) => true,
            (Some(start), Some(end)) if start < end => start <= now && now < end,
            _ => false,
        }
    }

    /// Current live spend after committed usage and outstanding reservations.
    /// Invalid arithmetic is represented by `None`; evaluators fail closed
    /// for hard policies rather than turning an overflow into capacity.
    pub fn used_minor(&self) -> Option<u64> {
        self.committed_minor.checked_add(self.reserved_minor)
    }

    pub fn remaining_minor(&self) -> Option<u64> {
        self.used_minor()
            .map(|used| self.limit_minor.saturating_sub(used))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetEvaluationRequest {
    pub context: ScopeContext,
    pub requested_minor: u64,
    pub eligible_cloud: bool,
    pub now: u64,
}

impl BudgetEvaluationRequest {
    pub fn new(
        context: ScopeContext,
        requested_minor: u64,
        eligible_cloud: bool,
        now: u64,
    ) -> Self {
        Self {
            context,
            requested_minor,
            eligible_cloud,
            now,
        }
    }
}

/// Evaluate every applicable policy and select the most restrictive result.
/// The function is total: malformed cloud input becomes a closed decision,
/// never a panic or an accidental allow.
pub fn evaluate_budget_request(
    request: &BudgetEvaluationRequest,
    policies: &[BudgetPolicy],
) -> BudgetEvaluation {
    let mut considered_policies = 0_usize;
    let mut best: Option<(BudgetDecision, BudgetDecisionReason, BudgetScope, u8, u64)> = None;
    let mut saw_soft_unavailable = false;

    if request.context.validate().is_err() {
        return BudgetEvaluation {
            decision: if request.eligible_cloud {
                BudgetDecision::Unavailable
            } else {
                BudgetDecision::Allow
            },
            reason: if request.eligible_cloud {
                BudgetDecisionReason::InvalidContext
            } else {
                BudgetDecisionReason::LocalOnly
            },
            matched_scope: None,
            considered_policies: 0,
            eligible_cloud: request.eligible_cloud,
        };
    }

    if request.requested_minor == 0 {
        return BudgetEvaluation {
            decision: BudgetDecision::Allow,
            reason: BudgetDecisionReason::WithinLimit,
            matched_scope: None,
            considered_policies: 0,
            eligible_cloud: request.eligible_cloud,
        };
    }

    if request.requested_minor > MAX_RESERVATION_MINOR {
        return BudgetEvaluation {
            decision: if request.eligible_cloud {
                BudgetDecision::Deny
            } else {
                BudgetDecision::Allow
            },
            reason: if request.eligible_cloud {
                BudgetDecisionReason::InvalidAmount
            } else {
                BudgetDecisionReason::LocalOnly
            },
            matched_scope: None,
            considered_policies: 0,
            eligible_cloud: request.eligible_cloud,
        };
    }

    for policy in policies {
        if !policy.active {
            continue;
        }
        if policy.scope.organization_id == request.context.organization_id
            && policy.scope.validate().is_err()
        {
            if policy.kind == BudgetKind::Hard {
                considered_policies += 1;
                consider_candidate(
                    &mut best,
                    BudgetDecision::Unavailable,
                    BudgetDecisionReason::InvalidContext,
                    policy,
                );
            }
            continue;
        }
        if !policy.scope.matches(&request.context) {
            continue;
        }
        if policy.kind == BudgetKind::Hard
            && (policy.limit_minor > MAX_RESERVATION_MINOR
                || policy.committed_minor > MAX_RESERVATION_MINOR
                || policy.reserved_minor > MAX_RESERVATION_MINOR)
        {
            considered_policies += 1;
            consider_candidate(
                &mut best,
                BudgetDecision::Unavailable,
                BudgetDecisionReason::BudgetStateUnavailable,
                policy,
            );
            continue;
        }

        match (policy.period_start, policy.period_end) {
            (None, None) => {}
            (Some(start), Some(end)) if start < end => {
                // A well-formed period outside the current window is simply
                // not applicable. Only malformed bounds fail closed.
                if request.now < start || request.now >= end {
                    continue;
                }
            }
            _ => {
                // An invalid period is not authority to ignore a hard policy.
                if policy.kind == BudgetKind::Hard {
                    considered_policies += 1;
                    consider_candidate(
                        &mut best,
                        BudgetDecision::Unavailable,
                        BudgetDecisionReason::InvalidPeriod,
                        policy,
                    );
                }
                continue;
            }
        }
        considered_policies += 1;

        if !policy.availability.is_available() {
            if policy.kind == BudgetKind::Hard {
                consider_candidate(
                    &mut best,
                    BudgetDecision::Unavailable,
                    BudgetDecisionReason::BudgetStateUnavailable,
                    policy,
                );
            } else {
                saw_soft_unavailable = true;
            }
            continue;
        }

        let Some(used) = policy.used_minor() else {
            if policy.kind == BudgetKind::Hard {
                consider_candidate(
                    &mut best,
                    BudgetDecision::Unavailable,
                    BudgetDecisionReason::BudgetStateUnavailable,
                    policy,
                );
            } else {
                saw_soft_unavailable = true;
            }
            continue;
        };
        let Some(projected) = used.checked_add(request.requested_minor) else {
            if policy.kind == BudgetKind::Hard {
                consider_candidate(
                    &mut best,
                    BudgetDecision::Unavailable,
                    BudgetDecisionReason::BudgetStateUnavailable,
                    policy,
                );
            } else {
                saw_soft_unavailable = true;
            }
            continue;
        };

        match policy.kind {
            BudgetKind::Hard if projected > policy.limit_minor => consider_candidate(
                &mut best,
                BudgetDecision::Deny,
                BudgetDecisionReason::HardLimitExceeded,
                policy,
            ),
            BudgetKind::Soft if projected >= policy.limit_minor => consider_candidate(
                &mut best,
                BudgetDecision::SoftLimit,
                BudgetDecisionReason::SoftLimitReached,
                policy,
            ),
            BudgetKind::Hard | BudgetKind::Soft => {}
        }
    }

    let Some((decision, reason, scope, _, _)) = best else {
        return BudgetEvaluation {
            decision: BudgetDecision::Allow,
            reason: if saw_soft_unavailable {
                BudgetDecisionReason::SoftBudgetStateUnavailable
            } else if considered_policies > 0 {
                BudgetDecisionReason::WithinLimit
            } else {
                BudgetDecisionReason::NoApplicablePolicy
            },
            matched_scope: None,
            considered_policies,
            eligible_cloud: request.eligible_cloud,
        };
    };

    if !request.eligible_cloud && decision.blocks_cloud_dispatch() {
        return BudgetEvaluation {
            decision: BudgetDecision::Allow,
            reason: BudgetDecisionReason::LocalOnly,
            matched_scope: Some(scope),
            considered_policies,
            eligible_cloud: false,
        };
    }

    BudgetEvaluation {
        decision,
        reason,
        matched_scope: Some(scope),
        considered_policies,
        eligible_cloud: request.eligible_cloud,
    }
}

fn consider_candidate(
    best: &mut Option<(BudgetDecision, BudgetDecisionReason, BudgetScope, u8, u64)>,
    decision: BudgetDecision,
    reason: BudgetDecisionReason,
    policy: &BudgetPolicy,
) {
    let candidate = (
        decision,
        reason,
        policy.scope.clone(),
        policy.scope.specificity(),
        policy.limit_minor,
    );
    let replace = match best {
        None => true,
        Some((
            current_decision,
            current_reason,
            current_scope,
            current_specificity,
            current_limit,
        )) => {
            let same_decision = decision_rank(decision) == decision_rank(*current_decision);
            decision_rank(decision) > decision_rank(*current_decision)
                || (same_decision
                    && (policy.scope.specificity() > *current_specificity
                        || (policy.scope.specificity() == *current_specificity
                            && (policy.limit_minor < *current_limit
                                || (policy.limit_minor == *current_limit
                                    && (scope_order(&policy.scope, current_scope)
                                        == Ordering::Less
                                        || (scope_order(&policy.scope, current_scope)
                                            == Ordering::Equal
                                            && reason.as_str() > current_reason.as_str())))))))
        }
    };
    if replace {
        *best = Some(candidate);
    }
}

fn decision_rank(decision: BudgetDecision) -> u8 {
    match decision {
        BudgetDecision::Allow => 1,
        BudgetDecision::SoftLimit => 2,
        BudgetDecision::Deny => 3,
        // Unknown authoritative state is closed before a known denial so a
        // caller cannot accidentally choose a less-safe explanation.
        BudgetDecision::Unavailable => 4,
    }
}

/// Convenience wrapper for a cloud/local request. `now` is Unix seconds.
pub fn evaluate_budgets(
    context: &ScopeContext,
    policies: &[BudgetPolicy],
    requested_minor: u64,
    eligible_cloud: bool,
    now: u64,
) -> BudgetEvaluation {
    evaluate_budget_request(
        &BudgetEvaluationRequest::new(context.clone(), requested_minor, eligible_cloud, now),
        policies,
    )
}

/// Strict wrapper for adapters that want malformed scope/period data surfaced
/// as a typed error before performing a persistence attempt.
pub fn try_evaluate_budgets(
    request: &BudgetEvaluationRequest,
    policies: &[BudgetPolicy],
) -> Result<BudgetEvaluation, BudgetError> {
    request
        .context
        .validate()
        .map_err(|_| BudgetError::InvalidContext)?;
    if request.requested_minor > MAX_RESERVATION_MINOR {
        return Err(BudgetError::ReservationTooLarge);
    }
    for policy in policies {
        if !policy.active || policy.scope.organization_id != request.context.organization_id {
            continue;
        }
        policy
            .scope
            .validate()
            .map_err(|_| BudgetError::InvalidScope)?;
        if matches!((policy.period_start, policy.period_end), (Some(start), Some(end)) if start >= end)
        {
            return Err(BudgetError::InvalidPeriod);
        }
        if policy.kind == BudgetKind::Hard
            && (policy.limit_minor > MAX_RESERVATION_MINOR
                || policy.committed_minor > MAX_RESERVATION_MINOR
                || policy.reserved_minor > MAX_RESERVATION_MINOR)
        {
            return Err(BudgetError::ReservationTooLarge);
        }
    }
    Ok(evaluate_budget_request(request, policies))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationState {
    Reserved,
    Committed,
    Released,
    Expired,
}

impl ReservationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Committed => "committed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }

    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationTransition {
    Applied { state: ReservationState },
    Unchanged { state: ReservationState },
}

impl ReservationTransition {
    pub const fn changed(self) -> bool {
        matches!(self, Self::Applied { .. })
    }

    pub const fn state(self) -> ReservationState {
        match self {
            Self::Applied { state } | Self::Unchanged { state } => state,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetReservation {
    pub reservation_id: String,
    pub request_id: String,
    pub org_id: String,
    pub run_id: Option<String>,
    pub reserved_minor: u64,
    pub committed_minor: u64,
    pub state: ReservationState,
    pub expires_at: u64,
    pub created_at: u64,
    pub updated_at: u64,
}

impl BudgetReservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reservation_id: impl Into<String>,
        request_id: impl Into<String>,
        org_id: impl Into<String>,
        run_id: Option<String>,
        reserved_minor: u64,
        expires_at: u64,
        now: u64,
    ) -> Result<Self, BudgetError> {
        let reservation = Self {
            reservation_id: reservation_id.into(),
            request_id: request_id.into(),
            org_id: org_id.into(),
            run_id,
            reserved_minor,
            committed_minor: 0,
            state: ReservationState::Reserved,
            expires_at,
            created_at: now,
            updated_at: now,
        };
        reservation.validate_identity()?;
        validate_reservation_amount(reserved_minor)?;
        validate_expiry(now, expires_at)?;
        Ok(reservation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        reservation_id: impl Into<String>,
        request_id: impl Into<String>,
        org_id: impl Into<String>,
        run_id: Option<String>,
        reserved_minor: u64,
        committed_minor: u64,
        state: ReservationState,
        expires_at: u64,
        created_at: u64,
        updated_at: u64,
    ) -> Result<Self, BudgetError> {
        let reservation = Self {
            reservation_id: reservation_id.into(),
            request_id: request_id.into(),
            org_id: org_id.into(),
            run_id,
            reserved_minor,
            committed_minor,
            state,
            expires_at,
            created_at,
            updated_at,
        };
        reservation.validate_identity()?;
        validate_reservation_amount(reserved_minor)?;
        if committed_minor > reserved_minor {
            return Err(BudgetError::ActualExceedsReservation);
        }
        match state {
            ReservationState::Reserved if committed_minor != 0 => {
                return Err(BudgetError::InvalidReconciliation);
            }
            ReservationState::Released | ReservationState::Expired if committed_minor != 0 => {
                return Err(BudgetError::InvalidReconciliation);
            }
            ReservationState::Reserved
            | ReservationState::Committed
            | ReservationState::Released
            | ReservationState::Expired => {}
        }
        if expires_at <= created_at || updated_at < created_at {
            return Err(BudgetError::InvalidExpiry);
        }
        if state == ReservationState::Reserved {
            validate_expiry(created_at, expires_at)?;
        }
        Ok(reservation)
    }

    pub fn validate_identity(&self) -> Result<(), BudgetError> {
        if !valid_reservation_value(&self.reservation_id)
            || !valid_reservation_value(&self.request_id)
            || !valid_reservation_value(&self.org_id)
            || self
                .run_id
                .as_deref()
                .is_some_and(|value| !valid_reservation_value(value))
        {
            return Err(BudgetError::InvalidScope);
        }
        Ok(())
    }

    pub fn state(&self) -> ReservationState {
        self.state
    }

    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    pub fn outstanding_minor(&self) -> u64 {
        match self.state {
            ReservationState::Reserved => self.reserved_minor,
            ReservationState::Committed
            | ReservationState::Released
            | ReservationState::Expired => 0,
        }
    }

    pub fn is_live_at(&self, now: u64) -> bool {
        self.state == ReservationState::Reserved && now < self.expires_at
    }

    pub fn is_expired_at(&self, now: u64) -> bool {
        self.state == ReservationState::Reserved && now >= self.expires_at
    }

    pub fn commit(
        &mut self,
        actual_minor: u64,
        now: u64,
    ) -> Result<ReservationTransition, BudgetError> {
        self.reject_if_expired(now)?;
        if actual_minor > self.reserved_minor {
            return Err(BudgetError::ActualExceedsReservation);
        }
        match self.state {
            ReservationState::Reserved => {
                self.ensure_time_can_advance(now)?;
                self.state = ReservationState::Committed;
                self.committed_minor = actual_minor;
                self.updated_at = now;
                Ok(ReservationTransition::Applied { state: self.state })
            }
            ReservationState::Committed if self.committed_minor == actual_minor => {
                Ok(ReservationTransition::Unchanged { state: self.state })
            }
            ReservationState::Committed
            | ReservationState::Released
            | ReservationState::Expired => Err(BudgetError::AlreadyReconciled),
        }
    }

    pub fn release(&mut self, now: u64) -> Result<ReservationTransition, BudgetError> {
        self.reject_if_expired(now)?;
        match self.state {
            ReservationState::Reserved => {
                self.ensure_time_can_advance(now)?;
                self.state = ReservationState::Released;
                self.updated_at = now;
                Ok(ReservationTransition::Applied { state: self.state })
            }
            ReservationState::Released => {
                Ok(ReservationTransition::Unchanged { state: self.state })
            }
            ReservationState::Committed | ReservationState::Expired => {
                Err(BudgetError::AlreadyReconciled)
            }
        }
    }

    pub fn expire(&mut self, now: u64) -> Result<ReservationTransition, BudgetError> {
        match self.state {
            ReservationState::Reserved if now >= self.expires_at => {
                self.ensure_time_can_advance(now)?;
                self.state = ReservationState::Expired;
                self.updated_at = now;
                Ok(ReservationTransition::Applied { state: self.state })
            }
            ReservationState::Reserved => {
                Ok(ReservationTransition::Unchanged { state: self.state })
            }
            ReservationState::Committed
            | ReservationState::Released
            | ReservationState::Expired => {
                Ok(ReservationTransition::Unchanged { state: self.state })
            }
        }
    }

    pub fn reconcile(
        &mut self,
        actual_minor: u64,
        status: ReservationReconciliation,
        now: u64,
    ) -> Result<ReservationTransition, BudgetError> {
        match status {
            ReservationReconciliation::Commit => self.commit(actual_minor, now),
            ReservationReconciliation::Release => self.release(now),
            ReservationReconciliation::Expire => self.expire(now),
        }
    }

    fn ensure_time_can_advance(&self, now: u64) -> Result<(), BudgetError> {
        if now < self.updated_at {
            Err(BudgetError::TimeWentBackwards)
        } else {
            Ok(())
        }
    }

    fn reject_if_expired(&mut self, now: u64) -> Result<(), BudgetError> {
        if self.state == ReservationState::Reserved && now >= self.expires_at {
            self.expire(now)?;
            return Err(BudgetError::ReservationExpired);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationReconciliation {
    Commit,
    Release,
    Expire,
}

/// Alias matching the API's `status` vocabulary.
pub type ReservationStatus = ReservationReconciliation;

fn valid_reservation_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SCOPE_VALUE_BYTES
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn validate_reservation_amount(amount: u64) -> Result<(), BudgetError> {
    if amount == 0 {
        Err(BudgetError::InvalidAmount)
    } else if amount > MAX_RESERVATION_MINOR {
        Err(BudgetError::ReservationTooLarge)
    } else {
        Ok(())
    }
}

fn validate_expiry(now: u64, expires_at: u64) -> Result<(), BudgetError> {
    if expires_at <= now {
        return Err(BudgetError::InvalidExpiry);
    }
    if expires_at - now > MAX_RESERVATION_TTL_SECONDS {
        return Err(BudgetError::ReservationTtlTooLong);
    }
    Ok(())
}

/// A point-in-time hard-budget projection. `can_reserve` is deliberately only
/// an advisory preflight; a persistence write must repeat the check against
/// current committed usage and live reservations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetSnapshot {
    pub limit_minor: u64,
    pub spent_minor: u64,
    pub live_reserved_minor: u64,
    pub max_reservation_minor: u64,
    pub observed_at: u64,
}

impl BudgetSnapshot {
    pub fn used_minor(self) -> Option<u64> {
        self.spent_minor.checked_add(self.live_reserved_minor)
    }

    pub fn remaining_minor(self) -> Option<u64> {
        self.limit_minor.checked_sub(self.used_minor()?)
    }

    pub fn can_reserve(self, amount: u64) -> bool {
        if amount == 0 || amount > self.max_reservation_minor || amount > MAX_RESERVATION_MINOR {
            return false;
        }
        let Some(projected) = self.used_minor().and_then(|used| used.checked_add(amount)) else {
            return false;
        };
        projected <= self.limit_minor
    }

    pub fn can_admit(self, amount: u64) -> bool {
        self.can_reserve(amount)
    }
}

/// Apply the same admission predicate to every applicable hard-budget scope.
/// An empty list means no hard budget is configured and is therefore
/// admissible; any one restrictive scope makes the whole request fail.
pub fn can_reserve_all(snapshots: &[BudgetSnapshot], amount: u64) -> bool {
    amount > 0
        && amount <= MAX_RESERVATION_MINOR
        && snapshots
            .iter()
            .all(|snapshot| snapshot.can_reserve(amount))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReservationAdmission {
    Created(BudgetReservation),
    Existing(BudgetReservation),
}

impl ReservationAdmission {
    pub fn reservation(&self) -> &BudgetReservation {
        match self {
            Self::Created(reservation) | Self::Existing(reservation) => reservation,
        }
    }

    pub fn into_reservation(self) -> BudgetReservation {
        match self {
            Self::Created(reservation) | Self::Existing(reservation) => reservation,
        }
    }

    pub const fn was_created(&self) -> bool {
        matches!(self, Self::Created(_))
    }
}

/// Deterministic in-memory model of one hard budget's conditional reservation
/// operation. The D1 adapter should use the same predicate inside its
/// transaction; cloning this model is useful for race-case tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetLedger {
    limit_minor: u64,
    spent_minor: u64,
    max_reservation_minor: u64,
    reservations: Vec<BudgetReservation>,
}

impl BudgetLedger {
    pub fn new(limit_minor: u64) -> Self {
        Self {
            limit_minor,
            spent_minor: 0,
            max_reservation_minor: MAX_RESERVATION_MINOR,
            reservations: Vec::new(),
        }
    }

    pub fn with_max_reservation(mut self, max_reservation_minor: u64) -> Result<Self, BudgetError> {
        validate_reservation_amount(max_reservation_minor)?;
        self.max_reservation_minor = max_reservation_minor;
        Ok(self)
    }

    pub fn limit_minor(&self) -> u64 {
        self.limit_minor
    }

    pub fn spent_minor(&self) -> u64 {
        self.spent_minor
    }

    pub fn reservations(&self) -> &[BudgetReservation] {
        &self.reservations
    }

    pub fn live_reserved_minor(&self, now: u64) -> u64 {
        self.reservations
            .iter()
            .filter(|reservation| reservation.is_live_at(now))
            .fold(0_u64, |total, reservation| {
                total.saturating_add(reservation.outstanding_minor())
            })
    }

    pub fn expire_due(&mut self, now: u64) -> usize {
        let mut expired = 0;
        for reservation in &mut self.reservations {
            if reservation
                .expire(now)
                .is_ok_and(|transition| transition.changed())
            {
                expired += 1;
            }
        }
        expired
    }

    pub fn snapshot(&self, now: u64) -> BudgetSnapshot {
        BudgetSnapshot {
            limit_minor: self.limit_minor,
            spent_minor: self.spent_minor,
            live_reserved_minor: self.live_reserved_minor(now),
            max_reservation_minor: self.max_reservation_minor,
            observed_at: now,
        }
    }

    pub fn available_minor(&self, now: u64) -> u64 {
        self.snapshot(now).remaining_minor().unwrap_or(0)
    }

    /// Atomically model one conditional insert. This method rechecks current
    /// state on every call; a stale [`BudgetSnapshot`] is never sufficient to
    /// authorize a write.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve(
        &mut self,
        reservation_id: impl Into<String>,
        request_id: impl Into<String>,
        org_id: impl Into<String>,
        run_id: Option<String>,
        reserved_minor: u64,
        expires_at: u64,
        now: u64,
    ) -> Result<ReservationAdmission, BudgetError> {
        let reservation = BudgetReservation::new(
            reservation_id,
            request_id,
            org_id,
            run_id,
            reserved_minor,
            expires_at,
            now,
        )?;
        self.expire_due(now);

        if let Some(existing) = self.reserved_by_identity(
            &reservation.reservation_id,
            &reservation.request_id,
            &reservation.org_id,
        ) {
            if existing.org_id != reservation.org_id
                || existing.run_id != reservation.run_id
                || existing.reserved_minor != reservation.reserved_minor
            {
                return Err(BudgetError::IdentityConflict);
            }
            return Ok(ReservationAdmission::Existing(existing.clone()));
        }

        if reserved_minor > self.max_reservation_minor {
            return Err(BudgetError::ReservationTooLarge);
        }
        let live = self.live_reserved_minor(now);
        let projected = self
            .spent_minor
            .checked_add(live)
            .and_then(|used| used.checked_add(reserved_minor))
            .ok_or(BudgetError::ArithmeticOverflow)?;
        if projected > self.limit_minor {
            return Err(BudgetError::CapacityExceeded);
        }

        self.reservations.push(reservation.clone());
        Ok(ReservationAdmission::Created(reservation))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn try_reserve(
        &mut self,
        reservation_id: impl Into<String>,
        request_id: impl Into<String>,
        org_id: impl Into<String>,
        run_id: Option<String>,
        reserved_minor: u64,
        expires_at: u64,
        now: u64,
    ) -> Result<ReservationAdmission, BudgetError> {
        self.reserve(
            reservation_id,
            request_id,
            org_id,
            run_id,
            reserved_minor,
            expires_at,
            now,
        )
    }

    pub fn commit(
        &mut self,
        org_id: &str,
        request_id: &str,
        actual_minor: u64,
        now: u64,
    ) -> Result<ReservationTransition, BudgetError> {
        let spent_minor = self.spent_minor;
        let reservation = self
            .reserved_matching(org_id, request_id)
            .ok_or(BudgetError::ReservationNotFound)?;
        if actual_minor > reservation.reserved_minor {
            return Err(BudgetError::ActualExceedsReservation);
        }
        let next_spent_minor =
            if reservation.state == ReservationState::Reserved && !reservation.is_expired_at(now) {
                Some(
                    spent_minor
                        .checked_add(actual_minor)
                        .ok_or(BudgetError::ArithmeticOverflow)?,
                )
            } else {
                None
            };
        let transition = reservation.commit(actual_minor, now)?;
        if let Some(next_spent_minor) = next_spent_minor {
            self.spent_minor = next_spent_minor;
        }
        Ok(transition)
    }

    pub fn release(
        &mut self,
        org_id: &str,
        request_id: &str,
        now: u64,
    ) -> Result<ReservationTransition, BudgetError> {
        let reservation = self
            .reserved_matching(org_id, request_id)
            .ok_or(BudgetError::ReservationNotFound)?;
        reservation.release(now)
    }

    pub fn expire_due_for(&mut self, now: u64) -> usize {
        self.expire_due(now)
    }

    fn reserved_by_identity(
        &self,
        reservation_id: &str,
        request_id: &str,
        org_id: &str,
    ) -> Option<&BudgetReservation> {
        self.reservations.iter().find(|reservation| {
            reservation.org_id == org_id
                && (reservation.reservation_id == reservation_id
                    || reservation.request_id == request_id)
        })
    }

    fn reserved_matching(
        &mut self,
        org_id: &str,
        request_id: &str,
    ) -> Option<&mut BudgetReservation> {
        self.reservations.iter_mut().find(|reservation| {
            reservation.org_id == org_id && reservation.request_id == request_id
        })
    }
}

/// A descriptive alias for persistence adapters and race tests.
pub type ReservationModel = BudgetLedger;

#[cfg(test)]
#[path = "budget_p05_tests.rs"]
mod budget_p05_tests;
