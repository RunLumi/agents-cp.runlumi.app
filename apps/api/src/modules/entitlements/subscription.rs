//! The Lumi subscription state machine, the provider-event ledger, and the
//! billable seat model.
//!
//! WHY this is pure and separate from the license matrix: a billing provider is
//! an unreliable, replaying, out-of-order event source. The frozen contract
//! (P06-CG `p06-cg-v1`) requires that a replayed or reordered webhook cannot
//! move commercial state, that a cancelled subscription cannot silently
//! reactivate, and that a seat count is derived from authoritative membership
//! rows rather than a client total. All three are pure decisions here; the D1
//! adapter only persists the result in one conditional write.
//!
//! # No provider product/price IDs
//!
//! [`PlanPointer`] carries a Lumi plan key validated by [`is_lumi_plan_key`]
//! (lowercase kebab-case) and a Lumi `plan_` identifier. A payment-provider
//! product/price ID contains `_` and mixed case, so it cannot be stored here
//! even by mistake, and no such field exists in this module. The provider
//! account reference is an adapter-private opaque string and is never used to
//! derive product behavior.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::core::{MembershipId, OrganizationId};

use super::{
    BillingAccountId, EntitlementError, MAX_TIMESTAMP_UNIX_SECONDS, MIN_TIMESTAMP_UNIX_SECONDS,
    PlanId, SubscriptionId,
};

/// Ceiling on a Lumi plan key, in bytes.
pub const MAX_PLAN_KEY_BYTES: usize = 32;

/// Ceiling on the adapter-private opaque provider account reference, in bytes.
pub const MAX_PROVIDER_REFERENCE_BYTES: usize = 128;

/// Ceiling on one provider event identifier, in bytes.
pub const MAX_PROVIDER_EVENT_ID_BYTES: usize = 128;

/// How many applied provider event IDs the in-memory ledger remembers for
/// replay detection. The ledger is a bounded pure model, so eviction is FIFO:
/// once an ID falls out of the window the monotonic version/timestamp ordering
/// still refuses it as `provider_event_out_of_order`.
pub const MAX_LEDGER_EVENT_IDS: usize = 256;

/// Largest clock skew tolerated on a provider-signed event timestamp before the
/// event is treated as future-dated and refused.
pub const MAX_PROVIDER_EVENT_SKEW_SECONDS: i64 = 120;

/// Widest grace window any capability class may ever receive. Local-only
/// offline grace is the 7-day baseline; nothing may widen past it.
pub const MAX_GRACE_WINDOW_SECONDS: i64 = 604_800;

/// The frozen Lumi subscription states.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Trialing,
    Active,
    Grace,
    PastDue,
    Suspended,
    Cancelled,
}

impl SubscriptionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trialing => "trialing",
            Self::Active => "active",
            Self::Grace => "grace",
            Self::PastDue => "past_due",
            Self::Suspended => "suspended",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "trialing" => Some(Self::Trialing),
            "active" => Some(Self::Active),
            "grace" => Some(Self::Grace),
            "past_due" => Some(Self::PastDue),
            "suspended" => Some(Self::Suspended),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }

    /// `cancelled` is terminal. Reactivation requires a new subscription row
    /// and a new provider account binding, never a silent state write.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Cancelled)
    }

    /// The frozen transition table. A self-transition is deliberately absent: it
    /// is an idempotent no-op handled by [`Subscription::apply_status`], not a
    /// transition.
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Trialing, Self::Active | Self::Cancelled)
                | (
                    Self::Active,
                    Self::Grace | Self::PastDue | Self::Suspended | Self::Cancelled
                )
                | (
                    Self::Grace,
                    Self::Active | Self::PastDue | Self::Suspended | Self::Cancelled
                )
                | (
                    Self::PastDue,
                    Self::Active | Self::Grace | Self::Suspended | Self::Cancelled
                )
                | (Self::Suspended, Self::Active | Self::Cancelled)
        )
    }
}

/// Result of one subscription status write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubscriptionTransition {
    Applied {
        from: SubscriptionStatus,
        to: SubscriptionStatus,
    },
    Unchanged {
        state: SubscriptionStatus,
    },
}

impl SubscriptionTransition {
    pub const fn changed(self) -> bool {
        matches!(self, Self::Applied { .. })
    }

    pub const fn state(self) -> SubscriptionStatus {
        match self {
            Self::Applied { to, .. } => to,
            Self::Unchanged { state } => state,
        }
    }
}

/// A Lumi plan pointer.
///
/// The pointer is immutable per version: a plan change publishes a new pointer
/// and appends history, it never rewrites what a previous period charged for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanPointer {
    pub plan_id: PlanId,
    pub plan_key: String,
    pub plan_version: i64,
}

impl PlanPointer {
    pub fn new(
        plan_id: PlanId,
        plan_key: impl Into<String>,
        plan_version: i64,
    ) -> Result<Self, EntitlementError> {
        let plan_key = plan_key.into();
        if !is_lumi_plan_key(&plan_key) || plan_version < 1 {
            return Err(EntitlementError::InvalidPlanKey);
        }
        Ok(Self {
            plan_id,
            plan_key,
            plan_version,
        })
    }

    pub fn as_key(&self) -> &str {
        self.plan_key.as_str()
    }
}

/// A Lumi plan key is lowercase kebab-case, two to [`MAX_PLAN_KEY_BYTES`]
/// bytes, starting with a lowercase letter.
///
/// `_` is rejected on purpose: mainstream payment providers encode product,
/// price, and plan identifiers with an underscore separator, so this rule makes
/// it impossible for a provider identifier to become a Lumi plan concept even
/// if an adapter passed one through by mistake.
pub fn is_lumi_plan_key(value: &str) -> bool {
    if value.len() < 2 || value.len() > MAX_PLAN_KEY_BYTES || !value.is_ascii() {
        return false;
    }
    let bytes = value.as_bytes();
    bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// The immutable plan-pointer transition produced by a plan change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanChange {
    pub previous: PlanPointer,
    pub current: PlanPointer,
    pub version: i64,
}

/// The pure Lumi subscription projection.
///
/// `version` is the compare-and-set token for the single atomic D1 write that
/// accompanies a provider event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    pub subscription_id: SubscriptionId,
    pub org_id: OrganizationId,
    pub billing_account_id: BillingAccountId,
    pub plan: PlanPointer,
    pub status: SubscriptionStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_expires_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_period_ends_at: Option<i64>,
    pub version: i64,
    pub updated_at: i64,
}

impl Subscription {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subscription_id: SubscriptionId,
        org_id: OrganizationId,
        billing_account_id: BillingAccountId,
        plan: PlanPointer,
        status: SubscriptionStatus,
        grace_expires_at: Option<i64>,
        current_period_ends_at: Option<i64>,
        version: i64,
        now: i64,
    ) -> Result<Self, EntitlementError> {
        if version < 1 {
            return Err(EntitlementError::InvalidPeriod);
        }
        if status == SubscriptionStatus::Grace && grace_expires_at.is_none() {
            return Err(EntitlementError::MissingGraceExpiry);
        }
        validate_optional_instant(grace_expires_at)?;
        validate_optional_instant(current_period_ends_at)?;
        validate_instant(now)?;
        Ok(Self {
            subscription_id,
            org_id,
            billing_account_id,
            plan,
            status,
            grace_expires_at,
            current_period_ends_at,
            version,
            updated_at: now,
        })
    }

    /// Apply one status transition.
    ///
    /// `grace_expires_at` is required when entering `grace` and cleared when
    /// leaving it, so a stale grace expiry can never keep a cloud capability
    /// alive after the window closed. A cancelled subscription refuses every
    /// transition, including back to `active`.
    pub fn apply_status(
        &mut self,
        next: SubscriptionStatus,
        grace_expires_at: Option<i64>,
        effective_at: i64,
        now: i64,
    ) -> Result<SubscriptionTransition, EntitlementError> {
        if effective_at < self.updated_at {
            return Err(EntitlementError::StaleTransition);
        }
        if next == self.status {
            return Ok(SubscriptionTransition::Unchanged { state: self.status });
        }
        if self.status.is_terminal() {
            return Err(EntitlementError::TerminalSubscription);
        }
        if !self.status.can_transition_to(next) {
            return Err(EntitlementError::InvalidTransition);
        }

        let resolved_grace = match next {
            SubscriptionStatus::Grace => {
                let Some(expiry) = grace_expires_at else {
                    return Err(EntitlementError::MissingGraceExpiry);
                };
                if expiry <= effective_at {
                    return Err(EntitlementError::InvalidPeriod);
                }
                validate_instant(expiry)?;
                Some(expiry)
            }
            _ => None,
        };

        let from = self.status;
        self.status = next;
        self.grace_expires_at = resolved_grace;
        self.version += 1;
        self.updated_at = now;
        Ok(SubscriptionTransition::Applied { from, to: next })
    }

    /// Publish a new plan pointer.
    ///
    /// The pointer moves; the subscription's commercial status, grace window,
    /// and period bounds are untouched, and the previous pointer is returned so
    /// the caller can append it to the immutable subscription history.
    pub fn apply_plan(
        &mut self,
        plan: PlanPointer,
        now: i64,
    ) -> Result<PlanChange, EntitlementError> {
        validate_instant(now)?;
        if plan.plan_id == self.plan.plan_id && plan.plan_key == self.plan.plan_key {
            return Err(EntitlementError::InvalidPlanKey);
        }
        let previous = self.plan.clone();
        self.plan = plan;
        self.version += 1;
        self.updated_at = now;
        Ok(PlanChange {
            previous,
            current: self.plan.clone(),
            version: self.version,
        })
    }
}

fn validate_instant(value: i64) -> Result<(), EntitlementError> {
    if !(MIN_TIMESTAMP_UNIX_SECONDS..=MAX_TIMESTAMP_UNIX_SECONDS).contains(&value) {
        return Err(EntitlementError::InvalidTimestampRange);
    }
    Ok(())
}

fn validate_optional_instant(value: Option<i64>) -> Result<(), EntitlementError> {
    match value {
        Some(instant) => validate_instant(instant),
        None => Ok(()),
    }
}

fn bounded_reference(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

/// One authenticated provider event, already translated by the billing
/// adapter into Lumi vocabulary.
///
/// `provider_event_id` and `account_reference` are adapter-private opaque
/// strings. The raw provider payload is never represented here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderEvent {
    pub provider_event_id: String,
    pub account_reference: String,
    pub provider_version: i64,
    pub occurred_at: i64,
    pub next_status: SubscriptionStatus,
    pub next_plan: Option<PlanPointer>,
}

impl ProviderEvent {
    pub fn new(
        provider_event_id: impl Into<String>,
        account_reference: impl Into<String>,
        provider_version: i64,
        occurred_at: i64,
        next_status: SubscriptionStatus,
        next_plan: Option<PlanPointer>,
    ) -> Result<Self, EntitlementError> {
        let provider_event_id = provider_event_id.into();
        if !bounded_reference(&provider_event_id, MAX_PROVIDER_EVENT_ID_BYTES) {
            return Err(EntitlementError::InvalidProviderReference);
        }
        let account_reference = account_reference.into();
        if !bounded_reference(&account_reference, MAX_PROVIDER_REFERENCE_BYTES) {
            return Err(EntitlementError::InvalidProviderReference);
        }
        if provider_version < 1 {
            return Err(EntitlementError::InvalidProviderReference);
        }
        validate_instant(occurred_at)?;
        Ok(Self {
            provider_event_id,
            account_reference,
            provider_version,
            occurred_at,
            next_status,
            next_plan,
        })
    }
}

/// Bounded, in-memory replay/ordering model for one billing account.
///
/// The D1 adapter persists the same facts as a `subscriptions.version` plus an
/// append-only `subscription_events` table; this pure model exists so replay,
/// reordering, and cross-account binding are provable in unit tests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProviderEventLedger {
    account_reference: Option<String>,
    last_version: Option<i64>,
    last_occurred_at: Option<i64>,
    applied_event_ids: Vec<String>,
}

impl ProviderEventLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind the ledger to one adapter account. Every later event must carry the
    /// same reference; an event bound to another account is refused before it
    /// can be replayed, reordered, or applied.
    pub fn bind_account(
        &mut self,
        account_reference: impl Into<String>,
    ) -> Result<(), EntitlementError> {
        let account_reference = account_reference.into();
        if !bounded_reference(&account_reference, MAX_PROVIDER_REFERENCE_BYTES) {
            return Err(EntitlementError::InvalidProviderReference);
        }
        match &self.account_reference {
            Some(bound) if *bound != account_reference => {
                Err(EntitlementError::AccountBindingMismatch)
            }
            _ => {
                self.account_reference = Some(account_reference);
                Ok(())
            }
        }
    }

    pub fn account_reference(&self) -> Option<&str> {
        self.account_reference.as_deref()
    }

    pub fn last_applied_version(&self) -> Option<i64> {
        self.last_version
    }

    pub fn last_applied_at(&self) -> Option<i64> {
        self.last_occurred_at
    }

    pub fn applied_event_count(&self) -> usize {
        self.applied_event_ids.len()
    }

    pub fn has_seen(&self, provider_event_id: &str) -> bool {
        self.applied_event_ids
            .iter()
            .any(|seen| seen == provider_event_id)
    }

    /// Accept one event and record it for replay detection.
    ///
    /// Rejection is total: a refused event never advances the version or the
    /// timestamp, so a retry or a forged webhook cannot move state.
    pub fn accept(&mut self, event: &ProviderEvent, now: i64) -> Result<(), EntitlementError> {
        validate_instant(now)?;
        match &self.account_reference {
            Some(bound) if *bound == event.account_reference => {}
            _ => return Err(EntitlementError::AccountBindingMismatch),
        }
        if self.has_seen(&event.provider_event_id) {
            return Err(EntitlementError::ProviderEventReplay);
        }
        if let Some(last_version) = self.last_version
            && event.provider_version <= last_version
        {
            return Err(EntitlementError::ProviderEventOutOfOrder);
        }
        if let Some(last_occurred_at) = self.last_occurred_at
            && event.occurred_at < last_occurred_at
        {
            return Err(EntitlementError::ProviderEventOutOfOrder);
        }
        if event.occurred_at > now.saturating_add(MAX_PROVIDER_EVENT_SKEW_SECONDS) {
            return Err(EntitlementError::ProviderEventOutOfOrder);
        }

        self.last_version = Some(event.provider_version);
        self.last_occurred_at = Some(event.occurred_at);
        if self.applied_event_ids.len() == MAX_LEDGER_EVENT_IDS {
            self.applied_event_ids.remove(0);
        }
        self.applied_event_ids.push(event.provider_event_id.clone());
        Ok(())
    }
}

/// Result of one provider event application.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderEventOutcome {
    Applied(SubscriptionTransition),
    /// The event identifier was new but the subscription was already in the
    /// requested state. Recorded for audit, no state change.
    Duplicate(SubscriptionStatus),
}

/// Apply one provider event to one subscription, atomically in the pure model.
///
/// Order: the whole state change is computed on a copy first, so a refused
/// transition cannot advance the ledger; the ledger then accepts the event, and
/// only then is the candidate published. This is the pure model of the single
/// conditional D1 write the adapter must perform inside one transaction, and it
/// is what makes a retry after a refusal safe.
pub fn apply_provider_event(
    subscription: &mut Subscription,
    ledger: &mut ProviderEventLedger,
    event: &ProviderEvent,
    grace_expires_at: Option<i64>,
    now: i64,
) -> Result<ProviderEventOutcome, EntitlementError> {
    let mut candidate = subscription.clone();
    let status =
        candidate.apply_status(event.next_status, grace_expires_at, event.occurred_at, now)?;
    if let Some(plan) = &event.next_plan {
        candidate.apply_plan(plan.clone(), now)?;
    }

    ledger.accept(event, now)?;
    *subscription = candidate;

    Ok(match status {
        SubscriptionTransition::Applied { .. } => ProviderEventOutcome::Applied(status),
        SubscriptionTransition::Unchanged { state } => ProviderEventOutcome::Duplicate(state),
    })
}

/// A membership state considered by seat accounting.
///
/// `active` and `suspended` are the states a seat-based plan bills by default.
/// `pending_invitation`, `removed`, and `viewer` are not billable unless the
/// plan contract says otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillableSeatState {
    Active,
    Suspended,
    PendingInvitation,
    Removed,
    Viewer,
}

impl BillableSeatState {
    pub const ALL: [Self; 5] = [
        Self::Active,
        Self::Suspended,
        Self::PendingInvitation,
        Self::Removed,
        Self::Viewer,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::PendingInvitation => "pending_invitation",
            Self::Removed => "removed",
            Self::Viewer => "viewer",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "suspended" => Some(Self::Suspended),
            "pending_invitation" => Some(Self::PendingInvitation),
            "removed" => Some(Self::Removed),
            "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }

    /// The frozen baseline seat rule: active and suspended are billable.
    pub const fn is_billable_by_default(self) -> bool {
        matches!(self, Self::Active | Self::Suspended)
    }
}

/// Which membership states a plan bills. A plan may widen this only for its own
/// documented commercial reasons, and the resulting count is still derived from
/// authoritative membership rows, never from a client total.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeatPolicy {
    billable_states: Vec<BillableSeatState>,
}

impl SeatPolicy {
    pub fn new(
        billable_states: impl IntoIterator<Item = BillableSeatState>,
    ) -> Result<Self, EntitlementError> {
        let states: Vec<BillableSeatState> = billable_states.into_iter().collect();
        if states.len() > BillableSeatState::ALL.len() {
            return Err(EntitlementError::TooManyBillableStates);
        }
        let unique: BTreeSet<BillableSeatState> = states.iter().copied().collect();
        if unique.len() != states.len() {
            return Err(EntitlementError::DuplicateBillableState);
        }
        Ok(Self {
            billable_states: unique.into_iter().collect(),
        })
    }

    /// `active` + `suspended`, the frozen baseline.
    pub fn baseline() -> Self {
        Self {
            billable_states: vec![BillableSeatState::Active, BillableSeatState::Suspended],
        }
    }

    pub fn billable_states(&self) -> &[BillableSeatState] {
        self.billable_states.as_slice()
    }

    pub fn bills(&self, state: BillableSeatState) -> bool {
        self.billable_states.contains(&state)
    }
}

/// One authoritative membership row as seat accounting sees it.
///
/// These rows come from a current store lookup. A client-supplied seat total is
/// never accepted here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BillingSeatRow {
    pub membership_id: MembershipId,
    pub org_id: OrganizationId,
    pub state: BillableSeatState,
}

impl BillingSeatRow {
    pub fn new(
        membership_id: MembershipId,
        org_id: OrganizationId,
        state: BillableSeatState,
    ) -> Self {
        Self {
            membership_id,
            org_id,
            state,
        }
    }
}

/// Derived seat totals, grouped by state so a remediation surface can show
/// exactly which rows to change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeatCount {
    pub billable: u64,
    pub non_billable: u64,
    pub by_state: BTreeMap<BillableSeatState, u64>,
}

impl SeatCount {
    pub fn total(&self) -> u64 {
        self.billable.saturating_add(self.non_billable)
    }

    pub fn count_of(&self, state: BillableSeatState) -> u64 {
        self.by_state.get(&state).copied().unwrap_or(0)
    }
}

/// Derive the billable seat count from authoritative membership rows.
///
/// A row from another tenant is refused instead of being counted, so a
/// cross-tenant membership leak cannot inflate or deflate a bill.
pub fn billable_seat_count(
    rows: &[BillingSeatRow],
    policy: &SeatPolicy,
) -> Result<SeatCount, EntitlementError> {
    let mut by_state: BTreeMap<BillableSeatState, u64> = BillableSeatState::ALL
        .iter()
        .map(|state| (*state, 0))
        .collect();
    let mut organization: Option<OrganizationId> = None;
    let mut billable = 0_u64;

    for row in rows {
        match &organization {
            Some(seen) if *seen != row.org_id => {
                return Err(EntitlementError::CrossTenantGrant);
            }
            Some(_) => {}
            None => organization = Some(row.org_id.clone()),
        }
        let counter = by_state
            .get_mut(&row.state)
            .ok_or(EntitlementError::InvalidMembershipState)?;
        *counter = counter
            .checked_add(1)
            .ok_or(EntitlementError::SeatCountOverflow)?;
        if policy.bills(row.state) {
            billable = billable
                .checked_add(1)
                .ok_or(EntitlementError::SeatCountOverflow)?;
        }
    }

    let total = u64::try_from(rows.len()).map_err(|_| EntitlementError::SeatCountOverflow)?;
    Ok(SeatCount {
        billable,
        non_billable: total.saturating_sub(billable),
        by_state,
    })
}

/// The org-owned billing account projection.
///
/// It stores only the adapter-private opaque provider account reference and the
/// plan seat policy. There is deliberately no second billing-status field here:
/// the commercial status is the [`Subscription`] row, and a duplicate status
/// would become a competing authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BillingAccount {
    pub billing_account_id: BillingAccountId,
    pub org_id: OrganizationId,
    pub provider_account_reference: String,
    pub seat_policy: SeatPolicy,
}

impl BillingAccount {
    pub fn new(
        billing_account_id: BillingAccountId,
        org_id: OrganizationId,
        provider_account_reference: impl Into<String>,
        seat_policy: SeatPolicy,
    ) -> Result<Self, EntitlementError> {
        let provider_account_reference = provider_account_reference.into();
        if !bounded_reference(&provider_account_reference, MAX_PROVIDER_REFERENCE_BYTES) {
            return Err(EntitlementError::InvalidProviderReference);
        }
        Ok(Self {
            billing_account_id,
            org_id,
            provider_account_reference,
            seat_policy,
        })
    }

    /// Seat count derived from authoritative membership rows.
    pub fn billable_seat_count(
        &self,
        rows: &[BillingSeatRow],
    ) -> Result<SeatCount, EntitlementError> {
        billable_seat_count(rows, &self.seat_policy)
    }
}

/// What established the grace anchor instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraceAnchorSource {
    AcceptedProviderTransition,
    LastSuccessfulSync,
}

/// The immutable instant a grace window started.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraceAnchor {
    pub started_at: i64,
    pub source: GraceAnchorSource,
    pub provider_event_id: String,
}

/// Outcome of a grace anchor attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraceAnchorOutcome {
    /// The anchor did not exist and was created now.
    Established,
    /// An anchor already existed. Grace is never re-anchored.
    Retained,
}

/// The grace anchor for one billing account.
///
/// WHY it is a separate type: the frozen rule is that grace begins at the *first*
/// accepted provider transition / last successful sync, is never extended by
/// repeated failed polling, and cannot be extended by a stale or future-dated
/// provider event. Modelling the anchor as immutable data makes each of those
/// three rules a property of the type rather than a code-review convention.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraceWindow {
    anchor: Option<GraceAnchor>,
}

impl GraceWindow {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn anchor(&self) -> Option<&GraceAnchor> {
        self.anchor.as_ref()
    }

    /// Record an accepted provider transition or successful sync.
    ///
    /// Only the first accepted instant anchors the window. A later or
    /// future-dated event is refused and never moves the anchor; a stale one is
    /// refused as out of order.
    pub fn record_accepted_event(
        &mut self,
        provider_event_id: impl Into<String>,
        source: GraceAnchorSource,
        at: i64,
        now: i64,
    ) -> Result<GraceAnchorOutcome, EntitlementError> {
        let provider_event_id = provider_event_id.into();
        if !bounded_reference(&provider_event_id, MAX_PROVIDER_EVENT_ID_BYTES) {
            return Err(EntitlementError::InvalidProviderReference);
        }
        if at <= MIN_TIMESTAMP_UNIX_SECONDS {
            return Err(EntitlementError::InvalidTimestampRange);
        }
        validate_instant(at)?;
        validate_instant(now)?;
        if at > now.saturating_add(MAX_PROVIDER_EVENT_SKEW_SECONDS) {
            return Err(EntitlementError::ProviderEventOutOfOrder);
        }
        if let Some(existing) = &self.anchor {
            if at < existing.started_at {
                return Err(EntitlementError::ProviderEventOutOfOrder);
            }
            return Ok(GraceAnchorOutcome::Retained);
        }
        self.anchor = Some(GraceAnchor {
            started_at: at,
            source,
            provider_event_id,
        });
        Ok(GraceAnchorOutcome::Established)
    }

    /// A failed poll is not an event. It must not create or move an anchor.
    pub const fn record_failed_poll(&mut self) -> GraceAnchorOutcome {
        GraceAnchorOutcome::Retained
    }

    /// Clamp a capability's grace window to the frozen maximum.
    pub const fn ceiling_seconds(grace_seconds: i64) -> i64 {
        if grace_seconds < 0 {
            0
        } else if grace_seconds > MAX_GRACE_WINDOW_SECONDS {
            MAX_GRACE_WINDOW_SECONDS
        } else {
            grace_seconds
        }
    }

    /// When the window closes for a capability, or `None` without an anchor.
    pub fn expires_at(&self, grace_seconds: i64) -> Option<i64> {
        self.anchor.as_ref().and_then(|anchor| {
            anchor
                .started_at
                .checked_add(Self::ceiling_seconds(grace_seconds))
        })
    }

    /// Seconds left, clamped at zero, or `None` without an anchor.
    pub fn seconds_remaining(&self, grace_seconds: i64, now: i64) -> Option<i64> {
        self.expires_at(grace_seconds)
            .map(|expires_at| expires_at.saturating_sub(now).max(0))
    }
}
