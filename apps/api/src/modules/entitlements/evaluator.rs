//! Effective-entitlement resolution, deterministic precedence, and the
//! downgrade over-limit projection.
//!
//! WHY precedence is computed here and not in a route: P06-CG freezes
//! `platform default < active plan value < active subscription-derived grant <
//! active, scoped internal override`. That chain, its fail-closed behaviour for
//! a protected capability, and the downgrade over-limit counts are all
//! reproducible only if they are pure functions of authoritative rows. The
//! result is order-independent by construction: grants are normalized and
//! sorted by a total order before the first one is selected.
//!
//! # Decision input separation
//!
//! This module resolves the *Lumi product entitlement* input only. It never
//! reads an authorization permission (`modules::authorization`) or a usage
//! budget (`modules::budget_p05`), and
//! [`ProviderEntitlementProjection`] is read-only status that can gate one
//! provider route but can never produce entitlements or change a subscription.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::core::{OrganizationId, ProjectId};

use super::keys::{
    EntitlementKey, EntitlementScope, EntitlementValue, EntitlementValueType, baseline_definition,
    baseline_entries, baseline_value_type,
};
use super::{
    EntitlementError, EntitlementGrantId, MAX_TIMESTAMP_UNIX_SECONDS, MIN_TIMESTAMP_UNIX_SECONDS,
    ProviderEntitlementProjectionId,
};

/// Ceiling on the audited reason text carried by an internal override.
pub const MAX_OVERRIDE_REASON_BYTES: usize = 512;

/// The frozen precedence ladder. Higher wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantSource {
    PlatformDefault,
    Plan,
    Subscription,
    InternalOverride,
}

impl GrantSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlatformDefault => "platform_default",
            Self::Plan => "plan",
            Self::Subscription => "subscription",
            Self::InternalOverride => "internal_override",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "platform_default" => Some(Self::PlatformDefault),
            "plan" => Some(Self::Plan),
            "subscription" => Some(Self::Subscription),
            "internal_override" => Some(Self::InternalOverride),
            _ => None,
        }
    }

    /// Precedence rank. The ladder is frozen; this value is the ladder.
    pub const fn rank(self) -> u8 {
        match self {
            Self::PlatformDefault => 0,
            Self::Plan => 1,
            Self::Subscription => 2,
            Self::InternalOverride => 3,
        }
    }
}

/// Why an entitlement was not granted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntitlementDenialReason {
    /// Nothing resolved a value for a protected key. This is the fail-closed
    /// path: an absent value is never a permissive default.
    NotConfigured,
    /// An active, scoped internal override set the deny value for this key.
    DeniedByOverride,
    /// An audit/legal denial is in force. No internal override can erase it.
    DeniedByLegalHold,
    /// A registered resource exists above the effective limit.
    LimitExceeded,
}

impl EntitlementDenialReason {
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotConfigured | Self::DeniedByOverride | Self::DeniedByLegalHold => {
                "entitlement_not_granted"
            }
            Self::LimitExceeded => "entitlement_limit_exceeded",
        }
    }
}

/// One time-bounded entitlement grant.
///
/// Every source is represented by the same type so the evaluator has one
/// comparison path. The `source` field must match the slice the grant is
/// supplied in, which is checked at resolve time rather than trusted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementGrant {
    pub grant_id: EntitlementGrantId,
    pub org_id: OrganizationId,
    pub key: EntitlementKey,
    pub value: EntitlementValue,
    pub source: GrantSource,
    pub scope: EntitlementScope,
    /// Audited reason. REQUIRED for an internal override so support access is
    /// always explainable and never silent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub effective_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
}

impl EntitlementGrant {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        grant_id: EntitlementGrantId,
        org_id: OrganizationId,
        key: EntitlementKey,
        value: EntitlementValue,
        source: GrantSource,
        scope: EntitlementScope,
        reason: Option<String>,
        effective_at: i64,
        expires_at: Option<i64>,
        revoked_at: Option<i64>,
    ) -> Result<Self, EntitlementError> {
        validate_instant(effective_at)?;
        validate_optional_instant(expires_at)?;
        validate_optional_instant(revoked_at)?;

        let Some(definition) = baseline_definition(&key) else {
            return Err(EntitlementError::UnknownEntitlementKey);
        };
        if !definition.type_matches(&value) {
            return Err(EntitlementError::EntitlementTypeMismatch);
        }
        if !definition.scope.contains(&scope) {
            return Err(EntitlementError::ScopeNotWithinDefinition);
        }
        if let Some(expiry) = expires_at
            && expiry <= effective_at
        {
            return Err(EntitlementError::InvalidPeriod);
        }
        if let Some(revoked) = revoked_at
            && revoked < effective_at
        {
            return Err(EntitlementError::InvalidPeriod);
        }
        if source == GrantSource::InternalOverride {
            if expires_at.is_none() {
                return Err(EntitlementError::MissingOverrideExpiry);
            }
            match reason.as_deref() {
                Some(text) if !text.is_empty() && text.len() <= MAX_OVERRIDE_REASON_BYTES => {}
                _ => return Err(EntitlementError::MissingOverrideReason),
            }
        }

        Ok(Self {
            grant_id,
            org_id,
            key,
            value,
            source,
            scope,
            reason,
            effective_at,
            expires_at,
            revoked_at,
        })
    }

    /// Whether the grant contributes to the effective value at `now`.
    ///
    /// A grant that has not started, has expired, or has been revoked is simply
    /// not a candidate: it never wins precedence and it never blocks a lower
    /// source.
    pub fn is_active_at(&self, now: i64) -> bool {
        if now < self.effective_at {
            return false;
        }
        if self.expires_at.is_some_and(|expiry| now >= expiry) {
            return false;
        }
        if self.revoked_at.is_some_and(|revoked| now >= revoked) {
            return false;
        }
        true
    }

    /// A total order used to make precedence selection order-independent.
    ///
    /// `Greater` means `self` wins: higher source first, then the narrower
    /// scope, then the newer `effective_at`, then the later expiry, then the
    /// `grant_id` as a final tie-break. The last comparison makes the order
    /// total, so two candidate grants can never tie.
    fn precedence_cmp(&self, other: &Self) -> Ordering {
        self.source
            .rank()
            .cmp(&other.source.rank())
            .then_with(|| self.scope.specificity().cmp(&other.scope.specificity()))
            .then_with(|| self.effective_at.cmp(&other.effective_at))
            .then_with(|| {
                self.expires_at
                    .unwrap_or(i64::MAX)
                    .cmp(&other.expires_at.unwrap_or(i64::MAX))
            })
            .then_with(|| self.grant_id.as_str().cmp(other.grant_id.as_str()))
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

/// An audit/legal denial against one key and scope.
///
/// It outranks every source, including an active internal override: support
/// access must never be able to erase an audit or legal hold. It carries the
/// originating F16 audit event so the denial is explainable, and it is still
/// time-bounded so it cannot become a silent permanent block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementDenial {
    pub key: EntitlementKey,
    pub scope: EntitlementScope,
    pub reason: EntitlementDenialReason,
    pub audit_event_id: String,
    pub effective_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

impl EntitlementDenial {
    pub fn new(
        key: EntitlementKey,
        scope: EntitlementScope,
        reason: EntitlementDenialReason,
        audit_event_id: impl Into<String>,
        effective_at: i64,
        expires_at: Option<i64>,
    ) -> Result<Self, EntitlementError> {
        let audit_event_id = audit_event_id.into();
        if audit_event_id.is_empty()
            || audit_event_id.len() > MAX_OVERRIDE_REASON_BYTES
            || !audit_event_id.is_ascii()
        {
            return Err(EntitlementError::InvalidClaims);
        }
        if !matches!(
            reason,
            EntitlementDenialReason::DeniedByLegalHold | EntitlementDenialReason::DeniedByOverride
        ) {
            return Err(EntitlementError::InvalidClaims);
        }
        validate_instant(effective_at)?;
        validate_optional_instant(expires_at)?;
        if expires_at.is_some_and(|expiry| expiry <= effective_at) {
            return Err(EntitlementError::InvalidPeriod);
        }
        Ok(Self {
            key,
            scope,
            reason,
            audit_event_id,
            effective_at,
            expires_at,
        })
    }

    fn is_active_at(&self, now: i64) -> bool {
        now >= self.effective_at && self.expires_at.is_none_or(|expiry| now < expiry)
    }

    fn applies_to(&self, request_scope: &EntitlementScope, key: &EntitlementKey) -> bool {
        self.key == *key
            && (self.scope == EntitlementScope::Organization || self.scope == *request_scope)
    }
}

/// The frozen upstream provider account/coding-plan statuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderEntitlementStatus {
    Available,
    Degraded,
    Unavailable,
    Unknown,
}

impl ProviderEntitlementStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "available" => Some(Self::Available),
            "degraded" => Some(Self::Degraded),
            "unavailable" => Some(Self::Unavailable),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// The four precedence slices, kept as separate inputs so a caller cannot
/// accidentally supply a subscription grant in the plan slice.
#[derive(Clone, Copy, Debug, Default)]
pub struct EntitlementInputs<'a> {
    pub platform_defaults: &'a [EntitlementGrant],
    pub plan_grants: &'a [EntitlementGrant],
    pub subscription_grants: &'a [EntitlementGrant],
    pub internal_overrides: &'a [EntitlementGrant],
    /// Audit/legal denials. Applied last and not overridable.
    pub denials: &'a [EntitlementDenial],
}

impl<'a> EntitlementInputs<'a> {
    fn slices(&self) -> [(&'a [EntitlementGrant], GrantSource); 4] {
        [
            (self.platform_defaults, GrantSource::PlatformDefault),
            (self.plan_grants, GrantSource::Plan),
            (self.subscription_grants, GrantSource::Subscription),
            (self.internal_overrides, GrantSource::InternalOverride),
        ]
    }
}

/// Everything one effective-entitlement resolution reads.
#[derive(Clone, Debug)]
pub struct EntitlementResolution<'a> {
    pub org_id: &'a OrganizationId,
    /// The scope being resolved. An organization-scoped grant applies to every
    /// scope beneath it; a project- or user-scoped grant applies only there.
    pub scope: EntitlementScope,
    pub now: i64,
    pub inputs: EntitlementInputs<'a>,
}

/// One resolved entitlement value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveEntitlement {
    pub key: EntitlementKey,
    pub value: EntitlementValue,
    pub source: GrantSource,
    pub scope: EntitlementScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<EntitlementGrantId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// Set when an audit/legal denial outranks every grant for this key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial: Option<EntitlementDenialReason>,
    /// `true` when a missing value for this key must fail closed.
    pub protected: bool,
}

impl EffectiveEntitlement {
    /// A protected key resolved to its fail-closed platform baseline grants
    /// nothing, even though a value is present.
    pub fn is_grant(&self) -> bool {
        self.denial.is_none() && (!self.protected || !self.value.is_fail_closed())
    }
}

/// The typed outcome for one key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntitlementDecision {
    Granted(EntitlementValue),
    NotGranted(EntitlementDenialReason),
}

impl EntitlementDecision {
    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted(_))
    }

    pub fn value(&self) -> Option<&EntitlementValue> {
        match self {
            Self::Granted(value) => Some(value),
            Self::NotGranted(_) => None,
        }
    }

    pub fn reason(&self) -> Option<EntitlementDenialReason> {
        match self {
            Self::Granted(_) => None,
            Self::NotGranted(reason) => Some(*reason),
        }
    }

    pub fn reason_code(&self) -> Option<&'static str> {
        self.reason().map(EntitlementDenialReason::code)
    }
}

/// The resolved entitlement projection for one organization scope.
///
/// Entries are sorted by key, so the same authoritative rows and the same
/// `now` always produce byte-identical output regardless of the order the rows
/// arrived in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveEntitlements {
    pub org_id: OrganizationId,
    pub scope: EntitlementScope,
    pub resolved_at: i64,
    entries: Vec<EffectiveEntitlement>,
}

impl EffectiveEntitlements {
    pub fn entries(&self) -> &[EffectiveEntitlement] {
        self.entries.as_slice()
    }

    pub fn get(&self, key: &EntitlementKey) -> Option<&EffectiveEntitlement> {
        self.entries
            .binary_search_by(|entry| entry.key.cmp(key))
            .ok()
            .map(|index| &self.entries[index])
    }

    /// Typed read of a boolean capability. `None` means the key is not a
    /// boolean key, which is a caller error rather than a denial.
    pub fn boolean_value(&self, key: &EntitlementKey) -> Option<bool> {
        self.get(key)?.value.as_bool()
    }

    /// Typed read of an integer limit.
    pub fn limit(&self, key: &EntitlementKey) -> Option<i64> {
        self.get(key)?.value.as_integer()
    }

    /// Fail-closed decision for one key.
    ///
    /// An unregistered key, a protected key sitting on its platform baseline,
    /// and an active audit/legal denial all resolve to a typed `NotGranted`
    /// rather than to a permissive default.
    pub fn decision(&self, key: &EntitlementKey) -> EntitlementDecision {
        let Some(definition_type) = baseline_value_type(key) else {
            return EntitlementDecision::NotGranted(EntitlementDenialReason::NotConfigured);
        };
        let Some(entry) = self.get(key) else {
            return EntitlementDecision::NotGranted(EntitlementDenialReason::NotConfigured);
        };
        if entry.value.value_type() != definition_type {
            return EntitlementDecision::NotGranted(EntitlementDenialReason::NotConfigured);
        }
        if let Some(denial) = entry.denial {
            return EntitlementDecision::NotGranted(denial);
        }
        if !entry.is_grant() {
            let reason = if entry.source == GrantSource::InternalOverride {
                EntitlementDenialReason::DeniedByOverride
            } else {
                EntitlementDenialReason::NotConfigured
            };
            return EntitlementDecision::NotGranted(reason);
        }
        EntitlementDecision::Granted(entry.value.clone())
    }

    pub fn is_granted(&self, key: &EntitlementKey) -> bool {
        self.decision(key).is_granted()
    }

    /// The wire projection used by `GET /orgs/{org_id}/entitlements`: a plain
    /// map of stable Lumi keys to native typed values.
    pub fn values(&self) -> BTreeMap<EntitlementKey, EntitlementValue> {
        self.entries
            .iter()
            .map(|entry| (entry.key.clone(), entry.value.clone()))
            .collect()
    }

    /// The resolved integer limits, keyed by stable Lumi entitlement key.
    pub fn limit_map(&self) -> BTreeMap<EntitlementKey, i64> {
        self.entries
            .iter()
            .filter_map(|entry| {
                entry
                    .value
                    .as_integer()
                    .map(|limit| (entry.key.clone(), limit))
            })
            .collect()
    }
}

/// Resolve one scope's effective entitlements.
///
/// Total on success and fail-closed on malformed input: a grant from another
/// tenant, a grant filed under the wrong precedence slice, an unregistered key,
/// or a type mismatch all produce an error rather than a partially applied
/// projection. Nothing here can be permissive by accident.
pub fn resolve_effective_entitlements(
    request: &EntitlementResolution<'_>,
) -> Result<EffectiveEntitlements, EntitlementError> {
    validate_instant(request.now)?;
    if !matches!(request.scope, EntitlementScope::Organization) {
        validate_scope_id(request.scope.scope_id())?;
    }

    for (slice, expected_source) in request.inputs.slices() {
        for grant in slice {
            if grant.source != expected_source {
                return Err(EntitlementError::SourceScopeMismatch);
            }
            if grant.org_id != *request.org_id {
                return Err(EntitlementError::CrossTenantGrant);
            }
            if !grant.is_active_at(request.now) {
                continue;
            }
            if baseline_value_type(&grant.key).is_none() {
                return Err(EntitlementError::UnknownEntitlementKey);
            }
        }
    }
    for denial in request.inputs.denials {
        if baseline_value_type(&denial.key).is_none() {
            return Err(EntitlementError::UnknownEntitlementKey);
        }
    }

    let mut entries = Vec::with_capacity(super::BASELINE_ENTITLEMENT_KEY_COUNT);
    for registry in baseline_entries() {
        let key = EntitlementKey::new(registry.key).expect("registry key is a valid Lumi key");
        let active_denial = request
            .inputs
            .denials
            .iter()
            .filter(|denial| {
                denial.is_active_at(request.now) && denial.applies_to(&request.scope, &key)
            })
            .max_by(|left, right| left.audit_event_id.cmp(&right.audit_event_id));

        if let Some(denial) = active_denial {
            entries.push(EffectiveEntitlement {
                value: registry.value_type.fail_closed_value(),
                key,
                source: GrantSource::PlatformDefault,
                scope: denial.scope.clone(),
                grant_id: None,
                expires_at: denial.expires_at,
                denial: Some(denial.reason),
                protected: registry.protected,
            });
            continue;
        }

        let winner = best_grant(&key, &request.scope, request.now, &request.inputs);

        match winner {
            Some(grant) => entries.push(EffectiveEntitlement {
                value: grant.value.clone(),
                key,
                source: grant.source,
                scope: grant.scope.clone(),
                grant_id: Some(grant.grant_id.clone()),
                expires_at: grant.expires_at,
                denial: None,
                protected: registry.protected,
            }),
            None => entries.push(EffectiveEntitlement {
                value: registry.default.clone(),
                key,
                source: GrantSource::PlatformDefault,
                scope: EntitlementScope::organization(),
                grant_id: None,
                expires_at: None,
                denial: None,
                protected: registry.protected,
            }),
        }
    }

    entries.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(EffectiveEntitlements {
        org_id: request.org_id.clone(),
        scope: request.scope.clone(),
        resolved_at: request.now,
        entries,
    })
}

fn validate_scope_id(scope_id: Option<&str>) -> Result<(), EntitlementError> {
    match scope_id {
        None => Ok(()),
        Some(value)
            if !value.is_empty()
                && value.len() <= super::MAX_ENTITLEMENT_SCOPE_ID_BYTES
                && !value.bytes().any(|byte| byte.is_ascii_control()) =>
        {
            Ok(())
        }
        Some(_) => Err(EntitlementError::InvalidScopeId),
    }
}

fn best_grant<'a>(
    key: &EntitlementKey,
    scope: &EntitlementScope,
    now: i64,
    inputs: &EntitlementInputs<'a>,
) -> Option<&'a EntitlementGrant> {
    let mut best: Option<&EntitlementGrant> = None;
    for (slice, _) in inputs.slices() {
        for grant in slice {
            if grant.key != *key
                || !grant.is_active_at(now)
                || !(grant.scope == EntitlementScope::Organization || grant.scope == *scope)
            {
                continue;
            }
            best = Some(match best {
                Some(current) if current.precedence_cmp(grant) == Ordering::Less => grant,
                Some(current) => current,
                None => grant,
            });
        }
    }
    best
}

/// The read-only upstream provider account/coding-plan projection.
///
/// It answers "can this provider route be used right now" and nothing else. There
/// is no method that mutates a subscription, an entitlement, a permission, or a
/// budget, which is the structural form of the P06-CR-002 separation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderEntitlementProjection {
    pub projection_id: ProviderEntitlementProjectionId,
    pub org_id: OrganizationId,
    /// Bounded, opaque provider key. Never a Lumi entitlement key.
    pub provider: String,
    pub status: super::ProviderEntitlementStatus,
    /// Bounded, opaque provider capability label from the adapter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_capability: Option<String>,
    pub observed_at: i64,
}

impl ProviderEntitlementProjection {
    pub fn new(
        projection_id: ProviderEntitlementProjectionId,
        org_id: OrganizationId,
        provider: impl Into<String>,
        status: super::ProviderEntitlementStatus,
        provider_capability: Option<String>,
        observed_at: i64,
    ) -> Result<Self, EntitlementError> {
        let provider = provider.into();
        if provider.is_empty()
            || provider.len() > super::MAX_BOUNDED_STRING_VALUE_BYTES
            || !provider.is_ascii()
            || provider.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(EntitlementError::InvalidProviderReference);
        }
        if provider_capability.as_deref().is_some_and(|value| {
            value.is_empty() || value.len() > super::MAX_BOUNDED_STRING_VALUE_BYTES
        }) {
            return Err(EntitlementError::InvalidProviderReference);
        }
        validate_instant(observed_at)?;
        Ok(Self {
            projection_id,
            org_id,
            provider,
            status,
            provider_capability,
            observed_at,
        })
    }

    /// Whether a provider-managed route may be used. This is the projection's
    /// only behavioural surface.
    pub fn route_usable(&self) -> bool {
        self.status == super::ProviderEntitlementStatus::Available
    }

    /// The reachability this projection contributes to the license matrix.
    pub fn availability(&self) -> super::ProviderAvailability {
        match self.status {
            super::ProviderEntitlementStatus::Available => super::ProviderAvailability::Available,
            super::ProviderEntitlementStatus::Degraded => super::ProviderAvailability::Degraded,
            super::ProviderEntitlementStatus::Unavailable => {
                super::ProviderAvailability::Unavailable
            }
            super::ProviderEntitlementStatus::Unknown => super::ProviderAvailability::Unknown,
        }
    }
}

/// Authoritative resource counts, read from the tenant's own rows.
///
/// A client-supplied count is never accepted here: the downgrade projection is
/// only as trustworthy as its counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoritativeCounts {
    pub members: u64,
    pub active_projects: u64,
    pub enrolled_devices: u64,
    pub active_automations: u64,
    pub webhook_endpoints: u64,
}

/// A downgrade NEVER deletes data. Frozen as a constant so the guarantee is
/// visible at every call site instead of being a comment.
pub const DOWNGRADE_DELETES_DATA: bool = false;

/// The remediation a downgraded organization must perform.
///
/// Every option blocks new/expansion work first; none of them removes a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverLimitRemediation {
    /// Deactivate, pause, or remove rows until the count fits the new limit.
    ReduceToLimit { target: u64 },
    /// Release billable capacity by moving seats to a non-billable state.
    SuspendSeats { target: u64 },
    /// Contact sales to raise the limit on the plan pointer.
    UpgradePlan,
}

impl OverLimitRemediation {
    /// Which mutations a downgrade blocks while the resource is over limit.
    pub const fn blocks(&self) -> MutationBlock {
        MutationBlock {
            create: true,
            expand: true,
            delete_data: DOWNGRADE_DELETES_DATA,
        }
    }
}

/// What a downgrade blocks for one resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationBlock {
    pub create: bool,
    pub expand: bool,
    /// Always `false`: a downgrade blocks new and expanded resources, it never
    /// deletes history.
    pub delete_data: bool,
}

/// One resource above its post-downgrade limit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverLimitItem {
    pub key: EntitlementKey,
    /// The new effective limit. A protected key with no resolved limit is
    /// treated as `0`, which fails closed.
    pub limit: i64,
    pub current: u64,
    pub over_by: u64,
    pub remediation: OverLimitRemediation,
    pub blocks: MutationBlock,
}

/// The over-limit remediation projection for one organization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverLimitProjection {
    pub org_id: OrganizationId,
    pub computed_at: i64,
    pub counts: AuthoritativeCounts,
    items: Vec<OverLimitItem>,
    limits: BTreeMap<EntitlementKey, i64>,
}

impl OverLimitProjection {
    /// A downgrade never deletes data.
    pub const fn deletes_data(&self) -> bool {
        DOWNGRADE_DELETES_DATA
    }

    pub fn items(&self) -> &[OverLimitItem] {
        self.items.as_slice()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// True when at least one resource is over its new limit.
    pub fn blocks_new_and_expansion(&self) -> bool {
        !self.items.is_empty()
    }

    /// The stable reason surfaced when a mutation is refused.
    pub fn reason(&self) -> EntitlementDenialReason {
        EntitlementDenialReason::LimitExceeded
    }

    pub fn item(&self, key: &EntitlementKey) -> Option<&OverLimitItem> {
        self.items.iter().find(|item| item.key == *key)
    }

    /// Whether `additional` more resources of this kind still fit.
    ///
    /// A downgrade blocks creation and expansion only. Reading, updating
    /// in-place, and deleting remain available so the organization can reduce
    /// its own footprint.
    pub fn allows_addition(&self, key: &EntitlementKey, additional: u64) -> bool {
        if self.item(key).is_some() {
            return false;
        }
        let Some(limit) = self.effective_limit(key) else {
            // An unregistered key is not a capacity question.
            return true;
        };
        let current = self.count_for(key);
        match current.checked_add(additional) {
            Some(projected) => projected <= limit.max(0) as u64,
            None => false,
        }
    }

    fn effective_limit(&self, key: &EntitlementKey) -> Option<i64> {
        self.item(key)
            .map(|item| item.limit)
            .or_else(|| self.limit_for(key))
    }

    fn limit_for(&self, key: &EntitlementKey) -> Option<i64> {
        self.limits.get(key).copied()
    }

    fn count_for(&self, key: &EntitlementKey) -> u64 {
        match key.as_str() {
            super::ORG_MAX_MEMBERS => self.counts.members,
            super::PROJECTS_MAX_ACTIVE => self.counts.active_projects,
            super::DEVICES_MAX_ENROLLED => self.counts.enrolled_devices,
            super::AUTOMATIONS_MAX_ACTIVE => self.counts.active_automations,
            super::WEBHOOKS_MAX_ENDPOINTS => self.counts.webhook_endpoints,
            _ => 0,
        }
    }
}

/// Compute the over-limit projection from authoritative counts and the
/// effective entitlement limits.
///
/// A protected key with no resolved limit is treated as `0` and therefore fails
/// closed: without a granted limit, no new resource is admitted.
pub fn compute_over_limit_projection(
    org_id: &OrganizationId,
    counts: AuthoritativeCounts,
    effective: &EffectiveEntitlements,
    now: i64,
) -> OverLimitProjection {
    let mut items = Vec::new();
    for key in [
        super::ORG_MAX_MEMBERS,
        super::PROJECTS_MAX_ACTIVE,
        super::DEVICES_MAX_ENROLLED,
        super::AUTOMATIONS_MAX_ACTIVE,
        super::WEBHOOKS_MAX_ENDPOINTS,
    ] {
        let Ok(key) = EntitlementKey::new(key) else {
            continue;
        };
        if baseline_value_type(&key) != Some(EntitlementValueType::Integer) {
            continue;
        }
        let current = count_for_key(&counts, &key);
        let limit = effective.limit(&key).unwrap_or(0).max(0) as u64;
        if current <= limit {
            continue;
        }
        let remediation = remediation_for(&key, limit);
        items.push(OverLimitItem {
            key,
            limit: limit as i64,
            current,
            over_by: current - limit,
            remediation,
            blocks: remediation.blocks(),
        });
    }
    items.sort_by(|left, right| left.key.cmp(&right.key));
    OverLimitProjection {
        org_id: org_id.clone(),
        computed_at: now,
        counts,
        items,
        limits: effective.limit_map(),
    }
}

fn count_for_key(counts: &AuthoritativeCounts, key: &EntitlementKey) -> u64 {
    match key.as_str() {
        super::ORG_MAX_MEMBERS => counts.members,
        super::PROJECTS_MAX_ACTIVE => counts.active_projects,
        super::DEVICES_MAX_ENROLLED => counts.enrolled_devices,
        super::AUTOMATIONS_MAX_ACTIVE => counts.active_automations,
        super::WEBHOOKS_MAX_ENDPOINTS => counts.webhook_endpoints,
        _ => 0,
    }
}

fn remediation_for(key: &EntitlementKey, limit: u64) -> OverLimitRemediation {
    match key.as_str() {
        super::ORG_MAX_MEMBERS => OverLimitRemediation::SuspendSeats { target: limit },
        _ => OverLimitRemediation::ReduceToLimit { target: limit },
    }
}

/// Build a resolution for the organization scope.
pub fn organization_resolution<'a>(
    org_id: &'a OrganizationId,
    now: i64,
    inputs: EntitlementInputs<'a>,
) -> EntitlementResolution<'a> {
    EntitlementResolution {
        org_id,
        scope: EntitlementScope::organization(),
        now,
        inputs,
    }
}

/// Build a resolution for one project inside an organization.
pub fn project_resolution<'a>(
    org_id: &'a OrganizationId,
    project_id: &'a ProjectId,
    now: i64,
    inputs: EntitlementInputs<'a>,
) -> EntitlementResolution<'a> {
    EntitlementResolution {
        org_id,
        scope: EntitlementScope::project(project_id.clone()),
        now,
        inputs,
    }
}
