//! The `LicenseState` capability matrix and pure license-snapshot validation.
//!
//! WHY a pure matrix: P06-CR-002 requires that a transient billing or provider
//! outage never instantly bricks unrelated local work, while cloud-paid
//! capabilities may fail sooner with a stable reason. That trade-off is a pure
//! function of (license state, provider availability, capability class, clock,
//! policy freshness, offline validity), so it is expressed as one total
//! function here instead of being re-derived per route.
//!
//! # Signatures
//!
//! This module performs NO cryptography. Verifying the Ed25519 signature over
//! the canonical license bytes (UTF-8 JSON, lexicographically sorted object
//! keys, no insignificant whitespace, RFC 3339 UTC integer timestamps) is the
//! job of the crypto adapter, and it must run *before*
//! [`validate_license_snapshot`]. A caller that cannot verify the signature
//! must treat the snapshot as absent; there is no "unverified but usable" path
//! in this module.

use serde::{Deserialize, Serialize};

use crate::core::{ManagedDeviceId, OrganizationId};

use super::{
    EntitlementError, LicenseSnapshotId, MAX_TIMESTAMP_UNIX_SECONDS, MIN_TIMESTAMP_UNIX_SECONDS,
    SubscriptionStatus,
};

/// Baseline offline grace for local-only capabilities: 7 days.
pub const LOCAL_ONLY_GRACE_SECONDS: i64 = 604_800;

/// Baseline bounded grace for cloud control-plane managed work: 24 hours.
pub const CLOUD_CONTROL_PLANE_GRACE_SECONDS: i64 = 86_400;

/// Platform-paid inference receives no additional billing grace.
pub const PLATFORM_PAID_INFERENCE_GRACE_SECONDS: i64 = 0;

/// Maximum tolerated clock skew when validating a signed license snapshot.
pub const MAX_CLOCK_SKEW_SECONDS: i64 = 120;

/// The only license snapshot claim schema this build understands.
pub const LICENSE_SNAPSHOT_SCHEMA_VERSION: u32 = 1;

/// Ceiling on a signing key identifier, in bytes.
pub const MAX_LICENSE_KEY_ID_BYTES: usize = 64;

/// Ceiling on a snapshot audience string, in bytes.
pub const MAX_LICENSE_AUDIENCE_BYTES: usize = 128;

/// The server-side license projection.
///
/// This is a projection of subscription state plus provider reachability, never
/// a second authority. [`LicenseState::from_subscription_status`] is the only
/// way commercial state becomes a license state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseState {
    Active,
    Grace,
    PastDue,
    Suspended,
    Cancelled,
    Expired,
    ProviderUnavailable,
}

impl LicenseState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Grace => "grace",
            Self::PastDue => "past_due",
            Self::Suspended => "suspended",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::ProviderUnavailable => "provider_unavailable",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "grace" => Some(Self::Grace),
            "past_due" => Some(Self::PastDue),
            "suspended" => Some(Self::Suspended),
            "cancelled" => Some(Self::Cancelled),
            "expired" => Some(Self::Expired),
            "provider_unavailable" => Some(Self::ProviderUnavailable),
            _ => None,
        }
    }

    /// Project the mapped subscription status and current provider reachability
    /// into a license state.
    ///
    /// [`LicenseState::ProviderUnavailable`] means the commercial state itself
    /// could not be read, which is strictly narrower than "the provider is
    /// slow". A readable subscription always wins, because a provider outage
    /// must never silently rewrite a known commercial state — provider
    /// reachability is applied per capability class in the matrix instead.
    pub fn from_subscription_status(
        status: SubscriptionStatus,
        provider: ProviderAvailability,
    ) -> Self {
        match provider {
            ProviderAvailability::Unavailable => Self::ProviderUnavailable,
            ProviderAvailability::Available
            | ProviderAvailability::Degraded
            | ProviderAvailability::Unknown => Self::license_state_for_status(status),
        }
    }

    /// Map a readable subscription status without any provider input. This is
    /// the only commercial source of a license state.
    pub const fn license_state_for_status(status: SubscriptionStatus) -> Self {
        match status {
            SubscriptionStatus::Trialing | SubscriptionStatus::Active => Self::Active,
            SubscriptionStatus::Grace => Self::Grace,
            SubscriptionStatus::PastDue => Self::PastDue,
            SubscriptionStatus::Suspended => Self::Suspended,
            SubscriptionStatus::Cancelled => Self::Cancelled,
        }
    }
}

/// Upstream provider reachability, as observed by the billing/entitlement
/// adapter. It is strictly read-only status: it may gate one provider route and
/// it can never change a Lumi subscription, entitlement, permission, or budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAvailability {
    Available,
    Degraded,
    Unavailable,
    Unknown,
}

impl ProviderAvailability {
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

    /// Whether a provider-paid route may be admitted at all. `degraded` and
    /// `unknown` are not `available`: paid work must not start on a provider
    /// whose commercial standing is not confirmed.
    pub const fn admits_paid_route(self) -> bool {
        matches!(self, Self::Available)
    }
}

/// The three frozen capability classes. The class, not the subscription state
/// alone, decides how much billing grace a capability gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityClass {
    LocalOnly,
    CloudControlPlane,
    PlatformPaidInference,
}

impl CapabilityClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalOnly => "local_only",
            Self::CloudControlPlane => "cloud_control_plane",
            Self::PlatformPaidInference => "platform_paid_inference",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "local_only" => Some(Self::LocalOnly),
            "cloud_control_plane" => Some(Self::CloudControlPlane),
            "platform_paid_inference" => Some(Self::PlatformPaidInference),
            _ => None,
        }
    }

    /// The frozen baseline grace window for this class: 7 days local-only,
    /// 24 hours for the cloud control plane, and zero for platform-paid
    /// inference. A `None` candidate keeps the default.
    pub const fn default_grace_seconds(self) -> i64 {
        match self {
            Self::LocalOnly => LOCAL_ONLY_GRACE_SECONDS,
            Self::CloudControlPlane => CLOUD_CONTROL_PLANE_GRACE_SECONDS,
            Self::PlatformPaidInference => PLATFORM_PAID_INFERENCE_GRACE_SECONDS,
        }
    }

    /// Narrow a class's baseline window. A candidate can only shorten it, so no
    /// plan, snapshot, or adapter can extend billing grace.
    pub const fn narrow_grace_seconds(self, candidate: Option<i64>) -> i64 {
        match candidate {
            Some(seconds) if seconds < self.default_grace_seconds() && seconds > 0 => seconds,
            _ => self.default_grace_seconds(),
        }
    }

    /// Cloud managed work must validate current policy freshness; a local-only
    /// runtime may rely on a previously signed snapshot instead.
    pub const fn requires_policy_freshness(self) -> bool {
        matches!(self, Self::CloudControlPlane)
    }
}

/// Stable license denial reasons drawn from the frozen P06 error list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseReason {
    /// Nothing grants the capability in the current commercial state.
    EntitlementNotGranted,
    /// The bounded billing grace window for this class has elapsed.
    EntitlementGraceExpired,
    /// The signed snapshot is past `offline_valid_until` or was issued too far
    /// in the future to be trusted.
    LicenseSnapshotExpired,
    /// `org_id` or device/audience does not match the verifier.
    LicenseAudienceMismatch,
    /// The snapshot was signed by a key ID this verifier does not trust.
    LicenseKeyUnknown,
    /// The snapshot carries an older policy version than one already accepted.
    LicensePolicyRollback,
    /// The upstream provider account is not `available`.
    ProviderEntitlementUnavailable,
    /// Commercial state could not be established, so managed work fails closed.
    SubscriptionStateUnavailable,
}

impl LicenseReason {
    /// Stable machine-readable code from the frozen P06 error list.
    pub const fn code(self) -> &'static str {
        match self {
            Self::EntitlementNotGranted => "entitlement_not_granted",
            Self::EntitlementGraceExpired => "entitlement_grace_expired",
            Self::LicenseSnapshotExpired => "license_snapshot_expired",
            Self::LicenseAudienceMismatch => "license_audience_mismatch",
            Self::LicenseKeyUnknown => "license_key_unknown",
            Self::LicensePolicyRollback => "license_policy_rollback",
            Self::ProviderEntitlementUnavailable => "provider_entitlement_unavailable",
            Self::SubscriptionStateUnavailable => "subscription_state_unavailable",
        }
    }
}

/// One capability-matrix decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LicenseDecision {
    /// `true` only when NEW work is permitted by the current license state.
    pub allowed: bool,
    /// `true` when already-authorized in-flight work may still settle. A
    /// suspended or cancelled license stops new work without stranding a local
    /// run that was admitted while the license was current. Cloud and
    /// platform-paid classes have no local runtime to settle against, so their
    /// denials close in-flight work too.
    pub in_flight_allowed: bool,
    /// The stable reason a denial occurred, or `None` for an allow.
    pub reason: Option<LicenseReason>,
    /// The instant at which this decision changes on its own, in whole Unix
    /// seconds. `None` means no future instant re-opens the capability without
    /// a new signed snapshot or a new commercial state.
    pub expires_at: Option<i64>,
}

impl LicenseDecision {
    fn allow(expires_at: Option<i64>) -> Self {
        Self {
            allowed: true,
            in_flight_allowed: true,
            reason: None,
            expires_at,
        }
    }

    fn in_flight_only(reason: LicenseReason, expires_at: Option<i64>) -> Self {
        Self {
            allowed: false,
            in_flight_allowed: true,
            reason: Some(reason),
            expires_at,
        }
    }

    /// New work AND already-authorized in-flight work are both refused. Used
    /// for the cloud control plane and platform-paid classes, which have no
    /// local runtime that could keep working without the control plane.
    fn denied(reason: LicenseReason, expires_at: Option<i64>) -> Self {
        Self {
            allowed: false,
            in_flight_allowed: false,
            reason: Some(reason),
            expires_at,
        }
    }

    pub const fn denies_new_work(&self) -> bool {
        !self.allowed
    }

    pub fn reason_code(&self) -> Option<&'static str> {
        self.reason.map(LicenseReason::code)
    }

    /// `true` when no future instant alone re-opens this capability: only new
    /// commercial state (or a newly signed snapshot) can change the outcome.
    pub const fn needs_new_commercial_state(&self) -> bool {
        !self.allowed && self.expires_at.is_none()
    }
}

/// Every input the capability matrix reads.
///
/// The four P06 decision inputs stay separate: this struct carries no
/// authorization permission, no usage-budget verdict, and no entitlement
/// value. A caller composes them itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LicenseEvaluationRequest {
    pub state: LicenseState,
    pub provider: ProviderAvailability,
    pub capability_class: CapabilityClass,
    /// Server clock, whole Unix seconds.
    pub now: i64,
    /// `policy_fresh_until` from the signed policy snapshot.
    pub policy_fresh_until: i64,
    /// `offline_valid_until` from the signed license snapshot.
    pub offline_valid_until: i64,
    /// When the current billing grace window started, if any.
    pub grace_started_at: Option<i64>,
    /// A capability class's narrowed grace window, in seconds.
    pub capability_grace_seconds: Option<i64>,
    /// The last known subscription status, used only when
    /// [`LicenseState::ProviderUnavailable`] left commercial state unreadable.
    pub last_known_subscription: Option<SubscriptionStatus>,
}

impl LicenseEvaluationRequest {
    pub fn new(
        state: LicenseState,
        provider: ProviderAvailability,
        capability_class: CapabilityClass,
        now: i64,
        policy_fresh_until: i64,
        offline_valid_until: i64,
    ) -> Self {
        Self {
            state,
            provider,
            capability_class,
            now,
            policy_fresh_until,
            offline_valid_until,
            grace_started_at: None,
            capability_grace_seconds: None,
            last_known_subscription: None,
        }
    }

    pub const fn with_grace_started_at(mut self, grace_started_at: i64) -> Self {
        self.grace_started_at = Some(grace_started_at);
        self
    }

    pub const fn with_capability_grace_seconds(mut self, seconds: i64) -> Self {
        self.capability_grace_seconds = Some(seconds);
        self
    }

    pub const fn with_last_known_subscription(mut self, status: SubscriptionStatus) -> Self {
        self.last_known_subscription = Some(status);
        self
    }

    pub const fn with_state(mut self, state: LicenseState) -> Self {
        self.state = state;
        self
    }

    /// The bounded cloud grace expiry for this request, or `None` when the
    /// grace anchor is unknown.
    pub fn cloud_grace_expires_at(&self) -> Option<i64> {
        self.grace_started_at.and_then(|started_at| {
            started_at.checked_add(
                self.capability_class
                    .narrow_grace_seconds(self.capability_grace_seconds),
            )
        })
    }

    /// The effective offline bound for local-only work.
    pub fn offline_expiry(&self) -> i64 {
        self.offline_valid_until
    }
}

/// The frozen six-input capability matrix.
///
/// With no grace anchor the cloud grace expiry is unknown, and unknown managed
/// state fails closed. Use [`evaluate_license_request`] when the caller holds
/// `grace_started_at` from the billing anchor.
pub fn evaluate_license(
    state: LicenseState,
    provider: ProviderAvailability,
    capability_class: CapabilityClass,
    now: i64,
    policy_fresh_until: i64,
    offline_valid_until: i64,
) -> LicenseDecision {
    evaluate_license_request(&LicenseEvaluationRequest::new(
        state,
        provider,
        capability_class,
        now,
        policy_fresh_until,
        offline_valid_until,
    ))
}

/// Evaluate the capability matrix. This is the single decision path for
/// "may this capability start new work under the current license".
pub fn evaluate_license_request(request: &LicenseEvaluationRequest) -> LicenseDecision {
    let base = base_decision(request);
    // Provider reachability is a cross-cutting modifier: local-only work is
    // unaffected by policy, cloud work follows the subscription state that the
    // base decision already applied, and platform-paid inference is refused
    // unless the provider is confirmed `available`.
    if request.capability_class == CapabilityClass::PlatformPaidInference
        && !request.provider.admits_paid_route()
    {
        return LicenseDecision::denied(
            LicenseReason::ProviderEntitlementUnavailable,
            Some(request.policy_fresh_until),
        );
    }
    base
}

fn base_decision(request: &LicenseEvaluationRequest) -> LicenseDecision {
    match request.state {
        LicenseState::Active => active_decision(request),
        LicenseState::Grace => grace_decision(request),
        LicenseState::PastDue => past_due_decision(request),
        LicenseState::Suspended | LicenseState::Cancelled => terminal_decision(request),
        LicenseState::Expired => expired_decision(request),
        LicenseState::ProviderUnavailable => provider_unavailable_decision(request),
    }
}

fn active_decision(request: &LicenseEvaluationRequest) -> LicenseDecision {
    match request.capability_class {
        // Local-only work is bounded by the signed offline validity, not by
        // online policy freshness: a local runtime may run from a previously
        // signed snapshot.
        CapabilityClass::LocalOnly => LicenseDecision::allow(Some(request.offline_valid_until)),
        CapabilityClass::CloudControlPlane | CapabilityClass::PlatformPaidInference => {
            policy_fresh_guarded(request)
        }
    }
}

fn grace_decision(request: &LicenseEvaluationRequest) -> LicenseDecision {
    match request.capability_class {
        CapabilityClass::LocalOnly => {
            if request.now >= request.offline_valid_until {
                LicenseDecision::in_flight_only(
                    LicenseReason::EntitlementGraceExpired,
                    Some(request.offline_valid_until),
                )
            } else {
                LicenseDecision::allow(Some(request.offline_valid_until))
            }
        }
        CapabilityClass::CloudControlPlane => {
            let Some(cloud_grace_expires_at) = request.cloud_grace_expires_at() else {
                return LicenseDecision::denied(
                    LicenseReason::SubscriptionStateUnavailable,
                    Some(request.policy_fresh_until),
                );
            };
            if request.now >= cloud_grace_expires_at {
                return LicenseDecision::denied(
                    LicenseReason::EntitlementGraceExpired,
                    Some(cloud_grace_expires_at),
                );
            }
            if request.now >= request.policy_fresh_until {
                return LicenseDecision::denied(
                    LicenseReason::LicenseSnapshotExpired,
                    Some(request.policy_fresh_until),
                );
            }
            LicenseDecision::allow(Some(cloud_grace_expires_at.min(request.policy_fresh_until)))
        }
        CapabilityClass::PlatformPaidInference => {
            LicenseDecision::denied(LicenseReason::EntitlementGraceExpired, None)
        }
    }
}

fn past_due_decision(request: &LicenseEvaluationRequest) -> LicenseDecision {
    match request.capability_class {
        CapabilityClass::LocalOnly => {
            if request.now >= request.offline_valid_until {
                LicenseDecision::in_flight_only(
                    LicenseReason::EntitlementGraceExpired,
                    Some(request.offline_valid_until),
                )
            } else {
                LicenseDecision::allow(Some(request.offline_valid_until))
            }
        }
        CapabilityClass::CloudControlPlane | CapabilityClass::PlatformPaidInference => {
            LicenseDecision::denied(LicenseReason::EntitlementGraceExpired, None)
        }
    }
}

fn terminal_decision(request: &LicenseEvaluationRequest) -> LicenseDecision {
    match request.capability_class {
        CapabilityClass::LocalOnly => {
            LicenseDecision::in_flight_only(LicenseReason::EntitlementNotGranted, None)
        }
        CapabilityClass::CloudControlPlane | CapabilityClass::PlatformPaidInference => {
            LicenseDecision::denied(LicenseReason::EntitlementNotGranted, None)
        }
    }
}

fn expired_decision(request: &LicenseEvaluationRequest) -> LicenseDecision {
    match request.capability_class {
        CapabilityClass::LocalOnly => {
            LicenseDecision::in_flight_only(LicenseReason::EntitlementGraceExpired, None)
        }
        CapabilityClass::CloudControlPlane | CapabilityClass::PlatformPaidInference => {
            LicenseDecision::denied(LicenseReason::EntitlementGraceExpired, None)
        }
    }
}

fn provider_unavailable_decision(request: &LicenseEvaluationRequest) -> LicenseDecision {
    match request.capability_class {
        // Local-only work is unaffected by provider reachability.
        CapabilityClass::LocalOnly => LicenseDecision::allow(Some(request.offline_valid_until)),
        // Cloud state follows the subscription grace that was last observed.
        // Mapping uses the status alone so this cannot recurse back into
        // `provider_unavailable`.
        CapabilityClass::CloudControlPlane => match request.last_known_subscription {
            Some(status) => {
                base_decision(&request.with_state(LicenseState::license_state_for_status(status)))
            }
            None => LicenseDecision::denied(
                LicenseReason::SubscriptionStateUnavailable,
                Some(request.policy_fresh_until),
            ),
        },
        CapabilityClass::PlatformPaidInference => LicenseDecision::denied(
            LicenseReason::ProviderEntitlementUnavailable,
            Some(request.policy_fresh_until),
        ),
    }
}

fn policy_fresh_guarded(request: &LicenseEvaluationRequest) -> LicenseDecision {
    if request.capability_class.requires_policy_freshness()
        && request.now >= request.policy_fresh_until
    {
        return LicenseDecision::denied(
            LicenseReason::LicenseSnapshotExpired,
            Some(request.policy_fresh_until),
        );
    }
    LicenseDecision::allow(Some(request.policy_fresh_until))
}

/// The signed claims carried inside the P03 device-policy response.
///
/// This mirrors the frozen shape only. The Ed25519 signature over the canonical
/// bytes is verified by the crypto adapter; this type deliberately contains no
/// signature field so an unverified claim set can never be mistaken for a
/// verified one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseSnapshotClaims {
    pub schema_version: u32,
    pub snapshot_id: LicenseSnapshotId,
    pub org_id: OrganizationId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<ManagedDeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    pub policy_version: i64,
    pub policy_fresh_until: i64,
    pub offline_valid_until: i64,
    pub issued_at: i64,
    pub capability_class: CapabilityClass,
    pub key_id: String,
}

impl LicenseSnapshotClaims {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        snapshot_id: LicenseSnapshotId,
        org_id: OrganizationId,
        device_id: Option<ManagedDeviceId>,
        audience: Option<String>,
        policy_version: i64,
        policy_fresh_until: i64,
        offline_valid_until: i64,
        issued_at: i64,
        capability_class: CapabilityClass,
        key_id: impl Into<String>,
    ) -> Result<Self, EntitlementError> {
        let key_id = key_id.into();
        if key_id.is_empty() || key_id.len() > MAX_LICENSE_KEY_ID_BYTES {
            return Err(EntitlementError::InvalidClaims);
        }
        if audience
            .as_deref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_LICENSE_AUDIENCE_BYTES)
        {
            return Err(EntitlementError::InvalidClaims);
        }
        for instant in [policy_fresh_until, offline_valid_until, issued_at] {
            if !(MIN_TIMESTAMP_UNIX_SECONDS..=MAX_TIMESTAMP_UNIX_SECONDS).contains(&instant) {
                return Err(EntitlementError::InvalidTimestampRange);
            }
        }
        if policy_version < 1 {
            return Err(EntitlementError::InvalidClaims);
        }
        Ok(Self {
            schema_version: LICENSE_SNAPSHOT_SCHEMA_VERSION,
            snapshot_id,
            org_id,
            device_id,
            audience,
            policy_version,
            policy_fresh_until,
            offline_valid_until,
            issued_at,
            capability_class,
            key_id,
        })
    }
}

/// What the verifier already trusts.
#[derive(Clone, Copy, Debug)]
pub struct LicenseSnapshotContext<'a> {
    pub now: i64,
    pub expected_org_id: &'a OrganizationId,
    pub expected_device_id: Option<&'a ManagedDeviceId>,
    /// Bounded set of currently trusted verification key IDs.
    pub trusted_key_ids: &'a [&'a str],
    /// Highest policy version already accepted for this audience.
    pub last_accepted_policy_version: i64,
}

/// Purely validate a verified claim set against the verifier's own context.
///
/// Every check fails closed, and the first failure wins so the reason is
/// deterministic. A malformed claim set reports `entitlement_not_granted`
/// because it can never grant anything.
pub fn validate_license_snapshot(
    claims: &LicenseSnapshotClaims,
    context: &LicenseSnapshotContext<'_>,
) -> Result<(), LicenseReason> {
    if claims.schema_version != LICENSE_SNAPSHOT_SCHEMA_VERSION {
        return Err(LicenseReason::EntitlementNotGranted);
    }
    if claims.key_id.is_empty()
        || claims.key_id.len() > MAX_LICENSE_KEY_ID_BYTES
        || !context.trusted_key_ids.contains(&claims.key_id.as_str())
    {
        return Err(LicenseReason::LicenseKeyUnknown);
    }
    if claims.policy_version < 1
        || claims.offline_valid_until <= claims.issued_at
        || claims.policy_fresh_until <= claims.issued_at
    {
        return Err(LicenseReason::EntitlementNotGranted);
    }
    if &claims.org_id != context.expected_org_id {
        return Err(LicenseReason::LicenseAudienceMismatch);
    }
    // The device binding is symmetric: an org-level verifier must not accept a
    // device-scoped snapshot, and a device verifier must not accept one that is
    // not bound to it.
    match (context.expected_device_id, claims.device_id.as_ref()) {
        (Some(expected), Some(actual)) if expected == actual => {}
        _ => return Err(LicenseReason::LicenseAudienceMismatch),
    }
    if claims.policy_version < context.last_accepted_policy_version {
        return Err(LicenseReason::LicensePolicyRollback);
    }
    if claims.issued_at > context.now.saturating_add(MAX_CLOCK_SKEW_SECONDS) {
        return Err(LicenseReason::LicenseSnapshotExpired);
    }
    if context.now
        > claims
            .offline_valid_until
            .saturating_add(MAX_CLOCK_SKEW_SECONDS)
    {
        return Err(LicenseReason::LicenseSnapshotExpired);
    }
    Ok(())
}
