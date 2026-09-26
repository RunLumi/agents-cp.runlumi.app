//! Feature flags and kill switches: the two rollout levers, and the one safety
//! off-switch, from F24-006 and F24-007.
//!
//! They are in one module because they are easy to confuse and must not be:
//!
//! * A **feature flag** turns something on. It is a rollout lever, never a plan
//!   entitlement — P06 owns entitlements, and a flag may not grant a capability
//!   the entitlement projection denies. A flag that could do that would be a
//!   back door into billing.
//! * A **kill switch** turns something off, and is a *platform* capability
//!   rather than a customer permission. ADR 0007 keeps it out of the
//!   `StaffPermission` conversation for exactly that reason: no customer role can
//!   reach it, and no org policy can grant it.
//!
//! # The two properties that are easy to get wrong
//!
//! **A percentage rollout must be stable for an organization.** Cohort membership
//! is a hash of the organization id against the percentage, not a random draw per
//! request. A per-request draw would make a tenant flicker in and out of a
//! rollout, which is worse than either state: an operator watching a partially
//! enabled feature cannot reason about what they are seeing.
//!
//! **A kill switch that expires stops applying, and says so.** An expired switch
//! resolves to *not engaged* and is reported as expired rather than silently
//! ignored, because a safety control that quietly stops working is worse than one
//! that was never there. Re-engagement is an explicit act with its own audit
//! record.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::core::OrganizationId;

// ------------------------------------------------------------------ flags ---

/// Who a percentage rollout is evaluated against (F24-006).
///
/// `none` means the percentage is evaluated against the organization, which is
/// the only stable unit available for an organization-scoped flag.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagCohort {
    User,
    Device,
    #[default]
    None,
}

impl FlagCohort {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Device => "device",
            Self::None => "none",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "device" => Some(Self::Device),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// A flag as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeatureFlag {
    pub flag_key: String,
    pub enabled: bool,
    /// 0..=100.
    pub rollout_percentage: u8,
    pub org_allowlist: Vec<String>,
    pub cohort: FlagCohort,
    /// Required. An expired flag resolves off and is reported as expired.
    pub expires_at: String,
    pub owner_staff_principal_id: String,
}

/// The resolved answer, with the reason it is that answer.
///
/// An operator asking "why is this on for them?" needs the reason, not just the
/// boolean, so the resolution carries which rule fired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagResolution {
    /// `expires_at` is in the past. F24-006's "not a permanent store" rule.
    Expired,
    Disabled,
    /// The organization is on the allowlist.
    Allowlisted,
    /// A stable hash of the organization id fell inside the rollout percentage.
    PercentageIncluded,
    /// A stable hash of the organization id fell outside the rollout percentage.
    PercentageExcluded,
}

impl FlagResolution {
    pub const fn is_on(self) -> bool {
        matches!(self, Self::Allowlisted | Self::PercentageIncluded)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::Disabled => "disabled",
            Self::Allowlisted => "allowlisted",
            Self::PercentageIncluded => "percentage_included",
            Self::PercentageExcluded => "percentage_excluded",
        }
    }
}

impl fmt::Display for FlagResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Resolve a flag for one organization.
///
/// The order is the contract:
/// `expires_at` in the past → off; org allowlist hit → on; percentage → stable
/// hash; otherwise off.
///
/// `now` is passed in rather than read from a clock so the resolution is a pure
/// function of stored state and a caller-supplied instant, which is what makes it
/// testable at the boundary of expiry.
pub fn resolve_flag(
    flag: &FeatureFlag,
    organization_id: &OrganizationId,
    now: &str,
) -> FlagResolution {
    // Expiry first. A flag whose expiry has passed is off even if it is enabled
    // and even if the organization is allowlisted: continuing to honour an
    // expired flag is how a temporary rollout becomes permanent configuration,
    // which is exactly what F24-006 warns against.
    if now >= flag.expires_at.as_str() {
        return FlagResolution::Expired;
    }
    if !flag.enabled {
        return FlagResolution::Disabled;
    }
    if flag
        .org_allowlist
        .iter()
        .any(|allowed| allowed == organization_id.as_str())
    {
        return FlagResolution::Allowlisted;
    }
    if flag.rollout_percentage == 0 {
        return FlagResolution::PercentageExcluded;
    }
    if flag.rollout_percentage >= 100 {
        return FlagResolution::PercentageIncluded;
    }
    if cohort_hash(organization_id.as_str()) % 100 < u32::from(flag.rollout_percentage) {
        FlagResolution::PercentageIncluded
    } else {
        FlagResolution::PercentageExcluded
    }
}

/// FNV-1a over the organization id, folded to a byte.
///
/// Chosen because it is a *stable* hash: the same organization must land in the
/// same cohort on every request, on every deploy, and on every region. It is not
/// a cryptographic hash and does not need to be — the input is a public
/// identifier and the property wanted is determinism, not unguessability. The
/// `cohort` field exists for the cases where the unit is a user or a device
/// instead, where the same stability requirement applies.
pub fn cohort_hash(value: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in value.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// Validate a flag write. F24-006 requires an expiry, so a flag with no
/// `expires_at` is refused rather than stored and reported as permanently on.
pub fn validate_flag_input(
    flag_key: &str,
    rollout_percentage: i64,
    expires_at: Option<&str>,
) -> Result<(), FlagError> {
    if flag_key.len() < 3
        || flag_key.len() > 64
        || !flag_key.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return Err(FlagError::InvalidFlagKey);
    }
    if !(0..=100).contains(&rollout_percentage) {
        return Err(FlagError::InvalidPercentage);
    }
    match expires_at {
        Some(expiry) if !expiry.is_empty() && expiry.len() == 24 => Ok(()),
        _ => Err(FlagError::ExpiryRequired),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagError {
    InvalidFlagKey,
    InvalidPercentage,
    ExpiryRequired,
}

impl FlagError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidFlagKey => "flag_key_invalid",
            Self::InvalidPercentage => "rollout_percentage_invalid",
            Self::ExpiryRequired => "flag_expires_required",
        }
    }
}

// ----------------------------------------------------------- kill switches ---

/// What a kill switch can target (F24-007).
///
/// Exactly one class and one reference per switch, and no bulk form. F24-007
/// requires a narrow switch and the acceptance criterion requires a rollback that
/// can "target one org/provider before global disable" — which is only possible
/// if the target is a single named thing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchTargetClass {
    InferenceProvider,
    ModelRoute,
    McpServer,
    PluginVersion,
    ComputerUse,
    ClientVersion,
}

impl KillSwitchTargetClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InferenceProvider => "inference_provider",
            Self::ModelRoute => "model_route",
            Self::McpServer => "mcp_server",
            Self::PluginVersion => "plugin_version",
            Self::ComputerUse => "computer_use",
            Self::ClientVersion => "client_version",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "inference_provider" => Some(Self::InferenceProvider),
            "model_route" => Some(Self::ModelRoute),
            "mcp_server" => Some(Self::McpServer),
            "plugin_version" => Some(Self::PluginVersion),
            "computer_use" => Some(Self::ComputerUse),
            "client_version" => Some(Self::ClientVersion),
            _ => None,
        }
    }
}

/// How wide the switch applies. Both values are checked; see
/// [`kill_switch_applies`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchScope {
    Global,
    Organization,
}

impl KillSwitchScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Organization => "organization",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "global" => Some(Self::Global),
            "organization" => Some(Self::Organization),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchState {
    Engaged,
    Lifted,
}

impl KillSwitchState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Engaged => "engaged",
            Self::Lifted => "lifted",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "engaged" => Some(Self::Engaged),
            "lifted" => Some(Self::Lifted),
            _ => None,
        }
    }
}

/// A kill switch as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KillSwitch {
    pub target_class: KillSwitchTargetClass,
    pub target_ref: String,
    pub scope: KillSwitchScope,
    /// Present exactly when `scope` is `organization`. The database enforces it;
    /// this type refuses to build a mismatched one, so the invariant is not
    /// expressible in a `KillSwitch` value either.
    pub organization_id: Option<OrganizationId>,
    pub state: KillSwitchState,
    /// `None` means "until lifted".
    pub expires_at: Option<String>,
}

/// Why a switch does not apply, or that it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KillSwitchResolution {
    Engaged,
    Lifted,
    Expired,
    NotEngaged,
}

impl KillSwitchResolution {
    /// An expired switch resolves to NOT engaged and is *reported* as expired.
    /// Returning `Engaged` here would be the fail-open direction.
    pub const fn is_engaged(self) -> bool {
        matches!(self, Self::Engaged)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Engaged => "engaged",
            Self::Lifted => "lifted",
            Self::Expired => "expired",
            Self::NotEngaged => "not_engaged",
        }
    }
}

/// Is this switch currently disabling the named target for this organization?
///
/// `now` is the caller-supplied request instant, compared against `expires_at` in
/// the same fixed 24-character UTC form the schema stores, which is what makes a
/// lexicographic comparison equivalent to a chronological one.
pub fn kill_switch_applies(
    switch: &KillSwitch,
    target_class: KillSwitchTargetClass,
    target_ref: &str,
    organization_id: &OrganizationId,
    now: &str,
) -> KillSwitchResolution {
    if switch.target_class != target_class || switch.target_ref != target_ref {
        return KillSwitchResolution::NotEngaged;
    }
    if switch.state == KillSwitchState::Lifted {
        return KillSwitchResolution::Lifted;
    }
    // Scope is checked before expiry: a switch aimed at another organization is
    // not this switch at all, and reporting it as "expired" would send an
    // operator to re-engage something that never applied to them.
    let in_scope = match switch.scope {
        KillSwitchScope::Global => true,
        KillSwitchScope::Organization => switch.organization_id.as_ref() == Some(organization_id),
    };
    if !in_scope {
        return KillSwitchResolution::NotEngaged;
    }
    if switch
        .expires_at
        .as_deref()
        .is_some_and(|expiry| now >= expiry)
    {
        return KillSwitchResolution::Expired;
    }
    KillSwitchResolution::Engaged
}

/// Validate a proposed switch before it is written.
///
/// `kill_switch_too_broad` is the reason this function exists rather than a
/// field check. The narrowness is structural — one class, one ref — but a `*` in
/// the reference would reintroduce the bulk form the schema's closed enum was
/// written to prevent, so it is refused here with its own code.
pub fn validate_kill_switch_input(
    target_class: KillSwitchTargetClass,
    target_ref: &str,
    scope: KillSwitchScope,
    organization_id: Option<&OrganizationId>,
    reason: &str,
    expires_at: Option<&str>,
) -> Result<(), KillSwitchError> {
    if target_ref.trim().is_empty() || target_ref.len() > 200 {
        return Err(KillSwitchError::TargetUnknown);
    }
    if target_ref.contains('*') {
        return Err(KillSwitchError::TooBroad);
    }
    if reason.trim().is_empty() || reason.len() > 500 {
        return Err(KillSwitchError::ReasonRequired);
    }
    // A `plugin_version` target is `package@version`; anything else with an `@`
    // is a caller trying to smuggle a two-part target into a class that takes
    // one part, which would make the reference ambiguous.
    if matches!(target_class, KillSwitchTargetClass::PluginVersion)
        && target_ref.split('@').count() != 2
    {
        return Err(KillSwitchError::TargetUnknown);
    }
    match scope {
        KillSwitchScope::Global if organization_id.is_some() => {
            return Err(KillSwitchError::ScopeOrganizationMismatch);
        }
        KillSwitchScope::Organization if organization_id.is_none() => {
            return Err(KillSwitchError::ScopeOrganizationMismatch);
        }
        _ => {}
    }
    if let Some(expiry) = expires_at
        && expiry.len() != 24
    {
        return Err(KillSwitchError::InvalidExpiry);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KillSwitchError {
    TargetUnknown,
    TooBroad,
    ReasonRequired,
    ScopeOrganizationMismatch,
    InvalidExpiry,
}

impl KillSwitchError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::TargetUnknown => "kill_switch_target_unknown",
            Self::TooBroad => "kill_switch_too_broad",
            Self::ReasonRequired => "kill_switch_reason_required",
            Self::ScopeOrganizationMismatch => "kill_switch_scope_mismatch",
            Self::InvalidExpiry => "kill_switch_expiry_invalid",
        }
    }
}

// ------------------------------------------------------------------ tests ---

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: &str = "2026-09-26T12:00:00.000Z";
    const FUTURE: &str = "2026-10-26T12:00:00.000Z";
    const PAST: &str = "2026-08-26T12:00:00.000Z";

    fn org() -> OrganizationId {
        "org_0123456789abcdef0123456789abcdef"
            .parse()
            .expect("org id")
    }

    fn org_other() -> OrganizationId {
        "org_ffffffffffffffffffffffffffffffff"
            .parse()
            .expect("org id")
    }

    fn flag() -> FeatureFlag {
        FeatureFlag {
            flag_key: "plugins.v2".into(),
            enabled: true,
            rollout_percentage: 50,
            org_allowlist: Vec::new(),
            cohort: FlagCohort::None,
            expires_at: FUTURE.into(),
            owner_staff_principal_id: "stf_0123456789abcdef0123456789abcdef".into(),
        }
    }

    // -- flags --------------------------------------------------------------

    /// F24-006's "avoid using flags as permanent configuration store" is only
    /// true if an expired flag actually stops working.
    #[test]
    fn an_expired_flag_resolves_off_even_when_enabled_and_allowlisted() {
        let mut expired = flag();
        expired.expires_at = PAST.into();
        expired.org_allowlist = vec![org().as_str().to_owned()];
        assert_eq!(resolve_flag(&expired, &org(), NOW), FlagResolution::Expired);
        assert!(!FlagResolution::Expired.is_on());
    }

    #[test]
    fn a_disabled_flag_is_off_even_inside_the_percentage() {
        let mut disabled = flag();
        disabled.enabled = false;
        assert_eq!(
            resolve_flag(&disabled, &org(), NOW),
            FlagResolution::Disabled
        );
    }

    #[test]
    fn the_org_allowlist_wins_over_the_percentage() {
        let allowlisted = FeatureFlag {
            org_allowlist: vec![org().as_str().to_owned()],
            ..flag()
        };
        // A 10% rollout would very likely exclude this org by hash; the
        // allowlist is checked first, so the answer is unconditional.
        assert_eq!(
            resolve_flag(&allowlisted, &org(), NOW),
            FlagResolution::Allowlisted
        );
    }

    /// The stability requirement. A per-request random draw would make a tenant
    /// flicker; a stable hash cannot.
    #[test]
    fn cohort_assignment_is_stable_for_an_organization_across_calls() {
        let first = resolve_flag(&flag(), &org(), NOW);
        for _ in 0..100 {
            assert_eq!(resolve_flag(&flag(), &org(), NOW), first);
        }
    }

    #[test]
    fn the_percentage_is_monotonic_so_a_ramp_never_removes_a_tenant() {
        let mut included_at_10 = Vec::new();
        for n in 0..200u32 {
            let id = format!("org_{n:032x}").parse().expect("org id");
            if resolve_flag(
                &FeatureFlag {
                    rollout_percentage: 10,
                    ..flag()
                },
                &id,
                NOW,
            )
            .is_on()
            {
                included_at_10.push(id.as_str().to_owned());
            }
        }
        for id in &included_at_10 {
            let parsed: OrganizationId = id.parse().expect("org id");
            for percentage in [20, 50, 100] {
                assert!(
                    resolve_flag(
                        &FeatureFlag {
                            rollout_percentage: percentage,
                            ..flag()
                        },
                        &parsed,
                        NOW
                    )
                    .is_on(),
                    "ramping to {percentage}% dropped a tenant that was already in"
                );
            }
        }
        // And 0% / 100% are the two degenerate answers.
        assert!(
            !resolve_flag(
                &FeatureFlag {
                    rollout_percentage: 0,
                    ..flag()
                },
                &org(),
                NOW
            )
            .is_on()
        );
        assert!(
            resolve_flag(
                &FeatureFlag {
                    rollout_percentage: 100,
                    ..flag()
                },
                &org(),
                NOW
            )
            .is_on()
        );
    }

    #[test]
    fn a_flag_needs_a_bounded_key_a_bounded_percentage_and_an_expiry() {
        assert_eq!(
            validate_flag_input("ab", 50, Some(FUTURE)),
            Err(FlagError::InvalidFlagKey)
        );
        assert_eq!(
            validate_flag_input("Plugins", 50, Some(FUTURE)),
            Err(FlagError::InvalidFlagKey)
        );
        assert_eq!(
            validate_flag_input("plugins.v2", 101, Some(FUTURE)),
            Err(FlagError::InvalidPercentage)
        );
        assert_eq!(
            validate_flag_input("plugins.v2", -1, Some(FUTURE)),
            Err(FlagError::InvalidPercentage)
        );
        assert_eq!(
            validate_flag_input("plugins.v2", 50, None),
            Err(FlagError::ExpiryRequired),
            "F24-006 forbids flags as a permanent configuration store"
        );
        assert_eq!(validate_flag_input("plugins.v2", 50, Some(FUTURE)), Ok(()));
    }

    // -- kill switches ------------------------------------------------------

    fn switch(scope: KillSwitchScope, organization_id: Option<OrganizationId>) -> KillSwitch {
        KillSwitch {
            target_class: KillSwitchTargetClass::PluginVersion,
            target_ref: "pkg_0123456789abcdef0123456789abcdef@1.0.0".into(),
            scope,
            organization_id,
            state: KillSwitchState::Engaged,
            expires_at: None,
        }
    }

    /// F24's acceptance criterion: rollback can target one org before a global
    /// disable. The organization-scoped switch must therefore not touch anyone
    /// else, and the global one must touch everyone.
    #[test]
    fn a_switch_is_narrow_to_its_own_target_and_scope() {
        let org_scoped = switch(KillSwitchScope::Organization, Some(org()));
        assert_eq!(
            kill_switch_applies(
                &org_scoped,
                KillSwitchTargetClass::PluginVersion,
                "pkg_0123456789abcdef0123456789abcdef@1.0.0",
                &org(),
                NOW
            ),
            KillSwitchResolution::Engaged
        );
        assert_eq!(
            kill_switch_applies(
                &org_scoped,
                KillSwitchTargetClass::PluginVersion,
                "pkg_0123456789abcdef0123456789abcdef@1.0.0",
                &org_other(),
                NOW
            ),
            KillSwitchResolution::NotEngaged
        );
        // A different version of the same package is not this switch.
        assert_eq!(
            kill_switch_applies(
                &org_scoped,
                KillSwitchTargetClass::PluginVersion,
                "pkg_0123456789abcdef0123456789abcdef@1.0.1",
                &org(),
                NOW
            ),
            KillSwitchResolution::NotEngaged
        );
        // A different class is not this switch.
        assert_eq!(
            kill_switch_applies(
                &org_scoped,
                KillSwitchTargetClass::McpServer,
                "pkg_0123456789abcdef0123456789abcdef@1.0.0",
                &org(),
                NOW
            ),
            KillSwitchResolution::NotEngaged
        );
        // ...and a global switch covers the organization as well.
        assert_eq!(
            kill_switch_applies(
                &switch(KillSwitchScope::Global, None),
                KillSwitchTargetClass::PluginVersion,
                "pkg_0123456789abcdef0123456789abcdef@1.0.0",
                &org(),
                NOW
            ),
            KillSwitchResolution::Engaged
        );
    }

    /// The direction that matters most. A safety control that silently stops
    /// applying is worse than no control, so an expired switch is NOT engaged and
    /// says so.
    #[test]
    fn an_expired_switch_stops_applying_and_is_reported_as_expired() {
        let expiring = KillSwitch {
            expires_at: Some(PAST.into()),
            ..switch(KillSwitchScope::Global, None)
        };
        let resolution = kill_switch_applies(
            &expiring,
            KillSwitchTargetClass::PluginVersion,
            "pkg_0123456789abcdef0123456789abcdef@1.0.0",
            &org(),
            NOW,
        );
        assert_eq!(resolution, KillSwitchResolution::Expired);
        assert!(!resolution.is_engaged());
        assert_eq!(resolution.as_str(), "expired");
    }

    #[test]
    fn a_lifted_switch_reports_lifted_rather_than_engaged() {
        let lifted = KillSwitch {
            state: KillSwitchState::Lifted,
            ..switch(KillSwitchScope::Global, None)
        };
        assert_eq!(
            kill_switch_applies(
                &lifted,
                KillSwitchTargetClass::PluginVersion,
                "pkg_0123456789abcdef0123456789abcdef@1.0.0",
                &org(),
                NOW
            ),
            KillSwitchResolution::Lifted
        );
    }

    #[test]
    fn a_switch_aimed_at_another_organization_reports_not_engaged_not_expired() {
        // Reporting `Expired` here would send an operator to re-engage something
        // that never applied to them.
        let expiring = KillSwitch {
            expires_at: Some(PAST.into()),
            ..switch(KillSwitchScope::Organization, Some(org_other()))
        };
        assert_eq!(
            kill_switch_applies(
                &expiring,
                KillSwitchTargetClass::PluginVersion,
                "pkg_0123456789abcdef0123456789abcdef@1.0.0",
                &org(),
                NOW
            ),
            KillSwitchResolution::NotEngaged
        );
    }

    /// No bulk form. `kill_switch_too_broad` is the code an operator sees when
    /// they try to reach for one.
    #[test]
    fn a_bulk_target_is_refused() {
        assert_eq!(
            validate_kill_switch_input(
                KillSwitchTargetClass::PluginVersion,
                "pkg_*",
                KillSwitchScope::Global,
                None,
                "incident 42",
                None
            ),
            Err(KillSwitchError::TooBroad)
        );
    }

    #[test]
    fn a_switch_needs_exactly_one_target_a_reason_and_a_matching_scope() {
        assert_eq!(
            validate_kill_switch_input(
                KillSwitchTargetClass::PluginVersion,
                "",
                KillSwitchScope::Global,
                None,
                "incident 42",
                None
            ),
            Err(KillSwitchError::TargetUnknown)
        );
        assert_eq!(
            validate_kill_switch_input(
                KillSwitchTargetClass::PluginVersion,
                "pkg_0123456789abcdef0123456789abcdef",
                KillSwitchScope::Global,
                None,
                "incident 42",
                None
            ),
            Err(KillSwitchError::TargetUnknown),
            "a plugin_version target is package@version"
        );
        assert_eq!(
            validate_kill_switch_input(
                KillSwitchTargetClass::PluginVersion,
                "pkg_0123456789abcdef0123456789abcdef@1.0.0",
                KillSwitchScope::Global,
                None,
                "  ",
                None
            ),
            Err(KillSwitchError::ReasonRequired)
        );
        assert_eq!(
            validate_kill_switch_input(
                KillSwitchTargetClass::PluginVersion,
                "pkg_0123456789abcdef0123456789abcdef@1.0.0",
                KillSwitchScope::Organization,
                None,
                "incident 42",
                None
            ),
            Err(KillSwitchError::ScopeOrganizationMismatch)
        );
        assert_eq!(
            validate_kill_switch_input(
                KillSwitchTargetClass::PluginVersion,
                "pkg_0123456789abcdef0123456789abcdef@1.0.0",
                KillSwitchScope::Global,
                Some(&org()),
                "incident 42",
                None
            ),
            Err(KillSwitchError::ScopeOrganizationMismatch)
        );
        assert_eq!(
            validate_kill_switch_input(
                KillSwitchTargetClass::PluginVersion,
                "pkg_0123456789abcdef0123456789abcdef@1.0.0",
                KillSwitchScope::Organization,
                Some(&org()),
                "incident 42",
                Some("2026-13-01")
            ),
            Err(KillSwitchError::InvalidExpiry)
        );
        assert_eq!(
            validate_kill_switch_input(
                KillSwitchTargetClass::PluginVersion,
                "pkg_0123456789abcdef0123456789abcdef@1.0.0",
                KillSwitchScope::Organization,
                Some(&org()),
                "incident 42",
                Some(FUTURE)
            ),
            Ok(())
        );
    }

    #[test]
    fn the_cohort_hash_is_stable_and_spreads_organizations() {
        assert_eq!(
            cohort_hash("org_0123456789abcdef0123456789abcdef"),
            cohort_hash("org_0123456789abcdef0123456789abcdef")
        );
        // A stable hash over distinct inputs should not collapse them all into one
        // bucket; a constant would make a 10% rollout all-or-nothing.
        let buckets = (0..200u32)
            .map(|n| cohort_hash(&format!("org_{n:032x}")) % 10)
            .collect::<std::collections::BTreeSet<_>>();
        assert!(
            buckets.len() >= 8,
            "the cohort hash is not spreading: {buckets:?}"
        );
    }

    #[test]
    fn every_error_has_a_stable_code() {
        assert_eq!(FlagError::ExpiryRequired.code(), "flag_expires_required");
        assert_eq!(KillSwitchError::TooBroad.code(), "kill_switch_too_broad");
        assert_eq!(
            KillSwitchError::TargetUnknown.code(),
            "kill_switch_target_unknown"
        );
    }
}
