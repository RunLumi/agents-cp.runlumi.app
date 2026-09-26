//! Internal staff: the third actor kind, and the least powerful one.
//!
//! F24's thesis is that the platform must be operable "without creating a
//! privileged backdoor that is hard to audit". This module is where that thesis
//! becomes structural rather than aspirational:
//!
//! * `StaffRole` and `StaffPermission` are their own enums. Neither converts to
//!   `MembershipRole`, and no `MembershipRole` satisfies a `StaffPermission`, so
//!   a customer `Admin` is structurally unable to hold platform authority and a
//!   `StaffRole` is structurally unable to hold organization authority.
//! * A staff actor's authority is a **role**, and anything that needs customer
//!   context additionally needs an explicit [`SupportGrantState`]. A grant
//!   carries a named actor, a reason, a ticket, a bounded TTL, and a capability
//!   subset, and it is evaluated on **every** request that relies on it — not
//!   once at creation.
//! * **There is no impersonation path.** No function in this module returns a
//!   `Principal`, and no `StaffActor` converts to one. F24-003's "default mode is
//!   metadata and support diagnostics, not impersonation" is met by that absence
//!   rather than by a flag, because a flag can be flipped and an absent
//!   conversion cannot.
//!
//! The credential scheme is `lumi_staff_`, disjoint from both the human session
//! bearer and `lumik_`, so the three actor kinds cannot be confused for one
//! another at a route boundary. That is the same property `core::machine`
//! documents for the machine scheme, and it is why `core::machine`'s tests
//! include a staff shape among its rejected credentials.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::core::{OrganizationId, StaffPrincipalId, SupportGrantId};

// -------------------------------------------------------------------- role ---

/// Platform authority level. F24-002 asks for these to be distinct as the team
/// grows; they are distinct now.
///
/// Adding a variant here without adding its `StaffPermission` set is a contract
/// change (ADR 0007), not an implementation detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaffRole {
    Support,
    Finance,
    Security,
    Engineering,
}

impl StaffRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Support => "support",
            Self::Finance => "finance",
            Self::Security => "security",
            Self::Engineering => "engineering",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "support" => Some(Self::Support),
            "finance" => Some(Self::Finance),
            "security" => Some(Self::Security),
            "engineering" => Some(Self::Engineering),
            _ => None,
        }
    }
}

/// Everything a staff role may do.
///
/// Two families, and the split is the point:
///
/// * `Org*` / `usage.read` require customer context, so they additionally need a
///   support grant naming that organization.
/// * The rest are platform-wide and need no grant: a platform capability is not a
///   customer's data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaffPermission {
    /// Find one organization from a customer-supplied identifier or slug. The
    /// only customer-scoped read available without a grant, and it returns
    /// identity-level metadata, not content.
    OrgLookup,
    OrgSubscriptionRead,
    OrgDevicesRead,
    OrgSessionsRead,
    UsageRead,
    AbuseFlagRead,
    AbuseFlagWrite,
    /// Platform decision against one `package@version` (F25-008). Not an org
    /// policy a customer can lift.
    PluginQuarantine,
    KillSwitchRead,
    /// Operate a kill switch: engage and lift. `kill_switch.operate` is
    /// deliberately NOT a `StaffPermission` a customer role could ever reach —
    /// ADR 0007 makes kill switches a platform capability, not a permission.
    KillSwitchOperate,
    RoutesHealthRead,
    /// A feature flag is a rollout lever, not an entitlement (F24-006).
    FeatureFlagRead,
    /// Every staff role may create and revoke support grants. A grant with no
    /// issuer is not a grant; whoever needs customer context must be able to
    /// request it, and every issuance is audited against a named actor.
    SupportGrantCreate,
    SupportGrantRevoke,
    /// Held by `support` only, exactly as the frozen gate lists it. This is the
    /// permission to ACT under a grant, and it is separate from the permission to
    /// create one on purpose: everyone may request customer context, but only the
    /// support role may use it. Without the split, a security engineer who can
    /// create a grant could also quietly use one.
    SupportGrantUse,
    /// Held by every role: read flags and read kill-switch state, so a support
    /// engineer can answer "is this disabled for them?" without a second role.
    FeatureFlagManage,
}

impl StaffPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OrgLookup => "org.lookup",
            Self::OrgSubscriptionRead => "org.subscription.read",
            Self::OrgDevicesRead => "org.devices.read",
            Self::OrgSessionsRead => "org.sessions.read",
            Self::UsageRead => "usage.read",
            Self::AbuseFlagRead => "abuse.flag.read",
            Self::AbuseFlagWrite => "abuse.flag.write",
            Self::PluginQuarantine => "plugin.quarantine",
            Self::KillSwitchRead => "kill_switch.read",
            Self::KillSwitchOperate => "kill_switch.operate",
            Self::RoutesHealthRead => "routes.health.read",
            Self::FeatureFlagRead => "feature_flag.read",
            Self::SupportGrantCreate => "support_grant.create",
            Self::SupportGrantRevoke => "support_grant.revoke",
            Self::SupportGrantUse => "support_grant.use",
            Self::FeatureFlagManage => "feature_flag.manage",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        for candidate in Self::all() {
            if candidate.as_str() == value {
                return Some(candidate);
            }
        }
        None
    }

    pub const fn all() -> [StaffPermission; 16] {
        [
            Self::OrgLookup,
            Self::OrgSubscriptionRead,
            Self::OrgDevicesRead,
            Self::OrgSessionsRead,
            Self::UsageRead,
            Self::AbuseFlagRead,
            Self::AbuseFlagWrite,
            Self::PluginQuarantine,
            Self::KillSwitchRead,
            Self::KillSwitchOperate,
            Self::RoutesHealthRead,
            Self::FeatureFlagRead,
            Self::SupportGrantCreate,
            Self::SupportGrantRevoke,
            Self::SupportGrantUse,
            Self::FeatureFlagManage,
        ]
    }

    /// Does reading this permission require a `SupportGrant` naming an
    /// organization?
    ///
    /// The list is the frozen gate's, and it is exactly the customer-data half.
    /// `org.lookup` is included because naming the customer is the first half of
    /// looking anything up, and a lookup that is allowed without a grant would
    /// be an ungranted read of customer identity.
    pub const fn requires_support_grant(self) -> bool {
        matches!(
            self,
            Self::OrgLookup
                | Self::OrgSubscriptionRead
                | Self::OrgDevicesRead
                | Self::OrgSessionsRead
                | Self::UsageRead
        )
    }
}

/// The permission set a role holds.
///
/// This is the frozen gate's §3 matrix, transcribed exactly — including the
/// asymmetries, which are the point:
///
/// * `usage.read` is finance-only, so a support engineer cannot read a
///   customer's spend.
/// * `org.devices.read` / `org.sessions.read` are support-only, so the
///   "engineering has no customer-content access by default" rule holds.
/// * `plugin.quarantine` and `kill_switch.operate` are security-only: those are
///   the two actions that disable something for someone else.
/// * `feature_flag.read` is engineering-only, while `feature_flag.manage` is
///   every role — anyone can see the rollout state, and changing it is an
///   explicit act anyone may take deliberately and auditably.
///
/// Each slice spells out the `all staff` tail rather than computing it, because a
/// reader reviewing one role must be able to see the whole set that role has
/// without jumping to another. The duplication is the price of that, and the
/// test below fails if the two ever drift.
///
/// Changing this function is a contract change (ADR 0007), not an
/// implementation detail.
pub fn permissions_for(role: StaffRole) -> &'static [StaffPermission] {
    use StaffPermission::{
        AbuseFlagRead, AbuseFlagWrite, FeatureFlagManage, FeatureFlagRead, KillSwitchOperate,
        KillSwitchRead, OrgDevicesRead, OrgLookup, OrgSessionsRead, OrgSubscriptionRead,
        PluginQuarantine, RoutesHealthRead, SupportGrantCreate, SupportGrantRevoke,
        SupportGrantUse, UsageRead,
    };
    /// The gate's `all staff` line, written out once per role because a
    /// permission present in one role's tail and absent from another's is
    /// invisible in a diff of the shared list.
    const ALL_STAFF: [StaffPermission; 4] = [
        SupportGrantCreate,
        SupportGrantRevoke,
        FeatureFlagManage,
        KillSwitchRead,
    ];
    match role {
        StaffRole::Support => &[
            OrgLookup,
            OrgSubscriptionRead,
            OrgDevicesRead,
            OrgSessionsRead,
            SupportGrantUse,
            ALL_STAFF[0],
            ALL_STAFF[1],
            ALL_STAFF[2],
            ALL_STAFF[3],
        ],
        StaffRole::Finance => &[
            OrgLookup,
            OrgSubscriptionRead,
            UsageRead,
            ALL_STAFF[0],
            ALL_STAFF[1],
            ALL_STAFF[2],
            ALL_STAFF[3],
        ],
        StaffRole::Security => &[
            OrgLookup,
            AbuseFlagRead,
            AbuseFlagWrite,
            PluginQuarantine,
            KillSwitchRead,
            KillSwitchOperate,
            ALL_STAFF[0],
            ALL_STAFF[1],
            ALL_STAFF[2],
            ALL_STAFF[3],
        ],
        StaffRole::Engineering => &[
            OrgLookup,
            RoutesHealthRead,
            FeatureFlagRead,
            ALL_STAFF[0],
            ALL_STAFF[1],
            ALL_STAFF[2],
            ALL_STAFF[3],
        ],
    }
}

pub fn role_allows(role: StaffRole, permission: StaffPermission) -> bool {
    permissions_for(role).contains(&permission)
}

// ------------------------------------------------------------------ actor ---

/// A resolved internal staff caller.
///
/// As with `Principal` and `MachineActor`, a value of this type is a statement
/// about what the store said. There is deliberately no `From<StaffActor>` for
/// `Principal` and no `as_principal` method, and clippy's `-D warnings` is what
/// keeps a future edit from adding one quietly.
#[derive(Clone, PartialEq, Eq)]
pub struct StaffActor {
    pub staff_principal_id: StaffPrincipalId,
    pub role: StaffRole,
    pub credential_prefix: String,
}

impl StaffActor {
    pub fn new(
        staff_principal_id: StaffPrincipalId,
        role: StaffRole,
        credential_prefix: impl Into<String>,
    ) -> Self {
        Self {
            staff_principal_id,
            role,
            credential_prefix: credential_prefix.into(),
        }
    }
}

impl fmt::Debug for StaffActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaffActor")
            .field("staff_principal_id", &self.staff_principal_id)
            .field("role", &self.role)
            .field("credential_prefix", &self.credential_prefix)
            .finish()
    }
}

// ------------------------------------------------------------------ grant ---

/// The grant's state, as read from the store during a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupportGrantState {
    Live,
    Expired,
    Revoked,
}

/// Why a staff request was refused. Every variant is a stable wire code from the
/// frozen gate, and the four grant failures are kept apart because they are four
/// different conversations with the person holding the grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaffDenyReason {
    AuthenticationRequired,
    StaffPrincipalSuspended,
    PermissionDenied,
    SupportGrantRequired,
    SupportGrantExpired,
    SupportGrantRevoked,
    SupportGrantOrganizationMismatch,
    SupportGrantReasonRequired,
    SupportGrantTtlInvalid,
}

impl StaffDenyReason {
    pub const fn code(self) -> &'static str {
        match self {
            Self::AuthenticationRequired => "staff_authentication_required",
            Self::StaffPrincipalSuspended => "staff_principal_suspended",
            Self::PermissionDenied => "staff_permission_denied",
            Self::SupportGrantRequired => "staff_grant_required",
            Self::SupportGrantExpired => "staff_grant_expired",
            Self::SupportGrantRevoked => "staff_grant_revoked",
            Self::SupportGrantOrganizationMismatch => "staff_grant_org_mismatch",
            Self::SupportGrantReasonRequired => "staff_grant_reason_required",
            Self::SupportGrantTtlInvalid => "staff_grant_ttl_invalid",
        }
    }
}

impl fmt::Display for StaffDenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaffDecision {
    Allow,
    Deny(StaffDenyReason),
}

impl StaffDecision {
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// A support grant as the request path sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupportGrantView {
    pub grant_id: SupportGrantId,
    pub organization_id: OrganizationId,
    pub staff_principal_id: StaffPrincipalId,
    /// The explicit capability subset the grant carries. A grant can narrow what
    /// a role holds and never widen it, so the effective authority is the
    /// intersection — see [`effective_permission`].
    pub capabilities: Vec<StaffPermission>,
    pub state: SupportGrantState,
}

impl SupportGrantView {
    pub fn allows(&self, permission: StaffPermission) -> bool {
        self.capabilities.contains(&permission)
    }
}

/// What a staff request is trying to reach.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StaffRequest<'a> {
    /// The customer organization the request touches, when it touches one.
    pub organization: Option<&'a OrganizationId>,
    /// The grant presented with the request, if any.
    pub grant: Option<&'a SupportGrantView>,
    pub principal_suspended: bool,
}

/// Resolve one staff-protected operation.
///
/// # Why the grant is checked for liveness and not merely for existence
///
/// A grant is evaluated on **every** request. If liveness were decided once, at
/// creation, then a grant whose TTL elapsed an hour ago would keep working for
/// whoever still held it, and a revoked grant would keep working until a cache
/// expired. Both are the specific failures ADR 0007 calls out, and both are
/// avoided by the grant's *state* arriving as a field rather than as a `bool`.
pub fn authorize_staff(
    actor: &StaffActor,
    permission: StaffPermission,
    request: StaffRequest<'_>,
) -> StaffDecision {
    if request.principal_suspended {
        return StaffDecision::Deny(StaffDenyReason::StaffPrincipalSuspended);
    }
    // Role first. A staff role that does not hold the permission is denied
    // regardless of any grant, because a grant narrows a role and never widens
    // one — so checking it first is what makes that true rather than aspirational.
    if !role_allows(actor.role, permission) {
        return StaffDecision::Deny(StaffDenyReason::PermissionDenied);
    }
    if !permission.requires_support_grant() {
        return StaffDecision::Allow;
    }

    let Some(organization) = request.organization else {
        return StaffDecision::Deny(StaffDenyReason::SupportGrantRequired);
    };
    let Some(grant) = request.grant else {
        return StaffDecision::Deny(StaffDenyReason::SupportGrantRequired);
    };
    // The grant must be THIS actor's. A support engineer forwarding a colleague's
    // grant id would otherwise act under someone else's named reason, and the
    // customer-visible audit would name the wrong person.
    if grant.staff_principal_id != actor.staff_principal_id {
        return StaffDecision::Deny(StaffDenyReason::SupportGrantRequired);
    }
    if &grant.organization_id != organization {
        return StaffDecision::Deny(StaffDenyReason::SupportGrantOrganizationMismatch);
    }
    // `support_grant.use` is support-only in the frozen matrix, so holding a
    // grant is not by itself authority to act under it. Checking it here means
    // every other role that can CREATE a grant still cannot USE one, which is
    // the separation the gate's list encodes.
    if !role_allows(actor.role, StaffPermission::SupportGrantUse) {
        return StaffDecision::Deny(StaffDenyReason::PermissionDenied);
    }

    match grant.state {
        SupportGrantState::Revoked => {
            return StaffDecision::Deny(StaffDenyReason::SupportGrantRevoked);
        }
        SupportGrantState::Expired => {
            return StaffDecision::Deny(StaffDenyReason::SupportGrantExpired);
        }
        SupportGrantState::Live => {}
    }
    if !grant.allows(permission) {
        return StaffDecision::Deny(StaffDenyReason::PermissionDenied);
    }
    StaffDecision::Allow
}

/// The authority a request actually has, which is the INTERSECTION of the role
/// and the grant rather than either one alone.
///
/// Returns `None` when the two do not overlap, which is a denial: a grant that
/// lists a permission its holder's role does not have grants nothing.
pub fn effective_permission(
    role: StaffRole,
    grant: Option<&SupportGrantView>,
    permission: StaffPermission,
) -> Option<StaffPermission> {
    if !role_allows(role, permission) {
        return None;
    }
    let grant = match grant {
        Some(grant) if grant.state == SupportGrantState::Live => grant,
        Some(_) => return None,
        None => return Some(permission),
    };
    grant.allows(permission).then_some(permission)
}

// ------------------------------------------------------------- grant input ---

/// Widest TTL the frozen gate allows. Seven days; there is no representable
/// "forever" grant.
pub const MAX_SUPPORT_GRANT_TTL_SECONDS: u32 = 604_800;

/// Validate a requested grant before it is written.
///
/// F24-003 and F24-008 both require a reason, and the gate requires a ticket
/// reference. Checking them here rather than in the route means an un-reasoned
/// grant is unrepresentable even if a future route forgets the rule.
pub fn validate_grant_input(
    reason: &str,
    ticket_reference: &str,
    ttl_seconds: u32,
    capabilities: &[StaffPermission],
    role: StaffRole,
) -> Result<(), StaffDenyReason> {
    if reason.trim().is_empty() || reason.len() > 500 {
        return Err(StaffDenyReason::SupportGrantReasonRequired);
    }
    if ticket_reference.trim().is_empty() || ticket_reference.len() > 120 {
        return Err(StaffDenyReason::SupportGrantReasonRequired);
    }
    if ttl_seconds == 0 || ttl_seconds > MAX_SUPPORT_GRANT_TTL_SECONDS {
        return Err(StaffDenyReason::SupportGrantTtlInvalid);
    }
    // A grant is a SUBSET. Rejecting a capability the issuer's role does not hold
    // is what stops a `finance` principal from minting a grant that would let a
    // later step look like device inspection.
    if let Some(capability) = capabilities
        .iter()
        .find(|capability| !role_allows(role, **capability))
    {
        let _ = capability;
        return Err(StaffDenyReason::PermissionDenied);
    }
    Ok(())
}

// ------------------------------------------------------------------ tests ---

#[cfg(test)]
mod tests {
    use super::*;

    /// One id per role, because several tests are specifically about one
    /// principal presenting another's grant. A shared hardcoded id makes those
    /// tests pass for the wrong reason.
    fn actor(role: StaffRole) -> StaffActor {
        let hex = match role {
            StaffRole::Support => "0123456789abcdef",
            StaffRole::Finance => "1111111111111111",
            StaffRole::Security => "2222222222222222",
            StaffRole::Engineering => "3333333333333333",
        };
        StaffActor::new(
            StaffPrincipalId::new(format!("stf_{hex}0123456789abcdef")).expect("staff id"),
            role,
            hex,
        )
    }

    fn org() -> OrganizationId {
        "org_0123456789abcdef0123456789abcdef"
            .parse()
            .expect("org id")
    }

    fn other_org() -> OrganizationId {
        "org_ffffffffffffffffffffffffffffffff"
            .parse()
            .expect("org id")
    }

    fn grant(state: SupportGrantState) -> SupportGrantView {
        SupportGrantView {
            grant_id: SupportGrantId::new("sgr_0123456789abcdef0123456789abcdef").expect("id"),
            organization_id: org(),
            staff_principal_id: actor(StaffRole::Support).staff_principal_id,
            capabilities: vec![
                StaffPermission::OrgLookup,
                StaffPermission::OrgSubscriptionRead,
                StaffPermission::OrgDevicesRead,
            ],
            state,
        }
    }

    fn request<'a>(
        organization: Option<&'a OrganizationId>,
        grant: Option<&'a SupportGrantView>,
    ) -> StaffRequest<'a> {
        StaffRequest {
            organization,
            grant,
            principal_suspended: false,
        }
    }

    /// The load-bearing structural claim of ADR 0007.
    #[test]
    fn a_customer_admin_role_has_no_expression_in_the_staff_permission_set() {
        // There is no `From<MembershipRole>` and no `From<StaffRole>`. This test
        // pins the *consequence* that matters: the two vocabularies share no
        // spelling, so no string, parse, or map can cross between them.
        let staff_codes: BTreeSet<&str> = StaffPermission::all()
            .iter()
            .map(|permission| permission.as_str())
            .collect();
        for membership_permission in [
            "org.read",
            "org.manage",
            "members.manage",
            "billing.manage",
            "data.delete",
            "plugins.manage",
            "service_accounts.manage",
        ] {
            assert!(
                !staff_codes.contains(membership_permission),
                "{membership_permission} must not resolve as a staff permission"
            );
        }
    }

    #[test]
    fn every_staff_permission_has_a_stable_code_and_round_trips() {
        for permission in StaffPermission::all() {
            assert_eq!(
                StaffPermission::parse(permission.as_str()),
                Some(permission),
                "{} must round-trip",
                permission.as_str()
            );
        }
        assert_eq!(StaffPermission::parse("org.manage"), None);
        assert_eq!(StaffPermission::parse("identity.manage"), None);
    }

    /// F24-002, and the gate's §3 matrix, transcribed as a test.
    ///
    /// The first version of this asserted that EVERY role holds EVERY
    /// permission, on the reasoning that a permission no role can exercise is a
    /// dead control. That reasoning is wrong for a least-privilege matrix: the
    /// frozen matrix is deliberately asymmetric, and `usage.read` being
    /// finance-only is the control, not a bug. What the test should pin is
    /// coverage — every permission is reachable by somebody — plus the specific
    /// separations that carry the security claim.
    #[test]
    fn the_four_roles_match_the_frozen_matrix() {
        let roles = [
            StaffRole::Support,
            StaffRole::Finance,
            StaffRole::Security,
            StaffRole::Engineering,
        ];
        // Every permission is held by at least one role: a permission no role
        // carries could never be exercised, which would make it decoration.
        for permission in StaffPermission::all() {
            assert!(
                roles.iter().any(|role| role_allows(*role, permission)),
                "{} is held by no role",
                permission.as_str()
            );
        }
        // Every role holds the `all staff` tail.
        for role in roles {
            for permission in [
                StaffPermission::SupportGrantCreate,
                StaffPermission::SupportGrantRevoke,
                StaffPermission::FeatureFlagManage,
                StaffPermission::KillSwitchRead,
            ] {
                assert!(
                    role_allows(role, permission),
                    "{} must hold {}",
                    role.as_str(),
                    permission.as_str()
                );
            }
        }
        // Spend is finance-only: a support engineer must not read it.
        assert!(role_allows(StaffRole::Finance, StaffPermission::UsageRead));
        for role in [
            StaffRole::Support,
            StaffRole::Security,
            StaffRole::Engineering,
        ] {
            assert!(!role_allows(role, StaffPermission::UsageRead));
        }
        // Customer device/session inspection is support-only, which is how
        // "engineering has no customer-content access by default" holds.
        for permission in [
            StaffPermission::OrgDevicesRead,
            StaffPermission::OrgSessionsRead,
        ] {
            assert!(role_allows(StaffRole::Support, permission));
            for role in [
                StaffRole::Finance,
                StaffRole::Security,
                StaffRole::Engineering,
            ] {
                assert!(!role_allows(role, permission));
            }
        }
        // Disabling something for someone else is security-only.
        for permission in [
            StaffPermission::PluginQuarantine,
            StaffPermission::KillSwitchOperate,
            StaffPermission::AbuseFlagWrite,
        ] {
            assert!(role_allows(StaffRole::Security, permission));
            for role in [
                StaffRole::Support,
                StaffRole::Finance,
                StaffRole::Engineering,
            ] {
                assert!(!role_allows(role, permission));
            }
        }
        // Acting under a grant is support-only. Everyone may request customer
        // context; only support may use it.
        assert!(role_allows(
            StaffRole::Support,
            StaffPermission::SupportGrantUse
        ));
        for role in [
            StaffRole::Finance,
            StaffRole::Security,
            StaffRole::Engineering,
        ] {
            assert!(!role_allows(role, StaffPermission::SupportGrantUse));
        }
        // `feature_flag.read` is engineering-only while `feature_flag.manage` is
        // every role.
        assert!(role_allows(
            StaffRole::Engineering,
            StaffPermission::FeatureFlagRead
        ));
        for role in [StaffRole::Support, StaffRole::Finance, StaffRole::Security] {
            assert!(!role_allows(role, StaffPermission::FeatureFlagRead));
            assert!(role_allows(role, StaffPermission::FeatureFlagManage));
        }
    }

    #[test]
    fn a_platform_capability_needs_no_grant_and_customer_data_does() {
        let security = actor(StaffRole::Security);
        // Platform-wide: quarantine a plugin version with no customer context.
        assert_eq!(
            authorize_staff(
                &security,
                StaffPermission::PluginQuarantine,
                request(None, None)
            ),
            StaffDecision::Allow
        );
        // Customer data: a live grant naming this organization.
        assert_eq!(
            authorize_staff(
                &actor(StaffRole::Support),
                StaffPermission::OrgDevicesRead,
                request(Some(&org()), Some(&grant(SupportGrantState::Live)))
            ),
            StaffDecision::Allow
        );
    }

    #[test]
    fn customer_data_without_a_grant_is_refused() {
        let support = actor(StaffRole::Support);
        assert_eq!(
            authorize_staff(
                &support,
                StaffPermission::OrgDevicesRead,
                request(Some(&org()), None)
            ),
            StaffDecision::Deny(StaffDenyReason::SupportGrantRequired)
        );
        // ...and with no organization named at all.
        assert_eq!(
            authorize_staff(
                &support,
                StaffPermission::OrgDevicesRead,
                request(None, None)
            ),
            StaffDecision::Deny(StaffDenyReason::SupportGrantRequired)
        );
    }

    /// F24-003 / F24-008 / ADR 0007: expiry is enforced on EVERY request, not at
    /// creation. Each of the three refusals is a different code because they are
    /// three different conversations.
    #[test]
    fn an_expired_revoked_or_mismatched_grant_is_refused_with_its_own_code() {
        let support = actor(StaffRole::Support);
        let decide = |grant: &SupportGrantView| {
            authorize_staff(
                &support,
                StaffPermission::OrgSubscriptionRead,
                request(Some(&org()), Some(grant)),
            )
        };
        assert_eq!(
            decide(&grant(SupportGrantState::Expired)),
            StaffDecision::Deny(StaffDenyReason::SupportGrantExpired)
        );
        assert_eq!(
            decide(&grant(SupportGrantState::Revoked)),
            StaffDecision::Deny(StaffDenyReason::SupportGrantRevoked)
        );
        let live = grant(SupportGrantState::Live);
        let mismatched = SupportGrantView {
            organization_id: other_org(),
            ..live.clone()
        };
        assert_eq!(
            decide(&mismatched),
            StaffDecision::Deny(StaffDenyReason::SupportGrantOrganizationMismatch)
        );
        assert_eq!(decide(&live), StaffDecision::Allow);
    }

    /// A grant is a named act. Forwarding a colleague's grant id would make the
    /// customer-visible audit name the wrong person.
    #[test]
    fn a_grant_issued_to_someone_else_is_refused() {
        let finance = actor(StaffRole::Finance);
        // The functional update comes FIRST, so the explicit field is the one
        // that survives. Written the other way round this test would silently
        // re-assert the grant's real owner and pass for the wrong reason.
        let someone_elses = SupportGrantView {
            ..grant(SupportGrantState::Live)
        };
        let someone_elses = SupportGrantView {
            staff_principal_id: actor(StaffRole::Support).staff_principal_id,
            ..someone_elses
        };
        assert_eq!(
            authorize_staff(
                &finance,
                StaffPermission::OrgSubscriptionRead,
                request(Some(&org()), Some(&someone_elses))
            ),
            StaffDecision::Deny(StaffDenyReason::SupportGrantRequired)
        );
    }

    /// A grant narrows a role and never widens one.
    #[test]
    fn a_grant_cannot_widen_the_role_of_its_holder() {
        let security = actor(StaffRole::Security);
        let impossible = SupportGrantView {
            staff_principal_id: security.staff_principal_id.clone(),
            capabilities: vec![StaffPermission::OrgDevicesRead],
            state: SupportGrantState::Live,
            ..grant(SupportGrantState::Live)
        };
        assert_eq!(
            authorize_staff(
                &security,
                StaffPermission::OrgDevicesRead,
                request(Some(&org()), Some(&impossible))
            ),
            StaffDecision::Deny(StaffDenyReason::PermissionDenied)
        );
    }

    /// Every role may CREATE a grant; only support may USE one. Without this
    /// separation, a security engineer — who is granted the ability to quarantine
    /// a vulnerable plugin — would also be able to mint a grant against a
    /// customer and read their devices with it.
    #[test]
    fn holding_a_grant_is_not_authority_to_act_under_it() {
        let mut granted = grant(SupportGrantState::Live);
        let security = actor(StaffRole::Security);
        granted.staff_principal_id = security.staff_principal_id.clone();
        // The role does not hold `org.lookup`'s sibling permission, so this is
        // refused on the role first...
        assert_eq!(
            authorize_staff(
                &security,
                StaffPermission::OrgDevicesRead,
                request(Some(&org()), Some(&granted))
            ),
            StaffDecision::Deny(StaffDenyReason::PermissionDenied)
        );
        // ...and a finance principal, who DOES hold `org.lookup`, is refused on
        // the missing `support_grant.use` rather than being allowed through by
        // the grant.
        let finance = actor(StaffRole::Finance);
        let mut finance_grant = grant(SupportGrantState::Live);
        finance_grant.staff_principal_id = finance.staff_principal_id.clone();
        assert_eq!(
            authorize_staff(
                &finance,
                StaffPermission::OrgLookup,
                request(Some(&org()), Some(&finance_grant))
            ),
            StaffDecision::Deny(StaffDenyReason::PermissionDenied)
        );
    }

    #[test]
    fn a_suspended_staff_principal_is_refused_before_anything_else() {
        let organization = org();
        let live = grant(SupportGrantState::Live);
        let mut suspended = request(Some(&organization), Some(&live));
        suspended.principal_suspended = true;
        assert_eq!(
            authorize_staff(
                &actor(StaffRole::Support),
                StaffPermission::OrgLookup,
                suspended
            ),
            StaffDecision::Deny(StaffDenyReason::StaffPrincipalSuspended)
        );
    }

    #[test]
    fn effective_authority_is_the_intersection_of_role_and_grant() {
        let role = StaffRole::Support;
        let narrow = SupportGrantView {
            capabilities: vec![StaffPermission::OrgLookup],
            ..grant(SupportGrantState::Live)
        };
        assert_eq!(
            effective_permission(role, Some(&narrow), StaffPermission::OrgLookup),
            Some(StaffPermission::OrgLookup)
        );
        assert_eq!(
            effective_permission(role, Some(&narrow), StaffPermission::OrgDevicesRead),
            None,
            "a grant narrows; it cannot add what it does not list"
        );
        // A platform capability needs no grant, so the role alone is enough.
        assert_eq!(
            effective_permission(StaffRole::Security, None, StaffPermission::PluginQuarantine),
            Some(StaffPermission::PluginQuarantine)
        );
        // An expired grant grants nothing, even to the right role.
        assert_eq!(
            effective_permission(
                role,
                Some(&grant(SupportGrantState::Expired)),
                StaffPermission::OrgLookup
            ),
            None
        );
    }

    #[test]
    fn a_grant_needs_a_reason_a_ticket_and_a_bounded_ttl() {
        let role = StaffRole::Support;
        assert_eq!(
            validate_grant_input("", "TICKET-1", 3600, &[], role),
            Err(StaffDenyReason::SupportGrantReasonRequired)
        );
        assert_eq!(
            validate_grant_input("looking into a report", "  ", 3600, &[], role),
            Err(StaffDenyReason::SupportGrantReasonRequired)
        );
        assert_eq!(
            validate_grant_input("looking into a report", "TICKET-1", 0, &[], role),
            Err(StaffDenyReason::SupportGrantTtlInvalid)
        );
        assert_eq!(
            validate_grant_input(
                "looking into a report",
                "TICKET-1",
                MAX_SUPPORT_GRANT_TTL_SECONDS + 1,
                &[],
                role
            ),
            Err(StaffDenyReason::SupportGrantTtlInvalid)
        );
        assert_eq!(
            validate_grant_input(
                "looking into a report",
                "TICKET-1",
                3600,
                &[StaffPermission::OrgDevicesRead],
                role
            ),
            Ok(())
        );
    }

    /// An issuer cannot mint a grant broader than its own role, so a later step
    /// cannot be made to look like something the issuer was entitled to.
    #[test]
    fn a_grant_cannot_list_a_capability_its_issuer_does_not_hold() {
        assert_eq!(
            validate_grant_input(
                "looking into a report",
                "TICKET-1",
                3600,
                &[StaffPermission::OrgDevicesRead],
                StaffRole::Finance
            ),
            Err(StaffDenyReason::PermissionDenied)
        );
    }

    #[test]
    fn every_staff_denial_reason_has_a_stable_code() {
        for (reason, code) in [
            (
                StaffDenyReason::AuthenticationRequired,
                "staff_authentication_required",
            ),
            (
                StaffDenyReason::StaffPrincipalSuspended,
                "staff_principal_suspended",
            ),
            (StaffDenyReason::PermissionDenied, "staff_permission_denied"),
            (
                StaffDenyReason::SupportGrantRequired,
                "staff_grant_required",
            ),
            (StaffDenyReason::SupportGrantExpired, "staff_grant_expired"),
            (StaffDenyReason::SupportGrantRevoked, "staff_grant_revoked"),
            (
                StaffDenyReason::SupportGrantOrganizationMismatch,
                "staff_grant_org_mismatch",
            ),
            (
                StaffDenyReason::SupportGrantReasonRequired,
                "staff_grant_reason_required",
            ),
            (
                StaffDenyReason::SupportGrantTtlInvalid,
                "staff_grant_ttl_invalid",
            ),
        ] {
            assert_eq!(reason.code(), code);
            assert_eq!(reason.to_string(), code);
        }
    }

    use std::collections::BTreeSet;
}
