//! Machine authorization: the second of three decision boundaries.
//!
//! ADR 0007 is the reasoning; this module is the contract. `authorize` in
//! `super::authorization` is untouched and takes `Option<&Principal>`, so a
//! machine caller cannot reach a route that only calls it. This function is the
//! only way a credential acts, and its authority is an `ApiKeyScope`.
//!
//! The order of the checks is the design, so it is worth stating plainly:
//!
//! 1. **Human-only permissions are refused first**, before the scope is even
//!    read. FR-F14-007 forbids machine identities from performing human-only
//!    actions "unless explicitly designed and strongly justified", and no such
//!    justification exists in P07. Checking first means a request for
//!    `org.lifecycle` is refused as `human_only_action` rather than being
//!    stored and refused later — and it means widening a key's scope can never
//!    accidentally grant one.
//! 2. **Organization state is checked** on the same terms as the human path, so
//!    a suspended or mid-deletion organization stops machine work exactly when
//!    it stops human work.
//! 3. **Scope is then consulted**: capability membership, project scope, model
//!    alias, and network allowlist.
//!
//! There is deliberately no `role` parameter. A `MembershipRole` cannot be
//! passed, cannot be derived, and cannot be stored on a key, so FR-F14-001's
//! "MUST NOT inherit an owner's permissions implicitly" is enforced by the shape
//! of this signature.

use std::fmt;

use crate::core::{MachineActor, OrganizationId, ProjectId};
use crate::modules::authorization::{OrganizationContext, OrganizationState, Permission};

/// Why a machine request was refused.
///
/// Every variant maps to a stable wire code in `P07-CG.md`. The distinctions
/// that matter operationally are kept separate rather than collapsed:
/// `ScopeDenied` means the credential lacks the capability, while
/// `KillSwitchActive` means the platform has disabled the thing it was trying
/// to do. Those are different pages in a runbook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineDenyReason {
    /// The key, its account, or the organization it belongs to is not usable.
    AuthenticationRequired,
    MachineKeyRevoked,
    MachineKeyExpired,
    MachineKeySuspended,
    /// The requested permission is human-only. Checked before scope.
    HumanOnlyAction,
    /// The capability is not in the key's scope.
    ScopeDenied,
    /// The target project is outside the key's project scope.
    ScopeProjectMismatch,
    /// A network allowlist is configured and the client address is not in it.
    ScopeNetworkDenied,
    /// A network allowlist is configured but the client address is unknown.
    ///
    /// Failing closed is deliberate. F14-003 says network restrictions apply
    /// "where reliable"; a restriction that cannot be evaluated reliably must
    /// not become a restriction that is quietly not applied.
    ScopeNetworkUnavailable,
    /// The requested model alias is not in the key's scope.
    ScopeModelDenied,
    OrganizationSuspended,
    OrganizationPendingDeletion,
    OrganizationDeleted,
    /// The key belongs to a different organization than the target.
    ResourceScopeMismatch,
    /// A kill switch is engaged for this capability.
    KillSwitchActive,
}

impl MachineDenyReason {
    /// The stable machine-readable code. Clients branch on this, never on prose.
    pub const fn code(self) -> &'static str {
        match self {
            Self::AuthenticationRequired => "machine_key_invalid",
            Self::MachineKeyRevoked => "machine_key_revoked",
            Self::MachineKeyExpired => "machine_key_expired",
            Self::MachineKeySuspended => "machine_key_suspended",
            Self::HumanOnlyAction => "human_only_action",
            Self::ScopeDenied => "scope_denied",
            Self::ScopeProjectMismatch => "scope_project_mismatch",
            Self::ScopeNetworkDenied => "scope_denied",
            Self::ScopeNetworkUnavailable => "scope_network_unavailable",
            Self::ScopeModelDenied => "scope_denied",
            Self::OrganizationSuspended => "organization_suspended",
            Self::OrganizationPendingDeletion => "organization_pending_deletion",
            Self::OrganizationDeleted => "organization_deleted",
            Self::ResourceScopeMismatch => "scope_denied",
            Self::KillSwitchActive => "kill_switch_active",
        }
    }
}

impl fmt::Display for MachineDenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineDecision {
    Allow,
    Deny(MachineDenyReason),
}

/// The credential's usability, as read from the store during authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialState {
    pub key_active: bool,
    pub account_active: bool,
    /// RFC 3339 UTC, already compared against the request time by the caller.
    pub key_expired: bool,
}

/// What the key is allowed to do.
///
/// `capabilities` is a set, never a wildcard. `project_ids` of `None` means
/// every project in the organization; `Some(vec![])` means no project at all.
/// That distinction is why this is an `Option<Vec<_>>` and not a bool: "all" and
/// "none" are both false for a boolean, and conflating them would silently
/// widen or silently kill a key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApiKeyScope {
    pub capabilities: Vec<Permission>,
    pub project_ids: Option<Vec<ProjectId>>,
    pub model_aliases: Option<Vec<String>>,
    /// CIDR-ish allowlist. `None` means no network restriction at all.
    pub network_allowlist: Option<Vec<String>>,
}

impl ApiKeyScope {
    pub fn new(capabilities: Vec<Permission>) -> Self {
        Self {
            capabilities,
            ..Self::default()
        }
    }

    pub fn allows(&self, permission: &Permission) -> bool {
        self.capabilities.iter().any(|held| held == permission)
    }

    /// `None` scope means unrestricted; `Some` means the project must be listed.
    /// An empty `Some` therefore denies everything, which is the correct reading
    /// of "scoped to no projects".
    pub fn allows_project(&self, project: Option<&ProjectId>) -> bool {
        let Some(list) = &self.project_ids else {
            return true;
        };
        let Some(project) = project else {
            // A project-scoped key may not act on an organization-level target.
            return false;
        };
        list.iter().any(|allowed| allowed == project)
    }

    pub fn allows_model_alias(&self, alias: &str) -> bool {
        let Some(list) = &self.model_aliases else {
            return true;
        };
        list.iter().any(|allowed| allowed == alias)
    }

    /// `None` allowlist means no restriction is configured.
    ///
    /// `client_ip` of `None` means the edge did not give us a trustworthy
    /// address while a restriction IS configured. That denies: a control that
    /// cannot be evaluated must not silently pass.
    ///
    /// # The wildcard matches on a LABEL BOUNDARY, and that is load-bearing
    ///
    /// A first version of this did `allowed.strip_prefix("*.")` and then
    /// `client_ip.ends_with(suffix)`. That is an authorization bypass, and the
    /// test below is what found it: `strip_prefix("*.")` removes the dot as
    /// well, leaving `trusted.example`, and `"ci.untrusted.example".ends_with(
    /// "trusted.example")` is **true**. An attacker controlling the string
    /// presented as a client address satisfies a `*.trusted.example` allowlist
    /// entry by ending their own domain with those characters.
    ///
    /// So a `*.` entry means "a strict subdomain of", and the match requires a
    /// `.` at the label boundary plus at least one label before it.
    pub fn allows_network(&self, client_ip: Option<&str>) -> bool {
        let Some(list) = &self.network_allowlist else {
            return true;
        };
        let Some(client_ip) = client_ip else {
            return false;
        };
        list.iter().any(|allowed| {
            if allowed == client_ip {
                return true;
            }
            let Some(suffix) = allowed.strip_prefix("*.") else {
                return false;
            };
            // `*.` with nothing after it would otherwise match any address
            // containing a dot.
            if suffix.is_empty() || client_ip.len() <= suffix.len() {
                return false;
            }
            let boundary = client_ip.len() - suffix.len() - 1;
            client_ip.as_bytes()[boundary] == b'.' && &client_ip[boundary + 1..] == suffix
        })
    }
}

/// Is this permission structurally unavailable to a machine?
///
/// FR-F14-007. `data.delete` and `billing.manage` are P07 judgement beyond
/// F14-007's "such as owner transfer": both are irreversible, and F20's honesty
/// requirements assume a human who can read the consequence copy before
/// confirming. A CI credential that can delete an organization's data is a
/// single-token blast radius with no human in the loop.
pub const fn is_human_only(permission: &Permission) -> bool {
    matches!(
        permission,
        Permission::OrgOwnershipTransfer
            | Permission::OrgLifecycle
            | Permission::OrgLeave
            | Permission::BillingManage
            | Permission::DataDelete
    )
}

/// What a machine request is trying to reach.
///
/// Grouped rather than passed as loose parameters. With `project`,
/// `model_alias`, `client_ip` and a kill-switch flag as four adjacent optional
/// arguments, a transposed pair compiles, type-checks, and silently scopes a
/// request to the wrong resource. Naming them once removes the hazard.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MachineRequest<'a> {
    /// Organization that owns the target resource, when the target has one.
    pub resource_organization: Option<&'a OrganizationId>,
    pub project: Option<&'a ProjectId>,
    pub model_alias: Option<&'a str>,
    /// Edge-supplied client address. `None` while a network allowlist is
    /// configured is a denial, not a pass.
    pub client_ip: Option<&'a str>,
    /// Whether a platform kill switch currently covers this capability.
    pub kill_switch_engaged: bool,
}

impl<'a> MachineRequest<'a> {
    /// The common case: an organization-level target, no project, no model, and
    /// a client address that is present.
    pub fn org_level(client_ip: &'a str) -> Self {
        Self {
            client_ip: Some(client_ip),
            ..Self::default()
        }
    }

    pub fn with_resource_organization(mut self, organization: &'a OrganizationId) -> Self {
        self.resource_organization = Some(organization);
        self
    }

    pub fn with_project(mut self, project: &'a ProjectId) -> Self {
        self.project = Some(project);
        self
    }

    pub fn with_model_alias(mut self, alias: &'a str) -> Self {
        self.model_alias = Some(alias);
        self
    }

    pub fn with_kill_switch(mut self, engaged: bool) -> Self {
        self.kill_switch_engaged = engaged;
        self
    }
}

/// Resolve one machine-protected operation.
///
/// There is no `membership` parameter and no `role` parameter, and there
/// cannot be one: a machine has no membership. Passing the organization
/// context, the resolved credential, and what the request targets is the whole
/// input.
pub fn authorize_machine(
    actor: &MachineActor,
    state: CredentialState,
    organization: &OrganizationContext,
    scope: &ApiKeyScope,
    permission: &Permission,
    request: MachineRequest<'_>,
) -> MachineDecision {
    let MachineRequest {
        resource_organization,
        project,
        model_alias,
        client_ip,
        kill_switch_engaged,
    } = request;
    // 1. Credential usability. A suspended account stops every key under it,
    //    including keys that have not yet expired.
    if !state.key_active {
        return MachineDecision::Deny(MachineDenyReason::MachineKeyRevoked);
    }
    if !state.account_active {
        return MachineDecision::Deny(MachineDenyReason::MachineKeySuspended);
    }
    if state.key_expired {
        return MachineDecision::Deny(MachineDenyReason::MachineKeyExpired);
    }

    // 2. Cross-tenant. The actor's organization comes from the key row, and the
    //    target's from the route. They must agree, or nothing below is reached.
    if actor.organization_id != organization.organization_id
        || resource_organization.is_some_and(|target| target != &actor.organization_id)
    {
        return MachineDecision::Deny(MachineDenyReason::ResourceScopeMismatch);
    }

    // 3. Organization state, on the same terms as the human path.
    match organization.state {
        OrganizationState::Active => {}
        OrganizationState::Suspended => {
            return MachineDecision::Deny(MachineDenyReason::OrganizationSuspended);
        }
        OrganizationState::PendingDeletion => {
            return MachineDecision::Deny(MachineDenyReason::OrganizationPendingDeletion);
        }
        OrganizationState::Deleted => {
            return MachineDecision::Deny(MachineDenyReason::OrganizationDeleted);
        }
    }

    // 4. Human-only, BEFORE scope. See the module comment: this ordering is the
    //    point, so a widened scope can never grant one of these.
    if is_human_only(permission) {
        return MachineDecision::Deny(MachineDenyReason::HumanOnlyAction);
    }

    // 5. A kill switch is reported as its own reason so an operator reading a
    //    denial knows the platform disabled this, rather than assuming the
    //    credential was under-scoped.
    if kill_switch_engaged {
        return MachineDecision::Deny(MachineDenyReason::KillSwitchActive);
    }

    // 6. Scope. Order is stable so a caller can reason about which limit bit.
    if !scope.allows(permission) {
        return MachineDecision::Deny(MachineDenyReason::ScopeDenied);
    }
    if !scope.allows_project(project) {
        return MachineDecision::Deny(MachineDenyReason::ScopeProjectMismatch);
    }
    if let Some(alias) = model_alias
        && !scope.allows_model_alias(alias)
    {
        return MachineDecision::Deny(MachineDenyReason::ScopeModelDenied);
    }
    if !scope.allows_network(client_ip) {
        // Distinguish "we could not evaluate" from "not allowed", because the
        // remediation differs: the first is an edge problem, the second is a
        // configuration problem.
        return MachineDecision::Deny(if scope.network_allowlist.is_some() {
            MachineDenyReason::ScopeNetworkUnavailable
        } else {
            MachineDenyReason::ScopeNetworkDenied
        });
    }

    MachineDecision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{ApiKeyId, OrganizationId, ServiceAccountId};

    const ORG: &str = "org_0123456789abcdef0123456789abcdef";
    const ORG_OTHER: &str = "org_ffffffffffffffffffffffffffffffff";
    const PROJECT: &str = "prj_0123456789abcdef0123456789abcdef";
    const PROJECT_OTHER: &str = "prj_ffffffffffffffffffffffffffffffff";

    fn org(state: OrganizationState) -> OrganizationContext {
        OrganizationContext {
            organization_id: ORG.parse().expect("org id"),
            state,
            version: 1,
        }
    }

    fn actor() -> MachineActor {
        MachineActor::new(
            ApiKeyId::new("key_0123456789abcdef0123456789abcdef").expect("key id"),
            ServiceAccountId::new("svc_0123456789abcdef0123456789abcdef").expect("sa id"),
            ORG.parse().expect("org id"),
            "0123456789ab",
        )
    }

    fn live() -> CredentialState {
        CredentialState {
            key_active: true,
            account_active: true,
            key_expired: false,
        }
    }

    fn org_id() -> OrganizationId {
        ORG.parse().expect("org id")
    }

    fn other_org_id() -> OrganizationId {
        ORG_OTHER.parse().expect("org id")
    }

    /// The ordinary case: an active key, an organization-level target, and a
    /// client address that is present. Anything else a test needs is added on
    /// top with the `MachineRequest` builder.
    fn allow(
        state: CredentialState,
        scope: &ApiKeyScope,
        permission: &Permission,
    ) -> MachineDecision {
        decide(
            state,
            scope,
            permission,
            MachineRequest::org_level("203.0.113.10").with_resource_organization(&org_id()),
        )
    }

    fn decide(
        state: CredentialState,
        scope: &ApiKeyScope,
        permission: &Permission,
        request: MachineRequest<'_>,
    ) -> MachineDecision {
        authorize_machine(
            &actor(),
            state,
            &org(OrganizationState::Active),
            scope,
            permission,
            request,
        )
    }

    #[test]
    fn an_active_key_with_the_capability_is_allowed() {
        let scope = ApiKeyScope::new(vec![Permission::RunsStart]);
        assert_eq!(
            allow(live(), &scope, &Permission::RunsStart),
            MachineDecision::Allow
        );
    }

    #[test]
    fn a_capability_outside_the_scope_is_denied() {
        let scope = ApiKeyScope::new(vec![Permission::RunsRead]);
        assert_eq!(
            allow(live(), &scope, &Permission::RunsStart),
            MachineDecision::Deny(MachineDenyReason::ScopeDenied)
        );
    }

    #[test]
    fn an_empty_scope_allows_nothing() {
        let scope = ApiKeyScope::new(vec![]);
        assert_eq!(
            allow(live(), &scope, &Permission::RunsRead),
            MachineDecision::Deny(MachineDenyReason::ScopeDenied)
        );
    }

    /// FR-F14-007. Each of the five must be refused even when the key's scope
    /// contains it, which is the case an ordering mistake would let through.
    #[test]
    fn human_only_permissions_are_refused_even_when_the_scope_contains_them() {
        for permission in [
            Permission::OrgOwnershipTransfer,
            Permission::OrgLifecycle,
            Permission::OrgLeave,
            Permission::BillingManage,
            Permission::DataDelete,
        ] {
            let scope = ApiKeyScope::new(vec![permission.clone()]);
            assert_eq!(
                allow(live(), &scope, &permission),
                MachineDecision::Deny(MachineDenyReason::HumanOnlyAction),
                "must refuse {permission:?} even when scoped"
            );
            assert!(is_human_only(&permission));
        }
    }

    /// Pins the ORDERING, which the case above cannot.
    ///
    /// When the scope CONTAINS the human-only permission, checking scope first
    /// and checking human-only first give the same answer, so that test passes
    /// either way. The order only becomes observable when the scope does NOT
    /// contain it: correct code reports `human_only_action` (the permission can
    /// never be granted to a machine at all), reordered code reports
    /// `scope_denied` (implying it could be granted with a wider scope).
    ///
    /// That second answer is the one worth preventing, because it tells an
    /// operator to widen the key's scope when the only fix is that the action
    /// is not machine-capable.
    #[test]
    fn a_human_only_permission_reports_itself_even_when_the_scope_omits_it() {
        let scope = ApiKeyScope::new(vec![Permission::RunsRead]);
        for permission in [
            Permission::OrgLifecycle,
            Permission::DataDelete,
            Permission::BillingManage,
        ] {
            assert_eq!(
                allow(live(), &scope, &permission),
                MachineDecision::Deny(MachineDenyReason::HumanOnlyAction),
                "{permission:?} must not be reported as a scope problem"
            );
        }
    }

    #[test]
    fn an_ordinary_permission_is_not_human_only() {
        for permission in [
            Permission::RunsStart,
            Permission::RunsRead,
            Permission::BillingRead,
            Permission::DataRead,
            Permission::ServiceAccountsRead,
        ] {
            assert!(
                !is_human_only(&permission),
                "{permission:?} must be machine-capable"
            );
        }
    }

    #[test]
    fn a_revoked_key_is_denied_before_anything_else_is_consulted() {
        let scope = ApiKeyScope::new(vec![Permission::RunsStart]);
        let revoked = CredentialState {
            key_active: false,
            ..live()
        };
        // Even a human-only permission reports the credential problem first, so
        // an operator debugging a dead key is not sent down the wrong path.
        assert_eq!(
            allow(revoked, &scope, &Permission::RunsStart),
            MachineDecision::Deny(MachineDenyReason::MachineKeyRevoked)
        );
        assert_eq!(
            allow(revoked, &scope, &Permission::OrgLifecycle),
            MachineDecision::Deny(MachineDenyReason::MachineKeyRevoked)
        );
    }

    #[test]
    fn a_suspended_account_denies_its_own_unexpired_key() {
        let scope = ApiKeyScope::new(vec![Permission::RunsStart]);
        let suspended = CredentialState {
            account_active: false,
            ..live()
        };
        assert_eq!(
            allow(suspended, &scope, &Permission::RunsStart),
            MachineDecision::Deny(MachineDenyReason::MachineKeySuspended)
        );
    }

    #[test]
    fn an_expired_key_is_denied() {
        let scope = ApiKeyScope::new(vec![Permission::RunsStart]);
        let expired = CredentialState {
            key_expired: true,
            ..live()
        };
        assert_eq!(
            allow(expired, &scope, &Permission::RunsStart),
            MachineDecision::Deny(MachineDenyReason::MachineKeyExpired)
        );
    }

    /// The F14 acceptance criterion: a project-scoped key cannot reach another
    /// project, even inside the same organization.
    #[test]
    fn a_project_scoped_key_cannot_reach_another_project_in_the_same_org() {
        let scope = ApiKeyScope {
            project_ids: Some(vec![PROJECT.parse().expect("project id")]),
            ..ApiKeyScope::new(vec![Permission::RunsStart])
        };
        let decision = decide(
            live(),
            &scope,
            &Permission::RunsStart,
            MachineRequest::org_level("203.0.113.10")
                .with_resource_organization(&org_id())
                .with_project(&PROJECT_OTHER.parse().expect("project id")),
        );
        assert_eq!(
            decision,
            MachineDecision::Deny(MachineDenyReason::ScopeProjectMismatch)
        );
    }

    #[test]
    fn a_project_scoped_key_reaches_its_own_project() {
        let scope = ApiKeyScope {
            project_ids: Some(vec![PROJECT.parse().expect("project id")]),
            ..ApiKeyScope::new(vec![Permission::RunsStart])
        };
        let decision = decide(
            live(),
            &scope,
            &Permission::RunsStart,
            MachineRequest::org_level("203.0.113.10")
                .with_resource_organization(&org_id())
                .with_project(&PROJECT.parse().expect("project id")),
        );
        assert_eq!(decision, MachineDecision::Allow);
    }

    /// "All projects" and "no projects" are both false for a boolean, which is
    /// why the scope is an Option. Conflating them would silently widen a key.
    #[test]
    fn an_empty_project_list_denies_every_project() {
        let scope = ApiKeyScope {
            project_ids: Some(vec![]),
            ..ApiKeyScope::new(vec![Permission::RunsStart])
        };
        for project in [PROJECT, PROJECT_OTHER] {
            assert!(!scope.allows_project(Some(&project.parse().expect("id"))));
        }
        assert!(!scope.allows_project(None));
    }

    #[test]
    fn an_absent_project_list_denies_nothing() {
        let scope = ApiKeyScope::new(vec![Permission::RunsStart]);
        assert!(scope.allows_project(None));
        assert!(scope.allows_project(Some(&PROJECT.parse().expect("id"))));
    }

    /// The pessimistic F14-003 decision, stated as a test because it is the one
    /// that looks like a bug to a future reader.
    #[test]
    fn a_network_allowlist_fails_closed_when_the_client_address_is_unknown() {
        let scope = ApiKeyScope {
            network_allowlist: Some(vec!["203.0.113.0/24".to_owned()]),
            ..ApiKeyScope::new(vec![Permission::RunsStart])
        };
        assert!(!scope.allows_network(None));
        // A configured restriction that cannot be evaluated must not pass.
        assert_eq!(
            decide(
                live(),
                &scope,
                &Permission::RunsStart,
                MachineRequest::default().with_resource_organization(&org_id()),
            ),
            MachineDecision::Deny(MachineDenyReason::ScopeNetworkUnavailable)
        );
    }

    #[test]
    fn an_absent_network_allowlist_ignores_a_missing_address() {
        let scope = ApiKeyScope::new(vec![Permission::RunsStart]);
        assert!(scope.allows_network(None));
    }

    /// The regression this whole case exists for. A `*.trusted.example`
    /// allowlist entry must not be satisfiable by a host that merely ENDS WITH
    /// those characters.
    ///
    /// The original implementation stripped `"*."` — dot included — and then
    /// used a bare `ends_with`, so `ci.untrusted.example` passed a
    /// `*.trusted.example` allowlist. That is an authorization bypass reachable
    /// by anyone who controls the string presented as a client address.
    #[test]
    fn a_wildcard_allowlist_entry_matches_on_a_label_boundary_only() {
        let scope = ApiKeyScope {
            network_allowlist: Some(vec!["*.trusted.example".to_owned()]),
            ..ApiKeyScope::new(vec![Permission::RunsStart])
        };

        // Genuine subdomains match.
        assert!(scope.allows_network(Some("ci.trusted.example")));
        assert!(scope.allows_network(Some("a.b.trusted.example")));

        // The bypass: these end with "trusted.example" but are not under it.
        assert!(
            !scope.allows_network(Some("ci.untrusted.example")),
            "a host ending in the same characters must not satisfy a wildcard entry"
        );
        assert!(!scope.allows_network(Some("eviltrusted.example")));
        assert!(!scope.allows_network(Some("xtrusted.example")));

        // The bare parent domain is not a subdomain of itself.
        assert!(!scope.allows_network(Some("trusted.example")));
    }

    #[test]
    fn a_bare_star_dot_allowlist_entry_matches_nothing() {
        // `*.` with an empty suffix would otherwise match any address that
        // contains a dot, which is nearly all of them.
        let scope = ApiKeyScope {
            network_allowlist: Some(vec!["*.".to_owned()]),
            ..ApiKeyScope::new(vec![Permission::RunsStart])
        };
        assert!(!scope.allows_network(Some("203.0.113.10")));
        assert!(!scope.allows_network(Some("anything.example")));
    }

    #[test]
    fn a_network_allowlist_matches_exact_entries_and_nothing_else() {
        let scope = ApiKeyScope {
            network_allowlist: Some(vec![
                "203.0.113.10".to_owned(),
                "*.trusted.example".to_owned(),
            ]),
            ..ApiKeyScope::new(vec![Permission::RunsStart])
        };
        assert!(scope.allows_network(Some("203.0.113.10")));
        assert!(scope.allows_network(Some("ci.trusted.example")));
        assert!(!scope.allows_network(Some("203.0.113.11")));
        // A CIDR-looking entry is matched literally, not parsed as a range. That
        // is a real limitation, and it is the safe direction: an unparseable
        // entry matches only itself rather than a range nobody intended.
        assert!(!scope.allows_network(Some("203.0.113.0/24")));
    }

    #[test]
    fn a_model_alias_outside_the_scope_is_denied() {
        let scope = ApiKeyScope {
            model_aliases: Some(vec!["fast".to_owned()]),
            ..ApiKeyScope::new(vec![Permission::RunsStart])
        };
        assert!(scope.allows_model_alias("fast"));
        assert!(!scope.allows_model_alias("slow"));
        let unrestricted = ApiKeyScope::new(vec![Permission::RunsStart]);
        assert!(unrestricted.allows_model_alias("anything"));

        assert_eq!(
            decide(
                live(),
                &scope,
                &Permission::RunsStart,
                MachineRequest::org_level("203.0.113.10")
                    .with_resource_organization(&org_id())
                    .with_model_alias("slow"),
            ),
            MachineDecision::Deny(MachineDenyReason::ScopeModelDenied)
        );
    }

    #[test]
    fn a_key_cannot_act_on_another_organization() {
        let scope = ApiKeyScope::new(vec![Permission::RunsStart]);
        let decision = decide(
            live(),
            &scope,
            &Permission::RunsStart,
            MachineRequest::org_level("203.0.113.10").with_resource_organization(&other_org_id()),
        );
        assert_eq!(
            decision,
            MachineDecision::Deny(MachineDenyReason::ResourceScopeMismatch)
        );
    }

    #[test]
    fn organization_state_stops_machine_work_exactly_when_it_stops_human_work() {
        let scope = ApiKeyScope::new(vec![Permission::RunsStart]);
        for (state, reason) in [
            (OrganizationState::Active, None),
            (
                OrganizationState::Suspended,
                Some(MachineDenyReason::OrganizationSuspended),
            ),
            (
                OrganizationState::PendingDeletion,
                Some(MachineDenyReason::OrganizationPendingDeletion),
            ),
            (
                OrganizationState::Deleted,
                Some(MachineDenyReason::OrganizationDeleted),
            ),
        ] {
            // The organization state has to actually reach `authorize_machine`
            // for this to test anything; going through the shared `allow` helper
            // would pin Active and assert nothing.
            let decision = authorize_machine(
                &actor(),
                live(),
                &org(state),
                &scope,
                &Permission::RunsStart,
                MachineRequest::org_level("203.0.113.10").with_resource_organization(&org_id()),
            );
            match reason {
                None => assert_eq!(decision, MachineDecision::Allow, "{state:?} must allow"),
                Some(expected) => {
                    assert_eq!(decision, MachineDecision::Deny(expected), "{state:?}");
                }
            }
        }
    }

    /// An engaged kill switch is distinguishable from an under-scoped key. They
    /// are different runbooks, so they must not share a code.
    #[test]
    fn an_engaged_kill_switch_is_reported_distinctly_from_a_scope_denial() {
        let scope = ApiKeyScope::new(vec![Permission::RunsStart]);
        let engaged = decide(
            live(),
            &scope,
            &Permission::RunsStart,
            MachineRequest::org_level("203.0.113.10")
                .with_resource_organization(&org_id())
                .with_kill_switch(true),
        );
        assert_eq!(
            engaged,
            MachineDecision::Deny(MachineDenyReason::KillSwitchActive)
        );
        assert_eq!(
            MachineDenyReason::KillSwitchActive.code(),
            "kill_switch_active"
        );
        assert_eq!(MachineDenyReason::ScopeDenied.code(), "scope_denied");
    }

    #[test]
    fn a_kill_switch_outranks_scope_but_not_a_dead_credential() {
        let scope = ApiKeyScope::new(vec![Permission::RunsStart]);
        // Scope missing AND switch engaged: the switch is reported, because that
        // is the thing an operator has to clear.
        let engaged_missing_scope = decide(
            live(),
            &scope,
            &Permission::DataRead,
            MachineRequest::org_level("203.0.113.10")
                .with_resource_organization(&org_id())
                .with_kill_switch(true),
        );
        assert_eq!(
            engaged_missing_scope,
            MachineDecision::Deny(MachineDenyReason::KillSwitchActive)
        );
        // A dead credential still reports the credential problem, or an operator
        // would clear a kill switch that was never the cause.
        let dead = CredentialState {
            key_active: false,
            ..live()
        };
        let dead_and_engaged = decide(
            dead,
            &scope,
            &Permission::RunsStart,
            MachineRequest::org_level("203.0.113.10")
                .with_resource_organization(&org_id())
                .with_kill_switch(true),
        );
        assert_eq!(
            dead_and_engaged,
            MachineDecision::Deny(MachineDenyReason::MachineKeyRevoked)
        );
    }

    #[test]
    fn every_denial_reason_has_a_stable_code() {
        for reason in [
            MachineDenyReason::AuthenticationRequired,
            MachineDenyReason::MachineKeyRevoked,
            MachineDenyReason::MachineKeyExpired,
            MachineDenyReason::MachineKeySuspended,
            MachineDenyReason::HumanOnlyAction,
            MachineDenyReason::ScopeDenied,
            MachineDenyReason::ScopeProjectMismatch,
            MachineDenyReason::ScopeNetworkUnavailable,
            MachineDenyReason::ScopeNetworkDenied,
            MachineDenyReason::OrganizationSuspended,
            MachineDenyReason::OrganizationPendingDeletion,
            MachineDenyReason::OrganizationDeleted,
            MachineDenyReason::KillSwitchActive,
        ] {
            assert!(!reason.code().is_empty());
            assert_eq!(reason.to_string(), reason.code());
        }
    }
}
