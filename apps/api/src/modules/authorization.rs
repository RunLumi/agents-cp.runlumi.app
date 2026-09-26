//! The single policy decision path for protected organization operations.
//!
//! Handlers resolve a current principal and membership, then call [`authorize`].
//! Role strings are data in this module; they are never an authority source
//! outside this decision function.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::core::{MembershipId, OrganizationId, Principal, UserId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationState {
    Active,
    Suspended,
    PendingDeletion,
    Deleted,
}

impl OrganizationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::PendingDeletion => "pending_deletion",
            Self::Deleted => "deleted",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "suspended" => Some(Self::Suspended),
            "pending_deletion" => Some(Self::PendingDeletion),
            "deleted" => Some(Self::Deleted),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipRole {
    Owner,
    Admin,
    Member,
    Viewer,
}

impl MembershipRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
            Self::Viewer => "viewer",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "member" => Some(Self::Member),
            "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipStatus {
    Active,
    Suspended,
    Removed,
}

impl MembershipStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Removed => "removed",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "suspended" => Some(Self::Suspended),
            "removed" => Some(Self::Removed),
            _ => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum Permission {
    OrgRead,
    OrgManage,
    OrgOwnershipTransfer,
    OrgLifecycle,
    OrgLeave,
    MembersRead,
    MembersManage,
    TeamsRead,
    TeamsManage,
    AuditRead,
    // P03-CG (p03-cg-v1): managed devices, projects, and policy visibility.
    DevicesRead,
    DevicesManage,
    ProjectsRead,
    ProjectsManage,
    ModelsRead,
    ModelsManage,
    CredentialsRead,
    CredentialsManage,
    RoutesRead,
    RoutesManage,
    InferenceUse,
    UsageRead,
    // P05-CG (p05-cg-v1): managed runs, tools, approvals, and budgets.
    AgentsRead,
    AgentsManage,
    SessionsRead,
    SessionsManage,
    RunsRead,
    RunsStart,
    RunsCancel,
    ToolsRead,
    ToolsManage,
    ApprovalsRead,
    ApprovalsResolve,
    BudgetsRead,
    BudgetsManage,
    // P06-CG (p06-cg-v1): automations, event delivery, commercial entitlements,
    // and data governance. Entitlement OVERRIDES are deliberately absent: they
    // are internal/support-only and have no browser permission and no public
    // route (P06-CR-002).
    AutomationsRead,
    AutomationsManage,
    AutomationsRun,
    WebhooksRead,
    WebhooksManage,
    NotificationsRead,
    NotificationsManage,
    BillingRead,
    BillingManage,
    EntitlementsRead,
    DataRead,
    DataManage,
    DataExport,
    DataDelete,
    // P07-CG (p07-cg-v1): machine identity and plugin governance.
    //
    // These are HUMAN permissions that let an operator manage credentials and
    // third-party code. They grant nothing to a machine: a machine's authority
    // is its `ApiKeyScope`, resolved by `machine_identity::authorize_machine`,
    // and no `MembershipRole` -- including Owner -- confers either of these on
    // a credential. Keeping them in this enum is what makes the separation
    // visible at the call site: a route that says `service_accounts.manage` is
    // unambiguously a human route.
    //
    // `plugins.manage` is admin-only because installing code is a supply-chain
    // decision, not a configuration one.
    ServiceAccountsRead,
    ServiceAccountsManage,
    PluginsRead,
    PluginsManage,
    Unknown(String),
}

impl Permission {
    pub fn parse(value: &str) -> Self {
        match value {
            "org.read" => Self::OrgRead,
            "org.manage" => Self::OrgManage,
            "org.ownership_transfer" => Self::OrgOwnershipTransfer,
            "org.lifecycle" => Self::OrgLifecycle,
            "org.leave" => Self::OrgLeave,
            "members.read" => Self::MembersRead,
            "members.manage" => Self::MembersManage,
            "teams.read" => Self::TeamsRead,
            "teams.manage" => Self::TeamsManage,
            "audit.read" => Self::AuditRead,
            "devices.read" => Self::DevicesRead,
            "devices.manage" => Self::DevicesManage,
            "projects.read" => Self::ProjectsRead,
            "projects.manage" => Self::ProjectsManage,
            "models.read" => Self::ModelsRead,
            "models.manage" => Self::ModelsManage,
            "credentials.read" => Self::CredentialsRead,
            "credentials.manage" => Self::CredentialsManage,
            "routes.read" => Self::RoutesRead,
            "routes.manage" => Self::RoutesManage,
            "inference.use" => Self::InferenceUse,
            "usage.read" => Self::UsageRead,
            "agents.read" => Self::AgentsRead,
            "agents.manage" => Self::AgentsManage,
            "sessions.read" => Self::SessionsRead,
            "sessions.manage" => Self::SessionsManage,
            "runs.read" => Self::RunsRead,
            "runs.start" => Self::RunsStart,
            "runs.cancel" => Self::RunsCancel,
            "tools.read" => Self::ToolsRead,
            "tools.manage" => Self::ToolsManage,
            "approvals.read" => Self::ApprovalsRead,
            "approvals.resolve" => Self::ApprovalsResolve,
            "budgets.read" => Self::BudgetsRead,
            "budgets.manage" => Self::BudgetsManage,
            "automations.read" => Self::AutomationsRead,
            "automations.manage" => Self::AutomationsManage,
            "automations.run" => Self::AutomationsRun,
            "webhooks.read" => Self::WebhooksRead,
            "webhooks.manage" => Self::WebhooksManage,
            "notifications.read" => Self::NotificationsRead,
            "notifications.manage" => Self::NotificationsManage,
            "billing.read" => Self::BillingRead,
            "billing.manage" => Self::BillingManage,
            "entitlements.read" => Self::EntitlementsRead,
            "data.read" => Self::DataRead,
            "data.manage" => Self::DataManage,
            "data.export" => Self::DataExport,
            "data.delete" => Self::DataDelete,
            "service_accounts.read" => Self::ServiceAccountsRead,
            "service_accounts.manage" => Self::ServiceAccountsManage,
            "plugins.read" => Self::PluginsRead,
            "plugins.manage" => Self::PluginsManage,
            _ => Self::Unknown(value.to_owned()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::OrgRead => "org.read",
            Self::OrgManage => "org.manage",
            Self::OrgOwnershipTransfer => "org.ownership_transfer",
            Self::OrgLifecycle => "org.lifecycle",
            Self::OrgLeave => "org.leave",
            Self::MembersRead => "members.read",
            Self::MembersManage => "members.manage",
            Self::TeamsRead => "teams.read",
            Self::TeamsManage => "teams.manage",
            Self::AuditRead => "audit.read",
            Self::DevicesRead => "devices.read",
            Self::DevicesManage => "devices.manage",
            Self::ProjectsRead => "projects.read",
            Self::ProjectsManage => "projects.manage",
            Self::ModelsRead => "models.read",
            Self::ModelsManage => "models.manage",
            Self::CredentialsRead => "credentials.read",
            Self::CredentialsManage => "credentials.manage",
            Self::RoutesRead => "routes.read",
            Self::RoutesManage => "routes.manage",
            Self::InferenceUse => "inference.use",
            Self::UsageRead => "usage.read",
            Self::AgentsRead => "agents.read",
            Self::AgentsManage => "agents.manage",
            Self::SessionsRead => "sessions.read",
            Self::SessionsManage => "sessions.manage",
            Self::RunsRead => "runs.read",
            Self::RunsStart => "runs.start",
            Self::RunsCancel => "runs.cancel",
            Self::ToolsRead => "tools.read",
            Self::ToolsManage => "tools.manage",
            Self::ApprovalsRead => "approvals.read",
            Self::ApprovalsResolve => "approvals.resolve",
            Self::BudgetsRead => "budgets.read",
            Self::BudgetsManage => "budgets.manage",
            Self::AutomationsRead => "automations.read",
            Self::AutomationsManage => "automations.manage",
            Self::AutomationsRun => "automations.run",
            Self::WebhooksRead => "webhooks.read",
            Self::WebhooksManage => "webhooks.manage",
            Self::NotificationsRead => "notifications.read",
            Self::NotificationsManage => "notifications.manage",
            Self::BillingRead => "billing.read",
            Self::BillingManage => "billing.manage",
            Self::EntitlementsRead => "entitlements.read",
            Self::DataRead => "data.read",
            Self::DataManage => "data.manage",
            Self::DataExport => "data.export",
            Self::DataDelete => "data.delete",
            Self::ServiceAccountsRead => "service_accounts.read",
            Self::ServiceAccountsManage => "service_accounts.manage",
            Self::PluginsRead => "plugins.read",
            Self::PluginsManage => "plugins.manage",
            Self::Unknown(value) => value,
        }
    }

    fn requires_verified_email(&self) -> bool {
        !matches!(
            self,
            Self::OrgRead
                | Self::MembersRead
                | Self::TeamsRead
                | Self::AuditRead
                | Self::DevicesRead
                | Self::ProjectsRead
                | Self::ModelsRead
                | Self::RoutesRead
                | Self::UsageRead
                | Self::AgentsRead
                | Self::SessionsRead
                | Self::RunsRead
                | Self::ToolsRead
                | Self::ApprovalsRead
                | Self::BudgetsRead
                // P06: reading automations, notifications, entitlements, or the
                // data-governance summary is observation, not action, so it is
                // treated like every other `*Read` permission here. Every
                // mutating P06 permission (run/manage/export/delete) still
                // requires a verified email.
                | Self::AutomationsRead
                | Self::NotificationsRead
                | Self::EntitlementsRead
                | Self::DataRead
        )
    }
}

impl fmt::Debug for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Permission").field(&self.as_str()).finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    AuthenticationRequired,
    EmailVerificationRequired,
    MembershipRequired,
    PermissionDenied,
    OrganizationSuspended,
    OrganizationPendingDeletion,
    OrganizationDeleted,
    ResourceScopeMismatch,
    StaleMembership,
    UnknownPermission,
    VersionConflict,
}

impl DenyReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticationRequired => "authentication_required",
            Self::EmailVerificationRequired => "email_verification_required",
            Self::MembershipRequired => "membership_required",
            Self::PermissionDenied => "permission_denied",
            Self::OrganizationSuspended => "organization_suspended",
            Self::OrganizationPendingDeletion => "organization_pending_deletion",
            Self::OrganizationDeleted => "organization_deleted",
            Self::ResourceScopeMismatch => "resource_scope_mismatch",
            Self::StaleMembership => "stale_membership",
            Self::UnknownPermission => "permission_denied",
            Self::VersionConflict => "version_conflict",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrganizationContext {
    pub organization_id: OrganizationId,
    pub state: OrganizationState,
    pub version: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipSnapshot {
    pub membership_id: MembershipId,
    pub organization_id: OrganizationId,
    pub user_id: UserId,
    pub role: MembershipRole,
    pub status: MembershipStatus,
    pub version: i64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ResourceContext {
    pub resource_type: String,
    pub resource_id: String,
    pub organization_id: OrganizationId,
}

impl fmt::Debug for ResourceContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceContext")
            .field("resource_type", &self.resource_type)
            .field("resource_id", &self.resource_id)
            .field("organization_id", &self.organization_id)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Allow,
    Deny(DenyReason),
}

impl AuthorizationDecision {
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    pub const fn denial_reason(&self) -> Option<DenyReason> {
        match self {
            Self::Allow => None,
            Self::Deny(reason) => Some(*reason),
        }
    }
}

impl fmt::Debug for AuthorizationDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("Allow"),
            Self::Deny(reason) => write!(f, "Deny({reason:?})"),
        }
    }
}

/// Resolve one protected operation. The membership snapshot must come from a
/// current store lookup; token claims and caller-provided role values are not
/// accepted by this function.
pub fn authorize(
    principal: Option<&Principal>,
    organization: &OrganizationContext,
    membership: Option<&MembershipSnapshot>,
    permission: &Permission,
    resource: Option<&ResourceContext>,
) -> AuthorizationDecision {
    let Some(principal) = principal else {
        return AuthorizationDecision::Deny(DenyReason::AuthenticationRequired);
    };

    if matches!(permission, Permission::Unknown(_)) {
        return AuthorizationDecision::Deny(DenyReason::UnknownPermission);
    }

    if permission.requires_verified_email() && !principal.email_verified {
        return AuthorizationDecision::Deny(DenyReason::EmailVerificationRequired);
    }

    let Some(membership) = membership else {
        return AuthorizationDecision::Deny(DenyReason::MembershipRequired);
    };

    if membership.organization_id != organization.organization_id
        || membership.user_id != principal.user_id
    {
        return AuthorizationDecision::Deny(DenyReason::ResourceScopeMismatch);
    }

    if membership.status != MembershipStatus::Active {
        return AuthorizationDecision::Deny(DenyReason::MembershipRequired);
    }

    if membership.version < 1 {
        return AuthorizationDecision::Deny(DenyReason::StaleMembership);
    }

    match organization.state {
        OrganizationState::Suspended if !matches!(permission, Permission::OrgLifecycle) => {
            return AuthorizationDecision::Deny(DenyReason::OrganizationSuspended);
        }
        OrganizationState::PendingDeletion if !matches!(permission, Permission::OrgLifecycle) => {
            return AuthorizationDecision::Deny(DenyReason::OrganizationPendingDeletion);
        }
        OrganizationState::Deleted => {
            return AuthorizationDecision::Deny(DenyReason::OrganizationDeleted);
        }
        OrganizationState::Active
        | OrganizationState::Suspended
        | OrganizationState::PendingDeletion => {}
    }

    if let Some(resource) = resource
        && resource.organization_id != organization.organization_id
    {
        return AuthorizationDecision::Deny(DenyReason::ResourceScopeMismatch);
    }

    if role_allows(membership.role, permission) {
        AuthorizationDecision::Allow
    } else {
        AuthorizationDecision::Deny(DenyReason::PermissionDenied)
    }
}

fn role_allows(role: MembershipRole, permission: &Permission) -> bool {
    match role {
        MembershipRole::Owner => !matches!(permission, Permission::Unknown(_)),
        MembershipRole::Admin => matches!(
            permission,
            Permission::OrgRead
                | Permission::OrgManage
                | Permission::OrgLeave
                | Permission::MembersRead
                | Permission::MembersManage
                | Permission::TeamsRead
                | Permission::TeamsManage
                | Permission::AuditRead
                | Permission::DevicesRead
                | Permission::DevicesManage
                | Permission::ProjectsRead
                | Permission::ProjectsManage
                | Permission::ModelsRead
                | Permission::ModelsManage
                | Permission::CredentialsRead
                | Permission::CredentialsManage
                | Permission::RoutesRead
                | Permission::RoutesManage
                | Permission::InferenceUse
                | Permission::UsageRead
                | Permission::AgentsRead
                | Permission::AgentsManage
                | Permission::SessionsRead
                | Permission::SessionsManage
                | Permission::RunsRead
                | Permission::RunsStart
                | Permission::RunsCancel
                | Permission::ToolsRead
                | Permission::ToolsManage
                | Permission::ApprovalsRead
                | Permission::ApprovalsResolve
                | Permission::BudgetsRead
                | Permission::BudgetsManage
                | Permission::AutomationsRead
                | Permission::AutomationsManage
                | Permission::AutomationsRun
                | Permission::WebhooksRead
                | Permission::WebhooksManage
                | Permission::NotificationsRead
                | Permission::NotificationsManage
                | Permission::BillingRead
                | Permission::BillingManage
                | Permission::EntitlementsRead
                | Permission::DataRead
                | Permission::DataManage
                | Permission::DataExport
                | Permission::DataDelete
                // P07: a credential is an ownership-level act, so only owners and
                // admins reach `service_accounts.*`. Installing third-party code
                // is a supply-chain decision, so `plugins.manage` is admin-only
                // for the same reason. Members and viewers get the read-only
                // `plugins.read` below.
                | Permission::ServiceAccountsRead
                | Permission::ServiceAccountsManage
                | Permission::PluginsRead
                | Permission::PluginsManage
        ),
        MembershipRole::Member => matches!(
            permission,
            Permission::OrgRead
                | Permission::OrgLeave
                | Permission::MembersRead
                | Permission::TeamsRead
                | Permission::DevicesRead
                | Permission::ProjectsRead
                | Permission::ModelsRead
                | Permission::RoutesRead
                | Permission::InferenceUse
                | Permission::UsageRead
                | Permission::AgentsRead
                | Permission::SessionsRead
                | Permission::SessionsManage
                | Permission::RunsRead
                | Permission::RunsStart
                | Permission::RunsCancel
                | Permission::ToolsRead
                | Permission::ApprovalsRead
                | Permission::BudgetsRead
                // P06: a member may read and run automations within visible
                // projects. Webhook/billing/data administration stays with
                // admins: those mutate org-wide configuration and can export or
                // delete organization data.
                | Permission::AutomationsRead
                | Permission::AutomationsRun
                | Permission::NotificationsRead
                | Permission::NotificationsManage
                | Permission::EntitlementsRead
                | Permission::DataRead
                // P07: a member may see which plugins exist and why a tool is
                // denied — that is diagnostic value and costs nothing. They may
                // not install, approve, pin, or block one.
                | Permission::PluginsRead
        ),
        MembershipRole::Viewer => matches!(
            permission,
            Permission::OrgRead
                | Permission::OrgLeave
                | Permission::MembersRead
                | Permission::TeamsRead
                | Permission::AuditRead
                | Permission::DevicesRead
                | Permission::ProjectsRead
                | Permission::ModelsRead
                | Permission::RoutesRead
                | Permission::UsageRead
                | Permission::AgentsRead
                | Permission::SessionsRead
                | Permission::RunsRead
                | Permission::ToolsRead
                | Permission::ApprovalsRead
                | Permission::BudgetsRead
                // P06: a viewer is strictly read-only. It may SEE automations,
                // entitlements, and the data-governance summary, but may not run,
                // administer, export, or delete anything.
                | Permission::AutomationsRead
                | Permission::NotificationsRead
                | Permission::EntitlementsRead
                | Permission::DataRead
                // P07: `plugins.read` is member-visible because a member can see
                // which tools exist and why a tool is denied. Nothing else in
                // this phase is viewer-visible: service-account metadata names
                // credentials, and a viewer has no business enumerating them.
                | Permission::PluginsRead
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{SessionId, UserId};

    fn ids() -> (OrganizationId, UserId, MembershipId, SessionId) {
        (
            "org_0123456789abcdef0123456789abcdef".parse().unwrap(),
            "usr_0123456789abcdef0123456789abcdef".parse().unwrap(),
            "mem_0123456789abcdef0123456789abcdef".parse().unwrap(),
            "ses_0123456789abcdef0123456789abcdef".parse().unwrap(),
        )
    }

    fn principal(verified: bool) -> (Principal, OrganizationId, UserId, MembershipId) {
        let (org, user, membership, session) = ids();
        (
            Principal::new(
                user.clone(),
                session,
                "person@example.com",
                "Person",
                verified,
            ),
            org,
            user,
            membership,
        )
    }

    fn make_membership(
        org: OrganizationId,
        user: UserId,
        id: MembershipId,
        role: MembershipRole,
    ) -> MembershipSnapshot {
        MembershipSnapshot {
            membership_id: id,
            organization_id: org,
            user_id: user,
            role,
            status: MembershipStatus::Active,
            version: 1,
        }
    }

    #[test]
    fn owner_can_manage_and_unknown_permission_denies() {
        let (user, org, user_id, membership_id) = principal(true);
        let organization = OrganizationContext {
            organization_id: org.clone(),
            state: OrganizationState::Active,
            version: 1,
        };
        let membership = make_membership(org, user_id, membership_id, MembershipRole::Owner);
        assert_eq!(
            authorize(
                Some(&user),
                &organization,
                Some(&membership),
                &Permission::OrgManage,
                None
            ),
            AuthorizationDecision::Allow
        );
        assert_eq!(
            authorize(
                Some(&user),
                &organization,
                Some(&membership),
                &Permission::parse("made.up"),
                None
            ),
            AuthorizationDecision::Deny(DenyReason::UnknownPermission)
        );
    }

    #[test]
    fn viewer_cannot_manage_members() {
        let (user, org, user_id, membership_id) = principal(true);
        let organization = OrganizationContext {
            organization_id: org.clone(),
            state: OrganizationState::Active,
            version: 1,
        };
        let membership = make_membership(org, user_id, membership_id, MembershipRole::Viewer);
        assert_eq!(
            authorize(
                Some(&user),
                &organization,
                Some(&membership),
                &Permission::MembersManage,
                None
            ),
            AuthorizationDecision::Deny(DenyReason::PermissionDenied)
        );
    }

    #[test]
    fn stale_removed_membership_and_cross_tenant_scope_deny() {
        let (user, org, user_id, membership_id) = principal(true);
        let organization = OrganizationContext {
            organization_id: org.clone(),
            state: OrganizationState::Active,
            version: 1,
        };
        let mut stale = make_membership(
            org.clone(),
            user_id.clone(),
            membership_id.clone(),
            MembershipRole::Admin,
        );
        stale.status = MembershipStatus::Removed;
        assert_eq!(
            authorize(
                Some(&user),
                &organization,
                Some(&stale),
                &Permission::OrgRead,
                None
            ),
            AuthorizationDecision::Deny(DenyReason::MembershipRequired)
        );

        let other_org: OrganizationId = "org_1123456789abcdef0123456789abcdef".parse().unwrap();
        let other = make_membership(other_org, user_id, membership_id, MembershipRole::Owner);
        assert_eq!(
            authorize(
                Some(&user),
                &organization,
                Some(&other),
                &Permission::OrgRead,
                None
            ),
            AuthorizationDecision::Deny(DenyReason::ResourceScopeMismatch)
        );
    }

    #[test]
    fn unverified_mutation_and_suspended_org_are_denied() {
        let (user, org, user_id, membership_id) = principal(false);
        let organization = OrganizationContext {
            organization_id: org.clone(),
            state: OrganizationState::Active,
            version: 1,
        };
        let membership = make_membership(org, user_id, membership_id, MembershipRole::Owner);
        assert_eq!(
            authorize(
                Some(&user),
                &organization,
                Some(&membership),
                &Permission::MembersManage,
                None
            ),
            AuthorizationDecision::Deny(DenyReason::EmailVerificationRequired)
        );

        let (user, org, user_id, membership_id) = principal(true);
        let organization = OrganizationContext {
            organization_id: org,
            state: OrganizationState::Suspended,
            version: 2,
        };
        let snapshot = make_membership(
            organization.organization_id.clone(),
            user_id,
            membership_id,
            MembershipRole::Owner,
        );
        assert_eq!(
            authorize(
                Some(&user),
                &organization,
                Some(&snapshot),
                &Permission::OrgRead,
                None
            ),
            AuthorizationDecision::Deny(DenyReason::OrganizationSuspended)
        );
    }

    #[test]
    fn resource_from_another_org_cannot_be_authorized_by_membership() {
        let (user, org, user_id, membership_id) = principal(true);
        let organization = OrganizationContext {
            organization_id: org.clone(),
            state: OrganizationState::Active,
            version: 1,
        };
        let membership = make_membership(org, user_id, membership_id, MembershipRole::Owner);
        let resource_org: OrganizationId = "org_1123456789abcdef0123456789abcdef".parse().unwrap();
        let resource = ResourceContext {
            resource_type: "member".into(),
            resource_id: "mem_1123456789abcdef0123456789abcdef".into(),
            organization_id: resource_org,
        };
        assert_eq!(
            authorize(
                Some(&user),
                &organization,
                Some(&membership),
                &Permission::MembersRead,
                Some(&resource)
            ),
            AuthorizationDecision::Deny(DenyReason::ResourceScopeMismatch)
        );
    }

    #[test]
    fn p05_roles_keep_managed_control_permissions_separate() {
        let (user, org, user_id, membership_id) = principal(true);
        let organization = OrganizationContext {
            organization_id: org.clone(),
            state: OrganizationState::Active,
            version: 1,
        };

        let member = make_membership(
            org.clone(),
            user_id.clone(),
            membership_id.clone(),
            MembershipRole::Member,
        );
        assert!(
            authorize(
                Some(&user),
                &organization,
                Some(&member),
                &Permission::RunsStart,
                None
            )
            .is_allowed()
        );
        assert_eq!(
            authorize(
                Some(&user),
                &organization,
                Some(&member),
                &Permission::ToolsManage,
                None
            ),
            AuthorizationDecision::Deny(DenyReason::PermissionDenied)
        );

        let viewer = make_membership(org, user_id, membership_id, MembershipRole::Viewer);
        assert!(
            authorize(
                Some(&user),
                &organization,
                Some(&viewer),
                &Permission::RunsRead,
                None
            )
            .is_allowed()
        );
        assert_eq!(
            authorize(
                Some(&user),
                &organization,
                Some(&viewer),
                &Permission::RunsStart,
                None
            ),
            AuthorizationDecision::Deny(DenyReason::PermissionDenied)
        );
    }

    /// P06-CG freezes the P06 role split: owners/admins receive every P06
    /// browser permission, members may read and RUN automations but may not
    /// administer webhooks/billing or export/delete org data, and viewers are
    /// strictly read-only. This test pins that matrix so a future grant widening
    /// fails review here rather than shipping.
    #[test]
    fn p06_roles_keep_durable_operations_separate() {
        let (user, org, user_id, membership_id) = principal(true);
        let organization = OrganizationContext {
            organization_id: org.clone(),
            state: OrganizationState::Active,
            version: 1,
        };
        let allow = |permission: &Permission, role: MembershipRole| {
            let membership =
                make_membership(org.clone(), user_id.clone(), membership_id.clone(), role);
            authorize(
                Some(&user),
                &organization,
                Some(&membership),
                permission,
                None,
            )
            .is_allowed()
        };

        // A member may read and run automations.
        assert!(allow(&Permission::AutomationsRead, MembershipRole::Member));
        assert!(allow(&Permission::AutomationsRun, MembershipRole::Member));
        // ...but may not administer webhooks, change billing, or export/delete.
        assert!(!allow(&Permission::WebhooksManage, MembershipRole::Member));
        assert!(!allow(&Permission::BillingManage, MembershipRole::Member));
        assert!(!allow(&Permission::DataExport, MembershipRole::Member));
        assert!(!allow(&Permission::DataDelete, MembershipRole::Member));

        // A viewer is read-only across every P06 surface.
        assert!(allow(&Permission::AutomationsRead, MembershipRole::Viewer));
        assert!(!allow(&Permission::AutomationsRun, MembershipRole::Viewer));
        assert!(!allow(&Permission::DataExport, MembershipRole::Viewer));

        // An admin receives the full P06 browser surface.
        assert!(allow(&Permission::WebhooksManage, MembershipRole::Admin));
        assert!(allow(&Permission::BillingManage, MembershipRole::Admin));
        assert!(allow(&Permission::DataExport, MembershipRole::Admin));
        assert!(allow(&Permission::DataDelete, MembershipRole::Admin));
        assert!(allow(&Permission::AutomationsManage, MembershipRole::Owner));
    }

    /// P06-CR-002: entitlement overrides are internal/support-only. There must
    /// be no browser permission that could authorize one, and the stable code
    /// space must not contain one either — a future addition would let a support
    /// override leak into a self-service browser surface.
    #[test]
    fn p06_exposes_no_entitlement_override_permission() {
        for code in [
            "entitlements.manage",
            "entitlements.override",
            "entitlements.grant",
        ] {
            assert!(
                matches!(Permission::parse(code), Permission::Unknown(_)),
                "{code} must not resolve to a real permission"
            );
        }
    }

    /// P07-CG reserves F06's `identity.read` / `identity.manage` without adding
    /// them to the enum. F06 is frozen-not-built, so a permission that named it
    /// would create a route shape promising an SSO surface the product does not
    /// have.
    #[test]
    fn p07_adds_no_permission_for_the_frozen_only_f06_surface() {
        for code in [
            "identity.read",
            "identity.manage",
            "sso.manage",
            "scim.manage",
        ] {
            assert!(
                matches!(Permission::parse(code), Permission::Unknown(_)),
                "{code} must not resolve until F06 is implemented"
            );
        }
    }

    /// P07-CG freezes the P07 role matrix, and this test is why the matrix is
    /// not a convention.
    ///
    /// The four P07 permissions were added to the enum in the foundation PR
    /// WITHOUT being added to `role_allows`, and because `Owner` is written as
    /// "everything except unknown", every owner-bound route still worked. The
    /// defect was invisible: an admin could not read or manage a service
    /// account, and no role but owner could read the plugin surface at all. A
    /// role that silently receives nothing is the same failure as a role that
    /// silently receives everything, and only an explicit per-role test finds
    /// it.
    #[test]
    fn p07_roles_keep_credential_and_plugin_authority_separate() {
        let (user, org, user_id, membership_id) = principal(true);
        let organization = OrganizationContext {
            organization_id: org.clone(),
            state: OrganizationState::Active,
            version: 1,
        };
        let allow = |permission: &Permission, role: MembershipRole| {
            let membership =
                make_membership(org.clone(), user_id.clone(), membership_id.clone(), role);
            authorize(
                Some(&user),
                &organization,
                Some(&membership),
                permission,
                None,
            )
            .is_allowed()
        };

        // Owner and admin both administer credentials and the plugin surface.
        for role in [MembershipRole::Owner, MembershipRole::Admin] {
            assert!(allow(&Permission::ServiceAccountsRead, role));
            assert!(allow(&Permission::ServiceAccountsManage, role));
            assert!(allow(&Permission::PluginsRead, role));
            assert!(allow(&Permission::PluginsManage, role));
        }

        // A member may read plugins and nothing else in P07.
        assert!(allow(&Permission::PluginsRead, MembershipRole::Member));
        assert!(!allow(&Permission::PluginsManage, MembershipRole::Member));
        assert!(!allow(
            &Permission::ServiceAccountsRead,
            MembershipRole::Member
        ));
        assert!(!allow(
            &Permission::ServiceAccountsManage,
            MembershipRole::Member
        ));

        // A viewer may read plugins — that is the diagnostic value F25 names —
        // and may not enumerate credentials.
        assert!(allow(&Permission::PluginsRead, MembershipRole::Viewer));
        assert!(!allow(&Permission::PluginsManage, MembershipRole::Viewer));
        assert!(!allow(
            &Permission::ServiceAccountsRead,
            MembershipRole::Viewer
        ));
    }
}
