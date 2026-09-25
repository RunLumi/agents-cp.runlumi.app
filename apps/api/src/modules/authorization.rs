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
        ),
        MembershipRole::Member => matches!(
            permission,
            Permission::OrgRead
                | Permission::OrgLeave
                | Permission::MembersRead
                | Permission::TeamsRead
                | Permission::DevicesRead
                | Permission::ProjectsRead
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
}
