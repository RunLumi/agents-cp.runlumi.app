use crate::modules::authorization::{MembershipRole, MembershipStatus};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Expired,
    Revoked,
}

impl InvitationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "accepted" => Some(Self::Accepted),
            "expired" => Some(Self::Expired),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

pub fn role_can_be_invited(role: MembershipRole) -> bool {
    matches!(role, MembershipRole::Admin | MembershipRole::Member | MembershipRole::Viewer)
}

pub fn can_change_role(
    actor_role: MembershipRole,
    target_role: MembershipRole,
    target_status: MembershipStatus,
) -> bool {
    target_status == MembershipStatus::Active
        && matches!(actor_role, MembershipRole::Owner | MembershipRole::Admin)
        && (actor_role == MembershipRole::Owner || target_role != MembershipRole::Owner)
}

pub fn can_remove_member(actor_role: MembershipRole, target_role: MembershipRole) -> bool {
    matches!(actor_role, MembershipRole::Owner | MembershipRole::Admin)
        && (actor_role == MembershipRole::Owner || target_role != MembershipRole::Owner)
}

pub fn can_leave(actor_role: MembershipRole, active_owner_count: u32) -> bool {
    actor_role != MembershipRole::Owner || active_owner_count > 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_non_owner_roles_can_be_invited() {
        assert!(role_can_be_invited(MembershipRole::Admin));
        assert!(role_can_be_invited(MembershipRole::Member));
        assert!(role_can_be_invited(MembershipRole::Viewer));
        assert!(!role_can_be_invited(MembershipRole::Owner));
    }

    #[test]
    fn last_owner_cannot_be_demoted_removed_or_leave() {
        assert!(!can_change_role(MembershipRole::Owner, MembershipRole::Owner, MembershipStatus::Active) == false);
        assert!(!can_remove_member(MembershipRole::Admin, MembershipRole::Owner));
        assert!(!can_leave(MembershipRole::Owner, 1));
        assert!(can_leave(MembershipRole::Owner, 2));
    }
}
