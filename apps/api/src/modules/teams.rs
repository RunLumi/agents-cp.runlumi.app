use crate::modules::authorization::MembershipRole;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TeamInputError {
    InvalidName,
    InvalidSlug,
    DuplicateMember,
}

pub fn validate_team_name(value: &str) -> Result<String, TeamInputError> {
    let value = value.trim();
    if !(1..=120).contains(&value.chars().count()) || value.chars().any(char::is_control) {
        return Err(TeamInputError::InvalidName);
    }
    Ok(value.to_owned())
}

pub fn normalize_team_slug(value: &str) -> Result<String, TeamInputError> {
    let value = value.trim().to_ascii_lowercase();
    if !(1..=63).contains(&value.len())
        || !value.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(TeamInputError::InvalidSlug);
    }
    Ok(value)
}

pub fn can_manage_teams(role: MembershipRole) -> bool {
    matches!(role, MembershipRole::Owner | MembershipRole::Admin | MembershipRole::Member)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn team_names_and_slugs_are_bounded() {
        assert_eq!(validate_team_name(" Platform ").unwrap(), "Platform");
        assert_eq!(normalize_team_slug("Platform").unwrap(), "platform");
        assert_eq!(normalize_team_slug("Platform-1").unwrap(), "platform-1");
    }

    #[test]
    fn team_manage_grants_are_explicit() {
        assert!(can_manage_teams(MembershipRole::Owner));
        assert!(can_manage_teams(MembershipRole::Admin));
        assert!(can_manage_teams(MembershipRole::Member));
        assert!(!can_manage_teams(MembershipRole::Viewer));
    }
}
