use crate::modules::authorization::OrganizationState;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrganizationInputError {
    InvalidDisplayName,
    InvalidSlug,
    InvalidVersion,
    MutationNotAllowed,
}

pub fn validate_display_name(value: &str) -> Result<String, OrganizationInputError> {
    let value = value.trim();
    if !(1..=120).contains(&value.chars().count()) || value.chars().any(char::is_control) {
        return Err(OrganizationInputError::InvalidDisplayName);
    }
    Ok(value.to_owned())
}

pub fn normalize_slug(value: &str) -> Result<String, OrganizationInputError> {
    let value = value.trim().to_ascii_lowercase();
    let valid = (3..=63).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-');
    if !valid {
        return Err(OrganizationInputError::InvalidSlug);
    }
    Ok(value)
}

pub fn validate_version(version: i64) -> Result<(), OrganizationInputError> {
    if version < 1 {
        return Err(OrganizationInputError::InvalidVersion);
    }
    Ok(())
}

pub fn can_mutate(state: OrganizationState) -> bool {
    matches!(state, OrganizationState::Active)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organization_names_and_slugs_are_bounded() {
        assert_eq!(validate_display_name(" Acme ").unwrap(), "Acme");
        assert!(validate_display_name("").is_err());
        assert_eq!(normalize_slug("  Acme-42 ").unwrap(), "acme-42");
        assert!(normalize_slug("-acme").is_err());
        assert!(normalize_slug("acme_42").is_err());
    }

    #[test]
    fn only_active_organizations_accept_ordinary_mutations() {
        assert!(can_mutate(OrganizationState::Active));
        assert!(!can_mutate(OrganizationState::Suspended));
        assert!(!can_mutate(OrganizationState::PendingDeletion));
        assert!(!can_mutate(OrganizationState::Deleted));
        assert!(validate_version(0).is_err());
    }
}
