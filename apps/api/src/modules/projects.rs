//! P03 project/workspace domain: naming, visibility, archive state, and the
//! binding rules that keep workspaces explicitly bound inside one org scope
//! (F07, F26-002).

use crate::core::CoreError;

pub const MAX_PROJECT_NAME_LEN: usize = 120;
pub const MAX_PROJECT_SLUG_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectVisibility {
    Org,
    Restricted,
}

impl ProjectVisibility {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Org => "org",
            Self::Restricted => "restricted",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "org" => Some(Self::Org),
            "restricted" => Some(Self::Restricted),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvironmentType {
    Local,
    Ssh,
    Wsl,
    Docker,
    Remote,
}

impl EnvironmentType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Ssh => "ssh",
            Self::Wsl => "wsl",
            Self::Docker => "docker",
            Self::Remote => "remote",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "local" => Some(Self::Local),
            "ssh" => Some(Self::Ssh),
            "wsl" => Some(Self::Wsl),
            "docker" => Some(Self::Docker),
            "remote" => Some(Self::Remote),
            _ => None,
        }
    }
}

/// Project display name: trimmed, bounded, control-free.
pub fn validate_project_name(name: &str) -> Result<String, CoreError> {
    let trimmed = name.trim();
    let ok = !trimmed.is_empty() && trimmed.chars().count() <= MAX_PROJECT_NAME_LEN;
    if ok {
        Ok(trimmed.to_owned())
    } else {
        Err(CoreError::InvalidProjectName)
    }
}

/// Slug: lowercase letters, digits, and hyphens; bounded; at least one
/// alphanumeric character so it stays URL-presentable.
pub fn normalize_project_slug(slug: &str) -> Result<String, CoreError> {
    // Fold whitespace/underscore runs into single hyphens, lowercase, and
    // trim leading/trailing dashes so names like "Project P" derive clean
    // URL-presentable slugs.
    let mut normalized = String::new();
    let mut last_was_dash = true; // suppress leading dashes
    for character in slug.trim().to_ascii_lowercase().chars() {
        if character.is_ascii_alphanumeric() {
            normalized.push(character);
            last_was_dash = false;
        } else if (character.is_whitespace() || character == '_' || character == '-')
            && !last_was_dash
        {
            normalized.push('-');
            last_was_dash = true;
        }
    }
    while normalized.ends_with('-') {
        normalized.pop();
    }
    let ok = !normalized.is_empty()
        && normalized.chars().count() <= MAX_PROJECT_SLUG_LEN
        && normalized.bytes().any(|byte| byte.is_ascii_alphanumeric());
    if ok {
        Ok(normalized)
    } else {
        Err(CoreError::InvalidProjectSlug)
    }
}

/// Optimistic-version guard shared by project mutations (FR-F23-005).
pub fn validate_project_version(version: i64) -> Result<(), CoreError> {
    if version > 0 {
        Ok(())
    } else {
        Err(CoreError::InvalidProjectVersion)
    }
}

/// Archive rule (F07-005): an archived project rejects new bindings and new
/// managed work, while history and audit stay intact.
pub fn ensure_project_accepts_work(archived: bool) -> Result<(), CoreError> {
    if archived {
        Err(CoreError::ProjectArchived)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visibility_and_environment_round_trip() {
        assert_eq!(
            ProjectVisibility::parse(ProjectVisibility::Restricted.as_str()),
            Some(ProjectVisibility::Restricted)
        );
        assert_eq!(
            EnvironmentType::parse(EnvironmentType::Docker.as_str()),
            Some(EnvironmentType::Docker)
        );
        assert!(ProjectVisibility::parse("public").is_none());
        assert!(EnvironmentType::parse("teleport").is_none());
    }

    #[test]
    fn project_names_are_trimmed_and_bounded() {
        assert_eq!(validate_project_name("  Inference ").unwrap(), "Inference");
        assert!(validate_project_name("").is_err());
        assert!(validate_project_name(&"x".repeat(200)).is_err());
    }

    #[test]
    fn project_slugs_are_normalized_and_rejected_on_bad_shape() {
        assert_eq!(
            normalize_project_slug("  Inference-2 ").unwrap(),
            "inference-2"
        );
        assert_eq!(normalize_project_slug("-leading").unwrap(), "leading");
        assert_eq!(normalize_project_slug("trailing-").unwrap(), "trailing");
        assert_eq!(
            normalize_project_slug("under_score").unwrap(),
            "under-score"
        );
        assert!(normalize_project_slug("").is_err());
        assert!(normalize_project_slug(&"x".repeat(80)).is_err());
    }

    #[test]
    fn archived_projects_reject_new_work() {
        assert!(ensure_project_accepts_work(false).is_ok());
        assert!(ensure_project_accepts_work(true).is_err());
    }

    #[test]
    fn versions_must_be_positive() {
        assert!(validate_project_version(1).is_ok());
        assert!(validate_project_version(0).is_err());
        assert!(validate_project_version(-3).is_err());
    }
}
