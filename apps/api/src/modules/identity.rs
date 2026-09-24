use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    Verification,
    Login,
}

impl ChallengeKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verification => "verification",
            Self::Login => "login",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Active,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceAuthorizationState {
    Pending,
    Approved,
    Consumed,
    Expired,
    Revoked,
}

#[derive(Clone, PartialEq, Eq)]
pub struct NormalizedEmail(String);

impl NormalizedEmail {
    pub fn parse(value: &str) -> Result<Self, IdentityInputError> {
        let normalized = value.trim().to_ascii_lowercase();
        let valid = normalized.len() >= 3
            && normalized.len() <= 320
            && normalized
                .split_once('@')
                .is_some_and(|(local, domain)| {
                    !local.is_empty()
                        && local.len() <= 64
                        && domain.contains('.')
                        && !domain.starts_with('.')
                        && !domain.ends_with('.')
                        && !domain.contains(char::is_whitespace)
                });
        if !valid {
            return Err(IdentityInputError::InvalidEmail);
        }
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NormalizedEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NormalizedEmail([redacted])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityInputError {
    InvalidEmail,
    InvalidDisplayName,
    InvalidDeviceLabel,
    InvalidCodeChallenge,
}

pub fn validate_display_name(value: &str) -> Result<String, IdentityInputError> {
    let value = value.trim();
    if !(1..=120).contains(&value.chars().count()) || value.chars().any(char::is_control) {
        return Err(IdentityInputError::InvalidDisplayName);
    }
    Ok(value.to_owned())
}

pub fn validate_device_label(value: &str) -> Result<String, IdentityInputError> {
    let value = value.trim();
    if !(1..=120).contains(&value.chars().count()) || value.chars().any(char::is_control) {
        return Err(IdentityInputError::InvalidDeviceLabel);
    }
    Ok(value.to_owned())
}

pub fn validate_pkce_challenge(value: &str) -> Result<String, IdentityInputError> {
    let valid = (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.');
    if !valid {
        return Err(IdentityInputError::InvalidCodeChallenge);
    }
    Ok(value.to_owned())
}

pub fn validate_role(value: &str) -> Option<&'static str> {
    match value {
        "owner" => Some("owner"),
        "admin" => Some("admin"),
        "member" => Some("member"),
        "viewer" => Some("viewer"),
        _ => None,
    }
}

pub fn is_active_session(revoked_at: Option<&str>, expires_at: &str, now: &str) -> bool {
    revoked_at.is_none() && expires_at > now
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_normalization_is_stable_and_debug_redacts() {
        let email = NormalizedEmail::parse("  Person@Example.COM ").unwrap();
        assert_eq!(email.as_str(), "person@example.com");
        assert!(!format!("{email:?}").contains("person@example.com"));
        assert!(NormalizedEmail::parse("not-an-email").is_err());
    }

    #[test]
    fn display_device_and_pkce_inputs_are_bounded() {
        assert_eq!(validate_display_name("  Person  ").unwrap(), "Person");
        assert!(validate_display_name("\n").is_err());
        assert_eq!(validate_device_label("Lumi Desktop").unwrap(), "Lumi Desktop");
        assert!(validate_pkce_challenge(&"a".repeat(43)).is_ok());
        assert!(validate_pkce_challenge("short").is_err());
    }

    #[test]
    fn session_state_requires_unexpired_and_unrevoked() {
        assert!(is_active_session(None, "2026-09-25T00:00:00.000Z", "2026-09-24T23:59:59.000Z"));
        assert!(!is_active_session(Some("2026-09-24T00:00:00.000Z"), "2026-09-25T00:00:00.000Z", "2026-09-24T23:59:59.000Z"));
        assert!(!is_active_session(None, "2026-09-24T00:00:00.000Z", "2026-09-24T23:59:59.000Z"));
    }
}
