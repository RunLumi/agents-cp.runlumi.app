//! P04 credential domain rules.
//!
//! Plaintext secret material never enters this module. A trusted adapter may
//! resolve a logical handle immediately before an outbound request, but only
//! after the caller has passed the central P02 authorization path.

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialOwnerType {
    Platform,
    Organization,
    User,
    ServiceAccount,
    LocalOnly,
}

impl CredentialOwnerType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::Organization => "organization",
            Self::User => "user",
            Self::ServiceAccount => "service_account",
            Self::LocalOnly => "local_only",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "platform" => Some(Self::Platform),
            "organization" => Some(Self::Organization),
            "user" => Some(Self::User),
            "service_account" => Some(Self::ServiceAccount),
            "local_only" => Some(Self::LocalOnly),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Active,
    Rotating,
    Revoked,
}

impl CredentialStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "rotating" => Some(Self::Rotating),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }

    pub const fn is_resolvable(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMode {
    PlatformOnly,
    OrganizationOnly,
    UserAllowed,
    PlatformOrOrganization,
    LocalDirect,
    OrderedFallback,
}

impl CredentialMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlatformOnly => "platform_only",
            Self::OrganizationOnly => "organization_only",
            Self::UserAllowed => "user_allowed",
            Self::PlatformOrOrganization => "platform_or_organization",
            Self::LocalDirect => "local_direct",
            Self::OrderedFallback => "ordered_fallback",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "platform_only" => Some(Self::PlatformOnly),
            "organization_only" => Some(Self::OrganizationOnly),
            "user_allowed" => Some(Self::UserAllowed),
            "platform_or_organization" => Some(Self::PlatformOrOrganization),
            "local_direct" => Some(Self::LocalDirect),
            "ordered_fallback" => Some(Self::OrderedFallback),
            _ => None,
        }
    }

    pub const fn allows(self, owner: CredentialOwnerType) -> bool {
        match self {
            Self::PlatformOnly => matches!(owner, CredentialOwnerType::Platform),
            Self::OrganizationOnly => matches!(owner, CredentialOwnerType::Organization),
            Self::UserAllowed => matches!(owner, CredentialOwnerType::User),
            Self::PlatformOrOrganization => matches!(
                owner,
                CredentialOwnerType::Platform | CredentialOwnerType::Organization
            ),
            Self::LocalDirect => matches!(owner, CredentialOwnerType::LocalOnly),
            Self::OrderedFallback => !matches!(owner, CredentialOwnerType::LocalOnly),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialMetadata {
    pub credential_id: String,
    pub org_id: Option<String>,
    pub owner_type: CredentialOwnerType,
    pub owner_user_id: Option<String>,
    pub provider_id: String,
    pub label: String,
    pub status: CredentialStatus,
    pub version: i64,
    pub fingerprint: String,
    pub key_version: String,
    pub created_at: String,
    pub updated_at: String,
    pub last_used_at: Option<String>,
}

impl fmt::Debug for CredentialMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialMetadata")
            .field("credential_id", &self.credential_id)
            .field("org_id", &self.org_id)
            .field("owner_type", &self.owner_type)
            .field("provider_id", &self.provider_id)
            .field("label", &self.label)
            .field("status", &self.status)
            .field("version", &self.version)
            .field("fingerprint", &"[redacted]")
            .field("key_version", &self.key_version)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("last_used_at", &self.last_used_at)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialHandle {
    pub credential_id: String,
    pub provider_id: String,
    pub owner_type: CredentialOwnerType,
}

pub fn can_resolve_credential(
    credential: &CredentialMetadata,
    organization_id: &str,
    user_id: &str,
    mode: CredentialMode,
) -> bool {
    if !credential.status.is_resolvable() || !mode.allows(credential.owner_type) {
        return false;
    }
    match credential.owner_type {
        CredentialOwnerType::Platform => credential.org_id.is_none(),
        CredentialOwnerType::Organization => credential.org_id.as_deref() == Some(organization_id),
        CredentialOwnerType::User => {
            credential.org_id.as_deref() == Some(organization_id)
                && credential.owner_user_id.as_deref() == Some(user_id)
        }
        CredentialOwnerType::ServiceAccount => {
            credential.org_id.as_deref() == Some(organization_id)
                && credential.owner_user_id.as_deref() == Some(user_id)
        }
        CredentialOwnerType::LocalOnly => false,
    }
}

pub fn metadata_fingerprint(digest_hex: &str) -> Option<String> {
    let value = digest_hex.trim().to_ascii_lowercase();
    if value.len() < 8 || value.len() > 128 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(value[..12].to_owned())
}

pub fn mask_fingerprint(fingerprint: &str) -> String {
    if fingerprint.len() <= 8 {
        return "••••".to_owned();
    }
    format!("••••{}", &fingerprint[fingerprint.len().saturating_sub(4)..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_are_explicit_and_platform_is_not_a_tenant_scope() {
        assert!(CredentialMode::PlatformOnly.allows(CredentialOwnerType::Platform));
        assert!(!CredentialMode::PlatformOnly.allows(CredentialOwnerType::Organization));
        assert!(!CredentialMode::OrganizationOnly.allows(CredentialOwnerType::Platform));
    }

    #[test]
    fn fingerprint_mask_does_not_return_a_full_digest() {
        let fingerprint = metadata_fingerprint("0123456789abcdef").unwrap();
        let masked = mask_fingerprint(&fingerprint);
        assert_eq!(fingerprint, "0123456789ab");
        assert_eq!(masked, "••••6789ab");
        assert!(!masked.contains("012345"));
    }
}
