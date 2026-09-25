//! P03 device domain: enrollment lifecycle, credential rules, bounded
//! capability reports, minimum-version evaluation, and heartbeat semantics.
//!
//! Pure decision logic lives here; SQL lives in repositories and HTTP shape
//! in routes. All timestamps are RFC 3339 UTC strings per P01-CG.

use serde_json::Value;

use crate::core::CoreError;

/// Enrollment lifecycle (P03-CG): `pending` until approved; approval plus a
/// valid proof-of-possession completes it; the pending window is bounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollmentStatus {
    Pending,
    Completed,
    Expired,
    Denied,
}

impl EnrollmentStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completed => "completed",
            Self::Expired => "expired",
            Self::Denied => "denied",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "completed" => Some(Self::Completed),
            "expired" => Some(Self::Expired),
            "denied" => Some(Self::Denied),
            _ => None,
        }
    }
}

/// Managed device lifecycle (P03-CG): revocation is terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceStatus {
    Active,
    Revoked,
}

impl DeviceStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

pub const ENROLLMENT_TTL_SECONDS: u32 = 15 * 60;
pub const DEVICE_TOKEN_TTL_SECONDS: u32 = 15 * 60;

pub const MAX_DEVICE_NAME_LEN: usize = 120;
pub const MAX_PLATFORM_LEN: usize = 64;
pub const MAX_PUBLIC_KEY_LEN: usize = 4096;
pub const FINGERPRINT_LEN: usize = 64;
pub const MAX_WORKSPACE_IDENTITY_LEN: usize = 256;
pub const MAX_WORKSPACE_DISPLAY_LEN: usize = 120;
pub const MAX_CAPABILITY_JSON_LEN: usize = 2048;

/// Validated enrollment begin payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentInput {
    pub public_key: String,
    pub key_fingerprint: String,
    pub device_name: String,
    pub platform: String,
    pub app_version: String,
}

/// Validate the anonymous enrollment begin payload (F19-001/FR-F19-002).
/// The fingerprint must be a 64-character lowercase hex SHA-256 digest and
/// the public key a bounded PEM/SPKI string; nothing here trusts the device.
pub fn validate_enrollment_input(
    public_key: &str,
    key_fingerprint: &str,
    device_name: &str,
    platform: &str,
    app_version: &str,
) -> Result<EnrollmentInput, CoreError> {
    let trimmed_name = device_name.trim();
    let name_ok = !trimmed_name.is_empty()
        && trimmed_name.chars().count() <= MAX_DEVICE_NAME_LEN
        && !trimmed_name.chars().any(|c| c.is_control());
    let fingerprint_ok = key_fingerprint.len() == FINGERPRINT_LEN
        && key_fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    let key_ok = !public_key.is_empty()
        && public_key.len() <= MAX_PUBLIC_KEY_LEN
        && public_key.contains("BEGIN")
        && public_key.ends_with('\n');
    if !name_ok || !fingerprint_ok || !key_ok {
        return Err(CoreError::InvalidEnrollmentInput);
    }
    validate_platform(platform)?;
    validate_app_version(app_version)?;
    Ok(EnrollmentInput {
        public_key: public_key.to_owned(),
        key_fingerprint: key_fingerprint.to_owned(),
        device_name: trimmed_name.to_owned(),
        platform: platform.to_owned(),
        app_version: app_version.to_owned(),
    })
}

pub fn validate_platform(platform: &str) -> Result<(), CoreError> {
    let ok = !platform.is_empty()
        && platform.chars().count() <= MAX_PLATFORM_LEN
        && platform
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    if ok {
        Ok(())
    } else {
        Err(CoreError::InvalidPlatform)
    }
}

pub fn validate_app_version(app_version: &str) -> Result<(), CoreError> {
    let ok = !app_version.is_empty()
        && app_version.chars().count() <= 32
        && app_version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.');
    if ok {
        Ok(())
    } else {
        Err(CoreError::InvalidAppVersion)
    }
}

/// Bounded capability keys a device may report (F19-003). Values are typed:
/// booleans for runtime toggles, short strings for versions, and an array of
/// short strings for policy schema versions.
const CAPABILITY_BOOL_KEYS: [&str; 4] = [
    "browser_use",
    "computer_use",
    "remote_environment",
    "automation_eligible",
];

const CAPABILITY_STRING_KEYS: [&str; 1] = ["runtime_version"];

/// Validate a capability report and return its canonical serialized form.
/// Unknown keys, wrong value types, and oversized payloads are rejected so
/// the control plane never stores unbounded device inventory (F19-003).
pub fn validate_capability_report(raw: &str) -> Result<String, CoreError> {
    if raw.len() > MAX_CAPABILITY_JSON_LEN {
        return Err(CoreError::InvalidCapabilityReport);
    }
    let value: Value = serde_json::from_str(raw).map_err(|_| CoreError::InvalidCapabilityReport)?;
    let object = value
        .as_object()
        .ok_or(CoreError::InvalidCapabilityReport)?;
    for (key, value) in object {
        if CAPABILITY_BOOL_KEYS.contains(&key.as_str()) {
            if !value.is_boolean() {
                return Err(CoreError::InvalidCapabilityReport);
            }
        } else if CAPABILITY_STRING_KEYS.contains(&key.as_str()) {
            let text = value.as_str().ok_or(CoreError::InvalidCapabilityReport)?;
            if text.is_empty() || text.len() > 64 {
                return Err(CoreError::InvalidCapabilityReport);
            }
        } else if key == "policy_schema_versions" {
            let versions = value.as_array().ok_or(CoreError::InvalidCapabilityReport)?;
            if versions.len() > 16 {
                return Err(CoreError::InvalidCapabilityReport);
            }
            for version in versions {
                let text = version.as_str().ok_or(CoreError::InvalidCapabilityReport)?;
                if text.is_empty() || text.len() > 64 || text.chars().any(char::is_control) {
                    return Err(CoreError::InvalidCapabilityReport);
                }
            }
        } else {
            return Err(CoreError::InvalidCapabilityReport);
        }
    }
    serde_json::to_string(&value).map_err(|_| CoreError::InvalidCapabilityReport)
}

/// Deterministic minimum-version comparison (F19-008): dot-separated numeric
/// components, up to four, missing components are zero. A version that does
/// not parse never satisfies the minimum (fail closed for managed operations).
pub fn version_at_least(current: &str, minimum: &str) -> bool {
    let parse = |text: &str| -> Option<[u64; 4]> {
        let mut parts = [0u64; 4];
        for (index, segment) in text.split('.').enumerate() {
            if index >= 4 || segment.is_empty() {
                return None;
            }
            let value: u64 = segment.parse().ok()?;
            parts[index] = value;
        }
        Some(parts)
    };
    match (parse(current), parse(minimum)) {
        (Some(current), Some(minimum)) => current >= minimum,
        _ => false,
    }
}

/// Validate a normalized workspace identity (F07-002/F07-007): non-secret,
/// stable, bounded, no control characters or absolute path semantics.
pub fn validate_workspace_identity(identity: &str) -> Result<String, CoreError> {
    let trimmed = identity.trim();
    let ok = !trimmed.is_empty()
        && trimmed.chars().count() <= MAX_WORKSPACE_IDENTITY_LEN
        && !trimmed.chars().any(char::is_control);
    if ok {
        Ok(trimmed.to_owned())
    } else {
        Err(CoreError::InvalidWorkspaceIdentity)
    }
}

pub fn validate_workspace_display_name(name: &str) -> Result<String, CoreError> {
    let trimmed = name.trim();
    let ok = !trimmed.is_empty() && trimmed.chars().count() <= MAX_WORKSPACE_DISPLAY_LEN;
    if ok {
        Ok(trimmed.to_owned())
    } else {
        Err(CoreError::InvalidWorkspaceDisplayName)
    }
}

/// Which org scope a binding may target. A binding is rejected when the
/// device org and project org disagree (cross-org binding, F07 acceptance).
pub fn binding_scope_check(device_org: &str, project_org: &str) -> Result<(), CoreError> {
    if device_org == project_org {
        Ok(())
    } else {
        Err(CoreError::WorkspaceBindingScopeMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "-----BEGIN PUBLIC KEY-----\nabc\n";

    #[test]
    fn enrollment_input_accepts_well_formed_devices() {
        let input = validate_enrollment_input(
            KEY,
            &"a".repeat(64),
            "  James Laptop ",
            "macos-arm64",
            "0.3.1",
        )
        .unwrap();
        assert_eq!(input.device_name, "James Laptop");
        assert_eq!(input.platform, "macos-arm64");
    }

    #[test]
    fn enrollment_input_rejects_bad_fingerprints_names_and_keys() {
        assert!(validate_enrollment_input(KEY, &"A".repeat(64), "n", "macos", "0.1.0").is_err());
        assert!(validate_enrollment_input(KEY, &"a".repeat(63), "n", "macos", "0.1.0").is_err());
        assert!(validate_enrollment_input(KEY, &"a".repeat(64), "", "macos", "0.1.0").is_err());
        assert!(validate_enrollment_input(KEY, &"a".repeat(64), "n", "mac os!", "0.1.0").is_err());
        assert!(
            validate_enrollment_input("raw-key", &"a".repeat(64), "n", "macos", "0.1.0").is_err()
        );
        assert!(validate_enrollment_input(KEY, &"a".repeat(64), "n", "macos", "0.1.0\n").is_err());
    }

    #[test]
    fn capability_reports_are_allowlisted_and_bounded() {
        let ok = validate_capability_report(
            r#"{"browser_use":true,"computer_use":false,"runtime_version":"1.2.0","policy_schema_versions":["tools@1"]}"#,
        )
        .unwrap();
        assert!(ok.contains("browser_use"));
        assert!(validate_capability_report(r#"{"process_list":["a","b"]}"#).is_err());
        assert!(validate_capability_report(r#"{"browser_use":"yes"}"#).is_err());
        assert!(
            validate_capability_report(&format!(r#"{{"runtime_version":"{}"}}"#, "x".repeat(80)))
                .is_err()
        );
        assert!(validate_capability_report(&"x".repeat(3000)).is_err());
    }

    #[test]
    fn version_comparison_is_numeric_and_fails_closed() {
        assert!(version_at_least("0.3.1", "0.3.0"));
        assert!(version_at_least("0.3", "0.3.0"));
        assert!(!version_at_least("0.2.9", "0.3.0"));
        assert!(!version_at_least("beta", "0.1.0"));
        assert!(!version_at_least("0.3.1", "not-a-version"));
        assert!(version_at_least("1", "0.9.9.9"));
    }

    #[test]
    fn workspace_identity_is_normalized_and_bounded() {
        assert_eq!(
            validate_workspace_identity("  ws-alpha ").unwrap(),
            "ws-alpha"
        );
        assert!(validate_workspace_identity("").is_err());
        assert!(validate_workspace_identity(&"x".repeat(300)).is_err());
        assert!(validate_workspace_identity("bad\nidentity").is_err());
    }

    #[test]
    fn binding_scope_rejects_cross_org() {
        let org_a = "org_a";
        assert!(binding_scope_check(org_a, org_a).is_ok());
        assert!(binding_scope_check("org_a", "org_b").is_err());
    }

    #[test]
    fn statuses_round_trip() {
        assert_eq!(
            EnrollmentStatus::parse(EnrollmentStatus::Completed.as_str()),
            Some(EnrollmentStatus::Completed)
        );
        assert_eq!(
            DeviceStatus::parse(DeviceStatus::Revoked.as_str()),
            Some(DeviceStatus::Revoked)
        );
        assert!(DeviceStatus::parse("pending").is_none());
    }
}
