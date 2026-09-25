//! P04 consumer for the P03 policy snapshot extension.
//!
//! P03 owns the envelope and transport. P04 only interprets the typed
//! `payload.models` section and never widens access when the section is absent
//! or malformed.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::modules::{catalog::CatalogPolicy, credentials::CredentialMode};

pub const MODEL_POLICY_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelPolicyExtension {
    pub schema_version: u32,
    #[serde(default)]
    pub allowed_aliases: BTreeSet<String>,
    #[serde(default)]
    pub allowed_models: BTreeSet<String>,
    #[serde(default)]
    pub allowed_providers: BTreeSet<String>,
    pub credential_mode: Option<CredentialMode>,
    pub managed_route_enabled: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicySnapshotEnvelope {
    pub policy_id: String,
    pub org_id: String,
    pub policy_version: i64,
    pub payload: Value,
}

impl PolicySnapshotEnvelope {
    pub fn models(&self) -> Option<ModelPolicyExtension> {
        let section = self.payload.get("models")?;
        let extension = serde_json::from_value::<ModelPolicyExtension>(section.clone()).ok()?;
        (extension.schema_version == MODEL_POLICY_SCHEMA_VERSION).then_some(extension)
    }

    pub fn trusted_project_id(&self) -> Option<&str> {
        self.payload
            .get("project_id")
            .and_then(Value::as_str)
            .or_else(|| {
                self.payload
                    .get("projects")
                    .and_then(|projects| projects.get("bindings"))
                    .and_then(|bindings| bindings.as_array())
                    .filter(|bindings| bindings.len() == 1)
                    .and_then(|bindings| bindings.first())
                    .and_then(Value::as_str)
            })
            .filter(|value| {
                !value.is_empty() && value.len() <= 255 && !value.chars().any(char::is_control)
            })
    }

    pub fn trusted_device_id(&self) -> Option<&str> {
        self.payload
            .get("device_id")
            .and_then(Value::as_str)
            .or_else(|| {
                self.payload
                    .get("device")
                    .and_then(|device| device.get("id"))
                    .and_then(Value::as_str)
            })
            .filter(|value| {
                !value.is_empty() && value.len() <= 255 && !value.chars().any(char::is_control)
            })
    }

    fn is_opaque_p03_placeholder(&self) -> bool {
        let Some(section) = self.payload.get("models") else {
            return false;
        };
        section
            .as_object()
            .is_some_and(|object| object.get("schema_version").and_then(Value::as_u64) == Some(0))
            && !section.as_object().is_some_and(|object| {
                [
                    "allowed_aliases",
                    "allowed_models",
                    "allowed_providers",
                    "credential_mode",
                    "managed_route_enabled",
                ]
                .iter()
                .any(|key| object.contains_key(*key))
            })
    }

    pub fn apply_to(
        &self,
        base: CatalogPolicy,
        base_mode: CredentialMode,
    ) -> (CatalogPolicy, CredentialMode) {
        if self.payload.get("models").is_some()
            && self.models().is_none()
            && !self.is_opaque_p03_placeholder()
        {
            // A present but malformed/unknown extension is not an instruction
            // to fall back to an unrestricted base policy. Disable managed
            // routing until P03 supplies a valid snapshot.
            return (
                CatalogPolicy {
                    allowed_aliases: Some(BTreeSet::new()),
                    allowed_models: Some(BTreeSet::new()),
                    allowed_providers: Some(BTreeSet::new()),
                    enabled: false,
                },
                base_mode,
            );
        }
        let Some(extension) = self.models() else {
            return (base, base_mode);
        };
        (
            CatalogPolicy {
                allowed_aliases: Some(extension.allowed_aliases.clone()),
                allowed_models: Some(extension.allowed_models.clone()),
                allowed_providers: Some(extension.allowed_providers.clone()),
                enabled: extension.managed_route_enabled.unwrap_or(base.enabled),
            },
            extension.credential_mode.unwrap_or(base_mode),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn p03_models_section_is_consumed_without_claiming_authority() {
        let snapshot = PolicySnapshotEnvelope {
            policy_id: "pol_1".to_owned(),
            org_id: "org_1".to_owned(),
            policy_version: 2,
            payload: json!({
                "models": {
                    "schema_version": 1,
                    "allowed_aliases": ["coding-default"],
                    "allowed_models": ["mdl_1"],
                    "allowed_providers": ["prv_1"],
                    "credential_mode": "organization_only",
                    "managed_route_enabled": true
                }
            }),
        };
        let (policy, mode) =
            snapshot.apply_to(CatalogPolicy::default(), CredentialMode::PlatformOnly);
        assert!(policy.allows_alias("coding-default"));
        assert!(!policy.allows_alias("coding-fast"));
        assert_eq!(mode, CredentialMode::OrganizationOnly);
    }

    #[test]
    fn malformed_or_unknown_models_section_does_not_widen_base_policy() {
        let snapshot = PolicySnapshotEnvelope {
            policy_id: "pol_1".to_owned(),
            org_id: "org_1".to_owned(),
            policy_version: 2,
            payload: json!({"models": {"schema_version": 99, "allowed_aliases": ["*"]}}),
        };
        let (policy, mode) =
            snapshot.apply_to(CatalogPolicy::default(), CredentialMode::PlatformOnly);
        assert!(!policy.allows_alias("anything"));
        assert!(!policy.enabled);
        assert_eq!(mode, CredentialMode::PlatformOnly);
    }

    #[test]
    fn opaque_p03_placeholder_does_not_widen_or_disable_base_policy() {
        let snapshot = PolicySnapshotEnvelope {
            policy_id: "pol_1".to_owned(),
            org_id: "org_1".to_owned(),
            policy_version: 7,
            payload: json!({
                "projects": {"bindings": ["prj_1"]},
                "models": {"schema_version": 0}
            }),
        };
        let (policy, mode) =
            snapshot.apply_to(CatalogPolicy::default(), CredentialMode::PlatformOnly);
        assert!(policy.enabled);
        assert_eq!(mode, CredentialMode::PlatformOnly);
        assert_eq!(snapshot.trusted_project_id(), Some("prj_1"));
    }

    #[test]
    fn trusted_project_scope_is_read_only_from_the_snapshot_payload() {
        let snapshot = PolicySnapshotEnvelope {
            policy_id: "pol_1".to_owned(),
            org_id: "org_1".to_owned(),
            policy_version: 2,
            payload: json!({"project_id": "prj_1", "models": {"schema_version": 99}}),
        };
        assert_eq!(snapshot.trusted_project_id(), Some("prj_1"));
        assert!(
            !snapshot
                .apply_to(CatalogPolicy::default(), CredentialMode::PlatformOnly)
                .0
                .enabled
        );
    }
}
