//! P03 policy compiler: assembles the immutable, versioned effective policy
//! snapshot for an organization (F19-004/FR-F19-005).
//!
//! P03 owns the envelope and the `org_access`, `projects`, and
//! `min_client_version` sections. The `models`, `tools`, `automation`,
//! `entitlements`, `budgets`, and `rate_limits` sections are typed extension points: opaque JSON objects
//! with a `schema_version` field that P04/P05 will own. Unknown sections are
//! dropped, malformed placeholders fail compilation, and the payload is
//! capped so a policy snapshot can never smuggle unbounded data.

use serde_json::{Map, Value, json};

use crate::core::CoreError;

pub const POLICY_PAYLOAD_MAX_LEN: usize = 65_536;
pub const DEFAULT_POLICY_TTL_SECONDS: u32 = 24 * 60 * 60;

/// Sections owned by later phases; P03 validates their shape only.
pub const EXTENSION_SECTIONS: [&str; 6] = [
    "models",
    "tools",
    "automation",
    "entitlements",
    "budgets",
    "rate_limits",
];

/// Effective-policy inputs gathered by the caller from current state.
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyInputs<'a> {
    pub org_active: bool,
    /// org-scope access for the device owner's membership (F19-004 org access)
    pub member_active: bool,
    /// Workspace bindings the device holds: `(project_id, archived)`.
    pub project_bindings: &'a [(String, bool)],
    /// Org/platform minimum client version, when one is enforced.
    pub min_client_version: Option<&'a str>,
}

/// Compile the policy payload for one device. The result is deterministic for
/// identical inputs so snapshot versions only change when state changes.
pub fn compile_policy_payload(
    inputs: &PolicyInputs<'_>,
    extension_sections: Option<&Value>,
) -> Result<Value, CoreError> {
    if !inputs.org_active {
        return Err(CoreError::InvalidPolicyInputs);
    }

    let bindings: Vec<&String> = inputs
        .project_bindings
        .iter()
        .filter_map(|(project_id, archived)| if !archived { Some(project_id) } else { None })
        .collect();

    let min_client_version = match inputs.min_client_version {
        Some(version) => {
            crate::modules::devices::validate_app_version(version)
                .map_err(|_| CoreError::InvalidPolicyInputs)?;
            Value::String(version.to_string())
        }
        None => Value::Null,
    };

    let mut sections = Map::new();
    if let Some(extensions) = extension_sections {
        let object = extensions
            .as_object()
            .ok_or(CoreError::InvalidPolicyInputs)?;
        for (key, value) in object {
            if !EXTENSION_SECTIONS.contains(&key.as_str()) {
                return Err(CoreError::InvalidPolicyInputs);
            }
            let section = value.as_object().ok_or(CoreError::InvalidPolicyInputs)?;
            if !section.contains_key("schema_version") {
                return Err(CoreError::InvalidPolicyInputs);
            }
            sections.insert(key.clone(), value.clone());
        }
    }
    for section in EXTENSION_SECTIONS {
        sections
            .entry(section.to_string())
            .or_insert_with(|| json!({ "schema_version": 0 }));
    }

    let payload = json!({
        "org_access": { "member": inputs.member_active },
        "projects": { "bindings": bindings },
        "min_client_version": min_client_version,
        "models": sections["models"],
        "tools": sections["tools"],
        "automation": sections["automation"],
        "entitlements": sections["entitlements"],
        "budgets": sections["budgets"],
        "rate_limits": sections["rate_limits"],
    });

    if serde_json::to_string(&payload)
        .map(|text| text.len() > POLICY_PAYLOAD_MAX_LEN)
        .unwrap_or(true)
    {
        return Err(CoreError::InvalidPolicyInputs);
    }
    Ok(payload)
}

/// True when the snapshot is currently usable by the device: issued for this
/// org, unexpired against the server clock, and acked state tracked outside.
pub fn snapshot_is_current(
    snapshot_org: &str,
    device_org: &str,
    expires_at: &str,
    now: &str,
) -> bool {
    snapshot_org == device_org && expires_at > now
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn inputs<'a>(
        bindings: &'a [(String, bool)],
        min_version: Option<&'a str>,
    ) -> PolicyInputs<'a> {
        PolicyInputs {
            org_active: true,
            member_active: true,
            project_bindings: bindings,
            min_client_version: min_version,
        }
    }

    #[test]
    fn payload_has_typed_sections_and_placeholders() {
        let bindings = vec![
            ("prj_a".to_string(), false),
            ("prj_archived".to_string(), true),
        ];
        let payload = compile_policy_payload(&inputs(&bindings, Some("0.3.0")), None).unwrap();
        assert_eq!(payload["projects"]["bindings"], json!(["prj_a"]));
        assert_eq!(payload["min_client_version"], json!("0.3.0"));
        assert_eq!(payload["org_access"]["member"], json!(true));
        for section in EXTENSION_SECTIONS {
            assert_eq!(payload[section]["schema_version"], json!(0));
        }
    }

    #[test]
    fn extension_sections_are_accepted_only_when_typed() {
        let extensions = json!({
            "models": { "schema_version": 1, "routes": [] },
            "mystery": {}
        });
        assert!(compile_policy_payload(&inputs(&[], None), Some(&extensions)).is_err());

        let extensions = json!({ "tools": { "schema_version": 2, "mcp": [] } });
        let payload = compile_policy_payload(&inputs(&[], None), Some(&extensions)).unwrap();
        assert_eq!(payload["tools"]["schema_version"], json!(2));
        assert_eq!(payload["models"]["schema_version"], json!(0));
    }

    #[test]
    fn inactive_orgs_and_bad_min_versions_fail_compilation() {
        let bindings: Vec<(String, bool)> = vec![];
        let mut inactive = inputs(&bindings, None);
        inactive.org_active = false;
        assert!(compile_policy_payload(&inactive, None).is_err());

        assert!(compile_policy_payload(&inputs(&bindings, Some("not a version")), None).is_err());
    }

    #[test]
    fn snapshot_currency_requires_same_org_and_validity_window() {
        assert!(snapshot_is_current(
            "org_a",
            "org_a",
            "2026-10-01T00:00:00Z",
            "2026-09-25T00:00:00Z"
        ));
        assert!(!snapshot_is_current(
            "org_b",
            "org_a",
            "2026-10-01T00:00:00Z",
            "2026-09-25T00:00:00Z"
        ));
        assert!(!snapshot_is_current(
            "org_a",
            "org_a",
            "2026-01-01T00:00:00Z",
            "2026-09-25T00:00:00Z"
        ));
    }
}
