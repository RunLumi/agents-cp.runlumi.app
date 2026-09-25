//! P05 typed consumers for the P03 policy snapshot extension.
//!
//! P03 remains the transport/authority owner. This module only parses bounded,
//! versioned P05 sections and fails closed for managed tool/budget decisions.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const TOOL_POLICY_SCHEMA_VERSION: u32 = 1;
pub const BUDGET_POLICY_SCHEMA_VERSION: u32 = 1;
pub const RATE_LIMIT_POLICY_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultPosture {
    #[default]
    Deny,
    Allow,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    RequireSessionApproval,
    RequirePerUseApproval,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolPolicyRule {
    pub tool_id: String,
    #[serde(default)]
    pub capability_id: Option<String>,
    pub decision: PolicyDecision,
    #[serde(default)]
    pub argument_scope: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BrowserPolicy {
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    #[serde(default)]
    pub blocked_categories: Vec<String>,
    #[serde(default)]
    pub allow_download: bool,
    #[serde(default)]
    pub allow_upload: bool,
    #[serde(default)]
    pub allow_authenticated: bool,
    #[serde(default)]
    pub allow_clipboard: bool,
    #[serde(default)]
    pub external_submit: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ComputerPolicy {
    #[serde(default)]
    pub allow_accessibility: bool,
    #[serde(default)]
    pub allow_screen_capture: bool,
    #[serde(default)]
    pub allow_keyboard_mouse: bool,
    #[serde(default)]
    pub allow_shell_escalation: bool,
    #[serde(default)]
    pub allowed_applications: Vec<String>,
    #[serde(default)]
    pub blocked_applications: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolPolicySection {
    pub schema_version: u32,
    #[serde(default)]
    pub default_posture: DefaultPosture,
    #[serde(default)]
    pub tool_ids: BTreeSet<String>,
    #[serde(default)]
    pub mcp_ids: BTreeSet<String>,
    #[serde(default)]
    pub rules: Vec<ToolPolicyRule>,
    #[serde(default)]
    pub browser: BrowserPolicy,
    #[serde(default)]
    pub computer: ComputerPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetPolicySection {
    pub schema_version: u32,
    #[serde(default)]
    pub hard_fail_closed: bool,
    #[serde(default)]
    pub scope_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitPolicySection {
    pub schema_version: u32,
    #[serde(default)]
    pub policies: Vec<Value>,
}

/// Parse the P05 tools section. A missing or schema-0 section is not an allow
/// decision; callers must treat `None` as unavailable for managed execution.
pub fn tool_policy(payload: &Value) -> Option<ToolPolicySection> {
    let section = payload.get("tools")?;
    let parsed = serde_json::from_value::<ToolPolicySection>(section.clone()).ok()?;
    (parsed.schema_version == TOOL_POLICY_SCHEMA_VERSION).then_some(parsed)
}

pub fn budget_policy(payload: &Value) -> Option<BudgetPolicySection> {
    let section = payload.get("budgets")?;
    let parsed = serde_json::from_value::<BudgetPolicySection>(section.clone()).ok()?;
    (parsed.schema_version == BUDGET_POLICY_SCHEMA_VERSION).then_some(parsed)
}

pub fn rate_limit_policy(payload: &Value) -> Option<RateLimitPolicySection> {
    let section = payload.get("rate_limits")?;
    let parsed = serde_json::from_value::<RateLimitPolicySection>(section.clone()).ok()?;
    (parsed.schema_version == RATE_LIMIT_POLICY_SCHEMA_VERSION).then_some(parsed)
}

pub fn is_opaque_placeholder(section: Option<&Value>) -> bool {
    section.is_some_and(|value| {
        value
            .as_object()
            .is_some_and(|object| object.get("schema_version").and_then(Value::as_u64) == Some(0))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn versioned_tool_policy_is_typed_and_schema_zero_is_not_allow() {
        let payload = json!({
            "tools": {
                "schema_version": 1,
                "default_posture": "deny",
                "tool_ids": ["tool_0123456789abcdef0123456789abcdef"],
                "rules": [{
                    "tool_id": "tool_0123456789abcdef0123456789abcdef",
                    "decision": "require_per_use_approval",
                    "argument_scope": ["destination"]
                }]
            }
        });
        let policy = tool_policy(&payload).expect("typed policy");
        assert_eq!(policy.default_posture, DefaultPosture::Deny);
        assert_eq!(
            policy.rules[0].decision,
            PolicyDecision::RequirePerUseApproval
        );
        assert!(tool_policy(&json!({"tools": {"schema_version": 0}})).is_none());
    }

    #[test]
    fn malformed_sections_fail_closed() {
        let payload = json!({"tools": {"schema_version": 1, "rules": "not-an-array"}});
        assert!(tool_policy(&payload).is_none());
        assert!(budget_policy(&json!({"budgets": {"schema_version": 2}})).is_none());
    }
}
