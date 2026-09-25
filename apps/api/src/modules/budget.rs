//! P04 budget decision boundary.
//!
//! P04 owns the pre-dispatch hook and reservation metadata. P05/P06 may
//! replace the allow-all implementation with a durable budget service without
//! changing inference route contracts.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDecision {
    Allow,
    Deny,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetRequest {
    pub organization_id: String,
    pub project_id: Option<String>,
    pub principal_user_id: String,
    pub model_alias: String,
    pub estimated_input_tokens: u32,
    pub estimated_output_tokens: u32,
}

/// A small, deterministic hook port. Implementations must fail closed for a
/// configured hard budget, while the default implementation keeps local-only
/// development usable when no budget store is configured.
pub trait BudgetHook {
    fn decide(&self, request: &BudgetRequest) -> BudgetDecision;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AllowAllBudgetHook;

impl BudgetHook for AllowAllBudgetHook {
    fn decide(&self, _request: &BudgetRequest) -> BudgetDecision {
        BudgetDecision::Allow
    }
}

pub fn estimate_text_tokens(text: &str) -> u32 {
    let bytes = text.len() as u64;
    bytes.div_ceil(4).min(u64::from(u32::MAX)) as u32
}

pub fn estimate_request_tokens(request: &crate::modules::inference::InferenceRequest) -> u32 {
    request
        .messages
        .iter()
        .flat_map(|message| message.content.iter())
        .fold(0_u32, |total, part| {
            let part_tokens = match part {
                crate::modules::inference::ContentPart::Text { text } => estimate_text_tokens(text),
            };
            total.saturating_add(part_tokens)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::catalog::ModelCapability;

    #[test]
    fn default_hook_allows_unconfigured_development_work() {
        let request = BudgetRequest {
            organization_id: "org_1".to_owned(),
            project_id: None,
            principal_user_id: "usr_1".to_owned(),
            model_alias: "coding-default".to_owned(),
            estimated_input_tokens: 10,
            estimated_output_tokens: 10,
        };
        assert_eq!(AllowAllBudgetHook.decide(&request), BudgetDecision::Allow);
    }

    #[test]
    fn token_estimate_is_bounded_and_does_not_overflow() {
        assert_eq!(estimate_text_tokens("abcd"), 1);
        assert_eq!(estimate_text_tokens("abcde"), 2);
        assert!(estimate_text_tokens(&"x".repeat(1_000_000)) < u32::MAX);
        let request = crate::modules::inference::InferenceRequest {
            model: "alias".to_owned(),
            messages: vec![crate::modules::inference::InferenceMessage::user("abcd")],
            required_capabilities: vec![ModelCapability::Text],
            stream: false,
            max_output_tokens: Some(100),
            temperature: None,
            tools: Vec::new(),
            retry_safe: true,
            project_id: None,
            session_id: None,
            run_id: None,
        };
        assert_eq!(estimate_request_tokens(&request), 1);
    }
}
