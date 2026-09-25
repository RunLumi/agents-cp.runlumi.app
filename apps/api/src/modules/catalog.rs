//! P04 provider/model catalog domain rules.
//!
//! Catalog identities are stable and vendor-neutral. This module contains no
//! SQL, HTTP, or provider transport code; those boundaries consume the typed
//! values and enforce their own resource predicates.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelCapability {
    Text,
    Vision,
    Tools,
    StructuredOutput,
    Reasoning,
    Audio,
    Embeddings,
}

impl ModelCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Vision => "vision",
            Self::Tools => "tools",
            Self::StructuredOutput => "structured_output",
            Self::Reasoning => "reasoning",
            Self::Audio => "audio",
            Self::Embeddings => "embeddings",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "text" => Some(Self::Text),
            "vision" => Some(Self::Vision),
            "tools" => Some(Self::Tools),
            "structured_output" => Some(Self::StructuredOutput),
            "reasoning" => Some(Self::Reasoning),
            "audio" => Some(Self::Audio),
            "embeddings" => Some(Self::Embeddings),
            _ => None,
        }
    }
}

impl fmt::Display for ModelCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogLifecycle {
    Active,
    Deprecated,
    Disabled,
}

impl CatalogLifecycle {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Deprecated => "deprecated",
            Self::Disabled => "disabled",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "deprecated" => Some(Self::Deprecated),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }

    /// Deprecated catalog entries remain readable but are not selected for a
    /// new route. Disabled entries are never selected for new inference.
    pub const fn allows_new_routes(self) -> bool {
        matches!(self, Self::Active | Self::Deprecated)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ModelCapabilities(BTreeSet<ModelCapability>);

impl ModelCapabilities {
    pub fn new(values: impl IntoIterator<Item = ModelCapability>) -> Self {
        Self(values.into_iter().collect())
    }

    pub fn contains(&self, capability: ModelCapability) -> bool {
        self.0.contains(&capability)
    }

    pub fn contains_all(&self, required: &[ModelCapability]) -> bool {
        required.iter().all(|capability| self.contains(*capability))
    }

    pub fn iter(&self) -> impl Iterator<Item = &ModelCapability> {
        self.0.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromIterator<ModelCapability> for ModelCapabilities {
    fn from_iter<T: IntoIterator<Item = ModelCapability>>(iter: T) -> Self {
        Self::new(iter)
    }
}

impl IntoIterator for ModelCapabilities {
    type Item = ModelCapability;
    type IntoIter = std::collections::btree_set::IntoIter<ModelCapability>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderDescriptor {
    pub provider_id: String,
    pub display_name: String,
    pub adapter: String,
    pub lifecycle: CatalogLifecycle,
    pub endpoint_url: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelDescriptor {
    pub model_id: String,
    pub provider_id: String,
    pub provider_model_id: String,
    pub display_name: String,
    pub capabilities: ModelCapabilities,
    pub max_input_tokens: Option<u32>,
    pub max_output_tokens: Option<u32>,
    pub lifecycle: CatalogLifecycle,
    pub pricing_version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogPolicy {
    /// `None` means the policy does not constrain this dimension. An explicit
    /// set is always an allowlist, including an empty set.
    pub allowed_aliases: Option<BTreeSet<String>>,
    pub allowed_models: Option<BTreeSet<String>>,
    pub allowed_providers: Option<BTreeSet<String>>,
    pub enabled: bool,
}

impl Default for CatalogPolicy {
    fn default() -> Self {
        Self {
            allowed_aliases: None,
            allowed_models: None,
            allowed_providers: None,
            enabled: true,
        }
    }
}

impl CatalogPolicy {
    pub fn allows_alias(&self, alias: &str) -> bool {
        self.enabled
            && self
                .allowed_aliases
                .as_ref()
                .is_none_or(|values| values.contains(alias))
    }

    pub fn allows_model(&self, model_id: &str) -> bool {
        self.enabled
            && self
                .allowed_models
                .as_ref()
                .is_none_or(|values| values.contains(model_id))
    }

    pub fn allows_provider(&self, provider_id: &str) -> bool {
        self.enabled
            && self
                .allowed_providers
                .as_ref()
                .is_none_or(|values| values.contains(provider_id))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogValidationError {
    EmptyDisplayName,
    InvalidProviderId,
    InvalidModelId,
    InvalidAdapter,
    InvalidCapabilities,
    InvalidTokenLimit,
    InvalidEndpoint,
}

impl fmt::Display for CatalogValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyDisplayName => "display name is required",
            Self::InvalidProviderId => "provider ID is invalid",
            Self::InvalidModelId => "model ID is invalid",
            Self::InvalidAdapter => "provider adapter is invalid",
            Self::InvalidCapabilities => "model capabilities are invalid",
            Self::InvalidTokenLimit => "model token limit is invalid",
            Self::InvalidEndpoint => "provider endpoint is invalid",
        })
    }
}

impl std::error::Error for CatalogValidationError {}

pub fn validate_provider(provider: &ProviderDescriptor) -> Result<(), CatalogValidationError> {
    if provider.provider_id.is_empty() || provider.provider_id.len() > 255 {
        return Err(CatalogValidationError::InvalidProviderId);
    }
    if provider.display_name.trim().is_empty() || provider.display_name.chars().count() > 160 {
        return Err(CatalogValidationError::EmptyDisplayName);
    }
    if !matches!(provider.adapter.as_str(), "openai_compatible" | "anthropic" | "mock") {
        return Err(CatalogValidationError::InvalidAdapter);
    }
    if let Some(endpoint) = &provider.endpoint_url
        && (endpoint.is_empty() || endpoint.len() > 2048 || endpoint.chars().any(char::is_control))
    {
        return Err(CatalogValidationError::InvalidEndpoint);
    }
    Ok(())
}

pub fn validate_model(model: &ModelDescriptor) -> Result<(), CatalogValidationError> {
    if model.model_id.is_empty() || model.model_id.len() > 255 {
        return Err(CatalogValidationError::InvalidModelId);
    }
    if model.provider_id.is_empty() || model.provider_model_id.trim().is_empty() {
        return Err(CatalogValidationError::InvalidModelId);
    }
    if model.display_name.trim().is_empty() || model.display_name.chars().count() > 160 {
        return Err(CatalogValidationError::EmptyDisplayName);
    }
    if model.capabilities.is_empty() {
        return Err(CatalogValidationError::InvalidCapabilities);
    }
    if model.max_input_tokens == Some(0) || model.max_output_tokens == Some(0) {
        return Err(CatalogValidationError::InvalidTokenLimit);
    }
    Ok(())
}

pub fn model_satisfies(
    model: &ModelDescriptor,
    required_capabilities: &[ModelCapability],
) -> bool {
    model.lifecycle.allows_new_routes() && model.capabilities.contains_all(required_capabilities)
}

pub fn provider_satisfies(provider: &ProviderDescriptor, policy: &CatalogPolicy) -> bool {
    provider.lifecycle.allows_new_routes() && policy.allows_provider(&provider.provider_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_round_trips_through_wire_names() {
        assert_eq!(ModelCapability::parse("structured_output"), Some(ModelCapability::StructuredOutput));
        assert_eq!(serde_json::to_string(&ModelCapability::Tools).unwrap(), "\"tools\"");
        assert!(ModelCapability::parse("unknown").is_none());
    }

    #[test]
    fn deprecated_models_remain_readable_but_not_newly_routable() {
        assert!(CatalogLifecycle::Deprecated.allows_new_routes());
        assert!(!CatalogLifecycle::Disabled.allows_new_routes());
    }
}
