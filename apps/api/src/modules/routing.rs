//! P04 route validation and deterministic candidate selection.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::catalog::{
    CatalogLifecycle, CatalogPolicy, ModelCapability, ModelDescriptor, ProviderDescriptor,
    model_satisfies, provider_satisfies,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStrategy {
    Fixed,
    OrderedFallback,
    WeightedHealthAware,
}

impl RouteStrategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::OrderedFallback => "ordered_fallback",
            Self::WeightedHealthAware => "weighted_health_aware",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "fixed" => Some(Self::Fixed),
            "ordered_fallback" => Some(Self::OrderedFallback),
            "weighted_health_aware" => Some(Self::WeightedHealthAware),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteCandidate {
    pub provider_id: String,
    pub model_id: String,
    pub weight: u16,
    pub timeout_ms: u32,
    pub max_retries: u8,
    pub credential_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteConfig {
    pub strategy: RouteStrategy,
    pub candidates: Vec<RouteCandidate>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectedCandidate {
    pub provider_id: String,
    pub model_id: String,
    pub weight: u16,
    pub timeout_ms: u32,
    pub max_retries: u8,
    pub credential_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum HealthState {
    Ready {
        provider_id: String,
    },
    CoolingDown {
        provider_id: String,
        cooldown_until: String,
    },
    Degraded {
        provider_id: String,
        last_error: String,
    },
}

impl HealthState {
    pub fn ready(provider_id: &str) -> Self {
        Self::Ready {
            provider_id: provider_id.to_owned(),
        }
    }

    pub fn cooling_down(provider_id: &str, cooldown_until: &str) -> Self {
        Self::CoolingDown {
            provider_id: provider_id.to_owned(),
            cooldown_until: cooldown_until.to_owned(),
        }
    }

    pub fn provider_id(&self) -> &str {
        match self {
            Self::Ready { provider_id }
            | Self::CoolingDown { provider_id, .. }
            | Self::Degraded { provider_id, .. } => provider_id,
        }
    }

    pub fn is_available(&self) -> bool {
        !matches!(self, Self::CoolingDown { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteSelectionError {
    NoCandidates,
    InvalidConfig,
    UnsupportedCapability,
    NoAllowedCandidate,
}

impl fmt::Display for RouteSelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoCandidates => "route has no candidates",
            Self::InvalidConfig => "route configuration is invalid",
            Self::UnsupportedCapability => "route candidates do not satisfy required capabilities",
            Self::NoAllowedCandidate => "no route candidate is allowed",
        })
    }
}

impl std::error::Error for RouteSelectionError {}

pub fn validate_route_config(config: &RouteConfig) -> Result<(), RouteSelectionError> {
    if config.candidates.is_empty() || config.candidates.len() > 16 {
        return Err(RouteSelectionError::NoCandidates);
    }
    let mut identities = BTreeSet::new();
    for candidate in &config.candidates {
        if candidate.provider_id.is_empty()
            || candidate.model_id.is_empty()
            || candidate.weight == 0
            || candidate.timeout_ms < 250
            || candidate.timeout_ms > 120_000
            || candidate.max_retries > 3
            || !identities.insert((candidate.provider_id.clone(), candidate.model_id.clone()))
        {
            return Err(RouteSelectionError::InvalidConfig);
        }
    }
    Ok(())
}

pub fn select_candidates(
    config: &RouteConfig,
    models: &[ModelDescriptor],
    providers: &[ProviderDescriptor],
    policy: &CatalogPolicy,
    health: &[HealthState],
    required_capabilities: &[String],
    seed: u64,
) -> Result<Vec<SelectedCandidate>, RouteSelectionError> {
    validate_route_config(config)?;
    let required = required_capabilities
        .iter()
        .map(|value| {
            ModelCapability::parse(value).ok_or(RouteSelectionError::UnsupportedCapability)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let provider_by_id = providers
        .iter()
        .map(|provider| (provider.provider_id.as_str(), provider))
        .collect::<BTreeMap<_, _>>();
    let model_by_id = models
        .iter()
        .map(|model| (model.model_id.as_str(), model))
        .collect::<BTreeMap<_, _>>();

    let mut eligible = config
        .candidates
        .iter()
        .filter_map(|candidate| {
            let provider = provider_by_id.get(candidate.provider_id.as_str())?;
            let model = model_by_id.get(candidate.model_id.as_str())?;
            if !provider_satisfies(provider, policy)
                || !policy.allows_model(&candidate.model_id)
                || provider.lifecycle == CatalogLifecycle::Disabled
                || !model_satisfies(model, &required)
                || model.provider_id != candidate.provider_id
                || health.iter().any(|state| {
                    state.provider_id() == candidate.provider_id && !state.is_available()
                })
            {
                return None;
            }
            Some(SelectedCandidate {
                provider_id: candidate.provider_id.clone(),
                model_id: candidate.model_id.clone(),
                weight: candidate.weight,
                timeout_ms: candidate.timeout_ms,
                max_retries: candidate.max_retries,
                credential_id: candidate.credential_id.clone(),
            })
        })
        .collect::<Vec<_>>();

    if eligible.is_empty() {
        let capability_mismatch = !required.is_empty()
            && config.candidates.iter().any(|candidate| {
                model_by_id
                    .get(candidate.model_id.as_str())
                    .is_some_and(|model| !model_satisfies(model, &required))
            });
        return Err(if capability_mismatch {
            RouteSelectionError::UnsupportedCapability
        } else {
            RouteSelectionError::NoAllowedCandidate
        });
    }
    match config.strategy {
        RouteStrategy::Fixed => eligible.truncate(1),
        RouteStrategy::OrderedFallback => {}
        RouteStrategy::WeightedHealthAware => {
            let total_weight = eligible
                .iter()
                .map(|candidate| u64::from(candidate.weight))
                .sum::<u64>();
            if total_weight > 0 {
                let mut ticket = seed % total_weight;
                let mut selected_index = 0;
                for (index, candidate) in eligible.iter().enumerate() {
                    let weight = u64::from(candidate.weight);
                    if ticket < weight {
                        selected_index = index;
                        break;
                    }
                    ticket -= weight;
                }
                let selected = eligible.remove(selected_index);
                eligible.insert(0, selected);
            }
        }
    }
    Ok(eligible)
}

pub fn compare_route_versions(left: i64, right: i64) -> Ordering {
    left.cmp(&right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::catalog::ModelCapabilities;

    fn candidate(provider: &str, model: &str, weight: u16) -> RouteCandidate {
        RouteCandidate {
            provider_id: provider.to_owned(),
            model_id: model.to_owned(),
            weight,
            timeout_ms: 1_000,
            max_retries: 1,
            credential_id: None,
        }
    }

    #[test]
    fn invalid_duplicate_candidates_are_rejected() {
        let config = RouteConfig {
            strategy: RouteStrategy::OrderedFallback,
            candidates: vec![candidate("p", "m", 1), candidate("p", "m", 1)],
        };
        assert_eq!(
            validate_route_config(&config),
            Err(RouteSelectionError::InvalidConfig)
        );
    }

    #[test]
    fn version_comparison_is_ascending() {
        assert_eq!(compare_route_versions(1, 2), Ordering::Less);
    }

    #[test]
    fn model_capability_filter_is_not_bypassed_by_route_weight() {
        let config = RouteConfig {
            strategy: RouteStrategy::OrderedFallback,
            candidates: vec![candidate("p", "m", 100)],
        };
        let model = ModelDescriptor {
            model_id: "m".to_owned(),
            provider_id: "p".to_owned(),
            provider_model_id: "m".to_owned(),
            display_name: "M".to_owned(),
            capabilities: ModelCapabilities::new([ModelCapability::Text]),
            max_input_tokens: None,
            max_output_tokens: None,
            lifecycle: CatalogLifecycle::Active,
            pricing_version: None,
        };
        let provider = ProviderDescriptor {
            provider_id: "p".to_owned(),
            display_name: "P".to_owned(),
            adapter: "mock".to_owned(),
            lifecycle: CatalogLifecycle::Active,
            endpoint_url: None,
        };
        let result = select_candidates(
            &config,
            &[model],
            &[provider],
            &CatalogPolicy::default(),
            &[],
            &["tools".to_owned()],
            1,
        );
        assert_eq!(result, Err(RouteSelectionError::UnsupportedCapability));
    }
}
