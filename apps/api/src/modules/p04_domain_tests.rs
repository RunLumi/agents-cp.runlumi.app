use std::collections::BTreeSet;

use super::catalog::{CatalogLifecycle, CatalogPolicy, ModelCapabilities, ModelCapability};
use super::credentials::{
    can_resolve_credential, CredentialMetadata, CredentialMode, CredentialOwnerType, CredentialStatus,
};
use super::inference::{
    AdapterErrorKind, AdapterStreamState, InferenceRequest, ProviderStreamEvent, ResponseLifecycle,
    RetryController, SseDecoder,
};
use super::routing::{
    select_candidates, HealthState, RouteCandidate, RouteConfig, RouteSelectionError, RouteStrategy,
};

fn id(prefix: &str, value: u8) -> String {
    format!("{prefix}_{:032x}", value as u32)
}

#[test]
fn catalog_capabilities_and_lifecycle_gate_new_routes() {
    let capabilities = ModelCapabilities::from_iter([
        ModelCapability::Text,
        ModelCapability::Tools,
        ModelCapability::Vision,
    ]);
    assert!(capabilities.contains(ModelCapability::Tools));
    assert!(!capabilities.contains(ModelCapability::Audio));
    assert!(CatalogLifecycle::Active.allows_new_routes());
    assert!(!CatalogLifecycle::Disabled.allows_new_routes());
}

#[test]
fn explicit_policy_lists_are_allowlists_and_missing_entries_are_denied() {
    let policy = CatalogPolicy {
        allowed_aliases: Some(BTreeSet::from(["coding-default".to_owned()])),
        allowed_models: Some(BTreeSet::from([id("mdl", 1)])),
        ..CatalogPolicy::default()
    };
    assert!(policy.allows_alias("coding-default"));
    assert!(!policy.allows_alias("coding-fast"));
    assert!(policy.allows_model(&id("mdl", 1)));
    assert!(!policy.allows_model(&id("mdl", 2)));
}

#[test]
fn credential_resolution_rejects_revoked_cross_user_and_local_only_handles() {
    let org_id = id("org", 1);
    let user_id = id("usr", 1);
    let other_user_id = id("usr", 2);
    let metadata = CredentialMetadata {
        credential_id: id("cred", 1),
        org_id: Some(org_id.clone()),
        owner_type: CredentialOwnerType::User,
        owner_user_id: Some(user_id.clone()),
        provider_id: id("prv", 1),
        label: "Coding key".to_owned(),
        status: CredentialStatus::Active,
        version: 1,
        fingerprint: "fp_1234".to_owned(),
        key_version: "v1".to_owned(),
        created_at: "2026-09-24T00:00:00.000Z".to_owned(),
        updated_at: "2026-09-24T00:00:00.000Z".to_owned(),
        last_used_at: None,
    };
    assert!(can_resolve_credential(
        &metadata,
        &org_id,
        &user_id,
        CredentialMode::OrderedFallback
    ));
    assert!(!can_resolve_credential(
        &metadata,
        &org_id,
        &other_user_id,
        CredentialMode::OrderedFallback
    ));
    let mut revoked = metadata.clone();
    revoked.status = CredentialStatus::Revoked;
    assert!(!can_resolve_credential(
        &revoked,
        &org_id,
        &user_id,
        CredentialMode::OrderedFallback
    ));
    let mut local = metadata;
    local.owner_type = CredentialOwnerType::LocalOnly;
    assert!(!can_resolve_credential(
        &local,
        &org_id,
        &user_id,
        CredentialMode::OrderedFallback
    ));
}

fn route_config() -> RouteConfig {
    RouteConfig {
        strategy: RouteStrategy::OrderedFallback,
        candidates: vec![
            RouteCandidate {
                provider_id: id("prv", 1),
                model_id: id("mdl", 1),
                weight: 70,
                timeout_ms: 1_000,
                max_retries: 1,
                credential_id: None,
            },
            RouteCandidate {
                provider_id: id("prv", 2),
                model_id: id("mdl", 2),
                weight: 30,
                timeout_ms: 1_000,
                max_retries: 0,
                credential_id: None,
            },
        ],
    }
}

fn model(id_value: &str, capabilities: &[ModelCapability]) -> super::catalog::ModelDescriptor {
    super::catalog::ModelDescriptor {
        model_id: id_value.to_owned(),
        provider_id: if id_value == id("mdl", 2) {
            id("prv", 2)
        } else {
            id("prv", 1)
        },
        provider_model_id: "upstream-model".to_owned(),
        display_name: "Model".to_owned(),
        capabilities: ModelCapabilities::from_iter(capabilities.iter().copied()),
        max_input_tokens: Some(8_000),
        max_output_tokens: Some(2_000),
        lifecycle: CatalogLifecycle::Active,
        pricing_version: Some("fixture-v1".to_owned()),
    }
}

fn provider(id_value: &str, lifecycle: CatalogLifecycle) -> super::catalog::ProviderDescriptor {
    super::catalog::ProviderDescriptor {
        provider_id: id_value.to_owned(),
        display_name: "Provider".to_owned(),
        adapter: "openai_compatible".to_owned(),
        lifecycle,
        endpoint_url: None,
    }
}

#[test]
fn selector_filters_capability_lifecycle_policy_and_health_before_ordering() {
    let config = route_config();
    let first = model(&id("mdl", 1), &[ModelCapability::Text]);
    let second = model(&id("mdl", 2), &[ModelCapability::Text]);
    let providers = vec![
        provider(&id("prv", 1), CatalogLifecycle::Active),
        provider(&id("prv", 2), CatalogLifecycle::Active),
    ];
    let health = vec![
        HealthState::ready(&id("prv", 1)),
        HealthState::cooling_down(&id("prv", 1), "2026-09-24T00:10:00.000Z"),
        HealthState::ready(&id("prv", 2)),
    ];
    let selected = select_candidates(
        &config,
        &[first.clone(), second.clone()],
        &providers,
        &CatalogPolicy::default(),
        &health,
        &["text".to_owned()],
        7,
    )
    .expect("selection should succeed");
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].provider_id, id("prv", 2));
    assert_eq!(selected[0].model_id, second.model_id);
}

#[test]
fn weighted_selection_is_deterministic_for_the_same_seed() {
    let mut config = route_config();
    config.strategy = RouteStrategy::WeightedHealthAware;
    let models = vec![
        model(&id("mdl", 1), &[ModelCapability::Text]),
        model(&id("mdl", 2), &[ModelCapability::Text]),
    ];
    let providers = vec![
        provider(&id("prv", 1), CatalogLifecycle::Active),
        provider(&id("prv", 2), CatalogLifecycle::Active),
    ];
    let first = select_candidates(
        &config,
        &models,
        &providers,
        &CatalogPolicy::default(),
        &[],
        &["text".to_owned()],
        42,
    )
    .unwrap();
    let second = select_candidates(
        &config,
        &models,
        &providers,
        &CatalogPolicy::default(),
        &[],
        &["text".to_owned()],
        42,
    )
    .unwrap();
    assert_eq!(first[0].model_id, second[0].model_id);
}

#[test]
fn selector_rejects_unsafe_or_empty_route_configs() {
    let mut config = route_config();
    config.candidates.clear();
    let error = select_candidates(
        &config,
        &[],
        &[],
        &CatalogPolicy::default(),
        &[],
        &[],
        1,
    )
    .expect_err("empty route must be rejected");
    assert_eq!(error, RouteSelectionError::NoCandidates);
}

fn request() -> InferenceRequest {
    InferenceRequest {
        model: "coding-default".to_owned(),
        messages: vec![super::inference::InferenceMessage::user("hello")],
        required_capabilities: vec![ModelCapability::Text],
        stream: true,
        max_output_tokens: Some(32),
        temperature: Some(0.2),
        tools: Vec::new(),
        project_id: None,
        session_id: None,
        run_id: None,
    }
}

#[test]
fn native_request_keeps_alias_and_scope_separate_from_provider_credentials() {
    let request = request();
    assert_eq!(request.model, "coding-default");
    assert!(request.stream);
    assert!(request.tools.is_empty());
    assert!(request.project_id.is_none());
}

#[test]
fn retry_controller_allows_fallback_only_before_output_commit() {
    let mut retry = RetryController::new(1, 1);
    retry.mark_dispatched();
    assert!(retry.can_retry());
    retry.mark_retryable_failure(AdapterErrorKind::ConnectionFailed);
    assert_eq!(retry.state(), ResponseLifecycle::NotDispatched);
    assert_eq!(retry.fallback_count(), 1);

    retry.mark_dispatched();
    retry.mark_stream_committed();
    assert!(!retry.can_retry());
    assert_eq!(retry.state(), ResponseLifecycle::StreamCommitted);
}

#[test]
fn retry_controller_does_not_retry_after_meaningful_output() {
    let mut retry = RetryController::new(0, 1);
    retry.mark_dispatched();
    retry.mark_stream_committed();
    retry.mark_retryable_failure(AdapterErrorKind::ConnectionFailed);
    assert_eq!(retry.state(), ResponseLifecycle::Failed);
    assert_eq!(retry.fallback_count(), 0);
}

#[test]
fn sse_decoder_handles_split_chunks_and_emits_typed_events() {
    let mut decoder = SseDecoder::new();
    let mut state = AdapterStreamState::default();
    let first = decoder.push(b"data: {\"choices\":[{\"delta\":{\"content\":\"hel\"}}]}\n\n", &mut state);
    assert!(matches!(first.as_slice(), [ProviderStreamEvent::TextDelta { .. }]));
    let second = decoder.push(b"data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\ndata: [DONE]\n\n", &mut state);
    assert!(second.iter().any(|event| matches!(event, ProviderStreamEvent::TextDelta { .. })));
    assert!(second.iter().any(|event| matches!(event, ProviderStreamEvent::Done)));
}

#[test]
fn adapter_error_taxonomy_never_exposes_upstream_body() {
    let error = super::inference::normalize_adapter_error(502, "secret upstream body");
    assert_eq!(error.kind, AdapterErrorKind::ProviderUnavailable);
    assert!(!error.to_string().contains("secret upstream body"));
}
