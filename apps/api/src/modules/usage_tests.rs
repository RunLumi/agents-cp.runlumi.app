use serde_json::json;

use super::*;

fn id(prefix: &str, value: u8) -> String {
    format!("{prefix}_{value:032x}")
}

fn pricing(version: &str) -> PricingVersion {
    PricingVersion::new("catalog", version, "2026-09-25T00:00:00.000Z").unwrap()
}

fn payload() -> BoundedPayload {
    BoundedPayload::from_value(&json!({
        "input_tokens": 12,
        "output_tokens": 4,
        "cached_tokens": 2,
        "provider_name": "fixture-provider",
        "prompt": "do not persist this",
        "response": {"text": "nor this"},
        "tool_arguments": {"path": "/private"},
        "headers": {"authorization": "Bearer secret"}
    }))
    .unwrap()
}

fn event(source: UsageSource) -> UsageEvent {
    let run_id = (source == UsageSource::Run).then(|| id("run", 1));
    UsageEvent::from_draft(UsageEventDraft {
        usage_event_id: id("use", 1),
        request_id: id("req", 1),
        org_id: id("org", 1),
        project_id: Some(id("prj", 1)),
        run_id,
        principal_user_id: id("usr", 1),
        session_id: Some(id("ses", 1)),
        device_id: Some(id("dvc", 1)),
        source,
        external_id: None,
        reconciliation_state: ReconciliationState::Pending,
        model_alias: "coding-default".to_owned(),
        route_version_id: id("rtv", 1),
        provider_id: id("prv", 1),
        model_id: id("mdl", 1),
        credential_id: None,
        input_tokens: Some(10),
        output_tokens: Some(3),
        cached_tokens: Some(1),
        provider_usage: Some(payload()),
        estimated_cost_minor: Some(7),
        actual_cost_minor: None,
        currency: Some("USD".to_owned()),
        pricing_version: Some("catalog-v1".to_owned()),
        budget_decision: "allow".to_owned(),
        ttft_ms: Some(4),
        total_latency_ms: Some(20),
        created_at: "2026-09-25T00:00:00.000Z".to_owned(),
    })
    .unwrap()
}

fn request(event: &UsageEvent, cost: i64, cost_id: &str) -> ReconciliationRequest {
    ReconciliationRequest::new_with_cost_record_id(
        cost_id,
        event.reconciliation_identity(),
        Some(cost),
        Some(payload()),
        Some(pricing("catalog-v1")),
        Some("USD".to_owned()),
        "2026-09-25T00:01:00.000Z",
    )
    .unwrap()
}

fn cost_draft(event: &UsageEvent, cost: i64, version: &str) -> CostRecordDraft {
    CostRecordDraft {
        cost_record_id: id("cost", 1),
        usage_event_id: event.usage_event_id.clone(),
        org_id: event.org_id.clone(),
        pricing: pricing(version),
        input_tokens: event.input_tokens,
        output_tokens: event.output_tokens,
        cached_tokens: event.cached_tokens,
        cost_minor: cost,
        currency: "USD".to_owned(),
        calculation_kind: CostCalculationKind::Estimated,
        recalculated_from_cost_record_id: None,
        created_at: "2026-09-25T00:00:00.000Z".to_owned(),
    }
}

#[test]
fn source_and_reconciliation_values_have_stable_wire_names() {
    assert_eq!(UsageSource::Inference.as_str(), "inference");
    assert_eq!(UsageSource::Run.as_str(), "run");
    assert_eq!(ReconciliationState::default().as_str(), "recorded");
    assert_eq!(ReconciliationState::Pending.as_str(), "pending");
    assert_eq!(ReconciliationState::Reconciled.as_str(), "reconciled");
    assert_eq!(ReconciliationState::Conflict.as_str(), "conflict");
    assert_eq!(CostCalculationKind::Recalculated.as_str(), "recalculated");
    assert_eq!(
        serde_json::to_value(UsageSource::Run).unwrap(),
        json!("run")
    );
}

#[test]
fn raw_usage_is_attributed_and_keeps_p04_shape() {
    let event = event(UsageSource::Run);
    assert_eq!(event.source, UsageSource::Run);
    assert_eq!(event.org_id, id("org", 1));
    assert_eq!(event.project_id.as_deref(), Some(id("prj", 1).as_str()));
    assert_eq!(event.run_id.as_deref(), Some(id("run", 1).as_str()));
    assert_eq!(event.principal_user_id, id("usr", 1));
    assert_eq!(event.request_id, id("req", 1));
    assert_eq!(event.input_tokens, Some(10));
    assert_eq!(event.cached_tokens, Some(1));
    assert!(
        event
            .provider_usage_json()
            .unwrap()
            .unwrap()
            .contains("[redacted]")
    );

    let encoded = serde_json::to_value(&event).unwrap();
    let decoded: UsageEvent = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(decoded, event);

    let mut invalid = encoded;
    invalid["input_tokens"] = json!(-1);
    assert!(serde_json::from_value::<UsageEvent>(invalid).is_err());
}

#[test]
fn normalized_projection_accepts_run_only_usage() {
    let projection = UsageEventProjection {
        event_id: id("rue", 1),
        request_id: None,
        run_id: Some(id("run", 1)),
        org_id: id("org", 1),
        project_id: Some(id("prj", 1)),
        principal_user_id: id("usr", 1),
        session_id: None,
        device_id: Some(id("dvc", 1)),
        source: UsageSource::Run,
        external_id: None,
        reconciliation_state: ReconciliationState::Recorded,
        model_alias: None,
        input_tokens: Some(2),
        output_tokens: Some(1),
        cached_tokens: None,
        provider_usage: Some(payload()),
        estimated_cost_minor: Some(1),
        actual_cost_minor: None,
        currency: Some("USD".to_owned()),
        pricing_version: Some("catalog-v1".to_owned()),
        budget_decision: "not_applicable".to_owned(),
        created_at: "2026-09-25T00:00:00.000Z".to_owned(),
    };
    projection.validate().unwrap();
    assert_eq!(
        projection.reconciliation_identity().run_id.as_deref(),
        Some(id("run", 1).as_str())
    );
    assert_eq!(projection.usage_event_id(), id("rue", 1));
    let mut legacy_wire = serde_json::to_value(&projection).unwrap();
    let provider_json = legacy_wire
        .as_object_mut()
        .unwrap()
        .remove("provider_usage")
        .unwrap();
    legacy_wire["provider_usage_json"] = json!(provider_json.to_string());
    let decoded: UsageEventProjection = serde_json::from_value(legacy_wire).unwrap();
    assert_eq!(decoded, projection);

    let request = ReconciliationRequest::new_with_cost_record_id(
        id("rcost", 1),
        projection.reconciliation_identity(),
        Some(2),
        Some(payload()),
        Some(pricing("catalog-v1")),
        Some("USD".to_owned()),
        "2026-09-25T00:01:00.000Z",
    )
    .unwrap();
    let outcome = reconcile_usage(&projection, None, &request).unwrap();
    let ReconciliationOutcome::Apply {
        cost_record: Some(cost),
        ..
    } = outcome
    else {
        panic!("run projection should create an actual cost record");
    };
    assert_eq!(cost.usage_event_id, projection.event_id);
    assert_eq!(cost.org_id, projection.org_id);
}

#[test]
fn redaction_removes_content_and_bounds_provider_metadata() {
    let raw = json!({
        "input_tokens": 12,
        "output_tokens": 4,
        "provider_name": "fixture",
        "prompt": "secret prompt",
        "response": {"content": "secret response"},
        "tool_arguments": {"command": "secret command"},
        "nested": {"api_key": "secret-key", "status": "ok"},
        "array": ["secret text", 7]
    });
    let redacted = redact_payload(&raw).unwrap();
    assert_eq!(redacted["input_tokens"], 12);
    assert_eq!(redacted["provider_name"], "fixture");
    assert_eq!(redacted["prompt"], REDACTED_VALUE);
    assert_eq!(redacted["response"], REDACTED_VALUE);
    assert_eq!(redacted["tool_arguments"], REDACTED_VALUE);
    assert_eq!(redacted["nested"]["api_key"], REDACTED_VALUE);
    assert_eq!(redacted["nested"]["status"], "ok");
    assert_eq!(redacted["array"][0], REDACTED_VALUE);
    assert_eq!(redacted["array"][1], 7);

    let too_large = json!({
        "input_tokens": 1,
        "blob": "x".repeat(MAX_RAW_PAYLOAD_BYTES)
    });
    assert_eq!(
        redact_payload(&too_large),
        Err(UsageModelError::PayloadTooLarge)
    );

    let debug = format!("{:?}", payload());
    assert!(!debug.contains("secret"));
    assert!(debug.contains(REDACTED_VALUE));
}

#[test]
fn provider_usage_must_be_an_object_and_is_bounded_on_deserialization() {
    assert_eq!(
        redact_provider_usage(json!(["not", "an", "object"])),
        Err(UsageModelError::InvalidField("provider_usage"))
    );
    let serialized = serde_json::to_string(&payload()).unwrap();
    let decoded: BoundedPayload = serde_json::from_str(&serialized).unwrap();
    assert_eq!(decoded, payload());
    assert!(decoded.encoded_len() <= MAX_PAYLOAD_BYTES);
}

#[test]
fn pricing_recalculation_appends_and_never_mutates_history() {
    let event = event(UsageSource::Inference);
    let original = CostRecord::estimated(cost_draft(&event, 7, "catalog-v1")).unwrap();
    let recalculated = original
        .recalculate(
            id("cost", 2),
            pricing("catalog-v2"),
            9,
            "USD",
            "2026-10-01T00:00:00.000Z",
        )
        .unwrap();

    assert_eq!(original.pricing_version, "catalog-v1");
    assert_eq!(original.cost_minor, 7);
    assert_eq!(original.calculation_kind, CostCalculationKind::Estimated);
    assert_eq!(recalculated.pricing_version, "catalog-v2");
    assert_eq!(recalculated.cost_minor, 9);
    assert_eq!(
        recalculated.calculation_kind,
        CostCalculationKind::Recalculated
    );
    assert_eq!(
        recalculated.recalculated_from_cost_record_id.as_deref(),
        Some(original.cost_record_id.as_str())
    );
    assert!(recalculated.is_recalculated());

    assert_eq!(
        original.recalculate(
            id("cost", 3),
            pricing("catalog-v1"),
            10,
            "USD",
            "2026-10-01T00:00:00.000Z"
        ),
        Err(UsageModelError::InvalidField("pricing_version"))
    );
}

#[test]
fn cost_record_rejects_negative_money_and_invalid_currency() {
    let event = event(UsageSource::Inference);
    let mut draft = cost_draft(&event, 7, "catalog-v1");
    draft.cost_minor = -1;
    assert_eq!(
        CostRecord::estimated(draft),
        Err(UsageModelError::InvalidField("cost_minor"))
    );

    let mut draft = cost_draft(&event, 7, "catalog-v1");
    draft.currency = "usd".to_owned();
    assert_eq!(
        CostRecord::estimated(draft),
        Err(UsageModelError::InvalidField("currency"))
    );
}

#[test]
fn reconciliation_is_idempotent_and_replays_without_a_second_cost_row() {
    let mut event = event(UsageSource::Inference);
    event.external_id = Some("provider-external".to_owned());
    let first_request = request(&event, 11, &id("cost", 10));
    let first = reconcile_usage(&event, None, &first_request).unwrap();
    let ReconciliationOutcome::Apply {
        reconciliation,
        cost_record: Some(cost),
    } = first
    else {
        panic!("first reconciliation should append one cost row");
    };
    assert_eq!(reconciliation.state, ReconciliationState::Reconciled);
    assert_eq!(cost.calculation_kind, CostCalculationKind::Actual);
    assert_eq!(cost.cost_minor, 11);
    assert_eq!(cost.usage_event_id, event.usage_event_id);

    let mut retry_identity = event.reconciliation_identity();
    retry_identity.external_id = None;
    let retry_request = ReconciliationRequest::new_with_cost_record_id(
        id("cost", 99),
        retry_identity,
        Some(11),
        Some(payload()),
        Some(pricing("catalog-v1")),
        Some("USD".to_owned()),
        "2026-09-25T00:02:00.000Z",
    )
    .unwrap();
    let replay = reconcile_usage(&event, Some(&reconciliation), &retry_request).unwrap();
    let ReconciliationOutcome::Replay {
        cost_record_id,
        reconciliation: replayed,
    } = replay
    else {
        panic!("same payload must replay");
    };
    assert_eq!(cost_record_id.as_deref(), Some(id("cost", 10).as_str()));
    assert_eq!(replayed, reconciliation);
}

#[test]
fn conflicting_reconciliation_returns_stable_reason() {
    let event = event(UsageSource::Inference);
    let first_request = request(&event, 11, &id("cost", 10));
    let first = reconcile_usage(&event, None, &first_request).unwrap();
    let reconciliation = first.reconciliation().clone();

    let conflicting = request(&event, 12, &id("cost", 11));
    let error = reconcile_usage(&event, Some(&reconciliation), &conflicting).unwrap_err();
    assert_eq!(error.code(), "usage_reconciliation_conflict");
    assert_eq!(
        error,
        UsageModelError::ReconciliationConflict(ReconciliationConflictReason::ActualCostMismatch)
    );
}

#[test]
fn reconciliation_pending_projection_is_idempotent_but_not_reapplied() {
    let event = event(UsageSource::Inference);
    let request = request(&event, 11, &id("cost", 10));
    let pending =
        UsageReconciliation::pending_for_request(&event.usage_event_id, &event.org_id, &request)
            .unwrap();
    let outcome = reconcile_usage(&event, Some(&pending), &request).unwrap();
    assert!(matches!(outcome, ReconciliationOutcome::InProgress { .. }));

    let mut different = request.clone();
    different.actual_cost_minor = Some(12);
    assert_eq!(
        reconcile_usage(&event, Some(&pending), &different),
        Err(UsageModelError::ReconciliationConflict(
            ReconciliationConflictReason::ActualCostMismatch
        ))
    );
}

#[test]
fn provider_only_reconciliation_does_not_fabricate_a_cost_record() {
    let event = event(UsageSource::Run);
    let identity = event.reconciliation_identity();
    let request = ReconciliationRequest::new(
        identity,
        None,
        Some(payload()),
        None,
        None,
        "2026-09-25T00:01:00.000Z",
    )
    .unwrap();
    let outcome = reconcile_usage(&event, None, &request).unwrap();
    let ReconciliationOutcome::Apply { cost_record, .. } = outcome else {
        panic!("provider metadata should reconcile");
    };
    assert!(cost_record.is_none());
}

#[test]
fn reconciliation_never_accepts_another_tenant_projection() {
    let event = event(UsageSource::Inference);
    let identity = event.reconciliation_identity();
    let projection =
        UsageReconciliation::pending(&event.usage_event_id, id("org", 2), identity.clone())
            .unwrap();
    let request = request(&event, 11, &id("cost", 10));
    assert_eq!(
        reconcile_usage(&event, Some(&projection), &request),
        Err(UsageModelError::ReconciliationConflict(
            ReconciliationConflictReason::TenantMismatch
        ))
    );
}

#[test]
fn rollup_normalization_uses_selected_cost_record_and_checks_overflow() {
    let event = event(UsageSource::Inference);
    let cost = CostRecord::actual({
        let mut draft = cost_draft(&event, 13, "catalog-v1");
        draft.calculation_kind = CostCalculationKind::Actual;
        draft
    })
    .unwrap();
    let input = normalize_rollup_input(
        &event,
        Some(&cost),
        RollupPeriod::Hour,
        "2026-09-25T00:00:00.000Z",
        "2026-09-25T01:00:00.000Z",
    )
    .unwrap();
    assert_eq!(input.input_tokens, 10);
    assert_eq!(input.output_tokens, 3);
    assert_eq!(input.cost_minor, 13);
    assert_eq!(input.currency.as_deref(), Some("USD"));

    let mut rollup = UsageRollup::new(id("url", 1), input.clone()).unwrap();
    rollup.add(&input).unwrap();
    assert_eq!(rollup.event_count, 2);
    assert_eq!(rollup.cost_minor, 26);

    let mut maximum = input.clone();
    maximum.cost_minor = i64::MAX;
    let mut overflow = UsageRollup::new(id("url", 2), maximum.clone()).unwrap();
    let before = overflow.clone();
    assert_eq!(
        overflow.add(&maximum),
        Err(UsageModelError::InvalidField("rollup_cost_minor"))
    );
    assert_eq!(overflow, before);
}

#[test]
fn raw_event_debug_does_not_print_provider_content() {
    let event = event(UsageSource::Inference);
    let debug = format!("{event:?}");
    assert!(!debug.contains("do not persist this"));
    assert!(debug.contains("BoundedPayload"));
}
