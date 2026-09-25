//! Behavioural evidence for the F20 acceptance criteria.
//!
//! The registry coverage tests are the acceptance evidence for "new persistent
//! schema cannot be considered complete without a data-class declaration":
//! [`gate_classes_are_all_registered`] names every class from both `P06-CG.md`
//! governance matrices and the P01–P05 table, and
//! [`every_registered_class_declares_all_six_attributes`] proves each row is
//! complete and internally consistent. If a new class is added without a
//! declaration, or a declaration is removed, one of those tests fails.
//!
//! The last group reads the frozen coordinator fixture
//! (`docs/implementation/fixtures/p06-contracts-v1.json`) directly, so the
//! domain is checked against the same contract the backend and frontend agents
//! are building from rather than against a restatement of it.

use super::deletion::{
    DISCLOSURES, DeletionError, DeletionInventoryEntry, DeletionJobState, DeletionPlanner,
    DeletionSkipReason, DeletionStep, DeletionStepState, DeletionTarget, FenceAction,
    FencedWorkflow, OrgMembershipRef, OrgRole, PENDING_REFERENCE_SYSTEMS,
    REFERENCE_SYSTEM_ABSENT_REASON, ReferenceCoverage, ReferenceKind, ResumeAuthorization,
    StepTransition, decide_fence, ensure_no_scope_conflict, evaluate_account_deletion_exit,
    reference_coverage, verify_account_deletion_request,
};
use super::export::{
    DELETION_CONFIRMATION_PHRASE, DownloadAuthorization, EXPORT_CONFIRMATION_PHRASE,
    ExportCategory, ExportError, ExportFormat, ExportJobState, ExportManifest, ExportRequest,
    ExportScope, MAX_EXPORT_EXPIRY_SECONDS, TypedConfirmation, authorize_download,
    manifest_is_stable,
};
use super::logging::{
    FieldClass, LoggingError, LoggingMode, LoggingModeChange, LoggingPolicy, LoggingRule,
    METADATA_FIELD_ALLOWLIST, REDACTED_EXCERPT_FIELD_ALLOWLIST, classify_field,
};
use super::registry::{
    DataClass, DataClassRecord, DeletionBehavior, ExportBehavior, MAX_DATA_CLASS_LEN, OwnerScope,
    Sensitivity, all_classes, class_set, deletion_reachable_classes, exportable_classes,
    lookup_by_key, registry,
};
use super::retention::{
    AuditedOverride, BackupLifecycle, BaselineRetention, HoldScope, LegalHold,
    MAX_RETENTION_SECONDS, RetentionAnchor, RetentionDecision, RetentionDuration, RetentionError,
    RetentionOverride, RetentionPolicy, RetentionReason, RetentionSource, RetentionWindow,
    baseline_retention, decide,
};

/// A fixed logical instant so every assertion is deterministic.
const NOW: u64 = 1_789_000_000;
const DAY: u64 = 86_400;

fn class(key: &str) -> DataClass {
    DataClass::parse(key).expect("valid registry class key")
}

fn record(key: &str) -> DataClassRecord {
    lookup_by_key(key).expect("registered class")
}

// ===========================================================================
// Registry completeness — the F20-001 acceptance evidence
// ===========================================================================

/// Every data class named by the `P06-CG.md` governance matrices and the
/// existing P01–P05 class table. A class missing from the registry fails here.
const GATE_CLASSES: [&str; 70] = [
    // P06 table-level governance map.
    "automation_definition",
    "schedule_rule",
    "occurrence",
    "execution_lease",
    "occurrence_attempt",
    "automation_run_link",
    "webhook_endpoint",
    "webhook_secret",
    "webhook_delivery",
    "webhook_delivery_attempt",
    "notification_preference",
    "notification",
    "notification_delivery",
    "plan",
    "plan_entitlement",
    "billing_account",
    "subscription",
    "subscription_event",
    "provider_entitlement_projection",
    "entitlement_definition",
    "entitlement_grant",
    "license_snapshot",
    "license_state",
    "license_signing_key",
    "data_governance_policy",
    "data_class_registry",
    "export_job",
    "export_artifact",
    "export_download_grant",
    "deletion_job",
    "deletion_step",
    "deletion_certificate",
    "queue_job_envelope",
    "provider_sync_state",
    "idempotency_record",
    // Existing P01-P05 classes.
    "identity",
    "login_session",
    "passkey_authenticator",
    "organization",
    "membership",
    "invitation",
    "team",
    "device_enrollment",
    "device",
    "workspace_binding",
    "provider",
    "model",
    "model_route",
    "credential",
    "policy_snapshot",
    "policy_ack",
    "tool_policy",
    "inference_request",
    "usage_event",
    "cost_record",
    "budget",
    "rate_limit_policy",
    "agent_definition",
    "agent_session",
    "run",
    "run_event",
    "tool_call",
    "approval_request",
    "artifact_ref",
    "artifact",
    "audit_security_event",
    "outbox_event",
    "upstream_provider_data",
    "secret",
    // F20 data class 10: operational logs/traces.
    "operational_log",
];

#[test]
fn gate_classes_are_all_registered() {
    let registered = class_set();
    let missing: Vec<&str> = GATE_CLASSES
        .iter()
        .copied()
        .filter(|key| !registered.contains(&class(key)))
        .collect();
    assert!(
        missing.is_empty(),
        "data classes named by the gate are not registered: {missing:?}"
    );
}

#[test]
fn registry_has_no_duplicate_or_underspecified_class_keys() {
    let keys = all_classes();
    let unique: std::collections::BTreeSet<DataClass> = keys.iter().cloned().collect();
    assert_eq!(
        keys.len(),
        unique.len(),
        "duplicate class key in the registry"
    );
    for key in &keys {
        assert!(!key.as_str().is_empty());
        assert!(key.as_str().len() <= MAX_DATA_CLASS_LEN);
    }
}

/// The six F20-001 attributes are non-optional on `DataClassRecord`, so this
/// test proves the cross-attribute rules and that the count matches the table.
#[test]
fn every_registered_class_declares_all_six_attributes() {
    let records = registry();
    assert_eq!(records.len(), super::registry::CLASS_COUNT);
    assert!(records.len() >= GATE_CLASSES.len());
    for entry in &records {
        entry
            .validate()
            .unwrap_or_else(|error| panic!("{} is incomplete: {error}", entry.class));
        // Reading each attribute through its accessor keeps the "declared"
        // claim honest: none of these can be absent.
        assert!(!entry.class().as_str().is_empty());
        assert!(!entry.description().is_empty());
        let _ = (
            entry.sensitivity(),
            entry.owner_scope(),
            entry.default_retention(),
            entry.export_behavior(),
            entry.deletion_behavior(),
            entry.logging(),
        );
    }
}

#[test]
fn class_keys_are_validated_snake_case() {
    for invalid in [
        "",
        "Occurrence",
        "occurrence ",
        "occurrence row",
        "_occurrence",
        "occurrence_",
        "occurrence__attempt",
        "occurrence-attempt",
        "occurrence/attempt",
        "occurrénce",
    ] {
        assert!(DataClass::parse(invalid).is_err(), "accepted {invalid:?}");
    }
    assert!(DataClass::parse(&"a".repeat(MAX_DATA_CLASS_LEN + 1)).is_err());
    assert!(DataClass::parse(&"a".repeat(MAX_DATA_CLASS_LEN)).is_ok());

    let parsed = DataClass::parse("automation_occurrence_attempts").unwrap();
    assert_eq!(parsed.as_str(), "automation_occurrence_attempts");
    assert_eq!(parsed.to_string(), "automation_occurrence_attempts");
    assert_eq!(
        serde_json::to_string(&parsed).unwrap(),
        "\"automation_occurrence_attempts\""
    );
    assert!(lookup_by_key("not_a_registered_class").is_err());
}

#[test]
fn secret_material_is_never_exported_and_is_crypto_erased() {
    for key in ["secret", "webhook_secret"] {
        let entry = record(key);
        assert_eq!(entry.sensitivity, Sensitivity::Secret, "{key}");
        assert_eq!(entry.export_behavior, ExportBehavior::Never, "{key}");
        assert_eq!(
            entry.deletion_behavior,
            DeletionBehavior::CryptoErase,
            "{key}"
        );
        assert!(!entry.is_exportable());
    }
    // The secret class is not loggable at all, not even as an identifier.
    let secret = record("secret");
    assert_eq!(secret.logging, LoggingRule::None);
    assert_eq!(secret.logging.max_mode(), None);
    // A destroyed passkey leaves nothing that decrypts.
    assert_eq!(
        record("passkey_authenticator").deletion_behavior,
        DeletionBehavior::CryptoErase
    );
}

/// The exact set of non-exportable classes. `P06-CG.md` says queue job
/// envelopes, outbox rows, operational logs, and login sessions are "not
/// exported"/"not user content export", so the registry declares them `never`.
/// This test pins that list: adding a class to it is a reviewed change, and it
/// is the list the persistence guard has to accommodate.
#[test]
fn documented_non_exportable_classes() {
    let records = registry();
    let mut never: Vec<&str> = records
        .iter()
        .filter(|entry| entry.export_behavior == ExportBehavior::Never)
        .map(|entry| entry.class.as_str())
        .collect();
    never.sort_unstable();
    assert_eq!(
        never,
        vec![
            "idempotency_record",
            "login_session",
            "operational_log",
            "outbox_event",
            "queue_job_envelope",
            "secret",
            "webhook_secret",
        ]
    );
    let exportable = exportable_classes();
    // The artifact *object* is not a class; only its sanitized metadata is
    // exportable, and the content is delivered through an expiring download.
    assert!(exportable.contains(&class("export_artifact")));
    assert!(exportable.contains(&class("usage_event")));
    assert!(!exportable.contains(&class("secret")));
}

#[test]
fn upstream_provider_data_is_never_claimed_as_lumi_deletable() {
    let external: Vec<DataClassRecord> = registry()
        .into_iter()
        .filter(|entry| entry.owner_scope == OwnerScope::External)
        .collect();
    assert!(
        external
            .iter()
            .any(|entry| entry.class.as_str() == "upstream_provider_data"),
        "the upstream provider class must be registered"
    );
    for entry in external {
        assert!(entry.is_legally_retained(), "{}", entry.class);
        assert!(
            !entry.deletion_behavior.is_actionable(),
            "{} claims an actionable Lumi deletion",
            entry.class
        );
    }
    assert_eq!(
        record("upstream_provider_data").deletion_behavior,
        DeletionBehavior::RetainLegalOnly
    );
}

#[test]
fn audit_and_billing_records_are_minimized_or_tombstoned_never_dropped() {
    for key in [
        "audit_security_event",
        "usage_event",
        "cost_record",
        "subscription",
        "subscription_event",
        "deletion_certificate",
    ] {
        let entry = lookup_by_key(key).expect("registered class");
        assert!(
            matches!(
                entry.deletion_behavior,
                DeletionBehavior::Minimize
                    | DeletionBehavior::Tombstone
                    | DeletionBehavior::RetainLegalOnly
            ),
            "{key} is {:?}",
            entry.deletion_behavior
        );
        assert!(
            entry.deletion_behavior.retains_record(),
            "{key} would be physically dropped"
        );
    }
    assert_eq!(
        record("audit_security_event").deletion_behavior,
        DeletionBehavior::RetainLegalOnly
    );
}

#[test]
fn registry_wire_values_match_the_persistence_layer_enums() {
    for entry in registry() {
        assert_eq!(
            Sensitivity::parse(entry.sensitivity.as_str()),
            Some(entry.sensitivity),
            "{}",
            entry.class
        );
        assert_eq!(
            OwnerScope::parse(entry.owner_scope.as_str()),
            Some(entry.owner_scope),
            "{}",
            entry.class
        );
        assert_eq!(
            ExportBehavior::parse(entry.export_behavior.as_str()),
            Some(entry.export_behavior),
            "{}",
            entry.class
        );
        assert_eq!(
            DeletionBehavior::parse(entry.deletion_behavior.as_str()),
            Some(entry.deletion_behavior),
            "{}",
            entry.class
        );
        assert_eq!(
            LoggingRule::parse(entry.logging.as_str()),
            Some(entry.logging),
            "{}",
            entry.class
        );
        assert!(
            entry
                .default_retention
                .bound_seconds()
                .is_none_or(|seconds| seconds <= MAX_RETENTION_SECONDS),
            "{}",
            entry.class
        );
    }
}

// ===========================================================================
// Retention and legal hold
// ===========================================================================

#[test]
fn baseline_values_match_the_frozen_gate() {
    assert_eq!(
        BaselineRetention::AutomationProjection.as_str(),
        "automation_projection"
    );
    assert_eq!(
        RetentionDuration::from_days_unchecked(90).seconds(),
        90 * DAY
    );
    assert_eq!(
        RetentionDuration::from_days_unchecked(30).seconds(),
        30 * DAY
    );
    assert_eq!(
        RetentionDuration::from_seconds_unchecked(86_400).seconds(),
        DAY
    );
    assert_eq!(
        RetentionDuration::from_days_unchecked(365).seconds(),
        365 * DAY
    );
    assert_eq!(
        RetentionDuration::from_days_unchecked(35).seconds(),
        35 * DAY
    );
    // Seven years is 2555 days in the gate, not 2557.
    assert_eq!(
        RetentionDuration::from_days_unchecked(2_555).seconds(),
        2_555 * DAY
    );

    assert_eq!(
        baseline_retention(BaselineRetention::AutomationProjection),
        RetentionWindow::AfterAnchor {
            anchor: RetentionAnchor::TerminalState,
            grace: RetentionDuration::from_days_unchecked(90),
        }
    );
    assert_eq!(
        baseline_retention(BaselineRetention::DeliveryProjection),
        RetentionWindow::AfterAnchor {
            anchor: RetentionAnchor::DeliveryCompleted,
            grace: RetentionDuration::from_days_unchecked(30),
        }
    );
    assert_eq!(
        baseline_retention(BaselineRetention::QueueJobProjection),
        RetentionWindow::AfterAnchor {
            anchor: RetentionAnchor::TerminalState,
            grace: RetentionDuration::from_days_unchecked(90),
        }
    );
    assert_eq!(
        baseline_retention(BaselineRetention::ExportJobMetadata),
        RetentionWindow::Bounded(RetentionDuration::from_days_unchecked(90))
    );
    assert_eq!(
        baseline_retention(BaselineRetention::ExportArtifact),
        RetentionWindow::Bounded(RetentionDuration::from_seconds_unchecked(86_400))
    );
    assert_eq!(
        baseline_retention(BaselineRetention::LicenseEntitlementMetadata),
        RetentionWindow::AfterAnchor {
            anchor: RetentionAnchor::LicenseOfflineValidUntil,
            grace: RetentionDuration::from_days_unchecked(30),
        }
    );
    assert_eq!(
        baseline_retention(BaselineRetention::DeletionStep),
        RetentionWindow::AfterAnchor {
            anchor: RetentionAnchor::DeletionJobCompleted,
            grace: RetentionDuration::from_days_unchecked(90),
        }
    );
    assert_eq!(
        baseline_retention(BaselineRetention::DeletionCertificate),
        RetentionWindow::Bounded(RetentionDuration::from_days_unchecked(365))
    );
    assert_eq!(
        baseline_retention(BaselineRetention::OperationalLog),
        RetentionWindow::Bounded(RetentionDuration::from_days_unchecked(30))
    );
    assert_eq!(
        baseline_retention(BaselineRetention::BackupLifecycle),
        RetentionWindow::Bounded(RetentionDuration::from_days_unchecked(35))
    );
    assert_eq!(
        baseline_retention(BaselineRetention::AuditSecurityEvent),
        RetentionWindow::Bounded(RetentionDuration::from_days_unchecked(365))
    );
    assert_eq!(
        baseline_retention(BaselineRetention::FinancialRecord),
        RetentionWindow::Bounded(RetentionDuration::from_days_unchecked(2_555))
    );
    assert_eq!(
        BackupLifecycle::default().as_str(),
        "platform_35_day_expiry"
    );
    assert_eq!(
        BackupLifecycle::PlatformExpiry.retention(),
        RetentionWindow::Bounded(RetentionDuration::from_days_unchecked(35))
    );
    assert_eq!(
        BackupLifecycle::parse("platform_no_backup"),
        Some(BackupLifecycle::PlatformNoBackup)
    );
    for kind in [
        BaselineRetention::AutomationProjection,
        BaselineRetention::FinancialRecord,
        BaselineRetention::ExportArtifact,
    ] {
        assert_eq!(
            BaselineRetention::parse(kind.as_str()),
            Some(kind),
            "{kind:?}"
        );
    }
}

#[test]
fn registry_defaults_use_the_frozen_baselines() {
    let automation_projection = [
        "occurrence",
        "execution_lease",
        "automation_run_link",
        "queue_job_envelope",
    ];
    for key in automation_projection {
        let window = record(key).default_retention;
        assert_eq!(
            window,
            RetentionWindow::AfterAnchor {
                anchor: RetentionAnchor::TerminalState,
                grace: RetentionDuration::from_days_unchecked(90),
            },
            "{key}"
        );
    }
    for key in [
        "webhook_delivery",
        "webhook_delivery_attempt",
        "notification",
        "notification_delivery",
    ] {
        assert_eq!(
            record(key).default_retention,
            RetentionWindow::AfterAnchor {
                anchor: RetentionAnchor::DeliveryCompleted,
                grace: RetentionDuration::from_days_unchecked(30),
            },
            "{key}"
        );
    }
    assert_eq!(
        record("export_artifact").default_retention,
        RetentionWindow::Bounded(RetentionDuration::from_seconds_unchecked(86_400))
    );
    assert_eq!(
        record("export_job").default_retention,
        RetentionWindow::Bounded(RetentionDuration::from_days_unchecked(90))
    );
    assert_eq!(
        record("deletion_step").default_retention,
        RetentionWindow::AfterAnchor {
            anchor: RetentionAnchor::DeletionJobCompleted,
            grace: RetentionDuration::from_days_unchecked(90),
        }
    );
    assert_eq!(
        record("deletion_certificate").default_retention,
        RetentionWindow::Bounded(RetentionDuration::from_days_unchecked(365))
    );
    for key in ["license_snapshot", "license_state", "entitlement_grant"] {
        assert!(
            !record(key).default_retention.is_lifecycle(),
            "{key} must have a bounded window"
        );
    }
    assert_eq!(
        record("license_snapshot").default_retention,
        RetentionWindow::AfterAnchor {
            anchor: RetentionAnchor::LicenseOfflineValidUntil,
            grace: RetentionDuration::from_days_unchecked(30),
        }
    );
    for key in [
        "usage_event",
        "cost_record",
        "subscription",
        "subscription_event",
    ] {
        assert_eq!(
            record(key).default_retention,
            RetentionWindow::Bounded(RetentionDuration::from_days_unchecked(2_555)),
            "{key}"
        );
    }
    assert_eq!(
        record("audit_security_event").default_retention,
        RetentionWindow::Bounded(RetentionDuration::from_days_unchecked(365))
    );
    assert_eq!(
        record("operational_log").default_retention,
        RetentionWindow::Bounded(RetentionDuration::from_days_unchecked(30))
    );
    // "Until deletion" classes have no expiry at all, not a very long one.
    for key in ["automation_definition", "organization", "webhook_secret"] {
        assert!(record(key).default_retention.is_lifecycle(), "{key}");
    }
}

#[test]
fn policy_may_shorten_retention() {
    let entry = record("occurrence");
    let terminal = NOW - DAY;
    let mut policy = RetentionPolicy::new();
    policy
        .set_override(
            entry.class.clone(),
            RetentionOverride::shorten_to(RetentionWindow::Bounded(
                RetentionDuration::from_days_unchecked(7),
            )),
        )
        .unwrap();

    let decision = decide(&entry, &policy, NOW, Some(terminal), None).expect("shortening allowed");
    assert_eq!(decision.expire_at, Some(terminal + 7 * DAY));
    assert_eq!(decision.source, RetentionSource::PolicyOverride);
    assert_eq!(decision.reason, RetentionReason::PolicyShortened);
    assert!(!decision.hold_applies);
}

#[test]
fn policy_may_not_extend_past_the_legal_maximum_without_an_audited_override() {
    let entry = record("occurrence");
    let terminal = NOW - DAY;
    // The operational ceiling for job/delivery projections is one year.
    let beyond_ceiling = RetentionWindow::Bounded(RetentionDuration::from_days_unchecked(400));
    let mut policy = RetentionPolicy::new();
    policy
        .set_override(
            entry.class.clone(),
            RetentionOverride::shorten_to(beyond_ceiling),
        )
        .unwrap();
    assert_eq!(
        decide(&entry, &policy, NOW, Some(terminal), None),
        Err(RetentionError::OverLegalMaximum)
    );
    assert_eq!(
        RetentionError::OverLegalMaximum.code(),
        "data_policy_retention_over_legal_maximum"
    );

    // The same window is accepted with an audited, attributed override.
    let audited = AuditedOverride::new("usr_operator", "evt_audit_correlation").unwrap();
    policy
        .set_override(
            entry.class.clone(),
            RetentionOverride::audited(beyond_ceiling, audited),
        )
        .unwrap();
    let decision = decide(&entry, &policy, NOW, Some(terminal), None).expect("audited override");
    assert_eq!(decision.expire_at, Some(terminal + 400 * DAY));
    assert_eq!(decision.source, RetentionSource::AuditedPolicyOverride);
    assert_eq!(decision.reason, RetentionReason::PolicyExtendedAudited);

    // An unattributed override is not an override.
    assert!(AuditedOverride::new("", "evt_audit").is_err());
    assert!(AuditedOverride::new("usr_operator", "  ").is_err());
}

#[test]
fn extension_within_the_legal_maximum_is_allowed_and_flagged() {
    let entry = record("occurrence");
    let terminal = NOW - DAY;
    // 180 days is longer than the 90-day baseline but inside the one-year
    // operational ceiling, so no audited override is required.
    let mut policy = RetentionPolicy::new();
    policy
        .set_override(
            entry.class.clone(),
            RetentionOverride::shorten_to(RetentionWindow::Bounded(
                RetentionDuration::from_days_unchecked(180),
            )),
        )
        .unwrap();
    let decision = decide(&entry, &policy, NOW, Some(terminal), None).expect("inside ceiling");
    assert_eq!(decision.expire_at, Some(terminal + 180 * DAY));
    assert_eq!(decision.source, RetentionSource::AuditedPolicyOverride);
}

#[test]
fn a_legal_hold_suspends_expiry_until_an_audited_release() {
    let entry = record("usage_event");
    let created = NOW - 10 * DAY;
    let hold = LegalHold::scope_wide(NOW - DAY, "litigation hold").unwrap();
    let decision = decide(
        &entry,
        &RetentionPolicy::new(),
        NOW,
        Some(created),
        Some(&hold),
    )
    .expect("hold decision");
    assert!(decision.hold_applies);
    assert_eq!(decision.expire_at, None);
    assert_eq!(decision.reason, RetentionReason::LegalHoldApplied);
    assert_eq!(decision.source, RetentionSource::LegalHold);
    assert!(!decision.is_expired_at(NOW));
    assert_eq!(
        RetentionReason::LegalHoldApplied.as_str(),
        "retention_legal_hold"
    );

    // A hold that has not been placed yet blocks nothing.
    let future = LegalHold::scope_wide(NOW + DAY, "not yet").unwrap();
    let decision = decide(
        &entry,
        &RetentionPolicy::new(),
        NOW,
        Some(created),
        Some(&future),
    )
    .unwrap();
    assert!(!decision.hold_applies);
    assert!(decision.expire_at.is_some());

    // An audited release removes the hold again.
    let released = LegalHold::new(
        true,
        HoldScope::All,
        NOW - DAY,
        Some(NOW - 3600),
        Some("usr_legal".to_string()),
        "released",
    )
    .unwrap();
    let decision = decide(
        &entry,
        &RetentionPolicy::new(),
        NOW,
        Some(created),
        Some(&released),
    )
    .unwrap();
    assert!(!decision.hold_applies);
    assert_eq!(decision.expire_at, Some(created + 2_555 * DAY));
}

#[test]
fn a_legal_hold_scope_can_be_narrowed_to_named_classes() {
    let hold = LegalHold::new(
        true,
        HoldScope::Classes(vec![class("audit_security_event")]),
        NOW - DAY,
        None,
        None,
        "scoped hold",
    )
    .unwrap();
    let decision = decide(
        &record("audit_security_event"),
        &RetentionPolicy::new(),
        NOW,
        Some(NOW - DAY),
        Some(&hold),
    )
    .unwrap();
    assert!(decision.hold_applies);
    let decision = decide(
        &record("occurrence"),
        &RetentionPolicy::new(),
        NOW,
        Some(NOW - DAY),
        Some(&hold),
    )
    .unwrap();
    assert!(
        !decision.hold_applies,
        "a scoped hold must not leak to other classes"
    );
}

#[test]
fn legal_hold_construction_fails_closed() {
    assert!(LegalHold::new(true, HoldScope::Classes(vec![]), NOW, None, None, "x").is_err());
    assert!(
        LegalHold::new(
            true,
            HoldScope::Classes((0..128).map(|i| class(&format!("class_{i}"))).collect()),
            NOW,
            None,
            None,
            "x"
        )
        .is_err()
    );
    assert!(LegalHold::new(true, HoldScope::All, NOW, Some(NOW - DAY), None, "x").is_err());
    assert!(LegalHold::new(true, HoldScope::All, NOW, Some(NOW + 1), None, "x").is_err());
    assert!(LegalHold::new(true, HoldScope::All, NOW, None, None, "  ").is_err());
    assert!(
        LegalHold::new(
            true,
            HoldScope::All,
            NOW,
            Some(NOW + 1),
            Some("usr".into()),
            "x"
        )
        .is_ok()
    );
}

#[test]
fn a_missing_retention_anchor_fails_closed() {
    let entry = record("occurrence");
    assert_eq!(
        decide(&entry, &RetentionPolicy::new(), NOW, None, None),
        Err(RetentionError::MissingAnchor(
            RetentionAnchor::TerminalState
        ))
    );
    // A bounded window still needs the record's own start instant.
    assert_eq!(
        decide(
            &record("export_artifact"),
            &RetentionPolicy::new(),
            NOW,
            None,
            None
        ),
        Ok(RetentionDecision {
            expire_at: None,
            hold_applies: false,
            reason: RetentionReason::DefaultWindow,
            source: RetentionSource::Default,
            window: RetentionWindow::Bounded(RetentionDuration::from_seconds_unchecked(86_400)),
        })
    );
}

#[test]
fn retention_durations_and_policies_are_bounded() {
    assert!(RetentionDuration::new(MAX_RETENTION_SECONDS).is_ok());
    assert!(RetentionDuration::new(MAX_RETENTION_SECONDS + 1).is_err());
    assert_eq!(
        RetentionError::DurationOutOfRange.code(),
        "data_policy_retention_out_of_range"
    );
    let mut policy = RetentionPolicy::new();
    for index in 0..RetentionPolicy::MAX_OVERRIDDEN_CLASSES {
        policy
            .set_override(
                class(&format!("class_{index}")),
                RetentionOverride::shorten_to(RetentionWindow::Lifecycle),
            )
            .unwrap();
    }
    assert_eq!(
        policy.set_override(
            class("one_too_many"),
            RetentionOverride::shorten_to(RetentionWindow::Lifecycle)
        ),
        Err(RetentionError::TooManyOverrides)
    );
}

#[test]
fn lifecycle_classes_have_no_expiry_and_no_ceiling() {
    let entry = record("automation_definition");
    assert!(entry.legal_maximum.is_lifecycle());
    let decision = decide(&entry, &RetentionPolicy::new(), NOW, None, None).unwrap();
    assert_eq!(decision.expire_at, None);
    assert_eq!(decision.reason, RetentionReason::LifecycleRetention);
}

// ===========================================================================
// Logging modes
// ===========================================================================

#[test]
fn metadata_only_is_the_default_everywhere() {
    assert_eq!(LoggingMode::default(), LoggingMode::MetadataOnly);
    assert!(LoggingMode::default().is_default());
    assert_eq!(LoggingMode::default().as_str(), "metadata_only");
    assert_eq!(
        LoggingPolicy::metadata_only().mode(),
        LoggingMode::MetadataOnly
    );
    assert_eq!(LoggingPolicy::metadata_only().full_content_until(), None);
    assert_eq!(LoggingRule::default(), LoggingRule::MetadataOnly);
    for mode in [
        LoggingMode::MetadataOnly,
        LoggingMode::RedactedContent,
        LoggingMode::FullContent,
    ] {
        assert_eq!(LoggingMode::parse(mode.as_str()), Some(mode));
    }
    assert_eq!(LoggingMode::parse("everything"), None);
}

#[test]
fn raw_content_credentials_and_secrets_are_rejected_in_every_mode() {
    let entry = record("run_event");
    let probes = [
        "prompt",
        "system_prompt",
        "response_text",
        "assistant_message",
        "tool_arguments",
        "raw_arguments",
        "api_key",
        "access_token",
        "session_token",
        "ciphertext",
        "webhook_secret",
        "authorization_header",
        "cookie",
        "export_content",
        "artifact_body",
    ];
    for mode in [
        LoggingMode::MetadataOnly,
        LoggingMode::RedactedContent,
        LoggingMode::FullContent,
    ] {
        let mut policy = LoggingPolicy::metadata_only();
        policy
            .set_mode(
                &LoggingModeChange::new(
                    mode,
                    true,
                    "usr_admin",
                    "evt_audit",
                    "diagnostic investigation",
                    Some(NOW + 3_600),
                ),
                NOW,
            )
            .unwrap();
        for field in probes {
            let decision = policy.allows_at(&entry, field, NOW + 1);
            assert!(
                !decision.is_allowed(),
                "{field} was loggable under {mode}: {:?}",
                decision.denial_code()
            );
        }
    }
}

#[test]
fn unknown_and_malformed_fields_fail_closed() {
    let entry = record("occurrence");
    let policy = LoggingPolicy::metadata_only();
    for field in [
        "",
        "Prompt",
        "prompt text",
        "some_new_field_nobody_reviewed",
        &"a".repeat(65),
        "org-id",
        "org..id",
        "org_id_",
    ] {
        let decision = policy.allows(&entry, field);
        assert!(!decision.is_allowed(), "{field:?} was loggable");
        assert_eq!(
            decision.denial_code(),
            Some("logging_field_unregistered"),
            "{field:?}"
        );
    }
}

#[test]
fn metadata_allowlist_is_well_formed_and_unique() {
    let mut sorted = METADATA_FIELD_ALLOWLIST.to_vec();
    sorted.sort_unstable();
    let unique = {
        let mut copy = sorted.clone();
        copy.dedup();
        copy
    };
    assert_eq!(
        sorted.len(),
        unique.len(),
        "duplicate metadata allowlist entry"
    );
    for field in METADATA_FIELD_ALLOWLIST {
        assert!(classify_field(field) == FieldClass::Metadata, "{field}");
    }
    for field in REDACTED_EXCERPT_FIELD_ALLOWLIST {
        assert!(
            field.starts_with("redacted_"),
            "a redacted excerpt must be redacted in its name: {field}"
        );
        assert_eq!(classify_field(field), FieldClass::RedactedExcerpt);
    }
}

#[test]
fn a_redacted_excerpt_requires_the_redacted_content_mode() {
    let entry = record("run_event");
    let field = "redacted_diagnostic_excerpt";

    let metadata_only = LoggingPolicy::metadata_only();
    let decision = metadata_only.allows(&entry, field);
    assert!(!decision.is_allowed());
    assert_eq!(decision.denial_code(), Some("logging_mode_insufficient"));

    let mut policy = LoggingPolicy::metadata_only();
    policy
        .set_mode(
            &LoggingModeChange::new(
                LoggingMode::RedactedContent,
                true,
                "usr_admin",
                "evt_audit",
                "diagnose a failing tool call",
                None,
            ),
            NOW,
        )
        .unwrap();
    assert!(policy.allows(&entry, field).is_allowed());
    // Raising the mode never makes a prohibited field loggable.
    assert!(!policy.allows(&entry, "tool_arguments").is_allowed());
}

#[test]
fn a_class_rule_narrows_the_tenant_mode() {
    // `run` is declared `metadata_only`; `audit_security_event` is narrower.
    let run = record("run");
    let audit = record("audit_security_event");
    let mut policy = LoggingPolicy::metadata_only();
    policy
        .set_mode(
            &LoggingModeChange::new(
                LoggingMode::FullContent,
                true,
                "usr_admin",
                "evt_audit",
                "support investigation",
                Some(NOW + 3_600),
            ),
            NOW,
        )
        .unwrap();

    assert!(
        policy
            .allows(&run, "redacted_diagnostic_excerpt")
            .is_allowed()
    );
    let denied = policy.allows(&audit, "redacted_diagnostic_excerpt");
    assert!(!denied.is_allowed(), "the class rule is the ceiling");
    assert_eq!(audit.logging, LoggingRule::IdsStatus);
}

#[test]
fn a_secret_class_is_never_loggable_in_any_mode() {
    let secret = record("secret");
    let mut policy = LoggingPolicy::metadata_only();
    policy
        .set_mode(
            &LoggingModeChange::new(
                LoggingMode::FullContent,
                true,
                "usr_admin",
                "evt_audit",
                "support investigation",
                Some(NOW + 3_600),
            ),
            NOW,
        )
        .unwrap();
    for field in ["org_id", "reason_code", "state", "redacted_error_summary"] {
        let decision = policy.allows(&secret, field);
        assert!(
            !decision.is_allowed(),
            "{field} leaked from the secret class"
        );
        assert_eq!(decision.denial_code(), Some("logging_class_rule_never"));
    }
    // `webhook_secret` is a secret class too: key IDs are allowed, values are not.
    let webhook_secret = record("webhook_secret");
    assert!(
        policy
            .allows(&webhook_secret, "secret_version")
            .is_allowed()
    );
    assert!(
        !policy
            .allows(&webhook_secret, "webhook_secret")
            .is_allowed()
    );
}

#[test]
fn full_content_requires_permission_and_a_bounded_audited_window() {
    let change = |authorized: bool, until: Option<u64>, actor: &str, correlation: &str| {
        LoggingModeChange::new(
            LoggingMode::FullContent,
            authorized,
            actor,
            correlation,
            "support investigation",
            until,
        )
    };

    let mut policy = LoggingPolicy::metadata_only();
    assert_eq!(
        policy.set_mode(
            &change(false, Some(NOW + 60), "usr_admin", "evt_audit"),
            NOW
        ),
        Err(LoggingError::PermissionDenied)
    );
    assert_eq!(LoggingError::PermissionDenied.code(), "permission_denied");
    assert_eq!(
        policy.set_mode(&change(true, None, "usr_admin", "evt_audit"), NOW),
        Err(LoggingError::UnboundedFullContent)
    );
    assert_eq!(
        policy.set_mode(&change(true, Some(NOW - 1), "usr_admin", "evt_audit"), NOW),
        Err(LoggingError::FullContentWindowInvalid)
    );
    assert_eq!(
        policy.set_mode(
            &change(true, Some(NOW + 30 * DAY), "usr_admin", "evt_audit"),
            NOW
        ),
        Err(LoggingError::FullContentWindowInvalid)
    );
    assert_eq!(
        policy.set_mode(&change(true, Some(NOW + 60), "", "evt_audit"), NOW),
        Err(LoggingError::MissingAuditIntent)
    );
    assert_eq!(
        policy.set_mode(&change(true, Some(NOW + 60), "usr_admin", ""), NOW),
        Err(LoggingError::MissingAuditIntent)
    );
    assert_eq!(policy.mode(), LoggingMode::MetadataOnly);
    assert!(!policy.changes_schema());
}

#[test]
fn an_elapsed_full_content_window_reverts_to_metadata_only() {
    let mut policy = LoggingPolicy::metadata_only();
    policy
        .set_mode(
            &LoggingModeChange::new(
                LoggingMode::FullContent,
                true,
                "usr_admin",
                "evt_audit",
                "support investigation",
                Some(NOW + 3_600),
            ),
            NOW,
        )
        .unwrap();
    assert_eq!(policy.effective_mode_at(NOW), LoggingMode::FullContent);
    assert_eq!(policy.audit_correlation_id(), Some("evt_audit"));
    assert_eq!(
        policy.effective_mode_at(NOW + 3_600),
        LoggingMode::MetadataOnly
    );

    let entry = record("run");
    assert!(
        policy
            .allows_at(&entry, "redacted_diagnostic_excerpt", NOW)
            .is_allowed()
    );
    assert!(
        !policy
            .allows_at(&entry, "redacted_diagnostic_excerpt", NOW + 3_600)
            .is_allowed()
    );

    // Returning to metadata-only clears the diagnostic window entirely.
    policy
        .set_mode(
            &LoggingModeChange::new(
                LoggingMode::MetadataOnly,
                true,
                "usr_admin",
                "evt_audit",
                "investigation closed",
                None,
            ),
            NOW,
        )
        .unwrap();
    assert_eq!(policy.full_content_until(), None);
    assert_eq!(policy.mode(), LoggingMode::MetadataOnly);
}

#[test]
fn a_logging_mode_never_changes_an_event_audit_webhook_or_log_schema() {
    for mode in [
        LoggingMode::MetadataOnly,
        LoggingMode::RedactedContent,
        LoggingMode::FullContent,
    ] {
        let mut policy = LoggingPolicy::metadata_only();
        policy
            .set_mode(
                &LoggingModeChange::new(
                    mode,
                    true,
                    "usr_admin",
                    "evt_audit",
                    "diagnostics",
                    Some(NOW + 60),
                ),
                NOW,
            )
            .unwrap();
        assert!(!policy.changes_schema(), "{mode} widened a schema");
    }
    // No class reaches `full_content`, so no mode can expose content through a
    // class field allowlist.
    for entry in registry() {
        assert_ne!(
            entry.logging.max_mode(),
            Some(LoggingMode::FullContent),
            "{} could log content",
            entry.class
        );
    }
}

// ===========================================================================
// Export planning
// ===========================================================================

#[test]
fn export_categories_match_the_frozen_list() {
    assert_eq!(ExportCategory::ALL.len(), 8);
    let keys: Vec<&str> = ExportCategory::ALL
        .iter()
        .map(|category| category.as_str())
        .collect();
    assert_eq!(
        keys,
        vec![
            "identity",
            "organization",
            "devices",
            "runs_metadata",
            "usage_billing",
            "audit_redacted",
            "notifications",
            "data_governance",
        ]
    );
    for category in ExportCategory::ALL {
        assert_eq!(ExportCategory::parse(category.as_str()), Some(category));
    }
    assert_eq!(ExportCategory::parse("everything"), None);
    for format in [ExportFormat::Json, ExportFormat::Jsonl, ExportFormat::Csv] {
        assert_eq!(ExportFormat::parse(format.as_str()), Some(format));
    }
    assert_eq!(ExportFormat::default(), ExportFormat::Json);
}

#[test]
fn a_personal_export_cannot_reach_tenant_or_platform_data() {
    let scope = ExportScope::new("user", "usr_0123456789abcdef0123456789abcdef").unwrap();
    for category in [
        ExportCategory::Organization,
        ExportCategory::Devices,
        ExportCategory::RunsMetadata,
        ExportCategory::UsageBilling,
        ExportCategory::AuditRedacted,
    ] {
        let request = ExportRequest {
            requested_by: "usr_0123456789abcdef0123456789abcdef".into(),
            scope: scope.clone(),
            categories: vec![category],
            cutoff_at: NOW,
            format: ExportFormat::Json,
            confirmation: Some(TypedConfirmation::new(EXPORT_CONFIRMATION_PHRASE, NOW - 60)),
        };
        let error = request
            .into_manifest(NOW)
            .expect_err("cross-tenant category");
        assert_eq!(error, ExportError::CategoryOutsideScope(category));
        assert_eq!(error.code(), "export_category_invalid");
    }
    // User-owned data is reachable.
    for category in [
        ExportCategory::Identity,
        ExportCategory::Notifications,
        ExportCategory::DataGovernance,
    ] {
        assert!(category.allowed_for_personal_export(), "{category}");
    }
}

#[test]
fn a_personal_export_requires_reauthentication_and_a_typed_confirmation() {
    let scope = ExportScope::new("user", "usr_0123456789abcdef0123456789abcdef").unwrap();
    let base = |confirmation| ExportRequest {
        requested_by: "usr_0123456789abcdef0123456789abcdef".into(),
        scope: scope.clone(),
        categories: vec![ExportCategory::Identity, ExportCategory::Notifications],
        cutoff_at: NOW,
        format: ExportFormat::Json,
        confirmation,
    };

    assert_eq!(
        base(None).into_manifest(NOW),
        Err(ExportError::ReauthenticationRequired)
    );
    assert_eq!(
        base(Some(TypedConfirmation::new("export my data", NOW - 60))).into_manifest(NOW),
        Err(ExportError::ConfirmationMismatch)
    );
    // A reauthentication older than the accepted window is not reauthentication.
    assert_eq!(
        base(Some(TypedConfirmation::new(
            EXPORT_CONFIRMATION_PHRASE,
            NOW - 86_400
        )))
        .into_manifest(NOW),
        Err(ExportError::ReauthenticationRequired)
    );
    let manifest = base(Some(TypedConfirmation::new(
        EXPORT_CONFIRMATION_PHRASE,
        NOW - 60,
    )))
    .into_manifest(NOW)
    .expect("typed confirmation accepted");
    assert_eq!(manifest.category_keys(), vec!["identity", "notifications"]);
    assert_eq!(manifest.cutoff_at, NOW);
}

#[test]
fn empty_and_oversized_category_sets_are_rejected() {
    let org = ExportScope::new("organization", "org_0123456789abcdef0123456789abcdef").unwrap();
    let request = |categories: Vec<ExportCategory>| ExportRequest {
        requested_by: "usr_0123456789abcdef0123456789abcdef".into(),
        scope: org.clone(),
        categories,
        cutoff_at: NOW,
        format: ExportFormat::Json,
        confirmation: None,
    };

    assert_eq!(
        request(vec![]).into_manifest(NOW),
        Err(ExportError::CategorySetEmpty)
    );
    let oversized: Vec<ExportCategory> = (0..9)
        .map(|_| ExportCategory::Identity)
        .chain(ExportCategory::ALL)
        .collect();
    assert_eq!(
        request(oversized).into_manifest(NOW),
        Err(ExportError::CategorySetTooLarge)
    );
    // An organization request may name all eight.
    let manifest = request(ExportCategory::ALL.to_vec())
        .into_manifest(NOW)
        .expect("all categories allowed for an organization");
    assert_eq!(manifest.categories.len(), 8);
    assert!(!manifest.scope.is_personal());
    assert!(ExportScope::new("user", "").is_err());
    assert!(ExportScope::new("tenant", "org_x").is_err());
}

#[test]
fn a_retry_must_reuse_the_same_cutoff_and_category_manifest() {
    let org = ExportScope::new("organization", "org_0123456789abcdef0123456789abcdef").unwrap();
    let original = ExportRequest {
        requested_by: "usr_0123456789abcdef0123456789abcdef".into(),
        scope: org.clone(),
        categories: vec![
            ExportCategory::UsageBilling,
            ExportCategory::Identity,
            ExportCategory::Notifications,
        ],
        cutoff_at: NOW,
        format: ExportFormat::Json,
        confirmation: None,
    }
    .into_manifest(NOW)
    .expect("valid manifest");

    // A retry that reorders the request is the same manifest.
    let reordered = ExportRequest {
        requested_by: "usr_0123456789abcdef0123456789abcdef".into(),
        scope: org.clone(),
        categories: vec![
            ExportCategory::Identity,
            ExportCategory::Notifications,
            ExportCategory::UsageBilling,
        ],
        cutoff_at: NOW,
        format: ExportFormat::Json,
        confirmation: None,
    }
    .into_manifest(NOW)
    .expect("valid manifest");
    assert_eq!(original.categories, reordered.categories);
    assert!(manifest_is_stable(&original, &reordered));
    assert!(reordered.is_stable(&original));

    // A retry that widens the categories, moves the cutoff, or changes the
    // format is not a retry.
    let mut widened = original.clone();
    widened.categories.push(ExportCategory::Devices);
    assert!(!manifest_is_stable(&original, &widened));

    let mut moved_cutoff = original.clone();
    moved_cutoff.cutoff_at += 1;
    assert!(!manifest_is_stable(&original, &moved_cutoff));

    let mut reformatted = original.clone();
    reformatted.format = ExportFormat::Csv;
    assert!(!manifest_is_stable(&original, &reformatted));

    let other_org =
        ExportScope::new("organization", "org_ffffffffffffffffffffffffffffffff").unwrap();
    let mut other_scope = original.clone();
    other_scope.scope = other_org;
    assert!(!manifest_is_stable(&original, &other_scope));

    // Duplicate submissions collapse to the canonical set.
    let duplicated = ExportManifest::new(
        org,
        vec![
            ExportCategory::Identity,
            ExportCategory::Identity,
            ExportCategory::Notifications,
        ],
        NOW,
        ExportFormat::Json,
    );
    assert_eq!(duplicated.categories.len(), 2);
}

#[test]
fn the_export_state_machine_matches_the_frozen_transitions() {
    assert_eq!(ExportJobState::ALL.len(), 10);
    for state in ExportJobState::ALL {
        assert_eq!(ExportJobState::parse(state.as_str()), Some(state));
    }
    // The happy path.
    let path = [
        ExportJobState::Requested,
        ExportJobState::Queued,
        ExportJobState::Collecting,
        ExportJobState::Packaging,
        ExportJobState::Verifying,
        ExportJobState::Ready,
        ExportJobState::Expired,
    ];
    for pair in path.windows(2) {
        assert!(pair[0].can_transition_to(pair[1]), "{pair:?}");
    }
    // Retry re-enters collection and never jumps to verification.
    assert!(ExportJobState::Collecting.can_transition_to(ExportJobState::RetryWait));
    assert!(ExportJobState::Packaging.can_transition_to(ExportJobState::RetryWait));
    assert!(ExportJobState::Verifying.can_transition_to(ExportJobState::RetryWait));
    assert!(ExportJobState::RetryWait.can_transition_to(ExportJobState::Collecting));
    assert!(!ExportJobState::RetryWait.can_transition_to(ExportJobState::Verifying));
    assert!(!ExportJobState::RetryWait.can_transition_to(ExportJobState::Ready));
    // Cancellation is available until the job is ready; failure needs a queued
    // job, so a request that was never accepted cannot report a pipeline
    // failure.
    for state in [
        ExportJobState::Requested,
        ExportJobState::Queued,
        ExportJobState::Collecting,
        ExportJobState::Packaging,
        ExportJobState::Verifying,
        ExportJobState::RetryWait,
    ] {
        assert!(
            state.can_transition_to(ExportJobState::Cancelled),
            "{state}"
        );
    }
    for state in [
        ExportJobState::Queued,
        ExportJobState::Collecting,
        ExportJobState::Packaging,
        ExportJobState::Verifying,
        ExportJobState::RetryWait,
    ] {
        assert!(state.can_transition_to(ExportJobState::Failed), "{state}");
    }
    assert!(!ExportJobState::Requested.can_transition_to(ExportJobState::Failed));
    // `ready` only leaves through expiry.
    assert!(ExportJobState::Ready.can_transition_to(ExportJobState::Expired));
    assert!(!ExportJobState::Ready.can_transition_to(ExportJobState::Failed));
    for terminal in [
        ExportJobState::Expired,
        ExportJobState::Failed,
        ExportJobState::Cancelled,
    ] {
        assert!(terminal.is_terminal());
        for next in ExportJobState::ALL {
            assert!(!terminal.can_transition_to(next), "{terminal} -> {next}");
        }
    }
    // Ordering can never be skipped.
    assert!(!ExportJobState::Requested.can_transition_to(ExportJobState::Ready));
    assert!(!ExportJobState::Queued.can_transition_to(ExportJobState::Packaging));
    assert_eq!(
        ExportJobState::Ready.transition(ExportJobState::Collecting),
        Err(ExportError::InvalidStateTransition)
    );
    assert!(ExportJobState::RetryWait.is_retry());
}

#[test]
fn only_a_ready_export_mints_a_download_grant() {
    for state in ExportJobState::ALL {
        assert_eq!(
            state.can_mint_download_grant(),
            state == ExportJobState::Ready,
            "{state}"
        );
    }
    let scope = ExportScope::new("organization", "org_0123456789abcdef0123456789abcdef").unwrap();
    let authorization =
        |state, expires: Option<u64>, reauth: bool, hold: bool| DownloadAuthorization {
            state,
            artifact_expires_at: expires,
            grant_scope: scope.clone(),
            principal_reauthorized: reauth,
            legal_hold_active: hold,
        };

    for state in ExportJobState::ALL {
        if state == ExportJobState::Ready {
            continue;
        }
        let error = authorize_download(&authorization(state, Some(NOW + DAY), true, false), NOW)
            .expect_err("only ready mints a grant");
        assert_eq!(error, ExportError::NotReady, "{state}");
        assert_eq!(error.code(), "export_not_ready");
    }

    let grant = authorize_download(
        &authorization(ExportJobState::Ready, Some(NOW + DAY), true, false),
        NOW,
    )
    .expect("ready mints a grant");
    assert!(grant.is_usable_at(NOW));
    assert!(!grant.is_usable_at(NOW + DAY));
    assert!(grant.scope.is_same_scope(&scope));

    assert_eq!(
        authorize_download(
            &authorization(ExportJobState::Ready, Some(NOW - 1), true, false),
            NOW
        ),
        Err(ExportError::Expired)
    );
    assert_eq!(ExportError::Expired.code(), "export_expired");
    assert_eq!(
        authorize_download(
            &authorization(ExportJobState::Ready, None, true, false),
            NOW
        ),
        Err(ExportError::ArtifactUnavailable)
    );
    assert_eq!(
        authorize_download(
            &authorization(ExportJobState::Ready, Some(NOW + DAY), false, false),
            NOW
        ),
        Err(ExportError::ReauthenticationRequired)
    );
    assert_eq!(
        authorize_download(
            &authorization(ExportJobState::Ready, Some(NOW + DAY), true, true),
            NOW
        ),
        Err(ExportError::LegalHoldActive)
    );
    // A long-lived artifact is refused rather than trusted.
    assert_eq!(
        authorize_download(
            &authorization(
                ExportJobState::Ready,
                Some(NOW + MAX_EXPORT_EXPIRY_SECONDS + 1),
                true,
                false
            ),
            NOW
        ),
        Err(ExportError::ArtifactUnavailable)
    );
}

#[test]
fn a_manifest_refuses_classes_that_are_no_longer_exportable() {
    let org = ExportScope::new("organization", "org_0123456789abcdef0123456789abcdef").unwrap();
    let manifest =
        ExportManifest::new(org, vec![ExportCategory::Identity], NOW, ExportFormat::Json);
    assert_eq!(
        manifest.assert_collectable(&[]),
        Err(ExportError::CategorySetEmpty)
    );
    assert_eq!(
        manifest.assert_collectable(&[record("secret")]),
        Err(ExportError::CategoryNotExportable)
    );
    assert_eq!(
        manifest.assert_collectable(&[record("queue_job_envelope")]),
        Err(ExportError::CategoryNotExportable)
    );
    assert!(manifest.assert_collectable(&[record("identity")]).is_ok());
}

// ===========================================================================
// Deletion planning
// ===========================================================================

#[test]
fn the_deletion_state_machine_matches_the_frozen_transitions() {
    assert_eq!(DeletionJobState::ALL.len(), 10);
    for state in DeletionJobState::ALL {
        assert_eq!(DeletionJobState::parse(state.as_str()), Some(state));
    }
    let path = [
        DeletionJobState::Requested,
        DeletionJobState::AwaitingGrace,
        DeletionJobState::Queued,
        DeletionJobState::Planning,
        DeletionJobState::Deleting,
        DeletionJobState::Verifying,
        DeletionJobState::Completed,
    ];
    for pair in path.windows(2) {
        assert!(pair[0].can_transition_to(pair[1]), "{pair:?}");
    }
    // A request may skip the grace window for a non-personal deletion.
    assert!(DeletionJobState::Requested.can_transition_to(DeletionJobState::Queued));
    // Retry and park.
    assert!(DeletionJobState::Deleting.can_transition_to(DeletionJobState::RetryWait));
    assert!(DeletionJobState::RetryWait.can_transition_to(DeletionJobState::Deleting));
    assert!(DeletionJobState::Deleting.can_transition_to(DeletionJobState::NeedsAttention));
    assert!(DeletionJobState::Verifying.can_transition_to(DeletionJobState::NeedsAttention));
    assert!(DeletionJobState::Planning.can_transition_to(DeletionJobState::NeedsAttention));
    // `needs_attention` has no plain exit.
    for next in DeletionJobState::ALL {
        assert!(
            !DeletionJobState::NeedsAttention.can_transition_to(next),
            "plain transition out of needs_attention to {next}"
        );
    }
    assert_eq!(
        DeletionJobState::NeedsAttention.transition(DeletionJobState::Deleting),
        Err(DeletionError::NotResumable)
    );
    assert_eq!(DeletionError::NotResumable.code(), "deletion_not_resumable");
    for terminal in [DeletionJobState::Completed, DeletionJobState::Cancelled] {
        assert!(terminal.is_terminal());
        for next in DeletionJobState::ALL {
            assert!(!terminal.can_transition_to(next));
        }
    }
    assert_eq!(
        DeletionJobState::Deleting.park_state(),
        DeletionJobState::NeedsAttention
    );
    assert!(DeletionJobState::NeedsAttention.is_resumable());
    assert!(!DeletionJobState::RetryWait.is_resumable());
}

#[test]
fn a_resume_requires_permission_and_an_audited_legal_hold_release() {
    // No hold: permission is the only requirement.
    assert_eq!(
        DeletionJobState::NeedsAttention.resume(&ResumeAuthorization {
            permitted: false,
            hold_blocked: false,
            hold_released: false,
            hold_released_by: None,
        }),
        Err(DeletionError::PermissionDenied)
    );
    assert_eq!(
        DeletionJobState::NeedsAttention.resume(&ResumeAuthorization::permitted()),
        Ok(DeletionJobState::Deleting)
    );
    // Hold still in force: the resume is refused with the gate's reason.
    let blocked = ResumeAuthorization::legal_hold_release(true, false, "usr_legal");
    assert_eq!(
        DeletionJobState::NeedsAttention.resume(&blocked),
        Err(DeletionError::LegalHold)
    );
    assert_eq!(DeletionError::LegalHold.code(), "deletion_legal_hold");
    let released = ResumeAuthorization::legal_hold_release(true, true, "usr_legal");
    assert_eq!(
        DeletionJobState::NeedsAttention.resume(&released),
        Ok(DeletionJobState::Deleting)
    );
    // Only `needs_attention` is resumable.
    assert_eq!(
        DeletionJobState::Deleting.resume(&ResumeAuthorization::permitted()),
        Err(DeletionError::NotResumable)
    );
}

#[test]
fn a_personal_deletion_can_be_cancelled_only_inside_its_grace_window() {
    let grace_expires_at = NOW + 7 * DAY;
    assert!(DeletionJobState::grace_cancel_allowed(
        DeletionJobState::AwaitingGrace,
        NOW,
        Some(grace_expires_at)
    ));
    assert!(!DeletionJobState::grace_cancel_allowed(
        DeletionJobState::AwaitingGrace,
        grace_expires_at,
        Some(grace_expires_at)
    ));
    assert!(!DeletionJobState::grace_cancel_allowed(
        DeletionJobState::AwaitingGrace,
        NOW,
        None
    ));
    for state in [
        DeletionJobState::Requested,
        DeletionJobState::Queued,
        DeletionJobState::Deleting,
        DeletionJobState::NeedsAttention,
        DeletionJobState::Completed,
    ] {
        assert!(
            !DeletionJobState::grace_cancel_allowed(state, NOW, Some(grace_expires_at)),
            "{state} must not be cancellable in a grace window"
        );
    }
}

#[test]
fn deletion_steps_are_idempotent_and_need_an_explicit_resume() {
    let mut step = DeletionStep::new(
        class("artifact"),
        ReferenceKind::R2Object,
        "exports/org_0123456789abcdef0123456789abcdef/exp_opaque",
    )
    .expect("valid step");
    assert_eq!(step.state, DeletionStepState::Pending);
    assert_eq!(step.step_key(), "artifact_objects");
    assert!(step.begin(NOW).unwrap().changed());
    assert_eq!(step.attempt, 1);
    assert_eq!(step.started_at, Some(NOW));

    // A redelivered `succeed` is a no-op, not a second completion.
    assert!(step.succeed(NOW).unwrap().changed());
    assert_eq!(
        step.succeed(NOW + 5),
        Ok(StepTransition::AlreadyApplied {
            state: DeletionStepState::Succeeded
        })
    );
    assert_eq!(step.completed_at, Some(NOW));
    assert!(step.is_terminal());
    assert!(step.begin(NOW + 6).is_err());

    // A failed step does not leave `failed` without an authorized resume.
    let mut failed = DeletionStep::new(class("occurrence"), ReferenceKind::DatabaseRow, "occ_1")
        .expect("valid step");
    failed.begin(NOW).unwrap();
    assert!(failed.fail("d1_write_failed", NOW).unwrap().changed());
    assert_eq!(failed.failure_code.as_deref(), Some("d1_write_failed"));
    assert!(failed.retry_wait(NOW).is_err());
    assert!(failed.succeed(NOW).is_err());
    assert_eq!(
        failed.resume(&ResumeAuthorization::permitted(), NOW + 60),
        Ok(StepTransition::Applied {
            from: DeletionStepState::Failed,
            to: DeletionStepState::Running
        })
    );
    assert_eq!(failed.attempt, 2);
    assert_eq!(failed.failure_code, None);
    assert!(failed.succeed(NOW + 61).unwrap().changed());

    // A retry_wait step resumes through the same explicit operation.
    let mut retry = DeletionStep::new(class("occurrence"), ReferenceKind::DatabaseRow, "occ_2")
        .expect("valid step");
    retry.begin(NOW).unwrap();
    assert!(retry.retry_wait(NOW).unwrap().changed());
    assert!(!retry.is_terminal());
    assert_eq!(retry.state, DeletionStepState::RetryWait);
    assert!(
        retry
            .resume(&ResumeAuthorization::permitted(), NOW + 60)
            .unwrap()
            .changed()
    );
}

#[test]
fn a_skipped_step_always_says_why() {
    let mut step = DeletionStep::new(
        class("upstream_provider_data"),
        ReferenceKind::UpstreamProviderData,
        "provider_ref_1",
    )
    .expect("valid step");
    assert!(
        step.skip(DeletionSkipReason::NotLumiOwned, NOW)
            .unwrap()
            .changed()
    );
    assert_eq!(step.skip_reason, Some(DeletionSkipReason::NotLumiOwned));
    assert_eq!(
        step.skip_reason.unwrap().as_str(),
        "deletion_not_lumi_owned"
    );
    assert!(DeletionStepState::Skipped.is_terminal());
    assert_eq!(
        step.skip(DeletionSkipReason::LegalHold, NOW + 10),
        Ok(StepTransition::AlreadyApplied {
            state: DeletionStepState::Skipped
        })
    );
    assert_eq!(step.skip_reason, Some(DeletionSkipReason::NotLumiOwned));
    assert!(DeletionSkipReason::parse("deletion_legal_hold").is_some());
    assert!(DeletionStepState::parse("pending").is_some());
    assert_eq!(DeletionStepState::ALL.len(), 7);
}

fn inventory() -> Vec<DeletionInventoryEntry> {
    vec![
        DeletionInventoryEntry::new(
            class("artifact"),
            ReferenceKind::R2Object,
            "exports/org_1/exp_1/opaque",
        ),
        DeletionInventoryEntry::new(class("artifact"), ReferenceKind::DatabaseRow, "art_1"),
        DeletionInventoryEntry::new(class("occurrence"), ReferenceKind::DatabaseRow, "occ_1"),
        DeletionInventoryEntry::new(class("occurrence"), ReferenceKind::DatabaseRow, "occ_2"),
        DeletionInventoryEntry::new(class("secret"), ReferenceKind::DatabaseRow, "cred_1"),
        DeletionInventoryEntry::new(
            class("audit_security_event"),
            ReferenceKind::DatabaseRow,
            "sec_1",
        ),
        DeletionInventoryEntry::new(class("credential"), ReferenceKind::DatabaseRow, "cred_2"),
        DeletionInventoryEntry::new(
            class("artifact"),
            ReferenceKind::LocalDeviceData,
            "zcode:local/workspace/file",
        ),
    ]
}

#[test]
fn the_planner_walks_the_registry_in_declaration_order() {
    let plan = DeletionPlanner::plan(
        DeletionTarget::new("organization", "org_0123456789abcdef0123456789abcdef").unwrap(),
        &inventory(),
        None,
        NOW,
    )
    .expect("bounded plan");

    // Declaration order: P06 projections first, then the P01-P05 classes.
    // Within a class the object traversal precedes the D1 row, so a failed
    // object deletion still leaves the metadata row that points at it.
    let keys: Vec<String> = plan.steps.iter().map(DeletionStep::step_key).collect();
    assert_eq!(
        keys,
        vec![
            "occurrence",
            "occurrence",
            "credential",
            "artifact_objects",
            "artifact",
            "artifact_device_data",
            "audit_security_event",
            "secret",
        ]
    );
    let object_first = plan
        .steps
        .iter()
        .position(|step| step.step_key() == "artifact_objects")
        .expect("object step");
    let row_after = plan
        .steps
        .iter()
        .position(|step| {
            step.step_key() == "artifact" && step.reference_kind == ReferenceKind::DatabaseRow
        })
        .expect("row step");
    assert!(object_first < row_after);
    // The private R2 object is Lumi-owned, so it is real work: F20-007 makes
    // deleting the row without the object insufficient.
    assert_eq!(
        plan.step_by_key("artifact_objects").map(|step| step.state),
        Some(DeletionStepState::Pending)
    );
    // The local ZCode copy is not Lumi's to delete.
    assert_eq!(
        plan.step_by_key("artifact_device_data")
            .map(|step| step.state),
        Some(DeletionStepState::Skipped)
    );
    assert_eq!(plan.coverage(), reference_coverage());
    assert!(!plan.is_complete());
}

#[test]
fn the_planner_never_claims_to_delete_data_lumi_does_not_own() {
    let plan = DeletionPlanner::plan(
        DeletionTarget::new("organization", "org_0123456789abcdef0123456789abcdef").unwrap(),
        &inventory(),
        None,
        NOW,
    )
    .expect("plan");
    let device = plan
        .step_by_key("artifact_device_data")
        .expect("device step");
    assert_eq!(device.state, DeletionStepState::Skipped);
    assert_eq!(device.skip_reason, Some(DeletionSkipReason::NotLumiOwned));
    assert!(device.is_terminal());
    assert!(plan.not_lumi_deletable.contains(&class("artifact")));

    let plan = DeletionPlanner::plan(
        DeletionTarget::new("organization", "org_1").unwrap(),
        &[DeletionInventoryEntry::new(
            class("upstream_provider_data"),
            ReferenceKind::UpstreamProviderData,
            "provider_account_ref",
        )],
        None,
        NOW,
    )
    .expect("plan");
    let step = &plan.steps[0];
    assert_eq!(step.state, DeletionStepState::Skipped);
    assert_eq!(step.skip_reason, Some(DeletionSkipReason::NotLumiOwned));
    assert!(
        plan.not_lumi_deletable
            .contains(&class("upstream_provider_data"))
    );

    // Every deletion result carries the non-over-claiming statements.
    assert_eq!(plan.disclosures(), DISCLOSURES.to_vec());
    assert!(
        DISCLOSURES
            .iter()
            .any(|text| text.contains("ZCode") && text.contains("not by this cloud job"))
    );
    assert!(
        DISCLOSURES
            .iter()
            .any(|text| text.contains("Upstream AI provider") && text.contains("cannot delete"))
    );
}

#[test]
fn the_planner_reports_legal_retention_instead_of_retrying_forever() {
    let plan = DeletionPlanner::plan(
        DeletionTarget::new("organization", "org_1").unwrap(),
        &inventory(),
        None,
        NOW,
    )
    .expect("plan");
    let audit = plan
        .step_by_key("audit_security_event")
        .expect("audit step");
    assert_eq!(audit.state, DeletionStepState::Skipped);
    assert_eq!(
        audit.skip_reason,
        Some(DeletionSkipReason::RetainedLegalOnly)
    );
    assert!(
        plan.retained_legal_classes
            .contains(&class("audit_security_event"))
    );

    // Platform-owned classes are out of a tenant deletion's reach.
    let plan = DeletionPlanner::plan(
        DeletionTarget::new("organization", "org_1").unwrap(),
        &[DeletionInventoryEntry::new(
            class("data_class_registry"),
            ReferenceKind::DatabaseRow,
            "dgp_1",
        )],
        None,
        NOW,
    )
    .expect("plan");
    assert_eq!(plan.steps[0].state, DeletionStepState::Skipped);
    assert_eq!(
        plan.steps[0].skip_reason,
        Some(DeletionSkipReason::RetainedLegalOnly)
    );
}

#[test]
fn the_planner_parks_on_a_legal_hold_with_the_gate_reason() {
    let hold = LegalHold::scope_wide(NOW - DAY, "litigation hold").unwrap();
    let plan = DeletionPlanner::plan(
        DeletionTarget::new("organization", "org_1").unwrap(),
        &inventory(),
        Some(&hold),
        NOW,
    )
    .expect("plan");
    assert!(plan.legal_hold_blocks);
    for step in &plan.steps {
        assert_eq!(
            step.state,
            DeletionStepState::Skipped,
            "{}",
            step.step_key()
        );
        if step.reference_kind.is_lumi_owned() {
            assert_eq!(
                step.skip_reason,
                Some(DeletionSkipReason::LegalHold),
                "{}",
                step.step_key()
            );
        } else {
            // A reference Lumi does not own is reported as such regardless of
            // the hold: Lumi was never going to delete it.
            assert_eq!(step.skip_reason, Some(DeletionSkipReason::NotLumiOwned));
        }
    }
    let occurrence = plan.step_by_key("occurrence").expect("occurrence step");
    assert_eq!(
        occurrence.skip_reason.unwrap().as_str(),
        "deletion_legal_hold"
    );

    // A released hold lets the plan run again.
    let released = LegalHold::new(
        true,
        HoldScope::All,
        NOW - DAY,
        Some(NOW - 60),
        Some("usr_legal".into()),
        "released",
    )
    .unwrap();
    let plan = DeletionPlanner::plan(
        DeletionTarget::new("organization", "org_1").unwrap(),
        &inventory(),
        Some(&released),
        NOW,
    )
    .expect("plan");
    assert!(!plan.legal_hold_blocks);
    assert_eq!(
        plan.step_by_key("occurrence").unwrap().state,
        DeletionStepState::Pending
    );
}

#[test]
fn the_planner_is_bounded_and_rejects_contradictory_input() {
    let target = DeletionTarget::new("organization", "org_1").unwrap();
    assert_eq!(
        DeletionPlanner::plan(target.clone(), &[], None, NOW),
        Err(DeletionError::EmptyInventory)
    );
    let duplicate = vec![
        DeletionInventoryEntry::new(class("occurrence"), ReferenceKind::DatabaseRow, "occ_1"),
        DeletionInventoryEntry::new(class("occurrence"), ReferenceKind::DatabaseRow, "occ_1"),
    ];
    assert_eq!(
        DeletionPlanner::plan(target.clone(), &duplicate, None, NOW),
        Err(DeletionError::DuplicateReference)
    );
    let undeclared = vec![DeletionInventoryEntry::new(
        DataClass::parse("not_a_class").unwrap(),
        ReferenceKind::DatabaseRow,
        "x_1",
    )];
    assert_eq!(
        DeletionPlanner::plan(target.clone(), &undeclared, None, NOW),
        Err(DeletionError::UndeclaredDataClass)
    );
    let huge = (0..super::deletion::MAX_REFERENCES_PER_CLASS + 1)
        .map(|index| {
            DeletionInventoryEntry::new(
                class("occurrence"),
                ReferenceKind::DatabaseRow,
                format!("occ_{index}"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        DeletionPlanner::plan(target, &huge, None, NOW),
        Err(DeletionError::PlanTooLarge)
    );
    assert!(DeletionStep::new(class("occurrence"), ReferenceKind::DatabaseRow, "").is_err());
    assert!(
        DeletionStep::new(
            class("occurrence"),
            ReferenceKind::DatabaseRow,
            "a".repeat(super::deletion::MAX_OBJECT_REFERENCE_LEN + 1)
        )
        .is_err()
    );
}

#[test]
fn reference_traversal_names_the_systems_the_control_plane_does_not_have() {
    let coverage: ReferenceCoverage = reference_coverage();
    assert_eq!(coverage.traversed, vec!["database_row", "r2_object"]);
    assert_eq!(coverage.pending, PENDING_REFERENCE_SYSTEMS.to_vec());
    assert!(!coverage.is_complete());
    assert_eq!(
        coverage.absent_reason(),
        Some(REFERENCE_SYSTEM_ABSENT_REASON)
    );
    // The closed reference-kind set matches the persistence layer's enum.
    assert_eq!(
        [
            ReferenceKind::DatabaseRow.as_str(),
            ReferenceKind::R2Object.as_str(),
            ReferenceKind::LocalDeviceData.as_str(),
            ReferenceKind::UpstreamProviderData.as_str()
        ],
        [
            "database_row",
            "r2_object",
            "local_device_data",
            "upstream_provider_data"
        ]
    );
    for kind in [
        ReferenceKind::DatabaseRow,
        ReferenceKind::R2Object,
        ReferenceKind::LocalDeviceData,
        ReferenceKind::UpstreamProviderData,
    ] {
        assert_eq!(ReferenceKind::parse(kind.as_str()), Some(kind));
    }
    assert!(ReferenceKind::DatabaseRow.is_lumi_owned());
    assert!(ReferenceKind::R2Object.is_lumi_owned());
    assert!(!ReferenceKind::LocalDeviceData.is_lumi_owned());
    assert!(!ReferenceKind::UpstreamProviderData.is_lumi_owned());
    assert_eq!(ReferenceKind::parse("cache"), None);
}

#[test]
fn the_pending_deletion_cutoff_fences_every_delayed_workflow() {
    let cutoff = NOW;
    for workflow in FencedWorkflow::ALL {
        let before = decide_fence(workflow, Some(cutoff), false, cutoff - 1);
        assert_eq!(before.action, FenceAction::Allowed, "{workflow}");
        assert!(!before.is_blocked());

        let after = decide_fence(workflow, Some(cutoff), false, cutoff);
        assert!(after.is_blocked(), "{workflow} ran after the cutoff");
        assert_eq!(after.reason, "deletion_cutoff_reached");
        if workflow == FencedWorkflow::DeletionRetry {
            // The deletion job itself is over: a retry is the resurrection the
            // cutoff exists to prevent.
            assert_eq!(after.action, FenceAction::Cancelled, "{workflow}");
        } else {
            assert_eq!(after.action, FenceAction::Fenced, "{workflow}");
        }
    }
    // `pending_deletion` fences new work even before the cutoff is frozen.
    let pending = decide_fence(FencedWorkflow::AutomationDispatch, None, true, NOW);
    assert_eq!(pending.action, FenceAction::Fenced);
    assert_eq!(pending.reason, "organization_pending_deletion");
    assert!(decide_fence(FencedWorkflow::BillingWrites, None, true, NOW).is_blocked());
    assert!(decide_fence(FencedWorkflow::ExportCreation, None, true, NOW).is_blocked());
    assert!(decide_fence(FencedWorkflow::WebhookFanOut, None, true, NOW).is_blocked());
    assert!(decide_fence(FencedWorkflow::NotificationFanOut, None, true, NOW).is_blocked());
    for workflow in FencedWorkflow::ALL {
        assert_eq!(FencedWorkflow::parse(workflow.as_str()), Some(workflow));
    }
}

#[test]
fn account_deletion_requires_leaving_or_transferring_owned_organizations() {
    let blocking = OrgMembershipRef {
        org_id: "org_1".into(),
        role: OrgRole::Owner,
        exit_possible: false,
    };
    assert_eq!(
        evaluate_account_deletion_exit(std::slice::from_ref(&blocking)),
        Err(DeletionError::RequiresOrgExit)
    );
    assert_eq!(
        DeletionError::RequiresOrgExit.code(),
        "deletion_requires_org_exit"
    );
    // Transferring ownership out is the documented alternative.
    assert!(
        evaluate_account_deletion_exit(&[OrgMembershipRef {
            exit_possible: true,
            ..blocking.clone()
        }])
        .is_ok()
    );
    // A plain member or viewer never blocks.
    for role in [OrgRole::Member, OrgRole::Viewer] {
        assert!(
            evaluate_account_deletion_exit(&[OrgMembershipRef {
                org_id: "org_1".into(),
                role,
                exit_possible: false,
            }])
            .is_ok(),
            "{role} blocked an account deletion"
        );
    }
    assert!(evaluate_account_deletion_exit(&[]).is_ok());
}

#[test]
fn an_account_deletion_request_requires_typed_confirmation() {
    let good = TypedConfirmation::new(DELETION_CONFIRMATION_PHRASE, NOW - 60);
    assert!(verify_account_deletion_request(&good, NOW).is_ok());
    assert_eq!(
        verify_account_deletion_request(
            &TypedConfirmation::new("delete my account", NOW - 60),
            NOW
        ),
        Err(DeletionError::ReauthenticationRequired)
    );
    assert_eq!(
        verify_account_deletion_request(
            &TypedConfirmation::new(DELETION_CONFIRMATION_PHRASE, NOW - 86_400),
            NOW
        ),
        Err(DeletionError::ReauthenticationRequired)
    );
    assert_eq!(
        DeletionError::ReauthenticationRequired.code(),
        "deletion_reauth_required"
    );
    assert!(
        DeletionTarget::new("user", "usr_0123456789abcdef0123456789abcdef")
            .unwrap()
            .is_personal()
    );
    assert!(DeletionTarget::new("org", "org_1").is_err());
}

#[test]
fn a_second_deletion_job_for_the_same_scope_conflicts() {
    let target = DeletionTarget::new("organization", "org_1").unwrap();
    assert!(ensure_no_scope_conflict(&target, &[]).is_ok());
    assert_eq!(
        ensure_no_scope_conflict(&target, std::slice::from_ref(&target)),
        Err(DeletionError::ScopeConflict)
    );
    assert_eq!(
        DeletionError::ScopeConflict.code(),
        "deletion_scope_conflict"
    );
    // A user job and an org job are different scopes.
    assert!(
        ensure_no_scope_conflict(&target, &[DeletionTarget::new("user", "org_1").unwrap()]).is_ok()
    );
}

#[test]
fn deletion_reachable_classes_exclude_platform_and_external_scopes() {
    let reachable = deletion_reachable_classes();
    assert!(reachable.contains(&class("occurrence")));
    assert!(reachable.contains(&class("artifact")));
    // `secret` IS reachable: crypto-erasing a credential is a deletion action.
    assert!(reachable.contains(&class("secret")));
    // Neither provider-held data nor platform-owned records are reachable.
    assert!(!reachable.contains(&class("upstream_provider_data")));
    assert!(!reachable.contains(&class("plan")));
    assert!(!reachable.contains(&class("audit_security_event")));
    for key in &reachable {
        assert!(
            record(key.as_str()).is_deletion_actionable(),
            "{key} is reachable but not actionable"
        );
    }
}

// ===========================================================================
// Frozen coordinator fixture
// ===========================================================================

const FIXTURE: &str =
    include_str!("../../../../../docs/implementation/fixtures/p06-contracts-v1.json");

fn fixture() -> serde_json::Value {
    serde_json::from_str(FIXTURE).expect("frozen P06 fixture is valid JSON")
}

#[test]
fn the_frozen_data_policy_fixture_is_representable() {
    let policy = &fixture()["data_policy"];
    assert_eq!(fixture()["contract_version"], "p06-cg-v1");

    // `metadata_only` is the frozen default.
    assert_eq!(policy["logging_mode"].as_str(), Some("metadata_only"));
    assert_eq!(
        LoggingMode::parse(policy["logging_mode"].as_str().unwrap()),
        Some(LoggingMode::MetadataOnly)
    );
    assert_eq!(
        LoggingPolicy::metadata_only().mode(),
        LoggingMode::MetadataOnly
    );

    // Empty per-class overrides means every class keeps its registry baseline.
    let overrides = policy["class_retention_overrides"]
        .as_object()
        .expect("overrides object");
    assert!(overrides.is_empty());
    let retention = RetentionPolicy::new();
    for entry in registry() {
        // A baseline decision never needs an audited override, because the
        // registry default is inside the class legal maximum.
        let anchor = Some(NOW);
        assert!(
            decide(&entry, &retention, NOW, anchor, None).is_ok(),
            "{}: {}",
            entry.class,
            entry.default_retention
        );
    }

    // `legal_hold: false` means nothing is held.
    assert_eq!(policy["legal_hold"], false);
    assert_eq!(
        BackupLifecycle::parse(policy["backup_lifecycle"].as_str().unwrap()),
        Some(BackupLifecycle::PlatformExpiry)
    );
    assert_eq!(
        policy["provider_retention_disclosure"].as_str(),
        Some("external_policy")
    );
    assert_eq!(
        policy["default_export_expiry_seconds"].as_u64(),
        Some(86_400)
    );
    assert_eq!(
        record("export_artifact").default_retention,
        RetentionWindow::Bounded(RetentionDuration::from_seconds_unchecked(86_400))
    );
    // The fixture's 90-day default matches the frozen job-projection baseline.
    assert_eq!(policy["default_retention_days"].as_u64(), Some(90));
    assert_eq!(
        record("occurrence").default_retention,
        baseline_retention(BaselineRetention::AutomationProjection)
    );
}

#[test]
fn the_frozen_deletion_job_fixture_is_representable() {
    let job = &fixture()["jobs"]["deletion"];
    assert_eq!(job["state"].as_str(), Some("needs_attention"));
    let state = DeletionJobState::parse(job["state"].as_str().unwrap()).expect("known state");
    assert_eq!(state, DeletionJobState::NeedsAttention);
    assert!(state.is_resumable());
    assert_eq!(job["resume_allowed"], true);

    // The failed step is the R2 object traversal of the artifact class.
    let step_key = job["failed_step"].as_str().unwrap();
    assert_eq!(step_key, "artifact_objects");
    let plan = DeletionPlanner::plan(
        DeletionTarget::new("organization", "org_0123456789abcdef0123456789abcdef").unwrap(),
        &inventory(),
        None,
        NOW,
    )
    .expect("plan");
    assert!(plan.step_by_key(step_key).is_some());

    // A legal hold blocks the resume until an audited support/legal release.
    let negative = &fixture()["negative_fixtures"]["legal_hold"];
    assert_eq!(negative["state"].as_str(), Some("needs_attention"));
    assert_eq!(negative["reason"].as_str(), Some("deletion_legal_hold"));
    assert_eq!(
        DeletionSkipReason::parse(negative["reason"].as_str().unwrap()),
        Some(DeletionSkipReason::LegalHold)
    );
    assert_eq!(
        negative["resume_requires"].as_str(),
        Some("audited_support_release")
    );

    let hold = LegalHold::scope_wide(NOW - DAY, "legal request").unwrap();
    let held = DeletionPlanner::plan(
        DeletionTarget::new("organization", "org_1").unwrap(),
        &inventory(),
        Some(&hold),
        NOW,
    )
    .expect("plan");
    assert!(held.legal_hold_blocks);
    let mut step = held.steps[0].clone();
    step.state = DeletionStepState::NeedsAttention;
    let blocked = ResumeAuthorization::legal_hold_release(true, false, "usr_legal");
    assert_eq!(step.resume(&blocked, NOW), Err(DeletionError::LegalHold));
    let released = ResumeAuthorization::legal_hold_release(true, true, "usr_legal");
    assert!(step.resume(&released, NOW).is_ok());
}

#[test]
fn the_frozen_personal_export_fixture_is_representable() {
    let negative = &fixture()["negative_fixtures"]["personal_export"];
    assert_eq!(negative["scope_type"].as_str(), Some("user"));
    assert_eq!(negative["requires_reauthentication"], true);
    assert_eq!(negative["download_state"].as_str(), Some("ready"));

    let scope = ExportScope::new("user", "usr_0123456789abcdef0123456789abcdef").unwrap();
    let categories: Vec<ExportCategory> = negative["categories"]
        .as_array()
        .expect("category array")
        .iter()
        .map(|value| ExportCategory::parse(value.as_str().unwrap()).expect("frozen category"))
        .collect();
    assert_eq!(
        categories,
        vec![ExportCategory::Identity, ExportCategory::Notifications]
    );
    let manifest = ExportRequest {
        requested_by: "usr_0123456789abcdef0123456789abcdef".into(),
        scope: scope.clone(),
        categories,
        cutoff_at: NOW,
        format: ExportFormat::Json,
        confirmation: Some(TypedConfirmation::new(EXPORT_CONFIRMATION_PHRASE, NOW - 60)),
    }
    .into_manifest(NOW)
    .expect("fixture export request is valid");
    assert_eq!(manifest.scope, scope);

    // The fixture's download state is the only one that mints a grant.
    let download_state =
        ExportJobState::parse(negative["download_state"].as_str().unwrap()).expect("state");
    assert!(download_state.can_mint_download_grant());
    let grant = authorize_download(
        &DownloadAuthorization {
            state: download_state,
            artifact_expires_at: Some(NOW + DAY),
            grant_scope: scope,
            principal_reauthorized: true,
            legal_hold_active: false,
        },
        NOW,
    )
    .expect("fixture grant");
    assert!(grant.is_usable_at(NOW));

    // The ready job fixture carries a 24-hour artifact expiry.
    let export = &fixture()["jobs"]["export"];
    assert_eq!(
        ExportJobState::parse(export["state"].as_str().unwrap()),
        Some(ExportJobState::Ready)
    );
    assert_eq!(export["attempt"].as_u64(), Some(1));
    assert!(export["artifact_expires_at"].as_str().is_some());
}
