//! P06 entitlement, license, and subscription domain tests.
//!
//! Every test here is a pure-function assertion over authoritative inputs. The
//! suite deliberately covers the frozen negative cases from
//! `docs/implementation/fixtures/p06-contracts-v1.json`
//! (`negative_fixtures.license_state_matrix`, `over_limit_downgrade`, and
//! `transient_billing_outage`) plus the cross-tenant negatives the control
//! plane requires.

use serde_json::json;

use crate::core::{ManagedDeviceId, MembershipId, OrganizationId, ProjectId, Timestamp, UserId};

use super::*;

// ---------------------------------------------------------------------------
// Fixtures and helpers
// ---------------------------------------------------------------------------

/// `2026-09-25T12:00:00.000Z`, the frozen fixture issue instant.
const T_2026_09_25_12: &str = "2026-09-25T12:00:00.000Z";
/// `2026-10-02T12:00:00.000Z`, exactly seven days later.
const T_2026_10_02_12: &str = "2026-10-02T12:00:00.000Z";
/// `2026-09-25T16:15:00.000Z`, the frozen `policy_fresh_until`.
const T_2026_09_25_16_15: &str = "2026-09-25T16:15:00.000Z";

fn ts(value: &str) -> Timestamp {
    Timestamp::new(value).expect("fixture timestamp is valid RFC 3339 UTC")
}

fn org_id() -> OrganizationId {
    OrganizationId::new("org_0123456789abcdef0123456789abcdef").unwrap()
}

fn other_org_id() -> OrganizationId {
    OrganizationId::new("org_fedcba9876543210fedcba9876543210").unwrap()
}

fn project_id() -> ProjectId {
    ProjectId::new("prj_0123456789abcdef0123456789abcdef").unwrap()
}

fn user_id() -> UserId {
    UserId::new("usr_0123456789abcdef0123456789abcdef").unwrap()
}

fn device_id() -> ManagedDeviceId {
    ManagedDeviceId::new("dvc_0123456789abcdef0123456789abcdef").unwrap()
}

fn ent_key(value: &str) -> EntitlementKey {
    EntitlementKey::new(value).expect("baseline key is well formed")
}

fn distinct_grant_id(index: u32) -> EntitlementGrantId {
    EntitlementGrantId::new(format!("egr_{index:032x}")).unwrap()
}

fn grant(
    index: u32,
    key: &EntitlementKey,
    value: EntitlementValue,
    source: GrantSource,
    now: i64,
) -> EntitlementGrant {
    EntitlementGrant::new(
        distinct_grant_id(index),
        org_id(),
        key.clone(),
        value,
        source,
        EntitlementScope::organization(),
        (source == GrantSource::InternalOverride).then(|| "support escalation".to_owned()),
        now,
        (source == GrantSource::InternalOverride).then_some(now + 3_600),
        None,
    )
    .expect("grant is valid")
}

fn resolve_with(
    defaults: &[EntitlementGrant],
    plan: &[EntitlementGrant],
    subscription: &[EntitlementGrant],
    overrides: &[EntitlementGrant],
    denials: &[EntitlementDenial],
    now: i64,
) -> EffectiveEntitlements {
    resolve_effective_entitlements(&EntitlementResolution {
        org_id: &org_id(),
        scope: EntitlementScope::organization(),
        now,
        inputs: EntitlementInputs {
            platform_defaults: defaults,
            plan_grants: plan,
            subscription_grants: subscription,
            internal_overrides: overrides,
            denials,
        },
    })
    .expect("resolution is valid")
}

// ---------------------------------------------------------------------------
// Entitlement key registry
// ---------------------------------------------------------------------------

#[test]
fn baseline_registry_contains_every_frozen_key() {
    let required = [
        "org.max_members",
        "projects.max_active",
        "inference.platform_managed",
        "inference.byok",
        "audit.retention_days",
        "automations.max_active",
        "devices.max_enrolled",
        "exports.enabled",
        "deletion.self_service",
        "webhooks.enabled",
        "sso.enabled",
        "scim.enabled",
    ];
    for name in required {
        assert!(
            is_baseline_key(name),
            "missing required baseline key {name}"
        );
        assert!(
            ent_key(name).is_registered(),
            "required key {name} is not registered"
        );
    }

    for name in [
        "webhooks.max_endpoints",
        "automations.max_concurrent",
        "automations.off_peak_enabled",
        "notifications.in_app_enabled",
        "notifications.email_enabled",
        "data.export.enabled",
        "data.deletion.self_service",
    ] {
        assert!(is_baseline_key(name), "missing matrix key {name}");
    }

    let definitions = all_baseline_definitions();
    assert_eq!(definitions.len(), BASELINE_ENTITLEMENT_KEY_COUNT);
    for definition in &definitions {
        assert!(definition.validate().is_ok(), "invalid {definition:?}");
        assert!(definition.protected, "baseline key must fail closed");
        assert!(!definition.description.is_empty());
    }
}

#[test]
fn every_baseline_key_has_a_stable_wire_value_type() {
    assert_eq!(
        baseline_value_type(&ent_key("org.max_members")),
        Some(EntitlementValueType::Integer)
    );
    assert_eq!(
        baseline_value_type(&ent_key("webhooks.enabled")),
        Some(EntitlementValueType::Boolean)
    );
    assert_eq!(baseline_value_type(&ent_key("org.max_member")), None);
    assert_eq!(baseline_value_type(&ent_key("ssso.enabled")), None);
}

#[test]
fn entitlement_keys_are_lowercase_dotted_and_bounded() {
    for invalid in [
        "",
        "org",
        ".org",
        "org.",
        "org..max_members",
        "org.max.members.extra.parts",
        "Org.max_members",
        "org.MAX_members",
        "org.max members",
        "org.max-members",
        "org.1members",
        "price_1A2b3C",
        "prod_Q1wOSpA0i2fMNx",
        "cus_NffrFeUfNV2Hib",
        "sub_1ABCdef",
        "stripe.price.1",
    ] {
        assert!(
            EntitlementKey::new(invalid).is_err(),
            "accepted invalid key {invalid}"
        );
    }

    let long_segment = "a".repeat(MAX_ENTITLEMENT_KEY_SEGMENT_BYTES + 1);
    assert!(EntitlementKey::new(&long_segment).is_err());
    let long_key = "a".repeat(MAX_ENTITLEMENT_KEY_BYTES + 1);
    assert!(EntitlementKey::new(&long_key).is_err());

    assert_eq!(ent_key("org.max_members").as_str(), "org.max_members");
    assert_eq!(ent_key("org.max_members").namespace(), "org");
    assert_eq!(ent_key("data.deletion.self_service").segment_count(), 3);
    assert_eq!(ent_key("org.max_members").segment_count(), 2);
}

#[test]
fn payment_provider_identifiers_can_never_be_entitlement_keys() {
    // P06-CR-002: provider product/price IDs are adapter-private. Every shape a
    // mainstream provider emits must fail structurally...
    for provider_id in [
        "prod_Q1wOSpA0i2fMNx",
        "price_1MznFTFhk1rX2AbCdEfGhIjK",
        "cus_NffrFeUfNV2Hib",
        "sub_1A2b3C4d5E6f7G8h",
        "PED_1234567890abcdef",
        "in_1ABCdefGHIjklMN",
        "acct_1AbCdEfGhIjKlMnO",
        "cs_live_51H8xyzABCDEFG",
        "A0AbCdEfGhIjKlMnOpQrStUv",
        "team_01H8XYZABCDEFG",
    ] {
        assert!(
            EntitlementKey::new(provider_id).is_err(),
            "provider identifier {provider_id} parsed as an entitlement key"
        );
        assert!(!is_baseline_key(provider_id));
    }

    // ...and a deliberately well-formed key that merely looks provider-ish is
    // still refused, because the registry is closed.
    for fabricated in [
        "price.team",
        "product.team",
        "provider.plan",
        "billing.price",
        "stripe.tier",
    ] {
        let parsed = EntitlementKey::new(fabricated);
        assert!(parsed.is_ok(), "{fabricated} should be shape-valid");
        let parsed = parsed.unwrap();
        assert!(
            !parsed.is_registered(),
            "{fabricated} must not be registered"
        );
        assert_eq!(baseline_value_type(&parsed), None);
        assert_eq!(baseline_definition(&parsed), None);
        assert_eq!(
            resolve_with(&[], &[], &[], &[], &[], 1_000).decision(&parsed),
            EntitlementDecision::NotGranted(EntitlementDenialReason::NotConfigured)
        );
    }
}

#[test]
fn entitlement_values_are_typed_and_bounded() {
    assert_eq!(EntitlementValue::boolean(true).as_bool(), Some(true));
    assert_eq!(EntitlementValue::boolean(true).as_integer(), None);
    assert_eq!(EntitlementValue::integer(7).unwrap().as_integer(), Some(7));
    assert_eq!(
        EntitlementValue::bounded_string("sha256").unwrap().as_str(),
        Some("sha256")
    );

    assert!(EntitlementValue::integer(-1).is_err());
    assert!(EntitlementValue::integer(MAX_ENTITLEMENT_VALUE_INTEGER + 1).is_err());
    assert!(EntitlementValue::integer(MIN_ENTITLEMENT_VALUE_INTEGER).is_ok());
    assert!(EntitlementValue::integer(MAX_ENTITLEMENT_VALUE_INTEGER).is_ok());
    assert!(EntitlementValue::bounded_string("").is_err());
    assert!(
        EntitlementValue::bounded_string("a".repeat(MAX_BOUNDED_STRING_VALUE_BYTES + 1)).is_err()
    );
    assert!(EntitlementValue::bounded_string("with\nnewline").is_err());
    assert!(EntitlementValue::bounded_string("日本語").is_err());
}

#[test]
fn entitlement_value_type_never_coerces() {
    let definition = baseline_definition(&ent_key("webhooks.enabled")).unwrap();
    assert!(definition.type_matches(&EntitlementValue::boolean(true)));
    assert!(!definition.type_matches(&EntitlementValue::integer(1).unwrap()));
    assert_ne!(
        definition.fail_closed_value(),
        &EntitlementValue::boolean(true)
    );
    let integer_definition = baseline_definition(&ent_key("org.max_members")).unwrap();
    assert!(!integer_definition.type_matches(&EntitlementValue::boolean(true)));
    assert_eq!(
        EntitlementValueType::String.fail_closed_value(),
        EntitlementValue::BoundedString(String::new())
    );
}

#[test]
fn entitlement_values_use_the_frozen_native_wire_shape() {
    let wire = json!({
        "automations.max_active": 100,
        "webhooks.enabled": true,
        "exports.enabled": true,
    });
    let parsed: std::collections::BTreeMap<EntitlementKey, EntitlementValue> =
        serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(parsed.len(), 3);
    assert_eq!(
        parsed[&ent_key("automations.max_active")].as_integer(),
        Some(100)
    );
    assert_eq!(parsed[&ent_key("webhooks.enabled")].as_bool(), Some(true));
    assert_eq!(parsed[&ent_key("exports.enabled")].as_bool(), Some(true));

    assert_eq!(
        serde_json::to_value(EntitlementValue::integer(100).unwrap()).unwrap(),
        json!(100)
    );
    assert_eq!(
        serde_json::to_value(EntitlementValue::boolean(true)).unwrap(),
        json!(true)
    );
    assert_eq!(
        serde_json::to_value(EntitlementValue::bounded_string("x").unwrap()).unwrap(),
        json!("x")
    );

    for rejected in [
        json!(null),
        json!([1]),
        json!({"a": 1}),
        json!(1.5),
        json!(-1),
        json!(""),
        json!("a".repeat(MAX_BOUNDED_STRING_VALUE_BYTES + 1)),
    ] {
        assert!(
            serde_json::from_value::<EntitlementValue>(rejected.clone()).is_err(),
            "accepted {rejected}"
        );
    }
}

#[test]
fn entitlement_scope_is_a_typed_tenant_scoped_value() {
    let organization = EntitlementScope::organization();
    assert_eq!(organization.scope_id(), None);
    assert_eq!(organization.specificity(), 0);

    let project = EntitlementScope::project(project_id());
    assert_eq!(project.scope_id(), Some(project_id().as_str()));
    assert_eq!(project.specificity(), 1);

    let user = EntitlementScope::user(user_id());
    assert_eq!(user.specificity(), 2);

    assert!(organization.contains(&project));
    assert!(organization.contains(&user));
    assert!(!project.contains(&organization));
    assert!(!project.contains(&EntitlementScope::user(user_id())));
    assert!(!user.contains(&project));
    assert!(!project.contains(&EntitlementScope::project(
        ProjectId::new("prj_fedcba9876543210fedcba9876543210").unwrap()
    )));
}

#[test]
fn entitlement_key_rejects_malformed_wire_input() {
    assert!(serde_json::from_str::<EntitlementKey>("\"org.max_members\"").is_ok());
    assert!(serde_json::from_str::<EntitlementKey>("\"prod_Q1wOSpA0i2fMNx\"").is_err());
    assert!(serde_json::from_str::<EntitlementKey>("\"Org.Max\"").is_err());
    assert_eq!(
        serde_json::to_string(&ent_key("webhooks.enabled")).unwrap(),
        "\"webhooks.enabled\""
    );
    assert!("org.max_members".parse::<EntitlementKey>().is_ok());
    assert!("PROD_team".parse::<EntitlementKey>().is_err());
    assert_eq!(
        ent_key("org.max_members").to_string(),
        "org.max_members".to_owned()
    );
    assert!(format!("{:?}", ent_key("org.max_members")).contains("org.max_members"));
}

// ---------------------------------------------------------------------------
// Instant decoding
// ---------------------------------------------------------------------------

#[test]
fn timestamps_decode_to_whole_unix_seconds() {
    assert_eq!(unix_seconds(&ts("1970-01-01T00:00:00Z")).unwrap(), 0);
    assert_eq!(unix_seconds(&ts(T_2026_09_25_12)).unwrap(), 1_790_337_600);
    // Precision must not change the decoded instant: the wire text differs but
    // the commercial decision must not.
    assert_eq!(
        unix_seconds(&ts(T_2026_09_25_12)).unwrap(),
        unix_seconds(&ts("2026-09-25T12:00:00Z")).unwrap()
    );
    // A validated leap second maps onto the same second, not the next minute.
    assert_eq!(
        unix_seconds(&ts("2024-02-29T23:59:60Z")).unwrap(),
        unix_seconds(&ts("2024-02-29T23:59:59Z")).unwrap()
    );
    // The frozen local-offline window is exactly 7 days.
    assert_eq!(
        unix_seconds(&ts(T_2026_10_02_12)).unwrap() - unix_seconds(&ts(T_2026_09_25_12)).unwrap(),
        LOCAL_ONLY_GRACE_SECONDS
    );
    assert_eq!(
        unix_seconds(&ts("2026-09-26T12:00:00.000Z")).unwrap()
            - unix_seconds(&ts("2026-09-25T12:00:00.000Z")).unwrap(),
        CLOUD_CONTROL_PLANE_GRACE_SECONDS
    );
    // The frozen fixture's `policy_fresh_until` instant decodes too.
    assert_eq!(
        unix_seconds(&ts(T_2026_09_25_16_15)).unwrap(),
        1_790_352_900
    );
    assert_eq!(PLATFORM_PAID_INFERENCE_GRACE_SECONDS, 0);
}

#[test]
fn timestamps_outside_the_supported_instant_range_fail_closed() {
    let too_late = Timestamp::new("9999-12-31T23:59:59Z").unwrap();
    assert_eq!(
        unix_seconds(&too_late),
        Err(EntitlementError::InvalidTimestampRange)
    );
    assert_eq!(
        MAX_TIMESTAMP_UNIX_SECONDS,
        unix_seconds(&ts("3000-01-01T00:00:00Z")).unwrap()
    );
}

// ---------------------------------------------------------------------------
// Effective entitlement precedence
// ---------------------------------------------------------------------------

#[test]
fn missing_values_fail_closed_for_protected_capabilities() {
    let effective = resolve_with(&[], &[], &[], &[], &[], 1_000);
    for name in [
        "webhooks.enabled",
        "sso.enabled",
        "scim.enabled",
        "exports.enabled",
        "deletion.self_service",
        "inference.byok",
        "inference.platform_managed",
        "automations.off_peak_enabled",
    ] {
        let key = ent_key(name);
        assert_eq!(
            effective.decision(&key),
            EntitlementDecision::NotGranted(EntitlementDenialReason::NotConfigured),
            "{name} must fail closed"
        );
        assert_eq!(
            effective.decision(&key).reason_code(),
            Some("entitlement_not_granted")
        );
        assert_eq!(effective.boolean_value(&key), Some(false));
    }
    for name in [
        "org.max_members",
        "projects.max_active",
        "devices.max_enrolled",
        "automations.max_active",
        "webhooks.max_endpoints",
    ] {
        let key = ent_key(name);
        assert_eq!(
            effective.decision(&key),
            EntitlementDecision::NotGranted(EntitlementDenialReason::NotConfigured),
            "{name} must fail closed at zero"
        );
        assert_eq!(effective.limit(&key), Some(0));
    }
}

#[test]
fn precedence_is_platform_default_then_plan_then_subscription_then_override() {
    let key = ent_key("automations.max_active");
    let now = 1_000_i64;
    let platform = grant(
        1,
        &key,
        EntitlementValue::integer(1).unwrap(),
        GrantSource::PlatformDefault,
        0,
    );
    let plan = grant(
        2,
        &key,
        EntitlementValue::integer(2).unwrap(),
        GrantSource::Plan,
        0,
    );
    let subscription = grant(
        3,
        &key,
        EntitlementValue::integer(3).unwrap(),
        GrantSource::Subscription,
        0,
    );
    let over = grant(
        4,
        &key,
        EntitlementValue::integer(4).unwrap(),
        GrantSource::InternalOverride,
        0,
    );

    let only = std::slice::from_ref;
    let triple = [platform.clone(), plan.clone(), subscription.clone()];

    assert_eq!(
        resolve_with(only(&platform), &[], &[], &[], &[], now).limit(&key),
        Some(1)
    );
    assert_eq!(
        resolve_with(only(&platform), only(&plan), &[], &[], &[], now).limit(&key),
        Some(2)
    );
    assert_eq!(
        resolve_with(&triple[..1], &triple[1..2], &triple[2..3], &[], &[], now).limit(&key),
        Some(3)
    );
    assert_eq!(
        resolve_with(
            std::slice::from_ref(&platform),
            std::slice::from_ref(&plan),
            std::slice::from_ref(&subscription),
            std::slice::from_ref(&over),
            &[],
            now
        )
        .limit(&key),
        Some(4)
    );
}

#[test]
fn entitlement_resolution_is_independent_of_input_order() {
    let key = ent_key("webhooks.enabled");
    // Inside every override window created by `grant` (effective 0, expiry 3600).
    let now = 1_000_i64;
    let defaults = [
        grant(
            1,
            &ent_key("projects.max_active"),
            EntitlementValue::integer(3).unwrap(),
            GrantSource::PlatformDefault,
            0,
        ),
        grant(
            2,
            &ent_key("org.max_members"),
            EntitlementValue::integer(5).unwrap(),
            GrantSource::PlatformDefault,
            0,
        ),
    ];
    let plan = [
        grant(
            3,
            &key,
            EntitlementValue::boolean(false),
            GrantSource::Plan,
            0,
        ),
        grant(
            4,
            &ent_key("devices.max_enrolled"),
            EntitlementValue::integer(2).unwrap(),
            GrantSource::Plan,
            0,
        ),
    ];
    let subscription = [
        grant(
            5,
            &key,
            EntitlementValue::boolean(true),
            GrantSource::Subscription,
            0,
        ),
        grant(
            6,
            &ent_key("audit.retention_days"),
            EntitlementValue::integer(30).unwrap(),
            GrantSource::Subscription,
            0,
        ),
    ];
    let over = [
        grant(
            7,
            &ent_key("sso.enabled"),
            EntitlementValue::boolean(true),
            GrantSource::InternalOverride,
            0,
        ),
        grant(
            8,
            &ent_key("automations.max_active"),
            EntitlementValue::integer(9).unwrap(),
            GrantSource::InternalOverride,
            0,
        ),
    ];

    let forward = resolve_with(&defaults, &plan, &subscription, &over, &[], now);
    let mut reversed_defaults = defaults.clone();
    reversed_defaults.reverse();
    let mut reversed_plan = plan.clone();
    reversed_plan.reverse();
    let mut reversed_subscription = subscription.clone();
    reversed_subscription.reverse();
    let mut reversed_over = over.clone();
    reversed_over.reverse();
    let reversed = resolve_with(
        &reversed_defaults,
        &reversed_plan,
        &reversed_subscription,
        &reversed_over,
        &[],
        now,
    );
    assert_eq!(forward, reversed);
    assert_eq!(forward.limit(&ent_key("automations.max_active")), Some(9));
    assert!(forward.is_granted(&key));
}

#[test]
fn resolution_is_stable_across_repeated_calls_and_ordered_by_key() {
    let now = 5_000;
    let first = resolve_with(&[], &[], &[], &[], &[], now);
    let second = resolve_with(&[], &[], &[], &[], &[], now);
    assert_eq!(first, second);
    let keys: Vec<&str> = first
        .entries()
        .iter()
        .map(|entry| entry.key.as_str())
        .collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(keys, sorted);
    // A later `now` with identical rows changes only the resolution stamp.
    let later = resolve_with(&[], &[], &[], &[], &[], now + 1);
    assert_ne!(first.resolved_at, later.resolved_at);
    assert_eq!(first.entries(), later.entries());
}

#[test]
fn a_more_specific_scope_wins_within_the_same_source() {
    let key = ent_key("automations.max_active");
    let org_grant = grant(
        1,
        &key,
        EntitlementValue::integer(2).unwrap(),
        GrantSource::Subscription,
        0,
    );
    let project_grant = EntitlementGrant::new(
        distinct_grant_id(2),
        org_id(),
        key.clone(),
        EntitlementValue::integer(50).unwrap(),
        GrantSource::Subscription,
        EntitlementScope::project(project_id()),
        None,
        0,
        None,
        None,
    )
    .unwrap();

    let inputs = EntitlementInputs {
        platform_defaults: &[],
        plan_grants: &[],
        subscription_grants: &[org_grant, project_grant],
        internal_overrides: &[],
        denials: &[],
    };
    let org = resolve_effective_entitlements(&EntitlementResolution {
        org_id: &org_id(),
        scope: EntitlementScope::organization(),
        now: 100,
        inputs,
    })
    .unwrap();
    let project =
        resolve_effective_entitlements(&project_resolution(&org_id(), &project_id(), 100, inputs))
            .unwrap();
    let other = resolve_effective_entitlements(&project_resolution(
        &org_id(),
        &ProjectId::new("prj_fedcba9876543210fedcba9876543210").unwrap(),
        100,
        inputs,
    ))
    .unwrap();

    assert_eq!(org.limit(&key), Some(2));
    assert_eq!(project.limit(&key), Some(50));
    assert_eq!(other.limit(&key), Some(2));
}

#[test]
fn internal_overrides_require_an_expiry_and_a_reason() {
    let key = ent_key("webhooks.enabled");
    let org = org_id();
    let scope = EntitlementScope::organization();
    let value = EntitlementValue::boolean(true);

    assert_eq!(
        EntitlementGrant::new(
            distinct_grant_id(1),
            org.clone(),
            key.clone(),
            value.clone(),
            GrantSource::InternalOverride,
            scope.clone(),
            Some("support escalation".to_owned()),
            100,
            None,
            None,
        )
        .err(),
        Some(EntitlementError::MissingOverrideExpiry)
    );
    assert_eq!(
        EntitlementGrant::new(
            distinct_grant_id(1),
            org.clone(),
            key.clone(),
            value.clone(),
            GrantSource::InternalOverride,
            scope.clone(),
            None,
            100,
            Some(200),
            None,
        )
        .err(),
        Some(EntitlementError::MissingOverrideReason)
    );
    assert_eq!(
        EntitlementGrant::new(
            distinct_grant_id(1),
            org.clone(),
            key.clone(),
            value.clone(),
            GrantSource::InternalOverride,
            scope.clone(),
            Some("x".repeat(MAX_OVERRIDE_REASON_BYTES + 1)),
            100,
            Some(200),
            None,
        )
        .err(),
        Some(EntitlementError::MissingOverrideReason)
    );
    // A non-override grant does not need either.
    assert!(
        EntitlementGrant::new(
            distinct_grant_id(1),
            org,
            key,
            value,
            GrantSource::Plan,
            scope,
            None,
            100,
            None,
            None,
        )
        .is_ok()
    );
}

#[test]
fn an_override_can_deny_and_its_expiry_falls_back_to_the_lower_source() {
    let key = ent_key("inference.byok");
    let plan = grant(
        1,
        &key,
        EntitlementValue::boolean(true),
        GrantSource::Plan,
        0,
    );
    let deny = grant(
        2,
        &key,
        EntitlementValue::boolean(false),
        GrantSource::InternalOverride,
        100,
    );
    assert_eq!(
        resolve_with(
            &[],
            std::slice::from_ref(&plan),
            &[],
            std::slice::from_ref(&deny),
            &[],
            200
        )
        .decision(&key),
        EntitlementDecision::NotGranted(EntitlementDenialReason::DeniedByOverride)
    );
    // After the override expires the plan value is visible again: an override is
    // never a permanent, silent flip.
    assert_eq!(
        resolve_with(
            &[],
            std::slice::from_ref(&plan),
            &[],
            std::slice::from_ref(&deny),
            &[],
            100 + 3_600
        )
        .decision(&key),
        EntitlementDecision::Granted(EntitlementValue::boolean(true))
    );
}

#[test]
fn an_active_audit_or_legal_denial_cannot_be_erased_by_an_override() {
    let key = ent_key("sso.enabled");
    let now = 1_000_i64;
    let grant_true = grant(
        1,
        &key,
        EntitlementValue::boolean(true),
        GrantSource::Subscription,
        0,
    );
    let override_true = grant(
        2,
        &key,
        EntitlementValue::boolean(true),
        GrantSource::InternalOverride,
        0,
    );
    let denial = EntitlementDenial::new(
        key.clone(),
        EntitlementScope::organization(),
        EntitlementDenialReason::DeniedByLegalHold,
        "sec_0123456789abcdef0123456789abcdef",
        0,
        None,
    )
    .unwrap();

    assert!(
        resolve_with(&[], &[], std::slice::from_ref(&grant_true), &[], &[], now).is_granted(&key)
    );
    assert!(
        resolve_with(
            &[],
            &[],
            std::slice::from_ref(&grant_true),
            std::slice::from_ref(&override_true),
            &[],
            now
        )
        .is_granted(&key)
    );

    let held = resolve_with(
        &[],
        &[],
        &[],
        std::slice::from_ref(&override_true),
        std::slice::from_ref(&denial),
        now,
    );
    assert_eq!(
        held.decision(&key),
        EntitlementDecision::NotGranted(EntitlementDenialReason::DeniedByLegalHold)
    );
    assert_eq!(
        held.decision(&key).reason_code(),
        Some("entitlement_not_granted")
    );

    // The denial is still time-bounded and auditable.
    let expiring = EntitlementDenial::new(
        key.clone(),
        EntitlementScope::organization(),
        EntitlementDenialReason::DeniedByLegalHold,
        "sec_fedcba9876543210fedcba9876543210",
        0,
        Some(2_000),
    )
    .unwrap();
    assert!(
        !resolve_with(&[], &[], &[], &[], std::slice::from_ref(&expiring), 2_000).is_granted(&key)
    );
    assert!(
        resolve_with(
            &[],
            &[],
            &[],
            std::slice::from_ref(&override_true),
            std::slice::from_ref(&expiring),
            2_001
        )
        .is_granted(&key)
    );
    assert_eq!(
        EntitlementDenial::new(
            key.clone(),
            EntitlementScope::organization(),
            EntitlementDenialReason::NotConfigured,
            "sec_0123456789abcdef0123456789abcdef",
            0,
            None,
        )
        .err(),
        Some(EntitlementError::InvalidClaims)
    );
}

#[test]
fn grant_activity_window_is_honoured() {
    let key = ent_key("webhooks.enabled");
    let expired = EntitlementGrant::new(
        distinct_grant_id(1),
        org_id(),
        key.clone(),
        EntitlementValue::boolean(true),
        GrantSource::Subscription,
        EntitlementScope::organization(),
        None,
        100,
        Some(200),
        None,
    )
    .unwrap();
    assert!(!expired.is_active_at(99));
    assert!(expired.is_active_at(100));
    assert!(expired.is_active_at(199));
    assert!(!expired.is_active_at(200));

    let revoked = EntitlementGrant::new(
        distinct_grant_id(2),
        org_id(),
        key,
        EntitlementValue::boolean(true),
        GrantSource::Subscription,
        EntitlementScope::organization(),
        None,
        100,
        None,
        Some(150),
    )
    .unwrap();
    assert!(revoked.is_active_at(149));
    assert!(!revoked.is_active_at(150));

    assert_eq!(
        EntitlementGrant::new(
            distinct_grant_id(3),
            org_id(),
            ent_key("webhooks.enabled"),
            EntitlementValue::boolean(true),
            GrantSource::Plan,
            EntitlementScope::organization(),
            None,
            100,
            Some(100),
            None,
        )
        .err(),
        Some(EntitlementError::InvalidPeriod)
    );
}

#[test]
fn cross_tenant_and_misfiled_grants_are_refused() {
    let key = ent_key("webhooks.enabled");
    let foreign = EntitlementGrant::new(
        distinct_grant_id(1),
        other_org_id(),
        key.clone(),
        EntitlementValue::boolean(true),
        GrantSource::Subscription,
        EntitlementScope::organization(),
        None,
        0,
        None,
        None,
    )
    .unwrap();
    let err = resolve_effective_entitlements(&EntitlementResolution {
        org_id: &org_id(),
        scope: EntitlementScope::organization(),
        now: 100,
        inputs: EntitlementInputs {
            platform_defaults: &[],
            plan_grants: &[],
            subscription_grants: std::slice::from_ref(&foreign),
            internal_overrides: &[],
            denials: &[],
        },
    })
    .err();
    assert_eq!(err, Some(EntitlementError::CrossTenantGrant));
    assert_eq!(err.unwrap().code(), "resource_not_found");

    let own = grant(
        1,
        &key,
        EntitlementValue::boolean(true),
        GrantSource::Subscription,
        0,
    );
    let err = resolve_effective_entitlements(&EntitlementResolution {
        org_id: &org_id(),
        scope: EntitlementScope::organization(),
        now: 100,
        inputs: EntitlementInputs {
            platform_defaults: &[],
            plan_grants: std::slice::from_ref(&own),
            subscription_grants: &[],
            internal_overrides: &[],
            denials: &[],
        },
    })
    .err();
    assert_eq!(err, Some(EntitlementError::SourceScopeMismatch));
}

#[test]
fn an_unregistered_key_is_refused_at_every_boundary() {
    let fabricated = ent_key("price.team");
    assert_eq!(
        EntitlementGrant::new(
            distinct_grant_id(1),
            org_id(),
            fabricated.clone(),
            EntitlementValue::integer(1).unwrap(),
            GrantSource::Plan,
            EntitlementScope::organization(),
            None,
            0,
            None,
            None,
        )
        .err(),
        Some(EntitlementError::UnknownEntitlementKey)
    );

    let err = resolve_effective_entitlements(&EntitlementResolution {
        org_id: &org_id(),
        scope: EntitlementScope::organization(),
        now: 100,
        inputs: EntitlementInputs {
            platform_defaults: &[],
            plan_grants: &[],
            subscription_grants: &[],
            internal_overrides: &[],
            denials: &[EntitlementDenial::new(
                fabricated,
                EntitlementScope::organization(),
                EntitlementDenialReason::DeniedByLegalHold,
                "sec_0123456789abcdef0123456789abcdef",
                0,
                None,
            )
            .unwrap()],
        },
    })
    .err();
    assert_eq!(err, Some(EntitlementError::UnknownEntitlementKey));
}

#[test]
fn entitlement_projection_values_match_the_frozen_wire_shape() {
    let now = 1_000;
    let plan = [
        grant(
            1,
            &ent_key("automations.max_active"),
            EntitlementValue::integer(100).unwrap(),
            GrantSource::Plan,
            0,
        ),
        grant(
            2,
            &ent_key("webhooks.enabled"),
            EntitlementValue::boolean(true),
            GrantSource::Plan,
            0,
        ),
        grant(
            3,
            &ent_key("exports.enabled"),
            EntitlementValue::boolean(true),
            GrantSource::Plan,
            0,
        ),
    ];
    let effective = resolve_with(&[], &plan, &[], &[], &[], now);
    let values = effective.values();
    let wire = serde_json::to_value(&values).unwrap();
    for name in [
        "automations.max_active",
        "webhooks.enabled",
        "exports.enabled",
    ] {
        assert!(wire.get(name).is_some(), "missing {name}");
    }
    assert_eq!(wire["automations.max_active"], json!(100));
    assert_eq!(wire["webhooks.enabled"], json!(true));
    assert_eq!(wire["exports.enabled"], json!(true));
    assert_eq!(
        wire.as_object().unwrap().len(),
        BASELINE_ENTITLEMENT_KEY_COUNT
    );
    // Round-trips through the frozen native scalar form.
    let restored: std::collections::BTreeMap<EntitlementKey, EntitlementValue> =
        serde_json::from_value(wire).unwrap();
    assert_eq!(restored.len(), BASELINE_ENTITLEMENT_KEY_COUNT);
    assert_eq!(
        restored[&ent_key("automations.max_active")].as_integer(),
        Some(100)
    );
}

// ---------------------------------------------------------------------------
// Provider entitlement separation
// ---------------------------------------------------------------------------

#[test]
fn provider_entitlement_projection_is_read_only_status() {
    let projection = ProviderEntitlementProjection::new(
        ProviderEntitlementProjectionId::new("pep_0123456789abcdef0123456789abcdef").unwrap(),
        org_id(),
        "upstream_ai",
        ProviderEntitlementStatus::Available,
        Some("provider_managed_inference".to_owned()),
        1_000,
    )
    .unwrap();
    assert!(projection.route_usable());
    assert_eq!(projection.availability(), ProviderAvailability::Available);
    assert_eq!(
        serde_json::to_value(&projection).unwrap(),
        json!({
            "projection_id": "pep_0123456789abcdef0123456789abcdef",
            "org_id": "org_0123456789abcdef0123456789abcdef",
            "provider": "upstream_ai",
            "status": "available",
            "provider_capability": "provider_managed_inference",
            "observed_at": 1000i64,
        })
    );

    for (status, usable, availability) in [
        (
            ProviderEntitlementStatus::Available,
            true,
            ProviderAvailability::Available,
        ),
        (
            ProviderEntitlementStatus::Degraded,
            false,
            ProviderAvailability::Degraded,
        ),
        (
            ProviderEntitlementStatus::Unavailable,
            false,
            ProviderAvailability::Unavailable,
        ),
        (
            ProviderEntitlementStatus::Unknown,
            false,
            ProviderAvailability::Unknown,
        ),
    ] {
        assert_eq!(status.as_str(), format!("{status:?}").to_lowercase());
        assert_eq!(
            ProviderEntitlementStatus::parse(status.as_str()),
            Some(status)
        );
        let degraded = ProviderEntitlementProjection::new(
            ProviderEntitlementProjectionId::new("pep_0123456789abcdef0123456789abcdef").unwrap(),
            org_id(),
            "upstream_ai",
            status,
            None,
            1_000,
        )
        .unwrap();
        assert_eq!(degraded.route_usable(), usable);
        assert_eq!(degraded.availability(), availability);
    }

    assert!(
        ProviderEntitlementProjection::new(
            ProviderEntitlementProjectionId::new("pep_0123456789abcdef0123456789abcdef").unwrap(),
            org_id(),
            "",
            ProviderEntitlementStatus::Available,
            None,
            0,
        )
        .is_err()
    );
}

#[test]
fn provider_account_state_cannot_change_lumi_entitlements_or_subscription_state() {
    // The separation is behavioural, not just documented: flipping every
    // upstream status leaves the resolved entitlements byte-identical.
    let now = 1_000;
    let plan = [grant(
        1,
        &ent_key("automations.max_active"),
        EntitlementValue::integer(3).unwrap(),
        GrantSource::Plan,
        0,
    )];
    let before = resolve_with(&[], &plan, &[], &[], &[], now);

    for status in [
        ProviderEntitlementStatus::Available,
        ProviderEntitlementStatus::Degraded,
        ProviderEntitlementStatus::Unavailable,
        ProviderEntitlementStatus::Unknown,
    ] {
        let _projection = ProviderEntitlementProjection::new(
            ProviderEntitlementProjectionId::new("pep_0123456789abcdef0123456789abcdef").unwrap(),
            org_id(),
            "upstream_ai",
            status,
            None,
            now,
        )
        .unwrap();
        assert_eq!(before, resolve_with(&[], &plan, &[], &[], &[], now));
    }
    // A provider projection is never one of the four precedence inputs.
    let inputs = EntitlementInputs {
        platform_defaults: &[],
        plan_grants: &plan,
        subscription_grants: &[],
        internal_overrides: &[],
        denials: &[],
    };
    assert!(inputs.platform_defaults.is_empty());
}

// ---------------------------------------------------------------------------
// Downgrade / over-limit projection
// ---------------------------------------------------------------------------

#[test]
fn downgrade_over_limit_blocks_new_and_expansion_without_deleting() {
    // negative_fixtures.over_limit_downgrade: starter, limit 3, 7 active.
    let now = 1_000;
    let plan = [grant(
        1,
        &ent_key("automations.max_active"),
        EntitlementValue::integer(3).unwrap(),
        GrantSource::Plan,
        0,
    )];
    let effective = resolve_with(&[], &plan, &[], &[], &[], now);
    let counts = AuthoritativeCounts {
        members: 0,
        active_projects: 0,
        enrolled_devices: 0,
        active_automations: 7,
        webhook_endpoints: 0,
    };
    let projection = compute_over_limit_projection(&org_id(), counts, &effective, now);

    assert!(!projection.deletes_data());
    const { assert!(!DOWNGRADE_DELETES_DATA) };
    assert!(projection.blocks_new_and_expansion());
    assert_eq!(projection.reason().code(), "entitlement_limit_exceeded");
    assert_eq!(projection.items().len(), 1);

    let item = projection.item(&ent_key("automations.max_active")).unwrap();
    assert_eq!(item.limit, 3);
    assert_eq!(item.current, 7);
    assert_eq!(item.over_by, 4);
    assert!(item.blocks.create);
    assert!(item.blocks.expand);
    assert!(!item.blocks.delete_data);
    assert_eq!(
        item.remediation,
        OverLimitRemediation::ReduceToLimit { target: 3 }
    );
    assert!(!item.remediation.blocks().delete_data);

    // Nothing new fits, nothing expands, and reading the data stays possible.
    assert!(!projection.allows_addition(&ent_key("automations.max_active"), 0));
    assert!(!projection.allows_addition(&ent_key("automations.max_active"), 1));
    assert!(projection.allows_addition(&ent_key("webhooks.max_endpoints"), 0));
    assert!(!projection.allows_addition(&ent_key("webhooks.max_endpoints"), 1));
    // The historical rows are still counted: the projection never pretends the
    // over-limit automations were removed.
    assert_eq!(projection.counts.active_automations, 7);
}

#[test]
fn over_limit_projection_reports_every_resource_above_its_new_limit() {
    let now = 2_000;
    let plan = [
        grant(
            1,
            &ent_key("automations.max_active"),
            EntitlementValue::integer(1).unwrap(),
            GrantSource::Plan,
            0,
        ),
        grant(
            2,
            &ent_key("devices.max_enrolled"),
            EntitlementValue::integer(2).unwrap(),
            GrantSource::Plan,
            0,
        ),
        grant(
            3,
            &ent_key("org.max_members"),
            EntitlementValue::integer(3).unwrap(),
            GrantSource::Plan,
            0,
        ),
        grant(
            4,
            &ent_key("projects.max_active"),
            EntitlementValue::integer(1).unwrap(),
            GrantSource::Plan,
            0,
        ),
        grant(
            5,
            &ent_key("webhooks.max_endpoints"),
            EntitlementValue::integer(1).unwrap(),
            GrantSource::Plan,
            0,
        ),
    ];
    let effective = resolve_with(&[], &plan, &[], &[], &[], now);
    let counts = AuthoritativeCounts {
        members: 5,
        active_projects: 4,
        enrolled_devices: 3,
        active_automations: 3,
        webhook_endpoints: 0,
    };
    let projection = compute_over_limit_projection(&org_id(), counts, &effective, now);
    let names: Vec<&str> = projection
        .items()
        .iter()
        .map(|item| item.key.as_str())
        .collect();
    assert_eq!(
        names,
        vec![
            "automations.max_active",
            "devices.max_enrolled",
            "org.max_members",
            "projects.max_active",
        ]
    );
    assert_eq!(
        projection
            .item(&ent_key("org.max_members"))
            .unwrap()
            .remediation,
        OverLimitRemediation::SuspendSeats { target: 3 }
    );
    assert_eq!(
        projection
            .item(&ent_key("devices.max_enrolled"))
            .unwrap()
            .over_by,
        1
    );
    assert_eq!(
        projection
            .item(&ent_key("automations.max_active"))
            .unwrap()
            .over_by,
        2
    );
    assert_eq!(
        projection
            .item(&ent_key("projects.max_active"))
            .unwrap()
            .over_by,
        3
    );
    // `webhooks.max_endpoints` is inside its limit and is not reported.
    assert!(
        projection
            .item(&ent_key("webhooks.max_endpoints"))
            .is_none()
    );
    assert_eq!(
        EntitlementDenialReason::LimitExceeded.code(),
        "entitlement_limit_exceeded"
    );
}

#[test]
fn an_ungranted_limit_fails_closed_in_the_over_limit_projection() {
    let now = 3_000;
    let effective = resolve_with(&[], &[], &[], &[], &[], now);
    let counts = AuthoritativeCounts {
        members: 1,
        active_projects: 0,
        enrolled_devices: 0,
        active_automations: 0,
        webhook_endpoints: 0,
    };
    let projection = compute_over_limit_projection(&org_id(), counts, &effective, now);
    let item = projection.item(&ent_key("org.max_members")).unwrap();
    assert_eq!(item.limit, 0);
    assert_eq!(item.over_by, 1);
    assert!(!projection.allows_addition(&ent_key("org.max_members"), 0));
    // An unregistered key is not a capacity question at all.
    assert!(projection.allows_addition(&ent_key("price.team"), 100));
}

#[test]
fn over_limit_projection_is_deterministic_and_wire_serializable() {
    let now = 4_000;
    let plan = [grant(
        1,
        &ent_key("automations.max_active"),
        EntitlementValue::integer(1).unwrap(),
        GrantSource::Plan,
        0,
    )];
    let effective = resolve_with(&[], &plan, &[], &[], &[], now);
    let counts = AuthoritativeCounts {
        members: 0,
        active_projects: 0,
        enrolled_devices: 0,
        active_automations: 9,
        webhook_endpoints: 0,
    };
    let first = compute_over_limit_projection(&org_id(), counts, &effective, now);
    let second = compute_over_limit_projection(&org_id(), counts, &effective, now);
    assert_eq!(first, second);
    assert_eq!(first.computed_at, now);
    let wire = serde_json::to_value(&first).unwrap();
    assert_eq!(wire["items"][0]["key"], json!("automations.max_active"));
    assert_eq!(wire["items"][0]["over_by"], json!(8));
    assert!(!wire["items"][0]["blocks"]["delete_data"].as_bool().unwrap());
}

// ---------------------------------------------------------------------------
// License state capability matrix
// ---------------------------------------------------------------------------

fn matrix_evaluation(
    state: LicenseState,
    provider: ProviderAvailability,
    class: CapabilityClass,
    now: i64,
    policy_fresh_until: i64,
    offline_valid_until: i64,
) -> LicenseDecision {
    evaluate_license(
        state,
        provider,
        class,
        now,
        policy_fresh_until,
        offline_valid_until,
    )
}

#[test]
fn license_state_and_capability_class_use_frozen_wire_vocabulary() {
    for state in [
        LicenseState::Active,
        LicenseState::Grace,
        LicenseState::PastDue,
        LicenseState::Suspended,
        LicenseState::Cancelled,
        LicenseState::Expired,
        LicenseState::ProviderUnavailable,
    ] {
        assert_eq!(LicenseState::parse(state.as_str()), Some(state));
        assert_eq!(
            serde_json::to_string(&state).unwrap(),
            format!("\"{}\"", state.as_str())
        );
    }
    assert_eq!(LicenseState::parse("past_due"), Some(LicenseState::PastDue));
    assert_eq!(
        LicenseState::parse("provider_unavailable"),
        Some(LicenseState::ProviderUnavailable)
    );
    assert_eq!(LicenseState::parse("pastdue"), None);

    for class in [
        CapabilityClass::LocalOnly,
        CapabilityClass::CloudControlPlane,
        CapabilityClass::PlatformPaidInference,
    ] {
        assert_eq!(CapabilityClass::parse(class.as_str()), Some(class));
    }
    assert_eq!(CapabilityClass::LocalOnly.default_grace_seconds(), 604_800);
    assert_eq!(
        CapabilityClass::CloudControlPlane.default_grace_seconds(),
        86_400
    );
    assert_eq!(
        CapabilityClass::PlatformPaidInference.default_grace_seconds(),
        0
    );
    assert!(CapabilityClass::CloudControlPlane.requires_policy_freshness());
    assert!(!CapabilityClass::LocalOnly.requires_policy_freshness());
    assert!(!CapabilityClass::PlatformPaidInference.requires_policy_freshness());
}

#[test]
fn baseline_grace_windows_may_only_be_narrowed() {
    assert_eq!(
        CapabilityClass::LocalOnly.narrow_grace_seconds(None),
        604_800
    );
    assert_eq!(
        CapabilityClass::LocalOnly.narrow_grace_seconds(Some(3_600)),
        3_600
    );
    assert_eq!(
        CapabilityClass::LocalOnly.narrow_grace_seconds(Some(604_801)),
        604_800
    );
    assert_eq!(
        CapabilityClass::LocalOnly.narrow_grace_seconds(Some(0)),
        604_800
    );
    assert_eq!(
        CapabilityClass::LocalOnly.narrow_grace_seconds(Some(-1)),
        604_800
    );
    // Platform-paid inference can never be widened into a billing grace.
    assert_eq!(
        CapabilityClass::PlatformPaidInference.narrow_grace_seconds(Some(604_800)),
        0
    );
    assert_eq!(
        CapabilityClass::CloudControlPlane.narrow_grace_seconds(Some(86_400)),
        86_400
    );
    assert_eq!(
        CapabilityClass::CloudControlPlane.narrow_grace_seconds(Some(900)),
        900
    );
    assert_eq!(
        GraceWindow::ceiling_seconds(MAX_GRACE_WINDOW_SECONDS + 1),
        MAX_GRACE_WINDOW_SECONDS
    );
    assert_eq!(GraceWindow::ceiling_seconds(-5), 0);
}

#[test]
fn license_state_is_projected_from_subscription_status() {
    assert_eq!(
        LicenseState::from_subscription_status(
            SubscriptionStatus::Trialing,
            ProviderAvailability::Available
        ),
        LicenseState::Active
    );
    for status in [
        SubscriptionStatus::Trialing,
        SubscriptionStatus::Active,
        SubscriptionStatus::Grace,
        SubscriptionStatus::PastDue,
        SubscriptionStatus::Suspended,
        SubscriptionStatus::Cancelled,
    ] {
        for provider in [
            ProviderAvailability::Available,
            ProviderAvailability::Degraded,
            ProviderAvailability::Unknown,
        ] {
            assert_eq!(
                LicenseState::from_subscription_status(status, provider),
                LicenseState::license_state_for_status(status),
                "{status:?} with {provider:?}"
            );
        }
        assert_eq!(
            LicenseState::from_subscription_status(status, ProviderAvailability::Unavailable),
            LicenseState::ProviderUnavailable
        );
    }
}

#[test]
fn active_with_provider_available_allows_every_capability_class() {
    // negative_fixtures.license_state_matrix.active
    let now = 1_000;
    let decision = matrix_evaluation(
        LicenseState::Active,
        ProviderAvailability::Available,
        CapabilityClass::LocalOnly,
        now,
        now + 900,
        now + 604_800,
    );
    assert!(decision.allowed);
    assert!(decision.in_flight_allowed);
    assert_eq!(decision.reason, None);
    assert_eq!(decision.expires_at, Some(now + 604_800));

    let cloud = matrix_evaluation(
        LicenseState::Active,
        ProviderAvailability::Available,
        CapabilityClass::CloudControlPlane,
        now,
        now + 900,
        now + 604_800,
    );
    assert!(cloud.allowed);
    assert_eq!(cloud.expires_at, Some(now + 900));

    let paid = matrix_evaluation(
        LicenseState::Active,
        ProviderAvailability::Available,
        CapabilityClass::PlatformPaidInference,
        now,
        now + 900,
        now + 604_800,
    );
    assert!(paid.allowed);
    assert_eq!(paid.reason, None);
}

#[test]
fn grace_allows_local_until_offline_expiry_and_cloud_until_cloud_grace() {
    // negative_fixtures.license_state_matrix.grace
    let now = 1_000;
    let request = |class: CapabilityClass, at: i64, policy_fresh: i64| {
        evaluate_license_request(
            &LicenseEvaluationRequest::new(
                LicenseState::Grace,
                ProviderAvailability::Available,
                class,
                at,
                policy_fresh,
                now + 604_800,
            )
            .with_grace_started_at(now),
        )
    };

    let local = request(CapabilityClass::LocalOnly, now, now + 900);
    assert!(local.allowed);
    assert_eq!(local.expires_at, Some(now + 604_800));

    // The decision expires at the first binding constraint, so with a fresh
    // policy the cloud grace window is the limit.
    let cloud = request(CapabilityClass::CloudControlPlane, now, now + 200_000);
    assert!(cloud.allowed);
    assert_eq!(cloud.expires_at, Some(now + 86_400));
    // With a 15-minute policy-fresh window, that window binds first.
    let cloud_policy_bound = request(CapabilityClass::CloudControlPlane, now, now + 900);
    assert!(cloud_policy_bound.allowed);
    assert_eq!(cloud_policy_bound.expires_at, Some(now + 900));

    // Cloud grace ends at 24 hours; the local 7-day window is not shortened by
    // the cloud window and not extended by it.
    let cloud_late = request(
        CapabilityClass::CloudControlPlane,
        now + 86_400,
        now + 200_000,
    );
    assert!(!cloud_late.allowed);
    assert_eq!(
        cloud_late.reason,
        Some(LicenseReason::EntitlementGraceExpired)
    );
    assert_eq!(cloud_late.expires_at, Some(now + 86_400));
    assert!(request(CapabilityClass::LocalOnly, now + 604_799, now + 900).allowed);
    assert!(!request(CapabilityClass::LocalOnly, now + 604_800, now + 900).allowed);

    // A narrowed capability window shortens, never lengthens, cloud grace.
    let narrowed = evaluate_license_request(
        &LicenseEvaluationRequest::new(
            LicenseState::Grace,
            ProviderAvailability::Available,
            CapabilityClass::CloudControlPlane,
            now + 3_600,
            now + 10_000,
            now + 604_800,
        )
        .with_grace_started_at(now)
        .with_capability_grace_seconds(1_800),
    );
    assert!(!narrowed.allowed);
    assert_eq!(
        narrowed.reason,
        Some(LicenseReason::EntitlementGraceExpired)
    );

    // Platform-paid inference receives no billing grace at all: with a
    // confirmed-available provider the zero-length window is already spent, and
    // an unconfirmed provider adds the provider reason on top.
    for (provider, code) in [
        (ProviderAvailability::Available, "entitlement_grace_expired"),
        (
            ProviderAvailability::Degraded,
            "provider_entitlement_unavailable",
        ),
        (
            ProviderAvailability::Unavailable,
            "provider_entitlement_unavailable",
        ),
        (
            ProviderAvailability::Unknown,
            "provider_entitlement_unavailable",
        ),
    ] {
        let paid = evaluate_license_request(
            &LicenseEvaluationRequest::new(
                LicenseState::Grace,
                provider,
                CapabilityClass::PlatformPaidInference,
                now,
                now + 900,
                now + 604_800,
            )
            .with_grace_started_at(now),
        );
        assert!(
            !paid.allowed,
            "paid inference must be denied for {provider:?}"
        );
        assert!(!paid.in_flight_allowed);
        assert_eq!(paid.reason_code(), Some(code), "for {provider:?}");
    }
}

#[test]
fn cloud_managed_work_requires_current_policy_freshness() {
    let now = 1_000;
    let stale = evaluate_license_request(
        &LicenseEvaluationRequest::new(
            LicenseState::Grace,
            ProviderAvailability::Available,
            CapabilityClass::CloudControlPlane,
            now + 901,
            now + 900,
            now + 604_800,
        )
        .with_grace_started_at(now),
    );
    assert!(!stale.allowed);
    assert_eq!(stale.reason_code(), Some("license_snapshot_expired"));

    // The same instant is still fine for local-only work: local execution may run
    // from the previously signed snapshot.
    let local = matrix_evaluation(
        LicenseState::Grace,
        ProviderAvailability::Available,
        CapabilityClass::LocalOnly,
        now + 901,
        now + 900,
        now + 604_800,
    );
    assert!(local.allowed);
}

#[test]
fn past_due_allows_only_local_work_until_the_signed_offline_expiry() {
    // negative_fixtures.license_state_matrix.past_due
    let now = 1_000;
    for class in [
        CapabilityClass::CloudControlPlane,
        CapabilityClass::PlatformPaidInference,
    ] {
        for provider in [
            ProviderAvailability::Available,
            ProviderAvailability::Degraded,
            ProviderAvailability::Unavailable,
            ProviderAvailability::Unknown,
        ] {
            let decision = matrix_evaluation(
                LicenseState::PastDue,
                provider,
                class,
                now,
                now + 900,
                now + 604_800,
            );
            assert!(!decision.allowed, "{class:?}/{provider:?} must be denied");
            assert!(!decision.in_flight_allowed);
        }
    }

    let local = matrix_evaluation(
        LicenseState::PastDue,
        ProviderAvailability::Available,
        CapabilityClass::LocalOnly,
        now,
        now + 900,
        now + 604_800,
    );
    assert!(local.allowed);
    assert!(local.in_flight_allowed);

    let expired_local = matrix_evaluation(
        LicenseState::PastDue,
        ProviderAvailability::Available,
        CapabilityClass::LocalOnly,
        now + 604_800,
        now + 900,
        now + 604_800,
    );
    assert!(!expired_local.allowed);
    assert!(expired_local.in_flight_allowed);
    assert_eq!(
        expired_local.reason_code(),
        Some("entitlement_grace_expired")
    );
    assert_eq!(expired_local.expires_at, Some(now + 604_800));
}

#[test]
fn suspended_and_cancelled_stop_new_work_everywhere() {
    // negative_fixtures.license_state_matrix.suspended / cancelled
    let now = 1_000;
    for state in [LicenseState::Suspended, LicenseState::Cancelled] {
        for class in [
            CapabilityClass::LocalOnly,
            CapabilityClass::CloudControlPlane,
            CapabilityClass::PlatformPaidInference,
        ] {
            let decision = matrix_evaluation(
                state,
                ProviderAvailability::Available,
                class,
                now,
                now + 900,
                now + 604_800,
            );
            assert!(!decision.allowed, "{state:?}/{class:?} admitted new work");
            assert_eq!(
                decision.reason_code(),
                Some("entitlement_not_granted"),
                "{state:?}/{class:?}"
            );
            assert!(decision.needs_new_commercial_state());
            assert_eq!(decision.expires_at, None);
            if class == CapabilityClass::LocalOnly {
                // Already-authorized in-flight local work still settles.
                assert!(decision.in_flight_allowed);
            } else {
                assert!(!decision.in_flight_allowed);
            }
        }
    }
}

#[test]
fn expired_license_state_is_terminal_for_new_work() {
    let now = 1_000;
    for class in [
        CapabilityClass::LocalOnly,
        CapabilityClass::CloudControlPlane,
        CapabilityClass::PlatformPaidInference,
    ] {
        let decision = matrix_evaluation(
            LicenseState::Expired,
            ProviderAvailability::Available,
            class,
            now,
            now + 900,
            now + 604_800,
        );
        assert!(
            !decision.allowed,
            "{class:?} admitted work for an expired license"
        );
        assert_eq!(decision.reason_code(), Some("entitlement_grace_expired"));
        assert!(decision.needs_new_commercial_state());
    }
}

#[test]
fn provider_unreachable_leaves_local_work_untouched() {
    let now = 1_000;
    let local = matrix_evaluation(
        LicenseState::ProviderUnavailable,
        ProviderAvailability::Unavailable,
        CapabilityClass::LocalOnly,
        now,
        now + 900,
        now + 604_800,
    );
    assert!(local.allowed, "a billing outage must not brick local work");
    assert_eq!(local.reason, None);
    assert_eq!(local.expires_at, Some(now + 604_800));

    // Cloud follows the last observed subscription grace...
    let cloud_grace = evaluate_license_request(
        &LicenseEvaluationRequest::new(
            LicenseState::ProviderUnavailable,
            ProviderAvailability::Unavailable,
            CapabilityClass::CloudControlPlane,
            now,
            now + 200_000,
            now + 604_800,
        )
        .with_grace_started_at(now)
        .with_last_known_subscription(SubscriptionStatus::Grace),
    );
    assert!(cloud_grace.allowed);
    assert_eq!(cloud_grace.expires_at, Some(now + 86_400));

    let cloud_active = evaluate_license_request(
        &LicenseEvaluationRequest::new(
            LicenseState::ProviderUnavailable,
            ProviderAvailability::Unavailable,
            CapabilityClass::CloudControlPlane,
            now,
            now + 900,
            now + 604_800,
        )
        .with_last_known_subscription(SubscriptionStatus::Active),
    );
    assert!(cloud_active.allowed);

    let cloud_past_due = evaluate_license_request(
        &LicenseEvaluationRequest::new(
            LicenseState::ProviderUnavailable,
            ProviderAvailability::Unavailable,
            CapabilityClass::CloudControlPlane,
            now,
            now + 900,
            now + 604_800,
        )
        .with_last_known_subscription(SubscriptionStatus::PastDue),
    );
    assert!(!cloud_past_due.allowed);
    assert_eq!(
        cloud_past_due.reason_code(),
        Some("entitlement_grace_expired")
    );

    // ...and unknown commercial state fails closed for cloud work.
    let cloud_unknown = matrix_evaluation(
        LicenseState::ProviderUnavailable,
        ProviderAvailability::Unavailable,
        CapabilityClass::CloudControlPlane,
        now,
        now + 900,
        now + 604_800,
    );
    assert!(!cloud_unknown.allowed);
    assert_eq!(
        cloud_unknown.reason_code(),
        Some("subscription_state_unavailable")
    );

    let paid = matrix_evaluation(
        LicenseState::ProviderUnavailable,
        ProviderAvailability::Unavailable,
        CapabilityClass::PlatformPaidInference,
        now,
        now + 900,
        now + 604_800,
    );
    assert!(!paid.allowed);
    assert_eq!(paid.reason_code(), Some("provider_entitlement_unavailable"));
}

#[test]
fn transient_billing_outage_denies_paid_inference_with_a_stable_reason() {
    // negative_fixtures.transient_billing_outage
    let now = 1_000;
    let request = LicenseEvaluationRequest::new(
        LicenseState::Grace,
        ProviderAvailability::Degraded,
        CapabilityClass::PlatformPaidInference,
        now,
        now + 900,
        now + 604_800,
    )
    .with_grace_started_at(now);
    let decision = evaluate_license_request(&request);
    assert!(!decision.allowed);
    // The same stable reason is returned for every degraded/unknown observation.
    let repeated = evaluate_license_request(&request);
    assert_eq!(decision, repeated);
    assert_eq!(
        decision.reason_code(),
        Some("provider_entitlement_unavailable")
    );

    let local = evaluate_license_request(&LicenseEvaluationRequest {
        state: LicenseState::Grace,
        provider: ProviderAvailability::Degraded,
        capability_class: CapabilityClass::LocalOnly,
        now,
        policy_fresh_until: now + 900,
        offline_valid_until: now + 604_800,
        grace_started_at: Some(now),
        capability_grace_seconds: None,
        last_known_subscription: None,
    });
    assert!(
        local.allowed,
        "local execution must survive a transient outage"
    );
}

#[test]
fn grace_without_a_known_anchor_fails_closed_for_cloud_work() {
    let now = 1_000;
    let decision = matrix_evaluation(
        LicenseState::Grace,
        ProviderAvailability::Available,
        CapabilityClass::CloudControlPlane,
        now,
        now + 900,
        now + 604_800,
    );
    assert!(!decision.allowed);
    assert_eq!(
        decision.reason_code(),
        Some("subscription_state_unavailable")
    );
    assert_eq!(decision.expires_at, Some(now + 900));
}

#[test]
fn license_reason_codes_are_drawn_from_the_frozen_error_list() {
    for (reason, code) in [
        (
            LicenseReason::EntitlementNotGranted,
            "entitlement_not_granted",
        ),
        (
            LicenseReason::EntitlementGraceExpired,
            "entitlement_grace_expired",
        ),
        (
            LicenseReason::LicenseSnapshotExpired,
            "license_snapshot_expired",
        ),
        (
            LicenseReason::LicenseAudienceMismatch,
            "license_audience_mismatch",
        ),
        (LicenseReason::LicenseKeyUnknown, "license_key_unknown"),
        (
            LicenseReason::LicensePolicyRollback,
            "license_policy_rollback",
        ),
        (
            LicenseReason::ProviderEntitlementUnavailable,
            "provider_entitlement_unavailable",
        ),
        (
            LicenseReason::SubscriptionStateUnavailable,
            "subscription_state_unavailable",
        ),
    ] {
        assert_eq!(reason.code(), code);
        assert_eq!(
            serde_json::to_string(&reason).unwrap(),
            format!("\"{code}\"")
        );
    }
}

// ---------------------------------------------------------------------------
// License snapshot claims
// ---------------------------------------------------------------------------

fn claims() -> LicenseSnapshotClaims {
    LicenseSnapshotClaims::new(
        LicenseSnapshotId::new("lic_0123456789abcdef0123456789abcdef").unwrap(),
        org_id(),
        Some(device_id()),
        Some("device:lumi-agents-desktop".to_owned()),
        4,
        1_789_720_500,
        1_791_327_600,
        1_789_719_600,
        CapabilityClass::LocalOnly,
        "key_2026_01",
    )
    .unwrap()
}

fn snapshot_context<'a>(
    now: i64,
    org: &'a OrganizationId,
    device: Option<&'a ManagedDeviceId>,
    keys: &'a [&'a str],
    policy_version: i64,
) -> LicenseSnapshotContext<'a> {
    LicenseSnapshotContext {
        now,
        expected_org_id: org,
        expected_device_id: device,
        trusted_key_ids: keys,
        last_accepted_policy_version: policy_version,
    }
}

#[test]
fn a_verified_claim_set_validates_and_its_wire_shape_is_stable() {
    let claims = claims();
    assert_eq!(claims.schema_version, LICENSE_SNAPSHOT_SCHEMA_VERSION);
    assert_eq!(
        validate_license_snapshot(
            &claims,
            &snapshot_context(
                1_789_719_600,
                &org_id(),
                Some(&device_id()),
                &["key_2026_01"],
                4
            )
        ),
        Ok(())
    );
    let wire = serde_json::to_value(&claims).unwrap();
    assert_eq!(wire["schema_version"], json!(1));
    assert_eq!(
        wire["snapshot_id"],
        json!("lic_0123456789abcdef0123456789abcdef")
    );
    assert_eq!(wire["policy_version"], json!(4));
    assert_eq!(wire["capability_class"], json!("local_only"));
    assert_eq!(wire["key_id"], json!("key_2026_01"));
    // The claim struct deliberately carries no signature field: verification is
    // the crypto adapter's job and cannot be skipped by deserialization.
    assert!(wire.get("signature").is_none());
}

#[test]
fn snapshot_validation_rejects_every_frozen_failure_mode() {
    let mut unknown_key = claims();
    unknown_key.key_id = "key_retired".to_owned();
    assert_eq!(
        validate_license_snapshot(
            &unknown_key,
            &snapshot_context(
                1_789_719_600,
                &org_id(),
                Some(&device_id()),
                &["key_2026_01"],
                4
            )
        ),
        Err(LicenseReason::LicenseKeyUnknown)
    );

    let mut foreign_org = claims();
    foreign_org.org_id = other_org_id();
    assert_eq!(
        validate_license_snapshot(
            &foreign_org,
            &snapshot_context(
                1_789_719_600,
                &org_id(),
                Some(&device_id()),
                &["key_2026_01"],
                4
            )
        ),
        Err(LicenseReason::LicenseAudienceMismatch)
    );

    let other_device = ManagedDeviceId::new("dvc_fedcba9876543210fedcba9876543210").unwrap();
    assert_eq!(
        validate_license_snapshot(
            &claims(),
            &snapshot_context(
                1_789_719_600,
                &org_id(),
                Some(&other_device),
                &["key_2026_01"],
                4
            )
        ),
        Err(LicenseReason::LicenseAudienceMismatch)
    );
    // An org-level verifier must not accept a device-scoped snapshot.
    assert_eq!(
        validate_license_snapshot(
            &claims(),
            &snapshot_context(1_789_719_600, &org_id(), None, &["key_2026_01"], 4)
        ),
        Err(LicenseReason::LicenseAudienceMismatch)
    );

    let mut rolled_back = claims();
    rolled_back.policy_version = 3;
    assert_eq!(
        validate_license_snapshot(
            &rolled_back,
            &snapshot_context(
                1_789_719_600,
                &org_id(),
                Some(&device_id()),
                &["key_2026_01"],
                4
            )
        ),
        Err(LicenseReason::LicensePolicyRollback)
    );

    // 120 seconds of clock skew is tolerated in each direction.
    assert_eq!(
        validate_license_snapshot(
            &claims(),
            &snapshot_context(
                1_789_719_600 - MAX_CLOCK_SKEW_SECONDS,
                &org_id(),
                Some(&device_id()),
                &["key_2026_01"],
                4
            )
        ),
        Ok(())
    );
    assert_eq!(
        validate_license_snapshot(
            &claims(),
            &snapshot_context(
                1_789_719_600 - MAX_CLOCK_SKEW_SECONDS - 1,
                &org_id(),
                Some(&device_id()),
                &["key_2026_01"],
                4
            )
        ),
        Err(LicenseReason::LicenseSnapshotExpired)
    );

    let mut future = claims();
    future.issued_at = 1_789_719_600 + MAX_CLOCK_SKEW_SECONDS + 1;
    assert_eq!(
        validate_license_snapshot(
            &future,
            &snapshot_context(
                1_789_719_600,
                &org_id(),
                Some(&device_id()),
                &["key_2026_01"],
                4
            )
        ),
        Err(LicenseReason::LicenseSnapshotExpired)
    );

    let mut past_offline = claims();
    past_offline.offline_valid_until = 1_789_719_600;
    assert_eq!(
        validate_license_snapshot(
            &past_offline,
            &snapshot_context(
                1_789_719_601,
                &org_id(),
                Some(&device_id()),
                &["key_2026_01"],
                4
            )
        ),
        Err(LicenseReason::EntitlementNotGranted)
    );

    let mut unsupported_schema = claims();
    unsupported_schema.schema_version = 99;
    assert_eq!(
        validate_license_snapshot(
            &unsupported_schema,
            &snapshot_context(
                1_789_719_600,
                &org_id(),
                Some(&device_id()),
                &["key_2026_01"],
                4
            )
        ),
        Err(LicenseReason::EntitlementNotGranted)
    );
}

#[test]
fn license_snapshot_claims_construction_is_validated() {
    let ok = LicenseSnapshotClaims::new(
        LicenseSnapshotId::new("lic_0123456789abcdef0123456789abcdef").unwrap(),
        org_id(),
        None,
        None,
        1,
        1_100,
        1_200,
        1_000,
        CapabilityClass::CloudControlPlane,
        "key_a",
    );
    assert!(ok.is_ok());

    let oversized_key_id = "k".repeat(MAX_LICENSE_KEY_ID_BYTES + 1);
    let oversized_audience = "a".repeat(MAX_LICENSE_AUDIENCE_BYTES + 1);
    for (key_id, policy_version, audience) in [
        ("", 1_i64, None),
        (oversized_key_id.as_str(), 1, None),
        ("key_a", 0, None),
        ("key_a", 1, Some("")),
        ("key_a", 1, Some(oversized_audience.as_str())),
    ] {
        assert!(
            LicenseSnapshotClaims::new(
                LicenseSnapshotId::new("lic_0123456789abcdef0123456789abcdef").unwrap(),
                org_id(),
                None,
                audience.map(str::to_owned),
                policy_version,
                1_100,
                1_200,
                1_000,
                CapabilityClass::LocalOnly,
                key_id,
            )
            .is_err(),
            "accepted key_id={key_id} policy_version={policy_version}"
        );
    }

    assert!(
        LicenseSnapshotClaims::new(
            LicenseSnapshotId::new("lic_0123456789abcdef0123456789abcdef").unwrap(),
            org_id(),
            None,
            None,
            1,
            1_100,
            1_200,
            MAX_TIMESTAMP_UNIX_SECONDS + 1,
            CapabilityClass::LocalOnly,
            "key_a",
        )
        .is_err()
    );
}

// ---------------------------------------------------------------------------
// Subscription state machine
// ---------------------------------------------------------------------------

fn plan(key: &str) -> PlanPointer {
    PlanPointer::new(
        PlanId::new("plan_0123456789abcdef0123456789abcdef").unwrap(),
        key,
        1,
    )
    .unwrap()
}

fn subscription(status: SubscriptionStatus) -> Subscription {
    Subscription::new(
        SubscriptionId::new("sub_0123456789abcdef0123456789abcdef").unwrap(),
        org_id(),
        BillingAccountId::new("bac_0123456789abcdef0123456789abcdef").unwrap(),
        plan("team"),
        status,
        (status == SubscriptionStatus::Grace).then_some(1_086_400),
        Some(1_800_000_000),
        1,
        1_000,
    )
    .expect("subscription is valid")
}

#[test]
fn lumi_plan_keys_reject_every_provider_identifier_shape() {
    for good in ["team", "starter", "enterprise-annual", "pro2", "ab"] {
        assert!(is_lumi_plan_key(good), "rejected {good}");
    }
    for bad in [
        "",
        "a",
        "Team",
        "team_plan",
        "prod_Q1wOSpA0i2fMNx",
        "price_1MznFTFhk1rX2AbCdEfGhIjK",
        "team ",
        "team/enterprise",
        "team:enterprise",
        &"a".repeat(MAX_PLAN_KEY_BYTES + 1),
    ] {
        assert!(!is_lumi_plan_key(bad), "accepted {bad}");
    }
    assert_eq!(
        PlanPointer::new(
            PlanId::new("plan_0123456789abcdef0123456789abcdef").unwrap(),
            "prod_Q1wOSpA0i2fMNx",
            1
        )
        .err(),
        Some(EntitlementError::InvalidPlanKey)
    );
    assert_eq!(
        PlanPointer::new(
            PlanId::new("plan_0123456789abcdef0123456789abcdef").unwrap(),
            "team",
            0
        )
        .err(),
        Some(EntitlementError::InvalidPlanKey)
    );
}

#[test]
fn subscription_status_vocabulary_round_trips() {
    for status in [
        SubscriptionStatus::Trialing,
        SubscriptionStatus::Active,
        SubscriptionStatus::Grace,
        SubscriptionStatus::PastDue,
        SubscriptionStatus::Suspended,
        SubscriptionStatus::Cancelled,
    ] {
        assert_eq!(SubscriptionStatus::parse(status.as_str()), Some(status));
        assert_eq!(
            serde_json::to_string(&status).unwrap(),
            format!("\"{}\"", status.as_str())
        );
    }
    assert_eq!(SubscriptionStatus::parse("pastdue"), None);
    assert!(SubscriptionStatus::Cancelled.is_terminal());
    assert!(!SubscriptionStatus::Suspended.is_terminal());
}

#[test]
fn the_frozen_transition_table_is_exact() {
    use SubscriptionStatus::{Active, Cancelled, Grace, PastDue, Suspended, Trialing};

    let allowed = [
        (Trialing, Active),
        (Trialing, Cancelled),
        (Active, Grace),
        (Active, PastDue),
        (Active, Suspended),
        (Active, Cancelled),
        (Grace, Active),
        (Grace, PastDue),
        (Grace, Suspended),
        (Grace, Cancelled),
        (PastDue, Active),
        (PastDue, Grace),
        (PastDue, Suspended),
        (PastDue, Cancelled),
        (Suspended, Active),
        (Suspended, Cancelled),
    ];

    let all = [
        SubscriptionStatus::Trialing,
        Active,
        Grace,
        PastDue,
        Suspended,
        Cancelled,
    ];
    for from in all {
        for to in all {
            let expected = allowed.contains(&(from, to));
            assert_eq!(
                from.can_transition_to(to),
                expected,
                "{from:?} -> {to:?} should be {expected}"
            );
        }
    }

    // `suspended` reactivation is only reachable through a new authenticated
    // provider event, never through a local state write.
    assert!(Suspended.can_transition_to(Active));
    assert!(!Suspended.can_transition_to(Grace));
    assert!(!Suspended.can_transition_to(PastDue));
    assert!(!Trialing.can_transition_to(Grace));
    assert!(!Trialing.can_transition_to(PastDue));
    assert!(!Cancelled.can_transition_to(Active));
}

#[test]
fn entering_grace_requires_an_expiry_and_leaving_it_clears_the_window() {
    let mut active = subscription(SubscriptionStatus::Active);
    assert_eq!(
        active
            .apply_status(SubscriptionStatus::Grace, None, 2_000, 2_000)
            .err(),
        Some(EntitlementError::MissingGraceExpiry)
    );
    assert_eq!(
        active
            .apply_status(SubscriptionStatus::Grace, Some(2_000), 2_000, 2_000)
            .err(),
        Some(EntitlementError::InvalidPeriod)
    );

    let transition = active
        .apply_status(
            SubscriptionStatus::Grace,
            Some(2_000 + 86_400),
            2_000,
            2_000,
        )
        .unwrap();
    assert_eq!(
        transition,
        SubscriptionTransition::Applied {
            from: SubscriptionStatus::Active,
            to: SubscriptionStatus::Grace
        }
    );
    assert!(transition.changed());
    assert_eq!(active.status, SubscriptionStatus::Grace);
    assert_eq!(active.grace_expires_at, Some(2_000 + 86_400));
    assert_eq!(active.version, 2);

    let transition = active
        .apply_status(SubscriptionStatus::Active, None, 2_100, 2_100)
        .unwrap();
    assert_eq!(transition.state(), SubscriptionStatus::Active);
    assert_eq!(
        active.grace_expires_at, None,
        "a stale grace expiry must be cleared"
    );

    // Self-transitions are idempotent no-ops.
    let transition = active
        .apply_status(SubscriptionStatus::Active, None, 2_200, 2_200)
        .unwrap();
    assert_eq!(
        transition,
        SubscriptionTransition::Unchanged {
            state: SubscriptionStatus::Active
        }
    );
    assert!(!transition.changed());
    assert_eq!(active.version, 3);

    assert_eq!(
        active
            .apply_status(SubscriptionStatus::Grace, Some(9_999), 1_500, 1_500)
            .err(),
        Some(EntitlementError::StaleTransition)
    );
    assert_eq!(
        active
            .apply_status(SubscriptionStatus::Trialing, None, 2_300, 2_300)
            .err(),
        Some(EntitlementError::InvalidTransition)
    );
    assert_eq!(
        active.version, 3,
        "a refused transition must not bump the version"
    );
}

#[test]
fn a_cancelled_subscription_does_not_silently_reactivate() {
    let mut cancelled = subscription(SubscriptionStatus::Active);
    cancelled
        .apply_status(SubscriptionStatus::Cancelled, None, 2_000, 2_000)
        .unwrap();
    assert_eq!(cancelled.status, SubscriptionStatus::Cancelled);
    let version = cancelled.version;

    for target in [
        SubscriptionStatus::Active,
        SubscriptionStatus::Grace,
        SubscriptionStatus::PastDue,
        SubscriptionStatus::Suspended,
    ] {
        assert_eq!(
            cancelled
                .apply_status(target, Some(9_999), 3_000, 3_000)
                .err(),
            Some(EntitlementError::TerminalSubscription)
        );
    }
    assert_eq!(cancelled.version, version);
    assert_eq!(cancelled.status, SubscriptionStatus::Cancelled);
    assert_eq!(
        EntitlementError::TerminalSubscription.code(),
        "subscription_state_unavailable"
    );
}

#[test]
fn plan_changes_move_an_immutable_pointer_without_rewriting_history() {
    let mut current = subscription(SubscriptionStatus::Grace);
    current.grace_expires_at = Some(1_086_400);
    current.version = 5;
    let before_status = current.status;
    let before_grace = current.grace_expires_at;
    let before_period = current.current_period_ends_at;

    let change = current
        .apply_plan(
            PlanPointer::new(
                PlanId::new("plan_fedcba9876543210fedcba9876543210").unwrap(),
                "starter",
                2,
            )
            .unwrap(),
            2_000,
        )
        .unwrap();

    assert_eq!(change.previous, plan("team"));
    assert_eq!(change.current.as_key(), "starter");
    assert_eq!(change.current.plan_version, 2);
    assert_eq!(change.version, 6);
    assert_eq!(current.plan.as_key(), "starter");
    // Status, grace window, and period bounds are untouched by a plan change.
    assert_eq!(current.status, before_status);
    assert_eq!(current.grace_expires_at, before_grace);
    assert_eq!(current.current_period_ends_at, before_period);
    assert_eq!(
        change.previous.as_key(),
        "team",
        "history keeps the old pointer"
    );

    // Re-publishing the pointer that is already current is a no-op, not a new
    // plan version.
    let unchanged = PlanPointer::new(
        PlanId::new("plan_fedcba9876543210fedcba9876543210").unwrap(),
        "starter",
        2,
    )
    .unwrap();
    assert_eq!(
        current.apply_plan(unchanged, 2_100).err(),
        Some(EntitlementError::InvalidPlanKey)
    );
    assert_eq!(current.version, 6);
    assert_eq!(current.plan.as_key(), "starter");
}

// ---------------------------------------------------------------------------
// Provider event ledger
// ---------------------------------------------------------------------------

fn provider_event(
    id: &str,
    version: i64,
    occurred_at: i64,
    status: SubscriptionStatus,
) -> ProviderEvent {
    ProviderEvent::new(id, "acct_opaque_1", version, occurred_at, status, None).unwrap()
}

fn bound_ledger() -> ProviderEventLedger {
    let mut ledger = ProviderEventLedger::new();
    ledger.bind_account("acct_opaque_1").unwrap();
    ledger
}

#[test]
fn provider_events_are_idempotent_replays_and_ordering_enforced() {
    let mut ledger = bound_ledger();
    let event = provider_event("evt_1", 1, 1_000, SubscriptionStatus::Active);
    ledger.accept(&event, 1_000).unwrap();
    assert_eq!(ledger.last_applied_version(), Some(1));
    assert_eq!(ledger.last_applied_at(), Some(1_000));
    assert!(ledger.has_seen("evt_1"));

    let replay = ledger.accept(&event, 1_000).err();
    assert_eq!(replay, Some(EntitlementError::ProviderEventReplay));
    assert_eq!(replay.unwrap().code(), "provider_event_replay");

    let mut second = bound_ledger();
    second
        .accept(
            &provider_event("evt_1", 1, 1_000, SubscriptionStatus::Active),
            1_000,
        )
        .unwrap();
    let out_of_order = second
        .accept(
            &provider_event("evt_2", 1, 1_500, SubscriptionStatus::Grace),
            1_500,
        )
        .err();
    assert_eq!(
        out_of_order,
        Some(EntitlementError::ProviderEventOutOfOrder)
    );
    assert_eq!(out_of_order.unwrap().code(), "provider_event_out_of_order");
    let stale = second
        .accept(
            &provider_event("evt_3", 5, 900, SubscriptionStatus::Grace),
            1_500,
        )
        .err();
    assert_eq!(stale, Some(EntitlementError::ProviderEventOutOfOrder));
    let future = second
        .accept(
            &provider_event(
                "evt_4",
                9,
                1_500 + MAX_PROVIDER_EVENT_SKEW_SECONDS + 1,
                SubscriptionStatus::Grace,
            ),
            1_500,
        )
        .err();
    assert_eq!(future, Some(EntitlementError::ProviderEventOutOfOrder));
    // None of the refused events advanced the applied state.
    assert_eq!(second.last_applied_version(), Some(1));
    assert_eq!(second.applied_event_count(), 1);
}

#[test]
fn provider_events_are_bound_to_one_adapter_account() {
    let mut ledger = ProviderEventLedger::new();
    assert_eq!(
        ledger
            .accept(
                &provider_event("evt_1", 1, 1_000, SubscriptionStatus::Active),
                1_000
            )
            .err(),
        Some(EntitlementError::AccountBindingMismatch)
    );
    ledger.bind_account("acct_opaque_1").unwrap();
    assert_eq!(ledger.account_reference(), Some("acct_opaque_1"));
    assert_eq!(
        ledger.bind_account("acct_opaque_2").err(),
        Some(EntitlementError::AccountBindingMismatch)
    );
    let foreign = ProviderEvent::new(
        "evt_9",
        "acct_opaque_2",
        7,
        1_100,
        SubscriptionStatus::Cancelled,
        None,
    )
    .unwrap();
    assert_eq!(
        ledger.accept(&foreign, 1_100).err(),
        Some(EntitlementError::AccountBindingMismatch)
    );
    assert_eq!(ledger.last_applied_version(), None);
    assert_eq!(
        EntitlementError::AccountBindingMismatch.code(),
        "resource_not_found"
    );
}

#[test]
fn the_ledger_replay_window_is_bounded() {
    let mut ledger = bound_ledger();
    for index in 0..(MAX_LEDGER_EVENT_IDS as u32) {
        let id = format!("evt_{index:04}");
        ledger
            .accept(
                &provider_event(&id, i64::from(index) + 1, 1_000, SubscriptionStatus::Active),
                1_000,
            )
            .unwrap();
    }
    assert_eq!(ledger.applied_event_count(), MAX_LEDGER_EVENT_IDS);
    ledger
        .accept(
            &provider_event(
                "evt_overflow",
                MAX_LEDGER_EVENT_IDS as i64 + 1,
                1_000,
                SubscriptionStatus::Active,
            ),
            1_000,
        )
        .unwrap();
    assert_eq!(ledger.applied_event_count(), MAX_LEDGER_EVENT_IDS);
    // The evicted identifier is no longer remembered, but its stale version is
    // still refused by the monotonic ordering.
    assert!(!ledger.has_seen("evt_0000"));
    assert_eq!(
        ledger
            .accept(
                &provider_event("evt_0000", 1, 2_000, SubscriptionStatus::Active),
                2_000
            )
            .err(),
        Some(EntitlementError::ProviderEventOutOfOrder)
    );
    assert_eq!(
        ledger.last_applied_version(),
        Some(MAX_LEDGER_EVENT_IDS as i64 + 1)
    );
}

#[test]
fn applying_a_provider_event_is_atomic() {
    let mut current = subscription(SubscriptionStatus::Active);
    let mut ledger = bound_ledger();

    let applied = apply_provider_event(
        &mut current,
        &mut ledger,
        &provider_event("evt_1", 1, 2_000, SubscriptionStatus::Grace),
        Some(2_000 + 86_400),
        2_000,
    )
    .unwrap();
    assert_eq!(
        applied,
        ProviderEventOutcome::Applied(SubscriptionTransition::Applied {
            from: SubscriptionStatus::Active,
            to: SubscriptionStatus::Grace
        })
    );
    assert_eq!(current.status, SubscriptionStatus::Grace);
    assert_eq!(current.version, 2);

    // A replayed webhook is refused by the ledger and changes nothing.
    let version = current.version;
    assert_eq!(
        apply_provider_event(
            &mut current,
            &mut ledger,
            &provider_event("evt_1", 1, 2_000, SubscriptionStatus::Grace),
            Some(9_999),
            2_000,
        )
        .err(),
        Some(EntitlementError::ProviderEventReplay)
    );
    assert_eq!(current.version, version);
    assert_eq!(current.grace_expires_at, Some(2_000 + 86_400));

    // A legal-but-unreachable transition is refused after the ledger accepted
    // the event; the caller must retry the whole unit of work, and the pure
    // model reports it instead of half-applying it.
    assert_eq!(
        apply_provider_event(
            &mut current,
            &mut ledger,
            &provider_event("evt_2", 2, 2_100, SubscriptionStatus::Trialing),
            None,
            2_100,
        )
        .err(),
        Some(EntitlementError::InvalidTransition)
    );
    assert_eq!(current.status, SubscriptionStatus::Grace);
    assert_eq!(current.version, version);

    let duplicate = apply_provider_event(
        &mut current,
        &mut ledger,
        &provider_event("evt_3", 3, 2_200, SubscriptionStatus::Grace),
        Some(9_999),
        2_200,
    )
    .unwrap();
    assert_eq!(
        duplicate,
        ProviderEventOutcome::Duplicate(SubscriptionStatus::Grace)
    );
    assert_eq!(current.version, version);
}

#[test]
fn a_provider_event_can_move_the_plan_pointer_atomically() {
    let mut current = subscription(SubscriptionStatus::Trialing);
    let mut ledger = bound_ledger();
    let event = ProviderEvent::new(
        "evt_1",
        "acct_opaque_1",
        1,
        2_000,
        SubscriptionStatus::Active,
        Some(
            PlanPointer::new(
                PlanId::new("plan_fedcba9876543210fedcba9876543210").unwrap(),
                "enterprise",
                3,
            )
            .unwrap(),
        ),
    )
    .unwrap();
    let applied = apply_provider_event(&mut current, &mut ledger, &event, None, 2_000).unwrap();
    assert_eq!(
        applied,
        ProviderEventOutcome::Applied(SubscriptionTransition::Applied {
            from: SubscriptionStatus::Trialing,
            to: SubscriptionStatus::Active
        })
    );
    assert_eq!(current.plan.as_key(), "enterprise");
    assert_eq!(current.plan.plan_version, 3);
    assert_eq!(current.status, SubscriptionStatus::Active);

    // A refused transition never advances the ledger, so the same provider
    // event ID can still be retried after the caller fixes the mapping.
    let mut fresh = subscription(SubscriptionStatus::Active);
    let mut ledger = bound_ledger();
    let illegal = provider_event("evt_1", 1, 2_000, SubscriptionStatus::Trialing);
    assert_eq!(
        apply_provider_event(&mut fresh, &mut ledger, &illegal, None, 2_000).err(),
        Some(EntitlementError::InvalidTransition)
    );
    assert_eq!(ledger.last_applied_version(), None);
    assert_eq!(fresh.version, 1);
}

#[test]
fn provider_event_construction_is_validated() {
    for (id, account, version) in [
        ("", "acct", 1_i64),
        ("evt_1", "", 1),
        ("evt_1", "acct", 0),
        (&"e".repeat(MAX_PROVIDER_EVENT_ID_BYTES + 1), "acct", 1),
        ("evt\n1", "acct", 1),
    ] {
        let id = id.to_owned();
        let label = id.clone();
        assert!(
            ProviderEvent::new(
                id,
                account,
                version,
                1_000,
                SubscriptionStatus::Active,
                None
            )
            .is_err(),
            "accepted id={label} account={account} version={version}"
        );
    }
    assert!(
        ProviderEvent::new(
            "evt_1",
            "acct",
            1,
            MAX_TIMESTAMP_UNIX_SECONDS + 1,
            SubscriptionStatus::Active,
            None
        )
        .is_err()
    );
}

// ---------------------------------------------------------------------------
// Grace anchor
// ---------------------------------------------------------------------------

#[test]
fn grace_begins_at_the_first_accepted_event_and_is_never_re_anchored() {
    let mut window = GraceWindow::new();
    assert!(window.anchor().is_none());
    assert_eq!(window.expires_at(86_400), None);

    assert_eq!(
        window
            .record_accepted_event(
                "evt_1",
                GraceAnchorSource::AcceptedProviderTransition,
                1_000,
                1_000
            )
            .unwrap(),
        GraceAnchorOutcome::Established
    );
    assert_eq!(window.anchor().unwrap().started_at, 1_000);
    assert_eq!(
        window.anchor().unwrap().source,
        GraceAnchorSource::AcceptedProviderTransition
    );
    assert_eq!(
        window.expires_at(CLOUD_CONTROL_PLANE_GRACE_SECONDS),
        Some(1_000 + 86_400)
    );
    assert_eq!(
        window.expires_at(LOCAL_ONLY_GRACE_SECONDS),
        Some(1_000 + 604_800)
    );
    assert_eq!(
        window.expires_at(PLATFORM_PAID_INFERENCE_GRACE_SECONDS),
        Some(1_000)
    );

    // A later accepted event keeps the original anchor.
    assert_eq!(
        window
            .record_accepted_event("evt_2", GraceAnchorSource::LastSuccessfulSync, 5_000, 5_000)
            .unwrap(),
        GraceAnchorOutcome::Retained
    );
    assert_eq!(window.anchor().unwrap().started_at, 1_000);
    assert_eq!(window.expires_at(86_400), Some(1_000 + 86_400));
}

#[test]
fn repeated_failed_polling_never_extends_grace() {
    let mut window = GraceWindow::new();
    for _ in 0..50 {
        assert_eq!(window.record_failed_poll(), GraceAnchorOutcome::Retained);
    }
    assert!(window.anchor().is_none(), "a failed poll is not an event");

    window
        .record_accepted_event(
            "evt_1",
            GraceAnchorSource::AcceptedProviderTransition,
            1_000,
            1_000,
        )
        .unwrap();
    for _ in 0..50 {
        assert_eq!(window.record_failed_poll(), GraceAnchorOutcome::Retained);
    }
    assert_eq!(window.expires_at(86_400), Some(1_000 + 86_400));
    assert_eq!(window.seconds_remaining(86_400, 1_000), Some(86_400));
    assert_eq!(window.seconds_remaining(86_400, 1_000 + 86_399), Some(1));
    assert_eq!(window.seconds_remaining(86_400, 1_000 + 86_400), Some(0));
    assert_eq!(window.seconds_remaining(86_400, 9_999_999), Some(0));
}

#[test]
fn a_stale_or_future_dated_provider_event_cannot_anchor_or_extend_grace() {
    let mut window = GraceWindow::new();
    assert_eq!(
        window
            .record_accepted_event(
                "evt_1",
                GraceAnchorSource::AcceptedProviderTransition,
                10_000,
                1_000
            )
            .err(),
        Some(EntitlementError::ProviderEventOutOfOrder)
    );
    assert!(window.anchor().is_none());
    assert_eq!(
        window
            .record_accepted_event("evt_2", GraceAnchorSource::LastSuccessfulSync, 0, 1_000)
            .err(),
        Some(EntitlementError::InvalidTimestampRange)
    );
    assert!(
        window
            .record_accepted_event(
                "evt_3",
                GraceAnchorSource::LastSuccessfulSync,
                1_000,
                MAX_TIMESTAMP_UNIX_SECONDS
            )
            .is_ok()
    );
    assert_eq!(
        window
            .record_accepted_event("evt_4", GraceAnchorSource::LastSuccessfulSync, 999, 5_000)
            .err(),
        Some(EntitlementError::ProviderEventOutOfOrder)
    );
    assert_eq!(window.anchor().unwrap().started_at, 1_000);
}

// ---------------------------------------------------------------------------
// Seat model
// ---------------------------------------------------------------------------

fn seat_row(index: u32, org: OrganizationId, state: BillableSeatState) -> BillingSeatRow {
    BillingSeatRow::new(
        MembershipId::new(format!("mem_{index:032x}")).unwrap(),
        org,
        state,
    )
}

#[test]
fn billable_seats_come_from_authoritative_membership_rows() {
    let rows = vec![
        seat_row(1, org_id(), BillableSeatState::Active),
        seat_row(2, org_id(), BillableSeatState::Active),
        seat_row(3, org_id(), BillableSeatState::Suspended),
        seat_row(4, org_id(), BillableSeatState::PendingInvitation),
        seat_row(5, org_id(), BillableSeatState::Removed),
        seat_row(6, org_id(), BillableSeatState::Viewer),
    ];
    let policy = SeatPolicy::baseline();
    assert_eq!(
        policy.billable_states(),
        &[BillableSeatState::Active, BillableSeatState::Suspended]
    );

    let count = billable_seat_count(&rows, &policy).unwrap();
    assert_eq!(count.billable, 3, "active + suspended are billable");
    assert_eq!(count.non_billable, 3);
    assert_eq!(count.total(), 6);
    assert_eq!(count.count_of(BillableSeatState::Active), 2);
    assert_eq!(count.count_of(BillableSeatState::Suspended), 1);
    assert_eq!(count.count_of(BillableSeatState::PendingInvitation), 1);
    assert_eq!(count.count_of(BillableSeatState::Removed), 1);
    assert_eq!(count.count_of(BillableSeatState::Viewer), 1);

    // A plan may bill viewers, and the count still comes from the rows.
    let viewer_plan =
        SeatPolicy::new([BillableSeatState::Active, BillableSeatState::Viewer]).unwrap();
    assert_eq!(
        billable_seat_count(&rows, &viewer_plan).unwrap().billable,
        3
    );

    let empty = billable_seat_count(&[], &policy).unwrap();
    assert_eq!(empty.billable, 0);
    assert_eq!(empty.total(), 0);
}

#[test]
fn seat_policy_rejects_duplicate_and_unbounded_state_lists() {
    assert_eq!(
        SeatPolicy::new([BillableSeatState::Active, BillableSeatState::Active]).err(),
        Some(EntitlementError::DuplicateBillableState)
    );
    let too_many = (0..(BillableSeatState::ALL.len() + 1))
        .map(|_| BillableSeatState::Active)
        .collect::<Vec<_>>();
    assert_eq!(
        SeatPolicy::new(too_many).err(),
        Some(EntitlementError::TooManyBillableStates)
    );
    for state in BillableSeatState::ALL {
        assert_eq!(BillableSeatState::parse(state.as_str()), Some(state));
        assert_eq!(
            state.is_billable_by_default(),
            matches!(
                state,
                BillableSeatState::Active | BillableSeatState::Suspended
            )
        );
    }
    assert_eq!(
        BillableSeatState::parse("active"),
        Some(BillableSeatState::Active)
    );
    assert_eq!(BillableSeatState::parse("invited"), None);
}

#[test]
fn cross_tenant_membership_rows_are_refused_by_seat_accounting() {
    let rows = vec![
        seat_row(1, org_id(), BillableSeatState::Active),
        seat_row(2, other_org_id(), BillableSeatState::Active),
    ];
    let err = billable_seat_count(&rows, &SeatPolicy::baseline()).err();
    assert_eq!(err, Some(EntitlementError::CrossTenantGrant));
    assert_eq!(err.unwrap().code(), "resource_not_found");

    let account = BillingAccount::new(
        BillingAccountId::new("bac_0123456789abcdef0123456789abcdef").unwrap(),
        org_id(),
        "acct_opaque_1",
        SeatPolicy::baseline(),
    )
    .unwrap();
    assert_eq!(account.org_id, org_id());
    assert_eq!(account.provider_account_reference, "acct_opaque_1");
    assert!(account.billable_seat_count(&rows).is_err());
    assert_eq!(
        account
            .billable_seat_count(&[seat_row(1, org_id(), BillableSeatState::Active)])
            .unwrap()
            .billable,
        1
    );
    assert!(
        BillingAccount::new(
            BillingAccountId::new("bac_0123456789abcdef0123456789abcdef").unwrap(),
            org_id(),
            "",
            SeatPolicy::baseline()
        )
        .is_err()
    );
}

// ---------------------------------------------------------------------------
// Identifier prefixes
// ---------------------------------------------------------------------------

#[test]
fn p06_identifiers_enforce_their_frozen_prefixes() {
    assert!(SubscriptionId::new("sub_0123456789abcdef0123456789abcdef").is_ok());
    assert!(SubscriptionId::new("run_0123456789abcdef0123456789abcdef").is_err());
    assert!(PlanId::new("plan_0123456789abcdef0123456789abcdef").is_ok());
    assert!(PlanId::new("plan_0123456789ABCDEF0123456789abcdef").is_err());
    assert!(BillingAccountId::new("bac_0123456789abcdef0123456789abcdef").is_ok());
    assert!(ProviderEntitlementProjectionId::new("pep_0123456789abcdef0123456789abcdef").is_ok());
    assert!(EntitlementGrantId::new("egr_0123456789abcdef0123456789abcdef").is_ok());
    assert!(EntitlementDefinitionId::new("ent_0123456789abcdef0123456789abcdef").is_ok());
    assert!(LicenseSnapshotId::new("lic_0123456789abcdef0123456789abcdef").is_ok());
    for bad in [
        "sub_0123456789abcdef0123456789abcde",
        "sub_",
        "_0123456789abcdef0123456789abcdef",
    ] {
        assert!(SubscriptionId::new(bad).is_err(), "accepted {bad}");
    }
    assert_eq!(
        serde_json::to_string(
            &SubscriptionId::new("sub_0123456789abcdef0123456789abcdef").unwrap()
        )
        .unwrap(),
        "\"sub_0123456789abcdef0123456789abcdef\""
    );
    assert!(
        serde_json::from_str::<SubscriptionId>("\"run_0123456789abcdef0123456789abcdef\"").is_err()
    );
}

#[test]
fn error_codes_stay_inside_the_frozen_stable_surface() {
    for error in [
        EntitlementError::InvalidId,
        EntitlementError::InvalidEntitlementKey,
        EntitlementError::EntitlementKeyTooLong,
        EntitlementError::EntitlementKeyTooManySegments,
        EntitlementError::UnknownEntitlementKey,
        EntitlementError::InvalidEntitlementValue,
        EntitlementError::EntitlementValueTooLong,
        EntitlementError::EntitlementValueOutOfRange,
        EntitlementError::EntitlementTypeMismatch,
        EntitlementError::InvalidScopeId,
        EntitlementError::ScopeNotWithinDefinition,
        EntitlementError::MissingOverrideExpiry,
        EntitlementError::MissingOverrideReason,
        EntitlementError::InvalidTimestampRange,
        EntitlementError::InvalidPeriod,
        EntitlementError::CrossTenantGrant,
        EntitlementError::SourceScopeMismatch,
        EntitlementError::InvalidPlanKey,
        EntitlementError::InvalidProviderReference,
        EntitlementError::ProviderEventReplay,
        EntitlementError::ProviderEventOutOfOrder,
        EntitlementError::InvalidTransition,
        EntitlementError::TerminalSubscription,
        EntitlementError::AccountBindingMismatch,
        EntitlementError::InvalidMembershipState,
        EntitlementError::DuplicateBillableState,
        EntitlementError::TooManyBillableStates,
        EntitlementError::SeatCountOverflow,
        EntitlementError::InvalidClaims,
        EntitlementError::StaleTransition,
        EntitlementError::MissingGraceExpiry,
    ] {
        let code = error.code();
        assert!(
            [
                "validation_failed",
                "entitlement_not_granted",
                "entitlement_limit_exceeded",
                "resource_not_found",
                "provider_event_replay",
                "provider_event_out_of_order",
                "subscription_state_unavailable",
                "version_conflict",
            ]
            .contains(&code),
            "unexpected code {code}"
        );
        assert_eq!(error.to_string(), code);
        // An error never carries the rejected input.
        assert!(!format!("{error:?}").contains("org_"));
    }
}
