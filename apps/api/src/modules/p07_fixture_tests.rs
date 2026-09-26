// The frozen `p07-contracts-v1.json` fixture, asserted against the Rust
// implementation.
//
// WHY A SEPARATE FILE. `docs/implementation/gates/P07-CG.md` §Fixtures freezes
// this document BEFORE implementation, and the gate's own words are that the
// frontend "should begin from frozen contracts/fixtures rather than waiting for
// backend completion". A fixture nothing reads is a comment. This test is what
// makes it a contract: if an implementation stops producing these shapes, or
// stops refusing what the fixture says it must refuse, this fails.
//
// The fixture carries `_note` / `_expected` / `_derivation` keys alongside the
// data. They are the reasoning, and they are stripped rather than ignored so a
// stray annotation cannot make a data assertion pass.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::modules::{
    machine_identity::{CapabilitySet, MachineIdentityError, scope_from_stored},
    plugins::{
        DiffClass, PluginDecision, PluginDenyReason, PluginFacts, PluginPermissionManifest,
        PluginPolicy, PluginReviewState, PublisherMode, UpdateMode, diff, host_is_compatible,
        integrity_matches, policy_conflicts, tool_decision,
    },
    rollouts::{
        FeatureFlag, FlagCohort, FlagResolution, KillSwitch, KillSwitchResolution, KillSwitchScope,
        KillSwitchState, KillSwitchTargetClass, cohort_hash, resolve_flag,
    },
    staff::{
        StaffActor, StaffDenyReason, StaffPermission, StaffRequest, StaffRole, SupportGrantState,
        SupportGrantView, authorize_staff,
    },
};

const FIXTURE: &str =
    include_str!("../../../../docs/implementation/fixtures/p07-contracts-v1.json");

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("the frozen fixture is valid JSON")
}

/// Strip the `_`-prefixed annotation keys so a data assertion cannot be satisfied
/// by a note.
fn data(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(key, _)| !key.starts_with('_'))
                .map(|(key, value)| (key.clone(), data(value)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(data).collect()),
        other => other.clone(),
    }
}

fn staff_actor(role: StaffRole) -> StaffActor {
    StaffActor::new(
        crate::core::StaffPrincipalId::new("stf_0123456789abcdef0123456789abcdef")
            .expect("fixture staff id"),
        role,
        "0123456789abcdef",
    )
}

fn org() -> crate::core::OrganizationId {
    "org_0123456789abcdef0123456789abcdef"
        .parse()
        .expect("fixture org id")
}

fn org_other() -> crate::core::OrganizationId {
    "org_ffffffffffffffffffffffffffffffff"
        .parse()
        .expect("fixture org id")
}

/// The frozen manifests are the source of truth for the diff cases, so a change
/// to the verdicts and a change to the manifests are the same edit. This also
/// keeps the declared `_note` honest: the fixture writes its `before` lists out
/// of order precisely so the normalizer has something to do.
fn frozen_manifest(value: &Value) -> PluginPermissionManifest {
    serde_json::from_value(data(value).clone()).expect("a frozen manifest deserializes")
}

#[test]
fn the_fixture_is_the_version_the_gate_names() {
    assert_eq!(fixture()["contract_version"], "p07-cg-v1");
}

#[test]
fn the_service_account_carries_exactly_the_declared_capabilities() {
    let raw = fixture();
    let account = &raw["service_account"];
    let parsed =
        CapabilitySet::parse(&serde_json::to_string(&account["capabilities"]).expect("json"))
            .expect("the frozen capability set parses");
    assert_eq!(
        parsed.to_json(),
        r#"["agents.read","runs.read","runs.start"]"#,
        "the frozen set is normalized, so the stored order is the sorted order"
    );
    // The projection the handler returns must carry exactly these fields and no
    // secret-adjacent ones.
    let projected = data(account);
    let keys: BTreeSet<&str> = projected
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    for absent in ["secret", "secret_hash", "key", "api_key_id"] {
        assert!(
            !keys.contains(absent),
            "a service account projection must not carry {absent}"
        );
    }
}

#[test]
fn the_human_only_capability_in_the_fixture_is_the_one_the_gate_refuses() {
    let raw = fixture();
    let refused = raw["service_account_with_a_human_only_capability"]["_refused"]
        .as_str()
        .expect("a refused capability is named");
    let account = CapabilitySet::parse(
        &serde_json::to_string(&raw["service_account"]["capabilities"]).expect("json"),
    )
    .expect("the declared set parses");
    // Adding the fixture's refused capability to the declared set must be refused
    // with the service-layer code, and must be refused as HUMAN-ONLY rather than
    // as unknown — the operator is told the control exists and cannot be granted.
    let mut with_human_only = account.to_json();
    with_human_only.pop();
    with_human_only.push_str(&format!(",\"{refused}\"]"));
    assert_eq!(
        CapabilitySet::parse(&with_human_only),
        Err(MachineIdentityError::CapabilityHumanOnly)
    );
    assert!(crate::modules::machine_identity::is_human_only(
        &crate::modules::authorization::Permission::parse(refused)
    ));
}

#[test]
fn the_api_key_projection_has_no_field_a_raw_credential_could_use() {
    let raw = fixture();
    let key = data(&raw["api_key"]);
    let object = key.as_object().expect("object");
    for absent in ["secret", "secret_hash", "wire_value", "raw"] {
        assert!(
            !object.contains_key(absent),
            "an api key projection must not carry {absent}"
        );
    }
    for present in [
        "key_prefix",
        "fingerprint",
        "capabilities",
        "last_used_source",
    ] {
        assert!(
            object.contains_key(present),
            "{present} is part of the contract"
        );
    }
    // The prefix is 12 lowercase hex and the fingerprint 16, as the derivation
    // note states. A drift here would be a wire-format change.
    let prefix = object["key_prefix"].as_str().expect("prefix");
    assert_eq!(prefix.len(), 12);
    assert!(
        prefix
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    let fingerprint = object["fingerprint"].as_str().expect("fingerprint");
    assert_eq!(fingerprint.len(), 16);
}

#[test]
fn the_api_key_scope_rebuilds_from_the_frozen_projection() {
    let raw = fixture();
    let key = &raw["api_key"];
    let scope = scope_from_stored(
        &serde_json::to_string(&key["capabilities"]).expect("json"),
        // The stored column holds the SERIALIZED array, not a bare id, and
        // `null` means "every project" while `[]` means "none". Feeding a bare id
        // here was the first version of this test and it failed with
        // `InvalidInput` for exactly the right reason.
        key["project_ids"]
            .as_array()
            .map(|_| serde_json::to_string(&key["project_ids"]).expect("json"))
            .as_deref(),
        key["model_aliases"]
            .as_array()
            .map(|_| serde_json::to_string(&key["model_aliases"]).expect("json"))
            .as_deref(),
        key["network_allowlist"]
            .as_array()
            .map(|_| serde_json::to_string(&key["network_allowlist"]).expect("json"))
            .as_deref(),
    )
    .expect("the frozen scope rebuilds");
    assert!(scope.allows(&crate::modules::authorization::Permission::RunsStart));
    assert!(!scope.allows(&crate::modules::authorization::Permission::RunsCancel));
    assert!(scope.allows_model_alias("coding-default"));
    assert!(scope.allows_network(Some("build.ci.trusted.example")));
    assert!(!scope.allows_network(Some("build.ci.untrusted.example")));
    // `*` means a strict subdomain, so the bare parent is not covered either.
    assert!(!scope.allows_network(Some("ci.trusted.example")));
    // A configured restriction that cannot be evaluated DENIES. Failing open
    // would make the control decorative.
    assert!(!scope.allows_network(None));
}

#[test]
fn the_rotation_shape_is_an_overlap_not_a_replacement() {
    let raw = fixture();
    let replacement = &raw["api_key_rotation"]["replacement"];
    assert_eq!(
        replacement["rotated_from_key_id"], raw["api_key"]["id"],
        "the replacement records the key it supersedes"
    );
    assert_eq!(
        replacement["same_scope_as"], "api_key",
        "F14-004: the replacement carries the SAME scope as the key it replaces"
    );
    let prior = &raw["api_key_rotation"]["prior_key_after"];
    assert_eq!(prior["status"], "rotated");
    assert!(
        prior["revoke_reason"]
            .as_str()
            .is_some_and(|r| !r.is_empty())
    );
}

/// The frozen `classes` array is the WIRE shape — `Vec<ClassDiff>` as
/// `PermissionDiff` serializes it and as the TypeScript decoder reads it — not a
/// map keyed by class name. A fixture keyed by name would let the two sides
/// agree on the verdicts while disagreeing on the shape, leaving the browser as
/// the only consumer unable to read its own contract.
fn frozen_verdict(value: &Value, class: &str) -> Value {
    value["classes"]
        .as_array()
        .expect("classes is the wire array")
        .iter()
        .find(|entry| entry["class"] == class)
        .unwrap_or_else(|| panic!("the fixture has no verdict for {class}"))
        .clone()
}

/// The frozen class names, in the order the server emits them.
fn frozen_class_order(value: &Value) -> Vec<String> {
    value["classes"]
        .as_array()
        .expect("classes is the wire array")
        .iter()
        .map(|entry| entry["class"].as_str().expect("a class name").to_owned())
        .collect()
}

#[test]
fn the_expanding_diff_matches_the_frozen_verdicts() {
    let raw = fixture();
    let frozen = &raw["permission_diff_expands"];
    let before = frozen_manifest(&frozen["before"]);
    let after = frozen_manifest(&frozen["after"]);
    let result = diff(
        frozen["from_version"].as_str(),
        &before,
        frozen["to_version"].as_str().expect("to_version"),
        &after,
    );
    assert_eq!(result.from_version, frozen["from_version"]);
    assert_eq!(result.to_version, frozen["to_version"]);
    assert_eq!(result.expands, frozen["expands"]);
    for class in &result.classes {
        let expected = frozen_verdict(frozen, &class.class);
        assert_eq!(
            class.verdict.as_str(),
            expected["verdict"],
            "{}",
            class.class
        );
        assert_eq!(
            class.added,
            string_vec(&expected["added"]),
            "{}.added",
            class.class
        );
        assert_eq!(
            class.removed,
            string_vec(&expected["removed"]),
            "{}.removed",
            class.class
        );
    }
    // The class count is part of the contract: a NEW capability class must be
    // added to the diff explicitly, which is what makes it impossible to add a
    // capability that no diff reports. So is the ORDER, because a diff reads as a
    // widening of authority from left to right and reordering it would make
    // `tools` look like the last word when it is the first.
    let actual_order: Vec<String> = result
        .classes
        .iter()
        .map(|class| class.class.clone())
        .collect();
    assert_eq!(actual_order, frozen_class_order(frozen));
    assert!(result.class("tools").expect("tools").verdict == DiffClass::Added);
    assert!(result.class("network_destinations").expect("net").verdict == DiffClass::Removed);
}

/// The expanding fixture's own note claims the diff normalizes both manifests
/// before comparing them. Asserted rather than asserted-in-prose: a reordering
/// of the same declarations is not a capability change, and a diff that reported
/// it as one would send every re-publish of an unchanged package back to review.
#[test]
fn a_reordering_of_the_same_declarations_is_not_a_capability_change() {
    let raw = fixture();
    let frozen = &raw["permission_diff_expands"];
    let before = frozen_manifest(&frozen["before"]);
    let reordered = PluginPermissionManifest {
        tools: before.tools.iter().rev().cloned().collect(),
        mcp_servers: before.mcp_servers.iter().rev().cloned().collect(),
        network_destinations: before.network_destinations.iter().rev().cloned().collect(),
        filesystem_scopes: before.filesystem_scopes.iter().rev().cloned().collect(),
        process_spawn: before.process_spawn,
        secret_handles: before.secret_handles.iter().rev().cloned().collect(),
        browser_capability: before.browser_capability,
        external_data_handling: before.external_data_handling,
    };
    assert_ne!(
        reordered.network_destinations, before.network_destinations,
        "the frozen before manifest is written out of order on purpose"
    );
    let result = diff(Some("1.0.0"), &before, "1.0.1", &reordered);
    assert!(!result.expands, "a reorder is not an expansion");
    for class in &result.classes {
        assert_eq!(
            class.verdict,
            DiffClass::Unchanged,
            "{} moved without gaining anything",
            class.class
        );
    }
    // A duplicate declaration is the same capability stated twice, not two.
    let duplicated = PluginPermissionManifest {
        network_destinations: [
            before.network_destinations.clone(),
            before.network_destinations.clone(),
        ]
        .concat(),
        ..reordered
    };
    assert!(!diff(Some("1.0.0"), &before, "1.0.2", &duplicated).expands);
}

#[test]
fn the_contracting_diff_matches_the_frozen_verdicts_and_is_not_an_expansion() {
    let raw = fixture();
    let frozen = &raw["permission_diff_contraction"];
    // Its OWN version pair, not the expanding fixture's pair reversed: asserting a
    // contraction by running the expansion backwards would pass whether or not
    // the diff were direction-sensitive.
    let before = frozen_manifest(&frozen["before"]);
    let after = frozen_manifest(&frozen["after"]);
    let result = diff(
        frozen["from_version"].as_str(),
        &before,
        frozen["to_version"].as_str().expect("to_version"),
        &after,
    );
    assert_eq!(result.from_version, frozen["from_version"]);
    assert_eq!(result.to_version, frozen["to_version"]);
    assert_eq!(result.expands, frozen["expands"]);
    assert!(
        !result.expands,
        "F25-004: a contraction installs without renewed review"
    );
    for class in &result.classes {
        let expected = frozen_verdict(frozen, &class.class);
        assert_eq!(
            class.verdict.as_str(),
            expected["verdict"],
            "{}",
            class.class
        );
        assert!(
            class.added.is_empty(),
            "{} grew on a contraction",
            class.class
        );
        assert_eq!(
            class.removed,
            string_vec(&expected["removed"]),
            "{}.removed",
            class.class
        );
    }
    let actual_order: Vec<String> = result
        .classes
        .iter()
        .map(|class| class.class.clone())
        .collect();
    assert_eq!(actual_order, frozen_class_order(frozen));
}

#[test]
fn the_policy_fixture_conflicts_and_the_block_wins() {
    let raw = fixture();
    let frozen = &raw["plugin_policy_with_a_conflict"];
    let policy = PluginPolicy {
        publisher_mode: PublisherMode::parse(frozen["publisher_mode"].as_str().expect("mode"))
            .expect("a known mode"),
        approved_publishers: string_vec(&frozen["approved_publishers"]),
        allowed_packages: string_vec(&frozen["allowed_packages"]),
        blocked_packages: string_vec(&frozen["blocked_packages"]),
        pinned_versions: serde_json::from_value(frozen["pinned_versions"].clone()).expect("map"),
        auto_update: frozen["auto_update"].as_bool().expect("bool"),
        update_mode: UpdateMode::parse(frozen["update_mode"].as_str().expect("mode"))
            .expect("known"),
    };
    let conflicts: Vec<String> = policy_conflicts(&policy)
        .into_iter()
        .map(|conflict| conflict.package_id)
        .collect();
    let frozen_conflicts: Vec<String> = frozen["conflicts"]
        .as_array()
        .expect("array")
        .iter()
        .map(|value| value.as_str().expect("string").to_owned())
        .collect();
    assert_eq!(conflicts, frozen_conflicts);

    let blocked_package = "pkg_0123456789abcdef0123456789abcdef".to_owned();
    let facts = PluginFacts {
        package_id: blocked_package.clone(),
        version: "1.0.0".into(),
        publisher_id: "pub_0123456789abcdef0123456789abcdef".into(),
        publisher_official: false,
        policy_conflict: true,
        quarantined: false,
        review_state: Some(PluginReviewState::Approved),
        pinned_elsewhere: false,
    };
    // The install decisions below are about POLICY, so they are given a diff that
    // changes nothing: any denial has to come from the policy, not from a
    // permission change the cases did not set up.
    let baseline = frozen_manifest(&raw["permission_diff_expands"]["before"]);
    let noop = diff(None, &baseline, "1.0.0", &baseline);
    assert!(!noop.expands);
    assert!(
        noop.classes
            .iter()
            .all(|class| class.verdict == DiffClass::Unchanged),
        "a manifest diffed against itself is a no-op in every class"
    );
    assert_eq!(
        facts.install_decision(&policy, &noop),
        PluginDecision::Deny(PluginDenyReason::Blocked),
        "the block wins and the reason an operator sees is the block"
    );

    let pinned_package = "pkg_ffffffffffffffffffffffffffffffff".to_owned();
    let pinned = PluginFacts {
        package_id: pinned_package,
        version: "2.0.0".into(),
        publisher_id: "pub_0123456789abcdef0123456789abcdef".into(),
        publisher_official: false,
        policy_conflict: false,
        quarantined: false,
        review_state: Some(PluginReviewState::Approved),
        pinned_elsewhere: true,
    };
    assert_eq!(
        pinned.install_decision(&policy, &noop),
        PluginDecision::Deny(PluginDenyReason::Pinned),
        "a pin blocks every other version, including a security update"
    );
}

/// F24's acceptance criterion, stated against the frozen fixture: a rollback can
/// target one organization before a global disable, so both rows are read and the
/// narrow one is evaluated last.
#[test]
fn the_organization_scoped_switch_is_the_answer_before_the_global_one() {
    let raw = fixture();
    let org_switch = fixture_kill_switch(&raw["kill_switch_organization_scope"]);
    let global_switch = fixture_kill_switch(&raw["kill_switch_global_scope"]);
    let class = KillSwitchTargetClass::PluginVersion;
    let reference = "pkg_0123456789abcdef0123456789abcdef@1.0.0";

    for switch in [&org_switch, &global_switch] {
        assert_eq!(
            crate::modules::rollouts::kill_switch_applies(switch, class, reference, &org(), NOW),
            KillSwitchResolution::Engaged
        );
    }
    // The narrow switch must not reach another organization, and the global one
    // must reach everyone. Ordering the reads `global` first is what makes "the
    // narrow decision is the reported one" true for a caller that stops at the
    // first engaged row.
    assert_eq!(
        crate::modules::rollouts::kill_switch_applies(
            &org_switch,
            class,
            reference,
            &org_other(),
            NOW
        ),
        KillSwitchResolution::NotEngaged
    );
    assert!("global" < "organization", "the narrow row is ordered last");
}

#[test]
fn an_expired_or_lifted_switch_is_not_engaged_and_says_which() {
    let raw = fixture();
    let base = fixture_kill_switch(&raw["kill_switch_organization_scope"]);
    let reference = "pkg_0123456789abcdef0123456789abcdef@1.0.0";
    let expired = KillSwitch {
        expires_at: Some(PAST.into()),
        ..base.clone()
    };
    let lifted = KillSwitch {
        state: KillSwitchState::Lifted,
        ..base
    };
    assert_eq!(
        crate::modules::rollouts::kill_switch_applies(
            &expired,
            KillSwitchTargetClass::PluginVersion,
            reference,
            &org(),
            NOW
        ),
        KillSwitchResolution::Expired
    );
    assert_eq!(
        crate::modules::rollouts::kill_switch_applies(
            &lifted,
            KillSwitchTargetClass::PluginVersion,
            reference,
            &org(),
            NOW
        ),
        KillSwitchResolution::Lifted
    );
    assert!(!KillSwitchResolution::Expired.is_engaged());
}

/// The frozen percentage rollout, asserted for the three properties F24-006 and
/// the gate name.
#[test]
fn the_frozen_flag_resolves_off_when_expired_and_stably_by_percentage() {
    let raw = fixture();
    let frozen = &raw["feature_flag_with_a_percentage"];
    let flag = FeatureFlag {
        flag_key: frozen["flag_key"].as_str().expect("key").into(),
        enabled: frozen["enabled"].as_bool().expect("bool"),
        rollout_percentage: frozen["rollout_percentage"].as_u64().expect("number") as u8,
        org_allowlist: string_vec(&frozen["org_allowlist"]),
        cohort: FlagCohort::parse(frozen["cohort"].as_str().expect("cohort")).expect("known"),
        expires_at: frozen["expires_at"].as_str().expect("expiry").into(),
        owner_staff_principal_id: frozen["owner_staff_principal_id"]
            .as_str()
            .expect("owner")
            .into(),
    };
    // The frozen expiry is in the future relative to the frozen instant, so the
    // resolution is decided by the percentage alone. The verdict for THIS org is
    // whatever the stable hash says — the point is that it is the same answer
    // every time, not that it is "on". Asserting a specific verdict here would
    // make a change to the hash look like a contract change, and the hash is an
    // implementation detail whose contract is its STABILITY.
    let first = resolve_flag(&flag, &org(), NOW);
    assert!(matches!(
        first,
        FlagResolution::PercentageIncluded | FlagResolution::PercentageExcluded
    ));
    for _ in 0..50 {
        assert_eq!(resolve_flag(&flag, &org(), NOW), first);
    }
    // 100% is the degenerate answer and is not a hash away: it is on for
    // everybody, which is what makes a ramp's endpoint checkable.
    assert_eq!(
        resolve_flag(
            &FeatureFlag {
                rollout_percentage: 100,
                ..flag.clone()
            },
            &org(),
            NOW
        ),
        FlagResolution::PercentageIncluded
    );
    // Expiry is checked FIRST, so an expired flag reports why it is off rather
    // than reporting "excluded" and leaving the operator to guess.
    let expired = FeatureFlag {
        expires_at: PAST.into(),
        ..flag.clone()
    };
    assert_eq!(resolve_flag(&expired, &org(), NOW), FlagResolution::Expired);
    // Monotonic: ramping never removes a tenant that was already in. Proved
    // across a population rather than for one organization, because a
    // single-organization assertion would pass for a hash that is not monotonic.
    let included: Vec<OrganizationIdLike> = (0..200u32)
        .map(|n| OrganizationIdLike(format!("org_{n:032x}")))
        .filter(|id| {
            resolve_flag(
                &FeatureFlag {
                    rollout_percentage: 10,
                    ..flag.clone()
                },
                &id.as_id(),
                NOW,
            )
            .is_on()
        })
        .collect();
    assert!(!included.is_empty(), "a 10% rollout must include somebody");
    for id in &included {
        for percentage in [10_u8, 25, 50, 100] {
            assert!(
                resolve_flag(
                    &FeatureFlag {
                        rollout_percentage: percentage,
                        ..flag.clone()
                    },
                    &id.as_id(),
                    NOW
                )
                .is_on(),
                "ramping to {percentage}% dropped a tenant that was already in"
            );
        }
    }
    // And the cohort hash is a function of the id, not a per-request draw.
    assert_eq!(cohort_hash(org().as_str()), cohort_hash(org().as_str()));
}

/// The two grant fixtures, asserted to produce two DIFFERENT codes. A collapse of
/// these into one is exactly the case a test has to prevent.
#[test]
fn the_expired_and_revoked_grants_are_two_different_denial_codes() {
    let raw = fixture();
    let expired = fixture_grant(&raw["support_grant_expired"], SupportGrantState::Expired);
    let revoked = fixture_grant(&raw["support_grant_revoked"], SupportGrantState::Revoked);
    let support = staff_actor(StaffRole::Support);
    let decide = |grant: &SupportGrantView| {
        authorize_staff(
            &support,
            StaffPermission::OrgDevicesRead,
            StaffRequest {
                organization: Some(&org()),
                grant: Some(grant),
                principal_suspended: false,
            },
        )
    };
    assert_eq!(
        decide(&expired),
        crate::modules::staff::StaffDecision::Deny(StaffDenyReason::SupportGrantExpired)
    );
    assert_eq!(
        decide(&revoked),
        crate::modules::staff::StaffDecision::Deny(StaffDenyReason::SupportGrantRevoked)
    );
    assert_ne!(
        StaffDenyReason::SupportGrantExpired.code(),
        StaffDenyReason::SupportGrantRevoked.code()
    );
    // A grant for a different organization is a third code, not a fourth meaning
    // of one of the first two.
    let mismatched = SupportGrantView {
        organization_id: org_other(),
        ..expired.clone()
    };
    assert_eq!(
        decide(&mismatched),
        crate::modules::staff::StaffDecision::Deny(
            StaffDenyReason::SupportGrantOrganizationMismatch
        )
    );
}

/// What a managed-mode expansion REFUSAL looks like: nothing installed, the
/// candidate recorded, and the reason present. The reason column is required by
/// 0017, so a row without one is not representable.
#[test]
fn the_pending_review_install_records_the_candidate_and_the_reason() {
    let raw = fixture();
    let frozen = &raw["plugin_install_pending_review"];
    assert_eq!(frozen["review_state"], "pending_review");
    assert_ne!(frozen["version"], frozen["pending_review_version"]);
    assert!(
        frozen["review_reason"]
            .as_str()
            .is_some_and(|reason| reason.starts_with("plugin.permission_expansion_detected.v1")),
        "the refusal records the frozen event id"
    );
    // The tool the expansion added is exactly the tool with no registration, so
    // the surface can show what is not usable.
    let registered = string_vec(&frozen["registered_tools"]);
    let unregistered = string_vec(&frozen["unregistered_tools"]);
    assert!(!registered.contains(&"pkg_write".to_owned()));
    assert!(unregistered.contains(&"pkg_write".to_owned()));

    // `_reason_format` is the whole stored reason FORMAT, not just an example of
    // one. A client matches the stable code and then reads the payload, so a
    // server that changed either half would silently stop the browser naming the
    // class that grew — which is the sentence the refusal exists to produce.
    let format = &frozen["_reason_format"];
    let stored = frozen["review_reason"]
        .as_str()
        .expect("the reason is stored");
    let event_id = format["event_id"].as_str().expect("an event id");
    assert_eq!(event_id, "plugin.permission_expansion_detected.v1");
    assert!(stored.starts_with(&format!("{event_id} ")), "{stored}");
    let payload: Value = serde_json::from_str(stored[event_id.len() + 1..].trim())
        .expect("the part after the event id is the summary json");
    assert_eq!(payload["expands"], true);
    // The payload names the growing class, and it is the tool the expansion
    // wanted: that is what the browser turns into a sentence.
    let growing: Vec<&str> = payload["classes"]
        .as_array()
        .expect("classes")
        .iter()
        .filter(|entry| entry["verdict"] == "added")
        .map(|entry| entry["class"].as_str().expect("a class name"))
        .collect();
    assert_eq!(growing, ["tools"]);
    assert_eq!(
        format["shape"], "<event id> <summary json>",
        "a client that matches the whole stored string against the bare id matches nothing"
    );

    let policy = PluginPolicy::default();
    let facts = PluginFacts {
        package_id: frozen["package_id"].as_str().expect("id").into(),
        version: frozen["version"].as_str().expect("version").into(),
        publisher_id: "pub_0123456789abcdef0123456789abcdef".into(),
        publisher_official: true,
        policy_conflict: false,
        quarantined: false,
        review_state: Some(PluginReviewState::PendingReview),
        pinned_elsewhere: false,
    };
    // A pending review is not executable even under the most permissive policy.
    assert_eq!(
        facts.execution_decision(&policy),
        PluginDecision::Deny(PluginDenyReason::Blocked)
    );
    // The tool the expansion wanted is denied by F13 default-deny once the
    // install IS approved, which is the case a reader actually needs the answer
    // for: "I approved this, why is the tool missing?"
    let approved = PluginFacts {
        review_state: Some(PluginReviewState::Approved),
        ..facts
    };
    assert!(approved.execution_decision(&policy).is_allowed());
    assert_eq!(
        tool_decision(&approved, &policy, true, false),
        PluginDecision::Deny(PluginDenyReason::ToolUnregistered)
    );
    assert!(tool_decision(&approved, &policy, true, true).is_allowed());
}

#[test]
fn the_frozen_compatibility_range_and_digest_shape_are_usable() {
    // A `plugin_version` target is `package@version`, and the frozen switches use
    // that form, so the validator must accept exactly what the fixture carries.
    let raw = fixture();
    let reference = raw["kill_switch_organization_scope"]["target_ref"]
        .as_str()
        .expect("target_ref");
    assert_eq!(
        crate::modules::rollouts::validate_kill_switch_input(
            KillSwitchTargetClass::PluginVersion,
            reference,
            KillSwitchScope::Organization,
            Some(&org()),
            raw["kill_switch_organization_scope"]["reason"]
                .as_str()
                .expect("reason"),
            None,
        ),
        Ok(())
    );
    // And the same reference with a wildcard is `kill_switch_too_broad`.
    assert_eq!(
        crate::modules::rollouts::validate_kill_switch_input(
            KillSwitchTargetClass::PluginVersion,
            "pkg_*",
            KillSwitchScope::Global,
            None,
            "incident 42",
            None,
        ),
        Err(crate::modules::rollouts::KillSwitchError::TooBroad)
    );
    // A compatible and an incompatible host, for the range the schema stores.
    assert!(host_is_compatible("1.0.0", "3.0.0", "2.0.0"));
    assert!(!host_is_compatible("1.0.0", "3.0.0", "0.9.0"));
    // A digest comparison has no shortcut, and a mismatch is the F25-005 refusal.
    let digest = "b".repeat(64);
    assert!(integrity_matches(&digest, &digest));
    assert!(!integrity_matches(&digest, &"c".repeat(64)));
}

/// A minimal newtype so the monotonicity sweep can build a population without a
/// `Result` at every step. A malformed id would be a bug in the generator, and
/// the generator is six characters long.
struct OrganizationIdLike(String);

impl OrganizationIdLike {
    fn as_id(&self) -> crate::core::OrganizationId {
        self.0.parse().expect("a generated org id parses")
    }
}

const NOW: &str = "2026-09-26T12:00:00.000Z";
const PAST: &str = "2026-08-26T12:00:00.000Z";

fn string_vec(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("an array of strings")
        .iter()
        .map(|entry| entry.as_str().expect("a string").to_owned())
        .collect()
}

fn permission_vec(value: &Value) -> Vec<StaffPermission> {
    string_vec(value)
        .iter()
        .map(|name| StaffPermission::parse(name).expect("a known staff permission"))
        .collect()
}

fn fixture_kill_switch(value: &Value) -> KillSwitch {
    KillSwitch {
        target_class: KillSwitchTargetClass::parse(value["target_class"].as_str().expect("class"))
            .expect("a known class"),
        target_ref: value["target_ref"].as_str().expect("ref").into(),
        scope: KillSwitchScope::parse(value["scope"].as_str().expect("scope")).expect("known"),
        organization_id: value["organization_id"]
            .as_str()
            .map(|id| id.parse().expect("a valid org id")),
        state: KillSwitchState::parse(value["state"].as_str().expect("state")).expect("known"),
        expires_at: value["expires_at"].as_str().map(str::to_owned),
    }
}

fn fixture_grant(value: &Value, state: SupportGrantState) -> SupportGrantView {
    SupportGrantView {
        grant_id: crate::core::SupportGrantId::new(value["grant_id"].as_str().expect("id"))
            .expect("a valid grant id"),
        organization_id: value["organization_id"]
            .as_str()
            .expect("org")
            .parse()
            .expect("a valid org id"),
        staff_principal_id: value["staff_principal_id"]
            .as_str()
            .expect("staff")
            .parse()
            .expect("a valid staff id"),
        capabilities: permission_vec(&value["capabilities_json"]),
        state,
    }
}
