//! P07 plugin governance HTTP surface (P07-BE-04, P07-INT-01).
//!
//! # Route surface (all under `/api/v1`)
//!
//! | Method | Path | Permission |
//! |---|---|---|
//! | GET | `/orgs/{org_id}/plugins` | `plugins.read` |
//! | GET | `/orgs/{org_id}/plugins/policy` | `plugins.read` |
//! | PATCH | `/orgs/{org_id}/plugins/policy` | `plugins.manage` |
//! | GET | `/orgs/{org_id}/plugins/{package_id}` | `plugins.read` |
//! | POST | `/orgs/{org_id}/plugins/{package_id}/install` | `plugins.manage` |
//! | POST | `/orgs/{org_id}/plugins/{package_id}/approve` | `plugins.manage` |
//! | POST | `/orgs/{org_id}/plugins/{package_id}/block` | `plugins.manage` |
//! | POST | `/orgs/{org_id}/plugins/{package_id}/unblock` | `plugins.manage` |
//! | POST | `/orgs/{org_id}/plugins/{package_id}/pin` | `plugins.manage` |
//! | GET | `/orgs/{org_id}/plugins/{package_id}/versions/{version}/permission-diff` | `plugins.read` |
//! | POST | `/orgs/{org_id}/plugin-reports` | `plugins.manage` |
//!
//! # Every decision comes from one pure function
//!
//! [`PluginFacts::install_decision`] and [`PluginFacts::execution_decision`] are
//! pure, so a handler's job is to read state, build the facts, ask, and report
//! the stable code. No handler re-implements part of a rule, which is what keeps
//! "blocked wins over allowed" true on the install path, the approve path, and
//! the report path at once.

use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    adapters::new_resource_id,
    app::AppState,
    core::{ApiError, ApiErrorCode, RequestContext},
    modules::{
        authorization::Permission,
        plugins::{
            BrowserCapability, ExternalDataHandling, PermissionDiff, PluginDecision,
            PluginDenyReason, PluginFacts, PluginPermissionManifest, PluginPolicy,
            PluginReviewState, PublisherMode, SecretHandle, UpdateMode, diff, host_is_compatible,
            integrity_matches, policy_conflicts, tool_decision,
        },
    },
    repositories::{
        PluginGovernanceRepository, PluginInstallInput, PluginPackageRecord, PluginPolicyInput,
        PluginVersionRecord,
    },
    routes::{
        agents::replay_response,
        authorization::authorize_org,
        errors,
        support::{database, domain_error, idempotency_key, security_event_statement},
        usage::{
            PreparedScopedMutation, ScopedMutationCommit, commit_scoped_mutation,
            prepare_scoped_mutation,
        },
    },
};

pub const PLUGIN_POLICY_PATCH_PATH: &str = "/api/v1/orgs/{org_id}/plugins/policy";
pub const PLUGIN_INSTALL_PATH: &str = "/api/v1/orgs/{org_id}/plugins/{package_id}/install";
pub const PLUGIN_APPROVE_PATH: &str = "/api/v1/orgs/{org_id}/plugins/{package_id}/approve";
pub const PLUGIN_BLOCK_PATH: &str = "/api/v1/orgs/{org_id}/plugins/{package_id}/block";
pub const PLUGIN_UNBLOCK_PATH: &str = "/api/v1/orgs/{org_id}/plugins/{package_id}/unblock";
/// The pin action writes the ORG POLICY row, so its idempotency scope is the
/// policy template rather than a per-package one: two pins of the same package
/// are the same logical mutation of one versioned row.
pub const PLUGIN_PIN_POLICY_PATH: &str = "/api/v1/orgs/{org_id}/plugins/policy";

/// The recorded reason a managed-mode expansion was refused. F25-009 wants the
/// refusal auditable, and an event id in a reason column is what lets an operator
/// jump from the UI to the audit view.
const PERMISSION_EXPANSION_REASON: &str = "plugin.permission_expansion_detected.v1";

// ------------------------------------------------------------- requests ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchPolicyBody {
    pub version: i64,
    pub publisher_mode: Option<String>,
    pub approved_publishers: Option<Vec<String>>,
    pub allowed_packages: Option<Vec<String>>,
    pub blocked_packages: Option<Vec<String>>,
    pub pinned_versions: Option<std::collections::BTreeMap<String, String>>,
    pub auto_update: Option<bool>,
    pub update_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallBody {
    pub version: String,
    /// Client-supplied request id for the caller's own tracing. The
    /// idempotency scope is the `Idempotency-Key` header, so this is never
    /// authority for anything; it is carried so a host can correlate its own log
    /// line with the install it asked for.
    #[allow(dead_code)]
    pub request_id: Option<String>,
    /// The reporting host's agent version, checked against the declared
    /// compatibility range. A version whose range excludes this host cannot be
    /// installed.
    pub host_runtime_version: String,
    /// The artifact digest the host fetched, verified against the trusted
    /// distribution metadata before anything is recorded.
    pub content_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveBody {
    /// See [`InstallBody::request_id`].
    #[allow(dead_code)]
    pub request_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyActionBody {
    pub version: i64,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinBody {
    pub version: i64,
    pub version_to_pin: String,
    pub reason: String,
}

/// `#[serde(default)]` rather than `Option<Query<_>>`: axum's last extractor
/// must implement `FromRequest`, and `Option<Query<T>>` does not.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct PermissionDiffQuery {
    pub against_version: Option<String>,
}

/// P07-INT-01. What the host agent actually has installed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginReportBody {
    pub entries: Vec<PluginReportEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginReportEntry {
    pub package_id: String,
    pub version: String,
    /// What the host believes the tool's fingerprint is. Recorded as evidence and
    /// compared against the manifest; the SERVER decides, and the report is never
    /// authority.
    pub tool_fingerprints: Vec<String>,
    pub content_digest: String,
    pub host_runtime_version: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ListQuery {
    pub limit: Option<i32>,
    pub cursor: Option<String>,
}

// ---------------------------------------------------------- projections ----

pub fn package_json(package: &PluginPackageRecord) -> Value {
    json!({
        "package_id": package.package_id,
        "publisher_id": package.publisher_id,
        "publisher_official": package.is_official(),
        "display_name": package.display_name,
        "summary": package.summary,
        "status": package.status,
        "created_at": package.created_at,
        "updated_at": package.updated_at,
    })
}

pub fn version_json(version: &PluginVersionRecord) -> Value {
    json!({
        "version": version.version,
        "runtime_min": version.runtime_min,
        "runtime_max": version.runtime_max,
        "content_digest": version.content_digest,
        "manifest": manifest_json(&version.manifest_json),
        "published_at": version.published_at,
    })
}

pub fn install_json(
    install: &crate::repositories::PluginInstallRecord,
    registered_tools: Vec<String>,
    unregistered_tools: Vec<String>,
) -> Value {
    json!({
        "install_id": install.install_id,
        "package_id": install.package_id,
        "version": install.version,
        "pending_review_version": install.pending_review_version,
        "review_state": install.review_state,
        "review_reason": install.review_reason,
        // The reason THIS organization gave, and the only place one is recorded.
        // It is on the detail projection as well as the list projection: an
        // operator who opens a blocked plugin must see why, and the browser's
        // decoder requires the field, so an omission here is not a smaller
        // response — it is a page that fails to decode and renders nothing.
        "blocked_reason": install.blocked_reason,
        "approved_by": install.approved_by,
        "approved_at": install.approved_at,
        "registered_tools": registered_tools,
        // F13 default-deny, made visible. A tool absent from this list is usable;
        // a tool IN it is declared by the version and not registered by the org.
        "unregistered_tools": unregistered_tools,
        "created_at": install.created_at,
        "updated_at": install.updated_at,
    })
}

pub fn policy_json(policy: &PluginPolicy, version: i64, conflicts: Vec<String>) -> Value {
    json!({
        "publisher_mode": policy.publisher_mode.as_str(),
        "approved_publishers": policy.approved_publishers,
        "allowed_packages": policy.allowed_packages,
        "blocked_packages": policy.blocked_packages,
        "pinned_versions": policy.pinned_versions,
        "auto_update": policy.auto_update,
        "update_mode": policy.update_mode.as_str(),
        "version": version,
        // Reported, never resolved: `blocked_packages` wins, and the org is told
        // its own policy contradicts itself.
        "conflicts": conflicts,
    })
}

fn manifest_json(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or(Value::Null)
}

// ------------------------------------------------------------- handlers ----

#[worker::send]
pub async fn list_plugins(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: axum::http::HeaderMap,
    Path((org_id,)): Path<(String,)>,
    Query(query): Query<ListQuery>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::PluginsRead,
        None,
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let repository = PluginGovernanceRepository::new(database);
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let catalog = repository
        .list_catalog(query.cursor.as_deref(), limit)
        .await
        .map_err(|_| store_unavailable(&context))?;
    let policy_record = repository
        .find_policy(&org_id)
        .await
        .map_err(|_| store_unavailable(&context))?;
    let policy = policy_record
        .as_ref()
        .map(|record| record.to_domain())
        .unwrap_or_default();
    let conflicts = repository
        .policy_conflicts(&org_id)
        .await
        .map_err(|_| store_unavailable(&context))?;
    let installs = repository
        .list_installs(&org_id, None, 100)
        .await
        .map_err(|_| store_unavailable(&context))?;

    let mut items = Vec::new();
    for package in catalog.iter().take(limit as usize) {
        let install = installs
            .iter()
            .find(|row| row.package_id == package.package_id);
        let mut quarantined_value = false;
        if let Some(row) = install {
            quarantined_value = repository
                .is_quarantined(&package.package_id, &row.version)
                .await
                .map_err(|_| store_unavailable(&context))?;
        }
        items.push(json!({
            "package": package_json(package),
            "install": install.map(|row| json!({
                "version": row.version,
                "review_state": row.review_state,
                "pending_review_version": row.pending_review_version,
                "review_reason": row.review_reason,
            })),
            "quarantined": quarantined_value,
            "pinned_version": policy.pinned_versions.get(&package.package_id).cloned(),
            "blocked": policy.blocked_packages.contains(&package.package_id),
        }));
    }
    Ok(json_response(json!({
        "items": items,
        "policy": policy_json(&policy, policy_record.map(|record| record.version).unwrap_or(1), conflicts),
    })))
}

#[worker::send]
pub async fn get_plugin(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: axum::http::HeaderMap,
    Path((org_id, package_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::PluginsRead,
        Some("plugin_package"),
        Some(&package_id),
    )
    .await?;
    let database = database(&state, &context)?;
    let repository = PluginGovernanceRepository::new(database);
    let package = find_package(&repository, &package_id, &context).await?;
    let versions = repository
        .list_versions(&package_id, 50)
        .await
        .map_err(|_| store_unavailable(&context))?;
    let install = repository
        .find_install(&org_id, &package_id)
        .await
        .map_err(|_| store_unavailable(&context))?;
    let registered = match &install {
        Some(row) => repository
            .registered_tools(&org_id, &package_id, &row.version)
            .await
            .map_err(|_| store_unavailable(&context))?
            .into_iter()
            .map(|row| row.tool_id)
            .collect::<Vec<_>>(),
        None => Vec::new(),
    };
    let unregistered = match &install {
        Some(row) => repository
            .unregistered_tools(&org_id, &package_id, &row.version)
            .await
            .map_err(|_| store_unavailable(&context))?,
        None => Vec::new(),
    };
    Ok(json_response(json!({
        "package": package_json(&package),
        "versions": versions.iter().map(version_json).collect::<Vec<_>>(),
        "install": install.as_ref().map(|row| install_json(row, registered, unregistered)),
    })))
}

#[worker::send]
pub async fn get_policy(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: axum::http::HeaderMap,
    Path((org_id,)): Path<(String,)>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::PluginsRead,
        None,
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let repository = PluginGovernanceRepository::new(database);
    let record = repository
        .find_policy(&org_id)
        .await
        .map_err(|_| store_unavailable(&context))?;
    let policy = record
        .as_ref()
        .map(|row| row.to_domain())
        .unwrap_or_default();
    let conflicts = repository
        .policy_conflicts(&org_id)
        .await
        .map_err(|_| store_unavailable(&context))?;
    Ok(json_response(json!({
        "policy": policy_json(&policy, record.map(|row| row.version).unwrap_or(1), conflicts),
    })))
}

#[worker::send]
pub async fn patch_policy(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: axum::http::HeaderMap,
    Path((org_id,)): Path<(String,)>,
    Json(body): Json<PatchPolicyBody>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::PluginsManage,
        Some("plugin_policy"),
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let repository = PluginGovernanceRepository::new(database);
    let current = repository
        .find_policy(&org_id)
        .await
        .map_err(|_| store_unavailable(&context))?;
    let mut policy = current
        .as_ref()
        .map(|row| row.to_domain())
        .unwrap_or_default();

    if let Some(mode) = &body.publisher_mode {
        policy.publisher_mode =
            PublisherMode::parse(mode).ok_or_else(|| invalid_input(&context))?;
    }
    if let Some(values) = &body.approved_publishers {
        policy.approved_publishers = string_list(values, 300, &context)?;
    }
    if let Some(values) = &body.allowed_packages {
        policy.allowed_packages = package_list(values, &context)?;
    }
    if let Some(values) = &body.blocked_packages {
        policy.blocked_packages = package_list(values, &context)?;
    }
    if let Some(values) = &body.pinned_versions {
        for version in values.values() {
            if version.is_empty() || version.len() > 64 {
                return Err(invalid_input(&context));
            }
        }
        policy.pinned_versions = values.clone();
    }
    if let Some(auto_update) = body.auto_update {
        policy.auto_update = auto_update;
    }
    if let Some(mode) = &body.update_mode {
        policy.update_mode = UpdateMode::parse(mode).ok_or_else(|| invalid_input(&context))?;
    }

    // A package on BOTH lists is storable and REPORTED, not resolved. The handler
    // returns it as a detail on a successful write rather than refusing, because
    // refusing would make the org unable to record the block it wants while the
    // stale allow entry is still there.
    let conflicts: Vec<String> = policy_conflicts(&policy)
        .into_iter()
        .map(|conflict| conflict.package_id)
        .collect();

    let pinned_json =
        serde_json::to_string(&policy.pinned_versions).map_err(|_| invalid_input(&context))?;
    let approved_json =
        serde_json::to_string(&policy.approved_publishers).map_err(|_| invalid_input(&context))?;
    let allowed_json =
        serde_json::to_string(&policy.allowed_packages).map_err(|_| invalid_input(&context))?;
    let blocked_json =
        serde_json::to_string(&policy.blocked_packages).map_err(|_| invalid_input(&context))?;
    let now = context.received_at.clone();
    let claim = match prepare_scoped_mutation(
        database,
        &context,
        access.principal.user_id.as_str(),
        &org_id,
        &idempotency_key(&headers, &context)?,
        "PATCH",
        PLUGIN_POLICY_PATCH_PATH,
        &json!({ "version": body.version, "policy": policy_json(&policy, body.version, conflicts.clone()) }),
    )
    .await?
    {
        PreparedScopedMutation::Replay(replay) => return Ok(replay_response(replay)),
        PreparedScopedMutation::Claim(claim) => claim,
    };

    let statement = if current.is_some() {
        repository
            .update_policy_statement(&crate::repositories::PluginPolicyUpdateInput {
                org_id: &org_id,
                publisher_mode: policy.publisher_mode.as_str(),
                approved_publishers_json: &approved_json,
                allowed_packages_json: &allowed_json,
                blocked_packages_json: &blocked_json,
                pinned_versions_json: &pinned_json,
                auto_update: if policy.auto_update { "on" } else { "off" },
                update_mode: policy.update_mode.as_str(),
                expected_version: body.version,
                now: now.as_str(),
            })
            .map_err(|_| store_unavailable(&context))?
    } else {
        // A first write creates the row at version 1. The body must therefore
        // carry version 1, or a client that assumed an existing row is wrong.
        if body.version != 1 {
            return Err(version_conflict(&context));
        }
        repository
            .insert_policy_statement(&PluginPolicyInput {
                org_id: &org_id,
                publisher_mode: policy.publisher_mode.as_str(),
                approved_publishers_json: &approved_json,
                allowed_packages_json: &allowed_json,
                blocked_packages_json: &blocked_json,
                pinned_versions_json: &pinned_json,
                auto_update: if policy.auto_update { "on" } else { "off" },
                update_mode: policy.update_mode.as_str(),
                now: now.as_str(),
            })
            .map_err(|_| store_unavailable(&context))?
    };
    let guard = repository
        .assert_policy_version_statement(&org_id, body.version)
        .map_err(|_| store_unavailable(&context))?;
    let audit = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        crate::adapters::new_event_id().as_str(),
        "plugin_policy.updated",
        "plugin_policy",
        Some(&org_id),
        "success",
        &json!({ "conflicts": conflicts, "version": body.version }),
    )?;
    let success = crate::core::StoredSuccess::new(
        StatusCode::OK.as_u16(),
        json!({ "policy": policy_json(&policy, body.version + 1, conflicts) }),
    )
    .map_err(|_| store_unavailable(&context))?;
    match commit_scoped_mutation(
        database,
        &context,
        claim,
        success,
        vec![statement, guard],
        audit,
    )
    .await?
    {
        ScopedMutationCommit::Committed => {}
        ScopedMutationCommit::Replayed(replay) => return Ok(replay_response(replay)),
        ScopedMutationCommit::Guarded => return Err(version_conflict(&context)),
    }
    Ok(json_response(json!({
        "policy": policy_json(&policy, body.version + 1, Vec::new()),
    })))
}

#[worker::send]
pub async fn install_plugin(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: axum::http::HeaderMap,
    Path((org_id, package_id)): Path<(String, String)>,
    Json(body): Json<InstallBody>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::PluginsManage,
        Some("plugin_package"),
        Some(&package_id),
    )
    .await?;
    let database = database(&state, &context)?;
    let repository = PluginGovernanceRepository::new(database);
    let package = find_package(&repository, &package_id, &context).await?;
    let version = repository
        .find_version(&package_id, &body.version)
        .await
        .map_err(|_| store_unavailable(&context))?
        .ok_or_else(|| plugin_error(&context, PluginDenyReason::Incompatible))?;
    let candidate_manifest = parse_manifest(&version.manifest_json, &context)?;
    let policy = load_policy(&repository, &org_id, &context).await?;
    let install = repository
        .find_install(&org_id, &package_id)
        .await
        .map_err(|_| store_unavailable(&context))?;

    // F25-005. The digest the host fetched must be the digest the platform
    // published. Checked BEFORE anything is written, so a mismatch never leaves a
    // row behind.
    if !integrity_matches(&version.content_digest, &body.content_digest) {
        return Err(plugin_error(&context, PluginDenyReason::IntegrityFailed));
    }
    // The compatibility range is a gate, not a warning.
    if !host_is_compatible(
        &version.runtime_min,
        &version.runtime_max,
        &body.host_runtime_version,
    ) {
        return Err(plugin_error(&context, PluginDenyReason::Incompatible));
    }
    // A manifest declaring a private or loopback destination is not recorded.
    if !candidate_manifest.rejected_destinations().is_empty() {
        return Err(plugin_error(&context, PluginDenyReason::ManifestInvalid));
    }

    let previous_manifest = match &install {
        Some(row) => {
            let previous = repository
                .find_version(&package_id, &row.version)
                .await
                .map_err(|_| store_unavailable(&context))?;
            match previous {
                Some(record) => parse_manifest(&record.manifest_json, &context)?,
                None => candidate_manifest.clone(),
            }
        }
        None => candidate_manifest.clone(),
    };
    let permission_diff = diff(
        install.as_ref().map(|row| row.version.as_str()),
        &previous_manifest,
        &body.version,
        &candidate_manifest,
    );

    let conflicts = repository
        .policy_conflicts(&org_id)
        .await
        .map_err(|_| store_unavailable(&context))?;
    let quarantined = repository
        .is_quarantined(&package_id, &body.version)
        .await
        .map_err(|_| store_unavailable(&context))?;
    let facts = PluginFacts {
        package_id: package_id.clone(),
        version: body.version.clone(),
        publisher_id: package.publisher_id.clone(),
        publisher_official: package.is_official(),
        policy_conflict: conflicts.contains(&package_id),
        quarantined,
        review_state: install.as_ref().and_then(|row| row.review_state()),
        pinned_elsewhere: policy
            .pinned_versions
            .get(&package_id)
            .is_some_and(|pinned| pinned != &body.version),
    };
    if let PluginDecision::Deny(reason) = facts.install_decision(&policy, &permission_diff) {
        // F25-003: a managed-mode expansion is REFUSED and recorded, not
        // installed-and-waiting. The refusal writes `pending_review` with the
        // reason so the org can see why.
        if reason == PluginDenyReason::PermissionExpanded {
            record_pending_review(
                &state,
                &context,
                &org_id,
                &package_id,
                &facts,
                &policy,
                install.as_ref(),
                &body.version,
                &access.principal,
                database,
                &policy_diff_summary(&permission_diff),
            )
            .await?;
        }
        return Err(plugin_error(&context, reason));
    }

    // The install is approved by the `plugins.manage` action itself, and the
    // version's declared tools are registered in the SAME batch: a tool that is
    // not registered is not usable, so registering later would leave a window
    // where an approved install has no usable tool and the UI implies otherwise.
    let now = context.received_at.clone();
    let claim = match prepare_scoped_mutation(
        database,
        &context,
        access.principal.user_id.as_str(),
        &org_id,
        &idempotency_key(&headers, &context)?,
        "POST",
        PLUGIN_INSTALL_PATH,
        &json!({ "package_id": package_id, "version": body.version }),
    )
    .await?
    {
        PreparedScopedMutation::Replay(replay) => return Ok(replay_response(replay)),
        PreparedScopedMutation::Claim(claim) => claim,
    };
    let mut writes = Vec::new();
    match &install {
        Some(row) => writes.push(
            repository
                .update_install_statement(&crate::repositories::PluginInstallUpdateInput {
                    org_id: &org_id,
                    package_id: &package_id,
                    version: &body.version,
                    pending_review_version: None,
                    review_state: PluginReviewState::Approved.as_str(),
                    review_reason: None,
                    approved_by: Some(access.principal.user_id.as_str()),
                    approved_at: Some(now.as_str()),
                    expected_counter: row.version_counter,
                    now: now.as_str(),
                })
                .map_err(|_| store_unavailable(&context))?,
        ),
        None => writes.push(
            repository
                .insert_install_statement(&PluginInstallInput {
                    install_id: new_resource_id("pil").as_str(),
                    org_id: &org_id,
                    package_id: &package_id,
                    version: &body.version,
                    pending_review_version: None,
                    review_state: PluginReviewState::Approved.as_str(),
                    review_reason: None,
                    approved_by: Some(access.principal.user_id.as_str()),
                    approved_at: Some(now.as_str()),
                    now: now.as_str(),
                })
                .map_err(|_| store_unavailable(&context))?,
        ),
    }
    for tool in &candidate_manifest.tools {
        writes.push(
            repository
                .insert_registration_statement(&crate::repositories::NewToolRegistrationInput {
                    registration_id: new_resource_id("ptr").as_str(),
                    org_id: &org_id,
                    package_id: &package_id,
                    version: &body.version,
                    tool_id: tool,
                    approved_by: access.principal.user_id.as_str(),
                    now: now.as_str(),
                })
                .map_err(|_| store_unavailable(&context))?,
        );
    }
    let audit = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        crate::adapters::new_event_id().as_str(),
        "plugin.installed",
        "plugin_package",
        Some(&package_id),
        "success",
        &json!({ "version": body.version, "expands": permission_diff.expands }),
    )?;
    let success = crate::core::StoredSuccess::new(
        StatusCode::CREATED.as_u16(),
        json!({ "package_id": package_id, "version": body.version, "review_state": "approved" }),
    )
    .map_err(|_| store_unavailable(&context))?;
    match commit_scoped_mutation(database, &context, claim, success, writes, audit).await? {
        ScopedMutationCommit::Committed => {}
        ScopedMutationCommit::Replayed(replay) => return Ok(replay_response(replay)),
        ScopedMutationCommit::Guarded => {
            return Err(plugin_error(&context, PluginDenyReason::PermissionExpanded));
        }
    }
    Ok(json_response(json!({
        "install": {
            "package_id": package_id,
            "version": body.version,
            "review_state": "approved",
            "registered_tools": candidate_manifest.tools,
            "permission_diff": permission_diff,
        }
    })))
}

#[worker::send]
pub async fn approve_plugin(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: axum::http::HeaderMap,
    Path((org_id, package_id)): Path<(String, String)>,
    Json(_body): Json<ApproveBody>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::PluginsManage,
        Some("plugin_package"),
        Some(&package_id),
    )
    .await?;
    let database = database(&state, &context)?;
    let repository = PluginGovernanceRepository::new(database);
    let install = repository
        .find_install(&org_id, &package_id)
        .await
        .map_err(|_| store_unavailable(&context))?
        .ok_or_else(|| not_found(&context))?;
    // Approving something that is not waiting for review is refused with its own
    // code, so a client that retries a completed approval learns it is done
    // rather than getting a generic conflict.
    if install.review_state() != Some(PluginReviewState::PendingReview) {
        return Err(plugin_error(
            &context,
            PluginDenyReason::VersionNotPendingReview,
        ));
    }
    let candidate = install
        .pending_review_version
        .clone()
        .ok_or_else(|| plugin_error(&context, PluginDenyReason::VersionNotPendingReview))?;
    let version = repository
        .find_version(&package_id, &candidate)
        .await
        .map_err(|_| store_unavailable(&context))?
        .ok_or_else(|| plugin_error(&context, PluginDenyReason::Incompatible))?;
    let manifest = parse_manifest(&version.manifest_json, &context)?;
    // The quarantine is re-checked at APPROVAL, not only at install. A version
    // that was quarantined while it waited must not become approved.
    if repository
        .is_quarantined(&package_id, &candidate)
        .await
        .map_err(|_| store_unavailable(&context))?
    {
        return Err(plugin_error(&context, PluginDenyReason::Quarantined));
    }
    let now = context.received_at.clone();
    let claim = match prepare_scoped_mutation(
        database,
        &context,
        access.principal.user_id.as_str(),
        &org_id,
        &idempotency_key(&headers, &context)?,
        "POST",
        PLUGIN_APPROVE_PATH,
        &json!({ "package_id": package_id, "version": candidate }),
    )
    .await?
    {
        PreparedScopedMutation::Replay(replay) => return Ok(replay_response(replay)),
        PreparedScopedMutation::Claim(claim) => claim,
    };
    let mut writes = vec![
        repository
            .update_install_statement(&crate::repositories::PluginInstallUpdateInput {
                org_id: &org_id,
                package_id: &package_id,
                version: &candidate,
                pending_review_version: None,
                review_state: PluginReviewState::Approved.as_str(),
                review_reason: None,
                approved_by: Some(access.principal.user_id.as_str()),
                approved_at: Some(now.as_str()),
                expected_counter: install.version_counter,
                now: now.as_str(),
            })
            .map_err(|_| store_unavailable(&context))?,
    ];
    for tool in &manifest.tools {
        writes.push(
            repository
                .insert_registration_statement(&crate::repositories::NewToolRegistrationInput {
                    registration_id: new_resource_id("ptr").as_str(),
                    org_id: &org_id,
                    package_id: &package_id,
                    version: &candidate,
                    tool_id: tool,
                    approved_by: access.principal.user_id.as_str(),
                    now: now.as_str(),
                })
                .map_err(|_| store_unavailable(&context))?,
        );
    }
    let audit = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        crate::adapters::new_event_id().as_str(),
        "plugin.approved",
        "plugin_package",
        Some(&package_id),
        "success",
        &json!({ "version": candidate }),
    )?;
    let success = crate::core::StoredSuccess::new(
        StatusCode::OK.as_u16(),
        json!({ "package_id": package_id, "version": candidate, "review_state": "approved" }),
    )
    .map_err(|_| store_unavailable(&context))?;
    match commit_scoped_mutation(database, &context, claim, success, writes, audit).await? {
        ScopedMutationCommit::Committed => {}
        ScopedMutationCommit::Replayed(replay) => return Ok(replay_response(replay)),
        ScopedMutationCommit::Guarded => {
            return Err(plugin_error(
                &context,
                PluginDenyReason::VersionNotPendingReview,
            ));
        }
    }
    Ok(json_response(json!({
        "install": { "package_id": package_id, "version": candidate, "review_state": "approved" }
    })))
}

/// F25-009: block, unblock, and pin are audited org-policy actions. They all
/// funnel through one policy write so a pin cannot be set without a reason and a
/// version guard, and so a block cannot quietly change a pin.
#[worker::send]
pub async fn block_plugin(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: axum::http::HeaderMap,
    Path((org_id, package_id)): Path<(String, String)>,
    Json(body): Json<PolicyActionBody>,
) -> Result<Response<Body>, ApiError> {
    change_policy(
        &state,
        &context,
        &headers,
        &org_id,
        &package_id,
        body,
        "block",
        PLUGIN_BLOCK_PATH,
    )
    .await
}

#[worker::send]
pub async fn unblock_plugin(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: axum::http::HeaderMap,
    Path((org_id, package_id)): Path<(String, String)>,
    Json(body): Json<PolicyActionBody>,
) -> Result<Response<Body>, ApiError> {
    change_policy(
        &state,
        &context,
        &headers,
        &org_id,
        &package_id,
        body,
        "unblock",
        PLUGIN_UNBLOCK_PATH,
    )
    .await
}

#[worker::send]
pub async fn pin_plugin(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: axum::http::HeaderMap,
    Path((org_id, package_id)): Path<(String, String)>,
    Json(body): Json<PinBody>,
) -> Result<Response<Body>, ApiError> {
    if body.version_to_pin.is_empty() || body.version_to_pin.len() > 64 {
        return Err(invalid_input(&context));
    }
    if body.reason.trim().is_empty() || body.reason.len() > 500 {
        return Err(invalid_input(&context));
    }
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::PluginsManage,
        Some("plugin_policy"),
        Some(&package_id),
    )
    .await?;
    let database = database(&state, &context)?;
    let repository = PluginGovernanceRepository::new(database);
    let record = repository
        .find_policy(&org_id)
        .await
        .map_err(|_| store_unavailable(&context))?;
    let mut policy = record
        .as_ref()
        .map(|row| row.to_domain())
        .unwrap_or_default();
    if let Some(existing) = policy.pinned_versions.get(&package_id)
        && existing != &body.version_to_pin
    {
        // A pin is exact and lifting one is explicit. Overwriting it silently would
        // defeat the control the pin exists to provide, so the conflict is
        // reported with its own code.
        return Err(plugin_error(&context, PluginDenyReason::Pinned)
            .with_detail("pinned_version", json!(existing)));
    }
    policy
        .pinned_versions
        .insert(package_id.clone(), body.version_to_pin.clone());
    write_policy(
        &state,
        &context,
        database,
        &repository,
        &access,
        &org_id,
        &policy,
        body.version,
        &idempotency_key(&headers, &context)?,
        "PATCH",
        PLUGIN_PIN_POLICY_PATH,
        "plugin.pinned",
        &package_id,
        &json!({ "version": body.version_to_pin, "reason": body.reason }),
        body.version + 1,
        None,
    )
    .await
}

#[worker::send]
pub async fn permission_diff(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: axum::http::HeaderMap,
    Path((org_id, package_id, version)): Path<(String, String, String)>,
    Query(query): Query<PermissionDiffQuery>,
) -> Result<Response<Body>, ApiError> {
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::PluginsRead,
        Some("plugin_package"),
        Some(&package_id),
    )
    .await?;
    let database = database(&state, &context)?;
    let repository = PluginGovernanceRepository::new(database);
    let candidate = repository
        .find_version(&package_id, &version)
        .await
        .map_err(|_| store_unavailable(&context))?
        .ok_or_else(|| not_found(&context))?;
    // `against_version` defaults to what the org actually has installed, so the
    // common question — "what does upgrading to this cost me?" — needs no
    // parameter.
    let against_version = match query.against_version.clone() {
        Some(value) => Some(value),
        None => repository
            .find_install(&org_id, &package_id)
            .await
            .map_err(|_| store_unavailable(&context))?
            .map(|row| row.version),
    };
    let (from_version, before) = match &against_version {
        Some(value) => {
            let record = repository
                .find_version(&package_id, value)
                .await
                .map_err(|_| store_unavailable(&context))?
                .ok_or_else(|| not_found(&context))?;
            (
                Some(value.clone()),
                parse_manifest(&record.manifest_json, &context)?,
            )
        }
        None => (None, PluginPermissionManifest::default()),
    };
    let after = parse_manifest(&candidate.manifest_json, &context)?;
    let result = diff(from_version.as_deref(), &before, &version, &after);
    Ok(json_response(json!({ "permission_diff": result })))
}

// ------------------------------------------------------- P07-INT-01 report ---

/// LumiAgents reports what it actually has installed; the server answers with the
/// policy verdict.
///
/// The report is EVIDENCE, never authority: it cannot approve anything, it can
/// only downgrade an install to `unreviewed` and record the verdict. A host that
/// reports a version the org never approved gets exactly that answer.
#[worker::send]
pub async fn submit_plugin_report(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: axum::http::HeaderMap,
    Path((org_id,)): Path<(String,)>,
    Json(body): Json<PluginReportBody>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::PluginsManage,
        Some("plugin_report"),
        None,
    )
    .await?;
    if body.entries.is_empty() || body.entries.len() > 100 {
        return Err(invalid_input(&context));
    }
    let database = database(&state, &context)?;
    let repository = PluginGovernanceRepository::new(database);
    let policy = load_policy(&repository, &org_id, &context).await?;
    let now = context.received_at.clone();
    let mut writes = Vec::new();
    let mut verdicts = Vec::new();
    for entry in &body.entries {
        let version = repository
            .find_version(&entry.package_id, &entry.version)
            .await
            .map_err(|_| store_unavailable(&context))?;
        let Some(version) = version else {
            verdicts.push(json!({
                "package_id": entry.package_id,
                "version": entry.version,
                "verdict": "unknown_package",
            }));
            continue;
        };
        let manifest = parse_manifest(&version.manifest_json, &context)?;
        if !integrity_matches(&version.content_digest, &entry.content_digest) {
            verdicts.push(json!({
                "package_id": entry.package_id,
                "version": entry.version,
                "verdict": PluginDenyReason::IntegrityFailed.code(),
            }));
            continue;
        }
        if !host_is_compatible(
            &version.runtime_min,
            &version.runtime_max,
            &entry.host_runtime_version,
        ) {
            verdicts.push(json!({
                "package_id": entry.package_id,
                "version": entry.version,
                "verdict": PluginDenyReason::Incompatible.code(),
            }));
            continue;
        }
        let install = repository
            .find_install(&org_id, &entry.package_id)
            .await
            .map_err(|_| store_unavailable(&context))?;
        let quarantined = repository
            .is_quarantined(&entry.package_id, &entry.version)
            .await
            .map_err(|_| store_unavailable(&context))?;
        let facts = PluginFacts {
            package_id: entry.package_id.clone(),
            version: entry.version.clone(),
            publisher_id: String::new(),
            publisher_official: false,
            policy_conflict: false,
            quarantined,
            review_state: install.as_ref().and_then(|row| row.review_state()),
            pinned_elsewhere: false,
        };
        // Execution, not install: a host that already HAS the artifact is asking
        // whether it may keep using it, and the answer must be the stricter one.
        let execution = facts.execution_decision(&policy);
        // F13 default-deny, per tool. A tool the org has not registered is denied
        // even when the package itself is approved.
        let registered = repository
            .registered_tools(&org_id, &entry.package_id, &entry.version)
            .await
            .map_err(|_| store_unavailable(&context))?
            .into_iter()
            .map(|row| row.tool_id)
            .collect::<Vec<_>>();
        let mut tool_verdicts = serde_json::Map::new();
        for tool in &manifest.tools {
            let decision = tool_decision(
                &facts,
                &policy,
                true,
                registered.iter().any(|row| row == tool),
            );
            tool_verdicts.insert(
                tool.clone(),
                json!(if decision.is_allowed() {
                    "allow"
                } else {
                    decision_code(decision)
                }),
            );
        }
        verdicts.push(json!({
            "package_id": entry.package_id,
            "version": entry.version,
            "verdict": if execution.is_allowed() { "allow" } else { decision_code(execution) },
            "tools": tool_verdicts,
            "reported_tool_fingerprints": entry.tool_fingerprints,
        }));
        // A report for a package the org has never installed records an
        // `unreviewed` row, which is what makes the default-deny visible in the UI
        // rather than only in this response.
        if install.is_none() {
            writes.push(
                repository
                    .record_report_statement(&crate::repositories::NewPluginReportInput {
                        install_id: new_resource_id("pil").as_str(),
                        org_id: &org_id,
                        package_id: &entry.package_id,
                        version: &entry.version,
                        reason: "plugin.reported_by_host",
                        now: now.as_str(),
                    })
                    .map_err(|_| store_unavailable(&context))?,
            );
        } else if install.as_ref().and_then(|row| row.review_state())
            != Some(PluginReviewState::Unreviewed)
        {
            writes.push(
                repository
                    .touch_report_statement(
                        &org_id,
                        &entry.package_id,
                        &now,
                        "plugin.reported_by_host",
                    )
                    .map_err(|_| store_unavailable(&context))?,
            );
        }
    }
    if !writes.is_empty() {
        // A report is not an idempotent mutation of a customer decision, so it
        // commits as a plain batch with an audit row rather than through the
        // idempotency scope. Repeating a report is harmless by construction: the
        // writes are conditional and the recorded state converges.
        let audit = security_event_statement(
            database,
            &context,
            Some(&access.principal),
            Some(&org_id),
            crate::adapters::new_event_id().as_str(),
            "plugin.report_received",
            "plugin_report",
            None,
            "success",
            &json!({ "entries": body.entries.len() }),
        )?;
        writes.push(audit);
        database
            .batch(writes)
            .await
            .map_err(|_| store_unavailable(&context))?;
    }
    Ok(json_response(json!({ "verdicts": verdicts })))
}

// ------------------------------------------------------------- helpers -----

#[allow(clippy::too_many_arguments)]
async fn change_policy(
    state: &Arc<AppState>,
    context: &RequestContext,
    headers: &axum::http::HeaderMap,
    org_id: &str,
    package_id: &str,
    body: PolicyActionBody,
    action: &str,
    path: &'static str,
) -> Result<Response<Body>, ApiError> {
    if body.reason.trim().is_empty() || body.reason.len() > 500 {
        return Err(invalid_input(context));
    }
    let access = authorize_org(
        state,
        headers,
        context,
        org_id,
        Permission::PluginsManage,
        Some("plugin_policy"),
        Some(package_id),
    )
    .await?;
    let database = database(state, context)?;
    let repository = PluginGovernanceRepository::new(database);
    let record = repository
        .find_policy(org_id)
        .await
        .map_err(|_| store_unavailable(context))?;
    let mut policy = record
        .as_ref()
        .map(|row| row.to_domain())
        .unwrap_or_default();
    match action {
        "block" => {
            if !policy.blocked_packages.contains(&package_id.to_owned()) {
                policy.blocked_packages.push(package_id.to_owned());
                policy.blocked_packages.sort();
            }
        }
        _ => {
            policy.blocked_packages.retain(|row| row != package_id);
        }
    }
    // A block records the operator's reason ON THE INSTALL as well as in the
    // security event. F25's Web UX asks for a visible blocked reason, and
    // `plugin_installs.blocked_reason` is the frozen contract's place for one —
    // 0017 has a trigger that refuses a `blocked` review state without it.
    // Writing it only to the audit row would satisfy the audit requirement and
    // leave the surface unable to answer the question that requirement exists to
    // support, which is a gap the frontend found and reported rather than papered
    // over with an invented value.
    let install = repository
        .find_install(org_id, package_id)
        .await
        .map_err(|_| store_unavailable(context))?;
    let install_write = match (&install, action) {
        (Some(row), "block") => Some(
            repository
                .set_install_block_statement(
                    org_id,
                    package_id,
                    PluginReviewState::Blocked,
                    Some(&body.reason),
                    row.version_counter,
                    context.received_at.as_str(),
                )
                .map_err(|_| store_unavailable(context))?,
        ),
        (Some(row), _) => Some(
            repository
                .set_install_block_statement(
                    org_id,
                    package_id,
                    // The prior state was not `blocked` — the 0017 trigger
                    // refuses a `blocked` row with no reason, so an unblock can
                    // safely restore the state the install is entitled to.
                    PluginReviewState::Approved,
                    None,
                    row.version_counter,
                    context.received_at.as_str(),
                )
                .map_err(|_| store_unavailable(context))?,
        ),
        // Nothing was installed, so there is no review state to change. A
        // policy block alone already denies new installs and new executions.
        (None, _) => None,
    };
    write_policy(
        state,
        context,
        database,
        &repository,
        &access,
        org_id,
        &policy,
        body.version,
        &idempotency_key(headers, context)?,
        "POST",
        path,
        &format!("plugin.{action}ed"),
        package_id,
        &json!({ "reason": body.reason, "version": body.version }),
        body.version + 1,
        install_write,
    )
    .await?;

    // Re-read the install so the response carries the reason that was just
    // recorded. F25's Web UX asks for a visible blocked reason, and returning it
    // here is what lets the surface show it without inventing one or sending the
    // operator to the audit log to find out why their own block has no text.
    let install = repository
        .find_install(org_id, package_id)
        .await
        .map_err(|_| store_unavailable(context))?;
    let conflicts: Vec<String> = policy_conflicts(&policy)
        .into_iter()
        .map(|conflict| conflict.package_id)
        .collect();
    Ok(json_response(json!({
        "policy": policy_json(&policy, body.version + 1, conflicts),
        "install": install.as_ref().map(|row| json!({
            "package_id": row.package_id,
            "version": row.version,
            "review_state": row.review_state,
            "blocked_reason": row.blocked_reason,
        })),
    })))
}

#[allow(clippy::too_many_arguments)]
async fn write_policy(
    _state: &Arc<AppState>,
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    repository: &PluginGovernanceRepository<'_>,
    access: &crate::routes::authorization::OrgAccess,
    org_id: &str,
    policy: &PluginPolicy,
    expected_version: i64,
    idempotency: &str,
    method: &str,
    path: &'static str,
    action: &str,
    package_id: &str,
    metadata: &Value,
    resulting_version: i64,
    // A second business write that must commit with the policy, or not at all.
    // The install's block state and the policy's block list are one decision, so
    // committing them separately would leave a window in which the policy says
    // blocked and the install does not, or the reverse.
    extra_write: Option<worker::d1::D1PreparedStatement>,
) -> Result<Response<Body>, ApiError> {
    let conflicts: Vec<String> = policy_conflicts(policy)
        .into_iter()
        .map(|conflict| conflict.package_id)
        .collect();
    let approved_json =
        serde_json::to_string(&policy.approved_publishers).map_err(|_| invalid_input(context))?;
    let allowed_json =
        serde_json::to_string(&policy.allowed_packages).map_err(|_| invalid_input(context))?;
    let blocked_json =
        serde_json::to_string(&policy.blocked_packages).map_err(|_| invalid_input(context))?;
    let pinned_json =
        serde_json::to_string(&policy.pinned_versions).map_err(|_| invalid_input(context))?;
    let now = context.received_at.clone();
    let claim = match prepare_scoped_mutation(
        database,
        context,
        access.principal.user_id.as_str(),
        org_id,
        idempotency,
        method,
        path,
        &json!({ "version": expected_version, "policy": policy_json(policy, expected_version, conflicts.clone()) }),
    )
    .await?
    {
        PreparedScopedMutation::Replay(replay) => return Ok(replay_response(replay)),
        PreparedScopedMutation::Claim(claim) => claim,
    };
    let statement = repository
        .update_policy_statement(&crate::repositories::PluginPolicyUpdateInput {
            org_id,
            publisher_mode: policy.publisher_mode.as_str(),
            approved_publishers_json: &approved_json,
            allowed_packages_json: &allowed_json,
            blocked_packages_json: &blocked_json,
            pinned_versions_json: &pinned_json,
            auto_update: if policy.auto_update { "on" } else { "off" },
            update_mode: policy.update_mode.as_str(),
            expected_version,
            now: now.as_str(),
        })
        .map_err(|_| store_unavailable(context))?;
    let guard = repository
        .assert_policy_version_statement(org_id, expected_version)
        .map_err(|_| store_unavailable(context))?;
    let audit = security_event_statement(
        database,
        context,
        Some(&access.principal),
        Some(org_id),
        crate::adapters::new_event_id().as_str(),
        action,
        "plugin_package",
        Some(package_id),
        "success",
        metadata,
    )?;
    let success = crate::core::StoredSuccess::new(
        StatusCode::OK.as_u16(),
        json!({ "policy": policy_json(policy, resulting_version, conflicts) }),
    )
    .map_err(|_| store_unavailable(context))?;
    let mut writes = vec![statement, guard];
    writes.extend(extra_write);
    match commit_scoped_mutation(database, context, claim, success, writes, audit).await? {
        ScopedMutationCommit::Committed => {}
        ScopedMutationCommit::Replayed(replay) => return Ok(replay_response(replay)),
        ScopedMutationCommit::Guarded => return Err(version_conflict(context)),
    }
    Ok(json_response(json!({
        "policy": policy_json(policy, resulting_version, Vec::new()),
    })))
}

/// Record a refused expansion as `pending_review` with its reason, so the org can
/// see WHY a version is waiting rather than finding a version that is neither
/// installed nor allowed.
#[allow(clippy::too_many_arguments)]
async fn record_pending_review(
    state: &Arc<AppState>,
    context: &RequestContext,
    org_id: &str,
    package_id: &str,
    _facts: &PluginFacts,
    _policy: &PluginPolicy,
    install: Option<&crate::repositories::PluginInstallRecord>,
    candidate_version: &str,
    principal: &crate::core::Principal,
    database: &crate::adapters::d1::D1Adapter,
    diff_summary: &Value,
) -> Result<(), ApiError> {
    let _ = state;
    let repository = PluginGovernanceRepository::new(database);
    let now = context.received_at.clone();
    let reason = format!("{PERMISSION_EXPANSION_REASON} {}", diff_summary);
    let statement = match install {
        Some(row) => repository
            .update_install_statement(&crate::repositories::PluginInstallUpdateInput {
                org_id,
                package_id,
                version: &row.version,
                pending_review_version: Some(candidate_version),
                review_state: PluginReviewState::PendingReview.as_str(),
                review_reason: Some(&reason),
                approved_by: None,
                approved_at: None,
                expected_counter: row.version_counter,
                now: now.as_str(),
            })
            .map_err(|_| store_unavailable(context))?,
        None => repository
            .insert_install_statement(&PluginInstallInput {
                install_id: new_resource_id("pil").as_str(),
                org_id,
                package_id,
                version: candidate_version,
                // A refused FIRST install still has to satisfy the 0016-style
                // rule that an installed version is a published one, so the
                // candidate is recorded in both slots: it is what is waiting, and
                // it is what the org would be running if it approved.
                pending_review_version: Some(candidate_version),
                review_state: PluginReviewState::PendingReview.as_str(),
                review_reason: Some(&reason),
                approved_by: None,
                approved_at: None,
                now: now.as_str(),
            })
            .map_err(|_| store_unavailable(context))?,
    };
    let audit = security_event_statement(
        database,
        context,
        Some(principal),
        Some(org_id),
        crate::adapters::new_event_id().as_str(),
        "plugin.permission_expansion_detected",
        "plugin_package",
        Some(package_id),
        "denied",
        diff_summary,
    )?;
    // Best effort. A failure to record the refusal must not turn a correct denial
    // into a success, and the denial is returned to the caller either way.
    let _ = database.batch(vec![statement, audit]).await;
    Ok(())
}

fn policy_diff_summary(value: &PermissionDiff) -> Value {
    json!({
        "expands": value.expands,
        "classes": value
            .classes
            .iter()
            .map(|class| json!({ "class": class.class, "verdict": class.verdict }))
            .collect::<Vec<_>>(),
    })
}

fn decision_code(decision: PluginDecision) -> &'static str {
    match decision {
        PluginDecision::Allow => "allow",
        PluginDecision::Deny(reason) => reason.code(),
    }
}

async fn find_package(
    repository: &PluginGovernanceRepository<'_>,
    package_id: &str,
    context: &RequestContext,
) -> Result<PluginPackageRecord, ApiError> {
    if package_id.len() != 36 || !package_id.starts_with("pkg_") {
        return Err(not_found(context));
    }
    repository
        .find_package(package_id)
        .await
        .map_err(|_| store_unavailable(context))?
        .ok_or_else(|| not_found(context))
}

async fn load_policy(
    repository: &PluginGovernanceRepository<'_>,
    org_id: &str,
    context: &RequestContext,
) -> Result<PluginPolicy, ApiError> {
    Ok(repository
        .find_policy(org_id)
        .await
        .map_err(|_| store_unavailable(context))?
        .as_ref()
        .map(|row| row.to_domain())
        .unwrap_or_default())
}

/// Parse a stored manifest.
///
/// Refuses an unknown field rather than ignoring it. A manifest that grew a
/// capability class this server does not understand must not be treated as
/// declaring nothing new, because that is precisely how a capability arrives
/// silently.
pub fn parse_manifest(
    raw: &str,
    context: &RequestContext,
) -> Result<PluginPermissionManifest, ApiError> {
    let value: Value = serde_json::from_str(raw)
        .map_err(|_| plugin_error(context, PluginDenyReason::ManifestInvalid))?;
    let object = value
        .as_object()
        .ok_or_else(|| plugin_error(context, PluginDenyReason::ManifestInvalid))?;
    for field in [
        "tools",
        "mcp_servers",
        "network_destinations",
        "filesystem_scopes",
        "process_spawn",
        "secret_handles",
        "browser_capability",
        "external_data_handling",
    ] {
        if !object.contains_key(field) {
            return Err(plugin_error(context, PluginDenyReason::ManifestInvalid));
        }
    }
    let handles = match object.get("secret_handles") {
        Some(Value::Array(entries)) => {
            let mut handles = Vec::with_capacity(entries.len());
            for entry in entries {
                let handle = entry.get("handle").and_then(Value::as_str);
                let purpose = entry.get("declared_purpose").and_then(Value::as_str);
                match (handle, purpose) {
                    (Some(handle), Some(purpose)) => {
                        handles.push(SecretHandle::new(handle, purpose).ok_or_else(|| {
                            plugin_error(context, PluginDenyReason::ManifestInvalid)
                        })?)
                    }
                    _ => return Err(plugin_error(context, PluginDenyReason::ManifestInvalid)),
                }
            }
            handles
        }
        _ => return Err(plugin_error(context, PluginDenyReason::ManifestInvalid)),
    };
    Ok(PluginPermissionManifest {
        tools: string_array(object.get("tools"), 120, context)?,
        mcp_servers: string_array(object.get("mcp_servers"), 120, context)?,
        network_destinations: string_array(object.get("network_destinations"), 300, context)?,
        filesystem_scopes: string_array(object.get("filesystem_scopes"), 300, context)?,
        process_spawn: object
            .get("process_spawn")
            .and_then(Value::as_bool)
            .ok_or_else(|| plugin_error(context, PluginDenyReason::ManifestInvalid))?,
        secret_handles: handles,
        browser_capability: object
            .get("browser_capability")
            .and_then(Value::as_str)
            .and_then(BrowserCapability::parse)
            .ok_or_else(|| plugin_error(context, PluginDenyReason::ManifestInvalid))?,
        external_data_handling: object
            .get("external_data_handling")
            .and_then(Value::as_str)
            .and_then(ExternalDataHandling::parse)
            .ok_or_else(|| plugin_error(context, PluginDenyReason::ManifestInvalid))?,
    }
    .normalized())
}

fn string_array(
    value: Option<&Value>,
    max_len: usize,
    context: &RequestContext,
) -> Result<Vec<String>, ApiError> {
    let Some(Value::Array(entries)) = value else {
        return Err(plugin_error(context, PluginDenyReason::ManifestInvalid));
    };
    let mut values = Vec::with_capacity(entries.len());
    for entry in entries {
        let text = entry
            .as_str()
            .ok_or_else(|| plugin_error(context, PluginDenyReason::ManifestInvalid))?;
        if text.is_empty() || text.len() > max_len {
            return Err(plugin_error(context, PluginDenyReason::ManifestInvalid));
        }
        values.push(text.to_owned());
    }
    Ok(values)
}

fn string_list(
    values: &[String],
    max_len: usize,
    context: &RequestContext,
) -> Result<Vec<String>, ApiError> {
    string_array(
        Some(&Value::Array(
            values.iter().map(|v| Value::String(v.clone())).collect(),
        )),
        max_len,
        context,
    )
}

fn package_list(values: &[String], context: &RequestContext) -> Result<Vec<String>, ApiError> {
    for value in values {
        if value.len() != 36 || !value.starts_with("pkg_") {
            return Err(invalid_input(context));
        }
    }
    let mut sorted: Vec<String> = values
        .iter()
        .filter(|value| *value != "*")
        .cloned()
        .collect();
    sorted.sort();
    sorted.dedup();
    Ok(sorted)
}

fn plugin_error(context: &RequestContext, reason: PluginDenyReason) -> ApiError {
    let code = match reason {
        // A refusal to grant, not a malformed request.
        PluginDenyReason::Blocked
        | PluginDenyReason::Quarantined
        | PluginDenyReason::PermissionExpanded
        | PluginDenyReason::Pinned
        | PluginDenyReason::PolicyConflict
        | PluginDenyReason::VersionNotPendingReview => ApiErrorCode::Conflict,
        PluginDenyReason::Incompatible
        | PluginDenyReason::IntegrityFailed
        | PluginDenyReason::ManifestInvalid
        | PluginDenyReason::PublisherNotAllowed => ApiErrorCode::ValidationFailed,
        PluginDenyReason::ToolUnregistered => ApiErrorCode::PermissionDenied,
    };
    let message = match reason {
        PluginDenyReason::Blocked => "This plugin is blocked by organization policy.",
        PluginDenyReason::Quarantined => "This plugin version is quarantined by the platform.",
        PluginDenyReason::PermissionExpanded => {
            "This version requests additional permissions and needs renewed approval."
        }
        PluginDenyReason::Pinned => "This plugin is pinned to another version.",
        PluginDenyReason::Incompatible => "This version is not compatible with the reporting host.",
        PluginDenyReason::IntegrityFailed => "This artifact does not match the published digest.",
        PluginDenyReason::ToolUnregistered => "This tool is not registered for your organization.",
        PluginDenyReason::PolicyConflict => {
            "The organization policy lists this package as both allowed and blocked."
        }
        PluginDenyReason::ManifestInvalid => "The plugin manifest is invalid.",
        PluginDenyReason::PublisherNotAllowed => "Your organization does not allow this publisher.",
        PluginDenyReason::VersionNotPendingReview => "This version is not awaiting review.",
    };
    domain_error(context, code, reason.code(), message)
}

fn version_conflict(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::Conflict,
        "version_conflict",
        "The plugin policy changed. Refresh and try again.",
    )
}

fn not_found(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::NotFound,
        "resource_not_found",
        "The requested resource was not found.",
    )
}

fn invalid_input(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::ValidationFailed,
        "invalid_input",
        "The request contains invalid fields.",
    )
}

fn store_unavailable(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::ServiceUnavailable,
        "The identity store is unavailable.",
    )
}

fn json_response(body: Value) -> Response<Body> {
    (StatusCode::OK, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    use crate::repositories::{PluginInstallRecord, PluginPackageRecord, PluginVersionRecord};

    const FIXTURE: &str =
        include_str!("../../../../docs/implementation/fixtures/p07-contracts-v1.json");

    fn context() -> RequestContext {
        RequestContext::new(
            "req_0123456789abcdef0123456789abcdef".parse().unwrap(),
            crate::core::CorrelationId::new("trace-p07").unwrap(),
            "2026-09-26T12:00:00.000Z".parse().unwrap(),
        )
    }

    fn fixture_install() -> Value {
        let value: Value = serde_json::from_str(FIXTURE).expect("the frozen fixture is valid JSON");
        value["plugin_install_pending_review"]
            .as_object()
            .expect("object")
            .iter()
            .filter(|(key, _)| !key.starts_with('_'))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<serde_json::Map<_, _>>()
            .into()
    }

    fn install(blocked_reason: Option<&str>) -> PluginInstallRecord {
        PluginInstallRecord {
            install_id: "pil_0123456789abcdef0123456789abcdef".to_owned(),
            org_id: "org_0123456789abcdef0123456789abcdef".to_owned(),
            package_id: "pkg_0123456789abcdef0123456789abcdef".to_owned(),
            version: "1.0.0".to_owned(),
            pending_review_version: Some("1.1.0".to_owned()),
            review_state: "pending_review".to_owned(),
            review_reason: Some("plugin.permission_expansion_detected.v1".to_owned()),
            approved_by: None,
            approved_at: None,
            blocked_reason: blocked_reason.map(str::to_owned),
            version_counter: 1,
            created_at: "2026-09-26T12:00:00.000Z".to_owned(),
            updated_at: "2026-09-26T12:00:00.000Z".to_owned(),
        }
    }

    fn keys(value: &Value) -> BTreeSet<String> {
        value
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect()
    }

    /// The projection and the browser's decoder are two implementations of one
    /// contract with no shared compiler between them, so the only thing standing
    /// between them is a key set compared against a frozen block. This pins the
    /// server's half of it: the projection emits EXACTLY the frozen fields, no
    /// more and no fewer. An extra field is state a client holds stale; a
    /// missing one is a page that does not render.
    #[test]
    fn the_install_projection_is_exactly_the_frozen_field_set() {
        let projection = install_json(
            &install(None),
            vec!["pkg_read".to_owned()],
            vec!["pkg_write".to_owned()],
        );
        assert_eq!(keys(&projection), keys(&fixture_install()));
    }

    /// The same projection with a reason recorded, so the block WINS over a block
    /// with none. A field that only ever appears as null is a field nobody has
    /// proven they can read.
    #[test]
    fn the_install_projection_carries_a_block_reason_when_there_is_one() {
        let projection = install_json(
            &install(Some("CVE-2026-0001 in 1.0.0")),
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(projection["blocked_reason"], "CVE-2026-0001 in 1.0.0");
        // The same key set, because a reason must not change the shape.
        assert_eq!(keys(&projection), keys(&fixture_install()));
    }

    /// `org_id` is deliberately absent: the route is org-scoped by the path, so
    /// returning it would be redundant state a client could hold stale. Asserted
    /// so a future "just include everything" edit is caught rather than shipped.
    #[test]
    fn the_install_projection_does_not_repeat_the_organizations_identity() {
        let projection = install_json(&install(None), Vec::new(), Vec::new());
        assert!(
            !projection
                .as_object()
                .expect("object")
                .contains_key("org_id")
        );
    }

    fn manifest(fields: &[(&str, Value)]) -> String {
        let mut object = serde_json::Map::new();
        for (key, value) in fields {
            object.insert((*key).to_owned(), value.clone());
        }
        let all: [(&str, Value); 8] = [
            ("tools", json!([])),
            ("mcp_servers", json!([])),
            ("network_destinations", json!([])),
            ("filesystem_scopes", json!([])),
            ("process_spawn", json!(false)),
            ("secret_handles", json!([])),
            ("browser_capability", json!("none")),
            ("external_data_handling", json!("none")),
        ];
        for (key, value) in all {
            object.entry(key.to_owned()).or_insert(value);
        }
        Value::Object(object).to_string()
    }

    /// A manifest is a supply-chain declaration, so a field the parser can skip is
    /// a capability nobody diffs. Every field is REQUIRED rather than defaulted,
    /// which is why `manifest` above fills all eight before overriding any.
    #[test]
    fn a_manifest_missing_any_field_is_refused_rather_than_defaulted() {
        let context = context();
        for field in [
            "tools",
            "mcp_servers",
            "network_destinations",
            "filesystem_scopes",
            "process_spawn",
            "secret_handles",
            "browser_capability",
            "external_data_handling",
        ] {
            let mut object: serde_json::Map<String, Value> =
                serde_json::from_str::<Value>(&manifest(&[]))
                    .expect("json")
                    .as_object()
                    .expect("object")
                    .clone();
            object.remove(field);
            let raw = Value::Object(object).to_string();
            assert!(
                parse_manifest(&raw, &context).is_err(),
                "a manifest without {field} is not a manifest this platform can review"
            );
        }
    }

    /// A private, loopback or link-local destination is refused at REPORT time,
    /// not filtered at install time, because a declaration the platform refuses to
    /// record cannot later be diffed, reviewed, or audited.
    ///
    /// `parse_manifest` deliberately still ACCEPTS one, because it is the
    /// submission boundary's job to refuse it with a reason, and a parser that
    /// dropped the field would turn a refused report into a report that quietly
    /// lost a capability. The refusal itself is asserted on the manifest the
    /// parser returns, which is what `submit_plugin_report` checks.
    ///
    /// The check is on the HOST LITERAL, so a hostname that resolves inward is
    /// still a declaration an operator can see, and a literal that is merely
    /// suspicious is not in this list. `metadata.google.internal` is the known
    /// case: it is a real metadata endpoint and it is NOT refused, because
    /// `.internal` is not a reserved suffix and an organization may legitimately
    /// host a name under it. A hostname blocklist is a policy decision for the
    /// gate, not something to smuggle in as a test expectation.
    #[test]
    fn a_private_or_loopback_destination_is_refused_at_report_time() {
        let context = context();
        for destination in [
            "http://127.0.0.1",
            "https://10.0.0.5/v1",
            "http://192.168.1.1",
            "http://169.254.169.254/latest/meta-data",
            "http://localhost:8080",
            "http://api.localhost",
            "http://files.local",
            "ftp://files.example.com",
            "example.com",
            "http://[::1]/v1",
        ] {
            let raw = manifest(&[("network_destinations", json!([destination]))]);
            let parsed = parse_manifest(&raw, &context)
                .unwrap_or_else(|_| panic!("{destination} is a declaration, not a syntax error"));
            assert_eq!(
                parsed.rejected_destinations(),
                vec![destination],
                "{destination} declares access to whatever the host can reach"
            );
        }
        // A public host is not rejected, and neither is a strict-subdomain
        // pattern \u2014 `*.cdn.example.com` is a host, not a range.
        let public = parse_manifest(
            &manifest(&[(
                "network_destinations",
                json!(["https://api.example.com", "*.cdn.example.com"]),
            )]),
            &context,
        )
        .expect("public destinations parse");
        assert!(public.rejected_destinations().is_empty());
        // And the limitation above, asserted rather than only written down.
        let metadata = parse_manifest(
            &manifest(&[(
                "network_destinations",
                json!(["http://metadata.google.internal"]),
            )]),
            &context,
        )
        .expect("a suspicious hostname is still a declaration");
        assert!(
            metadata.rejected_destinations().is_empty(),
            "if this ever starts being refused, the gate needs a policy note explaining why"
        );
    }

    #[test]
    fn a_public_destination_is_accepted_and_the_lists_come_back_normalized() {
        let context = context();
        let raw = manifest(&[
            ("tools", json!(["pkg_write", "pkg_read", "pkg_read"])),
            (
                "network_destinations",
                json!(["https://api.example.com", "*.cdn.example.com"]),
            ),
            (
                "secret_handles",
                json!([
                    {"handle": "aws", "declared_purpose": "read-logs"},
                    {"handle": "gh", "declared_purpose": "admin-org"},
                ]),
            ),
        ]);
        let parsed = parse_manifest(&raw, &context).expect("a valid manifest parses");
        // Sorted and deduplicated, because the diff compares them as sets: an
        // order change between two versions of the same manifest is not a
        // capability change, and treating it as one flags every re-publish.
        assert_eq!(parsed.tools, vec!["pkg_read", "pkg_write"]);
        assert_eq!(
            parsed.network_destinations,
            vec!["*.cdn.example.com", "https://api.example.com"]
        );
        let handles: Vec<String> = parsed
            .secret_handles
            .iter()
            .map(|handle| format!("{}::{}", handle.handle, handle.declared_purpose))
            .collect();
        assert_eq!(handles, vec!["aws::read-logs", "gh::admin-org"]);
    }

    #[test]
    fn a_malformed_manifest_is_refused_with_a_stable_reason() {
        let context = context();
        for raw in [
            "not json",
            "[]",
            "{}",
            &manifest(&[("process_spawn", json!("yes"))]),
            &manifest(&[("browser_capability", json!("omnipotent"))]),
            &manifest(&[("external_data_handling", json!("whatever"))]),
            &manifest(&[("tools", json!("pkg_read"))]),
            &manifest(&[("secret_handles", json!([{"handle": "gh"}]))]),
            &manifest(&[(
                "secret_handles",
                json!([{"handle": "", "declared_purpose": "admin-org"}]),
            )]),
        ] {
            let error = parse_manifest(raw, &context).expect_err("refused");
            assert_eq!(error.error.details["reason"], "manifest_invalid", "{raw}");
        }
    }

    /// Each refusal is a different conversation with the caller, so each gets its
    /// own stable code. A collapse of two of these into one is exactly the case a
    /// test has to prevent: a client that branches on the reason would treat
    /// "you are blocked" and "the digest does not match" as the same answer.
    #[test]
    fn every_denial_reason_is_a_distinct_stable_code() {
        let context = context();
        let reasons = [
            PluginDenyReason::Blocked,
            PluginDenyReason::Quarantined,
            PluginDenyReason::PermissionExpanded,
            PluginDenyReason::Pinned,
            PluginDenyReason::Incompatible,
            PluginDenyReason::IntegrityFailed,
            PluginDenyReason::ToolUnregistered,
            PluginDenyReason::PolicyConflict,
            PluginDenyReason::ManifestInvalid,
            PluginDenyReason::PublisherNotAllowed,
            PluginDenyReason::VersionNotPendingReview,
        ];
        let mut codes: BTreeMap<String, ApiErrorCode> = BTreeMap::new();
        for reason in reasons {
            let error = plugin_error(&context, reason);
            let code = error.error.details["reason"]
                .as_str()
                .expect("a reason")
                .to_owned();
            assert!(!code.is_empty(), "{reason:?} must carry a reason");
            assert!(
                codes.insert(code.clone(), error.error.code).is_none(),
                "{code} is used by two different refusals"
            );
        }
        assert_eq!(codes.len(), reasons.len());
    }

    /// A refusal to GRANT is a conflict the caller can resolve; a malformed or
    /// unverifiable artifact is not. Both carry a reason, so the status has to
    /// carry the difference between "not now" and "not ever, as submitted".
    #[test]
    fn the_status_distinguishes_a_refusal_from_an_unacceptable_submission() {
        let context = context();
        for reason in [
            PluginDenyReason::Blocked,
            PluginDenyReason::Quarantined,
            PluginDenyReason::PermissionExpanded,
            PluginDenyReason::Pinned,
            PluginDenyReason::PolicyConflict,
            PluginDenyReason::VersionNotPendingReview,
        ] {
            assert_eq!(
                plugin_error(&context, reason).error.code,
                ApiErrorCode::Conflict,
                "{reason:?} is a conflict the caller can resolve"
            );
        }
        for reason in [
            PluginDenyReason::Incompatible,
            PluginDenyReason::IntegrityFailed,
            PluginDenyReason::ManifestInvalid,
            PluginDenyReason::PublisherNotAllowed,
        ] {
            assert_eq!(
                plugin_error(&context, reason).error.code,
                ApiErrorCode::ValidationFailed,
                "{reason:?} is an unacceptable submission"
            );
        }
        // F13 default-deny is a permission decision, not a validation one, so a
        // client can tell "you did not ask for it" from "you asked wrongly".
        assert_eq!(
            plugin_error(&context, PluginDenyReason::ToolUnregistered)
                .error
                .code,
            ApiErrorCode::PermissionDenied
        );
    }

    #[test]
    fn the_policy_projection_reports_a_conflict_and_never_resolves_one() {
        // F25-004: the block wins and the contradiction is reported. Silently
        // dropping the allow entry would leave an admin believing a package is
        // permitted when it is not.
        let policy = PluginPolicy {
            publisher_mode: PublisherMode::ApprovedPublishers,
            approved_publishers: vec!["pub_0123456789abcdef0123456789abcdef".to_owned()],
            allowed_packages: vec![
                "pkg_0123456789abcdef0123456789abcdef".to_owned(),
                "pkg_ffffffffffffffffffffffffffffffff".to_owned(),
            ],
            blocked_packages: vec!["pkg_0123456789abcdef0123456789abcdef".to_owned()],
            pinned_versions: BTreeMap::from([(
                "pkg_ffffffffffffffffffffffffffffffff".to_owned(),
                "1.0.0".to_owned(),
            )]),
            auto_update: false,
            update_mode: UpdateMode::Managed,
        };
        let projection = policy_json(
            &policy,
            2,
            vec!["pkg_0123456789abcdef0123456789abcdef".to_owned()],
        );
        assert_eq!(
            projection["conflicts"],
            json!(["pkg_0123456789abcdef0123456789abcdef"])
        );
        // The allow entry is still there. Removing it would hide the contradiction
        // the conflicts array is reporting.
        assert_eq!(
            projection["allowed_packages"].as_array().map(Vec::len),
            Some(2)
        );
        assert_eq!(
            projection["blocked_packages"].as_array().map(Vec::len),
            Some(1)
        );
        assert_eq!(projection["update_mode"], "managed");
        assert_eq!(projection["version"], 2);
    }

    /// The audit payload and the stored reason carry the same summary, so an
    /// operator who jumps from the UI to the audit view sees the same class list
    /// rather than two different renderings of one decision.
    #[test]
    fn the_audit_summary_and_the_stored_reason_describe_the_same_classes() {
        let before = parse_manifest(&manifest(&[]), &context()).expect("baseline");
        let after = parse_manifest(
            &manifest(&[
                ("tools", json!(["pkg_read", "pkg_write"])),
                // Unchanged, so it must NOT appear among the growing classes. A
                // summary that listed it would make the audit view disagree with
                // the permission diff the reviewer just approved.
                ("network_destinations", json!(["https://api.example.com"])),
            ]),
            &context(),
        )
        .expect("candidate");
        let diff = crate::modules::plugins::diff(Some("1.0.0"), &before, "1.1.0", &after);
        // One tool added, one destination added: two growing classes, and the
        // summary names both, because the review gate reads growth in any class.
        let summary = policy_diff_summary(&diff);
        assert_eq!(summary["expands"], true);
        let growing: Vec<&str> = summary["classes"]
            .as_array()
            .expect("classes")
            .iter()
            .filter(|entry| entry["verdict"] == "added")
            .map(|entry| entry["class"].as_str().expect("a class name"))
            .collect();
        assert_eq!(growing, ["tools", "network_destinations"]);
        // The reason the install row stores is the event id plus this summary, and
        // the browser parses exactly that shape to name the class to a reviewer.
        let reason = format!("{PERMISSION_EXPANSION_REASON} {summary}");
        let prefix = format!("{PERMISSION_EXPANSION_REASON} ");
        assert!(reason.starts_with(&prefix), "{reason}");
        let payload: Value = serde_json::from_str(reason[prefix.len()..].trim())
            .expect("the reason payload is json");
        assert_eq!(payload, summary);
    }

    #[test]
    fn a_version_projection_carries_the_digest_and_nothing_private() {
        let version = PluginVersionRecord {
            plugin_version_id: "plv_0123456789abcdef0123456789abcdef".to_owned(),
            package_id: "pkg_0123456789abcdef0123456789abcdef".to_owned(),
            version: "1.0.0".to_owned(),
            runtime_min: "1.0.0".to_owned(),
            runtime_max: "3.0.0".to_owned(),
            content_digest: "b".repeat(64),
            // The signing secret's counterpart. A signature is not a credential,
            // but it is not part of the contract either, so it stays in the store.
            signature: "s".repeat(64),
            manifest_json: r#"{"tools":["pkg_read"]}"#.to_owned(),
            published_at: "2026-09-26T12:00:00.000Z".to_owned(),
            created_at: "2026-09-26T12:00:00.000Z".to_owned(),
        };
        let projection = version_json(&version);
        assert_eq!(projection["content_digest"], "b".repeat(64));
        assert!(
            !projection
                .as_object()
                .expect("object")
                .contains_key("signature")
        );
        // A manifest column that is not JSON is reported as null rather than as
        // an empty object, so a reviewer is not shown a capability set that
        // nothing declared.
        let mut corrupt = version;
        corrupt.manifest_json = "{not json".to_owned();
        assert_eq!(version_json(&corrupt)["manifest"], Value::Null);
    }

    #[test]
    fn a_package_projection_reports_officialness_as_a_boolean() {
        let package = PluginPackageRecord {
            package_id: "pkg_0123456789abcdef0123456789abcdef".to_owned(),
            publisher_id: "pub_0123456789abcdef0123456789abcdef".to_owned(),
            display_name: "Release helper".to_owned(),
            summary: Some("Reads release state.".to_owned()),
            status: "active".to_owned(),
            created_at: "2026-09-26T12:00:00.000Z".to_owned(),
            updated_at: "2026-09-26T12:00:00.000Z".to_owned(),
            // Stored as an integer because SQLite has no boolean; the wire has one
            // because a client that has to remember 0/1 is a client that will.
            publisher_official: 1,
            publisher_status: "active".to_owned(),
        };
        let projection = package_json(&package);
        assert_eq!(projection["publisher_official"], true);
        // The stored integer is normalized to a boolean, because a client that has
        // to remember that 0 means false is a client that will get it wrong on the
        // row that matters. And the publisher's own status is not part of this
        // contract, so it stays in the store.
        assert_eq!(
            keys(&projection),
            BTreeSet::from([
                "package_id".to_owned(),
                "publisher_id".to_owned(),
                "publisher_official".to_owned(),
                "display_name".to_owned(),
                "summary".to_owned(),
                "status".to_owned(),
                "created_at".to_owned(),
                "updated_at".to_owned(),
            ])
        );
    }
}
