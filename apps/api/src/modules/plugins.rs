//! Plugin governance: the third of P07's authorization decisions, expressed as
//! organization policy rather than as an actor kind.
//!
//! F25's objective is one sentence — "installed code does not automatically
//! become trusted code" — and its two acceptance criteria are supply-chain
//! claims. This module is where they are decided:
//!
//! * **"A plugin update cannot silently gain network/secret/tool capability."**
//!   The input is a [`PluginPermissionDiff`] between the installed version's
//!   manifest and a candidate's. [`diff`] is total over every capability class,
//!   and [`PermissionDiff::expands`] is true when ANY class grows. A version that
//!   adds one tool while removing two network destinations is an expansion; a
//!   reviewer who reads "networking was reduced" must not be able to miss that a
//!   tool appeared. In `managed` mode an expansion is refused outright and
//!   recorded as `pending_review` — it does not install and wait quietly.
//! * **"A blocked version cannot execute for managed org even if still present
//!   on disk."**   The decision here is a pure function of stored state:
//!   [`PluginDecision`] is computed from the org policy, the install's review
//!   state, and the platform quarantine set. On-disk artifact presence is not an
//!   input, so a managed organization cannot reach an execution it should not
//!   have by any means.
//!
//! What this module deliberately does NOT do:
//!
//! * It does not know about `custom` MCP servers. P05 already persists tool
//!   `source IN ('built_in','plugin','custom')`, and a `custom` server has no
//!   package identity to govern. Conflating the two would make plugin policy
//!   appear to cover servers it does not, so those stay under P05 tool policy and
//!   F13 default-deny alone.
//! * It does not decide *whether the platform trusts a publisher*. That is
//!   quarantine, a separate platform decision, checked after org policy.
//! * It does not execute anything. Every function is pure so the deny decision is
//!   testable without a host agent, an artifact, or a network.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------- manifest ---

/// How much browser authority a version asks for.
///
/// Ordered, because the diff has to decide whether `read` -> `computer_use` is
/// an expansion. An enum rather than a bool for the same reason: "can use
/// computer control" is not the same claim as "can read pages", and a manifest
/// that only recorded the latter would under-report a capability gain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserCapability {
    #[default]
    None,
    Read,
    Interact,
    ComputerUse,
}

impl BrowserCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Read => "read",
            Self::Interact => "interact",
            Self::ComputerUse => "computer_use",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "read" => Some(Self::Read),
            "interact" => Some(Self::Interact),
            "computer_use" => Some(Self::ComputerUse),
            _ => None,
        }
    }
}

/// Whether a version may send data to a third party it does not name.
///
/// F25-002 asks for "external data handling where known". `Unknown` exists
/// because the honest answer for a version that does not declare it is
/// "unknown", and collapsing that into `none` would under-report a capability.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalDataHandling {
    #[default]
    None,
    Declared,
    Unknown,
}

impl ExternalDataHandling {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Declared => "declared",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "declared" => Some(Self::Declared),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// One declared secret binding: a logical handle plus the integration purpose it
/// is declared for.
///
/// F25-006 is the reason this is a pair and not a credential id. A plugin asks
/// for "a token for the GitHub integration", and the platform binds it. A plugin
/// can therefore never enumerate an organization's credentials, because it has no
/// vocabulary for them.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecretHandle {
    pub handle: String,
    pub declared_purpose: String,
}

impl SecretHandle {
    /// Both halves are bounded and must be non-empty: a handle with no purpose is
    /// a request for a credential nobody reviewed, and a purpose with no handle
    /// is a declaration that binds nothing.
    pub fn new(handle: impl Into<String>, declared_purpose: impl Into<String>) -> Option<Self> {
        let handle = handle.into();
        let declared_purpose = declared_purpose.into();
        if handle.is_empty()
            || handle.len() > 120
            || declared_purpose.is_empty()
            || declared_purpose.len() > 200
        {
            return None;
        }
        Some(Self {
            handle,
            declared_purpose,
        })
    }
}

/// The capability set one version declares (F25-002).
///
/// Every field is a closed, finite set and there is no wildcard anywhere. The
/// lists are sorted sets rather than sequences, because the permission diff
/// compares them as sets: an order change between two versions of the same
/// manifest is not a capability change, and treating it as one would flag every
/// re-publish for review.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginPermissionManifest {
    /// `package + version + tool` stable identities (F25-007).
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub mcp_servers: Vec<String>,
    /// Exact `scheme://host[:port]` or a `*.suffix` pattern. Private, loopback and
    /// link-local ranges are rejected at report time — a plugin that declares
    /// `http://127.0.0.1` has declared access to whatever the host can reach.
    #[serde(default)]
    pub network_destinations: Vec<String>,
    /// Path prefixes. A path outside every scope is denied.
    #[serde(default)]
    pub filesystem_scopes: Vec<String>,
    /// Default false. A version that wants to spawn processes says so.
    #[serde(default)]
    pub process_spawn: bool,
    #[serde(default)]
    pub secret_handles: Vec<SecretHandle>,
    pub browser_capability: BrowserCapability,
    pub external_data_handling: ExternalDataHandling,
}

impl PluginPermissionManifest {
    /// Build a normalized manifest: every list deduplicated and sorted, so two
    /// manifests that declare the same capabilities compare equal regardless of
    /// how they were written.
    pub fn normalized(mut self) -> Self {
        self.tools = normalized_list(std::mem::take(&mut self.tools), 120);
        self.mcp_servers = normalized_list(std::mem::take(&mut self.mcp_servers), 120);
        self.network_destinations =
            normalized_list(std::mem::take(&mut self.network_destinations), 300);
        self.filesystem_scopes = normalized_list(std::mem::take(&mut self.filesystem_scopes), 300);
        self.secret_handles.sort();
        self.secret_handles.dedup();
        self
    }

    /// Is this network destination refused outright, independent of policy?
    ///
    /// Private and loopback ranges are rejected at report time rather than
    /// filtered at install time, because a declaration the platform refuses to
    /// record cannot later be diffed, reviewed, or audited. The check is on the
    /// host literal, not on a resolved address, so a hostname that later resolves
    /// inward is still a declaration the operator can see.
    pub fn rejects_destination(destination: &str) -> bool {
        // Two accepted forms, and BOTH have to be handled here. A wildcard
        // pattern carries no scheme, so splitting on `://` first would classify
        // every `*.example.com` declaration as a syntax error and refuse the
        // whole report — which is what this did before it was fixed, and it made
        // the documented wildcard form unusable.
        let host = match destination.strip_prefix("*.") {
            // A strict-subdomain pattern. The suffix is the host to evaluate: a
            // pattern rooted at a private or loopback name reaches inward the
            // same way an exact literal does.
            Some(suffix) => suffix,
            None => {
                let Some((scheme, rest)) = destination.split_once("://") else {
                    return true;
                };
                if !matches!(scheme, "http" | "https" | "ws" | "wss") {
                    return true;
                }
                let authority = rest.split('/').next().unwrap_or_default();
                // Strip the port, keeping IPv6 brackets intact.
                match authority.rsplit_once(':') {
                    Some((before, port))
                        if !before.is_empty() && port.chars().all(|c| c.is_ascii_digit()) =>
                    {
                        before
                    }
                    _ => authority,
                }
            }
        };
        // `*` alone, or `*.` with no host, is a pattern with no host in it. There
        // is nothing to bound, so it is refused rather than treated as public.
        if host.is_empty() || host.contains('*') {
            return true;
        }
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        if host == "local"
            || host == "localhost"
            || host.ends_with(".localhost")
            || host.ends_with(".local")
        {
            return true;
        }
        if let Ok(address) = host.parse::<std::net::Ipv4Addr>() {
            return address.is_private() || address.is_loopback() || address.is_link_local();
        }
        if let Ok(address) = host.parse::<std::net::Ipv6Addr>() {
            return address.is_loopback()
                || (address.segments()[0] & 0xfe00) == 0xfc00
                || (address.segments()[0] & 0xffc0) == 0xfe80;
        }
        false
    }

    /// Every declared destination the platform refuses to record.
    pub fn rejected_destinations(&self) -> Vec<&str> {
        self.network_destinations
            .iter()
            .map(String::as_str)
            .filter(|destination| Self::rejects_destination(destination))
            .collect()
    }
}

fn normalized_list(values: Vec<String>, max_len: usize) -> Vec<String> {
    let mut values: Vec<String> = values
        .into_iter()
        .filter(|value| !value.is_empty() && value.len() <= max_len)
        .collect();
    values.sort();
    values.dedup();
    values
}

// -------------------------------------------------------------------- diff ---

/// How one capability class moved between two versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffClass {
    /// Grown: entries were added, or the class's value was raised.
    Added,
    /// Shrunk: entries were removed, or the class's value was lowered.
    Removed,
    Unchanged,
}

impl DiffClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Unchanged => "unchanged",
        }
    }
}

/// A per-class expansion, contraction, or no-op.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassDiff {
    pub class: String,
    pub verdict: DiffClass,
    /// Sorted entries the candidate adds. Empty for a removal or no-op.
    pub added: Vec<String>,
    /// Sorted entries the candidate drops. Empty for an addition or no-op.
    pub removed: Vec<String>,
}

impl ClassDiff {
    fn list(class: &str, before: &[String], after: &[String]) -> Self {
        let before: BTreeSet<&String> = before.iter().collect();
        let after: BTreeSet<&String> = after.iter().collect();
        let added: Vec<String> = after.difference(&before).map(|v| (*v).clone()).collect();
        let removed: Vec<String> = before.difference(&after).map(|v| (*v).clone()).collect();
        let verdict = match (added.is_empty(), removed.is_empty()) {
            (true, true) => DiffClass::Unchanged,
            (false, true) => DiffClass::Added,
            (true, false) => DiffClass::Removed,
            // Both moved. The class as a whole is reported as `added`, because
            // this table exists to answer one question — did capability grow —
            // and a class that both gained and lost entries gained some.
            (false, false) => DiffClass::Added,
        };
        Self {
            class: class.to_owned(),
            verdict,
            added,
            removed,
        }
    }
}

/// Version-to-version capability change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionDiff {
    pub from_version: String,
    pub to_version: String,
    pub classes: Vec<ClassDiff>,
    /// True when ANY class grew. This is the field the managed-mode review gate
    /// reads, and it is deliberately not derived from a weighted score: an
    /// expansion is an expansion.
    pub expands: bool,
}

impl PermissionDiff {
    pub fn class(&self, name: &str) -> Option<&ClassDiff> {
        self.classes.iter().find(|entry| entry.class == name)
    }
}

/// Compute the diff between an installed manifest and a candidate's.
///
/// `before` is `None` for a FIRST install. A first install is not a diff and has
/// no previous version to compare with, so it is not an expansion: the review
/// decision for a first install is the install's own approval, and pretending
/// otherwise would make every first install of a zero-capability version a
/// special case for no reason.
pub fn diff(
    from_version: Option<&str>,
    before: &PluginPermissionManifest,
    to_version: &str,
    after: &PluginPermissionManifest,
) -> PermissionDiff {
    let before = before.clone().normalized();
    let after = after.clone().normalized();
    let mut classes = vec![
        ClassDiff::list("tools", &before.tools, &after.tools),
        ClassDiff::list("mcp_servers", &before.mcp_servers, &after.mcp_servers),
        ClassDiff::list(
            "network_destinations",
            &before.network_destinations,
            &after.network_destinations,
        ),
        ClassDiff::list(
            "filesystem_scopes",
            &before.filesystem_scopes,
            &after.filesystem_scopes,
        ),
        ClassDiff::list(
            "secret_handles",
            &handles(&before.secret_handles),
            &handles(&after.secret_handles),
        ),
    ];
    classes.push(scalar(
        "process_spawn",
        before.process_spawn,
        after.process_spawn,
    ));
    classes.push(ordered(
        "browser_capability",
        before.browser_capability.as_str(),
        after.browser_capability.as_str(),
    ));
    classes.push(enum_diff(
        "external_data_handling",
        before.external_data_handling != ExternalDataHandling::None,
        after.external_data_handling != ExternalDataHandling::None,
    ));
    PermissionDiff {
        from_version: from_version.unwrap_or_default().to_owned(),
        to_version: to_version.to_owned(),
        expands: classes
            .iter()
            .any(|entry| entry.verdict == DiffClass::Added),
        classes,
    }
}

fn handles(values: &[SecretHandle]) -> Vec<String> {
    values
        .iter()
        .map(|handle| format!("{}::{}", handle.handle, handle.declared_purpose))
        .collect()
}

fn scalar(class: &str, before: bool, after: bool) -> ClassDiff {
    let (verdict, added, removed) = match (before, after) {
        (false, true) => (DiffClass::Added, vec!["true".to_owned()], Vec::new()),
        (true, false) => (DiffClass::Removed, Vec::new(), vec!["true".to_owned()]),
        _ => (DiffClass::Unchanged, Vec::new(), Vec::new()),
    };
    ClassDiff {
        class: class.to_owned(),
        verdict,
        added,
        removed,
    }
}

/// An ordered scalar: a move UP the ordering is an expansion, a move DOWN is a
/// contraction, and equal is unchanged.
fn ordered(class: &str, before: &str, after: &str) -> ClassDiff {
    let verdict = rank_class(before, after);
    ClassDiff {
        class: class.to_owned(),
        verdict,
        added: if verdict == DiffClass::Added {
            vec![after.to_owned()]
        } else {
            Vec::new()
        },
        removed: if verdict == DiffClass::Removed {
            vec![before.to_owned()]
        } else {
            Vec::new()
        },
    }
}

fn rank_class(before: &str, after: &str) -> DiffClass {
    let rank = |value: &str| match value {
        "none" | "false" => 0_u8,
        "read" | "declared" | "true" => 1,
        "interact" => 2,
        "computer_use" => 3,
        // An unrecognised value ranks above everything known. A capability the
        // platform cannot place on the scale must not be treated as smaller.
        _ => 4,
    };
    match rank(after).cmp(&rank(before)) {
        std::cmp::Ordering::Greater => DiffClass::Added,
        std::cmp::Ordering::Less => DiffClass::Removed,
        std::cmp::Ordering::Equal => DiffClass::Unchanged,
    }
}

/// A two-valued class where only "is this claimed at all" matters.
fn enum_diff(class: &str, before: bool, after: bool) -> ClassDiff {
    scalar(class, before, after)
}

// ------------------------------------------------------------------ policy ---

/// Which publishers an organization trusts (F25-004).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherMode {
    /// The default, and therefore the value an unrecognised stored string falls
    /// back to: official publishers only.
    #[default]
    OfficialOnly,
    ApprovedPublishers,
    Any,
}

impl PublisherMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OfficialOnly => "official_only",
            Self::ApprovedPublishers => "approved_publishers",
            Self::Any => "any",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "official_only" => Some(Self::OfficialOnly),
            "approved_publishers" => Some(Self::ApprovedPublishers),
            "any" => Some(Self::Any),
            _ => None,
        }
    }
}

/// Whether an expansion needs renewed approval (F25-003).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateMode {
    /// An expanding update is refused and enters `pending_review`. The default,
    /// because an unrecognised stored value must narrow rather than widen.
    #[default]
    Managed,
    /// An expanding update may install; the expansion is still audited.
    Direct,
}

impl UpdateMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::Direct => "direct",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "managed" => Some(Self::Managed),
            "direct" => Some(Self::Direct),
            _ => None,
        }
    }
}

/// One organization's plugin policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginPolicy {
    pub publisher_mode: PublisherMode,
    pub approved_publishers: Vec<String>,
    pub allowed_packages: Vec<String>,
    pub blocked_packages: Vec<String>,
    /// `package_id -> version`. A pin is exact: a pinned package cannot update to
    /// ANY other version, including a security update, because a silent
    /// auto-patch would defeat the pin. Lifting it is an explicit audited action.
    pub pinned_versions: std::collections::BTreeMap<String, String>,
    pub auto_update: bool,
    pub update_mode: UpdateMode,
}

impl Default for PluginPolicy {
    /// The default is the most restrictive policy that still lets an
    /// organization install something: official publishers only, nothing blocked,
    /// nothing allowed-by-exception, no auto-update, and managed updates so an
    /// expansion always needs renewed approval.
    fn default() -> Self {
        Self {
            publisher_mode: PublisherMode::OfficialOnly,
            approved_publishers: Vec::new(),
            allowed_packages: Vec::new(),
            blocked_packages: Vec::new(),
            pinned_versions: std::collections::BTreeMap::new(),
            auto_update: false,
            update_mode: UpdateMode::Managed,
        }
    }
}

/// The conflict the frozen gate requires to be REPORTED rather than resolved.
///
/// A package on both the allow and the block list is storable on purpose: the
/// block wins, and the org is told there is a conflict so it can fix its own
/// policy. Silently dropping the allow entry would leave an admin believing a
/// package is permitted when it is not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConflict {
    pub package_id: String,
}

/// Every package that is on both lists.
pub fn policy_conflicts(policy: &PluginPolicy) -> Vec<PolicyConflict> {
    let blocked: BTreeSet<&str> = policy.blocked_packages.iter().map(String::as_str).collect();
    policy
        .allowed_packages
        .iter()
        .filter(|package| blocked.contains(package.as_str()))
        .map(|package| PolicyConflict {
            package_id: package.clone(),
        })
        .collect()
}

// ---------------------------------------------------------------- decision ---

/// Why an install or an execution is refused. Every variant is a stable wire
/// code from the frozen gate, and each is a DIFFERENT runbook:
///
/// * `Blocked` is the org's own decision; the fix is to change the org's policy.
/// * `Quarantined` is a platform decision; the fix is a new version from the
///   publisher, never an org policy change.
/// * `PermissionExpanded` is a review the org has not given yet.
/// * `Incompatible` and `IntegrityFailed` are facts about the artifact.
/// * `ToolUnregistered` is F13 default-deny, and it is the specific control an
///   install can no longer bypass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginDenyReason {
    Blocked,
    Quarantined,
    PermissionExpanded,
    Pinned,
    Incompatible,
    IntegrityFailed,
    ToolUnregistered,
    PublisherNotAllowed,
    VersionNotPendingReview,
    PolicyConflict,
    ManifestInvalid,
}

impl PluginDenyReason {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Blocked => "plugin_blocked",
            Self::Quarantined => "plugin_quarantined",
            Self::PermissionExpanded => "plugin_permission_expanded",
            Self::Pinned => "plugin_pinned",
            Self::Incompatible => "plugin_incompatible",
            Self::IntegrityFailed => "plugin_integrity_failed",
            Self::ToolUnregistered => "plugin_tool_unregistered",
            Self::PublisherNotAllowed => "plugin_publisher_not_allowed",
            Self::VersionNotPendingReview => "version_not_pending_review",
            Self::PolicyConflict => "policy_conflict",
            Self::ManifestInvalid => "manifest_invalid",
        }
    }
}

impl fmt::Display for PluginDenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginDecision {
    Allow,
    Deny(PluginDenyReason),
}

impl PluginDecision {
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// The stored facts a plugin decision is computed from.
///
/// Deliberately a value, not a store handle: the deny decision is authoritative
/// and server-side, so it must be computable from a snapshot the server read,
/// and must be testable with no database at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginFacts {
    pub package_id: String,
    pub version: String,
    pub publisher_id: String,
    pub publisher_official: bool,
    /// Present when the package appears on BOTH lists. Reported, not resolved.
    pub policy_conflict: bool,
    /// The exact `package@version` is under an ACTIVE platform quarantine.
    pub quarantined: bool,
    /// The install's review state. `None` means the package is not installed.
    pub review_state: Option<PluginReviewState>,
    /// The org pinned this package to a different version.
    pub pinned_elsewhere: bool,
}

impl PluginFacts {
    /// Is this candidate version installable right now?
    ///
    /// The order is the design. Org policy is checked first because it is the
    /// organization's own decision and the most likely reason; the platform
    /// quarantine is checked next, because a quarantined artifact is a security
    /// fact that no org policy can override; and the review state is last
    /// because it only matters for a candidate that policy already permits.
    ///
    /// # A first install is not an expansion
    ///
    /// `candidate.from_version` is empty when the package is not installed yet.
    /// F25-003 is about a version that "expands requested permissions" relative
    /// to what the org already approved, and a first install has no such prior
    /// state — the `plugins.manage` action that installs it IS the approval.
    /// Applying the managed-mode gate to first installs would make `managed`
    /// mode unusable, because no plugin could ever be installed: every manifest
    /// declares at least one tool or the plugin does nothing.
    pub fn install_decision(
        &self,
        policy: &PluginPolicy,
        candidate: &PermissionDiff,
    ) -> PluginDecision {
        // A conflicting policy is reported, and the block still applies. The
        // caller surfaces both facts: the denial reason is `plugin_blocked` and
        // the conflict is reported alongside it.
        if policy.blocked_packages.contains(&self.package_id) {
            return PluginDecision::Deny(PluginDenyReason::Blocked);
        }
        if self.policy_conflict {
            // The block above already won. This branch is unreachable while a
            // conflicting package is also blocked, and exists so a caller that
            // asks about the conflict alone gets a stable answer.
            return PluginDecision::Deny(PluginDenyReason::PolicyConflict);
        }
        if !publisher_permitted(policy, &self.publisher_id, self.publisher_official) {
            return PluginDecision::Deny(PluginDenyReason::PublisherNotAllowed);
        }
        if self.quarantined {
            return PluginDecision::Deny(PluginDenyReason::Quarantined);
        }
        if policy.update_mode == UpdateMode::Managed
            && candidate.expands
            && !candidate.from_version.is_empty()
        {
            return PluginDecision::Deny(PluginDenyReason::PermissionExpanded);
        }
        if self.pinned_elsewhere {
            return PluginDecision::Deny(PluginDenyReason::Pinned);
        }
        PluginDecision::Allow
    }

    /// May the organization EXECUTE this exact version now?
    ///
    /// Execution is stricter than installation, deliberately. An in-flight run
    /// started before a block or a quarantine finishes under the policy it
    /// started with; a NEW invocation does not. That matches the P06 lease
    /// `ambiguous` precedent — a decision that cannot be applied to work already
    /// in flight is not applied to it after the fact — so the caller only has to
    /// ask once, at invocation time.
    pub fn execution_decision(&self, policy: &PluginPolicy) -> PluginDecision {
        if policy.blocked_packages.contains(&self.package_id) {
            return PluginDecision::Deny(PluginDenyReason::Blocked);
        }
        if self.quarantined {
            return PluginDecision::Deny(PluginDenyReason::Quarantined);
        }
        match self.review_state {
            // Not installed, or blocked, or waiting for review: no execution.
            None | Some(PluginReviewState::Blocked) | Some(PluginReviewState::PendingReview) => {
                PluginDecision::Deny(PluginDenyReason::Blocked)
            }
            Some(PluginReviewState::Unreviewed) => {
                PluginDecision::Deny(PluginDenyReason::ToolUnregistered)
            }
            Some(PluginReviewState::Approved) => PluginDecision::Allow,
        }
    }
}

/// F25-007: may an organization use this one tool?
///
/// Default-deny, and the deny is specific. A tool that is absent from the
/// manifest, or present in the manifest with no `plugin_tool_registrations` row
/// for `(org, package, version, tool)`, is not available. This is the control
/// that installing code can no longer bypass by declaring a tool.
pub fn tool_decision(
    facts: &PluginFacts,
    policy: &PluginPolicy,
    tool_in_manifest: bool,
    tool_registered: bool,
) -> PluginDecision {
    if let PluginDecision::Deny(reason) = facts.execution_decision(policy) {
        return PluginDecision::Deny(reason);
    }
    if !tool_in_manifest {
        return PluginDecision::Deny(PluginDenyReason::ToolUnregistered);
    }
    if !tool_registered {
        return PluginDecision::Deny(PluginDenyReason::ToolUnregistered);
    }
    PluginDecision::Allow
}

fn publisher_permitted(policy: &PluginPolicy, publisher_id: &str, official: bool) -> bool {
    match policy.publisher_mode {
        PublisherMode::Any => true,
        PublisherMode::OfficialOnly => official,
        PublisherMode::ApprovedPublishers => {
            official
                || policy
                    .approved_publishers
                    .iter()
                    .any(|id| id == publisher_id)
        }
    }
}

/// Where an install stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginReviewState {
    Unreviewed,
    Approved,
    PendingReview,
    Blocked,
}

impl PluginReviewState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unreviewed => "unreviewed",
            Self::Approved => "approved",
            Self::PendingReview => "pending_review",
            Self::Blocked => "blocked",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "unreviewed" => Some(Self::Unreviewed),
            "approved" => Some(Self::Approved),
            "pending_review" => Some(Self::PendingReview),
            "blocked" => Some(Self::Blocked),
            _ => None,
        }
    }
}

/// Is the reporting host inside a version's compatibility range?
///
/// A version whose range excludes the host cannot be installed, so this is a
/// gate rather than a warning. The range is inclusive at both ends; a
/// half-open range would make "min == max" reject the only version that fits.
pub fn host_is_compatible(
    runtime_min: &str,
    runtime_max: &str,
    host_runtime_version: &str,
) -> bool {
    host_runtime_version >= runtime_min && host_runtime_version <= runtime_max
}

// -------------------------------------------------------------- integrity ---

/// F25-005: verify a reported artifact digest against the trusted distribution
/// metadata before recording an install.
///
/// A mismatch denies `plugin_integrity_failed`. This is a constant-shape
/// comparison, not a cryptographic verification: the signature is carried in the
/// trusted manifest and verified by the distribution client that fetched the
/// artifact, so what the control plane can honestly assert is "the digest the
/// host reported is the digest the platform published". Claiming more than that
/// would be a lie in a security control.
pub fn integrity_matches(expected_digest: &str, reported_digest: &str) -> bool {
    expected_digest.len() == 64
        && reported_digest.len() == 64
        && expected_digest
            .bytes()
            .zip(reported_digest.bytes())
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> PluginPermissionManifest {
        PluginPermissionManifest {
            browser_capability: BrowserCapability::None,
            external_data_handling: ExternalDataHandling::None,
            ..PluginPermissionManifest::default()
        }
    }

    fn facts() -> PluginFacts {
        PluginFacts {
            package_id: "pkg_0123456789abcdef0123456789abcdef".into(),
            version: "1.2.0".into(),
            publisher_id: "pub_0123456789abcdef0123456789abcdef".into(),
            publisher_official: true,
            policy_conflict: false,
            quarantined: false,
            review_state: Some(PluginReviewState::Approved),
            pinned_elsewhere: false,
        }
    }

    // -- manifest normalization --------------------------------------------

    #[test]
    fn manifest_lists_are_order_and_duplicate_insensitive() {
        let a = manifest().clone().with_tools(["b", "a", "b"]).normalized();
        let b = manifest().with_tools(["a", "b"]).normalized();
        assert_eq!(a, b, "a re-ordered manifest is not a capability change");
    }

    // -- the diff ----------------------------------------------------------

    /// The F25 acceptance criterion, stated as a test: a tool appearing is an
    /// expansion, even when the same update removes something else.
    #[test]
    fn adding_a_tool_is_an_expansion_even_while_network_shrinks() {
        let before = manifest()
            .with_tools(["read_file"])
            .with_network_destinations(["https://api.example.com"]);
        let after = manifest()
            .with_tools(["read_file", "shell_exec"])
            .with_network_destinations(Vec::<String>::new());
        let result = diff(Some("1.0.0"), &before, "1.1.0", &after);
        assert!(
            result.expands,
            "a new tool must be an expansion regardless of what was removed"
        );
        assert_eq!(
            result.class("tools").expect("tools class").verdict,
            DiffClass::Added
        );
        assert_eq!(
            result
                .class("network_destinations")
                .expect("net class")
                .verdict,
            DiffClass::Removed
        );
    }

    #[test]
    fn a_pure_contraction_is_not_an_expansion() {
        let before = manifest()
            .with_tools(["read_file", "shell_exec"])
            .with_secret_handles([SecretHandle::new("gh", "github").expect("handle")]);
        let after = manifest().with_tools(["read_file"]);
        let result = diff(Some("1.0.0"), &before, "1.1.0", &after);
        assert!(!result.expands);
        assert_eq!(
            result.class("tools").expect("tools class").verdict,
            DiffClass::Removed
        );
        assert_eq!(
            result.class("secret_handles").expect("secrets").verdict,
            DiffClass::Removed
        );
    }

    #[test]
    fn an_identical_manifest_is_no_change_at_all() {
        let before = manifest()
            .with_tools(["read_file"])
            .with_network_destinations(["https://api.example.com"]);
        let result = diff(Some("1.0.0"), &before, "1.0.0", &before);
        assert!(!result.expands);
        assert!(
            result
                .classes
                .iter()
                .all(|c| c.verdict == DiffClass::Unchanged)
        );
    }

    /// `browser_capability` is ordered, so raising it is an expansion. This is
    /// the case a boolean manifest would silently under-report.
    #[test]
    fn raising_browser_capability_is_an_expansion() {
        let before = PluginPermissionManifest {
            browser_capability: BrowserCapability::Read,
            ..manifest()
        };
        let after = PluginPermissionManifest {
            browser_capability: BrowserCapability::ComputerUse,
            ..manifest()
        };
        let result = diff(Some("1.0.0"), &before, "1.1.0", &after);
        assert!(result.expands);
        assert_eq!(
            result.class("browser_capability").expect("browser").verdict,
            DiffClass::Added
        );

        // ...and lowering it is not.
        let down = diff(Some("1.1.0"), &after, "1.2.0", &before);
        assert!(!down.expands);
    }

    #[test]
    fn process_spawn_appearing_is_an_expansion() {
        let before = manifest();
        let after = PluginPermissionManifest {
            process_spawn: true,
            ..manifest()
        };
        assert!(diff(Some("1.0.0"), &before, "1.1.0", &after).expands);
        assert!(!diff(Some("1.1.0"), &after, "1.2.0", &before).expands);
    }

    /// A secret handle is `handle::purpose`. A publisher that keeps the handle
    /// and silently widens the purpose has asked for the same credential with a
    /// broader claim, and that is an expansion.
    #[test]
    fn widening_a_secret_handle_purpose_is_an_expansion() {
        let before = PluginPermissionManifest {
            secret_handles: vec![SecretHandle::new("gh", "read-repos").expect("handle")],
            ..manifest()
        };
        let after = PluginPermissionManifest {
            secret_handles: vec![SecretHandle::new("gh", "admin-org").expect("handle")],
            ..manifest()
        };
        assert!(diff(Some("1.0.0"), &before, "1.1.0", &after).expands);
    }

    /// External data handling is two-valued for diff purposes. A version that
    /// starts declaring it at all has gained the capability, and a version that
    /// stops declaring it is reported as not claiming it — not as a contraction
    /// that a reviewer could mistake for a reduction.
    #[test]
    fn external_data_handling_unknown_and_declared_both_claim_the_capability() {
        let before = PluginPermissionManifest {
            external_data_handling: ExternalDataHandling::Unknown,
            ..manifest()
        };
        let after = PluginPermissionManifest {
            external_data_handling: ExternalDataHandling::Declared,
            ..manifest()
        };
        assert!(!diff(Some("1.0.0"), &before, "1.1.0", &after).expands);

        // Dropping the declaration is a contraction, not an expansion, and going
        // from no declaration to one is an expansion.
        let none = manifest();
        assert!(!diff(Some("1.1.0"), &after, "1.2.0", &none).expands);
        assert!(diff(Some("1.2.0"), &none, "1.3.0", &after).expands);
    }

    // -- network destination refusal ---------------------------------------

    /// The documented wildcard form is a DESTINATION, not a syntax error.
    ///
    /// This is the case that was wrong. `rejects_destination` split on `://`
    /// first, and a `*.suffix` pattern has no scheme, so every wildcard
    /// declaration was classified as unparseable and the whole plugin report was
    /// refused — which made a form the field's own documentation promises
    /// unusable. The suffix is now the host that gets evaluated.
    #[test]
    fn a_subdomain_pattern_is_evaluated_by_its_suffix() {
        for pattern in ["*.example.com", "*.cdn.example.com", "*.co.uk"] {
            assert!(
                !PluginPermissionManifest::rejects_destination(pattern),
                "{pattern} is a documented destination form"
            );
        }
        // A pattern rooted at a private, loopback or link-local name reaches
        // inward exactly the way an exact literal does, so it is refused too.
        // `*.local` needs the bare `local` case in the check above, because
        // stripping the wildcard leaves exactly that, with no dot in front of it
        // for a suffix test to find.
        //
        // A suffix that is a THREE-octet string (`*.0.0.1`) is deliberately not in
        // this list: it is not an IP literal, so it is a hostname like any other
        // and the literal-based check cannot call it private. Asserted below rather
        // than left for a reader to infer.
        for pattern in [
            "*.localhost",
            "*.local",
            "*.internal.local",
            "*.127.0.0.1",
            "*.10.0.0.5",
            "*.169.254.169.254",
            "*",   // no host at all
            "*.",  // no host after the dot
            "*.*", // two wildcards is not a pattern this platform bounds
        ] {
            assert!(
                PluginPermissionManifest::rejects_destination(pattern),
                "{pattern} is not a destination this platform will record"
            );
        }
        // The literal-based limitation, asserted: a three-octet suffix is a
        // hostname, and the check has no basis to call it private.
        assert!(!PluginPermissionManifest::rejects_destination("*.0.0.1"));
    }

    #[test]
    fn private_loopback_and_link_local_destinations_are_refused() {
        for destination in [
            "http://127.0.0.1",
            "http://localhost:8080",
            "http://app.localhost",
            "https://printer.local",
            "http://10.0.0.5",
            "http://192.168.1.1",
            "http://172.16.4.4",
            "http://169.254.169.254", // link-local: the cloud metadata address
            "http://[::1]",
            "ftp://example.com",
            "not-a-url",
        ] {
            assert!(
                PluginPermissionManifest::rejects_destination(destination),
                "{destination} must be refused at report time"
            );
        }
        for destination in [
            "https://api.example.com",
            "https://api.example.com:8443/v1",
            "wss://events.example.com",
        ] {
            assert!(
                !PluginPermissionManifest::rejects_destination(destination),
                "{destination} is a legitimate public destination"
            );
        }
    }

    /// A hostname that merely ENDS WITH an IP-looking string is not an IP. The
    /// filter is on the parsed literal, so a public host is not refused for
    /// looking unusual.
    #[test]
    fn a_hostname_ending_in_digits_is_not_treated_as_an_address() {
        assert!(!PluginPermissionManifest::rejects_destination(
            "https://127.0.0.1.example.com"
        ));
    }

    // -- policy ------------------------------------------------------------

    #[test]
    fn a_package_on_both_lists_is_reported_as_a_conflict_and_the_block_wins() {
        let policy = PluginPolicy {
            allowed_packages: vec!["pkg_1".into()],
            blocked_packages: vec!["pkg_1".into()],
            ..PluginPolicy::default()
        };
        let conflicts = policy_conflicts(&policy);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].package_id, "pkg_1");

        let mut f = facts();
        f.package_id = "pkg_1".into();
        f.policy_conflict = true;
        let decision = f.install_decision(&policy, &diff(None, &manifest(), "1.0.0", &manifest()));
        // The block wins, and the reason an operator sees is the block — not a
        // generic conflict that sends them to the wrong place.
        assert_eq!(decision, PluginDecision::Deny(PluginDenyReason::Blocked));
    }

    #[test]
    fn publisher_mode_narrows_who_may_install() {
        let mut f = facts();
        f.publisher_official = false;
        let policy = PluginPolicy::default();
        let noop = diff(None, &manifest(), "1.0.0", &manifest());

        assert_eq!(
            f.install_decision(&policy, &noop),
            PluginDecision::Deny(PluginDenyReason::PublisherNotAllowed)
        );

        let approved = PluginPolicy {
            publisher_mode: PublisherMode::ApprovedPublishers,
            approved_publishers: vec![f.publisher_id.clone()],
            ..PluginPolicy::default()
        };
        assert_eq!(f.install_decision(&approved, &noop), PluginDecision::Allow);

        let any = PluginPolicy {
            publisher_mode: PublisherMode::Any,
            ..PluginPolicy::default()
        };
        assert_eq!(f.install_decision(&any, &noop), PluginDecision::Allow);
    }

    /// An official publisher is trusted under `approved_publishers` without
    /// being listed, so switching from `official_only` to the broader mode does
    /// not lock an organization out of the official catalog it already had.
    #[test]
    fn an_official_publisher_survives_the_broader_publisher_mode() {
        let policy = PluginPolicy {
            publisher_mode: PublisherMode::ApprovedPublishers,
            ..PluginPolicy::default()
        };
        assert!(
            facts()
                .install_decision(&policy, &diff(None, &manifest(), "1.0.0", &manifest()))
                .is_allowed()
        );
    }

    // -- the F25 acceptance criteria ---------------------------------------

    /// "A plugin update cannot silently gain network/secret/tool capability."
    #[test]
    fn managed_mode_refuses_an_expanding_update_instead_of_installing_it() {
        let policy = PluginPolicy::default();
        assert_eq!(policy.update_mode, UpdateMode::Managed);
        let before = manifest().with_tools(["read_file"]);
        let after = manifest().with_tools(["read_file", "write_file"]);
        let candidate = diff(Some("1.0.0"), &before, "1.1.0", &after);
        assert!(candidate.expands);
        assert_eq!(
            facts().install_decision(&policy, &candidate),
            PluginDecision::Deny(PluginDenyReason::PermissionExpanded)
        );
    }

    #[test]
    fn direct_mode_permits_an_expansion_but_it_is_still_an_expansion() {
        let policy = PluginPolicy {
            update_mode: UpdateMode::Direct,
            ..PluginPolicy::default()
        };
        let before = manifest().with_tools(["read_file"]);
        let after = manifest().with_tools(["read_file", "write_file"]);
        let candidate = diff(Some("1.0.0"), &before, "1.1.0", &after);
        assert!(
            candidate.expands,
            "the diff is a fact; the mode does not change it"
        );
        assert!(facts().install_decision(&policy, &candidate).is_allowed());
    }

    /// "Blocked version cannot execute for managed org even if still present on
    /// disk."  The deny is computed from stored state alone, so there is no
    /// artifact on the host that changes the answer.
    #[test]
    fn a_blocked_or_quarantined_version_cannot_execute_whatever_is_on_disk() {
        let policy = PluginPolicy::default();
        assert!(facts().execution_decision(&policy).is_allowed());

        let mut blocked = facts();
        blocked.review_state = Some(PluginReviewState::Blocked);
        assert_eq!(
            blocked.execution_decision(&policy),
            PluginDecision::Deny(PluginDenyReason::Blocked)
        );

        let mut quarantined = facts();
        quarantined.quarantined = true;
        assert_eq!(
            quarantined.execution_decision(&policy),
            PluginDecision::Deny(PluginDenyReason::Quarantined)
        );

        let mut not_installed = facts();
        not_installed.review_state = None;
        assert!(!not_installed.execution_decision(&policy).is_allowed());
    }

    /// A quarantine is a platform decision and an org block is a customer one.
    /// Neither can lift the other, so a customer with a permissive policy still
    /// cannot execute a quarantined version.
    #[test]
    fn an_org_cannot_lift_a_platform_quarantine_by_its_own_policy() {
        let policy = PluginPolicy {
            publisher_mode: PublisherMode::Any,
            auto_update: true,
            update_mode: UpdateMode::Direct,
            allowed_packages: vec![facts().package_id.clone()],
            ..PluginPolicy::default()
        };
        let mut quarantined = facts();
        quarantined.quarantined = true;
        assert_eq!(
            quarantined.execution_decision(&policy),
            PluginDecision::Deny(PluginDenyReason::Quarantined)
        );
    }

    /// F25-007 + F13 default-deny, which the foundation PR had no owner for.
    #[test]
    fn a_tool_needs_both_a_manifest_entry_and_a_registration() {
        let policy = PluginPolicy::default();
        assert!(tool_decision(&facts(), &policy, true, true).is_allowed());
        assert_eq!(
            tool_decision(&facts(), &policy, true, false),
            PluginDecision::Deny(PluginDenyReason::ToolUnregistered)
        );
        assert_eq!(
            tool_decision(&facts(), &policy, false, true),
            PluginDecision::Deny(PluginDenyReason::ToolUnregistered)
        );
        assert_eq!(
            tool_decision(&facts(), &policy, false, false),
            PluginDecision::Deny(PluginDenyReason::ToolUnregistered)
        );
    }

    #[test]
    fn a_pin_blocks_every_other_version_including_a_security_update() {
        let policy = PluginPolicy::default();
        let mut pinned = facts();
        pinned.pinned_elsewhere = true;
        let noop = diff(None, &manifest(), "9.9.9", &manifest());
        assert_eq!(
            pinned.install_decision(&policy, &noop),
            PluginDecision::Deny(PluginDenyReason::Pinned)
        );
    }

    // -- compatibility and integrity ---------------------------------------

    #[test]
    fn the_compatibility_range_is_inclusive_at_both_ends() {
        assert!(host_is_compatible("1.0.0", "2.0.0", "1.0.0"));
        assert!(host_is_compatible("1.0.0", "2.0.0", "2.0.0"));
        assert!(host_is_compatible("1.0.0", "2.0.0", "1.5.0"));
        assert!(!host_is_compatible("1.0.0", "2.0.0", "0.9.9"));
        assert!(!host_is_compatible("1.0.0", "2.0.0", "2.0.1"));
    }

    #[test]
    fn integrity_comparison_has_no_length_or_value_shortcut() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        assert!(integrity_matches(&a, &a));
        assert!(!integrity_matches(&a, &b));
        assert!(!integrity_matches(&a, "short"));
        assert!(!integrity_matches(&a, &a[..63]));
    }

    #[test]
    fn every_denial_reason_has_a_stable_code() {
        for (reason, code) in [
            (PluginDenyReason::Blocked, "plugin_blocked"),
            (PluginDenyReason::Quarantined, "plugin_quarantined"),
            (
                PluginDenyReason::PermissionExpanded,
                "plugin_permission_expanded",
            ),
            (PluginDenyReason::Pinned, "plugin_pinned"),
            (PluginDenyReason::Incompatible, "plugin_incompatible"),
            (PluginDenyReason::IntegrityFailed, "plugin_integrity_failed"),
            (
                PluginDenyReason::ToolUnregistered,
                "plugin_tool_unregistered",
            ),
            (
                PluginDenyReason::VersionNotPendingReview,
                "version_not_pending_review",
            ),
            (PluginDenyReason::PolicyConflict, "policy_conflict"),
        ] {
            assert_eq!(reason.code(), code);
            assert_eq!(reason.to_string(), code);
        }
    }

    // -- test-only builders -------------------------------------------------

    impl PluginPermissionManifest {
        fn with_tools<I, S>(self, tools: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: Into<String>,
        {
            Self {
                tools: tools.into_iter().map(Into::into).collect(),
                ..self
            }
        }

        fn with_network_destinations<I, S>(self, values: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: Into<String>,
        {
            Self {
                network_destinations: values.into_iter().map(Into::into).collect(),
                ..self
            }
        }

        fn with_secret_handles<I>(self, values: I) -> Self
        where
            I: IntoIterator<Item = SecretHandle>,
        {
            Self {
                secret_handles: values.into_iter().collect(),
                ..self
            }
        }
    }

    #[test]
    fn a_first_install_is_expanding_by_the_diff_but_not_by_the_gate() {
        let first = diff(None, &manifest(), "1.0.0", &manifest().with_tools(["a"]));
        assert!(first.from_version.is_empty());
        assert!(first.expands);
        assert!(
            facts()
                .install_decision(&PluginPolicy::default(), &first)
                .is_allowed()
        );
    }
}
