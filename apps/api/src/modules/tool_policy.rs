//! P05 tool and capability policy evaluation.
//!
//! This module is deliberately pure. The caller resolves the organization,
//! project, device, agent, and current policy before calling [`evaluate`];
//! this code does not accept a client-supplied authorization result, prompt,
//! tool URL, or execution handle. The Worker remains the policy authority, but
//! the desktop/runtime remains the execution host.
//!
//! Evaluation is intentionally ordered and fail-closed:
//!
//! 1. platform hard deny;
//! 2. organization/project policy;
//! 3. agent allow-list;
//! 4. runtime capability support;
//! 5. catalog identity, risk, fingerprint, and MCP review state;
//! 6. browser/computer rules; and
//! 7. approval requirements.
//!
//! Approval bindings contain only bounded, redacted argument metadata. A
//! changed fingerprint or a newly discovered MCP tool therefore cannot reuse a
//! previous binding.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

/// The only managed tool-policy schema understood by this phase.
pub const TOOL_POLICY_SCHEMA_VERSION: u32 = 1;

/// Metadata limits are deliberately small because these values are returned
/// in policy decisions, approval bindings, and run timelines.
pub const MAX_TOOL_ID_LEN: usize = 128;
pub const MAX_FINGERPRINT_LEN: usize = 256;
pub const MAX_CAPABILITY_ID_LEN: usize = 96;
pub const MAX_CAPABILITY_IDS: usize = 128;
pub const MAX_TOOL_IDS_PER_POLICY: usize = 4_096;
pub const MAX_MCP_IDS_PER_POLICY: usize = 1_024;
pub const MAX_APPROVAL_RULES_PER_POLICY: usize = 4_096;
pub const MAX_DOMAINS_PER_POLICY: usize = 1_024;
pub const MAX_APPLICATIONS_PER_POLICY: usize = 256;
pub const MAX_MCP_FINGERPRINTS: usize = 4_096;
pub const MAX_ARGUMENT_SUMMARY_INPUT_LEN: usize = 2_048;
pub const MAX_ARGUMENT_SUMMARY_LEN: usize = 512;
pub const MAX_ARGUMENT_FIELDS: usize = 32;
pub const MAX_REASON_MESSAGE_LEN: usize = 160;

/// Capability names used by the runtime adapters. The catalog may use one of
/// the short or `cap_`-prefixed forms; policy decisions never infer authority
/// from a prompt or a tool name.
pub const BROWSER_CAPABILITY_ID: &str = "browser";
pub const COMPUTER_CAPABILITY_ID: &str = "computer";

/// Tool risk classes frozen by P05-CG.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    ReadOnly,
    FilesystemWrite,
    ProcessExecution,
    Network,
    Mcp,
    Browser,
    Computer,
    CredentialBearing,
    ExternalSideEffect,
    Destructive,
}

impl RiskClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::FilesystemWrite => "filesystem_write",
            Self::ProcessExecution => "process_execution",
            Self::Network => "network",
            Self::Mcp => "mcp",
            Self::Browser => "browser",
            Self::Computer => "computer",
            Self::CredentialBearing => "credential_bearing",
            Self::ExternalSideEffect => "external_side_effect",
            Self::Destructive => "destructive",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "read_only" => Some(Self::ReadOnly),
            "filesystem_write" => Some(Self::FilesystemWrite),
            "process_execution" => Some(Self::ProcessExecution),
            "network" => Some(Self::Network),
            "mcp" => Some(Self::Mcp),
            "browser" => Some(Self::Browser),
            "computer" => Some(Self::Computer),
            "credential_bearing" => Some(Self::CredentialBearing),
            "external_side_effect" => Some(Self::ExternalSideEffect),
            "destructive" => Some(Self::Destructive),
            _ => None,
        }
    }

    /// Anything other than a read-only operation is privileged for the
    /// purposes of managed unknown-tool handling.
    pub const fn is_privileged(self) -> bool {
        !matches!(self, Self::ReadOnly)
    }

    /// A policy can require more approval than this floor, but never less.
    /// This keeps a policy typo or an omitted approval rule from turning a
    /// side-effecting tool into a no-approval tool.
    pub const fn minimum_approval_mode(self) -> ApprovalMode {
        match self {
            Self::ReadOnly => ApprovalMode::None,
            Self::FilesystemWrite | Self::Network | Self::Browser => ApprovalMode::Session,
            Self::ProcessExecution
            | Self::Mcp
            | Self::Computer
            | Self::CredentialBearing
            | Self::ExternalSideEffect
            | Self::Destructive => ApprovalMode::PerUse,
        }
    }
}

/// Source metadata for a tool catalog entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolSource {
    BuiltIn,
    Plugin,
    Custom,
}

impl ToolSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BuiltIn => "built_in",
            Self::Plugin => "plugin",
            Self::Custom => "custom",
        }
    }
}

/// MCP registration source values are kept separate from [`ToolSource`] so a
/// registration cannot silently change identity when it is updated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpSource {
    BuiltIn,
    Plugin,
    Custom,
}

impl McpSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BuiltIn => "built_in",
            Self::Plugin => "plugin",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolLifecycle {
    Active,
    Deprecated,
    Review,
    Disabled,
}

impl ToolLifecycle {
    pub const fn allows_execution(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityLifecycle {
    Active,
    Disabled,
}

impl CapabilityLifecycle {
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpPolicyStatus {
    Approved,
    PendingReview,
    Denied,
    Disabled,
    Revoked,
}

/// Approval requirement independent of the final decision wire name.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    #[default]
    None,
    Session,
    PerUse,
}

impl ApprovalMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Session => "session",
            Self::PerUse => "per_use",
        }
    }

    pub const fn rank(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Session => 1,
            Self::PerUse => 2,
        }
    }

    pub const fn most_restrictive(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }
}

/// Effective tool decision returned by the broker boundary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolDecision {
    Allow,
    RequireSessionApproval,
    RequirePerUseApproval,
    #[default]
    Deny,
}

impl ToolDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::RequireSessionApproval => "require_session_approval",
            Self::RequirePerUseApproval => "require_per_use_approval",
            Self::Deny => "deny",
        }
    }

    pub const fn rank(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::RequireSessionApproval => 1,
            Self::RequirePerUseApproval => 2,
            Self::Deny => 3,
        }
    }

    pub const fn most_restrictive(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    pub const fn approval_mode(self) -> Option<ApprovalMode> {
        match self {
            Self::Allow | Self::Deny => None,
            Self::RequireSessionApproval => Some(ApprovalMode::Session),
            Self::RequirePerUseApproval => Some(ApprovalMode::PerUse),
        }
    }

    pub const fn from_approval_mode(mode: ApprovalMode) -> Self {
        match mode {
            ApprovalMode::None => Self::Allow,
            ApprovalMode::Session => Self::RequireSessionApproval,
            ApprovalMode::PerUse => Self::RequirePerUseApproval,
        }
    }

    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }

    pub const fn is_deny(self) -> bool {
        matches!(self, Self::Deny)
    }

    pub const fn requires_approval(self) -> bool {
        matches!(
            self,
            Self::RequireSessionApproval | Self::RequirePerUseApproval
        )
    }
}

/// Whether a policy is being evaluated for a managed organization or a local
/// personal execution context. Local personal mode may omit the managed policy
/// document, but it still cannot bypass platform hard denies or MCP review.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    ManagedOrganization,
    LocalPersonal,
}

/// Default posture for a policy layer. An explicit `Allow` is meaningful only
/// when the layer itself is a valid, server-resolved policy document.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPosture {
    #[default]
    Deny,
    Allow,
}

/// Browser external-submit policy. `Allow` still cannot lower the risk-class
/// approval floor or any platform deny.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalSubmitPolicy {
    Allow,
    SessionApproval,
    PerUseApproval,
    #[default]
    Deny,
}

impl ExternalSubmitPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::SessionApproval => "require_session_approval",
            Self::PerUseApproval => "require_per_use_approval",
            Self::Deny => "deny",
        }
    }

    pub const fn most_restrictive(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::SessionApproval => 1,
            Self::PerUseApproval => 2,
            Self::Deny => 3,
        }
    }
}

/// Stable machine-readable reason codes. Messages are static and never built
/// from a tool ID, URL, prompt, argument, or other caller-controlled value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionReasonCode {
    PolicyAllowed,
    PlatformHardDeny,
    PolicySchemaInvalid,
    ToolIdentityInvalid,
    ArgumentSummaryInvalid,
    OrgToolDenied,
    ProjectToolDenied,
    McpSourceNotAllowed,
    AgentToolNotAllowed,
    RuntimeCapabilityUnavailable,
    CapabilityNotDefined,
    ToolNotFound,
    ToolInactive,
    ToolRiskClassMismatch,
    ToolCapabilityMismatch,
    ToolFingerprintChanged,
    McpToolRequiresReview,
    BrowserActionDenied,
    ComputerActionDenied,
    ApprovalRequired,
}

impl DecisionReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyAllowed => "policy_allowed",
            Self::PlatformHardDeny => "platform_hard_deny",
            Self::PolicySchemaInvalid => "policy_schema_invalid",
            Self::ToolIdentityInvalid => "tool_identity_invalid",
            Self::ArgumentSummaryInvalid => "argument_summary_invalid",
            Self::OrgToolDenied => "org_tool_denied",
            Self::ProjectToolDenied => "project_tool_denied",
            Self::McpSourceNotAllowed => "mcp_source_not_allowed",
            Self::AgentToolNotAllowed => "agent_tool_not_allowed",
            Self::RuntimeCapabilityUnavailable => "runtime_capability_unavailable",
            Self::CapabilityNotDefined => "capability_not_defined",
            Self::ToolNotFound => "tool_not_found",
            Self::ToolInactive => "tool_denied",
            Self::ToolRiskClassMismatch => "tool_risk_class_mismatch",
            Self::ToolCapabilityMismatch => "tool_capability_mismatch",
            Self::ToolFingerprintChanged => "tool_fingerprint_changed",
            Self::McpToolRequiresReview => "mcp_tool_requires_review",
            Self::BrowserActionDenied => "browser_action_denied",
            Self::ComputerActionDenied => "computer_action_denied",
            Self::ApprovalRequired => "approval_required",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::PolicyAllowed => "All applicable policy checks passed.",
            Self::PlatformHardDeny => "Platform policy denies this capability.",
            Self::PolicySchemaInvalid => "The current tool policy is unavailable or invalid.",
            Self::ToolIdentityInvalid => "The tool identity or capability metadata is invalid.",
            Self::ArgumentSummaryInvalid => "The argument summary is invalid or too large.",
            Self::OrgToolDenied => "Organization policy does not allow this tool.",
            Self::ProjectToolDenied => "Project policy does not allow this tool.",
            Self::McpSourceNotAllowed => "The MCP source is not allowed by policy.",
            Self::AgentToolNotAllowed => "The agent definition does not allow this tool.",
            Self::RuntimeCapabilityUnavailable => {
                "The runtime does not provide a required capability."
            }
            Self::CapabilityNotDefined => "A required capability is not defined in the catalog.",
            Self::ToolNotFound => "The tool is not present in the current catalog.",
            Self::ToolInactive => "The tool lifecycle does not permit execution.",
            Self::ToolRiskClassMismatch => "The requested risk class does not match the catalog.",
            Self::ToolCapabilityMismatch => "The requested capabilities do not match the catalog.",
            Self::ToolFingerprintChanged => "The tool fingerprint changed and requires review.",
            Self::McpToolRequiresReview => "The MCP tool fingerprint requires policy review.",
            Self::BrowserActionDenied => "Browser policy denies this action.",
            Self::ComputerActionDenied => "Computer-use policy denies this action.",
            Self::ApprovalRequired => "The tool requires an approval before execution.",
        }
    }
}

/// Explainability metadata. The message is a bounded static string; rejected
/// input is never copied into it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReason {
    pub code: DecisionReasonCode,
    pub message: String,
}

impl DecisionReason {
    pub fn new(code: DecisionReasonCode) -> Self {
        let message = code.message().to_owned();
        let message = if message.len() <= MAX_REASON_MESSAGE_LEN {
            message
        } else {
            "Policy decision unavailable.".to_owned()
        };
        Self { code, message }
    }

    pub fn code(&self) -> DecisionReasonCode {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Debug for DecisionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecisionReason")
            .field("code", &self.code)
            .field("message", &self.message)
            .finish()
    }
}

/// Platform rules are an unconditional upper bound on every other policy
/// layer. These sets are intentionally explicit; an empty set does not widen
/// access.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformToolPolicy {
    pub denied_tool_ids: BTreeSet<String>,
    pub denied_capability_ids: BTreeSet<String>,
    pub denied_risk_classes: BTreeSet<RiskClass>,
    pub denied_mcp_ids: BTreeSet<String>,
}

impl PlatformToolPolicy {
    pub fn validate(&self) -> bool {
        self.denied_tool_ids.len() <= MAX_TOOL_IDS_PER_POLICY
            && self.denied_mcp_ids.len() <= MAX_MCP_IDS_PER_POLICY
            && self.denied_capability_ids.len() <= MAX_CAPABILITY_IDS
            && valid_id_set(&self.denied_tool_ids, MAX_TOOL_ID_LEN)
            && valid_id_set(&self.denied_mcp_ids, MAX_TOOL_ID_LEN)
            && valid_id_set(&self.denied_capability_ids, MAX_CAPABILITY_ID_LEN)
    }
}

/// A capability definition is catalog metadata. The runtime report is checked
/// separately; this prevents a runtime from silently enabling a disabled or
/// newly unknown managed capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDefinition {
    pub capability_id: String,
    pub lifecycle: CapabilityLifecycle,
}

impl CapabilityDefinition {
    pub fn validate(&self) -> bool {
        valid_metadata_id(&self.capability_id, MAX_CAPABILITY_ID_LEN)
    }
}

/// Non-secret catalog record. Endpoint, command, and secret-handle metadata are
/// deliberately outside this pure module.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub tool_id: String,
    pub name: String,
    pub source: ToolSource,
    pub risk_class: RiskClass,
    pub capability_ids: BTreeSet<String>,
    pub fingerprint: String,
    pub lifecycle: ToolLifecycle,
    pub mcp_registration_id: Option<String>,
}

impl ToolDefinition {
    pub fn validate(&self) -> bool {
        valid_metadata_id(&self.tool_id, MAX_TOOL_ID_LEN)
            && !self.name.trim().is_empty()
            && self.name.chars().count() <= 160
            && !self.name.chars().any(char::is_control)
            && valid_fingerprint(&self.fingerprint)
            && valid_capability_set(&self.capability_ids)
            && self
                .mcp_registration_id
                .as_deref()
                .is_none_or(|id| valid_metadata_id(id, MAX_TOOL_ID_LEN))
    }
}

/// MCP registration state used to bind a tool fingerprint to a reviewed tool
/// list. `current_tool_fingerprints` may contain a newly discovered fingerprint
/// that is intentionally absent from `reviewed_tool_fingerprints`; that state
/// must produce a re-review decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpRegistration {
    pub mcp_id: String,
    pub source: McpSource,
    pub policy_status: McpPolicyStatus,
    pub current_tool_fingerprints: BTreeSet<String>,
    pub reviewed_tool_fingerprints: BTreeSet<String>,
}

impl McpRegistration {
    pub fn validate(&self) -> bool {
        valid_metadata_id(&self.mcp_id, MAX_TOOL_ID_LEN)
            && self.current_tool_fingerprints.len() <= MAX_MCP_FINGERPRINTS
            && self.reviewed_tool_fingerprints.len() <= MAX_MCP_FINGERPRINTS
            && valid_fingerprint_set(&self.current_tool_fingerprints)
            && valid_fingerprint_set(&self.reviewed_tool_fingerprints)
    }
}

/// Catalog data needed by the evaluator. A missing catalog entry is never
/// authority for a privileged managed tool.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCatalog {
    pub tools: BTreeMap<String, ToolDefinition>,
    pub capability_definitions: BTreeMap<String, CapabilityDefinition>,
    pub mcp_registrations: BTreeMap<String, McpRegistration>,
}

impl ToolCatalog {
    pub fn tool(&self, tool_id: &str) -> Option<&ToolDefinition> {
        self.tools.get(tool_id)
    }
}

/// Agent-level intersection constraint. An empty allow-list denies every tool.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentToolPolicy {
    pub allowed_tool_ids: BTreeSet<String>,
    pub required_capability_ids: BTreeSet<String>,
}

impl AgentToolPolicy {
    pub fn validate(&self) -> bool {
        self.allowed_tool_ids.len() <= MAX_TOOL_IDS_PER_POLICY
            && self.required_capability_ids.len() <= MAX_CAPABILITY_IDS
            && valid_id_set(&self.allowed_tool_ids, MAX_TOOL_ID_LEN)
            && valid_capability_set(&self.required_capability_ids)
    }
}

/// Runtime-reported capability support. The report is not an authorization
/// grant; it only proves that the execution host can perform a capability that
/// has already passed policy checks.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCapabilities {
    pub supported_capability_ids: BTreeSet<String>,
}

impl RuntimeCapabilities {
    pub fn validate(&self) -> bool {
        self.supported_capability_ids.len() <= MAX_CAPABILITY_IDS
            && valid_capability_set(&self.supported_capability_ids)
    }

    pub fn supports_all(&self, capabilities: &BTreeSet<String>) -> bool {
        capabilities
            .iter()
            .all(|capability| self.supported_capability_ids.contains(capability))
    }
}

/// Browser policy fields match the P05-CG policy snapshot. Domain entries are
/// host names, never arbitrary URLs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserPolicy {
    pub allowed_domains: BTreeSet<String>,
    pub blocked_domains: BTreeSet<String>,
    pub allow_download: bool,
    pub allow_upload: bool,
    pub allow_authenticated: bool,
    pub allow_clipboard: bool,
    pub external_submit: ExternalSubmitPolicy,
}

impl Default for BrowserPolicy {
    fn default() -> Self {
        Self {
            allowed_domains: BTreeSet::new(),
            blocked_domains: BTreeSet::new(),
            allow_download: false,
            allow_upload: false,
            allow_authenticated: false,
            allow_clipboard: false,
            external_submit: ExternalSubmitPolicy::Deny,
        }
    }
}

impl BrowserPolicy {
    pub fn validate(&self) -> bool {
        self.allowed_domains.len() <= MAX_DOMAINS_PER_POLICY
            && self.blocked_domains.len() <= MAX_DOMAINS_PER_POLICY
            && valid_domain_set(&self.allowed_domains)
            && valid_domain_set(&self.blocked_domains)
    }

    fn intersection(&self, other: &Self) -> Self {
        Self {
            allowed_domains: intersect_sets(&self.allowed_domains, &other.allowed_domains),
            blocked_domains: union_sets(&self.blocked_domains, &other.blocked_domains),
            allow_download: self.allow_download && other.allow_download,
            allow_upload: self.allow_upload && other.allow_upload,
            allow_authenticated: self.allow_authenticated && other.allow_authenticated,
            allow_clipboard: self.allow_clipboard && other.allow_clipboard,
            external_submit: self.external_submit.most_restrictive(other.external_submit),
        }
    }
}

/// Computer-use policy fields match the P05-CG policy snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputerPolicy {
    pub allow_accessibility: bool,
    pub allow_screen_capture: bool,
    pub allow_keyboard_mouse: bool,
    pub allow_shell_escalation: bool,
    pub allowed_applications: BTreeSet<String>,
}

impl ComputerPolicy {
    pub fn validate(&self) -> bool {
        self.allowed_applications.len() <= MAX_APPLICATIONS_PER_POLICY
            && valid_application_set(&self.allowed_applications)
    }

    fn intersection(&self, other: &Self) -> Self {
        Self {
            allow_accessibility: self.allow_accessibility && other.allow_accessibility,
            allow_screen_capture: self.allow_screen_capture && other.allow_screen_capture,
            allow_keyboard_mouse: self.allow_keyboard_mouse && other.allow_keyboard_mouse,
            allow_shell_escalation: self.allow_shell_escalation && other.allow_shell_escalation,
            allowed_applications: intersect_sets(
                &self.allowed_applications,
                &other.allowed_applications,
            ),
        }
    }
}

/// One server-resolved organization or project policy layer. A project layer
/// is an intersection with the organization layer; it cannot broaden it.
///
/// The allow/deny sets and approval maps are evaluator overlays supplied by
/// the service layer; the P05 policy adapter remains responsible for mapping
/// the frozen wire document into this resolved value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPolicyLayer {
    pub schema_version: u32,
    pub default_posture: PolicyPosture,
    #[serde(default)]
    pub denied_tool_ids: BTreeSet<String>,
    pub tool_ids: BTreeSet<String>,
    #[serde(default)]
    pub denied_mcp_ids: BTreeSet<String>,
    pub mcp_ids: BTreeSet<String>,
    #[serde(default)]
    pub default_approval_mode: ApprovalMode,
    #[serde(default)]
    pub tool_approval_modes: BTreeMap<String, ApprovalMode>,
    pub browser: BrowserPolicy,
    pub computer: ComputerPolicy,
}

impl Default for ToolPolicyLayer {
    fn default() -> Self {
        Self {
            schema_version: TOOL_POLICY_SCHEMA_VERSION,
            default_posture: PolicyPosture::Deny,
            denied_tool_ids: BTreeSet::new(),
            tool_ids: BTreeSet::new(),
            denied_mcp_ids: BTreeSet::new(),
            mcp_ids: BTreeSet::new(),
            default_approval_mode: ApprovalMode::None,
            tool_approval_modes: BTreeMap::new(),
            browser: BrowserPolicy::default(),
            computer: ComputerPolicy::default(),
        }
    }
}

impl ToolPolicyLayer {
    pub fn validate(&self) -> bool {
        self.schema_version == TOOL_POLICY_SCHEMA_VERSION
            && self.denied_tool_ids.len() <= MAX_TOOL_IDS_PER_POLICY
            && self.tool_ids.len() <= MAX_TOOL_IDS_PER_POLICY
            && self.denied_mcp_ids.len() <= MAX_MCP_IDS_PER_POLICY
            && self.mcp_ids.len() <= MAX_MCP_IDS_PER_POLICY
            && self.tool_approval_modes.len() <= MAX_APPROVAL_RULES_PER_POLICY
            && valid_id_set(&self.denied_tool_ids, MAX_TOOL_ID_LEN)
            && valid_id_set(&self.tool_ids, MAX_TOOL_ID_LEN)
            && valid_id_set(&self.denied_mcp_ids, MAX_TOOL_ID_LEN)
            && valid_id_set(&self.mcp_ids, MAX_TOOL_ID_LEN)
            && self
                .tool_approval_modes
                .keys()
                .all(|tool_id| valid_metadata_id(tool_id, MAX_TOOL_ID_LEN))
            && self.browser.validate()
            && self.computer.validate()
    }

    /// Explicit denies win over the posture and allow-list. Explicitly listed
    /// tools are allowed; the posture controls tools that are not listed. This
    /// keeps a deny-by-default document restrictive without requiring a second
    /// duplicate rule for every allowed tool.
    fn allows_tool(&self, tool_id: &str) -> bool {
        !self.denied_tool_ids.contains(tool_id)
            && (self.tool_ids.contains(tool_id)
                || matches!(self.default_posture, PolicyPosture::Allow))
    }

    fn allows_mcp(&self, mcp_id: &str) -> bool {
        !self.denied_mcp_ids.contains(mcp_id) && self.mcp_ids.contains(mcp_id)
    }

    fn approval_for(&self, tool_id: &str) -> ApprovalMode {
        self.tool_approval_modes
            .get(tool_id)
            .copied()
            .unwrap_or(self.default_approval_mode)
    }
}

/// A normalized, risk-relevant browser action. It contains a host, not a URL
/// or page body, so policy evaluation cannot become an SSRF or data-exfiltration
/// primitive.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum BrowserAction {
    Visit { domain: String },
    Download { domain: String },
    Upload { domain: String },
    Authenticated { domain: String },
    Clipboard { domain: String },
    ExternalSubmit { domain: String },
}

impl BrowserAction {
    fn domain(&self) -> &str {
        match self {
            Self::Visit { domain }
            | Self::Download { domain }
            | Self::Upload { domain }
            | Self::Authenticated { domain }
            | Self::Clipboard { domain }
            | Self::ExternalSubmit { domain } => domain,
        }
    }
}

impl fmt::Debug for BrowserAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrowserAction")
            .field("action", &self.action_name())
            .field("domain", &"[redacted]")
            .finish()
    }
}

impl BrowserAction {
    const fn action_name(&self) -> &'static str {
        match self {
            Self::Visit { .. } => "visit",
            Self::Download { .. } => "download",
            Self::Upload { .. } => "upload",
            Self::Authenticated { .. } => "authenticated",
            Self::Clipboard { .. } => "clipboard",
            Self::ExternalSubmit { .. } => "external_submit",
        }
    }
}

/// A normalized, target-bound computer-use action.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ComputerAction {
    Accessibility { application: String },
    ScreenCapture { application: String },
    KeyboardMouse { application: String },
    ShellEscalation { application: String },
}

impl ComputerAction {
    fn application(&self) -> &str {
        match self {
            Self::Accessibility { application }
            | Self::ScreenCapture { application }
            | Self::KeyboardMouse { application }
            | Self::ShellEscalation { application } => application,
        }
    }

    const fn minimum_approval_mode(&self) -> ApprovalMode {
        match self {
            Self::Accessibility { .. }
            | Self::ScreenCapture { .. }
            | Self::KeyboardMouse { .. } => ApprovalMode::Session,
            Self::ShellEscalation { .. } => ApprovalMode::PerUse,
        }
    }
}

impl fmt::Debug for ComputerAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ComputerAction")
            .field("action", &self.action_name())
            .field("application", &"[redacted]")
            .finish()
    }
}

impl ComputerAction {
    const fn action_name(&self) -> &'static str {
        match self {
            Self::Accessibility { .. } => "accessibility",
            Self::ScreenCapture { .. } => "screen_capture",
            Self::KeyboardMouse { .. } => "keyboard_mouse",
            Self::ShellEscalation { .. } => "shell_escalation",
        }
    }
}

/// A tool-call candidate received from the broker boundary. There is
/// intentionally no `decision`, `allow`, `prompt`, or `approved` field.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCall {
    pub tool_call_id: String,
    pub tool_id: String,
    pub tool_fingerprint: String,
    pub capability_ids: BTreeSet<String>,
    pub risk_class: RiskClass,
    pub arguments_summary: String,
    pub browser_action: Option<BrowserAction>,
    pub computer_action: Option<ComputerAction>,
}

impl fmt::Debug for ToolCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolCall")
            .field("tool_call_id", &self.tool_call_id)
            .field("tool_id", &self.tool_id)
            .field("tool_fingerprint", &self.tool_fingerprint)
            .field("capability_ids", &self.capability_ids)
            .field("risk_class", &self.risk_class)
            .field("arguments_summary", &"[redacted]")
            .field(
                "browser_action",
                &self.browser_action.as_ref().map(|_| "[present]"),
            )
            .field(
                "computer_action",
                &self.computer_action.as_ref().map(|_| "[present]"),
            )
            .finish()
    }
}

/// Exact metadata that an approval must bind to. It contains the sanitized
/// summary, never the raw argument body.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalBinding {
    pub tool_call_id: String,
    pub tool_id: String,
    pub tool_fingerprint: String,
    pub capability_ids: BTreeSet<String>,
    pub risk_class: RiskClass,
    pub browser_action: Option<BrowserAction>,
    pub computer_action: Option<ComputerAction>,
    pub arguments_summary: String,
}

impl ApprovalBinding {
    pub fn matches_call(&self, call: &ToolCall) -> bool {
        if self.tool_call_id != call.tool_call_id
            || self.tool_id != call.tool_id
            || self.tool_fingerprint != call.tool_fingerprint
            || self.capability_ids != call.capability_ids
            || self.risk_class != call.risk_class
            || self.browser_action != call.browser_action
            || self.computer_action != call.computer_action
        {
            return false;
        }
        match redact_argument_summary(&call.arguments_summary) {
            Ok(summary) => self.arguments_summary == summary,
            Err(_) => false,
        }
    }
}

impl fmt::Debug for ApprovalBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalBinding")
            .field("tool_call_id", &self.tool_call_id)
            .field("tool_id", &self.tool_id)
            .field("tool_fingerprint", &self.tool_fingerprint)
            .field("capability_ids", &self.capability_ids)
            .field("risk_class", &self.risk_class)
            .field(
                "browser_action",
                &self.browser_action.as_ref().map(|_| "[present]"),
            )
            .field(
                "computer_action",
                &self.computer_action.as_ref().map(|_| "[present]"),
            )
            .field("arguments_summary", &"[redacted]")
            .finish()
    }
}

/// Result of one pure evaluation. `arguments_summary` is always the sanitized
/// value or `None` when the input was rejected. No approval binding is
/// returned for a deny, and an allow never means that an approval was granted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolPolicyDecision {
    pub decision: ToolDecision,
    pub reason: DecisionReason,
    pub policy_version: i64,
    pub arguments_summary: Option<String>,
    pub approval_binding: Option<ApprovalBinding>,
}

impl ToolPolicyDecision {
    pub fn is_allowed(&self) -> bool {
        self.decision.is_allowed()
    }

    pub fn is_deny(&self) -> bool {
        self.decision.is_deny()
    }

    pub fn requires_approval(&self) -> bool {
        self.decision.requires_approval()
    }
}

impl fmt::Debug for ToolPolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolPolicyDecision")
            .field("decision", &self.decision)
            .field("reason", &self.reason)
            .field("policy_version", &self.policy_version)
            .field(
                "arguments_summary",
                &self.arguments_summary.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "approval_binding",
                &self.approval_binding.as_ref().map(|_| "[present]"),
            )
            .finish()
    }
}

/// All inputs must already be resolved from authoritative server state. The
/// evaluator deliberately contains no organization/project IDs: route/service
/// code owns tenant scope and supplies the matching policy layers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyEvaluationInput {
    pub mode: ExecutionMode,
    pub platform: PlatformToolPolicy,
    pub organization_policy: Option<ToolPolicyLayer>,
    pub project_policy: Option<ToolPolicyLayer>,
    pub agent: AgentToolPolicy,
    pub runtime: RuntimeCapabilities,
    pub catalog: ToolCatalog,
    pub call: ToolCall,
    /// The server-resolved current policy version returned with the decision.
    pub policy_version: i64,
}

/// Evaluate a tool call without performing any tool action.
pub fn evaluate(input: &PolicyEvaluationInput) -> ToolPolicyDecision {
    // Platform rules deliberately run before every other input check. A
    // malformed lower layer cannot turn a platform deny into another result.
    if !input.platform.validate() || platform_denies(input) {
        return denied(
            input.policy_version,
            DecisionReasonCode::PlatformHardDeny,
            None,
        );
    }

    if input.policy_version < 0
        || (input.mode == ExecutionMode::ManagedOrganization && input.policy_version == 0)
        || !valid_call_metadata(&input.call)
    {
        return denied(
            input.policy_version,
            DecisionReasonCode::ToolIdentityInvalid,
            None,
        );
    }

    let summary = match redact_argument_summary(&input.call.arguments_summary) {
        Ok(summary) => summary,
        Err(_) => {
            return denied(
                input.policy_version,
                DecisionReasonCode::ArgumentSummaryInvalid,
                None,
            );
        }
    };

    if input.mode == ExecutionMode::ManagedOrganization {
        let Some(organization_policy) = input.organization_policy.as_ref() else {
            return denied(
                input.policy_version,
                DecisionReasonCode::PolicySchemaInvalid,
                Some(summary),
            );
        };
        if !organization_policy.validate() {
            return denied(
                input.policy_version,
                DecisionReasonCode::PolicySchemaInvalid,
                Some(summary),
            );
        }
        if !organization_policy.allows_tool(&input.call.tool_id) {
            return denied(
                input.policy_version,
                DecisionReasonCode::OrgToolDenied,
                Some(summary),
            );
        }
    } else if let Some(organization_policy) = input.organization_policy.as_ref()
        && !organization_policy.validate()
    {
        return denied(
            input.policy_version,
            DecisionReasonCode::PolicySchemaInvalid,
            Some(summary),
        );
    }

    if let Some(project_policy) = input.project_policy.as_ref() {
        if !project_policy.validate() {
            return denied(
                input.policy_version,
                DecisionReasonCode::PolicySchemaInvalid,
                Some(summary),
            );
        }
        if !project_policy.allows_tool(&input.call.tool_id) {
            return denied(
                input.policy_version,
                DecisionReasonCode::ProjectToolDenied,
                Some(summary),
            );
        }
    }

    if !input.agent.validate() {
        return denied(
            input.policy_version,
            DecisionReasonCode::PolicySchemaInvalid,
            Some(summary),
        );
    }

    if !input.agent.allowed_tool_ids.contains(&input.call.tool_id) {
        return denied(
            input.policy_version,
            DecisionReasonCode::AgentToolNotAllowed,
            Some(summary),
        );
    }

    if !input.runtime.validate() {
        return denied(
            input.policy_version,
            DecisionReasonCode::PolicySchemaInvalid,
            Some(summary),
        );
    }

    let definition = input.catalog.tool(&input.call.tool_id);
    let Some(definition) = definition else {
        // A privileged unknown tool is never allowed to inherit an approval or
        // rely on a client-provided risk class. Local personal mode can only
        // use the narrow read-only compatibility case.
        if input.mode == ExecutionMode::ManagedOrganization || input.call.risk_class.is_privileged()
        {
            let reason = if input.call.risk_class == RiskClass::Mcp {
                DecisionReasonCode::McpToolRequiresReview
            } else {
                DecisionReasonCode::ToolNotFound
            };
            return denied(input.policy_version, reason, Some(summary));
        }
        return finish_unknown_without_catalog(input, &summary, input.call.risk_class);
    };

    if !definition.validate() || definition.tool_id != input.call.tool_id {
        return denied(
            input.policy_version,
            DecisionReasonCode::ToolNotFound,
            Some(summary),
        );
    }
    if !definition.lifecycle.allows_execution() {
        let reason = if definition.lifecycle == ToolLifecycle::Review
            && definition.mcp_registration_id.is_some()
        {
            DecisionReasonCode::McpToolRequiresReview
        } else {
            DecisionReasonCode::ToolInactive
        };
        return denied(input.policy_version, reason, Some(summary));
    }
    if definition.source != ToolSource::BuiltIn && definition.mcp_registration_id.is_none() {
        return denied(
            input.policy_version,
            DecisionReasonCode::McpToolRequiresReview,
            Some(summary),
        );
    }
    if definition.risk_class != input.call.risk_class {
        return denied(
            input.policy_version,
            DecisionReasonCode::ToolRiskClassMismatch,
            Some(summary),
        );
    }
    if definition.capability_ids != input.call.capability_ids {
        return denied(
            input.policy_version,
            DecisionReasonCode::ToolCapabilityMismatch,
            Some(summary),
        );
    }
    if definition.fingerprint != input.call.tool_fingerprint {
        return denied(
            input.policy_version,
            DecisionReasonCode::ToolFingerprintChanged,
            Some(summary),
        );
    }

    let mut required_capabilities = definition.capability_ids.clone();
    required_capabilities.extend(input.agent.required_capability_ids.iter().cloned());
    if input.call.browser_action.is_some() && !has_browser_capability(&definition.capability_ids) {
        required_capabilities.insert(BROWSER_CAPABILITY_ID.to_owned());
    }
    if input.call.computer_action.is_some() && !has_computer_capability(&definition.capability_ids)
    {
        required_capabilities.insert(COMPUTER_CAPABILITY_ID.to_owned());
    }

    if input.mode == ExecutionMode::ManagedOrganization
        && !capabilities_are_catalogued(input, &required_capabilities)
    {
        return denied(
            input.policy_version,
            DecisionReasonCode::CapabilityNotDefined,
            Some(summary),
        );
    }
    if !input.runtime.supports_all(&required_capabilities) {
        return denied(
            input.policy_version,
            DecisionReasonCode::RuntimeCapabilityUnavailable,
            Some(summary),
        );
    }

    if let Some(mcp_id) = definition.mcp_registration_id.as_deref() {
        if input.platform.denied_mcp_ids.contains(mcp_id) {
            return denied(
                input.policy_version,
                DecisionReasonCode::PlatformHardDeny,
                Some(summary),
            );
        }
        if !mcp_allowed_by_layers(input, mcp_id) {
            return denied(
                input.policy_version,
                DecisionReasonCode::McpSourceNotAllowed,
                Some(summary),
            );
        }
        let Some(registration) = input.catalog.mcp_registrations.get(mcp_id) else {
            return denied(
                input.policy_version,
                DecisionReasonCode::McpToolRequiresReview,
                Some(summary),
            );
        };
        if !registration.validate()
            || registration.mcp_id != mcp_id
            || !sources_match(definition.source, registration.source)
        {
            return denied(
                input.policy_version,
                DecisionReasonCode::McpToolRequiresReview,
                Some(summary),
            );
        }
        if !matches!(registration.policy_status, McpPolicyStatus::Approved) {
            let reason = if matches!(
                registration.policy_status,
                McpPolicyStatus::Denied | McpPolicyStatus::Disabled | McpPolicyStatus::Revoked
            ) {
                DecisionReasonCode::McpSourceNotAllowed
            } else {
                DecisionReasonCode::McpToolRequiresReview
            };
            return denied(input.policy_version, reason, Some(summary));
        }
        if !registration
            .current_tool_fingerprints
            .contains(&input.call.tool_fingerprint)
        {
            return denied(
                input.policy_version,
                DecisionReasonCode::ToolFingerprintChanged,
                Some(summary),
            );
        }
        if !registration
            .reviewed_tool_fingerprints
            .contains(&input.call.tool_fingerprint)
        {
            return denied(
                input.policy_version,
                DecisionReasonCode::McpToolRequiresReview,
                Some(summary),
            );
        }
    }

    let mut approval_mode = effective_approval_mode(input, definition.risk_class);
    if let Some(result) = evaluate_browser_rules(input) {
        match result {
            Ok(mode) => approval_mode = approval_mode.most_restrictive(mode),
            Err(reason) => return denied(input.policy_version, reason, Some(summary)),
        }
    }
    if let Some(result) = evaluate_computer_rules(input) {
        match result {
            Ok(mode) => approval_mode = approval_mode.most_restrictive(mode),
            Err(reason) => return denied(input.policy_version, reason, Some(summary)),
        }
    }

    finish_known_tool(input, definition, &summary, approval_mode)
}

/// Explicit name for callers that prefer the domain operation over the short
/// `evaluate` name.
pub fn evaluate_tool_policy(input: &PolicyEvaluationInput) -> ToolPolicyDecision {
    evaluate(input)
}

/// Redact and canonicalize a risk-relevant argument summary. The input is
/// expected to be metadata such as `domain=example.test; operation=submit`,
/// not a raw prompt, request body, secret, or arbitrary URL. Malformed or
/// oversized input fails closed at the decision boundary.
pub fn redact_argument_summary(raw: &str) -> Result<String, ArgumentSummaryError> {
    if raw.len() > MAX_ARGUMENT_SUMMARY_INPUT_LEN {
        return Err(ArgumentSummaryError::TooLong);
    }
    if raw.chars().any(char::is_control) {
        return Err(ArgumentSummaryError::ControlCharacter);
    }
    if raw.is_empty() {
        return Ok(String::new());
    }
    if raw.trim() != raw {
        return Err(ArgumentSummaryError::Malformed);
    }

    let mut fields = Vec::new();
    for part in raw.split(';') {
        let part = part.trim();
        if part.is_empty() {
            return Err(ArgumentSummaryError::Malformed);
        }
        if fields.len() >= MAX_ARGUMENT_FIELDS {
            return Err(ArgumentSummaryError::TooManyFields);
        }
        let Some((key, value)) = part.split_once('=') else {
            return Err(ArgumentSummaryError::Malformed);
        };
        let key = key.trim();
        let value = value.trim();
        if !valid_summary_key(key) {
            return Err(ArgumentSummaryError::Malformed);
        }
        let normalized_key = key.to_ascii_lowercase();
        if fields
            .iter()
            .any(|(existing, _): &(String, String)| existing == &normalized_key)
        {
            return Err(ArgumentSummaryError::DuplicateField);
        }
        let normalized_value = if is_sensitive_key(&normalized_key) {
            REDACTED.to_owned()
        } else {
            redact_summary_value(value)
        };
        fields.push((normalized_key, normalized_value));
    }
    fields.sort_by(|left, right| left.0.cmp(&right.0));
    let output = fields
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(";");
    if output.len() > MAX_ARGUMENT_SUMMARY_LEN {
        return Err(ArgumentSummaryError::OutputTooLong);
    }
    Ok(output)
}

const REDACTED: &str = "[redacted]";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgumentSummaryError {
    TooLong,
    OutputTooLong,
    ControlCharacter,
    Malformed,
    DuplicateField,
    TooManyFields,
}

impl fmt::Display for ArgumentSummaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLong => "argument summary is too long",
            Self::OutputTooLong => "redacted argument summary is too long",
            Self::ControlCharacter => "argument summary contains a control character",
            Self::Malformed => "argument summary is malformed",
            Self::DuplicateField => "argument summary contains a duplicate field",
            Self::TooManyFields => "argument summary contains too many fields",
        })
    }
}

impl std::error::Error for ArgumentSummaryError {}

fn denied(
    policy_version: i64,
    code: DecisionReasonCode,
    arguments_summary: Option<String>,
) -> ToolPolicyDecision {
    ToolPolicyDecision {
        decision: ToolDecision::Deny,
        reason: DecisionReason::new(code),
        policy_version,
        arguments_summary,
        approval_binding: None,
    }
}

fn finish_known_tool(
    input: &PolicyEvaluationInput,
    definition: &ToolDefinition,
    summary: &str,
    approval_mode: ApprovalMode,
) -> ToolPolicyDecision {
    let decision = ToolDecision::from_approval_mode(approval_mode);
    let approval_binding = if decision.requires_approval() {
        Some(ApprovalBinding {
            tool_call_id: input.call.tool_call_id.clone(),
            tool_id: definition.tool_id.clone(),
            tool_fingerprint: definition.fingerprint.clone(),
            capability_ids: definition.capability_ids.clone(),
            risk_class: definition.risk_class,
            browser_action: input.call.browser_action.clone(),
            computer_action: input.call.computer_action.clone(),
            arguments_summary: summary.to_owned(),
        })
    } else {
        None
    };
    ToolPolicyDecision {
        decision,
        reason: DecisionReason::new(if decision.requires_approval() {
            DecisionReasonCode::ApprovalRequired
        } else {
            DecisionReasonCode::PolicyAllowed
        }),
        policy_version: input.policy_version,
        arguments_summary: Some(summary.to_owned()),
        approval_binding,
    }
}

fn effective_approval_mode(input: &PolicyEvaluationInput, risk_class: RiskClass) -> ApprovalMode {
    let mut mode = risk_class.minimum_approval_mode();
    if let Some(organization_policy) = input.organization_policy.as_ref() {
        mode = mode.most_restrictive(organization_policy.approval_for(&input.call.tool_id));
    }
    if let Some(project_policy) = input.project_policy.as_ref() {
        mode = mode.most_restrictive(project_policy.approval_for(&input.call.tool_id));
    }
    mode
}

fn finish_unknown_without_catalog(
    input: &PolicyEvaluationInput,
    summary: &str,
    risk_class: RiskClass,
) -> ToolPolicyDecision {
    let mut approval_mode = effective_approval_mode(input, risk_class);
    if let Some(result) = evaluate_browser_rules(input) {
        match result {
            Ok(mode) => approval_mode = approval_mode.most_restrictive(mode),
            Err(reason) => return denied(input.policy_version, reason, Some(summary.to_owned())),
        }
    }
    if let Some(result) = evaluate_computer_rules(input) {
        match result {
            Ok(mode) => approval_mode = approval_mode.most_restrictive(mode),
            Err(reason) => return denied(input.policy_version, reason, Some(summary.to_owned())),
        }
    }
    let decision = ToolDecision::from_approval_mode(approval_mode);
    let binding = if decision.requires_approval() {
        Some(ApprovalBinding {
            tool_call_id: input.call.tool_call_id.clone(),
            tool_id: input.call.tool_id.clone(),
            tool_fingerprint: input.call.tool_fingerprint.clone(),
            capability_ids: input.call.capability_ids.clone(),
            risk_class,
            browser_action: input.call.browser_action.clone(),
            computer_action: input.call.computer_action.clone(),
            arguments_summary: summary.to_owned(),
        })
    } else {
        None
    };
    ToolPolicyDecision {
        decision,
        reason: DecisionReason::new(if decision.requires_approval() {
            DecisionReasonCode::ApprovalRequired
        } else {
            DecisionReasonCode::PolicyAllowed
        }),
        policy_version: input.policy_version,
        arguments_summary: Some(summary.to_owned()),
        approval_binding: binding,
    }
}

fn platform_denies(input: &PolicyEvaluationInput) -> bool {
    input.platform.denied_tool_ids.contains(&input.call.tool_id)
        || input
            .platform
            .denied_capability_ids
            .iter()
            .any(|capability| input.call.capability_ids.contains(capability))
        || input
            .platform
            .denied_risk_classes
            .contains(&input.call.risk_class)
        || input
            .catalog
            .tool(&input.call.tool_id)
            .and_then(|tool| tool.mcp_registration_id.as_deref())
            .is_some_and(|mcp_id| input.platform.denied_mcp_ids.contains(mcp_id))
}

fn valid_call_metadata(call: &ToolCall) -> bool {
    valid_metadata_id(&call.tool_call_id, MAX_TOOL_ID_LEN)
        && valid_metadata_id(&call.tool_id, MAX_TOOL_ID_LEN)
        && valid_fingerprint(&call.tool_fingerprint)
        && valid_capability_set(&call.capability_ids)
        && call
            .browser_action
            .as_ref()
            .is_none_or(|action| valid_domain(action.domain()))
        && call
            .computer_action
            .as_ref()
            .is_none_or(|action| valid_application(action.application()))
}

fn capabilities_are_catalogued(
    input: &PolicyEvaluationInput,
    required_capabilities: &BTreeSet<String>,
) -> bool {
    required_capabilities.iter().all(|capability| {
        input
            .catalog
            .capability_definitions
            .get(capability)
            .is_some_and(|definition| {
                definition.capability_id == *capability
                    && definition.validate()
                    && definition.lifecycle.is_active()
            })
    })
}

fn mcp_allowed_by_layers(input: &PolicyEvaluationInput, mcp_id: &str) -> bool {
    let organization_allowed = input
        .organization_policy
        .as_ref()
        .is_some_and(|policy| policy.allows_mcp(mcp_id));
    let project_allowed = input
        .project_policy
        .as_ref()
        .is_none_or(|policy| policy.allows_mcp(mcp_id));
    organization_allowed && project_allowed
}

fn sources_match(tool_source: ToolSource, mcp_source: McpSource) -> bool {
    matches!(
        (tool_source, mcp_source),
        (ToolSource::BuiltIn, McpSource::BuiltIn)
            | (ToolSource::Plugin, McpSource::Plugin)
            | (ToolSource::Custom, McpSource::Custom)
    )
}

/// Returns `None` when the call is not browser-shaped and therefore no browser
/// policy rule applies. If an action is present, it is always evaluated; a
/// caller cannot use a non-browser risk label to bypass a browser deny.
fn evaluate_browser_rules(
    input: &PolicyEvaluationInput,
) -> Option<Result<ApprovalMode, DecisionReasonCode>> {
    let definition = input.catalog.tool(&input.call.tool_id);
    let browser_capability =
        definition.is_some_and(|tool| has_browser_capability(&tool.capability_ids));
    let browser_shaped = input.call.risk_class == RiskClass::Browser || browser_capability;
    if input.call.browser_action.is_none() {
        return browser_shaped.then_some(Err(DecisionReasonCode::BrowserActionDenied));
    }
    if input.call.computer_action.is_some() {
        return Some(Err(DecisionReasonCode::BrowserActionDenied));
    }

    let policy = effective_browser_policy(input);
    let action = input.call.browser_action.as_ref()?;
    let Some(domain) = normalize_domain(action.domain()) else {
        return Some(Err(DecisionReasonCode::BrowserActionDenied));
    };
    if !domain_allowed(&domain, &policy.allowed_domains, &policy.blocked_domains) {
        return Some(Err(DecisionReasonCode::BrowserActionDenied));
    }
    let permitted = match action {
        BrowserAction::Visit { .. } => true,
        BrowserAction::Download { .. } => policy.allow_download,
        BrowserAction::Upload { .. } => policy.allow_upload,
        BrowserAction::Authenticated { .. } => policy.allow_authenticated,
        BrowserAction::Clipboard { .. } => policy.allow_clipboard,
        BrowserAction::ExternalSubmit { .. } => match policy.external_submit {
            ExternalSubmitPolicy::Deny => false,
            ExternalSubmitPolicy::Allow
            | ExternalSubmitPolicy::SessionApproval
            | ExternalSubmitPolicy::PerUseApproval => true,
        },
    };
    if !permitted {
        return Some(Err(DecisionReasonCode::BrowserActionDenied));
    }
    let approval = match action {
        BrowserAction::ExternalSubmit { .. } => match policy.external_submit {
            ExternalSubmitPolicy::Deny => {
                return Some(Err(DecisionReasonCode::BrowserActionDenied));
            }
            ExternalSubmitPolicy::Allow => ApprovalMode::None,
            ExternalSubmitPolicy::SessionApproval => ApprovalMode::Session,
            ExternalSubmitPolicy::PerUseApproval => ApprovalMode::PerUse,
        },
        _ => ApprovalMode::None,
    };
    Some(Ok(approval))
}

fn evaluate_computer_rules(
    input: &PolicyEvaluationInput,
) -> Option<Result<ApprovalMode, DecisionReasonCode>> {
    let definition = input.catalog.tool(&input.call.tool_id);
    let computer_capability =
        definition.is_some_and(|tool| has_computer_capability(&tool.capability_ids));
    let computer_shaped = input.call.risk_class == RiskClass::Computer || computer_capability;
    if input.call.computer_action.is_none() {
        return computer_shaped.then_some(Err(DecisionReasonCode::ComputerActionDenied));
    }
    if input.call.browser_action.is_some() {
        return Some(Err(DecisionReasonCode::ComputerActionDenied));
    }
    let policy = effective_computer_policy(input);
    let action = input.call.computer_action.as_ref()?;
    let Some(application) = normalize_application(action.application()) else {
        return Some(Err(DecisionReasonCode::ComputerActionDenied));
    };
    if !policy
        .allowed_applications
        .iter()
        .any(|allowed| normalize_application(allowed).as_deref() == Some(application.as_str()))
    {
        return Some(Err(DecisionReasonCode::ComputerActionDenied));
    }
    let permitted = match action {
        ComputerAction::Accessibility { .. } => policy.allow_accessibility,
        ComputerAction::ScreenCapture { .. } => policy.allow_screen_capture,
        ComputerAction::KeyboardMouse { .. } => policy.allow_keyboard_mouse,
        ComputerAction::ShellEscalation { .. } => policy.allow_shell_escalation,
    };
    if !permitted {
        return Some(Err(DecisionReasonCode::ComputerActionDenied));
    }
    Some(Ok(action.minimum_approval_mode()))
}

fn effective_browser_policy(input: &PolicyEvaluationInput) -> BrowserPolicy {
    let mut layers = input
        .organization_policy
        .iter()
        .chain(input.project_policy.iter());
    let Some(first) = layers.next() else {
        return BrowserPolicy::default();
    };
    let mut effective = first.browser.clone();
    for layer in layers {
        effective = effective.intersection(&layer.browser);
    }
    effective
}

fn effective_computer_policy(input: &PolicyEvaluationInput) -> ComputerPolicy {
    let mut layers = input
        .organization_policy
        .iter()
        .chain(input.project_policy.iter());
    let Some(first) = layers.next() else {
        return ComputerPolicy::default();
    };
    let mut effective = first.computer.clone();
    for layer in layers {
        effective = effective.intersection(&layer.computer);
    }
    effective
}

fn has_browser_capability(capabilities: &BTreeSet<String>) -> bool {
    has_capability(capabilities, BROWSER_CAPABILITY_ID)
        || capabilities.contains("browser_use")
        || capabilities.contains("cap_browser_use")
}

fn has_computer_capability(capabilities: &BTreeSet<String>) -> bool {
    has_capability(capabilities, COMPUTER_CAPABILITY_ID)
        || capabilities.contains("computer_use")
        || capabilities.contains("cap_computer_use")
}

fn has_capability(capabilities: &BTreeSet<String>, expected: &str) -> bool {
    capabilities.iter().any(|capability| {
        capability == expected || capability.strip_prefix("cap_") == Some(expected)
    })
}

fn valid_metadata_id(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.trim() == value
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || byte == b'.'
        })
}

fn valid_fingerprint(value: &str) -> bool {
    valid_metadata_id(value, MAX_FINGERPRINT_LEN)
}

fn valid_capability_id(value: &str) -> bool {
    valid_metadata_id(value, MAX_CAPABILITY_ID_LEN)
}

fn valid_id_set(values: &BTreeSet<String>, max_len: usize) -> bool {
    values.iter().all(|value| valid_metadata_id(value, max_len))
}

fn valid_fingerprint_set(values: &BTreeSet<String>) -> bool {
    values.iter().all(|value| valid_fingerprint(value))
}

fn valid_capability_set(values: &BTreeSet<String>) -> bool {
    values.len() <= MAX_CAPABILITY_IDS && values.iter().all(|value| valid_capability_id(value))
}

fn valid_domain_set(values: &BTreeSet<String>) -> bool {
    values.iter().all(|value| normalize_domain(value).is_some())
}

fn valid_application_set(values: &BTreeSet<String>) -> bool {
    values
        .iter()
        .all(|value| normalize_application(value).is_some())
}

fn valid_domain(value: &str) -> bool {
    normalize_domain(value).is_some()
}

fn valid_application(value: &str) -> bool {
    normalize_application(value).is_some()
}

fn normalize_domain(value: &str) -> Option<String> {
    let value = value
        .strip_suffix('.')
        .unwrap_or(value)
        .to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || value.contains('/')
        || value.contains('@')
        || value.contains(':')
        || value.chars().any(char::is_control)
    {
        return None;
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Some(value);
    }
    if value.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return None;
    }
    Some(value)
}

fn domain_allowed(
    domain: &str,
    allowed_domains: &BTreeSet<String>,
    blocked_domains: &BTreeSet<String>,
) -> bool {
    let blocked_matches = |candidate: &str| {
        normalize_domain(candidate).is_some_and(|normalized| {
            domain == normalized
                || domain
                    .strip_suffix(&normalized)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
    };
    let allowed_matches = |candidate: &str| {
        normalize_domain(candidate).is_some_and(|normalized| domain == normalized)
    };
    !blocked_domains
        .iter()
        .any(|blocked| blocked_matches(blocked))
        && allowed_domains
            .iter()
            .any(|allowed| allowed_matches(allowed))
}

fn normalize_application(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(char::is_control)
        || value.contains('/')
        || value.contains('\\')
    {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn intersect_sets<T: Ord + Clone>(left: &BTreeSet<T>, right: &BTreeSet<T>) -> BTreeSet<T> {
    left.intersection(right).cloned().collect()
}

fn union_sets<T: Ord + Clone>(left: &BTreeSet<T>, right: &BTreeSet<T>) -> BTreeSet<T> {
    left.union(right).cloned().collect()
}

fn valid_summary_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 64
        && key
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        && key.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || byte == b'.'
        })
}

fn is_sensitive_key(key: &str) -> bool {
    [
        "secret",
        "token",
        "password",
        "passwd",
        "authorization",
        "auth",
        "cookie",
        "credential",
        "api_key",
        "private",
        "prompt",
        "response",
        "content",
        "body",
        "raw",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

fn redact_summary_value(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    if value.contains("://") {
        return redact_url_value(value);
    }
    if value.len() > 128 || value.chars().any(char::is_whitespace) || looks_sensitive_value(value) {
        return REDACTED.to_owned();
    }
    if value.bytes().all(is_summary_value_byte) {
        value.to_owned()
    } else {
        REDACTED.to_owned()
    }
}

fn redact_url_value(value: &str) -> String {
    let Some((scheme, rest)) = value.split_once("://") else {
        return REDACTED.to_owned();
    };
    if scheme.is_empty()
        || !scheme.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'-' || byte == b'.'
        })
    {
        return REDACTED.to_owned();
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let Some(normalized_host) = normalize_domain(host) else {
        return REDACTED.to_owned();
    };
    if looks_sensitive_value(&normalized_host) {
        return REDACTED.to_owned();
    }
    let suffix = if rest[authority_end..].contains('/') {
        "/[redacted]"
    } else {
        ""
    };
    format!("{scheme}://{normalized_host}{suffix}")
}

fn looks_sensitive_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("bearer ")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("token")
        || lower.starts_with("sk_")
        || lower.starts_with("ghp_")
        || lower.starts_with("xox")
}

fn is_summary_value_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b' ' | b'_'
                | b'-'
                | b'.'
                | b':'
                | b'/'
                | b'?'
                | b'#'
                | b'['
                | b']'
                | b'@'
                | b'!'
                | b'$'
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b'='
                | b'%'
                | b'&'
                | b'\''
                | b'~'
        )
}

#[cfg(test)]
#[path = "tool_policy_tests.rs"]
mod tool_policy_tests;
