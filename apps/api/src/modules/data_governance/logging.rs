//! Content logging modes and the field-level logging allowlist.
//!
//! Why this is an allowlist and not a denylist: F20-002 permits three modes,
//! and the gate is explicit that "raw prompts, responses, tool arguments,
//! credentials, and secrets remain prohibited in all modes". A denylist fails
//! open for every field nobody thought about, so classification here starts
//! from the gate's own enumeration — "IDs, versions, state, counts, bounded
//! reason codes, and timing" — and treats everything else as prohibited.
//!
//! Three properties this module guarantees, each with a test:
//!
//! 1. [`LoggingMode::default`] is `metadata_only`, the gate's default for
//!    inference and control-plane observability.
//! 2. No field is loggable in `full_content` that is not already loggable in
//!    `metadata_only`, except an explicitly redacted diagnostic excerpt. A
//!    mode raises diagnostic detail; it never raises a prohibition. Concretely,
//!    no registry class reaches `full_content`: the gate prohibits raw content
//!    "in all modes", so `full_content` is a diagnostic setting that widens no
//!    class's field allowlist at all.
//! 3. A mode never changes a schema. `full_content` is an audited, time-bounded
//!    diagnostic setting, so [`LoggingPolicy::changes_schema`] is unconditionally
//!    `false`: the P01/P05 event, audit, webhook, and log schemas are not
//!    mode-dependent, and a field that does not exist in those schemas is
//!    prohibited in every mode.
//!
//! A per-class ceiling ([`LoggingRule`]) sits below the tenant mode. The
//! registry declares the widest mode a class may ever be logged under, so an
//! org cannot use a permissive `full_content` policy to make a secret-bearing
//! class loggable.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::retention::RetentionDuration;

/// Longest logging-mode window an org may enable. `full_content` is a
/// diagnostic setting with a reviewable end, never a standing mode.
pub const MAX_FULL_CONTENT_WINDOW_SECONDS: u64 = 7 * RetentionDuration::SECONDS_PER_DAY;

/// Longest field name classification accepts. Field names are wire metadata,
/// not content, and stay small enough to match cheaply.
pub const MAX_FIELD_NAME_LEN: usize = 64;

/// Longest audit justification a mode change may carry.
pub const MAX_MODE_CHANGE_REASON_LEN: usize = 512;

/// Tenant-scoped content logging mode. `metadata_only` is the default.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum LoggingMode {
    #[default]
    MetadataOnly,
    RedactedContent,
    FullContent,
}

impl LoggingMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MetadataOnly => "metadata_only",
            Self::RedactedContent => "redacted_content",
            Self::FullContent => "full_content",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "metadata_only" => Some(Self::MetadataOnly),
            "redacted_content" => Some(Self::RedactedContent),
            "full_content" => Some(Self::FullContent),
            _ => None,
        }
    }

    pub const fn is_default(self) -> bool {
        matches!(self, Self::MetadataOnly)
    }

    /// Rank used to compare the active mode against a required mode.
    const fn rank(self) -> u8 {
        match self {
            Self::MetadataOnly => 0,
            Self::RedactedContent => 1,
            Self::FullContent => 2,
        }
    }

    pub const fn allows(self, required: Self) -> bool {
        self.rank() >= required.rank()
    }
}

impl fmt::Display for LoggingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a field cannot be logged. These are the gate's prohibitions, kept
/// explicit so a diagnostic reader can tell a deliberate prohibition from an
/// unregistered field name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProhibitionReason {
    /// Raw prompt text.
    RawPrompt,
    /// Raw model response text.
    RawResponse,
    /// Raw tool-call arguments.
    RawToolArgument,
    /// Credential or token material.
    CredentialValue,
    /// Secret or key material.
    SecretValue,
    /// An authorization or cookie header.
    AuthorizationHeader,
    /// Export artifact content.
    ExportContent,
    /// A field that is not on any allowlist.
    UnregisteredField,
    /// The class's declared logging rule forbids any content.
    ClassRuleNever,
    /// The class's declared logging rule is narrower than the current mode.
    ClassRuleNarrower,
    /// The field needs a mode the tenant has not enabled.
    ModeInsufficient,
}

impl ProhibitionReason {
    pub const fn code(self) -> &'static str {
        match self {
            Self::RawPrompt => "logging_raw_prompt_prohibited",
            Self::RawResponse => "logging_raw_response_prohibited",
            Self::RawToolArgument => "logging_raw_tool_argument_prohibited",
            Self::CredentialValue => "logging_credential_prohibited",
            Self::SecretValue => "logging_secret_prohibited",
            Self::AuthorizationHeader => "logging_authorization_header_prohibited",
            Self::ExportContent => "logging_export_content_prohibited",
            Self::UnregisteredField => "logging_field_unregistered",
            Self::ClassRuleNever => "logging_class_rule_never",
            Self::ClassRuleNarrower => "logging_class_rule_narrower",
            Self::ModeInsufficient => "logging_mode_insufficient",
        }
    }
}

/// How a field classifies. `Prohibited` is the fail-closed default: a caller
/// that has never heard of a field still cannot log it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FieldClass {
    /// Identifier, version, state, count, bounded reason code, or timing.
    Metadata,
    /// An explicitly redacted diagnostic excerpt. Only valid under
    /// `redacted_content` or `full_content`.
    RedactedExcerpt,
    /// Never loggable in any mode.
    Prohibited(ProhibitionReason),
}

impl FieldClass {
    pub const fn required_mode(self) -> Option<LoggingMode> {
        match self {
            Self::Metadata => Some(LoggingMode::MetadataOnly),
            Self::RedactedExcerpt => Some(LoggingMode::RedactedContent),
            Self::Prohibited(_) => None,
        }
    }
}

/// Fields `metadata_only` may carry: identifiers, versions, state, counts,
/// bounded reason codes, timing, and the non-secret capability/route/licence
/// status the gate already exposes in policy and license responses.
///
/// This is an allowlist on purpose. Adding a name here is a reviewed change,
/// not a side effect of adding a struct field somewhere else.
pub const METADATA_FIELD_ALLOWLIST: &[&str] = &[
    // Identifiers.
    "request_id",
    "correlation_id",
    "event_id",
    "org_id",
    "project_id",
    "user_id",
    "device_id",
    "session_id",
    "run_id",
    "occurrence_id",
    "lease_id",
    "automation_id",
    "endpoint_id",
    "delivery_id",
    "export_id",
    "deletion_id",
    "notification_id",
    "subscription_id",
    "grant_id",
    "policy_id",
    "job_id",
    "artifact_ref_id",
    "provider_id",
    "membership_id",
    // Versions and counters.
    "schema_version",
    "resource_version",
    "state_version",
    "policy_version",
    "schedule_rule_version",
    "version",
    "attempt",
    "item_count",
    "member_count",
    "over_limit_count",
    "batch_size",
    "dead_letter_count",
    // State and bounded reason codes.
    "state",
    "status",
    "outcome",
    "off_peak_mode",
    "disposition",
    "reason_code",
    "failure_code",
    "skip_reason",
    "error_code",
    "destinations",
    // Timing.
    "duration_ms",
    "latency_ms",
    "scheduled_for",
    "expires_at",
    "requested_at",
    "accepted_at",
    "next_attempt_at",
    "occurred_at",
    "created_at",
    "updated_at",
    "placed_at",
    "released_at",
    "cutoff_at",
    "ready_at",
    "completed_at",
    // Non-secret capability, routing, and commercial status.
    "capability",
    "platform",
    "app_version",
    "plan_key",
    "entitlement_key",
    "entitlement_source",
    "license_key_id",
    "secret_version",
    "offline_valid_until",
    "policy_fresh_until",
    "provider_status",
    "subscription_status",
    "deliverable",
];

/// Fields `redacted_content` may add. Every name must start with `redacted_`,
/// which [`classify_field`] enforces, so an unredacted body cannot be
/// registered as a "redacted" excerpt by accident.
pub const REDACTED_EXCERPT_FIELD_ALLOWLIST: &[&str] = &[
    "redacted_reason_excerpt",
    "redacted_error_summary",
    "redacted_diagnostic_excerpt",
    "redacted_subject_summary",
];

/// Names prohibited by rule even though they look like metadata.
///
/// Defence in depth: the allowlist already rejects them, and the explicit
/// mapping gives a stable reason code instead of a generic "unregistered", so
/// an operator can tell a policy decision from a typo.
const EXPLICIT_PROHIBITIONS: &[(&str, ProhibitionReason)] = &[
    ("prompt", ProhibitionReason::RawPrompt),
    ("prompts", ProhibitionReason::RawPrompt),
    ("system_prompt", ProhibitionReason::RawPrompt),
    ("prompt_text", ProhibitionReason::RawPrompt),
    ("response", ProhibitionReason::RawResponse),
    ("response_text", ProhibitionReason::RawResponse),
    ("completion", ProhibitionReason::RawResponse),
    ("assistant_message", ProhibitionReason::RawResponse),
    ("tool_arguments", ProhibitionReason::RawToolArgument),
    ("tool_args", ProhibitionReason::RawToolArgument),
    ("raw_arguments", ProhibitionReason::RawToolArgument),
    ("credential", ProhibitionReason::CredentialValue),
    ("credentials", ProhibitionReason::CredentialValue),
    ("api_key", ProhibitionReason::CredentialValue),
    ("access_token", ProhibitionReason::CredentialValue),
    ("refresh_token", ProhibitionReason::CredentialValue),
    ("session_token", ProhibitionReason::CredentialValue),
    ("password", ProhibitionReason::CredentialValue),
    ("ciphertext", ProhibitionReason::SecretValue),
    ("secret", ProhibitionReason::SecretValue),
    ("secret_value", ProhibitionReason::SecretValue),
    ("webhook_secret", ProhibitionReason::SecretValue),
    ("signing_key", ProhibitionReason::SecretValue),
    ("private_key", ProhibitionReason::SecretValue),
    ("authorization", ProhibitionReason::AuthorizationHeader),
    (
        "authorization_header",
        ProhibitionReason::AuthorizationHeader,
    ),
    ("cookie", ProhibitionReason::AuthorizationHeader),
    ("export_content", ProhibitionReason::ExportContent),
    ("artifact_content", ProhibitionReason::ExportContent),
    ("artifact_body", ProhibitionReason::ExportContent),
];

/// Classify a wire field name for logging.
///
/// Fails closed: an unregistered, oversized, or non-snake_case name is
/// `Prohibited(UnregisteredField)`, never `Metadata`.
pub fn classify_field(name: &str) -> FieldClass {
    if name.is_empty() || name.len() > MAX_FIELD_NAME_LEN || !is_snake_case(name) {
        return FieldClass::Prohibited(ProhibitionReason::UnregisteredField);
    }
    if let Some((_, reason)) = EXPLICIT_PROHIBITIONS
        .iter()
        .find(|(prohibited, _)| *prohibited == name)
    {
        return FieldClass::Prohibited(*reason);
    }
    if METADATA_FIELD_ALLOWLIST.contains(&name) {
        return FieldClass::Metadata;
    }
    if REDACTED_EXCERPT_FIELD_ALLOWLIST.contains(&name) {
        // A redacted excerpt must be redacted in the name itself; otherwise the
        // name is an attempt to smuggle a body past the allowlist.
        return if name.starts_with("redacted_") {
            FieldClass::RedactedExcerpt
        } else {
            FieldClass::Prohibited(ProhibitionReason::UnregisteredField)
        };
    }
    FieldClass::Prohibited(ProhibitionReason::UnregisteredField)
}

fn is_snake_case(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.first().is_some_and(u8::is_ascii_uppercase) {
        return false;
    }
    let mut previous_underscore = true;
    for byte in bytes {
        match byte {
            b'_' => {
                if previous_underscore {
                    return false;
                }
                previous_underscore = true;
            }
            _ if byte.is_ascii_lowercase() || byte.is_ascii_digit() => previous_underscore = false,
            _ => return false,
        }
    }
    !previous_underscore
}

/// The per-class logging ceiling declared in the data-class registry.
///
/// This is narrower than a tenant mode on purpose: a class whose logging rule
/// is `ids_status` may never carry a body, whatever the org has enabled.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum LoggingRule {
    /// IDs, versions, state, counts, bounded reason codes, timing.
    #[default]
    MetadataOnly,
    /// A tighter subset: status/state only.
    StatusOnly,
    /// The gate's "IDs/status only" wording for identity, device, and audit
    /// correlation rows.
    IdsStatus,
    /// Never logged in any mode, not even an identifier.
    None,
}

impl LoggingRule {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MetadataOnly => "metadata_only",
            Self::StatusOnly => "status_only",
            Self::IdsStatus => "ids_status",
            Self::None => "none",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "metadata_only" => Some(Self::MetadataOnly),
            "status_only" => Some(Self::StatusOnly),
            "ids_status" => Some(Self::IdsStatus),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    /// Widest content mode this class may ever be logged under. `None` means
    /// the class is not loggable at all.
    ///
    /// Note that nothing returns [`LoggingMode::FullContent`]. The gate
    /// prohibits raw prompts, responses, tool arguments, credentials, and
    /// secrets "in all modes", and no registry row is a place where content is
    /// acceptable. `full_content` is therefore an audited, time-bounded
    /// *diagnostic* setting for support tooling; it never widens a class's
    /// field allowlist, so the widest ceiling any class has is
    /// `redacted_content` and only for a class whose rule is `metadata_only`.
    pub const fn max_mode(self) -> Option<LoggingMode> {
        match self {
            Self::MetadataOnly => Some(LoggingMode::RedactedContent),
            Self::StatusOnly | Self::IdsStatus => Some(LoggingMode::MetadataOnly),
            Self::None => None,
        }
    }

    /// True when a field of `class` may appear under `mode` at all, ignoring
    /// whether the class's rule is narrower.
    pub const fn allows(self, mode: LoggingMode, class: FieldClass) -> bool {
        match (self.max_mode(), class.required_mode()) {
            (Some(ceiling), Some(required)) => mode.allows(required) && ceiling.allows(required),
            (Some(_), None) | (None, _) => false,
        }
    }
}

/// A fail-closed logging verdict. No rejected value is stored here, so logging
/// or formatting a decision cannot disclose a field's content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogDecision {
    pub allowed: bool,
    pub field_class: FieldClass,
    pub required_mode: Option<LoggingMode>,
    pub active_mode: LoggingMode,
}

impl LogDecision {
    pub const fn denied(reason: ProhibitionReason, active_mode: LoggingMode) -> Self {
        Self {
            allowed: false,
            field_class: FieldClass::Prohibited(reason),
            required_mode: None,
            active_mode,
        }
    }

    pub const fn is_allowed(&self) -> bool {
        self.allowed
    }

    /// Stable code for a denied decision, or `None` when allowed.
    pub fn denial_code(&self) -> Option<&'static str> {
        if self.allowed {
            return None;
        }
        match self.field_class {
            FieldClass::Prohibited(reason) => Some(reason.code()),
            _ => Some(ProhibitionReason::ModeInsufficient.code()),
        }
    }
}

/// A requested logging-mode change.
///
/// `authorized` is the caller's central-permission result for `data.manage`;
/// this module never grants it. `audit_correlation_id` ties the change to the
/// F16 audit event, and `effective_until` is mandatory for `full_content`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoggingModeChange {
    pub mode: LoggingMode,
    pub authorized: bool,
    pub actor_id: String,
    pub audit_correlation_id: String,
    pub reason: String,
    pub effective_until: Option<u64>,
}

impl LoggingModeChange {
    pub fn new(
        mode: LoggingMode,
        authorized: bool,
        actor_id: impl Into<String>,
        audit_correlation_id: impl Into<String>,
        reason: impl Into<String>,
        effective_until: Option<u64>,
    ) -> Self {
        Self {
            mode,
            authorized,
            actor_id: actor_id.into(),
            audit_correlation_id: audit_correlation_id.into(),
            reason: reason.into(),
            effective_until,
        }
    }
}

/// The tenant's effective logging configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoggingPolicy {
    mode: LoggingMode,
    full_content_until: Option<u64>,
    audit_correlation_id: Option<String>,
}

impl LoggingPolicy {
    /// The frozen baseline: metadata-only, with no diagnostic window.
    pub fn metadata_only() -> Self {
        Self::default()
    }

    pub const fn mode(&self) -> LoggingMode {
        self.mode
    }

    pub const fn full_content_until(&self) -> Option<u64> {
        self.full_content_until
    }

    pub fn audit_correlation_id(&self) -> Option<&str> {
        self.audit_correlation_id.as_deref()
    }

    /// Apply a mode change.
    ///
    /// `full_content` requires all of: the `data.manage` permission result, a
    /// named actor, an audit correlation, a bounded reason, and an expiry
    /// within [`MAX_FULL_CONTENT_WINDOW_SECONDS`]. Moving back to a narrower
    /// mode always clears the diagnostic window, so returning to
    /// `metadata_only` leaves no residual `full_content` capability.
    pub fn set_mode(&mut self, change: &LoggingModeChange, now: u64) -> Result<(), LoggingError> {
        if !change.authorized {
            return Err(LoggingError::PermissionDenied);
        }
        if change.actor_id.trim().is_empty() || change.actor_id.len() > MAX_FIELD_NAME_LEN {
            return Err(LoggingError::MissingAuditIntent);
        }
        if change.audit_correlation_id.trim().is_empty()
            || change.audit_correlation_id.len() > MAX_FIELD_NAME_LEN
        {
            return Err(LoggingError::MissingAuditIntent);
        }
        let reason = change.reason.trim();
        if reason.is_empty() || reason.len() > MAX_MODE_CHANGE_REASON_LEN {
            return Err(LoggingError::MissingAuditIntent);
        }
        match change.mode {
            LoggingMode::FullContent => {
                let until = change
                    .effective_until
                    .ok_or(LoggingError::UnboundedFullContent)?;
                if until <= now || until.saturating_sub(now) > MAX_FULL_CONTENT_WINDOW_SECONDS {
                    return Err(LoggingError::FullContentWindowInvalid);
                }
                self.full_content_until = Some(until);
            }
            LoggingMode::RedactedContent => {
                if change.effective_until.is_some_and(|until| until <= now) {
                    return Err(LoggingError::RedactedWindowInvalid);
                }
                self.full_content_until = None;
            }
            LoggingMode::MetadataOnly => self.full_content_until = None,
        }
        self.mode = change.mode;
        self.audit_correlation_id = Some(change.audit_correlation_id.clone());
        Ok(())
    }

    /// A `full_content` window that has elapsed reverts to `metadata_only`
    /// rather than persisting as a standing mode.
    pub fn effective_mode_at(&self, now: u64) -> LoggingMode {
        if self.mode == LoggingMode::FullContent
            && self.full_content_until.is_none_or(|until| now >= until)
        {
            return LoggingMode::MetadataOnly;
        }
        self.mode
    }

    /// Decide whether one field may be logged, honouring both the tenant mode
    /// and the class's declared logging rule.
    pub fn allows(&self, record: &super::registry::DataClassRecord, field: &str) -> LogDecision {
        self.allows_at(record, field, 0)
    }

    pub fn allows_at(
        &self,
        record: &super::registry::DataClassRecord,
        field: &str,
        now: u64,
    ) -> LogDecision {
        let mode = self.effective_mode_at(now);
        let field_class = classify_field(field);
        let Some(required) = field_class.required_mode() else {
            // A prohibited field stays prohibited at every mode and under every
            // class rule; that is the whole point of the prohibition.
            return LogDecision {
                allowed: false,
                field_class,
                required_mode: None,
                active_mode: mode,
            };
        };
        let Some(ceiling) = record.logging.max_mode() else {
            return LogDecision::denied(ProhibitionReason::ClassRuleNever, mode);
        };
        if ceiling.allows(required) && mode.allows(required) {
            return LogDecision {
                allowed: true,
                field_class,
                required_mode: Some(required),
                active_mode: mode,
            };
        }
        // Attribute the denial to the narrower of the two limits so the reason
        // code points at the actual fix.
        let reason = if !ceiling.allows(required) {
            ProhibitionReason::ClassRuleNarrower
        } else {
            ProhibitionReason::ModeInsufficient
        };
        LogDecision {
            allowed: false,
            field_class: FieldClass::Prohibited(reason),
            required_mode: Some(required),
            active_mode: mode,
        }
    }

    /// Fail-closed convenience for callers that only need a boolean.
    pub fn is_loggable(&self, record: &super::registry::DataClassRecord, field: &str) -> bool {
        self.allows(record, field).is_allowed()
    }

    /// A logging mode never changes the P01/P05 event, audit, webhook, or log
    /// schemas. This exists so the invariant is stated once, in code, instead
    /// of only in a contract document.
    pub const fn changes_schema(&self) -> bool {
        false
    }
}

/// Logging validation failures. No variant carries a field value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LoggingError {
    PermissionDenied,
    MissingAuditIntent,
    UnboundedFullContent,
    FullContentWindowInvalid,
    RedactedWindowInvalid,
}

impl LoggingError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::PermissionDenied => "permission_denied",
            Self::MissingAuditIntent
            | Self::UnboundedFullContent
            | Self::FullContentWindowInvalid
            | Self::RedactedWindowInvalid => "data_policy_invalid",
        }
    }
}

impl fmt::Display for LoggingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for LoggingError {}
