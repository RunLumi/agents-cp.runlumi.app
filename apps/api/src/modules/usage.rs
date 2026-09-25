//! P05 usage, cost, and reconciliation domain values.
//!
//! The P04 usage row is the immutable source of accounting truth.  This module
//! keeps the P05 source/reconciliation metadata separate from that row and
//! models cost calculations as append-only records.  Nothing in this module
//! performs I/O or authorizes a caller; a route must establish the trusted
//! organization and request context before using these values.

use std::{borrow::Borrow, fmt};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

/// Maximum serialized size of a redacted provider-usage payload.
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024;
/// Domain-specific spelling for adapters that persist provider usage.
pub const MAX_USAGE_PAYLOAD_BYTES: usize = MAX_PAYLOAD_BYTES;
pub const MAX_PROVIDER_USAGE_BYTES: usize = MAX_PAYLOAD_BYTES;
/// Maximum size accepted before redaction.  This prevents a caller from
/// making the Worker spend time walking an unbounded provider response.
pub const MAX_RAW_PAYLOAD_BYTES: usize = 64 * 1024;
/// Maximum nesting depth retained in a redacted payload.
pub const MAX_PAYLOAD_DEPTH: usize = 8;
/// Maximum object members retained in a redacted payload.
pub const MAX_PAYLOAD_KEYS: usize = 64;
/// Maximum array elements retained in a redacted payload.
pub const MAX_PAYLOAD_ARRAY_ITEMS: usize = 128;
/// Maximum length of a safe metadata string retained in a redacted payload.
pub const MAX_PAYLOAD_STRING_BYTES: usize = 1_024;
/// Maximum length for identifiers and opaque correlation values.
pub const MAX_IDENTIFIER_BYTES: usize = 255;
/// Maximum length for a cost record identifier.
pub const MAX_COST_RECORD_ID_BYTES: usize = 128;

const REDACTED_VALUE: &str = "[redacted]";
const TRUNCATED_VALUE: &str = "[truncated]";
const TRUNCATED_KEY: &str = "[truncated]";

/// Errors produced while constructing or reconciling usage values.
///
/// The error deliberately contains no caller payload or provider response.  A
/// transport adapter can map `code()` to the frozen API error vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsageModelError {
    /// A required field was empty, malformed, or out of range.
    InvalidField(&'static str),
    /// A payload exceeded the bounded metadata limits.
    PayloadTooLarge,
    /// A reconciliation did not match the immutable usage identity or a prior
    /// reconciliation payload.
    ReconciliationConflict(ReconciliationConflictReason),
}

impl UsageModelError {
    /// Stable machine-readable error code for an HTTP/service boundary.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidField(_) => "invalid_usage",
            Self::PayloadTooLarge => "usage_payload_too_large",
            Self::ReconciliationConflict(_) => "usage_reconciliation_conflict",
        }
    }

    pub const fn reconciliation_reason(self) -> Option<ReconciliationConflictReason> {
        match self {
            Self::ReconciliationConflict(reason) => Some(reason),
            Self::InvalidField(_) | Self::PayloadTooLarge => None,
        }
    }
}

impl fmt::Display for UsageModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(f, "invalid usage field: {field}"),
            Self::PayloadTooLarge => f.write_str("usage payload is too large"),
            Self::ReconciliationConflict(reason) => {
                write!(f, "usage reconciliation conflict: {}", reason.as_str())
            }
        }
    }
}

impl std::error::Error for UsageModelError {}

/// The execution path that produced a usage event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageSource {
    /// A P04 inference request.  This is the compatibility default for old
    /// P04 rows that predate the P05 source column.
    #[default]
    Inference,
    /// A managed P05 run-level event.
    Run,
}

impl UsageSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inference => "inference",
            Self::Run => "run",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "inference" => Some(Self::Inference),
            "run" => Some(Self::Run),
            _ => None,
        }
    }
}

/// State of the append-only reconciliation projection for one usage event.
///
/// The raw usage event remains immutable.  A projection may be inserted once
/// and then read as `recorded`, `pending`, `reconciled`, or `conflict`; it is
/// never edited in place to hide a discrepancy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationState {
    /// The raw event is durably recorded but no reconciliation attempt has
    /// been claimed yet.  This is the additive P05 default for old/new rows.
    #[default]
    Recorded,
    Pending,
    Reconciled,
    Conflict,
}

impl ReconciliationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Pending => "pending",
            Self::Reconciled => "reconciled",
            Self::Conflict => "conflict",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "recorded" => Some(Self::Recorded),
            "pending" => Some(Self::Pending),
            "reconciled" => Some(Self::Reconciled),
            "conflict" => Some(Self::Conflict),
            _ => None,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Reconciled | Self::Conflict)
    }
}

/// Why a cost record was created.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostCalculationKind {
    Estimated,
    Actual,
    Recalculated,
}

impl CostCalculationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Estimated => "estimated",
            Self::Actual => "actual",
            Self::Recalculated => "recalculated",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "estimated" => Some(Self::Estimated),
            "actual" => Some(Self::Actual),
            "recalculated" => Some(Self::Recalculated),
            _ => None,
        }
    }
}

/// Stable, non-sensitive explanations for a reconciliation conflict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationConflictReason {
    IdentityMismatch,
    ExternalIdMismatch,
    SourceMismatch,
    TenantMismatch,
    UsageEventMismatch,
    ActualCostMismatch,
    ProviderUsageMismatch,
    PricingVersionMismatch,
    CurrencyMismatch,
    InvalidProjection,
}

impl ReconciliationConflictReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IdentityMismatch => "identity_mismatch",
            Self::ExternalIdMismatch => "external_id_mismatch",
            Self::SourceMismatch => "source_mismatch",
            Self::TenantMismatch => "tenant_mismatch",
            Self::UsageEventMismatch => "usage_event_mismatch",
            Self::ActualCostMismatch => "actual_cost_mismatch",
            Self::ProviderUsageMismatch => "provider_usage_mismatch",
            Self::PricingVersionMismatch => "pricing_version_mismatch",
            Self::CurrencyMismatch => "currency_mismatch",
            Self::InvalidProjection => "invalid_projection",
        }
    }
}

/// Compatibility names for callers that use the longer domain vocabulary.
pub type UsageError = UsageModelError;
pub type UsageReconciliationState = ReconciliationState;
pub type ReconciliationStatus = ReconciliationState;
pub type CostKind = CostCalculationKind;
pub type ReconciliationProjection = UsageReconciliation;
pub type ReconciliationDecision = ReconciliationOutcome;

/// A validated pricing catalog reference captured by a cost calculation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PricingVersion {
    pub source: String,
    pub version: String,
    pub effective_at: String,
}

impl PricingVersion {
    pub fn new(
        source: impl Into<String>,
        version: impl Into<String>,
        effective_at: impl Into<String>,
    ) -> Result<Self, UsageModelError> {
        let value = Self {
            source: source.into(),
            version: version.into(),
            effective_at: effective_at.into(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), UsageModelError> {
        required_text(&self.source, "pricing_source", 128)?;
        required_text(&self.version, "pricing_version", 128)?;
        timestamp_text(&self.effective_at, "pricing_effective_at")?;
        Ok(())
    }

    /// A price version is identified by source and version.  An effective
    /// timestamp alone must not silently create a new price identity.
    pub fn same_version(&self, other: &Self) -> bool {
        self.source == other.source && self.version == other.version
    }
}

#[derive(Deserialize)]
struct PricingVersionWire {
    source: String,
    version: String,
    effective_at: String,
}

impl<'de> Deserialize<'de> for PricingVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PricingVersionWire::deserialize(deserializer)?;
        Self::new(wire.source, wire.version, wire.effective_at).map_err(serde::de::Error::custom)
    }
}

/// A bounded, recursively redacted JSON metadata value.
///
/// The inner value is private so a provider adapter cannot accidentally place
/// raw prompt/response content into usage persistence.  Deserialization is
/// validated as well, which protects rows loaded from a less careful adapter.
#[derive(Clone)]
pub struct BoundedPayload {
    value: Value,
    encoded_bytes: usize,
}

impl PartialEq for BoundedPayload {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for BoundedPayload {}

impl BoundedPayload {
    pub fn from_value(value: &Value) -> Result<Self, UsageModelError> {
        let value = redact_payload(value)?;
        Self::from_sanitized(value)
    }

    pub fn from_json(value: &str) -> Result<Self, UsageModelError> {
        let value: Value = serde_json::from_str(value)
            .map_err(|_| UsageModelError::InvalidField("provider_usage"))?;
        Self::from_value(&value)
    }

    fn from_sanitized(value: Value) -> Result<Self, UsageModelError> {
        let encoded_bytes = serialized_len(&value)?;
        if encoded_bytes > MAX_PAYLOAD_BYTES {
            return Err(UsageModelError::PayloadTooLarge);
        }
        Ok(Self {
            value,
            encoded_bytes,
        })
    }

    pub fn as_value(&self) -> &Value {
        &self.value
    }

    pub fn into_value(self) -> Value {
        self.value
    }

    pub fn encoded_len(&self) -> usize {
        self.encoded_bytes
    }

    pub fn is_empty(&self) -> bool {
        match &self.value {
            Value::Null => true,
            Value::Object(object) => object.is_empty(),
            Value::Array(array) => array.is_empty(),
            Value::String(value) => value.is_empty(),
            _ => false,
        }
    }

    pub fn to_json_string(&self) -> Result<String, UsageModelError> {
        serde_json::to_string(&self.value).map_err(|_| UsageModelError::InvalidField("payload"))
    }
}

impl Default for BoundedPayload {
    fn default() -> Self {
        let value = Value::Object(Map::new());
        let encoded_bytes = serialized_len(&value).unwrap_or(MAX_PAYLOAD_BYTES + 1);
        Self {
            value,
            encoded_bytes,
        }
    }
}

impl fmt::Debug for BoundedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedPayload")
            .field("encoded_bytes", &self.encoded_bytes)
            .field("value", &REDACTED_VALUE)
            .finish()
    }
}

impl Serialize for BoundedPayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BoundedPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Self::from_value(&value).map_err(serde::de::Error::custom)
    }
}

/// Recursively redact content-bearing provider metadata and enforce the
/// serialized byte bound.  Numeric usage counters and a small set of routing
/// metadata keys remain available to rollups and D1 adapters.
pub fn redact_payload(value: impl Borrow<Value>) -> Result<Value, UsageModelError> {
    let value = value.borrow();
    if serialized_len(value)? > MAX_RAW_PAYLOAD_BYTES {
        return Err(UsageModelError::PayloadTooLarge);
    }
    let redacted = redact_value(value, None, 0);
    if serialized_len(&redacted)? > MAX_PAYLOAD_BYTES {
        return Err(UsageModelError::PayloadTooLarge);
    }
    Ok(redacted)
}

/// Redact and validate a provider usage object for persistence.
pub fn redact_provider_usage(value: impl Borrow<Value>) -> Result<BoundedPayload, UsageModelError> {
    let redacted = sanitize_provider_usage_payload(value.borrow())?;
    BoundedPayload::from_value(&redacted)
}

/// Return a redacted provider-usage object without wrapping it in a DTO.
pub fn sanitize_provider_usage_payload(value: &Value) -> Result<Value, UsageModelError> {
    let redacted = redact_payload(value)?;
    if !redacted.is_object() {
        return Err(UsageModelError::InvalidField("provider_usage"));
    }
    Ok(redacted)
}

/// Alias matching the redaction helper naming used by run-event adapters.
pub fn redact_provider_usage_payload(value: &Value) -> Result<Value, UsageModelError> {
    sanitize_provider_usage_payload(value)
}

/// Alias with wording used by repository adapters.
pub fn bounded_provider_usage(
    value: impl Borrow<Value>,
) -> Result<BoundedPayload, UsageModelError> {
    redact_provider_usage(value)
}

/// Input for constructing an immutable P05 usage event.
///
/// The fields mirror the P04 usage row and add only the P05 source metadata.
/// Keeping this as a separate input lets callers validate at the boundary
/// while D1 adapters can continue using the public `UsageEvent` fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageEventDraft {
    pub usage_event_id: String,
    pub request_id: String,
    pub org_id: String,
    pub project_id: Option<String>,
    pub run_id: Option<String>,
    pub principal_user_id: String,
    pub session_id: Option<String>,
    pub device_id: Option<String>,
    pub source: UsageSource,
    pub external_id: Option<String>,
    pub reconciliation_state: ReconciliationState,
    pub model_alias: String,
    pub route_version_id: String,
    pub provider_id: String,
    pub model_id: String,
    pub credential_id: Option<String>,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cached_tokens: Option<i64>,
    pub provider_usage: Option<BoundedPayload>,
    pub estimated_cost_minor: Option<i64>,
    pub actual_cost_minor: Option<i64>,
    pub currency: Option<String>,
    pub pricing_version: Option<String>,
    pub budget_decision: String,
    pub ttft_ms: Option<i64>,
    pub total_latency_ms: Option<i64>,
    pub created_at: String,
}

/// Immutable raw usage event plus P05 source/reconciliation metadata.
///
/// The struct is intentionally made of plain, D1-friendly scalar fields.  The
/// persistence layer supplies the values once; the domain exposes no update
/// operation.  A later reconciliation is represented by
/// [`UsageReconciliation`] and a new [`CostRecord`], never by changing this
/// record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UsageEvent {
    pub usage_event_id: String,
    pub request_id: String,
    pub org_id: String,
    pub project_id: Option<String>,
    pub run_id: Option<String>,
    pub principal_user_id: String,
    pub session_id: Option<String>,
    pub device_id: Option<String>,
    #[serde(default)]
    pub source: UsageSource,
    #[serde(default)]
    pub external_id: Option<String>,
    #[serde(default)]
    pub reconciliation_state: ReconciliationState,
    pub model_alias: String,
    pub route_version_id: String,
    pub provider_id: String,
    pub model_id: String,
    pub credential_id: Option<String>,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cached_tokens: Option<i64>,
    pub provider_usage: Option<BoundedPayload>,
    pub estimated_cost_minor: Option<i64>,
    pub actual_cost_minor: Option<i64>,
    pub currency: Option<String>,
    pub pricing_version: Option<String>,
    pub budget_decision: String,
    pub ttft_ms: Option<i64>,
    pub total_latency_ms: Option<i64>,
    pub created_at: String,
}

impl UsageEvent {
    pub fn new(draft: UsageEventDraft) -> Result<Self, UsageModelError> {
        Self::from_draft(draft)
    }

    pub fn from_draft(draft: UsageEventDraft) -> Result<Self, UsageModelError> {
        let event = Self {
            usage_event_id: draft.usage_event_id,
            request_id: draft.request_id,
            org_id: draft.org_id,
            project_id: draft.project_id,
            run_id: draft.run_id,
            principal_user_id: draft.principal_user_id,
            session_id: draft.session_id,
            device_id: draft.device_id,
            source: draft.source,
            external_id: draft.external_id,
            reconciliation_state: draft.reconciliation_state,
            model_alias: draft.model_alias,
            route_version_id: draft.route_version_id,
            provider_id: draft.provider_id,
            model_id: draft.model_id,
            credential_id: draft.credential_id,
            input_tokens: draft.input_tokens,
            output_tokens: draft.output_tokens,
            cached_tokens: draft.cached_tokens,
            provider_usage: draft.provider_usage,
            estimated_cost_minor: draft.estimated_cost_minor,
            actual_cost_minor: draft.actual_cost_minor,
            currency: draft.currency,
            pricing_version: draft.pricing_version,
            budget_decision: draft.budget_decision,
            ttft_ms: draft.ttft_ms,
            total_latency_ms: draft.total_latency_ms,
            created_at: draft.created_at,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn validate(&self) -> Result<(), UsageModelError> {
        required_text(&self.usage_event_id, "usage_event_id", MAX_IDENTIFIER_BYTES)?;
        required_text(&self.request_id, "request_id", MAX_IDENTIFIER_BYTES)?;
        required_text(&self.org_id, "org_id", MAX_IDENTIFIER_BYTES)?;
        optional_text(
            self.project_id.as_deref(),
            "project_id",
            MAX_IDENTIFIER_BYTES,
        )?;
        optional_text(self.run_id.as_deref(), "run_id", MAX_IDENTIFIER_BYTES)?;
        required_text(
            &self.principal_user_id,
            "principal_user_id",
            MAX_IDENTIFIER_BYTES,
        )?;
        optional_text(
            self.session_id.as_deref(),
            "session_id",
            MAX_IDENTIFIER_BYTES,
        )?;
        optional_text(self.device_id.as_deref(), "device_id", MAX_IDENTIFIER_BYTES)?;
        optional_text(
            self.external_id.as_deref(),
            "external_id",
            MAX_IDENTIFIER_BYTES,
        )?;
        required_text(&self.model_alias, "model_alias", MAX_IDENTIFIER_BYTES)?;
        required_text(
            &self.route_version_id,
            "route_version_id",
            MAX_IDENTIFIER_BYTES,
        )?;
        required_text(&self.provider_id, "provider_id", MAX_IDENTIFIER_BYTES)?;
        required_text(&self.model_id, "model_id", MAX_IDENTIFIER_BYTES)?;
        optional_text(
            self.credential_id.as_deref(),
            "credential_id",
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_optional_nonnegative(self.input_tokens, "input_tokens")?;
        validate_optional_nonnegative(self.output_tokens, "output_tokens")?;
        validate_optional_nonnegative(self.cached_tokens, "cached_tokens")?;
        if let (Some(input), Some(cached)) = (self.input_tokens, self.cached_tokens)
            && cached > input
        {
            return Err(UsageModelError::InvalidField("cached_tokens"));
        }
        validate_optional_nonnegative(self.estimated_cost_minor, "estimated_cost_minor")?;
        validate_optional_nonnegative(self.actual_cost_minor, "actual_cost_minor")?;
        validate_provider_usage_payload(self.provider_usage.as_ref())?;
        if let Some(currency) = self.currency.as_deref() {
            validate_currency(currency, "currency")?;
        }
        optional_text(self.pricing_version.as_deref(), "pricing_version", 128)?;
        required_text(&self.budget_decision, "budget_decision", 64)?;
        validate_optional_nonnegative(self.ttft_ms, "ttft_ms")?;
        validate_optional_nonnegative(self.total_latency_ms, "total_latency_ms")?;
        timestamp_text(&self.created_at, "created_at")?;
        if self.source == UsageSource::Run && self.run_id.is_none() {
            return Err(UsageModelError::InvalidField("run_id"));
        }
        Ok(())
    }

    /// Return the D1 `provider_usage_json` representation without exposing
    /// the inner value to callers that only need persistence.
    pub fn provider_usage_json(&self) -> Result<Option<String>, UsageModelError> {
        self.provider_usage
            .as_ref()
            .map(BoundedPayload::to_json_string)
            .transpose()
    }

    pub fn reconciliation_identity(&self) -> ReconciliationIdentity {
        ReconciliationIdentity {
            source: self.source,
            request_id: Some(self.request_id.clone()),
            run_id: self.run_id.clone(),
            external_id: self.external_id.clone(),
        }
    }
}

impl TryFrom<UsageEventDraft> for UsageEvent {
    type Error = UsageModelError;

    fn try_from(value: UsageEventDraft) -> Result<Self, Self::Error> {
        Self::from_draft(value)
    }
}

#[derive(Deserialize)]
struct UsageEventWire {
    usage_event_id: String,
    request_id: String,
    org_id: String,
    project_id: Option<String>,
    run_id: Option<String>,
    principal_user_id: String,
    session_id: Option<String>,
    device_id: Option<String>,
    #[serde(default)]
    source: UsageSource,
    #[serde(default)]
    external_id: Option<String>,
    #[serde(default, alias = "reconciliation_status")]
    reconciliation_state: ReconciliationState,
    model_alias: String,
    route_version_id: String,
    provider_id: String,
    model_id: String,
    credential_id: Option<String>,
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
    cached_tokens: Option<i64>,
    provider_usage: Option<BoundedPayload>,
    #[serde(default)]
    provider_usage_json: Option<String>,
    estimated_cost_minor: Option<i64>,
    actual_cost_minor: Option<i64>,
    currency: Option<String>,
    pricing_version: Option<String>,
    budget_decision: String,
    ttft_ms: Option<i64>,
    total_latency_ms: Option<i64>,
    created_at: String,
}

impl<'de> Deserialize<'de> for UsageEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = UsageEventWire::deserialize(deserializer)?;
        let provider_usage = match (wire.provider_usage, wire.provider_usage_json) {
            (Some(payload), Some(json)) => {
                let legacy = BoundedPayload::from_json(&json).map_err(serde::de::Error::custom)?;
                if payload != legacy {
                    return Err(serde::de::Error::custom(UsageModelError::InvalidField(
                        "provider_usage",
                    )));
                }
                Some(payload)
            }
            (Some(payload), None) => Some(payload),
            (None, None) => None,
            (None, Some(json)) => {
                Some(BoundedPayload::from_json(&json).map_err(serde::de::Error::custom)?)
            }
        };
        Self::from_draft(UsageEventDraft {
            usage_event_id: wire.usage_event_id,
            request_id: wire.request_id,
            org_id: wire.org_id,
            project_id: wire.project_id,
            run_id: wire.run_id,
            principal_user_id: wire.principal_user_id,
            session_id: wire.session_id,
            device_id: wire.device_id,
            source: wire.source,
            external_id: wire.external_id,
            reconciliation_state: wire.reconciliation_state,
            model_alias: wire.model_alias,
            route_version_id: wire.route_version_id,
            provider_id: wire.provider_id,
            model_id: wire.model_id,
            credential_id: wire.credential_id,
            input_tokens: wire.input_tokens,
            output_tokens: wire.output_tokens,
            cached_tokens: wire.cached_tokens,
            provider_usage,
            estimated_cost_minor: wire.estimated_cost_minor,
            actual_cost_minor: wire.actual_cost_minor,
            currency: wire.currency,
            pricing_version: wire.pricing_version,
            budget_decision: wire.budget_decision,
            ttft_ms: wire.ttft_ms,
            total_latency_ms: wire.total_latency_ms,
            created_at: wire.created_at,
        })
        .map_err(serde::de::Error::custom)
    }
}

/// Normalized read projection over the immutable P04 inference row and the
/// additive P05 run-usage row.  It is deliberately not a second usage source:
/// `source` tells the adapter which physical append-only table supplied the
/// row, while the reconciliation rules remain shared.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UsageEventProjection {
    pub event_id: String,
    pub request_id: Option<String>,
    pub run_id: Option<String>,
    pub org_id: String,
    pub project_id: Option<String>,
    pub principal_user_id: String,
    pub session_id: Option<String>,
    pub device_id: Option<String>,
    pub source: UsageSource,
    pub external_id: Option<String>,
    pub reconciliation_state: ReconciliationState,
    pub model_alias: Option<String>,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cached_tokens: Option<i64>,
    pub provider_usage: Option<BoundedPayload>,
    pub estimated_cost_minor: Option<i64>,
    pub actual_cost_minor: Option<i64>,
    pub currency: Option<String>,
    pub pricing_version: Option<String>,
    pub budget_decision: String,
    pub created_at: String,
}

impl UsageEventProjection {
    pub fn validate(&self) -> Result<(), UsageModelError> {
        required_text(&self.event_id, "event_id", MAX_IDENTIFIER_BYTES)?;
        optional_text(
            self.request_id.as_deref(),
            "request_id",
            MAX_IDENTIFIER_BYTES,
        )?;
        optional_text(self.run_id.as_deref(), "run_id", MAX_IDENTIFIER_BYTES)?;
        required_text(&self.org_id, "org_id", MAX_IDENTIFIER_BYTES)?;
        optional_text(
            self.project_id.as_deref(),
            "project_id",
            MAX_IDENTIFIER_BYTES,
        )?;
        required_text(
            &self.principal_user_id,
            "principal_user_id",
            MAX_IDENTIFIER_BYTES,
        )?;
        optional_text(
            self.session_id.as_deref(),
            "session_id",
            MAX_IDENTIFIER_BYTES,
        )?;
        optional_text(self.device_id.as_deref(), "device_id", MAX_IDENTIFIER_BYTES)?;
        optional_text(
            self.external_id.as_deref(),
            "external_id",
            MAX_IDENTIFIER_BYTES,
        )?;
        optional_text(
            self.model_alias.as_deref(),
            "model_alias",
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_optional_nonnegative(self.input_tokens, "input_tokens")?;
        validate_optional_nonnegative(self.output_tokens, "output_tokens")?;
        validate_optional_nonnegative(self.cached_tokens, "cached_tokens")?;
        if let (Some(input), Some(cached)) = (self.input_tokens, self.cached_tokens)
            && cached > input
        {
            return Err(UsageModelError::InvalidField("cached_tokens"));
        }
        validate_provider_usage_payload(self.provider_usage.as_ref())?;
        validate_optional_nonnegative(self.estimated_cost_minor, "estimated_cost_minor")?;
        validate_optional_nonnegative(self.actual_cost_minor, "actual_cost_minor")?;
        if let Some(currency) = self.currency.as_deref() {
            validate_currency(currency, "currency")?;
        }
        optional_text(self.pricing_version.as_deref(), "pricing_version", 128)?;
        required_text(&self.budget_decision, "budget_decision", 64)?;
        timestamp_text(&self.created_at, "created_at")?;
        self.reconciliation_identity().validate()?;
        Ok(())
    }

    pub fn reconciliation_identity(&self) -> ReconciliationIdentity {
        ReconciliationIdentity {
            source: self.source,
            request_id: self.request_id.clone(),
            run_id: self.run_id.clone(),
            external_id: self.external_id.clone(),
        }
    }

    pub fn usage_event_id(&self) -> &str {
        &self.event_id
    }

    pub fn reconciliation_status(&self) -> &'static str {
        self.reconciliation_state.as_str()
    }

    pub fn provider_usage_json(&self) -> Result<Option<String>, UsageModelError> {
        self.provider_usage
            .as_ref()
            .map(BoundedPayload::to_json_string)
            .transpose()
    }
}

#[derive(Deserialize)]
struct UsageEventProjectionWire {
    event_id: String,
    request_id: Option<String>,
    run_id: Option<String>,
    org_id: String,
    project_id: Option<String>,
    principal_user_id: String,
    session_id: Option<String>,
    device_id: Option<String>,
    source: UsageSource,
    external_id: Option<String>,
    #[serde(alias = "reconciliation_status")]
    reconciliation_state: ReconciliationState,
    model_alias: Option<String>,
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
    cached_tokens: Option<i64>,
    provider_usage: Option<BoundedPayload>,
    #[serde(default)]
    provider_usage_json: Option<String>,
    estimated_cost_minor: Option<i64>,
    actual_cost_minor: Option<i64>,
    currency: Option<String>,
    pricing_version: Option<String>,
    budget_decision: String,
    created_at: String,
}

impl<'de> Deserialize<'de> for UsageEventProjection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = UsageEventProjectionWire::deserialize(deserializer)?;
        let provider_usage = match (wire.provider_usage, wire.provider_usage_json) {
            (Some(payload), Some(json)) => {
                let legacy = BoundedPayload::from_json(&json).map_err(serde::de::Error::custom)?;
                if payload != legacy {
                    return Err(serde::de::Error::custom(UsageModelError::InvalidField(
                        "provider_usage",
                    )));
                }
                Some(payload)
            }
            (Some(payload), None) => Some(payload),
            (None, None) => None,
            (None, Some(json)) => {
                Some(BoundedPayload::from_json(&json).map_err(serde::de::Error::custom)?)
            }
        };
        let value = Self {
            event_id: wire.event_id,
            request_id: wire.request_id,
            run_id: wire.run_id,
            org_id: wire.org_id,
            project_id: wire.project_id,
            principal_user_id: wire.principal_user_id,
            session_id: wire.session_id,
            device_id: wire.device_id,
            source: wire.source,
            external_id: wire.external_id,
            reconciliation_state: wire.reconciliation_state,
            model_alias: wire.model_alias,
            input_tokens: wire.input_tokens,
            output_tokens: wire.output_tokens,
            cached_tokens: wire.cached_tokens,
            provider_usage,
            estimated_cost_minor: wire.estimated_cost_minor,
            actual_cost_minor: wire.actual_cost_minor,
            currency: wire.currency,
            pricing_version: wire.pricing_version,
            budget_decision: wire.budget_decision,
            created_at: wire.created_at,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl UsageEvent {
    /// Project the P04-shaped event into the shared read model.  Run-source
    /// rows can use the same projection directly with a null request ID.
    pub fn as_projection(&self) -> UsageEventProjection {
        UsageEventProjection {
            event_id: self.usage_event_id.clone(),
            request_id: Some(self.request_id.clone()),
            run_id: self.run_id.clone(),
            org_id: self.org_id.clone(),
            project_id: self.project_id.clone(),
            principal_user_id: self.principal_user_id.clone(),
            session_id: self.session_id.clone(),
            device_id: self.device_id.clone(),
            source: self.source,
            external_id: self.external_id.clone(),
            reconciliation_state: self.reconciliation_state,
            model_alias: Some(self.model_alias.clone()),
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            cached_tokens: self.cached_tokens,
            provider_usage: self.provider_usage.clone(),
            estimated_cost_minor: self.estimated_cost_minor,
            actual_cost_minor: self.actual_cost_minor,
            currency: self.currency.clone(),
            pricing_version: self.pricing_version.clone(),
            budget_decision: self.budget_decision.clone(),
            created_at: self.created_at.clone(),
        }
    }
}

/// Compatibility spelling for adapters that use the normalized-row term.
pub type NormalizedUsageEvent = UsageEventProjection;

/// Common read-only facts needed by source-agnostic reconciliation.  The trait
/// is a domain port, not an authorization abstraction: the route still owns
/// tenant lookup and device/project scope before calling the reconciler.
pub trait UsageEventView {
    fn validate_event(&self) -> Result<(), UsageModelError>;
    fn usage_event_id(&self) -> &str;
    fn organization_id(&self) -> &str;
    fn usage_source(&self) -> UsageSource;
    fn request_id(&self) -> Option<&str>;
    fn run_id(&self) -> Option<&str>;
    fn external_id(&self) -> Option<&str>;
    fn input_tokens(&self) -> Option<i64>;
    fn output_tokens(&self) -> Option<i64>;
    fn cached_tokens(&self) -> Option<i64>;
    fn provider_usage(&self) -> Option<&BoundedPayload>;
}

impl UsageEventView for UsageEvent {
    fn validate_event(&self) -> Result<(), UsageModelError> {
        self.validate()
    }

    fn usage_event_id(&self) -> &str {
        &self.usage_event_id
    }

    fn organization_id(&self) -> &str {
        &self.org_id
    }

    fn usage_source(&self) -> UsageSource {
        self.source
    }

    fn request_id(&self) -> Option<&str> {
        Some(self.request_id.as_str())
    }

    fn run_id(&self) -> Option<&str> {
        self.run_id.as_deref()
    }

    fn external_id(&self) -> Option<&str> {
        self.external_id.as_deref()
    }

    fn input_tokens(&self) -> Option<i64> {
        self.input_tokens
    }

    fn output_tokens(&self) -> Option<i64> {
        self.output_tokens
    }

    fn cached_tokens(&self) -> Option<i64> {
        self.cached_tokens
    }

    fn provider_usage(&self) -> Option<&BoundedPayload> {
        self.provider_usage.as_ref()
    }
}

impl UsageEventView for UsageEventProjection {
    fn validate_event(&self) -> Result<(), UsageModelError> {
        self.validate()
    }

    fn usage_event_id(&self) -> &str {
        &self.event_id
    }

    fn organization_id(&self) -> &str {
        &self.org_id
    }

    fn usage_source(&self) -> UsageSource {
        self.source
    }

    fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    fn run_id(&self) -> Option<&str> {
        self.run_id.as_deref()
    }

    fn external_id(&self) -> Option<&str> {
        self.external_id.as_deref()
    }

    fn input_tokens(&self) -> Option<i64> {
        self.input_tokens
    }

    fn output_tokens(&self) -> Option<i64> {
        self.output_tokens
    }

    fn cached_tokens(&self) -> Option<i64> {
        self.cached_tokens
    }

    fn provider_usage(&self) -> Option<&BoundedPayload> {
        self.provider_usage.as_ref()
    }
}

/// Input used to validate and construct an immutable cost row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostRecordDraft {
    pub cost_record_id: String,
    pub usage_event_id: String,
    pub org_id: String,
    pub pricing: PricingVersion,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cached_tokens: Option<i64>,
    pub cost_minor: i64,
    pub currency: String,
    pub calculation_kind: CostCalculationKind,
    pub recalculated_from_cost_record_id: Option<String>,
    pub created_at: String,
}

/// Append-only cost calculation for one usage event and one pricing version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CostRecord {
    pub cost_record_id: String,
    pub usage_event_id: String,
    pub org_id: String,
    pub pricing_source: String,
    pub pricing_version: String,
    pub pricing_effective_at: String,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cached_tokens: Option<i64>,
    pub cost_minor: i64,
    pub currency: String,
    pub calculation_kind: CostCalculationKind,
    pub recalculated_from_cost_record_id: Option<String>,
    pub created_at: String,
}

impl CostRecord {
    pub fn new(draft: CostRecordDraft) -> Result<Self, UsageModelError> {
        Self::from_draft(draft)
    }

    pub fn from_draft(draft: CostRecordDraft) -> Result<Self, UsageModelError> {
        let record = Self {
            cost_record_id: draft.cost_record_id,
            usage_event_id: draft.usage_event_id,
            org_id: draft.org_id,
            pricing_source: draft.pricing.source,
            pricing_version: draft.pricing.version,
            pricing_effective_at: draft.pricing.effective_at,
            input_tokens: draft.input_tokens,
            output_tokens: draft.output_tokens,
            cached_tokens: draft.cached_tokens,
            cost_minor: draft.cost_minor,
            currency: draft.currency,
            calculation_kind: draft.calculation_kind,
            recalculated_from_cost_record_id: draft.recalculated_from_cost_record_id,
            created_at: draft.created_at,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn estimated(mut draft: CostRecordDraft) -> Result<Self, UsageModelError> {
        draft.calculation_kind = CostCalculationKind::Estimated;
        draft.recalculated_from_cost_record_id = None;
        Self::from_draft(draft)
    }

    pub fn actual(mut draft: CostRecordDraft) -> Result<Self, UsageModelError> {
        draft.calculation_kind = CostCalculationKind::Actual;
        draft.recalculated_from_cost_record_id = None;
        Self::from_draft(draft)
    }

    pub fn recalculated(
        mut draft: CostRecordDraft,
        previous: &Self,
    ) -> Result<Self, UsageModelError> {
        if previous.validate().is_err() {
            return Err(UsageModelError::InvalidField("previous_cost_record"));
        }
        if draft.usage_event_id != previous.usage_event_id || draft.org_id != previous.org_id {
            return Err(UsageModelError::InvalidField("cost_record_scope"));
        }
        if draft.cost_record_id == previous.cost_record_id {
            return Err(UsageModelError::InvalidField("cost_record_id"));
        }
        if draft.pricing.same_version(&previous.pricing()) {
            return Err(UsageModelError::InvalidField("pricing_version"));
        }
        draft.calculation_kind = CostCalculationKind::Recalculated;
        draft.recalculated_from_cost_record_id = Some(previous.cost_record_id.clone());
        Self::from_draft(draft)
    }

    /// Create a new recalculation without changing `self`.
    ///
    /// A new source/version pair is required.  This prevents a caller from
    /// presenting today's price as the original historical price while still
    /// allowing a chain of explicitly versioned recalculations.
    pub fn recalculate(
        &self,
        cost_record_id: impl Into<String>,
        pricing: PricingVersion,
        cost_minor: i64,
        currency: impl Into<String>,
        created_at: impl Into<String>,
    ) -> Result<Self, UsageModelError> {
        let draft = CostRecordDraft {
            cost_record_id: cost_record_id.into(),
            usage_event_id: self.usage_event_id.clone(),
            org_id: self.org_id.clone(),
            pricing,
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            cached_tokens: self.cached_tokens,
            cost_minor,
            currency: currency.into(),
            calculation_kind: CostCalculationKind::Recalculated,
            recalculated_from_cost_record_id: Some(self.cost_record_id.clone()),
            created_at: created_at.into(),
        };
        Self::recalculated(draft, self)
    }

    pub fn validate(&self) -> Result<(), UsageModelError> {
        required_text(
            &self.cost_record_id,
            "cost_record_id",
            MAX_COST_RECORD_ID_BYTES,
        )?;
        required_text(&self.usage_event_id, "usage_event_id", MAX_IDENTIFIER_BYTES)?;
        required_text(&self.org_id, "org_id", MAX_IDENTIFIER_BYTES)?;
        required_text(&self.pricing_source, "pricing_source", 128)?;
        required_text(&self.pricing_version, "pricing_version", 128)?;
        timestamp_text(&self.pricing_effective_at, "pricing_effective_at")?;
        validate_optional_nonnegative(self.input_tokens, "input_tokens")?;
        validate_optional_nonnegative(self.output_tokens, "output_tokens")?;
        validate_optional_nonnegative(self.cached_tokens, "cached_tokens")?;
        if let (Some(input), Some(cached)) = (self.input_tokens, self.cached_tokens)
            && cached > input
        {
            return Err(UsageModelError::InvalidField("cached_tokens"));
        }
        if self.cost_minor < 0 {
            return Err(UsageModelError::InvalidField("cost_minor"));
        }
        validate_currency(&self.currency, "currency")?;
        timestamp_text(&self.created_at, "created_at")?;
        match self.calculation_kind {
            CostCalculationKind::Recalculated => {
                let previous = self.recalculated_from_cost_record_id.as_deref().ok_or(
                    UsageModelError::InvalidField("recalculated_from_cost_record_id"),
                )?;
                required_text(
                    previous,
                    "recalculated_from_cost_record_id",
                    MAX_COST_RECORD_ID_BYTES,
                )?;
                if previous == self.cost_record_id {
                    return Err(UsageModelError::InvalidField("cost_record_id"));
                }
            }
            CostCalculationKind::Estimated | CostCalculationKind::Actual => {
                if self.recalculated_from_cost_record_id.is_some() {
                    return Err(UsageModelError::InvalidField(
                        "recalculated_from_cost_record_id",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn pricing(&self) -> PricingVersion {
        PricingVersion {
            source: self.pricing_source.clone(),
            version: self.pricing_version.clone(),
            effective_at: self.pricing_effective_at.clone(),
        }
    }

    pub const fn is_recalculated(&self) -> bool {
        matches!(self.calculation_kind, CostCalculationKind::Recalculated)
    }
}

impl TryFrom<CostRecordDraft> for CostRecord {
    type Error = UsageModelError;

    fn try_from(value: CostRecordDraft) -> Result<Self, Self::Error> {
        Self::from_draft(value)
    }
}

#[derive(Deserialize)]
struct CostRecordWire {
    cost_record_id: String,
    usage_event_id: String,
    org_id: String,
    pricing_source: String,
    pricing_version: String,
    pricing_effective_at: String,
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
    cached_tokens: Option<i64>,
    cost_minor: i64,
    currency: String,
    calculation_kind: CostCalculationKind,
    recalculated_from_cost_record_id: Option<String>,
    created_at: String,
}

impl<'de> Deserialize<'de> for CostRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CostRecordWire::deserialize(deserializer)?;
        Self::from_draft(CostRecordDraft {
            cost_record_id: wire.cost_record_id,
            usage_event_id: wire.usage_event_id,
            org_id: wire.org_id,
            pricing: PricingVersion::new(
                wire.pricing_source,
                wire.pricing_version,
                wire.pricing_effective_at,
            )
            .map_err(serde::de::Error::custom)?,
            input_tokens: wire.input_tokens,
            output_tokens: wire.output_tokens,
            cached_tokens: wire.cached_tokens,
            cost_minor: wire.cost_minor,
            currency: wire.currency,
            calculation_kind: wire.calculation_kind,
            recalculated_from_cost_record_id: wire.recalculated_from_cost_record_id,
            created_at: wire.created_at,
        })
        .map_err(serde::de::Error::custom)
    }
}

/// Stable identity used to deduplicate a reconciliation request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReconciliationIdentity {
    pub source: UsageSource,
    pub request_id: Option<String>,
    pub run_id: Option<String>,
    pub external_id: Option<String>,
}

impl ReconciliationIdentity {
    pub fn new(
        source: UsageSource,
        request_id: Option<String>,
        run_id: Option<String>,
        external_id: Option<String>,
    ) -> Result<Self, UsageModelError> {
        let identity = Self {
            source,
            request_id,
            run_id,
            external_id,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), UsageModelError> {
        optional_text(
            self.request_id.as_deref(),
            "request_id",
            MAX_IDENTIFIER_BYTES,
        )?;
        optional_text(self.run_id.as_deref(), "run_id", MAX_IDENTIFIER_BYTES)?;
        optional_text(
            self.external_id.as_deref(),
            "external_id",
            MAX_IDENTIFIER_BYTES,
        )?;
        let valid = match self.source {
            UsageSource::Inference => self.request_id.is_some(),
            UsageSource::Run => self.run_id.is_some(),
        };
        if !valid {
            return Err(UsageModelError::InvalidField("reconciliation_identity"));
        }
        Ok(())
    }

    /// Compare known identifiers while allowing a previously missing optional
    /// correlation to be filled by a later trusted reconciliation request.
    pub fn matches_known(&self, other: &Self) -> bool {
        self.source == other.source
            && optional_values_match(self.request_id.as_deref(), other.request_id.as_deref())
            && optional_values_match(self.run_id.as_deref(), other.run_id.as_deref())
            && optional_values_match(self.external_id.as_deref(), other.external_id.as_deref())
    }

    pub fn exact_eq(&self, other: &Self) -> bool {
        self == other
    }

    /// A compact, non-secret D1 uniqueness hint.  The structured fields should
    /// still be used in the unique index; this value is useful for logs and
    /// adapter-local maps.
    pub fn dedupe_key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.source.as_str(),
            self.request_id.as_deref().unwrap_or("-"),
            self.run_id.as_deref().unwrap_or("-")
        )
    }
}

#[derive(Deserialize)]
struct ReconciliationIdentityWire {
    source: UsageSource,
    request_id: Option<String>,
    run_id: Option<String>,
    external_id: Option<String>,
}

impl<'de> Deserialize<'de> for ReconciliationIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReconciliationIdentityWire::deserialize(deserializer)?;
        Self::new(wire.source, wire.request_id, wire.run_id, wire.external_id)
            .map_err(serde::de::Error::custom)
    }
}

/// Normalized, bounded provider reconciliation input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReconciliationRequest {
    /// The server-generated cost row ID.  It is required only when an actual
    /// cost is supplied; retries may use a different value and still replay
    /// the existing projection.
    pub cost_record_id: Option<String>,
    pub identity: ReconciliationIdentity,
    pub actual_cost_minor: Option<i64>,
    pub provider_usage: Option<BoundedPayload>,
    pub pricing: Option<PricingVersion>,
    pub currency: Option<String>,
    pub reconciled_at: String,
}

impl ReconciliationRequest {
    pub fn new(
        identity: ReconciliationIdentity,
        actual_cost_minor: Option<i64>,
        provider_usage: Option<BoundedPayload>,
        pricing: Option<PricingVersion>,
        currency: Option<String>,
        reconciled_at: impl Into<String>,
    ) -> Result<Self, UsageModelError> {
        let request = Self {
            cost_record_id: None,
            identity,
            actual_cost_minor,
            provider_usage,
            pricing,
            currency,
            reconciled_at: reconciled_at.into(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn with_cost_record_id(mut self, cost_record_id: impl Into<String>) -> Self {
        self.cost_record_id = Some(cost_record_id.into());
        self
    }

    /// Construct an actual-cost request in one fallible step.  The shorter
    /// `new` constructor remains strict for callers that already have a
    /// server-generated cost ID available.
    pub fn new_with_cost_record_id(
        cost_record_id: impl Into<String>,
        identity: ReconciliationIdentity,
        actual_cost_minor: Option<i64>,
        provider_usage: Option<BoundedPayload>,
        pricing: Option<PricingVersion>,
        currency: Option<String>,
        reconciled_at: impl Into<String>,
    ) -> Result<Self, UsageModelError> {
        let request = Self {
            cost_record_id: Some(cost_record_id.into()),
            identity,
            actual_cost_minor,
            provider_usage,
            pricing,
            currency,
            reconciled_at: reconciled_at.into(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), UsageModelError> {
        self.identity.validate()?;
        if let Some(cost_record_id) = self.cost_record_id.as_deref() {
            required_text(cost_record_id, "cost_record_id", MAX_COST_RECORD_ID_BYTES)?;
        }
        validate_optional_nonnegative(self.actual_cost_minor, "actual_cost_minor")?;
        validate_provider_usage_payload(self.provider_usage.as_ref())?;
        if let Some(pricing) = &self.pricing {
            pricing.validate()?;
        }
        if let Some(currency) = self.currency.as_deref() {
            validate_currency(currency, "currency")?;
        }
        let has_actual = self.actual_cost_minor.is_some();
        if has_actual
            && (self.cost_record_id.is_none() || self.pricing.is_none() || self.currency.is_none())
        {
            return Err(UsageModelError::InvalidField("actual_cost"));
        }
        if !has_actual
            && (self.cost_record_id.is_some() || self.pricing.is_some() || self.currency.is_some())
        {
            return Err(UsageModelError::InvalidField("actual_cost"));
        }
        timestamp_text(&self.reconciled_at, "reconciled_at")?;
        Ok(())
    }

    pub fn dedupe_key(&self) -> String {
        self.identity.dedupe_key()
    }
}

#[derive(Deserialize)]
struct ReconciliationRequestWire {
    cost_record_id: Option<String>,
    identity: ReconciliationIdentity,
    actual_cost_minor: Option<i64>,
    provider_usage: Option<BoundedPayload>,
    pricing: Option<PricingVersion>,
    currency: Option<String>,
    reconciled_at: String,
}

impl<'de> Deserialize<'de> for ReconciliationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReconciliationRequestWire::deserialize(deserializer)?;
        let value = Self {
            cost_record_id: wire.cost_record_id,
            identity: wire.identity,
            actual_cost_minor: wire.actual_cost_minor,
            provider_usage: wire.provider_usage,
            pricing: wire.pricing,
            currency: wire.currency,
            reconciled_at: wire.reconciled_at,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

/// Immutable projection of the reconciliation attempt for a usage event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UsageReconciliation {
    pub usage_event_id: String,
    pub org_id: String,
    pub identity: ReconciliationIdentity,
    pub state: ReconciliationState,
    pub cost_record_id: Option<String>,
    pub actual_cost_minor: Option<i64>,
    pub provider_usage: Option<BoundedPayload>,
    pub pricing: Option<PricingVersion>,
    pub currency: Option<String>,
    pub reconciled_at: Option<String>,
    pub conflict_reason: Option<ReconciliationConflictReason>,
}

impl UsageReconciliation {
    pub fn pending(
        usage_event_id: impl Into<String>,
        org_id: impl Into<String>,
        identity: ReconciliationIdentity,
    ) -> Result<Self, UsageModelError> {
        let projection = Self {
            usage_event_id: usage_event_id.into(),
            org_id: org_id.into(),
            identity,
            state: ReconciliationState::Pending,
            cost_record_id: None,
            actual_cost_minor: None,
            provider_usage: None,
            pricing: None,
            currency: None,
            reconciled_at: None,
            conflict_reason: None,
        };
        projection.validate()?;
        Ok(projection)
    }

    pub fn from_request(
        usage_event_id: impl Into<String>,
        org_id: impl Into<String>,
        request: &ReconciliationRequest,
    ) -> Result<Self, UsageModelError> {
        request.validate()?;
        let projection = Self {
            usage_event_id: usage_event_id.into(),
            org_id: org_id.into(),
            identity: request.identity.clone(),
            state: ReconciliationState::Reconciled,
            cost_record_id: request.cost_record_id.clone(),
            actual_cost_minor: request.actual_cost_minor,
            provider_usage: request.provider_usage.clone(),
            pricing: request.pricing.clone(),
            currency: request.currency.clone(),
            reconciled_at: Some(request.reconciled_at.clone()),
            conflict_reason: None,
        };
        projection.validate()?;
        Ok(projection)
    }

    /// Create an in-progress projection while retaining the normalized input
    /// fingerprint.  A later request with the same identity but a different
    /// payload can then be rejected instead of racing the first writer.
    pub fn pending_for_request(
        usage_event_id: impl Into<String>,
        org_id: impl Into<String>,
        request: &ReconciliationRequest,
    ) -> Result<Self, UsageModelError> {
        let mut projection = Self::from_request(usage_event_id, org_id, request)?;
        projection.state = ReconciliationState::Pending;
        projection.reconciled_at = None;
        projection.validate()?;
        Ok(projection)
    }

    pub fn validate(&self) -> Result<(), UsageModelError> {
        required_text(&self.usage_event_id, "usage_event_id", MAX_IDENTIFIER_BYTES)?;
        required_text(&self.org_id, "org_id", MAX_IDENTIFIER_BYTES)?;
        self.identity.validate()?;
        if let Some(cost_record_id) = self.cost_record_id.as_deref() {
            required_text(cost_record_id, "cost_record_id", MAX_COST_RECORD_ID_BYTES)?;
        }
        validate_optional_nonnegative(self.actual_cost_minor, "actual_cost_minor")?;
        validate_provider_usage_payload(self.provider_usage.as_ref())?;
        if let Some(pricing) = &self.pricing {
            pricing.validate()?;
        }
        if let Some(currency) = self.currency.as_deref() {
            validate_currency(currency, "currency")?;
        }
        if let Some(reconciled_at) = self.reconciled_at.as_deref() {
            timestamp_text(reconciled_at, "reconciled_at")?;
        }
        if self.actual_cost_minor.is_some()
            && (self.cost_record_id.is_none() || self.pricing.is_none() || self.currency.is_none())
        {
            return Err(UsageModelError::InvalidField("actual_cost"));
        }
        if self.actual_cost_minor.is_none()
            && (self.cost_record_id.is_some() || self.pricing.is_some() || self.currency.is_some())
        {
            return Err(UsageModelError::InvalidField("actual_cost"));
        }
        match self.state {
            ReconciliationState::Recorded | ReconciliationState::Pending => {
                if self.reconciled_at.is_some() || self.conflict_reason.is_some() {
                    return Err(UsageModelError::InvalidField("reconciliation_state"));
                }
            }
            ReconciliationState::Reconciled => {
                if self.reconciled_at.is_none() || self.conflict_reason.is_some() {
                    return Err(UsageModelError::InvalidField("reconciliation_state"));
                }
            }
            ReconciliationState::Conflict => {
                if self.conflict_reason.is_none() {
                    return Err(UsageModelError::InvalidField("reconciliation_state"));
                }
            }
        }
        Ok(())
    }

    pub fn is_reconciled(&self) -> bool {
        self.state == ReconciliationState::Reconciled
    }
}

#[derive(Deserialize)]
struct UsageReconciliationWire {
    usage_event_id: String,
    org_id: String,
    identity: ReconciliationIdentity,
    state: ReconciliationState,
    cost_record_id: Option<String>,
    actual_cost_minor: Option<i64>,
    provider_usage: Option<BoundedPayload>,
    pricing: Option<PricingVersion>,
    currency: Option<String>,
    reconciled_at: Option<String>,
    conflict_reason: Option<ReconciliationConflictReason>,
}

impl<'de> Deserialize<'de> for UsageReconciliation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = UsageReconciliationWire::deserialize(deserializer)?;
        let value = Self {
            usage_event_id: wire.usage_event_id,
            org_id: wire.org_id,
            identity: wire.identity,
            state: wire.state,
            cost_record_id: wire.cost_record_id,
            actual_cost_minor: wire.actual_cost_minor,
            provider_usage: wire.provider_usage,
            pricing: wire.pricing,
            currency: wire.currency,
            reconciled_at: wire.reconciled_at,
            conflict_reason: wire.conflict_reason,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

/// Result of applying a reconciliation request to the immutable domain model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconciliationOutcome {
    /// The caller should append the projection and optional cost record.
    Apply {
        reconciliation: UsageReconciliation,
        cost_record: Option<Box<CostRecord>>,
    },
    /// The exact completed request was already recorded.  No new row should be
    /// appended, even if the caller generated a different cost record ID.
    Replay {
        reconciliation: UsageReconciliation,
        cost_record_id: Option<String>,
    },
    /// Another request with the same identity and payload is in progress.
    InProgress { reconciliation: UsageReconciliation },
}

impl ReconciliationOutcome {
    pub fn reconciliation(&self) -> &UsageReconciliation {
        match self {
            Self::Apply { reconciliation, .. }
            | Self::Replay { reconciliation, .. }
            | Self::InProgress { reconciliation } => reconciliation,
        }
    }
}

/// Apply a normalized reconciliation request to a usage event.
///
/// The function is pure: it returns rows for the adapter to append.  It does
/// not mutate the raw event, does not generate IDs, and does not perform
/// authorization.  The existing projection is the idempotency record.
pub fn reconcile_usage<E: UsageEventView>(
    event: &E,
    existing: Option<&UsageReconciliation>,
    request: &ReconciliationRequest,
) -> Result<ReconciliationOutcome, UsageModelError> {
    event.validate_event()?;
    request.validate()?;

    let event_identity = ReconciliationIdentity {
        source: event.usage_source(),
        request_id: event.request_id().map(str::to_owned),
        run_id: event.run_id().map(str::to_owned),
        external_id: event.external_id().map(str::to_owned),
    };
    if event_identity.source != request.identity.source {
        return Err(conflict(ReconciliationConflictReason::SourceMismatch));
    }
    if let Some(reason) = event_identity_difference(&event_identity, &request.identity) {
        return Err(conflict(reason));
    }
    let mut normalized_request = request.clone();
    if normalized_request.identity.external_id.is_none() {
        normalized_request.identity.external_id = event_identity.external_id.clone();
    }
    let request = &normalized_request;

    if let Some(current) = existing {
        current.validate()?;
        if current.org_id != event.organization_id() {
            return Err(conflict(ReconciliationConflictReason::TenantMismatch));
        }
        if current.usage_event_id != event.usage_event_id() {
            return Err(conflict(ReconciliationConflictReason::UsageEventMismatch));
        }
        let current_identity = if current.identity.external_id.is_none() {
            let mut identity = current.identity.clone();
            identity.external_id = event_identity.external_id.clone();
            identity
        } else {
            current.identity.clone()
        };
        if !current_identity.exact_eq(&request.identity) {
            return Err(conflict(identity_difference_exact(
                &current_identity,
                &request.identity,
            )));
        }
        if matches!(
            current.state,
            ReconciliationState::Recorded | ReconciliationState::Pending
        ) && is_unbound_pending(current)
        {
            return Ok(ReconciliationOutcome::InProgress {
                reconciliation: current.clone(),
            });
        }
        if let Some(reason) = payload_difference(current, request) {
            return Err(conflict(reason));
        }
        return match current.state {
            ReconciliationState::Reconciled => Ok(ReconciliationOutcome::Replay {
                cost_record_id: current.cost_record_id.clone(),
                reconciliation: current.clone(),
            }),
            ReconciliationState::Recorded | ReconciliationState::Pending => {
                Ok(ReconciliationOutcome::InProgress {
                    reconciliation: current.clone(),
                })
            }
            ReconciliationState::Conflict => Err(conflict(
                current
                    .conflict_reason
                    .unwrap_or(ReconciliationConflictReason::InvalidProjection),
            )),
        };
    }

    let reconciliation = UsageReconciliation::from_request(
        event.usage_event_id(),
        event.organization_id(),
        request,
    )?;
    let cost_record = build_actual_cost_record(event, request)?;
    Ok(ReconciliationOutcome::Apply {
        reconciliation,
        cost_record,
    })
}

/// Short alias for callers that model reconciliation as an application
/// command rather than a repository operation.
pub fn apply_reconciliation<E: UsageEventView>(
    event: &E,
    existing: Option<&UsageReconciliation>,
    request: &ReconciliationRequest,
) -> Result<ReconciliationOutcome, UsageModelError> {
    reconcile_usage(event, existing, request)
}

/// A period used by a derived usage rollup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollupPeriod {
    Hour,
    Day,
    Month,
}

impl RollupPeriod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hour => "hour",
            Self::Day => "day",
            Self::Month => "month",
        }
    }
}

/// One normalized contribution to a derived usage rollup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UsageRollupInput {
    pub org_id: String,
    pub project_id: Option<String>,
    pub run_id: Option<String>,
    pub principal_user_id: String,
    pub source: UsageSource,
    pub model_alias: String,
    pub provider_id: String,
    pub period: RollupPeriod,
    pub period_start: String,
    pub period_end: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cached_tokens: i64,
    pub cost_minor: i64,
    pub currency: Option<String>,
}

impl UsageRollupInput {
    pub fn validate(&self) -> Result<(), UsageModelError> {
        required_text(&self.org_id, "org_id", MAX_IDENTIFIER_BYTES)?;
        optional_text(
            self.project_id.as_deref(),
            "project_id",
            MAX_IDENTIFIER_BYTES,
        )?;
        optional_text(self.run_id.as_deref(), "run_id", MAX_IDENTIFIER_BYTES)?;
        required_text(
            &self.principal_user_id,
            "principal_user_id",
            MAX_IDENTIFIER_BYTES,
        )?;
        required_text(&self.model_alias, "model_alias", MAX_IDENTIFIER_BYTES)?;
        required_text(&self.provider_id, "provider_id", MAX_IDENTIFIER_BYTES)?;
        timestamp_text(&self.period_start, "period_start")?;
        timestamp_text(&self.period_end, "period_end")?;
        if self.period_start >= self.period_end {
            return Err(UsageModelError::InvalidField("period"));
        }
        validate_nonnegative(self.input_tokens, "input_tokens")?;
        validate_nonnegative(self.output_tokens, "output_tokens")?;
        validate_nonnegative(self.cached_tokens, "cached_tokens")?;
        if self.cached_tokens > self.input_tokens {
            return Err(UsageModelError::InvalidField("cached_tokens"));
        }
        validate_nonnegative(self.cost_minor, "cost_minor")?;
        if let Some(currency) = self.currency.as_deref() {
            validate_currency(currency, "currency")?;
        }
        Ok(())
    }

    pub fn same_dimensions(&self, other: &Self) -> bool {
        self.org_id == other.org_id
            && self.project_id == other.project_id
            && self.run_id == other.run_id
            && self.principal_user_id == other.principal_user_id
            && self.source == other.source
            && self.model_alias == other.model_alias
            && self.provider_id == other.provider_id
            && self.period == other.period
            && self.period_start == other.period_start
            && self.period_end == other.period_end
            && self.currency == other.currency
    }
}

#[derive(Deserialize)]
struct UsageRollupInputWire {
    org_id: String,
    project_id: Option<String>,
    run_id: Option<String>,
    principal_user_id: String,
    source: UsageSource,
    model_alias: String,
    provider_id: String,
    period: RollupPeriod,
    period_start: String,
    period_end: String,
    input_tokens: i64,
    output_tokens: i64,
    cached_tokens: i64,
    cost_minor: i64,
    currency: Option<String>,
}

impl<'de> Deserialize<'de> for UsageRollupInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = UsageRollupInputWire::deserialize(deserializer)?;
        let value = Self {
            org_id: wire.org_id,
            project_id: wire.project_id,
            run_id: wire.run_id,
            principal_user_id: wire.principal_user_id,
            source: wire.source,
            model_alias: wire.model_alias,
            provider_id: wire.provider_id,
            period: wire.period,
            period_start: wire.period_start,
            period_end: wire.period_end,
            input_tokens: wire.input_tokens,
            output_tokens: wire.output_tokens,
            cached_tokens: wire.cached_tokens,
            cost_minor: wire.cost_minor,
            currency: wire.currency,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

/// Build a bounded, deterministic rollup contribution from a raw event and an
/// optional selected cost record.  The caller chooses which immutable cost
/// record to use; this function never substitutes today's price for an old
/// one.
pub fn normalize_rollup_input(
    event: &UsageEvent,
    cost_record: Option<&CostRecord>,
    period: RollupPeriod,
    period_start: impl Into<String>,
    period_end: impl Into<String>,
) -> Result<UsageRollupInput, UsageModelError> {
    event.validate()?;
    if let Some(cost) = cost_record {
        cost.validate()?;
        if cost.usage_event_id != event.usage_event_id || cost.org_id != event.org_id {
            return Err(UsageModelError::InvalidField("cost_record_scope"));
        }
    }
    let input = UsageRollupInput {
        org_id: event.org_id.clone(),
        project_id: event.project_id.clone(),
        run_id: event.run_id.clone(),
        principal_user_id: event.principal_user_id.clone(),
        source: event.source,
        model_alias: event.model_alias.clone(),
        provider_id: event.provider_id.clone(),
        period,
        period_start: period_start.into(),
        period_end: period_end.into(),
        input_tokens: cost_record
            .and_then(|cost| cost.input_tokens)
            .or(event.input_tokens)
            .unwrap_or_default(),
        output_tokens: cost_record
            .and_then(|cost| cost.output_tokens)
            .or(event.output_tokens)
            .unwrap_or_default(),
        cached_tokens: cost_record
            .and_then(|cost| cost.cached_tokens)
            .or(event.cached_tokens)
            .unwrap_or_default(),
        cost_minor: cost_record.map_or_else(
            || {
                event
                    .actual_cost_minor
                    .or(event.estimated_cost_minor)
                    .unwrap_or_default()
            },
            |cost| cost.cost_minor,
        ),
        currency: cost_record.map_or_else(
            || event.currency.clone(),
            |cost| Some(cost.currency.clone()),
        ),
    };
    input.validate()?;
    Ok(input)
}

/// A derived, rebuildable rollup accumulator.  Raw usage remains the source
/// of truth; this type only makes checked aggregation convenient for a D1
/// rollup worker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UsageRollup {
    pub rollup_id: String,
    pub dimensions: UsageRollupInput,
    pub event_count: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cached_tokens: i64,
    pub cost_minor: i64,
}

impl UsageRollup {
    pub fn validate(&self) -> Result<(), UsageModelError> {
        required_text(&self.rollup_id, "rollup_id", MAX_IDENTIFIER_BYTES)?;
        self.dimensions.validate()?;
        validate_nonnegative(self.event_count, "rollup_event_count")?;
        validate_nonnegative(self.input_tokens, "rollup_input_tokens")?;
        validate_nonnegative(self.output_tokens, "rollup_output_tokens")?;
        validate_nonnegative(self.cached_tokens, "rollup_cached_tokens")?;
        if self.cached_tokens > self.input_tokens {
            return Err(UsageModelError::InvalidField("rollup_cached_tokens"));
        }
        validate_nonnegative(self.cost_minor, "rollup_cost_minor")?;
        if self.event_count == 0
            && (self.input_tokens != 0
                || self.output_tokens != 0
                || self.cached_tokens != 0
                || self.cost_minor != 0)
        {
            return Err(UsageModelError::InvalidField("rollup_event_count"));
        }
        Ok(())
    }

    pub fn new(
        rollup_id: impl Into<String>,
        input: UsageRollupInput,
    ) -> Result<Self, UsageModelError> {
        input.validate()?;
        let rollup_id = rollup_id.into();
        required_text(&rollup_id, "rollup_id", MAX_IDENTIFIER_BYTES)?;
        let mut rollup = Self {
            rollup_id,
            dimensions: input.clone(),
            event_count: 0,
            input_tokens: 0,
            output_tokens: 0,
            cached_tokens: 0,
            cost_minor: 0,
        };
        rollup.add(&input)?;
        rollup.validate()?;
        Ok(rollup)
    }

    pub fn usage_rollup_id(&self) -> &str {
        &self.rollup_id
    }

    pub fn bucket_start(&self) -> &str {
        &self.dimensions.period_start
    }

    pub fn bucket_end(&self) -> &str {
        &self.dimensions.period_end
    }

    pub fn usage_event_count(&self) -> i64 {
        self.event_count
    }

    pub fn add(&mut self, input: &UsageRollupInput) -> Result<(), UsageModelError> {
        self.validate()?;
        input.validate()?;
        if !self.dimensions.same_dimensions(input) {
            return Err(UsageModelError::InvalidField("rollup_dimensions"));
        }
        let event_count = self
            .event_count
            .checked_add(1)
            .ok_or(UsageModelError::InvalidField("rollup_event_count"))?;
        let input_tokens = self
            .input_tokens
            .checked_add(input.input_tokens)
            .ok_or(UsageModelError::InvalidField("rollup_input_tokens"))?;
        let output_tokens = self
            .output_tokens
            .checked_add(input.output_tokens)
            .ok_or(UsageModelError::InvalidField("rollup_output_tokens"))?;
        let cached_tokens = self
            .cached_tokens
            .checked_add(input.cached_tokens)
            .ok_or(UsageModelError::InvalidField("rollup_cached_tokens"))?;
        let cost_minor = self
            .cost_minor
            .checked_add(input.cost_minor)
            .ok_or(UsageModelError::InvalidField("rollup_cost_minor"))?;
        if cached_tokens > input_tokens {
            return Err(UsageModelError::InvalidField("rollup_cached_tokens"));
        }
        self.event_count = event_count;
        self.input_tokens = input_tokens;
        self.output_tokens = output_tokens;
        self.cached_tokens = cached_tokens;
        self.cost_minor = cost_minor;
        Ok(())
    }
}

#[derive(Deserialize)]
struct UsageRollupWire {
    rollup_id: String,
    dimensions: UsageRollupInput,
    event_count: i64,
    input_tokens: i64,
    output_tokens: i64,
    cached_tokens: i64,
    cost_minor: i64,
}

impl<'de> Deserialize<'de> for UsageRollup {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = UsageRollupWire::deserialize(deserializer)?;
        let value = Self {
            rollup_id: wire.rollup_id,
            dimensions: wire.dimensions,
            event_count: wire.event_count,
            input_tokens: wire.input_tokens,
            output_tokens: wire.output_tokens,
            cached_tokens: wire.cached_tokens,
            cost_minor: wire.cost_minor,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

fn conflict(reason: ReconciliationConflictReason) -> UsageModelError {
    UsageModelError::ReconciliationConflict(reason)
}

fn build_actual_cost_record<E: UsageEventView>(
    event: &E,
    request: &ReconciliationRequest,
) -> Result<Option<Box<CostRecord>>, UsageModelError> {
    let Some(actual_cost_minor) = request.actual_cost_minor else {
        return Ok(None);
    };
    let pricing = request
        .pricing
        .clone()
        .ok_or(UsageModelError::InvalidField("pricing"))?;
    let currency = request
        .currency
        .clone()
        .ok_or(UsageModelError::InvalidField("currency"))?;
    let cost_record_id = request
        .cost_record_id
        .clone()
        .ok_or(UsageModelError::InvalidField("cost_record_id"))?;
    let provider_usage = request
        .provider_usage
        .as_ref()
        .or_else(|| event.provider_usage());
    let input_tokens =
        token_from_payload(provider_usage, "input_tokens").or_else(|| event.input_tokens());
    let output_tokens =
        token_from_payload(provider_usage, "output_tokens").or_else(|| event.output_tokens());
    let cached_tokens =
        token_from_payload(provider_usage, "cached_tokens").or_else(|| event.cached_tokens());
    CostRecord::actual(CostRecordDraft {
        cost_record_id,
        usage_event_id: event.usage_event_id().to_owned(),
        org_id: event.organization_id().to_owned(),
        pricing,
        input_tokens,
        output_tokens,
        cached_tokens,
        cost_minor: actual_cost_minor,
        currency,
        calculation_kind: CostCalculationKind::Actual,
        recalculated_from_cost_record_id: None,
        created_at: request.reconciled_at.clone(),
    })
    .map(|record| Some(Box::new(record)))
}

fn token_from_payload(payload: Option<&BoundedPayload>, key: &str) -> Option<i64> {
    payload
        .and_then(|payload| payload.as_value().get(key))
        .and_then(Value::as_i64)
        .filter(|value| *value >= 0)
}

fn is_unbound_pending(current: &UsageReconciliation) -> bool {
    current.cost_record_id.is_none()
        && current.actual_cost_minor.is_none()
        && current.provider_usage.is_none()
        && current.pricing.is_none()
        && current.currency.is_none()
}

fn payload_difference(
    current: &UsageReconciliation,
    request: &ReconciliationRequest,
) -> Option<ReconciliationConflictReason> {
    if current.actual_cost_minor != request.actual_cost_minor {
        return Some(ReconciliationConflictReason::ActualCostMismatch);
    }
    if current.provider_usage != request.provider_usage {
        return Some(ReconciliationConflictReason::ProviderUsageMismatch);
    }
    if current.pricing != request.pricing {
        return Some(ReconciliationConflictReason::PricingVersionMismatch);
    }
    if current.currency != request.currency {
        return Some(ReconciliationConflictReason::CurrencyMismatch);
    }
    None
}

fn event_identity_difference(
    event: &ReconciliationIdentity,
    request: &ReconciliationIdentity,
) -> Option<ReconciliationConflictReason> {
    if event.source != request.source {
        return Some(ReconciliationConflictReason::SourceMismatch);
    }
    if !optional_values_match(event.request_id.as_deref(), request.request_id.as_deref())
        || !optional_values_match(event.run_id.as_deref(), request.run_id.as_deref())
    {
        return Some(ReconciliationConflictReason::IdentityMismatch);
    }
    if let (Some(event_external), Some(request_external)) =
        (&event.external_id, &request.external_id)
        && event_external != request_external
    {
        return Some(ReconciliationConflictReason::ExternalIdMismatch);
    }
    None
}

fn identity_difference_exact(
    current: &ReconciliationIdentity,
    request: &ReconciliationIdentity,
) -> ReconciliationConflictReason {
    if current.source != request.source {
        return ReconciliationConflictReason::SourceMismatch;
    }
    if current.request_id != request.request_id || current.run_id != request.run_id {
        return ReconciliationConflictReason::IdentityMismatch;
    }
    if current.external_id != request.external_id {
        return ReconciliationConflictReason::ExternalIdMismatch;
    }
    ReconciliationConflictReason::IdentityMismatch
}

fn optional_values_match(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left == right,
        _ => true,
    }
}

fn timestamp_text(value: &str, field: &'static str) -> Result<(), UsageModelError> {
    required_text(value, field, 64)?;
    if !is_rfc3339_utc(value) {
        return Err(UsageModelError::InvalidField(field));
    }
    Ok(())
}

fn is_rfc3339_utc(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return false;
    }
    if !digits(bytes, 0, 4)
        || !digits(bytes, 5, 2)
        || !digits(bytes, 8, 2)
        || !digits(bytes, 11, 2)
        || !digits(bytes, 14, 2)
        || !digits(bytes, 17, 2)
    {
        return false;
    }
    let year = number(bytes, 0, 4);
    let month = number(bytes, 5, 2);
    let day = number(bytes, 8, 2);
    let hour = number(bytes, 11, 2);
    let minute = number(bytes, 14, 2);
    let second = number(bytes, 17, 2);
    if !(1..=12).contains(&month)
        || hour > 23
        || minute > 59
        || second > 60
        || day == 0
        || day > days_in_month(year, month)
    {
        return false;
    }
    match bytes.get(19) {
        Some(b'Z') if bytes.len() == 20 => true,
        Some(b'.')
            if bytes.len() > 20
                && bytes.last() == Some(&b'Z')
                && bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit) =>
        {
            true
        }
        _ => false,
    }
}

fn digits(bytes: &[u8], start: usize, width: usize) -> bool {
    bytes
        .get(start..start + width)
        .is_some_and(|slice| slice.iter().all(u8::is_ascii_digit))
}

fn number(bytes: &[u8], start: usize, width: usize) -> u32 {
    bytes[start..start + width]
        .iter()
        .fold(0, |value, digit| value * 10 + u32::from(digit - b'0'))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100)) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn required_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), UsageModelError> {
    if value.trim().is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(UsageModelError::InvalidField(field));
    }
    Ok(())
}

fn optional_text(
    value: Option<&str>,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), UsageModelError> {
    if let Some(value) = value {
        required_text(value, field, max_bytes)?;
    }
    Ok(())
}

fn validate_provider_usage_payload(
    payload: Option<&BoundedPayload>,
) -> Result<(), UsageModelError> {
    if payload.is_some_and(|payload| !payload.as_value().is_object()) {
        return Err(UsageModelError::InvalidField("provider_usage"));
    }
    Ok(())
}

fn validate_optional_nonnegative(
    value: Option<i64>,
    field: &'static str,
) -> Result<(), UsageModelError> {
    if let Some(value) = value
        && value < 0
    {
        return Err(UsageModelError::InvalidField(field));
    }
    Ok(())
}

fn validate_nonnegative(value: i64, field: &'static str) -> Result<(), UsageModelError> {
    if value < 0 {
        return Err(UsageModelError::InvalidField(field));
    }
    Ok(())
}

fn validate_currency(value: &str, field: &'static str) -> Result<(), UsageModelError> {
    if !(3..=12).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(UsageModelError::InvalidField(field));
    }
    Ok(())
}

fn serialized_len(value: &Value) -> Result<usize, UsageModelError> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|_| UsageModelError::InvalidField("payload"))
}

fn redact_value(value: &Value, key: Option<&str>, depth: usize) -> Value {
    if depth >= MAX_PAYLOAD_DEPTH && (value.is_array() || value.is_object()) {
        return Value::String(TRUNCATED_VALUE.to_owned());
    }
    if let Some(key) = key
        && is_sensitive_key(key)
    {
        return Value::String(REDACTED_VALUE.to_owned());
    }
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => value.clone(),
        Value::String(value) => {
            if value.chars().any(char::is_control) {
                Value::String(REDACTED_VALUE.to_owned())
            } else if key.is_some_and(is_safe_string_key) {
                Value::String(bounded_string(value))
            } else {
                Value::String(REDACTED_VALUE.to_owned())
            }
        }
        Value::Array(values) => {
            let mut output = Vec::with_capacity(values.len().min(MAX_PAYLOAD_ARRAY_ITEMS + 1));
            for value in values.iter().take(MAX_PAYLOAD_ARRAY_ITEMS) {
                output.push(redact_value(value, None, depth + 1));
            }
            if values.len() > MAX_PAYLOAD_ARRAY_ITEMS {
                output.push(Value::String(TRUNCATED_VALUE.to_owned()));
            }
            Value::Array(output)
        }
        Value::Object(object) => {
            let mut output = Map::new();
            for (count, (child_key, child_value)) in object.iter().enumerate() {
                if count >= MAX_PAYLOAD_KEYS {
                    output.insert(TRUNCATED_KEY.to_owned(), Value::Bool(true));
                    break;
                }
                let child_key = if child_key.len() > MAX_PAYLOAD_STRING_BYTES
                    || child_key.chars().any(char::is_control)
                {
                    "[redacted_key]".to_owned()
                } else {
                    child_key.clone()
                };
                if is_sensitive_key(&child_key) {
                    output.insert(child_key, Value::String(REDACTED_VALUE.to_owned()));
                } else {
                    output.insert(
                        child_key.clone(),
                        redact_value(child_value, Some(&child_key), depth + 1),
                    );
                }
            }
            Value::Object(output)
        }
    }
}

fn bounded_string(value: &str) -> String {
    if value.len() <= MAX_PAYLOAD_STRING_BYTES {
        return value.to_owned();
    }
    let mut end = MAX_PAYLOAD_STRING_BYTES;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &value[..end])
}

fn normalized_key(key: &str) -> String {
    let mut normalized = String::with_capacity(key.len());
    for character in key.chars() {
        if character.is_ascii_alphanumeric() {
            normalized.push(character.to_ascii_lowercase());
        } else {
            normalized.push('_');
        }
    }
    normalized
}

fn is_safe_token_key(key: &str) -> bool {
    matches!(
        normalized_key(key).as_str(),
        "input_tokens"
            | "output_tokens"
            | "cached_tokens"
            | "prompt_tokens"
            | "completion_tokens"
            | "total_tokens"
            | "token_count"
            | "tokens"
    )
}

fn is_safe_string_key(key: &str) -> bool {
    matches!(
        normalized_key(key).as_str(),
        "provider_name"
            | "provider_id"
            | "model"
            | "model_id"
            | "pricing_version"
            | "currency"
            | "request_id"
            | "response_id"
            | "external_id"
            | "finish_reason"
            | "status"
            | "cache_status"
            | "service_tier"
            | "region"
            | "source"
            | "usage_type"
            | "content_ref"
            | "content_length"
            | "argument_count"
    )
}

fn is_sensitive_key(key: &str) -> bool {
    let key = normalized_key(key);
    if is_safe_token_key(&key) || is_safe_string_key(&key) {
        return false;
    }
    if matches!(
        key.as_str(),
        "prompt"
            | "prompts"
            | "response"
            | "responses"
            | "content"
            | "contents"
            | "text"
            | "input"
            | "output"
            | "arguments"
            | "argument"
            | "tool_arguments"
            | "tool_input"
            | "tool_output"
            | "message"
            | "messages"
            | "body"
            | "raw"
            | "raw_body"
            | "data"
            | "file"
            | "files"
            | "filename"
            | "file_content"
            | "secret"
            | "secrets"
            | "token"
            | "access_token"
            | "refresh_token"
            | "authorization"
            | "credential"
            | "credentials"
            | "password"
            | "api_key"
            | "apikey"
            | "cookie"
            | "set_cookie"
            | "headers"
    ) {
        return true;
    }
    key.ends_with("_prompt")
        || key.ends_with("_response")
        || key.ends_with("_content")
        || key.ends_with("_arguments")
        || key.ends_with("_body")
        || key.ends_with("_secret")
        || key.contains("password")
        || key.contains("credential")
        || key.contains("authorization")
}

#[cfg(test)]
#[path = "usage_tests.rs"]
mod tests;
