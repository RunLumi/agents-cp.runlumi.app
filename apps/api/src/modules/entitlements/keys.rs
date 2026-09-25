//! The stable Lumi entitlement key registry and its typed, bounded values.
//!
//! WHY a closed registry instead of free-form strings: P06-CR-002 forbids
//! payment-provider product/price IDs from ever becoming a product concept.
//! Two independent guards enforce that here. First, [`EntitlementKey`] only
//! accepts lowercase dotted Lumi identifiers, so a provider identifier
//! (`prod_…`, `price_…`, `cus_…`) is structurally impossible: it has no dot
//! segment boundary and uses `_`/uppercase. Second, an *unregistered* but
//! well-formed key is still refused by [`baseline_value_type`] and
//! [`baseline_definition`], so a caller cannot invent a key that silently
//! behaves like a grant. Both guards fail closed.
//!
//! Values are typed. The frozen wire form is a native JSON scalar per key
//! (`{"automations.max_active": 100, "webhooks.enabled": true}`), so
//! [`EntitlementValue`] serializes and deserializes as that scalar rather than
//! as an internally tagged object. A value whose type does not match the
//! registered definition is rejected instead of being coerced.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de, de::Visitor};

use crate::core::{ProjectId, UserId};

use super::EntitlementError;

/// Ceiling on the serialized length of one entitlement key, in bytes.
pub const MAX_ENTITLEMENT_KEY_BYTES: usize = 64;

/// Maximum dotted segments in one entitlement key (`a.b.c` shape).
pub const MAX_ENTITLEMENT_KEY_SEGMENTS: usize = 4;

/// Minimum dotted segments in one entitlement key. A single-segment token is
/// never a valid Lumi key, which is one more reason a bare provider product or
/// price identifier cannot be mistaken for one.
pub const MIN_ENTITLEMENT_KEY_SEGMENTS: usize = 2;

/// Ceiling on a single dotted segment, in bytes.
pub const MAX_ENTITLEMENT_KEY_SEGMENT_BYTES: usize = 24;

/// Ceiling on a bounded string entitlement value, in bytes.
pub const MAX_BOUNDED_STRING_VALUE_BYTES: usize = 256;

/// Ceiling on a human-readable entitlement definition description, in bytes.
pub const MAX_ENTITLEMENT_DESCRIPTION_BYTES: usize = 240;

/// Ceiling on an entitlement definition unit suffix, in bytes.
pub const MAX_ENTITLEMENT_UNIT_BYTES: usize = 32;

/// Ceiling on an entitlement scope identifier, in bytes.
pub const MAX_ENTITLEMENT_SCOPE_ID_BYTES: usize = 128;

/// Lower bound for an integer entitlement value. A negative limit has no
/// product meaning, and a negative ceiling would grant capacity.
pub const MIN_ENTITLEMENT_VALUE_INTEGER: i64 = 0;

/// Upper bound for an integer entitlement value. Retentions, seat counts, and
/// concurrency limits above this number are never a real commercial plan and
/// would overflow the projection arithmetic.
pub const MAX_ENTITLEMENT_VALUE_INTEGER: i64 = 1_000_000_000;

/// Number of keys in the frozen P06 baseline registry.
pub const BASELINE_ENTITLEMENT_KEY_COUNT: usize = 19;

// Baseline key constants. Callers reference these instead of retyping wire
// strings; the registry itself is the only place a key literal may appear.
pub const ORG_MAX_MEMBERS: &str = "org.max_members";
pub const PROJECTS_MAX_ACTIVE: &str = "projects.max_active";
pub const INFERENCE_PLATFORM_MANAGED: &str = "inference.platform_managed";
pub const INFERENCE_BYOK: &str = "inference.byok";
pub const AUDIT_RETENTION_DAYS: &str = "audit.retention_days";
pub const AUTOMATIONS_MAX_ACTIVE: &str = "automations.max_active";
pub const DEVICES_MAX_ENROLLED: &str = "devices.max_enrolled";
pub const EXPORTS_ENABLED: &str = "exports.enabled";
pub const DELETION_SELF_SERVICE: &str = "deletion.self_service";
pub const WEBHOOKS_ENABLED: &str = "webhooks.enabled";
pub const SSO_ENABLED: &str = "sso.enabled";
pub const SCIM_ENABLED: &str = "scim.enabled";
pub const WEBHOOKS_MAX_ENDPOINTS: &str = "webhooks.max_endpoints";
pub const AUTOMATIONS_MAX_CONCURRENT: &str = "automations.max_concurrent";
pub const AUTOMATIONS_OFF_PEAK_ENABLED: &str = "automations.off_peak_enabled";
pub const NOTIFICATIONS_IN_APP_ENABLED: &str = "notifications.in_app_enabled";
pub const NOTIFICATIONS_EMAIL_ENABLED: &str = "notifications.email_enabled";
pub const DATA_EXPORT_ENABLED: &str = "data.export.enabled";
pub const DATA_DELETION_SELF_SERVICE: &str = "data.deletion.self_service";

/// A validated, stable Lumi entitlement key.
///
/// Keys are lowercase dotted identifiers, two to
/// [`MAX_ENTITLEMENT_KEY_SEGMENTS`] segments, each starting with a lowercase
/// letter and continuing with lowercase letters, digits, or `_`. This shape is
/// deliberately incompatible with a payment-provider product/price/plan ID.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct EntitlementKey(String);

impl EntitlementKey {
    /// Construct a key, rejecting any shape outside the frozen Lumi grammar.
    pub fn new(value: impl Into<String>) -> Result<Self, EntitlementError> {
        let value = value.into();
        if value.is_empty() {
            return Err(EntitlementError::InvalidEntitlementKey);
        }
        if value.len() > MAX_ENTITLEMENT_KEY_BYTES {
            return Err(EntitlementError::EntitlementKeyTooLong);
        }
        if !value.is_ascii() {
            return Err(EntitlementError::InvalidEntitlementKey);
        }

        let mut segments = 0_usize;
        for segment in value.split('.') {
            segments += 1;
            if segments > MAX_ENTITLEMENT_KEY_SEGMENTS
                || segment.is_empty()
                || segment.len() > MAX_ENTITLEMENT_KEY_SEGMENT_BYTES
                || !segment
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_lowercase())
                || !segment.bytes().all(valid_segment_byte)
            {
                return Err(EntitlementError::InvalidEntitlementKey);
            }
        }
        if segments < MIN_ENTITLEMENT_KEY_SEGMENTS {
            return Err(EntitlementError::InvalidEntitlementKey);
        }
        Ok(Self(value))
    }

    /// Wire entry point. Identical to [`EntitlementKey::new`] so callers that
    /// read a key from a payload do not need a second validation path.
    pub fn parse(value: &str) -> Result<Self, EntitlementError> {
        Self::new(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Number of dotted segments, always within the frozen range.
    pub fn segment_count(&self) -> usize {
        self.0.matches('.').count() + 1
    }

    /// Leading namespace segment (`org` in `org.max_members`). Used only for
    /// diagnostics and grouping; it is never an authorization decision input.
    pub fn namespace(&self) -> &str {
        self.0.split('.').next().unwrap_or_default()
    }

    /// Fail-closed registry membership check.
    ///
    /// `false` means the key grants nothing: the evaluator refuses to resolve
    /// it, and the definition lookup returns `None`.
    pub fn is_registered(&self) -> bool {
        is_baseline_key(self.as_str())
    }
}

fn valid_segment_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
}

impl fmt::Debug for EntitlementKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EntitlementKey").field(&self.0).finish()
    }
}

impl fmt::Display for EntitlementKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for EntitlementKey {
    type Err = EntitlementError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for EntitlementKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// The frozen entitlement value types. A value is never inferred from a
/// provider ID and never coerced between types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntitlementValueType {
    Boolean,
    Integer,
    String,
}

impl EntitlementValueType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Boolean => "boolean",
            Self::Integer => "integer",
            Self::String => "string",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "boolean" => Some(Self::Boolean),
            "integer" => Some(Self::Integer),
            "string" => Some(Self::String),
            _ => None,
        }
    }

    /// The value a protected capability of this type resolves to when nothing
    /// grants it. Always fail-closed.
    pub const fn fail_closed_value(self) -> EntitlementValue {
        match self {
            Self::Boolean => EntitlementValue::Boolean(false),
            Self::Integer => EntitlementValue::Integer(0),
            Self::String => EntitlementValue::BoundedString(String::new()),
        }
    }
}

/// A bounded, typed entitlement value.
///
/// Integers are bounded to
/// `[`[`MIN_ENTITLEMENT_VALUE_INTEGER`]`,`[`MAX_ENTITLEMENT_VALUE_INTEGER`]`]
/// and strings to [`MAX_BOUNDED_STRING_VALUE_BYTES`], so an entitlement
/// projection can never carry unbounded text into a policy snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum EntitlementValue {
    Boolean(bool),
    Integer(i64),
    BoundedString(String),
}

impl EntitlementValue {
    /// A boolean value is always representable.
    pub const fn boolean(value: bool) -> Self {
        Self::Boolean(value)
    }

    /// Const integer constructor for the frozen registry baseline only.
    ///
    /// The registry is validated by test and by
    /// [`EntitlementDefinition::validate`]; every runtime caller must use
    /// [`EntitlementValue::integer`] so the bound is enforced at the boundary.
    const fn const_integer(value: i64) -> Self {
        Self::Integer(value)
    }

    pub fn integer(value: i64) -> Result<Self, EntitlementError> {
        if !(MIN_ENTITLEMENT_VALUE_INTEGER..=MAX_ENTITLEMENT_VALUE_INTEGER).contains(&value) {
            return Err(EntitlementError::EntitlementValueOutOfRange);
        }
        Ok(Self::Integer(value))
    }

    pub fn bounded_string(value: impl Into<String>) -> Result<Self, EntitlementError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_BOUNDED_STRING_VALUE_BYTES
            || !value.is_ascii()
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(EntitlementError::EntitlementValueTooLong);
        }
        Ok(Self::BoundedString(value))
    }

    pub const fn value_type(&self) -> EntitlementValueType {
        match self {
            Self::Boolean(_) => EntitlementValueType::Boolean,
            Self::Integer(_) => EntitlementValueType::Integer,
            Self::BoundedString(_) => EntitlementValueType::String,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Boolean(value) => Some(*value),
            Self::Integer(_) | Self::BoundedString(_) => None,
        }
    }

    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => Some(*value),
            Self::Boolean(_) | Self::BoundedString(_) => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::BoundedString(value) => Some(value.as_str()),
            Self::Boolean(_) | Self::Integer(_) => None,
        }
    }

    /// True when the value grants nothing for a protected capability.
    pub const fn is_fail_closed(&self) -> bool {
        match self {
            Self::Boolean(value) => !*value,
            Self::Integer(value) => *value == 0,
            Self::BoundedString(value) => value.is_empty(),
        }
    }
}

// The frozen wire form is a native JSON scalar, so the enum is hand-serialized
// instead of using an internally tagged representation.
impl Serialize for EntitlementValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Boolean(value) => serializer.serialize_bool(*value),
            Self::Integer(value) => serializer.serialize_i64(*value),
            Self::BoundedString(value) => serializer.serialize_str(value),
        }
    }
}

impl<'de> Deserialize<'de> for EntitlementValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EntitlementValueVisitor;

        impl Visitor<'_> for EntitlementValueVisitor {
            type Value = EntitlementValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an entitlement boolean, integer, or bounded string")
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(EntitlementValue::Boolean(value))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                EntitlementValue::integer(value).map_err(de::Error::custom)
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                let value = i64::try_from(value)
                    .map_err(|_| de::Error::custom(EntitlementError::EntitlementValueOutOfRange))?;
                EntitlementValue::integer(value).map_err(de::Error::custom)
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                EntitlementValue::bounded_string(value).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_any(EntitlementValueVisitor)
    }
}

/// The scope an entitlement key or grant is resolved at.
///
/// A grant may narrow a definition's scope (for example a project-level
/// automation allowance inside an organization key) but may never widen it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntitlementScope {
    Organization,
    Project(ProjectId),
    User(UserId),
}

impl EntitlementScope {
    pub fn organization() -> Self {
        Self::Organization
    }

    pub fn project(project_id: ProjectId) -> Self {
        Self::Project(project_id)
    }

    pub fn user(user_id: UserId) -> Self {
        Self::User(user_id)
    }

    /// The opaque scope identifier, or `None` for the organization scope.
    pub fn scope_id(&self) -> Option<&str> {
        match self {
            Self::Organization => None,
            Self::Project(project_id) => Some(project_id.as_str()),
            Self::User(user_id) => Some(user_id.as_str()),
        }
    }

    /// Organization < project < user. Used only as a deterministic tie-breaker
    /// between two grants of the same source and key.
    pub const fn specificity(&self) -> u8 {
        match self {
            Self::Organization => 0,
            Self::Project(_) => 1,
            Self::User(_) => 2,
        }
    }

    /// True when `self` is the same scope as, or a broader scope than, `other`.
    pub fn contains(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Organization, _) => true,
            (Self::Project(left), Self::Project(right)) => left == right,
            (Self::User(left), Self::User(right)) => left == right,
            (Self::Project(_) | Self::User(_), _) => false,
        }
    }
}

/// One registry row: a stable Lumi entitlement key, its value type, and the
/// platform baseline value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementDefinition {
    pub key: EntitlementKey,
    pub value_type: EntitlementValueType,
    /// Platform baseline value. It is the fail-closed value for a protected
    /// key, so an unresolved key denies rather than defaulting to permissive.
    pub default: EntitlementValue,
    pub scope: EntitlementScope,
    /// `true` when a missing value must fail closed instead of falling through
    /// to a permissive default. Every P06 baseline capability is protected.
    pub protected: bool,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

impl EntitlementDefinition {
    /// Exact type match, never a coercion. `true`/`1` are different products.
    pub fn type_matches(&self, value: &EntitlementValue) -> bool {
        self.value_type == value.value_type()
    }

    /// The value a protected key resolves to when nothing grants it.
    pub fn fail_closed_value(&self) -> &EntitlementValue {
        &self.default
    }

    /// Validate a definition that arrived from persistence rather than from
    /// the compiled registry.
    pub fn validate(&self) -> Result<(), EntitlementError> {
        if !self.key.is_registered() {
            return Err(EntitlementError::UnknownEntitlementKey);
        }
        if !self.type_matches(&self.default) {
            return Err(EntitlementError::EntitlementTypeMismatch);
        }
        if self.default.as_integer().is_some_and(|value| {
            !(MIN_ENTITLEMENT_VALUE_INTEGER..=MAX_ENTITLEMENT_VALUE_INTEGER).contains(&value)
        }) {
            return Err(EntitlementError::EntitlementValueOutOfRange);
        }
        if self.description.is_empty() || self.description.len() > MAX_ENTITLEMENT_DESCRIPTION_BYTES
        {
            return Err(EntitlementError::InvalidEntitlementValue);
        }
        if self
            .unit
            .as_deref()
            .is_some_and(|unit| unit.is_empty() || unit.len() > MAX_ENTITLEMENT_UNIT_BYTES)
        {
            return Err(EntitlementError::InvalidEntitlementValue);
        }
        Ok(())
    }
}

/// One compiled baseline row. Kept allocation-free so the hot evaluator path
/// can resolve a key's type without building owned values.
pub(crate) struct BaselineEntry {
    pub(crate) key: &'static str,
    pub(crate) value_type: EntitlementValueType,
    pub(crate) default: EntitlementValue,
    pub(crate) protected: bool,
    pub(crate) description: &'static str,
    pub(crate) unit: Option<&'static str>,
}

const fn baseline(
    key: &'static str,
    value_type: EntitlementValueType,
    default: EntitlementValue,
    description: &'static str,
    unit: Option<&'static str>,
) -> BaselineEntry {
    BaselineEntry {
        key,
        value_type,
        default,
        protected: true,
        description,
        unit,
    }
}

/// The frozen P06 baseline registry.
///
/// Every P06 capability key is here, with its wire value type and a fail-closed
/// platform baseline. The array is a `static` (not a `const`) so lookups return
/// `&'static` data with no per-call allocation.
static BASELINE_ENTITLEMENTS: [BaselineEntry; BASELINE_ENTITLEMENT_KEY_COUNT] = [
    baseline(
        ORG_MAX_MEMBERS,
        EntitlementValueType::Integer,
        EntitlementValue::const_integer(0),
        "Maximum billable members a plan may seat in one organization.",
        Some("members"),
    ),
    baseline(
        PROJECTS_MAX_ACTIVE,
        EntitlementValueType::Integer,
        EntitlementValue::const_integer(0),
        "Maximum non-archived projects in one organization.",
        Some("projects"),
    ),
    baseline(
        INFERENCE_PLATFORM_MANAGED,
        EntitlementValueType::Boolean,
        EntitlementValue::boolean(false),
        "Inference over Lumi platform-managed credentials and routes.",
        None,
    ),
    baseline(
        INFERENCE_BYOK,
        EntitlementValueType::Boolean,
        EntitlementValue::boolean(false),
        "Inference over organization-managed credentials (BYOK).",
        None,
    ),
    baseline(
        AUDIT_RETENTION_DAYS,
        EntitlementValueType::Integer,
        EntitlementValue::const_integer(0),
        "Minimum audit and security event retention for the organization.",
        Some("days"),
    ),
    baseline(
        AUTOMATIONS_MAX_ACTIVE,
        EntitlementValueType::Integer,
        EntitlementValue::const_integer(0),
        "Maximum active (non-paused) automations in one organization.",
        Some("automations"),
    ),
    baseline(
        DEVICES_MAX_ENROLLED,
        EntitlementValueType::Integer,
        EntitlementValue::const_integer(0),
        "Maximum enrolled managed devices in one organization.",
        Some("devices"),
    ),
    baseline(
        EXPORTS_ENABLED,
        EntitlementValueType::Boolean,
        EntitlementValue::boolean(false),
        "Asynchronous organization data export.",
        None,
    ),
    baseline(
        DELETION_SELF_SERVICE,
        EntitlementValueType::Boolean,
        EntitlementValue::boolean(false),
        "Self-service account and organization deletion requests.",
        None,
    ),
    baseline(
        WEBHOOKS_ENABLED,
        EntitlementValueType::Boolean,
        EntitlementValue::boolean(false),
        "Organization webhook endpoints and delivery.",
        None,
    ),
    baseline(
        SSO_ENABLED,
        EntitlementValueType::Boolean,
        EntitlementValue::boolean(false),
        "Organization SAML single sign-on.",
        None,
    ),
    baseline(
        SCIM_ENABLED,
        EntitlementValueType::Boolean,
        EntitlementValue::boolean(false),
        "Organization SCIM user provisioning.",
        None,
    ),
    baseline(
        WEBHOOKS_MAX_ENDPOINTS,
        EntitlementValueType::Integer,
        EntitlementValue::const_integer(0),
        "Maximum enabled webhook endpoints in one organization.",
        Some("endpoints"),
    ),
    baseline(
        AUTOMATIONS_MAX_CONCURRENT,
        EntitlementValueType::Integer,
        EntitlementValue::const_integer(0),
        "Maximum concurrently executing automations in one organization.",
        Some("runs"),
    ),
    baseline(
        AUTOMATIONS_OFF_PEAK_ENABLED,
        EntitlementValueType::Boolean,
        EntitlementValue::boolean(false),
        "Provider-ticket off-peak automation execution.",
        None,
    ),
    baseline(
        NOTIFICATIONS_IN_APP_ENABLED,
        EntitlementValueType::Boolean,
        EntitlementValue::boolean(false),
        "In-app notification center delivery.",
        None,
    ),
    baseline(
        NOTIFICATIONS_EMAIL_ENABLED,
        EntitlementValueType::Boolean,
        EntitlementValue::boolean(false),
        "Email notification delivery.",
        None,
    ),
    baseline(
        DATA_EXPORT_ENABLED,
        EntitlementValueType::Boolean,
        EntitlementValue::boolean(false),
        "P06 data-governance export jobs, distinct from the baseline exports key.",
        None,
    ),
    baseline(
        DATA_DELETION_SELF_SERVICE,
        EntitlementValueType::Boolean,
        EntitlementValue::boolean(false),
        "P06 data-governance deletion jobs, distinct from the baseline deletion key.",
        None,
    ),
];

fn find_baseline(key: &str) -> Option<&'static BaselineEntry> {
    BASELINE_ENTITLEMENTS.iter().find(|entry| entry.key == key)
}

/// Every compiled baseline row, in registry order.
///
/// `pub(crate)` so the effective-entitlement resolver can project the registry
/// without materializing 19 owned definitions (and their descriptions) on every
/// policy compile.
pub(crate) fn baseline_entries() -> impl Iterator<Item = &'static BaselineEntry> {
    BASELINE_ENTITLEMENTS.iter()
}

/// Fail-closed membership check over the compiled registry.
pub fn is_baseline_key(key: &str) -> bool {
    find_baseline(key).is_some()
}

/// Cheap, allocation-free value type lookup for the evaluator's hot path.
///
/// `None` for an unregistered key, which the evaluator treats as
/// `entitlement_not_granted` rather than as a permissive unknown.
pub fn baseline_value_type(key: &EntitlementKey) -> Option<EntitlementValueType> {
    find_baseline(key.as_str()).map(|entry| entry.value_type)
}

/// Full definition lookup. Allocation on the cold plan/snapshot compile path.
pub fn baseline_definition(key: &EntitlementKey) -> Option<EntitlementDefinition> {
    find_baseline(key.as_str()).map(definition_of)
}

/// Materialize one compiled registry row.
///
/// The key literal is a compile-time constant that the registry tests assert
/// satisfies [`EntitlementKey::new`], so this cannot fail at runtime.
fn definition_of(entry: &'static BaselineEntry) -> EntitlementDefinition {
    EntitlementDefinition {
        key: EntitlementKey::new(entry.key).expect("registry key is a valid Lumi key"),
        value_type: entry.value_type,
        default: entry.default.clone(),
        scope: EntitlementScope::organization(),
        protected: entry.protected,
        description: entry.description.to_owned(),
        unit: entry.unit.map(str::to_owned),
    }
}

/// Every baseline definition, in registry order. The plan compiler and the
/// `/orgs/{org_id}/entitlements` projection both start from this list.
pub fn all_baseline_definitions() -> Vec<EntitlementDefinition> {
    BASELINE_ENTITLEMENTS.iter().map(definition_of).collect()
}
