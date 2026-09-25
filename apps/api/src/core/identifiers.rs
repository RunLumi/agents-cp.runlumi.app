use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize};

use super::CoreError;

/// Validated resource identifier in `<lowercase-prefix>_<32 lowercase hex>` form.
///
/// The trusted runtime boundary is responsible for generating UUID v4 values.
/// Validation stays compatible with the illustrative compact ID in P01-CG,
/// whose hex sample does not encode RFC 4122 version/variant bits.
#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ResourceId(String);

impl ResourceId {
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        let (prefix, uuid) = value.split_once('_').ok_or(CoreError::InvalidResourceId)?;
        if prefix.is_empty()
            || prefix.len() > 32
            || !prefix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || uuid.len() != 32
            || !uuid
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(CoreError::InvalidResourceId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn prefix(&self) -> &str {
        // Safe because construction validates one underscore separator.
        self.0.split_once('_').map_or("", |(prefix, _)| prefix)
    }
}

impl fmt::Debug for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ResourceId").field(&self.0).finish()
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ResourceId {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for ResourceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

macro_rules! resource_id_type {
    ($name:ident, $error:ident, $required_prefix:expr) => {
        #[derive(Clone, PartialEq, Eq, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(ResourceId);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
                let id = ResourceId::new(value)?;
                if let Some(expected_prefix) = $required_prefix {
                    if id.prefix() != expected_prefix {
                        return Err(CoreError::$error);
                    }
                }
                Ok(Self(id))
            }

            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }

            pub fn resource_id(&self) -> &ResourceId {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = CoreError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

resource_id_type!(RequestId, InvalidRequestId, Some("req"));
resource_id_type!(EventId, InvalidEventId, Some("evt"));
// P01-CG intentionally left the P02 resource prefixes open. P02-CG freezes the
// following names; keeping them typed prevents accidental ID/prefix swaps.
resource_id_type!(UserId, InvalidResourceId, Some("usr"));
resource_id_type!(IdentityId, InvalidResourceId, Some("idn"));
resource_id_type!(OrganizationId, InvalidResourceId, Some("org"));
resource_id_type!(MembershipId, InvalidResourceId, Some("mem"));
resource_id_type!(InvitationId, InvalidResourceId, Some("inv"));
resource_id_type!(TeamId, InvalidResourceId, Some("team"));
resource_id_type!(TeamMemberId, InvalidResourceId, Some("tmem"));
resource_id_type!(ReauthenticationGrantId, InvalidResourceId, Some("rag"));
resource_id_type!(DeviceAuthorizationId, InvalidResourceId, Some("dev"));
resource_id_type!(SecurityEventId, InvalidResourceId, Some("sec"));
resource_id_type!(DeviceId, InvalidResourceId, Some("dev"));
resource_id_type!(SessionId, InvalidResourceId, Some("ses"));
// P03-CG (p03-cg-v1) freezes the device/project/policy prefixes. `dev_` keeps
// its P02 device-authorization meaning; managed devices are `dvc_`.
resource_id_type!(ManagedDeviceId, InvalidResourceId, Some("dvc"));
resource_id_type!(DeviceEnrollmentId, InvalidResourceId, Some("enr"));
resource_id_type!(ProjectId, InvalidResourceId, Some("prj"));
resource_id_type!(WorkspaceBindingId, InvalidResourceId, Some("wsb"));
resource_id_type!(PolicySnapshotId, InvalidResourceId, Some("pol"));
resource_id_type!(PolicyAckId, InvalidResourceId, Some("pak"));
// P04 catalog, credential, route, and usage identifiers.
resource_id_type!(ProviderId, InvalidResourceId, Some("prv"));
resource_id_type!(ProviderEndpointId, InvalidResourceId, Some("pe"));
resource_id_type!(ModelId, InvalidResourceId, Some("mdl"));
resource_id_type!(ModelAliasId, InvalidResourceId, Some("mal"));
resource_id_type!(CredentialId, InvalidResourceId, Some("cred"));
resource_id_type!(RouteId, InvalidResourceId, Some("rte"));
resource_id_type!(RouteVersionId, InvalidResourceId, Some("rtv"));
resource_id_type!(UsageEventId, InvalidResourceId, Some("use"));
resource_id_type!(BudgetId, InvalidResourceId, Some("bud"));
resource_id_type!(BudgetReservationId, InvalidResourceId, Some("bres"));
// P05-CG (p05-cg-v1) managed run, tool, approval, and accounting IDs.
resource_id_type!(AgentDefinitionId, InvalidResourceId, Some("agd"));
resource_id_type!(AgentSessionId, InvalidResourceId, Some("rse"));
resource_id_type!(RunId, InvalidResourceId, Some("run"));
resource_id_type!(RunEventId, InvalidResourceId, Some("rev"));
resource_id_type!(ArtifactRefId, InvalidResourceId, Some("art"));
resource_id_type!(ToolCallId, InvalidResourceId, Some("tcl"));
resource_id_type!(McpRegistrationId, InvalidResourceId, Some("mcp"));
resource_id_type!(ApprovalId, InvalidResourceId, Some("apr"));
resource_id_type!(CapabilityId, InvalidResourceId, Some("cap"));
resource_id_type!(ToolId, InvalidResourceId, Some("tool"));
resource_id_type!(ToolPolicyId, InvalidResourceId, Some("tpol"));
resource_id_type!(CostRecordId, InvalidResourceId, Some("cost"));
resource_id_type!(RateLimitPolicyId, InvalidResourceId, Some("rlp"));
resource_id_type!(UsageRollupId, InvalidResourceId, Some("url"));
// P06-CG (p06-cg-v1) automation, schedule revision, occurrence, and lease
// identifiers. `sch_` is an immutable schedule revision, not a live rule: a
// schedule edit mints a new revision and therefore a new occurrence slot.
resource_id_type!(AutomationId, InvalidResourceId, Some("aut"));
resource_id_type!(ScheduleRuleId, InvalidResourceId, Some("sch"));
resource_id_type!(OccurrenceId, InvalidResourceId, Some("occ"));
resource_id_type!(ExecutionLeaseId, InvalidResourceId, Some("lse"));
// P06-CG (p06-cg-v1) commercial identifiers. Provider account references stay
// adapter-private strings; these are Lumi-owned rows only. The prefix is a wire
// namespace, never an authorization signal, and a payment-provider product or
// price ID can never be spelled as one of these typed rows.
resource_id_type!(PlanId, InvalidResourceId, Some("plan"));
resource_id_type!(BillingAccountId, InvalidResourceId, Some("bac"));
resource_id_type!(
    ProviderEntitlementProjectionId,
    InvalidResourceId,
    Some("pep")
);
resource_id_type!(SubscriptionId, InvalidResourceId, Some("sub"));
resource_id_type!(EntitlementDefinitionId, InvalidResourceId, Some("ent"));
resource_id_type!(EntitlementGrantId, InvalidResourceId, Some("egr"));
resource_id_type!(LicenseSnapshotId, InvalidResourceId, Some("lic"));

/// Opaque actor/principal identifier supplied only by trusted identity context.
#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ActorId(String);

impl ActorId {
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(CoreError::InvalidActorId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ActorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ActorId([redacted])")
    }
}

impl fmt::Display for ActorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ActorId {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for ActorId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Validated opaque diagnostic correlation value from `X-Correlation-ID`.
#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct CorrelationId(String);

impl CorrelationId {
    /// Accepts 1–128 visible ASCII bytes so header values stay bounded and safe
    /// for structured diagnostics. The runtime may default this to RequestId.
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(CoreError::InvalidCorrelationId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CorrelationId").field(&self.0).finish()
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for CorrelationId {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for CorrelationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_ids_are_opaque_and_serialize_as_strings() {
        let id: ResourceId = "evt_0123456789abcdef0123456789abcdef".parse().unwrap();
        assert_eq!(id.prefix(), "evt");
        assert_eq!(
            serde_json::to_string(&id).unwrap(),
            "\"evt_0123456789abcdef0123456789abcdef\""
        );
    }

    #[test]
    fn invalid_resource_ids_fail_in_construction_and_deserialization() {
        for value in [
            "evt_0123456789abcdef0123456789abcde",        // too short
            "evt_0123456789ABCDEF0123456789abcdef",       // uppercase
            "evt_0123456789abcdef0123456789abcdeg",       // non-hex
            "evt_0123456789abcdef0123456789abcdef_extra", // extra separator
            "_0123456789abcdef0123456789abcdef",          // no prefix
        ] {
            assert!(ResourceId::new(value).is_err(), "accepted {value}");
            assert!(serde_json::from_str::<ResourceId>(&format!("\"{value}\"")).is_err());
        }
    }

    #[test]
    fn typed_resource_ids_enforce_their_frozen_prefixes() {
        assert!(RequestId::new("evt_0123456789abcdef0123456789abcdef").is_err());
        assert!(EventId::new("req_0123456789abcdef0123456789abcdef").is_err());
        assert_eq!(
            RequestId::new("req_0123456789abcdef0123456789abcdef")
                .unwrap()
                .as_str(),
            "req_0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn p05_resource_ids_keep_their_domain_prefixes() {
        assert!(AgentDefinitionId::new("agd_0123456789abcdef0123456789abcdef").is_ok());
        assert!(AgentSessionId::new("rse_0123456789abcdef0123456789abcdef").is_ok());
        assert!(RunId::new("run_0123456789abcdef0123456789abcdef").is_ok());
        assert!(RunEventId::new("rev_0123456789abcdef0123456789abcdef").is_ok());
        assert!(ApprovalId::new("apr_0123456789abcdef0123456789abcdef").is_ok());
        assert!(ToolId::new("tool_0123456789abcdef0123456789abcdef").is_ok());
        assert!(RunId::new("rse_0123456789abcdef0123456789abcdef").is_err());
    }

    #[test]
    fn correlation_ids_are_bounded_visible_ascii() {
        assert!(CorrelationId::new("bad\nvalue").is_err());
        assert!(CorrelationId::new("x".repeat(129)).is_err());
        assert_eq!(
            CorrelationId::new("trace-123").unwrap().as_str(),
            "trace-123"
        );
    }

    #[test]
    fn actor_ids_do_not_accept_controls_or_log_the_value() {
        assert!(ActorId::new("user\nsecret").is_err());
        let actor = ActorId::new("user-private-123").unwrap();
        assert!(!format!("{actor:?}").contains("user-private-123"));
    }
}
