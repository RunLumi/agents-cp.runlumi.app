use std::fmt;

use serde::{Deserialize, Serialize};

use super::{ActorId, CorrelationId, DeviceId, OrganizationId, RequestId, SessionId, Timestamp};

/// Actor categories defined by the P01 request/event contract.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    User,
    ServiceAccount,
    Support,
    System,
    Anonymous,
}

impl fmt::Debug for ActorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::User => "User",
            Self::ServiceAccount => "ServiceAccount",
            Self::Support => "Support",
            Self::System => "System",
            Self::Anonymous => "Anonymous",
        })
    }
}

/// Actor identity attached by trusted request processing.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorContext {
    #[serde(rename = "type")]
    pub actor_type: ActorType,
    #[serde(rename = "id")]
    pub actor_id: Option<ActorId>,
    pub effective_user_id: Option<ActorId>,
}

impl ActorContext {
    pub const fn anonymous() -> Self {
        Self {
            actor_type: ActorType::Anonymous,
            actor_id: None,
            effective_user_id: None,
        }
    }

    pub const fn system() -> Self {
        Self {
            actor_type: ActorType::System,
            actor_id: None,
            effective_user_id: None,
        }
    }
}

impl fmt::Debug for ActorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActorContext")
            .field("actor_type", &self.actor_type)
            .field("actor_id", &self.actor_id.as_ref().map(|_| "[redacted]"))
            .field(
                "effective_user_id",
                &self.effective_user_id.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

/// Request-scoped identity and correlation context created at the trusted HTTP boundary.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestContext {
    pub request_id: RequestId,
    pub correlation_id: CorrelationId,
    pub received_at: Timestamp,
    pub actor: Option<ActorContext>,
    pub organization_id: Option<OrganizationId>,
    pub device_id: Option<DeviceId>,
    pub session_id: Option<SessionId>,
}

impl RequestContext {
    pub fn new(
        request_id: RequestId,
        correlation_id: CorrelationId,
        received_at: Timestamp,
    ) -> Self {
        Self {
            request_id,
            correlation_id,
            received_at,
            actor: None,
            organization_id: None,
            device_id: None,
            session_id: None,
        }
    }
}

impl fmt::Debug for RequestContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestContext")
            .field("request_id", &self.request_id)
            .field("correlation_id", &self.correlation_id)
            .field("received_at", &self.received_at)
            .field("actor_present", &self.actor.is_some())
            .field("organization_present", &self.organization_id.is_some())
            .field("device_present", &self.device_id.is_some())
            .field("session_present", &self.session_id.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn request_context_and_actor_serialize_with_contract_names() {
        let mut context = RequestContext::new(
            "req_0123456789abcdef0123456789abcdef".parse().unwrap(),
            CorrelationId::new("req_0123456789abcdef0123456789abcdef").unwrap(),
            "2026-09-24T12:00:00.000Z".parse().unwrap(),
        );
        context.actor = Some(ActorContext::anonymous());
        assert_eq!(
            serde_json::to_value(context).unwrap(),
            json!({
                "request_id": "req_0123456789abcdef0123456789abcdef",
                "correlation_id": "req_0123456789abcdef0123456789abcdef",
                "received_at": "2026-09-24T12:00:00.000Z",
                "actor": { "type": "anonymous", "id": null, "effective_user_id": null },
                "organization_id": null,
                "device_id": null,
                "session_id": null
            })
        );
    }

    #[test]
    fn debug_output_omits_actor_identifiers() {
        let actor = ActorContext {
            actor_type: ActorType::User,
            actor_id: Some("private-actor-id".parse().unwrap()),
            effective_user_id: Some("private-user-id".parse().unwrap()),
        };
        assert!(!format!("{actor:?}").contains("private-actor-id"));
        assert!(!format!("{actor:?}").contains("private-user-id"));
    }
}
