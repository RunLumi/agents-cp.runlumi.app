use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use super::{
    ActorContext, CoreError, CorrelationId, EventId, OrganizationId, RequestId, Timestamp,
};

/// Versioned lowercase dotted business event name, e.g. `foundation.check.requested.v1`.
#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct EventType(String);

impl EventType {
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        let Some((name, version)) = value.rsplit_once(".v") else {
            return Err(CoreError::InvalidEventType);
        };
        let valid_name = !name.is_empty()
            && name.split('.').all(|part| {
                !part.is_empty()
                    && part.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    })
            });
        if !valid_name
            || version.is_empty()
            || !version.bytes().all(|byte| byte.is_ascii_digit())
            || version.parse::<u32>().is_err()
        {
            return Err(CoreError::InvalidEventType);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EventType").field(&self.0).finish()
    }
}

impl FromStr for EventType {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for EventType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Versioned business event written transactionally to the outbox.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_id: EventId,
    pub event_type: EventType,
    pub occurred_at: Timestamp,
    pub request_id: RequestId,
    pub correlation_id: CorrelationId,
    pub actor: ActorContext,
    pub organization_id: Option<OrganizationId>,
    pub payload: Value,
}

impl fmt::Debug for EventEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventEnvelope")
            .field("event_id", &self.event_id)
            .field("event_type", &self.event_type)
            .field("occurred_at", &self.occurred_at)
            .field("request_id", &self.request_id)
            .field("correlation_id", &self.correlation_id)
            .field("actor", &self.actor)
            .field("organization_present", &self.organization_id.is_some())
            .field("payload", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn event() -> EventEnvelope {
        EventEnvelope {
            event_id: "evt_0123456789abcdef0123456789abcdef".parse().unwrap(),
            event_type: EventType::new("foundation.check.requested.v1").unwrap(),
            occurred_at: "2026-09-24T12:00:00.000Z".parse().unwrap(),
            request_id: "req_0123456789abcdef0123456789abcdef".parse().unwrap(),
            correlation_id: CorrelationId::new("req_0123456789abcdef0123456789abcdef").unwrap(),
            actor: ActorContext::anonymous(),
            organization_id: None,
            payload: json!({}),
        }
    }

    #[test]
    fn event_envelope_matches_frozen_json_contract() {
        assert_eq!(
            serde_json::to_value(event()).unwrap(),
            json!({
                "event_id": "evt_0123456789abcdef0123456789abcdef",
                "event_type": "foundation.check.requested.v1",
                "occurred_at": "2026-09-24T12:00:00.000Z",
                "request_id": "req_0123456789abcdef0123456789abcdef",
                "correlation_id": "req_0123456789abcdef0123456789abcdef",
                "actor": { "type": "anonymous", "id": null, "effective_user_id": null },
                "organization_id": null,
                "payload": {}
            })
        );
    }

    #[test]
    fn event_type_requires_lowercase_dotted_name_and_integer_version() {
        assert!(EventType::new("foundation.check.requested.v1").is_ok());
        for value in [
            "Foundation.check.v1",
            "foundation..check.v1",
            "foundation.check.v",
            "foundation.check.v1.beta",
        ] {
            assert!(EventType::new(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn event_debug_does_not_print_payload() {
        let mut event = event();
        event.payload = json!({ "private": "sensitive business data" });
        let debug = format!("{event:?}");
        assert!(!debug.contains("sensitive business data"));
        assert!(debug.contains("[redacted]"));
    }
}
