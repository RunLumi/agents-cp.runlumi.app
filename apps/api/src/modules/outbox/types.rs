use std::fmt;

use serde::{Deserialize, Serialize};

use crate::core::{EventEnvelope, EventId, Timestamp};

/// Durable delivery states from P01-CG. `Pending` is eligible for a bounded
/// retry sweep when `next_attempt_at` is due. `Queued` means publication was
/// observed; the queue remains at-least-once until a consumer acknowledges.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Pending,
    Queued,
    Delivered,
    DeadLetter,
}

impl DeliveryStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Delivered | Self::DeadLetter)
    }
}

/// A bounded stable error code suitable for logs and the outbox metadata.
/// Raw provider/database error strings must be mapped to a code before storage.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FailureCode(String);

impl FailureCode {
    pub const MAX_BYTES: usize = 128;

    pub fn new(value: impl Into<String>) -> Result<Self, FailureCodeError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > Self::MAX_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(FailureCodeError);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for FailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FailureCode").field(&self.0).finish()
    }
}

impl fmt::Display for FailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FailureCodeError;

impl fmt::Display for FailureCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid failure code")
    }
}

impl std::error::Error for FailureCodeError {}

/// A repository projection of an outbox row. The event's custom `Debug`
/// implementation redacts its payload, so logging this value is safe.
#[derive(Clone, PartialEq)]
pub struct OutboxRecord {
    pub event: EventEnvelope,
    pub delivery_status: DeliveryStatus,
    pub attempt_count: u32,
    pub next_attempt_at: Option<Timestamp>,
    pub queued_at: Option<Timestamp>,
    pub delivered_at: Option<Timestamp>,
    pub last_error_code: Option<FailureCode>,
}

impl OutboxRecord {
    pub fn event_id(&self) -> &EventId {
        &self.event.event_id
    }
}

impl fmt::Debug for OutboxRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboxRecord")
            .field("event", &self.event)
            .field("delivery_status", &self.delivery_status)
            .field("attempt_count", &self.attempt_count)
            .field("next_attempt_at", &self.next_attempt_at)
            .field("queued_at", &self.queued_at)
            .field("delivered_at", &self.delivered_at)
            .field("last_error_code", &self.last_error_code)
            .finish()
    }
}

/// Result of an optimistic, event-scoped state transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreTransition {
    /// The row was changed by this call.
    Applied,
    /// The row was absent, terminal, or no longer matched the expected state.
    /// This is a normal result under at-least-once delivery and concurrent sweeps.
    NotApplied,
}
