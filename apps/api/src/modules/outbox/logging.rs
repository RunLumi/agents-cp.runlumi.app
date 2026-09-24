use crate::core::EventEnvelope;

/// Redacted structured diagnostic record. It contains only bounded contract
/// metadata, never an event payload, request body, or provider error string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxLog {
    pub action: &'static str,
    pub event_id: String,
    pub event_type: String,
    pub request_id: String,
    pub correlation_id: String,
    pub attempt_count: u32,
    pub error_code: Option<String>,
}

impl OutboxLog {
    pub fn for_event(
        event: &EventEnvelope,
        action: &'static str,
        attempt_count: u32,
        error_code: Option<&str>,
    ) -> Self {
        Self {
            action,
            event_id: event.event_id.as_str().to_owned(),
            event_type: event.event_type.as_str().to_owned(),
            request_id: event.request_id.as_str().to_owned(),
            correlation_id: event.correlation_id.as_str().to_owned(),
            attempt_count,
            error_code: error_code.map(str::to_owned),
        }
    }
}

/// Logging port implemented by the Worker adapter.
pub trait OutboxLogger {
    fn log(&self, record: OutboxLog);
}
