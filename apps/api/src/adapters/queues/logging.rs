use crate::modules::outbox::{OutboxLog, OutboxLogger};

/// Structured console logger for bounded outbox metadata. Event payloads and
/// platform error details are intentionally absent from the record schema.
#[derive(Clone, Copy, Debug, Default)]
pub struct WorkerOutboxLogger;

impl OutboxLogger for WorkerOutboxLogger {
    fn log(&self, record: OutboxLog) {
        let json = serde_json::json!({
            "level": if record.error_code.is_some() { "warn" } else { "info" },
            "component": "outbox",
            "action": record.action,
            "event_id": record.event_id,
            "event_type": record.event_type,
            "request_id": record.request_id,
            "correlation_id": record.correlation_id,
            "attempt_count": record.attempt_count,
            "error_code": record.error_code,
        });
        worker::console_log!("{}", json);
    }
}
