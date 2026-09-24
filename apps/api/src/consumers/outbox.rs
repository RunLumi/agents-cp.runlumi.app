use crate::{
    adapters::queues::consume_queue_batch,
    core::{EventEnvelope, Timestamp},
    modules::outbox::{EventHandler, FailureCode, HandlerFailure, OutboxStore, RetryPolicy},
};

/// No-op consumer for the development-only P01 foundation event. The durable
/// delivery acknowledgement is the handled result; product event handlers
/// must apply effects idempotently by `event_id` before returning success.
#[derive(Clone, Copy, Debug, Default)]
pub struct FoundationEventHandler;

impl EventHandler for FoundationEventHandler {
    async fn handle_once(&self, event: &EventEnvelope) -> Result<(), HandlerFailure> {
        if event.event_type.as_str() == "foundation.check.requested.v1" {
            Ok(())
        } else {
            Err(HandlerFailure::permanent(
                FailureCode::new("unsupported_event_type").expect("static failure code is valid"),
            ))
        }
    }
}

/// Coordinator-facing Worker hook for P01's test consumer. Pass the configured
/// main and dead-letter queue names from the Worker boundary, not request input.
pub async fn consume_outbox_batch<S>(
    batch: &worker::MessageBatch<EventEnvelope>,
    store: &S,
    now: &Timestamp,
    retry_policy: RetryPolicy,
    dead_letter_queue: &str,
) -> worker::Result<()>
where
    S: OutboxStore,
{
    let handler = FoundationEventHandler;
    consume_queue_batch(batch, store, &handler, now, retry_policy, dead_letter_queue).await
}
