use crate::{
    core::{EventEnvelope, Timestamp},
    modules::outbox::{
        ConsumerOutcome, EventHandler, OutboxConsumer, OutboxLog, OutboxLogger, OutboxStore,
        RetryPolicy,
    },
};

use super::WorkerOutboxLogger;
use worker::MessageExt;

/// Fallback for Queue redelivery when D1 is unavailable. The configured
/// consumer retry limit and dead-letter queue provide the finite upper bound.
pub const OUTBOX_RETRY_DELAY_SECONDS: u32 = 30;

/// Consume a batch from the primary queue or its configured dead-letter queue.
/// The caller passes the exact DLQ name from coordinator-owned Wrangler config.
/// Individual messages are acknowledged only after their outbox transition is
/// durable; store errors use bounded platform retry without logging the body.
pub async fn consume_queue_batch<S, H>(
    batch: &worker::MessageBatch<EventEnvelope>,
    store: &S,
    handler: &H,
    now: &Timestamp,
    retry_policy: RetryPolicy,
    dead_letter_queue: &str,
) -> worker::Result<()>
where
    S: OutboxStore,
    H: EventHandler,
{
    let logger = WorkerOutboxLogger;
    let is_dead_letter_queue = batch.queue() == dead_letter_queue;
    let messages = match batch.messages() {
        Ok(messages) => messages,
        Err(_) => {
            logger.log(OutboxLog {
                action: "invalid_queue_batch",
                event_id: String::new(),
                event_type: String::new(),
                request_id: String::new(),
                correlation_id: String::new(),
                attempt_count: 0,
                error_code: Some("invalid_event_envelope".to_owned()),
            });
            let retry_options = retry_options();
            batch.retry_all_with_options(&retry_options);
            return Ok(());
        }
    };

    let consumer = OutboxConsumer::new(store, handler, &logger, retry_policy);
    for message in messages {
        let event = message.body();
        let outcome = if is_dead_letter_queue {
            consumer.consume_dead_letter(event).await
        } else {
            consumer.consume(event, now).await
        };

        match outcome {
            Ok(
                ConsumerOutcome::Delivered
                | ConsumerOutcome::Duplicate
                | ConsumerOutcome::RetryScheduled
                | ConsumerOutcome::DeadLettered
                | ConsumerOutcome::OrphanAcknowledged,
            ) => message.ack(),
            Err(_) => {
                logger.log(OutboxLog::for_event(
                    event,
                    "consumer_state_unavailable",
                    0,
                    Some("outbox_store_unavailable"),
                ));
                let retry_options = retry_options();
                message.retry_with_options(&retry_options);
            }
        }
    }
    Ok(())
}

fn retry_options() -> worker::QueueRetryOptions {
    worker::QueueRetryOptionsBuilder::new()
        .with_delay_seconds(OUTBOX_RETRY_DELAY_SECONDS)
        .build()
}
