use crate::core::{EventEnvelope, Timestamp};

use super::{
    DeliveryStatus, FailureCode, FailureDisposition, FailureUpdate, OutboxLog, OutboxLogger,
    OutboxStore, OutboxStoreError, RetryPolicy, StoreTransition, dispatch::is_duplicate_delivery,
};

/// Failure returned by an event handler. `retryable` must be false when
/// repeating the operation is unsafe or cannot make progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandlerFailure {
    pub code: FailureCode,
    pub retryable: bool,
}

impl HandlerFailure {
    pub fn retryable(code: FailureCode) -> Self {
        Self {
            code,
            retryable: true,
        }
    }

    pub fn permanent(code: FailureCode) -> Self {
        Self {
            code,
            retryable: false,
        }
    }
}

/// Contract for business event handlers. Any side effect must be committed
/// atomically with an `event_id` dedupe record, or otherwise be idempotent by
/// `event_id`; a pre-handler status lookup alone cannot prevent concurrent
/// duplicate Queue invocations from racing. The Worker path is statically
/// dispatched and does not require a trait object.
#[allow(async_fn_in_trait)]
pub trait EventHandler {
    async fn handle_once(&self, event: &EventEnvelope) -> Result<(), HandlerFailure>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsumerOutcome {
    Delivered,
    Duplicate,
    RetryScheduled,
    DeadLettered,
    OrphanAcknowledged,
}

/// Idempotent-consumer skeleton. It acknowledges only after either durable
/// handling or a durable retry/dead-letter transition has completed.
pub struct OutboxConsumer<'a, S, H, L> {
    store: &'a S,
    handler: &'a H,
    logger: &'a L,
    retry_policy: RetryPolicy,
}

impl<'a, S, H, L> OutboxConsumer<'a, S, H, L>
where
    S: OutboxStore,
    H: EventHandler,
    L: OutboxLogger,
{
    pub const fn new(
        store: &'a S,
        handler: &'a H,
        logger: &'a L,
        retry_policy: RetryPolicy,
    ) -> Self {
        Self {
            store,
            handler,
            logger,
            retry_policy,
        }
    }

    pub async fn consume(
        &self,
        event: &EventEnvelope,
        now: &Timestamp,
    ) -> Result<ConsumerOutcome, OutboxStoreError> {
        let Some(record) = self.store.get_record(&event.event_id).await? else {
            self.logger.log(OutboxLog::for_event(
                event,
                "orphan_message",
                0,
                Some("outbox_event_missing"),
            ));
            // Queue messages are emitted only after the event's D1 transaction
            // commits. Without an outbox row there is nothing safe to replay.
            return Ok(ConsumerOutcome::OrphanAcknowledged);
        };

        if is_duplicate_delivery(record.delivery_status) {
            self.logger.log(OutboxLog::for_event(
                event,
                "duplicate_acknowledged",
                record.attempt_count,
                None,
            ));
            return Ok(ConsumerOutcome::Duplicate);
        }

        match self.handler.handle_once(event).await {
            Ok(()) => match self.store.mark_delivered(&event.event_id, now).await? {
                StoreTransition::Applied => {
                    self.logger.log(OutboxLog::for_event(
                        event,
                        "delivered",
                        record.attempt_count,
                        None,
                    ));
                    Ok(ConsumerOutcome::Delivered)
                }
                StoreTransition::NotApplied => {
                    let latest = self.store.get_record(&event.event_id).await?;
                    match latest {
                        Some(latest) if is_duplicate_delivery(latest.delivery_status) => {
                            Ok(ConsumerOutcome::Duplicate)
                        }
                        Some(_) => Err(OutboxStoreError::Unavailable),
                        None => Ok(ConsumerOutcome::OrphanAcknowledged),
                    }
                }
            },
            Err(failure) if !failure.retryable => {
                match self
                    .store
                    .mark_dead_letter(&event.event_id, &failure.code)
                    .await?
                {
                    StoreTransition::Applied => {
                        self.logger.log(OutboxLog::for_event(
                            event,
                            "dead_lettered",
                            record.attempt_count,
                            Some(failure.code.as_str()),
                        ));
                        Ok(ConsumerOutcome::DeadLettered)
                    }
                    StoreTransition::NotApplied => self.resolve_changed_state(event).await,
                }
            }
            Err(failure) => {
                let Some(new_attempt_count) = record.attempt_count.checked_add(1) else {
                    let code = FailureCode::new("outbox_attempt_counter_exhausted")
                        .expect("static failure code is valid");
                    let transition = self.store.mark_dead_letter(&event.event_id, &code).await?;
                    if transition == StoreTransition::NotApplied {
                        return self.resolve_changed_state(event).await;
                    }
                    self.logger.log(OutboxLog::for_event(
                        event,
                        "dead_lettered",
                        record.attempt_count,
                        Some(code.as_str()),
                    ));
                    return Ok(ConsumerOutcome::DeadLettered);
                };
                let disposition = self
                    .retry_policy
                    .after_failure(new_attempt_count, &event.event_id);
                let transition = self
                    .store
                    .record_failure(
                        &event.event_id,
                        &FailureUpdate {
                            expected_status: record.delivery_status,
                            expected_attempt_count: record.attempt_count,
                            new_attempt_count,
                            failed_at: now,
                            disposition,
                            error_code: &failure.code,
                        },
                    )
                    .await?;

                if transition == StoreTransition::NotApplied {
                    return self.resolve_changed_state(event).await;
                }

                match disposition {
                    FailureDisposition::Retry { .. } => {
                        self.logger.log(OutboxLog::for_event(
                            event,
                            "retry_scheduled",
                            new_attempt_count,
                            Some(failure.code.as_str()),
                        ));
                        Ok(ConsumerOutcome::RetryScheduled)
                    }
                    FailureDisposition::DeadLetter => {
                        self.logger.log(OutboxLog::for_event(
                            event,
                            "dead_lettered",
                            new_attempt_count,
                            Some(failure.code.as_str()),
                        ));
                        Ok(ConsumerOutcome::DeadLettered)
                    }
                }
            }
        }
    }

    /// A Queue DLQ message is terminally recorded before acknowledgement.
    pub async fn consume_dead_letter(
        &self,
        event: &EventEnvelope,
    ) -> Result<ConsumerOutcome, OutboxStoreError> {
        let Some(record) = self.store.get_record(&event.event_id).await? else {
            self.logger.log(OutboxLog::for_event(
                event,
                "orphan_dead_letter",
                0,
                Some("outbox_event_missing"),
            ));
            return Ok(ConsumerOutcome::OrphanAcknowledged);
        };
        if record.delivery_status == DeliveryStatus::Delivered {
            return Ok(ConsumerOutcome::Duplicate);
        }

        let code = FailureCode::new("queue_dead_lettered").expect("static failure code is valid");
        match self.store.mark_dead_letter(&event.event_id, &code).await? {
            StoreTransition::Applied => {
                self.logger.log(OutboxLog::for_event(
                    event,
                    "dead_lettered",
                    record.attempt_count,
                    Some(code.as_str()),
                ));
                Ok(ConsumerOutcome::DeadLettered)
            }
            StoreTransition::NotApplied => self.resolve_changed_state(event).await,
        }
    }

    async fn resolve_changed_state(
        &self,
        event: &EventEnvelope,
    ) -> Result<ConsumerOutcome, OutboxStoreError> {
        match self.store.get_record(&event.event_id).await? {
            Some(record) if is_duplicate_delivery(record.delivery_status) => {
                Ok(ConsumerOutcome::Duplicate)
            }
            // A concurrent consumer has already durably scheduled a retry. This
            // copy may be acknowledged; the scheduled sweep owns redelivery.
            Some(record) if record.delivery_status == DeliveryStatus::Pending => {
                Ok(ConsumerOutcome::RetryScheduled)
            }
            Some(_) => Err(OutboxStoreError::Unavailable),
            None => Ok(ConsumerOutcome::OrphanAcknowledged),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        future::Future,
        pin::Pin,
        task::{Context, Poll, Waker},
    };

    use serde_json::json;

    use super::*;
    use crate::core::{ActorContext, CorrelationId, EventId, EventType};
    use crate::modules::outbox::{OutboxRecord, StoreTransition};

    struct MemoryStore(RefCell<OutboxRecord>);

    impl OutboxStore for MemoryStore {
        async fn list_due_pending(
            &self,
            _now: &Timestamp,
            _limit: u16,
        ) -> Result<Vec<OutboxRecord>, OutboxStoreError> {
            Ok(Vec::new())
        }

        async fn mark_queued(
            &self,
            _event_id: &EventId,
            _expected_attempt_count: u32,
            _queued_at: &Timestamp,
        ) -> Result<StoreTransition, OutboxStoreError> {
            Ok(StoreTransition::NotApplied)
        }

        async fn record_failure(
            &self,
            _event_id: &EventId,
            _update: &FailureUpdate<'_>,
        ) -> Result<StoreTransition, OutboxStoreError> {
            Ok(StoreTransition::NotApplied)
        }

        async fn mark_delivered(
            &self,
            event_id: &EventId,
            delivered_at: &Timestamp,
        ) -> Result<StoreTransition, OutboxStoreError> {
            let mut record = self.0.borrow_mut();
            if record.event_id() != event_id || record.delivery_status.is_terminal() {
                return Ok(StoreTransition::NotApplied);
            }
            record.delivery_status = DeliveryStatus::Delivered;
            record.next_attempt_at = None;
            record.delivered_at = Some(delivered_at.clone());
            Ok(StoreTransition::Applied)
        }

        async fn mark_dead_letter(
            &self,
            _event_id: &EventId,
            _error_code: &FailureCode,
        ) -> Result<StoreTransition, OutboxStoreError> {
            Ok(StoreTransition::NotApplied)
        }

        async fn get_record(
            &self,
            event_id: &EventId,
        ) -> Result<Option<OutboxRecord>, OutboxStoreError> {
            let record = self.0.borrow();
            Ok((record.event_id() == event_id).then(|| (*record).clone()))
        }
    }

    struct CountingHandler(Cell<u32>);

    impl EventHandler for CountingHandler {
        async fn handle_once(&self, _event: &EventEnvelope) -> Result<(), HandlerFailure> {
            self.0.set(self.0.get() + 1);
            Ok(())
        }
    }

    struct QuietLogger;

    impl OutboxLogger for QuietLogger {
        fn log(&self, _record: OutboxLog) {}
    }

    #[test]
    fn duplicate_delivery_is_acknowledged_without_reapplying_handler() {
        let event = event();
        let store = MemoryStore(RefCell::new(OutboxRecord {
            event: event.clone(),
            delivery_status: DeliveryStatus::Queued,
            attempt_count: 0,
            next_attempt_at: None,
            queued_at: Some("2026-09-24T12:00:00.000Z".parse().unwrap()),
            delivered_at: None,
            last_error_code: None,
        }));
        let handler = CountingHandler(Cell::new(0));
        let logger = QuietLogger;
        let consumer = OutboxConsumer::new(&store, &handler, &logger, RetryPolicy::p01_default());
        let now: Timestamp = "2026-09-24T12:00:01.000Z".parse().unwrap();

        assert_eq!(
            block_on(consumer.consume(&event, &now)).unwrap(),
            ConsumerOutcome::Delivered
        );
        assert_eq!(
            block_on(consumer.consume(&event, &now)).unwrap(),
            ConsumerOutcome::Duplicate
        );
        assert_eq!(handler.0.get(), 1);
        assert_eq!(store.0.borrow().delivery_status, DeliveryStatus::Delivered);
    }

    fn event() -> EventEnvelope {
        EventEnvelope {
            event_id: "evt_0123456789abcdef0123456789abcdef".parse().unwrap(),
            event_type: EventType::new("foundation.check.requested.v1").unwrap(),
            occurred_at: "2026-09-24T12:00:00.000Z".parse().unwrap(),
            request_id: "req_0123456789abcdef0123456789abcdef".parse().unwrap(),
            correlation_id: CorrelationId::new("req_0123456789abcdef0123456789abcdef").unwrap(),
            actor: ActorContext::anonymous(),
            organization_id: None,
            payload: json!({ "must_not_be_logged": "private" }),
        }
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut context = Context::from_waker(Waker::noop());
        let mut future = Box::pin(future);
        loop {
            match Pin::as_mut(&mut future).poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
