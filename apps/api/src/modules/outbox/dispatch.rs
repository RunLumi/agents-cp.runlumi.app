use crate::core::{EventEnvelope, Timestamp};

use super::{
    DeliveryStatus, FailureCode, FailureDisposition, FailureUpdate, OutboxLog, OutboxLogger,
    OutboxRecord, OutboxStore, OutboxStoreError, RetryPolicy, StoreTransition,
};

/// Queue publisher port. Implementations map platform errors to one stable code
/// and must not return raw error strings that could disclose binding details.
/// It is statically dispatched in the P01 job path, never used as `dyn`.
#[allow(async_fn_in_trait)]
pub trait EventPublisher {
    async fn publish(&self, event: &EventEnvelope) -> Result<(), FailureCode>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchOutcome {
    Published,
    RetryScheduled,
    DeadLettered,
    StateChanged,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DispatchReport {
    pub selected: u16,
    pub published: u16,
    pub retry_scheduled: u16,
    pub dead_lettered: u16,
    pub state_changed: u16,
    pub state_write_failures: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchError {
    Store(OutboxStoreError),
    InvalidBatchLimit,
}

/// Publish a just-committed outbox record to make delivery prompt. The caller
/// must invoke this only after the business mutation and event are committed in
/// the same D1 batch. Failures are persisted for the scheduled retry sweep and
/// do not change the already-committed business result.
pub async fn dispatch_committed_record<S, P, L>(
    store: &S,
    publisher: &P,
    logger: &L,
    record: &OutboxRecord,
    now: &Timestamp,
    retry_policy: RetryPolicy,
) -> Result<DispatchOutcome, OutboxStoreError>
where
    S: OutboxStore,
    P: EventPublisher,
    L: OutboxLogger,
{
    dispatch_one(store, publisher, logger, record, now, retry_policy).await
}

/// Run one bounded retry sweep. The D1 implementation orders by due timestamp
/// and rejects limits outside its own hard cap; this function also guards the
/// application boundary to avoid accidentally issuing an unbounded scan.
pub async fn retry_due_events<S, P, L>(
    store: &S,
    publisher: &P,
    logger: &L,
    now: &Timestamp,
    retry_policy: RetryPolicy,
    limit: u16,
) -> Result<DispatchReport, DispatchError>
where
    S: OutboxStore,
    P: EventPublisher,
    L: OutboxLogger,
{
    if !(1..=MAX_RETRY_BATCH).contains(&limit) {
        return Err(DispatchError::InvalidBatchLimit);
    }

    let due = store
        .list_due_pending(now, limit)
        .await
        .map_err(DispatchError::Store)?;
    let mut report = DispatchReport {
        selected: u16::try_from(due.len()).unwrap_or(limit),
        ..DispatchReport::default()
    };

    for record in due {
        match dispatch_one(store, publisher, logger, &record, now, retry_policy).await {
            Ok(DispatchOutcome::Published) => report.published += 1,
            Ok(DispatchOutcome::RetryScheduled) => report.retry_scheduled += 1,
            Ok(DispatchOutcome::DeadLettered) => report.dead_lettered += 1,
            Ok(DispatchOutcome::StateChanged) => report.state_changed += 1,
            // Queue send can succeed while D1 is unavailable, or recording a
            // failure can fail. In either case the durable row remains pending
            // or is already terminal; the next bounded sweep reconciles it.
            Err(_) => report.state_write_failures += 1,
        }
    }

    Ok(report)
}

pub const MAX_RETRY_BATCH: u16 = 100;

async fn dispatch_one<S, P, L>(
    store: &S,
    publisher: &P,
    logger: &L,
    record: &OutboxRecord,
    now: &Timestamp,
    retry_policy: RetryPolicy,
) -> Result<DispatchOutcome, OutboxStoreError>
where
    S: OutboxStore,
    P: EventPublisher,
    L: OutboxLogger,
{
    if record.delivery_status != DeliveryStatus::Pending {
        return Ok(DispatchOutcome::StateChanged);
    }

    match publisher.publish(&record.event).await {
        Ok(()) => match store
            .mark_queued(record.event_id(), record.attempt_count, now)
            .await
        {
            Err(error) => {
                logger.log(OutboxLog::for_event(
                    &record.event,
                    "publish_state_write_failed",
                    record.attempt_count,
                    Some("outbox_store_unavailable"),
                ));
                Err(error)
            }
            Ok(StoreTransition::Applied) => {
                logger.log(OutboxLog::for_event(
                    &record.event,
                    "published",
                    record.attempt_count,
                    None,
                ));
                Ok(DispatchOutcome::Published)
            }
            Ok(StoreTransition::NotApplied) => {
                logger.log(OutboxLog::for_event(
                    &record.event,
                    "publish_state_changed",
                    record.attempt_count,
                    Some("outbox_state_changed"),
                ));
                Ok(DispatchOutcome::StateChanged)
            }
        },
        Err(error_code) => {
            let Some(new_attempt_count) = record.attempt_count.checked_add(1) else {
                let transition = store
                    .mark_dead_letter(
                        record.event_id(),
                        &FailureCode::new("outbox_attempt_counter_exhausted")
                            .expect("static failure code is valid"),
                    )
                    .await?;
                if transition == StoreTransition::NotApplied {
                    return Ok(DispatchOutcome::StateChanged);
                }
                logger.log(OutboxLog::for_event(
                    &record.event,
                    "failure_counter_exhausted",
                    record.attempt_count,
                    Some("outbox_attempt_counter_exhausted"),
                ));
                return Ok(DispatchOutcome::DeadLettered);
            };
            let disposition = retry_policy.after_failure(new_attempt_count, record.event_id());
            let transition = store
                .record_failure(
                    record.event_id(),
                    &FailureUpdate {
                        expected_status: record.delivery_status,
                        expected_attempt_count: record.attempt_count,
                        new_attempt_count,
                        failed_at: now,
                        disposition,
                        error_code: &error_code,
                    },
                )
                .await;
            let transition = match transition {
                Ok(transition) => transition,
                Err(error) => {
                    logger.log(OutboxLog::for_event(
                        &record.event,
                        "failure_state_write_failed",
                        record.attempt_count,
                        Some("outbox_store_unavailable"),
                    ));
                    return Err(error);
                }
            };
            if transition == StoreTransition::NotApplied {
                logger.log(OutboxLog::for_event(
                    &record.event,
                    "failure_state_changed",
                    record.attempt_count,
                    Some("outbox_state_changed"),
                ));
                return Ok(DispatchOutcome::StateChanged);
            }

            let (action, outcome) = match disposition {
                FailureDisposition::Retry { .. } => {
                    ("retry_scheduled", DispatchOutcome::RetryScheduled)
                }
                FailureDisposition::DeadLetter => ("dead_lettered", DispatchOutcome::DeadLettered),
            };
            logger.log(OutboxLog::for_event(
                &record.event,
                action,
                new_attempt_count,
                Some(error_code.as_str()),
            ));
            Ok(outcome)
        }
    }
}

/// Narrow helper for consumers to classify persisted terminal states without
/// requiring payload inspection or inferring authority from organization IDs.
pub const fn is_duplicate_delivery(status: DeliveryStatus) -> bool {
    matches!(
        status,
        DeliveryStatus::Delivered | DeliveryStatus::DeadLetter
    )
}
