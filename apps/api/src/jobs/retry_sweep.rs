use crate::{
    core::Timestamp,
    modules::outbox::{
        DispatchError, DispatchReport, EventPublisher, OutboxLogger, OutboxStore, RetryPolicy,
        retry_due_events,
    },
};

/// Scheduled retry sweep. A single invocation reads at most `limit` due rows;
/// the same publisher/consumer path is used by immediate dispatch and retries.
pub async fn run_retry_sweep<S, P, L>(
    store: &S,
    publisher: &P,
    logger: &L,
    now: &Timestamp,
    retry_policy: RetryPolicy,
    limit: u16,
) -> Result<DispatchReport, RetrySweepError>
where
    S: OutboxStore,
    P: EventPublisher,
    L: OutboxLogger,
{
    retry_due_events(store, publisher, logger, now, retry_policy, limit)
        .await
        .map_err(RetrySweepError)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetrySweepError(pub DispatchError);
