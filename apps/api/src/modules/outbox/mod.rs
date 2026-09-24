//! Durable event delivery primitives. Event payloads are never formatted into
//! diagnostics; queue publishers and consumers operate on the frozen envelope.

mod consumer;
mod dispatch;
mod logging;
mod retry;
mod store;
mod types;

pub use consumer::{ConsumerOutcome, EventHandler, HandlerFailure, OutboxConsumer};
pub use dispatch::{
    DispatchError, DispatchOutcome, DispatchReport, EventPublisher, MAX_RETRY_BATCH,
    dispatch_committed_record, retry_due_events,
};
pub use logging::{OutboxLog, OutboxLogger};
pub use retry::{FailureDisposition, RetryPolicy};
pub use store::{FailureUpdate, OutboxStore, OutboxStoreError};
pub use types::{DeliveryStatus, FailureCode, OutboxRecord, StoreTransition};

#[cfg(test)]
mod tests;
