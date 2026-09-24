use crate::core::{EventId, Timestamp};

use super::{DeliveryStatus, FailureCode, FailureDisposition, OutboxRecord, StoreTransition};

/// Stable, non-sensitive repository failures. A concrete D1 adapter maps
/// platform/SQL details into these categories; callers never log raw errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboxStoreError {
    Unavailable,
    InvalidRecord,
}

/// Compare-and-set data for one failed publisher or consumer attempt.
#[derive(Clone, Copy, Debug)]
pub struct FailureUpdate<'a> {
    pub expected_status: DeliveryStatus,
    pub expected_attempt_count: u32,
    pub new_attempt_count: u32,
    pub failed_at: &'a Timestamp,
    pub disposition: FailureDisposition,
    pub error_code: &'a FailureCode,
}

/// Port implemented by the D1 repository. Every update is conditional on the
/// event ID, expected state, and expected attempt count so concurrent retries
/// cannot silently overwrite a newer transition. The P01 adapter is generic
/// and statically dispatched; the trait is intentionally not used as `dyn`.
#[allow(async_fn_in_trait)]
pub trait OutboxStore {
    /// Return at most `limit` pending rows whose `next_attempt_at <= now`, in
    /// deterministic due-time order. The implementation must reject a zero or
    /// unbounded limit and must not widen the query to other tenants by payload.
    async fn list_due_pending(
        &self,
        now: &Timestamp,
        limit: u16,
    ) -> Result<Vec<OutboxRecord>, OutboxStoreError>;

    /// Conditionally move one pending event to queued after Queue send
    /// succeeds. Return `NotApplied` if another consumer/retry already moved it.
    async fn mark_queued(
        &self,
        event_id: &EventId,
        expected_attempt_count: u32,
        queued_at: &Timestamp,
    ) -> Result<StoreTransition, OutboxStoreError>;

    /// Persist a failed publish or handler attempt. The repository atomically
    /// increments `attempt_count` once, records only the stable error code, and
    /// moves the row to pending with `next_attempt_at = failed_at + delay`, or
    /// to dead-letter. `new_attempt_count` must equal expected + 1. For a
    /// retry, `delay_seconds` is finite and bounded by the caller's policy.
    async fn record_failure(
        &self,
        event_id: &EventId,
        update: &FailureUpdate<'_>,
    ) -> Result<StoreTransition, OutboxStoreError>;

    /// Acknowledge durable handling. This is an atomic pending/queued →
    /// delivered transition; repeated calls do not change a delivered row.
    async fn mark_delivered(
        &self,
        event_id: &EventId,
        delivered_at: &Timestamp,
    ) -> Result<StoreTransition, OutboxStoreError>;

    /// Mark poison messages arriving through a configured Queue DLQ as
    /// terminal. Already delivered rows must remain delivered.
    async fn mark_dead_letter(
        &self,
        event_id: &EventId,
        error_code: &FailureCode,
    ) -> Result<StoreTransition, OutboxStoreError>;

    /// Read one persisted row for consumer deduplication and failure CAS.
    async fn get_record(
        &self,
        event_id: &EventId,
    ) -> Result<Option<OutboxRecord>, OutboxStoreError>;
}
