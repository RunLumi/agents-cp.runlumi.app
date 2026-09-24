//! D1-backed persistence operations for frozen P01 infrastructure contracts.
//!
//! Repository code owns SQL and row mapping. Callers supply trusted domain
//! values; all values are bound parameters and authorization stays outside this
//! layer.

mod idempotency;
mod outbox;

pub use idempotency::{IdempotencyClaimToken, IdempotencyLookup, IdempotencyRepository};
pub use outbox::OutboxRepository;
