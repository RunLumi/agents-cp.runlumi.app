//! Queue consumer application boundary.

mod outbox;
mod p05;

pub use outbox::{ProductEventHandler, consume_outbox_batch};
pub use p05::{P05_EVENT_REGISTRY, P05AuditEventHandler, P05EventHandler, is_p05_event_type};
