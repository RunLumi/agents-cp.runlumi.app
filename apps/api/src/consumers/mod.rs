//! Queue consumer application boundary.

mod outbox;

pub use outbox::{FoundationEventHandler, consume_outbox_batch};
