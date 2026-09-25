//! Queue consumer application boundary.

mod outbox;

pub use outbox::{ProductEventHandler, consume_outbox_batch};
