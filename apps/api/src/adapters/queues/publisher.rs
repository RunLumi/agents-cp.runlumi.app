use crate::{
    core::EventEnvelope,
    modules::outbox::{EventPublisher, FailureCode},
};

/// Thin producer wrapper around a named Wrangler Queue binding. The coordinator
/// obtains the binding from `Env` and passes it here, keeping raw `Env` out of
/// dispatch/domain code.
pub struct CloudflareQueuePublisher {
    queue: worker::Queue,
}

impl CloudflareQueuePublisher {
    pub fn new(queue: worker::Queue) -> Self {
        Self { queue }
    }
}

impl EventPublisher for CloudflareQueuePublisher {
    async fn publish(&self, event: &EventEnvelope) -> Result<(), FailureCode> {
        self.queue
            .send(event)
            .await
            .map_err(|_| FailureCode::new("queue_publish_failed").expect("static code is valid"))
    }
}
