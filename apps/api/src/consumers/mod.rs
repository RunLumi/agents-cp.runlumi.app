//! Queue consumer application boundary.

pub mod automations;
mod data_jobs;
mod outbox;
mod p05;
mod webhooks;

pub use automations::{AutomationJobHandler, enqueue_automation_job};
pub use data_jobs::*;
pub use outbox::{ProductEventHandler, consume_outbox_batch};
pub use p05::{P05_EVENT_REGISTRY, P05AuditEventHandler, P05EventHandler, is_p05_event_type};
pub use webhooks::{
    JobHandler, JobOutcome, NotificationDeliveryJobHandler, QueueJobEnvelope,
    WebhookDeliveryJobHandler, consume_jobs_batch,
};
