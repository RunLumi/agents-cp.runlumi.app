use crate::{
    adapters::queues::consume_queue_batch,
    core::{EventEnvelope, Timestamp},
    modules::outbox::{EventHandler, FailureCode, HandlerFailure, OutboxStore, RetryPolicy},
};

/// No-op consumer for the foundation fixture and P02 identity/org events. The
/// durable security-event write happens in the business transaction; this
/// consumer acknowledges delivery and leaves downstream notifications for
/// later phases. It still rejects unknown event types rather than silently
/// acknowledging arbitrary messages.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProductEventHandler;

impl EventHandler for ProductEventHandler {
    async fn handle_once(&self, event: &EventEnvelope) -> Result<(), HandlerFailure> {
        let event_type = event.event_type.as_str();
        if matches!(
            event_type,
            "foundation.check.requested.v1"
                | "identity.created.v1"
                | "identity.verified.v1"
                | "identity.linked.v1"
                | "identity.link_started.v1"
                | "auth.login.completed.v1"
                | "auth.logout.v1"
                | "auth.session.rotated.v1"
                | "organization.created.v1"
                | "organization.updated.v1"
                | "organization.ownership_transferred.v1"
                | "organization.suspended.v1"
                | "organization.resumed.v1"
                | "organization.deletion_started.v1"
                | "membership.invited.v1"
                | "membership.accepted.v1"
                | "membership.role_changed.v1"
                | "membership.removed.v1"
                | "membership.left.v1"
                | "membership.invitation_revoked.v1"
                | "membership.invitation_resent.v1"
                | "team.created.v1"
                | "team.member_removed.v1"
                | "session.revoked.v1"
                | "session.revoked_all.v1"
                | "reauthentication.granted.v1"
                | "device_code.approved.v1"
        ) {
            Ok(())
        } else {
            Err(HandlerFailure::permanent(
                FailureCode::new("unsupported_event_type").expect("static failure code is valid"),
            ))
        }
    }
}

/// Coordinator-facing Worker hook for P01's test consumer. Pass the configured
/// main and dead-letter queue names from the Worker boundary, not request input.
pub async fn consume_outbox_batch<S>(
    batch: &worker::MessageBatch<EventEnvelope>,
    store: &S,
    now: &Timestamp,
    retry_policy: RetryPolicy,
    dead_letter_queue: &str,
) -> worker::Result<()>
where
    S: OutboxStore,
{
    let handler = ProductEventHandler;
    consume_queue_batch(batch, store, &handler, now, retry_policy, dead_letter_queue).await
}
