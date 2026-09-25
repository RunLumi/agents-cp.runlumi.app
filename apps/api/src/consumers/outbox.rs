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

const SUPPORTED_EVENT_TYPES: &[&str] = &[
    "foundation.check.requested.v1",
    "identity.created.v1",
    "identity.verified.v1",
    "identity.linked.v1",
    "identity.link_started.v1",
    "auth.login.completed.v1",
    "auth.logout.v1",
    "auth.session.rotated.v1",
    "organization.created.v1",
    "organization.updated.v1",
    "organization.ownership_transferred.v1",
    "organization.suspended.v1",
    "organization.resumed.v1",
    "organization.deletion_started.v1",
    "membership.invited.v1",
    "membership.accepted.v1",
    "membership.role_changed.v1",
    "membership.removed.v1",
    "membership.left.v1",
    "membership.invitation_revoked.v1",
    "membership.invitation_resent.v1",
    "team.created.v1",
    "team.member_removed.v1",
    "session.revoked.v1",
    "session.revoked_all.v1",
    "reauthentication.granted.v1",
    "device_code.approved.v1",
    "model_policy.updated.v1",
    "model_catalog.provider_created.v1",
    "model_catalog.provider_lifecycle_changed.v1",
    "model_catalog.model_created.v1",
    "model_catalog.model_lifecycle_changed.v1",
    "credential.created.v1",
    "credential.rotated.v1",
    "credential.revoked.v1",
    "route.draft_created.v1",
    "route.published.v1",
    "route.rolled_back.v1",
    "route.lifecycle_changed.v1",
    "inference.requested.v1",
    "inference.completed.v1",
    "inference.failed.v1",
    "usage.recorded.v1",
    "project.created.v1",
    "project.updated.v1",
    "project.archived.v1",
    "device.enrollment.approved.v1",
    "device.revoked.v1",
    "agent_definition.created.v1",
    "agent_definition.updated.v1",
    "session.created.v1",
    "session.closed.v1",
    "run.created.v1",
    "run.retried.v1",
    "run.state_changed.v1",
    "run.started.v1",
    "run.completed.v1",
    "run.failed.v1",
    "run.cancelled.v1",
    "run.event_appended.v1",
    "tool.catalog_updated.v1",
    "tool.mcp_registration_changed.v1",
    "tool.decision_recorded.v1",
    "tool.denied.v1",
    "tool.result.v1",
    "tool.approval_requested.v1",
    "approval.requested.v1",
    "approval.resolved.v1",
    "usage.reconciled.v1",
    "budget.reserved.v1",
    "budget.reconciled.v1",
    "budget.denied.v1",
    "rate_limit.denied.v1",
    "artifact.created.v1",
    "tool.policy_updated.v1",
    "rate_limit_policy.updated.v1",
];

impl EventHandler for ProductEventHandler {
    async fn handle_once(&self, event: &EventEnvelope) -> Result<(), HandlerFailure> {
        if SUPPORTED_EVENT_TYPES.contains(&event.event_type.as_str()) {
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

#[cfg(test)]
mod tests {
    use super::SUPPORTED_EVENT_TYPES;

    #[test]
    fn p04_event_registry_covers_every_emitted_event() {
        for event in [
            "model_policy.updated.v1",
            "model_catalog.provider_created.v1",
            "model_catalog.provider_lifecycle_changed.v1",
            "model_catalog.model_created.v1",
            "model_catalog.model_lifecycle_changed.v1",
            "credential.created.v1",
            "credential.rotated.v1",
            "credential.revoked.v1",
            "route.draft_created.v1",
            "route.published.v1",
            "route.rolled_back.v1",
            "route.lifecycle_changed.v1",
            "inference.requested.v1",
            "inference.completed.v1",
            "inference.failed.v1",
            "usage.recorded.v1",
        ] {
            assert!(SUPPORTED_EVENT_TYPES.contains(&event), "missing {event}");
        }
    }
}
