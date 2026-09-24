pub mod adapters;
mod app;
pub mod consumers;
pub mod core;
pub mod http;
pub mod jobs;
pub mod modules;
pub mod repositories;
mod routes;

use crate::adapters::d1::D1Adapter;

use tower_service::Service;
use worker::*;

#[event(fetch)]
async fn fetch(
    req: HttpRequest,
    env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    Ok(app::router(env).call(req).await?)
}

/// Queue events are decoded into the versioned business envelope before the
/// consumer sees them. Per-message acknowledgement and retry are handled by
/// the adapter only after durable D1 state transitions.
#[event(queue)]
async fn queue(batch: MessageBatch<core::EventEnvelope>, env: Env, _ctx: Context) -> Result<()> {
    let database = D1Adapter::new(env.d1("DB")?);
    let store = repositories::OutboxRepository::new(&database);
    let now = jobs::now_utc().map_err(|_| Error::RustError("worker clock unavailable".into()))?;
    let retry_policy = outbox_retry_policy();
    let dead_letter_queue = env
        .var("OUTBOX_DLQ_NAME")
        .map(|value| value.to_string())
        .map_err(|_| Error::RustError("dead-letter queue configuration unavailable".into()))?;

    consumers::consume_outbox_batch(&batch, &store, &now, retry_policy, &dead_letter_queue).await
}

/// Sweep at most one bounded batch of due events each minute. D1 remains the
/// canonical source; Queue delivery is at-least-once and consumers deduplicate
/// by event ID.
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    if run_scheduled_sweep(env).await.is_err() {
        // ScheduledEvent's workers-rs bridge discards the Rust function's
        // return value, so emit a stable redacted failure signal explicitly.
        console_error!("outbox_retry_sweep_failed");
    }
}

async fn run_scheduled_sweep(env: Env) -> Result<()> {
    let database = D1Adapter::new(env.d1("DB")?);
    let store = repositories::OutboxRepository::new(&database);
    let queue = env.queue("OUTBOX_QUEUE")?;
    let publisher = adapters::queues::CloudflareQueuePublisher::new(queue);
    let logger = adapters::queues::WorkerOutboxLogger;
    let now = jobs::now_utc().map_err(|_| Error::RustError("worker clock unavailable".into()))?;

    jobs::run_retry_sweep(
        &store,
        &publisher,
        &logger,
        &now,
        outbox_retry_policy(),
        100,
    )
    .await
    .map(|_| ())
    .map_err(|_| Error::RustError("outbox retry sweep failed".into()))
}

fn outbox_retry_policy() -> modules::outbox::RetryPolicy {
    modules::outbox::RetryPolicy::new(6, 30, 900, 25).expect("static outbox retry policy is valid")
}
