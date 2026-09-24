use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::{Map, Value, json};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::{
        add_idempotency_ttl,
        d1::D1Adapter,
        new_event_id,
        queues::{CloudflareQueuePublisher, WorkerOutboxLogger},
        sha256_hex,
    },
    app::AppState,
    core::{
        ActorContext, ActorId, ApiError, ApiErrorCode, EventEnvelope, EventType, IdempotencyKey,
        IdempotencyKeyDigest, IdempotencyRecord, IdempotencyScope, IdempotencyState,
        RequestContext, RequestFingerprint, StoredSuccess,
    },
    modules::outbox::{DeliveryStatus, OutboxRecord, OutboxStore, dispatch_committed_record},
    repositories::{IdempotencyLookup, IdempotencyRepository, OutboxRepository},
    routes::errors,
};

const FOUNDATION_CHECKS_PATH: &str = "/api/v1/_internal/foundation-checks";
const FOUNDATION_EVENT_TYPE: &str = "foundation.check.requested.v1";
const LOCAL_PRINCIPAL: &str = "anonymous-local";

#[derive(Serialize)]
pub struct FoundationCheckResponse {
    event_id: String,
    delivery_status: DeliveryStatus,
}

/// Create one development-only fixture event. Its empty body is fingerprinted
/// and its accepted response is committed with the outbox row in one D1 batch.
#[worker::send]
pub async fn create(
    State(state): State<Arc<AppState>>,
    axum::Extension(context): axum::Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<Map<String, Value>>,
) -> Result<Response, ApiError> {
    let key = read_idempotency_key(&headers, &context)?;
    let database = state.database.as_ref().ok_or_else(|| {
        errors::api_error(
            &context,
            ApiErrorCode::ServiceUnavailable,
            "The local D1 binding is unavailable.",
        )
    })?;
    let queue = state.queue.as_ref().ok_or_else(|| {
        errors::api_error(
            &context,
            ApiErrorCode::ServiceUnavailable,
            "The local outbox queue is unavailable.",
        )
    })?;

    let scope = IdempotencyScope::new(
        ActorId::new(LOCAL_PRINCIPAL).map_err(|_| internal_error(&context))?,
        None,
        "POST",
        FOUNDATION_CHECKS_PATH,
    )
    .map_err(|_| internal_error(&context))?;
    let canonical_body = canonical_json_body(&body).map_err(|_| internal_error(&context))?;
    let fingerprint_input = format!("POST\n{FOUNDATION_CHECKS_PATH}\n{canonical_body}");
    let key_digest = IdempotencyKeyDigest::new(format!(
        "sha256:{}",
        sha256_hex(key.expose_for_digest())
            .await
            .map_err(|_| service_unavailable(&context))?
    ))
    .map_err(|_| internal_error(&context))?;
    let request_fingerprint = RequestFingerprint::new(format!(
        "sha256:{}",
        sha256_hex(&fingerprint_input)
            .await
            .map_err(|_| service_unavailable(&context))?
    ))
    .map_err(|_| internal_error(&context))?;
    let idempotency = IdempotencyRepository::new(database);

    match idempotency
        .lookup(
            &scope,
            &key_digest,
            &request_fingerprint,
            &context.received_at,
        )
        .await
        .map_err(|_| service_unavailable(&context))?
    {
        IdempotencyLookup::Replay(success) => return Ok(replay_response(success)),
        IdempotencyLookup::InProgress => return Err(idempotency_in_progress(&context)),
        IdempotencyLookup::FingerprintConflict => {
            return Err(idempotency_conflict(&context));
        }
        IdempotencyLookup::Missing => {}
    }

    // A live key with a different valid JSON body conflicts before endpoint
    // validation. A new non-empty body is rejected without claiming the key.
    if !body.is_empty() {
        return Err(errors::api_error(
            &context,
            ApiErrorCode::BadRequest,
            "The foundation check accepts an empty JSON object only.",
        ));
    }

    let claim_token = crate::repositories::IdempotencyClaimToken::new(context.request_id.as_str())
        .map_err(|_| internal_error(&context))?;
    let record = IdempotencyRecord {
        scope: scope.clone(),
        key_digest: key_digest.clone(),
        request_fingerprint: request_fingerprint.clone(),
        expires_at: add_idempotency_ttl(&context.received_at)
            .map_err(|_| service_unavailable(&context))?,
        state: IdempotencyState::Pending,
    };

    let event = EventEnvelope {
        event_id: new_event_id(),
        event_type: EventType::new(FOUNDATION_EVENT_TYPE).expect("static event type is valid"),
        occurred_at: context.received_at.clone(),
        request_id: context.request_id.clone(),
        correlation_id: context.correlation_id.clone(),
        actor: context
            .actor
            .clone()
            .unwrap_or_else(ActorContext::anonymous),
        organization_id: None,
        payload: json!({}),
    };
    let success_body = json!({
        "event_id": event.event_id.as_str(),
        "delivery_status": "pending"
    });
    let success =
        StoredSuccess::new(202, success_body.clone()).map_err(|_| internal_error(&context))?;
    let outbox = OutboxRepository::new(database);
    let outbox_insert = outbox
        .insert_statement(&event)
        .map_err(|_| service_unavailable(&context))?;

    let claim_statement = idempotency
        .claim_statement(&record, &claim_token, &context.received_at)
        .map_err(|_| service_unavailable(&context))?;

    let committed = idempotency
        .commit_success(
            &record,
            &claim_token,
            claim_statement,
            &success,
            Vec::<D1PreparedStatement>::new(),
            outbox_insert,
        )
        .await;
    let committed = match committed {
        Ok(results) => results,
        Err(_) => {
            return match idempotency
                .lookup(
                    &scope,
                    &key_digest,
                    &request_fingerprint,
                    &context.received_at,
                )
                .await
                .map_err(|_| service_unavailable(&context))?
            {
                IdempotencyLookup::Replay(success) => Ok(replay_response(success)),
                IdempotencyLookup::FingerprintConflict => Err(idempotency_conflict(&context)),
                IdempotencyLookup::InProgress => Err(idempotency_in_progress(&context)),
                IdempotencyLookup::Missing => Err(service_unavailable(&context)),
            };
        }
    };
    let committed_mutation = committed.len() == 4
        && D1Adapter::changes(&committed[0]).unwrap_or_default() == 1
        && D1Adapter::changes(&committed[2]).unwrap_or_default() == 1
        && D1Adapter::changes(&committed[3]).unwrap_or_default() == 1;
    if !committed_mutation {
        return Err(service_unavailable(&context));
    }

    let logger = WorkerOutboxLogger;
    let publisher = CloudflareQueuePublisher::new(queue.clone());
    let retry_policy = crate::outbox_retry_policy();
    let initial_record = OutboxRecord {
        event: event.clone(),
        delivery_status: DeliveryStatus::Pending,
        attempt_count: 0,
        next_attempt_at: Some(event.occurred_at.clone()),
        queued_at: None,
        delivered_at: None,
        last_error_code: None,
    };
    let _ = dispatch_committed_record(
        &outbox,
        &publisher,
        &logger,
        &initial_record,
        &context.received_at,
        retry_policy,
    )
    .await;

    Ok((
        StatusCode::ACCEPTED,
        Json(FoundationCheckResponse {
            event_id: event.event_id.to_string(),
            delivery_status: DeliveryStatus::Pending,
        }),
    )
        .into_response())
}

/// Read persisted delivery state for the local integration walkthrough.
#[worker::send]
pub async fn status(
    State(state): State<Arc<AppState>>,
    axum::Extension(context): axum::Extension<RequestContext>,
    Path(event_id): Path<String>,
) -> Result<Json<FoundationCheckResponse>, ApiError> {
    let database = state.database.as_ref().ok_or_else(|| {
        errors::api_error(
            &context,
            ApiErrorCode::ServiceUnavailable,
            "The local D1 binding is unavailable.",
        )
    })?;
    let event_id = crate::core::EventId::new(event_id).map_err(|_| {
        errors::api_error(
            &context,
            ApiErrorCode::BadRequest,
            "The event ID is invalid.",
        )
    })?;
    let repository = OutboxRepository::new(database);
    let record = repository
        .get_record(&event_id)
        .await
        .map_err(|_| service_unavailable(&context))?
        .ok_or_else(|| {
            errors::api_error(
                &context,
                ApiErrorCode::NotFound,
                "The foundation event was not found.",
            )
        })?;
    if record.event.event_type.as_str() != FOUNDATION_EVENT_TYPE {
        return Err(errors::api_error(
            &context,
            ApiErrorCode::NotFound,
            "The foundation event was not found.",
        ));
    }

    Ok(Json(FoundationCheckResponse {
        event_id: event_id.to_string(),
        delivery_status: record.delivery_status,
    }))
}

fn read_idempotency_key(
    headers: &HeaderMap,
    context: &RequestContext,
) -> Result<IdempotencyKey, ApiError> {
    let values = headers.get_all("idempotency-key");
    let mut values = values.iter();
    let Some(value) = values.next() else {
        return Err(errors::bad_request(
            context.request_id.clone(),
            "The Idempotency-Key header is required.",
        ));
    };
    if values.next().is_some() {
        return Err(errors::bad_request(
            context.request_id.clone(),
            "Exactly one Idempotency-Key header is allowed.",
        ));
    }
    let value = value.to_str().map_err(|_| {
        errors::bad_request(
            context.request_id.clone(),
            "The Idempotency-Key header is invalid.",
        )
    })?;
    IdempotencyKey::new(value).map_err(|_| {
        errors::bad_request(
            context.request_id.clone(),
            "The Idempotency-Key header is invalid.",
        )
    })
}

fn canonical_json_body(body: &Map<String, Value>) -> Result<String, serde_json::Error> {
    serde_json::to_string(&Value::Object(body.clone()))
}

fn replay_response(success: StoredSuccess) -> Response {
    let status = StatusCode::from_u16(success.status).unwrap_or(StatusCode::ACCEPTED);
    (status, Json(success.body)).into_response()
}

fn idempotency_conflict(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::IdempotencyConflict,
        "This Idempotency-Key was already used for a different request.",
    )
}

fn idempotency_in_progress(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::IdempotencyInProgress,
        "A request with this Idempotency-Key is still in progress.",
    )
}

fn service_unavailable(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::ServiceUnavailable,
        "The local foundation service is temporarily unavailable.",
    )
}

fn internal_error(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::InternalError,
        "An unexpected error occurred.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_body_is_stable_and_fingerprints_differing_json() {
        let mut left = Map::new();
        left.insert("a".to_owned(), json!(1));
        left.insert("b".to_owned(), json!(2));
        let mut reordered = Map::new();
        reordered.insert("b".to_owned(), json!(2));
        reordered.insert("a".to_owned(), json!(1));
        let mut changed = Map::new();
        changed.insert("a".to_owned(), json!(1));
        changed.insert("b".to_owned(), json!(3));

        assert_eq!(
            canonical_json_body(&left).unwrap(),
            canonical_json_body(&reordered).unwrap()
        );
        assert_ne!(
            canonical_json_body(&left).unwrap(),
            canonical_json_body(&changed).unwrap()
        );
    }
}
