use std::sync::Arc;

use serde_json::json;

use crate::{
    adapters::{d1::D1Adapter, new_event_id},
    app::AppState,
    core::{
        ActorContext, ActorId, ApiError, ApiErrorCode, EventEnvelope, EventType, OrganizationId,
        Principal, RequestContext,
    },
    repositories::{OutboxRepository, UserRecord},
    routes::errors,
};

pub fn idempotency_key(
    headers: &axum::http::HeaderMap,
    context: &RequestContext,
) -> Result<String, ApiError> {
    let value = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        })
        .ok_or_else(|| {
            domain_error(
                context,
                ApiErrorCode::BadRequest,
                "idempotency_key_required",
                "Idempotency-Key is required for this mutation.",
            )
        })?;
    Ok(value.to_owned())
}

pub async fn deterministic_resource_id(
    prefix: &str,
    key: &str,
    scope: &str,
    context: &RequestContext,
) -> Result<String, ApiError> {
    let digest = crate::adapters::sha256_hex(&format!("{scope}:{key}"))
        .await
        .map_err(|_| {
            errors::api_error(
                context,
                ApiErrorCode::ServiceUnavailable,
                "The idempotency store is unavailable.",
            )
        })?;
    let value = format!("{prefix}_{}", &digest[..32]);
    crate::core::ResourceId::new(value)
        .map(|id| id.as_str().to_owned())
        .map_err(|_| {
            errors::api_error(
                context,
                ApiErrorCode::InternalError,
                "The idempotency resource ID is invalid.",
            )
        })
}

pub fn database<'a>(
    state: &'a Arc<AppState>,
    context: &RequestContext,
) -> Result<&'a D1Adapter, ApiError> {
    state.database.as_deref().ok_or_else(|| {
        errors::api_error(
            context,
            ApiErrorCode::ServiceUnavailable,
            "The identity store is unavailable.",
        )
    })
}

pub fn outbox_statement(
    database: &D1Adapter,
    context: &RequestContext,
    principal: Option<&Principal>,
    organization_id: Option<&str>,
    event_type: &str,
    payload: &serde_json::Value,
) -> Result<worker::d1::D1PreparedStatement, ApiError> {
    let actor = if let Some(principal) = principal {
        let actor_id = ActorId::new(principal.user_id.as_str()).map_err(|_| {
            errors::api_error(
                context,
                ApiErrorCode::InternalError,
                "The event actor is invalid.",
            )
        })?;
        ActorContext {
            actor_type: crate::core::ActorType::User,
            actor_id: Some(actor_id.clone()),
            effective_user_id: Some(actor_id),
        }
    } else {
        ActorContext::anonymous()
    };
    let organization_id = organization_id
        .map(OrganizationId::new)
        .transpose()
        .map_err(|_| {
            errors::api_error(
                context,
                ApiErrorCode::InternalError,
                "The event scope is invalid.",
            )
        })?;
    let event = EventEnvelope {
        event_id: new_event_id(),
        event_type: EventType::new(event_type).map_err(|_| {
            errors::api_error(
                context,
                ApiErrorCode::InternalError,
                "The event type is invalid.",
            )
        })?,
        occurred_at: context.received_at.clone(),
        request_id: context.request_id.clone(),
        correlation_id: context.correlation_id.clone(),
        actor,
        organization_id,
        payload: payload.clone(),
    };
    OutboxRepository::new(database)
        .insert_statement(&event)
        .map_err(|_| {
            errors::api_error(
                context,
                ApiErrorCode::ServiceUnavailable,
                "The event store is unavailable.",
            )
        })
}

pub fn domain_error(
    context: &RequestContext,
    code: ApiErrorCode,
    reason: &str,
    message: &str,
) -> ApiError {
    errors::api_error(context, code, message).with_detail("reason", json!(reason))
}

pub fn database_error(context: &RequestContext, error: worker::Error) -> ApiError {
    let debug = format!("{error:?}");
    if debug.contains("UNIQUE") || debug.contains("constraint") || debug.contains("CONFLICT") {
        domain_error(
            context,
            ApiErrorCode::Conflict,
            "conflict",
            "The request conflicts with current state.",
        )
    } else {
        errors::api_error(
            context,
            ApiErrorCode::ServiceUnavailable,
            "The identity store is unavailable.",
        )
    }
}

pub fn user_json(user: &UserRecord) -> serde_json::Value {
    json!({
        "id": user.user_id,
        "email": user.email,
        "display_name": user.display_name,
        "email_verified": user.email_verified,
        "created_at": user.created_at,
    })
}

pub fn is_development(state: &AppState) -> bool {
    state.environment == "development"
}

pub fn secure_cookie(state: &AppState) -> bool {
    state.environment == "production"
}
