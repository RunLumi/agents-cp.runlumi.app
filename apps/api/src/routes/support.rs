use std::sync::Arc;

use serde_json::json;

use crate::{
    adapters::{
        d1::{BindValue, D1Adapter},
        new_event_id,
    },
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

/// Build an immutable security-event insert for a mutation. The helper
/// intentionally accepts only bounded metadata and never serializes a request
/// body, credential, prompt, or response. P05 callers may add device/run
/// correlation without changing the P01-P04 call sites.
#[allow(clippy::too_many_arguments)]
pub fn security_event_statement_with_context<'a>(
    database: &'a D1Adapter,
    context: &RequestContext,
    principal: Option<&Principal>,
    organization_id: Option<&'a str>,
    event_id: &'a str,
    action: &'a str,
    resource_type: &'a str,
    resource_id: Option<&'a str>,
    outcome: &'a str,
    metadata: &serde_json::Value,
    device_id: Option<&'a str>,
    run_id: Option<&'a str>,
    agent_session_id: Option<&'a str>,
    tool_call_id: Option<&'a str>,
) -> Result<worker::d1::D1PreparedStatement, ApiError> {
    let metadata = serde_json::to_string(metadata).map_err(|_| {
        errors::api_error(
            context,
            ApiErrorCode::InternalError,
            "The security event metadata is invalid.",
        )
    })?;
    let organization_id = organization_id.map_or(BindValue::Null, BindValue::Text);
    let actor_id = principal
        .map(|value| BindValue::Text(value.user_id.as_str()))
        .unwrap_or(BindValue::Null);
    let effective_user_id = principal
        .map(|value| BindValue::Text(value.user_id.as_str()))
        .unwrap_or(BindValue::Null);
    let session_id = principal
        .map(|value| BindValue::Text(value.session_id.as_str()))
        .unwrap_or(BindValue::Null);
    let device_id = device_id.map_or(BindValue::Null, BindValue::Text);
    let resource_id = resource_id.map_or(BindValue::Null, BindValue::Text);
    let run_id = run_id.map_or(BindValue::Null, BindValue::Text);
    let agent_session_id = agent_session_id.map_or(BindValue::Null, BindValue::Text);
    let tool_call_id = tool_call_id.map_or(BindValue::Null, BindValue::Text);
    database
        .prepare(
            "INSERT INTO security_events (event_id, org_id, actor_type, actor_id, effective_user_id, session_id, device_id, run_id, agent_session_id, tool_call_id, action, resource_type, resource_id, outcome, reason, metadata_json, request_id, correlation_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, NULL, ?15, ?16, ?17, ?18)",
            &[
                BindValue::Text(event_id),
                organization_id,
                BindValue::Text(if principal.is_some() { "user" } else { "system" }),
                actor_id,
                effective_user_id,
                session_id,
                device_id,
                run_id,
                agent_session_id,
                tool_call_id,
                BindValue::Text(action),
                BindValue::Text(resource_type),
                resource_id,
                BindValue::Text(outcome),
                BindValue::Text(&metadata),
                BindValue::Text(context.request_id.as_str()),
                BindValue::Text(context.correlation_id.as_str()),
                BindValue::Text(context.received_at.as_str()),
            ],
        )
        .map_err(|_| {
            errors::api_error(
                context,
                ApiErrorCode::ServiceUnavailable,
                "The security event store is unavailable.",
            )
        })
}

/// Build an immutable security-event insert for a P01-P04 mutation.
#[allow(clippy::too_many_arguments)]
pub fn security_event_statement<'a>(
    database: &'a D1Adapter,
    context: &RequestContext,
    principal: Option<&Principal>,
    organization_id: Option<&'a str>,
    event_id: &'a str,
    action: &'a str,
    resource_type: &'a str,
    resource_id: Option<&'a str>,
    outcome: &'a str,
    metadata: &serde_json::Value,
) -> Result<worker::d1::D1PreparedStatement, ApiError> {
    security_event_statement_with_context(
        database,
        context,
        principal,
        organization_id,
        event_id,
        action,
        resource_type,
        resource_id,
        outcome,
        metadata,
        None,
        None,
        None,
        None,
    )
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
