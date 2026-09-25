//! Tenant-scoped F16 audit query route.
//!
//! Authorization is delegated to the centralized organization policy path.
//! The repository requires the path organization as an explicit query scope,
//! so a handler bug cannot turn this into an unscoped audit search.

use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, Response},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    app::AppState,
    core::{ApiError, ApiErrorCode, RequestContext},
    modules::authorization::Permission,
    repositories::{AuditQuery, AuditQueryError, AuditRepository},
    routes::{authorization::authorize_org, errors, support::database},
};

const DEFAULT_LIMIT: u16 = 50;
const MAX_LIMIT: u16 = 100;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditListQuery {
    pub limit: Option<u16>,
    pub cursor: Option<String>,
    /// `actor` is the wire-friendly F16 filter.  `actor_id` is accepted as a
    /// compatibility alias for clients that already use the repository field.
    pub actor: Option<String>,
    pub actor_id: Option<String>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    /// An opaque resource filter alias.  It is interpreted as `resource_id`.
    pub resource: Option<String>,
    pub outcome: Option<String>,
    pub correlation_id: Option<String>,
    pub run_id: Option<String>,
    pub agent_session_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub request_id: Option<String>,
    pub device_id: Option<String>,
    pub session_id: Option<String>,
    pub project_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[worker::send]
pub async fn list(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<AuditListQuery>,
) -> Result<Response<Body>, ApiError> {
    // This call establishes the current session, organization state, active
    // membership, and `audit.read` permission.  The returned principal is not
    // used as a filter: an authorized auditor may search the whole tenant.
    let _ = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::AuditRead,
        Some("audit"),
        None,
    )
    .await?;

    let actor = choose_alias(
        query.actor.as_deref(),
        query.actor_id.as_deref(),
        &context,
        "actor_filter_invalid",
    )?;
    let resource_id = choose_alias(
        query.resource_id.as_deref(),
        query.resource.as_deref(),
        &context,
        "resource_filter_invalid",
    )?;
    let audit_query = AuditQuery {
        organization_id: &org_id,
        actor_id: actor,
        action: query.action.as_deref(),
        resource_type: query.resource_type.as_deref(),
        resource_id,
        outcome: query.outcome.as_deref(),
        correlation_id: query.correlation_id.as_deref(),
        run_id: query.run_id.as_deref(),
        agent_session_id: query.agent_session_id.as_deref(),
        tool_call_id: query.tool_call_id.as_deref(),
        request_id: query.request_id.as_deref(),
        device_id: query.device_id.as_deref(),
        session_id: query.session_id.as_deref(),
        project_id: query.project_id.as_deref(),
        from: query.from.as_deref(),
        to: query.to.as_deref(),
        cursor: query.cursor.as_deref(),
        limit: page_limit(query.limit),
    };
    audit_query
        .validate()
        .map_err(|error| validation_error(&context, error))?;

    let database = database(&state, &context)?;
    let page = AuditRepository::new(database)
        .query(&audit_query)
        .await
        .map_err(|_| unavailable(&context))?;
    Ok(Json(page).into_response())
}

/// Compatibility entry point for the existing `/orgs/{org_id}/audit` route
/// name.  The coordinator can wire either this function or [`list`].
#[worker::send]
pub async fn audit(
    state: State<Arc<AppState>>,
    context: Extension<RequestContext>,
    headers: HeaderMap,
    org_id: Path<String>,
    query: Query<AuditListQuery>,
) -> Result<Response<Body>, ApiError> {
    list(state, context, headers, org_id, query).await
}

fn choose_alias<'a>(
    primary: Option<&'a str>,
    alias: Option<&'a str>,
    context: &RequestContext,
    reason: &'static str,
) -> Result<Option<&'a str>, ApiError> {
    match (primary, alias) {
        (Some(left), Some(right)) if left != right => Err(domain_error(
            context,
            ApiErrorCode::ValidationFailed,
            reason,
            "Conflicting audit filters were supplied.",
        )),
        (Some(value), _) | (_, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

fn page_limit(limit: Option<u16>) -> u16 {
    match limit {
        None | Some(0) => DEFAULT_LIMIT,
        Some(value) => value.min(MAX_LIMIT),
    }
}

fn validation_error(context: &RequestContext, error: AuditQueryError) -> ApiError {
    let (code, reason, message) = match error {
        AuditQueryError::InvalidOrganization => (
            ApiErrorCode::ValidationFailed,
            "audit_organization_invalid",
            "The audit query is invalid.",
        ),
        AuditQueryError::InvalidFilter => (
            ApiErrorCode::ValidationFailed,
            "audit_filter_invalid",
            "The audit query is invalid.",
        ),
        AuditQueryError::InvalidOutcome => (
            ApiErrorCode::ValidationFailed,
            "audit_outcome_invalid",
            "The audit query is invalid.",
        ),
        AuditQueryError::InvalidTimeRange => (
            ApiErrorCode::ValidationFailed,
            "audit_time_range_invalid",
            "The audit query is invalid.",
        ),
        AuditQueryError::InvalidCursor => (
            ApiErrorCode::BadRequest,
            "invalid_cursor",
            "The pagination cursor is invalid.",
        ),
        AuditQueryError::InvalidPage => (
            ApiErrorCode::ValidationFailed,
            "audit_page_invalid",
            "The audit query is invalid.",
        ),
    };
    domain_error(context, code, reason, message)
}

fn domain_error(
    context: &RequestContext,
    code: ApiErrorCode,
    reason: &'static str,
    message: &'static str,
) -> ApiError {
    errors::api_error(context, code, message).with_detail("reason", json!(reason))
}

fn unavailable(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::ServiceUnavailable,
        "The audit store is unavailable.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_limit_is_bounded() {
        assert_eq!(page_limit(None), DEFAULT_LIMIT);
        assert_eq!(page_limit(Some(0)), DEFAULT_LIMIT);
        assert_eq!(page_limit(Some(1)), 1);
        assert_eq!(page_limit(Some(100)), 100);
        assert_eq!(page_limit(Some(255)), MAX_LIMIT);
    }

    #[test]
    fn invalid_cursor_uses_the_frozen_bad_request_shape() {
        let context = RequestContext::new(
            "req_0123456789abcdef0123456789abcdef".parse().unwrap(),
            "trace-1".parse().unwrap(),
            "2026-09-24T12:00:00.000Z".parse().unwrap(),
        );
        let error = validation_error(&context, AuditQueryError::InvalidCursor);
        assert_eq!(error.error.code, ApiErrorCode::BadRequest);
        assert_eq!(error.error.details["reason"], "invalid_cursor");
    }

    #[test]
    fn conflicting_aliases_are_rejected_without_echoing_values() {
        let context = RequestContext::new(
            "req_0123456789abcdef0123456789abcdef".parse().unwrap(),
            "trace-1".parse().unwrap(),
            "2026-09-24T12:00:00.000Z".parse().unwrap(),
        );
        let error = choose_alias(
            Some("actor-a"),
            Some("actor-b"),
            &context,
            "actor_filter_invalid",
        )
        .unwrap_err();
        assert_eq!(error.error.code, ApiErrorCode::ValidationFailed);
        assert!(!format!("{error:?}").contains("actor-a"));
        assert!(!format!("{error:?}").contains("actor-b"));
    }
}
