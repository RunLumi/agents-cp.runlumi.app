//! P05 approval request APIs: tenant-scoped listing, scoped detail, and the
//! single resolution path (P05-CG `p05-cg-v1`, F13 FR-F13-007, F04, F16, F23).
//!
//! Resolution is the only place a privileged tool call becomes authorized. It
//! requires `approvals.resolve` on the current membership, the current project
//! scope, CSRF, an `Idempotency-Key`, and the approval's optimistic `version`.
//! Only `pending → approved|denied|expired|cancelled` is possible; a resolved
//! approval is never re-decided, and an approval whose window closed is
//! terminalized as `expired` rather than approved.
//!
//! An approval stays bound to the exact tool ID, fingerprint, run, and
//! risk-relevant argument summary the broker recorded, so a decision made for
//! one call can never be replayed for a changed tool or changed high-impact
//! arguments.

use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, Response, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    adapters::new_resource_id,
    app::AppState,
    core::{ApiError, ApiErrorCode, ApprovalId, RequestContext, StoredSuccess},
    http::auth::require_csrf,
    modules::{authorization::Permission, projects::ProjectVisibility},
    repositories::{
        ApprovalRepository, ApprovalRequestRecord, NewRunEventInput, ProjectRepository,
        RunRepository,
    },
    routes::{
        authorization::authorize_org,
        support::{
            database, database_error, domain_error, idempotency_key, outbox_statement,
            security_event_statement,
        },
        tools::{
            MutationClaim, PAGE_FETCH_EXTRA, approval_json, begin_mutation, commit_mutation,
            decode_page_cursor, internal_error, lookup_mutation, page_body, page_limit,
            replay_response, service_unavailable, validation_error, version_conflict,
        },
    },
};

/// Reason recorded when an approval window closes before anyone decided.
const EXPIRED_RESOLUTION_REASON: &str = "expired";
/// Bound on the stored resolution reason.
const RESOLUTION_REASON_MAX: usize = 512;

#[derive(Debug, Deserialize)]
pub struct ApprovalListQuery {
    pub limit: Option<u16>,
    pub cursor: Option<String>,
    pub status: Option<String>,
    pub run_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveApprovalRequest {
    pub decision: String,
    pub reason: Option<String>,
    pub version: i64,
}

/// `GET /api/v1/orgs/{org_id}/approvals`
#[worker::send]
pub async fn list_approvals(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<ApprovalListQuery>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ApprovalsRead,
        Some("approval"),
        None,
    )
    .await?;
    let status = optional_filter(&context, query.status.as_deref())?;
    if !status.is_empty() && !valid_status(&status) {
        return Err(validation_error(
            &context,
            "status_invalid",
            "Choose a valid approval status.",
        ));
    }
    let run_id = optional_filter(&context, query.run_id.as_deref())?;
    let limit = page_limit(query.limit);
    let cursor = decode_page_cursor(query.cursor.as_deref(), &context)?;
    let database = database(&state, &context)?;
    let fetched = ApprovalRepository::new(database)
        .list_approvals(
            &org_id,
            &status,
            &run_id,
            cursor
                .as_ref()
                .map(|(timestamp, id)| (timestamp.as_str(), id.as_str())),
            limit + PAGE_FETCH_EXTRA,
        )
        .await
        .map_err(|error| database_error(&context, error))?;
    let has_more = i64::try_from(fetched.len()).unwrap_or_default() > i64::from(limit);
    let page_rows = fetched
        .iter()
        .take(limit.max(0) as usize)
        .collect::<Vec<_>>();
    // The cursor advances by the fetched window, not by the visible subset, so
    // withheld rows cannot make a page repeat itself.
    let last = page_rows
        .last()
        .map(|approval| (approval.requested_at.clone(), approval.approval_id.clone()));
    let projects = ProjectRepository::new(database);
    let now = context.received_at.as_str();
    let mut items = Vec::with_capacity(page_rows.len());
    for approval in page_rows {
        if project_is_readable(
            &projects,
            &context,
            &org_id,
            &approval.project_id,
            access.principal.user_id.as_str(),
        )
        .await?
        {
            items.push(approval_projection(approval, now));
        }
    }
    Ok(Json(page_body(items, last, has_more)).into_response())
}

/// `GET /api/v1/orgs/{org_id}/approvals/{approval_id}`
#[worker::send]
pub async fn get_approval(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, approval_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ApprovalsRead,
        Some("approval"),
        Some(&approval_id),
    )
    .await?;
    if ApprovalId::new(approval_id.as_str()).is_err() {
        return Err(approval_not_found(&context));
    }
    let database = database(&state, &context)?;
    let approval = ApprovalRepository::new(database)
        .find_approval(&approval_id, &org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| approval_not_found(&context))?;
    if !project_is_readable(
        &ProjectRepository::new(database),
        &context,
        &org_id,
        &approval.project_id,
        access.principal.user_id.as_str(),
    )
    .await?
    {
        return Err(approval_not_found(&context));
    }
    Ok(Json(approval_projection(&approval, context.received_at.as_str())).into_response())
}

/// `POST /api/v1/orgs/{org_id}/approvals/{approval_id}/resolve`
#[worker::send]
pub async fn resolve_approval(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, approval_id)): Path<(String, String)>,
    Json(body): Json<ResolveApprovalRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::ApprovalsResolve,
        Some("approval"),
        Some(&approval_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let key = idempotency_key(&headers, &context)?;
    if ApprovalId::new(approval_id.as_str()).is_err() {
        return Err(approval_not_found(&context));
    }
    let decision = normalize_decision(&context, &body.decision)?;
    let reason = resolution_reason(&context, &body.reason, decision)?;
    if body.version < 1 {
        return Err(validation_error(
            &context,
            "version_invalid",
            "Reload the approval before resolving it.",
        ));
    }
    let database = database(&state, &context)?;
    let resolve_path = format!("/api/v1/orgs/{org_id}/approvals/{approval_id}/resolve");
    let fingerprint_input = format!(
        "POST\\n{resolve_path}\\n{decision}:{reason}:{}",
        body.version
    );
    if let Some(success) = lookup_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &resolve_path,
        &fingerprint_input,
        database,
        &context,
    )
    .await?
    {
        return Ok(replay_response(&success));
    }
    let approvals = ApprovalRepository::new(database);
    let current = approvals
        .find_approval(&approval_id, &org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| approval_not_found(&context))?;
    // The run's project must still be live: an archived project cannot have a
    // privileged action approved against it.
    if !project_is_active(
        &ProjectRepository::new(database),
        &context,
        &org_id,
        &current.project_id,
    )
    .await?
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "project_archived",
            "The approval belongs to an archived project.",
        ));
    }
    if body.version != current.version {
        return Err(version_conflict(&context));
    }
    if current.status.as_str() != "pending" {
        // Repeating the same recorded decision is idempotent; a different
        // decision never overwrites a recorded resolution.
        if current.status.as_str() == decision
            && current.resolved_by_principal_id.as_deref()
                == Some(access.principal.user_id.as_str())
        {
            return Ok((
                StatusCode::OK,
                Json(approval_projection(&current, context.received_at.as_str())),
            )
                .into_response());
        }
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "approval_already_resolved",
            "The approval was already resolved.",
        ));
    }
    let live = current.expires_at.as_str() > context.received_at.as_str();
    // A closed window is terminalized as `expired`, never approved.
    let (status, stored_reason) = if live {
        (decision, reason)
    } else {
        ("expired", EXPIRED_RESOLUTION_REASON.to_owned())
    };
    let expected = ApprovalRequestRecord {
        status: status.to_owned(),
        resolved_by_principal_id: Some(access.principal.user_id.as_str().to_owned()),
        resolved_at: Some(context.received_at.as_str().to_owned()),
        resolution_reason: Some(stored_reason.clone()),
        version: current.version + 1,
        ..current.clone()
    };
    let success = StoredSuccess::new(
        200,
        approval_projection(&expected, context.received_at.as_str()),
    )
    .map_err(|_| internal_error(&context))?;
    let (write, guard) = if live {
        (
            approvals.resolve_statement(
                &approval_id,
                &org_id,
                status,
                access.principal.user_id.as_str(),
                &stored_reason,
                &context.received_at,
                current.version,
            ),
            approvals.assert_pending_statement(
                &approval_id,
                &org_id,
                current.version,
                &context.received_at,
            ),
        )
    } else {
        (
            approvals.expire_statement(
                &approval_id,
                access.principal.user_id.as_str(),
                &context.received_at,
            ),
            approvals.assert_pending_version_statement(&approval_id, &org_id, current.version),
        )
    };
    let write = write.map_err(|error| database_error(&context, error))?;
    let guard = guard.map_err(|error| database_error(&context, error))?;
    let event = run_event_statement(
        &context,
        database,
        &expected,
        status,
        &stored_reason,
        access.principal.user_id.as_str(),
    )
    .await?;
    let security_event_id = new_resource_id("sec").as_str().to_owned();
    let security = security_event_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        &security_event_id,
        "approval.resolved.v1",
        "approval",
        Some(&approval_id),
        if status == "approved" {
            "success"
        } else {
            "denied"
        },
        &json!({
            "decision": status,
            "approval_mode": expected.approval_mode,
            "risk_class": expected.risk_class,
        }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "approval.resolved.v1",
        &json!({
            "approval_id": expected.approval_id,
            "run_id": expected.run_id,
            "tool_call_id": expected.tool_call_id,
            "tool_id": expected.tool_id,
            "tool_fingerprint": expected.tool_fingerprint,
            "decision": status,
        }),
    )?;
    let mutation = begin_mutation(
        &key,
        access.principal.user_id.as_str(),
        &org_id,
        "POST",
        &resolve_path,
        &fingerprint_input,
        database,
        &context,
    )
    .await?;
    let pending = match mutation {
        MutationClaim::Replay(success) => return Ok(replay_response(&success)),
        MutationClaim::Pending(pending) => pending,
    };
    let results = commit_mutation(
        database,
        &pending,
        &context.received_at,
        &success,
        vec![guard, write, event, security],
        outbox,
    )
    .await;
    let results = match results {
        Ok(results) => results,
        Err(error) => {
            // The version guard aborts the batch when a concurrent resolver won
            // the race. Re-read so the caller sees the real outcome instead of a
            // storage error.
            let latest = approvals
                .find_approval(&approval_id, &org_id)
                .await
                .map_err(|_| service_unavailable(&context))?;
            if latest
                .as_ref()
                .is_some_and(|latest| latest.status != "pending")
            {
                return Err(domain_error(
                    &context,
                    ApiErrorCode::Conflict,
                    "approval_already_resolved",
                    "The approval was already resolved.",
                ));
            }
            return Err(database_error(&context, error));
        }
    };
    if crate::adapters::d1::D1Adapter::changes(&results[3]).unwrap_or_default() != 1 {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "approval_already_resolved",
            "The approval was already resolved.",
        ));
    }
    Ok(replay_response(&success))
}

/// Append the resolution to the run timeline so the execution host can correlate
/// the decision with the run it belongs to.
async fn run_event_statement(
    context: &RequestContext,
    database: &crate::adapters::d1::D1Adapter,
    approval: &ApprovalRequestRecord,
    status: &str,
    reason: &str,
    resolved_by: &str,
) -> Result<worker::d1::D1PreparedStatement, ApiError> {
    let runs = RunRepository::new(database);
    let sequence = runs
        .next_event_sequence(&approval.org_id, &approval.run_id)
        .await
        .map_err(|error| database_error(context, error))?;
    // Bounded metadata only: no argument body, prompt, or secret.
    let payload = json!({
        "decision": status,
        "tool_id": approval.tool_id,
        "risk_class": approval.risk_class,
        "reason": reason,
    });
    runs.insert_event_statement(&NewRunEventInput {
        run_event_id: new_resource_id("rev").as_str(),
        run_id: &approval.run_id,
        sequence,
        event_type: "approval.resolved.v1",
        occurred_at: &context.received_at,
        actor_type: "user",
        actor_id: Some(resolved_by),
        correlation_id: context.correlation_id.as_str(),
        tool_call_id: Some(&approval.tool_call_id),
        approval_id: Some(&approval.approval_id),
        payload: &payload,
    })
    .map_err(|error| database_error(context, error))
}

/// Approvals a caller may read: the project must belong to the organization and
/// a restricted project still needs an explicit grant.
async fn project_is_readable(
    projects: &ProjectRepository<'_>,
    context: &RequestContext,
    org_id: &str,
    project_id: &str,
    user_id: &str,
) -> Result<bool, ApiError> {
    let project = projects
        .find_project(project_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .filter(|project| project.org_id == org_id)
        .ok_or_else(|| approval_not_found(context))?;
    let visibility = ProjectVisibility::parse(&project.visibility)
        .ok_or_else(|| service_unavailable(context))?;
    if visibility != ProjectVisibility::Restricted {
        return Ok(true);
    }
    projects
        .member_has_explicit_grant(project_id, org_id, user_id)
        .await
        .map_err(|_| service_unavailable(context))
}

/// Resolution additionally requires a live project.
async fn project_is_active(
    projects: &ProjectRepository<'_>,
    context: &RequestContext,
    org_id: &str,
    project_id: &str,
) -> Result<bool, ApiError> {
    let project = projects
        .find_project(project_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .filter(|project| project.org_id == org_id)
        .ok_or_else(|| approval_not_found(context))?;
    Ok(project.archived_at.is_none())
}

/// Projected approval plus a derived expiry flag, so a pending approval whose
/// window has closed is visible as expired without a read mutating state.
fn approval_projection(approval: &ApprovalRequestRecord, now: &str) -> Value {
    let mut value = approval_json(approval);
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "expired".to_owned(),
            json!(approval.status == "pending" && approval.expires_at.as_str() <= now),
        );
    }
    value
}

fn valid_status(value: &str) -> bool {
    matches!(
        value,
        "pending" | "approved" | "denied" | "expired" | "cancelled"
    )
}

fn normalize_decision<'a>(context: &RequestContext, value: &'a str) -> Result<&'a str, ApiError> {
    match value {
        "approved" | "denied" | "cancelled" => Ok(value),
        _ => Err(validation_error(
            context,
            "decision_invalid",
            "Choose a valid approval decision.",
        )),
    }
}

/// A denial must record why; an approval may state its own context.
fn resolution_reason(
    context: &RequestContext,
    value: &Option<String>,
    decision: &str,
) -> Result<String, ApiError> {
    let reason = value
        .as_ref()
        .map(|value| value.trim().to_owned())
        .unwrap_or_default();
    if reason.is_empty() {
        return Ok(match decision {
            "approved" => "approved".to_owned(),
            "denied" => "denied_by_reviewer".to_owned(),
            _ => "cancelled_by_reviewer".to_owned(),
        });
    }
    if reason.chars().count() > RESOLUTION_REASON_MAX || reason.chars().any(char::is_control) {
        return Err(validation_error(
            context,
            "reason_invalid",
            "The resolution reason is invalid.",
        ));
    }
    Ok(reason)
}

fn optional_filter(context: &RequestContext, value: Option<&str>) -> Result<String, ApiError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(String::new());
    };
    if value.len() > 64 || value.chars().any(char::is_control) {
        return Err(validation_error(
            context,
            "filter_invalid",
            "The filter value is invalid.",
        ));
    }
    Ok(value.to_owned())
}

/// A cross-tenant or unknown approval is indistinguishable from a missing one.
fn approval_not_found(context: &RequestContext) -> ApiError {
    domain_error(
        context,
        ApiErrorCode::NotFound,
        "approval_not_found",
        "The approval request was not found.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> RequestContext {
        RequestContext::new(
            "req_0123456789abcdef0123456789abcdef".parse().unwrap(),
            "trace-1".parse().unwrap(),
            "2026-09-25T12:00:00.000Z".parse().unwrap(),
        )
    }

    fn approval(status: &str, expires_at: &str) -> ApprovalRequestRecord {
        ApprovalRequestRecord {
            approval_id: "apr_0123456789abcdef0123456789abcdef".to_owned(),
            org_id: "org_0123456789abcdef0123456789abcdef".to_owned(),
            project_id: "prj_0123456789abcdef0123456789abcdef".to_owned(),
            run_id: "run_0123456789abcdef0123456789abcdef".to_owned(),
            tool_call_id: "tcl_0123456789abcdef0123456789abcdef".to_owned(),
            tool_id: "tool_0123456789abcdef0123456789abcdef".to_owned(),
            tool_fingerprint: "sha256:aa".to_owned(),
            risk_class: "external_side_effect".to_owned(),
            approval_mode: "per_use".to_owned(),
            status: status.to_owned(),
            arguments_summary: "domain=example.test; operation=submit".to_owned(),
            requested_by_principal_id: "usr_0123456789abcdef0123456789abcdef".to_owned(),
            requested_at: "2026-09-25T12:00:01.000Z".to_owned(),
            expires_at: expires_at.to_owned(),
            resolved_by_principal_id: None,
            resolved_at: None,
            resolution_reason: None,
            version: 1,
        }
    }

    #[test]
    fn a_pending_approval_past_its_window_projects_as_expired() {
        let live = approval_projection(
            &approval("pending", "2026-09-25T12:15:01.000Z"),
            "2026-09-25T12:00:30.000Z",
        );
        assert_eq!(live["status"], json!("pending"));
        assert_eq!(live["expired"], json!(false));
        let stale = approval_projection(
            &approval("pending", "2026-09-25T12:00:01.000Z"),
            "2026-09-25T12:00:30.000Z",
        );
        assert_eq!(stale["expired"], json!(true));
    }

    #[test]
    fn the_projection_exposes_only_the_bounded_binding() {
        let value = approval_projection(
            &approval("pending", "2026-09-25T12:15:01.000Z"),
            "2026-09-25T12:00:30.000Z",
        );
        let object = value.as_object().unwrap();
        assert_eq!(object.get("tool_fingerprint").unwrap(), &json!("sha256:aa"));
        assert!(object.contains_key("arguments_summary"));
        for forbidden in [
            "arguments",
            "secret",
            "credential",
            "prompt",
            "arguments_body",
        ] {
            assert!(!object.contains_key(forbidden), "exposed {forbidden}");
        }
    }

    #[test]
    fn only_pending_and_terminal_statuses_filter() {
        for status in ["pending", "approved", "denied", "expired", "cancelled"] {
            assert!(valid_status(status), "rejected {status}");
        }
        assert!(!valid_status("deleted"));
        assert!(!valid_status(""));
    }

    #[test]
    fn decisions_are_whitelisted_and_reasons_are_bounded() {
        let context = context();
        assert_eq!(
            normalize_decision(&context, "approved").unwrap(),
            "approved"
        );
        assert_eq!(normalize_decision(&context, "denied").unwrap(), "denied");
        assert_eq!(
            normalize_decision(&context, "cancelled").unwrap(),
            "cancelled"
        );
        assert!(normalize_decision(&context, "allow").is_err());
        assert_eq!(
            resolution_reason(&context, &None, "approved").unwrap(),
            "approved"
        );
        assert_eq!(
            resolution_reason(&context, &None, "denied").unwrap(),
            "denied_by_reviewer"
        );
        assert_eq!(
            resolution_reason(
                &context,
                &Some("  verified domain  ".to_owned()),
                "approved"
            )
            .unwrap(),
            "verified domain"
        );
        assert!(resolution_reason(&context, &Some("x".repeat(513)), "approved").is_err());
        assert!(resolution_reason(&context, &Some("two\nlines".to_owned()), "approved").is_err());
    }

    #[test]
    fn filters_stay_within_the_documented_bounds() {
        let context = context();
        assert_eq!(optional_filter(&context, None).unwrap(), "");
        assert_eq!(optional_filter(&context, Some("  ")).unwrap(), "");
        assert_eq!(
            optional_filter(&context, Some("pending")).unwrap(),
            "pending"
        );
        assert!(optional_filter(&context, Some(&"x".repeat(65))).is_err());
        assert!(optional_filter(&context, Some("bad\nvalue")).is_err());
    }
}
