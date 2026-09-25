use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, Response, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    adapters::{add_seconds, deliver_auth_code, new_resource_id, new_secret, sha256_hex},
    app::AppState,
    core::{ApiError, ApiErrorCode, Principal, RequestContext},
    http::auth::{clear_session_cookies, require_csrf, require_session},
    modules::{
        authorization::Permission,
        identity::NormalizedEmail,
        memberships::role_can_be_invited,
        organizations::{normalize_slug, validate_display_name, validate_version},
        teams::{normalize_team_slug, validate_team_name},
    },
    repositories::{
        IdentityRepository, OrganizationRepository, SecurityEventInput, SecurityEventRepository,
    },
    routes::{
        auth::EmptyRequest,
        authorization::authorize_org,
        errors,
        support::{
            database, database_error, deterministic_resource_id, domain_error, idempotency_key,
            outbox_statement, secure_cookie,
        },
    },
};

const INVITE_TTL_SECONDS: u32 = 60 * 60 * 24 * 7;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateOrgRequest {
    pub display_name: String,
    pub slug: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateOrgRequest {
    pub display_name: String,
    pub slug: String,
    pub version: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteRequest {
    pub email: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptInviteRequest {
    pub token: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleRequest {
    pub role: String,
    pub version: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferOwnershipRequest {
    pub target_membership_id: String,
    pub reauth_grant_id: String,
    pub reauth_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleRequest {
    pub version: i64,
    pub reauth_grant_id: String,
    pub reauth_token: String,
    #[serde(default)]
    pub confirmation: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTeamRequest {
    pub display_name: String,
    pub slug: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddTeamMemberRequest {
    pub membership_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<u16>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PageResponse<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[worker::send]
pub async fn create(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(body): Json<CreateOrgRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    if !authenticated.principal.email_verified {
        return Err(domain_error(
            &context,
            ApiErrorCode::PermissionDenied,
            "email_verification_required",
            "Verify your email before creating an organization.",
        ));
    }
    let display_name = validate_display_name(&body.display_name).map_err(|_| {
        validation_error(
            &context,
            "display_name_invalid",
            "Enter a valid organization name.",
        )
    })?;
    let slug = match body.slug {
        Some(value) => normalize_slug(&value).map_err(|_| {
            validation_error(
                &context,
                "slug_invalid",
                "Choose a valid organization slug.",
            )
        })?,
        None => {
            let generated = new_resource_id("org");
            let suffix = generated
                .as_str()
                .split_once('_')
                .map_or("org", |(_, value)| &value[..8]);
            default_slug(&display_name, suffix)
        }
    };
    let database = database(&state, &context)?;
    let key = idempotency_key(&headers, &context)?;
    let org_id = deterministic_resource_id(
        "org",
        &key,
        &format!("org:{}", authenticated.principal.user_id.as_str()),
        &context,
    )
    .await?;
    let membership_id = deterministic_resource_id(
        "mem",
        &key,
        &format!("membership:{}", authenticated.principal.user_id.as_str()),
        &context,
    )
    .await?;
    // P06: the license projection identifier is derived from the SAME
    // idempotency key as the organization and membership, so a retried create
    // cannot mint a second license row for the same organization.
    let license_state_id = deterministic_resource_id(
        "lic",
        &key,
        &format!("license:{}", authenticated.principal.user_id.as_str()),
        &context,
    )
    .await?;
    let event_id = generated_id("sec");
    let repository = OrganizationRepository::new(database);
    if let Some(existing) = repository
        .find_organization(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        if existing.display_name != display_name
            || existing.slug != slug
            || existing.created_by_user_id != authenticated.principal.user_id.as_str()
        {
            return Err(domain_error(
                &context,
                ApiErrorCode::Conflict,
                "idempotency_conflict",
                "The idempotency key was already used for a different request.",
            ));
        }
        let membership = repository
            .find_membership(&org_id, authenticated.principal.user_id.as_str())
            .await
            .map_err(|error| database_error(&context, error))?
            .ok_or_else(|| service_unavailable(&context))?;
        return Ok((
            StatusCode::OK,
            Json(json!({ "organization": existing, "membership": membership })),
        )
            .into_response());
    }
    let org_statement = repository
        .insert_organization_statement(
            &org_id,
            &display_name,
            &slug,
            authenticated.principal.user_id.as_str(),
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let membership_statement = repository
        .insert_owner_membership_statement(
            &membership_id,
            &org_id,
            authenticated.principal.user_id.as_str(),
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let security_statement = security_statement(
        database,
        &context,
        &authenticated.principal,
        &event_id,
        Some(&org_id),
        "organization.created.v1",
        "organization",
        Some(&org_id),
        json!({ "kind": "team" }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&authenticated.principal),
        Some(&org_id),
        "organization.created.v1",
        &json!({ "kind": "team" }),
    )?;
    // P06: the license projection joins the SAME batch. Dispatch fails closed
    // when an organization has no `license_states` row, so creating the org
    // without it would produce a tenant that can never run an automation — a
    // failure that only surfaces when someone tries to use the product.
    let license_statement = repository
        .insert_default_license_state_statement(
            license_state_id.as_str(),
            org_id.as_str(),
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    database
        .batch(vec![
            org_statement,
            membership_statement,
            license_statement,
            security_statement,
            outbox,
        ])
        .await
        .map_err(|error| database_error(&context, error))?;
    let organization = repository
        .find_organization(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| service_unavailable(&context))?;
    let membership = repository
        .find_membership(&org_id, authenticated.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| service_unavailable(&context))?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "organization": organization, "membership": membership })),
    )
        .into_response())
}

#[worker::send]
pub async fn list(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Response<Body>, ApiError> {
    reject_cursor(&context, query.cursor.as_deref())?;
    let authenticated = require_session(&state, &headers, &context).await?;
    let limit = page_limit(query.limit);
    let database = database(&state, &context)?;
    let organizations = OrganizationRepository::new(database)
        .list_for_user(authenticated.principal.user_id.as_str(), limit, 0)
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(Json(PageResponse {
        items: organizations,
        next_cursor: None,
        has_more: false,
    })
    .into_response())
}

#[worker::send]
pub async fn get(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::OrgRead,
        Some("organization"),
        Some(&org_id),
    )
    .await?;
    Ok(Json(access.organization).into_response())
}

#[worker::send]
pub async fn update(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<UpdateOrgRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::OrgManage,
        Some("organization"),
        Some(&org_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    validate_version(body.version).map_err(|_| {
        validation_error(
            &context,
            "version_invalid",
            "Reload the organization and try again.",
        )
    })?;
    let display_name = validate_display_name(&body.display_name).map_err(|_| {
        validation_error(
            &context,
            "display_name_invalid",
            "Enter a valid organization name.",
        )
    })?;
    let slug = normalize_slug(&body.slug).map_err(|_| {
        validation_error(
            &context,
            "slug_invalid",
            "Choose a valid organization slug.",
        )
    })?;
    let database = database(&state, &context)?;
    let repository = OrganizationRepository::new(database);
    if !repository
        .update_organization(
            &org_id,
            &display_name,
            &slug,
            body.version,
            &context.received_at,
        )
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The organization changed. Refresh and try again.",
        ));
    }
    let event_id = generated_id("sec");
    let security_statement = security_statement(
        database,
        &context,
        &access.principal,
        &event_id,
        Some(&org_id),
        "organization.updated.v1",
        "organization",
        Some(&org_id),
        json!({ "fields": ["display_name", "slug"] }),
    )?;
    database
        .batch(vec![security_statement])
        .await
        .map_err(|error| database_error(&context, error))?;
    let organization = repository
        .find_organization(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| service_unavailable(&context))?;
    Ok(Json(organization).into_response())
}

#[worker::send]
pub async fn list_members(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Response<Body>, ApiError> {
    reject_cursor(&context, query.cursor.as_deref())?;
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::MembersRead,
        Some("organization"),
        Some(&org_id),
    )
    .await?;
    let database = database(&state, &context)?;
    let members = OrganizationRepository::new(database)
        .list_members(&org_id, page_limit(query.limit), 0)
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(Json(PageResponse {
        items: members,
        next_cursor: None,
        has_more: false,
    })
    .into_response())
}

#[worker::send]
pub async fn invite(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<InviteRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::MembersManage,
        Some("invitation"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let email = NormalizedEmail::parse(&body.email)
        .map_err(|_| validation_error(&context, "email_invalid", "Enter a valid email address."))?;
    let role = crate::modules::authorization::MembershipRole::parse(&body.role)
        .filter(|role| role_can_be_invited(*role))
        .ok_or_else(|| {
            validation_error(&context, "role_invalid", "Choose a valid invitation role.")
        })?;
    let database = database(&state, &context)?;
    let key = idempotency_key(&headers, &context)?;
    let invitation_id = deterministic_resource_id(
        "inv",
        &key,
        &format!(
            "invitation:{}:{}",
            org_id,
            access.principal.user_id.as_str()
        ),
        &context,
    )
    .await?;
    let repository = OrganizationRepository::new(database);
    if let Some(existing) = repository
        .find_invitation(&invitation_id)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        if existing.email != email.as_str() || existing.role != role.as_str() {
            return Err(domain_error(
                &context,
                ApiErrorCode::Conflict,
                "idempotency_conflict",
                "The idempotency key was already used for a different request.",
            ));
        }
        return Ok((
            StatusCode::OK,
            Json(json!({ "invitation": redact_invitation(existing), "duplicate": true })),
        )
            .into_response());
    }
    if let Some(existing) = repository
        .find_pending_invitation(&org_id, email.as_str())
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Ok((
            StatusCode::OK,
            Json(json!({ "invitation": redact_invitation(existing), "duplicate": true })),
        )
            .into_response());
    }
    let token = new_secret();
    let token_hash = sha256_hex(&token)
        .await
        .map_err(|_| service_unavailable(&context))?;
    let expires_at = add_seconds(&context.received_at, INVITE_TTL_SECONDS)
        .map_err(|_| service_unavailable(&context))?;
    let event_id = generated_id("sec");
    let invitation_statement = repository
        .insert_invitation_statement(
            &invitation_id,
            &org_id,
            email.as_str(),
            role.as_str(),
            access.principal.user_id.as_str(),
            &token_hash,
            &expires_at,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let security_statement = security_statement(
        database,
        &context,
        &access.principal,
        &event_id,
        Some(&org_id),
        "membership.invited.v1",
        "invitation",
        Some(&invitation_id),
        json!({ "role": role.as_str() }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "membership.invited.v1",
        &json!({ "role": role.as_str() }),
    )?;
    database
        .batch(vec![invitation_statement, security_statement, outbox])
        .await
        .map_err(|error| database_error(&context, error))?;
    deliver_auth_code(&state, email.as_str(), &token, "invitation")
        .await
        .map_err(|_| service_unavailable(&context))?;
    let invitation = repository
        .find_invitation(&invitation_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| service_unavailable(&context))?;
    let mut response = json!({ "invitation": redact_invitation(invitation) });
    if state.environment == "development" {
        response["development_token"] = json!(token);
    }
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

#[worker::send]
pub async fn list_invitations(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Response<Body>, ApiError> {
    reject_cursor(&context, query.cursor.as_deref())?;
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::MembersRead,
        Some("invitation"),
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let invitations = OrganizationRepository::new(database)
        .list_invitations(&org_id, page_limit(query.limit), 0)
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(Json(PageResponse {
        items: invitations
            .into_iter()
            .map(redact_invitation)
            .collect::<Vec<_>>(),
        next_cursor: None,
        has_more: false,
    })
    .into_response())
}

#[worker::send]
pub async fn revoke_invitation(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, invitation_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::MembersManage,
        Some("invitation"),
        Some(&invitation_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let database = database(&state, &context)?;
    if !OrganizationRepository::new(database)
        .revoke_invitation(&invitation_id, &org_id, &context.received_at)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "invitation_replayed",
            "The invitation is no longer available.",
        ));
    }
    let event_id = generated_id("sec");
    let security_statement = security_statement(
        database,
        &context,
        &access.principal,
        &event_id,
        Some(&org_id),
        "membership.invitation_revoked.v1",
        "invitation",
        Some(&invitation_id),
        json!({}),
    )?;
    database
        .batch(vec![security_statement])
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[worker::send]
pub async fn resend_invitation(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, invitation_id)): Path<(String, String)>,
    Json(_body): Json<EmptyRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::MembersManage,
        Some("invitation"),
        Some(&invitation_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let database = database(&state, &context)?;
    let repository = OrganizationRepository::new(database);
    let target_email = repository
        .find_invitation(&invitation_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .filter(|invitation| invitation.org_id == org_id)
        .map(|invitation| invitation.email)
        .ok_or_else(|| {
            domain_error(
                &context,
                ApiErrorCode::NotFound,
                "resource_not_found",
                "The invitation was not found.",
            )
        })?;
    let token = new_secret();
    let token_hash = sha256_hex(&token)
        .await
        .map_err(|_| service_unavailable(&context))?;
    let expires_at = add_seconds(&context.received_at, INVITE_TTL_SECONDS)
        .map_err(|_| service_unavailable(&context))?;
    let statement = repository
        .rotate_invitation_statement(
            &invitation_id,
            &org_id,
            &token_hash,
            &expires_at,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let event_id = generated_id("sec");
    let security_statement = security_statement(
        database,
        &context,
        &access.principal,
        &event_id,
        Some(&org_id),
        "membership.invitation_resent.v1",
        "invitation",
        Some(&invitation_id),
        json!({}),
    )?;
    let results = database
        .batch(vec![statement, security_statement])
        .await
        .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[0]).unwrap_or_default() != 1 {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "invitation_replayed",
            "The invitation is no longer available.",
        ));
    }
    deliver_auth_code(&state, &target_email, &token, "invitation")
        .await
        .map_err(|_| service_unavailable(&context))?;
    let refreshed = repository
        .find_invitation(&invitation_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| service_unavailable(&context))?;
    let mut response = json!({ "invitation": redact_invitation(refreshed) });
    if state.environment == "development" {
        response["development_token"] = json!(token);
    }
    Ok(Json(response).into_response())
}

#[worker::send]
pub async fn accept_invitation(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(invitation_id): Path<String>,
    Json(body): Json<AcceptInviteRequest>,
) -> Result<Response<Body>, ApiError> {
    let authenticated = require_session(&state, &headers, &context).await?;
    require_csrf(&headers, &authenticated.session, &context).await?;
    if !authenticated.principal.email_verified {
        return Err(domain_error(
            &context,
            ApiErrorCode::PermissionDenied,
            "email_verification_required",
            "Verify your email before accepting an invitation.",
        ));
    }
    let database = database(&state, &context)?;
    let repository = OrganizationRepository::new(database);
    let invitation = repository
        .find_invitation(&invitation_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| {
            domain_error(
                &context,
                ApiErrorCode::NotFound,
                "invitation_invalid",
                "The invitation was not found.",
            )
        })?;
    if invitation.status == "accepted" {
        if invitation.accepted_by_user_id.as_deref()
            != Some(authenticated.principal.user_id.as_str())
        {
            return Err(domain_error(
                &context,
                ApiErrorCode::PermissionDenied,
                "invitation_replayed",
                "The invitation is no longer available.",
            ));
        }
        let organization = repository
            .find_organization(&invitation.org_id)
            .await
            .map_err(|error| database_error(&context, error))?
            .ok_or_else(|| service_unavailable(&context))?;
        let membership = repository
            .find_membership(&invitation.org_id, authenticated.principal.user_id.as_str())
            .await
            .map_err(|error| database_error(&context, error))?
            .ok_or_else(|| service_unavailable(&context))?;
        return Ok(
            Json(json!({ "organization": organization, "membership": membership })).into_response(),
        );
    }
    if invitation.status == "expired"
        || invitation.status == "revoked"
        || invitation.expires_at.as_str() <= context.received_at.as_str()
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::PermissionDenied,
            &format!("invitation_{}", invitation.status),
            "The invitation is no longer available.",
        ));
    }
    if invitation.status != "pending" {
        return Err(domain_error(
            &context,
            ApiErrorCode::PermissionDenied,
            "invitation_replayed",
            "The invitation is no longer available.",
        ));
    }
    if invitation.email != authenticated.principal.email {
        return Err(domain_error(
            &context,
            ApiErrorCode::PermissionDenied,
            "invitation_email_mismatch",
            "This invitation belongs to a different email address.",
        ));
    }
    let token_hash = sha256_hex(&body.token)
        .await
        .map_err(|_| service_unavailable(&context))?;
    let membership_id = generated_id("mem");
    let accept_statement = repository
        .accept_invitation_statement(
            &invitation_id,
            authenticated.principal.user_id.as_str(),
            &token_hash,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let membership_statement = repository
        .insert_invited_membership_statement(
            &membership_id,
            &invitation.org_id,
            authenticated.principal.user_id.as_str(),
            &invitation.role,
            &invitation.invited_by_user_id,
            &invitation_id,
            &token_hash,
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let results = database
        .batch(vec![accept_statement, membership_statement])
        .await
        .map_err(|error| database_error(&context, error))?;
    if crate::adapters::d1::D1Adapter::changes(&results[0]).unwrap_or_default() != 1
        || crate::adapters::d1::D1Adapter::changes(&results[1]).unwrap_or_default() != 1
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "invitation_replayed",
            "The invitation is no longer available.",
        ));
    }
    let event_id = generated_id("sec");
    let security_statement = security_statement(
        database,
        &context,
        &authenticated.principal,
        &event_id,
        Some(&invitation.org_id),
        "membership.accepted.v1",
        "membership",
        Some(&membership_id),
        json!({ "role": invitation.role }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&authenticated.principal),
        Some(&invitation.org_id),
        "membership.accepted.v1",
        &json!({ "role": invitation.role }),
    )?;
    database
        .batch(vec![security_statement, outbox])
        .await
        .map_err(|error| database_error(&context, error))?;
    let organization = repository
        .find_organization(&invitation.org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| service_unavailable(&context))?;
    let membership = repository
        .find_membership(&invitation.org_id, authenticated.principal.user_id.as_str())
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| service_unavailable(&context))?;
    Ok(Json(json!({ "organization": organization, "membership": membership })).into_response())
}

#[worker::send]
pub async fn change_role(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, member_id)): Path<(String, String)>,
    Json(body): Json<RoleRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::MembersManage,
        Some("membership"),
        Some(&member_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let role = crate::modules::authorization::MembershipRole::parse(&body.role)
        .ok_or_else(|| validation_error(&context, "role_invalid", "Choose a valid role."))?;
    let database = database(&state, &context)?;
    let repository = OrganizationRepository::new(database);
    let target = repository
        .find_membership_by_id(&org_id, &member_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| {
            domain_error(
                &context,
                ApiErrorCode::NotFound,
                "resource_not_found",
                "The member was not found.",
            )
        })?;
    let actor_role = crate::modules::authorization::MembershipRole::parse(&access.membership.role)
        .ok_or_else(|| service_unavailable(&context))?;
    if !crate::modules::memberships::can_change_role(
        actor_role,
        crate::modules::authorization::MembershipRole::parse(&target.role)
            .unwrap_or(crate::modules::authorization::MembershipRole::Viewer),
        crate::modules::authorization::MembershipStatus::parse(&target.status)
            .unwrap_or(crate::modules::authorization::MembershipStatus::Removed),
    ) {
        return Err(domain_error(
            &context,
            ApiErrorCode::PermissionDenied,
            "permission_denied",
            "You do not have permission to change this role.",
        ));
    }
    if !repository
        .change_role(
            &member_id,
            &org_id,
            role.as_str(),
            body.version,
            &context.received_at,
        )
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "last_owner_required",
            "The last active owner cannot be demoted.",
        ));
    }
    let event_id = generated_id("sec");
    let security_statement = security_statement(
        database,
        &context,
        &access.principal,
        &event_id,
        Some(&org_id),
        "membership.role_changed.v1",
        "membership",
        Some(&member_id),
        json!({ "role": role.as_str() }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "membership.role_changed.v1",
        &json!({ "role": role.as_str() }),
    )?;
    database
        .batch(vec![security_statement, outbox])
        .await
        .map_err(|error| database_error(&context, error))?;
    let updated = repository
        .find_membership_by_id(&org_id, &member_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| service_unavailable(&context))?;
    Ok(Json(updated).into_response())
}

#[worker::send]
pub async fn leave(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(_body): Json<EmptyRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::OrgLeave,
        Some("membership"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let database = database(&state, &context)?;
    let repository = OrganizationRepository::new(database);
    let role = crate::modules::authorization::MembershipRole::parse(&access.membership.role)
        .ok_or_else(|| service_unavailable(&context))?;
    let owner_count = repository
        .active_owner_count(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?;
    if !crate::modules::memberships::can_leave(role, owner_count) {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "last_owner_required",
            "Transfer ownership before leaving this organization.",
        ));
    }
    if !repository
        .remove_member(
            &access.membership.membership_id,
            &org_id,
            access.membership.version,
            &context.received_at,
        )
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "last_owner_required",
            "Transfer ownership before leaving this organization.",
        ));
    }
    IdentityRepository::new(database)
        .revoke_user_sessions_statement(access.principal.user_id.as_str(), &context.received_at)
        .map_err(|error| database_error(&context, error))?
        .run()
        .await
        .map_err(|error| database_error(&context, error))?;
    let event_id = generated_id("sec");
    let security_statement = security_statement(
        database,
        &context,
        &access.principal,
        &event_id,
        Some(&org_id),
        "membership.left.v1",
        "membership",
        Some(&access.membership.membership_id),
        json!({}),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "membership.left.v1",
        &json!({}),
    )?;
    database
        .batch(vec![security_statement, outbox])
        .await
        .map_err(|error| database_error(&context, error))?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    clear_session_cookies(&mut response, secure_cookie(&state));
    Ok(response)
}

#[worker::send]
pub async fn remove_member(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::MembersManage,
        Some("membership"),
        Some(&member_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let database = database(&state, &context)?;
    let repository = OrganizationRepository::new(database);
    let target = repository
        .find_membership_by_id(&org_id, &member_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| {
            domain_error(
                &context,
                ApiErrorCode::NotFound,
                "resource_not_found",
                "The member was not found.",
            )
        })?;
    let actor_role = crate::modules::authorization::MembershipRole::parse(&access.membership.role)
        .ok_or_else(|| service_unavailable(&context))?;
    let target_role = crate::modules::authorization::MembershipRole::parse(&target.role)
        .ok_or_else(|| service_unavailable(&context))?;
    if !crate::modules::memberships::can_remove_member(actor_role, target_role) {
        return Err(domain_error(
            &context,
            ApiErrorCode::PermissionDenied,
            "permission_denied",
            "You do not have permission to remove this member.",
        ));
    }
    if !repository
        .remove_member(&member_id, &org_id, target.version, &context.received_at)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "last_owner_required",
            "The last active owner cannot be removed.",
        ));
    }
    IdentityRepository::new(database)
        .revoke_user_sessions_statement(&target.user_id, &context.received_at)
        .map_err(|error| database_error(&context, error))?
        .run()
        .await
        .map_err(|error| database_error(&context, error))?;
    let event_id = generated_id("sec");
    let security_statement = security_statement(
        database,
        &context,
        &access.principal,
        &event_id,
        Some(&org_id),
        "membership.removed.v1",
        "membership",
        Some(&member_id),
        json!({}),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "membership.removed.v1",
        &json!({}),
    )?;
    database
        .batch(vec![security_statement, outbox])
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[worker::send]
pub async fn suspend(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<LifecycleRequest>,
) -> Result<Response<Body>, ApiError> {
    transition_lifecycle(
        state,
        context,
        headers,
        org_id,
        body,
        "active",
        "suspended",
        "organization.suspended.v1",
    )
    .await
}

#[worker::send]
pub async fn resume(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<LifecycleRequest>,
) -> Result<Response<Body>, ApiError> {
    transition_lifecycle(
        state,
        context,
        headers,
        org_id,
        body,
        "suspended",
        "active",
        "organization.resumed.v1",
    )
    .await
}

#[worker::send]
pub async fn begin_deletion(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<LifecycleRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::OrgLifecycle,
        Some("organization"),
        Some(&org_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let expected_confirmation = format!("DELETE {}", access.organization.slug);
    if body.confirmation.as_deref() != Some(expected_confirmation.as_str()) {
        return Err(validation_error(
            &context,
            "confirmation_required",
            "Type DELETE plus the organization slug to continue.",
        ));
    }
    transition_lifecycle_with_access(
        state,
        context,
        headers,
        org_id,
        body,
        access,
        "active",
        "pending_deletion",
        "organization.deletion_started.v1",
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn transition_lifecycle(
    state: Arc<AppState>,
    context: RequestContext,
    headers: HeaderMap,
    org_id: String,
    body: LifecycleRequest,
    expected_state: &'static str,
    next_state: &'static str,
    action: &'static str,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::OrgLifecycle,
        Some("organization"),
        Some(&org_id),
    )
    .await?;
    transition_lifecycle_with_access(
        state,
        context,
        headers,
        org_id,
        body,
        access,
        expected_state,
        next_state,
        action,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn transition_lifecycle_with_access(
    state: Arc<AppState>,
    context: RequestContext,
    headers: HeaderMap,
    org_id: String,
    body: LifecycleRequest,
    access: crate::routes::authorization::OrgAccess,
    expected_state: &'static str,
    next_state: &'static str,
    action: &'static str,
) -> Result<Response<Body>, ApiError> {
    require_csrf(&headers, &access.session, &context).await?;
    let database = database(&state, &context)?;
    let repository = IdentityRepository::new(database);
    let token_hash = sha256_hex(&body.reauth_token)
        .await
        .map_err(|_| service_unavailable(&context))?;
    if !repository
        .consume_reauth(
            &body.reauth_grant_id,
            access.principal.user_id.as_str(),
            access.principal.session_id.as_str(),
            "org_lifecycle",
            &token_hash,
            &context.received_at,
        )
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::PermissionDenied,
            "reauthentication_required",
            "Complete a recent security check before changing organization lifecycle.",
        ));
    }
    let organizations = OrganizationRepository::new(database);
    // P06-CR-003: the lifecycle move and the P06 `DeletionJob` link commit in
    // the SAME batch. Executing the state change first would let an
    // organization become `pending_deletion` with no job to do the work — a
    // stall no retry can clear, because the lifecycle row is already past the
    // transition. The job's UNIQUE lifecycle key makes a repeated request
    // converge on the same job rather than forking a second one.
    let mut statements = vec![
        organizations
            .update_state_statement(
                &org_id,
                expected_state,
                next_state,
                body.version,
                &context.received_at,
            )
            .map_err(|error| database_error(&context, error))?,
    ];
    if next_state == "pending_deletion" {
        let deletion_id = generated_id("del");
        statements.push(
            crate::repositories::DataGovernanceRepository::new(database)
                .link_organization_deletion_job_statement(
                    &crate::repositories::DeletionJobLinkInput {
                        deletion_id: deletion_id.as_str(),
                        org_id: &org_id,
                        lifecycle_request_id: context.request_id.as_str(),
                        cutoff_at: context.received_at.as_str(),
                        legal_hold: false,
                        requested_by_principal_id: access.principal.user_id.as_str(),
                        now: &context.received_at,
                    },
                )
                .map_err(|error| database_error(&context, error))?,
        );
    }
    let event_id = generated_id("sec");
    let security_statement = security_statement(
        database,
        &context,
        &access.principal,
        &event_id,
        Some(&org_id),
        action,
        "organization",
        Some(&org_id),
        json!({ "state": next_state }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        action,
        &json!({ "state": next_state }),
    )?;
    statements.push(security_statement);
    statements.push(outbox);
    let results = database
        .batch(statements)
        .await
        .map_err(|error| database_error(&context, error))?;
    // A zero-row first statement is the optimistic version guard losing the
    // race, not a store outage, so it maps to `version_conflict` rather than a
    // 503. The batch rolled back, so no job was linked either.
    if crate::adapters::d1::D1Adapter::changes(&results[0]).unwrap_or(1) != 1 {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "version_conflict",
            "The organization lifecycle changed. Refresh and try again.",
        ));
    }
    let organization = organizations
        .find_organization(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| service_unavailable(&context))?;
    Ok(Json(organization).into_response())
}

#[worker::send]
pub async fn transfer_ownership(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<TransferOwnershipRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::OrgOwnershipTransfer,
        Some("membership"),
        Some(&body.target_membership_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let database = database(&state, &context)?;
    let identity = IdentityRepository::new(database);
    let reauth_hash = sha256_hex(&body.reauth_token)
        .await
        .map_err(|_| service_unavailable(&context))?;
    if !identity
        .consume_reauth(
            &body.reauth_grant_id,
            access.principal.user_id.as_str(),
            access.principal.session_id.as_str(),
            "ownership_transfer",
            &reauth_hash,
            &context.received_at,
        )
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::PermissionDenied,
            "reauthentication_required",
            "Complete a recent security check before transferring ownership.",
        ));
    }
    let repository = OrganizationRepository::new(database);
    let target = repository
        .find_membership_by_id(&org_id, &body.target_membership_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| {
            domain_error(
                &context,
                ApiErrorCode::NotFound,
                "resource_not_found",
                "The target member was not found.",
            )
        })?;
    if target.status != "active" {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "membership_required",
            "Ownership can only be transferred to an active member.",
        ));
    }
    if !repository
        .transfer_ownership(&body.target_membership_id, &org_id, &context.received_at)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::Conflict,
            "last_owner_required",
            "Ownership could not be transferred.",
        ));
    }
    let event_id = generated_id("sec");
    let security_statement = security_statement(
        database,
        &context,
        &access.principal,
        &event_id,
        Some(&org_id),
        "organization.ownership_transferred.v1",
        "membership",
        Some(&body.target_membership_id),
        json!({}),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "organization.ownership_transferred.v1",
        &json!({}),
    )?;
    database
        .batch(vec![security_statement, outbox])
        .await
        .map_err(|error| database_error(&context, error))?;
    let organization = repository
        .find_organization(&org_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| service_unavailable(&context))?;
    let membership = repository
        .find_membership_by_id(&org_id, &body.target_membership_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| service_unavailable(&context))?;
    Ok(Json(json!({ "organization": organization, "membership": membership })).into_response())
}

#[worker::send]
pub async fn list_teams(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Response<Body>, ApiError> {
    reject_cursor(&context, query.cursor.as_deref())?;
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::TeamsRead,
        Some("team"),
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let teams = OrganizationRepository::new(database)
        .list_teams(&org_id, page_limit(query.limit), 0)
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(Json(PageResponse {
        items: teams,
        next_cursor: None,
        has_more: false,
    })
    .into_response())
}

#[worker::send]
pub async fn create_team(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<CreateTeamRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::TeamsManage,
        Some("team"),
        None,
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let display_name = validate_team_name(&body.display_name)
        .map_err(|_| validation_error(&context, "team_name_invalid", "Enter a valid team name."))?;
    let slug = normalize_team_slug(&body.slug).map_err(|_| {
        validation_error(&context, "team_slug_invalid", "Choose a valid team slug.")
    })?;
    let database = database(&state, &context)?;
    let repository = OrganizationRepository::new(database);
    let team_id = generated_id("team");
    let statement = repository
        .insert_team_statement(
            &team_id,
            &org_id,
            &display_name,
            &slug,
            access.principal.user_id.as_str(),
            &context.received_at,
        )
        .map_err(|error| database_error(&context, error))?;
    let event_id = generated_id("sec");
    let security_statement = security_statement(
        database,
        &context,
        &access.principal,
        &event_id,
        Some(&org_id),
        "team.created.v1",
        "team",
        Some(&team_id),
        json!({}),
    )?;
    database
        .batch(vec![statement, security_statement])
        .await
        .map_err(|error| database_error(&context, error))?;
    let team = repository
        .find_team(&org_id, &team_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .ok_or_else(|| service_unavailable(&context))?;
    Ok((StatusCode::CREATED, Json(team)).into_response())
}

#[worker::send]
pub async fn add_team_member(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, team_id)): Path<(String, String)>,
    Json(body): Json<AddTeamMemberRequest>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::TeamsManage,
        Some("team"),
        Some(&team_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let database = database(&state, &context)?;
    let repository = OrganizationRepository::new(database);
    if repository
        .find_team(&org_id, &team_id)
        .await
        .map_err(|error| database_error(&context, error))?
        .is_none()
        || repository
            .find_membership_by_id(&org_id, &body.membership_id)
            .await
            .map_err(|error| database_error(&context, error))?
            .is_none()
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::NotFound,
            "resource_not_found",
            "The team or member was not found.",
        ));
    }
    let team_member_id = generated_id("tmem");
    repository
        .add_team_member(
            &team_member_id,
            &org_id,
            &team_id,
            &body.membership_id,
            &context.received_at,
        )
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok((StatusCode::CREATED, Json(json!({ "team_member_id": team_member_id, "team_id": team_id, "membership_id": body.membership_id }))).into_response())
}

#[worker::send]
pub async fn remove_team_member(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((org_id, team_id, member_id)): Path<(String, String, String)>,
) -> Result<Response<Body>, ApiError> {
    let access = authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::TeamsManage,
        Some("team_member"),
        Some(&member_id),
    )
    .await?;
    require_csrf(&headers, &access.session, &context).await?;
    let database = database(&state, &context)?;
    if !OrganizationRepository::new(database)
        .remove_team_member(&org_id, &team_id, &member_id)
        .await
        .map_err(|error| database_error(&context, error))?
    {
        return Err(domain_error(
            &context,
            ApiErrorCode::NotFound,
            "resource_not_found",
            "The team member was not found.",
        ));
    }
    let event_id = generated_id("sec");
    let security_statement = security_statement(
        database,
        &context,
        &access.principal,
        &event_id,
        Some(&org_id),
        "team.member_removed.v1",
        "team_member",
        Some(&member_id),
        json!({ "team_id": team_id }),
    )?;
    let outbox = outbox_statement(
        database,
        &context,
        Some(&access.principal),
        Some(&org_id),
        "team.member_removed.v1",
        &json!({ "team_id": team_id }),
    )?;
    database
        .batch(vec![security_statement, outbox])
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[worker::send]
pub async fn audit(
    State(state): State<Arc<AppState>>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Response<Body>, ApiError> {
    reject_cursor(&context, query.cursor.as_deref())?;
    authorize_org(
        &state,
        &headers,
        &context,
        &org_id,
        Permission::AuditRead,
        Some("audit"),
        None,
    )
    .await?;
    let database = database(&state, &context)?;
    let events = SecurityEventRepository::new(database)
        .list(Some(&org_id), None, page_limit(query.limit), 0)
        .await
        .map_err(|error| database_error(&context, error))?;
    Ok(Json(PageResponse {
        items: events,
        next_cursor: None,
        has_more: false,
    })
    .into_response())
}

#[allow(clippy::too_many_arguments)]
fn security_statement<'a>(
    database: &'a crate::adapters::d1::D1Adapter,
    context: &RequestContext,
    principal: &Principal,
    event_id: &'a str,
    organization_id: Option<&'a str>,
    action: &'a str,
    resource_type: &'a str,
    resource_id: Option<&'a str>,
    metadata: Value,
) -> Result<worker::d1::D1PreparedStatement, ApiError> {
    let input = SecurityEventInput {
        event_id,
        organization_id,
        actor_type: "user",
        actor_id: Some(principal.user_id.as_str()),
        effective_user_id: Some(principal.user_id.as_str()),
        session_id: Some(principal.session_id.as_str()),
        device_id: None,
        action,
        resource_type,
        resource_id,
        outcome: "success",
        reason: None,
        metadata: &metadata,
        request_id: context.request_id.as_str(),
        correlation_id: context.correlation_id.as_str(),
        created_at: &context.received_at,
    };
    SecurityEventRepository::new(database)
        .insert_statement(&input)
        .map_err(|_| service_unavailable(context))
}

fn generated_id(prefix: &str) -> String {
    new_resource_id(prefix).as_str().to_owned()
}

fn default_slug(name: &str, suffix: &str) -> String {
    let base = name
        .to_ascii_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    let base = base.trim_matches('-').to_owned();
    let candidate = if base.is_empty() {
        format!("org-{suffix}")
    } else {
        format!("{base}-{suffix}")
    };
    normalize_slug(&candidate).unwrap_or_else(|_| format!("org-{suffix}"))
}

fn page_limit(limit: Option<u16>) -> u16 {
    limit.unwrap_or(50).clamp(1, 100)
}

fn reject_cursor(context: &RequestContext, cursor: Option<&str>) -> Result<(), ApiError> {
    if cursor.is_some_and(|value| !value.is_empty()) {
        return Err(domain_error(
            context,
            ApiErrorCode::BadRequest,
            "invalid_cursor",
            "The pagination cursor is invalid.",
        ));
    }
    Ok(())
}

fn redact_invitation(invitation: crate::repositories::InvitationRecord) -> Value {
    json!({
        "id": invitation.invitation_id,
        "org_id": invitation.org_id,
        "email": invitation.email,
        "role": invitation.role,
        "status": invitation.status,
        "expires_at": invitation.expires_at,
        "created_at": invitation.created_at,
    })
}

fn validation_error(context: &RequestContext, reason: &str, message: &str) -> ApiError {
    domain_error(context, ApiErrorCode::ValidationFailed, reason, message)
}

fn service_unavailable(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::ServiceUnavailable,
        "The identity store is unavailable.",
    )
}
