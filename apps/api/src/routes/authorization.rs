use std::sync::Arc;

use axum::http::HeaderMap;
use serde_json::json;

use crate::{
    app::AppState,
    core::{ApiError, ApiErrorCode, Principal, RequestContext},
    http::auth::require_session,
    modules::authorization::{
        AuthorizationDecision, DenyReason, MembershipRole, MembershipSnapshot, MembershipStatus,
        OrganizationContext, OrganizationState, Permission, ResourceContext, authorize,
    },
    repositories::{MembershipRecord, OrganizationRecord, OrganizationRepository, SessionRecord},
    routes::{errors, support::database},
};

pub struct DeviceAccess {
    pub device: crate::repositories::DeviceRecord,
    #[allow(dead_code)]
    pub organization: OrganizationRecord,
    #[allow(dead_code)]
    pub membership: MembershipRecord,
}

/// Resolve a device-token request to one active organization and the current
/// membership of the user who enrolled the device. Device identity is never
/// accepted from a body or path; the token lookup supplies its scope.
pub(crate) async fn authorize_device(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    context: &RequestContext,
) -> Result<DeviceAccess, ApiError> {
    let device = crate::routes::devices::require_device(state, headers, context).await?;
    let database = database(state, context)?;
    let repository = OrganizationRepository::new(database);
    let organization = repository
        .find_organization(&device.org_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .ok_or_else(|| inaccessible(context))?;
    let membership = repository
        .find_membership(&device.org_id, &device.enrolled_by_user_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .ok_or_else(|| {
            errors::api_error(
                context,
                ApiErrorCode::PermissionDenied,
                "The device is no longer approved for this organization.",
            )
            .with_detail("reason", json!("device_not_approved"))
        })?;
    if membership.status != "active" {
        return Err(errors::api_error(
            context,
            ApiErrorCode::PermissionDenied,
            "The device is no longer approved for this organization.",
        )
        .with_detail("reason", json!("device_not_approved")));
    }
    if organization.state != "active" {
        return Err(errors::api_error(
            context,
            ApiErrorCode::PermissionDenied,
            "The organization is not active.",
        )
        .with_detail("reason", json!("organization_not_active")));
    }
    Ok(DeviceAccess {
        device,
        organization,
        membership,
    })
}

pub struct OrgAccess {
    pub principal: Principal,
    pub organization: OrganizationRecord,
    pub membership: MembershipRecord,
    pub session: SessionRecord,
}

/// The only route-level bridge to the central policy service. It resolves the
/// current session and current membership, then makes one decision.
pub async fn authorize_org(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    context: &RequestContext,
    org_id: &str,
    permission: Permission,
    resource_type: Option<&str>,
    resource_id: Option<&str>,
) -> Result<OrgAccess, ApiError> {
    if let Some(header_org) = headers
        .get("x-org-id")
        .and_then(|value| value.to_str().ok())
        && header_org != org_id
    {
        return Err(errors::api_error(
            context,
            ApiErrorCode::PermissionDenied,
            "The organization context does not match the requested resource.",
        )
        .with_detail("reason", json!("org_context_mismatch")));
    }
    let authenticated = require_session(state, headers, context).await?;
    let database = database(state, context)?;
    let repository = OrganizationRepository::new(database);
    let organization = repository
        .find_organization(org_id)
        .await
        .map_err(|_| service_unavailable(context))?
        .ok_or_else(|| inaccessible(context))?;
    let membership = repository
        .find_membership(org_id, authenticated.principal.user_id.as_str())
        .await
        .map_err(|_| service_unavailable(context))?
        .ok_or_else(|| inaccessible(context))?;
    let state_value = OrganizationState::parse(&organization.state)
        .ok_or_else(|| service_unavailable(context))?;
    let role =
        MembershipRole::parse(&membership.role).ok_or_else(|| service_unavailable(context))?;
    let status =
        MembershipStatus::parse(&membership.status).ok_or_else(|| service_unavailable(context))?;
    let organization_context = OrganizationContext {
        organization_id: crate::core::OrganizationId::new(org_id)
            .map_err(|_| inaccessible(context))?,
        state: state_value,
        version: organization.version,
    };
    let membership_snapshot = MembershipSnapshot {
        membership_id: crate::core::MembershipId::new(&membership.membership_id)
            .map_err(|_| service_unavailable(context))?,
        organization_id: organization_context.organization_id.clone(),
        user_id: authenticated.principal.user_id.clone(),
        role,
        status,
        version: membership.version,
    };
    let resource = resource_type.map(|resource_type| ResourceContext {
        resource_type: resource_type.to_owned(),
        resource_id: resource_id.unwrap_or_default().to_owned(),
        organization_id: organization_context.organization_id.clone(),
    });
    let decision = authorize(
        Some(&authenticated.principal),
        &organization_context,
        Some(&membership_snapshot),
        &permission,
        resource.as_ref(),
    );
    if let AuthorizationDecision::Deny(reason) = decision {
        return Err(denial(context, reason));
    }
    Ok(OrgAccess {
        principal: authenticated.principal,
        organization,
        membership,
        session: authenticated.session,
    })
}

pub fn denial(context: &RequestContext, reason: DenyReason) -> ApiError {
    let code = match reason {
        DenyReason::AuthenticationRequired => ApiErrorCode::AuthenticationRequired,
        DenyReason::EmailVerificationRequired
        | DenyReason::MembershipRequired
        | DenyReason::PermissionDenied
        | DenyReason::OrganizationSuspended
        | DenyReason::OrganizationPendingDeletion
        | DenyReason::ResourceScopeMismatch
        | DenyReason::StaleMembership
        | DenyReason::UnknownPermission
        | DenyReason::VersionConflict => ApiErrorCode::PermissionDenied,
        DenyReason::OrganizationDeleted => ApiErrorCode::NotFound,
    };
    let message = match reason {
        DenyReason::AuthenticationRequired => "Authentication is required.",
        DenyReason::EmailVerificationRequired => "Verify your email before continuing.",
        DenyReason::MembershipRequired => "An active organization membership is required.",
        DenyReason::PermissionDenied => "You do not have permission to perform this action.",
        DenyReason::OrganizationSuspended => "This organization is suspended.",
        DenyReason::OrganizationPendingDeletion => "This organization is pending deletion.",
        DenyReason::OrganizationDeleted => "The requested organization was not found.",
        DenyReason::ResourceScopeMismatch => {
            "The requested resource is outside the organization scope."
        }
        DenyReason::StaleMembership => {
            "The organization membership changed. Refresh and try again."
        }
        DenyReason::UnknownPermission | DenyReason::VersionConflict => {
            "The request is not permitted."
        }
    };
    errors::api_error(context, code, message).with_detail("reason", json!(reason.as_str()))
}

fn inaccessible(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::NotFound,
        "The requested resource was not found.",
    )
    .with_detail("reason", json!("resource_not_found"))
}

fn service_unavailable(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::ServiceUnavailable,
        "The identity store is unavailable.",
    )
}
