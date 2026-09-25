use std::sync::Arc;

use axum::{
    Router, middleware,
    routing::{delete, get, patch, post, put},
};
use worker::{Env, Queue, SendEmail};

use crate::adapters::crypto::DEVELOPMENT_CREDENTIAL_KEY_HEX;
use crate::adapters::webauthn::{WebAuthnAdapter, WebAuthnConfig};

use crate::{
    adapters::d1::D1Adapter,
    http::{json_body_limit, request_boundary},
    routes::{
        account, agents, ai_catalog, approvals, audit, auth, authenticators, automations, billing,
        budgets, data_governance, device_auth, device_runs, devices, foundation_checks,
        health::health, inference, meta::meta, organizations, projects, runs, tools, usage,
        webhooks,
    },
};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) database: Option<Arc<D1Adapter>>,
    pub(crate) queue: Option<Queue>,
    pub(crate) environment: String,
    pub(crate) email: Option<SendEmail>,
    pub(crate) email_from: Option<String>,
    pub(crate) credential_key: Option<String>,
    /// P06 license signing key, in `key_id:base64_pkcs8_der` form. A Wrangler
    /// SECRET, never a var and never request input. Absent means no signed
    /// license snapshot can be issued, which is reported as a stable reason
    /// rather than as a permissive unsigned claim.
    pub(crate) license_signing_secret: Option<String>,
    pub(crate) provider_allowlist: Vec<String>,
    pub(crate) allow_local_provider_endpoints: bool,
    pub(crate) webauthn: Option<WebAuthnAdapter>,
}

/// Construct the HTTP router for one Worker request. Public liveness/meta
/// routes remain available when a storage binding is unavailable; internal
/// foundation probes exist only in Wrangler's explicit development env.
pub fn router(env: Env) -> Router {
    let is_development = env
        .var("ENVIRONMENT")
        .map(|value| value.to_string() == "development")
        .unwrap_or(false);
    let environment = env
        .var("ENVIRONMENT")
        .map(|value| value.to_string())
        .unwrap_or_else(|_| "production".to_owned());
    let credential_key = if environment == "development" {
        Some(DEVELOPMENT_CREDENTIAL_KEY_HEX.to_owned())
    } else {
        env.var("CREDENTIAL_ENCRYPTION_KEY")
            .ok()
            .map(|value| value.to_string())
            .filter(|value| !value.is_empty())
    };
    let provider_allowlist = env
        .var("LUMI_PROVIDER_ALLOWLIST")
        .ok()
        .map(|value| {
            value
                .to_string()
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_ascii_lowercase)
                .collect()
        })
        .unwrap_or_default();
    let allow_local_provider_endpoints = environment == "development";
    let webauthn = if environment == "development" {
        WebAuthnConfig::new(
            Some(
                env.var("WEBAUTHN_RP_ID")
                    .ok()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "localhost".to_owned()),
            ),
            Some(
                env.var("WEBAUTHN_RP_NAME")
                    .ok()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "Lumi Agents".to_owned()),
            ),
            Some(
                env.var("WEBAUTHN_ORIGINS")
                    .ok()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "http://localhost:5173".to_owned()),
            ),
        )
        .ok()
        .map(WebAuthnAdapter::new)
    } else {
        WebAuthnConfig::new(
            env.var("WEBAUTHN_RP_ID")
                .ok()
                .map(|value| value.to_string()),
            env.var("WEBAUTHN_RP_NAME")
                .ok()
                .map(|value| value.to_string()),
            env.var("WEBAUTHN_ORIGINS")
                .ok()
                .map(|value| value.to_string()),
        )
        .ok()
        .map(WebAuthnAdapter::new)
    };
    let state = Arc::new(AppState {
        database: env.d1("DB").ok().map(D1Adapter::new).map(Arc::new),
        queue: env.queue("OUTBOX_QUEUE").ok(),
        environment,
        email: env.send_email("EMAIL").ok(),
        email_from: env.var("EMAIL_FROM").ok().map(|value| value.to_string()),
        credential_key,
        // A Wrangler secret, read once at Worker construction. It is never
        // logged and never echoed into a response; only the derived signature
        // and its key id leave this module.
        license_signing_secret: env
            .var("LICENSE_SIGNING_SECRET")
            .ok()
            .map(|v| v.to_string()),
        provider_allowlist,
        allow_local_provider_endpoints,
        webauthn,
    });

    let mut routes = Router::<Arc<AppState>>::new()
        .route("/api/health", get(health))
        .route("/api/v1/meta", get(meta))
        .route("/api/v1/auth/signup", post(auth::signup))
        .route("/api/v1/auth/verify-email", post(auth::verify_email))
        .route("/api/v1/auth/login/start", post(auth::login_start))
        .route("/api/v1/auth/login/complete", post(auth::login_complete))
        .route(
            "/api/v1/auth/passkey/signup/start",
            post(authenticators::passkey_signup_start),
        )
        .route(
            "/api/v1/auth/passkey/signup/complete",
            post(authenticators::passkey_signup_complete),
        )
        .route(
            "/api/v1/auth/passkey/login/start",
            post(authenticators::passkey_login_start),
        )
        .route(
            "/api/v1/auth/passkey/login/complete",
            post(authenticators::passkey_login_complete),
        )
        .route(
            "/api/v1/auth/password/signup",
            post(authenticators::password_signup),
        )
        .route(
            "/api/v1/auth/password/login",
            post(authenticators::password_login),
        )
        .route(
            "/api/v1/auth/password/forgot",
            post(authenticators::password_forgot),
        )
        .route(
            "/api/v1/auth/password/reset",
            post(authenticators::password_reset),
        )
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/auth/refresh", post(auth::refresh))
        .route("/api/v1/auth/device-code", post(device_auth::start))
        .route(
            "/api/v1/auth/device-code/approve",
            post(device_auth::approve),
        )
        .route(
            "/api/v1/auth/device-code/exchange",
            post(device_auth::exchange),
        )
        .route("/api/v1/me", get(auth::me))
        .route(
            "/api/v1/me/identities/link/start",
            post(auth::link_identity_start),
        )
        .route("/api/v1/me/identities/link", post(auth::link_identity))
        .route(
            "/api/v1/orgs",
            post(organizations::create).get(organizations::list),
        )
        .route(
            "/api/v1/orgs/{org_id}",
            get(organizations::get).patch(organizations::update),
        )
        .route(
            "/api/v1/orgs/{org_id}/members",
            get(organizations::list_members),
        )
        .route(
            "/api/v1/orgs/{org_id}/invitations",
            get(organizations::list_invitations).post(organizations::invite),
        )
        .route(
            "/api/v1/orgs/{org_id}/invitations/{invitation_id}",
            delete(organizations::revoke_invitation),
        )
        .route(
            "/api/v1/orgs/{org_id}/invitations/{invitation_id}/resend",
            post(organizations::resend_invitation),
        )
        .route(
            "/api/v1/invitations/{invitation_id}/accept",
            post(organizations::accept_invitation),
        )
        .route(
            "/api/v1/orgs/{org_id}/members/{member_id}",
            patch(organizations::change_role).delete(organizations::remove_member),
        )
        .route(
            "/api/v1/orgs/{org_id}/ownership-transfer",
            post(organizations::transfer_ownership),
        )
        .route("/api/v1/orgs/{org_id}/leave", post(organizations::leave))
        .route(
            "/api/v1/orgs/{org_id}/suspend",
            post(organizations::suspend),
        )
        .route("/api/v1/orgs/{org_id}/resume", post(organizations::resume))
        .route(
            "/api/v1/orgs/{org_id}/deletion",
            post(organizations::begin_deletion),
        )
        .route(
            "/api/v1/orgs/{org_id}/teams",
            get(organizations::list_teams).post(organizations::create_team),
        )
        .route(
            "/api/v1/orgs/{org_id}/teams/{team_id}/members",
            post(organizations::add_team_member),
        )
        .route(
            "/api/v1/orgs/{org_id}/teams/{team_id}/members/{member_id}",
            delete(organizations::remove_team_member),
        )
        .route("/api/v1/orgs/{org_id}/audit", get(audit::audit))
        .route(
            "/api/v1/orgs/{org_id}/policy",
            get(projects::org_policy).put(ai_catalog::update_policy),
        )
        .route("/api/v1/orgs/{org_id}/devices", get(devices::list_devices))
        .route(
            "/api/v1/orgs/{org_id}/devices/{device_id}",
            get(devices::get_device).delete(devices::revoke_device),
        )
        .route(
            "/api/v1/orgs/{org_id}/devices/enrollments/{enrollment_id}/approve",
            post(devices::approve_enrollment),
        )
        .route(
            "/api/v1/devices/enrollments",
            post(devices::begin_enrollment),
        )
        .route(
            "/api/v1/devices/enrollments/{enrollment_id}",
            get(devices::enrollment_status),
        )
        .route(
            "/api/v1/devices/enrollments/{enrollment_id}/complete",
            post(devices::complete_enrollment),
        )
        .route("/api/v1/devices/token/nonce", get(devices::token_nonce))
        .route("/api/v1/devices/token", post(devices::refresh_token))
        .route("/api/v1/devices/heartbeat", post(devices::heartbeat))
        .route("/api/v1/devices/policy", get(devices::fetch_policy))
        .route("/api/v1/devices/policy/ack", post(devices::ack_policy))
        .route(
            "/api/v1/devices/bindings",
            get(devices::list_device_bindings).post(devices::create_binding),
        )
        .route(
            "/api/v1/devices/bindings/{binding_id}",
            delete(devices::delete_device_binding),
        )
        .route(
            "/api/v1/devices/sessions",
            post(device_runs::create_session),
        )
        .route(
            "/api/v1/devices/sessions/{agent_session_id}/runs",
            post(device_runs::create_run),
        )
        .route("/api/v1/devices/runs/{run_id}", get(device_runs::get_run))
        .route(
            "/api/v1/devices/runs/{run_id}/events",
            get(device_runs::list_events),
        )
        .route(
            "/api/v1/devices/runs/{run_id}/start",
            post(device_runs::start_run),
        )
        .route(
            "/api/v1/devices/runs/{run_id}/complete",
            post(device_runs::complete_run),
        )
        .route(
            "/api/v1/devices/runs/{run_id}/fail",
            post(device_runs::fail_run),
        )
        .route(
            "/api/v1/devices/runs/{run_id}/cancel",
            post(device_runs::cancel_run),
        )
        .route(
            "/api/v1/orgs/{org_id}/projects",
            get(projects::list_projects).post(projects::create_project),
        )
        .route(
            "/api/v1/orgs/{org_id}/projects/{project_id}",
            get(projects::get_project).patch(projects::patch_project),
        )
        .route(
            "/api/v1/orgs/{org_id}/projects/{project_id}/access",
            get(projects::list_grants).post(projects::create_grant),
        )
        .route(
            "/api/v1/orgs/{org_id}/projects/{project_id}/access/{grant_id}",
            delete(projects::delete_grant),
        )
        .route(
            "/api/v1/orgs/{org_id}/projects/{project_id}/bindings",
            get(projects::list_project_bindings),
        )
        .route(
            "/api/v1/orgs/{org_id}/projects/{project_id}/bindings/{binding_id}",
            delete(projects::delete_project_binding),
        )
        .route("/api/v1/orgs/{org_id}/catalog", get(ai_catalog::catalog))
        .route(
            "/api/v1/orgs/{org_id}/catalog/providers",
            post(ai_catalog::create_provider),
        )
        .route(
            "/api/v1/orgs/{org_id}/catalog/models",
            post(ai_catalog::create_model),
        )
        .route(
            "/api/v1/orgs/{org_id}/catalog/providers/{provider_id}",
            patch(ai_catalog::update_provider_lifecycle),
        )
        .route(
            "/api/v1/orgs/{org_id}/catalog/models/{model_id}",
            patch(ai_catalog::update_model_lifecycle),
        )
        .route(
            "/api/v1/orgs/{org_id}/credentials",
            get(ai_catalog::list_credentials).post(ai_catalog::create_credential),
        )
        .route(
            "/api/v1/orgs/{org_id}/credentials/{credential_id}/rotate",
            post(ai_catalog::rotate_credential),
        )
        .route(
            "/api/v1/orgs/{org_id}/credentials/{credential_id}/revoke",
            post(ai_catalog::revoke_credential),
        )
        .route(
            "/api/v1/orgs/{org_id}/routes",
            get(ai_catalog::list_routes).post(ai_catalog::create_route),
        )
        .route(
            "/api/v1/orgs/{org_id}/routes/{route_id}/publish",
            post(ai_catalog::publish_route),
        )
        .route(
            "/api/v1/orgs/{org_id}/routes/{route_id}/rollback",
            post(ai_catalog::rollback_route),
        )
        .route(
            "/api/v1/orgs/{org_id}/routes/{route_id}/history",
            get(ai_catalog::route_history),
        )
        .route(
            "/api/v1/orgs/{org_id}/routes/{route_id}",
            patch(ai_catalog::update_route_lifecycle),
        )
        .route(
            "/api/v1/orgs/{org_id}/agents",
            get(agents::list_agents).post(agents::create_agent),
        )
        .route(
            "/api/v1/orgs/{org_id}/agents/{agent_id}",
            get(agents::get_agent).patch(agents::patch_agent),
        )
        .route(
            "/api/v1/orgs/{org_id}/sessions",
            get(agents::list_sessions).post(agents::create_session),
        )
        .route(
            "/api/v1/orgs/{org_id}/sessions/{session_id}",
            get(agents::get_session),
        )
        .route(
            "/api/v1/orgs/{org_id}/sessions/{session_id}/close",
            post(agents::close_session),
        )
        .route(
            "/api/v1/orgs/{org_id}/runs",
            get(runs::list_runs).post(runs::start_run),
        )
        .route("/api/v1/orgs/{org_id}/runs/{run_id}", get(runs::get_run))
        .route(
            "/api/v1/orgs/{org_id}/runs/{run_id}/cancel",
            post(runs::cancel_run),
        )
        .route(
            "/api/v1/orgs/{org_id}/runs/{run_id}/retry",
            post(runs::retry_run),
        )
        .route(
            "/api/v1/orgs/{org_id}/runs/{run_id}/events",
            get(runs::list_run_events),
        )
        .route(
            "/api/v1/orgs/{org_id}/runs/{run_id}/artifacts",
            get(runs::list_artifacts).post(runs::create_artifact),
        )
        .route(
            "/api/v1/orgs/{org_id}/tools",
            get(tools::list_tools).post(tools::create_tool),
        )
        .route(
            "/api/v1/orgs/{org_id}/tools/{tool_id}",
            patch(tools::update_tool),
        )
        .route(
            "/api/v1/orgs/{org_id}/mcp",
            get(tools::list_mcp).post(tools::create_mcp),
        )
        .route(
            "/api/v1/orgs/{org_id}/mcp/{mcp_id}",
            patch(tools::update_mcp),
        )
        .route(
            "/api/v1/orgs/{org_id}/policy/tools",
            get(tools::get_tool_policy).put(tools::put_tool_policy),
        )
        .route(
            "/api/v1/orgs/{org_id}/approvals",
            get(approvals::list_approvals),
        )
        .route(
            "/api/v1/orgs/{org_id}/approvals/{approval_id}",
            get(approvals::get_approval),
        )
        .route(
            "/api/v1/orgs/{org_id}/approvals/{approval_id}/resolve",
            post(approvals::resolve_approval),
        )
        .route("/api/v1/orgs/{org_id}/usage", get(usage::list_usage))
        .route(
            "/api/v1/orgs/{org_id}/usage/summary",
            get(usage::usage_summary),
        )
        .route(
            "/api/v1/orgs/{org_id}/usage/rollups",
            get(usage::usage_rollups),
        )
        .route(
            "/api/v1/orgs/{org_id}/usage/denials",
            get(usage::usage_denials),
        )
        .route(
            "/api/v1/orgs/{org_id}/budgets",
            get(budgets::list_budgets).post(budgets::create_budget),
        )
        .route(
            "/api/v1/orgs/{org_id}/budgets/{budget_id}",
            get(budgets::get_budget).patch(budgets::update_budget),
        )
        .route(budgets::RATE_LIMITS_PATH, get(budgets::list_rate_limits))
        .route(
            "/api/v1/orgs/{org_id}/rate-limits/{scope_type}/{scope_id}",
            put(budgets::update_rate_limit),
        )
        .route(
            "/api/v1/devices/{org_id}/budgets/{budget_id}/reservations",
            post(budgets::create_reservation),
        )
        .route(
            "/api/v1/devices/{org_id}/budgets/{budget_id}/reservations/{reservation_id}/reconcile",
            post(budgets::reconcile_reservation),
        )
        .route(
            "/api/v1/devices/{org_id}/usage/reconcile",
            post(usage::reconcile_usage),
        )
        .route(
            "/api/v1/runs/{run_id}/tool-decisions",
            post(tools::create_tool_decision),
        )
        .route(
            "/api/v1/devices/runs/{run_id}/tool-calls/{tool_call_id}/result",
            post(tools::record_tool_result),
        )
        .route("/api/v1/inference/models", get(inference::models))
        .route("/api/v1/inference/routes/{alias}", get(inference::route))
        .route("/api/v1/inference/responses", post(inference::responses))
        .route(
            "/api/v1/inference/chat/completions",
            post(inference::chat_completions),
        )
        .route("/api/v1/account/sessions", get(account::sessions))
        .route(
            "/api/v1/account/sessions/revoke-all",
            post(account::revoke_all_sessions),
        )
        .route(
            "/api/v1/account/sessions/{session_id}",
            delete(account::revoke_session),
        )
        .route("/api/v1/account/reauth", post(account::reauthenticate))
        .route(
            "/api/v1/account/reauth/passkey/start",
            post(authenticators::reauth_passkey_start),
        )
        .route(
            "/api/v1/account/reauth/passkey/complete",
            post(authenticators::reauth_passkey_complete),
        )
        .route(
            "/api/v1/account/reauth/password",
            post(authenticators::reauth_password),
        )
        .route(
            "/api/v1/account/passkeys",
            get(authenticators::list_passkeys),
        )
        .route(
            "/api/v1/account/passkeys/register/start",
            post(authenticators::passkey_add_start),
        )
        .route(
            "/api/v1/account/passkeys/register/complete",
            post(authenticators::passkey_add_complete),
        )
        .route(
            "/api/v1/account/passkeys/{passkey_id}",
            delete(authenticators::revoke_passkey).patch(authenticators::rename_passkey),
        )
        .route(
            "/api/v1/account/password/status",
            get(authenticators::password_status),
        )
        .route(
            "/api/v1/account/password",
            post(authenticators::set_account_password),
        )
        .route(
            "/api/v1/account/security-events",
            get(account::security_events),
        )
        // ------------------------------------------------------------------
        // P06 durable operations. Every route below is unreachable without this
        // block, so the mount is part of the contract, not bookkeeping: the
        // device lease routes in particular are the only way a host can ever
        // obtain execution authority.
        // ------------------------------------------------------------------
        .route(
            "/api/v1/orgs/{org_id}/automations",
            get(automations::list_automations).post(automations::create_automation),
        )
        .route(
            "/api/v1/orgs/{org_id}/automations/{automation_id}",
            get(automations::get_automation)
                .patch(automations::patch_automation)
                .delete(automations::delete_automation),
        )
        .route(
            "/api/v1/orgs/{org_id}/automations/{automation_id}/pause",
            post(automations::pause_automation),
        )
        .route(
            "/api/v1/orgs/{org_id}/automations/{automation_id}/resume",
            post(automations::resume_automation),
        )
        .route(
            "/api/v1/orgs/{org_id}/automations/{automation_id}/run-now",
            post(automations::run_now),
        )
        .route(
            "/api/v1/orgs/{org_id}/automations/{automation_id}/occurrences",
            get(automations::list_occurrences),
        )
        .route(
            "/api/v1/devices/automations/due",
            get(automations::due_automations),
        )
        .route(
            "/api/v1/devices/automation-occurrences/{occurrence_id}/claim",
            post(automations::claim_occurrence),
        )
        .route(
            "/api/v1/devices/automation-leases/{lease_id}/renew",
            post(automations::renew_lease),
        )
        .route(
            "/api/v1/devices/automation-occurrences/{occurrence_id}/start",
            post(automations::start_occurrence),
        )
        .route(
            "/api/v1/devices/automation-occurrences/{occurrence_id}/settle",
            post(automations::settle_occurrence),
        )
        .route(
            "/api/v1/devices/automation-occurrences/{occurrence_id}/release",
            post(automations::release_occurrence),
        )
        .route(
            "/api/v1/orgs/{org_id}/webhooks",
            get(webhooks::list_webhooks).post(webhooks::create_webhook),
        )
        .route(
            "/api/v1/orgs/{org_id}/webhooks/{endpoint_id}",
            patch(webhooks::patch_webhook).delete(webhooks::disable_webhook),
        )
        .route(
            "/api/v1/orgs/{org_id}/webhooks/{endpoint_id}/rotate-secret",
            post(webhooks::rotate_webhook_secret),
        )
        .route(
            "/api/v1/orgs/{org_id}/webhooks/{endpoint_id}/test",
            post(webhooks::test_webhook),
        )
        .route(
            "/api/v1/orgs/{org_id}/webhooks/{endpoint_id}/deliveries",
            get(webhooks::list_webhook_deliveries),
        )
        .route(
            "/api/v1/orgs/{org_id}/webhooks/deliveries/{delivery_id}/replay",
            post(webhooks::replay_webhook_delivery),
        )
        .route(
            "/api/v1/orgs/{org_id}/notification-preferences",
            get(webhooks::get_notification_preferences)
                .patch(webhooks::patch_notification_preferences),
        )
        .route("/api/v1/notifications", get(webhooks::list_notifications))
        .route(
            "/api/v1/notifications/{notification_id}/read",
            post(webhooks::mark_notification_read),
        )
        .route(
            "/api/v1/me/notification-preferences",
            get(webhooks::get_my_notification_preferences)
                .patch(webhooks::patch_my_notification_preferences),
        )
        .route(
            "/api/v1/orgs/{org_id}/billing/subscription",
            get(billing::read_subscription),
        )
        .route(
            "/api/v1/orgs/{org_id}/entitlements",
            get(billing::read_entitlements),
        )
        // The upstream provider projection is deliberately a SEPARATE read. It
        // exposes normalized status/reason only and can never grant or revoke a
        // Lumi entitlement (P06-CR-002).
        .route(
            "/api/v1/orgs/{org_id}/entitlements/provider",
            get(billing::read_provider_entitlements),
        )
        .route(
            "/api/v1/orgs/{org_id}/billing/portal-session",
            post(billing::create_portal_session),
        )
        .route(
            "/api/v1/orgs/{org_id}/billing/change",
            post(billing::change_plan),
        )
        .route(
            "/api/v1/orgs/{org_id}/billing/cancel",
            post(billing::cancel_subscription),
        )
        .route(
            data_governance::DATA_POLICY_PATH,
            get(data_governance::get_data_policy).patch(data_governance::patch_data_policy),
        )
        .route(
            data_governance::EXPORTS_PATH,
            get(data_governance::list_exports).post(data_governance::create_export),
        )
        .route(
            data_governance::EXPORT_PATH,
            get(data_governance::get_export),
        )
        .route(
            data_governance::EXPORT_DOWNLOAD_PATH,
            post(data_governance::download_export),
        )
        .route(
            data_governance::DELETIONS_PATH,
            get(data_governance::list_deletions),
        )
        .route(
            data_governance::DELETION_PATH,
            get(data_governance::get_deletion),
        )
        .route(
            data_governance::DELETION_RESUME_PATH,
            post(data_governance::resume_deletion),
        )
        .route(
            data_governance::ME_EXPORTS_PATH,
            get(data_governance::list_personal_exports)
                .post(data_governance::create_personal_export),
        )
        .route(
            data_governance::ME_EXPORT_DOWNLOAD_PATH,
            post(data_governance::download_personal_export),
        )
        .route(
            data_governance::ME_DELETION_PATH,
            get(data_governance::get_personal_deletion)
                .post(data_governance::create_personal_deletion),
        )
        .route(
            data_governance::ME_DELETION_CANCEL_PATH,
            post(data_governance::cancel_personal_deletion),
        );

    if is_development {
        routes = routes
            .route(
                "/api/v1/_internal/foundation-checks",
                post(foundation_checks::create),
            )
            .route(
                "/api/v1/_internal/foundation-checks/{event_id}",
                get(foundation_checks::status),
            );
    }

    routes
        .layer(json_body_limit())
        .layer(middleware::from_fn(request_boundary))
        .with_state(state)
}
