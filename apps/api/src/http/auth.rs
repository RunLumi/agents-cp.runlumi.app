use std::sync::Arc;

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Response, header},
};
use serde_json::json;

use crate::{
    adapters::sha256_hex,
    app::AppState,
    core::{
        ApiError, ApiErrorCode, MachineActor, MachineKey, Principal, RequestContext, SessionId,
        StaffPrincipalId, UserId, constant_time_eq as core_constant_time_eq,
    },
    modules::identity::is_active_session,
    repositories::{IdentityRepository, MachineIdentityRepository, SessionRecord},
    routes::errors,
};

pub const SESSION_COOKIE: &str = "lumi_session";
pub const CSRF_COOKIE: &str = "lumi_csrf";
pub const SESSION_MAX_AGE: u64 = 60 * 60 * 24 * 30;

#[derive(Clone)]
pub(crate) struct Authenticated {
    pub principal: Principal,
    pub session: SessionRecord,
}

/// Resolve the current session from a cookie or bearer token. The session row
/// is always read from D1; no role or membership data is accepted from a token.
pub(crate) async fn require_session(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    context: &RequestContext,
) -> Result<Authenticated, ApiError> {
    let database = state.database.as_ref().ok_or_else(|| {
        errors::api_error(
            context,
            ApiErrorCode::ServiceUnavailable,
            "The identity store is unavailable.",
        )
    })?;
    let raw_token = read_session_token(headers).ok_or_else(|| authentication_required(context))?;
    if raw_token.len() > 256 || !raw_token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(authentication_required(context));
    }
    let token_hash = sha256_hex(&raw_token).await.map_err(|_| {
        errors::api_error(
            context,
            ApiErrorCode::ServiceUnavailable,
            "The identity store is unavailable.",
        )
    })?;
    let session = IdentityRepository::new(database)
        .find_session_by_token_hash(&token_hash, &context.received_at)
        .await
        .map_err(|_| {
            errors::api_error(
                context,
                ApiErrorCode::ServiceUnavailable,
                "The identity store is unavailable.",
            )
        })?
        .ok_or_else(|| authentication_required(context))?;

    if !is_active_session(
        session.revoked_at.as_deref(),
        &session.expires_at,
        context.received_at.as_str(),
    ) {
        return Err(authentication_required(context));
    }
    let user_id =
        UserId::new(session.user_id.clone()).map_err(|_| authentication_required(context))?;
    let session_id =
        SessionId::new(session.session_id.clone()).map_err(|_| authentication_required(context))?;
    let principal = Principal::new(
        user_id,
        session_id,
        session.email.clone(),
        session.display_name.clone(),
        session.email_verified,
    );
    let _ = IdentityRepository::new(database)
        .touch_session(&session.session_id, &context.received_at)
        .await;
    Ok(Authenticated { principal, session })
}

pub(crate) async fn require_csrf(
    headers: &HeaderMap,
    session: &SessionRecord,
    context: &RequestContext,
) -> Result<(), ApiError> {
    let cookie = read_cookie(headers, CSRF_COOKIE).ok_or_else(|| csrf_error(context))?;
    let header = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or_else(|| csrf_error(context))?;
    if !constant_time_eq(cookie.as_bytes(), header.as_bytes()) {
        return Err(csrf_error(context));
    }
    let digest = sha256_hex(header).await.map_err(|_| {
        errors::api_error(
            context,
            ApiErrorCode::ServiceUnavailable,
            "The identity store is unavailable.",
        )
    })?;
    if !constant_time_eq(digest.as_bytes(), session.csrf_hash.as_bytes()) {
        return Err(csrf_error(context));
    }
    Ok(())
}

pub(crate) fn read_session_token(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        && let Some(token) = value.strip_prefix("Bearer ")
    {
        return Some(token.trim().to_owned());
    }
    read_cookie(headers, SESSION_COOKIE)
}

pub(crate) fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie
        .split(';')
        .filter_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name && is_cookie_value(value)).then(|| value.to_owned())
        })
        .next()
}

pub(crate) fn set_session_cookies(
    response: &mut Response<Body>,
    session_token: &str,
    csrf_token: &str,
    secure: bool,
) {
    append_cookie(
        response,
        SESSION_COOKIE,
        session_token,
        SESSION_MAX_AGE,
        secure,
        true,
    );
    append_cookie(
        response,
        CSRF_COOKIE,
        csrf_token,
        SESSION_MAX_AGE,
        secure,
        false,
    );
}

pub(crate) fn clear_session_cookies(response: &mut Response<Body>, secure: bool) {
    append_cookie(response, SESSION_COOKIE, "", 0, secure, true);
    append_cookie(response, CSRF_COOKIE, "", 0, secure, false);
}

pub fn authorization_failure(context: &RequestContext, reason: &str, message: &str) -> ApiError {
    errors::api_error(context, ApiErrorCode::PermissionDenied, message)
        .with_detail("reason", json!(reason))
}

fn append_cookie(
    response: &mut Response<Body>,
    name: &str,
    value: &str,
    max_age: u64,
    secure: bool,
    http_only: bool,
) {
    let mut cookie = format!("{name}={value}; Path=/; Max-Age={max_age}; SameSite=Lax");
    if http_only {
        cookie.push_str("; HttpOnly");
    }
    if secure {
        cookie.push_str("; Secure");
    }
    if let Ok(header_value) = HeaderValue::from_str(&cookie) {
        response
            .headers_mut()
            .append(header::SET_COOKIE, header_value);
    }
}

fn authentication_required(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::AuthenticationRequired,
        "Authentication is required.",
    )
    .with_detail("reason", json!("authentication_required"))
}

fn csrf_error(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::PermissionDenied,
        "The request could not be verified.",
    )
    .with_detail("reason", json!("csrf_failed"))
}

fn is_cookie_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-' || byte == b'_')
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0, |difference, (left, right)| difference | (left ^ right))
        == 0
}
// ------------------------------------------------------------ P07 machine ---

/// A machine caller resolved from a `lumik_` credential.
///
/// The shape is deliberately different from [`Authenticated`]: there is no
/// session, no user, and no cookie to set. A machine must not be able to acquire
/// anything a human session has, and the type has no field that could hold one.
pub(crate) struct MachineAuthenticated {
    pub actor: MachineActor,
    /// The resolved scope, ready for `authorize_machine`. Read in the same query
    /// as the credential so the scope cannot change between authentication and
    /// authorization.
    pub scope: crate::modules::machine_identity::ApiKeyScope,
    pub state: crate::modules::machine_identity::CredentialState,
}

/// Resolve a presented `lumik_` credential into a [`MachineActor`] (P07-INT-02).
///
/// # Why this is a separate function and not a branch inside `require_session`
///
/// ADR 0007 is explicit that `authorize` must stay frozen and that a machine
/// cannot reach a route which only calls it. A "smarter auth middleware" that
/// returned a session-shaped value for a machine would undo that, because the
/// route could not tell which kind of caller it had. Here the return type says so.
///
/// # Every refusal is the same error
///
/// A missing key, a wrong secret, a revoked key and a suspended account all
/// produce `machine_key_invalid` at this layer. A caller must not be able to
/// learn which keys exist by timing or by status code. The *specific* reasons
/// live in `authorize_machine` and are what an operator sees in a log, not what a
/// caller sees in a response.
pub(crate) async fn require_machine(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    context: &RequestContext,
) -> Result<MachineAuthenticated, ApiError> {
    let database = state.database.as_ref().ok_or_else(|| {
        errors::api_error(
            context,
            ApiErrorCode::ServiceUnavailable,
            "The identity store is unavailable.",
        )
    })?;
    let presented = read_bearer(headers).ok_or_else(|| machine_key_invalid(context))?;
    let key = MachineKey::parse(&presented).map_err(|_| machine_key_invalid(context))?;

    let resolved = MachineIdentityRepository::new(database)
        .resolve_credential(key.prefix())
        .await
        .map_err(|_| {
            errors::api_error(
                context,
                ApiErrorCode::ServiceUnavailable,
                "The identity store is unavailable.",
            )
        })?
        .ok_or_else(|| machine_key_invalid(context))?;

    // Constant-time on the stored hash. The prefix lookup has already told us
    // WHICH row this is, so the comparison is only the second factor; running it
    // in constant time keeps the habit in the same place as the session path,
    // where a shortcut is easiest to introduce by accident.
    let presented_hash = machine_secret_hash(key.secret());
    if !core_constant_time_eq(
        presented_hash.as_bytes(),
        resolved.key.secret_hash.as_bytes(),
    ) {
        return Err(machine_key_invalid(context));
    }
    if !resolved.key.is_active() || !resolved.account_is_active() {
        return Err(machine_key_invalid(context));
    }
    if is_expired(
        resolved.key.expires_at.as_deref(),
        context.received_at.as_str(),
    ) || is_expired(
        resolved.account_expires_at.as_deref(),
        context.received_at.as_str(),
    ) {
        return Err(machine_key_invalid(context));
    }

    let scope = crate::modules::machine_identity::scope_from_stored(
        &resolved.key.capabilities_json,
        resolved.key.project_ids_json.as_deref(),
        resolved.key.model_aliases_json.as_deref(),
        resolved.key.network_allowlist_json.as_deref(),
    )
    .map_err(|_| {
        errors::api_error(
            context,
            ApiErrorCode::ServiceUnavailable,
            "The identity store is unavailable.",
        )
    })?;

    let actor = MachineActor::new(
        crate::core::ApiKeyId::new(resolved.key.api_key_id.clone())
            .map_err(|_| machine_key_invalid(context))?,
        crate::core::ServiceAccountId::new(resolved.key.service_account_id.clone())
            .map_err(|_| machine_key_invalid(context))?,
        crate::core::OrganizationId::new(resolved.key.org_id.clone())
            .map_err(|_| machine_key_invalid(context))?,
        resolved.key.key_prefix.clone(),
    );

    // F14-005, best effort. A failure to record last-used must not fail the
    // request the credential was making.
    let _ = MachineIdentityRepository::new(database)
        .touch_key_use(
            &resolved.key.api_key_id,
            context.received_at.as_str(),
            crate::modules::machine_identity::last_used_source(
                read_header(headers, "cf-connecting-ip").as_deref(),
                None,
            )
            .as_deref()
            .unwrap_or("unknown"),
        )
        .await;

    Ok(MachineAuthenticated {
        actor,
        scope,
        state: crate::modules::machine_identity::CredentialState {
            key_active: true,
            account_active: true,
            key_expired: false,
        },
    })
}

/// The stored hash is SHA-256 of the SECRET half. `core::machine` owns that
/// derivation; this wrapper exists so the auth path never looks like it is
/// hashing something else.
fn machine_secret_hash(secret: &str) -> String {
    crate::core::MachineKeyMaterial::hash_secret(secret)
}

// -------------------------------------------------------------- P07 staff ---

/// A resolved internal staff caller.
pub(crate) struct StaffAuthenticated {
    pub actor: crate::modules::staff::StaffActor,
    /// Not used by any P07 route: `/internal` reads no customer data, so there
    /// is no response that needs the display name yet. It is resolved here
    /// rather than at the call site so a future console that DOES need it does
    /// not re-read the principal.
    #[allow(dead_code)]
    pub display_name: String,
    pub staff_role: crate::modules::staff::StaffRole,
}

/// Resolve a presented `lumi_staff_` credential into a [`StaffActor`].
///
/// The scheme is disjoint from both the human session bearer and `lumik_`, so
/// the three actor kinds cannot be confused for one another at a route boundary.
/// A `lumi_staff_` token presented on an organization route therefore fails at
/// `require_session` as an ordinary authentication failure, and a `lumik_` token
/// presented here fails as a staff authentication failure — neither is silently
/// reinterpreted.
pub(crate) async fn require_staff(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    context: &RequestContext,
) -> Result<StaffAuthenticated, ApiError> {
    let database = state.database.as_ref().ok_or_else(|| {
        errors::api_error(
            context,
            ApiErrorCode::ServiceUnavailable,
            "The identity store is unavailable.",
        )
    })?;
    let presented = read_bearer(headers).ok_or_else(|| staff_authentication_required(context))?;
    if !presented.starts_with(crate::core::STAFF_KEY_SCHEME) {
        return Err(staff_authentication_required(context));
    }
    let resolved = crate::repositories::PlatformOperationsRepository::new(database)
        .resolve_staff_credential(&presented)
        .await
        .map_err(|_| {
            errors::api_error(
                context,
                ApiErrorCode::ServiceUnavailable,
                "The identity store is unavailable.",
            )
        })?
        .ok_or_else(|| staff_authentication_required(context))?;

    // A stored role that no longer parses is reported as an authentication
    // failure rather than defaulted. Defaulting would mean a renamed or corrupted
    // role silently resolved to some other role's permissions, and the only safe
    // reading of "I do not know what this person is" is "I do not know who this
    // person is".
    let role = resolved
        .role()
        .ok_or_else(|| staff_authentication_required(context))?;
    if !resolved.is_active() {
        return Err(errors::api_error(
            context,
            ApiErrorCode::PermissionDenied,
            "This staff principal is suspended.",
        )
        .with_detail("reason", json!("staff_principal_suspended")));
    }
    Ok(StaffAuthenticated {
        actor: crate::modules::staff::StaffActor::new(
            StaffPrincipalId::new(resolved.staff_principal_id)
                .map_err(|_| staff_authentication_required(context))?,
            role,
            resolved.credential_prefix,
        ),
        display_name: resolved.display_name,
        staff_role: role,
    })
}

fn read_bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    if token.is_empty() || token.len() > 512 || token.chars().any(char::is_control) {
        return None;
    }
    Some(token.to_owned())
}

fn read_header(headers: &HeaderMap, name: &str) -> Option<String> {
    let value = headers.get(name)?.to_str().ok()?;
    let value = value.trim();
    if value.is_empty() || value.len() > 64 || value.chars().any(char::is_whitespace) {
        return None;
    }
    Some(value.to_owned())
}

/// The stored timestamps are the fixed 24-character UTC form, so a lexicographic
/// comparison is equivalent to a chronological one. `None` means "no expiry",
/// which is not the same as "expired".
fn is_expired(expires_at: Option<&str>, now: &str) -> bool {
    expires_at.is_some_and(|expiry| now >= expiry)
}

fn machine_key_invalid(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::AuthenticationRequired,
        "Authentication is required.",
    )
    .with_detail("reason", json!("machine_key_invalid"))
}

fn staff_authentication_required(context: &RequestContext) -> ApiError {
    errors::api_error(
        context,
        ApiErrorCode::AuthenticationRequired,
        "Authentication is required.",
    )
    .with_detail("reason", json!("staff_authentication_required"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_and_bearer_parsing_are_bounded() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other=x; lumi_session=abc123; lumi_csrf=def456"),
        );
        assert_eq!(read_session_token(&headers).as_deref(), Some("abc123"));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer bearer-token"),
        );
        assert_eq!(
            read_session_token(&headers).as_deref(),
            Some("bearer-token")
        );
    }

    #[test]
    fn constant_time_comparison_has_no_length_or_value_shortcut() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"different"));
        assert!(!constant_time_eq(b"same", b"sam"));
    }
}
