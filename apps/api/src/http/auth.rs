use std::sync::Arc;

use axum::{
    body::Body,
    http::{HeaderMap, HeaderName, HeaderValue, Response, header},
};
use serde_json::json;

use crate::{
    adapters::sha256_hex,
    app::AppState,
    core::{ApiError, ApiErrorCode, Principal, RequestContext, SessionId, UserId},
    modules::identity::is_active_session,
    repositories::{IdentityRepository, SessionRecord},
    routes::errors,
};

pub const SESSION_COOKIE: &str = "lumi_session";
pub const CSRF_COOKIE: &str = "lumi_csrf";
pub const SESSION_MAX_AGE: u64 = 60 * 60 * 24 * 30;

#[derive(Clone)]
pub struct Authenticated {
    pub principal: Principal,
    pub session: SessionRecord,
}

/// Resolve the current session from a cookie or bearer token. The session row
/// is always read from D1; no role or membership data is accepted from a token.
pub async fn require_session(
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
    let token_hash = sha256_hex(&raw_token)
        .await
        .map_err(|_| errors::api_error(context, ApiErrorCode::ServiceUnavailable, "The identity store is unavailable."))?;
    let session = IdentityRepository::new(database)
        .find_session_by_token_hash(&token_hash, &context.received_at)
        .await
        .map_err(|_| errors::api_error(context, ApiErrorCode::ServiceUnavailable, "The identity store is unavailable."))?
        .ok_or_else(|| authentication_required(context))?;

    if !is_active_session(session.revoked_at.as_deref(), &session.expires_at, context.received_at.as_str()) {
        return Err(authentication_required(context));
    }
    let user_id = UserId::new(session.user_id.clone()).map_err(|_| authentication_required(context))?;
    let session_id = SessionId::new(session.session_id.clone()).map_err(|_| authentication_required(context))?;
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

pub async fn require_csrf(
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
    let digest = sha256_hex(header)
        .await
        .map_err(|_| errors::api_error(context, ApiErrorCode::ServiceUnavailable, "The identity store is unavailable."))?;
    if !constant_time_eq(digest.as_bytes(), session.csrf_hash.as_bytes()) {
        return Err(csrf_error(context));
    }
    Ok(())
}

pub fn read_session_token(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers.get(header::AUTHORIZATION).and_then(|value| value.to_str().ok()) {
        if let Some(token) = value.strip_prefix("Bearer ") {
            return Some(token.trim().to_owned());
        }
    }
    read_cookie(headers, SESSION_COOKIE)
}

pub fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie.split(';').filter_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name && is_cookie_value(value)).then(|| value.to_owned())
    }).next()
}

pub fn set_session_cookies(
    response: &mut Response<Body>,
    session_token: &str,
    csrf_token: &str,
    secure: bool,
) {
    append_cookie(response, SESSION_COOKIE, session_token, SESSION_MAX_AGE, secure, true);
    append_cookie(response, CSRF_COOKIE, csrf_token, SESSION_MAX_AGE, secure, false);
}

pub fn clear_session_cookies(response: &mut Response<Body>, secure: bool) {
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
        response.headers_mut().append(header::SET_COOKIE, header_value);
    }
}

fn authentication_required(context: &RequestContext) -> ApiError {
    errors::api_error(context, ApiErrorCode::AuthenticationRequired, "Authentication is required.")
        .with_detail("reason", json!("authentication_required"))
}

fn csrf_error(context: &RequestContext) -> ApiError {
    errors::api_error(context, ApiErrorCode::PermissionDenied, "The request could not be verified.")
        .with_detail("reason", json!("csrf_failed"))
}

fn is_cookie_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| byte.is_ascii_hexdigit() || byte == b'-' || byte == b'_')
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter().zip(right).fold(0, |difference, (left, right)| difference | (left ^ right)) == 0
}

#[allow(dead_code)]
fn _header_name_is_stable() -> HeaderName {
    header::AUTHORIZATION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_and_bearer_parsing_are_bounded() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_static("other=x; lumi_session=abc123; lumi_csrf=def456"));
        assert_eq!(read_session_token(&headers).as_deref(), Some("abc123"));
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer bearer-token"));
        assert_eq!(read_session_token(&headers).as_deref(), Some("bearer-token"));
    }

    #[test]
    fn constant_time_comparison_has_no_length_or_value_shortcut() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"different"));
        assert!(!constant_time_eq(b"same", b"sam"));
    }
}
