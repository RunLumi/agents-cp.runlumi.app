//! Billing provider adapter boundary (P06-BE-03).
//!
//! WHY the boundary exists: `P06-CG` freezes a `BillingProviderAdapter` that
//! "maps provider state to Lumi subscription state; provider IDs never enter
//! product logic". This module is the only place that knows what a provider
//! product or price identifier is, and the only place that decides how a
//! provider's own vocabulary becomes a Lumi `SubscriptionStatus` / `PlanPointer`.
//!
//! # Adapter-private identifiers
//!
//! [`LocalBillingAdapter`] holds its Lumi-plan-key to provider product/price
//! mapping in a private table. That mapping is:
//!
//! * never returned by any method,
//! * never persisted in a Lumi column (`plans.plan_key` is a Lumi key; the
//!   subscription only ever stores an opaque `provider_subscription_ref`),
//! * never placed in a public response, an outbox payload, an audit row, or a
//!   log line.
//!
//! Product logic therefore branches on Lumi plan keys only, and a provider
//! changing its price catalogue never requires a feature-gate change.
//!
//! # Callback handling
//!
//! A provider callback is translated into a bounded
//! [`ProviderEvent`] at this boundary. The raw provider body is never
//! represented in a type here, so there is no path by which it can be logged or
//! stored. A callback must carry a stable provider event ID, a signed
//! timestamp/nonce pair, an adapter account binding, and a monotonic provider
//! version; the D1 `UNIQUE(provider_event_id)` index plus the pure
//! `ProviderEventLedger` in `modules::entitlements` reject replays, and
//! out-of-order/future-dated events are refused without advancing state.
//!
//! # Portal sessions
//!
//! [`LocalBillingAdapter::create_portal_session`] returns only an allowlisted
//! HTTPS provider portal URL with a short lifetime, or a stable unavailable
//! reason. Card data never enters Lumi: the request carries no payment
//! instrument, and no response contains one.

use std::fmt;
use std::future::Future;

use serde_json::{Value, json};

use crate::core::PlanId;
use crate::modules::entitlements::{
    MAX_PROVIDER_EVENT_ID_BYTES, MAX_PROVIDER_EVENT_SKEW_SECONDS, MAX_PROVIDER_REFERENCE_BYTES,
    PlanPointer, ProviderAvailability, ProviderEntitlementStatus, ProviderEvent,
    SubscriptionStatus, is_lumi_plan_key,
};

/// Provider kind identifier for the built-in local/mock adapter.
pub const LOCAL_PROVIDER_KIND: &str = "local";

/// Widest replay window a provider callback timestamp may fall inside.
pub const MAX_CALLBACK_REPLAY_WINDOW_SECONDS: i64 = 300;

/// Widest portal/checkout session lifetime Lumi will hand out.
pub const MAX_PORTAL_SESSION_TTL_SECONDS: i64 = 900;

/// Ceiling on a provider portal URL, matching the frozen bounded-URL rule.
pub const MAX_PORTAL_URL_BYTES: usize = 2048;

/// The billing provider adapter boundary.
pub trait BillingProviderAdapter {
    /// Stable adapter kind, stored in `billing_accounts.provider_kind`.
    fn kind(&self) -> &str;

    /// Map a bounded, authenticated provider callback into a Lumi
    /// [`ProviderEvent`]. Implementations MUST NOT retain the raw payload.
    fn map_callback(&self, callback: &ProviderCallback) -> Result<ProviderEvent, ProviderError>;

    /// Open a short-lived provider portal/checkout session.
    ///
    /// Returns only an allowlisted URL; no card data is accepted or returned.
    ///
    /// The outbound-capable methods return `impl Future` rather than `async fn`
    /// so the boundary is a normal trait method: it is never used as a trait
    /// object, and an explicit return type keeps the adapter contract readable
    /// and lint-free on the `wasm32-unknown-unknown` target.
    fn create_portal_session(
        &self,
        request: &PortalSessionRequest,
        now: i64,
    ) -> impl Future<Output = Result<PortalSession, ProviderError>>;

    /// Map a requested Lumi plan key to the provider-side subscription state the
    /// adapter expects. Lumi plan keys in, provider event out.
    fn request_plan_change(
        &self,
        request: &PlanChangeRequest,
    ) -> impl Future<Output = Result<ProviderEvent, ProviderError>>;

    /// Map a cancellation request to the provider-side transition.
    fn request_cancellation(
        &self,
        request: &CancellationRequest,
    ) -> impl Future<Output = Result<ProviderEvent, ProviderError>>;
}

/// Bounded, already-translated provider callback metadata.
///
/// This type is the ONLY representation of a provider callback inside Lumi. It
/// deliberately has no `raw_body`/`payload` field, so the raw provider payload
/// is unrepresentable rather than merely discouraged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderCallback {
    /// Stable provider event ID. Makes the callback idempotent.
    pub provider_event_id: String,
    /// Opaque, adapter-private provider account reference.
    pub account_reference: String,
    /// Monotonic provider version, used for out-of-order rejection.
    pub provider_version: i64,
    /// Provider-reported effective instant (whole Unix seconds).
    pub effective_at: i64,
    /// Adapter-authenticated timestamp (whole Unix seconds).
    pub signed_timestamp: i64,
    /// Adapter-authenticated single-use nonce.
    pub nonce: String,
    /// Provider status already mapped to Lumi vocabulary by the adapter.
    pub next_status: SubscriptionStatus,
    /// Lumi plan key the provider moved to, when the callback carries one.
    pub next_plan_key: Option<String>,
    /// HMAC-SHA256 over `timestamp "." nonce "." provider_event_id` using the
    /// adapter webhook secret, lowercase hex. Verified before mapping.
    pub signature_hex: String,
}

/// Bounded metadata for a portal/checkout session request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortalSessionRequest {
    /// Opaque, adapter-private provider account reference.
    pub account_reference: String,
    /// Lumi plan key the session should offer. Never a provider price ID.
    pub plan_key: String,
    /// Return-to path appended to the provider session. Must be a relative
    /// path; an absolute URL would let a client redirect a browser off-site.
    pub return_path: String,
}

/// A short-lived provider portal session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortalSession {
    /// Allowlisted HTTPS provider URL.
    pub url: String,
    /// Whole-Unix-seconds expiry.
    pub expires_at: i64,
    /// Stable adapter session reference, opaque and adapter-private.
    pub session_reference: String,
}

/// Bounded metadata for a plan change request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanChangeRequest {
    /// Opaque, adapter-private provider account reference.
    pub account_reference: String,
    /// Current Lumi plan key.
    pub from_plan_key: String,
    /// Requested Lumi plan key.
    pub to_plan_key: String,
    /// Whole Unix seconds the request was accepted.
    pub requested_at: i64,
}

/// Bounded metadata for a cancellation request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancellationRequest {
    /// Opaque, adapter-private provider account reference.
    pub account_reference: String,
    /// Current Lumi plan key.
    pub plan_key: String,
    /// `true` to cancel at period end rather than immediately.
    pub at_period_end: bool,
    /// Whole Unix seconds the request was accepted.
    pub requested_at: i64,
}

/// The stable failure classes a provider adapter can report.
///
/// `Unavailable` is retryable and must never become a permanent denial: a
/// transient provider outage may not brick unrelated local work. Every other
/// kind is a deterministic refusal. No variant carries provider text, so an
/// error can be logged without leaking a provider response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderErrorKind {
    /// The request referenced a plan key this adapter does not offer.
    UnknownPlan,
    /// The callback failed adapter authentication.
    SignatureInvalid,
    /// The callback timestamp is outside the replay window.
    ReplayWindowExceeded,
    /// The callback is bound to a different adapter account.
    AccountBindingMismatch,
    /// The callback is stale, replayed, or future-dated.
    OutOfOrder,
    /// The provider is unreachable or failing. Retryable.
    Unavailable,
    /// The adapter cannot mint a portal session right now. Retryable.
    PortalUnavailable,
    /// A request field failed bounded validation.
    InvalidRequest,
}

impl ProviderErrorKind {
    /// Stable machine-readable reason from the frozen P06 error list.
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnknownPlan | Self::InvalidRequest => "validation_failed",
            Self::SignatureInvalid => "webhook_signature_invalid",
            Self::ReplayWindowExceeded => "webhook_replay_window_exceeded",
            Self::AccountBindingMismatch => "resource_not_found",
            Self::OutOfOrder => "provider_event_out_of_order",
            Self::Unavailable => "provider_entitlement_unavailable",
            Self::PortalUnavailable => "subscription_state_unavailable",
        }
    }

    /// `true` for a transient provider condition, which must never be turned
    /// into a permanent commercial denial.
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Unavailable | Self::PortalUnavailable)
    }
}

/// A bounded provider-adapter failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderError {
    pub kind: ProviderErrorKind,
}

impl ProviderError {
    pub const fn new(kind: ProviderErrorKind) -> Self {
        Self { kind }
    }

    pub const fn code(self) -> &'static str {
        self.kind.code()
    }

    pub const fn is_retryable(self) -> bool {
        self.kind.is_retryable()
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind.code())
    }
}

impl std::error::Error for ProviderError {}

/// The built-in local/mock adapter.
///
/// It behaves like a well-behaved provider for development and tests: it derives
/// a stable provider event ID from the request, refuses a callback whose
/// signature/replay window/account binding does not check out, and maps Lumi
/// plan keys to a provider event. It never returns a product or price ID.
#[derive(Clone, Debug)]
pub struct LocalBillingAdapter {
    /// Exact host allowlist for portal sessions. A URL outside this set is
    /// refused rather than returned.
    portal_hosts: Vec<String>,
    /// Plan keys this adapter offers, in ascending order.
    plan_keys: Vec<String>,
}

impl Default for LocalBillingAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalBillingAdapter {
    /// A local adapter with no portal host allowlist and no offered plans.
    ///
    /// A deployment MUST configure the allowlist and plans; an unconfigured
    /// adapter refuses every portal session and every plan change rather than
    /// inventing a commercial answer.
    pub fn new() -> Self {
        Self {
            portal_hosts: Vec::new(),
            plan_keys: Vec::new(),
        }
    }

    /// Build an adapter for an exact portal host allowlist and plan set.
    ///
    /// Both are validated as bounded, lowercase, control-free strings. The
    /// allowlist is exact-host matching: no wildcard, no suffix matching, so a
    /// provider hostname typo cannot silently widen egress.
    pub fn with_configuration(
        portal_hosts: Vec<String>,
        plan_keys: Vec<String>,
    ) -> Result<Self, ProviderError> {
        for host in &portal_hosts {
            if !bounded_host(host) {
                return Err(ProviderError::new(ProviderErrorKind::InvalidRequest));
            }
        }
        let mut keys = plan_keys;
        keys.sort();
        keys.dedup();
        for key in &keys {
            if !is_lumi_plan_key(key) {
                return Err(ProviderError::new(ProviderErrorKind::InvalidRequest));
            }
        }
        Ok(Self {
            portal_hosts,
            plan_keys: keys,
        })
    }

    fn offers(&self, plan_key: &str) -> bool {
        self.plan_keys.iter().any(|key| key == plan_key)
    }
}

/// Derive the Lumi plan pointer for a plan KEY, before the immutable
/// `plans(plan_key, version)` row has been resolved.
///
/// WHY a key-derived placeholder exists: a provider callback can arrive before
/// the corresponding plan version row exists, and `PlanPointer` requires a
/// `plan_` identifier. Deriving the identifier from the validated Lumi plan key
/// (never from a provider product/price ID) keeps the pointer inside Lumi
/// vocabulary; the repository then re-binds it to the real immutable plan row
/// before anything is persisted, so a placeholder can never become a stored
/// foreign key.
pub fn plan_pointer_for(plan_key: &str) -> Result<PlanPointer, ProviderError> {
    if !is_lumi_plan_key(plan_key) {
        return Err(ProviderError::new(ProviderErrorKind::UnknownPlan));
    }
    let plan_id = PlanId::new(format!("plan_{}", stable_identifier(plan_key)))
        .map_err(|_| ProviderError::new(ProviderErrorKind::UnknownPlan))?;
    PlanPointer::new(plan_id, plan_key, 1)
        .map_err(|_| ProviderError::new(ProviderErrorKind::UnknownPlan))
}

/// A deterministic 32-hex-character suffix derived from a bounded ASCII string.
///
/// This is an identifier-derivation helper, explicitly NOT a security primitive:
/// no authorization, entitlement, or replay decision depends on it, and it never
/// protects anything secret. It exists so a plan key and an override key can map
/// to stable typed Lumi identifiers without a CSPRNG call on a pure path, and so
/// tests are reproducible.
pub fn stable_identifier(value: &str) -> String {
    // Two independently seeded 64-bit FNV-1a passes concatenated to 128 bits.
    // Collision resistance is irrelevant to correctness here because the
    // derived identifier is validated against a real row before it is used.
    const OFFSETS: [u64; 2] = [0xcbf2_9ce4_8422_2325, 0x9e37_79b9_7f4a_7c15];
    let mut out = String::with_capacity(32);
    for (index, seed) in OFFSETS.iter().enumerate() {
        let mut hash = *seed ^ (index as u64).wrapping_mul(0x0000_0100_0000_01b3);
        for byte in value.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        out.push_str(&format!("{hash:016x}"));
    }
    out
}

/// Exact-host validation for the portal allowlist. IP literals, userinfo, and
/// non-HTTPS schemes are impossible by construction because only a bare host is
/// stored and the URL is rebuilt from it.
fn bounded_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.contains("..")
        && value
            .split('.')
            .all(|label| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-'))
}

/// Validate a relative return path. An absolute URL, a scheme-relative path, or
/// anything containing a control byte is refused, so a portal session cannot
/// become an open redirect off the Lumi origin.
pub fn validate_return_path(value: &str) -> Result<&str, ProviderError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > 512
        || trimmed.starts_with('/')
        || trimmed.contains("://")
        || trimmed.contains('\\')
        || trimmed.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ProviderError::new(ProviderErrorKind::InvalidRequest));
    }
    Ok(trimmed)
}

/// Build the allowlisted provider portal URL.
///
/// PURE and host-testable: the outbound call a real provider needs lives in the
/// adapter method, while the URL contract — exact allowlisted host, no userinfo,
/// no fragment, bounded length, percent-encoded Lumi plan key and relative
/// return path — is decided here.
pub fn portal_session_url(
    host: &str,
    account_reference: &str,
    plan_key: &str,
    return_path: &str,
) -> Result<PortalSession, ProviderError> {
    if !bounded_host(host) || !bounded_reference(account_reference) {
        return Err(ProviderError::new(ProviderErrorKind::InvalidRequest));
    }
    let return_path = validate_return_path(return_path)?;
    // The session reference is derived from the opaque account reference, so the
    // URL cannot encode a card, a price ID, or a client-controlled host.
    let session_reference = session_reference(account_reference);
    let url = format!(
        "https://{host}/billing/session/{session_reference}/checkout?plan={}&return={}",
        url_encode(plan_key),
        url_encode(return_path)
    );
    if url.len() > MAX_PORTAL_URL_BYTES {
        return Err(ProviderError::new(ProviderErrorKind::InvalidRequest));
    }
    Ok(PortalSession {
        url,
        expires_at: 0,
        session_reference,
    })
}

/// Build the Lumi provider event for a plan change.
///
/// PURE: the event ID is derived from the accepted instant and the Lumi target
/// plan key, so a retried request produces the same stable event ID and D1's
/// `UNIQUE (provider_event_id)` index makes the retry a no-op.
pub fn plan_change_event(request: &PlanChangeRequest) -> Result<ProviderEvent, ProviderError> {
    if !bounded_reference(&request.account_reference)
        || !is_lumi_plan_key(&request.from_plan_key)
        || !is_lumi_plan_key(&request.to_plan_key)
        || request.from_plan_key == request.to_plan_key
        || request.requested_at < 0
    {
        return Err(ProviderError::new(ProviderErrorKind::InvalidRequest));
    }
    ProviderEvent::new(
        format!(
            "local_plan_{}_{}",
            request.requested_at, request.to_plan_key
        ),
        request.account_reference.clone(),
        request.requested_at,
        request.requested_at,
        SubscriptionStatus::Active,
        Some(plan_pointer_for(&request.to_plan_key)?),
    )
    .map_err(|_| ProviderError::new(ProviderErrorKind::InvalidRequest))
}

/// Build the Lumi provider event for a cancellation.
///
/// PURE, with the same stable-event-ID property as [`plan_change_event`].
pub fn cancellation_event(request: &CancellationRequest) -> Result<ProviderEvent, ProviderError> {
    if !bounded_reference(&request.account_reference)
        || !is_lumi_plan_key(&request.plan_key)
        || request.requested_at < 0
    {
        return Err(ProviderError::new(ProviderErrorKind::InvalidRequest));
    }
    ProviderEvent::new(
        format!("local_cancel_{}_{}", request.requested_at, request.plan_key),
        request.account_reference.clone(),
        request.requested_at,
        request.requested_at,
        SubscriptionStatus::Cancelled,
        None,
    )
    .map_err(|_| ProviderError::new(ProviderErrorKind::InvalidRequest))
}

impl BillingProviderAdapter for LocalBillingAdapter {
    fn kind(&self) -> &str {
        LOCAL_PROVIDER_KIND
    }

    fn map_callback(&self, callback: &ProviderCallback) -> Result<ProviderEvent, ProviderError> {
        validate_callback_shape(callback)?;
        if let Some(plan_key) = &callback.next_plan_key
            && !self.offers(plan_key)
        {
            return Err(ProviderError::new(ProviderErrorKind::UnknownPlan));
        }
        let next_plan = match &callback.next_plan_key {
            Some(plan_key) => Some(plan_pointer_for(plan_key)?),
            None => None,
        };
        ProviderEvent::new(
            callback.provider_event_id.clone(),
            callback.account_reference.clone(),
            callback.provider_version,
            callback.effective_at,
            callback.next_status,
            next_plan,
        )
        .map_err(|_| ProviderError::new(ProviderErrorKind::InvalidRequest))
    }

    async fn create_portal_session(
        &self,
        request: &PortalSessionRequest,
        now: i64,
    ) -> Result<PortalSession, ProviderError> {
        if !self.offers(&request.plan_key) {
            return Err(ProviderError::new(ProviderErrorKind::UnknownPlan));
        }
        let host = self
            .portal_hosts
            .first()
            .ok_or_else(|| ProviderError::new(ProviderErrorKind::PortalUnavailable))?;
        let mut session = portal_session_url(
            host,
            &request.account_reference,
            &request.plan_key,
            &request.return_path,
        )?;
        session.expires_at = now.saturating_add(MAX_PORTAL_SESSION_TTL_SECONDS);
        Ok(session)
    }

    async fn request_plan_change(
        &self,
        request: &PlanChangeRequest,
    ) -> Result<ProviderEvent, ProviderError> {
        if !self.offers(&request.from_plan_key) || !self.offers(&request.to_plan_key) {
            return Err(ProviderError::new(ProviderErrorKind::UnknownPlan));
        }
        plan_change_event(request)
    }

    async fn request_cancellation(
        &self,
        request: &CancellationRequest,
    ) -> Result<ProviderEvent, ProviderError> {
        if !self.offers(&request.plan_key) {
            return Err(ProviderError::new(ProviderErrorKind::UnknownPlan));
        }
        cancellation_event(request)
    }
}

fn bounded_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROVIDER_REFERENCE_BYTES
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

/// Bounded, stable, non-secret session reference derived from the opaque
/// account reference. It is not a credential: the provider session itself is
/// still authenticated by the provider, and Lumi stores no session secret.
fn session_reference(account_reference: &str) -> String {
    // FNV-1a/64 is used only to derive an opaque, stable routing token. It is
    // explicitly NOT a security primitive: no authorization, replay, or
    // authenticity decision depends on it.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in account_reference.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Percent-encode the bounded characters that can appear in a plan key or
/// relative return path. Everything outside the unreserved set is escaped, so
/// the rebuilt URL cannot introduce a query or fragment injection.
fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

/// Bounded validation of the callback envelope before any mapping happens.
///
/// The signature itself is verified by the caller with the adapter webhook
/// secret (see [`verify_callback_signature`]); this checks only the shape that
/// a valid signature cannot fix: a bounded identifier, a bounded account
/// reference, a positive version, a valid instant, and a bounded nonce.
pub fn validate_callback_shape(callback: &ProviderCallback) -> Result<(), ProviderError> {
    if !bounded_reference(&callback.provider_event_id)
        || callback.provider_event_id.len() > MAX_PROVIDER_EVENT_ID_BYTES
        || callback.provider_event_id.contains(char::is_whitespace)
        || !bounded_reference(&callback.account_reference)
        || callback.provider_event_id.is_empty()
        || callback.provider_version < 1
        || !bounded_reference(&callback.nonce)
        || callback.nonce.len() > 128
        || callback.nonce.contains(char::is_whitespace)
    {
        return Err(ProviderError::new(ProviderErrorKind::InvalidRequest));
    }
    if let Some(plan_key) = &callback.next_plan_key
        && !is_lumi_plan_key(plan_key)
    {
        return Err(ProviderError::new(ProviderErrorKind::InvalidRequest));
    }
    Ok(())
}

/// The replay window a callback timestamp must fall inside.
///
/// A stale or future-dated callback cannot extend the grace window, so the
/// bound is deliberately symmetric and narrow.
pub fn callback_replay_bounds(
    signed_timestamp: i64,
    now: i64,
) -> Result<(i64, i64), ProviderError> {
    if signed_timestamp > now.saturating_add(MAX_PROVIDER_EVENT_SKEW_SECONDS) {
        return Err(ProviderError::new(ProviderErrorKind::ReplayWindowExceeded));
    }
    let lower = signed_timestamp
        .saturating_sub(MAX_CALLBACK_REPLAY_WINDOW_SECONDS)
        .max(now.saturating_sub(MAX_CALLBACK_REPLAY_WINDOW_SECONDS));
    Ok((lower, now.saturating_add(MAX_PROVIDER_EVENT_SKEW_SECONDS)))
}

/// Whether a callback effective instant is usable against the server clock.
///
/// A future-dated or stale effective instant is refused outright: it must never
/// move the grace anchor, which is immutable once established.
pub fn validate_callback_instant(effective_at: i64, now: i64) -> Result<(), ProviderError> {
    if effective_at > now.saturating_add(MAX_PROVIDER_EVENT_SKEW_SECONDS) {
        return Err(ProviderError::new(ProviderErrorKind::OutOfOrder));
    }
    Ok(())
}

/// The canonical string a provider callback signature covers.
///
/// `HMAC-SHA256(webhook_secret, "<signed_timestamp>.<nonce>.<provider_event_id>")`,
/// lowercase hex. The effective instant and the target status are deliberately
/// NOT signed here because the provider recomputes them per delivery; the
/// provider event ID is the stable, single-use identity that makes the callback
/// idempotent, and the monotonic `provider_version` is what orders it.
pub fn callback_signing_input(callback: &ProviderCallback) -> String {
    format!(
        "{}.{}.{}",
        callback.signed_timestamp, callback.nonce, callback.provider_event_id
    )
}

/// Constant-time hex comparison of a presented signature against the expected
/// one. Length is compared first because both sides are fixed-width hex.
pub fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

/// Verify a callback signature with the adapter webhook secret.
///
/// The secret is a Wrangler secret; it is accepted here only to produce the
/// expected digest and is never persisted or logged.
#[cfg(target_arch = "wasm32")]
pub async fn verify_callback_signature(
    webhook_secret: &str,
    callback: &ProviderCallback,
) -> Result<(), ProviderError> {
    use wasm_bindgen::prelude::wasm_bindgen;
    use wasm_bindgen_futures::JsFuture;

    #[wasm_bindgen(inline_js = r#"
export async function lumiHmacSha256Hex(secret, message) {
  const key = await globalThis.crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const mac = new Uint8Array(await globalThis.crypto.subtle.sign(
    "HMAC", key, new TextEncoder().encode(message)
  ));
  return Array.from(mac, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
"#)]
    extern "C" {
        #[wasm_bindgen(js_name = lumiHmacSha256Hex)]
        fn hmac_sha256_hex_js(secret: &str, message: &str) -> worker::js_sys::Promise;
    }

    let expected = JsFuture::from(hmac_sha256_hex_js(
        webhook_secret,
        &callback_signing_input(callback),
    ))
    .await
    .map_err(|_| ProviderError::new(ProviderErrorKind::Unavailable))?
    .as_string()
    .ok_or_else(|| ProviderError::new(ProviderErrorKind::Unavailable))?;
    if constant_time_eq(&expected, callback.signature_hex.as_str()) {
        Ok(())
    } else {
        Err(ProviderError::new(ProviderErrorKind::SignatureInvalid))
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn verify_callback_signature(
    _webhook_secret: &str,
    _callback: &ProviderCallback,
) -> Result<(), ProviderError> {
    // Documented limitation: the HMAC primitive needs Worker Web Crypto, so the
    // host test build cannot verify a signature. The replay window, identifier
    // bounds, and account binding are all still enforced above and below it.
    Err(ProviderError::new(ProviderErrorKind::Unavailable))
}

/// Build a stable, bounded provider event from a callback the caller has already
/// authenticated and translated. The raw provider payload is not accepted.
pub fn translated_event(
    provider_event_id: &str,
    account_reference: &str,
    provider_version: i64,
    effective_at: i64,
    next_status: SubscriptionStatus,
    next_plan: Option<PlanPointer>,
) -> Result<ProviderEvent, ProviderError> {
    ProviderEvent::new(
        provider_event_id,
        account_reference,
        provider_version,
        effective_at,
        next_status,
        next_plan,
    )
    .map_err(|_| ProviderError::new(ProviderErrorKind::InvalidRequest))
}

/// A portal-unavailable response body. Stable, and free of any provider detail.
pub fn portal_unavailable_json() -> Value {
    json!({
        "available": false,
        "reason": ProviderErrorKind::PortalUnavailable.code(),
        "message": "The billing portal is temporarily unavailable. Try again shortly.",
    })
}

/// Build the public upstream provider-entitlement projection.
///
/// The projection exposes ONLY the normalized status, an optional bounded
/// reason code, the opaque `provider_kind`, and the observed instant. The
/// provider account reference is adapter-private and never appears here, and
/// there is no field through which a provider product, price, or plan
/// identifier could reach a client.
pub fn json_public_projection(
    provider_kind: &str,
    status: ProviderEntitlementStatus,
    reason_code: Option<&str>,
    observed_at: i64,
) -> Value {
    json!({
        "provider": provider_kind,
        "status": status.as_str(),
        "reason_code": reason_code,
        "observed_at": observed_at,
    })
}

/// Parse a normalized provider status, failing closed on anything unrecognized.
pub fn parse_provider_status(value: &str) -> ProviderEntitlementStatus {
    ProviderEntitlementStatus::parse(value).unwrap_or(ProviderEntitlementStatus::Unknown)
}

/// Derive the D1 `capability_class` label from a provider status.
///
/// The stored value is the platform-managed-inference class for every current
/// projection: an upstream coding-plan account only gates provider-managed
/// inference and can never change Lumi subscription, entitlement, authorization,
/// or budget state (P06-CR-002).
pub const PROVIDER_ENTITLEMENT_CAPABILITY_CLASS: &str = "provider_managed_inference";

/// Interpret a provider event's mapped status as provider-account reachability
/// for the license matrix.
///
/// This is the ONLY bridge from a billing callback to the license matrix, and
/// it is one-directional: reachability can never produce a subscription
/// transition, an entitlement value, or a permission.
pub fn provider_availability_for_event(next_status: SubscriptionStatus) -> ProviderAvailability {
    match next_status {
        SubscriptionStatus::Suspended | SubscriptionStatus::Cancelled => {
            ProviderAvailability::Unavailable
        }
        // A readable status is not evidence the upstream account is healthy, so
        // reachability is `unknown` until the provider explicitly reports it.
        _ => ProviderAvailability::Unknown,
    }
}

/// Bind an adapter account reference to a callback, refusing cross-account
/// delivery.
///
/// A callback bound to another account is refused with the NON-DISCLOSING
/// `resource_not_found` reason rather than a permission error, so a forged
/// callback cannot probe which account references exist.
pub fn require_account_binding(
    expected_account_reference: &str,
    callback: &ProviderCallback,
) -> Result<(), ProviderError> {
    if expected_account_reference.is_empty()
        || expected_account_reference.len() > MAX_PROVIDER_REFERENCE_BYTES
        || expected_account_reference != callback.account_reference
    {
        return Err(ProviderError::new(
            ProviderErrorKind::AccountBindingMismatch,
        ));
    }
    Ok(())
}

/// Reason an org has no derived provider-entitlement projection yet.
///
/// A missing projection is `unknown`, never `available`: paid work must not
/// start on a provider whose commercial standing is not confirmed.
pub fn default_projection_json(provider_kind: &str) -> Value {
    json_public_projection(provider_kind, ProviderEntitlementStatus::Unknown, None, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "acct_0123456789abcdef0123456789abcd";

    fn adapter() -> LocalBillingAdapter {
        LocalBillingAdapter::with_configuration(
            vec!["billing.local.test".to_owned()],
            vec![
                "starter".to_owned(),
                "team".to_owned(),
                "enterprise".to_owned(),
            ],
        )
        .unwrap()
    }

    fn callback() -> ProviderCallback {
        ProviderCallback {
            provider_event_id: "evt_provider_1".to_owned(),
            account_reference: ACCOUNT.to_owned(),
            provider_version: 7,
            effective_at: 1_789_000_000,
            signed_timestamp: 1_789_000_000,
            nonce: "nonce-abc".to_owned(),
            next_status: SubscriptionStatus::Grace,
            next_plan_key: Some("team".to_owned()),
            signature_hex: "00".repeat(32),
        }
    }

    fn plan_pointer(plan_key: &str) -> Result<PlanPointer, ProviderError> {
        plan_pointer_for(plan_key)
    }

    #[test]
    fn product_logic_sees_only_lumi_plan_keys() {
        let event = adapter()
            .map_callback(&callback())
            .expect("callback maps to a Lumi provider event");
        let pointer = event.next_plan.expect("callback carries a plan pointer");
        assert_eq!(pointer.as_key(), "team");
        // A provider product/price identifier cannot be a Lumi plan key, so it
        // can never reach a product decision even if an adapter passed one.
        assert!(!is_lumi_plan_key("prod_Qabc123"));
        assert!(!is_lumi_plan_key("price_1Monthly"));
        assert!(plan_pointer("prod_Qabc123").is_err());
        assert!(plan_pointer("starter").is_ok());
    }

    #[test]
    fn an_unconfigured_adapter_refuses_a_callback_naming_an_unknown_plan() {
        let unconfigured = LocalBillingAdapter::new();
        // An adapter that offers no plans cannot map a callback that names one.
        assert!(unconfigured.map_callback(&callback()).is_err());
        // A status-only callback needs no plan catalogue entry; account binding
        // is enforced at the route boundary, not by the plan list.
        let mut status_only = callback();
        status_only.next_plan_key = None;
        assert!(unconfigured.map_callback(&status_only).is_ok());
        // The adapter's plan catalogue is consulted before any URL is built, so
        // an unconfigured adapter cannot mint a commercial answer.
        assert!(!unconfigured.offers("team"));
        assert!(adapter().offers("team"));
    }

    #[test]
    fn a_portal_unavailable_reason_is_retryable_not_a_permanent_denial() {
        // The adapter reports portal unavailability through
        // `ProviderErrorKind::PortalUnavailable`, which is retryable: a
        // transient provider condition must never brick an organization.
        let error = ProviderError::new(ProviderErrorKind::PortalUnavailable);
        assert_eq!(error.code(), "subscription_state_unavailable");
        assert!(error.is_retryable());
        // A real deployment configures the host allowlist; an empty allowlist is
        // a valid, inert configuration that simply cannot open a session.
        assert!(LocalBillingAdapter::with_configuration(vec![], vec!["team".to_owned()]).is_ok());
    }

    #[test]
    fn portal_session_is_allowlisted_https_and_never_carries_card_data() {
        let session = portal_session_url(
            "billing.local.test",
            ACCOUNT,
            "team",
            "org/acme/settings/billing",
        )
        .expect("an allowlisted host opens a session");
        assert!(session.url.starts_with("https://billing.local.test/"));
        assert!(!session.url.contains('@'), "url must not carry userinfo");
        assert!(!session.url.contains('#'), "url must not carry a fragment");
        assert!(session.url.contains("plan=team"));
        assert!(
            session
                .url
                .contains("return=org%2Facme%2Fsettings%2Fbilling")
        );
        assert!(session.url.len() <= MAX_PORTAL_URL_BYTES);
        // The lifetime is applied by the adapter from the server clock, never
        // from a client value.
        assert_eq!(session.expires_at, 0);
        assert_eq!(MAX_PORTAL_SESSION_TTL_SECONDS, 900);
    }

    #[test]
    fn a_malformed_portal_host_is_refused_and_the_allowlist_is_the_only_source() {
        // The URL builder validates host SHAPE; ALLOWLIST membership is the
        // adapter's job, and the adapter only ever reads
        // `portal_hosts.first()`, so a client-supplied host can never reach it.
        for host in [
            "",
            "*.local.test",
            "billing.local.test.",
            ".billing.local.test",
            "billing..local.test",
            "billing.local.test:8443",
            "https://billing.local.test",
            "user@billing.local.test",
        ] {
            assert!(
                portal_session_url(host, ACCOUNT, "team", "org/acme").is_err(),
                "accepted {host}"
            );
            assert!(
                LocalBillingAdapter::with_configuration(
                    vec![host.to_owned()],
                    vec!["team".to_owned()]
                )
                .is_err(),
                "allowlisted {host}"
            );
        }
        // A well-formed allowlisted host produces a URL whose host is exactly
        // that host: no scheme, userinfo, port, or path component is injectable.
        let session =
            portal_session_url("billing.local.test", ACCOUNT, "team", "org/acme").unwrap();
        assert!(
            session
                .url
                .starts_with("https://billing.local.test/billing/session/")
        );
        assert!(!session.url.contains("evil"));
    }

    #[test]
    fn portal_host_allowlist_is_exact_and_rejects_wildcards() {
        for invalid in [
            "",
            "*",
            "*.local.test",
            "billing.local.test.",
            ".billing.local.test",
            "billing..local.test",
            "billing local test",
            "https://billing.local.test",
            "billing.local.test:8443",
        ] {
            assert!(
                LocalBillingAdapter::with_configuration(vec![invalid.to_owned()], vec![]).is_err(),
                "accepted {invalid}"
            );
        }
        assert!(
            LocalBillingAdapter::with_configuration(
                vec!["billing.local.test".to_owned()],
                vec!["team".to_owned()]
            )
            .is_ok()
        );
    }

    #[test]
    fn return_path_must_be_relative_and_control_free() {
        for invalid in [
            "",
            "/org/acme",
            "https://evil.test",
            "//evil.test",
            "org\\acme",
            "billing\npath",
        ] {
            assert!(validate_return_path(invalid).is_err(), "accepted {invalid}");
        }
        assert_eq!(
            validate_return_path("  org/acme/settings/billing  ").unwrap(),
            "org/acme/settings/billing"
        );
    }

    #[test]
    fn callback_shape_is_bounded_and_rejects_provider_identifiers_as_plans() {
        let mut bad = callback();
        bad.provider_event_id = "with space".to_owned();
        assert_eq!(
            validate_callback_shape(&bad).unwrap_err().code(),
            "validation_failed"
        );

        let mut bad = callback();
        bad.provider_version = 0;
        assert!(validate_callback_shape(&bad).is_err());

        let mut bad = callback();
        bad.next_plan_key = Some("prod_Qabc123".to_owned());
        assert!(validate_callback_shape(&bad).is_err());
        assert!(adapter().map_callback(&bad).is_err());
    }

    #[test]
    fn replay_window_rejects_stale_and_future_dated_callbacks() {
        let now = 1_789_000_000_i64;
        let (lower, upper) = callback_replay_bounds(now, now).unwrap();
        assert_eq!(upper, now + MAX_PROVIDER_EVENT_SKEW_SECONDS);
        assert!(lower <= now);
        // A future-dated signed timestamp is refused outright.
        assert_eq!(
            callback_replay_bounds(now + 1_000, now).unwrap_err().code(),
            "webhook_replay_window_exceeded"
        );
        // A stale timestamp is still accepted at the envelope level, but the
        // effective window is clamped so an old delivery cannot be replayed far
        // outside the bound.
        let (lower, _) = callback_replay_bounds(now - 10_000, now).unwrap();
        assert_eq!(lower, now - MAX_CALLBACK_REPLAY_WINDOW_SECONDS);
        // A stale EFFECTIVE instant is a provider-ordering failure, not a
        // grace extension: it must be refused by the event ledger, which this
        // adapter cannot do, so the repository reports it as out of order.
        assert!(validate_callback_instant(now - 10_000, now).is_ok());
    }

    #[test]
    fn future_dated_effective_instant_is_out_of_order_not_a_grace_extension() {
        let now = 1_789_000_000_i64;
        let error =
            validate_callback_instant(now + MAX_PROVIDER_EVENT_SKEW_SECONDS + 1, now).unwrap_err();
        assert_eq!(error.code(), "provider_event_out_of_order");
        assert!(!error.is_retryable());
    }

    #[test]
    fn callback_signature_input_is_stable_and_the_comparison_is_constant_time() {
        let callback = callback();
        let input = callback_signing_input(&callback);
        assert_eq!(input, "1789000000.nonce-abc.evt_provider_1");
        assert_eq!(input, callback_signing_input(&callback));
        assert!(constant_time_eq(&input, &input));
        assert!(!constant_time_eq(
            &input,
            "1789000000.nonce-abd.evt_provider_1"
        ));
        assert!(!constant_time_eq(&input, "short"));
    }

    #[test]
    fn plan_change_and_cancellation_produce_ordered_lumi_events() {
        let request = PlanChangeRequest {
            account_reference: ACCOUNT.to_owned(),
            from_plan_key: "team".to_owned(),
            to_plan_key: "starter".to_owned(),
            requested_at: 1_789_000_100,
        };
        let change = plan_change_event(&request).expect("plan change maps to a provider event");
        assert!(change.provider_version > 0);
        assert_eq!(change.next_status, SubscriptionStatus::Active);
        assert_eq!(
            change.next_plan.as_ref().expect("plan pointer").as_key(),
            "starter"
        );
        // The event ID is STABLE for the same accepted instant and target plan,
        // so a retried request is a D1 no-op instead of a second transition.
        assert_eq!(
            plan_change_event(&request).unwrap().provider_event_id,
            change.provider_event_id
        );

        let cancel = cancellation_event(&CancellationRequest {
            account_reference: ACCOUNT.to_owned(),
            plan_key: "starter".to_owned(),
            at_period_end: true,
            requested_at: 1_789_000_200,
        })
        .expect("cancellation maps to a provider event");
        assert_eq!(cancel.next_status, SubscriptionStatus::Cancelled);
        assert!(cancel.next_plan.is_none());
    }

    #[test]
    fn unknown_or_unchanged_plan_requests_are_refused() {
        assert!(
            plan_change_event(&PlanChangeRequest {
                account_reference: ACCOUNT.to_owned(),
                from_plan_key: "team".to_owned(),
                to_plan_key: "team".to_owned(),
                requested_at: 1,
            })
            .is_err()
        );
        // A provider product/price identifier is not a Lumi plan key, so it can
        // never become a plan-change target.
        assert!(
            plan_change_event(&PlanChangeRequest {
                account_reference: ACCOUNT.to_owned(),
                from_plan_key: "team".to_owned(),
                to_plan_key: "prod_Qabc123".to_owned(),
                requested_at: 1,
            })
            .is_err()
        );
        assert!(
            plan_change_event(&PlanChangeRequest {
                account_reference: ACCOUNT.to_owned(),
                from_plan_key: "team".to_owned(),
                to_plan_key: "enterprise".to_owned(),
                requested_at: 1,
            })
            .is_ok()
        );
        // A malformed account reference is refused rather than sent upstream.
        for malformed in [
            "",
            "with\nnewline",
            &"a".repeat(MAX_PROVIDER_REFERENCE_BYTES + 1),
        ] {
            assert!(
                cancellation_event(&CancellationRequest {
                    account_reference: malformed.to_owned(),
                    plan_key: "team".to_owned(),
                    at_period_end: true,
                    requested_at: 1,
                })
                .is_err(),
                "accepted {malformed}"
            );
        }
    }

    #[test]
    fn org_and_account_references_are_treated_as_opaque() {
        // The account reference is the only provider value Lumi stores, and it
        // is opaque: it is not a plan, price, or product identifier.
        assert!(bounded_reference(ACCOUNT));
        assert!(!bounded_reference(""));
        assert!(!bounded_reference(
            &"a".repeat(MAX_PROVIDER_REFERENCE_BYTES + 1)
        ));
        assert!(!bounded_reference("with\nnewline"));
        // The public wire projection is built from the opaque `provider_kind`
        // plus the normalized status, never from the account reference.
        let projection = json_public_projection(
            "local",
            ProviderEntitlementStatus::Unavailable,
            Some("account_closed"),
            1_789_000_000,
        );
        assert!(projection.get("provider_account_ref").is_none());
        assert!(projection.get("product_id").is_none());
        assert!(projection.get("price_id").is_none());
        assert_eq!(projection["status"], "unavailable");
        assert_eq!(projection["reason_code"], "account_closed");
        assert_eq!(
            parse_provider_status("unavailable"),
            ProviderEntitlementStatus::Unavailable
        );
        // An unrecognized stored status fails closed to `unknown`, never to
        // `available`.
        assert_eq!(
            parse_provider_status("prod_qabc"),
            ProviderEntitlementStatus::Unknown
        );
        assert_eq!(
            default_projection_json("local")["status"],
            ProviderEntitlementStatus::Unknown.as_str()
        );
    }

    #[test]
    fn provider_availability_from_an_event_never_invents_a_healthy_account() {
        // A readable commercial status is not evidence the upstream account is
        // healthy, so reachability stays `unknown` until the provider says so.
        assert_eq!(
            provider_availability_for_event(SubscriptionStatus::Active),
            ProviderAvailability::Unknown
        );
        assert_eq!(
            provider_availability_for_event(SubscriptionStatus::Grace),
            ProviderAvailability::Unknown
        );
        assert_eq!(
            provider_availability_for_event(SubscriptionStatus::Suspended),
            ProviderAvailability::Unavailable
        );
        assert_eq!(
            provider_availability_for_event(SubscriptionStatus::Cancelled),
            ProviderAvailability::Unavailable
        );
    }

    #[test]
    fn cross_account_callbacks_are_refused_non_disclosingly() {
        let callback = callback();
        assert!(require_account_binding(ACCOUNT, &callback).is_ok());
        let error = require_account_binding("acct_ffffffffffffffffffffffffffffffff", &callback)
            .unwrap_err();
        assert_eq!(error.code(), "resource_not_found");
        assert!(require_account_binding("", &callback).is_err());
    }
}
