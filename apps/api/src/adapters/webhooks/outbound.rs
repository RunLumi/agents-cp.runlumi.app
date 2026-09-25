//! Signed HTTPS webhook transport for P06.
//!
//! The frozen P06-CG contract is implemented here and nowhere else:
//!
//! * `X-Lumi-Event-Id`, `X-Lumi-Timestamp`, `X-Lumi-Signature-Key-Id`, and
//!   `X-Lumi-Signature: v1=<lowercase hex HMAC-SHA256(secret, timestamp + "." +
//!   event_id + "." + raw_body)>`.
//! * Only `2xx` is success. Network failures, timeouts, `408`, `425`, `429`,
//!   and `5xx` are retryable; other `4xx` are terminal.
//! * Redirects are disabled, the connect/read timeout is 10 seconds, response
//!   bodies above 64 KiB are discarded and never logged, and `Retry-After` is
//!   honored only when bounded to 24 hours.
//! * HTTPS only, no userinfo, ports 443/8443 only, and loopback, link-local,
//!   private, CGNAT, and cloud-metadata destinations are rejected. DNS is
//!   resolved and re-validated immediately before every connection.
//!
//! The signature is computed by a self-contained HMAC-SHA256 implementation so
//! the frozen `p06-contracts-v1.json` vector can be reproduced by `cargo test`
//! on the host target. Web Crypto is only available inside the Worker, which
//! would leave the frozen vector unverified by CI.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use wasm_bindgen::JsValue;
use worker::{Fetch, Headers, Method, Request, RequestInit, RequestRedirect};

use crate::core::Timestamp;

/// Signature scheme version frozen by P06-CG.
pub const SIGNATURE_VERSION: &str = "v1";

/// Header carrying the stable P01 event identifier.
pub const HEADER_EVENT_ID: &str = "x-lumi-event-id";
/// Header carrying the signing instant in unix seconds.
pub const HEADER_TIMESTAMP: &str = "x-lumi-timestamp";
/// Header carrying the `whs_`-prefixed key version used for the signature.
pub const HEADER_SIGNATURE_KEY_ID: &str = "x-lumi-signature-key-id";
/// Header carrying the versioned lowercase-hex signature.
pub const HEADER_SIGNATURE: &str = "x-lumi-signature";

/// Connect/read budget for one delivery attempt.
pub const DELIVERY_TIMEOUT_MS: u32 = 10_000;
/// Response bodies larger than this are discarded without being read further.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// `Retry-After` is honored only below this bound.
pub const MAX_RETRY_AFTER_SECONDS: u32 = 86_400;
/// Only these ports are accepted for an endpoint URL.
pub const ALLOWED_PORTS: [u16; 2] = [443, 8443];

/// Stable, gate-defined rejection reasons for endpoint validation and
/// transport classification. Every variant maps to a frozen P06 error code so
/// a client never sees a raw platform or provider string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SsrfRejection {
    /// The URL could not be parsed or violates a hard structural bound.
    EndpointInvalid,
    /// The scheme is not `https`.
    HttpsRequired,
    /// Userinfo, a disallowed port, or a blocked destination range.
    UrlBlocked,
    /// A redirect was requested or observed. Redirects are always disabled.
    RedirectBlocked,
    /// The response body exceeded [`MAX_RESPONSE_BYTES`] and was discarded.
    ResponseTooLarge,
    /// DNS could not be resolved, so the connection fails closed.
    DnsUnavailable,
    /// The connect/read budget elapsed. A duplicate request is possible.
    Timeout,
}

impl SsrfRejection {
    /// Frozen P06 error code for this rejection.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::EndpointInvalid => "webhook_endpoint_invalid",
            Self::HttpsRequired => "webhook_https_required",
            Self::UrlBlocked => "webhook_url_blocked",
            Self::RedirectBlocked => "webhook_redirect_blocked",
            Self::ResponseTooLarge => "webhook_response_too_large",
            Self::DnsUnavailable => "webhook_unreachable",
            Self::Timeout => "webhook_timeout",
        }
    }

    /// A transport-level rejection is retryable unless repeating it cannot
    /// change the outcome. A permanently blocked destination is terminal.
    pub const fn retryable(self) -> bool {
        matches!(self, Self::DnsUnavailable | Self::Timeout)
    }
}

impl fmt::Display for SsrfRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for SsrfRejection {}

/// A structurally valid, SSRF-checked endpoint target.
///
/// The value is derived only from server-owned configuration or from a request
/// that already passed boundary validation. It intentionally has no `Debug`
/// implementation that would print the path or query string.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedEndpoint {
    url: String,
    host: String,
    port: u16,
    ip_literal: bool,
}

impl ValidatedEndpoint {
    /// Canonical request URL, safe to hand to `fetch`.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Lowercase host with any trailing root label removed.
    pub fn host(&self) -> &str {
        &self.host
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    /// True when the host is an IP literal, in which case DNS is not consulted.
    pub const fn is_ip_literal(&self) -> bool {
        self.ip_literal
    }
}

impl fmt::Debug for ValidatedEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedEndpoint")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("ip_literal", &self.ip_literal)
            .finish()
    }
}

/// Structural, DNS-free endpoint validation.
///
/// Applied at endpoint creation, update, and test time. Delivery time repeats
/// this check and additionally resolves DNS.
pub fn validate_endpoint_url(raw: &str) -> Result<ValidatedEndpoint, SsrfRejection> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 2048 || trimmed.chars().any(char::is_control) {
        return Err(SsrfRejection::EndpointInvalid);
    }
    if trimmed.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(SsrfRejection::EndpointInvalid);
    }

    let parsed = url::Url::parse(trimmed).map_err(|_| SsrfRejection::EndpointInvalid)?;
    if parsed.cannot_be_a_base() {
        return Err(SsrfRejection::EndpointInvalid);
    }
    if parsed.scheme() != "https" {
        return Err(SsrfRejection::HttpsRequired);
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(SsrfRejection::UrlBlocked);
    }
    if parsed.fragment().is_some() {
        return Err(SsrfRejection::UrlBlocked);
    }
    let port = parsed
        .port_or_known_default()
        .filter(|port| ALLOWED_PORTS.contains(port))
        .ok_or(SsrfRejection::UrlBlocked)?;
    let host = parsed
        .host_str()
        .ok_or(SsrfRejection::EndpointInvalid)?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 {
        return Err(SsrfRejection::EndpointInvalid);
    }

    let ip_literal = match host.parse::<IpAddr>() {
        Ok(address) => {
            if is_blocked_address(&address) {
                return Err(SsrfRejection::UrlBlocked);
            }
            true
        }
        Err(_) => {
            if !is_dns_name(&host) || is_reserved_host_name(&host) {
                return Err(SsrfRejection::UrlBlocked);
            }
            false
        }
    };

    let mut url = String::with_capacity(trimmed.len());
    url.push_str("https://");
    if port == 443 {
        url.push_str(&host);
    } else {
        url.push_str(&host);
        url.push(':');
        url.push_str(&port.to_string());
    }
    let path = parsed.path();
    url.push_str(if path.is_empty() { "/" } else { path });
    if let Some(query) = parsed.query() {
        url.push('?');
        url.push_str(query);
    }

    Ok(ValidatedEndpoint {
        url,
        host,
        port,
        ip_literal,
    })
}

/// Reject every address in a resolution result. A single blocked answer fails
/// the whole attempt so a hostname that mixes a public and a private address
/// cannot be used to reach internal infrastructure.
pub fn validate_resolved_addresses(
    endpoint: &ValidatedEndpoint,
    addresses: &[IpAddr],
) -> Result<(), SsrfRejection> {
    if endpoint.is_ip_literal() {
        return Ok(());
    }
    if addresses.is_empty() {
        return Err(SsrfRejection::DnsUnavailable);
    }
    if addresses.iter().any(is_blocked_address) {
        return Err(SsrfRejection::UrlBlocked);
    }
    Ok(())
}

/// True for loopback, unspecified, link-local, private, CGNAT, multicast,
/// documentation, benchmarking, and cloud-metadata destinations.
pub fn is_blocked_address(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => is_blocked_v4(*value),
        IpAddr::V6(value) => is_blocked_v6(*value),
    }
}

fn is_blocked_v4(value: Ipv4Addr) -> bool {
    let [a, b, ..] = value.octets();
    value.is_unspecified()
        || value.is_loopback()
        || value.is_private()
        || value.is_link_local()
        || value.is_multicast()
        || value.is_broadcast()
        || value.is_documentation()
        || (a == 0) // "this network"
        || (a == 100 && (64..=127).contains(&b)) // carrier-grade NAT
        || (a == 192 && b == 0 && value.octets()[2] == 0) // IETF protocol assignments
        || (a == 192 && b == 88 && value.octets()[2] == 99) // 6to4 relay anycast
        || (a == 198 && (b == 18 || b == 19)) // benchmarking
        || (a == 198 && b == 51 && value.octets()[2] == 100) // TEST-NET-2
        || (a == 203 && b == 0 && value.octets()[2] == 113) // TEST-NET-3
        || a >= 240 // reserved, including 255.255.255.255
}

fn is_blocked_v6(value: Ipv6Addr) -> bool {
    if value.is_loopback() || value.is_unspecified() || value.is_multicast() {
        return true;
    }
    let segments = value.segments();
    // Unique-local (fc00::/7) and link-local (fe80::/10).
    if (segments[0] & 0xfe00) == 0xfc00 || (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // IPv4-mapped (::ffff:0:0/96) and IPv4-compatible (::/96): re-check the
    // embedded IPv4 address so a mapped loopback cannot bypass the IPv4 rules.
    if let Some(embedded) = embedded_v4(value) {
        return is_blocked_v4(embedded);
    }
    // Documentation (2001:db8::/32), 6to4 (2002::/16), and Teredo (2001::/32)
    // carry an embedded IPv4 destination or are not globally routable.
    (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || segments[0] == 0x2002
        || segments[0] == 0x2001
}

fn embedded_v4(value: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = value.segments();
    if segments[..5] == [0, 0, 0, 0, 0] && matches!(segments[5], 0 | 0xffff) {
        let octets = value.octets();
        return Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    None
}

fn is_dns_name(host: &str) -> bool {
    !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..")
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// Split-horizon and loopback names are rejected outright: a resolver cannot be
/// trusted to map them to a public address.
fn is_reserved_host_name(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".home.arpa")
        || host.ends_with(".in-addr.arpa")
        || host.ends_with(".onion")
}

/// Build the exact signed string: `timestamp + "." + event_id + "." + body`.
pub fn signing_payload(timestamp_seconds: i64, event_id: &str, body: &str) -> String {
    let mut payload = String::with_capacity(
        timestamp_seconds.unsigned_abs() as usize + event_id.len() + body.len() + 2,
    );
    payload.push_str(&timestamp_seconds.to_string());
    payload.push('.');
    payload.push_str(event_id);
    payload.push('.');
    payload.push_str(body);
    payload
}

/// Produce the frozen `X-Lumi-Signature` header value.
pub fn signature_header(
    secret: &str,
    timestamp_seconds: i64,
    event_id: &str,
    body: &str,
) -> String {
    let message = signing_payload(timestamp_seconds, event_id, body);
    let digest = hmac_sha256(secret.as_bytes(), message.as_bytes());
    let mut value = String::with_capacity(SIGNATURE_VERSION.len() + 1 + 64);
    value.push_str(SIGNATURE_VERSION);
    value.push('=');
    value.push_str(&to_hex(&digest));
    value
}

/// Lowercase hex SHA-256 of arbitrary bytes.
pub fn sha256_hex(message: &[u8]) -> String {
    to_hex(&sha256(message))
}

/// Lowercase hex SHA-256 of the exact stored body bytes. Stored alongside each
/// logical delivery so a later attempt can prove it reused the same bytes.
pub fn body_hash(body: &str) -> String {
    format!("sha256:{}", sha256_hex(body.as_bytes()))
}

/// Non-reversible fingerprint of a webhook secret.
///
/// The `webhook_secrets.fingerprint` column accepts 16–128 characters, so the
/// full 64-character SHA-256 hex digest is used. The plaintext secret is never
/// stored, returned after creation/rotation, or logged, and a SHA-256 digest of
/// a 32-byte CSPRNG value is not recoverable.
pub fn secret_fingerprint(secret: &str) -> String {
    sha256_hex(secret.as_bytes())
}

/// Convert an RFC 3339 UTC instant to unix seconds without a platform clock.
pub fn unix_seconds(value: &Timestamp) -> Result<i64, SsrfRejection> {
    let bytes = value.as_str().as_bytes();
    if bytes.len() < 20 {
        return Err(SsrfRejection::EndpointInvalid);
    }
    let year = read_number(bytes, 0, 4);
    let month = read_number(bytes, 5, 2);
    let day = read_number(bytes, 8, 2);
    let hour = read_number(bytes, 11, 2);
    let minute = read_number(bytes, 14, 2);
    let second = read_number(bytes, 17, 2);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(SsrfRejection::EndpointInvalid);
    }
    let days = days_from_civil(year, month, day);
    Ok(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn read_number(bytes: &[u8], start: usize, width: usize) -> i64 {
    bytes
        .get(start..start + width)
        .map(|slice| {
            slice.iter().fold(0_i64, |value, digit| {
                value * 10 + i64::from(digit.saturating_sub(b'0'))
            })
        })
        .unwrap_or(0)
}

/// Days since 1970-01-01 for a proleptic Gregorian civil date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let shifted = if month <= 2 { year - 1 } else { year };
    let era = if shifted >= 0 { shifted } else { shifted - 399 } / 400;
    let year_of_era = shifted - era * 400;
    let month_position = (month + 9) % 12;
    let day_of_year = (153 * month_position + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Why an attempt is retried or dead-lettered. Every branch maps to a stable
/// code; no raw status text or response body is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportOutcome {
    /// The endpoint answered `2xx`.
    Delivered,
    /// A retryable failure with a stable code.
    Retryable(&'static str),
    /// A terminal failure with a stable code.
    Terminal(&'static str),
}

impl TransportOutcome {
    pub const fn is_delivered(self) -> bool {
        matches!(self, Self::Delivered)
    }
}

/// Classify one HTTP response status.
///
/// `retry_conflict` reflects an explicit endpoint policy classification of
/// `409`/`425`; the frozen `0012` schema has no column for it yet, so the
/// repository always supplies `false` and `409` stays terminal. See the
/// P06-BE-02 handoff for the coordinator change request.
pub const fn classify_status(status: u16, retry_conflict: bool) -> TransportOutcome {
    match status {
        200..=299 => TransportOutcome::Delivered,
        300..=399 => TransportOutcome::Terminal(SsrfRejection::RedirectBlocked.reason()),
        408 => TransportOutcome::Retryable(SsrfRejection::Timeout.reason()),
        409 | 425 => {
            if retry_conflict {
                TransportOutcome::Retryable("webhook_conflict_retryable")
            } else {
                TransportOutcome::Terminal("webhook_endpoint_rejected")
            }
        }
        429 => TransportOutcome::Retryable("webhook_rate_limited"),
        400..=499 => TransportOutcome::Terminal("webhook_endpoint_rejected"),
        500..=599 => TransportOutcome::Retryable("webhook_server_error"),
        _ => TransportOutcome::Terminal("webhook_endpoint_rejected"),
    }
}

/// Why a `Retry-After` header was not honored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryAfter {
    /// A bounded delta-seconds value.
    Delay(u32),
    /// Absent, malformed, HTTP-date form, or above [`MAX_RETRY_AFTER_SECONDS`].
    Rejected,
}

/// Parse a delta-seconds `Retry-After` value. An HTTP-date form is rejected
/// rather than approximated, because the deterministic backoff is a safe
/// substitute and a clock-dependent guess is not.
pub fn parse_retry_after(value: &str) -> RetryAfter {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > 32
        || !trimmed.bytes().all(|byte| byte.is_ascii_digit())
    {
        return RetryAfter::Rejected;
    }
    match trimmed.parse::<u32>() {
        Ok(seconds) if seconds <= MAX_RETRY_AFTER_SECONDS => RetryAfter::Delay(seconds.max(1)),
        _ => RetryAfter::Rejected,
    }
}

/// The exact bytes and signature material for one delivery attempt.
#[derive(Clone, PartialEq, Eq)]
pub struct OutboundRequest {
    pub endpoint: ValidatedEndpoint,
    pub event_id: String,
    pub signature_key_id: String,
    pub signature: String,
    pub timestamp_seconds: i64,
    pub body: String,
}

impl fmt::Debug for OutboundRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundRequest")
            .field("endpoint", &self.endpoint)
            .field("event_id", &self.event_id)
            .field("signature_key_id", &self.signature_key_id)
            .field("signature", &"[redacted]")
            .field("timestamp_seconds", &self.timestamp_seconds)
            .field("body", &"[redacted]")
            .finish()
    }
}

/// The parts of a response the delivery worker is allowed to observe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboundResponse {
    pub status: u16,
    pub retry_after: RetryAfter,
    /// Number of body bytes observed. The bytes themselves are never retained.
    pub response_bytes: usize,
}

/// Resolves a host name immediately before a connection so a name that starts
/// resolving to a blocked address fails closed.
#[allow(async_fn_in_trait)]
pub trait DnsResolver {
    /// Return every A and AAAA answer for `host`.
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, SsrfRejection>;
}

/// DNS-over-HTTPS resolver used by the production delivery path.
///
/// The Workers `fetch` API cannot pin a connection to a validated address, so
/// the pre-resolution is defense in depth on top of the platform's own refusal
/// to connect to internal destinations. A resolution failure is reported, not
/// silently ignored, and the attempt fails closed.
pub struct CloudflareDnsResolver;

#[allow(async_fn_in_trait)]
impl DnsResolver for CloudflareDnsResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, SsrfRejection> {
        if !is_dns_name(host) {
            return Err(SsrfRejection::EndpointInvalid);
        }
        let mut addresses = Vec::new();
        for record_type in ["A", "AAAA"] {
            match resolve_record(host, record_type).await {
                Ok(found) => addresses.extend(found),
                Err(_) => return Err(SsrfRejection::DnsUnavailable),
            }
        }
        Ok(addresses)
    }
}

async fn resolve_record(host: &str, record_type: &str) -> Result<Vec<IpAddr>, SsrfRejection> {
    let mut url = String::with_capacity(host.len() + 96);
    url.push_str("https://cloudflare-dns.com/dns-query?name=");
    url.push_str(host);
    url.push_str("&type=");
    url.push_str(record_type);
    let headers = Headers::new();
    headers
        .set("accept", "application/dns-json")
        .map_err(|_| SsrfRejection::DnsUnavailable)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    init.with_redirect(RequestRedirect::Error);
    init.with_headers(headers);
    let mut response = Fetch::Request(
        Request::new_with_init(&url, &init).map_err(|_| SsrfRejection::DnsUnavailable)?,
    )
    .send()
    .await
    .map_err(|_| SsrfRejection::DnsUnavailable)?;
    if !(200..300).contains(&response.status_code()) {
        return Err(SsrfRejection::DnsUnavailable);
    }
    let body = response
        .text()
        .await
        .map_err(|_| SsrfRejection::DnsUnavailable)?;
    if body.len() > 64 * 1024 {
        return Err(SsrfRejection::DnsUnavailable);
    }
    parse_dns_json(&body)
}

/// Minimal parser for the `application/dns-json` answer shape. Unknown record
/// types are ignored; an unsuccessful resolver status is an error.
fn parse_dns_json(body: &str) -> Result<Vec<IpAddr>, SsrfRejection> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|_| SsrfRejection::DnsUnavailable)?;
    if value.get("Status").and_then(serde_json::Value::as_i64) != Some(0) {
        return Err(SsrfRejection::DnsUnavailable);
    }
    let Some(answers) = value.get("Answer").and_then(serde_json::Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut addresses = Vec::new();
    for answer in answers {
        let Some(record) = answer.get("type").and_then(serde_json::Value::as_i64) else {
            continue;
        };
        if record != 1 && record != 28 {
            continue;
        }
        let Some(data) = answer.get("data").and_then(serde_json::Value::as_str) else {
            continue;
        };
        // AAAA answers may carry a scope suffix; only the address is relevant.
        let literal = data.split_whitespace().next().unwrap_or_default();
        if let Ok(address) = literal.parse::<IpAddr>() {
            addresses.push(address);
        }
    }
    Ok(addresses)
}

/// Explicit test adapter. It is the only way a local fixture endpoint can be
/// reached, and no production route constructs it.
pub struct StaticDnsResolver {
    entries: Vec<(String, Vec<IpAddr>)>,
}

impl StaticDnsResolver {
    pub fn new(entries: Vec<(String, Vec<IpAddr>)>) -> Self {
        Self { entries }
    }
}

#[allow(async_fn_in_trait)]
impl DnsResolver for StaticDnsResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, SsrfRejection> {
        self.entries
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(host))
            .map(|(_, addresses)| addresses.clone())
            .ok_or(SsrfRejection::DnsUnavailable)
    }
}

/// Re-resolve and re-validate the endpoint immediately before connecting.
pub async fn resolve_endpoint<R: DnsResolver + ?Sized>(
    endpoint: &ValidatedEndpoint,
    resolver: &R,
) -> Result<(), SsrfRejection> {
    if endpoint.is_ip_literal() {
        return Ok(());
    }
    let addresses = resolver.resolve(&endpoint.host).await?;
    validate_resolved_addresses(endpoint, &addresses)
}

/// Perform one signed HTTPS POST of the exact stored body.
///
/// The body is never re-serialized: it is the byte sequence persisted with the
/// logical delivery, so the signature stays verifiable across attempts.
pub async fn post_signed<R: DnsResolver + ?Sized>(
    request: &OutboundRequest,
    resolver: &R,
) -> Result<OutboundResponse, SsrfRejection> {
    resolve_endpoint(&request.endpoint, resolver).await?;

    let headers = Headers::new();
    headers
        .set("content-type", "application/json")
        .and_then(|_| headers.set("accept", "application/json"))
        .and_then(|_| headers.set(HEADER_EVENT_ID, &request.event_id))
        .and_then(|_| headers.set(HEADER_TIMESTAMP, &request.timestamp_seconds.to_string()))
        .and_then(|_| headers.set(HEADER_SIGNATURE_KEY_ID, &request.signature_key_id))
        .and_then(|_| headers.set(HEADER_SIGNATURE, &request.signature))
        .map_err(|_| SsrfRejection::EndpointInvalid)?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_redirect(RequestRedirect::Error);
    init.with_headers(headers);
    init.with_body(Some(JsValue::from_str(&request.body)));

    let signal = timeout_signal(DELIVERY_TIMEOUT_MS);
    let response = match Fetch::Request(
        Request::new_with_init(request.endpoint.url(), &init)
            .map_err(|_| SsrfRejection::EndpointInvalid)?,
    )
    .send_with_signal(&signal)
    .await
    {
        Ok(response) => response,
        Err(_) if signal.aborted() => return Err(SsrfRejection::Timeout),
        Err(_) => return Err(SsrfRejection::DnsUnavailable),
    };

    let status = response.status_code();
    let retry_after = response
        .headers()
        .get("retry-after")
        .ok()
        .flatten()
        .map_or(RetryAfter::Rejected, |value| parse_retry_after(&value));
    let response_bytes = read_bounded_body(response).await?;
    Ok(OutboundResponse {
        status,
        retry_after,
        response_bytes,
    })
}

/// Read at most [`MAX_RESPONSE_BYTES`] bytes purely to enforce the cap. The
/// bytes are dropped immediately and are never stored, returned, or logged.
async fn read_bounded_body(mut response: worker::Response) -> Result<usize, SsrfRejection> {
    if let Some(declared) = response
        .headers()
        .get("content-length")
        .ok()
        .flatten()
        .and_then(|value| value.parse::<usize>().ok())
        && declared > MAX_RESPONSE_BYTES
    {
        return Err(SsrfRejection::ResponseTooLarge);
    }
    use futures_util::StreamExt as _;

    let mut stream = response
        .stream()
        .map_err(|_| SsrfRejection::DnsUnavailable)?
        .boxed_local();
    let mut observed = 0_usize;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| SsrfRejection::DnsUnavailable)?;
        observed = observed.saturating_add(chunk.len());
        if observed > MAX_RESPONSE_BYTES {
            return Err(SsrfRejection::ResponseTooLarge);
        }
    }
    Ok(observed)
}

fn timeout_signal(timeout_ms: u32) -> worker::AbortSignal {
    use wasm_bindgen::prelude::wasm_bindgen;

    #[wasm_bindgen(inline_js = r#"
export function lumiWebhookTimeoutSignal(timeoutMs) {
  return AbortSignal.timeout(timeoutMs);
}
"#)]
    extern "C" {
        #[wasm_bindgen(js_name = lumiWebhookTimeoutSignal)]
        fn signal_js(timeout_ms: u32) -> worker::web_sys::AbortSignal;
    }
    worker::AbortSignal::from(signal_js(timeout_ms))
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
        hex.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    hex
}

// -----------------------------------------------------------------------------
// SHA-256 / HMAC-SHA256
// -----------------------------------------------------------------------------

const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const SHA256_INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const SHA256_BLOCK_BYTES: usize = 64;
const SHA256_DIGEST_BYTES: usize = 32;

/// FIPS 180-4 SHA-256.
pub fn sha256(message: &[u8]) -> [u8; SHA256_DIGEST_BYTES] {
    let mut state = SHA256_INITIAL_STATE;
    let mut block = [0_u8; SHA256_BLOCK_BYTES];
    let mut offset = 0_usize;
    while offset + SHA256_BLOCK_BYTES <= message.len() {
        block.copy_from_slice(&message[offset..offset + SHA256_BLOCK_BYTES]);
        sha256_compress(&mut state, &block);
        offset += SHA256_BLOCK_BYTES;
    }

    let remainder = &message[offset..];
    block = [0_u8; SHA256_BLOCK_BYTES];
    block[..remainder.len()].copy_from_slice(remainder);
    block[remainder.len()] = 0x80;
    if remainder.len() + 1 + 8 > SHA256_BLOCK_BYTES {
        sha256_compress(&mut state, &block);
        block = [0_u8; SHA256_BLOCK_BYTES];
    }
    block[SHA256_BLOCK_BYTES - 8..].copy_from_slice(&((message.len() as u64) * 8).to_be_bytes());
    sha256_compress(&mut state, &block);

    let mut digest = [0_u8; SHA256_DIGEST_BYTES];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// RFC 2104 HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; SHA256_DIGEST_BYTES] {
    let mut block = [0_u8; SHA256_BLOCK_BYTES];
    if key.len() > SHA256_BLOCK_BYTES {
        block[..SHA256_DIGEST_BYTES].copy_from_slice(&sha256(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36_u8; SHA256_BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; SHA256_BLOCK_BYTES];
    for index in 0..SHA256_BLOCK_BYTES {
        inner_pad[index] ^= block[index];
        outer_pad[index] ^= block[index];
    }

    let mut inner = Vec::with_capacity(SHA256_BLOCK_BYTES + message.len());
    inner.extend_from_slice(&inner_pad);
    inner.extend_from_slice(message);
    let inner_digest = sha256(&inner);

    let mut outer = [0_u8; SHA256_BLOCK_BYTES + SHA256_DIGEST_BYTES];
    outer[..SHA256_BLOCK_BYTES].copy_from_slice(&outer_pad);
    outer[SHA256_BLOCK_BYTES..].copy_from_slice(&inner_digest);
    sha256(&outer)
}

fn sha256_compress(state: &mut [u32; 8], block: &[u8; SHA256_BLOCK_BYTES]) {
    let mut schedule = [0_u32; 64];
    for (index, word) in schedule.iter_mut().take(16).enumerate() {
        let start = index * 4;
        *word = u32::from_be_bytes([
            block[start],
            block[start + 1],
            block[start + 2],
            block[start + 3],
        ]);
    }
    for index in 16..64 {
        let s0 = schedule[index - 15].rotate_right(7)
            ^ schedule[index - 15].rotate_right(18)
            ^ (schedule[index - 15] >> 3);
        let s1 = schedule[index - 2].rotate_right(17)
            ^ schedule[index - 2].rotate_right(19)
            ^ (schedule[index - 2] >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(s0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for index in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choose = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(choose)
            .wrapping_add(SHA256_ROUND_CONSTANTS[index])
            .wrapping_add(schedule[index]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(majority);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_BODY: &str = concat!(
        r#"{"event_id":"evt_0123456789abcdef0123456789abcdef","#,
        r#""event_type":"automation.occurrence.completed.v1","#,
        r#""occurred_at":"2026-09-25T16:00:00.000Z","#,
        r#""request_id":"req_0123456789abcdef0123456789abcdef","#,
        r#""correlation_id":"req_0123456789abcdef0123456789abcdef","#,
        r#""actor":{"type":"system","id":null,"effective_user_id":null},"#,
        r#""organization_id":"org_0123456789abcdef0123456789abcdef","#,
        r#""payload":{"schema_version":1,"subject_type":"automation_occurrence","#,
        r#""subject_id":"occ_0123456789abcdef0123456789abcdef","#,
        r#""resource_version":4,"state":"succeeded","reason_code":null}}"#,
    );

    #[test]
    fn sha256_matches_fips_180_4_vectors() {
        assert_eq!(
            to_hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            to_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            to_hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_vectors() {
        assert_eq!(
            to_hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            to_hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn signature_reproduces_the_frozen_p06_fixture_vector() {
        // docs/implementation/fixtures/p06-contracts-v1.json -> webhook.
        assert_eq!(
            signature_header(
                "p06-fixture-key-v1",
                1_780_000_000,
                "evt_0123456789abcdef0123456789abcdef",
                FIXTURE_BODY,
            ),
            "v1=f7473e66f227a440883404278c7759d12c8fcceb609831dc9735a7c1ecae9341"
        );
    }

    #[test]
    fn signing_payload_is_timestamp_dot_event_dot_body() {
        assert_eq!(
            signing_payload(1_780_000_000, "evt_1", "{}"),
            "1780000000.evt_1.{}"
        );
    }

    #[test]
    fn body_hash_is_sha256_over_the_exact_stored_bytes() {
        assert_eq!(
            body_hash(FIXTURE_BODY),
            format!("sha256:{}", sha256_hex(FIXTURE_BODY.as_bytes()))
        );
        assert!(body_hash(FIXTURE_BODY).starts_with("sha256:"));
        assert_eq!(body_hash(FIXTURE_BODY).len(), 71);
    }

    #[test]
    fn secret_fingerprint_is_a_bounded_non_reversible_digest() {
        let fingerprint = secret_fingerprint("p06-fixture-key-v1");
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!fingerprint.contains("p06-fixture-key-v1"));
        assert_eq!(fingerprint, secret_fingerprint("p06-fixture-key-v1"));
        assert_ne!(fingerprint, secret_fingerprint("another-secret"));
    }

    #[test]
    fn unix_seconds_converts_rfc3339_utc_without_a_platform_clock() {
        let occurred_at: Timestamp = "2026-09-25T16:00:00.000Z".parse().unwrap();
        assert_eq!(unix_seconds(&occurred_at).unwrap(), 1_790_352_000);
        let epoch: Timestamp = "1970-01-01T00:00:00.000Z".parse().unwrap();
        assert_eq!(unix_seconds(&epoch).unwrap(), 0);
        let pre_epoch: Timestamp = "1969-12-31T23:59:59.000Z".parse().unwrap();
        assert_eq!(unix_seconds(&pre_epoch).unwrap(), -1);
        // The frozen fixture signing instant is a fixed vector constant, not the
        // body's `occurred_at`; it must convert to itself.
        let fixture: Timestamp = "2026-05-28T20:26:40.000Z".parse().unwrap();
        assert_eq!(unix_seconds(&fixture).unwrap(), 1_780_000_000);
        let second_precision: Timestamp = "2026-05-28T20:26:40Z".parse().unwrap();
        assert_eq!(unix_seconds(&second_precision).unwrap(), 1_780_000_000);
    }

    #[test]
    fn endpoint_validation_requires_https_443_or_8443_and_no_userinfo() {
        assert!(validate_endpoint_url("https://hooks.example.com/events").is_ok());
        assert!(validate_endpoint_url("https://hooks.example.com:8443/events").is_ok());
        assert_eq!(
            validate_endpoint_url("http://hooks.example.com/events").unwrap_err(),
            SsrfRejection::HttpsRequired
        );
        assert_eq!(
            validate_endpoint_url("https://user:pass@hooks.example.com/").unwrap_err(),
            SsrfRejection::UrlBlocked
        );
        assert_eq!(
            validate_endpoint_url("https://hooks.example.com:8080/").unwrap_err(),
            SsrfRejection::UrlBlocked
        );
        assert_eq!(
            validate_endpoint_url("https://hooks.example.com/#fragment").unwrap_err(),
            SsrfRejection::UrlBlocked
        );
        assert_eq!(
            validate_endpoint_url("not a url").unwrap_err(),
            SsrfRejection::EndpointInvalid
        );
        assert_eq!(
            validate_endpoint_url("https://127.0.0.1/hook").unwrap_err(),
            SsrfRejection::UrlBlocked
        );
        assert_eq!(
            validate_endpoint_url("https://[::1]/hook").unwrap_err(),
            SsrfRejection::UrlBlocked
        );
    }

    #[test]
    fn private_link_local_cgnat_and_metadata_ranges_are_blocked() {
        for literal in [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.4.4",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata (AWS/Azure/GCP)
            "100.64.0.1",      // carrier-grade NAT
            "0.0.0.0",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            let address: IpAddr = literal.parse().unwrap();
            assert!(is_blocked_address(&address), "allowed {literal}");
        }
        for literal in [
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd00::1",
            "ff02::1",
            "2001:db8::1",
        ] {
            let address: IpAddr = literal.parse().unwrap();
            assert!(is_blocked_address(&address), "allowed {literal}");
        }
        // An IPv4-mapped loopback must not bypass the IPv4 rules.
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_blocked_address(&mapped));
        // Public addresses stay usable.
        for literal in ["1.1.1.1", "8.8.8.8", "2606:4700::1111"] {
            let address: IpAddr = literal.parse().unwrap();
            assert!(!is_blocked_address(&address), "blocked {literal}");
        }
    }

    #[test]
    fn reserved_host_names_are_rejected_before_dns() {
        for value in [
            "https://localhost/hook",
            "https://api.localhost/hook",
            "https://db.internal/hook",
            "https://printer.local/hook",
        ] {
            assert_eq!(
                validate_endpoint_url(value).unwrap_err(),
                SsrfRejection::UrlBlocked,
                "accepted {value}"
            );
        }
    }

    #[test]
    fn a_hostname_that_changes_to_a_blocked_address_fails_closed() {
        let endpoint = validate_endpoint_url("https://hooks.example.com/events").unwrap();
        let clean = vec!["93.184.216.34".parse::<IpAddr>().unwrap()];
        assert!(validate_resolved_addresses(&endpoint, &clean).is_ok());
        // Resolution returns nothing: fail closed rather than connect blindly.
        assert_eq!(
            validate_resolved_addresses(&endpoint, &[]).unwrap_err(),
            SsrfRejection::DnsUnavailable
        );
        // A single poisoned answer rejects the whole resolution.
        let poisoned = vec![
            "93.184.216.34".parse::<IpAddr>().unwrap(),
            "169.254.169.254".parse::<IpAddr>().unwrap(),
        ];
        assert_eq!(
            validate_resolved_addresses(&endpoint, &poisoned).unwrap_err(),
            SsrfRejection::UrlBlocked
        );
    }

    #[test]
    fn status_classification_matches_the_frozen_retry_semantics() {
        assert_eq!(classify_status(200, false), TransportOutcome::Delivered);
        assert_eq!(classify_status(204, false), TransportOutcome::Delivered);
        assert_eq!(
            classify_status(301, false),
            TransportOutcome::Terminal("webhook_redirect_blocked")
        );
        assert_eq!(
            classify_status(400, false),
            TransportOutcome::Terminal("webhook_endpoint_rejected")
        );
        assert_eq!(
            classify_status(404, false),
            TransportOutcome::Terminal("webhook_endpoint_rejected")
        );
        assert_eq!(
            classify_status(408, false),
            TransportOutcome::Retryable("webhook_timeout")
        );
        assert_eq!(
            classify_status(409, false),
            TransportOutcome::Terminal("webhook_endpoint_rejected")
        );
        assert_eq!(
            classify_status(409, true),
            TransportOutcome::Retryable("webhook_conflict_retryable")
        );
        assert_eq!(
            classify_status(425, false),
            TransportOutcome::Terminal("webhook_endpoint_rejected")
        );
        assert_eq!(
            classify_status(425, true),
            TransportOutcome::Retryable("webhook_conflict_retryable")
        );
        assert_eq!(
            classify_status(429, false),
            TransportOutcome::Retryable("webhook_rate_limited")
        );
        assert_eq!(
            classify_status(500, false),
            TransportOutcome::Retryable("webhook_server_error")
        );
        assert_eq!(
            classify_status(503, false),
            TransportOutcome::Retryable("webhook_server_error")
        );
    }

    #[test]
    fn retry_after_is_honored_only_below_24_hours() {
        assert_eq!(parse_retry_after("0"), RetryAfter::Delay(1));
        assert_eq!(parse_retry_after("120"), RetryAfter::Delay(120));
        assert_eq!(parse_retry_after("86400"), RetryAfter::Delay(86_400));
        assert_eq!(parse_retry_after("86401"), RetryAfter::Rejected);
        assert_eq!(parse_retry_after("9999999999"), RetryAfter::Rejected);
        assert_eq!(
            parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT"),
            RetryAfter::Rejected
        );
        assert_eq!(parse_retry_after("-5"), RetryAfter::Rejected);
        assert_eq!(parse_retry_after(""), RetryAfter::Rejected);
    }

    #[test]
    fn dns_json_parser_ignores_non_address_answers() {
        let payload = r#"{"Status":0,"Answer":[
            {"name":"hooks.example.com","type":5,"TTL":300,"data":"hooks.example.com"},
            {"name":"hooks.example.com","type":1,"TTL":300,"data":"93.184.216.34"},
            {"name":"hooks.example.com","type":28,"TTL":300,"data":"2606:2800:220:1:248:1893:25c8:1946"}
        ]}"#;
        let addresses = parse_dns_json(payload).unwrap();
        assert_eq!(addresses.len(), 2);
        assert!(!addresses.iter().any(is_blocked_address));
        assert_eq!(
            parse_dns_json(r#"{"Status":3}"#).unwrap_err(),
            SsrfRejection::DnsUnavailable
        );
        assert_eq!(
            parse_dns_json("not json").unwrap_err(),
            SsrfRejection::DnsUnavailable
        );
    }

    #[test]
    fn outbound_request_debug_never_prints_the_body_or_signature() {
        let request = OutboundRequest {
            endpoint: validate_endpoint_url("https://hooks.example.com/events").unwrap(),
            event_id: "evt_0123456789abcdef0123456789abcdef".to_owned(),
            signature_key_id: "whs_0123456789abcdef0123456789abcdef".to_owned(),
            signature: "v1=deadbeef".to_owned(),
            timestamp_seconds: 1_780_000_000,
            body: "{\"secret\":\"must not be logged\"}".to_owned(),
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains("must not be logged"));
        assert!(!debug.contains("deadbeef"));
        assert!(debug.contains("[redacted]"));
    }
}
