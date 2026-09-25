//! P06 outbound webhook delivery boundary.
//!
//! [`outbound`] owns everything that leaves the Worker: SSRF-safe endpoint
//! validation, the frozen signature contract, and the bounded HTTP transport.
//! [`delivery`] owns the retry/dead-letter policy, the terminal-failure
//! auto-disable threshold, and the durable email adapter used for
//! `notification.deliver`.
//!
//! No module here formats a stored request body, a response body, a secret, or
//! a URL query string into a diagnostic. `Debug` implementations for the
//! request-bearing types are redacted on purpose.

pub mod delivery;
pub mod outbound;

pub use delivery::{
    AUTO_DISABLED_REASON, CANCELLED_REASON, DeliveryAction, DeliveryPolicy, EmailTransport,
    EmailTransportError, MAX_NOTIFICATION_BODY_CHARS, MAX_NOTIFICATION_SUBJECT_CHARS,
    NotificationMessage, WorkerEmailTransport, should_auto_disable,
};
pub use outbound::{
    CloudflareDnsResolver, DnsResolver, MAX_RESPONSE_BYTES, OutboundRequest, OutboundResponse,
    RetryAfter, SIGNATURE_VERSION, SsrfRejection, StaticDnsResolver, TransportOutcome, body_hash,
    secret_fingerprint, sha256_hex, signature_header, signing_payload, validate_endpoint_url,
};
