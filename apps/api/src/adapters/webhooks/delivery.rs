//! Retry, dead-letter, and notification-delivery policy for P06.
//!
//! The bounded backoff itself is the frozen P01 `modules::outbox::RetryPolicy`
//! (deterministic ±20% jitter derived from the stable event ID), so webhook
//! deliveries and business events share one tested delay function instead of a
//! second copy of it. What lives here is the P06-specific policy read from an
//! endpoint row, the terminal-failure auto-disable threshold, and the durable
//! email adapter.
//!
//! `adapters::email::deliver_auth_code` is deliberately NOT reused. That helper
//! is request-bound: it no-ops in development, it takes a raw auth code, and it
//! reports failure by returning `Err` to a request handler. Durable
//! notifications must survive a provider outage, retry through the jobs queue,
//! and never roll back the business mutation that produced them, so they need
//! their own small adapter behind [`EmailTransport`].

use std::fmt;

use worker::SendEmail;

use super::outbound::{RetryAfter, TransportOutcome};
use crate::{
    core::EventId,
    modules::outbox::{FailureDisposition, RetryPolicy},
};

/// P06-CG bounds: 1–8 attempts, 30-second base, 24-hour maximum, 20% jitter.
pub const MIN_ATTEMPTS: u32 = 1;
pub const MAX_ATTEMPTS: u32 = 8;
pub const DEFAULT_ATTEMPTS: u32 = 8;
pub const DEFAULT_BASE_DELAY_SECONDS: u32 = 30;
pub const DEFAULT_MAX_DELAY_SECONDS: u32 = 86_400;
pub const MIN_AUTO_DISABLE_THRESHOLD: i64 = 10;
pub const JITTER_PERCENT: u8 = 20;

/// Bounded, per-endpoint delivery policy read from `webhook_endpoints`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryPolicy {
    pub max_attempts: u32,
    pub base_delay_seconds: u32,
    pub max_delay_seconds: u32,
    pub replay_window_seconds: u32,
    pub auto_disable_enabled: bool,
    pub auto_disable_threshold: i64,
    /// Whether `409`/`425` are classified retryable for this endpoint. The
    /// frozen `0012` schema has no column for it, so the repository always
    /// supplies `false` and those statuses stay terminal.
    pub retry_conflict: bool,
}

impl Default for DeliveryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_ATTEMPTS,
            base_delay_seconds: DEFAULT_BASE_DELAY_SECONDS,
            max_delay_seconds: DEFAULT_MAX_DELAY_SECONDS,
            replay_window_seconds: 300,
            auto_disable_enabled: false,
            auto_disable_threshold: MIN_AUTO_DISABLE_THRESHOLD,
            retry_conflict: false,
        }
    }
}

impl DeliveryPolicy {
    /// Reject any row that drifts outside the frozen bounds instead of clamping
    /// it, so a corrupted endpoint cannot silently change delivery behavior.
    pub const fn is_valid(self) -> bool {
        self.max_attempts >= MIN_ATTEMPTS
            && self.max_attempts <= MAX_ATTEMPTS
            && self.base_delay_seconds >= 1
            && self.base_delay_seconds <= 3_600
            && self.max_delay_seconds >= 1
            && self.max_delay_seconds <= 86_400
            && self.max_delay_seconds >= self.base_delay_seconds
            && self.replay_window_seconds >= 30
            && self.replay_window_seconds <= 3_600
            && self.auto_disable_threshold >= MIN_AUTO_DISABLE_THRESHOLD
    }

    /// Project the endpoint policy onto the shared deterministic backoff.
    pub const fn retry_policy(self) -> Option<RetryPolicy> {
        RetryPolicy::new(
            self.max_attempts,
            self.base_delay_seconds,
            self.max_delay_seconds,
            JITTER_PERCENT,
        )
    }
}

/// Build a policy from a persisted endpoint row, or `None` when the row drifts
/// outside the frozen bounds.
pub const fn policy_from_row(
    max_attempts: i64,
    base_delay_seconds: i64,
    max_delay_seconds: i64,
    replay_window_seconds: i64,
    auto_disable_enabled: bool,
    auto_disable_threshold: i64,
) -> Option<DeliveryPolicy> {
    if max_attempts < 0
        || base_delay_seconds < 0
        || max_delay_seconds < 0
        || replay_window_seconds < 0
    {
        return None;
    }
    let policy = DeliveryPolicy {
        max_attempts: max_attempts as u32,
        base_delay_seconds: base_delay_seconds as u32,
        max_delay_seconds: max_delay_seconds as u32,
        replay_window_seconds: replay_window_seconds as u32,
        auto_disable_enabled,
        auto_disable_threshold,
        retry_conflict: false,
    };
    if policy.is_valid() {
        Some(policy)
    } else {
        None
    }
}

/// What the worker must do after one completed attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryAction {
    /// `2xx`: the logical delivery is complete.
    Delivered,
    /// Schedule the next attempt on the same logical delivery and event ID.
    Retry {
        delay_seconds: u32,
        error_code: &'static str,
    },
    /// Attempts are exhausted, or the failure was terminal.
    DeadLetter { error_code: &'static str },
}

impl DeliveryAction {
    pub const fn error_code(self) -> Option<&'static str> {
        match self {
            Self::Delivered => None,
            Self::Retry { error_code, .. } | Self::DeadLetter { error_code } => Some(error_code),
        }
    }

    pub const fn delay_seconds(self) -> Option<u32> {
        match self {
            Self::Retry { delay_seconds, .. } => Some(delay_seconds),
            _ => None,
        }
    }
}

/// Decide the durable transition for one attempt.
///
/// `completed_attempts` is the one-based number of attempts already recorded on
/// the logical delivery, so `1` means the first attempt just failed. The event
/// ID is the stable P01 identifier and is what makes the jitter deterministic
/// across queue redeliveries.
pub fn decide(
    policy: DeliveryPolicy,
    event_id: &EventId,
    completed_attempts: u32,
    outcome: TransportOutcome,
    retry_after: RetryAfter,
) -> DeliveryAction {
    match outcome {
        TransportOutcome::Delivered => DeliveryAction::Delivered,
        TransportOutcome::Terminal(code) => DeliveryAction::DeadLetter { error_code: code },
        TransportOutcome::Retryable(code) => {
            let disposition = match policy.retry_policy() {
                Some(retry) => retry.after_failure(completed_attempts, event_id),
                None => FailureDisposition::DeadLetter,
            };
            match disposition {
                FailureDisposition::Retry { delay_seconds } => {
                    // A bounded `Retry-After` wins over the deterministic backoff.
                    // An unbounded or malformed value falls back to it, and the
                    // attempt records the stable reason instead of the status.
                    let honored = matches!(retry_after, RetryAfter::Delay(_));
                    DeliveryAction::Retry {
                        delay_seconds: match retry_after {
                            RetryAfter::Delay(seconds) => {
                                seconds.min(policy.max_delay_seconds).max(1)
                            }
                            RetryAfter::Rejected => delay_seconds,
                        },
                        error_code: if honored || !is_rate_limited(code) {
                            code
                        } else {
                            "webhook_retry_after_invalid"
                        },
                    }
                }
                FailureDisposition::DeadLetter => DeliveryAction::DeadLetter { error_code: code },
            }
        }
    }
}

fn is_rate_limited(code: &'static str) -> bool {
    matches!(
        code,
        "webhook_rate_limited" | "webhook_server_error" | "webhook_conflict_retryable"
    )
}

/// Optional auto-disable. Disabled by default and, when enabled, requires at
/// least ten consecutive terminal failures.
pub const fn should_auto_disable(
    policy: DeliveryPolicy,
    consecutive_terminal_failures: i64,
) -> bool {
    policy.auto_disable_enabled && consecutive_terminal_failures >= policy.auto_disable_threshold
}

/// Stable code recorded when an endpoint crosses the auto-disable threshold.
pub const AUTO_DISABLED_REASON: &str = "webhook_endpoint_auto_disabled";
/// Stable code recorded when a delivery is cancelled because its endpoint was
/// disabled.
pub const CANCELLED_REASON: &str = "webhook_delivery_cancelled";
/// Stable code recorded when an endpoint is disabled while deliveries remain.
pub const ENDPOINT_DISABLED_REASON: &str = "webhook_endpoint_disabled";

// -----------------------------------------------------------------------------
// Notification email transport
// -----------------------------------------------------------------------------

/// Maximum accepted subject length for a durable notification.
pub const MAX_NOTIFICATION_SUBJECT_CHARS: usize = 120;
/// Maximum accepted body length for a durable notification.
pub const MAX_NOTIFICATION_BODY_CHARS: usize = 2_000;

/// A bounded, metadata-only notification message. It is built from the durable
/// `notifications` projection; a prompt, response, tool argument, credential,
/// or webhook secret can never reach it.
#[derive(Clone, PartialEq, Eq)]
pub struct NotificationMessage {
    pub recipient: String,
    pub subject: String,
    pub body: String,
}

impl fmt::Debug for NotificationMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotificationMessage")
            .field("recipient", &"[redacted]")
            .field("subject", &self.subject)
            .field("body", &"[redacted]")
            .finish()
    }
}

/// Why an email could not be handed to the provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmailTransportError {
    /// The binding or sender is not configured, or the provider refused the
    /// message. The delivery becomes retryable and the business mutation that
    /// produced the notification stays committed.
    ProviderUnavailable,
    /// The message is not deliverable. This is terminal: retrying cannot fix it.
    Rejected,
}

impl EmailTransportError {
    /// Stable P06 notification error code.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::ProviderUnavailable => "notification_provider_unavailable",
            Self::Rejected => "notification_recipient_invalid",
        }
    }

    pub const fn retryable(self) -> bool {
        matches!(self, Self::ProviderUnavailable)
    }
}

/// Durable notification email boundary. An unavailable provider is a
/// retryable delivery state, never a rolled-back business mutation.
#[allow(async_fn_in_trait)]
pub trait EmailTransport {
    async fn send(&self, message: &NotificationMessage) -> Result<(), EmailTransportError>;
}

/// Cloudflare Email Sending adapter for durable notifications.
///
/// Development intentionally reports the provider as unavailable instead of
/// silently succeeding, so a local vertical journey observes the same retryable
/// state a production outage produces.
pub struct WorkerEmailTransport {
    binding: Option<SendEmail>,
    from: Option<String>,
    environment: String,
}

impl WorkerEmailTransport {
    pub const fn new(
        binding: Option<SendEmail>,
        from: Option<String>,
        environment: String,
    ) -> Self {
        Self {
            binding,
            from,
            environment,
        }
    }
}

#[allow(async_fn_in_trait)]
impl EmailTransport for WorkerEmailTransport {
    async fn send(&self, message: &NotificationMessage) -> Result<(), EmailTransportError> {
        if self.environment == "development" {
            return Err(EmailTransportError::ProviderUnavailable);
        }
        if message.recipient.is_empty() || message.recipient.len() > 254 {
            return Err(EmailTransportError::Rejected);
        }
        if message.subject.is_empty()
            || message.subject.chars().count() > MAX_NOTIFICATION_SUBJECT_CHARS
            || message.body.is_empty()
            || message.body.chars().count() > MAX_NOTIFICATION_BODY_CHARS
        {
            return Err(EmailTransportError::Rejected);
        }
        let from = self
            .from
            .as_deref()
            .ok_or(EmailTransportError::ProviderUnavailable)?;
        let binding = self
            .binding
            .as_ref()
            .ok_or(EmailTransportError::ProviderUnavailable)?;
        let raw = format!(
            "From: {from}\r\nTo: {}\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{}",
            message.recipient, message.subject, message.body
        );
        let email = worker::EmailMessage::new(from, &message.recipient, &raw)
            .map_err(|_| EmailTransportError::Rejected)?;
        binding
            .send(&email)
            .await
            .map(|_| ())
            .map_err(|_| EmailTransportError::ProviderUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> DeliveryPolicy {
        DeliveryPolicy::default()
    }

    fn event_id() -> EventId {
        "evt_0123456789abcdef0123456789abcdef".parse().unwrap()
    }

    #[test]
    fn default_policy_matches_the_frozen_delivery_contract() {
        let policy = policy();
        assert!(policy.is_valid());
        assert_eq!(policy.max_attempts, 8);
        assert_eq!(policy.base_delay_seconds, 30);
        assert_eq!(policy.max_delay_seconds, 86_400);
        assert!(!policy.auto_disable_enabled);
        assert!(policy.retry_policy().is_some());
    }

    #[test]
    fn out_of_range_rows_are_rejected_instead_of_clamped() {
        assert!(
            !DeliveryPolicy {
                max_attempts: 9,
                ..policy()
            }
            .is_valid()
        );
        assert!(
            !DeliveryPolicy {
                max_attempts: 0,
                ..policy()
            }
            .is_valid()
        );
        assert!(
            !DeliveryPolicy {
                max_attempts: 3,
                base_delay_seconds: 60,
                max_delay_seconds: 30,
                ..policy()
            }
            .is_valid()
        );
        assert!(
            !DeliveryPolicy {
                auto_disable_threshold: 9,
                ..policy()
            }
            .is_valid()
        );
        assert!(
            DeliveryPolicy {
                max_attempts: 1,
                ..policy()
            }
            .is_valid()
        );
    }

    #[test]
    fn success_never_schedules_another_attempt() {
        assert_eq!(
            decide(
                policy(),
                &event_id(),
                1,
                TransportOutcome::Delivered,
                RetryAfter::Rejected
            ),
            DeliveryAction::Delivered
        );
    }

    #[test]
    fn retryable_failures_walk_the_deterministic_backoff_then_dead_letter() {
        let event = event_id();
        let mut previous: Option<u32> = None;
        for attempt in 1..=7_u32 {
            let action = decide(
                policy(),
                &event,
                attempt,
                TransportOutcome::Retryable("webhook_server_error"),
                RetryAfter::Rejected,
            );
            let delay = action.delay_seconds().expect("a retry carries a delay");
            assert!(delay >= 1);
            assert!(previous.is_none_or(|value| delay >= value));
            previous = Some(delay);
        }
        assert_eq!(
            decide(
                policy(),
                &event,
                8,
                TransportOutcome::Retryable("webhook_server_error"),
                RetryAfter::Rejected
            ),
            DeliveryAction::DeadLetter {
                error_code: "webhook_server_error"
            }
        );
        // A one-attempt endpoint dead-letters on the first failure.
        let strict = DeliveryPolicy {
            max_attempts: 1,
            ..policy()
        };
        assert_eq!(
            decide(
                strict,
                &event,
                1,
                TransportOutcome::Retryable("webhook_timeout"),
                RetryAfter::Rejected
            ),
            DeliveryAction::DeadLetter {
                error_code: "webhook_timeout"
            }
        );
    }

    #[test]
    fn bounded_retry_after_wins_and_unbounded_values_fall_back() {
        let event = event_id();
        let deterministic = decide(
            policy(),
            &event,
            1,
            TransportOutcome::Retryable("webhook_server_error"),
            RetryAfter::Rejected,
        );
        assert_eq!(
            decide(
                policy(),
                &event,
                1,
                TransportOutcome::Retryable("webhook_rate_limited"),
                RetryAfter::Delay(600)
            ),
            DeliveryAction::Retry {
                delay_seconds: 600,
                error_code: "webhook_rate_limited"
            }
        );
        // An out-of-bounds header is ignored and recorded as a stable reason.
        assert_eq!(
            decide(
                policy(),
                &event,
                1,
                TransportOutcome::Retryable("webhook_rate_limited"),
                RetryAfter::Rejected
            ),
            DeliveryAction::Retry {
                delay_seconds: deterministic.delay_seconds().expect("a delay"),
                error_code: "webhook_retry_after_invalid"
            }
        );
        // A bounded value is clamped to the endpoint's maximum delay.
        assert_eq!(
            decide(
                DeliveryPolicy {
                    max_delay_seconds: 120,
                    ..policy()
                },
                &event,
                1,
                TransportOutcome::Retryable("webhook_rate_limited"),
                RetryAfter::Delay(600)
            )
            .delay_seconds(),
            Some(120)
        );
    }

    #[test]
    fn terminal_failures_dead_letter_without_another_attempt() {
        let action = decide(
            policy(),
            &event_id(),
            1,
            TransportOutcome::Terminal("webhook_endpoint_rejected"),
            RetryAfter::Rejected,
        );
        assert_eq!(
            action,
            DeliveryAction::DeadLetter {
                error_code: "webhook_endpoint_rejected"
            }
        );
        assert_eq!(action.error_code(), Some("webhook_endpoint_rejected"));
    }

    #[test]
    fn auto_disable_is_opt_in_and_requires_ten_consecutive_terminal_failures() {
        assert!(!should_auto_disable(policy(), 1_000));
        let on = DeliveryPolicy {
            auto_disable_enabled: true,
            ..policy()
        };
        assert!(!should_auto_disable(on, 9));
        assert!(should_auto_disable(on, 10));
        let custom = DeliveryPolicy {
            auto_disable_enabled: true,
            auto_disable_threshold: 25,
            ..policy()
        };
        assert!(!should_auto_disable(custom, 24));
        assert!(should_auto_disable(custom, 25));
    }

    #[test]
    fn policy_from_row_rejects_a_persisted_out_of_range_row() {
        assert!(
            policy_from_row(8, 30, 86_400, 300, false, 10).is_some(),
            "the frozen default row must be accepted"
        );
        assert!(policy_from_row(8, 30, 86_400, 300, false, 3).is_none());
        assert!(policy_from_row(0, 30, 86_400, 300, false, 10).is_none());
        assert!(policy_from_row(8, 30, 86_400, 10, false, 10).is_none());
    }

    #[test]
    fn notification_message_debug_hides_the_recipient_and_body() {
        let message = NotificationMessage {
            recipient: "person@example.com".to_owned(),
            subject: "Security alert".to_owned(),
            body: "sensitive narrative".to_owned(),
        };
        let debug = format!("{message:?}");
        assert!(!debug.contains("person@example.com"));
        assert!(!debug.contains("sensitive narrative"));
    }

    #[test]
    fn email_transport_errors_map_to_stable_retry_semantics() {
        assert!(EmailTransportError::ProviderUnavailable.retryable());
        assert!(!EmailTransportError::Rejected.retryable());
        assert_eq!(
            EmailTransportError::ProviderUnavailable.reason(),
            "notification_provider_unavailable"
        );
    }
}
