use crate::core::EventId;

use super::{DeliveryStatus, FailureCode, FailureDisposition, OutboxRecord, RetryPolicy};

#[test]
fn delivery_status_terminal_states_are_explicit() {
    assert!(!DeliveryStatus::Pending.is_terminal());
    assert!(!DeliveryStatus::Queued.is_terminal());
    assert!(DeliveryStatus::Delivered.is_terminal());
    assert!(DeliveryStatus::DeadLetter.is_terminal());
}

#[test]
fn retry_policy_is_bounded_jittered_and_finite() {
    let policy = RetryPolicy::new(5, 10, 90, 20).unwrap();
    let event_id: EventId = "evt_0123456789abcdef0123456789abcdef".parse().unwrap();

    let first = policy.after_failure(1, &event_id);
    let second = policy.after_failure(2, &event_id);
    assert!(matches!(
        first,
        FailureDisposition::Retry {
            delay_seconds: 8..=12
        }
    ));
    assert!(matches!(
        second,
        FailureDisposition::Retry {
            delay_seconds: 16..=24
        }
    ));
    assert_eq!(
        policy.after_failure(5, &event_id),
        FailureDisposition::DeadLetter
    );
    assert_eq!(
        policy.after_failure(0, &event_id),
        FailureDisposition::DeadLetter
    );
    assert_eq!(policy.after_failure(2, &event_id), second);
    assert!(matches!(
        policy.after_failure(4, &event_id),
        FailureDisposition::Retry {
            delay_seconds: 64..=90
        }
    ));
}

#[test]
fn retry_policy_rejects_unbounded_or_invalid_configuration() {
    assert!(RetryPolicy::new(0, 1, 1, 0).is_none());
    assert!(RetryPolicy::new(3, 0, 10, 0).is_none());
    assert!(RetryPolicy::new(3, 10, 9, 0).is_none());
    assert!(RetryPolicy::new(3, 10, RetryPolicy::MAX_RETRY_DELAY_SECONDS + 1, 0).is_none());
    assert!(RetryPolicy::new(3, 1, 10, 101).is_none());
}

#[test]
fn failure_codes_are_bounded_and_machine_readable() {
    assert_eq!(
        FailureCode::new("queue_publish_failed").unwrap().as_str(),
        "queue_publish_failed"
    );
    assert!(FailureCode::new("Authorization: Bearer abc").is_err());
    assert!(FailureCode::new("x".repeat(FailureCode::MAX_BYTES + 1)).is_err());
}

#[test]
fn outbox_record_debug_relies_on_redacted_event_debug() {
    let event_id: EventId = "evt_0123456789abcdef0123456789abcdef".parse().unwrap();
    let code = FailureCode::new("queue_publish_failed").unwrap();
    let record = OutboxRecord {
        event: crate::core::EventEnvelope {
            event_id,
            event_type: "foundation.check.requested.v1".parse().unwrap(),
            occurred_at: "2026-09-24T12:00:00.000Z".parse().unwrap(),
            request_id: "req_0123456789abcdef0123456789abcdef".parse().unwrap(),
            correlation_id: "req_0123456789abcdef0123456789abcdef".parse().unwrap(),
            actor: crate::core::ActorContext::anonymous(),
            organization_id: None,
            payload: serde_json::json!({ "private": "must never appear" }),
        },
        delivery_status: DeliveryStatus::Pending,
        attempt_count: 1,
        next_attempt_at: Some("2026-09-24T12:00:10.000Z".parse().unwrap()),
        queued_at: None,
        delivered_at: None,
        last_error_code: Some(code),
    };
    let debug = format!("{record:?}");
    assert!(debug.contains("event_id"));
    assert!(!debug.contains("must never appear"));
}
