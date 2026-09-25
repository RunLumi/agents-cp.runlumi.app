use serde_json::json;

use crate::modules::runs::*;

fn id(prefix: &str, value: u8) -> String {
    format!("{prefix}_{value:032x}")
}

fn timestamp() -> &'static str {
    "2026-09-25T12:00:00.000Z"
}

fn session() -> Session {
    Session {
        id: id("rse", 1),
        org_id: id("org", 1),
        project_id: id("prj", 1),
        device_id: id("dvc", 1),
        workspace_binding_id: Some(id("wsb", 1)),
        agent_definition_id: id("agd", 1),
        agent_definition_version: 1,
        external_id: Some("zcode-session-1".to_owned()),
        title: Some("Fix issue 1".to_owned()),
        lifecycle: SessionState::Active,
        version: 1,
        created_at: timestamp().to_owned(),
        updated_at: timestamp().to_owned(),
    }
}

fn run(state: RunState) -> Run {
    let finished_at = state.is_terminal().then(|| timestamp().to_owned());
    Run::from_draft(RunDraft {
        id: id("run", 1),
        org_id: id("org", 1),
        project_id: id("prj", 1),
        agent_session_id: id("rse", 1),
        parent_run_id: None,
        attempt: 1,
        agent_definition_id: id("agd", 1),
        agent_definition_version: 1,
        principal_user_id: id("usr", 1),
        device_id: id("dvc", 1),
        model_alias: Some("coding-default".to_owned()),
        route_id: Some(id("rte", 1)),
        route_version_id: Some(id("rtv", 1)),
        state,
        failure_code: state.is_terminal().then(|| "fixture_failure".to_owned()),
        request_id: Some(id("req", 1)),
        started_at: Some(timestamp().to_owned()),
        finished_at,
        version: 1,
        created_at: timestamp().to_owned(),
        updated_at: timestamp().to_owned(),
    })
    .expect("fixture run should be valid")
}

fn event(sequence: i64, event_type: &str) -> RunEvent {
    RunEvent::new(
        id("rev", sequence as u8),
        id("run", 1),
        sequence,
        event_type,
        timestamp(),
        RunEventActorType::System.as_str(),
        None,
        id("req", 1),
        None,
        None,
        json!({ "state": "running" }),
    )
    .expect("fixture event should be valid")
}

#[test]
fn states_round_trip_through_the_frozen_wire_names() {
    assert_eq!(SessionState::Active.as_str(), "active");
    assert_eq!(SessionState::Closed.as_str(), "closed");
    assert_eq!(SessionState::Archived.as_str(), "archived");
    assert_eq!(
        SessionState::parse("archived"),
        Some(SessionState::Archived)
    );
    assert_eq!(RunState::WaitingUser.as_str(), "waiting_user");
    assert_eq!(RunState::WaitingApproval.as_str(), "waiting_approval");
    assert_eq!(RunState::TimedOut.as_str(), "timed_out");
    assert_eq!(
        RunState::parse("waiting_approval"),
        Some(RunState::WaitingApproval)
    );
    assert_eq!(
        serde_json::to_value(RunEventType::RunStateChanged).unwrap(),
        json!("run.state_changed.v1")
    );
    assert_eq!(
        RunEventType::parse("run.state_changed.v1"),
        Some(RunEventType::RunStateChanged)
    );
    assert_eq!(
        serde_json::to_value(RunState::Queued).unwrap(),
        json!("queued")
    );
    assert_eq!(
        serde_json::to_value(SessionState::Archived).unwrap(),
        json!("archived")
    );
    assert!(SessionState::Closed.is_terminal());
    assert!(SessionState::Archived.is_terminal());
    assert!(!SessionState::Active.is_terminal());
    assert!(RunState::Succeeded.is_terminal());
    assert!(RunState::Failed.is_terminal());
    assert!(RunState::Cancelled.is_terminal());
    assert!(RunState::TimedOut.is_terminal());
    assert!(!RunState::WaitingUser.is_terminal());
    let serialized = serde_json::to_value(event(1, "run.created.v1")).unwrap();
    assert_eq!(serialized["id"], json!(id("rev", 1)));
    assert_eq!(serialized["run_id"], json!(id("run", 1)));
    let decoded: RunEvent = serde_json::from_value(serialized).unwrap();
    assert_eq!(decoded.sequence, 1);
}

#[test]
fn session_transitions_are_monotonic_and_terminal() {
    assert!(SessionState::Active.can_transition_to(SessionState::Closed));
    assert!(SessionState::Active.can_transition_to(SessionState::Archived));
    assert!(!SessionState::Active.can_transition_to(SessionState::Active));
    assert_eq!(
        validate_session_transition(SessionState::Closed, SessionState::Archived),
        Err(RunStateError::SessionTerminal)
    );
    assert_eq!(
        validate_session_transition(SessionState::Active, SessionState::Active),
        Err(RunStateError::InvalidSessionTransition)
    );

    let current = session();
    let closed = current.close(1, "2026-09-25T12:00:01.000Z").unwrap();
    assert_eq!(closed.lifecycle, SessionState::Closed);
    assert_eq!(closed.version, 2);
    assert!(closed.close(1, timestamp()).is_err());
    assert!(closed.archive(2, timestamp()).is_err());
    assert!(current.close(2, timestamp()).is_err());
}

#[test]
fn exhaustive_run_transition_table_matches_the_contract() {
    let expected = [
        (
            RunState::Queued,
            [
                RunState::Dispatching,
                RunState::Failed,
                RunState::Cancelled,
                RunState::TimedOut,
            ]
            .as_slice(),
        ),
        (
            RunState::Dispatching,
            [
                RunState::Running,
                RunState::Failed,
                RunState::Cancelled,
                RunState::TimedOut,
            ]
            .as_slice(),
        ),
        (
            RunState::Running,
            [
                RunState::WaitingUser,
                RunState::WaitingApproval,
                RunState::Succeeded,
                RunState::Failed,
                RunState::Cancelled,
                RunState::TimedOut,
            ]
            .as_slice(),
        ),
        (
            RunState::WaitingUser,
            [
                RunState::Running,
                RunState::WaitingApproval,
                RunState::Failed,
                RunState::Cancelled,
                RunState::TimedOut,
            ]
            .as_slice(),
        ),
        (
            RunState::WaitingApproval,
            [
                RunState::Running,
                RunState::Succeeded,
                RunState::Failed,
                RunState::Cancelled,
                RunState::TimedOut,
            ]
            .as_slice(),
        ),
        (RunState::Succeeded, [].as_slice()),
        (RunState::Failed, [].as_slice()),
        (RunState::Cancelled, [].as_slice()),
        (RunState::TimedOut, [].as_slice()),
    ];

    for from in RunState::ALL {
        for to in RunState::ALL {
            let allowed = expected
                .iter()
                .find(|(state, _)| *state == from)
                .is_some_and(|(_, next)| next.contains(&to));
            assert_eq!(
                validate_run_transition(from, to),
                if allowed {
                    Ok(())
                } else if from.is_terminal() {
                    Err(RunStateError::RunTerminal)
                } else {
                    Err(RunStateError::InvalidRunTransition)
                },
                "{from:?} -> {to:?}"
            );
        }
    }

    assert!(RunState::WaitingUser.can_transition_to(RunState::Running));
    assert!(RunState::WaitingApproval.can_transition_to(RunState::Running));
    assert!(!RunState::Queued.can_transition_to(RunState::Running));
    assert!(!RunState::Dispatching.can_transition_to(RunState::WaitingApproval));
}

#[test]
fn run_transition_requires_matching_version_and_terminal_finished_at() {
    let queued = run(RunState::Queued);
    let dispatching = queued
        .transition(RunState::Dispatching, 1, "2026-09-25T12:00:01.000Z", None)
        .unwrap();
    assert_eq!(dispatching.state, RunState::Dispatching);
    assert_eq!(dispatching.version, 2);
    assert!(dispatching.finished_at.is_none());
    assert_eq!(
        queued.state,
        RunState::Queued,
        "input history stays unchanged"
    );

    assert_eq!(
        dispatching.transition(RunState::Running, 1, timestamp(), None),
        Err(RunStateError::VersionConflict)
    );
    assert_eq!(
        dispatching.transition(RunState::Running, 2, timestamp(), Some(timestamp())),
        Err(RunStateError::FinishedAtNotAllowed)
    );
    assert_eq!(
        dispatching.transition(RunState::Failed, 2, timestamp(), None),
        Err(RunStateError::FinishedAtRequired)
    );
    let failed = dispatching
        .transition(RunState::Failed, 2, timestamp(), Some(timestamp()))
        .unwrap();
    assert_eq!(failed.state, RunState::Failed);
    assert_eq!(failed.finished_at.as_deref(), Some(timestamp()));
    assert_eq!(
        failed.transition(RunState::Running, 3, timestamp(), None),
        Err(RunStateError::RunTerminal)
    );
}

#[test]
fn cancellation_is_idempotent_and_does_not_mutate_other_terminal_history() {
    let running = run(RunState::Running);
    let cancelled = running.cancel(1, timestamp(), timestamp()).unwrap();
    assert_eq!(cancelled.state, RunState::Cancelled);
    assert_eq!(cancelled.version, 2);

    // A retry of the same cancel returns the existing terminal result, even
    // when the caller still has the old version from its first request.
    let replay = cancelled
        .cancel(1, "2026-09-25T12:00:02.000Z", timestamp())
        .unwrap();
    assert_eq!(replay, cancelled);
    assert_eq!(replay.version, 2);

    for terminal in [RunState::Succeeded, RunState::Failed, RunState::TimedOut] {
        let historical = run(terminal);
        assert_eq!(
            historical.cancel(1, timestamp(), timestamp()),
            Err(RunStateError::RunTerminal)
        );
    }
    assert_eq!(
        cancel_run_state(RunState::Cancelled),
        Ok(RunState::Cancelled)
    );
    assert_eq!(
        cancel_run_state(RunState::Failed),
        Err(RunStateError::RunTerminal)
    );
}

#[test]
fn retry_creates_a_new_attempt_and_preserves_parent_history() {
    let parent = run(RunState::Failed);
    let parent_before = parent.clone();
    let link = RetryAttempt::from_parent(&parent, id("run", 2)).unwrap();
    assert_eq!(link.parent_run_id, parent.id);
    assert_eq!(link.agent_session_id, parent.agent_session_id);
    assert_eq!(link.attempt, 2);
    validate_retry_parent(&parent, &link).unwrap();

    let retry = retry_run(&parent, id("run", 2), 1, timestamp(), Some(id("req", 2))).unwrap();
    assert_eq!(retry.id, id("run", 2));
    assert_eq!(retry.parent_run_id.as_deref(), Some(parent.id.as_str()));
    assert_eq!(retry.attempt, 2);
    assert_eq!(retry.state, RunState::Queued);
    assert!(retry.failure_code.is_none());
    assert!(retry.finished_at.is_none());
    assert_eq!(parent, parent_before, "retry must not mutate prior history");

    let mut cross_tenant_retry = retry.clone();
    cross_tenant_retry.org_id = id("org", 2);
    assert_eq!(
        validate_retry_scope(&parent, &cross_tenant_retry),
        Err(RunStateError::InvalidRetryLink)
    );

    let mut wrong_session = link.clone();
    wrong_session.agent_session_id = id("rse", 2);
    assert_eq!(
        validate_retry_parent(&parent, &wrong_session),
        Err(RunStateError::InvalidRetryLink)
    );
    let mut wrong_attempt = link.clone();
    wrong_attempt.attempt = 1;
    assert_eq!(
        validate_retry_parent(&parent, &wrong_attempt),
        Err(RunStateError::InvalidRetryLink)
    );
    let mut later_attempt = link.clone();
    later_attempt.attempt = 3;
    assert!(validate_retry_parent(&parent, &later_attempt).is_ok());
    assert_eq!(
        retry_run(&parent, parent.id.clone(), 1, timestamp(), None),
        Err(RunStateError::InvalidRetryLink)
    );
    assert_eq!(
        retry_run(&parent, id("run", 3), 99, timestamp(), None),
        Err(RunStateError::VersionConflict)
    );
    assert_eq!(
        RetryAttempt::from_parent(&run(RunState::Running), id("run", 3)),
        Err(RunStateError::RetryNotAllowed)
    );
    assert_eq!(
        next_retry_attempt(i64::MAX),
        Err(RunStateError::AttemptOverflow)
    );
    assert_eq!(next_retry_attempt(0), Err(RunStateError::InvalidAttempt));
    assert_eq!(next_retry_attempt_from_history(&[1, 4, 2]), Ok(5));
    assert_eq!(
        next_retry_attempt_from_history(&[]),
        Err(RunStateError::InvalidAttempt)
    );
}

#[test]
fn run_event_sequences_are_strictly_increasing_and_bounded() {
    assert_eq!(next_run_event_sequence(0), Ok(1));
    assert_eq!(next_run_event_sequence(4), Ok(5));
    assert_eq!(
        next_run_event_sequence(MAX_RUN_EVENT_SEQUENCE),
        Err(RunStateError::EventSequenceOverflow)
    );
    assert_eq!(
        validate_run_event_sequence(4, 4),
        Err(RunStateError::InvalidEventSequence)
    );
    assert_eq!(
        validate_run_event_sequence(4, 3),
        Err(RunStateError::InvalidEventSequence)
    );

    let first = event(1, "run.created.v1");
    let third = event(3, "run.state_changed.v1");
    assert!(
        append_run_event(
            Some(&first),
            RunEventDraft {
                run_event_id: id("rev", 3),
                run_id: id("run", 1),
                sequence: 3,
                event_type: "run.state_changed.v1".to_owned(),
                occurred_at: timestamp().to_owned(),
                actor_type: "system".to_owned(),
                actor_id: None,
                correlation_id: id("req", 1),
                tool_call_id: None,
                approval_id: None,
                payload: json!({ "state": "running" }),
            }
        )
        .is_ok()
    );
    assert_eq!(
        append_run_event(
            Some(&first),
            RunEventDraft {
                run_event_id: id("rev", 2),
                run_id: id("run", 1),
                sequence: 2,
                event_type: "run.state_changed.v1".to_owned(),
                occurred_at: timestamp().to_owned(),
                actor_type: "system".to_owned(),
                actor_id: None,
                correlation_id: id("req", 1),
                tool_call_id: None,
                approval_id: None,
                payload: json!({}),
            },
        )
        .map(|event| event.sequence),
        Ok(2)
    );
    assert!(third.validate().is_ok());
    assert_eq!(
        append_run_event(
            None,
            RunEventDraft {
                run_event_id: id("rev", 4),
                run_id: id("run", 1),
                sequence: 4,
                event_type: "run.created.v1".to_owned(),
                occurred_at: timestamp().to_owned(),
                actor_type: "system".to_owned(),
                actor_id: None,
                correlation_id: id("req", 1),
                tool_call_id: None,
                approval_id: None,
                payload: json!({}),
            }
        ),
        Err(RunStateError::InvalidEventSequence)
    );
}

#[test]
fn run_event_payloads_are_bounded_redacted_and_debug_safe() {
    let event = RunEvent::new(
        id("rev", 1),
        id("run", 1),
        1,
        RunEventType::RunStateChanged.as_str(),
        timestamp(),
        RunEventActorType::Device.as_str(),
        Some(id("dvc", 1)),
        id("req", 1),
        Some(id("tcl", 1)),
        Some(id("apr", 1)),
        json!({
            "state": "waiting_approval",
            "prompt": "raw prompt",
            "response": { "text": "raw response" },
            "tool_arguments": { "command": "secret command" },
            "arguments_summary": "domain=example.test; operation=submit",
            "input_tokens": 12
        }),
    )
    .unwrap();
    assert_eq!(event.payload["state"], json!("waiting_approval"));
    assert_eq!(event.payload["prompt"], json!("[redacted]"));
    assert_eq!(event.payload["response"], json!("[redacted]"));
    assert_eq!(event.payload["tool_arguments"], json!("[redacted]"));
    assert_eq!(
        event.payload["arguments_summary"],
        json!("domain=example.test; operation=submit")
    );
    assert_eq!(event.payload["input_tokens"], json!(12));
    assert!(event.payload_json().unwrap().len() <= MAX_RUN_EVENT_PAYLOAD_BYTES);
    let debug = format!("{event:?}");
    assert!(!debug.contains("raw prompt"));
    assert!(!debug.contains("secret command"));
    assert!(debug.contains("[redacted]"));

    let too_large = json!({ "blob": "x".repeat(MAX_RUN_EVENT_PAYLOAD_BYTES) });
    assert_eq!(
        sanitize_run_event_payload(&too_large),
        Err(RunStateError::EventPayloadTooLarge)
    );
    assert!(
        RunEvent::new(
            id("rev", 2),
            id("run", 1),
            2,
            "not-versioned",
            timestamp(),
            "system",
            None,
            id("req", 1),
            None,
            None,
            json!({}),
        )
        .is_err()
    );
}
