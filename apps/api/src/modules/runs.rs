//! P05 session and run lifecycle rules.
//!
//! This module is deliberately pure.  It does not authorize a caller, read
//! D1, dispatch work, or generate identifiers.  The HTTP/service boundary must
//! establish the current organization, project, device, membership, and policy
//! before calling one of these functions.  Keeping that boundary explicit is
//! important: a client-supplied parent ID is correlation input, never proof of
//! access.
//!
//! Runs are historical records.  A state transition returns a new value and
//! never edits the input.  Terminal values are immutable, cancellation is the
//! one idempotent terminal operation, and a retry is a new queued run with a
//! parent link and a strictly larger attempt number.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

/// The frozen P05 event sequence is stored in a signed SQLite/D1 integer
/// column.  Keeping the ceiling explicit prevents an unchecked `+ 1` from
/// wrapping a sequence into a non-positive value.
pub const MAX_RUN_EVENT_SEQUENCE: i64 = i64::MAX;

/// Maximum serialized `RunEvent.payload` size, matching the P05 migration.
pub const MAX_RUN_EVENT_PAYLOAD_BYTES: usize = 32_768;
/// Compatibility aliases for adapters that use the shorter spelling.
pub const RUN_EVENT_PAYLOAD_MAX_BYTES: usize = MAX_RUN_EVENT_PAYLOAD_BYTES;
pub const MAX_EVENT_SEQUENCE: i64 = MAX_RUN_EVENT_SEQUENCE;

/// Maximum length of a versioned run event name.
pub const MAX_RUN_EVENT_TYPE_BYTES: usize = 96;

const MAX_EVENT_DEPTH: usize = 8;
const MAX_EVENT_OBJECT_KEYS: usize = 64;
const MAX_EVENT_ARRAY_ITEMS: usize = 128;
const MAX_EVENT_STRING_BYTES: usize = 1_024;
const REDACTED: &str = "[redacted]";

/// Durable conversational/work context.  This is deliberately separate from
/// the P02 authenticated `Session`/login-session concept.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    #[default]
    Active,
    Closed,
    Archived,
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl SessionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Closed => "closed",
            Self::Archived => "archived",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "closed" => Some(Self::Closed),
            "archived" => Some(Self::Archived),
            _ => None,
        }
    }

    /// Closed and archived sessions preserve history but cannot be revived or
    /// used to start new work.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed | Self::Archived)
    }

    pub const fn allows_new_runs(self) -> bool {
        matches!(self, Self::Active)
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(self, Self::Active) && matches!(next, Self::Closed | Self::Archived)
    }

    /// Compatibility spelling for callers that use a state-machine method.
    pub const fn can_transition(from: Self, to: Self) -> bool {
        from.can_transition_to(to)
    }

    pub fn transition(self, next: Self) -> Result<Self, RunStateError> {
        validate_session_transition(self, next)?;
        Ok(next)
    }
}

/// Canonical execution states from P05-CG.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    #[default]
    Queued,
    Dispatching,
    Running,
    WaitingUser,
    WaitingApproval,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
}

impl fmt::Display for RunState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl RunState {
    pub const ALL: [Self; 9] = [
        Self::Queued,
        Self::Dispatching,
        Self::Running,
        Self::WaitingUser,
        Self::WaitingApproval,
        Self::Succeeded,
        Self::Failed,
        Self::Cancelled,
        Self::TimedOut,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Dispatching => "dispatching",
            Self::Running => "running",
            Self::WaitingUser => "waiting_user",
            Self::WaitingApproval => "waiting_approval",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "queued" => Some(Self::Queued),
            "dispatching" => Some(Self::Dispatching),
            "running" => Some(Self::Running),
            "waiting_user" => Some(Self::WaitingUser),
            "waiting_approval" => Some(Self::WaitingApproval),
            "succeeded" => Some(Self::Succeeded),
            "failed" => Some(Self::Failed),
            "cancelled" => Some(Self::Cancelled),
            "timed_out" => Some(Self::TimedOut),
            _ => None,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::TimedOut
        )
    }

    /// Retry creates a new run from a terminal unsuccessful outcome.  A
    /// successful run is not retryable; cancellation and timeout are explicit
    /// terminal outcomes that may be attempted again under current policy.
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Failed | Self::Cancelled | Self::TimedOut)
    }

    pub const fn is_waiting(self) -> bool {
        matches!(self, Self::WaitingUser | Self::WaitingApproval)
    }

    /// State eligibility only. The service must call the transition function
    /// after the corresponding user event or approval resolution; the event
    /// itself belongs to the append-only timeline, not this enum.
    pub const fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Queued => matches!(
                next,
                Self::Dispatching | Self::Failed | Self::Cancelled | Self::TimedOut
            ),
            Self::Dispatching => matches!(
                next,
                Self::Running | Self::Failed | Self::Cancelled | Self::TimedOut
            ),
            Self::Running => matches!(
                next,
                Self::WaitingUser
                    | Self::WaitingApproval
                    | Self::Succeeded
                    | Self::Failed
                    | Self::Cancelled
                    | Self::TimedOut
            ),
            // A user response can resume execution or advance to approval.
            Self::WaitingUser => matches!(
                next,
                Self::Running
                    | Self::WaitingApproval
                    | Self::Failed
                    | Self::Cancelled
                    | Self::TimedOut
            ),
            // Approval resolution can resume execution or finish the run.
            Self::WaitingApproval => matches!(
                next,
                Self::Running | Self::Succeeded | Self::Failed | Self::Cancelled | Self::TimedOut
            ),
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::TimedOut => false,
        }
    }

    pub const fn can_transition(from: Self, to: Self) -> bool {
        from.can_transition_to(to)
    }

    pub fn transition(self, next: Self) -> Result<Self, RunStateError> {
        validate_run_transition(self, next)?;
        Ok(next)
    }
}

/// Errors returned by the pure state machine.  No rejected input is stored in
/// an error value, so formatting or logging it cannot disclose a body, secret,
/// or identifier supplied by a caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RunStateError {
    InvalidSessionTransition,
    InvalidRunTransition,
    SessionTerminal,
    RunTerminal,
    RetryNotAllowed,
    CancelNotAllowed,
    InvalidRetryLink,
    InvalidAttempt,
    AttemptOverflow,
    VersionConflict,
    FinishedAtRequired,
    FinishedAtNotAllowed,
    InvalidEventSequence,
    EventSequenceOverflow,
    EventPayloadTooLarge,
    InvalidEventPayload,
    InvalidEventType,
    InvalidActorType,
    InvalidField(&'static str),
}

impl RunStateError {
    /// Stable machine-readable code suitable for a transport adapter.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidSessionTransition => "invalid_session_transition",
            Self::InvalidRunTransition => "invalid_run_transition",
            Self::SessionTerminal => "session_terminal",
            Self::RunTerminal => "run_terminal",
            Self::RetryNotAllowed => "run_retry_not_allowed",
            Self::CancelNotAllowed => "run_cancel_not_allowed",
            Self::InvalidRetryLink => "run_retry_not_allowed",
            Self::InvalidAttempt => "invalid_run_attempt",
            Self::AttemptOverflow => "run_attempt_overflow",
            Self::VersionConflict => "version_conflict",
            Self::FinishedAtRequired => "finished_at_required",
            Self::FinishedAtNotAllowed => "finished_at_not_allowed",
            Self::InvalidEventSequence => "invalid_run_event_sequence",
            Self::EventSequenceOverflow => "run_event_sequence_overflow",
            Self::EventPayloadTooLarge => "run_event_payload_too_large",
            Self::InvalidEventPayload => "invalid_run_event_payload",
            Self::InvalidEventType => "invalid_run_event_type",
            Self::InvalidActorType => "invalid_run_event_actor_type",
            Self::InvalidField(_) => "invalid_run_field",
        }
    }
}

impl fmt::Display for RunStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(f, "invalid run field: {field}"),
            _ => f.write_str(self.code()),
        }
    }
}

impl std::error::Error for RunStateError {}

/// Compatibility aliases used by downstream domain adapters.
pub type RunTransitionError = RunStateError;
pub type StateTransitionError = RunStateError;
pub type SessionStateError = RunStateError;
pub type SessionLifecycle = SessionState;

/// Validate the two session transitions in the frozen contract.
pub fn validate_session_transition(
    current: SessionState,
    next: SessionState,
) -> Result<(), RunStateError> {
    if current.is_terminal() {
        return Err(RunStateError::SessionTerminal);
    }
    if !current.can_transition_to(next) {
        return Err(RunStateError::InvalidSessionTransition);
    }
    Ok(())
}

/// Validate one run transition.  Terminal states are checked before the table
/// so a caller cannot use a special-case transition to resurrect history.
pub fn validate_run_transition(current: RunState, next: RunState) -> Result<(), RunStateError> {
    if current.is_terminal() {
        return Err(RunStateError::RunTerminal);
    }
    if !current.can_transition_to(next) {
        return Err(RunStateError::InvalidRunTransition);
    }
    Ok(())
}

/// Free-function forms for adapters that keep state values in a generic
/// transition table rather than calling the enum methods directly.
pub const fn is_terminal_run_state(state: RunState) -> bool {
    state.is_terminal()
}

pub const fn is_terminal_session_state(state: SessionState) -> bool {
    state.is_terminal()
}

pub const fn can_retry_run_state(state: RunState) -> bool {
    state.is_retryable()
}

/// Return the state after a cancel request.  Cancellation is idempotent only
/// for an already-cancelled run; other terminal outcomes remain immutable.
/// This helper has no record/version input; use [`Run::cancel`] for the
/// version-guarded mutation.
pub fn cancel_run_state(current: RunState) -> Result<RunState, RunStateError> {
    if current == RunState::Cancelled {
        return Ok(RunState::Cancelled);
    }
    if current.is_terminal() {
        return Err(RunStateError::RunTerminal);
    }
    validate_run_transition(current, RunState::Cancelled)?;
    Ok(RunState::Cancelled)
}

/// A versioned, durable P05 session value.  The type is intentionally made of
/// plain strings rather than persistence-specific row structs; an adapter can
/// map it to the frozen D1 shape after authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Session {
    #[serde(rename = "id")]
    pub id: String,
    pub org_id: String,
    pub project_id: String,
    pub device_id: String,
    pub workspace_binding_id: Option<String>,
    pub agent_definition_id: String,
    pub agent_definition_version: i64,
    pub external_id: Option<String>,
    pub title: Option<String>,
    pub lifecycle: SessionState,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Deserialize)]
struct SessionWire {
    id: String,
    org_id: String,
    project_id: String,
    device_id: String,
    #[serde(default)]
    workspace_binding_id: Option<String>,
    agent_definition_id: String,
    agent_definition_version: i64,
    #[serde(default)]
    external_id: Option<String>,
    #[serde(default)]
    title: Option<String>,
    lifecycle: SessionState,
    version: i64,
    created_at: String,
    updated_at: String,
}

impl<'de> Deserialize<'de> for Session {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SessionWire::deserialize(deserializer)?;
        let session = Self {
            id: wire.id,
            org_id: wire.org_id,
            project_id: wire.project_id,
            device_id: wire.device_id,
            workspace_binding_id: wire.workspace_binding_id,
            agent_definition_id: wire.agent_definition_id,
            agent_definition_version: wire.agent_definition_version,
            external_id: wire.external_id,
            title: wire.title,
            lifecycle: wire.lifecycle,
            version: wire.version,
            created_at: wire.created_at,
            updated_at: wire.updated_at,
        };
        session.validate().map_err(serde::de::Error::custom)?;
        Ok(session)
    }
}

impl Session {
    pub fn agent_session_id(&self) -> &str {
        &self.id
    }

    pub fn validate(&self) -> Result<(), RunStateError> {
        required_text(&self.id, "id")?;
        required_text(&self.org_id, "org_id")?;
        required_text(&self.project_id, "project_id")?;
        required_text(&self.device_id, "device_id")?;
        required_text(&self.agent_definition_id, "agent_definition_id")?;
        optional_text(self.workspace_binding_id.as_deref(), "workspace_binding_id")?;
        optional_text(self.external_id.as_deref(), "external_id")?;
        if self
            .title
            .as_deref()
            .is_some_and(|value| value.chars().count() > 200)
        {
            return Err(RunStateError::InvalidField("title"));
        }
        optional_text(self.title.as_deref(), "title")?;
        if self.agent_definition_version <= 0 || self.version <= 0 {
            return Err(RunStateError::InvalidField("version"));
        }
        required_text(&self.created_at, "created_at")?;
        required_text(&self.updated_at, "updated_at")?;
        if !valid_timestamp(&self.created_at) || !valid_timestamp(&self.updated_at) {
            return Err(RunStateError::InvalidField("timestamp"));
        }
        Ok(())
    }

    pub fn allows_new_runs(&self) -> bool {
        self.lifecycle.allows_new_runs()
    }

    /// Return a new session value after a version-checked lifecycle change.
    pub fn transition(
        &self,
        next: SessionState,
        expected_version: i64,
        updated_at: impl Into<String>,
    ) -> Result<Self, RunStateError> {
        self.validate()?;
        if self.lifecycle.is_terminal() {
            return Err(RunStateError::SessionTerminal);
        }
        if expected_version <= 0 || expected_version != self.version {
            return Err(RunStateError::VersionConflict);
        }
        validate_session_transition(self.lifecycle, next)?;
        let updated_at = updated_at.into();
        required_text(&updated_at, "updated_at")?;
        let mut next_session = self.clone();
        next_session.lifecycle = next;
        next_session.version = self
            .version
            .checked_add(1)
            .ok_or(RunStateError::InvalidField("version"))?;
        next_session.updated_at = updated_at;
        next_session.validate()?;
        Ok(next_session)
    }

    pub fn close(
        &self,
        expected_version: i64,
        updated_at: impl Into<String>,
    ) -> Result<Self, RunStateError> {
        self.transition(SessionState::Closed, expected_version, updated_at)
    }

    pub fn archive(
        &self,
        expected_version: i64,
        updated_at: impl Into<String>,
    ) -> Result<Self, RunStateError> {
        self.transition(SessionState::Archived, expected_version, updated_at)
    }
}

/// Input shape for constructing a `Run` without exposing a database row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunDraft {
    pub id: String,
    pub org_id: String,
    pub project_id: String,
    pub agent_session_id: String,
    #[serde(default)]
    pub parent_run_id: Option<String>,
    pub attempt: i64,
    pub agent_definition_id: String,
    pub agent_definition_version: i64,
    pub principal_user_id: String,
    pub device_id: String,
    #[serde(default)]
    pub model_alias: Option<String>,
    #[serde(default)]
    pub route_id: Option<String>,
    #[serde(default)]
    pub route_version_id: Option<String>,
    pub state: RunState,
    #[serde(default)]
    pub failure_code: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub finished_at: Option<String>,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl Default for RunDraft {
    fn default() -> Self {
        Self {
            id: String::new(),
            org_id: String::new(),
            project_id: String::new(),
            agent_session_id: String::new(),
            parent_run_id: None,
            attempt: 1,
            agent_definition_id: String::new(),
            agent_definition_version: 1,
            principal_user_id: String::new(),
            device_id: String::new(),
            model_alias: None,
            route_id: None,
            route_version_id: None,
            state: RunState::Queued,
            failure_code: None,
            request_id: None,
            started_at: None,
            finished_at: None,
            version: 1,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }
}

/// A plain domain run value.  The parent and all historical fields remain on
/// the parent value when a retry is created; the retry is a separate value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Run {
    #[serde(rename = "id")]
    pub id: String,
    pub org_id: String,
    pub project_id: String,
    pub agent_session_id: String,
    #[serde(default)]
    pub parent_run_id: Option<String>,
    pub attempt: i64,
    pub agent_definition_id: String,
    pub agent_definition_version: i64,
    pub principal_user_id: String,
    pub device_id: String,
    #[serde(default)]
    pub model_alias: Option<String>,
    #[serde(default)]
    pub route_id: Option<String>,
    #[serde(default)]
    pub route_version_id: Option<String>,
    pub state: RunState,
    #[serde(default)]
    pub failure_code: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub finished_at: Option<String>,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl<'de> Deserialize<'de> for Run {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let draft = RunDraft::deserialize(deserializer)?;
        Run::from_draft(draft).map_err(serde::de::Error::custom)
    }
}

impl Run {
    pub fn run_id(&self) -> &str {
        &self.id
    }

    pub fn from_draft(draft: RunDraft) -> Result<Self, RunStateError> {
        let run = Self {
            id: draft.id,
            org_id: draft.org_id,
            project_id: draft.project_id,
            agent_session_id: draft.agent_session_id,
            parent_run_id: draft.parent_run_id,
            attempt: draft.attempt,
            agent_definition_id: draft.agent_definition_id,
            agent_definition_version: draft.agent_definition_version,
            principal_user_id: draft.principal_user_id,
            device_id: draft.device_id,
            model_alias: draft.model_alias,
            route_id: draft.route_id,
            route_version_id: draft.route_version_id,
            state: draft.state,
            failure_code: draft.failure_code,
            request_id: draft.request_id,
            started_at: draft.started_at,
            finished_at: draft.finished_at,
            version: draft.version,
            created_at: draft.created_at,
            updated_at: draft.updated_at,
        };
        run.validate()?;
        Ok(run)
    }

    pub fn validate(&self) -> Result<(), RunStateError> {
        required_text(&self.id, "id")?;
        required_text(&self.org_id, "org_id")?;
        required_text(&self.project_id, "project_id")?;
        required_text(&self.agent_session_id, "agent_session_id")?;
        required_text(&self.agent_definition_id, "agent_definition_id")?;
        required_text(&self.principal_user_id, "principal_user_id")?;
        required_text(&self.device_id, "device_id")?;
        optional_text(self.parent_run_id.as_deref(), "parent_run_id")?;
        optional_text(self.model_alias.as_deref(), "model_alias")?;
        optional_text(self.route_id.as_deref(), "route_id")?;
        optional_text(self.route_version_id.as_deref(), "route_version_id")?;
        optional_text(self.request_id.as_deref(), "request_id")?;
        optional_text(self.started_at.as_deref(), "started_at")?;
        optional_text(self.finished_at.as_deref(), "finished_at")?;
        if let Some(failure_code) = self.failure_code.as_deref() {
            required_text(failure_code, "failure_code")?;
            if failure_code.len() > 96 {
                return Err(RunStateError::InvalidField("failure_code"));
            }
        }
        if self.attempt <= 0 {
            return Err(RunStateError::InvalidAttempt);
        }
        if self.agent_definition_version <= 0 || self.version <= 0 {
            return Err(RunStateError::InvalidField("version"));
        }
        match (&self.parent_run_id, self.attempt) {
            (None, 1) => {}
            (Some(parent), attempt) if attempt > 1 && parent != &self.id => {}
            _ => return Err(RunStateError::InvalidAttempt),
        }
        required_text(&self.created_at, "created_at")?;
        required_text(&self.updated_at, "updated_at")?;
        if !valid_timestamp(&self.created_at) || !valid_timestamp(&self.updated_at) {
            return Err(RunStateError::InvalidField("timestamp"));
        }
        if self
            .started_at
            .as_deref()
            .is_some_and(|value| !valid_timestamp(value))
            || self
                .finished_at
                .as_deref()
                .is_some_and(|value| !valid_timestamp(value))
        {
            return Err(RunStateError::InvalidField("timestamp"));
        }
        if self.state.is_terminal() {
            if self.finished_at.is_none() {
                return Err(RunStateError::FinishedAtRequired);
            }
        } else if self.finished_at.is_some() {
            return Err(RunStateError::FinishedAtNotAllowed);
        }
        Ok(())
    }

    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    pub fn is_retryable(&self) -> bool {
        self.state.is_retryable()
    }

    /// Apply a version-checked state transition without mutating this value.
    pub fn transition(
        &self,
        next: RunState,
        expected_version: i64,
        updated_at: impl Into<String>,
        finished_at: Option<&str>,
    ) -> Result<Self, RunStateError> {
        self.validate()?;
        if self.state.is_terminal() {
            return Err(RunStateError::RunTerminal);
        }
        if expected_version <= 0 || expected_version != self.version {
            return Err(RunStateError::VersionConflict);
        }
        validate_run_transition(self.state, next)?;
        if next.is_terminal() {
            let Some(finished_at) = finished_at else {
                return Err(RunStateError::FinishedAtRequired);
            };
            required_text(finished_at, "finished_at")?;
        } else if finished_at.is_some() {
            return Err(RunStateError::FinishedAtNotAllowed);
        }
        let updated_at = updated_at.into();
        required_text(&updated_at, "updated_at")?;
        let mut next_run = self.clone();
        next_run.state = next;
        next_run.finished_at = finished_at.map(str::to_owned);
        next_run.updated_at = updated_at;
        next_run.version = self
            .version
            .checked_add(1)
            .ok_or(RunStateError::InvalidField("version"))?;
        next_run.validate()?;
        Ok(next_run)
    }

    /// Apply cancellation.  Repeating the request on the same cancelled value
    /// returns that existing value and does not increment its version.
    pub fn cancel(
        &self,
        expected_version: i64,
        updated_at: impl Into<String>,
        finished_at: &str,
    ) -> Result<Self, RunStateError> {
        self.validate()?;
        if self.state == RunState::Cancelled {
            return Ok(self.clone());
        }
        if self.state.is_terminal() {
            return Err(RunStateError::RunTerminal);
        }
        if expected_version <= 0 || expected_version != self.version {
            return Err(RunStateError::VersionConflict);
        }
        self.transition(
            RunState::Cancelled,
            expected_version,
            updated_at,
            Some(finished_at),
        )
    }
}

/// Version-checked run transition helper for service code that already owns a
/// plain `Run` value.
pub fn transition_run(
    run: &Run,
    next: RunState,
    expected_version: i64,
    updated_at: impl Into<String>,
    finished_at: Option<&str>,
) -> Result<Run, RunStateError> {
    run.transition(next, expected_version, updated_at, finished_at)
}

/// The minimal state-only transition helper is useful when a persistence
/// adapter has already loaded and validated the full row. It does not mutate
/// a record; use [`Run::transition`] when an optimistic version is available.
pub fn transition_run_state(current: RunState, next: RunState) -> Result<RunState, RunStateError> {
    validate_run_transition(current, next)?;
    Ok(next)
}

/// Cancel a full run value with optimistic version protection.
pub fn cancel_run(
    run: &Run,
    expected_version: i64,
    updated_at: impl Into<String>,
    finished_at: &str,
) -> Result<Run, RunStateError> {
    run.cancel(expected_version, updated_at, finished_at)
}

/// Calculate the one-based attempt number for a retry.  The parent must be a
/// valid positive attempt; a checked add prevents wrapping into a duplicate
/// attempt.
pub fn next_retry_attempt(previous_attempt: i64) -> Result<i64, RunStateError> {
    if previous_attempt <= 0 {
        return Err(RunStateError::InvalidAttempt);
    }
    previous_attempt
        .checked_add(1)
        .ok_or(RunStateError::AttemptOverflow)
}

/// Short alias used by route/service code.
pub fn next_attempt_number(previous_attempt: i64) -> Result<i64, RunStateError> {
    next_retry_attempt(previous_attempt)
}

/// Calculate the next attempt from all known attempts in a retry chain.  The
/// maximum, rather than only the selected parent, prevents a gap in history
/// from allowing a duplicate attempt number.
pub fn next_retry_attempt_from_history(previous_attempts: &[i64]) -> Result<i64, RunStateError> {
    let previous = previous_attempts
        .iter()
        .copied()
        .max()
        .ok_or(RunStateError::InvalidAttempt)?;
    next_retry_attempt(previous)
}

/// The immutable parent link carried by a new retry row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryAttempt {
    pub run_id: String,
    pub parent_run_id: String,
    pub attempt: i64,
    pub agent_session_id: String,
}

impl RetryAttempt {
    pub fn new(
        run_id: impl Into<String>,
        parent_run_id: impl Into<String>,
        attempt: i64,
        agent_session_id: impl Into<String>,
    ) -> Result<Self, RunStateError> {
        let link = Self {
            run_id: run_id.into(),
            parent_run_id: parent_run_id.into(),
            attempt,
            agent_session_id: agent_session_id.into(),
        };
        link.validate()?;
        Ok(link)
    }

    pub fn from_parent(parent: &Run, run_id: impl Into<String>) -> Result<Self, RunStateError> {
        if !parent.state.is_retryable() {
            return Err(RunStateError::RetryNotAllowed);
        }
        let run_id = run_id.into();
        required_text(&run_id, "run_id")?;
        if run_id == parent.id {
            return Err(RunStateError::InvalidRetryLink);
        }
        let attempt = next_retry_attempt(parent.attempt)?;
        Ok(Self {
            run_id,
            parent_run_id: parent.id.clone(),
            attempt,
            agent_session_id: parent.agent_session_id.clone(),
        })
    }

    pub fn validate(&self) -> Result<(), RunStateError> {
        required_text(&self.run_id, "run_id")?;
        required_text(&self.parent_run_id, "parent_run_id")?;
        required_text(&self.agent_session_id, "agent_session_id")?;
        if self.run_id == self.parent_run_id || self.attempt <= 1 {
            return Err(RunStateError::InvalidRetryLink);
        }
        Ok(())
    }
}

/// Validate that a candidate retry is linked to the supplied parent and has a
/// strictly larger attempt number in the same conversational/work session.
/// A persistence adapter may pass a number based on the maximum known sibling
/// attempt when history contains gaps.
pub fn validate_retry_parent(parent: &Run, candidate: &RetryAttempt) -> Result<(), RunStateError> {
    if !parent.state.is_retryable() {
        return Err(RunStateError::RetryNotAllowed);
    }
    candidate.validate()?;
    if candidate.parent_run_id != parent.id
        || candidate.agent_session_id != parent.agent_session_id
        || candidate.attempt <= parent.attempt
    {
        return Err(RunStateError::InvalidRetryLink);
    }
    Ok(())
}

/// Compatibility spelling for adapters that call the value a retry link.
pub fn validate_retry_link(parent: &Run, candidate: &RetryAttempt) -> Result<(), RunStateError> {
    validate_retry_parent(parent, candidate)
}

pub fn validate_retry_parent_link(
    parent: &Run,
    candidate: &RetryAttempt,
) -> Result<(), RunStateError> {
    validate_retry_parent(parent, candidate)
}

/// Validate the scope and shape of a fully materialized retry row.  This is
/// deliberately separate from the link-only helper so a persistence adapter
/// can check the candidate before inserting it.
pub fn validate_retry_scope(parent: &Run, retry: &Run) -> Result<(), RunStateError> {
    retry.validate()?;
    if retry.parent_run_id.as_deref() != Some(parent.id.as_str())
        || retry.org_id != parent.org_id
        || retry.project_id != parent.project_id
        || retry.agent_session_id != parent.agent_session_id
        || retry.attempt <= parent.attempt
        || retry.state != RunState::Queued
        || retry.finished_at.is_some()
        || retry.failure_code.is_some()
    {
        return Err(RunStateError::InvalidRetryLink);
    }
    Ok(())
}

/// Create a new queued run for a retry.  The parent is borrowed and never
/// modified.  The caller must re-resolve authorization and current policy and
/// may replace the copied model/route fields before persistence; this pure
/// function only establishes the append-only attempt relationship.  Any
/// `request_id` supplied here must already be server-generated correlation
/// metadata; it is never accepted as authorization evidence.
pub fn retry_run(
    parent: &Run,
    run_id: impl Into<String>,
    expected_version: i64,
    updated_at: impl Into<String>,
    request_id: Option<String>,
) -> Result<Run, RunStateError> {
    parent.validate()?;
    if !parent.state.is_retryable() {
        return Err(RunStateError::RetryNotAllowed);
    }
    if expected_version <= 0 || expected_version != parent.version {
        return Err(RunStateError::VersionConflict);
    }
    let link = RetryAttempt::from_parent(parent, run_id)?;
    validate_retry_parent(parent, &link)?;
    let updated_at = updated_at.into();
    required_text(&updated_at, "updated_at")?;
    let mut retry = parent.clone();
    retry.id = link.run_id;
    retry.parent_run_id = Some(link.parent_run_id);
    retry.attempt = link.attempt;
    retry.state = RunState::Queued;
    retry.failure_code = None;
    retry.request_id = request_id;
    retry.started_at = None;
    retry.finished_at = None;
    retry.version = 1;
    retry.created_at = updated_at.clone();
    retry.updated_at = updated_at;
    validate_retry_scope(parent, &retry)?;
    retry.validate()?;
    Ok(retry)
}

/// Explicitly named alias for callers that do not use the short operation
/// name.  It has the same version guard and parent-preservation semantics.
pub fn create_retry_run(
    parent: &Run,
    run_id: impl Into<String>,
    expected_version: i64,
    updated_at: impl Into<String>,
    request_id: Option<String>,
) -> Result<Run, RunStateError> {
    retry_run(parent, run_id, expected_version, updated_at, request_id)
}

/// A retry link without a version check is useful only after a service has
/// already performed the optimistic read/conditional-write check.
pub fn retry_run_after_version_check(
    parent: &Run,
    run_id: impl Into<String>,
    updated_at: impl Into<String>,
    request_id: Option<String>,
) -> Result<Run, RunStateError> {
    retry_run(parent, run_id, parent.version, updated_at, request_id)
}

/// Stable actor vocabulary for a run timeline record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunEventActorType {
    User,
    Device,
    ServiceAccount,
    System,
}

impl fmt::Display for RunEventActorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<RunEventActorType> for String {
    fn from(value: RunEventActorType) -> Self {
        value.as_str().to_owned()
    }
}

impl RunEventActorType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Device => "device",
            Self::ServiceAccount => "service_account",
            Self::System => "system",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "device" => Some(Self::Device),
            "service_account" => Some(Self::ServiceAccount),
            "system" => Some(Self::System),
            _ => None,
        }
    }
}

pub type RunActorType = RunEventActorType;

/// Stable P05 event names.  The `RunEvent` record stores the text form so a
/// future additive event can be read without making old timelines unreadable;
/// this enum gives the run-owned names a typed construction path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RunEventType {
    #[serde(rename = "agent_definition.created.v1")]
    AgentDefinitionCreated,
    #[serde(rename = "agent_definition.updated.v1")]
    AgentDefinitionUpdated,
    #[serde(rename = "session.created.v1")]
    SessionCreated,
    #[serde(rename = "session.closed.v1")]
    SessionClosed,
    #[serde(rename = "run.created.v1")]
    RunCreated,
    #[serde(rename = "run.state_changed.v1")]
    RunStateChanged,
    #[serde(rename = "run.cancelled.v1")]
    RunCancelled,
    #[serde(rename = "run.retried.v1")]
    RunRetried,
    #[serde(rename = "run.event_appended.v1")]
    RunEventAppended,
    #[serde(rename = "tool.catalog_updated.v1")]
    ToolCatalogUpdated,
    #[serde(rename = "tool.mcp_registration_changed.v1")]
    ToolMcpRegistrationChanged,
    #[serde(rename = "tool.decision_recorded.v1")]
    ToolDecisionRecorded,
    #[serde(rename = "tool.denied.v1")]
    ToolDenied,
    #[serde(rename = "approval.requested.v1")]
    ApprovalRequested,
    #[serde(rename = "approval.resolved.v1")]
    ApprovalResolved,
    #[serde(rename = "usage.reconciled.v1")]
    UsageReconciled,
    #[serde(rename = "budget.reserved.v1")]
    BudgetReserved,
    #[serde(rename = "budget.reconciled.v1")]
    BudgetReconciled,
    #[serde(rename = "budget.denied.v1")]
    BudgetDenied,
    #[serde(rename = "rate_limit.denied.v1")]
    RateLimitDenied,
    #[serde(rename = "artifact.created.v1")]
    ArtifactCreated,
}

impl fmt::Display for RunEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<RunEventType> for String {
    fn from(value: RunEventType) -> Self {
        value.as_str().to_owned()
    }
}

impl RunEventType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentDefinitionCreated => "agent_definition.created.v1",
            Self::AgentDefinitionUpdated => "agent_definition.updated.v1",
            Self::SessionCreated => "session.created.v1",
            Self::SessionClosed => "session.closed.v1",
            Self::RunCreated => "run.created.v1",
            Self::RunStateChanged => "run.state_changed.v1",
            Self::RunCancelled => "run.cancelled.v1",
            Self::RunRetried => "run.retried.v1",
            Self::RunEventAppended => "run.event_appended.v1",
            Self::ToolCatalogUpdated => "tool.catalog_updated.v1",
            Self::ToolMcpRegistrationChanged => "tool.mcp_registration_changed.v1",
            Self::ToolDecisionRecorded => "tool.decision_recorded.v1",
            Self::ToolDenied => "tool.denied.v1",
            Self::ApprovalRequested => "approval.requested.v1",
            Self::ApprovalResolved => "approval.resolved.v1",
            Self::UsageReconciled => "usage.reconciled.v1",
            Self::BudgetReserved => "budget.reserved.v1",
            Self::BudgetReconciled => "budget.reconciled.v1",
            Self::BudgetDenied => "budget.denied.v1",
            Self::RateLimitDenied => "rate_limit.denied.v1",
            Self::ArtifactCreated => "artifact.created.v1",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "agent_definition.created.v1" => Some(Self::AgentDefinitionCreated),
            "agent_definition.updated.v1" => Some(Self::AgentDefinitionUpdated),
            "session.created.v1" => Some(Self::SessionCreated),
            "session.closed.v1" => Some(Self::SessionClosed),
            "run.created.v1" => Some(Self::RunCreated),
            "run.state_changed.v1" => Some(Self::RunStateChanged),
            "run.cancelled.v1" => Some(Self::RunCancelled),
            "run.retried.v1" => Some(Self::RunRetried),
            "run.event_appended.v1" => Some(Self::RunEventAppended),
            "tool.catalog_updated.v1" => Some(Self::ToolCatalogUpdated),
            "tool.mcp_registration_changed.v1" => Some(Self::ToolMcpRegistrationChanged),
            "tool.decision_recorded.v1" => Some(Self::ToolDecisionRecorded),
            "tool.denied.v1" => Some(Self::ToolDenied),
            "approval.requested.v1" => Some(Self::ApprovalRequested),
            "approval.resolved.v1" => Some(Self::ApprovalResolved),
            "usage.reconciled.v1" => Some(Self::UsageReconciled),
            "budget.reserved.v1" => Some(Self::BudgetReserved),
            "budget.reconciled.v1" => Some(Self::BudgetReconciled),
            "budget.denied.v1" => Some(Self::BudgetDenied),
            "rate_limit.denied.v1" => Some(Self::RateLimitDenied),
            "artifact.created.v1" => Some(Self::ArtifactCreated),
            _ => None,
        }
    }
}

/// Input for constructing one immutable timeline record.
#[derive(Clone, Debug, PartialEq)]
pub struct RunEventDraft {
    pub run_event_id: String,
    pub run_id: String,
    pub sequence: i64,
    pub event_type: String,
    pub occurred_at: String,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub correlation_id: String,
    pub tool_call_id: Option<String>,
    pub approval_id: Option<String>,
    pub payload: Value,
}

/// An append-only, sequence-numbered run timeline record.
///
/// There is deliberately no update or delete operation.  `payload` is public
/// for ergonomic D1 mapping, but construction and deserialization run the
/// bounded redaction policy; callers should use `from_draft`/`new` rather than
/// inserting an unvalidated value.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RunEvent {
    #[serde(rename = "id")]
    pub run_event_id: String,
    pub run_id: String,
    pub sequence: i64,
    pub event_type: String,
    pub occurred_at: String,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub correlation_id: String,
    pub tool_call_id: Option<String>,
    pub approval_id: Option<String>,
    pub payload: Value,
}

impl RunEvent {
    pub fn id(&self) -> &str {
        &self.run_event_id
    }

    pub fn from_draft(draft: RunEventDraft) -> Result<Self, RunStateError> {
        if draft.sequence <= 0 {
            return Err(RunStateError::InvalidEventSequence);
        }
        if !valid_event_type(&draft.event_type) {
            return Err(RunStateError::InvalidEventType);
        }
        if RunEventActorType::parse(&draft.actor_type).is_none() {
            return Err(RunStateError::InvalidActorType);
        }
        required_text(&draft.run_event_id, "run_event_id")?;
        required_text(&draft.run_id, "run_id")?;
        required_text(&draft.occurred_at, "occurred_at")?;
        required_text(&draft.correlation_id, "correlation_id")?;
        optional_text(draft.actor_id.as_deref(), "actor_id")?;
        optional_text(draft.tool_call_id.as_deref(), "tool_call_id")?;
        optional_text(draft.approval_id.as_deref(), "approval_id")?;
        if !valid_timestamp(&draft.occurred_at) {
            return Err(RunStateError::InvalidField("occurred_at"));
        }
        let payload = sanitize_run_event_payload(&draft.payload)?;
        Ok(Self {
            run_event_id: draft.run_event_id,
            run_id: draft.run_id,
            sequence: draft.sequence,
            event_type: draft.event_type,
            occurred_at: draft.occurred_at,
            actor_type: draft.actor_type,
            actor_id: draft.actor_id,
            correlation_id: draft.correlation_id,
            tool_call_id: draft.tool_call_id,
            approval_id: draft.approval_id,
            payload,
        })
    }

    /// Construct a run event using the frozen migration column names.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_event_id: impl Into<String>,
        run_id: impl Into<String>,
        sequence: i64,
        event_type: impl Into<String>,
        occurred_at: impl Into<String>,
        actor_type: impl Into<String>,
        actor_id: Option<String>,
        correlation_id: impl Into<String>,
        tool_call_id: Option<String>,
        approval_id: Option<String>,
        payload: Value,
    ) -> Result<Self, RunStateError> {
        Self::from_draft(RunEventDraft {
            run_event_id: run_event_id.into(),
            run_id: run_id.into(),
            sequence,
            event_type: event_type.into(),
            occurred_at: occurred_at.into(),
            actor_type: actor_type.into(),
            actor_id,
            correlation_id: correlation_id.into(),
            tool_call_id,
            approval_id,
            payload,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_typed(
        run_event_id: impl Into<String>,
        run_id: impl Into<String>,
        sequence: i64,
        event_type: RunEventType,
        occurred_at: impl Into<String>,
        actor_type: RunEventActorType,
        actor_id: Option<String>,
        correlation_id: impl Into<String>,
        tool_call_id: Option<String>,
        approval_id: Option<String>,
        payload: Value,
    ) -> Result<Self, RunStateError> {
        Self::new(
            run_event_id,
            run_id,
            sequence,
            event_type.as_str(),
            occurred_at,
            actor_type.as_str(),
            actor_id,
            correlation_id,
            tool_call_id,
            approval_id,
            payload,
        )
    }

    pub fn validate(&self) -> Result<(), RunStateError> {
        if self.sequence <= 0 {
            return Err(RunStateError::InvalidEventSequence);
        }
        if !valid_event_type(&self.event_type) {
            return Err(RunStateError::InvalidEventType);
        }
        if RunEventActorType::parse(&self.actor_type).is_none() {
            return Err(RunStateError::InvalidActorType);
        }
        required_text(&self.run_event_id, "run_event_id")?;
        required_text(&self.run_id, "run_id")?;
        required_text(&self.correlation_id, "correlation_id")?;
        optional_text(self.actor_id.as_deref(), "actor_id")?;
        optional_text(self.tool_call_id.as_deref(), "tool_call_id")?;
        optional_text(self.approval_id.as_deref(), "approval_id")?;
        if !valid_timestamp(&self.occurred_at) {
            return Err(RunStateError::InvalidField("occurred_at"));
        }
        if sanitize_run_event_payload(&self.payload)? != self.payload {
            return Err(RunStateError::InvalidEventPayload);
        }
        Ok(())
    }

    pub fn payload_json(&self) -> Result<String, RunStateError> {
        serde_json::to_string(&self.payload).map_err(|_| RunStateError::InvalidEventPayload)
    }
}

impl fmt::Debug for RunEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunEvent")
            .field("run_event_id", &self.run_event_id)
            .field("run_id", &self.run_id)
            .field("sequence", &self.sequence)
            .field("event_type", &self.event_type)
            .field("occurred_at", &self.occurred_at)
            .field("actor_type", &self.actor_type)
            .field("actor_id", &self.actor_id)
            .field("correlation_id", &self.correlation_id)
            .field("tool_call_id", &self.tool_call_id)
            .field("approval_id", &self.approval_id)
            .field("payload", &"[redacted]")
            .finish()
    }
}

#[derive(Deserialize)]
struct RunEventWire {
    #[serde(rename = "id")]
    run_event_id: String,
    run_id: String,
    sequence: i64,
    event_type: String,
    occurred_at: String,
    actor_type: String,
    #[serde(default)]
    actor_id: Option<String>,
    correlation_id: String,
    #[serde(default)]
    tool_call_id: Option<String>,
    #[serde(default)]
    approval_id: Option<String>,
    payload: Value,
}

impl<'de> Deserialize<'de> for RunEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RunEventWire::deserialize(deserializer)?;
        Self::from_draft(RunEventDraft {
            run_event_id: wire.run_event_id,
            run_id: wire.run_id,
            sequence: wire.sequence,
            event_type: wire.event_type,
            occurred_at: wire.occurred_at,
            actor_type: wire.actor_type,
            actor_id: wire.actor_id,
            correlation_id: wire.correlation_id,
            tool_call_id: wire.tool_call_id,
            approval_id: wire.approval_id,
            payload: wire.payload,
        })
        .map_err(serde::de::Error::custom)
    }
}

/// Construct a validated event without a mutable repository object.
#[allow(clippy::too_many_arguments)]
pub fn build_run_event(
    run_event_id: impl Into<String>,
    run_id: impl Into<String>,
    sequence: i64,
    event_type: impl Into<String>,
    occurred_at: impl Into<String>,
    actor_type: impl Into<String>,
    actor_id: Option<String>,
    correlation_id: impl Into<String>,
    tool_call_id: Option<String>,
    approval_id: Option<String>,
    payload: Value,
) -> Result<RunEvent, RunStateError> {
    RunEvent::new(
        run_event_id,
        run_id,
        sequence,
        event_type,
        occurred_at,
        actor_type,
        actor_id,
        correlation_id,
        tool_call_id,
        approval_id,
        payload,
    )
}

/// Return the next positive sequence after an observed sequence.  A missing
/// timeline is represented by zero.
pub fn next_run_event_sequence(previous_sequence: i64) -> Result<i64, RunStateError> {
    if previous_sequence < 0 {
        return Err(RunStateError::InvalidEventSequence);
    }
    if previous_sequence == MAX_RUN_EVENT_SEQUENCE {
        return Err(RunStateError::EventSequenceOverflow);
    }
    Ok(previous_sequence + 1)
}

/// Validate an append relative to the last observed event.
pub fn validate_run_event_sequence(
    previous_sequence: i64,
    next_sequence: i64,
) -> Result<(), RunStateError> {
    if previous_sequence < 0 || next_sequence <= 0 {
        return Err(RunStateError::InvalidEventSequence);
    }
    if next_sequence <= previous_sequence {
        return Err(RunStateError::InvalidEventSequence);
    }
    Ok(())
}

/// Validate a new event against the prior event.  The first event for a run
/// must use sequence one; later events must be strictly increasing and belong
/// to the same run.
pub fn append_run_event(
    previous: Option<&RunEvent>,
    draft: RunEventDraft,
) -> Result<RunEvent, RunStateError> {
    let event = RunEvent::from_draft(draft)?;
    match previous {
        Some(previous) => {
            previous.validate()?;
            if previous.run_id != event.run_id {
                return Err(RunStateError::InvalidEventPayload);
            }
            validate_run_event_sequence(previous.sequence, event.sequence)?;
        }
        None if event.sequence != 1 => return Err(RunStateError::InvalidEventSequence),
        None => {}
    }
    Ok(event)
}

/// Redact content-bearing values and enforce the frozen 32 KiB payload bound.
pub fn sanitize_run_event_payload(value: &Value) -> Result<Value, RunStateError> {
    if !value.is_object() {
        return Err(RunStateError::InvalidEventPayload);
    }
    let raw = serde_json::to_vec(value).map_err(|_| RunStateError::InvalidEventPayload)?;
    if raw.len() > MAX_RUN_EVENT_PAYLOAD_BYTES {
        return Err(RunStateError::EventPayloadTooLarge);
    }
    let sanitized = redact_event_value(value, 0)?;
    let encoded = serde_json::to_vec(&sanitized).map_err(|_| RunStateError::InvalidEventPayload)?;
    if encoded.len() > MAX_RUN_EVENT_PAYLOAD_BYTES {
        return Err(RunStateError::EventPayloadTooLarge);
    }
    Ok(sanitized)
}

/// Alias with the shorter name used by event builders.
pub fn redact_run_event_payload(value: &Value) -> Result<Value, RunStateError> {
    sanitize_run_event_payload(value)
}

fn redact_event_value(value: &Value, depth: usize) -> Result<Value, RunStateError> {
    if depth > MAX_EVENT_DEPTH {
        return Err(RunStateError::EventPayloadTooLarge);
    }
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(value.clone()),
        Value::String(value) => {
            if value.chars().any(char::is_control) {
                return Err(RunStateError::InvalidEventPayload);
            }
            if value.len() > MAX_EVENT_STRING_BYTES {
                let mut bounded = value
                    .chars()
                    .take(MAX_EVENT_STRING_BYTES)
                    .collect::<String>();
                bounded.push_str("[truncated]");
                Ok(Value::String(bounded))
            } else {
                Ok(Value::String(value.clone()))
            }
        }
        Value::Array(values) => {
            if values.len() > MAX_EVENT_ARRAY_ITEMS {
                return Err(RunStateError::EventPayloadTooLarge);
            }
            values
                .iter()
                .map(|value| redact_event_value(value, depth + 1))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array)
        }
        Value::Object(values) => {
            if values.len() > MAX_EVENT_OBJECT_KEYS {
                return Err(RunStateError::EventPayloadTooLarge);
            }
            let mut sanitized = Map::new();
            for (key, value) in values {
                if key.is_empty() || key.len() > 64 || key.chars().any(char::is_control) {
                    return Err(RunStateError::InvalidEventPayload);
                }
                let next = if sensitive_event_key(key) {
                    Value::String(REDACTED.to_owned())
                } else {
                    redact_event_value(value, depth + 1)?
                };
                sanitized.insert(key.clone(), next);
            }
            Ok(Value::Object(sanitized))
        }
    }
}

fn sensitive_event_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    if normalized == "argumentssummary" || normalized == "contentref" {
        return false;
    }
    normalized.contains("prompt")
        || normalized.contains("response")
        || normalized.contains("secret")
        || normalized.contains("credential")
        || normalized.contains("password")
        || normalized.contains("authorization")
        || normalized.contains("apikey")
        || normalized.contains("privatekey")
        || normalized.contains("clientsecret")
        || normalized.contains("accesskey")
        || normalized.contains("bearer")
        || normalized.contains("accesstoken")
        || normalized.contains("refreshtoken")
        || normalized.contains("inputtext")
        || normalized.contains("outputtext")
        || normalized.contains("toolargument")
        || (normalized.contains("argument") && normalized != "argumentssummary")
        || normalized == "content"
        || normalized == "contents"
        || normalized == "body"
        || normalized == "text"
        || normalized == "command"
        || normalized == "commands"
        || normalized == "headers"
        || normalized == "cookie"
        || normalized == "filecontent"
        || normalized == "file"
        || normalized == "payload"
}

fn valid_event_type(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_RUN_EVENT_TYPE_BYTES {
        return false;
    }
    let Some((name, version)) = value.rsplit_once(".v") else {
        return false;
    };
    !name.is_empty()
        && name.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
        && !version.is_empty()
        && version.bytes().all(|byte| byte.is_ascii_digit())
        && version.parse::<u32>().is_ok()
}

fn valid_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || !digits(bytes, 0, 4)
        || !digits(bytes, 5, 2)
        || !digits(bytes, 8, 2)
        || !digits(bytes, 11, 2)
        || !digits(bytes, 14, 2)
        || !digits(bytes, 17, 2)
    {
        return false;
    }

    let year = number(bytes, 0, 4);
    let month = number(bytes, 5, 2);
    let day = number(bytes, 8, 2);
    let hour = number(bytes, 11, 2);
    let minute = number(bytes, 14, 2);
    let second = number(bytes, 17, 2);
    if !(1..=12).contains(&month)
        || hour > 23
        || minute > 59
        || second > 60
        || day == 0
        || day > days_in_month(year, month)
    {
        return false;
    }

    match bytes.get(19) {
        Some(b'Z') if bytes.len() == 20 => true,
        Some(b'.') if bytes.len() > 21 => {
            let fraction = &bytes[20..bytes.len() - 1];
            !fraction.is_empty()
                && fraction.iter().all(u8::is_ascii_digit)
                && bytes.last() == Some(&b'Z')
        }
        _ => false,
    }
}

fn digits(bytes: &[u8], start: usize, width: usize) -> bool {
    bytes
        .get(start..start + width)
        .is_some_and(|slice| slice.iter().all(u8::is_ascii_digit))
}

fn number(bytes: &[u8], start: usize, width: usize) -> u32 {
    bytes[start..start + width]
        .iter()
        .fold(0, |value, digit| value * 10 + u32::from(digit - b'0'))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100)) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn required_text(value: &str, field: &'static str) -> Result<(), RunStateError> {
    if value.is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
        return Err(RunStateError::InvalidField(field));
    }
    Ok(())
}

fn optional_text(value: Option<&str>, field: &'static str) -> Result<(), RunStateError> {
    if let Some(value) = value {
        required_text(value, field)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "runs_tests.rs"]
mod runs_tests;
