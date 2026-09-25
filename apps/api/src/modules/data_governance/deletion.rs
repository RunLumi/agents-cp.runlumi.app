//! The resumable deletion planner: ordered, bounded, idempotent deletion steps.
//!
//! F20-005 and F20-007 are the two requirements that shape this module. F20-005
//! makes deletion asynchronous, observable, and idempotent. F20-007 is the one
//! that is easy to get wrong: "deleting DB metadata is insufficient if
//! object/blob copies remain". So a step is not "a row" — it is a
//! *(data class, reference kind, object reference)* triple, and a plan for a
//! scope is a walk of the registry that emits one step per real reference.
//!
//! Four rules are enforced here rather than left to a persistence adapter:
//!
//! 1. **Lumi deletes only what it owns.** A reference to local ZCode device data
//!    or an upstream provider's data is recorded as a *skipped* step with a
//!    stable reason. It is never reported as deleted, and the plan says so
//!    explicitly so a certificate cannot over-claim.
//! 2. **Legal retention is not a failure.** Audit, security, billing, and
//!    certificate classes are `retain_legal_only`; they are reported as
//!    retained, not as pending work that can never finish.
//! 3. **Steps are idempotent.** Re-applying a terminal outcome is a no-op, so a
//!    redelivered job message cannot corrupt a step or double-count an attempt.
//!    A `failed` step only leaves that state through an explicit resume.
//! 4. **Plans are bounded.** Step count and reference length are capped, so a
//!    scope with a pathological number of objects fails at the boundary instead
//!    of exhausting Worker memory.
//!
//! The `pending_deletion` fence is modelled by [`decide_fence`]: after the
//! cutoff, automation dispatch, webhook/notification fan-out, billing writes,
//! export creation, and deletion retries are fenced or cancelled so a delayed
//! job cannot resurrect data that is being deleted.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::export::{DELETION_CONFIRMATION_PHRASE, ExportError, TypedConfirmation};
use super::registry::{DataClass, DataClassRecord, DeletionBehavior, lookup};
use super::retention::LegalHold;

/// Most steps one deletion plan may contain. A scope with more references than
/// this is chunked by the queue consumer, not planned in one unbounded batch.
pub const MAX_DELETION_STEPS: usize = 4_096;

/// Most references the planner will walk for one data class.
pub const MAX_REFERENCES_PER_CLASS: usize = 1_024;

/// Longest object reference the planner accepts. References are opaque keys or
/// bounded row identifiers, never a URL and never content.
pub const MAX_OBJECT_REFERENCE_LEN: usize = 512;

/// Longest failure code a step may record.
pub const MAX_FAILURE_CODE_LEN: usize = 96;

/// Reference systems F20-007 names that the control plane does not have yet.
///
/// The control plane stores data in D1 rows and, for export artifacts, a
/// private R2 bucket. There is no cache tier and no search index, so the
/// planner does not invent empty subsystems for them. It reports them as
/// pending with a stable reason, which keeps a deletion certificate honest:
/// coverage is stated, not implied. Adding either system is a schema/binding
/// change plus a new `ReferenceKind`, never a policy edit.
pub const PENDING_REFERENCE_SYSTEMS: [&str; 2] = ["cache", "search_index"];

/// Stable reason for a reference system that does not exist yet.
pub const REFERENCE_SYSTEM_ABSENT_REASON: &str = "deletion_reference_system_absent";

/// Which store a step's object reference points at.
///
/// The set is deliberately closed. Adding a variant is a reviewed change
/// because it changes what a deletion job claims to have traversed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceKind {
    /// A D1 row, referenced by its typed resource ID.
    DatabaseRow,
    /// A private R2 object, referenced by its opaque server-generated key.
    R2Object,
    /// Data on a managed device / ZCode host. Lumi does not own it.
    LocalDeviceData,
    /// Data held by an upstream AI provider. Lumi does not own it.
    UpstreamProviderData,
}

impl ReferenceKind {
    /// Traversal order within one data class: derived copies and objects are
    /// removed before the metadata row that points at them, so a failed object
    /// deletion still leaves a discoverable reference to retry.
    pub const fn traversal_rank(self) -> u8 {
        match self {
            Self::R2Object => 0,
            Self::DatabaseRow => 1,
            Self::LocalDeviceData => 2,
            Self::UpstreamProviderData => 3,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DatabaseRow => "database_row",
            Self::R2Object => "r2_object",
            Self::LocalDeviceData => "local_device_data",
            Self::UpstreamProviderData => "upstream_provider_data",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "database_row" => Some(Self::DatabaseRow),
            "r2_object" => Some(Self::R2Object),
            "local_device_data" => Some(Self::LocalDeviceData),
            "upstream_provider_data" => Some(Self::UpstreamProviderData),
            _ => None,
        }
    }

    /// True when Lumi owns the store and can therefore delete from it.
    pub const fn is_lumi_owned(self) -> bool {
        matches!(self, Self::DatabaseRow | Self::R2Object)
    }

    /// Suffix appended to the class key to build a stable step name. A D1 row
    /// step is named after its class; an object traversal is `<class>_objects`.
    pub const fn step_suffix(self) -> Option<&'static str> {
        match self {
            Self::DatabaseRow => None,
            Self::R2Object => Some("objects"),
            Self::LocalDeviceData => Some("device_data"),
            Self::UpstreamProviderData => Some("provider_data"),
        }
    }
}

/// Why a step was skipped. A skipped step always says why; the persistence
/// layer enforces the same rule with a trigger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionSkipReason {
    /// A legal hold covers this class and has not been released.
    LegalHold,
    /// The class is retained because a legal/security duty requires it.
    RetainedLegalOnly,
    /// The reference does not belong to Lumi and Lumi will not claim it.
    NotLumiOwned,
    /// A reference system the control plane does not have.
    ReferenceSystemAbsent,
}

impl DeletionSkipReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LegalHold => "deletion_legal_hold",
            Self::RetainedLegalOnly => "retained_legal_only",
            Self::NotLumiOwned => "deletion_not_lumi_owned",
            Self::ReferenceSystemAbsent => REFERENCE_SYSTEM_ABSENT_REASON,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [
            Self::LegalHold,
            Self::RetainedLegalOnly,
            Self::NotLumiOwned,
            Self::ReferenceSystemAbsent,
        ]
        .into_iter()
        .find(|reason| reason.as_str() == value)
    }
}

/// Frozen deletion job states and their transitions.
///
/// ```text
/// requested → awaiting_grace → queued → planning → deleting → verifying → completed
///                                       ↘ retry_wait → deleting
///                                       ↘ needs_attention → deleting (authorized resume)
///                                       ↘ cancelled
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionJobState {
    #[default]
    Requested,
    AwaitingGrace,
    Queued,
    Planning,
    Deleting,
    Verifying,
    Completed,
    RetryWait,
    NeedsAttention,
    Cancelled,
}

impl DeletionJobState {
    pub const ALL: [Self; 10] = [
        Self::Requested,
        Self::AwaitingGrace,
        Self::Queued,
        Self::Planning,
        Self::Deleting,
        Self::Verifying,
        Self::Completed,
        Self::RetryWait,
        Self::NeedsAttention,
        Self::Cancelled,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::AwaitingGrace => "awaiting_grace",
            Self::Queued => "queued",
            Self::Planning => "planning",
            Self::Deleting => "deleting",
            Self::Verifying => "verifying",
            Self::Completed => "completed",
            Self::RetryWait => "retry_wait",
            Self::NeedsAttention => "needs_attention",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.as_str() == value)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled)
    }

    /// `needs_attention` is the only resumable non-terminal state. It covers a
    /// legal hold, an unresolved external reference, and exhausted retries.
    pub const fn is_resumable(self) -> bool {
        matches!(self, Self::NeedsAttention)
    }

    /// The state a job enters when its plan cannot proceed.
    pub const fn park_state(self) -> Self {
        Self::NeedsAttention
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Requested => matches!(next, Self::AwaitingGrace | Self::Queued | Self::Cancelled),
            // A personal deletion has a bounded grace window in which the user
            // may still cancel; the window itself is enforced by the caller.
            Self::AwaitingGrace => matches!(next, Self::Queued | Self::Cancelled),
            Self::Queued => matches!(next, Self::Planning | Self::Cancelled),
            Self::Planning => matches!(
                next,
                Self::Deleting | Self::NeedsAttention | Self::Cancelled
            ),
            Self::Deleting => matches!(
                next,
                Self::Verifying | Self::RetryWait | Self::NeedsAttention
            ),
            // Verification is where object absence is proven, so it can still
            // park or retry rather than claiming completion.
            Self::Verifying => matches!(
                next,
                Self::Completed | Self::RetryWait | Self::NeedsAttention
            ),
            Self::RetryWait => matches!(
                next,
                Self::Deleting | Self::NeedsAttention | Self::Cancelled
            ),
            // Out of `needs_attention` only an authorized resume proceeds, so
            // the plain transition is refused; see `resume`.
            Self::NeedsAttention => false,
            Self::Completed | Self::Cancelled => false,
        }
    }

    pub const fn can_transition(from: Self, to: Self) -> bool {
        from.can_transition_to(to)
    }

    pub fn transition(self, next: Self) -> Result<Self, DeletionError> {
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(refusal(self))
        }
    }

    /// The only authorized way out of `needs_attention` and out of a
    /// grace-window cancellation race.
    ///
    /// A resume requires the `data.delete` permission, must not run before the
    /// grace window ends, and — when the job parked on a legal hold — requires
    /// the hold to have been released by an audited support/legal action.
    pub fn resume(self, authorization: &ResumeAuthorization) -> Result<Self, DeletionError> {
        if !self.is_resumable() {
            // Resuming anything other than a parked job is always reported as
            // `deletion_not_resumable`, whatever the state: the caller asked
            // for a resume that does not exist.
            return Err(DeletionError::NotResumable);
        }
        if !authorization.permitted {
            return Err(DeletionError::PermissionDenied);
        }
        if authorization.hold_blocked && !authorization.hold_released {
            return Err(DeletionError::LegalHold);
        }
        Ok(Self::Deleting)
    }

    /// A personal deletion may be cancelled only inside its bounded grace
    /// window. After the window, the job proceeds and cancellation fails.
    pub const fn grace_cancel_allowed(
        state: DeletionJobState,
        now: u64,
        grace_expires_at: Option<u64>,
    ) -> bool {
        if !matches!(state, DeletionJobState::AwaitingGrace) {
            return false;
        }
        match grace_expires_at {
            Some(expires) => now < expires,
            None => false,
        }
    }
}

/// Map a refused transition onto a stable reason.
///
/// A job parked in `needs_attention` refuses every plain transition because
/// the only way out is an authorized resume, which is reported as
/// `deletion_not_resumable` rather than as a generic state error.
const fn refusal(from: DeletionJobState) -> DeletionError {
    match from {
        DeletionJobState::NeedsAttention
        | DeletionJobState::Completed
        | DeletionJobState::Cancelled => DeletionError::NotResumable,
        _ => DeletionError::InvalidStateTransition,
    }
}

impl fmt::Display for DeletionJobState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for DeletionStepState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for ReferenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for FencedWorkflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for FenceAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for DeletionSkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for DeletionTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.target_type(), self.target_id())
    }
}

/// Proof that a resume was authorized, plus the legal-hold facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeAuthorization {
    /// The caller's `data.delete` permission result.
    pub permitted: bool,
    /// True when the job parked because a legal hold covered part of the scope.
    pub hold_blocked: bool,
    /// True when the hold has been released by an audited support/legal action.
    pub hold_released: bool,
    /// Present when a release happened, for the audit record.
    pub hold_released_by: Option<String>,
}

impl ResumeAuthorization {
    /// An authorized resume with no legal-hold involvement.
    pub fn permitted() -> Self {
        Self {
            permitted: true,
            hold_blocked: false,
            hold_released: false,
            hold_released_by: None,
        }
    }

    /// A resume of a job parked on a legal hold. The fixture case requires
    /// `audited_support_release` before anything proceeds.
    pub fn legal_hold_release(
        permitted: bool,
        hold_released: bool,
        hold_released_by: impl Into<String>,
    ) -> Self {
        Self {
            permitted,
            hold_blocked: true,
            hold_released,
            hold_released_by: Some(hold_released_by.into()),
        }
    }
}

/// Frozen per-step states.
///
/// Re-applying a terminal state is a no-op so a redelivered message is safe.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionStepState {
    #[default]
    Pending,
    Running,
    RetryWait,
    NeedsAttention,
    Succeeded,
    Failed,
    Skipped,
}

impl DeletionStepState {
    pub const ALL: [Self; 7] = [
        Self::Pending,
        Self::Running,
        Self::RetryWait,
        Self::NeedsAttention,
        Self::Succeeded,
        Self::Failed,
        Self::Skipped,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::RetryWait => "retry_wait",
            Self::NeedsAttention => "needs_attention",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.as_str() == value)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Skipped)
    }

    /// A terminal state re-applied with the same value is an idempotent no-op
    /// rather than an error, so an at-least-once queue cannot corrupt a step.
    pub fn is_idempotent_reapply(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Succeeded, Self::Succeeded)
                | (Self::Failed, Self::Failed)
                | (Self::Skipped, Self::Skipped)
        )
    }

    /// Plain transition, without the explicit resume path. `failed` and
    /// `needs_attention` deliberately do not leave here: partial failure is
    /// resumable only through [`DeletionJobState::resume`].
    pub const fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Pending => matches!(next, Self::Running | Self::Skipped),
            Self::Running => matches!(
                next,
                Self::Succeeded | Self::Failed | Self::RetryWait | Self::NeedsAttention
            ),
            Self::RetryWait => matches!(next, Self::Running | Self::NeedsAttention),
            Self::NeedsAttention | Self::Failed | Self::Succeeded | Self::Skipped => false,
        }
    }
}

/// The outcome of applying a step transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepTransition {
    /// The step moved.
    Applied {
        from: DeletionStepState,
        to: DeletionStepState,
    },
    /// The step already had this terminal state; nothing changed.
    AlreadyApplied { state: DeletionStepState },
}

impl StepTransition {
    pub const fn changed(&self) -> bool {
        matches!(self, Self::Applied { .. })
    }
}

/// One deletion step: a data class, a reference store, and an object reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletionStep {
    pub data_class: DataClass,
    pub reference_kind: ReferenceKind,
    pub object_reference: String,
    pub state: DeletionStepState,
    pub attempt: u32,
    pub failure_code: Option<String>,
    pub skip_reason: Option<DeletionSkipReason>,
    pub started_at: Option<u64>,
    pub completed_at: Option<u64>,
}

impl DeletionStep {
    pub fn new(
        data_class: DataClass,
        reference_kind: ReferenceKind,
        object_reference: impl Into<String>,
    ) -> Result<Self, DeletionError> {
        let object_reference = object_reference.into();
        if object_reference.is_empty() || object_reference.len() > MAX_OBJECT_REFERENCE_LEN {
            return Err(DeletionError::InvalidObjectReference);
        }
        if lookup(&data_class).is_none() {
            return Err(DeletionError::UndeclaredDataClass);
        }
        Ok(Self {
            data_class,
            reference_kind,
            object_reference,
            state: DeletionStepState::Pending,
            attempt: 0,
            failure_code: None,
            skip_reason: None,
            started_at: None,
            completed_at: None,
        })
    }

    /// Stable step name, e.g. `artifact_objects` for the R2 object traversal of
    /// the object-backed artifact class, or `occurrence` for its D1 rows.
    pub fn step_key(&self) -> String {
        match self.reference_kind.step_suffix() {
            Some(suffix) => format!("{}_{}", self.data_class, suffix),
            None => self.data_class.to_string(),
        }
    }

    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Claim the step. Re-claiming a `pending` step increments the attempt, so
    /// an abandoned attempt is visible rather than silently reused.
    pub fn begin(&mut self, now: u64) -> Result<StepTransition, DeletionError> {
        self.move_to(DeletionStepState::Running, |step| {
            step.attempt = step.attempt.saturating_add(1);
            step.started_at = Some(now);
            step.failure_code = None;
        })
    }

    /// Record a verified success. Idempotent.
    pub fn succeed(&mut self, now: u64) -> Result<StepTransition, DeletionError> {
        self.move_to(DeletionStepState::Succeeded, |step| {
            step.completed_at = Some(now);
            step.failure_code = None;
        })
    }

    /// Record a terminal failure. Only reachable from `running`; a retry of a
    /// `failed` step must go through [`Self::resume`].
    pub fn fail(
        &mut self,
        failure_code: impl Into<String>,
        now: u64,
    ) -> Result<StepTransition, DeletionError> {
        let failure_code = failure_code.into();
        if failure_code.is_empty() || failure_code.len() > MAX_FAILURE_CODE_LEN {
            return Err(DeletionError::InvalidFailureCode);
        }
        self.move_to(DeletionStepState::Failed, |step| {
            step.failure_code = Some(failure_code);
            step.completed_at = Some(now);
        })
    }

    /// Park on a transient failure and wait for a retry. Only from `running`.
    /// The instant is accepted for symmetry with the other transitions; the
    /// step's own timestamps stay on its attempt.
    pub fn retry_wait(&mut self, _now: u64) -> Result<StepTransition, DeletionError> {
        self.move_to(DeletionStepState::RetryWait, |_| {})
    }

    /// Park the step for human attention. Idempotent. The instant is accepted
    /// for symmetry; a parked step is not complete, so it records no
    /// `completed_at`.
    pub fn needs_attention(
        &mut self,
        failure_code: impl Into<String>,
        _now: u64,
    ) -> Result<StepTransition, DeletionError> {
        let failure_code = failure_code.into();
        if failure_code.is_empty() || failure_code.len() > MAX_FAILURE_CODE_LEN {
            return Err(DeletionError::InvalidFailureCode);
        }
        self.move_to(DeletionStepState::NeedsAttention, |step| {
            step.failure_code = Some(failure_code);
        })
    }

    /// Skip the step with a stable reason. Idempotent.
    pub fn skip(
        &mut self,
        reason: DeletionSkipReason,
        now: u64,
    ) -> Result<StepTransition, DeletionError> {
        self.move_to(DeletionStepState::Skipped, |step| {
            step.skip_reason = Some(reason);
            step.completed_at = Some(now);
        })
    }

    /// The explicit resume path for a step that failed or parked. This is the
    /// only way out of `failed`/`needs_attention`, and it is refused while a
    /// legal hold still covers the class.
    pub fn resume(
        &mut self,
        authorization: &ResumeAuthorization,
        now: u64,
    ) -> Result<StepTransition, DeletionError> {
        if !matches!(
            self.state,
            DeletionStepState::Failed
                | DeletionStepState::NeedsAttention
                | DeletionStepState::RetryWait
        ) {
            return Err(DeletionError::InvalidStateTransition);
        }
        if !authorization.permitted {
            return Err(DeletionError::PermissionDenied);
        }
        if authorization.hold_blocked && !authorization.hold_released {
            return Err(DeletionError::LegalHold);
        }
        let from = self.state;
        self.state = DeletionStepState::Running;
        self.attempt = self.attempt.saturating_add(1);
        self.started_at = Some(now);
        self.failure_code = None;
        self.completed_at = None;
        Ok(StepTransition::Applied {
            from,
            to: DeletionStepState::Running,
        })
    }

    fn move_to(
        &mut self,
        next: DeletionStepState,
        apply: impl FnOnce(&mut Self),
    ) -> Result<StepTransition, DeletionError> {
        if self.state.is_idempotent_reapply(next) {
            return Ok(StepTransition::AlreadyApplied { state: self.state });
        }
        if !self.state.can_transition_to(next) {
            return Err(DeletionError::InvalidStateTransition);
        }
        let from = self.state;
        self.state = next;
        apply(self);
        Ok(StepTransition::Applied { from, to: next })
    }
}

/// Who a deletion request targets.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "target_type", content = "target_id", rename_all = "snake_case")]
pub enum DeletionTarget {
    User(String),
    Organization(String),
}

impl DeletionTarget {
    pub fn new(target_type: &str, target_id: impl Into<String>) -> Result<Self, DeletionError> {
        let target_id = target_id.into();
        if target_id.is_empty() || target_id.len() > 64 || target_id.chars().any(char::is_control) {
            return Err(DeletionError::InvalidScope);
        }
        match target_type {
            "user" => Ok(Self::User(target_id)),
            "organization" => Ok(Self::Organization(target_id)),
            _ => Err(DeletionError::InvalidScope),
        }
    }

    pub const fn target_type(&self) -> &'static str {
        match self {
            Self::User(_) => "user",
            Self::Organization(_) => "organization",
        }
    }

    pub fn target_id(&self) -> &str {
        match self {
            Self::User(id) | Self::Organization(id) => id,
        }
    }

    /// True when the target's records can live under a tenant scope. A personal
    /// deletion also has to satisfy the organization-exit rule.
    pub const fn is_personal(&self) -> bool {
        matches!(self, Self::User(_))
    }
}

/// One reference the planner must act on, supplied by the caller because the
/// planner holds no database handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletionInventoryEntry {
    pub data_class: DataClass,
    pub reference_kind: ReferenceKind,
    pub object_reference: String,
}

impl DeletionInventoryEntry {
    pub fn new(
        data_class: DataClass,
        reference_kind: ReferenceKind,
        object_reference: impl Into<String>,
    ) -> Self {
        Self {
            data_class,
            reference_kind,
            object_reference: object_reference.into(),
        }
    }

    fn identity(&self) -> (DataClass, ReferenceKind, String) {
        (
            self.data_class.clone(),
            self.reference_kind,
            self.object_reference.clone(),
        )
    }
}

/// What a plan actually covered, and what it deliberately did not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceCoverage {
    /// Reference stores the plan traversed.
    pub traversed: Vec<&'static str>,
    /// Reference systems the control plane does not have yet.
    pub pending: Vec<&'static str>,
}

impl ReferenceCoverage {
    /// True when every reference system F20-007 names has been traversed.
    pub fn is_complete(&self) -> bool {
        self.pending.is_empty()
    }

    /// The stable reason to record when a named system has not been traversed.
    pub fn absent_reason(&self) -> Option<&'static str> {
        if self.pending.is_empty() {
            None
        } else {
            Some(REFERENCE_SYSTEM_ABSENT_REASON)
        }
    }
}

/// The systems this control plane can traverse today.
pub fn reference_coverage() -> ReferenceCoverage {
    ReferenceCoverage {
        traversed: vec![
            ReferenceKind::DatabaseRow.as_str(),
            ReferenceKind::R2Object.as_str(),
        ],
        pending: PENDING_REFERENCE_SYSTEMS.to_vec(),
    }
}

/// A bounded, ordered deletion plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletionPlan {
    pub scope: DeletionTarget,
    pub steps: Vec<DeletionStep>,
    /// A legal hold covered at least one step.
    pub legal_hold_blocks: bool,
    /// Classes kept because a legal/security duty requires them.
    pub retained_legal_classes: Vec<DataClass>,
    /// References Lumi does not own and will not claim to have deleted.
    pub not_lumi_deletable: Vec<DataClass>,
}

impl DeletionPlan {
    /// Steps the job may still execute, in plan order.
    pub fn actionable_steps(&self) -> impl Iterator<Item = &DeletionStep> {
        self.steps.iter().filter(|step| {
            matches!(
                step.state,
                DeletionStepState::Pending | DeletionStepState::RetryWait
            )
        })
    }

    /// True when every step reached a terminal state.
    pub fn is_complete(&self) -> bool {
        self.steps.iter().all(DeletionStep::is_terminal)
    }

    pub fn step_by_key(&self, step_key: &str) -> Option<&DeletionStep> {
        self.steps.iter().find(|step| step.step_key() == step_key)
    }

    pub fn coverage(&self) -> ReferenceCoverage {
        reference_coverage()
    }

    /// Statements a deletion result must carry so it never over-claims.
    ///
    /// The gate is explicit: a cloud deletion "never claims deletion of local
    /// ZCode or upstream provider data", and BYOK "does not automatically imply
    /// zero upstream retention". These are the exact sentences the API and the
    /// certificate surface.
    pub fn disclosures(&self) -> Vec<&'static str> {
        DISCLOSURES.to_vec()
    }
}

/// Stable, non-technical statements attached to any deletion result.
pub const DISCLOSURES: [&str; 3] = [
    "Lumi retention applies to Lumi-managed records only.",
    "Data on managed devices and ZCode hosts is deleted on the host, not by this cloud job.",
    "Upstream AI provider data is governed by the provider's own retention and data-use policy; Lumi cannot delete it.",
];

/// Builds a deletion plan by walking the registry.
pub struct DeletionPlanner;

impl DeletionPlanner {
    /// Produce the ordered, bounded set of steps for a scope.
    ///
    /// Ordering is `(registry declaration order, reference traversal rank)`,
    /// which is deterministic and reviewable: a plan diff between two runs
    /// shows a real state change rather than a reshuffle. Within a class the
    /// object traversal precedes the D1 row, so a failed object deletion still
    /// leaves the metadata row that points at it.
    ///
    /// Steps that Lumi must not or cannot act on are emitted as `skipped` with
    /// a stable reason rather than dropped, so the plan is a complete account of
    /// the scope.
    pub fn plan(
        scope: DeletionTarget,
        inventory: &[DeletionInventoryEntry],
        hold: Option<&LegalHold>,
        now: u64,
    ) -> Result<DeletionPlan, DeletionError> {
        if inventory.is_empty() {
            return Err(DeletionError::EmptyInventory);
        }
        if inventory.len() > MAX_DELETION_STEPS {
            return Err(DeletionError::PlanTooLarge);
        }

        let mut ordered: Vec<&DeletionInventoryEntry> = Vec::with_capacity(inventory.len());
        let mut seen: BTreeSet<(DataClass, ReferenceKind, String)> = BTreeSet::new();
        let mut per_class: BTreeMap<DataClass, usize> = BTreeMap::new();
        for entry in inventory {
            if !seen.insert(entry.identity()) {
                // The persistence layer has a uniqueness constraint on the
                // same triple; a duplicate here would be a second step for one
                // reference and would double-count an attempt.
                return Err(DeletionError::DuplicateReference);
            }
            let count = per_class.entry(entry.data_class.clone()).or_default();
            *count += 1;
            if *count > MAX_REFERENCES_PER_CLASS {
                return Err(DeletionError::PlanTooLarge);
            }
            ordered.push(entry);
        }

        // Deterministic order: registry declaration order first so the plan
        // groups a class's references together, then traversal rank.
        ordered.sort_by(|left, right| {
            let left_index = left.data_class.declaration_index();
            let right_index = right.data_class.declaration_index();
            left_index
                .cmp(&right_index)
                .then_with(|| {
                    left.reference_kind
                        .traversal_rank()
                        .cmp(&right.reference_kind.traversal_rank())
                })
                .then_with(|| left.object_reference.cmp(&right.object_reference))
        });

        let mut steps = Vec::with_capacity(ordered.len());
        let mut legal_hold_blocks = false;
        let mut retained_legal_classes: BTreeSet<DataClass> = BTreeSet::new();
        let mut not_lumi_deletable: BTreeSet<DataClass> = BTreeSet::new();

        for entry in &ordered {
            let record: DataClassRecord =
                lookup(&entry.data_class).ok_or(DeletionError::UndeclaredDataClass)?;
            let mut step = DeletionStep::new(
                entry.data_class.clone(),
                entry.reference_kind,
                entry.object_reference.as_str(),
            )?;

            // 1. A reference Lumi does not own is recorded, never claimed.
            if !entry.reference_kind.is_lumi_owned() {
                step.state = DeletionStepState::Skipped;
                step.skip_reason = Some(DeletionSkipReason::NotLumiOwned);
                step.completed_at = Some(now);
                not_lumi_deletable.insert(entry.data_class.clone());
                steps.push(step);
                continue;
            }

            // 2. A legal hold blocks deletion until an audited release.
            if hold.is_some_and(|legal| legal.covers_at(&record.class, now)) {
                step.state = DeletionStepState::Skipped;
                step.skip_reason = Some(DeletionSkipReason::LegalHold);
                step.completed_at = Some(now);
                legal_hold_blocks = true;
                steps.push(step);
                continue;
            }

            // 3. Legal/security retention is reported, not retried forever.
            if record.deletion_behavior == DeletionBehavior::RetainLegalOnly
                || !record.owner_scope.is_deletion_reachable()
            {
                step.state = DeletionStepState::Skipped;
                step.skip_reason = Some(DeletionSkipReason::RetainedLegalOnly);
                step.completed_at = Some(now);
                retained_legal_classes.insert(record.class.clone());
                steps.push(step);
                continue;
            }

            steps.push(step);
        }

        Ok(DeletionPlan {
            scope,
            steps,
            legal_hold_blocks,
            retained_legal_classes: retained_legal_classes.into_iter().collect(),
            not_lumi_deletable: not_lumi_deletable.into_iter().collect(),
        })
    }
}

/// Workflows that the `pending_deletion` cutoff must fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FencedWorkflow {
    AutomationDispatch,
    WebhookFanOut,
    NotificationFanOut,
    BillingWrites,
    ExportCreation,
    DeletionRetry,
}

impl FencedWorkflow {
    pub const ALL: [Self; 6] = [
        Self::AutomationDispatch,
        Self::WebhookFanOut,
        Self::NotificationFanOut,
        Self::BillingWrites,
        Self::ExportCreation,
        Self::DeletionRetry,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutomationDispatch => "automation_dispatch",
            Self::WebhookFanOut => "webhook_fan_out",
            Self::NotificationFanOut => "notification_fan_out",
            Self::BillingWrites => "billing_writes",
            Self::ExportCreation => "export_creation",
            Self::DeletionRetry => "deletion_retry",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|workflow| workflow.as_str() == value)
    }
}

/// What happens to a workflow relative to the deletion cutoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceAction {
    /// Before the cutoff: proceed.
    Allowed,
    /// At or after the cutoff: refuse to start new work.
    Fenced,
    /// At or after the cutoff: stop, including retries of the deletion itself.
    Cancelled,
}

impl FenceAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Fenced => "fenced",
            Self::Cancelled => "cancelled",
        }
    }

    pub const fn is_blocked(self) -> bool {
        !matches!(self, Self::Allowed)
    }
}

/// A single workflow's fence decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FenceDecision {
    pub workflow: FencedWorkflow,
    pub action: FenceAction,
    /// Stable reason code for the blocked case.
    pub reason: &'static str,
}

impl FenceDecision {
    pub const fn is_blocked(&self) -> bool {
        self.action.is_blocked()
    }
}

/// Reasons a workflow can be fenced. All three are stable codes; the first is
/// the "nothing is blocking this" marker, the other two are the gate's own.
pub const FENCE_REASON_ALLOWED: &str = "deletion_fence_not_applied";
pub const FENCE_REASON_CUTOFF_REACHED: &str = "deletion_cutoff_reached";
pub const FENCE_REASON_PENDING_DELETION: &str = "organization_pending_deletion";

/// Decide whether a delayed job may act.
///
/// The gate's rule is not "the organization is inactive" but "after the cutoff,
/// automation dispatch, webhook/notification fan-out, billing writes, export
/// creation, and deletion retries are fenced/cancelled so delayed jobs cannot
/// resurrect deleted data". Deletion *retries* are `cancelled` rather than
/// `fenced`: the job is over, so continuing it is exactly the resurrection the
/// rule forbids. A missing cutoff means the job has not been frozen yet, so
/// only a pre-existing `pending_deletion` fence applies.
pub fn decide_fence(
    workflow: FencedWorkflow,
    cutoff_at: Option<u64>,
    organization_pending_deletion: bool,
    now: u64,
) -> FenceDecision {
    let after_cutoff = cutoff_at.is_some_and(|cutoff| now >= cutoff);
    if after_cutoff {
        let action = match workflow {
            FencedWorkflow::DeletionRetry => FenceAction::Cancelled,
            _ => FenceAction::Fenced,
        };
        return FenceDecision {
            workflow,
            action,
            reason: FENCE_REASON_CUTOFF_REACHED,
        };
    }
    if organization_pending_deletion {
        let action = match workflow {
            FencedWorkflow::DeletionRetry => FenceAction::Cancelled,
            _ => FenceAction::Fenced,
        };
        return FenceDecision {
            workflow,
            action,
            reason: FENCE_REASON_PENDING_DELETION,
        };
    }
    FenceDecision {
        workflow,
        action: FenceAction::Allowed,
        reason: FENCE_REASON_ALLOWED,
    }
}

/// An organization role, reduced to what a deletion request must know.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgRole {
    Owner,
    Admin,
    Member,
    Viewer,
}

impl OrgRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
            Self::Viewer => "viewer",
        }
    }

    /// Roles that block an account deletion until the user leaves or transfers.
    pub const fn blocks_account_deletion(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }
}

impl fmt::Display for OrgRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One organization relationship that must be resolved before an account
/// deletion can proceed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrgMembershipRef {
    pub org_id: String,
    pub role: OrgRole,
    /// Server-resolved: whether the org's policy allows the user to leave or
    /// transfer out of it.
    pub exit_possible: bool,
}

/// Decide whether an account deletion may be requested.
///
/// A user must leave or transfer every organization in which they hold an
/// owner/admin role. The gate's stable result for a blocked request is
/// `deletion_requires_org_exit`; this function never silently proceeds and
/// never asks the caller to guess which org blocked it.
pub fn evaluate_account_deletion_exit(
    memberships: &[OrgMembershipRef],
) -> Result<(), DeletionError> {
    if memberships
        .iter()
        .any(|membership| membership.role.blocks_account_deletion() && !membership.exit_possible)
    {
        return Err(DeletionError::RequiresOrgExit);
    }
    Ok(())
}

/// Reject a second deletion job for a scope that already has an active one.
/// The persistence layer enforces uniqueness; this keeps the pure model aligned
/// with it so a caller cannot plan two conflicting jobs.
pub fn ensure_no_scope_conflict(
    requested: &DeletionTarget,
    active: &[DeletionTarget],
) -> Result<(), DeletionError> {
    if active.iter().any(|target| target == requested) {
        return Err(DeletionError::ScopeConflict);
    }
    Ok(())
}

/// Verify the typed confirmation and reauthentication for an account deletion
/// request. The gate requires both, and the stable result is
/// `deletion_reauth_required`.
pub fn verify_account_deletion_request(
    confirmation: &TypedConfirmation,
    now: u64,
) -> Result<(), DeletionError> {
    confirmation
        .verify(DELETION_CONFIRMATION_PHRASE, now)
        .map_err(|error| match error {
            ExportError::ConfirmationMismatch | ExportError::ReauthenticationRequired => {
                DeletionError::ReauthenticationRequired
            }
            _ => DeletionError::InvalidScope,
        })
}

/// Deletion validation failures, mapped onto the gate's stable reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeletionError {
    InvalidScope,
    InvalidObjectReference,
    InvalidFailureCode,
    InvalidStateTransition,
    UndeclaredDataClass,
    EmptyInventory,
    PlanTooLarge,
    DuplicateReference,
    NotResumable,
    PermissionDenied,
    LegalHold,
    ScopeConflict,
    RequiresOrgExit,
    ReauthenticationRequired,
}

impl DeletionError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidScope
            | Self::InvalidObjectReference
            | Self::InvalidFailureCode
            | Self::InvalidStateTransition
            | Self::UndeclaredDataClass
            | Self::EmptyInventory
            | Self::PlanTooLarge
            | Self::DuplicateReference => "data_policy_invalid",
            Self::NotResumable => "deletion_not_resumable",
            Self::PermissionDenied => "permission_denied",
            Self::LegalHold => "deletion_legal_hold",
            Self::ScopeConflict => "deletion_scope_conflict",
            Self::RequiresOrgExit => "deletion_requires_org_exit",
            Self::ReauthenticationRequired => "deletion_reauth_required",
        }
    }
}

impl fmt::Display for DeletionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for DeletionError {}
