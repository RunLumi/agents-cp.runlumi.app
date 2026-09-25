//! P06 data governance: the data-class registry, retention and legal hold,
//! content logging modes, export planning, and the resumable deletion planner.
//!
//! Why this module exists as pure code: F20 makes data governance a *contract*,
//! and a contract that can only be checked by reading prose does not hold. Every
//! decision here is a function of an explicit scope, the frozen registry record
//! for a data class, and a caller-supplied logical time in Unix seconds. There
//! is no D1, R2, HTTP, `worker`, async, clock, or filesystem code, so these
//! rules can be reviewed against the frozen contract and unit tested without a
//! Worker runtime, and so a persistence adapter cannot quietly substitute its
//! own retention arithmetic for the frozen one.
//!
//! Invariants the whole module obeys:
//!
//! * **Not an authorization layer.** Callers resolve the principal, membership,
//!   organization state, and permission first. Nothing here grants access, and
//!   a client-supplied scope is never treated as evidence.
//! * **Fail closed.** An undeclared data class, an unknown export category, an
//!   unknown log field, a missing retention anchor, and a retention override
//!   past the legal maximum without an audited override are all errors, never
//!   permissive defaults.
//! * **Nothing is silently destroyed.** Audit, security, billing, and
//!   certificate records are minimized, tombstoned, or legally retained.
//!   Lumi never claims to have deleted local ZCode data or an upstream
//!   provider's data; the planner records those references as skipped with a
//!   stable reason and the result carries the disclosure text.
//! * **No permanent artifact access.** Export artifacts live in a private R2
//!   bucket (ADR 0006) and are streamed through the Worker after a
//!   re-authorized, short-lived grant. This module produces no URL, and only
//!   the `ready` state can mint a grant.
//!
//! Module layout:
//!
//! * [`registry`] — the frozen data-class table and its cross-attribute rules.
//! * [`retention`] — baseline windows, legal holds, and the expiry decision.
//! * [`logging`] — content logging modes and the field-level logging allowlist.
//! * [`export`] — category manifest, snapshot cutoff, and export job states.
//! * [`deletion`] — reference traversal, ordered plans, and the fence.

pub mod deletion;
pub mod export;
pub mod logging;
pub mod registry;
pub mod retention;

#[cfg(test)]
mod tests;

pub use deletion::{
    DeletionError, DeletionInventoryEntry, DeletionJobState, DeletionPlan, DeletionPlanner,
    DeletionSkipReason, DeletionStep, DeletionStepState, DeletionTarget, FenceAction,
    FenceDecision, FencedWorkflow, OrgRole, ReferenceCoverage, ReferenceKind, ResumeAuthorization,
    StepTransition, decide_fence, ensure_no_scope_conflict, evaluate_account_deletion_exit,
    reference_coverage, verify_account_deletion_request,
};
pub use export::{
    DownloadAuthorization, ExportCategory, ExportDownloadGrant, ExportError, ExportFormat,
    ExportJobState, ExportManifest, ExportRequest, ExportScope, TypedConfirmation,
    authorize_download, manifest_is_stable,
};
pub use logging::{
    FieldClass, LogDecision, LoggingError, LoggingMode, LoggingModeChange, LoggingPolicy,
    LoggingRule, ProhibitionReason, classify_field,
};
pub use registry::{
    CLASS_COUNT, DataClass, DataClassRecord, DeletionBehavior, ExportBehavior, OwnerScope,
    RegistryError, Sensitivity, all_classes, class_set, deletion_reachable_classes,
    exportable_classes, lookup, lookup_by_key, registry,
};
pub use retention::{
    AuditedOverride, BackupLifecycle, BaselineRetention, HoldScope, LegalHold, RetentionAnchor,
    RetentionDecision, RetentionDuration, RetentionError, RetentionOverride, RetentionPolicy,
    RetentionReason, RetentionSource, RetentionWindow, baseline_retention, decide,
};
