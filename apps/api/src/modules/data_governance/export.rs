//! Export category manifest, snapshot cutoff, and the export job state machine.
//!
//! Three properties from the gate drive this module:
//!
//! 1. A request may select only categories allowed by the *current* scope. A
//!    personal export is a strict subset of an organization export, so the same
//!    planner rejects a personal request that names organization, device, run,
//!    billing, or audit data. That is the "export cannot include another org's
//!    data" acceptance criterion expressed as a type-level scope rule.
//! 2. The category manifest and snapshot cutoff are frozen at request time and
//!    a retry reuses them byte-for-byte. [`manifest_is_stable`] is the check a
//!    retry path must pass, and it deliberately ignores request ordering: a
//!    canonical manifest is a sorted set, not a list.
//! 3. `ready` is the only state that may mint a download grant, and the grant
//!    is re-authorized at download time. ADR 0006 forbids a permanent or
//!    bearer object URL, so nothing here produces a URL at all — only an
//!    expiry and a scope binding that the download route re-checks.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::registry::{DataClassRecord, ExportBehavior, OwnerScope};

/// Most categories one request may name. The gate freezes exactly eight, so a
/// larger list can only be a bug or an attempt to force unbounded collection.
pub const MAX_EXPORT_CATEGORIES: usize = 8;

/// Longest scope identifier accepted in a manifest. IDs are opaque, so the
/// only thing to check is that the value is bounded and free of control bytes.
pub const MAX_SCOPE_ID_LEN: usize = 64;

/// Default export artifact lifetime, matching the frozen
/// `default_export_expiry_seconds` baseline of 86 400 seconds (24 hours).
pub const DEFAULT_EXPORT_EXPIRY_SECONDS: u64 = 86_400;

/// Longest artifact lifetime the persistence layer accepts (seven days). ADR
/// 0006 requires a short-lived object; a tenant cannot turn this into an
/// archive.
pub const MAX_EXPORT_EXPIRY_SECONDS: u64 = 604_800;

/// The typed confirmation a personal export or account deletion must carry.
/// Requiring the exact phrase is what makes the action deliberate rather than
/// a mis-click; the phrase is compared verbatim.
pub const EXPORT_CONFIRMATION_PHRASE: &str = "EXPORT MY DATA";
pub const DELETION_CONFIRMATION_PHRASE: &str = "DELETE MY ACCOUNT";

/// How long a reauthentication grant stays acceptable for a personal data
/// action. The gate requires reauthentication, not a fresh login ceremony.
pub const MAX_REAUTHENTICATION_AGE_SECONDS: u64 = 900;

/// An explicit export category. The eight values are the frozen category list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportCategory {
    Identity,
    Organization,
    Devices,
    RunsMetadata,
    UsageBilling,
    AuditRedacted,
    Notifications,
    DataGovernance,
}

impl ExportCategory {
    pub const ALL: [Self; 8] = [
        Self::Identity,
        Self::Organization,
        Self::Devices,
        Self::RunsMetadata,
        Self::UsageBilling,
        Self::AuditRedacted,
        Self::Notifications,
        Self::DataGovernance,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Organization => "organization",
            Self::Devices => "devices",
            Self::RunsMetadata => "runs_metadata",
            Self::UsageBilling => "usage_billing",
            Self::AuditRedacted => "audit_redacted",
            Self::Notifications => "notifications",
            Self::DataGovernance => "data_governance",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|category| category.as_str() == value)
    }

    /// Owner scope whose data the category covers. A request may only name a
    /// category whose owner scope its own scope can reach.
    pub const fn owner_scope(self) -> OwnerScope {
        match self {
            Self::Identity | Self::Notifications => OwnerScope::User,
            Self::Organization | Self::Devices | Self::RunsMetadata | Self::DataGovernance => {
                OwnerScope::Organization
            }
            Self::UsageBilling => OwnerScope::Organization,
            Self::AuditRedacted => OwnerScope::Platform,
        }
    }

    /// True when a personal (user) export may request the category. Only
    /// user-owned data qualifies: organization, device, run, billing, and audit
    /// data belong to a tenant, not to an individual account.
    pub const fn allowed_for_personal_export(self) -> bool {
        matches!(
            self,
            Self::Identity | Self::Notifications | Self::DataGovernance
        )
    }

    /// True when an organization export may request the category.
    pub const fn allowed_for_organization_export(self) -> bool {
        true
    }
}

impl fmt::Display for ExportCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Wire format of the packaged artifact.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    #[default]
    Json,
    Jsonl,
    Csv,
}

impl ExportFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Jsonl => "jsonl",
            Self::Csv => "csv",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "json" => Some(Self::Json),
            "jsonl" => Some(Self::Jsonl),
            "csv" => Some(Self::Csv),
            _ => None,
        }
    }
}

/// Who the export is for. `User` and `Organization` never mix: the persistence
/// layer stores one scope kind and one scope id, and this type keeps them
/// consistent before that boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "scope_type", content = "scope_id", rename_all = "snake_case")]
pub enum ExportScope {
    User(String),
    Organization(String),
}

impl ExportScope {
    pub fn new(scope_type: &str, scope_id: impl Into<String>) -> Result<Self, ExportError> {
        let scope_id = scope_id.into();
        if scope_id.is_empty()
            || scope_id.len() > MAX_SCOPE_ID_LEN
            || scope_id.chars().any(char::is_control)
        {
            return Err(ExportError::InvalidScope);
        }
        match scope_type {
            "user" => Ok(Self::User(scope_id)),
            "organization" => Ok(Self::Organization(scope_id)),
            _ => Err(ExportError::InvalidScope),
        }
    }

    pub const fn scope_type(&self) -> &'static str {
        match self {
            Self::User(_) => "user",
            Self::Organization(_) => "organization",
        }
    }

    pub fn scope_id(&self) -> &str {
        match self {
            Self::User(id) | Self::Organization(id) => id,
        }
    }

    pub const fn is_personal(&self) -> bool {
        matches!(self, Self::User(_))
    }

    /// True when `self` may include `category`. A user scope never reaches
    /// tenant-owned or platform-owned data; that is the cross-tenant negative.
    pub const fn allows(&self, category: ExportCategory) -> bool {
        match self {
            Self::User(_) => category.allowed_for_personal_export(),
            Self::Organization(_) => category.allowed_for_organization_export(),
        }
    }

    /// True when two scopes are equal, used to keep a retry bound to the
    /// original request's scope.
    pub fn is_same_scope(&self, other: &Self) -> bool {
        self.scope_type() == other.scope_type() && self.scope_id() == other.scope_id()
    }
}

/// A typed confirmation plus its reauthentication evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedConfirmation {
    pub phrase: String,
    pub reauthenticated_at: u64,
}

impl TypedConfirmation {
    pub fn new(phrase: impl Into<String>, reauthenticated_at: u64) -> Self {
        Self {
            phrase: phrase.into(),
            reauthenticated_at,
        }
    }

    /// Verify the exact phrase and that the reauthentication is recent enough.
    pub fn verify(&self, expected_phrase: &str, now: u64) -> Result<(), ExportError> {
        if self.phrase != expected_phrase {
            return Err(ExportError::ConfirmationMismatch);
        }
        if self.reauthenticated_at > now
            || now.saturating_sub(self.reauthenticated_at) > MAX_REAUTHENTICATION_AGE_SECONDS
        {
            return Err(ExportError::ReauthenticationRequired);
        }
        Ok(())
    }
}

/// An export request as received, before validation.
///
/// `cutoff_at` is caller-resolved from the server clock. A client may not
/// supply its own snapshot boundary, so the field is documented as a
/// server-owned value even though the struct is constructible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportRequest {
    pub requested_by: String,
    pub scope: ExportScope,
    pub categories: Vec<ExportCategory>,
    pub cutoff_at: u64,
    pub format: ExportFormat,
    pub confirmation: Option<TypedConfirmation>,
}

impl ExportRequest {
    /// A personal export always requires reauthentication and a typed
    /// confirmation, even when the category set is small.
    pub fn requires_typed_confirmation(&self) -> bool {
        self.scope.is_personal()
    }

    /// Validate and freeze the request into a canonical manifest.
    ///
    /// Order is fixed: scope shape, then category cardinality/bounds, then
    /// per-category scope eligibility, then the personal reauthentication
    /// requirement. A retry reuses the returned manifest unchanged.
    pub fn into_manifest(self, now: u64) -> Result<ExportManifest, ExportError> {
        if self.requested_by.trim().is_empty() || self.requested_by.len() > MAX_SCOPE_ID_LEN {
            return Err(ExportError::InvalidRequester);
        }
        if self.categories.is_empty() {
            return Err(ExportError::CategorySetEmpty);
        }
        if self.categories.len() > MAX_EXPORT_CATEGORIES {
            return Err(ExportError::CategorySetTooLarge);
        }
        if let Some(outside) = self
            .categories
            .iter()
            .find(|category| !self.scope.allows(**category))
        {
            return Err(ExportError::CategoryOutsideScope(*outside));
        }
        if self.requires_typed_confirmation() {
            let confirmation = self
                .confirmation
                .as_ref()
                .ok_or(ExportError::ReauthenticationRequired)?;
            confirmation.verify(EXPORT_CONFIRMATION_PHRASE, now)?;
        }
        Ok(ExportManifest {
            scope: self.scope,
            categories: canonicalize(self.categories),
            cutoff_at: self.cutoff_at,
            format: self.format,
        })
    }
}

fn canonicalize(categories: Vec<ExportCategory>) -> Vec<ExportCategory> {
    let unique: BTreeSet<ExportCategory> = categories.into_iter().collect();
    unique.into_iter().collect()
}

/// The frozen, canonical export manifest.
///
/// This is the artifact of a *request*, not of a collection run: it is stored
/// with the job and every retry reads it back, so a retry can never widen the
/// category set or move the snapshot boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportManifest {
    pub scope: ExportScope,
    /// Sorted, deduplicated. Two manifests of the same request are equal.
    pub categories: Vec<ExportCategory>,
    pub cutoff_at: u64,
    pub format: ExportFormat,
}

impl ExportManifest {
    pub fn new(
        scope: ExportScope,
        categories: Vec<ExportCategory>,
        cutoff_at: u64,
        format: ExportFormat,
    ) -> Self {
        Self {
            scope,
            categories: canonicalize(categories),
            cutoff_at,
            format,
        }
    }

    /// True when `other` is the same manifest. A retry path must require this
    /// before reusing a stored manifest.
    pub fn is_stable(&self, other: &Self) -> bool {
        manifest_is_stable(self, other)
    }

    pub fn category_keys(&self) -> Vec<&'static str> {
        self.categories
            .iter()
            .map(|category| category.as_str())
            .collect()
    }

    /// Reject a manifest whose categories are no longer exportable, or whose
    /// class set is empty. A class whose export behavior changed to `never`
    /// after the request was made must not be collected.
    pub fn assert_collectable(&self, records: &[DataClassRecord]) -> Result<(), ExportError> {
        if records.is_empty() {
            return Err(ExportError::CategorySetEmpty);
        }
        if records.iter().any(|record| {
            !record.is_exportable() || record.export_behavior == ExportBehavior::Never
        }) {
            return Err(ExportError::CategoryNotExportable);
        }
        Ok(())
    }
}

/// True when two manifests describe the same request.
///
/// Order-independent by construction: a manifest is a canonical set, so a
/// client that submits the same categories in a different order has not
/// changed the request, and a client that submits an *extra* category has.
pub fn manifest_is_stable(left: &ExportManifest, right: &ExportManifest) -> bool {
    left.categories == right.categories
        && left.cutoff_at == right.cutoff_at
        && left.format == right.format
        && left.scope.is_same_scope(&right.scope)
}

/// Frozen export job states and their transitions.
///
/// ```text
/// requested → queued → collecting → packaging → verifying → ready → expired
///                          ↘ retry_wait → collecting
///                          ↘ failed
///                          ↘ cancelled
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportJobState {
    #[default]
    Requested,
    Queued,
    Collecting,
    Packaging,
    Verifying,
    Ready,
    Expired,
    RetryWait,
    Failed,
    Cancelled,
}

impl ExportJobState {
    pub const ALL: [Self; 10] = [
        Self::Requested,
        Self::Queued,
        Self::Collecting,
        Self::Packaging,
        Self::Verifying,
        Self::Ready,
        Self::Expired,
        Self::RetryWait,
        Self::Failed,
        Self::Cancelled,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Queued => "queued",
            Self::Collecting => "collecting",
            Self::Packaging => "packaging",
            Self::Verifying => "verifying",
            Self::Ready => "ready",
            Self::Expired => "expired",
            Self::RetryWait => "retry_wait",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.as_str() == value)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Expired | Self::Failed | Self::Cancelled)
    }

    /// `ready` is the only state that may mint a download grant. Every other
    /// state, including `verifying` and `retry_wait`, answers
    /// `export_not_ready`.
    pub const fn can_mint_download_grant(self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Whether entering this state counts as a retry attempt. Used to decide
    /// whether `attempt` increments on a transition.
    pub const fn is_retry(self) -> bool {
        matches!(self, Self::RetryWait)
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Requested => matches!(next, Self::Queued | Self::Cancelled),
            Self::Queued => matches!(next, Self::Collecting | Self::Failed | Self::Cancelled),
            Self::Collecting => matches!(
                next,
                Self::Packaging | Self::RetryWait | Self::Failed | Self::Cancelled
            ),
            Self::Packaging => matches!(
                next,
                Self::Verifying | Self::RetryWait | Self::Failed | Self::Cancelled
            ),
            Self::Verifying => matches!(
                next,
                Self::Ready | Self::RetryWait | Self::Failed | Self::Cancelled
            ),
            // A retry re-enters collection, never packaging, so a retry cannot
            // skip verification on an already-packaged object.
            Self::RetryWait => matches!(next, Self::Collecting | Self::Failed | Self::Cancelled),
            // A ready artifact only leaves through expiry; a failed package
            // re-enters the pipeline through `retry_wait` first.
            Self::Ready => matches!(next, Self::Expired),
            Self::Expired | Self::Failed | Self::Cancelled => false,
        }
    }

    pub const fn can_transition(from: Self, to: Self) -> bool {
        from.can_transition_to(to)
    }

    pub fn transition(self, next: Self) -> Result<Self, ExportError> {
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(ExportError::InvalidStateTransition)
        }
    }
}

impl fmt::Display for ExportJobState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The facts a download request needs, all resolved server-side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownloadAuthorization {
    pub state: ExportJobState,
    pub artifact_expires_at: Option<u64>,
    /// The grant must be bound to the same scope as the job.
    pub grant_scope: ExportScope,
    /// Re-authorization of the principal is a caller fact, not a claim here.
    pub principal_reauthorized: bool,
    pub legal_hold_active: bool,
}

/// Decide whether a download grant may be minted or used.
///
/// The gate requires `ready`, a re-check of authorization, a scope binding, and
/// an expiry. A legal hold keeps the artifact bytes in place for the audit
/// trail but still blocks a new grant.
pub fn authorize_download(
    job: &DownloadAuthorization,
    now: u64,
) -> Result<ExportDownloadGrant, ExportError> {
    if !job.principal_reauthorized {
        return Err(ExportError::ReauthenticationRequired);
    }
    if job.legal_hold_active {
        return Err(ExportError::LegalHoldActive);
    }
    if !job.state.can_mint_download_grant() {
        return Err(ExportError::NotReady);
    }
    let Some(expires_at) = job.artifact_expires_at else {
        return Err(ExportError::ArtifactUnavailable);
    };
    if now >= expires_at {
        return Err(ExportError::Expired);
    }
    let remaining = expires_at.saturating_sub(now);
    if remaining > MAX_EXPORT_EXPIRY_SECONDS {
        return Err(ExportError::ArtifactUnavailable);
    }
    Ok(ExportDownloadGrant {
        scope: job.grant_scope.clone(),
        artifact_expires_at: expires_at,
        grant_expires_at: now.saturating_add(remaining.min(DEFAULT_EXPORT_EXPIRY_SECONDS)),
    })
}

/// A re-authorized, short-lived download authorization.
///
/// It carries no URL. The download route re-checks the principal, the job
/// scope, the job state, and the expiry, then streams the private R2 object
/// through the Worker; ADR 0006 forbids a permanent or bearer object URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportDownloadGrant {
    pub scope: ExportScope,
    pub artifact_expires_at: u64,
    pub grant_expires_at: u64,
}

impl ExportDownloadGrant {
    pub const fn is_usable_at(&self, now: u64) -> bool {
        now < self.grant_expires_at && now < self.artifact_expires_at
    }
}

/// Export validation failures, mapped onto the gate's stable reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExportError {
    InvalidRequester,
    InvalidScope,
    ConfirmationMismatch,
    ReauthenticationRequired,
    CategorySetEmpty,
    CategorySetTooLarge,
    CategoryOutsideScope(ExportCategory),
    CategoryNotExportable,
    InvalidStateTransition,
    NotReady,
    Expired,
    ArtifactUnavailable,
    LegalHoldActive,
}

impl ExportError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRequester | Self::InvalidScope => "data_policy_invalid",
            Self::ConfirmationMismatch | Self::ReauthenticationRequired => {
                "deletion_reauth_required"
            }
            Self::CategorySetEmpty
            | Self::CategorySetTooLarge
            | Self::CategoryOutsideScope(_)
            | Self::CategoryNotExportable => "export_category_invalid",
            Self::InvalidStateTransition => "export_not_ready",
            Self::NotReady => "export_not_ready",
            Self::Expired => "export_expired",
            Self::ArtifactUnavailable => "export_artifact_unavailable",
            Self::LegalHoldActive => "deletion_legal_hold",
        }
    }
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ExportError {}
