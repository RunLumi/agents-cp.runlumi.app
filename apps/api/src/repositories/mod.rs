//! D1-backed persistence operations for frozen P01 infrastructure contracts.
//!
//! Repository code owns SQL and row mapping. Callers supply trusted domain
//! values; all values are bound parameters and authorization stays outside this
//! layer.

mod ai;
mod audit;
mod authenticators;
mod budgets;
mod device;
mod devices;
mod idempotency;
mod identity;
mod organizations;
mod outbox;
mod policy;
mod projects;
mod runs;
mod security;
mod tools;
mod usage;

pub use ai::{
    AiRepository, AliasRecord, CredentialRecord, HealthRecord, InferenceRequestRecord, ModelRecord,
    PolicyRecord, ProviderRecord, RouteRecord, RouteVersionRecord, UsageRecord,
};
pub use audit::*;
pub use budgets::*;
pub use authenticators::{
    AuthenticatorRepository, CeremonyRecord, PasskeyRecord, PasswordRecord, RecoveryRecord,
};
pub use device::{DeviceAuthorizationRecord, DeviceAuthorizationRepository};
pub use devices::{
    DeviceEnrollmentInput, DeviceEnrollmentRecord, DeviceRecord, DeviceRepository,
    DeviceTokenRecord,
};
pub use idempotency::{IdempotencyClaimToken, IdempotencyLookup, IdempotencyRepository};
pub use identity::{
    ChallengeRecord, IdentityRecord, IdentityRepository, SessionRecord, SessionSummary, UserRecord,
};
pub use organizations::{
    InvitationRecord, MembershipRecord, OrganizationRecord, OrganizationRepository,
    OrganizationSummary, TeamRecord,
};
pub use outbox::OutboxRepository;
pub use policy::{PolicyAckRecord, PolicyRepository, PolicySnapshotRecord};
pub use projects::{
    NewProjectInput, ProjectGrantRecord, ProjectRecord, ProjectRepository, ProjectUpdateInput,
    WorkspaceBindingRecord,
};
pub use runs::*;
pub use security::{SecurityEventInput, SecurityEventRecord, SecurityEventRepository};
pub use tools::*;
pub use usage::*;
