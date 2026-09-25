//! D1-backed persistence operations for frozen P01 infrastructure contracts.
//!
//! Repository code owns SQL and row mapping. Callers supply trusted domain
//! values; all values are bound parameters and authorization stays outside this
//! layer.

mod device;
mod idempotency;
mod identity;
mod organizations;
mod outbox;
mod security;

pub use device::{DeviceAuthorizationRecord, DeviceAuthorizationRepository};
pub use idempotency::{IdempotencyClaimToken, IdempotencyLookup, IdempotencyRepository};
pub use identity::{
    ChallengeRecord, IdentityRecord, IdentityRepository, SessionRecord, SessionSummary, UserRecord,
};
pub use organizations::{
    InvitationRecord, MembershipRecord, OrganizationRecord, OrganizationRepository,
    OrganizationSummary, TeamRecord,
};
pub use outbox::OutboxRepository;
pub use security::{SecurityEventInput, SecurityEventRecord, SecurityEventRepository};
