//! Worker-independent value types shared by the API and persistence adapters.
//!
//! This module deliberately contains no Cloudflare, HTTP framework, or database
//! bindings. Runtime boundaries are responsible for generating IDs and times;
//! these types validate and preserve the frozen P01 contract.

mod context;
mod error;
mod event;
mod idempotency;
mod identifiers;
mod pagination;
mod principal;
mod timestamp;

pub use context::{ActorContext, ActorType, RequestContext};
pub use error::{ApiError, ApiErrorBody, ApiErrorCode, CoreError};
pub use event::{EventEnvelope, EventType};
pub use idempotency::{
    IdempotencyKey, IdempotencyKeyDigest, IdempotencyRecord, IdempotencyScope, IdempotencyState,
    RequestFingerprint, StoredSuccess,
};
pub use identifiers::{
    ActorId, CorrelationId, DeviceAuthorizationId, DeviceEnrollmentId, DeviceId, EventId,
    IdentityId, InvitationId, ManagedDeviceId, MembershipId, OrganizationId, PolicyAckId,
    PolicySnapshotId, ProjectId, ReauthenticationGrantId, RequestId, ResourceId, SecurityEventId,
    SessionId, TeamId, TeamMemberId, UserId, WorkspaceBindingId,
};
pub use pagination::{Cursor, Page};
pub use principal::Principal;
pub use timestamp::Timestamp;
