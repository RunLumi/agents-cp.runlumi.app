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
mod timestamp;

pub use context::{ActorContext, ActorType, RequestContext};
pub use error::{ApiError, ApiErrorBody, ApiErrorCode, CoreError};
pub use event::{EventEnvelope, EventType};
pub use idempotency::{
    IdempotencyKey, IdempotencyKeyDigest, IdempotencyRecord, IdempotencyScope, IdempotencyState,
    RequestFingerprint, StoredSuccess,
};
pub use identifiers::{
    ActorId, CorrelationId, DeviceId, EventId, OrganizationId, RequestId, ResourceId, SessionId,
};
pub use pagination::{Cursor, Page};
pub use timestamp::Timestamp;
