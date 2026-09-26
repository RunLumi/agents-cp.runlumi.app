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
mod machine;
mod pagination;
mod principal;
mod staff;
mod timestamp;

pub use context::{ActorContext, ActorType, RequestContext};
pub use error::{ApiError, ApiErrorBody, ApiErrorCode, CoreError};
pub use event::{EventEnvelope, EventType};
pub use idempotency::{
    IdempotencyKey, IdempotencyKeyDigest, IdempotencyRecord, IdempotencyScope, IdempotencyState,
    RequestFingerprint, StoredSuccess,
};
pub use identifiers::{
    ActorId, AgentDefinitionId, AgentSessionId, ApiKeyId, ApprovalId, ArtifactRefId, AutomationId,
    BillingAccountId, BudgetId, BudgetReservationId, CapabilityId, CorrelationId, CostRecordId,
    CredentialId, DeviceAuthorizationId, DeviceEnrollmentId, DeviceId, EntitlementDefinitionId,
    EntitlementGrantId, EventId, ExecutionLeaseId, IdentityId, InvitationId, KillSwitchId,
    LicenseSnapshotId, ManagedDeviceId, McpRegistrationId, MembershipId, ModelAliasId, ModelId,
    OccurrenceId, OrganizationId, PlanId, PluginInstallId, PluginPackageId, PluginPublisherId,
    PluginQuarantineId, PluginToolRegistrationId, PluginVersionId, PolicyAckId, PolicySnapshotId,
    ProjectId, ProviderEndpointId, ProviderEntitlementProjectionId, ProviderId, RateLimitPolicyId,
    ReauthenticationGrantId, RequestId, ResourceId, RouteId, RouteVersionId, RunEventId, RunId,
    ScheduleRuleId, SecurityEventId, ServiceAccountId, SessionId, StaffPrincipalId, SubscriptionId,
    SupportGrantId, TeamId, TeamMemberId, ToolCallId, ToolId, ToolPolicyId, UsageEventId,
    UsageRollupId, UserId, WorkspaceBindingId,
};
pub use machine::{
    MACHINE_KEY_SCHEME, MachineActor, MachineKey, MachineKeyError, MachineKeyMaterial,
    constant_time_eq,
};
pub use pagination::{Cursor, Page};
pub use principal::Principal;
pub use staff::{STAFF_KEY_SCHEME, StaffKey, StaffKeyError, StaffPrincipal};
pub use timestamp::Timestamp;
