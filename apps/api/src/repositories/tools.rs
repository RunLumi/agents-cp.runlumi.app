//! D1 persistence for the P05 tool/capability/MCP catalog, the tenant tool
//! policy document, tool-call references, and approval requests
//! (P05-CG `p05-cg-v1`).
//!
//! SQL is constant and fully bound (P01/P02 convention). Every query that can
//! reach tenant data carries `org_id` in its predicate so a cross-tenant
//! identifier is indistinguishable from a missing one. Invariant-bearing writes
//! (version-guarded catalog/policy/approval updates) are exposed as prepared
//! statements so callers can commit them in one D1 batch with the audit, outbox,
//! and idempotency writes.

use serde::{Deserialize, Serialize};
use worker::d1::D1PreparedStatement;

use super::devices::DeviceRecord;
use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::Timestamp,
};

/// Bound shared by the frozen `tool_call_refs.arguments_summary` column.
const ARGUMENTS_SUMMARY_MAX: usize = 2048;
/// Bound for the tenant capability-class catalog read by the decision broker.
const CAPABILITY_CATALOG_MAX: i32 = 500;
/// Bounds shared by the frozen `fingerprint` columns. The upper bound is the
/// evaluator's `MAX_FINGERPRINT_LEN`: a fingerprint the policy layer would
/// reject as malformed is not storable in the first place.
const FINGERPRINT_MIN: usize = 4;
const FINGERPRINT_MAX: usize = 128;
/// Bound shared by the frozen `tool_policies.document_json` column.
const POLICY_DOCUMENT_MAX: usize = 65_536;

const INSERT_TOOL_SQL: &str = r#"
INSERT INTO tool_definitions (
    tool_id, org_id, name, source, risk_class, capability_ids_json, fingerprint,
    lifecycle, metadata_json, version, created_by_user_id, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?11, ?11)
"#;

const TOOL_BY_ID_SQL: &str = r#"
SELECT tool_id, org_id, name, source, risk_class, capability_ids_json, fingerprint,
       lifecycle, metadata_json, version, created_by_user_id, created_at, updated_at
FROM tool_definitions
WHERE tool_id = ?1 AND org_id = ?2
LIMIT 1
"#;

const TOOL_BY_FINGERPRINT_SQL: &str = r#"
SELECT tool_id, org_id, name, source, risk_class, capability_ids_json, fingerprint,
       lifecycle, metadata_json, version, created_by_user_id, created_at, updated_at
FROM tool_definitions
WHERE org_id = ?1 AND fingerprint = ?2
LIMIT 1
"#;

const TOOLS_PAGE_SQL: &str = r#"
SELECT tool_id, org_id, name, source, risk_class, capability_ids_json, fingerprint,
       lifecycle, metadata_json, version, created_by_user_id, created_at, updated_at
FROM tool_definitions
WHERE org_id = ?1
  AND (updated_at, tool_id) < (?2, ?3)
  AND (?4 = '' OR source = ?4)
  AND (?5 = '' OR risk_class = ?5)
ORDER BY updated_at DESC, tool_id DESC
LIMIT ?6
"#;

const FIRST_TOOLS_PAGE_SQL: &str = r#"
SELECT tool_id, org_id, name, source, risk_class, capability_ids_json, fingerprint,
       lifecycle, metadata_json, version, created_by_user_id, created_at, updated_at
FROM tool_definitions
WHERE org_id = ?1
  AND (?2 = '' OR source = ?2)
  AND (?3 = '' OR risk_class = ?3)
ORDER BY updated_at DESC, tool_id DESC
LIMIT ?4
"#;

const UPDATE_TOOL_SQL: &str = r#"
UPDATE tool_definitions
SET name = ?2, source = ?3, risk_class = ?4, capability_ids_json = ?5, fingerprint = ?6,
    lifecycle = ?7, metadata_json = ?8, version = version + 1, updated_at = ?9
WHERE tool_id = ?1 AND org_id = ?10 AND version = ?11
"#;

const ASSERT_TOOL_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM tool_definitions WHERE tool_id = ?1 AND org_id = ?2 AND version = ?3
)
"#;

const INSERT_MCP_SQL: &str = r#"
INSERT INTO mcp_registrations (
    mcp_registration_id, org_id, source, transport, endpoint_metadata_json,
    command_metadata_json, allowed_origins_json, required_secret_handles_json,
    tool_fingerprint, tool_list_json, policy_status, version, created_by_user_id,
    created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 1, ?12, ?13, ?13)
"#;

const MCP_BY_ID_SQL: &str = r#"
SELECT mcp_registration_id, org_id, source, transport, endpoint_metadata_json,
       command_metadata_json, allowed_origins_json, required_secret_handles_json,
       tool_fingerprint, tool_list_json, policy_status, version, created_by_user_id,
       created_at, updated_at
FROM mcp_registrations
WHERE mcp_registration_id = ?1 AND org_id = ?2
LIMIT 1
"#;

const MCP_BY_FINGERPRINT_SQL: &str = r#"
SELECT mcp_registration_id, org_id, source, transport, endpoint_metadata_json,
       command_metadata_json, allowed_origins_json, required_secret_handles_json,
       tool_fingerprint, tool_list_json, policy_status, version, created_by_user_id,
       created_at, updated_at
FROM mcp_registrations
WHERE org_id = ?1 AND tool_fingerprint = ?2
LIMIT 1
"#;

const MCP_PAGE_SQL: &str = r#"
SELECT mcp_registration_id, org_id, source, transport, endpoint_metadata_json,
       command_metadata_json, allowed_origins_json, required_secret_handles_json,
       tool_fingerprint, tool_list_json, policy_status, version, created_by_user_id,
       created_at, updated_at
FROM mcp_registrations
WHERE org_id = ?1 AND (updated_at, mcp_registration_id) < (?2, ?3)
ORDER BY updated_at DESC, mcp_registration_id DESC
LIMIT ?4
"#;

const FIRST_MCP_PAGE_SQL: &str = r#"
SELECT mcp_registration_id, org_id, source, transport, endpoint_metadata_json,
       command_metadata_json, allowed_origins_json, required_secret_handles_json,
       tool_fingerprint, tool_list_json, policy_status, version, created_by_user_id,
       created_at, updated_at
FROM mcp_registrations
WHERE org_id = ?1
ORDER BY updated_at DESC, mcp_registration_id DESC
LIMIT ?2
"#;

const UPDATE_MCP_SQL: &str = r#"
UPDATE mcp_registrations
SET source = ?2, transport = ?3, endpoint_metadata_json = ?4, command_metadata_json = ?5,
    allowed_origins_json = ?6, required_secret_handles_json = ?7, tool_fingerprint = ?8,
    tool_list_json = ?9, policy_status = ?10, version = version + 1, updated_at = ?11
WHERE mcp_registration_id = ?1 AND org_id = ?12 AND version = ?13
"#;

const ASSERT_MCP_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM mcp_registrations
    WHERE mcp_registration_id = ?1 AND org_id = ?2 AND version = ?3
)
"#;

const TOOL_POLICY_BY_SCOPE_SQL: &str = r#"
SELECT tool_policy_id, org_id, project_id, policy_version, document_json, version,
       created_by_user_id, created_at, updated_at
FROM tool_policies
WHERE org_id = ?1 AND COALESCE(project_id, '') = COALESCE(?2, '')
LIMIT 1
"#;

const INSERT_TOOL_POLICY_SQL: &str = r#"
INSERT INTO tool_policies (
    tool_policy_id, org_id, project_id, policy_version, document_json, version,
    created_by_user_id, created_at, updated_at
) VALUES (?1, ?2, NULL, 1, ?3, 1, ?4, ?5, ?5)
"#;

const UPDATE_TOOL_POLICY_SQL: &str = r#"
UPDATE tool_policies
SET document_json = ?2, policy_version = policy_version + 1, version = version + 1,
    updated_at = ?3
WHERE tool_policy_id = ?1 AND org_id = ?4 AND version = ?5
"#;

const ASSERT_TOOL_POLICY_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM tool_policies WHERE tool_policy_id = ?1 AND org_id = ?2 AND version = ?3
)
"#;

const ASSERT_TOOL_POLICY_ABSENT_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE EXISTS (
    SELECT 1 FROM tool_policies WHERE org_id = ?1 AND COALESCE(project_id, '') = ''
)
"#;

/// Resolve one run and its owning user by run ID alone.
///
/// The tool-decision broker receives no organization, project, device, or
/// principal claim from the execution host, so scope must be resolvable from a
/// run ID without a caller-supplied organization. Run and agent persistence
/// stays owned by `repositories::runs`; this projection exists only because the
/// broker has to resolve scope before it can authorize anything.
const RUN_TOOL_SCOPE_SQL: &str = r#"
SELECT r.run_id, r.org_id, r.project_id, r.agent_session_id, r.agent_definition_id, r.device_id,
       r.state, r.principal_user_id, u.email AS user_email,
       u.display_name AS user_display_name, u.email_verified AS user_email_verified
FROM runs r
JOIN users u ON u.user_id = r.principal_user_id
WHERE r.run_id = ?1
LIMIT 1
"#;

const INSERT_TOOL_CALL_REF_SQL: &str = r#"
INSERT INTO tool_call_refs (
    tool_call_id, org_id, project_id, run_id, tool_id, tool_fingerprint, risk_class,
    arguments_summary, status, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'requested', ?9, ?9)
"#;

const TOOL_CALL_REF_BY_ID_SQL: &str = r#"
SELECT tool_call_id, org_id, project_id, run_id, tool_id, tool_fingerprint, risk_class,
       arguments_summary, status, created_at, updated_at
FROM tool_call_refs
WHERE run_id = ?1 AND tool_call_id = ?2
LIMIT 1
"#;

/// Advance a requested call to a terminal broker state. A call that already
/// carries a decision is never rewritten, so a later allow cannot overwrite a
/// recorded denial.
const UPDATE_TOOL_CALL_STATUS_SQL: &str = r#"
UPDATE tool_call_refs
SET status = ?3, updated_at = ?4
WHERE run_id = ?1 AND tool_call_id = ?2 AND status IN ('requested', 'allowed')
"#;

const CAPABILITIES_FOR_ORG_SQL: &str = r#"
SELECT capability_id, org_id, capability_key, display_name, risk_class, metadata_json,
       version, created_at, updated_at
FROM capability_definitions
WHERE org_id IS NULL OR org_id = ?1
ORDER BY capability_key ASC
LIMIT ?2
"#;

const DEVICE_FOR_TOKEN_SQL: &str = r#"
SELECT d.device_id, d.org_id, d.enrolled_by_user_id, d.name, d.platform, d.app_version,
       d.public_key, d.key_fingerprint, d.status, d.capabilities, d.capability_reported_at,
       d.last_seen_at, d.revoked_at, d.revoked_by_user_id, d.created_at, d.updated_at
FROM device_tokens t
JOIN devices d ON d.device_id = t.device_id
WHERE t.token_hash = ?1 AND t.expires_at > ?2 AND d.status = 'active'
LIMIT 1
"#;

const INSERT_APPROVAL_SQL: &str = r#"
INSERT INTO approval_requests (
    approval_id, org_id, project_id, run_id, agent_session_id, tool_call_id, tool_id,
    tool_fingerprint, arguments_hash, requested_by_device_id, policy_snapshot_id,
    policy_version, risk_class, approval_mode, status, arguments_summary,
    requested_by_principal_id, requested_at, expires_at, version
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 'pending', ?15, ?16, ?17, ?18, 1)
"#;

const INSERT_RESOLVED_APPROVAL_SQL: &str = r#"
INSERT INTO approval_requests (
    approval_id, org_id, project_id, run_id, agent_session_id, tool_call_id, tool_id,
    tool_fingerprint, arguments_hash, requested_by_device_id, policy_snapshot_id,
    policy_version, risk_class, approval_mode, status, decision, arguments_summary,
    requested_by_principal_id, requested_at, expires_at, resolved_by_principal_id,
    resolved_at, resolution_reason, version
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, 1)
"#;

const APPROVAL_BY_ID_SQL: &str = r#"
SELECT approval_id, org_id, project_id, run_id, tool_call_id, tool_id, tool_fingerprint,
       risk_class, approval_mode, status, arguments_summary, requested_by_principal_id,
       requested_at, expires_at, resolved_by_principal_id, resolved_at, resolution_reason,
       version
FROM approval_requests
WHERE approval_id = ?1 AND org_id = ?2
LIMIT 1
"#;

const APPROVAL_BY_TOOL_CALL_SQL: &str = r#"
SELECT approval_id, org_id, project_id, run_id, tool_call_id, tool_id, tool_fingerprint,
       risk_class, approval_mode, status, arguments_summary, requested_by_principal_id,
       requested_at, expires_at, resolved_by_principal_id, resolved_at, resolution_reason,
       version
FROM approval_requests
WHERE run_id = ?1 AND tool_call_id = ?2
LIMIT 1
"#;

/// A live, already approved session-scope grant for the same run, tool,
/// fingerprint, and risk-relevant argument summary. This is the only way a
/// second tool call in one run may proceed without a new human decision.
const REUSABLE_SESSION_APPROVAL_SQL: &str = r#"
SELECT approval_id, org_id, project_id, run_id, tool_call_id, tool_id, tool_fingerprint,
       risk_class, approval_mode, status, arguments_summary, requested_by_principal_id,
       requested_at, expires_at, resolved_by_principal_id, resolved_at, resolution_reason,
       version
FROM approval_requests
WHERE run_id = ?1
  AND tool_id = ?2
  AND tool_fingerprint = ?3
  AND arguments_summary = ?4
  AND approval_mode = 'session'
  AND status = 'approved'
  AND expires_at > ?5
ORDER BY resolved_at ASC, approval_id ASC
LIMIT 1
"#;

const APPROVALS_PAGE_SQL: &str = r#"
SELECT approval_id, org_id, project_id, run_id, tool_call_id, tool_id, tool_fingerprint,
       risk_class, approval_mode, status, arguments_summary, requested_by_principal_id,
       requested_at, expires_at, resolved_by_principal_id, resolved_at, resolution_reason,
       version
FROM approval_requests
WHERE org_id = ?1
  AND (requested_at, approval_id) < (?2, ?3)
  AND (?4 = '' OR status = ?4)
  AND (?5 = '' OR run_id = ?5)
ORDER BY requested_at DESC, approval_id DESC
LIMIT ?6
"#;

const FIRST_APPROVALS_PAGE_SQL: &str = r#"
SELECT approval_id, org_id, project_id, run_id, tool_call_id, tool_id, tool_fingerprint,
       risk_class, approval_mode, status, arguments_summary, requested_by_principal_id,
       requested_at, expires_at, resolved_by_principal_id, resolved_at, resolution_reason,
       version
FROM approval_requests
WHERE org_id = ?1
  AND (?2 = '' OR status = ?2)
  AND (?3 = '' OR run_id = ?3)
ORDER BY requested_at DESC, approval_id DESC
LIMIT ?4
"#;

/// Terminalize a pending approval. `expected_version` and the unexpired window
/// are part of the predicate, so a concurrent or late resolver cannot win.
const RESOLVE_APPROVAL_SQL: &str = r#"
UPDATE approval_requests
SET status = ?3,
    decision = CASE WHEN ?3 IN ('approved', 'denied') THEN ?3 ELSE NULL END,
    resolved_by_principal_id = ?4, resolved_at = ?5, resolution_reason = ?6,
    version = version + 1
WHERE approval_id = ?1 AND org_id = ?2 AND status = 'pending' AND version = ?7
  AND expires_at > ?5
"#;

/// Expire a pending approval whose window closed. The `resolved_*` columns stay
/// populated because the frozen table requires them for every non-pending row.
const EXPIRE_APPROVAL_SQL: &str = r#"
UPDATE approval_requests
SET status = 'expired', resolved_by_principal_id = ?2, resolved_at = ?3,
    resolution_reason = 'expired', version = version + 1
WHERE approval_id = ?1 AND status = 'pending' AND expires_at <= ?3
"#;

const ASSERT_APPROVAL_PENDING_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM approval_requests
    WHERE approval_id = ?1 AND org_id = ?2 AND status = 'pending' AND version = ?3
      AND expires_at > ?4
)
"#;

/// The expiry path asserts the pending state and version without the window
/// predicate, because reaching this statement means the window already closed.
const ASSERT_APPROVAL_PENDING_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM approval_requests
    WHERE approval_id = ?1 AND org_id = ?2 AND status = 'pending' AND version = ?3
)
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinitionRecord {
    pub tool_id: String,
    pub org_id: String,
    pub name: String,
    pub source: String,
    pub risk_class: String,
    pub capability_ids_json: String,
    pub fingerprint: String,
    pub lifecycle: String,
    pub metadata_json: String,
    pub version: i64,
    pub created_by_user_id: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityDefinitionRecord {
    pub capability_id: String,
    pub org_id: Option<String>,
    pub capability_key: String,
    pub display_name: String,
    pub risk_class: String,
    pub metadata_json: String,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRegistrationRecord {
    pub mcp_registration_id: String,
    pub org_id: String,
    pub source: String,
    pub transport: String,
    pub endpoint_metadata_json: String,
    pub command_metadata_json: String,
    pub allowed_origins_json: String,
    pub required_secret_handles_json: String,
    pub tool_fingerprint: Option<String>,
    pub tool_list_json: String,
    pub policy_status: String,
    pub version: i64,
    pub created_by_user_id: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolPolicyRecord {
    pub tool_policy_id: String,
    pub org_id: String,
    pub project_id: Option<String>,
    pub policy_version: i64,
    pub document_json: String,
    pub version: i64,
    pub created_by_user_id: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Server-resolved run scope for the tool-decision broker. No field of this
/// record may be supplied by the execution host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunToolScopeRecord {
    pub run_id: String,
    pub org_id: String,
    pub project_id: String,
    pub agent_session_id: String,
    pub agent_definition_id: String,
    pub device_id: String,
    pub state: String,
    pub principal_user_id: String,
    pub user_email: String,
    pub user_display_name: String,
    pub user_email_verified: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRefRecord {
    pub tool_call_id: String,
    pub org_id: String,
    pub project_id: String,
    pub run_id: String,
    pub tool_id: String,
    pub tool_fingerprint: String,
    pub risk_class: String,
    pub arguments_summary: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequestRecord {
    pub approval_id: String,
    pub org_id: String,
    pub project_id: String,
    pub run_id: String,
    pub tool_call_id: String,
    pub tool_id: String,
    pub tool_fingerprint: String,
    pub risk_class: String,
    pub approval_mode: String,
    pub status: String,
    pub arguments_summary: String,
    pub requested_by_principal_id: String,
    pub requested_at: String,
    pub expires_at: String,
    pub resolved_by_principal_id: Option<String>,
    pub resolved_at: Option<String>,
    pub resolution_reason: Option<String>,
    pub version: i64,
}

/// Statement input for one new catalog tool.
pub struct NewToolDefinition<'a> {
    pub tool_id: &'a str,
    pub org_id: &'a str,
    pub name: &'a str,
    pub source: &'a str,
    pub risk_class: &'a str,
    pub capability_ids_json: &'a str,
    pub fingerprint: &'a str,
    pub metadata_json: &'a str,
    pub created_by_user_id: &'a str,
    pub now: &'a Timestamp,
}

/// Statement input for a version-guarded catalog tool update. Values are the
/// merged row: the caller reads the current row first and applies the patch.
#[allow(clippy::too_many_arguments)]
pub struct ToolDefinitionUpdate<'a> {
    pub tool_id: &'a str,
    pub org_id: &'a str,
    pub name: &'a str,
    pub source: &'a str,
    pub risk_class: &'a str,
    pub capability_ids_json: &'a str,
    pub fingerprint: &'a str,
    pub lifecycle: &'a str,
    pub metadata_json: &'a str,
    pub expected_version: i64,
    pub now: &'a Timestamp,
}

/// Statement input for one new MCP registration.
#[allow(clippy::too_many_arguments)]
pub struct NewMcpRegistration<'a> {
    pub mcp_registration_id: &'a str,
    pub org_id: &'a str,
    pub source: &'a str,
    pub transport: &'a str,
    pub endpoint_metadata_json: &'a str,
    pub command_metadata_json: &'a str,
    pub allowed_origins_json: &'a str,
    pub required_secret_handles_json: &'a str,
    pub tool_fingerprint: Option<&'a str>,
    pub tool_list_json: &'a str,
    pub policy_status: &'a str,
    pub created_by_user_id: &'a str,
    pub now: &'a Timestamp,
}

/// Statement input for a version-guarded MCP registration update.
#[allow(clippy::too_many_arguments)]
pub struct McpRegistrationUpdate<'a> {
    pub mcp_registration_id: &'a str,
    pub org_id: &'a str,
    pub source: &'a str,
    pub transport: &'a str,
    pub endpoint_metadata_json: &'a str,
    pub command_metadata_json: &'a str,
    pub allowed_origins_json: &'a str,
    pub required_secret_handles_json: &'a str,
    pub tool_fingerprint: Option<&'a str>,
    pub tool_list_json: &'a str,
    pub policy_status: &'a str,
    pub expected_version: i64,
    pub now: &'a Timestamp,
}

/// Statement input for one new tool-call reference.
#[allow(clippy::too_many_arguments)]
pub struct NewToolCallRef<'a> {
    pub tool_call_id: &'a str,
    pub org_id: &'a str,
    pub project_id: &'a str,
    pub run_id: &'a str,
    pub tool_id: &'a str,
    pub tool_fingerprint: &'a str,
    pub risk_class: &'a str,
    pub arguments_summary: &'a str,
    pub now: &'a Timestamp,
}

/// Statement input for one new pending approval request.
#[allow(clippy::too_many_arguments)]
pub struct NewApprovalRequest<'a> {
    pub approval_id: &'a str,
    pub org_id: &'a str,
    pub project_id: &'a str,
    pub run_id: &'a str,
    pub agent_session_id: &'a str,
    pub tool_call_id: &'a str,
    pub tool_id: &'a str,
    pub tool_fingerprint: &'a str,
    pub arguments_hash: &'a str,
    pub requested_by_device_id: &'a str,
    pub policy_snapshot_id: Option<&'a str>,
    pub policy_version: Option<i64>,
    pub risk_class: &'a str,
    pub approval_mode: &'a str,
    pub arguments_summary: &'a str,
    pub requested_by_principal_id: &'a str,
    pub requested_at: &'a Timestamp,
    pub expires_at: &'a Timestamp,
}

/// Statement input for a session-scope approval inherited from an earlier
/// human decision in the same run. The row is created already terminal so no
/// pending window can be replayed for a different tool call.
#[allow(clippy::too_many_arguments)]
pub struct InheritedApproval<'a> {
    pub approval_id: &'a str,
    pub org_id: &'a str,
    pub project_id: &'a str,
    pub run_id: &'a str,
    pub agent_session_id: &'a str,
    pub tool_call_id: &'a str,
    pub tool_id: &'a str,
    pub tool_fingerprint: &'a str,
    pub arguments_hash: &'a str,
    pub requested_by_device_id: &'a str,
    pub policy_snapshot_id: Option<&'a str>,
    pub policy_version: Option<i64>,
    pub risk_class: &'a str,
    pub approval_mode: &'a str,
    pub status: &'a str,
    pub arguments_summary: &'a str,
    pub requested_by_principal_id: &'a str,
    pub requested_at: &'a Timestamp,
    pub expires_at: &'a Timestamp,
    pub resolved_by_principal_id: &'a str,
    pub resolved_at: &'a str,
    pub resolution_reason: &'a str,
}

/// Catalog, MCP, policy-document, tool-call, and run-timeline persistence.
pub struct ToolRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> ToolRepository<'a> {
    pub fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    /// Keyset page ordered by `(updated_at, tool_id)` descending. `source` and
    /// `risk_class` are whitelisted filters supplied as bound parameters; an
    /// absent filter is the empty string, which the predicate ignores.
    pub async fn list_tools(
        &self,
        org_id: &str,
        source: &str,
        risk_class: &str,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<ToolDefinitionRecord>> {
        validate_page_limit(limit)?;
        let statement = match cursor {
            Some((updated_at, tool_id)) => self.database.prepare(
                TOOLS_PAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(updated_at),
                    BindValue::Text(tool_id),
                    BindValue::Text(source),
                    BindValue::Text(risk_class),
                    BindValue::Integer(limit),
                ],
            )?,
            None => self.database.prepare(
                FIRST_TOOLS_PAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(source),
                    BindValue::Text(risk_class),
                    BindValue::Integer(limit),
                ],
            )?,
        };
        statement.all().await?.results::<ToolDefinitionRecord>()
    }

    pub async fn find_tool(
        &self,
        tool_id: &str,
        org_id: &str,
    ) -> worker::Result<Option<ToolDefinitionRecord>> {
        let statement = self.database.prepare(
            TOOL_BY_ID_SQL,
            &[BindValue::Text(tool_id), BindValue::Text(org_id)],
        )?;
        statement.first::<ToolDefinitionRecord>(None).await
    }

    /// Resolve the catalog entry that owns a fingerprint. The broker uses this
    /// to distinguish "unknown/new tool" from "known tool whose fingerprint
    /// changed" without reaching into another tenant's catalog.
    pub async fn find_tool_by_fingerprint(
        &self,
        org_id: &str,
        fingerprint: &str,
    ) -> worker::Result<Option<ToolDefinitionRecord>> {
        let statement = self.database.prepare(
            TOOL_BY_FINGERPRINT_SQL,
            &[BindValue::Text(org_id), BindValue::Text(fingerprint)],
        )?;
        statement.first::<ToolDefinitionRecord>(None).await
    }

    pub fn insert_tool_statement(
        &self,
        tool: &NewToolDefinition<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        validate_fingerprint(tool.fingerprint)?;
        self.database.prepare(
            INSERT_TOOL_SQL,
            &[
                BindValue::Text(tool.tool_id),
                BindValue::Text(tool.org_id),
                BindValue::Text(tool.name),
                BindValue::Text(tool.source),
                BindValue::Text(tool.risk_class),
                BindValue::Text(tool.capability_ids_json),
                BindValue::Text(tool.fingerprint),
                BindValue::Text("active"),
                BindValue::Text(tool.metadata_json),
                BindValue::Text(tool.created_by_user_id),
                BindValue::Text(tool.now.as_str()),
            ],
        )
    }

    pub fn update_tool_statement(
        &self,
        update: &ToolDefinitionUpdate<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        validate_fingerprint(update.fingerprint)?;
        self.database.prepare(
            UPDATE_TOOL_SQL,
            &[
                BindValue::Text(update.tool_id),
                BindValue::Text(update.name),
                BindValue::Text(update.source),
                BindValue::Text(update.risk_class),
                BindValue::Text(update.capability_ids_json),
                BindValue::Text(update.fingerprint),
                BindValue::Text(update.lifecycle),
                BindValue::Text(update.metadata_json),
                BindValue::Text(update.now.as_str()),
                BindValue::Text(update.org_id),
                BindValue::Integer(version_bind(update.expected_version)),
            ],
        )
    }

    /// Abort the surrounding batch unless the tool row still holds the expected
    /// version. The insert violates `idempotency_records.principal_id NOT NULL`,
    /// which is the established guard used by the P02/P04 repositories.
    pub fn assert_tool_version_statement(
        &self,
        tool_id: &str,
        org_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_TOOL_VERSION_SQL,
            &[
                BindValue::Text(tool_id),
                BindValue::Text(org_id),
                BindValue::Integer(version_bind(expected_version)),
            ],
        )
    }

    pub async fn list_mcp_registrations(
        &self,
        org_id: &str,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<McpRegistrationRecord>> {
        validate_page_limit(limit)?;
        let statement = match cursor {
            Some((updated_at, mcp_id)) => self.database.prepare(
                MCP_PAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(updated_at),
                    BindValue::Text(mcp_id),
                    BindValue::Integer(limit),
                ],
            )?,
            None => self.database.prepare(
                FIRST_MCP_PAGE_SQL,
                &[BindValue::Text(org_id), BindValue::Integer(limit)],
            )?,
        };
        statement.all().await?.results::<McpRegistrationRecord>()
    }

    pub async fn find_mcp_registration(
        &self,
        mcp_id: &str,
        org_id: &str,
    ) -> worker::Result<Option<McpRegistrationRecord>> {
        let statement = self.database.prepare(
            MCP_BY_ID_SQL,
            &[BindValue::Text(mcp_id), BindValue::Text(org_id)],
        )?;
        statement.first::<McpRegistrationRecord>(None).await
    }

    /// MCP registrations bind to a tool through the frozen schema's single
    /// `tool_fingerprint` column: an external tool whose fingerprint has no
    /// registration is an unreviewed external tool.
    pub async fn find_mcp_registration_by_fingerprint(
        &self,
        org_id: &str,
        fingerprint: &str,
    ) -> worker::Result<Option<McpRegistrationRecord>> {
        let statement = self.database.prepare(
            MCP_BY_FINGERPRINT_SQL,
            &[BindValue::Text(org_id), BindValue::Text(fingerprint)],
        )?;
        statement.first::<McpRegistrationRecord>(None).await
    }

    pub fn insert_mcp_statement(
        &self,
        registration: &NewMcpRegistration<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_MCP_SQL,
            &[
                BindValue::Text(registration.mcp_registration_id),
                BindValue::Text(registration.org_id),
                BindValue::Text(registration.source),
                BindValue::Text(registration.transport),
                BindValue::Text(registration.endpoint_metadata_json),
                BindValue::Text(registration.command_metadata_json),
                BindValue::Text(registration.allowed_origins_json),
                BindValue::Text(registration.required_secret_handles_json),
                registration
                    .tool_fingerprint
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(registration.tool_list_json),
                BindValue::Text(registration.policy_status),
                BindValue::Text(registration.created_by_user_id),
                BindValue::Text(registration.now.as_str()),
            ],
        )
    }

    pub fn update_mcp_statement(
        &self,
        update: &McpRegistrationUpdate<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_MCP_SQL,
            &[
                BindValue::Text(update.mcp_registration_id),
                BindValue::Text(update.source),
                BindValue::Text(update.transport),
                BindValue::Text(update.endpoint_metadata_json),
                BindValue::Text(update.command_metadata_json),
                BindValue::Text(update.allowed_origins_json),
                BindValue::Text(update.required_secret_handles_json),
                update
                    .tool_fingerprint
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(update.tool_list_json),
                BindValue::Text(update.policy_status),
                BindValue::Text(update.now.as_str()),
                BindValue::Text(update.org_id),
                BindValue::Integer(version_bind(update.expected_version)),
            ],
        )
    }

    pub fn assert_mcp_version_statement(
        &self,
        mcp_id: &str,
        org_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_MCP_VERSION_SQL,
            &[
                BindValue::Text(mcp_id),
                BindValue::Text(org_id),
                BindValue::Integer(version_bind(expected_version)),
            ],
        )
    }

    /// Read the policy document for one scope. `project_id` selects a
    /// project-scoped row; the caller falls back to the organization row.
    pub async fn find_tool_policy(
        &self,
        org_id: &str,
        project_id: Option<&str>,
    ) -> worker::Result<Option<ToolPolicyRecord>> {
        let project_value = project_id.map_or(BindValue::Null, BindValue::Text);
        let statement = self.database.prepare(
            TOOL_POLICY_BY_SCOPE_SQL,
            &[BindValue::Text(org_id), project_value],
        )?;
        statement.first::<ToolPolicyRecord>(None).await
    }

    pub fn insert_tool_policy_statement(
        &self,
        tool_policy_id: &str,
        org_id: &str,
        document_json: &str,
        created_by_user_id: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        validate_policy_document(document_json)?;
        self.database.prepare(
            INSERT_TOOL_POLICY_SQL,
            &[
                BindValue::Text(tool_policy_id),
                BindValue::Text(org_id),
                BindValue::Text(document_json),
                BindValue::Text(created_by_user_id),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub fn update_tool_policy_statement(
        &self,
        tool_policy_id: &str,
        org_id: &str,
        document_json: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        validate_policy_document(document_json)?;
        self.database.prepare(
            UPDATE_TOOL_POLICY_SQL,
            &[
                BindValue::Text(tool_policy_id),
                BindValue::Text(document_json),
                BindValue::Text(now.as_str()),
                BindValue::Text(org_id),
                BindValue::Integer(version_bind(expected_version)),
            ],
        )
    }

    pub fn assert_tool_policy_version_statement(
        &self,
        tool_policy_id: &str,
        org_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_TOOL_POLICY_VERSION_SQL,
            &[
                BindValue::Text(tool_policy_id),
                BindValue::Text(org_id),
                BindValue::Integer(version_bind(expected_version)),
            ],
        )
    }

    pub fn assert_tool_policy_absent_statement(
        &self,
        org_id: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database
            .prepare(ASSERT_TOOL_POLICY_ABSENT_SQL, &[BindValue::Text(org_id)])
    }

    /// Resolve the run and its owning user from the run ID alone. The broker
    /// derives organization, project, device, and principal from this record
    /// instead of trusting any value supplied by the execution host.
    pub async fn find_run_tool_scope(
        &self,
        run_id: &str,
    ) -> worker::Result<Option<RunToolScopeRecord>> {
        let statement = self
            .database
            .prepare(RUN_TOOL_SCOPE_SQL, &[BindValue::Text(run_id)])?;
        statement.first::<RunToolScopeRecord>(None).await
    }

    /// Capability classes visible to one organization: platform rows plus the
    /// organization's own overrides. The catalog is small and bounded so the
    /// decision broker can resolve capability keys in one read.
    pub async fn list_capabilities(
        &self,
        org_id: &str,
        limit: i32,
    ) -> worker::Result<Vec<CapabilityDefinitionRecord>> {
        if !(1..=CAPABILITY_CATALOG_MAX).contains(&limit) {
            return Err(invalid());
        }
        let statement = self.database.prepare(
            CAPABILITIES_FOR_ORG_SQL,
            &[BindValue::Text(org_id), BindValue::Integer(limit)],
        )?;
        statement
            .all()
            .await?
            .results::<CapabilityDefinitionRecord>()
    }

    /// Authenticate one device-scoped call from a hashed device token. An
    /// expired token and a revoked device are both rejected here.
    pub async fn find_device_for_token(
        &self,
        token_hash: &str,
        now: &Timestamp,
    ) -> worker::Result<Option<DeviceRecord>> {
        let statement = self.database.prepare(
            DEVICE_FOR_TOKEN_SQL,
            &[BindValue::Text(token_hash), BindValue::Text(now.as_str())],
        )?;
        statement.first::<DeviceRecord>(None).await
    }

    pub fn insert_tool_call_ref_statement(
        &self,
        call: &NewToolCallRef<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        validate_fingerprint(call.tool_fingerprint)?;
        validate_arguments_summary(call.arguments_summary)?;
        self.database.prepare(
            INSERT_TOOL_CALL_REF_SQL,
            &[
                BindValue::Text(call.tool_call_id),
                BindValue::Text(call.org_id),
                BindValue::Text(call.project_id),
                BindValue::Text(call.run_id),
                BindValue::Text(call.tool_id),
                BindValue::Text(call.tool_fingerprint),
                BindValue::Text(call.risk_class),
                BindValue::Text(call.arguments_summary),
                BindValue::Text(call.now.as_str()),
            ],
        )
    }

    pub async fn find_tool_call_ref(
        &self,
        run_id: &str,
        tool_call_id: &str,
    ) -> worker::Result<Option<ToolCallRefRecord>> {
        let statement = self.database.prepare(
            TOOL_CALL_REF_BY_ID_SQL,
            &[BindValue::Text(run_id), BindValue::Text(tool_call_id)],
        )?;
        statement.first::<ToolCallRefRecord>(None).await
    }

    pub fn update_tool_call_status_statement(
        &self,
        run_id: &str,
        tool_call_id: &str,
        status: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_TOOL_CALL_STATUS_SQL,
            &[
                BindValue::Text(run_id),
                BindValue::Text(tool_call_id),
                BindValue::Text(status),
                BindValue::Text(now.as_str()),
            ],
        )
    }
}

/// Approval request persistence and the version-guarded resolution path.
pub struct ApprovalRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> ApprovalRepository<'a> {
    pub fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    /// Consume an approved per-use grant exactly once. Session-scoped grants
    /// intentionally do not use this statement and remain reusable within the
    /// run's current policy window.
    pub fn consume_approval_statement(
        &self,
        approval_id: &str,
        org_id: &str,
        tool_call_id: &str,
        device_id: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            "UPDATE approval_requests SET consumed_at = ?5, consumed_by_device_id = ?4, version = version + 1 WHERE approval_id = ?1 AND org_id = ?2 AND tool_call_id = ?3 AND status = 'approved' AND approval_mode = 'per_use' AND consumed_at IS NULL AND expires_at > ?5",
            &[
                BindValue::Text(approval_id),
                BindValue::Text(org_id),
                BindValue::Text(tool_call_id),
                BindValue::Text(device_id),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub fn insert_statement(
        &self,
        approval: &NewApprovalRequest<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        validate_fingerprint(approval.tool_fingerprint)?;
        validate_arguments_summary(approval.arguments_summary)?;
        if approval.approval_mode != "session" && approval.approval_mode != "per_use" {
            return Err(invalid());
        }
        self.database.prepare(
            INSERT_APPROVAL_SQL,
            &[
                BindValue::Text(approval.approval_id),
                BindValue::Text(approval.org_id),
                BindValue::Text(approval.project_id),
                BindValue::Text(approval.run_id),
                BindValue::Text(approval.agent_session_id),
                BindValue::Text(approval.tool_call_id),
                BindValue::Text(approval.tool_id),
                BindValue::Text(approval.tool_fingerprint),
                BindValue::Text(approval.arguments_hash),
                BindValue::Text(approval.requested_by_device_id),
                approval
                    .policy_snapshot_id
                    .map_or(BindValue::Null, BindValue::Text),
                approval
                    .policy_version
                    .map_or(BindValue::Null, BindValue::Int64),
                BindValue::Text(approval.risk_class),
                BindValue::Text(approval.approval_mode),
                BindValue::Text(approval.arguments_summary),
                BindValue::Text(approval.requested_by_principal_id),
                BindValue::Text(approval.requested_at.as_str()),
                BindValue::Text(approval.expires_at.as_str()),
            ],
        )
    }

    /// Record a session-scope approval inherited from an earlier decision in the
    /// same run. The row is inserted already terminal so no pending window can
    /// be replayed for a different tool call.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_inherited_statement(
        &self,
        approval: &InheritedApproval<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        validate_fingerprint(approval.tool_fingerprint)?;
        validate_arguments_summary(approval.arguments_summary)?;
        if approval.approval_mode != "session" || approval.status != "approved" {
            return Err(invalid());
        }
        self.database.prepare(
            INSERT_RESOLVED_APPROVAL_SQL,
            &[
                BindValue::Text(approval.approval_id),
                BindValue::Text(approval.org_id),
                BindValue::Text(approval.project_id),
                BindValue::Text(approval.run_id),
                BindValue::Text(approval.agent_session_id),
                BindValue::Text(approval.tool_call_id),
                BindValue::Text(approval.tool_id),
                BindValue::Text(approval.tool_fingerprint),
                BindValue::Text(approval.arguments_hash),
                BindValue::Text(approval.requested_by_device_id),
                approval
                    .policy_snapshot_id
                    .map_or(BindValue::Null, BindValue::Text),
                approval
                    .policy_version
                    .map_or(BindValue::Null, BindValue::Int64),
                BindValue::Text(approval.risk_class),
                BindValue::Text(approval.approval_mode),
                BindValue::Text(approval.status),
                BindValue::Text("approved"),
                BindValue::Text(approval.arguments_summary),
                BindValue::Text(approval.requested_by_principal_id),
                BindValue::Text(approval.requested_at.as_str()),
                BindValue::Text(approval.expires_at.as_str()),
                BindValue::Text(approval.resolved_by_principal_id),
                BindValue::Text(approval.resolved_at),
                BindValue::Text(approval.resolution_reason),
            ],
        )
    }

    pub async fn find_approval(
        &self,
        approval_id: &str,
        org_id: &str,
    ) -> worker::Result<Option<ApprovalRequestRecord>> {
        let statement = self.database.prepare(
            APPROVAL_BY_ID_SQL,
            &[BindValue::Text(approval_id), BindValue::Text(org_id)],
        )?;
        statement.first::<ApprovalRequestRecord>(None).await
    }

    pub async fn find_approval_for_tool_call(
        &self,
        run_id: &str,
        tool_call_id: &str,
    ) -> worker::Result<Option<ApprovalRequestRecord>> {
        let statement = self.database.prepare(
            APPROVAL_BY_TOOL_CALL_SQL,
            &[BindValue::Text(run_id), BindValue::Text(tool_call_id)],
        )?;
        statement.first::<ApprovalRequestRecord>(None).await
    }

    pub async fn find_reusable_session_approval(
        &self,
        run_id: &str,
        tool_id: &str,
        tool_fingerprint: &str,
        arguments_summary: &str,
        now: &Timestamp,
    ) -> worker::Result<Option<ApprovalRequestRecord>> {
        let statement = self.database.prepare(
            REUSABLE_SESSION_APPROVAL_SQL,
            &[
                BindValue::Text(run_id),
                BindValue::Text(tool_id),
                BindValue::Text(tool_fingerprint),
                BindValue::Text(arguments_summary),
                BindValue::Text(now.as_str()),
            ],
        )?;
        statement.first::<ApprovalRequestRecord>(None).await
    }

    /// Keyset page ordered by `(requested_at, approval_id)` descending.
    /// `status` and `run_id` are whitelisted filters; `""` disables one.
    pub async fn list_approvals(
        &self,
        org_id: &str,
        status: &str,
        run_id: &str,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<ApprovalRequestRecord>> {
        validate_page_limit(limit)?;
        let statement = match cursor {
            Some((requested_at, approval_id)) => self.database.prepare(
                APPROVALS_PAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(requested_at),
                    BindValue::Text(approval_id),
                    BindValue::Text(status),
                    BindValue::Text(run_id),
                    BindValue::Integer(limit),
                ],
            )?,
            None => self.database.prepare(
                FIRST_APPROVALS_PAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(status),
                    BindValue::Text(run_id),
                    BindValue::Integer(limit),
                ],
            )?,
        };
        statement.all().await?.results::<ApprovalRequestRecord>()
    }

    /// Resolve a still-pending, unexpired approval. The version predicate and
    /// the expiry window make a second resolve a no-op rather than a new state.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_statement(
        &self,
        approval_id: &str,
        org_id: &str,
        status: &str,
        resolved_by_principal_id: &str,
        resolution_reason: &str,
        now: &Timestamp,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        if !matches!(status, "approved" | "denied" | "cancelled") {
            return Err(invalid());
        }
        if resolution_reason.is_empty() || resolution_reason.len() > 512 {
            return Err(invalid());
        }
        self.database.prepare(
            RESOLVE_APPROVAL_SQL,
            &[
                BindValue::Text(approval_id),
                BindValue::Text(org_id),
                BindValue::Text(status),
                BindValue::Text(resolved_by_principal_id),
                BindValue::Text(now.as_str()),
                BindValue::Text(resolution_reason),
                BindValue::Integer(version_bind(expected_version)),
            ],
        )
    }

    /// Terminalize an approval whose window has closed.
    pub fn expire_statement(
        &self,
        approval_id: &str,
        resolved_by_principal_id: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            EXPIRE_APPROVAL_SQL,
            &[
                BindValue::Text(approval_id),
                BindValue::Text(resolved_by_principal_id),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    /// Abort the surrounding batch unless the approval is still pending,
    /// unexpired, and at the expected version.
    pub fn assert_pending_statement(
        &self,
        approval_id: &str,
        org_id: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_APPROVAL_PENDING_SQL,
            &[
                BindValue::Text(approval_id),
                BindValue::Text(org_id),
                BindValue::Integer(version_bind(expected_version)),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    /// Abort the surrounding batch unless the approval is still pending at the
    /// expected version. Used by the expiry path, where the window is expected
    /// to have closed and must therefore stay out of the predicate.
    pub fn assert_pending_version_statement(
        &self,
        approval_id: &str,
        org_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_APPROVAL_PENDING_VERSION_SQL,
            &[
                BindValue::Text(approval_id),
                BindValue::Text(org_id),
                BindValue::Integer(version_bind(expected_version)),
            ],
        )
    }
}

fn validate_page_limit(limit: i32) -> worker::Result<()> {
    if (1..=101).contains(&limit) {
        return Ok(());
    }
    Err(invalid())
}

/// A fingerprint must be a short opaque identifier: alphanumerics, `.`, `_`,
/// and `-`. Anything else (a digest prefix, base64 padding, whitespace) is
/// rejected so the stored value and the evaluated value can never disagree.
fn validate_fingerprint(fingerprint: &str) -> worker::Result<()> {
    let printable = fingerprint
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
    if (FINGERPRINT_MIN..=FINGERPRINT_MAX).contains(&fingerprint.len()) && printable {
        return Ok(());
    }
    Err(invalid())
}

fn validate_arguments_summary(summary: &str) -> worker::Result<()> {
    if summary.len() <= ARGUMENTS_SUMMARY_MAX && !summary.chars().any(char::is_control) {
        return Ok(());
    }
    Err(invalid())
}

fn validate_policy_document(document: &str) -> worker::Result<()> {
    if document.len() <= POLICY_DOCUMENT_MAX {
        return Ok(());
    }
    Err(invalid())
}

fn version_bind(value: i64) -> i32 {
    i32::try_from(value).unwrap_or_default()
}

fn invalid() -> worker::Error {
    worker::Error::RustError("invalid tool repository input".into())
}
