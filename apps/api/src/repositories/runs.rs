//! D1 persistence for P05 agent definitions, agent sessions, runs, timelines,
//! and artifact metadata.
//!
//! The repository is deliberately a thin SQL/row-mapping adapter.  It accepts
//! trusted values from the HTTP/domain boundary, binds every dynamic value,
//! and leaves authorization and device execution to the callers.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::Timestamp,
};

const AGENT_BY_ID_SQL: &str = r#"
SELECT agent_definition_id, org_id, project_id, name, description,
       instructions_ref, default_model_alias, required_capabilities_json,
       allowed_tool_ids_json, runtime_requirements_json, lifecycle, version,
       created_by_user_id, created_at, updated_at
FROM agent_definitions
WHERE agent_definition_id = ?1 AND org_id = ?2
LIMIT 1
"#;

const AGENTS_PAGE_SQL: &str = r#"
SELECT agent_definition_id, org_id, project_id, name, description,
       instructions_ref, default_model_alias, required_capabilities_json,
       allowed_tool_ids_json, runtime_requirements_json, lifecycle, version,
       created_by_user_id, created_at, updated_at
FROM agent_definitions
WHERE org_id = ?1
  AND (
    project_id IS NULL
    OR EXISTS (
      SELECT 1 FROM projects p
      WHERE p.project_id = agent_definitions.project_id
        AND p.org_id = agent_definitions.org_id
    )
  )
  AND (
    ?3 = 1
    OR project_id IS NULL
    OR EXISTS (
      SELECT 1 FROM projects p
      WHERE p.project_id = agent_definitions.project_id
        AND p.org_id = agent_definitions.org_id
        AND (
          p.visibility = 'org'
          OR EXISTS (
            SELECT 1 FROM project_access_grants g
            WHERE g.project_id = p.project_id
              AND g.org_id = p.org_id
              AND (
                g.member_id IN (
                  SELECT membership_id FROM memberships
                  WHERE org_id = ?1 AND user_id = ?2 AND status = 'active'
                )
                OR g.team_id IN (
                  SELECT tm.team_id
                  FROM team_members tm
                  JOIN memberships m ON m.membership_id = tm.membership_id
                  WHERE m.org_id = ?1 AND m.user_id = ?2 AND m.status = 'active'
                )
              )
          )
        )
    )
  )
  AND (?4 = '' OR project_id = ?4)
  AND (?5 = '' OR (updated_at, agent_definition_id) < (?5, ?6))
ORDER BY updated_at DESC, agent_definition_id DESC
LIMIT ?7
"#;

const INSERT_AGENT_SQL: &str = r#"
INSERT INTO agent_definitions (
    agent_definition_id, org_id, project_id, name, description,
    instructions_ref, default_model_alias, required_capabilities_json,
    allowed_tool_ids_json, runtime_requirements_json, lifecycle, version,
    created_by_user_id, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'active', 1, ?11, ?12, ?12)
"#;

const UPDATE_AGENT_SQL: &str = r#"
UPDATE agent_definitions
SET project_id = ?3,
    name = ?4,
    description = ?5,
    instructions_ref = ?6,
    default_model_alias = ?7,
    required_capabilities_json = ?8,
    allowed_tool_ids_json = ?9,
    runtime_requirements_json = ?10,
    lifecycle = ?11,
    version = version + 1,
    updated_at = ?12
WHERE agent_definition_id = ?1 AND org_id = ?2 AND version = ?13
"#;

const SESSION_BY_ID_SQL: &str = r#"
SELECT agent_session_id, org_id, project_id, device_id, workspace_binding_id,
       agent_definition_id, agent_definition_version, external_id, title,
       lifecycle, version, created_by_user_id, created_at, updated_at
FROM agent_sessions
WHERE agent_session_id = ?1 AND org_id = ?2
LIMIT 1
"#;

const SESSIONS_PAGE_SQL: &str = r#"
SELECT agent_session_id, org_id, project_id, device_id, workspace_binding_id,
       agent_definition_id, agent_definition_version, external_id, title,
       lifecycle, version, created_by_user_id, created_at, updated_at
FROM agent_sessions
WHERE org_id = ?1
  AND EXISTS (
    SELECT 1 FROM projects p
    WHERE p.project_id = agent_sessions.project_id
      AND p.org_id = agent_sessions.org_id
  )
  AND (
    ?3 = 1
    OR EXISTS (
      SELECT 1 FROM projects p
      WHERE p.project_id = agent_sessions.project_id
        AND p.org_id = agent_sessions.org_id
        AND (
          p.visibility = 'org'
          OR EXISTS (
            SELECT 1 FROM project_access_grants g
            WHERE g.project_id = p.project_id
              AND g.org_id = p.org_id
              AND (
                g.member_id IN (
                  SELECT membership_id FROM memberships
                  WHERE org_id = ?1 AND user_id = ?2 AND status = 'active'
                )
                OR g.team_id IN (
                  SELECT tm.team_id
                  FROM team_members tm
                  JOIN memberships m ON m.membership_id = tm.membership_id
                  WHERE m.org_id = ?1 AND m.user_id = ?2 AND m.status = 'active'
                )
              )
          )
        )
    )
  )
  AND (?4 = '' OR lifecycle = ?4)
  AND (?5 = '' OR project_id = ?5)
  AND (?6 = '' OR (updated_at, agent_session_id) < (?6, ?7))
ORDER BY updated_at DESC, agent_session_id DESC
LIMIT ?8
"#;

const INSERT_SESSION_SQL: &str = r#"
INSERT INTO agent_sessions (
    agent_session_id, org_id, project_id, device_id, workspace_binding_id,
    agent_definition_id, agent_definition_version, external_id, title,
    lifecycle, version, created_by_user_id, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'active', 1, ?10, ?11, ?11)
"#;

const UPDATE_SESSION_LIFECYCLE_SQL: &str = r#"
UPDATE agent_sessions
SET lifecycle = ?3, version = version + 1, updated_at = ?4
WHERE agent_session_id = ?1 AND org_id = ?2
  AND version = ?5 AND lifecycle = 'active'
"#;

const RUN_BY_ID_SQL: &str = r#"
SELECT run_id, org_id, project_id, agent_session_id, parent_run_id, attempt,
       agent_definition_id, agent_definition_version, principal_user_id,
       device_id, model_alias, route_id, route_version_id, state, failure_code,
       request_id, started_at, finished_at, version, state_version,
       cancel_requested_at, resumed_from_run_id, workspace_binding_id,
       policy_snapshot_id, policy_version, created_at, updated_at
FROM runs
WHERE run_id = ?1 AND org_id = ?2
  AND EXISTS (
    SELECT 1 FROM projects p
    WHERE p.project_id = runs.project_id
      AND p.org_id = runs.org_id
  )
LIMIT 1
"#;

const RUNS_PAGE_SQL: &str = r#"
SELECT run_id, org_id, project_id, agent_session_id, parent_run_id, attempt,
       agent_definition_id, agent_definition_version, principal_user_id,
       device_id, model_alias, route_id, route_version_id, state, failure_code,
       request_id, started_at, finished_at, version, state_version,
       cancel_requested_at, resumed_from_run_id, workspace_binding_id,
       policy_snapshot_id, policy_version, created_at, updated_at
FROM runs
WHERE org_id = ?1
  AND EXISTS (
    SELECT 1 FROM projects p
    WHERE p.project_id = runs.project_id
      AND p.org_id = runs.org_id
  )
  AND (
    ?3 = 1
    OR EXISTS (
      SELECT 1 FROM projects p
      WHERE p.project_id = runs.project_id
        AND p.org_id = runs.org_id
        AND (
          p.visibility = 'org'
          OR EXISTS (
            SELECT 1 FROM project_access_grants g
            WHERE g.project_id = p.project_id
              AND g.org_id = p.org_id
              AND (
                g.member_id IN (
                  SELECT membership_id FROM memberships
                  WHERE org_id = ?1 AND user_id = ?2 AND status = 'active'
                )
                OR g.team_id IN (
                  SELECT tm.team_id
                  FROM team_members tm
                  JOIN memberships m ON m.membership_id = tm.membership_id
                  WHERE m.org_id = ?1 AND m.user_id = ?2 AND m.status = 'active'
                )
              )
          )
        )
    )
  )
  AND (?4 = '' OR project_id = ?4)
  AND (?5 = '' OR agent_session_id = ?5)
  AND (?6 = '' OR state = ?6)
  AND (?7 = '' OR (created_at, run_id) < (?7, ?8))
ORDER BY created_at DESC, run_id DESC
LIMIT ?9
"#;

const INSERT_RUN_SQL: &str = r#"
INSERT INTO runs (
    run_id, org_id, project_id, agent_session_id, parent_run_id, attempt,
    agent_definition_id, agent_definition_version, principal_user_id, device_id,
    model_alias, route_id, route_version_id, state, failure_code, request_id,
    started_at, finished_at, version, state_version, created_at, updated_at,
    cancel_requested_at, resumed_from_run_id, workspace_binding_id,
    policy_snapshot_id, policy_version
) VALUES (
    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
    'queued', NULL, ?14, NULL, NULL, 1, 1, ?15, ?15,
    NULL, ?16, ?17, ?18, ?19
)
"#;

const UPDATE_RUN_STATE_SQL: &str = r#"
UPDATE runs
SET state = ?3,
    failure_code = ?4,
    started_at = COALESCE(started_at, ?5),
    finished_at = ?6,
    version = version + 1,
    state_version = state_version + 1,
    cancel_requested_at = CASE
        WHEN ?3 = 'cancelled' THEN COALESCE(cancel_requested_at, ?7)
        ELSE cancel_requested_at
    END,
    updated_at = ?7
WHERE run_id = ?1
  AND org_id = ?2
  AND version = ?8
  AND state = ?9
  AND state NOT IN ('succeeded', 'failed', 'cancelled', 'timed_out')
"#;

const NEXT_EVENT_SEQUENCE_SQL: &str = r#"
SELECT COALESCE(MAX(e.sequence), 0) + 1 AS next_sequence
FROM run_events e
JOIN runs r ON r.run_id = e.run_id AND r.org_id = e.org_id
WHERE e.run_id = ?1 AND r.org_id = ?2
"#;

const MAX_ATTEMPT_SQL: &str = r#"
SELECT COALESCE(MAX(attempt), 0) AS max_attempt
FROM runs
WHERE org_id = ?2 AND (run_id = ?1 OR parent_run_id = ?1)
"#;

const INSERT_EVENT_SQL: &str = r#"
INSERT INTO run_events (
    run_event_id, run_id, org_id, project_id, request_id, device_id,
    agent_session_id, schema_version, sequence, event_type, occurred_at,
    recorded_at, actor_type, actor_id, correlation_id, tool_call_id,
    approval_id, payload_json
)
SELECT ?1, r.run_id, r.org_id, r.project_id,
       COALESCE(NULLIF(?2, ''), r.request_id, ''), r.device_id,
       r.agent_session_id, 1, ?3, ?4, ?5, ?5, ?6, ?7, ?8, ?9, ?10, ?11
FROM runs AS r
JOIN agent_sessions AS s ON s.agent_session_id = r.agent_session_id
  AND s.org_id = r.org_id AND s.project_id = r.project_id
WHERE r.run_id = ?12
  AND (?13 = '' OR r.org_id = ?13)
"#;

const EVENTS_PAGE_SQL: &str = r#"
SELECT e.run_event_id, e.run_id, e.org_id, e.project_id, e.request_id, e.device_id,
       e.agent_session_id, e.schema_version, e.sequence, e.event_type, e.occurred_at,
       e.recorded_at, e.actor_type, e.actor_id, e.correlation_id, e.tool_call_id,
       e.approval_id, e.payload_json
FROM run_events e
JOIN runs r ON r.run_id = e.run_id AND r.org_id = e.org_id
JOIN agent_sessions s ON s.agent_session_id = e.agent_session_id
  AND s.org_id = e.org_id AND s.project_id = e.project_id
WHERE e.run_id = ?1
  AND r.org_id = ?5
  AND e.sequence > ?2
  AND (?3 = 0 OR (e.sequence, e.run_event_id) > (?3, ?4))
ORDER BY e.sequence ASC, e.run_event_id ASC
LIMIT ?6
"#;

const INSERT_ARTIFACT_SQL: &str = r#"
INSERT INTO artifact_refs (
    artifact_ref_id, org_id, project_id, run_id, kind, content_ref,
    mime_type, size_bytes, checksum, retention_policy, created_by_user_id,
    created_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
"#;

const ARTIFACTS_PAGE_SQL: &str = r#"
SELECT a.artifact_ref_id, a.org_id, a.project_id, a.run_id, a.kind, a.content_ref,
       a.mime_type, a.size_bytes, a.checksum, a.retention_policy, a.created_by_user_id,
       a.created_at
FROM artifact_refs AS a
JOIN runs AS r ON r.run_id = a.run_id AND r.org_id = a.org_id AND r.project_id = a.project_id
WHERE a.org_id = ?1 AND a.run_id = ?2
  AND (?3 = '' OR (a.created_at, a.artifact_ref_id) < (?3, ?4))
ORDER BY a.created_at DESC, a.artifact_ref_id DESC
LIMIT ?5
"#;

/* A failed version/state assertion intentionally violates the NOT NULL
 * idempotency constraint. D1 batches are transactional, so this statement
 * aborts the surrounding mutation before an outbox or completion row commits. */
const ASSERT_AGENT_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest,
    request_fingerprint, state, response_status, response_body, expires_at,
    claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM agent_definitions
    WHERE agent_definition_id = ?1 AND org_id = ?2 AND version = ?3
)
"#;

const ASSERT_SESSION_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest,
    request_fingerprint, state, response_status, response_body, expires_at,
    claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM agent_sessions
    WHERE agent_session_id = ?1 AND org_id = ?2
      AND version = ?3 AND lifecycle = 'active'
)
"#;

const ASSERT_RUN_STATE_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest,
    request_fingerprint, state, response_status, response_body, expires_at,
    claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM runs
    WHERE run_id = ?1 AND org_id = ?2 AND version = ?3 AND state = ?4
)
"#;

const ASSERT_RETRY_ATTEMPT_ABSENT_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest,
    request_fingerprint, state, response_status, response_body, expires_at,
    claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE EXISTS (
    SELECT 1 FROM runs
    WHERE org_id = ?1 AND parent_run_id = ?2 AND attempt = ?3
)
"#;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentDefinitionRecord {
    pub agent_definition_id: String,
    pub org_id: String,
    pub project_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub instructions_ref: Option<String>,
    pub default_model_alias: Option<String>,
    pub required_capabilities_json: String,
    pub allowed_tool_ids_json: String,
    pub runtime_requirements_json: String,
    pub lifecycle: String,
    pub version: i64,
    pub created_by_user_id: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentSessionRecord {
    pub agent_session_id: String,
    pub org_id: String,
    pub project_id: String,
    pub device_id: String,
    pub workspace_binding_id: Option<String>,
    pub agent_definition_id: String,
    pub agent_definition_version: i64,
    pub external_id: Option<String>,
    pub title: Option<String>,
    pub lifecycle: String,
    pub version: i64,
    pub created_by_user_id: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunRecord {
    pub run_id: String,
    pub org_id: String,
    pub project_id: String,
    pub agent_session_id: String,
    pub parent_run_id: Option<String>,
    pub attempt: i64,
    pub agent_definition_id: String,
    pub agent_definition_version: i64,
    pub principal_user_id: String,
    pub device_id: String,
    pub model_alias: Option<String>,
    pub route_id: Option<String>,
    pub route_version_id: Option<String>,
    pub state: String,
    pub failure_code: Option<String>,
    pub request_id: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub version: i64,
    pub state_version: i64,
    pub cancel_requested_at: Option<String>,
    pub resumed_from_run_id: Option<String>,
    pub workspace_binding_id: Option<String>,
    pub policy_snapshot_id: Option<String>,
    pub policy_version: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RunEventRecord {
    pub run_event_id: String,
    pub run_id: String,
    pub org_id: String,
    pub project_id: String,
    pub request_id: String,
    pub device_id: String,
    pub agent_session_id: String,
    pub schema_version: i64,
    pub sequence: i64,
    pub event_type: String,
    pub occurred_at: String,
    pub recorded_at: String,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub correlation_id: String,
    pub tool_call_id: Option<String>,
    pub approval_id: Option<String>,
    pub payload_json: String,
}

impl fmt::Debug for RunEventRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunEventRecord")
            .field("run_event_id", &self.run_event_id)
            .field("run_id", &self.run_id)
            .field("org_id", &self.org_id)
            .field("project_id", &self.project_id)
            .field("request_id", &self.request_id)
            .field("device_id", &self.device_id)
            .field("agent_session_id", &self.agent_session_id)
            .field("schema_version", &self.schema_version)
            .field("sequence", &self.sequence)
            .field("event_type", &self.event_type)
            .field("occurred_at", &self.occurred_at)
            .field("recorded_at", &self.recorded_at)
            .field("actor_type", &self.actor_type)
            .field("actor_id", &self.actor_id)
            .field("correlation_id", &self.correlation_id)
            .field("tool_call_id", &self.tool_call_id)
            .field("approval_id", &self.approval_id)
            .field("payload_json", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ArtifactRefRecord {
    pub artifact_ref_id: String,
    pub org_id: String,
    pub project_id: String,
    pub run_id: String,
    pub kind: String,
    pub content_ref: Option<String>,
    pub mime_type: Option<String>,
    pub size_bytes: Option<i64>,
    pub checksum: Option<String>,
    pub retention_policy: String,
    pub created_by_user_id: String,
    pub created_at: String,
}

impl fmt::Debug for ArtifactRefRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactRefRecord")
            .field("artifact_ref_id", &self.artifact_ref_id)
            .field("org_id", &self.org_id)
            .field("project_id", &self.project_id)
            .field("run_id", &self.run_id)
            .field("kind", &self.kind)
            .field(
                "content_ref",
                &self.content_ref.as_ref().map(|_| "[redacted]"),
            )
            .field("mime_type", &self.mime_type)
            .field("size_bytes", &self.size_bytes)
            .field("checksum", &self.checksum.as_ref().map(|_| "[redacted]"))
            .field("retention_policy", &self.retention_policy)
            .field("created_by_user_id", &self.created_by_user_id)
            .field("created_at", &self.created_at)
            .finish()
    }
}

pub struct NewAgentDefinitionInput<'a> {
    pub agent_definition_id: &'a str,
    pub org_id: &'a str,
    pub project_id: Option<&'a str>,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub instructions_ref: Option<&'a str>,
    pub default_model_alias: Option<&'a str>,
    pub required_capabilities_json: &'a str,
    pub allowed_tool_ids_json: &'a str,
    pub runtime_requirements_json: &'a str,
    pub created_by_user_id: &'a str,
}

pub struct AgentDefinitionUpdateInput<'a> {
    pub agent_definition_id: &'a str,
    pub org_id: &'a str,
    pub project_id: Option<&'a str>,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub instructions_ref: Option<&'a str>,
    pub default_model_alias: Option<&'a str>,
    pub required_capabilities_json: &'a str,
    pub allowed_tool_ids_json: &'a str,
    pub runtime_requirements_json: &'a str,
    pub lifecycle: &'a str,
    pub now: &'a Timestamp,
    pub expected_version: i64,
}

pub struct NewAgentSessionInput<'a> {
    pub agent_session_id: &'a str,
    pub org_id: &'a str,
    pub project_id: &'a str,
    pub device_id: &'a str,
    pub workspace_binding_id: Option<&'a str>,
    pub agent_definition_id: &'a str,
    pub agent_definition_version: i64,
    pub external_id: Option<&'a str>,
    pub title: Option<&'a str>,
    pub created_by_user_id: &'a str,
}

pub struct NewRunInput<'a> {
    pub run_id: &'a str,
    pub org_id: &'a str,
    pub project_id: &'a str,
    pub agent_session_id: &'a str,
    pub parent_run_id: Option<&'a str>,
    pub attempt: i64,
    pub agent_definition_id: &'a str,
    pub agent_definition_version: i64,
    pub principal_user_id: &'a str,
    pub device_id: &'a str,
    pub model_alias: Option<&'a str>,
    pub route_id: Option<&'a str>,
    pub route_version_id: Option<&'a str>,
    pub resumed_from_run_id: Option<&'a str>,
    pub workspace_binding_id: Option<&'a str>,
    pub policy_snapshot_id: Option<&'a str>,
    pub policy_version: Option<i64>,
    pub request_id: &'a str,
    pub now: &'a Timestamp,
}

pub struct NewRunEventInput<'a> {
    pub run_event_id: &'a str,
    pub run_id: &'a str,
    pub sequence: i64,
    pub event_type: &'a str,
    pub occurred_at: &'a Timestamp,
    pub actor_type: &'a str,
    pub actor_id: Option<&'a str>,
    pub correlation_id: &'a str,
    pub tool_call_id: Option<&'a str>,
    pub approval_id: Option<&'a str>,
    pub payload: &'a Value,
}

pub struct NewArtifactRefInput<'a> {
    pub artifact_ref_id: &'a str,
    pub org_id: &'a str,
    pub project_id: &'a str,
    pub run_id: &'a str,
    pub kind: &'a str,
    pub content_ref: Option<&'a str>,
    pub mime_type: Option<&'a str>,
    pub size_bytes: Option<i64>,
    pub checksum: Option<&'a str>,
    pub retention_policy: &'a str,
    pub created_by_user_id: &'a str,
    pub now: &'a Timestamp,
}

/// D1 persistence for all run-control resources.  The alias is retained so
/// downstream packets can use the domain name `RunsRepository` while existing
/// repository naming remains consistent with `ProjectRepository`.
pub struct RunRepository<'a> {
    database: &'a D1Adapter,
}

pub type RunsRepository<'a> = RunRepository<'a>;

impl<'a> RunRepository<'a> {
    pub fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    pub fn insert_agent_statement(
        &self,
        input: &NewAgentDefinitionInput<'_>,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_AGENT_SQL,
            &[
                BindValue::Text(input.agent_definition_id),
                BindValue::Text(input.org_id),
                input.project_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.name),
                input.description.map_or(BindValue::Null, BindValue::Text),
                input
                    .instructions_ref
                    .map_or(BindValue::Null, BindValue::Text),
                input
                    .default_model_alias
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.required_capabilities_json),
                BindValue::Text(input.allowed_tool_ids_json),
                BindValue::Text(input.runtime_requirements_json),
                BindValue::Text(input.created_by_user_id),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub async fn find_agent(
        &self,
        org_id: &str,
        agent_definition_id: &str,
    ) -> worker::Result<Option<AgentDefinitionRecord>> {
        self.database
            .prepare(
                AGENT_BY_ID_SQL,
                &[
                    BindValue::Text(agent_definition_id),
                    BindValue::Text(org_id),
                ],
            )?
            .first::<AgentDefinitionRecord>(None)
            .await
    }

    pub async fn list_agents(
        &self,
        org_id: &str,
        user_id: &str,
        manager: bool,
        project_id: Option<&str>,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<AgentDefinitionRecord>> {
        let (cursor_created, cursor_id) = cursor.unwrap_or(("", ""));
        self.database
            .prepare(
                AGENTS_PAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(user_id),
                    BindValue::Integer(i32::from(manager)),
                    BindValue::Text(project_id.unwrap_or("")),
                    BindValue::Text(cursor_created),
                    BindValue::Text(cursor_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<AgentDefinitionRecord>()
    }

    pub fn update_agent_statement(
        &self,
        input: &AgentDefinitionUpdateInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_AGENT_SQL,
            &[
                BindValue::Text(input.agent_definition_id),
                BindValue::Text(input.org_id),
                input.project_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.name),
                input.description.map_or(BindValue::Null, BindValue::Text),
                input
                    .instructions_ref
                    .map_or(BindValue::Null, BindValue::Text),
                input
                    .default_model_alias
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.required_capabilities_json),
                BindValue::Text(input.allowed_tool_ids_json),
                BindValue::Text(input.runtime_requirements_json),
                BindValue::Text(input.lifecycle),
                BindValue::Text(input.now.as_str()),
                BindValue::Int64(input.expected_version),
            ],
        )
    }

    pub async fn find_session(
        &self,
        org_id: &str,
        agent_session_id: &str,
    ) -> worker::Result<Option<AgentSessionRecord>> {
        self.database
            .prepare(
                SESSION_BY_ID_SQL,
                &[BindValue::Text(agent_session_id), BindValue::Text(org_id)],
            )?
            .first::<AgentSessionRecord>(None)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn list_sessions(
        &self,
        org_id: &str,
        user_id: &str,
        manager: bool,
        lifecycle: Option<&str>,
        project_id: Option<&str>,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<AgentSessionRecord>> {
        let (cursor_created, cursor_id) = cursor.unwrap_or(("", ""));
        self.database
            .prepare(
                SESSIONS_PAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(user_id),
                    BindValue::Integer(i32::from(manager)),
                    BindValue::Text(lifecycle.unwrap_or("")),
                    BindValue::Text(project_id.unwrap_or("")),
                    BindValue::Text(cursor_created),
                    BindValue::Text(cursor_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<AgentSessionRecord>()
    }

    pub fn insert_session_statement(
        &self,
        input: &NewAgentSessionInput<'_>,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_SESSION_SQL,
            &[
                BindValue::Text(input.agent_session_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.project_id),
                BindValue::Text(input.device_id),
                input
                    .workspace_binding_id
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.agent_definition_id),
                BindValue::Int64(input.agent_definition_version),
                input.external_id.map_or(BindValue::Null, BindValue::Text),
                input.title.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.created_by_user_id),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub fn update_session_lifecycle_statement(
        &self,
        agent_session_id: &str,
        org_id: &str,
        lifecycle: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_SESSION_LIFECYCLE_SQL,
            &[
                BindValue::Text(agent_session_id),
                BindValue::Text(org_id),
                BindValue::Text(lifecycle),
                BindValue::Text(now.as_str()),
                BindValue::Int64(expected_version),
            ],
        )
    }

    pub async fn find_run(&self, org_id: &str, run_id: &str) -> worker::Result<Option<RunRecord>> {
        self.database
            .prepare(
                RUN_BY_ID_SQL,
                &[BindValue::Text(run_id), BindValue::Text(org_id)],
            )?
            .first::<RunRecord>(None)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn list_runs(
        &self,
        org_id: &str,
        user_id: &str,
        manager: bool,
        project_id: Option<&str>,
        session_id: Option<&str>,
        state: Option<&str>,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<RunRecord>> {
        let (cursor_created, cursor_id) = cursor.unwrap_or(("", ""));
        self.database
            .prepare(
                RUNS_PAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(user_id),
                    BindValue::Integer(i32::from(manager)),
                    BindValue::Text(project_id.unwrap_or("")),
                    BindValue::Text(session_id.unwrap_or("")),
                    BindValue::Text(state.unwrap_or("")),
                    BindValue::Text(cursor_created),
                    BindValue::Text(cursor_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<RunRecord>()
    }

    pub fn insert_run_statement(
        &self,
        input: &NewRunInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_RUN_SQL,
            &[
                BindValue::Text(input.run_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.project_id),
                BindValue::Text(input.agent_session_id),
                input.parent_run_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Int64(input.attempt),
                BindValue::Text(input.agent_definition_id),
                BindValue::Int64(input.agent_definition_version),
                BindValue::Text(input.principal_user_id),
                BindValue::Text(input.device_id),
                input.model_alias.map_or(BindValue::Null, BindValue::Text),
                input.route_id.map_or(BindValue::Null, BindValue::Text),
                input
                    .route_version_id
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.request_id),
                BindValue::Text(input.now.as_str()),
                input
                    .resumed_from_run_id
                    .map_or(BindValue::Null, BindValue::Text),
                input
                    .workspace_binding_id
                    .map_or(BindValue::Null, BindValue::Text),
                input
                    .policy_snapshot_id
                    .map_or(BindValue::Null, BindValue::Text),
                input
                    .policy_version
                    .map_or(BindValue::Null, BindValue::Int64),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_run_state_statement(
        &self,
        run_id: &str,
        org_id: &str,
        next_state: &str,
        failure_code: Option<&str>,
        started_at: Option<&str>,
        finished_at: Option<&str>,
        expected_version: i64,
        expected_state: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_RUN_STATE_SQL,
            &[
                BindValue::Text(run_id),
                BindValue::Text(org_id),
                BindValue::Text(next_state),
                failure_code.map_or(BindValue::Null, BindValue::Text),
                started_at.map_or(BindValue::Null, BindValue::Text),
                finished_at.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(now.as_str()),
                BindValue::Int64(expected_version),
                BindValue::Text(expected_state),
            ],
        )
    }

    pub async fn next_event_sequence(&self, org_id: &str, run_id: &str) -> worker::Result<i64> {
        let row = self
            .database
            .prepare(
                NEXT_EVENT_SEQUENCE_SQL,
                &[BindValue::Text(run_id), BindValue::Text(org_id)],
            )?
            .first::<Value>(None)
            .await?
            .ok_or_else(|| worker::Error::RustError("run event sequence missing".into()))?;
        let next_sequence = row
            .get("next_sequence")
            .and_then(Value::as_i64)
            .ok_or_else(|| worker::Error::RustError("run event sequence is invalid".into()))?;
        if next_sequence <= 0 || next_sequence == i64::MAX {
            return Err(worker::Error::RustError(
                "run event sequence overflow".into(),
            ));
        }
        Ok(next_sequence)
    }

    pub async fn max_attempt(&self, org_id: &str, parent_run_id: &str) -> worker::Result<i64> {
        let row = self
            .database
            .prepare(
                MAX_ATTEMPT_SQL,
                &[BindValue::Text(parent_run_id), BindValue::Text(org_id)],
            )?
            .first::<Value>(None)
            .await?
            .ok_or_else(|| worker::Error::RustError("run attempt probe missing".into()))?;
        let max_attempt = row
            .get("max_attempt")
            .and_then(Value::as_i64)
            .ok_or_else(|| worker::Error::RustError("run attempt probe is invalid".into()))?;
        if max_attempt <= 0 {
            return Err(worker::Error::RustError(
                "run attempt probe is invalid".into(),
            ));
        }
        Ok(max_attempt)
    }

    /// Build an append-only run-event statement.  The compatibility method is
    /// intentionally unscoped because older P05 consumers provide only the
    /// run/event fields; callers that have the current organization should use
    /// [`Self::insert_event_statement_for_org`] so the event cannot be attached
    /// to a run from another tenant.
    pub fn insert_event_statement(
        &self,
        input: &NewRunEventInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.insert_event_statement_for_org("", input.correlation_id, input)
    }

    /// Build a tenant-scoped append-only run-event statement.  Required event
    /// columns that are owned by the run (`org_id`, `project_id`, `device_id`,
    /// and `agent_session_id`) are derived from the persisted run row rather
    /// than accepted from a client or repeated by a caller.
    pub fn insert_event_statement_for_org(
        &self,
        org_id: &str,
        request_id: &str,
        input: &NewRunEventInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        let payload = serde_json::to_string(input.payload)
            .map_err(|_| worker::Error::RustError("run event payload is invalid".into()))?;
        self.database.prepare(
            INSERT_EVENT_SQL,
            &[
                BindValue::Text(input.run_event_id),
                BindValue::Text(request_id),
                BindValue::Int64(input.sequence),
                BindValue::Text(input.event_type),
                BindValue::Text(input.occurred_at.as_str()),
                BindValue::Text(input.actor_type),
                input.actor_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.correlation_id),
                input.tool_call_id.map_or(BindValue::Null, BindValue::Text),
                input.approval_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(&payload),
                BindValue::Text(input.run_id),
                BindValue::Text(org_id),
            ],
        )
    }

    pub async fn list_events(
        &self,
        org_id: &str,
        run_id: &str,
        after_sequence: i64,
        cursor: Option<(i64, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<RunEventRecord>> {
        let (cursor_sequence, cursor_id) = cursor.unwrap_or((0, ""));
        self.database
            .prepare(
                EVENTS_PAGE_SQL,
                &[
                    BindValue::Text(run_id),
                    BindValue::Int64(after_sequence),
                    BindValue::Int64(cursor_sequence),
                    BindValue::Text(cursor_id),
                    BindValue::Text(org_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<RunEventRecord>()
    }

    pub fn insert_artifact_statement(
        &self,
        input: &NewArtifactRefInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_ARTIFACT_SQL,
            &[
                BindValue::Text(input.artifact_ref_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.project_id),
                BindValue::Text(input.run_id),
                BindValue::Text(input.kind),
                input.content_ref.map_or(BindValue::Null, BindValue::Text),
                input.mime_type.map_or(BindValue::Null, BindValue::Text),
                input.size_bytes.map_or(BindValue::Null, BindValue::Int64),
                input.checksum.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.retention_policy),
                BindValue::Text(input.created_by_user_id),
                BindValue::Text(input.now.as_str()),
            ],
        )
    }

    pub async fn list_artifacts(
        &self,
        org_id: &str,
        run_id: &str,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<ArtifactRefRecord>> {
        let (cursor_created, cursor_id) = cursor.unwrap_or(("", ""));
        self.database
            .prepare(
                ARTIFACTS_PAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(run_id),
                    BindValue::Text(cursor_created),
                    BindValue::Text(cursor_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<ArtifactRefRecord>()
    }

    pub fn assert_agent_version_statement(
        &self,
        agent_definition_id: &str,
        org_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_AGENT_VERSION_SQL,
            &[
                BindValue::Text(agent_definition_id),
                BindValue::Text(org_id),
                BindValue::Int64(expected_version),
            ],
        )
    }

    pub fn assert_session_version_statement(
        &self,
        agent_session_id: &str,
        org_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_SESSION_VERSION_SQL,
            &[
                BindValue::Text(agent_session_id),
                BindValue::Text(org_id),
                BindValue::Int64(expected_version),
            ],
        )
    }

    pub fn assert_run_state_version_statement(
        &self,
        run_id: &str,
        org_id: &str,
        expected_version: i64,
        expected_state: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_RUN_STATE_VERSION_SQL,
            &[
                BindValue::Text(run_id),
                BindValue::Text(org_id),
                BindValue::Int64(expected_version),
                BindValue::Text(expected_state),
            ],
        )
    }

    pub fn assert_retry_attempt_absent_statement(
        &self,
        org_id: &str,
        parent_run_id: &str,
        attempt: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_RETRY_ATTEMPT_ABSENT_SQL,
            &[
                BindValue::Text(org_id),
                BindValue::Text(parent_run_id),
                BindValue::Int64(attempt),
            ],
        )
    }
}
