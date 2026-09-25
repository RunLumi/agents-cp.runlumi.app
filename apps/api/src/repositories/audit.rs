//! Tenant-scoped audit persistence for the F16 security-event contract.
//!
//! P05 does not introduce a second audit store. Its operational events are
//! projected into the existing immutable `security_events` table, while the
//! product query surface remains organization-scoped and keyset-paginated.
//! The additive P05-CR-002 run/session/tool columns are part of the required
//! forward schema; the bounded metadata fallback keeps reads compatible with
//! rows written before those columns were populated. Metadata is allow-listed
//! and bounded before it is written or returned.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::{
        AgentSessionId, CorrelationId, OrganizationId, RequestId, RunId, SecurityEventId,
        Timestamp, ToolCallId,
    },
};

pub const DEFAULT_AUDIT_PAGE_SIZE: u16 = 50;
pub const MAX_AUDIT_PAGE_SIZE: u16 = 100;
pub const MAX_AUDIT_METADATA_BYTES: usize = 16 * 1024;
pub const MAX_AUDIT_METADATA_STRING_CHARS: usize = 512;
pub const MAX_AUDIT_METADATA_DEPTH: usize = 4;
pub const MAX_AUDIT_METADATA_KEYS: usize = 32;
pub const MAX_AUDIT_METADATA_ARRAY_ITEMS: usize = 16;

const MAX_FILTER_CHARS: usize = 255;
const MAX_ACTION_CHARS: usize = 128;
const MAX_RESOURCE_TYPE_CHARS: usize = 64;
const MAX_REASON_CHARS: usize = 96;
const MAX_CURSOR_CHARS: usize = 512;

const INSERT_AUDIT_SQL: &str = r#"
INSERT INTO security_events (
    event_id, org_id, actor_type, actor_id, effective_user_id,
    session_id, device_id, run_id, agent_session_id, tool_call_id,
    action, resource_type, resource_id, outcome, reason, metadata_json,
    request_id, correlation_id, created_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
"#;

const INSERT_AUDIT_IDEMPOTENT_SQL: &str = r#"
INSERT INTO security_events (
    event_id, org_id, actor_type, actor_id, effective_user_id,
    session_id, device_id, run_id, agent_session_id, tool_call_id,
    action, resource_type, resource_id, outcome, reason, metadata_json,
    request_id, correlation_id, created_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
ON CONFLICT(event_id) DO NOTHING
"#;

const LIST_AUDIT_SQL: &str = r#"
SELECT event_id, org_id, actor_type, actor_id, effective_user_id,
       session_id, device_id, run_id, agent_session_id, tool_call_id,
       action, resource_type, resource_id, outcome, reason, metadata_json,
       request_id, correlation_id, created_at
FROM security_events
WHERE org_id = ?1
  AND (?2 = '' OR actor_id = ?2 OR effective_user_id = ?2)
  AND (?3 = '' OR action = ?3)
  AND (?4 = '' OR resource_type = ?4)
  AND (?5 = '' OR resource_id = ?5)
  AND (?6 = '' OR outcome = ?6)
  AND (?7 = '' OR correlation_id = ?7)
  AND (?8 = '' OR run_id = ?8 OR json_extract(metadata_json, '$.run_id') = ?8)
  AND (?9 = '' OR agent_session_id = ?9 OR json_extract(metadata_json, '$.agent_session_id') = ?9)
  AND (?10 = '' OR tool_call_id = ?10 OR json_extract(metadata_json, '$.tool_call_id') = ?10)
  AND (?11 = '' OR request_id = ?11)
  AND (?12 = '' OR device_id = ?12)
  AND (?13 = '' OR session_id = ?13)
  AND (?14 = '' OR json_extract(metadata_json, '$.project_id') = ?14)
  AND (?15 = '' OR created_at >= ?15)
  AND (?16 = '' OR created_at <= ?16)
  AND (?17 = '' OR created_at < ?17 OR (created_at = ?17 AND event_id < ?18))
ORDER BY created_at DESC, event_id DESC
LIMIT ?19
"#;

const GET_AUDIT_SQL: &str = r#"
SELECT event_id, org_id, actor_type, actor_id, effective_user_id,
       session_id, device_id, run_id, agent_session_id, tool_call_id,
       action, resource_type, resource_id, outcome, reason, metadata_json,
       request_id, correlation_id, created_at
FROM security_events
WHERE event_id = ?1 AND org_id = ?2
LIMIT 1
"#;

/// A query error contains no rejected value, so formatting it cannot disclose
/// an identifier, cursor, or request body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditQueryError {
    InvalidOrganization,
    InvalidFilter,
    InvalidOutcome,
    InvalidTimeRange,
    InvalidCursor,
    InvalidPage,
}

impl fmt::Display for AuditQueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidOrganization => "invalid audit organization",
            Self::InvalidFilter => "invalid audit filter",
            Self::InvalidOutcome => "invalid audit outcome",
            Self::InvalidTimeRange => "invalid audit time range",
            Self::InvalidCursor => "invalid audit cursor",
            Self::InvalidPage => "invalid audit page",
        };
        f.write_str(message)
    }
}

impl std::error::Error for AuditQueryError {}

/// Borrowed filters keep the SQL boundary free of owned request-body values.
/// `organization_id` is deliberately mandatory: an unscoped audit query is
/// not representable through this repository.
#[derive(Clone, Copy)]
pub struct AuditQuery<'a> {
    pub organization_id: &'a str,
    pub actor_id: Option<&'a str>,
    pub action: Option<&'a str>,
    pub resource_type: Option<&'a str>,
    pub resource_id: Option<&'a str>,
    pub outcome: Option<&'a str>,
    pub correlation_id: Option<&'a str>,
    pub run_id: Option<&'a str>,
    pub agent_session_id: Option<&'a str>,
    pub tool_call_id: Option<&'a str>,
    pub request_id: Option<&'a str>,
    pub device_id: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub project_id: Option<&'a str>,
    pub from: Option<&'a str>,
    pub to: Option<&'a str>,
    pub cursor: Option<&'a str>,
    pub limit: u16,
}

impl<'a> AuditQuery<'a> {
    pub const fn new(organization_id: &'a str) -> Self {
        Self {
            organization_id,
            actor_id: None,
            action: None,
            resource_type: None,
            resource_id: None,
            outcome: None,
            correlation_id: None,
            run_id: None,
            agent_session_id: None,
            tool_call_id: None,
            request_id: None,
            device_id: None,
            session_id: None,
            project_id: None,
            from: None,
            to: None,
            cursor: None,
            limit: DEFAULT_AUDIT_PAGE_SIZE,
        }
    }

    pub fn validate(&self) -> Result<(), AuditQueryError> {
        OrganizationId::new(self.organization_id)
            .map_err(|_| AuditQueryError::InvalidOrganization)?;
        if !(1..=MAX_AUDIT_PAGE_SIZE).contains(&self.limit) {
            return Err(AuditQueryError::InvalidPage);
        }
        validate_optional_text(self.actor_id, MAX_FILTER_CHARS)?;
        validate_optional_text(self.action, MAX_ACTION_CHARS)?;
        validate_optional_text(self.resource_type, MAX_RESOURCE_TYPE_CHARS)?;
        validate_optional_text(self.resource_id, MAX_FILTER_CHARS)?;
        validate_optional_text(self.request_id, MAX_FILTER_CHARS)?;
        validate_optional_text(self.device_id, MAX_FILTER_CHARS)?;
        validate_optional_text(self.session_id, MAX_FILTER_CHARS)?;
        validate_optional_text(self.project_id, MAX_FILTER_CHARS)?;
        if let Some(value) = self.outcome
            && !matches!(value, "success" | "denied" | "failure")
        {
            return Err(AuditQueryError::InvalidOutcome);
        }
        if let Some(value) = self.correlation_id {
            CorrelationId::new(value).map_err(|_| AuditQueryError::InvalidFilter)?;
        }
        if let Some(value) = self.request_id {
            RequestId::new(value).map_err(|_| AuditQueryError::InvalidFilter)?;
        }
        if let Some(value) = self.run_id {
            RunId::new(value).map_err(|_| AuditQueryError::InvalidFilter)?;
        }
        if let Some(value) = self.agent_session_id {
            AgentSessionId::new(value).map_err(|_| AuditQueryError::InvalidFilter)?;
        }
        if let Some(value) = self.tool_call_id {
            ToolCallId::new(value).map_err(|_| AuditQueryError::InvalidFilter)?;
        }
        if let Some(value) = self.from {
            Timestamp::new(value).map_err(|_| AuditQueryError::InvalidTimeRange)?;
        }
        if let Some(value) = self.to {
            Timestamp::new(value).map_err(|_| AuditQueryError::InvalidTimeRange)?;
        }
        if let (Some(from), Some(to)) = (self.from, self.to)
            && from > to
        {
            return Err(AuditQueryError::InvalidTimeRange);
        }
        if let Some(cursor) = self.cursor {
            decode_cursor(cursor).map_err(|_| AuditQueryError::InvalidCursor)?;
        }
        Ok(())
    }
}

/// Result of an atomic idempotent append.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditAppendOutcome {
    Inserted,
    Duplicate,
}

/// A safe, tenant-scoped projection of one immutable F16 event.
#[derive(Clone, Deserialize, PartialEq, Serialize)]
pub struct AuditRecord {
    pub event_id: String,
    pub org_id: String,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub effective_user_id: Option<String>,
    pub session_id: Option<String>,
    pub device_id: Option<String>,
    pub run_id: Option<String>,
    pub agent_session_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub outcome: String,
    pub reason: Option<String>,
    pub metadata: Value,
    pub request_id: String,
    pub correlation_id: String,
    pub created_at: String,
}

impl fmt::Debug for AuditRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditRecord")
            .field("event_id", &self.event_id)
            .field("org_id", &self.org_id)
            .field("actor_type", &self.actor_type)
            .field("actor_id", &self.actor_id.as_ref().map(|_| "[redacted]"))
            .field(
                "effective_user_id",
                &self.effective_user_id.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "session_id",
                &self.session_id.as_ref().map(|_| "[redacted]"),
            )
            .field("device_id", &self.device_id.as_ref().map(|_| "[redacted]"))
            .field("run_id", &self.run_id)
            .field("agent_session_id", &self.agent_session_id)
            .field("tool_call_id", &self.tool_call_id)
            .field("action", &self.action)
            .field("resource_type", &self.resource_type)
            .field("resource_id", &self.resource_id)
            .field("outcome", &self.outcome)
            .field("reason", &self.reason)
            .field("metadata", &"[redacted]")
            .field("request_id", &self.request_id)
            .field("correlation_id", &self.correlation_id)
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Clone, PartialEq, Serialize)]
pub struct AuditPage {
    pub items: Vec<AuditRecord>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

/// Values accepted by a transactional audit append.  The repository sanitizes
/// `metadata` before it reaches D1; callers cannot bypass the redaction policy
/// by constructing a prepared statement themselves.
#[derive(Clone, Copy)]
pub struct AuditEventInput<'a> {
    pub event_id: &'a str,
    pub organization_id: &'a str,
    pub actor_type: &'a str,
    pub actor_id: Option<&'a str>,
    pub effective_user_id: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub device_id: Option<&'a str>,
    pub run_id: Option<&'a str>,
    pub agent_session_id: Option<&'a str>,
    pub tool_call_id: Option<&'a str>,
    pub action: &'a str,
    pub resource_type: &'a str,
    pub resource_id: Option<&'a str>,
    pub outcome: &'a str,
    pub reason: Option<&'a str>,
    pub metadata: &'a Value,
    pub request_id: &'a str,
    pub correlation_id: &'a str,
    pub created_at: &'a Timestamp,
}

pub struct AuditRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> AuditRepository<'a> {
    pub const fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    /// Build a normal immutable insert for use in the same D1 batch as the
    /// business mutation and any outbox row.
    pub fn insert_statement(
        &self,
        event: &AuditEventInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.prepare_insert(INSERT_AUDIT_SQL, event)
    }

    /// Build an insert that treats only an existing `event_id` as a duplicate.
    /// No update path exists, so retries cannot rewrite audit history.
    pub fn insert_idempotent_statement(
        &self,
        event: &AuditEventInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.prepare_insert(INSERT_AUDIT_IDEMPOTENT_SQL, event)
    }

    pub async fn append_idempotent(
        &self,
        event: &AuditEventInput<'_>,
    ) -> worker::Result<AuditAppendOutcome> {
        let result = self.insert_idempotent_statement(event)?.run().await?;
        match D1Adapter::changes(&result)? {
            0 => Ok(AuditAppendOutcome::Duplicate),
            1 => Ok(AuditAppendOutcome::Inserted),
            _ => Err(worker::Error::RustError(
                "audit append changed an unexpected number of rows".into(),
            )),
        }
    }

    pub async fn get_for_organization(
        &self,
        event_id: &str,
        organization_id: &str,
    ) -> worker::Result<Option<AuditRecord>> {
        validate_event_id(event_id).map_err(|_| invalid_record())?;
        OrganizationId::new(organization_id).map_err(|_| invalid_record())?;
        let row = self
            .database
            .prepare(
                GET_AUDIT_SQL,
                &[BindValue::Text(event_id), BindValue::Text(organization_id)],
            )?
            .first::<AuditRow>(None)
            .await?;
        row.map(try_into_record).transpose()
    }

    /// Query one tenant's audit stream with deterministic `(created_at,
    /// event_id)` keyset pagination.  The extra row is used to calculate
    /// `has_more` without an unbounded offset scan.
    pub async fn query(&self, query: &AuditQuery<'_>) -> worker::Result<AuditPage> {
        query.validate().map_err(|_| invalid_record())?;
        let (cursor_created_at, cursor_event_id) = match query.cursor {
            Some(cursor) => decode_cursor(cursor).map_err(|_| invalid_record())?,
            None => (String::new(), String::new()),
        };
        let actor_id = query.actor_id.unwrap_or("");
        let action = query.action.unwrap_or("");
        let resource_type = query.resource_type.unwrap_or("");
        let resource_id = query.resource_id.unwrap_or("");
        let outcome = query.outcome.unwrap_or("");
        let correlation_id = query.correlation_id.unwrap_or("");
        let run_id = query.run_id.unwrap_or("");
        let agent_session_id = query.agent_session_id.unwrap_or("");
        let tool_call_id = query.tool_call_id.unwrap_or("");
        let request_id = query.request_id.unwrap_or("");
        let device_id = query.device_id.unwrap_or("");
        let session_id = query.session_id.unwrap_or("");
        let project_id = query.project_id.unwrap_or("");
        let from = query.from.unwrap_or("");
        let to = query.to.unwrap_or("");
        let statement = self.database.prepare(
            LIST_AUDIT_SQL,
            &[
                BindValue::Text(query.organization_id),
                BindValue::Text(actor_id),
                BindValue::Text(action),
                BindValue::Text(resource_type),
                BindValue::Text(resource_id),
                BindValue::Text(outcome),
                BindValue::Text(correlation_id),
                BindValue::Text(run_id),
                BindValue::Text(agent_session_id),
                BindValue::Text(tool_call_id),
                BindValue::Text(request_id),
                BindValue::Text(device_id),
                BindValue::Text(session_id),
                BindValue::Text(project_id),
                BindValue::Text(from),
                BindValue::Text(to),
                BindValue::Text(&cursor_created_at),
                BindValue::Text(&cursor_event_id),
                BindValue::Integer(i32::from(query.limit.saturating_add(1))),
            ],
        )?;
        let rows = statement
            .all()
            .await?
            .results::<AuditRow>()?
            .into_iter()
            .map(try_into_record)
            .collect::<worker::Result<Vec<_>>>()?;
        let has_more = rows.len() > usize::from(query.limit);
        let mut items = rows;
        if has_more {
            items.pop();
        }
        let next_cursor = if has_more {
            items
                .last()
                .map(|item| encode_cursor(&item.created_at, &item.event_id))
        } else {
            None
        };
        Ok(AuditPage {
            items,
            next_cursor,
            has_more,
        })
    }

    /// Small convenience API for callers that need only the common tenant
    /// stream.  Rich F16 filters are available through [`Self::query`].
    pub async fn list(
        &self,
        organization_id: &str,
        limit: u16,
        cursor: Option<&str>,
    ) -> worker::Result<AuditPage> {
        self.query(&AuditQuery {
            cursor,
            limit,
            ..AuditQuery::new(organization_id)
        })
        .await
    }

    fn prepare_insert(
        &self,
        sql: &str,
        event: &AuditEventInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        validate_event_input(event).map_err(|_| invalid_record())?;
        let metadata = serde_json::to_string(&bounded_metadata(event.metadata))
            .map_err(|_| invalid_record())?;
        self.database
            .prepare(
                sql,
                &[
                    BindValue::Text(event.event_id),
                    BindValue::Text(event.organization_id),
                    BindValue::Text(event.actor_type),
                    optional_bind(event.actor_id),
                    optional_bind(event.effective_user_id),
                    optional_bind(event.session_id),
                    optional_bind(event.device_id),
                    optional_bind(event.run_id),
                    optional_bind(event.agent_session_id),
                    optional_bind(event.tool_call_id),
                    BindValue::Text(event.action),
                    BindValue::Text(event.resource_type),
                    optional_bind(event.resource_id),
                    BindValue::Text(event.outcome),
                    optional_bind(event.reason),
                    BindValue::Text(&metadata),
                    BindValue::Text(event.request_id),
                    BindValue::Text(event.correlation_id),
                    BindValue::Text(event.created_at.as_str()),
                ],
            )
            .map_err(|_| worker::Error::RustError("audit store is unavailable".into()))
    }
}

fn optional_bind(value: Option<&str>) -> BindValue<'_> {
    value.map_or(BindValue::Null, BindValue::Text)
}

fn validate_event_input(event: &AuditEventInput<'_>) -> Result<(), AuditQueryError> {
    validate_event_id(event.event_id).map_err(|_| AuditQueryError::InvalidFilter)?;
    OrganizationId::new(event.organization_id).map_err(|_| AuditQueryError::InvalidOrganization)?;
    if !matches!(
        event.actor_type,
        "user" | "service_account" | "support" | "system" | "anonymous"
    ) {
        return Err(AuditQueryError::InvalidFilter);
    }
    validate_optional_text(event.actor_id, MAX_FILTER_CHARS)?;
    validate_optional_text(event.effective_user_id, MAX_FILTER_CHARS)?;
    validate_optional_text(event.session_id, MAX_FILTER_CHARS)?;
    validate_optional_text(event.device_id, MAX_FILTER_CHARS)?;
    if let Some(value) = event.run_id {
        RunId::new(value).map_err(|_| AuditQueryError::InvalidFilter)?;
    }
    if let Some(value) = event.agent_session_id {
        AgentSessionId::new(value).map_err(|_| AuditQueryError::InvalidFilter)?;
    }
    if let Some(value) = event.tool_call_id {
        ToolCallId::new(value).map_err(|_| AuditQueryError::InvalidFilter)?;
    }
    validate_text(event.action, MAX_ACTION_CHARS)?;
    validate_text(event.resource_type, MAX_RESOURCE_TYPE_CHARS)?;
    validate_optional_text(event.resource_id, MAX_FILTER_CHARS)?;
    if !matches!(event.outcome, "success" | "denied" | "failure") {
        return Err(AuditQueryError::InvalidOutcome);
    }
    if let Some(reason) = event.reason {
        validate_code(reason, MAX_REASON_CHARS)?;
    }
    RequestId::new(event.request_id).map_err(|_| AuditQueryError::InvalidFilter)?;
    CorrelationId::new(event.correlation_id).map_err(|_| AuditQueryError::InvalidFilter)?;
    if Timestamp::new(event.created_at.as_str()).is_err() {
        return Err(AuditQueryError::InvalidTimeRange);
    }
    let metadata = bounded_metadata(event.metadata);
    if serde_json::to_vec(&metadata)
        .map(|bytes| bytes.len() > MAX_AUDIT_METADATA_BYTES)
        .unwrap_or(true)
    {
        return Err(AuditQueryError::InvalidFilter);
    }
    Ok(())
}

fn validate_event_id(value: &str) -> Result<(), AuditQueryError> {
    SecurityEventId::new(value)
        .map(|_| ())
        .map_err(|_| AuditQueryError::InvalidFilter)
}

fn validate_optional_text(value: Option<&str>, max: usize) -> Result<(), AuditQueryError> {
    value.map_or(Ok(()), |value| validate_text(value, max))
}

fn validate_text(value: &str, max: usize) -> Result<(), AuditQueryError> {
    if value.is_empty() || value.chars().count() > max || value.chars().any(char::is_control) {
        return Err(AuditQueryError::InvalidFilter);
    }
    Ok(())
}

fn validate_code(value: &str, max: usize) -> Result<(), AuditQueryError> {
    if value.is_empty()
        || value.len() > max
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return Err(AuditQueryError::InvalidFilter);
    }
    Ok(())
}

fn invalid_record() -> worker::Error {
    worker::Error::RustError("invalid audit record".into())
}

#[derive(Deserialize)]
struct AuditRow {
    event_id: String,
    org_id: String,
    actor_type: String,
    actor_id: Option<String>,
    effective_user_id: Option<String>,
    session_id: Option<String>,
    device_id: Option<String>,
    run_id: Option<String>,
    agent_session_id: Option<String>,
    tool_call_id: Option<String>,
    action: String,
    resource_type: String,
    resource_id: Option<String>,
    outcome: String,
    reason: Option<String>,
    metadata_json: String,
    request_id: String,
    correlation_id: String,
    created_at: String,
}

fn try_into_record(row: AuditRow) -> worker::Result<AuditRecord> {
    let raw_metadata: Value = serde_json::from_str(&row.metadata_json)
        .map_err(|_| worker::Error::RustError("invalid audit metadata".into()))?;
    let metadata = bounded_metadata(&raw_metadata);
    let run_id = nonempty(row.run_id).or_else(|| {
        metadata
            .get("run_id")
            .and_then(Value::as_str)
            .filter(|value| RunId::new(*value).is_ok())
            .map(str::to_owned)
    });
    let agent_session_id = nonempty(row.agent_session_id).or_else(|| {
        metadata
            .get("agent_session_id")
            .and_then(Value::as_str)
            .filter(|value| AgentSessionId::new(*value).is_ok())
            .map(str::to_owned)
    });
    let tool_call_id = nonempty(row.tool_call_id).or_else(|| {
        metadata
            .get("tool_call_id")
            .and_then(Value::as_str)
            .filter(|value| ToolCallId::new(*value).is_ok())
            .map(str::to_owned)
    });
    Ok(AuditRecord {
        event_id: row.event_id,
        org_id: row.org_id,
        actor_type: row.actor_type,
        actor_id: nonempty(row.actor_id),
        effective_user_id: nonempty(row.effective_user_id),
        session_id: nonempty(row.session_id),
        device_id: nonempty(row.device_id),
        run_id,
        agent_session_id,
        tool_call_id,
        action: row.action,
        resource_type: row.resource_type,
        resource_id: nonempty(row.resource_id),
        outcome: row.outcome,
        reason: safe_reason(row.reason),
        metadata,
        request_id: row.request_id,
        correlation_id: row.correlation_id,
        created_at: row.created_at,
    })
}

fn nonempty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

fn safe_reason(value: Option<String>) -> Option<String> {
    value.filter(|value| validate_code(value, MAX_REASON_CHARS).is_ok())
}

/// Encode the keyset used by [`AuditRepository::query`].  The result is
/// opaque to HTTP clients and contains only a timestamp and immutable event
/// identifier.
pub fn encode_audit_cursor(created_at: &str, event_id: &str) -> String {
    encode_cursor(created_at, event_id)
}

fn encode_cursor(created_at: &str, event_id: &str) -> String {
    use std::fmt::Write as _;
    let raw = format!("{created_at}|{event_id}");
    let mut encoded = String::with_capacity(raw.len() * 2);
    for byte in raw.as_bytes() {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn decode_cursor(raw: &str) -> Result<(String, String), AuditQueryError> {
    if raw.is_empty() || raw.len() > MAX_CURSOR_CHARS || !raw.len().is_multiple_of(2) {
        return Err(AuditQueryError::InvalidCursor);
    }
    let mut decoded = Vec::with_capacity(raw.len() / 2);
    for pair in raw.as_bytes().chunks(2) {
        let high = hex_value(pair[0]).ok_or(AuditQueryError::InvalidCursor)?;
        let low = hex_value(pair[1]).ok_or(AuditQueryError::InvalidCursor)?;
        decoded.push((high << 4) | low);
    }
    let text = String::from_utf8(decoded).map_err(|_| AuditQueryError::InvalidCursor)?;
    let (created_at, event_id) = text.split_once('|').ok_or(AuditQueryError::InvalidCursor)?;
    Timestamp::new(created_at).map_err(|_| AuditQueryError::InvalidCursor)?;
    SecurityEventId::new(event_id).map_err(|_| AuditQueryError::InvalidCursor)?;
    Ok((created_at.to_owned(), event_id.to_owned()))
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Redact and bound arbitrary event metadata before persistence or display.
///
/// The allow-list is intentionally conservative.  In particular, prompt,
/// response, tool-argument, credential, token, and file-content fields are
/// dropped even if a caller labels them with an otherwise harmless key.
pub fn bounded_metadata(value: &Value) -> Value {
    let sanitized = sanitize_value(value, None, 0);
    let object = match sanitized {
        Value::Object(object) => object,
        // Audit metadata is an allow-listed object. Do not wrap a scalar or
        // array under a synthetic key: callers must not turn an arbitrary
        // prompt/body value into persisted metadata by choosing a non-object
        // JSON shape.
        _ => Map::new(),
    };
    bound_object(object)
}

fn sanitize_value(value: &Value, key: Option<&str>, depth: usize) -> Value {
    if depth > MAX_AUDIT_METADATA_DEPTH {
        return Value::String("[truncated]".to_owned());
    }
    match value {
        Value::Null => Value::Null,
        Value::Bool(value) => Value::Bool(*value),
        Value::Number(value) => Value::Number(value.clone()),
        Value::String(value) => Value::String(sanitize_string(value, key)),
        Value::Array(values) => {
            if depth >= MAX_AUDIT_METADATA_DEPTH {
                return Value::String("[truncated]".to_owned());
            }
            Value::Array(
                values
                    .iter()
                    .take(MAX_AUDIT_METADATA_ARRAY_ITEMS)
                    .map(|item| sanitize_value(item, key, depth + 1))
                    .collect(),
            )
        }
        Value::Object(values) => {
            let mut entries = values
                .iter()
                .filter(|(child_key, _)| is_safe_metadata_key(child_key))
                .take(MAX_AUDIT_METADATA_KEYS * 4)
                .collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| {
                metadata_key_priority(left).cmp(&metadata_key_priority(right))
            });
            entries.truncate(MAX_AUDIT_METADATA_KEYS);
            let mut sanitized = Map::new();
            for (child_key, child_value) in entries {
                let normalized_key = child_key.to_ascii_lowercase().replace('-', "_");
                sanitized.insert(
                    normalized_key,
                    sanitize_value(child_value, Some(child_key), depth + 1),
                );
            }
            Value::Object(sanitized)
        }
    }
}

fn sanitize_string(value: &str, key: Option<&str>) -> String {
    let mut sanitized = String::with_capacity(value.len().min(MAX_AUDIT_METADATA_STRING_CHARS));
    for character in value.chars() {
        if character.is_control() {
            sanitized.push(' ');
        } else if sanitized.chars().count() >= MAX_AUDIT_METADATA_STRING_CHARS {
            sanitized.push('…');
            break;
        } else {
            sanitized.push(character);
        }
    }
    if key.is_some_and(is_code_key) {
        if is_stable_metadata_code(value) {
            value.chars().take(MAX_REASON_CHARS).collect()
        } else {
            "[redacted]".to_owned()
        }
    } else {
        sanitized
    }
}

fn bound_object(object: Map<String, Value>) -> Value {
    let mut entries: Vec<(String, Value)> = object.into_iter().collect();
    entries.sort_by_key(|(key, _)| metadata_key_priority(key));
    entries.truncate(MAX_AUDIT_METADATA_KEYS);

    let initial_size = serde_json::to_vec(&Value::Object(entries_to_map(entries.clone())))
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX);
    if initial_size <= MAX_AUDIT_METADATA_BYTES {
        return Value::Object(entries_to_map(entries));
    }

    let mut bounded = Map::new();
    bounded.insert("_truncated".to_owned(), Value::Bool(true));
    for (key, value) in entries {
        let mut candidate = bounded.clone();
        candidate.insert(key, value);
        if serde_json::to_vec(&Value::Object(candidate.clone()))
            .map(|bytes| bytes.len() <= MAX_AUDIT_METADATA_BYTES)
            .unwrap_or(false)
        {
            bounded = candidate;
        }
    }
    Value::Object(bounded)
}

fn entries_to_map(entries: Vec<(String, Value)>) -> Map<String, Value> {
    entries.into_iter().collect()
}

fn metadata_key_priority(key: &str) -> u8 {
    match key {
        "run_id" => 0,
        "agent_session_id" => 1,
        "project_id" => 2,
        "device_id" => 3,
        "request_id" => 4,
        "correlation_id" => 5,
        "event_type" => 6,
        "resource_id" | "tool_call_id" | "approval_id" | "usage_event_id" => 7,
        _ => 8,
    }
}

fn is_safe_metadata_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace('-', "_");
    if normalized.is_empty() || normalized.len() > 64 || normalized.chars().any(char::is_control) {
        return false;
    }
    const SENSITIVE_FRAGMENTS: &[&str] = &[
        "prompt",
        "response",
        "completion",
        "message_body",
        "request_body",
        "response_body",
        "tool_argument",
        "arguments",
        "args",
        "secret",
        "access_token",
        "refresh_token",
        "auth_token",
        "bearer_token",
        "id_token",
        "password",
        "credential",
        "authorization",
        "cookie",
        "private_key",
        "api_key",
        "access_key",
        "refresh",
        "file_content",
        "content",
        "body",
        "command",
        "url",
        "endpoint",
    ];
    if SENSITIVE_FRAGMENTS
        .iter()
        .any(|fragment| normalized.contains(fragment))
    {
        return false;
    }
    const SAFE_KEYS: &[&str] = &[
        "run_id",
        "parent_run_id",
        "agent_session_id",
        "project_id",
        "device_id",
        "session_id",
        "login_session_id",
        "request_id",
        "correlation_id",
        "event_type",
        "resource_type",
        "resource_id",
        "agent_definition_id",
        "agent_definition_version",
        "model_alias",
        "route_id",
        "route_version_id",
        "provider_id",
        "credential_mode",
        "risk_class",
        "tool_id",
        "tool_call_id",
        "tool_fingerprint",
        "mcp_id",
        "approval_id",
        "artifact_id",
        "usage_event_id",
        "budget_id",
        "reservation_id",
        "rate_limit_policy_id",
        "decision",
        "reason",
        "reason_code",
        "failure_code",
        "error_code",
        "state",
        "previous_state",
        "next_state",
        "attempt",
        "status",
        "outcome",
        "approval_mode",
        "source",
        "reconciliation_status",
        "limit_minor",
        "reserved_minor",
        "actual_minor",
        "cost_minor",
        "currency",
        "input_tokens",
        "output_tokens",
        "cached_tokens",
        "policy_version",
        "stream",
        "operation",
        "domain",
        "action",
        "kind",
        "scope_type",
        "scope_id",
        "fields",
        "changed_fields",
        "required_capabilities",
        "allowed_tool_ids",
        "runtime_requirements",
        "fingerprint_changed",
        "reservation_status",
        "budget_state",
        "tool_count",
        "item_count",
        "version",
        "count",
        "actor_kind",
        "execution_mode",
        "input_ref_present",
        "execution_host_signal",
        "dispatch_signal",
        "reason_present",
        "mime_type",
        "size_bytes",
    ];
    SAFE_KEYS.contains(&normalized.as_str())
}

fn is_stable_metadata_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REASON_CHARS
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

fn is_code_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().replace('-', "_").as_str(),
        "reason"
            | "reason_code"
            | "failure_code"
            | "error_code"
            | "decision"
            | "state"
            | "previous_state"
            | "next_state"
            | "outcome"
            | "status"
            | "source"
            | "reconciliation_status"
            | "approval_mode"
            | "risk_class"
            | "credential_mode"
            | "policy_version"
            | "actor_kind"
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn metadata_drops_sensitive_fields_and_stays_bounded() {
        let value = json!({
            "run-id": "run_0123456789abcdef0123456789abcdef",
            "prompt": "do not persist this",
            "response": "nor this",
            "tool_arguments": {"password": "do not persist"},
            "decision": "deny",
            "input_tokens": 42,
            "nested": {"secret": "hidden"},
            "safe": "x".repeat(MAX_AUDIT_METADATA_STRING_CHARS + 100)
        });
        let bounded = bounded_metadata(&value);
        assert_eq!(bounded["run_id"], "run_0123456789abcdef0123456789abcdef");
        assert_eq!(bounded["decision"], "deny");
        assert_eq!(bounded["input_tokens"], 42);
        assert!(bounded.get("prompt").is_none());
        assert!(bounded.get("response").is_none());
        assert!(bounded.get("tool_arguments").is_none());
        assert!(bounded.get("nested").is_none());
        assert!(serde_json::to_vec(&bounded).unwrap().len() <= MAX_AUDIT_METADATA_BYTES);
        assert!(!format!("{bounded:?}").contains("do not persist"));
        assert_eq!(bounded_metadata(&json!("private scalar")), json!({}));
        assert_eq!(bounded_metadata(&json!(["private array"])), json!({}));
    }

    #[test]
    fn metadata_prioritizes_run_correlation_ids_when_truncating() {
        let mut value = Map::new();
        value.insert(
            "run_id".to_owned(),
            json!("run_0123456789abcdef0123456789abcdef"),
        );
        value.insert(
            "request_id".to_owned(),
            json!("req_0123456789abcdef0123456789abcdef"),
        );
        value.insert("correlation_id".to_owned(), json!("trace-1"));
        for index in 0..MAX_AUDIT_METADATA_KEYS {
            value.insert(
                format!("safe_{index}"),
                json!("x".repeat(MAX_AUDIT_METADATA_STRING_CHARS)),
            );
        }
        // Unknown keys are intentionally not retained by the allow-list.
        let bounded = bounded_metadata(&Value::Object(value));
        assert_eq!(bounded["run_id"], "run_0123456789abcdef0123456789abcdef");
        assert_eq!(
            bounded["request_id"],
            "req_0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn query_requires_a_valid_tenant_and_page_limit() {
        let mut query = AuditQuery::new("org_0123456789abcdef0123456789abcdef");
        assert!(query.validate().is_ok());
        query.limit = 0;
        assert_eq!(query.validate(), Err(AuditQueryError::InvalidPage));
        let query = AuditQuery::new("not-an-org");
        assert_eq!(query.validate(), Err(AuditQueryError::InvalidOrganization));
    }

    #[test]
    fn query_validates_run_correlation_and_time_filters() {
        let mut query = AuditQuery::new("org_0123456789abcdef0123456789abcdef");
        query.run_id = Some("run_0123456789abcdef0123456789abcdef");
        query.correlation_id = Some("trace-1");
        query.from = Some("2026-09-24T00:00:00.000Z");
        query.to = Some("2026-09-25T00:00:00.000Z");
        assert!(query.validate().is_ok());
        query.from = Some("2026-09-26T00:00:00.000Z");
        assert_eq!(query.validate(), Err(AuditQueryError::InvalidTimeRange));
    }

    #[test]
    fn audit_cursor_round_trips_and_rejects_tampering() {
        let cursor = encode_audit_cursor(
            "2026-09-24T12:00:00.000Z",
            "sec_0123456789abcdef0123456789abcdef",
        );
        let (created_at, event_id) = decode_cursor(&cursor).unwrap();
        assert_eq!(created_at, "2026-09-24T12:00:00.000Z");
        assert_eq!(event_id, "sec_0123456789abcdef0123456789abcdef");
        assert!(decode_cursor("not-a-cursor").is_err());
        let tampered = format!("z{}", &cursor[1..]);
        assert!(decode_cursor(&tampered).is_err());
    }

    #[test]
    fn append_validation_rejects_unbounded_or_unstable_values() {
        let timestamp: Timestamp = "2026-09-24T12:00:00.000Z".parse().unwrap();
        let metadata = json!({"run_id": "run_0123456789abcdef0123456789abcdef"});
        let input = AuditEventInput {
            event_id: "sec_0123456789abcdef0123456789abcdef",
            organization_id: "org_0123456789abcdef0123456789abcdef",
            actor_type: "user",
            actor_id: Some("usr_0123456789abcdef0123456789abcdef"),
            effective_user_id: Some("usr_0123456789abcdef0123456789abcdef"),
            session_id: Some("ses_0123456789abcdef0123456789abcdef"),
            device_id: Some("dvc_0123456789abcdef0123456789abcdef"),
            run_id: Some("run_0123456789abcdef0123456789abcdef"),
            agent_session_id: Some("rse_0123456789abcdef0123456789abcdef"),
            tool_call_id: None,
            action: "run.created.v1",
            resource_type: "run",
            resource_id: Some("run_0123456789abcdef0123456789abcdef"),
            outcome: "success",
            reason: None,
            metadata: &metadata,
            request_id: "req_0123456789abcdef0123456789abcdef",
            correlation_id: "trace-1",
            created_at: &timestamp,
        };
        assert!(validate_event_input(&input).is_ok());
        let mut invalid = input;
        invalid.outcome = "unknown";
        assert_eq!(
            validate_event_input(&invalid),
            Err(AuditQueryError::InvalidOutcome)
        );
    }
}
