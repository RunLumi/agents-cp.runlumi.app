use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::Timestamp,
};

const INSERT_SECURITY_EVENT_SQL: &str = r#"
INSERT INTO security_events (
    event_id, org_id, actor_type, actor_id, effective_user_id,
    session_id, device_id, action, resource_type, resource_id,
    outcome, reason, metadata_json, request_id, correlation_id, created_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
"#;

const LIST_SECURITY_EVENTS_SQL: &str = r#"
SELECT event_id, org_id, actor_type, actor_id, effective_user_id,
       session_id, device_id, action, resource_type, resource_id,
       outcome, reason, metadata_json, request_id, correlation_id, created_at
FROM security_events
WHERE (?1 = '' OR org_id = ?1)
  AND (?2 = '' OR action = ?2)
ORDER BY created_at DESC, event_id DESC
LIMIT ?3 OFFSET ?4
"#;

#[derive(Clone, Debug)]
pub struct SecurityEventInput<'a> {
    pub event_id: &'a str,
    pub organization_id: Option<&'a str>,
    pub actor_type: &'a str,
    pub actor_id: Option<&'a str>,
    pub effective_user_id: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub device_id: Option<&'a str>,
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

#[derive(Clone, Deserialize, Serialize)]
pub struct SecurityEventRecord {
    pub event_id: String,
    pub org_id: Option<String>,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub effective_user_id: Option<String>,
    pub session_id: Option<String>,
    pub device_id: Option<String>,
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

const LIST_SECURITY_EVENTS_FOR_USER_SQL: &str = r#"
SELECT event_id, org_id, actor_type, actor_id, effective_user_id,
       session_id, device_id, action, resource_type, resource_id,
       outcome, reason, metadata_json, request_id, correlation_id, created_at
FROM security_events
WHERE actor_id = ?1 OR effective_user_id = ?1
ORDER BY created_at DESC, event_id DESC
LIMIT ?2 OFFSET ?3
"#;

#[derive(Deserialize)]
struct SecurityEventRow {
    event_id: String,
    org_id: Option<String>,
    actor_type: String,
    actor_id: Option<String>,
    effective_user_id: Option<String>,
    session_id: Option<String>,
    device_id: Option<String>,
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

pub struct SecurityEventRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> SecurityEventRepository<'a> {
    pub fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    pub fn insert_statement(
        &self,
        event: &SecurityEventInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        let metadata = serde_json::to_string(event.metadata)
            .map_err(|_| worker::Error::RustError("security event metadata is invalid".into()))?;
        let organization_id = event.organization_id.map_or(BindValue::Null, BindValue::Text);
        let actor_id = event.actor_id.map_or(BindValue::Null, BindValue::Text);
        let effective_user_id = event.effective_user_id.map_or(BindValue::Null, BindValue::Text);
        let session_id = event.session_id.map_or(BindValue::Null, BindValue::Text);
        let device_id = event.device_id.map_or(BindValue::Null, BindValue::Text);
        let resource_id = event.resource_id.map_or(BindValue::Null, BindValue::Text);
        let reason = event.reason.map_or(BindValue::Null, BindValue::Text);
        self.database.prepare(
            INSERT_SECURITY_EVENT_SQL,
            &[
                BindValue::Text(event.event_id),
                organization_id,
                BindValue::Text(event.actor_type),
                actor_id,
                effective_user_id,
                session_id,
                device_id,
                BindValue::Text(event.action),
                BindValue::Text(event.resource_type),
                resource_id,
                BindValue::Text(event.outcome),
                reason,
                BindValue::Text(&metadata),
                BindValue::Text(event.request_id),
                BindValue::Text(event.correlation_id),
                BindValue::Text(event.created_at.as_str()),
            ],
        )
    }

    pub async fn list_for_user(
        &self,
        user_id: &str,
        limit: u16,
        offset: u32,
    ) -> worker::Result<Vec<SecurityEventRecord>> {
        if !(1..=100).contains(&limit) || offset > 10_000 {
            return Err(worker::Error::RustError("invalid security event page".into()));
        }
        let result = self
            .database
            .prepare(
                LIST_SECURITY_EVENTS_FOR_USER_SQL,
                &[
                    BindValue::Text(user_id),
                    BindValue::Integer(i32::from(limit)),
                    BindValue::Integer(offset as i32),
                ],
            )?
            .all()
            .await?;
        result
            .results::<SecurityEventRow>()?
            .into_iter()
            .map(|row| {
                let metadata = serde_json::from_str(&row.metadata_json).map_err(|_| {
                    worker::Error::RustError("invalid security event metadata".into())
                })?;
                Ok(SecurityEventRecord {
                    event_id: row.event_id,
                    org_id: nonempty(row.org_id),
                    actor_type: row.actor_type,
                    actor_id: nonempty(row.actor_id),
                    effective_user_id: nonempty(row.effective_user_id),
                    session_id: nonempty(row.session_id),
                    device_id: nonempty(row.device_id),
                    action: row.action,
                    resource_type: row.resource_type,
                    resource_id: nonempty(row.resource_id),
                    outcome: row.outcome,
                    reason: nonempty(row.reason),
                    metadata,
                    request_id: row.request_id,
                    correlation_id: row.correlation_id,
                    created_at: row.created_at,
                })
            })
            .collect()
    }

    pub async fn list(
        &self,
        organization_id: Option<&str>,
        action: Option<&str>,
        limit: u16,
        offset: u32,
    ) -> worker::Result<Vec<SecurityEventRecord>> {
        if !(1..=100).contains(&limit) || offset > 10_000 {
            return Err(worker::Error::RustError("invalid security event page".into()));
        }
        let statement = self.database.prepare(
            LIST_SECURITY_EVENTS_SQL,
            &[
                BindValue::Text(organization_id.unwrap_or("")),
                BindValue::Text(action.unwrap_or("")),
                BindValue::Integer(i32::from(limit)),
                BindValue::Integer(offset as i32),
            ],
        )?;
        let result = statement.all().await?;
        result
            .results::<SecurityEventRow>()?
            .into_iter()
            .map(|row| {
                let metadata = serde_json::from_str(&row.metadata_json)
                    .map_err(|_| worker::Error::RustError("invalid security event metadata".into()))?;
                Ok(SecurityEventRecord {
                    event_id: row.event_id,
                    org_id: nonempty(row.org_id),
                    actor_type: row.actor_type,
                    actor_id: nonempty(row.actor_id),
                    effective_user_id: nonempty(row.effective_user_id),
                    session_id: nonempty(row.session_id),
                    device_id: nonempty(row.device_id),
                    action: row.action,
                    resource_type: row.resource_type,
                    resource_id: nonempty(row.resource_id),
                    outcome: row.outcome,
                    reason: nonempty(row.reason),
                    metadata,
                    request_id: row.request_id,
                    correlation_id: row.correlation_id,
                    created_at: row.created_at,
                })
            })
            .collect()
    }
}

fn nonempty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}
