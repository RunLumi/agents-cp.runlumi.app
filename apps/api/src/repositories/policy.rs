//! D1 persistence for P03 versioned policy snapshots and device acks.

use serde::{Deserialize, Serialize};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::Timestamp,
};

const INSERT_SNAPSHOT_SQL: &str = r#"
INSERT INTO policy_snapshots (policy_id, org_id, policy_version, payload, issued_at, expires_at, created_at)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?5)
"#;

const SNAPSHOT_BY_ID_SQL: &str = r#"
SELECT policy_id, org_id, policy_version, payload, issued_at, expires_at, created_at
FROM policy_snapshots
WHERE policy_id = ?1
LIMIT 1
"#;

const LATEST_SNAPSHOT_SQL: &str = r#"
SELECT policy_id, org_id, policy_version, payload, issued_at, expires_at, created_at
FROM policy_snapshots
WHERE org_id = ?1
ORDER BY policy_version DESC
LIMIT 1
"#;

const SNAPSHOT_BY_VERSION_SQL: &str = r#"
SELECT policy_id, org_id, policy_version, payload, issued_at, expires_at, created_at
FROM policy_snapshots
WHERE org_id = ?1 AND policy_version = ?2
LIMIT 1
"#;

const MAX_POLICY_VERSION_SQL: &str = r#"
SELECT COALESCE(MAX(policy_version), 0) AS max_version
FROM policy_snapshots
WHERE org_id = ?1
"#;

const INSERT_ACK_SQL: &str = r#"
INSERT INTO policy_acks (ack_id, org_id, device_id, policy_version, acked_at)
VALUES (?1, ?2, ?3, ?4, ?5)
"#;

const ACK_EXISTS_SQL: &str = r#"
SELECT 1 AS acked FROM policy_acks
WHERE device_id = ?1 AND policy_version = ?2
LIMIT 1
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySnapshotRecord {
    pub policy_id: String,
    pub org_id: String,
    pub policy_version: i64,
    pub payload: String,
    pub issued_at: String,
    pub expires_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAckRecord {
    pub ack_id: String,
    pub org_id: String,
    pub device_id: String,
    pub policy_version: i64,
    pub acked_at: String,
}

pub struct PolicyRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> PolicyRepository<'a> {
    pub fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    pub async fn next_policy_version(&self, org_id: &str) -> worker::Result<i64> {
        let statement = self
            .database
            .prepare(MAX_POLICY_VERSION_SQL, &[BindValue::Text(org_id)])?;
        let row = statement
            .first::<serde_json::Value>(None)
            .await?
            .ok_or_else(|| worker::Error::RustError("policy version probe missing".into()))?;
        Ok(row
            .get("max_version")
            .and_then(|value| value.as_i64())
            .unwrap_or_default()
            + 1)
    }

    pub fn insert_snapshot_statement(
        &self,
        policy_id: &str,
        org_id: &str,
        policy_version: i64,
        payload: &str,
        issued_at: &str,
        expires_at: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_SNAPSHOT_SQL,
            &[
                BindValue::Text(policy_id),
                BindValue::Text(org_id),
                BindValue::Int64(policy_version),
                BindValue::Text(payload),
                BindValue::Text(issued_at),
                BindValue::Text(expires_at),
            ],
        )
    }

    pub async fn find_snapshot(
        &self,
        policy_id: &str,
    ) -> worker::Result<Option<PolicySnapshotRecord>> {
        let statement = self
            .database
            .prepare(SNAPSHOT_BY_ID_SQL, &[BindValue::Text(policy_id)])?;
        statement.first::<PolicySnapshotRecord>(None).await
    }

    pub async fn latest_snapshot(
        &self,
        org_id: &str,
    ) -> worker::Result<Option<PolicySnapshotRecord>> {
        let statement = self
            .database
            .prepare(LATEST_SNAPSHOT_SQL, &[BindValue::Text(org_id)])?;
        statement.first::<PolicySnapshotRecord>(None).await
    }

    pub async fn find_snapshot_by_version(
        &self,
        org_id: &str,
        policy_version: i64,
    ) -> worker::Result<Option<PolicySnapshotRecord>> {
        let statement = self.database.prepare(
            SNAPSHOT_BY_VERSION_SQL,
            &[BindValue::Text(org_id), BindValue::Int64(policy_version)],
        )?;
        statement.first::<PolicySnapshotRecord>(None).await
    }

    /// Idempotent ack: repeated acks of the same version are a no-op.
    pub async fn ack_policy_version(
        &self,
        ack_id: &str,
        org_id: &str,
        device_id: &str,
        policy_version: i64,
        now: &Timestamp,
    ) -> worker::Result<bool> {
        let probe = self.database.prepare(
            ACK_EXISTS_SQL,
            &[BindValue::Text(device_id), BindValue::Int64(policy_version)],
        )?;
        if probe.first::<serde_json::Value>(None).await?.is_some() {
            return Ok(false);
        }
        let statement = self.database.prepare(
            INSERT_ACK_SQL,
            &[
                BindValue::Text(ack_id),
                BindValue::Text(org_id),
                BindValue::Text(device_id),
                BindValue::Int64(policy_version),
                BindValue::Text(now.as_str()),
            ],
        )?;
        statement.run().await?;
        Ok(true)
    }
}
