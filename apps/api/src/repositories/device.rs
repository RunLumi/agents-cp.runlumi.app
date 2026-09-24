use serde::{Deserialize, Serialize};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::Timestamp,
};

const INSERT_DEVICE_AUTHORIZATION_SQL: &str = r#"
INSERT INTO device_authorizations (
    device_authorization_id, user_code_hash, device_code_hash, code_challenge,
    code_challenge_method, device_label, status, expires_at, created_at
) VALUES (?1, ?2, ?3, ?4, 'S256', ?5, 'pending', ?6, ?7)
"#;

const DEVICE_BY_DEVICE_CODE_SQL: &str = r#"
SELECT device_authorization_id, user_code_hash, device_code_hash, code_challenge,
       code_challenge_method, device_label, status, user_id, session_id,
       expires_at, approved_at, consumed_at, created_at
FROM device_authorizations
WHERE device_code_hash = ?1
LIMIT 1
"#;

const APPROVE_DEVICE_SQL: &str = r#"
UPDATE device_authorizations
SET status = 'approved', user_id = ?2, approved_at = ?3
WHERE device_authorization_id = ?1 AND status = 'pending' AND expires_at > ?3
"#;

const CONSUME_DEVICE_SQL: &str = r#"
UPDATE device_authorizations
SET status = 'consumed', consumed_at = ?2
WHERE device_authorization_id = ?1
  AND status = 'approved'
  AND expires_at > ?2
  AND device_code_hash = ?3
"#;

#[derive(Clone, Deserialize, Serialize)]
pub struct DeviceAuthorizationRecord {
    pub device_authorization_id: String,
    pub user_code_hash: String,
    pub device_code_hash: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub device_label: String,
    pub status: String,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub expires_at: String,
    pub approved_at: Option<String>,
    pub consumed_at: Option<String>,
    pub created_at: String,
}

#[derive(Deserialize)]
struct DeviceRow {
    device_authorization_id: String,
    user_code_hash: String,
    device_code_hash: String,
    code_challenge: String,
    code_challenge_method: String,
    device_label: String,
    status: String,
    user_id: Option<String>,
    session_id: Option<String>,
    expires_at: String,
    approved_at: Option<String>,
    consumed_at: Option<String>,
    created_at: String,
}

pub struct DeviceAuthorizationRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> DeviceAuthorizationRepository<'a> {
    pub fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_statement(
        &self,
        id: &str,
        user_code_hash: &str,
        device_code_hash: &str,
        code_challenge: &str,
        device_label: &str,
        expires_at: &Timestamp,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_DEVICE_AUTHORIZATION_SQL,
            &[
                BindValue::Text(id),
                BindValue::Text(user_code_hash),
                BindValue::Text(device_code_hash),
                BindValue::Text(code_challenge),
                BindValue::Text(device_label),
                BindValue::Text(expires_at.as_str()),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub async fn find_by_device_code_hash(
        &self,
        device_code_hash: &str,
    ) -> worker::Result<Option<DeviceAuthorizationRecord>> {
        let row = self
            .database
            .prepare(
                DEVICE_BY_DEVICE_CODE_SQL,
                &[BindValue::Text(device_code_hash)],
            )?
            .first::<DeviceRow>(None)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    pub fn approve_statement(
        &self,
        id: &str,
        user_id: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            APPROVE_DEVICE_SQL,
            &[
                BindValue::Text(id),
                BindValue::Text(user_id),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub fn consume_statement(
        &self,
        id: &str,
        device_code_hash: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            CONSUME_DEVICE_SQL,
            &[
                BindValue::Text(id),
                BindValue::Text(now.as_str()),
                BindValue::Text(device_code_hash),
            ],
        )
    }
}

impl TryFrom<DeviceRow> for DeviceAuthorizationRecord {
    type Error = worker::Error;

    fn try_from(row: DeviceRow) -> Result<Self, Self::Error> {
        Ok(Self {
            device_authorization_id: row.device_authorization_id,
            user_code_hash: row.user_code_hash,
            device_code_hash: row.device_code_hash,
            code_challenge: row.code_challenge,
            code_challenge_method: row.code_challenge_method,
            device_label: row.device_label,
            status: row.status,
            user_id: row.user_id,
            session_id: row.session_id,
            expires_at: row.expires_at,
            approved_at: row.approved_at,
            consumed_at: row.consumed_at,
            created_at: row.created_at,
        })
    }
}
