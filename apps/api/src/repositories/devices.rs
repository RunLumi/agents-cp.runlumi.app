//! D1 persistence for P03 managed devices, enrollments, and device tokens.
//!
//! SQL is constant and fully bound (P01/P02 convention); invariant-bearing
//! writes run as D1 batches so state transitions stay atomic.

use serde::{Deserialize, Serialize};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::Timestamp,
};

const INSERT_ENROLLMENT_SQL: &str = r#"
INSERT INTO device_enrollments (
    enrollment_id, org_id, code_hash, public_key, key_fingerprint,
    device_name, platform, app_version, status, challenge, expires_at, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', ?9, ?10, ?11, ?11)
"#;

const ENROLLMENT_BY_ID_SQL: &str = r#"
SELECT enrollment_id, org_id, code_hash, public_key, key_fingerprint, device_name,
       platform, app_version, status, challenge, device_id, approved_by_user_id,
       expires_at, created_at, updated_at
FROM device_enrollments
WHERE enrollment_id = ?1
LIMIT 1
"#;

const EXPIRE_ENROLLMENT_SQL: &str = r#"
UPDATE device_enrollments
SET status = 'expired', updated_at = ?2
WHERE enrollment_id = ?1 AND status = 'pending'
"#;

const DENY_ENROLLMENT_SQL: &str = r#"
UPDATE device_enrollments
SET status = 'denied', updated_at = ?3
WHERE enrollment_id = ?1 AND org_id = ?2 AND status = 'pending'
"#;

const INSERT_DEVICE_SQL: &str = r#"
INSERT INTO devices (
    device_id, org_id, enrolled_by_user_id, name, platform, app_version,
    public_key, key_fingerprint, status, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9, ?9)
"#;

const COMPLETE_ENROLLMENT_SQL: &str = r#"
UPDATE device_enrollments
SET status = 'completed', challenge = NULL, device_id = ?2, approved_by_user_id = ?3, updated_at = ?4
WHERE enrollment_id = ?1 AND status = 'pending' AND expires_at > ?4
"#;

const INSERT_DEVICE_TOKEN_SQL: &str = r#"
INSERT INTO device_tokens (token_hash, device_id, expires_at, created_at)
VALUES (?1, ?2, ?3, ?4)
"#;

const DEVICE_BY_ID_SQL: &str = r#"
SELECT device_id, org_id, enrolled_by_user_id, name, platform, app_version,
       public_key, key_fingerprint, status, capabilities, capability_reported_at,
       last_seen_at, revoked_at, revoked_by_user_id, created_at, updated_at
FROM devices
WHERE device_id = ?1
LIMIT 1
"#;

const DEVICES_BY_ORG_SQL: &str = r#"
SELECT device_id, org_id, enrolled_by_user_id, name, platform, app_version,
       public_key, key_fingerprint, status, capabilities, capability_reported_at,
       last_seen_at, revoked_at, revoked_by_user_id, created_at, updated_at
FROM devices
WHERE org_id = ?1 AND (created_at, device_id) < (?2, ?3)
ORDER BY created_at DESC, device_id DESC
LIMIT ?4
"#;

const FIRST_DEVICES_PAGE_SQL: &str = r#"
SELECT device_id, org_id, enrolled_by_user_id, name, platform, app_version,
       public_key, key_fingerprint, status, capabilities, capability_reported_at,
       last_seen_at, revoked_at, revoked_by_user_id, created_at, updated_at
FROM devices
WHERE org_id = ?1
ORDER BY created_at DESC, device_id DESC
LIMIT ?2
"#;

const REVOKE_DEVICE_SQL: &str = r#"
UPDATE devices
SET status = 'revoked', revoked_at = ?2, revoked_by_user_id = ?3, updated_at = ?2
WHERE device_id = ?1 AND status = 'active'
"#;

const DELETE_DEVICE_TOKENS_SQL: &str = r#"
DELETE FROM device_tokens WHERE device_id = ?1
"#;

const DEVICE_TOKEN_BY_HASH_SQL: &str = r#"
SELECT token_hash, device_id, expires_at, created_at
FROM device_tokens
WHERE token_hash = ?1 AND device_id = ?2 AND expires_at > ?3
LIMIT 1
"#;

const UPDATE_DEVICE_HEARTBEAT_SQL: &str = r#"
UPDATE devices
SET last_seen_at = ?2, capabilities = ?3, capability_reported_at = ?4,
    app_version = ?5, updated_at = ?2
WHERE device_id = ?1 AND status = 'active'
"#;

const DEVICE_COUNT_BY_FINGERPRINT_SQL: &str = r#"
SELECT COUNT(*) AS n FROM devices WHERE org_id = ?1 AND key_fingerprint = ?2
"#;

/// Statement input for a new pending enrollment.
pub struct DeviceEnrollmentInput<'a> {
    pub enrollment_id: &'a str,
    pub org_id: &'a str,
    pub code_hash: &'a str,
    pub public_key: &'a str,
    pub key_fingerprint: &'a str,
    pub device_name: &'a str,
    pub platform: &'a str,
    pub app_version: &'a str,
    pub challenge: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub device_id: String,
    pub org_id: String,
    pub enrolled_by_user_id: String,
    pub name: String,
    pub platform: String,
    pub app_version: String,
    pub public_key: String,
    pub key_fingerprint: String,
    pub status: String,
    pub capabilities: Option<String>,
    pub capability_reported_at: Option<String>,
    pub last_seen_at: Option<String>,
    pub revoked_at: Option<String>,
    pub revoked_by_user_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEnrollmentRecord {
    pub enrollment_id: String,
    pub org_id: String,
    pub code_hash: String,
    pub public_key: String,
    pub key_fingerprint: String,
    pub device_name: String,
    pub platform: String,
    pub app_version: String,
    pub status: String,
    pub challenge: Option<String>,
    pub device_id: Option<String>,
    pub approved_by_user_id: Option<String>,
    pub expires_at: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTokenRecord {
    pub token_hash: String,
    pub device_id: String,
    pub expires_at: String,
    pub created_at: String,
}

pub struct DeviceRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> DeviceRepository<'a> {
    pub fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    pub fn insert_enrollment_statement(
        &self,
        enrollment: &DeviceEnrollmentInput<'_>,
        expires_at: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_ENROLLMENT_SQL,
            &[
                BindValue::Text(enrollment.enrollment_id),
                BindValue::Text(enrollment.org_id),
                BindValue::Text(enrollment.code_hash),
                BindValue::Text(enrollment.public_key),
                BindValue::Text(enrollment.key_fingerprint),
                BindValue::Text(enrollment.device_name),
                BindValue::Text(enrollment.platform),
                BindValue::Text(enrollment.app_version),
                BindValue::Text(enrollment.challenge),
                BindValue::Text(expires_at),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub async fn find_enrollment(
        &self,
        enrollment_id: &str,
    ) -> worker::Result<Option<DeviceEnrollmentRecord>> {
        let statement = self
            .database
            .prepare(ENROLLMENT_BY_ID_SQL, &[BindValue::Text(enrollment_id)])?;
        statement.first::<DeviceEnrollmentRecord>(None).await
    }

    pub async fn expire_enrollment(
        &self,
        enrollment_id: &str,
        now: &Timestamp,
    ) -> worker::Result<()> {
        let statement = self.database.prepare(
            EXPIRE_ENROLLMENT_SQL,
            &[
                BindValue::Text(enrollment_id),
                BindValue::Text(now.as_str()),
            ],
        )?;
        statement.run().await?;
        Ok(())
    }

    pub async fn deny_enrollment(
        &self,
        enrollment_id: &str,
        org_id: &str,
        now: &Timestamp,
    ) -> worker::Result<bool> {
        let statement = self.database.prepare(
            DENY_ENROLLMENT_SQL,
            &[
                BindValue::Text(enrollment_id),
                BindValue::Text(org_id),
                BindValue::Text(now.as_str()),
            ],
        )?;
        let result = statement.run().await?;
        Ok(D1Adapter::changes(&result)? > 0)
    }

    /// Atomically complete an approved enrollment: insert the managed device,
    /// close the enrollment, and store the first device token in one batch.
    pub async fn complete_enrollment(
        &self,
        enrollment: &DeviceEnrollmentRecord,
        device_id: &str,
        approved_by_user_id: &str,
        token_hash: &str,
        token_expires_at: &str,
        now: &Timestamp,
    ) -> worker::Result<Option<DeviceRecord>> {
        let now_text = now.as_str();
        let insert_device = self.database.prepare(
            INSERT_DEVICE_SQL,
            &[
                BindValue::Text(device_id),
                BindValue::Text(&enrollment.org_id),
                BindValue::Text(approved_by_user_id),
                BindValue::Text(&enrollment.device_name),
                BindValue::Text(&enrollment.platform),
                BindValue::Text(&enrollment.app_version),
                BindValue::Text(&enrollment.public_key),
                BindValue::Text(&enrollment.key_fingerprint),
                BindValue::Text(now_text),
            ],
        )?;
        let close_enrollment = self.database.prepare(
            COMPLETE_ENROLLMENT_SQL,
            &[
                BindValue::Text(&enrollment.enrollment_id),
                BindValue::Text(device_id),
                BindValue::Text(approved_by_user_id),
                BindValue::Text(now_text),
            ],
        )?;
        let insert_token = self.database.prepare(
            INSERT_DEVICE_TOKEN_SQL,
            &[
                BindValue::Text(token_hash),
                BindValue::Text(device_id),
                BindValue::Text(token_expires_at),
                BindValue::Text(now_text),
            ],
        )?;
        let results = self
            .database
            .batch(vec![insert_device, close_enrollment, insert_token])
            .await?;
        if !results.iter().all(|result| result.success()) {
            return Ok(None);
        }
        self.find_device(device_id).await
    }

    pub async fn find_device(&self, device_id: &str) -> worker::Result<Option<DeviceRecord>> {
        let statement = self
            .database
            .prepare(DEVICE_BY_ID_SQL, &[BindValue::Text(device_id)])?;
        statement.first::<DeviceRecord>(None).await
    }

    pub async fn device_fingerprint_count(
        &self,
        org_id: &str,
        key_fingerprint: &str,
    ) -> worker::Result<u32> {
        let statement = self.database.prepare(
            DEVICE_COUNT_BY_FINGERPRINT_SQL,
            &[BindValue::Text(org_id), BindValue::Text(key_fingerprint)],
        )?;
        let row = statement
            .first::<serde_json::Value>(None)
            .await?
            .ok_or_else(|| worker::Error::RustError("fingerprint count missing".into()))?;
        Ok(row
            .get("n")
            .and_then(|value| value.as_u64())
            .unwrap_or_default() as u32)
    }

    /// Keyset page ordered by `(created_at, device_id)` descending. `cursor`
    /// carries the encoded last-seen key of the previous page; `None` returns
    /// the first page.
    pub async fn list_devices_by_org(
        &self,
        org_id: &str,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<DeviceRecord>> {
        let statement = match cursor {
            Some((created_at, device_id)) => self.database.prepare(
                DEVICES_BY_ORG_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(created_at),
                    BindValue::Text(device_id),
                    BindValue::Integer(limit),
                ],
            )?,
            None => self.database.prepare(
                FIRST_DEVICES_PAGE_SQL,
                &[BindValue::Text(org_id), BindValue::Integer(limit)],
            )?,
        };
        statement.all().await?.results::<DeviceRecord>()
    }

    /// Revoke a device and invalidate every outstanding token atomically.
    /// Returns `false` when the device was already revoked or is missing.
    pub async fn revoke_device(
        &self,
        device_id: &str,
        revoked_by_user_id: &str,
        now: &Timestamp,
    ) -> worker::Result<bool> {
        let revoke = self.database.prepare(
            REVOKE_DEVICE_SQL,
            &[
                BindValue::Text(device_id),
                BindValue::Text(now.as_str()),
                BindValue::Text(revoked_by_user_id),
            ],
        )?;
        let drop_tokens = self
            .database
            .prepare(DELETE_DEVICE_TOKENS_SQL, &[BindValue::Text(device_id)])?;
        let results = self.database.batch(vec![revoke, drop_tokens]).await?;
        if !results.iter().all(|result| result.success()) {
            return Ok(false);
        }
        Ok(D1Adapter::changes(&results[0])? > 0)
    }

    pub async fn insert_device_token(
        &self,
        token_hash: &str,
        device_id: &str,
        expires_at: &str,
        now: &Timestamp,
    ) -> worker::Result<()> {
        let statement = self.database.prepare(
            INSERT_DEVICE_TOKEN_SQL,
            &[
                BindValue::Text(token_hash),
                BindValue::Text(device_id),
                BindValue::Text(expires_at),
                BindValue::Text(now.as_str()),
            ],
        )?;
        statement.run().await?;
        Ok(())
    }

    pub async fn find_live_device_token(
        &self,
        token_hash: &str,
        device_id: &str,
        now: &Timestamp,
    ) -> worker::Result<Option<DeviceTokenRecord>> {
        let statement = self.database.prepare(
            DEVICE_TOKEN_BY_HASH_SQL,
            &[
                BindValue::Text(token_hash),
                BindValue::Text(device_id),
                BindValue::Text(now.as_str()),
            ],
        )?;
        statement.first::<DeviceTokenRecord>(None).await
    }

    pub async fn update_heartbeat(
        &self,
        device_id: &str,
        now: &Timestamp,
        capabilities: Option<&str>,
        app_version: &str,
    ) -> worker::Result<bool> {
        let capability_value = capabilities.map(BindValue::Text).unwrap_or(BindValue::Null);
        let statement = self.database.prepare(
            UPDATE_DEVICE_HEARTBEAT_SQL,
            &[
                BindValue::Text(device_id),
                BindValue::Text(now.as_str()),
                capability_value,
                BindValue::Text(now.as_str()),
                BindValue::Text(app_version),
            ],
        )?;
        let result = statement.run().await?;
        Ok(D1Adapter::changes(&result)? > 0)
    }
}
