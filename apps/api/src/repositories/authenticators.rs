use serde::{Deserialize, Serialize};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::Timestamp,
    modules::authenticators::{CeremonyStatus, PasskeyCredential, WebAuthnCeremonyKind},
};

const INSERT_CEREMONY_SQL: &str = r#"
INSERT INTO webauthn_ceremonies (
    ceremony_id, kind, user_id, pending_user_id, email, display_name, session_id,
    state_json, status, attempts, expires_at, consumed_at, created_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', 0, ?9, NULL, ?10)
"#;

const CEREMONY_BY_ID_SQL: &str = r#"
SELECT ceremony_id, kind, user_id, pending_user_id, email, display_name, session_id,
       state_json, status, attempts, expires_at, consumed_at, created_at
FROM webauthn_ceremonies
WHERE ceremony_id = ?1
LIMIT 1
"#;

const CONSUME_CEREMONY_SQL: &str = r#"
UPDATE webauthn_ceremonies
SET status = 'consumed', consumed_at = ?2, attempts = attempts + 1
WHERE ceremony_id = ?1
  AND kind = ?3
  AND status = 'pending'
  AND attempts < 10
  AND expires_at > ?2
"#;

const FAILED_CEREMONY_SQL: &str = r#"
UPDATE webauthn_ceremonies
SET attempts = attempts + 1
WHERE ceremony_id = ?1 AND status = 'pending' AND attempts < 10
"#;

const INSERT_PASSKEY_SQL: &str = r#"
INSERT INTO passkey_credentials (
    passkey_id, user_id, credential_id, public_key_cose, sign_count,
    transports_json, backup_eligible, backup_state, label, created_at,
    last_used_at, revoked_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, NULL)
"#;

const PASSKEY_BY_CREDENTIAL_SQL: &str = r#"
SELECT passkey_id, user_id, credential_id, public_key_cose, sign_count,
       transports_json, backup_eligible, backup_state, label, created_at,
       last_used_at, revoked_at
FROM passkey_credentials
WHERE credential_id = ?1
LIMIT 1
"#;

const PASSKEY_BY_ID_SQL: &str = r#"
SELECT passkey_id, user_id, credential_id, public_key_cose, sign_count,
       transports_json, backup_eligible, backup_state, label, created_at,
       last_used_at, revoked_at
FROM passkey_credentials
WHERE passkey_id = ?1 AND user_id = ?2
LIMIT 1
"#;

const LIST_PASSKEYS_SQL: &str = r#"
SELECT passkey_id, user_id, credential_id, public_key_cose, sign_count,
       transports_json, backup_eligible, backup_state, label, created_at,
       last_used_at, revoked_at
FROM passkey_credentials
WHERE user_id = ?1 AND revoked_at IS NULL
ORDER BY created_at DESC, passkey_id DESC
LIMIT ?2
"#;

const ACTIVE_PASSKEY_COUNT_SQL: &str = r#"
SELECT COUNT(*) AS count FROM passkey_credentials
WHERE user_id = ?1 AND revoked_at IS NULL
"#;

const REVOKE_PASSKEY_SQL: &str = r#"
UPDATE passkey_credentials
SET revoked_at = ?3
WHERE passkey_id = ?1 AND user_id = ?2 AND revoked_at IS NULL
"#;

const UPDATE_PASSKEY_COUNTER_SQL: &str = r#"
UPDATE passkey_credentials
SET sign_count = ?3, last_used_at = ?4
WHERE credential_id = ?1 AND user_id = ?2 AND revoked_at IS NULL
"#;

const UPDATE_PASSKEY_LABEL_SQL: &str = r#"
UPDATE passkey_credentials
SET label = ?3
WHERE passkey_id = ?1 AND user_id = ?2 AND revoked_at IS NULL
"#;

const INSERT_PASSWORD_SQL: &str = r#"
INSERT INTO password_credentials (
    user_id, encoded_hash, algorithm, memory_kib, time_cost, parallelism,
    created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
"#;

const UPSERT_PASSWORD_SQL: &str = r#"
INSERT INTO password_credentials (
    user_id, encoded_hash, algorithm, memory_kib, time_cost, parallelism,
    created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
ON CONFLICT(user_id) DO UPDATE SET
    encoded_hash = excluded.encoded_hash,
    algorithm = excluded.algorithm,
    memory_kib = excluded.memory_kib,
    time_cost = excluded.time_cost,
    parallelism = excluded.parallelism,
    updated_at = excluded.updated_at
"#;

const PASSWORD_BY_USER_SQL: &str = r#"
SELECT user_id, encoded_hash, algorithm, memory_kib, time_cost, parallelism,
       created_at, updated_at
FROM password_credentials
WHERE user_id = ?1
LIMIT 1
"#;

const INSERT_RECOVERY_SQL: &str = r#"
INSERT INTO password_recovery_challenges (
    challenge_id, user_id, email, code_hash, status, attempts, expires_at,
    consumed_at, created_at
) VALUES (?1, ?2, ?3, ?4, 'pending', 0, ?5, NULL, ?6)
"#;

const RECOVERY_BY_ID_SQL: &str = r#"
SELECT challenge_id, user_id, email, code_hash, status, attempts, expires_at,
       consumed_at, created_at
FROM password_recovery_challenges
WHERE challenge_id = ?1
LIMIT 1
"#;

const CONSUME_RECOVERY_SQL: &str = r#"
UPDATE password_recovery_challenges
SET status = 'consumed', consumed_at = ?2, attempts = attempts + 1
WHERE challenge_id = ?1
  AND code_hash = ?3
  AND status = 'pending'
  AND attempts < 10
  AND expires_at > ?2
"#;

const FAILED_RECOVERY_SQL: &str = r#"
UPDATE password_recovery_challenges
SET attempts = attempts + 1
WHERE challenge_id = ?1 AND status = 'pending' AND attempts < 10
"#;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CeremonyRecord {
    pub ceremony_id: String,
    pub kind: String,
    pub user_id: Option<String>,
    pub pending_user_id: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub session_id: Option<String>,
    pub state_json: String,
    pub status: String,
    pub attempts: i64,
    pub expires_at: String,
    pub consumed_at: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize)]
struct CeremonyRow {
    ceremony_id: String,
    kind: String,
    user_id: Option<String>,
    pending_user_id: Option<String>,
    email: Option<String>,
    display_name: Option<String>,
    session_id: Option<String>,
    state_json: String,
    status: String,
    attempts: i64,
    expires_at: String,
    consumed_at: Option<String>,
    created_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PasskeyRecord {
    pub passkey_id: String,
    pub user_id: String,
    pub credential_id: String,
    pub public_key_cose: String,
    pub sign_count: i64,
    pub transports: Vec<String>,
    pub backup_eligible: Option<bool>,
    pub backup_state: Option<bool>,
    pub label: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct PasskeyRow {
    passkey_id: String,
    user_id: String,
    credential_id: String,
    public_key_cose: String,
    sign_count: i64,
    transports_json: String,
    backup_eligible: Option<i64>,
    backup_state: Option<i64>,
    label: String,
    created_at: String,
    last_used_at: Option<String>,
    revoked_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PasswordRecord {
    pub user_id: String,
    pub encoded_hash: String,
    pub algorithm: String,
    pub memory_kib: i64,
    pub time_cost: i64,
    pub parallelism: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize)]
struct PasswordRow {
    user_id: String,
    encoded_hash: String,
    algorithm: String,
    memory_kib: i64,
    time_cost: i64,
    parallelism: i64,
    created_at: String,
    updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecoveryRecord {
    pub challenge_id: String,
    pub user_id: Option<String>,
    pub email: String,
    pub code_hash: String,
    pub status: String,
    pub attempts: i64,
    pub expires_at: String,
    pub consumed_at: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize)]
struct RecoveryRow {
    challenge_id: String,
    user_id: Option<String>,
    email: String,
    code_hash: String,
    status: String,
    attempts: i64,
    expires_at: String,
    consumed_at: Option<String>,
    created_at: String,
}

#[derive(Deserialize)]
struct CountRow {
    count: i64,
}

pub struct AuthenticatorRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> AuthenticatorRepository<'a> {
    pub fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_ceremony_statement(
        &self,
        ceremony_id: &str,
        kind: WebAuthnCeremonyKind,
        user_id: Option<&str>,
        pending_user_id: Option<&str>,
        email: Option<&str>,
        display_name: Option<&str>,
        session_id: Option<&str>,
        state_json: &str,
        expires_at: &Timestamp,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_CEREMONY_SQL,
            &[
                BindValue::Text(ceremony_id),
                BindValue::Text(kind.as_str()),
                optional_text(user_id),
                optional_text(pending_user_id),
                optional_text(email),
                optional_text(display_name),
                optional_text(session_id),
                BindValue::Text(state_json),
                BindValue::Text(expires_at.as_str()),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub async fn find_ceremony(&self, ceremony_id: &str) -> worker::Result<Option<CeremonyRecord>> {
        self.database
            .prepare(CEREMONY_BY_ID_SQL, &[BindValue::Text(ceremony_id)])?
            .first::<CeremonyRow>(None)
            .await?
            .map(TryInto::try_into)
            .transpose()
    }

    pub async fn consume_ceremony(
        &self,
        ceremony_id: &str,
        kind: WebAuthnCeremonyKind,
        now: &Timestamp,
    ) -> worker::Result<bool> {
        let result = self
            .database
            .prepare(
                CONSUME_CEREMONY_SQL,
                &[
                    BindValue::Text(ceremony_id),
                    BindValue::Text(now.as_str()),
                    BindValue::Text(kind.as_str()),
                ],
            )?
            .run()
            .await?;
        Ok(D1Adapter::changes(&result)? == 1)
    }

    pub async fn record_failed_ceremony(&self, ceremony_id: &str) -> worker::Result<()> {
        self.database
            .prepare(FAILED_CEREMONY_SQL, &[BindValue::Text(ceremony_id)])?
            .run()
            .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_passkey_statement(
        &self,
        passkey_id: &str,
        user_id: &str,
        credential_id: &str,
        public_key_cose: &str,
        sign_count: i64,
        transports: &[String],
        backup_eligible: Option<bool>,
        backup_state: Option<bool>,
        label: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        let transports_json = serde_json::to_string(transports)
            .map_err(|_| worker::Error::RustError("invalid passkey transports".into()))?;
        self.database.prepare(
            INSERT_PASSKEY_SQL,
            &[
                BindValue::Text(passkey_id),
                BindValue::Text(user_id),
                BindValue::Text(credential_id),
                BindValue::Text(public_key_cose),
                BindValue::Integer(sign_count as i32),
                BindValue::Text(&transports_json),
                optional_bool(backup_eligible),
                optional_bool(backup_state),
                BindValue::Text(label),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub async fn find_passkey_by_credential(
        &self,
        credential_id: &str,
    ) -> worker::Result<Option<PasskeyRecord>> {
        self.database
            .prepare(PASSKEY_BY_CREDENTIAL_SQL, &[BindValue::Text(credential_id)])?
            .first::<PasskeyRow>(None)
            .await?
            .map(TryInto::try_into)
            .transpose()
    }

    pub async fn find_passkey(
        &self,
        user_id: &str,
        passkey_id: &str,
    ) -> worker::Result<Option<PasskeyRecord>> {
        self.database
            .prepare(
                PASSKEY_BY_ID_SQL,
                &[BindValue::Text(passkey_id), BindValue::Text(user_id)],
            )?
            .first::<PasskeyRow>(None)
            .await?
            .map(TryInto::try_into)
            .transpose()
    }

    pub async fn list_passkeys(&self, user_id: &str) -> worker::Result<Vec<PasskeyRecord>> {
        let result = self
            .database
            .prepare(
                LIST_PASSKEYS_SQL,
                &[BindValue::Text(user_id), BindValue::Integer(100)],
            )?
            .all()
            .await?;
        result
            .results::<PasskeyRow>()?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }

    pub async fn active_passkey_count(&self, user_id: &str) -> worker::Result<i64> {
        Ok(self
            .database
            .prepare(ACTIVE_PASSKEY_COUNT_SQL, &[BindValue::Text(user_id)])?
            .first::<CountRow>(None)
            .await?
            .map_or(0, |row| row.count))
    }

    pub async fn revoke_passkey(
        &self,
        user_id: &str,
        passkey_id: &str,
        now: &Timestamp,
    ) -> worker::Result<bool> {
        let result = self
            .database
            .prepare(
                REVOKE_PASSKEY_SQL,
                &[
                    BindValue::Text(passkey_id),
                    BindValue::Text(user_id),
                    BindValue::Text(now.as_str()),
                ],
            )?
            .run()
            .await?;
        Ok(D1Adapter::changes(&result)? == 1)
    }

    pub fn update_passkey_label_statement(
        &self,
        user_id: &str,
        passkey_id: &str,
        label: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_PASSKEY_LABEL_SQL,
            &[
                BindValue::Text(passkey_id),
                BindValue::Text(user_id),
                BindValue::Text(label),
            ],
        )
    }

    pub fn update_passkey_counter_statement(
        &self,
        user_id: &str,
        credential_id: &str,
        new_counter: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_PASSKEY_COUNTER_SQL,
            &[
                BindValue::Text(credential_id),
                BindValue::Text(user_id),
                BindValue::Integer(new_counter as i32),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_password_statement(
        &self,
        user_id: &str,
        encoded_hash: &str,
        algorithm: &str,
        memory_kib: i64,
        time_cost: i64,
        parallelism: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_PASSWORD_SQL,
            &[
                BindValue::Text(user_id),
                BindValue::Text(encoded_hash),
                BindValue::Text(algorithm),
                BindValue::Integer(memory_kib as i32),
                BindValue::Integer(time_cost as i32),
                BindValue::Integer(parallelism as i32),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_password_statement(
        &self,
        user_id: &str,
        encoded_hash: &str,
        algorithm: &str,
        memory_kib: i64,
        time_cost: i64,
        parallelism: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPSERT_PASSWORD_SQL,
            &[
                BindValue::Text(user_id),
                BindValue::Text(encoded_hash),
                BindValue::Text(algorithm),
                BindValue::Integer(memory_kib as i32),
                BindValue::Integer(time_cost as i32),
                BindValue::Integer(parallelism as i32),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub async fn find_password(&self, user_id: &str) -> worker::Result<Option<PasswordRecord>> {
        self.database
            .prepare(PASSWORD_BY_USER_SQL, &[BindValue::Text(user_id)])?
            .first::<PasswordRow>(None)
            .await?
            .map(TryInto::try_into)
            .transpose()
    }

    pub fn insert_recovery_statement(
        &self,
        challenge_id: &str,
        user_id: Option<&str>,
        email: &str,
        code_hash: &str,
        expires_at: &Timestamp,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_RECOVERY_SQL,
            &[
                BindValue::Text(challenge_id),
                optional_text(user_id),
                BindValue::Text(email),
                BindValue::Text(code_hash),
                BindValue::Text(expires_at.as_str()),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub async fn find_recovery(
        &self,
        challenge_id: &str,
    ) -> worker::Result<Option<RecoveryRecord>> {
        self.database
            .prepare(RECOVERY_BY_ID_SQL, &[BindValue::Text(challenge_id)])?
            .first::<RecoveryRow>(None)
            .await?
            .map(TryInto::try_into)
            .transpose()
    }

    pub async fn consume_recovery(
        &self,
        challenge_id: &str,
        code_hash: &str,
        now: &Timestamp,
    ) -> worker::Result<bool> {
        let result = self
            .database
            .prepare(
                CONSUME_RECOVERY_SQL,
                &[
                    BindValue::Text(challenge_id),
                    BindValue::Text(now.as_str()),
                    BindValue::Text(code_hash),
                ],
            )?
            .run()
            .await?;
        Ok(D1Adapter::changes(&result)? == 1)
    }

    pub async fn record_failed_recovery(&self, challenge_id: &str) -> worker::Result<()> {
        self.database
            .prepare(FAILED_RECOVERY_SQL, &[BindValue::Text(challenge_id)])?
            .run()
            .await?;
        Ok(())
    }
}

fn optional_text(value: Option<&str>) -> BindValue<'_> {
    value.map_or(BindValue::Null, BindValue::Text)
}

fn optional_bool(value: Option<bool>) -> BindValue<'static> {
    match value {
        Some(true) => BindValue::Integer(1),
        Some(false) => BindValue::Integer(0),
        None => BindValue::Null,
    }
}

impl TryFrom<CeremonyRow> for CeremonyRecord {
    type Error = worker::Error;

    fn try_from(row: CeremonyRow) -> Result<Self, Self::Error> {
        Ok(Self {
            ceremony_id: row.ceremony_id,
            kind: row.kind,
            user_id: row.user_id,
            pending_user_id: row.pending_user_id,
            email: row.email,
            display_name: row.display_name,
            session_id: row.session_id,
            state_json: row.state_json,
            status: row.status,
            attempts: row.attempts,
            expires_at: row.expires_at,
            consumed_at: row.consumed_at,
            created_at: row.created_at,
        })
    }
}

impl TryFrom<PasskeyRow> for PasskeyRecord {
    type Error = worker::Error;

    fn try_from(row: PasskeyRow) -> Result<Self, Self::Error> {
        let transports = serde_json::from_str::<Vec<String>>(&row.transports_json)
            .map_err(|_| worker::Error::RustError("invalid passkey transports".into()))?;
        Ok(Self {
            passkey_id: row.passkey_id,
            user_id: row.user_id,
            credential_id: row.credential_id,
            public_key_cose: row.public_key_cose,
            sign_count: row.sign_count,
            transports,
            backup_eligible: row.backup_eligible.map(|value| value == 1),
            backup_state: row.backup_state.map(|value| value == 1),
            label: row.label,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
            revoked_at: row.revoked_at,
        })
    }
}

impl TryFrom<PasswordRow> for PasswordRecord {
    type Error = worker::Error;

    fn try_from(row: PasswordRow) -> Result<Self, Self::Error> {
        Ok(Self {
            user_id: row.user_id,
            encoded_hash: row.encoded_hash,
            algorithm: row.algorithm,
            memory_kib: row.memory_kib,
            time_cost: row.time_cost,
            parallelism: row.parallelism,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

impl TryFrom<RecoveryRow> for RecoveryRecord {
    type Error = worker::Error;

    fn try_from(row: RecoveryRow) -> Result<Self, Self::Error> {
        Ok(Self {
            challenge_id: row.challenge_id,
            user_id: row.user_id,
            email: row.email,
            code_hash: row.code_hash,
            status: row.status,
            attempts: row.attempts,
            expires_at: row.expires_at,
            consumed_at: row.consumed_at,
            created_at: row.created_at,
        })
    }
}

impl From<PasskeyRecord> for PasskeyCredential {
    fn from(value: PasskeyRecord) -> Self {
        Self {
            passkey_id: value.passkey_id,
            user_id: value.user_id,
            credential_id: value.credential_id,
            public_key_cose: value.public_key_cose,
            sign_count: value.sign_count,
            transports: value.transports,
            backup_eligible: value.backup_eligible,
            backup_state: value.backup_state,
            label: value.label,
            created_at: value.created_at,
            last_used_at: value.last_used_at,
            revoked_at: value.revoked_at,
        }
    }
}

impl CeremonyStatus {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "consumed" => Some(Self::Consumed),
            "expired" => Some(Self::Expired),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}
