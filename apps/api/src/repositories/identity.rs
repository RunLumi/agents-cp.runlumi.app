use serde::{Deserialize, Serialize};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::Timestamp,
};

const INSERT_USER_SQL: &str = r#"
INSERT INTO users (user_id, email, display_name, email_verified, version, created_at, updated_at)
VALUES (?1, ?2, ?3, 0, 1, ?4, ?4)
"#;

const INSERT_IDENTITY_SQL: &str = r#"
INSERT INTO identities (
    identity_id, user_id, provider, provider_subject, email, email_verified, created_at
) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)
"#;

const LINK_IDENTITY_SQL: &str = r#"
INSERT INTO identities (
    identity_id, user_id, provider, provider_subject, email, email_verified, created_at
) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)
"#;

const USER_BY_EMAIL_SQL: &str = r#"
SELECT user_id, email, display_name, email_verified, version, created_at, updated_at
FROM users
WHERE email = ?1
LIMIT 1
"#;

const USER_BY_ID_SQL: &str = r#"
SELECT user_id, email, display_name, email_verified, version, created_at, updated_at
FROM users
WHERE user_id = ?1
LIMIT 1
"#;

const IDENTITY_BY_USER_SQL: &str = r#"
SELECT identity_id, user_id, provider, provider_subject, email, email_verified
FROM identities
WHERE user_id = ?1
ORDER BY created_at ASC
LIMIT 1
"#;

const INSERT_CHALLENGE_SQL: &str = r#"
INSERT INTO auth_challenges (
    challenge_id, user_id, email, kind, code_hash, status, attempts, expires_at, created_at
) VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6, ?7)
"#;

const CHALLENGE_BY_ID_SQL: &str = r#"
SELECT challenge_id, user_id, email, kind, code_hash, status, attempts, expires_at, consumed_at, created_at
FROM auth_challenges
WHERE challenge_id = ?1
LIMIT 1
"#;

const CONSUME_CHALLENGE_SQL: &str = r#"
UPDATE auth_challenges
SET status = 'consumed', consumed_at = ?2, attempts = attempts + 1
WHERE challenge_id = ?1
  AND code_hash = ?3
  AND status = 'pending'
  AND attempts < 10
  AND expires_at > ?2
"#;

const RECORD_FAILED_CHALLENGE_SQL: &str = r#"
UPDATE auth_challenges
SET attempts = attempts + 1
WHERE challenge_id = ?1 AND status = 'pending' AND attempts < 10
"#;

const VERIFY_USER_SQL: &str = r#"
UPDATE users
SET email_verified = 1, version = version + 1, updated_at = ?2
WHERE user_id = ?1
"#;

const VERIFY_IDENTITY_SQL: &str = r#"
UPDATE identities
SET email_verified = 1
WHERE user_id = ?1 AND email = ?2
"#;

const INSERT_SESSION_SQL: &str = r#"
INSERT INTO login_sessions (
    session_id, user_id, token_hash, csrf_hash, device_label, platform,
    expires_at, last_seen_at, created_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
"#;

const SESSION_BY_TOKEN_SQL: &str = r#"
SELECT s.session_id, s.user_id, s.token_hash, s.csrf_hash, s.device_label,
       s.platform, s.expires_at, s.last_seen_at, s.revoked_at, s.revoked_reason,
       u.email, u.display_name, u.email_verified
FROM login_sessions s
JOIN users u ON u.user_id = s.user_id
WHERE s.token_hash = ?1
  AND s.revoked_at IS NULL
  AND s.expires_at > ?2
LIMIT 1
"#;

const TOUCH_SESSION_SQL: &str = r#"
UPDATE login_sessions
SET last_seen_at = ?2
WHERE session_id = ?1 AND revoked_at IS NULL AND expires_at > ?2
"#;

const REVOKE_SESSION_SQL: &str = r#"
UPDATE login_sessions
SET revoked_at = ?2, revoked_reason = ?3
WHERE session_id = ?1 AND revoked_at IS NULL
"#;

const LIST_SESSIONS_SQL: &str = r#"
SELECT session_id, device_label, platform, expires_at, last_seen_at, created_at
FROM login_sessions
WHERE user_id = ?1 AND revoked_at IS NULL AND expires_at > ?2
ORDER BY last_seen_at DESC, session_id DESC
LIMIT ?3 OFFSET ?4
"#;

const REVOKE_ALL_OTHER_SESSIONS_SQL: &str = r#"
UPDATE login_sessions
SET revoked_at = ?2, revoked_reason = ?3
WHERE user_id = ?1 AND session_id <> ?4 AND revoked_at IS NULL
"#;

const REVOKE_USER_SESSIONS_SQL: &str = r#"
UPDATE login_sessions
SET revoked_at = ?2, revoked_reason = 'membership_removed'
WHERE user_id = ?1 AND revoked_at IS NULL
"#;

const REVOKE_OWNED_SESSION_SQL: &str = r#"
UPDATE login_sessions
SET revoked_at = ?2, revoked_reason = ?3
WHERE session_id = ?1 AND user_id = ?4 AND revoked_at IS NULL
"#;

const UPSERT_AUTH_RATE_LIMIT_SQL: &str = r#"
INSERT INTO auth_rate_limits (bucket_key, attempts, window_started_at, expires_at)
VALUES (?1, 1, ?2, ?3)
ON CONFLICT (bucket_key) DO UPDATE SET
    attempts = CASE WHEN auth_rate_limits.expires_at <= ?2 THEN 1 ELSE auth_rate_limits.attempts + 1 END,
    window_started_at = CASE WHEN auth_rate_limits.expires_at <= ?2 THEN ?2 ELSE auth_rate_limits.window_started_at END,
    expires_at = CASE WHEN auth_rate_limits.expires_at <= ?2 THEN ?3 ELSE auth_rate_limits.expires_at END
"#;

const GET_AUTH_RATE_LIMIT_SQL: &str = r#"
SELECT attempts FROM auth_rate_limits WHERE bucket_key = ?1 LIMIT 1
"#;

const INSERT_REAUTH_SQL: &str = r#"
INSERT INTO reauthentication_grants (
    grant_id, user_id, session_id, purpose, token_hash, expires_at, created_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
"#;

const CONSUME_REAUTH_SQL: &str = r#"
UPDATE reauthentication_grants
SET consumed_at = ?6
WHERE grant_id = ?1
  AND user_id = ?2
  AND session_id = ?3
  AND purpose = ?4
  AND token_hash = ?5
  AND consumed_at IS NULL
  AND expires_at > ?6
"#;

#[derive(Clone, Deserialize, Serialize)]
pub struct UserRecord {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub email_verified: bool,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct IdentityRecord {
    pub identity_id: String,
    pub user_id: String,
    pub provider: String,
    pub provider_subject: String,
    pub email: String,
    pub email_verified: bool,
}

#[derive(Clone, Deserialize)]
pub struct ChallengeRecord {
    pub challenge_id: String,
    pub user_id: Option<String>,
    pub email: String,
    pub kind: String,
    pub code_hash: String,
    pub status: String,
    pub attempts: i64,
    pub expires_at: String,
    pub consumed_at: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub device_label: String,
    pub platform: String,
    pub expires_at: String,
    pub last_seen_at: String,
    pub created_at: String,
}

#[derive(Deserialize)]
struct RateLimitRow {
    attempts: i64,
}

#[derive(Deserialize)]
struct SessionSummaryRow {
    session_id: String,
    device_label: String,
    platform: String,
    expires_at: String,
    last_seen_at: String,
    created_at: String,
}

#[derive(Clone, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub user_id: String,
    pub token_hash: String,
    pub csrf_hash: String,
    pub device_label: String,
    pub platform: String,
    pub expires_at: String,
    pub last_seen_at: String,
    pub revoked_at: Option<String>,
    pub revoked_reason: Option<String>,
    pub email: String,
    pub display_name: String,
    pub email_verified: bool,
}

#[derive(Deserialize)]
struct UserRow {
    user_id: String,
    email: String,
    display_name: String,
    email_verified: i64,
    version: i64,
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize)]
struct IdentityRow {
    identity_id: String,
    user_id: String,
    provider: String,
    provider_subject: String,
    email: String,
    email_verified: i64,
}

#[derive(Deserialize)]
struct ChallengeRow {
    challenge_id: String,
    user_id: Option<String>,
    email: String,
    kind: String,
    code_hash: String,
    status: String,
    attempts: i64,
    expires_at: String,
    consumed_at: Option<String>,
    created_at: String,
}

#[derive(Deserialize)]
struct SessionRow {
    session_id: String,
    user_id: String,
    token_hash: String,
    csrf_hash: String,
    device_label: String,
    platform: String,
    expires_at: String,
    last_seen_at: String,
    revoked_at: Option<String>,
    revoked_reason: Option<String>,
    email: String,
    display_name: String,
    email_verified: i64,
}

pub struct IdentityRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> IdentityRepository<'a> {
    pub fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    pub fn insert_user_statement(
        &self,
        user_id: &str,
        email: &str,
        display_name: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_USER_SQL,
            &[
                BindValue::Text(user_id),
                BindValue::Text(email),
                BindValue::Text(display_name),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub fn insert_identity_statement(
        &self,
        identity_id: &str,
        user_id: &str,
        email: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_IDENTITY_SQL,
            &[
                BindValue::Text(identity_id),
                BindValue::Text(user_id),
                BindValue::Text("email"),
                BindValue::Text(email),
                BindValue::Text(email),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn link_identity_statement(
        &self,
        identity_id: &str,
        user_id: &str,
        provider: &str,
        provider_subject: &str,
        email: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            LINK_IDENTITY_SQL,
            &[
                BindValue::Text(identity_id),
                BindValue::Text(user_id),
                BindValue::Text(provider),
                BindValue::Text(provider_subject),
                BindValue::Text(email),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub async fn create_user(
        &self,
        user_id: &str,
        identity_id: &str,
        email: &str,
        display_name: &str,
        now: &Timestamp,
    ) -> worker::Result<UserRecord> {
        self.database
            .batch(vec![
                self.insert_user_statement(user_id, email, display_name, now)?,
                self.insert_identity_statement(identity_id, user_id, email, now)?,
            ])
            .await?;
        self.find_user_by_id(user_id)
            .await?
            .ok_or_else(|| worker::Error::RustError("created user could not be read".into()))
    }

    pub async fn allow_auth_attempt(
        &self,
        bucket_key: &str,
        now: &Timestamp,
        expires_at: &Timestamp,
        limit: i64,
    ) -> worker::Result<bool> {
        if bucket_key.is_empty() || bucket_key.len() > 128 || !(1..=100).contains(&limit) {
            return Err(worker::Error::RustError("invalid auth rate limit".into()));
        }
        self.database
            .prepare(
                UPSERT_AUTH_RATE_LIMIT_SQL,
                &[
                    BindValue::Text(bucket_key),
                    BindValue::Text(now.as_str()),
                    BindValue::Text(expires_at.as_str()),
                ],
            )?
            .run()
            .await?;
        let row = self
            .database
            .prepare(GET_AUTH_RATE_LIMIT_SQL, &[BindValue::Text(bucket_key)])?
            .first::<RateLimitRow>(None)
            .await?;
        Ok(row.is_some_and(|row| row.attempts <= limit))
    }

    pub async fn find_user_by_email(&self, email: &str) -> worker::Result<Option<UserRecord>> {
        let row = self
            .database
            .prepare(USER_BY_EMAIL_SQL, &[BindValue::Text(email)])?
            .first::<UserRow>(None)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    pub async fn find_user_by_id(&self, user_id: &str) -> worker::Result<Option<UserRecord>> {
        let row = self
            .database
            .prepare(USER_BY_ID_SQL, &[BindValue::Text(user_id)])?
            .first::<UserRow>(None)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    pub async fn find_identity_by_user(
        &self,
        user_id: &str,
    ) -> worker::Result<Option<IdentityRecord>> {
        let row = self
            .database
            .prepare(IDENTITY_BY_USER_SQL, &[BindValue::Text(user_id)])?
            .first::<IdentityRow>(None)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_challenge_statement(
        &self,
        challenge_id: &str,
        user_id: Option<&str>,
        email: &str,
        kind: &str,
        code_hash: &str,
        expires_at: &Timestamp,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        let user_id_value = user_id.map_or(BindValue::Null, BindValue::Text);
        self.database.prepare(
            INSERT_CHALLENGE_SQL,
            &[
                BindValue::Text(challenge_id),
                user_id_value,
                BindValue::Text(email),
                BindValue::Text(kind),
                BindValue::Text(code_hash),
                BindValue::Text(expires_at.as_str()),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub async fn find_challenge(
        &self,
        challenge_id: &str,
    ) -> worker::Result<Option<ChallengeRecord>> {
        let row = self
            .database
            .prepare(CHALLENGE_BY_ID_SQL, &[BindValue::Text(challenge_id)])?
            .first::<ChallengeRow>(None)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    pub async fn consume_challenge(
        &self,
        challenge_id: &str,
        code_hash: &str,
        now: &Timestamp,
    ) -> worker::Result<bool> {
        let result = self
            .database
            .prepare(
                CONSUME_CHALLENGE_SQL,
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

    pub async fn record_failed_challenge(&self, challenge_id: &str) -> worker::Result<()> {
        self.database
            .prepare(
                RECORD_FAILED_CHALLENGE_SQL,
                &[BindValue::Text(challenge_id)],
            )?
            .run()
            .await?;
        Ok(())
    }

    pub fn verify_user_statements(
        &self,
        user_id: &str,
        email: &str,
        now: &Timestamp,
    ) -> worker::Result<Vec<D1PreparedStatement>> {
        Ok(vec![
            self.database.prepare(
                VERIFY_USER_SQL,
                &[BindValue::Text(user_id), BindValue::Text(now.as_str())],
            )?,
            self.database.prepare(
                VERIFY_IDENTITY_SQL,
                &[BindValue::Text(user_id), BindValue::Text(email)],
            )?,
        ])
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_session_statement(
        &self,
        session_id: &str,
        user_id: &str,
        token_hash: &str,
        csrf_hash: &str,
        device_label: &str,
        platform: &str,
        expires_at: &Timestamp,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_SESSION_SQL,
            &[
                BindValue::Text(session_id),
                BindValue::Text(user_id),
                BindValue::Text(token_hash),
                BindValue::Text(csrf_hash),
                BindValue::Text(device_label),
                BindValue::Text(platform),
                BindValue::Text(expires_at.as_str()),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub async fn find_session_by_token_hash(
        &self,
        token_hash: &str,
        now: &Timestamp,
    ) -> worker::Result<Option<SessionRecord>> {
        let row = self
            .database
            .prepare(
                SESSION_BY_TOKEN_SQL,
                &[BindValue::Text(token_hash), BindValue::Text(now.as_str())],
            )?
            .first::<SessionRow>(None)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    pub async fn touch_session(&self, session_id: &str, now: &Timestamp) -> worker::Result<bool> {
        let result = self
            .database
            .prepare(
                TOUCH_SESSION_SQL,
                &[BindValue::Text(session_id), BindValue::Text(now.as_str())],
            )?
            .run()
            .await?;
        Ok(D1Adapter::changes(&result)? == 1)
    }

    pub async fn list_sessions(
        &self,
        user_id: &str,
        now: &Timestamp,
        limit: u16,
        offset: u32,
    ) -> worker::Result<Vec<SessionSummary>> {
        let result = self
            .database
            .prepare(
                LIST_SESSIONS_SQL,
                &[
                    BindValue::Text(user_id),
                    BindValue::Text(now.as_str()),
                    BindValue::Integer(i32::from(limit)),
                    BindValue::Integer(offset as i32),
                ],
            )?
            .all()
            .await?;
        result
            .results::<SessionSummaryRow>()?
            .into_iter()
            .map(|row| {
                Ok(SessionSummary {
                    session_id: row.session_id,
                    device_label: row.device_label,
                    platform: row.platform,
                    expires_at: row.expires_at,
                    last_seen_at: row.last_seen_at,
                    created_at: row.created_at,
                })
            })
            .collect()
    }

    pub fn revoke_all_other_sessions_statement(
        &self,
        user_id: &str,
        keep_session_id: &str,
        now: &Timestamp,
        reason: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            REVOKE_ALL_OTHER_SESSIONS_SQL,
            &[
                BindValue::Text(user_id),
                BindValue::Text(now.as_str()),
                BindValue::Text(reason),
                BindValue::Text(keep_session_id),
            ],
        )
    }

    pub async fn revoke_owned_session(
        &self,
        session_id: &str,
        user_id: &str,
        now: &Timestamp,
        reason: &str,
    ) -> worker::Result<bool> {
        let result = self
            .database
            .prepare(
                REVOKE_OWNED_SESSION_SQL,
                &[
                    BindValue::Text(session_id),
                    BindValue::Text(now.as_str()),
                    BindValue::Text(reason),
                    BindValue::Text(user_id),
                ],
            )?
            .run()
            .await?;
        Ok(D1Adapter::changes(&result)? == 1)
    }

    pub fn revoke_user_sessions_statement(
        &self,
        user_id: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            REVOKE_USER_SESSIONS_SQL,
            &[BindValue::Text(user_id), BindValue::Text(now.as_str())],
        )
    }

    pub fn revoke_session_statement(
        &self,
        session_id: &str,
        now: &Timestamp,
        reason: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            REVOKE_SESSION_SQL,
            &[
                BindValue::Text(session_id),
                BindValue::Text(now.as_str()),
                BindValue::Text(reason),
            ],
        )
    }

    pub async fn revoke_session(
        &self,
        session_id: &str,
        now: &Timestamp,
        reason: &str,
    ) -> worker::Result<bool> {
        let result = self
            .revoke_session_statement(session_id, now, reason)?
            .run()
            .await?;
        Ok(D1Adapter::changes(&result)? == 1)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_reauth_statement(
        &self,
        grant_id: &str,
        user_id: &str,
        session_id: &str,
        purpose: &str,
        token_hash: &str,
        expires_at: &Timestamp,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_REAUTH_SQL,
            &[
                BindValue::Text(grant_id),
                BindValue::Text(user_id),
                BindValue::Text(session_id),
                BindValue::Text(purpose),
                BindValue::Text(token_hash),
                BindValue::Text(expires_at.as_str()),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    pub async fn consume_reauth(
        &self,
        grant_id: &str,
        user_id: &str,
        session_id: &str,
        purpose: &str,
        token_hash: &str,
        now: &Timestamp,
    ) -> worker::Result<bool> {
        let result = self
            .database
            .prepare(
                CONSUME_REAUTH_SQL,
                &[
                    BindValue::Text(grant_id),
                    BindValue::Text(user_id),
                    BindValue::Text(session_id),
                    BindValue::Text(purpose),
                    BindValue::Text(token_hash),
                    BindValue::Text(now.as_str()),
                ],
            )?
            .run()
            .await?;
        Ok(D1Adapter::changes(&result)? == 1)
    }
}

impl TryFrom<UserRow> for UserRecord {
    type Error = worker::Error;

    fn try_from(row: UserRow) -> Result<Self, Self::Error> {
        Ok(Self {
            user_id: row.user_id,
            email: row.email,
            display_name: row.display_name,
            email_verified: row.email_verified == 1,
            version: row.version,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

impl TryFrom<IdentityRow> for IdentityRecord {
    type Error = worker::Error;

    fn try_from(row: IdentityRow) -> Result<Self, Self::Error> {
        Ok(Self {
            identity_id: row.identity_id,
            user_id: row.user_id,
            provider: row.provider,
            provider_subject: row.provider_subject,
            email: row.email,
            email_verified: row.email_verified == 1,
        })
    }
}

impl TryFrom<ChallengeRow> for ChallengeRecord {
    type Error = worker::Error;

    fn try_from(row: ChallengeRow) -> Result<Self, Self::Error> {
        Ok(Self {
            challenge_id: row.challenge_id,
            user_id: row.user_id,
            email: row.email,
            kind: row.kind,
            code_hash: row.code_hash,
            status: row.status,
            attempts: row.attempts,
            expires_at: row.expires_at,
            consumed_at: row.consumed_at,
            created_at: row.created_at,
        })
    }
}

impl TryFrom<SessionRow> for SessionRecord {
    type Error = worker::Error;

    fn try_from(row: SessionRow) -> Result<Self, Self::Error> {
        Ok(Self {
            session_id: row.session_id,
            user_id: row.user_id,
            token_hash: row.token_hash,
            csrf_hash: row.csrf_hash,
            device_label: row.device_label,
            platform: row.platform,
            expires_at: row.expires_at,
            last_seen_at: row.last_seen_at,
            revoked_at: row.revoked_at,
            revoked_reason: row.revoked_reason,
            email: row.email,
            display_name: row.display_name,
            email_verified: row.email_verified == 1,
        })
    }
}
