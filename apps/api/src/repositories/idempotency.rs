use std::fmt;

use serde::Deserialize;
use serde_json::Value;
use worker::d1::{D1PreparedStatement, D1Result};

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::{
        IdempotencyKeyDigest, IdempotencyRecord, IdempotencyScope, IdempotencyState,
        RequestFingerprint, StoredSuccess, Timestamp,
    },
};

const LOOKUP_ACTIVE_SQL: &str = r#"
SELECT request_fingerprint, state, response_status, response_body
FROM idempotency_records
WHERE principal_id = ?1
  AND organization_id = ?2
  AND method = ?3
  AND path = ?4
  AND key_digest = ?5
  AND expires_at > ?6
LIMIT 1
"#;

const CLAIM_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest,
    request_fingerprint, state, response_status, response_body,
    expires_at, claim_token
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', NULL, NULL, ?7, ?8)
ON CONFLICT (principal_id, organization_id, method, path, key_digest)
DO UPDATE SET
    request_fingerprint = excluded.request_fingerprint,
    state = 'pending',
    response_status = NULL,
    response_body = NULL,
    expires_at = excluded.expires_at,
    claim_token = excluded.claim_token
WHERE idempotency_records.expires_at <= ?9
"#;

const COMPLETION_SQL: &str = r#"
UPDATE idempotency_records
SET state = 'completed',
    response_status = ?1,
    response_body = ?2,
    claim_token = NULL
WHERE principal_id = ?3
  AND organization_id = ?4
  AND method = ?5
  AND path = ?6
  AND key_digest = ?7
  AND request_fingerprint = ?8
  AND state = 'pending'
  AND claim_token = ?9
"#;

const RELEASE_CLAIM_SQL: &str = r#"
DELETE FROM idempotency_records
WHERE principal_id = ?1
  AND organization_id = ?2
  AND method = ?3
  AND path = ?4
  AND key_digest = ?5
  AND state = 'pending'
  AND claim_token = ?6
"#;

// This statement is first in the completion batch. If the claim token no
// longer owns the scoped pending row, the conditional INSERT attempts a NULL
// principal_id and violates the existing table constraint. D1 rolls the full
// batch back, so no business mutation or outbox event can commit under a stale
// claim. With a live claim the SELECT produces no rows and inserts nothing.
const ASSERT_CLAIM_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest,
    request_fingerprint, state, response_status, response_body,
    expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', ''
WHERE NOT EXISTS (
    SELECT 1 FROM idempotency_records
    WHERE principal_id = ?1
      AND organization_id = ?2
      AND method = ?3
      AND path = ?4
      AND key_digest = ?5
      AND request_fingerprint = ?6
      AND state = 'pending'
      AND claim_token = ?7
)
"#;

const PURGE_EXPIRED_SQL: &str = r#"
DELETE FROM idempotency_records
WHERE rowid IN (
    SELECT rowid FROM idempotency_records
    WHERE expires_at <= ?1
    ORDER BY expires_at ASC
    LIMIT ?2
)
"#;

/// Temporary server-generated ownership value for an in-progress idempotency
/// claim. It is never derived from the client key and is redacted in debug
/// output.
#[derive(Clone, PartialEq, Eq)]
pub struct IdempotencyClaimToken(String);

impl IdempotencyClaimToken {
    /// Construct a bounded, printable token from a trusted server-generated
    /// value (for example, the request's freshly generated opaque ID).
    pub fn new(value: impl Into<String>) -> worker::Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 255
            || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(invalid_input());
        }
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for IdempotencyClaimToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdempotencyClaimToken([redacted])")
    }
}

/// Result of looking up a live idempotency scope.
#[derive(Clone, PartialEq)]
pub enum IdempotencyLookup {
    /// No unexpired row exists. A caller may try to claim the key.
    Missing,
    /// A matching live key is owned by an operation that has not completed.
    InProgress,
    /// A completed response can be replayed with a fresh request ID.
    Replay(StoredSuccess),
    /// A live key exists, but its request fingerprint differs.
    FingerprintConflict,
}

impl fmt::Debug for IdempotencyLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str("Missing"),
            Self::InProgress => f.write_str("InProgress"),
            Self::Replay(_) => f.write_str("Replay([redacted])"),
            Self::FingerprintConflict => f.write_str("FingerprintConflict"),
        }
    }
}

#[derive(Deserialize)]
struct IdempotencyRow {
    request_fingerprint: String,
    state: String,
    response_status: Option<u16>,
    response_body: Option<String>,
}

/// Repository for the frozen `idempotency_records` table.
pub struct IdempotencyRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> IdempotencyRepository<'a> {
    pub fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    /// Read only an unexpired row from the complete principal/org/endpoint/key
    /// scope and classify it against the current request fingerprint.
    pub async fn lookup(
        &self,
        scope: &IdempotencyScope,
        key_digest: &IdempotencyKeyDigest,
        request_fingerprint: &RequestFingerprint,
        now: &Timestamp,
    ) -> worker::Result<IdempotencyLookup> {
        validate_scope(scope)?;
        validate_digest(key_digest)?;
        validate_fingerprint(request_fingerprint)?;
        validate_storage_timestamp(now)?;

        let statement = self.database.prepare(
            LOOKUP_ACTIVE_SQL,
            &[
                BindValue::Text(scope.principal_id.as_str()),
                BindValue::Text(organization_scope(scope)),
                BindValue::Text(&scope.method),
                BindValue::Text(&scope.path),
                BindValue::Text(key_digest.as_str()),
                BindValue::Text(now.as_str()),
            ],
        )?;

        let Some(row) = statement.first::<IdempotencyRow>(None).await? else {
            return Ok(IdempotencyLookup::Missing);
        };

        if row.request_fingerprint.as_str() != request_fingerprint.as_str() {
            return Ok(IdempotencyLookup::FingerprintConflict);
        }

        match row.state.as_str() {
            "pending" if row.response_status.is_none() && row.response_body.is_none() => {
                Ok(IdempotencyLookup::InProgress)
            }
            "completed" => {
                let status = row.response_status.ok_or_else(invalid_stored_record)?;
                let body = row.response_body.ok_or_else(invalid_stored_record)?;
                let body: Value =
                    serde_json::from_str(&body).map_err(|_| invalid_stored_record())?;
                let success =
                    StoredSuccess::new(status, body).map_err(|_| invalid_stored_record())?;
                Ok(IdempotencyLookup::Replay(success))
            }
            _ => Err(invalid_stored_record()),
        }
    }

    /// Atomically insert a new pending claim or replace only the same scoped
    /// key after its previous record has expired. The caller checks the single
    /// affected-row count to distinguish acquired from still-owned claims.
    pub fn claim_statement(
        &self,
        record: &IdempotencyRecord,
        claim_token: &IdempotencyClaimToken,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        validate_pending_record(record, now)?;

        self.database.prepare(
            CLAIM_SQL,
            &[
                BindValue::Text(record.scope.principal_id.as_str()),
                BindValue::Text(organization_scope(&record.scope)),
                BindValue::Text(&record.scope.method),
                BindValue::Text(&record.scope.path),
                BindValue::Text(record.key_digest.as_str()),
                BindValue::Text(record.request_fingerprint.as_str()),
                BindValue::Text(record.expires_at.as_str()),
                BindValue::Text(claim_token.as_str()),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    /// Execute an atomic claim. `true` means this request acquired the claim;
    /// `false` means an unexpired request already owns the same scoped key.
    pub async fn claim(
        &self,
        record: &IdempotencyRecord,
        claim_token: &IdempotencyClaimToken,
        now: &Timestamp,
    ) -> worker::Result<bool> {
        let statement = self.claim_statement(record, claim_token, now)?;
        let result = statement.run().await?;
        Ok(D1Adapter::changes(&result)? == 1)
    }

    /// Best-effort release after the business/outbox transaction fails. The
    /// claim token prevents cleanup from deleting a newer owner's row.
    pub async fn release_pending_claim(
        &self,
        record: &IdempotencyRecord,
        claim_token: &IdempotencyClaimToken,
    ) -> worker::Result<bool> {
        validate_record_scope(record)?;
        validate_digest(&record.key_digest)?;
        let statement = self.database.prepare(
            RELEASE_CLAIM_SQL,
            &[
                BindValue::Text(record.scope.principal_id.as_str()),
                BindValue::Text(organization_scope(&record.scope)),
                BindValue::Text(&record.scope.method),
                BindValue::Text(&record.scope.path),
                BindValue::Text(record.key_digest.as_str()),
                BindValue::Text(claim_token.as_str()),
            ],
        )?;
        let result = statement.run().await?;
        Ok(D1Adapter::changes(&result)? == 1)
    }

    /// Build the successful-result update for inclusion in the same D1 batch
    /// as the business mutation and outbox insert.
    pub fn completion_statement(
        &self,
        record: &IdempotencyRecord,
        claim_token: &IdempotencyClaimToken,
        success: &StoredSuccess,
    ) -> worker::Result<D1PreparedStatement> {
        validate_record_scope(record)?;
        validate_digest(&record.key_digest)?;
        validate_fingerprint(&record.request_fingerprint)?;
        if !matches!(&record.state, IdempotencyState::Pending) {
            return Err(invalid_input());
        }
        let success = StoredSuccess::new(success.status, success.body.clone())
            .map_err(|_| invalid_input())?;
        let body = serde_json::to_string(&success.body).map_err(|_| invalid_input())?;

        self.database.prepare(
            COMPLETION_SQL,
            &[
                BindValue::Integer(i32::from(success.status)),
                BindValue::Text(&body),
                BindValue::Text(record.scope.principal_id.as_str()),
                BindValue::Text(organization_scope(&record.scope)),
                BindValue::Text(&record.scope.method),
                BindValue::Text(&record.scope.path),
                BindValue::Text(record.key_digest.as_str()),
                BindValue::Text(record.request_fingerprint.as_str()),
                BindValue::Text(claim_token.as_str()),
            ],
        )
    }

    /// Commit the idempotency claim, business writes, outbox event, and
    /// replayable success in one D1 batch. Claim and guard are first so a
    /// duplicate/stale claim aborts the transaction before application writes;
    /// a failed operation cannot leave an orphan pending claim.
    pub async fn commit_success(
        &self,
        record: &IdempotencyRecord,
        claim_token: &IdempotencyClaimToken,
        claim_statement: D1PreparedStatement,
        success: &StoredSuccess,
        business_writes: Vec<D1PreparedStatement>,
        outbox_insert: D1PreparedStatement,
    ) -> worker::Result<Vec<D1Result>> {
        let guard = self.claim_guard_statement(record, claim_token)?;
        let completion = self.completion_statement(record, claim_token, success)?;
        let mut statements = Vec::with_capacity(business_writes.len() + 4);
        statements.push(claim_statement);
        statements.push(guard);
        statements.extend(business_writes);
        statements.push(outbox_insert);
        statements.push(completion);
        self.database.batch(statements).await
    }

    /// Bounded cleanup for expired idempotency rows. Active rows are never
    /// selected; the expiry index keeps each cleanup invocation bounded.
    pub fn purge_expired_statement(
        &self,
        now: &Timestamp,
        limit: usize,
    ) -> worker::Result<D1PreparedStatement> {
        validate_storage_timestamp(now)?;
        if !(1..=500).contains(&limit) {
            return Err(invalid_input());
        }
        self.database.prepare(
            PURGE_EXPIRED_SQL,
            &[
                BindValue::Text(now.as_str()),
                BindValue::Integer(i32::try_from(limit).map_err(|_| invalid_input())?),
            ],
        )
    }

    fn claim_guard_statement(
        &self,
        record: &IdempotencyRecord,
        claim_token: &IdempotencyClaimToken,
    ) -> worker::Result<D1PreparedStatement> {
        validate_record_scope(record)?;
        validate_digest(&record.key_digest)?;
        validate_fingerprint(&record.request_fingerprint)?;
        if !matches!(&record.state, IdempotencyState::Pending) {
            return Err(invalid_input());
        }
        self.database.prepare(
            ASSERT_CLAIM_SQL,
            &[
                BindValue::Text(record.scope.principal_id.as_str()),
                BindValue::Text(organization_scope(&record.scope)),
                BindValue::Text(&record.scope.method),
                BindValue::Text(&record.scope.path),
                BindValue::Text(record.key_digest.as_str()),
                BindValue::Text(record.request_fingerprint.as_str()),
                BindValue::Text(claim_token.as_str()),
            ],
        )
    }
}

fn validate_pending_record(record: &IdempotencyRecord, now: &Timestamp) -> worker::Result<()> {
    validate_record_scope(record)?;
    validate_digest(&record.key_digest)?;
    validate_fingerprint(&record.request_fingerprint)?;
    validate_storage_timestamp(now)?;
    validate_storage_timestamp(&record.expires_at)?;
    if !matches!(&record.state, IdempotencyState::Pending)
        || record.expires_at.as_str() <= now.as_str()
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn validate_record_scope(record: &IdempotencyRecord) -> worker::Result<()> {
    validate_scope(&record.scope)
}

fn validate_scope(scope: &IdempotencyScope) -> worker::Result<()> {
    if !within_sqlite_text_limit(scope.principal_id.as_str(), 255)
        || scope
            .organization_id
            .as_ref()
            .is_some_and(|id| !within_sqlite_text_limit(id.as_str(), 255))
        || scope.method.is_empty()
        || scope.method.len() > 16
        || !scope
            .method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
        || scope.path.is_empty()
        || scope.path.chars().count() > 2048
        || !scope.path.starts_with('/')
        || scope.path.contains('?')
        || scope.path.contains('#')
        || scope.path.chars().any(char::is_control)
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn validate_digest(value: &IdempotencyKeyDigest) -> worker::Result<()> {
    validate_visible_text(value.as_str(), 128)
}

fn validate_fingerprint(value: &RequestFingerprint) -> worker::Result<()> {
    validate_visible_text(value.as_str(), 128)
}

fn validate_visible_text(value: &str, maximum_bytes: usize) -> worker::Result<()> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn within_sqlite_text_limit(value: &str, maximum_characters: usize) -> bool {
    !value.is_empty()
        && value.chars().count() <= maximum_characters
        && !value.chars().any(char::is_control)
}

fn validate_storage_timestamp(value: &Timestamp) -> worker::Result<()> {
    let bytes = value.as_str().as_bytes();
    let valid = bytes.len() == 24
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'.'
        && bytes[23] == b'Z'
        && [0..4, 5..7, 8..10, 11..13, 14..16, 17..19, 20..23]
            .iter()
            .all(|range| bytes[range.clone()].iter().all(u8::is_ascii_digit));
    if !valid {
        return Err(invalid_input());
    }
    Ok(())
}

fn organization_scope(scope: &IdempotencyScope) -> &str {
    scope
        .organization_id
        .as_ref()
        .map_or("", |organization_id| organization_id.as_str())
}

fn invalid_input() -> worker::Error {
    worker::Error::RustError("invalid value for D1 idempotency repository".to_owned())
}

fn invalid_stored_record() -> worker::Error {
    worker::Error::RustError("invalid idempotency record stored in D1".to_owned())
}
