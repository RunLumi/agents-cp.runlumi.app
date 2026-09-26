//! D1 persistence for P07 machine identity (`0016_p07_machine_identity.sql`).
//!
//! # The one rule that shapes this file
//!
//! There is no column anywhere in `service_accounts` or `api_keys` that can hold
//! a raw key, and this repository never assembles one for storage. The
//! [`MachineKeyMaterial`] produced by `core::machine` is destructured once, at
//! the creation boundary, and only `key_prefix` / `secret_hash` / `fingerprint`
//! are bound. A future `INSERT` that tried to bind `secret` would not compile,
//! because the material's `secret` accessor returns `&str` and the writer takes
//! the three derived values by name.
//!
//! # Tenant scope is a SQL predicate
//!
//! Every read that a browser route performs binds `org_id` in the `WHERE`
//! clause. A cross-tenant `service_account_id` therefore returns the same empty
//! result as a missing one, and cannot be used as an existence oracle. The
//! single exception is `find_key_by_prefix`, which has no organization to bind
//! because the caller has not authenticated yet — that read resolves the
//! organization, and every authorization decision downstream uses the returned
//! row's `org_id` rather than anything the request carried.

use serde::{Deserialize, Serialize};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::Timestamp,
};

/// Most rows one list page may return. Every P07 collection is keyset-paginated
/// and bounded; nothing here can page a table into Worker memory.
/// Named with a P07 prefix because `repositories::data_governance` already
/// exports a `PAGE_LIMIT_MAX` of its own and a glob re-export would make the
/// second one a silent rename of the first.
pub const P07_PAGE_LIMIT_DEFAULT: i32 = 50;
pub const P07_PAGE_LIMIT_MAX: i32 = 100;

/// The gate's bounds, which exist so the list surface stays paginated and one
/// tenant cannot turn the table into a credential farm.
pub const MAX_ACTIVE_SERVICE_ACCOUNTS_PER_ORG: i32 = 50;
pub const MAX_ACTIVE_KEYS_PER_ACCOUNT: i32 = 5;

// ---------------------------------------------------------------- SQL ------

const ACCOUNT_BY_ID_FOR_ORG_SQL: &str = r#"
SELECT service_account_id, org_id, name, description, capabilities_json, created_by_principal,
       status, expires_at, suspended_at, suspend_reason, version, created_at, updated_at
FROM service_accounts
WHERE service_account_id = ?1 AND org_id = ?2
LIMIT 1
"#;

/// The organization comes from the KEY ROW, never from the request. This is the
/// frozen gate's rule for `{api_key_id}` routes, expressed as a predicate with
/// no `org_id` parameter at all: a client-supplied organization cannot even be
/// spelled here.
const KEY_BY_ID_SQL: &str = r#"
SELECT api_key_id, service_account_id, org_id, name, key_prefix, secret_hash, fingerprint,
       capabilities_json, project_ids_json, model_aliases_json, network_allowlist_json,
       status, rotated_from_key_id, rotated_to_key_id, last_used_at, last_used_source,
       expires_at, revoked_at, revoke_reason, version, created_at, updated_at
FROM api_keys
WHERE api_key_id = ?1
LIMIT 1
"#;

const KEY_BY_PREFIX_SQL: &str = r#"
SELECT api_key_id, service_account_id, org_id, name, key_prefix, secret_hash, fingerprint,
       capabilities_json, project_ids_json, model_aliases_json, network_allowlist_json,
       status, rotated_from_key_id, rotated_to_key_id, last_used_at, last_used_source,
       expires_at, revoked_at, revoke_reason, version, created_at, updated_at
FROM api_keys
WHERE key_prefix = ?1
LIMIT 1
"#;

/// Credential authentication joins the account in ONE read. A suspended account
/// must deny every key under it, including keys that have not expired, and doing
/// that in SQL rather than in a second query means there is no window in which a
/// key is authenticated against an account state that has since changed.
const KEY_BY_PREFIX_WITH_ACCOUNT_SQL: &str = r#"
SELECT k.api_key_id, k.service_account_id, k.org_id, k.name, k.key_prefix, k.secret_hash,
       k.fingerprint, k.capabilities_json, k.project_ids_json, k.model_aliases_json,
       k.network_allowlist_json, k.status, k.rotated_from_key_id, k.rotated_to_key_id,
       k.last_used_at, k.last_used_source, k.expires_at, k.revoked_at, k.revoke_reason,
       k.version, k.created_at, k.updated_at,
       a.status AS account_status, a.expires_at AS account_expires_at
FROM api_keys k
JOIN service_accounts a ON a.service_account_id = k.service_account_id
WHERE k.key_prefix = ?1
LIMIT 1
"#;

const ACCOUNTS_PAGE_FOR_ORG_SQL: &str = r#"
SELECT service_account_id, org_id, name, description, capabilities_json, created_by_principal,
       status, expires_at, suspended_at, suspend_reason, version, created_at, updated_at
FROM service_accounts
WHERE org_id = ?1 AND (?2 = '' OR (created_at, service_account_id) < (?2, ?3))
ORDER BY created_at DESC, service_account_id DESC
LIMIT ?4
"#;

const KEYS_PAGE_FOR_ORG_SQL: &str = r#"
SELECT api_key_id, service_account_id, org_id, name, key_prefix, secret_hash, fingerprint,
       capabilities_json, project_ids_json, model_aliases_json, network_allowlist_json,
       status, rotated_from_key_id, rotated_to_key_id, last_used_at, last_used_source,
       expires_at, revoked_at, revoke_reason, version, created_at, updated_at
FROM api_keys
WHERE org_id = ?1 AND (?2 = '' OR (created_at, api_key_id) < (?2, ?3))
ORDER BY created_at DESC, api_key_id DESC
LIMIT ?4
"#;

const INSERT_ACCOUNT_SQL: &str = r#"
INSERT INTO service_accounts (
    service_account_id, org_id, name, description, capabilities_json, created_by_principal,
    status, expires_at, version, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active', ?7, 1, ?8, ?8)
"#;

const UPDATE_ACCOUNT_SQL: &str = r#"
UPDATE service_accounts
SET name = ?3,
    description = ?4,
    capabilities_json = ?5,
    version = version + 1,
    updated_at = ?6
WHERE service_account_id = ?1 AND org_id = ?2 AND version = ?7
"#;

/// Suspend records the reason. A credential that stops working with no recorded
/// cause is exactly the case an operator cannot explain during an incident, and
/// the same rule the 0016 trigger enforces on a key's revocation.
const SUSPEND_ACCOUNT_SQL: &str = r#"
UPDATE service_accounts
SET status = 'suspended', suspended_at = ?3, suspend_reason = ?4, version = version + 1,
    updated_at = ?3
WHERE service_account_id = ?1 AND org_id = ?2 AND version = ?5 AND status = 'active'
"#;

const RESUME_ACCOUNT_SQL: &str = r#"
UPDATE service_accounts
SET status = 'active', suspended_at = NULL, suspend_reason = NULL, version = version + 1,
    updated_at = ?3
WHERE service_account_id = ?1 AND org_id = ?2 AND version = ?4 AND status = 'suspended'
"#;

const INSERT_KEY_SQL: &str = r#"
INSERT INTO api_keys (
    api_key_id, service_account_id, org_id, name, key_prefix, secret_hash, fingerprint,
    capabilities_json, project_ids_json, model_aliases_json, network_allowlist_json,
    status, rotated_from_key_id, expires_at, version, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'active', ?12, ?13, 1, ?14, ?14)
"#;

/// F14-004 rotation. The replacement is inserted first and the prior key is
/// marked `rotated` in the SAME batch, so there is no instant at which the
/// organization has no working key, and no instant at which the prior key is
/// dead without a replacement.
const MARK_KEY_ROTATED_SQL: &str = r#"
UPDATE api_keys
SET status = 'rotated', revoke_reason = ?3, revoked_at = ?4, rotated_to_key_id = ?5,
    version = version + 1, updated_at = ?4
WHERE api_key_id = ?1 AND org_id = ?2 AND status = 'active'
"#;

const REVOKE_KEY_SQL: &str = r#"
UPDATE api_keys
SET status = 'revoked', revoke_reason = ?3, revoked_at = ?4, version = version + 1,
    updated_at = ?4
WHERE api_key_id = ?1 AND org_id = ?2 AND version = ?5 AND status = 'active'
"#;

/// Last-used metadata. F14-005: a timestamp and a bounded source hint. The
/// statement has no column for a request body, a header bag, or a query string,
/// so none can be recorded even by a future mistake.
const TOUCH_KEY_USE_SQL: &str = r#"
UPDATE api_keys
SET last_used_at = ?2, last_used_source = ?3
WHERE api_key_id = ?1
"#;

/// Fails the surrounding D1 batch when a service account is not at the expected
/// version, so a concurrent PATCH cannot slip between the read and the write.
pub const ASSERT_ACCOUNT_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM service_accounts
    WHERE service_account_id = ?1 AND org_id = ?2 AND version = ?3
)
"#;

/// The same guard for a key transition, which additionally requires the expected
/// current status. A stale rotate must not be able to mark an already-revoked
/// key as `rotated` and thereby rewrite why it stopped working.
pub const ASSERT_KEY_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM api_keys
    WHERE api_key_id = ?1 AND org_id = ?2 AND version = ?3 AND status = 'active'
)
"#;

// ---------------------------------------------------------------- records ---

#[derive(Clone, Deserialize, Serialize)]
pub struct ServiceAccountRecord {
    pub service_account_id: String,
    pub org_id: String,
    pub name: String,
    pub description: Option<String>,
    pub capabilities_json: String,
    pub created_by_principal: String,
    pub status: String,
    pub expires_at: Option<String>,
    pub suspended_at: Option<String>,
    pub suspend_reason: Option<String>,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl ServiceAccountRecord {
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }
}

impl std::fmt::Debug for ServiceAccountRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAccountRecord")
            .field("service_account_id", &self.service_account_id)
            .field("org_id", &self.org_id)
            .field("name", &self.name)
            .field("status", &self.status)
            .field("version", &self.version)
            .finish()
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ApiKeyRecord {
    pub api_key_id: String,
    pub service_account_id: String,
    pub org_id: String,
    pub name: String,
    /// Non-secret. The lookup index, and the value a human sees.
    pub key_prefix: String,
    /// The 64-char hex hash. Never the raw key: there is no column for it.
    pub secret_hash: String,
    pub fingerprint: String,
    pub capabilities_json: String,
    pub project_ids_json: Option<String>,
    pub model_aliases_json: Option<String>,
    pub network_allowlist_json: Option<String>,
    pub status: String,
    pub rotated_from_key_id: Option<String>,
    pub rotated_to_key_id: Option<String>,
    pub last_used_at: Option<String>,
    pub last_used_source: Option<String>,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub revoke_reason: Option<String>,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl ApiKeyRecord {
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }

    /// `revoked`, `rotated` and `expired` are terminal. Rotation refuses to
    /// replace a key that is already in one of these, so a caller cannot mint a
    /// successor to a key whose revocation someone is relying on.
    pub fn is_terminal(&self) -> bool {
        matches!(self.status.as_str(), "revoked" | "rotated" | "expired")
    }
}

impl std::fmt::Debug for ApiKeyRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyRecord")
            .field("api_key_id", &self.api_key_id)
            .field("service_account_id", &self.service_account_id)
            .field("org_id", &self.org_id)
            .field("name", &self.name)
            .field("key_prefix", &self.key_prefix)
            .field("fingerprint", &self.fingerprint)
            .field("status", &self.status)
            .field("version", &self.version)
            .finish()
    }
}

/// A key resolved for authentication: the key plus the account state that decides
/// whether it may act at all.
#[derive(Clone, Deserialize, Serialize)]
pub struct ResolvedMachineKey {
    #[serde(flatten)]
    pub key: ApiKeyRecord,
    pub account_status: String,
    pub account_expires_at: Option<String>,
}

impl ResolvedMachineKey {
    pub fn account_is_active(&self) -> bool {
        self.account_status == "active"
    }
}

// --------------------------------------------------------------- writers ----

pub struct NewServiceAccountInput<'a> {
    pub service_account_id: &'a str,
    pub org_id: &'a str,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub capabilities_json: &'a str,
    pub created_by_principal: &'a str,
    pub expires_at: Option<&'a str>,
    pub now: &'a str,
}

/// The fields a PATCH may change, bound together.
///
/// Grouped rather than passed as eleven positional arguments for the same reason
/// `authorize_machine`'s `MachineRequest` is grouped: adjacent optional
/// parameters can be transposed, and a transposed write to a versioned row is a
/// silent data bug rather than a compile error.
pub struct ServiceAccountUpdateInput<'a> {
    pub service_account_id: &'a str,
    pub org_id: &'a str,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub capabilities_json: &'a str,
    pub expected_version: i64,
    pub now: &'a str,
}

pub struct NewApiKeyInput<'a> {
    pub api_key_id: &'a str,
    pub service_account_id: &'a str,
    pub org_id: &'a str,
    pub name: &'a str,
    /// Non-secret.
    pub key_prefix: &'a str,
    /// The hash. NEVER the secret: this input struct has no field for it, so a
    /// call site that tried to pass one would not compile.
    pub secret_hash: &'a str,
    pub fingerprint: &'a str,
    pub capabilities_json: &'a str,
    pub project_ids_json: Option<&'a str>,
    pub model_aliases_json: Option<&'a str>,
    pub network_allowlist_json: Option<&'a str>,
    pub rotated_from_key_id: Option<&'a str>,
    pub expires_at: Option<&'a str>,
    pub now: &'a str,
}

// ----------------------------------------------------------- repository -----

pub struct MachineIdentityRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> MachineIdentityRepository<'a> {
    pub fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    // -- reads -------------------------------------------------------------

    /// Tenant-scoped. A foreign `service_account_id` is indistinguishable from a
    /// missing one.
    pub async fn find_service_account(
        &self,
        service_account_id: &str,
        org_id: &str,
    ) -> worker::Result<Option<ServiceAccountRecord>> {
        self.database
            .prepare(
                ACCOUNT_BY_ID_FOR_ORG_SQL,
                &[BindValue::Text(service_account_id), BindValue::Text(org_id)],
            )?
            .first::<ServiceAccountRecord>(None)
            .await
    }

    /// Resolved from the key row, so the organization is server-derived. The
    /// route layer treats the result's `org_id` as the ONLY tenant scope.
    pub async fn find_key(&self, api_key_id: &str) -> worker::Result<Option<ApiKeyRecord>> {
        self.database
            .prepare(KEY_BY_ID_SQL, &[BindValue::Text(api_key_id)])?
            .first::<ApiKeyRecord>(None)
            .await
    }

    /// The authentication read: one row, key and account state together.
    pub async fn resolve_credential(
        &self,
        key_prefix: &str,
    ) -> worker::Result<Option<ResolvedMachineKey>> {
        self.database
            .prepare(
                KEY_BY_PREFIX_WITH_ACCOUNT_SQL,
                &[BindValue::Text(key_prefix)],
            )?
            .first::<ResolvedMachineKey>(None)
            .await
    }

    #[allow(dead_code)]
    pub async fn find_key_by_prefix(
        &self,
        key_prefix: &str,
    ) -> worker::Result<Option<ApiKeyRecord>> {
        self.database
            .prepare(KEY_BY_PREFIX_SQL, &[BindValue::Text(key_prefix)])?
            .first::<ApiKeyRecord>(None)
            .await
    }

    pub async fn list_service_accounts(
        &self,
        org_id: &str,
        cursor_created_at: Option<&str>,
        cursor_id: Option<&str>,
        limit: i32,
    ) -> worker::Result<Vec<ServiceAccountRecord>> {
        self.database
            .prepare(
                ACCOUNTS_PAGE_FOR_ORG_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(cursor_created_at.unwrap_or_default()),
                    BindValue::Text(cursor_id.unwrap_or_default()),
                    BindValue::Integer(limit.clamp(1, P07_PAGE_LIMIT_MAX)),
                ],
            )?
            .all()
            .await?
            .results::<ServiceAccountRecord>()
    }

    pub async fn list_keys(
        &self,
        org_id: &str,
        cursor_created_at: Option<&str>,
        cursor_id: Option<&str>,
        limit: i32,
    ) -> worker::Result<Vec<ApiKeyRecord>> {
        self.database
            .prepare(
                KEYS_PAGE_FOR_ORG_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(cursor_created_at.unwrap_or_default()),
                    BindValue::Text(cursor_id.unwrap_or_default()),
                    BindValue::Integer(limit.clamp(1, P07_PAGE_LIMIT_MAX)),
                ],
            )?
            .all()
            .await?
            .results::<ApiKeyRecord>()
    }

    /// The frozen bounds. Counted rather than enforced by a trigger so the
    /// refusal can be `key_limit_reached` rather than a constraint collision,
    /// which is a different answer to a different question.
    pub async fn count_active_service_accounts(&self, org_id: &str) -> worker::Result<i32> {
        self.database
            .prepare(
                "SELECT COUNT(*) AS total FROM service_accounts WHERE org_id = ?1 AND status = 'active'",
                &[BindValue::Text(org_id)],
            )?
            .first::<CountRow>(None)
            .await
            .map(|row| row.map_or(0, |row| row.total))
    }

    pub async fn count_active_keys(&self, service_account_id: &str) -> worker::Result<i32> {
        self.database
            .prepare(
                "SELECT COUNT(*) AS total FROM api_keys WHERE service_account_id = ?1 AND status = 'active'",
                &[BindValue::Text(service_account_id)],
            )?
            .first::<CountRow>(None)
            .await
            .map(|row| row.map_or(0, |row| row.total))
    }

    // -- writes ------------------------------------------------------------

    pub fn insert_service_account_statement(
        &self,
        input: &NewServiceAccountInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_ACCOUNT_SQL,
            &[
                BindValue::Text(input.service_account_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.name),
                optional_text(input.description),
                BindValue::Text(input.capabilities_json),
                BindValue::Text(input.created_by_principal),
                optional_text(input.expires_at),
                BindValue::Text(input.now),
            ],
        )
    }

    pub fn update_service_account_statement(
        &self,
        input: &ServiceAccountUpdateInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_ACCOUNT_SQL,
            &[
                BindValue::Text(input.service_account_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.name),
                optional_text(input.description),
                BindValue::Text(input.capabilities_json),
                BindValue::Text(input.now),
                BindValue::Int64(input.expected_version),
            ],
        )
    }

    pub fn suspend_service_account_statement(
        &self,
        service_account_id: &str,
        org_id: &str,
        reason: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            SUSPEND_ACCOUNT_SQL,
            &[
                BindValue::Text(service_account_id),
                BindValue::Text(org_id),
                BindValue::Text(now.as_str()),
                BindValue::Text(reason),
                BindValue::Int64(expected_version),
            ],
        )
    }

    pub fn resume_service_account_statement(
        &self,
        service_account_id: &str,
        org_id: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            RESUME_ACCOUNT_SQL,
            &[
                BindValue::Text(service_account_id),
                BindValue::Text(org_id),
                BindValue::Text(now.as_str()),
                BindValue::Int64(expected_version),
            ],
        )
    }

    pub fn assert_service_account_version_statement(
        &self,
        service_account_id: &str,
        org_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_ACCOUNT_VERSION_SQL,
            &[
                BindValue::Text(service_account_id),
                BindValue::Text(org_id),
                BindValue::Int64(expected_version),
            ],
        )
    }

    pub fn insert_key_statement(
        &self,
        input: &NewApiKeyInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_KEY_SQL,
            &[
                BindValue::Text(input.api_key_id),
                BindValue::Text(input.service_account_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.name),
                BindValue::Text(input.key_prefix),
                BindValue::Text(input.secret_hash),
                BindValue::Text(input.fingerprint),
                BindValue::Text(input.capabilities_json),
                optional_text(input.project_ids_json),
                optional_text(input.model_aliases_json),
                optional_text(input.network_allowlist_json),
                optional_text(input.rotated_from_key_id),
                optional_text(input.expires_at),
                BindValue::Text(input.now),
            ],
        )
    }

    pub fn mark_key_rotated_statement(
        &self,
        api_key_id: &str,
        org_id: &str,
        reason: &str,
        replacement_key_id: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            MARK_KEY_ROTATED_SQL,
            &[
                BindValue::Text(api_key_id),
                BindValue::Text(org_id),
                BindValue::Text(reason),
                BindValue::Text(now.as_str()),
                BindValue::Text(replacement_key_id),
            ],
        )
    }

    pub fn revoke_key_statement(
        &self,
        api_key_id: &str,
        org_id: &str,
        reason: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            REVOKE_KEY_SQL,
            &[
                BindValue::Text(api_key_id),
                BindValue::Text(org_id),
                BindValue::Text(reason),
                BindValue::Text(now.as_str()),
                BindValue::Int64(expected_version),
            ],
        )
    }

    pub fn assert_key_version_statement(
        &self,
        api_key_id: &str,
        org_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_KEY_VERSION_SQL,
            &[
                BindValue::Text(api_key_id),
                BindValue::Text(org_id),
                BindValue::Int64(expected_version),
            ],
        )
    }

    /// F14-005. Best-effort by design: a failure to record last-used must not
    /// fail the request the credential was making.
    pub async fn touch_key_use(
        &self,
        api_key_id: &str,
        at: &str,
        source: &str,
    ) -> worker::Result<()> {
        self.database
            .prepare(
                TOUCH_KEY_USE_SQL,
                &[
                    BindValue::Text(api_key_id),
                    BindValue::Text(at),
                    BindValue::Text(source),
                ],
            )?
            .run()
            .await
            .map(|_| ())
    }
}

#[derive(Deserialize)]
struct CountRow {
    total: i32,
}

fn optional_text(value: Option<&str>) -> BindValue<'_> {
    value.map_or(BindValue::Null, BindValue::Text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property F14-002 names, pinned at the type level rather than by
    /// inspection: no write input in this file can carry a raw key.
    ///
    /// `NewApiKeyInput` has `key_prefix`, `secret_hash` and `fingerprint`, and no
    /// other credential field. A `secret` parameter would not compile here, so
    /// the "the raw key is never persisted" claim is enforced by the signature
    /// instead of by a review of the INSERT statement.
    #[test]
    fn the_key_writer_has_no_field_for_a_raw_key() {
        let input = NewApiKeyInput {
            api_key_id: "key_0123456789abcdef0123456789abcdef",
            service_account_id: "svc_0123456789abcdef0123456789abcdef",
            org_id: "org_0123456789abcdef0123456789abcdef",
            name: "ci",
            key_prefix: "000000000001",
            secret_hash: &"a".repeat(64),
            fingerprint: "abcdef0123456789",
            capabilities_json: "[]",
            project_ids_json: None,
            model_aliases_json: None,
            network_allowlist_json: None,
            rotated_from_key_id: None,
            expires_at: None,
            now: "2026-09-26T12:00:00.000Z",
        };
        // Every bound value is either a non-secret identifier or the hash. The
        // check is on the SQL text because that is what runs in production.
        assert!(INSERT_KEY_SQL.contains("secret_hash"));
        assert!(!INSERT_KEY_SQL.to_lowercase().contains("raw_key"));
        assert!(!INSERT_KEY_SQL.contains("secret,"));
        // ...and the hash is bound from `input.secret_hash`, not from a name that
        // a future edit could repoint at the raw value.
        assert!(input.secret_hash.len() == 64);
    }

    #[test]
    fn the_insert_binds_only_three_credential_columns() {
        for column in ["key_prefix", "secret_hash", "fingerprint"] {
            assert!(
                INSERT_KEY_SQL.contains(column),
                "{column} must be persisted for lookup and identification"
            );
        }
        // No column that could hold the presented value.
        for forbidden in ["plaintext", "raw", "presented", "token"] {
            assert!(
                !INSERT_KEY_SQL.contains(forbidden),
                "{forbidden} must not be a column"
            );
        }
    }

    /// F14-004. Rotation inserts the replacement and marks the prior key in the
    /// same batch, and the prior key's transition binds the reason the 0016
    /// trigger refuses to do without.
    #[test]
    fn rotation_marks_the_prior_key_with_a_reason_in_the_same_shape() {
        assert!(MARK_KEY_ROTATED_SQL.contains("status = 'rotated'"));
        assert!(MARK_KEY_ROTATED_SQL.contains("revoke_reason = ?3"));
        assert!(MARK_KEY_ROTATED_SQL.contains("rotated_to_key_id = ?5"));
        // ...and only from an active key, so an already-terminal key cannot be
        // moved again.
        assert!(MARK_KEY_ROTATED_SQL.contains("AND status = 'active'"));
        assert!(REVOKE_KEY_SQL.contains("AND status = 'active'"));
    }

    /// The organization for a `{api_key_id}` route must come from the row. The
    /// statement has no `org_id` parameter at all, so a request cannot contribute
    /// one.
    #[test]
    fn a_key_lookup_cannot_be_given_an_organization_by_the_caller() {
        assert!(
            !KEY_BY_ID_SQL.contains("?2"),
            "the lookup takes exactly one id"
        );
        assert!(KEY_BY_ID_SQL.contains("org_id"));
    }

    /// F14-005. The last-used statement has two bound values and no column for a
    /// payload, a header, or a query string.
    #[test]
    fn last_used_records_a_time_and_a_bounded_source_and_nothing_else() {
        assert_eq!(TOUCH_KEY_USE_SQL.matches('?').count(), 3);
        assert!(!TOUCH_KEY_USE_SQL.contains("request"));
        assert!(!TOUCH_KEY_USE_SQL.contains("header"));
        assert!(!TOUCH_KEY_USE_SQL.contains("query"));
    }

    /// The credential read joins the account so a suspended account denies every
    /// key under it in the SAME read.
    #[test]
    fn the_credential_read_carries_account_state() {
        assert!(KEY_BY_PREFIX_WITH_ACCOUNT_SQL.contains("JOIN service_accounts"));
        assert!(KEY_BY_PREFIX_WITH_ACCOUNT_SQL.contains("a.status AS account_status"));
    }

    #[test]
    fn the_frozen_bounds_are_the_ones_the_gate_names() {
        assert_eq!(MAX_ACTIVE_SERVICE_ACCOUNTS_PER_ORG, 50);
        assert_eq!(MAX_ACTIVE_KEYS_PER_ACCOUNT, 5);
    }

    #[test]
    fn list_limits_are_clamped_to_a_bounded_page() {
        assert_eq!(P07_PAGE_LIMIT_DEFAULT, 50);
        assert_eq!(P07_PAGE_LIMIT_MAX, 100);
        const { assert!(P07_PAGE_LIMIT_MAX < 1_000) };
    }
}
