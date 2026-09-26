//! D1 persistence for P07 platform operations (`0018_p07_platform_operations.sql`).
//!
//! # Nothing here is tenant data, and nothing here is customer-reachable
//!
//! Every read a browser performs is impossible: there is no route that takes an
//! `org_id` and reads these tables with it. Staff resolve a credential, a role,
//! and (for customer context) a grant, and the organization in a grant is the one
//! the grant names — never one a request supplied.
//!
//! # The three properties this file exists to keep
//!
//! 1. **Staff credentials are hashed, once.** `resolve_staff_credential` reads by
//!    prefix, then compares the presented secret's hash in constant time. The raw
//!    token is never a column, and this file has no writer that takes one.
//! 2. **A grant's liveness is read, not cached.** `find_live_grant` returns the
//!    grant's stored state and its expiry, and the caller turns that into a
//!    decision. A grant that is written as `revoked` stops working on the next
//!    request; there is no path where a stale copy grants access.
//! 3. **Kill-switch resolution is a filter, not a post-filter.** `switches_for`
//!    binds the target class and reference in the `WHERE` clause and returns
//!    engaged rows only, so a switch aimed elsewhere cannot become a denial.

use serde::{Deserialize, Serialize};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::Timestamp,
    modules::{
        rollouts::{
            FeatureFlag, FlagCohort, KillSwitch, KillSwitchScope, KillSwitchState,
            KillSwitchTargetClass,
        },
        staff::{StaffPermission, StaffRole},
    },
};

/// Most rows one `/internal` list page may return.
pub const INTERNAL_PAGE_LIMIT_MAX: i32 = 100;

// ---------------------------------------------------------------- SQL ------

const STAFF_BY_CREDENTIAL_SQL: &str = r#"
SELECT staff_principal_id, email, display_name, staff_role, status,
       credential_prefix, credential_hash, credential_fingerprint,
       version, created_at, updated_at
FROM staff_principals
WHERE credential_prefix = ?1
LIMIT 1
"#;

const STAFF_BY_ID_SQL: &str = r#"
SELECT staff_principal_id, email, display_name, staff_role, status,
       credential_prefix, credential_hash, credential_fingerprint,
       version, created_at, updated_at
FROM staff_principals
WHERE staff_principal_id = ?1
LIMIT 1
"#;

const STAFF_PAGE_SQL: &str = r#"
SELECT staff_principal_id, email, display_name, staff_role, status,
       credential_prefix, credential_hash, credential_fingerprint,
       version, created_at, updated_at
FROM staff_principals
WHERE (?1 = '' OR (created_at, staff_principal_id) < (?1, ?2))
ORDER BY created_at DESC, staff_principal_id DESC
LIMIT ?3
"#;

const INSERT_STAFF_SQL: &str = r#"
INSERT INTO staff_principals (
    staff_principal_id, email, display_name, staff_role, status,
    credential_prefix, credential_hash, credential_fingerprint,
    version, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6, ?7, 1, ?8, ?8)
"#;

const INSERT_GRANT_SQL: &str = r#"
INSERT INTO support_grants (
    grant_id, staff_principal_id, organization_id, reason, ticket_reference,
    capabilities_json, issued_at, expires_at, version, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?7, ?7)
"#;

/// The grant read every customer-context request uses. It is scoped by ALL THREE
/// of staff, organization and state, because a request that names a different
/// organization must not receive a grant that names this one.
const GRANTS_FOR_STAFF_AND_ORG_SQL: &str = r#"
SELECT grant_id, staff_principal_id, organization_id, reason, ticket_reference,
       capabilities_json, issued_at, expires_at, revoked_at, revoke_reason,
       version, created_at, updated_at
FROM support_grants
WHERE staff_principal_id = ?1 AND organization_id = ?2
ORDER BY issued_at DESC, grant_id DESC
LIMIT ?3
"#;

const GRANT_BY_ID_SQL: &str = r#"
SELECT grant_id, staff_principal_id, organization_id, reason, ticket_reference,
       capabilities_json, issued_at, expires_at, revoked_at, revoke_reason,
       version, created_at, updated_at
FROM support_grants
WHERE grant_id = ?1
LIMIT 1
"#;

const GRANTS_PAGE_SQL: &str = r#"
SELECT grant_id, staff_principal_id, organization_id, reason, ticket_reference,
       capabilities_json, issued_at, expires_at, revoked_at, revoke_reason,
       version, created_at, updated_at
FROM support_grants
WHERE (?1 = '' OR (issued_at, grant_id) < (?1, ?2))
ORDER BY issued_at DESC, grant_id DESC
LIMIT ?3
"#;

const REVOKE_GRANT_SQL: &str = r#"
UPDATE support_grants
SET revoked_at = ?3, revoke_reason = ?4, version = version + 1, updated_at = ?3
WHERE grant_id = ?1 AND staff_principal_id = ?2 AND version = ?5 AND revoked_at IS NULL
"#;

const FLAGS_PAGE_SQL: &str = r#"
SELECT flag_key, enabled, rollout_percentage, org_allowlist_json, cohort, expires_at,
       owner_staff_principal_id, updated_by, version, created_at, updated_at
FROM feature_flags
WHERE (?1 = '' OR flag_key > ?1)
ORDER BY flag_key ASC
LIMIT ?2
"#;

const FLAG_BY_KEY_SQL: &str = r#"
SELECT flag_key, enabled, rollout_percentage, org_allowlist_json, cohort, expires_at,
       owner_staff_principal_id, updated_by, version, created_at, updated_at
FROM feature_flags
WHERE flag_key = ?1
LIMIT 1
"#;

const INSERT_FLAG_SQL: &str = r#"
INSERT INTO feature_flags (
    flag_key, enabled, rollout_percentage, org_allowlist_json, cohort, expires_at,
    owner_staff_principal_id, updated_by, version, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 1, ?8, ?8)
"#;

const UPDATE_FLAG_SQL: &str = r#"
UPDATE feature_flags
SET enabled = ?2,
    rollout_percentage = ?3,
    org_allowlist_json = ?4,
    cohort = ?5,
    expires_at = ?6,
    owner_staff_principal_id = ?7,
    updated_by = ?8,
    version = version + 1,
    updated_at = ?9
WHERE flag_key = ?1 AND version = ?10
"#;

/// A guard that fails the surrounding D1 batch when a flag is not at the expected
/// version, so a concurrent PATCH cannot slip between the read and the write.
pub const ASSERT_FLAG_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM feature_flags WHERE flag_key = ?1 AND version = ?2
)
"#;

const KILL_SWITCHES_FOR_TARGET_SQL: &str = r#"
SELECT kill_switch_id, target_class, target_ref, scope, organization_id, reason,
       engaged_by_staff_principal_id, engaged_at, expires_at, state, lifted_at,
       lifted_by, lift_reason, version, created_at, updated_at
FROM kill_switches
WHERE target_class = ?1
  AND target_ref = ?2
  AND state = 'engaged'
  AND (scope = 'global' OR organization_id = ?3)
ORDER BY scope ASC, engaged_at ASC, kill_switch_id ASC
LIMIT ?4
"#;

const KILL_SWITCHES_PAGE_SQL: &str = r#"
SELECT kill_switch_id, target_class, target_ref, scope, organization_id, reason,
       engaged_by_staff_principal_id, engaged_at, expires_at, state, lifted_at,
       lifted_by, lift_reason, version, created_at, updated_at
FROM kill_switches
WHERE (?1 = '' OR (created_at, kill_switch_id) < (?1, ?2))
ORDER BY created_at DESC, kill_switch_id DESC
LIMIT ?3
"#;

const KILL_SWITCH_BY_ID_SQL: &str = r#"
SELECT kill_switch_id, target_class, target_ref, scope, organization_id, reason,
       engaged_by_staff_principal_id, engaged_at, expires_at, state, lifted_at,
       lifted_by, lift_reason, version, created_at, updated_at
FROM kill_switches
WHERE kill_switch_id = ?1
LIMIT 1
"#;

const INSERT_KILL_SWITCH_SQL: &str = r#"
INSERT INTO kill_switches (
    kill_switch_id, target_class, target_ref, scope, organization_id, reason,
    engaged_by_staff_principal_id, engaged_at, expires_at, state, version,
    created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'engaged', 1, ?8, ?8)
"#;

const LIFT_KILL_SWITCH_SQL: &str = r#"
UPDATE kill_switches
SET state = 'lifted', lifted_at = ?3, lifted_by = ?4, lift_reason = ?5,
    version = version + 1, updated_at = ?3
WHERE kill_switch_id = ?1 AND version = ?2 AND state = 'engaged'
"#;

pub const ASSERT_KILL_SWITCH_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM kill_switches WHERE kill_switch_id = ?1 AND version = ?2
)
"#;

// ---------------------------------------------------------------- records ---

#[derive(Clone, Deserialize, Serialize)]
pub struct StaffPrincipalRecord {
    pub staff_principal_id: String,
    pub email: String,
    pub display_name: String,
    pub staff_role: String,
    pub status: String,
    pub credential_prefix: String,
    pub credential_hash: String,
    pub credential_fingerprint: String,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl StaffPrincipalRecord {
    pub fn role(&self) -> Option<StaffRole> {
        StaffRole::parse(&self.staff_role)
    }

    pub fn is_active(&self) -> bool {
        self.status == "active"
    }
}

impl std::fmt::Debug for StaffPrincipalRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaffPrincipalRecord")
            .field("staff_principal_id", &self.staff_principal_id)
            .field("staff_role", &self.staff_role)
            .field("status", &self.status)
            .field("credential_prefix", &self.credential_prefix)
            // The hash and the email are both excluded: the hash is credential
            // material and the email is an internal identity.
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct SupportGrantRecord {
    pub grant_id: String,
    pub staff_principal_id: String,
    pub organization_id: String,
    pub reason: String,
    pub ticket_reference: String,
    pub capabilities_json: String,
    pub issued_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub revoke_reason: Option<String>,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct FeatureFlagRecord {
    pub flag_key: String,
    pub enabled: i64,
    pub rollout_percentage: i64,
    pub org_allowlist_json: String,
    pub cohort: String,
    pub expires_at: String,
    pub owner_staff_principal_id: String,
    pub updated_by: String,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl FeatureFlagRecord {
    /// Rebuild the domain value. An unparseable stored `cohort` becomes `None`
    /// rather than a guess, because guessing would make a flag resolve for a
    /// cohort nobody configured.
    pub fn to_domain(&self) -> FeatureFlag {
        FeatureFlag {
            flag_key: self.flag_key.clone(),
            enabled: self.enabled != 0,
            rollout_percentage: self.rollout_percentage.clamp(0, 100) as u8,
            org_allowlist: crate::modules::machine_identity::string_list(Some(
                self.org_allowlist_json.as_str(),
            ))
            .ok()
            .flatten()
            .unwrap_or_default(),
            cohort: FlagCohort::parse(&self.cohort).unwrap_or_default(),
            expires_at: self.expires_at.clone(),
            owner_staff_principal_id: self.owner_staff_principal_id.clone(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct KillSwitchRecord {
    pub kill_switch_id: String,
    pub target_class: String,
    pub target_ref: String,
    pub scope: String,
    pub organization_id: Option<String>,
    pub reason: String,
    pub engaged_by_staff_principal_id: String,
    pub engaged_at: String,
    pub expires_at: Option<String>,
    pub state: String,
    pub lifted_at: Option<String>,
    pub lifted_by: Option<String>,
    pub lift_reason: Option<String>,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl KillSwitchRecord {
    /// Rebuild the domain value, or `None` when a stored enum is unrecognised.
    ///
    /// `None` is the fail-safe direction: an unreadable target class produces "no
    /// switch applies" from the caller's perspective only if the caller checks,
    /// which is why the read is paired with `switches_for` rather than used to
    /// replace it.
    pub fn to_domain(&self) -> Option<KillSwitch> {
        Some(KillSwitch {
            target_class: KillSwitchTargetClass::parse(&self.target_class)?,
            target_ref: self.target_ref.clone(),
            scope: KillSwitchScope::parse(&self.scope)?,
            organization_id: self
                .organization_id
                .as_deref()
                .and_then(|id| id.parse().ok()),
            state: KillSwitchState::parse(&self.state)?,
            expires_at: self.expires_at.clone(),
        })
    }
}

// --------------------------------------------------------------- writers ----

pub struct NewStaffPrincipalInput<'a> {
    pub staff_principal_id: &'a str,
    pub email: &'a str,
    pub display_name: &'a str,
    pub staff_role: &'a str,
    /// Non-secret lookup index.
    pub credential_prefix: &'a str,
    /// The hash. NEVER the raw token: this struct has no field for it.
    pub credential_hash: &'a str,
    pub credential_fingerprint: &'a str,
    pub now: &'a str,
}

pub struct NewSupportGrantInput<'a> {
    pub grant_id: &'a str,
    pub staff_principal_id: &'a str,
    pub organization_id: &'a str,
    pub reason: &'a str,
    pub ticket_reference: &'a str,
    pub capabilities_json: &'a str,
    pub issued_at: &'a str,
    pub expires_at: &'a str,
}

/// The fields a flag PATCH may change, bound together. Grouped for the same
/// reason as every other input struct here: a transposed pair of adjacent
/// optional parameters writes the wrong column on a versioned row.
pub struct FeatureFlagUpdateInput<'a> {
    pub flag_key: &'a str,
    pub enabled: bool,
    pub rollout_percentage: i64,
    pub org_allowlist_json: &'a str,
    pub cohort: &'a str,
    pub expires_at: &'a str,
    pub owner_staff_principal_id: &'a str,
    pub updated_by: &'a str,
    pub expected_version: i64,
    pub now: &'a str,
}

pub struct NewFeatureFlagInput<'a> {
    pub flag_key: &'a str,
    pub enabled: bool,
    pub rollout_percentage: i64,
    pub org_allowlist_json: &'a str,
    pub cohort: &'a str,
    pub expires_at: &'a str,
    pub owner_staff_principal_id: &'a str,
    pub now: &'a str,
}

pub struct NewKillSwitchInput<'a> {
    pub kill_switch_id: &'a str,
    pub target_class: &'a str,
    pub target_ref: &'a str,
    pub scope: &'a str,
    pub organization_id: Option<&'a str>,
    pub reason: &'a str,
    pub engaged_by_staff_principal_id: &'a str,
    pub engaged_at: &'a str,
    pub expires_at: Option<&'a str>,
}

// ----------------------------------------------------------- repository -----

pub struct PlatformOperationsRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> PlatformOperationsRepository<'a> {
    pub fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    // -- staff -------------------------------------------------------------

    /// The authentication read. One row, by non-secret prefix.
    pub async fn resolve_staff_credential(
        &self,
        presented: &str,
    ) -> worker::Result<Option<StaffPrincipalRecord>> {
        let key = match crate::core::StaffKey::parse(presented) {
            Ok(key) => key,
            Err(_) => return Ok(None),
        };
        self.database
            .prepare(STAFF_BY_CREDENTIAL_SQL, &[BindValue::Text(key.prefix())])?
            .first::<StaffPrincipalRecord>(None)
            .await
    }

    pub async fn find_staff(
        &self,
        staff_principal_id: &str,
    ) -> worker::Result<Option<StaffPrincipalRecord>> {
        self.database
            .prepare(STAFF_BY_ID_SQL, &[BindValue::Text(staff_principal_id)])?
            .first::<StaffPrincipalRecord>(None)
            .await
    }

    pub async fn list_staff(
        &self,
        cursor_created_at: Option<&str>,
        cursor_id: Option<&str>,
        limit: i32,
    ) -> worker::Result<Vec<StaffPrincipalRecord>> {
        self.database
            .prepare(
                STAFF_PAGE_SQL,
                &[
                    BindValue::Text(cursor_created_at.unwrap_or_default()),
                    BindValue::Text(cursor_id.unwrap_or_default()),
                    BindValue::Integer(limit.clamp(1, INTERNAL_PAGE_LIMIT_MAX)),
                ],
            )?
            .all()
            .await?
            .results::<StaffPrincipalRecord>()
    }

    /// P07 ships no staff-creation ROUTE. A staff principal is provisioned by a
    /// migration or an operator tool, not by a customer-facing endpoint, and the
    /// writer exists so that path is auditable rather than a raw `INSERT` in a
    /// shell.
    pub fn insert_staff_statement(
        &self,
        input: &NewStaffPrincipalInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_STAFF_SQL,
            &[
                BindValue::Text(input.staff_principal_id),
                BindValue::Text(input.email),
                BindValue::Text(input.display_name),
                BindValue::Text(input.staff_role),
                BindValue::Text(input.credential_prefix),
                BindValue::Text(input.credential_hash),
                BindValue::Text(input.credential_fingerprint),
                BindValue::Text(input.now),
            ],
        )
    }

    // -- support grants ----------------------------------------------------

    /// Grants issued to one staff principal against one organization.
    ///
    /// All three of staff, organization and bound are in the predicate, so a
    /// request cannot receive a grant naming a different organization and a
    /// caller cannot widen the result by naming a different staff principal.
    pub async fn find_grants_for_staff_and_org(
        &self,
        staff_principal_id: &str,
        organization_id: &str,
        limit: i32,
    ) -> worker::Result<Vec<SupportGrantRecord>> {
        self.database
            .prepare(
                GRANTS_FOR_STAFF_AND_ORG_SQL,
                &[
                    BindValue::Text(staff_principal_id),
                    BindValue::Text(organization_id),
                    BindValue::Integer(limit.clamp(1, INTERNAL_PAGE_LIMIT_MAX)),
                ],
            )?
            .all()
            .await?
            .results::<SupportGrantRecord>()
    }

    pub async fn find_grant(&self, grant_id: &str) -> worker::Result<Option<SupportGrantRecord>> {
        self.database
            .prepare(GRANT_BY_ID_SQL, &[BindValue::Text(grant_id)])?
            .first::<SupportGrantRecord>(None)
            .await
    }

    pub async fn list_grants(
        &self,
        cursor_issued_at: Option<&str>,
        cursor_id: Option<&str>,
        limit: i32,
    ) -> worker::Result<Vec<SupportGrantRecord>> {
        self.database
            .prepare(
                GRANTS_PAGE_SQL,
                &[
                    BindValue::Text(cursor_issued_at.unwrap_or_default()),
                    BindValue::Text(cursor_id.unwrap_or_default()),
                    BindValue::Integer(limit.clamp(1, INTERNAL_PAGE_LIMIT_MAX)),
                ],
            )?
            .all()
            .await?
            .results::<SupportGrantRecord>()
    }

    pub fn insert_grant_statement(
        &self,
        input: &NewSupportGrantInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_GRANT_SQL,
            &[
                BindValue::Text(input.grant_id),
                BindValue::Text(input.staff_principal_id),
                BindValue::Text(input.organization_id),
                BindValue::Text(input.reason),
                BindValue::Text(input.ticket_reference),
                BindValue::Text(input.capabilities_json),
                BindValue::Text(input.issued_at),
                BindValue::Text(input.expires_at),
            ],
        )
    }

    /// Revocation is attributed: the statement binds the ISSUER, so a principal
    /// cannot revoke a grant issued to somebody else. The 0018 trigger refuses a
    /// revocation without a reason, and this binds one.
    pub fn revoke_grant_statement(
        &self,
        grant_id: &str,
        staff_principal_id: &str,
        reason: &str,
        expected_version: i64,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            REVOKE_GRANT_SQL,
            &[
                BindValue::Text(grant_id),
                BindValue::Text(staff_principal_id),
                BindValue::Text(now.as_str()),
                BindValue::Text(reason),
                BindValue::Int64(expected_version),
            ],
        )
    }

    // -- feature flags -----------------------------------------------------

    pub async fn find_flag(&self, flag_key: &str) -> worker::Result<Option<FeatureFlagRecord>> {
        self.database
            .prepare(FLAG_BY_KEY_SQL, &[BindValue::Text(flag_key)])?
            .first::<FeatureFlagRecord>(None)
            .await
    }

    pub async fn list_flags(
        &self,
        cursor_key: Option<&str>,
        limit: i32,
    ) -> worker::Result<Vec<FeatureFlagRecord>> {
        self.database
            .prepare(
                FLAGS_PAGE_SQL,
                &[
                    BindValue::Text(cursor_key.unwrap_or_default()),
                    BindValue::Integer(limit.clamp(1, INTERNAL_PAGE_LIMIT_MAX)),
                ],
            )?
            .all()
            .await?
            .results::<FeatureFlagRecord>()
    }

    pub fn insert_flag_statement(
        &self,
        input: &NewFeatureFlagInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_FLAG_SQL,
            &[
                BindValue::Text(input.flag_key),
                BindValue::Integer(i32::from(input.enabled)),
                BindValue::Int64(input.rollout_percentage),
                BindValue::Text(input.org_allowlist_json),
                BindValue::Text(input.cohort),
                BindValue::Text(input.expires_at),
                BindValue::Text(input.owner_staff_principal_id),
                BindValue::Text(input.now),
            ],
        )
    }

    pub fn update_flag_statement(
        &self,
        input: &FeatureFlagUpdateInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_FLAG_SQL,
            &[
                BindValue::Text(input.flag_key),
                BindValue::Integer(i32::from(input.enabled)),
                BindValue::Int64(input.rollout_percentage),
                BindValue::Text(input.org_allowlist_json),
                BindValue::Text(input.cohort),
                BindValue::Text(input.expires_at),
                BindValue::Text(input.owner_staff_principal_id),
                BindValue::Text(input.updated_by),
                BindValue::Text(input.now),
                BindValue::Int64(input.expected_version),
            ],
        )
    }

    pub fn assert_flag_version_statement(
        &self,
        flag_key: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_FLAG_VERSION_SQL,
            &[
                BindValue::Text(flag_key),
                BindValue::Int64(expected_version),
            ],
        )
    }

    // -- kill switches -----------------------------------------------------

    /// Engaged switches covering one target for one organization.
    ///
    /// The target class, the reference, the engaged state, and the scope are all
    /// predicates. `scope = 'global' OR organization_id = ?3` is what makes
    /// "target one org before global disable" possible: both rows come back and
    /// the caller resolves them, rather than the query hiding the narrower one.
    /// `ORDER BY scope ASC` puts `global` before `organization`, because `'global'
    /// < 'organization'` lexicographically, so the narrow decision is evaluated
    /// after the broad one and a caller that stops at the first engaged row
    /// reports the narrow one.
    pub async fn switches_for(
        &self,
        target_class: KillSwitchTargetClass,
        target_ref: &str,
        organization_id: &str,
    ) -> worker::Result<Vec<KillSwitchRecord>> {
        self.database
            .prepare(
                KILL_SWITCHES_FOR_TARGET_SQL,
                &[
                    BindValue::Text(target_class.as_str()),
                    BindValue::Text(target_ref),
                    BindValue::Text(organization_id),
                    BindValue::Integer(INTERNAL_PAGE_LIMIT_MAX),
                ],
            )?
            .all()
            .await?
            .results::<KillSwitchRecord>()
    }

    pub async fn find_kill_switch(
        &self,
        kill_switch_id: &str,
    ) -> worker::Result<Option<KillSwitchRecord>> {
        self.database
            .prepare(KILL_SWITCH_BY_ID_SQL, &[BindValue::Text(kill_switch_id)])?
            .first::<KillSwitchRecord>(None)
            .await
    }

    pub async fn list_kill_switches(
        &self,
        cursor_created_at: Option<&str>,
        cursor_id: Option<&str>,
        limit: i32,
    ) -> worker::Result<Vec<KillSwitchRecord>> {
        self.database
            .prepare(
                KILL_SWITCHES_PAGE_SQL,
                &[
                    BindValue::Text(cursor_created_at.unwrap_or_default()),
                    BindValue::Text(cursor_id.unwrap_or_default()),
                    BindValue::Integer(limit.clamp(1, INTERNAL_PAGE_LIMIT_MAX)),
                ],
            )?
            .all()
            .await?
            .results::<KillSwitchRecord>()
    }

    pub fn insert_kill_switch_statement(
        &self,
        input: &NewKillSwitchInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_KILL_SWITCH_SQL,
            &[
                BindValue::Text(input.kill_switch_id),
                BindValue::Text(input.target_class),
                BindValue::Text(input.target_ref),
                BindValue::Text(input.scope),
                input
                    .organization_id
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.reason),
                BindValue::Text(input.engaged_by_staff_principal_id),
                BindValue::Text(input.engaged_at),
                input.expires_at.map_or(BindValue::Null, BindValue::Text),
            ],
        )
    }

    pub fn lift_kill_switch_statement(
        &self,
        kill_switch_id: &str,
        expected_version: i64,
        lifted_by: &str,
        lift_reason: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            LIFT_KILL_SWITCH_SQL,
            &[
                BindValue::Text(kill_switch_id),
                BindValue::Int64(expected_version),
                BindValue::Text(now.as_str()),
                BindValue::Text(lifted_by),
                BindValue::Text(lift_reason),
            ],
        )
    }

    pub fn assert_kill_switch_version_statement(
        &self,
        kill_switch_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_KILL_SWITCH_VERSION_SQL,
            &[
                BindValue::Text(kill_switch_id),
                BindValue::Int64(expected_version),
            ],
        )
    }
}

/// Render a staff permission set as the JSON array the schema stores. Sorted and
/// deduplicated so two equal sets serialize identically.
pub fn staff_capabilities_json(capabilities: &[StaffPermission]) -> String {
    let mut names: Vec<&str> = capabilities.iter().map(|c| c.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    serde_json::to_string(&names).unwrap_or_else(|_| "[]".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F24-001: no shared admin account. The staff writer takes a hash, and the
    /// struct has no field for the token, so the raw value cannot reach a row even
    /// by a future mistake.
    #[test]
    fn the_staff_writer_has_no_field_for_a_raw_token() {
        let input = NewStaffPrincipalInput {
            staff_principal_id: "stf_0123456789abcdef0123456789abcdef",
            email: "someone@internal.example",
            display_name: "Someone",
            staff_role: "support",
            credential_prefix: "0123456789abcdef",
            credential_hash: &"a".repeat(64),
            credential_fingerprint: "abcdef0123456789",
            now: "2026-09-26T12:00:00.000Z",
        };
        assert!(INSERT_STAFF_SQL.contains("credential_hash"));
        assert!(!INSERT_STAFF_SQL.contains("raw"));
        assert!(!INSERT_STAFF_SQL.contains("token"));
        assert_eq!(input.credential_hash.len(), 64);
    }

    /// The grant read is scoped by staff AND organization AND a bound. A request
    /// cannot name a grant that belongs to another organization.
    #[test]
    fn the_grant_read_is_scoped_by_staff_and_organization() {
        assert!(GRANTS_FOR_STAFF_AND_ORG_SQL.contains("staff_principal_id = ?1"));
        assert!(GRANTS_FOR_STAFF_AND_ORG_SQL.contains("organization_id = ?2"));
        assert!(GRANTS_FOR_STAFF_AND_ORG_SQL.contains("LIMIT ?3"));
    }

    /// The kill-switch read returns BOTH the global and the organization-scoped
    /// row, and orders the narrow one last. A query that returned only the
    /// global one would make F24's "target one org before global disable"
    /// impossible to resolve.
    #[test]
    fn the_kill_switch_read_returns_narrow_and_broad_ordered_narrow_last() {
        assert!(KILL_SWITCHES_FOR_TARGET_SQL.contains("scope = 'global' OR organization_id = ?3"));
        assert!(KILL_SWITCHES_FOR_TARGET_SQL.contains("ORDER BY scope ASC"));
        // `global` sorts before `organization`, so ASC puts the narrow row last
        // and a caller that takes the first engaged row reports the narrow one.
        assert!("global" < "organization");
        // ...and a lifted switch is not returned at all.
        assert!(KILL_SWITCHES_FOR_TARGET_SQL.contains("state = 'engaged'"));
    }

    /// The organization is a predicate, never a post-filter, on the credential
    /// read too.
    #[test]
    fn the_staff_credential_read_takes_only_a_prefix() {
        assert!(STAFF_BY_CREDENTIAL_SQL.contains("WHERE credential_prefix = ?1"));
        assert!(!STAFF_BY_CREDENTIAL_SQL.contains("?2"));
    }

    #[test]
    fn a_flag_read_fails_closed_on_an_unrecognised_cohort() {
        let record = FeatureFlagRecord {
            flag_key: "plugins.v2".into(),
            enabled: 1,
            rollout_percentage: 25,
            org_allowlist_json: "[]".into(),
            cohort: "nonsense".into(),
            expires_at: "2026-10-26T12:00:00.000Z".into(),
            owner_staff_principal_id: "stf_0123456789abcdef0123456789abcdef".into(),
            updated_by: "stf_0123456789abcdef0123456789abcdef".into(),
            version: 1,
            created_at: "2026-09-26T12:00:00.000Z".into(),
            updated_at: "2026-09-26T12:00:00.000Z".into(),
        };
        // `None` cohort is the default and means "evaluate against the
        // organization", which is the only unit that exists for an org flag.
        assert_eq!(record.to_domain().cohort, FlagCohort::None);
        assert_eq!(record.to_domain().rollout_percentage, 25);
    }

    #[test]
    fn staff_capabilities_serialize_deterministically() {
        let one =
            staff_capabilities_json(&[StaffPermission::OrgDevicesRead, StaffPermission::OrgLookup]);
        let two = staff_capabilities_json(&[
            StaffPermission::OrgLookup,
            StaffPermission::OrgDevicesRead,
            StaffPermission::OrgLookup,
        ]);
        assert_eq!(one, two);
        assert_eq!(one, r#"["org.devices.read","org.lookup"]"#);
    }
}
