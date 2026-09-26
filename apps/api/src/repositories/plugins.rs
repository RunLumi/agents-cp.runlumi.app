//! D1 persistence for P07 plugin governance (`0017_p07_plugin_governance.sql`).
//!
//! # The read that matters
//!
//! [`PluginGovernanceRepository::decision_inputs`] is the only read a decision
//! needs, and it is a single tenant-scoped query set. Everything the deny
//! decision depends on — the org's policy, the install's review state, the
//! platform quarantine for the exact `package@version`, the approved publisher
//! list — is fetched here and turned into a
//! [`PluginFacts`](crate::modules::plugins::PluginFacts) value. The decision
//! function itself never touches D1, which is what makes it testable without a
//! database and makes the deny decision reproducible from a snapshot.
//!
//! # Quarantine is read, never inferred
//!
//! `quarantined` is an EXISTS over `plugin_quarantines` for the exact
//! `(package_id, version)` with `lifted_at IS NULL`. A lifted quarantine stops
//! matching, so lifting takes effect on the next request. It is not a column on
//! the install that somebody has to remember to clear, because a column is
//! exactly how a lifted quarantine stays lifted after the reason is gone.

use serde::{Deserialize, Serialize};
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::Timestamp,
    modules::plugins::{
        PluginPolicy, PluginReviewState, PublisherMode, UpdateMode, policy_conflicts,
    },
};

pub const PLUGIN_PAGE_LIMIT_MAX: i32 = 100;

// ---------------------------------------------------------------- SQL ------

const PACKAGE_SQL: &str = r#"
SELECT p.package_id, p.publisher_id, p.display_name, p.summary, p.status,
       p.created_at, p.updated_at, pub.official AS publisher_official,
       pub.status AS publisher_status
FROM plugin_packages p
JOIN plugin_publishers pub ON pub.publisher_id = p.publisher_id
WHERE p.package_id = ?1
LIMIT 1
"#;

const CATALOG_SQL: &str = r#"
SELECT p.package_id, p.publisher_id, p.display_name, p.summary, p.status,
       p.created_at, p.updated_at, pub.official AS publisher_official,
       pub.status AS publisher_status
FROM plugin_packages p
JOIN plugin_publishers pub ON pub.publisher_id = p.publisher_id
WHERE (?1 = '' OR p.package_id > ?1)
ORDER BY p.package_id ASC
LIMIT ?2
"#;

const VERSIONS_FOR_PACKAGE_SQL: &str = r#"
SELECT plugin_version_id, package_id, version, runtime_min, runtime_max,
       content_digest, signature, manifest_json, published_at, created_at
FROM plugin_versions
WHERE package_id = ?1
ORDER BY published_at DESC, version DESC
LIMIT ?2
"#;

const VERSION_BY_PACKAGE_AND_VERSION_SQL: &str = r#"
SELECT plugin_version_id, package_id, version, runtime_min, runtime_max,
       content_digest, signature, manifest_json, published_at, created_at
FROM plugin_versions
WHERE package_id = ?1 AND version = ?2
LIMIT 1
"#;

const INSTALL_BY_ORG_AND_PACKAGE_SQL: &str = r#"
SELECT install_id, org_id, package_id, version, pending_review_version, review_state,
       review_reason, approved_by, approved_at, blocked_reason, version_counter,
       created_at, updated_at
FROM plugin_installs
WHERE org_id = ?1 AND package_id = ?2
LIMIT 1
"#;

const INSTALLS_FOR_ORG_SQL: &str = r#"
SELECT install_id, org_id, package_id, version, pending_review_version, review_state,
       review_reason, approved_by, approved_at, blocked_reason, version_counter,
       created_at, updated_at
FROM plugin_installs
WHERE org_id = ?1 AND (?2 = '' OR package_id > ?2)
ORDER BY package_id ASC
LIMIT ?3
"#;

/// F25-008. The platform decision against ONE exact `package@version`. The
/// predicate is the whole control: a quarantined version denies new executions
/// whether or not the artifact is still present on the host.
const QUARANTINE_ACTIVE_FOR_SQL: &str = r#"
SELECT COUNT(*) AS total
FROM plugin_quarantines
WHERE package_id = ?1 AND version = ?2 AND lifted_at IS NULL
"#;

const POLICY_BY_ORG_SQL: &str = r#"
SELECT org_id, publisher_mode, approved_publishers_json, allowed_packages_json,
       blocked_packages_json, pinned_versions_json, auto_update, update_mode,
       version, created_at, updated_at
FROM plugin_policies
WHERE org_id = ?1
LIMIT 1
"#;

const INSERT_POLICY_SQL: &str = r#"
INSERT INTO plugin_policies (
    org_id, publisher_mode, approved_publishers_json, allowed_packages_json,
    blocked_packages_json, pinned_versions_json, auto_update, update_mode,
    version, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?9)
"#;

const UPDATE_POLICY_SQL: &str = r#"
UPDATE plugin_policies
SET publisher_mode = ?2,
    approved_publishers_json = ?3,
    allowed_packages_json = ?4,
    blocked_packages_json = ?5,
    pinned_versions_json = ?6,
    auto_update = ?7,
    update_mode = ?8,
    version = version + 1,
    updated_at = ?9
WHERE org_id = ?1 AND version = ?10
"#;

const INSERT_INSTALL_SQL: &str = r#"
INSERT INTO plugin_installs (
    install_id, org_id, package_id, version, pending_review_version, review_state,
    review_reason, approved_by, approved_at, version_counter, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?10)
"#;

/// The installed version and the review state move together, and the review
/// state binds the expected current one. A concurrent approve cannot be lost into
/// a row that has since been blocked.
const UPDATE_INSTALL_SQL: &str = r#"
UPDATE plugin_installs
SET version = ?3,
    pending_review_version = ?4,
    review_state = ?5,
    review_reason = ?6,
    approved_by = ?7,
    approved_at = ?8,
    version_counter = version_counter + 1,
    updated_at = ?9
WHERE org_id = ?1 AND package_id = ?2 AND version_counter = ?10
"#;

/// The install's BLOCK STATE, which is where a blocked reason lives.
///
/// A separate statement from the policy write because the two rows are different
/// resources — one is the org's list, the other is this org's installation of
/// this package — and the caller commits them in one batch. The reason is bound
/// rather than interpolated, and the 0017 trigger refuses a `blocked` row whose
/// reason is missing, so a caller that forgets it fails loudly instead of
/// recording a block nobody can explain.
const SET_INSTALL_BLOCK_SQL: &str = r#"
UPDATE plugin_installs
SET review_state = ?3,
    blocked_reason = ?4,
    version_counter = version_counter + 1,
    updated_at = ?5
WHERE org_id = ?1 AND package_id = ?2 AND version_counter = ?6
"#;

const INSERT_REGISTRATION_SQL: &str = r#"
INSERT INTO plugin_tool_registrations (
    registration_id, org_id, package_id, version, tool_id, approved_by, approved_at, created_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
"#;

/// One row per tool the org has NOT registered, for the declared manifest. This
/// is the query that backs `plugin_tool_unregistered`: default-deny is the
/// absence of a row, so the list of what is still unavailable is cheap to
/// produce and impossible to get wrong by omission.
const UNREGISTERED_TOOLS_SQL: &str = r#"
SELECT tool.value AS tool_id
FROM plugin_versions pv, json_each(pv.manifest_json, '$.tools') AS tool
WHERE pv.package_id = ?1 AND pv.version = ?2
  AND NOT EXISTS (
      SELECT 1 FROM plugin_tool_registrations r
      WHERE r.org_id = ?3 AND r.package_id = ?1 AND r.version = ?2
        AND r.tool_id = tool.value
  )
ORDER BY tool.value ASC
"#;

const REGISTERED_TOOLS_SQL: &str = r#"
SELECT registration_id, org_id, package_id, version, tool_id, approved_by, approved_at, created_at
FROM plugin_tool_registrations
WHERE org_id = ?1 AND package_id = ?2 AND version = ?3
ORDER BY tool_id ASC
"#;

const INSERT_QUARANTINE_SQL: &str = r#"
INSERT INTO plugin_quarantines (
    quarantine_id, package_id, version, reason,
    engaged_by_staff_principal_id, engaged_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
"#;

const LIFT_QUARANTINE_SQL: &str = r#"
UPDATE plugin_quarantines
SET lifted_at = ?2, lifted_by = ?3, lift_reason = ?4
WHERE quarantine_id = ?1 AND lifted_at IS NULL
"#;

const QUARANTINES_PAGE_SQL: &str = r#"
SELECT quarantine_id, package_id, version, reason, engaged_by_staff_principal_id,
       engaged_at, lifted_at, lifted_by, lift_reason
FROM plugin_quarantines
WHERE (?1 = '' OR (engaged_at, quarantine_id) < (?1, ?2))
ORDER BY engaged_at DESC, quarantine_id DESC
LIMIT ?3
"#;

const RECORD_REPORT_SQL: &str = r#"
INSERT INTO plugin_installs (
    install_id, org_id, package_id, version, review_state, review_reason,
    version_counter, created_at, updated_at
)
SELECT ?1, ?2, ?3, ?4, 'unreviewed', ?5, 1, ?6, ?6
WHERE NOT EXISTS (
    SELECT 1 FROM plugin_installs WHERE org_id = ?2 AND package_id = ?3
)
"#;

const TOUCH_REPORT_SQL: &str = r#"
UPDATE plugin_installs
SET review_state = 'unreviewed',
    review_reason = ?4,
    version_counter = version_counter + 1,
    updated_at = ?3
WHERE org_id = ?1 AND package_id = ?2
"#;

pub const ASSERT_POLICY_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM plugin_policies WHERE org_id = ?1 AND version = ?2
)
"#;

// ---------------------------------------------------------------- records ---

#[derive(Clone, Deserialize, Serialize)]
pub struct PluginPackageRecord {
    pub package_id: String,
    pub publisher_id: String,
    pub display_name: String,
    pub summary: Option<String>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    pub publisher_official: i64,
    pub publisher_status: String,
}

impl PluginPackageRecord {
    pub fn is_official(&self) -> bool {
        self.publisher_official != 0
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PluginVersionRecord {
    pub plugin_version_id: String,
    pub package_id: String,
    pub version: String,
    pub runtime_min: String,
    pub runtime_max: String,
    pub content_digest: String,
    pub signature: String,
    pub manifest_json: String,
    pub published_at: String,
    pub created_at: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PluginInstallRecord {
    pub install_id: String,
    pub org_id: String,
    pub package_id: String,
    pub version: String,
    pub pending_review_version: Option<String>,
    pub review_state: String,
    pub review_reason: Option<String>,
    pub approved_by: Option<String>,
    pub approved_at: Option<String>,
    pub blocked_reason: Option<String>,
    pub version_counter: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl PluginInstallRecord {
    pub fn review_state(&self) -> Option<PluginReviewState> {
        PluginReviewState::parse(&self.review_state)
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PluginPolicyRecord {
    pub org_id: String,
    pub publisher_mode: String,
    pub approved_publishers_json: String,
    pub allowed_packages_json: String,
    pub blocked_packages_json: String,
    pub pinned_versions_json: String,
    pub auto_update: String,
    pub update_mode: String,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl PluginPolicyRecord {
    /// Rebuild the domain policy, or the default when a stored enum is
    /// unrecognised.
    ///
    /// The default is the RESTRICTIVE one — official publishers only, no
    /// auto-update, managed updates — so a store that has drifted narrows rather
    /// than widens. Widening on a parse failure is the direction that matters.
    pub fn to_domain(&self) -> PluginPolicy {
        PluginPolicy {
            publisher_mode: PublisherMode::parse(&self.publisher_mode).unwrap_or_default(),
            approved_publishers: string_list(&self.approved_publishers_json),
            allowed_packages: string_list(&self.allowed_packages_json),
            blocked_packages: string_list(&self.blocked_packages_json),
            pinned_versions: pinned_map(&self.pinned_versions_json),
            auto_update: self.auto_update == "on",
            update_mode: UpdateMode::parse(&self.update_mode).unwrap_or_default(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PluginToolRegistrationRecord {
    pub registration_id: String,
    pub org_id: String,
    pub package_id: String,
    pub version: String,
    pub tool_id: String,
    pub approved_by: String,
    pub approved_at: String,
    pub created_at: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PluginQuarantineRecord {
    pub quarantine_id: String,
    pub package_id: String,
    pub version: String,
    pub reason: String,
    pub engaged_by_staff_principal_id: String,
    pub engaged_at: String,
    pub lifted_at: Option<String>,
    pub lifted_by: Option<String>,
    pub lift_reason: Option<String>,
}

impl PluginQuarantineRecord {
    pub fn is_active(&self) -> bool {
        self.lifted_at.is_none()
    }
}

#[derive(Deserialize)]
struct CountRow {
    total: i32,
}

#[derive(Deserialize)]
struct ToolIdRow {
    tool_id: String,
}

#[derive(Deserialize)]
struct PolicyConflictRow {
    package_id: String,
}

// --------------------------------------------------------------- writers ----

pub struct PluginPolicyInput<'a> {
    pub org_id: &'a str,
    pub publisher_mode: &'a str,
    pub approved_publishers_json: &'a str,
    pub allowed_packages_json: &'a str,
    pub blocked_packages_json: &'a str,
    pub pinned_versions_json: &'a str,
    pub auto_update: &'a str,
    pub update_mode: &'a str,
    pub now: &'a str,
}

/// The fields a policy PATCH may change, bound together. Grouped for the same
/// reason as every other input struct here: eleven adjacent optional parameters
/// can be transposed, and a transposed write to a versioned policy row is a
/// silent bug rather than a compile error.
pub struct PluginPolicyUpdateInput<'a> {
    pub org_id: &'a str,
    pub publisher_mode: &'a str,
    pub approved_publishers_json: &'a str,
    pub allowed_packages_json: &'a str,
    pub blocked_packages_json: &'a str,
    pub pinned_versions_json: &'a str,
    pub auto_update: &'a str,
    pub update_mode: &'a str,
    pub expected_version: i64,
    pub now: &'a str,
}

/// The fields an install transition may change, bound together. The installed
/// version and the review state move in one statement, and naming them together
/// is what makes that visible.
pub struct PluginInstallUpdateInput<'a> {
    pub org_id: &'a str,
    pub package_id: &'a str,
    pub version: &'a str,
    pub pending_review_version: Option<&'a str>,
    pub review_state: &'a str,
    pub review_reason: Option<&'a str>,
    pub approved_by: Option<&'a str>,
    pub approved_at: Option<&'a str>,
    pub expected_counter: i64,
    pub now: &'a str,
}

/// One approved `(org, package, version, tool)` binding, bound together. The
/// four identity columns are inseparable: a registration missing any one of them
/// would authorize a different thing than the operator approved.
pub struct NewToolRegistrationInput<'a> {
    pub registration_id: &'a str,
    pub org_id: &'a str,
    pub package_id: &'a str,
    pub version: &'a str,
    pub tool_id: &'a str,
    pub approved_by: &'a str,
    pub now: &'a str,
}

pub struct PluginInstallInput<'a> {
    pub install_id: &'a str,
    pub org_id: &'a str,
    pub package_id: &'a str,
    pub version: &'a str,
    pub pending_review_version: Option<&'a str>,
    pub review_state: &'a str,
    pub review_reason: Option<&'a str>,
    pub approved_by: Option<&'a str>,
    pub approved_at: Option<&'a str>,
    pub now: &'a str,
}

pub struct NewPluginReportInput<'a> {
    pub install_id: &'a str,
    pub org_id: &'a str,
    pub package_id: &'a str,
    pub version: &'a str,
    pub reason: &'a str,
    pub now: &'a str,
}

// ----------------------------------------------------------- repository -----

pub struct PluginGovernanceRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> PluginGovernanceRepository<'a> {
    pub fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    // -- catalog -----------------------------------------------------------

    pub async fn find_package(
        &self,
        package_id: &str,
    ) -> worker::Result<Option<PluginPackageRecord>> {
        self.database
            .prepare(PACKAGE_SQL, &[BindValue::Text(package_id)])?
            .first::<PluginPackageRecord>(None)
            .await
    }

    pub async fn list_catalog(
        &self,
        cursor_package_id: Option<&str>,
        limit: i32,
    ) -> worker::Result<Vec<PluginPackageRecord>> {
        self.database
            .prepare(
                CATALOG_SQL,
                &[
                    BindValue::Text(cursor_package_id.unwrap_or_default()),
                    BindValue::Integer(limit.clamp(1, PLUGIN_PAGE_LIMIT_MAX)),
                ],
            )?
            .all()
            .await?
            .results::<PluginPackageRecord>()
    }

    pub async fn list_versions(
        &self,
        package_id: &str,
        limit: i32,
    ) -> worker::Result<Vec<PluginVersionRecord>> {
        self.database
            .prepare(
                VERSIONS_FOR_PACKAGE_SQL,
                &[
                    BindValue::Text(package_id),
                    BindValue::Integer(limit.clamp(1, PLUGIN_PAGE_LIMIT_MAX)),
                ],
            )?
            .all()
            .await?
            .results::<PluginVersionRecord>()
    }

    pub async fn find_version(
        &self,
        package_id: &str,
        version: &str,
    ) -> worker::Result<Option<PluginVersionRecord>> {
        self.database
            .prepare(
                VERSION_BY_PACKAGE_AND_VERSION_SQL,
                &[BindValue::Text(package_id), BindValue::Text(version)],
            )?
            .first::<PluginVersionRecord>(None)
            .await
    }

    // -- policy ------------------------------------------------------------

    pub async fn find_policy(&self, org_id: &str) -> worker::Result<Option<PluginPolicyRecord>> {
        self.database
            .prepare(POLICY_BY_ORG_SQL, &[BindValue::Text(org_id)])?
            .first::<PluginPolicyRecord>(None)
            .await
    }

    /// Packages on BOTH the allow and the block list.
    ///
    /// A dedicated read rather than a comparison in the handler, because the
    /// answer is also reported on every policy read: an org that has a conflict
    /// needs to be told, not silently corrected.
    pub async fn policy_conflicts(&self, org_id: &str) -> worker::Result<Vec<String>> {
        self.database
            .prepare(
                r#"
SELECT value AS package_id FROM (
    SELECT j.value AS value
    FROM plugin_policies p, json_each(p.allowed_packages_json) AS j
    WHERE p.org_id = ?1
      AND EXISTS (
          SELECT 1 FROM json_each(p.blocked_packages_json) AS b WHERE b.value = j.value
      )
)
ORDER BY package_id ASC
"#,
                &[BindValue::Text(org_id)],
            )?
            .all()
            .await?
            .results::<PolicyConflictRow>()
            .map(|rows| rows.into_iter().map(|row| row.package_id).collect())
    }

    pub fn insert_policy_statement(
        &self,
        input: &PluginPolicyInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_POLICY_SQL,
            &[
                BindValue::Text(input.org_id),
                BindValue::Text(input.publisher_mode),
                BindValue::Text(input.approved_publishers_json),
                BindValue::Text(input.allowed_packages_json),
                BindValue::Text(input.blocked_packages_json),
                BindValue::Text(input.pinned_versions_json),
                BindValue::Text(input.auto_update),
                BindValue::Text(input.update_mode),
                BindValue::Text(input.now),
            ],
        )
    }

    pub fn update_policy_statement(
        &self,
        input: &PluginPolicyUpdateInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_POLICY_SQL,
            &[
                BindValue::Text(input.org_id),
                BindValue::Text(input.publisher_mode),
                BindValue::Text(input.approved_publishers_json),
                BindValue::Text(input.allowed_packages_json),
                BindValue::Text(input.blocked_packages_json),
                BindValue::Text(input.pinned_versions_json),
                BindValue::Text(input.auto_update),
                BindValue::Text(input.update_mode),
                BindValue::Text(input.now),
                BindValue::Int64(input.expected_version),
            ],
        )
    }

    pub fn assert_policy_version_statement(
        &self,
        org_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_POLICY_VERSION_SQL,
            &[BindValue::Text(org_id), BindValue::Int64(expected_version)],
        )
    }

    // -- installs ----------------------------------------------------------

    pub async fn find_install(
        &self,
        org_id: &str,
        package_id: &str,
    ) -> worker::Result<Option<PluginInstallRecord>> {
        self.database
            .prepare(
                INSTALL_BY_ORG_AND_PACKAGE_SQL,
                &[BindValue::Text(org_id), BindValue::Text(package_id)],
            )?
            .first::<PluginInstallRecord>(None)
            .await
    }

    pub async fn list_installs(
        &self,
        org_id: &str,
        cursor_package_id: Option<&str>,
        limit: i32,
    ) -> worker::Result<Vec<PluginInstallRecord>> {
        self.database
            .prepare(
                INSTALLS_FOR_ORG_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(cursor_package_id.unwrap_or_default()),
                    BindValue::Integer(limit.clamp(1, PLUGIN_PAGE_LIMIT_MAX)),
                ],
            )?
            .all()
            .await?
            .results::<PluginInstallRecord>()
    }

    pub fn insert_install_statement(
        &self,
        input: &PluginInstallInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_INSTALL_SQL,
            &[
                BindValue::Text(input.install_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.package_id),
                BindValue::Text(input.version),
                input
                    .pending_review_version
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.review_state),
                input.review_reason.map_or(BindValue::Null, BindValue::Text),
                input.approved_by.map_or(BindValue::Null, BindValue::Text),
                input.approved_at.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.now),
            ],
        )
    }

    pub fn update_install_statement(
        &self,
        input: &PluginInstallUpdateInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_INSTALL_SQL,
            &[
                BindValue::Text(input.org_id),
                BindValue::Text(input.package_id),
                BindValue::Text(input.version),
                input
                    .pending_review_version
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.review_state),
                input.review_reason.map_or(BindValue::Null, BindValue::Text),
                input.approved_by.map_or(BindValue::Null, BindValue::Text),
                input.approved_at.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.now),
                BindValue::Int64(input.expected_counter),
            ],
        )
    }

    /// Move an install's review state, recording or clearing a block reason.
    pub fn set_install_block_statement(
        &self,
        org_id: &str,
        package_id: &str,
        review_state: PluginReviewState,
        blocked_reason: Option<&str>,
        expected_counter: i64,
        now: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            SET_INSTALL_BLOCK_SQL,
            &[
                BindValue::Text(org_id),
                BindValue::Text(package_id),
                BindValue::Text(review_state.as_str()),
                blocked_reason.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(now),
                BindValue::Int64(expected_counter),
            ],
        )
    }

    // -- quarantine --------------------------------------------------------

    /// The platform decision, read rather than cached. A lifted row stops
    /// matching, so lifting takes effect on the next request.
    pub async fn is_quarantined(&self, package_id: &str, version: &str) -> worker::Result<bool> {
        self.database
            .prepare(
                QUARANTINE_ACTIVE_FOR_SQL,
                &[BindValue::Text(package_id), BindValue::Text(version)],
            )?
            .first::<CountRow>(None)
            .await
            .map(|row| row.is_some_and(|row| row.total > 0))
    }

    pub async fn list_quarantines(
        &self,
        cursor_engaged_at: Option<&str>,
        cursor_id: Option<&str>,
        limit: i32,
    ) -> worker::Result<Vec<PluginQuarantineRecord>> {
        self.database
            .prepare(
                QUARANTINES_PAGE_SQL,
                &[
                    BindValue::Text(cursor_engaged_at.unwrap_or_default()),
                    BindValue::Text(cursor_id.unwrap_or_default()),
                    BindValue::Integer(limit.clamp(1, PLUGIN_PAGE_LIMIT_MAX)),
                ],
            )?
            .all()
            .await?
            .results::<PluginQuarantineRecord>()
    }

    pub fn insert_quarantine_statement(
        &self,
        quarantine_id: &str,
        package_id: &str,
        version: &str,
        reason: &str,
        engaged_by: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_QUARANTINE_SQL,
            &[
                BindValue::Text(quarantine_id),
                BindValue::Text(package_id),
                BindValue::Text(version),
                BindValue::Text(reason),
                BindValue::Text(engaged_by),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    /// Lifting requires a reason, which the 0017 trigger refuses to do without.
    pub fn lift_quarantine_statement(
        &self,
        quarantine_id: &str,
        lifted_by: &str,
        lift_reason: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            LIFT_QUARANTINE_SQL,
            &[
                BindValue::Text(quarantine_id),
                BindValue::Text(now.as_str()),
                BindValue::Text(lifted_by),
                BindValue::Text(lift_reason),
            ],
        )
    }

    // -- tool registrations (F25-007 / F13 default deny) -------------------

    pub async fn registered_tools(
        &self,
        org_id: &str,
        package_id: &str,
        version: &str,
    ) -> worker::Result<Vec<PluginToolRegistrationRecord>> {
        self.database
            .prepare(
                REGISTERED_TOOLS_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(package_id),
                    BindValue::Text(version),
                ],
            )?
            .all()
            .await?
            .results::<PluginToolRegistrationRecord>()
    }

    /// Declared tools with no registration. Their presence IS the default-deny:
    /// a tool is usable only when a row exists, so this list is exactly the set of
    /// tools the org may not use.
    pub async fn unregistered_tools(
        &self,
        org_id: &str,
        package_id: &str,
        version: &str,
    ) -> worker::Result<Vec<String>> {
        self.database
            .prepare(
                UNREGISTERED_TOOLS_SQL,
                &[
                    BindValue::Text(package_id),
                    BindValue::Text(version),
                    BindValue::Text(org_id),
                ],
            )?
            .all()
            .await?
            .results::<ToolIdRow>()
            .map(|rows| rows.into_iter().map(|row| row.tool_id).collect())
    }

    pub fn insert_registration_statement(
        &self,
        input: &NewToolRegistrationInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_REGISTRATION_SQL,
            &[
                BindValue::Text(input.registration_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.package_id),
                BindValue::Text(input.version),
                BindValue::Text(input.tool_id),
                BindValue::Text(input.approved_by),
                BindValue::Text(input.now),
            ],
        )
    }

    // -- P07-INT-01 report -------------------------------------------------

    /// P07-INT-01. The host agent reports what it actually has installed, and the
    /// server records it as `unreviewed` — never as approved.
    ///
    /// The insert is conditional on the install not existing, so a repeated report
    /// for a package the org already has does not create a SECOND review state.
    /// That is what the 0017 UNIQUE `(org_id, package_id)` index is for, and this
    /// statement honours it by construction rather than by catching the violation.
    pub fn record_report_statement(
        &self,
        input: &NewPluginReportInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            RECORD_REPORT_SQL,
            &[
                BindValue::Text(input.install_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.package_id),
                BindValue::Text(input.version),
                BindValue::Text(input.reason),
                BindValue::Text(input.now),
            ],
        )
    }

    /// For an org that already has the package, the report downgrades the install
    /// to `unreviewed`. A host reporting a version nobody approved is exactly the
    /// situation F13's default-deny exists for, so the recorded state reflects the
    /// report rather than the org's earlier decision.
    pub fn touch_report_statement(
        &self,
        org_id: &str,
        package_id: &str,
        now: &Timestamp,
        reason: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            TOUCH_REPORT_SQL,
            &[
                BindValue::Text(org_id),
                BindValue::Text(package_id),
                BindValue::Text(now.as_str()),
                BindValue::Text(reason),
            ],
        )
    }
}

fn string_list(raw: &str) -> Vec<String> {
    crate::modules::machine_identity::string_list(Some(raw))
        .ok()
        .flatten()
        .unwrap_or_default()
}

fn pinned_map(raw: &str) -> std::collections::BTreeMap<String, String> {
    serde_json::from_str(raw).unwrap_or_default()
}

/// The conflicts an org's policy currently has, computed from the domain value.
pub fn policy_conflict_ids(policy: &PluginPolicy) -> Vec<String> {
    policy_conflicts(policy)
        .into_iter()
        .map(|conflict| conflict.package_id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::plugins::PluginPolicy;

    /// F25-008's acceptance criterion, pinned at the query: the predicate is the
    /// exact `(package_id, version)` pair with `lifted_at IS NULL`, so a lifted
    /// quarantine stops applying and a different version is unaffected.
    #[test]
    fn the_quarantine_read_is_exact_version_and_ignores_a_lifted_row() {
        assert!(QUARANTINE_ACTIVE_FOR_SQL.contains("package_id = ?1"));
        assert!(QUARANTINE_ACTIVE_FOR_SQL.contains("version = ?2"));
        assert!(QUARANTINE_ACTIVE_FOR_SQL.contains("lifted_at IS NULL"));
    }

    /// F25-003. A managed-mode expansion is a REFUSAL that records why, so the row
    /// is written in `pending_review` with a reason rather than left absent.
    #[test]
    fn a_pending_review_install_records_its_reason_in_the_same_write() {
        assert!(INSERT_INSTALL_SQL.contains("pending_review_version"));
        assert!(INSERT_INSTALL_SQL.contains("review_reason"));
        assert!(UPDATE_INSTALL_SQL.contains("pending_review_version"));
        assert!(UPDATE_INSTALL_SQL.contains("review_reason"));
    }

    /// The review state and the installed version move together, and the update
    /// binds the expected counter. Without that, a concurrent approve could be lost
    /// into a row that had since been blocked.
    #[test]
    fn an_install_update_binds_the_expected_counter() {
        assert!(UPDATE_INSTALL_SQL.contains("version_counter = ?10"));
        assert!(UPDATE_INSTALL_SQL.contains("version_counter = version_counter + 1"));
    }

    /// F25-007 + F13. Default-deny is the ABSENCE of a registration, so the
    /// "what may I not use" list is a query rather than a comparison the caller
    /// has to remember to invert.
    #[test]
    fn default_deny_is_the_absence_of_a_registration_row() {
        assert!(UNREGISTERED_TOOLS_SQL.contains("NOT EXISTS"));
        assert!(UNREGISTERED_TOOLS_SQL.contains("plugin_tool_registrations"));
        assert!(UNREGISTERED_TOOLS_SQL.contains("r.tool_id = tool.value"));
        assert!(UNREGISTERED_TOOLS_SQL.contains("r.org_id = ?3"));
    }

    /// The organization is a predicate on every tenant read, so a cross-tenant
    /// identifier returns nothing and cannot be an existence oracle.
    #[test]
    fn every_tenant_read_binds_the_organization() {
        for sql in [
            INSTALL_BY_ORG_AND_PACKAGE_SQL,
            INSTALLS_FOR_ORG_SQL,
            POLICY_BY_ORG_SQL,
            REGISTERED_TOOLS_SQL,
        ] {
            assert!(sql.contains("org_id = ?1"), "{sql} must bind the org");
        }
    }

    /// P07-INT-01. A repeated report must not create a second review state, which
    /// is exactly what the 0017 UNIQUE index forbids — so the statement honours it
    /// by construction.
    #[test]
    fn a_repeated_report_never_creates_a_second_install_row() {
        assert!(RECORD_REPORT_SQL.contains("WHERE NOT EXISTS"));
        assert!(
            RECORD_REPORT_SQL
                .contains("FROM plugin_installs WHERE org_id = ?2 AND package_id = ?3")
        );
        // The report is recorded as `unreviewed`, never approved: the report is
        // evidence, never authority.
        assert!(RECORD_REPORT_SQL.contains("'unreviewed'"));
        assert!(!RECORD_REPORT_SQL.contains("'approved'"));
        assert!(TOUCH_REPORT_SQL.contains("'unreviewed'"));
    }

    /// A store whose enum has drifted must NARROW, not widen. The default policy
    /// is official-publishers-only with managed updates and no auto-update.
    #[test]
    fn an_unrecognised_stored_enum_narrows_rather_than_widens() {
        let record = PluginPolicyRecord {
            org_id: "org_0123456789abcdef0123456789abcdef".into(),
            publisher_mode: "nonsense".into(),
            approved_publishers_json: "[]".into(),
            allowed_packages_json: "[]".into(),
            blocked_packages_json: "[]".into(),
            pinned_versions_json: "{}".into(),
            auto_update: "nonsense".into(),
            update_mode: "nonsense".into(),
            version: 1,
            created_at: "2026-09-26T12:00:00.000Z".into(),
            updated_at: "2026-09-26T12:00:00.000Z".into(),
        };
        let policy = record.to_domain();
        assert_eq!(policy.publisher_mode, PublisherMode::OfficialOnly);
        assert!(!policy.auto_update, "auto-update must not default to on");
        assert_eq!(policy.update_mode, UpdateMode::Managed);
    }

    #[test]
    fn policy_conflicts_are_computed_from_the_domain_value() {
        let policy = PluginPolicy {
            allowed_packages: vec!["pkg_1".into(), "pkg_2".into()],
            blocked_packages: vec!["pkg_1".into()],
            ..PluginPolicy::default()
        };
        assert_eq!(policy_conflict_ids(&policy), vec!["pkg_1".to_owned()]);
    }
}
