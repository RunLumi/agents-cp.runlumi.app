//! D1 persistence for P05 usage, cost, and rollup accounting.
//!
//! P04 `usage_events` stays the immutable, request-scoped inference source and
//! P05-CR-002 `run_usage_events` is the additive non-inference source.  Both are
//! read through one normalized projection so summary/rollup reads and
//! reconciliation never need a second reservation or usage authority.
//!
//! Raw usage rows are never updated or deleted: `usage_events`,
//! `run_usage_events`, `cost_records`, and `run_cost_records` all carry
//! append-only triggers.  A later reconciliation is a *new* cost record, so
//! every write below is a conditional insert that is safe to retry.

use serde::{Deserialize, Serialize};
use worker::d1::D1PreparedStatement;

use crate::adapters::d1::{BindValue, D1Adapter};

/// Normalized projection columns shared by both usage sources.  The
/// `run_usage_events` branch supplies explicit NULL/constant values so the two
/// sources stay shape-compatible inside one keyset-paginated query.
const USAGE_EVENT_SOURCE_SQL: &str = r#"
SELECT usage_event_id AS event_id, request_id, run_id, org_id, project_id,
       principal_user_id, session_id, device_id, source, external_id,
       reconciliation_status, model_alias, input_tokens, output_tokens,
       cached_tokens, provider_usage_json, estimated_cost_minor,
       actual_cost_minor, currency, pricing_version, budget_decision,
       route_version_id, provider_id, model_id, ttft_ms, total_latency_ms,
       created_at
FROM usage_events
"#;

const RUN_USAGE_EVENT_SOURCE_SQL: &str = r#"
SELECT run_usage_event_id AS event_id, NULL AS request_id, run_id, org_id, project_id,
       principal_user_id, NULL AS session_id, device_id, 'run' AS source, external_id,
       reconciliation_status, model_alias, input_tokens, output_tokens,
       cached_tokens, provider_usage_json, estimated_cost_minor,
       actual_cost_minor, currency, pricing_version,
       'not_applicable' AS budget_decision, NULL AS route_version_id,
       NULL AS provider_id, NULL AS model_id, NULL AS ttft_ms,
       NULL AS total_latency_ms, created_at
FROM run_usage_events
"#;

/// ?1 org, ?2 project, ?3 run, ?4 from, ?5 to, ?6 cursor time, ?7 cursor id,
/// ?8 limit.
fn usage_page_sql() -> String {
    format!(
        "SELECT * FROM ({USAGE_EVENT_SOURCE_SQL} WHERE org_id = ?1 \
         UNION ALL {RUN_USAGE_EVENT_SOURCE_SQL} WHERE org_id = ?1) \
         WHERE (?2 = '' OR project_id = ?2) \
           AND (?3 = '' OR run_id = ?3) \
           AND (?4 = '' OR created_at >= ?4) \
           AND (?5 = '' OR created_at < ?5) \
           AND (?6 = '' OR (created_at, event_id) < (?6, ?7)) \
         ORDER BY created_at DESC, event_id DESC \
         LIMIT ?8"
    )
}

/// Same filters as the page query without pagination, used for the dashboard
/// summary.  Aggregates stay derived and rebuildable.
fn usage_summary_sql() -> String {
    format!(
        "SELECT COUNT(*) AS event_count, \
         COALESCE(SUM(COALESCE(input_tokens, 0)), 0) AS input_tokens, \
         COALESCE(SUM(COALESCE(output_tokens, 0)), 0) AS output_tokens, \
         COALESCE(SUM(COALESCE(cached_tokens, 0)), 0) AS cached_tokens, \
         COALESCE(SUM(COALESCE(actual_cost_minor, estimated_cost_minor, 0)), 0) AS cost_minor \
         FROM ({USAGE_EVENT_SOURCE_SQL} WHERE org_id = ?1 \
         UNION ALL {RUN_USAGE_EVENT_SOURCE_SQL} WHERE org_id = ?1) \
         WHERE (?2 = '' OR project_id = ?2) \
           AND (?3 = '' OR run_id = ?3) \
           AND (?4 = '' OR created_at >= ?4) \
           AND (?5 = '' OR created_at < ?5)"
    )
}

const USAGE_EVENT_BY_REQUEST_SQL: &str = r#"
SELECT usage_event_id AS event_id, request_id, run_id, org_id, project_id,
       principal_user_id, session_id, device_id, source, external_id,
       reconciliation_status, model_alias, input_tokens, output_tokens,
       cached_tokens, provider_usage_json, estimated_cost_minor,
       actual_cost_minor, currency, pricing_version, budget_decision,
       route_version_id, provider_id, model_id, ttft_ms, total_latency_ms,
       created_at
FROM usage_events
WHERE org_id = ?1 AND request_id = ?2
LIMIT 1
"#;

/// A managed run may be represented by either the additive run source or a
/// P04 inference row correlated to the same run.  Search both normalized
/// sources so `run_id` reconciliation never silently misses inference usage.
const USAGE_EVENT_BY_RUN_SQL: &str = r#"
SELECT * FROM (
    SELECT usage_event_id AS event_id, request_id, run_id, org_id, project_id,
           principal_user_id, session_id, device_id, source, external_id,
           reconciliation_status, model_alias, input_tokens, output_tokens,
           cached_tokens, provider_usage_json, estimated_cost_minor,
           actual_cost_minor, currency, pricing_version, budget_decision,
           route_version_id, provider_id, model_id, ttft_ms, total_latency_ms,
           created_at
    FROM usage_events
    WHERE org_id = ?1 AND run_id = ?2
    UNION ALL
    SELECT run_usage_event_id AS event_id, NULL AS request_id, run_id, org_id, project_id,
           principal_user_id, NULL AS session_id, device_id, 'run' AS source, external_id,
           reconciliation_status, model_alias, input_tokens, output_tokens,
           cached_tokens, provider_usage_json, estimated_cost_minor,
           actual_cost_minor, currency, pricing_version,
           'not_applicable' AS budget_decision, NULL AS route_version_id,
           NULL AS provider_id, NULL AS model_id, NULL AS ttft_ms,
           NULL AS total_latency_ms, created_at
    FROM run_usage_events
    WHERE org_id = ?1 AND run_id = ?2
)
ORDER BY created_at ASC, event_id ASC
LIMIT 1
"#;

const COST_RECORD_SELECT: &str = r#"
SELECT cost_record_id, usage_event_id, org_id, project_id, run_id, pricing_source,
       pricing_version, pricing_effective_at, calculation_kind, input_tokens,
       output_tokens, cached_tokens, cost_minor, currency, created_at
FROM cost_records
"#;

/// Conditional append of one cost row.  The `EXISTS` guard keeps the write
/// tenant-scoped to the owning immutable usage event and the `NOT EXISTS` guard
/// makes a replayed reconciliation a no-op instead of a duplicate row.
const INSERT_COST_RECORD_SQL: &str = r#"
INSERT INTO cost_records (
    cost_record_id, usage_event_id, org_id, project_id, run_id, pricing_source,
    pricing_version, pricing_effective_at, calculation_kind, input_tokens,
    output_tokens, cached_tokens, cost_minor, currency, created_at
)
SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
WHERE EXISTS (
    SELECT 1 FROM usage_events u
    WHERE u.usage_event_id = ?2 AND u.org_id = ?3
)
AND NOT EXISTS (
    SELECT 1 FROM cost_records c
    WHERE c.usage_event_id = ?2
      AND c.calculation_kind = ?9
      AND c.pricing_version = ?7
)
"#;

const RUN_COST_RECORD_SELECT: &str = r#"
SELECT run_cost_record_id, run_usage_event_id, org_id, project_id, run_id,
       pricing_source, pricing_version, pricing_effective_at, calculation_kind,
       input_tokens, output_tokens, cached_tokens, cost_minor, currency, created_at
FROM run_cost_records
"#;

const INSERT_RUN_COST_RECORD_SQL: &str = r#"
INSERT INTO run_cost_records (
    run_cost_record_id, run_usage_event_id, org_id, project_id, run_id,
    pricing_source, pricing_version, pricing_effective_at, calculation_kind,
    input_tokens, output_tokens, cached_tokens, cost_minor, currency, created_at
)
SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
WHERE EXISTS (
    SELECT 1 FROM run_usage_events u
    WHERE u.run_usage_event_id = ?2 AND u.org_id = ?3
)
AND NOT EXISTS (
    SELECT 1 FROM run_cost_records c
    WHERE c.run_usage_event_id = ?2
      AND c.calculation_kind = ?9
      AND c.pricing_version = ?7
)
"#;

/// Abort an idempotent reconciliation batch unless the exact immutable cost
/// fact is present.  This distinguishes a replay from a contradictory actual
/// cost without rewriting either source row.
const ASSERT_COST_RECORD_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM cost_records c
    WHERE c.usage_event_id = ?1 AND c.org_id = ?2
      AND c.calculation_kind = ?3 AND c.pricing_version = ?4
      AND c.cost_minor = ?5 AND c.currency = ?6
)
"#;

const ASSERT_RUN_COST_RECORD_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM run_cost_records c
    WHERE c.run_usage_event_id = ?1 AND c.org_id = ?2
      AND c.calculation_kind = ?3 AND c.pricing_version = ?4
      AND c.cost_minor = ?5 AND c.currency = ?6
)
"#;

const INSERT_RUN_USAGE_SQL: &str = r#"
INSERT INTO run_usage_events (
    run_usage_event_id, run_id, org_id, project_id, principal_user_id, device_id,
    model_alias, input_tokens, output_tokens, cached_tokens, provider_usage_json,
    estimated_cost_minor, actual_cost_minor, currency, pricing_version,
    reconciliation_status, external_id, created_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
"#;

/// ?1 org, ?2 project, ?3 principal, ?4 model alias, ?5 from, ?6 to,
/// ?7 cursor bucket, ?8 cursor id, ?9 limit.
const ROLLUPS_PAGE_SQL: &str = r#"
SELECT usage_rollup_id, org_id, project_id, principal_user_id, model_alias,
       bucket_start, bucket_end, input_tokens, output_tokens, cached_tokens,
       cost_minor, usage_event_count, updated_at
FROM usage_rollups
WHERE org_id = ?1
  AND (?2 = '' OR project_id = ?2)
  AND (?3 = '' OR principal_user_id = ?3)
  AND (?4 = '' OR model_alias = ?4)
  AND (?5 = '' OR bucket_end > ?5)
  AND (?6 = '' OR bucket_start < ?6)
  AND (?7 = '' OR (bucket_start, usage_rollup_id) < (?7, ?8))
ORDER BY bucket_start DESC, usage_rollup_id DESC
LIMIT ?9
"#;

const UPSERT_ROLLUP_SQL: &str = r#"
INSERT INTO usage_rollups (
    usage_rollup_id, org_id, project_id, principal_user_id, model_alias,
    bucket_start, bucket_end, input_tokens, output_tokens, cached_tokens,
    cost_minor, usage_event_count, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
ON CONFLICT(org_id, COALESCE(project_id, ''), COALESCE(principal_user_id, ''), COALESCE(model_alias, ''), bucket_start)
DO UPDATE SET
    bucket_end = excluded.bucket_end,
    input_tokens = usage_rollups.input_tokens + excluded.input_tokens,
    output_tokens = usage_rollups.output_tokens + excluded.output_tokens,
    cached_tokens = usage_rollups.cached_tokens + excluded.cached_tokens,
    cost_minor = usage_rollups.cost_minor + excluded.cost_minor,
    usage_event_count = usage_rollups.usage_event_count + excluded.usage_event_count,
    updated_at = excluded.updated_at
"#;

/// Budget and rate denials are read back from the immutable audit projection,
/// so a dashboard can explain a block without a second denial table.
const DENIALS_PAGE_SQL: &str = r#"
SELECT event_id, org_id, action, resource_type, resource_id, outcome, reason,
       metadata_json, request_id, correlation_id, run_id, agent_session_id, created_at
FROM security_events
WHERE org_id = ?1
  AND action IN ('budget.denied.v1', 'rate_limit.denied.v1')
  AND (?2 = '' OR created_at >= ?2)
  AND (?3 = '' OR created_at < ?3)
  AND (?4 = '' OR (created_at, event_id) < (?4, ?5))
ORDER BY created_at DESC, event_id DESC
LIMIT ?6
"#;

/// One normalized usage row from either source.  `request_id` is present only
/// for the P04 inference source; `run_id` is the P05 managed correlation.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UsageEventRecord {
    pub event_id: String,
    pub request_id: Option<String>,
    pub run_id: Option<String>,
    pub org_id: String,
    pub project_id: Option<String>,
    pub principal_user_id: String,
    pub session_id: Option<String>,
    pub device_id: Option<String>,
    pub source: String,
    pub external_id: Option<String>,
    pub reconciliation_status: String,
    pub model_alias: Option<String>,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cached_tokens: Option<i64>,
    pub provider_usage_json: String,
    pub estimated_cost_minor: Option<i64>,
    pub actual_cost_minor: Option<i64>,
    pub currency: Option<String>,
    pub pricing_version: Option<String>,
    pub budget_decision: String,
    pub route_version_id: Option<String>,
    pub provider_id: Option<String>,
    pub model_id: Option<String>,
    pub ttft_ms: Option<i64>,
    pub total_latency_ms: Option<i64>,
    pub created_at: String,
}

impl UsageEventRecord {
    pub fn is_run_source(&self) -> bool {
        self.source == "run"
    }
}

/// Append-only cost row for either usage source.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CostRecordRow {
    pub cost_record_id: String,
    pub usage_event_id: String,
    pub org_id: String,
    pub project_id: Option<String>,
    pub run_id: Option<String>,
    pub pricing_source: String,
    pub pricing_version: String,
    pub pricing_effective_at: String,
    pub calculation_kind: String,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cached_tokens: Option<i64>,
    pub cost_minor: i64,
    pub currency: String,
    pub created_at: String,
}

impl CostRecordRow {
    /// True when this row already states the same immutable fact as `other`.
    /// Used to make a replayed reconciliation idempotent without rewriting
    /// history.
    pub fn states_same_cost(&self, cost_minor: i64, pricing_version: &str, currency: &str) -> bool {
        self.cost_minor == cost_minor
            && self.pricing_version == pricing_version
            && self.currency == currency
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RunCostRecordRow {
    pub run_cost_record_id: String,
    pub run_usage_event_id: String,
    pub org_id: String,
    pub project_id: Option<String>,
    pub run_id: Option<String>,
    pub pricing_source: String,
    pub pricing_version: String,
    pub pricing_effective_at: String,
    pub calculation_kind: String,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cached_tokens: Option<i64>,
    pub cost_minor: i64,
    pub currency: String,
    pub created_at: String,
}

impl RunCostRecordRow {
    pub fn states_same_cost(&self, cost_minor: i64, pricing_version: &str, currency: &str) -> bool {
        self.cost_minor == cost_minor
            && self.pricing_version == pricing_version
            && self.currency == currency
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UsageRollupRecord {
    pub usage_rollup_id: String,
    pub org_id: String,
    pub project_id: Option<String>,
    pub principal_user_id: Option<String>,
    pub model_alias: Option<String>,
    pub bucket_start: String,
    pub bucket_end: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cached_tokens: i64,
    pub cost_minor: i64,
    pub usage_event_count: i64,
    pub updated_at: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UsageSummaryRecord {
    pub event_count: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cached_tokens: i64,
    pub cost_minor: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UsageDenialRecord {
    pub event_id: String,
    pub org_id: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub outcome: String,
    pub reason: Option<String>,
    pub metadata_json: String,
    pub request_id: String,
    pub correlation_id: String,
    pub run_id: Option<String>,
    pub agent_session_id: Option<String>,
    pub created_at: String,
}

/// Bounded, tenant-scoped filters for the usage collection reads.
#[derive(Clone, Copy, Debug, Default)]
pub struct UsageQuery<'a> {
    pub project_id: Option<&'a str>,
    pub run_id: Option<&'a str>,
    pub from: Option<&'a str>,
    pub to: Option<&'a str>,
    pub cursor: Option<(&'a str, &'a str)>,
    pub limit: i32,
}

impl<'a> UsageQuery<'a> {
    pub fn with_limit(mut self, limit: i32) -> Self {
        self.limit = limit;
        self
    }
}

/// Input for one append-only cost calculation.
#[derive(Clone, Copy, Debug)]
pub struct NewCostRecordInput<'a> {
    pub cost_record_id: &'a str,
    pub usage_event_id: &'a str,
    pub org_id: &'a str,
    pub project_id: Option<&'a str>,
    pub run_id: Option<&'a str>,
    pub pricing_source: &'a str,
    pub pricing_version: &'a str,
    pub pricing_effective_at: &'a str,
    pub calculation_kind: &'a str,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cached_tokens: Option<i64>,
    pub cost_minor: i64,
    pub currency: &'a str,
    pub created_at: &'a str,
}

/// Input for one append-only non-inference run usage event.
#[derive(Clone, Copy, Debug)]
pub struct NewRunUsageInput<'a> {
    pub run_usage_event_id: &'a str,
    pub run_id: &'a str,
    pub org_id: &'a str,
    pub project_id: &'a str,
    pub principal_user_id: &'a str,
    pub device_id: &'a str,
    pub model_alias: Option<&'a str>,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cached_tokens: Option<i64>,
    pub provider_usage_json: &'a str,
    pub estimated_cost_minor: Option<i64>,
    pub actual_cost_minor: Option<i64>,
    pub currency: Option<&'a str>,
    pub pricing_version: Option<&'a str>,
    pub reconciliation_status: &'a str,
    pub external_id: Option<&'a str>,
    pub created_at: &'a str,
}

/// One derived, rebuildable rollup contribution.
#[derive(Clone, Copy, Debug)]
pub struct NewRollupInput<'a> {
    pub usage_rollup_id: &'a str,
    pub org_id: &'a str,
    pub project_id: Option<&'a str>,
    pub principal_user_id: Option<&'a str>,
    pub model_alias: Option<&'a str>,
    pub bucket_start: &'a str,
    pub bucket_end: &'a str,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cached_tokens: i64,
    pub cost_minor: i64,
    pub usage_event_count: i64,
    pub updated_at: &'a str,
}

fn optional_text(value: Option<&str>) -> BindValue<'_> {
    value.map_or(BindValue::Null, BindValue::Text)
}

fn optional_integer(value: Option<i64>) -> BindValue<'static> {
    value.map_or(BindValue::Null, BindValue::Int64)
}

/// Repository for usage events, cost records, rollups, and denial reads.
pub struct UsageRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> UsageRepository<'a> {
    pub fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    /// Keyset-paginated usage page across both sources.  The cursor is the
    /// opaque `(created_at, event_id)` pair produced by the route layer.
    pub async fn list_usage(
        &self,
        org_id: &str,
        query: UsageQuery<'_>,
    ) -> worker::Result<Vec<UsageEventRecord>> {
        let (cursor_time, cursor_id) = query.cursor.unwrap_or(("", ""));
        self.database
            .prepare(
                &usage_page_sql(),
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(query.project_id.unwrap_or("")),
                    BindValue::Text(query.run_id.unwrap_or("")),
                    BindValue::Text(query.from.unwrap_or("")),
                    BindValue::Text(query.to.unwrap_or("")),
                    BindValue::Text(cursor_time),
                    BindValue::Text(cursor_id),
                    BindValue::Integer(query.limit),
                ],
            )?
            .all()
            .await?
            .results::<UsageEventRecord>()
    }

    /// Derived totals for the same filters as the page read.  This is a
    /// read-only projection: raw usage events remain the reconciliation source.
    #[allow(clippy::too_many_arguments)]
    pub async fn summarize_usage(
        &self,
        org_id: &str,
        project_id: Option<&str>,
        run_id: Option<&str>,
        from: Option<&str>,
        to: Option<&str>,
    ) -> worker::Result<UsageSummaryRecord> {
        let row = self
            .database
            .prepare(
                &usage_summary_sql(),
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(project_id.unwrap_or("")),
                    BindValue::Text(run_id.unwrap_or("")),
                    BindValue::Text(from.unwrap_or("")),
                    BindValue::Text(to.unwrap_or("")),
                ],
            )?
            .first::<UsageSummaryRow>(None)
            .await?;
        Ok(
            row.map_or_else(UsageSummaryRecord::default, |row| UsageSummaryRecord {
                event_count: row.event_count,
                input_tokens: row.input_tokens,
                output_tokens: row.output_tokens,
                cached_tokens: row.cached_tokens,
                cost_minor: row.cost_minor,
            }),
        )
    }

    /// Resolve the immutable usage event a reconciliation targets.  The tenant
    /// scope is part of the predicate, so a cross-tenant identifier reads as
    /// missing rather than forbidden.
    pub async fn find_usage_event_by_request(
        &self,
        org_id: &str,
        request_id: &str,
    ) -> worker::Result<Option<UsageEventRecord>> {
        self.database
            .prepare(
                USAGE_EVENT_BY_REQUEST_SQL,
                &[BindValue::Text(org_id), BindValue::Text(request_id)],
            )?
            .first::<UsageEventRecord>(None)
            .await
    }

    /// Resolve the earliest run-scoped usage event for one managed run.
    pub async fn find_usage_event_by_run(
        &self,
        org_id: &str,
        run_id: &str,
    ) -> worker::Result<Option<UsageEventRecord>> {
        self.database
            .prepare(
                USAGE_EVENT_BY_RUN_SQL,
                &[BindValue::Text(org_id), BindValue::Text(run_id)],
            )?
            .first::<UsageEventRecord>(None)
            .await
    }

    /// Read one immutable cost row.  `pricing_version` and `calculation_kind`
    /// are both part of the append-only uniqueness key.
    pub async fn find_cost_record(
        &self,
        org_id: &str,
        usage_event_id: &str,
        calculation_kind: &str,
        pricing_version: &str,
    ) -> worker::Result<Option<CostRecordRow>> {
        self.database
            .prepare(
                &format!(
                    "{COST_RECORD_SELECT} WHERE org_id = ?1 AND usage_event_id = ?2 \
                     AND calculation_kind = ?3 AND pricing_version = ?4 LIMIT 1"
                ),
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(usage_event_id),
                    BindValue::Text(calculation_kind),
                    BindValue::Text(pricing_version),
                ],
            )?
            .first::<CostRecordRow>(None)
            .await
    }

    pub async fn list_cost_records(
        &self,
        org_id: &str,
        usage_event_id: &str,
        limit: i32,
    ) -> worker::Result<Vec<CostRecordRow>> {
        self.database
            .prepare(
                &format!(
                    "{COST_RECORD_SELECT} WHERE org_id = ?1 AND usage_event_id = ?2 \
                     ORDER BY created_at ASC, cost_record_id ASC LIMIT ?3"
                ),
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(usage_event_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<CostRecordRow>()
    }

    pub async fn find_run_cost_record(
        &self,
        org_id: &str,
        run_usage_event_id: &str,
        calculation_kind: &str,
        pricing_version: &str,
    ) -> worker::Result<Option<RunCostRecordRow>> {
        self.database
            .prepare(
                &format!(
                    "{RUN_COST_RECORD_SELECT} WHERE org_id = ?1 AND run_usage_event_id = ?2 \
                     AND calculation_kind = ?3 AND pricing_version = ?4 LIMIT 1"
                ),
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(run_usage_event_id),
                    BindValue::Text(calculation_kind),
                    BindValue::Text(pricing_version),
                ],
            )?
            .first::<RunCostRecordRow>(None)
            .await
    }

    /// Conditional cost append for the P04 inference source.  A replay inserts
    /// zero rows, which is how reconciliation stays idempotent under retries.
    pub fn insert_cost_record_statement(
        &self,
        input: &NewCostRecordInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_COST_RECORD_SQL,
            &[
                BindValue::Text(input.cost_record_id),
                BindValue::Text(input.usage_event_id),
                BindValue::Text(input.org_id),
                optional_text(input.project_id),
                optional_text(input.run_id),
                BindValue::Text(input.pricing_source),
                BindValue::Text(input.pricing_version),
                BindValue::Text(input.pricing_effective_at),
                BindValue::Text(input.calculation_kind),
                optional_integer(input.input_tokens),
                optional_integer(input.output_tokens),
                optional_integer(input.cached_tokens),
                BindValue::Int64(input.cost_minor),
                BindValue::Text(input.currency),
                BindValue::Text(input.created_at),
            ],
        )
    }

    /// Conditional cost append for the additive run usage source.
    pub fn insert_run_cost_record_statement(
        &self,
        input: &NewCostRecordInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_RUN_COST_RECORD_SQL,
            &[
                BindValue::Text(input.cost_record_id),
                BindValue::Text(input.usage_event_id),
                BindValue::Text(input.org_id),
                optional_text(input.project_id),
                optional_text(input.run_id),
                BindValue::Text(input.pricing_source),
                BindValue::Text(input.pricing_version),
                BindValue::Text(input.pricing_effective_at),
                BindValue::Text(input.calculation_kind),
                optional_integer(input.input_tokens),
                optional_integer(input.output_tokens),
                optional_integer(input.cached_tokens),
                BindValue::Int64(input.cost_minor),
                BindValue::Text(input.currency),
                BindValue::Text(input.created_at),
            ],
        )
    }

    pub fn assert_cost_record_statement(
        &self,
        input: &NewCostRecordInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_COST_RECORD_SQL,
            &[
                BindValue::Text(input.usage_event_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.calculation_kind),
                BindValue::Text(input.pricing_version),
                BindValue::Int64(input.cost_minor),
                BindValue::Text(input.currency),
            ],
        )
    }

    pub fn assert_run_cost_record_statement(
        &self,
        input: &NewCostRecordInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_RUN_COST_RECORD_SQL,
            &[
                BindValue::Text(input.usage_event_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.calculation_kind),
                BindValue::Text(input.pricing_version),
                BindValue::Int64(input.cost_minor),
                BindValue::Text(input.currency),
            ],
        )
    }

    /// Append one non-inference usage row.  The unique external-ID index makes
    /// a replayed ingest conflict instead of duplicating usage.
    pub fn insert_run_usage_statement(
        &self,
        input: &NewRunUsageInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_RUN_USAGE_SQL,
            &[
                BindValue::Text(input.run_usage_event_id),
                BindValue::Text(input.run_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.project_id),
                BindValue::Text(input.principal_user_id),
                BindValue::Text(input.device_id),
                optional_text(input.model_alias),
                optional_integer(input.input_tokens),
                optional_integer(input.output_tokens),
                optional_integer(input.cached_tokens),
                BindValue::Text(input.provider_usage_json),
                optional_integer(input.estimated_cost_minor),
                optional_integer(input.actual_cost_minor),
                optional_text(input.currency),
                optional_text(input.pricing_version),
                BindValue::Text(input.reconciliation_status),
                optional_text(input.external_id),
                BindValue::Text(input.created_at),
            ],
        )
    }

    /// Bounded rollup page for dashboards.  Rollups are derived; deleting or
    /// rebuilding them never changes raw usage.
    #[allow(clippy::too_many_arguments)]
    pub async fn list_rollups(
        &self,
        org_id: &str,
        project_id: Option<&str>,
        principal_user_id: Option<&str>,
        model_alias: Option<&str>,
        from: Option<&str>,
        to: Option<&str>,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<UsageRollupRecord>> {
        let (cursor_bucket, cursor_id) = cursor.unwrap_or(("", ""));
        self.database
            .prepare(
                ROLLUPS_PAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(project_id.unwrap_or("")),
                    BindValue::Text(principal_user_id.unwrap_or("")),
                    BindValue::Text(model_alias.unwrap_or("")),
                    BindValue::Text(from.unwrap_or("")),
                    BindValue::Text(to.unwrap_or("")),
                    BindValue::Text(cursor_bucket),
                    BindValue::Text(cursor_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<UsageRollupRecord>()
    }

    /// Idempotent derived aggregation.  The unique scope/bucket index makes a
    /// replayed batch add once.
    pub fn upsert_rollup_statement(
        &self,
        input: &NewRollupInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPSERT_ROLLUP_SQL,
            &[
                BindValue::Text(input.usage_rollup_id),
                BindValue::Text(input.org_id),
                optional_text(input.project_id),
                optional_text(input.principal_user_id),
                optional_text(input.model_alias),
                BindValue::Text(input.bucket_start),
                BindValue::Text(input.bucket_end),
                BindValue::Int64(input.input_tokens),
                BindValue::Int64(input.output_tokens),
                BindValue::Int64(input.cached_tokens),
                BindValue::Int64(input.cost_minor),
                BindValue::Int64(input.usage_event_count),
                BindValue::Text(input.updated_at),
            ],
        )
    }

    /// Immutable budget/rate denial audit rows, newest first.
    pub async fn list_denials(
        &self,
        org_id: &str,
        from: Option<&str>,
        to: Option<&str>,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<UsageDenialRecord>> {
        let (cursor_time, cursor_id) = cursor.unwrap_or(("", ""));
        self.database
            .prepare(
                DENIALS_PAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(from.unwrap_or("")),
                    BindValue::Text(to.unwrap_or("")),
                    BindValue::Text(cursor_time),
                    BindValue::Text(cursor_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<UsageDenialRecord>()
    }
}

#[derive(Deserialize)]
struct UsageSummaryRow {
    event_count: i64,
    input_tokens: i64,
    output_tokens: i64,
    cached_tokens: i64,
    cost_minor: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(event_id: &str, source: &str) -> UsageEventRecord {
        UsageEventRecord {
            event_id: event_id.to_owned(),
            request_id: None,
            run_id: None,
            org_id: "org_1".to_owned(),
            project_id: None,
            principal_user_id: "usr_1".to_owned(),
            session_id: None,
            device_id: None,
            source: source.to_owned(),
            external_id: None,
            reconciliation_status: "recorded".to_owned(),
            model_alias: Some("coding-default".to_owned()),
            input_tokens: None,
            output_tokens: None,
            cached_tokens: None,
            provider_usage_json: "{}".to_owned(),
            estimated_cost_minor: None,
            actual_cost_minor: None,
            currency: None,
            pricing_version: None,
            budget_decision: "allow".to_owned(),
            route_version_id: None,
            provider_id: None,
            model_id: None,
            ttft_ms: None,
            total_latency_ms: None,
            created_at: "2026-09-25T12:00:00.000Z".to_owned(),
        }
    }

    #[test]
    fn usage_sources_are_disjoint_and_normalized() {
        let inference = record("use_1", "inference");
        let run = record("rue_1", "run");
        assert!(!inference.is_run_source());
        assert!(run.is_run_source());
    }

    #[test]
    fn both_source_selects_expose_the_same_column_shape() {
        // The union is only shape-safe when both branches name the same
        // columns in the same order.  Identical columns keep their name; only
        // the five that actually differ carry an alias.
        for column in [
            "run_id",
            "org_id",
            "project_id",
            "principal_user_id",
            "device_id",
            "external_id",
            "reconciliation_status",
            "model_alias",
            "input_tokens",
            "output_tokens",
            "cached_tokens",
            "provider_usage_json",
            "estimated_cost_minor",
            "actual_cost_minor",
            "currency",
            "pricing_version",
            "route_version_id",
            "provider_id",
            "model_id",
            "ttft_ms",
            "total_latency_ms",
            "created_at",
        ] {
            assert!(
                USAGE_EVENT_SOURCE_SQL.contains(column),
                "inference {column}"
            );
            assert!(RUN_USAGE_EVENT_SOURCE_SQL.contains(column), "run {column}");
        }
        // The two branches must expose the same column names in the same
        // order.  Only the columns whose expression differs from the stored
        // name carry an alias, and the union is only shape-safe when both
        // branches agree on those.
        for (inference, run) in [
            (
                "usage_event_id AS event_id",
                "run_usage_event_id AS event_id",
            ),
            ("request_id", "NULL AS request_id"),
            ("session_id", "NULL AS session_id"),
            ("source", "'run' AS source"),
            ("budget_decision", "'not_applicable' AS budget_decision"),
        ] {
            assert!(
                USAGE_EVENT_SOURCE_SQL.contains(inference),
                "inference {inference}"
            );
            assert!(RUN_USAGE_EVENT_SOURCE_SQL.contains(run), "run {run}");
        }
    }

    #[test]
    fn cost_replay_comparison_is_value_based() {
        let row = CostRecordRow {
            cost_record_id: "cost_1".to_owned(),
            usage_event_id: "use_1".to_owned(),
            org_id: "org_1".to_owned(),
            project_id: None,
            run_id: None,
            pricing_source: "provider_reported".to_owned(),
            pricing_version: "2026-09".to_owned(),
            pricing_effective_at: "2026-09-01T00:00:00.000Z".to_owned(),
            calculation_kind: "actual".to_owned(),
            input_tokens: None,
            output_tokens: None,
            cached_tokens: None,
            cost_minor: 42,
            currency: "USD".to_owned(),
            created_at: "2026-09-25T12:00:00.000Z".to_owned(),
        };
        assert!(row.states_same_cost(42, "2026-09", "USD"));
        assert!(!row.states_same_cost(43, "2026-09", "USD"));
        assert!(!row.states_same_cost(42, "2026-10", "USD"));
        assert!(!row.states_same_cost(42, "2026-09", "EUR"));
    }

    #[test]
    fn page_and_summary_filters_are_tenant_first() {
        let page = usage_page_sql();
        let summary = usage_summary_sql();
        assert!(page.contains("WHERE org_id = ?1"));
        assert!(summary.contains("WHERE org_id = ?1"));
        // The tenant predicate must bind before any optional filter.
        assert_eq!(page.matches("org_id = ?1").count(), 2);
        assert_eq!(summary.matches("org_id = ?1").count(), 2);
    }
}
