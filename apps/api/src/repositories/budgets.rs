//! D1 persistence for P05 budgets, reservations, and rate/concurrency policy.
//!
//! P04 already owns the `budgets` and `budget_reservations` tables and the
//! pre-dispatch reservation hook.  P05 extends those rows (P05-CR-002 §6) and
//! never introduces a second reservation authority: the conditional insert
//! below is the single hard-budget gate, it is evaluated inside the same D1
//! write as the reservation row, and the `request_id` unique constraint makes a
//! replayed reservation idempotent instead of duplicated.
//!
//! Money is integer minor units only.  Every predicate compares committed
//! usage plus *live* reservations inside the statement, so a stale pre-request
//! read cannot let concurrent eligible work exceed a hard limit.

use serde::{Deserialize, Serialize};
use worker::d1::D1PreparedStatement;

use crate::adapters::d1::{BindValue, D1Adapter};

const BUDGET_SELECT: &str = r#"
SELECT budget_id, org_id, scope_type, scope_id, period_start, period_end,
       limit_minor, hard, version, currency, created_at, updated_at
FROM budgets
"#;

/// ?1 org, ?2 scope type, ?3 scope id, ?4 cursor created, ?5 cursor id, ?6 limit.
const BUDGETS_PAGE_SQL: &str = r#"
SELECT budget_id, org_id, scope_type, scope_id, period_start, period_end,
       limit_minor, hard, version, currency, created_at, updated_at
FROM budgets
WHERE org_id = ?1
  AND (?2 = '' OR scope_type = ?2)
  AND (?3 = '' OR scope_id = ?3)
  AND (?4 = '' OR (created_at, budget_id) < (?4, ?5))
ORDER BY created_at DESC, budget_id DESC
LIMIT ?6
"#;

const INSERT_BUDGET_SQL: &str = r#"
INSERT INTO budgets (
    budget_id, org_id, scope_type, scope_id, period_start, period_end,
    limit_minor, hard, version, currency, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?10, ?10)
"#;

/// Budget periods are server-owned, but the limit and hard/soft posture are
/// mutable.  `period_end` is monotonic so a shortened period can never
/// retroactively move spend that already happened inside it.
const UPDATE_BUDGET_SQL: &str = r#"
UPDATE budgets
SET limit_minor = ?4, hard = ?5, period_start = ?6, period_end = ?7, currency = ?8,
    version = version + 1, updated_at = ?9
WHERE budget_id = ?1 AND org_id = ?2 AND version = ?3
  AND period_start <= ?6
  AND period_end >= ?7
"#;

/// A failed version predicate aborts the surrounding batch through a
/// duplicate primary key instead of silently writing a stale update.
const ASSERT_BUDGET_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM budgets WHERE budget_id = ?1 AND org_id = ?2 AND version = ?3
)
"#;

const ASSERT_BUDGET_ABSENT_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE EXISTS (
    SELECT 1 FROM budgets WHERE org_id = ?1 AND scope_type = ?2
      AND COALESCE(scope_id, '') = ?3 AND period_start = ?4 AND period_end = ?5
)
"#;

/// A failed conditional reservation must not allow the surrounding batch to
/// record a successful idempotency result.  The deliberately invalid sentinel
/// row is rolled back with the batch when the reservation was not inserted.
const ASSERT_RESERVATION_CREATED_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM budget_reservations
    WHERE reservation_id = ?1 AND org_id = ?2 AND request_id = ?3
)
"#;

/// A reconciliation update is terminal and monotonic.  This assertion keeps a
/// stale/raced request from completing an idempotency record when the guarded
/// UPDATE matched zero rows.
const ASSERT_RESERVATION_RECONCILED_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM budget_reservations
    WHERE reservation_id = ?1 AND request_id = ?2 AND org_id = ?3 AND status = ?4
)
"#;

/// Resolve the immutable P04 request identity used by the reservation gate.
/// This is deliberately a read in the reservation repository so callers
/// cannot infer organization/project/device authority from the request body.
const INFERENCE_REQUEST_SCOPE_SQL: &str = r#"
SELECT request_id, org_id, project_id, run_id, principal_user_id, device_id, model_alias
FROM inference_requests
WHERE request_id = ?1 AND org_id = ?2
LIMIT 1
"#;

const RESERVATION_SELECT: &str = r#"
SELECT reservation_id, request_id, org_id, reserved_minor, committed_minor, status,
       expires_at, created_at, updated_at, run_id, budget_id, currency,
       reconciled_at, reconciliation_reason
FROM budget_reservations
"#;

/// The P05 hard-budget gate.
///
/// The row is inserted only when all of the following hold inside this single
/// statement, which D1 serializes with the write transaction:
///
/// * the amount is bounded and non-zero and the expiry is in the future;
/// * the owning P04 inference request exists in this organization;
/// * an optional run correlation belongs to this organization;
/// * no reservation already exists for this request identity;
/// * no applicable hard budget would be exceeded by committed usage plus live
///   reservations plus this hold.
const INSERT_RESERVATION_IF_AVAILABLE_SQL: &str = r#"
INSERT INTO budget_reservations (
    reservation_id, request_id, org_id, reserved_minor, committed_minor,
    status, expires_at, created_at, updated_at, run_id, budget_id, currency
)
SELECT ?1, ?2, ?3, ?4, NULL, 'reserved', ?5, ?6, ?6, ?7, ?8, ?9
WHERE ?4 > 0
  AND ?5 > ?6
  AND EXISTS (
      SELECT 1 FROM inference_requests r
      WHERE r.request_id = ?2 AND r.org_id = ?3
  )
  AND (?7 IS NULL OR EXISTS (
      SELECT 1 FROM runs ru WHERE ru.run_id = ?7 AND ru.org_id = ?3
  ))
  AND NOT EXISTS (
      SELECT 1 FROM budget_reservations existing
      WHERE existing.org_id = ?3 AND existing.request_id = ?2
  )
  AND NOT EXISTS (
      SELECT 1 FROM budgets b
      WHERE b.org_id = ?3
        AND b.hard = 1
        AND b.period_start <= ?6 AND b.period_end > ?6
        AND (b.budget_id = ?8 OR b.scope_type = 'organization')
        AND b.limit_minor
            - COALESCE((
                SELECT SUM(COALESCE(u.actual_cost_minor, u.estimated_cost_minor, 0))
                FROM usage_events u
                WHERE u.org_id = b.org_id
                  AND u.created_at >= b.period_start AND u.created_at < b.period_end
                  AND (
                      b.scope_type = 'organization'
                      OR (b.scope_type = 'project' AND u.project_id = b.scope_id)
                      OR (b.scope_type IN ('user', 'service_account')
                          AND u.principal_user_id = b.scope_id)
                      OR (b.scope_type = 'model_alias' AND u.model_alias = b.scope_id)
                  )
              ), 0)
            - COALESCE((
                SELECT SUM(COALESCE(rv.reserved_minor, 0) - COALESCE(rv.committed_minor, 0))
                FROM budget_reservations rv
                WHERE rv.org_id = b.org_id
                  AND rv.status = 'reserved'
                  AND rv.expires_at > ?6
                  AND (
                      b.scope_type = 'organization'
                      OR rv.budget_id = b.budget_id
                  )
              ), 0)
            < ?4
  )
"#;

/// Monotonic reservation transitions: `reserved -> committed|released|expired`
/// only, never out of a terminal state.  A commit that exceeds the original
/// hold re-checks the hard budget for the overage, so committing more than was
/// reserved requires budget room rather than a new silent overspend.
const RECONCILE_RESERVATION_SQL: &str = r#"
UPDATE budget_reservations
SET committed_minor = CASE WHEN ?6 = 'committed' THEN ?5 ELSE committed_minor END,
    status = ?6,
    reconciled_at = ?4,
    reconciliation_reason = ?7,
    updated_at = ?4
WHERE reservation_id = ?1 AND org_id = ?2 AND request_id = ?3
  AND status = 'reserved'
  AND (
        ?6 <> 'committed'
     OR COALESCE(?5, 0) <= reserved_minor
     OR NOT EXISTS (
            SELECT 1 FROM budgets b
            WHERE b.org_id = ?2
              AND b.hard = 1
              AND b.period_start <= ?4 AND b.period_end > ?4
              AND (b.budget_id = ?8 OR b.scope_type = 'organization')
              AND b.limit_minor
                  - COALESCE((
                      SELECT SUM(COALESCE(u.actual_cost_minor, u.estimated_cost_minor, 0))
                      FROM usage_events u
                      WHERE u.org_id = b.org_id
                        AND u.created_at >= b.period_start AND u.created_at < b.period_end
                         AND (
                             b.scope_type = 'organization'
                             OR (b.scope_type = 'project' AND u.project_id = b.scope_id)
                             OR (b.scope_type IN ('user', 'service_account')
                                 AND u.principal_user_id = b.scope_id)
                             OR (b.scope_type = 'model_alias' AND u.model_alias = b.scope_id)
                         )
                    ), 0)
                  - COALESCE((
                      SELECT SUM(COALESCE(rv.reserved_minor, 0) - COALESCE(rv.committed_minor, 0))
                      FROM budget_reservations rv
                      WHERE rv.org_id = b.org_id
                        AND rv.status = 'reserved'
                        AND rv.expires_at > ?4
                         AND (
                             b.scope_type = 'organization'
                             OR rv.budget_id = b.budget_id
                         )
                    ), 0)
                  < COALESCE(?5, 0) - reserved_minor
        )
  )
"#;

/// Bounded crash recovery: a hold that outlived its expiry window is marked
/// terminal so it stops consuming budget.  Only live holds are selected, and
/// the statement stays index-bounded by `status, expires_at`.
const EXPIRE_RESERVATIONS_SQL: &str = r#"
UPDATE budget_reservations
SET status = 'expired', reconciled_at = ?1, reconciliation_reason = 'expired',
    updated_at = ?1
WHERE status = 'reserved'
  AND expires_at <= ?1
  AND reservation_id IN (
      SELECT reservation_id FROM budget_reservations
      WHERE status = 'reserved' AND expires_at <= ?1 AND org_id = ?2
      ORDER BY expires_at ASC
      LIMIT ?3
  )
"#;

const RATE_LIMIT_SELECT: &str = r#"
SELECT rate_limit_policy_id, org_id, scope_type, scope_id, requests_per_minute,
       tokens_per_minute, max_concurrent_requests, version, created_by_user_id,
       created_at, updated_at
FROM rate_limit_policies
"#;

/// ?1 org, ?2 scope type, ?3 scope id, ?4 cursor updated, ?5 cursor id, ?6 limit.
const RATE_LIMITS_PAGE_SQL: &str = r#"
SELECT rate_limit_policy_id, org_id, scope_type, scope_id, requests_per_minute,
       tokens_per_minute, max_concurrent_requests, version, created_by_user_id,
       created_at, updated_at
FROM rate_limit_policies
WHERE org_id = ?1
  AND (?2 = '' OR scope_type = ?2)
  AND (?3 = '' OR COALESCE(scope_id, '') = ?3)
  AND (?4 = '' OR (updated_at, rate_limit_policy_id) < (?4, ?5))
ORDER BY updated_at DESC, rate_limit_policy_id DESC
LIMIT ?6
"#;

const UPSERT_RATE_LIMIT_SQL: &str = r#"
INSERT INTO rate_limit_policies (
    rate_limit_policy_id, org_id, scope_type, scope_id, requests_per_minute,
    tokens_per_minute, max_concurrent_requests, version, created_by_user_id,
    created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?9)
ON CONFLICT(org_id, scope_type, COALESCE(scope_id, ''))
DO UPDATE SET
    requests_per_minute = excluded.requests_per_minute,
    tokens_per_minute = excluded.tokens_per_minute,
    max_concurrent_requests = excluded.max_concurrent_requests,
    version = rate_limit_policies.version + 1,
    updated_at = excluded.updated_at
WHERE rate_limit_policies.version = ?10
"#;

const ASSERT_RATE_LIMIT_VERSION_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM rate_limit_policies
    WHERE rate_limit_policy_id = ?1 AND org_id = ?2 AND version = ?3
)
"#;

const ASSERT_RATE_LIMIT_ABSENT_SQL: &str = r#"
INSERT INTO idempotency_records (
    principal_id, organization_id, method, path, key_digest, request_fingerprint,
    state, response_status, response_body, expires_at, claim_token
)
SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL
WHERE EXISTS (
    SELECT 1 FROM rate_limit_policies
    WHERE org_id = ?1 AND scope_type = ?2 AND COALESCE(scope_id, '') = ?3
)
"#;

/// ?1 org, ?2 now, ?3 project, ?4 principal, ?5 model alias, ?6 limit.  An
/// empty scope component means "not in scope", so a project-scoped budget can
/// never apply to a request that resolved no project.
const BUDGET_SCOPE_SNAPSHOT_SQL: &str = r#"
SELECT b.budget_id, b.org_id, b.scope_type, b.scope_id, b.period_start, b.period_end,
       b.limit_minor, b.hard, b.version, b.currency, b.created_at, b.updated_at,
       COALESCE((
           SELECT SUM(COALESCE(u.actual_cost_minor, u.estimated_cost_minor, 0))
           FROM usage_events u
           WHERE u.org_id = b.org_id
             AND u.created_at >= b.period_start AND u.created_at < b.period_end
             AND (
                 b.scope_type = 'organization'
                 OR (b.scope_type = 'project' AND u.project_id = b.scope_id)
                 OR (b.scope_type IN ('user', 'service_account')
                     AND u.principal_user_id = b.scope_id)
                 OR (b.scope_type = 'model_alias' AND u.model_alias = b.scope_id)
             )
       ), 0) AS spent_minor,
       COALESCE((
           SELECT SUM(COALESCE(rv.reserved_minor, 0) - COALESCE(rv.committed_minor, 0))
           FROM budget_reservations rv
           WHERE rv.org_id = b.org_id
             AND rv.status = 'reserved'
             AND rv.expires_at > ?2
             AND (
                 b.scope_type = 'organization'
                 OR rv.budget_id = b.budget_id
             )
       ), 0) AS live_reserved_minor
FROM budgets b
WHERE b.org_id = ?1
  AND b.period_start <= ?2 AND b.period_end > ?2
  AND (b.scope_type = 'organization'
       OR (b.scope_type = 'project' AND ?3 <> '' AND b.scope_id = ?3)
       OR (b.scope_type IN ('user', 'service_account') AND ?4 <> '' AND b.scope_id = ?4)
       OR (b.scope_type = 'model_alias' AND ?5 <> '' AND b.scope_id = ?5))
ORDER BY CASE b.scope_type
    WHEN 'model_alias' THEN 0 WHEN 'user' THEN 1 WHEN 'service_account' THEN 2
    WHEN 'project' THEN 3 ELSE 4 END,
    b.period_start DESC, b.budget_id DESC
LIMIT ?6
"#;

/// Derive request/token counters for the current minute from the immutable
/// usage source, and the live concurrency count from non-terminal inference
/// requests.  No new counter table is introduced, so the rate engine has no
/// second authority.
const RATE_LIMIT_USAGE_SQL: &str = r#"
SELECT
    (SELECT COUNT(*) FROM usage_events u
     WHERE u.org_id = ?1 AND u.created_at >= ?2 AND u.created_at < ?3
       AND (?4 = '' OR u.project_id = ?4)
       AND (?5 = '' OR u.principal_user_id = ?5)
       AND (?6 = '' OR u.model_alias = ?6)) AS requests,
    (SELECT COALESCE(SUM(COALESCE(u.input_tokens, 0) + COALESCE(u.output_tokens, 0)), 0)
     FROM usage_events u
     WHERE u.org_id = ?1 AND u.created_at >= ?2 AND u.created_at < ?3
       AND (?4 = '' OR u.project_id = ?4)
       AND (?5 = '' OR u.principal_user_id = ?5)
       AND (?6 = '' OR u.model_alias = ?6)) AS tokens,
    (SELECT COUNT(*) FROM inference_requests r
     WHERE r.org_id = ?1
       AND r.response_state IN ('not_dispatched', 'dispatched_no_output', 'stream_committed')
       AND (?4 = '' OR r.project_id = ?4)
       AND (?5 = '' OR r.principal_user_id = ?5)
       AND (?6 = '' OR r.model_alias = ?6)) AS active_inferences,
    ?7 AS minute_started_at
"#;

#[derive(Clone, Debug, Deserialize)]
struct BudgetRow {
    budget_id: String,
    org_id: String,
    scope_type: String,
    scope_id: Option<String>,
    period_start: String,
    period_end: String,
    limit_minor: i64,
    hard: i64,
    version: i64,
    currency: String,
    created_at: String,
    updated_at: String,
}

impl TryFrom<BudgetRow> for BudgetRecord {
    type Error = worker::Error;

    fn try_from(row: BudgetRow) -> Result<Self, Self::Error> {
        Ok(BudgetRecord {
            budget_id: row.budget_id,
            org_id: row.org_id,
            scope_type: row.scope_type,
            scope_id: row.scope_id,
            period_start: row.period_start,
            period_end: row.period_end,
            limit_minor: row.limit_minor,
            hard: row.hard == 1,
            version: row.version,
            currency: row.currency,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
struct BudgetScopeSnapshotRow {
    budget_id: String,
    org_id: String,
    scope_type: String,
    scope_id: Option<String>,
    period_start: String,
    period_end: String,
    limit_minor: i64,
    hard: i64,
    version: i64,
    currency: String,
    created_at: String,
    updated_at: String,
    spent_minor: i64,
    live_reserved_minor: i64,
}

impl TryFrom<BudgetScopeSnapshotRow> for BudgetScopeSnapshot {
    type Error = worker::Error;

    fn try_from(row: BudgetScopeSnapshotRow) -> Result<Self, Self::Error> {
        Ok(BudgetScopeSnapshot {
            budget_id: row.budget_id,
            org_id: row.org_id,
            scope_type: row.scope_type,
            scope_id: row.scope_id,
            period_start: row.period_start,
            period_end: row.period_end,
            limit_minor: row.limit_minor,
            hard: row.hard == 1,
            version: row.version,
            currency: row.currency,
            created_at: row.created_at,
            updated_at: row.updated_at,
            spent_minor: row.spent_minor,
            live_reserved_minor: row.live_reserved_minor,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InferenceRequestScopeRecord {
    pub request_id: String,
    pub org_id: String,
    pub project_id: Option<String>,
    pub run_id: Option<String>,
    pub principal_user_id: String,
    pub device_id: Option<String>,
    pub model_alias: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BudgetRecord {
    pub budget_id: String,
    pub org_id: String,
    pub scope_type: String,
    pub scope_id: Option<String>,
    pub period_start: String,
    pub period_end: String,
    pub limit_minor: i64,
    pub hard: bool,
    pub version: i64,
    pub currency: String,
    pub created_at: String,
    pub updated_at: String,
}

impl BudgetRecord {
    pub fn is_hard(&self) -> bool {
        self.hard
    }
}

/// One applicable budget plus its committed and live-held spend.  The budget
/// columns are flattened so the row maps directly from the snapshot query.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BudgetScopeSnapshot {
    pub budget_id: String,
    pub org_id: String,
    pub scope_type: String,
    pub scope_id: Option<String>,
    pub period_start: String,
    pub period_end: String,
    pub limit_minor: i64,
    pub hard: bool,
    pub version: i64,
    pub currency: String,
    pub created_at: String,
    pub updated_at: String,
    pub spent_minor: i64,
    pub live_reserved_minor: i64,
}

impl BudgetScopeSnapshot {
    pub fn budget(&self) -> BudgetRecord {
        BudgetRecord {
            budget_id: self.budget_id.clone(),
            org_id: self.org_id.clone(),
            scope_type: self.scope_type.clone(),
            scope_id: self.scope_id.clone(),
            period_start: self.period_start.clone(),
            period_end: self.period_end.clone(),
            limit_minor: self.limit_minor,
            hard: self.hard,
            version: self.version,
            currency: self.currency.clone(),
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
        }
    }

    /// Remaining hard-budget headroom in minor units.  `None` means the
    /// projection itself is unusable and the caller must fail closed.
    pub fn remaining_minor(&self) -> Option<i64> {
        self.limit_minor
            .checked_sub(self.spent_minor.saturating_add(self.live_reserved_minor))
    }

    pub fn can_reserve(&self, amount: i64) -> bool {
        amount > 0 && self.remaining_minor().is_some_and(|left| left >= amount)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BudgetReservationRecord {
    pub reservation_id: String,
    pub request_id: String,
    pub org_id: String,
    pub reserved_minor: i64,
    pub committed_minor: Option<i64>,
    pub status: String,
    pub expires_at: String,
    pub created_at: String,
    pub updated_at: String,
    pub run_id: Option<String>,
    pub budget_id: Option<String>,
    pub currency: String,
    pub reconciled_at: Option<String>,
    pub reconciliation_reason: Option<String>,
}

impl BudgetReservationRecord {
    /// Held amount that still consumes budget right now.
    pub fn outstanding_minor(&self, now: &str) -> i64 {
        if self.status != "reserved" || self.expires_at.as_str() <= now {
            return 0;
        }
        self.reserved_minor - self.committed_minor.unwrap_or_default()
    }

    pub fn is_live(&self, now: &str) -> bool {
        self.status == "reserved" && self.expires_at.as_str() > now
    }

    /// The reserved hold cannot be reused for a different request or run.
    pub fn matches_identity(&self, request_id: &str, run_id: Option<&str>) -> bool {
        self.request_id == request_id && self.run_id.as_deref() == run_id
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RateLimitPolicyRecord {
    pub rate_limit_policy_id: String,
    pub org_id: String,
    pub scope_type: String,
    pub scope_id: Option<String>,
    pub requests_per_minute: Option<i64>,
    pub tokens_per_minute: Option<i64>,
    pub max_concurrent_requests: Option<i64>,
    pub version: i64,
    pub created_by_user_id: String,
    pub created_at: String,
    pub updated_at: String,
}

impl RateLimitPolicyRecord {
    pub fn has_limits(&self) -> bool {
        self.requests_per_minute.is_some()
            || self.tokens_per_minute.is_some()
            || self.max_concurrent_requests.is_some()
    }
}

/// Derived minute-window counters for one trusted request scope.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct RateLimitUsageRow {
    pub requests: i64,
    pub tokens: i64,
    pub active_inferences: i64,
    pub minute_started_at: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct NewBudgetInput<'a> {
    pub budget_id: &'a str,
    pub org_id: &'a str,
    pub scope_type: &'a str,
    pub scope_id: Option<&'a str>,
    pub period_start: &'a str,
    pub period_end: &'a str,
    pub limit_minor: i64,
    pub hard: bool,
    pub currency: &'a str,
    pub created_at: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub struct BudgetUpdateInput<'a> {
    pub budget_id: &'a str,
    pub org_id: &'a str,
    pub expected_version: i64,
    pub limit_minor: i64,
    pub hard: bool,
    pub period_start: &'a str,
    pub period_end: &'a str,
    pub currency: &'a str,
    pub updated_at: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub struct NewReservationInput<'a> {
    pub reservation_id: &'a str,
    pub request_id: &'a str,
    pub org_id: &'a str,
    pub reserved_minor: i64,
    pub expires_at: &'a str,
    pub now: &'a str,
    pub run_id: Option<&'a str>,
    pub budget_id: Option<&'a str>,
    pub currency: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub struct ReservationReconcileInput<'a> {
    pub reservation_id: &'a str,
    pub org_id: &'a str,
    pub request_id: &'a str,
    pub reconciled_at: &'a str,
    pub committed_minor: Option<i64>,
    pub status: &'a str,
    pub reason: Option<&'a str>,
    pub budget_id: Option<&'a str>,
}

#[derive(Clone, Copy, Debug)]
pub struct UpsertRateLimitInput<'a> {
    pub rate_limit_policy_id: &'a str,
    pub org_id: &'a str,
    pub scope_type: &'a str,
    pub scope_id: Option<&'a str>,
    pub requests_per_minute: Option<i64>,
    pub tokens_per_minute: Option<i64>,
    pub max_concurrent_requests: Option<i64>,
    pub created_by_user_id: &'a str,
    pub now: &'a str,
    pub expected_version: Option<i64>,
}

fn optional_text(value: Option<&str>) -> BindValue<'_> {
    value.map_or(BindValue::Null, BindValue::Text)
}

fn optional_integer(value: Option<i64>) -> BindValue<'static> {
    match value {
        Some(value) => BindValue::Int64(value),
        None => BindValue::Null,
    }
}

/// Repository for budget CRUD, conditional reservations, and rate policy.
pub struct BudgetRepository<'a> {
    database: &'a D1Adapter,
}

impl<'a> BudgetRepository<'a> {
    pub fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    pub async fn find_budget(
        &self,
        org_id: &str,
        budget_id: &str,
    ) -> worker::Result<Option<BudgetRecord>> {
        self.database
            .prepare(
                &format!("{BUDGET_SELECT} WHERE org_id = ?1 AND budget_id = ?2 LIMIT 1"),
                &[BindValue::Text(org_id), BindValue::Text(budget_id)],
            )?
            .first::<BudgetRow>(None)
            .await?
            .map(TryInto::try_into)
            .transpose()
    }

    pub async fn list_budgets(
        &self,
        org_id: &str,
        scope_type: Option<&str>,
        scope_id: Option<&str>,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<BudgetRecord>> {
        let (cursor_created, cursor_id) = cursor.unwrap_or(("", ""));
        self.database
            .prepare(
                BUDGETS_PAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(scope_type.unwrap_or("")),
                    BindValue::Text(scope_id.unwrap_or("")),
                    BindValue::Text(cursor_created),
                    BindValue::Text(cursor_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<BudgetRow>()?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }

    /// Resolve one request's trusted scope before an internal reservation is
    /// admitted.  The route uses this to bind a device token to the P04
    /// request instead of accepting a caller-selected organization or project.
    pub async fn find_inference_request_scope(
        &self,
        org_id: &str,
        request_id: &str,
    ) -> worker::Result<Option<InferenceRequestScopeRecord>> {
        self.database
            .prepare(
                INFERENCE_REQUEST_SCOPE_SQL,
                &[BindValue::Text(request_id), BindValue::Text(org_id)],
            )?
            .first::<InferenceRequestScopeRecord>(None)
            .await
    }

    /// Look up an exact scope/period key for deterministic create conflicts.
    pub async fn find_budget_for_scope_period(
        &self,
        org_id: &str,
        scope_type: &str,
        scope_id: Option<&str>,
        period_start: &str,
        period_end: &str,
    ) -> worker::Result<Option<BudgetRecord>> {
        self.database
            .prepare(
                &format!(
                    "{BUDGET_SELECT} WHERE org_id = ?1 AND scope_type = ?2 \
                     AND COALESCE(scope_id, '') = ?3 AND period_start = ?4 \
                     AND period_end = ?5 LIMIT 1"
                ),
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(scope_type),
                    BindValue::Text(scope_id.unwrap_or("")),
                    BindValue::Text(period_start),
                    BindValue::Text(period_end),
                ],
            )?
            .first::<BudgetRow>(None)
            .await?
            .map(TryInto::try_into)
            .transpose()
    }

    pub fn assert_reservation_created_statement(
        &self,
        reservation_id: &str,
        org_id: &str,
        request_id: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_RESERVATION_CREATED_SQL,
            &[
                BindValue::Text(reservation_id),
                BindValue::Text(org_id),
                BindValue::Text(request_id),
            ],
        )
    }

    pub fn assert_reservation_reconciled_statement(
        &self,
        reservation_id: &str,
        request_id: &str,
        org_id: &str,
        status: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_RESERVATION_RECONCILED_SQL,
            &[
                BindValue::Text(reservation_id),
                BindValue::Text(request_id),
                BindValue::Text(org_id),
                BindValue::Text(status),
            ],
        )
    }

    pub fn insert_budget_statement(
        &self,
        input: &NewBudgetInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_BUDGET_SQL,
            &[
                BindValue::Text(input.budget_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.scope_type),
                optional_text(input.scope_id),
                BindValue::Text(input.period_start),
                BindValue::Text(input.period_end),
                BindValue::Int64(input.limit_minor),
                BindValue::Integer(i32::from(input.hard)),
                BindValue::Text(input.currency),
                BindValue::Text(input.created_at),
            ],
        )
    }

    pub fn update_budget_statement(
        &self,
        input: &BudgetUpdateInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_BUDGET_SQL,
            &[
                BindValue::Text(input.budget_id),
                BindValue::Text(input.org_id),
                BindValue::Int64(input.expected_version),
                BindValue::Int64(input.limit_minor),
                BindValue::Integer(i32::from(input.hard)),
                BindValue::Text(input.period_start),
                BindValue::Text(input.period_end),
                BindValue::Text(input.currency),
                BindValue::Text(input.updated_at),
            ],
        )
    }

    pub fn assert_budget_version_statement(
        &self,
        budget_id: &str,
        org_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_BUDGET_VERSION_SQL,
            &[
                BindValue::Text(budget_id),
                BindValue::Text(org_id),
                BindValue::Int64(expected_version),
            ],
        )
    }

    /// Guard the P04 unique scope/period key so a duplicate create is a
    /// deterministic conflict instead of a 500.
    pub fn assert_budget_absent_statement(
        &self,
        org_id: &str,
        scope_type: &str,
        scope_id: Option<&str>,
        period_start: &str,
        period_end: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_BUDGET_ABSENT_SQL,
            &[
                BindValue::Text(org_id),
                BindValue::Text(scope_type),
                BindValue::Text(scope_id.unwrap_or("")),
                BindValue::Text(period_start),
                BindValue::Text(period_end),
            ],
        )
    }

    /// Every budget that can apply to one trusted request scope, each with the
    /// committed and live-held spend it already has.  A read error must be
    /// surfaced as `budget_state_unavailable`, never as "allowed".
    #[allow(clippy::too_many_arguments)]
    pub async fn budget_scope_snapshots(
        &self,
        org_id: &str,
        now: &str,
        project_id: Option<&str>,
        principal_user_id: Option<&str>,
        model_alias: Option<&str>,
        limit: i32,
    ) -> worker::Result<Vec<BudgetScopeSnapshot>> {
        let project = project_id.unwrap_or("");
        let principal = principal_user_id.unwrap_or("");
        let model = model_alias.unwrap_or("");
        self.database
            .prepare(
                BUDGET_SCOPE_SNAPSHOT_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(now),
                    BindValue::Text(project),
                    BindValue::Text(principal),
                    BindValue::Text(model),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<BudgetScopeSnapshotRow>()?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }

    pub async fn find_reservation(
        &self,
        org_id: &str,
        reservation_id: &str,
    ) -> worker::Result<Option<BudgetReservationRecord>> {
        self.database
            .prepare(
                &format!("{RESERVATION_SELECT} WHERE org_id = ?1 AND reservation_id = ?2 LIMIT 1"),
                &[BindValue::Text(org_id), BindValue::Text(reservation_id)],
            )?
            .first::<BudgetReservationRecord>(None)
            .await
    }

    /// Reservations are keyed by the P04 request identity, so a replay of the
    /// same request resolves to the same hold instead of a second one.
    pub async fn find_reservation_by_request(
        &self,
        org_id: &str,
        request_id: &str,
    ) -> worker::Result<Option<BudgetReservationRecord>> {
        self.database
            .prepare(
                &format!("{RESERVATION_SELECT} WHERE org_id = ?1 AND request_id = ?2 LIMIT 1"),
                &[BindValue::Text(org_id), BindValue::Text(request_id)],
            )?
            .first::<BudgetReservationRecord>(None)
            .await
    }

    /// Keyset-paginated reservation history for an authorized dashboard.
    pub async fn list_reservations_page(
        &self,
        org_id: &str,
        run_id: Option<&str>,
        status: Option<&str>,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<BudgetReservationRecord>> {
        let (cursor_created, cursor_id) = cursor.unwrap_or(("", ""));
        self.database
            .prepare(
                &format!(
                    "{RESERVATION_SELECT} WHERE org_id = ?1 \
                     AND (?2 IS NULL OR run_id = ?2) \
                     AND (?3 = '' OR status = ?3) \
                     AND (?4 = '' OR (created_at, reservation_id) < (?4, ?5)) \
                     ORDER BY created_at DESC, reservation_id DESC LIMIT ?6"
                ),
                &[
                    BindValue::Text(org_id),
                    optional_text(run_id),
                    BindValue::Text(status.unwrap_or("")),
                    BindValue::Text(cursor_created),
                    BindValue::Text(cursor_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<BudgetReservationRecord>()
    }

    /// The single P05 hard-budget admission write.  One changed row means the
    /// hold was granted; zero rows means the request identity already holds a
    /// reservation or a hard budget would be exceeded.
    pub fn insert_reservation_if_available_statement(
        &self,
        input: &NewReservationInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_RESERVATION_IF_AVAILABLE_SQL,
            &[
                BindValue::Text(input.reservation_id),
                BindValue::Text(input.request_id),
                BindValue::Text(input.org_id),
                BindValue::Int64(input.reserved_minor),
                BindValue::Text(input.expires_at),
                BindValue::Text(input.now),
                optional_text(input.run_id),
                optional_text(input.budget_id),
                BindValue::Text(input.currency),
            ],
        )
    }

    /// Apply one terminal reservation transition.  The statement only matches a
    /// live hold, so a second reconcile is a no-op the handler replays.
    pub fn reconcile_reservation_statement(
        &self,
        input: &ReservationReconcileInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            RECONCILE_RESERVATION_SQL,
            &[
                BindValue::Text(input.reservation_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.request_id),
                BindValue::Text(input.reconciled_at),
                optional_integer(input.committed_minor),
                BindValue::Text(input.status),
                optional_text(input.reason),
                optional_text(input.budget_id),
            ],
        )
    }

    /// Bounded expiry sweep for crash recovery.
    pub fn expire_reservations_statement(
        &self,
        org_id: &str,
        now: &str,
        limit: i32,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            EXPIRE_RESERVATIONS_SQL,
            &[
                BindValue::Text(now),
                BindValue::Text(org_id),
                BindValue::Integer(limit),
            ],
        )
    }

    pub async fn find_rate_limit_policy(
        &self,
        org_id: &str,
        scope_type: &str,
        scope_id: Option<&str>,
    ) -> worker::Result<Option<RateLimitPolicyRecord>> {
        self.database
            .prepare(
                &format!(
                    "{RATE_LIMIT_SELECT} WHERE org_id = ?1 AND scope_type = ?2 \
                     AND COALESCE(scope_id, '') = ?3 LIMIT 1"
                ),
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(scope_type),
                    BindValue::Text(scope_id.unwrap_or("")),
                ],
            )?
            .first::<RateLimitPolicyRecord>(None)
            .await
    }

    pub async fn list_rate_limit_policies(
        &self,
        org_id: &str,
        scope_type: Option<&str>,
        scope_id: Option<&str>,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<RateLimitPolicyRecord>> {
        let (cursor_updated, cursor_id) = cursor.unwrap_or(("", ""));
        self.database
            .prepare(
                RATE_LIMITS_PAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(scope_type.unwrap_or("")),
                    BindValue::Text(scope_id.unwrap_or("")),
                    BindValue::Text(cursor_updated),
                    BindValue::Text(cursor_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<RateLimitPolicyRecord>()
    }

    /// Create or update one scoped rate/concurrency policy.  The unique scope
    /// index makes the write a single atomic upsert, and the version guard
    /// rejects a stale overwrite.
    pub fn upsert_rate_limit_policy_statement(
        &self,
        input: &UpsertRateLimitInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPSERT_RATE_LIMIT_SQL,
            &[
                BindValue::Text(input.rate_limit_policy_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.scope_type),
                optional_text(input.scope_id),
                optional_integer(input.requests_per_minute),
                optional_integer(input.tokens_per_minute),
                optional_integer(input.max_concurrent_requests),
                BindValue::Text(input.created_by_user_id),
                BindValue::Text(input.now),
                BindValue::Int64(input.expected_version.unwrap_or_default()),
            ],
        )
    }

    pub fn assert_rate_limit_version_statement(
        &self,
        rate_limit_policy_id: &str,
        org_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_RATE_LIMIT_VERSION_SQL,
            &[
                BindValue::Text(rate_limit_policy_id),
                BindValue::Text(org_id),
                BindValue::Int64(expected_version),
            ],
        )
    }

    /// Guard the unique scope key so a create with a wrong expected version is
    /// a deterministic conflict instead of an upsert.
    pub fn assert_rate_limit_absent_statement(
        &self,
        org_id: &str,
        scope_type: &str,
        scope_id: Option<&str>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ASSERT_RATE_LIMIT_ABSENT_SQL,
            &[
                BindValue::Text(org_id),
                BindValue::Text(scope_type),
                BindValue::Text(scope_id.unwrap_or("")),
            ],
        )
    }

    /// Derived minute counters and live concurrency for one trusted scope.
    /// The caller passes the minute window bounds it already computed.
    #[allow(clippy::too_many_arguments)]
    pub async fn rate_limit_usage(
        &self,
        org_id: &str,
        window_start: &str,
        window_end: &str,
        project_id: Option<&str>,
        principal_user_id: Option<&str>,
        model_alias: Option<&str>,
        minute_started_at: i64,
    ) -> worker::Result<RateLimitUsageRow> {
        self.database
            .prepare(
                RATE_LIMIT_USAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(window_start),
                    BindValue::Text(window_end),
                    BindValue::Text(project_id.unwrap_or("")),
                    BindValue::Text(principal_user_id.unwrap_or("")),
                    BindValue::Text(model_alias.unwrap_or("")),
                    BindValue::Int64(minute_started_at),
                ],
            )?
            .first::<RateLimitUsageRow>(None)
            .await
            .map(|row| row.unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(
        limit_minor: i64,
        spent_minor: i64,
        live_reserved_minor: i64,
    ) -> BudgetScopeSnapshot {
        BudgetScopeSnapshot {
            budget_id: "bud_1".to_owned(),
            org_id: "org_1".to_owned(),
            scope_type: "organization".to_owned(),
            scope_id: None,
            period_start: "2026-09-01T00:00:00.000Z".to_owned(),
            period_end: "2026-10-01T00:00:00.000Z".to_owned(),
            limit_minor,
            hard: true,
            version: 1,
            currency: "USD".to_owned(),
            created_at: "2026-09-01T00:00:00.000Z".to_owned(),
            updated_at: "2026-09-01T00:00:00.000Z".to_owned(),
            spent_minor,
            live_reserved_minor,
        }
    }

    fn reservation() -> BudgetReservationRecord {
        BudgetReservationRecord {
            reservation_id: "bud_2".to_owned(),
            request_id: "req_1".to_owned(),
            org_id: "org_1".to_owned(),
            reserved_minor: 100,
            committed_minor: None,
            status: "reserved".to_owned(),
            expires_at: "2026-09-25T13:00:00.000Z".to_owned(),
            created_at: "2026-09-25T12:00:00.000Z".to_owned(),
            updated_at: "2026-09-25T12:00:00.000Z".to_owned(),
            run_id: None,
            budget_id: None,
            currency: "USD".to_owned(),
            reconciled_at: None,
            reconciliation_reason: None,
        }
    }

    #[test]
    fn headroom_subtracts_committed_spend_and_live_holds() {
        let row = snapshot(1_000, 400, 250);
        assert_eq!(row.remaining_minor(), Some(350));
        assert!(row.can_reserve(350));
        assert!(!row.can_reserve(351));
        assert!(!row.can_reserve(0));
        assert!(row.budget().is_hard());
    }

    #[test]
    fn an_exhausted_or_overdrawn_budget_reports_no_headroom() {
        let exhausted = snapshot(100, 100, 0);
        assert_eq!(exhausted.remaining_minor(), Some(0));
        assert!(!exhausted.can_reserve(1));
        let overdrawn = snapshot(100, 140, 0);
        assert_eq!(overdrawn.remaining_minor(), Some(-40));
        assert!(!overdrawn.can_reserve(1));
    }

    #[test]
    fn a_reservation_holds_budget_only_while_it_is_live() {
        let row = reservation();
        assert!(row.is_live("2026-09-25T12:30:00.000Z"));
        assert_eq!(row.outstanding_minor("2026-09-25T12:30:00.000Z"), 100);
        assert!(!row.is_live("2026-09-25T13:00:00.000Z"));
        assert_eq!(row.outstanding_minor("2026-09-25T13:00:00.000Z"), 0);
        let mut committed = row.clone();
        committed.status = "committed".to_owned();
        committed.committed_minor = Some(40);
        assert!(!committed.is_live("2026-09-25T12:30:00.000Z"));
    }

    #[test]
    fn a_reservation_cannot_be_reused_for_another_request_or_run() {
        let row = reservation();
        assert!(row.matches_identity("req_1", None));
        assert!(!row.matches_identity("req_2", None));
        let mut with_run = row.clone();
        with_run.run_id = Some("run_1".to_owned());
        assert!(with_run.matches_identity("req_1", Some("run_1")));
        assert!(!with_run.matches_identity("req_1", Some("run_2")));
        assert!(!with_run.matches_identity("req_1", None));
    }

    #[test]
    fn reservation_writes_are_tenant_scoped_and_idempotent() {
        let sql = INSERT_RESERVATION_IF_AVAILABLE_SQL;
        // A hold may only be created for a request that already exists in the
        // same organization, may not be duplicated for that request, and is
        // bounded by committed usage plus live reservations.
        assert!(sql.contains("FROM inference_requests r"));
        assert!(sql.contains("r.org_id = ?3"));
        assert!(sql.contains("FROM budget_reservations existing"));
        assert!(sql.contains("existing.request_id = ?2"));
        assert!(sql.contains("b.hard = 1"));
        assert!(sql.contains("rv.status = 'reserved'"));
        assert!(sql.contains("rv.expires_at > ?6"));
    }

    #[test]
    fn reservation_transitions_are_monotonic_and_idempotent() {
        let sql = RECONCILE_RESERVATION_SQL;
        assert!(sql.contains("AND status = 'reserved'"));
        assert!(sql.contains("reservation_id = ?1 AND org_id = ?2 AND request_id = ?3"));
        // Committing beyond the hold is allowed only with budget headroom.
        assert!(sql.contains("COALESCE(?5, 0) <= reserved_minor"));
        assert!(sql.contains("b.hard = 1"));
    }

    #[test]
    fn every_budget_and_rate_query_binds_the_tenant_first() {
        for sql in [
            BUDGETS_PAGE_SQL,
            BUDGET_SCOPE_SNAPSHOT_SQL,
            RATE_LIMITS_PAGE_SQL,
            RATE_LIMIT_USAGE_SQL,
        ] {
            assert!(
                sql.contains("org_id = ?1"),
                "missing tenant predicate: {sql}"
            );
        }
    }
}
