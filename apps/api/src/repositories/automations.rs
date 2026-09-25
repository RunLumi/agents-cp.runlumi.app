//! D1 persistence for the P06 automation control plane.
//!
//! This repository owns SQL and row mapping for `automation_schedule_rules`,
//! `automation_definitions`, `automation_occurrences`, `automation_leases`,
//! `automation_occurrence_attempts`, and `automation_run_links` (migration
//! `0011_p06_automations.sql`). It never decides policy: every transition it
//! writes was already decided by `modules::automations`, and every authorization,
//! membership, entitlement, and device-eligibility question is answered by the
//! caller from current rows.
//!
//! # Two load-bearing boundaries
//!
//! 1. **One logical occurrence.** A scheduled occurrence is inserted with a
//!    `WHERE NOT EXISTS` guard on `(automation_id, schedule_rule_id,
//!    scheduled_for_utc)`, so a queue redelivery, a worker reconnect, or a second
//!    generation pass cannot mint a second logical occurrence. The unique index
//!    `ux_automation_occurrences_scheduled` is the backstop.
//! 2. **At most one current lease.** A claim is a single D1 batch whose first
//!    statement asserts the occurrence is still claimable and has no active
//!    lease. The partial unique index `ux_automation_leases_active` is the
//!    backstop, so a losing concurrent claim aborts its own batch and re-reads
//!    the winner's projection.
//!
//! Guards are expressed as a deliberately invalid `idempotency_records` insert
//! (the established P05 idiom): when the precondition does not hold the SELECT
//! yields zero rows and the statement is a no-op, and when it does hold the
//! insert violates a NOT NULL constraint and D1 rolls the whole batch back.
//! [`is_guard_violation`] separates a refused batch from an unavailable store.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::d1::D1PreparedStatement;

use crate::{
    adapters::d1::{BindValue, D1Adapter},
    core::Timestamp,
    modules::automations::{
        DomainError, ExecutionRetry, LeaseFence, OccurrenceKind, OccurrenceState, PredecessorView,
        ScheduleRule, ZoneOffsets, transition,
    },
};

/// Frozen bound on the device "due work" response.
pub const MAX_DUE_OCCURRENCES: i32 = 20;
/// Frozen maximum page size for every P06 list endpoint.
pub const MAX_OCCURRENCE_PAGE_SIZE: i32 = 100;
/// Bounded number of occurrences a single generation pass may create.
pub const MAX_GENERATED_OCCURRENCES: usize = 20;
/// Bounded number of automations one scheduler pass may advance.
pub const MAX_SCHEDULER_AUTOMATIONS: i32 = 50;
/// Bounded number of expired leases one sweep may resolve.
pub const MAX_EXPIRED_LEASES: i32 = 50;
/// The `automation.*` durable event names frozen by `p06-cg-v1`.
pub const EVENT_DEFINITION_CREATED: &str = "automation.definition.created.v1";
pub const EVENT_DEFINITION_UPDATED: &str = "automation.definition.updated.v1";
pub const EVENT_DEFINITION_PAUSED: &str = "automation.definition.paused.v1";
pub const EVENT_DEFINITION_RESUMED: &str = "automation.definition.resumed.v1";
pub const EVENT_DEFINITION_DELETED: &str = "automation.definition.deleted.v1";
pub const EVENT_OCCURRENCE_CREATED: &str = "automation.occurrence.created.v1";
pub const EVENT_OCCURRENCE_DISPATCHED: &str = "automation.occurrence.dispatched.v1";
pub const EVENT_OCCURRENCE_STARTED: &str = "automation.occurrence.started.v1";
pub const EVENT_OCCURRENCE_COMPLETED: &str = "automation.occurrence.completed.v1";
pub const EVENT_OCCURRENCE_FAILED: &str = "automation.occurrence.failed.v1";
pub const EVENT_OCCURRENCE_SKIPPED: &str = "automation.occurrence.skipped.v1";
pub const EVENT_OCCURRENCE_MISSED: &str = "automation.occurrence.missed.v1";
pub const EVENT_OCCURRENCE_LEASE_EXPIRED: &str = "automation.occurrence.lease_expired.v1";
pub const EVENT_OCCURRENCE_AMBIGUOUS: &str = "automation.occurrence.ambiguous.v1";

/// Every `automation.*` event name this packet may emit. Adding a name requires
/// a contract change, not a new string literal at a call site.
pub const AUTOMATION_EVENT_TYPES: &[&str] = &[
    EVENT_DEFINITION_CREATED,
    EVENT_DEFINITION_UPDATED,
    EVENT_DEFINITION_PAUSED,
    EVENT_DEFINITION_RESUMED,
    EVENT_DEFINITION_DELETED,
    EVENT_OCCURRENCE_CREATED,
    EVENT_OCCURRENCE_DISPATCHED,
    EVENT_OCCURRENCE_STARTED,
    EVENT_OCCURRENCE_COMPLETED,
    EVENT_OCCURRENCE_FAILED,
    EVENT_OCCURRENCE_SKIPPED,
    EVENT_OCCURRENCE_MISSED,
    EVENT_OCCURRENCE_LEASE_EXPIRED,
    EVENT_OCCURRENCE_AMBIGUOUS,
];

/// A guard statement inserts an invalid `idempotency_records` row when the
/// precondition does NOT hold, which aborts the surrounding D1 batch.
macro_rules! guard {
    ($condition:literal) => {
        concat!(
            "INSERT INTO idempotency_records (principal_id, organization_id, method, path, ",
            "key_digest, request_fingerprint, state, response_status, response_body, ",
            "expires_at, claim_token) ",
            "SELECT NULL, '', '', '', '', '', 'pending', NULL, NULL, '', NULL ",
            "WHERE NOT EXISTS (",
            $condition,
            ")"
        )
    };
}

const AUTOMATION_BY_ID_SQL: &str = r#"
SELECT automation_id, org_id, project_id, name, description,
       agent_definition_id, schedule_rule_id, execution_principal_kind,
       execution_principal_id, target_kind, target_device_id,
       target_workspace_binding_id, required_capabilities_json,
       execution_model_alias, execution_budget_id, tool_policy_scope,
       required_policy_version, off_peak_eligibility_source,
       off_peak_allowed_route_aliases_json, off_peak_deny_automation_mutation,
       off_peak_deny_recursive_off_peak, off_peak_allow_background_processes,
       status, max_start_attempts, lease_ttl_seconds, heartbeat_interval_seconds,
       schedule_cursor_at, next_run_at, last_run_at, version,
       created_by_user_id, created_at, updated_at, queued_successor_max_age_seconds
FROM automation_definitions
WHERE automation_id = ?1 AND org_id = ?2
LIMIT 1
"#;

const AUTOMATIONS_PAGE_SQL: &str = r#"
SELECT automation_id, org_id, project_id, name, description,
       agent_definition_id, schedule_rule_id, execution_principal_kind,
       execution_principal_id, target_kind, target_device_id,
       target_workspace_binding_id, required_capabilities_json,
       execution_model_alias, execution_budget_id, tool_policy_scope,
       required_policy_version, off_peak_eligibility_source,
       off_peak_allowed_route_aliases_json, off_peak_deny_automation_mutation,
       off_peak_deny_recursive_off_peak, off_peak_allow_background_processes,
       status, max_start_attempts, lease_ttl_seconds, heartbeat_interval_seconds,
       schedule_cursor_at, next_run_at, last_run_at, version,
       created_by_user_id, created_at, updated_at, queued_successor_max_age_seconds
FROM automation_definitions
WHERE org_id = ?1
  AND (?2 = '' OR status = ?2)
  AND (?3 = '' OR project_id = ?3)
  AND (
    ?4 = 1
    OR project_id IS NULL
    OR EXISTS (
      SELECT 1 FROM projects p
      WHERE p.project_id = automation_definitions.project_id
        AND p.org_id = automation_definitions.org_id
        AND p.archived_at IS NULL
        AND (
          p.visibility = 'org'
          OR EXISTS (
            SELECT 1 FROM project_access_grants g
            WHERE g.project_id = p.project_id
              AND g.org_id = p.org_id
              AND (
                g.member_id IN (
                  SELECT membership_id FROM memberships
                  WHERE org_id = ?1 AND user_id = ?5 AND status = 'active'
                )
                OR g.team_id IN (
                  SELECT tm.team_id
                  FROM team_members tm
                  JOIN memberships m ON m.membership_id = tm.membership_id
                  WHERE m.org_id = ?1 AND m.user_id = ?5 AND m.status = 'active'
                )
              )
          )
        )
    )
  )
  AND (?6 = '' OR (updated_at, automation_id) < (?6, ?7))
ORDER BY updated_at DESC, automation_id DESC
LIMIT ?8
"#;

const ACTIVE_AUTOMATION_COUNT_SQL: &str = r#"
SELECT COUNT(*) AS active_count
FROM automation_definitions
WHERE org_id = ?1 AND status = 'active'
"#;

/// Bounded scheduler selection. Only an `active` automation with a due
/// `next_run_at` in a non-deleted organization is selected, so a paused or
/// suspended automation never mints a new occurrence.
const DUE_AUTOMATIONS_SQL: &str = r#"
SELECT a.automation_id, a.org_id, a.project_id, a.name, a.description,
       a.agent_definition_id, a.schedule_rule_id, a.execution_principal_kind,
       a.execution_principal_id, a.target_kind, a.target_device_id,
       a.target_workspace_binding_id, a.required_capabilities_json,
       a.execution_model_alias, a.execution_budget_id, a.tool_policy_scope,
       a.required_policy_version, a.off_peak_eligibility_source,
       a.off_peak_allowed_route_aliases_json, a.off_peak_deny_automation_mutation,
       a.off_peak_deny_recursive_off_peak, a.off_peak_allow_background_processes,
       a.status, a.max_start_attempts, a.lease_ttl_seconds, a.heartbeat_interval_seconds,
       a.schedule_cursor_at, a.next_run_at, a.last_run_at, a.version,
       a.created_by_user_id, a.created_at, a.updated_at, a.queued_successor_max_age_seconds
FROM automation_definitions a
JOIN organizations o ON o.org_id = a.org_id
WHERE a.status = 'active'
  AND a.next_run_at IS NOT NULL
  AND a.next_run_at <= ?1
  AND o.state = 'active'
  AND a.schedule_rule_id IN (SELECT schedule_rule_id FROM automation_schedule_rules WHERE kind <> 'manual')
ORDER BY a.next_run_at ASC, a.automation_id ASC
LIMIT ?2
"#;

const SCHEDULE_RULE_BY_ID_SQL: &str = r#"
SELECT schedule_rule_id, org_id, kind, expression, timezone, dom_dow_mode, dst_policy,
       interval_every, interval_unit, anchor_at, scheduled_at, by_weekday_json,
       by_monthday_json, by_month_json, overlap_policy, missed_policy, catch_up_limit,
       canonical_json, version, created_at
FROM automation_schedule_rules
WHERE schedule_rule_id = ?1 AND org_id = ?2
LIMIT 1
"#;

const INSERT_SCHEDULE_RULE_SQL: &str = r#"
INSERT INTO automation_schedule_rules (
    schedule_rule_id, org_id, kind, expression, timezone, dom_dow_mode, dst_policy,
    interval_every, interval_unit, anchor_at, scheduled_at, by_weekday_json,
    by_monthday_json, by_month_json, overlap_policy, missed_policy, catch_up_limit,
    canonical_json, version, created_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
"#;

const INSERT_AUTOMATION_SQL: &str = r#"
INSERT INTO automation_definitions (
    automation_id, org_id, project_id, name, description, agent_definition_id,
    schedule_rule_id, execution_principal_kind, execution_principal_id, target_kind,
    target_device_id, target_workspace_binding_id, required_capabilities_json,
    execution_model_alias, execution_budget_id, tool_policy_scope, required_policy_version,
    off_peak_eligibility_source, off_peak_allowed_route_aliases_json,
    off_peak_deny_automation_mutation, off_peak_deny_recursive_off_peak,
    off_peak_allow_background_processes, status, max_start_attempts, lease_ttl_seconds,
    heartbeat_interval_seconds, schedule_cursor_at, next_run_at, last_run_at, version,
    created_by_user_id, created_at, updated_at, queued_successor_max_age_seconds
) VALUES (
    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
    ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, NULL, 1, ?29, ?29, ?30
)
"#;

const UPDATE_AUTOMATION_SQL: &str = r#"
UPDATE automation_definitions
SET name = ?3,
    description = ?4,
    project_id = ?5,
    agent_definition_id = ?6,
    schedule_rule_id = ?7,
    target_kind = ?8,
    target_device_id = ?9,
    target_workspace_binding_id = ?10,
    required_capabilities_json = ?11,
    execution_model_alias = ?12,
    execution_budget_id = ?13,
    tool_policy_scope = ?14,
    required_policy_version = ?15,
    off_peak_eligibility_source = ?16,
    off_peak_allowed_route_aliases_json = ?17,
    off_peak_deny_automation_mutation = ?18,
    off_peak_deny_recursive_off_peak = ?19,
    off_peak_allow_background_processes = ?20,
    max_start_attempts = ?21,
    lease_ttl_seconds = ?22,
    heartbeat_interval_seconds = ?23,
    queued_successor_max_age_seconds = ?24,
    version = version + 1,
    updated_at = ?25
WHERE automation_id = ?1 AND org_id = ?2 AND version = ?26
"#;

const SET_AUTOMATION_STATUS_SQL: &str = r#"
UPDATE automation_definitions
SET status = ?3,
    next_run_at = ?4,
    schedule_cursor_at = ?5,
    version = version + 1,
    updated_at = ?6
WHERE automation_id = ?1 AND org_id = ?2 AND version = ?7 AND status = ?8
"#;

/// Tombstone. Occurrences, leases, and schedule revisions are immutable history
/// and are never cascaded away, so a delete is a status transition and the
/// unique-active-name index stops excluding the row.
const SOFT_DELETE_AUTOMATION_SQL: &str = r#"
UPDATE automation_definitions
SET status = 'deleted',
    next_run_at = NULL,
    version = version + 1,
    updated_at = ?3
WHERE automation_id = ?1 AND org_id = ?2 AND version = ?4
  AND status NOT IN ('deleted', 'completed')
"#;

const ADVANCE_CURSOR_SQL: &str = r#"
UPDATE automation_definitions
SET schedule_cursor_at = ?3,
    next_run_at = ?4,
    last_run_at = COALESCE(?5, last_run_at),
    version = version + 1,
    updated_at = ?6
WHERE automation_id = ?1 AND org_id = ?2 AND schedule_cursor_at = ?7 AND status = 'active'
"#;

/// Scheduled work is keyed by `(automation_id, schedule_rule_id,
/// scheduled_for_utc)` and manual work by `(automation_id, trigger_key_digest)`.
/// The `WHERE NOT EXISTS` clause makes a redelivered generation pass a no-op for
/// that slot instead of a constraint failure that would also roll back the
/// authoritative cursor advance.
const INSERT_OCCURRENCE_SQL: &str = r#"
INSERT INTO automation_occurrences (
    occurrence_id, automation_id, org_id, project_id, schedule_rule_id, kind,
    scheduled_for_utc, trigger_key_digest, execution_principal_kind,
    execution_principal_id, off_peak_mode, policy_snapshot_id, policy_version,
    state, state_version, attempt, reason_code, run_id, blocked_by_occurrence_id,
    lease_expires_at, queued_at, started_at, finished_at, created_at, updated_at
)
SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 1, ?15, ?16, NULL,
       ?17, NULL, ?18, NULL, NULL, ?19, ?19
WHERE NOT EXISTS (
    SELECT 1 FROM automation_occurrences existing
    WHERE existing.automation_id = ?2
      AND (
        (?6 = 'scheduled' AND existing.kind = 'scheduled'
             AND existing.schedule_rule_id = ?5
             AND existing.scheduled_for_utc = ?7)
        OR
        (?6 <> 'scheduled' AND existing.trigger_key_digest = ?8)
      )
)
"#;

const OCCURRENCE_BY_ID_SQL: &str = r#"
SELECT o.occurrence_id, o.automation_id, o.org_id, o.project_id, o.schedule_rule_id, o.kind,
       o.scheduled_for_utc, o.trigger_key_digest, o.execution_principal_kind,
       o.execution_principal_id, o.off_peak_mode, o.policy_snapshot_id, o.policy_version,
       o.state, o.state_version, o.attempt, o.reason_code, o.run_id,
       o.blocked_by_occurrence_id, o.lease_expires_at, o.queued_at, o.started_at, o.finished_at,
       o.created_at, o.updated_at, r.version AS schedule_rule_version
FROM automation_occurrences o
JOIN automation_schedule_rules r ON r.schedule_rule_id = o.schedule_rule_id
WHERE o.occurrence_id = ?1 AND o.org_id = ?2
LIMIT 1
"#;

const OCCURRENCES_PAGE_SQL: &str = r#"
SELECT o.occurrence_id, o.automation_id, o.org_id, o.project_id, o.schedule_rule_id, o.kind,
       o.scheduled_for_utc, o.trigger_key_digest, o.execution_principal_kind,
       o.execution_principal_id, o.off_peak_mode, o.policy_snapshot_id, o.policy_version,
       o.state, o.state_version, o.attempt, o.reason_code, o.run_id,
       o.blocked_by_occurrence_id, o.lease_expires_at, o.queued_at, o.started_at, o.finished_at,
       o.created_at, o.updated_at, r.version AS schedule_rule_version
FROM automation_occurrences o
JOIN automation_schedule_rules r ON r.schedule_rule_id = o.schedule_rule_id
WHERE o.org_id = ?1 AND o.automation_id = ?2
  AND (?3 = '' OR o.state = ?3)
  AND (?4 = '' OR (o.created_at, o.occurrence_id) < (?4, ?5))
ORDER BY o.created_at DESC, o.occurrence_id DESC
LIMIT ?6
"#;

/// The predecessor the overlap decision reads: the newest occurrence of the
/// same automation that is still able to overlap a new slot. `ambiguous` is
/// included because an ambiguous predecessor is never safe to overlap.
const PREDECESSOR_SQL: &str = r#"
SELECT o.occurrence_id, o.automation_id, o.org_id, o.project_id, o.schedule_rule_id, o.kind,
       o.scheduled_for_utc, o.trigger_key_digest, o.execution_principal_kind,
       o.execution_principal_id, o.off_peak_mode, o.policy_snapshot_id, o.policy_version,
       o.state, o.state_version, o.attempt, o.reason_code, o.run_id,
       o.blocked_by_occurrence_id, o.lease_expires_at, o.queued_at, o.started_at, o.finished_at,
       o.created_at, o.updated_at, r.version AS schedule_rule_version
FROM automation_occurrences o
JOIN automation_schedule_rules r ON r.schedule_rule_id = o.schedule_rule_id
WHERE o.automation_id = ?1
  AND o.state IN ('pending', 'dispatching', 'leased', 'started', 'ambiguous')
  AND (?2 = '' OR o.occurrence_id <> ?2)
ORDER BY COALESCE(o.scheduled_for_utc, o.queued_at, o.created_at) DESC, o.occurrence_id DESC
LIMIT 1
"#;

/// `queue_one` allows at most ONE open successor. Two open rows would deadlock
/// the automation behind an unbounded queue.
const OPEN_QUEUED_SUCCESSOR_SQL: &str = r#"
SELECT o.occurrence_id, o.automation_id, o.org_id, o.project_id, o.schedule_rule_id, o.kind,
       o.scheduled_for_utc, o.trigger_key_digest, o.execution_principal_kind,
       o.execution_principal_id, o.off_peak_mode, o.policy_snapshot_id, o.policy_version,
       o.state, o.state_version, o.attempt, o.reason_code, o.run_id,
       o.blocked_by_occurrence_id, o.lease_expires_at, o.queued_at, o.started_at, o.finished_at,
       o.created_at, o.updated_at, r.version AS schedule_rule_version
FROM automation_occurrences o
JOIN automation_schedule_rules r ON r.schedule_rule_id = o.schedule_rule_id
WHERE o.automation_id = ?1
  AND o.queued_at IS NOT NULL
  AND o.state IN ('pending', 'dispatching')
  AND (?2 = '' OR o.occurrence_id <> ?2)
LIMIT 1
"#;

/// Device due work. Bounded by the caller, scoped to the token's own
/// organization, and restricted to occurrences the SERVER has already moved to
/// `dispatching` after its dispatch-time recheck. Minimum metadata only.
const DEVICE_DUE_OCCURRENCES_SQL: &str = r#"
SELECT o.occurrence_id, o.automation_id, o.org_id, o.project_id, o.schedule_rule_id, o.kind,
       o.scheduled_for_utc, o.execution_principal_kind, o.execution_principal_id,
       o.off_peak_mode, o.policy_snapshot_id, o.policy_version, o.state, o.state_version,
       o.attempt, o.scheduled_for_utc AS reason_code, NULL AS trigger_key_digest,
       o.run_id, o.blocked_by_occurrence_id, o.lease_expires_at, o.queued_at, o.started_at,
       o.finished_at, o.created_at, o.updated_at,
       d.lease_ttl_seconds, d.heartbeat_interval_seconds, d.required_capabilities_json,
       d.execution_model_alias, d.execution_budget_id, d.tool_policy_scope
FROM automation_occurrences o
JOIN automation_definitions d ON d.automation_id = o.automation_id
JOIN devices dev ON dev.device_id = ?1 AND dev.org_id = o.org_id AND dev.status = 'active'
JOIN organizations org ON org.org_id = o.org_id AND org.state = 'active'
WHERE o.org_id = ?2
  AND o.state = 'dispatching'
  AND o.queued_at IS NULL
  AND (o.scheduled_for_utc IS NULL OR o.scheduled_for_utc <= ?3)
  AND (d.target_kind = 'eligible_device' OR d.target_device_id = ?1)
  AND (d.target_workspace_binding_id IS NULL OR EXISTS (
        SELECT 1 FROM workspace_bindings b
        WHERE b.binding_id = d.target_workspace_binding_id
          AND b.device_id = ?1 AND b.org_id = o.org_id
      ))
  AND NOT EXISTS (
      SELECT 1 FROM automation_leases l
      WHERE l.occurrence_id = o.occurrence_id AND l.state = 'active'
  )
ORDER BY o.scheduled_for_ ASC, o.occurrence_id ASC
LIMIT ?4
"#;

const TRANSITION_OCCURRENCE_SQL: &str = r#"
UPDATE automation_occurrences
SET state = ?3,
    state_version = state_version + 1,
    reason_code = ?4,
    run_id = COALESCE(?5, run_id),
    lease_expires_at = ?6,
    queued_at = ?7,
    blocked_by_occurrence_id = ?8,
    started_at = COALESCE(started_at, ?9),
    finished_at = ?10,
    updated_at = ?11
WHERE occurrence_id = ?1 AND org_id = ?2 AND state = ?12 AND state_version = ?13
"#;

const INSERT_LEASE_SQL: &str = r#"
INSERT INTO automation_leases (
    lease_id, occurrence_id, org_id, device_id, state, attempt,
    lease_token_fingerprint, lease_version, lease_fence, claimed_at, expires_at,
    released_at, completed_at, version
) VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6, 1, 1, ?7, ?8, NULL, NULL, 1)
"#;

const LEASE_BY_ID_SQL: &str = r#"
SELECT lease_id, occurrence_id, org_id, device_id, state, attempt,
       lease_token_fingerprint, lease_version, lease_fence, claimed_at, expires_at,
       released_at, completed_at, version
FROM automation_leases
WHERE lease_id = ?1 AND org_id = ?2
LIMIT 1
"#;

const ACTIVE_LEASE_FOR_OCCURRENCE_SQL: &str = r#"
SELECT lease_id, occurrence_id, org_id, device_id, state, attempt,
       lease_token_fingerprint, lease_version, lease_fence, claimed_at, expires_at,
       released_at, completed_at, version
FROM automation_leases
WHERE occurrence_id = ?1 AND state = 'active'
LIMIT 1
"#;

const INSERT_ATTEMPT_SQL: &str = r#"
INSERT INTO automation_occurrence_attempts (
    attempt_id, occurrence_id, lease_id, attempt, outcome, run_id, reason_code,
    lease_version, lease_fence, recorded_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
"#;

const ATTEMPTS_SQL: &str = r#"
SELECT attempt_id, occurrence_id, lease_id, attempt, outcome, run_id, reason_code,
       lease_version, lease_fence, recorded_at
FROM automation_occurrence_attempts a
JOIN automation_occurrences o ON o.occurrence_id = a.occurrence_id
WHERE a.occurrence_id = ?1 AND o.org_id = ?2
ORDER BY a.recorded_at DESC, a.attempt_id DESC
LIMIT ?3
"#;

const RENEW_LEASE_SQL: &str = r#"
UPDATE automation_leases
SET expires_at = ?3,
    lease_version = lease_version + 1,
    version = version + 1
WHERE lease_id = ?1 AND occurrence_id = ?2 AND org_id = ?3
  AND state = 'active' AND lease_version = ?4 AND lease_fence = ?5
"#;

const SETTLE_LEASE_SQL: &str = r#"
UPDATE automation_leases
SET completed_at = ?3,
    version = version + 1
WHERE lease_id = ?1 AND occurrence_id = ?2 AND org_id = ?3
  AND state = 'active' AND lease_version = ?4 AND lease_fence = ?5
"#;

const CLOSE_LEASE_SQL: &str = r#"
UPDATE automation_leases
SET state = ?3,
    released_at = ?4,
    version = version + 1
WHERE lease_id = ?1 AND occurrence_id = ?2 AND org_id = ?3
  AND state = 'active' AND lease_version = ?5 AND lease_fence = ?6
"#;

/// Expired leases are resolved only while their occurrence is still
/// non-terminal. A settled occurrence therefore keeps its lease row as
/// authoritative attempt history instead of being re-expired into `ambiguous`.
const EXPIRED_LEASES_SQL: &str = r#"
SELECT l.lease_id, l.occurrence_id, l.org_id, l.device_id, l.state, l.attempt,
       l.lease_token_fingerprint, l.lease_version, l.lease_fence, l.claimed_at,
       l.expires_at, l.released_at, l.completed_at, l.version
FROM automation_leases l
JOIN automation_occurrences o ON o.occurrence_id = l.occurrence_id
WHERE l.state = 'active'
  AND l.expires_at <= ?1
  AND o.state IN ('dispatching', 'leased', 'started')
ORDER BY l.expires_at ASC, l.lease_id ASC
LIMIT ?2
"#;

const RUN_LINK_BY_ATTEMPT_SQL: &str = r#"
SELECT link_id, occurrence_id, org_id, run_id, lease_id, attempt, state, created_at, updated_at
FROM automation_run_links
WHERE occurrence_id = ?1 AND attempt = ?2
LIMIT 1
"#;

const INSERT_RUN_LINK_SQL: &str = r#"
INSERT INTO automation_run_links (
    link_id, occurrence_id, org_id, run_id, lease_id, attempt, state, created_at, updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
"#;

const UPDATE_RUN_LINK_STATE_SQL: &str = r#"
UPDATE automation_run_links
SET state = ?3, updated_at = ?4
WHERE link_id = ?1 AND org_id = ?2
"#;

/// The P05 run is created server-owned and correlated to the occurrence in the
/// same insert, so no host can execute a side effect before the correlation
/// exists. `external_id` is the occurrence ID, which makes the P05 agent
/// session discoverable and idempotent for repeated `start` calls.
const INSERT_AUTOMATION_SESSION_SQL: &str = r#"
INSERT INTO agent_sessions (
    agent_session_id, org_id, project_id, device_id, workspace_binding_id,
    agent_definition_id, agent_definition_version, external_id, title, lifecycle,
    version, created_by_user_id, created_at, updated_at
)
SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, 'active', 1, ?9, ?10, ?10
WHERE NOT EXISTS (
    SELECT 1 FROM agent_sessions s
    WHERE s.org_id = ?2 AND s.device_id = ?4 AND s.external_id = ?8
)
"#;

const INSERT_AUTOMATION_RUN_SQL: &str = r#"
INSERT INTO runs (
    run_id, org_id, project_id, agent_session_id, parent_run_id, attempt,
    agent_definition_id, agent_definition_version, principal_user_id, device_id,
    model_alias, route_id, route_version_id, state, failure_code, request_id,
    started_at, finished_at, version, state_version, created_at, updated_at,
    cancel_requested_at, resumed_from_run_id, workspace_binding_id,
    policy_snapshot_id, policy_version, automation_occurrence_id, automation_lease_id
)
SELECT ?1, ?2, ?3, s.agent_session_id, NULL, 1, ?4, ?5, ?6, ?7, ?8, NULL, NULL,
       'queued', NULL, ?9, NULL, NULL, 1, 1, ?10, ?10, NULL, NULL, ?11, ?12, ?13, ?14, ?15
FROM agent_sessions s
WHERE s.org_id = ?2 AND s.device_id = ?7 AND s.external_id = ?16 AND s.lifecycle = 'active'
"#;

/// The P05 agent session created for one occurrence, discovered by the
/// occurrence's `external_id`. A repeated `start` must return the SAME session so
/// the host's grant is idempotent.
const AUTOMATION_SESSION_BY_EXTERNAL_ID_SQL: &str = r#"
SELECT agent_session_id FROM agent_sessions
WHERE external_id = ?1 AND lifecycle = 'active'
ORDER BY created_at ASC, agent_session_id ASC
LIMIT 1
"#;

const RUN_LINK_ATTEMPT_EXISTS_SQL: &str = r#"
SELECT 1 AS present FROM automation_run_links
WHERE occurrence_id = ?1 AND attempt = ?2
LIMIT 1
"#;

const LICENSE_STATE_SQL: &str = r#"
SELECT state, grace_expires_at
FROM license_states
WHERE org_id = ?1
LIMIT 1
"#;

const PRINCIPAL_MEMBERSHIP_ACTIVE_SQL: &str = r#"
SELECT 1 AS active FROM memberships
WHERE org_id = ?1 AND user_id = ?2 AND status = 'active'
LIMIT 1
"#;

const EFFECTIVE_INTEGER_ENTITLEMENT_SQL: &str = r#"
SELECT value_json FROM entitlement_grants
WHERE org_id = ?1
  AND entitlement_key = ?2
  AND scope = 'organization'
  AND effective_at <= ?3
  AND (expires_at IS NULL OR expires_at > ?3)
  AND revoked_at IS NULL
ORDER BY CASE WHEN source = 'internal_override' THEN 1 ELSE 0 END DESC, effective_at DESC
LIMIT 1
"#;

const CURRENT_POLICY_VERSION_SQL: &str = r#"
SELECT COALESCE(MAX(policy_version), 0) AS policy_version
FROM policy_snapshots
WHERE org_id = ?1
"#;

// -----------------------------------------------------------------------------
// Records
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScheduleRuleRecord {
    pub schedule_rule_id: String,
    pub org_id: String,
    pub kind: String,
    pub expression: Option<String>,
    pub timezone: Option<String>,
    pub dom_dow_mode: Option<String>,
    pub dst_policy: Option<String>,
    pub interval_every: Option<i64>,
    pub interval_unit: Option<String>,
    pub anchor_at: Option<String>,
    pub scheduled_at: Option<String>,
    pub by_weekday_json: Option<String>,
    pub by_monthday_json: Option<String>,
    pub by_month_json: Option<String>,
    pub overlap_policy: String,
    pub missed_policy: String,
    pub catch_up_limit: Option<i64>,
    pub canonical_json: String,
    pub version: i64,
    pub created_at: String,
}

/// The normalized schedule plus the adapter-resolved zone, persisted as the
/// revision's authoritative `canonical_json`.
///
/// The Worker links no tz database, so `ZoneOffsets` is supplied by the caller
/// at definition-write time and stored with the revision. Dispatch therefore
/// never has to re-resolve a zone, and the same rule always yields the same
/// canonical UTC instant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredScheduleRevision {
    pub rule: ScheduleRule,
    pub zone: ZoneOffsets,
}

impl StoredScheduleRevision {
    pub fn new(rule: ScheduleRule, zone: ZoneOffsets) -> Self {
        Self { rule, zone }
    }

    pub fn to_canonical_json(&self) -> Result<String, DomainError> {
        serde_json::to_string(self).map_err(|_| DomainError::ScheduleInvalid)
    }

    pub fn from_canonical_json(value: &str) -> Result<Self, DomainError> {
        serde_json::from_str(value).map_err(|_| DomainError::ScheduleInvalid)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AutomationDefinitionRecord {
    pub automation_id: String,
    pub org_id: String,
    pub project_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub agent_definition_id: Option<String>,
    pub schedule_rule_id: String,
    pub execution_principal_kind: String,
    pub execution_principal_id: String,
    pub target_kind: String,
    pub target_device_id: Option<String>,
    pub target_workspace_binding_id: Option<String>,
    pub required_capabilities_json: String,
    pub execution_model_alias: Option<String>,
    pub execution_budget_id: Option<String>,
    pub tool_policy_scope: String,
    pub required_policy_version: Option<i64>,
    pub off_peak_eligibility_source: Option<String>,
    pub off_peak_allowed_route_aliases_json: Option<String>,
    pub off_peak_deny_automation_mutation: i64,
    pub off_peak_deny_recursive_off_peak: i64,
    pub off_peak_allow_background_processes: i64,
    pub status: String,
    pub max_start_attempts: i64,
    pub lease_ttl_seconds: i64,
    pub heartbeat_interval_seconds: i64,
    pub schedule_cursor_at: Option<String>,
    pub next_run_at: Option<String>,
    pub last_run_at: Option<String>,
    pub version: i64,
    pub created_by_user_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub queued_successor_max_age_seconds: i64,
}

impl AutomationDefinitionRecord {
    /// The frozen bounded retry policy, validated before it reaches a lease.
    pub fn execution_retry(&self) -> Result<ExecutionRetry, DomainError> {
        ExecutionRetry::new(
            u8::try_from(self.max_start_attempts)
                .map_err(|_| DomainError::AutomationInvalidState)?,
            u32::try_from(self.lease_ttl_seconds)
                .map_err(|_| DomainError::AutomationInvalidState)?,
            u32::try_from(self.heartbeat_interval_seconds)
                .map_err(|_| DomainError::AutomationInvalidState)?,
        )
        .validate()
    }

    /// The bounded queued-successor age that keeps a `queue_one` or
    /// `cancel_previous` successor from blocking its automation forever.
    pub const fn queued_successor_max_age_seconds(&self) -> i64 {
        self.queued_successor_max_age_seconds
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AutomationOccurrenceRecord {
    pub occurrence_id: String,
    pub automation_id: String,
    pub org_id: String,
    pub project_id: Option<String>,
    pub schedule_rule_id: String,
    pub kind: String,
    pub scheduled_for_utc: Option<String>,
    pub trigger_key_digest: Option<String>,
    pub execution_principal_kind: String,
    pub execution_principal_id: String,
    pub off_peak_mode: String,
    pub policy_snapshot_id: Option<String>,
    pub policy_version: Option<i64>,
    pub state: String,
    pub state_version: i64,
    pub attempt: i64,
    pub reason_code: Option<String>,
    pub run_id: Option<String>,
    pub blocked_by_occurrence_id: Option<String>,
    pub lease_expires_at: Option<String>,
    pub queued_at: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    /// The immutable schedule revision version that produced this slot. It comes
    /// from the revision row, never from a mutable definition.
    pub schedule_rule_version: i64,
}

impl AutomationOccurrenceRecord {
    pub fn state(&self) -> Result<OccurrenceState, DomainError> {
        OccurrenceState::parse(&self.state).ok_or(DomainError::AutomationInvalidState)
    }

    pub fn kind(&self) -> Result<OccurrenceKind, DomainError> {
        OccurrenceKind::parse(&self.kind).ok_or(DomainError::AutomationInvalidState)
    }

    pub fn fence(&self, lease: &ExecutionLeaseRecord) -> Result<LeaseFence, DomainError> {
        let lease_id = crate::core::ExecutionLeaseId::new(lease.lease_id.clone())
            .map_err(|_| DomainError::AutomationInvalidState)?;
        Ok(LeaseFence::new(
            lease_id,
            lease.lease_version,
            lease.lease_fence,
        ))
    }
}

/// A device due-work row. It deliberately carries no description, no
/// instruction reference, and no credential material: a device learns only what
/// it needs to claim and then calls `start` for authoritative context.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DueOccurrenceRecord {
    pub occurrence_id: String,
    pub automation_id: String,
    pub org_id: String,
    pub project_id: Option<String>,
    pub schedule_rule_id: String,
    pub kind: String,
    pub scheduled_for_utc: Option<String>,
    pub execution_principal_kind: String,
    pub execution_principal_id: String,
    pub off_peak_mode: String,
    pub policy_snapshot_id: Option<String>,
    pub policy_version: Option<i64>,
    pub state: String,
    pub state_version: i64,
    pub attempt: i64,
    pub reason_code: Option<String>,
    pub run_id: Option<String>,
    pub blocked_by_occurrence_id: Option<String>,
    pub lease_expires_at: Option<String>,
    pub queued_at: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub lease_ttl_seconds: i64,
    pub heartbeat_interval_seconds: i64,
    pub required_capabilities_json: String,
    pub execution_model_alias: Option<String>,
    pub execution_budget_id: Option<String>,
    pub tool_policy_scope: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ExecutionLeaseRecord {
    pub lease_id: String,
    pub occurrence_id: String,
    pub org_id: String,
    pub device_id: String,
    pub state: String,
    pub attempt: i64,
    pub lease_token_fingerprint: String,
    pub lease_version: i64,
    pub lease_fence: i64,
    pub claimed_at: String,
    pub expires_at: String,
    pub released_at: Option<String>,
    pub completed_at: Option<String>,
    pub version: i64,
}

/// The token fingerprint is security material: it is the only persisted proof of
/// the raw lease token, so `Debug` never prints it.
impl fmt::Debug for ExecutionLeaseRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutionLeaseRecord")
            .field("lease_id", &self.lease_id)
            .field("occurrence_id", &self.occurrence_id)
            .field("org_id", &self.org_id)
            .field("device_id", &self.device_id)
            .field("state", &self.state)
            .field("attempt", &self.attempt)
            .field("lease_token_fingerprint", &"[redacted]")
            .field("lease_version", &self.lease_version)
            .field("lease_fence", &self.lease_fence)
            .field("claimed_at", &self.claimed_at)
            .field("expires_at", &self.expires_at)
            .field("released_at", &self.released_at)
            .field("completed_at", &self.completed_at)
            .field("version", &self.version)
            .finish()
    }
}

impl ExecutionLeaseRecord {
    pub fn state(&self) -> Result<crate::modules::automations::LeaseState, DomainError> {
        crate::modules::automations::LeaseState::parse(&self.state)
            .ok_or(DomainError::AutomationInvalidState)
    }

    pub fn fence(&self) -> Result<LeaseFence, DomainError> {
        let lease_id = crate::core::ExecutionLeaseId::new(self.lease_id.clone())
            .map_err(|_| DomainError::AutomationInvalidState)?;
        Ok(LeaseFence::new(
            lease_id,
            self.lease_version,
            self.lease_fence,
        ))
    }

    /// Constant-time-ish comparison of a presented token fingerprint. A
    /// mismatch is reported as a fence failure so a caller cannot distinguish a
    /// wrong token from a superseded lease.
    pub fn matches_token(&self, fingerprint: &str) -> bool {
        constant_time_eq(
            self.lease_token_fingerprint.as_bytes(),
            fingerprint.as_bytes(),
        )
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OccurrenceAttemptRecord {
    pub attempt_id: String,
    pub occurrence_id: String,
    pub lease_id: Option<String>,
    pub attempt: i64,
    pub outcome: String,
    pub run_id: Option<String>,
    pub reason_code: Option<String>,
    pub lease_version: Option<i64>,
    pub lease_fence: Option<i64>,
    pub recorded_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AutomationRunLinkRecord {
    pub link_id: String,
    pub occurrence_id: String,
    pub org_id: String,
    pub run_id: String,
    pub lease_id: String,
    pub attempt: i64,
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Current-state facts the dispatcher must re-read at dispatch time. Values
/// captured when the schedule was created are never authority.
#[derive(Clone, Debug, Default)]
pub struct DispatchEligibility {
    pub organization_state: Option<String>,
    pub principal_membership_active: bool,
    pub current_policy_version: i64,
    pub license_state: Option<String>,
    pub license_grace_expires_at: Option<String>,
    pub max_active_automations: Option<i64>,
    pub active_automation_count: i64,
    pub now: Option<String>,
}

// -----------------------------------------------------------------------------
// Store errors
// -----------------------------------------------------------------------------

/// A repository failure with no caller-supplied text, so formatting or logging
/// it can never disclose an identifier, token, or request body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutomationStoreError {
    /// A precondition guard refused the batch. The caller re-reads
    /// authoritative state and reports a stable reason.
    Guarded,
    /// D1 or the Worker runtime is unavailable.
    Unavailable,
    /// A stored row is not interpretable as a P06 value.
    InvalidRow,
}

impl fmt::Display for AutomationStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Guarded => "automation precondition guard refused the batch",
            Self::Unavailable => "automation store unavailable",
            Self::InvalidRow => "automation row is invalid",
        };
        f.write_str(message)
    }
}

impl std::error::Error for AutomationStoreError {}

/// A guard statement aborts a D1 batch by violating a table constraint, so the
/// batch error text is the only signal that a write was refused on purpose.
pub fn is_guard_violation(error: &worker::Error) -> bool {
    let detail = format!("{error:?}");
    detail.contains("NOT NULL") || detail.contains("constraint")
}

// -----------------------------------------------------------------------------
// Inputs
// -----------------------------------------------------------------------------

pub struct NewScheduleRuleInput<'a> {
    pub schedule_rule_id: &'a str,
    pub org_id: &'a str,
    pub kind: &'a str,
    pub expression: Option<&'a str>,
    pub timezone: Option<&'a str>,
    pub dom_dow_mode: Option<&'a str>,
    pub dst_policy: Option<&'a str>,
    pub interval_every: Option<i64>,
    pub interval_unit: Option<&'a str>,
    pub anchor_at: Option<&'a str>,
    pub scheduled_at: Option<&'a str>,
    pub by_weekday_json: Option<&'a str>,
    pub by_monthday_json: Option<&'a str>,
    pub by_month_json: Option<&'a str>,
    pub overlap_policy: &'a str,
    pub missed_policy: &'a str,
    pub catch_up_limit: Option<i64>,
    pub canonical_json: &'a str,
}

/// The columns the repository owns. Optional `None` values are passed straight
/// through; the caller has already resolved them from the authorized scope.
#[allow(clippy::too_many_arguments)]
pub struct NewAutomationInput<'a> {
    pub automation_id: &'a str,
    pub org_id: &'a str,
    pub project_id: Option<&'a str>,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub agent_definition_id: Option<&'a str>,
    pub schedule_rule_id: &'a str,
    pub execution_principal_kind: &'a str,
    pub execution_principal_id: &'a str,
    pub target_kind: &'a str,
    pub target_device_id: Option<&'a str>,
    pub target_workspace_binding_id: Option<&'a str>,
    pub required_capabilities_json: &'a str,
    pub execution_model_alias: Option<&'a str>,
    pub execution_budget_id: Option<&'a str>,
    pub tool_policy_scope: &'a str,
    pub required_policy_version: Option<i64>,
    pub off_peak_eligibility_source: Option<&'a str>,
    pub off_peak_allowed_route_aliases_json: Option<&'a str>,
    pub off_peak_deny_automation_mutation: i64,
    pub off_peak_deny_recursive_off_peak: i64,
    pub off_peak_allow_background_processes: i64,
    pub max_start_attempts: i64,
    pub lease_ttl_seconds: i64,
    pub heartbeat_interval_seconds: i64,
    pub schedule_cursor_at: &'a str,
    pub next_run_at: Option<&'a str>,
    pub created_by_user_id: &'a str,
    pub queued_successor_max_age_seconds: i64,
}

#[allow(clippy::too_many_arguments)]
pub struct AutomationUpdateInput<'a> {
    pub automation_id: &'a str,
    pub org_id: &'a str,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub project_id: Option<&'a str>,
    pub agent_definition_id: Option<&'a str>,
    pub schedule_rule_id: &'a str,
    pub target_kind: &'a str,
    pub target_device_id: Option<&'a str>,
    pub target_workspace_binding_id: Option<&'a str>,
    pub required_capabilities_json: &'a str,
    pub execution_model_alias: Option<&'a str>,
    pub execution_budget_id: Option<&'a str>,
    pub tool_policy_scope: &'a str,
    pub required_policy_version: Option<i64>,
    pub off_peak_eligibility_source: Option<&'a str>,
    pub off_peak_allowed_route_aliases_json: Option<&'a str>,
    pub off_peak_deny_automation_mutation: i64,
    pub off_peak_deny_recursive_off_peak: i64,
    pub off_peak_allow_background_processes: i64,
    pub max_start_attempts: i64,
    pub lease_ttl_seconds: i64,
    pub heartbeat_interval_seconds: i64,
    pub queued_successor_max_age_seconds: i64,
    pub now: &'a Timestamp,
    pub expected_version: i64,
}

pub struct NewOccurrenceInput<'a> {
    pub occurrence_id: &'a str,
    pub automation_id: &'a str,
    pub org_id: &'a str,
    pub project_id: Option<&'a str>,
    pub schedule_rule_id: &'a str,
    pub kind: &'a str,
    pub scheduled_for_utc: Option<&'a str>,
    pub trigger_key_digest: Option<&'a str>,
    pub execution_principal_kind: &'a str,
    pub execution_principal_id: &'a str,
    pub off_peak_mode: &'a str,
    pub policy_snapshot_id: Option<&'a str>,
    pub policy_version: Option<i64>,
    /// A `pending` occurrence, or the terminal state a deliberate skip
    /// produced. A skipped slot never occupies a non-terminal state.
    pub state: &'a str,
    pub attempt: i64,
    pub reason_code: Option<&'a str>,
    pub blocked_by_occurrence_id: Option<&'a str>,
    pub queued_at: Option<&'a str>,
    pub now: &'a Timestamp,
}

/// One compare-and-set occurrence transition.
pub struct OccurrenceTransition<'a> {
    pub occurrence_id: &'a str,
    pub org_id: &'a str,
    pub next_state: &'a str,
    pub reason_code: Option<&'a str>,
    pub run_id: Option<&'a str>,
    pub lease_expires_at: Option<&'a str>,
    pub queued_at: Option<&'a str>,
    pub blocked_by_occurrence_id: Option<&'a str>,
    pub started_at: Option<&'a str>,
    pub finished_at: Option<&'a str>,
    pub now: &'a Timestamp,
    pub expected_state: &'a str,
    pub expected_state_version: i64,
}

pub struct NewLeaseInput<'a> {
    pub lease_id: &'a str,
    pub occurrence_id: &'a str,
    pub org_id: &'a str,
    pub device_id: &'a str,
    pub attempt: i64,
    /// SHA-256 of the one-time raw lease token. The raw token is never bound.
    pub lease_token_fingerprint: &'a str,
    pub claimed_at: &'a str,
    pub expires_at: &'a str,
}

pub struct NewAttemptInput<'a> {
    pub attempt_id: &'a str,
    pub occurrence_id: &'a str,
    pub lease_id: Option<&'a str>,
    pub attempt: i64,
    pub outcome: &'a str,
    pub run_id: Option<&'a str>,
    pub reason_code: Option<&'a str>,
    pub lease_version: Option<i64>,
    pub lease_fence: Option<i64>,
    pub recorded_at: &'a str,
}

pub struct NewRunLinkInput<'a> {
    pub link_id: &'a str,
    pub occurrence_id: &'a str,
    pub org_id: &'a str,
    pub run_id: &'a str,
    pub lease_id: &'a str,
    pub attempt: i64,
    pub state: &'a str,
    pub now: &'a Timestamp,
}

#[allow(clippy::too_many_arguments)]
pub struct NewAutomationRunInput<'a> {
    pub run_id: &'a str,
    pub agent_session_id: &'a str,
    pub org_id: &'a str,
    pub project_id: &'a str,
    pub device_id: &'a str,
    pub workspace_binding_id: Option<&'a str>,
    pub agent_definition_id: &'a str,
    pub agent_definition_version: i64,
    pub external_id: &'a str,
    pub created_by_user_id: &'a str,
    pub model_alias: Option<&'a str>,
    pub request_id: &'a str,
    pub policy_snapshot_id: Option<&'a str>,
    pub policy_version: Option<i64>,
    pub occurrence_id: &'a str,
    pub lease_id: &'a str,
    pub now: &'a Timestamp,
}

// -----------------------------------------------------------------------------
// Repository
// -----------------------------------------------------------------------------

/// D1 persistence for the P06 automation control plane.
pub struct AutomationsRepository<'a> {
    database: &'a D1Adapter,
}

pub type AutomationRepository<'a> = AutomationsRepository<'a>;

impl<'a> AutomationsRepository<'a> {
    pub const fn new(database: &'a D1Adapter) -> Self {
        Self { database }
    }

    // -- definitions ---------------------------------------------------------

    pub async fn find_automation(
        &self,
        org_id: &str,
        automation_id: &str,
    ) -> worker::Result<Option<AutomationDefinitionRecord>> {
        self.database
            .prepare(
                AUTOMATION_BY_ID_SQL,
                &[BindValue::Text(automation_id), BindValue::Text(org_id)],
            )?
            .first::<AutomationDefinitionRecord>(None)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn list_automations(
        &self,
        org_id: &str,
        user_id: &str,
        manager: bool,
        status: Option<&str>,
        project_id: Option<&str>,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<AutomationDefinitionRecord>> {
        let (cursor_updated, cursor_id) = cursor.unwrap_or(("", ""));
        self.database
            .prepare(
                AUTOMATIONS_PAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(status.unwrap_or("")),
                    BindValue::Text(project_id.unwrap_or("")),
                    BindValue::Integer(i32::from(manager)),
                    BindValue::Text(user_id),
                    BindValue::Text(cursor_updated),
                    BindValue::Text(cursor_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<AutomationDefinitionRecord>()
    }

    pub async fn active_automation_count(&self, org_id: &str) -> worker::Result<i64> {
        let row = self
            .database
            .prepare(ACTIVE_AUTOMATION_COUNT_SQL, &[BindValue::Text(org_id)])?
            .first::<Value>(None)
            .await?
            .ok_or_else(|| worker::Error::RustError("automation count missing".into()))?;
        Ok(row
            .get("active_count")
            .and_then(Value::as_i64)
            .unwrap_or_default())
    }

    /// Bounded scheduler selection. Only an `active` automation in an `active`
    /// organization with a due `next_run_at` and a clock schedule is returned.
    pub async fn list_due_automations(
        &self,
        now: &str,
        limit: i32,
    ) -> worker::Result<Vec<AutomationDefinitionRecord>> {
        self.database
            .prepare(
                DUE_AUTOMATIONS_SQL,
                &[BindValue::Text(now), BindValue::Integer(limit)],
            )?
            .all()
            .await?
            .results::<AutomationDefinitionRecord>()
    }

    pub async fn find_schedule_rule(
        &self,
        org_id: &str,
        schedule_rule_id: &str,
    ) -> worker::Result<Option<ScheduleRuleRecord>> {
        self.database
            .prepare(
                SCHEDULE_RULE_BY_ID_SQL,
                &[BindValue::Text(schedule_rule_id), BindValue::Text(org_id)],
            )?
            .first::<ScheduleRuleRecord>(None)
            .await
    }

    pub fn insert_schedule_rule_statement(
        &self,
        input: &NewScheduleRuleInput<'_>,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_SCHEDULE_RULE_SQL,
            &[
                BindValue::Text(input.schedule_rule_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.kind),
                input.expression.map_or(BindValue::Null, BindValue::Text),
                input.timezone.map_or(BindValue::Null, BindValue::Text),
                input.dom_dow_mode.map_or(BindValue::Null, BindValue::Text),
                input.dst_policy.map_or(BindValue::Null, BindValue::Text),
                input
                    .interval_every
                    .map_or(BindValue::Null, BindValue::Int64),
                input.interval_unit.map_or(BindValue::Null, BindValue::Text),
                input.anchor_at.map_or(BindValue::Null, BindValue::Text),
                input.scheduled_at.map_or(BindValue::Null, BindValue::Text),
                input
                    .by_weekday_json
                    .map_or(BindValue::Null, BindValue::Text),
                input
                    .by_monthday_json
                    .map_or(BindValue::Null, BindValue::Text),
                input.by_month_json.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.overlap_policy),
                BindValue::Text(input.missed_policy),
                input
                    .catch_up_limit
                    .map_or(BindValue::Null, BindValue::Int64),
                BindValue::Text(input.canonical_json),
                BindValue::Int64(1),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_automation_statement(
        &self,
        input: &NewAutomationInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_AUTOMATION_SQL,
            &[
                BindValue::Text(input.automation_id),
                BindValue::Text(input.org_id),
                input.project_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.name),
                input.description.map_or(BindValue::Null, BindValue::Text),
                input
                    .agent_definition_id
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.schedule_rule_id),
                BindValue::Text(input.execution_principal_kind),
                BindValue::Text(input.execution_principal_id),
                BindValue::Text(input.target_kind),
                input
                    .target_device_id
                    .map_or(BindValue::Null, BindValue::Text),
                input
                    .target_workspace_binding_id
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.required_capabilities_json),
                input
                    .execution_model_alias
                    .map_or(BindValue::Null, BindValue::Text),
                input
                    .execution_budget_id
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.tool_policy_scope),
                input
                    .required_policy_version
                    .map_or(BindValue::Null, BindValue::Int64),
                input
                    .off_peak_eligibility_source
                    .map_or(BindValue::Null, BindValue::Text),
                input
                    .off_peak_allowed_route_aliases_json
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Int64(input.off_peak_deny_automation_mutation),
                BindValue::Int64(input.off_peak_deny_recursive_off_peak),
                BindValue::Int64(input.off_peak_allow_background_processes),
                BindValue::Text("active"),
                BindValue::Int64(input.max_start_attempts),
                BindValue::Int64(input.lease_ttl_seconds),
                BindValue::Int64(input.heartbeat_interval_seconds),
                BindValue::Text(input.schedule_cursor_at),
                input.next_run_at.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.created_by_user_id),
                BindValue::Int64(input.queued_successor_max_age_seconds),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_automation_statement(
        &self,
        input: &AutomationUpdateInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_AUTOMATION_SQL,
            &[
                BindValue::Text(input.automation_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.name),
                input.description.map_or(BindValue::Null, BindValue::Text),
                input.project_id.map_or(BindValue::Null, BindValue::Text),
                input
                    .agent_definition_id
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.schedule_rule_id),
                BindValue::Text(input.target_kind),
                input
                    .target_device_id
                    .map_or(BindValue::Null, BindValue::Text),
                input
                    .target_workspace_binding_id
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.required_capabilities_json),
                input
                    .execution_model_alias
                    .map_or(BindValue::Null, BindValue::Text),
                input
                    .execution_budget_id
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.tool_policy_scope),
                input
                    .required_policy_version
                    .map_or(BindValue::Null, BindValue::Int64),
                input
                    .off_peak_eligibility_source
                    .map_or(BindValue::Null, BindValue::Text),
                input
                    .off_peak_allowed_route_aliases_json
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Int64(input.off_peak_deny_automation_mutation),
                BindValue::Int64(input.off_peak_deny_recursive_off_peak),
                BindValue::Int64(input.off_peak_allow_background_processes),
                BindValue::Int64(input.max_start_attempts),
                BindValue::Int64(input.lease_ttl_seconds),
                BindValue::Int64(input.heartbeat_interval_seconds),
                BindValue::Int64(input.queued_successor_max_age_seconds),
                BindValue::Text(input.now.as_str()),
                BindValue::Int64(input.expected_version),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn set_automation_status_statement(
        &self,
        automation_id: &str,
        org_id: &str,
        next_status: &str,
        next_run_at: Option<&str>,
        schedule_cursor_at: Option<&str>,
        now: &Timestamp,
        expected_version: i64,
        expected_status: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            SET_AUTOMATION_STATUS_SQL,
            &[
                BindValue::Text(automation_id),
                BindValue::Text(org_id),
                BindValue::Text(next_status),
                next_run_at.map_or(BindValue::Null, BindValue::Text),
                schedule_cursor_at.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(now.as_str()),
                BindValue::Int64(expected_version),
                BindValue::Text(expected_status),
            ],
        )
    }

    pub fn soft_delete_automation_statement(
        &self,
        automation_id: &str,
        org_id: &str,
        now: &Timestamp,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            SOFT_DELETE_AUTOMATION_SQL,
            &[
                BindValue::Text(automation_id),
                BindValue::Text(org_id),
                BindValue::Text(now.as_str()),
                BindValue::Int64(expected_version),
            ],
        )
    }

    /// Compare-and-set the authoritative schedule cursor. The cursor is the
    /// only thing that makes generation idempotent, so it is never inferred from
    /// a device's last run.
    #[allow(clippy::too_many_arguments)]
    pub fn advance_schedule_cursor_statement(
        &self,
        automation_id: &str,
        org_id: &str,
        new_cursor: &str,
        next_run_at: Option<&str>,
        last_run_at: Option<&str>,
        now: &Timestamp,
        expected_cursor: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            ADVANCE_CURSOR_SQL,
            &[
                BindValue::Text(automation_id),
                BindValue::Text(org_id),
                BindValue::Text(new_cursor),
                next_run_at.map_or(BindValue::Null, BindValue::Text),
                last_run_at.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(now.as_str()),
                BindValue::Text(expected_cursor),
            ],
        )
    }

    /// Restart the cursor without requiring the automation to be `active`.
    ///
    /// A schedule edit, a pause, and a resume all restart the window at the
    /// current instant. Restricting the restart to `active` would make a
    /// schedule edit on a paused automation fail for no product reason, and the
    /// cursor is inert while the automation is not dispatching anyway. The
    /// compare-and-set on the previous cursor text is what prevents a concurrent
    /// writer from winning twice.
    pub fn restart_schedule_cursor_statement(
        &self,
        automation_id: &str,
        org_id: &str,
        new_cursor: &str,
        next_run_at: Option<&str>,
        now: &Timestamp,
        expected_cursor: &str,
    ) -> worker::Result<D1PreparedStatement> {
        const RESTART_CURSOR_SQL: &str = r#"
UPDATE automation_definitions
SET schedule_cursor_at = ?3,
    next_run_at = COALESCE(?4, next_run_at),
    version = version + 1,
    updated_at = ?5
WHERE automation_id = ?1 AND org_id = ?2
  AND COALESCE(schedule_cursor_at, '') = ?6
  AND status NOT IN ('deleted', 'completed')
"#;
        self.database.prepare(
            RESTART_CURSOR_SQL,
            &[
                BindValue::Text(automation_id),
                BindValue::Text(org_id),
                BindValue::Text(new_cursor),
                next_run_at.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(now.as_str()),
                BindValue::Text(expected_cursor),
            ],
        )
    }

    // -- occurrences ---------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn insert_occurrence_statement(
        &self,
        input: &NewOccurrenceInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_OCCURRENCE_SQL,
            &[
                BindValue::Text(input.occurrence_id),
                BindValue::Text(input.automation_id),
                BindValue::Text(input.org_id),
                input.project_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.schedule_rule_id),
                BindValue::Text(input.kind),
                input
                    .scheduled_for_utc
                    .map_or(BindValue::Null, BindValue::Text),
                input
                    .trigger_key_digest
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.execution_principal_kind),
                BindValue::Text(input.execution_principal_id),
                BindValue::Text(input.off_peak_mode),
                input
                    .policy_snapshot_id
                    .map_or(BindValue::Null, BindValue::Text),
                input
                    .policy_version
                    .map_or(BindValue::Null, BindValue::Int64),
                BindValue::Text(input.state),
                BindValue::Int64(input.attempt),
                input.reason_code.map_or(BindValue::Null, BindValue::Text),
                input
                    .blocked_by_occurrence_id
                    .map_or(BindValue::Null, BindValue::Text),
                input.queued_at.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.now.as_str()),
            ],
        )
    }

    pub async fn find_occurrence(
        &self,
        org_id: &str,
        occurrence_id: &str,
    ) -> worker::Result<Option<AutomationOccurrenceRecord>> {
        self.database
            .prepare(
                OCCURRENCE_BY_ID_SQL,
                &[BindValue::Text(occurrence_id), BindValue::Text(org_id)],
            )?
            .first::<AutomationOccurrenceRecord>(None)
            .await
    }

    pub async fn list_occurrences(
        &self,
        org_id: &str,
        automation_id: &str,
        state: Option<&str>,
        cursor: Option<(&str, &str)>,
        limit: i32,
    ) -> worker::Result<Vec<AutomationOccurrenceRecord>> {
        let (cursor_created, cursor_id) = cursor.unwrap_or(("", ""));
        self.database
            .prepare(
                OCCURRENCES_PAGE_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(automation_id),
                    BindValue::Text(state.unwrap_or("")),
                    BindValue::Text(cursor_created),
                    BindValue::Text(cursor_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<AutomationOccurrenceRecord>()
    }

    pub async fn find_predecessor(
        &self,
        automation_id: &str,
        exclude_occurrence_id: &str,
    ) -> worker::Result<Option<AutomationOccurrenceRecord>> {
        self.database
            .prepare(
                PREDECESSOR_SQL,
                &[
                    BindValue::Text(automation_id),
                    BindValue::Text(exclude_occurrence_id),
                ],
            )?
            .first::<AutomationOccurrenceRecord>(None)
            .await
    }

    pub async fn find_open_queued_successor(
        &self,
        automation_id: &str,
        exclude_occurrence_id: &str,
    ) -> worker::Result<Option<AutomationOccurrenceRecord>> {
        self.database
            .prepare(
                OPEN_QUEUED_SUCCESSOR_SQL,
                &[
                    BindValue::Text(automation_id),
                    BindValue::Text(exclude_occurrence_id),
                ],
            )?
            .first::<AutomationOccurrenceRecord>(None)
            .await
    }

    /// Compare-and-set the occurrence projection. `expected_state` and
    /// `expected_state_version` are the only accepted preconditions, so a
    /// concurrent transition or a redelivered job cannot overwrite newer state.
    #[allow(clippy::too_many_arguments)]
    pub fn transition_occurrence_statement(
        &self,
        input: &OccurrenceTransition<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            TRANSITION_OCCURRENCE_SQL,
            &[
                BindValue::Text(input.occurrence_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.next_state),
                input.reason_code.map_or(BindValue::Null, BindValue::Text),
                input.run_id.map_or(BindValue::Null, BindValue::Text),
                input
                    .lease_expires_at
                    .map_or(BindValue::Null, BindValue::Text),
                input.queued_at.map_or(BindValue::Null, BindValue::Text),
                input
                    .blocked_by_occurrence_id
                    .map_or(BindValue::Null, BindValue::Text),
                input.started_at.map_or(BindValue::Null, BindValue::Text),
                input.finished_at.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.now.as_str()),
                BindValue::Text(input.expected_state),
                BindValue::Int64(input.expected_state_version),
            ],
        )
    }

    // -- leases --------------------------------------------------------------

    /// Bounded, minimum-metadata due work for one device token. The occurrence
    /// must already be `dispatching`, which is the server's durable record that
    /// its dispatch-time recheck passed.
    pub async fn list_due_occurrences(
        &self,
        device_id: &str,
        org_id: &str,
        now: &str,
        limit: i32,
    ) -> worker::Result<Vec<DueOccurrenceRecord>> {
        self.database
            .prepare(
                DEVICE_DUE_OCCURRENCES_SQL,
                &[
                    BindValue::Text(device_id),
                    BindValue::Text(org_id),
                    BindValue::Text(now),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<DueOccurrenceRecord>()
    }

    pub async fn find_lease(
        &self,
        org_id: &str,
        lease_id: &str,
    ) -> worker::Result<Option<ExecutionLeaseRecord>> {
        self.database
            .prepare(
                LEASE_BY_ID_SQL,
                &[BindValue::Text(lease_id), BindValue::Text(org_id)],
            )?
            .first::<ExecutionLeaseRecord>(None)
            .await
    }

    pub async fn find_active_lease(
        &self,
        occurrence_id: &str,
    ) -> worker::Result<Option<ExecutionLeaseRecord>> {
        self.database
            .prepare(
                ACTIVE_LEASE_FOR_OCCURRENCE_SQL,
                &[BindValue::Text(occurrence_id)],
            )?
            .first::<ExecutionLeaseRecord>(None)
            .await
    }

    pub fn insert_lease_statement(
        &self,
        input: &NewLeaseInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_LEASE_SQL,
            &[
                BindValue::Text(input.lease_id),
                BindValue::Text(input.occurrence_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.device_id),
                BindValue::Int64(input.attempt),
                BindValue::Text(input.lease_token_fingerprint),
                BindValue::Text(input.claimed_at),
                BindValue::Text(input.expires_at),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn renew_lease_statement(
        &self,
        lease_id: &str,
        occurrence_id: &str,
        org_id: &str,
        expires_at: &str,
        expected_lease_version: i64,
        expected_lease_fence: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            RENEW_LEASE_SQL,
            &[
                BindValue::Text(lease_id),
                BindValue::Text(occurrence_id),
                BindValue::Text(org_id),
                BindValue::Text(expires_at),
                BindValue::Int64(expected_lease_version),
                BindValue::Int64(expected_lease_fence),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn settle_lease_statement(
        &self,
        lease_id: &str,
        occurrence_id: &str,
        org_id: &str,
        completed_at: &str,
        expected_lease_version: i64,
        expected_lease_fence: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            SETTLE_LEASE_SQL,
            &[
                BindValue::Text(lease_id),
                BindValue::Text(occurrence_id),
                BindValue::Text(org_id),
                BindValue::Text(completed_at),
                BindValue::Int64(expected_lease_version),
                BindValue::Int64(expected_lease_fence),
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn close_lease_statement(
        &self,
        lease_id: &str,
        occurrence_id: &str,
        org_id: &str,
        next_state: &str,
        closed_at: &str,
        expected_lease_version: i64,
        expected_lease_fence: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            CLOSE_LEASE_SQL,
            &[
                BindValue::Text(lease_id),
                BindValue::Text(occurrence_id),
                BindValue::Text(org_id),
                BindValue::Text(next_state),
                BindValue::Text(closed_at),
                BindValue::Int64(expected_lease_version),
                BindValue::Int64(expected_lease_fence),
            ],
        )
    }

    /// Expired leases whose occurrence is still non-terminal. A settled
    /// occurrence keeps its lease as attempt history and is never re-expired.
    pub async fn list_expired_leases(
        &self,
        now: &str,
        limit: i32,
    ) -> worker::Result<Vec<ExecutionLeaseRecord>> {
        self.database
            .prepare(
                EXPIRED_LEASES_SQL,
                &[BindValue::Text(now), BindValue::Integer(limit)],
            )?
            .all()
            .await?
            .results::<ExecutionLeaseRecord>()
    }

    pub fn insert_attempt_statement(
        &self,
        input: &NewAttemptInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_ATTEMPT_SQL,
            &[
                BindValue::Text(input.attempt_id),
                BindValue::Text(input.occurrence_id),
                input.lease_id.map_or(BindValue::Null, BindValue::Text),
                BindValue::Int64(input.attempt),
                BindValue::Text(input.outcome),
                input.run_id.map_or(BindValue::Null, BindValue::Text),
                input.reason_code.map_or(BindValue::Null, BindValue::Text),
                input
                    .lease_version
                    .map_or(BindValue::Null, BindValue::Int64),
                input.lease_fence.map_or(BindValue::Null, BindValue::Int64),
                BindValue::Text(input.recorded_at),
            ],
        )
    }

    pub async fn list_attempts(
        &self,
        org_id: &str,
        occurrence_id: &str,
        limit: i32,
    ) -> worker::Result<Vec<OccurrenceAttemptRecord>> {
        self.database
            .prepare(
                ATTEMPTS_SQL,
                &[
                    BindValue::Text(occurrence_id),
                    BindValue::Text(org_id),
                    BindValue::Integer(limit),
                ],
            )?
            .all()
            .await?
            .results::<OccurrenceAttemptRecord>()
    }

    // -- P05 run correlation -------------------------------------------------

    pub async fn find_run_link(
        &self,
        occurrence_id: &str,
        attempt: i64,
    ) -> worker::Result<Option<AutomationRunLinkRecord>> {
        self.database
            .prepare(
                RUN_LINK_BY_ATTEMPT_SQL,
                &[BindValue::Text(occurrence_id), BindValue::Int64(attempt)],
            )?
            .first::<AutomationRunLinkRecord>(None)
            .await
    }

    /// `true` is the server's durable proof that a P05 run already exists for
    /// this attempt. It is the only evidence that distinguishes a safe requeue
    /// from an `ambiguous` outcome.
    /// Discover the P05 agent session an occurrence's run was created under.
    pub async fn find_automation_session(
        &self,
        occurrence_id: &str,
    ) -> worker::Result<Option<String>> {
        let row = self
            .database
            .prepare(
                AUTOMATION_SESSION_BY_EXTERNAL_ID_SQL,
                &[BindValue::Text(occurrence_id)],
            )?
            .first::<AutomationSessionRow>(None)
            .await?;
        Ok(row.map(|row| row.agent_session_id))
    }

    pub async fn run_link_exists(&self, occurrence_id: &str, attempt: i64) -> worker::Result<bool> {
        Ok(self
            .database
            .prepare(
                RUN_LINK_ATTEMPT_EXISTS_SQL,
                &[BindValue::Text(occurrence_id), BindValue::Int64(attempt)],
            )?
            .first::<Value>(None)
            .await?
            .is_some())
    }

    pub fn insert_run_link_statement(
        &self,
        input: &NewRunLinkInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_RUN_LINK_SQL,
            &[
                BindValue::Text(input.link_id),
                BindValue::Text(input.occurrence_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.run_id),
                BindValue::Text(input.lease_id),
                BindValue::Int64(input.attempt),
                BindValue::Text(input.state),
                BindValue::Text(input.now.as_str()),
            ],
        )
    }

    pub fn update_run_link_state_statement(
        &self,
        link_id: &str,
        org_id: &str,
        state: &str,
        now: &Timestamp,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            UPDATE_RUN_LINK_STATE_SQL,
            &[
                BindValue::Text(link_id),
                BindValue::Text(org_id),
                BindValue::Text(state),
                BindValue::Text(now.as_str()),
            ],
        )
    }

    /// Idempotent insert of the P05 agent session for one occurrence. A
    /// repeated `start` discovers the same session instead of creating a second
    /// one.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_automation_session_statement(
        &self,
        input: &NewAutomationRunInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_AUTOMATION_SESSION_SQL,
            &[
                BindValue::Text(input.agent_session_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.project_id),
                BindValue::Text(input.device_id),
                input
                    .workspace_binding_id
                    .map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.agent_definition_id),
                BindValue::Int64(input.agent_definition_version),
                BindValue::Text(input.external_id),
                BindValue::Text(input.created_by_user_id),
                BindValue::Text(input.now.as_str()),
            ],
        )
    }

    /// Insert the correlated P05 run. The occurrence/lease correlation columns
    /// are written by this same statement, so the link is durable before the
    /// host can execute any side effect.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_automation_run_statement(
        &self,
        input: &NewAutomationRunInput<'_>,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            INSERT_AUTOMATION_RUN_SQL,
            &[
                BindValue::Text(input.run_id),
                BindValue::Text(input.org_id),
                BindValue::Text(input.project_id),
                BindValue::Text(input.agent_definition_id),
                BindValue::Int64(input.agent_definition_version),
                BindValue::Text(input.created_by_user_id),
                BindValue::Text(input.device_id),
                input.model_alias.map_or(BindValue::Null, BindValue::Text),
                BindValue::Text(input.request_id),
                BindValue::Text(input.now.as_str()),
                input
                    .workspace_binding_id
                    .map_or(BindValue::Null, BindValue::Text),
                input
                    .policy_snapshot_id
                    .map_or(BindValue::Null, BindValue::Text),
                input
                    .policy_version
                    .map_or(BindValue::Null, BindValue::Int64),
                BindValue::Text(input.occurrence_id),
                BindValue::Text(input.lease_id),
                BindValue::Text(input.external_id),
            ],
        )
    }

    // -- dispatch-time eligibility reads -------------------------------------

    pub async fn license_state(
        &self,
        org_id: &str,
    ) -> worker::Result<Option<(String, Option<String>)>> {
        self.database
            .prepare(LICENSE_STATE_SQL, &[BindValue::Text(org_id)])?
            .first::<LicenseStateRow>(None)
            .await
            .map(|row| row.map(|row| (row.state, row.grace_expires_at)))
    }

    pub async fn principal_membership_active(
        &self,
        org_id: &str,
        user_id: &str,
    ) -> worker::Result<bool> {
        Ok(self
            .database
            .prepare(
                PRINCIPAL_MEMBERSHIP_ACTIVE_SQL,
                &[BindValue::Text(org_id), BindValue::Text(user_id)],
            )?
            .first::<Value>(None)
            .await?
            .is_some())
    }

    /// The effective integer entitlement. `None` means "no current value", and
    /// the caller must fail closed for a protected capability rather than assume
    /// a default.
    pub async fn effective_integer_entitlement(
        &self,
        org_id: &str,
        entitlement_key: &str,
        now: &str,
    ) -> worker::Result<Option<i64>> {
        let Some(row) = self
            .database
            .prepare(
                EFFECTIVE_INTEGER_ENTITLEMENT_SQL,
                &[
                    BindValue::Text(org_id),
                    BindValue::Text(entitlement_key),
                    BindValue::Text(now),
                ],
            )?
            .first::<Value>(None)
            .await?
        else {
            return Ok(None);
        };
        let Some(raw) = row.get("value_json").and_then(Value::as_str) else {
            return Ok(None);
        };
        Ok(serde_json::from_str::<i64>(raw).ok())
    }

    pub async fn current_policy_version(&self, org_id: &str) -> worker::Result<i64> {
        let row = self
            .database
            .prepare(CURRENT_POLICY_VERSION_SQL, &[BindValue::Text(org_id)])?
            .first::<Value>(None)
            .await?
            .ok_or_else(|| worker::Error::RustError("policy version missing".into()))?;
        Ok(row
            .get("policy_version")
            .and_then(Value::as_i64)
            .unwrap_or_default())
    }

    // -- guards --------------------------------------------------------------

    /// Refuse a stale definition write. A `version` mismatch aborts the batch
    /// before any business row or outbox event is written.
    pub fn assert_automation_version_statement(
        &self,
        automation_id: &str,
        org_id: &str,
        expected_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            guard!(
                "SELECT 1 FROM automation_definitions
                   WHERE automation_id = ?1 AND org_id = ?2
                     AND status NOT IN ('deleted', 'completed') AND version = ?3"
            ),
            &[
                BindValue::Text(automation_id),
                BindValue::Text(org_id),
                BindValue::Int64(expected_version),
            ],
        )
    }

    pub fn assert_automation_status_statement(
        &self,
        automation_id: &str,
        org_id: &str,
        expected_status: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            guard!(
                "SELECT 1 FROM automation_definitions
                   WHERE automation_id = ?1 AND org_id = ?2 AND status = ?3"
            ),
            &[
                BindValue::Text(automation_id),
                BindValue::Text(org_id),
                BindValue::Text(expected_status),
            ],
        )
    }

    /// Refuse a generation pass whose cursor has already moved. Only one
    /// concurrent pass can advance a given cursor, so a duplicate cannot mint a
    /// second logical occurrence or rewind the window.
    pub fn assert_schedule_cursor_statement(
        &self,
        automation_id: &str,
        org_id: &str,
        expected_cursor: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            guard!(
                "SELECT 1 FROM automation_definitions
                   WHERE automation_id = ?1 AND org_id = ?2
                     AND status = 'active' AND schedule_cursor_at = ?3"
            ),
            &[
                BindValue::Text(automation_id),
                BindValue::Text(org_id),
                BindValue::Text(expected_cursor),
            ],
        )
    }

    /// Refuse an occurrence transition whose projection has moved on.
    pub fn assert_occurrence_state_statement(
        &self,
        occurrence_id: &str,
        org_id: &str,
        expected_state: &str,
        expected_state_version: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            guard!(
                "SELECT 1 FROM automation_occurrences
                   WHERE occurrence_id = ?1 AND org_id = ?2
                     AND state = ?3 AND state_version = ?4"
            ),
            &[
                BindValue::Text(occurrence_id),
                BindValue::Text(org_id),
                BindValue::Text(expected_state),
                BindValue::Int64(expected_state_version),
            ],
        )
    }

    /// Refuse a claim unless the occurrence is still claimable, has no active
    /// lease, and has no run link. `ux_automation_leases_active` is the
    /// backstop for a true concurrent race.
    pub fn assert_occurrence_claimable_statement(
        &self,
        occurrence_id: &str,
        org_id: &str,
        expected_state: &str,
        expected_state_version: i64,
        attempt: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            guard!(
                "SELECT 1 FROM automation_occurrences o
                   WHERE o.occurrence_id = ?1 AND o.org_id = ?2
                     AND o.state = ?3 AND o.state_version = ?4
                     AND o.attempt = ?5
                     AND NOT EXISTS (
                         SELECT 1 FROM automation_leases l
                         WHERE l.occurrence_id = o.occurrence_id AND l.state = 'active'
                     )
                     AND NOT EXISTS (
                         SELECT 1 FROM automation_run_links k
                         WHERE k.occurrence_id = o.occurrence_id
                     )"
            ),
            &[
                BindValue::Text(occurrence_id),
                BindValue::Text(org_id),
                BindValue::Text(expected_state),
                BindValue::Int64(expected_state_version),
                BindValue::Int64(attempt),
            ],
        )
    }

    /// Refuse any device-authoritative call that does not present the current
    /// lease, its current version, and its current fence. A superseded attempt
    /// is rejected here rather than overwriting newer state.
    #[allow(clippy::too_many_arguments)]
    pub fn assert_lease_current_statement(
        &self,
        lease_id: &str,
        occurrence_id: &str,
        org_id: &str,
        expected_state: &str,
        expected_lease_version: i64,
        expected_lease_fence: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            guard!(
                "SELECT 1 FROM automation_leases l
                   JOIN automation_occurrences o ON o.occurrence_id = l.occurrence_id
                   WHERE l.lease_id = ?1 AND l.occurrence_id = ?2 AND l.org_id = ?3
                     AND l.state = ?4 AND l.lease_version = ?5 AND l.lease_fence = ?6
                     AND o.org_id = ?3"
            ),
            &[
                BindValue::Text(lease_id),
                BindValue::Text(occurrence_id),
                BindValue::Text(org_id),
                BindValue::Text(expected_state),
                BindValue::Int64(expected_lease_version),
                BindValue::Int64(expected_lease_fence),
            ],
        )
    }

    /// Refuse a `start` that would create a second P05 run for the same
    /// `(occurrence, attempt)`.
    pub fn assert_run_link_absent_statement(
        &self,
        occurrence_id: &str,
        attempt: i64,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            guard!(
                "SELECT 1 FROM automation_run_links
                   WHERE occurrence_id = ?1 AND attempt = ?2"
            ),
            &[BindValue::Text(occurrence_id), BindValue::Int64(attempt)],
        )
    }

    /// `queue_one` permits at most ONE open successor.
    pub fn assert_single_queued_successor_statement(
        &self,
        automation_id: &str,
        exclude_occurrence_id: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            guard!(
                "SELECT 1 FROM automation_occurrences
                   WHERE automation_id = ?1
                     AND queued_at IS NOT NULL
                     AND state IN ('pending', 'dispatching')
                     AND (?2 = '' OR occurrence_id <> ?2)"
            ),
            &[
                BindValue::Text(automation_id),
                BindValue::Text(exclude_occurrence_id),
            ],
        )
    }

    /// The dispatch-time recheck runs inside the same batch as the transition,
    /// so a dispatch can never commit against state the caller read earlier.
    #[allow(clippy::too_many_arguments)]
    pub fn assert_dispatch_eligible_statement(
        &self,
        org_id: &str,
        principal_user_id: &str,
        now: &str,
        expected_license_state: &str,
    ) -> worker::Result<D1PreparedStatement> {
        self.database.prepare(
            guard!(
                "SELECT 1 FROM organizations o
                   JOIN memberships m ON m.org_id = o.org_id
                   WHERE o.org_id = ?1 AND o.state = 'active'
                     AND m.user_id = ?2 AND m.status = 'active'
                     AND EXISTS (
                         SELECT 1 FROM license_states l
                         WHERE l.org_id = o.org_id
                           AND l.state = ?4
                           AND (l.state <> 'grace' OR l.grace_expires_at > ?3)
                     )"
            ),
            &[
                BindValue::Text(org_id),
                BindValue::Text(principal_user_id),
                BindValue::Text(now),
                BindValue::Text(expected_license_state),
            ],
        )
    }
}

#[derive(Deserialize)]
struct LicenseStateRow {
    state: String,
    grace_expires_at: Option<String>,
}

#[derive(Deserialize)]
struct AutomationSessionRow {
    agent_session_id: String,
}

// -----------------------------------------------------------------------------
// Domain delegation
// -----------------------------------------------------------------------------

/// Decide the occurrence state a claim should persist.
///
/// A claim implies both edges the frozen table allows: `pending -> dispatching`
/// and `dispatching -> leased`. Applying them here means the adapter never
/// invents a state the domain did not decide, and the claim response can tell a
/// device whether this claim was also the dispatch.
pub fn claim_target_state(current: OccurrenceState) -> Result<OccurrenceState, DomainError> {
    let dispatched = match current {
        OccurrenceState::Pending => transition(
            current,
            crate::modules::automations::OccurrenceEvent::Dispatch,
        )?,
        other => other,
    };
    transition(
        dispatched,
        crate::modules::automations::OccurrenceEvent::Claimed,
    )
}

/// Whether a claim also performed the `pending -> dispatching` dispatch edge, so
/// the caller knows to emit the frozen `dispatched` event for it.
pub const fn claim_performs_dispatch(current: OccurrenceState) -> bool {
    matches!(current, OccurrenceState::Pending)
}

/// Apply a deliberate-skip decision to an already-persisted occurrence. A slot
/// that the generation plan skipped is persisted directly in its terminal state
/// and needs no transition; an occurrence that is already `pending` is
/// dispatched first because the frozen table has no `pending -> skipped` edge.
pub fn skip_target_state(current: OccurrenceState) -> Result<OccurrenceState, DomainError> {
    let dispatched = match current {
        // A `pending` slot is dispatched first because the frozen table has no
        // `pending -> skipped` edge.
        OccurrenceState::Pending => transition(
            current,
            crate::modules::automations::OccurrenceEvent::Dispatch,
        )?,
        other => other,
    };
    transition(
        dispatched,
        crate::modules::automations::OccurrenceEvent::Skipped(DomainError::AutomationOverlapPolicy),
    )
}

/// Apply the missed-window decision to an already-persisted occurrence.
pub fn missed_target_state(current: OccurrenceState) -> Result<OccurrenceState, DomainError> {
    match current {
        // `pending -> missed` is not an edge the frozen table applies, so the
        // slot is dispatched first and the miss is recorded against a slot the
        // server actually tried to dispatch.
        OccurrenceState::Pending => transition(
            transition(
                current,
                crate::modules::automations::OccurrenceEvent::Dispatch,
            )?,
            crate::modules::automations::OccurrenceEvent::Missed,
        ),
        other => transition(other, crate::modules::automations::OccurrenceEvent::Missed),
    }
}

/// Build the predecessor view the overlap decision reads. A predecessor that is
/// itself queued has not waited; the successor's own `queued_at` is what the
/// bounded age applies to.
pub fn predecessor_view(
    predecessor: &AutomationOccurrenceRecord,
    now_epoch_seconds: i64,
) -> Result<PredecessorView, DomainError> {
    let state = predecessor.state()?;
    let queued_age_seconds = match predecessor.queued_at.as_deref() {
        Some(queued_at) => now_epoch_seconds
            .saturating_sub(crate::modules::automations::parse_instant_utc(queued_at)?),
        None => 0,
    };
    Ok(PredecessorView {
        state,
        queued_age_seconds,
        now: now_epoch_seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::automations::OverlapPolicy;

    #[test]
    fn frozen_event_names_are_versioned_and_complete() {
        for event in AUTOMATION_EVENT_TYPES {
            assert!(event.ends_with(".v1"), "{event}");
            assert!(
                AUTOMATION_EVENT_TYPES.contains(event),
                "duplicated registry entry {event}"
            );
        }
        assert_eq!(AUTOMATION_EVENT_TYPES.len(), 14);
        assert!(AUTOMATION_EVENT_TYPES.contains(&EVENT_OCCURRENCE_AMBIGUOUS));
    }

    #[test]
    fn claim_applies_both_frozen_edges() {
        assert_eq!(
            claim_target_state(OccurrenceState::Pending).unwrap(),
            OccurrenceState::Leased
        );
        assert_eq!(
            claim_target_state(OccurrenceState::Dispatching).unwrap(),
            OccurrenceState::Leased
        );
        assert!(claim_performs_dispatch(OccurrenceState::Pending));
        assert!(!claim_performs_dispatch(OccurrenceState::Dispatching));
    }

    #[test]
    fn a_started_or_ambiguous_occurrence_can_never_be_claimed_again() {
        for state in [
            OccurrenceState::Started,
            OccurrenceState::Ambiguous,
            OccurrenceState::Succeeded,
            OccurrenceState::Cancelled,
            OccurrenceState::Missed,
            OccurrenceState::Skipped,
            OccurrenceState::Failed,
        ] {
            assert_eq!(
                claim_target_state(state),
                Err(DomainError::AutomationInvalidState),
                "{state:?} was claimable"
            );
        }
    }

    #[test]
    fn skip_and_missed_require_the_dispatch_edge_first() {
        assert_eq!(
            skip_target_state(OccurrenceState::Pending).unwrap(),
            OccurrenceState::Skipped
        );
        assert_eq!(
            skip_target_state(OccurrenceState::Dispatching).unwrap(),
            OccurrenceState::Skipped
        );
        assert_eq!(
            missed_target_state(OccurrenceState::Pending).unwrap(),
            OccurrenceState::Missed
        );
        assert_eq!(
            skip_target_state(OccurrenceState::Leased).unwrap(),
            OccurrenceState::Skipped
        );
        assert_eq!(
            missed_target_state(OccurrenceState::Leased).unwrap(),
            OccurrenceState::Missed
        );
    }

    #[test]
    fn execution_retry_is_bounded_by_the_frozen_envelope() {
        let record = AutomationDefinitionRecord {
            automation_id: "aut_0123456789abcdef0123456789abcdef".into(),
            org_id: "org_0123456789abcdef0123456789abcdef".into(),
            project_id: None,
            name: "review".into(),
            description: None,
            agent_definition_id: None,
            schedule_rule_id: "sch_0123456789abcdef0123456789abcdef".into(),
            execution_principal_kind: "user".into(),
            execution_principal_id: "usr_0123456789abcdef0123456789abcdef".into(),
            target_kind: "eligible_device".into(),
            target_device_id: None,
            target_workspace_binding_id: None,
            required_capabilities_json: "[]".into(),
            execution_model_alias: None,
            execution_budget_id: None,
            tool_policy_scope: "project".into(),
            required_policy_version: None,
            off_peak_eligibility_source: None,
            off_peak_allowed_route_aliases_json: None,
            off_peak_deny_automation_mutation: 1,
            off_peak_deny_recursive_off_peak: 1,
            off_peak_allow_background_processes: 0,
            status: "active".into(),
            max_start_attempts: 2,
            lease_ttl_seconds: 300,
            heartbeat_interval_seconds: 30,
            schedule_cursor_at: None,
            next_run_at: None,
            last_run_at: None,
            version: 1,
            created_by_user_id: "usr_0123456789abcdef0123456789abcdef".into(),
            created_at: "2026-09-25T12:00:00.000Z".into(),
            updated_at: "2026-09-25T12:00:00.000Z".into(),
            queued_successor_max_age_seconds: 86_400,
        };
        assert_eq!(
            record.execution_retry().unwrap(),
            ExecutionRetry::default_policy()
        );

        let mut invalid = record;
        invalid.lease_ttl_seconds = 5;
        assert_eq!(
            invalid.execution_retry(),
            Err(DomainError::AutomationInvalidState)
        );
    }

    #[test]
    fn stored_schedule_revision_round_trips_through_canonical_json() {
        let rule = ScheduleRule::cron(
            "0 9 * * 1-5",
            "America/Los_Angeles",
            crate::modules::automations::DomDowMode::Or,
            crate::modules::automations::DstPolicy::SkipDuplicate,
            OverlapPolicy::Skip,
            crate::modules::automations::MissedPolicy::RunOnce,
            None,
        )
        .unwrap();
        let revision = StoredScheduleRevision::new(rule, ZoneOffsets::fixed(-28_800).unwrap());
        let json = revision.to_canonical_json().unwrap();
        // The persisted rule is the NORMALIZED expression plus the resolved zone,
        // never the caller's display spelling.
        assert!(
            json.contains("\"expression\":\"0 9 * * 1,2,3,4,5\""),
            "{json}"
        );
        assert!(!json.contains("1-5"), "{json}");
        assert!(json.contains("\"default_offset_seconds\":-28800"), "{json}");
        assert_eq!(
            StoredScheduleRevision::from_canonical_json(&json).unwrap(),
            revision
        );
    }

    #[test]
    fn a_corrupt_canonical_json_is_a_schedule_failure_not_a_panic() {
        assert_eq!(
            StoredScheduleRevision::from_canonical_json("{\"rule\":"),
            Err(DomainError::ScheduleInvalid)
        );
        assert_eq!(
            StoredScheduleRevision::from_canonical_json("{}"),
            Err(DomainError::ScheduleInvalid)
        );
    }

    #[test]
    fn lease_debug_never_prints_the_token_fingerprint() {
        let lease = ExecutionLeaseRecord {
            lease_id: "lse_0123456789abcdef0123456789abcdef".into(),
            occurrence_id: "occ_0123456789abcdef0123456789abcdef".into(),
            org_id: "org_0123456789abcdef0123456789abcdef".into(),
            device_id: "dvc_0123456789abcdef0123456789abcdef".into(),
            state: "active".into(),
            attempt: 1,
            lease_token_fingerprint: "sha256:super-secret-fingerprint".into(),
            lease_version: 1,
            lease_fence: 1,
            claimed_at: "2026-09-25T16:00:00.000Z".into(),
            expires_at: "2026-09-25T16:05:00.000Z".into(),
            released_at: None,
            completed_at: None,
            version: 1,
        };
        let debug = format!("{lease:?}");
        assert!(!debug.contains("super-secret-fingerprint"));
        assert!(debug.contains("[redacted]"));
        assert!(lease.matches_token("sha256:super-secret-fingerprint"));
        assert!(!lease.matches_token("sha256:other"));
        assert!(!lease.matches_token("sha256:"));
    }
}
