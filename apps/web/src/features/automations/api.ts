// P06 automation browser client.
//
// Contract source: `p06-cg-v1` (docs/implementation/gates/P06-CG.md) plus the
// frozen fixture `docs/implementation/fixtures/p06-contracts-v1.json`.
//
// Two rules govern this module:
//   1. Decoders fail closed. A projection this module cannot prove came from the
//      frozen contract rejects the whole page rather than rendering a guess.
//   2. Client snapshots are untrusted. Nothing here decides schedule, lease,
//      entitlement, or device eligibility; the server re-evaluates all of it.

import {
  ApiClientError,
  apiErrorFromEnvelope,
  makeInvalidResponseError,
  makeTransportError,
} from "@/lib/errors";

// -----------------------------------------------------------------------------
// Frozen enums
// -----------------------------------------------------------------------------

export const SCHEDULE_KINDS = ["one_time", "cron", "interval", "manual"] as const;
export type ScheduleKind = (typeof SCHEDULE_KINDS)[number];

export const OVERLAP_POLICIES = ["allow", "skip", "queue_one", "cancel_previous"] as const;
export type OverlapPolicy = (typeof OVERLAP_POLICIES)[number];

export const MISSED_POLICIES = ["skip", "run_once", "catch_up"] as const;
export type MissedPolicy = (typeof MISSED_POLICIES)[number];

export const DOM_DOW_MODES = ["or", "and"] as const;
export type DomDowMode = (typeof DOM_DOW_MODES)[number];

export const DST_POLICIES = ["skip_duplicate", "run_first", "run_both"] as const;
export type DstPolicy = (typeof DST_POLICIES)[number];

export const INTERVAL_UNITS = ["minutes", "hours", "days", "weeks", "months", "years"] as const;
export type IntervalUnit = (typeof INTERVAL_UNITS)[number];

export const AUTOMATION_STATUSES = ["active", "paused", "suspended", "failed"] as const;
export type AutomationStatus = (typeof AUTOMATION_STATUSES)[number];

export const TARGET_KINDS = [
  "eligible_device",
  "specific_device",
  "remote_workspace",
  "server_runner",
] as const;
export type TargetKind = (typeof TARGET_KINDS)[number];

export const TOOL_POLICY_SCOPES = ["project", "organization", "agent"] as const;
export type ToolPolicyScope = (typeof TOOL_POLICY_SCOPES)[number];

export const PRINCIPAL_KINDS = ["user", "service_account"] as const;
export type PrincipalKind = (typeof PRINCIPAL_KINDS)[number];

export const OFF_PEAK_ELIGIBILITY_SOURCES = ["provider_ticket", "org_window"] as const;
export type OffPeakEligibilitySource = (typeof OFF_PEAK_ELIGIBILITY_SOURCES)[number];

export const OCCURRENCE_KINDS = ["scheduled", "manual", "off_peak"] as const;
export type OccurrenceKind = (typeof OCCURRENCE_KINDS)[number];

export const OCCURRENCE_STATES = [
  "pending",
  "dispatching",
  "leased",
  "started",
  "succeeded",
  "failed",
  "cancelled",
  "missed",
  "skipped",
  "ambiguous",
] as const;
export type OccurrenceState = (typeof OCCURRENCE_STATES)[number];

export const OFF_PEAK_MODES = ["normal", "off_peak"] as const;
export type OffPeakMode = (typeof OFF_PEAK_MODES)[number];

// Frozen defaults from the gate: "Defaults are `skip` for overlap and
// `run_once` for missed schedules."
export const DEFAULT_OVERLAP_POLICY: OverlapPolicy = "skip";
export const DEFAULT_MISSED_POLICY: MissedPolicy = "run_once";
export const DEFAULT_DOM_DOW_MODE: DomDowMode = "or";
export const DEFAULT_DST_POLICY: DstPolicy = "skip_duplicate";

export const MIN_CATCH_UP_LIMIT = 1;
export const MAX_CATCH_UP_LIMIT = 20;
export const MIN_INTERVAL_EVERY = 1;
export const MAX_INTERVAL_EVERY = 200;
export const MAX_SELECTOR_VALUES = 32;
export const MAX_CRON_EXPRESSION_BYTES = 128;
export const MAX_TIMEZONE_BYTES = 64;
export const MAX_TIMEZONE_SEGMENTS = 4;
export const MAX_UTC_OFFSET_SECONDS = 18 * 60 * 60;

export const AUTOMATION_PAGE_LIMIT = 50;
export const OCCURRENCE_PAGE_LIMIT = 50;

// -----------------------------------------------------------------------------
// Projections
// -----------------------------------------------------------------------------

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
  has_more: boolean;
}

export interface ExecutionPrincipal {
  kind: PrincipalKind;
  id: string;
}

export interface AutomationTarget {
  kind: TargetKind;
  device_id: string | null;
  workspace_binding_id: string | null;
  required_capabilities: string[];
}

export interface ExecutionPolicy {
  model_alias: string | null;
  budget_id: string | null;
  tool_policy_scope: ToolPolicyScope;
  required_policy_version: number | null;
}

export interface ExecutionRetry {
  max_start_attempts: number;
  lease_ttl_seconds: number;
  heartbeat_interval_seconds: number;
}

export interface OffPeakToolConstraints {
  deny_automation_mutation: boolean;
  deny_recursive_off_peak: boolean;
  allow_background_processes: boolean;
}

export interface OffPeakPolicy {
  schema_version: number;
  eligibility_source: OffPeakEligibilitySource;
  allowed_route_aliases: string[];
  tool_constraints: OffPeakToolConstraints;
}

/** The effective overlap/missed policy, after the frozen defaults are applied. */
export interface SchedulePolicy {
  overlap_policy: OverlapPolicy;
  missed_policy: MissedPolicy;
  catch_up_limit: number | null;
}

export interface OneTimeSchedule extends SchedulePolicy {
  kind: "one_time";
  scheduled_at: string;
}

export interface CronSchedule extends SchedulePolicy {
  kind: "cron";
  expression: string;
  timezone: string;
  dom_dow_mode: DomDowMode;
  dst_policy: DstPolicy;
}

export interface IntervalSchedule extends SchedulePolicy {
  kind: "interval";
  every: number;
  unit: IntervalUnit;
  anchor_at: string;
  timezone: string;
  by_weekday: number[] | null;
  by_monthday: number[] | null;
  by_month: number[] | null;
}

export interface ManualSchedule extends SchedulePolicy {
  kind: "manual";
}

export type ScheduleRule = OneTimeSchedule | CronSchedule | IntervalSchedule | ManualSchedule;

export interface AutomationDefinition {
  automation_id: string;
  org_id: string;
  project_id: string | null;
  name: string;
  description: string | null;
  agent_definition_id: string;
  execution_principal: ExecutionPrincipal;
  target: AutomationTarget;
  schedule: ScheduleRule;
  execution_policy: ExecutionPolicy;
  off_peak_policy: OffPeakPolicy | null;
  status: AutomationStatus;
  version: number;
  next_run_at: string | null;
  last_run_at: string | null;
  schedule_cursor_at: string | null;
  execution_retry: ExecutionRetry;
  created_by_user_id: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface Occurrence {
  occurrence_id: string;
  automation_id: string;
  org_id: string;
  project_id: string | null;
  kind: OccurrenceKind;
  execution_principal: ExecutionPrincipal | null;
  off_peak_mode: OffPeakMode | null;
  policy_snapshot_id: string | null;
  policy_version: number | null;
  scheduled_for: string | null;
  schedule_rule_id: string | null;
  state: OccurrenceState;
  state_version: number | null;
  attempt: number;
  reason_code: string | null;
  run_id: string | null;
  blocked_by_occurrence_id: string | null;
  lease_expires_at: string | null;
  queued_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export type EntitlementValue = boolean | number | string;

/**
 * The effective entitlement projection used for the automation limit. The
 * entitlement decision stays server-side; this is read-only context.
 */
export interface AutomationEntitlements {
  subscription_id: string | null;
  billing_account_id: string | null;
  org_id: string | null;
  plan_key: string | null;
  status: string | null;
  policy_fresh_until: string | null;
  offline_valid_until: string | null;
  values: Record<string, EntitlementValue>;
}

export interface ListAutomationsQuery {
  limit?: number;
  cursor?: string;
  project_id?: string;
  status?: AutomationStatus;
}

export interface ListOccurrencesQuery {
  limit?: number;
  cursor?: string;
  state?: OccurrenceState;
}

export interface ZoneOffset {
  at_utc: number;
  offset_seconds: number;
}

/**
 * The client-resolved zone for a named IANA timezone. A Worker links no
 * timezone database, so a cron/interval rule must carry the current offset and
 * its bounded transitions. The browser is the only place that can resolve them,
 * and the server still validates the whole table.
 */
export interface ResolvedZone {
  utc_offset_seconds: number;
  utc_offset_transitions: ZoneOffset[];
}

export interface ScheduleRequestPayload {
  kind: ScheduleKind;
  overlap_policy: OverlapPolicy;
  missed_policy: MissedPolicy;
  catch_up_limit?: number;
  expression?: string;
  timezone?: string;
  dom_dow_mode?: DomDowMode;
  dst_policy?: DstPolicy;
  scheduled_at?: string;
  every?: number;
  unit?: IntervalUnit;
  anchor_at?: string;
  by_weekday?: number[];
  by_monthday?: number[];
  by_month?: number[];
  utc_offset_seconds?: number;
  utc_offset_transitions?: ZoneOffset[];
}

export interface CreateAutomationInput {
  name: string;
  description?: string | null;
  project_id: string;
  agent_definition_id: string;
  execution_principal: { kind: PrincipalKind; id?: string | null };
  target: {
    kind: TargetKind;
    device_id?: string | null;
    workspace_binding_id?: string | null;
    required_capabilities?: string[];
  };
  schedule: ScheduleRequestPayload;
  execution_policy: {
    model_alias?: string | null;
    budget_id?: string | null;
    tool_policy_scope?: ToolPolicyScope;
    required_policy_version?: number | null;
  };
  execution_retry?: ExecutionRetry;
  off_peak_policy?: {
    schema_version: number;
    eligibility_source: OffPeakEligibilitySource;
    allowed_route_aliases?: string[];
    tool_constraints: OffPeakToolConstraints;
  } | null;
}

export interface UpdateAutomationInput extends Partial<CreateAutomationInput> {
  version: number;
}

// -----------------------------------------------------------------------------
// Decoders
// -----------------------------------------------------------------------------

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isOneOf<T extends string>(value: unknown, allowed: readonly T[]): value is T {
  return typeof value === "string" && (allowed as readonly string[]).includes(value);
}

function readString(value: unknown, maxLength: number): string | null {
  if (typeof value !== "string") return null;
  const normalized = stripControlCharacters(value).replace(/\s+/g, " ").trim();
  if (normalized.length === 0 || normalized.length > maxLength) return null;
  return normalized;
}

function stripControlCharacters(value: string): string {
  return Array.from(value, (character) => {
    const code = character.charCodeAt(0);
    return code < 32 || code === 127 ? " " : character;
  }).join("");
}

function readNullableString(value: unknown, maxLength: number): string | null {
  if (value === null || value === undefined) return null;
  return readString(value, maxLength);
}

function readInteger(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isInteger(value)) return null;
  return value;
}

function readBoundedInteger(value: unknown, min: number, max: number): number | null {
  const parsed = readInteger(value);
  if (parsed === null || parsed < min || parsed > max) return null;
  return parsed;
}

function readNullableInteger(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  return readInteger(value);
}

/**
 * An optional bounded integer. `null` means the wire omitted it; `undefined`
 * means a value is present but not representable, so the projection is rejected
 * rather than silently coerced.
 */
function readOptionalBoundedInteger(
  value: unknown,
  min: number,
  max: number,
): number | null | undefined {
  if (value === null || value === undefined) return null;
  return readBoundedInteger(value, min, max) ?? undefined;
}

function readStringArray(value: unknown, maxItems: number, maxLength: number): string[] | null {
  if (value === null || value === undefined) return [];
  if (!Array.isArray(value) || value.length > maxItems) return null;
  const items: string[] = [];
  for (const item of value) {
    const normalized = readString(item, maxLength);
    if (normalized === null) return null;
    items.push(normalized);
  }
  return items;
}

function readNumberArray(
  value: unknown,
  minItems: number,
  maxItems: number,
  min: number,
  max: number,
): number[] | null | undefined {
  // `null` means the wire omitted the optional selector; `undefined` means a
  // present selector is not representable and the projection must be rejected.
  if (value === null || value === undefined) return null;
  if (!Array.isArray(value) || value.length < minItems || value.length > maxItems) return undefined;
  const items: number[] = [];
  for (const item of value) {
    if (typeof item !== "number" || !Number.isInteger(item) || item < min || item > max)
      return undefined;
    items.push(item);
  }
  return items;
}

function decodeExecutionPrincipal(value: unknown): ExecutionPrincipal | null {
  if (!isObject(value)) return null;
  const kind = value.kind;
  const id = readString(value.id, 96);
  if (id === null || !isOneOf(kind, PRINCIPAL_KINDS)) return null;
  return { kind, id };
}

function decodeTarget(value: unknown): AutomationTarget | null {
  if (!isObject(value)) return null;
  if (!isOneOf(value.kind, TARGET_KINDS)) return null;
  const capabilities = readStringArray(value.required_capabilities, 64, 128);
  if (capabilities === null) return null;
  return {
    kind: value.kind,
    device_id: readNullableString(value.device_id, 96),
    workspace_binding_id: readNullableString(value.workspace_binding_id, 96),
    required_capabilities: capabilities,
  };
}

function decodeExecutionPolicy(value: unknown): ExecutionPolicy | null {
  if (!isObject(value)) return null;
  if (!isOneOf(value.tool_policy_scope, TOOL_POLICY_SCOPES)) return null;
  const modelAlias = readNullableString(value.model_alias, 96);
  const budgetId = readNullableString(value.budget_id, 96);
  const requiredPolicyVersion = readNullableInteger(value.required_policy_version);
  if (value.model_alias !== null && value.model_alias !== undefined && modelAlias === null)
    return null;
  if (value.budget_id !== null && value.budget_id !== undefined && budgetId === null) return null;
  return {
    model_alias: modelAlias,
    budget_id: budgetId,
    tool_policy_scope: value.tool_policy_scope,
    required_policy_version: requiredPolicyVersion,
  };
}

function decodeExecutionRetry(value: unknown): ExecutionRetry | null {
  if (!isObject(value)) return null;
  const maxStartAttempts = readBoundedInteger(value.max_start_attempts, 1, 3);
  const leaseTtl = readBoundedInteger(value.lease_ttl_seconds, 30, 3600);
  const heartbeat = readBoundedInteger(value.heartbeat_interval_seconds, 10, 60);
  if (maxStartAttempts === null || leaseTtl === null || heartbeat === null) return null;
  return {
    max_start_attempts: maxStartAttempts,
    lease_ttl_seconds: leaseTtl,
    heartbeat_interval_seconds: heartbeat,
  };
}

function decodeOffPeakPolicy(value: unknown): OffPeakPolicy | null {
  if (value === null || value === undefined) return null;
  if (!isObject(value)) return null;
  if (!isOneOf(value.eligibility_source, OFF_PEAK_ELIGIBILITY_SOURCES)) return null;
  if (readBoundedInteger(value.schema_version, 1, 1) === null) return null;
  const aliases = readStringArray(value.allowed_route_aliases, 16, 64);
  if (aliases === null) return null;
  const constraints = value.tool_constraints;
  if (
    !isObject(constraints) ||
    typeof constraints.deny_automation_mutation !== "boolean" ||
    typeof constraints.deny_recursive_off_peak !== "boolean" ||
    typeof constraints.allow_background_processes !== "boolean"
  ) {
    return null;
  }
  return {
    schema_version: 1,
    eligibility_source: value.eligibility_source,
    allowed_route_aliases: aliases,
    tool_constraints: {
      deny_automation_mutation: constraints.deny_automation_mutation,
      deny_recursive_off_peak: constraints.deny_recursive_off_peak,
      allow_background_processes: constraints.allow_background_processes,
    },
  };
}

/**
 * Decode one canonical `ScheduleRule`.
 *
 * `overlap_policy`, `missed_policy`, and the interval selectors are omitted from
 * the wire when they hold the frozen default, so an absent value means the
 * default rather than an unknown one. A present-but-unrecognized value rejects
 * instead of silently falling back.
 */
export function decodeScheduleRule(value: unknown): ScheduleRule | null {
  if (!isObject(value)) return null;
  const kind = value.kind;
  if (!isOneOf(kind, SCHEDULE_KINDS)) return null;

  const rawOverlap = value.overlap_policy;
  if (rawOverlap !== undefined && rawOverlap !== null && !isOneOf(rawOverlap, OVERLAP_POLICIES))
    return null;
  const overlapPolicy: OverlapPolicy = isOneOf(rawOverlap, OVERLAP_POLICIES)
    ? rawOverlap
    : DEFAULT_OVERLAP_POLICY;

  const rawMissed = value.missed_policy;
  if (rawMissed !== undefined && rawMissed !== null && !isOneOf(rawMissed, MISSED_POLICIES))
    return null;
  const missedPolicy: MissedPolicy = isOneOf(rawMissed, MISSED_POLICIES)
    ? rawMissed
    : DEFAULT_MISSED_POLICY;

  const rawCatchUp = value.catch_up_limit;
  let catchUpLimit: number | null = null;
  if (rawCatchUp !== undefined && rawCatchUp !== null) {
    const parsed = readBoundedInteger(rawCatchUp, MIN_CATCH_UP_LIMIT, MAX_CATCH_UP_LIMIT);
    if (parsed === null) return null;
    // A present limit is tolerated for any missed policy; the gate's own
    // examples show it alongside `run_once`. It is only meaningful for
    // `catch_up`, so the projection keeps it either way.
    catchUpLimit = parsed;
  }
  if (missedPolicy === "catch_up" && catchUpLimit === null) return null;

  const policy: SchedulePolicy = {
    overlap_policy: overlapPolicy,
    missed_policy: missedPolicy,
    catch_up_limit: catchUpLimit,
  };

  if (kind === "manual") return { kind: "manual", ...policy };

  if (kind === "one_time") {
    const scheduledAt = readString(value.scheduled_at, 64);
    if (scheduledAt === null) return null;
    return { kind: "one_time", scheduled_at: scheduledAt, ...policy };
  }

  const timezone = readString(value.timezone, MAX_TIMEZONE_BYTES);
  if (timezone === null) return null;

  if (kind === "cron") {
    const expression = readString(value.expression, MAX_CRON_EXPRESSION_BYTES);
    if (expression === null) return null;
    if (value.dom_dow_mode !== undefined && value.dom_dow_mode !== null)
      if (!isOneOf(value.dom_dow_mode, DOM_DOW_MODES)) return null;
    if (value.dst_policy !== undefined && value.dst_policy !== null)
      if (!isOneOf(value.dst_policy, DST_POLICIES)) return null;
    return {
      kind: "cron",
      expression,
      timezone,
      dom_dow_mode: isOneOf(value.dom_dow_mode, DOM_DOW_MODES)
        ? value.dom_dow_mode
        : DEFAULT_DOM_DOW_MODE,
      dst_policy: isOneOf(value.dst_policy, DST_POLICIES) ? value.dst_policy : DEFAULT_DST_POLICY,
      ...policy,
    };
  }

  const every = readBoundedInteger(value.every, MIN_INTERVAL_EVERY, MAX_INTERVAL_EVERY);
  const anchorAt = readString(value.anchor_at, 64);
  if (every === null || anchorAt === null || !isOneOf(value.unit, INTERVAL_UNITS)) return null;
  const byWeekday = readNumberArray(value.by_weekday, 1, MAX_SELECTOR_VALUES, 0, 6);
  const byMonthday = readNumberArray(value.by_monthday, 1, MAX_SELECTOR_VALUES, 1, 31);
  const byMonth = readNumberArray(value.by_month, 1, MAX_SELECTOR_VALUES, 1, 12);
  if (byWeekday === undefined || byMonthday === undefined || byMonth === undefined) return null;
  return {
    kind: "interval",
    every,
    unit: value.unit,
    anchor_at: anchorAt,
    timezone,
    by_weekday: byWeekday,
    by_monthday: byMonthday,
    by_month: byMonth,
    ...policy,
  };
}

export function decodeAutomation(value: unknown): AutomationDefinition | null {
  if (!isObject(value)) return null;
  const automationId = readString(value.automation_id, 96);
  const orgId = readString(value.org_id, 96);
  const name = readString(value.name, 160);
  const agentDefinitionId = readString(value.agent_definition_id, 96);
  const version = readBoundedInteger(value.version, 1, Number.MAX_SAFE_INTEGER);
  if (
    automationId === null ||
    orgId === null ||
    name === null ||
    agentDefinitionId === null ||
    version === null ||
    !isOneOf(value.status, AUTOMATION_STATUSES)
  ) {
    return null;
  }
  const principal = decodeExecutionPrincipal(value.execution_principal);
  const target = decodeTarget(value.target);
  const schedule = decodeScheduleRule(value.schedule);
  const executionPolicy = decodeExecutionPolicy(value.execution_policy);
  const offPeakPolicy = decodeOffPeakPolicy(value.off_peak_policy);
  const executionRetry = decodeExecutionRetry(value.execution_retry);
  const description = readNullableString(value.description, 2000);
  const projectId = readNullableString(value.project_id, 96);
  if (
    principal === null ||
    target === null ||
    schedule === null ||
    executionPolicy === null ||
    executionRetry === null ||
    offPeakPolicy === undefined ||
    (value.description !== null && value.description !== undefined && description === null) ||
    (value.project_id !== null && value.project_id !== undefined && projectId === null)
  ) {
    return null;
  }
  return {
    automation_id: automationId,
    org_id: orgId,
    project_id: projectId,
    name,
    description,
    agent_definition_id: agentDefinitionId,
    execution_principal: principal,
    target,
    schedule,
    execution_policy: executionPolicy,
    off_peak_policy: offPeakPolicy,
    status: value.status,
    version,
    next_run_at: readNullableString(value.next_run_at, 64),
    last_run_at: readNullableString(value.last_run_at, 64),
    schedule_cursor_at: readNullableString(value.schedule_cursor_at, 64),
    execution_retry: executionRetry,
    created_by_user_id: readNullableString(value.created_by_user_id, 96),
    created_at: readNullableString(value.created_at, 64),
    updated_at: readNullableString(value.updated_at, 64),
  };
}

/**
 * Decode one occurrence. `run-now` answers with a reduced creation projection,
 * so every field that projection omits decodes to `null` instead of rejecting.
 */
export function decodeOccurrence(value: unknown): Occurrence | null {
  if (!isObject(value)) return null;
  const occurrenceId = readString(value.occurrence_id, 96);
  const automationId = readString(value.automation_id, 96);
  const orgId = readString(value.org_id, 96);
  const stateVersion = readOptionalBoundedInteger(value.state_version, 1, Number.MAX_SAFE_INTEGER);
  const attempt = readBoundedInteger(value.attempt, 0, 1000);
  if (
    occurrenceId === null ||
    automationId === null ||
    orgId === null ||
    stateVersion === undefined ||
    attempt === null ||
    !isOneOf(value.kind, OCCURRENCE_KINDS) ||
    !isOneOf(value.state, OCCURRENCE_STATES)
  ) {
    return null;
  }
  const principal =
    value.execution_principal === undefined
      ? null
      : decodeExecutionPrincipal(value.execution_principal);
  if (principal === undefined) return null;
  const offPeakMode = value.off_peak_mode === undefined ? null : value.off_peak_mode;
  if (offPeakMode !== null && !isOneOf(offPeakMode, OFF_PEAK_MODES)) return null;
  const projectId = readNullableString(value.project_id, 96);
  if (value.project_id !== null && value.project_id !== undefined && projectId === null)
    return null;
  const reasonCode = readNullableString(value.reason_code, 96);
  if (value.reason_code !== null && value.reason_code !== undefined && reasonCode === null)
    return null;
  const runId = readNullableString(value.run_id, 96);
  if (value.run_id !== null && value.run_id !== undefined && runId === null) return null;
  return {
    occurrence_id: occurrenceId,
    automation_id: automationId,
    org_id: orgId,
    project_id: projectId,
    kind: value.kind,
    execution_principal: principal,
    off_peak_mode: offPeakMode,
    policy_snapshot_id: readNullableString(value.policy_snapshot_id, 96),
    policy_version: readNullableInteger(value.policy_version),
    scheduled_for: readNullableString(value.scheduled_for, 64),
    schedule_rule_id: readNullableString(value.schedule_rule_id, 96),
    state: value.state,
    state_version: stateVersion,
    attempt,
    reason_code: reasonCode,
    run_id: runId,
    blocked_by_occurrence_id: readNullableString(value.blocked_by_occurrence_id, 96),
    lease_expires_at: readNullableString(value.lease_expires_at, 64),
    queued_at: readNullableString(value.queued_at, 64),
    started_at: readNullableString(value.started_at, 64),
    finished_at: readNullableString(value.finished_at, 64),
    created_at: readNullableString(value.created_at, 64),
    updated_at: readNullableString(value.updated_at, 64),
  };
}

function decodePage<T>(value: unknown, decodeItem: (item: unknown) => T | null): Page<T> | null {
  if (!isObject(value)) return null;
  const items = value.items;
  if (!Array.isArray(items)) return null;
  if (value.next_cursor !== null && typeof value.next_cursor !== "string") return null;
  if (typeof value.has_more !== "boolean") return null;
  const decoded: T[] = [];
  for (const item of items) {
    const projection = decodeItem(item);
    if (projection === null) return null;
    decoded.push(projection);
  }
  return { items: decoded, next_cursor: value.next_cursor, has_more: value.has_more };
}

export const decodeAutomationPage = (value: unknown): Page<AutomationDefinition> | null =>
  decodePage(value, decodeAutomation);

export const decodeOccurrencePage = (value: unknown): Page<Occurrence> | null =>
  decodePage(value, decodeOccurrence);

/**
 * Decode the effective entitlement projection. The fixture shape is flat; a
 * single-key envelope is also accepted so a future envelope change degrades to a
 * read failure rather than a wrong number. Only `automations.max_active` drives
 * UI copy — the server is the sole authority on the limit.
 */
export function decodeEntitlements(value: unknown): AutomationEntitlements | null {
  const source = isObject(value) && isObject(value.entitlements) ? value.entitlements : value;
  if (!isObject(source)) return null;
  const rawValues = source.values;
  if (!isObject(rawValues)) return null;
  const entries = Object.entries(rawValues);
  if (entries.length > 64) return null;
  const values: Record<string, EntitlementValue> = {};
  for (const [key, item] of entries) {
    if (!/^[a-z][a-z0-9]*(?:\.[a-z0-9_]+)*$/.test(key) || key.length > 96) return null;
    if (typeof item === "boolean" || typeof item === "number" || typeof item === "string") {
      values[key] = item;
      continue;
    }
    return null;
  }
  return {
    subscription_id: readNullableString(source.subscription_id, 96),
    billing_account_id: readNullableString(source.billing_account_id, 96),
    org_id: readNullableString(source.org_id, 96),
    plan_key: readNullableString(source.plan_key, 64),
    status: readNullableString(source.status, 32),
    policy_fresh_until: readNullableString(source.policy_fresh_until, 64),
    offline_valid_until: readNullableString(source.offline_valid_until, 64),
    values,
  };
}

// -----------------------------------------------------------------------------
// Client
// -----------------------------------------------------------------------------

export interface AutomationsApiClient {
  listAutomations(
    orgId: string,
    query?: ListAutomationsQuery,
    signal?: AbortSignal,
  ): Promise<Page<AutomationDefinition>>;
  getAutomation(
    orgId: string,
    automationId: string,
    signal?: AbortSignal,
  ): Promise<AutomationDefinition>;
  createAutomation(
    orgId: string,
    input: CreateAutomationInput,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<AutomationDefinition>;
  updateAutomation(
    orgId: string,
    automationId: string,
    input: UpdateAutomationInput,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<AutomationDefinition>;
  pauseAutomation(
    orgId: string,
    automationId: string,
    input: { version: number },
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<AutomationDefinition>;
  resumeAutomation(
    orgId: string,
    automationId: string,
    input: { version: number },
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<AutomationDefinition>;
  runAutomationNow(
    orgId: string,
    automationId: string,
    input: { version: number },
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<Occurrence>;
  deleteAutomation(
    orgId: string,
    automationId: string,
    input: { version: number },
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<void>;
  listOccurrences(
    orgId: string,
    automationId: string,
    query?: ListOccurrencesQuery,
    signal?: AbortSignal,
  ): Promise<Page<Occurrence>>;
  getEntitlements(orgId: string, signal?: AbortSignal): Promise<AutomationEntitlements>;
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  idempotencyKey?: string;
  signal?: AbortSignal;
}

function orgPath(orgId: string): string {
  return `/api/v1/orgs/${encodeURIComponent(orgId)}/automations`;
}

function withQuery(path: string, query: Record<string, string | number | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === "") continue;
    params.set(key, String(value));
  }
  const encoded = params.toString();
  return encoded ? `${path}?${encoded}` : path;
}

function withSignal(signal?: AbortSignal): RequestOptions {
  return signal ? { signal } : {};
}

export const defaultAutomationsApi: AutomationsApiClient = {
  listAutomations(orgId, query, signal) {
    return requestAutomationJson(
      withQuery(orgPath(orgId), {
        limit: query?.limit ?? AUTOMATION_PAGE_LIMIT,
        cursor: query?.cursor,
        project_id: query?.project_id,
        status: query?.status,
      }),
      withSignal(signal),
      decodeAutomationPage,
    );
  },
  getAutomation(orgId, automationId, signal) {
    return requestAutomationJson(
      `${orgPath(orgId)}/${encodeURIComponent(automationId)}`,
      withSignal(signal),
      decodeAutomation,
    );
  },
  createAutomation(orgId, input, idempotencyKey, signal) {
    return requestAutomationJson(
      orgPath(orgId),
      { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
      decodeAutomation,
    );
  },
  updateAutomation(orgId, automationId, input, idempotencyKey, signal) {
    return requestAutomationJson(
      `${orgPath(orgId)}/${encodeURIComponent(automationId)}`,
      { method: "PATCH", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
      decodeAutomation,
    );
  },
  pauseAutomation(orgId, automationId, input, idempotencyKey, signal) {
    return requestAutomationJson(
      `${orgPath(orgId)}/${encodeURIComponent(automationId)}/pause`,
      { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
      decodeAutomation,
    );
  },
  resumeAutomation(orgId, automationId, input, idempotencyKey, signal) {
    return requestAutomationJson(
      `${orgPath(orgId)}/${encodeURIComponent(automationId)}/resume`,
      { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
      decodeAutomation,
    );
  },
  runAutomationNow(orgId, automationId, input, idempotencyKey, signal) {
    return requestAutomationJson(
      `${orgPath(orgId)}/${encodeURIComponent(automationId)}/run-now`,
      { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
      decodeOccurrence,
    );
  },
  async deleteAutomation(orgId, automationId, input, idempotencyKey, signal) {
    await requestAutomationNoContent(`${orgPath(orgId)}/${encodeURIComponent(automationId)}`, {
      method: "DELETE",
      body: input,
      idempotencyKey,
      ...(signal ? { signal } : {}),
    });
  },
  listOccurrences(orgId, automationId, query, signal) {
    return requestAutomationJson(
      withQuery(`${orgPath(orgId)}/${encodeURIComponent(automationId)}/occurrences`, {
        limit: query?.limit ?? OCCURRENCE_PAGE_LIMIT,
        cursor: query?.cursor,
        state: query?.state,
      }),
      withSignal(signal),
      decodeOccurrencePage,
    );
  },
  getEntitlements(orgId, signal) {
    return requestAutomationJson(
      `/api/v1/orgs/${encodeURIComponent(orgId)}/entitlements`,
      withSignal(signal),
      decodeEntitlements,
    );
  },
};

async function requestAutomationJson<T>(
  path: string,
  options: RequestOptions,
  decode: (value: unknown) => T | null,
): Promise<T> {
  const result = await sendAutomationRequest(path, options);
  if (result.kind === "no-content") throw makeInvalidResponseError(result);
  const decoded = decode(result.body);
  if (decoded === null) throw makeInvalidResponseError(result);
  return decoded;
}

/** A confirmed delete answers `204` with no body, so only the status matters. */
async function requestAutomationNoContent(path: string, options: RequestOptions): Promise<void> {
  await sendAutomationRequest(path, options);
}

type AutomationResult =
  | { kind: "no-content"; requestId: string | undefined; status: number }
  | { kind: "json"; body: unknown; requestId: string | undefined; status: number };

async function sendAutomationRequest(
  path: string,
  options: RequestOptions,
): Promise<AutomationResult> {
  const method = (options.method ?? "GET").toUpperCase();
  const headers = new Headers();
  headers.set("Accept", "application/json");
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  if (options.idempotencyKey) headers.set("Idempotency-Key", options.idempotencyKey);
  if (!isSafeMethod(method)) {
    const csrf = readCookie("lumi_csrf");
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }

  const init: RequestInit = {
    method,
    headers,
    credentials: "include",
    ...(options.signal ? { signal: options.signal } : {}),
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
  };
  const retryable = isSafeMethod(method) || Boolean(options.idempotencyKey);

  let response: Response;
  try {
    response = await fetch(path, init);
  } catch (cause) {
    throw makeTransportError(cause, options.signal, { retryable });
  }

  const requestId = readRequestId(response.headers.get("X-Request-ID"));
  let text: string;
  try {
    text = await response.text();
  } catch (cause) {
    throw makeTransportError(cause, options.signal, {
      requestId,
      status: response.status,
      retryable: response.status >= 500 || response.status === 429,
    });
  }

  if (response.status === 204) {
    if (!response.ok) throw makeApiError(response.status, null, requestId, retryable);
    return { kind: "no-content", requestId, status: response.status };
  }

  let payload: unknown;
  let validJson = text.length > 0;
  if (validJson) {
    try {
      payload = JSON.parse(text) as unknown;
    } catch {
      validJson = false;
    }
  }

  if (!response.ok) {
    throw makeApiError(
      response.status,
      validJson ? payload : null,
      requestId,
      retryable && isRetryableStatus(response.status),
    );
  }
  if (!validJson) throw makeInvalidResponseError({ requestId, status: response.status });
  return { kind: "json", body: payload, requestId, status: response.status };
}

function isSafeMethod(method: string): boolean {
  return method === "GET" || method === "HEAD" || method === "OPTIONS";
}

function isRetryableStatus(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}

function makeApiError(
  status: number,
  payload: unknown,
  requestId: string | undefined,
  retryable: boolean,
): ApiClientError {
  const envelope = isObject(payload) && isObject(payload.error) ? payload.error : null;
  const bodyRequestId = readRequestId(
    typeof envelope?.request_id === "string" ? envelope.request_id : null,
  );
  const code = typeof envelope?.code === "string" ? envelope.code : null;
  if (code && /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/.test(code)) {
    return new ApiClientError({
      code,
      kind: "api",
      status,
      requestId: requestId ?? bodyRequestId,
      details: {},
      retryable,
    });
  }
  return apiErrorFromEnvelope(status, payload, requestId ?? bodyRequestId, retryable);
}

function readCookie(name: string): string | undefined {
  if (typeof document === "undefined") return undefined;
  const value = document.cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`))
    ?.slice(name.length + 1);
  return value && value.length <= 256 ? value : undefined;
}

function readRequestId(value: string | null): string | undefined {
  if (value === null) return undefined;
  const normalized = value.trim();
  return normalized.length > 0 && normalized.length <= 160 ? normalized : undefined;
}
