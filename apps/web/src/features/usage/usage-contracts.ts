import type { Page, UsageMetadata } from "@/lib/api";

import { isCurrencyCode, normalizeCurrency } from "./money";

export type UsageTab = "budgets" | "rate-limits" | "denials";

export type BudgetScopeType =
  | "organization"
  | "project"
  | "user"
  | "service_account"
  | "team"
  | "agent"
  | "model_alias";

export type BudgetLifecycle = "active" | "paused" | "archived" | "disabled";
export type BudgetDecisionCode = string;

export interface RawUsageEvent {
  id?: string;
  usage_event_id?: string;
  request_id?: string | null;
  org_id: string;
  project_id?: string | null;
  run_id?: string | null;
  principal_user_id: string;
  session_id?: string | null;
  device_id?: string | null;
  model_alias?: string | null;
  route_version_id?: string | null;
  provider_id?: string | null;
  model_id?: string | null;
  input_tokens?: number | null;
  output_tokens?: number | null;
  cached_tokens?: number | null;
  provider_usage?: Record<string, unknown>;
  estimated_cost_minor?: number | null;
  actual_cost_minor?: number | null;
  currency?: string | null;
  pricing_version?: string | null;
  budget_decision?: string;
  ttft_ms?: number | null;
  total_latency_ms?: number | null;
  created_at: string;
  source?: "inference" | "run";
  reconciliation_status?: "recorded" | "pending" | "reconciled" | "conflict";
  reconciliation_state?: "recorded" | "pending" | "reconciled" | "conflict";
  reconciled_at?: string | null;
  denial_code?: string | null;
}

export interface UsageEvent {
  usage_event_id: string;
  request_id: string;
  org_id: string;
  project_id: string | null;
  run_id: string | null;
  principal_user_id: string;
  model_alias: string;
  route_version_id: string;
  provider_id: string;
  model_id: string;
  input_tokens: number | null;
  output_tokens: number | null;
  cached_tokens: number | null;
  estimated_cost_minor: number | null;
  actual_cost_minor: number | null;
  currency: string | null;
  pricing_version: string | null;
  budget_decision: string;
  ttft_ms: number | null;
  total_latency_ms: number | null;
  created_at: string;
  source?: "inference" | "run";
  reconciliation_status?: "recorded" | "pending" | "reconciled" | "conflict";
  reconciled_at?: string | null;
  denial_code?: string | null;
}

/**
 * Only the safe accounting/provenance fields are retained in component state.
 * In particular, provider_usage is intentionally not copied from the P04
 * metadata object: it is provider-defined data and can contain more than the
 * control plane needs to display.
 */
export function sanitizeUsageEvent(value: UsageMetadata | RawUsageEvent): UsageEvent {
  const record = value as RawUsageEvent;
  const reconciliationStatus = safeEnum(
    record.reconciliation_status ?? record.reconciliation_state,
    ["recorded", "pending", "reconciled", "conflict"] as const,
  );
  const source = safeEnum(record.source, ["inference", "run"] as const);

  return {
    usage_event_id: safeText(record.usage_event_id, safeText(record.id, "unknown")),
    request_id: safeText(record.request_id, "unknown"),
    org_id: safeText(record.org_id, "unknown"),
    project_id: safeNullableText(record.project_id),
    run_id: safeNullableText(record.run_id),
    principal_user_id: safeText(record.principal_user_id, "unknown"),
    model_alias: safeText(record.model_alias, "unknown"),
    route_version_id: safeText(record.route_version_id, "unknown"),
    provider_id: safeText(record.provider_id, "unknown"),
    model_id: safeText(record.model_id, "unknown"),
    input_tokens: safeCount(record.input_tokens),
    output_tokens: safeCount(record.output_tokens),
    cached_tokens: safeCount(record.cached_tokens),
    estimated_cost_minor: safeCost(record.estimated_cost_minor),
    actual_cost_minor: safeCost(record.actual_cost_minor),
    currency: isCurrencyCode(record.currency) ? normalizeCurrency(record.currency) : null,
    pricing_version: safeNullableText(record.pricing_version),
    budget_decision: stableCode(safeText(record.budget_decision, "unknown")),
    ttft_ms: safeCount(record.ttft_ms),
    total_latency_ms: safeCount(record.total_latency_ms),
    created_at: safeText(record.created_at, ""),
    ...(source ? { source } : {}),
    ...(reconciliationStatus ? { reconciliation_status: reconciliationStatus } : {}),
    ...(typeof record.reconciled_at === "string" ? { reconciled_at: record.reconciled_at } : {}),
    ...(typeof record.denial_code === "string"
      ? { denial_code: stableCode(record.denial_code) }
      : {}),
  };
}

export interface CostRecord {
  cost_record_id: string;
  usage_event_id: string;
  org_id: string;
  project_id: string | null;
  run_id: string | null;
  pricing_source: string;
  pricing_version: string;
  pricing_effective_at: string;
  calculation_kind: "estimated" | "actual" | "recalculated";
  input_tokens: number | null;
  output_tokens: number | null;
  cached_tokens: number | null;
  cost_minor: number;
  currency: string;
  created_at: string;
}

export interface Budget {
  budget_id: string;
  org_id: string;
  scope_type: BudgetScopeType;
  scope_id: string | null;
  period_start: string;
  period_end: string;
  limit_minor: number;
  spent_minor: number | null;
  used_minor: number | null;
  reserved_minor: number | null;
  currency: string | null;
  hard: boolean;
  lifecycle: BudgetLifecycle;
  state: "active" | "paused" | "archived" | "disabled" | "unavailable";
  version: number;
  updated_at: string | null;
}

export interface BudgetReservation {
  reservation_id: string;
  request_id: string;
  run_id: string | null;
  org_id: string;
  budget_id: string | null;
  reserved_minor: number;
  committed_minor: number | null;
  status: "reserved" | "committed" | "released" | "expired" | "failed";
  currency: string | null;
  expires_at: string;
  reconciled_at: string | null;
  created_at: string;
}

export interface RateLimitPolicy {
  rate_limit_policy_id: string;
  org_id: string;
  scope_type: Extract<
    BudgetScopeType,
    "organization" | "project" | "user" | "service_account" | "model_alias"
  >;
  scope_id: string | null;
  requests_per_minute: number | null;
  tokens_per_minute: number | null;
  max_concurrent_requests: number | null;
  applicable_model_aliases: string[];
  status: "healthy" | "rate_limited" | "degraded" | "unhealthy" | "disabled" | "unknown";
  version: number;
  updated_at: string | null;
}

export interface UsageDenial {
  denial_id: string;
  org_id: string;
  code: string;
  request_id: string | null;
  run_id: string | null;
  project_id: string | null;
  scope_type: BudgetScopeType | null;
  scope_id: string | null;
  model_alias: string | null;
  limit_type: "budget" | "rate_limit" | "concurrency" | "policy" | "unknown";
  retry_after_seconds: number | null;
  created_at: string;
}

export interface UsageTrendPoint {
  bucket_start: string;
  cost_minor: number;
  currency: string | null;
  event_count: number;
  input_tokens: number;
  output_tokens: number;
}

export interface UsageBudgetsData {
  /** Optional tenant marker; a mismatched snapshot is ignored on org switch. */
  orgId?: string;
  usage?: UsageEvent[];
  budgets?: Budget[];
  reservations?: BudgetReservation[];
  rateLimits?: RateLimitPolicy[];
  denials?: UsageDenial[];
  trend?: UsageTrendPoint[];
  updatedAt?: string;
}

/**
 * The only required client method is the existing P04/P05 usage read. The
 * optional methods map to the frozen P05 routes and can be added to api.ts by
 * the coordinator without changing this feature's component contract.
 */
export interface UsageApi {
  listUsage: (orgId: string, signal?: AbortSignal) => Promise<Page<RawUsageEvent>>;
  /** Preferred P05 usage read when the shared API client exposes it. */
  listUsageEvents?: (orgId: string, signal?: AbortSignal) => Promise<Page<RawUsageEvent>>;
  listBudgets?: (orgId: string, signal?: AbortSignal) => Promise<Page<Budget>>;
  listRateLimits?: (orgId: string, signal?: AbortSignal) => Promise<Page<RateLimitPolicy>>;
  listUsageDenials?: (orgId: string, signal?: AbortSignal) => Promise<Page<UsageDenial>>;
  listBudgetReservations?: (
    orgId: string,
    signal?: AbortSignal,
  ) => Promise<Page<BudgetReservation>>;
}

export class UsageContractError extends Error {
  constructor() {
    super("The usage response did not match the expected contract.");
    this.name = "UsageContractError";
  }
}

export function decodeBudget(value: unknown): Budget {
  const record = objectValue(value);
  const scopeType = readEnum(record.scope_type, [
    "organization",
    "project",
    "user",
    "service_account",
    "team",
    "agent",
    "model_alias",
  ]);
  const hard = readBoolean(record.hard);
  const lifecycle =
    readNullableEnum(record.lifecycle, ["active", "paused", "archived", "disabled"]) ?? "active";
  const state =
    readNullableEnum(record.state, ["active", "paused", "archived", "disabled", "unavailable"]) ??
    "active";

  return {
    budget_id: readString(record.budget_id) ?? readString(record.id) ?? invalid("budget_id"),
    org_id: readString(record.org_id) ?? invalid("org_id"),
    scope_type: scopeType,
    scope_id: readNullableString(record.scope_id),
    period_start: readString(record.period_start) ?? invalid("period_start"),
    period_end: readString(record.period_end) ?? invalid("period_end"),
    limit_minor: readMinor(record.limit_minor) ?? invalid("limit_minor"),
    spent_minor: readOptionalMinor(record.spent_minor),
    used_minor: readOptionalMinor(record.used_minor),
    reserved_minor: readOptionalMinor(record.reserved_minor),
    currency: readNullableString(record.currency),
    hard,
    lifecycle,
    state,
    version: readPositiveInteger(record.version) ?? 1,
    updated_at: readNullableString(record.updated_at),
  };
}

export function decodeBudgetReservation(value: unknown): BudgetReservation {
  const record = objectValue(value);
  const status = readEnum(record.status, [
    "reserved",
    "committed",
    "released",
    "expired",
    "failed",
  ]);

  return {
    reservation_id:
      readString(record.reservation_id) ?? readString(record.id) ?? invalid("reservation_id"),
    request_id: readString(record.request_id) ?? invalid("request_id"),
    run_id: readNullableString(record.run_id),
    org_id: readString(record.org_id) ?? invalid("org_id"),
    budget_id: readNullableString(record.budget_id),
    reserved_minor: readMinor(record.reserved_minor) ?? invalid("reserved_minor"),
    committed_minor: readOptionalMinor(record.committed_minor),
    status,
    currency: readNullableString(record.currency),
    expires_at: readString(record.expires_at) ?? invalid("expires_at"),
    reconciled_at: readNullableString(record.reconciled_at),
    created_at: readString(record.created_at) ?? invalid("created_at"),
  };
}

export function decodeRateLimitPolicy(value: unknown): RateLimitPolicy {
  const record = objectValue(value);
  const scopeType = readEnum(record.scope_type, [
    "organization",
    "project",
    "user",
    "service_account",
    "model_alias",
  ]);
  const status =
    record.enabled === false
      ? "disabled"
      : (readNullableEnum(record.status, [
          "healthy",
          "rate_limited",
          "degraded",
          "unhealthy",
          "unknown",
        ]) ?? "unknown");

  return {
    rate_limit_policy_id:
      readString(record.rate_limit_policy_id) ??
      readString(record.policy_id) ??
      readString(record.id) ??
      invalid("rate_limit_policy_id"),
    org_id: readString(record.org_id) ?? invalid("org_id"),
    scope_type: scopeType,
    scope_id: readNullableString(record.scope_id),
    requests_per_minute: readOptionalPositiveInteger(record.requests_per_minute),
    tokens_per_minute: readOptionalPositiveInteger(record.tokens_per_minute),
    max_concurrent_requests: readOptionalPositiveInteger(record.max_concurrent_requests),
    applicable_model_aliases: readStringArray(
      record.applicable_model_aliases ?? record.model_aliases ?? record.model_alias,
    ),
    status,
    version: readPositiveInteger(record.version) ?? 1,
    updated_at: readNullableString(record.updated_at),
  };
}

export function decodeUsageDenial(value: unknown): UsageDenial {
  const record = objectValue(value);
  const limitType = readEnum(record.limit_type, [
    "budget",
    "rate_limit",
    "concurrency",
    "policy",
    "unknown",
  ]);

  return {
    denial_id:
      readString(record.denial_id) ??
      readString(record.event_id) ??
      readString(record.id) ??
      readString(record.request_id) ??
      invalid("denial_id"),
    org_id: readString(record.org_id) ?? invalid("org_id"),
    code: stableCode(readString(record.code) ?? readString(record.reason)),
    request_id: readNullableString(record.request_id),
    run_id: readNullableString(record.run_id),
    project_id: readNullableString(record.project_id),
    scope_type: readNullableEnum(record.scope_type, [
      "organization",
      "project",
      "user",
      "service_account",
      "team",
      "agent",
      "model_alias",
    ]),
    scope_id: readNullableString(record.scope_id),
    model_alias: readNullableString(record.model_alias),
    limit_type: limitType,
    retry_after_seconds: readOptionalPositiveInteger(record.retry_after_seconds),
    created_at: readString(record.created_at) ?? invalid("created_at"),
  };
}

export function decodeCostRecord(value: unknown): CostRecord {
  const record = objectValue(value);
  const calculationKind = readEnum(record.calculation_kind, [
    "estimated",
    "actual",
    "recalculated",
  ]);

  return {
    cost_record_id:
      readString(record.cost_record_id) ?? readString(record.id) ?? invalid("cost_record_id"),
    usage_event_id: readString(record.usage_event_id) ?? invalid("usage_event_id"),
    org_id: readString(record.org_id) ?? invalid("org_id"),
    project_id: readNullableString(record.project_id),
    run_id: readNullableString(record.run_id),
    pricing_source: readString(record.pricing_source) ?? invalid("pricing_source"),
    pricing_version: readString(record.pricing_version) ?? invalid("pricing_version"),
    pricing_effective_at:
      readString(record.pricing_effective_at) ?? invalid("pricing_effective_at"),
    calculation_kind: calculationKind,
    input_tokens: readOptionalMinor(record.input_tokens),
    output_tokens: readOptionalMinor(record.output_tokens),
    cached_tokens: readOptionalMinor(record.cached_tokens),
    cost_minor: readMinor(record.cost_minor) ?? invalid("cost_minor"),
    currency: readNullableString(record.currency) ?? invalid("currency"),
    created_at: readString(record.created_at) ?? invalid("created_at"),
  };
}

function safeText(value: unknown, fallback: string): string {
  if (typeof value !== "string") return fallback;
  const normalized = value.trim();
  return normalized.length > 0 && normalized.length <= 512 ? normalized : fallback;
}

function safeNullableText(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value.trim().slice(0, 512) : null;
}

function safeCount(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function safeCost(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function safeEnum<const T extends readonly string[]>(value: unknown, values: T): T[number] | null {
  return typeof value === "string" && values.includes(value) ? (value as T[number]) : null;
}

function objectValue(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalid("object");
  return value as Record<string, unknown>;
}

function readString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim();
  return normalized.length > 0 && normalized.length <= 512 ? normalized : null;
}

function stableCode(value: string | null): string {
  if (!value) return "request_denied";
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, "_");
  return normalized.slice(0, 96) || "request_denied";
}

function readNullableString(value: unknown): string | null {
  return readString(value);
}

function readStringArray(value: unknown): string[] {
  if (typeof value === "string") return value.length <= 512 ? [value] : [];
  if (!Array.isArray(value)) return [];
  return value
    .filter((item): item is string => typeof item === "string" && item.trim().length > 0)
    .map((item) => item.trim().slice(0, 160));
}

function readEnum<const T extends readonly string[]>(value: unknown, values: T): T[number] {
  return typeof value === "string" && values.includes(value)
    ? (value as T[number])
    : invalid("enum");
}

function readNullableEnum<const T extends readonly string[]>(
  value: unknown,
  values: T,
): T[number] | null {
  return typeof value === "string" && values.includes(value) ? (value as T[number]) : null;
}

function readBoolean(value: unknown): boolean {
  if (typeof value === "boolean") return value;
  if (value === 1) return true;
  if (value === 0) return false;
  return invalid("boolean");
}

function readMinor(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function readOptionalMinor(value: unknown): number | null {
  return value === null || value === undefined ? null : readMinor(value);
}

function readPositiveInteger(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : null;
}

function readOptionalPositiveInteger(value: unknown): number | null {
  return value === null || value === undefined ? null : readPositiveInteger(value);
}

function invalid(_field: string): never {
  throw new UsageContractError();
}
