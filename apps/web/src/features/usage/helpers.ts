import type {
  Budget,
  BudgetReservation,
  BudgetScopeType,
  UsageDenial,
  UsageEvent,
  UsageTrendPoint,
} from "./usage-contracts";
import { addMinorUnits, formatMinorUnits } from "./money";

export type RecordedCostKind = "actual" | "estimated" | "unknown";

export interface RecordedCost {
  minor: number | null;
  currency: string | null;
  kind: RecordedCostKind;
  pricingVersion: string | null;
}

export interface UsageSummary {
  eventCount: number;
  recordedMinor: number | null;
  actualMinor: number | null;
  estimatedMinor: number | null;
  unknownCostCount: number;
  primaryCurrency: string | null;
  currencies: string[];
  mixedCurrencies: boolean;
  inputTokens: number;
  outputTokens: number;
  pricingVersions: string[];
  deniedCount: number;
  unavailableCount: number;
}

export interface BudgetUsageSummary {
  usedMinor: number | null;
  reservedMinor: number | null;
  currency: string | null;
  pricingVersions: string[];
  derived: boolean;
  scopeSupported: boolean;
}

export type UsageBreakdownDimension = "project" | "user" | "model" | "provider";

export interface UsageBreakdownRow {
  key: string;
  label: string;
  eventCount: number;
  inputTokens: number;
  outputTokens: number;
  costMinor: number | null;
  currency: string | null;
}

export function recordedCostForEvent(event: UsageEvent): RecordedCost {
  if (isSafeCost(event.actual_cost_minor)) {
    return {
      minor: event.actual_cost_minor,
      currency: event.currency,
      kind: "actual",
      pricingVersion: event.pricing_version,
    };
  }
  if (isSafeCost(event.estimated_cost_minor)) {
    return {
      minor: event.estimated_cost_minor,
      currency: event.currency,
      kind: "estimated",
      pricingVersion: event.pricing_version,
    };
  }
  return {
    minor: null,
    currency: event.currency,
    kind: "unknown",
    pricingVersion: event.pricing_version,
  };
}

export function summarizeUsage(events: readonly UsageEvent[]): UsageSummary {
  const costs = events.map(recordedCostForEvent);
  const knownCosts = costs.filter(
    (cost): cost is RecordedCost & { minor: number; currency: string } =>
      cost.minor !== null && cost.currency !== null,
  );
  const currencies = unique(knownCosts.map((cost) => cost.currency));
  const primaryCurrency = currencies.length === 1 ? (currencies[0] ?? null) : null;
  const sameCurrencyCosts = primaryCurrency
    ? knownCosts.filter((cost) => cost.currency === primaryCurrency)
    : [];
  const actualMinor = addMinorUnits(
    sameCurrencyCosts.filter((cost) => cost.kind === "actual").map((cost) => cost.minor),
  );
  const estimatedMinor = addMinorUnits(
    sameCurrencyCosts.filter((cost) => cost.kind === "estimated").map((cost) => cost.minor),
  );
  const recordedMinor =
    sameCurrencyCosts.length === 0
      ? null
      : addMinorUnits(sameCurrencyCosts.map((cost) => cost.minor));
  const pricingVersions = unique(
    events
      .map((event) => event.pricing_version)
      .filter((version): version is string => typeof version === "string" && version.length > 0),
  );

  return {
    eventCount: events.length,
    recordedMinor,
    actualMinor,
    estimatedMinor,
    unknownCostCount: events.filter((event) => recordedCostForEvent(event).minor === null).length,
    primaryCurrency,
    currencies,
    mixedCurrencies: currencies.length > 1,
    inputTokens: sumTokens(events.map((event) => event.input_tokens)),
    outputTokens: sumTokens(events.map((event) => event.output_tokens)),
    pricingVersions,
    deniedCount: events.filter((event) => isDeniedDecision(event.budget_decision)).length,
    unavailableCount: events.filter((event) => isUnavailableDecision(event.budget_decision)).length,
  };
}

export function buildUsageBreakdown(
  events: readonly UsageEvent[],
  dimension: UsageBreakdownDimension,
): UsageBreakdownRow[] {
  const rows = new Map<string, UsageBreakdownRow>();
  for (const event of events) {
    const value = breakdownValue(event, dimension);
    const cost = recordedCostForEvent(event);
    const key = `${value}:${cost.currency ?? "unknown"}`;
    const current = rows.get(key);
    if (current) {
      current.eventCount += 1;
      current.inputTokens = sumTokens([current.inputTokens, event.input_tokens]);
      current.outputTokens = sumTokens([current.outputTokens, event.output_tokens]);
      current.costMinor =
        current.costMinor === null || cost.minor === null
          ? current.costMinor === null && cost.minor === null
            ? null
            : addMinorUnits([current.costMinor, cost.minor])
          : addMinorUnits([current.costMinor, cost.minor]);
      continue;
    }
    rows.set(key, {
      key,
      label: value,
      eventCount: 1,
      inputTokens: event.input_tokens ?? 0,
      outputTokens: event.output_tokens ?? 0,
      costMinor: cost.minor,
      currency: cost.currency,
    });
  }
  return [...rows.values()].sort((left, right) => {
    if (right.eventCount !== left.eventCount) return right.eventCount - left.eventCount;
    return left.label.localeCompare(right.label);
  });
}

export function deriveDenials(events: readonly UsageEvent[]): UsageDenial[] {
  return events
    .filter(
      (event) =>
        isDeniedDecision(event.budget_decision) ||
        (event.denial_code !== undefined &&
          event.denial_code !== null &&
          !isUnavailableDecision(event.denial_code)),
    )
    .map((event) => ({
      denial_id: event.usage_event_id,
      org_id: event.org_id,
      code: event.denial_code ?? decisionCode(event.budget_decision),
      request_id: event.request_id,
      run_id: event.run_id,
      project_id: event.project_id,
      scope_type: null,
      scope_id: null,
      model_alias: event.model_alias,
      limit_type: limitTypeForCode(event.denial_code ?? event.budget_decision),
      retry_after_seconds: null,
      created_at: event.created_at,
    }));
}

export function budgetUsage(
  budget: Budget,
  events: readonly UsageEvent[],
  reservations: readonly BudgetReservation[] = [],
): BudgetUsageSummary {
  const directSpent = budget.spent_minor ?? budget.used_minor;
  if (directSpent !== null) {
    return {
      usedMinor: directSpent,
      reservedMinor: budget.reserved_minor,
      currency: budget.currency,
      pricingVersions: [],
      derived: false,
      scopeSupported: true,
    };
  }

  const scopeSupported = scopeCanBeMatched(budget.scope_type);
  const matchingEvents = scopeSupported
    ? events.filter((event) => eventMatchesBudget(event, budget))
    : [];
  const costs = matchingEvents
    .map(recordedCostForEvent)
    .filter((cost): cost is RecordedCost & { minor: number } => cost.minor !== null);
  const currencies = unique(
    costs.map((cost) => cost.currency).filter((currency): currency is string => currency !== null),
  );
  const currency = currencies.length === 1 ? (currencies[0] ?? null) : budget.currency;
  const sameCurrencyCosts = currency ? costs.filter((cost) => cost.currency === currency) : [];
  const usedMinor =
    sameCurrencyCosts.length === 0
      ? null
      : addMinorUnits(sameCurrencyCosts.map((cost) => cost.minor));
  const matchingReservations = reservations.filter(
    (reservation) =>
      reservation.org_id === budget.org_id &&
      (reservation.budget_id === null || reservation.budget_id === budget.budget_id) &&
      reservation.status === "reserved",
  );
  const matchingReservationAmounts = matchingReservations
    .filter((reservation) => reservation.currency === null || reservation.currency === currency)
    .map((reservation) => reservation.reserved_minor);
  const reservedMinor =
    budget.reserved_minor ??
    (matchingReservationAmounts.length === 0 ? null : addMinorUnits(matchingReservationAmounts));

  return {
    usedMinor,
    reservedMinor,
    currency,
    pricingVersions: unique(
      matchingEvents
        .map((event) => event.pricing_version)
        .filter((version): version is string => typeof version === "string" && version.length > 0),
    ),
    derived: true,
    scopeSupported,
  };
}

export function buildUsageTrend(events: readonly UsageEvent[], maxPoints = 14): UsageTrendPoint[] {
  const buckets = new Map<string, UsageTrendPoint>();
  for (const event of events) {
    const timestamp = Date.parse(event.created_at);
    if (Number.isNaN(timestamp)) continue;
    const date = new Date(timestamp);
    const bucketStart = new Date(
      Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()),
    ).toISOString();
    const cost = recordedCostForEvent(event);
    if (cost.minor === null) continue;
    const bucketKey = `${bucketStart}:${cost.currency ?? "unknown"}`;
    const current = buckets.get(bucketKey);
    const nextCost = (current?.cost_minor ?? 0) + cost.minor;
    if (!Number.isSafeInteger(nextCost)) continue;
    buckets.set(bucketKey, {
      bucket_start: bucketStart,
      cost_minor: nextCost,
      currency: current?.currency ?? cost.currency,
      event_count: (current?.event_count ?? 0) + 1,
      input_tokens: (current?.input_tokens ?? 0) + (event.input_tokens ?? 0),
      output_tokens: (current?.output_tokens ?? 0) + (event.output_tokens ?? 0),
    });
  }

  return [...buckets.values()]
    .sort((left, right) => left.bucket_start.localeCompare(right.bucket_start))
    .slice(-Math.max(1, maxPoints));
}

export function isDeniedDecision(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return (
    [
      "deny",
      "denied",
      "blocked",
      "block",
      "budget_exceeded",
      "rate_limit_exceeded",
      "concurrency_limit_exceeded",
    ].includes(normalized) ||
    normalized.includes("denied") ||
    normalized.includes("blocked") ||
    normalized.endsWith("_exceeded")
  );
}

export function isUnavailableDecision(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return normalized === "unavailable" || normalized === "budget_state_unavailable";
}

export function decisionCode(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (normalized === "deny" || normalized === "denied") return "request_denied";
  if (normalized === "blocked" || normalized === "block") return "request_blocked";
  return normalized.replace(/[^a-z0-9_]+/g, "_").slice(0, 96) || "request_denied";
}

export function limitTypeForCode(value: string): UsageDenial["limit_type"] {
  const normalized = value.trim().toLowerCase();
  if (normalized.includes("rate")) return "rate_limit";
  if (normalized.includes("concurr")) return "concurrency";
  if (normalized.includes("budget")) return "budget";
  if (normalized.includes("policy")) return "policy";
  return "unknown";
}

export function formatScopeLabel(scope: BudgetScopeType, scopeId: string | null): string {
  const label = scope.replaceAll("_", " ");
  if (!scopeId) return label;
  return `${label} · ${scopeId}`;
}

export function formatShortId(value: string | null | undefined): string {
  if (!value) return "—";
  return value.length > 16 ? `${value.slice(0, 13)}…` : value;
}

export function formatUsageTimestamp(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
}

export function formatUsageDate(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export function formatCost(cost: RecordedCost, showCode = false): string {
  return formatMinorUnits(cost.minor, cost.currency, { showCode });
}

function breakdownValue(event: UsageEvent, dimension: UsageBreakdownDimension): string {
  if (dimension === "project") return event.project_id ?? "Organization";
  if (dimension === "user") return event.principal_user_id;
  if (dimension === "model") return event.model_alias;
  return event.provider_id;
}

function eventMatchesBudget(event: UsageEvent, budget: Budget): boolean {
  const timestamp = Date.parse(event.created_at);
  const periodStart = Date.parse(budget.period_start);
  const periodEnd = Date.parse(budget.period_end);
  if (!Number.isFinite(periodStart) || !Number.isFinite(periodEnd)) return false;
  if (!Number.isFinite(timestamp) || timestamp < periodStart || timestamp >= periodEnd)
    return false;

  switch (budget.scope_type) {
    case "organization":
      return true;
    case "project":
      return budget.scope_id !== null && event.project_id === budget.scope_id;
    case "user":
    case "service_account":
      return budget.scope_id !== null && event.principal_user_id === budget.scope_id;
    case "model_alias":
      return budget.scope_id !== null && event.model_alias === budget.scope_id;
    case "team":
    case "agent":
      return false;
  }
}

function scopeCanBeMatched(scope: BudgetScopeType): boolean {
  return scope !== "team" && scope !== "agent";
}

function isSafeCost(value: number | null): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function sumTokens(values: readonly (number | null)[]): number {
  let total = 0;
  for (const value of values) {
    if (value === null || !Number.isSafeInteger(value) || value < 0) continue;
    total += value;
    if (!Number.isSafeInteger(total)) return Number.MAX_SAFE_INTEGER;
  }
  return total;
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}
