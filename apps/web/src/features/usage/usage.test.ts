import { describe, expect, it } from "vitest";

import { buildUsageBreakdown, deriveDenials, summarizeUsage } from "./helpers";
import { formatMinorUnits, formatPercent } from "./money";
import { decodeBudget, sanitizeUsageEvent, type RawUsageEvent } from "./usage-contracts";

const baseEvent: RawUsageEvent = {
  id: "use_0123456789abcdef0123456789abcdef",
  request_id: "req_0123456789abcdef0123456789abcdef",
  org_id: "org_0123456789abcdef0123456789abcdef",
  project_id: "prj_0123456789abcdef0123456789abcdef",
  run_id: null,
  principal_user_id: "usr_0123456789abcdef0123456789abcdef",
  model_alias: "coding-default",
  route_version_id: "rtv_0123456789abcdef0123456789abcdef",
  provider_id: "prv_0123456789abcdef0123456789abcdef",
  model_id: "mdl_0123456789abcdef0123456789abcdef",
  input_tokens: 100,
  output_tokens: 20,
  cached_tokens: 5,
  estimated_cost_minor: 1250,
  actual_cost_minor: null,
  currency: "usd",
  pricing_version: "price-v1",
  budget_decision: "allow",
  ttft_ms: 100,
  total_latency_ms: 500,
  created_at: "2026-09-25T12:00:00.000Z",
  source: "run",
  reconciliation_status: "reconciled",
  provider_usage: { raw: "must not enter component state" },
};

describe("usage money and provenance helpers", () => {
  it("formats integer minor units without coercing missing currency", () => {
    expect(formatMinorUnits(123456, "USD", { showCode: true })).toBe("$1,234.56 USD");
    expect(formatMinorUnits(1234, "JPY", { showCode: true })).toBe("¥1,234 JPY");
    expect(formatMinorUnits(100, null, { showCode: true })).toBe("Currency unavailable");
    expect(formatPercent(120, 100)).toBe("120%");
  });

  it("sanitizes provider metadata and keeps only safe accounting fields", () => {
    const event = sanitizeUsageEvent(baseEvent);

    expect(event.usage_event_id).toBe(baseEvent.id);
    expect(event.currency).toBe("USD");
    expect(event.budget_decision).toBe("allow");
    expect(event).not.toHaveProperty("provider_usage");
    expect(event).not.toHaveProperty("session_id");
    expect(event).not.toHaveProperty("device_id");
  });

  it("keeps actual and estimated provenance without recalculating cost", () => {
    const event = sanitizeUsageEvent({
      ...baseEvent,
      actual_cost_minor: 1100,
    });
    const summary = summarizeUsage([event]);

    expect(summary.recordedMinor).toBe(1100);
    expect(summary.actualMinor).toBe(1100);
    expect(summary.estimatedMinor).toBe(0);
    expect(summary.pricingVersions).toEqual(["price-v1"]);
  });

  it("does not combine different currencies in a breakdown", () => {
    const rows = buildUsageBreakdown(
      [
        sanitizeUsageEvent(baseEvent),
        sanitizeUsageEvent({
          ...baseEvent,
          id: "use_1123456789abcdef0123456789abcdef",
          currency: "EUR",
          estimated_cost_minor: 900,
        }),
      ],
      "model",
    );

    expect(rows).toHaveLength(2);
    expect(rows.every((row) => row.costMinor !== null)).toBe(true);
  });

  it("separates denied requests from unavailable budget state", () => {
    const denied = sanitizeUsageEvent({ ...baseEvent, budget_decision: "rate_limit_exceeded" });
    const unavailable = sanitizeUsageEvent({
      ...baseEvent,
      id: "use_2123456789abcdef0123456789abcdef",
      budget_decision: "budget_state_unavailable",
    });

    expect(deriveDenials([denied, unavailable])).toHaveLength(1);
    expect(deriveDenials([denied, unavailable])[0]?.code).toBe("rate_limit_exceeded");
  });

  it("accepts the additive budget lifecycle defaults", () => {
    const budget = decodeBudget({
      budget_id: "bud_0123456789abcdef0123456789abcdef",
      org_id: "org_0123456789abcdef0123456789abcdef",
      scope_type: "organization",
      period_start: "2026-09-01T00:00:00.000Z",
      period_end: "2026-10-01T00:00:00.000Z",
      limit_minor: 100000,
      hard: true,
      currency: "USD",
    });

    expect(budget.lifecycle).toBe("active");
    expect(budget.state).toBe("active");
  });
});
