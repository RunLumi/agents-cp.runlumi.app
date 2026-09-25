import { describe, expect, it } from "vitest";

import fixture from "../../../../../docs/implementation/fixtures/p06-contracts-v1.json";

import { decodeEntitlementProjection, type EntitlementEntry } from "./api";
import {
  BASELINE_ENTITLEMENT_KEYS,
  countEntitlementSources,
  describeEntitlement,
  findEntitlementKey,
  humanizeKey,
  humanizeStatus,
  isBaselineEntitlementKey,
  isDenyingValue,
  orderEntitlements,
  PRECEDENCE_CHAIN,
  sourceLabel,
  sourceMeaning,
  sourceRank,
} from "./entitlements";

function entry(overrides: Partial<EntitlementEntry> & { key: string }): EntitlementEntry {
  return {
    value: null,
    source: "unknown",
    effective_at: null,
    expires_at: null,
    reason: null,
    scope: null,
    ...overrides,
  };
}

describe("entitlement key catalogue", () => {
  it("covers every baseline key frozen in the contract gate", () => {
    const expected = [
      "org.max_members",
      "projects.max_active",
      "inference.platform_managed",
      "inference.byok",
      "audit.retention_days",
      "automations.max_active",
      "devices.max_enrolled",
      "exports.enabled",
      "deletion.self_service",
      "webhooks.enabled",
      "sso.enabled",
      "scim.enabled",
    ];

    expect(BASELINE_ENTITLEMENT_KEYS.map((info) => info.key)).toEqual(expected);
  });

  it("treats only the members limit as seat-based", () => {
    expect(findEntitlementKey("org.max_members")?.seat_based).toBe(true);
    expect(findEntitlementKey("automations.max_active")?.seat_based).toBe(false);
  });

  it("marks a key outside the frozen baseline set", () => {
    expect(isBaselineEntitlementKey("webhooks.enabled")).toBe(true);
    expect(isBaselineEntitlementKey("usage.export_credit")).toBe(false);
    expect(findEntitlementKey("usage.export_credit")).toBeNull();
  });
});

describe("precedence chain presentation", () => {
  it("orders the chain weakest to strongest as the contract states", () => {
    expect(PRECEDENCE_CHAIN.map((step) => step.source)).toEqual([
      "platform_default",
      "plan",
      "subscription",
      "internal_override",
    ]);
    expect(PRECEDENCE_CHAIN.map((step) => step.rank)).toEqual([1, 2, 3, 4]);
  });

  it("ranks a known source and refuses to rank an unattributed value", () => {
    expect(sourceRank("platform_default")).toBe(1);
    expect(sourceRank("internal_override")).toBe(4);
    expect(sourceRank("unknown")).toBeNull();
  });

  it("says so plainly when the server withheld the source", () => {
    expect(sourceLabel("unknown")).toBe("Source not itemized");
    expect(sourceMeaning("unknown")).toContain("do not read it as a plan grant");
  });

  it("counts values per layer so an operator can see which layer acted", () => {
    const counts = countEntitlementSources([
      entry({ key: "org.max_members", source: "plan" }),
      entry({ key: "webhooks.enabled", source: "plan" }),
      entry({ key: "scim.enabled", source: "internal_override" }),
      entry({ key: "sso.enabled" }),
    ]);

    expect(counts).toEqual({
      platform_default: 0,
      plan: 2,
      subscription: 0,
      internal_override: 1,
      unknown: 1,
    });
  });
});

describe("entitlement value presentation", () => {
  it("renders a boolean, a limit, and a retention window distinctly", () => {
    expect(describeEntitlement(entry({ key: "webhooks.enabled", value: true })).valueText).toBe(
      "Included",
    );
    expect(describeEntitlement(entry({ key: "webhooks.enabled", value: false })).valueText).toBe(
      "Not included",
    );
    expect(
      describeEntitlement(entry({ key: "automations.max_active", value: 100 })).valueText,
    ).toBe("100");
    expect(describeEntitlement(entry({ key: "audit.retention_days", value: 365 })).valueText).toBe(
      "365 days",
    );
  });

  it("fails closed for a missing protected value", () => {
    const display = describeEntitlement(entry({ key: "scim.enabled" }));

    expect(display.missing).toBe(true);
    expect(display.valueText).toBe("Not granted");
    expect(display.enabled).toBeNull();
  });

  it("humanizes a key outside the baseline set instead of dropping it", () => {
    const display = describeEntitlement(entry({ key: "usage.export_credit", value: 5 }));

    expect(display.outsideBaseline).toBe(true);
    expect(display.label).toBe("Export credit");
  });

  it("orders baseline keys in gate order and appends later keys", () => {
    const ordered = orderEntitlements([
      entry({ key: "zzz.late_key" }),
      entry({ key: "webhooks.enabled" }),
      entry({ key: "org.max_members" }),
      entry({ key: "aaa.new_key" }),
    ]);

    expect(ordered.map((item) => item.key)).toEqual([
      "org.max_members",
      "webhooks.enabled",
      "aaa.new_key",
      "zzz.late_key",
    ]);
  });

  it("identifies a denying value", () => {
    expect(isDenyingValue(false)).toBe(true);
    expect(isDenyingValue(0)).toBe(true);
    expect(isDenyingValue(true)).toBe(false);
    expect(isDenyingValue(null)).toBe(false);
  });

  it("humanizes statuses for the operator", () => {
    expect(humanizeStatus("past_due")).toBe("Past Due");
    expect(humanizeStatus("provider_unavailable")).toBe("Provider Unavailable");
    expect(humanizeKey("devices.max_enrolled")).toBe("Max enrolled");
  });
});

describe("entitlement projection against the frozen fixture", () => {
  it("keeps the fixture values unattributed rather than guessing a plan", () => {
    const projection = decodeEntitlementProjection({
      org_id: fixture.entitlements.org_id,
      plan_key: fixture.entitlements.plan_key,
      status: fixture.entitlements.status,
      policy_fresh_until: fixture.entitlements.policy_fresh_until,
      offline_valid_until: fixture.entitlements.offline_valid_until,
      values: fixture.entitlements.values,
    });

    expect(projection.entitlements).toHaveLength(3);
    expect(projection.entitlements.every((item) => item.source === "unknown")).toBe(true);
    expect(projection.over_limit).toEqual([]);
  });
});
