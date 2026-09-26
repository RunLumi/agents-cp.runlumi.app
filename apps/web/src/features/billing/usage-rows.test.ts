/**
 * "Usage vs. plan limits" status derivation.
 *
 * WHY the derivation is tested as a pure function rather than through the
 * rendered card: the repository's web harness is `vitest` plus
 * `renderToStaticMarkup`. There is no DOM and no `act()`, so a container with
 * an async read can only ever render its loading branch. A status bug in this
 * card — reporting a resource as within limit when the server never published a
 * count, or inventing a zero — would be completely invisible to a markup
 * assertion, and would be the most damaging possible bug on a page whose whole
 * purpose is not to conflate plan limits with usage.
 *
 * So the contract-relevant logic is extracted to `usageRows` and tested here
 * against real baseline keys and real server shapes.
 */
import { describe, expect, it } from "vitest";

import type { EntitlementEntry, EntitlementAttribution, OverLimitResource } from "./api";
import { BASELINE_ENTITLEMENT_KEYS } from "./entitlements";
import { statusLabelFor, usageRows } from "./usage-rows";

const PLAN_SOURCE: EntitlementAttribution = "plan";

function entry(key: string, value: number | boolean | string | null): EntitlementEntry {
  return {
    key,
    value,
    source: PLAN_SOURCE,
    effective_at: "2026-01-01T00:00:00Z",
    expires_at: null,
    reason: null,
    scope: null,
  };
}

function overLimit(
  partial: Partial<OverLimitResource> & { entitlement_key: string },
): OverLimitResource {
  return {
    limit: 10,
    current: 14,
    over_by: 4,
    seat_based: false,
    remediation: [],
    ...partial,
  };
}

describe("usage rows", () => {
  it("covers every counted limit in the projection and nothing else", () => {
    const counted = BASELINE_ENTITLEMENT_KEYS.filter(
      (info) => info.kind === "limit" && info.resource !== null,
    ).map((info) => info.key);
    // Guards the fixture itself: if the baseline ever gains or loses a counted
    // limit, this test tells us the expectation moved rather than silently
    // passing against a stale key list.
    expect(counted.length).toBeGreaterThan(0);
    expect(counted).toContain("org.max_members");

    const rows = usageRows(
      counted.map((key) => entry(key, 10)),
      [],
    );

    expect(rows.map((row) => row.key)).toEqual(counted);
    for (const row of rows) {
      expect(row.resource).not.toBe("");
      expect(row.label).not.toBe("");
    }
  });

  it("excludes toggles and retention keys, which have no count to exceed", () => {
    const nonCounted = BASELINE_ENTITLEMENT_KEYS.filter(
      (info) => info.kind !== "limit" || info.resource === null,
    ).map((info) => info.key);
    expect(nonCounted.length).toBeGreaterThan(0);

    const rows = usageRows(
      BASELINE_ENTITLEMENT_KEYS.map((info) => entry(info.key, 5)),
      [],
    );

    for (const key of nonCounted) {
      expect(rows.map((row) => row.key)).not.toContain(key);
    }
  });

  it("reports a server-published over-limit resource with its real numbers", () => {
    const rows = usageRows(
      [entry("org.max_members", 10)],
      [overLimit({ entitlement_key: "org.max_members", limit: 10, current: 14, over_by: 4 })],
    );

    expect(rows).toHaveLength(1);
    const row = rows[0];
    expect(row?.status).toBe("over_limit");
    expect(row?.current).toBe(14);
    expect(row?.limit).toBe(10);
    expect(row?.overBy).toBe(4);
    expect(statusLabelFor(row!)).toBe("Over limit by 4");
  });

  it("prefers the server's reported limit over the plan value when they differ", () => {
    // The server counts against the effective limit it resolved, which can
    // differ from the raw entitlement value after a subscription grant. The
    // server's number is the one the resource was actually compared to, so
    // showing the raw value would misstate the comparison.
    const rows = usageRows(
      [entry("org.max_members", 25)],
      [overLimit({ entitlement_key: "org.max_members", limit: 10, current: 12, over_by: 2 })],
    );

    expect(rows[0]?.limit).toBe(10);
    expect(rows[0]?.current).toBe(12);
  });

  /**
   * The bug this exists to prevent: the contract publishes a current count
   * ONLY for a resource already over its limit. Absence from `over_limit` is
   * the server saying "not over", but it is NOT a count of zero, and rendering
   * it as 0 would state that the workspace has consumed nothing.
   */
  it("never invents a zero for a resource the server did not count", () => {
    const rows = usageRows([entry("org.max_members", 10)], []);

    expect(rows[0]?.status).toBe("within_limit");
    expect(rows[0]?.current).toBeNull();
    expect(rows[0]?.overBy).toBeNull();
    // The limit itself IS published, so it stays visible.
    expect(rows[0]?.limit).toBe(10);
    expect(statusLabelFor(rows[0]!)).toBe("Within limit");
  });

  it("fails a protected capability closed rather than calling it within limit", () => {
    // A null value on a limit is not "zero used" and not "unlimited" — the
    // effective value is missing, so no comparison is possible.
    const rows = usageRows([entry("org.max_members", null)], []);

    expect(rows[0]?.status).toBe("not_available");
    expect(rows[0]?.current).toBeNull();
    expect(rows[0]?.limit).toBeNull();
    expect(rows[0]?.includedText).toBe("Not granted");
    expect(statusLabelFor(rows[0]!)).toBe("Not available");
  });

  it("keeps an over-limit report visible even when the entitlement value is missing", () => {
    // The server counted the resource and found it over. That fact is
    // independent of whether the plan value resolved, and hiding it would
    // under-report a real overage.
    const rows = usageRows(
      [entry("org.max_members", null)],
      [overLimit({ entitlement_key: "org.max_members", current: 30, over_by: 20 })],
    );

    expect(rows[0]?.status).toBe("not_available");
    expect(rows[0]?.current).toBe(30);
    expect(rows[0]?.overBy).toBe(20);
  });

  it("marks a non-numeric limit as not comparable instead of coercing it", () => {
    const rows = usageRows([entry("org.max_members", "unlimited")], []);

    expect(rows[0]?.status).toBe("not_available");
    expect(rows[0]?.includedText).toBe("unlimited");
  });

  it("keeps baseline order so the table does not reshuffle between reads", () => {
    const keys = [
      "automations.max_active",
      "org.max_members",
      "projects.max_active",
      "devices.max_enrolled",
    ];
    const first = usageRows(
      keys.map((key) => entry(key, 5)),
      [],
    ).map((row) => row.key);
    const second = usageRows(
      [...keys].reverse().map((key) => entry(key, 5)),
      [],
    ).map((row) => row.key);

    expect(second).toEqual(first);
  });

  it("returns no rows for an empty projection rather than assuming everything fits", () => {
    expect(usageRows([], [])).toEqual([]);
  });
});
