/**
 * "Usage vs. plan limits" row derivation.
 *
 * Split from `usage-vs-limits.tsx` deliberately: this is the part of the card
 * whose correctness the rendered markup cannot demonstrate. The repository's
 * web harness is `vitest` plus `renderToStaticMarkup` — no DOM, no `act()` — so
 * a container fed by an async read can only ever render its loading branch. The
 * status logic therefore lives here, free of JSX, and is tested directly in
 * `usage-rows.test.ts`.
 *
 * The card this feeds is the second of the two tables
 * `docs/screens/lumi_plan_entitlements.webp` sets side by side. The reference
 * places "Included capabilities" next to "Usage vs. plan limits" precisely so a
 * reader never has to infer that *what the plan includes* and *how much of it
 * is used* are different questions. Collapsing them into one table is what lets
 * a plan total be read as a usage total, which P06-CR-002 forbids.
 */

import type { EntitlementEntry, EntitlementProjection, OverLimitResource } from "./api";
import { describeEntitlement, orderEntitlements } from "./entitlements";
import type { BillingTone } from "./ui";

/**
 * How a counted limit compares to the plan.
 *
 * `not_available` is not a fourth opinion about usage. It is the honest answer
 * when the frozen contract publishes nothing to compare: a protected
 * capability with no entitlement value fails closed, and a non-numeric limit
 * cannot be weighed against a count at all.
 */
export type UsageStatus = "over_limit" | "within_limit" | "not_available";

export interface UsageRow {
  key: string;
  /** Human label from the frozen baseline key set. */
  label: string;
  /** The resource identifier the server counts against this key. */
  resource: string;
  /**
   * The server-published current count, or `null` when the contract publishes
   * none. `GET /entitlements` reports counts ONLY for resources already above
   * their limit, so `null` here means "not published" — never "zero".
   */
  current: number | null;
  /** The limit the comparison was actually made against, or `null`. */
  limit: number | null;
  /** Human rendering of the included limit, which may be non-numeric. */
  includedText: string;
  status: UsageStatus;
  /** How far over the limit, when the server says it is over. */
  overBy: number | null;
}

/**
 * Derive one row per counted limit in the projection.
 *
 * A key qualifies when the frozen baseline describes it as a `limit` the server
 * counts a resource against. Toggles and retention keys are excluded: they have
 * no count to exceed.
 *
 * Status resolution, in order:
 *
 * 1. No numeric value, or a null value on a protected capability — no
 *    comparison is possible, so the row is `not_available`. It is never
 *    optimistically reported as within limit, because a missing value on a
 *    protected capability fails closed.
 * 2. The server listed the key in `over_limit` — `over_limit`. Count, limit and
 *    overshoot are all server-published.
 * 3. Otherwise — `within_limit`. Absence from `over_limit` IS the server's
 *    statement that the resource is not above its limit; the count itself is
 *    simply not published, so `current` stays `null` rather than being faked
 *    as 0.
 */
export function usageRows(
  entitlements: readonly EntitlementEntry[],
  overLimit: readonly OverLimitResource[],
): UsageRow[] {
  const reported = new Map<string, OverLimitResource>(
    overLimit.map((resource) => [resource.entitlement_key, resource]),
  );

  const rows: UsageRow[] = [];
  for (const entry of orderEntitlements(entitlements)) {
    const display = describeEntitlement(entry);
    if (display.info === null || display.info.kind !== "limit") continue;
    if (display.info.resource === null) continue;

    const over = reported.get(entry.key) ?? null;
    const comparable = !display.missing && display.numeric !== null;

    if (!comparable) {
      rows.push({
        key: entry.key,
        label: display.label,
        resource: display.info.resource,
        // An over-limit report stays visible even when the plan value did not
        // resolve: the server counted the resource and found it over, and
        // hiding that would under-report a real overage.
        current: over?.current ?? null,
        limit: null,
        includedText: display.valueText,
        status: "not_available",
        overBy: over?.over_by ?? null,
      });
      continue;
    }

    rows.push({
      key: entry.key,
      label: display.label,
      resource: display.info.resource,
      current: over?.current ?? null,
      // The server counts against the effective limit it resolved, which can
      // differ from the raw entitlement value after a subscription grant. Its
      // number is the one the resource was actually compared to.
      limit: over?.limit ?? display.numeric,
      includedText: display.valueText,
      status: over ? "over_limit" : "within_limit",
      overBy: over?.over_by ?? null,
    });
  }
  return rows;
}

export function statusTone(status: UsageStatus): BillingTone {
  if (status === "over_limit") return "danger";
  if (status === "within_limit") return "success";
  return "neutral";
}

export function statusLabelFor(row: UsageRow): string {
  if (row.status === "over_limit") return `Over limit by ${row.overBy ?? row.current ?? 0}`;
  if (row.status === "not_available") return "Not available";
  return "Within limit";
}

/** Build the rows for a whole projection. */
export function usageRowsFor(projection: EntitlementProjection): UsageRow[] {
  return usageRows(projection.entitlements, projection.over_limit);
}
