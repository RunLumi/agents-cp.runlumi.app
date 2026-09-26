/**
 * "Usage vs. plan limits" — the second of the two tables
 * `docs/screens/lumi_plan_entitlements.webp` sets side by side, beside
 * "Included capabilities".
 *
 * All status derivation lives in `usage-rows.ts` so it can be unit tested
 * without a DOM; this file is presentation only. See that module for why the
 * split exists.
 */

import type { EntitlementProjection } from "./api";
import { statusLabelFor, statusTone, usageRowsFor } from "./usage-rows";
import {
  BillingEmpty,
  BillingPanel,
  BillingPanelHeader,
  BillingPill,
  BillingTableCaption,
} from "./ui";

export function UsageVsPlanLimits({
  projection,
  onReviewOverLimit,
}: {
  projection: EntitlementProjection;
  /**
   * Moves focus to the over-limit projection further down the page. Omitted
   * when nothing is over limit, because the affordance must never point at a
   * region that is not rendered.
   */
  onReviewOverLimit?: () => void;
}) {
  const rows = usageRowsFor(projection);
  const counted = rows.length;
  const overCount = rows.filter((row) => row.status === "over_limit").length;
  const unreported = rows.filter((row) => row.current === null).length;

  return (
    <BillingPanel ariaLabel="Usage versus plan limits">
      <BillingPanelHeader
        eyebrow="USAGE VS. PLAN LIMITS"
        title="Current usage against what is included"
        description="Your current usage for this billing period, compared to what is included in your plan. Usage budgets are a separate input from the plan and are enforced in Usage & Budgets."
        action={
          onReviewOverLimit ? (
            <button
              type="button"
              className="inline-flex min-h-10 items-center gap-1 rounded-lg px-1 text-sm font-medium text-[var(--lumi-blue)] outline-none transition hover:underline focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
              onClick={onReviewOverLimit}
            >
              Review over-limit resources
              <span aria-hidden="true">&rarr;</span>
            </button>
          ) : null
        }
      />

      <div className="space-y-4 p-5">
        {rows.length === 0 ? (
          <BillingEmpty
            title="No counted limits were returned"
            description="This projection published no countable limit. An empty table is not a statement that every resource is within its limit; the server is authoritative."
          />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-[var(--border)]">
            <table className="w-full min-w-[560px] text-left text-sm">
              <BillingTableCaption>
                Counted limits on plan {projection.plan_key ?? "unknown"}, with the server's
                reported usage
              </BillingTableCaption>
              <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
                <tr>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Resource
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Current usage
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Included in plan
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Status
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {rows.map((row) => (
                  <tr key={row.key} className="align-top">
                    <th
                      scope="row"
                      className="px-4 py-4 text-left font-medium text-[var(--civic-navy)]"
                    >
                      {row.label}
                      <code className="mt-0.5 block break-all font-mono text-xs font-normal text-[var(--muted)]">
                        {row.key}
                      </code>
                    </th>
                    <td className="px-4 py-4 tabular-nums text-[var(--civic-navy)]">
                      {row.current === null ? (
                        <span className="text-[var(--muted)]">&mdash;</span>
                      ) : (
                        row.current
                      )}
                    </td>
                    <td className="px-4 py-4 font-medium tabular-nums text-[var(--civic-navy)]">
                      {row.includedText}
                    </td>
                    <td className="px-4 py-4">
                      <BillingPill tone={statusTone(row.status)}>{statusLabelFor(row)}</BillingPill>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <p className="text-xs leading-5 text-[var(--muted)]">
          {counted} counted limit{counted === 1 ? "" : "s"} on this plan
          {overCount > 0 ? `, ${overCount} over limit` : ", none over limit"}.
          {unreported > 0
            ? ` The server publishes a current count only for a resource already above its limit, so ${unreported} row${unreported === 1 ? "" : "s"} show no usage figure. A dash means "not published", never zero.`
            : ""}{" "}
          This table reports the plan comparison. It neither authorizes a request nor deletes data.
        </p>
      </div>
    </BillingPanel>
  );
}
