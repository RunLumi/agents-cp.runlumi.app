import type { UsageTrendPoint } from "./usage-contracts";
import { formatMinorUnits, formatPercent } from "./money";
import { formatUsageDate } from "./helpers";

export interface UsageTrendProps {
  points: readonly UsageTrendPoint[];
}

export default function UsageTrend({ points }: UsageTrendProps) {
  if (points.length === 0) {
    return (
      <p className="rounded-xl border border-dashed border-[var(--border-strong)] bg-[var(--panel)] p-5 text-sm text-[var(--muted-strong)]">
        Trend data is not available in the loaded usage page.
      </p>
    );
  }

  const currencies = new Set(points.map((point) => point.currency).filter(Boolean));
  const currency = currencies.size === 1 ? (currencies.values().next().value ?? null) : null;
  const maxCost = Math.max(...points.map((point) => point.cost_minor), 1);
  const chartLabel = currency
    ? `Recorded spend trend in ${currency}`
    : "Recorded spend trend; mixed currencies are shown without a combined total";

  return (
    <figure className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-4 shadow-[var(--shadow)]">
      <figcaption className="text-sm font-semibold text-[var(--civic-navy)]">
        Recorded spend trend
      </figcaption>
      <p id="usage-trend-description" className="mt-1 text-xs text-[var(--muted-strong)]">
        A lightweight view of cost-bearing events in the loaded page. It does not replace a server
        rollup.
      </p>
      {currencies.size > 1 ? (
        <p className="mt-3 rounded-lg border border-[var(--warning)]/30 bg-[var(--warning)]/10 p-2 text-xs text-[var(--danger)]">
          This loaded page contains more than one currency. Bars remain separate and are not summed
          across currencies.
        </p>
      ) : null}
      <div
        className="mt-5 flex h-36 items-end gap-1.5 border-b border-l border-[var(--border-strong)] px-2 pb-0 pt-2"
        role="img"
        aria-label={chartLabel}
        aria-describedby="usage-trend-description"
      >
        {points.map((point) => {
          const height = Math.max(3, Math.round((point.cost_minor / maxCost) * 100));
          return (
            <div
              key={point.bucket_start}
              className="group relative flex h-full min-w-0 flex-1 items-end"
              title={`${formatUsageDate(point.bucket_start)} · ${formatMinorUnits(point.cost_minor, point.currency, { showCode: true })}`}
            >
              <div
                className="w-full rounded-t bg-[var(--lumi-blue)]/80 transition-[height] duration-150 motion-reduce:transition-none"
                style={{ height: `${height}%` }}
              />
              <span className="sr-only">
                {formatUsageDate(point.bucket_start)}:{" "}
                {formatMinorUnits(point.cost_minor, point.currency, { showCode: true })},{" "}
                {point.event_count} events
              </span>
            </div>
          );
        })}
      </div>
      <div className="mt-2 flex justify-between text-xs tabular-nums text-[var(--muted)]">
        <span>{formatUsageDate(points[0]?.bucket_start)}</span>
        <span>{formatUsageDate(points.at(-1)?.bucket_start)}</span>
      </div>
      <details className="mt-4 rounded-lg border border-[var(--border)]">
        <summary className="cursor-pointer px-3 py-2 text-xs font-medium text-[var(--civic-navy)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]">
          View trend data table
        </summary>
        <div className="overflow-x-auto border-t border-[var(--border)]">
          <table className="w-full min-w-[520px] text-left text-xs">
            <caption className="sr-only">Accessible recorded spend trend data</caption>
            <thead className="bg-[var(--panel-hover)] text-[var(--muted)]">
              <tr>
                <th scope="col" className="px-3 py-2 font-medium">
                  Period
                </th>
                <th scope="col" className="px-3 py-2 font-medium">
                  Cost
                </th>
                <th scope="col" className="px-3 py-2 font-medium">
                  Share of max
                </th>
                <th scope="col" className="px-3 py-2 font-medium">
                  Events
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border)]">
              {points.map((point) => (
                <tr key={point.bucket_start}>
                  <td className="px-3 py-2 tabular-nums">{formatUsageDate(point.bucket_start)}</td>
                  <td className="px-3 py-2 tabular-nums">
                    {formatMinorUnits(point.cost_minor, point.currency, { showCode: true })}
                  </td>
                  <td className="px-3 py-2 tabular-nums">
                    {formatPercent(point.cost_minor, maxCost)}
                  </td>
                  <td className="px-3 py-2 tabular-nums">{point.event_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </figure>
  );
}
