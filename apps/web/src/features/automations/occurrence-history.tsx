// Occurrence history for one automation.
//
// P05 owns the run state machine. This view correlates by `run_id` only and
// never reconstructs a run timeline, a second execution authority, or a retry
// affordance. `ambiguous` is presented as the reconciliation state the gate
// defines: never automatically retried, never safe to overlap.

import { useId } from "react";

import {
  AMBIGUOUS_EXPLANATION,
  isOccurrenceState,
  isPermissionFailure,
  isTerminalOccurrenceState,
  occurrenceKindLabel,
  occurrenceStateExplanation,
  offPeakModeLabel,
} from "./automation-helpers";
import type { Occurrence, OccurrenceState } from "./api";
import { OCCURRENCE_STATES } from "./api";
import {
  ErrorState,
  Loading,
  OccurrenceStatePill,
  Panel,
  PanelHeader,
  PaginationFooter,
} from "./ui";

export function OccurrenceHistory({
  occurrences,
  loading,
  refreshing,
  error,
  hasMore,
  filter,
  ambiguousCount,
  onFilterChange,
  onRetry,
  onLoadMore,
}: {
  occurrences: Occurrence[];
  loading: boolean;
  refreshing: boolean;
  error: unknown;
  hasMore: boolean;
  filter: OccurrenceState | "";
  ambiguousCount: number;
  onFilterChange: (next: OccurrenceState | "") => void;
  onRetry: () => void;
  onLoadMore: () => void;
}) {
  if (loading)
    return (
      <Panel ariaLabel="Loading occurrence history">
        <Loading label="Loading occurrence history…" />
      </Panel>
    );
  if (error && occurrences.length === 0) {
    return isPermissionFailure(error) ? (
      <ErrorState error={error} title="Occurrence history is not available" compact />
    ) : (
      <ErrorState error={error} title="Occurrence history unavailable" onRetry={onRetry} compact />
    );
  }

  const pendingReconciliation = ambiguousCount;
  const filterId = useId();

  return (
    <Panel ariaLabel="Occurrence history">
      <PanelHeader
        title="Occurrence history"
        description="One row is one logical scheduled slot. A retry, a queue redelivery, or a second lease claim updates the same row; it never creates another one."
      />
      <div className="flex flex-col gap-3 border-b border-[var(--border)] px-5 py-4 sm:flex-row sm:items-end sm:justify-between">
        <label className="text-xs font-semibold text-[var(--muted-strong)]" htmlFor={filterId}>
          Occurrence state
          <select
            id={filterId}
            value={filter}
            onChange={(event) => {
              const value = event.target.value;
              onFilterChange(isOccurrenceState(value) ? value : "");
            }}
            className="mt-1.5 min-h-10 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 text-sm font-normal text-[var(--foreground)] outline-none transition focus-visible:border-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)]"
          >
            <option value="">All states</option>
            {OCCURRENCE_STATES.map((state) => (
              <option key={state} value={state}>
                {state === "ambiguous"
                  ? "ambiguous (needs reconciliation)"
                  : state.replaceAll("_", " ")}
              </option>
            ))}
          </select>
        </label>
        <p className="text-xs text-[var(--muted)]" aria-live="polite">
          {refreshing
            ? "Refreshing occurrences…"
            : `${occurrences.length} occurrence${occurrences.length === 1 ? "" : "s"} loaded${
                pendingReconciliation > 0
                  ? ` · ${pendingReconciliation} awaiting reconciliation`
                  : ""
              }`}
        </p>
      </div>

      <AmbiguousExplainer count={pendingReconciliation} />

      {error ? (
        <div className="border-b border-[var(--danger)]/20 bg-[var(--danger)]/5 px-5 py-3">
          <ErrorState
            error={error}
            title="Could not refresh occurrences"
            onRetry={onRetry}
            compact
          />
        </div>
      ) : null}

      {occurrences.length === 0 ? (
        <p className="px-5 py-6 text-sm leading-6 text-[var(--muted)]">
          No occurrence matches this organization, automation, and state filter. A missed slot with
          the skip policy produces no occurrence at all, so an empty history is not by itself an
          error.
        </p>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] text-left text-sm">
              <caption className="sr-only">
                Logical occurrence history for the selected automation
              </caption>
              <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
                <tr>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Occurrence
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Scheduled for
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    State
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Attempt
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Class
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Run
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Reason
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {occurrences.map((occurrence) => (
                  <OccurrenceRow key={occurrence.occurrence_id} occurrence={occurrence} />
                ))}
              </tbody>
            </table>
          </div>
          <PaginationFooter
            loaded={occurrences.length}
            hasMore={hasMore}
            loading={refreshing}
            onLoadMore={onLoadMore}
            noun="occurrence"
          />
        </>
      )}
    </Panel>
  );
}

function OccurrenceRow({ occurrence }: { occurrence: Occurrence }) {
  const ambiguous = occurrence.state === "ambiguous";
  const explanation = occurrenceStateExplanation(occurrence.state);
  return (
    <tr className={ambiguous ? "bg-[var(--lumi-blue-soft)]/40" : "bg-[var(--panel)]"}>
      <td className="px-5 py-4 align-top">
        <span className="block break-all font-mono text-xs font-semibold text-[var(--lumi-blue)]">
          {occurrence.occurrence_id}
        </span>
        <span className="mt-1 block text-xs text-[var(--muted)]">
          {occurrenceKindLabel(occurrence)}
          {isTerminalOccurrenceState(occurrence.state) ? " · terminal" : " · in flight"}
        </span>
      </td>
      <td className="px-5 py-4 align-top text-xs tabular-nums text-[var(--muted-strong)]">
        {occurrence.scheduled_for ? (
          <time dateTime={occurrence.scheduled_for}>{occurrence.scheduled_for}</time>
        ) : (
          <span className="text-[var(--muted)]">No clock instant (manual or off-peak)</span>
        )}
      </td>
      <td className="px-5 py-4 align-top">
        <OccurrenceStatePill state={occurrence.state} />
        {explanation ? (
          <p className="mt-2 max-w-[26rem] text-xs leading-5 text-[var(--muted-strong)]">
            {explanation}
          </p>
        ) : null}
      </td>
      <td className="px-5 py-4 align-top text-xs tabular-nums text-[var(--muted-strong)]">
        {occurrence.attempt}
      </td>
      <td className="px-5 py-4 align-top text-xs text-[var(--muted-strong)]">
        {offPeakModeLabel(occurrence.off_peak_mode)}
        {occurrence.off_peak_mode === "off_peak" ? (
          <span className="mt-1 block text-xs text-[var(--muted)]">separate execution class</span>
        ) : null}
      </td>
      <td className="px-5 py-4 align-top">
        {occurrence.run_id ? (
          <span className="block max-w-[16rem] truncate font-mono text-xs text-[var(--muted-strong)]">
            {occurrence.run_id}
          </span>
        ) : (
          <span className="text-xs text-[var(--muted)]">Not linked</span>
        )}
      </td>
      <td className="px-5 py-4 align-top">
        {occurrence.reason_code ? (
          <span className="block font-mono text-xs text-[var(--muted-strong)]">
            {occurrence.reason_code}
          </span>
        ) : (
          <span className="text-xs text-[var(--muted)]">None recorded</span>
        )}
      </td>
    </tr>
  );
}

/** The `ambiguous` explanation, shown once above the table as well. */
export function AmbiguousExplainer({ count }: { count: number }) {
  if (count === 0) return null;
  return (
    <div className="border-b border-[var(--lumi-blue)]/30 bg-[var(--lumi-blue-soft)] px-5 py-4">
      <p className="text-sm font-semibold text-[var(--civic-navy)]">
        {count} occurrence{count === 1 ? "" : "s"} awaiting reconciliation
      </p>
      <p className="mt-1 text-sm leading-6 text-[var(--muted-strong)]">{AMBIGUOUS_EXPLANATION}</p>
    </div>
  );
}
