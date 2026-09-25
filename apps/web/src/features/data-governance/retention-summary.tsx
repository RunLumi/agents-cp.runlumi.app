/**
 * Retention summary: the frozen data-class table with the policy's effective
 * window beside the baseline.
 *
 * This is a read-only statement of F20-001. It never edits a window; the editor
 * in `data-policy.tsx` does that. The table is dense and scrollable rather than
 * filtered, because an operator asking "how long do you keep this?" is asking
 * about one class and a hidden row is an unhelpful answer.
 *
 * `DESIGN.md` asks for quiet, high-information admin surfaces with tabular
 * numbers and document-like lines, so the table uses 1px archival row rules and
 * no boxed cells.
 */

import { useId, useState } from "react";

import {
  DATA_CLASS_SUMMARIES,
  effectiveRetention,
  type DataClassSummary,
  type OwnerScope,
} from "./contracts";
import type { DataGovernancePolicy } from "./api";
import { DataTable, Notice, Pill, Surface, SurfaceHeader, TableCell, inputClass } from "./ui";

const OWNER_LABEL: Readonly<Record<OwnerScope, string>> = {
  platform: "Platform",
  organization: "Organization",
  project: "Project",
  user: "User",
  device: "Device",
  external: "External",
};

const FILTERS = ["all", "overridden", "lumi_owned", "external"] as const;
type Filter = (typeof FILTERS)[number];

export interface RetentionSummaryProps {
  policy: DataGovernancePolicy;
}

export function RetentionSummary({ policy }: RetentionSummaryProps) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const searchId = useId();
  const filterId = useId();

  const normalized = query.trim().toLowerCase();
  const rows = DATA_CLASS_ROWS.filter((row) => {
    if (filter === "overridden" && policy.class_retention_overrides[row.key] === undefined)
      return false;
    if (filter === "lumi_owned" && row.owner === "external") return false;
    if (filter === "external" && row.owner !== "external") return false;
    if (normalized.length === 0) return true;
    return (
      row.key.includes(normalized) ||
      row.label.toLowerCase().includes(normalized) ||
      row.defaultWindow.toLowerCase().includes(normalized)
    );
  });

  const overrideCount = Object.keys(policy.class_retention_overrides).length;

  return (
    <Surface ariaLabel="Retention summary">
      <SurfaceHeader
        eyebrow="F20-001 DATA-CLASS DECLARATION"
        title="Retention summary"
        description="Every persistent data class Lumi holds, with the window it is kept for and the maximum it may never exceed. Sensitive content, prompts, responses, and tool arguments are not a row here because no class stores them."
        action={
          overrideCount > 0 ? (
            <Pill tone="info">
              {overrideCount} class{overrideCount === 1 ? "" : "es"} overridden
            </Pill>
          ) : (
            <Pill>Baseline windows</Pill>
          )
        }
      />
      <div className="space-y-3 px-5 py-4">
        <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_12rem]">
          <div>
            <label htmlFor={searchId} className="text-xs font-medium text-[var(--muted-strong)]">
              Filter classes
            </label>
            <input
              id={searchId}
              className={inputClass}
              type="search"
              value={query}
              placeholder="for example: run, audit, export"
              onChange={(event) => setQuery(event.target.value)}
            />
          </div>
          <div>
            <label htmlFor={filterId} className="text-xs font-medium text-[var(--muted-strong)]">
              Scope
            </label>
            <select
              id={filterId}
              className={inputClass}
              value={filter}
              onChange={(event) => setFilter(event.target.value as Filter)}
            >
              <option value="all">All classes</option>
              <option value="overridden">Overridden by this policy</option>
              <option value="lumi_owned">Lumi-managed only</option>
              <option value="external">Not Lumi's to delete</option>
            </select>
          </div>
        </div>

        {rows.length === 0 ? (
          <p className="text-sm leading-5 text-[var(--muted-strong)]">
            No data class matches this filter. The full registry is unchanged; this is only a view
            filter.
          </p>
        ) : (
          <DataTable
            caption="Data classes with their effective and maximum retention windows"
            headers={[
              "Data class",
              "Owner",
              "Effective window",
              "Legal maximum",
              "Export",
              "Deletion",
            ]}
          >
            {rows.map((row) => {
              const effective = effectiveRetention(row.key, policy.class_retention_overrides);
              const overridden = effective?.source === "policy_override";
              return (
                <tr key={row.key} className="border-b border-[var(--border)] last:border-b-0">
                  <TableCell header="Data class">
                    <span className="block font-medium text-[var(--civic-navy)]">{row.label}</span>
                    <code className="mt-0.5 block font-mono text-xs text-[var(--muted)]">
                      {row.key}
                    </code>
                    {row.owner === "external" ? (
                      <span className="mt-1 inline-flex rounded-full bg-[var(--warning)]/15 px-2 py-0.5 text-xs font-medium text-[var(--civic-navy)]">
                        Not Lumi-deletable
                      </span>
                    ) : null}
                  </TableCell>
                  <TableCell header="Owner">{OWNER_LABEL[row.owner]}</TableCell>
                  <TableCell header="Effective window">
                    <span className="block tabular-nums">
                      {overridden && effective ? effective.human : row.defaultWindow}
                    </span>
                    {overridden && effective ? (
                      <span className="mt-0.5 block text-xs text-[var(--muted)]">
                        shortened from {row.defaultWindow}
                      </span>
                    ) : null}
                  </TableCell>
                  <TableCell header="Legal maximum">
                    {row.legalMaximum ?? (
                      <span className="text-[var(--muted)]">Lifecycle, not numeric</span>
                    )}
                  </TableCell>
                  <TableCell header="Export">{row.exportBehavior}</TableCell>
                  <TableCell header="Deletion">{row.deletionBehavior}</TableCell>
                </tr>
              );
            })}
          </DataTable>
        )}

        <p className="text-xs leading-5 text-[var(--muted)]" aria-live="polite">
          Showing {rows.length} of {DATA_CLASS_ROWS.length} declared classes
          {policy.legal_hold
            ? " · a legal hold is active, so expiry and deletion are suspended for the classes it covers"
            : ""}
          .
        </p>

        {policy.legal_hold ? (
          <Notice tone="warning">
            <p className="font-semibold">A legal hold is active for this organization.</p>
            <p className="mt-1">
              While it is active, no window below is expiring anything. The reason and the releasing
              principal are recorded with the hold, and only an audited release lifts it.
            </p>
          </Notice>
        ) : null}

        <Notice tone="info">
          <p className="font-semibold">
            Prompts, responses, and tool arguments are not a data class.
          </p>
          <p className="mt-1">
            No class stores them, so no row above can be read as permission to keep them. Secrets
            and credentials are never exported and are destroyed rather than tombstoned, because a
            tombstone that still decrypts is not a deletion.
          </p>
        </Notice>
      </div>
    </Surface>
  );
}

/**
 * The rows, ordered the way the frozen registry declares them: P06 classes
 * first, then the existing P01–P05 classes.
 */
const DATA_CLASS_ROWS: readonly DataClassSummary[] = DATA_CLASS_SUMMARIES;
