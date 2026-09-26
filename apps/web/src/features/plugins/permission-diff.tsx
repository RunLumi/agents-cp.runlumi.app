/**
 * The permission diff on an update, with expansion dominance.
 *
 * The failure this component exists to prevent: a reviewer reads a diff, sees
 * "network destinations — lost", concludes the update is a tightening, and misses
 * that a tool appeared. That is precisely the outcome F25-003 and P07-CG's
 * "expansion in any class is expansion" rule are written against.
 *
 * So the layout is deliberate, not decorative:
 *
 * 1. The overall verdict is a single full-width rail, and it is red the moment
 *    ANY class grows — never a summary of counts, never a colour scale.
 * 2. The growing classes are listed FIRST, in their own block, above everything
 *    else, naming exactly what was added.
 * 3. Only then does the full per-class table appear, so the reductions are read in
 *    the context of the expansion rather than instead of it.
 *
 * `DESIGN.md` §5 keeps status colours to real semantics and §8.2 allows a 3px
 * severity rail; the rail below is that 3px rail, and the warning/danger values
 * come from the existing `--warning` and `--danger` tokens.
 */

import type { PluginPermissionDiff } from "./api";
import {
  classVerdicts,
  diffExpands,
  expansionDetail,
  expansionHeadline,
  expandingClasses,
  verdictLabel,
  verdictTone,
  type ClassVerdict,
} from "./contracts";
import { Notice, Pill, StatusDot } from "./ui";

export function PermissionDiffView({ diff }: { diff: PluginPermissionDiff }) {
  const growing = expandingClasses(diff);
  const { contradictsServer } = diffExpands(diff);
  const contracts = classVerdicts(diff);

  return (
    <div className="space-y-4">
      <DiffRail diff={diff} expanding={growing.length > 0} />

      {contradictsServer ? (
        <Notice tone="danger" title="The diff contradicts itself">
          The server reports this update as an expansion, but no growing class is named. Treat it as
          an expansion and do not approve it until the classes are reconciled.
        </Notice>
      ) : null}

      {growing.length > 0 ? (
        <section
          aria-label="Capability this update gains"
          className="overflow-hidden rounded-lg border border-[var(--danger)]/40 border-l-[3px] border-l-[var(--danger)]"
        >
          <header className="bg-[var(--danger)]/5 px-4 py-3">
            <p className="text-[11px] font-semibold tracking-[0.1em] text-[var(--danger)] uppercase">
              This update gains
            </p>
            <p className="mt-1 text-sm leading-5 text-[var(--civic-navy)]">
              Read this before anything below. Each of these is new authority the plugin did not
              have at {diff.from_version || "the previous version"}.
            </p>
          </header>
          <ul className="divide-y divide-[var(--border)]">
            {growing.map((entry) => (
              <ClassRow key={entry.class} entry={entry} dominant />
            ))}
          </ul>
        </section>
      ) : null}

      <section
        aria-label="Every permission class"
        className="overflow-hidden rounded-lg border border-[var(--border)]"
      >
        <header className="border-b border-[var(--border)] bg-[var(--panel-hover)] px-4 py-3">
          <p className="text-sm font-semibold text-[var(--civic-navy)]">
            Every class ({contracts.length})
          </p>
          <p className="mt-1 text-xs leading-5 text-[var(--muted-strong)]">
            Each class is judged on its own. There is no combined score, because a reduction
            anywhere does not offset a gain anywhere else.
          </p>
        </header>
        <ul className="divide-y divide-[var(--border)]">
          {contracts.map((entry) => (
            <ClassRow key={entry.class} entry={entry} />
          ))}
        </ul>
      </section>
    </div>
  );
}

function DiffRail({ diff, expanding }: { diff: PluginPermissionDiff; expanding: boolean }) {
  return (
    <div
      role="status"
      aria-label={
        expanding ? "This update expands capability" : "This update does not expand capability"
      }
      className={[
        "rounded-lg border p-4",
        expanding
          ? "border-[var(--danger)]/40 border-l-[3px] border-l-[var(--danger)] bg-[var(--danger)]/5"
          : "border-[var(--success)]/30 border-l-[3px] border-l-[var(--success)] bg-[var(--success)]/5",
      ].join(" ")}
    >
      <div className="flex flex-wrap items-center gap-2">
        <Pill tone={expanding ? "danger" : "success"}>
          <StatusDot tone={expanding ? "danger" : "success"} />
          {expanding ? "Expands capability" : "No expansion"}
        </Pill>
        <span className="font-mono text-xs text-[var(--muted-strong)]">
          {diff.from_version || "not installed"} → {diff.to_version}
        </span>
      </div>
      <p className="mt-2 text-sm leading-5 text-[var(--civic-navy)]">{expansionHeadline(diff)}</p>
      <ul className="mt-2 space-y-1">
        {expansionDetail(diff).map((paragraph) => (
          <li key={paragraph.slice(0, 40)} className="text-sm leading-5 text-[var(--civic-navy)]">
            {paragraph}
          </li>
        ))}
      </ul>
      {expanding ? (
        <p className="mt-3 text-xs leading-5 text-[var(--danger)]">
          In managed mode an expanding update is refused and held for review. It does not install
          and wait quietly; nothing about the new version runs.
        </p>
      ) : null}
    </div>
  );
}

function ClassRow({ entry, dominant = false }: { entry: ClassVerdict; dominant?: boolean }) {
  return (
    <li
      className={["px-4 py-3", dominant ? "bg-[var(--danger)]/5" : ""].join(" ")}
      data-expanding={entry.expanding ? "true" : "false"}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p
          className={[
            "text-sm font-semibold",
            dominant ? "text-[var(--danger)]" : "text-[var(--civic-navy)]",
          ].join(" ")}
        >
          {entry.label}
          <span className="ml-2 font-mono text-xs font-normal text-[var(--muted)]">
            {entry.class}
          </span>
        </p>
        <Pill tone={verdictTone(entry.verdict)}>
          <StatusDot tone={verdictTone(entry.verdict)} />
          {verdictLabel(entry.verdict)}
        </Pill>
      </div>
      {entry.added.length > 0 ? (
        <EntryList
          heading={dominant ? "Newly permitted" : "Added"}
          tone="danger"
          values={entry.added}
        />
      ) : null}
      {entry.removed.length > 0 ? (
        <EntryList heading="Removed" tone="info" values={entry.removed} />
      ) : null}
      {entry.added.length === 0 && entry.removed.length === 0 ? (
        <p className="mt-1 text-xs text-[var(--muted)]">Identical at both versions.</p>
      ) : null}
    </li>
  );
}

function EntryList({
  heading,
  tone,
  values,
}: {
  heading: string;
  tone: "danger" | "info";
  values: readonly string[];
}) {
  return (
    <div className="mt-2">
      <p
        className={[
          "text-[11px] font-semibold tracking-[0.06em] uppercase",
          tone === "danger" ? "text-[var(--danger)]" : "text-[var(--muted)]",
        ].join(" ")}
      >
        {heading}
      </p>
      <ul className="mt-1 flex flex-wrap gap-1.5">
        {values.map((value) => (
          <li
            key={value}
            className={[
              "rounded-md px-2 py-1 font-mono text-xs",
              tone === "danger"
                ? "bg-[var(--danger)]/10 text-[var(--danger)]"
                : "bg-[var(--panel-strong)] text-[var(--muted-strong)]",
            ].join(" ")}
          >
            {value}
          </li>
        ))}
      </ul>
    </div>
  );
}
