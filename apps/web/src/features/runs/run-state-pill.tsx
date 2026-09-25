import { runStateLabel } from "@/features/runs/run-helpers";

interface RunStatePillProps {
  state: string;
  compact?: boolean;
}

const stateClasses: Record<string, string> = {
  queued: "bg-[var(--panel-strong)] text-[var(--muted-strong)]",
  dispatching: "bg-[var(--lumi-blue-soft)] text-[var(--lumi-blue)]",
  running: "bg-[var(--lumi-blue-soft)] text-[var(--lumi-blue)]",
  waiting_user: "bg-[var(--warning)]/15 text-[var(--civic-navy)]",
  waiting_approval: "bg-[var(--warning)]/15 text-[var(--civic-navy)]",
  succeeded: "bg-[var(--success)]/10 text-[var(--success)]",
  failed: "bg-[var(--danger)]/10 text-[var(--danger)]",
  cancelled: "bg-[var(--panel-strong)] text-[var(--muted-strong)]",
  timed_out: "bg-[var(--danger)]/10 text-[var(--danger)]",
};

const dotClasses: Record<string, string> = {
  queued: "bg-[var(--muted)]",
  dispatching: "bg-[var(--lumi-blue)]",
  running: "bg-[var(--lumi-blue)]",
  waiting_user: "bg-[var(--warning)]",
  waiting_approval: "bg-[var(--warning)]",
  succeeded: "bg-[var(--success)]",
  failed: "bg-[var(--danger)]",
  cancelled: "bg-[var(--muted)]",
  timed_out: "bg-[var(--danger)]",
};

export function RunStatePill({ state, compact = false }: RunStatePillProps) {
  const knownState = Object.hasOwn(stateClasses, state);
  const stateClass = knownState
    ? (stateClasses[state] ?? "bg-[var(--panel-strong)] text-[var(--muted-strong)]")
    : "bg-[var(--panel-strong)] text-[var(--muted-strong)]";
  const dotClass = knownState ? (dotClasses[state] ?? "bg-[var(--muted)]") : "bg-[var(--muted)]";
  return (
    <span
      className={[
        "inline-flex w-fit items-center rounded-full font-medium capitalize",
        compact ? "gap-1.5 px-2 py-0.5 text-[11px]" : "gap-2 px-2.5 py-1 text-xs",
        stateClass,
      ].join(" ")}
    >
      <span aria-hidden="true" className={["size-1.5 shrink-0 rounded-full", dotClass].join(" ")} />
      {runStateLabel(state)}
    </span>
  );
}
