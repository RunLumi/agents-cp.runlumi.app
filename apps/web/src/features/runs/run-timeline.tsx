import { useMemo } from "react";

import { formatDateTime, isPermissionFailure } from "@/features/runs/run-helpers";
import { presentApiError } from "@/lib/errors";

export interface RunTimelineEvent {
  id?: string;
  run_event_id?: string;
  run_id: string;
  sequence: number;
  event_type: string;
  occurred_at: string;
  actor_type: string;
  actor_id?: string | null;
  correlation_id?: string | null;
  tool_call_id?: string | null;
  approval_id?: string | null;
}

interface RunTimelineProps {
  events: readonly RunTimelineEvent[];
  loading?: boolean;
  refreshing?: boolean;
  error?: unknown;
  hasMore?: boolean;
  loadingMore?: boolean;
  onRetry?: () => void;
  onLoadMore?: () => void;
}

const eventLabels: Record<string, string> = {
  "run.created.v1": "Run created",
  "run.state_changed.v1": "State changed",
  "run.cancelled.v1": "Cancellation recorded",
  "run.retried.v1": "Retry recorded",
  "run.event_appended.v1": "Timeline event appended",
  "model.requested.v1": "Model request recorded",
  "model.completed.v1": "Model response metadata recorded",
  "tool.requested.v1": "Tool request recorded",
  "tool.completed.v1": "Tool result metadata recorded",
  "tool.decision_recorded.v1": "Tool decision recorded",
  "tool.denied.v1": "Tool denied",
  "tool.approval_requested.v1": "Approval requested",
  "approval.requested.v1": "Approval requested",
  "approval.resolved.v1": "Approval resolved",
  "usage.recorded.v1": "Usage recorded",
  "usage.reconciled.v1": "Usage reconciled",
  "budget.reserved.v1": "Budget reserved",
  "budget.reconciled.v1": "Budget reconciled",
  "budget.denied.v1": "Run denied by budget",
  "rate_limit.denied.v1": "Run denied by rate limit",
  "artifact.created.v1": "Artifact recorded",
  "error.recorded.v1": "Error metadata recorded",
};

const eventDescriptions: Record<string, string> = {
  model: "Model request and response metadata only.",
  tool: "Tool identity, policy, and result metadata only.",
  approval: "Approval state changed; arguments and credentials are omitted.",
  usage: "Token, cost, and reconciliation metadata only.",
  budget: "Budget reservation or decision metadata only.",
  artifact: "Artifact reference metadata only; file content is not loaded here.",
  error: "Stable failure metadata only; the raw provider error is not shown.",
  run: "Immutable run lifecycle record.",
};

export function RunTimeline({
  events,
  loading = false,
  refreshing = false,
  error,
  hasMore = false,
  loadingMore = false,
  onRetry,
  onLoadMore,
}: RunTimelineProps) {
  const orderedEvents = useMemo(
    () => [...events].sort((left, right) => left.sequence - right.sequence),
    [events],
  );
  const counts = useMemo(
    () => ({
      tool: orderedEvents.filter((event) => event.event_type.startsWith("tool.")).length,
      approvals: orderedEvents.filter((event) => event.event_type.includes("approval")).length,
      usage: orderedEvents.filter((event) => event.event_type.startsWith("usage.")).length,
    }),
    [orderedEvents],
  );

  if (loading) {
    return <TimelineSkeleton />;
  }

  if (error && orderedEvents.length === 0) {
    return isPermissionFailure(error) ? (
      <PermissionState />
    ) : (
      <TimelineError error={error} {...(onRetry ? { onRetry } : {})} />
    );
  }

  return (
    <section
      aria-labelledby="run-timeline-title"
      className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]"
    >
      <div className="flex flex-col gap-3 border-b border-[var(--border)] px-5 py-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h3 id="run-timeline-title" className="text-base font-semibold text-[var(--civic-navy)]">
            Run timeline
          </h3>
          <p className="mt-1 text-sm text-[var(--muted-strong)]">
            Append-only, sequence-numbered metadata. Prompt, response, and tool argument bodies are
            intentionally omitted.
          </p>
        </div>
        <div className="flex flex-wrap gap-1.5" aria-label="Timeline event summary">
          <TimelineCount label="tools" value={counts.tool} />
          <TimelineCount label="approvals" value={counts.approvals} />
          <TimelineCount label="usage" value={counts.usage} />
        </div>
      </div>

      <div className="border-b border-[var(--border)] bg-[var(--lumi-blue-soft)]/45 px-5 py-2.5 text-xs text-[var(--muted-strong)]">
        <span className="font-medium text-[var(--civic-navy)]">Immutable history.</span> Retry
        creates a new run; it never edits this timeline.
      </div>

      {error ? (
        <div className="border-b border-[var(--danger)]/20 bg-[var(--danger)]/5 px-5 py-3">
          <InlineError error={error} {...(onRetry ? { onRetry } : {})} />
        </div>
      ) : null}

      {orderedEvents.length === 0 ? (
        <p className="px-5 py-8 text-sm text-[var(--muted)]">
          No timeline events are available yet.
        </p>
      ) : (
        <ol className="px-5 py-2">
          {orderedEvents.map((event, index) => {
            const eventId = event.id ?? event.run_event_id ?? `${event.run_id}:${event.sequence}`;
            const category = eventCategory(event.event_type);
            const references = [
              event.tool_call_id ? { label: "Tool call", value: event.tool_call_id } : null,
              event.approval_id ? { label: "Approval", value: event.approval_id } : null,
              event.correlation_id ? { label: "Correlation", value: event.correlation_id } : null,
            ].filter((item): item is { label: string; value: string } => item !== null);

            return (
              <li
                key={eventId}
                className="relative grid grid-cols-[2.25rem_minmax(0,1fr)] gap-3 py-4"
              >
                {index < orderedEvents.length - 1 ? (
                  <span
                    aria-hidden="true"
                    className="absolute bottom-0 left-[1.08rem] top-9 w-px bg-[var(--border)]"
                  />
                ) : null}
                <div className="relative z-10 pt-0.5 text-center">
                  <span className="grid size-9 place-items-center rounded-full border border-[var(--border)] bg-[var(--panel-hover)] font-mono text-[11px] font-semibold text-[var(--muted-strong)]">
                    {event.sequence}
                  </span>
                </div>
                <div className="min-w-0">
                  <div className="flex flex-col gap-1 sm:flex-row sm:items-start sm:justify-between">
                    <div>
                      <p className="text-sm font-semibold text-[var(--civic-navy)]">
                        {eventLabel(event.event_type)}
                      </p>
                      <p className="mt-1 text-xs text-[var(--muted-strong)]">
                        {eventDescription(event.event_type, category)}
                      </p>
                    </div>
                    <time
                      dateTime={event.occurred_at}
                      className="shrink-0 text-xs tabular-nums text-[var(--muted)]"
                    >
                      {formatDateTime(event.occurred_at)}
                    </time>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-[var(--muted)]">
                    <span>
                      Actor:{" "}
                      <span className="capitalize">{event.actor_type.replaceAll("_", " ")}</span>
                      {event.actor_id ? ` · ${event.actor_id}` : ""}
                    </span>
                    {references.map((reference) => (
                      <span
                        key={`${reference.label}:${reference.value}`}
                        className="min-w-0 break-all"
                      >
                        {reference.label}: <span className="font-mono">{reference.value}</span>
                      </span>
                    ))}
                  </div>
                </div>
              </li>
            );
          })}
        </ol>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[var(--border)] px-5 py-3">
        <p className="text-xs text-[var(--muted)]" aria-live="polite">
          {refreshing ? "Refreshing timeline…" : `${orderedEvents.length} events loaded`}
        </p>
        {hasMore && onLoadMore ? (
          <button
            type="button"
            className={secondaryButton}
            onClick={onLoadMore}
            disabled={loadingMore}
          >
            {loadingMore ? "Loading…" : "Load older events"}
          </button>
        ) : null}
      </div>
    </section>
  );
}

function TimelineSkeleton() {
  return (
    <section
      aria-label="Loading run timeline"
      aria-busy="true"
      className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]"
    >
      <div className="border-b border-[var(--border)] px-5 py-4">
        <p className="text-sm font-semibold text-[var(--civic-navy)]">Loading run timeline…</p>
      </div>
      <div className="space-y-4 p-5">
        {[0, 1, 2, 3].map((item) => (
          <div key={item} className="grid grid-cols-[2.25rem_minmax(0,1fr)] gap-3">
            <div className="size-9 rounded-full bg-[var(--panel-strong)]" />
            <div className="space-y-2 pt-1">
              <div className="h-3 w-40 rounded bg-[var(--panel-strong)]" />
              <div className="h-3 w-full max-w-md rounded bg-[var(--panel-strong)]" />
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function TimelineError({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const presentation = presentApiError(error);
  return (
    <div
      role="alert"
      className="rounded-xl border border-[var(--danger)]/30 bg-[var(--danger)]/5 p-5 text-sm text-[var(--danger)]"
    >
      <p className="font-semibold">Timeline unavailable</p>
      <p className="mt-1">{presentation.message}</p>
      {presentation.requestId ? (
        <p className="mt-1 break-all text-xs opacity-75">Request {presentation.requestId}</p>
      ) : null}
      {onRetry ? (
        <button type="button" className={secondaryButton} onClick={onRetry}>
          Try again
        </button>
      ) : null}
    </div>
  );
}

function InlineError({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const presentation = presentApiError(error);
  return (
    <div
      role="alert"
      className="flex flex-wrap items-center justify-between gap-3 text-sm text-[var(--danger)]"
    >
      <div>
        <p>{presentation.message}</p>
        {presentation.requestId ? (
          <p className="mt-1 break-all text-xs opacity-75">Request {presentation.requestId}</p>
        ) : null}
      </div>
      {onRetry ? (
        <button
          type="button"
          className="min-h-9 rounded-lg border border-[var(--danger)]/35 px-3 text-xs font-semibold outline-none hover:bg-[var(--danger)]/5 focus-visible:ring-2 focus-visible:ring-[var(--ring)]"
          onClick={onRetry}
        >
          Retry timeline
        </button>
      ) : null}
    </div>
  );
}

function PermissionState() {
  return (
    <div
      role="alert"
      className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)]"
    >
      <h3 className="text-sm font-semibold text-[var(--civic-navy)]">
        Timeline access not permitted
      </h3>
      <p className="mt-1 text-sm text-[var(--muted-strong)]">
        Ask an administrator to grant run read access in your current organization scope.
      </p>
    </div>
  );
}

function TimelineCount({ label, value }: { label: string; value: number }) {
  return (
    <span className="rounded-md bg-[var(--panel)] px-2 py-1 text-[11px] font-medium text-[var(--muted-strong)] ring-1 ring-[var(--border)] ring-inset">
      {value} {label}
    </span>
  );
}

function eventCategory(eventType: string): string {
  if (eventType.startsWith("tool.") || eventType.startsWith("approval.")) return "tool";
  if (eventType.startsWith("usage.") || eventType.startsWith("budget.")) return "usage";
  if (eventType.includes("model.")) return "model";
  if (eventType.startsWith("artifact.")) return "artifact";
  if (eventType.includes("error") || eventType.includes("denied")) return "error";
  return "run";
}

function eventLabel(eventType: string): string {
  const known = eventLabels[eventType];
  if (known) return known;
  const normalized = eventType
    .replace(/\.v\d+$/, "")
    .replaceAll(".", " · ")
    .replaceAll("_", " ");
  return normalized.slice(0, 96) || "Timeline event";
}

function eventDescription(eventType: string, category: string): string {
  if (eventType === "run.cancelled.v1")
    return "Cancellation metadata is recorded without deleting prior events.";
  if (eventType === "run.retried.v1")
    return "A separate run was created; this attempt remains unchanged.";
  return eventDescriptions[category] ?? eventDescriptions.run ?? "Immutable metadata event.";
}

const secondaryButton =
  "min-h-10 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 py-1.5 text-sm font-semibold text-[var(--civic-navy)] outline-none transition hover:bg-[var(--panel-hover)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] disabled:cursor-not-allowed disabled:opacity-50";
