// Feature-local presentation primitives.
//
// These follow the tokens and materials already established in the control
// plane (`apps/web/src/styles/globals.css` and DESIGN.md §4, §8): opaque white
// sheets, 1px archival borders, navy-tinted elevation, and status color only
// where it carries real semantics. They are intentionally local to
// `features/automations` so the feature owns its own density without coupling
// to another feature's internals.

import type { ReactNode } from "react";

import { presentApiError } from "@/lib/errors";

import { occurrenceStateLabel, occurrenceTone, type OccurrenceTone } from "./automation-helpers";
import type { OccurrenceState } from "./api";

export function Panel({
  children,
  className,
  ariaLabel,
}: {
  children: ReactNode;
  className?: string;
  ariaLabel?: string;
}) {
  return (
    <section
      aria-label={ariaLabel}
      className={[
        "overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]",
        className ?? "",
      ]
        .filter(Boolean)
        .join(" ")}
    >
      {children}
    </section>
  );
}

export function PanelHeader({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-3 border-b border-[var(--border)] px-5 py-4 sm:flex-row sm:items-start sm:justify-between">
      <div className="min-w-0">
        <h3 className="text-base font-semibold text-[var(--civic-navy)]">{title}</h3>
        <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--muted-strong)]">{description}</p>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}

export function Loading({ label, rows = 3 }: { label: string; rows?: number }) {
  return (
    <div className="p-5" role="status" aria-live="polite" aria-busy="true">
      <p className="text-sm text-[var(--muted-strong)]">{label}</p>
      <div className="mt-4 space-y-2" aria-hidden="true">
        {Array.from({ length: rows }, (_, index) => (
          <div key={index} className="h-10 rounded-lg bg-[var(--panel-hover)]" />
        ))}
      </div>
    </div>
  );
}

export function ErrorState({
  error,
  title = "Could not load this view",
  onRetry,
  compact = false,
}: {
  error: unknown;
  title?: string;
  onRetry?: () => void;
  compact?: boolean;
}) {
  const presentation = presentApiError(error);
  return (
    <div
      role="alert"
      className={[
        "rounded-xl border border-[var(--danger)]/30 bg-[var(--danger)]/5 text-[var(--danger)]",
        compact ? "p-4" : "p-6",
      ].join(" ")}
    >
      <p className="text-sm font-semibold">{title}</p>
      <p className="mt-1 text-sm leading-5">{presentation.message}</p>
      <p className="mt-1 font-mono text-xs opacity-80">{presentation.code}</p>
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

export function PermissionState({ resource }: { resource: string }) {
  return (
    <div className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-6 text-center shadow-[var(--shadow)]">
      <h3 className="text-sm font-semibold text-[var(--civic-navy)]">Access not permitted</h3>
      <p className="mt-1 text-sm leading-5 text-[var(--muted-strong)]">
        Your current membership cannot view {resource}. Ask an administrator to review access.
      </p>
    </div>
  );
}

export function EmptyState({ title, copy }: { title: string; copy: string }) {
  return (
    <div className="p-6">
      <p className="text-sm font-semibold text-[var(--civic-navy)]">{title}</p>
      <p className="mt-1 max-w-2xl text-sm leading-5 text-[var(--muted-strong)]">{copy}</p>
    </div>
  );
}

export function Notice({
  children,
  tone = "info",
}: {
  children: ReactNode;
  tone?: "info" | "warning" | "danger" | "success";
}) {
  const toneClass = {
    info: "border-[var(--lumi-blue)]/30 bg-[var(--lumi-blue-soft)] text-[var(--civic-navy)]",
    warning: "border-[var(--warning)]/40 bg-[var(--warning)]/10 text-[var(--civic-navy)]",
    danger: "border-[var(--danger)]/30 bg-[var(--danger)]/5 text-[var(--danger)]",
    success: "border-[var(--success)]/30 bg-[var(--success)]/5 text-[var(--success)]",
  }[tone];
  return (
    <div
      role={tone === "danger" ? "alert" : "status"}
      className={`rounded-lg border p-3 text-sm leading-5 ${toneClass}`}
    >
      {children}
    </div>
  );
}

const TONE_CLASS: Readonly<Record<OccurrenceTone | "muted", string>> = {
  neutral: "bg-[var(--panel-strong)] text-[var(--muted-strong)]",
  muted: "bg-[var(--panel-strong)] text-[var(--muted-strong)]",
  info: "bg-[var(--lumi-blue-soft)] text-[var(--lumi-blue)]",
  success: "bg-[var(--success)]/10 text-[var(--success)]",
  warning: "bg-[var(--warning)]/15 text-[var(--civic-navy)]",
  danger: "bg-[var(--danger)]/10 text-[var(--danger)]",
  // A dashed rail plus a distinct border keeps `ambiguous` legible without
  // borrowing the danger color that means "failed".
  ambiguous:
    "border border-dashed border-[var(--lumi-blue)]/60 bg-[var(--lumi-blue-soft)] text-[var(--civic-navy)]",
};

export function Pill({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: OccurrenceTone | "muted";
}) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-1 text-xs font-medium ${TONE_CLASS[tone]}`}
    >
      {children}
    </span>
  );
}

/**
 * The occurrence state marker. `ambiguous` is visually distinct by design: it is
 * a reconciliation state, so it must not read like a retryable failure.
 */
export function OccurrenceStatePill({ state }: { state: OccurrenceState }) {
  return <Pill tone={occurrenceTone(state)}>{occurrenceStateLabel(state)}</Pill>;
}

export function Metadata({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-medium text-[var(--muted)]">{label}</dt>
      <dd
        className={[
          "mt-1 break-all text-sm text-[var(--civic-navy)]",
          mono ? "font-mono text-xs" : "",
        ].join(" ")}
      >
        {value}
      </dd>
    </div>
  );
}

export function PaginationFooter({
  loaded,
  hasMore,
  loading,
  onLoadMore,
  noun,
}: {
  loaded: number;
  hasMore: boolean;
  loading: boolean;
  onLoadMore: () => void;
  noun: string;
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[var(--border)] px-5 py-3">
      <p className="text-xs text-[var(--muted)]" aria-live="polite">
        {loaded} {noun}
        {loaded === 1 ? "" : "s"} loaded{hasMore ? " · more available" : ""}
      </p>
      {hasMore ? (
        <button type="button" className={secondaryButton} onClick={onLoadMore} disabled={loading}>
          {loading ? "Loading…" : `Load more ${noun}s`}
        </button>
      ) : null}
    </div>
  );
}

export interface FieldControlProps {
  id: string;
  describedBy: string | undefined;
  invalid: boolean;
}

/**
 * Label + optional hint + optional error, with the control supplied as a render
 * function so the ids stay bound to the input the operator actually focuses.
 */
export function Field({
  label,
  id,
  hint,
  error,
  children,
}: {
  label: string;
  id: string;
  hint?: string;
  error?: string | undefined;
  children: (control: FieldControlProps) => ReactNode;
}) {
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy = [hintId, errorId].filter(Boolean).join(" ") || undefined;
  return (
    <div className="min-w-0">
      <label htmlFor={id} className="text-xs font-semibold text-[var(--muted-strong)]">
        {label}
      </label>
      {hint ? (
        <p id={hintId} className="mt-1 text-xs leading-5 text-[var(--muted)]">
          {hint}
        </p>
      ) : null}
      {children({ id, describedBy, invalid: error !== undefined })}
      {error ? (
        <p id={errorId} className="mt-1 text-xs leading-5 text-[var(--danger)]">
          {error}
        </p>
      ) : null}
    </div>
  );
}

export const inputClass =
  "mt-1.5 min-h-10 w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 text-sm text-[var(--foreground)] outline-none transition placeholder:text-[var(--muted)] focus-visible:border-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2";

export const primaryButton =
  "inline-flex min-h-10 items-center justify-center gap-2 rounded-lg bg-[var(--lumi-blue)] px-4 py-2 text-sm font-semibold text-white shadow-[var(--shadow-button)] outline-none transition hover:bg-[var(--lumi-blue-hover)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";

export const secondaryButton =
  "inline-flex min-h-10 items-center justify-center gap-2 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 py-2 text-sm font-semibold text-[var(--civic-navy)] outline-none transition hover:bg-[var(--panel-hover)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";

export const dangerButton =
  "inline-flex min-h-10 items-center justify-center gap-2 rounded-lg border border-[var(--danger)]/40 bg-[var(--panel)] px-4 py-2 text-sm font-semibold text-[var(--danger)] outline-none transition hover:bg-[var(--danger)]/5 focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";

export const monoClass = "break-all font-mono text-xs text-[var(--muted-strong)]";
