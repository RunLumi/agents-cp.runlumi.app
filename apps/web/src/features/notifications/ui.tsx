/**
 * Notification surface primitives.
 *
 * Local to `features/notifications/**` for the same reason as the webhooks
 * primitives: the design-system components are not generated in this repository
 * and `@/lib` is outside the P06-FE-02 write surface. Tokens, radii, borders,
 * and motion follow `DESIGN.md` and `src/styles/globals.css`; nothing here adds
 * a palette, typeface, or decorative style.
 */

import type { ReactNode } from "react";

import { presentApiError } from "@/lib/errors";

export type Tone = "neutral" | "info" | "success" | "warning" | "danger";

export function Surface({
  children,
  ariaLabel,
  ariaLabelledBy,
  className,
}: {
  children: ReactNode;
  ariaLabel?: string;
  ariaLabelledBy?: string;
  className?: string;
}) {
  return (
    <section
      {...(ariaLabel ? { "aria-label": ariaLabel } : {})}
      {...(ariaLabelledBy ? { "aria-labelledby": ariaLabelledBy } : {})}
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

export function SurfaceHeader({
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

export function LoadingRows({ label, rows = 4 }: { label: string; rows?: number }) {
  return (
    <div className="p-5" role="status" aria-live="polite" aria-busy="true">
      <p className="text-sm text-[var(--muted-strong)]">{label}</p>
      <div className="mt-4 space-y-2" aria-hidden="true">
        {Array.from({ length: rows }, (_, index) => (
          <div key={index} className="h-14 animate-pulse rounded-lg bg-[var(--panel-hover)]" />
        ))}
      </div>
    </div>
  );
}

export function ErrorNotice({
  error,
  title = "The request could not be completed",
  onRetry,
}: {
  error: unknown;
  title?: string;
  onRetry?: () => void;
}) {
  const presentation = presentApiError(error);
  return (
    <div
      role="alert"
      className="rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/5 p-4 text-sm text-[var(--danger)]"
    >
      <p className="font-semibold">{title}</p>
      <p className="mt-1">{presentation.message}</p>
      <p className="mt-1 text-xs opacity-75">Reason code {presentation.code}</p>
      {presentation.requestId ? (
        <p className="mt-1 break-all text-xs opacity-75">Request {presentation.requestId}</p>
      ) : null}
      {onRetry ? (
        <button type="button" className={dangerButtonClass} onClick={onRetry}>
          Try again
        </button>
      ) : null}
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
    warning: "border-[var(--warning)]/45 bg-[var(--warning)]/10 text-[var(--civic-navy)]",
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

export function EmptyState({ title, copy }: { title: string; copy: string }) {
  return (
    <div className="p-6">
      <p className="text-sm font-semibold text-[var(--civic-navy)]">{title}</p>
      <p className="mt-1 max-w-2xl text-sm leading-5 text-[var(--muted-strong)]">{copy}</p>
    </div>
  );
}

export function PermissionState({ resource }: { resource: string }) {
  return (
    <div className="rounded-xl border border-[var(--border)] bg-[var(--panel-hover)] p-5 shadow-[var(--shadow)]">
      <p className="text-sm font-semibold text-[var(--civic-navy)]">Access not permitted</p>
      <p className="mt-1 text-sm leading-5 text-[var(--muted-strong)]">
        Your current membership cannot view {resource}. Ask an administrator to review access.
      </p>
    </div>
  );
}

export function Pill({ children, tone = "neutral" }: { children: ReactNode; tone?: Tone }) {
  const toneClass = {
    neutral: "bg-[var(--panel-strong)] text-[var(--muted-strong)]",
    info: "bg-[var(--lumi-blue-soft)] text-[var(--lumi-blue)]",
    success: "bg-[var(--success)]/10 text-[var(--success)]",
    warning: "bg-[var(--warning)]/15 text-[var(--civic-navy)]",
    danger: "bg-[var(--danger)]/10 text-[var(--danger)]",
  }[tone];
  return (
    <span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium ${toneClass}`}>
      {children}
    </span>
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
        <button
          type="button"
          className={secondaryButtonClass}
          onClick={onLoadMore}
          disabled={loading}
        >
          {loading ? "Loading…" : `Load more ${noun}s`}
        </button>
      ) : null}
    </div>
  );
}

export const primaryButtonClass =
  "inline-flex min-h-11 items-center justify-center gap-2 rounded-lg bg-[var(--lumi-blue)] px-4 py-2 text-sm font-semibold text-white shadow-[var(--shadow-button)] outline-none transition hover:bg-[var(--lumi-blue-hover)] active:translate-y-px focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";

export const secondaryButtonClass =
  "inline-flex min-h-11 items-center justify-center gap-2 rounded-lg border border-[var(--lumi-blue)]/40 bg-[var(--panel)] px-3 py-2 text-sm font-semibold text-[var(--lumi-blue)] outline-none transition hover:border-[var(--lumi-blue)]/60 hover:bg-[var(--lumi-blue-soft)] active:translate-y-px focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";

export const dangerButtonClass =
  "inline-flex min-h-11 items-center justify-center gap-2 rounded-lg border border-[var(--danger)]/40 bg-[var(--panel)] px-3 py-2 text-sm font-semibold text-[var(--danger)] outline-none transition hover:bg-[var(--danger)]/5 active:translate-y-px focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";

export const ghostButtonClass =
  "inline-flex min-h-9 items-center justify-center gap-2 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 py-1.5 text-xs font-semibold text-[var(--muted-strong)] outline-none transition hover:bg-[var(--panel-hover)] hover:text-[var(--foreground)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";

export const selectedButtonClass =
  "inline-flex min-h-9 items-center justify-center gap-2 rounded-lg border border-[var(--lumi-blue)] bg-[var(--lumi-blue-soft)] px-3 py-1.5 text-xs font-semibold text-[var(--lumi-blue)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2";

export const inputClass =
  "mt-1.5 min-h-11 w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 text-sm font-normal text-[var(--foreground)] outline-none transition placeholder:text-[var(--muted)] focus-visible:border-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2";

export const filterControlClass =
  "mt-1.5 min-h-10 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 text-sm font-normal text-[var(--foreground)] outline-none transition focus-visible:border-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)]";

export const checkboxClass =
  "size-4 shrink-0 rounded border-[var(--border-strong)] accent-[var(--lumi-blue)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2";
