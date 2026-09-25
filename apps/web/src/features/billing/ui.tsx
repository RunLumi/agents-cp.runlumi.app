import type { ReactNode } from "react";

import { presentApiError } from "@/lib/errors";

/** Feature-local primitives. Tokens come from `globals.css`; nothing new. */

export function BillingPanel({
  children,
  ariaLabel,
  tone = "default",
}: {
  children: ReactNode;
  ariaLabel: string;
  tone?: "default" | "quiet";
}) {
  return (
    <section
      aria-label={ariaLabel}
      className={[
        "overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]",
        tone === "quiet" ? "border-t-0" : "",
      ].join(" ")}
    >
      {children}
    </section>
  );
}

export function BillingPanelHeader({
  title,
  description,
  eyebrow,
  action,
}: {
  title: string;
  description: string;
  eyebrow?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-3 border-b border-[var(--border)] px-5 py-4 sm:flex-row sm:items-start sm:justify-between">
      <div className="min-w-0">
        {eyebrow ? (
          <p className="text-[11px] font-semibold tracking-[0.1em] text-[var(--muted)]">
            {eyebrow}
          </p>
        ) : null}
        <h2 className="mt-0.5 text-base font-semibold text-[var(--civic-navy)]">{title}</h2>
        <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--muted-strong)]">{description}</p>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}

export function BillingLoading({ label, rows = 3 }: { label: string; rows?: number }) {
  return (
    <div className="p-5" role="status" aria-live="polite" aria-busy="true">
      <p className="text-sm text-[var(--muted-strong)]">{label}</p>
      <div className="mt-4 space-y-2" aria-hidden="true">
        {Array.from({ length: rows }, (_, index) => (
          <div key={index} className="h-10 animate-pulse rounded-lg bg-[var(--panel-hover)]" />
        ))}
      </div>
    </div>
  );
}

export function BillingError({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const presentation = presentApiError(error);
  return (
    <div
      role="alert"
      className="rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/5 p-4 text-sm text-[var(--danger)]"
    >
      <p className="font-medium">{presentation.title}</p>
      <p className="mt-1 leading-5 text-[var(--muted-strong)]">{presentation.message}</p>
      {presentation.requestId ? (
        <p className="mt-1 text-xs text-[var(--muted)]">Request {presentation.requestId}</p>
      ) : null}
      {onRetry ? (
        <button type="button" className={dangerButtonClass} onClick={onRetry}>
          Try again
        </button>
      ) : null}
    </div>
  );
}

export function BillingPermission({ message }: { message?: string }) {
  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-5">
      <p className="text-sm font-semibold text-[var(--civic-navy)]">Access not permitted</p>
      <p className="mt-1 text-sm leading-5 text-[var(--muted-strong)]">
        {message ??
          "Your current organization role cannot read this billing surface. Ask an administrator to review the `billing.read` or `entitlements.read` permission."}
      </p>
    </div>
  );
}

export function BillingEmpty({ title, description }: { title: string; description: string }) {
  return (
    <div className="p-6">
      <p className="text-sm font-semibold text-[var(--civic-navy)]">{title}</p>
      <p className="mt-1 max-w-2xl text-sm leading-5 text-[var(--muted-strong)]">{description}</p>
    </div>
  );
}

export function BillingNotice({
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

export type BillingTone = "neutral" | "success" | "warning" | "danger" | "info";

export function BillingPill({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: BillingTone;
}) {
  const toneClass = {
    neutral: "bg-[var(--panel-strong)] text-[var(--muted-strong)]",
    success: "bg-[var(--success)]/10 text-[var(--success)]",
    warning: "bg-[var(--warning)]/15 text-[var(--civic-navy)]",
    danger: "bg-[var(--danger)]/10 text-[var(--danger)]",
    info: "bg-[var(--lumi-blue-soft)] text-[var(--lumi-blue)]",
  }[tone];
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs font-medium ${toneClass}`}
    >
      {children}
    </span>
  );
}

export function BillingMetric({
  label,
  value,
  detail,
  tone = "neutral",
}: {
  label: string;
  value: string;
  detail: string;
  tone?: BillingTone;
}) {
  const valueClass = {
    neutral: "text-[var(--civic-navy)]",
    success: "text-[var(--success)]",
    warning: "text-[var(--civic-navy)]",
    danger: "text-[var(--danger)]",
    info: "text-[var(--lumi-blue)]",
  }[tone];
  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-4">
      <p className="text-xs font-medium text-[var(--muted)]">{label}</p>
      <p className={`mt-2 text-xl font-semibold tabular-nums tracking-[-0.02em] ${valueClass}`}>
        {value}
      </p>
      <p className="mt-1 text-xs leading-4 text-[var(--muted)]">{detail}</p>
    </div>
  );
}

export function BillingCode({ children }: { children: ReactNode }) {
  return <code className="break-all font-mono text-xs text-[var(--muted-strong)]">{children}</code>;
}

export function BillingTableCaption({ children }: { children: ReactNode }) {
  return <caption className="sr-only">{children}</caption>;
}

export function BillingDate({ value, label }: { value: string | null; label?: string }) {
  if (!value) return <span className="text-[var(--muted)]">—</span>;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return <span className="text-[var(--muted)]">Unknown</span>;
  return (
    <time dateTime={value} title={label ? `${label}: ${value}` : value}>
      {date.toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      })}
    </time>
  );
}

/**
 * A bounded inline bar for a countable limit. A plain, static, width-bounded
 * track; no charting library and no animation, so reduced motion needs no
 * special case here. The numbers are always present as text next to it.
 */
export function BillingLimitBar({
  current,
  limit,
  label,
}: {
  current: number;
  limit: number;
  label: string;
}) {
  const safeLimit = Math.max(0, limit);
  const ratio = safeLimit === 0 ? 1 : Math.min(1.5, current / safeLimit);
  const percent = Math.round(ratio * 100);
  const over = current > safeLimit;
  return (
    <div className="min-w-[120px]">
      <div
        aria-hidden="true"
        className="h-1.5 w-full overflow-hidden rounded-full bg-[var(--panel-strong)]"
      >
        <div
          className={over ? "h-full bg-[var(--danger)]" : "h-full bg-[var(--lumi-blue)]"}
          style={{ width: `${Math.min(100, percent)}%` }}
        />
      </div>
      <p className="mt-1 text-xs tabular-nums text-[var(--muted-strong)]">
        <span className="sr-only">{label}: </span>
        {current} of {safeLimit} used
      </p>
    </div>
  );
}

export function BillingDefinitionRow({
  term,
  description,
  children,
}: {
  term: string;
  description: string;
  children?: ReactNode;
}) {
  return (
    <div className="grid gap-1 border-b border-[var(--border)] py-3 last:border-b-0 sm:grid-cols-[minmax(0,15rem)_minmax(0,1fr)] sm:gap-4">
      <dt className="text-sm font-semibold text-[var(--civic-navy)]">{term}</dt>
      <dd className="text-sm leading-5 text-[var(--muted-strong)]">
        <p>{description}</p>
        {children ? <div className="mt-2">{children}</div> : null}
      </dd>
    </div>
  );
}

export const primaryButtonClass =
  "inline-flex min-h-11 items-center justify-center gap-2 rounded-lg bg-[var(--lumi-blue)] px-3 py-2 text-sm font-semibold text-white shadow-[var(--shadow-button)] outline-none transition hover:bg-[var(--lumi-blue-hover)] active:translate-y-px focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";

export const secondaryButtonClass =
  "inline-flex min-h-11 items-center justify-center gap-2 rounded-lg border border-[var(--lumi-blue)]/40 bg-[var(--panel)] px-3 py-2 text-sm font-medium text-[var(--lumi-blue)] outline-none transition hover:border-[var(--lumi-blue)]/60 hover:bg-[var(--lumi-blue-soft)] active:translate-y-px focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";

export const dangerButtonClass =
  "inline-flex min-h-11 items-center justify-center gap-2 rounded-lg border border-[var(--danger)]/40 bg-[var(--panel)] px-3 py-2 text-sm font-medium text-[var(--danger)] outline-none transition hover:bg-[var(--danger)]/5 active:translate-y-px focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";

export const inputClass =
  "mt-1.5 min-h-10 w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 text-sm text-[var(--foreground)] outline-none transition placeholder:text-[var(--muted)] focus-visible:border-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2";
