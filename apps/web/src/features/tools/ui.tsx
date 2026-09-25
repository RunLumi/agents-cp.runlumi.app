import type { ReactNode } from "react";

import { presentApiError } from "@/lib/errors";

import type { ApprovalStatus, ToolDecision, ToolLifecycle, ToolRiskClass } from "./helpers";
import { humanize } from "./helpers";

export { humanize } from "./helpers";

export function ToolPanel({
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
      className={joinClasses(
        "overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]",
        className,
      )}
    >
      {children}
    </section>
  );
}

export function ToolPanelHeader({
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
        <h2 className="text-base font-semibold text-[var(--civic-navy)]">{title}</h2>
        <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--muted-strong)]">{description}</p>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}

export function ToolLoading({ label, rows = 3 }: { label: string; rows?: number }) {
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

export function ToolError({
  error,
  onRetry,
}: {
  error: unknown;
  onRetry?: (() => void) | undefined;
}) {
  const presentation = presentApiError(error);
  return (
    <div
      role="alert"
      className="rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/5 p-4 text-sm text-[var(--danger)]"
    >
      <p className="font-medium">{presentation.message}</p>
      {presentation.requestId ? (
        <p className="mt-1 text-xs opacity-75">Request {presentation.requestId}</p>
      ) : null}
      {onRetry ? (
        <button type="button" className={dangerButtonClass} onClick={onRetry}>
          Try again
        </button>
      ) : null}
    </div>
  );
}

export function ToolPermission({ message }: { message?: string }) {
  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-5">
      <p className="text-sm font-semibold text-[var(--civic-navy)]">Access not permitted</p>
      <p className="mt-1 text-sm leading-5 text-[var(--muted-strong)]">
        {message ?? "Your current organization role cannot view this control-plane surface."}
      </p>
    </div>
  );
}

export function ToolEmpty({ title, description }: { title: string; description: string }) {
  return (
    <div className="p-6">
      <p className="text-sm font-semibold text-[var(--civic-navy)]">{title}</p>
      <p className="mt-1 max-w-2xl text-sm leading-5 text-[var(--muted-strong)]">{description}</p>
    </div>
  );
}

export function ToolNotice({
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

export function StatusPill({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: "neutral" | "success" | "warning" | "danger" | "info";
}) {
  const toneClass = {
    neutral: "bg-[var(--panel-strong)] text-[var(--muted-strong)]",
    success: "bg-[var(--success)]/10 text-[var(--success)]",
    warning: "bg-[var(--warning)]/15 text-[var(--civic-navy)]",
    danger: "bg-[var(--danger)]/10 text-[var(--danger)]",
    info: "bg-[var(--lumi-blue-soft)] text-[var(--lumi-blue)]",
  }[tone];
  return (
    <span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium ${toneClass}`}>
      {children}
    </span>
  );
}

export function DecisionBadge({ decision }: { decision: ToolDecision | null }) {
  if (decision === "allow") return <StatusPill tone="success">Allow</StatusPill>;
  if (decision === "require_session_approval") {
    return <StatusPill tone="warning">Session approval</StatusPill>;
  }
  if (decision === "require_per_use_approval") {
    return <StatusPill tone="warning">Per-use approval</StatusPill>;
  }
  if (decision === "deny") return <StatusPill tone="danger">Deny</StatusPill>;
  return <StatusPill tone="warning">Not evaluated</StatusPill>;
}

export function RiskBadge({ riskClass }: { riskClass: ToolRiskClass }) {
  const tone = riskTone(riskClass);
  return <StatusPill tone={tone}>{humanize(riskClass)}</StatusPill>;
}

export function ApprovalStatusPill({ status }: { status: ApprovalStatus }) {
  if (status === "approved") return <StatusPill tone="success">Approved</StatusPill>;
  if (status === "denied") return <StatusPill tone="danger">Denied</StatusPill>;
  if (status === "expired") return <StatusPill tone="warning">Expired</StatusPill>;
  if (status === "cancelled") return <StatusPill tone="neutral">Cancelled</StatusPill>;
  return <StatusPill tone="info">Pending</StatusPill>;
}

export function LifecyclePill({ lifecycle }: { lifecycle: ToolLifecycle }) {
  if (lifecycle === "active") return <StatusPill tone="success">Active</StatusPill>;
  if (lifecycle === "review") return <StatusPill tone="warning">Review</StatusPill>;
  return <StatusPill tone="danger">Disabled</StatusPill>;
}

export function ToolDate({ value }: { value: string | null }) {
  if (!value) return <span className="text-[var(--muted)]">—</span>;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return <span className="text-[var(--muted)]">Unknown</span>;
  return <time dateTime={value}>{date.toLocaleString()}</time>;
}

export function ToolCode({ children }: { children: ReactNode }) {
  return <code className="break-all font-mono text-xs text-[var(--muted-strong)]">{children}</code>;
}

export function ToolMetric({
  label,
  value,
  detail,
}: {
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-4">
      <p className="text-xs font-medium text-[var(--muted)]">{label}</p>
      <p className="mt-2 text-xl font-semibold tabular-nums tracking-[-0.02em] text-[var(--civic-navy)]">
        {value}
      </p>
      <p className="mt-1 text-xs text-[var(--muted)]">{detail}</p>
    </div>
  );
}

export function ToolTableCaption({ children }: { children: ReactNode }) {
  return <caption className="sr-only">{children}</caption>;
}

export const primaryButtonClass =
  "inline-flex min-h-11 items-center justify-center gap-2 rounded-lg bg-[var(--lumi-blue)] px-3 py-2 text-sm font-semibold text-white shadow-[var(--shadow-button)] outline-none transition hover:bg-[var(--lumi-blue-hover)] active:translate-y-px focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";

export const secondaryButtonClass =
  "inline-flex min-h-11 items-center justify-center gap-2 rounded-lg border border-[var(--lumi-blue)]/40 bg-[var(--panel)] px-3 py-2 text-sm font-medium text-[var(--lumi-blue)] outline-none transition hover:border-[var(--lumi-blue)]/60 hover:bg-[var(--lumi-blue-soft)] active:translate-y-px focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";

export const dangerButtonClass =
  "inline-flex min-h-11 items-center justify-center gap-2 rounded-lg border border-[var(--danger)]/40 bg-[var(--panel)] px-3 py-2 text-sm font-medium text-[var(--danger)] outline-none transition hover:bg-[var(--danger)]/5 active:translate-y-px focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";

export const inputClass =
  "mt-1.5 min-h-10 w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 text-sm text-[var(--foreground)] outline-none transition placeholder:text-[var(--muted)] focus-visible:border-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2";

function riskTone(riskClass: ToolRiskClass): "neutral" | "success" | "warning" | "danger" | "info" {
  if (riskClass === "read_only") return "success";
  if (riskClass === "network" || riskClass === "browser" || riskClass === "computer") return "info";
  if (
    riskClass === "filesystem_write" ||
    riskClass === "process_execution" ||
    riskClass === "mcp"
  ) {
    return "warning";
  }
  return "danger";
}

function joinClasses(...values: Array<string | undefined>): string {
  return values.filter((value): value is string => Boolean(value)).join(" ");
}
