/**
 * Data-governance surface primitives.
 *
 * Local to `features/data-governance/**`, like the other P06 feature
 * primitives: the shared design-system components are not generated in this
 * repository and `@/components` is outside this packet's write surface. Every
 * value here is a token from `src/styles/globals.css`; no palette, typeface,
 * radius, or decorative style is introduced.
 *
 * `DESIGN.md` supplies the material model: paper canvas, white evidence sheets
 * with a 1px archival border, Civic Navy headings, Lumi Blue as authority and
 * never decoration, status colors only where they carry real semantics, and
 * 120–180ms hover/focus transitions that `prefers-reduced-motion` removes.
 */

import { useRef, type KeyboardEvent, type ReactNode } from "react";

import { presentDataError } from "./contracts";
import type { Tone } from "./contracts";

/**
 * A horizontal tab strip for the sub-pages of one settings surface.
 *
 * WHY this is here: `docs/screens/lumi_export_history.webp` shows Data &
 * Retention as ONE page with four tabs — Retention policies, Export history,
 * Data controls, Deletion requests — rather than four separate surfaces. The
 * tabs sit above a single hairline rule, left-aligned, with the active tab
 * carrying an Lumi Blue underline.
 *
 * Lumi Blue is the authority color, so it is correct here: the underline marks
 * which sub-page you are on. It is never decoration.
 *
 * Keyboard behavior follows the ARIA tabs pattern: arrow keys move between
 * tabs, Home/End jump to the ends, and focus is roving so a single Tab press
 * reaches the strip rather than every tab in it.
 */
export function TabNav<T extends string>({
  tabs,
  active,
  onChange,
  label,
}: {
  tabs: ReadonlyArray<{ id: T; label: string }>;
  active: T;
  onChange: (id: T) => void;
  label: string;
}) {
  const listRef = useRef<HTMLDivElement | null>(null);

  function move(next: number) {
    const bounded = (next + tabs.length) % tabs.length;
    const target = tabs[bounded];
    if (!target) return;
    onChange(target.id);
    // Move focus with the selection so the keyboard user keeps their place.
    listRef.current
      ?.querySelector<HTMLButtonElement>(`[data-tab-id="${CSS.escape(target.id)}"]`)
      ?.focus();
  }

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const current = tabs.findIndex((tab) => tab.id === active);
    if (current < 0) return;
    if (event.key === "ArrowRight") {
      event.preventDefault();
      move(current + 1);
    } else if (event.key === "ArrowLeft") {
      event.preventDefault();
      move(current - 1);
    } else if (event.key === "Home") {
      event.preventDefault();
      move(0);
    } else if (event.key === "End") {
      event.preventDefault();
      move(tabs.length - 1);
    }
  }

  return (
    <div
      ref={listRef}
      role="tablist"
      aria-label={label}
      onKeyDown={onKeyDown}
      className="flex gap-1 overflow-x-auto border-b border-[var(--border)]"
    >
      {tabs.map((tab) => {
        const selected = tab.id === active;
        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            data-tab-id={tab.id}
            id={`${label.replace(/\s+/g, "-").toLowerCase()}-tab-${tab.id}`}
            aria-selected={selected}
            aria-controls={`${label.replace(/\s+/g, "-").toLowerCase()}-panel-${tab.id}`}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(tab.id)}
            className={`-mb-px shrink-0 border-b-2 px-3 py-2.5 text-sm font-medium whitespace-nowrap transition-colors outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 ${
              selected
                ? "border-[var(--lumi-blue)] text-[var(--civic-navy)]"
                : "border-transparent text-[var(--muted-strong)] hover:bg-[var(--panel-hover)] hover:text-[var(--civic-navy)]"
            }`}
          >
            {tab.label}
          </button>
        );
      })}
    </div>
  );
}

/**
 * The single tab panel body. `role="tabpanel"` is required for the tabs to be
 * announced correctly, and it must be labelled by its tab.
 */
export function TabPanel({
  id,
  label,
  children,
}: {
  id: string;
  label: string;
  children: ReactNode;
}) {
  const base = label.replace(/\s+/g, "-").toLowerCase();
  return (
    <div
      role="tabpanel"
      id={`${base}-panel-${id}`}
      aria-labelledby={`${base}-tab-${id}`}
      tabIndex={0}
      className="outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
    >
      {children}
    </div>
  );
}

export function Surface({
  children,
  ariaLabel,
  ariaLabelledBy,
  className,
  tone = "default",
}: {
  children: ReactNode;
  ariaLabel?: string;
  ariaLabelledBy?: string;
  className?: string;
  /** `quiet` continues the surface above it instead of starting a new one. */
  tone?: "default" | "quiet";
}) {
  return (
    <section
      {...(ariaLabel ? { "aria-label": ariaLabel } : {})}
      {...(ariaLabelledBy ? { "aria-labelledby": ariaLabelledBy } : {})}
      className={[
        "overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]",
        tone === "quiet" ? "rounded-t-none border-t-0" : "",
        className ?? "",
      ]
        .filter(Boolean)
        .join(" ")}
    >
      {children}
    </section>
  );
}

/** The 3px severity rail, applied to a wrapper rather than the sheet. */
export function SeverityRail({
  children,
  severity,
  className,
}: {
  children: ReactNode;
  severity: "warning" | "danger";
  className?: string;
}) {
  const rail = severity === "danger" ? "border-l-[var(--danger)]" : "border-l-[var(--warning)]";
  return (
    <div
      className={[
        "overflow-hidden rounded-xl border border-[var(--border)] border-l-[3px] bg-[var(--panel)] shadow-[var(--shadow)]",
        rail,
        className ?? "",
      ]
        .filter(Boolean)
        .join(" ")}
    >
      {children}
    </div>
  );
}

export function SurfaceHeader({
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

export function LoadingRows({ label, rows = 4 }: { label: string; rows?: number }) {
  return (
    <div className="p-5" role="status" aria-live="polite" aria-busy="true">
      <p className="text-sm text-[var(--muted-strong)]">{label}</p>
      <div className="mt-4 space-y-2" aria-hidden="true">
        {Array.from({ length: rows }, (_, index) => (
          <div key={index} className="h-12 animate-pulse rounded-lg bg-[var(--panel-hover)]" />
        ))}
      </div>
    </div>
  );
}

/**
 * The shared error surface.
 *
 * `presentDataError` maps the stable P06 reason code to frozen copy; the
 * server's own message is never rendered. The code is shown so an operator can
 * quote it, and the request id is shown so a support question is actionable.
 */
export function ErrorNotice({
  error,
  title,
  onRetry,
}: {
  error: unknown;
  title?: string;
  onRetry?: () => void;
}) {
  const presentation = presentDataError(error);
  return (
    <div
      role="alert"
      className="rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/5 p-4 text-sm text-[var(--danger)]"
    >
      <p className="font-semibold">{title ?? presentation.title}</p>
      <p className="mt-1 leading-5 text-[var(--muted-strong)]">{presentation.message}</p>
      <p className="mt-1 text-xs opacity-80">Reason code {presentation.code}</p>
      {presentation.requestId ? (
        <p className="mt-1 break-all text-xs opacity-80">Request {presentation.requestId}</p>
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
        Your current membership cannot view {resource}. Ask an administrator to review the data
        permission for this organization.
      </p>
    </div>
  );
}

const TONE_CLASS: Readonly<Record<Tone, string>> = {
  neutral: "bg-[var(--panel-strong)] text-[var(--muted-strong)]",
  info: "bg-[var(--lumi-blue-soft)] text-[var(--lumi-blue)]",
  success: "bg-[var(--success)]/10 text-[var(--success)]",
  warning: "bg-[var(--warning)]/15 text-[var(--civic-navy)]",
  danger: "bg-[var(--danger)]/10 text-[var(--danger)]",
};

/** A true chip: fully rounded, per the frozen radius scale. */
export function Pill({ children, tone = "neutral" }: { children: ReactNode; tone?: Tone }) {
  return (
    <span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium ${TONE_CLASS[tone]}`}>
      {children}
    </span>
  );
}

/** A short structural label, not a chip. Used for class keys and codes. */
export function Code({ children }: { children: ReactNode }) {
  return <code className="break-all font-mono text-xs text-[var(--muted-strong)]">{children}</code>;
}

export function DateTime({ value, label }: { value: string | null; label?: string }) {
  if (value === null) return <span className="text-[var(--muted)]">—</span>;
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return <span className="text-[var(--muted)]">Unknown</span>;
  return (
    <time dateTime={value} title={label ? `${label}: ${value}` : value} className="tabular-nums">
      {new Date(parsed).toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      })}
    </time>
  );
}

/** A definition row: a term, a description, and optional children. */
export function DefinitionRow({
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

/** A dense, horizontal-scroll table. Native markup, native focus order. */
export function DataTable({
  caption,
  headers,
  children,
}: {
  caption: string;
  headers: readonly string[];
  children: ReactNode;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr className="border-b border-[var(--border)]">
            {headers.map((header) => (
              <th
                key={header}
                scope="col"
                className="whitespace-nowrap px-4 py-2.5 text-xs font-semibold tracking-[0.04em] text-[var(--muted)] uppercase"
              >
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

export function TableCell({ children, header }: { children: ReactNode; header: string }) {
  return (
    <th
      scope="row"
      className="px-4 py-3 align-top text-left text-sm font-normal text-[var(--muted-strong)]"
    >
      <span className="sr-only">{header}: </span>
      {children}
    </th>
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

/**
 * A confirmation dialog built on the native `dialog` element.
 *
 * Native means the browser supplies focus trapping, the backdrop, Escape, and
 * the correct screen-reader semantics. The consequence copy is data, so the
 * caller cannot confirm an action that has no stated consequence.
 */
export function ConfirmDialog({
  open,
  eyebrow,
  title,
  body,
  confirmLabel,
  cancelLabel,
  busyLabel,
  busy,
  destructive,
  children,
  onClose,
  onConfirm,
}: {
  open: boolean;
  eyebrow: string;
  title: string;
  body: readonly string[];
  confirmLabel: string;
  cancelLabel: string;
  busyLabel: string;
  busy: boolean;
  destructive: boolean;
  /** Extra content inside the dialog, e.g. a typed-confirmation field. */
  children?: ReactNode;
  onClose: () => void;
  onConfirm: () => void;
}) {
  return (
    <dialog
      open={open}
      aria-label={open ? title : undefined}
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) onClose();
      }}
      className="m-auto w-[calc(100%-2rem)] max-w-xl rounded-xl border border-[var(--border)] bg-[var(--panel)] p-0 text-[var(--foreground)] shadow-[var(--shadow)] backdrop:bg-[var(--civic-navy)]/35"
    >
      {open ? (
        <div className="p-6">
          <p className="text-xs font-semibold tracking-[0.1em] text-[var(--lumi-blue)]">
            {eyebrow}
          </p>
          <h2 className="mt-2 text-lg font-semibold text-[var(--civic-navy)]">{title}</h2>
          <div className="mt-3 space-y-3 text-sm leading-6 text-[var(--muted-strong)]">
            {body.map((paragraph) => (
              <p key={paragraph.slice(0, 40)}>{paragraph}</p>
            ))}
          </div>
          {children ? <div className="mt-4">{children}</div> : null}
          <div className="mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <button
              type="button"
              className={secondaryButtonClass}
              onClick={onClose}
              disabled={busy}
              autoFocus
            >
              {cancelLabel}
            </button>
            <button
              type="button"
              className={destructive ? dangerButtonClass : primaryButtonClass}
              onClick={onConfirm}
              disabled={busy}
            >
              {busy ? busyLabel : confirmLabel}
            </button>
          </div>
        </div>
      ) : null}
    </dialog>
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

export const inputClass =
  "mt-1.5 min-h-11 w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 text-sm font-normal text-[var(--foreground)] outline-none transition placeholder:text-[var(--muted)] focus-visible:border-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2";

export const selectClass =
  "mt-1.5 min-h-11 w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 text-sm font-normal text-[var(--foreground)] outline-none transition focus-visible:border-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2";

export const checkboxClass =
  "size-4 shrink-0 rounded border-[var(--border-strong)] accent-[var(--lumi-blue)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2";
