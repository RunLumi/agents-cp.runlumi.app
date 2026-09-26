/**
 * Identity surface primitives.
 *
 * Local to `features/identity/**`, following the precedent set by
 * `features/webhooks/ui.tsx` and `features/data-governance/ui.tsx`: the shared
 * design-system components under `src/components/ui` are not generated in this
 * repository, so each surface owns primitives built from the semantic tokens in
 * `src/styles/globals.css`. No palette, typeface, radius, or decorative style is
 * introduced here — `DESIGN.md` §5, §8, and §13 are the source for every value.
 *
 * `DESIGN.md` §8.1 fixes the radii used below (8px controls, 12px sheets), §8.2
 * fixes 1px archival borders and the 2px focus ring, and §13 limits transitions
 * to 120–180ms — which `globals.css` already removes under
 * `prefers-reduced-motion`.
 */

import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";

import { presentIdentityError } from "./api";

export type Tone = "neutral" | "info" | "success" | "warning" | "danger";

/**
 * A horizontal tab strip for the sub-pages of one settings surface.
 *
 * Roving tabindex WITH arrow-key movement, following the ARIA tabs pattern and
 * the precedent in `features/data-governance/ui.tsx`. The combination matters:
 * roving tabindex on its own would make every unselected tab unreachable from the
 * keyboard, because a `tabindex="-1"` button can only be reached programmatically.
 * A strip of four buttons all at `tabindex=0` would instead make a keyboard user
 * tab through the whole strip on every visit, which is why the roving form is
 * right — provided the arrow keys actually move the selection.
 *
 * The strip is the only navigation inside these panels, so it has to be
 * operable: arrows move, Home/End jump to the ends, and focus follows selection.
 */
export function TabStrip<T extends string>({
  tabs,
  active,
  onChange,
  label,
  idPrefix,
}: {
  tabs: ReadonlyArray<{ id: T; label: string }>;
  active: T;
  onChange: (id: T) => void;
  label: string;
  idPrefix: string;
}) {
  const listRef = useRef<HTMLDivElement | null>(null);

  function move(next: number) {
    const bounded = (next + tabs.length) % tabs.length;
    const target = tabs[bounded];
    if (!target) return;
    onChange(target.id);
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
            id={`${idPrefix}-tab-${tab.id}`}
            aria-selected={selected}
            aria-controls={`${idPrefix}-panel-${tab.id}`}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(tab.id)}
            className={[
              "-mb-px min-h-11 shrink-0 border-b-2 px-3 text-sm font-medium whitespace-nowrap outline-none transition focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2",
              selected
                ? "border-[var(--lumi-blue)] text-[var(--civic-navy)]"
                : "border-transparent text-[var(--muted-strong)] hover:bg-[var(--panel-hover)] hover:text-[var(--civic-navy)]",
            ].join(" ")}
          >
            {tab.label}
          </button>
        );
      })}
    </div>
  );
}

/** The single tab panel body, labelled by its own tab. */
export function TabPanel({
  id,
  idPrefix,
  children,
}: {
  id: string;
  idPrefix: string;
  children: ReactNode;
}) {
  return (
    <div
      role="tabpanel"
      id={`${idPrefix}-panel-${id}`}
      aria-labelledby={`${idPrefix}-tab-${id}`}
      tabIndex={0}
      className="space-y-5 outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
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
          <p className="text-[11px] font-semibold tracking-[0.1em] text-[var(--muted)] uppercase">
            {eyebrow}
          </p>
        ) : null}
        <h3 className="mt-0.5 text-base font-semibold text-[var(--civic-navy)]">{title}</h3>
        <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--muted-strong)]">{description}</p>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}

export function LoadingRows({ label, rows = 3 }: { label: string; rows?: number }) {
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

export function ErrorNotice({
  error,
  title,
  onRetry,
}: {
  error: unknown;
  title?: string;
  onRetry?: () => void;
}) {
  const presentation = presentIdentityError(error);
  return (
    <div
      role="alert"
      className="rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/5 p-4 text-sm"
    >
      <p className="font-semibold text-[var(--danger)]">{title ?? presentation.title}</p>
      <p className="mt-1 leading-5 text-[var(--civic-navy)]">{presentation.message}</p>
      <p className="mt-1 text-xs text-[var(--muted)]">Reason code {presentation.code}</p>
      {presentation.requestId ? (
        <p className="mt-1 break-all text-xs text-[var(--muted)]">
          Request {presentation.requestId}
        </p>
      ) : null}
      {onRetry ? (
        <button type="button" className={dangerButtonClass} onClick={onRetry}>
          Try again
        </button>
      ) : null}
    </div>
  );
}

const NOTICE_TONE: Readonly<Record<Tone, string>> = {
  neutral: "border-[var(--border)] bg-[var(--panel-hover)] text-[var(--civic-navy)]",
  info: "border-[var(--lumi-blue)]/30 bg-[var(--lumi-blue-soft)] text-[var(--civic-navy)]",
  success: "border-[var(--success)]/30 bg-[var(--success)]/5 text-[var(--civic-navy)]",
  warning: "border-[var(--warning)]/45 bg-[var(--warning)]/10 text-[var(--civic-navy)]",
  danger: "border-[var(--danger)]/30 bg-[var(--danger)]/5 text-[var(--civic-navy)]",
};

export function Notice({
  children,
  tone = "info",
  title,
}: {
  children: ReactNode;
  tone?: Tone;
  title?: string;
}) {
  return (
    <div
      role={tone === "danger" ? "alert" : "status"}
      className={`rounded-lg border p-3 text-sm leading-5 ${NOTICE_TONE[tone]}`}
    >
      {title ? <p className="font-semibold">{title}</p> : null}
      {title ? <div className="mt-1">{children}</div> : children}
    </div>
  );
}

const PILL_TONE: Readonly<Record<Tone, string>> = {
  neutral: "bg-[var(--panel-strong)] text-[var(--muted-strong)]",
  info: "bg-[var(--lumi-blue-soft)] text-[var(--lumi-blue)]",
  success: "bg-[var(--success)]/10 text-[var(--success)]",
  warning: "bg-[var(--warning)]/15 text-[var(--civic-navy)]",
  danger: "bg-[var(--danger)]/10 text-[var(--danger)]",
};

/** A true chip: fully rounded, per `DESIGN.md` §8.1. */
export function Pill({ children, tone = "neutral" }: { children: ReactNode; tone?: Tone }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2 py-1 text-xs font-medium ${PILL_TONE[tone]}`}
    >
      {children}
    </span>
  );
}

/** The status dot the design references pair with a status pill. */
export function StatusDot({ tone }: { tone: Tone }) {
  const color = {
    neutral: "bg-[var(--muted)]",
    info: "bg-[var(--lumi-blue)]",
    success: "bg-[var(--success)]",
    warning: "bg-[var(--warning)]",
    danger: "bg-[var(--danger)]",
  }[tone];
  return <span aria-hidden="true" className={`size-1.5 shrink-0 rounded-full ${color}`} />;
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
          "mt-1 text-sm text-[var(--civic-navy)]",
          mono ? "break-all font-mono text-xs" : "break-words",
        ].join(" ")}
      >
        {value}
      </dd>
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

export function PermissionState({ title, copy }: { title: string; copy: string }) {
  return (
    <div className="rounded-xl border border-[var(--border)] bg-[var(--panel-hover)] p-5 shadow-[var(--shadow)]">
      <p className="text-sm font-semibold text-[var(--civic-navy)]">{title}</p>
      <p className="mt-1 text-sm leading-5 text-[var(--muted-strong)]">{copy}</p>
    </div>
  );
}

export function PaginationFooter({
  loaded,
  hasMore,
  loading,
  onLoadMore,
  noun,
  limitNote,
}: {
  loaded: number;
  hasMore: boolean;
  loading: boolean;
  onLoadMore: () => void;
  noun: string;
  /** A frozen bound the reader should know about before they hit it. */
  limitNote?: string;
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[var(--border)] px-5 py-3">
      <p className="text-xs text-[var(--muted)]" aria-live="polite">
        {loaded} {noun}
        {loaded === 1 ? "" : "s"} loaded{hasMore ? " · more available" : ""}
        {limitNote ? ` · ${limitNote}` : ""}
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
 * The consequence + reason dialog.
 *
 * Built on the native `dialog` element so the browser supplies focus trapping,
 * the backdrop, Escape, and the correct screen-reader semantics — the same
 * pattern `features/webhooks/webhooks-panel.tsx` and
 * `features/data-governance/ui.tsx` already use. A reason field is always
 * present and always required: the server refuses an empty one, so a control
 * that let an operator submit without it would be a control that always fails.
 */
export function ReasonDialog({
  open,
  eyebrow,
  title,
  body,
  reasonLabel,
  reasonHint,
  confirmLabel,
  cancelLabel,
  busyLabel,
  busy,
  destructive,
  onClose,
  onConfirm,
}: {
  open: boolean;
  eyebrow: string;
  title: string;
  body: readonly string[];
  reasonLabel: string;
  reasonHint: string;
  confirmLabel: string;
  cancelLabel: string;
  busyLabel: string;
  busy: boolean;
  destructive: boolean;
  onClose: () => void;
  onConfirm: (reason: string) => void;
}) {
  const reasonId = useId();
  const [reason, setReason] = useState("");
  // Reset on the open edge so a reason typed for an action that was abandoned
  // can never be submitted against the next one. The value lives only in this
  // component: a closed dialog holds no operator text at all.
  const wasOpen = useRef(open);
  useEffect(() => {
    if (open && !wasOpen.current) setReason("");
    wasOpen.current = open;
  }, [open]);

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
          <p className="text-[11px] font-semibold tracking-[0.1em] text-[var(--lumi-blue)] uppercase">
            {eyebrow}
          </p>
          <h2 className="mt-2 text-lg font-semibold text-[var(--civic-navy)]">{title}</h2>
          <div className="mt-3 space-y-2 text-sm leading-6 text-[var(--muted-strong)]">
            {body.map((paragraph) => (
              <p key={paragraph.slice(0, 40)}>{paragraph}</p>
            ))}
          </div>
          <div className="mt-5">
            <label
              htmlFor={reasonId}
              className="block text-sm font-medium text-[var(--civic-navy)]"
            >
              {reasonLabel}
            </label>
            <textarea
              id={reasonId}
              required
              rows={3}
              maxLength={500}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder="Recorded in the security audit log with your name."
              className="mt-1.5 w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 py-2 text-sm text-[var(--foreground)] outline-none transition placeholder:text-[var(--muted)] focus-visible:border-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
            />
            <p className="mt-1 text-xs text-[var(--muted)]">{reasonHint}</p>
          </div>
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
              onClick={() => onConfirm(reason.trim())}
              disabled={busy || reason.trim().length === 0}
            >
              {busy ? busyLabel : confirmLabel}
            </button>
          </div>
        </div>
      ) : null}
    </dialog>
  );
}

/** A labelled text input, used by the create forms. */
export function TextField({
  label,
  value,
  onChange,
  placeholder,
  type = "text",
  required = false,
  hint,
  maxLength,
  autoComplete = "off",
  disabled = false,
}: {
  label: string;
  value: string;
  onChange: (next: string) => void;
  placeholder?: string;
  type?: string;
  required?: boolean;
  hint?: string;
  maxLength?: number;
  autoComplete?: string;
  disabled?: boolean;
}) {
  const id = useId();
  return (
    <div>
      <label htmlFor={id} className="block text-sm font-medium text-[var(--civic-navy)]">
        {label}
      </label>
      <input
        id={id}
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        {...(placeholder ? { placeholder } : {})}
        {...(maxLength ? { maxLength } : {})}
        {...(required ? { required } : {})}
        {...(disabled ? { disabled } : {})}
        autoComplete={autoComplete}
        className={inputClass}
      />
      {hint ? <p className="mt-1 text-xs text-[var(--muted)]">{hint}</p> : null}
    </div>
  );
}

export function SelectField({
  label,
  value,
  onChange,
  children,
  hint,
  disabled = false,
}: {
  label: string;
  value: string;
  onChange: (next: string) => void;
  children: ReactNode;
  hint?: string;
  disabled?: boolean;
}) {
  const id = useId();
  return (
    <div>
      <label htmlFor={id} className="block text-sm font-medium text-[var(--civic-navy)]">
        {label}
      </label>
      <select
        id={id}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        disabled={disabled}
        className={selectClass}
      >
        {children}
      </select>
      {hint ? <p className="mt-1 text-xs text-[var(--muted)]">{hint}</p> : null}
    </div>
  );
}

/** A comma or newline separated list field, parsed to a trimmed string array. */
export function ListField({
  label,
  value,
  onChange,
  placeholder,
  hint,
  disabled = false,
}: {
  label: string;
  value: string;
  onChange: (next: string) => void;
  placeholder?: string;
  hint?: string;
  disabled?: boolean;
}) {
  return (
    <TextField
      label={label}
      value={value}
      onChange={onChange}
      {...(placeholder ? { placeholder } : {})}
      {...(hint ? { hint } : {})}
      {...(disabled ? { disabled } : {})}
    />
  );
}

export function parseListField(value: string): string[] {
  return Array.from(
    new Set(
      value
        .split(/[\n,]/)
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0),
    ),
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

/** The "this row is selected" state for a row-level view control. */
export const selectedButtonClass =
  "inline-flex min-h-9 items-center justify-center gap-2 rounded-lg border border-[var(--lumi-blue)] bg-[var(--lumi-blue-soft)] px-3 py-1.5 text-xs font-semibold text-[var(--lumi-blue)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2";

export const inputClass =
  "mt-1.5 min-h-11 w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 text-sm font-normal text-[var(--foreground)] outline-none transition placeholder:text-[var(--muted)] focus-visible:border-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-60";

export const selectClass =
  "mt-1.5 min-h-11 w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 text-sm font-normal text-[var(--foreground)] outline-none transition focus-visible:border-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-60";

export const checkboxClass =
  "size-4 shrink-0 rounded border-[var(--border-strong)] accent-[var(--lumi-blue)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2";
