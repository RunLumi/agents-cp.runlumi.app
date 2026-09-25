/**
 * Organization data policy: logging mode, retention overrides, legal hold,
 * backup lifecycle, and the provider-retention disclosure.
 *
 * Frozen contract: `GET/PATCH /api/v1/orgs/{org_id}/data-policy` as implemented
 * in `apps/api/src/routes/data_governance.rs`, and the "Data governance
 * contract" section of `P06-CG.md`.
 *
 * Two honesty rules are load-bearing here and are stated on the surface, not
 * hidden in a tooltip:
 *
 * 1. A retention override may only SHORTEN a window. Extending one past the
 *    class legal maximum needs an audited override, and a browser cannot mint
 *    one, so the server refuses it. The editor therefore offers a bounded
 *    number with the maximum shown next to it.
 * 2. `full_content` is described but not selectable. It is an audited,
 *    time-bounded diagnostic grant; the policy row has no window column, so the
 *    server refuses to store it. Offering a control that always fails would be
 *    a lie about what the page can do.
 */

import { useEffect, useId, useMemo, useRef, useState } from "react";

import {
  ALWAYS_PROHIBITED,
  BACKUP_LIFECYCLE_COPY,
  CONTENT_LOGGING_PRECEDENCE,
  dataClassSummary,
  formatWindow,
  LOGGING_MODE_COPY,
  LOGGING_MODE_ORDER,
  PROVIDER_DISCLOSURE_COPY,
  RETENTION_RULES,
  BYOK_NOTE,
} from "./contracts";
import {
  MAX_EXPORT_EXPIRY_SECONDS,
  MIN_EXPORT_EXPIRY_SECONDS,
  type BackupLifecycle,
  type DataGovernanceApi,
  type DataGovernancePolicy,
  type LoggingMode,
  type PersistableLoggingMode,
  type PolicyPatch,
  type ProviderRetentionDisclosure,
} from "./api";
import {
  ConfirmDialog,
  ErrorNotice,
  Notice,
  Pill,
  Surface,
  SurfaceHeader,
  dangerButtonClass,
  inputClass,
  primaryButtonClass,
  secondaryButtonClass,
  selectClass,
} from "./ui";

export interface DataPolicyEditorProps {
  orgId: string;
  api: DataGovernanceApi;
  policy: DataGovernancePolicy;
  status: "ready" | "stale" | "error";
  onRefresh: () => void;
  onSaved: (policy: DataGovernancePolicy) => void;
  /**
   * The acting principal. A legal-hold release must be attributed, so the field
   * is pre-filled when the shell knows the user and stays editable when it does
   * not. The server records whatever is sent, so an unattributed release is
   * refused rather than silently defaulted.
   */
  currentUserId?: string;
  /** Convenience only; authorization is enforced server-side. */
  canManage?: boolean;
}

const SECONDS_PER_DAY = 86_400;
const SECONDS_PER_MINUTE = 60;

type SaveState =
  | { kind: "idle" }
  | { kind: "busy" }
  | { kind: "done"; message: string }
  | { kind: "failed"; error: unknown };

interface DraftState {
  loggingMode: PersistableLoggingMode;
  overrides: Record<string, number>;
  backupLifecycle: BackupLifecycle;
  disclosure: ProviderRetentionDisclosure;
  disclosureUrl: string;
  exportExpiryMinutes: string;
}

const PLACEHOLDER_OVERRIDE = "__select__";

export function DataPolicyEditor({
  orgId,
  api,
  policy,
  status,
  onRefresh,
  onSaved,
  currentUserId,
  canManage = true,
}: DataPolicyEditorProps) {
  const [draft, setDraft] = useState<DraftState>(() => draftFrom(policy));
  const [save, setSave] = useState<SaveState>({ kind: "idle" });
  const [overrideClass, setOverrideClass] = useState<string>(PLACEHOLDER_OVERRIDE);
  const [overrideDays, setOverrideDays] = useState("30");
  const [overrideError, setOverrideError] = useState<string | null>(null);
  const [holdReason, setHoldReason] = useState("");
  const [holdError, setHoldError] = useState<string | null>(null);
  const [releaseBy, setReleaseBy] = useState(currentUserId ?? "");
  const [holdDialog, setHoldDialog] = useState<"place" | "release" | null>(null);
  const controller = useRef<AbortController | null>(null);

  // A loaded policy replaces the draft, so a reload never leaves stale input.
  useEffect(() => {
    setDraft(draftFrom(policy));
    setSave({ kind: "idle" });
  }, [policy]);

  useEffect(() => {
    setReleaseBy(currentUserId ?? "");
  }, [currentUserId]);

  useEffect(() => () => controller.current?.abort(), []);

  const editableClasses = useMemo(
    () => OVERRIDABLE_CLASSES.filter((key) => dataClassSummary(key) !== null),
    [],
  );
  const dirty = useMemo(() => patchesBetween(policy, draft).length > 0, [draft, policy]);

  async function submit(patch: PolicyPatch, message: string) {
    controller.current?.abort();
    const active = new AbortController();
    controller.current = active;
    setSave({ kind: "busy" });
    try {
      const next = await api.updatePolicy(orgId, patch, crypto.randomUUID(), active.signal);
      onSaved(next);
      setSave({ kind: "done", message });
    } catch (error) {
      setSave({ kind: "failed", error });
    }
  }

  const patches = patchesBetween(policy, draft);

  function saveDraft() {
    if (patches.length === 0) return;
    const patch: PolicyPatch = { version: policy.version };
    for (const entry of patches) {
      Object.assign(patch, entry.patch);
    }
    void submit(
      patch,
      "The data policy was saved. The server recorded the change and its audit event.",
    );
  }

  function addOverride() {
    if (overrideClass === PLACEHOLDER_OVERRIDE) {
      setOverrideError("Choose the data class this override applies to.");
      return;
    }
    const days = Number.parseInt(overrideDays, 10);
    if (!Number.isSafeInteger(days) || days < 1) {
      setOverrideError("Enter a whole number of days, at least 1.");
      return;
    }
    const seconds = days * SECONDS_PER_DAY;
    const summary = dataClassSummary(overrideClass);
    if (summary === null) {
      setOverrideError("That data class is not declared in the registry.");
      return;
    }
    setOverrideError(null);
    setDraft((current) => ({
      ...current,
      overrides: { ...current.overrides, [overrideClass]: seconds },
    }));
  }

  function removeOverride(key: string) {
    setOverrideError(null);
    setDraft((current) => {
      const next = { ...current.overrides };
      delete next[key];
      return { ...current, overrides: next };
    });
  }

  function confirmHold() {
    if (holdDialog === "place") {
      const reason = holdReason.trim();
      if (reason.length === 0) {
        setHoldError("A legal hold needs a reason. It is recorded with the hold.");
        return;
      }
      setHoldError(null);
      setHoldDialog(null);
      void submit(
        { version: policy.version, legal_hold: true, legal_hold_reason: reason },
        "The legal hold was placed. Records in scope are no longer expired or deleted until an audited release.",
      );
      return;
    }
    const principal = releaseBy.trim();
    if (principal.length === 0) {
      setHoldError("A release must name the principal that authorizes it.");
      return;
    }
    setHoldError(null);
    setHoldDialog(null);
    void submit(
      { version: policy.version, legal_hold: false, legal_hold_released_by: principal },
      "The hold was released and attributed. The release is recorded in the audit trail.",
    );
  }

  return (
    <div className="space-y-5">
      <LoggingModeSection
        policy={policy}
        draft={draft}
        disabled={!canManage}
        onChange={(mode) => setDraft((current) => ({ ...current, loggingMode: mode }))}
      />

      {policy.legal_hold ? (
        <HoldBanner
          policy={policy}
          canManage={canManage}
          onRelease={() => {
            setHoldError(null);
            setHoldDialog("release");
          }}
        />
      ) : null}

      <RetentionOverrideSection
        policy={policy}
        draft={draft}
        disabled={!canManage}
        classes={editableClasses}
        selectedClass={overrideClass}
        selectedDays={overrideDays}
        error={overrideError}
        onSelectClass={setOverrideClass}
        onDaysChange={setOverrideDays}
        onAdd={addOverride}
        onRemove={removeOverride}
      />

      <LifecycleSection
        draft={draft}
        disabled={!canManage}
        onBackupLifecycle={(value) =>
          setDraft((current) => ({ ...current, backupLifecycle: value }))
        }
        onDisclosure={(value) => setDraft((current) => ({ ...current, disclosure: value }))}
        onDisclosureUrl={(value) => setDraft((current) => ({ ...current, disclosureUrl: value }))}
        onExportExpiry={(value) =>
          setDraft((current) => ({ ...current, exportExpiryMinutes: value }))
        }
      />

      {status === "stale" ? (
        <Notice tone="warning">
          This policy snapshot is stale. Reload before saving, or the server will refuse the write
          with a version conflict.
        </Notice>
      ) : null}

      {save.kind === "done" ? (
        <Notice tone="success">
          <p>{save.message}</p>
        </Notice>
      ) : null}

      {save.kind === "failed" ? <ErrorNotice error={save.error} onRetry={saveDraft} /> : null}

      {canManage ? (
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            className={primaryButtonClass}
            onClick={saveDraft}
            disabled={!dirty || save.kind === "busy"}
          >
            {save.kind === "busy" ? "Saving…" : "Save policy changes"}
          </button>
          <button
            type="button"
            className={secondaryButtonClass}
            onClick={onRefresh}
            disabled={save.kind === "busy"}
          >
            Reload from server
          </button>
          <p className="text-xs text-[var(--muted)]" aria-live="polite">
            {dirty
              ? `${patches.length} unsaved change${patches.length === 1 ? "" : "s"}`
              : "No unsaved changes"}
          </p>
        </div>
      ) : (
        <Notice tone="info">
          Your current role can read this policy but not change it. The server enforces this on
          every write, so a read-only view is what your role can honestly be shown.
        </Notice>
      )}

      <LegalHoldSection
        policy={policy}
        canManage={canManage}
        busy={save.kind === "busy"}
        reason={holdReason}
        releasedBy={releaseBy}
        onReasonChange={setHoldReason}
        onReleasedByChange={setReleaseBy}
        onPlace={() => {
          setHoldError(null);
          setHoldDialog("place");
        }}
      />

      <ConfirmDialog
        open={holdDialog !== null}
        eyebrow={holdDialog === "release" ? "RELEASE LEGAL HOLD" : "PLACE LEGAL HOLD"}
        title={holdDialog === "release" ? "Release the legal hold?" : "Place a legal hold?"}
        body={holdDialog === "release" ? RELEASE_HOLD_COPY : PLACE_HOLD_COPY}
        confirmLabel={holdDialog === "release" ? "Release and attribute" : "Place hold"}
        cancelLabel={holdDialog === "release" ? "Keep the hold" : "Do not place a hold"}
        busyLabel={holdDialog === "release" ? "Releasing…" : "Placing…"}
        busy={save.kind === "busy"}
        destructive={holdDialog === "release"}
        onClose={() => setHoldDialog(null)}
        onConfirm={confirmHold}
      >
        {holdError ? (
          <p role="alert" className="text-sm font-medium text-[var(--danger)]">
            {holdError}
          </p>
        ) : null}
        <p className="text-xs leading-5 text-[var(--muted)]">
          {holdDialog === "release" ? "Releasing principal" : "Reason recorded with the hold"}
        </p>
        <input
          className={inputClass}
          value={holdDialog === "release" ? releaseBy : holdReason}
          onChange={(event) =>
            holdDialog === "release"
              ? setReleaseBy(event.target.value)
              : setHoldReason(event.target.value)
          }
          maxLength={holdDialog === "release" ? 64 : 2_000}
          autoComplete="off"
          aria-label={holdDialog === "release" ? "Releasing principal" : "Legal hold reason"}
        />
      </ConfirmDialog>
    </div>
  );
}

const PLACE_HOLD_COPY = [
  "A legal hold suspends expiry and deletion for the records it covers, in this organization. Expiry jobs stop for them and deletion steps skip them with a stated reason.",
  "Nothing is deleted by placing a hold. It is the opposite of deletion: it preserves records that would otherwise expire.",
  "Only an audited support or legal release lifts the hold, and the release is attributed and recorded. A hold is not a quiet setting.",
] as const;

const RELEASE_HOLD_COPY = [
  "Releasing the hold resumes expiry and deletion for the records it covered. Anything already past its retention window becomes eligible for deletion on the next sweep.",
  "The release must name the principal that authorizes it, and that attribution is recorded with the audit event.",
  "A deletion job that parked on this hold stays parked until it is explicitly resumed. Releasing the hold does not resume anything by itself.",
] as const;

function draftFrom(policy: DataGovernancePolicy): DraftState {
  return {
    loggingMode: policy.logging_mode === "redacted_content" ? "redacted_content" : "metadata_only",
    overrides: { ...policy.class_retention_overrides },
    backupLifecycle: policy.backup_lifecycle,
    disclosure: policy.provider_retention_disclosure,
    disclosureUrl: policy.provider_retention_url ?? "",
    exportExpiryMinutes: String(
      Math.round(policy.default_export_expiry_seconds / SECONDS_PER_MINUTE),
    ),
  };
}

interface DraftPatch {
  readonly field: string;
  readonly patch: Partial<Omit<PolicyPatch, "version">>;
}

/**
 * Diff the loaded policy against the draft.
 *
 * Only changed fields are sent: the route rejects unknown fields, and a partial
 * patch keeps a concurrent change on another field from being silently reverted.
 */
function patchesBetween(policy: DataGovernancePolicy, draft: DraftState): DraftPatch[] {
  const patches: DraftPatch[] = [];
  const currentMode: PersistableLoggingMode =
    policy.logging_mode === "redacted_content" ? "redacted_content" : "metadata_only";
  if (draft.loggingMode !== currentMode) {
    patches.push({ field: "logging_mode", patch: { logging_mode: draft.loggingMode } });
  }
  if (!sameNumbers(policy.class_retention_overrides, draft.overrides)) {
    patches.push({
      field: "class_retention_overrides",
      patch: { class_retention_overrides: draft.overrides },
    });
  }
  if (draft.backupLifecycle !== policy.backup_lifecycle) {
    patches.push({ field: "backup_lifecycle", patch: { backup_lifecycle: draft.backupLifecycle } });
  }
  if (draft.disclosure !== policy.provider_retention_disclosure) {
    patches.push({
      field: "provider_retention_disclosure",
      patch: { provider_retention_disclosure: draft.disclosure },
    });
  }
  const url = draft.disclosureUrl.trim();
  if (url !== (policy.provider_retention_url ?? "")) {
    if (url.length > 0) {
      patches.push({ field: "provider_retention_url", patch: { provider_retention_url: url } });
    }
  }
  const minutes = Number.parseInt(draft.exportExpiryMinutes, 10);
  if (Number.isSafeInteger(minutes)) {
    const seconds = minutes * SECONDS_PER_MINUTE;
    if (seconds >= MIN_EXPORT_EXPIRY_SECONDS && seconds <= MAX_EXPORT_EXPIRY_SECONDS) {
      if (seconds !== policy.default_export_expiry_seconds) {
        patches.push({
          field: "default_export_expiry_seconds",
          patch: { default_export_expiry_seconds: seconds },
        });
      }
    }
  }
  return patches;
}

function sameNumbers(
  left: Readonly<Record<string, number>>,
  right: Readonly<Record<string, number>>,
): boolean {
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  if (leftKeys.length !== rightKeys.length) return false;
  return leftKeys.every((key, index) => rightKeys[index] === key && left[key] === right[key]);
}

/** Classes a tenant policy may name. Mirrors `overridable` in the summary. */
const OVERRIDABLE_CLASSES = [
  "occurrence",
  "execution_lease",
  "occurrence_attempt",
  "automation_run_link",
  "webhook_delivery",
  "webhook_delivery_attempt",
  "notification",
  "notification_delivery",
  "provider_entitlement_projection",
  "entitlement_grant",
  "license_snapshot",
  "export_job",
  "export_artifact",
  "deletion_job",
  "deletion_step",
  "queue_job_envelope",
  "outbox_event",
  "operational_log",
] as const;

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

function LoggingModeSection({
  policy,
  draft,
  disabled,
  onChange,
}: {
  policy: DataGovernancePolicy;
  draft: DraftState;
  disabled: boolean;
  onChange: (mode: PersistableLoggingMode) => void;
}) {
  const groupId = useId();
  const active = policy.logging_mode;
  return (
    <Surface ariaLabel="Content logging mode">
      <SurfaceHeader
        eyebrow="WHAT IS WRITTEN TO LOGS"
        title="Content logging mode"
        description="The widest mode this organization may record. The default is metadata only, and it stays metadata only for inference and control-plane observability."
        action={
          <Pill tone={active === "metadata_only" ? "info" : "warning"}>
            {active.replace("_", " ")}
          </Pill>
        }
      />
      <fieldset className="px-5 py-4" disabled={disabled}>
        <legend className="sr-only">Content logging mode</legend>
        <div className="space-y-3">
          {LOGGING_MODE_ORDER.map((mode: LoggingMode) => {
            const copy = LOGGING_MODE_COPY[mode];
            const inputId = `${groupId}-${mode}`;
            const describedBy = `${inputId}-detail`;
            return (
              <div
                key={mode}
                className={[
                  "rounded-lg border p-3",
                  active === mode
                    ? "border-[var(--lumi-blue)]/50 bg-[var(--lumi-blue-soft)]"
                    : "border-[var(--border)] bg-[var(--panel-hover)]",
                ].join(" ")}
              >
                <div className="flex items-start gap-3">
                  <input
                    type="radio"
                    id={inputId}
                    name={`${groupId}-logging-mode`}
                    value={mode}
                    checked={draft.loggingMode === mode}
                    disabled={disabled || !copy.selectable}
                    aria-describedby={describedBy}
                    onChange={() => onChange(mode as PersistableLoggingMode)}
                    className="mt-1 size-4 shrink-0 accent-[var(--lumi-blue)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
                  />
                  <div className="min-w-0">
                    <label
                      htmlFor={inputId}
                      className="text-sm font-semibold text-[var(--civic-navy)]"
                    >
                      {copy.label}
                    </label>
                    <p className="mt-0.5 text-xs text-[var(--muted)]">{copy.summary}</p>
                    <div
                      id={describedBy}
                      className="mt-2 space-y-1 text-xs leading-5 text-[var(--muted-strong)]"
                    >
                      <p>{copy.includes}</p>
                      <p>{copy.doesNot}</p>
                      {!copy.selectable && copy.unavailableReason ? (
                        <p className="font-medium text-[var(--civic-navy)]">
                          Not selectable here. {copy.unavailableReason}
                        </p>
                      ) : null}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
        <div className="mt-4 rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-3">
          <p className="text-xs font-semibold tracking-[0.06em] text-[var(--muted)] uppercase">
            Prohibited in every mode
          </p>
          <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-[var(--muted-strong)]">
            {ALWAYS_PROHIBITED.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
          <p className="mt-2 text-xs leading-5 text-[var(--muted)]">{CONTENT_LOGGING_PRECEDENCE}</p>
        </div>
      </fieldset>
    </Surface>
  );
}

function HoldBanner({
  policy,
  canManage,
  onRelease,
}: {
  policy: DataGovernancePolicy;
  canManage: boolean;
  onRelease: () => void;
}) {
  return (
    <div
      role="status"
      className="rounded-xl border border-[var(--warning)]/45 border-l-[3px] border-l-[var(--warning)] bg-[var(--panel)] p-4 shadow-[var(--shadow)]"
    >
      <p className="text-xs font-semibold tracking-[0.1em] text-[var(--civic-navy)]">
        LEGAL HOLD ACTIVE
      </p>
      <p className="mt-1.5 text-sm font-semibold text-[var(--civic-navy)]">
        Expiry and deletion are suspended for the records this hold covers
      </p>
      <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
        <div>
          <dt className="text-xs font-medium text-[var(--muted)]">Reason</dt>
          <dd className="mt-0.5 leading-5 text-[var(--muted-strong)]">
            {policy.legal_hold_reason ?? "No reason was published with this hold."}
          </dd>
        </div>
        <div>
          <dt className="text-xs font-medium text-[var(--muted)]">Placed</dt>
          <dd className="mt-0.5 leading-5 text-[var(--muted-strong)]">
            {policy.legal_hold_placed_at ?? "Unknown"}
          </dd>
        </div>
      </dl>
      <p className="mt-3 text-xs leading-5 text-[var(--muted)]">
        A held export cannot mint a new download grant, and a held deletion step is skipped with the
        reason stated. Releasing the hold does not resume a parked deletion job.
      </p>
      {canManage ? (
        <button type="button" className={dangerButtonClass} onClick={onRelease}>
          Release the hold
        </button>
      ) : null}
    </div>
  );
}

function RetentionOverrideSection({
  policy,
  draft,
  disabled,
  classes,
  selectedClass,
  selectedDays,
  error,
  onSelectClass,
  onDaysChange,
  onAdd,
  onRemove,
}: {
  policy: DataGovernancePolicy;
  draft: DraftState;
  disabled: boolean;
  classes: readonly string[];
  selectedClass: string;
  selectedDays: string;
  error: string | null;
  onSelectClass: (value: string) => void;
  onDaysChange: (value: string) => void;
  onAdd: () => void;
  onRemove: (key: string) => void;
}) {
  const selectId = useId();
  const daysId = useId();
  const errorId = useId();
  const entries = Object.entries(draft.overrides).sort(([left], [right]) =>
    left.localeCompare(right),
  );
  return (
    <Surface ariaLabel="Retention overrides">
      <SurfaceHeader
        eyebrow="RETENTION"
        title="Per-class retention overrides"
        description="Each override replaces one class's baseline window. Shortening is always allowed; extending past the legal maximum needs an audited override that this page cannot create."
        action={
          <Pill tone={entries.length === 0 ? "neutral" : "info"}>
            {entries.length} override{entries.length === 1 ? "" : "s"}
          </Pill>
        }
      />
      <div className="space-y-4 px-5 py-4">
        <ul className="space-y-2">
          {RETENTION_RULES.map((rule) => (
            <li
              key={rule.title}
              className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-3"
            >
              <p className="text-sm font-semibold text-[var(--civic-navy)]">{rule.title}</p>
              <p className="mt-1 text-xs leading-5 text-[var(--muted-strong)]">{rule.body}</p>
            </li>
          ))}
        </ul>

        {entries.length === 0 ? (
          <p className="text-sm leading-5 text-[var(--muted-strong)]">
            No class is overridden. Every class keeps its frozen baseline window.
          </p>
        ) : (
          <ul className="divide-y divide-[var(--border)] rounded-lg border border-[var(--border)]">
            {entries.map(([key, seconds]) => {
              const summary = dataClassSummary(key);
              return (
                <li
                  key={key}
                  className="flex flex-wrap items-start justify-between gap-3 px-3 py-2.5"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-[var(--civic-navy)]">
                      {summary?.label ?? key}
                    </p>
                    <p className="mt-0.5 text-xs text-[var(--muted)]">
                      <code className="font-mono">{key}</code> · baseline{" "}
                      {summary?.defaultWindow ?? "unknown"} · legal maximum{" "}
                      {summary?.legalMaximum ?? "lifecycle, no numeric maximum"}
                    </p>
                    <p className="mt-1 text-xs text-[var(--muted-strong)]">
                      Effective window: {formatWindow(seconds)} ({seconds.toLocaleString()} seconds)
                    </p>
                  </div>
                  <button
                    type="button"
                    className="shrink-0 text-xs font-semibold text-[var(--danger)] underline outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:opacity-50"
                    onClick={() => onRemove(key)}
                    disabled={disabled}
                  >
                    Remove override
                  </button>
                </li>
              );
            })}
          </ul>
        )}

        <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_8rem_auto] sm:items-end">
          <div>
            <label htmlFor={selectId} className="text-xs font-medium text-[var(--muted-strong)]">
              Data class
            </label>
            <select
              id={selectId}
              className={selectClass}
              value={selectedClass}
              disabled={disabled}
              onChange={(event) => onSelectClass(event.target.value)}
            >
              <option value={PLACEHOLDER_OVERRIDE}>Choose a class…</option>
              {classes.map((key) => (
                <option key={key} value={key}>
                  {dataClassSummary(key)?.label ?? key}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor={daysId} className="text-xs font-medium text-[var(--muted-strong)]">
              Keep for (days)
            </label>
            <input
              id={daysId}
              className={inputClass}
              type="number"
              min={1}
              max={3650}
              step={1}
              inputMode="numeric"
              value={selectedDays}
              disabled={disabled}
              aria-describedby={error ? errorId : undefined}
              onChange={(event) => onDaysChange(event.target.value)}
            />
          </div>
          <button
            type="button"
            className={secondaryButtonClass}
            onClick={onAdd}
            disabled={disabled}
            aria-describedby={error ? errorId : undefined}
          >
            Add override
          </button>
        </div>
        {error ? (
          <p id={errorId} role="alert" className="text-xs font-medium text-[var(--danger)]">
            {error}
          </p>
        ) : null}
        <p className="text-xs leading-5 text-[var(--muted)]">
          Values are sent as whole seconds and stored with the policy version {policy.version}. A
          value beyond a class maximum is refused by the server rather than clamped, so a rejected
          edit never silently changes a different window.
        </p>
      </div>
    </Surface>
  );
}

function LifecycleSection({
  draft,
  disabled,
  onBackupLifecycle,
  onDisclosure,
  onDisclosureUrl,
  onExportExpiry,
}: {
  draft: DraftState;
  disabled: boolean;
  onBackupLifecycle: (value: BackupLifecycle) => void;
  onDisclosure: (value: ProviderRetentionDisclosure) => void;
  onDisclosureUrl: (value: string) => void;
  onExportExpiry: (value: string) => void;
}) {
  const backupGroup = useId();
  const disclosureGroup = useId();
  const urlId = useId();
  const expiryId = useId();
  const expirySeconds = Number.parseInt(draft.exportExpiryMinutes, 10);
  const expiryValid =
    Number.isSafeInteger(expirySeconds) &&
    expirySeconds * SECONDS_PER_MINUTE >= MIN_EXPORT_EXPIRY_SECONDS &&
    expirySeconds * SECONDS_PER_MINUTE <= MAX_EXPORT_EXPIRY_SECONDS;
  return (
    <Surface ariaLabel="Backup lifecycle, provider retention, and export expiry">
      <SurfaceHeader
        eyebrow="DELETION PROPAGATION AND DISCLOSURE"
        title="Backups, provider retention, and export expiry"
        description="How a deletion reaches backup copies, what is said about data Lumi does not hold, and how long a packaged export stays downloadable."
      />
      <div className="space-y-5 px-5 py-4">
        <fieldset disabled={disabled}>
          <legend className="text-sm font-semibold text-[var(--civic-navy)]">
            Backup lifecycle
          </legend>
          <div className="mt-2 space-y-2">
            {(["platform_35_day_expiry", "platform_no_backup"] as const).map((value) => {
              const copy = BACKUP_LIFECYCLE_COPY[value];
              const inputId = `${backupGroup}-${value}`;
              return (
                <label
                  key={value}
                  htmlFor={inputId}
                  className="flex cursor-pointer items-start gap-3 rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-3"
                >
                  <input
                    type="radio"
                    id={inputId}
                    name={`${backupGroup}-backup`}
                    className="mt-1 size-4 shrink-0 accent-[var(--lumi-blue)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
                    checked={draft.backupLifecycle === value}
                    onChange={() => onBackupLifecycle(value)}
                  />
                  <span>
                    <span className="block text-sm font-medium text-[var(--civic-navy)]">
                      {copy.label}
                    </span>
                    <span className="mt-0.5 block text-xs leading-5 text-[var(--muted-strong)]">
                      {copy.body}
                    </span>
                    <span className="mt-0.5 block text-xs text-[var(--muted)]">{copy.doesNot}</span>
                  </span>
                </label>
              );
            })}
          </div>
        </fieldset>

        <fieldset disabled={disabled}>
          <legend className="text-sm font-semibold text-[var(--civic-navy)]">
            Upstream provider retention
          </legend>
          <p className="mt-1 text-xs leading-5 text-[var(--muted-strong)]">
            This is a disclosure about data Lumi does not own. It is never a Lumi control, and no
            option here makes Lumi able to delete provider-held data.
          </p>
          <div className="mt-2 space-y-2">
            {(["external_policy", "linked_policy"] as const).map((value) => {
              const copy = PROVIDER_DISCLOSURE_COPY[value];
              const inputId = `${disclosureGroup}-${value}`;
              return (
                <label
                  key={value}
                  htmlFor={inputId}
                  className="flex cursor-pointer items-start gap-3 rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-3"
                >
                  <input
                    type="radio"
                    id={inputId}
                    name={`${disclosureGroup}-disclosure`}
                    className="mt-1 size-4 shrink-0 accent-[var(--lumi-blue)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
                    checked={draft.disclosure === value}
                    onChange={() => onDisclosure(value)}
                  />
                  <span>
                    <span className="block text-sm font-medium text-[var(--civic-navy)]">
                      {copy.label}
                    </span>
                    <span className="mt-0.5 block text-xs leading-5 text-[var(--muted-strong)]">
                      {copy.body}
                    </span>
                  </span>
                </label>
              );
            })}
          </div>
          {draft.disclosure === "linked_policy" ? (
            <div className="mt-3">
              <label htmlFor={urlId} className="text-xs font-medium text-[var(--muted-strong)]">
                Provider policy link (https only)
              </label>
              <input
                id={urlId}
                className={inputClass}
                type="url"
                inputMode="url"
                placeholder="https://provider.example/retention"
                value={draft.disclosureUrl}
                onChange={(event) => onDisclosureUrl(event.target.value)}
                aria-describedby={`${urlId}-hint`}
              />
              <p id={`${urlId}-hint`} className="mt-1 text-xs leading-5 text-[var(--muted)]">
                The server refuses a non-https link. The link is shown to the reader as a reference;
                it grants no control over the provider's retention.
              </p>
            </div>
          ) : null}
          <p className="mt-3 text-xs leading-5 text-[var(--muted)]">{BYOK_NOTE}</p>
        </fieldset>

        <div>
          <label htmlFor={expiryId} className="text-sm font-semibold text-[var(--civic-navy)]">
            Default export artifact expiry
          </label>
          <p className="mt-1 text-xs leading-5 text-[var(--muted-strong)]">
            How long a packaged export stays downloadable. The default is 24 hours and the server
            accepts 5 minutes to 7 days; a longer artifact is refused so a tenant cannot turn an
            export into an archive.
          </p>
          <input
            id={expiryId}
            className={inputClass}
            type="number"
            min={5}
            max={10_080}
            step={5}
            inputMode="numeric"
            value={draft.exportExpiryMinutes}
            onChange={(event) => onExportExpiry(event.target.value)}
            aria-describedby={`${expiryId}-hint`}
          />
          <p
            id={`${expiryId}-hint`}
            className={`mt-1 text-xs leading-5 ${expiryValid ? "text-[var(--muted)]" : "font-medium text-[var(--danger)]"}`}
          >
            {expiryValid
              ? `${formatWindow(expirySeconds * SECONDS_PER_MINUTE)}. Download grants are shorter still and are re-minted on every use.`
              : "Enter between 5 and 10,080 minutes. The field is left unchanged until the value is in range."}
          </p>
        </div>
      </div>
    </Surface>
  );
}

function LegalHoldSection({
  policy,
  canManage,
  busy,
  reason,
  releasedBy,
  onReasonChange,
  onReleasedByChange,
  onPlace,
}: {
  policy: DataGovernancePolicy;
  canManage: boolean;
  busy: boolean;
  reason: string;
  releasedBy: string;
  onReasonChange: (value: string) => void;
  onReleasedByChange: (value: string) => void;
  onPlace: () => void;
}) {
  if (policy.legal_hold) return null;
  return (
    <Surface ariaLabel="Legal hold">
      <SurfaceHeader
        eyebrow="PRESERVATION"
        title="Place a legal hold"
        description="A hold suspends expiry and deletion for the records in this organization. It preserves records that would otherwise expire, and it is released only by an audited, attributed action."
      />
      <div className="space-y-3 px-5 py-4">
        <p className="text-xs leading-5 text-[var(--muted)]">
          A hold applies to this organization only. It is not a tenant-wide platform switch, and it
          does not reach data Lumi does not hold.
        </p>
        {canManage ? (
          <>
            <div>
              <label
                htmlFor="legal-hold-reason"
                className="text-xs font-medium text-[var(--muted-strong)]"
              >
                Reason
              </label>
              <textarea
                id="legal-hold-reason"
                className={`${inputClass} min-h-20`}
                value={reason}
                maxLength={2_000}
                onChange={(event) => onReasonChange(event.target.value)}
                placeholder="For example: pending litigation over account records"
              />
            </div>
            <div>
              <label
                htmlFor="legal-hold-released-by"
                className="text-xs font-medium text-[var(--muted-strong)]"
              >
                Releasing principal (required to release later)
              </label>
              <input
                id="legal-hold-released-by"
                className={inputClass}
                value={releasedBy}
                maxLength={64}
                autoComplete="off"
                onChange={(event) => onReleasedByChange(event.target.value)}
                placeholder="usr_…"
              />
              <p className="mt-1 text-xs leading-5 text-[var(--muted)]">
                The server refuses an unattributed release. The principal you enter here is what a
                later release will be recorded against.
              </p>
            </div>
            <button type="button" className={dangerButtonClass} onClick={onPlace} disabled={busy}>
              Place a legal hold…
            </button>
          </>
        ) : (
          <Notice tone="info">
            Your current role can read this policy but not place a hold. Placing one is a
            `data.manage` action and the server enforces it on every write.
          </Notice>
        )}
      </div>
    </Surface>
  );
}
