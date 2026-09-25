import { useId, useState, type FormEvent } from "react";

import {
  assessPlanChange,
  DOWNGRADE_BLOCKED_COPY,
  DOWNGRADE_HONESTY_STATEMENT,
  type DowngradeAssessment,
} from "./downgrade";
import { humanizeStatus } from "./entitlements";
import {
  BillingError,
  BillingNotice,
  BillingPanel,
  BillingPanelHeader,
  BillingPill,
  dangerButtonClass,
  inputClass,
  primaryButtonClass,
  secondaryButtonClass,
} from "./ui";

export type PlanActionOutcome =
  | { kind: "idle" }
  | { kind: "busy"; label: string }
  | { kind: "done"; message: string }
  | { kind: "failed"; error: unknown };

export function PlanChangePanel({
  currentPlanKey,
  canManage,
  previewAvailable,
  preview,
  previewRequested,
  previewFailed,
  action,
  onPreview,
  onSubmitChange,
  onCancel,
  onOpenPortal,
  portalUnavailableReason,
}: {
  currentPlanKey: string;
  canManage: boolean;
  previewAvailable: boolean;
  preview: DowngradeAssessment | null;
  previewRequested: boolean;
  previewFailed: boolean;
  action: PlanActionOutcome;
  onPreview: (planKey: string) => void;
  onSubmitChange: (planKey: string) => void;
  onCancel: () => void;
  onOpenPortal: () => void;
  portalUnavailableReason: string | null;
}) {
  const [targetPlanKey, setTargetPlanKey] = useState("");
  const planFieldId = useId().replaceAll(":", "");
  const busy = action.kind === "busy";

  const assessment =
    preview && preview.targetPlanKey === targetPlanKey
      ? preview
      : assessPlanChange({
          preview: null,
          previewRequested,
          previewFailed,
          previewAvailable,
          currentPlanKey,
          targetPlanKey,
        });

  const canPreview = canManage && !busy && targetPlanKey.trim().length > 0;
  const canSubmit =
    canManage &&
    !busy &&
    targetPlanKey.trim().length > 0 &&
    previewAvailable &&
    assessment.blockedReason === null &&
    assessment.direction !== "unknown";

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    onSubmitChange(targetPlanKey.trim());
  }

  return (
    <BillingPanel ariaLabel="Plan change and cancellation">
      <BillingPanelHeader
        eyebrow="PLAN CHANGE"
        title="Change the plan or cancel"
        description="Plan selection happens in the provider portal or through a versioned change request. A downgrade is always previewed before it is submitted, and a change is never submitted when the server has not stated whether it is an upgrade or a downgrade."
        action={
          <BillingPill tone="info">Current plan: {humanizeStatus(currentPlanKey)}</BillingPill>
        }
      />

      <div className="space-y-5 p-5">
        {!canManage ? (
          <BillingNotice tone="info">
            Billing management is an owner or administrator action. This surface is read-only for
            your current role, and the server re-checks the `billing.manage` permission on every
            mutation regardless of what this browser shows.
          </BillingNotice>
        ) : null}

        <form onSubmit={submit} className="space-y-4">
          <label
            className="block text-sm font-medium text-[var(--civic-navy)]"
            htmlFor={planFieldId}
          >
            Target plan key
            <input
              id={planFieldId}
              value={targetPlanKey}
              onChange={(event) => setTargetPlanKey(event.target.value)}
              placeholder="starter"
              autoComplete="off"
              className={inputClass}
              disabled={!canManage || busy}
            />
          </label>
          <p className="text-xs leading-4 text-[var(--muted)]">
            A stable Lumi plan key. A payment-provider product or price identifier is never accepted
            here; the provider adapter maps the plan on the server side.
          </p>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              className={secondaryButtonClass}
              onClick={() => onPreview(targetPlanKey.trim())}
              disabled={!canPreview}
            >
              Preview this change
            </button>
            <button type="submit" className={primaryButtonClass} disabled={!canSubmit}>
              Submit plan change
            </button>
            <button
              type="button"
              className={secondaryButtonClass}
              onClick={onOpenPortal}
              disabled={!canManage || busy}
            >
              Open the provider portal
            </button>
          </div>
        </form>

        <AssessmentSummary assessment={assessment} previewAvailable={previewAvailable} />

        <BillingNotice tone="info">
          <p className="font-semibold">A plan change never deletes existing data.</p>
          <p className="mt-1">{DOWNGRADE_HONESTY_STATEMENT}</p>
          <p className="mt-1">{DOWNGRADE_BLOCKED_COPY}</p>
        </BillingNotice>

        {portalUnavailableReason ? (
          <BillingNotice tone="warning">
            <span className="font-semibold">The provider portal is unavailable.</span>{" "}
            {portalUnavailableReason}
          </BillingNotice>
        ) : null}

        {action.kind === "busy" ? <BillingNotice tone="info">{action.label}</BillingNotice> : null}
        {action.kind === "done" ? (
          <BillingNotice tone="success">{action.message}</BillingNotice>
        ) : null}
        {action.kind === "failed" ? <BillingError error={action.error} /> : null}

        <hr className="border-[var(--border)]" />

        <CancellationBlock canManage={canManage} busy={busy} onCancel={onCancel} />
      </div>
    </BillingPanel>
  );
}

function AssessmentSummary({
  assessment,
  previewAvailable,
}: {
  assessment: DowngradeAssessment;
  previewAvailable: boolean;
}) {
  if (!previewAvailable) {
    return (
      <BillingNotice tone="warning">
        <p className="font-semibold">A downgrade cannot be submitted from this browser.</p>
        <p className="mt-1">
          A downgrade that would leave this organization over a limit must be previewed before it is
          submitted, and this deployment does not publish a downgrade preview. Make the change in
          the provider portal, which shows the exact consequences first. Upgrades and lateral
          changes do not need a preview.
        </p>
      </BillingNotice>
    );
  }
  if (assessment.blockedReason) {
    return (
      <BillingNotice tone="warning">
        <p className="font-semibold">Nothing has been submitted.</p>
        <p className="mt-1">{assessment.blockedReason}</p>
      </BillingNotice>
    );
  }
  if (assessment.targetPlanKey.length === 0) return null;
  return (
    <BillingNotice tone={assessment.isDowngrade ? "warning" : "info"}>
      <p className="font-semibold">
        The server states this is a {humanizeStatus(assessment.direction)} from{" "}
        {assessment.currentPlanKey ?? "the current plan"} to {assessment.targetPlanKey}.
      </p>
      {assessment.serverReason ? <p className="mt-1">{assessment.serverReason}</p> : null}
    </BillingNotice>
  );
}

function CancellationBlock({
  canManage,
  busy,
  onCancel,
}: {
  canManage: boolean;
  busy: boolean;
  onCancel: () => void;
}) {
  const [armed, setArmed] = useState(false);
  const confirmId = useId().replaceAll(":", "");

  return (
    <section aria-label="Cancel subscription" className="space-y-3">
      <div>
        <h3 className="text-sm font-semibold text-[var(--civic-navy)]">Cancel the subscription</h3>
        <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--muted-strong)]">
          Cancellation is requested through the provider adapter. Historical data, audit records,
          and exports are all retained. Cancellation is terminal for this subscription row: it does
          not silently reactivate, and returning requires a new subscription and provider account
          binding.
        </p>
      </div>

      {armed ? (
        <div
          role="alert"
          className="rounded-lg border border-[var(--danger)]/40 bg-[var(--danger)]/5 p-4 text-sm"
        >
          <p className="font-semibold text-[var(--danger)]">
            Request cancellation for this organization?
          </p>
          <p id={confirmId} className="mt-1 leading-5 text-[var(--muted-strong)]">
            No work, history, or data is deleted. New work stops once the cancellation is applied,
            and this subscription row will not reactivate on its own.
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              className={dangerButtonClass}
              onClick={() => {
                setArmed(false);
                onCancel();
              }}
              disabled={busy}
              aria-describedby={confirmId}
            >
              Request cancellation
            </button>
            <button
              type="button"
              className={secondaryButtonClass}
              onClick={() => setArmed(false)}
              disabled={busy}
            >
              Keep the subscription
            </button>
          </div>
        </div>
      ) : (
        <button
          type="button"
          className={dangerButtonClass}
          onClick={() => setArmed(true)}
          disabled={!canManage || busy}
        >
          Cancel subscription…
        </button>
      )}
    </section>
  );
}
