import { Dialog } from "@base-ui/react/dialog";
import { useId, useMemo, useRef, useState } from "react";

import { presentApiError } from "@/lib/errors";

import {
  approvalToActivity,
  isAlreadyResolvedError,
  isApprovalExpired,
  isApprovalExpiredError,
  type ApprovalDecision,
  type ApprovalRequest,
  type ToolActivity,
} from "./helpers";
import {
  ApprovalStatusPill,
  RiskBadge,
  StatusPill,
  ToolCode,
  ToolDate,
  ToolEmpty,
  ToolError,
  ToolLoading,
  ToolNotice,
  ToolPanel,
  ToolPanelHeader,
  ToolPermission,
  dangerButtonClass,
  inputClass,
  primaryButtonClass,
  secondaryButtonClass,
} from "./ui";

export interface ResolveApprovalInput {
  approval: ApprovalRequest;
  decision: ApprovalDecision;
  idempotencyKey: string;
  reason?: string;
}

export type ResolveApprovalHandler = (
  input: ResolveApprovalInput,
) => Promise<ApprovalRequest | void>;

export interface ApprovalQueueProps {
  approvals?: ApprovalRequest[];
  loading?: boolean;
  error?: unknown;
  permissionDenied?: boolean;
  canResolve?: boolean;
  onResolve?: ResolveApprovalHandler;
  onRetry?: () => void;
  onRefresh?: () => void | Promise<void>;
  recentActivity?: ToolActivity[] | undefined;
  recentEvents?: ToolActivity[] | undefined;
}

interface DialogState {
  approval: ApprovalRequest;
  decision: ApprovalDecision;
}

export function ApprovalQueue({
  approvals = [],
  loading = false,
  error,
  permissionDenied = false,
  canResolve = false,
  onResolve,
  onRetry,
  onRefresh,
  recentActivity,
  recentEvents,
}: ApprovalQueueProps) {
  const [dialog, setDialog] = useState<DialogState | null>(null);
  const [reviewed, setReviewed] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const idempotencyKeys = useRef<Record<string, string>>({});

  const pending = useMemo(
    () =>
      approvals.filter((approval) => approval.status === "pending" && !isApprovalExpired(approval)),
    [approvals],
  );
  const expiredPending = useMemo(
    () =>
      approvals.filter((approval) => approval.status === "pending" && isApprovalExpired(approval)),
    [approvals],
  );
  const activity = useMemo(() => {
    const suppliedActivity = recentActivity ?? recentEvents;
    if (suppliedActivity) return suppliedActivity.slice(0, 20);
    return approvals
      .map(approvalToActivity)
      .filter((item): item is ToolActivity => item !== null)
      .sort((left, right) => Date.parse(right.occurred_at) - Date.parse(left.occurred_at))
      .slice(0, 20);
  }, [approvals, recentActivity, recentEvents]);

  function openDecision(approval: ApprovalRequest, decision: ApprovalDecision) {
    if (!canResolve || !onResolve || approval.status !== "pending" || isApprovalExpired(approval)) {
      return;
    }
    if (!approval.tool_fingerprint) {
      setNotice("This request has no verifiable tool fingerprint and cannot be resolved here.");
      return;
    }
    setActionError(null);
    setNotice(null);
    setReviewed(false);
    setReason("");
    setDialog({ approval, decision });
  }

  function closeDialog() {
    if (busy) return;
    setDialog(null);
    setReviewed(false);
    setReason("");
    setActionError(null);
  }

  async function confirmDecision() {
    if (!dialog || !onResolve || !canResolve || !reviewed || busy) return;
    const operation = `${dialog.approval.id}:${dialog.decision}`;
    idempotencyKeys.current[operation] ??= crypto.randomUUID();
    setBusy(true);
    setActionError(null);
    try {
      const result = await onResolve({
        approval: dialog.approval,
        decision: dialog.decision,
        idempotencyKey: idempotencyKeys.current[operation],
        ...(dialog.decision === "denied" && reason.trim() ? { reason: reason.trim() } : {}),
      });
      if (result?.status === "expired") {
        setNotice(
          "The approval window expired. The server closed the request without authorizing the call.",
        );
      } else if (result && result.status !== dialog.decision) {
        setNotice(
          `The server resolved this request as ${result.status}. No client override was applied.`,
        );
      } else {
        setNotice(
          dialog.decision === "approved"
            ? "The exact tool call was approved. The execution host must still validate the binding before proceeding."
            : "The exact tool call was denied. It cannot proceed under this approval request.",
        );
      }
      setDialog(null);
      setReviewed(false);
      setReason("");
    } catch (requestError) {
      if (isAlreadyResolvedError(requestError) || isApprovalExpiredError(requestError)) {
        setNotice(
          isApprovalExpiredError(requestError)
            ? "The approval window expired. The server closed the request without authorizing the call."
            : "This approval was already resolved. The current server state is authoritative.",
        );
        if (onRefresh) void Promise.resolve(onRefresh()).catch(() => undefined);
        setDialog(null);
        setReviewed(false);
        setReason("");
      } else {
        setActionError(requestError);
      }
    } finally {
      setBusy(false);
    }
  }

  if (permissionDenied) {
    return (
      <ToolPanel ariaLabel="Approval queue">
        <ToolPanelHeader
          title="Approval queue"
          description="Exact tool, fingerprint, run, and redacted argument bindings that need a human decision."
        />
        <div className="p-5">
          <ToolPermission message="Your current organization role cannot view approval requests." />
        </div>
      </ToolPanel>
    );
  }
  if (loading) {
    return (
      <ToolPanel ariaLabel="Approval queue">
        <ToolPanelHeader
          title="Approval queue"
          description="Exact tool, fingerprint, run, and redacted argument bindings that need a human decision."
        />
        <ToolLoading label="Loading approval requests…" rows={4} />
      </ToolPanel>
    );
  }
  if (error) {
    return (
      <ToolPanel ariaLabel="Approval queue">
        <ToolPanelHeader
          title="Approval queue"
          description="Exact tool, fingerprint, run, and redacted argument bindings that need a human decision."
        />
        <div className="p-5">
          <ToolError error={error} onRetry={onRetry} />
        </div>
      </ToolPanel>
    );
  }

  return (
    <div className="space-y-5">
      <ToolPanel ariaLabel="Approval queue">
        <ToolPanelHeader
          title="Approval queue"
          description="Exact tool, fingerprint, run, and redacted argument bindings that need a human decision."
          action={
            <StatusPill tone={pending.length > 0 ? "warning" : "success"}>
              {pending.length} pending
            </StatusPill>
          }
        />
        <div className="space-y-4 p-5">
          <ToolNotice tone="info">
            Approval is a server decision for one exact binding. It does not change organization
            policy, reveal secrets, or provide a client-side force-allow control.
          </ToolNotice>
          {notice ? <ToolNotice tone="success">{notice}</ToolNotice> : null}
          {actionError && !dialog ? <ToolError error={actionError} /> : null}
          {!canResolve ? (
            <ToolNotice tone="warning">
              You can inspect approval history, but your current role cannot resolve requests. The
              API remains the authority for this control.
            </ToolNotice>
          ) : null}
          {expiredPending.length > 0 ? (
            <ToolNotice tone="warning">
              {expiredPending.length} pending request{expiredPending.length === 1 ? " is" : "s are"}{" "}
              past the displayed expiry and cannot be approved from this queue.
            </ToolNotice>
          ) : null}
          {pending.length === 0 ? (
            <ToolEmpty
              title="No pending approvals"
              description="Privileged actions that require a decision will appear here with their exact server binding."
            />
          ) : (
            <ul className="space-y-3">
              {pending.map((approval) => (
                <ApprovalCard
                  key={approval.id}
                  approval={approval}
                  canResolve={
                    canResolve && Boolean(onResolve) && Boolean(approval.tool_fingerprint)
                  }
                  onDecision={openDecision}
                />
              ))}
            </ul>
          )}
        </div>
      </ToolPanel>

      <RecentApprovalActivity activity={activity} />

      {dialog ? (
        <ApprovalDecisionDialog
          state={dialog}
          canResolve={canResolve}
          reviewed={reviewed}
          reason={reason}
          busy={busy}
          error={actionError}
          onReviewedChange={setReviewed}
          onReasonChange={setReason}
          onConfirm={() => void confirmDecision()}
          onClose={closeDialog}
        />
      ) : null}
    </div>
  );
}

function ApprovalCard({
  approval,
  canResolve,
  onDecision,
}: {
  approval: ApprovalRequest;
  canResolve: boolean;
  onDecision: (approval: ApprovalRequest, decision: ApprovalDecision) => void;
}) {
  const expired = isApprovalExpired(approval);
  return (
    <li className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <p className="font-medium text-[var(--civic-navy)]">{approval.tool_id}</p>
            <ApprovalStatusPill status={expired ? "expired" : approval.status} />
            <StatusPill tone="neutral">
              {approval.approval_mode === "per_use" ? "Per-use" : "Session"}
            </StatusPill>
          </div>
          <p className="mt-1 text-xs text-[var(--muted)]">
            Requested <ToolDate value={approval.requested_at} /> · expires{" "}
            <ToolDate value={approval.expires_at} />
          </p>
        </div>
        {canResolve && !expired ? (
          <div className="flex shrink-0 flex-wrap gap-2">
            <button
              type="button"
              className={primaryButtonClass}
              onClick={() => onDecision(approval, "approved")}
              aria-label={`Approve exact call for ${approval.tool_id}`}
            >
              Approve
            </button>
            <button
              type="button"
              className={dangerButtonClass}
              onClick={() => onDecision(approval, "denied")}
              aria-label={`Deny exact call for ${approval.tool_id}`}
            >
              Deny
            </button>
          </div>
        ) : null}
      </div>

      <dl className="mt-4 grid gap-3 text-xs sm:grid-cols-2 lg:grid-cols-4">
        <BindingFact label="Tool ID" value={<ToolCode>{approval.tool_id}</ToolCode>} />
        <BindingFact
          label="Tool fingerprint"
          value={
            approval.tool_fingerprint ? (
              <ToolCode>{approval.tool_fingerprint}</ToolCode>
            ) : (
              <span className="text-[var(--danger)]">Unbound — cannot resolve</span>
            )
          }
        />
        <BindingFact label="Run ID" value={<ToolCode>{approval.run_id}</ToolCode>} />
        <BindingFact label="Tool call ID" value={<ToolCode>{approval.tool_call_id}</ToolCode>} />
      </dl>
      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-[var(--muted)]">
        <RiskBadge riskClass={approval.risk_class} />
        <span>Arguments are shown only as the server&apos;s bounded, redacted summary.</span>
      </div>
      <div className="mt-2 rounded-md border border-[var(--border)] bg-[var(--panel)] px-3 py-2">
        <p className="text-xs font-medium text-[var(--muted)]">Arguments summary</p>
        <p className="mt-1 break-words text-sm text-[var(--civic-navy)]">
          {approval.arguments_summary}
        </p>
      </div>
      {!approval.tool_fingerprint ? (
        <p className="mt-3 text-xs font-medium text-[var(--danger)]">
          The server did not return a fingerprint, so this request is not safe to resolve.
        </p>
      ) : null}
    </li>
  );
}

function BindingFact({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[var(--muted)]">{label}</dt>
      <dd className="mt-1">{value}</dd>
    </div>
  );
}

function ApprovalDecisionDialog({
  state,
  canResolve,
  reviewed,
  reason,
  busy,
  error,
  onReviewedChange,
  onReasonChange,
  onConfirm,
  onClose,
}: {
  state: DialogState;
  canResolve: boolean;
  reviewed: boolean;
  reason: string;
  busy: boolean;
  error: unknown;
  onReviewedChange: (value: boolean) => void;
  onReasonChange: (value: string) => void;
  onConfirm: () => void;
  onClose: () => void;
}) {
  const reasonId = useId();
  const approving = state.decision === "approved";
  const title = approving ? "Approve exact tool call" : "Deny exact tool call";
  return (
    <Dialog.Root
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <Dialog.Portal>
        <Dialog.Backdrop className="fixed inset-0 z-40 bg-[var(--civic-navy)]/35" />
        <Dialog.Viewport className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto p-4">
          <Dialog.Popup className="my-auto w-full max-w-xl rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)] sm:p-6">
            <Dialog.Title className="text-lg font-semibold tracking-[-0.02em] text-[var(--civic-navy)]">
              {title}
            </Dialog.Title>
            <Dialog.Description className="mt-2 text-sm leading-5 text-[var(--muted-strong)]">
              {approving
                ? "This approves one exact server-bound call. It does not broaden policy or authorize a different tool, fingerprint, run, or argument set."
                : "This prevents one exact server-bound call from proceeding. It does not change the organization policy or reveal the underlying arguments."}
            </Dialog.Description>

            <div className="mt-5 rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-4">
              <p className="text-xs font-semibold tracking-[0.08em] text-[var(--muted)]">
                EXACT BINDING
              </p>
              <dl className="mt-3 grid gap-3 text-xs sm:grid-cols-2">
                <BindingFact
                  label="Tool ID"
                  value={<ToolCode>{state.approval.tool_id}</ToolCode>}
                />
                <BindingFact
                  label="Fingerprint"
                  value={<ToolCode>{state.approval.tool_fingerprint ?? "Unavailable"}</ToolCode>}
                />
                <BindingFact label="Run ID" value={<ToolCode>{state.approval.run_id}</ToolCode>} />
                <BindingFact
                  label="Tool call ID"
                  value={<ToolCode>{state.approval.tool_call_id}</ToolCode>}
                />
                <BindingFact
                  label="Risk class"
                  value={<RiskBadge riskClass={state.approval.risk_class} />}
                />
                <BindingFact
                  label="Approval mode"
                  value={state.approval.approval_mode === "per_use" ? "Per-use" : "Session"}
                />
              </dl>
              <div className="mt-3 border-t border-[var(--border)] pt-3">
                <p className="text-xs text-[var(--muted)]">Redacted arguments summary</p>
                <p className="mt-1 break-words text-sm text-[var(--civic-navy)]">
                  {state.approval.arguments_summary}
                </p>
              </div>
            </div>

            <label className="mt-5 flex cursor-pointer items-start gap-3 rounded-lg border border-[var(--border)] p-3 text-sm leading-5 text-[var(--civic-navy)]">
              <input
                type="checkbox"
                checked={reviewed}
                onChange={(event) => onReviewedChange(event.target.checked)}
                className="mt-0.5 size-4 shrink-0 accent-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
              />
              <span>
                I reviewed the exact tool ID, fingerprint, run, and redacted argument summary above.
              </span>
            </label>

            {!approving ? (
              <label
                className="mt-4 block text-sm font-medium text-[var(--civic-navy)]"
                htmlFor={reasonId}
              >
                Reason <span className="font-normal text-[var(--muted)]">(optional)</span>
                <textarea
                  id={reasonId}
                  value={reason}
                  onChange={(event) => onReasonChange(event.target.value)}
                  maxLength={512}
                  rows={3}
                  className={inputClass}
                  placeholder="Explain why this exact call is denied"
                />
              </label>
            ) : null}

            {error ? (
              <div className="mt-4">
                <ToolError error={error} />
              </div>
            ) : null}

            <div className="mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
              <Dialog.Close type="button" className={secondaryButtonClass} disabled={busy}>
                Cancel
              </Dialog.Close>
              <button
                type="button"
                className={approving ? primaryButtonClass : dangerButtonClass}
                onClick={onConfirm}
                disabled={!canResolve || !reviewed || busy || !state.approval.tool_fingerprint}
              >
                {busy ? "Saving decision…" : approving ? "Confirm approval" : "Confirm denial"}
              </button>
            </div>
            {error ? (
              <p className="mt-3 text-xs leading-5 text-[var(--muted)]">
                Request ID: {presentApiError(error).requestId ?? "not available"}
              </p>
            ) : null}
          </Dialog.Popup>
        </Dialog.Viewport>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function RecentApprovalActivity({ activity }: { activity: ToolActivity[] }) {
  return (
    <ToolPanel ariaLabel="Recent approval activity">
      <ToolPanelHeader
        title="Recent approval activity"
        description="Resolved decisions remain visible as an append-only operational trail; no argument bodies are stored here."
        action={<StatusPill tone="neutral">{activity.length} recent</StatusPill>}
      />
      {activity.length === 0 ? (
        <ToolEmpty
          title="No resolved decisions"
          description="Approved, denied, expired, and cancelled approval decisions will remain visible here."
        />
      ) : (
        <ul className="divide-y divide-[var(--border)]">
          {activity.map((item) => (
            <li
              key={item.id}
              className="flex flex-col gap-2 px-5 py-3 sm:flex-row sm:items-center sm:justify-between"
            >
              <div className="min-w-0">
                <p className="text-sm font-medium text-[var(--civic-navy)]">{item.tool_id}</p>
                <p className="mt-1 text-xs text-[var(--muted)]">
                  Run <ToolCode>{item.run_id}</ToolCode>
                </p>
              </div>
              <div className="flex items-center gap-3">
                <StatusPill
                  tone={
                    item.kind === "approved"
                      ? "success"
                      : item.kind === "denied"
                        ? "danger"
                        : "warning"
                  }
                >
                  {item.kind === "approved"
                    ? "Approved"
                    : item.kind === "denied"
                      ? "Denied"
                      : item.kind === "expired"
                        ? "Expired"
                        : "Cancelled"}
                </StatusPill>
                <span className="text-xs text-[var(--muted)]">
                  <ToolDate value={item.occurred_at} />
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </ToolPanel>
  );
}
