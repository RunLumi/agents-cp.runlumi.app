/**
 * Deletion workflows: job state, per-step progress by data class, the parked
 * `needs_attention` reason, the explicit resume, and the account-scoped
 * request.
 *
 * Frozen contract: `GET /api/v1/orgs/{org_id}/deletions`,
 * `GET /api/v1/orgs/{org_id}/deletions/{deletion_id}`,
 * `POST /api/v1/orgs/{org_id}/deletions/{deletion_id}/resume`, and
 * `/api/v1/me/data/deletion{,/cancel}`, as implemented in
 * `apps/api/src/routes/data_governance.rs`.
 *
 * P06-CR-003 is respected: this module never requests an organization
 * deletion. The P02 organization lifecycle route is the sole request, and the
 * panel only observes and resumes the job it created. A wiring slot is exposed
 * for the coordinator so the button can live in organization settings without
 * this panel inventing a second route.
 *
 * The honesty rules are structural, not stylistic:
 *
 * * a step is only ever called a deletion when its state is `succeeded` and its
 *   store is Lumi-owned (`presentDeletionStep`);
 * * a skipped step always states its reason;
 * * provider and device data are rendered in a separate disclosure block that
 *   never appears inside a success list;
 * * the certificate states coverage, so a completed job is not drawn as if it
 *   covered every system.
 */

import { useEffect, useId, useMemo, useState } from "react";

import {
  ACCOUNT_DELETION_PREREQUISITES,
  CERTIFICATE_NOTE,
  COVERAGE_NOTE,
  PERSONAL_DELETION_COPY,
  REAUTH_NOTE,
  RESUME_COPY,
  deletionStateCopy,
  jobFailureCopy,
  mergeDisclosures,
  needsAttentionCopy,
  presentDeletionStep,
  readClassResults,
  readReferenceCoverage,
  tallySteps,
} from "./contracts";
import {
  DELETION_CONFIRMATION_PHRASE,
  mintReauthGrant,
  type DataGovernanceApi,
  type DeletionJob,
  type Page,
  type PersonalDeletionStatus,
} from "./api";
import {
  Code,
  ConfirmDialog,
  DateTime,
  DefinitionRow,
  EmptyState,
  ErrorNotice,
  Notice,
  PaginationFooter,
  Pill,
  SeverityRail,
  Surface,
  SurfaceHeader,
  dangerButtonClass,
  inputClass,
  primaryButtonClass,
  secondaryButtonClass,
} from "./ui";

// ---------------------------------------------------------------------------
// Organization deletion
// ---------------------------------------------------------------------------

export interface OrgDeletionWorkflowProps {
  orgId: string;
  api: DataGovernanceApi;
  page: Page<DeletionJob>;
  detail: DeletionJob | null;
  detailStatus: "idle" | "loading" | "ready" | "error";
  detailError: unknown;
  status: "loading" | "ready" | "error" | "permission";
  error: unknown;
  refreshing: boolean;
  canDelete: boolean;
  onRefresh: () => void;
  onLoadMore: () => void;
  onSelect: (deletionId: string) => void;
  onResumed: (job: DeletionJob) => void;
  /**
   * Wiring slot for the P02 organization lifecycle request. The panel never
   * calls a deletion request route itself; the coordinator passes the shell's
   * existing reauthenticated lifecycle action here, or nothing at all.
   */
  onRequestOrganizationDeletion?: (orgId: string) => void;
}

export function OrgDeletionWorkflow({
  orgId,
  api,
  page,
  detail,
  detailStatus,
  detailError,
  status,
  error,
  refreshing,
  canDelete,
  onRefresh,
  onLoadMore,
  onSelect,
  onResumed,
  onRequestOrganizationDeletion,
}: OrgDeletionWorkflowProps) {
  const [resumeDialog, setResumeDialog] = useState(false);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const disclosures = useMemo(
    () => mergeDisclosures(detail?.disclosures ?? page.items[0]?.disclosures),
    [detail, page.items],
  );

  async function resume() {
    if (detail === null) return;
    setBusy(true);
    setActionError(null);
    try {
      const next = await api.resumeDeletion(orgId, detail.id, detail.version, crypto.randomUUID());
      setResumeDialog(false);
      onResumed(next);
      setNotice(
        `The resume was accepted for ${next.id}. It is now ${next.state}; the audit event records who authorized it.`,
      );
    } catch (resumeError) {
      setActionError(resumeError);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Surface ariaLabel="Organization deletion workflows">
      <SurfaceHeader
        eyebrow="DELETION WORKFLOWS"
        title="Organization deletion"
        description="A deletion is a durable, resumable job that records one outcome per data class and reference. The organization lifecycle request is the only way to start one; this page observes the job and can resume it."
        action={
          <button
            type="button"
            className={secondaryButtonClass}
            onClick={onRefresh}
            disabled={refreshing}
          >
            {refreshing ? "Refreshing…" : "Refresh"}
          </button>
        }
      />
      <div className="space-y-4 px-5 py-4">
        {status === "loading" ? (
          <p className="text-sm text-[var(--muted-strong)]" role="status" aria-busy="true">
            Loading deletion workflows…
          </p>
        ) : null}
        {status === "error" ? <ErrorNotice error={error} onRetry={onRefresh} /> : null}
        {status === "permission" ? (
          <Notice tone="info">
            Your current membership cannot read the organization deletion workflows.
          </Notice>
        ) : null}

        {status === "ready" && page.items.length === 0 ? (
          <EmptyState
            title="No deletion job exists for this organization"
            copy="Requesting organization deletion is a separate, reauthenticated organization-lifecycle action. It moves the organization to pending deletion and creates one job; there is no second request route here."
          />
        ) : null}

        {page.items.length > 0 ? (
          <ul className="divide-y divide-[var(--border)] rounded-lg border border-[var(--border)]">
            {page.items.map((job) => {
              const copy = deletionStateCopy(job.state);
              const selected = detail?.id === job.id;
              return (
                <li key={job.id} className="px-3 py-3">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <Pill tone={copy.tone}>{copy.label}</Pill>
                        <Code>{job.id}</Code>
                        {job.fenced ? <Pill tone="warning">New work fenced</Pill> : null}
                        {job.legal_hold ? <Pill tone="warning">Legal hold</Pill> : null}
                      </div>
                      <p className="mt-1 text-xs leading-5 text-[var(--muted-strong)]">
                        {copy.body}
                      </p>
                      <p className="mt-1 text-xs text-[var(--muted)]">
                        attempt {job.attempt} · version {job.version} · requested{" "}
                        <DateTime value={job.created_at} />
                        {job.cutoff_at ? (
                          <>
                            {" "}
                            · cutoff <DateTime value={job.cutoff_at} />
                          </>
                        ) : null}
                      </p>
                      {job.failure_code !== null ? (
                        <p className="mt-1 text-xs leading-5 text-[var(--danger)]">
                          <Code>{job.failure_code}</Code>
                          {jobFailureCopy(job.failure_code)?.body ?? ""}
                        </p>
                      ) : null}
                    </div>
                    <button
                      type="button"
                      className={selected ? primaryButtonClass : secondaryButtonClass}
                      onClick={() => onSelect(job.id)}
                      aria-expanded={selected}
                    >
                      {selected ? "Showing steps" : "Show steps"}
                    </button>
                  </div>
                  {job.state === "needs_attention" ? <NeedsAttention job={job} /> : null}
                </li>
              );
            })}
          </ul>
        ) : null}

        {status === "ready" ? (
          <PaginationFooter
            loaded={page.items.length}
            hasMore={page.has_more}
            loading={refreshing}
            onLoadMore={onLoadMore}
            noun="deletion"
          />
        ) : null}

        {notice ? (
          <Notice tone="success">
            <p>{notice}</p>
          </Notice>
        ) : null}
        {actionError !== null ? <ErrorNotice error={actionError} /> : null}

        {detailStatus === "loading" ? (
          <p className="text-sm text-[var(--muted-strong)]" role="status" aria-busy="true">
            Loading the step list…
          </p>
        ) : null}
        {detailStatus === "error" ? <ErrorNotice error={detailError} onRetry={onRefresh} /> : null}
        {detail ? <DeletionDetail job={detail} /> : null}

        {detail !== null && detail.resumable ? (
          <div className="space-y-2">
            <button
              type="button"
              className={dangerButtonClass}
              onClick={() => {
                setActionError(null);
                setResumeDialog(true);
              }}
              disabled={!canDelete}
            >
              Resume this deletion job…
            </button>
            {canDelete ? null : (
              <p className="text-xs leading-5 text-[var(--muted)]">
                Resuming is a `data.delete` action. The server refuses it without that permission,
                so the control is offered read-only rather than implying the role has it.
              </p>
            )}
          </div>
        ) : null}

        <DisclosureList items={disclosures} title="What this workflow does not delete" />

        {onRequestOrganizationDeletion ? (
          <div className="space-y-2">
            <button
              type="button"
              className={dangerButtonClass}
              onClick={() => onRequestOrganizationDeletion(orgId)}
            >
              Start organization deletion…
            </button>
            <p className="text-xs leading-5 text-[var(--muted)]">
              The lifecycle request reauthenticates you, requires a typed confirmation, moves the
              organization to <code className="font-mono">pending_deletion</code>, and
              transactionally creates exactly one job. After the cutoff, automation dispatch,
              webhook and notification fan-out, billing writes, export creation, and deletion
              retries are fenced.
            </p>
          </div>
        ) : (
          <p className="text-xs leading-5 text-[var(--muted)]">
            Organization deletion is requested from organization settings. This page only observes
            the resulting job and can resume it; it never creates a second deletion request.
          </p>
        )}
      </div>

      <ConfirmDialog
        open={resumeDialog}
        eyebrow="RESUME DELETION JOB"
        title={RESUME_COPY.title}
        body={RESUME_COPY.body}
        confirmLabel={RESUME_COPY.confirmLabel}
        cancelLabel={RESUME_COPY.cancelLabel}
        busyLabel={RESUME_COPY.busyLabel}
        busy={busy}
        destructive
        onClose={() => setResumeDialog(false)}
        onConfirm={() => void resume()}
      />
    </Surface>
  );
}

function NeedsAttention({ job }: { job: DeletionJob }) {
  const copy = needsAttentionCopy(job.failure_code);
  return (
    <div className="mt-3 rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/5 p-3">
      <p className="text-sm font-semibold text-[var(--civic-navy)]">{copy.label}</p>
      <p className="mt-1 text-xs leading-5 text-[var(--muted-strong)]">{copy.body}</p>
      <p className="mt-1 text-xs leading-5 text-[var(--muted-strong)]">{copy.resumeNote}</p>
      {job.failure_code !== null ? (
        <p className="mt-1 text-xs text-[var(--muted)]">
          Server reason <Code>{job.failure_code}</Code>
        </p>
      ) : null}
      {copy.resumeBlocked ? (
        <p className="mt-2 text-xs font-medium text-[var(--danger)]">
          A resume while the hold is active would be refused. Release the hold first, through the
          audited support or legal process.
        </p>
      ) : null}
    </div>
  );
}

export interface DeletionDetailProps {
  job: DeletionJob;
}

export function DeletionDetail({ job }: DeletionDetailProps) {
  const steps = job.steps ?? [];
  const tally = tallySteps(steps);
  const coverage = readReferenceCoverage(job.certificate?.class_results ?? {});
  const retained = job.certificate?.retained_legal_classes ?? [];
  const notLumiOwned = steps.filter(
    (step) => presentDeletionStep(step).ownership === "not_lumi_owned",
  );

  return (
    <div className="space-y-4">
      <SeverityRail severity={job.state === "needs_attention" ? "danger" : "warning"}>
        <SurfaceHeader
          eyebrow="STEP PROGRESS"
          title={`Steps for ${job.id}`}
          description="One row per data class and reference. A row is only called a deletion when the store is Lumi's and the step succeeded."
          action={
            <div className="flex flex-wrap gap-1.5">
              <Pill tone="success">{tally.deleted} deleted</Pill>
              <Pill tone="warning">{tally.skipped} skipped</Pill>
              <Pill tone="neutral">{tally.open} open</Pill>
            </div>
          }
        />
        <div className="space-y-3 px-5 py-4">
          {steps.length === 0 ? (
            <p className="text-sm leading-5 text-[var(--muted-strong)]">
              No step has been planned yet. A plan is not a deletion: until a step reaches a
              terminal state, nothing is known to be gone.
            </p>
          ) : (
            <ul className="divide-y divide-[var(--border)] rounded-lg border border-[var(--border)]">
              {steps.map((step) => {
                const presentation = presentDeletionStep(step);
                return (
                  <li key={step.id} className="px-3 py-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-[var(--civic-navy)]">
                          {step.data_class}
                        </p>
                        <p className="mt-0.5 text-xs text-[var(--muted)]">
                          {presentation.ownershipLabel}
                          {step.reference_kind === null
                            ? " · the server published a store this build does not recognize"
                            : ""}
                        </p>
                      </div>
                      <Pill tone={presentation.tone}>{presentation.stateLabel}</Pill>
                    </div>
                    <p className="mt-1 text-xs leading-5 text-[var(--muted-strong)]">
                      {presentation.claim}
                    </p>
                    {presentation.reason.length > 0 ? (
                      <p className="mt-1 text-xs leading-5 text-[var(--warning)]">
                        {presentation.reason}
                      </p>
                    ) : null}
                    <p className="mt-1 break-all text-xs text-[var(--muted)]">
                      <span className="font-medium">Opaque reference:</span> {step.object_reference}{" "}
                      (attempt {step.attempt}
                      {step.completed_at ? `, completed ${step.completed_at}` : ""})
                    </p>
                  </li>
                );
              })}
            </ul>
          )}

          {notLumiOwned.length > 0 ? (
            <div className="rounded-lg border border-[var(--warning)]/45 bg-[var(--warning)]/10 p-3">
              <p className="text-sm font-semibold text-[var(--civic-navy)]">
                Recorded, not deleted: {notLumiOwned.length} reference
                {notLumiOwned.length === 1 ? "" : "s"} outside Lumi's stores
              </p>
              <ul className="mt-2 space-y-1 text-xs leading-5 text-[var(--muted-strong)]">
                {notLumiOwned.map((step) => (
                  <li key={step.id}>
                    <code className="font-mono">{step.data_class}</code> —{" "}
                    {presentDeletionStep(step).reason}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          {retained.length > 0 ? (
            <div className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-3">
              <p className="text-sm font-semibold text-[var(--civic-navy)]">
                Retained for a legal or security duty
              </p>
              <p className="mt-1 text-xs leading-5 text-[var(--muted-strong)]">
                These classes were not deleted. Their personal content is minimized and identifiers
                are tombstoned where that is possible, but the history is not rewritten.
              </p>
              <ul className="mt-2 flex flex-wrap gap-1.5">
                {retained.map((key) => (
                  <li key={key}>
                    <Pill tone="warning">{key}</Pill>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      </SeverityRail>

      {job.certificate ? <CertificateBlock job={job} coverage={coverage} /> : null}
    </div>
  );
}

function CertificateBlock({
  job,
  coverage,
}: {
  job: DeletionJob;
  coverage: ReturnType<typeof readReferenceCoverage>;
}) {
  const certificate = job.certificate;
  if (certificate === null || certificate === undefined) return null;
  const rows = readClassResults(certificate.class_results);
  return (
    <Surface ariaLabel="Deletion certificate">
      <SurfaceHeader
        eyebrow="CERTIFICATE"
        title="What this job covered"
        description={CERTIFICATE_NOTE}
        action={<Code>{certificate.id}</Code>}
      />
      <div className="space-y-4 px-5 py-4">
        <dl>
          <DefinitionRow
            term="Completed"
            description="The instant the certificate was issued. A certificate is a statement about one traversal at one time."
          >
            <DateTime value={certificate.completed_at} />
          </DefinitionRow>
          <DefinitionRow
            term="Retained for 365 days"
            description="A certificate is itself a legal record. It outlives the job rows it describes and is not rewritten by a later job."
          >
            <DateTime value={certificate.expires_at} />
          </DefinitionRow>
          <DefinitionRow term="Reference coverage" description={COVERAGE_NOTE}>
            <p className="text-sm text-[var(--civic-navy)]">
              Traversed:{" "}
              {coverage.traversed.length === 0 ? "none published" : coverage.traversed.join(", ")}
            </p>
            <p
              className={`mt-1 text-sm ${coverage.complete ? "text-[var(--success)]" : "text-[var(--warning)]"}`}
            >
              {coverage.complete
                ? "Every named reference system was traversed."
                : `Not covered: ${coverage.pending.join(", ")}${
                    coverage.absentReason === null ? "" : ` (${coverage.absentReason})`
                  }. A completed job is not a claim about these systems.`}
            </p>
          </DefinitionRow>
        </dl>

        {rows.length > 0 ? (
          <div>
            <p className="text-xs font-semibold tracking-[0.06em] text-[var(--muted)] uppercase">
              Classes this job reported
            </p>
            <ul className="mt-2 space-y-1">
              {rows.map((row) => (
                <li key={row.dataClass} className="text-xs leading-5 text-[var(--muted-strong)]">
                  <code className="font-mono">{row.dataClass}</code> — {row.label}:{" "}
                  {row.counts.map((entry) => `${entry.count} ${entry.state}`).join(", ")}
                </li>
              ))}
            </ul>
          </div>
        ) : (
          <p className="text-xs leading-5 text-[var(--muted)]">
            The certificate published no per-class counts, so nothing is claimed about which classes
            it touched.
          </p>
        )}

        <DisclosureList items={mergeDisclosures(job.disclosures)} title="Disclosures" />
      </div>
    </Surface>
  );
}

function DisclosureList({ items, title }: { items: readonly string[]; title: string }) {
  if (items.length === 0) return null;
  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-3">
      <p className="text-xs font-semibold tracking-[0.06em] text-[var(--muted)] uppercase">
        {title}
      </p>
      <ul className="mt-2 space-y-1.5">
        {items.map((item) => (
          <li key={item} className="text-xs leading-5 text-[var(--muted-strong)]">
            {item}
          </li>
        ))}
      </ul>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Personal (account) deletion
// ---------------------------------------------------------------------------

export interface PersonalDeletionWorkflowProps {
  api: DataGovernanceApi;
  status: DeletionJob | PersonalDeletionStatus;
  statusState: "loading" | "ready" | "error";
  error: unknown;
  organizations: ReadonlyArray<{
    org_id: string;
    display_name: string;
    role: string;
    organization_state: string;
    membership_status: string;
  }>;
  onRefresh: () => void;
  onChanged: (job: DeletionJob) => void;
}

export function PersonalDeletionWorkflow({
  api,
  status,
  statusState,
  error,
  organizations,
  onRefresh,
  onChanged,
}: PersonalDeletionWorkflowProps) {
  const [dialog, setDialog] = useState<"request" | "cancel" | null>(null);
  const [phrase, setPhrase] = useState("");
  const [phraseError, setPhraseError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const dialogTitleId = useId();

  const job = statusState === "ready" && "id" in status ? status : null;
  const disclosures = useMemo(
    () => mergeDisclosures(statusState === "ready" ? status.disclosures : null),
    [status, statusState],
  );
  const blockingOrgs = organizations.filter(
    (org) =>
      (org.role === "owner" || org.role === "admin") &&
      org.organization_state === "active" &&
      org.membership_status === "active",
  );
  const graceOpen =
    job !== null && job.state === "awaiting_grace" && job.grace_expires_at !== null
      ? new Date(job.grace_expires_at).getTime() > Date.now()
      : false;

  useEffect(() => {
    setPhrase("");
    setPhraseError(null);
  }, [dialog]);

  async function request() {
    if (phrase.trim() !== DELETION_CONFIRMATION_PHRASE) {
      setPhraseError(
        `Type ${DELETION_CONFIRMATION_PHRASE} exactly. The server compares the phrase verbatim.`,
      );
      return;
    }
    setPhraseError(null);
    setBusy(true);
    setActionError(null);
    try {
      const grant = await mintReauthGrant();
      const created = await api.createPersonalDeletion(
        {
          confirmation: DELETION_CONFIRMATION_PHRASE,
          reauth_grant_id: grant.grant_id,
          reauth_token: grant.token,
        },
        crypto.randomUUID(),
      );
      setDialog(null);
      onChanged(created);
      setNotice(
        "The account deletion is in its grace window. You can cancel it until the window closes; after that it proceeds.",
      );
    } catch (requestError) {
      setActionError(requestError);
    } finally {
      setBusy(false);
    }
  }

  async function cancel() {
    setBusy(true);
    setActionError(null);
    try {
      const grant = await mintReauthGrant();
      const cancelled = await api.cancelPersonalDeletion(
        { reauth_grant_id: grant.grant_id, reauth_token: grant.token },
        crypto.randomUUID(),
      );
      setDialog(null);
      onChanged(cancelled);
      setNotice(
        "The pending account deletion was cancelled inside its grace window. Nothing was deleted.",
      );
    } catch (cancelError) {
      setActionError(cancelError);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Surface ariaLabel="Account deletion">
      <SurfaceHeader
        eyebrow="YOUR ACCOUNT"
        title="Account deletion"
        description="A staged, auditable workflow with a grace window. It removes Lumi-managed records for your account and records what it did not touch."
        action={
          <button type="button" className={secondaryButtonClass} onClick={onRefresh}>
            Refresh
          </button>
        }
      />
      <div className="space-y-4 px-5 py-4">
        {statusState === "loading" ? (
          <p className="text-sm text-[var(--muted-strong)]" role="status" aria-busy="true">
            Loading your account deletion status…
          </p>
        ) : null}
        {statusState === "error" ? <ErrorNotice error={error} onRetry={onRefresh} /> : null}

        {blockingOrgs.length > 0 ? (
          <SeverityRail severity="warning">
            <div className="px-5 py-4">
              <p className="text-xs font-semibold tracking-[0.1em] text-[var(--civic-navy)]">
                BEFORE YOU START
              </p>
              <p className="mt-1.5 text-sm font-semibold text-[var(--civic-navy)]">
                Leave or transfer{" "}
                {blockingOrgs.length === 1 ? "this organization" : "these organizations"} first
              </p>
              <p className="mt-1 text-xs leading-5 text-[var(--muted-strong)]">
                You hold an owner or admin role in an active organization. The server refuses the
                request with a stable <code className="font-mono">deletion_requires_org_exit</code>{" "}
                result rather than deleting an organization on your behalf.
              </p>
              <ul className="mt-2 space-y-1 text-xs text-[var(--muted-strong)]">
                {blockingOrgs.map((org) => (
                  <li key={org.org_id}>
                    {org.display_name} — {org.role}
                  </li>
                ))}
              </ul>
            </div>
          </SeverityRail>
        ) : null}

        {statusState === "ready" && job === null ? (
          <EmptyState
            title="No account deletion is in progress"
            copy="Nothing is scheduled. Starting one requires a recent security check and the typed confirmation phrase, and it waits out a grace window before it touches anything."
          />
        ) : null}

        {job !== null ? (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <Pill tone={deletionStateCopy(job.state).tone}>
                {deletionStateCopy(job.state).label}
              </Pill>
              <Code>{job.id}</Code>
            </div>
            <p className="text-xs leading-5 text-[var(--muted-strong)]">
              {deletionStateCopy(job.state).body}
            </p>
            <dl className="grid gap-2 text-xs text-[var(--muted)] sm:grid-cols-2">
              <div>
                <dt className="font-medium">Grace closes</dt>
                <dd>
                  <DateTime value={job.grace_expires_at} />
                </dd>
              </div>
              <div>
                <dt className="font-medium">Cutoff</dt>
                <dd>
                  <DateTime value={job.cutoff_at} />
                </dd>
              </div>
            </dl>
            {job.failure_code !== null ? (
              <p className="text-xs leading-5 text-[var(--danger)]">
                <Code>{job.failure_code}</Code> {jobFailureCopy(job.failure_code)?.body ?? ""}
              </p>
            ) : null}
            {graceOpen ? (
              <button
                type="button"
                className={dangerButtonClass}
                onClick={() => setDialog("cancel")}
                disabled={busy}
              >
                Cancel this deletion…
              </button>
            ) : null}
          </div>
        ) : null}

        {notice ? (
          <Notice tone="success">
            <p>{notice}</p>
          </Notice>
        ) : null}
        {actionError !== null ? <ErrorNotice error={actionError} /> : null}

        {job === null ? (
          <div className="space-y-3 rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-3">
            <p className="text-xs font-semibold tracking-[0.06em] text-[var(--muted)] uppercase">
              Before you start
            </p>
            <ul className="space-y-1.5">
              {ACCOUNT_DELETION_PREREQUISITES.map((item) => (
                <li
                  key={item.slice(0, 40)}
                  className="text-xs leading-5 text-[var(--muted-strong)]"
                >
                  {item}
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {job === null ? (
          <div className="space-y-2">
            <button
              type="button"
              className={dangerButtonClass}
              onClick={() => {
                setActionError(null);
                setDialog("request");
              }}
              disabled={blockingOrgs.length > 0}
            >
              {PERSONAL_DELETION_COPY.requestLabel}…
            </button>
            {blockingOrgs.length > 0 ? (
              <p className="text-xs leading-5 text-[var(--muted)]">
                The control is disabled because the requirement above is not met. Leaving or
                transferring an organization is a separate action on that organization, and this
                page does not perform it for you.
              </p>
            ) : null}
          </div>
        ) : null}

        <DisclosureList items={disclosures} title="What account deletion does not remove" />
      </div>

      <ConfirmDialog
        open={dialog !== null}
        eyebrow={dialog === "cancel" ? "CANCEL ACCOUNT DELETION" : "DELETE ACCOUNT"}
        title={
          dialog === "cancel"
            ? PERSONAL_DELETION_COPY.cancelTitle
            : PERSONAL_DELETION_COPY.requestTitle
        }
        body={
          dialog === "cancel"
            ? PERSONAL_DELETION_COPY.cancelBody
            : PERSONAL_DELETION_COPY.requestBody
        }
        confirmLabel={
          dialog === "cancel"
            ? PERSONAL_DELETION_COPY.cancelLabel
            : PERSONAL_DELETION_COPY.requestLabel
        }
        cancelLabel="Go back"
        busyLabel={
          dialog === "cancel"
            ? PERSONAL_DELETION_COPY.cancelBusyLabel
            : PERSONAL_DELETION_COPY.busyLabel
        }
        busy={busy}
        destructive
        onClose={() => setDialog(null)}
        onConfirm={() => void (dialog === "cancel" ? cancel() : request())}
      >
        {dialog === "request" ? (
          <div>
            <label
              htmlFor={dialogTitleId}
              className="text-sm font-semibold text-[var(--civic-navy)]"
            >
              {PERSONAL_DELETION_COPY.confirmPhraseLabel}
            </label>
            <input
              id={dialogTitleId}
              className={inputClass}
              value={phrase}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => setPhrase(event.target.value)}
              aria-describedby={`${dialogTitleId}-hint`}
            />
            <p id={`${dialogTitleId}-hint`} className="mt-1 text-xs leading-5 text-[var(--muted)]">
              Type <code className="font-mono">{DELETION_CONFIRMATION_PHRASE}</code> exactly.{" "}
              {REAUTH_NOTE}
            </p>
            {phraseError !== null ? (
              <p role="alert" className="mt-1 text-xs font-medium text-[var(--danger)]">
                {phraseError}
              </p>
            ) : null}
          </div>
        ) : null}
      </ConfirmDialog>
    </Surface>
  );
}
