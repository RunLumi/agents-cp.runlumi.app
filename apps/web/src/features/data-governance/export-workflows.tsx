/**
 * Export request, history, and the short-lived download grant.
 *
 * Frozen contract: `GET/POST /api/v1/orgs/{org_id}/exports`,
 * `GET /api/v1/orgs/{org_id}/exports/{export_id}`,
 * `POST /api/v1/orgs/{org_id}/exports/{export_id}/download`, and the personal
 * trio under `/api/v1/me/data/exports`, as implemented in
 * `apps/api/src/routes/data_governance.rs`.
 *
 * The three things this surface refuses to do:
 *
 * 1. It never offers a permanent link. A download is a POST that mints a
 *    short-lived, re-authorized grant, and the artifact expiry is always shown
 *    next to the control.
 * 2. It never implies a fresh snapshot on retry. The manifest and cutoff are
 *    frozen at request time, and the copy says a resumed export is consistent
 *    rather than current.
 * 3. It never renders a download control for a job that cannot mint a grant. The
 *    control is absent with a stated reason, not present and disabled.
 */

import { useEffect, useId, useMemo, useRef, useState } from "react";

import {
  DOWNLOAD_GRANT_NOTES,
  EXPORT_CATEGORY_COPY,
  EXPORT_SNAPSHOT_RULES,
  NOT_DOWNLOADABLE_NOTE,
  PERSONAL_EXPORT_COPY,
  REAUTH_NOTE,
  allowedCategories,
  downloadAvailability,
  exportCategoryCopy,
  exportStateCopy,
  jobFailureCopy,
  type Tone,
} from "./contracts";
import {
  EXPORT_CONFIRMATION_PHRASE,
  EXPORT_FORMATS,
  MAX_EXPORT_CATEGORIES,
  downloadExportArtifact,
  mintReauthGrant,
  resolveDownloadPath,
  type DataGovernanceApi,
  type ExportCategory,
  type ExportFormat,
  type ExportJob,
  type Page,
  type PersonalExportCategory,
} from "./api";
import {
  Code,
  ConfirmDialog,
  DataTable,
  DateTime,
  EmptyState,
  ErrorNotice,
  Notice,
  PaginationFooter,
  Pill,
  Surface,
  SurfaceHeader,
  TableCell,
  primaryButtonClass,
  secondaryButtonClass,
} from "./ui";

// ---------------------------------------------------------------------------
// Shared pieces
// ---------------------------------------------------------------------------

function stateTone(state: ExportJob["state"]): Tone {
  return exportStateCopy(state).tone;
}

function ExportRowFacts({ job }: { job: ExportJob }) {
  const copy = exportStateCopy(job.state);
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <Pill tone={stateTone(job.state)}>{copy.label}</Pill>
        <span className="text-xs text-[var(--muted)]">
          attempt {job.attempt} · state version {job.state_version}
        </span>
      </div>
      <p className="text-xs leading-5 text-[var(--muted-strong)]">{copy.body}</p>
      <dl className="grid gap-x-4 gap-y-1 text-xs text-[var(--muted)] sm:grid-cols-2">
        <div className="flex gap-1.5">
          <dt className="font-medium">Snapshot cutoff</dt>
          <dd>
            <DateTime value={job.snapshot_cutoff_at} />
          </dd>
        </div>
        <div className="flex gap-1.5">
          <dt className="font-medium">Artifact expires</dt>
          <dd>
            <DateTime value={job.artifact?.expires_at ?? null} />
          </dd>
        </div>
        <div className="flex gap-1.5">
          <dt className="font-medium">Format</dt>
          <dd>{job.format}</dd>
        </div>
        <div className="flex gap-1.5">
          <dt className="font-medium">Ready at</dt>
          <dd>
            <DateTime value={job.ready_at} />
          </dd>
        </div>
      </dl>
      <p className="text-xs leading-5 text-[var(--muted)]">
        Manifest frozen at request:{" "}
        {job.categories.length === 0
          ? "no categories"
          : job.categories.map((key) => key).join(", ")}
        {job.unrecognized_categories.length > 0 ? (
          <>
            {" "}
            <span className="font-medium text-[var(--danger)]">
              plus {job.unrecognized_categories.length} category this build does not recognize:{" "}
              <Code>{job.unrecognized_categories.join(", ")}</Code>
            </span>
          </>
        ) : null}
        . A retry resumes this same manifest against this same cutoff.
      </p>
      {job.failure_code !== null ? <FailureLine failureCode={job.failure_code} /> : null}
    </div>
  );
}

function FailureLine({ failureCode }: { failureCode: string }) {
  const copy = jobFailureCopy(failureCode);
  return (
    <p className="text-xs leading-5 text-[var(--danger)]">
      <span className="font-semibold">{copy?.label ?? "Failure"}</span> <Code>{failureCode}</Code>
      {copy ? ` — ${copy.body}` : " — the server recorded a code this build does not recognize."}
    </p>
  );
}

function DownloadReceiptNote({
  receipt,
}: {
  receipt: {
    grant_id: string | null;
    grant_expires_at: string | null;
    filename: string;
    byte_length: number | null;
  };
}) {
  return (
    <div
      role="status"
      className="mt-3 rounded-lg border border-[var(--success)]/30 bg-[var(--success)]/5 p-3"
    >
      <p className="text-sm font-semibold text-[var(--civic-navy)]">
        The download was authorized and saved
      </p>
      <ul className="mt-2 space-y-1 text-xs leading-5 text-[var(--muted-strong)]">
        <li>
          File <Code>{receipt.filename}</Code>
          {receipt.byte_length === null ? "" : ` · ${receipt.byte_length.toLocaleString()} bytes`}
        </li>
        <li>
          Grant <Code>{receipt.grant_id ?? "not published"}</Code> · expires{" "}
          <DateTime value={receipt.grant_expires_at} />
        </li>
      </ul>
      <p className="mt-2 text-xs leading-5 text-[var(--muted)]">
        The grant is consumed by this download. When it lapses there is nothing to reuse: mint a new
        one with the same button. The grant token itself is never shown, stored, or logged.
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Organization exports
// ---------------------------------------------------------------------------

export interface OrgExportWorkflowProps {
  orgId: string;
  api: DataGovernanceApi;
  legalHold: boolean;
  canExport: boolean;
  page: Page<ExportJob>;
  status: "loading" | "ready" | "error" | "permission";
  error: unknown;
  refreshing: boolean;
  onRefresh: () => void;
  onLoadMore: () => void;
  onCreated: (job: ExportJob) => void;
}

export function OrgExportWorkflow({
  orgId,
  api,
  legalHold,
  canExport,
  page,
  status,
  error,
  refreshing,
  onRefresh,
  onLoadMore,
  onCreated,
}: OrgExportWorkflowProps) {
  const [selected, setSelected] = useState<ExportCategory[]>(["identity"]);
  const [format, setFormat] = useState<ExportFormat>("json");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const formatId = useId();
  const controller = useRef<AbortController | null>(null);

  useEffect(() => () => controller.current?.abort(), []);

  const known = useMemo(() => allowedCategories("organization"), []);
  const selectionError = describeSelection(selected);

  async function request() {
    if (selectionError !== null) return;
    setBusy(true);
    setActionError(null);
    setNotice(null);
    try {
      const job = await api.createExport(
        orgId,
        { categories: selected, format },
        crypto.randomUUID(),
      );
      onCreated(job);
      setNotice(
        `The export ${job.id} was accepted. Its manifest and snapshot cutoff are frozen now; a retry resumes the same two.`,
      );
    } catch (requestError) {
      setActionError(requestError);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Surface ariaLabel="Organization exports">
      <SurfaceHeader
        eyebrow="SCOPED EXPORT"
        title="Organization exports"
        description="An export is a frozen, tenant-scoped snapshot of the categories you name. Only a ready export can mint a download, and every download mints a new short-lived grant."
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

      {legalHold ? (
        <div className="px-5 pt-4">
          <Notice tone="warning">
            <p className="font-semibold">A legal hold is active for this organization.</p>
            <p className="mt-1">
              Existing exports stay in place for the audit trail, but no new download grant is
              minted while a hold is active. The artifact bytes are kept; the grant is what is
              blocked.
            </p>
          </Notice>
        </div>
      ) : null}

      <div className="space-y-4 px-5 py-4">
        {status === "loading" ? (
          <p className="text-sm text-[var(--muted-strong)]" role="status" aria-busy="true">
            Loading export history…
          </p>
        ) : null}

        {status === "error" ? <ErrorNotice error={error} onRetry={onRefresh} /> : null}

        {status === "permission" ? (
          <Notice tone="info">
            Your current membership cannot read the organization export history.
          </Notice>
        ) : null}

        {canExport ? (
          <fieldset className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-3">
            <legend className="px-1 text-xs font-semibold tracking-[0.06em] text-[var(--muted)] uppercase">
              Category manifest
            </legend>
            <ul className="space-y-2">
              {known.map((key) => {
                const copy = exportCategoryCopy(key);
                const inputId = `org-export-${key}`;
                return (
                  <li key={key} className="flex items-start gap-3">
                    <input
                      type="checkbox"
                      id={inputId}
                      className="mt-1 size-4 shrink-0 rounded border-[var(--border-strong)] accent-[var(--lumi-blue)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
                      checked={selected.includes(key)}
                      onChange={(event) => toggle(setSelected, key, event.target.checked, known)}
                    />
                    <label htmlFor={inputId} className="min-w-0">
                      <span className="block text-sm font-medium text-[var(--civic-navy)]">
                        {copy?.label ?? key}
                      </span>
                      <span className="mt-0.5 block text-xs leading-5 text-[var(--muted-strong)]">
                        {copy?.contains ?? ""}
                      </span>
                    </label>
                  </li>
                );
              })}
            </ul>
            <div className="mt-3 grid gap-3 sm:grid-cols-[10rem_minmax(0,1fr)]">
              <div>
                <label
                  htmlFor={formatId}
                  className="text-xs font-medium text-[var(--muted-strong)]"
                >
                  Format
                </label>
                <select
                  id={formatId}
                  className="mt-1.5 min-h-11 w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 text-sm outline-none transition focus-visible:border-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
                  value={format}
                  onChange={(event) => setFormat(event.target.value as ExportFormat)}
                >
                  {EXPORT_FORMATS.map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </select>
              </div>
              <div className="self-end">
                <button
                  type="button"
                  className={primaryButtonClass}
                  onClick={() => void request()}
                  disabled={busy || selectionError !== null}
                >
                  {busy ? "Requesting…" : "Request an export"}
                </button>
              </div>
            </div>
            {selectionError !== null ? (
              <p role="alert" className="mt-2 text-xs font-medium text-[var(--danger)]">
                {selectionError}
              </p>
            ) : (
              <p className="mt-2 text-xs leading-5 text-[var(--muted)]">
                {selected.length} of {MAX_EXPORT_CATEGORIES} categories selected. The manifest is
                frozen when the request is accepted.
              </p>
            )}
          </fieldset>
        ) : (
          <Notice tone="info">
            Your current role can read export history but not request one. Requesting an export is a
            `data.export` action and the server enforces it on every call.
          </Notice>
        )}

        {notice ? (
          <Notice tone="success">
            <p>{notice}</p>
          </Notice>
        ) : null}

        {actionError !== null ? <ErrorNotice error={actionError} /> : null}

        <ul className="space-y-2">
          {EXPORT_SNAPSHOT_RULES.map((rule) => (
            <li key={rule.slice(0, 40)} className="text-xs leading-5 text-[var(--muted-strong)]">
              {rule}
            </li>
          ))}
        </ul>

        {status === "ready" && page.items.length === 0 ? (
          <EmptyState
            title="No export has been requested"
            copy="A request creates a durable job with a frozen manifest and snapshot cutoff. Nothing is packaged until a worker runs it, and nothing is downloadable until it is ready."
          />
        ) : null}

        {page.items.length > 0 ? (
          <DataTable
            caption="Export jobs for this organization"
            headers={["Requested", "Categories", "State", "Download"]}
          >
            {page.items.map((job) => (
              <ExportRow
                key={job.id}
                job={job}
                orgId={orgId}
                canExport={canExport}
                blocked={legalHold}
                onChanged={onRefresh}
              />
            ))}
          </DataTable>
        ) : null}

        {status === "ready" ? (
          <PaginationFooter
            loaded={page.items.length}
            hasMore={page.has_more}
            loading={refreshing}
            onLoadMore={onLoadMore}
            noun="export"
          />
        ) : null}
      </div>
    </Surface>
  );
}

function ExportRow({
  job,
  orgId,
  canExport,
  blocked,
  onChanged,
}: {
  job: ExportJob;
  orgId: string;
  canExport: boolean;
  blocked: boolean;
  onChanged: () => void;
}) {
  const now = useNow(60_000);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [receipt, setReceipt] = useState<{
    grant_id: string | null;
    grant_expires_at: string | null;
    filename: string;
    byte_length: number | null;
  } | null>(null);
  const availability = downloadAvailability({
    state: job.state,
    serverDownloadable: job.downloadable,
    artifactExpiresAt: job.artifact?.expires_at ?? null,
    now,
  });
  const holdBlocked = blocked && availability.available;

  async function download() {
    setBusy(true);
    setError(null);
    setReceipt(null);
    try {
      const result = await downloadExportArtifact({
        path: resolveDownloadPath(
          { kind: "org", orgId },
          job.id,
          job.artifact?.download_path ?? null,
        ),
        exportId: job.id,
      });
      setReceipt({
        grant_id: result.grant_id,
        grant_expires_at: result.grant_expires_at,
        filename: result.filename,
        byte_length: result.byte_length,
      });
      onChanged();
    } catch (downloadError) {
      setError(downloadError);
    } finally {
      setBusy(false);
    }
  }

  return (
    <tr className="border-b border-[var(--border)] last:border-b-0 align-top">
      <TableCell header="Requested">
        <span className="block">
          <DateTime value={job.requested_at} />
        </span>
        <Code>{job.id}</Code>
      </TableCell>
      <TableCell header="Categories">
        <span className="block">{job.categories.length}</span>
        <span className="text-xs text-[var(--muted)]">{job.categories.join(", ")}</span>
      </TableCell>
      <TableCell header="State">
        <ExportRowFacts job={job} />
      </TableCell>
      <TableCell header="Download">
        {availability.available && !holdBlocked ? (
          canExport ? (
            <div className="space-y-2">
              <button
                type="button"
                className={primaryButtonClass}
                onClick={() => void download()}
                disabled={busy}
              >
                {busy ? "Authorizing…" : "Download (mints a new grant)"}
              </button>
              <ul className="space-y-1 text-xs leading-5 text-[var(--muted)]">
                {DOWNLOAD_GRANT_NOTES.map((note) => (
                  <li key={note.slice(0, 40)}>{note}</li>
                ))}
              </ul>
              {receipt ? <DownloadReceiptNote receipt={receipt} /> : null}
              {error !== null ? <ErrorNotice error={error} /> : null}
            </div>
          ) : (
            <div className="space-y-1 text-xs leading-5 text-[var(--muted)]">
              <p className="font-medium text-[var(--civic-navy)]">No download action</p>
              <p>
                Your role cannot mint a download grant. The server refuses the request, so the
                control is not offered as if it would work.
              </p>
            </div>
          )
        ) : (
          <div className="space-y-1 text-xs leading-5 text-[var(--muted)]">
            <p className="font-medium text-[var(--civic-navy)]">No download action</p>
            <p>{holdBlocked ? holdBlockedReason : availability.reason}</p>
            <p>{NOT_DOWNLOADABLE_NOTE}</p>
          </div>
        )}
      </TableCell>
    </tr>
  );
}

const holdBlockedReason =
  "A legal hold is active. The artifact bytes are kept for the audit trail, but the server refuses to mint a new download grant while the hold is in place.";

function describeSelection(selected: readonly ExportCategory[]): string | null {
  if (selected.length === 0)
    return "Select at least one category. An export with no category is refused.";
  if (selected.length > MAX_EXPORT_CATEGORIES) {
    return `Select at most ${MAX_EXPORT_CATEGORIES} categories.`;
  }
  return null;
}

function toggle<T extends ExportCategory>(
  setter: (updater: (current: T[]) => T[]) => void,
  key: T,
  checked: boolean,
  order: readonly T[],
): void {
  setter((current) =>
    checked
      ? order.filter((item) => new Set([...current, key]).has(item))
      : current.filter((item) => item !== key),
  );
}

/**
 * Re-evaluate time-dependent facts on a bounded interval.
 *
 * Expiry is a deadline, so a stale row would offer a dead download. One minute
 * is the only timer in this feature, and it is cleared on unmount.
 */
function useNow(intervalMs: number): Date {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const handle = setInterval(() => setNow(new Date()), intervalMs);
    return () => clearInterval(handle);
  }, [intervalMs]);
  return now;
}

// ---------------------------------------------------------------------------
// Personal (account) exports
// ---------------------------------------------------------------------------

export interface PersonalExportWorkflowProps {
  api: DataGovernanceApi;
  page: Page<ExportJob>;
  status: "loading" | "ready" | "error";
  error: unknown;
  refreshing: boolean;
  onRefresh: () => void;
  onLoadMore: () => void;
  onCreated: (job: ExportJob) => void;
}

export function PersonalExportWorkflow({
  api,
  page,
  status,
  error,
  refreshing,
  onRefresh,
  onLoadMore,
  onCreated,
}: PersonalExportWorkflowProps) {
  const [selected, setSelected] = useState<PersonalExportCategory[]>(["identity", "notifications"]);
  const [phrase, setPhrase] = useState("");
  const [dialog, setDialog] = useState(false);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const known = useMemo<PersonalExportCategory[]>(
    () => allowedCategories("user") as PersonalExportCategory[],
    [],
  );

  async function request() {
    setBusy(true);
    setActionError(null);
    setNotice(null);
    try {
      // The reauthentication grant is minted immediately before the request and
      // consumed by it. It is never stored, logged, or put in the URL.
      const grant = await mintReauthGrant();
      const job = await api.createPersonalExport(
        {
          categories: selected,
          format: "json",
          confirmation: EXPORT_CONFIRMATION_PHRASE,
          reauth_grant_id: grant.grant_id,
          reauth_token: grant.token,
        },
        crypto.randomUUID(),
      );
      setDialog(false);
      setPhrase("");
      onCreated(job);
      setNotice(
        `Your export ${job.id} was accepted. The manifest and snapshot cutoff are frozen now.`,
      );
    } catch (requestError) {
      setActionError(requestError);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Surface ariaLabel="Personal account exports">
      <SurfaceHeader
        eyebrow="YOUR ACCOUNT DATA"
        title="Personal export"
        description="Account-scoped data only. Organization, device, run, usage, and audit data belong to the organization scope and are not part of this export."
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
            Loading your export history…
          </p>
        ) : null}
        {status === "error" ? <ErrorNotice error={error} onRetry={onRefresh} /> : null}

        <fieldset className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-3">
          <legend className="px-1 text-xs font-semibold tracking-[0.06em] text-[var(--muted)] uppercase">
            Account-scoped categories
          </legend>
          <ul className="space-y-2">
            {known.map((key) => {
              const copy = exportCategoryCopy(key);
              const inputId = `me-export-${key}`;
              return (
                <li key={key} className="flex items-start gap-3">
                  <input
                    type="checkbox"
                    id={inputId}
                    className="mt-1 size-4 shrink-0 rounded border-[var(--border-strong)] accent-[var(--lumi-blue)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
                    checked={selected.includes(key)}
                    onChange={(event) => toggle(setSelected, key, event.target.checked, known)}
                  />
                  <label htmlFor={inputId} className="min-w-0">
                    <span className="block text-sm font-medium text-[var(--civic-navy)]">
                      {copy?.label ?? key}
                    </span>
                    <span className="mt-0.5 block text-xs leading-5 text-[var(--muted-strong)]">
                      {copy?.contains ?? ""}
                    </span>
                  </label>
                </li>
              );
            })}
          </ul>
          <p className="mt-2 text-xs leading-5 text-[var(--muted)]">
            A personal export cannot name an organization category. The server refuses one, and the
            organization export is the route for that data.
          </p>
          <button
            type="button"
            className={primaryButtonClass}
            onClick={() => {
              setActionError(null);
              setDialog(true);
            }}
            disabled={selected.length === 0}
          >
            Request my export…
          </button>
        </fieldset>

        {notice ? (
          <Notice tone="success">
            <p>{notice}</p>
          </Notice>
        ) : null}
        {actionError !== null ? <ErrorNotice error={actionError} /> : null}

        {status === "ready" && page.items.length === 0 ? (
          <EmptyState
            title="You have not requested a personal export"
            copy="A personal export needs a recent security check and the typed confirmation phrase, even for a small account."
          />
        ) : null}

        {page.items.length > 0 ? (
          <DataTable
            caption="Your personal export jobs"
            headers={["Requested", "Categories", "State", "Download"]}
          >
            {page.items.map((job) => (
              <PersonalExportRow key={job.id} job={job} onChanged={onRefresh} />
            ))}
          </DataTable>
        ) : null}

        {status === "ready" ? (
          <PaginationFooter
            loaded={page.items.length}
            hasMore={page.has_more}
            loading={refreshing}
            onLoadMore={onLoadMore}
            noun="export"
          />
        ) : null}

        <Notice tone="info">
          <p className="font-semibold">What a personal export does not include</p>
          <ul className="mt-2 space-y-1 text-xs leading-5">
            {EXPORT_CATEGORY_COPY.filter((row) => !row.personal).map((row) => (
              <li key={row.key}>
                <span className="font-medium">{row.label}.</span> {row.personalNote}
              </li>
            ))}
          </ul>
        </Notice>
      </div>

      <ConfirmDialog
        open={dialog}
        eyebrow="PERSONAL EXPORT"
        title={PERSONAL_EXPORT_COPY.requestTitle}
        body={PERSONAL_EXPORT_COPY.requestBody}
        confirmLabel={PERSONAL_EXPORT_COPY.requestLabel}
        cancelLabel="Do not request"
        busyLabel={PERSONAL_EXPORT_COPY.busyLabel}
        busy={busy}
        destructive={false}
        onClose={() => setDialog(false)}
        onConfirm={() => void request()}
      >
        <label
          htmlFor="me-export-phrase"
          className="text-sm font-semibold text-[var(--civic-navy)]"
        >
          {PERSONAL_EXPORT_COPY.confirmPhraseLabel}
        </label>
        <input
          id="me-export-phrase"
          className="mt-1.5 min-h-11 w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 text-sm outline-none transition focus-visible:border-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
          value={phrase}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => setPhrase(event.target.value)}
          aria-describedby="me-export-phrase-hint"
        />
        <p id="me-export-phrase-hint" className="mt-1 text-xs leading-5 text-[var(--muted)]">
          Type <code className="font-mono">{EXPORT_CONFIRMATION_PHRASE}</code> exactly.{" "}
          {REAUTH_NOTE}
        </p>
      </ConfirmDialog>
    </Surface>
  );
}

function PersonalExportRow({ job, onChanged }: { job: ExportJob; onChanged: () => void }) {
  const now = useNow(60_000);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const availability = downloadAvailability({
    state: job.state,
    serverDownloadable: job.downloadable,
    artifactExpiresAt: job.artifact?.expires_at ?? null,
    now,
  });

  async function download() {
    setBusy(true);
    setError(null);
    try {
      await downloadExportArtifact({
        path: resolveDownloadPath({ kind: "me" }, job.id, job.artifact?.download_path ?? null),
        exportId: job.id,
      });
      onChanged();
    } catch (downloadError) {
      setError(downloadError);
    } finally {
      setBusy(false);
    }
  }

  return (
    <tr className="border-b border-[var(--border)] last:border-b-0 align-top">
      <TableCell header="Requested">
        <span className="block">
          <DateTime value={job.requested_at} />
        </span>
        <Code>{job.id}</Code>
      </TableCell>
      <TableCell header="Categories">{job.categories.join(", ")}</TableCell>
      <TableCell header="State">
        <ExportRowFacts job={job} />
      </TableCell>
      <TableCell header="Download">
        {availability.available ? (
          <button
            type="button"
            className={primaryButtonClass}
            onClick={() => void download()}
            disabled={busy}
          >
            {busy ? "Authorizing…" : "Download (mints a new grant)"}
          </button>
        ) : (
          <div className="space-y-1 text-xs leading-5 text-[var(--muted)]">
            <p className="font-medium text-[var(--civic-navy)]">No download action</p>
            <p>{availability.reason}</p>
          </div>
        )}
        {error !== null ? (
          <div className="mt-2">
            <ErrorNotice error={error} />
          </div>
        ) : null}
      </TableCell>
    </tr>
  );
}
