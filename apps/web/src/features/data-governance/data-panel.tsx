/**
 * Data & retention — the organization section entry (P06-FE-04).
 *
 * Frozen contract: `docs/implementation/gates/P06-CG.md` "Data governance
 * contract" and "API contract"; implemented in
 * `apps/api/src/routes/data_governance.rs`.
 *
 * The panel is a section, not a route: the coordinator owns the shell, the
 * navigation entry, and the lazy import. It renders the four organization
 * surfaces in reading order — policy, retention, exports, deletion — and a
 * separate account-scoped section for personal export and deletion, because the
 * gate keeps account data out of an organization's settings context.
 *
 * Load behaviour follows the other P06 panels: one abortable load per surface,
 * a generation counter so a late response cannot overwrite a newer one, a stale
 * marker instead of a flash of empty, and a tenant reset on org change so no
 * other organization's data is ever on screen.
 */

import { useCallback, useEffect, useRef, useState } from "react";

import { ApiClientError } from "@/lib/errors";

import {
  defaultDataGovernanceApi,
  type DataGovernanceApi,
  type DataGovernancePolicy,
  type DeletionJob,
  type ExportJob,
  type Page,
  type PersonalDeletionStatus,
} from "./api";
import { DataPolicyEditor } from "./data-policy";
import { OrgDeletionWorkflow, PersonalDeletionWorkflow } from "./deletion-workflows";
import { OrgExportWorkflow, PersonalExportWorkflow } from "./export-workflows";
import { RetentionSummary } from "./retention-summary";
import { ErrorNotice, LoadingRows, PermissionState, Pill, Surface } from "./ui";

type LoadState<T> =
  | { kind: "loading" }
  | { kind: "ready"; data: T; stale: boolean }
  | { kind: "error"; error: unknown; previous: T | null }
  | { kind: "permission" };

const EMPTY_EXPORT_PAGE: Page<ExportJob> = { items: [], next_cursor: null, has_more: false };
const EMPTY_DELETION_PAGE: Page<DeletionJob> = { items: [], next_cursor: null, has_more: false };

export interface OrgMembershipSummary {
  org_id: string;
  display_name: string;
  role: string;
  organization_state: string;
  membership_status: string;
}

export interface DataPanelProps {
  orgId: string;
  /**
   * Optional client. When omitted, the feature-local client bound to the
   * implemented P06 routes is used. The coordinator may pass a client that
   * also records telemetry, but the decoders are already closed over the wire
   * contract so there is nothing to extend.
   */
  api?: DataGovernanceApi;
  /** Convenience only. Authorization is enforced server-side. */
  canManage?: boolean;
  canExport?: boolean;
  canDelete?: boolean;
  /** The acting principal, used to attribute a legal-hold release. */
  currentUserId?: string;
  /**
   * Wiring slot for the P02 organization lifecycle deletion request. The panel
   * never calls a deletion request route itself (P06-CR-003).
   */
  onRequestOrganizationDeletion?: (orgId: string) => void;
}

export function DataPanel({
  orgId,
  api,
  canManage = true,
  canExport = true,
  canDelete = true,
  currentUserId,
  onRequestOrganizationDeletion,
}: DataPanelProps) {
  const clientRef = useRef<DataGovernanceApi | null>(null);
  const client = api ?? (clientRef.current ??= defaultDataGovernanceApi());
  const generation = useRef(0);
  const controller = useRef<AbortController | null>(null);

  const [policy, setPolicy] = useState<LoadState<DataGovernancePolicy>>({ kind: "loading" });
  const [exports, setExports] = useState<LoadState<Page<ExportJob>>>({ kind: "loading" });
  const [exportCursor, setExportCursor] = useState<string | null>(null);
  const [deletions, setDeletions] = useState<LoadState<Page<DeletionJob>>>({ kind: "loading" });
  const [deletionCursor, setDeletionCursor] = useState<string | null>(null);
  const [detail, setDetail] = useState<{
    id: string;
    status: "loading" | "ready" | "error";
    job: DeletionJob | null;
    error: unknown;
  } | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    if (!orgId) return;
    const current = ++generation.current;
    controller.current?.abort();
    const active = new AbortController();
    controller.current = active;
    setRefreshing(true);

    const [policyResult, exportResult, deletionResult] = await Promise.all([
      settle(() => client.getPolicy(orgId, active.signal)),
      settle(() => client.listExports(orgId, { limit: 25 }, active.signal)),
      settle(() => client.listDeletions(orgId, { limit: 25 }, active.signal)),
    ]);
    if (current !== generation.current || active.signal.aborted) return;

    setPolicy(policyResult);
    setExports(exportResult);
    setDeletions(deletionResult);
    setExportCursor(null);
    setDeletionCursor(null);
    setRefreshing(false);
  }, [client, orgId]);

  useEffect(() => {
    void load();
    return () => {
      generation.current += 1;
      controller.current?.abort();
    };
  }, [load]);

  // An org switch must not leave another tenant's data on screen.
  useEffect(() => {
    setPolicy({ kind: "loading" });
    setExports({ kind: "loading" });
    setDeletions({ kind: "loading" });
    setDetail(null);
    setSelected(null);
  }, [orgId]);

  const loadDetail = useCallback(
    async (deletionId: string) => {
      if (selected === deletionId) {
        setSelected(null);
        setDetail(null);
        return;
      }
      setSelected(deletionId);
      setDetail({ id: deletionId, status: "loading", job: null, error: null });
      const active = new AbortController();
      try {
        const job = await client.getDeletion(orgId, deletionId, active.signal);
        setDetail({ id: deletionId, status: "ready", job, error: null });
      } catch (error) {
        if (active.signal.aborted) return;
        setDetail({ id: deletionId, status: "error", job: null, error });
      }
    },
    [client, orgId, selected],
  );

  async function loadMoreExports() {
    if (exportCursor === null) return;
    setRefreshing(true);
    try {
      const next = await client.listExports(orgId, { limit: 25, cursor: exportCursor });
      setExports((current) =>
        current.kind === "ready"
          ? { kind: "ready", data: mergePage(current.data, next), stale: false }
          : current,
      );
      setExportCursor(next.next_cursor);
    } catch (error) {
      setExports((current) =>
        current.kind === "ready" ? { kind: "error", error, previous: current.data } : current,
      );
    } finally {
      setRefreshing(false);
    }
  }

  async function loadMoreDeletions() {
    if (deletionCursor === null) return;
    setRefreshing(true);
    try {
      const next = await client.listDeletions(orgId, { limit: 25, cursor: deletionCursor });
      setDeletions((current) =>
        current.kind === "ready"
          ? { kind: "ready", data: mergePage(current.data, next), stale: false }
          : current,
      );
      setDeletionCursor(next.next_cursor);
    } catch (error) {
      setDeletions((current) =>
        current.kind === "ready" ? { kind: "error", error, previous: current.data } : current,
      );
    } finally {
      setRefreshing(false);
    }
  }

  if (
    policy.kind === "permission" ||
    exports.kind === "permission" ||
    deletions.kind === "permission"
  ) {
    return (
      <section aria-label="Data and retention" className="space-y-5">
        <PanelHeading stale={false} refreshing={refreshing} onRefresh={() => void load()} />
        <PermissionState resource="the organization's data policy, exports, or deletion workflows" />
      </section>
    );
  }

  if (policy.kind === "loading") {
    return (
      <section aria-label="Data and retention" className="space-y-5">
        <PanelHeading stale={false} refreshing={refreshing} onRefresh={() => void load()} />
        <Surface ariaLabel="Data policy">
          <LoadingRows
            label="Loading the data policy, retention windows, and job history…"
            rows={5}
          />
        </Surface>
      </section>
    );
  }

  if (policy.kind === "error" && policy.previous === null) {
    return (
      <section aria-label="Data and retention" className="space-y-5">
        <PanelHeading stale={false} refreshing={refreshing} onRefresh={() => void load()} />
        <Surface ariaLabel="Data policy">
          <div className="p-5">
            <ErrorNotice error={policy.error} onRetry={() => void load()} />
          </div>
        </Surface>
      </section>
    );
  }

  const currentPolicy = policy.kind === "error" ? policy.previous : policy.data;
  if (currentPolicy === null) return null;

  const exportPage =
    exports.kind === "ready"
      ? exports.data
      : exports.kind === "error" && exports.previous !== null
        ? exports.previous
        : EMPTY_EXPORT_PAGE;
  const deletionPage =
    deletions.kind === "ready"
      ? deletions.data
      : deletions.kind === "error" && deletions.previous !== null
        ? deletions.previous
        : EMPTY_DELETION_PAGE;

  return (
    <section aria-label="Data and retention" className="space-y-5">
      <PanelHeading
        stale={
          policy.kind === "error" ||
          policy.stale ||
          exports.kind === "error" ||
          deletions.kind === "error"
        }
        refreshing={refreshing}
        onRefresh={() => void load()}
      />

      {policy.kind === "error" ? (
        <ErrorNotice
          error={policy.error}
          title="The data policy could not be refreshed"
          onRetry={() => void load()}
        />
      ) : null}

      <DataPolicyEditor
        orgId={orgId}
        api={client}
        policy={currentPolicy}
        status={policy.kind === "error" ? "stale" : policy.stale ? "stale" : "ready"}
        onRefresh={() => void load()}
        onSaved={(next) => setPolicy({ kind: "ready", data: next, stale: false })}
        {...(currentUserId === undefined ? {} : { currentUserId })}
        canManage={canManage}
      />

      <RetentionSummary policy={currentPolicy} />

      <OrgExportWorkflow
        orgId={orgId}
        api={client}
        legalHold={currentPolicy.legal_hold}
        canExport={canExport}
        page={exportPage}
        status={
          exports.kind === "loading" ? "loading" : exports.kind === "error" ? "error" : "ready"
        }
        error={exports.kind === "error" ? exports.error : null}
        refreshing={refreshing}
        onRefresh={() => void load()}
        onLoadMore={() => void loadMoreExports()}
        onCreated={(job) =>
          setExports((current) =>
            current.kind === "ready"
              ? { kind: "ready", data: prepend(current.data, job), stale: false }
              : current,
          )
        }
      />

      <OrgDeletionWorkflow
        orgId={orgId}
        api={client}
        page={deletionPage}
        detail={detail?.job ?? null}
        detailStatus={detail === null ? "idle" : detail.status}
        detailError={detail?.error ?? null}
        status={
          deletions.kind === "loading" ? "loading" : deletions.kind === "error" ? "error" : "ready"
        }
        error={deletions.kind === "error" ? deletions.error : null}
        refreshing={refreshing}
        canDelete={canDelete}
        onRefresh={() => void load()}
        onLoadMore={() => void loadMoreDeletions()}
        onSelect={(deletionId) => void loadDetail(deletionId)}
        onResumed={(job) =>
          setDetail((current) =>
            current === null ? current : { ...current, status: "ready", job, error: null },
          )
        }
        {...(onRequestOrganizationDeletion === undefined ? {} : { onRequestOrganizationDeletion })}
      />

      {exports.kind === "error" ? (
        <ErrorNotice
          error={exports.error}
          title="Export history could not be refreshed"
          onRetry={() => void load()}
        />
      ) : null}
      {deletions.kind === "error" ? (
        <ErrorNotice
          error={deletions.error}
          title="Deletion history could not be refreshed"
          onRetry={() => void load()}
        />
      ) : null}
    </section>
  );
}

function PanelHeading({
  stale,
  refreshing,
  onRefresh,
}: {
  stale: boolean;
  refreshing: boolean;
  onRefresh: () => void;
}) {
  return (
    <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p className="text-xs font-semibold tracking-[0.1em] text-[var(--lumi-blue)]">
          DATA &amp; RETENTION
        </p>
        <h1 className="mt-1.5 text-2xl font-semibold tracking-[-0.03em] text-[var(--civic-navy)]">
          What Lumi stores, for how long, and what it cannot delete
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-[var(--muted-strong)]">
          Retention and logging policy, scoped exports with short-lived download grants, and staged
          deletion. Upstream provider data and local device data are shown separately, because Lumi
          does not hold them.
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {stale ? (
          <span className="inline-flex items-center rounded-full bg-[var(--warning)]/15 px-2 py-1 text-xs font-medium text-[var(--civic-navy)]">
            {refreshing ? "Refreshing" : "Stale snapshot"}
          </span>
        ) : null}
        <button
          type="button"
          className="min-h-10 rounded-lg border border-[var(--lumi-blue)]/40 bg-[var(--panel)] px-3 text-sm font-medium text-[var(--lumi-blue)] outline-none transition hover:border-[var(--lumi-blue)]/60 hover:bg-[var(--lumi-blue-soft)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
          onClick={onRefresh}
          disabled={refreshing}
        >
          {refreshing ? "Refreshing…" : "Refresh"}
        </button>
      </div>
    </header>
  );
}

// ---------------------------------------------------------------------------
// Account-scoped surface (`/account/data`)
// ---------------------------------------------------------------------------

export interface PersonalDataPanelProps {
  api?: DataGovernanceApi;
  organizations?: readonly OrgMembershipSummary[];
}

/**
 * The personal surface.
 *
 * It is deliberately not a child of the organization panel: the gate places
 * account-level export and deletion outside an organization's settings context,
 * so the coordinator mounts it on the account route with the signed-in
 * principal and no `orgId`.
 */
export function PersonalDataPanel({ api, organizations = [] }: PersonalDataPanelProps) {
  const clientRef = useRef<DataGovernanceApi | null>(null);
  const client = api ?? (clientRef.current ??= defaultDataGovernanceApi());
  const generation = useRef(0);
  const controller = useRef<AbortController | null>(null);

  const [exports, setExports] = useState<LoadState<Page<ExportJob>>>({ kind: "loading" });
  const [exportCursor, setExportCursor] = useState<string | null>(null);
  const [deletion, setDeletion] = useState<LoadState<DeletionJob | PersonalDeletionStatus>>({
    kind: "loading",
  });
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    const current = ++generation.current;
    controller.current?.abort();
    const active = new AbortController();
    controller.current = active;
    setRefreshing(true);
    const [exportResult, deletionResult] = await Promise.all([
      settle(() => client.listPersonalExports({ limit: 25 }, active.signal)),
      settle(() => client.getPersonalDeletion(active.signal)),
    ]);
    if (current !== generation.current || active.signal.aborted) return;
    setExports(exportResult);
    setDeletion(deletionResult);
    setExportCursor(null);
    setRefreshing(false);
  }, [client]);

  useEffect(() => {
    void load();
    return () => {
      generation.current += 1;
      controller.current?.abort();
    };
  }, [load]);

  async function loadMoreExports() {
    if (exportCursor === null) return;
    setRefreshing(true);
    try {
      const next = await client.listPersonalExports({ limit: 25, cursor: exportCursor });
      setExports((current) =>
        current.kind === "ready"
          ? { kind: "ready", data: mergePage(current.data, next), stale: false }
          : current,
      );
      setExportCursor(next.next_cursor);
    } catch (error) {
      setExports((current) =>
        current.kind === "ready" ? { kind: "error", error, previous: current.data } : current,
      );
    } finally {
      setRefreshing(false);
    }
  }

  const stale = exports.kind === "error" || deletion.kind === "error";

  return (
    <section aria-label="Your data" className="space-y-5">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-xs font-semibold tracking-[0.1em] text-[var(--lumi-blue)]">
            YOUR DATA
          </p>
          <h1 className="mt-1.5 text-2xl font-semibold tracking-[-0.03em] text-[var(--civic-navy)]">
            Export or delete your own account data
          </h1>
          <p className="mt-1 max-w-3xl text-sm text-[var(--muted-strong)]">
            Account-scoped only. Organization data is exported or deleted from that organization,
            and upstream provider data is governed by the provider's own policy.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {stale ? <Pill tone="warning">Stale snapshot</Pill> : null}
          <button
            type="button"
            className="min-h-10 rounded-lg border border-[var(--lumi-blue)]/40 bg-[var(--panel)] px-3 text-sm font-medium text-[var(--lumi-blue)] outline-none transition hover:border-[var(--lumi-blue)]/60 hover:bg-[var(--lumi-blue-soft)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
            onClick={() => void load()}
            disabled={refreshing}
          >
            {refreshing ? "Refreshing…" : "Refresh"}
          </button>
        </div>
      </header>

      {exports.kind === "error" ? (
        <ErrorNotice
          error={exports.error}
          title="Your export history could not be refreshed"
          onRetry={() => void load()}
        />
      ) : null}
      {deletion.kind === "error" ? (
        <ErrorNotice
          error={deletion.error}
          title="Your deletion status could not be refreshed"
          onRetry={() => void load()}
        />
      ) : null}

      <PersonalExportWorkflow
        api={client}
        page={
          exports.kind === "ready"
            ? exports.data
            : exports.kind === "error" && exports.previous !== null
              ? exports.previous
              : EMPTY_EXPORT_PAGE
        }
        status={
          exports.kind === "loading" ? "loading" : exports.kind === "error" ? "error" : "ready"
        }
        error={exports.kind === "error" ? exports.error : null}
        refreshing={refreshing}
        onRefresh={() => void load()}
        onLoadMore={() => void loadMoreExports()}
        onCreated={(job) =>
          setExports((current) =>
            current.kind === "ready"
              ? { kind: "ready", data: prepend(current.data, job), stale: false }
              : current,
          )
        }
      />

      {deletion.kind === "loading" ? (
        <Surface ariaLabel="Account deletion">
          <LoadingRows label="Loading your account deletion status…" rows={2} />
        </Surface>
      ) : deletion.kind === "ready" ? (
        <PersonalDeletionWorkflow
          api={client}
          status={deletion.data}
          statusState="ready"
          error={null}
          organizations={organizations}
          onRefresh={() => void load()}
          onChanged={(job) => setDeletion({ kind: "ready", data: job, stale: false })}
        />
      ) : deletion.kind === "error" && deletion.previous !== null ? (
        <PersonalDeletionWorkflow
          api={client}
          status={deletion.previous}
          statusState="ready"
          error={null}
          organizations={organizations}
          onRefresh={() => void load()}
          onChanged={(job) => setDeletion({ kind: "ready", data: job, stale: false })}
        />
      ) : null}
    </section>
  );
}

// ---------------------------------------------------------------------------
// State helpers
// ---------------------------------------------------------------------------

async function settle<T>(load: () => Promise<T>): Promise<LoadState<T>> {
  try {
    return { kind: "ready", data: await load(), stale: false };
  } catch (error) {
    if (
      error instanceof ApiClientError &&
      (error.status === 403 || error.code === "permission_denied")
    ) {
      return { kind: "permission" };
    }
    return { kind: "error", error, previous: null };
  }
}

function mergePage<T>(current: Page<T>, next: Page<T>): Page<T> {
  const seen = new Set(current.items.map((item) => JSON.stringify(item)));
  const items = [...current.items];
  for (const item of next.items) {
    const key = JSON.stringify(item);
    if (seen.has(key)) continue;
    seen.add(key);
    items.push(item);
  }
  return { items, next_cursor: next.next_cursor, has_more: next.has_more };
}

function prepend<T extends { id: string }>(current: Page<T>, item: T): Page<T> {
  if (current.items.some((existing) => existing.id === item.id)) return current;
  return { ...current, items: [item, ...current.items] };
}
