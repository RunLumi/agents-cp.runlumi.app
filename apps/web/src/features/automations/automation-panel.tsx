// P06 automation management surface.
//
// Structure follows the existing control-plane panels: a dense, quiet list, one
// detail surface for the selected definition, a separate occurrence-history
// surface, and one confirmation dialog for every lifecycle action.
//
// Authority boundaries this panel respects:
//   - it never computes the next run, a lease, or an entitlement decision;
//   - it never renders a second run timeline (P05 owns runs, correlated by
//     `run_id` only);
//   - it never reuses another organization's state, and every mutation carries
//     the `version` the server requires plus its own idempotency key.

import { useCallback, useEffect, useId, useRef, useState } from "react";

import {
  AUTOMATION_STATUS_LABELS,
  automationActionErrorMessage,
  automationLimitState,
  executionPolicySummary,
  isAutomationConflict,
  isPermissionFailure,
  offPeakEligibilityLabel,
  principalSummary,
  targetSummary,
  toolPolicyScopeLabel,
} from "./automation-helpers";
import {
  AUTOMATION_PAGE_LIMIT,
  defaultAutomationsApi,
  type AutomationsApiClient,
  type AutomationDefinition,
  type AutomationEntitlements,
  type AutomationStatus,
  type CreateAutomationInput,
  type Occurrence,
  type OccurrenceState,
  type TargetKind,
  type ToolPolicyScope,
} from "./api";
import { OccurrenceHistory } from "./occurrence-history";
import { OffPeakCard } from "./off-peak-card";
import { describePayload, ScheduleBuilder } from "./schedule-builder";
import {
  buildSchedulePayload,
  createScheduleDraft,
  describeSchedule,
  describeSchedulePolicy,
  describeScheduleWindow,
  formatInstant,
  formatInstantUtc,
  missedPolicyDetail,
  overlapPolicyDetail,
  type ScheduleDraft,
  type ScheduleIssue,
} from "./schedule-helpers";
import {
  EmptyState,
  ErrorState,
  Field,
  Loading,
  Metadata,
  Notice,
  Panel,
  PanelHeader,
  PermissionState,
  Pill,
  dangerButton,
  inputClass,
  primaryButton,
  secondaryButton,
} from "./ui";

export interface AutomationPanelProps {
  orgId: string;
  /** `automations.manage` in the current membership. Defaults to allow. */
  canManage?: boolean;
  /** `automations.run` in the current membership. Defaults to `canManage`. */
  canRun?: boolean;
  /** Injected in tests and by the coordinator; defaults to the browser client. */
  client?: AutomationsApiClient;
}

type LoadStatus = "idle" | "loading" | "refreshing" | "ready" | "error";
type LifecycleAction = "pause" | "resume" | "run_now" | "delete";

interface AutomationCollection {
  orgId: string;
  status: LoadStatus;
  items: AutomationDefinition[];
  nextCursor: string | null;
  hasMore: boolean;
  error: unknown;
}

interface OccurrenceCollection {
  orgId: string;
  automationId: string | null;
  status: LoadStatus;
  items: Occurrence[];
  nextCursor: string | null;
  hasMore: boolean;
  error: unknown;
  ambiguousCount: number;
}

interface DetailState {
  orgId: string;
  id: string | null;
  status: LoadStatus;
  value: AutomationDefinition | null;
  error: unknown;
}

interface EntitlementState {
  orgId: string;
  status: LoadStatus;
  value: AutomationEntitlements | null;
  error: unknown;
}

interface PendingAction {
  kind: LifecycleAction;
  automation: AutomationDefinition;
}

export function AutomationPanel({
  orgId,
  canManage = true,
  canRun,
  client = defaultAutomationsApi,
}: AutomationPanelProps) {
  const panelId = useId();
  const effectiveCanRun = canRun ?? canManage;
  const orgIdRef = useRef(orgId);
  orgIdRef.current = orgId;

  const [statusFilter, setStatusFilter] = useState<AutomationStatus | "">("");
  const [occurrenceFilter, setOccurrenceFilter] = useState<OccurrenceState | "">("");
  const [collection, setCollection] = useState<AutomationCollection>(() => emptyCollection(orgId));
  const [selectedAutomationId, setSelectedAutomationId] = useState<string | null>(null);
  const selectedAutomationIdRef = useRef<string | null>(null);
  const [detail, setDetail] = useState<DetailState>(() => emptyDetail(orgId));
  const [occurrences, setOccurrences] = useState<OccurrenceCollection>(() =>
    emptyOccurrences(orgId, null),
  );
  const [entitlements, setEntitlements] = useState<EntitlementState>(() => ({
    orgId,
    status: "idle",
    value: null,
    error: null,
  }));
  const [pendingAction, setPendingAction] = useState<PendingAction | null>(null);
  const [busyAction, setBusyAction] = useState<LifecycleAction | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  const listController = useRef<AbortController | null>(null);
  const detailController = useRef<AbortController | null>(null);
  const occurrenceController = useRef<AbortController | null>(null);
  const entitlementController = useRef<AbortController | null>(null);
  const listGeneration = useRef(0);
  const detailGeneration = useRef(0);
  const occurrenceGeneration = useRef(0);
  const operationKeys = useRef(new Map<string, string>());
  const mutationGeneration = useRef(0);
  // The append base is read through a ref so the occurrence loader stays stable
  // across renders. Reading it from state would make this callback change on
  // every load, and its effect would reload in a loop.
  const occurrencesRef = useRef<OccurrenceCollection>(occurrences);

  useEffect(() => {
    selectedAutomationIdRef.current = selectedAutomationId;
  }, [selectedAutomationId]);

  useEffect(() => {
    occurrencesRef.current = occurrences;
  }, [occurrences]);

  useEffect(() => {
    mutationGeneration.current += 1;
    operationKeys.current.clear();
    setPendingAction(null);
    setBusyAction(null);
    setActionError(null);
    setNotice(null);
    setCreateOpen(false);
    setStatusFilter("");
    setOccurrenceFilter("");
    setSelectedAutomationId(null);
    selectedAutomationIdRef.current = null;
    return () => {
      mutationGeneration.current += 1;
    };
  }, [orgId]);

  const refreshAutomations = useCallback(
    async (options: { append?: boolean; cursor?: string } = {}) => {
      const appending = options.append === true;
      listController.current?.abort();
      const controller = new AbortController();
      listController.current = controller;
      const generation = ++listGeneration.current;

      setCollection((current) => ({
        ...current,
        orgId,
        status:
          appending || (current.orgId === orgId && current.items.length > 0)
            ? "refreshing"
            : "loading",
        error: null,
      }));

      try {
        const page = await client.listAutomations(
          orgId,
          {
            limit: AUTOMATION_PAGE_LIMIT,
            ...(options.cursor ? { cursor: options.cursor } : {}),
            ...(statusFilter ? { status: statusFilter } : {}),
          },
          controller.signal,
        );
        if (controller.signal.aborted || generation !== listGeneration.current) return;
        const currentSelection = selectedAutomationIdRef.current;
        const nextSelection =
          currentSelection && page.items.some((item) => item.automation_id === currentSelection)
            ? currentSelection
            : (page.items[0]?.automation_id ?? null);
        setSelectedAutomationId(nextSelection);
        selectedAutomationIdRef.current = nextSelection;
        setCollection((current) => ({
          orgId,
          status: "ready",
          items: appending ? [...current.items, ...page.items] : page.items,
          nextCursor: page.next_cursor,
          hasMore: page.has_more,
          error: null,
        }));
      } catch (error) {
        if (controller.signal.aborted || generation !== listGeneration.current) return;
        setCollection((current) => ({
          ...(current.orgId === orgId ? current : emptyCollection(orgId)),
          status: current.orgId === orgId && current.items.length > 0 ? "ready" : "error",
          error,
        }));
      }
    },
    [client, orgId, statusFilter],
  );

  const refreshEntitlements = useCallback(async () => {
    entitlementController.current?.abort();
    const controller = new AbortController();
    entitlementController.current = controller;
    setEntitlements({ orgId, status: "loading", value: null, error: null });
    try {
      const value = await client.getEntitlements(orgId, controller.signal);
      if (controller.signal.aborted) return;
      setEntitlements({ orgId, status: "ready", value, error: null });
    } catch (error) {
      if (controller.signal.aborted) return;
      setEntitlements({ orgId, status: "error", value: null, error });
    }
  }, [client, orgId]);

  const loadOccurrences = useCallback(
    async (automationId: string, options: { append?: boolean; cursor?: string } = {}) => {
      const appending = options.append === true;
      const previous = occurrencesRef.current;
      const canAppend = appending && previous.automationId === automationId;
      const previousItems = canAppend ? previous.items : [];
      const filter = occurrenceFilter;
      occurrenceController.current?.abort();
      const controller = new AbortController();
      occurrenceController.current = controller;
      const generation = ++occurrenceGeneration.current;

      setOccurrences({
        orgId,
        automationId,
        status: canAppend ? "refreshing" : "loading",
        items: previousItems,
        nextCursor: canAppend ? previous.nextCursor : null,
        hasMore: canAppend ? previous.hasMore : false,
        error: null,
        ambiguousCount: canAppend ? previous.ambiguousCount : 0,
      });

      try {
        const page = await client.listOccurrences(
          orgId,
          automationId,
          {
            limit: AUTOMATION_PAGE_LIMIT,
            ...(options.cursor ? { cursor: options.cursor } : {}),
            ...(filter ? { state: filter } : {}),
          },
          controller.signal,
        );
        if (controller.signal.aborted || generation !== occurrenceGeneration.current) return;
        const items = [...previousItems, ...page.items];
        setOccurrences({
          orgId,
          automationId,
          status: "ready",
          items,
          nextCursor: page.next_cursor,
          hasMore: page.has_more,
          error: null,
          ambiguousCount: items.filter((item) => item.state === "ambiguous").length,
        });
      } catch (error) {
        if (controller.signal.aborted || generation !== occurrenceGeneration.current) return;
        setOccurrences((current) => ({
          ...current,
          orgId,
          automationId,
          status: "error",
          error,
          nextCursor: null,
          hasMore: false,
        }));
      }
    },
    [client, occurrenceFilter, orgId],
  );

  useEffect(() => {
    void refreshAutomations();
    return () => {
      listController.current?.abort();
      listGeneration.current += 1;
    };
  }, [refreshAutomations, refreshKey]);

  useEffect(() => {
    void refreshEntitlements();
    return () => {
      entitlementController.current?.abort();
    };
  }, [refreshEntitlements]);

  useEffect(() => {
    detailController.current?.abort();
    const generation = ++detailGeneration.current;
    if (!selectedAutomationId) {
      setDetail(emptyDetail(orgId));
      return;
    }
    const controller = new AbortController();
    detailController.current = controller;
    setDetail({ orgId, id: selectedAutomationId, status: "loading", value: null, error: null });
    void client
      .getAutomation(orgId, selectedAutomationId, controller.signal)
      .then((value) => {
        if (controller.signal.aborted || generation !== detailGeneration.current) return;
        setDetail({ orgId, id: selectedAutomationId, status: "ready", value, error: null });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted || generation !== detailGeneration.current) return;
        setDetail({ orgId, id: selectedAutomationId, status: "error", value: null, error });
      });
    return () => controller.abort();
  }, [client, orgId, refreshKey, selectedAutomationId]);

  useEffect(() => {
    if (!selectedAutomationId) {
      occurrenceController.current?.abort();
      setOccurrences(emptyOccurrences(orgId, null));
      return;
    }
    void loadOccurrences(selectedAutomationId);
    return () => {
      occurrenceController.current?.abort();
      occurrenceGeneration.current += 1;
    };
  }, [loadOccurrences, orgId, selectedAutomationId]);

  function operationKey(actionOrgId: string, kind: LifecycleAction, automationId: string): string {
    const mapKey = `${actionOrgId}:${kind}:${automationId}`;
    const existing = operationKeys.current.get(mapKey);
    if (existing) return existing;
    const created = crypto.randomUUID();
    operationKeys.current.set(mapKey, created);
    return created;
  }

  function openAction(kind: LifecycleAction, automation: AutomationDefinition) {
    setActionError(null);
    setNotice(null);
    setPendingAction({ kind, automation });
  }

  function selectAutomation(automationId: string) {
    setSelectedAutomationId(automationId);
    selectedAutomationIdRef.current = automationId;
    setActionError(null);
    setNotice(null);
  }

  async function confirmAction() {
    if (!pendingAction || busyAction) return;
    const { kind, automation } = pendingAction;
    const actionOrgId = orgId;
    const generation = ++mutationGeneration.current;
    const mapKey = `${actionOrgId}:${kind}:${automation.automation_id}`;
    const key = operationKey(actionOrgId, kind, automation.automation_id);
    const isCurrent = () =>
      mutationGeneration.current === generation && orgIdRef.current === actionOrgId;
    setBusyAction(kind);
    setActionError(null);

    try {
      if (kind === "delete") {
        await client.deleteAutomation(
          actionOrgId,
          automation.automation_id,
          { version: automation.version },
          key,
        );
        if (!isCurrent()) return;
        operationKeys.current.delete(mapKey);
        setNotice(
          "The automation was deleted. Dispatch stops immediately, the definition is tombstoned, and its schedule revision and occurrence history are retained for their retention window. It is not recoverable from this control plane.",
        );
        setPendingAction(null);
        setSelectedAutomationId(null);
        selectedAutomationIdRef.current = null;
        setRefreshKey((value) => value + 1);
        return;
      }

      if (kind === "run_now") {
        const occurrence = await client.runAutomationNow(
          actionOrgId,
          automation.automation_id,
          { version: automation.version },
          key,
        );
        if (!isCurrent()) return;
        operationKeys.current.delete(mapKey);
        setNotice(
          `One manual occurrence was created (${occurrence.occurrence_id}). It is dispatched on its own logical identity and is not treated as a scheduled slot.`,
        );
        setPendingAction(null);
        setRefreshKey((value) => value + 1);
        return;
      }

      const updated =
        kind === "pause"
          ? await client.pauseAutomation(
              actionOrgId,
              automation.automation_id,
              { version: automation.version },
              key,
            )
          : await client.resumeAutomation(
              actionOrgId,
              automation.automation_id,
              { version: automation.version },
              key,
            );
      if (!isCurrent()) return;
      operationKeys.current.delete(mapKey);
      setNotice(
        kind === "pause"
          ? "Dispatch is paused. No new occurrence is created while the pause lasts, a manual run-now is refused, and an occurrence that is already leased or started continues under its own lease."
          : "Dispatch resumed. The server re-checked membership, device eligibility, tool policy, model route, budget, and entitlement, and the schedule cursor restarted from the resume instant.",
      );
      setPendingAction(null);
      setCollection((current) => ({
        ...current,
        items: current.items.map((item) =>
          item.automation_id === updated.automation_id ? updated : item,
        ),
      }));
      setDetail((current) =>
        current.id === updated.automation_id
          ? { ...current, status: "ready", value: updated, error: null }
          : current,
      );
      setRefreshKey((value) => value + 1);
    } catch (error) {
      if (!isCurrent()) return;
      if (isAutomationConflict(error)) {
        operationKeys.current.delete(mapKey);
        setRefreshKey((value) => value + 1);
      }
      setActionError(error);
    } finally {
      if (isCurrent()) setBusyAction(null);
    }
  }

  const visible: AutomationCollection =
    collection.orgId === orgId ? collection : emptyCollection(orgId);
  const visibleDetail: DetailState =
    detail.orgId === orgId && detail.id === selectedAutomationId
      ? detail
      : {
          orgId,
          id: selectedAutomationId,
          status: selectedAutomationId ? "loading" : "idle",
          value: null,
          error: null,
        };
  const visibleOccurrences: OccurrenceCollection =
    occurrences.orgId === orgId && occurrences.automationId === selectedAutomationId
      ? occurrences
      : emptyOccurrences(orgId, selectedAutomationId);
  const visibleEntitlements: EntitlementState =
    entitlements.orgId === orgId
      ? entitlements
      : { orgId, status: "idle", value: null, error: null };
  const limit = automationLimitState(visible.items, visibleEntitlements.value, visible.hasMore);
  const busy = busyAction !== null;

  return (
    <section aria-labelledby={`${panelId}-title`} className="space-y-5">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-xs font-semibold tracking-[0.1em] text-[var(--lumi-blue)]">
            AGENTS / AUTOMATIONS
          </p>
          <h2
            id={`${panelId}-title`}
            className="mt-2 text-2xl font-semibold tracking-[-0.03em] text-[var(--civic-navy)]"
          >
            Automations
          </h2>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-[var(--muted-strong)]">
            Scheduled, manual, and off-peak execution for this organization. The server owns the
            schedule cursor, lease claims, and dispatch decisions; this view reports the state it
            stores.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            className={secondaryButton}
            onClick={() => setRefreshKey((value) => value + 1)}
            disabled={visible.status === "refreshing"}
          >
            {visible.status === "refreshing" ? "Refreshing…" : "Refresh"}
          </button>
          {canManage ? (
            <button type="button" className={primaryButton} onClick={() => setCreateOpen(true)}>
              New automation
            </button>
          ) : null}
        </div>
      </header>

      <LimitBar
        status={visibleEntitlements.status}
        error={visibleEntitlements.error}
        state={limit}
      />

      {notice ? <Notice tone="success">{notice}</Notice> : null}

      <Panel ariaLabel="Automation list">
        <PanelHeader
          title="Definitions"
          description="Select an automation to inspect its canonical schedule, target, policy constraints, and occurrence history."
        />
        <div className="flex flex-col gap-3 border-b border-[var(--border)] px-5 py-4 sm:flex-row sm:items-end sm:justify-between">
          <Field label="Status" id={`${panelId}-status-filter`}>
            {({ id }) => (
              <select
                id={id}
                value={statusFilter}
                onChange={(event) => {
                  const value = event.target.value;
                  setStatusFilter(value === "" ? "" : (value as AutomationStatus));
                }}
                className={inputClass}
              >
                <option value="">All statuses</option>
                {(Object.keys(AUTOMATION_STATUS_LABELS) as AutomationStatus[]).map((status) => (
                  <option key={status} value={status}>
                    {AUTOMATION_STATUS_LABELS[status]}
                  </option>
                ))}
              </select>
            )}
          </Field>
          <p className="text-xs text-[var(--muted)]" aria-live="polite">
            {visible.status === "refreshing"
              ? "Refreshing automations…"
              : `${visible.items.length} automation${visible.items.length === 1 ? "" : "s"} loaded`}
          </p>
        </div>

        {visible.status === "loading" || visible.status === "idle" ? (
          <Loading label="Loading automations…" rows={4} />
        ) : visible.status === "error" && visible.items.length === 0 ? (
          isPermissionFailure(visible.error) ? (
            <PermissionState resource="automations" />
          ) : (
            <div className="p-5">
              <ErrorState
                error={visible.error}
                title="Automations could not be loaded"
                onRetry={() => setRefreshKey((value) => value + 1)}
              />
            </div>
          )
        ) : visible.items.length === 0 ? (
          <EmptyState
            title="No automations match this filter"
            copy="This organization has no automation with the selected status. An automation always belongs to an organization and a project."
          />
        ) : (
          <>
            {visible.error ? (
              <div className="border-b border-[var(--danger)]/20 bg-[var(--danger)]/5 px-5 py-3">
                <ErrorState
                  error={visible.error}
                  title="Could not refresh automations"
                  onRetry={() => setRefreshKey((value) => value + 1)}
                  compact
                />
              </div>
            ) : null}
            <div className="overflow-x-auto">
              <table className="w-full min-w-[900px] text-left text-sm">
                <caption className="sr-only">Organization automations</caption>
                <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
                  <tr>
                    <th scope="col" className="px-5 py-3 font-medium">
                      Automation
                    </th>
                    <th scope="col" className="px-5 py-3 font-medium">
                      Status
                    </th>
                    <th scope="col" className="px-5 py-3 font-medium">
                      Schedule
                    </th>
                    <th scope="col" className="px-5 py-3 font-medium">
                      Next run
                    </th>
                    <th scope="col" className="px-5 py-3 font-medium">
                      Last run
                    </th>
                    <th scope="col" className="px-5 py-3 font-medium">
                      Target
                    </th>
                    <th scope="col" className="px-5 py-3 font-medium">
                      Details
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border)]">
                  {visible.items.map((automation) => (
                    <AutomationRow
                      key={automation.automation_id}
                      automation={automation}
                      selected={selectedAutomationId === automation.automation_id}
                      onSelect={selectAutomation}
                    />
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[var(--border)] px-5 py-3">
              <p className="text-xs text-[var(--muted)]" aria-live="polite">
                {visible.items.length} loaded{visible.hasMore ? " · more available" : ""}
              </p>
              {visible.hasMore ? (
                <button
                  type="button"
                  className={secondaryButton}
                  disabled={visible.status === "refreshing"}
                  onClick={() => {
                    if (!visible.nextCursor) return;
                    void refreshAutomations({ append: true, cursor: visible.nextCursor });
                  }}
                >
                  {visible.status === "refreshing" ? "Loading…" : "Load more"}
                </button>
              ) : null}
            </div>
          </>
        )}
      </Panel>

      {visibleDetail.id ? (
        <AutomationDetail
          detail={visibleDetail}
          canManage={canManage}
          canRun={effectiveCanRun}
          busy={busy}
          onPause={(automation) => openAction("pause", automation)}
          onResume={(automation) => openAction("resume", automation)}
          onRunNow={(automation) => openAction("run_now", automation)}
          onDelete={(automation) => openAction("delete", automation)}
        />
      ) : (
        <Panel ariaLabel="Selected automation">
          <EmptyState
            title="Select an automation"
            copy="Its canonical schedule, target, execution policy, off-peak class, and occurrence history appear here."
          />
        </Panel>
      )}

      {selectedAutomationId ? (
        <OccurrenceHistory
          occurrences={visibleOccurrences.items}
          loading={visibleOccurrences.status === "loading" || visibleOccurrences.status === "idle"}
          refreshing={visibleOccurrences.status === "refreshing"}
          error={visibleOccurrences.error}
          hasMore={visibleOccurrences.hasMore}
          filter={occurrenceFilter}
          ambiguousCount={visibleOccurrences.ambiguousCount}
          onFilterChange={(next) => {
            // Setting the filter re-runs the occurrence effect with the new value.
            setOccurrenceFilter(next);
          }}
          onRetry={() => void loadOccurrences(selectedAutomationId)}
          onLoadMore={() => {
            if (!visibleOccurrences.nextCursor) return;
            void loadOccurrences(selectedAutomationId, {
              append: true,
              cursor: visibleOccurrences.nextCursor,
            });
          }}
        />
      ) : null}

      <LifecycleDialog
        action={pendingAction}
        busy={busyAction}
        error={actionError}
        onClose={() => {
          if (!busyAction) setPendingAction(null);
        }}
        onConfirm={() => void confirmAction()}
      />

      <CreateAutomationDialog
        open={createOpen}
        orgId={orgId}
        client={client}
        onClose={() => setCreateOpen(false)}
        onCreated={(automation) => {
          setCreateOpen(false);
          selectAutomation(automation.automation_id);
          setNotice(
            "The automation was created. The server stores the canonical schedule and advances the schedule cursor from the creation instant.",
          );
          setRefreshKey((value) => value + 1);
        }}
      />
    </section>
  );
}

function LimitBar({
  status,
  error,
  state,
}: {
  status: LoadStatus;
  error: unknown;
  state: ReturnType<typeof automationLimitState>;
}) {
  if (status === "loading" || status === "idle") {
    return (
      <Panel ariaLabel="Automation entitlement limit">
        <Loading label="Reading the automation entitlement limit…" rows={1} />
      </Panel>
    );
  }
  return (
    <Panel ariaLabel="Automation entitlement limit">
      <div className="flex flex-col gap-2 px-5 py-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <p className="text-sm font-semibold text-[var(--civic-navy)]">{state.headline}</p>
          <p className="mt-1 max-w-3xl text-xs leading-5 text-[var(--muted-strong)]">
            {state.detail}
          </p>
          {status === "error" ? (
            <p className="mt-1 text-xs leading-5 text-[var(--danger)]">
              The entitlement projection could not be read, so the limit below is unknown. The
              server still enforces it on every create, resume, and dispatch.
            </p>
          ) : null}
        </div>
        {state.limit !== null ? (
          <Pill tone={state.atLimit ? "warning" : "muted"}>{state.limit} max</Pill>
        ) : null}
      </div>
      {status === "error" ? (
        <div className="border-t border-[var(--danger)]/20 bg-[var(--danger)]/5 px-5 py-3">
          <ErrorState error={error} title="Entitlement projection unavailable" compact />
        </div>
      ) : null}
    </Panel>
  );
}

function AutomationRow({
  automation,
  selected,
  onSelect,
}: {
  automation: AutomationDefinition;
  selected: boolean;
  onSelect: (automationId: string) => void;
}) {
  return (
    <tr className={selected ? "bg-[var(--lumi-blue-soft)]/55" : "bg-[var(--panel)]"}>
      <td className="px-5 py-4">
        <button
          type="button"
          onClick={() => onSelect(automation.automation_id)}
          aria-pressed={selected}
          aria-label={`View ${automation.name}`}
          className="max-w-[20rem] text-left outline-none focus-visible:rounded-md focus-visible:ring-2 focus-visible:ring-[var(--ring)]"
        >
          <span className="block font-medium text-[var(--civic-navy)]">{automation.name}</span>
          <span className="mt-1 block break-all font-mono text-xs text-[var(--muted)]">
            {automation.automation_id}
          </span>
        </button>
      </td>
      <td className="px-5 py-4">
        <Pill tone={automation.status === "active" ? "success" : "neutral"}>
          {AUTOMATION_STATUS_LABELS[automation.status]}
        </Pill>
        {automation.off_peak_policy ? (
          <span className="mt-1 block text-xs text-[var(--muted)]">
            off-peak · {offPeakEligibilityLabel(automation.off_peak_policy)}
          </span>
        ) : null}
      </td>
      <td className="px-5 py-4 text-xs text-[var(--muted-strong)]">
        <span className="block font-mono">{describeSchedule(automation.schedule)}</span>
        <span className="mt-1 block">{describeSchedulePolicy(automation.schedule)}</span>
      </td>
      <td className="px-5 py-4 text-xs tabular-nums text-[var(--muted-strong)]">
        {formatInstant(automation.next_run_at)}
      </td>
      <td className="px-5 py-4 text-xs tabular-nums text-[var(--muted-strong)]">
        {formatInstant(automation.last_run_at)}
      </td>
      <td className="px-5 py-4 text-xs text-[var(--muted-strong)]">
        <span className="block">{targetSummary(automation)}</span>
        <span className="mt-1 block font-mono text-xs text-[var(--muted)]">
          {automation.project_id ?? "no project"}
        </span>
      </td>
      <td className="px-5 py-4">
        <button
          type="button"
          className={selected ? primaryButton : secondaryButton}
          onClick={() => onSelect(automation.automation_id)}
          aria-pressed={selected}
        >
          {selected ? "Selected" : "View"}
        </button>
      </td>
    </tr>
  );
}

function AutomationDetail({
  detail,
  canManage,
  canRun,
  busy,
  onPause,
  onResume,
  onRunNow,
  onDelete,
}: {
  detail: DetailState;
  canManage: boolean;
  canRun: boolean;
  busy: boolean;
  onPause: (automation: AutomationDefinition) => void;
  onResume: (automation: AutomationDefinition) => void;
  onRunNow: (automation: AutomationDefinition) => void;
  onDelete: (automation: AutomationDefinition) => void;
}) {
  if (detail.status === "loading" || detail.status === "idle") {
    return (
      <Panel ariaLabel="Loading automation details">
        <Loading label="Loading automation details…" rows={4} />
      </Panel>
    );
  }
  if (detail.status === "error" || !detail.value) {
    return isPermissionFailure(detail.error) ? (
      <PermissionState resource="this automation" />
    ) : (
      <ErrorState error={detail.error} title="Automation details unavailable" />
    );
  }

  const automation = detail.value;
  const active = automation.status === "active";

  return (
    <div className="space-y-5">
      <Panel ariaLabel="Selected automation details">
        <PanelHeader
          title={automation.name}
          description={
            automation.description ??
            "The server stores the canonical schedule, resolves the execution principal and target, and advances the cursor transactionally with due-occurrence generation."
          }
          action={
            <div className="flex flex-wrap gap-2">
              {canRun ? (
                <button
                  type="button"
                  className={primaryButton}
                  onClick={() => onRunNow(automation)}
                  disabled={busy || !active}
                  title={
                    active
                      ? "Create one manual occurrence"
                      : "Run now is refused by the server while dispatch is paused"
                  }
                >
                  Run now
                </button>
              ) : null}
              {canManage ? (
                active ? (
                  <button
                    type="button"
                    className={secondaryButton}
                    onClick={() => onPause(automation)}
                    disabled={busy}
                  >
                    Pause
                  </button>
                ) : (
                  <button
                    type="button"
                    className={secondaryButton}
                    onClick={() => onResume(automation)}
                    disabled={busy}
                  >
                    Resume
                  </button>
                )
              ) : null}
              {canManage ? (
                <button
                  type="button"
                  className={dangerButton}
                  onClick={() => onDelete(automation)}
                  disabled={busy}
                >
                  Delete
                </button>
              ) : null}
            </div>
          }
        />
        <dl className="grid gap-x-6 gap-y-5 px-5 py-4 sm:grid-cols-2 lg:grid-cols-3">
          <Metadata label="Automation" value={automation.automation_id} mono />
          <Metadata label="Version" value={String(automation.version)} />
          <Metadata label="Status" value={AUTOMATION_STATUS_LABELS[automation.status]} />
          <Metadata label="Project" value={automation.project_id ?? "Not recorded"} mono />
          <Metadata label="Agent definition" value={automation.agent_definition_id} mono />
          <Metadata label="Execution principal" value={principalSummary(automation)} mono />
          <Metadata label="Target" value={targetSummary(automation)} />
          <Metadata
            label="Required capabilities"
            value={
              automation.target.required_capabilities.length > 0
                ? automation.target.required_capabilities.join(", ")
                : "None recorded"
            }
          />
          <Metadata label="Next run" value={formatInstant(automation.next_run_at)} />
          <Metadata label="Last run" value={formatInstant(automation.last_run_at)} />
          <Metadata label="Schedule cursor" value={formatInstant(automation.schedule_cursor_at)} />
          <Metadata
            label="Next run instant (UTC)"
            value={formatInstantUtc(automation.next_run_at)}
          />
          <Metadata label="Execution policy" value={executionPolicySummary(automation)} />
          <Metadata
            label="Tool policy scope"
            value={toolPolicyScopeLabel(automation.execution_policy.tool_policy_scope)}
          />
          <Metadata
            label="Model alias"
            value={
              automation.execution_policy.model_alias ?? "Inherit the agent or project default"
            }
            mono={automation.execution_policy.model_alias !== null}
          />
          <Metadata
            label="Budget"
            value={automation.execution_policy.budget_id ?? "Inherit default"}
            mono={automation.execution_policy.budget_id !== null}
          />
          <Metadata
            label="Required policy version"
            value={
              automation.execution_policy.required_policy_version === null
                ? "Current policy accepted"
                : String(automation.execution_policy.required_policy_version)
            }
          />
          <Metadata
            label="Start attempts"
            value={`${automation.execution_retry.max_start_attempts} (1–3)`}
          />
          <Metadata
            label="Lease TTL"
            value={`${automation.execution_retry.lease_ttl_seconds}s (30–3600)`}
          />
          <Metadata
            label="Heartbeat"
            value={`${automation.execution_retry.heartbeat_interval_seconds}s (10–60)`}
          />
        </dl>
        <div className="border-t border-[var(--border)] bg-[var(--panel-hover)] px-5 py-3 text-xs leading-5 text-[var(--muted-strong)]">
          <p>
            These are constraints, not authority. The server re-checks membership, service identity,
            device health and capability, tool policy, model route, budget, and entitlement
            immediately before it creates a run. A null model or budget means inherit; a supplied
            value may only narrow or select an already-authorized route.
          </p>
          {!active && canRun ? (
            <p className="mt-1">
              Dispatch is paused, so the server refuses a manual run-now for this automation.
            </p>
          ) : null}
        </div>
      </Panel>

      <Panel ariaLabel="Canonical schedule">
        <PanelHeader
          title="Canonical schedule"
          description="This is the rule the server stores and normalizes. Occurrence identity comes from the UTC instant, never from the displayed expression."
        />
        <dl className="grid gap-x-6 gap-y-5 px-5 py-4 sm:grid-cols-2">
          <Metadata label="Schedule" value={describeSchedule(automation.schedule)} />
          <Metadata
            label="Window and selectors"
            value={describeScheduleWindow(automation.schedule)}
          />
          <Metadata label="Policy summary" value={describeSchedulePolicy(automation.schedule)} />
          <Metadata
            label="Overlap detail"
            value={overlapPolicyDetail(automation.schedule.overlap_policy)}
          />
          <Metadata
            label="Missed detail"
            value={missedPolicyDetail(
              automation.schedule.missed_policy,
              automation.schedule.catch_up_limit,
            )}
          />
        </dl>
        <div className="border-t border-[var(--border)] px-5 py-3 text-xs leading-5 text-[var(--muted-strong)]">
          Editing or rolling back a schedule mints a new immutable revision, so the new revision has
          its own logical occurrence slots and its own history.
        </div>
      </Panel>

      <OffPeakCard policy={automation.off_peak_policy} />
    </div>
  );
}

function LifecycleDialog({
  action,
  busy,
  error,
  onClose,
  onConfirm,
}: {
  action: PendingAction | null;
  busy: LifecycleAction | null;
  error: unknown;
  onClose: () => void;
  onConfirm: () => void;
}) {
  const dialogRef = useRef<HTMLDialogElement | null>(null);
  const titleId = useId();
  const descriptionId = useId();

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (action && !dialog.open) dialog.showModal();
    if (!action && dialog.open) dialog.close();
  }, [action]);

  return (
    <dialog
      ref={dialogRef}
      aria-labelledby={action ? titleId : undefined}
      aria-describedby={action ? descriptionId : undefined}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      className="m-auto w-[calc(100%-2rem)] max-w-lg rounded-xl border border-[var(--border)] bg-[var(--panel)] p-0 text-[var(--foreground)] shadow-[var(--shadow)] backdrop:bg-[var(--civic-navy)]/35"
    >
      {action ? (
        <div className="p-6">
          <p className="text-xs font-semibold tracking-[0.1em] text-[var(--lumi-blue)]">
            {LIFECYCLE_ACTION_COPY[action.kind].eyebrow}
          </p>
          <h2 id={titleId} className="mt-2 text-lg font-semibold text-[var(--civic-navy)]">
            {LIFECYCLE_ACTION_COPY[action.kind].title}
          </h2>
          <div
            id={descriptionId}
            className="mt-3 space-y-3 text-sm leading-6 text-[var(--muted-strong)]"
          >
            <p className="break-all font-mono text-xs text-[var(--civic-navy)]">
              {action.automation.automation_id} · version {action.automation.version}
            </p>
            <p>{LIFECYCLE_ACTION_COPY[action.kind].body}</p>
            <p className="text-xs text-[var(--muted)]">
              Schedule: {describeSchedule(action.automation.schedule)}.{" "}
              {describeSchedulePolicy(action.automation.schedule)}.
            </p>
          </div>
          {error ? (
            <div className="mt-4 rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/5 p-3 text-sm text-[var(--danger)]">
              <p className="font-medium">{automationActionErrorMessage(error)}</p>
            </div>
          ) : null}
          <div className="mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <button
              type="button"
              className={secondaryButton}
              onClick={onClose}
              disabled={busy !== null}
              autoFocus
            >
              {LIFECYCLE_ACTION_COPY[action.kind].cancelLabel}
            </button>
            <button
              type="button"
              className={action.kind === "delete" ? dangerButton : primaryButton}
              onClick={onConfirm}
              disabled={busy !== null}
            >
              {busy !== null
                ? LIFECYCLE_ACTION_COPY[action.kind].busyLabel
                : LIFECYCLE_ACTION_COPY[action.kind].confirmLabel}
            </button>
          </div>
        </div>
      ) : null}
    </dialog>
  );
}

/**
 * Consequence copy for every lifecycle action. Each body states what the server
 * does, what the operator keeps, and what cannot be undone, before the action is
 * confirmed. Exported so the copy is covered by a test rather than by review.
 */
export const LIFECYCLE_ACTION_COPY: Record<
  LifecycleAction,
  {
    eyebrow: string;
    title: string;
    body: string;
    confirmLabel: string;
    busyLabel: string;
    cancelLabel: string;
  }
> = {
  pause: {
    eyebrow: "PAUSE DISPATCH",
    title: "Pause new dispatch?",
    body: "No new occurrence is dispatched while this automation is paused, and a manual run-now is refused. An occurrence that is already leased or started continues under its own lease. The schedule revision and occurrence history are unchanged.",
    confirmLabel: "Pause dispatch",
    busyLabel: "Pausing…",
    cancelLabel: "Keep dispatching",
  },
  resume: {
    eyebrow: "RESUME DISPATCH",
    title: "Resume dispatch?",
    body: "Dispatch resumes after the server re-checks current membership, device eligibility, tool policy, model route, budget, and entitlement. The schedule cursor restarts from the resume instant, so a long pause cannot produce a replay burst.",
    confirmLabel: "Resume dispatch",
    busyLabel: "Resuming…",
    cancelLabel: "Stay paused",
  },
  run_now: {
    eyebrow: "RUN NOW",
    title: "Create one manual occurrence?",
    body: "This creates exactly one manual occurrence, identified by the authorized run-now idempotency key rather than a client-supplied ID. It is dispatched on its own logical identity instead of a scheduled slot, and it consumes whatever the current budget and entitlement allow.",
    confirmLabel: "Create occurrence",
    busyLabel: "Creating…",
    cancelLabel: "Do not run",
  },
  delete: {
    eyebrow: "DELETE AUTOMATION",
    title: "Delete this automation?",
    body: "Deletion is permanent and cannot be undone. The server stops dispatch, clears the next run, and tombstones the definition. The schedule revision and occurrence history are retained for their retention window for audit, and the definition cannot be recovered from this control plane. An occurrence that is already leased or started is handled by its own lease state.",
    confirmLabel: "Delete permanently",
    busyLabel: "Deleting…",
    cancelLabel: "Keep automation",
  },
};

function CreateAutomationDialog({
  open,
  orgId,
  client,
  onClose,
  onCreated,
}: {
  open: boolean;
  orgId: string;
  client: AutomationsApiClient;
  onClose: () => void;
  onCreated: (automation: AutomationDefinition) => void;
}) {
  const dialogRef = useRef<HTMLDialogElement | null>(null);
  const id = useId();
  const [draft, setDraft] = useState<ScheduleDraft>(() => createScheduleDraft());
  const [name, setName] = useState("");
  const [projectId, setProjectId] = useState("");
  const [agentDefinitionId, setAgentDefinitionId] = useState("");
  const [targetKind, setTargetKind] = useState<TargetKind>("eligible_device");
  const [workspaceBindingId, setWorkspaceBindingId] = useState("");
  const [requiredCapabilities, setRequiredCapabilities] = useState("");
  const [modelAlias, setModelAlias] = useState("");
  const [toolPolicyScope, setToolPolicyScope] = useState<ToolPolicyScope>("project");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [nameError, setNameError] = useState<string | undefined>(undefined);
  const [projectError, setProjectError] = useState<string | undefined>(undefined);
  const [agentError, setAgentError] = useState<string | undefined>(undefined);

  // The live preview validates bounds only. Resolving the zone costs one `Intl`
  // formatter per sample, so it happens once on submit instead of per keystroke.
  const built = buildSchedulePayload(draft, { includeZone: false });
  const issues: readonly ScheduleIssue[] = built.ok ? [] : built.issues;

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  async function submit() {
    if (busy) return;
    const trimmedName = name.trim();
    const trimmedProject = projectId.trim();
    const trimmedAgent = agentDefinitionId.trim();
    setNameError(trimmedName === "" ? "Enter a name for this automation." : undefined);
    setProjectError(
      trimmedProject === "" ? "Enter the project that owns this automation." : undefined,
    );
    setAgentError(trimmedAgent === "" ? "Enter the agent definition to run." : undefined);
    if (trimmedName === "" || trimmedProject === "" || trimmedAgent === "") return;
    if (!built.ok) return;
    // The submitted payload carries the client-resolved zone table, because a
    // Worker links no timezone database and the server requires it for a named
    // zone. The server validates the whole table.
    const submitted = buildSchedulePayload(draft);
    if (!submitted.ok) return;

    setBusy(true);
    setError(null);
    try {
      const capabilities = requiredCapabilities
        .split(",")
        .map((item) => item.trim())
        .filter((item) => item !== "");
      const input: CreateAutomationInput = {
        name: trimmedName,
        project_id: trimmedProject,
        agent_definition_id: trimmedAgent,
        execution_principal: { kind: "user" },
        target: {
          kind: targetKind,
          ...(workspaceBindingId.trim() === ""
            ? {}
            : { workspace_binding_id: workspaceBindingId.trim() }),
          ...(capabilities.length > 0 ? { required_capabilities: capabilities } : {}),
        },
        schedule: submitted.payload,
        execution_policy: {
          ...(modelAlias.trim() === "" ? {} : { model_alias: modelAlias.trim() }),
          tool_policy_scope: toolPolicyScope,
        },
      };
      const created = await client.createAutomation(orgId, input, crypto.randomUUID());
      onCreated(created);
      setName("");
      setProjectId("");
      setAgentDefinitionId("");
      setWorkspaceBindingId("");
      setRequiredCapabilities("");
      setModelAlias("");
      setDraft(createScheduleDraft());
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  return (
    <dialog
      ref={dialogRef}
      aria-labelledby={`${id}-title`}
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) onClose();
      }}
      className="m-auto max-h-[90dvh] w-[calc(100%-2rem)] max-w-3xl overflow-y-auto rounded-xl border border-[var(--border)] bg-[var(--panel)] p-0 text-[var(--foreground)] shadow-[var(--shadow)] backdrop:bg-[var(--civic-navy)]/35"
    >
      <div className="p-6">
        <p className="text-xs font-semibold tracking-[0.1em] text-[var(--lumi-blue)]">
          NEW AUTOMATION
        </p>
        <h2 id={`${id}-title`} className="mt-2 text-lg font-semibold text-[var(--civic-navy)]">
          Define an automation
        </h2>
        <p className="mt-2 text-sm leading-6 text-[var(--muted-strong)]">
          The execution principal defaults to you. The server requires a current active membership
          for it and re-evaluates every constraint before dispatch.
        </p>

        <div className="mt-5 grid gap-4 sm:grid-cols-2">
          <Field label="Name" id={`${id}-name`} error={nameError}>
            {({ id: controlId, describedBy, invalid }) => (
              <input
                id={controlId}
                type="text"
                value={name}
                maxLength={160}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                onChange={(event) => setName(event.target.value)}
                className={inputClass}
              />
            )}
          </Field>
          <Field label="Project" id={`${id}-project`} error={projectError}>
            {({ id: controlId, describedBy, invalid }) => (
              <input
                id={controlId}
                type="text"
                value={projectId}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                onChange={(event) => setProjectId(event.target.value)}
                className={`${inputClass} font-mono`}
              />
            )}
          </Field>
          <Field label="Agent definition" id={`${id}-agent`} error={agentError}>
            {({ id: controlId, describedBy, invalid }) => (
              <input
                id={controlId}
                type="text"
                value={agentDefinitionId}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                onChange={(event) => setAgentDefinitionId(event.target.value)}
                className={`${inputClass} font-mono`}
              />
            )}
          </Field>
          <Field label="Execution target" id={`${id}-target`}>
            {({ id: controlId }) => (
              <select
                id={controlId}
                value={targetKind}
                onChange={(event) => setTargetKind(event.target.value as TargetKind)}
                className={inputClass}
              >
                <option value="eligible_device">Any eligible enrolled device</option>
                <option value="specific_device">A specific device</option>
                <option value="remote_workspace">Remote workspace</option>
              </select>
            )}
          </Field>
          <Field
            label="Workspace binding"
            id={`${id}-binding`}
            hint="Optional. A binding must belong to this organization and match the target device."
          >
            {({ id: controlId }) => (
              <input
                id={controlId}
                type="text"
                value={workspaceBindingId}
                onChange={(event) => setWorkspaceBindingId(event.target.value)}
                className={`${inputClass} font-mono`}
              />
            )}
          </Field>
          <Field
            label="Required capabilities"
            id={`${id}-capabilities`}
            hint="Optional. Comma-separated capability names the target must have."
          >
            {({ id: controlId }) => (
              <input
                id={controlId}
                type="text"
                value={requiredCapabilities}
                onChange={(event) => setRequiredCapabilities(event.target.value)}
                className={inputClass}
              />
            )}
          </Field>
          <Field
            label="Model alias"
            id={`${id}-model`}
            hint="Optional. Leave empty to inherit the agent or project default. A value may only narrow or select an already-authorized route."
          >
            {({ id: controlId }) => (
              <input
                id={controlId}
                type="text"
                value={modelAlias}
                onChange={(event) => setModelAlias(event.target.value)}
                className={inputClass}
              />
            )}
          </Field>
          <Field label="Tool policy scope" id={`${id}-scope`}>
            {({ id: controlId }) => (
              <select
                id={controlId}
                value={toolPolicyScope}
                onChange={(event) => setToolPolicyScope(event.target.value as ToolPolicyScope)}
                className={inputClass}
              >
                <option value="project">Project</option>
                <option value="organization">Organization</option>
                <option value="agent">Agent</option>
              </select>
            )}
          </Field>
        </div>

        <div className="mt-6 border-t border-[var(--border)] pt-5">
          <h3 className="text-sm font-semibold text-[var(--civic-navy)]">Schedule</h3>
          <div className="mt-4">
            <ScheduleBuilder draft={draft} onChange={setDraft} issues={issues} />
          </div>
        </div>

        <div className="mt-5">
          {built.ok ? (
            <Notice tone="info">
              <span className="font-semibold">Ready to send:</span> {describePayload(built.payload)}
            </Notice>
          ) : (
            <Notice tone="danger">
              {issues.length} schedule field{issues.length === 1 ? "" : "s"} need attention before
              this automation can be created.
            </Notice>
          )}
        </div>

        {error ? (
          <div className="mt-4 rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/5 p-3 text-sm text-[var(--danger)]">
            <p className="font-medium">{automationActionErrorMessage(error)}</p>
          </div>
        ) : null}

        <div className="mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <button type="button" className={secondaryButton} onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button
            type="button"
            className={primaryButton}
            onClick={() => void submit()}
            disabled={busy || !built.ok}
          >
            {busy ? "Creating…" : "Create automation"}
          </button>
        </div>
      </div>
    </dialog>
  );
}

function emptyCollection(orgId: string): AutomationCollection {
  return { orgId, status: "idle", items: [], nextCursor: null, hasMore: false, error: null };
}

function emptyDetail(orgId: string): DetailState {
  return { orgId, id: null, status: "idle", value: null, error: null };
}

function emptyOccurrences(orgId: string, automationId: string | null): OccurrenceCollection {
  return {
    orgId,
    automationId,
    status: "idle",
    items: [],
    nextCursor: null,
    hasMore: false,
    error: null,
    ambiguousCount: 0,
  };
}
