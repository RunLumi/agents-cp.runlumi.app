import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type KeyboardEvent,
  type RefObject,
} from "react";

import {
  canCancelRun,
  canRetryRun,
  formatBytes,
  formatDateTime,
  formatDuration,
  isAmbiguousRunMutationFailure,
  isPermissionFailure,
  isRunVersionConflict,
  readRunStateFromUrl,
  readSessionFromUrl,
  readSessionLifecycleFromUrl,
  syncRunFiltersToUrl,
  type RunState,
  RUN_STATES,
} from "@/features/runs/run-helpers";
import { RunStatePill } from "@/features/runs/run-state-pill";
import { RunTimeline } from "@/features/runs/run-timeline";
import {
  cancelRun,
  getRun,
  listAgentSessions,
  listRunArtifacts,
  listRunEvents,
  listRuns,
  listUsage,
  retryRun,
  type AgentSession,
  type AgentSessionLifecycle,
  type ArtifactRef,
  type ListRunsQuery,
  type Run,
  type RunEvent,
  type UsageMetadata,
} from "@/lib/api";
import { presentApiError } from "@/lib/errors";

interface RunsPanelProps {
  orgId: string;
}

type TabId = "runs" | "sessions";
type RunAction = "cancel" | "retry";
type LoadStatus = "idle" | "loading" | "refreshing" | "ready" | "error";

const PAGE_SIZE = 40;
const EVENT_PAGE_SIZE = 50;
const ARTIFACT_PAGE_SIZE = 50;

interface Collection<T> {
  orgId: string;
  runId: string | null;
  status: LoadStatus;
  items: T[];
  nextCursor: string | null;
  hasMore: boolean;
  error: unknown;
}

interface DetailState {
  orgId: string;
  runId: string | null;
  status: LoadStatus;
  run: Run | null;
  error: unknown;
}

interface UsageState {
  orgId: string;
  runId: string | null;
  status: LoadStatus;
  items: UsageMetadata[];
  error: unknown;
}

interface ScopedFilter<T> {
  orgId: string;
  value: T;
}

interface PendingAction {
  kind: RunAction;
  run: Run;
}

export function RunsPanel({ orgId }: RunsPanelProps) {
  const panelId = useId();
  const [activeTab, setActiveTab] = useState<TabId>("runs");
  const tabRefs = useRef<Record<TabId, HTMLButtonElement | null>>({ runs: null, sessions: null });
  const detailSectionRef = useRef<HTMLElement | null>(null);

  const [runFilter, setRunFilter] = useState<ScopedFilter<RunState | "">>(() =>
    readRunStateFromUrl(orgId),
  );
  const [sessionFilter, setSessionFilter] = useState<ScopedFilter<string | null>>(() =>
    readSessionFromUrl(orgId),
  );
  const [sessionLifecycle, setSessionLifecycle] = useState<
    ScopedFilter<AgentSessionLifecycle | "">
  >(() => readSessionLifecycleFromUrl(orgId));
  const effectiveRunFilter = runFilter.orgId === orgId ? runFilter.value : "";
  const effectiveSessionFilter = sessionFilter.orgId === orgId ? sessionFilter.value : null;
  const effectiveSessionLifecycle = sessionLifecycle.orgId === orgId ? sessionLifecycle.value : "";

  const [runCollection, setRunCollection] = useState<Collection<Run>>(() => emptyCollection(orgId));
  const [sessionCollection, setSessionCollection] = useState<Collection<AgentSession>>(() =>
    emptyCollection(orgId),
  );
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const selectedRunIdRef = useRef<string | null>(null);
  const [detailRefreshKey, setDetailRefreshKey] = useState(0);
  const [detail, setDetail] = useState<DetailState>(() => emptyDetail(orgId));
  const [events, setEvents] = useState<Collection<RunEvent>>(() => emptyCollection(orgId, null));
  const [artifacts, setArtifacts] = useState<Collection<ArtifactRef>>(() =>
    emptyCollection(orgId, null),
  );
  const [usage, setUsage] = useState<UsageState>({
    orgId,
    runId: null,
    status: "idle",
    items: [],
    error: null,
  });

  const [pendingAction, setPendingAction] = useState<PendingAction | null>(null);
  const [busyAction, setBusyAction] = useState<RunAction | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const operationKeys = useRef(new Map<string, string>());
  const orgIdRef = useRef(orgId);
  const mutationGeneration = useRef(0);
  orgIdRef.current = orgId;

  const runController = useRef<AbortController | null>(null);
  const sessionController = useRef<AbortController | null>(null);
  const detailController = useRef<AbortController | null>(null);
  const eventController = useRef<AbortController | null>(null);
  const artifactController = useRef<AbortController | null>(null);
  const runRequestGeneration = useRef(0);
  const sessionRequestGeneration = useRef(0);
  const detailRequestGeneration = useRef(0);
  const eventRequestGeneration = useRef(0);
  const artifactRequestGeneration = useRef(0);
  const runQueryKey = useRef("");
  const sessionQueryKey = useRef("");

  useEffect(() => {
    selectedRunIdRef.current = selectedRunId;
  }, [selectedRunId]);

  useEffect(() => {
    mutationGeneration.current += 1;
    operationKeys.current.clear();
    setPendingAction(null);
    setBusyAction(null);
    setActionError(null);
    setNotice(null);
    return () => {
      mutationGeneration.current += 1;
    };
  }, [orgId]);

  useEffect(() => {
    syncRunFiltersToUrl(
      orgId,
      effectiveRunFilter,
      effectiveSessionFilter,
      effectiveSessionLifecycle,
    );
  }, [effectiveRunFilter, effectiveSessionFilter, effectiveSessionLifecycle, orgId]);

  useEffect(() => {
    const restoreFromUrl = () => {
      setRunFilter(readRunStateFromUrl(orgId));
      setSessionFilter(readSessionFromUrl(orgId));
      setSessionLifecycle(readSessionLifecycleFromUrl(orgId));
    };
    window.addEventListener("popstate", restoreFromUrl);
    return () => window.removeEventListener("popstate", restoreFromUrl);
  }, [orgId]);

  useEffect(() => {
    if (notice && busyAction === null) detailSectionRef.current?.focus();
  }, [busyAction, notice, selectedRunId]);

  const refreshRuns = useCallback(async () => {
    runController.current?.abort();
    const controller = new AbortController();
    runController.current = controller;
    const generation = ++runRequestGeneration.current;
    const nextQueryKey = `${orgId}:${effectiveRunFilter}:${effectiveSessionFilter ?? ""}`;
    const preserveCurrentPage = runQueryKey.current === nextQueryKey;
    runQueryKey.current = nextQueryKey;

    setRunCollection((current) =>
      preserveCurrentPage && current.orgId === orgId
        ? { ...current, status: "refreshing", error: null }
        : { ...emptyCollection<Run>(orgId), status: "loading" },
    );

    const query: ListRunsQuery = {
      limit: PAGE_SIZE,
      ...(effectiveRunFilter ? { state: effectiveRunFilter } : {}),
      ...(effectiveSessionFilter ? { session_id: effectiveSessionFilter } : {}),
    };

    try {
      const page = await listRuns(orgId, query, controller.signal);
      if (controller.signal.aborted || generation !== runRequestGeneration.current) return;
      const items = page.items;
      const currentSelection = selectedRunIdRef.current;
      const nextSelection =
        currentSelection &&
        items.some((run) => resourceId(run, "id", "run_id") === currentSelection)
          ? currentSelection
          : resourceId(items[0], "id", "run_id");
      setSelectedRunId(nextSelection || null);
      selectedRunIdRef.current = nextSelection || null;
      setRunCollection({
        orgId,
        runId: null,
        status: "ready",
        items,
        nextCursor: page.next_cursor,
        hasMore: page.has_more,
        error: null,
      });
    } catch (error) {
      if (controller.signal.aborted || generation !== runRequestGeneration.current) return;
      setRunCollection((current) => ({
        ...(current.orgId === orgId ? current : emptyCollection(orgId)),
        status: current.orgId === orgId && current.items.length > 0 ? "ready" : "error",
        error,
      }));
    }
  }, [effectiveRunFilter, effectiveSessionFilter, orgId]);

  const loadMoreRuns = useCallback(async () => {
    if (runCollection.orgId !== orgId || !runCollection.hasMore || !runCollection.nextCursor)
      return;
    runController.current?.abort();
    const controller = new AbortController();
    runController.current = controller;
    const generation = ++runRequestGeneration.current;
    setRunCollection((current) => ({ ...current, status: "refreshing", error: null }));

    try {
      const page = await listRuns(
        orgId,
        {
          limit: PAGE_SIZE,
          cursor: runCollection.nextCursor,
          ...(effectiveRunFilter ? { state: effectiveRunFilter } : {}),
          ...(effectiveSessionFilter ? { session_id: effectiveSessionFilter } : {}),
        },
        controller.signal,
      );
      if (controller.signal.aborted || generation !== runRequestGeneration.current) return;
      setRunCollection((current) => ({
        ...current,
        status: "ready",
        items: [...current.items, ...page.items],
        nextCursor: page.next_cursor,
        hasMore: page.has_more,
        error: null,
      }));
    } catch (error) {
      if (controller.signal.aborted || generation !== runRequestGeneration.current) return;
      setRunCollection((current) => ({ ...current, status: "ready", error }));
    }
  }, [
    effectiveRunFilter,
    effectiveSessionFilter,
    orgId,
    runCollection.hasMore,
    runCollection.nextCursor,
    runCollection.orgId,
  ]);

  const refreshSessions = useCallback(async () => {
    sessionController.current?.abort();
    const controller = new AbortController();
    sessionController.current = controller;
    const generation = ++sessionRequestGeneration.current;
    const nextQueryKey = `${orgId}:${effectiveSessionLifecycle}`;
    const preserveCurrentPage = sessionQueryKey.current === nextQueryKey;
    sessionQueryKey.current = nextQueryKey;

    setSessionCollection((current) =>
      preserveCurrentPage && current.orgId === orgId
        ? { ...current, status: "refreshing", error: null }
        : { ...emptyCollection<AgentSession>(orgId), status: "loading" },
    );

    try {
      const page = await listAgentSessions(
        orgId,
        {
          limit: PAGE_SIZE,
          ...(effectiveSessionLifecycle ? { lifecycle: effectiveSessionLifecycle } : {}),
        },
        controller.signal,
      );
      if (controller.signal.aborted || generation !== sessionRequestGeneration.current) return;
      setSessionCollection({
        orgId,
        runId: null,
        status: "ready",
        items: page.items,
        nextCursor: page.next_cursor,
        hasMore: page.has_more,
        error: null,
      });
    } catch (error) {
      if (controller.signal.aborted || generation !== sessionRequestGeneration.current) return;
      setSessionCollection((current) => ({
        ...(current.orgId === orgId ? current : emptyCollection(orgId)),
        status: current.orgId === orgId && current.items.length > 0 ? "ready" : "error",
        error,
      }));
    }
  }, [effectiveSessionLifecycle, orgId]);

  const loadMoreSessions = useCallback(async () => {
    if (
      sessionCollection.orgId !== orgId ||
      !sessionCollection.hasMore ||
      !sessionCollection.nextCursor
    ) {
      return;
    }
    sessionController.current?.abort();
    const controller = new AbortController();
    sessionController.current = controller;
    const generation = ++sessionRequestGeneration.current;
    setSessionCollection((current) => ({ ...current, status: "refreshing", error: null }));

    try {
      const page = await listAgentSessions(
        orgId,
        {
          limit: PAGE_SIZE,
          cursor: sessionCollection.nextCursor,
          ...(effectiveSessionLifecycle ? { lifecycle: effectiveSessionLifecycle } : {}),
        },
        controller.signal,
      );
      if (controller.signal.aborted || generation !== sessionRequestGeneration.current) return;
      setSessionCollection((current) => ({
        ...current,
        status: "ready",
        items: [...current.items, ...page.items],
        nextCursor: page.next_cursor,
        hasMore: page.has_more,
        error: null,
      }));
    } catch (error) {
      if (controller.signal.aborted || generation !== sessionRequestGeneration.current) return;
      setSessionCollection((current) => ({ ...current, status: "ready", error }));
    }
  }, [
    effectiveSessionLifecycle,
    orgId,
    sessionCollection.hasMore,
    sessionCollection.nextCursor,
    sessionCollection.orgId,
  ]);

  useEffect(() => {
    void refreshRuns();
    return () => {
      runController.current?.abort();
      runRequestGeneration.current += 1;
    };
  }, [refreshRuns]);

  useEffect(() => {
    void refreshSessions();
    return () => {
      sessionController.current?.abort();
      sessionRequestGeneration.current += 1;
    };
  }, [refreshSessions]);

  useEffect(() => {
    detailController.current?.abort();
    eventController.current?.abort();
    artifactController.current?.abort();
    const generation = ++detailRequestGeneration.current;
    const eventGeneration = ++eventRequestGeneration.current;
    const artifactGeneration = ++artifactRequestGeneration.current;

    if (!selectedRunId) {
      setDetail(emptyDetail(orgId));
      setEvents(emptyCollection(orgId, null));
      setArtifacts(emptyCollection(orgId, null));
      setUsage({ orgId, runId: null, status: "idle", items: [], error: null });
      return;
    }

    const detailAbort = new AbortController();
    const eventsAbort = new AbortController();
    const artifactsAbort = new AbortController();
    detailController.current = detailAbort;
    eventController.current = eventsAbort;
    artifactController.current = artifactsAbort;

    setDetail({ orgId, runId: selectedRunId, status: "loading", run: null, error: null });
    setEvents(emptyCollection(orgId, selectedRunId));
    setArtifacts(emptyCollection(orgId, selectedRunId));
    setUsage({ orgId, runId: selectedRunId, status: "loading", items: [], error: null });

    void getRun(orgId, selectedRunId, detailAbort.signal)
      .then((run) => {
        if (detailAbort.signal.aborted || generation !== detailRequestGeneration.current) return;
        setDetail({ orgId, runId: selectedRunId, status: "ready", run, error: null });
      })
      .catch((error: unknown) => {
        if (detailAbort.signal.aborted || generation !== detailRequestGeneration.current) return;
        setDetail({ orgId, runId: selectedRunId, status: "error", run: null, error });
      });

    void listRunEvents(orgId, selectedRunId, { limit: EVENT_PAGE_SIZE }, eventsAbort.signal)
      .then((page) => {
        if (eventsAbort.signal.aborted || eventGeneration !== eventRequestGeneration.current)
          return;
        setEvents({
          orgId,
          runId: selectedRunId,
          status: "ready",
          items: page.items,
          nextCursor: page.next_cursor,
          hasMore: page.has_more,
          error: null,
        });
      })
      .catch((error: unknown) => {
        if (eventsAbort.signal.aborted || eventGeneration !== eventRequestGeneration.current)
          return;
        setEvents({
          orgId,
          runId: selectedRunId,
          status: "error",
          items: [],
          nextCursor: null,
          hasMore: false,
          error,
        });
      });

    void listRunArtifacts(
      orgId,
      selectedRunId,
      { limit: ARTIFACT_PAGE_SIZE },
      artifactsAbort.signal,
    )
      .then((page) => {
        if (
          artifactsAbort.signal.aborted ||
          artifactGeneration !== artifactRequestGeneration.current
        ) {
          return;
        }
        setArtifacts({
          orgId,
          runId: selectedRunId,
          status: "ready",
          items: page.items,
          nextCursor: page.next_cursor,
          hasMore: page.has_more,
          error: null,
        });
      })
      .catch((error: unknown) => {
        if (
          artifactsAbort.signal.aborted ||
          artifactGeneration !== artifactRequestGeneration.current
        ) {
          return;
        }
        setArtifacts({
          orgId,
          runId: selectedRunId,
          status: "error",
          items: [],
          nextCursor: null,
          hasMore: false,
          error,
        });
      });

    void listUsage(orgId)
      .then((page) => {
        if (generation !== detailRequestGeneration.current) return;
        const matchingUsage = page.items
          .filter((item) => item.run_id === selectedRunId)
          .sort((left, right) => right.created_at.localeCompare(left.created_at));
        setUsage({
          orgId,
          runId: selectedRunId,
          status: "ready",
          items: matchingUsage,
          error: null,
        });
      })
      .catch((error: unknown) => {
        if (generation !== detailRequestGeneration.current) return;
        setUsage({ orgId, runId: selectedRunId, status: "error", items: [], error });
      });

    return () => {
      detailAbort.abort();
      eventsAbort.abort();
      artifactsAbort.abort();
    };
  }, [detailRefreshKey, orgId, selectedRunId]);

  const loadMoreEvents = useCallback(async () => {
    if (!selectedRunId || events.orgId !== orgId || events.runId !== selectedRunId) return;
    if (!events.hasMore || !events.nextCursor || events.status === "refreshing") return;
    eventController.current?.abort();
    const controller = new AbortController();
    eventController.current = controller;
    const generation = ++eventRequestGeneration.current;
    setEvents((current) => ({ ...current, status: "refreshing", error: null }));

    try {
      const page = await listRunEvents(
        orgId,
        selectedRunId,
        { limit: EVENT_PAGE_SIZE, cursor: events.nextCursor },
        controller.signal,
      );
      if (controller.signal.aborted || generation !== eventRequestGeneration.current) return;
      setEvents((current) => ({
        ...current,
        status: "ready",
        items: [...current.items, ...page.items],
        nextCursor: page.next_cursor,
        hasMore: page.has_more,
        error: null,
      }));
    } catch (error) {
      if (controller.signal.aborted || generation !== eventRequestGeneration.current) return;
      setEvents((current) => ({ ...current, status: "ready", error }));
    }
  }, [
    events.hasMore,
    events.nextCursor,
    events.orgId,
    events.runId,
    events.status,
    orgId,
    selectedRunId,
  ]);

  const loadMoreArtifacts = useCallback(async () => {
    if (!selectedRunId || artifacts.orgId !== orgId || artifacts.runId !== selectedRunId) return;
    if (!artifacts.hasMore || !artifacts.nextCursor || artifacts.status === "refreshing") return;
    artifactController.current?.abort();
    const controller = new AbortController();
    artifactController.current = controller;
    const generation = ++artifactRequestGeneration.current;
    setArtifacts((current) => ({ ...current, status: "refreshing", error: null }));

    try {
      const page = await listRunArtifacts(
        orgId,
        selectedRunId,
        { limit: ARTIFACT_PAGE_SIZE, cursor: artifacts.nextCursor },
        controller.signal,
      );
      if (controller.signal.aborted || generation !== artifactRequestGeneration.current) return;
      setArtifacts((current) => ({
        ...current,
        status: "ready",
        items: [...current.items, ...page.items],
        nextCursor: page.next_cursor,
        hasMore: page.has_more,
        error: null,
      }));
    } catch (error) {
      if (controller.signal.aborted || generation !== artifactRequestGeneration.current) return;
      setArtifacts((current) => ({ ...current, status: "ready", error }));
    }
  }, [
    artifacts.hasMore,
    artifacts.nextCursor,
    artifacts.orgId,
    artifacts.runId,
    artifacts.status,
    orgId,
    selectedRunId,
  ]);

  const selectTab = useCallback((next: TabId) => {
    setActiveTab(next);
    tabRefs.current[next]?.focus();
  }, []);

  function onTabKeyDown(event: KeyboardEvent<HTMLButtonElement>, tab: TabId) {
    const tabs: TabId[] = ["runs", "sessions"];
    const currentIndex = tabs.indexOf(tab);
    let nextIndex: number | null = null;
    if (event.key === "ArrowRight") nextIndex = (currentIndex + 1) % tabs.length;
    if (event.key === "ArrowLeft") nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = tabs.length - 1;
    if (nextIndex === null) return;
    event.preventDefault();
    const next = tabs[nextIndex];
    if (next) selectTab(next);
  }

  function viewSessionRuns(session: AgentSession) {
    const sessionId = resourceId(session, "id", "agent_session_id");
    setSessionFilter({ orgId, value: sessionId });
    setSelectedRunId(null);
    selectedRunIdRef.current = null;
    setActiveTab("runs");
    setActionError(null);
    setNotice(null);
    tabRefs.current.runs?.focus();
  }

  function openAction(kind: RunAction, run: Run) {
    setActionError(null);
    setNotice(null);
    setPendingAction({ kind, run });
  }

  function operationKey(actionOrgId: string, kind: RunAction, runId: string): string {
    const mapKey = `${actionOrgId}:${kind}:${runId}`;
    const existing = operationKeys.current.get(mapKey);
    if (existing) return existing;
    const created = crypto.randomUUID();
    operationKeys.current.set(mapKey, created);
    return created;
  }

  async function confirmAction() {
    if (!pendingAction || busyAction) return;
    const { kind, run } = pendingAction;
    const actionOrgId = orgId;
    const generation = ++mutationGeneration.current;
    const runId = resourceId(run, "id", "run_id");
    const mapKey = `${actionOrgId}:${kind}:${runId}`;
    const key = operationKey(actionOrgId, kind, runId);
    const isCurrentMutation = () =>
      mutationGeneration.current === generation && orgIdRef.current === actionOrgId;
    setBusyAction(kind);
    setActionError(null);

    try {
      if (kind === "cancel") {
        const updated = await cancelRun(actionOrgId, runId, { version: run.version }, key);
        if (!isCurrentMutation()) return;
        operationKeys.current.delete(mapKey);
        setRunCollection((current) => ({
          ...current,
          items: current.items.map((item) =>
            resourceId(item, "id", "run_id") === runId ? updated : item,
          ),
        }));
        setDetail((current) =>
          current.orgId === actionOrgId && current.runId === runId
            ? { ...current, status: "ready", run: updated, error: null }
            : current,
        );
        setNotice(
          "Cancellation confirmed by the server. Existing timeline and usage records remain.",
        );
        setPendingAction(null);
        setDetailRefreshKey((value) => value + 1);
        return;
      }

      const created = await retryRun(actionOrgId, runId, { version: run.version }, key);
      if (!isCurrentMutation()) return;
      operationKeys.current.delete(mapKey);
      const createdId = resourceId(created, "id", "run_id");
      setRunCollection((current) => ({
        ...current,
        items: [
          created,
          ...current.items.filter((item) => resourceId(item, "id", "run_id") !== createdId),
        ],
      }));
      setSessionFilter({ orgId: actionOrgId, value: null });
      setSelectedRunId(createdId);
      selectedRunIdRef.current = createdId;
      setNotice(
        "A new attempt was created. The previous run, error, usage, and timeline remain unchanged.",
      );
      setPendingAction(null);
      setActiveTab("runs");
    } catch (error) {
      if (!isCurrentMutation()) return;
      if (isRunVersionConflict(error)) {
        operationKeys.current.delete(mapKey);
        void refreshRuns();
        setDetailRefreshKey((value) => value + 1);
      }
      setActionError(error);
    } finally {
      if (isCurrentMutation()) setBusyAction(null);
    }
  }

  const visibleRuns = runCollection.orgId === orgId ? runCollection : emptyCollection<Run>(orgId);
  const visibleSessions =
    sessionCollection.orgId === orgId ? sessionCollection : emptyCollection<AgentSession>(orgId);
  const visibleDetail: DetailState =
    detail.orgId === orgId && detail.runId === selectedRunId
      ? detail
      : {
          ...emptyDetail(orgId),
          runId: selectedRunId,
          status: selectedRunId ? "loading" : "idle",
        };
  const visibleEvents =
    events.orgId === orgId && events.runId === selectedRunId
      ? events
      : emptyCollection<RunEvent>(orgId, selectedRunId);
  const visibleArtifacts =
    artifacts.orgId === orgId && artifacts.runId === selectedRunId
      ? artifacts
      : emptyCollection<ArtifactRef>(orgId, selectedRunId);
  const visibleUsage =
    usage.orgId === orgId && usage.runId === selectedRunId
      ? usage
      : { orgId, runId: selectedRunId, status: "loading" as const, items: [], error: null };

  const currentRefreshing =
    activeTab === "runs"
      ? visibleRuns.status === "refreshing" || visibleEvents.status === "refreshing"
      : visibleSessions.status === "refreshing";

  function refreshCurrentView() {
    setNotice(null);
    setActionError(null);
    if (activeTab === "runs") {
      void refreshRuns();
      if (selectedRunId) setDetailRefreshKey((value) => value + 1);
    } else {
      void refreshSessions();
    }
  }

  return (
    <section aria-labelledby={`${panelId}-title`} className="space-y-5">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-xs font-semibold tracking-[0.1em] text-[var(--lumi-blue)]">
            AGENTS / RUNS
          </p>
          <h2
            id={`${panelId}-title`}
            className="mt-2 text-2xl font-semibold tracking-[-0.03em] text-[var(--civic-navy)]"
          >
            Run history
          </h2>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-[var(--muted-strong)]">
            Inspect session-scoped execution history, state, model metadata, approvals, usage, and
            artifacts without exposing prompt or tool argument bodies.
          </p>
        </div>
        <button
          type="button"
          className={secondaryButton}
          onClick={refreshCurrentView}
          disabled={currentRefreshing}
        >
          {currentRefreshing ? "Refreshing…" : "Refresh"}
        </button>
      </header>

      <div className="border-b border-[var(--border)]">
        <div role="tablist" aria-label="Agent work history" className="flex gap-5 overflow-x-auto">
          <TabButton
            id={`${panelId}-runs-tab`}
            panelId={`${panelId}-runs-panel`}
            label="Runs"
            active={activeTab === "runs"}
            ref={(node) => {
              tabRefs.current.runs = node;
            }}
            onClick={() => selectTab("runs")}
            onKeyDown={(event) => onTabKeyDown(event, "runs")}
          />
          <TabButton
            id={`${panelId}-sessions-tab`}
            panelId={`${panelId}-sessions-panel`}
            label="Sessions"
            active={activeTab === "sessions"}
            ref={(node) => {
              tabRefs.current.sessions = node;
            }}
            onClick={() => selectTab("sessions")}
            onKeyDown={(event) => onTabKeyDown(event, "sessions")}
          />
        </div>
      </div>

      {notice ? (
        <p
          role="status"
          className="rounded-lg border border-[var(--success)]/30 bg-[var(--success)]/5 p-3 text-sm text-[var(--success)]"
        >
          {notice}
        </p>
      ) : null}

      {activeTab === "runs" ? (
        <div
          id={`${panelId}-runs-panel`}
          role="tabpanel"
          aria-labelledby={`${panelId}-runs-tab`}
          className="space-y-5"
        >
          <div className="flex flex-col gap-3 rounded-xl border border-[var(--border)] bg-[var(--panel)] p-4 shadow-[var(--shadow)] sm:flex-row sm:items-end sm:justify-between">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
              <label
                className="text-xs font-semibold text-[var(--muted-strong)]"
                htmlFor={`${panelId}-state-filter`}
              >
                Run state
                <select
                  id={`${panelId}-state-filter`}
                  value={effectiveRunFilter}
                  onChange={(event) => {
                    const value = event.target.value;
                    setRunFilter({
                      orgId,
                      value: RUN_STATES.includes(value as RunState) ? (value as RunState) : "",
                    });
                    setSelectedRunId(null);
                    selectedRunIdRef.current = null;
                    setActionError(null);
                    setNotice(null);
                  }}
                  className={filterControlClass}
                >
                  <option value="">All states</option>
                  {RUN_STATES.map((state) => (
                    <option value={state} key={state}>
                      {state.replaceAll("_", " ")}
                    </option>
                  ))}
                </select>
              </label>
              {effectiveSessionFilter ? (
                <button
                  type="button"
                  className={secondaryButton}
                  onClick={() => {
                    setSessionFilter({ orgId, value: null });
                    setSelectedRunId(null);
                    selectedRunIdRef.current = null;
                    setActionError(null);
                    setNotice(null);
                  }}
                >
                  Clear session filter
                </button>
              ) : null}
            </div>
            <p className="text-xs text-[var(--muted)]" aria-live="polite">
              {visibleRuns.status === "refreshing"
                ? "Refreshing runs…"
                : `${visibleRuns.items.length} runs loaded`}
            </p>
          </div>

          {effectiveSessionFilter ? (
            <p className="text-xs text-[var(--muted-strong)]">
              Filtered to session{" "}
              <span className="break-all font-mono">{effectiveSessionFilter}</span>
            </p>
          ) : null}

          <RunTable
            runs={visibleRuns.items}
            status={visibleRuns.status}
            error={visibleRuns.error}
            hasMore={visibleRuns.hasMore}
            selectedRunId={selectedRunId}
            onSelect={(runId) => {
              setSelectedRunId(runId);
              selectedRunIdRef.current = runId;
              setActionError(null);
              setNotice(null);
            }}
            onRetry={() => void refreshRuns()}
            onLoadMore={() => void loadMoreRuns()}
          />

          {visibleDetail.runId || selectedRunId ? (
            <RunDetail
              orgId={orgId}
              detail={visibleDetail}
              events={visibleEvents}
              artifacts={visibleArtifacts}
              usage={visibleUsage}
              sectionRef={detailSectionRef}
              actionError={actionError}
              busyAction={busyAction}
              onCancel={(run) => openAction("cancel", run)}
              onRetry={(run) => openAction("retry", run)}
              onRefreshTimeline={() => setDetailRefreshKey((value) => value + 1)}
              onLoadMoreEvents={() => void loadMoreEvents()}
              onLoadMoreArtifacts={() => void loadMoreArtifacts()}
            />
          ) : (
            <EmptyDetail />
          )}
        </div>
      ) : (
        <div
          id={`${panelId}-sessions-panel`}
          role="tabpanel"
          aria-labelledby={`${panelId}-sessions-tab`}
          className="space-y-4"
        >
          <div className="flex flex-col gap-3 rounded-xl border border-[var(--border)] bg-[var(--panel)] p-4 shadow-[var(--shadow)] sm:flex-row sm:items-end sm:justify-between">
            <label
              className="text-xs font-semibold text-[var(--muted-strong)]"
              htmlFor={`${panelId}-session-filter`}
            >
              Session lifecycle
              <select
                id={`${panelId}-session-filter`}
                value={effectiveSessionLifecycle}
                onChange={(event) => {
                  const value = event.target.value;
                  setSessionLifecycle({
                    orgId,
                    value:
                      value === "active" || value === "closed" || value === "archived" ? value : "",
                  });
                }}
                className={filterControlClass}
              >
                <option value="">All lifecycles</option>
                <option value="active">Active</option>
                <option value="closed">Closed</option>
                <option value="archived">Archived</option>
              </select>
            </label>
            <p className="text-xs text-[var(--muted)]" aria-live="polite">
              {visibleSessions.status === "refreshing"
                ? "Refreshing sessions…"
                : `${visibleSessions.items.length} sessions loaded`}
            </p>
          </div>

          <SessionTable
            sessions={visibleSessions.items}
            status={visibleSessions.status}
            error={visibleSessions.error}
            hasMore={visibleSessions.hasMore}
            onRetry={() => void refreshSessions()}
            onLoadMore={() => void loadMoreSessions()}
            onViewRuns={viewSessionRuns}
          />
        </div>
      )}

      <RunActionDialog
        action={pendingAction}
        busy={busyAction}
        error={actionError}
        onClose={() => {
          if (!busyAction) setPendingAction(null);
        }}
        onConfirm={() => void confirmAction()}
      />
    </section>
  );
}

function RunTable({
  runs,
  status,
  error,
  hasMore,
  selectedRunId,
  onSelect,
  onRetry,
  onLoadMore,
}: {
  runs: Run[];
  status: LoadStatus;
  error: unknown;
  hasMore: boolean;
  selectedRunId: string | null;
  onSelect: (runId: string) => void;
  onRetry: () => void;
  onLoadMore: () => void;
}) {
  if (status === "loading" || status === "idle") return <TableSkeleton label="Loading runs…" />;
  if (status === "error" && runs.length === 0) {
    return isPermissionFailure(error) ? (
      <PermissionState resource="runs" />
    ) : (
      <ErrorState error={error} onRetry={onRetry} />
    );
  }
  if (runs.length === 0) {
    return (
      <EmptyState
        title="No runs found"
        copy="No run history matches the current organization and filters."
      />
    );
  }

  return (
    <section className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]">
      <div className="border-b border-[var(--border)] px-5 py-4">
        <h3 className="text-base font-semibold text-[var(--civic-navy)]">Runs</h3>
        <p className="mt-1 text-sm text-[var(--muted-strong)]">
          Select a run to inspect its immutable timeline and current server state.
        </p>
      </div>
      {error ? (
        <div className="border-b border-[var(--danger)]/20 bg-[var(--danger)]/5 px-5 py-3">
          <InlineError error={error} onRetry={onRetry} />
        </div>
      ) : null}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[880px] text-left text-sm">
          <caption className="sr-only">Organization run history</caption>
          <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
            <tr>
              <th scope="col" className="px-5 py-3 font-medium">
                Run / attempt
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Scope
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                State
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Model / route
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Created
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Details
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border)]">
            {runs.map((run) => {
              const runId = resourceId(run, "id", "run_id");
              const selected = selectedRunId === runId;
              return (
                <tr
                  key={runId}
                  className={selected ? "bg-[var(--lumi-blue-soft)]/55" : "bg-[var(--panel)]"}
                >
                  <td className="px-5 py-4">
                    <button
                      type="button"
                      onClick={() => onSelect(runId)}
                      aria-pressed={selected}
                      aria-label={`View run ${runId}, attempt ${run.attempt}`}
                      className="max-w-[19rem] text-left outline-none focus-visible:rounded-md focus-visible:ring-2 focus-visible:ring-[var(--ring)]"
                    >
                      <span className="block font-mono text-xs font-semibold text-[var(--lumi-blue)]">
                        {runId}
                      </span>
                      <span className="mt-1 block text-xs text-[var(--muted)]">
                        Attempt {run.attempt}
                        {run.parent_run_id ? (
                          <span className="block break-all">Parent {run.parent_run_id}</span>
                        ) : null}
                      </span>
                    </button>
                  </td>
                  <td className="px-5 py-4">
                    <p className="max-w-[16rem] truncate font-mono text-xs text-[var(--muted-strong)]">
                      {run.agent_session_id}
                    </p>
                    <p className="mt-1 max-w-[16rem] truncate font-mono text-xs text-[var(--muted)]">
                      {run.project_id}
                    </p>
                  </td>
                  <td className="px-5 py-4">
                    <RunStatePill state={run.state} compact />
                  </td>
                  <td className="px-5 py-4">
                    <p className="font-medium text-[var(--civic-navy)]">
                      {run.model_alias ?? "Not selected"}
                    </p>
                    <p className="mt-1 max-w-[14rem] truncate font-mono text-xs text-[var(--muted)]">
                      {run.route_version_id ?? run.route_id ?? "No managed route"}
                    </p>
                  </td>
                  <td className="px-5 py-4 text-xs tabular-nums text-[var(--muted-strong)]">
                    {formatDateTime(run.created_at)}
                  </td>
                  <td className="px-5 py-4">
                    <button
                      type="button"
                      className={selected ? selectedButton : secondaryButton}
                      onClick={() => onSelect(runId)}
                      aria-pressed={selected}
                    >
                      {selected ? "Selected" : "View"}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <PaginationFooter
        loaded={runs.length}
        hasMore={hasMore}
        loading={status === "refreshing"}
        onLoadMore={onLoadMore}
        noun="run"
      />
    </section>
  );
}

function SessionTable({
  sessions,
  status,
  error,
  hasMore,
  onRetry,
  onLoadMore,
  onViewRuns,
}: {
  sessions: AgentSession[];
  status: LoadStatus;
  error: unknown;
  hasMore: boolean;
  onRetry: () => void;
  onLoadMore: () => void;
  onViewRuns: (session: AgentSession) => void;
}) {
  if (status === "loading" || status === "idle") return <TableSkeleton label="Loading sessions…" />;
  if (status === "error" && sessions.length === 0) {
    return isPermissionFailure(error) ? (
      <PermissionState resource="sessions" />
    ) : (
      <ErrorState error={error} onRetry={onRetry} />
    );
  }
  if (sessions.length === 0) {
    return (
      <EmptyState
        title="No sessions found"
        copy="No agent sessions match this organization and lifecycle filter."
      />
    );
  }

  return (
    <section className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]">
      <div className="border-b border-[var(--border)] px-5 py-4">
        <h3 className="text-base font-semibold text-[var(--civic-navy)]">Sessions</h3>
        <p className="mt-1 text-sm text-[var(--muted-strong)]">
          A session is durable work context. Each retry remains a separate run attempt.
        </p>
      </div>
      {error ? (
        <div className="border-b border-[var(--danger)]/20 bg-[var(--danger)]/5 px-5 py-3">
          <InlineError error={error} onRetry={onRetry} />
        </div>
      ) : null}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[820px] text-left text-sm">
          <caption className="sr-only">Organization agent sessions</caption>
          <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
            <tr>
              <th scope="col" className="px-5 py-3 font-medium">
                Session
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Project / device
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Agent
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Lifecycle
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Updated
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Runs
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border)]">
            {sessions.map((session) => {
              const sessionId = resourceId(session, "id", "agent_session_id");
              return (
                <tr key={sessionId}>
                  <td className="px-5 py-4">
                    <p className="font-medium text-[var(--civic-navy)]">
                      {session.title?.trim() || "Untitled session"}
                    </p>
                    <p className="mt-1 max-w-[20rem] truncate font-mono text-xs text-[var(--muted)]">
                      {sessionId}
                    </p>
                  </td>
                  <td className="px-5 py-4">
                    <p className="max-w-[15rem] truncate font-mono text-xs text-[var(--muted-strong)]">
                      {session.project_id}
                    </p>
                    <p className="mt-1 max-w-[15rem] truncate font-mono text-xs text-[var(--muted)]">
                      {session.device_id}
                    </p>
                  </td>
                  <td className="px-5 py-4">
                    <p className="max-w-[15rem] truncate font-mono text-xs text-[var(--muted-strong)]">
                      {session.agent_definition_id}
                    </p>
                    <p className="mt-1 text-xs text-[var(--muted)]">
                      Session v{session.version} · agent v{session.agent_definition_version}
                    </p>
                  </td>
                  <td className="px-5 py-4">
                    <span
                      className={[
                        "inline-flex rounded-full px-2 py-1 text-xs font-medium capitalize",
                        session.lifecycle === "active"
                          ? "bg-[var(--success)]/10 text-[var(--success)]"
                          : "bg-[var(--panel-strong)] text-[var(--muted-strong)]",
                      ].join(" ")}
                    >
                      {session.lifecycle}
                    </span>
                  </td>
                  <td className="px-5 py-4 text-xs tabular-nums text-[var(--muted-strong)]">
                    {formatDateTime(session.updated_at)}
                  </td>
                  <td className="px-5 py-4">
                    <button
                      type="button"
                      className={secondaryButton}
                      onClick={() => onViewRuns(session)}
                    >
                      View runs
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <PaginationFooter
        loaded={sessions.length}
        hasMore={hasMore}
        loading={status === "refreshing"}
        onLoadMore={onLoadMore}
        noun="session"
      />
    </section>
  );
}

function RunDetail({
  orgId,
  detail,
  events,
  artifacts,
  usage,
  sectionRef,
  actionError,
  busyAction,
  onCancel,
  onRetry,
  onRefreshTimeline,
  onLoadMoreEvents,
  onLoadMoreArtifacts,
}: {
  orgId: string;
  detail: DetailState;
  events: Collection<RunEvent>;
  artifacts: Collection<ArtifactRef>;
  usage: UsageState;
  sectionRef: RefObject<HTMLElement | null>;
  actionError: unknown;
  busyAction: RunAction | null;
  onCancel: (run: Run) => void;
  onRetry: (run: Run) => void;
  onRefreshTimeline: () => void;
  onLoadMoreEvents: () => void;
  onLoadMoreArtifacts: () => void;
}) {
  if (detail.status === "loading" || detail.status === "idle") return <DetailSkeleton />;
  if (detail.status === "error" || !detail.run) {
    if (isPermissionFailure(detail.error)) return <PermissionState resource="run details" />;
    return (
      <ErrorState
        error={detail.error}
        title="Run details unavailable"
        onRetry={onRefreshTimeline}
      />
    );
  }

  const run = detail.run;
  const runId = resourceId(run, "id", "run_id");
  const cancellable = canCancelRun(run.state);
  const retryable = canRetryRun(run.state);

  return (
    <div className="space-y-5">
      <section
        ref={sectionRef}
        tabIndex={-1}
        aria-label="Selected run details"
        className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)] outline-none"
      >
        <div className="border-b border-[var(--border)] px-5 py-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <RunStatePill state={run.state} />
                <span className="rounded-md bg-[var(--panel-strong)] px-2 py-1 text-xs font-medium text-[var(--muted-strong)]">
                  Attempt {run.attempt}
                </span>
              </div>
              <h3 className="mt-3 break-all font-mono text-sm font-semibold text-[var(--civic-navy)]">
                {runId}
              </h3>
              <p className="mt-1 text-sm text-[var(--muted-strong)]">
                Run history is append-only. Retry creates a separate attempt.
              </p>
            </div>
            <div className="flex shrink-0 flex-wrap gap-2">
              {cancellable ? (
                <button
                  type="button"
                  className={dangerButton}
                  onClick={() => onCancel(run)}
                  disabled={busyAction !== null}
                >
                  Cancel run
                </button>
              ) : null}
              {retryable ? (
                <button
                  type="button"
                  className={primaryButton}
                  onClick={() => onRetry(run)}
                  disabled={busyAction !== null}
                >
                  Retry as new attempt
                </button>
              ) : null}
            </div>
          </div>
        </div>

        {run.failure_code ? (
          <div className="border-b border-[var(--danger)]/25 bg-[var(--danger)]/5 px-5 py-3">
            <p className="text-xs font-semibold text-[var(--danger)]">Stable failure reason</p>
            <p className="mt-1 font-mono text-xs text-[var(--danger)]">{run.failure_code}</p>
          </div>
        ) : null}

        {actionError ? (
          <div className="border-b border-[var(--danger)]/25 bg-[var(--danger)]/5 px-5 py-4">
            <ActionError error={actionError} />
          </div>
        ) : null}

        <dl className="grid gap-x-6 gap-y-5 p-5 sm:grid-cols-2 lg:grid-cols-3">
          <Metadata label="Session" value={run.agent_session_id} mono />
          <Metadata label="Project" value={run.project_id} mono />
          <Metadata label="Device" value={run.device_id} mono />
          <Metadata label="Model alias" value={run.model_alias ?? "Not selected"} />
          <Metadata label="Route" value={run.route_id ?? "Local or unmanaged execution"} mono />
          <Metadata label="Route version" value={run.route_version_id ?? "Not recorded"} mono />
          <Metadata
            label="Agent definition"
            value={`${run.agent_definition_id} · v${run.agent_definition_version}`}
            mono
          />
          <Metadata label="Started" value={formatDateTime(run.started_at)} />
          <Metadata label="Finished" value={formatDateTime(run.finished_at)} />
          <Metadata label="Duration" value={formatDuration(run.started_at, run.finished_at)} />
          <Metadata label="Created" value={formatDateTime(run.created_at)} />
          <Metadata label="Updated" value={formatDateTime(run.updated_at)} />
          <Metadata label="Request" value={run.request_id ?? "Not assigned"} mono />
          <Metadata label="Parent run" value={run.parent_run_id ?? "Original attempt"} mono />
        </dl>
        <div className="border-t border-[var(--border)] bg-[var(--panel-hover)] px-5 py-3 text-xs leading-5 text-[var(--muted-strong)]">
          The API remains authoritative for permission, current device and project state, policy,
          budget, and legal state transitions. UI controls do not grant access.
        </div>
      </section>

      <UsageCard orgId={orgId} usage={usage} />
      <ArtifactsCard
        artifacts={artifacts}
        onRetry={onRefreshTimeline}
        onLoadMore={onLoadMoreArtifacts}
      />
      <RunTimeline
        events={events.items}
        loading={events.status === "loading" || events.status === "idle"}
        refreshing={events.status === "refreshing"}
        error={events.error}
        hasMore={events.hasMore}
        loadingMore={events.status === "refreshing"}
        onRetry={onRefreshTimeline}
        onLoadMore={onLoadMoreEvents}
      />
    </div>
  );
}

function UsageCard({ orgId, usage }: { orgId: string; usage: UsageState }) {
  if (usage.status === "loading" || usage.status === "idle") {
    return (
      <section
        aria-label="Loading run usage"
        aria-busy="true"
        className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)]"
      >
        <p className="text-sm font-semibold text-[var(--civic-navy)]">Loading usage metadata…</p>
        <div className="mt-4 h-14 rounded-lg bg-[var(--panel-strong)]" />
      </section>
    );
  }
  if (usage.status === "error") {
    return isPermissionFailure(usage.error) ? (
      <PermissionState resource="usage metadata" compact />
    ) : (
      <ErrorState error={usage.error} title="Usage metadata unavailable" compact />
    );
  }

  const inputTokens = sumNullable(usage.items.map((item) => item.input_tokens));
  const outputTokens = sumNullable(usage.items.map((item) => item.output_tokens));
  const cachedTokens = sumNullable(usage.items.map((item) => item.cached_tokens));
  const latest = usage.items[0];

  return (
    <section className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]">
      <div className="border-b border-[var(--border)] px-5 py-4">
        <h3 className="text-base font-semibold text-[var(--civic-navy)]">
          Model, provider, and usage
        </h3>
        <p className="mt-1 text-sm text-[var(--muted-strong)]">
          Reconciled metadata from the recent usage page for organization {orgId}. Prompt and
          provider response bodies are never displayed.
        </p>
      </div>
      {usage.items.length === 0 ? (
        <p className="px-5 py-6 text-sm text-[var(--muted)]">
          No reconciled usage is present in the recent usage page for this run.
        </p>
      ) : (
        <>
          <dl className="grid gap-4 border-b border-[var(--border)] px-5 py-4 sm:grid-cols-2 lg:grid-cols-4">
            <CompactMetric label="Provider" value={latest?.provider_id ?? "Not recorded"} mono />
            <CompactMetric label="Model" value={latest?.model_id ?? "Not recorded"} mono />
            <CompactMetric
              label="Input / output"
              value={`${formatCount(inputTokens)} / ${formatCount(outputTokens)}`}
            />
            <CompactMetric label="Cached tokens" value={formatCount(cachedTokens)} />
          </dl>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-left text-sm">
              <caption className="sr-only">Recent usage metadata for selected run</caption>
              <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
                <tr>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Model
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Tokens
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Cost
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Budget
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Recorded
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {usage.items.slice(0, 10).map((item) => (
                  <tr key={item.usage_event_id}>
                    <td className="px-5 py-3">
                      <p className="font-medium text-[var(--civic-navy)]">{item.model_alias}</p>
                      <p className="mt-1 font-mono text-xs text-[var(--muted)]">
                        {item.provider_id}
                      </p>
                    </td>
                    <td className="px-5 py-3 text-xs tabular-nums text-[var(--muted-strong)]">
                      {formatCount(item.input_tokens)} / {formatCount(item.output_tokens)}
                      {item.cached_tokens !== null
                        ? ` · ${formatCount(item.cached_tokens)} cached`
                        : ""}
                    </td>
                    <td className="px-5 py-3 text-xs tabular-nums text-[var(--muted-strong)]">
                      {formatMinorCost(
                        item.actual_cost_minor ?? item.estimated_cost_minor,
                        item.currency,
                      )}
                    </td>
                    <td className="px-5 py-3 text-xs capitalize text-[var(--muted-strong)]">
                      {item.budget_decision.replaceAll("_", " ")}
                    </td>
                    <td className="px-5 py-3 text-xs tabular-nums text-[var(--muted)]">
                      {formatDateTime(item.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}

function ArtifactsCard({
  artifacts,
  onRetry,
  onLoadMore,
}: {
  artifacts: Collection<ArtifactRef>;
  onRetry: () => void;
  onLoadMore: () => void;
}) {
  if (artifacts.status === "loading" || artifacts.status === "idle") {
    return (
      <section
        aria-label="Loading run artifacts"
        aria-busy="true"
        className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)]"
      >
        <p className="text-sm font-semibold text-[var(--civic-navy)]">
          Loading artifact references…
        </p>
      </section>
    );
  }
  if (artifacts.status === "error" && artifacts.items.length === 0) {
    return isPermissionFailure(artifacts.error) ? (
      <PermissionState resource="artifact metadata" compact />
    ) : (
      <ErrorState
        error={artifacts.error}
        title="Artifact metadata unavailable"
        onRetry={onRetry}
        compact
      />
    );
  }

  return (
    <section className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]">
      <div className="border-b border-[var(--border)] px-5 py-4">
        <h3 className="text-base font-semibold text-[var(--civic-navy)]">Artifact references</h3>
        <p className="mt-1 text-sm text-[var(--muted-strong)]">
          Only artifact metadata is shown. Content references and file bytes are not loaded into
          this view.
        </p>
      </div>
      {artifacts.items.length === 0 ? (
        <p className="px-5 py-6 text-sm text-[var(--muted)]">
          No artifact references are available.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[680px] text-left text-sm">
            <caption className="sr-only">Artifact metadata for selected run</caption>
            <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
              <tr>
                <th scope="col" className="px-5 py-3 font-medium">
                  Artifact
                </th>
                <th scope="col" className="px-5 py-3 font-medium">
                  Kind
                </th>
                <th scope="col" className="px-5 py-3 font-medium">
                  Type / size
                </th>
                <th scope="col" className="px-5 py-3 font-medium">
                  Retention
                </th>
                <th scope="col" className="px-5 py-3 font-medium">
                  Created
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border)]">
              {artifacts.items.map((artifact) => (
                <tr key={resourceId(artifact, "id", "artifact_ref_id")}>
                  <td className="px-5 py-3 font-mono text-xs text-[var(--civic-navy)]">
                    {resourceId(artifact, "id", "artifact_ref_id")}
                  </td>
                  <td className="px-5 py-3 text-xs capitalize text-[var(--muted-strong)]">
                    {artifact.kind.replaceAll("_", " ")}
                  </td>
                  <td className="px-5 py-3 text-xs text-[var(--muted-strong)]">
                    {artifact.mime_type ?? "Type not recorded"} · {formatBytes(artifact.size_bytes)}
                  </td>
                  <td className="px-5 py-3 text-xs text-[var(--muted-strong)]">
                    {artifact.retention_policy}
                  </td>
                  <td className="px-5 py-3 text-xs tabular-nums text-[var(--muted)]">
                    {formatDateTime(artifact.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <PaginationFooter
        loaded={artifacts.items.length}
        hasMore={artifacts.hasMore}
        loading={artifacts.status === "refreshing"}
        onLoadMore={onLoadMore}
        noun="artifact"
      />
    </section>
  );
}

function RunActionDialog({
  action,
  busy,
  error,
  onClose,
  onConfirm,
}: {
  action: PendingAction | null;
  busy: RunAction | null;
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

  const runId = action ? resourceId(action.run, "id", "run_id") : "";
  const isCancel = action?.kind === "cancel";

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
            {isCancel ? "CANCEL RUN" : "NEW ATTEMPT"}
          </p>
          <h2 id={titleId} className="mt-2 text-lg font-semibold text-[var(--civic-navy)]">
            {isCancel ? "Stop this run?" : "Retry as a new attempt?"}
          </h2>
          <div
            id={descriptionId}
            className="mt-3 space-y-3 text-sm leading-6 text-[var(--muted-strong)]"
          >
            <p className="break-all font-mono text-xs text-[var(--civic-navy)]">{runId}</p>
            {isCancel ? (
              <p>
                The control plane will ask the execution host and managed inference stream to stop.
                Existing timeline, usage, artifacts, and audit records remain. Cancellation is
                idempotent and cannot be undone.
              </p>
            ) : (
              <p>
                This creates a separate run attempt. The prior run, failure, usage, and timeline are
                not changed. Current membership, project, device, model, budget, and tool policy are
                re-evaluated, and the new attempt may incur usage.
              </p>
            )}
          </div>
          {error ? (
            <div className="mt-4 rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/5 p-3 text-sm text-[var(--danger)]">
              <ActionError error={error} />
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
              {isCancel ? "Keep run active" : "Keep this attempt"}
            </button>
            <button
              type="button"
              className={isCancel ? dangerButton : primaryButton}
              onClick={onConfirm}
              disabled={busy !== null}
            >
              {busy === "cancel"
                ? "Cancelling…"
                : busy === "retry"
                  ? "Creating attempt…"
                  : isCancel
                    ? "Cancel run"
                    : "Create new attempt"}
            </button>
          </div>
        </div>
      ) : null}
    </dialog>
  );
}

function TabButton({
  id,
  panelId,
  label,
  active,
  onClick,
  onKeyDown,
  ref,
}: {
  id: string;
  panelId: string;
  label: string;
  active: boolean;
  onClick: () => void;
  onKeyDown: (event: KeyboardEvent<HTMLButtonElement>) => void;
  ref: (node: HTMLButtonElement | null) => void;
}) {
  return (
    <button
      ref={ref}
      id={id}
      type="button"
      role="tab"
      aria-selected={active}
      aria-controls={panelId}
      tabIndex={active ? 0 : -1}
      onClick={onClick}
      onKeyDown={onKeyDown}
      className={[
        "min-h-11 shrink-0 border-b-2 px-1 text-sm font-semibold outline-none transition focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2",
        active
          ? "border-[var(--lumi-blue)] text-[var(--lumi-blue)]"
          : "border-transparent text-[var(--muted-strong)] hover:text-[var(--foreground)]",
      ].join(" ")}
    >
      {label}
    </button>
  );
}

function Metadata({
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
          "mt-1 break-all text-sm text-[var(--civic-navy)]",
          mono ? "font-mono text-xs" : "",
        ].join(" ")}
      >
        {value}
      </dd>
    </div>
  );
}

function CompactMetric({
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
      <dt className="text-xs text-[var(--muted)]">{label}</dt>
      <dd
        className={[
          "mt-1 break-all text-sm font-semibold tabular-nums text-[var(--civic-navy)]",
          mono ? "font-mono text-xs" : "",
        ].join(" ")}
      >
        {value}
      </dd>
    </div>
  );
}

function TableSkeleton({ label }: { label: string }) {
  return (
    <section
      aria-label={label}
      aria-busy="true"
      className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]"
    >
      <div className="border-b border-[var(--border)] px-5 py-4 text-sm font-semibold text-[var(--civic-navy)]">
        {label}
      </div>
      <div className="divide-y divide-[var(--border)]">
        {[0, 1, 2, 3, 4].map((row) => (
          <div key={row} className="grid grid-cols-4 gap-4 px-5 py-4">
            <div className="h-4 rounded bg-[var(--panel-strong)]" />
            <div className="h-4 rounded bg-[var(--panel-strong)]" />
            <div className="h-4 rounded bg-[var(--panel-strong)]" />
            <div className="h-4 rounded bg-[var(--panel-strong)]" />
          </div>
        ))}
      </div>
    </section>
  );
}

function DetailSkeleton() {
  return (
    <section
      aria-label="Loading run details"
      aria-busy="true"
      className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)]"
    >
      <div className="flex items-center justify-between gap-4">
        <div className="h-6 w-40 rounded bg-[var(--panel-strong)]" />
        <div className="h-9 w-28 rounded bg-[var(--panel-strong)]" />
      </div>
      <div className="mt-6 grid gap-4 sm:grid-cols-3">
        {[0, 1, 2, 3, 4, 5].map((item) => (
          <div key={item} className="space-y-2">
            <div className="h-3 w-20 rounded bg-[var(--panel-strong)]" />
            <div className="h-4 w-full rounded bg-[var(--panel-strong)]" />
          </div>
        ))}
      </div>
    </section>
  );
}

function PaginationFooter({
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
      <p className="text-xs text-[var(--muted)]">
        {loaded} {noun}
        {loaded === 1 ? "" : "s"} loaded{hasMore ? " · more available" : ""}
      </p>
      {hasMore ? (
        <button type="button" className={secondaryButton} onClick={onLoadMore} disabled={loading}>
          {loading ? "Loading…" : `Load more ${noun}s`}
        </button>
      ) : null}
    </div>
  );
}

function PermissionState({ resource, compact = false }: { resource: string; compact?: boolean }) {
  return (
    <div
      role="alert"
      className={[
        "rounded-xl border border-[var(--border)] bg-[var(--panel)] text-[var(--muted-strong)] shadow-[var(--shadow)]",
        compact ? "p-4" : "p-6 text-center",
      ].join(" ")}
    >
      <h3 className="text-sm font-semibold text-[var(--civic-navy)]">Access not permitted</h3>
      <p className="mt-1 text-sm">
        Your current membership cannot view {resource}. Ask an administrator to review access.
      </p>
    </div>
  );
}

function ErrorState({
  error,
  title = "Could not load this view",
  onRetry,
  compact = false,
}: {
  error: unknown;
  title?: string;
  onRetry?: () => void;
  compact?: boolean;
}) {
  const presentation = presentApiError(error);
  return (
    <div
      role="alert"
      className={[
        "rounded-xl border border-[var(--danger)]/30 bg-[var(--danger)]/5 text-[var(--danger)]",
        compact ? "p-4" : "p-6",
      ].join(" ")}
    >
      <p className="font-semibold">{title}</p>
      <p className="mt-1 text-sm">{presentation.message}</p>
      {presentation.requestId ? (
        <p className="mt-1 break-all text-xs opacity-75">Request {presentation.requestId}</p>
      ) : null}
      {onRetry ? (
        <button type="button" className={secondaryButton} onClick={onRetry}>
          Try again
        </button>
      ) : null}
    </div>
  );
}

function InlineError({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  const presentation = presentApiError(error);
  return (
    <div
      role="alert"
      className="flex flex-wrap items-center justify-between gap-3 text-sm text-[var(--danger)]"
    >
      <div>
        <p>{presentation.message}</p>
        {presentation.requestId ? (
          <p className="mt-1 break-all text-xs opacity-75">Request {presentation.requestId}</p>
        ) : null}
      </div>
      <button
        type="button"
        className="min-h-9 rounded-lg border border-[var(--danger)]/35 px-3 text-xs font-semibold outline-none hover:bg-[var(--danger)]/5 focus-visible:ring-2 focus-visible:ring-[var(--ring)]"
        onClick={onRetry}
      >
        Try again
      </button>
    </div>
  );
}

function ActionError({ error }: { error: unknown }) {
  const presentation = presentApiError(error);
  const message = isPermissionFailure(error)
    ? "You cannot perform this action in the current access scope. Ask an administrator."
    : isRunVersionConflict(error)
      ? "The run changed or can no longer accept that action. Refresh before trying again."
      : isAmbiguousRunMutationFailure(error)
        ? "The server did not confirm the result. The action may already have been applied. Refresh before retrying; this confirmation reuses the same idempotency key."
        : presentation.message;
  return (
    <div role="alert">
      <p className="text-sm font-medium">{message}</p>
      {presentation.requestId ? (
        <p className="mt-1 break-all text-xs opacity-75">Request {presentation.requestId}</p>
      ) : null}
    </div>
  );
}

function EmptyDetail() {
  return (
    <section className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-8 text-center shadow-[var(--shadow)]">
      <h3 className="text-sm font-semibold text-[var(--civic-navy)]">Select a run</h3>
      <p className="mt-1 text-sm text-[var(--muted-strong)]">
        Run state, model metadata, usage, artifacts, and the append-only timeline appear here.
      </p>
    </section>
  );
}

function EmptyState({ title, copy }: { title: string; copy: string }) {
  return (
    <section className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-8 text-center shadow-[var(--shadow)]">
      <h3 className="text-sm font-semibold text-[var(--civic-navy)]">{title}</h3>
      <p className="mt-1 text-sm text-[var(--muted-strong)]">{copy}</p>
    </section>
  );
}

function emptyCollection<T>(orgId: string, runId: string | null = null): Collection<T> {
  return {
    orgId,
    runId,
    status: "idle",
    items: [],
    nextCursor: null,
    hasMore: false,
    error: null,
  };
}

function emptyDetail(orgId: string): DetailState {
  return { orgId, runId: null, status: "idle", run: null, error: null };
}

function resourceId(value: unknown, primaryKey: string, fallbackKey: string): string {
  if (typeof value !== "object" || value === null) return "";
  const record = value as Record<string, unknown>;
  const primary = record[primaryKey];
  if (typeof primary === "string" && primary.length > 0) return primary;
  const fallback = record[fallbackKey];
  return typeof fallback === "string" ? fallback : "";
}

function sumNullable(values: Array<number | null>): number | null {
  const present = values.filter(
    (value): value is number => value !== null && Number.isFinite(value),
  );
  if (present.length === 0) return null;
  return present.reduce((total, value) => total + value, 0);
}

function formatCount(value: number | null): string {
  return value === null ? "—" : value.toLocaleString();
}

function formatMinorCost(value: number | null, currency: string | null): string {
  if (value === null || !Number.isFinite(value)) return "—";
  if (!currency) return `${value.toLocaleString()} minor units`;
  try {
    return new Intl.NumberFormat(undefined, { style: "currency", currency }).format(value / 100);
  } catch {
    return `${value.toLocaleString()} ${currency} minor units`;
  }
}

const filterControlClass =
  "mt-1.5 min-h-10 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 text-sm font-normal text-[var(--foreground)] outline-none transition focus-visible:border-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)]";
const primaryButton =
  "min-h-10 rounded-lg bg-[var(--lumi-blue)] px-4 py-2 text-sm font-semibold text-white shadow-[var(--shadow-button)] outline-none transition hover:bg-[var(--lumi-blue-hover)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";
const secondaryButton =
  "inline-flex min-h-10 items-center justify-center rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 py-1.5 text-sm font-semibold text-[var(--civic-navy)] outline-none transition hover:bg-[var(--panel-hover)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";
const dangerButton =
  "inline-flex min-h-10 items-center justify-center rounded-lg border border-[var(--danger)]/35 bg-[var(--danger)]/5 px-4 py-2 text-sm font-semibold text-[var(--danger)] outline-none transition hover:bg-[var(--danger)]/10 focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";
const selectedButton =
  "inline-flex min-h-10 items-center justify-center rounded-lg border border-[var(--lumi-blue)] bg-[var(--lumi-blue-soft)] px-3 py-1.5 text-sm font-semibold text-[var(--lumi-blue)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]";
