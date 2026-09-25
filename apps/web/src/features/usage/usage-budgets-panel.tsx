import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
} from "react";

import * as apiClient from "@/lib/api";
import type { Page } from "@/lib/api";
import { ApiClientError, presentApiError } from "@/lib/errors";

import {
  BudgetCards,
  BudgetList,
  BudgetReservationsTable,
  DenialTable,
  RateLimitPoliciesTable,
  UsageBreakdownTable,
  UsageEventsTable,
} from "./budget-cards";
import { buildUsageTrend, deriveDenials, formatUsageTimestamp, summarizeUsage } from "./helpers";
import {
  decodeBudget,
  decodeBudgetReservation,
  decodeRateLimitPolicy,
  decodeUsageDenial,
  sanitizeUsageEvent,
  UsageContractError,
  type Budget,
  type BudgetReservation,
  type RateLimitPolicy,
  type RawUsageEvent,
  type UsageApi,
  type UsageBudgetsData,
  type UsageDenial,
  type UsageEvent,
  type UsageTab,
  type UsageTrendPoint,
} from "./usage-contracts";

const LazyUsageTrend = lazy(() => import("./usage-trend"));

export interface UsageBudgetsPanelProps {
  orgId: string;
  /**
   * Optional adapter for the P05 reads. When omitted, the existing
   * listUsage export is used and optional P05 methods are discovered from
   * api.ts when the coordinator adds them.
   */
  api?: UsageApi;
  /** Optional server snapshot for route-level composition or tests. */
  initialData?: UsageBudgetsData;
  /** Marks a server snapshot as stale even when it is younger than the panel. */
  stale?: boolean;
}

type ResourceStatus = "loading" | "ready" | "error" | "permission" | "unavailable";

interface ResourceState<T> {
  status: ResourceStatus;
  data: T[];
  receivedAt: number | null;
  error: unknown;
  reason: string | null;
  stale: boolean;
}

interface PanelState {
  orgId: string;
  usage: ResourceState<UsageEvent>;
  budgets: ResourceState<Budget>;
  reservations: ResourceState<BudgetReservation>;
  rateLimits: ResourceState<RateLimitPolicy>;
  denials: ResourceState<UsageDenial>;
  trend: UsageTrendPoint[];
  refreshing: boolean;
}

const tabs: { id: UsageTab; label: string }[] = [
  { id: "budgets", label: "Budgets" },
  { id: "rate-limits", label: "Rate limits" },
  { id: "denials", label: "Denials" },
];

export function UsageBudgetsPanel({
  orgId,
  api,
  initialData,
  stale = false,
}: UsageBudgetsPanelProps) {
  const defaultClientRef = useRef<UsageApi | null>(null);
  const client = api ?? (defaultClientRef.current ??= getDefaultUsageApi());
  const initialDataRef = useRef(initialData);
  initialDataRef.current = initialData;
  const [activeTab, setActiveTab] = useState<UsageTab>("budgets");
  const [state, setState] = useState<PanelState>(() =>
    createInitialState(orgId, client, scopedInitialData(orgId, initialDataRef.current)),
  );
  const stateRef = useRef(state);
  stateRef.current = state;
  const requestGeneration = useRef(0);
  const activeController = useRef<AbortController | null>(null);
  const [trendOpen, setTrendOpen] = useState(false);
  const [breakdownDimension, setBreakdownDimension] = useState<
    "project" | "user" | "model" | "provider"
  >("project");
  const tabRefs = useRef<Record<UsageTab, HTMLButtonElement | null>>({
    budgets: null,
    "rate-limits": null,
    denials: null,
  });
  const tabSetId = useId().replaceAll(":", "");

  const load = useCallback(async () => {
    if (!orgId) return;
    const generation = ++requestGeneration.current;
    activeController.current?.abort();
    const controller = new AbortController();
    activeController.current = controller;

    const previous = stateRef.current;
    const sameOrganization = previous.orgId === orgId;
    const base = sameOrganization
      ? previous
      : createInitialState(orgId, client, scopedInitialData(orgId, initialDataRef.current));
    const seeded = hasReadyResource(base);
    const next: PanelState = {
      ...base,
      refreshing: true,
      usage: seeded ? markStale(base.usage) : loadingResource<UsageEvent>(),
      budgets:
        client.listBudgets || hasBudgetSeed(base)
          ? seeded
            ? markStale(base.budgets)
            : loadingResource<Budget>()
          : unavailableResource("Budget reads are not connected in this client."),
      reservations:
        client.listBudgetReservations || hasReservationSeed(base)
          ? seeded
            ? markStale(base.reservations)
            : loadingResource<BudgetReservation>()
          : unavailableResource("Reservation reads are not connected in this client."),
      rateLimits:
        client.listRateLimits || hasRateLimitSeed(base)
          ? seeded
            ? markStale(base.rateLimits)
            : loadingResource<RateLimitPolicy>()
          : unavailableResource("Rate-limit reads are not connected in this client."),
      denials:
        client.listUsageDenials || hasDenialSeed(base)
          ? seeded
            ? markStale(base.denials)
            : loadingResource<UsageDenial>()
          : base.denials,
    };
    stateRef.current = next;
    setState(next);

    const seed = scopedInitialData(orgId, initialDataRef.current);
    const [usageResult, budgetsResult, reservationsResult, rateLimitsResult, denialsResult] =
      await Promise.all([
        settleResource(
          () => client.listUsage(orgId, controller.signal),
          (page: Page<RawUsageEvent>) => page.items.map((item) => sanitizeUsageEvent(item)),
          loadingResource<UsageEvent>(),
        ),
        settleResource(
          client.listBudgets ? () => client.listBudgets!(orgId, controller.signal) : undefined,
          (page: Page<Budget>) => page.items.map((item) => decodeBudget(item)),
          next.budgets,
        ),
        settleResource(
          client.listBudgetReservations
            ? () => client.listBudgetReservations!(orgId, controller.signal)
            : undefined,
          (page: Page<BudgetReservation>) =>
            page.items.map((item) => decodeBudgetReservation(item)),
          next.reservations,
        ),
        settleResource(
          client.listRateLimits
            ? () => client.listRateLimits!(orgId, controller.signal)
            : undefined,
          (page: Page<RateLimitPolicy>) => page.items.map((item) => decodeRateLimitPolicy(item)),
          next.rateLimits,
        ),
        settleResource(
          client.listUsageDenials
            ? () => client.listUsageDenials!(orgId, controller.signal)
            : undefined,
          (page: Page<UsageDenial>) => page.items.map((item) => decodeUsageDenial(item)),
          next.denials,
        ),
      ]);

    if (generation !== requestGeneration.current || controller.signal.aborted) return;

    const usage = preserveOnSoftFailure(
      usageResult,
      sameOrganization ? previous.usage : next.usage,
    );
    const budgets = preserveOnSoftFailure(
      budgetsResult,
      sameOrganization ? previous.budgets : next.budgets,
    );
    const reservations = preserveOnSoftFailure(
      reservationsResult,
      sameOrganization ? previous.reservations : next.reservations,
    );
    const rateLimits = preserveOnSoftFailure(
      rateLimitsResult,
      sameOrganization ? previous.rateLimits : next.rateLimits,
    );
    let denials = preserveOnSoftFailure(
      denialsResult,
      sameOrganization ? previous.denials : next.denials,
    );

    // A denial is observable from immutable usage metadata even when the
    // dedicated denial endpoint is not connected yet. Merge it with a
    // dedicated page without duplicating the same opaque denial ID.
    if (usage.status === "ready") {
      const derived = deriveDenials(usage.data);
      if (!client.listUsageDenials && !seed?.denials) {
        denials = readyResource(derived);
      } else if (denials.status === "ready") {
        const known = new Set(denials.data.map((denial) => denial.denial_id));
        denials = readyResource([
          ...denials.data,
          ...derived.filter((denial) => !known.has(denial.denial_id)),
        ]);
      }
    }

    const trend = seed?.trend ?? buildUsageTrend(usage.data);
    const finalState: PanelState = {
      orgId,
      usage,
      budgets,
      reservations,
      rateLimits,
      denials,
      trend,
      refreshing: false,
    };
    stateRef.current = finalState;
    setState(finalState);
  }, [client, orgId]);

  useEffect(() => {
    void load();
    return () => {
      requestGeneration.current += 1;
      activeController.current?.abort();
    };
  }, [load]);

  const usage = state.usage.data;
  const summary = useMemo(() => summarizeUsage(usage), [usage]);
  const mismatchedOrganization = state.orgId !== orgId;
  if (
    mismatchedOrganization ||
    (state.usage.status === "loading" && state.usage.data.length === 0)
  ) {
    return <LoadingPanel label="Loading usage and budget state…" />;
  }
  if (state.usage.status === "permission") {
    return <PermissionPanel onRetry={() => void load()} />;
  }
  if (state.usage.status === "error" && state.usage.data.length === 0) {
    return <ErrorPanel error={state.usage.error} onRetry={() => void load()} />;
  }
  if (state.usage.status === "unavailable" && state.usage.data.length === 0) {
    return <UnavailablePanel label="Usage state is unavailable" onRetry={() => void load()} />;
  }

  const isStale =
    stale ||
    state.refreshing ||
    state.usage.stale ||
    state.budgets.stale ||
    state.reservations.stale ||
    state.rateLimits.stale ||
    state.denials.stale;
  const updatedAt = latestUsageTimestamp(usage, state.usage.receivedAt);

  function selectTab(next: UsageTab) {
    setActiveTab(next);
    tabRefs.current[next]?.focus();
  }

  function onTabKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    if (event.key === "ArrowRight" || event.key === "ArrowDown") {
      event.preventDefault();
      selectTab(tabs[(index + 1) % tabs.length]?.id ?? "budgets");
    } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
      event.preventDefault();
      selectTab(tabs[(index - 1 + tabs.length) % tabs.length]?.id ?? "budgets");
    } else if (event.key === "Home") {
      event.preventDefault();
      selectTab(tabs[0]?.id ?? "budgets");
    } else if (event.key === "End") {
      event.preventDefault();
      selectTab(tabs.at(-1)?.id ?? "denials");
    }
  }

  return (
    <section aria-label="Usage and budgets" className="space-y-5">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-xs font-semibold tracking-[0.1em] text-[var(--lumi-blue)]">
            USAGE &amp; BUDGETS
          </p>
          <h1 className="mt-1.5 text-2xl font-semibold tracking-[-0.03em] text-[var(--civic-navy)]">
            Monitor spend and limits
          </h1>
          <p className="mt-1 text-sm text-[var(--muted-strong)]">
            Review immutable usage, budget pressure, rate limits, and denied requests for this
            organization.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {isStale ? (
            <span className={staleBadgeClass}>
              {state.refreshing ? "Refreshing" : "Stale snapshot"}
            </span>
          ) : null}
          <span className="text-xs tabular-nums text-[var(--muted)]">
            Updated {formatUsageTimestamp(updatedAt)}
          </span>
          <button
            type="button"
            className={secondaryButton}
            onClick={() => void load()}
            disabled={state.refreshing}
          >
            {state.refreshing ? "Refreshing…" : "Refresh"}
          </button>
        </div>
      </header>

      {isStale && !state.refreshing ? (
        <p role="status" className={noticeClass}>
          This snapshot is stale. Refresh before making a spend or limit decision.
        </p>
      ) : null}
      {state.refreshing && state.usage.data.length > 0 ? (
        <p role="status" className={noticeClass}>
          Refreshing usage data. The last loaded immutable snapshot remains visible until the
          response arrives.
        </p>
      ) : null}
      {state.usage.status === "error" && state.usage.data.length > 0 ? (
        <ErrorPanel error={state.usage.error} onRetry={() => void load()} compact />
      ) : null}
      <ProvenanceNotice summary={summary} />

      <BudgetCards
        summary={summary}
        budgets={state.budgets.data}
        usage={usage}
        reservations={state.reservations.data}
        denials={state.denials.data}
        budgetState={state.budgets.status}
      />

      <div className="border-b border-[var(--border)]">
        <div role="tablist" aria-label="Usage detail views" className="flex gap-1 overflow-x-auto">
          {tabs.map((tab, index) => (
            <button
              key={tab.id}
              ref={(element) => {
                tabRefs.current[tab.id] = element;
              }}
              id={`${tabSetId}-${tab.id}-tab`}
              type="button"
              role="tab"
              aria-selected={activeTab === tab.id}
              aria-controls={`${tabSetId}-${tab.id}-panel`}
              tabIndex={activeTab === tab.id ? 0 : -1}
              onClick={() => selectTab(tab.id)}
              onKeyDown={(event) => onTabKeyDown(event, index)}
              className={tabClass(activeTab === tab.id)}
            >
              {tab.label}
              {tab.id === "denials" && state.denials.data.length > 0 ? (
                <span className="ml-1.5 rounded-full bg-[var(--warning)]/15 px-1.5 py-0.5 text-xs text-[var(--danger)]">
                  {state.denials.data.length}
                </span>
              ) : null}
            </button>
          ))}
        </div>
      </div>

      {tabs.map((tab) => (
        <div
          key={tab.id}
          id={`${tabSetId}-${tab.id}-panel`}
          role="tabpanel"
          aria-labelledby={`${tabSetId}-${tab.id}-tab`}
          hidden={activeTab !== tab.id}
          tabIndex={0}
          className="min-w-0 outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
        >
          {tab.id === "budgets" ? (
            <BudgetTab state={state} usage={usage} onRetry={() => void load()} />
          ) : tab.id === "rate-limits" ? (
            <RateLimitTab state={state} onRetry={() => void load()} />
          ) : (
            <DenialTab state={state} onRetry={() => void load()} />
          )}
        </div>
      ))}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-[var(--civic-navy)]">Usage breakdown</h2>
          <p className="mt-1 text-sm text-[var(--muted-strong)]">
            Compare recorded activity by project, model, or provider without exposing request
            content.
          </p>
        </div>
        <label className="flex items-center gap-2 text-xs font-medium text-[var(--muted-strong)]">
          Group by
          <select
            value={breakdownDimension}
            onChange={(event) =>
              setBreakdownDimension(event.target.value as "project" | "user" | "model" | "provider")
            }
            className="min-h-10 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-2 text-sm outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]"
          >
            <option value="project">Project</option>
            <option value="user">User / service account</option>
            <option value="model">Model</option>
            <option value="provider">Provider</option>
          </select>
        </label>
      </div>
      <UsageBreakdownTable events={usage} dimension={breakdownDimension} />

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-[var(--civic-navy)]">Usage detail</h2>
          <p className="mt-1 text-sm text-[var(--muted-strong)]">
            The table shows the loaded page only. Server pagination and rollups remain
            authoritative.
          </p>
        </div>
        <button
          type="button"
          className={secondaryButton}
          aria-expanded={trendOpen}
          aria-controls={`${tabSetId}-trend`}
          disabled={state.trend.length === 0}
          onClick={() => setTrendOpen((open) => !open)}
        >
          {trendOpen ? "Hide trend" : "Show trend"}
        </button>
      </div>
      {trendOpen ? (
        <div id={`${tabSetId}-trend`}>
          <Suspense fallback={<LoadingPanel label="Loading lightweight trend…" compact />}>
            <LazyUsageTrend points={state.trend} />
          </Suspense>
        </div>
      ) : null}
      <UsageEventsTable events={usage} />
    </section>
  );
}

function BudgetTab({
  state,
  usage,
  onRetry,
}: {
  state: PanelState;
  usage: readonly UsageEvent[];
  onRetry: () => void;
}) {
  if (state.budgets.status === "loading") return <InlineLoading label="Loading budgets…" />;
  if (state.budgets.status === "permission") return <PermissionPanel onRetry={onRetry} compact />;
  if (state.budgets.status === "error") {
    return <ErrorPanel error={state.budgets.error} onRetry={onRetry} compact />;
  }
  if (state.budgets.status === "unavailable") {
    return <UnavailablePanel label="Budget state is unavailable" onRetry={onRetry} compact />;
  }

  return (
    <div className="space-y-4">
      <BudgetList
        budgets={state.budgets.data}
        usage={usage}
        reservations={state.reservations.data}
      />
      {state.reservations.status === "ready" ? (
        <BudgetReservationsTable reservations={state.reservations.data} />
      ) : state.reservations.status === "loading" ? (
        <InlineLoading label="Loading reservations…" />
      ) : state.reservations.status === "unavailable" ? (
        <UnavailablePanel label="Reservation history is unavailable" onRetry={onRetry} compact />
      ) : state.reservations.status === "permission" ? (
        <PermissionPanel onRetry={onRetry} compact />
      ) : (
        <ErrorPanel error={state.reservations.error} onRetry={onRetry} compact />
      )}
    </div>
  );
}

function RateLimitTab({ state, onRetry }: { state: PanelState; onRetry: () => void }) {
  if (state.rateLimits.status === "loading") return <InlineLoading label="Loading rate limits…" />;
  if (state.rateLimits.status === "permission")
    return <PermissionPanel onRetry={onRetry} compact />;
  if (state.rateLimits.status === "error") {
    return <ErrorPanel error={state.rateLimits.error} onRetry={onRetry} compact />;
  }
  if (state.rateLimits.status === "unavailable") {
    return (
      <UnavailablePanel label="Rate-limit policies are unavailable" onRetry={onRetry} compact />
    );
  }
  return <RateLimitPoliciesTable policies={state.rateLimits.data} />;
}

function DenialTab({ state, onRetry }: { state: PanelState; onRetry: () => void }) {
  if (state.denials.status === "loading") return <InlineLoading label="Loading denied requests…" />;
  if (state.denials.status === "permission") return <PermissionPanel onRetry={onRetry} compact />;
  if (state.denials.status === "error") {
    return <ErrorPanel error={state.denials.error} onRetry={onRetry} compact />;
  }
  if (state.denials.status === "unavailable") {
    return (
      <UnavailablePanel label="Denied request history is unavailable" onRetry={onRetry} compact />
    );
  }
  return <DenialTable denials={state.denials.data} />;
}

function ProvenanceNotice({ summary }: { summary: ReturnType<typeof summarizeUsage> }) {
  const hasUnversionedCost = summary.pricingVersions.length === 0 && summary.recordedMinor !== null;
  return (
    <aside className="rounded-xl border border-[var(--lumi-blue)]/25 bg-[var(--lumi-blue-soft)] p-3.5 text-sm text-[var(--civic-navy)]">
      <div className="flex flex-wrap items-start gap-3">
        <span
          className="mt-0.5 grid size-6 shrink-0 place-items-center rounded-full border border-[var(--lumi-blue)]/40 text-xs font-semibold text-[var(--lumi-blue)]"
          aria-hidden="true"
        >
          i
        </span>
        <div className="min-w-0">
          <p className="font-semibold">Usage events are immutable</p>
          <p className="mt-1 text-xs leading-5 text-[var(--muted-strong)]">
            Amounts use the currency and pricing version returned by the server. This view never
            recalculates historical cost, and prompt, response, tool-argument, and secret content is
            not displayed.
          </p>
          {hasUnversionedCost ? (
            <p className="mt-1 text-xs font-medium text-[var(--danger)]">
              Pricing provenance is incomplete on at least one loaded cost-bearing event.
            </p>
          ) : null}
          {summary.unavailableCount > 0 ? (
            <p className="mt-1 text-xs font-medium text-[var(--danger)]">
              {summary.unavailableCount} loaded event{summary.unavailableCount === 1 ? "" : "s"}{" "}
              report an unavailable budget state. Do not treat those events as an approval to spend.
            </p>
          ) : null}
        </div>
      </div>
    </aside>
  );
}

function LoadingPanel({ label, compact = false }: { label: string; compact?: boolean }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={[
        "rounded-xl border border-[var(--border)] bg-[var(--panel)] text-sm text-[var(--muted-strong)] shadow-[var(--shadow)]",
        compact ? "p-4" : "p-8",
      ].join(" ")}
    >
      <div className="flex items-center gap-3">
        <span className="h-2 w-2 rounded-full bg-[var(--lumi-blue)]" aria-hidden="true" />
        <span>{label}</span>
      </div>
      {!compact ? (
        <div className="mt-5 grid gap-3 sm:grid-cols-3" aria-hidden="true">
          <div className="h-16 rounded-lg bg-[var(--panel-hover)]" />
          <div className="h-16 rounded-lg bg-[var(--panel-hover)]" />
          <div className="h-16 rounded-lg bg-[var(--panel-hover)]" />
        </div>
      ) : null}
    </div>
  );
}

function InlineLoading({ label }: { label: string }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 text-sm text-[var(--muted-strong)] shadow-[var(--shadow)]"
    >
      {label}
    </div>
  );
}

function PermissionPanel({ onRetry, compact = false }: { onRetry: () => void; compact?: boolean }) {
  return (
    <section
      role="alert"
      className={[
        "rounded-xl border border-[var(--warning)]/35 bg-[var(--warning)]/10 text-[var(--civic-navy)]",
        compact ? "p-4" : "p-8",
      ].join(" ")}
    >
      <h2 className="text-base font-semibold">Access not permitted</h2>
      <p className="mt-2 max-w-xl text-sm leading-5 text-[var(--muted-strong)]">
        Your current organization role does not include access to this usage surface. Ask an
        administrator to review the `usage.read` or `budgets.read` permission.
      </p>
      <button type="button" className={secondaryButton} onClick={onRetry}>
        Check again
      </button>
    </section>
  );
}

function ErrorPanel({
  error,
  onRetry,
  compact = false,
}: {
  error: unknown;
  onRetry: () => void;
  compact?: boolean;
}) {
  const presentation = presentApiError(error);
  return (
    <section
      role="alert"
      className={[
        "rounded-xl border border-[var(--danger)]/30 bg-[var(--danger)]/5 text-[var(--danger)]",
        compact ? "p-4" : "p-6",
      ].join(" ")}
    >
      <h2 className="text-sm font-semibold">{presentation.title}</h2>
      <p className="mt-1 text-sm leading-5 text-[var(--muted-strong)]">{presentation.message}</p>
      {presentation.requestId ? (
        <p className="mt-1 text-xs text-[var(--muted)]">Request {presentation.requestId}</p>
      ) : null}
      <button type="button" className={secondaryButton} onClick={onRetry}>
        Try again
      </button>
    </section>
  );
}

function UnavailablePanel({
  label,
  onRetry,
  compact = false,
}: {
  label: string;
  onRetry: () => void;
  compact?: boolean;
}) {
  return (
    <section
      role="status"
      className={[
        "rounded-xl border border-[var(--warning)]/35 bg-[var(--warning)]/10 text-[var(--civic-navy)]",
        compact ? "p-4" : "p-8",
      ].join(" ")}
    >
      <h2 className="text-base font-semibold">{label}</h2>
      <p className="mt-2 max-w-xl text-sm leading-5 text-[var(--muted-strong)]">
        The service could not confirm this state. Do not treat it as zero spend or an available
        limit; managed cloud work may fail closed until the state is readable.
      </p>
      <button type="button" className={secondaryButton} onClick={onRetry}>
        Check again
      </button>
    </section>
  );
}

function getDefaultUsageApi(): UsageApi {
  const extensions = apiClient as typeof apiClient & {
    listUsageEvents?: UsageApi["listUsageEvents"];
    listBudgets?: UsageApi["listBudgets"];
    listRateLimits?: UsageApi["listRateLimits"];
    listUsageDenials?: UsageApi["listUsageDenials"];
    listBudgetReservations?: UsageApi["listBudgetReservations"];
  };
  const client: UsageApi = {
    listUsage: (organizationId, signal) =>
      extensions.listUsageEvents
        ? extensions.listUsageEvents(organizationId, signal)
        : apiClient.listUsage(organizationId, signal),
  };
  if (extensions.listUsageEvents) client.listUsageEvents = extensions.listUsageEvents;
  if (extensions.listBudgets) client.listBudgets = extensions.listBudgets;
  if (extensions.listRateLimits) client.listRateLimits = extensions.listRateLimits;
  if (extensions.listUsageDenials) client.listUsageDenials = extensions.listUsageDenials;
  if (extensions.listBudgetReservations)
    client.listBudgetReservations = extensions.listBudgetReservations;
  return client;
}

function scopedInitialData(
  orgId: string,
  data: UsageBudgetsData | undefined,
): UsageBudgetsData | undefined {
  if (data?.orgId && data.orgId !== orgId) return undefined;
  return data;
}

function createInitialState(
  orgId: string,
  client: UsageApi,
  data: UsageBudgetsData | undefined,
): PanelState {
  const usage = data?.usage ? readyResource(data.usage) : loadingResource<UsageEvent>();
  return {
    orgId,
    usage,
    budgets: data?.budgets
      ? readyResource(data.budgets)
      : client.listBudgets
        ? loadingResource<Budget>()
        : unavailableResource("Budget reads are not connected in this client."),
    reservations: data?.reservations
      ? readyResource(data.reservations)
      : client.listBudgetReservations
        ? loadingResource<BudgetReservation>()
        : unavailableResource("Reservation reads are not connected in this client."),
    rateLimits: data?.rateLimits
      ? readyResource(data.rateLimits)
      : client.listRateLimits
        ? loadingResource<RateLimitPolicy>()
        : unavailableResource("Rate-limit reads are not connected in this client."),
    denials: data?.denials
      ? readyResource(data.denials)
      : client.listUsageDenials
        ? loadingResource<UsageDenial>()
        : unavailableResource(
            "Denial reads are not connected; showing immutable usage decisions when available.",
          ),
    trend: data?.trend ?? (data?.usage ? buildUsageTrend(data.usage) : []),
    refreshing: false,
  };
}

async function settleResource<T, P>(
  load: (() => Promise<P>) | undefined,
  decode: (page: P) => T[],
  fallback: ResourceState<T>,
): Promise<ResourceState<T>> {
  if (!load) return fallback;
  try {
    const page = await load();
    if (!isPageLike(page)) throw new UsageContractError();
    return readyResource(decode(page));
  } catch (error) {
    return resourceFromError(error);
  }
}

function isPageLike(value: unknown): value is { items: unknown[] } {
  return (
    typeof value === "object" &&
    value !== null &&
    Array.isArray((value as { items?: unknown }).items)
  );
}

function preserveOnSoftFailure<T>(
  next: ResourceState<T>,
  previous: ResourceState<T>,
): ResourceState<T> {
  if (next.status === "error" && previous.data.length > 0 && previous.status !== "permission") {
    return { ...next, data: previous.data, receivedAt: previous.receivedAt, stale: true };
  }
  return next;
}

function resourceFromError<T>(error: unknown): ResourceState<T> {
  if (
    error instanceof ApiClientError &&
    (error.status === 403 || error.code === "permission_denied")
  ) {
    return permissionResource(error);
  }
  if (isUnavailableError(error))
    return unavailableResource("The service could not confirm this state.");
  return errorResource(error);
}

function isUnavailableError(error: unknown): boolean {
  return (
    error instanceof ApiClientError &&
    (error.status === 503 ||
      error.code === "budget_state_unavailable" ||
      error.code === "service_unavailable" ||
      error.code === "not_implemented")
  );
}

function hasReadyResource(state: PanelState): boolean {
  return [state.usage, state.budgets, state.reservations, state.rateLimits, state.denials].some(
    (resource) => resource.status === "ready",
  );
}

function hasBudgetSeed(state: PanelState): boolean {
  return state.budgets.status === "ready";
}

function hasReservationSeed(state: PanelState): boolean {
  return state.reservations.status === "ready";
}

function hasRateLimitSeed(state: PanelState): boolean {
  return state.rateLimits.status === "ready";
}

function hasDenialSeed(state: PanelState): boolean {
  return state.denials.status === "ready";
}

function markStale<T>(resource: ResourceState<T>): ResourceState<T> {
  return resource.status === "ready" ? { ...resource, stale: true } : resource;
}

function loadingResource<T>(): ResourceState<T> {
  return { status: "loading", data: [], receivedAt: null, error: null, reason: null, stale: false };
}

function readyResource<T>(data: T[]): ResourceState<T> {
  return {
    status: "ready",
    data,
    receivedAt: Date.now(),
    error: null,
    reason: null,
    stale: false,
  };
}

function errorResource<T>(error: unknown): ResourceState<T> {
  return { status: "error", data: [], receivedAt: null, error, reason: null, stale: false };
}

function permissionResource<T>(error: unknown): ResourceState<T> {
  return { status: "permission", data: [], receivedAt: null, error, reason: null, stale: false };
}

function unavailableResource<T>(reason: string): ResourceState<T> {
  return { status: "unavailable", data: [], receivedAt: null, error: null, reason, stale: false };
}

function latestUsageTimestamp(
  events: readonly UsageEvent[],
  receivedAt: number | null,
): string | null {
  const latestEvent = events.reduce<string | null>((latest, event) => {
    if (!latest || event.created_at > latest) return event.created_at;
    return latest;
  }, null);
  if (latestEvent) return latestEvent;
  return receivedAt === null ? null : new Date(receivedAt).toISOString();
}

function tabClass(active: boolean): string {
  return [
    "min-h-11 shrink-0 border-b-2 px-3 text-sm font-medium outline-none transition focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2",
    active
      ? "border-[var(--lumi-blue)] text-[var(--lumi-blue)]"
      : "border-transparent text-[var(--muted-strong)] hover:border-[var(--border-strong)] hover:text-[var(--civic-navy)]",
  ].join(" ");
}

const secondaryButton =
  "inline-flex min-h-10 items-center justify-center rounded-lg border border-[var(--lumi-blue)]/40 bg-[var(--panel)] px-3 text-sm font-medium text-[var(--lumi-blue)] outline-none transition hover:border-[var(--lumi-blue)]/60 hover:bg-[var(--lumi-blue-soft)] active:translate-y-px focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--surface)] disabled:cursor-not-allowed disabled:opacity-50";
const noticeClass =
  "rounded-lg border border-[var(--warning)]/30 bg-[var(--warning)]/10 p-3 text-sm text-[var(--danger)]";
const staleBadgeClass =
  "inline-flex items-center rounded-full bg-[var(--warning)]/15 px-2 py-1 text-xs font-medium text-[var(--danger)]";
