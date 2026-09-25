import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { ApiClientError } from "@/lib/errors";

import {
  BillingContractError,
  defaultBillingApi,
  type BillingApi,
  type BillingPortalSession,
  type BillingSnapshot,
  type EntitlementProjection,
  type PlanChangePreview,
  type ProviderEntitlementProjection,
  type Subscription,
} from "./api";
import { assessPlanChange, countableLimits, type DowngradeAssessment } from "./downgrade";
import { EntitlementTable } from "./entitlement-table";
import { LicenseCapabilityMatrix } from "./license-capabilities";
import { projectLicense, readLicenseClocks } from "./license-state";
import { OverLimitProjectionPanel } from "./downgrade-projection";
import { PlanChangePanel, type PlanActionOutcome } from "./plan-change";
import { ProviderAccountCard } from "./provider-account-card";
import { SubscriptionSummary } from "./subscription-summary";
import {
  BillingDefinitionRow,
  BillingError,
  BillingLoading,
  BillingNotice,
  BillingPanel as BillingSurface,
  BillingPanelHeader,
  BillingPermission,
} from "./ui";

export interface BillingPanelProps {
  orgId: string;
  /**
   * Optional adapter. When omitted, the feature-local client bound to the
   * frozen P06 routes is used. The coordinator may pass a client that also
   * exposes `previewPlanChange` once a real preview route is published.
   */
  api?: BillingApi;
  /** Optional server snapshot for route-level composition or tests. */
  initialData?: BillingSnapshot;
  /**
   * Convenience only. Authorization is enforced server-side; this avoids
   * showing a control the current role cannot use. `undefined` means "unknown",
   * and the controls are shown so a permitted admin is never locked out.
   */
  canManage?: boolean;
  /** Marks a server snapshot as stale even when it is younger than the panel. */
  stale?: boolean;
}

type ResourceStatus = "loading" | "ready" | "error" | "permission" | "unavailable";

interface Resource<T> {
  status: ResourceStatus;
  data: T | null;
  error: unknown;
  stale: boolean;
}

interface PanelState {
  orgId: string;
  /** Increments on every completed load so time-dependent facts re-evaluate. */
  loadToken: number;
  subscription: Resource<Subscription>;
  entitlements: Resource<EntitlementProjection>;
  provider: Resource<ProviderEntitlementProjection>;
  refreshing: boolean;
}

const DECISION_INPUTS = [
  {
    term: "Authorization permission",
    description:
      "Decided by your organization role and the central permission check. It answers whether you may read or change billing at all.",
    doesNot: "It does not decide what the plan includes.",
  },
  {
    term: "Lumi product entitlement",
    description:
      "Decided by the precedence chain: platform default, then plan, then subscription grant, then an audited internal override. It answers what this organization's plan includes.",
    doesNot: "It does not decide whether you may act, and it is not a usage total.",
  },
  {
    term: "Usage budget",
    description:
      "Decided from measured usage and budget records in the Usage & Budgets section. It answers how much work is allowed right now.",
    doesNot: "It does not decide what the plan includes.",
  },
  {
    term: "Upstream provider account status",
    description:
      "Decided by the provider adapter's observation of an external AI provider account. It answers whether provider-managed routes may run.",
    doesNot:
      "It does not grant or revoke a Lumi entitlement, change your plan, or change a permission.",
  },
] as const;

export function BillingPanel({
  orgId,
  api,
  initialData,
  canManage,
  stale = false,
}: BillingPanelProps) {
  const defaultClientRef = useRef<BillingApi | null>(null);
  const client = api ?? (defaultClientRef.current ??= defaultBillingApi());
  const initialDataRef = useRef(initialData);
  initialDataRef.current = initialData;
  const canManageBilling = canManage ?? true;
  const [state, setState] = useState<PanelState>(() =>
    createInitialState(orgId, scopedSnapshot(orgId, initialDataRef.current)),
  );
  const stateRef = useRef(state);
  stateRef.current = state;
  const requestGeneration = useRef(0);
  const activeController = useRef<AbortController | null>(null);

  const [preview, setPreview] = useState<PlanChangePreview | null>(null);
  const [previewRequested, setPreviewRequested] = useState(false);
  const [previewFailed, setPreviewFailed] = useState(false);
  const [action, setAction] = useState<PlanActionOutcome>({ kind: "idle" });
  const [portal, setPortal] = useState<BillingPortalSession | null>(null);

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
      : createInitialState(orgId, scopedSnapshot(orgId, initialDataRef.current));
    const seeded = hasReadyResource(base);
    setState({
      ...base,
      loadToken: previous.loadToken,
      refreshing: true,
      subscription: seeded ? markStale(base.subscription) : loading<Subscription>(),
      entitlements: seeded ? markStale(base.entitlements) : loading<EntitlementProjection>(),
      provider: seeded ? markStale(base.provider) : loading<ProviderEntitlementProjection>(),
    });

    const [subscriptionResult, entitlementsResult, providerResult] = await Promise.all([
      settle(() => client.getSubscription(orgId, controller.signal)),
      settle(() => client.getEntitlements(orgId, controller.signal)),
      settle(() => client.getProviderEntitlement(orgId, controller.signal)),
    ]);

    if (generation !== requestGeneration.current || controller.signal.aborted) return;
    setState({
      orgId,
      loadToken: base.loadToken + 1,
      subscription: keepPrevious(subscriptionResult, base.subscription),
      entitlements: keepPrevious(entitlementsResult, base.entitlements),
      provider: keepPrevious(providerResult, base.provider),
      refreshing: false,
    });
  }, [client, orgId]);

  useEffect(() => {
    void load();
    return () => {
      requestGeneration.current += 1;
      activeController.current?.abort();
    };
  }, [load]);

  // An org switch must not leave another tenant's commercial state on screen.
  useEffect(() => {
    setPreview(null);
    setPreviewRequested(false);
    setPreviewFailed(false);
    setAction({ kind: "idle" });
    setPortal(null);
  }, [orgId]);

  const snapshot = scopedSnapshot(orgId, initialDataRef.current);
  const now = useEvaluationInstant(state.loadToken);
  const license = useMemo(() => {
    const status = state.subscription.data?.status ?? state.entitlements.data?.status ?? null;
    if (!status) return null;
    const clocks = readLicenseClocks({
      offlineValidUntil:
        state.entitlements.data?.offline_valid_until ??
        snapshot?.entitlements?.offline_valid_until ??
        null,
      policyFreshUntil:
        state.entitlements.data?.policy_fresh_until ??
        snapshot?.entitlements?.policy_fresh_until ??
        null,
      graceExpiresAt: state.subscription.data?.grace_expires_at ?? null,
    });
    return projectLicense({
      subscriptionStatus: status,
      providerStatus: state.provider.data?.status ?? "unknown",
      offlineValidUntil: clocks.localUntil,
      policyFreshUntil: clocks.cloudPolicyFreshUntil,
      graceExpiresAt: clocks.cloudGraceExpiresAt,
      paidInferenceGraceSeconds: snapshot?.policy?.platform_paid_inference_grace_seconds ?? 0,
      now,
    });
  }, [snapshot, state.entitlements.data, state.provider.data, state.subscription.data, now]);

  const mismatched = state.orgId !== orgId;
  const primary =
    state.subscription.status === "loading" ||
    state.entitlements.status === "loading" ||
    state.provider.status === "loading";

  if (mismatched || (primary && !hasReadyResource(state))) {
    return (
      <section aria-label="Billing and entitlements" className="space-y-5">
        <PanelHeading stale={stale || state.refreshing} onRefresh={() => void load()} />
        <BillingSurface ariaLabel="Billing and entitlements">
          <BillingLoading label="Loading plan, subscription, and license state…" rows={4} />
        </BillingSurface>
      </section>
    );
  }

  if (state.subscription.status === "permission" || state.entitlements.status === "permission") {
    return (
      <section aria-label="Billing and entitlements" className="space-y-5">
        <PanelHeading stale={stale || state.refreshing} onRefresh={() => void load()} />
        <BillingSurface ariaLabel="Billing and entitlements">
          <div className="p-5">
            <BillingPermission />
          </div>
        </BillingSurface>
      </section>
    );
  }

  if (!state.subscription.data && state.subscription.status === "error") {
    return (
      <section aria-label="Billing and entitlements" className="space-y-5">
        <PanelHeading stale={stale || state.refreshing} onRefresh={() => void load()} />
        <BillingSurface ariaLabel="Billing and entitlements">
          <div className="p-5">
            <BillingError error={state.subscription.error} onRetry={() => void load()} />
          </div>
        </BillingSurface>
      </section>
    );
  }

  if (!state.entitlements.data && state.entitlements.status === "error") {
    return (
      <section aria-label="Billing and entitlements" className="space-y-5">
        <PanelHeading stale={stale || state.refreshing} onRefresh={() => void load()} />
        <BillingSurface ariaLabel="Billing and entitlements">
          <div className="p-5">
            <BillingError error={state.entitlements.error} onRetry={() => void load()} />
          </div>
        </BillingSurface>
      </section>
    );
  }

  if (!state.subscription.data || !state.entitlements.data || !license) {
    return (
      <section aria-label="Billing and entitlements" className="space-y-5">
        <PanelHeading stale={stale || state.refreshing} onRefresh={() => void load()} />
        <BillingSurface ariaLabel="Billing and entitlements">
          <div className="p-5">
            <BillingNotice tone="warning">
              <p className="font-semibold">Commercial state could not be read.</p>
              <p className="mt-1">
                Do not treat an unreadable plan or license state as an available capability. Managed
                cloud work may fail closed until the state is readable.
              </p>
            </BillingNotice>
          </div>
        </BillingSurface>
      </section>
    );
  }

  const isStale = stale || state.refreshing;
  const currentPlanKey = state.entitlements.data.plan_key ?? state.subscription.data.plan_key;
  const previewAvailable = typeof client.previewPlanChange === "function";

  const assessment: DowngradeAssessment = assessPlanChange({
    preview,
    previewRequested,
    previewFailed,
    previewAvailable,
    currentPlanKey,
    targetPlanKey: preview?.target_plan_key ?? "",
  });

  async function runPreview(planKey: string) {
    if (!client.previewPlanChange || planKey.length === 0) return;
    setPreviewRequested(true);
    setPreviewFailed(false);
    setAction({ kind: "busy", label: "Previewing the change…" });
    try {
      const result = await client.previewPlanChange(
        orgId,
        { plan_key: planKey, version: stateRef.current.subscription.data?.version ?? 1 },
        crypto.randomUUID(),
      );
      setPreview(result);
      setAction({ kind: "idle" });
    } catch (error) {
      setPreview(null);
      setPreviewFailed(true);
      setAction({ kind: "failed", error });
    }
  }

  async function runChange(planKey: string) {
    if (!client.requestPlanChange) {
      setAction({
        kind: "failed",
        error: new BillingContractError("billing/change"),
      });
      return;
    }
    setAction({ kind: "busy", label: "Requesting the plan change…" });
    try {
      const result = await client.requestPlanChange(
        orgId,
        { plan_key: planKey, version: stateRef.current.subscription.data?.version ?? 1 },
        crypto.randomUUID(),
      );
      setPreview(null);
      setPreviewRequested(false);
      setAction({
        kind: "done",
        message: result.accepted
          ? `The plan change request was accepted. The server now reports ${
              result.subscription?.plan_key ?? "the new plan"
            }${
              result.over_limit.length > 0
                ? `, with ${result.over_limit.length} resource(s) over the new limit. New work above the limit is blocked; nothing was deleted.`
                : "."
            }`
          : "The provider adapter did not accept the plan change. Nothing was applied and no data was touched.",
      });
      await load();
    } catch (error) {
      setAction({ kind: "failed", error });
    }
  }

  async function runCancellation() {
    if (!client.requestCancellation) {
      setAction({ kind: "failed", error: new BillingContractError("billing/cancel") });
      return;
    }
    setAction({ kind: "busy", label: "Requesting cancellation…" });
    try {
      const result = await client.requestCancellation(
        orgId,
        { version: stateRef.current.subscription.data?.version ?? 1 },
        crypto.randomUUID(),
      );
      setAction({
        kind: "done",
        message: result.accepted
          ? "The cancellation request was accepted. Historical data, audit records, and exports are retained. The subscription row will not reactivate on its own."
          : "The provider adapter did not accept the cancellation request. Nothing changed.",
      });
      await load();
    } catch (error) {
      setAction({ kind: "failed", error });
    }
  }

  async function runPortal() {
    if (!client.createPortalSession) {
      setPortal({
        portal_url: null,
        expires_at: null,
        reason: "This deployment does not expose a billing portal session.",
      });
      return;
    }
    setAction({ kind: "busy", label: "Opening the provider portal…" });
    try {
      setPortal(await client.createPortalSession(orgId, crypto.randomUUID()));
      setAction({ kind: "idle" });
    } catch (error) {
      setAction({ kind: "failed", error });
    }
  }

  return (
    <section aria-label="Billing and entitlements" className="space-y-5">
      <PanelHeading stale={isStale} onRefresh={() => void load()} refreshing={state.refreshing} />

      {isStale ? (
        <BillingNotice tone="warning">
          This commercial snapshot is stale. Refresh before making a plan or capacity decision. A
          stale plan is not an available plan.
        </BillingNotice>
      ) : null}

      <DecisionInputs />

      <SubscriptionSummary
        subscription={state.subscription.data}
        license={license}
        canManage={canManageBilling}
        onRefresh={() => void load()}
        refreshing={state.refreshing}
      />

      {state.entitlements.stale || state.entitlements.status === "error" ? (
        <BillingError error={state.entitlements.error} onRetry={() => void load()} />
      ) : null}

      <EntitlementTable projection={state.entitlements.data} onRefresh={() => void load()} />

      <LicenseCapabilityMatrix
        license={license}
        clocks={readLicenseClocks({
          offlineValidUntil: state.entitlements.data.offline_valid_until,
          policyFreshUntil: state.entitlements.data.policy_fresh_until,
          graceExpiresAt: state.subscription.data.grace_expires_at,
        })}
      />

      {state.provider.status === "loading" ? (
        <BillingSurface ariaLabel="Upstream provider account status">
          <BillingLoading label="Loading the upstream provider account projection…" rows={2} />
        </BillingSurface>
      ) : state.provider.status === "permission" ? (
        <BillingSurface ariaLabel="Upstream provider account status">
          <div className="p-5">
            <BillingPermission message="Your current organization role cannot read the upstream provider account projection." />
          </div>
        </BillingSurface>
      ) : state.provider.status === "error" ? (
        <BillingSurface ariaLabel="Upstream provider account status">
          <div className="p-5">
            <BillingError error={state.provider.error} onRetry={() => void load()} />
          </div>
        </BillingSurface>
      ) : state.provider.data ? (
        <ProviderAccountCard
          projection={state.provider.data}
          observedStateStaleAfterSeconds={snapshot?.policy?.policy_fresh_seconds ?? null}
        />
      ) : (
        <BillingSurface ariaLabel="Upstream provider account status">
          <div className="p-5">
            <BillingNotice tone="warning">
              The upstream provider account projection is unavailable. It is not a Lumi entitlement,
              and its absence grants nothing.
            </BillingNotice>
          </div>
        </BillingSurface>
      )}

      {state.entitlements.data.over_limit.length > 0 ? (
        <OverLimitProjectionPanel
          assessment={assessPlanChange({
            preview: null,
            previewRequested: false,
            previewFailed: false,
            previewAvailable: true,
            currentPlanKey,
            targetPlanKey: currentPlanKey,
          })}
          title="Resources already over the current plan limit"
          description="The server computed these counts from authoritative rows. New and expanded work above the limit is blocked until the count is inside it."
        />
      ) : null}

      {assessment.overLimit.length > 0 ? (
        <OverLimitProjectionPanel
          assessment={assessment}
          title={`Preview of the change to ${assessment.targetPlanKey}`}
          description="This is what the server would do if the change were submitted. Nothing has been applied yet."
        />
      ) : null}

      <PlanChangePanel
        currentPlanKey={currentPlanKey}
        canManage={canManageBilling}
        previewAvailable={previewAvailable}
        preview={assessment.previewAvailable ? assessment : null}
        previewRequested={previewRequested}
        previewFailed={previewFailed}
        action={action}
        onPreview={(planKey) => void runPreview(planKey)}
        onSubmitChange={(planKey) => void runChange(planKey)}
        onCancel={() => void runCancellation()}
        onOpenPortal={() => void runPortal()}
        portalUnavailableReason={portal ? (portal.reason ?? "No portal URL was returned.") : null}
      />

      {portal?.portal_url ? (
        <BillingSurface ariaLabel="Provider billing portal">
          <div className="p-5">
            <BillingNotice tone="info">
              <p className="font-semibold">A short-lived provider portal session is ready.</p>
              <p className="mt-1">
                Card data never enters Lumi. The link is short-lived and only opens the allowlisted
                provider portal.
              </p>
              <a
                href={portal.portal_url}
                target="_blank"
                rel="noreferrer noopener"
                className="mt-2 inline-flex min-h-11 items-center rounded-lg border border-[var(--lumi-blue)]/40 px-3 text-sm font-medium text-[var(--lumi-blue)] outline-none transition hover:bg-[var(--lumi-blue-soft)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
              >
                Open the provider portal
              </a>
            </BillingNotice>
          </div>
        </BillingSurface>
      ) : null}

      <LimitsAndBudgetsNote
        countedLimits={countableLimits(state.entitlements.data.entitlements).length}
        entitlementCount={state.entitlements.data.entitlements.length}
      />
    </section>
  );
}

function PanelHeading({
  stale,
  refreshing = false,
  onRefresh,
}: {
  stale: boolean;
  refreshing?: boolean;
  onRefresh: () => void;
}) {
  return (
    <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p className="text-xs font-semibold tracking-[0.1em] text-[var(--lumi-blue)]">
          BILLING &amp; ENTITLEMENTS
        </p>
        <h1 className="mt-1.5 text-2xl font-semibold tracking-[-0.03em] text-[var(--civic-navy)]">
          Plan, subscription, and licensing
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-[var(--muted-strong)]">
          What the plan includes, what the current license state allows, and what a downgrade would
          change. Four separate inputs decide this page, and they are never merged.
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

function DecisionInputs() {
  return (
    <BillingSurface ariaLabel="Four separate decision inputs">
      <BillingPanelHeader
        eyebrow="HOW TO READ THIS PAGE"
        title="Four separate decision inputs"
        description="Authorization, product entitlement, usage budget, and upstream provider account status are four different things. Collapsing them produces wrong answers, so this page keeps them apart."
      />
      <dl className="px-5 py-1">
        {DECISION_INPUTS.map((item) => (
          <BillingDefinitionRow key={item.term} term={item.term} description={item.description}>
            <p className="text-xs text-[var(--muted)]">{item.doesNot}</p>
          </BillingDefinitionRow>
        ))}
      </dl>
    </BillingSurface>
  );
}

function LimitsAndBudgetsNote({
  entitlementCount,
  countedLimits,
}: {
  entitlementCount: number;
  countedLimits: number;
}) {
  return (
    <p className="text-xs leading-5 text-[var(--muted)]">
      This projection reports {entitlementCount} entitlement key{entitlementCount === 1 ? "" : "s"},
      of which {countedLimits} are counted limits. Current usage and budgets are measured and
      enforced in the Usage &amp; Budgets section, which is a separate input from the plan. Nothing
      on this page authorizes a request, and nothing on this page deletes data.
    </p>
  );
}

// ---------------------------------------------------------------------------
// State helpers
// ---------------------------------------------------------------------------

function loading<T>(): Resource<T> {
  return { status: "loading", data: null, error: null, stale: false };
}

function ready<T>(data: T): Resource<T> {
  return { status: "ready", data, error: null, stale: false };
}

function fromError<T>(error: unknown): Resource<T> {
  if (
    error instanceof ApiClientError &&
    (error.status === 403 || error.code === "permission_denied")
  ) {
    return { status: "permission", data: null, error, stale: false };
  }
  if (
    error instanceof ApiClientError &&
    (error.status === 503 || error.code === "subscription_state_unavailable")
  ) {
    return { status: "unavailable", data: null, error, stale: false };
  }
  return { status: "error", data: null, error, stale: false };
}

async function settle<T>(load: () => Promise<T>): Promise<Resource<T>> {
  try {
    return ready(await load());
  } catch (error) {
    return fromError<T>(error);
  }
}

function keepPrevious<T>(next: Resource<T>, previous: Resource<T>): Resource<T> {
  if (next.status === "error" && previous.data !== null && previous.status !== "permission") {
    return { ...next, data: previous.data, stale: true };
  }
  return next;
}

function markStale<T>(resource: Resource<T>): Resource<T> {
  return resource.status === "ready" ? { ...resource, stale: true } : resource;
}

function hasReadyResource(state: PanelState): boolean {
  return (
    state.subscription.status === "ready" ||
    state.entitlements.status === "ready" ||
    state.provider.status === "ready"
  );
}

function scopedSnapshot(
  orgId: string,
  data: BillingSnapshot | undefined,
): BillingSnapshot | undefined {
  if (data?.orgId && data.orgId !== orgId) return undefined;
  return data;
}

function createInitialState(orgId: string, data: BillingSnapshot | undefined): PanelState {
  return {
    orgId,
    loadToken: 0,
    subscription: data?.subscription ? ready(data.subscription) : loading<Subscription>(),
    entitlements: data?.entitlements ? ready(data.entitlements) : loading<EntitlementProjection>(),
    provider: data?.provider ? ready(data.provider) : loading<ProviderEntitlementProjection>(),
    refreshing: false,
  };
}

/**
 * The license projection is time-dependent because two of its inputs are
 * deadlines. Re-evaluate on every completed load and once a minute; the
 * interval is cleared on unmount and is the only timer this panel owns.
 */
function useEvaluationInstant(loadToken: number): Date {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    setNow(new Date());
    const handle = setInterval(() => setNow(new Date()), 60_000);
    return () => clearInterval(handle);
  }, [loadToken]);
  return now;
}
