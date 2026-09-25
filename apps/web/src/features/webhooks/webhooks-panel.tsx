/**
 * Webhook endpoint administration (`/org/:slug/settings/webhooks`).
 *
 * Frozen contract: `docs/implementation/gates/P06-CG.md`. The panel lists and
 * edits endpoints, rotates the signing secret (shown exactly once), sends a
 * bounded test delivery, and exposes delivery history with retry, dead-letter,
 * and replay lineage.
 *
 * Tenant and authorization decisions stay server-side. Every mutation carries a
 * CSRF token and an idempotency key, and every state-changing request carries
 * the current resource `version` so a stale write is refused rather than
 * silently applied.
 */

import { useCallback, useEffect, useId, useRef, useState } from "react";

import {
  createWebhookEndpoint,
  disableWebhookEndpoint,
  listWebhookDeliveries,
  listWebhookEndpoints,
  replayWebhookDelivery,
  rotateWebhookSecret,
  sendWebhookTest,
  updateWebhookEndpoint,
  type CreateWebhookEndpointInput,
  type WebhookDelivery,
  type WebhookDeliveryState,
  type WebhookEndpoint,
} from "./api";
import { DeliveryHistory } from "./delivery-history";
import {
  emptyEndpointFormValues,
  EndpointForm,
  endpointFormValues,
  type EndpointFormValues,
} from "./endpoint-form";
import { partitionSubscription } from "./event-types";
import {
  endpointActivation,
  endpointActivationDetail,
  endpointActivationLabel,
  endpointActivationTone,
  formatDateTime,
  isAmbiguousMutationFailure,
  isPermissionFailure,
  isVersionConflict,
} from "./helpers";
import { useOneTimeSecret } from "./one-time-secret";
import { SecretReveal } from "./secret-reveal";
import {
  dangerButtonClass,
  EmptyState,
  ErrorNotice,
  ghostButtonClass,
  LoadingRows,
  Metadata,
  Notice,
  PaginationFooter,
  PermissionState,
  Pill,
  primaryButtonClass,
  secondaryButtonClass,
  Surface,
  SurfaceHeader,
} from "./ui";

const ENDPOINT_PAGE_SIZE = 25;
const DELIVERY_PAGE_SIZE = 25;

type LoadStatus = "idle" | "loading" | "refreshing" | "ready" | "error";

interface EndpointCollection {
  readonly orgId: string;
  readonly status: LoadStatus;
  readonly items: WebhookEndpoint[];
  readonly nextCursor: string | null;
  readonly hasMore: boolean;
  readonly error: unknown;
}

interface DeliveryCollection {
  readonly orgId: string;
  readonly endpointId: string | null;
  readonly status: LoadStatus;
  readonly items: WebhookDelivery[];
  readonly nextCursor: string | null;
  readonly hasMore: boolean;
  readonly error: unknown;
}

type EditorMode = "create" | "edit" | null;

interface ConfirmState {
  readonly kind: "disable" | "rotate" | "replay";
  readonly endpoint: WebhookEndpoint;
  readonly delivery?: WebhookDelivery;
}

export interface WebhooksPanelProps {
  orgId: string;
}

export function WebhooksPanel({ orgId }: WebhooksPanelProps) {
  const panelId = useId();
  const detailRef = useRef<HTMLDivElement | null>(null);
  const secret = useOneTimeSecret();

  const [endpoints, setEndpoints] = useState<EndpointCollection>(() => emptyEndpoints(orgId));
  const [selectedEndpointId, setSelectedEndpointId] = useState<string | null>(null);
  const selectedEndpointIdRef = useRef<string | null>(null);
  const [deliveries, setDeliveries] = useState<DeliveryCollection>(() => emptyDeliveries(orgId));
  const [selectedDeliveryId, setSelectedDeliveryId] = useState<string | null>(null);
  const [deliveryStateFilter, setDeliveryStateFilter] = useState<WebhookDeliveryState | "">("");

  const [editor, setEditor] = useState<EditorMode>(null);
  const [formValues, setFormValues] = useState<EndpointFormValues>(emptyEndpointFormValues);
  const [formError, setFormError] = useState<unknown>(null);
  const [busyAction, setBusyAction] = useState<
    "save" | "test" | "rotate" | "disable" | "enable" | "replay" | null
  >(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<ConfirmState | null>(null);

  const endpointController = useRef<AbortController | null>(null);
  const deliveryController = useRef<AbortController | null>(null);
  const endpointGeneration = useRef(0);
  const deliveryGeneration = useRef(0);
  const idempotencyKeys = useRef(new Map<string, string>());
  const orgIdRef = useRef(orgId);
  const mutationGeneration = useRef(0);
  orgIdRef.current = orgId;

  useEffect(() => {
    selectedEndpointIdRef.current = selectedEndpointId;
  }, [selectedEndpointId]);

  // A new organization is a new tenant boundary: drop every secret, selection,
  // in-flight request, and idempotency key rather than carrying them across.
  useEffect(() => {
    mutationGeneration.current += 1;
    idempotencyKeys.current.clear();
    setSelectedEndpointId(null);
    selectedEndpointIdRef.current = null;
    setEditor(null);
    setFormError(null);
    setActionError(null);
    setNotice(null);
    setConfirm(null);
    setBusyAction(null);
    setDeliveryStateFilter("");
    setSelectedDeliveryId(null);
    secret.forget();
    return () => {
      mutationGeneration.current += 1;
    };
  }, [orgId, secret.forget]);

  const refreshEndpoints = useCallback(async () => {
    endpointController.current?.abort();
    const controller = new AbortController();
    endpointController.current = controller;
    const generation = ++endpointGeneration.current;
    setEndpoints((current) =>
      current.orgId === orgId && current.items.length > 0
        ? { ...current, status: "refreshing", error: null }
        : { ...emptyEndpoints(orgId), status: "loading" },
    );
    try {
      const page = await listWebhookEndpoints(
        orgId,
        { limit: ENDPOINT_PAGE_SIZE, include_disabled: true },
        controller.signal,
      );
      if (controller.signal.aborted || generation !== endpointGeneration.current) return;
      const current = selectedEndpointIdRef.current;
      const nextSelection =
        current && page.items.some((item) => item.endpoint_id === current)
          ? current
          : (page.items[0]?.endpoint_id ?? null);
      selectedEndpointIdRef.current = nextSelection;
      setSelectedEndpointId(nextSelection);
      setEndpoints({
        orgId,
        status: "ready",
        items: page.items,
        nextCursor: page.next_cursor,
        hasMore: page.has_more,
        error: null,
      });
    } catch (error) {
      if (controller.signal.aborted || generation !== endpointGeneration.current) return;
      setEndpoints((current) => ({
        ...(current.orgId === orgId ? current : emptyEndpoints(orgId)),
        status: current.orgId === orgId && current.items.length > 0 ? "ready" : "error",
        error,
      }));
    }
  }, [orgId]);

  const loadMoreEndpoints = useCallback(async () => {
    if (endpoints.orgId !== orgId || !endpoints.hasMore || !endpoints.nextCursor) return;
    endpointController.current?.abort();
    const controller = new AbortController();
    endpointController.current = controller;
    const generation = ++endpointGeneration.current;
    setEndpoints((current) => ({ ...current, status: "refreshing", error: null }));
    try {
      const page = await listWebhookEndpoints(
        orgId,
        { limit: ENDPOINT_PAGE_SIZE, cursor: endpoints.nextCursor, include_disabled: true },
        controller.signal,
      );
      if (controller.signal.aborted || generation !== endpointGeneration.current) return;
      setEndpoints((current) => ({
        ...current,
        status: "ready",
        items: [...current.items, ...page.items],
        nextCursor: page.next_cursor,
        hasMore: page.has_more,
        error: null,
      }));
    } catch (error) {
      if (controller.signal.aborted || generation !== endpointGeneration.current) return;
      setEndpoints((current) => ({ ...current, status: "ready", error }));
    }
  }, [endpoints.hasMore, endpoints.nextCursor, endpoints.orgId, orgId]);

  const refreshDeliveries = useCallback(async () => {
    const endpointId = selectedEndpointIdRef.current;
    if (!endpointId) {
      setDeliveries(emptyDeliveries(orgId));
      return;
    }
    deliveryController.current?.abort();
    const controller = new AbortController();
    deliveryController.current = controller;
    const generation = ++deliveryGeneration.current;
    setDeliveries((current) =>
      current.endpointId === endpointId && current.items.length > 0
        ? { ...current, status: "refreshing", error: null }
        : { ...emptyDeliveries(orgId), endpointId, status: "loading" },
    );
    try {
      const page = await listWebhookDeliveries(
        orgId,
        endpointId,
        {
          limit: DELIVERY_PAGE_SIZE,
          ...(deliveryStateFilter ? { state: deliveryStateFilter } : {}),
        },
        controller.signal,
      );
      if (controller.signal.aborted || generation !== deliveryGeneration.current) return;
      setDeliveries({
        orgId,
        endpointId,
        status: "ready",
        items: page.items,
        nextCursor: page.next_cursor,
        hasMore: page.has_more,
        error: null,
      });
    } catch (error) {
      if (controller.signal.aborted || generation !== deliveryGeneration.current) return;
      setDeliveries((current) => ({
        ...(current.endpointId === endpointId ? current : emptyDeliveries(orgId)),
        status: current.endpointId === endpointId && current.items.length > 0 ? "ready" : "error",
        error,
      }));
    }
  }, [deliveryStateFilter, orgId]);

  const loadMoreDeliveries = useCallback(async () => {
    const endpointId = selectedEndpointIdRef.current;
    if (!endpointId || deliveries.orgId !== orgId || deliveries.endpointId !== endpointId) return;
    if (!deliveries.hasMore || !deliveries.nextCursor) return;
    deliveryController.current?.abort();
    const controller = new AbortController();
    deliveryController.current = controller;
    const generation = ++deliveryGeneration.current;
    setDeliveries((current) => ({ ...current, status: "refreshing", error: null }));
    try {
      const page = await listWebhookDeliveries(
        orgId,
        endpointId,
        {
          limit: DELIVERY_PAGE_SIZE,
          cursor: deliveries.nextCursor,
          ...(deliveryStateFilter ? { state: deliveryStateFilter } : {}),
        },
        controller.signal,
      );
      if (controller.signal.aborted || generation !== deliveryGeneration.current) return;
      setDeliveries((current) => ({
        ...current,
        status: "ready",
        items: [...current.items, ...page.items],
        nextCursor: page.next_cursor,
        hasMore: page.has_more,
        error: null,
      }));
    } catch (error) {
      if (controller.signal.aborted || generation !== deliveryGeneration.current) return;
      setDeliveries((current) => ({ ...current, status: "ready", error }));
    }
  }, [
    deliveries.hasMore,
    deliveries.nextCursor,
    deliveries.orgId,
    deliveries.endpointId,
    deliveryStateFilter,
    orgId,
  ]);

  useEffect(() => {
    void refreshEndpoints();
    return () => {
      endpointController.current?.abort();
      endpointGeneration.current += 1;
    };
  }, [refreshEndpoints]);

  useEffect(() => {
    void refreshDeliveries();
    return () => {
      deliveryController.current?.abort();
      deliveryGeneration.current += 1;
    };
  }, [refreshDeliveries, selectedEndpointId]);

  // Move focus with the selection so a keyboard operator lands on the detail
  // they just asked for instead of staying on the table row.
  useEffect(() => {
    if (selectedEndpointId) detailRef.current?.focus();
  }, [selectedEndpointId]);

  function operationKey(name: string): string {
    const existing = idempotencyKeys.current.get(name);
    if (existing) return existing;
    const created = crypto.randomUUID();
    idempotencyKeys.current.set(name, created);
    return created;
  }

  function releaseOperationKey(name: string) {
    idempotencyKeys.current.delete(name);
  }

  function openCreate() {
    setActionError(null);
    setNotice(null);
    setFormError(null);
    setFormValues(emptyEndpointFormValues());
    setEditor("create");
  }

  function openEdit(endpoint: WebhookEndpoint) {
    setActionError(null);
    setNotice(null);
    setFormError(null);
    setFormValues(endpointFormValues(endpoint));
    setEditor("edit");
  }

  function closeEditor() {
    if (busyAction === "save") return;
    setEditor(null);
    setFormError(null);
  }

  async function saveEndpoint(input: CreateWebhookEndpointInput) {
    const editing = editor === "edit";
    const endpoint = selectedEndpoint;
    if (editing && !endpoint) return;
    setBusyAction("save");
    setFormError(null);
    setActionError(null);
    const keyName = editing && endpoint ? `patch:${endpoint.endpoint_id}` : "create";
    const key = operationKey(keyName);
    const generation = mutationGeneration.current;
    try {
      if (editing && endpoint) {
        const updated = await updateWebhookEndpoint(
          orgId,
          endpoint.endpoint_id,
          { ...input, version: endpoint.version },
          key,
        );
        releaseOperationKey(keyName);
        setEditor(null);
        setNotice(`Endpoint ${updated.name} saved at version ${updated.version}.`);
        await refreshEndpoints();
      } else {
        const created = await createWebhookEndpoint(orgId, input, key);
        releaseOperationKey(keyName);
        setEditor(null);
        secret.reveal(created.secret, "created");
        setNotice(
          `Endpoint ${created.endpoint.name} created. Copy the signing secret now — it is shown once.`,
        );
        selectedEndpointIdRef.current = created.endpoint.endpoint_id;
        setSelectedEndpointId(created.endpoint.endpoint_id);
        await refreshEndpoints();
      }
    } catch (error) {
      if (mutationGeneration.current !== generation) return;
      if (isVersionConflict(error)) releaseOperationKey(keyName);
      setFormError(error);
      if (isVersionConflict(error)) void refreshEndpoints();
    } finally {
      if (mutationGeneration.current === generation) setBusyAction(null);
    }
  }

  async function sendTest(endpoint: WebhookEndpoint) {
    setBusyAction("test");
    setActionError(null);
    setNotice(null);
    const key = operationKey(`test:${endpoint.endpoint_id}`);
    try {
      const queued = await sendWebhookTest(orgId, endpoint.endpoint_id, key);
      releaseOperationKey(`test:${endpoint.endpoint_id}`);
      setNotice(
        `Test delivery ${queued.delivery_id} queued. It appears in delivery history once the worker runs it.`,
      );
      await refreshDeliveries();
    } catch (error) {
      setActionError(error);
    } finally {
      setBusyAction(null);
    }
  }

  async function enableEndpoint(endpoint: WebhookEndpoint) {
    setBusyAction("enable");
    setActionError(null);
    setNotice(null);
    const keyName = `enable:${endpoint.endpoint_id}`;
    try {
      const updated = await updateWebhookEndpoint(
        orgId,
        endpoint.endpoint_id,
        {
          name: endpoint.name,
          url: endpoint.url,
          subscribed_event_types: endpoint.subscribed_event_types,
          description: endpoint.description,
          enabled: true,
          max_attempts: endpoint.max_attempts,
          base_delay_seconds: endpoint.base_delay_seconds,
          max_delay_seconds: endpoint.max_delay_seconds,
          replay_window_seconds: endpoint.replay_window_seconds,
          auto_disable_enabled: endpoint.auto_disable_enabled,
          auto_disable_threshold: endpoint.auto_disable_threshold,
          version: endpoint.version,
        },
        operationKey(keyName),
      );
      releaseOperationKey(keyName);
      setNotice(
        updated.auto_disable_enabled
          ? `Endpoint enabled. Auto-disable stays armed at ${updated.auto_disable_threshold} consecutive terminal failures.`
          : "Endpoint enabled. It will accept new deliveries again.",
      );
      await refreshEndpoints();
    } catch (error) {
      if (isVersionConflict(error)) {
        releaseOperationKey(keyName);
        void refreshEndpoints();
      }
      setActionError(error);
    } finally {
      setBusyAction(null);
    }
  }

  async function runConfirmedAction() {
    if (!confirm) return;
    const { kind, endpoint } = confirm;
    const delivery = confirm.delivery ?? null;
    if (kind === "disable") {
      await performDisable(endpoint);
      return;
    }
    if (kind === "rotate") {
      await performRotate(endpoint);
      return;
    }
    if (kind === "replay" && delivery) {
      await performReplay(endpoint, delivery);
    }
  }

  async function performDisable(endpoint: WebhookEndpoint) {
    setBusyAction("disable");
    setActionError(null);
    setNotice(null);
    const keyName = `disable:${endpoint.endpoint_id}`;
    try {
      await disableWebhookEndpoint(
        orgId,
        endpoint.endpoint_id,
        { version: endpoint.version },
        operationKey(keyName),
      );
      releaseOperationKey(keyName);
      setConfirm(null);
      setNotice(
        "Endpoint disabled. Pending deliveries were cancelled; delivered and dead-letter history is kept.",
      );
      await refreshEndpoints();
    } catch (error) {
      if (isVersionConflict(error)) {
        releaseOperationKey(keyName);
        void refreshEndpoints();
      }
      setConfirm(null);
      setActionError(error);
    } finally {
      setBusyAction(null);
    }
  }

  async function performRotate(endpoint: WebhookEndpoint) {
    setBusyAction("rotate");
    setActionError(null);
    setNotice(null);
    const keyName = `rotate:${endpoint.endpoint_id}`;
    try {
      const rotated = await rotateWebhookSecret(orgId, endpoint.endpoint_id, operationKey(keyName));
      releaseOperationKey(keyName);
      setConfirm(null);
      secret.reveal(rotated.secret, "rotated");
      setNotice(`Secret version ${rotated.secret_version_id} is now signing new deliveries.`);
      await refreshEndpoints();
    } catch (error) {
      if (isVersionConflict(error)) releaseOperationKey(keyName);
      setConfirm(null);
      setActionError(error);
    } finally {
      setBusyAction(null);
    }
  }

  async function performReplay(endpoint: WebhookEndpoint, delivery: WebhookDelivery) {
    setBusyAction("replay");
    setActionError(null);
    setNotice(null);
    const keyName = `replay:${delivery.delivery_id}`;
    try {
      const replayed = await replayWebhookDelivery(
        orgId,
        delivery.delivery_id,
        { version: delivery.version },
        operationKey(keyName),
      );
      releaseOperationKey(keyName);
      setConfirm(null);
      setNotice(
        `Successor delivery ${replayed.delivery_id} created from ${delivery.delivery_id}. The original stays dead-lettered.`,
      );
      await refreshDeliveries();
    } catch (error) {
      if (isVersionConflict(error)) {
        releaseOperationKey(keyName);
        void refreshDeliveries();
      }
      setConfirm(null);
      setActionError(error);
    } finally {
      setBusyAction(null);
    }
  }

  const visibleEndpoints = endpoints.orgId === orgId ? endpoints : emptyEndpoints(orgId);
  const selectedEndpoint =
    visibleEndpoints.items.find((item) => item.endpoint_id === selectedEndpointId) ?? null;
  const visibleDeliveries: DeliveryCollection =
    deliveries.orgId === orgId && deliveries.endpointId === selectedEndpointId
      ? deliveries
      : { ...emptyDeliveries(orgId), endpointId: selectedEndpointId };
  const refreshing = visibleEndpoints.status === "refreshing";

  return (
    <section aria-labelledby={`${panelId}-title`} className="space-y-5">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-xs font-semibold tracking-[0.1em] text-[var(--lumi-blue)]">
            SETTINGS / WEBHOOKS
          </p>
          <h2
            id={`${panelId}-title`}
            className="mt-2 text-2xl font-semibold tracking-[-0.03em] text-[var(--civic-navy)]"
          >
            Webhook endpoints
          </h2>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-[var(--muted-strong)]">
            Each endpoint receives one signed HTTPS POST per matching event. Delivery is
            at-least-once: a retry reuses the same event ID, and consumers must deduplicate on it.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            className={secondaryButtonClass}
            onClick={() => void refreshEndpoints()}
            disabled={refreshing}
          >
            {refreshing ? "Refreshing…" : "Refresh"}
          </button>
          <button
            type="button"
            className={primaryButtonClass}
            onClick={openCreate}
            disabled={busyAction !== null}
          >
            New endpoint
          </button>
        </div>
      </header>

      {notice ? (
        <p
          role="status"
          className="rounded-lg border border-[var(--success)]/30 bg-[var(--success)]/5 p-3 text-sm text-[var(--success)]"
        >
          {notice}
        </p>
      ) : null}
      {actionError ? (
        <ErrorNotice
          error={actionError}
          title={
            isAmbiguousMutationFailure(actionError)
              ? "The server did not confirm the result"
              : "The action could not be completed"
          }
        />
      ) : null}
      {isAmbiguousMutationFailure(actionError) ? (
        <Notice tone="warning">
          The request may already have been applied. Refresh before retrying; the retry reuses the
          same idempotency key, so it cannot duplicate the mutation.
        </Notice>
      ) : null}

      {secret.state.secret ? <SecretReveal state={secret.state} onForget={secret.forget} /> : null}

      {editor ? (
        <Surface
          ariaLabel={editor === "create" ? "Create webhook endpoint" : "Edit webhook endpoint"}
        >
          <div className="p-5">
            <EndpointForm
              key={editor === "create" ? "create" : (selectedEndpoint?.endpoint_id ?? "edit")}
              mode={editor}
              initialValues={formValues}
              busy={busyAction === "save"}
              error={formError}
              onSubmit={(input) => void saveEndpoint(input)}
              onCancel={closeEditor}
            />
          </div>
        </Surface>
      ) : null}

      <EndpointTable
        endpoints={visibleEndpoints.items}
        status={visibleEndpoints.status}
        error={visibleEndpoints.error}
        hasMore={visibleEndpoints.hasMore}
        selectedEndpointId={selectedEndpointId}
        onSelect={(endpointId) => {
          selectedEndpointIdRef.current = endpointId;
          setSelectedEndpointId(endpointId);
          setActionError(null);
          setNotice(null);
        }}
        onRetry={() => void refreshEndpoints()}
        onLoadMore={() => void loadMoreEndpoints()}
      />

      {visibleEndpoints.status === "error" && isPermissionFailure(visibleEndpoints.error) ? (
        <PermissionState resource="webhook endpoints" />
      ) : null}

      {selectedEndpoint ? (
        <>
          <EndpointDetail
            sectionRef={detailRef}
            endpoint={selectedEndpoint}
            busyAction={busyAction}
            onEdit={() => openEdit(selectedEndpoint)}
            onTest={() => void sendTest(selectedEndpoint)}
            onRotate={() => setConfirm({ kind: "rotate", endpoint: selectedEndpoint })}
            onDisable={() => setConfirm({ kind: "disable", endpoint: selectedEndpoint })}
            onEnable={() => void enableEndpoint(selectedEndpoint)}
          />
          <DeliveryHistory
            endpoint={selectedEndpoint}
            deliveries={visibleDeliveries.items}
            selectedDeliveryId={selectedDeliveryId}
            status={visibleDeliveries.status === "idle" ? "loading" : visibleDeliveries.status}
            error={visibleDeliveries.error}
            hasMore={visibleDeliveries.hasMore}
            stateFilter={deliveryStateFilter}
            onStateFilterChange={(next) => {
              setDeliveryStateFilter(next);
              setSelectedDeliveryId(null);
            }}
            onRetry={() => void refreshDeliveries()}
            onLoadMore={() => void loadMoreDeliveries()}
            onSelectDelivery={(deliveryId) => {
              if (visibleDeliveries.items.some((item) => item.delivery_id === deliveryId)) {
                setSelectedDeliveryId(deliveryId);
                return;
              }
              // The predecessor may sit on an earlier page; refresh, then select.
              setSelectedDeliveryId(deliveryId);
              void refreshDeliveries();
            }}
            onReplay={(delivery) =>
              setConfirm({ kind: "replay", endpoint: selectedEndpoint, delivery })
            }
            replayingDeliveryId={
              busyAction === "replay" ? (confirm?.delivery?.delivery_id ?? null) : null
            }
            replayError={busyAction === "replay" ? null : actionError}
          />
        </>
      ) : visibleEndpoints.status === "ready" ? (
        <Surface ariaLabel="No endpoint selected">
          <EmptyState
            title={
              visibleEndpoints.items.length === 0 ? "No webhook endpoints" : "Select an endpoint"
            }
            copy={
              visibleEndpoints.items.length === 0
                ? "Create an endpoint to receive signed event deliveries. The signing secret is shown once, at creation."
                : "Endpoint configuration, delivery history, and replay appear here."
            }
          />
        </Surface>
      ) : null}

      <ConfirmDialog
        state={confirm}
        busy={busyAction}
        onClose={() => {
          if (busyAction === null) setConfirm(null);
        }}
        onConfirm={() => void runConfirmedAction()}
      />
    </section>
  );
}

function EndpointTable({
  endpoints,
  status,
  error,
  hasMore,
  selectedEndpointId,
  onSelect,
  onRetry,
  onLoadMore,
}: {
  endpoints: WebhookEndpoint[];
  status: LoadStatus;
  error: unknown;
  hasMore: boolean;
  selectedEndpointId: string | null;
  onSelect: (endpointId: string) => void;
  onRetry: () => void;
  onLoadMore: () => void;
}) {
  if (status === "loading" || status === "idle") {
    return (
      <Surface ariaLabel="Loading webhook endpoints">
        <LoadingRows label="Loading webhook endpoints…" rows={3} />
      </Surface>
    );
  }
  if (status === "error" && endpoints.length === 0) {
    return (
      <Surface ariaLabel="Webhook endpoints unavailable">
        <div className="p-5">
          {isPermissionFailure(error) ? (
            <PermissionState resource="webhook endpoints" />
          ) : (
            <ErrorNotice
              error={error}
              title="Webhook endpoints are unavailable"
              onRetry={onRetry}
            />
          )}
        </div>
      </Surface>
    );
  }
  if (endpoints.length === 0) {
    return (
      <Surface ariaLabel="No webhook endpoints">
        <EmptyState
          title="No webhook endpoints"
          copy="This organization has no webhook endpoint. Create one to receive signed event deliveries."
        />
      </Surface>
    );
  }

  return (
    <Surface ariaLabel="Webhook endpoints">
      <SurfaceHeader
        title="Endpoints"
        description="An auto-disabled endpoint is marked separately from one an operator disabled, so the reason for the outage is never ambiguous."
      />
      {error ? (
        <div className="border-b border-[var(--danger)]/20 bg-[var(--danger)]/5 px-5 py-3">
          <ErrorNotice error={error} title="Refreshing endpoints failed" onRetry={onRetry} />
        </div>
      ) : null}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[860px] text-left text-sm">
          <caption className="sr-only">Webhook endpoints in this organization</caption>
          <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
            <tr>
              <th scope="col" className="px-5 py-3 font-medium">
                Endpoint
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                State
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Subscriptions
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Secret
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Updated
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Action
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border)]">
            {endpoints.map((endpoint) => {
              const activation = endpointActivation(endpoint);
              const selected = endpoint.endpoint_id === selectedEndpointId;
              return (
                <tr key={endpoint.endpoint_id}>
                  <td className="px-5 py-4">
                    <p className="font-medium text-[var(--civic-navy)]">{endpoint.name}</p>
                    <p className="mt-1 max-w-[22rem] truncate font-mono text-xs text-[var(--muted)]">
                      {endpoint.url}
                    </p>
                    <p className="mt-1 font-mono text-xs text-[var(--muted)]">
                      v{endpoint.version} · {endpoint.endpoint_id}
                    </p>
                  </td>
                  <td className="px-5 py-4">
                    <Pill tone={endpointActivationTone(activation)}>
                      {endpointActivationLabel(activation)}
                    </Pill>
                    {activation.kind === "auto_disabled" ? (
                      <p className="mt-1 max-w-[16rem] text-xs leading-5 text-[var(--muted-strong)]">
                        {activation.consecutive} consecutive terminal failures, threshold{" "}
                        {activation.threshold}.
                      </p>
                    ) : null}
                  </td>
                  <td className="px-5 py-4 text-xs tabular-nums text-[var(--muted-strong)]">
                    {endpoint.subscribed_event_types.length}
                    <span className="block text-[var(--muted)]">exact event names</span>
                  </td>
                  <td className="px-5 py-4 text-xs text-[var(--muted-strong)]">
                    {endpoint.secret_version_id ?? "Not issued"}
                    <span className="block text-[var(--muted)]">plaintext never stored</span>
                  </td>
                  <td className="px-5 py-4 text-xs tabular-nums text-[var(--muted)]">
                    {formatDateTime(endpoint.updated_at)}
                  </td>
                  <td className="px-5 py-4">
                    <button
                      type="button"
                      className={selected ? selectedButtonClass : ghostButtonClass}
                      onClick={() => onSelect(endpoint.endpoint_id)}
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
        loaded={endpoints.length}
        hasMore={hasMore}
        loading={status === "refreshing"}
        onLoadMore={onLoadMore}
        noun="endpoint"
      />
    </Surface>
  );
}

function EndpointDetail({
  sectionRef,
  endpoint,
  busyAction,
  onEdit,
  onTest,
  onRotate,
  onDisable,
  onEnable,
}: {
  sectionRef: React.RefObject<HTMLDivElement | null>;
  endpoint: WebhookEndpoint;
  busyAction: string | null;
  onEdit: () => void;
  onTest: () => void;
  onRotate: () => void;
  onDisable: () => void;
  onEnable: () => void;
}) {
  const activation = endpointActivation(endpoint);
  const { p06, external } = partitionSubscription(endpoint.subscribed_event_types);
  const busy = busyAction !== null;

  return (
    <Surface ariaLabel="Selected webhook endpoint">
      <div ref={sectionRef} tabIndex={-1} className="outline-none">
        <SurfaceHeader
          title={endpoint.name}
          description={endpointActivationDetail(endpoint)}
          action={
            <div className="flex flex-wrap gap-2">
              <button type="button" className={ghostButtonClass} onClick={onEdit} disabled={busy}>
                Edit
              </button>
              <button type="button" className={ghostButtonClass} onClick={onTest} disabled={busy}>
                {busyAction === "test" ? "Queueing…" : "Send test"}
              </button>
              <button type="button" className={ghostButtonClass} onClick={onRotate} disabled={busy}>
                {busyAction === "rotate" ? "Rotating…" : "Rotate secret"}
              </button>
              {endpoint.enabled ? (
                <button
                  type="button"
                  className={dangerButtonClass}
                  onClick={onDisable}
                  disabled={busy}
                >
                  {busyAction === "disable" ? "Disabling…" : "Disable"}
                </button>
              ) : (
                <button
                  type="button"
                  className={primaryButtonClass}
                  onClick={onEnable}
                  disabled={busy}
                >
                  {busyAction === "enable" ? "Enabling…" : "Enable"}
                </button>
              )}
            </div>
          }
        />

        {activation.kind === "auto_disabled" ? (
          <div className="border-b border-[var(--danger)]/25 bg-[var(--danger)]/5 px-5 py-4">
            <p className="text-xs font-semibold tracking-[0.08em] text-[var(--danger)]">
              AUTO-DISABLED
            </p>
            <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--civic-navy)]">
              Automatic disable stopped delivery after {activation.consecutive} consecutive terminal
              failures. The threshold is {activation.threshold} and cannot be set below 10. Fix the
              destination, then enable the endpoint; the previous deliveries stay dead-lettered
              until each one is replayed.
            </p>
          </div>
        ) : activation.kind === "operator_disabled" ? (
          <div className="border-b border-[var(--border)] bg-[var(--panel-hover)] px-5 py-4">
            <p className="text-xs font-semibold tracking-[0.08em] text-[var(--muted-strong)]">
              DISABLED BY AN OPERATOR
            </p>
            <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--muted-strong)]">
              This is a manual disable, not the automatic threshold. No consecutive-failure
              threshold was reached.
            </p>
          </div>
        ) : null}

        <dl className="grid gap-x-6 gap-y-5 p-5 sm:grid-cols-2 lg:grid-cols-3">
          <Metadata label="Endpoint ID" value={endpoint.endpoint_id} mono />
          <Metadata label="Version" value={`v${endpoint.version}`} />
          <Metadata label="Destination" value={endpoint.url} mono />
          <Metadata label="Description" value={endpoint.description ?? "Not set"} />
          <Metadata
            label="Secret version ID"
            value={endpoint.secret_version_id ?? "Not issued"}
            mono
          />
          <Metadata label="Created" value={formatDateTime(endpoint.created_at)} />
          <Metadata label="Updated" value={formatDateTime(endpoint.updated_at)} />
          <Metadata label="Max attempts" value={String(endpoint.max_attempts)} />
          <Metadata label="Base delay" value={`${endpoint.base_delay_seconds}s`} />
          <Metadata label="Max delay" value={`${endpoint.max_delay_seconds}s`} />
          <Metadata label="Replay window" value={`${endpoint.replay_window_seconds}s`} />
          <Metadata
            label="Auto-disable"
            value={
              endpoint.auto_disable_enabled
                ? `On at ${endpoint.auto_disable_threshold} consecutive failures`
                : "Off"
            }
          />
          <Metadata
            label="Consecutive terminal failures"
            value={String(endpoint.consecutive_terminal_failures)}
          />
        </dl>

        <div className="border-t border-[var(--border)] px-5 py-4">
          <p className="text-sm font-semibold text-[var(--civic-navy)]">
            Subscribed event names ({p06.length} P06)
            {external.length > 0 ? ` + ${external.length} preserved` : ""}
          </p>
          <p className="mt-1 text-xs leading-5 text-[var(--muted-strong)]">
            Subscriptions are exact names. Editing the endpoint never widens a subscription, and the
            server re-evaluates the tenant scope on every fan-out.
          </p>
          <ul className="mt-2 flex flex-wrap gap-2">
            {endpoint.subscribed_event_types.map((eventType) => (
              <li key={eventType}>
                <span className="inline-block break-all rounded-md bg-[var(--panel-strong)] px-2 py-1 font-mono text-xs text-[var(--muted-strong)]">
                  {eventType}
                </span>
              </li>
            ))}
          </ul>
        </div>

        <div className="border-t border-[var(--border)] bg-[var(--panel-hover)] px-5 py-3 text-xs leading-5 text-[var(--muted-strong)]">
          The API is authoritative for permission, current membership, organization state, and the
          signed body. This view never displays a signing secret, a request body, or a raw server
          error string.
        </div>
      </div>
    </Surface>
  );
}

function ConfirmDialog({
  state,
  busy,
  onClose,
  onConfirm,
}: {
  state: ConfirmState | null;
  busy: string | null;
  onClose: () => void;
  onConfirm: () => void;
}) {
  const dialogRef = useRef<HTMLDialogElement | null>(null);
  const titleId = useId();
  const descriptionId = useId();

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (state && !dialog.open) dialog.showModal();
    if (!state && dialog.open) dialog.close();
  }, [state]);

  const copy = confirmCopy(state);

  return (
    <dialog
      ref={dialogRef}
      aria-labelledby={state ? titleId : undefined}
      aria-describedby={state ? descriptionId : undefined}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      className="m-auto w-[calc(100%-2rem)] max-w-lg rounded-xl border border-[var(--border)] bg-[var(--panel)] p-0 text-[var(--foreground)] shadow-[var(--shadow)] backdrop:bg-[var(--civic-navy)]/35"
    >
      {state ? (
        <div className="p-6">
          <p className="text-xs font-semibold tracking-[0.1em] text-[var(--lumi-blue)]">
            {copy.eyebrow}
          </p>
          <h2 id={titleId} className="mt-2 text-lg font-semibold text-[var(--civic-navy)]">
            {copy.title}
          </h2>
          <div
            id={descriptionId}
            className="mt-3 space-y-3 text-sm leading-6 text-[var(--muted-strong)]"
          >
            {copy.body.map((paragraph) => (
              <p key={paragraph.slice(0, 32)}>{paragraph}</p>
            ))}
          </div>
          <div className="mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <button
              type="button"
              className={secondaryButtonClass}
              onClick={onClose}
              disabled={busy !== null}
              autoFocus
            >
              {copy.cancelLabel}
            </button>
            <button
              type="button"
              className={copy.destructive ? dangerButtonClass : primaryButtonClass}
              onClick={onConfirm}
              disabled={busy !== null}
            >
              {busy !== null ? copy.busyLabel : copy.confirmLabel}
            </button>
          </div>
        </div>
      ) : null}
    </dialog>
  );
}

interface ConfirmCopy {
  readonly eyebrow: string;
  readonly title: string;
  readonly body: readonly string[];
  readonly cancelLabel: string;
  readonly confirmLabel: string;
  readonly busyLabel: string;
  readonly destructive: boolean;
}

function confirmCopy(state: ConfirmState | null): ConfirmCopy {
  if (!state) {
    return {
      eyebrow: "",
      title: "",
      body: [],
      cancelLabel: "Close",
      confirmLabel: "Continue",
      busyLabel: "Working…",
      destructive: false,
    };
  }
  if (state.kind === "disable") {
    return {
      eyebrow: "DISABLE ENDPOINT",
      title: `Disable ${state.endpoint.name}?`,
      body: [
        "Pending deliveries for this endpoint are cancelled. Delivered and dead-letter history is kept, and nothing is erased.",
        "The signing secret is not changed. Re-enabling the endpoint resumes delivery with the same secret version.",
      ],
      cancelLabel: "Keep endpoint enabled",
      confirmLabel: "Disable endpoint",
      busyLabel: "Disabling…",
      destructive: true,
    };
  }
  if (state.kind === "rotate") {
    return {
      eyebrow: "ROTATE SECRET",
      title: "Rotate the signing secret?",
      body: [
        "A new secret version is generated and shown once. The previous version stops verifying new deliveries immediately.",
        "In-flight retries keep the secret version captured when their logical delivery was created. A replay after rotation uses the new version.",
      ],
      cancelLabel: "Keep current secret",
      confirmLabel: "Rotate and show new secret",
      busyLabel: "Rotating…",
      destructive: true,
    };
  }
  const delivery = state.delivery;
  return {
    eyebrow: "REPLAY DEAD LETTER",
    title: "Create a successor delivery?",
    body: [
      `Replay of ${delivery?.delivery_id ?? "this delivery"} creates a new logical delivery that reuses the same event ID and body.`,
      "The original delivery stays dead-lettered. Nothing is reset, and the original history remains readable.",
    ],
    cancelLabel: "Keep dead-lettered",
    confirmLabel: "Create successor delivery",
    busyLabel: "Replaying…",
    destructive: false,
  };
}

function emptyEndpoints(orgId: string): EndpointCollection {
  return {
    orgId,
    status: "idle",
    items: [],
    nextCursor: null,
    hasMore: false,
    error: null,
  };
}

function emptyDeliveries(orgId: string): DeliveryCollection {
  return {
    orgId,
    endpointId: null,
    status: "idle",
    items: [],
    nextCursor: null,
    hasMore: false,
    error: null,
  };
}

const selectedButtonClass =
  "inline-flex min-h-9 items-center justify-center gap-2 rounded-lg border border-[var(--lumi-blue)] bg-[var(--lumi-blue-soft)] px-3 py-1.5 text-xs font-semibold text-[var(--lumi-blue)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2";
