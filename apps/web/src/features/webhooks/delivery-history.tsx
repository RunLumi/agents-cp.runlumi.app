/**
 * Delivery history and diagnostics for one endpoint.
 *
 * Everything here is bounded metadata. The signed body stays on the server: the
 * history route returns identifiers, state, counts, a body hash, and a stable
 * reason code — never prompt, response, credential, or raw tool-argument
 * content. The retry/dead-letter distinction is stated explicitly, and a replay
 * is offered only where the contract allows it.
 */

import { useEffect, useId, useRef } from "react";

import {
  WEBHOOK_DELIVERY_STATES,
  type WebhookDelivery,
  type WebhookDeliveryState,
  type WebhookEndpoint,
} from "./api";
import {
  canReplayDelivery,
  classifyDeliveryReason,
  deliveryLineage,
  deliveryStateInfo,
  describeLineage,
  endpointActivation,
  endpointActivationDetail,
  endpointActivationLabel,
  endpointActivationTone,
  formatAttemptCount,
  formatDateTime,
  formatHttpStatus,
  formatLatency,
  humanizeToken,
  isDeliveryState,
  isPermissionFailure,
  replayBlockedReason,
} from "./helpers";
import {
  EmptyState,
  ErrorNotice,
  ghostButtonClass,
  LoadingRows,
  Metadata,
  Notice,
  PaginationFooter,
  PermissionState,
  Pill,
  Surface,
  SurfaceHeader,
} from "./ui";

export interface DeliveryHistoryProps {
  endpoint: WebhookEndpoint;
  deliveries: readonly WebhookDelivery[];
  selectedDeliveryId: string | null;
  status: "loading" | "refreshing" | "ready" | "error";
  error: unknown;
  hasMore: boolean;
  stateFilter: WebhookDeliveryState | "";
  onStateFilterChange: (next: WebhookDeliveryState | "") => void;
  onRetry: () => void;
  onLoadMore: () => void;
  onSelectDelivery: (deliveryId: string) => void;
  onReplay: (delivery: WebhookDelivery) => void;
  replayingDeliveryId: string | null;
  replayError: unknown;
}

export function DeliveryHistory({
  endpoint,
  deliveries,
  selectedDeliveryId,
  status,
  error,
  hasMore,
  stateFilter,
  onStateFilterChange,
  onRetry,
  onLoadMore,
  onSelectDelivery,
  onReplay,
  replayingDeliveryId,
  replayError,
}: DeliveryHistoryProps) {
  const lineage = deliveryLineage(deliveries);
  const selected =
    deliveries.find((delivery) => delivery.delivery_id === selectedDeliveryId) ?? deliveries[0];
  const selectedLineage = selected ? lineage.get(selected.delivery_id) : undefined;

  return (
    <div className="space-y-5">
      <Surface ariaLabel={`Delivery history for ${endpoint.name}`}>
        <SurfaceHeader
          title="Delivery history"
          description="One row is one logical delivery. A retry appends a new attempt to the same row and reuses the same event ID; a replay creates a separate successor delivery and never changes the original."
          action={
            <label className="block min-w-[12rem] text-xs font-semibold text-[var(--muted-strong)]">
              Delivery state
              <select
                value={stateFilter}
                onChange={(event) => {
                  const value = event.target.value;
                  onStateFilterChange(isDeliveryState(value) ? value : "");
                }}
                className="mt-1.5 min-h-10 w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 text-sm font-normal outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]"
              >
                <option value="">All states</option>
                {WEBHOOK_DELIVERY_STATES.map((state) => (
                  <option key={state} value={state}>
                    {deliveryStateInfo(state).label}
                  </option>
                ))}
              </select>
            </label>
          }
        />
        {status === "loading" ? <LoadingRows label="Loading delivery history…" rows={4} /> : null}
        {status === "error" && deliveries.length === 0 ? (
          isPermissionFailure(error) ? (
            <div className="p-5">
              <PermissionState resource="webhook delivery history" />
            </div>
          ) : (
            <div className="p-5">
              <ErrorNotice
                error={error}
                title="Delivery history is unavailable"
                onRetry={onRetry}
              />
            </div>
          )
        ) : null}
        {status !== "loading" && deliveries.length === 0 && status !== "error" ? (
          <EmptyState
            title={stateFilter ? "No deliveries in this state" : "No deliveries yet"}
            copy={
              stateFilter
                ? "Clear the state filter to see every delivery for this endpoint."
                : "A delivery appears here after an event matches this endpoint's subscriptions. Send a test delivery to check the destination now."
            }
          />
        ) : null}
        {deliveries.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[980px] text-left text-sm">
              <caption className="sr-only">Webhook deliveries for {endpoint.name}</caption>
              <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
                <tr>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Event
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    State
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Attempts
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    HTTP
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Latency
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Reason code
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Lineage
                  </th>
                  <th scope="col" className="px-5 py-3 font-medium">
                    Action
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {deliveries.map((delivery) => {
                  const info = deliveryStateInfo(delivery.state);
                  const link = lineage.get(delivery.delivery_id);
                  return (
                    <tr key={delivery.delivery_id}>
                      <td className="px-5 py-4">
                        <p className="max-w-[18rem] truncate font-mono text-xs text-[var(--civic-navy)]">
                          {delivery.event_type}
                        </p>
                        <p className="mt-1 max-w-[18rem] truncate font-mono text-xs text-[var(--muted)]">
                          {delivery.event_id}
                        </p>
                      </td>
                      <td className="px-5 py-4">
                        <Pill tone={info.tone}>{info.label}</Pill>
                        <p className="mt-1 text-xs tabular-nums text-[var(--muted)]">
                          {formatDateTime(delivery.created_at)}
                        </p>
                      </td>
                      <td className="px-5 py-4 text-xs tabular-nums text-[var(--muted-strong)]">
                        {formatAttemptCount(delivery, endpoint.max_attempts)}
                        {info.waitingForRetry && delivery.next_attempt_at ? (
                          <span className="mt-1 block text-[var(--muted)]">
                            next {formatDateTime(delivery.next_attempt_at)}
                          </span>
                        ) : null}
                      </td>
                      <td className="px-5 py-4 text-xs tabular-nums text-[var(--muted-strong)]">
                        {formatHttpStatus(delivery.last_http_status)}
                      </td>
                      <td className="px-5 py-4 text-xs tabular-nums text-[var(--muted-strong)]">
                        {formatLatency(delivery.last_latency_ms)}
                      </td>
                      <td className="px-5 py-4">
                        {delivery.last_error_code ? (
                          <>
                            <span className="font-mono text-xs text-[var(--civic-navy)]">
                              {delivery.last_error_code}
                            </span>
                            <span className="mt-1 block text-xs text-[var(--muted)]">
                              {classifyDeliveryReason(delivery.last_error_code) === "terminal"
                                ? "Terminal — the next step is a replay."
                                : classifyDeliveryReason(delivery.last_error_code) === "retryable"
                                  ? "Retryable."
                                  : "Bounded, stable reason code."}
                            </span>
                          </>
                        ) : (
                          <span className="text-xs text-[var(--muted)]">—</span>
                        )}
                      </td>
                      <td className="px-5 py-4 text-xs text-[var(--muted-strong)]">
                        {delivery.replay_of_delivery_id ? (
                          <button
                            type="button"
                            className="min-h-9 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-2 py-1 text-left font-mono text-xs text-[var(--lumi-blue)] outline-none hover:bg-[var(--panel-hover)] focus-visible:ring-2 focus-visible:ring-[var(--ring)]"
                            onClick={() => onSelectDelivery(delivery.replay_of_delivery_id ?? "")}
                          >
                            Replay of {delivery.replay_of_delivery_id?.slice(0, 12)}…
                          </button>
                        ) : (
                          <span className="block">Generation {link?.generation ?? 0}</span>
                        )}
                        {link && link.childIds.length > 0 ? (
                          <span className="mt-1 block text-[var(--muted)]">
                            {link.childIds.length} replay successor
                            {link.childIds.length === 1 ? "" : "s"}
                          </span>
                        ) : null}
                      </td>
                      <td className="px-5 py-4">
                        <div className="flex flex-wrap gap-2">
                          <button
                            type="button"
                            className={
                              delivery.delivery_id === selected?.delivery_id
                                ? "inline-flex min-h-9 items-center justify-center gap-2 rounded-lg border border-[var(--lumi-blue)] bg-[var(--lumi-blue-soft)] px-3 py-1.5 text-xs font-semibold text-[var(--lumi-blue)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
                                : ghostButtonClass
                            }
                            onClick={() => onSelectDelivery(delivery.delivery_id)}
                            aria-pressed={delivery.delivery_id === selected?.delivery_id}
                          >
                            Details
                          </button>
                          <button
                            type="button"
                            className={ghostButtonClass}
                            onClick={() => onReplay(delivery)}
                            disabled={!canReplayDelivery(delivery) || replayingDeliveryId !== null}
                            title={replayBlockedReason(delivery) || "Create a successor delivery"}
                          >
                            {replayingDeliveryId === delivery.delivery_id ? "Replaying…" : "Replay"}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : null}
        {error && deliveries.length > 0 ? (
          <div className="border-t border-[var(--danger)]/20 bg-[var(--danger)]/5 px-5 py-3">
            <ErrorNotice error={error} title="Refreshing deliveries failed" onRetry={onRetry} />
          </div>
        ) : null}
        {deliveries.length > 0 ? (
          <PaginationFooter
            loaded={deliveries.length}
            hasMore={hasMore}
            loading={status === "refreshing"}
            onLoadMore={onLoadMore}
            noun="delivery"
          />
        ) : null}
      </Surface>

      {replayError ? <ErrorNotice error={replayError} title="The replay was not created" /> : null}

      {selected ? (
        <DeliveryDetail
          delivery={selected}
          endpoint={endpoint}
          lineageDescription={
            selectedLineage ? describeLineage(selected, lineage) : "Original delivery."
          }
        />
      ) : null}
    </div>
  );
}

function DeliveryDetail({
  delivery,
  endpoint,
  lineageDescription,
}: {
  delivery: WebhookDelivery;
  endpoint: WebhookEndpoint;
  lineageDescription: string;
}) {
  const panelId = useId();
  const sectionRef = useRef<HTMLDivElement | null>(null);
  const info = deliveryStateInfo(delivery.state);
  const activation = endpointActivation(endpoint);
  const payloadEntries = delivery.payload ? Object.entries(delivery.payload) : [];

  useEffect(() => {
    sectionRef.current?.focus();
  }, [delivery.delivery_id]);

  return (
    <Surface ariaLabel="Selected delivery details">
      <SurfaceHeader
        title="Delivery detail"
        description="Bounded delivery metadata. The signed request body is not returned by this route and is never displayed."
      />
      <div
        id={panelId}
        ref={sectionRef}
        tabIndex={-1}
        className="space-y-4 p-5 outline-none"
        aria-live="polite"
      >
        <div className="flex flex-wrap items-center gap-2">
          <Pill tone={info.tone}>{info.label}</Pill>
          <Pill tone={endpointActivationTone(activation)}>
            {endpointActivationLabel(activation)}
          </Pill>
          <span className="font-mono text-xs text-[var(--muted)]">{delivery.delivery_id}</span>
        </div>
        <p className="max-w-3xl text-sm leading-6 text-[var(--muted-strong)]">{info.detail}</p>

        {delivery.state === "dead_letter" ? (
          <Notice tone="danger">
            This delivery is not retried again. Replay creates a new successor delivery that reuses
            this event ID and body; this row keeps its dead-letter state and history.
          </Notice>
        ) : null}
        {delivery.state === "retry_wait" ? (
          <Notice tone="warning">
            A retry is already scheduled. The same logical delivery and event ID are reused, and a
            new attempt is appended.
          </Notice>
        ) : null}

        <dl className="grid gap-x-6 gap-y-5 sm:grid-cols-2 lg:grid-cols-3">
          <Metadata label="Event type" value={delivery.event_type} mono />
          <Metadata label="Event ID" value={delivery.event_id} mono />
          <Metadata label="Body hash" value={delivery.body_hash} mono />
          <Metadata label="Signature key ID" value={delivery.signature_key_id} mono />
          <Metadata
            label="Attempts"
            value={`${formatAttemptCount(delivery, endpoint.max_attempts)} · state ${humanizeToken(delivery.state)}`}
          />
          <Metadata label="HTTP status" value={formatHttpStatus(delivery.last_http_status)} />
          <Metadata label="Latency" value={formatLatency(delivery.last_latency_ms)} />
          <Metadata
            label="Last reason code"
            value={delivery.last_error_code ?? "None recorded"}
            mono
          />
          <Metadata label="Next attempt" value={formatDateTime(delivery.next_attempt_at)} />
          <Metadata label="Delivered at" value={formatDateTime(delivery.delivered_at)} />
          <Metadata label="Replay generation" value={String(delivery.replay_generation)} />
          <Metadata
            label="Replays this delivery"
            value={delivery.replay_of_delivery_id ?? "None"}
            mono
          />
          <Metadata label="Created" value={formatDateTime(delivery.created_at)} />
          <Metadata label="Updated" value={formatDateTime(delivery.updated_at)} />
          <Metadata label="Endpoint" value={`${endpoint.name} · v${endpoint.version}`} />
        </dl>

        <p className="text-xs leading-5 text-[var(--muted-strong)]">{lineageDescription}</p>
        <p className="text-xs leading-5 text-[var(--muted-strong)]">
          {endpointActivationDetail(endpoint)}
        </p>

        {payloadEntries.length > 0 ? (
          <details className="rounded-lg border border-[var(--warning)]/45 bg-[var(--warning)]/5">
            <summary className="min-h-11 cursor-pointer px-4 py-3 text-sm font-semibold text-[var(--civic-navy)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]">
              Delivery payload metadata — may contain customer identifiers
            </summary>
            <div className="border-t border-[var(--warning)]/30 px-4 py-3">
              <p className="text-xs leading-5 text-[var(--muted-strong)]">
                Bounded metadata reported for this delivery. It stays collapsed by default. Prompt,
                response, credential, and raw tool-argument content is never included in a webhook
                payload.
              </p>
              <dl className="mt-3 grid gap-x-6 gap-y-3 sm:grid-cols-2">
                {payloadEntries.map(([key, value]) => (
                  <div key={key} className="min-w-0">
                    <dt className="font-mono text-xs text-[var(--muted)]">{key}</dt>
                    <dd className="mt-1 break-all font-mono text-xs text-[var(--civic-navy)]">
                      {renderBoundedValue(value)}
                    </dd>
                  </div>
                ))}
              </dl>
            </div>
          </details>
        ) : null}

        {!canReplayDelivery(delivery) ? (
          <p className="text-xs leading-5 text-[var(--muted)]">{replayBlockedReason(delivery)}</p>
        ) : null}
      </div>
    </Surface>
  );
}

function renderBoundedValue(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return "Nested value omitted";
}
