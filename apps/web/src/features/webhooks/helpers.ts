/**
 * Webhook delivery, activation, and URL semantics.
 *
 * Every rule here mirrors the frozen P06 contract so the control plane can
 * explain a state before an operator acts. The API remains authoritative: a UI
 * affordance never widens what the server will accept.
 */

import { ApiClientError } from "@/lib/errors";

import type { WebhookDelivery, WebhookDeliveryState, WebhookEndpoint } from "./api";

// ---------------------------------------------------------------------------
// Delivery policy bounds (frozen)
// ---------------------------------------------------------------------------

export const MAX_ATTEMPTS_MIN = 1;
export const MAX_ATTEMPTS_MAX = 8;
export const BASE_DELAY_MIN_SECONDS = 1;
export const BASE_DELAY_MAX_SECONDS = 3600;
export const MAX_DELAY_MIN_SECONDS = 1;
export const MAX_DELAY_MAX_SECONDS = 86400;
export const REPLAY_WINDOW_MIN_SECONDS = 30;
export const REPLAY_WINDOW_MAX_SECONDS = 3600;
/**
 * Optional auto-disable is off by default and, when enabled, requires a
 * threshold of at least 10 consecutive terminal failures.
 */
export const AUTO_DISABLE_MIN_THRESHOLD = 10;
export const AUTO_DISABLE_MAX_THRESHOLD = 100;
export const ENDPOINT_URL_MAX_LENGTH = 2048;
export const ALLOWED_ENDPOINT_PORTS = [443, 8443] as const;

export const DEFAULT_ENDPOINT_POLICY = {
  max_attempts: 8,
  base_delay_seconds: 30,
  max_delay_seconds: 86400,
  replay_window_seconds: 300,
  auto_disable_enabled: false,
  auto_disable_threshold: 10,
} as const;

// ---------------------------------------------------------------------------
// Delivery state semantics
// ---------------------------------------------------------------------------

export type Tone = "neutral" | "info" | "success" | "warning" | "danger";

export interface DeliveryStateInfo {
  readonly state: WebhookDeliveryState;
  readonly label: string;
  readonly tone: Tone;
  /** What this state means for the event, in one sentence. */
  readonly detail: string;
  readonly terminal: boolean;
  /** True while the worker still owns a scheduled attempt. */
  readonly waitingForRetry: boolean;
}

const DELIVERY_STATE_INFO: Readonly<Record<WebhookDeliveryState, DeliveryStateInfo>> = {
  pending: {
    state: "pending",
    label: "Recorded",
    tone: "neutral",
    detail:
      "The delivery row is durable and has not been queued yet. The business event already succeeded.",
    terminal: false,
    waitingForRetry: false,
  },
  queued: {
    state: "queued",
    label: "Queued",
    tone: "info",
    detail: "A delivery job is queued. Ordering between events is not guaranteed.",
    terminal: false,
    waitingForRetry: false,
  },
  delivering: {
    state: "delivering",
    label: "Delivering",
    tone: "info",
    detail:
      "An attempt is in flight. A timeout can produce a duplicate request, so dedupe on the event ID.",
    terminal: false,
    waitingForRetry: false,
  },
  delivered: {
    state: "delivered",
    label: "Delivered",
    tone: "success",
    detail: "The destination returned a 2xx response. Only 2xx counts as success.",
    terminal: true,
    waitingForRetry: false,
  },
  retry_wait: {
    state: "retry_wait",
    label: "Retry scheduled",
    tone: "warning",
    detail:
      "This attempt failed and another one is scheduled with bounded backoff and deterministic jitter.",
    terminal: false,
    waitingForRetry: true,
  },
  dead_letter: {
    state: "dead_letter",
    label: "Dead letter",
    tone: "danger",
    detail:
      "The attempt budget is exhausted. This delivery is NOT retried again unless an authorized replay creates a new successor delivery.",
    terminal: true,
    waitingForRetry: false,
  },
  cancelled: {
    state: "cancelled",
    label: "Cancelled",
    tone: "neutral",
    detail: "Cancelled when the endpoint was disabled. Delivered and dead-letter history is kept.",
    terminal: true,
    waitingForRetry: false,
  },
};

export function deliveryStateInfo(state: WebhookDeliveryState): DeliveryStateInfo {
  return DELIVERY_STATE_INFO[state];
}

export function isTerminalDeliveryState(state: WebhookDeliveryState): boolean {
  return DELIVERY_STATE_INFO[state].terminal;
}

export function isDeliveryState(value: string): value is WebhookDeliveryState {
  return Object.hasOwn(DELIVERY_STATE_INFO, value);
}

/**
 * FR-F17-006: after the retry window the delivery is marked dead, the failure
 * is exposed, and a replay is offered. A replay creates a successor; it never
 * resets the original.
 */
export function canReplayDelivery(delivery: WebhookDelivery): boolean {
  return delivery.state === "dead_letter";
}

export function replayBlockedReason(delivery: WebhookDelivery): string {
  if (canReplayDelivery(delivery)) return "";
  if (delivery.state === "retry_wait") {
    return "A retry is already scheduled. Wait for the next attempt before replaying.";
  }
  if (
    delivery.state === "pending" ||
    delivery.state === "queued" ||
    delivery.state === "delivering"
  ) {
    return "This delivery is still in progress. Replay is only available once it dead-letters.";
  }
  if (delivery.state === "delivered") {
    return "This delivery already succeeded. It cannot be replayed.";
  }
  return "This delivery was cancelled when the endpoint was disabled. Enable the endpoint before replaying.";
}

// ---------------------------------------------------------------------------
// Delivery lineage
//
// A replay never edits the original. The successor is a new logical delivery
// linked by `replay_of_delivery_id`, carrying the same stable event ID.
// ---------------------------------------------------------------------------

export interface DeliveryLineage {
  readonly parentId: string | null;
  readonly childIds: readonly string[];
  readonly generation: number;
}

export function deliveryLineage(
  deliveries: readonly WebhookDelivery[],
): ReadonlyMap<string, DeliveryLineage> {
  const children = new Map<string, string[]>();
  for (const delivery of deliveries) {
    const parentId = delivery.replay_of_delivery_id;
    if (!parentId) continue;
    const existing = children.get(parentId);
    if (existing) existing.push(delivery.delivery_id);
    else children.set(parentId, [delivery.delivery_id]);
  }
  const lineage = new Map<string, DeliveryLineage>();
  for (const delivery of deliveries) {
    lineage.set(delivery.delivery_id, {
      parentId: delivery.replay_of_delivery_id,
      childIds: children.get(delivery.delivery_id) ?? [],
      generation: delivery.replay_generation,
    });
  }
  return lineage;
}

export function describeLineage(
  delivery: WebhookDelivery,
  lineage: ReadonlyMap<string, DeliveryLineage>,
): string {
  const link = lineage.get(delivery.delivery_id);
  if (!link) return "Original delivery. No replay has been created from it.";
  if (link.parentId) {
    return `Successor replay of ${link.parentId} (generation ${link.generation}). The original delivery keeps its own state.`;
  }
  if (link.childIds.length > 0) {
    return `Original delivery. ${link.childIds.length} replay successor${link.childIds.length === 1 ? "" : "s"} created.`;
  }
  return "Original delivery. No replay has been created from it.";
}

// ---------------------------------------------------------------------------
// Endpoint activation: operator-disabled vs auto-disabled
// ---------------------------------------------------------------------------

export type EndpointActivation =
  | { readonly kind: "active" }
  | { readonly kind: "failing"; readonly consecutive: number; readonly threshold: number }
  | { readonly kind: "auto_disabled"; readonly consecutive: number; readonly threshold: number }
  | { readonly kind: "operator_disabled" };

export function endpointActivation(endpoint: WebhookEndpoint): EndpointActivation {
  const threshold = endpoint.auto_disable_threshold;
  const consecutive = endpoint.consecutive_terminal_failures;
  if (!endpoint.enabled) {
    if (consecutive >= threshold) {
      return { kind: "auto_disabled", consecutive, threshold };
    }
    return { kind: "operator_disabled" };
  }
  if (consecutive > 0) {
    return { kind: "failing", consecutive, threshold };
  }
  return { kind: "active" };
}

export function endpointActivationLabel(activation: EndpointActivation): string {
  switch (activation.kind) {
    case "active":
      return "Enabled";
    case "failing":
      return `Degraded · ${activation.consecutive} consecutive failures`;
    case "auto_disabled":
      return "Auto-disabled";
    case "operator_disabled":
      return "Disabled by an operator";
  }
}

export function endpointActivationTone(activation: EndpointActivation): Tone {
  switch (activation.kind) {
    case "active":
      return "success";
    case "failing":
      return "warning";
    case "auto_disabled":
      return "danger";
    case "operator_disabled":
      return "neutral";
  }
}

export function endpointActivationDetail(endpoint: WebhookEndpoint): string {
  const activation = endpointActivation(endpoint);
  switch (activation.kind) {
    case "active":
      return "The endpoint accepts new deliveries.";
    case "failing":
      return `${activation.consecutive} of ${activation.threshold} consecutive terminal failures. Auto-disable ${
        endpoint.auto_disable_enabled ? "is on" : "is off"
      } and the endpoint stays enabled until the threshold is reached.`;
    case "auto_disabled":
      return `Auto-disable stopped delivery after ${activation.consecutive} consecutive terminal failures, at or above the ${activation.threshold}-failure threshold. Fix the destination, then enable the endpoint again.`;
    case "operator_disabled":
      return "An operator disabled this endpoint. Pending deliveries were cancelled; delivered and dead-letter history is kept.";
  }
}

// ---------------------------------------------------------------------------
// Endpoint URL
// ---------------------------------------------------------------------------

export type UrlRejectionCode =
  | "empty"
  | "too_long"
  | "unparsable"
  | "https_required"
  | "userinfo"
  | "port";

export interface UrlRejection {
  readonly code: UrlRejectionCode;
  readonly message: string;
}

/**
 * The client mirrors the subset of the frozen endpoint rules an operator can
 * fix without a round trip. DNS resolution, private/link-local/loopback ranges,
 * cloud metadata ranges, redirect following, and revalidation immediately
 * before each connection are server-side and cannot be checked here.
 */
export function validateEndpointUrl(value: string): UrlRejection | null {
  const trimmed = value.trim();
  if (trimmed.length === 0) return { code: "empty", message: "Enter an HTTPS endpoint URL." };
  if (trimmed.length > ENDPOINT_URL_MAX_LENGTH) {
    return {
      code: "too_long",
      message: `The URL may be at most ${ENDPOINT_URL_MAX_LENGTH} characters.`,
    };
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { code: "unparsable", message: "This is not a valid absolute URL." };
  }
  if (parsed.protocol !== "https:") {
    return { code: "https_required", message: "Webhook delivery uses HTTPS only." };
  }
  if (parsed.username || parsed.password) {
    return { code: "userinfo", message: "Remove the username and password from the URL." };
  }
  if (parsed.port !== "" && !ALLOWED_ENDPOINT_PORTS.some((port) => String(port) === parsed.port)) {
    return {
      code: "port",
      message: `Only ports ${ALLOWED_ENDPOINT_PORTS.join(" and ")} are accepted. Leave the port empty for the default.`,
    };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Failure classification
// ---------------------------------------------------------------------------

const RETRYABLE_DELIVERY_REASONS = new Set([
  "webhook_timeout",
  "webhook_response_too_large",
  "webhook_retry_after_invalid",
  "network_error",
  "connection_failed",
]);

const TERMINAL_DELIVERY_REASONS = new Set([
  "webhook_endpoint_invalid",
  "webhook_https_required",
  "webhook_url_blocked",
  "webhook_redirect_blocked",
  "webhook_signature_invalid",
]);

/**
 * A bounded, stable reason code only. The server never returns a raw provider
 * or platform string, and this view never renders one as prose.
 */
export function classifyDeliveryReason(
  reasonCode: string | null,
): "retryable" | "terminal" | "unknown" {
  if (!reasonCode) return "unknown";
  if (RETRYABLE_DELIVERY_REASONS.has(reasonCode)) return "retryable";
  if (TERMINAL_DELIVERY_REASONS.has(reasonCode)) return "terminal";
  return "unknown";
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

/**
 * A foreign organization, endpoint, or delivery returns the same
 * non-disclosing not-found shape as a missing one, so the UI must present both as
 * an access problem rather than confirming that the record exists elsewhere.
 */
export function isPermissionFailure(error: unknown): boolean {
  return (
    error instanceof ApiClientError &&
    (error.status === 403 ||
      error.code === "permission_denied" ||
      error.code === "resource_not_found" ||
      error.code === "not_found")
  );
}

export function isVersionConflict(error: unknown): boolean {
  return error instanceof ApiClientError && error.code === "version_conflict";
}

export function isEndpointInvalid(error: unknown): boolean {
  return (
    error instanceof ApiClientError &&
    [
      "webhook_endpoint_invalid",
      "webhook_https_required",
      "webhook_url_blocked",
      "webhook_redirect_blocked",
    ].includes(error.code)
  );
}

export function isAmbiguousMutationFailure(error: unknown): boolean {
  return (
    error instanceof ApiClientError &&
    (error.kind === "network" ||
      error.kind === "invalid_response" ||
      error.code === "idempotency_in_progress" ||
      error.status === 408 ||
      error.status === 429 ||
      (error.status !== undefined && error.status >= 500))
  );
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "Not recorded";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatLatency(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "Not reported";
  if (value < 1000) return `${Math.round(value)} ms`;
  return `${(value / 1000).toFixed(2)} s`;
}

export function formatHttpStatus(value: number | null | undefined): string {
  if (value === null || value === undefined) return "Not reported";
  return String(value);
}

export function formatAttemptCount(delivery: WebhookDelivery, maxAttempts: number): string {
  const budget = maxAttempts > 0 ? ` of ${maxAttempts}` : "";
  return `${delivery.attempt_count}${budget}`;
}

export function humanizeToken(value: string): string {
  return value.replaceAll("_", " ");
}
