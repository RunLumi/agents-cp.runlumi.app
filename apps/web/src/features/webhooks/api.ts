/**
 * P06 webhook endpoint and delivery client.
 *
 * Frozen contract: `docs/implementation/gates/P06-CG.md` → "API contract" and
 * "Event and webhook contract" (contract version `p06-cg-v1`).
 *
 * A plaintext webhook secret is returned exactly once, by create and by
 * rotate-secret. This module never stores, caches, or re-emits it: the value is
 * handed straight to the caller and dropped. `@/lib/api.ts` owns the shared
 * client; this module owns the P06 wire shapes and their strict decoders, and
 * exports the minimal P06 transport so the notifications client reuses the same
 * CSRF, idempotency, and error-envelope handling instead of copying it.
 */

import { apiErrorFromEnvelope, makeInvalidResponseError, makeTransportError } from "@/lib/errors";
import type { Page } from "@/lib/api";

// ---------------------------------------------------------------------------
// P06 transport
// ---------------------------------------------------------------------------

export interface P06RequestOptions {
  method?: string;
  body?: unknown;
  idempotencyKey?: string;
  signal?: AbortSignal;
}

export type P06ResponseDecoder<T> = (value: unknown) => T | undefined;

/**
 * Identical in behaviour to the shared client in `@/lib/api.ts`. It exists only
 * because that client does not export its `requestJson` helper and P06 owns new
 * routes; the coordinator can swap both P06 clients over to a shared export
 * with a one-line change when it is made available.
 */
export async function p06RequestJson<T>(
  path: string,
  options: P06RequestOptions,
  decode: P06ResponseDecoder<T>,
): Promise<T> {
  const method = (options.method ?? "GET").toUpperCase();
  const headers = new Headers();
  headers.set("Accept", "application/json");
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  if (options.idempotencyKey) headers.set("Idempotency-Key", options.idempotencyKey);
  const safeMethod = isSafeMethod(method);
  if (!safeMethod) {
    const csrf = readCookie("lumi_csrf");
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  const init: RequestInit = {
    method,
    headers,
    credentials: "include",
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
    ...(options.signal ? { signal: options.signal } : {}),
  };
  const retrySafe = safeMethod || options.idempotencyKey !== undefined;

  let response: Response;
  try {
    response = await fetch(path, init);
  } catch (cause) {
    throw makeTransportError(cause, options.signal, { retryable: retrySafe });
  }

  const requestId = readRequestId(response.headers.get("X-Request-ID"));
  let responseText: string;
  try {
    responseText = await response.text();
  } catch (cause) {
    throw makeTransportError(cause, options.signal, {
      requestId,
      status: response.status,
      retryable: response.status >= 500 || response.status === 429,
    });
  }

  let payload: unknown;
  let validJson = responseText.length > 0;
  if (validJson) {
    try {
      payload = JSON.parse(responseText) as unknown;
    } catch {
      validJson = false;
    }
  }
  if (!response.ok) {
    const apiCode = readApiErrorCode(payload);
    throw apiErrorFromEnvelope(
      response.status,
      validJson ? payload : undefined,
      requestId,
      isRetryableStatus(response.status, apiCode, retrySafe),
    );
  }
  if (response.status === 204) return undefined as T;
  const decoded = validJson ? decode(payload) : undefined;
  if (decoded === undefined) {
    throw makeInvalidResponseError({ requestId, status: response.status });
  }
  return decoded;
}

function isSafeMethod(method: string): boolean {
  return method === "GET" || method === "HEAD" || method === "OPTIONS";
}

function isRetryableStatus(status: number, code: string | undefined, retrySafe: boolean): boolean {
  if (!retrySafe) return false;
  return (
    status === 408 ||
    status === 425 ||
    status === 429 ||
    status >= 500 ||
    code === "idempotency_in_progress"
  );
}

function readCookie(name: string): string | undefined {
  if (typeof document === "undefined") return undefined;
  const value = document.cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`))
    ?.slice(name.length + 1);
  return value && value.length <= 256 ? value : undefined;
}

function readRequestId(value: string | null): string | undefined {
  if (value === null) return undefined;
  const normalized = value.trim();
  return normalized.length > 0 && normalized.length <= 160 ? normalized : undefined;
}

function readApiErrorCode(payload: unknown): string | undefined {
  if (!isObject(payload)) return undefined;
  const error = payload.error;
  return isObject(error) && typeof error.code === "string" ? error.code : undefined;
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

export interface WebhookEndpoint {
  endpoint_id: string;
  org_id: string;
  name: string;
  description: string | null;
  url: string;
  subscribed_event_types: string[];
  secret_version_id: string | null;
  enabled: boolean;
  max_attempts: number;
  base_delay_seconds: number;
  max_delay_seconds: number;
  replay_window_seconds: number;
  auto_disable_enabled: boolean;
  auto_disable_threshold: number;
  consecutive_terminal_failures: number;
  version: number;
  created_at: string;
  updated_at: string;
}

export const WEBHOOK_DELIVERY_STATES = [
  "pending",
  "queued",
  "delivering",
  "delivered",
  "retry_wait",
  "dead_letter",
  "cancelled",
] as const;

export type WebhookDeliveryState = (typeof WEBHOOK_DELIVERY_STATES)[number];

export interface WebhookDelivery {
  delivery_id: string;
  endpoint_id: string;
  event_id: string;
  event_type: string;
  body_hash: string;
  secret_version_id: string;
  signature_key_id: string;
  state: WebhookDeliveryState;
  attempt_count: number;
  next_attempt_at: string | null;
  delivered_at: string | null;
  last_error_code: string | null;
  replay_of_delivery_id: string | null;
  replay_generation: number;
  version: number;
  created_at: string;
  updated_at: string;
  /**
   * Last attempt HTTP status. The frozen delivery projection does not require
   * it, so it is optional: a missing value renders as "Not reported" rather
   * than an invented number.
   */
  last_http_status?: number | null;
  /** Last attempt round-trip latency in milliseconds, when reported. */
  last_latency_ms?: number | null;
  /**
   * Bounded delivery metadata only. The signed body itself stays on the server
   * and is never returned by the history route; a payload preview, if a future
   * contract revision adds one, is rendered collapsed and labelled as customer
   * data.
   */
  payload?: Record<string, unknown> | null;
}

/** Create response. `secret` is plaintext and is shown to the operator once. */
export interface WebhookEndpointCreated {
  endpoint: WebhookEndpoint;
  secret: string;
}

/** Rotate response. `secret` is plaintext and is shown to the operator once. */
export interface WebhookSecretRotated {
  endpoint_id: string;
  secret_version_id: string;
  secret: string;
}

/** Test-delivery response: `202`, a bounded `webhook.test.v1` delivery was queued. */
export interface WebhookTestQueued {
  delivery_id: string;
  endpoint_id: string;
  event_id: string;
  state: WebhookDeliveryState;
}

/** Replay response: `201`, a successor logical delivery was created. */
export interface WebhookDeliveryReplayed {
  delivery_id: string;
  replay_of_delivery_id: string;
  replay_generation: number;
  event_id: string;
  body_hash: string;
  secret_version_id: string;
  state: WebhookDeliveryState;
}

// ---------------------------------------------------------------------------
// Request shapes
// ---------------------------------------------------------------------------

export interface CreateWebhookEndpointInput {
  name: string;
  url: string;
  subscribed_event_types: string[];
  description?: string | null;
  enabled?: boolean;
  max_attempts?: number;
  base_delay_seconds?: number;
  max_delay_seconds?: number;
  replay_window_seconds?: number;
  auto_disable_enabled?: boolean;
  auto_disable_threshold?: number;
}

export interface UpdateWebhookEndpointInput extends CreateWebhookEndpointInput {
  version: number;
}

export interface ListWebhookEndpointsQuery {
  limit?: number;
  cursor?: string;
  include_disabled?: boolean;
}

export interface ListWebhookDeliveriesQuery {
  limit?: number;
  cursor?: string;
  state?: WebhookDeliveryState;
}

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

export async function listWebhookEndpoints(
  orgId: string,
  queryOrSignal?: ListWebhookEndpointsQuery | AbortSignal,
  signal?: AbortSignal,
): Promise<Page<WebhookEndpoint>> {
  const request = resolveQuery(queryOrSignal, signal);
  return p06RequestJson(
    withQuery(webhooksPath(orgId), request.query),
    request.signal ? { signal: request.signal } : {},
    decodeEndpointPage,
  );
}

export async function createWebhookEndpoint(
  orgId: string,
  input: CreateWebhookEndpointInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<WebhookEndpointCreated> {
  return p06RequestJson(
    webhooksPath(orgId),
    { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    decodeEndpointCreated,
  );
}

/**
 * PATCH requires the current `version`. A stale write is refused by the server
 * with `409 version_conflict`; the caller refreshes and retries.
 */
export async function updateWebhookEndpoint(
  orgId: string,
  endpointId: string,
  input: UpdateWebhookEndpointInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<WebhookEndpoint> {
  return p06RequestJson(
    `${webhooksPath(orgId)}/${encodeURIComponent(endpointId)}`,
    { method: "PATCH", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    decodeEndpoint,
  );
}

/**
 * Disable an endpoint. This cancels its pending deliveries but keeps delivered
 * and dead-letter history. Returns no body.
 */
export async function disableWebhookEndpoint(
  orgId: string,
  endpointId: string,
  input: { version: number },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<void> {
  await p06RequestJson(
    `${webhooksPath(orgId)}/${encodeURIComponent(endpointId)}`,
    { method: "DELETE", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    decodeNoContent,
  );
}

export async function rotateWebhookSecret(
  orgId: string,
  endpointId: string,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<WebhookSecretRotated> {
  return p06RequestJson(
    `${webhooksPath(orgId)}/${encodeURIComponent(endpointId)}/rotate-secret`,
    { method: "POST", body: {}, idempotencyKey, ...(signal ? { signal } : {}) },
    decodeSecretRotated,
  );
}

export async function sendWebhookTest(
  orgId: string,
  endpointId: string,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<WebhookTestQueued> {
  return p06RequestJson(
    `${webhooksPath(orgId)}/${encodeURIComponent(endpointId)}/test`,
    { method: "POST", body: {}, idempotencyKey, ...(signal ? { signal } : {}) },
    decodeTestQueued,
  );
}

export async function listWebhookDeliveries(
  orgId: string,
  endpointId: string,
  queryOrSignal?: ListWebhookDeliveriesQuery | AbortSignal,
  signal?: AbortSignal,
): Promise<Page<WebhookDelivery>> {
  const request = resolveQuery(queryOrSignal, signal);
  return p06RequestJson(
    withQuery(`${webhooksPath(orgId)}/${encodeURIComponent(endpointId)}/deliveries`, request.query),
    request.signal ? { signal: request.signal } : {},
    decodeDeliveryPage,
  );
}

/**
 * Replay a dead-lettered delivery. The server creates a SUCCESSOR logical
 * delivery linked by `replay_of_delivery_id`; the original keeps its
 * dead-letter state and its stable event ID.
 */
export async function replayWebhookDelivery(
  orgId: string,
  deliveryId: string,
  input: { version: number },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<WebhookDeliveryReplayed> {
  return p06RequestJson(
    `${webhooksPath(orgId)}/deliveries/${encodeURIComponent(deliveryId)}/replay`,
    { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    decodeDeliveryReplayed,
  );
}

// ---------------------------------------------------------------------------
// Strict decoders
//
// A response that does not match the frozen shape is rejected rather than
// partially trusted, so contract drift surfaces as a visible error state instead
// of a half-rendered control plane.
// ---------------------------------------------------------------------------

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isBoolean(value: unknown): value is boolean {
  return typeof value === "boolean";
}

function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isHttpStatus(value: unknown): value is number | null {
  return value === null || (typeof value === "number" && value >= 100 && value <= 599);
}

function isNonNegativeMilliseconds(value: unknown): value is number | null {
  return value === null || (typeof value === "number" && value >= 0);
}

function isDeliveryState(value: unknown): value is WebhookDeliveryState {
  return (WEBHOOK_DELIVERY_STATES as readonly unknown[]).includes(value);
}

function isPage<T>(value: unknown, isItem: (item: unknown) => boolean): value is Page<T> {
  return (
    isObject(value) &&
    Array.isArray(value.items) &&
    value.items.every(isItem) &&
    isNullableString(value.next_cursor) &&
    isBoolean(value.has_more)
  );
}

function isEndpoint(value: unknown): value is WebhookEndpoint {
  return (
    isObject(value) &&
    typeof value.endpoint_id === "string" &&
    typeof value.org_id === "string" &&
    typeof value.name === "string" &&
    isNullableString(value.description) &&
    typeof value.url === "string" &&
    isStringArray(value.subscribed_event_types) &&
    isNullableString(value.secret_version_id) &&
    isBoolean(value.enabled) &&
    isPositiveInteger(value.max_attempts) &&
    isPositiveInteger(value.base_delay_seconds) &&
    isPositiveInteger(value.max_delay_seconds) &&
    isPositiveInteger(value.replay_window_seconds) &&
    isBoolean(value.auto_disable_enabled) &&
    isPositiveInteger(value.auto_disable_threshold) &&
    isCount(value.consecutive_terminal_failures) &&
    isPositiveInteger(value.version) &&
    typeof value.created_at === "string" &&
    typeof value.updated_at === "string"
  );
}

function decodeEndpoint(value: unknown): WebhookEndpoint | undefined {
  return isEndpoint(value) ? value : undefined;
}

function decodeEndpointPage(value: unknown): Page<WebhookEndpoint> | undefined {
  return isPage<WebhookEndpoint>(value, isEndpoint) ? value : undefined;
}

function decodeEndpointCreated(value: unknown): WebhookEndpointCreated | undefined {
  if (!isObject(value) || typeof value.secret !== "string" || value.secret.length === 0) {
    return undefined;
  }
  const endpoint = decodeEndpoint(value.endpoint);
  return endpoint ? { endpoint, secret: value.secret } : undefined;
}

function decodeSecretRotated(value: unknown): WebhookSecretRotated | undefined {
  if (
    !isObject(value) ||
    typeof value.endpoint_id !== "string" ||
    typeof value.secret_version_id !== "string" ||
    typeof value.secret !== "string" ||
    value.secret.length === 0
  ) {
    return undefined;
  }
  return {
    endpoint_id: value.endpoint_id,
    secret_version_id: value.secret_version_id,
    secret: value.secret,
  };
}

function isDelivery(value: unknown): value is WebhookDelivery {
  if (
    !isObject(value) ||
    typeof value.delivery_id !== "string" ||
    typeof value.endpoint_id !== "string" ||
    typeof value.event_id !== "string" ||
    typeof value.event_type !== "string" ||
    typeof value.body_hash !== "string" ||
    typeof value.secret_version_id !== "string" ||
    typeof value.signature_key_id !== "string" ||
    !isDeliveryState(value.state) ||
    !isCount(value.attempt_count) ||
    !isNullableString(value.next_attempt_at) ||
    !isNullableString(value.delivered_at) ||
    !isNullableString(value.last_error_code) ||
    !isNullableString(value.replay_of_delivery_id) ||
    !isCount(value.replay_generation) ||
    !isPositiveInteger(value.version) ||
    typeof value.created_at !== "string" ||
    typeof value.updated_at !== "string"
  ) {
    return false;
  }
  // The three diagnostic fields are optional in the frozen projection. When a
  // revision adds them they must still be well-typed, or the whole page is
  // refused rather than half-trusted.
  if (value.last_http_status !== undefined && !isHttpStatus(value.last_http_status)) return false;
  if (value.last_latency_ms !== undefined && !isNonNegativeMilliseconds(value.last_latency_ms)) {
    return false;
  }
  if (value.payload !== undefined && value.payload !== null && !isObject(value.payload))
    return false;
  return true;
}

function decodeDeliveryPage(value: unknown): Page<WebhookDelivery> | undefined {
  return isPage<WebhookDelivery>(value, isDelivery) ? value : undefined;
}

function decodeTestQueued(value: unknown): WebhookTestQueued | undefined {
  if (
    !isObject(value) ||
    typeof value.delivery_id !== "string" ||
    typeof value.endpoint_id !== "string" ||
    typeof value.event_id !== "string" ||
    !isDeliveryState(value.state)
  ) {
    return undefined;
  }
  return {
    delivery_id: value.delivery_id,
    endpoint_id: value.endpoint_id,
    event_id: value.event_id,
    state: value.state,
  };
}

function decodeDeliveryReplayed(value: unknown): WebhookDeliveryReplayed | undefined {
  if (
    !isObject(value) ||
    typeof value.delivery_id !== "string" ||
    typeof value.replay_of_delivery_id !== "string" ||
    !isCount(value.replay_generation) ||
    typeof value.event_id !== "string" ||
    typeof value.body_hash !== "string" ||
    typeof value.secret_version_id !== "string" ||
    !isDeliveryState(value.state)
  ) {
    return undefined;
  }
  return {
    delivery_id: value.delivery_id,
    replay_of_delivery_id: value.replay_of_delivery_id,
    replay_generation: value.replay_generation,
    event_id: value.event_id,
    body_hash: value.body_hash,
    secret_version_id: value.secret_version_id,
    state: value.state,
  };
}

function decodeNoContent(_value: unknown): undefined {
  return undefined;
}

// ---------------------------------------------------------------------------
// Request plumbing
// ---------------------------------------------------------------------------

function webhooksPath(orgId: string): string {
  return `/api/v1/orgs/${encodeURIComponent(orgId)}/webhooks`;
}

function resolveQuery<T extends object>(
  queryOrSignal: T | AbortSignal | undefined,
  signal: AbortSignal | undefined,
): { query: T | undefined; signal: AbortSignal | undefined } {
  if (isAbortSignal(queryOrSignal)) return { query: undefined, signal: queryOrSignal };
  return { query: queryOrSignal, signal };
}

function isAbortSignal(value: unknown): value is AbortSignal {
  return typeof value === "object" && value !== null && "aborted" in value;
}

function withQuery(path: string, query: object | undefined): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      params.set(key, String(value));
    }
  }
  const encoded = params.toString();
  return encoded ? `${path}?${encoded}` : path;
}
