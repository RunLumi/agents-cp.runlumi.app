import { apiErrorFromEnvelope, makeInvalidResponseError, makeTransportError } from "@/lib/errors";

export interface HealthResponse {
  status: "ok";
  service: string;
}

export interface ApiMetaResponse {
  api_version: string;
  contract_version: string;
  service: string;
}

export type DeliveryStatus = "pending" | "queued" | "delivered" | "dead_letter";

export interface FoundationCheckResponse {
  event_id: string;
  delivery_status: DeliveryStatus;
}

type Decoder<T> = (value: unknown) => value is T;

const INTERNAL_FOUNDATION_CHECKS = "/api/v1/_internal/foundation-checks";

export async function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return requestJson("/api/health", signal ? { signal } : {}, isHealthResponse);
}

export async function getApiMeta(signal?: AbortSignal): Promise<ApiMetaResponse> {
  return requestJson("/api/v1/meta", signal ? { signal } : {}, isApiMetaResponse);
}

export async function createFoundationCheck(
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<FoundationCheckResponse> {
  const headers = new Headers({ Accept: "application/json", "Content-Type": "application/json" });
  headers.set("Idempotency-Key", idempotencyKey);

  return requestJson(
    INTERNAL_FOUNDATION_CHECKS,
    { method: "POST", headers, body: "{}", ...(signal ? { signal } : {}) },
    isFoundationCheckResponse,
    true,
  );
}

export async function getFoundationCheckStatus(
  eventId: string,
  signal?: AbortSignal,
): Promise<FoundationCheckResponse> {
  return requestJson(
    `${INTERNAL_FOUNDATION_CHECKS}/${encodeURIComponent(eventId)}`,
    signal ? { signal } : {},
    isFoundationCheckResponse,
  );
}

async function requestJson<T>(
  path: string,
  options: RequestInit,
  decode: Decoder<T>,
  hasIdempotencyKey = false,
): Promise<T> {
  const headers = new Headers(options.headers);
  if (!headers.has("Accept")) headers.set("Accept", "application/json");

  const init: RequestInit = { ...options, headers };
  const method = (options.method ?? "GET").toUpperCase();
  const retrySafe = method === "GET" || method === "HEAD" || hasIdempotencyKey;

  let response: Response;
  try {
    response = await fetch(path, init);
  } catch (cause) {
    throw makeTransportError(cause, options.signal ?? undefined, { retryable: retrySafe });
  }

  const requestId = readRequestId(response.headers.get("X-Request-ID"));
  let responseText: string;
  try {
    responseText = await response.text();
  } catch (cause) {
    if (!response.ok) {
      throw makeTransportError(cause, options.signal ?? undefined, {
        requestId,
        status: response.status,
        retryable: isRetryableStatus(response.status, undefined, retrySafe),
      });
    }
    throw makeTransportError(cause, options.signal ?? undefined, {
      requestId,
      status: response.status,
      retryable: false,
    });
  }

  let payload: unknown = undefined;
  let validJson = true;
  if (responseText.length === 0) {
    validJson = false;
  } else {
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

  if (!validJson || !decode(payload)) {
    throw makeInvalidResponseError({ requestId, status: response.status });
  }

  return payload;
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

function readApiErrorCode(payload: unknown): string | undefined {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return undefined;
  const root = payload as Record<string, unknown>;
  const error = root.error;
  if (typeof error !== "object" || error === null || Array.isArray(error)) return undefined;
  const code = (error as Record<string, unknown>).code;
  return typeof code === "string" ? code : undefined;
}

function readRequestId(value: string | null): string | undefined {
  if (value === null) return undefined;
  const requestId = value.trim();
  return requestId.length > 0 && requestId.length <= 160 ? requestId : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isHealthResponse(value: unknown): value is HealthResponse {
  return (
    isRecord(value) &&
    value.status === "ok" &&
    typeof value.service === "string" &&
    value.service.length > 0
  );
}

function isApiMetaResponse(value: unknown): value is ApiMetaResponse {
  return (
    isRecord(value) &&
    typeof value.api_version === "string" &&
    typeof value.contract_version === "string" &&
    typeof value.service === "string"
  );
}

function isDeliveryStatus(value: unknown): value is DeliveryStatus {
  return (
    value === "pending" || value === "queued" || value === "delivered" || value === "dead_letter"
  );
}

function isFoundationCheckResponse(value: unknown): value is FoundationCheckResponse {
  return (
    isRecord(value) &&
    typeof value.event_id === "string" &&
    value.event_id.length > 0 &&
    isDeliveryStatus(value.delivery_status)
  );
}
