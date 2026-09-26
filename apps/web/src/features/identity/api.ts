/**
 * P07 machine identity client — service accounts and API keys.
 *
 * Frozen contract: `docs/implementation/gates/P07-CG.md` §"Machine identity
 * contract" and §"API contract" (contract version `p07-cg-v1`), implemented in
 * `apps/api/src/routes/machine_identity.rs`.
 *
 * Three rules shape this module:
 *
 * 1. **The secret appears exactly once.** Create and rotate return a plaintext
 *    key that is never persisted server-side. This module hands it straight to the
 *    caller and keeps no copy: `decodeApiKeyWithSecret` refuses a response with no
 *    `secret` rather than pretending a key was created, and the plain `ApiKey`
 *    decoder has no field a secret could occupy.
 * 2. **Every decoder is an allowlist.** A response that does not match the frozen
 *    shape is refused whole, so contract drift surfaces as a visible error state
 *    instead of a half-rendered control plane.
 * 3. **The transport is feature-local** because `@/lib/api.ts` does not export its
 *    `requestJson` helper. It is the same precedent `features/webhooks/api.ts`
 *    set for P06, and `features/plugins/api.ts` reuses this exact export rather
 *    than carrying a third copy. CSRF, idempotency, and the error envelope are
 *    therefore identical across every P07 surface.
 */

import {
  ApiClientError,
  apiErrorFromEnvelope,
  makeInvalidResponseError,
  makeTransportError,
  presentApiError,
  type ErrorPresentation,
} from "@/lib/errors";

// ---------------------------------------------------------------------------
// P07 transport
// ---------------------------------------------------------------------------

export interface P07RequestOptions {
  method?: string;
  body?: unknown;
  idempotencyKey?: string;
  signal?: AbortSignal;
}

export type P07ResponseDecoder<T> = (value: unknown) => T | undefined;

export async function p07RequestJson<T>(
  path: string,
  options: P07RequestOptions,
  decode: P07ResponseDecoder<T>,
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
// Frozen vocabulary
// ---------------------------------------------------------------------------

/** `ServiceAccount.status`. A suspended account denies every capability. */
export const SERVICE_ACCOUNT_STATUSES = ["active", "suspended"] as const;
export type ServiceAccountStatus = (typeof SERVICE_ACCOUNT_STATUSES)[number];

/** `ApiKey.status`. `revoked` and `expired` are terminal. */
export const API_KEY_STATUSES = ["active", "revoked", "rotated", "expired"] as const;
export type ApiKeyStatus = (typeof API_KEY_STATUSES)[number];

/** P07-CG: max 50 active service accounts per organization. */
export const MAX_ACTIVE_SERVICE_ACCOUNTS_PER_ORG = 50;
/** P07-CG: max 5 active keys per service account. */
export const MAX_ACTIVE_KEYS_PER_ACCOUNT = 5;

/** The wire key format. The public prefix is a lookup key, not a secret. */
export const API_KEY_PREFIX_PATTERN = /^lumik_[0-9a-f]{12}_[A-Za-z0-9_-]{43}$/;

export interface ServiceAccount {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  capabilities: string[];
  status: ServiceAccountStatus;
  expires_at: string | null;
  suspended_at: string | null;
  suspend_reason: string | null;
  created_by_principal_id: string;
  version: number;
  created_at: string;
  updated_at: string;
}

/**
 * The key projection. There is deliberately no field a plaintext secret could
 * occupy, and `GET /api-keys/{id}` returns exactly this shape — a get can never
 * leak a credential even by accident.
 */
export interface ApiKey {
  id: string;
  service_account_id: string;
  organization_id: string;
  name: string;
  key_prefix: string;
  fingerprint: string;
  capabilities: string[];
  project_ids: string[];
  model_aliases: string[];
  network_allowlist: string[];
  status: ApiKeyStatus;
  rotated_from_key_id: string | null;
  rotated_to_key_id: string | null;
  last_used_at: string | null;
  last_used_source: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  revoke_reason: string | null;
  version: number;
  created_at: string;
  updated_at: string;
}

/** Create and rotate only. This is the only shape that ever carries `secret`. */
export interface ApiKeyWithSecret extends ApiKey {
  secret: string;
  secret_notice: string;
}

/**
 * A cursor page.
 *
 * The P07 route returns `{ items, page: { limit, next_cursor } }` and no
 * `has_more`, so the flag is derived rather than invented: another page exists
 * exactly when the server handed back a cursor.
 */
export interface Page<T> {
  items: T[];
  limit: number;
  next_cursor: string | null;
  has_more: boolean;
}

export interface ListQuery {
  limit?: number;
  cursor?: string;
}

export interface CreateServiceAccountInput {
  name: string;
  capabilities: string[];
  description?: string | null;
  expires_at?: string | null;
}

export interface UpdateServiceAccountInput {
  version: number;
  name?: string;
  description?: string | null;
  capabilities?: string[];
}

export interface CreateApiKeyInput {
  service_account_id: string;
  name: string;
  capabilities: string[];
  project_ids?: string[];
  model_aliases?: string[];
  network_allowlist?: string[];
  expires_at?: string | null;
}

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

export async function listServiceAccounts(
  orgId: string,
  query?: ListQuery,
  signal?: AbortSignal,
): Promise<Page<ServiceAccount>> {
  return p07RequestJson(
    withQuery(serviceAccountsPath(orgId), query),
    signal ? { signal } : {},
    decodeServiceAccountPage,
  );
}

export async function createServiceAccount(
  orgId: string,
  input: CreateServiceAccountInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<ServiceAccount> {
  return p07RequestJson(
    serviceAccountsPath(orgId),
    { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    (value) => decodeServiceAccount(readRecord(value, "service_account")),
  );
}

export async function getServiceAccount(
  orgId: string,
  serviceAccountId: string,
  signal?: AbortSignal,
): Promise<ServiceAccount> {
  return p07RequestJson(
    `${serviceAccountsPath(orgId)}/${encodeURIComponent(serviceAccountId)}`,
    signal ? { signal } : {},
    (value) => decodeServiceAccount(readRecord(value, "service_account")),
  );
}

export async function updateServiceAccount(
  orgId: string,
  serviceAccountId: string,
  input: UpdateServiceAccountInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<ServiceAccount> {
  return p07RequestJson(
    `${serviceAccountsPath(orgId)}/${encodeURIComponent(serviceAccountId)}`,
    { method: "PATCH", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    (value) => decodeServiceAccount(readRecord(value, "service_account")),
  );
}

export async function suspendServiceAccount(
  orgId: string,
  serviceAccountId: string,
  input: { version: number; reason: string },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<ServiceAccount> {
  return p07RequestJson(
    `${serviceAccountsPath(orgId)}/${encodeURIComponent(serviceAccountId)}/suspend`,
    { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    (value) => decodeServiceAccount(readRecord(value, "service_account")),
  );
}

export async function resumeServiceAccount(
  orgId: string,
  serviceAccountId: string,
  input: { version: number },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<ServiceAccount> {
  return p07RequestJson(
    `${serviceAccountsPath(orgId)}/${encodeURIComponent(serviceAccountId)}/resume`,
    { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    (value) => decodeServiceAccount(readRecord(value, "service_account")),
  );
}

export async function listApiKeys(
  orgId: string,
  query?: ListQuery,
  signal?: AbortSignal,
): Promise<Page<ApiKey>> {
  return p07RequestJson(
    withQuery(apiKeysPath(orgId), query),
    signal ? { signal } : {},
    decodeApiKeyPage,
  );
}

/**
 * Mint a key. The returned `secret` is plaintext and is shown to the operator
 * exactly once; the server stores only a hash, the prefix, and a fingerprint.
 */
export async function createApiKey(
  orgId: string,
  input: CreateApiKeyInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<ApiKeyWithSecret> {
  return p07RequestJson(
    apiKeysPath(orgId),
    { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    (value) => decodeApiKeyWithSecret(readRecord(value, "api_key")),
  );
}

/** Key metadata. This route has no secret to return and therefore never does. */
export async function getApiKey(apiKeyId: string, signal?: AbortSignal): Promise<ApiKey> {
  return p07RequestJson(
    `/api/v1/api-keys/${encodeURIComponent(apiKeyId)}`,
    signal ? { signal } : {},
    (value) => decodeApiKey(readRecord(value, "api_key")),
  );
}

/**
 * F14-004: rotation creates the overlapping replacement first and only then
 * marks the prior key `rotated`. A failed rotation leaves both keys untouched.
 */
export async function rotateApiKey(
  apiKeyId: string,
  input: { reason: string },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<ApiKeyWithSecret> {
  return p07RequestJson(
    `/api/v1/api-keys/${encodeURIComponent(apiKeyId)}/rotate`,
    { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    (value) => decodeApiKeyWithSecret(readRecord(value, "api_key")),
  );
}

/** Revocation is terminal. There is no un-revoke, and the key stays readable. */
export async function revokeApiKey(
  apiKeyId: string,
  input: { version: number; reason: string },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<ApiKey> {
  return p07RequestJson(
    `/api/v1/api-keys/${encodeURIComponent(apiKeyId)}/revoke`,
    { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    (value) => decodeApiKey(readRecord(value, "api_key")),
  );
}

// ---------------------------------------------------------------------------
// Strict decoders
// ---------------------------------------------------------------------------

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readRecord(value: unknown, field: string): unknown {
  return isObject(value) ? value[field] : undefined;
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isServiceAccountStatus(value: unknown): value is ServiceAccountStatus {
  return (SERVICE_ACCOUNT_STATUSES as readonly unknown[]).includes(value);
}

function isApiKeyStatus(value: unknown): value is ApiKeyStatus {
  return (API_KEY_STATUSES as readonly unknown[]).includes(value);
}

/**
 * The decoders are ALLOWLISTS: each one copies named fields out of the wire
 * object into a fresh value and never spreads it.
 *
 * That is what makes the "the secret cannot be retrieved again" claim hold from
 * the browser's side rather than merely being intended. If a future server
 * revision started adding `secret` to the list or get projection — a mistake with
 * no upside — a spread decoder would hand it straight to component state. An
 * allowlist makes that structurally impossible, and the test asserting it is the
 * one that would catch it.
 */
export function decodeServiceAccount(value: unknown): ServiceAccount | undefined {
  if (!isObject(value)) return undefined;
  if (
    typeof value.id !== "string" ||
    typeof value.organization_id !== "string" ||
    typeof value.name !== "string" ||
    !isNullableString(value.description) ||
    !isStringArray(value.capabilities) ||
    !isServiceAccountStatus(value.status) ||
    !isNullableString(value.expires_at) ||
    !isNullableString(value.suspended_at) ||
    !isNullableString(value.suspend_reason) ||
    typeof value.created_by_principal_id !== "string" ||
    typeof value.version !== "number" ||
    typeof value.created_at !== "string" ||
    typeof value.updated_at !== "string"
  ) {
    return undefined;
  }
  return {
    id: value.id,
    organization_id: value.organization_id,
    name: value.name,
    description: value.description,
    // Copied, so a caller mutating the array cannot reach back into the payload.
    capabilities: [...value.capabilities],
    status: value.status,
    expires_at: value.expires_at,
    suspended_at: value.suspended_at,
    suspend_reason: value.suspend_reason,
    created_by_principal_id: value.created_by_principal_id,
    version: value.version,
    created_at: value.created_at,
    updated_at: value.updated_at,
  };
}

export function decodeApiKey(value: unknown): ApiKey | undefined {
  if (!isObject(value)) return undefined;
  if (
    typeof value.id !== "string" ||
    typeof value.service_account_id !== "string" ||
    typeof value.organization_id !== "string" ||
    typeof value.name !== "string" ||
    typeof value.key_prefix !== "string" ||
    typeof value.fingerprint !== "string" ||
    !isStringArray(value.capabilities) ||
    !isStringArray(value.project_ids) ||
    !isStringArray(value.model_aliases) ||
    !isStringArray(value.network_allowlist) ||
    !isApiKeyStatus(value.status) ||
    !isNullableString(value.rotated_from_key_id) ||
    !isNullableString(value.rotated_to_key_id) ||
    !isNullableString(value.last_used_at) ||
    !isNullableString(value.last_used_source) ||
    !isNullableString(value.expires_at) ||
    !isNullableString(value.revoked_at) ||
    !isNullableString(value.revoke_reason) ||
    typeof value.version !== "number" ||
    typeof value.created_at !== "string" ||
    typeof value.updated_at !== "string"
  ) {
    return undefined;
  }
  return {
    id: value.id,
    service_account_id: value.service_account_id,
    organization_id: value.organization_id,
    name: value.name,
    key_prefix: value.key_prefix,
    fingerprint: value.fingerprint,
    capabilities: [...value.capabilities],
    project_ids: [...value.project_ids],
    model_aliases: [...value.model_aliases],
    network_allowlist: [...value.network_allowlist],
    status: value.status,
    rotated_from_key_id: value.rotated_from_key_id,
    rotated_to_key_id: value.rotated_to_key_id,
    last_used_at: value.last_used_at,
    last_used_source: value.last_used_source,
    expires_at: value.expires_at,
    revoked_at: value.revoked_at,
    revoke_reason: value.revoke_reason,
    version: value.version,
    created_at: value.created_at,
    updated_at: value.updated_at,
  };
}

/**
 * The create/rotate response is the ONLY place a plaintext secret exists.
 *
 * A response with no `secret` is refused, not downgraded to a metadata key: an
 * operator who is told a key exists but never sees it cannot use it, and the
 * mistake must be visible rather than silent. A `secret` that does not match the
 * frozen wire format is refused for the same reason — a value nobody can send as a
 * bearer token is not a usable credential.
 */
function decodeApiKeyWithSecret(value: unknown): ApiKeyWithSecret | undefined {
  if (!isObject(value)) return undefined;
  const metadata = decodeApiKey(value);
  if (!metadata) return undefined;
  const secret = value.secret;
  const notice = value.secret_notice;
  if (typeof secret !== "string" || secret.length === 0) return undefined;
  if (!API_KEY_PREFIX_PATTERN.test(secret)) return undefined;
  if (typeof notice !== "string" || notice.length === 0) return undefined;
  return { ...metadata, secret, secret_notice: notice };
}

function decodeCursorPage<T>(
  value: unknown,
  decodeItem: (item: unknown) => T | undefined,
): Page<T> | undefined {
  if (!isObject(value) || !Array.isArray(value.items)) return undefined;
  const items: T[] = [];
  for (const entry of value.items) {
    const item = decodeItem(entry);
    if (item === undefined) return undefined;
    items.push(item);
  }
  const page = isObject(value.page) ? value.page : undefined;
  const limit = page?.limit;
  const nextCursor = page?.next_cursor;
  if (typeof limit !== "number") return undefined;
  if (!isNullableString(nextCursor)) return undefined;
  return { items, limit, next_cursor: nextCursor, has_more: nextCursor !== null };
}

function decodeServiceAccountPage(value: unknown): Page<ServiceAccount> | undefined {
  return decodeCursorPage<ServiceAccount>(value, decodeServiceAccount);
}

function decodeApiKeyPage(value: unknown): Page<ApiKey> | undefined {
  return decodeCursorPage<ApiKey>(value, decodeApiKey);
}

// ---------------------------------------------------------------------------
// Request plumbing
// ---------------------------------------------------------------------------

function serviceAccountsPath(orgId: string): string {
  return `/api/v1/orgs/${encodeURIComponent(orgId)}/service-accounts`;
}

function apiKeysPath(orgId: string): string {
  return `/api/v1/orgs/${encodeURIComponent(orgId)}/api-keys`;
}

function withQuery(path: string, query: ListQuery | undefined): string {
  if (!query) return path;
  const params = new URLSearchParams();
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  if (query.cursor) params.set("cursor", query.cursor);
  const encoded = params.toString();
  return encoded ? `${path}?${encoded}` : path;
}

// ---------------------------------------------------------------------------
// Error presentation
// ---------------------------------------------------------------------------

export type IdentityTone = "neutral" | "info" | "success" | "warning" | "danger";

export interface IdentityErrorCopy {
  readonly title: string;
  readonly message: string;
  readonly tone: IdentityTone;
}

/**
 * Every stable P07 machine-identity reason code, in the order the gate lists it.
 *
 * The server's own message is never rendered. Each entry answers the question an
 * operator actually has — what happened, and what to do next — because "try again"
 * is the wrong remediation for a human-only capability or a terminal key.
 */
export const IDENTITY_ERROR_COPY: Readonly<Record<string, IdentityErrorCopy>> = {
  capability_human_only: {
    title: "That capability is human-only",
    message:
      "A machine credential can never hold this capability, so it was refused before the request was stored. Perform the action as a signed-in person, or grant the credential a different capability.",
    tone: "warning",
  },
  capability_unknown: {
    title: "Unknown capability",
    message:
      "One of the selected capabilities is not a permission this product defines. Remove it and submit again.",
    tone: "danger",
  },
  scope_capability_unknown: {
    title: "Capability is outside the service account",
    message:
      "A key may only hold capabilities its service account already has. Widen the service account first, then create or rotate the key.",
    tone: "danger",
  },
  key_limit_reached: {
    title: "Active credential limit reached",
    message:
      "This organization has reached its active service-account or per-account key limit. Suspend, revoke, or reuse an existing credential before creating another.",
    tone: "warning",
  },
  key_terminal: {
    title: "This key is terminal",
    message:
      "A revoked, expired, or already-rotated key cannot be rotated again. Create a new key on the same service account instead.",
    tone: "warning",
  },
  machine_key_suspended: {
    title: "Service account is suspended",
    message:
      "The account that owns this key is suspended, so the key is denied with machine_key_suspended even before it expires. Resume the account, then retry.",
    tone: "warning",
  },
  machine_key_expired: {
    title: "Key expired",
    message: "This key is past its expiry and is refused. Create a new key with a later expiry.",
    tone: "warning",
  },
  machine_key_revoked: {
    title: "Key revoked",
    message: "This key was revoked and is refused permanently. Create a new key on the account.",
    tone: "warning",
  },
  machine_key_invalid: {
    title: "Key could not be verified",
    message:
      "The presented key did not match a stored credential. Check that the whole value was copied without truncation.",
    tone: "danger",
  },
  scope_denied: {
    title: "Outside the key's capability scope",
    message:
      "The key does not hold the capability this action needs. Grant it on the key, or perform the action with a human credential.",
    tone: "warning",
  },
  scope_project_mismatch: {
    title: "Project outside the key's scope",
    message:
      "A project-scoped key cannot reach a project it was not scoped to, even inside the same organization. Widen the key's project list deliberately.",
    tone: "warning",
  },
  scope_network_unavailable: {
    title: "Network allowlist could not be evaluated",
    message:
      "This key restricts callers by network, and the edge did not report a client address, so the request was denied rather than allowed. The control fails closed on purpose.",
    tone: "warning",
  },
  human_only_action: {
    title: "That action is human-only",
    message:
      "Some organization actions are permanently unavailable to a machine credential. Perform the action as a signed-in person.",
    tone: "warning",
  },
  version_conflict: {
    title: "The record changed while you were working",
    message:
      "Someone else changed this credential, so the write was refused rather than overwriting their change. Review the current state, then repeat the action.",
    tone: "warning",
  },
  permission_denied: {
    title: "Access not permitted",
    message:
      "Ask an administrator to grant service-account access. Your current membership cannot read or change these credentials.",
    tone: "warning",
  },
};

/**
 * Presentation for a machine-identity failure.
 *
 * `details.reason` is the stable code the gate freezes; the envelope `code` is
 * checked too, because a refusal raised before a domain decision (a 403, a 401)
 * carries its reason in the code rather than in a detail.
 */
export function presentIdentityError(error: unknown): ErrorPresentation & { tone: IdentityTone } {
  if (error instanceof ApiClientError) {
    const reason = error.details.reason;
    const candidates = [error.code, typeof reason === "string" ? reason : null];
    for (const entry of candidates) {
      if (entry === null) continue;
      const known = IDENTITY_ERROR_COPY[entry];
      if (known) {
        return {
          title: known.title,
          message: known.message,
          code: entry,
          requestId: error.requestId,
          retryable: error.retryable,
          tone: known.tone,
        };
      }
    }
  }
  const base = presentApiError(error);
  return { ...base, tone: base.retryable ? "warning" : "danger" };
}
