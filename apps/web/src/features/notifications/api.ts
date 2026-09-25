/**
 * P06 notification center and notification preferences client.
 *
 * Frozen contract: `docs/implementation/gates/P06-CG.md` → "API contract" and
 * "Notification channels" (contract version `p06-cg-v1`).
 *
 * The notification center is principal-scoped: the recipient is resolved from
 * the authenticated session, never from a path or body value, and a foreign
 * notification ID returns the same non-disclosing not-found shape. Mandatory
 * security events remain visible regardless of informational preferences.
 *
 * The P06 transport is shared with the webhooks client so CSRF, idempotency, and
 * error-envelope normalization are implemented once. `@/lib/api.ts` owns the
 * shared client; see the note in `@/features/webhooks/api.ts`.
 */

import type { Page } from "@/lib/api";
import { p06RequestJson } from "@/features/webhooks/api";

export const NOTIFICATION_CATEGORIES = [
  "security",
  "billing",
  "automation",
  "policy",
  "operational",
] as const;

export type NotificationCategory = (typeof NOTIFICATION_CATEGORIES)[number];

export const NOTIFICATION_CHANNELS = ["in_app", "email"] as const;

export type NotificationChannel = (typeof NOTIFICATION_CHANNELS)[number];

export const NOTIFICATION_STATES = ["unread", "read", "archived"] as const;

export type NotificationState = (typeof NOTIFICATION_STATES)[number];

export interface Notification {
  notification_id: string;
  org_id: string | null;
  event_id: string;
  event_type: string;
  category: NotificationCategory;
  /** True for a mandatory security event: it cannot be disabled by preferences. */
  mandatory: boolean;
  state: NotificationState;
  read_at: string | null;
  /** Bounded rendered metadata only. Never prompt, response, or raw content. */
  body: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface NotificationPreference {
  channel: NotificationChannel;
  /** Exact event names opted out of on this channel. Mandatory events are never here. */
  disabled_event_types: string[];
  /** `0` means no row exists yet, which is also the expected version to create one. */
  version: number;
  updated_at: string | null;
}

export interface NotificationPreferencesResponse {
  preferences: NotificationPreference[];
}

export interface ListNotificationsQuery {
  limit?: number;
  cursor?: string;
  unread?: boolean;
  category?: NotificationCategory;
}

export type NotificationPreferenceScope =
  | { readonly kind: "me" }
  | { readonly kind: "org"; readonly orgId: string };

function preferencesPath(scope: NotificationPreferenceScope): string {
  return scope.kind === "me"
    ? "/api/v1/me/notification-preferences"
    : `/api/v1/orgs/${encodeURIComponent(scope.orgId)}/notification-preferences`;
}

export async function listNotifications(
  queryOrSignal?: ListNotificationsQuery | AbortSignal,
  signal?: AbortSignal,
): Promise<Page<Notification>> {
  const request = resolveQuery(queryOrSignal, signal);
  return p06RequestJson(
    withQuery("/api/v1/notifications", request.query),
    request.signal ? { signal: request.signal } : {},
    decodeNotificationPage,
  );
}

/**
 * Mark one owned notification read. Idempotent: a repeat returns the same
 * projection and does not change `read_at` again.
 */
export async function markNotificationRead(
  notificationId: string,
  signal?: AbortSignal,
): Promise<Notification> {
  return p06RequestJson(
    `/api/v1/notifications/${encodeURIComponent(notificationId)}/read`,
    { method: "POST", body: {}, ...(signal ? { signal } : {}) },
    decodeNotification,
  );
}

export async function getNotificationPreferences(
  scope: NotificationPreferenceScope,
  signal?: AbortSignal,
): Promise<NotificationPreference[]> {
  const response = await p06RequestJson(
    preferencesPath(scope),
    signal ? { signal } : {},
    decodePreferencesResponse,
  );
  return response.preferences;
}

export interface UpdateNotificationPreferenceInput {
  channel: NotificationChannel;
  /** Current row version; `0` when the row must not exist yet. */
  version: number;
  disabled_event_types: string[];
}

export async function updateNotificationPreference(
  scope: NotificationPreferenceScope,
  input: UpdateNotificationPreferenceInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<NotificationPreference> {
  return p06RequestJson(
    preferencesPath(scope),
    {
      method: "PATCH",
      body: input,
      idempotencyKey,
      ...(signal ? { signal } : {}),
    },
    decodePreference,
  );
}

// ---------------------------------------------------------------------------
// Strict decoders
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

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isNotificationCategory(value: unknown): value is NotificationCategory {
  return (NOTIFICATION_CATEGORIES as readonly unknown[]).includes(value);
}

function isNotificationChannel(value: unknown): value is NotificationChannel {
  return (NOTIFICATION_CHANNELS as readonly unknown[]).includes(value);
}

function isNotificationState(value: unknown): value is NotificationState {
  return (NOTIFICATION_STATES as readonly unknown[]).includes(value);
}

function isPage<T>(value: unknown, isItem: (item: unknown) => boolean): value is Page<T> {
  return (
    isObject(value) &&
    Array.isArray(value.items) &&
    value.items.every(isItem) &&
    isNullableString(value.next_cursor) &&
    typeof value.has_more === "boolean"
  );
}

function isNotification(value: unknown): value is Notification {
  return (
    isObject(value) &&
    typeof value.notification_id === "string" &&
    isNullableString(value.org_id) &&
    typeof value.event_id === "string" &&
    typeof value.event_type === "string" &&
    isNotificationCategory(value.category) &&
    typeof value.mandatory === "boolean" &&
    isNotificationState(value.state) &&
    isNullableString(value.read_at) &&
    isObject(value.body) &&
    typeof value.created_at === "string" &&
    typeof value.updated_at === "string"
  );
}

function decodeNotification(value: unknown): Notification | undefined {
  return isNotification(value) ? value : undefined;
}

function decodeNotificationPage(value: unknown): Page<Notification> | undefined {
  return isPage<Notification>(value, isNotification) ? value : undefined;
}

function isPreference(value: unknown): value is NotificationPreference {
  return (
    isObject(value) &&
    isNotificationChannel(value.channel) &&
    isStringArray(value.disabled_event_types) &&
    isNonNegativeInteger(value.version) &&
    isNullableString(value.updated_at)
  );
}

function decodePreference(value: unknown): NotificationPreference | undefined {
  return isPreference(value) ? value : undefined;
}

function decodePreferencesResponse(value: unknown): NotificationPreferencesResponse | undefined {
  if (!isObject(value) || !Array.isArray(value.preferences)) return undefined;
  const preferences = value.preferences.filter(isPreference);
  return preferences.length === value.preferences.length ? { preferences } : undefined;
}

// ---------------------------------------------------------------------------
// Request plumbing
// ---------------------------------------------------------------------------

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
