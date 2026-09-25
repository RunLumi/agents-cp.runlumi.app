/**
 * P06 billing, entitlement, and licensing client.
 *
 * Built against the FROZEN P06 contract gate `p06-cg-v1` and the
 * `docs/implementation/fixtures/p06-contracts-v1.json` fixture.
 *
 * Two deliberate rules shape this module:
 *
 * 1. Every decoder is an ALLOWLIST. It copies named fields out of the wire
 *    object and never spreads it. A payment-provider product ID, price ID, or
 *    customer reference therefore cannot reach component state, even if the
 *    server sends one. `isProviderIdentifier` exists so tests can prove it.
 * 2. The transport here is feature-local because the P06 routes are not yet in
 *    `@/lib/api.ts` and `@/lib/api.ts` is outside this packet's write surface.
 *    It reuses `@/lib/errors` for every failure path. The coordinator may fold
 *    `requestJson` into a shared internal module when P06 lands there; the
 *    decoders and types below are already independent of the transport.
 */

import { apiErrorFromEnvelope, makeInvalidResponseError, makeTransportError } from "@/lib/errors";

// ---------------------------------------------------------------------------
// Frozen vocabulary
// ---------------------------------------------------------------------------

/** `Subscription.status` — P06-CG "Subscription and license". */
export const SUBSCRIPTION_STATUSES = [
  "trialing",
  "active",
  "grace",
  "past_due",
  "suspended",
  "cancelled",
] as const;
export type SubscriptionStatus = (typeof SUBSCRIPTION_STATUSES)[number];

/** `LicenseState` — a server-side projection, not a provider state. */
export const LICENSE_STATES = [
  "active",
  "grace",
  "past_due",
  "suspended",
  "cancelled",
  "expired",
  "provider_unavailable",
] as const;
export type LicenseState = (typeof LICENSE_STATES)[number];

/** `ProviderEntitlementProjection.status` — read-only upstream observation. */
export const PROVIDER_PROJECTION_STATUSES = [
  "available",
  "degraded",
  "unavailable",
  "unknown",
] as const;
export type ProviderProjectionStatus = (typeof PROVIDER_PROJECTION_STATUSES)[number];

/**
 * Effective entitlement precedence, weakest to strongest.
 * P06-CG: "platform default < active plan value < active subscription-derived
 * grant < active, scoped internal override".
 */
export const ENTITLEMENT_SOURCES = [
  "platform_default",
  "plan",
  "subscription",
  "internal_override",
] as const;
export type EntitlementSource = (typeof ENTITLEMENT_SOURCES)[number];

/**
 * `unknown` is the fail-closed presentation when the server returns a value
 * without attribution. The browser must not assume a plan grant.
 */
export type EntitlementAttribution = EntitlementSource | "unknown";

/** The three capability classes the license matrix is defined over. */
export const CAPABILITY_CLASSES = [
  "local_only",
  "cloud_control_plane",
  "platform_paid_inference",
] as const;
export type CapabilityClass = (typeof CAPABILITY_CLASSES)[number];

/** Remediation paths the server may publish for an over-limit resource. */
export const REMEDIATION_OPTIONS = ["reduce_to_limit", "suspend_seats", "upgrade_plan"] as const;
export type RemediationOption = (typeof REMEDIATION_OPTIONS)[number];

/**
 * The browser never infers plan rank. The server states the direction; without
 * that statement a change cannot be previewed and therefore cannot be submitted
 * from the browser.
 */
export const PLAN_CHANGE_DIRECTIONS = [
  "upgrade",
  "downgrade",
  "lateral",
  "same",
  "unknown",
] as const;
export type PlanChangeDirection = (typeof PLAN_CHANGE_DIRECTIONS)[number];

/** Bounded typed entitlement value. Never inferred from a provider ID. */
export type EntitlementValue = boolean | number | string;

// ---------------------------------------------------------------------------
// Wire projections
// ---------------------------------------------------------------------------

/** `Subscription` — the org commercial state mapped from a provider adapter. */
export interface Subscription {
  subscription_id: string;
  org_id: string;
  plan_key: string;
  status: SubscriptionStatus;
  /** Cloud control-plane grace expiry. Null unless the provider reported grace. */
  grace_expires_at: string | null;
  current_period_starts_at: string | null;
  current_period_ends_at: string | null;
  version: number;
}

/**
 * The signed license block carried inside the existing P03 device-policy
 * response. There is no second license endpoint and no second authority.
 * Field-for-field identical to the fixture `entitlements` block.
 */
export interface LicenseSnapshotBlock {
  subscription_id: string;
  billing_account_id: string;
  org_id: string;
  plan_key: string;
  status: SubscriptionStatus;
  /** Policy freshness clock — governs cloud control-plane work. */
  policy_fresh_until: string;
  /** Signed offline validity clock — governs local-only work. */
  offline_valid_until: string;
  values: Record<string, EntitlementValue>;
}

/** The P03 `entitlements` policy section. Governs the grace windows. */
export interface EntitlementPolicySection {
  schema_version: number;
  policy_fresh_seconds: number;
  local_offline_grace_seconds: number;
  cloud_control_plane_grace_seconds: number;
  platform_paid_inference_grace_seconds: number;
}

export interface EntitlementEntry {
  key: string;
  value: EntitlementValue | null;
  source: EntitlementAttribution;
  effective_at: string | null;
  /** An override always carries an expiry (P06-CR-002). */
  expires_at: string | null;
  /** Override reason. Never a credential, token, or provider payload. */
  reason: string | null;
  scope: string | null;
}

/** One resource the server reports as above the plan's included limit. */
export interface OverLimitResource {
  entitlement_key: string;
  limit: number;
  current: number;
  over_by: number;
  seat_based: boolean;
  remediation: RemediationOption[];
}

/** Effective Lumi entitlement projection for one organization. */
export interface EntitlementProjection {
  org_id: string;
  plan_key: string | null;
  status: SubscriptionStatus;
  policy_fresh_until: string | null;
  offline_valid_until: string | null;
  entitlements: EntitlementEntry[];
  over_limit: OverLimitResource[];
  version: number | null;
  updated_at: string | null;
}

/** Read-only upstream AI-provider account status. Never a Lumi entitlement. */
export interface ProviderEntitlementProjection {
  projection_id: string;
  org_id: string;
  /** Lumi provider key, not a payment-provider product or price identifier. */
  provider: string;
  status: ProviderProjectionStatus;
  observed_at: string;
  capability_class: string;
}

export interface BillingPortalSession {
  /** Allowlisted provider portal URL, or null when unavailable. */
  portal_url: string | null;
  expires_at: string | null;
  reason: string | null;
}

export interface PlanChangePreview {
  direction: PlanChangeDirection;
  current_plan_key: string | null;
  target_plan_key: string;
  over_limit: OverLimitResource[];
  /**
   * A downgrade never deletes data (F18 FR-F18-006, P06-CG). Typed as the
   * literal `false` so no code path can flip it to a claim of deletion.
   */
  deletes_data: false;
  blocks_new_work: boolean;
  reason: string | null;
}

export interface PlanChangeResult {
  accepted: boolean;
  subscription: Subscription | null;
  over_limit: OverLimitResource[];
  reason: string | null;
}

export interface CancelRequestResult {
  accepted: boolean;
  subscription: Subscription | null;
  reason: string | null;
}

export interface BillingSnapshot {
  /** Optional tenant marker; a mismatched snapshot is ignored on org switch. */
  orgId?: string;
  subscription?: Subscription;
  entitlements?: EntitlementProjection;
  provider?: ProviderEntitlementProjection;
  /** P03 `entitlements` policy section, when the shell already loaded it. */
  policy?: EntitlementPolicySection;
  updatedAt?: string;
}

/** The P06 browser surface. Every method is optional except the three reads. */
export interface BillingApi {
  getSubscription: (orgId: string, signal?: AbortSignal) => Promise<Subscription>;
  getEntitlements: (orgId: string, signal?: AbortSignal) => Promise<EntitlementProjection>;
  getProviderEntitlement: (
    orgId: string,
    signal?: AbortSignal,
  ) => Promise<ProviderEntitlementProjection>;
  createPortalSession?: (
    orgId: string,
    idempotencyKey: string,
    signal?: AbortSignal,
  ) => Promise<BillingPortalSession>;
  requestPlanChange?: (
    orgId: string,
    input: { plan_key: string; version: number },
    idempotencyKey: string,
    signal?: AbortSignal,
  ) => Promise<PlanChangeResult>;
  /**
   * A downgrade must be previewed before it is submitted. The frozen gate does
   * not publish a preview route and rejects unknown request fields, so this
   * method is intentionally NOT bound here: the panel refuses to submit a
   * change it cannot preview and routes the user to the provider portal.
   * P06-BE-03 (or a follow-on CR) must publish a real preview route before the
   * panel enables a direct downgrade submit.
   */
  previewPlanChange?: (
    orgId: string,
    input: { plan_key: string; version: number },
    idempotencyKey: string,
    signal?: AbortSignal,
  ) => Promise<PlanChangePreview>;
  requestCancellation?: (
    orgId: string,
    input: { version: number },
    idempotencyKey: string,
    signal?: AbortSignal,
  ) => Promise<CancelRequestResult>;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class BillingContractError extends Error {
  constructor(field: string) {
    super(`The billing response field ${field} did not match the expected contract.`);
    this.name = "BillingContractError";
  }
}

// ---------------------------------------------------------------------------
// Provider-identifier containment
// ---------------------------------------------------------------------------

/**
 * Wire keys a payment provider product/price/customer reference would arrive
 * under. They are listed so the containment test reads as a contract, not a
 * guess, and so a future decoder cannot quietly add one.
 */
export const PROVIDER_IDENTIFIER_FIELDS = [
  "product_id",
  "product",
  "price_id",
  "price",
  "customer_id",
  "customer",
  "customer_reference",
  "subscription_item_id",
  "invoice_id",
  "payment_method_id",
  "provider_reference",
  "provider_account_reference",
  "provider_customer_id",
  "raw_provider_payload",
] as const;

/** Lumi's own opaque ID shape: `<prefix>_<32 lowercase hex>`. Never a provider ID. */
const LUMI_OPAQUE_ID_PATTERN = /^[a-z]{2,4}_[0-9a-f]{32}$/;

/**
 * Payment-provider commercial identifier shapes. These are deliberately the
 * known provider prefixes, not a loose `word_thing` guess, so a legitimate Lumi
 * opaque ID is never misclassified.
 */
const PROVIDER_ID_VALUE_PATTERN = /^(?:prod|price|cus|si|in|pm|acct)_[A-Za-z0-9][A-Za-z0-9_-]{2,}$/;

/** True when a string looks like a payment-provider commercial identifier. */
export function isProviderIdentifier(value: string): boolean {
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 256) return false;
  if (LUMI_OPAQUE_ID_PATTERN.test(normalized)) return false;
  return PROVIDER_ID_VALUE_PATTERN.test(normalized);
}

/**
 * Recursively assert that a decoded structure carries no provider commercial
 * identifier. Used by tests and available to a future dev-time assertion.
 */
export function findProviderIdentifier(value: unknown, path = "$"): string | null {
  if (typeof value === "string") {
    return isProviderIdentifier(value) ? `${path} = ${value}` : null;
  }
  if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) {
      const found = findProviderIdentifier(item, `${path}[${index}]`);
      if (found) return found;
    }
    return null;
  }
  if (typeof value === "object" && value !== null) {
    for (const [key, item] of Object.entries(value)) {
      if ((PROVIDER_IDENTIFIER_FIELDS as readonly string[]).includes(key)) {
        return `${path}.${key}`;
      }
      const found = findProviderIdentifier(item, `${path}.${key}`);
      if (found) return found;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Decoders
// ---------------------------------------------------------------------------

const ENTITLEMENT_KEY_PATTERN = /^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*$/;
const STABLE_CODE_PATTERN = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/;
const MAX_KEY_LENGTH = 96;
const MAX_REASON_LENGTH = 240;
const MAX_SCOPE_LENGTH = 160;
const MAX_STRING_VALUE_LENGTH = 240;

export function isEntitlementKey(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length <= MAX_KEY_LENGTH &&
    ENTITLEMENT_KEY_PATTERN.test(value)
  );
}

/** `true` for a stable machine-readable reason code, `false` for prose. */
export function isStableReasonCode(value: unknown): value is string {
  return typeof value === "string" && value.length <= 96 && STABLE_CODE_PATTERN.test(value);
}

function objectValue(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new BillingContractError(field);
  }
  return value as Record<string, unknown>;
}

function readString(value: unknown, field: string, max = 256): string {
  if (typeof value !== "string") throw new BillingContractError(field);
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > max) throw new BillingContractError(field);
  return normalized;
}

function readOptionalString(value: unknown, field: string, max = 256): string | null {
  if (value === null || value === undefined) return null;
  return readString(value, field, max);
}

function readTimestamp(value: unknown, field: string): string {
  const raw = readString(value, field, 64);
  if (Number.isNaN(Date.parse(raw))) throw new BillingContractError(field);
  return raw;
}

function readOptionalTimestamp(value: unknown, field: string): string | null {
  if (value === null || value === undefined) return null;
  return readTimestamp(value, field);
}

function readVersion(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw new BillingContractError(field);
  }
  return value;
}

function readCount(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new BillingContractError(field);
  }
  return value;
}

function readEnum<const T extends readonly string[]>(
  value: unknown,
  values: T,
  field: string,
): T[number] {
  if (typeof value !== "string" || !(values as readonly string[]).includes(value)) {
    throw new BillingContractError(field);
  }
  return value as T[number];
}

function readNullableEnum<const T extends readonly string[]>(
  value: unknown,
  values: T,
  field: string,
): T[number] | null {
  if (value === null || value === undefined) return null;
  return readEnum(value, values, field);
}

function readBoundedSeconds(value: unknown, field: string): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > 31_536_000
  ) {
    throw new BillingContractError(field);
  }
  return value;
}

function readEntitlementValue(value: unknown, field: string): EntitlementValue {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new BillingContractError(field);
    return value;
  }
  if (typeof value === "string") {
    if (value.length === 0 || value.length > MAX_STRING_VALUE_LENGTH) {
      throw new BillingContractError(field);
    }
    return value;
  }
  throw new BillingContractError(field);
}

function readSource(value: unknown): EntitlementAttribution {
  if (typeof value !== "string") return "unknown";
  return (ENTITLEMENT_SOURCES as readonly string[]).includes(value)
    ? (value as EntitlementSource)
    : "unknown";
}

function readRemediationList(value: unknown): RemediationOption[] {
  if (!Array.isArray(value)) return [];
  const seen = new Set<RemediationOption>();
  for (const item of value) {
    if ((REMEDIATION_OPTIONS as readonly string[]).includes(String(item))) {
      seen.add(item as RemediationOption);
    }
  }
  return REMEDIATION_OPTIONS.filter((option) => seen.has(option));
}

function readSeatBased(value: unknown, key: string): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "string" && (value === "seat" || value === "seats")) return true;
  // A seat-based limit is a commercial fact, not a guess; when the server does
  // not publish it, fall back to the one key the gate defines as seat-based.
  return key === "org.max_members";
}

export function decodeSubscription(value: unknown): Subscription {
  const record = objectValue(value, "subscription");
  return {
    subscription_id: readString(record.subscription_id, "subscription_id", 64),
    org_id: readString(record.org_id, "org_id", 64),
    plan_key: readString(record.plan_key, "plan_key", 96),
    status: readEnum(record.status, SUBSCRIPTION_STATUSES, "status"),
    grace_expires_at: readOptionalTimestamp(record.grace_expires_at, "grace_expires_at"),
    current_period_starts_at: readOptionalTimestamp(
      record.current_period_starts_at,
      "current_period_starts_at",
    ),
    current_period_ends_at: readOptionalTimestamp(
      record.current_period_ends_at,
      "current_period_ends_at",
    ),
    version: readVersion(record.version, "version"),
  };
}

export function decodeLicenseSnapshotBlock(value: unknown): LicenseSnapshotBlock {
  const record = objectValue(value, "license");
  const values = objectValue(record.values, "values");
  const decoded: Record<string, EntitlementValue> = {};
  for (const [key, raw] of Object.entries(values)) {
    if (!isEntitlementKey(key)) throw new BillingContractError("values");
    decoded[key] = readEntitlementValue(raw, `values.${key}`);
  }
  return {
    subscription_id: readString(record.subscription_id, "subscription_id", 64),
    billing_account_id: readString(record.billing_account_id, "billing_account_id", 64),
    org_id: readString(record.org_id, "org_id", 64),
    plan_key: readString(record.plan_key, "plan_key", 96),
    status: readEnum(record.status, SUBSCRIPTION_STATUSES, "status"),
    policy_fresh_until: readTimestamp(record.policy_fresh_until, "policy_fresh_until"),
    offline_valid_until: readTimestamp(record.offline_valid_until, "offline_valid_until"),
    values: decoded,
  };
}

export function decodeEntitlementPolicySection(value: unknown): EntitlementPolicySection {
  const record = objectValue(value, "entitlements");
  return {
    schema_version: readVersion(record.schema_version, "schema_version"),
    policy_fresh_seconds: readBoundedSeconds(record.policy_fresh_seconds, "policy_fresh_seconds"),
    local_offline_grace_seconds: readBoundedSeconds(
      record.local_offline_grace_seconds,
      "local_offline_grace_seconds",
    ),
    cloud_control_plane_grace_seconds: readBoundedSeconds(
      record.cloud_control_plane_grace_seconds,
      "cloud_control_plane_grace_seconds",
    ),
    platform_paid_inference_grace_seconds: readBoundedSeconds(
      record.platform_paid_inference_grace_seconds,
      "platform_paid_inference_grace_seconds",
    ),
  };
}

function readOverLimitResource(value: unknown, index: number): OverLimitResource {
  const record = objectValue(value, `over_limit[${index}]`);
  const entitlementKey = readString(
    record.entitlement_key,
    `over_limit[${index}].entitlement_key`,
    MAX_KEY_LENGTH,
  );
  const limit = readCount(record.limit, `over_limit[${index}].limit`);
  const current = readCount(record.current, `over_limit[${index}].current`);
  return {
    entitlement_key: entitlementKey,
    limit,
    current,
    over_by: Math.max(0, current - limit),
    seat_based: readSeatBased(record.seat_based, entitlementKey),
    remediation: readRemediationList(record.remediation),
  };
}

function readOverLimitList(value: unknown): OverLimitResource[] {
  if (!Array.isArray(value)) return [];
  return value.map((item, index) => readOverLimitResource(item, index));
}

function readEntitlementEntries(record: Record<string, unknown>): EntitlementEntry[] {
  const sources = objectValueOrEmpty(record.sources);
  const entries: EntitlementEntry[] = [];

  if (Array.isArray(record.entitlements)) {
    record.entitlements.forEach((item, index) => {
      const entry = objectValue(item, `entitlements[${index}]`);
      const key = readString(entry.key, `entitlements[${index}].key`, MAX_KEY_LENGTH);
      if (!isEntitlementKey(key)) throw new BillingContractError(`entitlements[${index}].key`);
      entries.push({
        key,
        value:
          entry.value === null || entry.value === undefined
            ? null
            : readEntitlementValue(entry.value, `entitlements[${index}].value`),
        source: readSource(entry.source),
        effective_at: readOptionalTimestamp(entry.effective_at, "effective_at"),
        expires_at: readOptionalTimestamp(entry.expires_at, "expires_at"),
        reason: readOptionalString(entry.reason, "reason", MAX_REASON_LENGTH),
        scope: readOptionalString(entry.scope, "scope", MAX_SCOPE_LENGTH),
      });
    });
    return entries.sort((left, right) => left.key.localeCompare(right.key));
  }

  const raw = objectValueOrEmpty(record.values);
  for (const key of Object.keys(raw).sort()) {
    if (!isEntitlementKey(key)) throw new BillingContractError("values");
    const source = readSource(sources[key]);
    entries.push({
      key,
      value: readEntitlementValue(raw[key], `values.${key}`),
      source,
      effective_at: null,
      expires_at: null,
      reason: null,
      scope: null,
    });
  }
  return entries;
}

function objectValueOrEmpty(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

export function decodeEntitlementProjection(value: unknown): EntitlementProjection {
  const record = objectValue(value, "entitlements");
  const overLimitSource = Array.isArray(record.over_limit)
    ? record.over_limit
    : objectValueOrEmpty(record.remediation).over_limit;
  return {
    org_id: readString(record.org_id, "org_id", 64),
    plan_key: readOptionalString(record.plan_key, "plan_key", 96),
    status: readEnum(record.status, SUBSCRIPTION_STATUSES, "status"),
    policy_fresh_until: readOptionalTimestamp(record.policy_fresh_until, "policy_fresh_until"),
    offline_valid_until: readOptionalTimestamp(record.offline_valid_until, "offline_valid_until"),
    entitlements: readEntitlementEntries(record),
    over_limit: readOverLimitList(overLimitSource),
    version:
      record.version === null || record.version === undefined
        ? null
        : readVersion(record.version, "version"),
    updated_at: readOptionalTimestamp(record.updated_at, "updated_at"),
  };
}

export function decodeProviderEntitlementProjection(value: unknown): ProviderEntitlementProjection {
  const record = objectValue(value, "provider_entitlement");
  return {
    projection_id: readString(record.projection_id, "projection_id", 64),
    org_id: readString(record.org_id, "org_id", 64),
    provider: readString(record.provider, "provider", 96),
    status: readEnum(record.status, PROVIDER_PROJECTION_STATUSES, "status"),
    observed_at: readTimestamp(record.observed_at, "observed_at"),
    capability_class: readString(record.capability_class, "capability_class", 96),
  };
}

export function decodeBillingPortalSession(value: unknown): BillingPortalSession {
  const record = objectValue(value, "portal_session");
  const rawUrl = readOptionalString(record.portal_url, "portal_url", 2048);
  return {
    // A non-allowlisted or non-HTTPS portal URL is not offered as a link. The
    // server is authoritative; this keeps a bad value from becoming a
    // navigable surface.
    portal_url: rawUrl && isSafePortalUrl(rawUrl) ? rawUrl : null,
    expires_at: readOptionalTimestamp(record.expires_at, "expires_at"),
    reason: readOptionalString(record.reason, "reason", MAX_REASON_LENGTH),
  };
}

export function isSafePortalUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.hostname.length > 0 && url.username === "";
  } catch {
    return false;
  }
}

export function decodePlanChangePreview(value: unknown): PlanChangePreview {
  const record = objectValue(value, "plan_change_preview");
  return {
    direction: readNullableEnum(record.direction, PLAN_CHANGE_DIRECTIONS, "direction") ?? "unknown",
    current_plan_key: readOptionalString(record.current_plan_key, "current_plan_key", 96),
    target_plan_key: readString(record.target_plan_key, "target_plan_key", 96),
    over_limit: readOverLimitList(record.over_limit),
    deletes_data: false,
    blocks_new_work: record.blocks_new_work !== false,
    reason: readOptionalString(record.reason, "reason", MAX_REASON_LENGTH),
  };
}

export function decodePlanChangeResult(value: unknown): PlanChangeResult {
  const record = objectValue(value, "plan_change");
  return {
    accepted: record.accepted === true,
    subscription:
      record.subscription === null || record.subscription === undefined
        ? null
        : decodeSubscription(record.subscription),
    over_limit: readOverLimitList(record.over_limit),
    reason: readOptionalString(record.reason, "reason", MAX_REASON_LENGTH),
  };
}

export function decodeCancelResult(value: unknown): CancelRequestResult {
  const record = objectValue(value, "cancel");
  return {
    accepted: record.accepted === true,
    subscription:
      record.subscription === null || record.subscription === undefined
        ? null
        : decodeSubscription(record.subscription),
    reason: readOptionalString(record.reason, "reason", MAX_REASON_LENGTH),
  };
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

interface RequestOptions extends Omit<RequestInit, "body" | "method"> {
  method?: string;
  body?: unknown;
  idempotencyKey?: string;
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

async function requestJson<T>(
  path: string,
  options: RequestOptions,
  decode: (value: unknown) => T,
): Promise<T> {
  const method = (options.method ?? "GET").toUpperCase();
  const headers = new Headers(options.headers);
  headers.set("Accept", "application/json");
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  if (options.idempotencyKey) headers.set("Idempotency-Key", options.idempotencyKey);
  if (!isSafeMethod(method)) {
    const csrf = readCookie("lumi_csrf");
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  const { body, idempotencyKey: _key, ...requestInit } = options;
  const init: RequestInit = {
    ...requestInit,
    method,
    headers,
    credentials: "include",
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  };
  const retrySafe = isSafeMethod(method) || options.idempotencyKey !== undefined;

  let response: Response;
  try {
    response = await fetch(path, init);
  } catch (cause) {
    throw makeTransportError(cause, options.signal ?? undefined, { retryable: retrySafe });
  }

  const headerRequestId = normalizeRequestId(response.headers.get("X-Request-ID"));
  let text: string;
  try {
    text = await response.text();
  } catch (cause) {
    throw makeTransportError(cause, options.signal ?? undefined, {
      requestId: headerRequestId,
      status: response.status,
      retryable: response.status >= 500 || response.status === 429,
    });
  }

  let payload: unknown;
  let validJson = text.length > 0;
  if (validJson) {
    try {
      payload = JSON.parse(text) as unknown;
    } catch {
      validJson = false;
    }
  }
  if (!response.ok) {
    throw apiErrorFromEnvelope(
      response.status,
      validJson ? payload : undefined,
      headerRequestId,
      isRetryableStatus(response.status, readApiErrorCode(payload), retrySafe),
    );
  }
  if (response.status === 204) {
    throw makeInvalidResponseError({ requestId: headerRequestId, status: response.status });
  }
  if (!validJson) {
    throw makeInvalidResponseError({ requestId: headerRequestId, status: response.status });
  }
  try {
    return decode(payload);
  } catch (cause) {
    if (cause instanceof BillingContractError) {
      throw makeInvalidResponseError({ requestId: headerRequestId, status: response.status });
    }
    throw cause;
  }
}

function normalizeRequestId(value: string | null): string | undefined {
  if (value === null) return undefined;
  const normalized = value.trim();
  return normalized.length > 0 && normalized.length <= 160 ? normalized : undefined;
}

function readApiErrorCode(payload: unknown): string | undefined {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return undefined;
  const error = (payload as Record<string, unknown>).error;
  if (typeof error !== "object" || error === null || Array.isArray(error)) return undefined;
  const code = (error as Record<string, unknown>).code;
  return typeof code === "string" ? code : undefined;
}

function orgPath(orgId: string, suffix: string): string {
  return `/api/v1/orgs/${encodeURIComponent(orgId)}${suffix}`;
}

function unwrap<T>(value: T | Record<string, unknown>, field: string): unknown {
  if (typeof value === "object" && value !== null && field in (value as Record<string, unknown>)) {
    return (value as Record<string, unknown>)[field];
  }
  return value;
}

/**
 * The default client bound to the frozen P06 routes.
 *
 * `previewPlanChange` is deliberately absent: the gate publishes no preview
 * route and rejects unknown request fields, so a guessed request body would be
 * rejected server-side. The panel treats its absence as "no direct downgrade
 * submit" rather than inventing a wire contract.
 */
export function defaultBillingApi(): BillingApi {
  return {
    getSubscription: (orgId, signal) =>
      requestJson(orgPath(orgId, "/billing/subscription"), signal ? { signal } : {}, (payload) =>
        decodeSubscription(unwrap(payload, "subscription")),
      ),
    getEntitlements: (orgId, signal) =>
      requestJson(orgPath(orgId, "/entitlements"), signal ? { signal } : {}, (payload) =>
        decodeEntitlementProjection(unwrap(payload, "entitlements")),
      ),
    getProviderEntitlement: (orgId, signal) =>
      requestJson(orgPath(orgId, "/entitlements/provider"), signal ? { signal } : {}, (payload) =>
        decodeProviderEntitlementProjection(unwrap(payload, "provider_entitlement")),
      ),
    createPortalSession: (orgId, idempotencyKey, signal) =>
      requestJson(
        orgPath(orgId, "/billing/portal-session"),
        { method: "POST", body: {}, idempotencyKey, ...(signal ? { signal } : {}) },
        (payload) => decodeBillingPortalSession(unwrap(payload, "portal_session")),
      ),
    requestPlanChange: (orgId, input, idempotencyKey, signal) =>
      requestJson(
        orgPath(orgId, "/billing/change"),
        {
          method: "POST",
          body: { plan_key: input.plan_key, version: input.version },
          idempotencyKey,
          ...(signal ? { signal } : {}),
        },
        (payload) => decodePlanChangeResult(unwrap(payload, "plan_change")),
      ),
    requestCancellation: (orgId, input, idempotencyKey, signal) =>
      requestJson(
        orgPath(orgId, "/billing/cancel"),
        {
          method: "POST",
          body: { version: input.version },
          idempotencyKey,
          ...(signal ? { signal } : {}),
        },
        (payload) => decodeCancelResult(unwrap(payload, "cancel")),
      ),
  };
}
