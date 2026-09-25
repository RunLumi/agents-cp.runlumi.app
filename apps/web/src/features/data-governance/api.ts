/**
 * P06 data-governance, export, and deletion client.
 *
 * Built against the IMPLEMENTED backend (`apps/api/src/routes/data_governance.rs`,
 * contract gate `p06-cg-v1`) and the frozen fixture
 * `docs/implementation/fixtures/p06-contracts-v1.json` (`data_policy`,
 * `jobs`, `negative_fixtures.legal_hold`, `negative_fixtures.personal_export`).
 *
 * Three deliberate rules shape this module:
 *
 * 1. Every decoder is an ALLOWLIST. It copies named fields out of the wire
 *    object and never spreads it, so an object key, a grant token, or a provider
 *    reference that the server chooses to add cannot reach component state. The
 *    export projection is asserted to carry no `object_key`, no bucket name, and
 *    no absolute URL, matching the backend test of the same name.
 * 2. The browser never invents a download link. The server publishes a
 *    Worker-mediated path; this module refuses an absolute or off-origin value
 *    and always re-authorizes through the download route. There is no permanent
 *    URL to cache, and no code path stores a grant token.
 * 3. The transport is feature-local because `@/lib/api.ts` is outside this
 *    packet's write surface. It reuses `@/lib/errors` for every failure path, so
 *    `presentApiError` still owns the shared presentation.
 */

import { apiErrorFromEnvelope, makeInvalidResponseError, makeTransportError } from "@/lib/errors";

// ---------------------------------------------------------------------------
// Frozen vocabulary
// ---------------------------------------------------------------------------

/** `LoggingMode`. `metadata_only` is the frozen default. */
export const LOGGING_MODES = ["metadata_only", "redacted_content", "full_content"] as const;
export type LoggingMode = (typeof LOGGING_MODES)[number];

/**
 * The modes a browser caller may persist.
 *
 * The backend refuses to store `full_content` on the policy surface: it is an
 * audited, time-bounded diagnostic grant, and the policy row has no window
 * column. The panel therefore renders it as described-but-unselectable rather
 * than offering a control the server always rejects.
 */
export const PERSISTABLE_LOGGING_MODES = ["metadata_only", "redacted_content"] as const;
export type PersistableLoggingMode = (typeof PERSISTABLE_LOGGING_MODES)[number];

export const BACKUP_LIFECYCLES = ["platform_35_day_expiry", "platform_no_backup"] as const;
export type BackupLifecycle = (typeof BACKUP_LIFECYCLES)[number];

export const PROVIDER_RETENTION_DISCLOSURES = ["external_policy", "linked_policy"] as const;
export type ProviderRetentionDisclosure = (typeof PROVIDER_RETENTION_DISCLOSURES)[number];

/** The eight frozen export categories, in the gate's declaration order. */
export const EXPORT_CATEGORIES = [
  "identity",
  "organization",
  "devices",
  "runs_metadata",
  "usage_billing",
  "audit_redacted",
  "notifications",
  "data_governance",
] as const;
export type ExportCategory = (typeof EXPORT_CATEGORIES)[number];

/**
 * Categories a personal (user) export may request. Organization, device, run,
 * billing, and audit data belong to a tenant, not to an individual account, so
 * a personal request naming one is refused server-side.
 */
export const PERSONAL_EXPORT_CATEGORIES = ["identity", "notifications", "data_governance"] as const;
export type PersonalExportCategory = (typeof PERSONAL_EXPORT_CATEGORIES)[number];

/** `MAX_EXPORT_CATEGORIES` is 8, so the whole set is requestable at once. */
export const MAX_EXPORT_CATEGORIES = 8;

export const EXPORT_FORMATS = ["json", "jsonl", "csv"] as const;
export type ExportFormat = (typeof EXPORT_FORMATS)[number];

export const EXPORT_STATES = [
  "requested",
  "queued",
  "collecting",
  "packaging",
  "verifying",
  "ready",
  "expired",
  "retry_wait",
  "failed",
  "cancelled",
] as const;
export type ExportState = (typeof EXPORT_STATES)[number];

export const DELETION_STATES = [
  "requested",
  "awaiting_grace",
  "queued",
  "planning",
  "deleting",
  "verifying",
  "completed",
  "retry_wait",
  "needs_attention",
  "cancelled",
] as const;
export type DeletionState = (typeof DELETION_STATES)[number];

export const DELETION_STEP_STATES = [
  "pending",
  "running",
  "retry_wait",
  "needs_attention",
  "succeeded",
  "failed",
  "skipped",
] as const;
export type DeletionStepState = (typeof DELETION_STEP_STATES)[number];

/** Why a step was skipped. A skipped step always carries one of these. */
export const DELETION_SKIP_REASONS = [
  "deletion_legal_hold",
  "retained_legal_only",
  "deletion_not_lumi_owned",
  "deletion_reference_system_absent",
] as const;
export type DeletionSkipReason = (typeof DELETION_SKIP_REASONS)[number];

/** Closed set of reference stores a deletion step can point at. */
export const REFERENCE_KINDS = [
  "database_row",
  "r2_object",
  "local_device_data",
  "upstream_provider_data",
] as const;
export type ReferenceKind = (typeof REFERENCE_KINDS)[number];

/** The typed confirmation phrases the server compares verbatim. */
export const EXPORT_CONFIRMATION_PHRASE = "EXPORT MY DATA";
export const DELETION_CONFIRMATION_PHRASE = "DELETE MY ACCOUNT";

/**
 * Reauthentication purpose consumed by a personal data action. The backend
 * consumes the existing P02 `org_lifecycle` grant; adding a dedicated
 * `account_data` purpose is a P02 change the coordinator owns.
 */
export const REAUTH_PURPOSE = "org_lifecycle";

/** Bounded grant lifetime the backend mints for one download. */
export const DOWNLOAD_GRANT_TTL_SECONDS = 900;

/** Bounded personal-deletion grace window, in seconds (7 days). */
export const PERSONAL_DELETION_GRACE_SECONDS = 604_800;

/** Bounds the frozen `default_export_expiry_seconds` policy field. */
export const MIN_EXPORT_EXPIRY_SECONDS = 300;
export const MAX_EXPORT_EXPIRY_SECONDS = 604_800;

/** The frozen baseline: an export artifact is short-lived by default. */
export const DEFAULT_EXPORT_EXPIRY_SECONDS = 86_400;

/** Stable `DataClass` key shape, matching the registry's bounded identifier. */
const DATA_CLASS_PATTERN = /^[a-z][a-z0-9_]{0,127}$/;
/** Stable machine-readable reason code. */
const REASON_CODE_PATTERN = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/;

// ---------------------------------------------------------------------------
// Wire projections
// ---------------------------------------------------------------------------

/**
 * `DataGovernancePolicy` as `GET/PATCH /orgs/{org_id}/data-policy` returns it.
 *
 * `persisted: false` is the frozen baseline shape for an organization that has
 * never changed a policy: the baseline still reads back at `version: 1`, so the
 * first PATCH works without a create call.
 */
export interface DataGovernancePolicy {
  policy_id: string | null;
  persisted: boolean;
  org_id: string;
  project_id: string | null;
  logging_mode: LoggingMode;
  /** Data class -> window in seconds. Absent keys keep the frozen baseline. */
  class_retention_overrides: Record<string, number>;
  legal_hold: boolean;
  legal_hold_reason: string | null;
  legal_hold_placed_at: string | null;
  legal_hold_released_at: string | null;
  legal_hold_released_by: string | null;
  backup_lifecycle: BackupLifecycle;
  provider_retention_disclosure: ProviderRetentionDisclosure;
  provider_retention_url: string | null;
  default_export_expiry_seconds: number;
  version: number;
  created_at: string;
  updated_at: string;
}

/** A PATCH body. Only the fields the operator actually changed are sent. */
export interface PolicyPatch {
  version: number;
  logging_mode?: PersistableLoggingMode;
  class_retention_overrides?: Record<string, number>;
  legal_hold?: boolean;
  legal_hold_reason?: string;
  legal_hold_released_by?: string;
  backup_lifecycle?: BackupLifecycle;
  provider_retention_disclosure?: ProviderRetentionDisclosure;
  provider_retention_url?: string;
  default_export_expiry_seconds?: number;
}

/** The private export artifact metadata, without any object handle. */
export interface ExportArtifact {
  content_type: string;
  size_bytes: number | null;
  expires_at: string;
  /** Worker-mediated path. Never an object URL, never a public link. */
  download_path: string;
}

export interface ExportJob {
  id: string;
  org_id: string | null;
  scope_type: "organization" | "user";
  scope_id: string | null;
  categories: ExportCategory[];
  /** Categories the server returned that this build does not recognize. */
  unrecognized_categories: string[];
  format: ExportFormat;
  snapshot_cutoff_at: string;
  state: ExportState;
  state_version: number;
  attempt: number;
  next_attempt_at: string | null;
  requested_by: string;
  requested_at: string;
  ready_at: string | null;
  finished_at: string | null;
  failure_code: string | null;
  /** Server verdict: `ready` and a live artifact. The UI still re-checks. */
  downloadable: boolean;
  artifact: ExportArtifact | null;
  version: number;
  updated_at: string;
  disclosures: string[];
}

export interface DeletionStep {
  id: string;
  data_class: string;
  /** `null` when the server published a kind this build does not recognize. */
  reference_kind: ReferenceKind | null;
  /** Bounded opaque reference. Never rendered as a link. */
  object_reference: string;
  state: DeletionStepState;
  attempt: number;
  failure_code: string | null;
  skip_reason: DeletionSkipReason | null;
  /** The raw reason when this build does not recognize it. */
  unmapped_skip_reason: string | null;
  completed_at: string | null;
}

export interface DeletionCertificate {
  id: string;
  scope_type: string;
  scope_id: string;
  /** Per-class state counts plus the `reference_coverage` block. */
  class_results: Record<string, unknown>;
  retained_legal_classes: string[];
  completed_at: string;
  expires_at: string;
}

export interface DeletionJob {
  id: string;
  org_id: string | null;
  target_type: "organization" | "user";
  target_id: string | null;
  state: DeletionState;
  state_version: number;
  attempt: number;
  next_attempt_at: string | null;
  grace_expires_at: string | null;
  cutoff_at: string | null;
  /** True once new work is fenced for this scope. */
  fenced: boolean;
  legal_hold: boolean;
  failure_code: string | null;
  certificate_id: string | null;
  /** Server verdict that only `needs_attention` may leave, by explicit resume. */
  resumable: boolean;
  requested_by: string;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  version: number;
  disclosures: string[];
  /** Always present: the list route returns an empty array, the detail route the plan. */
  steps: DeletionStep[];
  certificate: DeletionCertificate | null;
}

/** `GET /me/data/deletion` answers `none` when no job exists. */
export interface PersonalDeletionStatus {
  state: "none";
  grace_expires_at: null;
  disclosures: string[];
}

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
  has_more: boolean;
}

export interface ListExportsQuery {
  limit?: number;
  cursor?: string;
}

/** Proof that a short-lived grant was minted for one download. */
export interface DownloadReceipt {
  export_id: string;
  grant_id: string | null;
  /** The grant's own expiry, which is shorter than the artifact's. */
  grant_expires_at: string | null;
  content_type: string | null;
  byte_length: number | null;
  filename: string;
}

export interface ReauthGrant {
  grant_id: string;
  token: string;
  expires_at: string;
}

export interface PersonalExportRequest {
  categories: PersonalExportCategory[];
  format?: ExportFormat;
  confirmation: string;
  reauth_grant_id: string;
  reauth_token: string;
}

export interface PersonalDeletionRequest {
  confirmation: string;
  reauth_grant_id: string;
  reauth_token: string;
}

export interface DataGovernanceApi {
  getPolicy: (orgId: string, signal?: AbortSignal) => Promise<DataGovernancePolicy>;
  updatePolicy: (
    orgId: string,
    patch: PolicyPatch,
    idempotencyKey: string,
    signal?: AbortSignal,
  ) => Promise<DataGovernancePolicy>;

  listExports: (
    orgId: string,
    query?: ListExportsQuery,
    signal?: AbortSignal,
  ) => Promise<Page<ExportJob>>;
  createExport: (
    orgId: string,
    input: { categories: ExportCategory[]; format?: ExportFormat },
    idempotencyKey: string,
    signal?: AbortSignal,
  ) => Promise<ExportJob>;
  getExport: (orgId: string, exportId: string, signal?: AbortSignal) => Promise<ExportJob>;

  listDeletions: (
    orgId: string,
    query?: ListExportsQuery,
    signal?: AbortSignal,
  ) => Promise<Page<DeletionJob>>;
  getDeletion: (orgId: string, deletionId: string, signal?: AbortSignal) => Promise<DeletionJob>;
  resumeDeletion: (
    orgId: string,
    deletionId: string,
    version: number,
    idempotencyKey: string,
    signal?: AbortSignal,
  ) => Promise<DeletionJob>;

  listPersonalExports: (query?: ListExportsQuery, signal?: AbortSignal) => Promise<Page<ExportJob>>;
  createPersonalExport: (
    input: PersonalExportRequest,
    idempotencyKey: string,
    signal?: AbortSignal,
  ) => Promise<ExportJob>;
  getPersonalDeletion: (signal?: AbortSignal) => Promise<DeletionJob | PersonalDeletionStatus>;
  createPersonalDeletion: (
    input: PersonalDeletionRequest,
    idempotencyKey: string,
    signal?: AbortSignal,
  ) => Promise<DeletionJob>;
  cancelPersonalDeletion: (
    input: { reauth_grant_id: string; reauth_token: string },
    idempotencyKey: string,
    signal?: AbortSignal,
  ) => Promise<DeletionJob>;
}

// ---------------------------------------------------------------------------
// Contract error
// ---------------------------------------------------------------------------

export class DataGovernanceContractError extends Error {
  readonly field: string;

  constructor(field: string) {
    super(`The data-governance response field ${field} did not match the expected contract.`);
    this.name = "DataGovernanceContractError";
    this.field = field;
  }
}

// ---------------------------------------------------------------------------
// Decoders
// ---------------------------------------------------------------------------

function objectValue(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new DataGovernanceContractError(field);
  }
  return value as Record<string, unknown>;
}

function readString(value: unknown, field: string, max = 256): string {
  if (typeof value !== "string") throw new DataGovernanceContractError(field);
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > max)
    throw new DataGovernanceContractError(field);
  return normalized;
}

function readOptionalString(value: unknown, field: string, max = 256): string | null {
  if (value === null || value === undefined) return null;
  return readString(value, field, max);
}

function readTimestamp(value: unknown, field: string): string {
  const raw = readString(value, field, 64);
  if (Number.isNaN(Date.parse(raw))) throw new DataGovernanceContractError(field);
  return raw;
}

function readOptionalTimestamp(value: unknown, field: string): string | null {
  if (value === null || value === undefined) return null;
  return readTimestamp(value, field);
}

function readVersion(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw new DataGovernanceContractError(field);
  }
  return value;
}

function readCount(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new DataGovernanceContractError(field);
  }
  return value;
}

function readEnum<const T extends readonly string[]>(
  value: unknown,
  values: T,
  field: string,
): T[number] {
  if (typeof value !== "string" || !(values as readonly string[]).includes(value)) {
    throw new DataGovernanceContractError(field);
  }
  return value as T[number];
}

/**
 * Lenient enum read: a value outside the set decodes to `null` instead of
 * failing the whole response.
 *
 * This is the fail-closed direction for honesty fields. A deletion step whose
 * `reference_kind` or `skip_reason` this build does not recognize must still
 * render — as "ownership not established" and as an unparsed reason code — never
 * as a step Lumi claims it deleted.
 */
function readKnownEnum<const T extends readonly string[]>(
  value: unknown,
  values: T,
): T[number] | null {
  return typeof value === "string" && (values as readonly string[]).includes(value)
    ? (value as T[number])
    : null;
}

function readBoundedSeconds(value: unknown, field: string, max: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > max) {
    throw new DataGovernanceContractError(field);
  }
  return value;
}

/** A stable reason code, or `null`. Server prose never reaches this layer. */
export function readReasonCode(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim();
  return normalized.length > 0 && normalized.length <= 96 && REASON_CODE_PATTERN.test(normalized)
    ? normalized
    : null;
}

function readDisclosures(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const seen = new Set<string>();
  for (const item of value) {
    if (typeof item !== "string") continue;
    const normalized = item.trim();
    // Bounded: a disclosure is a sentence, never a document.
    if (normalized.length === 0 || normalized.length > 400) continue;
    seen.add(normalized);
  }
  return [...seen];
}

function readRetentionOverrides(value: unknown, field: string): Record<string, number> {
  const record = objectValue(value, field);
  const decoded: Record<string, number> = {};
  for (const [key, raw] of Object.entries(record)) {
    if (!DATA_CLASS_PATTERN.test(key)) throw new DataGovernanceContractError(`${field}.${key}`);
    if (typeof raw !== "number" || !Number.isSafeInteger(raw) || raw < 0) {
      throw new DataGovernanceContractError(`${field}.${key}`);
    }
    decoded[key] = raw;
  }
  return decoded;
}

export function decodeDataGovernancePolicy(value: unknown): DataGovernancePolicy {
  const record = objectValue(value, "data_policy");
  return {
    policy_id: readOptionalString(record.policy_id, "policy_id", 64),
    persisted: record.persisted === true,
    org_id: readString(record.org_id, "org_id", 64),
    project_id: readOptionalString(record.project_id, "project_id", 64),
    logging_mode: readEnum(record.logging_mode, LOGGING_MODES, "logging_mode"),
    class_retention_overrides: readRetentionOverrides(
      record.class_retention_overrides,
      "class_retention_overrides",
    ),
    legal_hold: record.legal_hold === true,
    legal_hold_reason: readOptionalString(record.legal_hold_reason, "legal_hold_reason", 2_000),
    legal_hold_placed_at: readOptionalTimestamp(
      record.legal_hold_placed_at,
      "legal_hold_placed_at",
    ),
    legal_hold_released_at: readOptionalTimestamp(
      record.legal_hold_released_at,
      "legal_hold_released_at",
    ),
    legal_hold_released_by: readOptionalString(
      record.legal_hold_released_by,
      "legal_hold_released_by",
      64,
    ),
    backup_lifecycle: readEnum(record.backup_lifecycle, BACKUP_LIFECYCLES, "backup_lifecycle"),
    provider_retention_disclosure: readEnum(
      record.provider_retention_disclosure,
      PROVIDER_RETENTION_DISCLOSURES,
      "provider_retention_disclosure",
    ),
    provider_retention_url: readOptionalString(
      record.provider_retention_url,
      "provider_retention_url",
      2_048,
    ),
    default_export_expiry_seconds: readBoundedSeconds(
      record.default_export_expiry_seconds,
      "default_export_expiry_seconds",
      MAX_EXPORT_EXPIRY_SECONDS,
    ),
    version: readVersion(record.version, "version"),
    created_at: readString(record.created_at, "created_at", 64),
    updated_at: readString(record.updated_at, "updated_at", 64),
  };
}

/**
 * A download path is only usable when it is a same-origin `/api/v1/` path.
 * An absolute URL, a protocol-relative URL, or a path outside the API namespace
 * is refused, so a server response can never become an off-site link here.
 */
export function isSafeDownloadPath(value: string): boolean {
  return (
    value.startsWith("/api/v1/") &&
    !value.includes("..") &&
    !value.includes("//") &&
    !value.includes(":")
  );
}

function readArtifact(value: unknown, field: string): ExportArtifact | null {
  if (value === null || value === undefined) return null;
  const record = objectValue(value, field);
  const contentType = readString(record.content_type, `${field}.content_type`, 128);
  const downloadPath = readString(record.download_path, `${field}.download_path`, 512);
  if (!isSafeDownloadPath(downloadPath))
    throw new DataGovernanceContractError(`${field}.download_path`);
  const size = record.size_bytes;
  return {
    content_type: contentType,
    size_bytes: typeof size === "number" && Number.isSafeInteger(size) && size >= 0 ? size : null,
    expires_at: readTimestamp(record.expires_at, `${field}.expires_at`),
    download_path: downloadPath,
  };
}

function readCategories(
  value: unknown,
  field: string,
): {
  categories: ExportCategory[];
  unrecognized: string[];
} {
  if (!Array.isArray(value)) throw new DataGovernanceContractError(field);
  const known = new Set<ExportCategory>();
  const unrecognized: string[] = [];
  for (const item of value) {
    if (typeof item !== "string") continue;
    if ((EXPORT_CATEGORIES as readonly string[]).includes(item)) {
      known.add(item as ExportCategory);
    } else {
      unrecognized.push(item.slice(0, 64));
    }
  }
  // Canonical order: the manifest is a sorted set, so present it sorted.
  return { categories: EXPORT_CATEGORIES.filter((category) => known.has(category)), unrecognized };
}

export function decodeExportJob(value: unknown): ExportJob {
  const record = objectValue(value, "export_job");
  const { categories, unrecognized } = readCategories(record.categories, "categories");
  return {
    id: readString(record.id, "id", 64),
    org_id: readOptionalString(record.org_id, "org_id", 64),
    scope_type: readEnum(record.scope_type, ["organization", "user"] as const, "scope_type"),
    scope_id: readOptionalString(record.scope_id, "scope_id", 64),
    categories,
    unrecognized_categories: unrecognized,
    format: readEnum(record.format, EXPORT_FORMATS, "format"),
    snapshot_cutoff_at: readTimestamp(record.snapshot_cutoff_at, "snapshot_cutoff_at"),
    state: readEnum(record.state, EXPORT_STATES, "state"),
    state_version: readVersion(record.state_version, "state_version"),
    attempt: readCount(record.attempt, "attempt"),
    next_attempt_at: readOptionalTimestamp(record.next_attempt_at, "next_attempt_at"),
    requested_by: readString(record.requested_by, "requested_by", 64),
    requested_at: readTimestamp(record.requested_at, "requested_at"),
    ready_at: readOptionalTimestamp(record.ready_at, "ready_at"),
    finished_at: readOptionalTimestamp(record.finished_at, "finished_at"),
    failure_code: readReasonCode(record.failure_code),
    downloadable: record.downloadable === true,
    artifact: readArtifact(record.artifact, "artifact"),
    version: readVersion(record.version, "version"),
    updated_at: readString(record.updated_at, "updated_at", 64),
    disclosures: readDisclosures(record.disclosures),
  };
}

function readDeletionStep(value: unknown, field: string): DeletionStep {
  const record = objectValue(value, field);
  const rawSkip = readReasonCode(record.skip_reason);
  const skipReason = readKnownEnum(record.skip_reason, DELETION_SKIP_REASONS);
  return {
    id: readString(record.id, `${field}.id`, 64),
    data_class: readString(record.data_class, `${field}.data_class`, 128),
    /** `null` when the server published a kind this build does not recognize. */
    reference_kind: readKnownEnum(record.reference_kind, REFERENCE_KINDS),
    // A reference is an opaque handle. It is bounded and never a URL: a
    // scheme-bearing or root-relative value would be a content handle rather
    // than an opaque reference, so it is dropped rather than rendered.
    object_reference: readOpaqueReference(record.object_reference, `${field}.object_reference`),
    state: readEnum(record.state, DELETION_STEP_STATES, `${field}.state`),
    attempt: readCount(record.attempt, `${field}.attempt`),
    failure_code: readReasonCode(record.failure_code),
    skip_reason: skipReason,
    /** The raw reason when this build does not recognize it. */
    unmapped_skip_reason: rawSkip !== null && skipReason === null ? rawSkip : null,
    completed_at: readOptionalTimestamp(record.completed_at, `${field}.completed_at`),
  };
}

/** Reject anything that is a URL or a root-relative content handle. */
function readOpaqueReference(value: unknown, field: string): string {
  const raw = readString(value, field, 512);
  if (
    raw.startsWith("/") ||
    /^(?:https?|data|file|blob|javascript):/i.test(raw) ||
    raw.includes("://")
  ) {
    throw new DataGovernanceContractError(field);
  }
  return raw;
}

function readCertificate(value: unknown, field: string): DeletionCertificate | null {
  if (value === null || value === undefined) return null;
  const record = objectValue(value, field);
  const results = record.class_results;
  const retained = Array.isArray(record.retained_legal_classes)
    ? record.retained_legal_classes.filter(
        (item): item is string => typeof item === "string" && item.length <= 128,
      )
    : [];
  return {
    id: readString(record.id, `${field}.id`, 64),
    scope_type: readString(record.scope_type, `${field}.scope_type`, 32),
    scope_id: readString(record.scope_id, `${field}.scope_id`, 64),
    class_results:
      typeof results === "object" && results !== null && !Array.isArray(results)
        ? (results as Record<string, unknown>)
        : {},
    retained_legal_classes: retained,
    completed_at: readTimestamp(record.completed_at, `${field}.completed_at`),
    expires_at: readTimestamp(record.expires_at, `${field}.expires_at`),
  };
}

export function decodeDeletionJob(value: unknown): DeletionJob {
  const record = objectValue(value, "deletion_job");
  return {
    id: readString(record.id, "id", 64),
    org_id: readOptionalString(record.org_id, "org_id", 64),
    target_type: readEnum(record.target_type, ["organization", "user"] as const, "target_type"),
    target_id: readOptionalString(record.target_id, "target_id", 64),
    state: readEnum(record.state, DELETION_STATES, "state"),
    state_version: readVersion(record.state_version, "state_version"),
    attempt: readCount(record.attempt, "attempt"),
    next_attempt_at: readOptionalTimestamp(record.next_attempt_at, "next_attempt_at"),
    grace_expires_at: readOptionalTimestamp(record.grace_expires_at, "grace_expires_at"),
    cutoff_at: readOptionalTimestamp(record.cutoff_at, "cutoff_at"),
    fenced: record.fenced === true,
    legal_hold: record.legal_hold === true,
    failure_code: readReasonCode(record.failure_code),
    certificate_id: readOptionalString(record.certificate_id, "certificate_id", 64),
    resumable: record.resumable === true,
    requested_by: readString(record.requested_by, "requested_by", 64),
    created_at: readString(record.created_at, "created_at", 64),
    updated_at: readString(record.updated_at, "updated_at", 64),
    completed_at: readOptionalTimestamp(record.completed_at, "completed_at"),
    version: readVersion(record.version, "version"),
    disclosures: readDisclosures(record.disclosures),
    steps: Array.isArray(record.steps)
      ? record.steps.map((step, index) => readDeletionStep(step, `steps[${index}]`))
      : [],
    certificate: readCertificate(record.certificate, "certificate"),
  };
}

export function decodePersonalDeletionStatus(value: unknown): PersonalDeletionStatus {
  const record = objectValue(value, "personal_deletion");
  const state = record.state;
  if (state !== "none") {
    throw new DataGovernanceContractError("state");
  }
  return {
    state: "none",
    grace_expires_at: null,
    disclosures: readDisclosures(record.disclosures),
  };
}

export function decodePage<T>(
  value: unknown,
  decodeItem: (item: unknown, index: number) => T,
): Page<T> {
  const record = objectValue(value, "page");
  if (!Array.isArray(record.items)) throw new DataGovernanceContractError("items");
  return {
    items: record.items.map((item, index) => decodeItem(item, index)),
    next_cursor: readOptionalString(record.next_cursor, "next_cursor", 512),
    has_more: record.has_more === true,
  };
}

export function decodeReauthGrant(value: unknown): ReauthGrant {
  const record = objectValue(value, "reauth");
  return {
    grant_id: readString(record.grant_id, "grant_id", 64),
    token: readString(record.token, "token", 256),
    expires_at: readTimestamp(record.expires_at, "expires_at"),
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
  const raw: unknown = document.cookie;
  if (typeof raw !== "string") return undefined;
  const value = raw
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`))
    ?.slice(name.length + 1);
  return value && value.length <= 256 ? value : undefined;
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
  if (response.status === 204 || !validJson) {
    throw makeInvalidResponseError({ requestId: headerRequestId, status: response.status });
  }
  try {
    return decode(payload);
  } catch (cause) {
    if (cause instanceof DataGovernanceContractError) {
      throw makeInvalidResponseError({ requestId: headerRequestId, status: response.status });
    }
    throw cause;
  }
}

function orgPath(orgId: string, suffix: string): string {
  return `/api/v1/orgs/${encodeURIComponent(orgId)}${suffix}`;
}

function pageQuery(query: ListExportsQuery | undefined): string {
  const parts: string[] = [];
  const limit = boundedLimit(query);
  if (limit !== undefined) parts.push(`limit=${encodeURIComponent(String(limit))}`);
  if (query?.cursor) parts.push(`cursor=${encodeURIComponent(query.cursor)}`);
  return parts.length === 0 ? "" : `?${parts.join("&")}`;
}

function boundedLimit(query: ListExportsQuery | undefined): number | undefined {
  if (query?.limit === undefined) return undefined;
  return Math.min(100, Math.max(1, Math.trunc(query.limit)));
}

/**
 * Resolve the Worker-mediated download path for one export.
 *
 * The server publishes `download_path` with the job id resolved and the org
 * placeholder intact, so the panel resolves it against the scope it already
 * authorized. The locally built path is the fallback; either way the value has
 * already passed `isSafeDownloadPath` in the decoder.
 */
export function resolveDownloadPath(
  scope: { kind: "org"; orgId: string } | { kind: "me" },
  exportId: string,
  published: string | null,
): string {
  const fallback =
    scope.kind === "org"
      ? orgPath(scope.orgId, `/exports/${encodeURIComponent(exportId)}/download`)
      : `/api/v1/me/data/exports/${encodeURIComponent(exportId)}/download`;
  if (!published) return fallback;
  const resolved = scope.kind === "org" ? published.replace("{org_id}", scope.orgId) : published;
  return isSafeDownloadPath(resolved) ? resolved : fallback;
}

/** File extension the server will use for a content type. */
function filenameFor(
  exportId: string,
  contentType: string | null,
  disposition: string | null,
): string {
  const fromHeader = disposition?.match(/filename="([^"]{1,128})"/)?.[1];
  if (fromHeader && /^[A-Za-z0-9._-]{1,128}$/.test(fromHeader)) return fromHeader;
  const extension =
    contentType === "application/x-ndjson" ? "jsonl" : contentType === "text/csv" ? "csv" : "json";
  return `${exportId}.${extension}`;
}

interface DownloadOptions {
  path: string;
  exportId: string;
  grantToken?: string | undefined;
  signal?: AbortSignal | undefined;
}

/**
 * Mint (or reuse) a short-lived download grant and save the artifact.
 *
 * The request is a POST with a JSON body because both the re-authorization and
 * the grant minting happen server-side; the browser cannot express that with a
 * bare link. The response body is the artifact, so it is handed to the platform
 * as a blob and released through a one-shot object URL that is revoked as soon
 * as the save is triggered. The raw grant token is deliberately not returned,
 * stored, or displayed: only its id and expiry are, so the receipt is evidence
 * and not a capability.
 */
export async function downloadExportArtifact(options: DownloadOptions): Promise<DownloadReceipt> {
  const { path, exportId } = options;
  const headers = new Headers();
  headers.set("Accept", "application/octet-stream, application/json");
  headers.set("Content-Type", "application/json");
  const csrf = readCookie("lumi_csrf");
  if (csrf) headers.set("X-CSRF-Token", csrf);
  const init: RequestInit = {
    method: "POST",
    headers,
    credentials: "include",
    body: JSON.stringify(options.grantToken ? { grant_token: options.grantToken } : {}),
    ...(options.signal ? { signal: options.signal } : {}),
  };

  let response: Response;
  try {
    response = await fetch(path, init);
  } catch (cause) {
    throw makeTransportError(cause, options.signal, { retryable: true });
  }

  const requestId = normalizeRequestId(response.headers.get("X-Request-ID"));
  if (!response.ok) {
    let payload: unknown;
    try {
      payload = JSON.parse(await response.text());
    } catch {
      payload = undefined;
    }
    throw apiErrorFromEnvelope(
      response.status,
      payload,
      requestId,
      isRetryableStatus(response.status, readApiErrorCode(payload), true),
    );
  }

  const contentType = response.headers.get("Content-Type");
  const disposition = response.headers.get("Content-Disposition");
  const filename = filenameFor(exportId, contentType, disposition);
  let blob: Blob;
  try {
    blob = await response.blob();
  } catch (cause) {
    throw makeTransportError(cause, options.signal, {
      requestId,
      status: response.status,
      retryable: true,
    });
  }

  saveBlob(blob, filename);

  return {
    export_id: exportId,
    grant_id: readHeaderToken(response.headers.get("x-lumi-download-grant-id")),
    grant_expires_at: readHeaderToken(response.headers.get("x-lumi-download-grant-expires-at")),
    content_type: contentType,
    byte_length: blob.size,
    filename,
  };
}

/** A bounded response-header value, or `null` when the server sent none. */
function readHeaderToken(value: string | null): string | null {
  if (value === null) return null;
  const normalized = value.trim();
  return normalized.length > 0 && normalized.length <= 160 ? normalized : null;
}

/**
 * Hand a blob to the platform download flow with a plain anchor, then release
 * the object URL. No download library: the anchor element is the whole
 * mechanism, and the URL never outlives the click.
 */
function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noreferrer";
  anchor.hidden = true;
  document.body.append(anchor);
  try {
    anchor.click();
  } finally {
    anchor.remove();
    URL.revokeObjectURL(url);
  }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/** The default client bound to the implemented P06 routes. */
export function defaultDataGovernanceApi(): DataGovernanceApi {
  return {
    getPolicy: (orgId, signal) =>
      requestJson(
        orgPath(orgId, "/data-policy"),
        signal ? { signal } : {},
        decodeDataGovernancePolicy,
      ),

    updatePolicy: (orgId, patch, idempotencyKey, signal) =>
      requestJson(
        orgPath(orgId, "/data-policy"),
        { method: "PATCH", body: patch, idempotencyKey, ...(signal ? { signal } : {}) },
        decodeDataGovernancePolicy,
      ),

    listExports: (orgId, query, signal) =>
      requestJson(
        `${orgPath(orgId, "/exports")}${pageQuery(query)}`,
        signal ? { signal } : {},
        (payload) => decodePage(payload, decodeExportJob),
      ),

    createExport: (orgId, input, idempotencyKey, signal) =>
      requestJson(
        orgPath(orgId, "/exports"),
        {
          method: "POST",
          body: { categories: input.categories, format: input.format ?? "json" },
          idempotencyKey,
          ...(signal ? { signal } : {}),
        },
        decodeExportJob,
      ),

    getExport: (orgId, exportId, signal) =>
      requestJson(
        orgPath(orgId, `/exports/${encodeURIComponent(exportId)}`),
        signal ? { signal } : {},
        decodeExportJob,
      ),

    listDeletions: (orgId, query, signal) =>
      requestJson(
        `${orgPath(orgId, "/deletions")}${pageQuery(query)}`,
        signal ? { signal } : {},
        (payload) => decodePage(payload, decodeDeletionJob),
      ),

    getDeletion: (orgId, deletionId, signal) =>
      requestJson(
        orgPath(orgId, `/deletions/${encodeURIComponent(deletionId)}`),
        signal ? { signal } : {},
        decodeDeletionJob,
      ),

    resumeDeletion: (orgId, deletionId, version, idempotencyKey, signal) =>
      requestJson(
        orgPath(orgId, `/deletions/${encodeURIComponent(deletionId)}/resume`),
        { method: "POST", body: { version }, idempotencyKey, ...(signal ? { signal } : {}) },
        decodeDeletionJob,
      ),

    listPersonalExports: (query, signal) =>
      requestJson(
        `/api/v1/me/data/exports${pageQuery(query)}`,
        signal ? { signal } : {},
        (payload) => decodePage(payload, decodeExportJob),
      ),

    createPersonalExport: (input, idempotencyKey, signal) =>
      requestJson(
        "/api/v1/me/data/exports",
        {
          method: "POST",
          body: {
            categories: input.categories,
            format: input.format ?? "json",
            confirmation: input.confirmation,
            reauth_grant_id: input.reauth_grant_id,
            reauth_token: input.reauth_token,
          },
          idempotencyKey,
          ...(signal ? { signal } : {}),
        },
        decodeExportJob,
      ),

    getPersonalDeletion: (signal) =>
      requestJson("/api/v1/me/data/deletion", signal ? { signal } : {}, (payload) => {
        const record =
          typeof payload === "object" && payload !== null && !Array.isArray(payload)
            ? (payload as Record<string, unknown>)
            : {};
        return record.state === "none"
          ? decodePersonalDeletionStatus(record)
          : decodeDeletionJob(record);
      }),

    createPersonalDeletion: (input, idempotencyKey, signal) =>
      requestJson(
        "/api/v1/me/data/deletion",
        {
          method: "POST",
          body: {
            confirmation: input.confirmation,
            reauth_grant_id: input.reauth_grant_id,
            reauth_token: input.reauth_token,
          },
          idempotencyKey,
          ...(signal ? { signal } : {}),
        },
        decodeDeletionJob,
      ),

    cancelPersonalDeletion: (input, idempotencyKey, signal) =>
      requestJson(
        "/api/v1/me/data/deletion/cancel",
        {
          method: "POST",
          body: { reauth_grant_id: input.reauth_grant_id, reauth_token: input.reauth_token },
          idempotencyKey,
          ...(signal ? { signal } : {}),
        },
        decodeDeletionJob,
      ),
  };
}

/**
 * Mint a reauthentication grant for a personal data action.
 *
 * The grant is returned to the caller in memory only. It is consumed by the next
 * personal request and never persisted, logged, or placed in the URL.
 */
export async function mintReauthGrant(signal?: AbortSignal): Promise<ReauthGrant> {
  return requestJson(
    "/api/v1/account/reauth",
    {
      method: "POST",
      body: { purpose: REAUTH_PURPOSE },
      ...(signal ? { signal } : {}),
    },
    decodeReauthGrant,
  );
}
