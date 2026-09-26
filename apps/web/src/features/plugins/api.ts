/**
 * P07 plugin governance client — installed packages, catalog, org policy,
 * permission diff, and the block / pin / approve actions.
 *
 * Frozen contract: `docs/implementation/gates/P07-CG.md` §"Plugin governance
 * contract" and §"API contract" (contract version `p07-cg-v1`), implemented in
 * `apps/api/src/routes/plugins.rs`.
 *
 * The transport is imported from `@/features/identity/api` rather than copied a
 * third time: `features/webhooks/api.ts` owns the P06 transport and
 * `features/notifications/api.ts` reuses it, so this module follows the same
 * precedent for P07. CSRF, idempotency, and the error envelope are therefore
 * identical across every P07 surface.
 *
 * The install body requires `host_runtime_version` and `content_digest` — the
 * host agent's own facts, verified by the server before anything is recorded.
 * This client therefore takes both from the caller rather than inventing them:
 * a browser has no honest source for either, and sending a guess would turn an
 * integrity check into decoration.
 */

import { p07RequestJson } from "@/features/identity/api";

// ---------------------------------------------------------------------------
// Frozen vocabulary
// ---------------------------------------------------------------------------

/**
 * `PluginReviewState`. `quarantined` is a separate platform decision against a
 * `package@version` and arrives as its own flag, not as a review state, but it is
 * accepted here so a future projection that folds the two cannot silently drop a
 * row.
 */
export const PLUGIN_REVIEW_STATES = [
  "unreviewed",
  "approved",
  "pending_review",
  "blocked",
  "quarantined",
] as const;
export type PluginReviewState = (typeof PLUGIN_REVIEW_STATES)[number];

/** `PluginPolicy.publisher_mode`. */
export const PUBLISHER_MODES = ["official_only", "approved_publishers", "any"] as const;
export type PublisherMode = (typeof PUBLISHER_MODES)[number];

/** `PluginPolicy.update_mode`. */
export const UPDATE_MODES = ["managed", "direct"] as const;
export type UpdateMode = (typeof UPDATE_MODES)[number];

/** `DiffClass`. */
export const DIFF_CLASSES = ["added", "removed", "unchanged"] as const;
export type DiffClass = (typeof DIFF_CLASSES)[number];

/**
 * The eight manifest classes, in the order the server emits them.
 *
 * The order is load bearing: a diff reads as a widening of authority from left to
 * right, and reordering it would make `tools` look like the last word when it is
 * the first.
 */
export const PLUGIN_PERMISSION_CLASSES = [
  "tools",
  "mcp_servers",
  "network_destinations",
  "filesystem_scopes",
  "secret_handles",
  "process_spawn",
  "browser_capability",
  "external_data_handling",
] as const;
export type PluginPermissionClass = (typeof PLUGIN_PERMISSION_CLASSES)[number];

const PERMISSION_CLASS_LABELS: Readonly<Record<PluginPermissionClass, string>> = {
  tools: "Tools",
  mcp_servers: "MCP servers",
  network_destinations: "Network destinations",
  filesystem_scopes: "Filesystem scopes",
  secret_handles: "Secret handles",
  process_spawn: "Process spawn",
  browser_capability: "Browser capability",
  external_data_handling: "External data handling",
};

export function permissionClassLabel(name: string): string {
  return PERMISSION_CLASS_LABELS[name as PluginPermissionClass] ?? name;
}

/** The recorded reason a managed-mode expansion was refused. */
export const PERMISSION_EXPANSION_REASON = "plugin.permission_expansion_detected.v1";

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

export interface PluginPackage {
  package_id: string;
  publisher_id: string;
  publisher_official: boolean;
  display_name: string;
  summary: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface PluginListInstall {
  version: string;
  review_state: PluginReviewState;
  pending_review_version: string | null;
  review_reason: string | null;
  /** The reason THIS organization gave when it blocked the package. */
  blocked_reason: string | null;
}

export interface PluginListItem {
  package: PluginPackage;
  /** Null when the package is in the catalog but not installed here. */
  install: PluginListInstall | null;
  /** Platform decision against this exact `package@version`. */
  quarantined: boolean;
  pinned_version: string | null;
  blocked: boolean;
}

export interface PluginVersion {
  version: string;
  runtime_min: string;
  runtime_max: string;
  content_digest: string;
  manifest: unknown;
  published_at: string;
}

export interface PluginInstall {
  install_id: string;
  package_id: string;
  version: string;
  pending_review_version: string | null;
  review_state: PluginReviewState;
  review_reason: string | null;
  blocked_reason: string | null;
  approved_by: string | null;
  approved_at: string | null;
  /** Approved bindings. A tool here is usable. */
  registered_tools: string[];
  /**
   * Declared by the version, not registered by this organization. F13
   * default-deny: every one of these is **denied** with
   * `plugin_tool_unregistered`.
   */
  unregistered_tools: string[];
  created_at: string;
  updated_at: string;
}

export interface PluginPolicy {
  publisher_mode: PublisherMode;
  approved_publishers: string[];
  allowed_packages: string[];
  blocked_packages: string[];
  pinned_versions: Record<string, string>;
  auto_update: boolean;
  update_mode: UpdateMode;
  version: number;
  /**
   * Packages on both the allow and the block list. `blocked_packages` wins, and
   * the contradiction is REPORTED rather than silently resolved.
   */
  conflicts: string[];
}

export interface PluginOverview {
  items: PluginListItem[];
  policy: PluginPolicy;
}

export interface PluginDetail {
  package: PluginPackage;
  versions: PluginVersion[];
  install: PluginInstall | null;
}

export interface PermissionClassDiff {
  class: string;
  verdict: DiffClass;
  added: string[];
  removed: string[];
}

export interface PluginPermissionDiff {
  from_version: string;
  to_version: string;
  classes: PermissionClassDiff[];
  /** True when ANY class grew. Never a weighted score. */
  expands: boolean;
}

export interface InstallInput {
  version: string;
  /** The reporting host's agent version, checked against the declared range. */
  host_runtime_version: string;
  /** The artifact digest the host fetched, verified before anything is recorded. */
  content_digest: string;
  request_id?: string;
}

export interface PolicyActionInput {
  version: number;
  reason: string;
}

export interface PinInput {
  version: number;
  version_to_pin: string;
  reason: string;
}

export interface UpdatePolicyInput {
  version: number;
  publisher_mode?: PublisherMode;
  approved_publishers?: string[];
  allowed_packages?: string[];
  blocked_packages?: string[];
  pinned_versions?: Record<string, string>;
  auto_update?: boolean;
  update_mode?: UpdateMode;
}

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

export async function listPlugins(orgId: string, signal?: AbortSignal): Promise<PluginOverview> {
  return p07RequestJson(pluginsPath(orgId), signal ? { signal } : {}, (value) =>
    decodeOverview(value),
  );
}

export async function getPluginPolicy(orgId: string, signal?: AbortSignal): Promise<PluginPolicy> {
  return p07RequestJson(`${pluginsPath(orgId)}/policy`, signal ? { signal } : {}, (value) =>
    decodePolicy(record(value, "policy")),
  );
}

export async function updatePluginPolicy(
  orgId: string,
  input: UpdatePolicyInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<PluginPolicy> {
  return p07RequestJson(
    `${pluginsPath(orgId)}/policy`,
    { method: "PATCH", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    (value) => decodePolicy(record(value, "policy")),
  );
}

export async function getPlugin(
  orgId: string,
  packageId: string,
  signal?: AbortSignal,
): Promise<PluginDetail> {
  return p07RequestJson(
    `${pluginsPath(orgId)}/${encodeURIComponent(packageId)}`,
    signal ? { signal } : {},
    decodeDetail,
  );
}

export async function installPlugin(
  orgId: string,
  packageId: string,
  input: InstallInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<PluginInstall> {
  return p07RequestJson(
    `${pluginsPath(orgId)}/${encodeURIComponent(packageId)}/install`,
    { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    (value) => decodeInstall(record(value, "install")),
  );
}

export async function approvePluginInstall(
  orgId: string,
  packageId: string,
  input: { request_id?: string },
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<PluginInstall> {
  return p07RequestJson(
    `${pluginsPath(orgId)}/${encodeURIComponent(packageId)}/approve`,
    { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    (value) => decodeInstall(record(value, "install")),
  );
}

export async function blockPlugin(
  orgId: string,
  packageId: string,
  input: PolicyActionInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<PluginPolicy> {
  return p07RequestJson(
    `${pluginsPath(orgId)}/${encodeURIComponent(packageId)}/block`,
    { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    (value) => decodePolicy(record(value, "policy")),
  );
}

export async function unblockPlugin(
  orgId: string,
  packageId: string,
  input: PolicyActionInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<PluginPolicy> {
  return p07RequestJson(
    `${pluginsPath(orgId)}/${encodeURIComponent(packageId)}/unblock`,
    { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    (value) => decodePolicy(record(value, "policy")),
  );
}

export async function pinPluginVersion(
  orgId: string,
  packageId: string,
  input: PinInput,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<PluginPolicy> {
  return p07RequestJson(
    `${pluginsPath(orgId)}/${encodeURIComponent(packageId)}/pin`,
    { method: "POST", body: input, idempotencyKey, ...(signal ? { signal } : {}) },
    (value) => decodePolicy(record(value, "policy")),
  );
}

export async function getPluginPermissionDiff(
  orgId: string,
  packageId: string,
  version: string,
  againstVersion: string,
  signal?: AbortSignal,
): Promise<PluginPermissionDiff> {
  const params = new URLSearchParams();
  params.set("against_version", againstVersion);
  return p07RequestJson(
    `${pluginsPath(orgId)}/${encodeURIComponent(packageId)}/versions/${encodeURIComponent(version)}/permission-diff?${params.toString()}`,
    signal ? { signal } : {},
    (value) => decodePermissionDiff(record(value, "permission_diff")),
  );
}

// ---------------------------------------------------------------------------
// Strict decoders
// ---------------------------------------------------------------------------

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function record(value: unknown, field: string): unknown {
  return isObject(value) ? value[field] : undefined;
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isStringRecord(value: unknown): value is Record<string, string> {
  return isObject(value) && Object.values(value).every((item) => typeof item === "string");
}

function isReviewState(value: unknown): value is PluginReviewState {
  return (PLUGIN_REVIEW_STATES as readonly unknown[]).includes(value);
}

function isDiffClass(value: unknown): value is DiffClass {
  return (DIFF_CLASSES as readonly unknown[]).includes(value);
}

function decodePackage(value: unknown): PluginPackage | undefined {
  if (
    !isObject(value) ||
    typeof value.package_id !== "string" ||
    typeof value.publisher_id !== "string" ||
    typeof value.publisher_official !== "boolean" ||
    typeof value.display_name !== "string" ||
    typeof value.summary !== "string" ||
    typeof value.status !== "string" ||
    typeof value.created_at !== "string" ||
    typeof value.updated_at !== "string"
  ) {
    return undefined;
  }
  return {
    package_id: value.package_id,
    publisher_id: value.publisher_id,
    publisher_official: value.publisher_official,
    display_name: value.display_name,
    summary: value.summary,
    status: value.status,
    created_at: value.created_at,
    updated_at: value.updated_at,
  };
}

function decodeListInstall(value: unknown): PluginListInstall | undefined {
  if (
    !isObject(value) ||
    typeof value.version !== "string" ||
    !isReviewState(value.review_state) ||
    !isNullableString(value.pending_review_version) ||
    !isNullableString(value.review_reason) ||
    !isNullableString(value.blocked_reason)
  ) {
    return undefined;
  }
  return {
    version: value.version,
    review_state: value.review_state,
    pending_review_version: value.pending_review_version,
    review_reason: value.review_reason,
    blocked_reason: value.blocked_reason,
  };
}

function decodeListItem(value: unknown): PluginListItem | undefined {
  const pkg = decodePackage(record(value, "package"));
  if (!pkg || !isObject(value)) return undefined;
  if (typeof value.quarantined !== "boolean" || typeof value.blocked !== "boolean")
    return undefined;
  if (!isNullableString(value.pinned_version)) return undefined;
  const install =
    value.install === null || value.install === undefined ? null : decodeListInstall(value.install);
  if (value.install !== null && value.install !== undefined && install === null) return undefined;
  return {
    package: pkg,
    install: install ?? null,
    quarantined: value.quarantined,
    pinned_version: value.pinned_version,
    blocked: value.blocked,
  };
}

export function decodePolicy(value: unknown): PluginPolicy | undefined {
  if (
    !isObject(value) ||
    !["official_only", "approved_publishers", "any"].includes(String(value.publisher_mode)) ||
    !isStringArray(value.approved_publishers) ||
    !isStringArray(value.allowed_packages) ||
    !isStringArray(value.blocked_packages) ||
    !isStringRecord(value.pinned_versions) ||
    typeof value.auto_update !== "boolean" ||
    !["managed", "direct"].includes(String(value.update_mode)) ||
    typeof value.version !== "number" ||
    !isStringArray(value.conflicts)
  ) {
    return undefined;
  }
  return {
    publisher_mode: value.publisher_mode as PublisherMode,
    approved_publishers: [...value.approved_publishers],
    allowed_packages: [...value.allowed_packages],
    blocked_packages: [...value.blocked_packages],
    pinned_versions: { ...value.pinned_versions },
    auto_update: value.auto_update,
    update_mode: value.update_mode as UpdateMode,
    version: value.version,
    conflicts: [...value.conflicts],
  };
}

function decodeVersion(value: unknown): PluginVersion | undefined {
  if (
    !isObject(value) ||
    typeof value.version !== "string" ||
    typeof value.runtime_min !== "string" ||
    typeof value.runtime_max !== "string" ||
    typeof value.content_digest !== "string" ||
    typeof value.published_at !== "string"
  ) {
    return undefined;
  }
  return {
    version: value.version,
    runtime_min: value.runtime_min,
    runtime_max: value.runtime_max,
    content_digest: value.content_digest,
    // The manifest is an open object, so it is the one field carried through as
    // `unknown` rather than a typed shape. It is never rendered: the diff route
    // is the surface for manifest content, and an untyped object is not
    // something to interpolate.
    manifest: value.manifest ?? null,
    published_at: value.published_at,
  };
}

function decodeInstall(value: unknown): PluginInstall | undefined {
  if (
    !isObject(value) ||
    typeof value.install_id !== "string" ||
    typeof value.package_id !== "string" ||
    typeof value.version !== "string" ||
    !isNullableString(value.pending_review_version) ||
    !isReviewState(value.review_state) ||
    !isNullableString(value.review_reason) ||
    !isNullableString(value.blocked_reason) ||
    !isNullableString(value.approved_by) ||
    !isNullableString(value.approved_at) ||
    !isStringArray(value.registered_tools) ||
    !isStringArray(value.unregistered_tools) ||
    typeof value.created_at !== "string" ||
    typeof value.updated_at !== "string"
  ) {
    return undefined;
  }
  return {
    install_id: value.install_id,
    package_id: value.package_id,
    version: value.version,
    pending_review_version: value.pending_review_version,
    review_state: value.review_state,
    review_reason: value.review_reason,
    blocked_reason: value.blocked_reason,
    approved_by: value.approved_by,
    approved_at: value.approved_at,
    registered_tools: [...value.registered_tools],
    unregistered_tools: [...value.unregistered_tools],
    created_at: value.created_at,
    updated_at: value.updated_at,
  };
}

export function decodePermissionDiff(value: unknown): PluginPermissionDiff | undefined {
  if (
    !isObject(value) ||
    typeof value.from_version !== "string" ||
    typeof value.to_version !== "string" ||
    typeof value.expands !== "boolean" ||
    !Array.isArray(value.classes)
  ) {
    return undefined;
  }
  const classes: PermissionClassDiff[] = [];
  for (const entry of value.classes) {
    if (
      !isObject(entry) ||
      typeof entry.class !== "string" ||
      !isDiffClass(entry.verdict) ||
      !isStringArray(entry.added) ||
      !isStringArray(entry.removed)
    ) {
      return undefined;
    }
    classes.push({
      class: entry.class,
      verdict: entry.verdict,
      added: entry.added,
      removed: entry.removed,
    });
  }
  return {
    from_version: value.from_version,
    to_version: value.to_version,
    classes,
    expands: value.expands,
  };
}

function decodeDetail(value: unknown): PluginDetail | undefined {
  const pkg = decodePackage(record(value, "package"));
  if (!pkg || !isObject(value) || !Array.isArray(value.versions)) return undefined;
  const versions: PluginVersion[] = [];
  for (const entry of value.versions) {
    const version = decodeVersion(entry);
    if (!version) return undefined;
    versions.push(version);
  }
  const install =
    value.install === null || value.install === undefined ? null : decodeInstall(value.install);
  if (value.install !== null && value.install !== undefined && install === null) return undefined;
  return { package: pkg, versions, install: install ?? null };
}

function decodeOverview(value: unknown): PluginOverview | undefined {
  const policy = decodePolicy(record(value, "policy"));
  if (!policy || !isObject(value) || !Array.isArray(value.items)) return undefined;
  const items: PluginListItem[] = [];
  for (const entry of value.items) {
    const item = decodeListItem(entry);
    if (!item) return undefined;
    items.push(item);
  }
  return { items, policy };
}

// ---------------------------------------------------------------------------
// Request plumbing
// ---------------------------------------------------------------------------

function pluginsPath(orgId: string): string {
  return `/api/v1/orgs/${encodeURIComponent(orgId)}/plugins`;
}
