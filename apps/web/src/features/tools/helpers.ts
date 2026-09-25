import {
  ApiClientError,
  apiErrorFromEnvelope,
  makeInvalidResponseError,
  makeTransportError,
} from "@/lib/errors";

export const TOOLS_PAGE_LIMIT = 50;

export type ToolRole = "owner" | "admin" | "member" | "viewer";
export type ToolSource = "built_in" | "plugin" | "custom";
export type ToolRiskClass =
  | "read_only"
  | "filesystem_write"
  | "process_execution"
  | "network"
  | "mcp"
  | "browser"
  | "computer"
  | "credential_bearing"
  | "external_side_effect"
  | "destructive";
export type ToolLifecycle = "active" | "review" | "disabled";
export type ToolDecision =
  | "allow"
  | "require_session_approval"
  | "require_per_use_approval"
  | "deny";
export type DefaultToolPosture = "allow" | "deny";
export type PolicyState = "ok" | "missing" | "schema_unsupported";
export type McpTransport = "http" | "sse" | "stdio" | "other";
export type McpPolicyStatus = "approved" | "pending_review" | "denied" | "disabled";
export type ApprovalMode = "session" | "per_use";
export type PolicyApprovalMode = "none" | "session" | "per_use";
export type ApprovalStatus = "pending" | "approved" | "denied" | "expired" | "cancelled";
export type ApprovalDecision = "approved" | "denied";
export type ExternalSubmitDecision =
  | "deny"
  | "allow"
  | "require_approval"
  | "require_session_approval"
  | "require_per_use_approval";

export interface ToolsPage<T> {
  items: T[];
  next_cursor: string | null;
  has_more: boolean;
}

export interface ToolDefinition {
  tool_id: string;
  name: string;
  source: ToolSource;
  risk_class: ToolRiskClass;
  capability_ids: string[];
  fingerprint: string;
  lifecycle: ToolLifecycle;
  version: number;
  decision?: ToolDecision;
  review_required?: boolean;
  mcp_id?: string;
}

export interface ToolPolicyEntry {
  tool_id: string;
  decision: ToolDecision;
  fingerprint: string | null;
  review_required: boolean;
}

export interface BrowserPolicy {
  allowed_domains: string[];
  blocked_domains: string[];
  allow_download: boolean;
  allow_upload: boolean;
  allow_authenticated: boolean;
  allow_clipboard: boolean;
  external_submit: ExternalSubmitDecision;
}

export interface ComputerPolicy {
  allow_accessibility: boolean;
  allow_screen_capture: boolean;
  allow_keyboard_mouse: boolean;
  allow_shell_escalation: boolean;
  allowed_applications: string[];
}

export interface ToolPolicyDocument {
  schema_version: number;
  default_posture: DefaultToolPosture;
  default_approval_mode: PolicyApprovalMode;
  tool_ids: string[];
  mcp_ids: string[];
  tool_approval_modes: Record<string, PolicyApprovalMode>;
  tool_decisions: Record<string, ToolDecision>;
  entries: ToolPolicyEntry[];
  browser: BrowserPolicy;
  computer: ComputerPolicy;
  valid: boolean;
  issues: string[];
}

export interface ToolPolicy {
  org_id: string | null;
  policy_state: PolicyState;
  policy_version: number;
  version: number;
  document: ToolPolicyDocument;
  expires_at: string | null;
  updated_at: string | null;
}

export interface McpToolSummary {
  tool_id: string;
  name: string;
  fingerprint: string | null;
  risk_class: ToolRiskClass | null;
  review_required: boolean;
}

export interface McpRegistration {
  mcp_id: string;
  source: ToolSource;
  transport: McpTransport;
  policy_status: McpPolicyStatus;
  version: number;
  allowed_origins: string[];
  required_secret_handle_labels: string[];
  tool_fingerprint: string | null;
  tools: McpToolSummary[];
  endpoint_label: string;
  command_label: string;
  review_required: boolean;
  created_at: string | null;
  updated_at: string | null;
}

export interface ApprovalRequest {
  id: string;
  org_id: string;
  project_id: string;
  run_id: string;
  tool_call_id: string;
  tool_id: string;
  tool_fingerprint: string | null;
  risk_class: ToolRiskClass;
  approval_mode: ApprovalMode;
  status: ApprovalStatus;
  arguments_summary: string;
  requested_by_principal_id: string | null;
  requested_at: string;
  expires_at: string;
  resolved_by_principal_id: string | null;
  resolved_at: string | null;
  resolution_reason: string | null;
  version: number;
}

export interface ToolActivity {
  id: string;
  kind: "approved" | "denied" | "expired" | "cancelled";
  tool_id: string;
  run_id: string;
  occurred_at: string;
  reason: string | null;
}

export interface ResolveApprovalRequest {
  decision: ApprovalDecision;
  reason?: string;
  version: number;
}

export interface ToolsApiClient {
  listTools(orgId: string, signal?: AbortSignal): Promise<ToolsPage<ToolDefinition>>;
  listMcpRegistrations(orgId: string, signal?: AbortSignal): Promise<ToolsPage<McpRegistration>>;
  getToolPolicy(orgId: string, signal?: AbortSignal): Promise<ToolPolicy>;
  listApprovals(orgId: string, signal?: AbortSignal): Promise<ToolsPage<ApprovalRequest>>;
  resolveApproval(
    orgId: string,
    approvalId: string,
    input: ResolveApprovalRequest,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<ApprovalRequest>;
}

type JsonObject = Record<string, unknown>;

interface RequestOptions {
  method?: string;
  body?: unknown;
  idempotencyKey?: string;
  signal?: AbortSignal;
}

export const defaultToolsApi: ToolsApiClient = {
  listTools(orgId, signal) {
    return requestToolsJson(
      `${orgPath(orgId)}/tools?limit=${TOOLS_PAGE_LIMIT}`,
      withSignal(signal),
      decodeToolPage,
    );
  },
  listMcpRegistrations(orgId, signal) {
    return requestToolsJson(
      `${orgPath(orgId)}/mcp?limit=${TOOLS_PAGE_LIMIT}`,
      withSignal(signal),
      decodeMcpPage,
    );
  },
  getToolPolicy(orgId, signal) {
    return requestToolsJson(`${orgPath(orgId)}/policy/tools`, withSignal(signal), decodeToolPolicy);
  },
  listApprovals(orgId, signal) {
    return requestToolsJson(
      `${orgPath(orgId)}/approvals?limit=${TOOLS_PAGE_LIMIT}`,
      withSignal(signal),
      decodeApprovalPage,
    );
  },
  resolveApproval(orgId, approvalId, input, idempotencyKey, signal) {
    const body: ResolveApprovalRequest = { decision: input.decision, version: input.version };
    const reason = input.reason?.trim();
    if (reason) body.reason = reason;
    return requestToolsJson(
      `${orgPath(orgId)}/approvals/${encodeURIComponent(approvalId)}/resolve`,
      {
        method: "POST",
        body,
        idempotencyKey,
        ...(signal ? { signal } : {}),
      },
      decodeApproval,
    );
  },
};

export function decodeToolPage(value: unknown): ToolsPage<ToolDefinition> | null {
  return decodePage(value, decodeToolDefinition);
}

export function decodeMcpPage(value: unknown): ToolsPage<McpRegistration> | null {
  return decodePage(value, decodeMcpRegistration);
}

export function decodeApprovalPage(value: unknown): ToolsPage<ApprovalRequest> | null {
  return decodePage(value, decodeApproval);
}

export const decodeToolDefinitionPage = decodeToolPage;
export const decodeMcpRegistrationPage = decodeMcpPage;
export const decodeApprovalRequestPage = decodeApprovalPage;

export function decodeToolDefinition(value: unknown): ToolDefinition | null {
  if (!isObject(value)) return null;
  const toolId = cleanText(value.tool_id ?? value.id, 96);
  const name = cleanText(value.name, 160);
  const source = normalizeSource(value.source);
  const riskClass = normalizeRiskClass(value.risk_class ?? value.risk);
  const fingerprint = cleanText(value.fingerprint ?? value.tool_fingerprint, 256);
  if (!toolId || !name || !source || !riskClass || !fingerprint) return null;

  const capabilityIds = readStringArray(value.capability_ids ?? value.capabilities, 100, 96);
  const lifecycle = normalizeLifecycle(value.lifecycle ?? value.status) ?? "review";
  const decision = normalizeDecision(
    value.decision ?? value.policy_decision ?? value.effective_decision,
  );
  const reviewValue = readBoolean(value.review_required ?? value.requires_review);
  const metadataMcpId = isObject(value.metadata)
    ? (value.metadata.mcp_registration_id ?? value.metadata.mcp_id)
    : undefined;
  const mcpId = cleanText(value.mcp_id ?? value.mcp_registration_id ?? metadataMcpId, 96);
  const result: ToolDefinition = {
    tool_id: toolId,
    name,
    source,
    risk_class: riskClass,
    capability_ids: capabilityIds,
    fingerprint,
    lifecycle,
    version: readNumber(value.version) ?? 1,
  };
  if (decision) result.decision = decision;
  if (reviewValue !== undefined) result.review_required = reviewValue;
  if (mcpId) result.mcp_id = mcpId;
  return result;
}

export function decodeMcpRegistration(value: unknown): McpRegistration | null {
  if (!isObject(value)) return null;
  const mcpId = cleanText(value.mcp_id ?? value.mcp_registration_id ?? value.id, 96);
  const source = normalizeSource(value.source);
  if (!mcpId || !source) return null;

  const transport = normalizeTransport(value.transport) ?? "other";
  const policyStatus =
    normalizeMcpPolicyStatus(value.policy_status ?? value.status) ?? "pending_review";
  const toolFingerprint = cleanText(value.tool_fingerprint ?? value.fingerprint, 256);
  const tools = decodeMcpTools(value.tool_list ?? value.tools);
  const reviewValue = readBoolean(value.review_required ?? value.requires_review);
  const fingerprintChanged = readBoolean(value.fingerprint_changed);
  const reviewRequired =
    reviewValue === true ||
    policyStatus === "pending_review" ||
    fingerprintChanged === true ||
    (tools.length > 0 && !toolFingerprint) ||
    tools.some((tool) => tool.review_required || !tool.fingerprint);

  return {
    mcp_id: mcpId,
    source,
    transport,
    policy_status: policyStatus,
    version: readNumber(value.version) ?? 1,
    allowed_origins: readStringArray(value.allowed_origins, 50, 160).map(safeOrigin),
    required_secret_handle_labels: readSecretHandleLabels(
      value.required_secret_handles ?? value.secret_handles,
    ),
    tool_fingerprint: toolFingerprint,
    tools,
    endpoint_label: summarizeEndpointMetadata(value.endpoint_metadata),
    command_label: summarizeCommandMetadata(value.command_metadata),
    review_required: reviewRequired,
    created_at: cleanText(value.created_at, 64),
    updated_at: cleanText(value.updated_at, 64),
  };
}

export function decodeApproval(value: unknown): ApprovalRequest | null {
  if (!isObject(value)) return null;
  const id = cleanText(value.approval_id ?? value.id, 96);
  const orgId = cleanText(value.org_id, 96);
  const projectId = cleanText(value.project_id, 96);
  const runId = cleanText(value.run_id, 96);
  const toolCallId = cleanText(value.tool_call_id, 96);
  const toolId = cleanText(value.tool_id, 96);
  const riskClass = normalizeRiskClass(value.risk_class ?? value.risk);
  if (!id || !orgId || !projectId || !runId || !toolCallId || !toolId || !riskClass) return null;

  const rawSummary = cleanText(value.arguments_summary, 2048) ?? "Summary unavailable";
  const status = normalizeApprovalStatus(value.status) ?? "pending";
  const approvalMode = normalizeApprovalMode(value.approval_mode) ?? "per_use";
  const resolutionReason = cleanText(value.resolution_reason, 512);
  return {
    id,
    org_id: orgId,
    project_id: projectId,
    run_id: runId,
    tool_call_id: toolCallId,
    tool_id: toolId,
    tool_fingerprint: cleanText(value.tool_fingerprint, 256),
    risk_class: riskClass,
    approval_mode: approvalMode,
    status,
    arguments_summary: redactArgumentsSummary(rawSummary),
    requested_by_principal_id: cleanText(value.requested_by_principal_id, 96),
    requested_at: cleanText(value.requested_at, 64) ?? "Unknown time",
    expires_at: cleanText(value.expires_at, 64) ?? "Unknown expiry",
    resolved_by_principal_id: cleanText(value.resolved_by_principal_id, 96),
    resolved_at: cleanText(value.resolved_at, 64),
    resolution_reason: resolutionReason ? redactArgumentsSummary(resolutionReason) : null,
    version: readNumber(value.version) ?? 1,
  };
}

export function decodeToolPolicy(value: unknown): ToolPolicy | null {
  if (!isObject(value)) return null;
  const responseRoot = value;
  const documentValue =
    responseRoot.document ?? responseRoot.policy ?? responseRoot.tools ?? responseRoot;
  const documentRoot = parseObject(documentValue);
  if (!documentRoot) return null;
  const candidate =
    isObject(documentRoot.tools) && readNumber(documentRoot.tools.schema_version) !== undefined
      ? documentRoot.tools
      : documentRoot;

  const issues: string[] = [];
  const policyState =
    responseRoot.policy_state === undefined
      ? "ok"
      : (normalizePolicyState(responseRoot.policy_state) ?? "schema_unsupported");
  if (policyState !== "ok") issues.push(`server policy state: ${policyState}`);
  const schemaVersion = readNumber(candidate.schema_version) ?? 0;
  if (schemaVersion !== 1) issues.push("unsupported policy schema");

  const defaultPosture = normalizeDefaultPosture(candidate.default_posture);
  if (!defaultPosture) issues.push("invalid default posture; deny applied");
  const defaultApprovalMode =
    candidate.default_approval_mode === undefined
      ? "none"
      : normalizePolicyApprovalMode(candidate.default_approval_mode);
  if (!defaultApprovalMode) issues.push("invalid default approval mode; per-use review applied");
  if (candidate.tool_approval_modes !== undefined && !isObject(candidate.tool_approval_modes)) {
    issues.push("invalid tool approval mode map; per-use review applied");
  }
  const toolApprovalModes = decodeApprovalModeMap(candidate.tool_approval_modes);
  if (!Array.isArray(candidate.tool_ids)) {
    issues.push("invalid tool id list; deny applied");
  }
  if (!Array.isArray(candidate.mcp_ids)) {
    issues.push("invalid MCP id list; deny applied");
  }
  if (candidate.tool_decisions !== undefined && !isObject(candidate.tool_decisions)) {
    issues.push("invalid tool decision map; deny applied");
  }
  for (const key of ["tool_policies", "policies", "entries", "rules"]) {
    if (candidate[key] !== undefined && !Array.isArray(candidate[key])) {
      issues.push(`invalid ${key}; deny applied`);
    }
  }
  const browser = decodeBrowserPolicy(candidate.browser, issues);
  const computer = decodeComputerPolicy(candidate.computer, issues);
  const toolIds = readStringArray(candidate.tool_ids, 500, 96);
  const mcpIds = readStringArray(candidate.mcp_ids, 500, 96);
  const decisions = decodeDecisionMap(candidate.tool_decisions);
  const entries = mergePolicyEntries([
    ...decodePolicyEntries(candidate.tool_policies),
    ...decodePolicyEntries(candidate.policies),
    ...decodePolicyEntries(candidate.entries),
    ...decodePolicyEntries(candidate.rules),
  ]);
  for (const entry of entries) {
    decisions[entry.tool_id] = entry.decision;
  }

  return {
    org_id: cleanText(responseRoot.org_id, 96),
    policy_state: policyState,
    policy_version:
      readNumber(
        responseRoot.policy_version ?? documentRoot.policy_version ?? candidate.policy_version,
      ) ?? 0,
    version: readNumber(responseRoot.version ?? documentRoot.version ?? candidate.version) ?? 0,
    document: {
      schema_version: schemaVersion,
      default_posture: defaultPosture ?? "deny",
      default_approval_mode: defaultApprovalMode ?? "per_use",
      tool_ids: toolIds,
      mcp_ids: mcpIds,
      tool_approval_modes: toolApprovalModes,
      tool_decisions: decisions,
      entries,
      browser,
      computer,
      valid: issues.length === 0,
      issues,
    },
    expires_at: cleanText(
      responseRoot.expires_at ?? documentRoot.expires_at ?? candidate.expires_at,
      64,
    ),
    updated_at: cleanText(
      responseRoot.updated_at ?? documentRoot.updated_at ?? candidate.updated_at,
      64,
    ),
  };
}

export function getToolDecision(
  tool: ToolDefinition,
  policy: ToolPolicy | null | undefined,
): ToolDecision | null {
  if (!policy || !policy.document.valid || policy.policy_state !== "ok") return null;
  if (tool.decision) return tool.decision;
  const direct = policy.document.tool_decisions[tool.tool_id];
  if (direct) return direct;
  const entry = policy.document.entries.find((item) => item.tool_id === tool.tool_id);
  return entry?.decision ?? null;
}

export function getToolApprovalMode(
  tool: ToolDefinition,
  policy: ToolPolicy | null | undefined,
): PolicyApprovalMode | null {
  if (!policy || !policy.document.valid || policy.policy_state !== "ok") return null;
  return policy.document.tool_approval_modes[tool.tool_id] ?? policy.document.default_approval_mode;
}

export function isToolReviewRequired(
  tool: ToolDefinition,
  policy: ToolPolicy | null | undefined,
  mcpRegistrations: McpRegistration[] = [],
): boolean {
  if (tool.review_required || tool.lifecycle === "review") return true;
  if (tool.source !== "built_in" && !tool.mcp_id) return true;
  const mcp = tool.mcp_id
    ? mcpRegistrations.find((registration) => registration.mcp_id === tool.mcp_id)
    : undefined;
  if (mcp?.review_required) return true;
  const entry = policy?.document.entries.find((item) => item.tool_id === tool.tool_id);
  return (
    entry?.review_required === true ||
    (entry?.fingerprint !== null &&
      entry?.fingerprint !== undefined &&
      entry.fingerprint !== tool.fingerprint)
  );
}

export function isApprovalExpired(approval: ApprovalRequest, now = Date.now()): boolean {
  if (approval.status === "expired") return true;
  const expiry = Date.parse(approval.expires_at);
  return Number.isFinite(expiry) && expiry <= now;
}

export function approvalToActivity(
  approval: ApprovalRequest,
  now = Date.now(),
): ToolActivity | null {
  if (approval.status === "pending" && !isApprovalExpired(approval, now)) return null;
  const kind = approval.status === "pending" ? "expired" : approval.status;
  if (kind !== "approved" && kind !== "denied" && kind !== "expired" && kind !== "cancelled") {
    return null;
  }
  return {
    id: approval.id,
    kind,
    tool_id: approval.tool_id,
    run_id: approval.run_id,
    occurred_at:
      kind === "expired" && approval.status === "pending"
        ? approval.expires_at
        : (approval.resolved_at ?? approval.requested_at),
    reason: approval.resolution_reason,
  };
}

export function isPermissionError(error: unknown): boolean {
  return (
    error instanceof ApiClientError &&
    (error.status === 403 ||
      error.code === "permission_denied" ||
      error.code === "project_access_denied" ||
      error.code === "tools_read_forbidden" ||
      error.code === "approvals_read_forbidden")
  );
}

export function isNotFoundError(error: unknown): boolean {
  return error instanceof ApiClientError && (error.status === 404 || error.code === "not_found");
}

export function isAlreadyResolvedError(error: unknown): boolean {
  return (
    error instanceof ApiClientError &&
    (error.code === "approval_already_resolved" || error.code === "approval_not_pending")
  );
}

export function isApprovalExpiredError(error: unknown): boolean {
  return error instanceof ApiClientError && error.code === "approval_expired";
}

export function isAbortedError(error: unknown): boolean {
  return error instanceof ApiClientError && error.kind === "aborted";
}

export function redactArgumentsSummary(value: string): string {
  const compact = stripControlCharacters(value).replace(/\s+/g, " ").trim();
  let redacted = compact.replace(
    /((?:secret|token|password|passcode|api[_-]?key|authorization|credential|private[_-]?key)\s*[:=]\s*)([^\s,;&]+)/gi,
    "$1[redacted]",
  );
  redacted = redacted.replace(/(bearer\s+)[^\s,;&]+/gi, "$1[redacted]");
  redacted = redacted.replace(
    /([?&](?:secret|token|password|passcode|api[_-]?key|authorization|credential)=)[^&\s]+/gi,
    "$1[redacted]",
  );
  redacted = redacted.replace(
    /("(?:secret|token|password|passcode|api[_-]?key|authorization|credential|private[_-]?key)"\s*:\s*")[^"]*(")/gi,
    "$1[redacted]$2",
  );
  redacted = redacted.replace(/\b(?:sk|pk|api|key)[-_][a-z0-9_-]{8,}\b/gi, "[redacted]");
  redacted = redacted.replace(/\beyJ[a-z0-9_-]{20,}\b/g, "[redacted]");
  return redacted.length > 512 ? `${redacted.slice(0, 509)}…` : redacted || "Summary unavailable";
}

export function maskSecretHandle(value: string): string {
  const normalized = cleanText(value, 160);
  if (!normalized) return "handle unavailable";
  if (normalized.length <= 8) return `${normalized.slice(0, 2)}••`;
  return `${normalized.slice(0, 6)}…${normalized.slice(-4)}`;
}

export function safeOrigin(value: string): string {
  const normalized = cleanText(value, 160);
  if (!normalized) return "Configured origin";
  if (normalized.startsWith("*.")) {
    return /^\*\.[a-z0-9.-]+$/i.test(normalized) ? normalized.slice(0, 160) : "Configured origin";
  }
  try {
    const url = new URL(normalized.includes("://") ? normalized : `https://${normalized}`);
    if (!url.hostname) return "Configured origin";
    const host = url.hostname.toLowerCase();
    const looksLikeHost = host === "localhost" || host.includes(".") || /^[0-9a-f:]+$/i.test(host);
    if (!looksLikeHost) return "Configured origin";
    return `${url.protocol}//${url.host}`;
  } catch {
    return "Configured origin";
  }
}

export function humanize(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function decodePage<T>(value: unknown, decoder: (item: unknown) => T | null): ToolsPage<T> | null {
  const root = isObject(value) && isObject(value.data) ? value.data : value;
  if (!isObject(root) || !Array.isArray(root.items)) return null;
  const items: T[] = [];
  for (const item of root.items) {
    const decoded = decoder(item);
    if (!decoded) return null;
    items.push(decoded);
  }
  if (root.next_cursor !== null && typeof root.next_cursor !== "string") return null;
  if (typeof root.has_more !== "boolean") return null;
  return {
    items,
    next_cursor: root.next_cursor,
    has_more: root.has_more,
  };
}

function decodeMcpTools(value: unknown): McpToolSummary[] {
  const list = parseArray(value);
  if (!list) return [];
  const tools: McpToolSummary[] = [];
  for (const item of list.slice(0, 100)) {
    if (typeof item === "string") {
      const name = cleanText(item, 160);
      if (name) {
        tools.push({
          tool_id: name,
          name,
          fingerprint: null,
          risk_class: null,
          review_required: false,
        });
      }
      continue;
    }
    if (!isObject(item)) continue;
    const toolId = cleanText(item.tool_id ?? item.id ?? item.name, 160);
    if (!toolId) continue;
    const name = cleanText(item.name ?? item.display_name, 160) ?? toolId;
    const fingerprint = cleanText(item.fingerprint ?? item.tool_fingerprint, 256);
    const reviewRequired =
      readBoolean(item.review_required ?? item.requires_review) === true ||
      normalizeMcpPolicyStatus(item.policy_status) === "pending_review";
    tools.push({
      tool_id: toolId,
      name,
      fingerprint,
      risk_class: normalizeRiskClass(item.risk_class),
      review_required: reviewRequired,
    });
  }
  return tools;
}

function decodeBrowserPolicy(value: unknown, issues: string[]): BrowserPolicy {
  if (!isObject(value)) {
    issues.push("browser policy missing; deny applied");
    return {
      allowed_domains: [],
      blocked_domains: [],
      allow_download: false,
      allow_upload: false,
      allow_authenticated: false,
      allow_clipboard: false,
      external_submit: "deny",
    };
  }
  if (!Array.isArray(value.allowed_domains) || !Array.isArray(value.blocked_domains)) {
    issues.push("invalid browser domain list; deny applied");
  }
  for (const key of ["allow_download", "allow_upload", "allow_authenticated", "allow_clipboard"]) {
    if (typeof value[key] !== "boolean") issues.push(`invalid browser ${key}; deny applied`);
  }
  const externalSubmit = normalizeExternalSubmit(value.external_submit);
  if (!externalSubmit) issues.push("invalid browser submit decision; deny applied");
  return {
    allowed_domains: readStringArray(value.allowed_domains, 200, 160).map(safeOrigin),
    blocked_domains: readStringArray(value.blocked_domains, 200, 160).map(safeOrigin),
    allow_download: readBoolean(value.allow_download) === true,
    allow_upload: readBoolean(value.allow_upload) === true,
    allow_authenticated: readBoolean(value.allow_authenticated) === true,
    allow_clipboard: readBoolean(value.allow_clipboard) === true,
    external_submit: externalSubmit ?? "deny",
  };
}

function decodeComputerPolicy(value: unknown, issues: string[]): ComputerPolicy {
  if (!isObject(value)) {
    issues.push("computer policy missing; deny applied");
    return {
      allow_accessibility: false,
      allow_screen_capture: false,
      allow_keyboard_mouse: false,
      allow_shell_escalation: false,
      allowed_applications: [],
    };
  }
  if (!Array.isArray(value.allowed_applications)) {
    issues.push("invalid computer application list; deny applied");
  }
  for (const key of [
    "allow_accessibility",
    "allow_screen_capture",
    "allow_keyboard_mouse",
    "allow_shell_escalation",
  ]) {
    if (typeof value[key] !== "boolean") issues.push(`invalid computer ${key}; deny applied`);
  }
  return {
    allow_accessibility: readBoolean(value.allow_accessibility) === true,
    allow_screen_capture: readBoolean(value.allow_screen_capture) === true,
    allow_keyboard_mouse: readBoolean(value.allow_keyboard_mouse) === true,
    allow_shell_escalation: readBoolean(value.allow_shell_escalation) === true,
    allowed_applications: readStringArray(value.allowed_applications, 100, 160),
  };
}

function decodeDecisionMap(value: unknown): Record<string, ToolDecision> {
  if (!isObject(value)) return {};
  const result: Record<string, ToolDecision> = {};
  for (const [toolId, rawDecision] of Object.entries(value)) {
    const normalizedId = cleanText(toolId, 96);
    const decision = normalizeDecision(rawDecision);
    if (normalizedId && decision) result[normalizedId] = decision;
  }
  return result;
}

function mergePolicyEntries(entries: ToolPolicyEntry[]): ToolPolicyEntry[] {
  const merged = new Map<string, ToolPolicyEntry>();
  for (const entry of entries) merged.set(entry.tool_id, entry);
  return Array.from(merged.values()).slice(0, 500);
}

function decodePolicyEntries(value: unknown): ToolPolicyEntry[] {
  const list = parseArray(value);
  if (!list) return [];
  const entries: ToolPolicyEntry[] = [];
  for (const item of list.slice(0, 500)) {
    if (!isObject(item)) continue;
    const toolId = cleanText(item.tool_id ?? item.id, 96);
    const decision = normalizeDecision(item.decision ?? item.policy_decision);
    if (!toolId || !decision) continue;
    entries.push({
      tool_id: toolId,
      decision,
      fingerprint: cleanText(item.fingerprint ?? item.tool_fingerprint, 256),
      review_required:
        readBoolean(item.review_required ?? item.requires_review) === true ||
        normalizeMcpPolicyStatus(item.policy_status) === "pending_review",
    });
  }
  return entries;
}

function summarizeEndpointMetadata(value: unknown): string {
  const metadata = parseObject(value);
  if (!metadata) return "Not configured";
  const candidate = firstString(metadata, [
    "origin",
    "host",
    "hostname",
    "endpoint",
    "url",
    "base_url",
  ]);
  if (!candidate) return "Endpoint metadata configured";
  const origin = safeOrigin(candidate);
  return origin === "Configured origin"
    ? "Endpoint configured"
    : `Host ${origin.replace(/^https?:\/\//, "")}`;
}

function summarizeCommandMetadata(value: unknown): string {
  const metadata = parseObject(value);
  if (!metadata) return "Not configured";
  const candidate = firstString(metadata, ["command", "executable", "program", "binary"]);
  if (!candidate) return "Command metadata configured";
  const basename = candidate.split(/[\\/]/).filter(Boolean).at(-1) ?? "configured";
  return `Command ${basename.slice(0, 80)}`;
}

function firstString(value: JsonObject, keys: string[]): string | null {
  for (const key of keys) {
    const candidate = cleanText(value[key], 256);
    if (candidate) return candidate;
  }
  return null;
}

function parseObject(value: unknown): JsonObject | null {
  if (isObject(value)) return value;
  if (typeof value !== "string" || value.length > 65536) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    return isObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function normalizeDecision(value: unknown): ToolDecision | null {
  if (
    value === "allow" ||
    value === "require_session_approval" ||
    value === "require_per_use_approval" ||
    value === "deny"
  ) {
    return value;
  }
  return null;
}

function normalizeDefaultPosture(value: unknown): DefaultToolPosture | null {
  return value === "allow" || value === "deny" ? value : null;
}

function normalizePolicyState(value: unknown): PolicyState | null {
  return value === "ok" || value === "missing" || value === "schema_unsupported" ? value : null;
}

function normalizeSource(value: unknown): ToolSource | null {
  return value === "built_in" || value === "plugin" || value === "custom" ? value : null;
}

function normalizeRiskClass(value: unknown): ToolRiskClass | null {
  if (
    value === "read_only" ||
    value === "filesystem_write" ||
    value === "process_execution" ||
    value === "network" ||
    value === "mcp" ||
    value === "browser" ||
    value === "computer" ||
    value === "credential_bearing" ||
    value === "external_side_effect" ||
    value === "destructive"
  ) {
    return value;
  }
  return null;
}

function normalizeLifecycle(value: unknown): ToolLifecycle | null {
  return value === "active" || value === "review" || value === "disabled" ? value : null;
}

function normalizeTransport(value: unknown): McpTransport | null {
  return value === "http" || value === "sse" || value === "stdio" || value === "other"
    ? value
    : null;
}

function normalizeMcpPolicyStatus(value: unknown): McpPolicyStatus | null {
  return value === "approved" ||
    value === "pending_review" ||
    value === "denied" ||
    value === "disabled"
    ? value
    : null;
}

function normalizePolicyApprovalMode(value: unknown): PolicyApprovalMode | null {
  return value === "none" || value === "session" || value === "per_use" ? value : null;
}

function decodeApprovalModeMap(value: unknown): Record<string, PolicyApprovalMode> {
  if (!isObject(value)) return {};
  const result: Record<string, PolicyApprovalMode> = {};
  for (const [toolId, rawMode] of Object.entries(value)) {
    const normalizedId = cleanText(toolId, 96);
    const mode = normalizePolicyApprovalMode(rawMode);
    if (normalizedId && mode) result[normalizedId] = mode;
  }
  return result;
}

function normalizeApprovalMode(value: unknown): ApprovalMode | null {
  return value === "session" || value === "per_use" ? value : null;
}

function normalizeApprovalStatus(value: unknown): ApprovalStatus | null {
  return value === "pending" ||
    value === "approved" ||
    value === "denied" ||
    value === "expired" ||
    value === "cancelled"
    ? value
    : null;
}

function normalizeExternalSubmit(value: unknown): ExternalSubmitDecision | null {
  return value === "deny" ||
    value === "allow" ||
    value === "require_approval" ||
    value === "require_session_approval" ||
    value === "require_per_use_approval"
    ? value
    : null;
}

function readBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function readNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function readSecretHandleLabels(value: unknown): string[] {
  const list = parseArray(value);
  if (!list) return [];
  const handles: string[] = [];
  for (const item of list.slice(0, 50)) {
    const raw = isObject(item) ? (item.handle ?? item.secret_handle ?? item.name ?? item.id) : item;
    const handle = cleanText(raw, 160);
    if (handle) handles.push(maskSecretHandle(handle));
  }
  return Array.from(new Set(handles));
}

function parseArray(value: unknown): unknown[] | null {
  if (Array.isArray(value)) return value;
  if (typeof value !== "string" || value.length > 65536) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function readStringArray(value: unknown, maxItems: number, maxLength: number): string[] {
  const list = parseArray(value);
  if (!list) return [];
  const result: string[] = [];
  const seen = new Set<string>();
  for (const item of list.slice(0, maxItems)) {
    const normalized = cleanText(item, maxLength);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    result.push(normalized);
  }
  return result;
}

function stripControlCharacters(value: string): string {
  return Array.from(value, (character) => {
    const code = character.charCodeAt(0);
    return code < 32 || code === 127 ? " " : character;
  }).join("");
}

function cleanText(value: unknown, maxLength: number): string | null {
  if (typeof value !== "string") return null;
  const normalized = stripControlCharacters(value).replace(/\s+/g, " ").trim();
  if (!normalized) return null;
  return normalized.slice(0, maxLength);
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function orgPath(orgId: string): string {
  return `/api/v1/orgs/${encodeURIComponent(orgId)}`;
}

function withSignal(signal?: AbortSignal): RequestOptions {
  return signal ? { signal } : {};
}

async function requestToolsJson<T>(
  path: string,
  options: RequestOptions,
  decode: (value: unknown) => T | null,
): Promise<T> {
  const method = (options.method ?? "GET").toUpperCase();
  const headers = new Headers();
  headers.set("Accept", "application/json");
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  if (options.idempotencyKey) headers.set("Idempotency-Key", options.idempotencyKey);
  if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
    const csrf = readCookie("lumi_csrf");
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }

  const init: RequestInit = {
    method,
    headers,
    credentials: "include",
    ...(options.signal ? { signal: options.signal } : {}),
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
  };

  let response: Response;
  try {
    response = await fetch(path, init);
  } catch (cause) {
    throw makeTransportError(cause, options.signal, { retryable: isRetryableMethod(options) });
  }

  const requestId = readRequestId(response.headers.get("X-Request-ID"));
  let text: string;
  try {
    text = await response.text();
  } catch (cause) {
    throw makeTransportError(cause, options.signal, {
      requestId,
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
    throw makeApiError(response.status, payload, requestId, isRetryableStatus(response.status));
  }
  if (!validJson) throw makeInvalidResponseError({ requestId, status: response.status });
  const decoded = decode(payload);
  if (!decoded) throw makeInvalidResponseError({ requestId, status: response.status });
  return decoded;
}

function isRetryableMethod(options: RequestOptions): boolean {
  const method = (options.method ?? "GET").toUpperCase();
  return (
    method === "GET" || method === "HEAD" || method === "OPTIONS" || Boolean(options.idempotencyKey)
  );
}

function isRetryableStatus(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}

function makeApiError(
  status: number,
  payload: unknown,
  requestId: string | undefined,
  retryable: boolean,
): ApiClientError {
  const envelope = isObject(payload) && isObject(payload.error) ? payload.error : null;
  const bodyRequestId = readRequestId(
    typeof envelope?.request_id === "string" ? envelope.request_id : null,
  );
  const code = typeof envelope?.code === "string" ? envelope.code : null;
  if (code && /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/.test(code)) {
    return new ApiClientError({
      code,
      kind: "api",
      status,
      requestId: requestId ?? bodyRequestId,
      details: {},
      retryable,
    });
  }
  return apiErrorFromEnvelope(status, payload, requestId ?? bodyRequestId, retryable);
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
