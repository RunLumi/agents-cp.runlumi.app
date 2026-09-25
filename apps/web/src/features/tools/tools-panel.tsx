import { Tabs } from "@base-ui/react/tabs";
import { useCallback, useEffect, useRef, useState } from "react";

import {
  defaultToolsApi,
  isAbortedError,
  isNotFoundError,
  isPermissionError,
  type ApprovalRequest,
  type McpRegistration,
  type ToolActivity,
  type ToolDefinition,
  type ToolPolicy,
  type ToolsApiClient,
  type ToolRole,
  type ToolsPage,
} from "./helpers";
import { ApprovalQueue, type ResolveApprovalInput } from "./approval-queue";
import { BrowserComputerPolicy } from "./browser-computer-policy";
import { CapabilityMatrix } from "./capability-matrix";
import {
  RiskBadge,
  StatusPill,
  ToolCode,
  ToolDate,
  ToolEmpty,
  ToolError,
  ToolLoading,
  ToolNotice,
  ToolPanel,
  ToolPanelHeader,
  ToolPermission,
  humanize,
  secondaryButtonClass,
} from "./ui";

export interface ToolsPanelPermissions {
  toolsRead?: boolean;
  toolsManage?: boolean;
  mcpRead?: boolean;
  policyRead?: boolean;
  approvalsRead?: boolean;
  approvalsResolve?: boolean;
}

export interface ToolsPanelProps {
  orgId: string;
  role?: ToolRole | undefined;
  membership?: { role?: ToolRole | undefined } | undefined;
  permissions?: ToolsPanelPermissions | undefined;
  client?: ToolsApiClient | undefined;
  recentActivity?: ToolActivity[] | undefined;
  recentEvents?: ToolActivity[] | undefined;
}

type ResourceState<T> =
  | { kind: "loading" }
  | { kind: "ready"; data: T }
  | { kind: "error"; error: unknown }
  | { kind: "permission" };

type ToolsTab = "matrix" | "mcp" | "policy" | "approvals";

export function ToolsPanel({
  orgId,
  role,
  membership,
  permissions,
  client,
  recentActivity,
  recentEvents,
}: ToolsPanelProps) {
  const activeClient = client ?? defaultToolsApi;
  const effectiveRole = membership?.role ?? role;
  const toolsRead = permissions?.toolsRead ?? true;
  const mcpRead = permissions?.mcpRead ?? toolsRead;
  const policyRead = permissions?.policyRead ?? toolsRead;
  const approvalsRead = permissions?.approvalsRead ?? toolsRead;
  const canManage =
    permissions?.toolsManage ?? (effectiveRole === "owner" || effectiveRole === "admin");
  const canResolve =
    permissions?.approvalsResolve ?? (effectiveRole === "owner" || effectiveRole === "admin");
  const normalizedOrgId = orgId.trim();

  const [activeTab, setActiveTab] = useState<ToolsTab>("matrix");
  const [activeOrgId, setActiveOrgId] = useState(normalizedOrgId);
  const [toolsState, setToolsState] = useState<ResourceState<ToolsPage<ToolDefinition>>>({
    kind: "loading",
  });
  const [mcpState, setMcpState] = useState<ResourceState<ToolsPage<McpRegistration>>>({
    kind: "loading",
  });
  const [policyState, setPolicyState] = useState<ResourceState<ToolPolicy | null>>({
    kind: "loading",
  });
  const [approvalsState, setApprovalsState] = useState<ResourceState<ToolsPage<ApprovalRequest>>>({
    kind: "loading",
  });
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const generation = useRef(0);
  const controller = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    const requestGeneration = ++generation.current;
    controller.current?.abort();
    const nextController = new AbortController();
    controller.current = nextController;
    setActiveOrgId(normalizedOrgId);

    if (!normalizedOrgId) {
      setToolsState({ kind: "permission" });
      setMcpState({ kind: "permission" });
      setPolicyState({ kind: "permission" });
      setApprovalsState({ kind: "permission" });
      return;
    }

    setLastUpdated(null);
    if (toolsRead) setToolsState({ kind: "loading" });
    else setToolsState({ kind: "permission" });
    if (mcpRead) setMcpState({ kind: "loading" });
    else setMcpState({ kind: "permission" });
    if (policyRead) setPolicyState({ kind: "loading" });
    else setPolicyState({ kind: "permission" });
    if (approvalsRead) setApprovalsState({ kind: "loading" });
    else setApprovalsState({ kind: "permission" });

    const [toolsResult, mcpResult, policyResult, approvalsResult] = await Promise.allSettled([
      toolsRead
        ? activeClient.listTools(normalizedOrgId, nextController.signal)
        : Promise.resolve(null),
      mcpRead
        ? activeClient.listMcpRegistrations(normalizedOrgId, nextController.signal)
        : Promise.resolve(null),
      policyRead
        ? activeClient.getToolPolicy(normalizedOrgId, nextController.signal)
        : Promise.resolve(null),
      approvalsRead
        ? activeClient.listApprovals(normalizedOrgId, nextController.signal)
        : Promise.resolve(null),
    ]);

    if (requestGeneration !== generation.current || nextController.signal.aborted) return;

    if (toolsRead) {
      if (toolsResult.status === "fulfilled" && toolsResult.value) {
        setToolsState({ kind: "ready", data: toolsResult.value });
      } else if (toolsResult.status === "rejected" && isNotFoundError(toolsResult.reason)) {
        setToolsState({ kind: "ready", data: emptyPage() });
      } else if (toolsResult.status === "rejected" && isPermissionError(toolsResult.reason)) {
        setToolsState({ kind: "permission" });
      } else if (toolsResult.status === "rejected" && !isAbortedError(toolsResult.reason)) {
        setToolsState({ kind: "error", error: toolsResult.reason });
      }
    }

    if (mcpRead) {
      if (mcpResult.status === "fulfilled" && mcpResult.value) {
        setMcpState({ kind: "ready", data: mcpResult.value });
      } else if (mcpResult.status === "rejected" && isNotFoundError(mcpResult.reason)) {
        setMcpState({ kind: "ready", data: emptyPage() });
      } else if (mcpResult.status === "rejected" && isPermissionError(mcpResult.reason)) {
        setMcpState({ kind: "permission" });
      } else if (mcpResult.status === "rejected" && !isAbortedError(mcpResult.reason)) {
        setMcpState({ kind: "error", error: mcpResult.reason });
      }
    }

    if (policyRead) {
      if (policyResult.status === "fulfilled") {
        setPolicyState({ kind: "ready", data: policyResult.value });
      } else if (policyResult.status === "rejected" && isNotFoundError(policyResult.reason)) {
        setPolicyState({ kind: "ready", data: null });
      } else if (policyResult.status === "rejected" && isPermissionError(policyResult.reason)) {
        setPolicyState({ kind: "permission" });
      } else if (policyResult.status === "rejected" && !isAbortedError(policyResult.reason)) {
        setPolicyState({ kind: "error", error: policyResult.reason });
      }
    }

    if (approvalsRead) {
      if (approvalsResult.status === "fulfilled" && approvalsResult.value) {
        setApprovalsState({ kind: "ready", data: approvalsResult.value });
      } else if (approvalsResult.status === "rejected" && isNotFoundError(approvalsResult.reason)) {
        setApprovalsState({ kind: "ready", data: emptyPage() });
      } else if (
        approvalsResult.status === "rejected" &&
        isPermissionError(approvalsResult.reason)
      ) {
        setApprovalsState({ kind: "permission" });
      } else if (approvalsResult.status === "rejected" && !isAbortedError(approvalsResult.reason)) {
        setApprovalsState({ kind: "error", error: approvalsResult.reason });
      }
    }

    setLastUpdated(new Date().toISOString());
  }, [activeClient, approvalsRead, mcpRead, normalizedOrgId, policyRead, toolsRead]);

  useEffect(() => {
    void load();
    return () => {
      generation.current += 1;
      controller.current?.abort();
    };
  }, [load]);

  const resolveApproval = useCallback(
    async ({ approval, decision, idempotencyKey, reason }: ResolveApprovalInput) => {
      const result = await activeClient.resolveApproval(
        normalizedOrgId,
        approval.id,
        {
          decision,
          version: approval.version,
          ...(reason ? { reason } : {}),
        },
        idempotencyKey,
      );
      if (result) {
        setApprovalsState((current) => {
          if (current.kind !== "ready") return current;
          return {
            kind: "ready",
            data: {
              ...current.data,
              items: current.data.items.map((item) => (item.id === result.id ? result : item)),
            },
          };
        });
      }
      return result;
    },
    [activeClient, normalizedOrgId],
  );

  const isLoading =
    toolsState.kind === "loading" ||
    mcpState.kind === "loading" ||
    policyState.kind === "loading" ||
    approvalsState.kind === "loading";
  const tools = toolsState.kind === "ready" ? toolsState.data.items : [];
  const mcp = mcpState.kind === "ready" ? mcpState.data.items : [];
  const policy = policyState.kind === "ready" ? policyState.data : null;
  const approvals = approvalsState.kind === "ready" ? approvalsState.data.items : [];
  const supplementalActivity = recentActivity ?? recentEvents;

  if (activeOrgId !== normalizedOrgId) {
    return (
      <div className="space-y-5">
        <PanelHeading
          title="Tools & policy"
          description="Inspect the server-authoritative capability, MCP, browser, computer, and approval state."
          onRefresh={() => void load()}
          refreshing={isLoading}
          lastUpdated={lastUpdated}
        />
        <ToolPanel ariaLabel="Tools loading">
          <ToolLoading label="Switching organization scope…" rows={5} />
        </ToolPanel>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PanelHeading
        title="Tools & policy"
        description="Inspect the server-authoritative capability, MCP, browser, computer, and approval state."
        onRefresh={() => void load()}
        refreshing={isLoading}
        lastUpdated={lastUpdated}
      />

      <Tabs.Root
        value={activeTab}
        onValueChange={(value) => {
          if (typeof value === "string") setActiveTab(value as ToolsTab);
        }}
      >
        <Tabs.List
          aria-label="Tools and policy sections"
          className="relative flex gap-1 overflow-x-auto border-b border-[var(--border)]"
        >
          <Tab value="matrix">Capability matrix</Tab>
          <Tab value="mcp">MCP registrations</Tab>
          <Tab value="policy">Browser & computer</Tab>
          <Tab value="approvals">Approvals</Tab>
          <Tabs.Indicator className="absolute bottom-0 left-0 h-0.5 w-0.5 rounded-full bg-[var(--lumi-blue)] transition-[left,width] duration-150" />
        </Tabs.List>

        <Tabs.Panel value="matrix" className="pt-5">
          <CapabilityMatrix
            tools={tools}
            policy={policy}
            mcpRegistrations={mcp}
            loading={toolsState.kind === "loading"}
            error={toolsState.kind === "error" ? toolsState.error : undefined}
            permissionDenied={toolsState.kind === "permission"}
            onRetry={() => void load()}
          />
        </Tabs.Panel>
        <Tabs.Panel value="mcp" className="pt-5">
          <McpCatalog
            registrations={mcp}
            loading={mcpState.kind === "loading"}
            error={mcpState.kind === "error" ? mcpState.error : undefined}
            permissionDenied={mcpState.kind === "permission"}
            canManage={canManage}
            onRetry={() => void load()}
          />
        </Tabs.Panel>
        <Tabs.Panel value="policy" className="pt-5">
          <BrowserComputerPolicy
            policy={policy}
            loading={policyState.kind === "loading"}
            error={policyState.kind === "error" ? policyState.error : undefined}
            permissionDenied={policyState.kind === "permission"}
            onRetry={() => void load()}
          />
        </Tabs.Panel>
        <Tabs.Panel value="approvals" className="pt-5">
          <ApprovalQueue
            approvals={approvals}
            loading={approvalsState.kind === "loading"}
            error={approvalsState.kind === "error" ? approvalsState.error : undefined}
            permissionDenied={approvalsState.kind === "permission"}
            canResolve={canResolve}
            onResolve={resolveApproval}
            onRetry={() => void load()}
            onRefresh={() => load()}
            {...(supplementalActivity ? { recentActivity: supplementalActivity } : {})}
          />
        </Tabs.Panel>
      </Tabs.Root>
    </div>
  );
}

function Tab({ value, children }: { value: ToolsTab; children: string }) {
  return (
    <Tabs.Tab
      value={value}
      className="min-h-11 shrink-0 border-b-2 border-transparent px-3 py-2 text-sm font-medium text-[var(--muted-strong)] outline-none transition hover:text-[var(--civic-navy)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] data-[active]:border-[var(--lumi-blue)] data-[active]:text-[var(--lumi-blue)]"
    >
      {children}
    </Tabs.Tab>
  );
}

function PanelHeading({
  title,
  description,
  onRefresh,
  refreshing,
  lastUpdated,
}: {
  title: string;
  description: string;
  onRefresh: () => void;
  refreshing: boolean;
  lastUpdated: string | null;
}) {
  return (
    <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p className="text-xs font-semibold tracking-[0.1em] text-[var(--lumi-blue)]">
          TOOLS &amp; POLICY
        </p>
        <h1 className="mt-2 text-2xl font-semibold tracking-[-0.03em] text-[var(--civic-navy)]">
          {title}
        </h1>
        <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--muted-strong)]">{description}</p>
        {lastUpdated ? (
          <p className="mt-2 text-xs text-[var(--muted)]">
            Last refreshed <ToolDate value={lastUpdated} />
          </p>
        ) : null}
      </div>
      <button
        type="button"
        className={secondaryButtonClass}
        onClick={onRefresh}
        disabled={refreshing}
      >
        {refreshing ? "Refreshing…" : "Refresh"}
      </button>
    </header>
  );
}

export interface McpCatalogProps {
  registrations?: McpRegistration[];
  loading?: boolean;
  error?: unknown;
  permissionDenied?: boolean;
  canManage?: boolean;
  onRetry?: () => void;
}

export function McpCatalog({
  registrations = [],
  loading = false,
  error,
  permissionDenied = false,
  canManage = false,
  onRetry,
}: McpCatalogProps) {
  if (permissionDenied) {
    return (
      <ToolPanel ariaLabel="MCP registrations">
        <ToolPanelHeader
          title="MCP registrations"
          description="Non-secret source, transport, target, fingerprint, and review metadata."
        />
        <div className="p-5">
          <ToolPermission message="Your current organization role cannot view MCP registrations." />
        </div>
      </ToolPanel>
    );
  }
  if (loading) {
    return (
      <ToolPanel ariaLabel="MCP registrations">
        <ToolPanelHeader
          title="MCP registrations"
          description="Non-secret source, transport, target, fingerprint, and review metadata."
        />
        <ToolLoading label="Loading MCP registrations…" rows={4} />
      </ToolPanel>
    );
  }
  if (error) {
    return (
      <ToolPanel ariaLabel="MCP registrations">
        <ToolPanelHeader
          title="MCP registrations"
          description="Non-secret source, transport, target, fingerprint, and review metadata."
        />
        <div className="p-5">
          <ToolError error={error} onRetry={onRetry} />
        </div>
      </ToolPanel>
    );
  }

  return (
    <ToolPanel ariaLabel="MCP registrations">
      <ToolPanelHeader
        title="MCP registrations"
        description="Non-secret source, transport, target, fingerprint, and review metadata."
        action={
          <StatusPill
            tone={
              registrations.some((registration) => registration.review_required)
                ? "warning"
                : "success"
            }
          >
            {registrations.filter((registration) => registration.review_required).length} need
            review
          </StatusPill>
        }
      />
      <div className="space-y-4 p-5">
        <ToolNotice tone="info">
          Secret requirements are shown only as masked handles. Endpoint and command metadata are
          reduced to safe target summaries; full credentials, authorization headers, arguments, and
          tool schemas are never displayed here.
        </ToolNotice>
        {canManage ? (
          <p className="text-xs leading-5 text-[var(--muted)]">
            Management permissions are available for policy review, but this surface is
            intentionally read-only. New or changed fingerprints must be re-evaluated by the server
            before use.
          </p>
        ) : null}
        {registrations.length === 0 ? (
          <ToolEmpty
            title="No MCP registrations"
            description="Built-in, plugin, and custom MCP sources will appear here with their stable identity and review state."
          />
        ) : (
          <ul className="space-y-3">
            {registrations.map((registration) => (
              <li
                key={registration.mcp_id}
                className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-4"
              >
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="font-medium text-[var(--civic-navy)]">
                        {humanize(registration.source)} MCP
                      </p>
                      <McpStatusPill registration={registration} />
                      {registration.review_required ? (
                        <StatusPill tone="warning">Review required</StatusPill>
                      ) : null}
                    </div>
                    <p className="mt-1 text-xs text-[var(--muted)]">
                      <ToolCode>{registration.mcp_id}</ToolCode>
                    </p>
                  </div>
                  <StatusPill tone="neutral">{humanize(registration.transport)}</StatusPill>
                </div>

                <dl className="mt-4 grid gap-3 text-xs sm:grid-cols-2 lg:grid-cols-4">
                  <McpFact label="Target" value={mcpTargetLabel(registration)} />
                  <McpFact
                    label="Tool fingerprint"
                    value={
                      registration.tool_fingerprint ? (
                        <ToolCode>{registration.tool_fingerprint}</ToolCode>
                      ) : (
                        "Not supplied"
                      )
                    }
                  />
                  <McpFact
                    label="Allowed origins"
                    value={<OriginList origins={registration.allowed_origins} />}
                  />
                  <McpFact
                    label="Secret handles"
                    value={<HandleList handles={registration.required_secret_handle_labels} />}
                  />
                </dl>

                <details className="mt-4 rounded-md border border-[var(--border)] bg-[var(--panel)]">
                  <summary className="cursor-pointer px-3 py-2 text-sm font-medium text-[var(--civic-navy)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]">
                    Inspect tool identity ({registration.tools.length})
                  </summary>
                  <div className="border-t border-[var(--border)] px-3 py-3">
                    {registration.tools.length === 0 ? (
                      <p className="text-sm text-[var(--muted)]">
                        No discoverable tool list recorded.
                      </p>
                    ) : (
                      <ul className="space-y-2">
                        {registration.tools.map((tool) => (
                          <li
                            key={tool.tool_id}
                            className="flex flex-col gap-1 text-xs sm:flex-row sm:items-center sm:justify-between"
                          >
                            <span className="font-medium text-[var(--civic-navy)]">
                              {tool.name}
                            </span>
                            <span className="flex items-center gap-2">
                              {tool.fingerprint ? (
                                <ToolCode>{tool.fingerprint}</ToolCode>
                              ) : (
                                <span className="text-[var(--danger)]">No fingerprint</span>
                              )}
                              {tool.risk_class ? <RiskBadge riskClass={tool.risk_class} /> : null}
                              {tool.review_required ? (
                                <StatusPill tone="warning">Review</StatusPill>
                              ) : null}
                            </span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </details>
              </li>
            ))}
          </ul>
        )}
      </div>
    </ToolPanel>
  );
}

function mcpTargetLabel(registration: McpRegistration): string {
  if (registration.transport === "stdio") {
    return registration.command_label === "Not configured"
      ? "Command not configured"
      : registration.command_label;
  }
  if (registration.endpoint_label !== "Not configured") return registration.endpoint_label;
  return registration.command_label === "Not configured"
    ? "Target not configured"
    : registration.command_label;
}

function McpStatusPill({ registration }: { registration: McpRegistration }) {
  if (registration.policy_status === "approved")
    return <StatusPill tone="success">Approved</StatusPill>;
  if (registration.policy_status === "denied") return <StatusPill tone="danger">Denied</StatusPill>;
  if (registration.policy_status === "disabled")
    return <StatusPill tone="neutral">Disabled</StatusPill>;
  return <StatusPill tone="warning">Pending review</StatusPill>;
}

function McpFact({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[var(--muted)]">{label}</dt>
      <dd className="mt-1 break-words text-[var(--civic-navy)]">{value}</dd>
    </div>
  );
}

function OriginList({ origins }: { origins: string[] }) {
  if (origins.length === 0) return <span className="text-[var(--danger)]">None configured</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {origins.map((origin) => (
        <StatusPill key={origin} tone="neutral">
          {origin}
        </StatusPill>
      ))}
    </div>
  );
}

function HandleList({ handles }: { handles: string[] }) {
  if (handles.length === 0) return <span className="text-[var(--muted)]">None required</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {handles.map((handle) => (
        <StatusPill key={handle} tone="info">
          {handle}
        </StatusPill>
      ))}
    </div>
  );
}

function emptyPage<T>(): ToolsPage<T> {
  return { items: [], next_cursor: null, has_more: false };
}
