import {
  getToolApprovalMode,
  getToolDecision,
  isToolReviewRequired,
  type McpRegistration,
  type ToolDecision,
  type ToolDefinition,
  type ToolPolicy,
} from "./helpers";
import {
  DecisionBadge,
  LifecyclePill,
  RiskBadge,
  StatusPill,
  ToolCode,
  ToolEmpty,
  ToolError,
  ToolLoading,
  ToolMetric,
  ToolNotice,
  ToolPanel,
  ToolPanelHeader,
  ToolPermission,
  ToolTableCaption,
  humanize,
} from "./ui";

export interface CapabilityMatrixProps {
  tools?: ToolDefinition[];
  policy?: ToolPolicy | null;
  mcpRegistrations?: McpRegistration[];
  loading?: boolean;
  error?: unknown;
  permissionDenied?: boolean;
  onRetry?: () => void;
}

export function CapabilityMatrix({
  tools = [],
  policy,
  mcpRegistrations = [],
  loading = false,
  error,
  permissionDenied = false,
  onRetry,
}: CapabilityMatrixProps) {
  if (permissionDenied) {
    return (
      <ToolPanel ariaLabel="Capability matrix">
        <ToolPanelHeader
          title="Capability matrix"
          description="Server-evaluated access for each stable tool and capability."
        />
        <div className="p-5">
          <ToolPermission message="Your current organization role cannot view tool policy metadata." />
        </div>
      </ToolPanel>
    );
  }
  if (loading) {
    return (
      <ToolPanel ariaLabel="Capability matrix">
        <ToolPanelHeader
          title="Capability matrix"
          description="Server-evaluated access for each stable tool and capability."
        />
        <ToolLoading label="Loading tool definitions and policy decisions…" rows={5} />
      </ToolPanel>
    );
  }
  if (error) {
    return (
      <ToolPanel ariaLabel="Capability matrix">
        <ToolPanelHeader
          title="Capability matrix"
          description="Server-evaluated access for each stable tool and capability."
        />
        <div className="p-5">
          <ToolError error={error} onRetry={onRetry} />
        </div>
      </ToolPanel>
    );
  }

  const decisionCounts = (() => {
    const counts: Record<ToolDecision, number> = {
      allow: 0,
      require_session_approval: 0,
      require_per_use_approval: 0,
      deny: 0,
    };
    let review = 0;
    for (const tool of tools) {
      const decision = getToolDecision(tool, policy);
      if (decision) counts[decision] += 1;
      if (isToolReviewRequired(tool, policy, mcpRegistrations)) review += 1;
    }
    return { counts, review };
  })();
  const capabilities = Array.from(new Set(tools.flatMap((tool) => tool.capability_ids))).slice(
    0,
    16,
  );
  const policyWarning = !policy || !policy.document.valid || policy.policy_state !== "ok";

  return (
    <ToolPanel ariaLabel="Capability matrix">
      <ToolPanelHeader
        title="Capability matrix"
        description="Stable tool identity, capability requirements, risk class, and the current server decision."
        action={
          <StatusPill tone="info">
            {policy ? `Policy v${policy.policy_version || policy.version}` : "Policy unavailable"}
          </StatusPill>
        }
      />
      <div className="space-y-5 p-5">
        {policyWarning ? (
          <ToolNotice tone="danger">
            <span className="font-semibold">Fail-closed policy.</span> The server document is
            missing, malformed, or uses an unsupported schema. Missing or invalid permissions are
            shown as denied; this browser never grants access.
          </ToolNotice>
        ) : (
          <ToolNotice tone="info">
            Decisions are evaluated by the control plane. This view is an inspection surface, not a
            client-side policy override.
          </ToolNotice>
        )}

        {policy ? (
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="font-medium text-[var(--muted)]">Server policy defaults</span>
            <StatusPill
              tone={
                policy.policy_state === "ok" && policy.document.default_posture === "allow"
                  ? "success"
                  : "danger"
              }
            >
              Default posture: {humanize(policy.document.default_posture)}
            </StatusPill>
            <StatusPill
              tone={policy.document.default_approval_mode === "none" ? "info" : "warning"}
            >
              Default approval: {humanize(policy.document.default_approval_mode)}
            </StatusPill>
          </div>
        ) : null}

        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          <ToolMetric
            label="Allow"
            value={String(decisionCounts.counts.allow)}
            detail="No approval gate"
          />
          <ToolMetric
            label="Session approval"
            value={String(decisionCounts.counts.require_session_approval)}
            detail="Approval covers the session"
          />
          <ToolMetric
            label="Per-use approval"
            value={String(decisionCounts.counts.require_per_use_approval)}
            detail="Exact call must be approved"
          />
          <ToolMetric
            label="Deny"
            value={String(decisionCounts.counts.deny)}
            detail="Blocked by policy"
          />
          <ToolMetric
            label="Review queue"
            value={String(decisionCounts.review)}
            detail="New or changed identity"
          />
        </div>

        {capabilities.length > 0 ? (
          <div>
            <p className="text-xs font-semibold tracking-[0.08em] text-[var(--muted)]">
              CAPABILITIES IN CATALOG
            </p>
            <div className="mt-2 flex flex-wrap gap-2">
              {capabilities.map((capability) => (
                <StatusPill key={capability} tone="neutral">
                  {humanize(capability)}
                </StatusPill>
              ))}
            </div>
          </div>
        ) : null}

        {tools.length === 0 ? (
          <ToolEmpty
            title="No tool definitions"
            description="The organization has no stable tool catalog entries yet. Unknown tools remain denied until the server classifies and reviews them."
          />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-[var(--border)]">
            <table className="w-full min-w-[920px] text-left text-sm">
              <ToolTableCaption>
                Tool capability and risk matrix with server-returned policy decisions
              </ToolTableCaption>
              <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
                <tr>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Tool
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Source
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Capabilities
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Risk
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Decision
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Identity binding
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {tools.map((tool) => {
                  const decision = getToolDecision(tool, policy);
                  const policyMode = getToolApprovalMode(tool, policy);
                  const reviewRequired = isToolReviewRequired(tool, policy, mcpRegistrations);
                  return (
                    <tr key={tool.tool_id} className="align-top">
                      <td className="px-4 py-4">
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="font-medium text-[var(--civic-navy)]">{tool.name}</p>
                          <LifecyclePill lifecycle={tool.lifecycle} />
                        </div>
                        <ToolCode>{tool.tool_id}</ToolCode>
                      </td>
                      <td className="px-4 py-4 text-[var(--muted-strong)]">
                        {humanize(tool.source)}
                        {tool.mcp_id ? (
                          <span className="mt-1 block text-xs text-[var(--muted)]">
                            MCP registration
                          </span>
                        ) : null}
                      </td>
                      <td className="px-4 py-4">
                        {tool.capability_ids.length === 0 ? (
                          <span className="text-xs text-[var(--muted)]">No capability tags</span>
                        ) : (
                          <div className="flex max-w-[220px] flex-wrap gap-1.5">
                            {tool.capability_ids.map((capability) => (
                              <StatusPill key={capability} tone="neutral">
                                {humanize(capability)}
                              </StatusPill>
                            ))}
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-4">
                        <RiskBadge riskClass={tool.risk_class} />
                      </td>
                      <td className="px-4 py-4">
                        <div className="flex flex-col items-start gap-2">
                          {policyWarning ? (
                            <StatusPill tone="danger">Fail closed</StatusPill>
                          ) : (
                            <DecisionBadge decision={decision} />
                          )}
                          {reviewRequired ? (
                            <StatusPill tone="warning">Review required</StatusPill>
                          ) : null}
                          {policyMode ? (
                            <span className="text-xs text-[var(--muted)]">
                              Policy layer: {humanize(policyMode)}
                            </span>
                          ) : null}
                        </div>
                      </td>
                      <td className="px-4 py-4">
                        <ToolCode>{tool.fingerprint}</ToolCode>
                        <p className="mt-1 text-xs text-[var(--muted)]">
                          Approval is bound to this fingerprint.
                        </p>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        <p className="text-xs leading-5 text-[var(--muted)]">
          A changed fingerprint, unknown privileged tool, or pending MCP review never inherits an
          earlier approval. The execution host must receive a fresh server decision for the exact
          call.
        </p>
      </div>
    </ToolPanel>
  );
}
