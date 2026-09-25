# Contract Gate — P05-CG

- Phase: P05 — Runs, sessions, tool policy, usage, budgets
- Owner: P05 coordinator
- State: frozen
- Contract version: `p05-cg-v1`
- Inputs: Plan00, Plan05, F04, F07, F08, F10, F11, F12, F13, F16, F21, F23, ADR 0001–0005, P03-CG `p03-cg-v1`, P04-CG `p04-cg-v1`, P03-IG, and P04-IG
- Preconditions: P03 and P04 stable handoffs are merged; P04 conditional local downstream-disconnect limitation remains an explicit runtime follow-up and is not redefined here
- Additive clarifications: `docs/implementation/change-requests/P05-CR-001.md`, `docs/implementation/change-requests/P05-CR-002.md`
- Shared-file owner: P05 coordinator

## Purpose and scope

P05 adds the first managed-agent control loop:

```text
principal + device + project
→ agent session/run
→ managed inference alias
→ tool/MCP/browser/computer decision
→ approval
→ usage/cost reservation and reconciliation
→ immutable run timeline and audit
→ visible control-plane state
```

P05 does not move local desktop execution, shell, browser, computer-use, or MCP execution into the Worker. The desktop/runtime remains the execution host; the control plane is the policy, approval, accounting, and audit authority.

## P05-CR-002 integration clarifications

The additive clarifications in `docs/implementation/change-requests/P05-CR-002.md` are normative for implementation:

- managed device run lifecycle and tool-result routes are part of the device API;
- Run projections carry `version`, `state_version`, policy snapshot/version, workspace binding, cancel time, and resume lineage;
- RunEvent envelopes carry org/project/request/device/agent-session correlation and use P01-compatible actor types;
- approvals bind fingerprint, argument hash, policy version, and atomically consume per-use grants;
- tool policy has typed rules and project scope;
- browser clients cannot submit authoritative cost/reservation/reconciliation values; internal accounting operations are server-owned;
- inference usage remains P04 request-scoped, while non-inference run usage uses the additive `run_usage_events` source;
- dashboard summary/rollup/denial reads and audit run correlation are additive;
- P03 policy transport gains versioned budget/rate sections through a coordinated compiler extension.

Where the initial tables below describe a broader shape, P05-CR-002's narrower security and compatibility rules control.

## Domain vocabulary

| Concept | Stable name | Meaning |
|---|---|---|
| Agent definition | `AgentDefinition` | Versioned minimum agent policy/configuration record; instructions are references, not inline prompt content. |
| Conversational/work session | `Session` | Durable cloud-visible conversation/work context. It is distinct from a P02 `LoginSession`. |
| Execution attempt | `Run` | One immutable historical execution attempt within a `Session`. A retry creates a new `Run`. |
| Timeline record | `RunEvent` | Append-only, sequence-numbered metadata event belonging to one `Run`. |
| Artifact reference | `ArtifactRef` | Metadata reference to local-only, uploaded, or external output; no authoritative content is stored in the control plane by default. |
| Tool call reference | `ToolCallRef` | Stable identity and result metadata for a runtime tool invocation. |
| Tool/capability catalog entry | `ToolDefinition` / `CapabilityDefinition` | Stable identity, source, risk class, and policy metadata for a runtime capability. |
| MCP registration | `McpRegistration` | Non-secret metadata for a built-in, plugin, or custom MCP source. |
| Approval request | `ApprovalRequest` | Pending or resolved approval for a session-scoped or per-use privileged action. |
| Usage event | `UsageEvent` | Immutable inference/run accounting event; P04 usage rows remain the source shape and P05 adds source/reconciliation metadata. |
| Cost record | `CostRecord` | Immutable cost calculation tied to one usage event and pricing version. |
| Budget | `Budget` | Organization-scoped soft/hard spend limit for a defined scope and period. |
| Budget reservation | `BudgetReservation` | Bounded pre-dispatch hold, committed or released after terminal run/inference state. |
| Rate/concurrency policy | `RateLimitPolicy` | Requests/tokens/concurrency limits applied by scope. |

`Session` IDs use the P05 `rse_` prefix so they cannot be confused with P02 login-session IDs (`ses_`). P04's existing `session_id` correlation continues to mean the authenticated P02 session; P05's cloud work context is always named `agent_session_id` in P05-owned APIs/events.

## IDs, ownership, and time

- IDs use `<prefix>_<32 lowercase hexadecimal characters>` and are opaque to clients.
- P05 prefixes: `agd_` AgentDefinition, `rse_` Session, `run_` Run, `rev_` RunEvent, `art_` ArtifactRef, `tcl_` ToolCallRef, `mcp_` McpRegistration, `apr_` ApprovalRequest, `cap_` CapabilityDefinition, `tool_` ToolDefinition, `bgt_` P05 budget-policy record when a distinct ID is needed, and `rlp_` RateLimitPolicy. P04's existing `bud_` namespace remains valid for its existing `Budget` and `BudgetReservation` rows; type is determined by the table/contract, not by the prefix alone.
- All organization-owned rows carry `org_id`; managed `Session` and `Run` rows also carry a non-null `project_id` and an explicit `device_id` or execution-host identity.
- A client-supplied ID is correlation input only. The server resolves current principal, active membership, organization, project/device scope, and current policy before mutation.
- Timestamps are RFC 3339 UTC text. Costs are integer minor units plus explicit currency and pricing version. Sequence numbers are monotonically increasing positive integers per run.
- Prompt, response, tool argument, file content, credential, and secret material are not stored in RunEvent payloads by default. Payloads are bounded metadata with a documented redaction policy.

## Central authorization and permissions

P05 extends the P02 authorization registry; handlers MUST call the centralized decision path and MUST NOT compare role strings.

Stable P05 permissions:

- `agents.read`
- `agents.manage`
- `sessions.read`
- `sessions.manage`
- `runs.read`
- `runs.start`
- `runs.cancel`
- `tools.read`
- `tools.manage`
- `approvals.read`
- `approvals.resolve`
- `usage.read`
- `budgets.read`
- `budgets.manage`
- `audit.read`

Default role additions:

- `owner`: all P05 permissions.
- `admin`: all P05 permissions.
- `member`: read/start/cancel permitted subject to project visibility, active membership, device/policy checks, and budget; tool management and approval resolution remain restricted.
- `viewer`: read-only P05 permissions where project visibility permits.
- Unknown permissions, inactive membership, stale membership version, suspended org, archived project, revoked device, or resource-organization mismatch deny by default.

Approval resolution requires `approvals.resolve` plus current project/org scope. A run creator cannot bypass approval by supplying a client decision. Membership removal, device revocation, or policy expiry prevents new tool execution and requires a new authorization check for resume/retry.

## State machines

### Session

```text
active → closed
active → archived
```

Closing or archiving prevents new runs but preserves events, usage, and audit. Resume/retry never revives a closed session without creating/validating a new run under current policy.

### Run

Canonical states:

```text
queued
→ dispatching
→ running
→ waiting_user
→ waiting_approval
→ succeeded
queued|dispatching|running|waiting_user|waiting_approval
→ failed
queued|dispatching|running|waiting_user|waiting_approval
→ cancelled
queued|dispatching|running|waiting_user|waiting_approval
→ timed_out
```

Only server-side transition functions may change state. Terminal states are immutable. `waiting_*` states may return to `running` only through a validated transition after the corresponding event/approval. A retry always inserts a new `Run` with `parent_run_id` and a strictly increasing `attempt`; it never edits the prior run's state, events, usage, or error. Cancel is idempotent; a second cancel returns the existing terminal result.

### Tool decision

```text
allow
require_session_approval
require_per_use_approval
deny
```

The decision is calculated in this order:

```text
platform hard deny
→ org/project policy
→ agent definition
→ runtime/device capability
→ session/per-use approval
```

The most restrictive applicable result wins. An unknown or newly discovered privileged tool in managed organization mode is `deny` or `require_per_use_approval` until catalog fingerprint and policy review complete. A prompt, model output, tool result, or client header cannot turn `deny` into `allow`.

### Budget reservation

```text
reserved → committed
reserved → released
reserved → expired
```

A hard budget is checked and reserved before eligible cloud dispatch. If authoritative hard-budget state cannot be read, cloud inference fails closed with `budget_state_unavailable`; local-only execution is not failed solely for cloud budget unavailability. Reservation amounts are bounded estimates, never unbounded floats. Reconciliation is idempotent by request/run identity.

## Contract schemas

### AgentDefinition

```json
{
  "id": "agd_0123456789abcdef0123456789abcdef",
  "org_id": "org_0123456789abcdef0123456789abcdef",
  "project_id": null,
  "name": "Coding agent",
  "description": "Repository-aware coding assistant",
  "instructions_ref": "local://agent/instructions/v1",
  "default_model_alias": "coding-default",
  "required_capabilities": ["text", "tools"],
  "allowed_tool_ids": ["tool_0123456789abcdef0123456789abcdef"],
  "runtime_requirements": ["filesystem_read"],
  "lifecycle": "active",
  "version": 1,
  "created_at": "2026-09-25T12:00:00.000Z",
  "updated_at": "2026-09-25T12:00:00.000Z"
}
```

`instructions_ref` is an opaque reference, not inline instructions. `allowed_tool_ids` is an intersection constraint, never a way to broaden org/platform policy. `project_id` may be null for an org-level reusable definition; managed runs still resolve a concrete project.

### Session

```json
{
  "id": "rse_0123456789abcdef0123456789abcdef",
  "org_id": "org_0123456789abcdef0123456789abcdef",
  "project_id": "prj_0123456789abcdef0123456789abcdef",
  "device_id": "dvc_0123456789abcdef0123456789abcdef",
  "workspace_binding_id": "wsb_0123456789abcdef0123456789abcdef",
  "agent_definition_id": "agd_0123456789abcdef0123456789abcdef",
  "agent_definition_version": 1,
  "external_id": "zcode-session-123",
  "title": "Fix issue 42",
  "lifecycle": "active",
  "version": 1,
  "created_at": "2026-09-25T12:00:00.000Z",
  "updated_at": "2026-09-25T12:00:00.000Z"
}
```

`external_id` preserves a ZCode/LumiAgents task/session reference for migration and debugging. The cloud `Session` is not the browser `LoginSession`.

### Run

```json
{
  "id": "run_0123456789abcdef0123456789abcdef",
  "org_id": "org_0123456789abcdef0123456789abcdef",
  "project_id": "prj_0123456789abcdef0123456789abcdef",
  "agent_session_id": "rse_0123456789abcdef0123456789abcdef",
  "parent_run_id": null,
  "attempt": 1,
  "agent_definition_id": "agd_0123456789abcdef0123456789abcdef",
  "agent_definition_version": 1,
  "principal_user_id": "usr_0123456789abcdef0123456789abcdef",
  "device_id": "dvc_0123456789abcdef0123456789abcdef",
  "model_alias": "coding-default",
  "route_id": "rte_0123456789abcdef0123456789abcdef",
  "route_version_id": "rtv_0123456789abcdef0123456789abcdef",
  "state": "running",
  "failure_code": null,
  "request_id": "req_0123456789abcdef0123456789abcdef",
  "started_at": "2026-09-25T12:00:00.000Z",
  "finished_at": null,
  "created_at": "2026-09-25T12:00:00.000Z",
  "updated_at": "2026-09-25T12:00:00.000Z"
}
```

The server chooses request IDs, policy snapshots, route versions, and current authorization. A client may supply a parent run only for an authorized retry.

### RunEvent

```json
{
  "id": "rev_0123456789abcdef0123456789abcdef",
  "run_id": "run_0123456789abcdef0123456789abcdef",
  "sequence": 4,
  "event_type": "tool.approval_requested.v1",
  "occurred_at": "2026-09-25T12:00:01.000Z",
  "actor_type": "device",
  "actor_id": "dvc_0123456789abcdef0123456789abcdef",
  "correlation_id": "req_0123456789abcdef0123456789abcdef",
  "tool_call_id": "tcl_0123456789abcdef0123456789abcdef",
  "approval_id": "apr_0123456789abcdef0123456789abcdef",
  "payload": {
    "risk_class": "external_side_effect",
    "arguments_summary": "domain=example.test; operation=submit"
  }
}
```

`UNIQUE(run_id, sequence)` and append-only database triggers are required. Normal product APIs cannot update/delete RunEvent rows. Payloads are bounded and redacted; a `content_ref` may point to separately governed storage.

### Tool, capability, and MCP policy

`ToolDefinition` contains `tool_id`, stable `name`, `source`, `risk_class`, `capability_ids`, `fingerprint`, and lifecycle. Risk classes are:

```text
read_only
filesystem_write
process_execution
network
mcp
browser
computer
credential_bearing
external_side_effect
destructive
```

`McpRegistration` contains `mcp_id`, `source` (`built_in|plugin|custom`), transport, non-secret endpoint/command metadata, allowed origins, required secret handles, tool fingerprint/list, policy status, and version. Secrets are handles only. New tools/fingerprints under an updated registration require re-evaluation.

The P03 `PolicySnapshot` extension is:

```json
{
  "tools": {
    "schema_version": 1,
    "default_posture": "deny",
    "tool_ids": [],
    "mcp_ids": [],
    "browser": {
      "allowed_domains": [],
      "blocked_domains": [],
      "allow_download": false,
      "allow_upload": false,
      "allow_authenticated": false,
      "allow_clipboard": false,
      "external_submit": "deny"
    },
    "computer": {
      "allow_accessibility": false,
      "allow_screen_capture": false,
      "allow_keyboard_mouse": false,
      "allow_shell_escalation": false,
      "allowed_applications": []
    }
  }
}
```

Malformed or unsupported schema versions fail closed for managed tool execution. A missing section is not authority to allow tools.

### ApprovalRequest

```json
{
  "id": "apr_0123456789abcdef0123456789abcdef",
  "org_id": "org_0123456789abcdef0123456789abcdef",
  "project_id": "prj_0123456789abcdef0123456789abcdef",
  "run_id": "run_0123456789abcdef0123456789abcdef",
  "tool_call_id": "tcl_0123456789abcdef0123456789abcdef",
  "tool_id": "tool_0123456789abcdef0123456789abcdef",
  "risk_class": "external_side_effect",
  "approval_mode": "per_use",
  "status": "pending",
  "arguments_summary": "domain=example.test; operation=submit",
  "requested_by_principal_id": "usr_0123456789abcdef0123456789abcdef",
  "requested_at": "2026-09-25T12:00:01.000Z",
  "expires_at": "2026-09-25T12:15:01.000Z",
  "resolved_by_principal_id": null,
  "resolved_at": null,
  "resolution_reason": null,
  "version": 1
}
```

Only `pending → approved|denied|expired|cancelled` is valid. Resolution is idempotent by request ID, version, and idempotency key. An approval is bound to exact tool ID, fingerprint, run, and arguments summary; it cannot be replayed for a changed tool set or changed high-impact arguments.

### Usage, cost, and budget

P05 extends the P04 `usage_events` source with `source` (`inference|run`), `external_id`, and reconciliation state without changing the frozen P04 fields. `CostRecord` is append-only and stores `usage_event_id`, pricing source/version/effective time, input/output/cached token basis, minor-unit cost, currency, and calculation kind (`estimated|actual|recalculated`). A recalculation is a new record; historical rows are never overwritten.

P05 budget APIs operate on the P04 `budgets`/`budget_reservations` tables and add scope/rate/concurrency policy support without creating a second reservation system. A reservation is keyed by request/run identity, has a bounded amount and expiry, and transitions monotonically. D1 conditional insert/update is the P05 baseline for hard-budget concurrency; a Durable Object requires a measured serialization need and an ADR.

## API

All routes are under `/api/v1`, use the P01 error envelope and `X-Request-ID`, require P02 session/CSRF for browser mutations, and enforce active org membership. Device routes use `Authorization: DeviceToken` and never rely on caller-supplied org/project authority. Collections use opaque cursor pagination with bounded limits.

### Agent/session/run APIs

| Method | Path | Permission/context | Request | Success |
|---|---|---|---|---|
| GET | `/orgs/{org_id}/agents` | `agents.read` | `limit?,cursor?,project_id?` | `200 Page<AgentDefinition>` |
| POST | `/orgs/{org_id}/agents` | `agents.manage` + Idempotency-Key | `{name,description?,instructions_ref?,default_model_alias?,required_capabilities?,allowed_tool_ids?,runtime_requirements?,project_id?}` | `201 AgentDefinition` |
| GET | `/orgs/{org_id}/agents/{agent_id}` | `agents.read` + scope | — | `200 AgentDefinition` |
| PATCH | `/orgs/{org_id}/agents/{agent_id}` | `agents.manage` + `version` | mutable metadata/config fields | `200 AgentDefinition` |
| GET | `/orgs/{org_id}/sessions` | `sessions.read` | `limit?,cursor?,project_id?,lifecycle?` | `200 Page<Session>` |
| POST | `/orgs/{org_id}/sessions` | `sessions.manage` + Idempotency-Key | `{project_id,device_id,workspace_binding_id?,agent_definition_id,agent_definition_version?,external_id?,title?}` | `201 Session` |
| GET | `/orgs/{org_id}/sessions/{session_id}` | `sessions.read` + scope | — | `200 Session` |
| POST | `/orgs/{org_id}/sessions/{session_id}/close` | `sessions.manage` + Idempotency-Key | `{version}` | `200 Session` |
| GET | `/orgs/{org_id}/runs` | `runs.read` | `limit?,cursor?,project_id?,session_id?,state?` | `200 Page<Run>` |
| POST | `/orgs/{org_id}/runs` | `runs.start` + active device/project + Idempotency-Key | `{agent_session_id,model_alias?,input_ref?,parent_run_id?}` | `201 Run` |
| GET | `/orgs/{org_id}/runs/{run_id}` | `runs.read` + scope | — | `200 Run` |
| POST | `/orgs/{org_id}/runs/{run_id}/cancel` | `runs.cancel` + Idempotency-Key | `{version,reason?}` | `200 Run` |
| POST | `/orgs/{org_id}/runs/{run_id}/retry` | `runs.start` + current policy + Idempotency-Key | `{version}` | `201 Run` |
| GET | `/orgs/{org_id}/runs/{run_id}/events` | `runs.read` | `limit?,cursor?,after_sequence?` | `200 Page<RunEvent>` |
| POST | `/orgs/{org_id}/runs/{run_id}/artifacts` | `runs.start` + Idempotency-Key | `{kind,content_ref?,mime_type?,size_bytes?,checksum?,retention_policy?}` | `201 ArtifactRef` |
| GET | `/orgs/{org_id}/runs/{run_id}/artifacts` | `runs.read` | `limit?,cursor?` | `200 Page<ArtifactRef>` |

`POST /runs` creates a queued/dispatching record and performs current policy, device, project, rate, and budget checks before eligible cloud dispatch. A local-only run may record state without a cloud budget reservation; it still receives a visible run/timeline and must not be represented as managed cloud inference.

P05-CR-002 adds the device-token equivalents under `/api/v1/devices/sessions` and `/api/v1/devices/runs`, including start/complete/fail/cancel, event reads, and tool-call result/consumption. The device's token-derived organization and workspace binding are authoritative; no body field can replace them.

### Tool/policy/approval APIs

| Method | Path | Permission/context | Request | Success |
|---|---|---|---|---|
| GET | `/orgs/{org_id}/tools` | `tools.read` | `limit?,cursor?,source?,risk_class?` | `200 Page<ToolDefinition>` |
| POST | `/orgs/{org_id}/tools` | `tools.manage` + Idempotency-Key | `{name,source,risk_class,capability_ids,fingerprint,metadata?}` | `201 ToolDefinition` |
| PATCH | `/orgs/{org_id}/tools/{tool_id}` | `tools.manage` + `version` | `{lifecycle?,risk_class?,capability_ids?,fingerprint?}` | `200 ToolDefinition` |
| GET | `/orgs/{org_id}/mcp` | `tools.read` | `limit?,cursor?` | `200 Page<McpRegistration>` |
| POST | `/orgs/{org_id}/mcp` | `tools.manage` + Idempotency-Key | `{source,transport,endpoint_metadata?,command_metadata?,allowed_origins?,required_secret_handles?,tool_fingerprint?}` | `201 McpRegistration` |
| PATCH | `/orgs/{org_id}/mcp/{mcp_id}` | `tools.manage` + `version` | mutable policy/status fields | `200 McpRegistration` |
| GET | `/orgs/{org_id}/policy/tools` | `tools.read` | — | `200 ToolPolicy` |
| PUT | `/orgs/{org_id}/policy/tools` | `tools.manage` + `version` | tool/browser/computer policy document | `200 ToolPolicy` |
| POST | `/runs/{run_id}/tool-decisions` | device token + `runs.start` + current policy | `{tool_call_id,tool_id,tool_fingerprint,capability_ids,risk_class,arguments_summary}` | `200 {decision,approval_id?,policy_version}` |
| GET | `/orgs/{org_id}/approvals` | `approvals.read` | `limit?,cursor?,status?,run_id?` | `200 Page<ApprovalRequest>` |
| GET | `/orgs/{org_id}/approvals/{approval_id}` | `approvals.read` + scope | — | `200 ApprovalRequest` |
| POST | `/orgs/{org_id}/approvals/{approval_id}/resolve` | `approvals.resolve` + CSRF + Idempotency-Key | `{decision,reason?,version}` | `200 ApprovalRequest` |

The tool-decision endpoint is a broker boundary, not a client override. It evaluates the current policy and returns no secret. For a privileged action, the execution host must not proceed until it receives a valid `approved` decision tied to the exact call.

### Usage/budget APIs

| Method | Path | Permission/context | Request | Success |
|---|---|---|---|---|
| GET | `/orgs/{org_id}/usage` | `usage.read` | `limit?,cursor?,project_id?,run_id?,from?,to?` | `200 Page<UsageEvent>` |
| GET | `/orgs/{org_id}/usage/summary` | `usage.read` | `project_id?,from?,to?` | `200 UsageSummary` |
| GET | `/orgs/{org_id}/usage/rollups` | `usage.read` | `period=hour\|day\|month,from?,to?` | `200 Page<UsageRollup>` |
| GET | `/orgs/{org_id}/usage/denials` | `usage.read` | `limit?,cursor?,from?,to?` | `200 Page<BudgetDenial>` |
| POST | `/orgs/{org_id}/usage/reconcile` | internal service identity + Idempotency-Key (not browser) | `{request_id|run_id,external_id?,actual_cost_minor?,provider_usage?}` | `200 {usage_event,cost_record}` |
| GET | `/orgs/{org_id}/budgets` | `budgets.read` | `limit?,cursor?,scope_type?,scope_id?` | `200 Page<Budget>` |
| POST | `/orgs/{org_id}/budgets` | `budgets.manage` + Idempotency-Key | `{scope_type,scope_id?,period_start,period_end,limit_minor,currency,hard}` | `201 Budget` |
| PATCH | `/orgs/{org_id}/budgets/{budget_id}` | `budgets.manage` + `version` | mutable limit/period/lifecycle fields | `200 Budget` |
| GET | `/orgs/{org_id}/budgets/{budget_id}` | `budgets.read` + scope | — | `200 Budget` |
| POST | `/orgs/{org_id}/budgets/{budget_id}/reservations` | internal inference-engine identity + Idempotency-Key (not browser) | `{request_id,run_id?,reserved_minor,expires_at}` | `201 BudgetReservation` |
| POST | `/orgs/{org_id}/budgets/{budget_id}/reservations/{reservation_id}/reconcile` | internal/service identity + Idempotency-Key (not browser) | `{actual_minor,status}` | `200 BudgetReservation` |
| GET | `/orgs/{org_id}/rate-limits` | `budgets.read` | — | `200 Page<RateLimitPolicy>` |
| PUT | `/orgs/{org_id}/rate-limits/{scope_type}/{scope_id}` | `budgets.manage` + `version` | rate/concurrency policy | `200 RateLimitPolicy` |

All budget mutations use optimistic `version`; reservation/reconciliation uses idempotency and request identity. A reservation is never silently reused for a different request/run.

### Run event/artifact API details

Run events are read-only to product clients. There is no endpoint to edit or delete an event. Artifact content is returned only through an authorized content reference; the control plane stores metadata and retention class, not raw file bytes.

## Permissions and policy precedence

P05 uses the P02 centralized authorization service. Resource scope checks are performed after permission checks, and policy evaluation is performed again at run start/resume and at every sensitive tool use. Platform hard deny cannot be overridden by org policy, agent configuration, model output, or client request.

The P03 policy snapshot remains the transport authority. P05 extends its `tools` section and adds a versioned `budgets`/rate section without redefining P03 `org_access`, `projects`, or `min_client_version`:

```json
{
  "budgets": {
    "schema_version": 1,
    "hard_fail_closed": true,
    "scope_ids": []
  },
  "rate_limits": {
    "schema_version": 1,
    "policies": []
  }
}
```

P03 schema-0 placeholders remain non-authoritative. A malformed P05 section fails closed for managed cloud inference/tool execution; local personal execution may continue only when it does not claim managed authorization.

## Events and audit

P05 event names are stable and versioned:

- `agent_definition.created.v1`
- `agent_definition.updated.v1`
- `session.created.v1`
- `session.closed.v1`
- `run.created.v1`
- `run.state_changed.v1`
- `run.started.v1`
- `run.completed.v1`
- `run.failed.v1`
- `run.cancelled.v1`
- `run.retried.v1`
- `run.event_appended.v1`
- `tool.catalog_updated.v1`
- `tool.mcp_registration_changed.v1`
- `tool.decision_recorded.v1`
- `tool.result.v1`
- `tool.denied.v1`
- `approval.requested.v1`
- `approval.resolved.v1`
- `usage.reconciled.v1`
- `budget.reserved.v1`
- `budget.reconciled.v1`
- `budget.denied.v1`
- `rate_limit.denied.v1`
- `artifact.created.v1`

RunEvent records are the ordered execution timeline. Security-critical mutations also append F16 audit events with actor, effective user, device/session/request ID, resource, outcome, stable reason, and correlation/run IDs. Audit metadata excludes prompt/response/tool-argument bodies and all secret values.

## Persistence skeleton

Migration `0010_p05_runs_tools_usage_control.sql` creates or extends:

- `agent_definitions`, `agent_sessions`, `runs`, `run_events`, `artifact_refs`, `tool_call_refs`;
- `tool_definitions`, `capability_definitions`, `mcp_registrations`, `tool_policies`;
- `approval_requests`;
- `cost_records`, `run_usage_events`, `run_cost_records`, `usage_rollups` (derived/rebuildable), `rate_limit_policies`;
- P05 additions to P04 `usage_events` and reservation reconciliation columns where additive.

Invariant-bearing constraints include:

- `(org_id, project_id, run_id, sequence)` uniqueness for RunEvent ordering;
- append-only triggers for RunEvent, UsageEvent, CostRecord, and audit/event records;
- unique active external session mapping per org/device;
- unique `(run_id, tool_call_id)` and exact tool fingerprint binding for approvals;
- unique idempotent reservation `(org_id, request_id/run_id)`;
- budget/version predicates for all mutable budget/policy rows;
- tenant/org foreign keys and indexes for every protected query.

D1 is canonical. Reservation creation uses a conditional insert/update against current committed usage plus live reservations. A Durable Object is not introduced unless a measured race/serialization benchmark shows D1 cannot satisfy the hard-budget invariant.

## Error semantics

Existing P01/P02/P03/P04 codes remain unchanged. P05 adds stable machine-readable reasons/codes:

- `agent_not_found`
- `session_not_found`
- `run_not_found`
- `invalid_run_transition`
- `run_terminal`
- `run_retry_not_allowed`
- `run_cancel_not_allowed`
- `project_access_denied`
- `device_not_approved`
- `device_revoked`
- `tool_not_found`
- `tool_fingerprint_changed`
- `tool_denied`
- `approval_required`
- `approval_not_found`
- `approval_already_resolved`
- `approval_expired`
- `mcp_source_not_allowed`
- `mcp_tool_requires_review`
- `browser_action_denied`
- `computer_action_denied`
- `budget_exceeded`
- `budget_state_unavailable`
- `reservation_not_found`
- `reservation_already_reconciled`
- `rate_limit_exceeded`
- `concurrency_limit_exceeded`
- `usage_reconciliation_conflict`
- `artifact_not_found`

Handlers return the P01 envelope and `X-Request-ID`; clients branch on codes/reasons, never English messages. Inaccessible cross-tenant IDs use the same not-found/denied shape wherever an ID could otherwise be an existence oracle.

## Fixtures

The frozen machine-readable fixture is `docs/implementation/fixtures/p05-managed-run-v1.json`. The frozen P05 fixture uses opaque, obviously synthetic values and a development-only mock execution host:

- Org A, Project A, enrolled active Device A, AgentDefinition A, Session A.
- Org B and a revoked Device B for tenant/revocation negatives.
- `tool_readonly_repo` (`read_only`, allow).
- `tool_browser_submit` (`external_side_effect`, per-use approval).
- `tool_unknown_privileged` (unknown fingerprint, managed-mode deny/re-review).
- `mcp_fixture` source `custom`, transport `http`, non-secret endpoint metadata, one stable tool fingerprint.
- A managed mock inference route using `coding-default` and a budget with a small hard limit.
- Run events: queued, dispatching, running, approval requested, approval resolved, tool allowed, usage recorded, succeeded.
- A retry fixture linked to a failed run and a second reservation/usage event.

No fixture contains a real secret, raw credential, prompt body, or external endpoint credential.

## Compatibility and migration

- P01/P02 authorization, P03 policy/device/project contracts, P04 catalog/credential/route/inference contracts, stable aliases, request IDs, error envelope, cursor shape, and idempotency projections remain unchanged.
- P04 `session_id` remains the authenticated login-session correlation in P04 inference records. P05 uses `agent_session_id` for its durable work context and may pass both through usage/run correlation.
- P04 usage/reservation tables remain canonical; P05 adds source/reconciliation metadata and cost records without rewriting historical P04 rows.
- P03 opaque `tools.schema_version: 0` is not an allow decision. P05 schema version 1 is required for managed tool execution.
- Migration expectations: apply `0010_p05_runs_tools_usage_control.sql` after `0009`; forward-only repair is the rollback strategy, consistent with prior phases.
- LumiAgents/ZCode mapping preserves external session/task IDs and tool source/fingerprint metadata. The control plane does not reinterpret vendor provider/model IDs.

## Freeze and change rule

- Contract Gate file: `docs/implementation/gates/P05-CG.md`
- Contract version: `p05-cg-v1`
- Freeze commit: `b5a5ea8`
- Unlocked packets: `P05-MOD-01..04`, `P05-BE-01..04`, `P05-FE-01..03`, `P05-INT-01..04`, `P05-QA-01`
- Shared files: P05 coordinator owns router registration, module/permission registries, migrations, package manifests, and STATUS.

After freeze, dependent packets MUST NOT silently redefine these names, states, precedence, or API paths. Any necessary breaking or additive contract change requires `docs/implementation/templates/change-request.md`, dependency review, and an explicit compatibility decision.
