# P05 managed run protocol v1

- Contract version: `p05-run-v1`
- Consumer: LumiAgents/ZCode managed runtime
- Authority: P05-CG `p05-cg-v1`
- Transport: HTTPS JSON over the existing P02/P03/P04 API

## Runtime context

A managed run request carries correlation metadata, not authorization evidence:

```json
{
  "org_id": "org_...",
  "project_id": "prj_...",
  "device_id": "dvc_...",
  "agent_session_id": "rse_...",
  "run_id": "run_...",
  "agent_definition_id": "agd_...",
  "agent_definition_version": 1,
  "external_id": "zcode-session-123",
  "request_id": "req_..."
}
```

The server resolves the current device token, membership, project visibility, policy snapshot, agent definition version, route version, and budget. A client may omit IDs for a create request; the server creates canonical IDs and returns them. A client-supplied ID is never sufficient to bypass authorization.

## Lifecycle

1. Runtime obtains/refreshes a device token through the P03 flow.
2. Runtime creates an agent session and run through the P05 APIs, or receives a server-created run identity from the desktop host.
3. Runtime sends managed inference with the P04 alias and P05 `agent_session_id`/`run_id` correlation. The server creates the request ID and reservation.
4. Before each privileged tool action, runtime submits a tool decision request containing run/tool-call identity, stable tool ID/fingerprint, capability IDs, risk class, and a bounded redacted arguments summary.
5. Runtime waits for `allow`, `require_*` approval resolution, or `deny`. Missing/malformed/stale/mismatched responses fail closed.
6. Runtime may execute only after an approved decision for the exact binding. It reports result metadata through the next decision/event call; raw secrets and full arguments stay local.
7. Cancel is sent to the control plane and the local execution host. The control plane records a terminal event idempotently; passive runtime disconnect is not assumed to be observable on every platform.

## Decision response

```json
{
  "decision": "require_per_use_approval",
  "approval_id": "apr_...",
  "policy_version": 12,
  "tool_fingerprint": "sha256:...",
  "reason": "approval_required"
}
```

`decision` is one of `allow`, `require_session_approval`, `require_per_use_approval`, or `deny`. The response contains no credential, endpoint secret, prompt, or full tool argument.

## Compatibility

Existing P04 `model_alias` and route contracts remain unchanged. Unmanaged/local personal execution may skip the broker only when it is explicitly outside managed organization mode; it must not claim P05 managed authorization or write managed run history without the control-plane APIs.
