# F13 — Tools, MCP, Browser & Computer Use Policies

Priority: P0  
Depends on: F04, F07, F08, F11

## Objective

Đưa các capability có side effect mạnh của ZCode/Lumi Agents vào organization policy mà không phá local execution.

## Capability classes

- read-only local tools;
- filesystem mutation;
- shell/process execution;
- network access;
- MCP tools;
- browser use;
- computer use;
- credential-bearing integration;
- external messaging/publishing;
- destructive/high-impact action.

## Requirements

### FR-F13-001 — Tool catalog

Control plane stores stable tool/capability identifiers and risk class.

Desktop reports runtime-supported capabilities separately.

### FR-F13-002 — Effective policy

Effective tool access derives from:

```text
platform hard deny
+ org policy
+ project policy
+ agent definition
+ runtime/device capability
+ per-run approval
```

### FR-F13-003 — Default posture

Unknown external tools default deny in managed org mode until classified/approved.

Local personal mode may be more permissive according to product policy.

### FR-F13-004 — MCP

MCP server config includes:

- stable ID;
- source: built-in/plugin/custom;
- transport;
- endpoint/command metadata;
- required secret handles;
- allowed origins/hosts;
- tool list/fingerprint where discoverable;
- policy status.

### FR-F13-005 — Browser use

Policy controls:

- allowed domains;
- blocked domains/categories;
- download/upload;
- authenticated browsing;
- clipboard;
- external submit/purchase/send actions.

### FR-F13-006 — Computer use

Policy controls high-risk desktop capabilities:

- accessibility;
- screen capture;
- keyboard/mouse control;
- shell escalation;
- target application allow/deny where available.

### FR-F13-007 — Approval gates

Tool calls can require:

- no approval;
- session approval;
- every-use approval;
- deny.

Approval event records exact tool + risk-relevant arguments summary before action.

### FR-F13-008 — Secret isolation

Agent/tool receives scoped credential through broker/adapter where possible, not raw org secret.

This follows the good pattern already present in ZCode official MCP auth where host acts as identity authority rather than agent process holding secrets.

### FR-F13-009 — Network egress

Custom MCP/provider/tool URLs must pass SSRF defenses and destination policy.

## Web UX

- tool policy matrix;
- MCP catalog;
- browser policy;
- computer-use policy;
- recent denied/approved actions.

## Threat model

- malicious MCP server;
- prompt injection causing tool exfiltration;
- hidden browser submit;
- credential theft;
- arbitrary localhost/cloud metadata access;
- tool name collision;
- plugin update adding new tools under previously approved identity.

## Acceptance criteria

- A newly discovered tool from an updated MCP cannot silently inherit approval if tool fingerprint/policy requires re-review.
- Denied browser/computer capability cannot be re-enabled by agent prompt.
- Every privileged action is attributable to run + device + principal.
