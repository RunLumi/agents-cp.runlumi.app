# Plan 05 — Runs, sessions, tool policy, usage, budgets

Status: Complete (conditional gate) — Contract Gate `p05-cg-v1` frozen at `b5a5ea8`; implementation, external integration, and the fresh-D1 managed control-loop smoke are complete. P05 Integration Gate is a conditional PASS; public CUA/browser execution and passive cancellation remain explicit limitations.
Specs: F08, F12, F13, F16, F21
Depends on: P03, P04

## 1. Phase outcome

A managed LumiAgents run is traceable end-to-end:

```text
principal/device/project
→ session/run
→ model route/inference
→ tool/MCP/browser/computer decisions
→ usage/budget
→ audit/timeline
```

This is the first full control-plane value loop.

## 2. Contract Gate — P05-CG

Freeze:

- Session/Run states;
- RunEvent envelope + sequence;
- AgentDefinition minimal schema;
- tool/capability IDs and risk classes;
- approval decision schema;
- UsageEvent/CostRecord;
- Budget/Reservation;
- rate-limit denial codes;
- policy snapshot sections for models/tools/budgets.

## 3. Modules lane

### P05-MOD-01 — Session/run state machine

Implement monotonic transitions and retry/resume semantics.

Retry = new run attempt, never overwrite failed history.

### P05-MOD-02 — Tool policy evaluator

Input:

- org/project policy;
- agent definition;
- runtime capability;
- tool identity/risk;
- run context.

Output:

- allow;
- deny;
- require session approval;
- require per-use approval.

### P05-MOD-03 — Budget engine

Implement:

- scopes: org/project/user/service identity;
- soft/hard;
- reservation;
- reconciliation;
- expiration;
- rate limits/concurrency.

For hard budget correctness under concurrency, benchmark D1-only approach. Introduce a Durable Object coordinator only if required by measured race/serialization needs.

### P05-MOD-04 — Usage/cost model

Immutable raw events with pricing version.

Historical cost remains explainable after price updates.

## 4. Backend lane

### P05-BE-01 — Run/session APIs

Implement:

- create/list/detail;
- start/cancel/retry;
- event timeline;
- artifact metadata reference;
- server-side current policy evaluation.

### P05-BE-02 — Tool policy APIs

Implement:

- tool catalog;
- MCP registrations/policy;
- browser policy;
- computer-use policy;
- approval create/resolve.

### P05-BE-03 — Usage/budget APIs

Implement:

- usage ingest from inference and runs;
- reservation/reconcile;
- rollups;
- budget CRUD;
- rate/concurrency checks;
- usage dashboard queries.

### P05-BE-04 — Audit integration

Ensure critical events:

- run start/cancel;
- approval;
- privileged tool denial/allow;
- budget denial;
- credential route selection metadata where safe.

## 5. Frontend lane

### P05-FE-01 — Runs

Build:

- run/session list;
- timeline;
- status;
- selected model/provider;
- tool events;
- usage;
- failure reason;
- retry/cancel.

### P05-FE-02 — Tool/MCP policies

Build:

- capability matrix;
- MCP entries;
- approval mode;
- browser/computer policies;
- recent denies.

### P05-FE-03 — Usage/budgets

Build:

- current usage/spend;
- breakdown;
- budget progress;
- hard/soft state;
- denied requests;
- basic trend.

Charts remain lazy and decision-oriented.

## 6. LumiAgents integration lane

### P05-INT-01 — Run identity propagation

Every managed run sends:

- org;
- project;
- device;
- session/run correlation;
- agent definition/version where applicable.

### P05-INT-02 — Tool decision broker

Before managed privileged tool execution:

- evaluate cached valid policy;
- call approval/control plane when required;
- record stable tool identity;
- do not allow prompt to override deny.

### P05-INT-03 — MCP mapping

Map existing ZCode:

- builtin;
- plugin;
- custom

sources into Lumi policy identity.

Unknown/new tool under an updated plugin/MCP must be re-evaluated.

### P05-INT-04 — Browser/computer use

Integrate existing runtime capabilities with control-plane policy without moving actual desktop execution to server.

## 7. QA lane

Mandatory:

- cross-tenant run/session ID;
- run state regression;
- double cancel/retry idempotency;
- hard budget concurrent requests;
- expired reservation cleanup;
- denied tool cannot be forced via prompt;
- MCP tool-set expansion;
- stale policy;
- revoked device mid-run;
- usage reconciliation after stream disconnect.

## 8. Integration Gate

Demonstrate:

1. managed device starts agent run;
2. inference uses managed route;
3. usage reservation created;
4. a privileged browser/tool action requires approval;
5. web admin/user approves;
6. action proceeds and event appears;
7. usage reconciles;
8. run timeline/audit is visible;
9. hard budget blocks next run/inference when threshold reached.

## 9. Exit criteria

The system can now safely manage a real team using Lumi Agents for controlled AI work.

## 10. Completion evidence and follow-ups

Coordinator evidence is recorded in `docs/implementation/gates/P05-IG.md`
and `docs/implementation/evidence/P05-IG-2026-09-25.md`. The fresh-D1/Worker
smoke passes 185 checks with zero required failures. It proves managed device
run identity, queued → dispatching → running lifecycle, managed mock
inference, D1 reservation/usage correlation, generic privileged approval and
result/replay, MCP expansion denial, stale-policy denial, hard-budget denial,
retry/cancel, cross-tenant/device negatives, timeline, audit, and request/run
correlation.

The gate is deliberately conditional rather than claiming unavailable host
execution: the public CUA package is an API-compatible placeholder, no Worker
browser/computer execution route exists, the capability catalog has no public
write route, and local workerd did not persist a `request_cancelled` row for
the passive-disconnect probe. Accounting uses a bounded token estimate for the
pre-reservation and appends authoritative actual cost during reconciliation;
a future hardening packet may add priced conversion and atomic rate counters.
These limitations are recorded, tested where possible, and do not weaken the
server-side fail-closed controls.
