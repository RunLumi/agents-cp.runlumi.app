# Plan 05 — Runs, sessions, tool policy, usage, budgets

Status: Planned
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
