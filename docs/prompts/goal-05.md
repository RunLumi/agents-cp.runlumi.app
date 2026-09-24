# /goal 05 — Complete P05 Runs, Tools, Usage, Budgets, and Managed Control

You are the **P05 phase coordinator and implementation lead**.

Complete `docs/implementation/plan05-runs-tools-usage-control.md`.

P03 and P04 must both provide their stable handoffs before P05 integration can exit.

## Read first

- `AGENTS.md`
- Plan00 and P05
- F08 Agents/Sessions/Runs/Artifacts
- F12 Usage/Quotas/Budgets
- F13 Tools/MCP/Browser/Computer Use
- F16 Audit
- F21 Operations
- P03 and P04 Contract Gates/handoffs
- current LumiAgents/ZCode run/tool/MCP/browser/computer code

## Mission

Create the first complete managed-agent control loop:

```text
principal + device + project
→ session/run
→ managed inference
→ tool policy/approval
→ usage/budget
→ audit/run timeline
→ visible control-plane state
```

## Contract Gate

Freeze:

- AgentDefinition minimum schema;
- Session;
- Run;
- Run states/transitions;
- RunEvent + sequence;
- artifact metadata reference;
- tool/capability identity and risk class;
- approval decisions;
- UsageEvent/CostRecord;
- Budget/Reservation;
- rate/concurrency policy;
- policy snapshot model/tool/budget sections.

## Parallel lanes

### MOD
- session/run state machine
- tool policy evaluator
- budget/reservation engine
- usage/cost model

### BE
- session/run APIs
- tool/MCP/browser/computer policy APIs
- approval APIs
- usage/budget APIs
- audit integration

### FE
- run/session timeline
- tool/MCP policy
- approval surfaces
- usage/budgets

### INT
- run identity propagation from LumiAgents
- privileged tool decision broker
- MCP source/tool mapping
- browser/computer use policy integration

### QA
- tenant/run hostile cases
- state transition/race cases
- budget concurrency
- stale policy
- MCP capability expansion
- revoked device mid-run

## State-machine discipline

Runs are append-only history.

A retry creates a new attempt.

Never rewrite a failed historical run into success.

All state transitions must be validated server-side and correlated to immutable events.

## Tool-policy discipline

Prompts cannot override policy.

Effective decision must compose:

- platform hard deny;
- org/project policy;
- agent definition;
- runtime capability;
- per-run/per-use approval.

Unknown privileged tools in managed org mode default deny/re-review.

## Budget discipline

Hard budget must resist obvious concurrent overspend races.

Start with D1 if it can satisfy the invariant.

Use a Durable Object only if measured coordination/serialization needs justify it.

Do not prematurely move the whole budget system into DO.

## Integration Gate

Prove one real managed run:

1. enrolled device starts run;
2. inference uses managed alias;
3. budget reservation exists;
4. privileged action requires approval;
5. web approves;
6. action proceeds;
7. usage reconciles;
8. run timeline and audit are visible;
9. hard budget blocks a subsequent eligible request.

## Completion

P05 is complete when the control plane can safely govern real team usage of Lumi Agents rather than merely observe it.
