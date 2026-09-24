# /goal 06 — Complete P06 Automations, Events, Billing, Entitlements, and Data Governance

You are the **P06 phase coordinator and implementation lead**.

Complete `docs/implementation/plan06-automations-events-billing-data.md`.

## Read first

- `AGENTS.md`
- Plan00 and P06
- F15 Automations
- F17 Notifications/Webhooks
- F18 Billing/Plans/Entitlements/Licensing
- F20 Data Governance
- P05 handoff
- existing ZCode cron/off-peak behavior

## Mission

Move the system from interactive control to durable operations:

- scheduled/off-peak execution;
- exactly-one logical occurrence despite at-least-once infrastructure;
- durable event/webhook delivery;
- commercial entitlements independent of authorization;
- licensing/grace semantics;
- exports;
- retention;
- staged deletion.

## Contract Gate

Freeze:

- AutomationDefinition
- canonical ScheduleRule
- Occurrence ID
- execution lease/claim
- overlap/missed-run policy
- webhook/event envelope
- entitlement keys
- Subscription/License state
- export/deletion job state
- queue job/dedupe envelope

## Parallel lanes

### MOD
- scheduler semantics
- entitlement evaluator
- retention/deletion planner

### BE
- automation CRUD/dispatcher
- durable notification/webhook delivery
- billing-provider adapter + entitlements
- export/deletion workers

### FE
- automation management
- webhook/notification admin
- billing/entitlement UI
- data/retention/export/delete UI

### INT
- LumiAgents leased automation execution
- licensing/policy snapshot integration

### QA
- duplicate lease claims
- offline missed schedules
- webhook at-least-once behavior
- downgrade over-limit state
- export tenant isolation
- deletion retries

## Scheduler correctness

Each scheduled logical occurrence has a stable ID.

Multiple delivery attempts must not create multiple logical effects.

Define behavior for:

- overlapping runs;
- reconnect catch-up;
- long offline periods;
- manual run;
- pause/suspend;
- device loss.

Preserve ZCode's distinction between normal automation and off-peak safety restrictions.

## Entitlement architecture

Never couple product logic to payment-provider product/price IDs.

Keep distinct:

- authorization permission;
- Lumi product entitlement;
- usage budget;
- upstream provider account entitlement.

## Data governance

Every persistent data class must know:

- sensitivity;
- owner/scope;
- retention;
- export behavior;
- deletion behavior;
- logging rules.

Exports and deletion jobs are durable, asynchronous, idempotent, and auditable.

## Integration Gate

Prove:

- one automation dispatches exactly one occurrence;
- a webhook event is signed and retryable;
- entitlement changes affect behavior without client redeploy;
- export creates controlled short-lived artifact;
- deletion can resume after partial failure;
- local work is not unnecessarily bricked by transient billing outage.

## Completion

P06 is complete when durable operational workflows survive retries, reconnects, partial failure, and commercial state changes coherently.
