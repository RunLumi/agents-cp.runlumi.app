# Plan 06 — Automations, event delivery, billing, entitlements, data governance

Status: Planned
Specs: F15, F17, F18, F20
Depends on: P05

## 1. Phase outcome

Move from interactive-only control plane to durable operations:

- scheduled/off-peak jobs;
- reliable notifications/webhooks;
- commercial entitlements;
- data export/retention/deletion.

## 2. Contract Gate — P06-CG

Freeze:

- AutomationDefinition/ScheduleRule/Occurrence;
- execution lease;
- notification/webhook event envelope;
- Plan/Subscription/Entitlement keys;
- retention/export/deletion job schemas;
- queue job envelope + dedupe keys.

## 3. Modules lane

### P06-MOD-01 — Automation scheduler model

Implement:

- canonical schedule semantics;
- occurrence identity;
- overlap policy;
- missed-run behavior;
- lease/claim model;
- off-peak policy.

### P06-MOD-02 — Entitlement evaluator

Separate:

- product entitlement;
- permission;
- budget;
- external provider entitlement.

Provide stable entitlement-key API.

### P06-MOD-03 — Retention/deletion planner

Map persistent data classes to:

- retention;
- export;
- deletion;
- tombstone;
- backup lifecycle notes.

## 4. Backend lane

### P06-BE-01 — Automation APIs/dispatcher

Implement:

- CRUD/pause/resume/run-now;
- due occurrence generation;
- device target eligibility;
- atomic claim/lease;
- result settlement;
- retry/missed schedule semantics.

Reuse ZCode cron/off-peak meaning rather than flattening it.

### P06-BE-02 — Notifications/webhooks

Build:

- durable outbox consumer;
- signed webhook delivery;
- retry/backoff;
- dead-letter;
- replay;
- endpoint auto-disable policy.

### P06-BE-03 — Billing/entitlements

Add payment-provider adapter boundary.

Product code consumes only Lumi entitlement keys.

Implement:

- subscription state;
- grace;
- plan limits;
- temporary override with expiry/reason.

### P06-BE-04 — Export/deletion jobs

Use queue-backed idempotent jobs.

R2 stores export artifacts with short-lived access.

Deletion traverses metadata + object references + derived indexes.

## 5. Frontend lane

### P06-FE-01 — Automations

List/detail:

- schedule;
- next/last run;
- target device/workspace;
- run history;
- pause/run now;
- overlap/missed behavior.

### P06-FE-02 — Webhooks/notifications

Build:

- endpoint config;
- event types;
- secret creation/rotation;
- test delivery;
- failures/replay.

### P06-FE-03 — Billing/entitlements

Build:

- current plan;
- included limits;
- grace/past-due state;
- over-limit remediation;
- provider coding-plan status shown separately.

### P06-FE-04 — Data controls

Build:

- retention summary;
- logging mode;
- export;
- deletion workflow/status.

## 6. Integration lane

### P06-INT-01 — Managed automation execution

LumiAgents:

- receives leased occurrence;
- validates policy freshness;
- executes one logical occurrence once;
- returns run ID/result;
- handles reconnect without burst duplicate replay.

### P06-INT-02 — Licensing snapshot

Extend P03 policy/license sync:

- product entitlements;
- grace expiry;
- cloud-managed features.

Do not brick unrelated local work on transient billing outage.

## 7. QA lane

Mandatory:

- two devices claiming same occurrence;
- missed schedule after long offline period;
- webhook duplicate delivery same event ID;
- invalid webhook signature/replay;
- downgrade with over-limit resources;
- provider entitlement loss vs Lumi subscription;
- export cross-tenant isolation;
- deletion job partial failure/retry.

## 8. Integration Gate

Demonstrate:

- scheduled automation dispatches exactly one occurrence;
- event/webhook emitted and retryable;
- entitlement change takes effect without client redeploy;
- export produces short-lived artifact;
- deletion workflow is auditable and idempotent.
