# Plan 06 — Automations, event delivery, billing, entitlements, data governance

Status: Contract Gate `p06-cg-v1` frozen; implementation packets ready (see `docs/implementation/gates/P06-CG.md` and `docs/implementation/packets/`).
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
- deletion workflow is auditable and idempotent;
- local work is not unnecessarily bricked by a transient billing outage.

## 9. Progress log

### Schema foundation (coordinator)

Migrations `0011`–`0014` are written and apply cleanly to a fresh D1
(`wrangler d1 migrations apply ... --local`: 14/14 ✅, 37 new P06 tables, plus
the additive `runs.automation_occurrence_id` / `runs.automation_lease_id`
correlation columns).

Frozen invariants proven against a real D1 instance:

| # | Invariant | Probe | Result |
|---|---|---|---|
| 1 | One active lease per occurrence (P06-CR-001) | Two devices insert an `active` lease for the same `occurrence_id` with different attempts | 2nd rejected by `ux_automation_leases_active`; active count = 1 |
| 2 | One logical occurrence per schedule slot | Two different `occurrence_id`s for the same `(automation_id, schedule_rule_id, scheduled_for_utc)` | 2nd rejected by `ux_automation_occurrences_scheduled` |
| 3 | No provider product/price ID as an entitlement key (P06-CR-002) | `INSERT entitlement_definitions(entitlement_key='price_abc123')` | Rejected by `trg_entitlement_definitions_no_provider_id` |
| 4 | No silent forever internal override (F18) | `INSERT entitlement_grants(source='internal_override')` without `expires_at`/`reason`/`granted_by` | Rejected by CHECK constraint |
| 5 | Mandatory security notifications cannot be opted out (F17) | `INSERT notification_preferences(disabled_event_types_json='["auth.*"]')` | Rejected by `trg_notification_preferences_no_security_optout` |
| 6 | No wildcard webhook subscriptions (F17) | `INSERT webhook_endpoints(subscribed_event_types_json='["*"]')` | Rejected by `trg_webhook_endpoints_no_wildcard` |
| 7 | Lumi never claims upstream-provider deletion (F20) | `INSERT deletion_tasks(reference_kind='upstream_provider_data', state='succeeded')` | Rejected by `trg_deletion_tasks_provider_external` |
| 8 | No recursive webhook fan-out | `INSERT webhook_deliveries(event_type='webhook.delivery_*')` | Rejected by `trg_webhook_deliveries_no_recursive_fanout` |

Lease tokens are stored only as SHA-256 fingerprints; no plaintext secret,
prompt, response, credential, or export content is persisted in these tables.
