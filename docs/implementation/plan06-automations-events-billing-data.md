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

### Integration Gate evidence (P06-QA-01)

Every claim below is backed by a named test that passes, or by a probe run
against a real fresh D1. Commands and results are reproducible.

| Gate claim | Evidence |
|---|---|
| One automation dispatches exactly one occurrence | **D1 probe:** five redelivery attempts for the same `(automation, schedule revision, instant)` produced exactly **1** row. An unguarded duplicate insert was rejected by `ux_automation_occurrences_scheduled`. Unit: `modules::automations::tests::a_scheduled_slot_has_one_stable_identity_key`, `a_new_schedule_revision_is_a_different_logical_slot` |
| A webhook event is signed and retryable | `adapters::webhooks::outbound::tests::signature_reproduces_the_frozen_p06_fixture_vector` (reproduces the frozen HMAC vector exactly), plus FIPS 180-4 / RFC 4231 vectors. Retry: `adapters::webhooks::delivery::tests::retryable_failures_walk_the_deterministic_backoff_then_dead_letter`, `terminal_failures_dead_letter_without_another_attempt`, `outbound::tests::status_classification_matches_the_frozen_retry_semantics` |
| Entitlement change affects behavior without client redeploy | Dispatch re-reads entitlement, license, and policy at claim time from D1, never from a value captured at schedule creation: `jobs::automations::tests::dispatch_recheck_refuses_an_expired_grace_and_a_stale_policy`. Precedence and downgrade: `modules::entitlements::tests::downgrade_over_limit_blocks_new_and_expansion_without_deleting`, `an_ungranted_limit_fails_closed_in_the_over_limit_projection` |
| Export creates a controlled short-lived artifact | `adapters::r2::artifacts::tests::object_key_is_namespaced_and_opaque`, `object_key_requires_a_csprng_segment`, `object_key_rejects_traversal_and_foreign_namespaces`, `consumers::data_jobs::tests::artifact_ttl_is_the_frozen_24_hour_baseline`. No public or presigned URL exists in any code path (ADR 0006) |
| Deletion resumes after partial failure | `modules::data_governance::tests::deletion_steps_are_idempotent_and_need_an_explicit_resume`, `a_resume_requires_permission_and_an_audited_legal_hold_release`, `a_skipped_step_always_says_why`, `consumers::data_jobs::tests::every_step_state_is_known_to_the_certificate_gate` |
| Local work is not unnecessarily bricked by a transient billing outage | `routes::billing::tests::the_capability_matrix_keeps_local_work_alive_during_a_provider_outage`, `modules::entitlements::tests::transient_billing_outage_denies_paid_inference_with_a_stable_reason`, `modules::budget_p05::budget_p05_tests::unavailable_hard_state_does_not_fail_local_only_work` |
| P02 deletion and the P06 job are one fact (P06-CR-003) | **D1 probe:** two bridge attempts with different lifecycle request IDs produced exactly **1** `deletion_jobs` row, with the organization correctly `pending_deletion`. The state transition and the job link commit in one D1 batch |

Verification at the time of writing: `cargo test --lib` 666 passed /
0 failed, `cargo clippy --all-targets -- -D warnings` clean,
`cargo check --target wasm32-unknown-unknown` clean, 15 migrations apply
to a fresh D1.

### Defects the implementation surfaced in this phase's own artifacts

Recording these because each was found by a test or probe rather than by
review, and each would have shipped as a silent correctness failure:

- Cron bit indexing read `value - 1` while insert wrote `value - spec.min`.
  Minutes and hours are 0-based, so a canonical `0 9 * * 1-5` fired at
  `2 11`, meaning automations ran at the wrong time.
- `Field::is_full` compared against an un-folded day-of-week range while
  insert folds the `7` alias onto `0`, so `*` was never recognized as
  unrestricted. A monthly `0 9 15 * *` therefore fired **every day**.
- `missed_run_plan` scanned forward with no upper bound, returning a slot
  ~275 years in the future that the adapter would have persisted as a real
  occurrence.
- `MissedPolicy::Skip` behaved identically to `run_once`, defeating the
  "no burst replay after reconnect" requirement.
- The overlap decision treated `ambiguous` as a terminal predecessor and
  allowed a second device to take the slot.
- `trg_export_jobs_artifact_only_when_ready` fired on every state write and
  so aborted the entire export lifecycle, including the gate-required
  `ready -> expired` transition.
- The anti-recursion webhook trigger also blocked `webhook.test.v1`, which
  would have made the documented test-delivery endpoint unable to persist
  anything.
- `project_access_grant` and `team_member` are persistent tables in deletion
  scope with no data-class declaration, so they could not be planned.
- Dispatch failed closed with no seeded `license_states` row, so a new
  tenant could never run a single automation.

### Open contract follow-ups needing a Change Request

Recorded rather than resolved. Each is a limit of `p06-cg-v1` that the phase
worked around honestly instead of quietly widening the contract. None of them
blocks the Integration Gate; all three would need `CR-004` or later to change.

1. **No downgrade-preview route.** The frozen route table has
   `POST /billing/change` but no preview equivalent, so a downgrade cannot be
   shown to the operator before it is submitted. The panel refuses to submit an
   unpreviewed downgrade and routes to the provider portal instead, which is
   honest but is a worse experience than a preview.
2. **`GET /entitlements` reports no count for an in-limit resource.**
   `over_limit[]` carries real `current`/`limit`/`over_by`, but only for
   resources already above their limit. The "Usage vs. plan limits" table
   therefore shows a dash for every in-limit row and states in its caption that
   a dash means "not published", never zero. The status column stays sound,
   because absence from `over_limit` is the server's statement that the resource
   is within limit.
3. **The delivery projection has no attempt-level diagnostics.** No frozen route
   returns webhook or notification attempt rows, so a failed delivery cannot be
   explained on the surface — only counted.

### Cross-repository follow-ups

- `LumiAgents` `packages/provider/src/lumi-managed-inference.ts` carries P06
  changes that interleave with roughly 310 lines of uncommitted P05 work on the
  same file. Splitting the hunks is owed by the P05 owner. Until it lands,
  `feat/p06-automation-lease` does not compile standalone.
- `LumiAgents` has **four divergent copies** of the off-peak/automation tool
  denylist, and `server-operations.ts` is missing `CronUpdate` and `CronDelete`.
  Verified directly: a model refused `CronCreate` can still see `CronDelete` on
  the legacy path, which is a real correctness gap, not a cosmetic divergence.
  Canonical values are already published in `@zcode/shared`. The affected files
  are outside P06's write surface. Detail in `handoffs/P06-INT-01.md`.

### F22 information-architecture conformance

`docs/specs/f22-web-control-plane-ux-information-architecture.md` is the
authority on the org navigation tree, and the P06 surfaces now match it:

- `Automations` is a top-level nav item.
- `Billing`, `Data / Retention`, and `Webhooks` are Settings sub-pages at
  `/org/{slug}/settings/{billing,data,webhooks}`, with `Security / Identity`
  alongside them.
- `Integrations / MCP` is a separate top-level item in F22's tree. This
  codebase has no MCP or provider-connection surface, so no nav item claims the
  name. `Tools & approvals` is the likely future occupant; renaming or moving it
  is outside P06's write surface.

F22's `General` and `Credentials` sub-pages are absent rather than stubbed. A
nav item pointing at nothing is worse than a missing one.

### Frontend verification still owed

No P06 surface has been rendered in a browser; none is attached to this session
(`browser.tabs.list` returns `[browser.disconnected]`). The structural work is
asserted over the real component tree and, for the billing status derivation,
in a pure module precisely because `renderToStaticMarkup` cannot drive a
container with an async read. What remains unverified is pixel layout at narrow
widths, tab-strip overflow, and focus-ring contrast. Screen references used,
and the five deliberate deviations from them, are in `handoffs/P06-FE.md`.
