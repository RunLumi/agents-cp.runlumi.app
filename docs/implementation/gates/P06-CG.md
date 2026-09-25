# Contract Gate — P06-CG

- Phase: P06 — Automations, event delivery, billing, entitlements, and data governance
- Owner: P06 coordinator
- State: **draft — coordinator review required**
- Contract version: `p06-cg-v1`
- Inputs: Plan00, Plan06, F15, F17, F18, F20, ADR 0001–0005, P05-CG, P05-COORD-02, and current ZCode cron/off-peak behavior
- Preconditions: P05 is merged with a conditional pass; P05 limitations remain explicit and are not redefined here
- Shared-file owner: P06 coordinator

## Purpose and boundaries

P06 moves the control plane from interactive requests to durable operations:

```text
AutomationDefinition
→ due Occurrence
→ one execution lease
→ managed run/device execution
→ durable event/webhook delivery
→ commercial entitlement/license snapshot
→ auditable export/deletion work
```

P06 does not move local execution into the Worker. LumiAgents/ZCode remains the execution host for local files, shell, browser, computer use, and MCP. The Worker owns schedule authority, lease claims, policy/entitlement decisions, delivery state, job state, audit, and visibility.

This gate freezes shared contracts only. It does not promise exactly-once network delivery or billing-provider availability. It guarantees stable logical occurrence identity and idempotent job transitions despite at-least-once infrastructure.

## Domain vocabulary

| Concept | Stable name | Meaning |
|---|---|---|
| Automation definition | `AutomationDefinition` | Org/project-owned definition of a trigger, schedule, target, and policy constraints. |
| Canonical schedule | `ScheduleRule` | Canonical one-time, cron, or interval semantics with timezone, missed-run, and overlap behavior. |
| Logical occurrence | `Occurrence` | Stable scheduled logical work identity. Delivery retries and lease attempts do not create another occurrence. |
| Execution lease | `ExecutionLease` | Time-bounded claim by one eligible device/host for one occurrence. |
| Automation execution | `AutomationRun` | Correlation record from an occurrence to a P05 `run_id` and terminal result. |
| Off-peak policy | `OffPeakPolicy` | Explicit normal/off-peak mode and safety restrictions; it is not flattened into ordinary cron. |
| Event envelope | `EventEnvelope` | Existing P01 versioned durable event contract, extended only with P06 event types/payloads. |
| Webhook endpoint | `WebhookEndpoint` | Org-owned HTTPS destination, subscriptions, secret reference, and delivery policy. |
| Webhook delivery | `WebhookDelivery` | One retryable attempt/history row for one stable event and endpoint. |
| Notification | `Notification` | Durable in-app informational projection; critical security events remain mandatory. |
| Billing provider adapter | `BillingProviderAdapter` | Boundary that maps provider state to Lumi subscription state; provider IDs never enter product logic. |
| Plan | `Plan` | Lumi product plan keyed by a stable Lumi key and versioned limits. |
| Subscription | `Subscription` | Org commercial state mapped from a provider, including grace and past-due semantics. |
| Entitlement definition | `EntitlementDefinition` | Stable Lumi entitlement key, value type, and default/limit metadata. |
| Entitlement grant | `EntitlementGrant` | Time-bounded grant from a subscription or audited temporary override. |
| License snapshot | `LicenseSnapshot` | Short-lived signed snapshot of entitlements, grace, and policy freshness for clients. |
| Data governance policy | `DataGovernancePolicy` | Org/project logging mode, retention, export, deletion, and legal-hold settings. |
| Export job | `ExportJob` | Durable asynchronous request for a controlled export artifact. |
| Deletion job | `DeletionJob` | Durable asynchronous, resumable, idempotent deletion workflow. |
| Queue job envelope | `QueueJobEnvelope` | Versioned, deduplicated worker message envelope; never carries secrets or raw content. |

All P06 IDs are opaque `<prefix>_<32 lowercase hex characters>`. The prefix is a wire namespace, never an authorization signal.

| Resource | ID prefix | Tenant owner | Parent/owner |
|---|---|---|---|
| AutomationDefinition | `aut_` | org | project and optional agent/session/workspace/device target |
| Occurrence | `occ_` | org | automation |
| ExecutionLease | `lse_` | org | occurrence and eligible device/host |
| AutomationRun | `arun_` | org | occurrence and P05 run |
| WebhookEndpoint | `whe_` | org | organization |
| WebhookDelivery | `whd_` | org | endpoint and stable event |
| Notification | `ntf_` | org/user | event/preferences |
| Plan | `plan_` | platform | none |
| Subscription | `sub_` | org | billing account and plan |
| EntitlementDefinition | `ent_` | platform/org | none |
| EntitlementGrant | `egr_` | org | subscription or override |
| LicenseSnapshot | `lic_` | org | subscription/policy state |
| DataGovernancePolicy | `dgp_` | org/project | none |
| ExportJob | `exp_` | org | requested by principal |
| DeletionJob | `del_` | org/account | requested by principal |
| QueueJob | `job_` | platform/tenant | dedupe key |

`Occurrence` identity is deterministic from the automation ID, canonical schedule instant, and schedule-rule version. A retry, queue redelivery, reconnect, or second claim cannot mint a new occurrence ID. Manual runs receive a separate stable occurrence kind and are not silently treated as a scheduled occurrence.

## Schedule and target contract

### ScheduleRule

The wire form is a bounded discriminated object:

```json
{
  "kind": "cron",
  "expression": "0 9 * * 1-5",
  "timezone": "America/Los_Angeles",
  "overlap_policy": "skip",
  "missed_policy": "run_once",
  "catch_up_limit": 1
}
```

Supported kinds:

- `one_time`: `scheduled_at` (UTC instant), no recurrence.
- `cron`: a canonical five-field expression, IANA timezone, and explicit daylight-saving resolution (`skip_duplicate`, `run_once`, or `run_twice`); the server stores the normalized expression and timezone.
- `interval`: `every_seconds` plus an anchor instant and a bounded minimum/maximum duration. The server stores the canonical anchor, not a display-only string.
- `manual`: no scheduled instant; only `run-now` may create an occurrence.

`overlap_policy` is one of `allow`, `skip`, `queue_one`, or `cancel_previous`. `missed_policy` is one of `skip`, `run_once`, or `catch_up`; `catch_up` requires a bounded positive `catch_up_limit`. Defaults are `skip` for overlap and `run_once` for missed schedules, with a documented maximum catch-up window.

`OffPeakPolicy` is explicit:

```json
{
  "mode": "off_peak",
  "window": {"start": "22:00", "end": "07:00", "timezone": "America/Los_Angeles"},
  "tool_restrictions": "zcode_off_peak_safety",
  "allow_network": false,
  "allow_browser": false,
  "allow_computer_use": false
}
```

The server re-evaluates off-peak policy at dispatch and execution time. A schedule creation response is not a permission to execute a later occurrence. ZCode's normal/off-peak distinction and safety restrictions remain authoritative for the execution host; the Worker may narrow but never broaden them.

### AutomationDefinition

Required fields:

```json
{
  "automation_id": "aut_0123456789abcdef0123456789abcdef",
  "org_id": "org_0123456789abcdef0123456789abcdef",
  "project_id": "prj_0123456789abcdef0123456789abcdef",
  "name": "Weekday review",
  "description": "Run the review agent on weekdays",
  "agent_definition_id": "agd_0123456789abcdef0123456789abcdef",
  "target": {
    "kind": "eligible_device",
    "device_id": null,
    "workspace_binding_id": "wsb_0123456789abcdef0123456789abcdef",
    "required_capabilities": ["text"]
  },
  "schedule": {"kind": "manual"},
  "off_peak_policy": null,
  "status": "active",
  "version": 1,
  "next_run_at": null,
  "last_run_at": null,
  "created_by_user_id": "usr_0123456789abcdef0123456789abcdef",
  "created_at": "2026-09-25T12:00:00.000Z",
  "updated_at": "2026-09-25T12:00:00.000Z"
}
```

Target kinds are `eligible_device`, `specific_device`, `remote_workspace`, and `server_runner` (the latter is accepted only when a server runner is actually enabled). A device target is resolved from current enrollment, binding, capability, membership, and policy state. Client-supplied target or schedule values never bypass current authorization.

## Occurrence and lease contract

### Occurrence

```json
{
  "occurrence_id": "occ_0123456789abcdef0123456789abcdef",
  "automation_id": "aut_0123456789abcdef0123456789abcdef",
  "org_id": "org_0123456789abcdef0123456789abcdef",
  "project_id": "prj_0123456789abcdef0123456789abcdef",
  "kind": "scheduled",
  "scheduled_for": "2026-09-25T16:00:00.000Z",
  "schedule_rule_version": 3,
  "state": "pending",
  "attempt": 0,
  "reason_code": null,
  "automation_run_id": null,
  "run_id": null,
  "created_at": "2026-09-25T15:59:59.000Z",
  "updated_at": "2026-09-25T15:59:59.000Z"
}
```

States:

```text
pending → dispatching → leased → running → succeeded
pending|dispatching|leased → skipped
pending|dispatching|leased|running → failed
pending|dispatching|leased|running → cancelled
pending|dispatching|leased → missed
leased → pending (lease expiry, attempt incremented)
```

Terminal occurrence history is immutable. A lease expiry or retry updates only the current occurrence/lease projection; it does not create a second logical occurrence. `skip`, `missed`, `failed`, and `cancelled` require a bounded stable reason code.

### ExecutionLease

```json
{
  "lease_id": "lse_0123456789abcdef0123456789abcdef",
  "occurrence_id": "occ_0123456789abcdef0123456789abcdef",
  "org_id": "org_0123456789abcdef0123456789abcdef",
  "device_id": "dvc_0123456789abcdef0123456789abcdef",
  "state": "active",
  "attempt": 1,
  "lease_token_fingerprint": "sha256:...",
  "claimed_at": "2026-09-25T16:00:00.000Z",
  "expires_at": "2026-09-25T16:05:00.000Z",
  "completed_at": null,
  "version": 1
}
```

A claim is an atomic compare-and-set from `pending`/`dispatching` to `leased`, with a unique active lease per occurrence. Only a server-issued device/host token can claim. A second device receives the existing lease projection or a stable `occurrence_already_claimed` response; it cannot receive the raw lease token. Lease tokens are stored only as fingerprints.

## Event and webhook contract

### Durable event envelope

Business transactions emit the existing P01 `EventEnvelope` to `outbox_events`. P06 payloads are bounded metadata only and use versioned dotted event types. Every event has one stable `event_id` across queue redelivery and webhook retries.

P06 event names are frozen in this gate:

- `automation.created.v1`
- `automation.updated.v1`
- `automation.paused.v1`
- `automation.resumed.v1`
- `automation.deleted.v1`
- `automation.occurrence_created.v1`
- `automation.dispatched.v1`
- `automation.started.v1`
- `automation.completed.v1`
- `automation.failed.v1`
- `automation.skipped.v1`
- `automation.missed.v1`
- `automation.lease_expired.v1`
- `webhook.endpoint_created.v1`
- `webhook.endpoint_updated.v1`
- `webhook.endpoint_rotated.v1`
- `webhook.endpoint_disabled.v1`
- `webhook.delivery_succeeded.v1`
- `webhook.delivery_retry_scheduled.v1`
- `webhook.delivery_dead_lettered.v1`
- `webhook.delivery_replayed.v1`
- `notification.created.v1`
- `billing.subscription_updated.v1`
- `billing.grace_started.v1`
- `billing.grace_ended.v1`
- `entitlement.granted.v1`
- `entitlement.revoked.v1`
- `entitlement.override_created.v1`
- `entitlement.override_expired.v1`
- `license.snapshot_issued.v1`
- `billing.downgrade_over_limit.v1`
- `data_policy.updated.v1`
- `export.requested.v1`
- `export.started.v1`
- `export.completed.v1`
- `export.failed.v1`
- `export.expired.v1`
- `deletion.requested.v1`
- `deletion.started.v1`
- `deletion.step_completed.v1`
- `deletion.failed.v1`
- `deletion.resumed.v1`
- `deletion.completed.v1`

### Webhook endpoint and delivery

Endpoint configuration stores encrypted secret material, never a returned plaintext secret after creation/rotation. It contains subscribed event types, enabled state, description, failure policy, and version. HTTPS and SSRF validation are required; localhost/private destinations are rejected outside explicit development fixtures.

Delivery is at-least-once. A retry uses a new `WebhookDelivery` ID/attempt but the same stable event ID. A replay explicitly creates a new delivery attempt and records `replay_of_delivery_id`; it never edits the original attempt.

Signature contract:

```text
X-Lumi-Event-Id: evt_<32 hex>
X-Lumi-Timestamp: <unix seconds>
X-Lumi-Signature: v1=<lowercase hex HMAC-SHA256(secret, timestamp + "." + event_id + "." + raw_body)>
```

The signed body is the exact UTF-8 request body. Timestamps outside the endpoint's replay window are rejected. No prompt, response, credential, raw tool argument, or secret is included in the payload. Default retry policy is bounded exponential backoff with deterministic jitter, five to eight attempts depending on endpoint policy, a maximum 24-hour delay, dead-letter after exhaustion, and optional auto-disable after a configured consecutive-failure threshold.

### QueueJobEnvelope

Workers consume:

```json
{
  "job_id": "job_0123456789abcdef0123456789abcdef",
  "job_type": "automation.dispatch",
  "schema_version": 1,
  "dedupe_key": "automation_id:scheduled_for:schedule_version",
  "event_id": "evt_0123456789abcdef0123456789abcdef",
  "occurred_at": "2026-09-25T16:00:00.000Z",
  "attempt": 1,
  "correlation_id": "req_0123456789abcdef0123456789abcdef",
  "tenant_scope": {"org_id": "org_0123456789abcdef0123456789abcdef"},
  "payload_ref": "d1:automation_occurrences/occ_...",
  "payload": {"automation_id": "aut_...", "occurrence_id": "occ_..."}
}
```

The envelope is bounded and metadata-only. `dedupe_key` is unique for the logical job; a redelivered envelope with the same key is acknowledged as duplicate after the domain job is confirmed complete. Queue transport is never treated as authorization or exactly-once delivery.

## Entitlement, plan, and licensing contract

### Stable entitlement keys

Product code consumes only Lumi keys. Payment provider product/price IDs are adapter-private and MUST NOT appear in authorization, feature gates, or UI entitlement contracts.

Required baseline keys:

- `org.max_members`
- `projects.max_active`
- `inference.platform_managed`
- `inference.byok`
- `audit.retention_days`
- `automations.max_active`
- `devices.max_enrolled`
- `exports.enabled`
- `deletion.self_service`
- `webhooks.enabled`
- `sso.enabled`
- `scim.enabled`

Keys are lowercase dotted identifiers and are versioned in the policy snapshot. Values are typed (`boolean`, `integer`, or bounded `string`) and never inferred from provider IDs.

### Subscription and license

Subscription states are `trialing`, `active`, `grace`, `past_due`, `suspended`, and `cancelled`. A provider adapter maps provider state into these values and records an opaque provider reference, never a product/price ID in product logic.

```json
{
  "subscription_id": "sub_0123456789abcdef0123456789abcdef",
  "org_id": "org_0123456789abcdef0123456789abcdef",
  "plan_key": "team",
  "status": "grace",
  "grace_expires_at": "2026-10-02T12:00:00.000Z",
  "current_period_ends_at": "2026-10-01T12:00:00.000Z",
  "version": 4
}
```

A downgrade never deletes data. It blocks new/expanded resources above the new limit and exposes an over-limit remediation projection. A temporary override requires an expiry, reason, grant scope, and F16 audit event. There are no silent forever overrides.

A short-lived signed `LicenseSnapshot` contains entitlement values, grace expiry, policy freshness, snapshot ID/version, issued/expiry timestamps, and a signature. Desktop/CLI may use the signed snapshot for bounded offline grace; it never becomes the permanent source of truth. Transient billing/provider outages must not brick unrelated local editing/execution. Cloud-paid inference may fail sooner, with a stable entitlement/billing reason.

Authorization permission, Lumi product entitlement, usage budget, and upstream provider account entitlement remain separate decision inputs.

## Data governance contract

Every new persistent P06 data class declares:

| Data class | Sensitivity | Owner/scope | Default retention | Export | Deletion | Logging |
|---|---|---|---|---|---|---|
| Automation definition | internal metadata | org/project | until deletion | included | delete/tombstone | metadata only |
| Occurrence/lease | operational metadata | org/project/device | 90 days after terminal | included | delete/tombstone | IDs/status only |
| Webhook endpoint config | secret-bearing metadata | org | until disabled/deleted | redacted config | delete secret/config | never secret |
| Webhook delivery | delivery metadata | org/endpoint | 30 days | included | delete/tombstone | status/error code only |
| Notification | user/org content | user/org | 30 days | user-visible export | delete/tombstone | metadata only |
| Plan/subscription | commercial metadata | platform/org | legal/billing policy | redacted billing export | tombstone | status only |
| Entitlement grant/license snapshot | commercial/policy metadata | org | snapshot expiry + audit policy | redacted state | tombstone | keys/status only |
| Data governance policy | privacy configuration | org/project | until deletion | included | delete/tombstone | metadata only |
| Export job metadata | sensitive pointer | org/requester | 90 days | included | delete/tombstone | job status only |
| Export artifact | sensitive content | org/requester | short-lived, default 24 hours | downloadable only through expiring access | delete object and derived copies | never content |
| Deletion job/task | sensitive operational metadata | org/account | legal/security policy | redacted job state | tombstone after completion | state/reason only |
| Queue job envelope | operational metadata | tenant/platform | retry/DLQ policy | not exported | delete after retention | IDs/status only |

Content logging mode is `metadata_only` (default), `redacted_content`, or `full_content`, scoped to org/project. Metadata-only is the default for inference/control-plane observability. Export artifacts are encrypted/access-controlled, have an expiry and checksum, and are never represented by a public permanent URL. Deletion traverses metadata, R2 objects, caches, search indexes, and derived copies; legal/security retention uses minimized/tombstoned records where justified.

### ExportJob and DeletionJob states

```text
Export: queued → running → succeeded → expired
                  ↘ failed → queued (retry/resume)
                  ↘ cancelled

Deletion: queued → running → failed → running (resume)
                         ↘ succeeded
                         ↘ cancelled
```

Every job has a stable job ID, dedupe key, org/account scope, requested-by principal, state version, attempt count, bounded failure code, timestamps, and audit correlation. A retry/replay must be idempotent. Export download authorization is checked again at download time and is bound to the job scope and expiry. Deletion step completion is recorded per data class/object reference; partial failure is resumable.

## API contract

All routes are under `/api/v1`; all browser mutations require CSRF and idempotency keys where a retry can duplicate work. Machine routes use device/service identity and never accept browser-supplied authoritative lease, billing, or accounting values.

| Method | Path | Permission/identity | Purpose |
|---|---|---|---|
| GET/POST | `/orgs/{org_id}/automations` | `automations.read/manage` | List/create definitions. |
| GET/PATCH/DELETE | `/orgs/{org_id}/automations/{automation_id}` | `automations.read/manage` | Read/update/delete definition. |
| POST | `/orgs/{org_id}/automations/{automation_id}/pause` | `automations.manage` | Pause new dispatch. |
| POST | `/orgs/{org_id}/automations/{automation_id}/resume` | `automations.manage` | Resume after current policy/entitlement checks. |
| POST | `/orgs/{org_id}/automations/{automation_id}/run-now` | `automations.run` | Create one manual occurrence. |
| GET | `/orgs/{org_id}/automations/{automation_id}/occurrences` | `automations.read` | Cursor-paginated occurrence history. |
| GET | `/devices/automations/due` | device token | Return eligible leased work. |
| POST | `/devices/automation-occurrences/{occurrence_id}/claim` | device token | Atomic lease claim. |
| POST | `/devices/automation-occurrences/{occurrence_id}/complete` | device token | Settle success/failure with run ID. |
| GET/POST | `/orgs/{org_id}/webhooks` | `webhooks.read/manage` | List/create endpoint config. |
| PATCH/DELETE | `/orgs/{org_id}/webhooks/{endpoint_id}` | `webhooks.manage` | Update/disable endpoint. |
| POST | `/orgs/{org_id}/webhooks/{endpoint_id}/rotate-secret` | `webhooks.manage` | Rotate secret; plaintext shown once. |
| POST | `/orgs/{org_id}/webhooks/{endpoint_id}/test` | `webhooks.manage` | Enqueue a bounded test delivery. |
| GET | `/orgs/{org_id}/webhooks/{endpoint_id}/deliveries` | `webhooks.read` | Delivery history/failures. |
| POST | `/orgs/{org_id}/webhooks/deliveries/{delivery_id}/replay` | `webhooks.manage` | Replay same event with a new attempt. |
| GET/PATCH | `/orgs/{org_id}/notification-preferences` | `notifications.read/manage` | Informational preferences. |
| GET | `/orgs/{org_id}/billing/subscription` | `billing.read` | Current mapped subscription state. |
| GET | `/orgs/{org_id}/entitlements` | `entitlements.read` | Effective Lumi entitlement projection. |
| POST | `/orgs/{org_id}/entitlements/overrides` | `entitlements.manage` | Expiring audited override. |
| GET | `/devices/license` | device token | Short-lived signed license/entitlement snapshot. |
| GET/PATCH | `/orgs/{org_id}/data-policy` | `data.read/manage` | Logging/retention policy. |
| GET/POST | `/orgs/{org_id}/exports` | `data.read/export` | List/request exports. |
| GET | `/orgs/{org_id}/exports/{export_id}` | `data.read/export` | Job state and expiry. |
| POST | `/orgs/{org_id}/exports/{export_id}/download` | `data.export` | Re-authorized short-lived download grant. |
| GET/POST | `/orgs/{org_id}/deletions` | `data.read/delete` | List/request deletion workflows. |
| GET | `/orgs/{org_id}/deletions/{deletion_id}` | `data.read/delete` | Job/step/failure state. |
| POST | `/orgs/{org_id}/deletions/{deletion_id}/resume` | `data.delete` | Resume a partial failure. |

Billing provider callbacks and scheduler ticks are internal queue/handler surfaces, not browser contracts. Provider callback authentication is adapter-specific and must not weaken the public API contract.

## Permissions and role behavior

P06 adds:

- `automations.read`
- `automations.manage`
- `automations.run`
- `webhooks.read`
- `webhooks.manage`
- `notifications.read`
- `notifications.manage`
- `billing.read`
- `entitlements.read`
- `entitlements.manage`
- `data.read`
- `data.export`
- `data.delete`

Owners/admins receive all P06 permissions. Members may read and run automations within visible projects when target/policy checks pass. Viewers are read-only. Webhook secret rotation, billing/override changes, exports, and deletion are admin/owner operations unless a later explicit contract says otherwise. All checks pass through the central authorization path and current organization state.

## Error semantics

Stable machine-readable reasons include:

- `automation_not_found`
- `automation_invalid_state`
- `automation_overlap_policy`
- `automation_missed_schedule_limit`
- `occurrence_not_found`
- `occurrence_already_claimed`
- `occurrence_lease_expired`
- `device_not_eligible`
- `off_peak_not_allowed`
- `schedule_invalid`
- `schedule_timezone_invalid`
- `webhook_endpoint_invalid`
- `webhook_https_required`
- `webhook_signature_invalid`
- `webhook_replay_window_exceeded`
- `webhook_delivery_dead`
- `webhook_endpoint_auto_disabled`
- `subscription_state_unavailable`
- `entitlement_not_granted`
- `entitlement_limit_exceeded`
- `entitlement_grace_expired`
- `entitlement_override_expired`
- `license_snapshot_expired`
- `provider_entitlement_unavailable`
- `data_policy_invalid`
- `export_not_ready`
- `export_expired`
- `export_artifact_unavailable`
- `deletion_not_resumable`
- `deletion_scope_conflict`
- `deletion_legal_hold`
- `queue_job_duplicate`
- `queue_job_dedupe_conflict`

No error exposes raw provider responses, secret values, prompt/response content, or unbounded SQL/platform errors.

## Policy and configuration snapshot

The P03 policy snapshot gains bounded, versioned P06 extension sections:

```json
{
  "automations": {
    "schema_version": 1,
    "max_active": 100,
    "allowed_overlap_policies": ["skip", "queue_one", "allow", "cancel_previous"],
    "allowed_missed_policies": ["skip", "run_once", "catch_up"]
  },
  "entitlements": {
    "schema_version": 1,
    "license_snapshot_ttl_seconds": 900,
    "grace_default_seconds": 604800
  },
  "notifications": {
    "schema_version": 1,
    "webhook_max_attempts": 8,
    "webhook_replay_window_seconds": 300
  },
  "data_governance": {
    "schema_version": 1,
    "default_logging_mode": "metadata_only",
    "default_export_expiry_seconds": 86400
  }
}
```

The server resolves current organization/project scope and applies the narrowest policy. Client snapshots are untrusted inputs. Unknown sections or malformed schema versions fail closed for managed operations. A local-only runtime can use a previously signed license snapshot for bounded grace, but a current cloud operation must validate policy freshness.

## Persistence skeleton

Migration `0011_p06_durable_operations.sql` is additive and forward-only after `0010_p05_runs_tools_usage_control.sql`. It may create these tables and indexes:

- `automation_definitions`
- `automation_occurrences`
- `automation_leases`
- `automation_runs`
- `webhook_endpoints`
- `webhook_deliveries`
- `notification_preferences`
- `notifications`
- `plans`
- `subscriptions`
- `entitlement_definitions`
- `entitlement_grants`
- `license_snapshots`
- `data_governance_policies`
- `export_jobs`
- `deletion_jobs`
- `deletion_tasks`
- `queue_job_envelopes`

Invariant-bearing constraints:

- one unique active automation name per org/project scope (or explicit product decision in the migration);
- one occurrence per `(automation_id, scheduled_for, schedule_rule_version)` for scheduled work;
- one active lease per occurrence;
- one automation run mapping per occurrence;
- one delivery attempt ID per event/endpoint/attempt, with stable event ID repeated across retries;
- one subscription current-state row per org;
- one effective entitlement definition per key/scope/version;
- one active grant per key/scope unless the product explicitly supports additive grants;
- one current data policy per org/project scope;
- one export/deletion job per idempotency/dedupe key;
- immutable audit/security rows and immutable event IDs; stateful delivery/job rows may transition only through compare-and-set versions.

R2 is used for export artifacts only. D1 stores metadata, opaque object references, checksums, expiry, and audit state; it is not an export-content authority.

## Compatibility and migration

- Existing P01–P05 routes and IDs remain valid.
- P06 IDs are additive and typed; no P05 `run_id`, `rse_` session, or P02 `ses_` login-session meaning changes.
- P01 `EventEnvelope` remains the business outbox envelope. P06 queue jobs use a separate versioned envelope so a webhook retry does not mutate the business event.
- `0011` must apply before P06 handlers read new tables. Rollback is application-code rollback with additive schema retained; do not delete historical jobs, audit, or billing records to roll back.
- ZCode/LumiAgents mappings use opaque `external_id`/provider references and preserve normal automation versus off-peak safety semantics.
- Billing provider product/price IDs remain adapter-private. Public and persisted product contracts use Lumi keys.
- Browser clients never receive raw lease tokens, webhook secrets, provider credentials, export content URLs, or authoritative job settlement values.

## Fixtures and evidence

The coordinator provides `docs/implementation/fixtures/p06-contracts-v1.json` before MOD/BE/FE implementation packets start. It includes one valid and one invalid schedule, a deterministic occurrence identity example, a lease race fixture, a signed webhook fixture (secret placeholder only), a grace/downgrade entitlement fixture, a data-class policy fixture, and an export/deletion retry fixture.

Before freeze, the coordinator must review:

- [ ] current ZCode cron/off-peak semantics mapped without flattening;
- [ ] P05 outbox and run correlation seams reused;
- [ ] D1/Queue/R2 responsibilities are explicit;
- [ ] no data class lacks a governance declaration;
- [ ] no client contract exposes provider IDs or secrets;
- [ ] tenant, idempotency, retry, and partial-failure negatives are defined;
- [ ] FE fixtures can be built without waiting for BE implementation.

## Freeze commit

After review and merge:

- Contract Gate commit: `PENDING`
- Contract version: `p06-cg-v1`
- Dependent packets unlocked: `PENDING`
- Change requests: none unless implementation evidence invalidates this gate

After freeze, dependent packets MUST NOT silently redefine these contracts. A required change uses `docs/implementation/templates/change-request.md` before implementation changes.
