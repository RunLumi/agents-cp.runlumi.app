# Contract Gate — P06-CG

- Phase: P06 — Automations, event delivery, billing, entitlements, and data governance
- Owner: P06 coordinator
- State: **frozen**
- Contract version: `p06-cg-v1`
- Inputs: Plan00, Plan06, F15, F17, F18, F20, ADR 0001–0006, P05-CG, P05-COORD-02, and current ZCode cron/off-peak behavior
- Preconditions: P05 is merged with a conditional pass; P05 limitations remain explicit and are not redefined here
- Normative clarifications: `P06-CR-001` (lease/off-peak), `P06-CR-002` (entitlements/licensing), `P06-CR-003` (deletion/R2)
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
| Automation execution correlation | `AutomationRunLink` | Server-owned link from one occurrence/lease to the existing P05 `Run`; it is not a second run authority. |
| Off-peak policy | `OffPeakPolicy` | Explicit normal/off-peak mode and safety restrictions; it is not flattened into ordinary cron. |
| Event envelope | `EventEnvelope` | Existing P01 versioned durable event contract, extended only with P06 event types/payloads. |
| Webhook endpoint | `WebhookEndpoint` | Org-owned HTTPS destination, subscriptions, secret reference, and delivery policy. |
| Webhook delivery | `WebhookDelivery` | One retryable attempt/history row for one stable event and endpoint. |
| Notification | `Notification` | Durable in-app informational projection; critical security events remain mandatory. |
| Billing provider adapter | `BillingProviderAdapter` | Boundary that maps provider state to Lumi subscription state; provider IDs never enter product logic. |
| Plan | `Plan` | Lumi product plan keyed by a stable Lumi key and versioned limits. |
| Billing account | `BillingAccount` | Adapter-owned billing customer/account projection; provider IDs remain private. |
| Provider entitlement projection | `ProviderEntitlementProjection` | Read-only upstream AI-provider account/coding-plan state, distinct from Lumi product entitlements. |
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
| ScheduleRule revision | `sch_` | org | immutable schedule revision |
| Occurrence | `occ_` | org | automation |
| ExecutionLease | `lse_` | org | occurrence and eligible device/host |
| WebhookEndpoint | `whe_` | org | organization |
| Webhook secret version | `whs_` | org | encrypted secret version/fingerprint |
| WebhookDelivery | `whd_` | org | endpoint and stable event |
| Webhook attempt | `wha_` | org | delivery attempt/job |
| Notification | `ntf_` | org/user | event/preferences |
| Notification delivery | `ndl_` | user/org | notification channel attempt |
| Plan | `plan_` | platform | none |
| BillingAccount | `bac_` | org | provider adapter and customer reference |
| ProviderEntitlementProjection | `pep_` | org | upstream provider account reference |
| Subscription | `sub_` | org | billing account and plan |
| EntitlementDefinition | `ent_` | platform/org | none |
| EntitlementGrant | `egr_` | org | subscription or override |
| LicenseSnapshot | `lic_` | org | subscription/policy state |
| DataGovernancePolicy | `dgp_` | org/project | none |
| ExportJob | `exp_` | org/account | requested by principal |
| DeletionJob | `del_` | org/account | requested by principal |
| Deletion step | `dts_` | org/account | data class/object reference |
| Deletion certificate | `delc_` | org/account | final audited result |
| QueueJob | `job_` | platform/tenant | dedupe key |

`Occurrence` identity is deterministic from the automation ID, the immutable schedule-rule revision ID, and the canonical schedule instant (`UNIQUE(automation_id, schedule_rule_id, scheduled_for_utc)`). A retry, queue redelivery, reconnect, or second claim cannot mint a new occurrence ID for the same revision/instant. Manual runs use a deterministic occurrence key derived from the automation ID and the authorized run-now idempotency key (`UNIQUE(automation_id, trigger_key_digest)`); they are not silently treated as a scheduled occurrence. `queue_one` permits at most one pending successor for the same automation, while `cancel_previous` records a cancellation reason before creating the successor.

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
- `cron`: a canonical five-field expression, IANA timezone, `dom_dow_mode` (`or` for standard cron OR semantics or `and`), and `dst_policy` (`skip_duplicate`, `run_first`, or `run_both`); the server stores the normalized expression and timezone.
- `interval`: `every` (1–200) plus `unit` (`minutes`, `hours`, `days`, `weeks`, `months`, or `years`), an anchor instant, timezone, and optional calendar selectors. Minutes/hours use elapsed arithmetic; days/weeks/months/years use local-calendar arithmetic. Invalid calendar dates are skipped, not rolled into another period.
- `manual`: no scheduled instant; only `run-now` may create an occurrence.

DST behavior is explicit: a missing local time is skipped with `dst_missing_time`; a repeated local time runs once at the first UTC instant or twice at both UTC instants according to the frozen policy. The canonical UTC instant, not the display expression, determines occurrence identity. `overlap_policy` is one of `allow`, `skip`, `queue_one`, or `cancel_previous`. `missed_policy` is one of `skip`, `run_once`, or `catch_up`; `catch_up` requires a bounded positive `catch_up_limit` from 1–20 and the server inspects at most seven days of missed history. Defaults are `skip` for overlap and `run_once` for missed schedules.

`OffPeakPolicy` is a distinct execution class, not a cron window or a generic interval:

```json
{
  "schema_version": 1,
  "eligibility_source": "provider_ticket",
  "allowed_route_aliases": [],
  "tool_constraints": {
    "deny_automation_mutation": true,
    "deny_recursive_off_peak": true,
    "allow_background_processes": false
  }
}
```

A provider-ticket off-peak occurrence has no clock schedule; ticket renewal does not create a second logical occurrence. Scheduled normal automations may create an off-peak task only when the current policy allows it. Off-peak runs retain ZCode's recursive-creation and background-process restrictions; network, browser, and computer decisions remain composed from current P05 tool policy and route configuration rather than blanket booleans in this object. The server re-evaluates the class at dispatch and execution time, and may narrow but never broaden the host safety restrictions.

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
  "execution_principal": {
    "kind": "user",
    "id": "usr_0123456789abcdef0123456789abcdef"
  },
  "target": {
    "kind": "eligible_device",
    "device_id": null,
    "workspace_binding_id": "wsb_0123456789abcdef0123456789abcdef",
    "required_capabilities": ["text"]
  },
  "schedule": {"kind": "manual"},
  "execution_policy": {
    "model_alias": "coding-default",
    "budget_id": null,
    "tool_policy_scope": "project",
    "required_policy_version": null
  },
  "off_peak_policy": null,
  "status": "active",
  "version": 1,
  "next_run_at": null,
  "last_run_at": null,
  "schedule_cursor_at": null,
  "execution_retry": {
    "max_start_attempts": 2,
    "lease_ttl_seconds": 300,
    "heartbeat_interval_seconds": 30
  },
  "created_by_user_id": "usr_0123456789abcdef0123456789abcdef",
  "created_at": "2026-09-25T12:00:00.000Z",
  "updated_at": "2026-09-25T12:00:00.000Z"
}
```

Target kinds are `eligible_device`, `specific_device`, `remote_workspace`, and `server_runner` (the latter is accepted only when a server runner is actually enabled). A device target is resolved from current enrollment, binding, capability, membership, and policy state. The server stores an authoritative `schedule_cursor_at` and advances it transactionally with due-occurrence generation. Cursor advancement is idempotent and bounded by the missed-window policy; it is not inferred from a device's last run. This prevents reconnect bursts after a long offline period. The execution principal is a server-resolved discriminated value (`user` in the P06 MVP, `service_account` when the F14 service identity is available); membership, service identity, device health/capability, tool policy, model route, budget, entitlement, and policy freshness are rechecked immediately before creating the P05 session/run. If no current P05-compatible principal exists, the occurrence is skipped with a stable reason rather than run under a fabricated identity. Automation policy fields are constraints, not authority: a null model/budget means inherit the agent/project default, while a supplied value may only narrow or select an already-authorized route. At execution time P05 admission recomputes current tool policy, model route, budget reservation, device health/capability, entitlement, and policy snapshot. Client-supplied target, principal, or schedule values never bypass current authorization.

## Occurrence and lease contract

### Occurrence

```json
{
  "occurrence_id": "occ_0123456789abcdef0123456789abcdef",
  "automation_id": "aut_0123456789abcdef0123456789abcdef",
  "org_id": "org_0123456789abcdef0123456789abcdef",
  "project_id": "prj_0123456789abcdef0123456789abcdef",
  "kind": "scheduled",
  "execution_principal": {
    "kind": "user",
    "id": "usr_0123456789abcdef0123456789abcdef"
  },
  "off_peak_mode": "normal",
  "policy_snapshot_id": "pol_0123456789abcdef0123456789abcdef",
  "policy_version": 4,
  "scheduled_for": "2026-09-25T16:00:00.000Z",
  "schedule_rule_id": "sch_0123456789abcdef0123456789abcdef",
  "schedule_rule_version": 3,
  "state": "pending",
  "attempt": 0,
  "reason_code": null,
  "run_id": null,
  "created_at": "2026-09-25T15:59:59.000Z",
  "updated_at": "2026-09-25T15:59:59.000Z"
}
```

States:

```text
pending → dispatching → leased → started → succeeded
pending|dispatching|leased → skipped
pending|dispatching|leased|started → failed
pending|dispatching|leased|started → cancelled
pending|dispatching|leased → missed
leased → pending (only when the server can prove execution never started)
leased|started → ambiguous (lost authority after execution may have begun)
ambiguous → no automatic re-dispatch
```

Scheduled occurrence identity is `UNIQUE(automation_id, schedule_rule_id, scheduled_for_utc)`. `schedule_rule_id` is immutable; editing or rolling back a schedule creates a new revision and therefore a new logical slot. Manual occurrences use `UNIQUE(automation_id, trigger_key_digest)` where the digest references the P01 idempotency record. After the P01 idempotency TTL expires, a new manual run key may intentionally create a new manual occurrence.

`ambiguous` is a reconciliation state, not a retryable state. A lease renewal, device reconnect, or worker recovery may attach evidence and resolve it through an audited operator/support action, but must not automatically issue a second lease. This is the enforceable distributed-systems boundary: at most one current server-authorized lease; a network partition cannot prove that a disconnected host did not start side effects.

Terminal occurrence history is immutable. A lease expiry or retry updates only the current occurrence/lease projection; it does not create a second logical occurrence. `skip`, `missed`, `failed`, `ambiguous`, and `cancelled` require a bounded stable reason code. The occurrence stores the server-resolved execution principal, P06 policy snapshot/version, and off-peak mode so P05 run/tool/inference admission can re-evaluate the same trusted context. `cancel_previous` is best-effort for a connected host and does not claim that a passive-disconnected host stopped; the successor stays queued until the predecessor reaches a terminal state or an audited reconciliation explicitly resolves `ambiguous`. An ambiguous predecessor is never treated as safe to overlap. A `queue_one` successor that reaches its bounded queue age is recorded as `skipped` with a stable reason rather than blocking forever.

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

Lease states are `active`, `released`, `expired`, and `revoked`. A claim is an atomic compare-and-set from `pending`/`dispatching` to `leased`, with a unique active lease per occurrence. The claim response includes a one-time raw lease token; D1 stores only its fingerprint, and browser responses never include it. The lease API supports claim, renew, start, settle, and release; release is allowed only before the occurrence is marked started. A renewal is bounded and cannot extend an already ambiguous occurrence. Only a server-issued device/host token can claim. A second device receives the existing lease projection or a stable `occurrence_already_claimed` response; it cannot receive the raw lease token. Lease tokens are stored only as fingerprints. Device revocation, membership loss, policy expiry, or device loss invalidates the lease at settlement and causes the occurrence to follow the configured missed/retry policy; it never grants a new capability.

`AutomationRunLink` is the immutable correlation row from one occurrence attempt to one existing P05 `run_id`. P05 `Run` remains the sole execution state machine; P06 adds only nullable occurrence/lease correlation to that run and a unique link row. A pre-start lease expiry may create a later attempt and a new P05 `Run`; once a run has started, a lost lease becomes `ambiguous` and no new P05 run is automatically created. Creating a P05 run and its link is server-owned and idempotent by `(occurrence_id, attempt)`.

Before a host may execute any tool or external side effect, the server must durably create or discover the P05 run/link in response to the idempotent `start` transition. The response includes the current lease ID, lease version/fence, and run ID. The host must retain that fencing context for settlement and tool-result correlation. A stale lease, stale fence, or response from a superseded attempt is rejected.

`AutomationDefinition` carries bounded execution retry settings: `max_start_attempts` (1–3), `lease_ttl_seconds` (30–3600), and `heartbeat_interval_seconds` (10–60). A pre-start lease expiry releases/requeues only when the server can prove no run/start side effect occurred. A post-start expiry enters `ambiguous`; repeated provider/device recovery never changes that state automatically.

## Event and webhook contract

### Durable event envelope

Business transactions emit the existing P01 `EventEnvelope` to `outbox_events`. P06 payloads are bounded metadata only and use versioned dotted event types. Every event has one stable `event_id` across queue redelivery and webhook retries. Global event ordering is not guaranteed; consumers that care about resource order must use the included resource version/sequence.

P06 event names are frozen in this gate:

- `automation.definition.created.v1`
- `automation.definition.updated.v1`
- `automation.definition.paused.v1`
- `automation.definition.resumed.v1`
- `automation.definition.deleted.v1`
- `automation.occurrence.created.v1`
- `automation.occurrence.dispatched.v1`
- `automation.occurrence.started.v1`
- `automation.occurrence.completed.v1`
- `automation.occurrence.failed.v1`
- `automation.occurrence.skipped.v1`
- `automation.occurrence.missed.v1`
- `automation.occurrence.lease_expired.v1`
- `automation.occurrence.ambiguous.v1`
- `webhook.endpoint_created.v1`
- `webhook.endpoint_updated.v1`
- `webhook.endpoint_rotated.v1`
- `webhook.endpoint_disabled.v1`
- `webhook.test.v1`
- `webhook.delivery_succeeded.v1`
- `webhook.delivery_retry_scheduled.v1`
- `webhook.delivery_dead_lettered.v1`
- `webhook.delivery_replayed.v1`
- `notification.created.v1`
- `notification.delivery_succeeded.v1`
- `notification.delivery_retry_scheduled.v1`
- `notification.delivery_dead_lettered.v1`
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

Every event descriptor has `schema_version`, `subject_type`, required identifiers, `resource_version`, bounded metadata, `security_class`, `recipient_scope`, and `fanout_eligible`. Required payload fields by family are frozen as follows:

| Event family | Required payload fields |
|---|---|
| `automation.definition.*` | `automation_id`, `org_id`, `project_id`, `version`, `status`, `next_run_at` |
| `automation.occurrence.*` | `occurrence_id`, `automation_id`, `attempt`, `state`, `resource_version`, optional `run_id`, bounded `reason_code` |
| `billing.*` | `subscription_id`, `org_id`, `status`, `effective_at`, bounded grace/period fields |
| `entitlement.*` | `grant_id`, `org_id`, `entitlement_key`, typed value, `source`, `effective_at`, optional `expires_at` |
| `data_policy.*` | `policy_id`, `org_id`, `version`, bounded changed keys |
| `export.*` / `deletion.*` | `job_id`, `scope_type`, `scope_id`, `state`, `attempt`, `resource_version`, optional `failure_code` |
| `notification.*` | `notification_id`, `event_id`, `recipient_scope`, `channel`, `state` |

No family may add prompt/response content, raw tool arguments, credentials, provider payloads, or unbounded URLs. Webhook fan-out requires `event.organization_id == endpoint.org_id`; endpoint subscriptions are evaluated against the immutable event tenant scope, never a queue message's untrusted org field. Mandatory security events are the P01/P05 security event families (`auth.*`, `device.revoked`, `organization.suspended`, approval/security denials, and credential revocation) and are delivered to the owning org's security recipients regardless of informational preferences.

### Webhook endpoint and delivery

Endpoint configuration stores encrypted secret material, never a returned plaintext secret after creation/rotation. It contains a `secret_version`/key ID, an explicit finite set of subscribed event types (wildcards are not accepted), enabled state, description, failure policy, and version. Test delivery uses a dedicated bounded `webhook.test.v1` event and the same tenant/SSRF/signature path. HTTPS and SSRF validation are required at creation, update, test delivery, and delivery time. Userinfo, non-HTTPS schemes, non-443/8443 ports, redirects, proxy rewriting, IPv4/IPv6 loopback/link-local/private ranges, and cloud metadata ranges are rejected. DNS is resolved and revalidated immediately before each outbound connection; a hostname that changes to a blocked address fails closed. Development fixtures may use a local endpoint only through an explicit test adapter, never a production route.

Delivery is at-least-once. A logical `WebhookDelivery` has states `pending`, `queued`, `delivering`, `delivered`, `retry_wait`, `dead_letter`, and `cancelled`; each attempt is an append-only `WebhookDeliveryAttempt`. A retry keeps the same logical delivery and event ID but creates a new attempt/job. An authorized replay always creates a successor logical delivery linked by `replay_of_delivery_id`; it never edits or resets the original delivery/event.

Signature contract:

```text
X-Lumi-Event-Id: evt_<32 hex>
X-Lumi-Timestamp: <unix seconds>
X-Lumi-Signature-Key-Id: whs_<opaque key version>
X-Lumi-Signature: v1=<lowercase hex HMAC-SHA256(secret, timestamp + "." + event_id + "." + raw_body)>
```

Only an HTTP `2xx` response is success. Network errors, timeouts, `408`, `425`, `429`, and `5xx` are retryable; other `4xx` responses are terminal except `409`/`425` when explicitly classified by endpoint policy. A timeout may result in a duplicate request, so consumers must deduplicate by stable event ID. `Retry-After` is honored only when bounded to 24 hours; otherwise the deterministic backoff is used. Redirects are disabled. The delivery worker uses a 10-second connect/read timeout, caps and discards response bodies above 64 KiB, and never logs them. The exact serialized UTF-8 body is stored once per logical delivery and reused byte-for-byte for every attempt, so signatures remain verifiable.

The signed body is the exact UTF-8 request body. Timestamps outside the endpoint's replay window are rejected. No prompt, response, credential, raw tool argument, or secret is included in the payload. Endpoint policy is bounded to 1–8 attempts; the default is 8 attempts, 30-second base delay, 24-hour maximum delay, and 20% deterministic jitter. Exhaustion dead-letters the delivery. Optional auto-disable is disabled by default and, when enabled, requires a threshold of at least 10 consecutive terminal failures. Retries use the secret version captured when the logical delivery was created; an explicit replay after rotation uses the current endpoint secret version and creates a new linked logical delivery with the same event/body. Disabling an endpoint cancels pending deliveries but does not erase delivered/dead-letter history. `webhook.delivery_*`, `webhook.endpoint_*`, and notification-delivery events are not fanned out to the same webhook endpoint by default; this prevents recursive delivery loops.

### Notification channels

Informational notifications support `in_app` and `email` channels. Each notification has a stable notification ID, event ID, recipient scope, bounded rendered metadata, delivery status, attempt count, and dedupe key. Security events are mandatory and cannot be disabled by ordinary preferences. Email delivery uses the existing Worker email binding behind a small adapter; an unavailable email provider creates a retryable notification-delivery state and never rolls back the business mutation. Slack/Teams delivery is reserved for the plugin/integration layer and is not part of the P06 contract. Notification center reads are cursor-paginated by `(created_at, notification_id)`, support unread/category filters, and resolve recipients from the authenticated principal plus current org/project membership; a foreign notification ID returns the same non-disclosing not-found shape.

### QueueJobEnvelope

The existing `OUTBOX_QUEUE` remains typed as P01 `EventEnvelope` for business events. P06 `QueueJobEnvelope` messages use a separate `JOBS_QUEUE` and `JOBS_DLQ` binding with their own Worker handler; queue messages are never decoded as an untrusted union. This keeps source-event delivery state separate from per-endpoint webhook delivery state and allows job retries without rewriting a business event.

Workers consume the following frozen `job_type` values: `automation.generate_occurrence`, `automation.dispatch`, `automation.expire_lease`, `webhook.deliver`, `notification.deliver`, `billing.sync`, `license.issue`, `export.run`, and `deletion.run`. Unknown job types are permanent failures; malformed or unbounded payloads are rejected before domain dispatch.

```json
{
  "job_id": "job_0123456789abcdef0123456789abcdef",
  "job_type": "automation.dispatch",
  "schema_version": 1,
  "dedupe_key": "automation.dispatch:occ_0123456789abcdef0123456789abcdef",
  "event_id": "evt_0123456789abcdef0123456789abcdef",
  "occurred_at": "2026-09-25T16:00:00.000Z",
  "attempt": 1,
  "correlation_id": "req_0123456789abcdef0123456789abcdef",
  "tenant_scope": {"org_id": "org_0123456789abcdef0123456789abcdef"},
  "payload_ref": "d1:automation_occurrences/occ_...",
  "payload": {"automation_id": "aut_...", "occurrence_id": "occ_..."}
}
```

The envelope is bounded and metadata-only. `dedupe_key` is unique for the logical job; a redelivered envelope with the same key is acknowledged as duplicate only after the D1 domain job and queue state are durably complete. `queue_job_envelopes` persists job ID, type, schema version, tenant scope, subject version, attempt, state, lease, next time, and stable failure code. Claiming `queued → running` is an atomic CAS on job ID, attempt, state, and lease version; a consumer crash before that CAS leaves the job retryable, while a crash after it is recovered by lease expiry. Normal retries keep the job ID and increment attempt; explicit replay/resume creates a linked new generation. A unique `(job_type, tenant_scope, dedupe_key)` constraint and durable side-effect/dedupe transition—not Cloudflare Queue delivery guarantees—enforce dedupe. Delayed jobs recheck current authorization, entitlement, policy, and organization state before acting.

The P06 coordinator integration must add a separate `JOBS_QUEUE`/`JOBS_DLQ`, a private `EXPORT_ARTIFACTS` R2 binding, and explicit signing/encryption secret bindings to Wrangler configuration. `lib.rs` must expose a typed P01 outbox queue handler, a typed P06 jobs queue handler, and a scheduled handler for automation cursors, job leases, expiry cleanup, and bounded outbox retries. The existing `OUTBOX_QUEUE` source-event status is never reused as webhook-delivery status. Queue transport is never treated as authorization or exactly-once delivery.

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

Subscription states are `trialing`, `active`, `grace`, `past_due`, `suspended`, and `cancelled`. A provider adapter maps provider state into these values and records an opaque provider reference, never a product/price ID in product logic. Normal transitions are `trialing → active|cancelled`, `active → grace|past_due|suspended|cancelled`, `grace → active|past_due|suspended|cancelled`, `past_due → active|grace|suspended|cancelled`, and `suspended → active|cancelled` only through a new authenticated provider event. Terminal `cancelled` does not silently reactivate; a new subscription row/provider account binding is required. Plan changes update an immutable plan pointer and never rewrite subscription history. Provider events are idempotent by provider event ID, bound to the adapter account, ordered by provider version/timestamp, and applied atomically with a D1 subscription version.

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

`BillingAccount` stores only the adapter-owned opaque provider account reference, billing status, and seat policy. If a plan is seat-based, billable membership states are explicit (`active` and `suspended` are billable; pending invitations, removed members, and viewers are not billable unless the plan contract says otherwise). Seat counts are derived from authoritative membership rows, not client totals.

`ProviderEntitlementProjection` is a read-only status for an upstream provider account/coding plan (`available`, `degraded`, `unavailable`, or `unknown`) with an opaque provider reference and observed timestamp. It can block or degrade a provider-specific route, but it never changes the Lumi subscription, product entitlement, authorization permission, or usage-budget state.

A short-lived signed `LicenseSnapshot` is carried inside the existing P03 device-policy response; it is not a second authority or a separate `/devices/license` endpoint. It contains entitlement values, `policy_fresh_until`, `offline_valid_until`, snapshot ID/version, issued timestamp, and an Ed25519 signature over canonical JSON with a key ID. Canonical license bytes are UTF-8 JSON with lexicographically sorted object keys, no insignificant whitespace, and integer timestamps encoded as RFC 3339 UTC. The signature includes the snapshot ID and key ID in the signed object; clients reject unknown key IDs, malformed canonical bytes, expiry, audience/device mismatch, or policy-version rollback. Verification allows at most 120 seconds of clock skew, binds `org_id`, `device_id`/audience, capability class, policy version, `policy_fresh_until`, and `offline_valid_until`, and rejects a snapshot older than the last accepted policy version for that audience. Key rotation retains a bounded verification overlap and old keys never grant new work after their expiry. Transient billing/provider outages must not brick unrelated local editing/execution. Cloud-paid inference may fail sooner, with a stable entitlement/billing reason.

The baseline grace windows are deliberately separate: local-only capabilities may use a signed snapshot for up to seven days, cloud control-plane managed operations may use a 24-hour bounded grace, and platform-paid inference receives no additional billing grace. These are policy defaults, not a promise that a provider outage is local-safe for every feature; a capability class may narrow them.

Effective entitlement precedence is deterministic: platform default < active plan value < active subscription-derived grant < active, scoped internal override. A missing value fails closed for a protected capability; an override may grant or deny only its named key/scope, must have an expiry, and cannot erase an audit/legal denial. Downgrade computes over-limit counts from authoritative rows and blocks new/expansion mutations without deleting data.

`LicenseState` is a server-side projection with `active`, `grace`, `past_due`, `suspended`, `cancelled`, `expired`, and `provider_unavailable` states. The capability matrix is:

| Subscription/provider state | Local-only new work | Cloud control-plane managed work | Platform-paid inference |
|---|---|---|---|
| `active` + provider available | allowed by policy | allowed by policy/entitlement | allowed by provider + budget |
| `grace` + provider available/unknown | allowed until `offline_valid_until` | allowed until cloud grace expiry | denied after provider billing uncertainty/grace |
| `past_due` | allowed only until signed offline expiry | denied | denied |
| `suspended`/`cancelled` | no new work; already-authorized in-flight work only | denied | denied |
| provider unavailable/unknown | local unaffected by policy | cloud state follows subscription grace | denied or provider-degraded with stable reason |

Grace begins at the first accepted provider transition/last successful sync event, is not extended by repeated failed polling, and expires against the server clock. A stale or future-dated provider event cannot extend it.

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
| Notification delivery | delivery metadata | user/org/channel | 30 days | included | delete/tombstone | status/error code only |
| Plan/subscription | commercial metadata | platform/org | seven-year baseline | redacted billing export | tombstone | status only |
| Provider entitlement projection | upstream account metadata | org/provider adapter | 30 days after last observation | redacted status | tombstone | status only |
| Entitlement grant/license snapshot | commercial/policy metadata | org | offline expiry + 30 days | redacted state | tombstone | keys/status only |
| Data governance policy | privacy configuration | org/project | until lifecycle deletion | included | delete/tombstone | metadata only |
| Export job metadata | sensitive pointer | org/requester | 90 days | included | delete/tombstone | job status only |
| Export artifact | sensitive content | org/requester | short-lived, default 24 hours | downloadable only through expiring access | delete object and derived copies | never content |
| Deletion job/task | sensitive operational metadata | org/account | 90 days for steps, 365 days for certificate | redacted job state | tombstone after completion | state/reason only |
| Queue job envelope | operational metadata | tenant/platform | 90 days after terminal | not exported | delete after retention | IDs/status only |

`DataGovernancePolicy` wire baseline:

```json
{
  "policy_id": "dgp_0123456789abcdef0123456789abcdef",
  "org_id": "org_0123456789abcdef0123456789abcdef",
  "project_id": null,
  "logging_mode": "metadata_only",
  "class_retention_overrides": {},
  "legal_hold": false,
  "backup_lifecycle": "platform_35_day_expiry",
  "provider_retention_disclosure": "external_policy",
  "default_export_expiry_seconds": 86400,
  "version": 1
}
```

Baseline retention values are frozen for P06 job/delivery projections: occurrence/lease/automation-run links 90 days after terminal; webhook delivery attempts and notification deliveries 30 days; queue job/dead-letter rows 90 days after terminal; export job metadata 90 days; export artifacts 24 hours by default; license/entitlement metadata `offline_valid_until + 30 days`; deletion step rows 90 days and deletion certificates 365 days; operational logs/traces 30 days; platform backups expire on a 35-day lifecycle. Audit/security events default to 365 days unless legal/entitlement policy requires longer; usage/cost/subscription records default to seven years for financial/legal audit and are tombstoned rather than physically rewritten. A legal hold blocks deletion/expiry for its scoped records until an audited support/legal release. These defaults may be shortened by policy, never extended beyond the legal maximum without an audited override.

Content logging mode is `metadata_only` (default), `redacted_content`, or `full_content`, scoped to org/project. `metadata_only` permits IDs, versions, state, counts, bounded reason codes, and timing; `redacted_content` may include explicitly redacted diagnostic excerpts; `full_content` is an audited, time-bounded diagnostic setting and never changes the normal P01/P05 event, audit, webhook, or log schemas. Raw prompts, responses, tool arguments, credentials, and secrets remain prohibited in all modes. Metadata-only is the default for inference/control-plane observability. Export artifacts are encrypted/access-controlled, have an expiry and checksum, and are never represented by a public permanent URL. Deletion traverses metadata, R2 objects, caches, search indexes, and derived copies; legal/security retention uses minimized/tombstoned records where justified.

P06 table-level governance map:

| P06 table/class | Sensitivity/owner | Default retention | Export | Deletion/tombstone | Logging |
|---|---|---|---|---|---|
| `automation_definitions` | internal org/project | until deletion | included | delete/tombstone | IDs/status/version |
| `automation_schedule_rules` | internal org/project | until definition deletion | included | immutable history retained, labels tombstoned | rule version/hash |
| `automation_occurrences` | operational org/project | 90d terminal | included | delete/tombstone | state/reason |
| `automation_leases` | security/operational | 90d terminal | redacted | delete/tombstone | state/fence only |
| `automation_occurrence_attempts` | operational/audit | 90d terminal | redacted | tombstone after certificate | attempt/state |
| `automation_run_links` | correlation metadata | 90d terminal | redacted | tombstone | IDs/state |
| `webhook_endpoints` | secret-bearing org | endpoint lifetime | sanitized | delete secret/config | state/version |
| `webhook_secrets` | restricted secret | rotation/revoke lifetime | never | crypto-erase/tombstone | key ID only |
| `webhook_deliveries` | operational org | 30d | sanitized | tombstone | event/status |
| `webhook_delivery_attempts` | operational org | 30d | sanitized | tombstone | outcome/error code |
| `notification_preferences` | user/org | account/org lifetime | owner export | delete/tombstone | channel/state |
| `notifications` | user/org content | 30d | owner export | delete/tombstone | metadata only |
| `notification_deliveries` | operational user/org | 30d | owner export | delete/tombstone | channel/status |
| `plans`/`plan_entitlements` | commercial platform | immutable plan history | sanitized billing export | retain version, tombstone label | key/version |
| `billing_accounts` | commercial/private | subscription lifetime | redacted | tombstone provider ref | status only |
| `subscriptions`/`subscription_events` | commercial/audit | seven-year baseline | redacted billing export | tombstone user ref, retain state | state/version |
| `provider_entitlement_projections` | external status | observed-state policy | sanitized status | tombstone | normalized status/reason |
| `entitlement_definitions`/`entitlement_grants` | commercial/policy | grant expiry + audit | sanitized values | revoke/tombstone | key/source/expiry |
| `license_snapshots`/`license_states`/signing-key metadata | restricted policy | offline expiry + 30d | sanitized state | tombstone | state/key ID/expiry |
| `data_governance_policies`/class registry | privacy config | policy lifetime | included | delete/tombstone | version/changed keys |
| `export_jobs` | sensitive pointer | 90d | metadata only | delete/tombstone | state/attempt |
| `export_artifacts` metadata/download grants | restricted content | 24h object/grant | downloadable only | delete R2/derived copies, tombstone | opaque key/expiry |
| `deletion_jobs`/`deletion_tasks` | restricted legal/operational | job policy/certificate | redacted state | tombstone after certificate | state/step/reason |
| `deletion_certificates` | legal audit | 365d or legal policy | restricted certificate | retain/tombstone | certificate ID/status |
| `queue_job_envelopes` | operational tenant/platform | 90d terminal | not exported | delete/tombstone | job/state/error |
| `provider_sync_state`/idempotency/download-grant metadata | confidential operational | bounded retry/access TTL | never raw payload | delete/tombstone | state/version |

The P06 registry also governs existing P01–P05 classes. These rows are normative migration guidance, not an invitation to delete immutable records directly:

| Existing data class | Sensitivity/scope | Export and deletion treatment | Logging rule |
|---|---|---|---|
| Identity, login session, passkey/authenticator metadata | high, user-scoped | personal export; revoke/delete credentials and sessions; tombstone identity where legal retention requires | IDs/status only, never codes, tokens, or key material |
| Organization, membership, invitation, team | internal/personal, org-scoped | org-authorized export; delete/tombstone on lifecycle completion | metadata/status only |
| Device enrollment, device metadata, workspace binding | internal/security, org-scoped | org export; revoke/delete device and binding; tombstone audit correlation | IDs/capability/status only |
| Provider, model, route, credential metadata | config/secret boundary, org/platform | redacted org export; credentials revoke/delete and never export secret material | no credential values/URLs with embedded secrets |
| Policy snapshots/acks and P05 tool/policy records | policy metadata, org/platform | redacted export; delete/tombstone after policy/audit retention | keys/version/status only |
| Inference requests, usage, cost, budget/rate rows | commercial/sensitive, org/project/user | scoped export; tombstone/minimize after legal/billing retention; never rewrite history | counts/cost/status only |
| Agent definitions/sessions, runs, run events, tool/approval metadata | potentially sensitive, org/project/device | org export; content references follow retention policy; delete/tombstone metadata and preserve required audit | no prompts, responses, arguments, or raw content |
| Artifact refs and object-backed artifacts | sensitive, org/project/run | export only through approved artifact path; delete metadata plus object/cache/index copies | opaque refs/checksums only |
| Audit/security events | high/security/legal, org/platform | restricted redacted export; retain/tombstone rather than physical delete when legally required | metadata only |
| Outbox/queue/dead-letter rows | operational, tenant/platform | not user content export; delete/tombstone after bounded delivery retention | event ID/status/error code only |
| Upstream provider data and provider account state | external, provider-policy | export only Lumi status/reference; never claim provider deletion; show provider policy link/status separately | provider status/reason only |
| Secrets/credentials and encrypted key material | highest, owner-scoped | never export; revoke/delete ciphertext and key references | never log or include in errors |

### ExportJob and DeletionJob states

```text
Export: requested → queued → collecting → packaging → verifying → ready → expired
                         ↘ retry_wait → collecting
                         ↘ failed
                         ↘ cancelled
Deletion: requested → awaiting_grace → queued → planning → deleting → verifying → completed
                                      ↘ retry_wait → deleting
                                      ↘ needs_attention → deleting (authorized resume)
                                      ↘ cancelled
```

Export jobs freeze a category manifest and snapshot cutoff at request time. Categories are explicit (`identity`, `organization`, `devices`, `runs_metadata`, `usage_billing`, `audit_redacted`, `notifications`, and `data_governance`) and a requester may select only categories allowed by current scope. The export is a consistent tenant-scoped snapshot; retries reuse the same cutoff/category manifest. Personal export and deletion require reauthentication and typed confirmation; account deletion requires the user to leave/transfer organizations or receive a stable `deletion_requires_org_exit` result, supports a bounded grace-period cancel, and never claims deletion of local ZCode or upstream provider data.

Every job has a stable job ID, dedupe key, org/account scope, requested-by principal, state version, attempt count, bounded failure code, timestamps, legal-hold state, and audit correlation. A retry/replay must be idempotent. `ready` is the only export state that can mint a download grant. Download authorization is checked again at download time and is bound to the job scope, snapshot cutoff, and expiry. Deletion step completion is recorded per data class/object reference; `needs_attention` covers legal hold, unresolved external references, or exhausted retries. Partial failure is resumable only through the explicit job resume operation.

The existing P02 organization lifecycle transition to `pending_deletion` is a compatibility bridge, not a second deletion system. The existing `POST /api/v1/orgs/{org_id}/deletion` route remains the sole organization deletion request: it requires reauthentication and typed confirmation, moves the organization to `pending_deletion`, and transactionally creates/links one P06 `DeletionJob`. Normal organization permissions stop new work once `pending_deletion` is set, while the job-status/resume endpoints use an explicit deletion-job scope and lifecycle exception. Automation dispatch, webhook/notification fan-out, billing writes, export creation, and deletion retries are fenced/cancelled after the cutoff so delayed jobs cannot resurrect deleted data. Completion performs tombstone/minimization and object traversal; it does not blindly drop rows blocked by immutable audit/usage FKs.

## API contract

All routes are under `/api/v1`; all browser mutations require CSRF and idempotency keys where a retry can duplicate work. Machine routes use device/service identity and never accept browser-supplied authoritative lease, billing, or accounting values.

Wire conventions:

- List endpoints return `{items, next_cursor, has_more}` with opaque cursors, default limit 50, maximum limit 100, and stable ordering.
- Create/patch/delete/pause/resume/run-now/webhook/billing/data mutations use the P01 idempotency scope `(principal, organization, method, path, key_digest)` and request fingerprint. PATCH/DELETE state transitions also require the current `version` (or `If-Match` equivalent) and return `409 version_conflict` on stale writes.
- Success is `200` for reads/updates, `201` for resource/job creation, `202` for enqueue-only work, `204` for a confirmed delete/cancel with no body, and `409/422/403/404/503` for the stable P01/P06 reasons below. Errors use the P01 error envelope and never expose provider/SQL strings.
- Every tenant-owned path requires the authenticated org header/context to match the path, active membership, current org state, resource scope, and central permission. Foreign IDs return the same non-disclosing `404 resource_not_found` shape. Device routes derive org/project/workspace/device from the device token and binding, reject cookie/browser auth, and never trust body scope IDs.
- All P06 event fan-out requires `event.organization_id == endpoint.org_id` before subscription evaluation. Notification reads filter by the authenticated principal and current tenant scope.
- Delayed jobs recheck current org state, membership, entitlement, policy, and resource scope before acting; a job delayed across `pending_deletion` is fenced/cancelled rather than allowed to resurrect work.

| Method | Path | Permission/identity | Purpose |
|---|---|---|---|
| GET/POST | `/orgs/{org_id}/automations` | `automations.read` (GET), `automations.manage` (POST) | List/create definitions. |
| GET/PATCH/DELETE | `/orgs/{org_id}/automations/{automation_id}` | `automations.read` (GET), `automations.manage` (PATCH/DELETE) | Read/update/delete definition. |
| POST | `/orgs/{org_id}/automations/{automation_id}/pause` | `automations.manage` | Pause new dispatch. |
| POST | `/orgs/{org_id}/automations/{automation_id}/resume` | `automations.manage` | Resume after current policy/entitlement checks. |
| POST | `/orgs/{org_id}/automations/{automation_id}/run-now` | `automations.run` | Create one manual occurrence. |
| GET | `/orgs/{org_id}/automations/{automation_id}/occurrences` | `automations.read` | Cursor-paginated occurrence history. |
| GET | `/devices/automations/due` | device token | Return bounded eligible unleased work. |
| POST | `/devices/automation-occurrences/{occurrence_id}/claim` | device token | Atomic lease claim. |
| POST | `/devices/automation-leases/{lease_id}/renew` | device token | Extend a current pre-ambiguous lease. |
| POST | `/devices/automation-occurrences/{occurrence_id}/start` | device token | Idempotently create/get the P05 `run_id` and mark started. |
| POST | `/devices/automation-occurrences/{occurrence_id}/settle` | device token | Settle success/failure with lease/run binding. |
| POST | `/devices/automation-occurrences/{occurrence_id}/release` | device token | Release only before started. |
| GET/POST | `/orgs/{org_id}/webhooks` | `webhooks.read` (GET), `webhooks.manage` (POST) | List/create endpoint config. |
| PATCH/DELETE | `/orgs/{org_id}/webhooks/{endpoint_id}` | `webhooks.manage` | Update/disable endpoint. |
| POST | `/orgs/{org_id}/webhooks/{endpoint_id}/rotate-secret` | `webhooks.manage` | Rotate secret; plaintext shown once. |
| POST | `/orgs/{org_id}/webhooks/{endpoint_id}/test` | `webhooks.manage` | Enqueue a bounded test delivery. |
| GET | `/orgs/{org_id}/webhooks/{endpoint_id}/deliveries` | `webhooks.read` | Delivery history/failures. |
| POST | `/orgs/{org_id}/webhooks/deliveries/{delivery_id}/replay` | `webhooks.manage` | Replay same event with a new attempt. |
| GET/PATCH | `/orgs/{org_id}/notification-preferences` | `notifications.read` (GET), `notifications.manage` (PATCH) | Informational preferences. |
| GET | `/notifications` | authenticated principal | App-level notification center; mandatory security events remain visible. |
| POST | `/notifications/{notification_id}/read` | authenticated principal | Mark one owned notification read idempotently. |
| GET/PATCH | `/me/notification-preferences` | authenticated principal | Personal informational notification preferences. |
| GET | `/orgs/{org_id}/billing/subscription` | `billing.read` | Current mapped subscription state. |
| GET | `/orgs/{org_id}/entitlements` | `entitlements.read` | Effective Lumi entitlement projection. |
| GET | `/orgs/{org_id}/entitlements/provider` | `billing.read` or `entitlements.read` | Upstream provider entitlement projection, kept separate. |
| POST | `/orgs/{org_id}/billing/portal-session` | `billing.manage` | Create a short-lived provider portal/checkout session; no card data enters Lumi. |
| POST | `/orgs/{org_id}/billing/change` | `billing.manage` | Request a versioned plan change; downgrade exposes over-limit remediation. |
| POST | `/orgs/{org_id}/billing/cancel` | `billing.manage` | Request cancellation through the provider adapter; historical data remains. |
| internal only | entitlement override service | service/support identity | Expiring audited override; no public browser route. |
| GET | `/devices/policy` | device token | Current policy response including the signed license/entitlement block; no second license authority. |
| GET/PATCH | `/orgs/{org_id}/data-policy` | `data.read` (GET), `data.manage` (PATCH) | Logging/retention policy. |
| GET/POST | `/orgs/{org_id}/exports` | `data.read` (GET), `data.export` (POST) | List/request organization exports. |
| POST | `/me/data/exports` | authenticated principal | Request a personal account export. |
| GET | `/me/data/exports` | authenticated principal | Personal export history/status. |
| POST | `/me/data/exports/{export_id}/download` | authenticated principal | Re-authorized short-lived personal download grant. |
| GET | `/orgs/{org_id}/exports/{export_id}` | `data.read` | Job state and expiry. |
| POST | `/orgs/{org_id}/exports/{export_id}/download` | `data.export` | Re-authorized short-lived download grant. |
| GET | `/orgs/{org_id}/deletions` | `data.read` | List organization deletion workflows. |
| POST | `/orgs/{org_id}/deletion` | `org.lifecycle` + reauthentication | Existing lifecycle request; transactionally creates/links the P06 job. |
| POST | `/me/data/deletion` | authenticated principal | Request personal account deletion workflow. |
| GET | `/me/data/deletion` | authenticated principal | Personal deletion job status. |
| POST | `/me/data/deletion/cancel` | authenticated principal + reauthentication | Cancel a personal deletion during its grace window. |
| GET | `/orgs/{org_id}/deletions/{deletion_id}` | `data.read` | Job/step/failure state. |
| POST | `/orgs/{org_id}/deletions/{deletion_id}/resume` | `data.delete` | Resume a partial failure. |

For device routes, the server derives org/project/workspace/device from the authenticated device token and current binding; body values are ignored. Every claim/renew/start/settle/release checks the occurrence belongs to that scope, the device is active/eligible, the principal/membership/policy/entitlement/budget are current, and the request carries the current lease ID plus token fingerprint/version/fence. Stale claims, renewals, starts, settlements, and tool results are rejected. `GET /devices/automations/due` is bounded (maximum 20 items) and returns only the minimum redacted metadata required to claim work.

### Representative request/response shapes

P06 request fields are bounded, reject unknown fields, and never accept authoritative lease/billing/job state from a browser:

```json
{
  "name": "Weekday review",
  "project_id": "prj_0123456789abcdef0123456789abcdef",
  "agent_definition_id": "agd_0123456789abcdef0123456789abcdef",
  "execution_principal": {"kind": "user", "id": "usr_0123456789abcdef0123456789abcdef"},
  "schedule": {"kind": "cron", "expression": "0 9 * * 1-5", "timezone": "America/Los_Angeles", "overlap_policy": "skip", "missed_policy": "run_once", "catch_up_limit": 1},
  "target": {"kind": "eligible_device", "workspace_binding_id": "wsb_0123456789abcdef0123456789abcdef", "required_capabilities": ["text"]},
  "execution_policy": {"model_alias": "coding-default", "budget_id": null, "tool_policy_scope": "project"},
  "execution_retry": {"max_start_attempts": 2, "lease_ttl_seconds": 300, "heartbeat_interval_seconds": 30}
}
```

Pause/resume/patch requests contain `{ "version": <positive integer> }`; run-now contains no client occurrence ID and relies on `Idempotency-Key`. Webhook create/update contains endpoint URL, exact subscribed event types, description, enabled state, and failure policy; the generated secret is returned once. Export/deletion requests contain category/scope or typed confirmation and never a client-supplied artifact/object URL or job state. Responses use the entity projections in this gate, plus `version`, `created_at`, and `updated_at`; list responses use the P01 `Page<T>` shape. Each provider event has a stable provider event ID, signed timestamp/nonce, adapter account binding, replay rejection, out-of-order version handling, atomic D1 subscription transition, and bounded metadata; raw provider payloads are never stored or logged. Billing portal sessions are short-lived, CSRF/idempotency protected, reauthorization checked, and return only an allowlisted provider portal URL or a stable unavailable reason.

### Web information architecture

P06 adds a secondary organization Settings group and an app-level notification center:

```text
/org/:slug/automations
/org/:slug/settings/webhooks
/org/:slug/settings/billing
/org/:slug/settings/data
/notifications
/account/data
```

The shared shell must parse the full path (not only its final segment), handle browser `popstate`, lazy-load P06 panels, and clear stale organization data on org changes. Account-level notification preferences and personal export/deletion are not placed under an organization's settings context. These routes consume the P06 API contracts; they do not create a second authorization or entitlement model.

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
- `billing.manage`
- `entitlements.read`
- `data.read`
- `data.manage`
- `data.export`
- `data.delete`

Owners/admins receive all P06 browser permissions. Members may read and run automations within visible projects when target/policy checks pass. Viewers are read-only. Webhook secret rotation, billing portal/session changes, exports, and deletion are admin/owner operations unless a later explicit contract says otherwise. Entitlement overrides are internal/support-only and have no browser permission or public route. All checks pass through the central authorization path and current organization state.

## Error semantics

Stable machine-readable reasons include:

- `permission_denied`
- `resource_not_found`
- `idempotency_conflict`
- `idempotency_in_progress`
- `version_conflict`
- `organization_pending_deletion`
- `automation_not_found`
- `automation_invalid_state`
- `automation_overlap_policy`
- `automation_missed_schedule_limit`
- `occurrence_not_found`
- `occurrence_already_claimed`
- `occurrence_lease_expired`
- `occurrence_ambiguous`
- `lease_fence_invalid`
- `execution_principal_unavailable`
- `device_not_eligible`
- `off_peak_not_allowed`
- `schedule_invalid`
- `schedule_timezone_invalid`
- `schedule_interval_invalid`
- `dst_missing_time`
- `dst_repeated_time`
- `webhook_endpoint_invalid`
- `webhook_https_required`
- `webhook_url_blocked`
- `webhook_redirect_blocked`
- `webhook_timeout`
- `webhook_response_too_large`
- `webhook_retry_after_invalid`
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
- `license_audience_mismatch`
- `license_key_unknown`
- `license_policy_rollback`
- `provider_entitlement_unavailable`
- `provider_event_replay`
- `provider_event_out_of_order`
- `data_policy_invalid`
- `data_policy_version_conflict`
- `export_not_ready`
- `export_category_invalid`
- `export_expired`
- `export_artifact_unavailable`
- `deletion_not_resumable`
- `deletion_scope_conflict`
- `deletion_legal_hold`
- `deletion_reauth_required`
- `deletion_requires_org_exit`
- `deletion_cutoff_reached`
- `queue_job_duplicate`
- `queue_job_dedupe_conflict`
- `queue_job_lease_expired`
- `queue_job_claim_conflict`
- `notification_recipient_scope`

No error exposes raw provider responses, secret values, prompt/response content, or unbounded SQL/platform errors.

## Policy and configuration snapshot

The existing P03 device-policy snapshot gains only the bounded `automation` and `entitlements` sections below. Webhook retry policy and data-governance settings are server-side P06 resources and are not added as new device-snapshot keys; adding another P03 extension would require a separate coordinated P03 CR.

```json
{
  "automation": {
    "schema_version": 1,
    "max_active": 100,
    "allowed_overlap_policies": ["skip", "queue_one", "allow", "cancel_previous"],
    "allowed_missed_policies": ["skip", "run_once", "catch_up"]
  },
  "entitlements": {
    "schema_version": 1,
    "policy_fresh_seconds": 900,
    "local_offline_grace_seconds": 604800,
    "cloud_control_plane_grace_seconds": 86400,
    "platform_paid_inference_grace_seconds": 0
  }
}
```

The server resolves current organization/project scope and applies the narrowest policy. The canonical policy extension key is the existing P03 key `automation` (singular); the public resource/API vocabulary remains `automations` (plural). Client snapshots are untrusted inputs. Unknown sections or malformed schema versions fail closed for managed operations. A local-only runtime can use a previously signed license snapshot for bounded grace, but a current cloud operation must validate policy freshness.

## Persistence skeleton

Migrations are additive and forward-only after `0010_p05_runs_tools_usage_control.sql`:

- `0011_p06_automations.sql` — schedule revisions, definitions, occurrences, leases, occurrence attempts, and P05 run correlation.
- `0012_p06_event_delivery.sql` — webhook endpoints/secrets/deliveries/attempts, notifications/preferences/deliveries, and queue job envelopes.
- `0013_p06_billing_entitlements.sql` — plans, plan entitlements, billing accounts, subscriptions/history, provider projections, entitlement definitions/grants, and license snapshot metadata.
- `0014_p06_data_governance.sql` — data policies/class registry, export jobs/artifacts metadata, deletion jobs/steps/certificates, and additive user deletion state.

The migrations may create these tables and indexes:

- `automation_definitions`
- `automation_schedule_rules`
- `automation_occurrences`
- `automation_leases`
- `automation_occurrence_attempts`
- `automation_run_links`
- `webhook_endpoints`
- `webhook_secrets`
- `webhook_deliveries`
- `webhook_delivery_attempts`
- `notification_preferences`
- `notifications`
- `notification_deliveries`
- `plans`
- `billing_accounts`
- `provider_entitlement_projections`
- `provider_sync_state`
- `subscriptions`
- `entitlement_definitions`
- `entitlement_grants`
- `license_snapshots`
- `license_states`
- `data_governance_policies`
- `export_jobs`
- `deletion_jobs`
- `deletion_tasks`
- `deletion_certificates`
- `queue_job_envelopes`

P05 `runs` receives nullable `automation_occurrence_id` and `automation_lease_id` correlation columns; P06 does not add a parallel run lifecycle. `automation_run_links` enforces one link per occurrence/attempt and one P05 run per link.

- one unique active automation name per org/project scope;
- one occurrence per `(automation_id, schedule_rule_id, scheduled_for_utc)` for scheduled work;
- one active lease per occurrence and one append-only attempt record per lease attempt;
- one P05 run link per `(occurrence_id, attempt)`; a pre-start expiry may create a later attempt, while a started/ambiguous occurrence is never automatically reissued;
- one logical webhook delivery per endpoint/event/replay generation, with append-only attempts and stable event ID/body hash;
- one subscription current-state row per org, immutable plan versions, and append-only subscription events;
- one effective entitlement definition per key/scope/version; plan-derived grants and scoped support overrides have explicit precedence;
- one provider entitlement projection per org/provider reference;
- one current data policy per org/project scope and immutable policy versions;
- one export/deletion job per idempotency/dedupe key; one queue job generation per job type/tenant/dedupe key;
- immutable audit/security rows and immutable event IDs; stateful delivery/job rows transition only through compare-and-set versions.

R2 is used for export artifacts only. D1 stores metadata, opaque object references, checksums, expiry, and audit state; it is not an export-content authority.

## Compatibility and migration

- Existing P01–P05 routes and IDs remain valid.
- P06 IDs are additive and typed; no P05 `run_id`, `rse_` session, or P02 `ses_` login-session meaning changes.
- P01 `EventEnvelope` remains the business outbox envelope. P06 queue jobs use a separate versioned envelope so a webhook retry does not mutate the business event.
- `0011`–`0014` must apply in order before P06 handlers read the corresponding tables. Rollback is application-code rollback with additive schema retained; do not delete historical jobs, audit, or billing records to roll back.
- ZCode/LumiAgents mappings use opaque `external_id`/provider references and preserve normal automation versus off-peak safety semantics.
- Billing provider product/price IDs remain adapter-private. Public and persisted product contracts use Lumi keys.
- Browser clients never receive raw lease tokens, webhook secrets, provider credentials, export content URLs, or authoritative job settlement values.

## Fixtures and evidence

The coordinator provides `docs/implementation/fixtures/p06-contracts-v1.json` before MOD/BE/FE implementation packets start. It includes one valid and one invalid schedule, a deterministic occurrence identity example, a lease race/partition fixture, a signed webhook fixture with a non-production deterministic test vector, a grace/downgrade/license-state matrix, a data-class/legal-hold policy fixture, personal export/deletion cases, and export/deletion retry fixtures.

Before freeze, the coordinator must review:

- [x] current ZCode cron/off-peak semantics mapped without flattening; `automationCron`, interval carrier, and off-peak continuation are reuse candidates, while `recoverInterrupted`, local misfire grace, and local run IDs are explicitly not authorities;
- [x] P05 outbox and run correlation seams reused; P05 `Run` remains the only execution state machine;
- [x] D1/Queue/R2 responsibilities are explicit;
- [x] no data class lacks a governance declaration, including all P01–P05 and P06 classes;
- [x] no client contract exposes provider IDs or secrets;
- [x] tenant, idempotency, retry, and partial-failure negatives are defined;
- [x] FE fixtures can be built without waiting for BE implementation;
- [x] migration ownership and sequence are consistent across BE packets and CRs;
- [x] focused P06 tests and a P06 CI/smoke surface are assigned to P06-QA-01.

## Coordinator decisions before freeze

The following review findings are resolved normatively in this draft:

1. Lease safety uses `ambiguous` after a possible start; no automatic re-dispatch. `P06-CR-001` records the distributed-systems clarification.
2. Off-peak supports explicit `provider_ticket` and `org_window` eligibility sources; current ZCode provider-ticket mode is never flattened into cron, and intervals preserve calendar/DST semantics. `P06-CR-001` is normative.
3. The canonical P03 device-policy extension keys remain the existing singular `automation` and `entitlements`; notification and data-governance settings remain separate server-side resources.
4. Entitlement overrides are internal/support-only. The existing `/devices/policy` response is the single device license authority, with separate policy-fresh and offline-valid expiries. `P06-CR-002` is normative.
5. P05 `Run` remains the sole execution state machine; P06 adds occurrence/lease correlation, not a parallel `AutomationRun` authority.
6. The existing reauthenticated organization deletion route creates/links the P06 job; no duplicate public deletion request route exists. `P06-CR-003` and ADR 0006 are normative.
7. Webhook bodies are the exact existing P01 `EventEnvelope`; no P01 shape change is introduced. P06 uses a separate typed jobs queue, not a mixed/guessed union.
8. Every P01–P05 and P06 persistent class is included in the data-class matrix before migration review.

## Freeze commit

After review and merge:

- Contract Gate commit: `11341a5` (PR #22, merged to `main`)
- Contract version: `p06-cg-v1`
- Dependent packets unlocked: `P06-MOD-01..03`, `P06-BE-01..04`, `P06-FE-01..04`, `P06-INT-01..02`; `P06-QA-01` unblocks when implementation packets merge
- Change requests: `P06-CR-001`, `P06-CR-002`, `P06-CR-003`; ADR 0006 for private R2 exports

After freeze, dependent packets MUST NOT silently redefine these contracts. A required change uses `docs/implementation/templates/change-request.md` before implementation changes.
