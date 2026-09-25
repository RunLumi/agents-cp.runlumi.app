# Contract Gate — P04-CG

- Phase: P04 — Model catalog, credentials, AI inference router/proxy
- Owner: P04 coordinator
- State: frozen
- Contract version: `p04-cg-v1`
- Inputs: Plan00, Plan04, F09, F10, F11, F12 foundations, F21, F23, ADR 0001–0005, P02-CG `p02-cg-v1`, P02 downstream handoff
- Additive clarification: `docs/implementation/change-requests/P04-CR-002.md`
- Shared-file owner: P04 coordinator
- Previous phase: P02 complete; P03 may extend project/device/policy contracts without changing the definitions below

## Domain vocabulary

| Concept | Stable name | Meaning |
|---|---|---|
| Provider | `Provider` | Stable provider identity and adapter family, independent of display name or vendor branding. |
| Provider endpoint | `ProviderEndpoint` | Server-controlled, allowlisted destination for a provider adapter. |
| Model | `Model` | Stable catalog model identity mapped to one provider model ID. |
| Capability | `ModelCapability` | Typed requirement such as `text`, `vision`, `tools`, `structured_output`, or `reasoning`. |
| Model alias | `ModelAlias` | Stable client-facing name such as `coding-default`; it resolves to a route, never directly to a secret. |
| Credential | `Credential` | Metadata plus encrypted secret material for a provider, with explicit ownership and version. |
| Route | `Route` | Organization-scoped alias mapping and current immutable version pointer. |
| Route version | `RouteVersion` | Immutable, published candidate configuration identified by a monotonic version. |
| Inference request | `InferenceRequest` | One authorized request with one route version and a stable request ID. |
| Provider stream event | `ProviderStreamEvent` | Adapter-normalized output, usage, provider request ID, or terminal status. |
| Usage event | `UsageEvent` | Immutable, prompt-free accounting record for one inference request. |
| Budget reservation | `BudgetReservation` | Bounded pre-dispatch reservation reconciled after completion or failure. |
| Policy snapshot | `PolicySnapshot` | Signed/versioned P03 extension containing allowed aliases/models and credential mode. |

The public contract does not expose Cloudflare AI Gateway types, provider SDK types, raw provider errors, or plaintext credentials.

## IDs, ownership, and time

- IDs use `<prefix>_<32 lowercase hexadecimal characters>` and are opaque to clients.
- P04 prefixes are `prv_` provider, `pe_` endpoint, `mdl_` model, `mal_` alias, `cred_` credential, `rte_` route, `rtv_` route version, `use_` usage event, and `bud_` budget reservation.
- `org_id` is required on organization-owned catalog, route, credential, inference, usage, and health rows. Platform credentials/providers may use a null organization scope; local-only capability metadata is creator-scoped, excluded from organization enumeration, and never treated as a caller-selected tenant scope.
- `project_id` is an optional opaque scope in the policy and usage envelopes. P04 preserves it when supplied by a trusted P03 policy snapshot; P04 does not invent project membership semantics.
- IDs, email domains, model names, client headers, and route config are never authorization evidence. Every protected operation reuses P02 principal/session/current-membership authorization.
- Timestamps are RFC 3339 UTC text. Monetary values are integer minor units plus an explicit currency and pricing version.

## Permissions and central authorization

P04 extends the P02 policy decision path; route handlers do not compare role strings.

Stable P04 permission identifiers:

- `models.read`
- `models.manage`
- `credentials.read`
- `credentials.manage`
- `routes.read`
- `routes.manage`
- `inference.use`
- `usage.read`

Default role additions:

- `owner`: all P02 and P04 permissions.
- `admin`: all P04 permissions, including organization credential and route management.
- `member`: `models.read`, `routes.read`, `inference.use`, and `usage.read` for the active organization.
- `viewer`: `models.read` and `routes.read` only.
- Unknown permissions, inactive memberships, stale membership versions, organization suspension/deletion, and resource-organization mismatch deny.

Credential ownership is an additional resource-scope check after the central permission decision. A member may not use or enumerate another user's credential. Platform credentials are usable only when the current policy permits platform-managed mode.

## State machines

### Provider/model/alias lifecycle

```text
active ↔ deprecated → disabled
```

Disabling prevents new routed inference but does not rewrite historical usage records or route versions. Deprecated entries remain readable for migration/audit but are not eligible for new inference or new route validation.

### Credential lifecycle

```text
active → rotating → revoked
active → revoked
rotating → active
```

Rotation creates a new credential/version and immediately revokes the prior version in the P04 slice; configurable overlap/in-flight rotation semantics remain a P05 credential-lifecycle extension. A revoked credential is excluded from new resolution immediately. A local-only credential contains metadata/fingerprint only and is never uploaded.

### Route lifecycle

```text
draft → published → disabled
published → published (new immutable version)
published → draft (rollback creates a new version or repoints an active immutable version)
```

A published `RouteVersion` is immutable. Rollback changes the route's active version pointer; it never edits historical configuration.

### Inference response lifecycle

```text
not_dispatched
  → dispatched_no_output
  → stream_committed
  → completed
  → failed
```

Fallback is permitted only from `not_dispatched` or `dispatched_no_output`, and only for the bounded retry rules in F10. Once a non-empty upstream event or downstream response event is committed, no cross-model fallback is attempted. A side-effectful request cannot be retried after dispatch unless the provider contract explicitly declares it idempotent.

## API

All routes are under `/api/v1`, use the P01 JSON error envelope, and return `X-Request-ID`. Mutating routes require the P02 CSRF proof. Tenant administration uses `/orgs/:org_id`; inference resolves exactly one `X-Org-ID` and rejects a missing or mismatched context.

| Method | Path | Permission/context | Request | Success |
|---|---|---|---|---|
| GET | `/orgs/:org_id/catalog` | `models.read` | — | `{providers,models,aliases,health,catalog_version}` |
| POST | `/orgs/:org_id/catalog/providers` | `models.manage` | `{provider_key,display_name,adapter,endpoint_url?}` | `201 {provider}` |
| PATCH | `/orgs/:org_id/catalog/providers/:provider_id` | `models.manage` | `{lifecycle,version}` | `200 {provider}` |
| PATCH | `/orgs/:org_id/catalog/models/:model_id` | `models.manage` | `{lifecycle,version}` | `200 {model}` |
| GET/PUT | `/orgs/:org_id/policy` | `models.read` / `models.manage` | policy allowlists, credential mode, and version | `200 {policy}`; integrated P03 reads may include `persisted: false` when no device snapshot exists |
| POST | `/orgs/:org_id/catalog/models` | `models.manage` | `{provider_id,provider_model_id,display_name,capabilities,max_input_tokens?,max_output_tokens?}` | `201 {model}` |
| GET | `/orgs/:org_id/credentials` | `credentials.read` | `limit?,cursor?` | `200 Page<CredentialMetadata>` |
| POST | `/orgs/:org_id/credentials` | `credentials.manage` + verified email | `{provider_id,owner_type,label,secret}` | `201 {credential}`; never returns `secret` |
| POST | `/orgs/:org_id/credentials/:credential_id/rotate` | `credentials.manage` | `{label?,secret}` | `201 {credential}`; prior version lineage recorded |
| POST | `/orgs/:org_id/credentials/:credential_id/revoke` | `credentials.manage` | `{version}` | `200 {credential}` |
| GET | `/orgs/:org_id/routes` | `routes.read` | `limit?,cursor?` | `200 Page<Route>` |
| POST | `/orgs/:org_id/routes` | `routes.manage` + `Idempotency-Key` | `{alias,display_name,strategy,config}` | `201 {route,version}` |
| POST | `/orgs/:org_id/routes/:route_id/publish` | `routes.manage` + `Idempotency-Key` | `{version,config}` | `200 {route,version}` |
| POST | `/orgs/:org_id/routes/:route_id/rollback` | `routes.manage` + `Idempotency-Key` | `{version}` | `200 {route,version}` |
| GET | `/orgs/:org_id/routes/:route_id/history` | `routes.read` | `limit?,cursor?` | `200 Page<RouteVersion>` |
| PATCH | `/orgs/:org_id/routes/:route_id` | `routes.manage` | `{lifecycle,version}` | `200 {route}` |
| GET | `/inference/models` | `models.read` + `X-Org-ID` | `limit?,cursor?` | `200 Page<ModelAliasView>` |
| GET | `/inference/routes/:alias` | `routes.read` + `X-Org-ID` | — | `200 {route,version}` without credential material |
| POST | `/inference/responses` | `inference.use` + `X-Org-ID` | native request, `stream` default true | SSE native events or JSON response |
| POST | `/inference/chat/completions` | `inference.use` + `X-Org-ID` | supported OpenAI subset | OpenAI-compatible JSON/SSE subset |
| GET | `/orgs/:org_id/usage` | `usage.read` | `limit?,cursor?` | `200 Page<UsageMetadata>` |

`Idempotency-Key` is required for credential create/rotate, route create/publish/rollback, and other mutations whose retries could duplicate effects. Same key/same fingerprint replays; same key/different fingerprint conflicts.

## Native inference envelope

The native request is vendor-neutral:

```json
{
  "model": "coding-default",
  "messages": [{"role":"user","content":[{"type":"text","text":"Hello"}]}],
  "required_capabilities": ["text"],
  "stream": true,
  "max_output_tokens": 256,
  "temperature": 0.2,
  "tools": [],
  "project_id": null,
  "session_id": null,
  "run_id": null
}
```

The server creates `request_id`; callers cannot choose it as an authority or idempotency key. A streaming response uses `text/event-stream` and emits JSON events with stable `type` values:

- `response.started` — request, route version, and authorized provider/model metadata; no credential.
- `response.output_text.delta` — text delta.
- `response.tool_call.delta` — normalized tool-call delta.
- `response.completed` — terminal metadata and usage when available.
- `error` — terminal normalized gateway error; no raw upstream body.

Every event carries the same `request_id`, alias, route version, and (after selection) provider/model IDs. The gateway emits metadata only in normal logs and never logs prompts, responses, tool arguments, or credential values.

The OpenAI-compatible subset supports `model`, `messages` with string or text-part content, `stream`, `temperature`, `max_tokens`/`max_completion_tokens`, and `tools` as an opaque validated array. Unsupported fields are rejected rather than silently forwarded.

## Provider adapter contract

Every adapter implements the following pure/transport boundary:

- `validate_request`
- `translate_request`
- `send`
- `stream_decode`
- `translate_response`
- `classify_error`
- `extract_usage`
- `extract_provider_request_id`
- `capabilities`

P04 ships an OpenAI-compatible adapter, an Anthropic-style adapter, and a development-only deterministic mock adapter used for local integration tests. The mock adapter is unavailable when `ENVIRONMENT=production`. Provider endpoint URLs are server-controlled and validated against an HTTPS allowlist; caller-supplied URLs, headers, auth values, redirects to unapproved hosts, localhost/private/link-local destinations, and arbitrary proxying are rejected.

Normalized upstream error taxonomy:

`connection_failed`, `timeout`, `rate_limited`, `provider_unavailable`, `invalid_request`, `invalid_response`, `credential_rejected`, `unsupported_capability`, `content_filtered`.

The client-facing stable reasons are `model_not_allowed`, `route_unavailable`, `provider_unavailable`, `provider_rate_limited`, `request_timeout`, `budget_exceeded`, `budget_state_unavailable`, `rate_limit_exceeded`, `credential_unavailable`, `unsupported_capability`, `upstream_invalid_response`, and `ssrf_blocked`.

## Credential and secret contract

- Create input is one-time only and is never returned, stored in plaintext, put in a URL, or included in audit/outbox payloads.
- D1 stores ciphertext, nonce, key version, fingerprint, and metadata only. Web Crypto AES-GCM is the Worker adapter boundary.
- Normal reads return label, owner, provider, status, version, fingerprint/mask, timestamps, and last-used metadata only.
- Credential handles are tenant-scoped. A guessed cross-organization ID returns the same not-found/denied shape as any other inaccessible resource.
- Provider errors and structured logs redact common key patterns and never include request bodies by default.
- Credential resolution occurs only after authorization, route selection, and policy checks, immediately before outbound dispatch.

## Usage and budget contract

Each dispatched request can create one immutable `UsageEvent` with request/run/org/project/principal/session/device scope, alias/route version, provider/model, input/output/cached tokens, provider usage, estimated/actual cost, currency/pricing version, timestamps, TTFT/total latency, fallback count, and budget decision. Content is excluded.

Before dispatch, a `BudgetHook` returns `allow`, `deny`, or `unavailable`. Hard-budget mode fails closed with `budget_exceeded` or `budget_state_unavailable`; local-only execution is not failed merely because cloud budget state is unavailable. Reservations are bounded by an input/output token estimate and reconciled after completion/failure.

## Events and observability

Material mutations append P01 `EventEnvelope` records and immutable security/audit events. P04 event names include:

- `model_catalog.provider_created.v1`
- `model_catalog.model_created.v1`
- `model_catalog.provider_lifecycle_changed.v1`
- `model_catalog.model_lifecycle_changed.v1`
- `model_policy.updated.v1`
- `credential.created.v1`
- `credential.rotated.v1`
- `credential.revoked.v1`
- `route.draft_created.v1`
- `route.published.v1`
- `route.rolled_back.v1`
- `route.lifecycle_changed.v1`
- `inference.requested.v1`
- `inference.completed.v1`
- `inference.failed.v1`
- `usage.recorded.v1`

Every event carries the P01 request/correlation IDs. Provider/model/tenant IDs belong in event payloads and traces, not unbounded metric labels. Health inputs distinguish global provider outage, tenant credential failure, and request validation failure; tenant credential failures do not globally circuit-break a provider.

## Persistence skeleton

Migration `0009_p04_ai_platform.sql` creates:

- `providers`, `provider_endpoints`, `models`, `model_aliases`;
- `org_model_policies`;
- `credentials`;
- `routes`, immutable `route_versions` (draft rows have no `published_at`; publishing creates a published immutable pointer);
- `provider_health`;
- `inference_requests`, `usage_events`, `budget_reservations`, and `budgets`.

Invariant-bearing uniqueness/indexes include provider/model identity, `(org_id, alias)` routes, `(route_id, version_number)` versions, credential provider/scope indexes, and request-scoped usage uniqueness. D1 remains canonical; mutation batches carry state transitions, security/outbox writes, and idempotency projections together.

## Policy and P03 extension

`PolicySnapshot` is an outer versioned object supplied by a trusted policy service. P04 consumes optional fields:

```json
{
  "version": 1,
  "allowed_aliases": ["coding-default"],
  "allowed_models": [],
  "credential_mode": "platform_or_organization",
  "managed_route_enabled": true,
  "project_id": null
}
```

P04 filters route candidates by capabilities, model/provider allowlists, lifecycle, and credential mode. P03 may add project/device policy fields or a signed snapshot transport without redefining aliases, provider IDs, credential ownership, route versions, or the authorization decision. The frozen P03 `models.schema_version: 0` opaque placeholder is treated as no model override; a malformed P04-shaped section fails closed. A missing P03 extension is not authority to broaden access.

## Fixtures

The local fixture uses four development-only mock providers:

- `mock://lumi-fail` with model `mock-fail` — fails before output;
- `mock://lumi-success` with model `mock-success` — emits two text deltas and usage;
- `mock://lumi-post-output-failure` with model `mock-post-output-failure` — emits a text delta and then fails, proving commitment prevents fallback;
- `mock://lumi-timeout` with model `mock-timeout` — non-streaming requests never emit a byte, proving the dispatch/read deadline is classified as `request_timeout`; streaming requests emit one event and remain pending to exercise downstream cancellation handling.

An organization configures an encrypted managed credential, publishes `coding-default` with both candidates, streams by alias, observes fallback, verifies usage attribution, and rolls back the route version. The fixture never contains a real secret or provider response body in logs.

## Compatibility and freeze

- P01 errors, IDs, request IDs, pagination, idempotency, and outbox envelope remain unchanged.
- P02 principal/org/current-membership authorization remains the only organization authorization path.
- Existing P03/P04 clients consume stable aliases and route versions; no desktop release is needed for a route change.
- P04 does not reinterpret ZCode provider/model IDs. P08 owns migration; P04 exposes a mapping hook with stable Lumi IDs/aliases.
- A breaking change after freeze requires `docs/implementation/templates/change-request.md` and a versioned compatibility decision.

### Freeze record

- Contract Gate file: `docs/implementation/gates/P04-CG.md`
- Contract version: `p04-cg-v1`
- Freeze commit: `57b2df9` (P04-CG)
- Unlocked packets: `P04-MOD-01..04`, `P04-BE-01..05`, `P04-FE-01..03`, `P04-INT-01..02`, `P04-QA-01`
- Shared files: P04 coordinator owns router, module declarations, Wrangler configuration, migrations, package manifests, and STATUS.
