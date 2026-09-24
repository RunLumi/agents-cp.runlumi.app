# Contract Gate — P01-CG

## Purpose and ownership

- Phase: P01 — Foundation, contracts, persistence, test harness
- Owner: P01 coordinator
- State: frozen
- Contract version: `p01-cg-v1`
- Inputs: Plan00, Plan01, F16, F21, F23, ADR 0001–0005
- Previous phase: P00 execution model operationalized

This is the shared contract for P01 packets. It intentionally defines only the substrate later phases need. It does not create organization-specific product behavior.

## Domain vocabulary

| Concept | Stable name | Meaning |
|---|---|---|
| Request context | `RequestContext` | Request-scoped IDs, receive time, and optional actor/org/device/session context. |
| API error | `ApiError` | Stable machine-readable JSON error envelope. |
| Resource ID | opaque string | Prefix plus UUID-like random value; clients treat the full value as opaque. |
| Cursor page | `Page<T>` | `items`, `next_cursor`, `has_more`; cursors are opaque to clients. |
| Idempotency record | `IdempotencyRecord` | A scoped key, request fingerprint, bounded expiry, and replayable successful result. |
| Event | `EventEnvelope` | Versioned business event persisted to the outbox before queue delivery. |
| Outbox event | `OutboxEvent` | Durable event plus dispatch/delivery/retry state. |

## IDs and time

- Resource IDs are text values formatted as `<resource-prefix>_<UUID-v4-simple-lowercase>`, for example `evt_0123456789abcdef0123456789abcdef`. IDs are never authorization evidence.
- Request IDs use the `req_` prefix and a UUID v4 value. The Worker creates one request ID at the trusted HTTP boundary for every request and returns it in `X-Request-ID`.
- A validated incoming `X-Correlation-ID` may be retained as correlation context; otherwise correlation ID defaults to the generated request ID. Correlation IDs are diagnostic only and never establish identity or authority.
- API and persisted timestamps use RFC 3339 UTC text ending in `Z`. SQLite timestamp strings use fixed UTC precision so lexical order matches time order.
- IDs and timestamps are strings in JSON and SQLite. Database row IDs are not exposed as API resource IDs.

## Request context

```text
RequestContext {
  request_id: RequestId,
  correlation_id: CorrelationId,
  received_at: Timestamp,
  actor: optional ActorContext,
  organization_id: optional OrganizationId,
  device_id: optional DeviceId,
  session_id: optional SessionId
}

ActorContext {
  actor_type: user | service_account | support | system | anonymous,
  actor_id: optional opaque string,
  effective_user_id: optional opaque string
}
```

P01 supplies anonymous/system placeholders only. Later identity packets provide authenticated values. Missing identity is not permission to access tenant-owned resources.

## API

### Shared response rules

- Product JSON contracts live under `/api/v1`; liveness stays unversioned.
- Every HTTP response includes `X-Request-ID`. Error envelopes use that same ID.
- JSON request bodies are limited to 1 MiB. List limits default to 50 and are capped at 100. Query filters and sort fields are server-whitelisted.
- API clients branch on `error.code`, never on the English message.

### Error envelope

```json
{
  "error": {
    "code": "permission_denied",
    "message": "You do not have permission to perform this action.",
    "request_id": "req_0123456789abcdef0123456789abcdef",
    "details": {}
  }
}
```

`details` is always a JSON object and excludes secrets and raw request bodies. Error codes use lowercase `snake_case` and remain stable across message edits.

| Code | HTTP status | Use |
|---|---:|---|
| `bad_request` | 400 | Malformed request or invalid cursor. |
| `validation_failed` | 422 | Valid JSON that fails field validation. |
| `authentication_required` | 401 | Authentication is required. |
| `permission_denied` | 403 | Authenticated principal lacks permission. |
| `not_found` | 404 | Route or resource does not exist in the caller's scope. |
| `method_not_allowed` | 405 | Route does not accept this method. |
| `payload_too_large` | 413 | Request exceeds the body limit. |
| `unsupported_media_type` | 415 | Unsupported content type. |
| `conflict` | 409 | General state conflict. |
| `idempotency_conflict` | 409 | A live key is reused with a different request fingerprint. |
| `idempotency_in_progress` | 409 | The original request with this key is still executing. |
| `rate_limited` | 429 | A bounded request limit was exceeded. |
| `internal_error` | 500 | Unexpected failure; details are redacted. |
| `service_unavailable` | 503 | A required dependency is unavailable. |

### Frozen endpoints

| Method | Path | Purpose | Success |
|---|---|---|---|
| `GET` | `/api/health` | Public liveness only; does not expose topology, bindings, or credentials. | `200 {"status":"ok","service":"lumi-agents-control-plane-api"}` |
| `GET` | `/api/v1/meta` | API and contract version metadata. | `200 {"api_version":"v1","contract_version":"p01-cg-v1","service":"lumi-agents-control-plane-api"}` |
| `POST` | `/api/v1/_internal/foundation-checks` | Local integration proof only; requires `Idempotency-Key`; body must be `{}`. Route is registered only when the runtime environment is explicitly `development`. | `202 {"event_id":"evt_…","delivery_status":"pending"}` |
| `GET` | `/api/v1/_internal/foundation-checks/{event_id}` | Local integration proof only; returns persisted outbox state. Same development-only gate as POST. | `200 {"event_id":"evt_…","delivery_status":"pending|queued|delivered|dead_letter"}` |

The internal foundation-check endpoints are not part of the deployable production API contract. Production configuration sets the environment to `production`; only the local Wrangler environment enables these routes. The POST accepts no user content and creates no real customer data.

### Cursor pagination

Request query: `limit`, `cursor`, plus explicitly documented filters and order fields.

```json
{
  "items": [],
  "next_cursor": null,
  "has_more": false
}
```

`next_cursor` is either an opaque non-empty string or `null`. Invalid, expired, or unsupported cursor tokens return `400 bad_request`; clients must not parse or construct them.

## Idempotency

- Header: `Idempotency-Key`; 1–128 printable ASCII bytes.
- Scope: principal ID, organization ID (empty scope for non-tenant operations), normalized method/path, and a server-side digest of the key.
- The server stores a request fingerprint, never the raw key. Same live key plus same fingerprint replays the first successful status/body; the response's `X-Request-ID` is fresh for the retry. Same live key plus a different fingerprint returns `409 idempotency_conflict`. A concurrent first request returns `409 idempotency_in_progress` and can be retried with the same key.
- Successful result and the corresponding business mutation/outbox insert commit in one D1 batch. Failed transactions leave neither a completed idempotency result nor a partial mutation.
- Records expire after 24 hours. An expired key may begin a new operation. Cleanup is bounded and does not affect unexpired records.
- The development foundation-check endpoint uses the anonymous local principal and has an empty organization scope. Product mutations use the authenticated principal/org supplied by server-side context.

## Events and outbox

```json
{
  "event_id": "evt_0123456789abcdef0123456789abcdef",
  "event_type": "foundation.check.requested.v1",
  "occurred_at": "2026-09-24T12:00:00.000Z",
  "request_id": "req_0123456789abcdef0123456789abcdef",
  "correlation_id": "req_0123456789abcdef0123456789abcdef",
  "actor": {"type":"anonymous","id":null,"effective_user_id":null},
  "organization_id": null,
  "payload": {}
}
```

- Event type names are lowercase dotted names ending in `.v<integer>`.
- A mutation writes the event to D1 in the same transaction as its state/idempotency result; queue delivery happens only after commit.
- Queue delivery is at least once. Consumers deduplicate by `event_id`; a consumer acknowledgement follows durable handling. Retries are bounded with backoff. Pending, queued, delivered, and dead-letter states are observable without logging event payloads.
- Logs may include bounded route/status/timing dimensions and request/correlation IDs. They never include bodies, credentials, authorization headers, prompts, or full event payloads by default.

## Persistence and migrations

- Canonical state is D1. All SQL and Cloudflare binding access remain in adapters/repositories; domain modules depend on small traits/value types.
- Use prepared statements and D1 `batch()` when multiple statements form one invariant. Do not add read replicas, Durable Objects, R2, or generic ORM layers in P01.
- Wrangler D1 migrations are the migration runner/source of applied versions. Files use immutable `<four-digit-version>_<snake_case>.sql` names, starting at `0001_p01_foundation.sql`; later changes append forward migrations.
- Initial infrastructure tables are limited to `idempotency_records` and `outbox_events`; Wrangler owns its migration bookkeeping table. Index names use `idx_<table>_<columns>` and uniqueness constraints are named/documented by their indexed columns.
- Timestamps are UTC RFC 3339 text. JSON columns contain contract envelopes, not client-controlled SQL identifiers.

## Meta/health fixtures

```json
{"status":"ok","service":"lumi-agents-control-plane-api"}
```

```json
{"api_version":"v1","contract_version":"p01-cg-v1","service":"lumi-agents-control-plane-api"}
```

The web client expects JSON errors with `error.code`, `error.message`, `error.request_id`, and object-valued `error.details`. Unknown error codes render a generic message while retaining the request ID for support.

## Compatibility

- `/api/v1` remains compatible by adding optional fields only; breaking changes require a new API version or explicit compatibility layer.
- P01 migrations are append-only. Corrective changes use a new migration; do not edit a migration already applied in any environment.
- Desktop/local ZCode IDs are not reinterpreted as control-plane IDs. Mapping belongs to P08.

## Freeze commit and unlocked packets

- Contract Gate commit: recorded in the P01 packet artifacts after this file is committed.
- Unlocked packets: `P01-MOD-01`, `P01-BE-01`, `P01-BE-02`, `P01-BE-03`, `P01-FE-01`, `P01-QA-01`.
- Shared-file/integration owner: P01 coordinator.

## Change rule

Any change to an API shape, error/status mapping, ID/time convention, idempotency semantics, event envelope, or migration invariant requires a Change Request from `docs/implementation/templates/change-request.md` before dependent packet changes proceed.
