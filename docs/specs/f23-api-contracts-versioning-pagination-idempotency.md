# F23 — API Contracts, Versioning, Pagination & Idempotency

Priority: P0  
Depends on: ADR 0005

## Objective

Cho web, desktop, CLI và integrations dùng một API predictable, evolvable và safe under retries.

## Base conventions

- JSON API under `/api/v1` for product contracts.
- Health/internal endpoints may remain unversioned.
- Resource IDs are opaque strings/UUID-like values.
- Timestamps are RFC 3339 UTC.
- Monetary values use integer minor units or explicit decimal string + currency.
- Never use floating point for authoritative money totals.

## Envelope

Success MAY return direct resource/documented collection shape.

Errors MUST use stable shape:

```json
{
  "error": {
    "code": "permission_denied",
    "message": "You do not have permission to perform this action.",
    "request_id": "req_...",
    "details": {}
  }
}
```

Client behavior keys off `code`, not English message.

## Requirements

### FR-F23-001 — Versioning

Breaking contract change requires new API version or explicit compatibility layer.

Adding optional field is normally non-breaking.

### FR-F23-002 — Pagination

Use cursor pagination for growing lists.

Request:

- `limit`
- `cursor`
- filters/order

Response:

- items
- next_cursor
- has_more optional

Cursor is opaque to clients.

### FR-F23-003 — Filtering

Server whitelists filter/sort fields.

Do not forward arbitrary client column names into SQL.

### FR-F23-004 — Idempotency

Mutations vulnerable to duplicate side effects accept `Idempotency-Key`.

Examples:

- invitations;
- key/credential create;
- billing operations;
- run/automation dispatch;
- export jobs;
- webhook replay requests.

Store key scoped by principal/org/endpoint plus request fingerprint and bounded TTL.

Same key with different body -> conflict.

### FR-F23-005 — Optimistic concurrency

Mutable administrative resources use `version`, ETag/If-Match, or equivalent where lost updates matter.

Examples:

- route config;
- org policy;
- retention policy;
- automation config.

### FR-F23-006 — Request limits

Define bounded:

- JSON body size;
- list limit;
- filter length;
- file upload size;
- inference payload size separately.

### FR-F23-007 — Deprecation

Return machine-readable deprecation warning/header where feasible and document removal date.

Desktop compatibility window must reflect release adoption reality.

### FR-F23-008 — OpenAPI

Once stable product endpoints exist, maintain OpenAPI as canonical or generated contract and generate TS client/types.

Do not hand-maintain duplicate types indefinitely.

### FR-F23-009 — Org context

Prefer org in route:

`/api/v1/orgs/:org_id/projects`

for explicit administrative APIs.

Inference may use token/request context but must still resolve one unambiguous org/project.

### FR-F23-010 — Rate-limit headers

When useful expose safe standardized/custom limit metadata without revealing other tenants.

## Acceptance criteria

- Retrying an idempotent create does not duplicate resource.
- Invalid cursor fails cleanly.
- Stale policy update cannot overwrite newer config silently.
