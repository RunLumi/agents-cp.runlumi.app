# ADR 0005: API contracts and testing

- Status: Accepted
- Date: 2026-09-24

## API

The backend is authoritative for authorization and domain invariants.

Use JSON REST under `/api`. Version externally consumed product contracts under `/api/v1` when those contracts exist.

Use stable machine error codes, cursor pagination for growing collections, idempotency keys where retry can duplicate effects, and optimistic concurrency where lost updates matter.

Do not expose database models directly as wire contracts.

## Client generation

Do not add OpenAPI generation before stable product endpoints exist. When multiple frontend features consume durable contracts, introduce one OpenAPI source of truth and generated TS client through a later ADR.

## Tests

Rust:
- unit-test domain rules;
- integration-test HTTP behavior around router/service boundaries;
- add hostile cross-tenant tests for every tenant-owned resource.

Web:
- Vitest for fast deterministic logic/components;
- Playwright for real browser flows once authentication/navigation exists;
- assert user-visible behavior, not component internals.

## Security invariant

Future tenant-owned operations must establish:

```text
principal
+ active organization context/membership
+ permission
+ resource ownership/scope
```

Knowing an ID is never authority. Tests must include A-to-B tenant identifier substitution, not only happy paths.
