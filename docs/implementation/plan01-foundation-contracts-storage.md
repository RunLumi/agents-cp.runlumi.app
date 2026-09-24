# Plan 01 — Foundation, contracts, persistence, test harness

Status: Complete — Integration Gate PASS, PR #5 merged
Specs: F16, F21, F23 foundations
Depends on: P00

## 1. Phase outcome

Create the minimum production-grade substrate so later agents can add features without repeatedly editing the same root files.

Exit with:

- stable module/adapter/http boundaries;
- D1 migration mechanism;
- request context + request ID;
- canonical API error envelope;
- pagination/idempotency primitives;
- audit/outbox interfaces;
- generated or generation-ready API contract;
- local/test environment for D1/R2/Queues where used;
- CI-quality commands wired without broad feature implementation.

## 2. Contract Gate — P01-CG

Single owner.

Freeze:

- `ApiError` shape;
- `RequestContext` fields;
- opaque ID convention;
- RFC3339 timestamp convention;
- permission/error naming convention;
- cursor page shape;
- idempotency-key behavior;
- event envelope;
- migration naming convention.

Deliver a small API contract for:

- `GET /api/health`
- `GET /api/v1/meta` or equivalent version metadata
- one internal test endpoint only if needed, removed before production.

## 3. Parallel work packets

### P01-MOD-01 — Core domain primitives

Write surface:

- `apps/api/src/core/**` or narrowly named foundational modules.

Build:

- opaque ID/value types;
- clock trait;
- request/correlation ID;
- actor/principal placeholder types;
- domain error taxonomy;
- pagination types;
- idempotency command/result abstraction;
- event envelope type.

Do not add organization-specific rules yet.

### P01-BE-01 — D1 persistence substrate

Build:

- D1 binding adapter;
- migration runner/process;
- prepared statement helpers;
- repository transaction/batch conventions;
- migration test fixtures;
- index naming conventions.

Initial tables only for infrastructure if needed:

- schema migrations;
- idempotency records;
- outbox events.

Do not create every future product table in one mega migration.

### P01-BE-02 — Async/outbox substrate

Build:

- outbox repository;
- queue publisher adapter;
- retry metadata;
- dead-letter state model;
- idempotent consumer skeleton.

The business transaction writes an outbox event before delivery.

### P01-BE-03 — HTTP middleware

Build:

- request ID;
- structured error mapping;
- body-size guard;
- normalized JSON response;
- safe structured logging;
- timing;
- auth principal hook interface, initially anonymous/test principal only.

### P01-FE-01 — Web application foundation

Build only shared application shell pieces that later feature agents need:

- route skeleton;
- error boundary;
- global 401/403/404/500 states;
- API client base;
- request ID surfaced in error UI;
- query/mutation primitive if and only if chosen by ADR;
- organization context placeholder interface, not real behavior yet.

Avoid a huge design-system buildout.

### P01-QA-01 — Test harness

Build:

- Rust unit test conventions;
- repository/persistence tests;
- API error snapshot/contract tests;
- cross-request idempotency test;
- web API-client tests;
- smoke script that starts Worker/web locally where practical.

## 4. Shared-file ownership

Only P01 integration owner edits:

- root `Cargo.toml`;
- root `package.json`;
- `wrangler.jsonc`;
- central app router;
- migration manifest;
- CI workflow files.

Other packets submit requested shared-file changes as notes rather than conflicting edits.

## 5. Architecture constraints

### D1

Use D1 as canonical relational store for control-plane metadata.

Use:

- prepared statements;
- explicit indexes;
- batch/transaction semantics where multiple statements form one invariant.

Do not assume global low-latency writes.

Read replication is a later optimization, not a correctness primitive.

### Durable Objects

Do not use DO as a default database.

Introduce only when a later plan proves a coordination requirement that benefits from single-object serialization/state.

### R2

Introduce binding only if P01 test/export fixture requires it. Otherwise defer real R2 use until artifact/export feature.

### Queues

Use for asynchronous delivery/outbox consumption. Business correctness must not depend on a synchronous webhook/email send.

## 6. Integration Gate

Demonstrate:

1. web calls Rust Worker;
2. request receives request ID;
3. Worker reads/writes a tiny D1 fixture;
4. mutation writes an outbox record;
5. queue consumer or test consumer marks delivery;
6. duplicate idempotency key does not duplicate mutation;
7. structured logs contain no request body/secret by default.

## 7. Exit criteria

- no product feature has bypassed core error/context abstractions;
- migration process works in dev/test;
- WASM build passes;
- D1 query code is isolated behind adapters/repositories;
- API error envelope is stable;
- docs contain how agents add a new module/migration/route/test.

## 8. References

- Cloudflare D1 Workers API and batch semantics
- Cloudflare Queues
- Cloudflare R2
- Cloudflare Durable Objects

See Cloudflare references already collected in architecture research; verify Rust binding support before adopting any newer primitive.
