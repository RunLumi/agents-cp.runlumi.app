# /goal 01 — Complete P01 Foundation, Contracts, Persistence, and Test Harness

You are the **P01 phase coordinator and implementation lead**.

Your job is to complete `docs/implementation/plan01-foundation-contracts-storage.md` end-to-end and unlock P02.

## Read first

Read completely:

- `AGENTS.md`
- `docs/prompts/README.md`
- `docs/implementation/STATUS.md`
- `docs/implementation/plan00-execution-model.md`
- `docs/implementation/plan01-foundation-contracts-storage.md`
- `docs/specs/f16-audit-security-events-support-access.md`
- `docs/specs/f21-operations-observability-reliability.md`
- `docs/specs/f23-api-contracts-versioning-pagination-idempotency.md`
- all ADRs relevant to Rust/Workers, Vite, API contracts, performance
- current backend/web source

Inspect current code before deciding what is missing.

## Mission

Create the minimum production-grade substrate that every later feature can safely reuse:

- clear domain/module vs Cloudflare adapter boundaries;
- D1 persistence and migration discipline;
- request/correlation context;
- stable API error semantics;
- cursor pagination primitives;
- idempotency primitives;
- event/outbox foundation;
- async delivery substrate;
- web API/error foundation;
- deterministic test harness;
- clean local/CI build path.

Do not overbuild future product tables or generic frameworks.

## Step 1 — Open P01 Contract Gate

Create/fill P01-CG using the Contract Gate template.

Freeze the minimum shared contract required by P01:

- `ApiError` envelope;
- `RequestContext`;
- request/correlation IDs;
- opaque resource ID convention;
- timestamp convention;
- pagination envelope;
- idempotency semantics;
- event envelope;
- migration naming/versioning;
- meta/health API contract;
- shared error codes needed by later phases.

Commit/merge the Contract Gate before dependent packets diverge.

## Step 2 — Decompose and execute packets

At minimum execute the plan's packets:

- P01-MOD-01 core domain primitives
- P01-BE-01 D1 persistence substrate
- P01-BE-02 outbox/async substrate
- P01-BE-03 HTTP middleware
- P01-FE-01 web foundation
- P01-QA-01 test harness

Assign one integration/shared-file owner.

Parallelize packets with disjoint write surfaces after P01-CG is frozen.

## Technical expectations

### Backend

Preserve:

```text
HTTP/Cloudflare
→ adapters
→ application/domain
→ repository/service traits
```

Do not spread raw Cloudflare `Env` through domain code.

Use D1 for canonical relational control-plane state.

Use Queues/outbox for durable async delivery.

Do not introduce Durable Objects merely because they exist.

### API

All errors must have stable machine-readable codes and request IDs.

Client behavior must never parse English error strings.

Mutations with duplicate-side-effect risk need reusable idempotency support.

### Web

Build only reusable shell/API/error primitives needed by later feature agents.

Do not create a giant component library or global state architecture.

### Tests

Prove:

- duplicate idempotency key does not duplicate mutation;
- persistence/migrations can be tested deterministically;
- error envelope remains stable;
- request ID propagates;
- structured logs omit body/secrets by default.

## Integration Gate

Do not finish on isolated packet completion.

Demonstrate the exact P01 vertical slice from the plan:

web → Rust Worker → request ID → D1 read/write → durable outbox → consumer/test delivery → user-visible/API result.

Run all required quality gates.

## Change discipline

If current Cloudflare Rust bindings make an assumption in the plan invalid, gather evidence and use a Change Request. Do not silently replace the architecture.

## Completion

P01 is complete only when:

- Integration Gate passes;
- build/test/WASM checks pass;
- migration process is usable;
- downstream agents can add modules/routes/migrations without redesigning foundations;
- `STATUS.md` marks P01 complete and P02 ready;
- handoff clearly states what P02 can rely on.

Continue working until these conditions are true or a documented external blocker makes them impossible.
