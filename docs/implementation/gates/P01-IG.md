# Integration Gate — P01-IG

## Goal

Prove P01 as one real web → Worker → D1 → outbox → Queue → D1 status slice using isolated local resources.

## Preconditions

- [x] P01-MOD-01, BE-01, BE-02, BE-03, FE-01, and QA-01 merged in PR #5 at `ced9635e047ab3ef51b9759f1138a77e9255314f`.
- [x] Frozen contract `p01-cg-v1` is an ancestor (`7835fd9`) of packet coordination and implementation.
- [x] Migration `0001_p01_foundation.sql` applied to Wrangler's local development D1; `wrangler d1 migrations list DB --local --env development` reported no pending migrations.
- [x] No known contract drift; request, error, event, and endpoint shapes match P01-CG.
- [x] One P01 coordinator owns root manifests, Wrangler config, router, module declarations, and status coordination.

## Specification scope

- F16 foundation only: versioned event envelope and durable outbox metadata support future audit append paths. Immutable audit tables, search/export, security event policies, and support access depend on identity and authorization phases and are not P01 deliverables.
- F21 foundation: request/correlation propagation, bounded structured redacted logs, stable health, and bounded queue retry. Production telemetry routing, launch SLOs, and backup/restore drills remain later operations work.
- F23 foundation: stable errors, versioned API metadata, opaque IDs/cursors, idempotency fingerprints/replay/conflict, and bounded JSON requests. Product pagination endpoints, OpenAPI generation, deprecation, and rate-limit contracts wait for stable product routes.

## Vertical slice

```text
Browser UI
→ Vite /api proxy
→ Rust Worker request boundary
→ RequestContext and request ID
→ D1 atomic idempotency claim + outbox insert + replay response
→ Cloudflare Queue local consumer
→ D1 delivered state
→ UI refresh reads persisted status
```

## Scenarios

### Happy path

1. Open `http://localhost:5173` under Wrangler's `development` environment; `/api/health` shows the connected Worker.
2. Activate “Create foundation check”; the Worker persists one synthetic event and returns `202` with an opaque event ID.
3. The local queue consumer durably transitions the event to `delivered`; “Refresh status” reads that state from D1.

### Permission/tenant negative path

1. The test-only route is absent in the production-config Worker and returns `404 not_found`.
2. Local D1 scope probe inserted rows sharing a key across distinct principal and organization pairs; all three remained distinct. A duplicate exact scope used `INSERT OR IGNORE` and the resulting scoped count remained three.
3. P01 introduces no authenticated tenant-owned product route; the F23 scope test is the negative boundary for this substrate.

### Dependency failure path

1. Axum in-memory tests cover stable 400/413/415/422/404/405/500 responses, request IDs, and body/error redaction.
2. Outbox retry policy tests verify finite bounded retries, deterministic jitter, and terminal dead-letter transition. A real remote D1/Queue outage was not injected.

### Retry/idempotency/concurrency path

1. Repeating the same POST key/body returns the same event and stored result with a fresh request ID; direct local D1 query confirms exactly one outbox row.
2. Reusing the same key with a different valid body returns `409 idempotency_conflict`.
3. The claim, guard, outbox insert, and completion share one D1 batch. Wrangler D1 transactional batch rollback protects a stale claim from committing business writes.
4. A live local Worker reclaimed an expired key as a new event; a separate active pending claim stayed intact and returned `409 idempotency_in_progress`.
5. Sequential duplicate queue delivery is acknowledged without a second handler application; the live local queue path reached `delivered`.

## Evidence

- Tests: GitHub Actions [Checks run 36021309632](https://github.com/RunLumi/agents-cp.runlumi.app/actions/runs/36021309632) succeeded on exact PR #5 head `01380edb127a950e7406bc9ef46a08d39dc80dc2`. It installed pinned pnpm and Node 24, ran `pnpm check` (format, lint, typecheck, Vitest 10/10, Rust tests 47/47, Clippy, WASM target check), then ran `pnpm build` (web and production-config Worker dry run). Local direct component checks also passed.
- Local smoke: `apps/api/scripts/smoke-local.mjs` passed on 2026-09-24 using local-only development/production-config Workers and synthetic fixture data. It proved a failed stale-claim guard rolls back the D1 outbox insert, an expired key is reclaimed, and an active claim remains untouched.
- Browser review: reference screens `docs/screens/lumi_account.webp`, `docs/screens/lumi_models_routing.webp`, and `docs/screens/lumi_budget_activity.webp` were reviewed. P01 preserves the Lumi header, rail, title, and quiet surfaces; feature-specific tabs/search/profile/data/icons are omitted because this phase has no real destinations or data. Screenshots are in `output/playwright/`.
- Browser flow: real local request displayed `pending` then D1-backed `delivered`; stopping the Worker displayed a safe retryable error; after restart the retry action restored API connectivity. The deliberate outage produced one expected Vite proxy HTTP 502 console entry and no application exception.
- Responsive/focus: at 390×844 the document had no horizontal overflow; keyboard Tab focused “Create foundation check” and showed a blue 2px ring with a warm-surface 2px offset.
- Request IDs: final smoke request `req_46d8507076af48f98b92d67d1a4a505a` matched both `event.request_id` and outbox correlation ID; event `evt_8649576df48c4934bea21f002c8ef878` was delivered. Mutation replay returned the same event with a fresh request ID.
- Migration/rollback: clean local migration applied, ledger readback had no pending migration. Migrations are append-only; repair via forward migration. No production rollback/restore was exercised.
- Performance: production web output is 72.69 KiB gzip JS and 4.47 KiB gzip CSS; Wrangler production-config dry run reports 785.38 KiB upload / 240.88 KiB gzip. Initial web assets remain within the 170 KiB JS / 35 KiB CSS budgets. Dry-run bundle size is a local packaging measurement, not deployment evidence.
- Logs: middleware unit tests assert bounded fields only; Worker smoke logs showed event/action/request metadata without body, key, or event payload.

## Required gates

- [x] `pnpm check` passed in hosted CI on the exact merged PR head.
- [x] `pnpm build` passed in hosted CI on the exact merged PR head.
- [x] Rust WASM target check
- [x] Worker dry-run
- [x] Relevant P01 spec requirements
- [x] Cross-scope idempotency negative test
- [x] Secret/log review
- [x] Keyboard/focus/loading/error review for UI
- [x] Migration forward/restore strategy documented
- [x] Performance budget reviewed

## Exit decision

**PASS** — the local integration slice is real, repeatable, and uses local D1/Queues; the exact `pnpm check` and `pnpm build` scripts passed in hosted CI on the merged head. P01 is complete and P02 may open its Contract Gate. Remote Cloudflare deployment, production backup/restore, and the full F21 launch readiness contract remain outside this P01 evidence and are not claimed.
