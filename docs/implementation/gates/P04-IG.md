# P04 Integration Gate — AI catalog, secrets, routing, inference

- Contract Gate: `p04-cg-v1`
- Contract freeze: `57b2df9`
- Date: 2026-09-25
- Coordinator: P04

## Vertical slice evidence

1. A fresh local D1 persist directory applies `0001`–`0009`, including merged P03 `0007_p03_devices_projects_policy.sql`, P02 authenticators `0008`, and coordinated `0009_p04_ai_platform.sql` without skipping a migration.
2. `apps/api/scripts/p04-smoke.mjs` provisions two authenticated users, one organization, encrypted organization credentials for the deterministic pre-output-failure, success, post-output-failure, and read-timeout providers, plus a metadata-only local-only credential registration.
3. `coding-default` is published with two candidates. The native streaming request returns `response.started`, text deltas, and `response.completed`; the first candidate fails before output and the second succeeds. The OpenAI-compatible non-streaming request also returns normalized JSON.
4. A route whose first candidate emits text and then fails returns a terminal `upstream_invalid_response` and does not contain the second candidate's output or a completion event. The non-stream timeout fixture never emits a byte and returns `request_timeout`; the streaming timeout fixture emits one event and remains pending for the downstream-abort path.
5. Usage rows contain provider/model/token metadata and no prompt/response content. D1 inspection shows completed rows with fallback counts, failed rows for post-output and revoked-credential cases, committed/released budget reservations, and usage rows only for successful dispatches. The final local slice recorded non-zero TTFT/total latency samples (1–3 ms / 1–4 ms) separately from provider timing; active reservations are token-bounded with a conditional D1 availability guard, and health marks the post-output failure provider cooldown. Non-stream 2xx bodies containing an upstream `error` are rejected rather than committed as empty successes.
6. The route is published, changed to a second immutable version, rolled back, and its history remains readable. The client continues using the same alias with no client release.
7. Hostile checks reject private/custom endpoint SSRF, guessed cross-tenant route/inference access, unsupported capabilities, revoked credentials, stale route/model versions, and raw-secret reflection. Local-only credential registration returns creator-scoped metadata with no ciphertext or uploaded secret and is excluded from organization credential enumeration. Provider/model lifecycle idempotency replay/conflict is exercised in the same slice.

## Requirement coverage audit

| Requirement | Concrete evidence | Status |
|---|---|---|
| Vendor-neutral Provider/Model/Alias/capability catalog | `p04-cg-v1`, migration `0009`, catalog API/UI, provider/model lifecycle smoke | pass |
| Tenant-scoped encrypted credentials and modes | AES-GCM adapter, creator-scoped local-only query, encrypted-row/plaintext-column D1 query | pass |
| Immutable route versions, publish/history/rollback | route schema/triggers, D1 history query, smoke replay/rollback | pass |
| Native/OpenAI streaming and backpressure | shared `SseDecoder`, `Body::from_stream`, metadata-only preflight, native/chat smoke | pass |
| Safe retry/fallback and side-effect boundary | `RetryController`, preflight commitment tests, post-output smoke | pass |
| Timeout and downstream cancellation | per-read deadline and signal/drop finalizer; local disconnect delivery remains follow-up | conditional |
| Health/cooldown and usage | health counters/latencies, usage/reservation D1 queries | pass for P04 foundation; pricing/scope reconciliation is P05/P06 |
| P03 policy/device extension | merged `0007`/P03 router, server-side snapshot resolution, schema-0 compatibility/project scope tests, combined P03+P04 smoke | pass |
| Control-plane UI and role safety | authenticated desktop/narrow/editor captures, typecheck/lint, role-aware requests and stable retry keys | pass for P04-owned UI |

## Verification commands

- `CARGO_HOME=/private/var/folders/zz/jzz3w1rj5lq21d_7c0nkc31m0000gn/T/opencode/cargo-home cargo test -p lumi-agents-control-plane-api --locked --lib` — **131 passed**.
- `CARGO_HOME=/private/var/folders/zz/jzz3w1rj5lq21d_7c0nkc31m0000gn/T/opencode/cargo-home cargo clippy -p lumi-agents-control-plane-api --all-targets --locked -- -D warnings` — **passed**.
- `CARGO_HOME=/private/var/folders/zz/jzz3w1rj5lq21d_7c0nkc31m0000gn/T/opencode/cargo-home cargo check -p lumi-agents-control-plane-api --locked --target wasm32-unknown-unknown` — **passed**.
- `CARGO_HOME=/private/var/folders/zz/jzz3w1rj5lq21d_7c0nkc31m0000gn/T/opencode/cargo-home pnpm --filter @runlumi/agents-cp-api build` — **Worker dry-run passed** (4,114.94 KiB upload / 1,080.80 KiB gzip).
- `pnpm --filter @runlumi/agents-cp-web typecheck` — **passed**.
- `pnpm --filter @runlumi/agents-cp-web build` — **passed** (89.55 KiB initial JS gzip; 6.55 KiB CSS gzip).
- `CARGO_HOME=... pnpm check` — **passed** (format, lint, web tests, 131 Rust tests, clippy, and WASM check).
- Fresh combined migration + local Worker (`p04-p03-merge1`) + `P03_API_BASE=http://127.0.0.1:8787 pnpm --filter @runlumi/agents-cp-api smoke:p03` — **17/17 checks passed**.
- The same combined Worker + `P04_API_BASE=http://127.0.0.1:8787 pnpm --filter @runlumi/agents-cp-api smoke:p04` — **passed** with output `{"ok":true,"org_id":"org_998aa1c9b46709fee916a6bb7afc0fca","route_id":"rte_eeeea7c0518ee7e47f143896aa26a321","usage_events":2,"caller_abort_attempted":{"responseReceived":true,"firstChunk":true}}`. It covers metadata-only preflight, custom provider/model lifecycle idempotency, local-only registration, stale-route rejection, route/credential replay/conflict, timeout classification, post-output no-fallback, and secret-free responses. The combined D1 audit reports 8 completed requests, 8 committed and 12 released reservations, 79 completed idempotency projections, 8 P03 policy snapshots, zero `request_cancelled` rows, and zero raw-secret columns. The local runtime returned the first chunk but did not deliver a corresponding `request_cancelled` D1 row; the signal/drop finalizer is code-verified, while platform disconnect delivery remains an explicit runtime limitation.

## Contract and security checks

- P02 remains the only principal/session/membership authorization path; P04 only extends centralized permissions. A small P02 repository compatibility fix aliases `membership_version` in the organization summary query so the authenticated shell and P04 panel can load together.
- The active outbox consumer now registers every emitted P04 event (catalog, policy, credentials, routes, inference, and usage) and has a registry regression test; P04 events are acknowledged instead of dead-lettered as unsupported.
- P04 catalog, credential, route, policy, and lifecycle mutations persist scoped idempotency projections; policy/provider/model/route/credential version guards abort stale conditional batches, and failed claims are released. Fixed/weighted strategies, fail-closed production policy, tenant model ownership, creator-scoped local-only metadata, provider health counters, request-ID propagation, Anthropic request/stream normalization, and UI retry-key reuse are covered by the slice.
- Raw secrets never enter catalog responses, usage, events, outbox payloads, errors, or normal logs.
- Provider endpoints are server-controlled, exact-host allowlisted, HTTPS-only in production, private/link-local blocked, and redirects rejected.
- The first meaningful provider text/tool event commits the response; metadata/usage-only events are held in preflight, and fallback exists only before commitment.
- P03 remains the owner of trusted project/device policy transport; the merged P03 route now returns the P04 model-policy view alongside the versioned snapshot, and P04 resolves the latest persisted snapshot server-side after authorization. The frozen P03 opaque `models.schema_version: 0` placeholder is treated as no model override, while a present-but-malformed P04 extension still disables managed routing.

## Evidence limitation

The OpenCode Review browser was unavailable, so the Review-browser focus traversal itself was not claimed. A local Chrome CDP pass against the P04 Worker rendered the authenticated Models & Routing screen at 1440×1000 and 390×844, plus the route editor at desktop width; screenshots are stored at `docs/implementation/evidence/p04-models-routing-desktop.png`, `docs/implementation/evidence/p04-models-routing-narrow.png`, and `docs/implementation/evidence/p04-models-routing-editor.png`. A CDP keyboard audit found 27 enabled focusable controls, including navigation, refresh, credential form, route strategy/candidates, weight/timeout/retry inputs, credential handles, and publish. The captures were compared with `docs/screens/lumi_models_routing.webp` and `DESIGN.md`; the narrow catalog table intentionally preserves horizontal scrolling for dense evidence columns. Re-run the Review-browser focus pass when the desktop browser is connected.
