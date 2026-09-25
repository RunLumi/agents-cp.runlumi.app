# Integration Gate — P03-IG

## Goal

Prove P03 as one real desktop-client → Worker → D1 → policy → revocation slice using a scripted Ed25519 device client over local wrangler resources.

## Preconditions

- [x] P03-MOD-01..03, BE-01..03, FE-01..03, QA-01 integrated on `impl/p03-contract-gate`
- [x] Frozen contract `p03-cg-v1` merged (PR #9, `7952bd7`); amended by P03-CR-001 (in-branch, pre-merge)
- [x] Migration `0007_p03_devices_projects_policy.sql` applied to local development D1; no pending migrations
- [x] No contract drift; P02-CR-002 (passkey) landed mid-phase and required no P03 changes
- [x] One P03 coordinator owns router, module/permission registries, migrations, and P03 STATUS rows

## Vertical slice

```text
Desktop (scripted Ed25519 client, Node crypto)
→ POST /api/v1/devices/enrollments (anonymous begin, hashed one-time code)
→ admin approval in org session (POST /…/enrollments/:id/approve, audited)
→ GET status releases proof challenge
→ POST …/complete with Ed25519 signature over challenge
→ D1 batch: enrollment completed + first device token
→ POST /devices/bindings (explicit workspace binding)
→ GET /devices/policy (versioned snapshot, audience-bound, ack)
→ DELETE device (revocation) → heartbeat/policy/refresh all denied
```

## Scenarios

### Happy path

1. Admin signs in and creates Org A; device begins enrollment anonymously and receives a one-time user code.
2. Admin approves; the device polls, receives the proof challenge, signs it, and completes — device row `active`, first token issued.
3. Device binds workspace `ws-smoke-001` to Project P and fetches policy version N; ack recorded.

### Permission/tenant negative path

1. Pending status polls leak no challenge; completion before approval denies `enrollment_expired`.
2. A workspace binding whose project belongs to another org denies `resource_scope_mismatch`; duplicate binding identity on a device denies `workspace_binding_conflict`; restricted projects 404 for members without grants.

### Dependency failure path

1. A device whose enrolling member is removed from the org fails token refresh with `membership_required` (live negative in smoke).
2. Inline policy snapshot refresh failing does not block the mutation; the snapshot is recomputed on the next trigger.

### Retry/idempotency/concurrency path

1. Approval carries `Idempotency-Key`; completion replay after completion denies with `enrollment_expired` (single-use).
2. Wrong proof (64 zero bytes) denies `device_proof_invalid` before any state changes; Ed25519 verification is delegated to Worker WebCrypto with the enrolled public key.
3. Revocation + token invalidation share one D1 batch; a revoked device's heartbeat/policy/refresh all fail closed.

## Evidence

- Tests: Vitest 11/11, Rust 102/102, clippy `-D warnings`, cargo fmt, wasm32 check, hosted `quality` workflow PASS on PRs #11 and #14.
- Local smoke: `apps/api/scripts/p03-smoke.mjs` — **17/17 checks PASS** against `wrangler dev --env development` (local D1 + Queues), covering the full journey above including the integrated P03 snapshot/P04 policy view, replay/conflict/stale-membership negatives. When no device snapshot exists, the combined route returns the P04 default model-policy view with `persisted: false`; the P03 policy panel renders that as the explicit empty state rather than treating it as a published device snapshot. The same combined Worker persist also passed the P04 vertical smoke after the policy-route delegation was merged.
- Browser/keyboard: dashboard sections follow the P02 panel patterns (focus-visible rings, `aria` labels, loading/empty/error/retry states); devices/projects sections reachable from the org nav; smoke asserts stable `error.code`/`details.reason` so the UI branches on codes, never messages.
- Request IDs: smoke requests carry and echo `X-Request-ID`; device enrollment/approval/revoke append immutable `security_events`; binding/project lifecycle events flow through the outbox.
- Migration/rollback: `0007` applied cleanly to local development D1; append-only repair strategy.
- Performance: web 82.22 KiB gzip JS / 6.40 KiB gzip CSS (budgets 170/35); worker dry-run 533.50 KiB gzip; policy snapshot refresh is O(device bindings) and only writes on payload change.

## Required gates

- [x] `pnpm check` (format:check, lint, typecheck, test, rust:check)
- [x] `pnpm build` (web + worker dry-run)
- [x] Rust WASM target check
- [x] Worker dry-run (bindings: DB, OUTBOX_QUEUE/DLQ, ENVIRONMENT)
- [x] Relevant P03 spec requirements (F07, F13 foundations, F19, F26 foundations)
- [x] Cross-scope negatives (cross-org binding, cross-org policy audience, stale membership, duplicate identity)
- [x] Secret/log review (codes/challenges/tokens hashed at rest; logs carry IDs and stable reasons only)
- [x] Keyboard/focus/loading/error review for UI
- [x] Migration forward-only strategy documented
- [x] Performance budget reviewed

## Exit decision

**PASS** — the real vertical slice is repeatable locally with hosted CI green. The LumiAgents desktop integration lane (browser auth, key storage UX) is a later PR in the `RunLumi/LumiAgents` repo per plan03 §6 and does not gate this repository's P03 exit.
