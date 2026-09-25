# P05 Integration Gate — Managed control loop

- Contract Gate: `p05-cg-v1`
- Contract freeze: `b5a5ea8`
- Change requests: `P05-CR-001`, `P05-CR-002`
- Date: 2026-09-25
- Owner: P05 coordinator / QA
- State: **CONDITIONAL PASS**

## Gate decision

The real local Worker/D1 managed control loop passes with zero required
failures. The gate is conditional only where the frozen contract explicitly
has no public execution surface: the Worker records browser/computer policy,
approval, result metadata, and audit state, while the desktop/CUA host remains
outside this checkout. The passive-disconnect probe is also explicitly
non-claiming when workerd does not persist a cancellation row.

The following vertical slice was observed end-to-end on a fresh D1 database:

```text
authenticated user + two tenants
→ device enrollment/approval/binding
→ managed agent/session/run (queued → dispatching → running)
→ managed mock inference and D1 budget reservation
→ tool policy decision
→ per-use approval required and pre-approval result denied
→ browser approval resolution and tool result
→ usage/cost reconciliation and idempotent replay
→ run timeline, audit, request/run/device correlation
→ hard-budget denial of the next eligible request
→ retry/cancel, cross-tenant, stale-membership, revoked-device, MCP expansion,
  stale-policy, and concurrency probes
```

## Reproduction commands

Run from the repository root with Node 24 and the API package dependencies
installed. The script starts its own Wrangler development Worker unless
`P05_API_BASE` is supplied.

```bash
node --check apps/api/scripts/p05-smoke.mjs
pnpm exec oxfmt --check apps/api/scripts/p05-smoke.mjs
node apps/api/scripts/p05-smoke.mjs
```

For a retained fresh database while diagnosing a failure:

```bash
P05_KEEP_PERSIST=1 node apps/api/scripts/p05-smoke.mjs
```

Optional controls:

```bash
P05_PROBE_DISCONNECT=0 node apps/api/scripts/p05-smoke.mjs
P05_REQUIRE_CANCELLATION_ROW=1 node apps/api/scripts/p05-smoke.mjs
P05_API_BASE=http://127.0.0.1:8787 \
  P05_D1_PERSIST_TO=/absolute/path/to/fresh-persist \
  node apps/api/scripts/p05-smoke.mjs
```

The script creates a unique `mkdtemp` persist directory, applies migrations
`0001` through `0010`, starts Wrangler on an available local port, performs D1
`SELECT` evidence queries, and removes only the directory it created. It does
not add direct D1 fixtures, patch application schema, or use a client snapshot
as authority.

## Coordinator diagnostic execution

The following command was run against the combined current application state:

```bash
node apps/api/scripts/p05-smoke.mjs
```

Observed result:

- exit code: `0`
- fresh migration ledger: `0001`–`0010`, including `0010_p05_runs_tools_usage_control.sql`
- Worker health: passed
- checks passed: `185`
- required failures: `0`
- explicit limitations: `4`

The redacted machine report is retained in the coordinator evidence note
`docs/implementation/evidence/P05-IG-2026-09-25.md`. The report contains no raw
prompts, tool arguments, credentials, device tokens, or cookie values.

## Scenario coverage

| Area | Scripted evidence | Status |
|---|---|---|
| Fresh infrastructure | Unique local persist, migration ledger through `0010`, Wrangler health | PASS |
| Tenant isolation | Two users, two organizations, two projects, invitation/member setup, distinct IDs | PASS |
| Device lifecycle | Ed25519 enrollment, approval, invalid-proof negative, completion, heartbeat, workspace binding | PASS |
| Managed model plane | Mock success/timeout catalog selection, encrypted organization credential, fixed route, publish, model policy | PASS |
| Managed run | Device-created session/run with server-derived org/project/device/agent-session identity; queued → dispatching → running | PASS |
| Inference/accounting | Managed alias, request/run/device correlation, D1 reservation and usage rows, internal reservation replay, usage reconciliation | PASS |
| Tool policy | Read-only, privileged, browser-shaped, MCP, and stale-policy decisions | PASS |
| Approval boundary | Per-use approval-required decision, pre-approval denial, browser/admin resolution, result, replay resistance | PASS |
| MCP safety | Approved registration, approval-required MCP call, pending-review fingerprint expansion denial | PASS |
| Stale policy | Current tool policy is changed after a baseline decision; the next use is denied | PASS |
| Budget/rate | Hard-budget second-request denial, denial projection, project concurrency probe | PASS |
| Retry/cancel | Failed parent, new retry attempt, cancel, same-key replay, second terminal cancel | PASS |
| Cross-tenant/device | Foreign run reads, foreign device token, stale membership refresh, revoked-device heartbeat | PASS |
| Timeline/audit | Browser timeline/read projections plus direct D1 run-event, request, and security-event correlation | PASS |
| Passive disconnect | Conditional mock-timeout stream; no `request_cancelled` row observed by local workerd, so cancellation success is not claimed | CONDITIONAL |
| Public browser/CUA | No Worker execution route is treated as evidence; policy/result metadata only | UNSUPPORTED BY DESIGN |

## Explicit limitations and boundaries

1. **Public CUA/browser execution:** the Worker exposes policy decisions and
   bounded result metadata, not a public browser/computer execution endpoint.
   The external LumiAgents host seams enforce the same policy contract, but
   the public `@zcode/zcode-cua` package remains an unavailable placeholder.
   No browser, shell, MCP server, or computer-use action is claimed to have run
   from this smoke.
2. **Capability catalog administration:** the current public route surface has
   no capability-definition write route and the fresh database has no platform
   browser capability row. The browser-shaped decision therefore fails closed
   with `capability_not_defined`; the smoke does not seed D1 privately. The
   generic privileged-tool approval path is fully exercised and passes.
3. **Passive disconnect:** the script observes the timeout stream/concurrency
   behavior, but local workerd did not persist `error_code = request_cancelled`
   after the client abort. The report says so explicitly. With
   `P05_REQUIRE_CANCELLATION_ROW=1`, absence of that row is a failure; no
   cancellation success is inferred from an abort.
4. **Accounting units:** the managed reservation currently uses the bounded P04
   token estimate represented in the minor-unit field, while the usage
   reconciliation endpoint appends the authoritative actual cost record. Priced
   token-to-money conversion remains follow-up work; the hard-budget gate and
   immutable reconciliation behavior are still exercised.
5. **Rate counters:** RPM/TPM/concurrency checks derive from D1 usage and
   inference rows rather than a separately incremented counter table. The
   project concurrency probe passes; a future hardening packet may add an
   atomic counter projection if measured need appears.

## Evidence checklist

- [x] `node --check apps/api/scripts/p05-smoke.mjs` passes.
- [x] Targeted formatter check passes.
- [x] Fresh D1 migration through `0010` passes and the smoke starts a healthy
      development Worker.
- [x] Two-tenant provisioning and cross-tenant negatives are recorded.
- [x] Managed request/reservation/usage D1 correlation is captured.
- [x] Privileged approval-required, pre-approval denial, resolution, result,
      and replay checks are captured.
- [x] MCP expansion and stale-policy checks fail closed.
- [x] Hard-budget denial and retry/cancel checks pass.
- [x] Run timeline, audit, request ID, and tool-call correlation are captured.
- [x] Passive-disconnect result is explicitly recorded as an observed absence;
      no cancellation row is fabricated.
- [x] Public CUA limitation is explicitly accepted; no execution-host claim is
      made.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` passes.
- [x] `cargo test --workspace --lib` passes (243 tests).
- [x] `cargo check --workspace --target wasm32-unknown-unknown` passes.
- [x] Web typecheck, lint, tests, and production build pass.
- [ ] Browser screenshots/focus traversal: the review browser was disconnected
      in this environment; no screenshot is claimed.

## Required handoff evidence

Before merge, the coordinator must attach:

1. The exact smoke command, exit code, and redacted JSON report.
2. The fresh persist/migration identifier and the D1 queries used for request,
   run, reservation, usage, timeline, audit, and denial correlation.
3. Results for each hostile case, including stable error reasons.
4. The separate passive-disconnect statement above.
5. The separate public-CUA statement above.
6. Review of Rust/WASM/web verification output.
7. A follow-up issue/PR for the explicitly listed accounting and rate-counter
   hardening items; none is silently treated as complete.

## Handoff notes

- Do not treat a successful local Worker build as proof of the P05 vertical
  slice; the fresh-D1 smoke is the evidence.
- Do not treat a browser approval response as proof of browser execution.
- Do not treat a client-side abort as proof of `request_cancelled` persistence.
- Do not add direct D1 fixture writes to make a failing contract check pass.
- The optional `P05AuditEventHandler` remains disabled because producers write
  authoritative F16 security rows transactionally; the queue consumer validates
  the P05 event registry without creating a second audit authority.
