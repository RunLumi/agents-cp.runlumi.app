# P05 Coordinator Handoff — Implementation and integration closeout

## Scope completed

- MOD: run/session state machine, tool policy, budget/rate engine, usage/cost model.
- BE: agent/session/run/device lifecycle, tool/MCP/policy/approval broker, usage/budget/rate APIs, audit/event integration.
- FE: lazy run timeline, tool/approval surface, usage/budget surface, API decoders and error handling.
- INT: managed run correlation, managed tool decision gate, MCP identity mapping, browser/CUA policy seams in external LumiAgents.
- QA: fresh-D1/Worker managed-loop smoke and hostile matrix.

## Contract/version

- `p05-cg-v1`, freeze `b5a5ea8`.
- Accepted CR-001 and CR-002 are reflected in routes, IDs, migration, and policy snapshots.
- External LumiAgents commit: `ef5522a` on `feat/p05-managed-control-loop`.

## Verification

- `pnpm check` passes.
- `pnpm --filter @runlumi/agents-cp-web build` passes; initial JS 98.51 KiB gzip, CSS 7.92 KiB gzip; P05 chunks remain lazy and within route budgets.
- `cargo test --workspace --lib`: 243 passed.
- Clippy `-D warnings` and WASM check pass.
- Fresh D1 migrations 0001–0010 apply.
- `node apps/api/scripts/p05-smoke.mjs`: exit 0, 185 checks passed, 0 failures, 4 explicit limitations.

## Gate disposition

P05 is **conditional PASS**. The control-plane managed loop is real and
server-authoritative. Public browser/computer execution is not claimed, public
CUA remains unavailable, capability-definition administration is not exposed,
and passive disconnect cancellation is not claimed unless a D1 row is observed.

## Follow-up issues to file

1. Add a public capability-definition administration surface or seed a reviewed
   platform capability catalog for browser/computer policy smoke coverage.
2. Replace token-estimate minor units with a server-owned pricing conversion and
   introduce an atomic rate counter projection if measured concurrency requires
   it.
3. Add a host-level managed policy gate adapter and executable CUA runtime; the
   protocol/policy seams are present but the public package is a placeholder.
4. Investigate workerd passive downstream disconnect cancellation delivery in a
   runtime that persists the finalizer row.

## Review notes

- No raw prompts, arguments, secrets, tokens, or cookies are stored in run
  events, usage/cost rows, audit metadata, or smoke evidence.
- Optional P05 queue audit projection remains disabled to avoid a second audit
  authority; producers write security rows transactionally.
- Browser visual review was attempted but the desktop browser was disconnected;
  no screenshot claim is made.
