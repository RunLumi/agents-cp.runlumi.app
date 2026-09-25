# P05 coordinator handoff — contract and shared foundations

## What changed

- Froze `p05-cg-v1` at `b5a5ea8` and opened `P05-CR-001`/`P05-CR-002` for integration clarifications.
- Added the `0010_p05_runs_tools_usage_control.sql` forward migration skeleton.
- Added shared P05 permission variants, opaque P05 resource IDs, device authorization helper, correlated security-event helper, and P05 policy consumers.
- Extended the P03 policy compiler with versioned `budgets` and `rate_limits` extension sections.

## Contracts produced

- P05 device run lifecycle and tool-result routes.
- Run projection/event/approval binding fields.
- Additive non-inference `run_usage_events` source.
- Internal-only reservation/reconciliation semantics.
- Runtime protocol contracts for run identity, MCP mapping, and browser/computer decisions.

## Database/migration impact

- Apply `0001`–`0010` in order on a fresh D1 database.
- P05 migration extends P04 `inference_requests`, `usage_events`, `budget_reservations`, `budgets`, and `security_events` additively.
- Do not edit applied P03/P04 migrations; use forward repair migrations for later changes.

## Known limitations

- Local workerd passive downstream disconnect delivery remains a P04 runtime limitation; P05 must not claim a cancellation lifecycle row without observing it.
- The public Computer Use package remains an API-compatible unavailable placeholder; the integration seam can be implemented but real CUA execution cannot be claimed from this checkout.

## Downstream agent notes

Read `P05-CR-002` before implementing routes or external protocol code. P05 remains incomplete until a real enrolled-device → managed inference → approval → tool result → usage/audit loop passes.
