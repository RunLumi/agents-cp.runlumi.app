# Integration Gate — PNN-IG

## Goal

Prove the phase works as one real vertical slice, not as isolated merged modules.

## Preconditions

- [ ] required packets merged
- [ ] contract version is current
- [ ] migrations applied in test environment
- [ ] no known contract drift
- [ ] shared-file owner confirms integration branch/main is coherent

## Vertical slice

Document exact journey:

```text
client
→ API
→ auth/policy
→ domain logic
→ persistence/provider/runtime
→ audit/usage/event
→ user-visible result
```

## Scenarios

### Happy path

1.
2.
3.

### Permission/tenant negative path

1.
2.

### Dependency failure path

1.
2.

### Retry/idempotency/concurrency path

1.
2.

## Evidence

- tests:
- screenshots/logs if useful:
- request IDs:
- metrics/performance:
- migration/rollback proof:

## Required gates

- [ ] `pnpm check`
- [ ] `pnpm build`
- [ ] Rust WASM target check
- [ ] Worker dry-run
- [ ] relevant spec acceptance criteria
- [ ] cross-tenant negative tests
- [ ] secret/log review
- [ ] keyboard/focus/loading/error review for UI
- [ ] rollback/migration strategy
- [ ] performance budget reviewed

## Exit decision

- PASS
- PASS WITH FOLLOW-UP
- FAIL

A phase cannot exit on "PASS WITH FOLLOW-UP" if the follow-up is security-critical, tenant-isolation-critical, data-loss-critical, or contract-breaking.
