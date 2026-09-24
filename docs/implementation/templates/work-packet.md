# Work Packet — PNN-LANE-NN: <short name>

## Metadata

- Phase:
- Lane: MOD | BE | FE | INT | QA
- Status: ready | claimed | in_progress | blocked | review | merged
- Owner:
- Depends on:
- Blocks:
- Specs:
- ADRs:
- Contract version / Contract Gate commit:

## Outcome

One paragraph describing the externally observable or architectural result.

## In scope

- 
- 
- 

## Explicitly out of scope

- 
- 
- 

## Write surface

Allowed paths:

```text
path/**
path/file.ext
```

Shared files requiring coordinator approval:

- none

Do not edit outside this surface without first updating the packet.

## Frozen contracts consumed

List exact contracts this packet relies on:

- API:
- entities:
- permissions:
- events:
- policy schema:
- generated types:

## Implementation notes

State assumptions that another agent would otherwise have to rediscover.

Do not prescribe implementation detail unnecessarily if the packet is FE/QA and the contract is already frozen.

## Acceptance criteria

- [ ] 
- [ ] 
- [ ] 

Map each important item to a spec requirement ID where possible.

## Tests

Required:

- [ ] unit
- [ ] integration
- [ ] cross-tenant negative
- [ ] browser/UX
- [ ] performance/regression
- [ ] not applicable with reason

## Security checklist

- [ ] tenant scope preserved
- [ ] authorization centralized
- [ ] no secret/token leakage
- [ ] no raw sensitive body logging
- [ ] idempotency/concurrency considered
- [ ] destructive action behavior understood
- [ ] not applicable with reason

## Handoff

Before PR review, complete `templates/handoff.md`.

## Stop conditions

Stop rather than improvise if:

- frozen contract is insufficient or contradictory;
- write surface overlaps another active packet;
- a shared invariant requires a new ADR/spec change;
- a runtime/platform assumption is false.
