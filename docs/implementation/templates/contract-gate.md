# Contract Gate — PNN-CG

## Purpose

Freeze the smallest shared contract required for parallel work in this phase.

The Contract Gate is not the implementation PR.

## Owner

One owner only.

## Inputs

- phase plan:
- specs:
- ADRs:
- previous phase outputs:

## Contracts to freeze

### Domain vocabulary

| Concept | Stable name | Notes |
|---|---|---|
| | | |

### IDs and ownership

| Resource | ID type | Tenant owner | Parent |
|---|---|---|---|
| | | | |

### API

| Method | Path | Permission | Request | Response | Errors |
|---|---|---|---|---|---|
| | | | | | |

### Permissions

- 

### Events

| Event | Producer | Consumer | Versioned payload |
|---|---|---|---|
| | | | |

### State machines

Document only shared states/transitions that parallel agents must agree on.

### Persistence skeleton

List table/entity names and invariant-bearing unique/index constraints. Do not pre-design every future column.

### Policy/config snapshot

If applicable, define the versioned outer envelope and extension points.

## Compatibility

- previous client/server compatibility:
- migration expectations:
- external ZCode/LumiAgents identifier mapping:

## Error semantics

List stable machine-readable codes required by downstream agents.

## Fixtures

Provide minimal contract fixtures for FE/QA before backend implementation exists.

## Freeze commit

After merge:

- Contract Gate commit:
- Contract version/tag if used:
- dependent packets unlocked:

## Change rule

After freeze, no dependent PR may silently redefine this contract.

A required change must use `change-request.md`.
