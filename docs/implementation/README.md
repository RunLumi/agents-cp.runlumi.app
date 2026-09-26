# Implementation Execution Hub

This directory is the operating system for multi-agent delivery of the Lumi Agents Control Plane.

## Read order

Every implementation agent reads, in order:

1. `AGENTS.md`
2. `docs/specs/README.md`
3. relevant `docs/specs/fXX-*.md`
4. `docs/implementation/plan00-execution-model.md`
5. the active phase plan
6. relevant ADRs

## Plans

| Plan | Scope | Status |
|---|---|---|
| P00 | Multi-agent execution model | Active |
| P01 | Foundation, contracts, storage | Complete |
| P02 | Identity, organization, authorization | Complete (`p02-cg-v1`) |
| P03 | Device, project, policy sync | Complete (`p03-cg-v1`, P03-IG PASS) |
| P04 | AI platform, catalog, secrets, inference | Implemented/review (`p04-cg-v1`; P04-IG conditional) |
| P05 | Runs, tools, usage, control | Complete (`p05-cg-v1`, P05-IG conditional PASS) |
| P06 | Automations, events, billing, data | Contract Gate frozen (`p06-cg-v1`); packets ready |
| P07 | Enterprise, admin, plugins | Implementation complete (`p07-cg-v1`; P07-IG PASS WITH FOLLOW-UP). F06 and the internal ops console frozen-not-built by coordinator decision |
| P08 | LumiAgents migration and adoption | Blocked by relevant P03-P07 work; P07's INT seams are server-side only |
| P09 | Hardening and release | Blocked by MVP implementation |

The live execution state is in `STATUS.md`. Only the coordinator should update that file.

## Templates

- `templates/work-packet.md` — mandatory packet definition
- `templates/contract-gate.md` — phase contract freeze
- `templates/integration-gate.md` — vertical integration proof
- `templates/handoff.md` — downstream handoff
- `templates/change-request.md` — contract/plan change request

## Execution rule

Feature specs define **what** the system must do.

Implementation plans define **how work is partitioned**.

ADRs define **why durable architecture choices exist**.

A coding agent must not silently change any of those layers from inside an unrelated implementation packet.


## Goal prompts

Reusable coordinator prompts live in `docs/prompts/`.

Use the goal matching the current executable plan:

```text
P00 -> docs/prompts/goal-00.md
P01 -> docs/prompts/goal-01.md
P02 -> docs/prompts/goal-02.md
P03 -> docs/prompts/goal-03.md
P04 -> docs/prompts/goal-04.md
P05 -> docs/prompts/goal-05.md
P06 -> docs/prompts/goal-06.md
P07 -> docs/prompts/goal-07.md
P08 -> docs/prompts/goal-08.md
P09 -> docs/prompts/goal-09.md
```

See `docs/prompts/README.md` for usage, authority order, parallelism rules, and feature coverage.
