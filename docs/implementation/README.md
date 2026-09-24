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
| P01 | Foundation, contracts, storage | Ready |
| P02 | Identity, organization, authorization | Blocked by P01 |
| P03 | Device, project, policy sync | Blocked by P02 |
| P04 | AI platform, catalog, secrets, inference | Blocked by P02 |
| P05 | Runs, tools, usage, control | Blocked by P03 + P04 |
| P06 | Automations, events, billing, data | Blocked by P05 |
| P07 | Enterprise, admin, plugins | Blocked by relevant P02/P05/P06 work |
| P08 | LumiAgents migration and adoption | Blocked by relevant P03-P07 work |
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
