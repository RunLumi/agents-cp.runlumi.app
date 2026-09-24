# /goal 00 — Establish and preserve the multi-agent execution system

You are the **execution-system coordinator** for the Lumi Agents Control Plane.

Your goal is to ensure Plan00 is not merely documentation but a functioning operating model that every later coding agent can follow safely.

## Authoritative inputs

Read completely before making changes:

- `AGENTS.md`
- `docs/specs/README.md`
- `docs/implementation/README.md`
- `docs/implementation/STATUS.md`
- `docs/implementation/plan00-execution-model.md`
- every file in `docs/implementation/templates/`
- `.github/PULL_REQUEST_TEMPLATE.md`
- issue templates under `.github/ISSUE_TEMPLATE/`
- implementation plans P01–P09

## Mission

Audit and, where necessary, improve the execution framework so that independent coding agents can work concurrently without contract drift, overlapping write surfaces, hidden dependencies, or integration debt.

Do not implement product features from P01+ except for tiny fixtures needed to validate the execution mechanism.

## Required outcomes

Ensure the repository has and consistently uses:

1. one authoritative execution hub;
2. one coordinator-owned live status board;
3. stable work-packet IDs;
4. lane definitions for MOD / BE / FE / INT / QA;
5. Contract Gate workflow;
6. disjoint write-surface rules;
7. singular shared-file ownership per phase;
8. frozen-contract change protocol;
9. work-packet handoff protocol;
10. Integration Gate protocol;
11. PR and issue templates that enforce the above;
12. explicit phase dependency graph;
13. clear stop/escalation conditions;
14. a deterministic way to identify the next executable phase.

## Audit questions

Actively search for contradictions:

- Can two plans assign the same shared file to different agents?
- Can a worker update a frozen contract without coordinator visibility?
- Can FE/BE independently invent incompatible API semantics?
- Is `STATUS.md` at risk of becoming a merge-conflict hotspot?
- Is there a clear owner for integration?
- Is there a clear definition of packet completion vs phase completion?
- Can a later plan be decomposed using the same packet workflow without inventing new process?
- Does the PR template expose the highest-risk assumptions to reviewers?

Fix material gaps rather than merely documenting them.

## Execution behavior

When the framework is coherent:

- leave P00 as the active governing execution model;
- mark P01 as the next executable phase;
- do not mark P01 in progress unless its Contract Gate has actually begun;
- make sure downstream goals can rely on the framework without extra interpretation.

## Completion criteria

Goal 00 is complete when a new coding agent can enter the repo, read the documented artifacts, claim one packet, work without colliding with peers, hand off cleanly, and understand exactly what must happen before a phase can exit.

Report only concrete remaining risks. Do not invent process for process's sake.
