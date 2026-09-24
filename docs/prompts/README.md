# Lumi Agents Control Plane — /goal Prompt Library

These files are reusable **long-horizon coordinator prompts** for implementing the control plane.

The prompts do not replace the repository's source of truth:

```text
AGENTS.md
   ↓
docs/specs/        WHAT must exist
   ↓
docs/implementation/ HOW work is partitioned
   ↓
docs/adr/          WHY durable choices exist
   ↓
docs/prompts/      EXECUTE the plans autonomously
```

## How to use

Start an agent in the repository root and invoke the relevant goal file using the agent's `/goal` mechanism.

Typical examples:

```text
/goal @docs/prompts/goal-01.md
```

or copy the complete contents of the file into `/goal` if the harness does not support file references.

Do **not** concatenate every goal into one mega-prompt. Run the goal for the current executable phase.

## Goal index

| Goal | Plan | Main scope | Specs/features covered |
|---|---|---|---|
| `goal-00.md` | P00 | execution governance | all |
| `goal-01.md` | P01 | foundation/contracts/storage | F16, F21, F23 foundations |
| `goal-02.md` | P02 | identity/org/authz | F01–F05, F16, F23 |
| `goal-03.md` | P03 | devices/projects/policy sync | F07, F13 foundations, F19, F26 foundations |
| `goal-04.md` | P04 | models/secrets/inference | F09–F12 foundations, F21, F23 |
| `goal-05.md` | P05 | runs/tools/usage/control | F08, F12, F13, F16, F21 |
| `goal-06.md` | P06 | automation/events/billing/data | F15, F17, F18, F20 |
| `goal-07.md` | P07 | enterprise/admin/plugins | F06, F14, F24, F25 |
| `goal-08.md` | P08 | LumiAgents migration/adoption | F26 + integration requirements across F03–F19 |
| `goal-09.md` | P09 | security/reliability/release | all P0 + release-critical P1 |

Together these goals cover **F01–F26**.

## Standard operating model

Every goal assumes the agent acts as the **phase coordinator** unless the prompt says otherwise.

The coordinator should:

1. inspect current repository state before editing;
2. read `AGENTS.md`;
3. read `docs/implementation/STATUS.md`;
4. read Plan00 and the target phase plan;
5. read all referenced feature specs and ADRs;
6. verify dependencies are actually satisfied;
7. create/finalize the phase Contract Gate before parallel implementation;
8. decompose work into packet IDs and disjoint write surfaces;
9. execute independent packets in parallel where the harness permits;
10. keep shared-file ownership singular;
11. integrate continuously;
12. use a Change Request for frozen-contract changes;
13. complete the Integration Gate;
14. update `STATUS.md` only as coordinator;
15. stop only when the phase exit criteria are truly met.

## Prompt hierarchy

If instructions appear to conflict, use this precedence:

1. current explicit human instruction;
2. `AGENTS.md`;
3. feature specs;
4. accepted ADRs;
5. frozen Contract Gate;
6. implementation phase plan;
7. goal prompt;
8. implementation preferences discovered during execution.

A goal prompt must never silently override a MUST in a spec or an accepted architecture decision.

## Autonomous behavior

These goals are deliberately written for long-horizon execution.

The agent should not stop merely because:

- one work packet finished;
- a PR was created;
- tests for one lane pass;
- frontend and backend work exist separately;
- a mock demonstrates the flow.

Continue until the phase's real integration gate and exit criteria pass.

If a real blocker appears, leave the repository in a coherent state and document:

- exact blocker;
- evidence;
- affected packets;
- cheapest unblock path;
- whether dependent work can continue safely.

## Parallelism

Good parallelism:

```text
Contract Gate merged
       ↓
MOD   BE   FE   INT   QA
 \     |    |    |   /
     Integration Gate
```

Bad parallelism:

- two agents editing the same shared schema independently;
- multiple migrations defining the same invariant;
- FE inventing an API while BE invents another;
- multiple agents updating `STATUS.md`;
- a worker silently changing a frozen contract.

## Required artifacts

Use the templates in:

```text
docs/implementation/templates/
  work-packet.md
  contract-gate.md
  integration-gate.md
  handoff.md
  change-request.md
```

PRs must use `.github/PULL_REQUEST_TEMPLATE.md`.

## Definition of success

A goal is complete only when:

- its phase outcome is real, not mocked;
- relevant spec acceptance criteria pass;
- tenant/security invariants hold;
- tests/builds pass;
- integration works end-to-end;
- migrations/rollback are understood;
- downstream phase assumptions are documented;
- `STATUS.md` accurately reflects the new execution state.

When that happens, proceed to the next goal whose dependencies are satisfied.
