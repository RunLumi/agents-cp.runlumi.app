# Plan 00 — Multi-agent execution model

Status: Active
Scope: all implementation work
Reads first: `AGENTS.md`, `docs/specs/README.md`, relevant ADRs/specs

## 1. Goal

Turn the feature specs into a dependency-aware execution graph that lets multiple coding agents work concurrently without:

- inventing parallel domain concepts;
- changing shared contracts underneath each other;
- creating migration conflicts;
- duplicating authorization/policy logic;
- integrating frontend only after backend is "finished";
- producing large PRs that are impossible to review safely.

The unit of execution is a **work packet**, not an entire phase.

## 2. Lanes

Every plan uses the same lanes.

| Lane | Responsibility | Typical paths |
|---|---|---|
| MOD | domain modules, invariants, repository traits, pure logic | `apps/api/src/modules/<domain>/` |
| BE | HTTP handlers, persistence adapters, Cloudflare bindings, migrations | `apps/api/src/http/`, `apps/api/src/adapters/`, migrations |
| FE | routes, feature UI, query/mutation hooks, UX states | `apps/web/src/features/<domain>/` |
| INT | LumiAgents/device/protocol integration, policy sync, compatibility | versioned API/protocol code + integration docs |
| QA | contract/security/integration/performance tests | tests colocated or dedicated test dirs |

A single agent SHOULD own one lane/work packet at a time.

## 3. Contract gate before parallel work

Each phase starts with a short **Contract Gate**. Only the contract owner edits the shared contract artifacts during this gate.

Contract Gate outputs may include:

- API paths + request/response/error schemas;
- DB migration skeleton and stable entity names;
- permission identifiers;
- event names;
- policy snapshot schema;
- route/model alias schema;
- OpenAPI fragments once introduced.

After the gate is merged, MOD/BE/FE/INT/QA lanes can work in parallel against the frozen contract.

If the contract must change:

1. stop dependent merge;
2. update contract in one focused PR;
3. regenerate clients/fixtures;
4. rebase dependent work packets.

Do not let five PRs each redefine the same API.

## 4. File-ownership rule

To reduce conflicts, work packets SHOULD have disjoint write surfaces.

Example:

```text
MOD-A  apps/api/src/modules/organizations/**
BE-A   apps/api/src/http/organizations/** + adapter files
FE-A   apps/web/src/features/organizations/**
INT-A  protocol/device integration files only
QA-A   relevant tests/fixtures only
```

Shared files such as:

- root `Cargo.toml`;
- `wrangler.jsonc`;
- root `package.json`;
- central router;
- central navigation;
- migration manifest;
- generated API client;
- `AGENTS.md`;

must have one designated owner in that phase.

## 5. Branch/work-packet convention

Recommended branch:

```text
impl/pNN-<lane>-<short-topic>
```

Examples:

- `impl/p02-mod-authorization`
- `impl/p04-be-inference-streaming`
- `impl/p04-fe-routing-editor`
- `impl/p03-int-device-enrollment`

Work packet IDs:

```text
P02-MOD-01
P02-BE-01
P02-FE-01
P02-INT-01
P02-QA-01
```

PR title starts with the packet ID.

## 6. Merge order inside a phase

Default merge order:

```text
Contract Gate
    ↓
MOD ──────┐
BE adapter├──→ BE HTTP/API ─┐
FE shell ─┤                 ├──→ INT gate ─→ Phase exit
INT stub ─┤                 │
QA matrix ┘─────────────────┘
```

Important: FE does not wait for BE implementation. It starts from frozen contracts and mock/fixture data, then swaps to real API at integration gate.

## 7. Backend module rule

Prefer one module per domain:

```text
apps/api/src/modules/
  identity/
  organizations/
  memberships/
  authorization/
  devices/
  projects/
  models/
  credentials/
  inference/
  usage/
  tools/
  runs/
  audit/
  automations/
  billing/
  ...
```

A module may contain:

- domain types;
- commands/queries;
- invariants;
- repository/service traits;
- errors;
- pure tests.

Cloudflare-specific code belongs in adapters, not domain modules.

Avoid generic `common` or `utils` modules unless code has proven cross-domain meaning.

## 8. Frontend feature rule

Prefer vertical feature folders:

```text
apps/web/src/features/
  organizations/
  members/
  projects/
  models/
  routing/
  credentials/
  usage/
  devices/
  audit/
```

Each feature owns:

- route/page composition;
- API hooks/client wrapper;
- feature components;
- loading/empty/error/permission states;
- focused tests.

Reusable primitive UI remains under `components/ui`.

## 9. Integration rule

Integration must happen continuously.

Each phase should end with at least one **real vertical slice**:

```text
web or LumiAgents client
→ Rust Worker
→ authorization/policy
→ persistence/provider
→ audit/usage
→ response/state visible to user
```

Mocks are allowed during parallel development but are not phase exit criteria.

## 10. Quality gates

Every phase exit MUST pass:

- `pnpm check`;
- `pnpm build`;
- Rust WASM target check;
- Worker dry-run build;
- feature acceptance criteria from `docs/specs`;
- tenant-crossing negative tests for tenant-owned resources;
- no raw secrets in logs/test snapshots;
- keyboard/focus/error/loading review for new web flows;
- migration up/down or forward/rollback strategy documented;
- no unexplained performance-budget regression.

## 11. Persistence/platform default

Initial implementation direction:

- **D1**: canonical relational control-plane state;
- **R2**: large artifacts/exports, never authoritative metadata alone;
- **Queues**: durable async event/outbox delivery;
- **Durable Objects**: only for coordination that truly requires serialized state, e.g. selected budget reservation/lease/concurrency hotspots;
- **KV/cache**: derived cache only, never authorization authority.

D1 reads may later use read replication only after the Rust binding/session path is verified and consistency semantics are explicit.

## 12. Global dependency graph

```text
P01 Foundation/contracts/storage
  ↓
P02 Identity/org/membership/authz
  ├──────────────┐
  ↓              ↓
P03 Device/project/policy sync     P04 AI platform
  └───────┬──────┘
          ↓
P05 Runs/tools/usage/control
          ↓
P06 Automations/events/billing/data
          ↓
P07 Enterprise/admin/plugins
          ↓
P08 LumiAgents migration/adoption
          ↓
P09 Hardening/release
```

P03 and P04 should run substantially in parallel after P02 exposes stable principal/org/authorization primitives.

## 13. Definition of a completed work packet

A packet is complete only if:

- it stays inside its declared write surface or documents necessary exceptions;
- relevant spec requirement IDs are listed in the PR;
- tests cover behavior/invariants;
- no TODO hides a security-critical missing path;
- API/schema changes are reflected in contracts;
- integration notes are present for downstream packets;
- the PR is small enough to review causally.

## 14. Stop conditions

Stop and escalate contract/ADR rather than continuing if:

- two agents need incompatible definitions of the same entity;
- a feature requires bypassing centralized authorization;
- persistence semantics cannot satisfy a MUST invariant;
- Rust/Worker runtime cannot support an assumed Cloudflare primitive;
- a provider/library forces secrets into the client;
- implementation materially violates local-first migration guarantees.
