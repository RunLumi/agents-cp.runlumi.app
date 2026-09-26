# Execution Status

Coordinator-owned file. Coding agents MUST NOT edit this file unless explicitly assigned the coordinator role.

Last initialized: 2026-09-24

## Current phase

- Active execution model: **P00**
- Current implementation phases: **P07 implementation complete (Integration Gate: PASS WITH FOLLOW-UP); P06 implementation complete; P05 complete; P04 implemented/review; P03 complete**
- Next implementable phase: **P08, once P07's browser and local-D1 follow-ups are accepted as carried debt. P07-MOD-01/BE-01 (F06) stay frozen-not-built and are not blockers.**
- Current Contract Gates: **P02-CG `p02-cg-v2`; P03-CG `p03-cg-v1`; P04-CG `p04-cg-v1`; P05-CG `p05-cg-v1`; P06-CG `p06-cg-v1`; P07-CG `p07-cg-v1` (frozen, no Change Request)**
- Shared-file owner: **P07 coordinator for P07; P06 coordinator for P06; P05 coordinator for P05; P04 coordinator for P04; P03 coordinator (merged) for P03**
- Integration owner: **P07 coordinator for P07; P06 coordinator for P06; P05 coordinator for P05; P04 coordinator for P04; P03 coordinator (merged) for P03**

## Phase status

| Phase | State                                     | Contract Gate                                                      | Integration Gate                                        | Notes                                                                                                                                                                                                                                                                                                         |
| ----- | ----------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P00   | active                                    | n/a                                                                | n/a                                                     | execution mechanics operationalized                                                                                                                                                                                                                                                                           |
| P01   | complete                                  | merged: `7835fd9` (PR #4)                                          | PASS: `docs/implementation/gates/P01-IG.md`             | PR #5 merged as `ced9635`; hosted check/build and local vertical slice passed                                                                                                                                                                                                                                 |
| P02   | complete                                  | frozen: `ba35fb6`; CR-001: `0290e68`                               | PASS: `docs/implementation/gates/P02-IG.md`             | Real local identity/org/member/authz/audit slice and hostile smoke pass; browser capture follow-up documented                                                                                                                                                                                                 |
| P03   | complete                                  | frozen: `p03-cg-v1` (PR #9; +P03-CR-001)                           | PASS: `docs/implementation/gates/P03-IG.md`             | PR #11 (MOD/BE) + PR #14 (FE/QA) merged, hosted CI green; local smoke 17/17                                                                                                                                                                                                                                   |
| P04   | review                                    | frozen: `p04-cg-v1` (`57b2df9`)                                    | conditional: `docs/implementation/gates/P04-IG.md`      | P03 is merged and the combined P03/P04 smoke passes; P04 vertical slice, 131 Rust tests, Worker/WASM builds, hostile smoke, idempotency/health/policy extensions, authenticated desktop/narrow/editor captures, and handoffs pass; local downstream-disconnect delivery remains an explicit runtime follow-up |
| P05   | complete                                  | frozen: `p05-cg-v1` (`b5a5ea8`; CR-001/CR-002 accepted)            | conditional PASS: `docs/implementation/gates/P05-IG.md` | PR #18 merged as `976a40b`; 185-check fresh-D1/Worker managed loop passes; generic privileged approval, accounting, hostile cases, timeline/audit, and hard-budget denial pass; public CUA/browser execution and passive cancellation remain explicit limitations                                             |
| P06   | implementation complete; visual pass owed | frozen: `p06-cg-v1` (`11341a5`, PR #22; CR-001/002/003 + ADR 0006) | PASS: all six claims mapped to named evidence           | 15 migrations, 48 routes mounted, 668 Rust + 479 web tests, hosted CI green. Frontend reconciled with `docs/screens/lumi_plan_entitlements.webp` and `lumi_export_history.webp`, under the authority of F22's information-architecture tree: Data & Retention is one four-tab Settings page, Billing is the reference's two-column card grid with a "Usage vs. plan limits" table, and the three P06 settings surfaces (billing, data, webhooks) sit under Settings at `/org/{slug}/settings/...` with breadcrumbs, while Automations stays top level. **Outstanding:** no P06 surface has been visually verified in a browser — none is attached to this session. `docs/screens/` has no reference for automations or webhooks; that gap is real, and is recorded in the P06-FE handoff together with the deliberate deviations |
| P07   | implementation complete; visual pass owed | frozen: `p07-cg-v1` (ADR 0007), fixture `p07-contracts-v1.json`   | PASS WITH FOLLOW-UP: `docs/implementation/gates/P07-IG.md` | Scope cut to F14 + F25 + F24-007, with F06 (SSO/SCIM/domains) and the internal ops console frozen-not-built per the gate's decisions 3 and 4. 22 routes mounted across 3 modules plus `require_machine`/`require_staff`; migrations `0016`–`0018`; 848 Rust + 720 web tests; **97/97 storage invariants proven rejected by the database itself, now a CI gate via `pnpm test`**. Six defects found by tests and fixed, including a `blocked_reason` omission that made the plugin detail page render nothing and a `*.suffix` manifest form that could not be reported at all. **Outstanding, and the reason this is not a plain PASS:** no P07 surface has been rendered in a browser (none attached), so desktop/narrow layout, focus rings, and async states are visually unverified — P06 carries the same debt; and the vertical slice is proven at the domain/projection/database layers rather than by an end-to-end request against a running Worker. `docs/screens/` has no reference for any P07 surface. F22 places neither, so `Plugins` and `Identity & access` are recorded deviations under Settings rather than claimed as F22-authorized |
| P08   | blocked                                   | blocked                                                            | blocked                                                 | waits for integration foundations                                                                                                                                                                                                                                                                             |
| P09   | blocked                                   | blocked                                                            | blocked                                                 | release hardening only                                                                                                                                                                                                                                                                                        |

## Packet status vocabulary

- `ready` — dependency satisfied; not claimed
- `claimed` — one agent owns it
- `in_progress` — implementation underway
- `blocked` — cannot proceed; blocker named
- `review` — PR open and ready
- `merged` — merged to main
- `superseded` — replaced by a new packet/contract
- `cancelled` — intentionally abandoned

## Coordinator responsibilities

The coordinator alone:

- opens/closes phase Contract Gates;
- assigns shared-file ownership;
- keeps packet IDs unique;
- resolves write-surface overlap;
- updates this status board;
- declares Integration Gate readiness;
- decides whether a contract change blocks dependent merges;
- marks phase exit only after the real vertical slice passes.

## P01 packet status

| Packet     | State  | Notes                                              |
| ---------- | ------ | -------------------------------------------------- |
| P01-MOD-01 | merged | Core primitives; PR #5                             |
| P01-BE-01  | merged | D1 substrate; PR #5                                |
| P01-BE-02  | merged | Outbox and Queue substrate; PR #5                  |
| P01-BE-03  | merged | HTTP middleware; PR #5                             |
| P01-FE-01  | merged | Typed web shell; PR #5                             |
| P01-QA-01  | merged | CI, smoke harness, and integration evidence; PR #5 |

## P02 packet status

| Packet     | State  | Notes                                             |
| ---------- | ------ | ------------------------------------------------- |
| P02-MOD-01 | merged | Identity/session domain and CSRF/session boundary |
| P02-MOD-02 | merged | Organization lifecycle and last-owner rules       |
| P02-MOD-03 | merged | Membership/invitation/team rules                  |
| P02-MOD-04 | merged | Central authorization decision path               |
| P02-BE-01  | merged | D1 migration and repositories                     |
| P02-BE-02  | merged | Auth/session HTTP flow                            |
| P02-BE-03  | merged | Org/member/team/audit APIs                        |
| P02-BE-04  | merged | Account/session security APIs                     |
| P02-FE-01  | merged | Auth and account UI                               |
| P02-FE-02  | merged | Organization shell/switcher                       |
| P02-FE-03  | merged | Members/teams UI                                  |
| P02-INT-01 | merged | Desktop PKCE handoff                              |
| P02-QA-01  | merged | Hostile matrix and local integration evidence     |

## P02 additive authentication upgrade

P02 core remains complete; P03/P04 are not blocked.

| Packet     | State | Notes                                                              |
| ---------- | ----- | ------------------------------------------------------------------ |
| P02-MOD-05 | ready | Passkey/password credential domain and ceremony invariants         |
| P02-BE-05  | ready | Worker/WASM verifier+KDF spike, persistence, passkey/password APIs |
| P02-FE-04  | ready | Passkey-first signup/login; email/password secondary               |
| P02-QA-02  | ready | WebAuthn/password hostile + browser compatibility matrix           |

Target auth hierarchy: **passkey first, email/password second**. Existing email-code login is compatibility/recovery only after the upgrade ships.

## P04 packet status

| Packet     | State  | Notes                                           |
| ---------- | ------ | ----------------------------------------------- |
| P04-MOD-01 | review | Provider/model/alias catalog and policy filters |
| P04-MOD-02 | review | Credential ownership, lifecycle, and precedence |
| P04-MOD-03 | review | Immutable route compiler and selector           |
| P04-MOD-04 | review | Explicit retry/fallback response state machine  |
| P04-BE-01  | review | Catalog/route APIs and D1 repository            |
| P04-BE-02  | review | Encrypted credential storage and resolution     |
| P04-BE-03  | review | Provider adapters and SSRF boundary             |
| P04-BE-04  | review | Streaming inference gateway and usage hook      |
| P04-BE-05  | review | Provider health/cooldown persistence            |
| P04-FE-01  | review | Provider/model catalog UI                       |
| P04-FE-02  | review | Credentials UI                                  |
| P04-FE-03  | review | Routing editor/history UI                       |
| P04-INT-01 | review | LumiAgents managed inference path               |
| P04-INT-02 | review | ZCode provider/model mapping                    |
| P04-QA-01  | review | Streaming/fallback/security smoke matrix        |

P04 packets remain marked `review` until the coordinator's change is committed/PR-ready; P04-owned evidence is complete, while the phase remains conditional on the named local disconnect follow-up.

## P05 packet status

| Packet     | State  | Notes                                               |
| ---------- | ------ | --------------------------------------------------- |
| P05-MOD-01 | merged | Session/run state machine and retry semantics       |
| P05-MOD-02 | merged | Tool/capability policy evaluator                    |
| P05-MOD-03 | merged | Budget reservation and rate-limit engine            |
| P05-MOD-04 | merged | Usage/cost/reconciliation model                     |
| P05-BE-01  | merged | Agent/session/run persistence and APIs              |
| P05-BE-02  | merged | Tool/MCP/policy/approval APIs                       |
| P05-BE-03  | merged | Usage/budget/rate APIs                              |
| P05-BE-04  | merged | Audit and operational event integration             |
| P05-FE-01  | merged | Runs/session timeline UI                            |
| P05-FE-02  | merged | Tool policy and approvals UI                        |
| P05-FE-03  | merged | Usage/budget UI                                     |
| P05-INT-01 | merged | Managed run identity propagation                    |
| P05-INT-02 | merged | Privileged tool decision broker                     |
| P05-INT-03 | merged | MCP source/tool mapping                             |
| P05-INT-04 | merged | Browser/computer policy integration                 |
| P05-QA-01  | merged | Managed control-loop integration and hostile matrix |

P05 Contract Gate `p05-cg-v1` is frozen at `b5a5ea8`; no dependent packet may redefine its contracts without a Change Request. Coordinator evidence is recorded in `docs/implementation/evidence/P05-IG-2026-09-25.md`; PR #18 merged the control plane as `976a40b`, and external LumiAgents PR #29 merged the managed integration seams as `9dc43d6`.

## P06 packet status

| Packet        | State  | Notes                                                                                            |
| ------------- | ------ | ------------------------------------------------------------------------------------------------ |
| P06-MOD-01    | merged | Scheduler/occurrence/lease/off-peak semantics; 64 tests                                          |
| P06-MOD-02    | merged | Entitlement evaluator and license/grace matrix; 65 tests                                         |
| P06-MOD-03    | merged | Retention/deletion planner and 72-class data registry; 57 tests                                  |
| P06-SCHEMA-01 | merged | Migrations `0011`–`0015`; 8 frozen invariants proven against fresh D1                            |
| P06-BE-01     | merged | Automation APIs, dispatcher, device lease lifecycle; 68 tests                                    |
| P06-BE-02     | merged | Webhooks/notifications, signed delivery, job consumer; 58 tests                                  |
| P06-BE-03     | merged | Billing/entitlements/licensing, provider adapter, Ed25519 signing; 51 tests                      |
| P06-BE-04     | merged | Export/deletion jobs, private R2 adapter; 56 tests                                               |
| P06-COORD-01  | merged | 48 P06 routes mounted, merged job queue, automation sweeps, license seeding, P02 deletion bridge |
| P06-FE-01     | merged | Automations UI; 76 tests. Section registered                                                     |
| P06-FE-02     | merged | Webhook/notification UI; 116 tests. Section registered                                           |
| P06-FE-03     | merged | Billing/entitlement UI; 70 tests. Section registered                                             |
| P06-FE-04     | merged | Data/retention/export/delete UI; 109 tests. Section registered                                   |
| P06-INT-01    | merged | LumiAgents lease/fence seam on `feat/p06-automation-lease`; 81 tests                             |
| P06-INT-02    | merged | Licensing snapshot embedded in the existing `/devices/policy`                                    |
| P06-QA-01     | done   | All six Integration Gate claims mapped to named evidence                                         |

P06 Contract Gate `p06-cg-v1` is frozen at `11341a5` in `docs/implementation/gates/P06-CG.md`, with fixture `docs/implementation/fixtures/p06-contracts-v1.json`. Normative clarifications: `P06-CR-001` (lease fencing/`ambiguous`, calendar intervals, off-peak execution class), `P06-CR-002` (entitlement/license separation, internal-only overrides, provider projection), `P06-CR-003` (P02 deletion bridge, private R2 per ADR 0006). No implementation packet may silently redefine these contracts.

## P07 packet status

| Packet        | State  | Notes                                                                                                    |
| ------------- | ------ | -------------------------------------------------------------------------------------------------------- |
| P07-CG        | merged | `p07-cg-v1` frozen with ADR 0007; fixture `p07-contracts-v1.json` created and consumed by Rust **and** TS |
| P07-MOD-01    | frozen | Enterprise identity (F06). Frozen-not-built per coordinator decision 3; no schema needed, `sso.enabled`/`scim.enabled` already seeded `false` |
| P07-MOD-02    | merged | Machine identity: `CapabilitySet`, `ApiKeyScope`, `authorize_machine`, key material. 35 + 35 tests     |
| P07-MOD-03    | merged | Plugin governance: manifest, 8-class diff, policy, two decision functions. 24 tests                     |
| P07-MOD-04    | merged | Staff/support: `StaffRole`, 5 human-only permissions, support-grant TTL and reason. 14 tests            |
| P07-BE-01     | frozen | SSO/SCIM APIs. Frozen-not-built with MOD-01                                                              |
| P07-BE-02     | merged | 9 service-account/API-key routes; `require_machine`; 10 projection and error tests                      |
| P07-BE-03     | merged | 6 `/api/v1/internal/*` routes; `require_staff`; 8 tests. No web client, per gate decision 4              |
| P07-BE-04     | merged | 9 plugin policy/install/report routes; 13 tests. Migrations `0017`/`0018`, 13 data classes              |
| P07-COORD-01  | merged | 22 routes mounted in `app.rs`; the four P07 permissions added to `role_allows`, not only `Permission`    |
| P07-FE-01     | merged | Identity settings section. 3-capability set, human-only refused, no wildcard offered. 15 tests          |
| P07-FE-02     | merged | Service accounts + API keys; one-time secret reveal as a pure reducer. 30 tests                         |
| P07-FE-03     | merged | Plugin governance: diff, install state, pin, block reason, tool registration. 35 tests                  |
| P07-FE-04     | frozen | Internal operations UI. Not needed; deliberately not built per gate decision 4                          |
| P07-INT-01    | merged | `POST /plugin-reports`; the server decides, the report is evidence and can only downgrade               |
| P07-INT-02    | merged | `require_machine` + `GET /api/v1/machine/whoami`. Server-side seam only; **no LumiAgents-side code exists** |
| P07-QA-01     | merged | 97 storage invariants (5 cross-tenant), the plan07 hostile matrix traced item by item, 4 items N/A      |

P07 Contract Gate `p07-cg-v1` is frozen in `docs/implementation/gates/P07-CG.md`
with ADR 0007 and no Change Request. Scope was cut by coordinator decision, not by
omission: F06 (SSO/SCIM/domains) and the internal operations console are frozen in
full in the gate, so implementing either is mechanical rather than a fresh design
exercise. Coordinator evidence is in `docs/implementation/gates/P07-IG.md`; the
prior foundation handoff, `P07-COORD-01.md`, is superseded by the four packet
handoffs and the gate.

## Rule

This file is a coordination artifact, not a task log. Keep it compact. Detailed work belongs in issues/PRs using the templates.
