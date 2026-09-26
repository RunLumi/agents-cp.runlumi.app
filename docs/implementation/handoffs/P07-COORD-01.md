# P07 — Coordinator status: foundation merged, phase not complete

- Phase: P07 — Enterprise identity, machine identity, internal admin, plugins
- Contract version: `p07-cg-v1` (frozen in `docs/implementation/gates/P07-CG.md`)
- Normative architecture: ADR 0007 — three actor kinds, three authorization boundaries
- Branch: `feat/p07-enterprise-admin-plugins`

## Read this first: P07 is NOT finished

This handoff describes the **foundation** of P07, not the phase. One of four
feature areas is substantially built; the other three are untouched. Nothing
here should be read as P07 being done, and no Integration Gate has been called.

| Packet | State |
|---|---|
| P07-CG contract gate | **Frozen** |
| ADR 0007 | **Accepted** |
| P07-MOD-01 enterprise identity rules | **Not started** — F06 is frozen-not-built, see below |
| P07-MOD-02 machine identity | **Substantially complete** (domain layer) |
| P07-MOD-03 plugin governance | Not started |
| P07-MOD-04 staff/support access | Not started |
| P07-BE-01 SSO/SCIM APIs | **Deliberately not started** — F06 is gated |
| P07-BE-02 service-account APIs | Schema + domain done; **no routes yet** |
| P07-BE-03 staff/admin APIs | Not started |
| P07-BE-04 plugin policy APIs | Not started |
| P07-FE-01..03 | Not started |
| P07-FE-04 internal ops UI | Deliberately not started (see scope) |
| P07-INT-01..02 | Not started |
| P07-QA-01 | Not started |

## Scope decision, and the evidence for it

Plan07 sets P07 priority as "only execute full scope when product/customer
demand justifies it", so the gate froze the whole contract and implemented the
part with a demand signal in this repository.

**Implemented.** F14 machine identity, because no machine can call any of the
48 P06 routes today except by borrowing a human session cookie — which
misattributes audit and is unusable headless, and P07-INT-02 exists for exactly
that. F25 plugin governance, because P05 already persists tool source
`IN ('built_in','plugin','custom')` with no governance above it, so F25's
"a plugin update cannot silently gain network/secret/tool capability" has no
owner and F13's default-deny is violated by any install that adds a tool.
F24-007 kill switches, because P05/P06 just shipped managed execution,
plugin-capable tools, inference routes and off-peak automation, F24-007 names
those, and there is currently no reversible off-switch for any of them.

**Frozen, not implemented.** F06 domains/SSO/SCIM. Priority P2, its own spec
says it must not be a prerequisite for the SMB/org MVP, and P06 already seeded
`sso.enabled`/`scim.enabled` defaulting `false` — so the gating seam exists and
no P07 schema is needed for it to be useful later. F06 is frozen in full in the
gate so implementing it is mechanical rather than a fresh design exercise.

**Partially implemented.** F24 staff/support: the boundary and the audit
invariants are in the contract and ADR, but no support console ships, no route
consumes a grant, and no impersonation route exists. F24-003's "default mode is
metadata, not impersonation" is met by absence.

## What is built and verified

### ADR 0007 — the load-bearing decision

`Principal` and P02's `authorize` are **untouched**. A machine or staff caller
therefore cannot reach any route that only calls `authorize`, because those
routes take `Option<&Principal>` and there is no conversion into one. Machine
authority is an `ApiKeyScope`, which has no expression that becomes a
`MembershipRole` — so FR-F14-001's "MUST NOT inherit an owner's permissions
implicitly" is a compile-time fact rather than a review rule.

Staff get a separate `StaffRole` and `StaffPermission` set that converts to
neither a `MembershipRole` nor across the boundary. Five permissions are
human-only and are refused **before** scope is consulted.

### Schema — `0016_p07_machine_identity.sql`

`service_accounts` and `api_keys`. There is no column in which an inherited
role could be recorded. The raw key never reaches D1: the wire form is
`lumik_<12 hex>_<43 base64url>`, and the server keeps a non-secret
`key_prefix`, a `secret_hash`, and a short `fingerprint`. A 64-char hex CHECK
on `secret_hash` means a raw key cannot be written there even by a future
mistake.

### Verification — `apps/api/scripts/p07-schema-invariants.mjs`

33 behaviours proven against the real DDL using Node's built-in `node:sqlite`,
so no dependency is added. Two control cases assert that legitimate writes are
**accepted**, so a blanket failure cannot masquerade as enforcement, and every
case runs in a rolled-back SAVEPOINT so the suite is order-independent.

### Domain — `core/machine.rs`, `modules/machine_identity.rs`

`MachineActor`, credential parsing, and `authorize_machine` with a 6-step check
order that is stated in the module and pinned by tests.

## Defects this work found in its own artifacts

Four, each found by a test rather than by review. All are fixed.

1. **A revoked API key's reason could be erased after the fact.**
   `trg_api_keys_revoked_requires_reason` fired on `UPDATE OF status`, so on an
   already-revoked row `UPDATE ... SET revoke_reason = NULL` never mentioned
   `status`, the trigger did not fire, and the recorded reason vanished. The
   reason for a revocation is the first thing an incident review asks for. It
   now watches both columns.
2. **An authorization bypass in the network allowlist.** A `*.trusted.example`
   entry was matched with `strip_prefix("*.")` + `ends_with`. `strip_prefix`
   removes the dot too, leaving `trusted.example`, and
   `"ci.untrusted.example".ends_with("trusted.example")` is **true** — so a host
   that merely ended with those characters satisfied a subdomain allowlist, and
   the client address is a string a caller can influence. The match now
   requires a `.` at the label boundary plus at least one label before it.
3. **The human-only check ordering was not pinned by any test.** When the scope
   contains a human-only permission, checking scope first and checking
   human-only first give the same answer, so the original test passed either
   way. The order is only observable when the scope *omits* it, and there the
   two answers differ meaningfully. There is now a test for that case.
4. **Three of my own test expectations were wrong**: I asserted `z` was invalid
   base64url (it is valid), asserted two empty secrets compare unequal (they are
   equal), and hand-typed a 44-character fixture for a 43-character field.

Clippy also caught a speculative `parse_machine_id` helper (deleted, not
`#[allow(dead_code)]`) and a 10-argument `authorize_machine` signature. The
latter was a real hazard, not a style complaint: `project`, `model_alias`,
`client_ip` and a kill-switch flag are four adjacent optional arguments, and a
transposed pair compiles and silently scopes a request to the wrong resource.
They are now a `MachineRequest`.

## Known gaps and deliberate omissions

- **No routes exist yet.** `0016` and the domain layer are in place; the BE
  routes that would call them are not written. Nothing is exposed over HTTP, so
  the foundation is inert rather than half-wired.
- **No authentication path resolves a `MachineKey` into a `MachineActor` yet.**
  `require_machine` is specified in the gate but not implemented, so no request
  can currently present a machine credential.
- **Plugins, staff/support, feature flags and kill switches are schema-frozen
  only.** Migrations `0017` and `0018` do not exist.
- **`docs/specs/f22`'s tree has no sub-page for either P07 surface.** F25 and
  F14 both mandate Web UX that F22 does not place, so the gate records two
  explicit deviations (`Plugins`, `Identity & access` under Settings) rather
  than claiming F22 authorised them. If F22 later adds these pages, relocating
  is a Change Request.
- **No data-class rows are seeded yet.** The gate names 13; P07's migrations
  must add them to `data_class_registry` or P06's F20-001 discipline is broken.
- **No plugin or staff code exists**, so none of ADR 0007's staff-side claims
  are yet enforced in code. They are frozen contract only.

## Verification at the time of writing

`pnpm check` exits 0: 496 web tests across 33 files, 700 Rust tests, lint 0
warnings, `clippy -D warnings` clean, `wasm32-unknown-unknown` checks. The
schema harness reports 33/33 invariants as declared and is identical on a
second run. Every security test above was verified to fail when its subject is
broken, by reintroducing the defect.
