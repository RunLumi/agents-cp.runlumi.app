# ADR 0007: Three actor kinds and three separate authorization boundaries

- Status: Accepted
- Date: 2026-09-26
- Scope: P07 machine identity, internal staff access, and plugin governance

## Context

`core::Principal` is a **human** principal. It carries a `UserId` and a
revocable `SessionId`, is produced only by `http::auth::require_session` after
a session row is read from the canonical store, and is the input to
`modules::authorization::authorize` — the single policy decision path for
protected organization operations.

Two new kinds of caller now need to act, and neither is a human:

- **Machine identity.** F14's objective is that CI, integrations, managed
  runners, and automations call the control plane "without pretending to be a
  human user". Today there is no way for any of them to call the 48 P06 routes
  except by borrowing a human session cookie, which is simultaneously wrong
  (the audit trail attributes machine work to a person) and unusable (a runner
  has no interactive login).
- **Internal staff.** F24 requires named staff identity and a staff role, and
  Plan07 BE-03 states plainly: "Do not reuse customer Admin role as platform
  staff role."

The tempting shortcut is to widen `Principal` — add a kind, make `user_id`
optional, and let a machine present a service account in the same field. That
shortcut is unsafe for three specific reasons:

1. `authorize` scopes a request with `membership.user_id != principal.user_id`.
   A machine has no `user_id`, so the scope check would either be skipped for
   machines (removing tenant isolation for exactly the caller that needs it most)
   or be faked with a sentinel that could collide with a real user.
2. Every existing call site would gain a "what if this is a machine" branch.
   With four call sites today that is cheap; the point is that the *type* would
   no longer make the mistake impossible, only unlikely.
3. Staff and customer authority would end up in one enum. Plan07 and F24 both
   forbid a customer `Admin` from conferring platform authority. If both live in
   one role type, that separation becomes a runtime check that a future edit can
   remove, instead of a type error.

## Decision

Keep `Principal` exactly as it is and add **two new actor kinds that cannot be
expressed as a human principal**. There are three actors and three
authorization boundaries.

```text
Human   → Principal     → authorize(...)        → MembershipRole + permission
Machine → MachineActor  → authorize_machine(...) → APIKey scope (never a role)
Staff   → StaffActor    → authorize_staff(...)   → StaffRole + StaffPermission
```

- `authorize` is **not modified**. P02's decision path is frozen and every
  existing route keeps calling it unchanged.
- **Machine authority is a scope, not a role.** F14-001 says a service account
  "MUST NOT inherit an owner's permissions implicitly". Because the authority is
  the key's own scope set, there is no expression in the type system that grants
  a machine a `MembershipRole`, so the F14-001 prohibition is structural rather
  than a rule someone has to remember.
- **Machine scope is checked against the resource on every request**, including
  the organization and project scope of the target. A key scoped to one project
  cannot reach another project in the same organization (F14 acceptance
  criterion), and cannot reach any organization but its own.
- **Staff authority is a separate role enum and a separate permission enum.**
  A `StaffRole` never converts to a `MembershipRole` and a `MembershipRole`
  never satisfies a `StaffPermission`. Staff routes live under a distinct path
  prefix and resolve a distinct principal from a distinct credential.
- **Staff access to a customer organization requires an explicit
  `SupportGrant`**: named actor, reason/ticket, bounded TTL, and a
  customer-visible audit event. Default staff mode is metadata and support
  diagnostics, never impersonation (F24-003).
- Secrets for both new kinds follow the P02 rule already in force: the raw value
  is shown once, only a hash plus a non-secret prefix/fingerprint is persisted,
  and comparison is constant-time.

### Why not one `Actor` enum

A single `enum Actor { Human, Machine, Staff }` passed to one `authorize` is
more elegant to write and strictly worse to audit: every branch inside the
decision function has to decide which authority model applies, and the P02
function that 48 routes depend on would grow branches it has no tests for. Three
entry points make the boundary visible in the type system and keep P02 untouched.

## Consequences

- P02's `authorize`, `Principal`, and every existing route are unchanged. P07
  is additive.
- A machine or staff caller cannot reach a route that only calls `authorize`,
  because those routes take `Option<&Principal>`. Adding a machine path to an
  existing route is therefore a deliberate, visible change rather than something
  that happens because an auth middleware got smarter.
- The cost is that shared logic (organization-state fencing, rate limiting,
  idempotency) must be factored for three callers instead of one. That factoring
  is done once, in the module layer, and each boundary keeps its own decision
  function.
- F24-007 kill switches are a **platform** capability, not a customer
  permission, so they are not modelled as a `StaffPermission` that a customer
  role could ever reach.

## Implementation constraints

- `MachineActor` and `StaffActor` must not be constructible from a
  `Principal`, and `Principal` must not gain a kind field.
- Any new `StaffRole` variant requires a new `StaffPermission` set; adding one
  without the other is a contract change, not an implementation detail.
- A `SupportGrant` that has expired, been revoked, or whose organization no
  longer matches the target denies with a stable code. Expiry is enforced
  server-side on every request, not only at grant creation.
- A staff audit event is written on **grant creation and on every use**, so a
  support session is reconstructable from the customer's own audit view without
  trusting platform-side logs.
- Plugin governance decisions (F25) are customer-org policy and stay inside the
  human `MembershipRole` boundary. Platform quarantine of a vulnerable plugin
  version is a kill switch, and is deliberately not an org policy a customer can
  grant or revoke.

## Rollback

The three boundaries are additive. Reverting P07 removes the new routes and the
new actor types and leaves P02–P06 behaviour byte-identical, because nothing
existing was modified. There is no data migration to undo beyond dropping P07
tables, which contain no P02–P06 data.

## References

- `docs/specs/f14-api-keys-service-accounts-machine-identity.md` (FR-F14-001,
  FR-F14-003, FR-F14-007)
- `docs/specs/f24-admin-support-abuse-feature-rollouts.md` (FR-F24-001,
  FR-F24-003, FR-F24-007)
- `docs/implementation/plan07-enterprise-admin-plugins.md` (BE-03)
- `docs/implementation/gates/P07-CG.md`
