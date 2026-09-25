# P06 frontend handoff (coordinator)

Covers P06-FE-01 (automations), P06-FE-02 (webhooks and notifications),
P06-FE-03 (billing and entitlements), and P06-FE-04 (data governance),
plus the four shell registrations that make them reachable.

## What shipped

| Section           | Feature directory                                       | Tests |
| ----------------- | ------------------------------------------------------- | ----- |
| Automations       | `apps/web/src/features/automations/`                    | 76    |
| Webhooks & alerts | `apps/web/src/features/webhooks/`, `.../notifications/` | 116   |
| Plan & usage      | `apps/web/src/features/billing/`                        | 70    |
| Data & retention  | `apps/web/src/features/data-governance/`                | 109   |

All four are lazy panels registered in
`apps/web/src/features/organizations/org-dashboard.tsx`, so the initial route
chunk is unaffected. Total web suite: 445 tests across 28 files.

## The rules the UI enforces rather than merely describes

A UI that lets someone compose a request the server will reject, and then
shows a 403, is worse than one that refuses it up front. Three frozen rules
are therefore enforced client-side as well as server-side:

- **Exact event names only.** A webhook subscription may not be a wildcard or
  a family prefix. The picker rejects both, disables the never-fanned-out
  names with the reason shown, and passes already-stored names through
  unchanged so editing an endpoint never silently drops a live subscription.
- **Mandatory security notifications cannot be opted out.** The client mirrors
  the server's family _containment_ check rather than exact equality. A
  stricter client would show a mandatory event as optional and then let the
  write fail.
- **Retention may be shortened, never extended** past the legal maximum
  without an audited override. The editor refuses rather than silently
  accepting.

## The honesty requirements

These are the reasons the surfaces exist, and each is asserted against the
real rendered component tree rather than described in a comment.

- **`ambiguous` is not a failure.** An occurrence whose authority was lost is
  in a reconciliation state: the server cannot prove whether execution began,
  so it is never automatically retried. It is deliberately not styled with
  danger tokens, which would tell an operator the run had failed.
- **A downgrade blocks new work and deletes nothing.** The over-limit
  projection names what is over, what remediation is required, and states that
  existing data survives.
- **A deletion certificate states coverage, not completion.** A `skipped`
  step always says why, upstream provider data is never presented as deleted
  by Lumi, local device data is not removed by a Lumi deletion, and the
  coverage a certificate could not traverse is stated rather than implied.
- **A download grant is short-lived and must be re-minted.** There is no
  permanent link, and the expiry is visible.
- **A resumed export is not a fresh snapshot.** It reuses the same frozen
  category manifest and cutoff, and the panel says so.
- **The four decision inputs are separate.** Authorization permission, Lumi
  product entitlement, usage budget, and upstream provider entitlement get
  distinct surfaces, and the panel opens by naming them and what each one
  does _not_ decide.

## Two rules that make the honesty properties structural

**No provider product, price, or customer ID can reach the screen.** Every
decoder is an allowlist that copies named fields and never spreads the wire
object, and a test walks both the decoded structures and the rendered HTML for
known provider ID shapes. The classifier excludes Lumi's own opaque IDs, so a
`sub_` or `pep_` row is not a false positive — a real bug the packet's own
tests caught.

**Nothing renders a raw server error string.** Every failure path goes through
`presentApiError`. A test asserts that a 409 whose message contains a
provider price ID surfaces only the stable code.

## Shell wiring decisions

- `canRun` for automations is deliberately **wider** than `canManage`: P06-CG
  grants `automations.run` to members while `automations.manage` stays with
  admins. A viewer is read-only on every P06 surface.
- `canExport`, `canDelete`, and the billing `canManage` are wired to
  `canManage` for the same reason: the server enforces them independently, so
  the flags only avoid rendering a control the role cannot use.
- The two expiries in the license block are presented as two **named clocks**
  ("signed offline validity" and "policy freshness"), because a bare date
  invites collapsing them into one.

## Findings, not inventions

Recorded rather than papered over:

- The frozen API has **no downgrade-preview route**, so a downgrade cannot be
  previewed before submission. The panel refuses to submit and routes to the
  provider portal instead. This is a contract gap and needs a Change Request
  if previews are in scope.
- `GET /entitlements` publishes **no over-limit counts**, so the usage column
  reads "Usage not reported here" rather than guessing. A limit with no
  server-reported count is never shown as zero.
- The delivery projection carries **no attempt-level diagnostics**, because no
  frozen route returns attempt rows.
- `DESIGN.md` has no token for `ambiguous`, no pattern for "these are four
  different decision types", and no deadline-presentation rule. Each was
  composed from existing variables rather than invented: a dashed border, a
  definition list with hairline dividers, and a 3px severity rail with
  `tabular-nums` `<time>`. The "provenance eyebrow" pattern
  (`LUMI SUBSCRIPTION` / `LICENSE STATE` / `UPSTREAM PROVIDER ACCOUNT`) emerged
  and is used consistently. All three are candidates for `DESIGN.md`.

## Test-harness limitation found while verifying, not assumed

While completing a partially-written test I tried to assert that the data
panel renders its export and deletion job surfaces even when the policy
read is refused — the `pending_deletion` case, where a tenant must still see
the deletion it has to finish.

**It cannot be asserted with this repo's web test stack.** `apps/web` has
vitest with `renderToStaticMarkup` and no DOM, no `act()`, and no
`@testing-library`. A container with an async read is therefore always
captured in its initial loading state, so the conditional wiring is not
reachable from a static render.

I first wrote a version of that test anyway. It passed — and then it also
passed with the job surfaces deliberately nested inside the policy guard,
because the assertions were matching the panel's own static headings rather
than the workflows. It was a vacuous test.

What is actually pinned now:

- The copy shown when the policy is unreadable, asserted on the exported
  `POLICY_UNAVAILABLE_REASON`, including that it never reads as though the
  deletion record were missing.
- The deletion workflow's own scope disclosure, rendered directly. Removing
  `<DisclosureList items={disclosures} …>` from `deletion-workflows.tsx` fails
  both this test and the pre-existing disclosure test, so the property has
  teeth.
- The panel's conditional wiring is verified by reading the component:
  `exportPage` and `deletionPage` are rendered outside the
  `currentPolicy !== null` guard.

**Closing this properly needs a render-cycle test harness, which means adding
a DOM test dependency.** That is a deliberate decision for a follow-up, not
something to slip in at the end of a phase. It is named here rather than
papered over with a test that cannot fail.

## Known limitation: browser evidence is owed

**No P06 surface has been visually verified in a browser.** No desktop browser
is attached to this session — `browser.*` reports
`[browser.disconnected]` — and there is no headless fallback.

Each packet substituted `renderToStaticMarkup` assertions over the real
component tree, which is stronger evidence for the honesty requirements than a
screenshot would be, but it is not a substitute for the checks `AGENTS.md`
requires: desktop and narrow layout, keyboard focus order, focus-ring
visibility, and comparison against `docs/screens/`.

`docs/screens/` also has no reference for automations, webhooks, billing, or
data governance, so those panels were built from the density and tokens of
`runs-panel.tsx`. That is a gap in the screen library, not a finding against
the panels.

**This must be closed by a reviewer with the app running before P06 is
called done.**
