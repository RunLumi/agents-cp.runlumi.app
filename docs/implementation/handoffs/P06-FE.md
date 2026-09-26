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
- `GET /entitlements` reports `over_limit` rows with a real `current`, `limit`,
  and `over_by` — but **only for resources already above their limit**. There is
  no count for a resource that is within its limit, so the "Usage vs. plan
  limits" table shows a dash for those and says in its caption that a dash means
  "not published", never zero. Absence from `over_limit` *is* the server's
  statement that the resource is within limit, so the status column is honest
  even though the figure is not. If per-resource usage for in-limit resources is
  wanted on this page, that is a contract gap and needs a Change Request.
- The delivery projection carries **no attempt-level diagnostics**, because no
  frozen route returns attempt rows.

Two further gaps were found while reconciling this work against F22, and
neither would have surfaced as a failing test:

- **No UI anywhere can request an organization deletion.**
  `POST /orgs/{org_id}/deletion` requires the `org.lifecycle` permission plus
  reauthentication plus typed confirmation. Nothing in `apps/web` calls it. This
  panel accepts an `onRequestOrganizationDeletion` seam that no caller supplies,
  so it correctly tells the reader the request lives in organization settings —
  where no such control exists. Not a P06 defect: the route, the permission, and
  the reauth primitive are P02's, and F22 places the request outside a
  data-governance page. Recorded for P02/F02 in the plan rather than half-built
  here, because it is the most destructive action in the product and getting the
  confirmation flow subtly wrong is worse than not shipping it in this phase.
- **The export and deletion job tables are paginated but not filterable.**
  F22's FR-F22-004 also asks for URL-backed filters, sortable columns, and
  search. Both lists satisfy server pagination and none of the rest. The cursors
  are already server-side, so this is cheap to add if it is wanted.
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

## Screen references used

`AGENTS.md` requires opening the relevant images in `docs/screens/` before
frontend work and comparing the result against them. An earlier revision of
this handoff claimed `docs/screens/` held no reference for any of the four P06
surfaces. **That claim was wrong**, and it was the reason the information
architecture shipped wrong. `docs/screens/` contains 24 images; the relevant
ones were read and acted on.

### Directly relevant, and acted on

| Reference | What it decided |
| --- | --- |
| `docs/screens/lumi_export_history.webp` | Data & Retention is ONE page with four tabs — Retention policies, Export history, Data controls, Deletion requests — not four stacked surfaces. Breadcrumb `Lumi Workspace › Settings › Data & Retention › Export history`. |

The four-tab split also forced a division of labour that was previously
implicit. Retention policies owns the editor and the full 72-class registry
with each class's owner, window, legal maximum, export behavior, and
deletion behavior. **Data controls** owns what the platform is doing right
now: logging mode, legal-hold state, backup lifecycle, export artifact
lifetime, and upstream provider retention — read-only, because putting a
second editor on the same page would give an operator two places to change
one thing. The reference shows the tab but not its contents, so its content
was derived from the frozen policy fields and every consequence sentence is
quoted from the contract rather than authored as product copy.
| `docs/screens/lumi_plan_entitlements.webp` | Billing is a two-column card grid: Plan & entitlements beside Subscription state and Payment provider status, then Included capabilities beside Usage vs. plan limits. Breadcrumb `Settings › Billing plan and entitlements`. Four inputs are separated by card adjacency and per-card copy, not by a leading definition list. |

**`docs/specs/f22-web-control-plane-ux-information-architecture.md` outranks all
three.** Its information-architecture tree is explicit, and the navigation change
was made to match it:

```text
├── Automations
├── Integrations / MCP
└── Settings
    ├── General
    ├── Security / Identity
    ├── Credentials
    ├── Billing
    ├── Data / Retention
    └── Webhooks
```

All three P06 settings surfaces — billing, data retention, webhooks — are
Settings sub-pages, at `/org/{slug}/settings/{billing,data,webhooks,security}`.
`Integrations / MCP` is a **separate** top-level destination that this codebase
has no surface for yet, so there is no nav item claiming the name.

An earlier revision of this change got that wrong. It read
`lumi_billing_overview.webp`'s "Go to Integrations/MCP →" as placing the webhook
panel at the top level under that name. That link is about connecting a provider
billing account, which is an integration, not an outbound webhook. F22 settles
it, and `section-routing.test.ts` now encodes the tree so the same screenshot
cannot be misread a third time.

### Read for context, not copied

`lumi_account.webp` is the **personal** account surface with its own shell and
left rail (Profile / Security / Sessions & devices / Security activity). It is
not the organization Settings page, so it was not treated as one. It does
confirm the pattern that a settings area is a group with sub-navigation.

### No reference exists

**Automations and Integrations / MCP (webhooks) have no reference anywhere in
`docs/screens/`.** All 24 images are billing, account, rate-limit, models, or
budget screens. Those two panels were built from the density and tokens of
`runs-panel.tsx` and `policy-panel.tsx`. That is a gap in the screen library,
stated here rather than glossed, and it is a genuine one: it means the automations
and webhooks layouts have had no external check at all.

### Deviations from the references, and why

- **The org heading is kept.** The references' content pages open with a
  breadcrumb and go straight to the page `<h1>`, repeating neither the
  workspace nor the organization. The shell keeps its organization heading
  because it also carries the organization slug, its lifecycle state, and the
  contextual action button, none of which the breadcrumb can hold.
- **`Included capabilities` keeps its provenance columns.** The reference's
  table is `Capability | Included`. The shipped table adds the stable key and
  the precedence-chain layer that set each value. P06-CR-002 requires the
  attribution to be visible, and dropping it to match a two-column reference
  would have removed a frozen-contract requirement to satisfy a layout
  suggestion.
- **No plan marketing copy was invented.** The reference's Plan & entitlements
  card shows a plan name, a one-line tagline, and three feature bullets. The
  frozen contract has no plan catalog, so the shipped card shows the plan key
  and the plan's reach — entitlement key count and counted-limit count — and
  says nothing about who the plan is for.
- **The Settings sub-navigation is horizontal.** The reference's org Settings
  screenshots show no sub-nav on the billing page, and the personal account
  shell uses a left rail. A horizontal sub-nav inside the existing 232px
  organization sidebar was chosen over restructuring the main grid.
- **The reference nav is a later generation of the product IA** and was not
  adopted wholesale. It has no `Tools & approvals`, folds `Members` and `Teams`
  into one item, and renames `Policy` to `Audit Log`. F22 specifies the same
  tree, so those are genuine gaps against the spec rather than only against the
  screenshots — but all of them are P01–P05 surfaces and outside P06's write
  surface. The placements that concern P06's own surfaces were changed; the rest
  are recorded as follow-ups below.
- **F22's `Integrations / MCP` has no nav item.** No surface in this codebase
  is an MCP server list or a provider-connection page. `Tools & approvals` is
  the likely future occupant, but renaming or moving it is not P06's call, and
  pointing an empty item at nothing would be worse than omitting it.

## Known limitation: browser evidence is owed

**No P06 surface has been visually verified in a browser.** No desktop browser
is attached to this session — `browser.*` reports
`[browser.disconnected]` — and there is no headless fallback.

Each packet substituted `renderToStaticMarkup` assertions over the real
component tree, which is stronger evidence for the honesty requirements than a
screenshot would be, but it is not a substitute for the checks `AGENTS.md`
requires: desktop and narrow layout, keyboard focus order, and focus-ring
visibility.

The structural work in this revision was verified where the harness allows it:
the four-tab strip's ARIA wiring and ordering, the two-column card
composition, the settings sub-navigation, and the breadcrumb are all asserted
over the real component tree. The billing card's status derivation was moved
into a pure module (`usage-rows.ts`) specifically so it could be tested without
a DOM — `renderToStaticMarkup` cannot drive a container whose state comes from
an async read, and a status bug in "Usage vs. plan limits" would have been
invisible to any markup assertion. Injecting its worst bug (rendering `0` for a
resource the server never counted, which would state the workspace has consumed
nothing) fails two tests.

What remains genuinely unverified is pixel layout: the `lg:grid-cols-2` split
at narrow widths, whether the tab strip scrolls acceptably on a phone, and
whether focus rings are visible against every surface they can land on. None of
that can be asserted without a browser.

**This must be closed by a reviewer with the app running before P06 is
called done.**
