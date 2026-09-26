# Integration Gate — P07-IG

## Goal

Prove the phase works as one real vertical slice, not as isolated merged modules.

**Exit decision: PASS WITH FOLLOW-UP.** The follow-ups are named below and none
is security-critical, tenant-isolation-critical, data-loss-critical, or
contract-breaking, so the template's bar for a plain PASS is met. What is missing
is a browser and a running Worker, not a property.

## Preconditions

- [x] required packets merged — MOD 01..04, BE 02/03/04, FE 01/02/03, INT 01/02,
      QA 01; MOD-01 and BE-01 deliberately not built (F06 frozen)
- [x] contract version is current — `p07-cg-v1`, no Change Request
- [x] migrations applied in test environment — `0016`→`0018` applied in order by
      the schema harness against the real DDL
- [x] no known contract drift — the frozen fixture is consumed by both languages
- [x] shared-file owner confirms integration branch/main is coherent — 22 P07
      routes mounted in `app.rs`; no other phase's file was edited

## Vertical slice

The permission-expansion refusal, end to end. It is the slice that matters
because it is the one P07 exists to make possible, and because every layer of it
is load-bearing.

```text
client (Settings → Plugins → permission diff, or LumiAgents reporting a host)
→ API  (POST /api/v1/orgs/{org_id}/plugins/{package_id}/install)
→ auth/policy  (authorize_org with plugins.manage; ApiKeyScope for a machine)
→ domain logic  (PluginFacts::install_decision → PluginDecision::Deny(PermissionExpanded))
                (diff() → eight ClassDiff rows; expands = any class grew)
→ persistence   (ONE D1 batch: install review state → pending_review,
                 pending_review_version = candidate, review_reason = "<event id> <summary json>")
                 + the audit/security event, best effort so a failed audit
                   cannot turn a correct denial into a success)
→ audit/event   (plugin.permission_expansion_detected, with the same class list)
→ user-visible  (the org sees a version that is neither installed nor allowed,
                 and WHY: "widens the plugin's declared capability in 1 class:
                 Tools. It is not installed, and nothing about it runs until you
                 approve it deliberately.")
```

The three things this slice proves that no layer proves alone:

1. **A refusal is one write, not two.** The install review state and the policy
   block list move in the same batch on block/unblock. A reader who only looks
   at `plugin_installs` will believe there is a window.
2. **The reason an operator reads is the reason the audit event carries.** They
   are the same `policy_diff_summary`, asserted to be byte-identical, because a
   reviewer who jumps from the UI to the audit view must not see two
   renderings of one decision.
3. **The browser names the class that grew.** The server stores a stable code
   plus a payload; the client reads both. Before this phase it compared the whole
   string to the bare code — which the server never writes — so every real
   expansion rendered as a raw event id and a JSON blob.

## Scenarios

### Happy path

1. An org admin opens Settings → Plugins, sees the installed set, and reads a
   permission diff that reports `tools: added [pkg_write]`,
   `network_destinations: removed [...]`, `expands: true`.
2. They install `1.1.0`. Managed mode detects the expansion, records the
   candidate and the reason, installs nothing, and returns
   `plugin_permission_expanded`.
3. The list shows the installed `1.0.0` as **Pending review** with
   `pending_review_version: 1.1.0` and the reason naming `Tools`. `registered_tools`
   still lists `pkg_read`; `unregistered_tools` lists `pkg_write`.
4. They approve deliberately. `1.1.0` becomes installed. `pkg_write` is **still
   denied** by F13 default-deny until a `PluginToolRegistration` exists — and the
   UI shows that as an unusable tool rather than hiding it.

### Permission/tenant negative path

1. A key scoped to `runs.read` calls a route needing `runs.write` →
   `machine_permission_denied`. Proven by
   `a_key_cannot_act_on_another_organization` and the scope tests.
2. A key for org A acts on org B's resource → `resource_scope_mismatch`.
3. A key whose request carries one of the five human-only permissions is refused
   **before** scope is consulted, with `capability_human_only` — a distinct code
   from `capability_unknown`, so a client can tell "you may not hold that" from
   "that does not exist".
4. An org admin grants `org.lifecycle` to a service account → refused.
5. A support grant is issued for org A and presented for org B →
   `support_grant_organization_mismatch`, a third code distinct from expired and
   revoked. All three proven in-database: a grant issued for another
   organization is not returned for this one.
6. Org A blocks a package. Org B, which has the same package installed and
   approved, is unaffected, in both the policy and the install row. Proven
   in-database, and the cases fail if the `org_id` predicate is removed.
7. A wildcard in a grant's capabilities → `PermissionDenied`, not
   `ValidationFailed`. A wildcard support grant is a standing superuser pass.
8. `/api/v1/internal/*` is unreachable with an org session or an API key. There is
   no conversion in either direction between `StaffRole` and `MembershipRole`, so
   this is a compile-time fact (ADR 0007).

### Dependency failure path

1. A support grant whose TTL elapsed an hour ago is refused on **this** request.
   Expiry is evaluated per request, never once at creation.
2. A revoked grant is refused with a different code, because "expired" and
   "revoked" are different conversations with the person holding it.
3. A feature flag past its expiry resolves `off` and reports `expired` — checked
   **before** the enabled flag, so an operator is told why rather than guessing.
4. A kill switch past its expiry reports `Expired`, not `NotEngaged`; a lifted one
   reports `Lifted`. All three differ, and all three are asserted.
5. A D1 failure returns `ServiceUnavailable` and never a partial write. A failed
   audit event on the expansion path is deliberately swallowed so it cannot turn
   a correct denial into a success — the denial is returned either way.

### Retry/idempotency/concurrency path

1. Rotation creates the replacement **before** marking the prior key rotated, and
   both writes are in one batch. There is no instant in which the org has no
   working key. Proven in-database: a revoked or rotated key cannot be
   reactivated, and a revocation's reason cannot be blanked afterwards.
2. Every mutating route takes a `version` and an idempotency key; a stale version
   is `version_conflict` rather than a lost update.
3. A policy PATCH and the block/unblock it accompanies are one batch, via
   `extra_write: Option<D1PreparedStatement>`. Two statements would be a window.
4. A repeated request is refused rather than duplicated — the P06 idempotency
   record, reused. P07 adds no second queue entry point.

## Evidence

- **tests:** 848 Rust tests, 720 web tests across 43 files, 97/97 storage
  invariants. `pnpm check` exits 0.
- **screenshots:** none. No browser is attached to this session. This is the
  single largest gap in this gate and it is stated rather than worked around.
- **request IDs:** none. No end-to-end request was made against a running Worker;
  the slice is proven at the domain, projection, and database layers and by
  `pnpm build`'s dry run.
- **metrics/performance:** initial JS **100.1 KiB gzip** (budget 170), initial CSS
  **8.7 KiB gzip** (budget 35), new route chunks **16.6 KiB** (`identity-panel`)
  and **16.7 KiB** (`plugins-panel`) against an 80 KiB budget. No new dependency.
  Worker dry run succeeds.
- **migration/rollback proof:** `0017` and `0018` create new tables and alter no
  P02–P06 table, so rollback is dropping the new tables with no pre-P07 data at
  risk. Forward-only, stated in both handoffs.

## Required gates

- [x] `pnpm check`
- [x] `pnpm build`
- [x] Rust WASM target check
- [x] Worker dry run
- [x] relevant spec acceptance criteria — F14, F24-007, F25 traced in
      `P07-QA-01.md`; F06 frozen by the gate's decision 3
- [x] cross-tenant negative tests — 5 new in-database cases, each written so it
      fails without its `org_id` predicate
- [x] secret/log review — no read projection has a parameter or field a secret
      could occupy; no secret in `localStorage`, `sessionStorage`, a cookie, the
      URL, or a log
- [ ] **keyboard/focus/loading/error review for UI — NOT DONE.** No browser. The
      FE agent found and fixed a keyboard trap (roving tabindex with no arrow-key
      handling) during development, and the async states are covered by unit
      tests, but nothing has been rendered.
- [x] rollback/migration strategy
- [x] performance budget reviewed

## Defects this gate found

Six, each found by a test rather than by review. All are fixed.

1. **The plugin detail page would have rendered nothing.** `install_json` omitted
   `blocked_reason`, which `decodeInstall` *requires*; the detail decoder then
   returned `undefined`. No error anywhere — just a blank page. The two halves of
   a wire contract have no shared compiler, so the frozen fixture is now what
   holds them together: the Rust side pins its key set to it, the TS side decodes
   it and requires an exact match.
2. **A documented manifest form was unusable.** `rejects_destination` split on
   `://` first, and a `*.suffix` pattern has no scheme, so every wildcard
   destination was classified as unparseable and the whole plugin report was
   refused — for a form the field's own documentation promises. The suffix is now
   the host that gets evaluated, and a pattern rooted at a private or loopback
   name is refused the same way an exact literal is.
3. **The expansion refusal rendered as a code and a JSON blob.**
   `pendingReviewReason` compared the stored reason to the bare event id, which
   the server never writes. Every real expansion fell through to the generic
   branch. The prefix is matched and the payload read, so the reviewer is told
   which class grew.
4. **The four P07 permissions were in `Permission` but not in `role_allows`,** so
   only Owner had them. Pinned now by
   `p07_roles_keep_credential_and_plugin_authority_separate`.
5. **`block` wrote its reason only to the audit event.**
   `plugin_installs.blocked_reason` existed and was never written — a column
   nobody read, for the one fact an operator most needs. Block and unblock now
   move the review state and the policy block list in one batch.
6. **The schema harness ran only by hand.** Dependency-free, 0.26s, and the
   repository's CI gate for the 97 storage invariants. It is now in `pnpm test`.

## Exit decision

- **PASS WITH FOLLOW-UP**

Named follow-ups, none of them security-, isolation-, data-loss-, or
contract-critical:

1. A browser pass over both Settings sub-pages at desktop and narrow widths,
   with keyboard focus and async states. P06 carries the same debt.
2. A local-D1 vertical slice with recorded request IDs, replacing this gate's
   layer-by-layer evidence with an end-to-end transcript.
3. The LumiAgents-side implementation of `POST /plugin-reports` and
   `GET /api/v1/machine/whoami`.
4. A policy decision on whether suspicious-but-legal hostnames such as
   `metadata.google.internal` should be refused. The current behaviour is
   deliberate and asserted, not an oversight.

Deliberately not built, per the gate: F06 (SSO/SCIM/domains) and the internal
operations console. Both are frozen in full, so implementing either is mechanical
rather than a fresh design exercise.
