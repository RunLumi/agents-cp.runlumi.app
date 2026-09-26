# Contract Gate — P07-CG

- Phase: P07 — Enterprise identity, machine identity, internal admin, plugins
- Owner: P07 coordinator
- State: **frozen**
- Contract version: `p07-cg-v1`
- Inputs: Plan00, Plan07, F06, F14, F24, F25, ADR 0001–0007, P02-CG, P05-CG, P06-CG, and current ZCode plugin/MCP source semantics
- Preconditions: P06 is merged with all six Integration Gate claims passing; P06's recorded limitations (no downgrade-preview route, no count for an in-limit resource, no attempt-level delivery diagnostics) remain explicit and are not redefined here
- Shared-file owner: P07 coordinator
- Related ADRs: ADR 0007 (three actor kinds and three authorization boundaries) is normative for §3

## Purpose and boundaries

P07 adds enterprise and platform-operations capability without contaminating the
simple org core. The shape is:

```text
human org operator ──► Principal ──► authorize()       ──► MembershipRole
machine caller      ──► MachineActor ──► authorize_machine() ──► ApiKey scope
internal staff      ──► StaffActor  ──► authorize_staff()   ──► StaffRole + SupportGrant
```

Everything below the first line is new. P02's `Principal` and `authorize()` are
unchanged; see §3 and ADR 0007 for why that separation is structural rather
than conventional.

### Scope actually implemented, and why

Plan07 sets P07 priority as "only execute full scope when product/customer
demand justifies it". This gate freezes the full contract and implements the
part with a demand signal in this repository. The split is deliberate and is
recorded here so a later reader does not mistake an omission for an oversight.

| Area | Spec priority | Decision | Demand evidence |
|---|---|---|---|
| F14 machine identity | P1 | **Implement** | F14's objective is CI/integrations/runners calling the control plane without a human. Today no machine can call any of the 48 P06 routes except by borrowing a human session cookie, which misattributes audit and is unusable headless. P07-INT-02 exists for exactly this. |
| F25 plugin governance | P1 | **Implement** | P05 already persists tool/MCP `source IN ('built_in','plugin','custom')`, so the source concept exists with no governance above it. F25's acceptance criterion "a plugin update cannot silently gain network/secret/tool capability" has **no owner today**, and F13's default-deny is silently violated by any install that adds a tool. |
| F24-007 kill switches | P1 | **Implement** | P05/P06 just shipped managed execution, plugin-capable tools, platform inference routes, and off-peak automation. F24-007 names exactly those. There is currently no reversible off-switch for any of them, so a bad plugin or route has no lever. This is the highest safety value in the phase. |
| F24-001..003, 008 staff + support grants | P1 | **Freeze contract; boundary implemented, console deferred** | No support-ticket volume exists yet, so a support console is speculative. But F24's thesis is "operate safely without creating a privileged backdoor that is hard to audit", so the *boundary* and the audit invariants are implemented and proven. A support console is a UI over a route that already refuses to impersonate. |
| F06 domains / SSO / SCIM | **P2** | **Freeze contract; no implementation** | F06 states its own purpose as "enterprise identity controls without making them prerequisites for SMB/org MVP" and is priority P2. P06 already seeded `sso.enabled` and `scim.enabled` entitlement keys defaulting to `false`, so the gating seam exists. There is no customer demand signal in this repository. Building SAML/OIDC/SCIM speculatively is precisely the "enterprise checkboxes as mandatory MVP complexity" Plan07 warns against. |

F06 is frozen in full (§9) so that implementing it later is a mechanical
consequence of this document rather than a fresh design exercise. Its
entitlement keys already exist, so the extension seam is complete and requires
no P07 schema to be useful later.

**This gate does not add browser permissions for unimplemented features.**
Following the P06-CR-002 precedent — entitlement overrides have no permission and
no public route because they are internal-only — F06's `identity.read` /
`identity.manage` are named in §11 as *reserved* and are not added to
`Permission` until F06 is implemented.

## Actor and authorization boundary contract

Normative, and the load-bearing decision of this phase. ADR 0007 records the
reasoning; this section is the contract.

- `core::Principal` is unchanged. It is created only by
  `http::auth::require_session` from a live session row, and it gains no "kind"
  field.
- `modules::authorization::authorize` is unchanged. Every existing route keeps
  calling it with `Option<&Principal>`.
- A machine or staff caller therefore **cannot** reach a route that only calls
  `authorize`. Adding a machine path to an existing route is a visible change,
  not a side effect of a smarter auth middleware.
- `core::machine::MachineActor` and `core::staff::StaffActor` are separate types
  with separate credential resolution (`require_machine`, `require_staff`) and
  separate decision functions (`authorize_machine`, `authorize_staff`).

### Machine authority is a scope, never a role

F14-001: a service account "MUST NOT inherit an owner's permissions implicitly".
`authorize_machine` resolves the `ApiKey`'s own scope set. There is no
expression that converts an `ApiKeyScope` into a `MembershipRole`, so the
prohibition is a compile-time fact rather than a review rule.

A key's scope names capabilities using the **existing `Permission` vocabulary**,
so a machine's authority is expressed in the same language as a human's but
resolved by a different function. This avoids inventing a second permission
namespace that could drift from the first.

### Human-only permissions

F14-007: machine identities cannot perform human-only actions "unless explicitly
designed and strongly justified". No such justification exists in P07, so the
following are structurally unavailable to every machine credential:

| Permission | Why it is human-only |
|---|---|
| `org.ownership_transfer` | F14-007 names it explicitly. Irreversible and changes who can delete the organization. |
| `org.lifecycle` | Suspends or deletes an organization. A CI credential that can do this is a single-token catastrophic blast radius. |
| `org.leave` | Meaningless without a human. |
| `billing.manage` | Plan change and cancellation are commercial acts with contractual consequence. |
| `data.delete` | F20 deletion is irreversible. F20's honesty requirements assume a human who can read the consequences copy. |

`authorize_machine` denies with `human_only_action` **before** consulting scope,
so an API key cannot request one of these and have the request merely stored.

### Staff authority is a separate role and permission set

`StaffRole` and `StaffPermission` are distinct enums. Neither converts to the
other. A `MembershipRole` of `Admin` confers **no** platform authority, and a
`StaffRole` confers **no** organization authority.

Frozen `StaffRole` set (F24-002 asks for these to be distinct):

| StaffRole | Purpose |
|---|---|
| `support` | Customer support diagnostics under an explicit grant. |
| `finance` | Subscription/entitlement and usage inspection. |
| `security` | Abuse flags, incident response, quarantine. |
| `engineering` | Route/provider health. No customer-content access by default. |

Frozen `StaffPermission` set, grouped by the role that holds it:

```text
support    → org.lookup, org.subscription.read, org.devices.read,
             org.sessions.read, support_grant.use
finance    → org.lookup, org.subscription.read, usage.read
security   → org.lookup, abuse.flag.read, abuse.flag.write,
             plugin.quarantine, kill_switch.read, kill_switch.operate
engineering→ org.lookup, routes.health.read, feature_flag.read
all staff  → support_grant.create, support_grant.revoke,
             feature_flag.manage, kill_switch.read
```

Adding a `StaffRole` without a corresponding `StaffPermission` set is a contract
change, not an implementation detail.

### Support grant requirements

F24-003 and F24-008. A `SupportGrant` requires all of: named staff principal,
reason/ticket reference, bounded TTL, target organization, and an explicit
capability subset. It is checked on **every** request that relies on it, not
only at creation.

Default staff mode is metadata and support diagnostics, **never impersonation**.
There is no route in P07 that creates a session, cookie, or API key on behalf of
a customer user. A staff actor resolving to a customer `Principal` is a contract
violation, not a feature.

## Domain vocabulary

| Concept | Stable name | Meaning |
|---|---|---|
| Service account | `ServiceAccount` | Org-owned non-human account with an explicit capability set. Never has a `MembershipRole`. |
| API key | `ApiKey` | One credential belonging to exactly one `ServiceAccount`. Shown once, stored hashed. |
| Key scope | `ApiKeyScope` | The credential's authority: project set, capability allowlist, model aliases, expiry, optional network allowlist. |
| Key fingerprint | `ApiKeyFingerprint` | Truncated hash of the presented key, for identification without revealing it. |
| Plugin package | `PluginPackage` | Stable plugin identity, separate from display name and version (F25-001). |
| Plugin version | `PluginVersion` | One immutable published version with a runtime compatibility range and integrity metadata. |
| Permission manifest | `PluginPermissionManifest` | The capability set a version declares (F25-002). |
| Plugin install | `PluginInstall` | One org's installation of one package at one version, with a review state. |
| Plugin policy | `PluginPolicy` | One org's allow/block/pin/auto-update rules (F25-004). |
| Permission diff | `PluginPermissionDiff` | Version-to-version expansion/contraction of the manifest. |
| Tool registration | `PluginToolRegistration` | Approved binding of `package + version + tool` to an org (F25-007). |
| Review state | `PluginReviewState` | `unreviewed` / `approved` / `pending_review` / `blocked` / `quarantined`. |
| Staff principal | `StaffPrincipal` | Named internal identity. Distinct from any customer user (F24-001). |
| Staff role | `StaffRole` | Platform authority level. See §3. |
| Support grant | `SupportGrant` | Time-bounded, reasoned, audited access to one customer organization. |
| Feature flag | `FeatureFlag` | Rollout control: off/on, percentage, org allowlist, cohort, expiry, owner (F24-006). |
| Kill switch | `KillSwitch` | Narrow, reversible, audited off-switch for one capability class (F24-007). |
| Domain verification | `DomainVerification` | **Frozen, not implemented.** Proof of domain control. Never confers membership. |
| SSO connection | `SsoConnection` | **Frozen, not implemented.** IdP metadata and enforcement policy. |
| SCIM config | `ScimConfig` | **Frozen, not implemented.** Provisioning token and mapping. |

## Machine identity contract

### ServiceAccount

- Belongs to exactly one organization. `org_id` is server-resolved from the
  authenticated actor for creation and is never accepted from the request body.
- Carries an explicit `capabilities` allowlist. There is no wildcard and no
  "inherit from creator".
- `status`: `active` / `suspended`. A suspended account denies every capability
  with `machine_key_suspended`, including a key that has not yet expired.
- Every service account is created by, and attributable to, a human principal
  (`created_by_principal`). A machine may not create a service account.
- Max 50 active service accounts per organization, max 5 active keys per
  account. Bounded so the list surface stays paginated and so one tenant cannot
  turn the table into a credential farm.

### ApiKey

Wire format:

```text
lumik_<12 lowercase hex public prefix>_<43 base64url secret>
```

- The prefix is **not** a secret. It is the lookup key and is shown in the UI so
  a human can identify a key without seeing it.
- The secret is 256 bits from the platform CSPRNG. It is returned exactly once,
  in the creation response, and never again.
- Persisted: `key_prefix` (unique), `secret_hash` (SHA-256 hex of the secret
  part), `fingerprint`, and metadata. **The raw key is never persisted.** A
  compromise of the `api_keys` table alone yields no usable credential (F14
  acceptance criterion).
- Verification is constant-time on the hash, matching the existing session path.
- `status`: `active` / `revoked` / `rotated` / `expired`. `revoked` and `expired`
  are terminal.

### Rotation

F14-004: rotation creates an **overlapping** replacement and only then revokes
the prior key.

- `POST /api-keys/{key_id}/rotate` creates a new key on the same service account
  with the same scope and a fresh `rotated_from_key_id`, and marks the prior key
  `rotated` in the same transaction.
- The prior key stops working only after the replacement exists. A failed
  rotation leaves both keys untouched.
- The replacement's secret is returned once, in the rotation response.

### Last-used metadata

F14-005. `last_used_at` and a bounded `last_used_source` (derived network prefix
or device slug, never a request payload, header bag, or URL with query string).
No request body, path parameter value, or header is stored.

### Network restrictions

F14-003 says "optional IP/network restrictions **where reliable**". Cloudflare
Workers see the client IP in `CF-Connecting-IP`, which is reliable at the edge
but is trivially wrong in local development and behind a misconfigured proxy.
Therefore:

- The allowlist is **stored and enforced** when present.
- When the edge IP is unavailable, a key with a network allowlist **denies** with
  `scope_network_unavailable` rather than allowing. Failing open here would make
  the control decorative.

This is the one F14-003 item that is deliberately pessimistic, and it is
recorded here because "where reliable" is doing real work in that sentence.

### Authenticated machine request

```http
Authorization: Bearer lumik_<prefix>_<secret>
```

The `lumik_` scheme is disjoint from the human session bearer and from the
staff scheme, so a machine key can never be parsed as a session or as a staff
credential. Presentation of a `lumi_staff_` token on an org route is
`machine_key_invalid`, not a staff error — a staff credential on a customer
route is a boundary violation and is reported as such.

## Plugin governance contract

### PluginPackage

- `package_id` is stable and **independent of display name and version**
  (F25-001). Renaming a plugin never changes its identity and never orphans its
  installs or org policy.
- `publisher_id` identifies the publisher. Org policy may allowlist publishers.

### PluginVersion

- Immutable once published. A published version is never edited; a change is a
  new version.
- `runtime_compatibility` is a bounded range on the host agent version. A version
  whose range excludes the reporting host **cannot be installed** (deny
  `plugin_incompatible`).
- Integrity metadata: publisher signature plus content digest, carried in the
  trusted distribution manifest (F25-005). Lumi verifies the digest before
  recording an install; a mismatch denies `plugin_integrity_failed` and is
  audited as a security event.

### PluginPermissionManifest

The declared capability set. Every field is a closed, finite set — no
wildcards, matching the P06 webhook-subscription precedent.

| Class | Field | Rule |
|---|---|---|
| Tools | `tools[]` | `plugin + version + tool` stable identities. A tool absent from the manifest is not available to the plugin. |
| MCP servers | `mcp_servers[]` | Named servers the version starts. |
| Network | `network_destinations[]` | Exact `scheme://host[:port]` or a `*.suffix` pattern. Private/loopback/link-local ranges are rejected at report time. |
| Filesystem | `filesystem_scopes[]` | Path prefixes. A path outside every scope is denied. |
| Process | `process_spawn` | Boolean. Default `false`. |
| Secrets | `secret_handles[]` | `(handle, declared_purpose)` pairs only (F25-006). A plugin can never enumerate organization credentials. |
| Browser | `browser_capability` | `none` / `read` / `interact` / `computer_use`. |
| External data | `external_data_handling` | `none` / `declared`. |

### PluginPermissionDiff

Computed between an installed version's manifest and a candidate version's
manifest. Each class is one of `added` / `removed` / `unchanged`, and the diff
carries an overall `expands: bool`.

**Expansion in any class is expansion.** A version that adds a tool, widens a
network destination, adds a secret handle, or raises `browser_capability` from
`read` to `computer_use` is an expansion even if it removes something else.

### Managed-mode approval (F25-003)

`PluginPolicy.update_mode` is `managed` or `direct`.

- `managed` + `expands == true` → install is **refused** and the install enters
  `pending_review` with `plugin.permission_expansion_detected.v1` written. It
  does not install and wait quietly; it installs nothing.
- `managed` + `expands == false` → installs on approval of the version, no
  re-review needed.
- `direct` → auto-update permitted, and the expansion is still audited.

### Org policy (F25-004)

```text
publisher_mode        = official_only | approved_publishers | any
approved_publishers   = [publisher_id]
allowed_packages      = [package_id]
blocked_packages      = [package_id]
pinned_versions       = { package_id: version }
auto_update           = on | off
update_mode           = managed | direct
```

- `blocked_packages` **wins over** `allowed_packages`. A package on both lists is
  blocked, and the state is reported as a policy conflict rather than silently
  resolved.
- A pin is exact. A pinned package cannot update to any other version, including
  a security update; lifting the pin is an explicit, audited `plugins.manage`
  action. This is deliberate — a silent auto-patch would defeat the pin.
- Org policy is a **customer** control. Platform quarantine (§7) is not.

### Revocation and quarantine (F25-008)

- `blocked` is an org decision: new installs and new executions deny.
- `quarantined` is a **platform** decision against a specific
  `package@version`, applied by `plugin.quarantine` (security staff). It denies
  new executions for that exact version.
- A quarantine does **not** delete the artifact from disk. A managed
  organization must not be able to execute a quarantined version even if the
  files are still present, which is the F25 acceptance criterion. The
  deny decision is server-side and authoritative; on-disk presence is irrelevant
  to it.
- In-flight runs started before a quarantine **finish** under the policy they
  started with. New invocations deny. This matches the P06 lease/`ambiguous`
  precedent: a decision that cannot be applied to work already in flight is not
  applied to it after the fact.

### Tool registration and default deny (F25-007)

- A tool is usable by an org only when a `PluginToolRegistration` exists for
  `(package_id, version, tool_id)` and the org policy permits the package.
- A tool present in a manifest but with no registration **denies** with
  `plugin_tool_unregistered`. This is F13's default-deny, and it is the specific
  control that an install can no longer bypass.

## Feature flags and kill switches

### FeatureFlag (F24-006)

```text
flag_key, enabled, rollout_percentage (0..100),
org_allowlist, cohort (user | device | none),
expires_at, owner_staff_principal_id, updated_by, version
```

- Resolution is a fixed order: `expires_at` in the past → off; org allowlist
  hit → on; percentage rollout → stable hash of the org ID against the
  percentage; otherwise off.
- **The percentage must be stable for an org.** It is a hash of the org ID, not
  a random draw per request, or a tenant would flicker in and out of a cohort.
- F24-006 says "avoid using flags as permanent configuration store". Therefore
  `expires_at` is **required** on every flag, and an expired flag resolves off
  and is reported as expired rather than silently ignored.
- Flags are not a plan entitlement. P06 owns entitlements; a flag is a rollout
  lever, not a commercial grant. A flag may not grant a capability that the
  entitlement projection denies.

### KillSwitch (F24-007)

```text
target_class = inference_provider | model_route | mcp_server
             | plugin_version | computer_use | client_version
target_ref   = provider id | route id | server id | package@version
                        | integration name | version range
scope        = global | organization
organization_id (nullable, required when scope = organization)
reason, engaged_by_staff_principal_id, engaged_at, expires_at (nullable)
state        = engaged | lifted
```

- F24 acceptance: "Feature rollback can target one org/provider before global
  disable." Therefore `scope = organization` is a first-class target and is
  checked **before** `scope = global`.
- Narrow by construction: a kill switch names exactly one `target_class` and one
  `target_ref`. There is no "disable all plugins" or "disable everything for
  this tenant" form. F24-007 calls switches "narrow" and the goal states they
  are "narrow, reversible, and audited".
- Engaged is reversible. `lift` requires a reason and is audited as its own
  event; the engage is never deleted.
- An **expired** kill switch resolves to *not engaged* and is reported as
  expired. A safety control that silently stops applying is worse than none, so
  expiry requires re-engagement to continue, and expiry is visible in the
  response.
- Kill switches are **not** `StaffPermission`-reachable from a customer role and
  are not modelled as an org policy a customer can set.

## Enterprise identity contract — frozen, not implemented

Recorded in full so implementing F06 later is mechanical. **No P07 code, route,
table, or permission implements any of this.**

- `DomainVerification`: org adds a domain and proves control by DNS TXT. A
  verified domain is a **fact about the domain**, never a membership grant.
  F06-001 and F06's acceptance criterion are explicit that domain verification
  does not itself create memberships, and F06-004 puts JIT behind an explicit
  setting that is **off by default**.
- `SsoConnection`: one active primary connection is the MVP enterprise path
  (F06-002 explicitly permits limiting to one). IdP private secrets never reach
  the browser. Enforcement applies to members and **must** ship with a documented
  owner recovery path protected by strong verification (F06-003).
- `ScimConfig`: a P2 endpoint set for users/groups. Deactivation **suspends**
  membership and never deletes user identity or immutable audit history
  (F06-005). Account linking requires a safe verified flow; matching on an
  unverified email is insufficient (F06-006).
- Gating: `sso.enabled` and `scim.enabled` entitlement keys already exist
  (P06 baseline) and default to `false`. F06 routes must check them server-side.

When F06 is scheduled, this section plus the existing entitlement keys are the
entire design input. That is what "coherent extension seam" has to mean.

## API contract

All org routes are nested under the organization and use the P01 idempotency
scope `(principal, organization, method, path, key_digest)`. PATCH/DELETE
transitions also require the current `version` and return `409 version_conflict`
on a stale write.

### Machine identity

| Method | Path | Permission | Request | Response | Errors |
|---|---|---|---|---|---|
| GET | `/orgs/{org_id}/service-accounts` | `service_accounts.read` | — | cursor page of accounts | |
| POST | `/orgs/{org_id}/service-accounts` | `service_accounts.manage` | `{name, description?, capabilities[], expires_at?}` | `201` account | `capability_unknown`, `capability_human_only` |
| GET | `/orgs/{org_id}/service-accounts/{service_account_id}` | `service_accounts.read` | — | account | |
| PATCH | `/orgs/{org_id}/service-accounts/{service_account_id}` | `service_accounts.manage` | `{version, name?, description?, capabilities?}` | account | `version_conflict` |
| POST | `/orgs/{org_id}/service-accounts/{service_account_id}/suspend` | `service_accounts.manage` | `{version, reason}` | account | `version_conflict` |
| POST | `/orgs/{org_id}/service-accounts/{service_account_id}/resume` | `service_accounts.manage` | `{version}` | account | `version_conflict` |
| GET | `/orgs/{org_id}/api-keys` | `service_accounts.read` | — | cursor page of keys, **no secret** | |
| POST | `/orgs/{org_id}/api-keys` | `service_accounts.manage` | `{service_account_id, name, scope}` | `201` key **with secret, once** | `scope_capability_unknown`, `key_limit_reached` |
| GET | `/api-keys/{api_key_id}` | `service_accounts.read` | — | key metadata, no secret | |
| POST | `/api-keys/{api_key_id}/rotate` | `service_accounts.manage` | `{reason}` | replacement key **with secret, once** | `key_terminal` |
| POST | `/api-keys/{api_key_id}/revoke` | `service_accounts.manage` | `{version, reason}` | key | `version_conflict` |

`{api_key_id}` routes resolve the organization **from the key row**, never from
the request. A client-supplied `org_id` is never authorization evidence.

### Plugin governance

| Method | Path | Permission | Request | Response | Errors |
|---|---|---|---|---|---|
| GET | `/orgs/{org_id}/plugins` | `plugins.read` | — | installed + available + review states | |
| GET | `/orgs/{org_id}/plugins/policy` | `plugins.read` | — | `PluginPolicy` | |
| PATCH | `/orgs/{org_id}/plugins/policy` | `plugins.manage` | `{version, …policy fields}` | `PluginPolicy` | `policy_conflict`, `version_conflict` |
| GET | `/orgs/{org_id}/plugins/{package_id}` | `plugins.read` | — | package, versions, install state | |
| POST | `/orgs/{org_id}/plugins/{package_id}/install` | `plugins.manage` | `{version, request_id}` | install | `plugin_blocked`, `plugin_quarantined`, `plugin_permission_expanded`, `plugin_incompatible`, `plugin_integrity_failed`, `plugin_pinned` |
| POST | `/orgs/{org_id}/plugins/{package_id}/approve` | `plugins.manage` | `{version, request_id}` | install in `approved` | `version_not_pending_review` |
| POST | `/orgs/{org_id}/plugins/{package_id}/block` | `plugins.manage` | `{version, reason}` | policy | |
| POST | `/orgs/{org_id}/plugins/{package_id}/unblock` | `plugins.manage` | `{version, reason}` | policy | |
| POST | `/orgs/{org_id}/plugins/{package_id}/pin` | `plugins.manage` | `{version, reason}` | policy | `plugin_pinned_conflict` |
| GET | `/orgs/{org_id}/plugins/{package_id}/versions/{version}/permission-diff` | `plugins.read` | `?against_version=` | `PluginPermissionDiff` | |
| POST | `/orgs/{org_id}/plugin-reports` | `plugins.manage` | host agent manifest report | accepted + policy verdict | `manifest_invalid`, `manifest_digest_mismatch` |

`/plugin-reports` is the P07-INT-01 seam: LumiAgents reports what it actually
has installed, and the server answers with the policy verdict. The **server**
decides; the report is evidence, never authority.

### Platform operations (staff boundary)

Separate path prefix, separate credential scheme, separate role and permission
sets. None of these is reachable with an org session or an API key.

| Method | Path | StaffPermission | Request | Response | Errors |
|---|---|---|---|---|---|
| GET | `/internal/feature-flags` | `feature_flag.read` | — | flags | |
| POST | `/internal/feature-flags` | `feature_flag.manage` | `{flag_key, …}` | flag | `flag_expires_required` |
| PATCH | `/internal/feature-flags/{flag_key}` | `feature_flag.manage` | `{version, …}` | flag | `version_conflict` |
| GET | `/internal/kill-switches` | `kill_switch.read` | — | switches | |
| POST | `/internal/kill-switches` | `kill_switch.operate` | `{target_class, target_ref, scope, organization_id?, reason, expires_at?}` | switch | `kill_switch_target_unknown`, `kill_switch_too_broad` |
| POST | `/internal/kill-switches/{kill_switch_id}/lift` | `kill_switch.operate` | `{version, reason}` | switch | `version_conflict` |
| GET | `/internal/support-grants` | `support_grant.revoke` | — | grants | |
| POST | `/internal/support-grants` | `support_grant.create` | `{organization_id, reason, ticket_reference, ttl_seconds, capabilities[]}` | grant | `support_grant_reason_required`, `support_grant_ttl_invalid` |
| POST | `/internal/support-grants/{grant_id}/revoke` | `support_grant.revoke` | `{version, reason}` | grant | `version_conflict` |

Support grants are created and revoked in P07; **no route consumes one**. The
grant is the frozen boundary that a future support console must satisfy, and
F24-003's "default mode is metadata/support diagnostics, not impersonation" is
enforced by the absence of any impersonation route rather than by a flag.

### Web information architecture

F22 is authoritative for the organization tree, and its Settings group is:

```text
└── Settings
    ├── General
    ├── Security / Identity
    ├── Credentials
    ├── Billing
    ├── Data / Retention
    └── Webhooks
```

**F22's tree has no place for either P07 surface, and that is a spec gap rather
than a licence to invent a location.** F25 requires a plugin governance surface
(installed plugins, catalog, permission diff, pin, blocked reason, usage) and F14
requires a machine-identity surface (service-account list, permission preview,
one-time key reveal, rotate/revoke, last-used). Neither appears in F22's tree,
and `Credentials` in F22 means model provider credentials under F11, not API
keys under F14.

P07 therefore adds two Settings sub-pages and records the deviation:

| P07 sub-page | Contains | Why here |
|---|---|---|
| `Identity & access` | Service accounts, API keys | Organization configuration that a human admin manages. F22's `Security / Identity` is about human sign-in and SSO, which P07 does not implement (F06 is frozen only), so reusing that name would promise an SSO surface that does not exist. |
| `Plugins` | Installed, catalog, permission diff, pin, block reason, usage | Supply-chain governance is organization configuration. It sits beside `Credentials` conceptually — both concern what may act on the organization's behalf — and not under a new top-level item, because F22's tree has none. |

Both are deviations from F22's literal tree, taken because F25/F14 mandate the
surfaces and F22 is silent rather than contrary. **If F22 later adds explicit
sub-pages for these, P07 relocates to them.** That is a Change Request, not an
implementation detail.

Both are human-organization surfaces inside the Settings group created in P06 and
use the existing sub-navigation and breadcrumb. P07 adds no top-level nav item.

There is no customer-visible route for `/internal/*`. F22 states account-level
pages live outside org navigation, and staff tooling is not a customer surface
at all. P07 ships **no** internal-operations UI; see §1.

## Permissions and role behavior

New browser permissions, added to the existing `Permission` enum:

| Permission | Owner | Admin | Member | Viewer |
|---|---|---|---|---|
| `service_accounts.read` | allow | allow | — | — |
| `service_accounts.manage` | allow | allow | — | — |
| `plugins.read` | allow | allow | allow | allow |
| `plugins.manage` | allow | allow | — | — |

- `plugins.read` is member-visible because a member can see which tools exist
  and why a tool is denied; that is diagnostic value and costs nothing.
- `plugins.manage` is admin-only. Installing code is a supply-chain decision.
- `service_accounts.*` is admin-only. A credential is an ownership-level act.
- **No machine or staff authority is expressible as a `MembershipRole`**, and no
  `MembershipRole` confers platform authority. This is the F24-001/Plan07-BE-03
  separation.

Reserved but **not added** (F06, unimplemented): `identity.read`,
`identity.manage`. They enter the enum only with F06.

Staff permissions are the separate set in §3 and never appear in the
organization matrix.

## Error semantics

Stable machine-readable codes. All are returned in the existing error envelope
with a `reason` detail; none carries a provider or raw store body.

```text
machine_key_invalid            machine_key_expired
machine_key_revoked            machine_key_suspended
scope_denied                   scope_project_mismatch
scope_network_unavailable      human_only_action
capability_unknown             capability_human_only
key_limit_reached              key_terminal

plugin_blocked                 plugin_quarantined
plugin_permission_expanded     plugin_incompatible
plugin_integrity_failed        plugin_pinned
plugin_pinned_conflict         plugin_tool_unregistered
manifest_invalid               manifest_digest_mismatch
policy_conflict                version_not_pending_review

staff_grant_required           staff_grant_expired
staff_grant_revoked            staff_grant_org_mismatch
staff_grant_reason_required    staff_grant_ttl_invalid

flag_expires_required          flag_expired
kill_switch_active             kill_switch_target_unknown
kill_switch_too_broad
```

- `kill_switch_active` is distinct from `scope_denied` so a caller can tell "you
  lack permission" from "the platform has disabled this", which are different
  operational situations.
- Every denial above is a **stable code**, never a prose string a client must
  parse.

## Persistence skeleton

Forward-only migrations after `0015_p06_baseline_seed.sql`. Tables:

```text
-- machine identity
service_accounts        (service_account_id PK, org_id FK, name, description,
                         capabilities_json, status, created_by_principal,
                         expires_at, version, …)
api_keys                (api_key_id PK, service_account_id FK, org_id FK, name,
                         key_prefix UNIQUE, secret_hash, fingerprint,
                         capabilities_json, project_ids_json, model_aliases_json,
                         network_allowlist_json, expires_at, status,
                         rotated_from_key_id, last_used_at, last_used_source,
                         revoked_at, revoke_reason, version, …)

-- plugin governance
plugin_packages         (package_id PK, publisher_id, display_name, …)
plugin_versions         (plugin_version_id PK, package_id FK, version,
                         runtime_min, runtime_max, content_digest,
                         signature, manifest_json, published_at,
                         UNIQUE(package_id, version))
plugin_installs         (install_id PK, org_id FK, package_id FK, version,
                         review_state, pending_review_version, approved_by,
                         approved_at, …)
plugin_policies         (org_id PK, publisher_mode, approved_publishers_json,
                         allowed_packages_json, blocked_packages_json,
                         pinned_versions_json, auto_update, update_mode,
                         version, …)
plugin_tool_registrations (registration_id PK, org_id FK, package_id,
                         version, tool_id, approved_by, approved_at,
                         UNIQUE(org_id, package_id, version, tool_id))
plugin_quarantines      (quarantine_id PK, package_id, version,
                         reason, engaged_by_staff_principal_id, engaged_at,
                         lifted_at, lifted_by, lift_reason, …)

-- platform operations
staff_principals        (staff_principal_id PK, email, display_name,
                         staff_role, status, created_at, …)
support_grants          (grant_id PK, staff_principal_id FK, organization_id FK,
                         reason, ticket_reference, capabilities_json,
                         issued_at, expires_at, revoked_at, revoke_reason,
                         version, …)
feature_flags           (flag_key PK, enabled, rollout_percentage,
                         org_allowlist_json, cohort, expires_at,
                         owner_staff_principal_id, version, …)
kill_switches           (kill_switch_id PK, target_class, target_ref, scope,
                         organization_id, reason, engaged_by_staff_principal_id,
                         engaged_at, expires_at, state, lifted_at, …)
```

Invariant-bearing constraints, proven rejected in-database like P06's:

1. `api_keys.key_prefix` is UNIQUE — a prefix collision would make one key
   authenticate as another.
2. `api_keys.secret_hash` is never equal to any presented key material; the
   column is a 64-char hex CHECK, so a raw key cannot be stored there even by
   mistake.
3. `service_accounts.capabilities_json` is a valid JSON array of known
   permission strings. A wildcard `"*"` is rejected — F14-001.
4. `api_keys` has no column that can hold the raw key. Enforced by CHECK
   constraints on every text column's shape plus the absence of any plaintext
   column; proven by a test that the projection has no such field.
5. `plugin_installs` UNIQUE `(org_id, package_id)` — one install row per package
   per org, so a second install cannot create a second approval state.
6. `plugin_versions` UNIQUE `(package_id, version)` and immutable after insert
   (trigger refusing UPDATE of `version`, `manifest_json`, `content_digest`,
   `signature`).
7. `kill_switches`: `organization_id` is NOT NULL exactly when `scope =
   'organization'`, and NULL when `scope = 'global'`. A global switch carrying
   an org, or an org switch with none, is a scoping bug that would silently
   under-apply a safety control.
8. `feature_flags.expires_at` is NOT NULL (F24-006: not a permanent store).
9. `support_grants.expires_at` is NOT NULL and bounded to 1..604800 seconds; a
   grant with no expiry is refused.
10. `plugin_quarantines` has no DELETE path; quarantine is lifted, never erased,
    so the record of a security action survives.

### Data class registry additions

Every P07 table is a new persistent data class and must be declared in
`data_class_registry` (P06-F20-001). P07 adds 13 classes across 12 new tables —
`api_key_fingerprint` is a projection carried on `api_keys` rather than a table
of its own, because a fingerprint with no owning key row is meaningless and
separating them would permit an orphan:

| Class | Sensitivity | Owner | Export | Deletion | Logging |
|---|---|---|---|---|---|
| `service_account` | confidential | organization | metadata_only | revoke | ids_status |
| `api_key` | **secret** | organization | never | **crypto_erase** | ids_status |
| `api_key_fingerprint` | internal | organization | metadata_only | physical_delete | ids_status |
| `plugin_package` | public | platform | included | tombstone | metadata_only |
| `plugin_version` | internal | platform | included | tombstone | metadata_only |
| `plugin_install` | internal | organization | included | tombstone | ids_status |
| `plugin_policy` | internal | organization | included | tombstone | metadata_only |
| `plugin_tool_registration` | internal | organization | included | tombstone | ids_status |
| `plugin_quarantine` | internal | platform | metadata_only | retain_legal_only | ids_status |
| `staff_principal` | restricted | platform | **never** | tombstone | ids_status |
| `support_grant` | restricted | platform | **never** | retain_legal_only | ids_status |
| `feature_flag` | internal | platform | metadata_only | tombstone | metadata_only |
| `kill_switch` | internal | platform | metadata_only | retain_legal_only | ids_status |

Notes that are load-bearing, not decorative:

- `api_key` is `secret` + `never` exported + `crypto_erase`. The P06 trigger
  `trg_data_class_registry_secret_guard` requires a `never`-export class to be
  one of the unrecoverable shapes; crypto-erase is one, so this row is accepted
  by the existing invariant without weakening it.
- `staff_principal` and `support_grant` are `never` exported. A customer export
  must not carry platform staff identities, and `retain_legal_only` keeps the
  audit trail after a staff departure. This is F24's "hard to audit" failure
  mode, closed at the data layer rather than at the UI.
- `plugin_quarantine` and `kill_switch` are `retain_legal_only`. Deleting the
  record of a security action would destroy the evidence that it happened.

## Compatibility and migration

- **Previous client/server compatibility:** additive. New routes, new tables, new
  permission values. No existing route, event type, or response shape changes.
  P02–P06 clients continue to work unchanged.
- **Migration expectations:** migrations `0016`–`0018` are forward-only and apply
  after `0015`. Each is independently applicable to a fresh D1.
- **No existing data is rewritten.** P07 adds no column to a P02–P06 table.
- **External ZCode/LumiAgents mapping:** P05's `source IN
  ('built_in','plugin','custom')` is preserved exactly. P07 adds
  `plugin_installs` **above** that source column, keyed by
  `(package_id, version, tool_id)`. ZCode's builtin/plugin/custom distinction is
  not flattened, and a `custom` MCP server is not treated as a `plugin` package
  — a custom server has no package identity to govern, so it continues to be
  governed by P05 tool policy and F13 default-deny alone. That is recorded
  because conflating them would make plugin policy appear to cover servers it
  does not.
- **One queue entry point.** `workers-rs` hard-codes a single `#[event(queue)]`
  (established in P06). Plugin report processing and support-grant expiry reuse
  the P06 job envelope and are routed on `job_type` before any decode. P07 adds
  no second queue macro.

## Fixtures

`docs/implementation/fixtures/p07-contracts-v1.json` freezes, before backend
implementation exists:

- one `ServiceAccount` with a known capability set, including one human-only
  capability that must be refused;
- one `ApiKey` projection with `secret` present exactly once and a stable
  `key_prefix`/`fingerprint` pair that agree with a documented derivation;
- one machine permission diff that **expands** (`tools` added) and one that
  does not, with the expected per-class verdicts;
- one `PluginPolicy` with a package on both the allow and block lists, to pin the
  `policy_conflict` behavior;
- one `KillSwitch` at organization scope and one at global scope, so the
  precedence order is testable;
- one `FeatureFlag` with a percentage, so stable-hash cohort assignment is
  testable;
- one expired `SupportGrant` and one revoked one.

## Coordinator decisions before freeze

1. **Three actor kinds, three decision functions** (ADR 0007). `Principal` and
   `authorize` are untouched. Machine authority is a scope and is structurally
   incapable of becoming a `MembershipRole`.
2. **Five human-only permissions**, refused before scope is consulted.
   `data.delete` and `billing.manage` are included as P07 judgment, beyond
   F14-007's "such as owner transfer", because both are irreversible
   commercial/data acts and no justification for machine access exists.
3. **F06 is frozen and not implemented.** Its entitlement keys already exist, so
   the seam is complete without schema. This is the main scope reduction and is
   deliberate.
4. **No internal-operations UI in P07.** Staff boundaries and kill-switch
   semantics are implemented and tested at the API and domain layers. Plan07-FE-04
   says "only if needed", and there is no staff user to need it yet.
5. **Staff support grants are created/revoked but not consumed.** No route
   consumes a grant and no impersonation route exists. F24-003's "default mode
   is metadata, not impersonation" is met by absence.
6. **Network allowlists fail closed** when the edge IP is unavailable.
7. **Kill switches are exactly one target.** No bulk or tenant-wide form.
8. **`custom` MCP servers are not plugin packages** and stay under P05/F13
   governance.
9. **P06's three recorded contract gaps are unchanged** and are not addressed
   here: no downgrade-preview route, no count for an in-limit resource, no
   attempt-level delivery diagnostics. They remain open for a Change Request.
10. **No browser permission or table for F06.** Following the P06-CR-002
    precedent for internal-only or unimplemented capability.

## Freeze commit

- Contract Gate commit: recorded in `docs/implementation/gates/P07-CG.md` merge
  history and `STATUS.md`.
- Contract version: `p07-cg-v1`
- Dependent packets unlocked: P07-MOD-01..04, P07-BE-01..04, P07-FE-01..03,
  P07-INT-01..02, P07-QA-01

## Change rule

After freeze, no dependent PR may silently redefine this contract. A required
change must use `docs/implementation/templates/change-request.md`.
