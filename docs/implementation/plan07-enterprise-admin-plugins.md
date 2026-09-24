# Plan 07 — Enterprise identity, internal admin, plugins

Status: Planned
Specs: F06, F14, F24, F25
Depends on: P02, P05, P06
Priority: only execute full scope when product/customer demand justifies it

## 1. Phase outcome

Add enterprise and platform-operations surfaces without contaminating the simple SMB/org core.

## 2. Contract Gate — P07-CG

Freeze:

- verified domain;
- SSO connection/JIT policy;
- SCIM token/resource mapping;
- ServiceAccount/APIKey scope;
- StaffRole/SupportGrant;
- feature flag/kill switch;
- PluginPackage/Version/Manifest/Policy.

## 3. Modules lane

### P07-MOD-01 — Enterprise identity

Rules:

- domain verification;
- JIT;
- SSO enforcement + owner recovery;
- SCIM deactivate semantics.

### P07-MOD-02 — Machine identity

Rules:

- service accounts;
- scoped API keys;
- secret hash/fingerprint;
- rotation/revoke.

### P07-MOD-03 — Plugin governance

Rules:

- manifest permissions;
- version permission diff;
- org allow/block/pin;
- new tool review;
- vulnerable-version quarantine.

### P07-MOD-04 — Internal staff access

Rules:

- named staff principal;
- least privilege;
- support grant TTL/reason;
- break glass;
- customer-visible audit.

## 4. Backend lane

### P07-BE-01 — SSO/SCIM APIs

Keep behind entitlement/feature flag until production ready.

### P07-BE-02 — Service-account APIs

Scoped keys, expiry, rotation, last-used.

### P07-BE-03 — Staff/admin APIs

Separate route namespace and authorization boundary.

Do not reuse customer Admin role as platform staff role.

### P07-BE-04 — Plugin policy APIs

Catalog metadata, install policy, version pin, quarantine, permission review.

## 5. Frontend lane

### P07-FE-01 — Identity settings

Domains, SSO, JIT, SCIM.

### P07-FE-02 — Service accounts

Create, scope, one-time secret reveal, revoke.

### P07-FE-03 — Plugin governance

Installed/approved/blocked, permission diff, version state.

### P07-FE-04 — Internal operations UI

Only if needed. Keep separately routed and permissioned from customer control plane.

## 6. Integration lane

### P07-INT-01 — Plugin manifest/report

LumiAgents reports installed plugin/version/tool fingerprint needed for policy.

### P07-INT-02 — API/service identities

Support headless/managed runner path without pretending to be a human account.

## 7. QA lane

Mandatory:

- SSO email mismatch/account takeover;
- SCIM deactivate;
- owner break-glass;
- service-account scope escalation;
- hashed key storage;
- staff impersonation/audit;
- plugin update expands permissions;
- blocked plugin remains on disk but cannot execute managed capability.

## 8. Exit criteria

Enterprise features cannot weaken P02/P05 authorization or secret invariants.
