# Plan 02 — Identity, organizations, membership, authorization

Status: Complete
Specs: F01, F02, F03, F04, F05, F16, F23
Depends on: P01

## 1. Phase outcome

A real user can authenticate, create/join an organization, switch org context, invite/manage members, and hit protected APIs through one centralized authorization path.

This is the first real multi-tenant vertical slice.

## 2. Contract Gate — P02-CG

Freeze:

- `User`, `Identity`, `LoginSession`;
- `Organization`, `Membership`, `Invitation`, `Team`;
- default role IDs and stable permission strings;
- org lifecycle states;
- membership/invitation states;
- auth/session API shapes;
- org/member/team API shapes;
- authorization decision interface and denial codes.

Do not freeze custom-role schema yet.

## 3. Parallel modules lane

### P02-MOD-01 — Identity/session domain

Implement:

- stable user ID;
- identity linking rules;
- session revoke logic;
- reauthentication-grant rules;
- security event commands.

Auth provider/OIDC specifics stay behind adapter.

### P02-MOD-02 — Organization domain

Implement:

- create/suspend/pending-delete lifecycle;
- last-owner invariant;
- ownership transfer;
- slug/name rules.

### P02-MOD-03 — Membership/team domain

Implement:

- invitation lifecycle;
- accept/revoke/resend;
- leave/remove;
- team membership;
- duplicate/concurrency invariants.

### P02-MOD-04 — Authorization engine

Implement one policy service:

```text
authorize(principal, org, permission, resource_context) -> decision
```

Centralize:

- membership active check;
- role grant mapping;
- resource scope;
- default deny;
- stable denial reason.

No handler-level ad hoc `role == admin`.

## 4. Backend lane

### P02-BE-01 — Persistence/migrations

Tables/indexes for:

- users;
- identities;
- sessions;
- organizations;
- memberships;
- invitations;
- teams/team_members;
- security events or audit projection as needed.

Use uniqueness/constraints for concurrency invariants where possible.

### P02-BE-02 — Auth HTTP flow

Implement initial supported auth path.

Must support:

- web login;
- logout;
- refresh/session;
- verified identity;
- browser-to-desktop device authorization primitive needed by P03.

Keep provider adapter replaceable.

### P02-BE-03 — Org/member/team APIs

Implement routes from F02/F03 with:

- explicit org path context;
- pagination;
- idempotent invitation create/accept where applicable;
- authorization middleware/service.

### P02-BE-04 — Session security APIs

Implement:

- list sessions/devices placeholder;
- revoke one/all;
- recent security events;
- reauth grant endpoint.

Device enrollment itself is P03.

## 5. Frontend lane

### P02-FE-01 — Auth flows

Pages:

- login/signup;
- verify;
- auth callback;
- basic account security;
- login error/recovery states.

### P02-FE-02 — Org shell/switcher

Build:

- create org;
- org switcher;
- route-scoped org context;
- stale-cache clearing on switch;
- organization settings basics.

### P02-FE-03 — Members/teams

Build:

- directory;
- pending invites;
- invite dialog;
- member role/team management;
- last-owner protected UX;
- team list/detail.

Frontend starts from frozen contract fixtures before BE routes are ready.

## 6. Integration lane

### P02-INT-01 — Desktop sign-in protocol contract

Define browser auth handoff consumed later by LumiAgents:

- one-time code;
- state/PKCE binding;
- device label;
- expiration;
- exchange semantics.

Do not yet implement full managed-device enrollment.

## 7. QA lane

### P02-QA-01 — Tenant/auth hostile matrix

Mandatory tests:

- Org A resource ID used by Org B;
- removed member using old token;
- stale role/membership cache;
- concurrent last-owner demotions;
- revoked/expired invitation;
- invitation token replay;
- identity linking conflict;
- revoked session refresh.

## 8. Integration Gate

Demonstrate:

1. User A signs in.
2. Creates Org A.
3. Invites User B.
4. User B accepts.
5. B can access permitted member API.
6. B cannot access Owner-only mutation.
7. User from Org C cannot discover/read Org A by ID substitution.
8. Org switcher never shows stale data from prior org.
9. Security/audit event exists for membership/role changes.

## 9. Exit criteria

P03/P04 may begin when these are stable:

- principal resolution;
- org context;
- membership lookup;
- permission service;
- audit actor model;
- authenticated desktop handoff contract.


## 10. Additive passkey-first authentication upgrade — P02-CR-002

P02 core remains **Complete**. P03 and P04 remain unblocked.

The product authentication hierarchy has changed after P02 completion:

1. Passkey is the primary/default signup and login option.
2. Email + password is the secondary/fallback option.
3. The shipped email one-time-code flow remains for verification/recovery/compatibility, not the target everyday sign-in UX.

This is recorded by `docs/implementation/change-requests/P02-CR-002.md` and advances the auth contract to `p02-cg-v2` without changing principal/session/org semantics.

### Follow-up packets

#### P02-MOD-05 — Authenticator credential domain

Define passkey/password credential invariants, WebAuthn ceremony lifecycle, lockout prevention, passkey metadata, password credential semantics, and security-event names.

#### P02-BE-05 — Passkey/password backend

First perform a Worker/WASM compatibility spike for maintained WebAuthn verification and the required password KDF. Then implement additive migrations, passkey ceremonies, password signup/login/reset, passkey management, rate limits, sessions, and audit events.

Do not manually implement WebAuthn cryptography. Do not weaken password hashing to fit Workers without an ADR.

#### P02-FE-04 — Passkey-first auth UX

Replace everyday email-code login UI with:

- primary passkey signup/login;
- conditional mediation/autofill where supported;
- secondary email/password;
- recovery/verification flows;
- passkey account management.

#### P02-QA-02 — Passkey/password hostile matrix

Prove replay/origin/RP/user-verification/signature rejection, credential ownership, password storage/rate limits/recovery, browser fallback, session compatibility, and lockout prevention.

### Shared-file ownership

If these packets execute concurrently with P03/P04, the P02 auth-upgrade coordinator owns changes to:

- auth route declarations;
- auth migrations/manifests;
- shared API client auth types;
- auth-screen top-level routing.

P03/P04 should consume the stable session/principal contracts and do not need to wait for the new authenticators.

### Upgrade integration gate

The additive auth upgrade is complete when:

1. a new user registers with a passkey;
2. signs out;
3. signs back in usernameless with that passkey;
4. a second user registers/signs in through email/password;
5. unsupported/cancelled passkey UX falls back cleanly;
6. both paths create the existing secure server session/CSRF contract;
7. passkey challenge/replay/origin/RP/signature hostile cases pass;
8. password KDF/storage and recovery tests pass;
9. desktop PKCE approval still works after browser authentication with either method;
10. no P03/P04 contract is regressed.
