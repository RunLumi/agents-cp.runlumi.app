# /goal 02 — Complete P02 Identity, Organizations, Membership, and Authorization

You are the **P02 phase coordinator and implementation lead**.

Complete `docs/implementation/plan02-identity-organization-authorization.md` end-to-end and create the first real multi-tenant vertical slice.

## Preconditions

Verify P01 is actually complete in `docs/implementation/STATUS.md`.

If foundational P01 contracts are missing, do not invent replacements inside P02. Repair or formally change the upstream contract first.

## Read first

- `AGENTS.md`
- `docs/prompts/README.md`
- Plan00 and P02
- F01 Identity & Authentication
- F02 Organization & Tenant Lifecycle
- F03 Membership, Invitations & Teams
- F04 Authorization & Policy Engine
- F05 Sessions, Devices & Account Security
- F16 Audit
- F23 API Contracts
- relevant ADRs
- P01 handoffs/contracts

## Mission

Ship a secure multi-tenant identity and organization core where:

- real users authenticate;
- users create/join organizations;
- org switching is explicit;
- members/invitations/teams work;
- one centralized authorization path protects every org resource;
- last-owner and membership lifecycle invariants are transactional;
- security-sensitive account/session actions are auditable;
- desktop auth handoff contract exists for P03.

## Contract Gate

Create and merge P02-CG before parallel packets.

Freeze at minimum:

- User / Identity / LoginSession;
- Organization / Membership / Invitation / Team;
- org and membership states;
- default role IDs;
- stable permission identifiers;
- authorization decision input/output;
- denial/error codes;
- auth/session API contracts;
- org/member/team APIs;
- audit actor representation;
- browser-to-desktop one-time auth handoff.

## Parallel work packets

Execute the plan's lane decomposition:

### MOD
- Identity/session domain
- Organization lifecycle
- Membership/invitation/team domain
- Authorization engine

### BE
- persistence/migrations
- auth HTTP flow
- org/member/team APIs
- account/session security APIs

### FE
- auth flows
- org shell/switcher
- members/teams UI

### INT
- desktop browser-auth handoff protocol

### QA
- tenant/auth hostile matrix

Use disjoint write surfaces and one shared-file owner.

## Non-negotiable security invariants

Every protected operation establishes:

```text
principal
+ explicit org context
+ active membership
+ permission
+ resource scope
```

Never treat a resource ID, email domain, frontend role, or stale token claim as authority.

No route handler may implement its own role logic when centralized authorization should decide.

## Required hostile tests

Include at least:

- Org A ID substituted into Org B request;
- removed member with stale token;
- concurrent last-owner changes;
- invitation replay;
- revoked/expired invitation;
- identity-link conflict;
- revoked session refresh;
- org switch stale cache/data flash;
- unauthorized direct URL access.

## Integration Gate

Prove the real journey:

1. User A signs in.
2. Creates Org A.
3. Invites User B.
4. B accepts.
5. B can perform granted actions.
6. B cannot perform owner-only action.
7. Org C cannot discover/read Org A by ID substitution.
8. Web org switch does not leak stale Org A/B state.
9. Security/audit events exist for material changes.

## Completion

P02 is complete only when:

- the centralized principal/org/authz primitives are stable;
- P03 and P04 can consume them without redefining identity or tenant semantics;
- Integration Gate passes;
- STATUS unlocks P03 and P04;
- downstream handoff explicitly documents the stable contracts.

Do not stop at "auth works". Finish the tenant security model.


## P02-CR-002: passkey-first additive auth upgrade

If `docs/implementation/STATUS.md` already shows P02 core complete, do **not** redo the completed organization/authz packets.

Instead execute the accepted additive authenticator upgrade defined by P02-CR-002 and `p02-cg-v2`:

- P02-MOD-05
- P02-BE-05
- P02-FE-04
- P02-QA-02

### Product hierarchy

The resulting normal auth UI MUST be:

1. passkey primary/default;
2. email + password secondary.

Email one-time-code remains verification/recovery/compatibility, not normal everyday login.

### Backend safety gate

Before adding a WebAuthn/password crypto dependency, prove it:

- compiles for `wasm32-unknown-unknown`;
- builds in the Cloudflare Worker;
- verifies a real registration/assertion end-to-end;
- can run the required password KDF within real Worker constraints.

If not, stop and create an ADR rather than implementing WebAuthn crypto manually or weakening password hashing.

### Upgrade integration proof

Do not call this extension complete until real tests show:

- passkey signup;
- usernameless passkey login;
- password signup/login fallback;
- passkey browser-unavailable/cancel fallback;
- challenge replay/expiry/origin/RP/signature/user-verification rejection;
- passkey add/remove with last-login-method protection;
- secure password storage and reset;
- unchanged cookie/session/CSRF behavior;
- unchanged desktop PKCE handoff.
