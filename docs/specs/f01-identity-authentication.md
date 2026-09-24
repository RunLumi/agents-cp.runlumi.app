# F01 — Identity & Authentication

Priority: P0  
Owner: Control Plane  
Depends on: F23

## Objective

Cung cấp một user identity ổn định dùng xuyên web control plane và Lumi Agents desktop/CLI, không gắn user identity với một AI provider account.

## Scope

- user signup/sign-in;
- email verification;
- OAuth/OIDC social login where useful;
- passwordless/passkey-ready auth;
- MFA-ready account model;
- account recovery;
- identity linking;
- logout/revocation;
- secure handoff to desktop app.

## Non-goals

- Provider OAuth/token ownership: F11.
- Enterprise SSO/SCIM: F06.
- Service accounts: F14.

## Core entities

```text
User
Identity
Credential / Authenticator
EmailAddress
LoginSession
RecoveryMethod
```

`User.id` MUST be immutable and never use email as primary key.

A user may have multiple verified identities mapping to the same account.

## Requirements

### FR-F01-001 — User identity

Backend MUST issue a stable opaque `user_id`.

### FR-F01-002 — Email verification

Signup by email MUST require verification before the user can join an organization through an email invitation unless product explicitly allows pre-verified enterprise provisioning.

### FR-F01-003 — Login methods

System SHOULD support:

- email magic link or secure password flow;
- at least one OIDC provider;
- WebAuthn/passkey compatibility;
- MFA enrollment later without schema rewrite.

### FR-F01-004 — Identity linking

A logged-in user MAY attach another login identity only after re-authentication.

Conflicting verified email identities MUST NOT auto-merge accounts without an explicit safe merge flow.

### FR-F01-005 — Desktop sign-in

Desktop app MUST authenticate through browser-based authorization with:

- short-lived one-time code;
- PKCE or equivalent binding;
- explicit device name;
- callback only to registered app protocol/loopback target;
- no long-lived access token exposed in browser URL.

### FR-F01-006 — Access tokens

Use short-lived access tokens and separately revocable refresh/session state.

Tokens MUST contain minimal claims. Authorization decisions MUST be re-evaluated server-side, not trusted from stale token role claims.

### FR-F01-007 — Recovery

Recovery MUST invalidate or rotate sensitive session material and create a security event.

### FR-F01-008 — Account merge protection

Same email with different upstream IdP subject MUST not silently overwrite existing identity.

## Web UX

Routes:

- `/login`
- `/signup`
- `/verify-email`
- `/account/security`
- `/account/identities`

Security page shows login methods, MFA/passkeys, recent sessions and recovery state.

## API surface

Indicative:

- `POST /api/v1/auth/login/start`
- `POST /api/v1/auth/login/complete`
- `POST /api/v1/auth/logout`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/device-code`
- `POST /api/v1/auth/device-code/exchange`
- `GET /api/v1/me`
- `POST /api/v1/me/identities/link`
- `DELETE /api/v1/me/identities/:id`

## Security invariants

- Never trust email domain alone as proof of org membership.
- Prevent login CSRF and OAuth state confusion.
- Login attempts MUST be rate limited.
- Session cookies on web: Secure, HttpOnly, SameSite appropriate to flow.
- Auth events MUST be auditable.

## Edge cases

- user changes primary email;
- invitation sent to alias email;
- upstream IdP email changes;
- duplicate identities;
- deleted account tries to reactivate through OAuth;
- browser auth completes after desktop device code expires.

## Acceptance criteria

- A user can sign in on web and authorize one desktop device without copying a token.
- Revoking the device/session prevents further refresh.
- Linking a second IdP cannot hijack an existing unrelated user.
- Cross-user session token substitution returns 401/403 and logs security telemetry.
