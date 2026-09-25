# F01 — Identity & Authentication

Priority: P0  
Owner: Control Plane  
Depends on: F23

## Objective

Cung cấp một user identity ổn định dùng xuyên web control plane và Lumi Agents desktop/CLI, không gắn user identity với một AI provider account.

**Authentication order is a product requirement:**

1. **Passkey is the primary/default registration and login path.**
2. **Email + password is the secondary/fallback path.**
3. Email one-time-code remains for verification, recovery, compatibility, or another explicitly scoped challenge. It is not the normal primary sign-in CTA after the passkey-first upgrade.

## Scope

- passkey-first registration and sign-in;
- multiple passkeys per user;
- discoverable/usernameless passkey login;
- conditional passkey mediation/autofill where supported;
- email + password fallback;
- email verification;
- password/passkey recovery;
- OAuth/OIDC social login later where useful;
- MFA/step-up-ready account model;
- identity linking;
- logout/revocation;
- secure browser-to-desktop handoff.

## Non-goals

- Provider OAuth/token ownership: F11.
- Enterprise SSO/SCIM: F06.
- Service accounts: F14.
- Device enrollment/policy identity: F19.

## Core entities

```text
User
Identity
PasskeyCredential
PasswordCredential
WebAuthnCeremony
EmailAddress
LoginSession
RecoveryMethod
```

`User.id` MUST be immutable and never use email as primary key.

A user may have multiple verified identities and multiple passkeys mapping to the same account.

## Requirements

### FR-F01-001 — User identity

Backend MUST issue a stable opaque `user_id`.

WebAuthn user handles MUST be opaque, stable, non-PII identifiers. Email MUST NOT be used as the WebAuthn user handle.

### FR-F01-002 — Email verification

A passkey or password account MAY establish a session before email verification, but email-sensitive organization actions such as accepting an email invitation MUST require a verified matching email unless product explicitly allows pre-verified enterprise provisioning.

Email verification is separate from authenticator verification.

### FR-F01-003 — Authentication priority

The normal signup/sign-in UX MUST present methods in this order:

1. passkey;
2. email + password.

Passkey is the visually primary/default CTA when WebAuthn is available in a secure context.

Email/password remains fully accessible and usable as the second option.

Existing email-code login endpoints MAY remain temporarily for compatibility, but the normal web auth screen MUST NOT present email-code sign-in as the primary or secondary everyday login method after this feature ships.

### FR-F01-004 — Passkey registration

Passkey signup MUST use a server-authoritative, short-lived, one-time WebAuthn registration ceremony.

For first-account registration:

1. client submits required account metadata such as email + display name;
2. server creates a pending ceremony and opaque proposed user handle;
3. server returns WebAuthn `PublicKeyCredentialCreationOptions`;
4. browser creates the credential;
5. server verifies the attestation/registration result against stored ceremony state;
6. only after successful verification does the backend create/link user + identity + passkey and create the login session.

Default policy:

- `residentKey: "required"` or equivalent discoverable credential requirement;
- `userVerification: "required"`;
- `attestation: "none"` unless a later enterprise policy explicitly needs attestation;
- do not force `authenticatorAttachment: "platform"`; synced passkeys and security keys should both work;
- exclude already-registered credentials when adding a new passkey where the browser/API supports it.

A failed/expired ceremony MUST NOT leave an authenticated account or usable credential record.

### FR-F01-005 — Passkey login

Passkey login MUST support discoverable/usernameless credentials.

Normal login start MUST NOT require an email address and SHOULD omit `allowCredentials` so the authenticator can present eligible discoverable credentials.

Server verification MUST bind the verified credential ID/user handle to the account. A client-supplied `user_id` is never authority.

After successful verification, the system creates the same revocable server-side LoginSession used by other authentication methods.

### FR-F01-006 — Conditional mediation

On supported browsers, the login screen SHOULD enable WebAuthn conditional mediation/autofill.

When conditional mediation is used:

- the relevant username/email input may use `autocomplete="username webauthn"`;
- feature detection MUST precede conditional calls;
- failure/unavailability MUST fall back cleanly to the explicit passkey button and email/password path;
- conditional mediation MUST NOT be required for passkey support.

### FR-F01-007 — Password fallback

Email/password is the secondary authentication method.

Passwords MUST be protected using a slow password KDF designed for password storage, never reversible encryption and never a fast raw hash such as SHA-256.

Target baseline for new credentials is current OWASP Argon2id guidance or stronger, subject to a real Cloudflare Worker/WASM compatibility and performance test. If the required KDF cannot safely run within Worker memory/CPU limits, engineering MUST stop and record an ADR for an alternative trusted password-verification boundary rather than silently weakening the KDF.

Password UX MUST:

- support long passwords with a maximum of at least 64 characters;
- allow password managers and paste;
- avoid arbitrary composition rules that reduce usability without meaningful security;
- use generic login/reset errors where account enumeration matters;
- use bounded credential-stuffing/rate-limit controls independently from passkey ceremonies.

### FR-F01-008 — Password signup/login

Password signup requires email, display name, and password.

Password login requires email + password and MUST NOT disclose whether the email or password was wrong.

Password signup/linking creates a PasswordCredential separate from Identity so future identity-provider changes do not rewrite credential semantics.

### FR-F01-009 — Passkey management

Authenticated users MAY register multiple passkeys.

Passkey metadata MAY include a user-visible label, creation time, last-used time, transports, and backup eligibility/state when available.

Users can revoke a passkey after recent reauthentication.

The system MUST NOT allow removal of the last usable sign-in method unless another usable passkey or password-based recovery/sign-in method exists.

Raw private keys never exist on the server.

### FR-F01-010 — WebAuthn ceremony state

Registration/authentication ceremonies MUST be:

- server-generated;
- short-lived;
- one-time;
- rate limited;
- bound to ceremony kind;
- verified against explicitly configured RP ID and allowed origin(s);
- consumed atomically on success.

Do not derive trusted RP ID/origin from an arbitrary request Host header.

Do not implement WebAuthn cryptographic verification ad hoc. Use a maintained verifier only after proving its compatibility with the Worker `wasm32-unknown-unknown` target.

### FR-F01-011 — WebAuthn verification

Authentication verification MUST validate, as applicable:

- challenge;
- credential ID;
- relying-party ID/hash;
- allowed origin;
- authenticator/client data;
- credential public-key signature;
- required user verification;
- stored credential ownership/state.

Synced passkeys may legitimately have a zero or non-incrementing signature counter. Zero alone MUST NOT cause rejection. A meaningful positive-counter regression MAY create a security event and step-up/review according to verifier guidance.

### FR-F01-012 — Identity linking

A logged-in user MAY attach another login identity only after recent reauthentication.

Conflicting verified email/provider identities MUST NOT auto-merge accounts without an explicit safe merge flow.

### FR-F01-013 — Desktop sign-in

Desktop app MUST authenticate through browser-based authorization with:

- short-lived one-time code;
- PKCE or equivalent binding;
- explicit device name;
- callback only to registered app protocol/loopback target;
- no long-lived access token exposed in browser URL.

The browser may authenticate the human using passkey or password before approving the existing device authorization flow. P03 does not need a separate desktop passkey protocol.

### FR-F01-014 — Access tokens/sessions

Use short-lived/revocable server-side session state. Refresh/session rotation remains separate from the user's authenticator credential.

Tokens MUST contain minimal claims. Authorization decisions MUST be re-evaluated server-side, not trusted from stale token role claims.

### FR-F01-015 — Recovery

Verified email is the default recovery anchor for lost-passkey/password recovery until another explicit recovery mechanism is added.

Password-reset and authenticator-recovery flows MUST:

- use short-lived one-time challenges;
- be rate limited;
- create immutable security events;
- rotate/revoke sensitive session state according to risk;
- never email a password.

Recovery MUST NOT silently merge accounts.

### FR-F01-016 — Reauthentication / step-up

Security-sensitive actions such as passkey removal, passkey addition, password change, ownership transfer, or disabling a strong authenticator SHOULD use a recent reauthentication grant.

A current passkey assertion is the preferred step-up method when available; password is the fallback.

### FR-F01-017 — Security events

At minimum audit:

- passkey registered;
- passkey authentication success/failure classification where useful;
- passkey revoked;
- password credential set/changed/reset;
- recovery completed;
- suspicious credential/sign-counter event;
- session created/revoked.

Never store raw password, WebAuthn private material, session token, or raw recovery token in audit metadata.

## Web UX

Routes:

- `/login`
- `/signup`
- `/verify-email`
- `/account/security`
- `/account/passkeys`
- `/account/identities`

### Sign in

Default hierarchy:

```text
[ Sign in with passkey ]       <- primary

----------- or -----------

Email
Password
[ Sign in with email ]         <- secondary

Forgot password?
```

If passkeys are unavailable in the browser/context, the password path remains usable and the UI does not dead-end.

Conditional passkey/autofill MAY surface passkeys before the explicit button when supported.

### Sign up

Default hierarchy:

```text
[ Create account with passkey ] <- primary
  -> collect/confirm email + name as needed
  -> WebAuthn create ceremony
  -> create session
  -> verify recovery/contact email

----------- or -----------

Email
Name
Password
[ Create with email/password ]  <- secondary
```

### Account security

Show:

- passkeys with labels/last used/revoke/add;
- password status/change;
- verified emails/identities;
- active sessions;
- recent security events;
- recovery state.

## API surface

Passkey-first endpoints:

- `POST /api/v1/auth/passkey/signup/start`
- `POST /api/v1/auth/passkey/signup/complete`
- `POST /api/v1/auth/passkey/login/start`
- `POST /api/v1/auth/passkey/login/complete`

Password fallback:

- `POST /api/v1/auth/password/signup`
- `POST /api/v1/auth/password/login`
- `POST /api/v1/auth/password/forgot`
- `POST /api/v1/auth/password/reset`

Authenticator management:

- `GET /api/v1/account/passkeys`
- `POST /api/v1/account/passkeys/register/start`
- `POST /api/v1/account/passkeys/register/complete`
- `DELETE /api/v1/account/passkeys/:passkey_id`
- `POST /api/v1/account/password`

Existing/session flows:

- `POST /api/v1/auth/verify-email`
- `POST /api/v1/auth/logout`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/device-code`
- `POST /api/v1/auth/device-code/exchange`
- `GET /api/v1/me`
- `POST /api/v1/me/identities/link/start`
- `POST /api/v1/me/identities/link`
- `DELETE /api/v1/me/identities/:id`

Legacy email-code login routes may remain temporarily for backwards compatibility but are not the target everyday UX.

## Persistence requirements

Expected additive entities:

### PasskeyCredential

- passkey_id;
- user_id;
- globally unique credential_id;
- public key / verifier credential material;
- sign_count;
- transports metadata;
- backup eligibility/state when provided;
- display label;
- created_at;
- last_used_at;
- revoked_at.

### WebAuthnCeremony

- ceremony_id;
- kind;
- optional user/pending user handle;
- normalized email/display-name metadata when needed for signup;
- server-side verification state/challenge;
- expires_at;
- consumed_at;
- created_at.

### PasswordCredential

- user_id;
- password hash in an encoded self-describing format where possible;
- algorithm/work-factor metadata;
- created_at;
- updated_at.

Private keys and raw passwords MUST NOT be persisted.

## Security invariants

- Never trust email domain alone as proof of org membership.
- Prevent login CSRF and OAuth/WebAuthn state confusion.
- Passkey, password, recovery, and email-verification attempts MUST be separately rate limited.
- Session cookies on web: Secure, HttpOnly, SameSite appropriate to flow.
- Auth/security events MUST be auditable.
- Password hashes, credential public material, WebAuthn ceremony state, and account identity MUST remain server-side authority.
- Do not log raw WebAuthn responses when they contain more data than necessary for diagnostics.

## Edge cases

- browser/device does not support WebAuthn;
- WebAuthn available but conditional mediation unavailable;
- user cancels native passkey prompt;
- passkey signup ceremony expires midway;
- credential is already registered;
- synced passkey has zero/non-incrementing sign counter;
- passkey deleted from device but still registered server-side;
- user loses all passkey devices;
- attempted deletion of last usable login method;
- email/password account later adds passkey;
- passkey-first account later adds fallback password;
- password reset while active sessions exist;
- user changes primary email;
- invitation sent to alias email;
- upstream IdP email changes;
- duplicate identities;
- deleted account attempts recovery;
- browser auth completes after desktop device code expires.

## Acceptance criteria

- On a supported browser, passkey is visibly the first/default sign-up and sign-in option.
- User can create an account with a passkey, sign out, and sign back in without typing an email or password.
- Email/password is visibly the second option and can register/login successfully.
- Unsupported/cancelled passkey flow falls back cleanly to password without losing entered non-secret account metadata.
- Passkey registration/login rejects challenge replay, expired ceremony, wrong RP ID/origin, missing required user verification, invalid signature, and unknown/revoked credential.
- A client cannot authenticate as another user by supplying a different `user_id`.
- Multiple passkeys can be added/revoked without allowing accidental account lockout.
- Password is never stored/logged in plaintext or with a fast raw hash.
- Password login/reset uses generic failure behavior where enumeration matters.
- Existing cookie/session/CSRF and desktop PKCE semantics remain compatible.
- Revoking the device/session prevents further refresh.
- Linking a second identity cannot hijack an existing unrelated user.
- Cross-user session token substitution returns 401/403 and logs security telemetry.

## Implementation note for Cloudflare Workers

Before choosing Rust libraries for WebAuthn verification or Argon2id, P02-BE-05 MUST prove:

1. dependency compiles for `wasm32-unknown-unknown`;
2. Worker dry-run/build succeeds;
3. WebAuthn registration + assertion verify end-to-end with server-side ceremony state;
4. password KDF fits real Worker CPU/memory limits at the required security parameters;
5. bundle/performance impact is acceptable.

If those tests fail, stop and write an ADR. Do not implement authentication crypto manually and do not silently lower security parameters.

## References

- MDN Web Authentication API: https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API
- MDN passkeys: https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Passkeys
- FIDO passkeys: https://fidoalliance.org/passkeys/
- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- Cloudflare Workers Rust: https://developers.cloudflare.com/workers/languages/rust/
