# P02 authentication upgrade — Phase 0 audit

- Date: 2026-09-25
- Scope: additive P02-CR-002 upgrade; no historical P02 packet is rewritten.
- Evidence basis: current `main` plus the in-progress P04 worktree changes. P04 files were left intact.

## Current signup and email verification

- `POST /api/v1/auth/signup` is handled by `apps/api/src/routes/auth.rs`.
- It validates and normalizes email, validates display name, applies the existing signup rate bucket, rejects an existing normalized email, generates `usr_`/`idn_` IDs, and inserts `users`, the initial email `identities` row, a `verification` `auth_challenges` row, and an immutable `identity.created.v1` event in one D1 batch.
- It does not create a session. The raw verification code is delivered through the existing email adapter and is only returned in development.
- `POST /api/v1/auth/verify-email` loads the challenge, requires the `verification` kind and a `user_id`, consumes a hashed code with the existing bounded-attempt update, then verifies the matching user/identity and appends `identity.verified.v1`.
- A consumed verification challenge is idempotently accepted when the user can still be read.

## Current login and session lifecycle

- `POST /api/v1/auth/login/start` requires email, applies the existing login rate bucket, creates a short-lived hashed `login` challenge, and delivers an email code for a known user.
- `POST /api/v1/auth/login/complete` requires the challenge kind/status and consumes the hashed code, then creates the existing revocable `LoginSession` and sets the existing cookies.
- `create_session` in `auth.rs` is the current session authority: it creates a new opaque session token and CSRF token, stores only SHA-256 hashes, records device/platform metadata, writes the session plus immutable event/outbox rows in a D1 batch, and returns the raw values only to the cookie-setting response.
- `POST /api/v1/auth/refresh` requires the current session and CSRF, creates a replacement session, and revokes the old row in the same batch.
- `require_session` reads the `lumi_session` cookie or bearer token, hashes it, reads the active D1 row, checks expiry/revocation, and rehydrates the principal from the database. Role or email claims are not accepted from the token.

## CSRF and reauthentication

- Authenticated mutations use `require_session` plus `require_csrf`.
- `lumi_csrf` is a readable cookie paired with `X-CSRF-Token`; values are compared in constant time and the header digest must equal the session's stored CSRF hash.
- `POST /api/v1/account/reauth` currently requires a session and CSRF, validates a purpose allowlist, and issues a five-minute one-time `ReauthenticationGrant` containing only a token hash server-side. The current implementation does not itself perform a credential assertion; it is a session-bound grant factory.
- Existing org/lifecycle/identity-link routes consume the grant with user ID, session ID, purpose, token hash, and expiry. The authenticator upgrade must add an actual passkey/password step-up before consuming grants for passkey/password changes.

## Identity linking

- `POST /api/v1/me/identities/link/start` requires a verified current email, a current session, CSRF, a matching non-conflicting normalized email, and a consumed `identity_link` reauth grant. It creates a hashed email challenge and sends the code.
- `POST /api/v1/me/identities/link` requires the same session/CSRF, challenge ownership/kind/status, a valid code, and a second conflict check. It creates a new email identity and appends immutable event/outbox rows; it never auto-merges accounts.
- The existing `identities` table is intentionally separate from authenticator credentials. The upgrade must add credential tables rather than adding passkey/password fields to `users` or `identities`.

## Desktop PKCE

- `POST /api/v1/auth/device-code` creates a pending device authorization with hashed user/device codes, an S256 PKCE challenge, device label, and ten-minute expiry.
- Authenticated `POST /api/v1/auth/device-code/approve` binds the authorization to the current principal.
- `POST /api/v1/auth/device-code/exchange` validates the verifier hash, atomically consumes the approved authorization, creates a desktop `LoginSession`, and sets the same session/CSRF cookies.
- This protocol is independent of the human authentication method. Passkey or password browser authentication must only precede approval; the PKCE exchange and device authorization tables remain unchanged.

## Account security UI and API

- `apps/web/src/features/account/account-panel.tsx` displays active sessions and recent immutable security events and can revoke a session or request a reauth grant.
- The current panel has no passkey, password, identity-management, or credential-recovery controls.
- `apps/web/src/features/auth/auth-screen.tsx` is an email-code-first login/signup screen. It has no WebAuthn adapter, conditional mediation, password path, or recovery states.

## Schema and migrations

- `0001_p01_foundation.sql` establishes the P01 platform primitives.
- `0002_p02_identity_organizations.sql` creates users, identities, auth challenges, login sessions, organizations, memberships, invitations, teams, reauth grants, device authorizations, and immutable security events.
- `0003_p02_auth_rate_limits.sql` adds server-digested D1 rate buckets.
- `0004_p02_identity_link_challenges.sql` adds the `identity_link` challenge kind.
- `0005_p02_multiple_email_identities.sql` removes the one-email-per-user constraint while retaining global provider-subject uniqueness.
- `0006_p02_device_consumed_state.sql` preserves approved user/session bindings through device-code consumption.
- The current worktree also contains uncommitted `0007_p04_ai_platform.sql`; it is unrelated P04 work and must be preserved. The auth upgrade should use the next available additive migration number after the coordinated migration set, not rewrite these files.
- D1 is canonical; SQL is bound through the repository/adapter boundary and invariant-bearing batches are used for mutations.

## Existing rate limits

- Signup: server-digested bucket `signup:<normalized-email>`, five attempts per 15-minute window.
- Legacy email login start: server-digested bucket `login:<normalized-email>`, ten starts per 15-minute window.
- Email challenges: maximum ten failed/consumed attempts, with one-time conditional consumption.
- Device authorization has bounded expiry and one-time conditional consumption, but no separate passkey ceremony or password credential bucket exists.
- The upgrade needs independent bounded buckets for passkey start/complete, password signup/login/forgot/reset, and recovery, without persisting raw email/IP values.

## Existing security-event coverage

- Existing immutable events include identity creation/verification/linking, legacy login completion, logout/session rotation, session revocation, reauthentication grant creation, organization/membership/team lifecycle, and device approval.
- The upgrade should add versioned passkey/password/recovery events through the same `SecurityEventRepository` and, where appropriate, the existing outbox path.
- The request boundary logs only bounded transport dimensions; no raw body, credential, token, or secret is logged.

## Smallest safe extension points

1. Add a sibling `authenticator` domain module and D1 repository for credential/ceremony state; do not overload `Identity` or `User`.
2. Add one additive migration after the coordinated P04 migration number with `passkey_credentials`, `webauthn_ceremonies`, and `password_credentials`; use a narrowly scoped recovery table only if the existing challenge model cannot safely express the state.
3. Wrap the maintained `passkey-auth` verifier behind a small adapter configured only from trusted environment variables for RP ID/name/origin. Keep library types out of domain and wire contracts.
4. Use Argon2id 19 MiB / t=2 / p=1 (with encoded PHC parameters) only after the Worker/WASM benchmark spike passes; do not add a fallback fast hash.
5. Reuse the existing session creation, cookie, CSRF, device-PKCE, security-event, and outbox paths. Extract only the small shared session helper needed to avoid a parallel session system.
6. Add the frozen additive routes in `app.rs` and the focused auth/account API client, then replace only the everyday auth panel and extend the existing account panel.
7. Add a coordinator-owned handoff/evidence file for runtime, QA, browser, and performance results. Historical P02 packet files and the original P02 integration gate remain immutable.

## Audit conclusion

The completed P02 foundation is suitable for an additive passkey/password upgrade. The smallest safe change is a new credential/ceremony persistence and verifier boundary that feeds the existing `LoginSession` authority. The main implementation risk is not session or organization compatibility; it is proving the crypto/KDF runtime and making ceremony consumption, credential ownership, and last-method protection atomic and hostile-tested.
