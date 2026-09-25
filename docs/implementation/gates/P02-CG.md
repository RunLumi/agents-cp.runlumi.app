# Contract Gate — P02-CG

- Phase: P02 — Identity, organizations, membership, authorization
- Owner: P02 coordinator
- State: frozen
- Contract version: `p02-cg-v1`
- Inputs: Plan00, Plan02, F01–F05, F16, F23, ADR 0002/0004/0005, P01-CG `p01-cg-v1`, P01-IG PASS
- Shared-file owner: P02 coordinator

## Domain and IDs

Stable entities are `User`, `Identity`, `LoginSession`, `Organization`, `Membership`, `Invitation`, `Team`, `TeamMember`, `ReauthenticationGrant`, `DeviceAuthorization`, and immutable `SecurityEvent`.

P01 opaque resource IDs remain authoritative. P02 prefixes are `usr_`, `idn_`, `ses_`, `org_`, `mem_`, `inv_`, `team_`, `tmem_`, `rag_`, `dev_`, and `sec_`, each followed by 32 lowercase hexadecimal characters. IDs, email domains, frontend role labels, and token claims are never authorization evidence. Raw session, challenge, invitation, device, reauth, and CSRF values are never persisted or logged; only hashes are stored. P01 RFC3339 UTC timestamps and error envelope remain unchanged.

## States and invariants

- Organization: `active`, `suspended`, `pending_deletion`, `deleted`; mutations are versioned and lifecycle changes are audited.
- Membership: unique `(org_id,user_id)`; only `active` grants access; removal revokes org-scoped sessions and preserves audit history.
- Invitation: `pending`, `accepted`, `expired`, `revoked`; secret is single-use, resend rotates it, accept requires a verified matching email, and duplicate accept is idempotent.
- Session: `active`, `revoked`, `expired`; refresh rotates the opaque session and old state cannot refresh.
- Device authorization: `pending`, `approved`, `consumed`, `expired`, `revoked`; exchange is one-time and PKCE-bound.
- An organization always has at least one active owner. Demotion, removal, or leave of the last owner fails atomically.

## Central authorization

```text
authorize(principal, explicit_org, active_membership, permission, resource_context)
  -> Allow | Deny(reason)
```

The decision includes principal, org state, membership role/status/version, stable permission, resource type/id/org, and optional team/project scope. It denies unknown permissions, missing context, inactive membership, suspended/pending-deletion orgs, stale membership, and resource-org mismatch. Every protected route uses this service; handlers do not compare role strings.

Default role IDs: `owner`, `admin`, `member`, `viewer`. P02 permissions: `org.read`, `org.manage`, `org.lifecycle`, `org.leave`, `org.ownership_transfer`, `members.read`, `members.manage`, `teams.read`, `teams.manage`, `audit.read`. Owner has all P02 permissions and minimum ownership recovery; admin has all except lifecycle/ownership transfer; member has `org.read`, `org.leave`, `members.read`, `teams.read`; viewer has read-only permissions plus `org.leave`.

Stable denial/lifecycle reasons in `error.details.reason`: `email_verification_required`, `membership_required`, `permission_denied`, `org_context_mismatch`, `resource_scope_mismatch`, `organization_suspended`, `organization_pending_deletion`, `last_owner_required`, `invitation_expired`, `invitation_revoked`, `invitation_replayed`, `invitation_email_mismatch`, `identity_conflict`, `session_revoked`, `session_expired`, `reauthentication_required`, `device_code_expired`, `device_code_replayed`, and `version_conflict`.

## API

All routes are under `/api/v1`, use JSON, return P01 errors, and include `X-Request-ID`. Org routes always carry `org_id` in the path; a header org must exactly match it.

| Method | Path | Permission/context | Request | Success |
|---|---|---|---|---|
| POST | `/auth/signup` | anonymous | `{email,display_name}` | `201 {user,verification}`; dev-only code |
| POST | `/auth/verify-email` | anonymous | `{challenge_id,code}` | `200 {user}` |
| POST | `/auth/login/start` | anonymous | `{email}` | `202 {challenge_id,expires_at}`; dev-only code |
| POST | `/auth/login/complete` | anonymous | `{challenge_id,code}` | `200 {user}` + session cookies |
| POST | `/auth/logout` | session | `{}` | `204` |
| POST | `/auth/refresh` | session | `{}` | `200 {user}` + rotated cookies |
| GET | `/me` | session | — | `200 {user,organizations}` |
| POST | `/me/identities/link/start` | session + reauth | `{email,reauth_grant_id,reauth_token}` | `202 ChallengeResponse`; dev-only code |
| POST | `/me/identities/link` | session + link challenge | `{challenge_id,code}` | `201 {identity}` |
| POST | `/auth/device-code` | anonymous | `{device_name,code_challenge,code_challenge_method}` | `201 {device_authorization,user_code,verification_uri,expires_at}` |
| POST | `/auth/device-code/approve` | session | `{user_code}` | `204` |
| POST | `/auth/device-code/exchange` | anonymous | `{device_code,code_verifier}` | `200 {session}` + device cookies |
| POST | `/orgs` | verified session | `{display_name,slug?}` | `201 {organization,membership}` |
| GET | `/orgs` | session | — | `200 Page<OrganizationSummary>` |
| GET | `/orgs/:org_id` | `org.read` | — | `200 Organization` |
| PATCH | `/orgs/:org_id` | `org.manage` | `{display_name?,slug?,version}` | `200 Organization` |
| GET | `/orgs/:org_id/members` | `members.read` | `limit?,cursor?` | `200 Page<Member>` |
| POST | `/orgs/:org_id/invitations` | `members.manage` | `{email,role}` | `201 Invitation`; dev-only token |
| GET | `/orgs/:org_id/invitations` | `members.read` | `limit?,cursor?` | `200 Page<Invitation>` |
| DELETE | `/orgs/:org_id/invitations/:invitation_id` | `members.manage` | — | `204` |
| POST | `/orgs/:org_id/invitations/:invitation_id/resend` | `members.manage` | `{}` | `200 Invitation`; dev-only token |
| POST | `/invitations/:invitation_id/accept` | verified session | `{token}` | `200 {organization,membership}` |
| PATCH | `/orgs/:org_id/members/:member_id` | `members.manage` | `{role,version}` | `200 Member` |
| DELETE | `/orgs/:org_id/members/:member_id` | `members.manage` | version/If-Match | `204` |
| POST | `/orgs/:org_id/ownership-transfer` | `org.ownership_transfer` + reauth | `{target_member_id,reauth_grant_id,reauth_token}` | `200 {organization,membership}` |
| POST | `/orgs/:org_id/leave` | `org.leave` | `{}` | `204` |
| POST | `/orgs/:org_id/suspend` | `org.lifecycle` + reauth | `{version,reauth_grant_id,reauth_token}` | `200 Organization` |
| POST | `/orgs/:org_id/resume` | `org.lifecycle` + reauth | `{version,reauth_grant_id,reauth_token}` | `200 Organization` |
| POST | `/orgs/:org_id/deletion` | `org.lifecycle` + reauth | `{version,reauth_grant_id,reauth_token,confirmation}` | `200 Organization` |
| GET/POST | `/orgs/:org_id/teams` | `teams.read` / `teams.manage` | cursor / `{name,slug}` | page / `201 Team` |
| POST/DELETE | `/orgs/:org_id/teams/:team_id/members` | `teams.manage` | `{member_id}` | `201 TeamMember` / `204` |
| GET | `/orgs/:org_id/audit` | `audit.read` | cursor/filter | `200 Page<AuditEvent>` |
| GET | `/account/sessions` | session | — | `200 Page<SessionSummary>` |
| DELETE | `/account/sessions/:session_id` | session | — | `204` |
| POST | `/account/sessions/revoke-all` | session | `{}` | `204` |
| POST | `/account/reauth` | session | `{}` | `201 {grant,expires_at}` |

Invitation create/accept, org create, role/removal, ownership transfer, session revoke, and device exchange require `Idempotency-Key` where retries can duplicate effects. Error `details.reason` is stable; `error.code` remains the P01 status-level code.

## Audit and desktop handoff

Material auth, org, membership, role, session, and device mutations append immutable `security_events`; safe versioned events use P01 `EventEnvelope`/outbox. Event names include `identity.created.v1`, `auth.login.completed.v1`, `auth.logout.v1`, `organization.created.v1`, `membership.invited.v1`, `membership.accepted.v1`, `membership.role_changed.v1`, `membership.removed.v1`, `session.revoked.v1`, `reauthentication.granted.v1`, and `device_code.approved.v1`. No normal product API updates/deletes audit rows.

Desktop flow is create pending code → authenticated browser approval → one-time PKCE exchange. No long-lived token is placed in a browser URL. Managed device enrollment and policy sync remain P03.

## Persistence

Migration `0002_p02_identity_organizations.sql` creates the base P02 tables; `0003_p02_auth_rate_limits.sql` adds bounded auth buckets; `0004_p02_identity_link_challenges.sql` extends the challenge kind for verified identity linking; `0005_p02_multiple_email_identities.sql` permits multiple verified email identities per user while retaining global provider-subject uniqueness; `0006_p02_device_consumed_state.sql` preserves the approved user binding when a device authorization is consumed. All tenant-owned rows carry `org_id`; normalized-email/slug uniqueness, `(org_id,user_id)` membership uniqueness, one-time hash uniqueness, state checks, and indexes are enforced. D1 is canonical; invariant-bearing mutations use D1 batches and conditional version predicates. There is no KV authorization cache, Durable Object database, or process-global tenant state.

P01 clients remain compatible: P01 errors, IDs, pagination, idempotency, and outbox shapes do not change. P02 adds only `/api/v1` routes and optional fields. A required contract change must use `docs/implementation/templates/change-request.md` before dependent packets proceed.

## P02-CR-001 clarifications

- Browser session cookie: `lumi_session`, opaque revocable value, `HttpOnly`, `Path=/`, `SameSite=Lax`, 30-day maximum; production adds `Secure`. The non-HttpOnly `lumi_csrf` cookie is paired with `X-CSRF-Token` on every cookie-authenticated mutation. Access/refresh material is never placed in a URL or local storage.
- Refresh rotates the session row and revokes the old row. A revoked/expired row is filtered during the current D1 lookup. Auth rate limits use a D1-backed, server-digested 15-minute bucket (5 signup attempts and 10 login starts per normalized identity bucket); the raw email/IP is not persisted.
- `X-Org-ID`, when supplied, must exactly equal the `:org_id` path. A mismatch is `org_context_mismatch`; there is no fallback.
- Identity linking is challenge-based: a current session, CSRF, and a short-lived reauthentication grant with purpose `identity_link` start a one-time email challenge; the final link consumes that challenge and its code. A verified identity already owned by another user returns `identity_conflict` and is never merged.
- Invitation administration includes list, revoke, and resend. Resend rotates the token hash and expiry; accepted invitations cannot be replayed. Member leave uses the same last-owner guard as removal.
- Owner-only `org.lifecycle` permits `active -> suspended`, `suspended -> active`, and `active -> pending_deletion` after reauth and typed confirmation. The centralized policy still denies ordinary mutations while suspended/pending deletion.
- The complete default matrix is: Owner = all P02 permissions including `org.lifecycle`, `org.leave`, and ownership transfer; Admin = org/member/team/audit management plus `org.leave` but not lifecycle or ownership transfer; Member = `org.read`, `org.leave`, `members.read`, `teams.read`; Viewer = the same read set plus `org.leave`. Unknown permissions and stale membership versions deny.
- P02 list responses use the P01 `Page<T>` envelope. The first slice accepts a bounded `limit` and rejects non-empty cursors with `invalid_cursor`; downstream packets must add opaque cursor encoding rather than exposing offsets.
- P01 idempotency storage is used only for secret-free response projections. Auth, invitation, device, and reauth one-time flows never persist raw secrets in an idempotency response.

## Freeze

- Contract Gate commit: `ba35fb6`; P02-CR-001 clarification merged at `0290e68` (`p02-cg-v1`).
- Unlocked packets: P02-MOD-01..04, P02-BE-01..04, P02-FE-01..03, P02-INT-01, P02-QA-01.
- Shared files: P02 coordinator owns manifests, Wrangler config, router, module declarations, and STATUS.
