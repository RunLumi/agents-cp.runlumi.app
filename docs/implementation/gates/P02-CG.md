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

Default role IDs: `owner`, `admin`, `member`, `viewer`. P02 permissions: `org.read`, `org.manage`, `members.read`, `members.manage`, `teams.read`, `teams.manage`, `audit.read`. Owner has all P02 permissions and minimum ownership recovery; admin has all except ownership-only transfer; member has `org.read`, `members.read`, `teams.read`; viewer has read-only permissions.

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
| POST | `/auth/device-code` | anonymous | `{device_name,code_challenge,code_challenge_method}` | `201 {device_authorization,user_code,verification_uri,expires_at}` |
| POST | `/auth/device-code/approve` | session | `{device_authorization_id}` | `204` |
| POST | `/auth/device-code/exchange` | anonymous | `{device_code,code_verifier}` | `200 {session}` + device cookies |
| POST | `/orgs` | verified session | `{display_name,slug?}` | `201 {organization,membership}` |
| GET | `/orgs` | session | — | `200 Page<OrganizationSummary>` |
| GET | `/orgs/:org_id` | `org.read` | — | `200 Organization` |
| PATCH | `/orgs/:org_id` | `org.manage` | `{display_name?,slug?,version}` | `200 Organization` |
| GET | `/orgs/:org_id/members` | `members.read` | `limit?,cursor?` | `200 Page<Member>` |
| POST | `/orgs/:org_id/invitations` | `members.manage` | `{email,role}` | `201 Invitation`; dev-only token |
| POST | `/invitations/:invitation_id/accept` | verified session | `{}` | `200 {organization,membership}` |
| PATCH | `/orgs/:org_id/members/:member_id` | `members.manage` | `{role,version}` | `200 Member` |
| DELETE | `/orgs/:org_id/members/:member_id` | `members.manage` | version/If-Match | `204` |
| POST | `/orgs/:org_id/ownership-transfer` | `org.manage` + reauth | `{target_member_id,reauth_grant_id,version}` | `200 {organization,membership}` |
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

Migration `0002_p02_identity_organizations.sql` creates all P02 tables with `org_id` on tenant-owned rows, normalized-email/slug uniqueness, `(org_id,user_id)` membership uniqueness, one-time hash uniqueness, state checks, and indexes for org/member/session/audit lookups. D1 is canonical; invariant-bearing mutations use D1 batches and conditional version predicates. There is no KV authorization cache, Durable Object database, or process-global tenant state.

P01 clients remain compatible: P01 errors, IDs, pagination, idempotency, and outbox shapes do not change. P02 adds only `/api/v1` routes and optional fields. A required contract change must use `docs/implementation/templates/change-request.md` before dependent packets proceed.

## Freeze

- Contract Gate commit: recorded after this file is committed.
- Unlocked packets: P02-MOD-01..04, P02-BE-01..04, P02-FE-01..03, P02-INT-01, P02-QA-01.
- Shared files: P02 coordinator owns manifests, Wrangler config, router, module declarations, and STATUS.
