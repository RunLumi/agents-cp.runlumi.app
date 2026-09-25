# P02 downstream handoff — principal, organization, authorization

## Stable contracts

- Identity: `User`, `Identity`, `LoginSession`, `ReauthenticationGrant`, and `DeviceAuthorization` are D1-backed. IDs use the frozen P02 prefixes; session/token/grant values are opaque and only hashes are persisted.
- Session boundary: `Principal` is created only after a current D1 session lookup. Web cookies are `lumi_session` (HttpOnly) and `lumi_csrf`; protected mutations require the CSRF header. No client stores a token in localStorage or a URL.
- Tenant context: org-owned routes use `/api/v1/orgs/:org_id/...`; an optional `X-Org-ID` must match exactly. Every protected org handler resolves current active membership and calls `modules::authorization::authorize`.
- Authorization: default roles are `owner`, `admin`, `member`, `viewer`; stable P02 permissions are `org.read`, `org.manage`, `org.lifecycle`, `org.leave`, `org.ownership_transfer`, `members.read`, `members.manage`, `teams.read`, `teams.manage`, and `audit.read`. Unknown/stale/cross-org decisions deny.
- Invariants: org-owned rows carry `org_id`; membership uniqueness is `(org_id,user_id)`; last-owner demotion/removal is a conditional D1 update; invitation and device codes are one-time hashes; security events are immutable and material mutations also emit P01 outbox envelopes.
- Desktop: P03 must use `docs/contracts/desktop-auth-v1.md`; device approval is not managed-device enrollment or policy sync.

## API surfaces available to P03/P04

- Auth/session/account routes under `/api/v1/auth/*`, `/api/v1/me`, and `/api/v1/account/*`.
- Organization/member/invitation/team/audit routes under `/api/v1/orgs/:org_id/*`.
- Device handoff routes under `/api/v1/auth/device-code*`.
- P01 errors, request IDs, bounded page envelope, and migration conventions remain unchanged.

## Migration/runtime

- Apply `0002_p02_identity_organizations.sql`, `0003_p02_auth_rate_limits.sql`, `0004_p02_identity_link_challenges.sql`, `0005_p02_multiple_email_identities.sql`, then `0006_p02_device_consumed_state.sql` before P03 migrations.
- D1 `DB`, `OUTBOX_QUEUE`, and the optional production `EMAIL` send-email binding are configured. Production email requires an onboarded sender domain and `EMAIL_FROM`; development uses the explicit code fixture.
- New P02 events are accepted by the outbox consumer; unknown event types still dead-letter.

## Do not redefine

Do not put roles/permissions in trusted client claims, derive tenant access from email domain, accept a resource ID without an org predicate, or create a second authorization path in a handler. Extend the central policy module and use a Change Request for contract changes.

## Follow-up

- P03 consumes principal/org/authz/device handoff for managed device/project policy sync.
- P04 consumes the same tenant boundary for model, credential, inference, usage, and budget resources.
- P09 owns remote deployment, restore drills, SLOs, and final browser/accessibility evidence.
