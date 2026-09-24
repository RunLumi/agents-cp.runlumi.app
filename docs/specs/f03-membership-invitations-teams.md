# F03 — Membership, Invitations & Teams

Priority: P0  
Depends on: F01, F02, F04

## Objective

Quản lý người dùng trong organization với invitation flow an toàn và team grouping đủ nhẹ để dùng cho permissions, budgets và routing.

## Entities

```text
Membership
Invitation
Team
TeamMember
```

## Requirements

### FR-F03-001 — Member directory

Admins can list/search active, invited, suspended and removed members.

### FR-F03-002 — Invitations

Invitation MUST include:

- org;
- target email;
- intended role;
- inviter;
- expiration;
- single-use random token hash;
- status.

Invitation token MUST not contain authorization claims trusted without database lookup.

### FR-F03-003 — Accept invitation

Acceptance requires the logged-in user's verified email to match invitation target unless an explicit admin-approved transfer flow exists.

Duplicate accept is idempotent.

### FR-F03-004 — Invite lifecycle

States:

- pending
- accepted
- expired
- revoked

Admin can resend by rotating token/expiry, not by reusing stale secret.

### FR-F03-005 — Member removal

Removing a member MUST:

- terminate org-scoped active sessions/refresh scopes as appropriate;
- revoke org API/service delegation owned solely by that membership;
- remove team memberships;
- preserve audit history;
- apply resource transfer rules from F07.

### FR-F03-006 — Leave organization

Member may leave unless they are last owner or organizational policy prevents self-leave.

### FR-F03-007 — Teams

Admins can create teams used for:

- project access;
- routing/budgets;
- policies;
- directory organization.

Avoid nested teams in MVP.

### FR-F03-008 — Bulk operations

P1: CSV/bulk invite and bulk team assignment with partial-failure report.

## Web UX

- `/org/:slug/members`
- `/org/:slug/teams`
- invite dialog;
- role/team change dialog;
- pending invite table;
- member detail drawer.

## Failure modes

- invite email case/alias differences;
- two admins invite same email simultaneously;
- invitation accepted while role changed;
- member removed while active inference stream exists;
- owner demotion race.

Use DB uniqueness + transaction + idempotency, not frontend locks.

## Acceptance criteria

- Duplicate invitation create yields existing pending invite or deterministic conflict.
- Revoked/expired token cannot join org.
- Removed member loses org access without deleting immutable audit records.
- Concurrent role edits cannot result in zero owners.
