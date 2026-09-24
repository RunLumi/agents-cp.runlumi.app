# F02 — Organization & Tenant Lifecycle

Priority: P0  
Depends on: F01, F04

## Objective

Tạo một tenant boundary rõ ràng cho mọi cloud-managed resource của Lumi Agents.

## Model

```text
Organization
├── Memberships
├── Teams
├── Projects
├── Policies
├── Credentials
├── Usage/Budgets
├── Audit Events
└── Devices/Service Accounts
```

Recommend one organization model with `kind = personal | team` instead of maintaining two authorization stacks.

## Requirements

### FR-F02-001 — Organization creation

Verified user MAY create an organization subject to product limits.

Required fields:

- display name;
- immutable `org_id`;
- unique mutable slug;
- creator membership as owner.

### FR-F02-002 — Tenant scoping

Every org-owned table/entity MUST include immutable `org_id` or derive ownership through a parent with enforced foreign-key/resource lookup.

### FR-F02-003 — Active org context

Every org-scoped API request MUST resolve explicit org context from route/token/header approved by F23.

The backend MUST reject stale/mismatched org context instead of silently falling back.

### FR-F02-004 — Organization lifecycle

States:

- `active`
- `suspended`
- `pending_deletion`
- `deleted`

Suspension blocks mutations/inference according to policy but retains recoverability.

### FR-F02-005 — Ownership

An organization MUST have at least one active owner.

Removing/demoting the last owner MUST fail transactionally.

### FR-F02-006 — Ownership transfer

Owner transfer requires:

- current owner authorization;
- target active member;
- recent re-authentication;
- security/audit event.

### FR-F02-007 — Deletion

Org deletion uses staged process:

1. re-auth + typed confirmation;
2. mark `pending_deletion`;
3. revoke new inference and sensitive mutations;
4. configurable grace period;
5. asynchronous deletion/tombstoning;
6. final deletion certificate/event.

## Data constraints

- Unique slug among non-deleted orgs.
- Membership uniqueness on `(org_id, user_id)`.
- Resource references cannot cross org boundaries.
- Org state changes use optimistic concurrency/version.

## Web UX

- organization switcher;
- create org;
- org profile/settings;
- danger zone;
- ownership transfer;
- suspension/deletion status.

## Security invariants

- Any query by external resource ID MUST additionally scope by org.
- Do not rely on UI filtering.
- Background jobs carry immutable `org_id`.
- Cache keys MUST contain org scope.

## Acceptance criteria

- A user in Org A cannot read or mutate any Org B resource by guessing ID.
- Last owner cannot leave/delete themselves until another owner exists.
- Pending deletion blocks new long-running work.
- Switching org invalidates stale project/member caches in the web client.
