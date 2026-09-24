# F04 — Authorization & Policy Engine

Priority: P0  
Depends on: F02, F03

## Objective

Một authorization model đủ đơn giản để đúng, nhưng đủ mở để áp dụng lên projects, models, tools, devices và budgets.

## Decision

MVP uses **RBAC + scoped resource checks + explicit policy attributes**, not a fully generic ABAC language.

Default roles:

- Owner
- Admin
- Member
- Viewer

Later custom roles MAY be added without changing permission identifiers.

## Permission namespace

Examples:

```text
org.read
org.manage
members.read
members.manage
projects.create
projects.read
projects.manage
agents.run
agents.manage
models.use
models.manage
credentials.manage
usage.read
budgets.manage
audit.read
devices.manage
billing.manage
```

Permissions are stable strings and versioned as product capabilities evolve.

## Requirements

### FR-F04-001 — Server-side authorization

Every protected backend operation MUST call one authorization decision function/policy interface.

### FR-F04-002 — Resource scope

Decision inputs include:

- principal;
- org membership;
- permission;
- resource type/id;
- resource org;
- project/team scope where applicable;
- entitlement/policy context where relevant.

### FR-F04-003 — Deny by default

Unknown permission, missing context or inconsistent resource scope MUST deny.

### FR-F04-004 — Owner invariants

Owner retains minimum capabilities needed to prevent lockout. Custom policy cannot accidentally remove ability to recover organization ownership.

### FR-F04-005 — Project access

Project visibility modes:

- org
- restricted

Restricted project may grant access to members/teams with read/manage/run permissions.

### FR-F04-006 — Policy precedence

Recommended:

```text
hard platform security deny
> organization explicit deny
> project/tool/model restrictions
> role grants
> default deny
```

Explicit denies are reserved for a small documented set to avoid impossible-to-debug policy graphs.

### FR-F04-007 — Explainability

Backend SHOULD return machine-readable denial reason, e.g.:

- `membership_required`
- `permission_denied`
- `project_access_denied`
- `model_not_allowed`
- `budget_exceeded`

Do not leak existence of inaccessible resources where that becomes an IDOR oracle.

## Caching

Permission caching is allowed only if cache key includes:

- user/principal;
- org;
- membership version;
- relevant policy version.

Role changes MUST invalidate or rapidly expire decisions.

## Testing

Each protected resource requires:

- owner/admin/member/viewer positive matrix;
- cross-tenant ID substitution;
- removed membership;
- stale membership version;
- restricted project;
- suspended org.

## Acceptance criteria

No handler is considered complete if it directly checks `role == "admin"` instead of using the authorization layer, except bootstrap internals explicitly documented.
