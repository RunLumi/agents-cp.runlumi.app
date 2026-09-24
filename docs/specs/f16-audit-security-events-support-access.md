# F16 — Audit Logs, Security Events & Support Access

Priority: P0  
Depends on: F01-F05

## Objective

Cho organization trả lời được: **ai đã làm gì, với resource nào, khi nào, từ đâu, kết quả gì, dưới policy nào**.

## Event classes

- authentication/security;
- membership/role;
- org/project settings;
- credential lifecycle;
- model route/policy;
- device enrollment/revocation;
- agent/run/tool approvals;
- billing/budget;
- data export/deletion;
- support access.

## Requirements

### FR-F16-001 — Immutable audit event

Fields:

- event_id;
- timestamp;
- org_id;
- actor type/id;
- effective user if delegated;
- device/session/request ID;
- action;
- resource type/id;
- outcome;
- reason/error code;
- important before/after metadata with secret redaction;
- correlation/run ID.

Normal product APIs cannot mutate/delete individual audit rows.

### FR-F16-002 — Append path

Security-critical mutation should write audit event transactionally where practical, or through durable outbox guaranteeing eventual append.

### FR-F16-003 — Search/export

Admins with permission can filter by:

- actor;
- action;
- resource;
- outcome;
- time;
- correlation/run.

P1 export in CSV/JSON.

### FR-F16-004 — Security events

Security events may trigger F17 notification and higher retention.

### FR-F16-005 — Support access

Internal support access MUST:

- be explicit;
- require reason/ticket;
- use short-lived scoped grant;
- be visible in customer audit;
- avoid secret access by default;
- support customer-disable policy where feasible.

No permanent "god mode" shared account.

## Privacy

Audit metadata should identify actions without unnecessarily storing prompt/file content.

## Acceptance criteria

- Role change, credential rotation, route publish and device revocation create auditable events.
- Support impersonation/access is distinguishable from customer actor.
- Audit viewer cannot reveal masked secrets.
