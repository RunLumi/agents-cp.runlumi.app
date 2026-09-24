# F20 — Data Governance, Export, Retention & Deletion

Priority: P1  
Depends on: F02, F08, F16

## Objective

Định nghĩa dữ liệu nào Lumi thu thập, giữ bao lâu, ai có thể export/delete, và cách xóa mà không phá audit/security obligations.

## Data classes

1. Account/identity data
2. Organization configuration
3. Workspace/device metadata
4. Conversation/prompt/response content
5. Run/tool/artifact metadata
6. Uploaded artifacts
7. Usage/billing records
8. Audit/security events
9. Secrets/credentials
10. Operational logs/traces

Each class has explicit retention and deletion rules.

## Requirements

### FR-F20-001 — Data classification

Every new persistent data type MUST declare:

- owner/scope;
- sensitivity;
- default retention;
- deletion behavior;
- export behavior;
- whether it may appear in logs.

### FR-F20-002 — Content logging modes

Per org/project:

- metadata-only;
- redacted content;
- full content.

Metadata-only should be the default for inference/control-plane observability unless product requirements say otherwise.

### FR-F20-003 — User export

User can export personal account data and organization-owned data only according to org permission.

### FR-F20-004 — Organization export

Authorized org admin can request async export containing documented data categories.

Export artifact:

- encrypted/access-controlled;
- short-lived URL;
- expiry;
- audit event.

### FR-F20-005 — Deletion

Deletion pipelines are asynchronous and idempotent.

Track deletion job state and failures.

### FR-F20-006 — Legal/security retention

Some audit/billing/security data may outlive user/org deletion where legally/security justified.

Such retained records should minimize personal content and use tombstoned identifiers where practical.

### FR-F20-007 — Artifact deletion

Deleting DB metadata is insufficient if object/blob copies remain.

Deletion job traverses durable storage/cache/search indexes/derived copies.

### FR-F20-008 — Backups

Deletion from active data propagates to backup lifecycle according to documented retention; backups are not selectively rewritten if operationally unsafe, but expired backups must disappear on schedule.

### FR-F20-009 — Provider data

UI/docs distinguish Lumi retention from upstream AI provider retention/data-use policy.

BYOK does not automatically imply zero upstream retention.

## Web UX

- privacy/data settings;
- conversation logging mode;
- export request/history;
- delete org/account workflow;
- retention summary.

## Acceptance criteria

- New persistent schema cannot be considered complete without data-class declaration.
- Export cannot include another org's data.
- Deleted artifact references do not leave publicly reachable blob URLs.
