# F26 — Migration from Local ZCode State to Org-aware Lumi Agents

Priority: P0  
Depends on: F01-F25

## Objective

Nâng fork từ local-first ZCode lên org-aware Lumi Agents mà **không yêu cầu big-bang migration**, không upload local data ngoài ý muốn và giữ đường rollback.

## Current-state assumptions from ZCode

Observed concepts include:

- local workspace paths/identities;
- session/task snapshots and SQLite indexes;
- model/provider registry;
- account-provider/coding-plan credentials;
- MCP config;
- browser/computer-use capabilities;
- cron/off-peak automations;
- remote workspace/session runtimes.

The migration MUST respect these as existing local facts.

## Migration stages

### Stage 0 — Unmanaged compatibility

Existing Lumi Agents runs without sign-in for local-only mode if product decision permits.

No cloud state required.

### Stage 1 — Account optional

User signs in.

Cloud stores user/account/device identity, but existing local workspaces/sessions remain local.

### Stage 2 — Org enrollment

User enrolls device into org.

Client receives policy snapshot.

Existing workspace is not automatically attached to org.

### Stage 3 — Explicit workspace/project binding

User chooses which local workspace maps to which cloud project.

Show exactly what metadata will sync.

### Stage 4 — Managed inference/policy

Selected projects may use:

- org model routes;
- org credentials;
- usage/budgets;
- tool policy.

Local BYOK remains available only if org policy permits.

### Stage 5 — Optional history sync

Conversation/run metadata/content can be synced according to explicit org/user policy.

No default bulk upload of historical prompts/files.

## Requirements

### FR-F26-001 — External IDs

Cloud records preserve mapping to existing ZCode/Lumi local identifiers where necessary for resume/debugging.

### FR-F26-002 — No silent ownership conversion

A local workspace/session does not become org-owned merely because user signs in.

Binding must be explicit.

### FR-F26-003 — Secret migration

Never upload existing local provider secret without explicit user action and destination explanation.

Support metadata-only registration/fingerprint.

### FR-F26-004 — Automation migration

Existing local automations remain local until imported.

Import flow shows:

- schedule;
- target workspace;
- tool/model requirements;
- org policy conflicts.

### FR-F26-005 — Schema versioning

Client/cloud sync payloads have explicit schema versions and compatibility handling.

### FR-F26-006 — Rollback

If control-plane enrollment fails:

- local state remains intact;
- cloud binding can be removed;
- client can return to unmanaged/local mode where product policy permits.

### FR-F26-007 — Conflict handling

Cloud policy is authoritative for managed org operations.

Local user preferences remain authoritative for local-only concerns.

Do not create silent last-write-wins between conceptually different scopes.

### FR-F26-008 — Telemetry

Migration metrics:

- signed-in devices;
- enrolled devices;
- bound projects/workspaces;
- migration failures by stage;
- policy incompatibility;
- secret import decline/acceptance.

Do not count content itself.

## Web/Desktop UX

Desktop enrollment wizard:

1. Sign in
2. Choose/create org
3. Enroll device
4. Select workspace(s)
5. Map/create projects
6. Review model/tool policy
7. Choose credential mode
8. Finish

Each step is resumable.

## Acceptance criteria

- Existing local project opens after installing org-aware version without forced migration.
- No local secret/history uploads without explicit action.
- Enrollment rollback does not corrupt local SQLite/session state.
- Managed project policy cannot be bypassed by stale local config once device has valid active policy.
