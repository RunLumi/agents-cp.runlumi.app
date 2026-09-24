# F07 — Projects, Workspaces & Resource Ownership

Priority: P0  
Depends on: F02-F04

## Objective

Ánh xạ khái niệm ZCode workspace/project vào organization control plane mà không giả định mọi workspace đều nằm trên server.

## Key distinction

- **Project:** cloud-managed logical scope for policy, access, usage, agents and configuration.
- **Workspace:** execution context on a specific device/remote environment, often backed by a filesystem path or remote identity.

A project can have multiple workspace bindings across devices/environments.

## Entities

```text
Project
WorkspaceBinding
ResourceOwner
ProjectMember / ProjectTeamGrant
```

## Requirements

### FR-F07-001 — Project creation

Project belongs to exactly one org.

Fields:

- id;
- name;
- slug;
- visibility: org/restricted;
- default model route;
- policy version;
- archival state.

### FR-F07-002 — Workspace binding

Desktop client can register a workspace binding containing non-secret metadata:

- project_id;
- device_id;
- stable local workspace identity;
- display path/name;
- environment type: local/ssh/wsl/docker/remote;
- last seen.

Raw filesystem content MUST NOT be uploaded by default.

### FR-F07-003 — Ownership

Cloud resources created inside a project inherit `org_id` and `project_id`.

Personal user ownership may be recorded as creator/owner metadata, but tenant ownership remains organization.

### FR-F07-004 — Restricted projects

Access can be granted to specific members/teams.

Authorization remains server-side.

### FR-F07-005 — Archive

Archive prevents new agent runs/automations but preserves history and audit.

### FR-F07-006 — Member removal

Member-owned personal artifacts inside an org project remain organization-owned unless explicitly classified private before creation.

### FR-F07-007 — Workspace privacy

Control plane stores enough metadata to manage policy/device association but should not collect absolute local paths if a normalized display identifier suffices.

## Integration with ZCode

ZCode already carries real `workspacePath`, workspace identity and remote workspace/session concepts. Lumi should introduce a cloud project ID as an additional authority context, not replace the runtime's actual workspace identity.

## Web UX

- project list;
- project details;
- access/team assignments;
- connected workspaces/devices;
- model/tool policy;
- usage.

## Acceptance criteria

- Same physical workspace may bind to only one project per enrollment context unless user explicitly rebinds.
- Cross-org workspace binding is rejected.
- Restricted project is absent or permission-denied to unauthorized members without leaking sensitive metadata.
