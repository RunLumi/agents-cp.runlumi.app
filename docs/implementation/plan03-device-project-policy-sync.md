# Plan 03 — Devices, projects, workspaces, policy sync

Status: Planned
Specs: F07, F13 foundations, F19, F26 foundations
Depends on: P02
May run in parallel with: P04

## 1. Phase outcome

A signed-in Lumi Agents desktop instance can enroll as a revocable organization device, bind an explicit local workspace to a cloud project, receive a versioned managed policy snapshot, and be revoked safely.

No historical prompts/files/secrets are uploaded automatically.

## 2. Contract Gate — P03-CG

Freeze:

- `Device` and enrollment state;
- device public-key/fingerprint model;
- capability snapshot schema;
- `Project`;
- `WorkspaceBinding`;
- project visibility;
- policy snapshot envelope/version;
- policy ACK;
- revoke/error states;
- device/project API endpoints.

Policy payload initially contains placeholders for model/tool policy sections owned by P04/P05.

## 3. Modules lane

### P03-MOD-01 — Device domain

Implement:

- enrollment state machine;
- device credential/public-key rules;
- revoke;
- heartbeat/last-seen;
- minimum client-version evaluation.

### P03-MOD-02 — Project/workspace domain

Implement:

- org-owned project;
- restricted/org visibility;
- explicit workspace binding;
- archive;
- access grants to members/teams.

### P03-MOD-03 — Policy compiler

Input:

- org;
- membership;
- project;
- device capabilities;
- current policy versions.

Output:

- immutable/versioned effective snapshot.

Start with identity/project/device rules; P04/P05 later add model/tool sections through typed extension points.

## 4. Backend lane

### P03-BE-01 — Device APIs

Implement:

- begin/complete enrollment;
- list/detail;
- heartbeat;
- capability report;
- revoke;
- policy fetch/ack.

### P03-BE-02 — Project/workspace APIs

Implement CRUD/access/bind/unbind/archive.

Absolute filesystem paths should not be required if stable normalized workspace identity is enough.

### P03-BE-03 — Short-lived device token exchange

Prefer device-bound/asymmetric identity to permanent API key.

Token exchange checks:

- device active;
- membership active;
- org active;
- app version acceptable.

## 5. Frontend lane

### P03-FE-01 — Projects

Build:

- list/create;
- access;
- workspace/device bindings;
- archive state.

### P03-FE-02 — Devices

Build:

- enrolled devices;
- owner/platform/version/capabilities;
- last seen;
- revoke;
- policy status.

### P03-FE-03 — Policy visibility

Read-only effective policy inspector first.

Do not build a generic policy-language editor.

## 6. LumiAgents integration lane

### P03-INT-01 — Browser auth + enrollment client

In `RunLumi/LumiAgents` later integration PR:

- browser login;
- one-time exchange;
- generate/persist device key;
- enrollment confirmation;
- refresh short-lived device auth.

### P03-INT-02 — Capability report

Map existing ZCode/LumiAgents runtime facts:

- OS/arch;
- browser use;
- computer use;
- remote workspace support;
- CLI/runtime version.

Do not report unrelated local inventory.

### P03-INT-03 — Workspace binding

Add explicit user flow:

```text
local workspace
→ choose/create org project
→ review metadata
→ bind
```

Never silently bind all existing workspaces.

### P03-INT-04 — Policy sync

Client:

- fetches policy;
- validates org/device/version/expiry;
- ACKs version;
- caches only safe offline snapshot;
- fails closed for managed high-risk actions after expiry;
- never deletes local data on policy loss.

## 7. QA lane

Mandatory:

- replay policy for another org/device;
- revoked device token exchange;
- stale membership;
- device version below minimum;
- same workspace bound across org incorrectly;
- enrollment interrupted mid-flow;
- policy fetch unavailable/offline semantics.

## 8. Integration Gate

Real vertical slice:

1. user logs into LumiAgents;
2. enrolls device to Org A;
3. binds one local workspace to Project P;
4. admin sees device/workspace in web;
5. device fetches policy version N;
6. admin revokes device;
7. device can no longer refresh managed access;
8. local workspace remains intact.

## 9. Exit criteria

P05 can rely on:

- stable device identity;
- project/workspace context;
- policy snapshot extension mechanism;
- revocation;
- runtime capability report.
