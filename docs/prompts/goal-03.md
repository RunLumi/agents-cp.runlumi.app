# /goal 03 — Complete P03 Devices, Projects, Workspaces, and Policy Sync

You are the **P03 phase coordinator and implementation lead**.

Complete `docs/implementation/plan03-device-project-policy-sync.md`.

P03 may execute in parallel with P04, but only after P02 contracts are stable.

## Read first

- `AGENTS.md`
- Plan00 and P03
- F07 Projects/Workspaces
- F13 tool policy foundations
- F19 Device Enrollment & Policy Sync
- F26 migration foundations
- P02 Contract Gate/handoff
- current `RunLumi/LumiAgents` integration points where accessible
- relevant ADRs

## Mission

Make Lumi Agents desktop a revocable organization client without destroying local-first behavior.

A user must be able to:

- sign into the desktop client;
- enroll one device into an organization;
- explicitly bind one local workspace to one cloud project;
- report bounded capabilities;
- receive a versioned effective policy snapshot;
- be revoked remotely;
- continue to retain local data safely when managed access disappears.

## Contract Gate

Freeze P03-CG before lane implementation:

- Device;
- DeviceEnrollment;
- device credential/public-key semantics;
- capability snapshot;
- Project;
- WorkspaceBinding;
- project visibility/access;
- PolicySnapshot envelope/version/expiry;
- policy ACK;
- heartbeat/last-seen;
- revoke/error states;
- device/project API endpoints;
- extension points later used by P04/P05 for model/tool/budget policy.

Do not put model-routing internals into P03. Provide typed extension points.

## Execute parallel lanes

### MOD
- device state machine
- project/workspace ownership/access
- policy compiler

### BE
- device enrollment/heartbeat/revoke/policy APIs
- project/workspace APIs
- short-lived device token exchange

### FE
- projects
- devices
- read-only policy inspector

### INT
Work in LumiAgents integration path:
- browser login
- device key generation/storage
- enrollment
- capability report
- explicit workspace bind flow
- policy fetch/cache/ACK
- revocation behavior

### QA
Test policy replay, stale membership, revoked device, offline expiry, workspace cross-org binding, interrupted enrollment.

## Privacy constraints

Do not upload by default:

- raw local files;
- historical conversations;
- provider secrets;
- unrelated process/application inventory.

A workspace becomes org-managed only through explicit user binding.

## Offline semantics

Define them explicitly.

Never solve policy expiration by deleting or locking local files.

Managed high-risk/cloud operations may fail closed after policy expiry while local unmanaged behavior follows documented product rules.

## Integration Gate

Demonstrate:

1. LumiAgents browser-auths.
2. Device enrolls into Org A.
3. One local workspace binds to Project P.
4. Web control plane sees device and binding.
5. Device fetches policy N.
6. Admin revokes device.
7. Device cannot refresh managed access.
8. Local workspace remains intact and usable according to local-mode rules.

## Completion

P03 is complete only when P05 can rely on:

- stable device identity;
- project/workspace context;
- policy snapshot extension points;
- capability reports;
- reliable revocation.

Do not confuse "device listed in web UI" with managed-device security.
