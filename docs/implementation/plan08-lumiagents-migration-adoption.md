# Plan 08 — LumiAgents integration, migration, adoption

Status: Planned
Specs: F26 plus integration requirements from F03-F19
Depends on: P03-P07 relevant capabilities

## 1. Phase outcome

Ship an org-aware LumiAgents version that existing ZCode/LumiAgents users can adopt incrementally without a big-bang migration.

This plan primarily targets the `RunLumi/LumiAgents` repo plus compatibility contracts in the control plane.

## 2. Migration principle

The upgrade path is:

```text
existing local user
→ optional account
→ optional device enrollment
→ explicit org/project selection
→ explicit workspace binding
→ managed model/tool policy
→ optional history sync
```

Never invert this into "sign in and we uploaded everything".

## 3. Contract Gate — P08-CG

Freeze:

- supported client protocol versions;
- minimum/maximum policy schema versions;
- external-ID mapping;
- local-only vs managed resource states;
- workspace binding record;
- credential migration choices;
- automation import format;
- compatibility error codes.

## 4. Control-plane lane

### P08-BE-01 — Compatibility endpoints

Add only migration/sync endpoints not already covered by P03-P06.

### P08-BE-02 — Client-version compatibility

Return:

- supported protocol range;
- required upgrade;
- degraded/local-only eligibility;
- policy schema version.

### P08-BE-03 — Migration telemetry

Collect stage/result counts without collecting local content.

## 5. LumiAgents integration lane

### P08-INT-01 — Account optionality

Local-only launch path remains functional according to product decision.

Sign-in is not allowed to corrupt old state.

### P08-INT-02 — Enrollment wizard

Steps:

1. sign in;
2. select/create org;
3. enroll device;
4. choose workspace;
5. map/create project;
6. review model/tool policy;
7. choose credential mode;
8. finish.

Wizard is resumable.

### P08-INT-03 — Local/cloud ownership markers

Runtime/UI clearly distinguishes:

- local unmanaged;
- org-managed;
- local credential;
- managed inference;
- policy-limited capability.

### P08-INT-04 — Credential migration

Never upload existing local secret automatically.

Choices:

- keep local;
- register metadata only;
- explicitly copy to org credential store.

### P08-INT-05 — Automation import

Show policy conflicts before import.

Existing local automation remains untouched until successful import.

### P08-INT-06 — Optional history sync

Ship only after data-retention controls are mature.

Default no historical bulk upload.

## 6. Frontend lane

### P08-FE-01 — Adoption status

Control plane shows:

- enrolled devices;
- client versions;
- migration stage;
- policy compatibility;
- workspace bindings.

### P08-FE-02 — Migration remediation

Admin/user can understand:

- outdated client;
- failed policy sync;
- missing credential;
- unsupported capability;
- unbound workspace.

## 7. QA lane

Build a migration matrix across representative existing states:

- fresh install;
- old sessions;
- many workspaces;
- local BYOK;
- custom MCP;
- browser/computer permissions;
- local automations;
- remote workspace;
- offline startup;
- interrupted enrollment.

Test rollback after every stage.

## 8. Integration Gate

Take a copy of realistic pre-org local state and prove:

1. new client starts;
2. local session still opens;
3. user optionally signs in;
4. enrolls one device/workspace;
5. managed inference/tool policy works there;
6. another local workspace stays unmanaged;
7. rollback/unbind leaves local data usable;
8. no secret/history uploaded without explicit choice.

## 9. Exit criteria

Migration must be boring.

If adoption requires users to reason about backend topology, the integration is not finished.
