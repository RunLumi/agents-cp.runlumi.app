# /goal 08 — Complete P08 LumiAgents Migration and Adoption

You are the **P08 phase coordinator and migration lead** across:

- `RunLumi/agents-cp.runlumi.app`
- `RunLumi/LumiAgents`

Complete `docs/implementation/plan08-lumiagents-migration-adoption.md`.

## Mission

Make the transition from local-first ZCode/LumiAgents to org-aware Lumi Agents **boring, explicit, reversible, and privacy-preserving**.

Existing local users must not be forced into a big-bang cloud migration.

## Read first

- `AGENTS.md`
- Plan00 and P08
- F26 Migration
- integration requirements from F03–F19
- handoffs from P03–P07
- current LumiAgents/ZCode local persistence/provider/session/automation code
- license/provenance constraints when modifying forked code

## Required adoption path

Preserve this staged model:

```text
existing local user
→ optional account
→ optional device enrollment
→ explicit org/project selection
→ explicit workspace binding
→ managed model/tool policy
→ optional history sync
```

Never silently skip stages by uploading existing state.

## Contract Gate

Freeze:

- client protocol version range;
- policy schema compatibility range;
- external-ID mapping;
- local/unmanaged vs org-managed states;
- workspace binding;
- credential migration choices;
- automation import format;
- compatibility/degraded-mode error codes.

## Control-plane packets

Implement only missing migration/compatibility endpoints:

- protocol compatibility;
- migration-stage telemetry;
- remediation state;
- version/degraded-mode signaling.

Avoid duplicating APIs already provided by P03–P07.

## LumiAgents packets

Implement:

- optional account path;
- resumable enrollment wizard;
- clear local vs managed ownership labels;
- explicit workspace binding;
- explicit credential migration choices;
- automation import with conflict preview;
- optional history sync only when data governance is mature;
- clean unbind/rollback;
- offline startup semantics.

## Privacy invariants

Never automatically upload:

- local API keys;
- historical prompts;
- files;
- automations;
- MCP credentials;
- workspace contents.

Telemetry measures stage/result, not user content.

## Migration matrix

Test realistic existing states:

- fresh install;
- long-lived sessions;
- multiple local workspaces;
- local BYOK;
- custom MCP;
- browser/computer permissions;
- scheduled tasks;
- remote workspaces;
- offline startup;
- interrupted enrollment;
- rollback at each stage.

## Integration Gate

Using realistic pre-org local state, prove:

1. upgraded client starts normally;
2. old local session still opens;
3. sign-in is optional where product policy permits;
4. one device/workspace can become managed;
5. managed inference/tool policy works there;
6. another workspace can remain local;
7. unbind/rollback preserves local data;
8. no secret/history uploads without explicit choice.

## Completion

Migration is complete only when users do not need to understand control-plane topology to adopt the managed experience.

Do not optimize migration metrics at the expense of consent or reversibility.
