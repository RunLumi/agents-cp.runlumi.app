# Plan 04 — Model catalog, credentials, AI inference router/proxy

Status: Planned
Specs: F09, F10, F11, F12 foundations, F21, F23
Depends on: P02
May run in parallel with: P03

## 1. Phase outcome

Lumi owns a stable inference API that can route one request through at least two providers without exposing provider credentials to clients, with immutable route versions, safe streaming/fallback, usage metadata, and org/project policy.

## 2. Contract Gate — P04-CG

Freeze:

- Provider/Model/ModelAlias schema;
- capabilities enum;
- Credential metadata/ownership modes;
- Route/RouteVersion schema;
- provider adapter interface;
- native inference request/event/error envelope;
- OpenAI-compatible endpoint subset;
- normalized upstream errors;
- usage event skeleton;
- budget decision hook interface.

## 3. Modules lane

### P04-MOD-01 — Provider/model catalog

Implement:

- providers;
- models;
- aliases;
- capabilities;
- lifecycle;
- org allowlist decision.

### P04-MOD-02 — Credential domain

Implement:

- platform/org/user/local-only metadata;
- version/rotation lineage;
- revoke;
- fingerprint/masking;
- precedence policy.

Plaintext resolution is an adapter concern.

### P04-MOD-03 — Route compiler/selector

Implement pure logic:

- immutable route version;
- candidate filtering by capability/policy;
- fixed;
- ordered fallback;
- weighted selection;
- provider cooldown/health input;
- deterministic test injection for selection.

### P04-MOD-04 — Retry/fallback state machine

Explicit states:

```text
not_dispatched
dispatched_no_output
stream_committed
completed
failed
```

Fallback allowed only where F10 permits.

This module must be heavily unit tested.

## 4. Backend lane

### P04-BE-01 — Catalog/route APIs

CRUD:

- provider/model metadata;
- aliases;
- route draft/publish/list/rollback;
- org/project enable/disable.

Publishing creates immutable route version.

### P04-BE-02 — Secret storage adapter

Implement encrypted storage with:

- ciphertext only in DB;
- key version;
- one-time input;
- no normal reveal;
- safe rotation/revoke;
- log redaction.

Do not invent browser-readable secret APIs.

### P04-BE-03 — Provider adapters

Start with the minimum provider set needed by Lumi.

Each adapter implements F10 contract:

- translate request;
- send;
- stream decode;
- normalize response/error;
- usage extraction;
- provider request ID.

### P04-BE-04 — Streaming gateway

Implement:

- `/api/v1/inference/responses`;
- OpenAI-compatible subset;
- SSE/streaming;
- backpressure;
- caller disconnect cancellation;
- timeout;
- fallback before stream commit;
- stable request ID.

### P04-BE-05 — Health/cooldown

Track provider health inputs without creating high-cardinality metric chaos.

Differentiate:

- platform/provider outage;
- tenant credential failure;
- request-specific validation failure.

Tenant credential failure must not globally circuit-break provider.

## 5. Frontend lane

### P04-FE-01 — Provider/model catalog

Admin pages:

- providers/models;
- capability/lifecycle;
- enabled state.

### P04-FE-02 — Credentials

Build:

- create secret;
- mask/fingerprint;
- validation state;
- rotate/revoke;
- last used.

No full secret redisplay.

### P04-FE-03 — Routing

Build form-based route editor:

- alias;
- candidates;
- order/weights;
- timeout/retry;
- publish;
- history;
- rollback;
- basic health.

No node-graph editor.

## 6. Integration lane

### P04-INT-01 — LumiAgents managed inference client

Add optional managed route path:

```text
LumiAgents
→ Lumi inference API
→ selected upstream provider
```

Preserve local/BYOK direct provider path where org policy permits.

### P04-INT-02 — Provider/model mapping

Map existing ZCode provider/model IDs to Lumi stable IDs/aliases without rewriting all local selection code.

Policy snapshot from P03 receives:

- allowed aliases/models;
- managed-vs-local credential mode;
- route version hints if needed.

## 7. QA lane

Mandatory cases:

- provider A fails before output -> provider B fallback;
- provider A emits content then fails -> no unsafe fallback;
- caller disconnect cancels upstream;
- timeout classification;
- guessed cross-org credential ID;
- revoked credential;
- model lacks required tool/vision capability;
- custom endpoint SSRF attempts;
- route rollback;
- no raw secret in logs.

## 8. Integration Gate

Demonstrate:

1. Org configures one managed credential/provider.
2. Route `coding-default` has two candidates.
3. LumiAgents sends streaming inference via alias.
4. Gateway selects provider and streams response.
5. Forced first-provider pre-stream failure falls back.
6. Usage event records org/project/user/run placeholder.
7. Admin rolls route back without client update.

## 9. Exit criteria

P05 can depend on:

- stable model alias;
- inference request ID;
- usage event;
- project/org model policy hook;
- credential resolution;
- route health/fallback semantics.
