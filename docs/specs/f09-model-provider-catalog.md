# F09 — Model & Provider Catalog

Priority: P0  
Depends on: F04, F11

## Objective

Tạo catalog canonical cho provider/model capabilities để Lumi Agents không hard-code provider logic trong desktop UI hay từng agent runtime.

## Entities

```text
Provider
ProviderEndpoint
Model
ModelAlias
ModelCapability
ProviderHealth
CatalogVersion
```

## Requirements

### FR-F09-001 — Provider registry

Control plane maintains a provider registry with stable provider IDs independent of display name.

Provider may represent:

- OpenAI-compatible HTTP API;
- Anthropic-style API;
- Gemini-style API;
- Z.ai/GLM;
- self-hosted endpoint;
- local-only provider reference;
- future custom adapter.

### FR-F09-002 — Model records

Model metadata SHOULD include:

- provider model ID;
- display name;
- input/output modalities;
- streaming support;
- tool/function calling;
- reasoning/thinking controls;
- max input/context and max output where known;
- structured output capability;
- image/audio support;
- pricing metadata/version;
- lifecycle: active/deprecated/disabled.

### FR-F09-003 — Aliases

Clients SHOULD request a stable `model_alias` or route alias such as:

- `coding-default`
- `coding-fast`
- `coding-deep`
- `vision-default`

Alias resolves server-side to F10 routing policy.

Do not force client upgrades when upstream provider renames or replaces a model.

### FR-F09-004 — Capability-based selection

Agent/tool can declare required capabilities. Router MUST exclude models that cannot satisfy them.

### FR-F09-005 — Org allowlist

Org/project policy can restrict usable aliases/providers/models.

### FR-F09-006 — Catalog distribution

Desktop receives a signed/versioned policy/catalog snapshot containing only metadata it is permitted to see.

### FR-F09-007 — Provider health

Store rolling health metadata:

- success rate;
- timeout rate;
- rate-limit signals;
- first-token latency;
- completion latency.

Health is an input to routing but not exposed as precise vendor SLA unless measured reliably.

## ZCode compatibility

ZCode already has provider registry/model selection/account-provider concepts. Preserve external provider/model identifiers and add a mapping layer rather than rewriting local provider selection immediately.

## Web UX

- model/provider list;
- enabled/disabled state;
- aliases/routes;
- capability filters;
- pricing source timestamp;
- provider health indicator.

## Acceptance criteria

- Disabling provider/model prevents new routed runs without breaking historical records.
- Renaming display name does not change stable IDs.
- Alias changes do not require desktop release.
