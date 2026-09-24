# /goal 04 — Complete P04 Model Catalog, Secrets, and AI Inference Router/Proxy

You are the **P04 phase coordinator and implementation lead**.

Complete `docs/implementation/plan04-ai-platform-catalog-secrets-inference.md` end-to-end.

This phase is a core technical moat. Prioritize correctness, streaming behavior, latency, secret safety, and vendor-neutral contracts.

## Preconditions

P02 must be complete.

P03 may be running concurrently. Coordinate only on shared project/device/policy extension contracts, never by editing each other's frozen definitions independently.

## Read first

- `AGENTS.md`
- Plan00 and P04
- F09 Model & Provider Catalog
- F10 AI Inference Router / Proxy
- F11 Credentials, Secrets & BYOK
- F12 usage/budget foundations
- F21 observability
- F23 API contracts
- P02 stable principal/org/authz contracts
- P03 policy extension contract if available
- relevant ADRs and current provider/model code in LumiAgents/ZCode

## Mission

Ship a Lumi-owned inference control plane where clients can call stable Lumi aliases and the backend:

- authorizes the request;
- selects an allowed route;
- resolves credentials without exposing them;
- routes to multiple upstream providers;
- streams without unnecessary buffering;
- safely retries/falls back only before response commitment;
- records health/usage metadata;
- supports platform/org/user/local credential modes;
- lets routes change without desktop client releases.

The public Lumi contract must not be coupled to Cloudflare AI Gateway or any specific upstream vendor.

## Contract Gate

Freeze P04-CG:

- Provider
- Model
- ModelAlias
- capabilities
- Credential metadata/ownership/version
- Route / immutable RouteVersion
- provider adapter contract
- native inference request/event/error envelope
- OpenAI-compatible supported subset
- normalized upstream error taxonomy
- usage event skeleton
- budget hook interface
- policy snapshot extension for model/credential mode

## Parallel packets

### MOD
- provider/model catalog
- credential domain
- route compiler/selector
- retry/fallback state machine

### BE
- catalog/route APIs
- encrypted secret adapter
- provider adapters
- streaming inference gateway
- provider health/cooldown

### FE
- providers/models
- credentials
- routing editor/history/rollback

### INT
- managed inference path in LumiAgents
- mapping existing ZCode provider/model identities to Lumi aliases

### QA
- streaming/fallback/security/SSRF/secret tests

## Critical routing invariant

Model the response lifecycle explicitly:

```text
not_dispatched
→ dispatched_no_output
→ stream_committed
→ completed | failed
```

Fallback may occur only where F10 permits.

Never "helpfully" retry onto another model after meaningful streamed output or a potentially side-effectful request has committed.

## Secret invariants

- raw provider secret never enters normal frontend state;
- raw secret is not returned after creation;
- credential IDs are tenant-scoped;
- adapter resolves plaintext only at the trusted outbound boundary;
- errors/logs are redacted;
- custom endpoints cannot turn the gateway into SSRF or a secret-exfiltration proxy.

## Performance

Measure gateway overhead separately from provider latency.

Preserve streaming/backpressure.

Do not add expensive abstractions to the hot path without evidence.

## Integration Gate

Prove:

1. Org configures managed provider credential.
2. `coding-default` has two candidates.
3. LumiAgents sends streaming request by alias.
4. Gateway selects provider and streams output.
5. Forced pre-stream failure falls back safely.
6. Usage metadata is attributed.
7. Admin rolls back route version.
8. Client needs no upgrade for the route change.

## Completion

P04 is complete only when P05 can rely on stable:

- model aliases;
- inference request IDs;
- provider adapters;
- credential resolution;
- route versioning;
- usage hooks;
- policy integration;
- safe retry/fallback semantics.

Do not stop when "one provider works".
