# F10 — AI Inference Router / Proxy

Priority: P0  
Depends on: F04, F09, F11, F12, F21, F23

## Objective

Cung cấp một **vendor-neutral AI inference gateway** cho Lumi Agents, đặt policy, auth, budgets, provider credentials, routing, retries, failover, streaming telemetry và cost attribution vào một control point.

The public contract is Lumi-owned even if an implementation internally uses Cloudflare AI Gateway features.

## Design principles

1. Client requests **capability/alias**, not raw secret.
2. Routing policy is server-side, versioned and auditable.
3. Streaming must remain streaming; gateway must not buffer the full response.
4. No unsafe fallback after meaningful output has been emitted.
5. Provider-specific behavior stays behind adapters.
6. Request/response content logging is opt-in by policy; metadata telemetry is separate.
7. Budget enforcement and routing are concurrency-safe enough to prevent obvious overspend races.

## Public endpoints

P0:

- `POST /api/v1/inference/responses`
- `POST /api/v1/inference/chat/completions` for OpenAI-compatible clients
- `GET /api/v1/inference/models`
- `GET /api/v1/inference/routes/:alias` subject to permission

The native Lumi endpoint SHOULD converge on a response/event model expressive enough for text, tool calls, reasoning metadata and multimodal inputs.

## Request context

Every call MUST resolve:

```text
principal
org_id
project_id
device/service identity
model_alias
route_version
policy snapshot
budget scope(s)
request_id
optional session_id/run_id
```

## Routing pipeline

Recommended order:

1. Authenticate principal.
2. Resolve org/project.
3. Authorize `models.use` / `agents.run`.
4. Validate request schema/body size.
5. Apply model/tool/data policy.
6. Check entitlements.
7. Reserve rate/cost budget.
8. Resolve alias to immutable route version.
9. Filter candidates by capability.
10. Filter unavailable/disabled/cooldown providers.
11. Select candidate via strategy.
12. Resolve credential without exposing it.
13. Dispatch with timeout.
14. Retry/fallback only under safe conditions.
15. Stream response to caller.
16. Reconcile usage/cost reservation.
17. Emit immutable usage/audit/observability events.

## Route definition

A route is versioned and immutable after publish.

Example conceptual schema:

```json
{
  "alias": "coding-default",
  "version": 12,
  "strategy": "weighted-health-aware",
  "candidates": [
    {
      "provider": "provider-a",
      "model": "model-x",
      "weight": 70,
      "timeout_ms": 45000,
      "max_retries": 1
    },
    {
      "provider": "provider-b",
      "model": "model-y",
      "weight": 30,
      "timeout_ms": 45000,
      "max_retries": 1
    }
  ]
}
```

## Routing strategies

P0:

- fixed;
- ordered fallback;
- weighted random with health exclusion.

P1:

- latency-aware;
- rate-limit-aware;
- cost-aware;
- region/provider capacity aware;
- sticky routing for session cache locality where safe.

Do not start with a generic visual rules language. Store typed JSON route config first.

## Retry rules

Retry only when request semantics make retry safe.

Eligible examples:

- connect failure before provider accepted request;
- explicit provider 429/5xx according to policy;
- timeout before any response bytes/event.

Do NOT retry blindly:

- after tool side effects;
- after meaningful streamed content;
- if provider may have accepted a non-idempotent operation;
- when retry would exceed request deadline/budget.

Use bounded exponential backoff + jitter.

## Fallback rules

Fallback to another candidate only before the response is committed to the client unless protocol explicitly supports resumable semantics.

Cross-model fallback MUST satisfy required capabilities and policy.

Response metadata SHOULD indicate selected provider/model and fallback count to authorized callers without leaking credentials.

## Streaming

- Support SSE or protocol-appropriate streaming.
- Preserve backpressure.
- Emit first-byte/first-token timestamps.
- On downstream disconnect, cancel upstream request where possible.
- Final usage may arrive after stream completion; reconcile asynchronously if necessary.
- Do not log full chunks by default.

## Provider adapter contract

Each adapter implements:

```text
validate_request
translate_request
send
stream_decode
translate_response
classify_error
extract_usage
extract_provider_request_id
capabilities
```

Adapters MUST normalize provider errors into stable gateway errors while retaining internal raw details for observability.

## Credential modes

F11 controls:

- platform-managed;
- organization-managed BYOK;
- user BYOK;
- local-only/direct provider mode.

Recommended precedence is policy-driven, not hard-coded. The client never chooses a credential ID it is not authorized to use.

## Budget and rate limiting

Integrate F12 before dispatch.

Scopes MAY stack:

- platform;
- org;
- project;
- team;
- user;
- service account;
- model alias.

Use reservation for requests whose maximum cost can be bounded. Reconcile reservation to actual usage.

If authoritative budget state is unavailable, fail closed for hard budget mode; do not silently overspend.

## Caching

P1 and opt-in only.

Safe candidates:

- deterministic/non-sensitive requests;
- identical embedding-style calls;
- bounded product workflows with explicit cache key.

Cache key MUST include effective model/route version, relevant parameters and tenant/privacy scope.

Do not cache arbitrary confidential conversations by default.

## Prompt/response logging

Modes:

- metadata-only;
- redacted content;
- full content.

Default should be metadata-only for enterprise/control-plane telemetry.

Content retention is governed by F20.

## Guardrails

P1:

- body size limits;
- allowed model modalities;
- DLP/redaction hook;
- malware/file scanning before multimodal forwarding;
- prompt-injection policy hooks for tool-bearing workflows;
- destination allowlist for custom endpoints.

Guardrails cannot be marketed as absolute safety.

## Error model

Stable codes:

- `model_not_allowed`
- `route_unavailable`
- `provider_unavailable`
- `provider_rate_limited`
- `request_timeout`
- `budget_exceeded`
- `rate_limit_exceeded`
- `credential_unavailable`
- `unsupported_capability`
- `upstream_invalid_response`

Return a gateway `request_id` on all failures.

## Observability

Per request collect:

- request_id;
- org/project/principal hashes/IDs according to privacy policy;
- alias/route version;
- selected provider/model;
- retries/fallbacks;
- HTTP/provider status class;
- TTFT;
- total latency;
- input/output tokens or provider usage;
- estimated/actual cost;
- cache status;
- budget decision.

## Web UX

- route list/detail;
- draft/publish/rollback route version;
- provider/model candidates;
- timeout/retry/fallback config;
- route health;
- usage/cost;
- test request with redacted payload;
- audit history.

P0 UI can be form-based. Visual node graph is not required.

## Security

- Upstream credentials resolved only inside trusted backend.
- Custom provider base URL must defend against SSRF.
- Never proxy arbitrary caller-supplied URL.
- Strip caller headers except an explicit allowlist.
- Generate outbound headers from adapter/credential policy.
- Enforce max request/response metadata size.
- Separate provider error details from client-facing error text.

## Deployment note

Current backend runs Rust on Cloudflare Workers.

Implementation MAY:

1. route directly to upstream providers using Worker fetch; or
2. send selected calls through Cloudflare AI Gateway for telemetry/retries/caching features.

The stable Lumi API and policy model MUST remain independent so implementation can switch later.

## Industry evidence

Patterns intentionally align with current gateway practice:

- Cloudflare AI Gateway: analytics/logging, retries, fallbacks, dynamic routing, rate/budget controls, caching and BYOK;
- LiteLLM: load balancing, cooldowns, timeouts, retries, routing strategies and hierarchical budgets;
- Vercel AI Gateway: stacked budget scopes.

References:
- https://developers.cloudflare.com/ai-gateway/
- https://developers.cloudflare.com/ai-gateway/features/dynamic-routing/
- https://developers.cloudflare.com/ai-gateway/configuration/request-handling/
- https://developers.cloudflare.com/ai-gateway/features/caching/
- https://docs.litellm.ai/docs/routing
- https://docs.litellm.ai/docs/proxy/users
- https://vercel.com/docs/ai-gateway/observability-and-spend/budgets

## Acceptance criteria

- One client endpoint can route to at least two providers without exposing provider secrets.
- A failed first provider can fallback before stream commit.
- No fallback happens after user-visible content has begun unless protocol explicitly supports it.
- Usage and cost are attributed to org/project/user/run.
- Budget denial occurs before upstream dispatch.
- Cross-tenant credential IDs cannot be used even if guessed.
- Route rollback restores prior immutable route version without redeploying desktop clients.
