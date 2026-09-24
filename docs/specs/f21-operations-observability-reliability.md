# F21 — Operations, Observability & Reliability

Priority: P0  
Depends on: all backend features

## Objective

Có đủ telemetry và failure isolation để vận hành control plane + inference gateway ở production mà không log quá mức hay làm tăng latency đáng kể.

## Golden signals

Track by service/route:

- request rate;
- error rate;
- latency;
- saturation/concurrency;
- upstream provider health;
- Worker CPU/duration where available;
- queue lag;
- database latency/errors;
- inference TTFT/stream duration;
- budget/rate-limit denials.

## Requirements

### FR-F21-001 — Correlation ID

Every external request gets a stable `request_id`.

Propagate through:

- API handler;
- DB/outbox;
- inference upstream;
- queue/background job;
- audit/usage events.

### FR-F21-002 — Structured logs

Logs are structured and include bounded dimensions.

Never include:

- raw auth header;
- secret;
- refresh token;
- full prompt/response by default;
- arbitrary uploaded file contents.

### FR-F21-003 — Metrics cardinality

Do not use raw user/project/request IDs as unbounded metric labels.

High-cardinality data belongs in logs/traces/events.

### FR-F21-004 — Tracing

P1 distributed tracing across API -> upstream/provider -> queue where platform support makes it useful.

Sampling policy increases on error/slow requests without storing sensitive body.

### FR-F21-005 — Health

Expose:

- liveness;
- readiness where meaningful;
- dependency-specific internal health for ops.

Public health MUST not leak credentials/topology.

### FR-F21-006 — Timeouts

Every outbound network dependency has explicit timeout.

No request may wait forever on provider/webhook/external API.

### FR-F21-007 — Retries

Only idempotent/safe operations retry automatically.

Use bounded exponential backoff + jitter.

### FR-F21-008 — Circuit/cooldown

AI providers and unstable integrations may enter temporary cooldown after repeated classified failures.

Do not globally circuit-break one tenant due to tenant-specific credential failure.

### FR-F21-009 — Queues/jobs

Background jobs use durable queue/outbox semantics.

Each job MUST be idempotent or carry dedupe key.

Dead-letter/failure state must be observable and replayable where safe.

### FR-F21-010 — SLOs

Initial targets:

- control-plane read API availability >= 99.9% monthly after production launch;
- p95 normal control-plane API < 200 ms excluding external provider delay;
- inference gateway overhead target < 50 ms p95 excluding provider/network;
- no single provider outage should cause total inference outage when route has healthy fallback.

Targets are hypotheses and should be revised from measured data.

### FR-F21-011 — Backup/restore

Persistent primary data requires:

- automated backup;
- restore procedure;
- periodic restore test;
- stated RPO/RTO.

Initial target hypothesis:

- RPO <= 15 min for transactional control-plane data;
- RTO <= 4 h.

## Cloudflare-specific guidance

Use platform-native telemetry where appropriate, but preserve vendor-neutral event schemas for Lumi business telemetry.

## Acceptance criteria

- One request can be traced from API through inference/usage/audit via correlation IDs.
- Secret redaction tests exist.
- Queue failures are visible before users report them.
