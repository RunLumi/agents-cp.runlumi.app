# Plan 09 — Security, reliability, performance, release hardening

Status: Planned
Specs: all, especially F16, F20, F21, F22, F23, F24
Depends on: P02-P08 relevant MVP scope

## 1. Phase outcome

Convert "features work" into "system can be trusted in production".

No major new product feature belongs here.

## 2. Workstream clusters

### P09-SEC-01 — Tenant isolation audit

Inventory every org-owned resource and prove:

```text
external ID lookup
+ org scope
+ active principal/membership
+ permission
```

Automate cross-tenant ID-substitution tests.

### P09-SEC-02 — Secrets/auth audit

Review:

- logs;
- error bodies;
- traces;
- frontend storage;
- R2 exports;
- webhook payloads;
- crash telemetry;
- provider adapter errors.

Run secret-canary tests.

### P09-SEC-03 — SSRF/egress/tool abuse

Test:

- custom provider endpoints;
- MCP URLs;
- webhook URLs;
- localhost/private network/cloud metadata destinations;
- redirect chains;
- DNS rebinding assumptions where relevant.

### P09-REL-01 — Failure injection

Inject:

- D1 errors;
- provider timeouts;
- queue delay;
- duplicate queue delivery;
- R2 failure;
- webhook outage;
- revoked credential/device mid-request;
- partial streaming disconnect.

Verify bounded retry and consistent user state.

### P09-REL-02 — Backup/restore

Document and perform restore rehearsal.

Record measured RPO/RTO and update hypotheses.

### P09-PERF-01 — Web budgets

Measure production bundle and core flows:

- initial JS/CSS;
- LCP;
- INP;
- CLS;
- large members/runs/audit tables;
- route chunk sizes.

Remove decorative/heavy dependencies before raising budget.

### P09-PERF-02 — API/inference overhead

Measure:

- p50/p95 API latency;
- D1 query count/latency;
- inference gateway overhead;
- TTFT overhead;
- stream memory behavior;
- provider fallback overhead.

Use D1 read replication only if supported by the Rust binding path and measured read latency justifies it; preserve sequential-consistency semantics.

### P09-OPS-01 — Observability/SLO

Verify:

- request IDs;
- correlation;
- error-rate dashboards;
- provider health;
- queue lag;
- budget denies;
- security alerts;
- dead-letter visibility.

### P09-QA-01 — End-to-end critical journeys

Automate representative journeys:

1. signup -> org -> invite;
2. desktop enroll -> project bind;
3. configure model/credential -> managed inference;
4. managed run -> tool approval -> usage;
5. budget denial;
6. scheduled automation;
7. revoke device/member/credential;
8. export/delete;
9. migration from local state.

## 3. Release gates

### Gate A — Functional

All P0 acceptance criteria satisfied.

### Gate B — Security

No known critical/high tenant-isolation, auth, secret-exposure or remote-code policy bypass issue.

### Gate C — Performance

No unexplained regression against `AGENTS.md` budgets.

### Gate D — Operations

On-call/operator can answer:

- what is failing?
- which tenant/provider?
- since when?
- blast radius?
- safe rollback/kill switch?

### Gate E — Rollback

Every release has:

- Worker rollback path;
- compatible DB migration strategy;
- client compatibility window;
- route/policy rollback;
- provider kill switch.

## 4. Final release artifacts

- architecture map;
- schema/migration map;
- threat model;
- runbook;
- incident checklist;
- backup/restore instructions;
- SLO dashboard references;
- known limitations;
- client compatibility matrix;
- data retention map.

## 5. Release principle

Do not trade tenant isolation or secret safety for launch speed.

Do trade non-essential enterprise polish for a smaller, observable, reversible release.
