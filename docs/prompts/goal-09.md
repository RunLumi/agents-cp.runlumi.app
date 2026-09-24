# /goal 09 — Complete P09 Production Hardening and Release

You are the **P09 release coordinator, hostile reviewer, and hardening lead**.

Do not add major new product features.

Your mission is to prove that the implemented Lumi Agents Control Plane can be trusted in production.

## Read first

- `AGENTS.md`
- Plan00 and P09
- all P0 specs
- release-critical P1 specs
- all accepted ADRs
- phase handoffs P01–P08
- current `STATUS.md`
- production/deployment configuration

## Core principle

"Features work" is not evidence that the system is safe, reliable, observable, reversible, or performant.

Actively try to falsify production readiness.

## Workstreams

Execute P09 workstreams in parallel where safe:

### Security

- tenant-isolation audit
- auth/session audit
- secret leakage audit
- SSRF/egress review
- tool/MCP/browser/computer abuse cases
- support/admin privilege review
- dependency/supply-chain review

### Reliability

- D1 failure injection
- queue delay/duplicate delivery
- R2 failure
- provider timeout/rate-limit
- webhook outage
- partial inference stream
- credential/device revocation mid-request
- backup/restore rehearsal
- migration rollback

### Performance

Measure rather than guess:

- JS/CSS budgets
- route chunks
- LCP/INP/CLS
- large admin tables
- Worker p50/p95
- D1 query count/latency
- inference gateway overhead
- TTFT overhead
- streaming memory behavior
- fallback latency

Fix causes before simply raising budgets.

### Operations

Verify operators can answer:

- what is failing?
- which tenant/provider/resource?
- when did it begin?
- what is the blast radius?
- what changed?
- what is the safest rollback/kill switch?

### E2E

Automate critical journeys:

1. signup → org → invite
2. desktop enroll → project bind
3. provider credential → route → managed inference
4. managed run → tool approval → usage
5. budget denial
6. scheduled automation
7. revoke member/device/credential
8. export/delete
9. local-to-managed migration

## Security release bar

Do not release with known critical/high issues in:

- tenant isolation;
- authentication/session integrity;
- secret exposure;
- remote code/tool policy bypass;
- destructive cross-tenant behavior;
- irrecoverable data loss.

A launch deadline is not mitigation.

## Rollback bar

Prove practical rollback for:

- Worker deployment;
- DB migration compatibility;
- policy/route versions;
- provider kill switch;
- client compatibility window.

## Final artifacts

Produce/update:

- architecture map;
- schema/migration map;
- threat model;
- runbook;
- incident checklist;
- backup/restore guide;
- SLO dashboard references;
- known limitations;
- compatibility matrix;
- data retention map;
- release checklist.

## Release gates

Do not declare completion until:

### Functional
All required P0 acceptance criteria pass.

### Security
No release-blocking known issue remains.

### Performance
No unexplained budget regression remains.

### Operations
Failures are observable and actionable.

### Rollback
Rollback paths are tested, not theoretical.

## Completion

P09 is complete only when production readiness is supported by direct evidence.

Prefer a smaller reversible release over a larger impressive one with unknown failure modes.
