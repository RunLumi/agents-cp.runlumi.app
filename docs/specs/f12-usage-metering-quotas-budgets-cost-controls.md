# F12 — Usage Metering, Quotas, Budgets & Cost Controls

Priority: P0  
Depends on: F02, F08-F10

## Objective

Đo và giới hạn tài nguyên AI theo org/project/team/user/agent/model mà không phụ thuộc hoàn toàn vào invoice của provider.

## Entities

- UsageEvent
- CostRecord
- Budget
- BudgetReservation
- RateLimitPolicy
- UsageRollup
- PricingVersion

## Requirements

### FR-F12-001 — Immutable raw usage

Every inference/run emits immutable usage event with:

- request/run ID;
- org/project;
- principal;
- model/provider/route;
- input/output/cached tokens where available;
- provider-reported usage;
- estimated cost;
- currency/pricing version;
- timestamp.

### FR-F12-002 — Pricing version

Never recompute historical cost using today's price without labeling it as recalculation.

Store pricing source/version/effective time.

### FR-F12-003 — Budget scopes

P0:

- organization;
- project;
- user/service account.

P1:

- team;
- agent;
- model alias.

### FR-F12-004 — Hard and soft limits

- soft: notify/mark only;
- hard: block new eligible work;
- optional fallback: route to an approved lower-cost/free route.

### FR-F12-005 — Reservation

Before dispatch, estimate maximum or bounded expected cost and reserve against hard budgets when feasible.

After completion:

- commit actual;
- release unused reservation;
- release/mark failed reservation.

Reservation expiry handles crashed requests.

### FR-F12-006 — Rate limits

Support at least:

- requests/minute;
- tokens/minute;
- concurrent inference requests.

Policies stack by scope; the most restrictive applicable limit wins unless product explicitly defines another rule.

### FR-F12-007 — Usage rollups

Async rollups by hour/day/month for dashboards.

Raw event remains source of truth for reconciliation window.

### FR-F12-008 — Provider reconciliation

P1 compare internal usage/cost with provider invoice/export where API exists.

Discrepancy is surfaced, not silently overwritten.

## Web UX

- current spend/usage;
- trend;
- by project/user/model/provider;
- budget progress;
- denied requests;
- reset period;
- CSV export.

## Failure policy

If hard budget state cannot be checked reliably, fail closed for expensive cloud inference and expose `budget_state_unavailable`.

Avoid failing closed for unrelated local-only execution.

## Acceptance criteria

- Concurrent requests cannot trivially bypass a hard budget by checking stale pre-request spend.
- Every F10 request is attributable to one org/project/principal.
- Historical usage remains explainable after provider price changes.
