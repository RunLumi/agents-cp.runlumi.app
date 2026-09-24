# F22 — Web Control Plane UX & Information Architecture

Priority: P0  
Depends on: F01-F21

## Objective

Tạo admin/control surface nhanh, dense, predictable cho operator và organization admin. Đây là operations software, không phải marketing dashboard.

## Information architecture

Recommended top-level:

```text
Organization switcher
├── Overview
├── Projects
├── Agents / Runs
├── Members & Teams
├── Models & Routing
├── Usage & Budgets
├── Automations
├── Devices
├── Integrations / MCP
├── Audit Log
└── Settings
    ├── General
    ├── Security / Identity
    ├── Credentials
    ├── Billing
    ├── Data / Retention
    └── Webhooks
```

Account-level pages live outside org navigation.

## Requirements

### FR-F22-001 — Org switcher

Switcher always shows current org.

Switching clears/refetches org-scoped data and route context.

No stale data flash from prior org.

### FR-F22-002 — Permission-aware navigation

Hide actions user clearly cannot perform, but backend remains authoritative.

When direct URL is denied, show explicit 403 state rather than redirect loop.

### FR-F22-003 — Page states

Every data surface defines:

- skeleton/loading;
- empty;
- error with retry;
- permission denied;
- stale/refreshing where relevant.

### FR-F22-004 — Tables

Large directories/logs use:

- server pagination;
- URL-backed filters;
- sortable supported columns;
- search where meaningful;
- sticky headers only when useful;
- no full dataset download into browser.

### FR-F22-005 — Mutations

Use optimistic UI only when rollback is unambiguous.

Security/billing/role changes should normally confirm server result before claiming success.

### FR-F22-006 — Destructive actions

Use consequence-oriented confirmation:

- what will stop;
- what data remains;
- whether reversible;
- required typed confirmation/re-auth.

### FR-F22-007 — Accessibility

Target WCAG 2.2 AA behavior for critical flows.

- keyboard reachable;
- visible focus;
- semantic structure;
- screen-reader labels;
- adequate contrast;
- reduced-motion respect;
- no hover-only essential action.

### FR-F22-008 — Responsive

Desktop-first density, but critical admin/security actions work on tablet/mobile.

### FR-F22-009 — Performance

Protect ADR budgets:

- route code splitting;
- lazy heavy charts/editors;
- avoid giant client state;
- server-driven pagination;
- minimize provider nesting.

### FR-F22-010 — Design system

Use shadcn with Base UI, Tailwind CSS semantic tokens, Tabler icons.

No Radix.

### FR-F22-011 — Error language

Errors should tell user:

- what failed;
- whether action was applied;
- what can be retried;
- support request ID where useful.

Never expose raw provider stack/error body.

## Dashboard philosophy

Overview should prioritize action:

- current incidents/credential failures;
- budget pressure;
- unhealthy providers/routes;
- pending invites/security alerts;
- failed automations;
- recently active projects.

Avoid decorative charts without decision value.

## Acceptance criteria

- Full control plane works without mouse for core member/project/security flows.
- Organization switch never renders data from previous org under new org header.
- Critical tables remain usable with 10k+ rows through server pagination.
