# F18 — Billing, Plans, Entitlements & Licensing

Priority: P1  
Depends on: F02, F04, F09, F12

## Objective

Tách **commercial plan**, **product entitlement** và **runtime licensing** để pricing có thể thay đổi mà không làm authorization code phụ thuộc payment provider.

## Core model

```text
Plan
Subscription
EntitlementDefinition
EntitlementGrant
LicenseState
BillingAccount
```

Authorization answers "may this principal do X?". Entitlements answer "does this org's product plan include capability X?". They are related but distinct.

## Requirements

### FR-F18-001 — Stable entitlement keys

Examples:

- `org.max_members`
- `projects.max_active`
- `inference.platform_managed`
- `inference.byok`
- `audit.retention_days`
- `sso.enabled`
- `scim.enabled`
- `automations.max_active`
- `devices.max_enrolled`

Product code checks entitlement keys, never Stripe/product-price IDs.

### FR-F18-002 — Subscription state

Recommended states:

- trialing
- active
- grace
- past_due
- suspended
- cancelled

Payment-provider state is mapped into Lumi subscription state through adapter.

### FR-F18-003 — License evaluation

Desktop/CLI receives short-lived signed license/entitlement snapshot sufficient for offline grace behavior.

Do not ship perpetual client-side flags as the source of truth.

### FR-F18-004 — Grace periods

Temporary billing/provider outage MUST not instantly brick local work.

Define bounded grace behavior separately for:

- local-only capabilities;
- cloud control plane;
- platform-paid inference.

Platform-paid inference can fail sooner than local editing/execution.

### FR-F18-005 — Seat model

If billing uses seats, define billable membership states explicitly.

Do not count pending invites unless commercial policy intentionally does so.

### FR-F18-006 — Plan change

Upgrade can apply immediately.

Downgrade must handle over-limit resources predictably:

- do not delete data;
- block creation/expansion;
- indicate resources above limit;
- give remediation path.

### FR-F18-007 — Entitlement override

Internal/customer-success override requires expiry, reason and F16 audit event.

No silent forever override.

### FR-F18-008 — Provider coding-plan compatibility

ZCode currently exposes provider-specific coding-plan/start-plan/team-plan entitlements.

Lumi MUST distinguish:

1. entitlement to Lumi product feature;
2. entitlement/account state at external AI provider.

Do not conflate the two in schema or UI.

## Web UX

- plan/subscription overview;
- usage vs included limits;
- invoice/provider portal link when added;
- upgrade/downgrade;
- over-limit remediation;
- enterprise contact state.

## Acceptance criteria

- Changing payment provider does not require rewriting feature authorization.
- A downgraded org keeps historical data and receives deterministic creation limits.
- Provider coding-plan loss does not incorrectly cancel Lumi org subscription.
