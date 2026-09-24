# F24 — Admin/Support, Abuse Controls & Feature Rollouts

Priority: P1  
Depends on: F04, F16, F21

## Objective

Vận hành platform an toàn mà không tạo một privileged backdoor khó audit.

## Internal admin areas

- organization lookup;
- subscription/entitlement inspection;
- device/session inspection;
- provider/route health;
- abuse flags;
- support access grants;
- feature rollout state.

## Requirements

### FR-F24-001 — Separate staff identity

Internal staff access uses named identity and staff role.

No shared admin account.

### FR-F24-002 — Least privilege

Support, finance, security and engineering permissions SHOULD be distinct as team grows.

### FR-F24-003 — Customer context access

Access to customer org requires reason/ticket and creates F16 event.

Default mode is metadata/support diagnostics, not impersonation.

### FR-F24-004 — Suspension

Platform can suspend:

- org;
- user membership;
- API key/service account;
- device;
- inference route access.

Suspension reason and actor are audited.

### FR-F24-005 — Abuse controls

Signals MAY include:

- anomalous request rates;
- credential probing;
- repeated denied tool/network actions;
- extreme resource consumption;
- malicious upload indicators.

Automated action should be narrow/reversible unless threat is clear.

### FR-F24-006 — Feature flags

Flags support:

- off/on;
- percentage rollout;
- org allowlist;
- user/device cohort when needed;
- expiration/owner metadata.

Avoid using flags as permanent configuration store.

### FR-F24-007 — Kill switches

Critical capabilities need rapid kill switch:

- platform-managed inference provider;
- specific model/route;
- MCP/plugin;
- browser/computer use integration;
- vulnerable client version.

Kill-switch action is audited and reversible.

### FR-F24-008 — Break glass

Production break-glass access:

- strongest available MFA;
- short TTL;
- explicit incident reason;
- immutable audit;
- post-event review.

## Acceptance criteria

- Staff cannot silently impersonate customer without audit evidence.
- Feature rollback can target one org/provider before global disable.
