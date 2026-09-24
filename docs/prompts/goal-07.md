# /goal 07 — Complete P07 Enterprise Identity, Machine Accounts, Admin, and Plugin Governance

You are the **P07 phase coordinator and implementation lead**.

Complete only the P07 scope justified by current product/customer demand, while keeping the full architecture upgrade-safe.

Do not turn enterprise checkboxes into mandatory MVP complexity.

## Read first

- `AGENTS.md`
- Plan00 and P07
- F06 Domains/SSO/SCIM
- F14 API Keys/Service Accounts
- F24 Admin/Support/Abuse/Feature Rollouts
- F25 Plugins/Extensions
- P02/P05/P06 handoffs
- current ZCode plugin/MCP architecture

## Mission

Add enterprise/platform operations without weakening the simpler core.

Capabilities include:

- verified domains;
- SSO/JIT/SCIM where enabled;
- service accounts and scoped API keys;
- named internal staff identities;
- short-lived auditable support access;
- kill switches/feature rollouts;
- organization plugin governance;
- permission-aware plugin version updates.

## Contract Gate

Freeze:

- DomainVerification;
- SSOConnection/JIT policy;
- SCIM semantics;
- ServiceAccount/APIKey scopes;
- StaffRole/SupportGrant;
- feature flag/kill switch;
- PluginPackage/PluginVersion/manifest;
- plugin permission diff;
- plugin org allow/block/pin policy.

## Parallel lanes

### MOD
- enterprise identity rules
- machine identity
- plugin governance
- staff/support access

### BE
- SSO/SCIM
- service-account APIs
- internal admin APIs
- plugin policy APIs

### FE
- identity settings
- service accounts
- plugin governance
- internal operations UI only if genuinely needed

### INT
- plugin manifest/tool fingerprint reporting
- headless machine identity path

### QA
- SSO takeover cases
- SCIM deactivate
- service-account escalation
- support-access audit
- plugin permission expansion
- blocked/quarantined plugin behavior

## Security principles

- verified domain does not equal automatic membership unless policy explicitly enables JIT;
- internal staff role is never customer Org Admin;
- support access requires named actor, reason, TTL, and customer-visible audit;
- service secrets are shown once and stored hashed/encrypted as appropriate;
- plugin updates that expand capabilities require renewed review in managed mode;
- kill switches are narrow, reversible, and audited.

## Completion

P07 is complete when the implemented enterprise scope is secure and isolated, and unimplemented P2 capabilities remain cleanly gated rather than half-built.

If there is no real demand for a P2 feature, leave a coherent extension seam instead of shipping speculative complexity.
