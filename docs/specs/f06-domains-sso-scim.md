# F06 — Domains, SSO & SCIM

Priority: P2  
Depends on: F01-F04

## Objective

Enterprise identity controls without making them prerequisites for SMB/org MVP.

## Scope

- verified domains;
- OIDC/SAML SSO;
- domain-based login discovery;
- optional SSO enforcement;
- SCIM provisioning;
- enterprise group-to-team mapping later.

## Requirements

### FR-F06-001 — Domain verification

Organization can add domain and prove control using DNS TXT or another strong method.

Email domain alone MUST NOT grant membership automatically by default.

### FR-F06-002 — SSO connections

Support multiple SSO connections only when enterprise demand requires it; MVP enterprise path can limit to one active primary connection.

Store metadata/config, never IdP private secrets in browser.

### FR-F06-003 — SSO enforcement

Enforcement policy may apply to organization members, but MUST provide a documented owner recovery/break-glass path protected by strong verification.

### FR-F06-004 — JIT provisioning

If enabled, valid SSO user can create membership with configured default role/team.

JIT is off by default.

### FR-F06-005 — SCIM

P2 endpoints support:

- Users create/update/deactivate;
- Groups create/update/delete;
- group membership mapping.

SCIM deactivation suspends membership; it MUST NOT delete user identity or immutable audit history.

### FR-F06-006 — Account linking

SSO identity links to existing user only through safe verified flow; matching unverified email is insufficient.

## Web UX

`/org/:slug/settings/identity`

Sections:

- domains;
- SSO connection status/test;
- enforcement;
- JIT;
- SCIM token + endpoint;
- sync errors.

## Security

- signed SAML/OIDC validation with issuer/audience/state/nonce;
- encrypted SCIM secret;
- rotate SCIM bearer token;
- audit configuration changes;
- rate limit provisioning API.

## Acceptance criteria

- Domain verification does not itself create memberships.
- Enforced SSO org still has a controlled owner recovery path.
- SCIM deactivation prevents org access but preserves audit records.
