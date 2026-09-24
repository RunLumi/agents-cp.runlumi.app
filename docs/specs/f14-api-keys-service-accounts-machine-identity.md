# F14 — API Keys, Service Accounts & Machine Identity

Priority: P1  
Depends on: F02, F04, F05

## Objective

Cho CI, integrations, managed runners và automation gọi control plane mà không giả làm human user.

## Entities

- ServiceAccount
- APIKey
- MachineCredential
- KeyScope

## Requirements

### FR-F14-001 — Service account

Service account belongs to one org and has explicit role/permission set.

It MUST NOT inherit an owner's permissions implicitly.

### FR-F14-002 — API key format

Secret shown once at creation.

Persist only secure hash + prefix/fingerprint + metadata.

### FR-F14-003 — Scope

Keys can be scoped to:

- project;
- allowed API capabilities;
- model aliases;
- optional IP/network restrictions where reliable;
- expiry.

### FR-F14-004 — Rotation

Create overlapping replacement key, then revoke prior key.

### FR-F14-005 — Last-used metadata

Record last-used time and approximate source metadata without storing sensitive request payload.

### FR-F14-006 — Machine identity

For first-party managed device/runner, prefer short-lived exchanged credentials over permanent API keys when possible.

### FR-F14-007 — No interactive privileges

Machine identities cannot perform human-only actions such as owner transfer unless explicitly designed and strongly justified.

## Web UX

- service-account list;
- create with permission preview;
- API key one-time reveal;
- rotate/revoke;
- last-used.

## Acceptance criteria

- Database compromise of API key table alone does not yield raw key.
- Revocation blocks new requests.
- Project-scoped key cannot access another project even inside same org.
