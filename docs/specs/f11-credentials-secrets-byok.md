# F11 — Credentials, Secrets & BYOK

Priority: P0  
Depends on: F02, F04, F09

## Objective

Quản lý provider credentials và secrets an toàn cho platform, organization, user và runtime integrations.

## Secret classes

- AI provider API keys/OAuth refresh material;
- MCP/integration credentials;
- webhook secrets;
- service-account secrets;
- SSO/SCIM secrets;
- optional customer-managed endpoint credentials.

## Credential ownership

```text
platform
organization
user-within-organization
service-account
local-only (never uploaded)
```

## Requirements

### FR-F11-001 — Secret envelope

Stored secret values MUST be encrypted at rest using a managed key/envelope approach appropriate to Cloudflare deployment.

Database rows contain metadata + ciphertext reference, not plaintext.

### FR-F11-002 — No re-display

After creation, API returns masked metadata only.

If product offers reveal, require reauthentication and audit it; default recommendation is no reveal.

### FR-F11-003 — Credential metadata

Store:

- id;
- org scope;
- owner type;
- provider/integration type;
- label;
- status;
- created/updated/last-used;
- key fingerprint;
- secret version;
- rotation lineage.

### FR-F11-004 — BYOK precedence

Project/org policy chooses eligible credential source.

Possible modes:

- org-managed only;
- user BYOK allowed;
- platform-managed only;
- local direct only;
- ordered fallback between approved modes.

Do not let desktop silently override org policy.

### FR-F11-005 — Validation

Credential creation SHOULD validate with a low-risk provider endpoint when possible.

Validation failure does not store plaintext in logs.

### FR-F11-006 — Rotation

Rotation creates a new secret version.

Support overlap window for in-flight work, then revoke prior version.

### FR-F11-007 — Revocation

Revoked credential is excluded from new routing immediately.

In-flight request behavior is provider/protocol dependent and recorded.

### FR-F11-008 — Secret use

Business code requests a logical credential handle; only the adapter layer resolves plaintext just before outbound use.

### FR-F11-009 — Local-only

Lumi Agents may retain existing local provider credentials. Control plane stores only metadata/fingerprint if user opts to register capability.

## Security

- never log secret value;
- redact common key patterns from exception/log pipelines;
- no secret in URL/query string;
- no secret in frontend state persistence;
- per-org authorization before resolving handle;
- secret rotation/revocation audited;
- protect custom endpoints from credential exfiltration/SSRF.

## Web UX

`/org/:slug/settings/credentials`

Show:

- label/provider;
- owner/scope;
- masked fingerprint;
- last used;
- status;
- rotate/revoke.

## Acceptance criteria

- Secret cannot be read back through normal API after creation.
- Revoked secret is not selected by F10.
- Cross-org credential handle returns indistinguishable not-found/denied response.
- Logs remain free of raw secret in provider failure tests.
