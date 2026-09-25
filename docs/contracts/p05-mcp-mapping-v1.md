# P05 MCP mapping contract v1

- Contract version: `p05-mcp-v1`
- Authority: P05-CG `p05-cg-v1`
- Scope: non-secret registration and stable tool identity mapping

## Registration mapping

| Runtime source | `source` | Required metadata |
|---|---|---|
| Lumi built-in | `built_in` | stable source key, tool list/fingerprint |
| ZCode/Lumi plugin | `plugin` | plugin identity/version, tool list/fingerprint |
| User custom MCP | `custom` | transport, endpoint or command metadata, allowed origins, secret handles, tool fingerprint/list |

Endpoint/command metadata must not contain secret values. Secret requirements are opaque handles resolved by the trusted host/broker.

## Identity rules

- `mcp_registration_id` identifies the source registration.
- `tool_id` is stable within the organization/source and is not inferred from a mutable display name alone.
- `fingerprint` covers the tool schema/behavior identity and is required for approval binding.
- A changed fingerprint or new tool invalidates prior approval for managed execution and returns `mcp_tool_requires_review`/`tool_fingerprint_changed`.
- Unknown privileged tools default to deny or per-use review in managed organization mode.

## Network boundary

Custom endpoints are validated by the control plane/runtime against the organization allowlist and SSRF policy. Redirects, private/link-local destinations, arbitrary proxying, and caller-supplied authorization headers are rejected.
