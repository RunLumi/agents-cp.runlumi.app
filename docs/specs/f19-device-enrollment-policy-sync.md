# F19 — Device Enrollment & Policy Sync

Priority: P0  
Depends on: F01-F05, F07, F13

## Objective

Biến Lumi Agents desktop/CLI thành trusted-but-revocable organization clients với device identity, capability reporting và versioned policy synchronization.

## Entities

- Device
- DeviceEnrollment
- DeviceCredential
- DeviceCapabilitySnapshot
- PolicySnapshot
- PolicyAck

## Requirements

### FR-F19-001 — Enrollment

A signed-in user enrolls device into an org.

Enrollment requires:

- user authentication;
- active org membership;
- device-generated keypair or equivalent strong device credential;
- device name/platform/app version;
- explicit user confirmation for managed-org enrollment.

### FR-F19-002 — Device credential

Prefer asymmetric device key with short-lived server token exchange.

Server stores public key/fingerprint, not reusable client private secret.

### FR-F19-003 — Capability reporting

Device periodically reports bounded metadata:

- OS/platform/arch;
- Lumi Agents version;
- browser-use available;
- computer-use available;
- runtime/CLI version;
- remote environment support;
- policy schema versions.

Do not upload process lists/filesystem contents merely for inventory.

### FR-F19-004 — Policy snapshot

Server publishes versioned effective policy covering relevant:

- org/project access;
- model aliases/routes;
- tool/MCP rules;
- browser/computer-use restrictions;
- automation permission;
- update minimum version;
- entitlement/licensing state.

### FR-F19-005 — Signed/versioned sync

Client treats snapshot as data with:

- policy version;
- issued_at;
- expires_at;
- org/device binding;
- integrity/signature or authenticated transport + token binding.

### FR-F19-006 — Fail-safe behavior

On policy expiry/network loss:

- local personal work can follow defined offline policy;
- managed org high-risk operations fail closed where required;
- already-open local files are not deleted/locked;
- cloud inference obeys server state naturally because gateway is online authority.

### FR-F19-007 — Revocation

Admin/user can revoke device.

Revocation blocks:

- token exchange;
- remote dispatch;
- managed inference identity;
- policy refresh.

### FR-F19-008 — Minimum client version

Org/platform can require minimum version for cloud-managed operations when a security fix demands it.

Use staged rollout + grace messaging, not surprise hard brick by default.

### FR-F19-009 — Heartbeat

Track last_seen and health state for scheduling/automation eligibility.

Avoid high-frequency telemetry.

## Integration with ZCode

ZCode has host processes, remote workspace/session semantics and environment-specific provider registries. Device enrollment should wrap those runtimes with cloud identity, not collapse remote/local execution into one fake server environment.

## Web UX

- devices list;
- user/device owner;
- app version/platform;
- capabilities;
- last seen;
- project/workspace bindings;
- revoke;
- policy sync status.

## Acceptance criteria

- Revoked device cannot fetch new org policy or run new managed cloud operations.
- Policy for Org A cannot be replayed as Org B policy.
- Offline policy behavior is deterministic and documented.
