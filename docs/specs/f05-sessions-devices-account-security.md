# F05 — Sessions, Devices & Account Security

Priority: P0  
Depends on: F01

## Objective

Cho user khả năng thấy và thu hồi mọi login/device session, đồng thời cung cấp nền tảng cho security-sensitive operations.

## Entities

- LoginSession
- Device
- SecurityEvent
- ReauthenticationGrant

## Requirements

### FR-F05-001 — Session inventory

User can view active/recent sessions with:

- device label;
- platform/browser;
- approximate location metadata where legally/technically appropriate;
- created/last-seen time;
- current session marker.

Never show raw token identifiers.

### FR-F05-002 — Revocation

User can revoke one or all other sessions.

Revocation MUST block token refresh immediately or within documented bounded propagation delay.

### FR-F05-003 — Device identity

Desktop auth creates a logical device record separate from login session.

A device can hold multiple app sessions over time.

### FR-F05-004 — Reauthentication

Sensitive operations require recent auth, e.g.:

- owner transfer;
- secret reveal/rotation where reveal exists;
- SSO changes;
- org deletion;
- disabling MFA.

Use a short-lived server-side reauth grant rather than asking each feature to invent its own timestamp.

### FR-F05-005 — MFA/passkeys

P1:

- WebAuthn/passkeys;
- TOTP as fallback if needed;
- recovery codes;
- MFA reset security event.

### FR-F05-006 — Security notifications

Notify user for material events:

- new device sign-in;
- recovery;
- MFA change;
- identity linked;
- suspicious token reuse.

## Threats

- refresh token theft;
- session fixation;
- device-code interception;
- CSRF;
- replay;
- stale revoked refresh token;
- recovery flow abuse.

## Web UX

`/account/security` groups:

- authentication methods;
- MFA/passkeys;
- active sessions;
- devices;
- recent account security activity.

## Acceptance criteria

- Revoking a device blocks subsequent refresh from that device.
- Reauth grants cannot be reused across users or after expiry.
- Security events are immutable from normal user APIs.
