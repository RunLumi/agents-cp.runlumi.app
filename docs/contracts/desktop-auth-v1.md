# Lumi Agents desktop authorization v1

P02-INT-01 freezes the browser-to-desktop handoff consumed by LumiAgents in P03.

## Flow

1. Desktop creates a PKCE S256 verifier and sends `POST /api/v1/auth/device-code` with `device_name`, `code_challenge`, and `code_challenge_method: "S256"`.
2. Worker returns a short-lived `device_authorization_id`, one-time `device_code`, human-transcribable `user_code`, verification URI, and expiry. The desktop keeps the device code out of browser URLs and logs.
3. An authenticated browser opens the verification URI, confirms the device label, and calls `POST /api/v1/auth/device-code/approve` with the human-transcribed `user_code` (the browser never needs the device authorization ID or device code).
4. Desktop calls `POST /api/v1/auth/device-code/exchange` with the original device code and verifier.
5. Worker atomically consumes the authorization, validates PKCE, creates a revocable device session, and returns session cookies. A second exchange fails with `device_code_replayed` or `device_code_expired`.

## Rules

- Codes expire after ten minutes, are single-use, and are stored only as SHA-256 hashes.
- Approval requires a current browser session and CSRF proof; approval never returns a long-lived token to a URL.
- The exchange response creates a `LoginSession`; P03 may attach a logical `Device` record after enrollment.
- Device labels are bounded display metadata, not authorization evidence.
- A device authorization is not a policy, entitlement, or managed-device enrollment record; P03 owns those concepts.
