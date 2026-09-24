# Integration Gate — P02-IG

## Goal

Prove P02 as a real multi-tenant identity and organization slice: browser session → Rust Worker → D1 → centralized authorization → mutation → immutable audit/outbox → user-visible API result.

## Preconditions

- [x] P01 complete: `docs/implementation/gates/P01-IG.md` PASS.
- [x] P02-CG frozen at `ba35fb6`; clarification `P02-CR-001` recorded at `3719b8d`.
- [x] P02 packets and handoffs integrated on the current coordinator branch.
- [x] `0002_p02_identity_organizations.sql` and `0003_p02_auth_rate_limits.sql` applied to local Wrangler D1.
- [x] Development Worker exposes local-only verification/login/device fixtures; production response does not return those codes.
- [x] Shared-file owner is the P02 coordinator.

## Vertical slice

```text
Vite/React auth + org shell
→ POST /api/v1/auth/*
→ request boundary + request ID
→ D1 users/identities/session lookup
→ HttpOnly session + CSRF
→ explicit /api/v1/orgs/:org_id context
→ current membership lookup
→ centralized authorize()
→ D1 batch: mutation + security_events + EventEnvelope/outbox
→ API DTO rendered in org switcher/member/account views
```

## Real journey evidence

`apps/api/scripts/p02-smoke.mjs` passed against the local Worker on 2026-09-25:

1. Alice signs up, verifies email, and signs in.
2. Alice creates an organization and retries the same idempotency key (one resource, replay response).
3. Alice invites Bob; Bob accepts the one-time invitation.
4. Duplicate accept is idempotent.
5. Bob can read the member directory.
6. Bob's owner-only role mutation is denied with `permission_denied`.
7. Bob cannot read the audit route.
8. Bob's request to Alice's second organization is denied without resource disclosure.
9. Alice removes Bob; Bob's stale session loses organization access.
10. Alice reads organization audit events for invitation, acceptance, and removal.
11. Alice obtains a reauth grant and linking Bob's identity returns `identity_conflict`.
12. Revoking the current session makes refresh return `authentication_required`.

The smoke output was:

```json
{"ok":true,"org_id":"org_8f1033473d99dd0467962bf5d1f5ec42","owner_membership_id":"mem_00128dfcc3fb9aa6d9e0b699f4fd0cc9","audit_events":6}
```

No invitation token, session token, CSRF token, or password appears in the smoke output.

## Hostile matrix

| Case | Evidence/result |
|---|---|
| Org A ID substituted into Org B request | Bob → Alice's second org: `403/404`, no org data. |
| Removed member with stale token | Bob after removal: `403/404` on the old org. |
| Concurrent last-owner changes | Local P02 smoke creates two active owners, starts two demotion requests concurrently, and observes statuses `[200, 409]`; conditional D1 `UPDATE` plus expected version leaves one owner. A remote Cloudflare probe remains a CI follow-up. |
| Invitation replay | Second accept after accepted returns the same membership, not a second grant. |
| Revoked/expired invitation | Revoke/list/resend routes and conditional acceptance SQL reject non-pending/expired rows; raw token is never trusted as a claim. |
| Identity-link conflict | Reauth-bound link to another user's normalized email returns `identity_conflict`. |
| Revoked session refresh | Account revoke followed by `/auth/refresh` returns `401`. |
| Auth rate limiting | Twelve login starts for one bucket produce ten `202` then `429`. |
| Org switch stale data | Web switch increments request generation, aborts old requests, and clears load state before the next org fetch. |
| Unauthorized direct URL | Web path guard renders a scoped not-found state without falling back to another org; browser automation was unavailable in this session, so this remains manually verified in CI/desktop review. |
| PKCE replay/expiry | Device exchange validates S256 verifier and atomically consumes the authorization; expiry/status checks precede session creation. |

## Quality evidence

- `/opt/homebrew/bin/pnpm check` — PASS (format, Oxlint, TypeScript, 11 Vitest tests, 64 Rust tests, Clippy `-D warnings`, WASM check).
- `/opt/homebrew/bin/pnpm build` — PASS (Vite 78.05 KiB gzip JS, 5.16 KiB gzip CSS; Worker production dry run 1,601.38 KiB upload / 415.96 KiB gzip).
- `node apps/api/scripts/p02-smoke.mjs` — PASS against local Worker/D1.
- `wrangler d1 migrations apply DB --local --env development` — PASS for migrations 0001–0003.
- `cargo check --workspace --target wasm32-unknown-unknown` — PASS.
- `git diff --check` — PASS.
- Browser screenshot/focus automation — attempted through the available browser tool, but no desktop browser was connected. Visual implementation was compared against `docs/screens/lumi_account.webp`, `docs/screens/lumi_models_routing.webp`, and `docs/screens/lumi_budget_activity.webp`; desktop/narrow browser evidence must be captured in the desktop review environment.

## Performance and migration review

- No new runtime dependency was added for P02; the Worker size increase is from the identity/org/authorization implementation and must be tracked against the P01 baseline.
- Web assets remain below the 170 KiB JS / 35 KiB CSS budgets.
- Migrations are additive and forward-only. `0002` establishes P02 relational constraints; `0003` adds bounded auth rate-limit storage. No production data or remote resource was modified.

## Exit decision

**PASS WITH DOCUMENTED ENVIRONMENT FOLLOW-UP** — the real local identity → organization → membership → authorization → audit journey passes, hostile security cases are covered, and P03/P04 can consume the stable contracts. The only non-security follow-up is desktop browser screenshot/focus capture, which could not run because the session had no connected desktop browser.
