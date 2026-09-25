# P02 auth upgrade — implementation handoff (ceremony + frontend adapter)

- Date: 2026-09-25
- Scope: P02-CR-002 / p02-cg-v2 additive only. No historical P02 packets rewritten. P04 work preserved untouched except formatting from `cargo fmt`.
- Files verified read-only before edits: `git status`/`git diff --stat` audit; concurrent P04 changes left intact.

## Fixed in this slice

1. `apps/api/migrations/0008_p02_authenticators.sql`
   - Old CHECK required `user_id IS NOT NULL` for every non-signup ceremony, which rejects usernameless `passkey_login` inserts (route inserts `user_id=None`).
   - New CHECK: signup requires pending user; login allows NULL user with no pending; add/reauthenticate require user and no pending.
   - Verified with sqlite in-memory: 0008 parses; login NULL-user insert succeeds; signup-without-pending and add-without-user correctly fail.

2. `apps/api/src/routes/authenticators.rs` — `passkey_add_start`
   - Was calling `start_authentication` (assertion) for a registration flow and blocking empty-credential users with `password_fallback_required`.
   - Now: loads user for email/display_name, collects existing credential IDs as exclusion list, calls `start_registration` with the authenticated `user_id` bytes, stores `PasskeyAdd` ceremony. Empty-set users (password-only) can now add their first passkey after a `passkey_management` reauth grant obtained via password.
   - Backup flags set to `None` (unknown) instead of inferring `false` from empty aaguid, in both signup-complete and add-complete.

3. Frontend additive adapter (P02-FE-04 start)
   - `apps/web/src/lib/api.ts`: ceremony/passkey/password/reauth functions + decoders for all P02-CR-002 routes. Legacy OTP functions untouched.
   - `apps/web/src/lib/webauthn.ts` (new): base64url helpers, `passkeysSupported`, `createPasskeyCredential`, `getPasskeyAssertion` over `navigator.credentials`.
   - `apps/web/src/features/auth/auth-screen.tsx`: passkey-first hierarchy — primary passkey CTA, secondary password with `or` separator, verification/recovery states retained but demoted from primary login. No OTP primary CTA.
   - `apps/web/src/features/account/account-panel.tsx`: lists passkeys + password fallback status; notes last-method protection.
   - Tests: `api.test.ts` +2 (usernameless login start sends `{}`; password login + passkey list decode). `typecheck` + `vitest` pass (13 tests).

## Not yet done (blocked or deferred)

- `cargo check/test`, WASM target check, Worker dry-run, Argon2 benchmark: blocked by sandbox having no crates.io network (`argon2`/`passkey-auth` not in local cargo cache, `cargo check --offline` fails). No code changed to work around this; no fast-hash fallback introduced per CR alternatives.
- Real browser ceremony + hostile matrix (replay/RP/origin/UV/signature/counter/substitution): needs Worker dev + browser; not run here.
- Full account management mutations (register/revoke/rename/set-password UI wiring), Playwright evidence, P02-MOD-05/BE-05/FE-04/QA-02 packet closeouts, ADR update, STATUS (coordinator-owned).

## Validation performed

- `pnpm --filter ./apps/web typecheck`: pass.
- `pnpm --filter ./apps/web test`: 13 passed.
- sqlite in-memory migration check: pass (see above).
- `wrangler d1 migrations list DB --local --env development`: only `0009_p04_ai_platform.sql` pending; 0008 already applied to local dev ledger, so deployed environments created from pre-fix 0008 will need a forward fix or local reset (0008 is still unmerged/untracked, so this is dev-only).
- `cargo fmt --all` applied; `cargo check` not runnable offline (documented blocker).

## Next

1. On a networked runner: `cargo check`, `cargo test`, `cargo check --target wasm32-unknown-unknown`, `wrangler deploy --dry-run`, Argon2id benchmark; record KDF latency/memory/bundle delta.
2. Wire account-panel mutations + reauth step-up UI; Playwright passkey-first evidence (desktop + narrow, keyboard/focus, async states).
3. Hostile WebAuthn/password tests per P02-QA-02; update ADR + packet handoffs; coordinator updates STATUS.
