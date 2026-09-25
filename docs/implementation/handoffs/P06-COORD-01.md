# P06 Coordinator Handoff — Contract Gate freeze

## Scope

- P06 Contract Gate `p06-cg-v1` frozen in `docs/implementation/gates/P06-CG.md`.
- Contract fixture frozen at `docs/implementation/fixtures/p06-contracts-v1.json` and validated (ID formats, occurrence identity key, state enums, and the deterministic webhook HMAC test vector all check out).
- Fourteen P06 work packets defined under `docs/implementation/packets/` with disjoint write surfaces and named shared-file ownership.
- The gate was reviewed against five independent audits: control-plane reconnaissance, ZCode/LumiAgents reuse audit, web/frontend surface audit, and two contract-consistency reviews. All blocking findings are resolved in the gate, the three Change Requests, or ADR 0006.

## Normative clarifications

- `P06-CR-001` — distributed lease fencing, `ambiguous` reconciliation, calendar/DST-correct intervals, and the distinct off-peak execution class.
- `P06-CR-002` — entitlement/license/provider separation, internal-only expiring overrides, `policy_fresh_until` vs `offline_valid_until`, and the existing `/devices/policy` response as the single device license authority.
- `P06-CR-003` — the existing reauthenticated P02 organization-deletion route as the sole deletion request bridge, plus the private R2 export-artifact decision.
- `docs/adr/0006-r2-private-export-artifacts.md` — private R2 binding, Worker-mediated re-authorized short-lived downloads, no public/bearer object URLs.

## Key decisions made during review

1. At most one current server-authorized lease per occurrence. A lease lost after execution may have begun becomes `ambiguous` and is never auto-redispatched; only proven-not-started leases requeue. This is the enforceable distributed boundary and updates the F15 acceptance wording.
2. Off-peak is a distinct execution class with explicit `provider_ticket` and `org_window` eligibility sources; it is never flattened into a cron window. Intervals preserve minutes/hours/days/weeks/months/years calendar semantics.
3. The canonical P03 device-policy extension keys stay the existing singular `automation` and `entitlements`; notification and data-governance settings are separate server-side resources (no P03 CR needed).
4. Entitlement overrides are internal/support-only (no browser route or permission). Upstream provider coding-plan state is a read-only projection that never changes Lumi subscription/entitlement/authorization/budget.
5. P05 `Run` remains the sole execution state machine; P06 adds occurrence/lease correlation and a `run_id` link, not a parallel run authority.
6. Business events use the existing P01 `EventEnvelope`; a separate typed `JOBS_QUEUE`/`JOBS_DLQ` carries P06 job envelopes with a D1-enforced dedupe CAS (never a mixed/guessed union).
7. Organization deletion reuses the existing reauthenticated `POST /api/v1/orgs/{org_id}/deletion`; it transactionally creates/links one P06 `DeletionJob`.
8. Every P01–P05 and P06 persistent class has an explicit sensitivity/owner/retention/export/deletion/logging declaration, with concrete baseline retention values, legal-hold handling, and provider-retention disclosure.

## Write-surface ownership

Single-owner shared files (coordinator integrates): `apps/api/src/lib.rs`, `app.rs`, `wrangler.jsonc`, `routes/mod.rs`, `repositories/mod.rs`, `modules/mod.rs`, `adapters/mod.rs`, `consumers/mod.rs`, `jobs/mod.rs`, `consumers/outbox.rs`, `core/identifiers.rs`, `modules/authorization.rs`, `routes/support.rs`, `routes/devices.rs`, and shared web API/shell wiring. Migration ownership is split by lane: BE-01 → `0011_p06_automations.sql`, BE-02 → `0012_p06_event_delivery.sql`, BE-03 → `0013_p06_billing_entitlements.sql`, BE-04 → `0014_p06_data_governance.sql`.

## Downstream

MOD/BE/FE/INT packets are unblocked and may start from the frozen gate and fixture. FE packets build from the fixture without waiting for backend completion. P06-QA-01 remains blocked until implementation packets merge. No implementation packet may silently redefine these contracts; a required change uses `docs/implementation/templates/change-request.md` first.
