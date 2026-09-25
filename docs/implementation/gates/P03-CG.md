# Contract Gate — P03-CG

- Phase: P03 — Devices, projects, workspaces, policy sync
- Owner: P03 coordinator
- State: frozen
- Contract version: `p03-cg-v1`
- Inputs: Plan00, Plan03, F07, F13 (foundations), F19, F26 (foundations), ADR 0002/0004/0005, P01-CG `p01-cg-v1`, P02-CG `p02-cg-v1` (merged `ba35fb6`/`0290e68`, shipped `ca8e6cb`)
- Shared-file owner: P03 coordinator

## Domain vocabulary and IDs

New stable entities: `Device`, `DeviceEnrollment`, `DeviceCredential` (server-side public-key + fingerprint record), `DeviceCapabilityReport` (bounded metadata stored on the device row), `Project`, `WorkspaceBinding`, `ProjectAccessGrant`, `PolicySnapshot`, `PolicyAck`.

P01/P02 opaque ID conventions remain authoritative (`<prefix>_<32 lowercase hex>`). New P03 prefixes: `dvc_` (managed device), `enr_` (enrollment), `prj_` (project), `wsb_` (workspace binding), `pol_` (policy snapshot), `pak_` (policy ack). The P02 `dev_` prefix keeps its existing meaning (browser device-authorization codes) and is never reused. Raw enrollment codes, challenges, and device tokens are stored only as hashes; private keys never reach the server.

## States and invariants

- `DeviceEnrollment`: `pending` → `completed` | `expired` | `denied`. Begin is anonymous (device-side) and creates a one-time hashed code plus a proof-of-possession challenge; approval requires an authenticated, email-verified user with an active membership in the target org and explicit confirmation; completion requires a signature over the server challenge by the enrollment key. One-time code and challenge are single-use; expiry is bounded (15 minutes).
- `Device`: `active` | `revoked`; revocation is terminal and blocks token exchange, policy fetch, heartbeat/capability updates, and binding mutations while preserving rows and audit history. A device belongs to exactly one org. Unique `(org_id, key_fingerprint)`. Revocation is performed by an admin with `devices.manage` or by the user who approved the enrollment.
- `DeviceToken`: short-lived (15 minutes), opaque, stored hashed, bound to one device. Refresh (proof-of-possession signature over a server nonce) checks: device `active`, enrollment `completed`, membership `active`, organization `active`, app version ≥ org/platform minimum; any failure denies with the stable reason below.
- `Project`: belongs to exactly one org; `visibility` is `org` (all active members) or `restricted` (explicit member/team grants only). Slug is unique per org. Mutations use optimistic `version`. `archived` projects reject new bindings and later run/automation use, preserving history (F07-005).
- `WorkspaceBinding`: `(device_id, workspace_identity)` is unique among live bindings; `workspace_identity` is a stable normalized local identifier plus non-secret display name (F07-007); `environment_type` ∈ `local|ssh|wsl|docker|remote`. Binding is always explicit (F26-002); a binding whose device belongs to a different org than the project is rejected with `resource_scope_mismatch`.
- `PolicySnapshot`: org-scoped, monotonically increasing integer `policy_version`; immutable rows carry `issued_at`, `expires_at` (default 24 h), and a payload envelope with typed sections: `org_access`, `projects`, `min_client_version` (P03-owned), and `models`, `tools`, `automation`, `entitlements` as opaque versioned placeholders owned by P04/P05. Audience binding = the fetching device's token; the `signature` field is reserved (`null`) — integrity relies on authenticated transport plus device-token binding (F19-005 option). Policy for Org A is never served to a device of Org B.
- `PolicyAck`: unique `(device_id, policy_version)`; acks are recorded for sync-status visibility.
- Heartbeat updates `devices.last_seen_at` and optionally the bounded capability report (F19-003/F19-009); heartbeats are not audited and are rate-bounded by normal update semantics.

## Central authorization

Protected org routes keep using the P02 `authorize()` decision service. P03 appends permissions to the stable registry: `devices.read`, `devices.manage`, `projects.read`, `projects.manage`.

Role mapping (additive to P02 matrix): Owner = all P03 permissions; Admin = all P03 permissions; Member = `projects.read`, `devices.read` (org-visible devices/projects) plus self-service actions (approve own enrollment, revoke own enrolled device, manage own device tokens/bindings); Viewer = `projects.read`, `devices.read`. Restricted-project reads additionally require an explicit `ProjectAccessGrant` (member or team) for non-managers.

New stable denial/lifecycle reasons appended to the P02 registry in `error.details.reason`: `device_not_found`, `device_revoked`, `enrollment_expired`, `enrollment_denied`, `device_token_expired`, `device_proof_invalid`, `client_version_too_old`, `project_archived`, `workspace_binding_conflict`, `device_not_approved`. Existing P01 error codes are unchanged (`validation_failed` 422, `idempotency_conflict`, `permission_denied`, `authentication_required`, …).

## API

All routes under `/api/v1`, JSON, P01 error envelope, `X-Request-ID`, 1 MiB body limit, `Page<T>` pagination with opaque cursors (P03 implements real cursor encoding for its lists). Browser-session mutations carry CSRF per P02-CR-001. Device-side routes authenticate with the `Authorization: DeviceToken <token>` header (no cookies, no CSRF). Org-scoped admin routes keep `org_id` in the path with the `X-Org-ID` equality rule.

Device-side (desktop client):

| Method | Path | Auth | Request | Success |
|---|---|---|---|---|
| POST | `/devices/enrollments` | anonymous | `{org_slug, public_key, key_fingerprint, device_name, platform, app_version}` | `201 {enrollment_id, user_code, verification_uri, expires_at}` |
| GET | `/devices/enrollments/{enrollment_id}` | anonymous | — | `200 {status, challenge?}` (`pending` returns a fresh challenge once approved) |
| POST | `/devices/enrollments/{enrollment_id}/complete` | anonymous | `{signature}` | `201 {device_id, org_id, device_token, token_expires_at, policy_version}` |
| GET | `/devices/token/nonce` | anonymous | — | `200 {nonce, expires_at}` |
| POST | `/devices/token` | anonymous | `{device_id, signature, app_version}` | `200 {device_token, token_expires_at, policy_version}` |
| POST | `/devices/heartbeat` | device token | `{capabilities?}` | `200 {server_time, policy_version, min_client_version}` |
| GET | `/devices/policy` | device token | — | `200 PolicySnapshot` (current org version, audience-bound) |
| POST | `/devices/policy/ack` | device token | `{policy_version}` | `204` |
| GET | `/devices/bindings` | device token | — | `200 Page<WorkspaceBinding>` |
| POST | `/devices/bindings` | device token | `{project_id, workspace_identity, display_name, environment_type}` | `201 WorkspaceBinding` |
| DELETE | `/devices/bindings/{binding_id}` | device token | — | `204` (own bindings only) |

Browser/session-side (org admin and member):

| Method | Path | Permission | Request | Success |
|---|---|---|---|---|
| POST | `/orgs/{org_id}/devices/enrollments/{enrollment_id}/approve` | active member, self-approval | `{}` + Idempotency-Key | `201 Device` |
| GET | `/orgs/{org_id}/devices` | `devices.read` | `limit?,cursor?` | `200 Page<DeviceSummary>` |
| GET | `/orgs/{org_id}/devices/{device_id}` | `devices.read` | — | `200 Device` |
| DELETE | `/orgs/{org_id}/devices/{device_id}` | `devices.manage` or enrolled-by user | `{}` + Idempotency-Key | `204` |
| GET | `/orgs/{org_id}/projects` | `projects.read` (restricted filtered) | `limit?,cursor?,include_archived?` | `200 Page<Project>` |
| POST | `/orgs/{org_id}/projects` | `projects.manage` | `{name, slug?, visibility}` + Idempotency-Key | `201 Project` |
| GET | `/orgs/{org_id}/projects/{project_id}` | `projects.read` + grant check | — | `200 Project` |
| PATCH | `/orgs/{org_id}/projects/{project_id}` | `projects.manage` | `{name?, visibility?, archived?, version}` | `200 Project` |
| GET/POST/DELETE | `/orgs/{org_id}/projects/{project_id}/access` | `projects.read` / `projects.manage` | grants: `{member_id?}` or `{team_id?}` | page / `201 Grant` / `204` |
| GET | `/orgs/{org_id}/projects/{project_id}/bindings` | `projects.read` + grant check | — | `200 Page<WorkspaceBinding>` |
| DELETE | `/orgs/{org_id}/projects/{project_id}/bindings/{binding_id}` | `projects.manage` | — | `204` |
| GET | `/orgs/{org_id}/policy` | `projects.read` | — | `200 PolicySnapshot` (latest org version; read-only inspector) |

`DELETE /orgs/{org_id}/devices/{device_id}`, project create, and enrollment approval require `Idempotency-Key`; replay returns the stored projection with no duplicate mutation.

## Events and audit

Immutable `security_events` append for: enrollment approved (`device.enrolled.v1`), device revoked (`device.revoked.v1`), enrollment denied/expired transitions (`device.enrollment_closed.v1`). Outbox `EventEnvelope` events for project lifecycle: `project.created.v1`, `project.updated.v1`, `project.archived.v1`, `project.binding_created.v1`, `project.binding_removed.v1`. Heartbeats, capability reports, policy fetches, and acks are not audited. No product API mutates or deletes audit rows.

## Persistence

Migration `0007_p03_devices_projects_policy.sql` creates: `devices`, `device_enrollments`, `device_tokens`, `projects`, `project_access_grants`, `workspace_bindings`, `policy_snapshots`, `policy_acks`. All tenant rows carry `org_id`. Invariant-bearing uniqueness: `(org_id, key_fingerprint)` on devices, `(org_id, slug)` on projects, `(device_id, workspace_identity)` on workspace bindings, `(device_id, policy_version)` on policy acks, `(org_id, policy_version)` on policy snapshots. State CHECK constraints, explicit indexes per P01 naming, D1 batches for invariant-bearing mutations (approve+device insert, revoke+token invalidation, project mutations with version predicate). No KV cache, no Durable Objects.

## Compatibility

P01/P02 clients, errors, IDs, pagination, idempotency, and outbox shapes are unchanged; P03 adds only routes, permissions (registry appended), denial reasons (registry appended), and tables. The `dev_` prefix and P02 device-code browser flow are untouched; P03 managed enrollment is a separate mechanism that may compose with it later. A required change to any of the above uses `docs/implementation/templates/change-request.md`.

## Fixtures

Minimal FE/QA fixtures (also used by tests):

```json
// DeviceSummary
{ "id": "dvc_0123456789abcdef0123456789abcdef", "org_id": "org_0123456789abcdef0123456789abcdef", "name": "James Laptop", "platform": "macos-arm64", "app_version": "0.3.1", "status": "active", "last_seen_at": "2026-09-25T12:00:00Z", "enrolled_by_user_id": "usr_0123456789abcdef0123456789abcdef", "created_at": "2026-09-25T11:00:00Z" }

// Project
{ "id": "prj_0123456789abcdef0123456789abcdef", "org_id": "org_0123456789abcdef0123456789abcdef", "name": "Inference", "slug": "inference", "visibility": "org", "archived": false, "version": 3, "created_at": "2026-09-25T11:00:00Z", "updated_at": "2026-09-25T12:00:00Z" }

// PolicySnapshot (sections `models`/`tools`/`automation`/`entitlements` are opaque P04/P05 placeholders)
{ "id": "pol_0123456789abcdef0123456789abcdef", "org_id": "org_0123456789abcdef0123456789abcdef", "policy_version": 7, "issued_at": "2026-09-25T12:00:00Z", "expires_at": "2026-09-26T12:00:00Z", "signature": null, "payload": { "org_access": { "member": true }, "projects": { "bindings": ["prj_0123456789abcdef0123456789abcdef"] }, "min_client_version": "0.3.0", "models": { "schema_version": 0 }, "tools": { "schema_version": 0 }, "automation": { "schema_version": 0 }, "entitlements": { "schema_version": 0 } } }
```

## Freeze

- Contract Gate commit: this commit (`p03-cg-v1`).
- Unlocked packets: P03-MOD-01..03, P03-BE-01..03, P03-FE-01..03, P03-QA-01. The LumiAgents desktop integration lane (plan03 §6) is a later integration PR in the `RunLumi/LumiAgents` repo and is not gated by this repository's P03 exit; the Integration Gate proves the desktop flow with a scripted device client over the frozen API.
- Shared files: P03 coordinator owns router registration, module declarations, permission/denial registries, migrations, Wrangler config, and the P03 rows of STATUS.
