# P06 Automation Lease Protocol v1

- Status: implemented (host side); control-plane side is the frozen `p06-cg-v1`
- Contract Gate: `p06-cg-v1` (`11341a5`)
- Normative clarification: `P06-CR-001`
- Related handoff: `docs/implementation/handoffs/P06-INT-01.md`

This document describes the wire and behavioural contract between the Lumi
control plane and a LumiAgents/ZCode execution host for a leased automation
occurrence. The control plane is authoritative for occurrence identity, lease
ownership, and the P05 run link.

## The boundary this protocol exists to enforce

At most one current server-authorized lease exists per occurrence. A lease lost
after execution may have begun cannot be proven safe, so the occurrence becomes
`ambiguous`, which is terminal and is never automatically re-dispatched. Only a
provably-not-started lease may return to `pending`.

The host therefore cannot reason its way to authority. It obtains every
transition from the server and refuses itself when its own view is stale.

## Route builders

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/devices/automations/due` | Bounded eligible unleased work (max 20) |
| POST | `/api/v1/devices/automation-occurrences/{occurrence_id}/claim` | Atomic lease claim; returns the one-time raw lease token |
| POST | `/api/v1/devices/automation-leases/{lease_id}/renew` | Extend a current pre-ambiguous lease |
| POST | `/api/v1/devices/automation-occurrences/{occurrence_id}/start` | Durably create/discover the P05 run link, then mark started |
| POST | `/api/v1/devices/automation-occurrences/{occurrence_id}/settle` | Settle with the current lease/run binding |
| POST | `/api/v1/devices/automation-occurrences/{occurrence_id}/release` | Release, allowed only before started |

Every device route authenticates with the device token. Body-supplied org,
project, workspace, or device identifiers are ignored: scope is derived from the
token and the current binding.

## Wire shapes

`P06AutomationOccurrenceRef` — `occurrence_id`, `automation_id`, `attempt`,
`scheduled_for`, `off_peak_mode`, `policy_snapshot_id`, `policy_version`,
`execution_principal`.

`P06AutomationLease` — `lease_id`, `lease_version`, `lease_fence`, `expires_at`.
The raw lease token is returned once by `claim` and is held in memory only; it
is never persisted, logged, or placed in a URL.

`P06AutomationStartGrant` — `occurrence_id`, `attempt`, `run_id`,
`agent_session_id`, `lease_id`, `lease_version`, `lease_fence`. The host may not
execute any tool or external side effect before receiving this, because the
server creates the P05 run link durably on `start`.

All decoders are strict (`.strict()`), so an unexpected field is rejected rather
than ignored. A malformed body becomes the stable `automation_wire_invalid`
rather than a message the caller must parse.

## Ordering rule

```text
due → claim → start → execute → settle
                    ↘ renew (bounded, pre-ambiguous only)
                    ↘ release (only before started)
```

There is no local retry and no local requeue. A new attempt requires a new
server lease and a new guard instance.

## Fencing

The guard holds the fence the server most recently confirmed. It is monotonic:
a delayed renewal cannot resurrect a superseded fence. A caller cannot express a
stale request, because the only way to build a fence request is to stamp the
held value.

Comparison is three-way. A different `lease_id`, or a version/fence ahead of
anything observed, is `automation_lease_fence_unknown` — "newer" is not
"authoritative". A version/fence behind the held one is
`automation_lease_fence_stale`, the lost-renewal case.

## Recovery

`classifyInterruptedAutomationOccurrence` returns exactly three outcomes, and
the union deliberately has no `requeued` member:

- `ambiguous` when the server lost authority after execution may have begun —
  surface for operator reconciliation, never re-dispatch;
- `continue` when a live lease still holds;
- `releasable` (no start grant) or `needs_reconciliation` (with one) when the
  lease expired.

`releasable` means the server can still prove nothing started. It is not a local
retry grant: the host calls `release` and the server applies its own
missed/retry policy.

The observation carries no misfire value, only server facts plus the lease
expiry, so client clock skew cannot manufacture authority.

## Off-peak

Off-peak is a distinct execution class, never a cron window. A provider ticket
has no clock schedule, and a ticket **renewal does not create a second logical
occurrence**. The server may narrow the host's tool constraints but never
broaden them, so `narrowOffPeakToolConstraints` combines `deny_*` flags with OR
and `allow_*` flags with AND. Network, browser, and computer decisions are not
part of this object; they belong to the P05 tool policy.

## Known divergence requiring follow-up

The off-peak/automation tool denylist currently exists in four copies with two
genuine correctness differences. `apps/zcode-cli/packages/bootstrap/src/zcode-protocol/server-operations.ts`
denies only `CronCreate` on an automation turn, so a model refused
`CronCreate` can still see `CronDelete` — the recursion the adjacent comment
says the denylist prevents. `packages/services/src/zcode-agent/automationToolPolicy.ts`
omits `SendMessage`/`Workflow` from the off-peak set. The canonical values are
published in `@zcode/shared` as `P06_AUTOMATION_RESTRICTED_TOOL_NAMES` and
`P06_AUTOMATION_MUTATION_TOOL_NAMES`; all four copies should import them.
