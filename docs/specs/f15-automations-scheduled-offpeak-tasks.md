# F15 — Automations, Scheduled & Off-peak Tasks

Priority: P1  
Depends on: F07, F08, F12, F13, F19

## Objective

Đồng bộ và quản trị organization-aware automations dựa trên năng lực cron/off-peak scheduler đã có trong ZCode.

## Concepts

- AutomationDefinition
- ScheduleRule
- AutomationRun
- ExecutionTarget
- OffPeakPolicy

## Requirements

### FR-F15-001 — Automation ownership

Automation belongs to org + project, optionally bound to agent/session/workspace target.

### FR-F15-002 — Schedule

Support:

- one-time;
- cron;
- product-level interval rule that preserves semantics cron cannot faithfully represent;
- manual run.

Store canonical schedule semantics, not just display cron.

### FR-F15-003 — Execution target

Automation specifies required environment:

- any eligible enrolled device;
- specific device;
- remote workspace;
- server-side runner if supported later.

### FR-F15-004 — Dispatch

Server decides due work and issues a lease/dispatch to eligible device.

A device MUST atomically claim work to avoid duplicate side effects. A lease that expires after execution may have begun is marked `ambiguous` and cannot be automatically reissued; this distributed boundary is normative in `P06-CR-001`.

### FR-F15-005 — Idempotency

Each scheduled occurrence has stable `run_id`/occurrence key.

Retries do not create a second logical occurrence.

### FR-F15-006 — Policies

At execution time re-evaluate:

- membership/service identity;
- tool policy;
- model route;
- budget;
- device health/capability.

Do not use stale authorization captured when schedule was created.

### FR-F15-007 — Off-peak

Org may designate off-peak eligibility sources and windows, lower-cost route aliases, and mutation restrictions. P06 supports both an organization-window mode and the existing ZCode provider-ticket/no-clock mode; the eligibility source is explicit and the server never silently converts one into the other.

ZCode already separates off-peak tasks and applies special tool restrictions; preserve that safety distinction.

### FR-F15-008 — Missed schedules

Define per automation:

- skip;
- run once on recovery;
- catch up up to N.

Default should avoid burst replay after device reconnect.

### FR-F15-009 — Concurrency

Policy:

- allow overlap;
- skip if running;
- queue one;
- cancel previous.

## Web UX

- automations list;
- next run;
- last run;
- target device/workspace;
- schedule;
- budget/model policy;
- run history;
- pause/resume/run now.

## Acceptance criteria

- At most one current server-authorized lease exists for an occurrence. If a lease expires after execution may have started, the occurrence enters an audited `ambiguous` reconciliation state and is not automatically re-dispatched; a second device cannot claim it.
- Paused/suspended org stops new dispatch.
- Missed-run behavior is deterministic and visible.
