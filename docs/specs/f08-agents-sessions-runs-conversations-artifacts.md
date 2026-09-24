# F08 — Agents, Sessions, Runs, Conversations & Artifacts

Priority: P0  
Depends on: F04, F07, F09-F13

## Objective

Chuẩn hóa cloud-visible lifecycle của agent execution mà vẫn để desktop/remote host thực hiện local work.

## Canonical concepts

```text
AgentDefinition
Session
Run
Conversation
RunEvent
ArtifactRef
ToolCallRef
```

Do not collapse Session and Run:

- Session = durable conversational/work context.
- Run = one execution attempt within a session.

## Requirements

### FR-F08-001 — Agent definition

Agent definition may contain:

- name/description;
- instructions reference;
- default model route alias;
- allowed tools/policies;
- runtime capability requirements;
- owner project/org;
- version.

### FR-F08-002 — Session

A session belongs to org + project and references workspace binding when execution needs one.

Session records SHOULD preserve compatibility with ZCode session/task identifiers via external IDs.

### FR-F08-003 — Run states

Recommended:

- queued
- dispatching
- running
- waiting_user
- waiting_approval
- succeeded
- failed
- cancelled
- timed_out

State transitions MUST be monotonic and validated server-side.

### FR-F08-004 — Event stream

Run events append immutable sequence-numbered records:

- model request/response metadata;
- tool request/result metadata;
- approval;
- state transition;
- usage;
- artifact created;
- error.

Large payloads may live in object storage with references.

### FR-F08-005 — Conversation privacy

Prompt/response content logging is configurable. Metadata/audit must remain available even if content retention is disabled.

### FR-F08-006 — Artifact references

Artifacts can be:

- local-only;
- cloud-uploaded;
- external link/reference.

Metadata records MIME/type, size, checksum when available, creator run and retention policy.

### FR-F08-007 — Cancellation

Cancellation is idempotent and propagates to execution host and inference stream.

### FR-F08-008 — Resume/retry

Retry creates a new run attempt linked to prior run; do not mutate failed run history.

Resume of a session MUST respect current authorization/policy, not blindly reuse stale permissions.

## ZCode mapping

ZCode already exposes task/session snapshots, model selection, tool execution, browser/computer capabilities and remote workspace runtime. Preserve external references so migration/debugging remains possible.

## Web UX

P0 web views:

- session/run list;
- run detail/timeline;
- status and failure reason;
- model/provider/usage summary;
- tool/approval summary;
- artifact links where permitted.

## Acceptance criteria

- Run history is append-only.
- Retried run does not overwrite prior error/usage.
- Removed member cannot resume old session without renewed authorization.
- Tool/model policy is evaluated at run start and again for sensitive dynamic operations where required.
