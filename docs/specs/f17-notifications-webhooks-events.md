# F17 — Notifications, Webhooks & Event Delivery

Priority: P1  
Depends on: F16, F21

## Objective

Phát security, operational và product events ra email/in-app/webhook mà không để notification logic chen vào business transaction.

## Channels

- in-app notification;
- email;
- webhook;
- future Slack/Teams connector through plugin/integration layer.

## Requirements

### FR-F17-001 — Event outbox

Business transaction emits durable event/outbox record.

Delivery workers process asynchronously.

### FR-F17-002 — Preferences

User preferences apply to informational notifications.

Critical security events may be mandatory and cannot be fully disabled.

### FR-F17-003 — Webhook endpoint

Org admin can configure endpoint with:

- subscribed event types;
- secret;
- enabled state;
- optional description.

### FR-F17-004 — Webhook security

Deliver over HTTPS.

Sign payload with timestamp + HMAC secret.

Consumer can detect replay.

### FR-F17-005 — Delivery semantics

At-least-once delivery.

Each event has stable `event_id`.

Retry with bounded exponential backoff + jitter.

Do not promise exactly-once.

### FR-F17-006 — Failure handling

After retry window:

- mark dead;
- expose failure;
- allow replay;
- optionally auto-disable persistently failing endpoint.

### FR-F17-007 — Ordering

Do not guarantee global ordering.

For resources where ordering matters, include resource version/sequence.

### FR-F17-008 — Event schema

Version event envelopes.

Never put provider secrets, tokens or raw confidential prompts in webhook payload.

## Web UX

- notification center;
- preferences;
- webhook endpoints;
- test delivery;
- delivery history;
- replay failure.

## Acceptance criteria

- Retried webhook retains same event ID.
- Signature validation example is documented.
- Business mutation succeeds even if destination is temporarily down once event is durably enqueued.
