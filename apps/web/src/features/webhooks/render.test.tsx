import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import type { WebhookDelivery, WebhookEndpoint } from "./api";
import { DeliveryHistory } from "./delivery-history";
import { EventTypePicker } from "./event-type-picker";
import { INITIAL_ONE_TIME_SECRET, oneTimeSecretReducer } from "./one-time-secret";
import { SecretReveal } from "./secret-reveal";
import type { EndpointFormValues } from "./endpoint-form";
import { emptyEndpointFormValues } from "./endpoint-form";

/** Synthetic show-once signing values; see the note in api.test.ts. */
const SHOWN_ONCE = "fixture-signing-value-once_only";
const ROTATED = "fixture-signing-value-rotated";

function endpoint(overrides: Partial<WebhookEndpoint> = {}): WebhookEndpoint {
  return {
    endpoint_id: "whe_0123456789abcdef0123456789abcdef",
    org_id: "org_0123456789abcdef0123456789abcdef",
    name: "Billing events",
    description: null,
    url: "https://hooks.example.com/lumi",
    subscribed_event_types: ["billing.grace_ended.v1"],
    secret_version_id: "whs_0123456789abcdef0123456789abcdef",
    enabled: false,
    max_attempts: 8,
    base_delay_seconds: 30,
    max_delay_seconds: 86400,
    replay_window_seconds: 300,
    auto_disable_enabled: true,
    auto_disable_threshold: 10,
    consecutive_terminal_failures: 10,
    version: 5,
    created_at: "2026-09-25T12:00:00.000Z",
    updated_at: "2026-09-25T12:30:00.000Z",
    ...overrides,
  };
}

function delivery(overrides: Partial<WebhookDelivery> = {}): WebhookDelivery {
  return {
    delivery_id: "whd_0123456789abcdef0123456789abcdef",
    endpoint_id: "whe_0123456789abcdef0123456789abcdef",
    event_id: "evt_0123456789abcdef0123456789abcdef",
    event_type: "automation.occurrence.completed.v1",
    body_hash: "sha256:0123456789abcdef",
    secret_version_id: "whs_0123456789abcdef0123456789abcdef",
    signature_key_id: "whs_0123456789abcdef0123456789abcdef",
    state: "dead_letter",
    attempt_count: 8,
    next_attempt_at: null,
    delivered_at: null,
    last_error_code: "webhook_timeout",
    replay_of_delivery_id: null,
    replay_generation: 0,
    version: 1,
    created_at: "2026-09-25T12:00:00.000Z",
    updated_at: "2026-09-25T12:05:00.000Z",
    ...overrides,
  };
}

function renderDeliveryHistory(props: Partial<Parameters<typeof DeliveryHistory>[0]> = {}): string {
  return renderToStaticMarkup(
    <DeliveryHistory
      endpoint={endpoint()}
      deliveries={[delivery()]}
      selectedDeliveryId={null}
      status="ready"
      error={null}
      hasMore={false}
      stateFilter=""
      onStateFilterChange={() => {}}
      onRetry={() => {}}
      onLoadMore={() => {}}
      onSelectDelivery={() => {}}
      onReplay={() => {}}
      replayingDeliveryId={null}
      replayError={null}
      {...props}
    />,
  );
}

describe("delivery history rendering", () => {
  it("states that a dead letter is not retried and offers a replay", () => {
    const markup = renderDeliveryHistory();
    expect(markup).toContain("Dead letter");
    expect(markup).toContain("not retried again");
    expect(markup).toContain("Original delivery");
    expect(markup).toContain("Replay");
  });

  it("reports the attempt budget and every stable diagnostic", () => {
    const markup = renderDeliveryHistory({
      deliveries: [delivery({ last_http_status: 503, last_latency_ms: 980 })],
    });
    expect(markup).toContain("8 of 8");
    expect(markup).toContain("503");
    expect(markup).toContain("980 ms");
    expect(markup).toContain("webhook_timeout");
  });

  it("shows a waiting retry differently from an exhausted delivery", () => {
    const markup = renderDeliveryHistory({
      deliveries: [delivery({ state: "retry_wait", next_attempt_at: "2026-09-25T12:10:00.000Z" })],
    });
    expect(markup).toContain("Retry scheduled");
    expect(markup).toContain("next ");
    expect(markup).not.toContain("This delivery is not retried again");
  });

  it("shows a replay successor's lineage and keeps the original state visible", () => {
    const original = delivery();
    const successor = delivery({
      delivery_id: "whd_1123456789abcdef0123456789abcdef",
      state: "queued",
      replay_of_delivery_id: original.delivery_id,
      replay_generation: 1,
    });
    const markup = renderDeliveryHistory({ deliveries: [successor, original] });
    expect(markup).toContain("Replay of whd_01234567");
    expect(markup).toContain("1 replay successor");
    expect(markup).toContain("Successor replay of");
  });

  it("never renders a delivery body, only bounded metadata and the body hash", () => {
    const markup = renderDeliveryHistory();
    expect(markup).toContain("sha256:0123456789abcdef");
    expect(markup).toContain("is not returned by this route");
    expect(markup).not.toContain("<pre");
  });

  it("keeps an optional payload preview collapsed and labelled as customer data", () => {
    const markup = renderDeliveryHistory({
      deliveries: [delivery({ payload: { state: "succeeded", reason_code: null } })],
    });
    expect(markup).toContain("Delivery payload metadata — may contain customer identifiers");
    expect(markup).toContain("<details");
  });

  it("shows the auto-disabled reason and threshold on the delivery surface", () => {
    const markup = renderDeliveryHistory();
    expect(markup).toContain("Auto-disabled");
    expect(markup).toContain("10 consecutive terminal failures");
  });
});

describe("one-time secret rendering", () => {
  it("renders nothing once the secret is forgotten", () => {
    const forgotten = oneTimeSecretReducer(INITIAL_ONE_TIME_SECRET, { type: "forget" });
    expect(renderToStaticMarkup(<SecretReveal state={forgotten} onForget={() => {}} />)).toBe("");
  });

  it("marks the value as shown once and says it cannot be recovered", () => {
    const revealed = oneTimeSecretReducer(INITIAL_ONE_TIME_SECRET, {
      type: "reveal",
      secret: SHOWN_ONCE,
      reason: "created",
    });
    const markup = renderToStaticMarkup(<SecretReveal state={revealed} onForget={() => {}} />);
    expect(markup).toContain("SHOWN ONCE");
    expect(markup).toContain("Signing secret — shown once");
    expect(markup).toContain("cannot be shown again");
    expect(markup).toContain(SHOWN_ONCE);
    expect(markup).toContain("never written to browser storage");
    expect(markup).toContain("X-Lumi-Signature");
  });

  it("warns that a rotation invalidates the previous secret immediately", () => {
    const rotated = oneTimeSecretReducer(INITIAL_ONE_TIME_SECRET, {
      type: "reveal",
      secret: ROTATED,
      reason: "rotated",
    });
    const markup = renderToStaticMarkup(<SecretReveal state={rotated} onForget={() => {}} />);
    expect(markup).toContain("previous secret stops verifying");
  });
});

describe("event-type picker rendering", () => {
  function renderPicker(selected: readonly string[] = []): string {
    const values: EndpointFormValues = {
      ...emptyEndpointFormValues(),
      subscribedEventTypes: selected,
    };
    expect(values).toBeDefined();
    return renderToStaticMarkup(
      <EventTypePicker
        selected={selected}
        preservedExternal={["auth.login.completed.v1"]}
        onChange={() => {}}
      />,
    );
  }

  it("makes the exact-names-only rule visible", () => {
    const markup = renderPicker();
    expect(markup).toContain("EXACT NAMES ONLY");
    expect(markup).toContain("A wildcard (*)");
    expect(markup).toContain("family prefix");
    expect(markup).toContain("is rejected here with a reason");
  });

  it("disables and explains the never-fanned-out families", () => {
    const markup = renderPicker();
    expect(markup).toContain("Never fanned out");
    expect(markup).toContain("webhook.test.v1");
    expect(markup).toContain("disabled");
  });

  it("warns when nothing is selected yet", () => {
    expect(renderPicker()).toContain("receives nothing");
  });

  it("lists a preserved non-P06 subscription instead of dropping it", () => {
    const markup = renderPicker(["billing.grace_ended.v1"]);
    expect(markup).toContain("Preserved subscriptions outside the P06 list");
    expect(markup).toContain("auth.login.completed.v1");
  });
});
