import { describe, expect, it } from "vitest";

import { WEBHOOK_DELIVERY_STATES, type WebhookDelivery, type WebhookEndpoint } from "./api";
import {
  AUTO_DISABLE_MIN_THRESHOLD,
  canReplayDelivery,
  classifyDeliveryReason,
  deliveryLineage,
  deliveryStateInfo,
  describeLineage,
  endpointActivation,
  endpointActivationLabel,
  formatAttemptCount,
  formatLatency,
  isDeliveryState,
  isTerminalDeliveryState,
  replayBlockedReason,
  validateEndpointUrl,
} from "./helpers";

function endpoint(overrides: Partial<WebhookEndpoint> = {}): WebhookEndpoint {
  return {
    endpoint_id: "whe_0123456789abcdef0123456789abcdef",
    org_id: "org_0123456789abcdef0123456789abcdef",
    name: "Billing events",
    description: null,
    url: "https://hooks.example.com/lumi",
    subscribed_event_types: ["billing.grace_ended.v1"],
    secret_version_id: "whs_0123456789abcdef0123456789abcdef",
    enabled: true,
    max_attempts: 8,
    base_delay_seconds: 30,
    max_delay_seconds: 86400,
    replay_window_seconds: 300,
    auto_disable_enabled: false,
    auto_disable_threshold: 10,
    consecutive_terminal_failures: 0,
    version: 3,
    created_at: "2026-09-25T12:00:00.000Z",
    updated_at: "2026-09-25T12:00:00.000Z",
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
    state: "delivered",
    attempt_count: 1,
    next_attempt_at: null,
    delivered_at: "2026-09-25T12:00:05.000Z",
    last_error_code: null,
    replay_of_delivery_id: null,
    replay_generation: 0,
    version: 1,
    created_at: "2026-09-25T12:00:00.000Z",
    updated_at: "2026-09-25T12:00:05.000Z",
    ...overrides,
  };
}

describe("delivery state semantics", () => {
  it("recognizes only the seven frozen states", () => {
    expect(WEBHOOK_DELIVERY_STATES).toEqual([
      "pending",
      "queued",
      "delivering",
      "delivered",
      "retry_wait",
      "dead_letter",
      "cancelled",
    ]);
    expect(isDeliveryState("retry_wait")).toBe(true);
    expect(isDeliveryState("expired")).toBe(false);
  });

  it("separates a waiting retry from an exhausted dead letter", () => {
    expect(deliveryStateInfo("retry_wait").waitingForRetry).toBe(true);
    expect(isTerminalDeliveryState("retry_wait")).toBe(false);
    expect(isTerminalDeliveryState("dead_letter")).toBe(true);
    expect(deliveryStateInfo("dead_letter").detail).toContain("NOT retried");
    expect(deliveryStateInfo("delivered").detail).toContain("2xx");
  });

  it("offers replay only for a dead letter and explains every other state", () => {
    expect(canReplayDelivery(delivery({ state: "dead_letter" }))).toBe(true);
    for (const state of [
      "pending",
      "queued",
      "delivering",
      "delivered",
      "cancelled",
      "retry_wait",
    ] as const) {
      const candidate = delivery({ state });
      expect(canReplayDelivery(candidate)).toBe(false);
      expect(replayBlockedReason(candidate).length).toBeGreaterThan(0);
    }
  });
});

describe("replay lineage", () => {
  it("links a successor to its predecessor without mutating either", () => {
    const original = delivery({ state: "dead_letter", attempt_count: 8 });
    const successor = delivery({
      delivery_id: "whd_1123456789abcdef0123456789abcdef",
      state: "queued",
      attempt_count: 0,
      replay_of_delivery_id: original.delivery_id,
      replay_generation: 1,
    });
    const lineage = deliveryLineage([original, successor]);

    expect(lineage.get(original.delivery_id)?.childIds).toEqual([successor.delivery_id]);
    expect(lineage.get(successor.delivery_id)?.parentId).toBe(original.delivery_id);
    expect(original.state).toBe("dead_letter");
    expect(successor.event_id).toBe(original.event_id);
    expect(describeLineage(successor, lineage)).toContain("Successor replay");
    expect(describeLineage(original, lineage)).toContain("1 replay successor");
  });

  it("describes an original with no replay", () => {
    const lineage = deliveryLineage([delivery()]);
    expect(describeLineage(delivery(), lineage)).toBe(
      "Original delivery. No replay has been created from it.",
    );
  });
});

describe("endpoint activation", () => {
  it("marks an automatic disable apart from an operator disable", () => {
    const autoDisabled = endpoint({
      enabled: false,
      auto_disable_enabled: true,
      consecutive_terminal_failures: AUTO_DISABLE_MIN_THRESHOLD,
    });
    const activation = endpointActivation(autoDisabled);
    expect(activation).toEqual({
      kind: "auto_disabled",
      consecutive: 10,
      threshold: 10,
    });
    expect(endpointActivationLabel(activation)).toBe("Auto-disabled");

    const operatorDisabled = endpoint({ enabled: false, consecutive_terminal_failures: 2 });
    expect(endpointActivation(operatorDisabled)).toEqual({ kind: "operator_disabled" });
    expect(endpointActivationLabel(endpointActivation(operatorDisabled))).toBe(
      "Disabled by an operator",
    );
  });

  it("keeps an under-threshold endpoint enabled and reports the gap", () => {
    const activation = endpointActivation(
      endpoint({ auto_disable_enabled: true, consecutive_terminal_failures: 9 }),
    );
    expect(activation).toEqual({ kind: "failing", consecutive: 9, threshold: 10 });
  });

  it("reports a healthy endpoint as active", () => {
    expect(endpointActivation(endpoint())).toEqual({ kind: "active" });
  });
});

describe("endpoint URL rules", () => {
  it("requires HTTPS and rejects credentials and non-standard ports", () => {
    expect(validateEndpointUrl("http://hooks.example.com")?.code).toBe("https_required");
    expect(validateEndpointUrl("https://user:pass@hooks.example.com")?.code).toBe("userinfo");
    expect(validateEndpointUrl("https://hooks.example.com:8443")).toBeNull();
    expect(validateEndpointUrl("https://hooks.example.com:443")).toBeNull();
    expect(validateEndpointUrl("https://hooks.example.com:8080")?.code).toBe("port");
    expect(validateEndpointUrl("not a url")?.code).toBe("unparsable");
    expect(validateEndpointUrl("")?.code).toBe("empty");
  });
});

describe("bounded reason codes", () => {
  it("classifies only stable frozen codes and never invents prose", () => {
    expect(classifyDeliveryReason("webhook_timeout")).toBe("retryable");
    expect(classifyDeliveryReason("webhook_url_blocked")).toBe("terminal");
    expect(classifyDeliveryReason("webhook_signature_invalid")).toBe("terminal");
    expect(classifyDeliveryReason("something new")).toBe("unknown");
    expect(classifyDeliveryReason(null)).toBe("unknown");
  });
});

describe("diagnostic formatting", () => {
  it("shows the attempt budget and reports absent diagnostics as unreported", () => {
    expect(formatAttemptCount(delivery({ attempt_count: 3 }), 8)).toBe("3 of 8");
    expect(formatLatency(240)).toBe("240 ms");
    expect(formatLatency(1500)).toBe("1.50 s");
    expect(formatLatency(null)).toBe("Not reported");
    expect(formatLatency(undefined)).toBe("Not reported");
  });
});
