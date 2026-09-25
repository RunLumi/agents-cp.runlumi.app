import { describe, expect, it } from "vitest";

import { DEFAULT_ENDPOINT_POLICY, MAX_ATTEMPTS_MAX, validateEndpointUrl } from "./helpers";
import {
  buildEndpointRequest,
  emptyEndpointFormValues,
  endpointFormValues,
  type EndpointFormValues,
} from "./endpoint-form";
import type { WebhookEndpoint } from "./api";

function values(overrides: Partial<EndpointFormValues> = {}): EndpointFormValues {
  return { ...emptyEndpointFormValues(), ...overrides };
}

function frozenEndpoint(overrides: Partial<WebhookEndpoint> = {}): WebhookEndpoint {
  return {
    endpoint_id: "whe_0123456789abcdef0123456789abcdef",
    org_id: "org_0123456789abcdef0123456789abcdef",
    name: "Billing events",
    description: "Consumed by finance",
    url: "https://hooks.example.com/lumi",
    subscribed_event_types: ["billing.grace_ended.v1", "auth.login.completed.v1"],
    secret_version_id: "whs_0123456789abcdef0123456789abcdef",
    enabled: true,
    max_attempts: 8,
    base_delay_seconds: 30,
    max_delay_seconds: 86400,
    replay_window_seconds: 300,
    auto_disable_enabled: false,
    auto_disable_threshold: 10,
    consecutive_terminal_failures: 0,
    version: 4,
    created_at: "2026-09-25T12:00:00.000Z",
    updated_at: "2026-09-25T12:00:00.000Z",
    ...overrides,
  };
}

describe("endpoint request building", () => {
  it("defaults to the frozen delivery policy", () => {
    expect(emptyEndpointFormValues().maxAttempts).toBe(DEFAULT_ENDPOINT_POLICY.max_attempts);
    expect(emptyEndpointFormValues().baseDelaySeconds).toBe(30);
    expect(emptyEndpointFormValues().maxDelaySeconds).toBe(86400);
    expect(emptyEndpointFormValues().replayWindowSeconds).toBe(300);
    expect(emptyEndpointFormValues().autoDisableEnabled).toBe(false);
  });

  it("builds a bounded create request from a valid form", () => {
    const result = buildEndpointRequest(
      values({
        name: "  Billing events  ",
        description: "  Consumed by finance  ",
        url: " https://hooks.example.com/lumi ",
        subscribedEventTypes: ["billing.grace_ended.v1", "billing.grace_started.v1"],
        externalEventTypes: ["auth.login.completed.v1"],
      }),
    );
    expect(result.fieldErrors).toEqual({});
    expect(result.input).toEqual({
      name: "Billing events",
      description: "Consumed by finance",
      url: "https://hooks.example.com/lumi",
      subscribed_event_types: [
        "auth.login.completed.v1",
        "billing.grace_ended.v1",
        "billing.grace_started.v1",
      ],
      enabled: true,
      max_attempts: 8,
      base_delay_seconds: 30,
      max_delay_seconds: 86400,
      replay_window_seconds: 300,
      auto_disable_enabled: false,
      auto_disable_threshold: 10,
    });
  });

  it("refuses a wildcard or prefix that reached the form state", () => {
    const wildcard = buildEndpointRequest(
      values({
        name: "x",
        url: "https://hooks.example.com/lumi",
        subscribedEventTypes: ["automation.*"],
      }),
    );
    expect(wildcard.input).toBeNull();
    expect(wildcard.fieldErrors["subscribed_event_types"]).toContain("Wildcards are not accepted");

    const prefix = buildEndpointRequest(
      values({
        name: "x",
        url: "https://hooks.example.com/lumi",
        subscribedEventTypes: ["automation.occurrence"],
      }),
    );
    expect(prefix.fieldErrors["subscribed_event_types"]).toContain("is a family");
  });

  it("requires at least one subscribed event name", () => {
    const result = buildEndpointRequest(
      values({ name: "x", url: "https://hooks.example.com/lumi" }),
    );
    expect(result.input).toBeNull();
    expect(result.fieldErrors["subscribed_event_types"]).toContain("at least one");
  });

  it("bounds the delivery policy to the frozen ranges", () => {
    const result = buildEndpointRequest(
      values({
        name: "x",
        url: "https://hooks.example.com/lumi",
        subscribedEventTypes: ["billing.grace_ended.v1"],
        maxAttempts: MAX_ATTEMPTS_MAX + 1,
        maxDelaySeconds: 10,
        baseDelaySeconds: 30,
        replayWindowSeconds: 10,
      }),
    );
    expect(result.input).toBeNull();
    expect(result.fieldErrors["max_attempts"]).toContain("between 1 and 8");
    expect(result.fieldErrors["max_delay_seconds"]).toContain("cannot be shorter");
    expect(result.fieldErrors["replay_window_seconds"]).toContain("between 30 and 3600");
  });

  it("refuses an auto-disable threshold below ten", () => {
    const below = buildEndpointRequest(
      values({
        name: "x",
        url: "https://hooks.example.com/lumi",
        subscribedEventTypes: ["billing.grace_ended.v1"],
        autoDisableEnabled: true,
        autoDisableThreshold: 5,
      }),
    );
    expect(below.input).toBeNull();
    expect(below.fieldErrors["auto_disable_threshold"]).toContain("at least 10");

    const atFloor = buildEndpointRequest(
      values({
        name: "x",
        url: "https://hooks.example.com/lumi",
        subscribedEventTypes: ["billing.grace_ended.v1"],
        autoDisableEnabled: true,
        autoDisableThreshold: 10,
      }),
    );
    expect(atFloor.input?.auto_disable_threshold).toBe(10);
  });

  it("rejects a non-HTTPS destination before a request is made", () => {
    const result = buildEndpointRequest(
      values({
        name: "x",
        url: "http://hooks.example.com/lumi",
        subscribedEventTypes: ["billing.grace_ended.v1"],
      }),
    );
    expect(result.input).toBeNull();
    expect(result.fieldErrors["url"]).toBe("Webhook delivery uses HTTPS only.");
  });

  it("bounds the name and description lengths", () => {
    const result = buildEndpointRequest(
      values({
        name: "x".repeat(161),
        description: "y".repeat(2001),
        url: "https://hooks.example.com/lumi",
        subscribedEventTypes: ["billing.grace_ended.v1"],
      }),
    );
    expect(result.input).toBeNull();
    expect(result.fieldErrors["name"]).toContain("160");
    expect(result.fieldErrors["description"]).toContain("2000");
  });
});

describe("editing an existing endpoint", () => {
  it("separates P06 names from preserved non-P06 names", () => {
    const form = endpointFormValues(frozenEndpoint());
    expect(form.subscribedEventTypes).toEqual(["billing.grace_ended.v1"]);
    expect(form.externalEventTypes).toEqual(["auth.login.completed.v1"]);
    expect(form.name).toBe("Billing events");
  });

  it("keeps a preserved name in the PATCH body when nothing else changes", () => {
    const form = endpointFormValues(frozenEndpoint());
    const result = buildEndpointRequest(form);
    expect(result.input?.subscribed_event_types).toContain("auth.login.completed.v1");
    expect(result.input?.subscribed_event_types).toContain("billing.grace_ended.v1");
  });

  it("does not invent a description for an endpoint that has none", () => {
    const form = endpointFormValues(frozenEndpoint({ description: null }));
    expect(form.description).toBe("");
    expect(buildEndpointRequest(form).input?.description).toBeNull();
  });
});

describe("url rule parity with the frozen contract", () => {
  it("accepts the two allowed ports and rejects everything else", () => {
    expect(validateEndpointUrl("https://hooks.example.com:8443")).toBeNull();
    expect(validateEndpointUrl("https://hooks.example.com:443")).toBeNull();
    expect(validateEndpointUrl("https://hooks.example.com:80")?.code).toBe("port");
  });
});
