import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiClientError } from "@/lib/errors";

import {
  createWebhookEndpoint,
  disableWebhookEndpoint,
  listWebhookDeliveries,
  listWebhookEndpoints,
  replayWebhookDelivery,
  rotateWebhookSecret,
  sendWebhookTest,
  updateWebhookEndpoint,
  WEBHOOK_DELIVERY_STATES,
} from "./api";

/**
 * Synthetic signing values standing in for the plaintext the server returns
 * exactly once. These are not credentials and leave the test process only as
 * an in-memory object literal.
 */
const PLAINTEXT_ON_CREATE = "fixture-signing-value-plaintext_once";
const PLAINTEXT_ON_ROTATE = "fixture-signing-value-rotated_once";

const requestId = "req_0123456789abcdef0123456789abcdef";
const orgId = "org_0123456789abcdef0123456789abcdef";
const endpointId = "whe_0123456789abcdef0123456789abcdef";
const deliveryId = "whd_0123456789abcdef0123456789abcdef";

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "X-Request-ID": requestId },
  });
}

function endpointBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    endpoint_id: endpointId,
    org_id: orgId,
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
    version: 1,
    created_at: "2026-09-25T12:00:00.000Z",
    updated_at: "2026-09-25T12:00:00.000Z",
    ...overrides,
  };
}

function deliveryBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    delivery_id: deliveryId,
    endpoint_id: endpointId,
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

function lastCall(): [string, RequestInit] {
  const call = vi.mocked(fetch).mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  const [url, init] = call;
  if (typeof url !== "string") throw new Error("fetch was not called with a string URL");
  return [url, (init ?? {}) as RequestInit];
}

function requestBody(init: RequestInit): unknown {
  if (typeof init.body !== "string") throw new Error("the request carried no JSON body");
  return JSON.parse(init.body);
}

describe("P06 webhook API contract", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
    vi.stubGlobal("document", { cookie: "lumi_csrf=csrf-token" });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("exposes exactly the seven frozen delivery states", () => {
    expect(WEBHOOK_DELIVERY_STATES).toEqual([
      "pending",
      "queued",
      "delivering",
      "delivered",
      "retry_wait",
      "dead_letter",
      "cancelled",
    ]);
  });

  it("lists endpoints on the org path with disabled rows included", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ items: [endpointBody()], next_cursor: "cursor-1", has_more: true }),
    );
    const page = await listWebhookEndpoints(orgId, { limit: 25, include_disabled: true });
    expect(page.items[0]?.endpoint_id).toBe(endpointId);
    expect(page.has_more).toBe(true);

    const [path, init] = lastCall();
    expect(path).toBe(`/api/v1/orgs/${orgId}/webhooks?limit=25&include_disabled=true`);
    expect(init.method).toBe("GET");
  });

  it("returns the create secret exactly once and sends the idempotency boundary", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ endpoint: endpointBody(), secret: PLAINTEXT_ON_CREATE }, 201),
    );
    const created = await createWebhookEndpoint(
      orgId,
      {
        name: "Billing events",
        url: "https://hooks.example.com/lumi",
        subscribed_event_types: ["billing.grace_ended.v1"],
      },
      "idem-create",
    );
    expect(created.secret).toBe(PLAINTEXT_ON_CREATE);
    expect(created.endpoint.secret_version_id).toBe("whs_0123456789abcdef0123456789abcdef");

    const [, init] = lastCall();
    expect(new Headers(init.headers).get("Idempotency-Key")).toBe("idem-create");
    expect(new Headers(init.headers).get("X-CSRF-Token")).toBe("csrf-token");
  });

  it("refuses a create response with no secret rather than pretending it succeeded", async () => {
    vi.mocked(fetch).mockResolvedValue(response({ endpoint: endpointBody() }, 201));
    await expect(
      createWebhookEndpoint(
        orgId,
        {
          name: "Billing events",
          url: "https://hooks.example.com/lumi",
          subscribed_event_types: [],
        },
        "idem-create",
      ),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("carries the current version on PATCH and returns the post-commit projection", async () => {
    vi.mocked(fetch).mockResolvedValue(response(endpointBody({ version: 2 })));
    const updated = await updateWebhookEndpoint(
      orgId,
      endpointId,
      {
        name: "Billing events",
        url: "https://hooks.example.com/lumi",
        subscribed_event_types: ["billing.grace_ended.v1"],
        version: 1,
      },
      "idem-patch",
    );
    expect(updated.version).toBe(2);
    const [path, init] = lastCall();
    expect(path).toBe(`/api/v1/orgs/${orgId}/webhooks/${endpointId}`);
    expect(init.method).toBe("PATCH");
    expect(requestBody(init)).toMatchObject({ version: 1 });
  });

  it("disables with a versioned DELETE and tolerates the empty 204 body", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(null, { status: 204 }));
    await expect(
      disableWebhookEndpoint(orgId, endpointId, { version: 2 }, "idem-disable"),
    ).resolves.toBeUndefined();
    const [path, init] = lastCall();
    expect(path).toBe(`/api/v1/orgs/${orgId}/webhooks/${endpointId}`);
    expect(init.method).toBe("DELETE");
  });

  it("rotates the secret and returns only the new version plus the one-time value", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({
        endpoint_id: endpointId,
        secret_version_id: "whs_1123456789abcdef0123456789abcdef",
        secret: PLAINTEXT_ON_ROTATE,
      }),
    );
    const rotated = await rotateWebhookSecret(orgId, endpointId, "idem-rotate");
    expect(rotated.secret).toBe(PLAINTEXT_ON_ROTATE);
    const [path] = lastCall();
    expect(path).toBe(`/api/v1/orgs/${orgId}/webhooks/${endpointId}/rotate-secret`);
  });

  it("queues a bounded test delivery and reports the queued state", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response(
        {
          delivery_id: deliveryId,
          endpoint_id: endpointId,
          event_id: "evt_0123456789abcdef0123456789abcdef",
          state: "pending",
        },
        202,
      ),
    );
    const queued = await sendWebhookTest(orgId, endpointId, "idem-test");
    expect(queued.state).toBe("pending");
    const [path, init] = lastCall();
    expect(path).toBe(`/api/v1/orgs/${orgId}/webhooks/${endpointId}/test`);
    expect(init.method).toBe("POST");
  });

  it("passes the state filter through to delivery history", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ items: [deliveryBody()], next_cursor: null, has_more: false }),
    );
    const page = await listWebhookDeliveries(orgId, endpointId, {
      limit: 25,
      state: "dead_letter",
    });
    expect(page.items[0]?.state).toBe("dead_letter");
    const [path] = lastCall();
    expect(path).toBe(
      `/api/v1/orgs/${orgId}/webhooks/${endpointId}/deliveries?limit=25&state=dead_letter`,
    );
  });

  it("accepts the optional attempt diagnostics without inventing them", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({
        items: [deliveryBody({ last_http_status: 503, last_latency_ms: 980 })],
        next_cursor: null,
        has_more: false,
      }),
    );
    const withDiagnostics = await listWebhookDeliveries(orgId, endpointId);
    expect(withDiagnostics.items[0]?.last_http_status).toBe(503);
    expect(withDiagnostics.items[0]?.last_latency_ms).toBe(980);

    vi.mocked(fetch).mockResolvedValue(
      response({ items: [deliveryBody()], next_cursor: null, has_more: false }),
    );
    const withoutDiagnostics = await listWebhookDeliveries(orgId, endpointId);
    expect(withoutDiagnostics.items[0]?.last_http_status).toBeUndefined();
  });

  it("rejects the whole page when a diagnostic field is out of range", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({
        items: [deliveryBody({ last_http_status: 999 })],
        next_cursor: null,
        has_more: false,
      }),
    );
    await expect(listWebhookDeliveries(orgId, endpointId)).rejects.toMatchObject({
      code: "invalid_response",
    });
  });

  it("rejects an unknown delivery state rather than rendering it as a live value", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({
        items: [deliveryBody({ state: "expired" })],
        next_cursor: null,
        has_more: false,
      }),
    );
    await expect(listWebhookDeliveries(orgId, endpointId)).rejects.toMatchObject({
      code: "invalid_response",
    });
  });

  it("creates a successor delivery on replay and keeps the original reference", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response(
        {
          delivery_id: "whd_1123456789abcdef0123456789abcdef",
          replay_of_delivery_id: deliveryId,
          replay_generation: 1,
          event_id: "evt_0123456789abcdef0123456789abcdef",
          body_hash: "sha256:0123456789abcdef",
          secret_version_id: "whs_1123456789abcdef0123456789abcdef",
          state: "pending",
        },
        201,
      ),
    );
    const replayed = await replayWebhookDelivery(orgId, deliveryId, { version: 1 }, "idem-replay");
    expect(replayed.replay_of_delivery_id).toBe(deliveryId);
    expect(replayed.replay_generation).toBe(1);
    const [path] = lastCall();
    expect(path).toBe(`/api/v1/orgs/${orgId}/webhooks/deliveries/${deliveryId}/replay`);
  });

  it("surfaces a non-disclosing not-found through the shared error envelope", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response(
        {
          error: {
            code: "resource_not_found",
            message: "Not found",
            request_id: requestId,
            details: { reason: "resource_not_found" },
          },
        },
        404,
      ),
    );
    const error = await listWebhookEndpoints("org_1123456789abcdef0123456789abcdef").catch(
      (thrown: unknown) => thrown,
    );
    expect(error).toBeInstanceOf(ApiClientError);
    expect((error as ApiClientError).code).toBe("resource_not_found");
    // The message must never be the server prose.
    expect((error as ApiClientError).message).toBe("The request could not be completed.");
  });

  it("refuses a page whose cursor shape is wrong", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ items: [endpointBody()], next_cursor: 42, has_more: false }),
    );
    await expect(listWebhookEndpoints(orgId)).rejects.toMatchObject({ code: "invalid_response" });
  });
});
