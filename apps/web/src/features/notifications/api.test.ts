import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiClientError } from "@/lib/errors";

import {
  getNotificationPreferences,
  listNotifications,
  markNotificationRead,
  NOTIFICATION_CATEGORIES,
  NOTIFICATION_CHANNELS,
  updateNotificationPreference,
} from "./api";

const requestId = "req_0123456789abcdef0123456789abcdef";
const notificationId = "ntf_0123456789abcdef0123456789abcdef";
const orgId = "org_0123456789abcdef0123456789abcdef";

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "X-Request-ID": requestId },
  });
}

function notificationBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    notification_id: notificationId,
    org_id: orgId,
    event_id: "evt_0123456789abcdef0123456789abcdef",
    event_type: "automation.occurrence.completed.v1",
    category: "automation",
    mandatory: false,
    state: "unread",
    read_at: null,
    body: { state: "succeeded" },
    created_at: "2026-09-25T12:00:00.000Z",
    updated_at: "2026-09-25T12:00:00.000Z",
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

describe("P06 notification API contract", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
    vi.stubGlobal("document", { cookie: "lumi_csrf=csrf-token" });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("declares only the frozen categories and channels", () => {
    expect(NOTIFICATION_CATEGORIES).toEqual([
      "security",
      "billing",
      "automation",
      "policy",
      "operational",
    ]);
    expect(NOTIFICATION_CHANNELS).toEqual(["in_app", "email"]);
  });

  it("reads the app-level center without an organization in the path", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ items: [notificationBody()], next_cursor: "c1", has_more: true }),
    );
    const page = await listNotifications({ limit: 25, unread: true, category: "security" });
    expect(page.items[0]?.notification_id).toBe(notificationId);
    const [path] = lastCall();
    expect(path).toBe("/api/v1/notifications?limit=25&unread=true&category=security");
    expect(path).not.toContain(orgId);
  });

  it("marks one owned notification read idempotently", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response(notificationBody({ state: "read", read_at: "2026-09-25T12:30:00.000Z" })),
    );
    const read = await markNotificationRead(notificationId);
    expect(read.state).toBe("read");
    const [path, init] = lastCall();
    expect(path).toBe(`/api/v1/notifications/${notificationId}/read`);
    expect(init.method).toBe("POST");
    expect(new Headers(init.headers).get("X-CSRF-Token")).toBe("csrf-token");
  });

  it("keeps a mandatory security notification visible in the projection", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({
        items: [
          notificationBody({
            event_type: "auth.login.completed.v1",
            category: "security",
            mandatory: true,
            state: "unread",
          }),
        ],
        next_cursor: null,
        has_more: false,
      }),
    );
    const page = await listNotifications();
    expect(page.items[0]?.mandatory).toBe(true);
    expect(page.items[0]?.category).toBe("security");
  });

  it("rejects an unknown category rather than sending it to the server", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({
        items: [notificationBody({ category: "marketing" })],
        next_cursor: null,
        has_more: false,
      }),
    );
    await expect(listNotifications()).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("rejects a page whose item is missing the mandatory flag", async () => {
    const body = notificationBody();
    delete body["mandatory"];
    vi.mocked(fetch).mockResolvedValue(
      response({ items: [body], next_cursor: null, has_more: false }),
    );
    await expect(listNotifications()).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("reads personal preferences from the account route", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({
        preferences: [
          { channel: "in_app", disabled_event_types: [], version: 3, updated_at: null },
          {
            channel: "email",
            disabled_event_types: ["export.requested.v1"],
            version: 1,
            updated_at: null,
          },
        ],
      }),
    );
    const rows = await getNotificationPreferences({ kind: "me" });
    expect(rows.map((row) => row.channel)).toEqual(["in_app", "email"]);
    expect(rows[0]?.version).toBe(3);
    const [path] = lastCall();
    expect(path).toBe("/api/v1/me/notification-preferences");
  });

  it("reads organization preferences from the org route", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({
        preferences: [
          { channel: "in_app", disabled_event_types: [], version: 0, updated_at: null },
        ],
      }),
    );
    await getNotificationPreferences({ kind: "org", orgId });
    const [path] = lastCall();
    expect(path).toBe(`/api/v1/orgs/${orgId}/notification-preferences`);
  });

  it("sends the current version and idempotency key on a preference write", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({
        channel: "email",
        disabled_event_types: ["export.requested.v1"],
        version: 2,
        updated_at: "2026-09-25T12:00:00.000Z",
      }),
    );
    const saved = await updateNotificationPreference(
      { kind: "me" },
      { channel: "email", version: 1, disabled_event_types: ["export.requested.v1"] },
      "idem-pref",
    );
    expect(saved.version).toBe(2);
    const [path, init] = lastCall();
    expect(path).toBe("/api/v1/me/notification-preferences");
    expect(init.method).toBe("PATCH");
    expect(new Headers(init.headers).get("Idempotency-Key")).toBe("idem-pref");
    expect(requestBody(init)).toEqual({
      channel: "email",
      version: 1,
      disabled_event_types: ["export.requested.v1"],
    });
  });

  it("surfaces a foreign notification as the same non-disclosing not-found shape", async () => {
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
    const error = await markNotificationRead("ntf_1123456789abcdef0123456789abcdef").catch(
      (thrown: unknown) => thrown,
    );
    expect(error).toBeInstanceOf(ApiClientError);
    expect((error as ApiClientError).code).toBe("resource_not_found");
    expect((error as ApiClientError).message).toBe("The request could not be completed.");
  });
});
