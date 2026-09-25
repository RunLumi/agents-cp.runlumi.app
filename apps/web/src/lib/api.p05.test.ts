import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createBudget, listTools } from "@/lib/api";
import { ApiClientError, presentApiError } from "@/lib/errors";

const requestId = "req_0123456789abcdef0123456789abcdef";

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "X-Request-ID": requestId },
  });
}

describe("P05 API contracts", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
    vi.stubGlobal("document", { cookie: "lumi_csrf=csrf-token" });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("decodes the stable tool_id field", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({
        items: [
          {
            tool_id: "tool_0123456789abcdef0123456789abcdef",
            org_id: "org_0123456789abcdef0123456789abcdef",
            name: "Read repository",
            source: "built_in",
            risk_class: "read_only",
            capability_ids: [],
            fingerprint: "sha256:fixture",
            lifecycle: "active",
            metadata: {},
            version: 1,
            created_at: "2026-09-25T12:00:00.000Z",
            updated_at: "2026-09-25T12:00:00.000Z",
          },
        ],
        next_cursor: null,
        has_more: false,
      }),
    );

    await expect(listTools("org_0123456789abcdef0123456789abcdef")).resolves.toMatchObject({
      items: [{ tool_id: "tool_0123456789abcdef0123456789abcdef" }],
    });
    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/orgs/org_0123456789abcdef0123456789abcdef/tools",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("keeps budget mutations currency-safe and sends the idempotency boundary", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response(
        {
          budget_id: "bud_0123456789abcdef0123456789abcdef",
          org_id: "org_0123456789abcdef0123456789abcdef",
          scope_type: "organization",
          scope_id: null,
          period_start: "2026-09-01T00:00:00.000Z",
          period_end: "2026-10-01T00:00:00.000Z",
          limit_minor: 1000,
          currency: "USD",
          hard: true,
          lifecycle: "active",
          state: "active",
          version: 1,
          created_at: "2026-09-25T12:00:00.000Z",
          updated_at: "2026-09-25T12:00:00.000Z",
        },
        201,
      ),
    );

    await createBudget(
      "org_0123456789abcdef0123456789abcdef",
      {
        scope_type: "organization",
        scope_id: null,
        period_start: "2026-09-01T00:00:00.000Z",
        period_end: "2026-10-01T00:00:00.000Z",
        limit_minor: 1000,
        currency: "USD",
        hard: true,
      },
      "budget-key",
    );

    const [, init] = vi.mocked(fetch).mock.calls[0] ?? [];
    const headers = new Headers(init?.headers);
    expect(headers.get("Idempotency-Key")).toBe("budget-key");
    expect(headers.get("X-CSRF-Token")).toBe("csrf-token");
  });

  it("presents the stable hard-budget denial without server prose", () => {
    const error = new ApiClientError({
      code: "budget_exceeded",
      kind: "api",
      status: 403,
      requestId,
      retryable: false,
    });
    const presentation = presentApiError(error);
    expect(presentation).toMatchObject({ code: "budget_exceeded", retryable: false });
    expect(presentation.message).not.toContain("provider diagnostic");
  });
});
