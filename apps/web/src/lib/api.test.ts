import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createFoundationCheck, getHealth } from "@/lib/api";
import { ApiClientError, presentApiError } from "@/lib/errors";

const requestId = "req_0123456789abcdef0123456789abcdef";

describe("API client", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("parses a successful health response", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ status: "ok", service: "lumi-agents-control-plane-api" }),
    );

    await expect(getHealth()).resolves.toEqual({
      status: "ok",
      service: "lumi-agents-control-plane-api",
    });
    expect(fetch).toHaveBeenCalledWith(
      "/api/health",
      expect.objectContaining({ headers: expect.any(Headers) }),
    );
  });

  it("uses the stable API code and prefers the trusted response request ID", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(
        {
          error: {
            code: "permission_denied",
            message: "Private server diagnostic text",
            request_id: "req_body_value",
            details: {},
          },
        },
        403,
        { "X-Request-ID": requestId },
      ),
    );

    const error = await getHealth().catch((value: unknown) => value);

    expect(error).toBeInstanceOf(ApiClientError);
    expect(error).toMatchObject({
      code: "permission_denied",
      status: 403,
      requestId,
      retryable: false,
    });
    expect(presentApiError(error)).toMatchObject({
      title: "Access not permitted",
      code: "permission_denied",
      requestId,
    });
    expect(presentApiError(error).message).not.toContain("Private server diagnostic text");
  });

  it("falls back to the request ID in an API error envelope", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(
        {
          error: {
            code: "not_found",
            message: "Not found",
            request_id: requestId,
            details: {},
          },
        },
        404,
      ),
    );

    const error = await getHealth().catch((value: unknown) => value);

    expect(error).toMatchObject({ code: "not_found", requestId, status: 404 });
    expect(presentApiError(error).requestId).toBe(requestId);
  });

  it("shows generic copy for unknown API codes while retaining the code and request ID", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(
        {
          error: {
            code: "future_error_code",
            message: "A server message that may change",
            request_id: requestId,
            details: {},
          },
        },
        400,
      ),
    );

    const error = await getHealth().catch((value: unknown) => value);
    const presentation = presentApiError(error);

    expect(presentation).toMatchObject({
      title: "The request could not be completed",
      code: "future_error_code",
      requestId,
    });
    expect(presentation.message).not.toContain("A server message that may change");
  });

  it("normalizes malformed JSON and retains the response request ID", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response("{", { status: 200, headers: { "X-Request-ID": requestId } }),
    );

    const error = await getHealth().catch((value: unknown) => value);

    expect(error).toMatchObject({
      code: "invalid_response",
      kind: "invalid_response",
      requestId,
      status: 200,
    });
  });

  it("normalizes an invalid error envelope without exposing its body", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response('{"error":{"message":"private detail"}}', {
        status: 500,
        headers: { "X-Request-ID": requestId },
      }),
    );

    const error = await getHealth().catch((value: unknown) => value);

    expect(error).toMatchObject({
      code: "invalid_error_response",
      kind: "invalid_response",
      requestId,
      status: 500,
      retryable: true,
    });
    expect(presentApiError(error).message).not.toContain("private detail");
  });

  it("marks safe reads retryable after a network failure", async () => {
    vi.mocked(fetch).mockRejectedValue(new Error("private transport diagnostic"));

    const error = await getHealth().catch((value: unknown) => value);

    expect(error).toMatchObject({
      code: "network_error",
      kind: "network",
      retryable: true,
    });
    expect(presentApiError(error).message).not.toContain("private transport diagnostic");
  });

  it("preserves the request ID when a response body read is aborted", async () => {
    const response = new Response("{}", {
      status: 200,
      headers: { "X-Request-ID": requestId },
    });
    vi.spyOn(response, "text").mockRejectedValue(new DOMException("Aborted", "AbortError"));
    vi.mocked(fetch).mockResolvedValue(response);

    const error = await getHealth().catch((value: unknown) => value);

    expect(error).toMatchObject({
      code: "request_aborted",
      kind: "aborted",
      requestId,
      status: 200,
      retryable: false,
    });
  });

  it("sends the frozen empty foundation-check body and idempotency key", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(
        { event_id: "evt_0123456789abcdef0123456789abcdef", delivery_status: "pending" },
        202,
      ),
    );

    const result = await createFoundationCheck("stable-key-1");
    const [, init] = vi.mocked(fetch).mock.calls[0] ?? [];
    const headers = new Headers(init?.headers);

    expect(result).toEqual({
      event_id: "evt_0123456789abcdef0123456789abcdef",
      delivery_status: "pending",
    });
    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/_internal/foundation-checks",
      expect.objectContaining({ method: "POST", body: "{}" }),
    );
    expect(headers.get("Idempotency-Key")).toBe("stable-key-1");
  });
});

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}
