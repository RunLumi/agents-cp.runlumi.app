/**
 * P07 machine-identity API contract.
 *
 * The assertions here are the ones whose failure would be silent: a wrong path
 * reads as an empty list, a missing idempotency key reads as an intermittent
 * duplicate, and a decoder that accepted a response with no `secret` would tell
 * an operator a key exists that they can never use.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiClientError } from "@/lib/errors";

import {
  createApiKey,
  createServiceAccount,
  getApiKey,
  listApiKeys,
  listServiceAccounts,
  presentIdentityError,
  resumeServiceAccount,
  revokeApiKey,
  rotateApiKey,
  suspendServiceAccount,
  updateServiceAccount,
  API_KEY_PREFIX_PATTERN,
  MAX_ACTIVE_KEYS_PER_ACCOUNT,
  MAX_ACTIVE_SERVICE_ACCOUNTS_PER_ORG,
} from "./api";

/**
 * Synthetic show-once key material standing in for the plaintext the server
 * returns exactly once. These are not credentials and leave the test process only
 * as an in-memory object literal.
 */
const PLAINTEXT_ON_CREATE = "lumik_0123456789ab_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v";
const PLAINTEXT_ON_ROTATE = "lumik_0123456789ac_Z9y8X7w6V5u4T3s2R1q0Po9n8Ml7Kj6Ih5Gf4Ed3Cb2";

const requestId = "req_0123456789abcdef0123456789abcdef";
const orgId = "org_0123456789abcdef0123456789abcdef";
const accountId = "svc_0123456789abcdef0123456789abcdef";
const keyId = "key_0123456789abcdef0123456789abcdef";

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "X-Request-ID": requestId },
  });
}

function accountBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: accountId,
    organization_id: orgId,
    name: "Release pipeline",
    description: "Publishes releases on merge to main",
    capabilities: ["runs.start", "projects.read"],
    status: "active",
    expires_at: null,
    suspended_at: null,
    suspend_reason: null,
    created_by_principal_id: "usr_0123456789abcdef0123456789abcdef",
    version: 1,
    created_at: "2026-09-25T12:00:00.000Z",
    updated_at: "2026-09-25T12:30:00.000Z",
    ...overrides,
  };
}

function keyBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: keyId,
    service_account_id: accountId,
    organization_id: orgId,
    name: "Release publisher",
    key_prefix: "lumik_0123456789ab",
    fingerprint: "sha256:0123456789abcdef",
    capabilities: ["runs.start"],
    project_ids: [],
    model_aliases: [],
    network_allowlist: [],
    status: "active",
    rotated_from_key_id: null,
    rotated_to_key_id: null,
    last_used_at: null,
    last_used_source: null,
    expires_at: null,
    revoked_at: null,
    revoke_reason: null,
    version: 1,
    created_at: "2026-09-25T12:00:00.000Z",
    updated_at: "2026-09-25T12:00:00.000Z",
    ...overrides,
  };
}

function keyBodyWithSecret(
  secret: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    ...keyBody(overrides),
    secret,
    secret_notice: "This value is shown once and cannot be retrieved again. Store it now.",
  };
}

function errorResponse(reason: string, status = 409, code = "conflict"): Response {
  return new Response(
    JSON.stringify({
      error: {
        code,
        message: "The request conflicts with current state.",
        request_id: requestId,
        details: { reason },
      },
    }),
    { status, headers: { "Content-Type": "application/json", "X-Request-ID": requestId } },
  );
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

describe("P07 machine identity API contract", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
    vi.stubGlobal("document", { cookie: "lumi_csrf=csrf-token" });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("lists service accounts on the org path and derives has_more from the cursor", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ items: [accountBody()], page: { limit: 25, next_cursor: "cursor-1" } }),
    );
    const page = await listServiceAccounts(orgId, { limit: 25 });
    expect(page.items[0]?.id).toBe(accountId);
    expect(page.limit).toBe(25);
    // The P07 route returns no `has_more`; another page exists exactly when the
    // server handed back a cursor.
    expect(page.has_more).toBe(true);

    const [path, init] = lastCall();
    expect(path).toBe(`/api/v1/orgs/${orgId}/service-accounts?limit=25`);
    expect(init.method).toBe("GET");
  });

  it("reports the end of the list when the cursor is null", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ items: [], page: { limit: 25, next_cursor: null } }),
    );
    const page = await listServiceAccounts(orgId, { limit: 25 });
    expect(page.has_more).toBe(false);
    expect(page.next_cursor).toBeNull();
  });

  it("refuses a page whose shape does not match the frozen projection", async () => {
    vi.mocked(fetch).mockResolvedValue(response({ items: [accountBody()], page: { limit: 25 } }));
    await expect(listServiceAccounts(orgId, { limit: 25 })).rejects.toMatchObject({
      code: "invalid_response",
    });
  });

  it("creates a service account with the CSRF and idempotency boundaries", async () => {
    vi.mocked(fetch).mockResolvedValue(response({ service_account: accountBody() }, 201));
    const created = await createServiceAccount(
      orgId,
      { name: "Release pipeline", capabilities: ["runs.start"] },
      "idem-create-account",
    );
    expect(created.id).toBe(accountId);

    const [path, init] = lastCall();
    expect(path).toBe(`/api/v1/orgs/${orgId}/service-accounts`);
    expect(init.method).toBe("POST");
    expect(new Headers(init.headers).get("Idempotency-Key")).toBe("idem-create-account");
    expect(new Headers(init.headers).get("X-CSRF-Token")).toBe("csrf-token");
    expect(requestBody(init)).toEqual({ name: "Release pipeline", capabilities: ["runs.start"] });
  });

  it("carries the current version on PATCH so a stale write is refused server-side", async () => {
    vi.mocked(fetch).mockResolvedValue(response({ service_account: accountBody({ version: 2 }) }));
    const updated = await updateServiceAccount(
      orgId,
      accountId,
      { version: 1, capabilities: ["runs.start", "runs.cancel"] },
      "idem-patch",
    );
    expect(updated.version).toBe(2);

    const [path, init] = lastCall();
    expect(path).toBe(`/api/v1/orgs/${orgId}/service-accounts/${accountId}`);
    expect(init.method).toBe("PATCH");
    expect(requestBody(init)).toEqual({ version: 1, capabilities: ["runs.start", "runs.cancel"] });
  });

  it("requires a reason on suspend and sends no body at all on resume", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({
        service_account: accountBody({ status: "suspended", suspend_reason: "offboarded" }),
      }),
    );
    const suspended = await suspendServiceAccount(
      orgId,
      accountId,
      { version: 1, reason: "offboarded" },
      "idem-suspend",
    );
    expect(suspended.status).toBe("suspended");
    expect(requestBody(lastCall()[1])).toEqual({ version: 1, reason: "offboarded" });
    expect(lastCall()[0]).toBe(`/api/v1/orgs/${orgId}/service-accounts/${accountId}/suspend`);

    vi.mocked(fetch).mockResolvedValue(
      response({ service_account: accountBody({ status: "active", version: 3 }) }),
    );
    const resumed = await resumeServiceAccount(orgId, accountId, { version: 2 }, "idem-resume");
    expect(resumed.status).toBe("active");
    expect(requestBody(lastCall()[1])).toEqual({ version: 2 });
    expect(lastCall()[0]).toBe(`/api/v1/orgs/${orgId}/service-accounts/${accountId}/resume`);
  });

  it("returns the create secret exactly once, and the wire key format is the frozen one", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ api_key: keyBodyWithSecret(PLAINTEXT_ON_CREATE) }, 201),
    );
    const created = await createApiKey(
      orgId,
      { service_account_id: accountId, name: "Release publisher", capabilities: ["runs.start"] },
      "idem-create-key",
    );
    expect(created.secret).toBe(PLAINTEXT_ON_CREATE);
    expect(created.secret_notice).toContain("shown once");
    expect(API_KEY_PREFIX_PATTERN.test(created.secret)).toBe(true);
    expect(lastCall()[0]).toBe(`/api/v1/orgs/${orgId}/api-keys`);
  });

  it("refuses a create response with no secret rather than pretending it succeeded", async () => {
    vi.mocked(fetch).mockResolvedValue(response({ api_key: keyBody() }, 201));
    await expect(
      createApiKey(
        orgId,
        { service_account_id: accountId, name: "Release publisher", capabilities: ["runs.start"] },
        "idem-create-key",
      ),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("refuses a secret that does not match the frozen wire format", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ api_key: keyBodyWithSecret("lumik_not-a-valid-secret") }, 201),
    );
    await expect(
      createApiKey(
        orgId,
        { service_account_id: accountId, name: "Release publisher", capabilities: ["runs.start"] },
        "idem-create-key",
      ),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  /**
   * The negative case for the one-time secret.
   *
   * The read routes have no secret to return, and this module's `ApiKey` type has
   * no field one could occupy. If a future revision put a secret on the list or
   * get projection, the decoder here would still refuse the extra field silently
   * — so the assertion is that the read path returns the metadata shape and
   * never a secret, which is what makes "cannot be retrieved again" true from the
   * browser's side rather than merely intended.
   */
  it("has no path that re-reads a secret: the list and get routes return metadata only", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ items: [keyBody()], page: { limit: 25, next_cursor: null } }),
    );
    const page = await listApiKeys(orgId, { limit: 25 });
    expect(page.items[0]?.id).toBe(keyId);
    expect(Object.hasOwn(page.items[0] as object, "secret")).toBe(false);
    expect(Object.hasOwn(page.items[0] as object, "secret_notice")).toBe(false);
    expect(lastCall()[0]).toBe(`/api/v1/orgs/${orgId}/api-keys?limit=25`);

    vi.mocked(fetch).mockResolvedValue(response({ api_key: keyBody() }));
    const read = await getApiKey(keyId);
    expect(read.key_prefix).toBe("lumik_0123456789ab");
    expect(Object.hasOwn(read as object, "secret")).toBe(false);
    // The `{api_key_id}` route resolves the organization from the key row, so it
    // takes no org in the path at all.
    expect(lastCall()[0]).toBe(`/api/v1/api-keys/${keyId}`);
  });

  it("refuses a metadata response to the get route that smuggles a secret back in", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ api_key: { ...keyBody(), secret: PLAINTEXT_ON_CREATE } }),
    );
    const read = await getApiKey(keyId);
    // The decoder copies the allowlisted fields, so an extra wire key cannot
    // reach component state even if a server change adds one.
    expect(Object.hasOwn(read as object, "secret")).toBe(false);
  });

  it("rotates on the key-scoped path and returns the replacement secret once", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ api_key: keyBodyWithSecret(PLAINTEXT_ON_ROTATE, { rotated_from_key_id: keyId }) }),
    );
    const replacement = await rotateApiKey(keyId, { reason: "scheduled rotation" }, "idem-rotate");
    expect(replacement.secret).toBe(PLAINTEXT_ON_ROTATE);
    expect(replacement.rotated_from_key_id).toBe(keyId);

    const [path, init] = lastCall();
    expect(path).toBe(`/api/v1/api-keys/${keyId}/rotate`);
    expect(requestBody(init)).toEqual({ reason: "scheduled rotation" });
    expect(new Headers(init.headers).get("Idempotency-Key")).toBe("idem-rotate");
  });

  it("revokes with the current version and returns the terminal projection", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ api_key: keyBody({ status: "revoked", revoke_reason: "leaked" }) }),
    );
    const revoked = await revokeApiKey(keyId, { version: 1, reason: "leaked" }, "idem-revoke");
    expect(revoked.status).toBe("revoked");
    expect(revokeReason(revoked.revoke_reason)).toBe("leaked");

    const [path, init] = lastCall();
    expect(path).toBe(`/api/v1/api-keys/${keyId}/revoke`);
    expect(requestBody(init)).toEqual({ version: 1, reason: "leaked" });
  });

  it("publishes the frozen credential bounds so the UI can state them", () => {
    expect(MAX_ACTIVE_SERVICE_ACCOUNTS_PER_ORG).toBe(50);
    expect(MAX_ACTIVE_KEYS_PER_ACCOUNT).toBe(5);
  });

  /**
   * The whole path, end to end: wire envelope → `ApiClientError` with a
   * `details.reason` → the specific message an operator reads.
   *
   * The other presentation tests build the error directly, and would still pass if
   * the transport stopped populating `details` — so this one is what actually
   * proves the gate's `reason` code reaches the surface.
   */
  it("carries a stable reason from the wire envelope into the presentation", async () => {
    vi.mocked(fetch).mockResolvedValue(errorResponse("key_limit_reached", 409, "conflict"));
    const thrown = await listApiKeys(orgId).catch((error: unknown) => error);
    expect(thrown).toBeInstanceOf(ApiClientError);
    const presentation = presentIdentityError(thrown);
    expect(presentation.code).toBe("key_limit_reached");
    expect(presentation.message).toContain("active service-account or per-account key limit");
    expect(presentation.requestId).toBe(requestId);
  });
});

function revokeReason(value: string | null): string | null {
  return value;
}

describe("P07 machine-identity error presentation", () => {
  /**
   * Every stable reason code the gate lists for machine identity, mapped to a
   * message an operator can act on. A generic fallback would be technically
   * correct and operationally useless: "try again" is the wrong remediation for a
   * human-only capability or a terminal key.
   */
  const CASES: ReadonlyArray<readonly [string, string]> = [
    ["capability_human_only", "can never hold this capability"],
    ["capability_unknown", "not a permission this product defines"],
    ["scope_capability_unknown", "may only hold capabilities its service account"],
    ["key_limit_reached", "active service-account or per-account key limit"],
    ["key_terminal", "cannot be rotated again"],
    ["machine_key_suspended", "machine_key_suspended even before it expires"],
    ["machine_key_expired", "past its expiry"],
    ["machine_key_revoked", "refused permanently"],
    ["scope_denied", "does not hold the capability"],
    ["scope_project_mismatch", "cannot reach a project it was not scoped to"],
    ["scope_network_unavailable", "denied rather than allowed"],
    ["human_only_action", "permanently unavailable to a machine credential"],
    ["version_conflict", "refused rather than overwriting"],
  ];

  for (const [reason, fragment] of CASES) {
    it(`maps ${reason} to specific, actionable copy`, () => {
      const error = new ApiClientError({
        code: "conflict",
        kind: "api",
        status: 409,
        requestId,
        details: { reason },
        retryable: false,
      });
      const presentation = presentIdentityError(error);
      expect(presentation.code).toBe(reason);
      expect(presentation.message).toContain(fragment);
      expect(presentation.requestId).toBe(requestId);
    });
  }

  it("falls back to the shared presentation for a code it does not know", () => {
    const error = new ApiClientError({
      code: "some_future_code",
      kind: "api",
      status: 500,
      requestId,
      details: {},
      retryable: true,
    });
    const presentation = presentIdentityError(error);
    expect(presentation.tone).toBe("warning");
    expect(presentation.code).toBe("some_future_code");
  });

  it("reads the envelope code when the reason detail is absent", () => {
    // A refusal raised before a domain decision (a 403) carries its code in the
    // envelope rather than in `details.reason`.
    const error = new ApiClientError({
      code: "permission_denied",
      kind: "api",
      status: 403,
      requestId,
      details: {},
      retryable: false,
    });
    expect(presentIdentityError(error).code).toBe("permission_denied");
    expect(presentIdentityError(error).message).toContain("administrator");
  });
});
