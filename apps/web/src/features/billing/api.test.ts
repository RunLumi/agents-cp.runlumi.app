import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import fixture from "../../../../../docs/implementation/fixtures/p06-contracts-v1.json";

import {
  BillingContractError,
  decodeBillingPortalSession,
  decodeEntitlementPolicySection,
  decodeEntitlementProjection,
  decodeLicenseSnapshotBlock,
  decodePlanChangePreview,
  decodePlanChangeResult,
  decodeProviderEntitlementProjection,
  decodeSubscription,
  defaultBillingApi,
  findProviderIdentifier,
  isEntitlementKey,
  isProviderIdentifier,
  isSafePortalUrl,
  PROVIDER_IDENTIFIER_FIELDS,
} from "./api";
import { ApiClientError } from "@/lib/errors";

const requestId = "req_0123456789abcdef0123456789abcdef";

describe("P06 billing decoders against the frozen fixture", () => {
  it("decodes the signed license block field-for-field", () => {
    const block = decodeLicenseSnapshotBlock(fixture.entitlements);

    expect(block).toEqual({
      subscription_id: "sub_0123456789abcdef0123456789abcdef",
      billing_account_id: "bac_0123456789abcdef0123456789abcdef",
      org_id: "org_0123456789abcdef0123456789abcdef",
      plan_key: "team",
      status: "grace",
      policy_fresh_until: "2026-09-25T16:15:00.000Z",
      offline_valid_until: "2026-10-02T12:00:00.000Z",
      values: {
        "automations.max_active": 100,
        "webhooks.enabled": true,
        "exports.enabled": true,
      },
    });
  });

  it("decodes the provider entitlement projection field-for-field", () => {
    const projection = decodeProviderEntitlementProjection(fixture.provider_entitlements);

    expect(projection).toEqual({
      projection_id: "pep_0123456789abcdef0123456789abcdef",
      org_id: "org_0123456789abcdef0123456789abcdef",
      provider: "upstream_ai",
      status: "available",
      observed_at: "2026-09-25T15:59:00.000Z",
      capability_class: "provider_managed_inference",
    });
  });

  it("decodes the Subscription projection from the gate", () => {
    const subscription = decodeSubscription({
      subscription_id: "sub_0123456789abcdef0123456789abcdef",
      org_id: "org_0123456789abcdef0123456789abcdef",
      plan_key: "team",
      status: "grace",
      grace_expires_at: "2026-10-02T12:00:00.000Z",
      current_period_ends_at: "2026-10-01T12:00:00.000Z",
      version: 4,
    });

    expect(subscription.status).toBe("grace");
    expect(subscription.grace_expires_at).toBe("2026-10-02T12:00:00.000Z");
    expect(subscription.current_period_starts_at).toBeNull();
    expect(subscription.version).toBe(4);
  });

  it("keeps the P03 entitlements policy section grace windows separate", () => {
    const policy = decodeEntitlementPolicySection({
      schema_version: 1,
      policy_fresh_seconds: 900,
      local_offline_grace_seconds: 604800,
      cloud_control_plane_grace_seconds: 86400,
      platform_paid_inference_grace_seconds: 0,
    });

    expect(policy.local_offline_grace_seconds).toBe(604800);
    expect(policy.cloud_control_plane_grace_seconds).toBe(86400);
    expect(policy.platform_paid_inference_grace_seconds).toBe(0);
  });

  it("reads a flat value map and marks unattributed values as unproven", () => {
    const projection = decodeEntitlementProjection({
      org_id: "org_0123456789abcdef0123456789abcdef",
      plan_key: "team",
      status: "grace",
      policy_fresh_until: "2026-09-25T16:15:00.000Z",
      offline_valid_until: "2026-10-02T12:00:00.000Z",
      values: { "automations.max_active": 100, "webhooks.enabled": true },
    });

    expect(projection.entitlements.map((entry) => entry.key)).toEqual([
      "automations.max_active",
      "webhooks.enabled",
    ]);
    expect(projection.entitlements.every((entry) => entry.source === "unknown")).toBe(true);
  });

  it("reads an itemized projection with per-key precedence attribution", () => {
    const projection = decodeEntitlementProjection({
      org_id: "org_0123456789abcdef0123456789abcdef",
      plan_key: "team",
      status: "grace",
      entitlements: [
        { key: "org.max_members", value: 25, source: "plan" },
        { key: "scim.enabled", value: true, source: "platform_default" },
        {
          key: "automations.max_active",
          value: 100,
          source: "internal_override",
          expires_at: "2026-10-10T00:00:00.000Z",
          reason: "escalation_window",
          scope: "org",
        },
        { key: "unknown.future_key", value: "x", source: "plan" },
      ],
    });

    const byKey = new Map(projection.entitlements.map((entry) => [entry.key, entry]));
    expect(byKey.get("org.max_members")?.source).toBe("plan");
    expect(byKey.get("scim.enabled")?.source).toBe("platform_default");
    expect(byKey.get("automations.max_active")).toMatchObject({
      source: "internal_override",
      expires_at: "2026-10-10T00:00:00.000Z",
      reason: "escalation_window",
      scope: "org",
    });
  });

  it("fails closed on an unknown entitlement source rather than inventing one", () => {
    const projection = decodeEntitlementProjection({
      org_id: "org_0123456789abcdef0123456789abcdef",
      status: "active",
      entitlements: [{ key: "webhooks.enabled", value: true, source: "provider_plan" }],
    });

    expect(projection.entitlements[0]?.source).toBe("unknown");
  });

  it("fails closed on an out-of-contract subscription status", () => {
    expect(() =>
      decodeSubscription({
        subscription_id: "sub_0123456789abcdef0123456789abcdef",
        org_id: "org_0123456789abcdef0123456789abcdef",
        plan_key: "team",
        status: "delinquent",
        version: 1,
      }),
    ).toThrow(BillingContractError);
  });

  it("fails closed on a non-dotted entitlement key", () => {
    expect(() =>
      decodeEntitlementProjection({
        org_id: "org_0123456789abcdef0123456789abcdef",
        status: "active",
        values: { "Automations Max": 3 },
      }),
    ).toThrow(BillingContractError);
    expect(isEntitlementKey("automations.max_active")).toBe(true);
    expect(isEntitlementKey("prod_123")).toBe(true);
    expect(isEntitlementKey("Automations")).toBe(false);
  });
});

describe("payment-provider identifier containment", () => {
  it("drops provider commercial identifiers from a subscription payload", () => {
    const subscription = decodeSubscription({
      subscription_id: "sub_0123456789abcdef0123456789abcdef",
      org_id: "org_0123456789abcdef0123456789abcdef",
      plan_key: "team",
      status: "active",
      version: 1,
      product_id: "prod_Q1TeamAnnual",
      price_id: "price_1NxyzABCDEF",
      customer_id: "cus_R1zzzQQQQ",
      provider_reference: "acct_9f8e7d6c5b4a",
    });

    expect(findProviderIdentifier(subscription)).toBeNull();
    expect(JSON.stringify(subscription)).not.toContain("prod_");
    expect(JSON.stringify(subscription)).not.toContain("price_");
    expect(JSON.stringify(subscription)).not.toContain("cus_");
    expect(JSON.stringify(subscription)).not.toContain("acct_");
  });

  it("drops provider commercial identifiers from a provider projection", () => {
    const projection = decodeProviderEntitlementProjection({
      ...fixture.provider_entitlements,
      product_id: "prod_Q1TeamAnnual",
      customer_reference: "cus_R1zzzQQQQ",
      raw_provider_payload: { seats: 40 },
    });

    expect(findProviderIdentifier(projection)).toBeNull();
    expect(projection.provider).toBe("upstream_ai");
  });

  it("keeps an over-limit projection free of provider identifiers", () => {
    const result = decodePlanChangeResult({
      accepted: true,
      subscription: {
        subscription_id: "sub_0123456789abcdef0123456789abcdef",
        org_id: "org_0123456789abcdef0123456789abcdef",
        plan_key: "starter",
        status: "active",
        version: 5,
        price_id: "price_1NxyzABCDEF",
      },
      over_limit: [
        {
          entitlement_key: "automations.max_active",
          limit: 3,
          current: 7,
          product_id: "prod_Q1TeamAnnual",
        },
      ],
    });

    expect(findProviderIdentifier(result)).toBeNull();
    expect(result.over_limit[0]).toEqual({
      entitlement_key: "automations.max_active",
      limit: 3,
      current: 7,
      over_by: 4,
      seat_based: false,
      remediation: [],
    });
  });

  it("recognizes provider commercial identifier shapes", () => {
    expect(isProviderIdentifier("prod_Q1TeamAnnual")).toBe(true);
    expect(isProviderIdentifier("price_1NxyzABCDEF")).toBe(true);
    expect(isProviderIdentifier("cus_R1zzzQQQQ")).toBe(true);
    expect(isProviderIdentifier("automations.max_active")).toBe(false);
    expect(isProviderIdentifier("sub_0123456789abcdef0123456789abcdef")).toBe(false);
    expect(isProviderIdentifier("upstream_ai")).toBe(false);
  });

  it("names every field that must never reach component state", () => {
    for (const field of ["product_id", "price_id", "customer_id", "provider_reference"]) {
      expect(PROVIDER_IDENTIFIER_FIELDS).toContain(field);
    }
  });
});

describe("billing portal session safety", () => {
  it("refuses a non-HTTPS or credentialed portal URL", () => {
    expect(isSafePortalUrl("https://billing.example.test/session/abc")).toBe(true);
    expect(isSafePortalUrl("http://billing.example.test/session/abc")).toBe(false);
    expect(isSafePortalUrl("https://user:pass@billing.example.test/s")).toBe(false);
    expect(isSafePortalUrl("javascript:alert(1)")).toBe(false);
  });

  it("reports an unavailable reason instead of offering a rejected URL", () => {
    const session = decodeBillingPortalSession({
      portal_url: "http://billing.example.test/session/abc",
      reason: "provider_portal_unavailable",
    });

    expect(session.portal_url).toBeNull();
    expect(session.reason).toBe("provider_portal_unavailable");
  });
});

describe("downgrade preview decoding", () => {
  it("can never report that a change deletes data", () => {
    const preview = decodePlanChangePreview({
      direction: "downgrade",
      current_plan_key: "team",
      target_plan_key: "starter",
      over_limit: [
        {
          entitlement_key: "automations.max_active",
          limit: 3,
          current: 7,
          seat_based: false,
        },
      ],
      deletes_data: true,
    });

    expect(preview.deletes_data).toBe(false);
    expect(preview.blocks_new_work).toBe(true);
    expect(preview.over_limit[0]?.over_by).toBe(4);
  });

  it("treats a missing direction as unknown rather than assuming an upgrade", () => {
    const preview = decodePlanChangePreview({
      target_plan_key: "starter",
    });

    expect(preview.direction).toBe("unknown");
  });
});

describe("billing client transport", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("reads the frozen subscription route and decodes the payload", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({
        subscription: {
          subscription_id: "sub_0123456789abcdef0123456789abcdef",
          org_id: "org_0123456789abcdef0123456789abcdef",
          plan_key: "team",
          status: "active",
          current_period_ends_at: "2026-10-01T12:00:00.000Z",
          version: 4,
        },
      }),
    );

    const subscription = await defaultBillingApi().getSubscription(
      "org_0123456789abcdef0123456789abcdef",
    );

    expect(subscription.plan_key).toBe("team");
    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/orgs/org_0123456789abcdef0123456789abcdef/billing/subscription",
      expect.objectContaining({ method: "GET", credentials: "include" }),
    );
  });

  it("keeps the provider projection on its own read-only route", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(fixture.provider_entitlements));

    await defaultBillingApi().getProviderEntitlement("org_0123456789abcdef0123456789abcdef");

    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/orgs/org_0123456789abcdef0123456789abcdef/entitlements/provider",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("sends an idempotency key and the subscription version on a plan change", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({
        plan_change: {
          accepted: true,
          subscription: {
            subscription_id: "sub_0123456789abcdef0123456789abcdef",
            org_id: "org_0123456789abcdef0123456789abcdef",
            plan_key: "enterprise",
            status: "active",
            version: 5,
          },
          over_limit: [],
        },
      }),
    );

    const result = await defaultBillingApi().requestPlanChange?.(
      "org_0123456789abcdef0123456789abcdef",
      { plan_key: "enterprise", version: 4 },
      "idem-1",
    );

    expect(result?.accepted).toBe(true);
    const [, init] = vi.mocked(fetch).mock.calls[0] ?? [];
    const headers = (init?.headers ?? new Headers()) as Headers;
    expect(headers.get("Idempotency-Key")).toBe("idem-1");
    const sentBody: unknown = JSON.parse(init?.body as string);
    expect(sentBody).toEqual({ plan_key: "enterprise", version: 4 });
  });

  it("does not guess a downgrade preview route", () => {
    expect(defaultBillingApi().previewPlanChange).toBeUndefined();
  });

  it("surfaces a stable API code without exposing the server message", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(
        {
          error: {
            code: "entitlement_limit_exceeded",
            message: "provider price_1NxyzABCDEF rejected the seat reduction",
            request_id: requestId,
            details: {},
          },
        },
        409,
        { "X-Request-ID": requestId },
      ),
    );

    const error = await defaultBillingApi()
      .getEntitlements("org_0123456789abcdef0123456789abcdef")
      .catch((value: unknown) => value);

    expect(error).toBeInstanceOf(ApiClientError);
    expect(error).toMatchObject({ code: "entitlement_limit_exceeded", status: 409 });
    expect((error as ApiClientError).message).not.toContain("price_");
  });

  it("rejects a 2xx response that does not match the contract", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ org_id: "org_1", plan_key: 42 }));

    const error = await defaultBillingApi()
      .getSubscription("org_0123456789abcdef0123456789abcdef")
      .catch((value: unknown) => value);

    expect(error).toBeInstanceOf(ApiClientError);
    expect(error).toMatchObject({ code: "invalid_response", kind: "invalid_response" });
  });
});

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}
