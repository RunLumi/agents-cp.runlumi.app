import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import fixture from "../../../../../docs/implementation/fixtures/p06-contracts-v1.json";

import {
  decodeEntitlementProjection,
  decodeProviderEntitlementProjection,
  decodeSubscription,
  findProviderIdentifier,
  isProviderIdentifier,
  type BillingApi,
  type BillingSnapshot,
} from "./api";
import { BillingPanel } from "./billing-panel";
import { DOWNGRADE_HONESTY_STATEMENT } from "./downgrade";

const ORG_ID = fixture.entitlements.org_id;

const subscription = decodeSubscription({
  subscription_id: fixture.entitlements.subscription_id,
  org_id: ORG_ID,
  plan_key: "team",
  status: "grace",
  grace_expires_at: "2026-09-26T16:00:00.000Z",
  current_period_ends_at: "2026-10-01T12:00:00.000Z",
  version: 4,
});

const entitlements = decodeEntitlementProjection({
  org_id: ORG_ID,
  plan_key: "team",
  status: "grace",
  policy_fresh_until: "2026-09-25T16:15:00.000Z",
  offline_valid_until: "2026-10-02T12:00:00.000Z",
  entitlements: [
    { key: "org.max_members", value: 25, source: "plan" },
    { key: "automations.max_active", value: 100, source: "plan" },
    { key: "webhooks.enabled", value: true, source: "platform_default" },
    { key: "scim.enabled", value: true, source: "subscription" },
    { key: "sso.enabled", value: true, source: "internal_override" },
    { key: "exports.enabled", value: true },
  ],
});

const provider = decodeProviderEntitlementProjection(fixture.provider_entitlements);

const snapshot: BillingSnapshot = {
  orgId: ORG_ID,
  subscription,
  entitlements,
  provider,
  policy: {
    schema_version: 1,
    policy_fresh_seconds: 900,
    local_offline_grace_seconds: 604800,
    cloud_control_plane_grace_seconds: 86400,
    platform_paid_inference_grace_seconds: 0,
  },
};

const api: BillingApi = {
  getSubscription: async () => subscription,
  getEntitlements: async () => entitlements,
  getProviderEntitlement: async () => provider,
};

function render(): string {
  return renderToStaticMarkup(
    createElement(BillingPanel, { orgId: ORG_ID, api, initialData: snapshot, canManage: true }),
  );
}

/** Rendered copy with HTML entity escaping undone, so assertions read as copy. */
function renderText(): string {
  return render()
    .replaceAll("&#x27;", "'")
    .replaceAll("&amp;", "&")
    .replaceAll("&quot;", '"')
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">");
}

describe("billing panel rendered output", () => {
  it("renders the four decision inputs as four distinct labelled sections", () => {
    const html = render();

    expect(html).toContain("Four separate decision inputs");
    for (const term of [
      "Authorization permission",
      "Lumi product entitlement",
      "Usage budget",
      "Upstream provider account status",
    ]) {
      expect(html).toContain(term);
    }
    expect(html).toContain("It does not grant or revoke a Lumi entitlement");
  });

  it("makes the grace window unmistakable and says what stops when it ends", () => {
    const text = renderText();

    expect(text).toContain("Billing grace is active and time-limited");
    expect(text).toContain("Grace does not renew");
    expect(text).toContain("CLOUD CONTROL-PLANE GRACE ENDS");
    expect(text).toContain("SIGNED OFFLINE VALIDITY ENDS");
    expect(text).toContain("Stops first:");
    expect(text).toContain("cloud control-plane managed work, when the shorter cloud window ends");
    expect(text).toContain("Stops last:");
    expect(text).toContain("local-only work, when the signed offline validity instant passes");
    expect(text).toContain("No grace at all:");
  });

  it("renders the two expiries as two distinct clocks", () => {
    const html = render();

    expect(html).toContain("Two separate license clocks");
    expect(html).toContain("Signed offline validity");
    expect(html).toContain("Policy freshness");
    expect(html).toContain("Grace window");
    expect(html).toContain("This is a different clock from the one above");
  });

  it("shows each capability class with its own decision and reason", () => {
    const html = render();

    for (const label of [
      "Local-only work",
      "Cloud control-plane managed work",
      "Platform-paid inference",
    ]) {
      expect(html).toContain(label);
    }
    expect(html).toContain("license_grace_active");
    expect(html).toContain("paid_inference_no_billing_grace");
    // Each deadline names the clock that bounds it rather than a bare date.
    expect(html).toContain("Basis: signed offline validity");
    expect(html).toContain("Basis: policy freshness");
  });

  it("renders every entitlement key with its precedence-chain source", () => {
    const html = render();

    expect(html).toContain("PRECEDENCE CHAIN, WEAKEST TO STRONGEST");
    expect(html).toContain("P1 · Platform default");
    expect(html).toContain("P2 · Plan");
    expect(html).toContain("P3 · Subscription grant");
    expect(html).toContain("P4 · Internal override");
    expect(html).toContain("org.max_members");
    expect(html).toContain("automations.max_active");
    // One value arrived without attribution, so it must be called out.
    expect(html).toContain("Source not itemized");
  });

  it("separates the provider projection and states what it cannot change", () => {
    const text = renderText();

    expect(text).toContain("UPSTREAM PROVIDER ACCOUNT — NOT A LUMI ENTITLEMENT");
    expect(text).toContain("never grants or revokes one");
    expect(text).toContain(
      "the provider's product, price, or customer reference. Those stay inside the adapter",
    );
    expect(text).toContain(
      "your Lumi plan, your Lumi subscription state, your effective entitlement values, your authorization permissions, or your usage budget",
    );
  });

  it("states the downgrade honesty requirement verbatim on the page", () => {
    const text = renderText();

    expect(text).toContain(DOWNGRADE_HONESTY_STATEMENT);
    expect(text).toContain("It does not delete anything that already exists");
    expect(text).toContain("remain readable");
  });

  it("refuses to submit a downgrade that cannot be previewed", () => {
    const html = render();

    expect(html).toContain("A downgrade cannot be submitted from this browser");
    expect(html).toContain("previewed before it is submitted");
    expect(html).toContain("Make the change in the");
  });

  it("reports how many entitlement keys and counted limits the projection carries", () => {
    const text = renderText();

    expect(text).toContain("This projection reports 6 entitlement keys, of which 2 are counted");
  });

  it("offers no entitlement override control", () => {
    const html = render();

    expect(html).toContain("There is no override control on this surface");
    expect(html).not.toMatch(/type="file"/);
    expect(html).not.toContain("Revoke override");
    expect(html).not.toContain("Create override");
  });

  it("gives cancellation a confirmation with its consequence copy", () => {
    const html = render();

    expect(html).toContain("Cancel subscription…");
    expect(html).toContain("does not silently reactivate");
  });

  it("never renders a payment-provider product, price, or customer identifier", () => {
    const html = render();

    expect(findProviderIdentifier(html)).toBeNull();
    for (const forbidden of ["prod_", "price_", "cus_", "acct_"]) {
      expect(html).not.toContain(forbidden);
    }
  });

  it("ignores a snapshot that belongs to another organization", () => {
    const html = renderToStaticMarkup(
      createElement(BillingPanel, {
        orgId: ORG_ID,
        api: {
          getSubscription: async () => {
            throw new Error("should not be reached in this assertion");
          },
          getEntitlements: async () => {
            throw new Error("should not be reached in this assertion");
          },
          getProviderEntitlement: async () => {
            throw new Error("should not be reached in this assertion");
          },
        },
        initialData: { orgId: "org_ffffffffffffffffffffffffffffffff", ...snapshot },
        stale: true,
      }),
    );

    expect(html).toContain("Stale snapshot");
    expect(html).not.toContain("Grace window</dt>");
  });

  it("keeps an Lumi opaque ID out of the provider-identifier classifier", () => {
    expect(isProviderIdentifier(subscription.subscription_id)).toBe(false);
    expect(isProviderIdentifier(provider.projection_id)).toBe(false);
    expect(isProviderIdentifier(ORG_ID)).toBe(false);
  });
});
