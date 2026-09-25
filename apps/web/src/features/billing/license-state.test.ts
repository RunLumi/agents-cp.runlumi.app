import { describe, expect, it } from "vitest";

import fixture from "../../../../../docs/implementation/fixtures/p06-contracts-v1.json";

import type { LicenseState, ProviderProjectionStatus, SubscriptionStatus } from "./api";
import {
  earliest,
  FROZEN_CAPABILITY_MATRIX,
  projectLicense,
  readLicenseClocks,
  type LicenseProjection,
} from "./license-state";

const matrix = fixture.negative_fixtures.license_state_matrix;
const NOW = new Date("2026-09-25T16:00:00.000Z");
const LOCAL_UNTIL = "2026-10-02T12:00:00.000Z";
const POLICY_FRESH_UNTIL = "2026-09-25T16:15:00.000Z";
const GRACE_UNTIL = "2026-09-26T16:00:00.000Z";

function project(
  subscriptionStatus: SubscriptionStatus,
  providerStatus: ProviderProjectionStatus,
  overrides: {
    offlineValidUntil?: string | null;
    policyFreshUntil?: string | null;
    graceExpiresAt?: string | null;
  } = {},
): LicenseProjection {
  return projectLicense({
    subscriptionStatus,
    providerStatus,
    offlineValidUntil:
      overrides.offlineValidUntil === undefined ? LOCAL_UNTIL : overrides.offlineValidUntil,
    policyFreshUntil:
      overrides.policyFreshUntil === undefined ? POLICY_FRESH_UNTIL : overrides.policyFreshUntil,
    graceExpiresAt: overrides.graceExpiresAt === undefined ? null : overrides.graceExpiresAt,
    paidInferenceGraceSeconds: 0,
    now: NOW,
  });
}

function decision(
  license: LicenseProjection,
  capability: "local_only" | "cloud_control_plane" | "platform_paid_inference",
) {
  const found = license.decisions.find((item) => item.capability === capability);
  if (!found) throw new Error(`missing decision for ${capability}`);
  return found;
}

describe("license state against the frozen capability matrix", () => {
  it("allows all three capability classes on an active subscription with a healthy provider", () => {
    expect(matrix.active).toEqual({
      local: "allowed",
      cloud: "allowed",
      paid_inference: "allowed",
    });

    const license = project("active", "available");

    expect(license.state).toBe("active");
    expect(decision(license, "local_only").verdict).toBe("allowed");
    expect(decision(license, "cloud_control_plane").verdict).toBe("allowed_until");
    expect(decision(license, "platform_paid_inference").verdict).toBe("allowed");
  });

  it("keeps the two grace clocks apart instead of collapsing them", () => {
    expect(matrix.grace).toEqual({
      local: "until_offline_valid_until",
      cloud: "until_cloud_grace",
      paid_inference: "provider_dependent",
    });

    const license = project("grace", "available", { graceExpiresAt: GRACE_UNTIL });
    const local = decision(license, "local_only");
    const cloud = decision(license, "cloud_control_plane");

    expect(license.state).toBe("grace");
    expect(local.until).toBe(LOCAL_UNTIL);
    expect(local.untilBasis).toEqual(["offline_valid_until"]);
    expect(cloud.until).toBe(POLICY_FRESH_UNTIL);
    expect(cloud.untilBasis).toEqual(["policy_fresh_until", "grace_expires_at"]);
    expect(local.until).not.toBe(cloud.until);
  });

  it("gives platform-paid inference no additional billing grace", () => {
    const license = project("grace", "available", { graceExpiresAt: GRACE_UNTIL });
    const paid = decision(license, "platform_paid_inference");

    expect(license.paidInferenceGraceSeconds).toBe(0);
    expect(paid.verdict).toBe("allowed");
    expect(paid.reason).toBe("paid_inference_no_billing_grace");
    expect(paid.until).toBeNull();
  });

  it("denies platform-paid inference the moment the provider billing is uncertain", () => {
    expect(project("grace", "unavailable").decisions[2]?.verdict).toBe("denied");
    expect(project("grace", "unknown").decisions[2]?.verdict).toBe("denied");
    expect(project("grace", "degraded").decisions[2]?.degraded).toBe(true);
  });

  it("allows past-due local work only until the signed offline expiry", () => {
    expect(matrix.past_due).toEqual({
      local: "until_signed_offline_expiry",
      cloud: "denied",
      paid_inference: "denied",
    });

    const license = project("past_due", "available");

    expect(license.state).toBe("past_due");
    expect(decision(license, "local_only").verdict).toBe("allowed_until");
    expect(decision(license, "cloud_control_plane").verdict).toBe("denied");
    expect(decision(license, "platform_paid_inference").verdict).toBe("denied");
  });

  it("stops local work when the signed offline expiry has passed", () => {
    const license = project("past_due", "available", {
      offlineValidUntil: "2026-09-20T00:00:00.000Z",
    });

    expect(license.state).toBe("expired");
    expect(decision(license, "local_only").verdict).toBe("denied");
    expect(decision(license, "local_only").lapsed).toBe(true);
    expect(decision(license, "cloud_control_plane").verdict).toBe("denied");
  });

  it("permits only in-flight work for a suspended or cancelled subscription", () => {
    for (const state of ["suspended", "cancelled"] as const) {
      expect(matrix[state]).toEqual({
        local: "in_flight_only",
        cloud: "denied",
        paid_inference: "denied",
      });

      const license = project(state, "available");

      expect(license.state).toBe(state);
      expect(decision(license, "local_only").verdict).toBe("in_flight_only");
      expect(decision(license, "local_only").allowed).toBe(false);
      expect(decision(license, "cloud_control_plane").verdict).toBe("denied");
      expect(decision(license, "platform_paid_inference").verdict).toBe("denied");
    }
  });

  it("leaves local work unaffected when the provider is unavailable", () => {
    const license = project("active", "unavailable");

    expect(license.state).toBe("provider_unavailable");
    expect(decision(license, "local_only").verdict).toBe("allowed");
    expect(decision(license, "cloud_control_plane").verdict).toBe("allowed_until");
    expect(decision(license, "platform_paid_inference").verdict).toBe("denied");
    expect(decision(license, "platform_paid_inference").reason).toBe("provider_unavailable");
  });

  it("fails closed for an unobserved provider rather than assuming health", () => {
    const license = project("active", "unknown");

    expect(decision(license, "platform_paid_inference").verdict).toBe("denied");
    expect(decision(license, "platform_paid_inference").reason).toBe("provider_unknown");
    expect(decision(license, "platform_paid_inference").meaning).toContain(
      "says nothing about the provider's actual account",
    );
  });

  it("denies cloud work on a stale policy snapshot even with a good subscription", () => {
    const license = project("active", "available", {
      policyFreshUntil: "2026-09-25T15:00:00.000Z",
    });

    expect(license.state).toBe("active");
    expect(decision(license, "cloud_control_plane").verdict).toBe("denied");
    expect(decision(license, "cloud_control_plane").reason).toBe("policy_snapshot_stale");
  });

  it("denies cloud work once the cloud grace window has ended", () => {
    const license = project("grace", "available", { graceExpiresAt: "2026-09-25T15:00:00.000Z" });

    expect(decision(license, "cloud_control_plane").verdict).toBe("denied");
    expect(decision(license, "cloud_control_plane").reason).toBe("license_grace_expired");
  });

  it("keeps local work alive through a transient billing outage", () => {
    const outage = fixture.negative_fixtures.transient_billing_outage;

    expect(outage).toEqual({
      subscription_status: "grace",
      local_execution: "allowed_until_offline_valid_until",
      platform_paid_inference: "may_deny_with_stable_reason",
    });

    const license = project("grace", "unavailable", { graceExpiresAt: GRACE_UNTIL });

    expect(license.state).toBe("grace");
    expect(decision(license, "local_only").allowed).toBe(true);
    expect(decision(license, "local_only").until).toBe(LOCAL_UNTIL);
    expect(decision(license, "platform_paid_inference").allowed).toBe(false);
    expect(decision(license, "platform_paid_inference").reason).toBe("provider_unavailable");
  });

  it("never reports a reason as server prose", () => {
    for (const status of ["active", "grace", "past_due", "suspended", "cancelled"] as const) {
      for (const decisionItem of project(status, "available").decisions) {
        expect(decisionItem.reason).toMatch(/^[a-z][a-z0-9_]*$/);
      }
    }
  });
});

describe("license matrix reference", () => {
  it("covers every LicenseState the contract defines", () => {
    const states: LicenseState[] = [
      "active",
      "grace",
      "past_due",
      "suspended",
      "cancelled",
      "expired",
      "provider_unavailable",
    ];

    expect(FROZEN_CAPABILITY_MATRIX.map((row) => row.state)).toEqual(states);
  });
});

describe("two separate clocks", () => {
  it("reports the local clock and both cloud clocks as distinct facts", () => {
    const clocks = readLicenseClocks({
      offlineValidUntil: LOCAL_UNTIL,
      policyFreshUntil: POLICY_FRESH_UNTIL,
      graceExpiresAt: GRACE_UNTIL,
    });

    expect(clocks.separate).toBe(true);
    expect(clocks.localUntil).toBe(LOCAL_UNTIL);
    expect(clocks.cloudPolicyFreshUntil).toBe(POLICY_FRESH_UNTIL);
    expect(clocks.cloudGraceExpiresAt).toBe(GRACE_UNTIL);
  });

  it("picks the earliest boundary when several constrain one decision", () => {
    expect(earliest(GRACE_UNTIL, POLICY_FRESH_UNTIL, LOCAL_UNTIL)).toBe(POLICY_FRESH_UNTIL);
    expect(earliest(null, GRACE_UNTIL)).toBe(GRACE_UNTIL);
    expect(earliest(null, undefined)).toBeNull();
  });
});
