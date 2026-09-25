import { describe, expect, it } from "vitest";

import fixture from "../../../../../docs/implementation/fixtures/p06-contracts-v1.json";

import type { OverLimitResource } from "./api";
import { decodePlanChangePreview } from "./api";
import {
  assessPlanChange,
  BLOCKED_OPERATIONS,
  countableLimits,
  DOWNGRADE_BLOCKED_COPY,
  DOWNGRADE_HONESTY_STATEMENT,
  projectOverLimit,
  projectOverLimitList,
  reportedCount,
} from "./downgrade";

const overLimitFixture = fixture.negative_fixtures.over_limit_downgrade;

function resource(overrides: Partial<OverLimitResource> = {}): OverLimitResource {
  return {
    entitlement_key: "automations.max_active",
    limit: 3,
    current: 7,
    over_by: 4,
    seat_based: false,
    remediation: [],
    ...overrides,
  };
}

describe("over-limit projection", () => {
  it("reports the frozen downgrade fixture exactly", () => {
    expect(overLimitFixture).toEqual({
      plan_key: "starter",
      "automations.max_active": 3,
      current_active_automations: 7,
      expected: "block_new_and_expansion_without_delete",
    });

    const projected = projectOverLimit(
      resource({
        limit: overLimitFixture["automations.max_active"],
        current: overLimitFixture.current_active_automations,
      }),
    );

    expect(projected).toMatchObject({
      entitlementKey: "automations.max_active",
      label: "Active automations",
      limit: 3,
      current: 7,
      overBy: 4,
    });
  });

  it("can never report that a downgrade deletes data", () => {
    const projected = projectOverLimit(resource());

    expect(projected.deletesData).toBe(false);
    expect(DOWNGRADE_HONESTY_STATEMENT).toBe(
      "A downgrade blocks new and expanded work above the new limit. It does not delete anything that already exists.",
    );
    expect(DOWNGRADE_BLOCKED_COPY).toContain("remain readable");
  });

  it("blocks creation and expansion only", () => {
    expect(BLOCKED_OPERATIONS).toEqual([
      "create new resources above the limit",
      "expand an existing resource above the limit",
    ]);
  });

  it("offers seat suspension only for a seat-based limit", () => {
    const automations = projectOverLimit(resource());
    const members = projectOverLimit(
      resource({
        entitlement_key: "org.max_members",
        limit: 5,
        current: 12,
        over_by: 7,
        seat_based: true,
      }),
    );

    expect(automations.remediation).toEqual(["reduce_to_limit", "upgrade_plan"]);
    expect(members.remediation).toEqual(["reduce_to_limit", "suspend_seats", "upgrade_plan"]);
  });

  it("derives the seat-based default from the entitlement key at the boundary", () => {
    const decoded = decodePlanChangePreview({
      direction: "downgrade",
      target_plan_key: "starter",
      over_limit: [
        { entitlement_key: "org.max_members", limit: 5, current: 12 },
        { entitlement_key: "automations.max_active", limit: 3, current: 7 },
      ],
    });

    expect(decoded.over_limit[0]?.seat_based).toBe(true);
    expect(decoded.over_limit[1]?.seat_based).toBe(false);
  });

  it("keeps a server-published remediation set while adding the mandatory paths", () => {
    const projected = projectOverLimit(
      resource({ remediation: ["upgrade_plan", "suspend_seats"] }),
    );

    expect(projected.remediation).toEqual(["reduce_to_limit", "suspend_seats", "upgrade_plan"]);
  });

  it("drops a resource that is not actually over the limit", () => {
    const projections = projectOverLimitList([
      resource(),
      resource({ entitlement_key: "devices.max_enrolled", limit: 10, current: 4, over_by: 0 }),
    ]);

    expect(projections.map((item) => item.entitlementKey)).toEqual(["automations.max_active"]);
  });

  it("marks a key outside the frozen baseline set", () => {
    const projected = projectOverLimit(
      resource({ entitlement_key: "usage.realtime_hours", limit: 1, current: 4, over_by: 3 }),
    );

    expect(projected.outsideBaseline).toBe(true);
  });
});

describe("plan change assessment", () => {
  it("submits an upgrade the server stated is an upgrade without a downgrade preview", () => {
    const assessment = assessPlanChange({
      preview: {
        direction: "upgrade",
        current_plan_key: "starter",
        target_plan_key: "team",
        over_limit: [],
        deletes_data: false,
        blocks_new_work: false,
        reason: null,
      },
      previewRequested: true,
      previewFailed: false,
      previewAvailable: true,
      currentPlanKey: "starter",
      targetPlanKey: "team",
    });

    expect(assessment.direction).toBe("upgrade");
    expect(assessment.isDowngrade).toBe(false);
    expect(assessment.blockedReason).toBeNull();
    expect(assessment.deletesData).toBe(false);
  });

  it("submits a previewed downgrade and states that new work is blocked", () => {
    const assessment = assessPlanChange({
      preview: {
        direction: "downgrade",
        current_plan_key: "team",
        target_plan_key: "starter",
        over_limit: [resource()],
        deletes_data: false,
        blocks_new_work: true,
        reason: null,
      },
      previewRequested: true,
      previewFailed: false,
      previewAvailable: true,
      currentPlanKey: "team",
      targetPlanKey: "starter",
    });

    expect(assessment.isDowngrade).toBe(true);
    expect(assessment.blockedReason).toBeNull();
    expect(assessment.blocksNewWork).toBe(true);
    expect(assessment.overLimit).toHaveLength(1);
    expect(assessment.deletesData).toBe(false);
  });

  it("refuses to submit anything when no preview route is published", () => {
    const assessment = assessPlanChange({
      preview: null,
      previewRequested: false,
      previewFailed: false,
      previewAvailable: false,
      currentPlanKey: "team",
      targetPlanKey: "starter",
    });

    expect(assessment.previewAvailable).toBe(false);
    expect(assessment.blockedReason).toContain("previewed before it is submitted");
  });

  it("refuses to submit when the preview failed and says nothing was sent", () => {
    const assessment = assessPlanChange({
      preview: null,
      previewRequested: true,
      previewFailed: true,
      previewAvailable: true,
      currentPlanKey: "team",
      targetPlanKey: "starter",
    });

    expect(assessment.blockedReason).toContain("Nothing was submitted");
  });

  it("refuses to guess whether a change is an upgrade or a downgrade", () => {
    const assessment = assessPlanChange({
      preview: {
        direction: "unknown",
        current_plan_key: "team",
        target_plan_key: "starter",
        over_limit: [],
        deletes_data: false,
        blocks_new_work: false,
        reason: null,
      },
      previewRequested: true,
      previewFailed: false,
      previewAvailable: true,
      currentPlanKey: "team",
      targetPlanKey: "starter",
    });

    expect(assessment.direction).toBe("unknown");
    expect(assessment.isDowngrade).toBe(false);
    expect(assessment.previewRequired).toBe(true);
    expect(assessment.blockedReason).toContain("will not submit it");
  });

  it("never states that a downgrade deletes data, whatever the server said", () => {
    const assessment = assessPlanChange({
      preview: {
        direction: "downgrade",
        current_plan_key: "team",
        target_plan_key: "starter",
        over_limit: [resource()],
        deletes_data: false,
        blocks_new_work: true,
        reason: "provider_plan_will_be_removed",
      },
      previewRequested: true,
      previewFailed: false,
      previewAvailable: true,
      currentPlanKey: "team",
      targetPlanKey: "starter",
    });

    expect(assessment.deletesData).toBe(false);
    expect(JSON.stringify(assessment)).not.toContain('"deletes_data":true');
  });
});

describe("counted limits and authoritative usage", () => {
  it("lists only limits backed by a counted resource", () => {
    const limits = countableLimits([
      {
        key: "automations.max_active",
        value: 100,
        source: "plan",
        effective_at: null,
        expires_at: null,
        reason: null,
        scope: null,
      },
      {
        key: "webhooks.enabled",
        value: true,
        source: "plan",
        effective_at: null,
        expires_at: null,
        reason: null,
        scope: null,
      },
      {
        key: "audit.retention_days",
        value: 365,
        source: "plan",
        effective_at: null,
        expires_at: null,
        reason: null,
        scope: null,
      },
      {
        key: "org.max_members",
        value: 25,
        source: "plan",
        effective_at: null,
        expires_at: null,
        reason: null,
        scope: null,
      },
    ]);

    expect(limits.map((item) => item.key)).toEqual(["org.max_members", "automations.max_active"]);
  });

  it("attaches a reported count only when the server published one", () => {
    const reported = [resource({ entitlement_key: "org.max_members", limit: 25, current: 9 })];

    expect(reportedCount("org.max_members", reported)?.current).toBe(9);
    expect(reportedCount("automations.max_active", reported)).toBeNull();
  });
});
