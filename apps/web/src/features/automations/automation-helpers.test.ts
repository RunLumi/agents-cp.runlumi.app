// Occurrence, off-peak, limit, and action-error presentation.
//
// The load-bearing assertions here are the two the gate calls out: `ambiguous`
// must not read as a retryable failure, and a provider-ticket off-peak
// occurrence must never be described as a clock schedule.

import { describe, expect, it } from "vitest";

import fixture from "../../../../../docs/implementation/fixtures/p06-contracts-v1.json";
import { ApiClientError } from "@/lib/errors";
import {
  AMBIGUOUS_EXPLANATION,
  automationActionErrorMessage,
  automationLimitState,
  executionPolicySummary,
  isAutomationConflict,
  isOccurrenceState,
  isPermissionFailure,
  isTerminalOccurrenceState,
  isUnconfirmedMutation,
  occurrenceStateExplanation,
  occurrenceStateLabel,
  occurrenceTone,
  offPeakConstraintSummary,
  offPeakEligibilityDetail,
  offPeakEligibilityLabel,
  principalSummary,
  targetSummary,
} from "./automation-helpers";
import { decodeAutomation, decodeEntitlements } from "./api";
import type { AutomationDefinition, AutomationEntitlements, OffPeakPolicy } from "./api";

const automation = decodeAutomation(fixture.automation) as AutomationDefinition;
const entitlements = decodeEntitlements(fixture.entitlements) as AutomationEntitlements;
// The fixture's off-peak object is the frozen wire shape; it is typed through the
// projection the components consume.
const offPeak = fixture.off_peak as unknown as OffPeakPolicy;

describe("occurrence state presentation", () => {
  it("recognizes only the frozen occurrence states", () => {
    expect(isOccurrenceState("ambiguous")).toBe(true);
    expect(isOccurrenceState("reconciled")).toBe(false);
  });

  it("keeps the frozen terminal set, with ambiguous included", () => {
    for (const state of [
      "succeeded",
      "failed",
      "cancelled",
      "missed",
      "skipped",
      "ambiguous",
    ] as const) {
      expect(isTerminalOccurrenceState(state)).toBe(true);
    }
    for (const state of ["pending", "dispatching", "leased", "started"] as const) {
      expect(isTerminalOccurrenceState(state)).toBe(false);
    }
  });

  it("never dresses ambiguous as a retryable failure", () => {
    expect(occurrenceTone("ambiguous")).not.toBe(occurrenceTone("failed"));
    expect(occurrenceTone("ambiguous")).toBe("ambiguous");
    expect(occurrenceStateLabel("ambiguous")).toBe("Needs reconciliation");
    const explanation = occurrenceStateExplanation("ambiguous");
    expect(explanation).toBe(AMBIGUOUS_EXPLANATION);
    expect(explanation).toMatch(/cannot prove/i);
    expect(explanation).toMatch(/never retried automatically/i);
    expect(explanation).toMatch(/cannot claim it/i);
  });

  it("explains the deliberate non-execution states", () => {
    expect(occurrenceStateExplanation("skipped")).toMatch(/overlap or missed-run policy/i);
    expect(occurrenceStateExplanation("missed")).toMatch(/missed-run policy/i);
    expect(occurrenceStateExplanation("leased")).toMatch(/ambiguous/i);
    expect(occurrenceStateExplanation("succeeded")).toBeNull();
  });
});

describe("off-peak execution class", () => {
  it("states that a provider ticket has no clock schedule and no second occurrence", () => {
    const detail = offPeakEligibilityDetail("provider_ticket");
    expect(detail).toMatch(/no clock schedule/i);
    expect(detail).toMatch(/renewal does not create a second occurrence/i);
    expect(offPeakEligibilityDetail("org_window")).toMatch(/window/i);
  });

  it("labels both frozen eligibility sources", () => {
    expect(offPeakEligibilityLabel(offPeak)).toBe("Provider ticket");
    expect(offPeakEligibilityLabel({ ...offPeak, eligibility_source: "org_window" })).toBe(
      "Organization window",
    );
    expect(offPeakEligibilityLabel(null)).toBe("Not configured");
  });

  it("summarizes the surviving host safety restrictions", () => {
    const summary = offPeakConstraintSummary(offPeak);
    expect(summary).toContain("no automation changes");
    expect(summary).toContain("no nested off-peak work");
    expect(summary).toContain("no background processes");
  });
});

describe("definition summaries", () => {
  it("describes the target and principal from the frozen fixture", () => {
    expect(targetSummary(automation)).toBe(
      "Any eligible device · wsb_0123456789abcdef0123456789abcdef",
    );
    expect(principalSummary(automation)).toBe("user · usr_0123456789abcdef0123456789abcdef");
    expect(executionPolicySummary(automation)).toBe(
      "coding-default · Inherit budget · Project tool policy",
    );
  });
});

describe("entitlement limit presentation", () => {
  it("reads the frozen limit and stays exact only when the set is complete", () => {
    const state = automationLimitState([automation], entitlements, false);
    expect(state.limit).toBe(100);
    expect(state.activeLoaded).toBe(1);
    expect(state.atLimit).toBe(false);
    expect(state.headline).toBe("1 active of 100 allowed");
    expect(state.detail).toContain("Plan team");
  });

  it("reports the limit as reached only with a complete result set", () => {
    const overLimit = [
      automation,
      { ...automation, automation_id: "aut_1", status: "paused" as const },
      { ...automation, automation_id: "aut_2" },
    ];
    const partial = automationLimitState(overLimit, entitlements, true);
    expect(partial.atLimit).toBe(false);
    expect(partial.detail).toMatch(/counted from the results loaded so far/);

    const tight: AutomationEntitlements = {
      ...entitlements,
      values: { ...entitlements.values, "automations.max_active": 2 },
    };
    const reached = automationLimitState(overLimit, tight, false);
    expect(reached.atLimit).toBe(true);
    expect(reached.tone).toBe("warning");
    expect(reached.detail).toMatch(/Pause or delete one/);
  });

  it("fails closed in copy when the projection has no limit", () => {
    const state = automationLimitState([automation], null, false);
    expect(state.limit).toBeNull();
    expect(state.headline).toBe("Automation limit not readable");
    expect(state.detail).toMatch(/server still enforces the limit/i);
  });
});

describe("action error mapping", () => {
  it("maps a stale version to the frozen conflict copy", () => {
    const error = new ApiClientError({
      code: "version_conflict",
      kind: "api",
      status: 409,
      requestId: "req_0123456789abcdef0123456789abcdef",
      retryable: false,
    });
    expect(isAutomationConflict(error)).toBe(true);
    expect(automationActionErrorMessage(error)).toMatch(/Refresh the automation/i);
  });

  it("treats an invalid state as a conflict, not a permission problem", () => {
    const error = new ApiClientError({
      code: "automation_invalid_state",
      kind: "api",
      status: 409,
      requestId: undefined,
      retryable: false,
    });
    expect(isAutomationConflict(error)).toBe(true);
    expect(isPermissionFailure(error)).toBe(false);
  });

  it("recognizes an explicit permission denial", () => {
    const error = new ApiClientError({
      code: "permission_denied",
      kind: "api",
      status: 403,
      requestId: undefined,
      retryable: false,
    });
    expect(isPermissionFailure(error)).toBe(true);
    expect(automationActionErrorMessage(error)).toMatch(/cannot perform this action/i);
  });

  it("marks an unconfirmed mutation as possibly applied", () => {
    const error = new ApiClientError({
      code: "network_error",
      kind: "network",
      status: undefined,
      requestId: undefined,
      retryable: true,
    });
    expect(isUnconfirmedMutation(error)).toBe(true);
    expect(automationActionErrorMessage(error)).toMatch(/may already have been applied/i);
    expect(isAutomationConflict(error)).toBe(false);
  });

  it("never renders server prose", () => {
    const error = new ApiClientError({
      code: "schedule_invalid",
      kind: "api",
      status: 422,
      requestId: undefined,
      details: { reason: "provider diagnostic string" },
      retryable: false,
    });
    expect(automationActionErrorMessage(error)).not.toContain("provider diagnostic");
  });
});
