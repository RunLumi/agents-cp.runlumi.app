import { describe, expect, it } from "vitest";

import { P06_EVENT_TYPES } from "@/features/webhooks/event-types";

import {
  CATEGORY_LABELS,
  enforcedOptOuts,
  INFORMATIONAL_EVENT_TYPES,
  isMandatorySecurityEvent,
  mandatoryRuleFor,
  MANDATORY_SECURITY_RULES,
  notificationCategoryOf,
  notificationSummary,
  validateOptOutList,
} from "./event-types";
import { NOTIFICATION_CATEGORIES } from "./api";

describe("informational notification vocabulary", () => {
  it("is a subset of the frozen P06 list and excludes delivery plumbing", () => {
    expect(INFORMATIONAL_EVENT_TYPES.length).toBeGreaterThan(0);
    for (const eventType of INFORMATIONAL_EVENT_TYPES) {
      expect(P06_EVENT_TYPES).toContain(eventType);
      expect(eventType.startsWith("webhook.")).toBe(false);
      expect(eventType.startsWith("notification.delivery_")).toBe(false);
    }
  });

  it("keeps the notification-created event and every business family", () => {
    expect(INFORMATIONAL_EVENT_TYPES).toContain("notification.created.v1");
    expect(INFORMATIONAL_EVENT_TYPES).toContain("automation.occurrence.ambiguous.v1");
    expect(INFORMATIONAL_EVENT_TYPES).toContain("deletion.completed.v1");
    expect(INFORMATIONAL_EVENT_TYPES).toContain("export.failed.v1");
  });

  it("maps every informational event to one of the five frozen categories", () => {
    for (const eventType of INFORMATIONAL_EVENT_TYPES) {
      expect(NOTIFICATION_CATEGORIES).toContain(notificationCategoryOf(eventType));
    }
    expect(Object.keys(CATEGORY_LABELS).sort()).toEqual([...NOTIFICATION_CATEGORIES].sort());
  });

  it("groups export, deletion, and data policy as policy work", () => {
    expect(notificationCategoryOf("export.requested.v1")).toBe("policy");
    expect(notificationCategoryOf("deletion.step_completed.v1")).toBe("policy");
    expect(notificationCategoryOf("data_policy.updated.v1")).toBe("policy");
    expect(notificationCategoryOf("license.snapshot_issued.v1")).toBe("billing");
    expect(notificationCategoryOf("entitlement.override_created.v1")).toBe("billing");
    expect(notificationCategoryOf("automation.definition.paused.v1")).toBe("automation");
  });
});

describe("mandatory security rule", () => {
  it("covers exactly the families the contract gate names", () => {
    expect(MANDATORY_SECURITY_RULES.map((rule) => rule.value)).toEqual([
      "auth.",
      "device.revoked",
      "organization.suspended",
      "approval.",
      "credential.",
    ]);
  });

  it("matches by family, so a new event inside a family is mandatory too", () => {
    expect(isMandatorySecurityEvent("auth.login.completed.v1")).toBe(true);
    expect(isMandatorySecurityEvent("auth.session.rotated.v1")).toBe(true);
    expect(isMandatorySecurityEvent("auth.something_new.v1")).toBe(true);
    expect(isMandatorySecurityEvent("device.revoked.v1")).toBe(true);
    expect(isMandatorySecurityEvent("organization.suspended.v1")).toBe(true);
    expect(isMandatorySecurityEvent("approval.resolved.v1")).toBe(true);
    expect(isMandatorySecurityEvent("credential.revoked.v1")).toBe(true);
  });

  it("mirrors the server's containment check for the two name stems", () => {
    // The server trigger matches `device.revoked` and `organization.suspended`
    // by containment, so the client must too: a stricter client would show a
    // mandatory event as optional and then let the write fail.
    expect(isMandatorySecurityEvent("device.revoked.v1")).toBe(true);
    expect(isMandatorySecurityEvent("organization.suspended.v1")).toBe(true);
    expect(isMandatorySecurityEvent("device.revoked_extra.v1")).toBe(true);
    expect(mandatoryRuleFor("device.revoked.v1")?.label).toBe("device revocation");
  });

  it("does not over-match an unrelated event", () => {
    expect(isMandatorySecurityEvent("device.enrollment.approved.v1")).toBe(false);
    expect(isMandatorySecurityEvent("device_code.approved.v1")).toBe(false);
    expect(isMandatorySecurityEvent("organization.resumed.v1")).toBe(false);
    expect(isMandatorySecurityEvent("organization.deletion_started.v1")).toBe(false);
    expect(isMandatorySecurityEvent("authenticated.v1")).toBe(false);
    expect(isMandatorySecurityEvent("billing.grace_ended.v1")).toBe(false);
    expect(mandatoryRuleFor("billing.grace_ended.v1")).toBeUndefined();
  });

  it("never classifies an informational P06 event as mandatory", () => {
    for (const eventType of INFORMATIONAL_EVENT_TYPES) {
      expect(isMandatorySecurityEvent(eventType)).toBe(false);
    }
  });
});

describe("opt-out validation", () => {
  it("accepts an informational opt-out list and sorts it", () => {
    const result = validateOptOutList([
      "export.requested.v1",
      "billing.grace_ended.v1",
      "export.requested.v1",
    ]);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.eventTypes).toEqual(["billing.grace_ended.v1", "export.requested.v1"]);
    }
  });

  it("refuses a mandatory security opt-out with the reason, not silently", () => {
    const result = validateOptOutList(["auth.login.completed.v1", "export.requested.v1"]);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.rejections).toHaveLength(1);
      expect(result.rejections[0]?.eventType).toBe("auth.login.completed.v1");
      expect(result.rejections[0]?.rule.label).toContain("authentication");
      expect(result.rejections[0]?.message).toContain("mandatory");
    }
  });

  it("refuses every mandatory family it is shown", () => {
    for (const rule of MANDATORY_SECURITY_RULES) {
      const probe = rule.kind === "prefix" ? `${rule.value}probe.v1` : `${rule.value}.v1`;
      expect(validateOptOutList([probe]).ok).toBe(false);
    }
  });

  it("treats an empty list as deliver-everything", () => {
    expect(validateOptOutList([])).toEqual({ ok: true, eventTypes: [] });
  });

  it("strips a mandatory name from a stored or stale row instead of showing it as saved", () => {
    expect(
      enforcedOptOuts(["auth.login.completed.v1", "device.revoked.v1", "export.requested.v1"]),
    ).toEqual(["export.requested.v1"]);
    expect(enforcedOptOuts(["  ", "billing.grace_ended.v1", "billing.grace_ended.v1"])).toEqual([
      "billing.grace_ended.v1",
    ]);
  });
});

describe("bounded notification body rendering", () => {
  it("prefers a title, then a summary, then the event name", () => {
    expect(notificationSummary({ title: "Credential revoked" }, "fallback").title).toBe(
      "Credential revoked",
    );
    expect(notificationSummary({ summary: "Grace ended" }, "fallback").title).toBe("Grace ended");
    expect(notificationSummary({}, "fallback").title).toBe("fallback");
  });

  it("keeps only scalar bounded facts and drops nested values", () => {
    const summary = notificationSummary(
      { count: 3, flag: true, missing: null, nested: { secret: "no" }, text: "ok" },
      "fallback",
    );
    expect(summary.facts).toEqual([
      { key: "count", value: "3" },
      { key: "flag", value: "true" },
      { key: "text", value: "ok" },
    ]);
  });

  it("caps the number of rendered facts", () => {
    const body = Object.fromEntries(
      Array.from({ length: 20 }, (_, index) => [`field_${index}`, String(index)]),
    );
    expect(notificationSummary(body, "fallback").facts).toHaveLength(6);
  });
});
