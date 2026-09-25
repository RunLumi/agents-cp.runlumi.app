import { describe, expect, it } from "vitest";

import {
  EVENT_FAMILIES,
  EVENT_FAMILY_PAYLOAD_FIELDS,
  isFanoutExcluded,
  isP06EventType,
  MAX_SUBSCRIPTIONS,
  P06_EVENT_TYPES,
  partitionSubscription,
  filterFamilies,
  payloadFieldsFor,
  sortEventTypes,
  SUBSCRIBABLE_EVENT_TYPES,
  validateExactEventName,
  validateSubscription,
} from "@/features/webhooks/event-types";

describe("frozen P06 event vocabulary", () => {
  it("lists the 48 frozen names exactly once each", () => {
    expect(P06_EVENT_TYPES).toHaveLength(48);
    expect(new Set(P06_EVENT_TYPES).size).toBe(48);
  });

  it("covers every family named by the contract gate", () => {
    const families = EVENT_FAMILIES.map((family) => family.id);
    expect(families).toEqual([
      "automation.definition",
      "automation.occurrence",
      "webhook.endpoint",
      "webhook.delivery",
      "notification",
      "billing",
      "entitlement",
      "license",
      "data_policy",
      "export",
      "deletion",
    ]);
  });

  it("partitions the frozen list into families with no gaps or overlaps", () => {
    const grouped = EVENT_FAMILIES.flatMap((family) => family.eventTypes);
    expect(grouped).toHaveLength(P06_EVENT_TYPES.length);
    expect(new Set(grouped).size).toBe(grouped.length);
    for (const eventType of P06_EVENT_TYPES) {
      expect(grouped).toContain(eventType);
    }
  });

  it("only publishes the frozen required-payload fields the gate tabulates", () => {
    for (const family of EVENT_FAMILIES) {
      const fields = EVENT_FAMILY_PAYLOAD_FIELDS[family.id];
      if (fields === undefined) {
        expect(payloadFieldsFor(family.eventTypes[0] ?? "")).toEqual([]);
        continue;
      }
      expect(fields.length).toBeGreaterThan(0);
    }
  });

  it("never offers a delivery, endpoint, or notification-delivery name for subscription", () => {
    for (const eventType of SUBSCRIBABLE_EVENT_TYPES) {
      expect(isFanoutExcluded(eventType)).toBe(false);
    }
    expect(SUBSCRIBABLE_EVENT_TYPES).toHaveLength(36);
    for (const eventType of P06_EVENT_TYPES) {
      if (isFanoutExcluded(eventType)) {
        expect(SUBSCRIBABLE_EVENT_TYPES).not.toContain(eventType);
      }
    }
  });
});

describe("exact-name subscription rule", () => {
  it("rejects a wildcard with an explicit reason", () => {
    const rejection = validateExactEventName("automation.occurrence.*");
    expect(rejection?.code).toBe("wildcard");
    expect(rejection?.message).toContain("Wildcards are not accepted");
  });

  it("rejects a bare wildcard and a mid-name wildcard", () => {
    expect(validateExactEventName("*")?.code).toBe("wildcard");
    expect(validateExactEventName("webhook.*")?.code).toBe("wildcard");
  });

  it("rejects a family prefix and says it is a family", () => {
    const rejection = validateExactEventName("automation.occurrence");
    expect(rejection?.code).toBe("family_prefix");
    expect(rejection?.message).toContain("is a family");
    expect(validateExactEventName("automation")?.code).toBe("family_prefix");
  });

  it("rejects a registered name that is never fanned out", () => {
    expect(validateExactEventName("webhook.test.v1")?.code).toBe("fanout_excluded");
    expect(validateExactEventName("webhook.delivery_succeeded.v1")?.code).toBe("fanout_excluded");
    expect(validateExactEventName("notification.delivery_dead_lettered.v1")?.code).toBe(
      "fanout_excluded",
    );
  });

  it("rejects an unregistered dotted name and a non-dotted value differently", () => {
    expect(validateExactEventName("automation.occurrence.invented.v1")?.code).toBe("unknown");
    expect(validateExactEventName("not an event")?.code).toBe("unknown");
    expect(validateExactEventName("")?.code).toBe("empty");
    expect(validateExactEventName("x".repeat(97))?.code).toBe("too_long");
  });

  it("accepts every subscribable frozen name", () => {
    for (const eventType of SUBSCRIBABLE_EVENT_TYPES) {
      expect(validateExactEventName(eventType)).toBeNull();
    }
  });

  it("requires at least one exact name and bounds the list", () => {
    const empty = validateSubscription([]);
    expect(empty.ok).toBe(false);

    const many = Array.from({ length: MAX_SUBSCRIPTIONS + 1 }, (_, index) => {
      // Distinct, valid, subscribable names are limited to 36; the bound is
      // enforced even though the picker cannot exceed it on its own.
      return `automation.definition.created.v${index + 1}`;
    });
    expect(validateSubscription(many).ok).toBe(false);
  });

  it("de-duplicates and sorts so a repeated selection cannot change the stored list", () => {
    const result = validateSubscription([
      "billing.grace_ended.v1",
      "automation.occurrence.completed.v1",
      "billing.grace_ended.v1",
    ]);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.eventTypes).toEqual([
        "automation.occurrence.completed.v1",
        "billing.grace_ended.v1",
      ]);
    }
    expect(sortEventTypes([" b.v1 ", "a.v1", "a.v1", ""])).toEqual(["a.v1", "b.v1"]);
  });

  it("reports every rejection instead of only the first", () => {
    const result = validateSubscription([
      "automation.*",
      "automation.occurrence",
      "webhook.delivery_replayed.v1",
    ]);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.rejections.map((rejection) => rejection.code)).toEqual([
        "wildcard",
        "family_prefix",
        "fanout_excluded",
      ]);
    }
  });
});

describe("stored subscriptions the P06 picker does not own", () => {
  it("preserves an already-stored non-P06 name instead of dropping it on save", () => {
    const partition = partitionSubscription([
      "auth.login.completed.v1",
      "automation.occurrence.completed.v1",
      "webhook.test.v1",
    ]);
    expect(partition.p06).toEqual(["automation.occurrence.completed.v1", "webhook.test.v1"]);
    expect(partition.external).toEqual(["auth.login.completed.v1"]);
  });

  it("keeps a fan-out-excluded name that is already stored, but never offers it", () => {
    expect(isP06EventType("webhook.test.v1")).toBe(true);
    expect(partitionSubscription(["webhook.test.v1"]).p06).toEqual(["webhook.test.v1"]);
    expect(SUBSCRIBABLE_EVENT_TYPES).not.toContain("webhook.test.v1");
  });
});

describe("picker filter", () => {
  it("narrows families by substring and drops empty families", () => {
    const families = filterFamilies("occurrence");
    expect(families).toHaveLength(1);
    expect(families[0]?.id).toBe("automation.occurrence");
    expect(filterFamilies("")).toHaveLength(EVENT_FAMILIES.length);
    expect(filterFamilies("zzzz")).toHaveLength(0);
  });
});
