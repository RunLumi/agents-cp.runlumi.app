import { describe, expect, it } from "vitest";

import { ApiClientError } from "@/lib/errors";

import type { Notification } from "./api";
import {
  applyReadState,
  countUnread,
  formatRelativeAge,
  isNonDisclosingNotFound,
  isPermissionFailure,
  isVersionConflict,
  notificationStateLabel,
  notificationStateTone,
  PERSISTED_TRANSITION_COPY,
} from "./helpers";

function notification(overrides: Partial<Notification> = {}): Notification {
  return {
    notification_id: "ntf_0123456789abcdef0123456789abcdef",
    org_id: "org_0123456789abcdef0123456789abcdef",
    event_id: "evt_0123456789abcdef0123456789abcdef",
    event_type: "automation.occurrence.completed.v1",
    category: "automation",
    mandatory: false,
    state: "unread",
    read_at: null,
    body: {},
    created_at: "2026-09-25T12:00:00.000Z",
    updated_at: "2026-09-25T12:00:00.000Z",
    ...overrides,
  };
}

describe("notification read state", () => {
  it("marks a mandatory security notification before any other read state", () => {
    const mandatory = notification({ mandatory: true, state: "read", category: "security" });
    expect(notificationStateLabel(mandatory)).toBe("Mandatory security");
    expect(notificationStateTone(mandatory)).toBe("danger");
    expect(notificationStateLabel(notification())).toBe("Unread");
    expect(notificationStateTone(notification())).toBe("info");
    expect(notificationStateLabel(notification({ state: "archived" }))).toBe("Archived");
  });

  it("applies a local overlay without mutating the server projection", () => {
    const source = [
      notification(),
      notification({ notification_id: "ntf_1123456789abcdef0123456789abcdef" }),
    ];
    const overlaid = applyReadState(source, new Set([source[0]!.notification_id]), new Set());
    expect(overlaid[0]?.state).toBe("read");
    expect(overlaid[1]?.state).toBe("unread");
    expect(source[0]?.state).toBe("unread");
  });

  it("lets an archive override a read mark", () => {
    const source = [notification()];
    const overlaid = applyReadState(
      source,
      new Set([source[0]!.notification_id]),
      new Set([source[0]!.notification_id]),
    );
    expect(overlaid[0]?.state).toBe("archived");
  });

  it("counts unread items after the overlay", () => {
    const source = [
      notification(),
      notification({ notification_id: "ntf_1123456789abcdef0123456789abcdef" }),
    ];
    const overlaid = applyReadState(source, new Set([source[0]!.notification_id]), new Set());
    expect(countUnread(overlaid)).toBe(1);
    expect(countUnread([])).toBe(0);
  });

  it("states that only mark-read is persisted, rather than implying an archive route", () => {
    expect(PERSISTED_TRANSITION_COPY).toContain("no separate archive route");
  });
});

describe("non-disclosing failures", () => {
  it("treats a foreign and a missing notification identically", () => {
    const notFound = new ApiClientError({
      code: "resource_not_found",
      kind: "api",
      status: 404,
      requestId: undefined,
      retryable: false,
    });
    expect(isNonDisclosingNotFound(notFound)).toBe(true);
    expect(isNonDisclosingNotFound(new Error("boom"))).toBe(false);
  });

  it("separates permission and version failures", () => {
    const denied = new ApiClientError({
      code: "permission_denied",
      kind: "api",
      status: 403,
      requestId: undefined,
      retryable: false,
    });
    expect(isPermissionFailure(denied)).toBe(true);
    expect(isPermissionFailure(new Error("boom"))).toBe(false);

    const conflict = new ApiClientError({
      code: "version_conflict",
      kind: "api",
      status: 409,
      requestId: undefined,
      retryable: false,
    });
    expect(isVersionConflict(conflict)).toBe(true);
  });
});

describe("relative age", () => {
  it("reads as a short operator-facing age and degrades to empty on bad input", () => {
    const now = Date.parse("2026-09-25T12:00:00.000Z");
    expect(formatRelativeAge("2026-09-25T11:59:30.000Z", now)).toBe("just now");
    expect(formatRelativeAge("2026-09-25T11:30:00.000Z", now)).toBe("30m ago");
    expect(formatRelativeAge("2026-09-25T06:00:00.000Z", now)).toBe("6h ago");
    expect(formatRelativeAge("2026-09-20T12:00:00.000Z", now)).toBe("5d ago");
    expect(formatRelativeAge("not a date", now)).toBe("");
  });
});
