import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import { NotificationItem } from "./notification-center";
import { MandatorySecurityPanel } from "./notification-preferences";
import type { Notification } from "./api";
import {
  applyReadState,
  countUnread,
  notificationStateLabel,
  notificationStateTone,
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
    body: { state: "succeeded" },
    created_at: "2026-09-25T12:00:00.000Z",
    updated_at: "2026-09-25T12:00:00.000Z",
    ...overrides,
  };
}

function renderItem(overrides: Partial<Notification> = {}): string {
  return renderToStaticMarkup(
    <ul>
      <NotificationItem
        notification={notification(overrides)}
        marking={false}
        anyMarking={false}
        onMarkRead={() => {}}
        onToggleArchive={() => {}}
      />
    </ul>,
  );
}

describe("notification row rendering", () => {
  it("marks a mandatory security notification and says it cannot be switched off", () => {
    const markup = renderItem({
      event_type: "auth.login.completed.v1",
      category: "security",
      mandatory: true,
    });
    expect(markup).toContain("Mandatory security");
    expect(markup).toContain("cannot be switched off by notification preferences");
    expect(markup).toContain("auth.login.completed.v1");
  });

  it("keeps the bounded details collapsed and labelled", () => {
    const markup = renderItem();
    expect(markup).toContain("<details");
    expect(markup).toContain("Notification details — may name your own resources");
    // Bounded metadata renders as a definition list, never as a serialized blob.
    expect(markup).toContain("<dl");
    expect(markup).toContain("state");
    expect(markup).not.toContain("<pre");
  });

  it("offers mark-read as the only persisted action and labels archive as a toggle", () => {
    const markup = renderItem();
    expect(markup).toContain("Mark read");
    expect(markup).toContain("Archive");
    expect(markup).toContain('aria-pressed="false"');
  });

  it("disables mark-read once the notification is already read", () => {
    const markup = renderItem({ state: "read", read_at: "2026-09-25T12:30:00.000Z" });
    expect(markup).toContain("Read");
    expect(markup).toMatch(/<button[^>]*disabled[^>]*>Read<\/button>/);
  });
});

describe("mandatory security surface", () => {
  it("names every mandatory family and marks each one as not optional", () => {
    const markup = renderToStaticMarkup(<MandatorySecurityPanel />);
    expect(markup).toContain("Mandatory security event families");
    expect(markup).toContain("are not optional");
    expect(markup).toContain("auth.*");
    expect(markup).toContain("device.revoked.*");
    expect(markup).toContain("organization.suspended.*");
    expect(markup).toContain("approval.*");
    expect(markup).toContain("credential.*");
    expect(markup).toContain("The check is by family");
  });
});

describe("read-state overlay", () => {
  it("always presents a mandatory security notification as mandatory", () => {
    const mandatory = notification({ mandatory: true, category: "security" });
    expect(notificationStateLabel(mandatory)).toBe("Mandatory security");
    expect(notificationStateTone(mandatory)).toBe("danger");
  });

  it("counts a mandatory notification as unread until it is actually read", () => {
    const source = [notification({ mandatory: true, category: "security" })];
    expect(countUnread(applyReadState(source, new Set(), new Set()))).toBe(1);
    expect(
      countUnread(applyReadState(source, new Set([source[0]!.notification_id]), new Set())),
    ).toBe(0);
  });
});
