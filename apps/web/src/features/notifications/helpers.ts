/**
 * Notification state helpers: read state, archive semantics, and the
 * non-disclosing not-found behaviour the contract requires.
 */

import { ApiClientError } from "@/lib/errors";

import type { Notification, NotificationState } from "./api";

export function isUnread(notification: Notification): boolean {
  return notification.state === "unread";
}

export function isArchived(notification: Notification): boolean {
  return notification.state === "archived";
}

export function notificationStateTone(
  notification: Notification,
): "neutral" | "info" | "success" | "warning" | "danger" {
  if (notification.mandatory) return "danger";
  if (notification.state === "unread") return "info";
  if (notification.state === "archived") return "neutral";
  return "success";
}

export function notificationStateLabel(notification: Notification): string {
  if (notification.mandatory) return "Mandatory security";
  if (notification.state === "unread") return "Unread";
  if (notification.state === "archived") return "Archived";
  return "Read";
}

/**
 * The contract exposes exactly one mutation — mark read — and it is idempotent.
 * The UI therefore offers read/unread and archive as local view state, and
 * states plainly that only "mark read" is persisted. Inventing a second server
 * route would be a contract change, not a UI decision.
 */
export const PERSISTED_TRANSITION_COPY =
  "Marking read is persisted and idempotent. Archive and read/unread view filters are local to this page; the contract exposes no separate archive route.";

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "Not recorded";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatRelativeAge(value: string, now: number = Date.now()): string {
  const time = new Date(value).getTime();
  if (!Number.isFinite(time)) return "";
  const seconds = Math.round((now - time) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.round(days / 30);
  return months < 12 ? `${months}mo ago` : `${Math.round(months / 12)}y ago`;
}

export function isPermissionFailure(error: unknown): boolean {
  return (
    error instanceof ApiClientError && (error.status === 403 || error.code === "permission_denied")
  );
}

/**
 * A foreign notification ID returns the same non-disclosing not-found shape as a
 * missing one, so the UI must not claim that a record exists elsewhere.
 */
export function isNonDisclosingNotFound(error: unknown): boolean {
  return (
    error instanceof ApiClientError &&
    (error.code === "resource_not_found" || error.code === "not_found" || error.status === 404)
  );
}

export function isVersionConflict(error: unknown): boolean {
  return error instanceof ApiClientError && error.code === "version_conflict";
}

/** Apply a local read-state overlay without mutating the server projection. */
export function applyReadState(
  notifications: readonly Notification[],
  readIds: ReadonlySet<string>,
  archivedIds: ReadonlySet<string>,
): Notification[] {
  return notifications.map((notification) => {
    if (archivedIds.has(notification.notification_id)) {
      return { ...notification, state: "archived" as NotificationState };
    }
    if (readIds.has(notification.notification_id) && notification.state === "unread") {
      return { ...notification, state: "read" as NotificationState };
    }
    return notification;
  });
}

export function countUnread(notifications: readonly Notification[]): number {
  return notifications.filter((notification) => notification.state === "unread").length;
}
