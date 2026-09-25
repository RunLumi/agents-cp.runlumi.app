/**
 * App-level notification center (`/notifications`).
 *
 * Frozen contract: `docs/implementation/gates/P06-CG.md` → "API contract" and
 * "Notification channels". The list is principal-scoped and cursor-paginated by
 * `(created_at, notification_id)`; the recipient is resolved from the
 * authenticated session, never from a path or body value.
 *
 * Mandatory security notifications are marked and cannot be filtered away, so an
 * operator cannot archive their way out of a credential revocation.
 */

import { useCallback, useEffect, useId, useRef, useState } from "react";

import { ApiClientError } from "@/lib/errors";

import {
  listNotifications,
  markNotificationRead,
  NOTIFICATION_CATEGORIES,
  type ListNotificationsQuery,
  type Notification,
  type NotificationCategory,
} from "./api";
import {
  applyReadState,
  countUnread,
  formatDateTime,
  formatRelativeAge,
  isNonDisclosingNotFound,
  isPermissionFailure,
  notificationStateLabel,
  notificationStateTone,
  PERSISTED_TRANSITION_COPY,
} from "./helpers";
import { CATEGORY_LABELS, notificationSummary } from "./event-types";
import {
  EmptyState,
  ErrorNotice,
  filterControlClass,
  ghostButtonClass,
  LoadingRows,
  Notice,
  PaginationFooter,
  PermissionState,
  Pill,
  secondaryButtonClass,
  selectedButtonClass,
  Surface,
  SurfaceHeader,
} from "./ui";

const PAGE_SIZE = 25;

type LoadStatus = "idle" | "loading" | "refreshing" | "ready" | "error";

interface NotificationCollection {
  readonly status: LoadStatus;
  readonly items: Notification[];
  readonly nextCursor: string | null;
  readonly hasMore: boolean;
  readonly error: unknown;
  readonly queryKey: string;
}

type ViewFilter = "all" | "unread" | "read" | "archived";

const VIEW_FILTERS: readonly { id: ViewFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "unread", label: "Unread" },
  { id: "read", label: "Read" },
  { id: "archived", label: "Archived" },
];

export interface NotificationCenterProps {
  /** Optional deep link target, e.g. from a shell badge. Defaults to no filter. */
  initialCategory?: NotificationCategory | "";
}

export function NotificationCenter({ initialCategory = "" }: NotificationCenterProps = {}) {
  const panelId = useId();
  const [view, setView] = useState<ViewFilter>("all");
  const [category, setCategory] = useState<NotificationCategory | "">(initialCategory);
  const [collection, setCollection] = useState<NotificationCollection>(() => emptyCollection());
  /** Local read/archive overlay. Only "mark read" is persisted by the API. */
  const [readIds, setReadIds] = useState<ReadonlySet<string>>(() => new Set());
  const [archivedIds, setArchivedIds] = useState<ReadonlySet<string>>(() => new Set());
  const [markingId, setMarkingId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const controller = useRef<AbortController | null>(null);
  const generation = useRef(0);

  const load = useCallback(async () => {
    controller.current?.abort();
    const active = new AbortController();
    controller.current = active;
    const current = ++generation.current;
    const queryKey = `${view}:${category}`;
    setCollection((state) =>
      state.items.length > 0 && state.queryKey === queryKey
        ? { ...state, status: "refreshing", error: null }
        : { ...emptyCollection(), status: "loading", queryKey },
    );
    const query: ListNotificationsQuery = { limit: PAGE_SIZE };
    // `unread` is a server-side filter. Read and archived are local views,
    // because the contract exposes no archived read query.
    if (view === "unread") query.unread = true;
    if (category) query.category = category;
    try {
      const page = await listNotifications(query, active.signal);
      if (active.signal.aborted || current !== generation.current) return;
      setCollection({
        status: "ready",
        items: page.items,
        nextCursor: page.next_cursor,
        hasMore: page.has_more,
        error: null,
        queryKey,
      });
    } catch (error) {
      if (active.signal.aborted || current !== generation.current) return;
      setCollection((state) => ({
        ...state,
        status: state.items.length > 0 ? "ready" : "error",
        error,
      }));
    }
  }, [category, view]);

  const loadMore = useCallback(async () => {
    if (!collection.hasMore || !collection.nextCursor || collection.status === "refreshing") return;
    const active = new AbortController();
    controller.current = active;
    const current = ++generation.current;
    setCollection((state) => ({ ...state, status: "refreshing", error: null }));
    try {
      const page = await listNotifications(
        {
          limit: PAGE_SIZE,
          cursor: collection.nextCursor,
          ...(view === "unread" ? { unread: true } : {}),
          ...(category ? { category } : {}),
        },
        active.signal,
      );
      if (active.signal.aborted || current !== generation.current) return;
      setCollection((state) => ({
        ...state,
        status: "ready",
        items: [...state.items, ...page.items],
        nextCursor: page.next_cursor,
        hasMore: page.has_more,
        error: null,
      }));
    } catch (error) {
      if (active.signal.aborted || current !== generation.current) return;
      setCollection((state) => ({ ...state, status: "ready", error }));
    }
  }, [category, collection.hasMore, collection.nextCursor, collection.status, view]);

  useEffect(() => {
    void load();
    return () => {
      controller.current?.abort();
      generation.current += 1;
    };
  }, [load]);

  async function markRead(notification: Notification) {
    setMarkingId(notification.notification_id);
    setActionError(null);
    setNotice(null);
    try {
      const refreshed = await markNotificationRead(notification.notification_id);
      setReadIds((current) => new Set(current).add(refreshed.notification_id));
      setArchivedIds((current) => {
        const next = new Set(current);
        next.delete(refreshed.notification_id);
        return next;
      });
      setCollection((state) => ({
        ...state,
        items: state.items.map((item) =>
          item.notification_id === refreshed.notification_id ? refreshed : item,
        ),
      }));
      setNotice(`Notification marked read. Repeating this is safe: the operation is idempotent.`);
    } catch (error) {
      if (isNonDisclosingNotFound(error)) {
        setActionError(
          new ApiClientError({
            code: "resource_not_found",
            kind: "api",
            status: 404,
            requestId: undefined,
            retryable: false,
          }),
        );
        return;
      }
      setActionError(error);
    } finally {
      setMarkingId(null);
    }
  }

  function toggleArchived(notification: Notification) {
    const archived = archivedIds.has(notification.notification_id);
    setArchivedIds((current) => {
      const next = new Set(current);
      if (next.has(notification.notification_id)) next.delete(notification.notification_id);
      else next.add(notification.notification_id);
      return next;
    });
    setNotice(
      archived
        ? "Restored from the archive view. Only the read mark is stored on the server."
        : "Archived in this view only. The contract has no archive route, so only the read mark is stored.",
    );
  }

  const overlaid = applyReadState(collection.items, readIds, archivedIds);
  const visible = overlaid.filter((notification) => {
    if (view === "read") return notification.state === "read";
    if (view === "archived") return notification.state === "archived";
    if (view === "unread") return notification.state === "unread";
    return true;
  });
  const unreadCount = countUnread(overlaid);

  return (
    <section aria-labelledby={`${panelId}-title`} className="space-y-5">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-xs font-semibold tracking-[0.1em] text-[var(--lumi-blue)]">
            NOTIFICATIONS
          </p>
          <h2
            id={`${panelId}-title`}
            className="mt-2 text-2xl font-semibold tracking-[-0.03em] text-[var(--civic-navy)]"
          >
            Notification center
          </h2>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-[var(--muted-strong)]">
            Durable in-app notifications for the signed-in principal. Recipients are resolved from
            your session and current organization membership, so a notification outside your scope
            simply does not appear.
          </p>
        </div>
        <button
          type="button"
          className={secondaryButtonClass}
          onClick={() => void load()}
          disabled={collection.status === "refreshing"}
        >
          {collection.status === "refreshing" ? "Refreshing…" : "Refresh"}
        </button>
      </header>

      <div className="flex flex-col gap-3 rounded-xl border border-[var(--border)] bg-[var(--panel)] p-4 shadow-[var(--shadow)] lg:flex-row lg:items-end lg:justify-between">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <div role="group" aria-label="Read state filter" className="flex flex-wrap gap-2">
            {VIEW_FILTERS.map((filter) => (
              <button
                key={filter.id}
                type="button"
                aria-pressed={view === filter.id}
                className={view === filter.id ? selectedButtonClass : ghostButtonClass}
                onClick={() => setView(filter.id)}
              >
                {filter.label}
              </button>
            ))}
          </div>
          <label
            className="text-xs font-semibold text-[var(--muted-strong)]"
            htmlFor={`${panelId}-category`}
          >
            Category
            <select
              id={`${panelId}-category`}
              value={category}
              onChange={(event) => {
                const value = event.target.value;
                setCategory(
                  NOTIFICATION_CATEGORIES.includes(value as NotificationCategory)
                    ? (value as NotificationCategory)
                    : "",
                );
              }}
              className={filterControlClass}
            >
              <option value="">All categories</option>
              {NOTIFICATION_CATEGORIES.map((item) => (
                <option key={item} value={item}>
                  {CATEGORY_LABELS[item]}
                </option>
              ))}
            </select>
          </label>
        </div>
        <p className="text-xs text-[var(--muted)]" aria-live="polite">
          {unreadCount} unread of {overlaid.length} loaded
        </p>
      </div>

      {notice ? (
        <p
          role="status"
          className="rounded-lg border border-[var(--success)]/30 bg-[var(--success)]/5 p-3 text-sm text-[var(--success)]"
        >
          {notice}
        </p>
      ) : null}
      {actionError ? (
        <ErrorNotice error={actionError} title="The notification was not updated" />
      ) : null}

      <Surface ariaLabel="Notifications">
        <SurfaceHeader
          title="Notifications"
          description="Ordered by creation time, then notification ID. Security notifications are mandatory and are delivered regardless of informational preferences."
        />
        {collection.status === "loading" || collection.status === "idle" ? (
          <LoadingRows label="Loading notifications…" />
        ) : null}
        {collection.status === "error" && overlaid.length === 0 ? (
          <div className="p-5">
            {isPermissionFailure(collection.error) ? (
              <PermissionState resource="the notification center" />
            ) : (
              <ErrorNotice
                error={collection.error}
                title="Notifications are unavailable"
                onRetry={() => void load()}
              />
            )}
          </div>
        ) : null}
        {collection.status !== "loading" && collection.status !== "idle" && visible.length === 0 ? (
          <EmptyState
            title="Nothing here"
            copy={
              view === "unread"
                ? "No unread notification matches this filter."
                : view === "archived"
                  ? "Nothing is archived. Archiving is a local view state on this page."
                  : "No notification matches this category and read-state filter."
            }
          />
        ) : null}
        {visible.length > 0 ? (
          <ul className="divide-y divide-[var(--border)]">
            {visible.map((notification) => (
              <NotificationItem
                key={notification.notification_id}
                notification={notification}
                marking={markingId === notification.notification_id}
                anyMarking={markingId !== null}
                onMarkRead={() => void markRead(notification)}
                onToggleArchive={() => toggleArchived(notification)}
              />
            ))}
          </ul>
        ) : null}
        {collection.error && overlaid.length > 0 ? (
          <div className="border-t border-[var(--danger)]/20 bg-[var(--danger)]/5 px-5 py-3">
            <ErrorNotice
              error={collection.error}
              title="Refreshing notifications failed"
              onRetry={() => void load()}
            />
          </div>
        ) : null}
        {overlaid.length > 0 ? (
          <PaginationFooter
            loaded={overlaid.length}
            hasMore={collection.hasMore}
            loading={collection.status === "refreshing"}
            onLoadMore={() => void loadMore()}
            noun="notification"
          />
        ) : null}
      </Surface>

      <Surface ariaLabel="Notification behaviour">
        <div className="p-5">
          <Notice tone="info">{PERSISTED_TRANSITION_COPY}</Notice>
          <p className="mt-3 text-xs leading-5 text-[var(--muted-strong)]">
            An unavailable email provider creates a retryable notification-delivery state; it never
            rolls back the business mutation that produced the notification. Slack and Teams
            delivery are reserved for the plugin layer and are not part of this contract.
          </p>
        </div>
      </Surface>
    </section>
  );
}

/**
 * One notification row. Exported so the mandatory marker, the collapsed bounded
 * details, and the two available actions can be asserted without a DOM harness.
 */
export function NotificationItem({
  notification,
  marking,
  anyMarking,
  onMarkRead,
  onToggleArchive,
}: {
  notification: Notification;
  marking: boolean;
  anyMarking: boolean;
  onMarkRead: () => void;
  onToggleArchive: () => void;
}) {
  const summary = notificationSummary(
    notification.body,
    notification.event_type.replaceAll(".", " "),
  );
  const unread = notification.state === "unread";
  return (
    <li className={unread ? "border-l-[3px] border-l-[var(--lumi-blue)] px-5 py-4" : "px-5 py-4"}>
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Pill tone={notificationStateTone(notification)}>
              {notificationStateLabel(notification)}
            </Pill>
            <Pill tone="neutral">{CATEGORY_LABELS[notification.category]}</Pill>
            {unread ? <Pill tone="info">Unread</Pill> : null}
            {notification.state === "archived" ? <Pill tone="neutral">Archived</Pill> : null}
          </div>
          <p className="mt-2 text-sm font-semibold text-[var(--civic-navy)]">{summary.title}</p>
          <p className="mt-1 break-all font-mono text-xs text-[var(--muted)]">
            {notification.event_type} · {notification.event_id}
          </p>
          <p className="mt-1 text-xs text-[var(--muted)]">
            {formatDateTime(notification.created_at)} · {formatRelativeAge(notification.created_at)}
            {notification.read_at ? ` · read ${formatDateTime(notification.read_at)}` : ""}
          </p>
          {notification.mandatory ? (
            <p className="mt-2 text-xs leading-5 text-[var(--danger)]">
              Mandatory security notification. It stays visible and cannot be switched off by
              notification preferences.
            </p>
          ) : null}
          {summary.facts.length > 0 ? (
            <details className="mt-2 rounded-lg border border-[var(--border)]">
              <summary className="min-h-9 cursor-pointer px-3 py-2 text-xs font-semibold text-[var(--muted-strong)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]">
                Notification details — may name your own resources
              </summary>
              <dl className="grid gap-x-6 gap-y-2 border-t border-[var(--border)] px-3 py-3 sm:grid-cols-2">
                {summary.facts.map((fact) => (
                  <div key={fact.key} className="min-w-0">
                    <dt className="font-mono text-xs text-[var(--muted)]">{fact.key}</dt>
                    <dd className="mt-0.5 break-all font-mono text-xs text-[var(--civic-navy)]">
                      {fact.value}
                    </dd>
                  </div>
                ))}
              </dl>
            </details>
          ) : null}
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          <button
            type="button"
            className={ghostButtonClass}
            onClick={onMarkRead}
            disabled={anyMarking || notification.state === "read"}
          >
            {marking ? "Marking…" : notification.state === "read" ? "Read" : "Mark read"}
          </button>
          <button
            type="button"
            className={ghostButtonClass}
            onClick={onToggleArchive}
            aria-pressed={notification.state === "archived"}
          >
            {notification.state === "archived" ? "Unarchive" : "Archive"}
          </button>
        </div>
      </div>
    </li>
  );
}

function emptyCollection(): NotificationCollection {
  return {
    status: "idle",
    items: [],
    nextCursor: null,
    hasMore: false,
    error: null,
    queryKey: "",
  };
}
