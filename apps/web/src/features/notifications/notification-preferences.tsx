/**
 * Notification preferences.
 *
 * Frozen contract: `docs/implementation/gates/P06-CG.md` → "API contract"
 * (`GET/PATCH /me/notification-preferences` and
 * `GET/PATCH /orgs/{org_id}/notification-preferences`) and "Notification
 * channels".
 *
 * Preferences apply to informational notifications only. Mandatory security
 * events are shown as permanently on, and an attempt to opt out of one is
 * refused here with the reason rather than silently dropped — the server would
 * reject the whole write, so hiding the refusal would strand the operator.
 */

import { useCallback, useEffect, useId, useRef, useState } from "react";

import {
  getNotificationPreferences,
  NOTIFICATION_CHANNELS,
  updateNotificationPreference,
  type NotificationChannel,
  type NotificationCategory,
  type NotificationPreference,
  type NotificationPreferenceScope,
} from "./api";
import {
  CATEGORY_LABELS,
  enforcedOptOuts,
  INFORMATIONAL_EVENT_TYPES,
  isMandatorySecurityEvent,
  MANDATORY_SECURITY_COPY,
  MANDATORY_SECURITY_REFUSAL_COPY,
  MANDATORY_SECURITY_RULES,
  notificationCategoryOf,
  validateOptOutList,
  type OptOutRejection,
} from "./event-types";
import { formatDateTime, isPermissionFailure, isVersionConflict } from "./helpers";
import {
  checkboxClass,
  ErrorNotice,
  Notice,
  PermissionState,
  Pill,
  primaryButtonClass,
  secondaryButtonClass,
  Surface,
  SurfaceHeader,
} from "./ui";

type LoadStatus = "idle" | "loading" | "ready" | "error";

export interface NotificationPreferencesProps {
  /**
   * `me` is the personal route and is not scoped to an organization.
   * `org` is the organization-scoped route and requires `orgId`.
   */
  scope: NotificationPreferenceScope;
}

export function NotificationPreferences({ scope }: NotificationPreferencesProps) {
  const panelId = useId();
  const scopeKey = scope.kind === "org" ? `org:${scope.orgId}` : "me";
  const [status, setStatus] = useState<LoadStatus>("idle");
  const [preferences, setPreferences] = useState<NotificationPreference[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [savingChannel, setSavingChannel] = useState<NotificationChannel | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [refusals, setRefusals] = useState<readonly OptOutRejection[]>([]);
  const idempotencyKeys = useRef(new Map<string, string>());
  const controller = useRef<AbortController | null>(null);
  const generation = useRef(0);

  const load = useCallback(async () => {
    controller.current?.abort();
    const active = new AbortController();
    controller.current = active;
    const current = ++generation.current;
    setStatus("loading");
    setError(null);
    try {
      const rows = await getNotificationPreferences(scope, active.signal);
      if (active.signal.aborted || current !== generation.current) return;
      setPreferences(
        rows.map((row) => ({
          ...row,
          disabled_event_types: enforcedOptOuts(row.disabled_event_types),
        })),
      );
      setStatus("ready");
    } catch (requestError) {
      if (active.signal.aborted || current !== generation.current) return;
      setStatus("error");
      setError(requestError);
    }
  }, [scope]);

  useEffect(() => {
    idempotencyKeys.current.clear();
    setNotice(null);
    setActionError(null);
    setRefusals([]);
    void load();
    return () => {
      controller.current?.abort();
      generation.current += 1;
    };
  }, [load, scopeKey]);

  async function save(channel: NotificationChannel, nextDisabled: readonly string[]) {
    const validation = validateOptOutList(nextDisabled);
    if (!validation.ok) {
      setRefusals(validation.rejections);
      setNotice(null);
      return;
    }
    setRefusals([]);
    setSavingChannel(channel);
    setActionError(null);
    setNotice(null);
    const keyName = `${scopeKey}:${channel}`;
    const existing = idempotencyKeys.current.get(keyName) ?? crypto.randomUUID();
    idempotencyKeys.current.set(keyName, existing);
    try {
      const saved = await updateNotificationPreference(
        scope,
        {
          channel,
          version: preferences.find((row) => row.channel === channel)?.version ?? 0,
          disabled_event_types: [...validation.eventTypes],
        },
        existing,
      );
      idempotencyKeys.current.delete(keyName);
      setPreferences((current) => current.map((row) => (row.channel === channel ? saved : row)));
      setNotice(
        saved.disabled_event_types.length === 0
          ? `All informational ${channel === "email" ? "email" : "in-app"} notifications are enabled again.`
          : `${saved.disabled_event_types.length} informational event${
              saved.disabled_event_types.length === 1 ? "" : "s"
            } opted out of ${channel === "email" ? "email" : "in-app"}.`,
      );
    } catch (requestError) {
      if (isVersionConflict(requestError)) {
        idempotencyKeys.current.delete(keyName);
        void load();
      }
      setActionError(requestError);
    } finally {
      setSavingChannel(null);
    }
  }

  const title =
    scope.kind === "org"
      ? "Organization notification preferences"
      : "Your notification preferences";
  const description =
    scope.kind === "org"
      ? "Informational event types for this organization, per delivery channel. Mandatory security events are always delivered."
      : "Informational event types for your account, per delivery channel. Mandatory security events are always delivered.";

  return (
    <section aria-labelledby={`${panelId}-title`} className="space-y-5">
      <header>
        <p className="text-xs font-semibold tracking-[0.1em] text-[var(--lumi-blue)]">
          PREFERENCES
        </p>
        <h2
          id={`${panelId}-title`}
          className="mt-2 text-2xl font-semibold tracking-[-0.03em] text-[var(--civic-navy)]"
        >
          {title}
        </h2>
        <p className="mt-1 max-w-2xl text-sm leading-6 text-[var(--muted-strong)]">{description}</p>
      </header>

      {notice ? (
        <p
          role="status"
          className="rounded-lg border border-[var(--success)]/30 bg-[var(--success)]/5 p-3 text-sm text-[var(--success)]"
        >
          {notice}
        </p>
      ) : null}
      {actionError ? <ErrorNotice error={actionError} title="Preferences were not saved" /> : null}
      {isVersionConflict(actionError) ? (
        <Notice tone="warning">
          Another change landed first. The preferences were reloaded — review them and save again.
        </Notice>
      ) : null}
      {refusals.length > 0 ? (
        <div
          role="alert"
          className="rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/5 p-4 text-sm text-[var(--danger)]"
        >
          <p className="font-semibold">That opt-out was refused</p>
          <ul className="mt-2 space-y-1">
            {refusals.map((rejection) => (
              <li key={rejection.eventType} className="leading-5">
                <span className="font-mono">{rejection.eventType}</span> — {rejection.message}
              </li>
            ))}
          </ul>
          <p className="mt-2 leading-5">{MANDATORY_SECURITY_REFUSAL_COPY}</p>
        </div>
      ) : null}

      <Notice tone="warning">
        <span className="font-semibold">Mandatory security events.</span> {MANDATORY_SECURITY_COPY}
      </Notice>

      {status === "loading" || status === "idle" ? (
        <Surface ariaLabel="Loading notification preferences">
          <div className="p-5" role="status" aria-live="polite" aria-busy="true">
            <p className="text-sm text-[var(--muted-strong)]">Loading notification preferences…</p>
            <div
              className="mt-4 h-32 animate-pulse rounded-lg bg-[var(--panel-hover)]"
              aria-hidden="true"
            />
          </div>
        </Surface>
      ) : null}

      {status === "error" ? (
        isPermissionFailure(error) ? (
          <PermissionState resource="notification preferences" />
        ) : (
          <ErrorNotice
            error={error}
            title="Preferences are unavailable"
            onRetry={() => void load()}
          />
        )
      ) : null}

      {status === "ready"
        ? NOTIFICATION_CHANNELS.map((channel) => {
            const row = preferences.find((item) => item.channel === channel);
            return (
              <ChannelCard
                key={channel}
                channel={channel}
                preference={row ?? null}
                saving={savingChannel === channel}
                disabled={savingChannel !== null}
                onSave={(next) => void save(channel, next)}
              />
            );
          })
        : null}

      <MandatorySecurityPanel />
    </section>
  );
}

/**
 * The mandatory families, stated as families rather than as an enumerated list.
 * Exported so the rule can be rendered and asserted independently of the load
 * state of the preference rows.
 */
export function MandatorySecurityPanel() {
  return (
    <Surface ariaLabel="Mandatory security event families">
      <SurfaceHeader
        title="Mandatory security event families"
        description="These families are not optional. They are delivered to the owning organization's security recipients regardless of informational preferences, and the API refuses an opt-out that names one."
      />
      <ul className="divide-y divide-[var(--border)]">
        {MANDATORY_SECURITY_RULES.map((rule) => (
          <li
            key={`${rule.kind}:${rule.value}`}
            className="flex flex-wrap items-center gap-2 px-5 py-3"
          >
            <Pill tone="danger">Mandatory</Pill>
            <span className="break-all font-mono text-xs text-[var(--civic-navy)]">
              {rule.kind === "prefix" ? `${rule.value}*` : `${rule.value}.*`}
            </span>
            <span className="text-xs text-[var(--muted-strong)]">{rule.label}</span>
          </li>
        ))}
      </ul>
      <div className="border-t border-[var(--border)] bg-[var(--panel-hover)] px-5 py-3 text-xs leading-5 text-[var(--muted-strong)]">
        The check is by family, not by an enumerated list, so a new security event in one of these
        families is mandatory from the moment it is registered — the UI cannot be used to opt out of
        something it has not seen.
      </div>
    </Surface>
  );
}

function ChannelCard({
  channel,
  preference,
  saving,
  disabled,
  onSave,
}: {
  channel: NotificationChannel;
  preference: NotificationPreference | null;
  saving: boolean;
  disabled: boolean;
  onSave: (next: readonly string[]) => void;
}) {
  const [draft, setDraft] = useState<readonly string[]>(
    () => preference?.disabled_event_types ?? [],
  );
  const [dirty, setDirty] = useState(false);
  const groupId = useId();

  useEffect(() => {
    setDraft(preference?.disabled_event_types ?? []);
    setDirty(false);
  }, [preference]);

  const label = channel === "email" ? "Email" : "In-app";
  const draftSet = new Set(draft);
  const disabledCount = draft.length;
  const allSelected = draft.length === INFORMATIONAL_EVENT_TYPES.length;

  function toggle(eventType: string) {
    setDirty(true);
    setDraft((current) =>
      current.includes(eventType)
        ? current.filter((value) => value !== eventType)
        : [...current, eventType],
    );
  }

  const grouped = groupByCategory(INFORMATIONAL_EVENT_TYPES);

  return (
    <Surface ariaLabel={`${label} notification preferences`}>
      <SurfaceHeader
        title={`${label} channel`}
        description={
          channel === "email"
            ? "Email uses the existing Worker email binding behind a small adapter. An unavailable provider creates a retryable notification-delivery state and never rolls back the business mutation."
            : "In-app notifications are durable projections. They stay visible for 30 days and are exported only to their owner."
        }
        action={
          <Pill tone={disabledCount === 0 ? "success" : "neutral"}>
            {disabledCount === 0 ? "All enabled" : `${disabledCount} opted out`}
          </Pill>
        }
      />
      <div className="flex flex-wrap items-center gap-3 border-b border-[var(--border)] bg-[var(--panel-hover)] px-5 py-3">
        <button
          type="button"
          className={secondaryButtonClass}
          onClick={() => {
            setDirty(true);
            setDraft(allSelected ? [] : [...INFORMATIONAL_EVENT_TYPES]);
          }}
          disabled={disabled}
        >
          {allSelected ? "Re-enable all" : `Opt out of all ${INFORMATIONAL_EVENT_TYPES.length}`}
        </button>
        <span className="text-xs text-[var(--muted)]">
          Preference version {preference?.version ?? 0}
          {preference?.updated_at ? ` · updated ${formatDateTime(preference.updated_at)}` : ""}
        </span>
      </div>

      <div className="space-y-4 p-5">
        {grouped.map(([category, eventTypes]) => (
          <fieldset key={category} className="rounded-lg border border-[var(--border)] p-4">
            <legend className="px-1 text-sm font-semibold text-[var(--civic-navy)]">
              {CATEGORY_LABELS[category]}
            </legend>
            <ul className="space-y-2">
              {eventTypes.map((eventType) => {
                const mandatory = isMandatorySecurityEvent(eventType);
                const inputId = `${groupId}-${eventType.replaceAll(".", "-")}`;
                return (
                  <li key={eventType}>
                    <label
                      htmlFor={inputId}
                      className="flex min-h-9 items-start gap-2 text-sm text-[var(--civic-navy)]"
                    >
                      <input
                        id={inputId}
                        type="checkbox"
                        className={checkboxClass}
                        checked={!draftSet.has(eventType)}
                        disabled={disabled || mandatory}
                        onChange={(event) => {
                          if (event.target.checked) {
                            setDirty(true);
                            setDraft((current) => current.filter((value) => value !== eventType));
                            return;
                          }
                          toggle(eventType);
                        }}
                      />
                      <span className="break-all font-mono text-xs leading-5">{eventType}</span>
                      {mandatory ? <Pill tone="danger">Mandatory</Pill> : null}
                    </label>
                  </li>
                );
              })}
            </ul>
          </fieldset>
        ))}

        <Notice tone="info">
          An unchecked event type is added to the opt-out list for this channel only. A mandatory
          security event can never appear in that list.
        </Notice>

        <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <button
            type="button"
            className={secondaryButtonClass}
            onClick={() => {
              setDraft(preference?.disabled_event_types ?? []);
              setDirty(false);
            }}
            disabled={disabled || !dirty}
          >
            Discard changes
          </button>
          <button
            type="button"
            className={primaryButtonClass}
            onClick={() => onSave(draft)}
            disabled={disabled || !dirty}
          >
            {saving ? "Saving…" : "Save channel preferences"}
          </button>
        </div>
        {preference === null ? (
          <p className="text-xs leading-5 text-[var(--muted)]">
            No preference row exists for this channel yet. Saving creates it at version 1.
          </p>
        ) : null}
      </div>
    </Surface>
  );
}

function groupByCategory(eventTypes: readonly string[]): [NotificationCategory, string[]][] {
  const groups = new Map<NotificationCategory, string[]>();
  for (const eventType of eventTypes) {
    const category = notificationCategoryOf(eventType);
    const existing = groups.get(category);
    if (existing) existing.push(eventType);
    else groups.set(category, [eventType]);
  }
  return [...groups.entries()].map(([category, values]) => [category, [...values].sort()]);
}
