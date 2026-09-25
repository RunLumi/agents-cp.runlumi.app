/**
 * Event-type subscription picker.
 *
 * A subscription is an explicit finite set of exact frozen event names. This
 * picker makes that rule visible and enforces it in the client: wildcards,
 * family prefixes, and unregistered names are rejected with a reason before a
 * request is made, and the delivery/endpoint/notification-delivery families are
 * shown as never fanned out so an operator can see why they cannot be chosen.
 *
 * Values already stored on the endpoint that are outside the P06 list — a
 * P01/P05 frozen name the server also accepts — are listed read-only and passed
 * through unchanged, so editing an endpoint never silently drops a live
 * subscription.
 */

import { useId, useMemo, useState } from "react";

import {
  filterFamilies,
  isFanoutExcluded,
  isP06EventType,
  payloadFieldsFor,
  sortEventTypes,
  validateExactEventName,
  EVENT_FAMILY_PAYLOAD_FIELDS,
  MAX_SUBSCRIPTIONS,
  SUBSCRIPTION_RULE_COPY,
  type EventFamily,
} from "./event-types";
import { checkboxClass, inputClass, Notice, Pill, secondaryButtonClass } from "./ui";

export function EventTypePicker({
  selected,
  preservedExternal,
  onChange,
  disabled = false,
}: {
  selected: readonly string[];
  /** Stored names outside the frozen P06 list; preserved, never editable here. */
  preservedExternal: readonly string[];
  onChange: (next: string[]) => void;
  disabled?: boolean;
}) {
  const groupId = useId();
  const [query, setQuery] = useState("");
  const [manualValue, setManualValue] = useState("");
  const [manualError, setManualError] = useState<string | null>(null);
  const selectedSet = useMemo(() => new Set(selected), [selected]);
  const families = useMemo(() => filterFamilies(query), [query]);
  const requiredFields = EVENT_FAMILY_PAYLOAD_FIELDS;

  function toggle(eventType: string, checked: boolean) {
    onChange(
      checked
        ? sortEventTypes([...selected, eventType])
        : sortEventTypes(selected.filter((value) => value !== eventType)),
    );
  }

  function toggleFamily(family: EventFamily, checked: boolean) {
    const selectable = family.eventTypes.filter((eventType) => !isFanoutExcluded(eventType));
    onChange(
      checked
        ? sortEventTypes([...selected, ...selectable])
        : sortEventTypes(selected.filter((value) => !selectable.includes(value))),
    );
  }

  function addManual() {
    const rejection = validateExactEventName(manualValue);
    if (rejection) {
      setManualError(rejection.message);
      return;
    }
    const value = manualValue.trim();
    setManualError(null);
    setManualValue("");
    if (!selectedSet.has(value)) onChange(sortEventTypes([...selected, value]));
  }

  const overLimit = selected.length > MAX_SUBSCRIPTIONS;

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-[var(--lumi-blue)]/30 bg-[var(--lumi-blue-soft)] p-3">
        <p className="text-xs font-semibold tracking-[0.08em] text-[var(--lumi-blue)]">
          EXACT NAMES ONLY
        </p>
        <p className="mt-1 text-sm leading-5 text-[var(--civic-navy)]">{SUBSCRIPTION_RULE_COPY}</p>
      </div>

      <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
        <label className="block min-w-0 flex-1 text-xs font-semibold text-[var(--muted-strong)]">
          Filter event names
          <input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            disabled={disabled}
            placeholder="occurrence, billing, export…"
            className={inputClass}
          />
        </label>
        <p className="text-xs tabular-nums text-[var(--muted)]" aria-live="polite">
          {selected.length} of {MAX_SUBSCRIPTIONS} selected
        </p>
      </div>

      {overLimit ? (
        <Notice tone="danger">
          Select at most {MAX_SUBSCRIPTIONS} exact event names. Remove{" "}
          {selected.length - MAX_SUBSCRIPTIONS} before saving.
        </Notice>
      ) : null}

      {selected.length === 0 ? (
        <Notice tone="warning">
          An endpoint with no subscribed event names receives nothing. Select at least one exact
          name before saving.
        </Notice>
      ) : null}

      <div className="space-y-4">
        {families.map((family) => {
          const selectable = family.eventTypes.filter((eventType) => !isFanoutExcluded(eventType));
          const chosen = selectable.filter((eventType) => selectedSet.has(eventType));
          const allChosen = selectable.length > 0 && chosen.length === selectable.length;
          const fieldList = requiredFields[family.id];
          return (
            <fieldset
              key={family.id}
              className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-4"
            >
              <legend className="px-1 text-sm font-semibold text-[var(--civic-navy)]">
                {family.label}
              </legend>
              <p className="text-xs leading-5 text-[var(--muted-strong)]">{family.description}</p>
              {fieldList && fieldList.length > 0 ? (
                <p className="mt-1 text-xs text-[var(--muted)]">
                  Required payload fields: <span className="font-mono">{fieldList.join(", ")}</span>
                </p>
              ) : null}
              {selectable.length > 1 ? (
                <label className="mt-3 flex min-h-9 items-center gap-2 text-xs font-semibold text-[var(--muted-strong)]">
                  <input
                    type="checkbox"
                    className={checkboxClass}
                    checked={allChosen}
                    disabled={disabled}
                    onChange={(event) => toggleFamily(family, event.target.checked)}
                  />
                  {allChosen ? "Clear this family" : `Select all ${selectable.length} exact names`}
                </label>
              ) : null}
              <ul className="mt-3 space-y-2">
                {family.eventTypes.map((eventType) => {
                  const excluded = isFanoutExcluded(eventType);
                  const checked = selectedSet.has(eventType);
                  const inputId = `${groupId}-${eventType.replaceAll(".", "-")}`;
                  return (
                    <li key={eventType} className="flex flex-col gap-1">
                      <label
                        htmlFor={inputId}
                        className={[
                          "flex min-h-9 items-start gap-2 text-sm",
                          excluded
                            ? "text-[var(--muted)]"
                            : "cursor-pointer text-[var(--civic-navy)]",
                        ].join(" ")}
                      >
                        <input
                          id={inputId}
                          type="checkbox"
                          className={checkboxClass}
                          checked={checked}
                          disabled={disabled || excluded}
                          onChange={(event) => toggle(eventType, event.target.checked)}
                        />
                        <span className="break-all font-mono text-xs leading-5">{eventType}</span>
                        {excluded ? (
                          <Pill tone="neutral">Never fanned out</Pill>
                        ) : payloadFieldsFor(eventType).length === 0 ? (
                          <Pill tone="neutral">Metadata only</Pill>
                        ) : null}
                      </label>
                      {excluded ? (
                        <p className="pl-6 text-xs leading-5 text-[var(--muted)]">
                          {eventType === "webhook.test.v1"
                            ? "A test delivery is sent only to the endpoint you name, and is not subscribable."
                            : "Delivery, endpoint, and notification-delivery events are never fanned out to an endpoint, so this name cannot be subscribed."}
                        </p>
                      ) : null}
                    </li>
                  );
                })}
              </ul>
            </fieldset>
          );
        })}
      </div>

      <div className="rounded-lg border border-[var(--border)] p-4">
        <label className="block text-xs font-semibold text-[var(--muted-strong)]">
          Add an exact event name
          <input
            type="text"
            value={manualValue}
            onChange={(event) => {
              setManualValue(event.target.value);
              setManualError(null);
            }}
            disabled={disabled}
            placeholder="automation.occurrence.completed.v1"
            aria-describedby={`${groupId}-manual-help`}
            aria-invalid={manualError ? true : undefined}
            className={`${inputClass} font-mono`}
          />
        </label>
        <p id={`${groupId}-manual-help`} className="mt-1 text-xs leading-5 text-[var(--muted)]">
          A wildcard, a family such as <code className="font-mono">automation.occurrence</code>, or
          an unregistered name is rejected here with a reason.
        </p>
        {manualError ? (
          <p role="alert" className="mt-2 text-xs font-semibold text-[var(--danger)]">
            {manualError}
          </p>
        ) : null}
        <button
          type="button"
          className={`${secondaryButtonClass} mt-3`}
          onClick={addManual}
          disabled={disabled || manualValue.trim().length === 0}
        >
          Add exact name
        </button>
      </div>

      {preservedExternal.length > 0 ? (
        <div className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-4">
          <p className="text-sm font-semibold text-[var(--civic-navy)]">
            Preserved subscriptions outside the P06 list
          </p>
          <p className="mt-1 text-xs leading-5 text-[var(--muted-strong)]">
            These exact names are already stored on this endpoint and are not part of the P06 frozen
            list. They are sent back unchanged. The server remains the authority on whether each
            name is still accepted.
          </p>
          <ul className="mt-2 space-y-1">
            {preservedExternal.map((eventType) => (
              <li key={eventType} className="flex items-center gap-2">
                <span className="break-all font-mono text-xs text-[var(--muted-strong)]">
                  {eventType}
                </span>
                <Pill tone="neutral">
                  {isP06EventType(eventType) ? "P06" : "Other frozen name"}
                </Pill>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
