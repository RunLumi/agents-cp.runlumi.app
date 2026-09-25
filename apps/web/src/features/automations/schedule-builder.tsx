// The schedule builder for the frozen `ScheduleRule` union.
//
// The builder holds *string* draft state, because an operator's typing state is
// not yet a typed rule. Every rule is validated against the same bounds the
// server enforces and the same stable reason codes, then handed to the panel as
// a canonical wire payload. The server still stores the normalized expression,
// the resolved zone, and the schedule cursor; nothing here computes the next run.

import { useId } from "react";

import type { MissedPolicy, OverlapPolicy, ScheduleRequestPayload } from "./api";
import {
  DST_POLICY_OPTIONS,
  DOM_DOW_MODE_OPTIONS,
  INTERVAL_UNIT_OPTIONS,
  MISSED_POLICY_OPTIONS,
  OVERLAP_POLICY_OPTIONS,
  SCHEDULE_KIND_OPTIONS,
  formatInstant,
  formatInstantUtc,
  humanizeToken,
  localTimezone,
  missedPolicyDetail,
  overlapPolicyDetail,
  parseLocalInstant,
  scheduleKindLabel,
  type ScheduleDraft,
  type ScheduleIssue,
  type SchedulePolicyOptions,
} from "./schedule-helpers";
import { Field, inputClass } from "./ui";

export interface ScheduleBuilderProps {
  draft: ScheduleDraft;
  onChange: (draft: ScheduleDraft) => void;
  issues: readonly ScheduleIssue[];
  policyOptions?: SchedulePolicyOptions;
}

export function issueFor(issues: readonly ScheduleIssue[], field: string): string | undefined {
  return issues.find((issue) => issue.field === field)?.message;
}

export function ScheduleBuilder({ draft, onChange, issues, policyOptions }: ScheduleBuilderProps) {
  const id = useId();
  const set = <K extends keyof ScheduleDraft>(key: K, value: ScheduleDraft[K]): void => {
    onChange({ ...draft, [key]: value });
  };

  const overlapOptions = policyOptions?.allowedOverlapPolicies
    ? OVERLAP_POLICY_OPTIONS.filter((option) =>
        policyOptions.allowedOverlapPolicies?.includes(option.value),
      )
    : OVERLAP_POLICY_OPTIONS;
  const missedOptions = policyOptions?.allowedMissedPolicies
    ? MISSED_POLICY_OPTIONS.filter((option) =>
        policyOptions.allowedMissedPolicies?.includes(option.value),
      )
    : MISSED_POLICY_OPTIONS;

  const scheduledInstant = draft.kind === "one_time" ? parseLocalInstant(draft.scheduledAt) : null;
  const anchorInstant = draft.kind === "interval" ? parseLocalInstant(draft.anchorAt) : null;

  return (
    <div className="space-y-5">
      <fieldset>
        <legend className="text-xs font-semibold text-[var(--muted-strong)]">Schedule class</legend>
        <p className="mt-1 text-xs leading-5 text-[var(--muted)]">
          A manual automation has no clock schedule. Only an authorized run-now creates an
          occurrence for it.
        </p>
        <div className="mt-2 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {SCHEDULE_KIND_OPTIONS.map((option) => {
            const active = draft.kind === option.value;
            return (
              <label
                key={option.value}
                className={[
                  "flex min-h-11 cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 text-sm outline-none transition",
                  "focus-within:ring-2 focus-within:ring-[var(--ring)] focus-within:ring-offset-2",
                  active
                    ? "border-[var(--lumi-blue)] bg-[var(--lumi-blue-soft)] font-semibold text-[var(--lumi-blue)]"
                    : "border-[var(--border)] bg-[var(--panel)] text-[var(--muted-strong)] hover:bg-[var(--panel-hover)]",
                ].join(" ")}
              >
                <input
                  type="radio"
                  name={`${id}-kind`}
                  value={option.value}
                  checked={active}
                  onChange={() => set("kind", option.value)}
                  className="h-4 w-4 accent-[var(--lumi-blue)]"
                />
                {option.label}
              </label>
            );
          })}
        </div>
      </fieldset>

      {draft.kind === "one_time" ? (
        <div className="grid gap-4 sm:grid-cols-2">
          <Field
            label="Runs once at"
            id={`${id}-scheduled-at`}
            hint={`Entered in this browser's zone (${localTimezone()}) and stored as a UTC instant.`}
            error={issueFor(issues, "scheduledAt")}
          >
            {({ id: controlId, describedBy, invalid }) => (
              <input
                id={controlId}
                type="datetime-local"
                value={draft.scheduledAt}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                onChange={(event) => set("scheduledAt", event.target.value)}
                className={inputClass}
              />
            )}
          </Field>
          <InstantPreview instant={scheduledInstant} label="Stored instant" />
        </div>
      ) : null}

      {draft.kind === "cron" ? (
        <div className="grid gap-4 sm:grid-cols-2">
          <Field
            label="Cron expression"
            id={`${id}-expression`}
            hint="Five fields: minute, hour, day of month, month, day of week. Ranges, lists, and */step are supported, as are month and weekday names."
            error={issueFor(issues, "expression")}
          >
            {({ id: controlId, describedBy, invalid }) => (
              <input
                id={controlId}
                type="text"
                inputMode="text"
                spellCheck={false}
                autoComplete="off"
                value={draft.expression}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                onChange={(event) => set("expression", event.target.value)}
                className={`${inputClass} font-mono`}
              />
            )}
          </Field>
          <Field
            label="Timezone"
            id={`${id}-timezone`}
            hint="IANA name. The server stores the normalized expression and re-resolves every instant."
            error={issueFor(issues, "timezone")}
          >
            {({ id: controlId, describedBy, invalid }) => (
              <input
                id={controlId}
                type="text"
                autoComplete="off"
                spellCheck={false}
                value={draft.timezone}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                onChange={(event) => set("timezone", event.target.value)}
                className={`${inputClass} font-mono`}
              />
            )}
          </Field>
          <Field
            label="Day-of-month and day-of-week"
            id={`${id}-dom-dow`}
            hint="Standard cron OR-ed the two fields unless both are restricted. Choose AND to require both."
            error={issueFor(issues, "domDowMode")}
          >
            {({ id: controlId, describedBy, invalid }) => (
              <select
                id={controlId}
                value={draft.domDowMode}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                onChange={(event) =>
                  set("domDowMode", event.target.value as ScheduleDraft["domDowMode"])
                }
                className={inputClass}
              >
                {DOM_DOW_MODE_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            )}
          </Field>
          <Field
            label="Daylight saving behavior"
            id={`${id}-dst`}
            hint="A local time that does not exist is always skipped. This policy decides what happens when a local time happens twice."
            error={issueFor(issues, "dstPolicy")}
          >
            {({ id: controlId, describedBy, invalid }) => (
              <select
                id={controlId}
                value={draft.dstPolicy}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                onChange={(event) =>
                  set("dstPolicy", event.target.value as ScheduleDraft["dstPolicy"])
                }
                className={inputClass}
              >
                {DST_POLICY_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            )}
          </Field>
        </div>
      ) : null}

      {draft.kind === "interval" ? (
        <div className="grid gap-4 sm:grid-cols-2">
          <Field
            label="Repeat every"
            id={`${id}-every`}
            hint="A whole number from 1 to 200."
            error={issueFor(issues, "every")}
          >
            {({ id: controlId, describedBy, invalid }) => (
              <input
                id={controlId}
                type="number"
                inputMode="numeric"
                min={1}
                max={200}
                step={1}
                value={draft.every}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                onChange={(event) => set("every", event.target.value)}
                className={inputClass}
              />
            )}
          </Field>
          <Field
            label="Unit"
            id={`${id}-unit`}
            hint="Minutes and hours step by elapsed time. Days, weeks, months, and years step by the local calendar, and an invalid calendar date is skipped rather than moved."
            error={issueFor(issues, "unit")}
          >
            {({ id: controlId, describedBy, invalid }) => (
              <select
                id={controlId}
                value={draft.unit}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                onChange={(event) => set("unit", event.target.value as ScheduleDraft["unit"])}
                className={inputClass}
              >
                {INTERVAL_UNIT_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            )}
          </Field>
          <Field
            label="Anchor"
            id={`${id}-anchor`}
            hint={`Entered in this browser's zone (${localTimezone()}) and stored as a UTC instant.`}
            error={issueFor(issues, "anchorAt")}
          >
            {({ id: controlId, describedBy, invalid }) => (
              <input
                id={controlId}
                type="datetime-local"
                value={draft.anchorAt}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                onChange={(event) => set("anchorAt", event.target.value)}
                className={inputClass}
              />
            )}
          </Field>
          <InstantPreview instant={anchorInstant} label="Stored anchor" />
          <Field
            label="Weekdays"
            id={`${id}-by-weekday`}
            hint="Optional. Comma-separated 0 (Sunday) to 6."
            error={issueFor(issues, "byWeekday")}
          >
            {({ id: controlId, describedBy, invalid }) => (
              <input
                id={controlId}
                type="text"
                inputMode="numeric"
                autoComplete="off"
                value={draft.byWeekday}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                onChange={(event) => set("byWeekday", event.target.value)}
                className={`${inputClass} font-mono`}
              />
            )}
          </Field>
          <Field
            label="Days of month"
            id={`${id}-by-monthday`}
            hint="Optional. Comma-separated 1 to 31."
            error={issueFor(issues, "byMonthday")}
          >
            {({ id: controlId, describedBy, invalid }) => (
              <input
                id={controlId}
                type="text"
                inputMode="numeric"
                autoComplete="off"
                value={draft.byMonthday}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                onChange={(event) => set("byMonthday", event.target.value)}
                className={`${inputClass} font-mono`}
              />
            )}
          </Field>
          <Field
            label="Months"
            id={`${id}-by-month`}
            hint="Optional. Comma-separated 1 to 12."
            error={issueFor(issues, "byMonth")}
          >
            {({ id: controlId, describedBy, invalid }) => (
              <input
                id={controlId}
                type="text"
                inputMode="numeric"
                autoComplete="off"
                value={draft.byMonth}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                onChange={(event) => set("byMonth", event.target.value)}
                className={`${inputClass} font-mono`}
              />
            )}
          </Field>
        </div>
      ) : null}

      <fieldset className="grid gap-4 border-t border-[var(--border)] pt-4 sm:grid-cols-2">
        <legend className="text-xs font-semibold text-[var(--muted-strong)]">
          Concurrency and missed runs
        </legend>
        <Field
          label="When the previous occurrence is still running"
          id={`${id}-overlap`}
          hint={overlapPolicyDetail(draft.overlapPolicy)}
          error={issueFor(issues, "overlapPolicy")}
        >
          {({ id: controlId, describedBy, invalid }) => (
            <select
              id={controlId}
              value={draft.overlapPolicy}
              aria-describedby={describedBy}
              aria-invalid={invalid}
              onChange={(event) => set("overlapPolicy", event.target.value as OverlapPolicy)}
              className={inputClass}
            >
              {overlapOptions.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field
          label="When a slot is missed"
          id={`${id}-missed`}
          hint={missedPolicyDetail(draft.missedPolicy, catchUpValue(draft))}
          error={issueFor(issues, "missedPolicy")}
        >
          {({ id: controlId, describedBy, invalid }) => (
            <select
              id={controlId}
              value={draft.missedPolicy}
              aria-describedby={describedBy}
              aria-invalid={invalid}
              onChange={(event) => set("missedPolicy", event.target.value as MissedPolicy)}
              className={inputClass}
            >
              {missedOptions.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          )}
        </Field>
        {draft.missedPolicy === "catch_up" ? (
          <Field
            label="Catch-up limit"
            id={`${id}-catch-up`}
            hint="How many missed occurrences recovery may create, newest first. The server inspects at most seven days of missed history."
            error={issueFor(issues, "catchUpLimit")}
          >
            {({ id: controlId, describedBy, invalid }) => (
              <input
                id={controlId}
                type="number"
                inputMode="numeric"
                min={1}
                max={20}
                step={1}
                value={draft.catchUpLimit}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                onChange={(event) => set("catchUpLimit", event.target.value)}
                className={inputClass}
              />
            )}
          </Field>
        ) : null}
      </fieldset>

      <p className="border-t border-[var(--border)] pt-3 text-xs leading-5 text-[var(--muted)]">
        {scheduleKindLabel(draft.kind)} schedules are stored as canonical rules. Editing a schedule
        creates a new revision, so each revision keeps its own occurrence history.
      </p>
    </div>
  );
}

function catchUpValue(draft: ScheduleDraft): number | null {
  const parsed = Number(draft.catchUpLimit);
  return Number.isInteger(parsed) ? parsed : null;
}

function InstantPreview({ instant, label }: { instant: string | null; label: string }) {
  return (
    <div className="min-w-0">
      <p className="text-xs font-semibold text-[var(--muted-strong)]">{label}</p>
      <p className="mt-1 text-xs leading-5 text-[var(--muted)]">
        The server stores a UTC instant. Occurrence identity comes from that instant, not from the
        displayed expression.
      </p>
      <p className="mt-1.5 min-h-10 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 py-2 font-mono text-xs text-[var(--civic-navy)]">
        {instant ? formatInstantUtc(instant) : "Enter a local date and time"}
      </p>
      <p className="mt-1 text-xs text-[var(--muted)]">
        {instant ? `Shown here as ${formatInstant(instant)}.` : null}
      </p>
    </div>
  );
}

/** A short, human summary of a payload that passed validation. */
export function describePayload(payload: ScheduleRequestPayload): string {
  if (payload.kind === "manual") return "Manual only · run now creates one occurrence";
  if (payload.kind === "one_time") return `One time · ${formatInstantUtc(payload.scheduled_at)}`;
  if (payload.kind === "cron")
    return `${payload.expression} · ${payload.timezone} · ${humanizeToken(payload.dom_dow_mode ?? "or")} · ${humanizeToken(
      payload.dst_policy ?? "skip_duplicate",
    )}`;
  return `Every ${payload.every} ${humanizeToken(payload.unit ?? "minutes")} · ${payload.timezone} · anchored ${formatInstantUtc(payload.anchor_at)}`;
}
