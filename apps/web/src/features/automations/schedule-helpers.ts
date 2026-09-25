// Schedule authoring, validation, and description for the frozen `ScheduleRule`
// union (`p06-cg-v1`).
//
// This module mirrors the server's bounds so an operator sees a stable reason
// code before sending a request. It is a *mirror*, never an authority: every
// bound is re-validated server-side, and the server's canonical rule (its
// normalized cron text, resolved zone, and cursor) replaces whatever the browser
// submitted.

import {
  DEFAULT_DOM_DOW_MODE,
  DEFAULT_DST_POLICY,
  DEFAULT_MISSED_POLICY,
  DEFAULT_OVERLAP_POLICY,
  INTERVAL_UNITS,
  MAX_CATCH_UP_LIMIT,
  MAX_CRON_EXPRESSION_BYTES,
  MAX_INTERVAL_EVERY,
  MAX_SELECTOR_VALUES,
  MAX_TIMEZONE_BYTES,
  MAX_TIMEZONE_SEGMENTS,
  MAX_UTC_OFFSET_SECONDS,
  MIN_CATCH_UP_LIMIT,
  MIN_INTERVAL_EVERY,
  type DomDowMode,
  type DstPolicy,
  type IntervalUnit,
  type MissedPolicy,
  type OverlapPolicy,
  type ResolvedZone,
  type ScheduleKind,
  type ScheduleRequestPayload,
  type ScheduleRule,
  type ZoneOffset,
} from "./api";

/** Stable reason codes the browser can produce, all from the frozen list. */
export type ScheduleReasonCode =
  | "schedule_invalid"
  | "schedule_timezone_invalid"
  | "schedule_interval_invalid"
  | "automation_overlap_policy"
  | "automation_missed_schedule_limit"
  | "off_peak_not_allowed"
  | "version_conflict";

export interface ScheduleIssue {
  /** The draft field the issue belongs to, used to bind `aria-describedby`. */
  field: string;
  code: ScheduleReasonCode;
  message: string;
}

export interface ScheduleDraft {
  kind: ScheduleKind;
  /** `datetime-local` input value for a one-time instant (browser local zone). */
  scheduledAt: string;
  expression: string;
  timezone: string;
  domDowMode: DomDowMode;
  dstPolicy: DstPolicy;
  every: string;
  unit: IntervalUnit;
  /** `datetime-local` input value for an interval anchor (browser local zone). */
  anchorAt: string;
  byWeekday: string;
  byMonthday: string;
  byMonth: string;
  overlapPolicy: OverlapPolicy;
  missedPolicy: MissedPolicy;
  catchUpLimit: string;
}

export function createScheduleDraft(): ScheduleDraft {
  return {
    kind: "cron",
    scheduledAt: "",
    expression: "0 9 * * 1-5",
    timezone: localTimezone(),
    domDowMode: DEFAULT_DOM_DOW_MODE,
    dstPolicy: DEFAULT_DST_POLICY,
    every: "15",
    unit: "minutes",
    anchorAt: "",
    byWeekday: "",
    byMonthday: "",
    byMonth: "",
    overlapPolicy: DEFAULT_OVERLAP_POLICY,
    missedPolicy: DEFAULT_MISSED_POLICY,
    catchUpLimit: "1",
  };
}

export interface SchedulePolicyOptions {
  allowedOverlapPolicies?: readonly OverlapPolicy[];
  allowedMissedPolicies?: readonly MissedPolicy[];
}

export interface ScheduleBuildOptions extends SchedulePolicyOptions {
  /** Injected in tests so the resolved zone table is deterministic. */
  nowMs?: number;
  /**
   * Whether to attach the client-resolved zone table. Resolving a zone costs
   * one `Intl` formatter per sample, so the live form preview leaves it off and
   * only the submitted request carries it.
   */
  includeZone?: boolean;
}

export type ScheduleBuildResult =
  | { ok: true; payload: ScheduleRequestPayload; issues: [] }
  | { ok: false; issues: ScheduleIssue[] };

/**
 * Validate a draft and, when it is complete, build the wire payload.
 *
 * Field-level issues are returned for every offending input so the form can mark
 * each one. Only when `ok` is true is the payload safe to send.
 */
export function buildSchedulePayload(
  draft: ScheduleDraft,
  options: ScheduleBuildOptions = {},
): ScheduleBuildResult {
  const nowMs = options.nowMs ?? Date.now();
  const includeZone = options.includeZone ?? true;
  const issues: ScheduleIssue[] = [];
  const allowedOverlap = options.allowedOverlapPolicies;
  const allowedMissed = options.allowedMissedPolicies;

  if (allowedOverlap && !allowedOverlap.includes(draft.overlapPolicy)) {
    issues.push({
      field: "overlapPolicy",
      code: "automation_overlap_policy",
      message: "Current organization policy does not allow this overlap behavior.",
    });
  }
  if (allowedMissed && !allowedMissed.includes(draft.missedPolicy)) {
    issues.push({
      field: "missedPolicy",
      code: "schedule_invalid",
      message: "Current organization policy does not allow this missed-run behavior.",
    });
  }

  const catchUpLimit = validateCatchUpLimit(draft, issues);
  // The limit is only meaningful for `catch_up`, so it is only sent for
  // `catch_up`. The server still tolerates a present-but-unused limit, but
  // sending it would imply a behavior the operator did not choose.
  const catchUpFields =
    catchUpLimit !== null && draft.missedPolicy === "catch_up"
      ? { catch_up_limit: catchUpLimit }
      : {};

  if (draft.kind === "manual") {
    // A manual rule has no clock schedule, so overlap and missed behavior have
    // no slot to act on. The stored values are still bounded and echoed back.
    if (issues.length > 0) return { ok: false, issues };
    return {
      ok: true,
      payload: {
        kind: "manual",
        overlap_policy: draft.overlapPolicy,
        missed_policy: draft.missedPolicy,
        ...catchUpFields,
      },
      issues: [],
    };
  }

  if (draft.kind === "one_time") {
    const scheduledAt = parseLocalInstant(draft.scheduledAt);
    if (scheduledAt === null) {
      issues.push({
        field: "scheduledAt",
        code: "schedule_invalid",
        message: "Enter the one-time instant as a local date and time.",
      });
    }
    if (issues.length > 0) return { ok: false, issues };
    return {
      ok: true,
      payload: {
        kind: "one_time",
        scheduled_at: scheduledAt as string,
        overlap_policy: draft.overlapPolicy,
        missed_policy: draft.missedPolicy,
        ...catchUpFields,
      },
      issues: [],
    };
  }

  const timezone = validateTimezone(draft.timezone, issues);

  if (draft.kind === "cron") {
    if (!isValidCronExpression(draft.expression)) {
      issues.push({
        field: "expression",
        code: "schedule_invalid",
        message: cronHelpMessage(draft.expression),
      });
    }
    if (issues.length > 0) return { ok: false, issues };
    return {
      ok: true,
      payload: {
        kind: "cron",
        expression: draft.expression.trim(),
        timezone: timezone as string,
        dom_dow_mode: draft.domDowMode,
        dst_policy: draft.dstPolicy,
        overlap_policy: draft.overlapPolicy,
        missed_policy: draft.missedPolicy,
        ...catchUpFields,
        ...(includeZone ? resolveZone(draft.timezone, nowMs) : {}),
      },
      issues: [],
    };
  }

  const every = parseBoundedInteger(draft.every, MIN_INTERVAL_EVERY, MAX_INTERVAL_EVERY);
  if (every === null) {
    issues.push({
      field: "every",
      code: "schedule_interval_invalid",
      message: `Enter a whole number from ${MIN_INTERVAL_EVERY} to ${MAX_INTERVAL_EVERY}.`,
    });
  }
  const anchorAt = parseLocalInstant(draft.anchorAt);
  if (anchorAt === null) {
    issues.push({
      field: "anchorAt",
      code: "schedule_interval_invalid",
      message: "Enter the interval anchor as a local date and time.",
    });
  }
  const byWeekday = parseSelectors(draft.byWeekday, 0, 6, "byWeekday", issues);
  const byMonthday = parseSelectors(draft.byMonthday, 1, 31, "byMonthday", issues);
  const byMonth = parseSelectors(draft.byMonth, 1, 12, "byMonth", issues);

  if (issues.length > 0) return { ok: false, issues };
  return {
    ok: true,
    payload: {
      kind: "interval",
      every: every as number,
      unit: draft.unit,
      anchor_at: anchorAt as string,
      timezone: timezone as string,
      ...(byWeekday ? { by_weekday: byWeekday } : {}),
      ...(byMonthday ? { by_monthday: byMonthday } : {}),
      ...(byMonth ? { by_month: byMonth } : {}),
      overlap_policy: draft.overlapPolicy,
      missed_policy: draft.missedPolicy,
      ...catchUpFields,
      ...(includeZone ? resolveZone(draft.timezone, nowMs) : {}),
    },
    issues: [],
  };
}

function validateCatchUpLimit(draft: ScheduleDraft, issues: ScheduleIssue[]): number | null {
  const raw = draft.catchUpLimit.trim();
  if (raw === "") {
    if (draft.missedPolicy === "catch_up") {
      issues.push({
        field: "catchUpLimit",
        code: "schedule_invalid",
        message: `Catch-up needs a limit from ${MIN_CATCH_UP_LIMIT} to ${MAX_CATCH_UP_LIMIT}.`,
      });
    }
    return null;
  }
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < MIN_CATCH_UP_LIMIT || parsed > MAX_CATCH_UP_LIMIT) {
    issues.push({
      field: "catchUpLimit",
      code: "schedule_invalid",
      message: `Catch-up limit must be a whole number from ${MIN_CATCH_UP_LIMIT} to ${MAX_CATCH_UP_LIMIT}.`,
    });
    return null;
  }
  return parsed;
}

/** The server checks name shape and length only; the client checks the same. */
export function validateTimezone(value: string, issues?: ScheduleIssue[]): string | null {
  const timezone = value.trim();
  const bytes = timezone.split("").map((character) => character.charCodeAt(0));
  const shaped =
    timezone.length > 0 &&
    timezone.length <= MAX_TIMEZONE_BYTES &&
    !timezone.startsWith("/") &&
    !timezone.endsWith("/") &&
    !timezone.includes("//") &&
    timezone.split("/").length <= MAX_TIMEZONE_SEGMENTS &&
    bytes.every(
      (byte) =>
        (byte >= 48 && byte <= 57) ||
        (byte >= 65 && byte <= 90) ||
        (byte >= 97 && byte <= 122) ||
        byte === 47 ||
        byte === 95 ||
        byte === 45 ||
        byte === 43,
    );
  if (shaped) return timezone;
  issues?.push({
    field: "timezone",
    code: "schedule_timezone_invalid",
    message: "Enter an IANA timezone name such as America/Los_Angeles or UTC.",
  });
  return null;
}

/** Confirm the browser actually knows the zone, not just its shape. */
export function isKnownTimezone(value: string): boolean {
  const timezone = value.trim();
  if (timezone === "") return false;
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: timezone }).format(new Date(0));
    return true;
  } catch {
    return false;
  }
}

/**
 * The UTC offset of `timezone` at `dateMs`, in seconds.
 *
 * `Intl` is the only timezone database available in a browser, and the frozen
 * contract requires a named zone to carry its resolved offset. A zone the
 * runtime cannot resolve returns `null` and the field is left unset.
 */
export function zoneOffsetSeconds(timezone: string, dateMs: number): number | null {
  let parts: Intl.DateTimeFormatPart[];
  try {
    parts = new Intl.DateTimeFormat("en-US", {
      timeZone: timezone,
      hourCycle: "h23",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }).formatToParts(new Date(dateMs));
  } catch {
    return null;
  }
  const read = (type: Intl.DateTimeFormatPartTypes): number => {
    const part = parts.find((candidate) => candidate.type === type);
    return part ? Number.parseInt(part.value, 10) : Number.NaN;
  };
  const year = read("year");
  const month = read("month");
  const day = read("day");
  const hour = read("hour");
  const minute = read("minute");
  const second = read("second");
  if ([year, month, day, hour, minute, second].some((value) => !Number.isFinite(value)))
    return null;
  const asUtc = Date.UTC(year, month - 1, day, hour, minute, second);
  const offset = Math.round((asUtc - dateMs) / 1000);
  if (!Number.isInteger(offset) || Math.abs(offset) > MAX_UTC_OFFSET_SECONDS) return null;
  return offset;
}

/**
 * Resolve the zone table a cron/interval rule must carry.
 *
 * The table is a bounded monthly sample of the zone's offset for the next year
 * plus the current instant, which is what a schedule can plausibly need. The
 * server validates the offset range, the ordering, and the table size, and
 * remains the authority for every instant the rule produces.
 */
export function resolveZoneOffsets(
  timezone: string,
  nowMs: number = Date.now(),
): ResolvedZone | null {
  const current = zoneOffsetSeconds(timezone, nowMs);
  if (current === null) return null;
  const transitions: ZoneOffset[] = [];
  let previous = current;
  for (let month = 1; month <= 12; month += 1) {
    const sampleMs = Date.UTC(new Date(nowMs).getUTCFullYear(), month, 1, 12, 0, 0);
    if (sampleMs <= nowMs) continue;
    const offset = zoneOffsetSeconds(timezone, sampleMs);
    if (offset === null) return null;
    if (offset !== previous) {
      transitions.push({ at_utc: Math.floor(sampleMs / 1000), offset_seconds: offset });
      previous = offset;
    }
  }
  return { utc_offset_seconds: current, utc_offset_transitions: transitions };
}

function resolveZone(timezone: string, nowMs: number): Partial<ScheduleRequestPayload> {
  const resolved = resolveZoneOffsets(timezone, nowMs);
  if (resolved === null) return {};
  return {
    utc_offset_seconds: resolved.utc_offset_seconds,
    utc_offset_transitions: resolved.utc_offset_transitions,
  };
}

function parseBoundedInteger(raw: string, min: number, max: number): number | null {
  const trimmed = raw.trim();
  if (!/^\d{1,6}$/.test(trimmed)) return null;
  const value = Number(trimmed);
  if (!Number.isInteger(value) || value < min || value > max) return null;
  return value;
}

function parseSelectors(
  raw: string,
  min: number,
  max: number,
  field: string,
  issues: ScheduleIssue[],
): number[] | null {
  const trimmed = raw.trim();
  if (trimmed === "") return null;
  const parts = trimmed
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part !== "");
  if (parts.length === 0 || parts.length > MAX_SELECTOR_VALUES) {
    issues.push({
      field,
      code: "schedule_interval_invalid",
      message: `List up to ${MAX_SELECTOR_VALUES} values between ${min} and ${max}.`,
    });
    return null;
  }
  const values: number[] = [];
  for (const part of parts) {
    const value = Number(part);
    if (!Number.isInteger(value) || value < min || value > max) {
      issues.push({
        field,
        code: "schedule_interval_invalid",
        message: `Each value must be a whole number from ${min} to ${max}.`,
      });
      return null;
    }
    if (!values.includes(value)) values.push(value);
  }
  return values.sort((left, right) => left - right);
}

/**
 * Convert a `datetime-local` value to the UTC instant the contract stores.
 *
 * A `datetime-local` value has no zone, so the browser's own zone is used and
 * the resolved instant is shown next to the input. The server re-resolves the
 * instant and owns the canonical value.
 */
export function parseLocalInstant(value: string): string | null {
  const trimmed = value.trim();
  if (trimmed === "") return null;
  const parsed = new Date(trimmed);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

/** The browser's current IANA zone, used as the default for a new schedule. */
export function localTimezone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

/** A `datetime-local` input value for a UTC instant, in the browser's zone. */
export function toLocalInputValue(instant: string): string {
  const parsed = new Date(instant);
  if (Number.isNaN(parsed.getTime())) return "";
  const pad = (value: number): string => String(value).padStart(2, "0");
  return `${parsed.getFullYear()}-${pad(parsed.getMonth() + 1)}-${pad(parsed.getDate())}T${pad(
    parsed.getHours(),
  )}:${pad(parsed.getMinutes())}`;
}

// -----------------------------------------------------------------------------
// Cron grammar
// -----------------------------------------------------------------------------

interface CronFieldSpec {
  min: number;
  max: number;
  /** Cron day-of-week `7` is an accepted alias for Sunday `0`. */
  foldMax: number | null;
  names: Readonly<Record<string, number>>;
}

const MONTH_NAMES: Readonly<Record<string, number>> = {
  jan: 1,
  feb: 2,
  mar: 3,
  apr: 4,
  may: 5,
  jun: 6,
  jul: 7,
  aug: 8,
  sep: 9,
  oct: 10,
  nov: 11,
  dec: 12,
};

const DAY_NAMES: Readonly<Record<string, number>> = {
  sun: 0,
  mon: 1,
  tue: 2,
  wed: 3,
  thu: 4,
  fri: 5,
  sat: 6,
};

const CRON_FIELD_SPECS: readonly CronFieldSpec[] = [
  { min: 0, max: 59, foldMax: null, names: {} },
  { min: 0, max: 23, foldMax: null, names: {} },
  { min: 1, max: 31, foldMax: null, names: {} },
  { min: 1, max: 12, foldMax: null, names: MONTH_NAMES },
  { min: 0, max: 7, foldMax: 0, names: DAY_NAMES },
];

/**
 * Mirror of the server's five-field cron grammar.
 *
 * Accepts `*`, literals, `a-b` ranges, `,` lists, and an optional `/step` on any
 * of them, plus month and weekday names. Everything else — a sixth field, a
 * reversed range, a zero step, an out-of-range literal — is invalid.
 */
export function isValidCronExpression(expression: string): boolean {
  if (expression.length === 0 || expression.length > MAX_CRON_EXPRESSION_BYTES) return false;
  const fields = expression.trim().split(/\s+/);
  if (fields.length !== 5) return false;
  return fields.every((field, index) => {
    const spec = CRON_FIELD_SPECS[index];
    return spec ? isValidCronField(field, spec) : false;
  });
}

function isValidCronField(text: string, spec: CronFieldSpec): boolean {
  if (text === "") return false;
  let inserted = 0;
  for (const part of text.split(",")) {
    if (part.trim() === "") return false;
    const [rawBase, rawStep, ...extra] = part.split("/");
    if (extra.length > 0) return false;
    let step = 1;
    if (rawStep !== undefined) {
      const parsedStep = readCronValue(rawStep, spec);
      if (parsedStep === null || parsedStep === 0 || parsedStep > spec.max) return false;
      step = parsedStep;
    }
    const base = (rawBase ?? "").trim();
    if (base === "*") {
      inserted += spec.max - spec.min + 1;
      continue;
    }
    if (base.includes("-")) {
      const [rawFrom, rawTo, ...rest] = base.split("-");
      if (rest.length > 0) return false;
      const from = readCronValue(rawFrom ?? "", spec);
      const to = readCronValue(rawTo ?? "", spec);
      if (from === null || to === null || from > to) return false;
      inserted += Math.floor((to - from) / step) + 1;
      continue;
    }
    const value = readCronValue(base, spec);
    if (value === null) return false;
    inserted += 1;
  }
  return inserted > 0;
}

function readCronValue(text: string, spec: CronFieldSpec): number | null {
  const trimmed = text.trim();
  if (trimmed === "") return null;
  if (/^\d{1,3}$/.test(trimmed)) {
    const value = Number(trimmed);
    if (value < spec.min || value > spec.max) return null;
    return value;
  }
  const named = spec.names[trimmed.toLowerCase()];
  return named === undefined ? null : named;
}

function cronHelpMessage(expression: string): string {
  if (expression.trim().split(/\s+/).length !== 5) {
    return "Use five fields: minute, hour, day of month, month, day of week.";
  }
  return "Use five fields such as 0 9 * * 1-5. Ranges, lists, and */step are supported.";
}

// -----------------------------------------------------------------------------
// Description
// -----------------------------------------------------------------------------

export function humanizeToken(value: string): string {
  return value.replaceAll("_", " ");
}

export function scheduleKindLabel(kind: ScheduleKind): string {
  if (kind === "one_time") return "One time";
  if (kind === "cron") return "Cron";
  if (kind === "interval") return "Interval";
  return "Manual";
}

export function overlapPolicyLabel(policy: OverlapPolicy): string {
  if (policy === "allow") return "Allow overlap";
  if (policy === "skip") return "Skip while running";
  if (policy === "queue_one") return "Queue one";
  return "Cancel previous";
}

export function overlapPolicyDetail(policy: OverlapPolicy): string {
  if (policy === "allow") return "A new occurrence starts even if the previous one is still live.";
  if (policy === "skip")
    return "A new occurrence is dropped and recorded as skipped while the previous one is live.";
  if (policy === "queue_one")
    return "At most one pending successor waits. A successor that ages out is recorded as skipped.";
  return "A cancellation is recorded for the previous occurrence before the successor is created.";
}

export function missedPolicyLabel(policy: MissedPolicy): string {
  if (policy === "skip") return "Skip missed";
  if (policy === "run_once") return "Run once on recovery";
  return "Catch up";
}

export function missedPolicyDetail(policy: MissedPolicy, catchUpLimit: number | null): string {
  if (policy === "skip") return "A missed slot produces no occurrence at all.";
  if (policy === "run_once") return "Recovery runs the most recent missed slot exactly once.";
  return `Recovery runs up to ${catchUpLimit ?? "—"} missed occurrence${
    catchUpLimit === 1 ? "" : "s"
  }, newest first, within at most seven days of missed history.`;
}

export function dstPolicyLabel(policy: DstPolicy): string {
  if (policy === "skip_duplicate") return "Skip duplicate";
  if (policy === "run_first") return "First instant only";
  return "Both instants";
}

export function domDowModeLabel(mode: DomDowMode): string {
  return mode === "and" ? "Day of month AND day of week" : "Standard cron OR";
}

export function intervalUnitLabel(unit: IntervalUnit): string {
  return humanizeToken(unit);
}

/** One-line, dense description of a stored canonical rule. */
export function describeSchedule(schedule: ScheduleRule): string {
  if (schedule.kind === "manual") return "Manual only · run now creates one occurrence";
  if (schedule.kind === "one_time") return `One time · ${formatInstant(schedule.scheduled_at)}`;
  if (schedule.kind === "cron")
    return `${schedule.expression} · ${schedule.timezone} · ${domDowModeLabel(schedule.dom_dow_mode)}`;
  return `Every ${schedule.every} ${intervalUnitLabel(schedule.unit)} · ${schedule.timezone} · anchored ${formatInstant(schedule.anchor_at)}`;
}

export function describeSchedulePolicy(schedule: ScheduleRule): string {
  const parts = [
    `Overlap: ${overlapPolicyLabel(schedule.overlap_policy).toLowerCase()}`,
    `Missed: ${missedPolicyLabel(schedule.missed_policy).toLowerCase()}`,
  ];
  if (schedule.missed_policy === "catch_up") {
    parts.push(`limit ${schedule.catch_up_limit ?? "—"}`);
  }
  return parts.join(" · ");
}

export function describeScheduleWindow(schedule: ScheduleRule): string {
  if (schedule.kind === "cron") return `DST: ${dstPolicyLabel(schedule.dst_policy).toLowerCase()}`;
  if (schedule.kind === "interval") {
    const selectors: string[] = [];
    if (schedule.by_weekday) selectors.push(`weekdays ${schedule.by_weekday.join(", ")}`);
    if (schedule.by_monthday) selectors.push(`month days ${schedule.by_monthday.join(", ")}`);
    if (schedule.by_month) selectors.push(`months ${schedule.by_month.join(", ")}`);
    return selectors.length > 0
      ? `Calendar selectors · ${selectors.join(" · ")}`
      : "No calendar selectors";
  }
  return schedule.kind === "one_time" ? "No recurrence" : "No clock schedule";
}

export function formatInstant(value: string | null | undefined): string {
  if (!value) return "Not recorded";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
  });
}

export function formatInstantUtc(value: string | null | undefined): string {
  if (!value) return "Not recorded";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return `${date.toISOString().replace(".000Z", "Z")} UTC`;
}

export const SCHEDULE_KIND_OPTIONS: readonly { value: ScheduleKind; label: string }[] = [
  { value: "cron", label: "Cron" },
  { value: "interval", label: "Interval" },
  { value: "one_time", label: "One time" },
  { value: "manual", label: "Manual" },
];

export const OVERLAP_POLICY_OPTIONS: readonly { value: OverlapPolicy; label: string }[] = [
  { value: "skip", label: overlapPolicyLabel("skip") },
  { value: "queue_one", label: overlapPolicyLabel("queue_one") },
  { value: "allow", label: overlapPolicyLabel("allow") },
  { value: "cancel_previous", label: overlapPolicyLabel("cancel_previous") },
];

export const MISSED_POLICY_OPTIONS: readonly { value: MissedPolicy; label: string }[] = [
  { value: "run_once", label: missedPolicyLabel("run_once") },
  { value: "skip", label: missedPolicyLabel("skip") },
  { value: "catch_up", label: missedPolicyLabel("catch_up") },
];

export const DST_POLICY_OPTIONS: readonly { value: DstPolicy; label: string }[] = [
  { value: "skip_duplicate", label: dstPolicyLabel("skip_duplicate") },
  { value: "run_first", label: dstPolicyLabel("run_first") },
  { value: "run_both", label: dstPolicyLabel("run_both") },
];

export const DOM_DOW_MODE_OPTIONS: readonly { value: DomDowMode; label: string }[] = [
  { value: "or", label: domDowModeLabel("or") },
  { value: "and", label: domDowModeLabel("and") },
];

export const INTERVAL_UNIT_OPTIONS: readonly { value: IntervalUnit; label: string }[] =
  INTERVAL_UNITS.map((unit) => ({ value: unit, label: unit }));
