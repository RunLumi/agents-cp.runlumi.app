// The schedule builder's client-side validation must mirror the server's frozen
// bounds, and it must report the server's stable reason codes rather than its
// prose. The bounds below are the ones `p06-cg-v1` freezes and the P06 domain
// enforces: `every` 1–200, `catch_up_limit` 1–20, a five-field cron grammar, an
// IANA name of at most four segments, and interval selectors inside their own
// ranges.

import { describe, expect, it } from "vitest";

import fixture from "../../../../../docs/implementation/fixtures/p06-contracts-v1.json";
import type { ScheduleDraft } from "./schedule-helpers";
import {
  buildSchedulePayload,
  createScheduleDraft,
  describeSchedule,
  describeSchedulePolicy,
  isKnownTimezone,
  isValidCronExpression,
  parseLocalInstant,
  resolveZoneOffsets,
  toLocalInputValue,
  validateTimezone,
} from "./schedule-helpers";

const JAN_1_2026 = Date.UTC(2026, 0, 1, 12, 0, 0);

function draft(overrides: Partial<ScheduleDraft> = {}): ScheduleDraft {
  return { ...createScheduleDraft(), ...overrides };
}

function codes(result: ReturnType<typeof buildSchedulePayload>): string[] {
  return result.ok ? [] : result.issues.map((issue) => issue.code);
}

function fields(result: ReturnType<typeof buildSchedulePayload>): string[] {
  return result.ok ? [] : result.issues.map((issue) => issue.field);
}

describe("cron grammar mirror", () => {
  it("accepts the frozen expression and ordinary cron spellings", () => {
    expect(isValidCronExpression("0 9 * * 1-5")).toBe(true);
    expect(isValidCronExpression("*/15 * * * *")).toBe(true);
    expect(isValidCronExpression("0 0 1 jan *")).toBe(true);
    expect(isValidCronExpression("0 0 * * 7")).toBe(true);
    expect(isValidCronExpression("0,30 8-18 * * mon-fri")).toBe(true);
  });

  it("rejects the frozen negative fixture and the same failure classes", () => {
    expect(isValidCronExpression(fixture.negative_fixtures.invalid_schedule.expression)).toBe(
      false,
    );
    expect(isValidCronExpression("0 9 * *")).toBe(false);
    expect(isValidCronExpression("0 9 * * * *")).toBe(false);
    expect(isValidCronExpression("60 * * * *")).toBe(false);
    expect(isValidCronExpression("0 24 * * *")).toBe(false);
    expect(isValidCronExpression("0 0 0 * *")).toBe(false);
    expect(isValidCronExpression("0 0 * 13 *")).toBe(false);
    expect(isValidCronExpression("5-1 * * * *")).toBe(false);
    expect(isValidCronExpression("*/0 * * * *")).toBe(false);
    expect(isValidCronExpression("1,,2 * * * *")).toBe(false);
    expect(isValidCronExpression("")).toBe(false);
    expect(isValidCronExpression("0 0 * * mon-")).toBe(false);
    // The stored expression is bounded at 128 bytes.
    expect(isValidCronExpression(`${"0".repeat(129)} * * * *`)).toBe(false);
  });
});

describe("timezone validation", () => {
  it("mirrors the server's shape check", () => {
    const issues: { code: string }[] = [];
    expect(validateTimezone("America/Los_Angeles")).toBe("America/Los_Angeles");
    expect(validateTimezone("UTC")).toBe("UTC");
    expect(validateTimezone("Etc/GMT+5")).toBe("Etc/GMT+5");
    expect(validateTimezone("/UTC", issues as never)).toBeNull();
    expect(validateTimezone("a/b/c/d/e", issues as never)).toBeNull();
    expect(validateTimezone("Europe//Paris", issues as never)).toBeNull();
    expect(validateTimezone("Europe/Paris x", issues as never)).toBeNull();
    expect(issues.map((issue) => issue.code)).toEqual([
      "schedule_timezone_invalid",
      "schedule_timezone_invalid",
      "schedule_timezone_invalid",
      "schedule_timezone_invalid",
    ]);
  });

  it("confirms the browser actually knows a zone", () => {
    expect(isKnownTimezone("UTC")).toBe(true);
    expect(isKnownTimezone("America/Los_Angeles")).toBe(true);
    expect(isKnownTimezone("Not/AZone")).toBe(false);
    expect(isKnownTimezone("")).toBe(false);
  });
});

describe("client-resolved zone table", () => {
  it("reports a zero offset with no transitions for UTC", () => {
    const resolved = resolveZoneOffsets("UTC", JAN_1_2026);
    expect(resolved).toEqual({ utc_offset_seconds: 0, utc_offset_transitions: [] });
  });

  it("samples a bounded, ascending transition table for a zone with DST", () => {
    const resolved = resolveZoneOffsets("America/Los_Angeles", JAN_1_2026);
    expect(resolved?.utc_offset_seconds).toBe(-28_800);
    const transitions = resolved?.utc_offset_transitions ?? [];
    expect(transitions.length).toBeGreaterThan(0);
    expect(transitions.length).toBeLessThanOrEqual(12);
    for (const transition of transitions) {
      expect(Math.abs(transition.offset_seconds)).toBeLessThanOrEqual(18 * 60 * 60);
      expect(Number.isInteger(transition.at_utc)).toBe(true);
    }
    const instants = transitions.map((transition) => transition.at_utc);
    expect([...instants].sort((left, right) => left - right)).toEqual(instants);
    for (const instant of instants) expect(instant).toBeGreaterThan(JAN_1_2026 / 1000);
  });

  it("returns nothing for a zone the runtime cannot resolve", () => {
    expect(resolveZoneOffsets("Not/AZone", JAN_1_2026)).toBeNull();
  });
});

describe("schedule payload construction", () => {
  it("builds a cron rule with its resolved zone", () => {
    const result = buildSchedulePayload(
      draft({ kind: "cron", expression: "0 9 * * 1-5", timezone: "America/Los_Angeles" }),
      { nowMs: JAN_1_2026 },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.payload).toMatchObject({
      kind: "cron",
      expression: "0 9 * * 1-5",
      timezone: "America/Los_Angeles",
      dom_dow_mode: "or",
      dst_policy: "skip_duplicate",
      overlap_policy: "skip",
      missed_policy: "run_once",
      utc_offset_seconds: -28_800,
    });
  });

  it("omits the zone table when the caller asks for bounds only", () => {
    const result = buildSchedulePayload(
      draft({ kind: "cron", expression: "0 9 * * 1-5", timezone: "America/Los_Angeles" }),
      { includeZone: false, nowMs: JAN_1_2026 },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.payload.utc_offset_seconds).toBeUndefined();
    expect(result.payload.utc_offset_transitions).toBeUndefined();
  });

  it("builds a manual rule with no instant and no zone", () => {
    const result = buildSchedulePayload(draft({ kind: "manual" }));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.payload).toEqual({
      kind: "manual",
      overlap_policy: "skip",
      missed_policy: "run_once",
    });
  });

  it("builds an interval rule with an anchor and normalized selectors", () => {
    const result = buildSchedulePayload(
      draft({
        kind: "interval",
        every: "15",
        unit: "minutes",
        anchorAt: "2026-09-25T09:00",
        timezone: "UTC",
        byWeekday: "3, 1,1",
        byMonthday: "31",
        byMonth: "12, 1",
      }),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.payload).toMatchObject({
      kind: "interval",
      every: 15,
      unit: "minutes",
      timezone: "UTC",
      by_weekday: [1, 3],
      by_monthday: [31],
      by_month: [1, 12],
    });
    expect(result.payload.anchor_at).toBe(parseLocalInstant("2026-09-25T09:00"));
  });

  it("bounds the interval amount at 1 to 200", () => {
    for (const every of ["1", "200"]) {
      expect(
        buildSchedulePayload(
          draft({ kind: "interval", every, anchorAt: "2026-09-25T09:00", timezone: "UTC" }),
        ).ok,
      ).toBe(true);
    }
    for (const every of ["0", "201", "-1", "1.5", "many", ""]) {
      const result = buildSchedulePayload(
        draft({ kind: "interval", every, anchorAt: "2026-09-25T09:00", timezone: "UTC" }),
      );
      expect(codes(result)).toContain("schedule_interval_invalid");
      expect(fields(result)).toContain("every");
    }
  });

  it("requires a bounded catch-up limit only when the missed policy catches up", () => {
    const catchingUp = { missedPolicy: "catch_up" as const };
    expect(buildSchedulePayload(draft({ ...catchingUp, catchUpLimit: "1" })).ok).toBe(true);
    expect(buildSchedulePayload(draft({ ...catchingUp, catchUpLimit: "20" })).ok).toBe(true);
    for (const limit of ["0", "21", "", "3.5"]) {
      const result = buildSchedulePayload(draft({ ...catchingUp, catchUpLimit: limit }));
      expect(codes(result)).toContain("schedule_invalid");
      expect(fields(result)).toContain("catchUpLimit");
    }
    // A limit alongside a non-catching policy is tolerated but not required,
    // exactly as the server tolerates it.
    expect(buildSchedulePayload(draft({ catchUpLimit: "" })).ok).toBe(true);
  });

  it("rejects an interval selector outside its own range", () => {
    const result = buildSchedulePayload(
      draft({
        kind: "interval",
        anchorAt: "2026-09-25T09:00",
        timezone: "UTC",
        byWeekday: "7",
      }),
    );
    expect(codes(result)).toContain("schedule_interval_invalid");
    expect(fields(result)).toContain("byWeekday");
  });

  it("rejects a malformed cron and a malformed timezone with stable codes", () => {
    const badCron = buildSchedulePayload(
      draft({ kind: "cron", expression: fixture.negative_fixtures.invalid_schedule.expression }),
    );
    expect(codes(badCron)).toEqual(["schedule_invalid"]);
    const badZone = buildSchedulePayload(draft({ kind: "cron", timezone: "/UTC" }));
    expect(codes(badZone)).toEqual(["schedule_timezone_invalid"]);
  });

  it("rejects a one-time rule without an instant", () => {
    const result = buildSchedulePayload(draft({ kind: "one_time", scheduledAt: "" }));
    expect(codes(result)).toContain("schedule_invalid");
    expect(fields(result)).toContain("scheduledAt");
  });

  it("refuses an overlap policy the current policy snapshot excludes", () => {
    const result = buildSchedulePayload(draft({ overlapPolicy: "queue_one" }), {
      allowedOverlapPolicies: ["allow", "skip"],
    });
    expect(codes(result)).toEqual(["automation_overlap_policy"]);
    expect(fields(result)).toEqual(["overlapPolicy"]);
  });

  it("offers only the policies a narrow snapshot allows", () => {
    const result = buildSchedulePayload(
      draft({ overlapPolicy: "skip", missedPolicy: "run_once" }),
      { allowedOverlapPolicies: ["skip"], allowedMissedPolicies: ["run_once"] },
    );
    expect(result.ok).toBe(true);
  });
});

describe("local instant conversion", () => {
  it("round-trips a local input value through a UTC instant", () => {
    const instant = parseLocalInstant("2026-09-25T09:00");
    expect(instant).not.toBeNull();
    expect(toLocalInputValue(instant as string)).toBe("2026-09-25T09:00");
  });

  it("refuses an unparseable instant instead of inventing one", () => {
    expect(parseLocalInstant("")).toBeNull();
    expect(parseLocalInstant("not-a-date")).toBeNull();
    expect(toLocalInputValue("not-a-date")).toBe("");
  });
});

describe("stored schedule description", () => {
  it("describes each kind without implying an off-peak window", () => {
    expect(
      describeSchedule({
        kind: "manual",
        overlap_policy: "skip",
        missed_policy: "run_once",
        catch_up_limit: null,
      }),
    ).toBe("Manual only · run now creates one occurrence");
    expect(
      describeSchedule({
        kind: "cron",
        expression: "0 9 * * 1-5",
        timezone: "America/Los_Angeles",
        dom_dow_mode: "or",
        dst_policy: "skip_duplicate",
        overlap_policy: "skip",
        missed_policy: "run_once",
        catch_up_limit: null,
      }),
    ).toBe("0 9 * * 1-5 · America/Los_Angeles · Standard cron OR");
    expect(
      describeSchedulePolicy({
        kind: "manual",
        overlap_policy: "queue_one",
        missed_policy: "catch_up",
        catch_up_limit: 3,
      }),
    ).toBe("Overlap: queue one · Missed: catch up · limit 3");
  });
});
