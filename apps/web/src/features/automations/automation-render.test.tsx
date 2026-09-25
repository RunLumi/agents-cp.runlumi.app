// Render smoke tests for the automation surface.
//
// These use `renderToStaticMarkup`, the same approach the other P06 panels take,
// so the component tree is actually executed rather than only type-checked. They
// assert the load-bearing copy and the accessibility shape an operator depends
// on: a labelled landmark, a native radio group for the schedule class, an
// `ambiguous` row that offers no retry, and consequence copy on every
// destructive or state-changing action.

import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import fixture from "../../../../../docs/implementation/fixtures/p06-contracts-v1.json";
import { AMBIGUOUS_EXPLANATION } from "./automation-helpers";
import { AutomationPanel, LIFECYCLE_ACTION_COPY } from "./automation-panel";
import type {
  AutomationsApiClient,
  AutomationDefinition,
  AutomationEntitlements,
  Occurrence,
  OffPeakPolicy,
  Page,
} from "./api";
import { decodeAutomation } from "./api";
import { OccurrenceHistory } from "./occurrence-history";
import { OffPeakCard } from "./off-peak-card";
import { ScheduleBuilder } from "./schedule-builder";
import { createScheduleDraft } from "./schedule-helpers";

const orgId = "org_0123456789abcdef0123456789abcdef";
const automation = decodeAutomation(fixture.automation) as AutomationDefinition;

function occurrence(overrides: Partial<Occurrence>): Occurrence {
  return {
    occurrence_id: "occ_0123456789abcdef0123456789abcdef",
    automation_id: automation.automation_id,
    org_id: orgId,
    project_id: automation.project_id,
    kind: "scheduled",
    execution_principal: { kind: "user", id: "usr_0123456789abcdef0123456789abcdef" },
    off_peak_mode: "normal",
    policy_snapshot_id: "pol_0123456789abcdef0123456789abcdef",
    policy_version: 4,
    scheduled_for: "2026-09-25T16:00:00.000Z",
    schedule_rule_id: "sch_0123456789abcdef0123456789abcdef",
    state: "succeeded",
    state_version: 9,
    attempt: 1,
    reason_code: null,
    run_id: "run_0123456789abcdef0123456789abcdef",
    blocked_by_occurrence_id: null,
    lease_expires_at: null,
    queued_at: null,
    started_at: "2026-09-25T16:00:01.000Z",
    finished_at: "2026-09-25T16:01:00.000Z",
    created_at: "2026-09-25T15:59:59.000Z",
    updated_at: "2026-09-25T16:01:00.000Z",
    ...overrides,
  };
}

const page = <T,>(items: T[]): Page<T> => ({ items, next_cursor: null, has_more: false });

const client: AutomationsApiClient = {
  listAutomations: async () => page([automation]),
  getAutomation: async () => automation,
  createAutomation: async () => automation,
  updateAutomation: async () => automation,
  pauseAutomation: async () => ({ ...automation, status: "paused" as const }),
  resumeAutomation: async () => automation,
  runAutomationNow: async () => occurrence({ kind: "manual", state: "pending" }),
  deleteAutomation: async () => undefined,
  listOccurrences: async () => page([occurrence({})]),
  getEntitlements: async () => fixture.entitlements as unknown as AutomationEntitlements,
};

describe("automation panel render", () => {
  it("renders its landmark, heading, and first-load states without crashing", () => {
    const markup = renderToStaticMarkup(<AutomationPanel orgId={orgId} client={client} />);
    expect(markup).toContain("AGENTS / AUTOMATIONS");
    expect(markup).toContain("aria-labelledby=");
    expect(markup).toContain("Loading automations…");
    expect(markup).toContain("Reading the automation entitlement limit…");
    expect(markup).toContain("Select an automation");
  });

  it("keeps every action control a real focusable button", () => {
    const markup = renderToStaticMarkup(<AutomationPanel orgId={orgId} client={client} />);
    // Native controls only: no div-as-button, no hover-only affordance.
    expect(markup).not.toContain('role="button"');
    expect(markup).not.toContain("<div tabindex");
    expect(markup).toContain("<button");
  });
});

describe("occurrence history render", () => {
  const history = (items: Occurrence[], ambiguousCount: number, filter: "" | "ambiguous" = "") =>
    renderToStaticMarkup(
      <OccurrenceHistory
        occurrences={items}
        loading={false}
        refreshing={false}
        error={null}
        hasMore={false}
        filter={filter}
        ambiguousCount={ambiguousCount}
        onFilterChange={() => undefined}
        onRetry={() => undefined}
        onLoadMore={() => undefined}
      />,
    );

  it("marks ambiguous as a reconciliation state and offers no retry", () => {
    const markup = history(
      [occurrence({ state: "ambiguous", run_id: null, reason_code: "occurrence_lease_expired" })],
      1,
    );
    expect(markup).toContain("Needs reconciliation");
    expect(markup).toContain("awaiting reconciliation");
    expect(markup).toContain("occurrence_lease_expired");
    expect(markup).toContain("never retried automatically");
    // No retry or run control may appear on an ambiguous occurrence.
    expect(markup).not.toMatch(/<button[^>]*>[^<]*retry/i);
    expect(markup).not.toMatch(/<button[^>]*>[^<]*run now/i);
    expect(markup).not.toMatch(/re-?dispatch/i);
  });

  it("shows every frozen state label and the correlated run only", () => {
    const markup = history(
      [
        occurrence({ state: "succeeded" }),
        occurrence({
          occurrence_id: "occ_2",
          state: "skipped",
          reason_code: "automation_overlap_policy",
        }),
        occurrence({ occurrence_id: "occ_3", state: "missed" }),
        occurrence({ occurrence_id: "occ_4", state: "leased" }),
        occurrence({ occurrence_id: "occ_5", state: "dispatching" }),
        occurrence({ occurrence_id: "occ_6", state: "started" }),
        occurrence({ occurrence_id: "occ_7", state: "failed", reason_code: "device_not_eligible" }),
        occurrence({ occurrence_id: "occ_8", state: "cancelled" }),
      ],
      0,
    );
    for (const label of [
      "succeeded",
      "skipped",
      "missed",
      "leased",
      "Dispatching",
      "started",
      "failed",
      "cancelled",
    ]) {
      expect(markup).toContain(`>${label}<`);
    }
    // P05 owns the run; this view only correlates the id.
    expect(markup).toContain("run_0123456789abcdef0123456789abcdef");
    expect(markup).not.toContain("timeline");
  });

  it("labels an off-peak occurrence as its own class", () => {
    const markup = history(
      [occurrence({ kind: "off_peak", off_peak_mode: "off_peak", scheduled_for: null })],
      0,
    );
    expect(markup).toContain("Off-peak");
    expect(markup).toContain("separate execution class");
    expect(markup).toContain("No clock instant (manual or off-peak)");
  });

  it("explains an empty history instead of implying a failure", () => {
    const markup = history([], 0);
    expect(markup).toContain("No occurrence matches");
  });

  it("exposes ambiguous in the state filter", () => {
    const markup = history([occurrence({ state: "ambiguous" })], 1, "ambiguous");
    expect(markup).toContain("ambiguous (needs reconciliation)");
  });
});

describe("off-peak class render", () => {
  const providerTicket = fixture.off_peak as unknown as OffPeakPolicy;

  it("never presents a provider ticket as a clock window", () => {
    const markup = renderToStaticMarkup(<OffPeakCard policy={providerTicket} />);
    expect(markup).toContain("Off-peak execution class");
    expect(markup).toContain("None — no clock schedule");
    expect(markup).toContain("does not create a second logical occurrence");
    expect(markup).toContain("never a schedule window");
    expect(markup).toMatch(/may narrow these restrictions but never widen them/i);
    // The class is never editable as a schedule: no expression field, no kind
    // selector, and the word "cron" appears only in the negating sentence.
    expect(markup).not.toContain('type="text"');
    expect(markup).not.toContain("<select");
    expect(markup.match(/cron/gi) ?? []).toHaveLength(
      (markup.match(/not a cron window/gi) ?? []).length,
    );
  });

  it("says a window is an eligibility condition, not a second schedule", () => {
    const markup = renderToStaticMarkup(
      <OffPeakCard
        policy={{
          schema_version: 1,
          eligibility_source: "org_window",
          allowed_route_aliases: ["nightly"],
          tool_constraints: {
            deny_automation_mutation: true,
            deny_recursive_off_peak: true,
            allow_background_processes: false,
          },
        }}
      />,
    );
    expect(markup).toContain("Inside the organization window");
    expect(markup).toContain("eligibility condition, not a separate schedule");
    expect(markup).toContain("nightly");
  });

  it("states the class is not requested when the policy is absent", () => {
    const markup = renderToStaticMarkup(<OffPeakCard policy={null} />);
    expect(markup).toContain("does not request one");
    expect(markup).toContain("not a cron window");
  });
});

describe("schedule builder render", () => {
  it("uses a labelled native radio group for the schedule class", () => {
    const markup = renderToStaticMarkup(
      <ScheduleBuilder draft={createScheduleDraft()} onChange={() => undefined} issues={[]} />,
    );
    expect(markup).toContain("<fieldset>");
    expect(markup).toContain("<legend");
    expect(markup).toContain('type="radio"');
    expect(markup).toContain("has no clock schedule. Only an authorized run-now creates");
    for (const label of ["Cron", "Interval", "One time", "Manual"]) {
      expect(markup).toContain(`>${label}`);
    }
  });

  it("binds each field's hint and error to its control", () => {
    const markup = renderToStaticMarkup(
      <ScheduleBuilder
        draft={createScheduleDraft()}
        onChange={() => undefined}
        issues={[
          {
            field: "expression",
            code: "schedule_invalid",
            message: "Use five fields such as 0 9 * * 1-5.",
          },
        ]}
      />,
    );
    expect(markup).toContain('aria-invalid="true"');
    expect(markup).toMatch(/aria-describedby="[^"]+-error"/);
    expect(markup).toContain("Use five fields such as 0 9 * * 1-5.");
  });

  it("reveals the bounded catch-up limit only for catch_up", () => {
    const withoutCatchUp = renderToStaticMarkup(
      <ScheduleBuilder draft={createScheduleDraft()} onChange={() => undefined} issues={[]} />,
    );
    expect(withoutCatchUp).not.toContain("Catch-up limit");

    const withCatchUp = renderToStaticMarkup(
      <ScheduleBuilder
        draft={{ ...createScheduleDraft(), missedPolicy: "catch_up" }}
        onChange={() => undefined}
        issues={[]}
      />,
    );
    expect(withCatchUp).toContain("Catch-up limit");
    expect(withCatchUp).toContain('max="20"');
    expect(withCatchUp).toContain('min="1"');
  });

  it("explains the overlap and missed policies next to their controls", () => {
    const markup = renderToStaticMarkup(
      <ScheduleBuilder
        draft={{
          ...createScheduleDraft(),
          overlapPolicy: "cancel_previous",
          missedPolicy: "catch_up",
          catchUpLimit: "3",
        }}
        onChange={() => undefined}
        issues={[]}
      />,
    );
    expect(markup).toContain(
      "A cancellation is recorded for the previous occurrence before the successor is created",
    );
    expect(markup).toContain("up to 3 missed occurrences");
    expect(markup).toContain("at most seven days of missed history");
  });
});

describe("lifecycle consequence copy", () => {
  it("states what each action changes before it is confirmed", () => {
    expect(LIFECYCLE_ACTION_COPY.pause.body).toMatch(/no new occurrence is dispatched/i);
    expect(LIFECYCLE_ACTION_COPY.pause.body).toMatch(/run-now is refused/i);
    expect(LIFECYCLE_ACTION_COPY.resume.body).toMatch(/re-checks current membership/i);
    expect(LIFECYCLE_ACTION_COPY.resume.body).toMatch(/cannot produce a replay burst/i);
    expect(LIFECYCLE_ACTION_COPY.run_now.body).toMatch(/exactly one manual occurrence/i);
    expect(LIFECYCLE_ACTION_COPY.run_now.body).toMatch(/idempotency key/i);
  });

  it("makes delete irreversible and names what is retained", () => {
    const body = LIFECYCLE_ACTION_COPY.delete.body;
    expect(body).toMatch(/permanent and cannot be undone/i);
    expect(body).toMatch(/stops dispatch/i);
    expect(body).toMatch(/retained for their retention window/i);
    expect(LIFECYCLE_ACTION_COPY.delete.confirmLabel).toBe("Delete permanently");
  });
});

describe("ambiguous explanation wiring", () => {
  it("is the same copy the history renders", () => {
    const markup = renderToStaticMarkup(
      <OccurrenceHistory
        occurrences={[occurrence({ state: "ambiguous" })]}
        loading={false}
        refreshing={false}
        error={null}
        hasMore={false}
        filter=""
        ambiguousCount={1}
        onFilterChange={() => undefined}
        onRetry={() => undefined}
        onLoadMore={() => undefined}
      />,
    );
    expect(markup).toContain(AMBIGUOUS_EXPLANATION.replaceAll("'", "&#x27;"));
  });
});
