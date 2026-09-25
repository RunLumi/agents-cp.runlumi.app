// P06 automation client contracts.
//
// Every projection under test comes from the frozen fixture
// (`docs/implementation/fixtures/p06-contracts-v1.json`) or from the frozen gate
// examples, including the negative fixtures. Nothing here is invented.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import fixture from "../../../../../docs/implementation/fixtures/p06-contracts-v1.json";
import {
  decodeAutomation,
  decodeAutomationPage,
  decodeEntitlements,
  decodeOccurrence,
  decodeOccurrencePage,
  decodeScheduleRule,
  defaultAutomationsApi,
  type AutomationDefinition,
  type Occurrence,
} from "./api";
import { ApiClientError, presentApiError } from "@/lib/errors";

const requestId = "req_0123456789abcdef0123456789abcdef";
const orgId = "org_0123456789abcdef0123456789abcdef";
const automationId = "aut_0123456789abcdef0123456789abcdef";

function response(body: unknown, status = 200): Response {
  return new Response(body === undefined ? "" : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "X-Request-ID": requestId },
  });
}

function errorResponse(status: number, code: string, reason?: string): Response {
  return new Response(
    JSON.stringify({
      error: {
        code,
        message: "provider diagnostic string that must never be rendered",
        request_id: requestId,
        details: reason ? { reason } : {},
      },
    }),
    { status, headers: { "Content-Type": "application/json", "X-Request-ID": requestId } },
  );
}

/** The full read projection the server returns for a stored definition. */
const storedAutomation: Record<string, unknown> = {
  automation_id: automationId,
  org_id: orgId,
  project_id: "prj_0123456789abcdef0123456789abcdef",
  name: "Weekday review",
  description: "Run the review agent on weekdays",
  agent_definition_id: "agd_0123456789abcdef0123456789abcdef",
  execution_principal: { kind: "user", id: "usr_0123456789abcdef0123456789abcdef" },
  target: {
    kind: "eligible_device",
    device_id: null,
    workspace_binding_id: "wsb_0123456789abcdef0123456789abcdef",
    required_capabilities: ["text"],
  },
  schedule: {
    kind: "cron",
    expression: "0 9 * * 1-5",
    timezone: "America/Los_Angeles",
    dom_dow_mode: "or",
    dst_policy: "skip_duplicate",
    overlap_policy: "skip",
    missed_policy: "run_once",
    catch_up_limit: 1,
  },
  execution_policy: {
    model_alias: "coding-default",
    budget_id: null,
    tool_policy_scope: "project",
    required_policy_version: null,
  },
  off_peak_policy: {
    schema_version: 1,
    eligibility_source: "provider_ticket",
    allowed_route_aliases: [],
    tool_constraints: {
      deny_automation_mutation: true,
      deny_recursive_off_peak: true,
      allow_background_processes: false,
    },
  },
  status: "active",
  version: 3,
  next_run_at: "2026-09-26T16:00:00.000Z",
  last_run_at: "2026-09-25T16:00:00.000Z",
  schedule_cursor_at: "2026-09-25T16:00:00.000Z",
  execution_retry: {
    max_start_attempts: 2,
    lease_ttl_seconds: 300,
    heartbeat_interval_seconds: 30,
  },
  created_by_user_id: "usr_0123456789abcdef0123456789abcdef",
  created_at: "2026-09-25T12:00:00.000Z",
  updated_at: "2026-09-25T12:00:00.000Z",
};

describe("P06 automation decoders", () => {
  it("decodes the frozen fixture definition exactly", () => {
    const automation = decodeAutomation(fixture.automation);
    expect(automation).not.toBeNull();
    expect(automation).toMatchObject({
      automation_id: automationId,
      org_id: orgId,
      name: "Weekday review",
      status: "active",
      version: 3,
    });
    // The fixture omits the fields the store only fills after the first sweep.
    expect(automation?.off_peak_policy).toBeNull();
    expect(automation?.next_run_at).toBeNull();
    expect(automation?.last_run_at).toBeNull();
    expect(automation?.created_at).toBeNull();
    expect(automation?.schedule).toMatchObject({
      kind: "cron",
      expression: "0 9 * * 1-5",
      timezone: "America/Los_Angeles",
      dom_dow_mode: "or",
      dst_policy: "skip_duplicate",
      overlap_policy: "skip",
      missed_policy: "run_once",
      catch_up_limit: 1,
    });
    expect(automation?.execution_retry).toEqual({
      max_start_attempts: 2,
      lease_ttl_seconds: 300,
      heartbeat_interval_seconds: 30,
    });
  });

  it("applies the frozen defaults when the server omits a default policy", () => {
    // The stored rule omits `overlap_policy` and `missed_policy` when they hold
    // the frozen default, so an absent value means the default.
    const automation = decodeAutomation({
      ...storedAutomation,
      schedule: { kind: "manual" },
    }) as AutomationDefinition;
    expect(automation.schedule).toEqual({
      kind: "manual",
      overlap_policy: "skip",
      missed_policy: "run_once",
      catch_up_limit: null,
    });
  });

  it("decodes every frozen schedule kind", () => {
    const kinds = [
      { kind: "manual" },
      { kind: "one_time", scheduled_at: "2026-09-25T16:00:00.000Z" },
      { kind: "cron", expression: "0 9 * * 1-5", timezone: "America/Los_Angeles" },
      {
        kind: "interval",
        every: 15,
        unit: "minutes",
        anchor_at: "2026-09-25T16:00:00.000Z",
        timezone: "UTC",
      },
    ];
    for (const schedule of kinds) {
      const automation = decodeAutomation({ ...storedAutomation, schedule });
      expect(automation?.schedule.kind).toBe((schedule as { kind: string }).kind);
    }
  });

  it("keeps interval calendar selectors bounded and optional", () => {
    const automation = decodeAutomation({
      ...storedAutomation,
      schedule: {
        kind: "interval",
        every: 1,
        unit: "months",
        anchor_at: "2026-09-25T16:00:00.000Z",
        timezone: "UTC",
        by_weekday: [1, 3, 5],
        by_monthday: [31],
        by_month: [1, 12],
      },
    });
    expect(automation?.schedule).toMatchObject({
      by_weekday: [1, 3, 5],
      by_monthday: [31],
      by_month: [1, 12],
    });
    // A weekday of 7 is not representable: cron folds 7 to 0 only in expressions.
    expect(
      decodeAutomation({
        ...storedAutomation,
        schedule: {
          kind: "interval",
          every: 1,
          unit: "weeks",
          anchor_at: "2026-09-25T16:00:00.000Z",
          timezone: "UTC",
          by_weekday: [7],
        },
      }),
    ).toBeNull();
  });

  it("rejects a schedule whose catch-up limit is missing or out of bounds", () => {
    const withSchedule = (schedule: unknown): unknown => ({ ...storedAutomation, schedule });
    expect(
      decodeAutomation(withSchedule({ kind: "manual", missed_policy: "catch_up" })),
    ).toBeNull();
    expect(
      decodeAutomation(
        withSchedule({ kind: "manual", missed_policy: "catch_up", catch_up_limit: 0 }),
      ),
    ).toBeNull();
    expect(
      decodeAutomation(
        withSchedule({ kind: "manual", missed_policy: "catch_up", catch_up_limit: 21 }),
      ),
    ).toBeNull();
    expect(
      decodeAutomation(
        withSchedule({ kind: "manual", missed_policy: "catch_up", catch_up_limit: 20 }),
      ),
    ).not.toBeNull();
  });

  it("rejects an unknown discriminant instead of guessing", () => {
    expect(decodeAutomation({ ...storedAutomation, status: "retired" })).toBeNull();
    expect(decodeAutomation({ ...storedAutomation, schedule: { kind: "rrule" } })).toBeNull();
    expect(
      decodeAutomation({
        ...storedAutomation,
        schedule: { kind: "manual", overlap_policy: "queue_all" },
      }),
    ).toBeNull();
    expect(
      decodeAutomation({
        ...storedAutomation,
        execution_retry: {
          max_start_attempts: 4,
          lease_ttl_seconds: 300,
          heartbeat_interval_seconds: 30,
        },
      }),
    ).toBeNull();
  });

  it("decodes the frozen fixture occurrence", () => {
    const occurrence = decodeOccurrence(fixture.occurrence) as Occurrence;
    expect(occurrence).toMatchObject({
      occurrence_id: "occ_0123456789abcdef0123456789abcdef",
      kind: "scheduled",
      state: "pending",
      attempt: 0,
      off_peak_mode: "normal",
      reason_code: null,
      run_id: null,
    });
    // The frozen fixture carries no `state_version`; an omitted counter is
    // reported as unknown rather than invented.
    expect(occurrence.state_version).toBeNull();
  });

  it("decodes the reduced run-now creation projection", () => {
    const occurrence = decodeOccurrence({
      occurrence_id: "occ_1123456789abcdef0123456789abcdef",
      automation_id: automationId,
      org_id: orgId,
      project_id: "prj_0123456789abcdef0123456789abcdef",
      kind: "manual",
      state: "pending",
      state_version: 1,
      attempt: 0,
      schedule_rule_id: "sch_0123456789abcdef0123456789abcdef",
      created_at: "2026-09-25T16:00:00.000Z",
    }) as Occurrence;
    expect(occurrence.kind).toBe("manual");
    expect(occurrence.scheduled_for).toBeNull();
    expect(occurrence.run_id).toBeNull();
    expect(occurrence.execution_principal).toBeNull();
  });

  it("decodes every frozen occurrence state, including ambiguous", () => {
    for (const state of [
      "pending",
      "dispatching",
      "leased",
      "started",
      "succeeded",
      "failed",
      "cancelled",
      "missed",
      "skipped",
      "ambiguous",
    ]) {
      const occurrence = decodeOccurrence({ ...fixture.occurrence, state });
      expect(occurrence?.state).toBe(state);
    }
    expect(decodeOccurrence({ ...fixture.occurrence, state: "reconciled" })).toBeNull();
  });

  it("rejects a whole page when one entry cannot be proven", () => {
    expect(
      decodeAutomationPage({
        items: [storedAutomation, { ...storedAutomation, version: 0 }],
        next_cursor: null,
        has_more: false,
      }),
    ).toBeNull();
    expect(
      decodeOccurrencePage({
        items: [{ occurrence_id: "occ_x" }],
        next_cursor: null,
        has_more: false,
      }),
    ).toBeNull();
  });

  it("decodes the frozen entitlement projection", () => {
    const entitlements = decodeEntitlements(fixture.entitlements);
    expect(entitlements).toMatchObject({
      org_id: orgId,
      plan_key: "team",
      status: "grace",
    });
    expect(entitlements?.values["automations.max_active"]).toBe(100);
    expect(entitlements?.values["webhooks.enabled"]).toBe(true);
  });
});

describe("canonical schedule decoder", () => {
  it("decodes the union without inventing a field", () => {
    expect(decodeScheduleRule(fixture.automation.schedule)).toEqual({
      kind: "cron",
      expression: "0 9 * * 1-5",
      timezone: "America/Los_Angeles",
      dom_dow_mode: "or",
      dst_policy: "skip_duplicate",
      overlap_policy: "skip",
      missed_policy: "run_once",
      catch_up_limit: 1,
    });
    // A one-time rule is a UTC instant with the frozen policies; an interval rule
    // keeps its calendar selectors nullable when the store omits them.
    expect(
      decodeScheduleRule({
        kind: "interval",
        every: 30,
        unit: "hours",
        anchor_at: "2026-09-25T16:00:00.000Z",
        timezone: "UTC",
      }),
    ).toEqual({
      kind: "interval",
      every: 30,
      unit: "hours",
      anchor_at: "2026-09-25T16:00:00.000Z",
      timezone: "UTC",
      by_weekday: null,
      by_monthday: null,
      by_month: null,
      overlap_policy: "skip",
      missed_policy: "run_once",
      catch_up_limit: null,
    });
  });

  it("rejects a rule whose required discriminant field is missing", () => {
    expect(decodeScheduleRule({ kind: "cron", timezone: "UTC" })).toBeNull();
    expect(decodeScheduleRule({ kind: "one_time" })).toBeNull();
    expect(decodeScheduleRule({ kind: "interval", every: 15, unit: "minutes" })).toBeNull();
  });
});

describe("P06 automation browser routes", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
    vi.stubGlobal("document", { cookie: "lumi_csrf=csrf-token" });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("lists definitions through the frozen org route with cursor pagination", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ items: [storedAutomation], next_cursor: "cursor-1", has_more: true }),
    );
    const page = await defaultAutomationsApi.listAutomations(orgId, {
      limit: 50,
      status: "active",
    });
    expect(page.items).toHaveLength(1);
    const [path, init] = vi.mocked(fetch).mock.calls[0] ?? [];
    expect(path).toBe(`/api/v1/orgs/${orgId}/automations?limit=50&status=active`);
    expect(init?.method).toBe("GET");
  });

  it("reads occurrence history through the frozen occurrence route", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ items: [fixture.occurrence], next_cursor: null, has_more: false }),
    );
    await defaultAutomationsApi.listOccurrences(orgId, automationId, { state: "ambiguous" });
    const [path] = vi.mocked(fetch).mock.calls[0] ?? [];
    expect(path).toBe(
      `/api/v1/orgs/${orgId}/automations/${automationId}/occurrences?limit=50&state=ambiguous`,
    );
  });

  it("sends CSRF, idempotency, and the current version for pause", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ ...storedAutomation, status: "paused", version: 4 }),
    );
    const updated = await defaultAutomationsApi.pauseAutomation(
      orgId,
      automationId,
      { version: 3 },
      "stable-pause-key",
    );
    expect(updated.status).toBe("paused");
    const [path, init] = vi.mocked(fetch).mock.calls[0] ?? [];
    expect(path).toBe(`/api/v1/orgs/${orgId}/automations/${automationId}/pause`);
    const headers = new Headers(init?.headers);
    expect(headers.get("X-CSRF-Token")).toBe("csrf-token");
    expect(headers.get("Idempotency-Key")).toBe("stable-pause-key");
    expect(init?.body).toBe(JSON.stringify({ version: 3 }));
    expect(init?.credentials).toBe("include");
  });

  it("never sends a client occurrence identity with run-now", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response(
        {
          occurrence_id: "occ_2123456789abcdef0123456789abcdef",
          automation_id: automationId,
          org_id: orgId,
          project_id: null,
          kind: "manual",
          state: "pending",
          state_version: 1,
          attempt: 0,
          schedule_rule_id: "sch_0123456789abcdef0123456789abcdef",
          created_at: "2026-09-25T16:00:00.000Z",
        },
        201,
      ),
    );
    const occurrence = await defaultAutomationsApi.runAutomationNow(
      orgId,
      automationId,
      { version: 3 },
      "stable-run-key",
    );
    expect(occurrence.occurrence_id).toBe("occ_2123456789abcdef0123456789abcdef");
    const [path, init] = vi.mocked(fetch).mock.calls[0] ?? [];
    expect(path).toBe(`/api/v1/orgs/${orgId}/automations/${automationId}/run-now`);
    expect(init?.body).toBe(JSON.stringify({ version: 3 }));
  });

  it("treats a confirmed delete as a bodyless 204", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(null, { status: 204 }));
    await expect(
      defaultAutomationsApi.deleteAutomation(
        orgId,
        automationId,
        { version: 3 },
        "stable-delete-key",
      ),
    ).resolves.toBeUndefined();
    const [, init] = vi.mocked(fetch).mock.calls[0] ?? [];
    expect(init?.method).toBe("DELETE");
  });

  it("surfaces a stale write as a version conflict without server prose", async () => {
    vi.mocked(fetch).mockResolvedValue(errorResponse(409, "version_conflict"));
    const error = await defaultAutomationsApi
      .pauseAutomation(orgId, automationId, { version: 3 }, "stale-key")
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ApiClientError);
    expect((error as ApiClientError).code).toBe("version_conflict");
    const presentation = presentApiError(error);
    expect(presentation.code).toBe("version_conflict");
    expect(presentation.message).not.toContain("provider diagnostic");
  });

  it("treats a foreign automation as the same non-disclosing not-found shape", async () => {
    vi.mocked(fetch).mockResolvedValue(
      errorResponse(404, "resource_not_found", "automation_not_found"),
    );
    const foreign = await defaultAutomationsApi
      .getAutomation(orgId, "aut_ffffffffffffffffffffffffffffffff")
      .catch((caught: unknown) => caught);
    vi.mocked(fetch).mockResolvedValue(errorResponse(404, "resource_not_found"));
    const missing = await defaultAutomationsApi
      .getAutomation(orgId, "aut_00000000000000000000000000000000")
      .catch((caught: unknown) => caught);

    const foreignPresentation = presentApiError(foreign);
    const missingPresentation = presentApiError(missing);
    expect(foreignPresentation.title).toBe(missingPresentation.title);
    expect(foreignPresentation.message).toBe(missingPresentation.message);
  });

  it("keeps a lease-partition failure as a stable code on the occurrence", () => {
    const partition = fixture.negative_fixtures.lease_partition;
    expect(partition.expected_state).toBe("ambiguous");
    expect(partition.expected_redispatch).toBe(false);
    const occurrence = decodeOccurrence({
      ...fixture.occurrence,
      state: partition.expected_state,
      reason_code: "occurrence_lease_expired",
    });
    expect(occurrence?.state).toBe("ambiguous");
    expect(occurrence?.reason_code).toBe("occurrence_lease_expired");
  });

  it("rejects a page that claims the wire shape but carries a malformed item", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({
        items: [storedAutomation, { automation_id: "aut_broken" }],
        next_cursor: null,
        has_more: false,
      }),
    );
    const error = await defaultAutomationsApi
      .listAutomations(orgId)
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ApiClientError);
    expect((error as ApiClientError).kind).toBe("invalid_response");
  });
});
