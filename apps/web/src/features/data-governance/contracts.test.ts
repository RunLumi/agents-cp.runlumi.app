/**
 * Tests for the frozen presentation rules.
 *
 * These are the honesty invariants the feature exists to keep, so they are
 * asserted directly against the rule functions rather than only through a
 * render: a "skipped" step must say why, provider data must never be counted as
 * a deletion, a completed deletion must not imply full coverage, and a download
 * must never be offered where the server would refuse a grant.
 */

import { describe, expect, it } from "vitest";

import {
  DELETION_DISCLOSURES,
  DELETION_STATE_COPY,
  EXPORT_STATE_COPY,
  LOGGING_MODE_COPY,
  RETENTION_RULES,
  SKIP_REASON_COPY,
  allowedCategories,
  canMintDownloadGrant,
  dataClassSummary,
  downloadAvailability,
  effectiveRetention,
  exportCategoryCopy,
  formatWindow,
  jobFailureCopy,
  mergeDisclosures,
  needsAttentionReason,
  presentDataError,
  presentDeletionStep,
  readClassResults,
  readReferenceCoverage,
  tallySteps,
} from "./contracts";
import { DELETION_STATES, EXPORT_STATES, type DeletionStep } from "./api";
import { ApiClientError } from "@/lib/errors";

function step(overrides: Partial<DeletionStep> = {}): DeletionStep {
  return {
    id: "dts_0123456789abcdef0123456789abcdef",
    data_class: "membership",
    reference_kind: "database_row",
    object_reference: "mem_0123456789abcdef0123456789abcdef",
    state: "succeeded",
    attempt: 1,
    failure_code: null,
    skip_reason: null,
    unmapped_skip_reason: null,
    completed_at: "2026-09-25T12:01:00.000Z",
    ...overrides,
  };
}

describe("logging mode copy", () => {
  it("makes metadata-only the default and says what it contains", () => {
    const copy = LOGGING_MODE_COPY.metadata_only;
    expect(copy.label).toBe("Metadata only");
    expect(copy.selectable).toBe(true);
    expect(copy.includes).toMatch(/Identifiers, versions, state, counts/);
  });

  it("prohibits raw content in every mode, not only in metadata-only", () => {
    for (const mode of ["metadata_only", "redacted_content", "full_content"] as const) {
      expect(LOGGING_MODE_COPY[mode].doesNot).toMatch(
        /prompt|response|argument|credential|secret/i,
      );
    }
  });

  it("describes full content as audited and not self-service, and does not offer it", () => {
    const copy = LOGGING_MODE_COPY.full_content;
    expect(copy.selectable).toBe(false);
    expect(copy.summary).toMatch(/audited, time-bounded/i);
    expect(copy.doesNot).toMatch(/never widens a class's field allowlist/i);
    expect(copy.doesNot).toMatch(/never changes the normal event, audit, webhook, or log schemas/i);
    expect(copy.unavailableReason).toBeTruthy();
  });

  it("says a content mode does not widen an allowlist", () => {
    expect(LOGGING_MODE_COPY.redacted_content.doesNot).toMatch(/widens no data class/i);
  });
});

describe("retention rules", () => {
  it("states the shorten-only rule and the legal maximum rule", () => {
    expect(RETENTION_RULES[0].title).toMatch(/shorten retention\. It cannot extend it/i);
    expect(RETENTION_RULES[0].body).toMatch(/refused unless an audited override exists/i);
    expect(RETENTION_RULES[1].body).toMatch(/legal maximum/i);
    expect(RETENTION_RULES[2].title).toMatch(/legal hold suspends expiry/i);
    expect(RETENTION_RULES[2].body).toMatch(/not expired and not deleted/i);
  });

  it("marks upstream provider data as not Lumi-deletable", () => {
    const external = dataClassSummary("upstream_provider_data");
    expect(external?.owner).toBe("external");
    expect(external?.deletionBehavior).toMatch(/not Lumi-deletable/i);
    expect(external?.overridable).toBe(false);
  });

  it("marks secret material as never exported and not overridable", () => {
    const secret = dataClassSummary("secret");
    expect(secret?.exportBehavior).toMatch(/never exported/i);
    expect(secret?.deletionBehavior).toMatch(/revoke and delete ciphertext/i);
    expect(secret?.overridable).toBe(false);
  });

  it("resolves an override as a shortened window beside the baseline", () => {
    const shortened = effectiveRetention("notification", { notification: 604_800 });
    expect(shortened?.source).toBe("policy_override");
    expect(shortened?.human).toBe("7 days");
    expect(shortened?.shortened).toBe(true);

    const baseline = effectiveRetention("notification", {});
    expect(baseline?.source).toBe("default");
    expect(baseline?.human).toBe("30 days");
  });

  it("returns nothing for an undeclared class rather than inventing a window", () => {
    expect(effectiveRetention("not_a_class", {})).toBeNull();
    expect(dataClassSummary("not_a_class")).toBeNull();
  });

  it("formats windows in the largest honest unit", () => {
    expect(formatWindow(86_400)).toBe("1 day");
    expect(formatWindow(604_800)).toBe("7 days");
    expect(formatWindow(900)).toBe("15 minutes");
    expect(formatWindow(31_536_000)).toBe("1 year");
  });
});

describe("export categories", () => {
  it("lets an organization request every category", () => {
    expect(allowedCategories("organization")).toHaveLength(8);
  });

  it("restricts a personal export to the account-scoped categories", () => {
    expect(allowedCategories("user")).toEqual(["identity", "notifications", "data_governance"]);
  });

  it("explains why a tenant category is not in a personal export", () => {
    for (const key of [
      "organization",
      "devices",
      "runs_metadata",
      "usage_billing",
      "audit_redacted",
    ] as const) {
      const copy = exportCategoryCopy(key);
      expect(copy?.personal).toBe(false);
      expect(copy?.personalNote).toBeTruthy();
    }
  });
});

describe("export state presentation", () => {
  it("describes every frozen state", () => {
    for (const state of EXPORT_STATES) {
      expect(EXPORT_STATE_COPY[state].label.length).toBeGreaterThan(0);
      expect(EXPORT_STATE_COPY[state].body.length).toBeGreaterThan(0);
    }
  });

  it("says only ready may mint a grant", () => {
    expect(EXPORT_STATES.filter(canMintDownloadGrant)).toEqual(["ready"]);
  });

  it("states that a retry resumes the same manifest and cutoff", () => {
    expect(EXPORT_STATE_COPY.retry_wait.body).toMatch(
      /same manifest and the same snapshot cutoff/i,
    );
  });

  it("states that an expired artifact needs a new request", () => {
    expect(EXPORT_STATE_COPY.expired.body).toMatch(/no longer downloadable/i);
  });

  it("refuses a download before ready with a reason", () => {
    const availability = downloadAvailability({
      state: "verifying",
      serverDownloadable: true,
      artifactExpiresAt: "2099-01-01T00:00:00.000Z",
      now: new Date("2026-09-25T12:00:00.000Z"),
    });
    expect(availability.available).toBe(false);
    expect(availability.reason).toMatch(/only a ready export can mint a download grant/i);
  });

  it("refuses a download whose artifact expiry has passed", () => {
    const availability = downloadAvailability({
      state: "ready",
      serverDownloadable: true,
      artifactExpiresAt: "2026-09-25T11:00:00.000Z",
      now: new Date("2026-09-25T12:00:00.000Z"),
    });
    expect(availability.available).toBe(false);
    expect(availability.reason).toMatch(/passed its expiry/i);
  });

  it("refuses a download the server did not mark as downloadable", () => {
    const availability = downloadAvailability({
      state: "ready",
      serverDownloadable: false,
      artifactExpiresAt: "2099-01-01T00:00:00.000Z",
      now: new Date("2026-09-25T12:00:00.000Z"),
    });
    expect(availability.available).toBe(false);
    expect(availability.reason).toMatch(/not available for download/i);
  });

  it("refuses a download when the expiry cannot be read", () => {
    const availability = downloadAvailability({
      state: "ready",
      serverDownloadable: true,
      artifactExpiresAt: null,
      now: new Date("2026-09-25T12:00:00.000Z"),
    });
    expect(availability.available).toBe(false);
  });

  it("offers a download for a live ready artifact", () => {
    const availability = downloadAvailability({
      state: "ready",
      serverDownloadable: true,
      artifactExpiresAt: "2026-09-26T12:00:00.000Z",
      now: new Date("2026-09-25T12:00:00.000Z"),
    });
    expect(availability.available).toBe(true);
    expect(availability.reason).toBe("");
  });
});

describe("deletion state presentation", () => {
  it("describes every frozen state", () => {
    for (const state of DELETION_STATES) {
      expect(DELETION_STATE_COPY[state].label.length).toBeGreaterThan(0);
      expect(DELETION_STATE_COPY[state].body.length).toBeGreaterThan(0);
    }
  });

  it("says completion is not the same as having covered everything", () => {
    expect(DELETION_STATE_COPY.completed.body).toMatch(
      /completion is not the same as having touched everything/i,
    );
  });

  it("says a parked job is never retried by itself", () => {
    expect(DELETION_STATE_COPY.needs_attention.body).toMatch(/will not retry on its own/i);
  });
});

describe("needs_attention reasons", () => {
  it("maps the three real reasons the gate names", () => {
    expect(needsAttentionReason("deletion_legal_hold")).toBe("legal_hold");
    expect(needsAttentionReason("deletion_reference_system_absent")).toBe(
      "unresolved_external_reference",
    );
    expect(needsAttentionReason("deletion_executor_unavailable")).toBe("exhausted_retries");
    expect(needsAttentionReason("deletion_step_failed")).toBe("exhausted_retries");
  });

  it("fails closed on an unrecognized or missing reason", () => {
    expect(needsAttentionReason("something_new")).toBe("unknown");
    expect(needsAttentionReason(null)).toBe("unknown");
  });

  it("says a legal hold blocks the resume rather than silently refusing it", () => {
    // A held job parked; the UI must explain why, not just disable a button.
    expect(needsAttentionReason("deletion_legal_hold")).toBe("legal_hold");
  });
});

describe("deletion step presentation", () => {
  it("calls a step a deletion only when it succeeded against a Lumi-owned store", () => {
    const presentation = presentDeletionStep(step());
    expect(presentation.deleted).toBe(true);
    expect(presentation.claim).toBe("Removed from a store Lumi owns.");
  });

  it("never calls an upstream provider step a deletion", () => {
    const presentation = presentDeletionStep(
      step({
        data_class: "upstream_provider_data",
        reference_kind: "upstream_provider_data",
        state: "skipped",
        skip_reason: "deletion_not_lumi_owned",
        object_reference: "upstream_provider:org_1",
      }),
    );
    expect(presentation.deleted).toBe(false);
    expect(presentation.claim).toBe("Not deleted.");
    expect(presentation.ownership).toBe("not_lumi_owned");
    expect(presentation.reason).toMatch(/does not own/i);
  });

  it("never calls a local device step a deletion", () => {
    const presentation = presentDeletionStep(
      step({
        reference_kind: "local_device_data",
        state: "skipped",
        skip_reason: "deletion_not_lumi_owned",
      }),
    );
    expect(presentation.deleted).toBe(false);
    expect(presentation.reason).toMatch(/does not own/i);
  });

  it("gives every skip reason its own stated reason", () => {
    expect(SKIP_REASON_COPY.deletion_legal_hold.body).toMatch(/legal hold/i);
    expect(SKIP_REASON_COPY.retained_legal_only.body).toMatch(/outlive deletion/i);
    expect(SKIP_REASON_COPY.deletion_not_lumi_owned.body).toMatch(/does not own/i);
    expect(SKIP_REASON_COPY.deletion_reference_system_absent.body).toMatch(
      /not part of this control plane/i,
    );
    for (const reason of Object.keys(SKIP_REASON_COPY) as Array<keyof typeof SKIP_REASON_COPY>) {
      expect(SKIP_REASON_COPY[reason].lumiDeleted).toBe(false);
      expect(SKIP_REASON_COPY[reason].label.length).toBeGreaterThan(0);
      expect(SKIP_REASON_COPY[reason].body.length).toBeGreaterThan(0);
    }
  });

  it("states a missing skip reason rather than implying a deletion", () => {
    const presentation = presentDeletionStep(step({ state: "skipped", skip_reason: null }));
    expect(presentation.deleted).toBe(false);
    expect(presentation.reason).toMatch(/no skip reason/i);
  });

  it("shows an unrecognized skip reason as a code, not as prose", () => {
    const presentation = presentDeletionStep(
      step({ state: "skipped", skip_reason: null, unmapped_skip_reason: "deletion_reason_2099" }),
    );
    expect(presentation.reason).toContain("deletion_reason_2099");
    expect(presentation.deleted).toBe(false);
  });

  it("refuses to call a succeeded step a deletion when ownership is unknown", () => {
    const presentation = presentDeletionStep(step({ reference_kind: null }));
    expect(presentation.deleted).toBe(false);
    expect(presentation.ownership).toBe("not_established");
  });

  it("does not count an open step as deleted", () => {
    expect(presentDeletionStep(step({ state: "pending", completed_at: null })).deleted).toBe(false);
    expect(
      presentDeletionStep(step({ state: "failed", failure_code: "deletion_step_failed" })).deleted,
    ).toBe(false);
  });

  it("tallies deleted, skipped, retained, and not-Lumi-owned separately", () => {
    const tally = tallySteps([
      step(),
      step({
        data_class: "run",
        reference_kind: "local_device_data",
        state: "skipped",
        skip_reason: "deletion_not_lumi_owned",
      }),
      step({
        data_class: "upstream_provider_data",
        reference_kind: "upstream_provider_data",
        state: "skipped",
        skip_reason: "deletion_not_lumi_owned",
      }),
      step({
        data_class: "audit_security_event",
        state: "skipped",
        skip_reason: "retained_legal_only",
      }),
      step({ data_class: "invoice_request", state: "skipped", skip_reason: "deletion_legal_hold" }),
      step({ data_class: "export_job", state: "pending", completed_at: null }),
    ]);

    expect(tally.total).toBe(6);
    expect(tally.deleted).toBe(1);
    expect(tally.skipped).toBe(4);
    expect(tally.retained).toBe(2);
    expect(tally.notLumiOwned).toBe(2);
    expect(tally.open).toBe(1);
  });
});

describe("certificate coverage", () => {
  it("reports incomplete coverage when a named system was not traversed", () => {
    const coverage = readReferenceCoverage({
      reference_coverage: {
        traversed: ["database_row", "r2_object"],
        pending: ["cache", "search_index"],
        absent_reason: "deletion_reference_system_absent",
      },
    });

    expect(coverage.complete).toBe(false);
    expect(coverage.traversed).toEqual(["database_row", "r2_object"]);
    expect(coverage.pending).toEqual(["cache", "search_index"]);
    expect(coverage.absentReason).toBe("deletion_reference_system_absent");
  });

  it("does not read an absent coverage block as full coverage", () => {
    const coverage = readReferenceCoverage({ export_artifact: { succeeded: 1 } });
    expect(coverage.complete).toBe(false);
    expect(coverage.traversed).toEqual([]);
  });

  it("is complete only when something was traversed and nothing is pending", () => {
    expect(
      readReferenceCoverage({ reference_coverage: { traversed: ["database_row"], pending: [] } })
        .complete,
    ).toBe(true);
    expect(
      readReferenceCoverage({ reference_coverage: { traversed: [], pending: [] } }).complete,
    ).toBe(false);
  });

  it("reads per-class counts and leaves the non-class keys out", () => {
    const rows = readClassResults({
      export_artifact: { succeeded: 2, failed: 1 },
      reference_coverage: { traversed: [], pending: [] },
      disclosures: [],
      organization_row: "deletion_org_row_managed_by_lifecycle",
    });

    expect(rows).toHaveLength(1);
    expect(rows[0]?.dataClass).toBe("export_artifact");
    expect(rows[0]?.counts).toEqual([
      { state: "failed", count: 1 },
      { state: "succeeded", count: 2 },
    ]);
  });
});

describe("disclosures", () => {
  it("keeps the three frozen statements even when the server omits them", () => {
    const merged = mergeDisclosures([]);
    for (const statement of DELETION_DISCLOSURES) {
      expect(merged).toContain(statement);
    }
  });

  it("puts the server's own statements first and de-duplicates", () => {
    const merged = mergeDisclosures([
      "A server-specific statement.",
      DELETION_DISCLOSURES[0] ?? "",
    ]);
    expect(merged[0]).toBe("A server-specific statement.");
    expect(merged.filter((item) => item === DELETION_DISCLOSURES[0])).toHaveLength(1);
  });

  it("names provider and device data as things Lumi does not delete", () => {
    expect(mergeDisclosures(null).join(" ")).toMatch(/ZCode hosts is deleted on the host/);
    expect(mergeDisclosures(null).join(" ")).toMatch(/Lumi cannot delete it/);
  });
});

describe("job failure copy", () => {
  it("explains a retryable failure without claiming a deletion", () => {
    expect(jobFailureCopy("store_unavailable")?.body).toMatch(/Nothing is known to be deleted/i);
  });

  it("explains a legal hold as a block, not a failure of the job", () => {
    expect(jobFailureCopy("deletion_legal_hold")?.body).toMatch(/audited release/i);
  });

  it("fails closed on an unknown code", () => {
    const copy = jobFailureCopy("deletion_code_from_the_future");
    expect(copy?.label).toMatch(/Unrecognized/i);
    expect(copy?.body).toMatch(/does not recognize/i);
  });

  it("returns nothing when there is no failure", () => {
    expect(jobFailureCopy(null)).toBeNull();
  });
});

describe("data error presentation", () => {
  it("maps a stable P06 reason from details onto frozen copy", () => {
    const presentation = presentDataError(
      new ApiClientError({
        code: "conflict",
        kind: "api",
        status: 409,
        requestId: "req_1",
        details: { reason: "data_policy_version_conflict" },
        retryable: false,
      }),
    );

    expect(presentation.title).toBe("The policy changed");
    expect(presentation.code).toBe("data_policy_version_conflict");
    expect(presentation.message).toMatch(/Reload it/i);
  });

  it("explains a legal maximum refusal instead of showing the server text", () => {
    const presentation = presentDataError(
      new ApiClientError({
        code: "validation_failed",
        kind: "api",
        status: 422,
        requestId: "req_1",
        details: { reason: "data_policy_retention_over_legal_maximum" },
        retryable: false,
      }),
    );

    expect(presentation.title).toBe("Beyond the legal maximum");
    expect(presentation.message).toMatch(/cannot be extended past the class maximum/i);
  });

  it("states the organization-exit requirement for an account deletion", () => {
    const presentation = presentDataError(
      new ApiClientError({
        code: "conflict",
        kind: "api",
        status: 409,
        requestId: "req_1",
        details: { reason: "deletion_requires_org_exit" },
        retryable: false,
      }),
    );

    expect(presentation.title).toBe("Leave or transfer organizations first");
    expect(presentation.message).toMatch(/Leave or transfer every organization/i);
  });

  it("falls back to the shared presenter for an unknown failure", () => {
    const presentation = presentDataError(new Error("boom"));
    expect(presentation.title).toBe("Something went wrong");
    expect(presentation.message).not.toContain("boom");
  });
});
