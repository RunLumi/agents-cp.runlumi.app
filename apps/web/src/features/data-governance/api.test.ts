/**
 * P06 data-governance client tests.
 *
 * The wire shapes here are copied from the IMPLEMENTED backend projections —
 * `policy_json`, `export_json`, `deletion_json`, `deletion_detail_json`, and the
 * two `negative_fixtures` cases — rather than from a hand-written guess, so a
 * decoder that drifts from the server fails here rather than in the browser.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import fixture from "../../../../../docs/implementation/fixtures/p06-contracts-v1.json";

import {
  DataGovernanceContractError,
  DEFAULT_EXPORT_EXPIRY_SECONDS,
  DELETION_CONFIRMATION_PHRASE,
  EXPORT_CATEGORIES,
  EXPORT_CONFIRMATION_PHRASE,
  EXPORT_STATES,
  DELETION_STATES,
  decodeDataGovernancePolicy,
  decodeDeletionJob,
  decodeExportJob,
  decodePersonalDeletionStatus,
  decodeReauthGrant,
  defaultDataGovernanceApi,
  downloadExportArtifact,
  isSafeDownloadPath,
  mintReauthGrant,
  resolveDownloadPath,
} from "./api";
import { ApiClientError } from "@/lib/errors";

/**
 * Synthetic stand-in for a reauthentication grant value. Not a credential: the
 * tests only prove the client forwards whatever the server minted, so the exact
 * value is arbitrary and this keeps it obviously so.
 */
const REAUTH_VALUE = "reauth-value";

const ORG_ID = "org_0123456789abcdef0123456789abcdef";
const EXPORT_ID = "exp_0123456789abcdef0123456789abcdef";
const DELETION_ID = "del_0123456789abcdef0123456789abcdef";
const USER_ID = "usr_0123456789abcdef0123456789abcdef";
const REQUEST_ID = "req_0123456789abcdef0123456789abcdef";

/** `policy_json` for a persisted policy, field-for-field. */
function policyWire(overrides: Record<string, unknown> = {}) {
  return {
    policy_id: "dgp_0123456789abcdef0123456789abcdef",
    persisted: true,
    org_id: ORG_ID,
    project_id: null,
    logging_mode: "metadata_only",
    class_retention_overrides: { notification: 604_800 },
    legal_hold: false,
    legal_hold_reason: null,
    legal_hold_placed_at: null,
    legal_hold_released_at: null,
    legal_hold_released_by: null,
    backup_lifecycle: "platform_35_day_expiry",
    provider_retention_disclosure: "external_policy",
    provider_retention_url: null,
    default_export_expiry_seconds: 86_400,
    version: 2,
    created_at: "2026-09-01T09:00:00.000Z",
    updated_at: "2026-09-25T12:00:00.000Z",
    ...overrides,
  };
}

/** `export_json` for a ready organization export. */
function exportWire(overrides: Record<string, unknown> = {}) {
  return {
    id: EXPORT_ID,
    org_id: ORG_ID,
    scope_type: "organization",
    scope_id: ORG_ID,
    categories: ["devices", "identity"],
    format: "json",
    snapshot_cutoff_at: "2026-09-25T12:00:00.000Z",
    state: "ready",
    state_version: 4,
    attempt: 1,
    next_attempt_at: null,
    requested_by: USER_ID,
    requested_at: "2026-09-25T12:00:00.000Z",
    ready_at: "2026-09-25T12:00:03.000Z",
    finished_at: null,
    failure_code: null,
    downloadable: true,
    artifact: {
      content_type: "application/json",
      size_bytes: 42,
      expires_at: "2026-09-26T12:00:00.000Z",
      download_path: `/api/v1/orgs/{org_id}/exports/${EXPORT_ID}/download`,
    },
    version: 1,
    updated_at: "2026-09-25T12:00:03.000Z",
    disclosures: ["Lumi retention applies to Lumi-managed records only."],
    ...overrides,
  };
}

/** `deletion_json` plus the detail route's `steps` and `certificate`. */
function deletionWire(overrides: Record<string, unknown> = {}) {
  return {
    id: DELETION_ID,
    org_id: ORG_ID,
    target_type: "organization",
    target_id: ORG_ID,
    state: "needs_attention",
    state_version: 3,
    attempt: 1,
    next_attempt_at: null,
    grace_expires_at: null,
    cutoff_at: "2026-09-25T12:00:00.000Z",
    fenced: true,
    legal_hold: false,
    failure_code: "deletion_legal_hold",
    certificate_id: null,
    resumable: true,
    requested_by: USER_ID,
    created_at: "2026-09-25T12:00:00.000Z",
    updated_at: "2026-09-25T12:05:00.000Z",
    completed_at: null,
    version: 4,
    disclosures: [
      "Lumi retention applies to Lumi-managed records only.",
      "Data on managed devices and ZCode hosts is deleted on the host, not by this cloud job.",
      "Upstream AI provider data is governed by the provider's own retention and data-use policy; Lumi cannot delete it.",
    ],
    steps: [
      {
        id: "dts_0123456789abcdef0123456789abcdef",
        data_class: "upstream_provider_data",
        reference_kind: "upstream_provider_data",
        object_reference: `upstream_provider:${ORG_ID}`,
        state: "skipped",
        attempt: 0,
        failure_code: null,
        skip_reason: "deletion_not_lumi_owned",
        completed_at: "2026-09-25T12:01:00.000Z",
      },
    ],
    certificate: null,
    ...overrides,
  };
}

describe("data policy decoding", () => {
  it("decodes the frozen fixture policy field-for-field", () => {
    const policy = decodeDataGovernancePolicy({
      ...fixture.data_policy,
      policy_id: "dgp_0123456789abcdef0123456789abcdef",
      persisted: true,
      created_at: "2026-09-01T09:00:00.000Z",
      updated_at: "2026-09-25T12:00:00.000Z",
      version: 1,
      class_retention_overrides: {},
    });

    expect(policy.logging_mode).toBe("metadata_only");
    expect(policy.class_retention_overrides).toEqual({});
    expect(policy.legal_hold).toBe(false);
    expect(policy.backup_lifecycle).toBe("platform_35_day_expiry");
    expect(policy.provider_retention_disclosure).toBe("external_policy");
    expect(policy.default_export_expiry_seconds).toBe(DEFAULT_EXPORT_EXPIRY_SECONDS);
  });

  it("accepts the baseline projection an organization has never edited", () => {
    // `policy_json` for a policy with no persisted row: `policy_id` is null,
    // `persisted` is false, and the version is still 1 so the first PATCH works.
    const policy = decodeDataGovernancePolicy(
      policyWire({
        policy_id: null,
        persisted: false,
        class_retention_overrides: {},
        version: 1,
      }),
    );

    expect(policy.policy_id).toBeNull();
    expect(policy.persisted).toBe(false);
    expect(policy.version).toBe(1);
  });

  it("reads a legal hold with its reason, placement, and attribution", () => {
    const policy = decodeDataGovernancePolicy(
      policyWire({
        legal_hold: true,
        legal_hold_reason: "litigation hold",
        legal_hold_placed_at: "2026-09-20T10:00:00.000Z",
        legal_hold_released_at: "2026-09-24T10:00:00.000Z",
        legal_hold_released_by: USER_ID,
      }),
    );

    expect(policy.legal_hold).toBe(true);
    expect(policy.legal_hold_reason).toBe("litigation hold");
    expect(policy.legal_hold_released_by).toBe(USER_ID);
  });

  it("rejects an undeclared data class key in the override map", () => {
    expect(() =>
      decodeDataGovernancePolicy(policyWire({ class_retention_overrides: { "Not A Class": 60 } })),
    ).toThrow(DataGovernanceContractError);
  });

  it("rejects a non-integer retention window rather than rounding it", () => {
    expect(() =>
      decodeDataGovernancePolicy(policyWire({ class_retention_overrides: { notification: 60.5 } })),
    ).toThrow(DataGovernanceContractError);
  });

  it("rejects an unknown logging mode instead of guessing one", () => {
    expect(() => decodeDataGovernancePolicy(policyWire({ logging_mode: "everything" }))).toThrow(
      DataGovernanceContractError,
    );
  });

  it("rejects a policy version that is not a positive integer", () => {
    expect(() => decodeDataGovernancePolicy(policyWire({ version: 0 }))).toThrow(
      DataGovernanceContractError,
    );
  });
});

describe("export job decoding", () => {
  it("decodes a ready organization export field-for-field", () => {
    const job = decodeExportJob(exportWire());

    expect(job).toMatchObject({
      id: EXPORT_ID,
      org_id: ORG_ID,
      scope_type: "organization",
      scope_id: ORG_ID,
      format: "json",
      state: "ready",
      state_version: 4,
      attempt: 1,
      requested_by: USER_ID,
      downloadable: true,
      version: 1,
    });
    expect(job.categories).toEqual(["identity", "devices"]);
    expect(job.artifact?.expires_at).toBe("2026-09-26T12:00:00.000Z");
    expect(job.artifact?.download_path).toBe(`/api/v1/orgs/{org_id}/exports/${EXPORT_ID}/download`);
  });

  it("never carries an object key, a bucket name, or an absolute URL", () => {
    // The backend asserts the same thing: the projection must not expose the
    // private object handle, because a browser client has no business holding it.
    const rendered = JSON.stringify(decodeExportJob(exportWire()));
    expect(rendered).not.toContain("object_key");
    expect(rendered).not.toContain("lumi-export-artifacts");
    expect(rendered).not.toContain("http");
  });

  it("reports every frozen export state, and only ready is downloadable", () => {
    for (const state of EXPORT_STATES) {
      const job = decodeExportJob(exportWire({ state, downloadable: state === "ready" }));
      expect(job.state).toBe(state);
    }
    expect(EXPORT_STATES.filter((state) => state === "ready")).toEqual(["ready"]);
  });

  it("drops the artifact for a deleted object and never advertises it", () => {
    const job = decodeExportJob(exportWire({ downloadable: false, artifact: null }));
    expect(job.artifact).toBeNull();
    expect(job.downloadable).toBe(false);
  });

  it("surfaces a category this build does not recognize instead of hiding it", () => {
    const job = decodeExportJob(exportWire({ categories: ["identity", "quantum_archive"] }));

    expect(job.categories).toEqual(["identity"]);
    expect(job.unrecognized_categories).toEqual(["quantum_archive"]);
  });

  it("decodes a personal export fixture from the negative-case block", () => {
    const personal = fixture.negative_fixtures.personal_export as {
      scope_type: string;
      categories: string[];
      requires_reauthentication: boolean;
      download_state: string;
    };
    expect(personal.scope_type).toBe("user");
    expect(personal.categories).toEqual(["identity", "notifications"]);
    expect(personal.requires_reauthentication).toBe(true);
    expect(personal.download_state).toBe("ready");

    const job = decodeExportJob(
      exportWire({
        org_id: null,
        scope_type: "user",
        scope_id: USER_ID,
        categories: personal.categories,
        state: personal.download_state,
      }),
    );
    expect(job.org_id).toBeNull();
    expect(job.scope_type).toBe("user");
  });

  it("refuses an absolute or off-namespace download path", () => {
    expect(() =>
      decodeExportJob(
        exportWire({
          artifact: {
            content_type: "application/json",
            size_bytes: 1,
            expires_at: "2026-09-26T12:00:00.000Z",
            download_path: "https://exports.example/exp.json",
          },
        }),
      ),
    ).toThrow(DataGovernanceContractError);
  });
});

describe("deletion job decoding", () => {
  it("decodes the frozen legal-hold fixture field-for-field", () => {
    const legalHold = fixture.negative_fixtures.legal_hold as {
      deletion_id: string;
      state: string;
      reason: string;
      resume_requires: string;
    };
    expect(legalHold.deletion_id).toBe(DELETION_ID);
    expect(legalHold.state).toBe("needs_attention");
    expect(legalHold.reason).toBe("deletion_legal_hold");
    expect(legalHold.resume_requires).toBe("audited_support_release");

    const job = decodeDeletionJob(deletionWire());
    expect(job.state).toBe("needs_attention");
    expect(job.failure_code).toBe("deletion_legal_hold");
    expect(job.resumable).toBe(true);
    expect(job.fenced).toBe(true);
  });

  it("decodes every frozen deletion state", () => {
    for (const state of DELETION_STATES) {
      expect(decodeDeletionJob(deletionWire({ state })).state).toBe(state);
    }
  });

  it("keeps a skipped step's reason and its non-Lumi-owned reference", () => {
    const job = decodeDeletionJob(deletionWire());
    const step = job.steps[0];

    expect(step?.data_class).toBe("upstream_provider_data");
    expect(step?.reference_kind).toBe("upstream_provider_data");
    expect(step?.state).toBe("skipped");
    expect(step?.skip_reason).toBe("deletion_not_lumi_owned");
    expect(step?.unmapped_skip_reason).toBeNull();
    expect(step?.object_reference).toBe(`upstream_provider:${ORG_ID}`);
  });

  it("keeps an unrecognized skip reason visible instead of dropping it", () => {
    const job = decodeDeletionJob(
      deletionWire({
        steps: [
          {
            id: "dts_0123456789abcdef0123456789abcdef",
            data_class: "run",
            reference_kind: "database_row",
            object_reference: "run_0123456789abcdef0123456789abcdef",
            state: "skipped",
            attempt: 0,
            failure_code: null,
            skip_reason: "deletion_reason_from_the_future",
            completed_at: null,
          },
        ],
      }),
    );

    expect(job.steps[0]?.skip_reason).toBeNull();
    expect(job.steps[0]?.unmapped_skip_reason).toBe("deletion_reason_from_the_future");
  });

  it("treats an unknown reference kind as not established rather than owned", () => {
    const job = decodeDeletionJob(
      deletionWire({
        steps: [
          {
            id: "dts_0123456789abcdef0123456789abcdef",
            data_class: "artifact",
            reference_kind: "quantum_store",
            object_reference: "artifact_0123456789abcdef0123456789abcdef",
            state: "succeeded",
            attempt: 1,
            failure_code: null,
            skip_reason: null,
            completed_at: "2026-09-25T12:01:00.000Z",
          },
        ],
      }),
    );

    expect(job.steps[0]?.reference_kind).toBeNull();
  });

  it("refuses an object reference that is really a URL", () => {
    expect(() =>
      decodeDeletionJob(
        deletionWire({
          steps: [
            {
              id: "dts_0123456789abcdef0123456789abcdef",
              data_class: "export_artifact",
              reference_kind: "r2_object",
              object_reference: "https://exports.example/object",
              state: "succeeded",
              attempt: 1,
              failure_code: null,
              skip_reason: null,
              completed_at: null,
            },
          ],
        }),
      ),
    ).toThrow(DataGovernanceContractError);
  });

  it("decodes the certificate coverage and retained legal classes", () => {
    const job = decodeDeletionJob(
      deletionWire({
        state: "completed",
        resumable: false,
        failure_code: null,
        certificate: {
          id: "delc_0123456789abcdef0123456789abcdef",
          scope_type: "organization",
          scope_id: ORG_ID,
          class_results: {
            export_artifact: { succeeded: 1 },
            audit_security_event: { skipped: 1 },
            reference_coverage: { traversed: ["database_row", "r2_object"], pending: ["cache"] },
          },
          retained_legal_classes: ["audit_security_event"],
          completed_at: "2026-09-25T12:10:00.000Z",
          expires_at: "2027-09-25T12:10:00.000Z",
        },
      }),
    );

    expect(job.certificate?.retained_legal_classes).toEqual(["audit_security_event"]);
    const coverage = job.certificate?.class_results["reference_coverage"] as {
      pending: string[];
    };
    expect(coverage.pending).toEqual(["cache"]);
  });

  it("decodes the none answer for a personal deletion that does not exist", () => {
    const status = decodePersonalDeletionStatus({
      state: "none",
      grace_expires_at: null,
      disclosures: ["Lumi retention applies to Lumi-managed records only."],
    });

    expect(status.state).toBe("none");
    expect(status.grace_expires_at).toBeNull();
    expect(status.disclosures).toHaveLength(1);
  });

  it("refuses to read a personal deletion status that is not none", () => {
    expect(() => decodePersonalDeletionStatus({ state: "deleting" })).toThrow(
      DataGovernanceContractError,
    );
  });
});

describe("download path resolution", () => {
  it("resolves the published path against the scope the caller already authorized", () => {
    const published = `/api/v1/orgs/{org_id}/exports/${EXPORT_ID}/download`;
    expect(resolveDownloadPath({ kind: "org", orgId: ORG_ID }, EXPORT_ID, published)).toBe(
      `/api/v1/orgs/${ORG_ID}/exports/${EXPORT_ID}/download`,
    );
    expect(resolveDownloadPath({ kind: "me" }, EXPORT_ID, null)).toBe(
      `/api/v1/me/data/exports/${EXPORT_ID}/download`,
    );
  });

  it("falls back to a locally built path rather than trusting a bad value", () => {
    expect(resolveDownloadPath({ kind: "me" }, EXPORT_ID, "https://evil.example/x")).toBe(
      `/api/v1/me/data/exports/${EXPORT_ID}/download`,
    );
  });

  it("classifies which paths are safe to hand to a browser", () => {
    expect(isSafeDownloadPath("/api/v1/me/data/exports/exp_1/download")).toBe(true);
    expect(isSafeDownloadPath("//evil.example/x")).toBe(false);
    expect(isSafeDownloadPath("/api/v1/../../etc/passwd")).toBe(false);
    expect(isSafeDownloadPath("javascript:alert(1)")).toBe(false);
  });
});

describe("reauthentication grant", () => {
  it("mints a grant for the purpose the P06 routes consume", async () => {
    vi.stubGlobal("fetch", vi.fn());
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({
        grant_id: "rag_0123456789abcdef0123456789abcdef",
        token: REAUTH_VALUE,
        expires_at: "2026-09-25T12:15:00.000Z",
      }),
    );

    const grant = await mintReauthGrant();

    expect(grant.grant_id).toBe("rag_0123456789abcdef0123456789abcdef");
    const [, init] = vi.mocked(fetch).mock.calls[0] ?? [];
    const body: unknown = JSON.parse(init?.body as string);
    // The P06 routes consume the existing P02 `org_lifecycle` grant.
    expect(body).toEqual({ purpose: "org_lifecycle" });
  });

  it("rejects a grant response that does not carry a token", () => {
    expect(() => decodeReauthGrant({ grant_id: "rag_1" })).toThrow(DataGovernanceContractError);
  });
});

describe("data-governance client transport", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("reads the frozen policy route", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(policyWire()));

    const policy = await defaultDataGovernanceApi().getPolicy(ORG_ID);

    expect(policy.version).toBe(2);
    expect(fetch).toHaveBeenCalledWith(
      `/api/v1/orgs/${ORG_ID}/data-policy`,
      expect.objectContaining({ method: "GET", credentials: "include" }),
    );
  });

  it("sends the current version and an idempotency key on a policy patch", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(policyWire({ version: 3 })));

    await defaultDataGovernanceApi().updatePolicy(
      ORG_ID,
      { version: 2, logging_mode: "redacted_content" },
      "idem-policy",
    );

    const [, init] = vi.mocked(fetch).mock.calls[0] ?? [];
    const headers = (init?.headers ?? new Headers()) as Headers;
    expect(headers.get("Idempotency-Key")).toBe("idem-policy");
    const body: unknown = JSON.parse(init?.body as string);
    expect(body).toEqual({ version: 2, logging_mode: "redacted_content" });
  });

  it("requests an organization export with an explicit category manifest", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(exportWire({ state: "requested", downloadable: false, artifact: null }), 201),
    );

    const job = await defaultDataGovernanceApi().createExport(
      ORG_ID,
      { categories: ["identity", "devices"], format: "jsonl" },
      "idem-export",
    );

    expect(job.state).toBe("requested");
    const [, init] = vi.mocked(fetch).mock.calls[0] ?? [];
    const body: unknown = JSON.parse(init?.body as string);
    expect(body).toEqual({ categories: ["identity", "devices"], format: "jsonl" });
  });

  it("bounds the page limit the client asks for", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ items: [], next_cursor: null, has_more: false }),
    );

    await defaultDataGovernanceApi().listExports(ORG_ID, { limit: 4_000 });

    expect(fetch).toHaveBeenCalledWith(
      `/api/v1/orgs/${ORG_ID}/exports?limit=100`,
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("posts a version to the explicit resume route", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(deletionWire({ state: "deleting", resumable: false, failure_code: null })),
    );

    await defaultDataGovernanceApi().resumeDeletion(ORG_ID, DELETION_ID, 4, "idem-resume");

    expect(fetch).toHaveBeenCalledWith(
      `/api/v1/orgs/${ORG_ID}/deletions/${DELETION_ID}/resume`,
      expect.objectContaining({ method: "POST" }),
    );
    const [, init] = vi.mocked(fetch).mock.calls[0] ?? [];
    expect(JSON.parse(init?.body as string)).toEqual({ version: 4 });
  });

  it("reads the none answer from the personal deletion route", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ state: "none", grace_expires_at: null, disclosures: [] }),
    );

    const status = await defaultDataGovernanceApi().getPersonalDeletion();

    expect(status).toEqual({ state: "none", grace_expires_at: null, disclosures: [] });
  });

  it("sends the typed confirmation and the reauthentication grant for a personal export", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(
        exportWire({
          org_id: null,
          scope_type: "user",
          scope_id: USER_ID,
          state: "requested",
          downloadable: false,
          artifact: null,
        }),
        201,
      ),
    );

    await defaultDataGovernanceApi().createPersonalExport(
      {
        categories: ["identity", "notifications"],
        format: "json",
        confirmation: EXPORT_CONFIRMATION_PHRASE,
        reauth_grant_id: "rag_1",
        reauth_token: REAUTH_VALUE,
      },
      "idem-me-export",
    );

    const body: unknown = JSON.parse((vi.mocked(fetch).mock.calls[0]?.[1]?.body ?? "{}") as string);
    expect(body).toEqual({
      categories: ["identity", "notifications"],
      format: "json",
      confirmation: EXPORT_CONFIRMATION_PHRASE,
      reauth_grant_id: "rag_1",
      reauth_token: REAUTH_VALUE,
    });
  });

  it("sends the typed confirmation for an account deletion", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(
        deletionWire({
          org_id: null,
          target_type: "user",
          target_id: USER_ID,
          state: "awaiting_grace",
          resumable: false,
          failure_code: null,
          legal_hold: false,
          grace_expires_at: "2026-10-02T12:00:00.000Z",
          cutoff_at: "2026-09-25T12:00:00.000Z",
        }),
        201,
      ),
    );

    const job = await defaultDataGovernanceApi().createPersonalDeletion(
      { confirmation: DELETION_CONFIRMATION_PHRASE, reauth_grant_id: "rag_1", reauth_token: "t" },
      "idem-me-deletion",
    );

    expect(job.state).toBe("awaiting_grace");
    const body: unknown = JSON.parse((vi.mocked(fetch).mock.calls[0]?.[1]?.body ?? "{}") as string);
    expect(body).toEqual({
      confirmation: DELETION_CONFIRMATION_PHRASE,
      reauth_grant_id: "rag_1",
      reauth_token: "t",
    });
  });

  it("surfaces a stable reason code without exposing the server message", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(
        {
          error: {
            code: "conflict",
            message: "D1 error near 'org_0123': UNIQUE constraint failed",
            request_id: REQUEST_ID,
            details: { reason: "data_policy_version_conflict" },
          },
        },
        409,
        { "X-Request-ID": REQUEST_ID },
      ),
    );

    const error = await defaultDataGovernanceApi()
      .updatePolicy(ORG_ID, { version: 1 }, "idem")
      .catch((value: unknown) => value);

    expect(error).toBeInstanceOf(ApiClientError);
    expect(error).toMatchObject({ code: "conflict", status: 409 });
    expect((error as ApiClientError).details.reason).toBe("data_policy_version_conflict");
    expect((error as ApiClientError).message).not.toContain("UNIQUE");
  });

  it("rejects a 2xx response that does not match the contract", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ id: EXPORT_ID, state: "imaginary" }));

    const error = await defaultDataGovernanceApi()
      .getExport(ORG_ID, EXPORT_ID)
      .catch((value: unknown) => value);

    expect(error).toBeInstanceOf(ApiClientError);
    expect(error).toMatchObject({ code: "invalid_response", kind: "invalid_response" });
  });
});

describe("short-lived download grant", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
    vi.stubGlobal("URL", {
      createObjectURL: vi.fn(() => "blob:local"),
      revokeObjectURL: vi.fn(),
    });
    vi.stubGlobal("document", {
      cookie: "",
      createElement: () => {
        const anchor = {
          href: "",
          download: "",
          rel: "",
          hidden: false,
          click: vi.fn(),
          remove: vi.fn(),
        };
        return anchor;
      },
      body: { append: vi.fn() },
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("returns the grant id and expiry as evidence, never the grant token", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ categories: ["identity"] }), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Content-Disposition": `attachment; filename="${EXPORT_ID}.json"`,
          "x-lumi-download-grant-id": "grant_0123456789abcdef0123456789abcdef",
          "x-lumi-download-grant-expires-at": "2026-09-25T12:15:00.000Z",
          "x-lumi-download-grant": "super-secret-token",
        },
      }),
    );

    const receipt = await downloadExportArtifact({
      path: `/api/v1/orgs/${ORG_ID}/exports/${EXPORT_ID}/download`,
      exportId: EXPORT_ID,
    });

    expect(receipt.grant_id).toBe("grant_0123456789abcdef0123456789abcdef");
    expect(receipt.grant_expires_at).toBe("2026-09-25T12:15:00.000Z");
    expect(receipt.filename).toBe(`${EXPORT_ID}.json`);
    // The raw grant is a one-time capability: it is never handed to a component.
    expect(JSON.stringify(receipt)).not.toContain("super-secret-token");
  });

  it("posts an empty body so the server mints a new grant", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } }),
    );

    await downloadExportArtifact({
      path: `/api/v1/orgs/${ORG_ID}/exports/${EXPORT_ID}/download`,
      exportId: EXPORT_ID,
    });

    const [, init] = vi.mocked(fetch).mock.calls[0] ?? [];
    expect(init?.method).toBe("POST");
    expect(init?.body).toBe("{}");
    expect(init?.credentials).toBe("include");
  });

  it("reports a refused grant as a stable reason rather than a silent failure", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(
        {
          error: {
            code: "conflict",
            message: "no rows in export_artifacts",
            request_id: REQUEST_ID,
            details: { reason: "export_expired" },
          },
        },
        409,
      ),
    );

    const error = await downloadExportArtifact({
      path: `/api/v1/orgs/${ORG_ID}/exports/${EXPORT_ID}/download`,
      exportId: EXPORT_ID,
    }).catch((value: unknown) => value);

    expect(error).toBeInstanceOf(ApiClientError);
    expect((error as ApiClientError).details.reason).toBe("export_expired");
  });
});

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

describe("frozen vocabulary", () => {
  it("names the eight export categories and no others", () => {
    expect(EXPORT_CATEGORIES).toHaveLength(8);
    expect(new Set(EXPORT_CATEGORIES).size).toBe(8);
  });
});
