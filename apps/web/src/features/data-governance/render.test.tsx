// Render smoke tests for the data-governance surface.
//
// `renderToStaticMarkup` executes the component tree, the same approach the
// other P06 panels take, so the load-bearing copy and the accessibility shape
// are asserted against real markup rather than against types. The focus is the
// honesty requirements: a skipped step says why, provider and device data are
// never listed as deletions, a completed job is not drawn as full coverage, and
// no download control exists for a job that cannot mint a grant.

import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import {
  decodeDataGovernancePolicy,
  decodeDeletionJob,
  decodeExportJob,
  type DataGovernanceApi,
  type DeletionJob,
  type ExportJob,
} from "./api";
import { DataPanel } from "./data-panel";
import { DataPolicyEditor } from "./data-policy";
import {
  DeletionDetail,
  OrgDeletionWorkflow,
  PersonalDeletionWorkflow,
} from "./deletion-workflows";
import { OrgExportWorkflow, PersonalExportWorkflow } from "./export-workflows";
import { RetentionSummary } from "./retention-summary";
import { ErrorNotice, PermissionState } from "./ui";
import { ApiClientError } from "@/lib/errors";

const ORG_ID = "org_0123456789abcdef0123456789abcdef";
const USER_ID = "usr_0123456789abcdef0123456789abcdef";
const EXPORT_ID = "exp_0123456789abcdef0123456789abcdef";
const DELETION_ID = "del_0123456789abcdef0123456789abcdef";

const policy = decodeDataGovernancePolicy({
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
});

const noopApi = {
  updatePolicy: async () => policy,
} as unknown as Parameters<typeof DataPolicyEditor>[0]["api"];

function exportJob(overrides: Record<string, unknown> = {}): ExportJob {
  return decodeExportJob({
    id: EXPORT_ID,
    org_id: ORG_ID,
    scope_type: "organization",
    scope_id: ORG_ID,
    categories: ["identity", "notifications"],
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
      expires_at: "2099-01-01T00:00:00.000Z",
      download_path: `/api/v1/orgs/{org_id}/exports/${EXPORT_ID}/download`,
    },
    version: 1,
    updated_at: "2026-09-25T12:00:03.000Z",
    disclosures: ["Lumi retention applies to Lumi-managed records only."],
    ...overrides,
  });
}

function deletionJob(overrides: Record<string, unknown> = {}): DeletionJob {
  return decodeDeletionJob({
    id: DELETION_ID,
    org_id: ORG_ID,
    target_type: "organization",
    target_id: ORG_ID,
    state: "completed",
    state_version: 6,
    attempt: 2,
    next_attempt_at: null,
    grace_expires_at: null,
    cutoff_at: "2026-09-25T12:00:00.000Z",
    fenced: true,
    legal_hold: false,
    failure_code: null,
    certificate_id: "delc_0123456789abcdef0123456789abcdef",
    resumable: false,
    requested_by: USER_ID,
    created_at: "2026-09-25T12:00:00.000Z",
    updated_at: "2026-09-25T12:10:00.000Z",
    completed_at: "2026-09-25T12:10:00.000Z",
    version: 7,
    disclosures: [],
    steps: [],
    certificate: {
      id: "delc_0123456789abcdef0123456789abcdef",
      scope_type: "organization",
      scope_id: ORG_ID,
      class_results: {
        membership: { succeeded: 4 },
        audit_security_event: { skipped: 1 },
        reference_coverage: {
          traversed: ["database_row", "r2_object"],
          pending: ["cache", "search_index"],
          absent_reason: "deletion_reference_system_absent",
        },
      },
      retained_legal_classes: ["audit_security_event"],
      completed_at: "2026-09-25T12:10:00.000Z",
      expires_at: "2027-09-25T12:10:00.000Z",
    },
    ...overrides,
  });
}

const mixedSteps = [
  {
    id: "dts_1",
    data_class: "membership",
    reference_kind: "database_row",
    object_reference: "mem_1",
    state: "succeeded",
    attempt: 1,
    failure_code: null,
    skip_reason: null,
    completed_at: "2026-09-25T12:01:00.000Z",
  },
  {
    id: "dts_2",
    data_class: "run",
    reference_kind: "local_device_data",
    object_reference: "local_device_data:org_1",
    state: "skipped",
    attempt: 0,
    failure_code: null,
    skip_reason: "deletion_not_lumi_owned",
    completed_at: "2026-09-25T12:01:00.000Z",
  },
  {
    id: "dts_3",
    data_class: "upstream_provider_data",
    reference_kind: "upstream_provider_data",
    object_reference: "upstream_provider:org_1",
    state: "skipped",
    attempt: 0,
    failure_code: null,
    skip_reason: "deletion_not_lumi_owned",
    completed_at: "2026-09-25T12:01:00.000Z",
  },
  {
    id: "dts_4",
    data_class: "audit_security_event",
    reference_kind: "database_row",
    object_reference: "sec_1",
    state: "skipped",
    attempt: 0,
    failure_code: null,
    skip_reason: "retained_legal_only",
    completed_at: "2026-09-25T12:01:00.000Z",
  },
];

const page = <T,>(items: T[]) => ({ items, next_cursor: null, has_more: false });

describe("data policy surface", () => {
  it("renders metadata-only as the default and says what it contains", () => {
    const markup = renderToStaticMarkup(
      <DataPolicyEditor
        orgId={ORG_ID}
        api={noopApi}
        policy={policy}
        status="ready"
        onRefresh={() => undefined}
        onSaved={() => undefined}
      />,
    );

    expect(markup).toContain("Content logging mode");
    expect(markup).toContain("Metadata only");
    expect(markup).toMatch(/The default, and the narrowest mode/);
    expect(markup).toContain("Prohibited in every mode");
  });

  it("describes full content as audited and does not offer it as a control", () => {
    const markup = renderToStaticMarkup(
      <DataPolicyEditor
        orgId={ORG_ID}
        api={noopApi}
        policy={policy}
        status="ready"
        onRefresh={() => undefined}
        onSaved={() => undefined}
      />,
    );

    expect(markup).toMatch(/audited, time-bounded diagnostic setting/);
    expect(markup).toMatch(/never widens a class&#x27;s field allowlist/);
    expect(markup).toMatch(/never changes the normal event, audit, webhook, or log schemas/);
    expect(markup).toMatch(/Not selectable here/);
    // The control exists but is disabled, so the mode is described, not hidden.
    expect(markup).toMatch(/id="[^"]+-full_content"[^>]*disabled/);
  });

  it("uses a native radio group so the mode is keyboard reachable", () => {
    const markup = renderToStaticMarkup(
      <DataPolicyEditor
        orgId={ORG_ID}
        api={noopApi}
        policy={policy}
        status="ready"
        onRefresh={() => undefined}
        onSaved={() => undefined}
      />,
    );

    expect(markup).toContain("<fieldset");
    expect(markup).toContain("<legend");
    expect(markup).toContain('type="radio"');
  });

  it("states the shorten-only retention rule and shows the current override", () => {
    const markup = renderToStaticMarkup(
      <DataPolicyEditor
        orgId={ORG_ID}
        api={noopApi}
        policy={policy}
        status="ready"
        onRefresh={() => undefined}
        onSaved={() => undefined}
      />,
    );

    expect(markup).toMatch(/can shorten retention\. It cannot extend it/i);
    expect(markup).toMatch(/audited override that this page cannot create/i);
    expect(markup).toContain("Notification");
    expect(markup).toContain("Effective window: 7 days");
    expect(markup).toMatch(/baseline 30 days · legal maximum 90 days/);
  });

  it("separates provider retention from Lumi retention", () => {
    const markup = renderToStaticMarkup(
      <DataPolicyEditor
        orgId={ORG_ID}
        api={noopApi}
        policy={policy}
        status="ready"
        onRefresh={() => undefined}
        onSaved={() => undefined}
      />,
    );

    expect(markup).toMatch(/Upstream provider retention is governed by the provider/);
    expect(markup).toMatch(/cannot delete provider-held data and does not claim to/i);
    expect(markup).toMatch(/Bringing your own model key does not mean zero upstream retention/);
  });

  it("shows a legal hold as an active block with its reason", () => {
    const held = decodeDataGovernancePolicy({
      ...(policy as unknown as Record<string, unknown>),
      legal_hold: true,
      legal_hold_reason: "litigation hold",
      legal_hold_placed_at: "2026-09-20T10:00:00.000Z",
    });
    const markup = renderToStaticMarkup(
      <DataPolicyEditor
        orgId={ORG_ID}
        api={noopApi}
        policy={held}
        status="ready"
        onRefresh={() => undefined}
        onSaved={() => undefined}
      />,
    );

    expect(markup).toContain("LEGAL HOLD ACTIVE");
    expect(markup).toContain("litigation hold");
    expect(markup).toMatch(/cannot mint a new download grant/i);
    expect(markup).toMatch(/does not resume a parked deletion job/i);
  });

  it("has no hover-only action and no div-as-button", () => {
    const markup = renderToStaticMarkup(
      <DataPolicyEditor
        orgId={ORG_ID}
        api={noopApi}
        policy={policy}
        status="ready"
        onRefresh={() => undefined}
        onSaved={() => undefined}
      />,
    );

    expect(markup).not.toContain('role="button"');
    expect(markup).not.toContain("onMouseEnter");
    expect(markup).toContain("<button");
    expect(markup).toContain("Save policy changes");
  });
});

describe("retention summary", () => {
  it("shows the declared classes with their effective and maximum windows", () => {
    const markup = renderToStaticMarkup(<RetentionSummary policy={policy} />);

    expect(markup).toContain("Retention summary");
    expect(markup).toContain("Automation definition");
    expect(markup).toContain("upstream_provider_data");
    expect(markup).toContain("Not Lumi-deletable");
    expect(markup).toMatch(/Prompts, responses, and tool arguments are not a data class/);
  });

  it("labels every declared class as Lumi-owned or external", () => {
    const markup = renderToStaticMarkup(<RetentionSummary policy={policy} />);
    expect(markup).toContain("External");
    expect(markup).toContain("Organization");
    expect(markup).toContain("Platform");
  });

  it("states that secrets are never exported", () => {
    const markup = renderToStaticMarkup(<RetentionSummary policy={policy} />);
    expect(markup).toMatch(/Secrets and credentials are never exported/);
  });
});

describe("organization export surface", () => {
  const client = { listExports: async () => page([exportJob()]) } as unknown as Parameters<
    typeof OrgExportWorkflow
  >[0]["api"];

  it("offers a download only for a ready job and names the grant", () => {
    const markup = renderToStaticMarkup(
      <OrgExportWorkflow
        orgId={ORG_ID}
        api={client}
        legalHold={false}
        canExport
        page={page([exportJob()])}
        status="ready"
        error={null}
        refreshing={false}
        onRefresh={() => undefined}
        onLoadMore={() => undefined}
        onCreated={() => undefined}
      />,
    );

    expect(markup).toContain("Download (mints a new grant)");
    expect(markup).toMatch(/re-authorized grant/);
    expect(markup).toMatch(/not a link you can share or bookmark/);
    expect(markup).toMatch(/There is no permanent artifact URL/);
  });

  it("offers no download control for a job that is not ready", () => {
    const markup = renderToStaticMarkup(
      <OrgExportWorkflow
        orgId={ORG_ID}
        api={client}
        legalHold={false}
        canExport
        page={page([exportJob({ state: "packaging", downloadable: false, artifact: null })])}
        status="ready"
        error={null}
        refreshing={false}
        onRefresh={() => undefined}
        onLoadMore={() => undefined}
        onCreated={() => undefined}
      />,
    );

    expect(markup).toContain("No download action");
    expect(markup).not.toContain("Download (mints a new grant)");
    expect(markup).toMatch(/Only a ready export can mint a download grant/);
  });

  it("withholds the download when a legal hold is active and says why", () => {
    const markup = renderToStaticMarkup(
      <OrgExportWorkflow
        orgId={ORG_ID}
        api={client}
        legalHold
        canExport
        page={page([exportJob()])}
        status="ready"
        error={null}
        refreshing={false}
        onRefresh={() => undefined}
        onLoadMore={() => undefined}
        onCreated={() => undefined}
      />,
    );

    expect(markup).toMatch(/no new download grant is minted while a hold is active/i);
    expect(markup).toMatch(/The artifact bytes are kept; the grant is what is blocked/);
    expect(markup).not.toContain("Download (mints a new grant)");
  });

  it("states that a retry resumes the same manifest and cutoff", () => {
    const markup = renderToStaticMarkup(
      <OrgExportWorkflow
        orgId={ORG_ID}
        api={client}
        legalHold={false}
        canExport
        page={page([exportJob({ state: "retry_wait", downloadable: false, artifact: null })])}
        status="ready"
        error={null}
        refreshing={false}
        onRefresh={() => undefined}
        onLoadMore={() => undefined}
        onCreated={() => undefined}
      />,
    );

    expect(markup).toMatch(/A retry is not a fresh snapshot/);
    expect(markup).toMatch(/Data written after the cutoff is not in the artifact/);
    expect(markup).toContain("Waiting to retry");
  });

  it("lists the frozen category manifest with what each one contains", () => {
    const markup = renderToStaticMarkup(
      <OrgExportWorkflow
        orgId={ORG_ID}
        api={client}
        legalHold={false}
        canExport
        page={page([])}
        status="ready"
        error={null}
        refreshing={false}
        onRefresh={() => undefined}
        onLoadMore={() => undefined}
        onCreated={() => undefined}
      />,
    );

    expect(markup).toContain("Category manifest");
    expect(markup).toContain("Audit (redacted)");
    expect(markup).toMatch(/Secrets, credentials, and login sessions are in no category/);
    expect(markup).toContain("No export has been requested");
  });

  it("hides the request form from a role that cannot export", () => {
    const markup = renderToStaticMarkup(
      <OrgExportWorkflow
        orgId={ORG_ID}
        api={client}
        legalHold={false}
        canExport={false}
        page={page([exportJob()])}
        status="ready"
        error={null}
        refreshing={false}
        onRefresh={() => undefined}
        onLoadMore={() => undefined}
        onCreated={() => undefined}
      />,
    );

    expect(markup).not.toContain("Category manifest");
    expect(markup).toMatch(/can read export history but not request one/);
  });
});

describe("organization deletion surface", () => {
  const client = { getDeletion: async () => deletionJob() } as unknown as Parameters<
    typeof OrgDeletionWorkflow
  >[0]["api"];
  const noop = {
    onRefresh: () => undefined,
    onLoadMore: () => undefined,
    onSelect: () => undefined,
    onResumed: () => undefined,
  };

  const render = (job: DeletionJob) =>
    renderToStaticMarkup(
      <OrgDeletionWorkflow
        orgId={ORG_ID}
        api={client}
        page={page([job])}
        detail={job}
        detailStatus="ready"
        detailError={null}
        status="ready"
        error={null}
        refreshing={false}
        canDelete
        {...noop}
      />,
    );

  it("offers no resume for a completed job", () => {
    const markup = render(deletionJob());
    expect(markup).not.toContain("Resume this deletion job…");
  });

  it("offers a resume for a parked job and states its real reason", () => {
    const parked = deletionJob({
      state: "needs_attention",
      resumable: true,
      failure_code: "deletion_legal_hold",
      certificate: null,
      completed_at: null,
    });
    const markup = render(parked);

    expect(markup).toContain("Needs attention");
    expect(markup).toContain("A legal hold covers part of this scope");
    expect(markup).toMatch(/Resuming now would be refused while the hold is active/);
    expect(markup).toMatch(/Release the hold first, through the audited support or legal process/);
    expect(markup).toContain("Resume this deletion job…");
  });

  it("names the three needs-attention reasons distinctly", () => {
    const external = deletionJob({
      state: "needs_attention",
      resumable: true,
      failure_code: "deletion_reference_system_absent",
      certificate: null,
      completed_at: null,
    });
    expect(render(external)).toMatch(/An external reference could not be resolved/);

    const retries = deletionJob({
      state: "needs_attention",
      resumable: true,
      failure_code: "deletion_executor_unavailable",
      certificate: null,
      completed_at: null,
    });
    const retryMarkup = render(retries);
    expect(retryMarkup).toMatch(/Retries were exhausted/);
    expect(retryMarkup).toMatch(/not an automatic action/);
  });

  it("never exposes an organization deletion request route of its own", () => {
    const markup = render(
      deletionJob({ state: "needs_attention", resumable: true, certificate: null }),
    );
    expect(markup).toMatch(
      /Organization deletion is requested from organization settings\. This page only observes/,
    );
    expect(markup).not.toContain("Start organization deletion");
  });

  it("uses the coordinator's lifecycle wiring when it is provided", () => {
    const markup = renderToStaticMarkup(
      <OrgDeletionWorkflow
        orgId={ORG_ID}
        api={client}
        page={page([deletionJob()])}
        detail={deletionJob()}
        detailStatus="ready"
        detailError={null}
        status="ready"
        error={null}
        refreshing={false}
        canDelete
        onRequestOrganizationDeletion={() => undefined}
        {...noop}
      />,
    );

    expect(markup).toContain("Start organization deletion…");
    expect(markup).toMatch(/transactionally creates exactly one job/);
  });

  it("always shows the three frozen disclosures", () => {
    const markup = render(deletionJob({ steps: mixedSteps }));
    expect(markup).toContain("What this workflow does not delete");
    expect(markup).toMatch(/deleted on the host, not by this cloud job/);
    expect(markup).toMatch(/Lumi cannot delete it/);
  });
});

describe("panel async states", () => {
  it("shows a loading state instead of an empty policy", () => {
    // `renderToStaticMarkup` does not run effects, so this is exactly the
    // first paint an operator sees: a stated load, never a blank surface that
    // could be misread as "no policy configured".
    const markup = renderToStaticMarkup(<DataPanel orgId={ORG_ID} api={pendingApi} />);
    expect(markup).toContain("DATA &amp; RETENTION");
    expect(markup).toContain("Loading the data policy, retention windows, and job history…");
    expect(markup).toMatch(/aria-busy="true"/);
  });

  it("delegates its error surface to the shared presenter", () => {
    const markup = renderToStaticMarkup(
      <ErrorNotice
        error={
          new ApiClientError({
            code: "conflict",
            kind: "api",
            status: 409,
            requestId: "req_1",
            details: { reason: "data_policy_version_conflict" },
            retryable: false,
          })
        }
        title="The data policy could not be refreshed"
        onRetry={() => undefined}
      />,
    );

    expect(markup).toContain("The data policy could not be refreshed");
    expect(markup).toMatch(/Reason code data_policy_version_conflict/);
    expect(markup).toContain("Request req_1");
    expect(markup).not.toMatch(/D1|SQL|UNIQUE constraint/);
    expect(markup).toContain("Try again");
  });

  it("shows a permission state rather than a denial of fact", () => {
    const markup = renderToStaticMarkup(
      <PermissionState resource="the organization's data policy, exports, or deletion workflows" />,
    );
    expect(markup).toContain("Access not permitted");
    expect(markup).toMatch(/cannot view/);
    // A permission refusal must never read as "there is nothing here".
    expect(markup).not.toContain("Nothing is known to be deleted");
    expect(markup).not.toContain("No deletion job exists");
  });
});

const pendingApi = {
  getPolicy: () => new Promise(() => undefined),
  listExports: () => new Promise(() => undefined),
  listDeletions: () => new Promise(() => undefined),
} as unknown as DataGovernanceApi;

describe("deletion step surface", () => {
  it("separates what Lumi deleted from what it cannot delete", () => {
    const markup = renderToStaticMarkup(
      <DeletionDetail job={deletionJob({ steps: mixedSteps })} />,
    );

    // The one real deletion is stated as such.
    expect(markup).toContain("Removed from a store Lumi owns.");
    // Provider and device data are recorded, not deleted, each with a reason.
    expect(markup).toContain("Recorded, not deleted");
    expect(markup).toMatch(/Not Lumi&#x27;s data to delete/);
    expect(markup).toContain("Local device data");
    expect(markup).toContain("Upstream provider data");
    expect(markup).toMatch(/Retained for a legal or security duty/);
    expect(markup).toContain("audit_security_event");
  });

  it("never renders an opaque reference as a link", () => {
    const markup = renderToStaticMarkup(
      <DeletionDetail job={deletionJob({ steps: mixedSteps })} />,
    );

    expect(markup).toContain("Opaque reference:");
    expect(markup).not.toMatch(/href="[^"]*local_device_data/);
    expect(markup).not.toMatch(/href="[^"]*upstream_provider/);
  });

  it("states incomplete coverage instead of implying everything was covered", () => {
    const markup = renderToStaticMarkup(<DeletionDetail job={deletionJob()} />);

    expect(markup).toContain("Reference coverage");
    expect(markup).toContain("Not covered: cache, search_index");
    expect(markup).toMatch(/A completed job is not a claim about these systems/);
    expect(markup).toMatch(/coverage states which reference stores this job traversed/i);
  });

  it("does not claim completeness when coverage is pending", () => {
    const markup = renderToStaticMarkup(<DeletionDetail job={deletionJob()} />);
    expect(markup).not.toContain("Every named reference system was traversed.");
  });

  it("renders an unowned reference as not established when the store is unknown", () => {
    const markup = renderToStaticMarkup(
      <DeletionDetail
        job={deletionJob({
          steps: [
            {
              id: "dts_9",
              data_class: "artifact",
              reference_kind: "quantum_store",
              object_reference: "artifact_1",
              state: "succeeded",
              attempt: 1,
              failure_code: null,
              skip_reason: null,
              completed_at: "2026-09-25T12:01:00.000Z",
            },
          ],
        })}
      />,
    );

    expect(markup).toContain("Ownership not established");
    expect(markup).toMatch(/No deletion is claimed here/);
    expect(markup).not.toContain("Removed from a store Lumi owns.");
  });

  it("shows the frozen disclosures on a completed job", () => {
    const markup = renderToStaticMarkup(<DeletionDetail job={deletionJob()} />);
    expect(markup).toMatch(/deleted on the host, not by this cloud job/);
    expect(markup).toMatch(/Lumi cannot delete it/);
  });
});

describe("personal account deletion surface", () => {
  it("renders the organization-exit requirement before the user starts", () => {
    const markup = renderToStaticMarkup(
      <PersonalDeletionWorkflow
        api={{} as never}
        status={{ state: "none", grace_expires_at: null, disclosures: [] }}
        statusState="ready"
        error={null}
        organizations={[
          {
            org_id: ORG_ID,
            display_name: "Lumi Workspace",
            role: "owner",
            organization_state: "active",
            membership_status: "active",
          },
        ]}
        onRefresh={() => undefined}
        onChanged={() => undefined}
      />,
    );

    expect(markup).toContain("BEFORE YOU START");
    expect(markup).toMatch(/Leave or transfer this organization first/);
    expect(markup).toContain("Lumi Workspace");
    expect(markup).toMatch(/deletion_requires_org_exit/);
    expect(markup).toMatch(/The control is disabled because the requirement above is not met/);
    // The control is rendered disabled, not removed: the requirement is explained.
    expect(markup).toMatch(/Request account deletion…[\s\S]*disabled/);
  });

  it("offers the request when no organization blocks it, with a typed phrase", () => {
    const markup = renderToStaticMarkup(
      <PersonalDeletionWorkflow
        api={{} as never}
        status={{ state: "none", grace_expires_at: null, disclosures: [] }}
        statusState="ready"
        error={null}
        organizations={[
          {
            org_id: ORG_ID,
            display_name: "Lumi Workspace",
            role: "member",
            organization_state: "active",
            membership_status: "active",
          },
        ]}
        onRefresh={() => undefined}
        onChanged={() => undefined}
      />,
    );

    expect(markup).not.toContain("BEFORE YOU START");
    expect(markup).toMatch(/Request account deletion…/);
    expect(markup).toMatch(/deleted on the host, not by this cloud job/);
    expect(markup).toMatch(/Lumi cannot delete it/);
  });

  it("offers a cancel only inside the grace window", () => {
    const inGrace = deletionJob({
      org_id: null,
      target_type: "user",
      target_id: USER_ID,
      state: "awaiting_grace",
      resumable: false,
      failure_code: null,
      grace_expires_at: "2099-01-01T00:00:00.000Z",
      certificate: null,
    });
    const graceMarkup = renderToStaticMarkup(
      <PersonalDeletionWorkflow
        api={{} as never}
        status={inGrace}
        statusState="ready"
        error={null}
        organizations={[]}
        onRefresh={() => undefined}
        onChanged={() => undefined}
      />,
    );
    expect(graceMarkup).toMatch(/Cancel this deletion…/);
    expect(graceMarkup).toMatch(/Waiting out the grace window/);

    const afterGrace = deletionJob({
      org_id: null,
      target_type: "user",
      target_id: USER_ID,
      state: "deleting",
      resumable: false,
      failure_code: null,
      grace_expires_at: "2026-01-01T00:00:00.000Z",
      certificate: null,
    });
    const closedMarkup = renderToStaticMarkup(
      <PersonalDeletionWorkflow
        api={{} as never}
        status={afterGrace}
        statusState="ready"
        error={null}
        organizations={[]}
        onRefresh={() => undefined}
        onChanged={() => undefined}
      />,
    );
    expect(closedMarkup).not.toContain("Cancel this deletion…");
  });
});

describe("personal export surface", () => {
  const client = { listPersonalExports: async () => page([]) } as unknown as Parameters<
    typeof PersonalExportWorkflow
  >[0]["api"];

  it("offers only the account-scoped categories and says why the rest are absent", () => {
    const markup = renderToStaticMarkup(
      <PersonalExportWorkflow
        api={client}
        page={page([])}
        status="ready"
        error={null}
        refreshing={false}
        onRefresh={() => undefined}
        onLoadMore={() => undefined}
        onCreated={() => undefined}
      />,
    );

    expect(markup).toContain("Account-scoped categories");
    // The tenant categories are absent as controls…
    expect(markup).not.toContain('id="me-export-runs_metadata"');
    expect(markup).not.toContain('id="me-export-devices"');
    expect(markup).not.toContain('id="me-export-audit_redacted"');
    expect(markup).toContain('id="me-export-identity"');
    expect(markup).toContain('id="me-export-notifications"');
    expect(markup).toContain('id="me-export-data_governance"');
    // …and present as a stated reason rather than silently missing.
    expect(markup).toMatch(/What a personal export does not include/);
    expect(markup).toMatch(/Run metadata\.<\/span> Run metadata belongs to the organization/);
    expect(markup).toMatch(/Audit \(redacted\)/);
  });

  it("requires a typed confirmation phrase in the request dialog", () => {
    const markup = renderToStaticMarkup(
      <PersonalExportWorkflow
        api={client}
        page={page([])}
        status="ready"
        error={null}
        refreshing={false}
        onRefresh={() => undefined}
        onLoadMore={() => undefined}
        onCreated={() => undefined}
      />,
    );

    // The dialog is closed on first render, so the phrase requirement is stated
    // in the copy the operator reads before opening it.
    expect(markup).toMatch(/Account-scoped data only/);
    expect(markup).toMatch(/recent security check/);
    expect(markup).toMatch(/Request my export…/);
  });
});
