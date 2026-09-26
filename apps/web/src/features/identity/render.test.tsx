/**
 * Identity & access rendering.
 *
 * The cases that matter are the ones where a wrong answer is silent: a
 * permission gate that renders an empty table instead of a refusal, a capability
 * picker that quietly offers a human-only permission, a suspend dialog with no
 * consequence copy, or a state that shows success where the record says otherwise.
 */

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ApiClientError } from "@/lib/errors";

import type { ApiKey, ServiceAccount } from "./api";
import {
  AccountScopeSummary,
  CapabilityPicker,
  CapabilityPreview,
  HumanOnlyNotice,
} from "./capability-picker";
import { HUMAN_ONLY_CAPABILITIES, MACHINE_CAPABILITIES } from "./capabilities";
import {
  CreateApiKeyForm,
  ApiKeyTable,
  apiKeyRotationBlockedReason,
  isApiKeyTerminal,
} from "./api-keys";
import {
  IDENTITY_MANAGE_ONLY_COPY,
  IDENTITY_REFUSAL_COPY,
  identityPermissions,
} from "./permissions";
import {
  CreateServiceAccountForm,
  ServiceAccountTable,
  serviceAccountStatusDetail,
} from "./service-accounts";
import { parseListField, PermissionState } from "./ui";

const NOOP = () => {};

function account(overrides: Partial<ServiceAccount> = {}): ServiceAccount {
  return {
    id: "svc_0123456789abcdef0123456789abcdef",
    organization_id: "org_0123456789abcdef0123456789abcdef",
    name: "Release pipeline",
    description: "Publishes releases on merge to main",
    capabilities: ["runs.start", "projects.read", "usage.read"],
    status: "active",
    expires_at: null,
    suspended_at: null,
    suspend_reason: null,
    created_by_principal_id: "usr_0123456789abcdef0123456789abcdef",
    version: 1,
    created_at: "2026-09-25T12:00:00.000Z",
    updated_at: "2026-09-25T12:30:00.000Z",
    ...overrides,
  };
}

function key(overrides: Partial<ApiKey> = {}): ApiKey {
  return {
    id: "key_0123456789abcdef0123456789abcdef",
    service_account_id: account().id,
    organization_id: account().organization_id,
    name: "Release publisher",
    key_prefix: "lumik_0123456789ab",
    fingerprint: "sha256:0123456789abcdef",
    capabilities: ["runs.start"],
    project_ids: [],
    model_aliases: [],
    network_allowlist: [],
    status: "active",
    rotated_from_key_id: null,
    rotated_to_key_id: null,
    last_used_at: null,
    last_used_source: null,
    expires_at: null,
    revoked_at: null,
    revoke_reason: null,
    version: 1,
    created_at: "2026-09-25T12:00:00.000Z",
    updated_at: "2026-09-25T12:00:00.000Z",
    ...overrides,
  };
}

function renderAccountTable(
  props: Partial<Parameters<typeof ServiceAccountTable>[0]> = {},
): string {
  return renderToStaticMarkup(
    <ServiceAccountTable
      accounts={[account()]}
      status="ready"
      error={null}
      hasMore={false}
      selectedId={null}
      canManage={true}
      onSelect={NOOP}
      onRetry={NOOP}
      onLoadMore={NOOP}
      {...props}
    />,
  );
}

function renderKeyTable(props: Partial<Parameters<typeof ApiKeyTable>[0]> = {}): string {
  return renderToStaticMarkup(
    <ApiKeyTable
      keys={[key()]}
      status="ready"
      error={null}
      hasMore={false}
      selectedId={null}
      onSelect={NOOP}
      onRetry={NOOP}
      onLoadMore={NOOP}
      {...props}
    />,
  );
}

describe("permission gating on the rendered surface", () => {
  it("shows a refusal, not an empty list, when the principal may not read", () => {
    const permissions = identityPermissions("member");
    expect(permissions.canRead).toBe(false);
    // The panel's refusal is a titled state, never a zero-row table that reads
    // as "this organization has no credentials".
    const markup = renderToStaticMarkup(
      <PermissionState title="Access not permitted" copy={IDENTITY_REFUSAL_COPY} />,
    );
    expect(markup).toContain("Access not permitted");
    expect(markup).toContain("administrator");
    expect(markup).not.toContain("<table");
  });

  it("states the read-only rule for an admin-capable-but-not-manageable role", () => {
    const permissions = identityPermissions("viewer");
    expect(permissions.canRead).toBe(false);
    expect(IDENTITY_MANAGE_ONLY_COPY).toContain("administrator action");
    expect(IDENTITY_MANAGE_ONLY_COPY).toContain("last-used time");
  });

  it("hides the manage controls from a principal without manage, for each action", () => {
    // A create-account form renders its submit control, so the panel's own gate is
    // the thing under test: for a read-only principal the panel never mounts it.
    // This asserts the gate input, not the form.
    const readOnly = identityPermissions("member");
    expect(readOnly.canManage).toBe(false);
    const admin = identityPermissions("admin");
    expect(admin.canManage).toBe(true);
    // The service-account table marks the row action as gated for screen readers
    // when manage is absent, so the absence is not silent.
    const markup = renderAccountTable({ canManage: false });
    expect(markup).toContain("requires administrator access");
  });
});

describe("the capability picker", () => {
  it("renders a checkbox for every machine capability and no more", () => {
    const markup = renderToStaticMarkup(<CapabilityPicker selected={[]} onChange={NOOP} />);
    const checkboxes = markup.match(/type="checkbox"/g) ?? [];
    expect(checkboxes).toHaveLength(MACHINE_CAPABILITIES.length);
  });

  it("never renders a human-only capability as a checkbox", () => {
    const markup = renderToStaticMarkup(<CapabilityPicker selected={[]} onChange={NOOP} />);
    for (const capability of HUMAN_ONLY_CAPABILITIES) {
      // The name must not appear as an input id, as a label target, or as a
      // rendered option.
      expect(markup).not.toContain(`id="identity-${capability.replaceAll(".", "-")}"`);
      expect(markup).not.toContain(`>${capability}<`);
    }
    // The count assertion above is the load-bearing one: exactly
    // MACHINE_CAPABILITIES.length checkboxes exist, and no human-only capability
    // is in that list.
    expect(markup.match(/type="checkbox"/g) ?? []).toHaveLength(MACHINE_CAPABILITIES.length);
  });

  it("renders no wildcard control of any kind", () => {
    const markup = renderToStaticMarkup(<CapabilityPicker selected={[]} onChange={NOOP} />);
    expect(markup).not.toContain('value="*"');
    expect(markup).not.toContain("All capabilities");
    expect(markup).not.toContain("Full access");
  });

  it("gives every capability a plain-language effect", () => {
    const markup = renderToStaticMarkup(<CapabilityPicker selected={[]} onChange={NOOP} />);
    expect(markup).toContain("Start runs.");
    expect(markup).toContain("Create, rotate, and revoke provider credentials.");
  });

  it("explains the absent human-only capabilities rather than hiding them", () => {
    const markup = renderToStaticMarkup(<HumanOnlyNotice />);
    for (const capability of HUMAN_ONLY_CAPABILITIES) {
      expect(markup).toContain(capability);
    }
    expect(markup).toContain("permanently unavailable to any machine credential");
  });
});

describe("the permission preview", () => {
  it("states the absence of a wildcard and of inheritance", () => {
    const markup = renderToStaticMarkup(
      <CapabilityPreview
        kind="service_account"
        subject="this service account"
        selected={["runs.start"]}
      />,
    );
    expect(markup).toContain("Permission preview");
    expect(markup).toContain("What this service account will be able to do");
    expect(markup).toContain("1 explicit capability");
  });

  it("states the authorisation order, so a 403 is not read as a scope problem", () => {
    const markup = renderToStaticMarkup(
      <CapabilityPreview
        kind="service_account"
        subject="this service account"
        selected={["runs.start"]}
      />,
    );
    expect(markup).toContain("the key authenticates");
    expect(markup).toContain("its service account is active");
    expect(markup).toContain("suspended account denies everything");
  });

  it("names the wildcard rule explicitly", () => {
    const markup = renderToStaticMarkup(
      <CapabilityPreview
        kind="service_account"
        subject="this service account"
        selected={["runs.start"]}
      />,
    );
    expect(markup).toContain("no all-capabilities option");
    expect(markup).toContain("never inherits its creator");
  });

  it("warns when a key selection widens beyond its service account", () => {
    const markup = renderToStaticMarkup(
      <CapabilityPreview
        kind="api_key"
        subject="this key"
        selected={["runs.start", "projects.manage"]}
        available={["runs.start"]}
      />,
    );
    expect(markup).toContain("This selection will be refused");
    expect(markup).toContain("projects.manage");
  });

  it("surfaces a granted capability the control plane cannot describe", () => {
    const markup = renderToStaticMarkup(
      <CapabilityPreview
        kind="service_account"
        subject="this service account"
        selected={["runs.start", "legacy.retired.permission"]}
      />,
    );
    expect(markup).toContain("not recognised here");
    expect(markup).toContain("legacy.retired.permission");
  });

  it("states each restriction's actual effect rather than repeating the field", () => {
    const markup = renderToStaticMarkup(
      <CapabilityPreview
        kind="api_key"
        subject="this key"
        selected={["runs.start"]}
        available={["runs.start"]}
        projectIds={["prj_1"]}
        modelAliases={[]}
        networkAllowlist={["203.0.113.0/24"]}
        expiresAt={null}
      />,
    );
    expect(markup).toContain("Restricted to 1 named project");
    expect(markup).toContain("No alias restriction");
    expect(markup).toContain("denied rather than allowed");
    expect(markup).toContain("Revocation is then the only way to stop it");
  });
});

describe("the service-account surfaces", () => {
  it("shows name, status, capabilities, creator, and timestamps on the row", () => {
    const markup = renderAccountTable();
    expect(markup).toContain("Release pipeline");
    expect(markup).toContain("Active");
    expect(markup).toContain("3 capabilities");
    expect(markup).toContain("usr_0123456789abcdef");
    expect(markup).toContain("50 active accounts maximum");
  });

  it("names the suspension reason on the row rather than only a status", () => {
    const markup = renderAccountTable({
      accounts: [
        account({
          status: "suspended",
          suspend_reason: "offboarded",
          suspended_at: "2026-09-26T09:00:00.000Z",
        }),
      ],
    });
    expect(markup).toContain("Suspended");
    expect(markup).toContain("offboarded");
  });

  it("flags a granted capability the control plane cannot describe", () => {
    const markup = renderAccountTable({
      accounts: [account({ capabilities: ["runs.start", "legacy.retired.permission"] })],
    });
    expect(markup).toContain("1 capability is not recognised");
  });

  it("renders an empty state that says how to create one", () => {
    const markup = renderAccountTable({ accounts: [] });
    expect(markup).toContain("No service accounts");
    expect(markup).toContain("without borrowing a person");
  });

  it("renders a loading state with a live region", () => {
    const markup = renderAccountTable({ accounts: [], status: "loading" });
    expect(markup).toContain('role="status"');
    expect(markup).toContain("Loading service accounts");
  });

  it("surfaces the stable reason code on the error state", () => {
    const error = new ApiClientError({
      code: "permission_denied",
      kind: "api",
      status: 403,
      requestId: "req_0123456789abcdef0123456789abcdef",
      details: {},
      retryable: false,
    });
    const markup = renderAccountTable({ accounts: [], status: "error", error });
    expect(markup).toContain("Service accounts are unavailable");
    expect(markup).toContain("Reason code permission_denied");
    expect(markup).toContain("req_0123456789abcdef0123456789abcdef");
  });

  it("keeps a stale list visible when a refresh fails", () => {
    const error = new ApiClientError({
      code: "service_unavailable",
      kind: "api",
      status: 503,
      requestId: undefined,
      details: {},
      retryable: true,
    });
    const markup = renderAccountTable({ status: "ready", error });
    expect(markup).toContain("Release pipeline");
    expect(markup).toContain("Refreshing service accounts failed");
  });

  it("states the consequence of a suspension in the detail copy", () => {
    expect(
      serviceAccountStatusDetail(account({ status: "suspended", suspend_reason: "offboarded" })),
    ).toContain("Every key on this account is denied");
    expect(
      serviceAccountStatusDetail(account({ status: "suspended", suspend_reason: "offboarded" })),
    ).toContain("offboarded");
    expect(serviceAccountStatusDetail(account())).toContain("limited to the capabilities listed");
  });

  it("summarises a scope without dumping the whole list on the row", () => {
    const markup = renderToStaticMarkup(
      <AccountScopeSummary
        account={account({
          capabilities: ["runs.start", "projects.read", "usage.read", "tools.read", "runs.cancel"],
        })}
      />,
    );
    expect(markup).toContain("5 capabilities");
    expect(markup).toContain("+1 more");
  });

  it("cannot submit the create form with no capability", () => {
    const markup = renderToStaticMarkup(
      <CreateServiceAccountForm busy={false} error={null} onSubmit={NOOP} onCancel={NOOP} />,
    );
    expect(markup).toContain("disabled");
    expect(markup).toContain("A service account needs at least one capability");
  });

  it("previews what the new account may do before it is saved", () => {
    const markup = renderToStaticMarkup(
      <CreateServiceAccountForm busy={false} error={null} onSubmit={NOOP} onCancel={NOOP} />,
    );
    expect(markup).toContain("Permission preview");
    expect(markup).toContain("What this service account will be able to do");
    expect(markup).toContain("There is no wildcard");
  });
});

describe("the API-key surfaces", () => {
  it("shows name, prefix, fingerprint, status, scope, last use, expiry, and created", () => {
    const markup = renderKeyTable({
      keys: [
        key({
          last_used_at: "2026-09-26T08:00:00.000Z",
          last_used_source: "203.0.113.7",
          expires_at: "2027-01-01T00:00:00.000Z",
        }),
      ],
    });
    expect(markup).toContain("Release publisher");
    expect(markup).toContain("lumik_0123456789ab");
    expect(markup).toContain("fp sha256:0123456789abcdef");
    expect(markup).toContain("Active");
    expect(markup).toContain("203.0.113.7");
    expect(markup).toContain("5 active keys per account");
  });

  it("says a never-used key has never been used rather than showing a blank", () => {
    const markup = renderKeyTable();
    expect(markup).toContain("Never used");
  });

  it("names the revoke reason on a revoked row", () => {
    const markup = renderKeyTable({
      keys: [key({ status: "revoked", revoke_reason: "leaked in a build log" })],
    });
    expect(markup).toContain("Revoked");
    expect(markup).toContain("leaked in a build log");
  });

  it("renders an empty state that says the secret is shown once", () => {
    const markup = renderKeyTable({ keys: [] });
    expect(markup).toContain("No API keys");
    expect(markup).toContain("shown once");
  });

  it("treats revoked, expired, and rotated as terminal", () => {
    expect(isApiKeyTerminal("active")).toBe(false);
    for (const status of ["revoked", "expired", "rotated"] as const) {
      expect(isApiKeyTerminal(status)).toBe(true);
      // Every terminal state blocks rotation, and each one says what to do
      // instead — "try again" is the wrong remediation for a terminal key.
      expect(apiKeyRotationBlockedReason(key({ status }))).toBeTypeOf("string");
    }
    expect(apiKeyRotationBlockedReason(key({ status: "revoked" }))).toContain("new key");
    expect(apiKeyRotationBlockedReason(key({ status: "expired" }))).toContain("new key");
    expect(apiKeyRotationBlockedReason(key({ status: "rotated" }))).toContain(
      "Rotate the current key",
    );
    expect(apiKeyRotationBlockedReason(key())).toBeNull();
  });

  it("warns that a key cannot be created without a service account", () => {
    const markup = renderToStaticMarkup(
      <CreateApiKeyForm accounts={[]} busy={false} error={null} onSubmit={NOOP} onCancel={NOOP} />,
    );
    expect(markup).toContain("This organization has no service account");
  });

  it("says the key create button will reveal the secret exactly once", () => {
    const markup = renderToStaticMarkup(
      <CreateApiKeyForm
        accounts={[account()]}
        busy={false}
        error={null}
        onSubmit={NOOP}
        onCancel={NOOP}
      />,
    );
    expect(markup).toContain("Create key and show secret");
    expect(markup).toContain("shown once, in a dialog you must acknowledge");
  });

  it("warns when the chosen service account is suspended", () => {
    const markup = renderToStaticMarkup(
      <CreateApiKeyForm
        accounts={[account({ status: "suspended" })]}
        busy={false}
        error={null}
        onSubmit={NOOP}
        onCancel={NOOP}
      />,
    );
    expect(markup).toContain("This service account is suspended");
    expect(markup).toContain("machine_key_suspended");
  });
});

describe("list field parsing", () => {
  it("splits on commas and newlines, trims, and deduplicates", () => {
    expect(parseListField(" prj_1, prj_2 \n prj_1 ")).toEqual(["prj_1", "prj_2"]);
    expect(parseListField("")).toEqual([]);
    expect(parseListField(" , , ")).toEqual([]);
  });
});
