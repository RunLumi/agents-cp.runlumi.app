/**
 * P07 plugin-governance API contract.
 *
 * The two things whose failure would be silent: a decoder that accepts a
 * projection with a field it does not understand, and a transport that drops the
 * idempotency boundary on a supply-chain mutation.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiClientError } from "@/lib/errors";

import {
  approvePluginInstall,
  blockPlugin,
  getPlugin,
  getPluginPermissionDiff,
  listPlugins,
  permissionClassLabel,
  pinPluginVersion,
  unblockPlugin,
  updatePluginPolicy,
  DIFF_CLASSES,
  PLUGIN_PERMISSION_CLASSES,
  PLUGIN_REVIEW_STATES,
  PUBLISHER_MODES,
  UPDATE_MODES,
} from "./api";
import { presentPluginError } from "./errors";

const requestId = "req_0123456789abcdef0123456789abcdef";
const orgId = "org_0123456789abcdef0123456789abcdef";
const packageId = "pkg_web_search";
const version = "2.1.0";

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "X-Request-ID": requestId },
  });
}

function policyBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    publisher_mode: "approved_publishers",
    approved_publishers: ["pub_acme"],
    allowed_packages: ["pkg_web_search"],
    blocked_packages: ["pkg_web_search"],
    pinned_versions: {},
    auto_update: false,
    update_mode: "managed",
    version: 4,
    conflicts: ["pkg_web_search"],
    ...overrides,
  };
}

function packageBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    package_id: packageId,
    publisher_id: "pub_acme",
    publisher_official: false,
    display_name: "Web search",
    summary: "Search the web from a run.",
    status: "published",
    created_at: "2026-09-01T00:00:00.000Z",
    updated_at: "2026-09-20T00:00:00.000Z",
    ...overrides,
  };
}

function listInstallBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: "2.0.0",
    review_state: "approved",
    pending_review_version: null,
    review_reason: null,
    blocked_reason: null,
    ...overrides,
  };
}

function installBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    install_id: "ins_0123456789abcdef0123456789abcdef",
    package_id: packageId,
    version: "2.0.0",
    pending_review_version: "2.1.0",
    review_state: "pending_review",
    review_reason: "plugin.permission_expansion_detected.v1",
    blocked_reason: null,
    approved_by: null,
    approved_at: null,
    registered_tools: ["web_search"],
    unregistered_tools: ["web_fetch_raw"],
    created_at: "2026-09-01T00:00:00.000Z",
    updated_at: "2026-09-25T00:00:00.000Z",
    ...overrides,
  };
}

function lastCall(): [string, RequestInit] {
  const call = vi.mocked(fetch).mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  const [url, init] = call;
  if (typeof url !== "string") throw new Error("fetch was not called with a string URL");
  return [url, (init ?? {}) as RequestInit];
}

function requestBody(init: RequestInit): unknown {
  if (typeof init.body !== "string") throw new Error("the request carried no JSON body");
  return JSON.parse(init.body);
}

describe("P07 plugin API contract", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
    vi.stubGlobal("document", { cookie: "lumi_csrf=csrf-token" });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("publishes exactly the frozen vocabularies", () => {
    expect([...PLUGIN_REVIEW_STATES].sort()).toEqual([
      "approved",
      "blocked",
      "pending_review",
      "quarantined",
      "unreviewed",
    ]);
    expect([...PUBLISHER_MODES].sort()).toEqual(["any", "approved_publishers", "official_only"]);
    expect([...UPDATE_MODES].sort()).toEqual(["direct", "managed"]);
    expect([...DIFF_CLASSES].sort()).toEqual(["added", "removed", "unchanged"]);
    expect(PLUGIN_PERMISSION_CLASSES).toHaveLength(8);
    expect(permissionClassLabel("secret_handles")).toBe("Secret handles");
    expect(permissionClassLabel("a_class_from_the_future")).toBe("a_class_from_the_future");
  });

  it("lists installed and available packages with the policy in one read", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({
        items: [
          {
            package: packageBody(),
            install: listInstallBody(),
            quarantined: false,
            pinned_version: null,
            blocked: true,
          },
          {
            package: packageBody({ package_id: "pkg_uninstalled", display_name: "Uninstalled" }),
            install: null,
            quarantined: false,
            pinned_version: null,
            blocked: false,
          },
        ],
        policy: policyBody(),
      }),
    );
    const overview = await listPlugins(orgId);
    expect(overview.items).toHaveLength(2);
    // The conflict is carried on the policy, not resolved away.
    expect(overview.policy.conflicts).toEqual(["pkg_web_search"]);
    expect(overview.items[0]?.blocked).toBe(true);
    // A catalog-only package has a null install rather than a zero-valued one.
    expect(overview.items[1]?.install).toBeNull();

    const [path, init] = lastCall();
    expect(path).toBe(`/api/v1/orgs/${orgId}/plugins`);
    expect(init.method).toBe("GET");
  });

  it("refuses a policy whose conflicts field is missing, rather than defaulting it", async () => {
    // Defaulting `conflicts` to empty would silently hide a self-contradictory
    // policy, which is the one state this surface exists to surface.
    const { conflicts: _dropped, ...withoutConflicts } = policyBody();
    vi.mocked(fetch).mockResolvedValue(
      response({
        items: [],
        policy: withoutConflicts,
      }),
    );
    await expect(listPlugins(orgId)).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("reads a package detail with its versions and install", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({
        package: packageBody(),
        versions: [
          {
            version: "2.1.0",
            runtime_min: "0.4.0",
            runtime_max: "0.9.0",
            content_digest: "sha256:aaaa",
            manifest: { tools: ["web_search"] },
            published_at: "2026-09-20T00:00:00.000Z",
          },
        ],
        install: installBody(),
      }),
    );
    const detail = await getPlugin(orgId, packageId);
    expect(detail.versions).toHaveLength(1);
    expect(detail.install?.unregistered_tools).toEqual(["web_fetch_raw"]);
    expect(lastCall()[0]).toBe(`/api/v1/orgs/${orgId}/plugins/${packageId}`);
  });

  it("carries the current policy version on a block, with the CSRF boundary", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ policy: policyBody({ version: 5, blocked_packages: [packageId] }) }),
    );
    const updated = await blockPlugin(
      orgId,
      packageId,
      { version: 4, reason: "untrusted publisher" },
      "idem-block",
    );
    expect(updated.version).toBe(5);

    const [path, init] = lastCall();
    expect(path).toBe(`/api/v1/orgs/${orgId}/plugins/${packageId}/block`);
    expect(init.method).toBe("POST");
    expect(requestBody(init)).toEqual({ version: 4, reason: "untrusted publisher" });
    expect(new Headers(init.headers).get("Idempotency-Key")).toBe("idem-block");
    expect(new Headers(init.headers).get("X-CSRF-Token")).toBe("csrf-token");
  });

  it("unblocks through the symmetric route and requires the same reason", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ policy: policyBody({ version: 6, blocked_packages: [], conflicts: [] }) }),
    );
    const updated = await unblockPlugin(
      orgId,
      packageId,
      { version: 5, reason: "publisher reviewed" },
      "idem-unblock",
    );
    expect(updated.blocked_packages).toEqual([]);
    expect(lastCall()[0]).toBe(`/api/v1/orgs/${orgId}/plugins/${packageId}/unblock`);
  });

  it("pins an exact version and says so in the request", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ policy: policyBody({ version: 7, pinned_versions: { [packageId]: version } }) }),
    );
    const updated = await pinPluginVersion(
      orgId,
      packageId,
      { version: 6, version_to_pin: version, reason: "held for audit" },
      "idem-pin",
    );
    expect(updated.pinned_versions[packageId]).toBe(version);

    const [path, init] = lastCall();
    expect(path).toBe(`/api/v1/orgs/${orgId}/plugins/${packageId}/pin`);
    expect(requestBody(init)).toEqual({
      version: 6,
      version_to_pin: version,
      reason: "held for audit",
    });
  });

  it("approves a pending review and returns the approved install", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ install: installBody({ review_state: "approved", approved_by: "usr_1" }) }),
    );
    const install = await approvePluginInstall(
      orgId,
      packageId,
      { request_id: "req_client_trace" },
      "idem-approve",
    );
    expect(install.review_state).toBe("approved");
    expect(lastCall()[0]).toBe(`/api/v1/orgs/${orgId}/plugins/${packageId}/approve`);
    expect(requestBody(lastCall()[1])).toEqual({ request_id: "req_client_trace" });
  });

  it("reads the permission diff against an explicit base version", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({
        permission_diff: {
          from_version: "2.0.0",
          to_version: version,
          expands: true,
          classes: [
            { class: "tools", verdict: "added", added: ["web_fetch_raw"], removed: [] },
            {
              class: "network_destinations",
              verdict: "removed",
              added: [],
              removed: ["https://api.example.com/*"],
            },
          ],
        },
      }),
    );
    const diff = await getPluginPermissionDiff(orgId, packageId, version, "2.0.0");
    expect(diff.expands).toBe(true);
    expect(diff.classes[0]?.added).toEqual(["web_fetch_raw"]);
    expect(lastCall()[0]).toBe(
      `/api/v1/orgs/${orgId}/plugins/${packageId}/versions/${version}/permission-diff?against_version=2.0.0`,
    );
  });

  it("refuses a diff whose verdict is not one of the three frozen values", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({
        permission_diff: {
          from_version: "2.0.0",
          to_version: version,
          expands: true,
          classes: [{ class: "tools", verdict: "maybe", added: [], removed: [] }],
        },
      }),
    );
    await expect(getPluginPermissionDiff(orgId, packageId, version, "2.0.0")).rejects.toMatchObject(
      { code: "invalid_response" },
    );
  });

  it("patches the policy with only the fields the caller changed", async () => {
    vi.mocked(fetch).mockResolvedValue(
      response({ policy: policyBody({ version: 5, update_mode: "direct" }) }),
    );
    await updatePluginPolicy(orgId, { version: 4, update_mode: "direct" }, "idem-policy");
    const [path, init] = lastCall();
    expect(path).toBe(`/api/v1/orgs/${orgId}/plugins/policy`);
    expect(init.method).toBe("PATCH");
    // `deny_unknown_fields` on the Rust body means a stray key is a 400, so only
    // the changed field is sent.
    expect(requestBody(init)).toEqual({ version: 4, update_mode: "direct" });
  });
});

describe("P07 plugin error presentation", () => {
  const CASES: ReadonlyArray<readonly [string, string]> = [
    ["plugin_blocked", "This organization blocks the package"],
    ["plugin_quarantined", "even if the files are still on disk"],
    ["plugin_permission_expanded", "managed mode refused the install"],
    ["plugin_incompatible", "cannot be installed here"],
    ["plugin_integrity_failed", "treated as a security event"],
    ["plugin_pinned", "cannot move to any other"],
    ["plugin_pinned_conflict", "already pinned to a different version"],
    ["plugin_tool_unregistered", "default to denied"],
    ["plugin_publisher_not_allowed", "does not permit this publisher"],
    ["policy_conflict", "put a package on both the allow list and the block list"],
    ["version_not_pending_review", "no install awaiting review"],
    ["manifest_invalid", "could not be parsed"],
    ["manifest_digest_mismatch", "report is evidence, never permission"],
    ["version_conflict", "refused rather than overwriting"],
  ];

  for (const [reason, fragment] of CASES) {
    it(`maps ${reason} to specific, actionable copy`, () => {
      const error = new ApiClientError({
        code: "conflict",
        kind: "api",
        status: 409,
        requestId,
        details: { reason },
        retryable: false,
      });
      const presentation = presentPluginError(error);
      expect(presentation.code).toBe(reason);
      expect(presentation.message).toContain(fragment);
      expect(presentation.requestId).toBe(requestId);
    });
  }

  it("distinguishes a quarantine from an org block in the title", () => {
    // "Try again" and "ask an administrator" are both wrong for these; the
    // remediation is to wait for the platform in one case and to unblock in the
    // other, so the two must not share a message.
    const quarantine = presentPluginError(
      new ApiClientError({
        code: "conflict",
        kind: "api",
        status: 409,
        requestId: undefined,
        details: { reason: "plugin_quarantined" },
        retryable: false,
      }),
    );
    const blocked = presentPluginError(
      new ApiClientError({
        code: "conflict",
        kind: "api",
        status: 409,
        requestId: undefined,
        details: { reason: "plugin_blocked" },
        retryable: false,
      }),
    );
    expect(quarantine.title).not.toBe(blocked.title);
    expect(quarantine.title).toContain("platform");
    expect(blocked.title).toContain("blocked");
  });

  it("falls back to the shared presentation for a code it does not know", () => {
    const presentation = presentPluginError(
      new ApiClientError({
        code: "some_future_code",
        kind: "api",
        status: 500,
        requestId: undefined,
        details: {},
        retryable: true,
      }),
    );
    expect(presentation.tone).toBe("warning");
    expect(presentation.code).toBe("some_future_code");
  });
});
