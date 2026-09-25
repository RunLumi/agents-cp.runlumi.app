import { afterEach, describe, expect, it, vi } from "vitest";

import {
  decodeApproval,
  decodeMcpRegistration,
  decodeToolPage,
  decodeToolPolicy,
  getToolDecision,
  defaultToolsApi,
  type ToolDefinition,
} from "./helpers";

describe("P05 tools contracts", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("decodes the tool page without retaining arbitrary metadata", () => {
    const page = decodeToolPage({
      items: [
        {
          id: "tool_readonly_repo",
          name: "Read repository",
          source: "built_in",
          risk_class: "read_only",
          capability_ids: ["filesystem_read"],
          fingerprint: "sha256:read",
          lifecycle: "active",
          version: 2,
          metadata: { private_note: "opaque-fixture" },
        },
      ],
      next_cursor: null,
      has_more: false,
    });

    expect(page?.items[0]).toMatchObject({
      tool_id: "tool_readonly_repo",
      risk_class: "read_only",
      capability_ids: ["filesystem_read"],
    });
    expect(JSON.stringify(page)).not.toContain("opaque-fixture");
  });

  it("keeps MCP metadata non-secret and masks secret handles", () => {
    const registration = decodeMcpRegistration({
      mcp_id: "mcp_fixture",
      source: "custom",
      transport: "http",
      endpoint_metadata: {
        origin: "https://mcp.example.test/v1?token=raw-token",
        authorization: "Bearer raw-token",
      },
      command_metadata: { command: "/opt/bin/node", args: ["--token", "raw-token"] },
      allowed_origins: ["https://mcp.example.test/path?token=raw-token"],
      required_secret_handles: ["secret_handle_abcdef123456"],
      tool_fingerprint: "sha256:tool",
      tool_list: [
        {
          tool_id: "tool_submit",
          name: "Submit",
          fingerprint: "sha256:submit",
          risk_class: "external_side_effect",
        },
      ],
      policy_status: "pending_review",
      version: 1,
    });

    expect(registration).toMatchObject({
      endpoint_label: "Host mcp.example.test",
      command_label: "Command node",
      allowed_origins: ["https://mcp.example.test"],
      required_secret_handle_labels: ["secret…3456"],
      review_required: true,
    });
    expect(registration?.tools[0]?.risk_class).toBe("external_side_effect");
    expect(JSON.stringify(registration)).not.toContain("raw-token");
  });

  it("redacts common secret-shaped values in approval summaries", () => {
    const approval = decodeApproval({
      id: "apr_fixture",
      org_id: "org_fixture",
      project_id: "prj_fixture",
      run_id: "run_fixture",
      tool_call_id: "tcl_fixture",
      tool_id: "tool_browser_submit",
      tool_fingerprint: "sha256:browser",
      risk_class: "external_side_effect",
      approval_mode: "per_use",
      status: "pending",
      arguments_summary: "domain=example.test; token=raw-token; operation=submit",
      requested_by_principal_id: "usr_fixture",
      requested_at: "2026-09-25T12:00:00.000Z",
      expires_at: "2026-09-25T12:15:00.000Z",
      resolved_by_principal_id: null,
      resolved_at: null,
      resolution_reason: null,
      version: 1,
    });

    expect(approval?.arguments_summary).toContain("token=[redacted]");
    expect(approval?.arguments_summary).not.toContain("raw-token");
  });

  it("keeps a valid policy document explicit and reviewable", () => {
    const policy = decodeToolPolicy({
      org_id: "org_fixture",
      policy_version: 4,
      version: 2,
      document: {
        schema_version: 1,
        default_posture: "deny",
        default_approval_mode: "per_use",
        tool_ids: ["tool_fixture"],
        mcp_ids: ["mcp_fixture"],
        tool_decisions: { tool_fixture: "require_per_use_approval" },
        browser: {
          allowed_domains: ["example.test"],
          blocked_domains: [],
          allow_download: false,
          allow_upload: false,
          allow_authenticated: false,
          allow_clipboard: false,
          external_submit: "require_approval",
        },
        computer: {
          allow_accessibility: false,
          allow_screen_capture: false,
          allow_keyboard_mouse: false,
          allow_shell_escalation: false,
          allowed_applications: [],
        },
      },
    });
    const tool: ToolDefinition = {
      tool_id: "tool_fixture",
      name: "Fixture",
      source: "custom",
      risk_class: "external_side_effect",
      capability_ids: [],
      fingerprint: "sha256:fixture",
      lifecycle: "active",
      version: 1,
    };

    expect(policy?.document.valid).toBe(true);
    expect(getToolDecision(tool, policy)).toBe("require_per_use_approval");
  });

  it("fails closed for malformed policy sections and never infers allow", () => {
    const policy = decodeToolPolicy({
      org_id: "org_fixture",
      policy_version: 4,
      version: 1,
      document: {
        schema_version: 1,
        default_posture: "deny",
        default_approval_mode: "per_use",
        tool_ids: ["tool_fixture"],
        mcp_ids: [],
        tool_decisions: { tool_fixture: "allow" },
      },
    });
    const tool: ToolDefinition = {
      tool_id: "tool_fixture",
      name: "Fixture",
      source: "custom",
      risk_class: "network",
      capability_ids: [],
      fingerprint: "sha256:fixture",
      lifecycle: "active",
      version: 1,
    };

    expect(policy?.document.valid).toBe(false);
    expect(policy?.policy_state).toBe("ok");
    expect(policy?.document.browser.allow_download).toBe(false);
    expect(policy?.document.computer.allow_keyboard_mouse).toBe(false);
    expect(getToolDecision(tool, policy)).toBeNull();
    expect(getToolDecision({ ...tool, tool_id: "unknown" }, policy)).toBeNull();
  });

  it("treats a missing server policy as fail closed", () => {
    const policy = decodeToolPolicy({
      org_id: "org_fixture",
      policy_state: "missing",
      policy_version: 0,
      version: 0,
      document: {
        schema_version: 1,
        default_posture: "deny",
        default_approval_mode: "none",
        tool_ids: [],
        mcp_ids: [],
        browser: {
          allowed_domains: [],
          blocked_domains: [],
          allow_download: false,
          allow_upload: false,
          allow_authenticated: false,
          allow_clipboard: false,
          external_submit: "deny",
        },
        computer: {
          allow_accessibility: false,
          allow_screen_capture: false,
          allow_keyboard_mouse: false,
          allow_shell_escalation: false,
          allowed_applications: [],
        },
      },
    });

    expect(policy?.policy_state).toBe("missing");
    expect(policy?.document.valid).toBe(false);
  });

  it("sends CSRF and the stable idempotency key when resolving an approval", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          id: "apr_fixture",
          org_id: "org_fixture",
          project_id: "prj_fixture",
          run_id: "run_fixture",
          tool_call_id: "tcl_fixture",
          tool_id: "tool_fixture",
          tool_fingerprint: "sha256:fixture",
          risk_class: "external_side_effect",
          approval_mode: "per_use",
          status: "approved",
          arguments_summary: "domain=example.test; operation=submit",
          requested_by_principal_id: "usr_fixture",
          requested_at: "2026-09-25T12:00:00.000Z",
          expires_at: "2026-09-25T12:15:00.000Z",
          resolved_by_principal_id: "usr_reviewer",
          resolved_at: "2026-09-25T12:01:00.000Z",
          resolution_reason: "approved",
          version: 2,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("document", { cookie: "lumi_csrf=csrf-token" });

    await defaultToolsApi.resolveApproval(
      "org_fixture",
      "apr_fixture",
      { decision: "approved", version: 1 },
      "stable-approval-key",
    );

    const [, init] = fetchMock.mock.calls[0] ?? [];
    const headers = new Headers(init?.headers);
    expect(init?.credentials).toBe("include");
    expect(headers.get("X-CSRF-Token")).toBe("csrf-token");
    expect(headers.get("Idempotency-Key")).toBe("stable-approval-key");
    expect(init?.body).toBe(JSON.stringify({ decision: "approved", version: 1 }));
  });

  it("rejects a page when one tool entry is malformed", () => {
    expect(
      decodeToolPage({
        items: [{ tool_id: "tool_missing_fields" }],
        next_cursor: null,
        has_more: false,
      }),
    ).toBeNull();
  });
});
