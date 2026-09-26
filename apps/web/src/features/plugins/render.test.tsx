/**
 * Plugin governance rendering.
 *
 * The cases that matter: the expansion block is visually dominant and appears
 * BEFORE the reductions; an unregistered tool is shown as denied rather than
 * filtered out; a policy conflict is its own state; and permission gating
 * produces a read-only surface rather than a disabled one full of controls.
 */

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ApiClientError } from "@/lib/errors";

import type { PluginDetail, PluginInstall, PluginListItem, PluginPolicy } from "./api";
import { packagePolicyVerdict } from "./contracts";
import { PluginDetailView } from "./plugin-detail";
import { PluginTable, PolicySummary } from "./plugin-lists";
import { PermissionDiffView } from "./permission-diff";
import {
  PLUGIN_MANAGE_COPY,
  PLUGIN_READ_COPY,
  PLUGIN_REFUSAL_COPY,
  pluginPermissions,
} from "./plugins-panel";

const NOOP = () => {};
const REF = { current: null } as React.RefObject<HTMLDivElement | null>;

function policy(overrides: Partial<PluginPolicy> = {}): PluginPolicy {
  return {
    publisher_mode: "approved_publishers",
    approved_publishers: ["pub_acme"],
    allowed_packages: [],
    blocked_packages: [],
    pinned_versions: {},
    auto_update: false,
    update_mode: "managed",
    version: 4,
    conflicts: [],
    ...overrides,
  };
}

function item(overrides: Partial<PluginListItem> = {}): PluginListItem {
  return {
    package: {
      package_id: "pkg_web_search",
      publisher_id: "pub_acme",
      publisher_official: false,
      display_name: "Web search",
      summary: "Search the web from a run.",
      status: "published",
      created_at: "2026-09-01T00:00:00.000Z",
      updated_at: "2026-09-20T00:00:00.000Z",
    },
    install: {
      version: "2.0.0",
      review_state: "approved",
      pending_review_version: null,
      review_reason: null,
      blocked_reason: null,
    },
    quarantined: false,
    pinned_version: null,
    blocked: false,
    ...overrides,
  };
}

function install(overrides: Partial<PluginInstall> = {}): PluginInstall {
  return {
    install_id: "ins_1",
    package_id: "pkg_web_search",
    version: "2.0.0",
    pending_review_version: null,
    review_state: "approved",
    review_reason: null,
    blocked_reason: null,
    approved_by: null,
    approved_at: null,
    registered_tools: ["web_search"],
    unregistered_tools: ["web_fetch_raw"],
    created_at: "2026-09-01T00:00:00.000Z",
    updated_at: "2026-09-20T00:00:00.000Z",
    ...overrides,
  };
}

function detail(overrides: Partial<PluginDetail> = {}): PluginDetail {
  return {
    package: item().package,
    versions: [
      {
        version: "2.0.0",
        runtime_min: "0.4.0",
        runtime_max: "0.9.0",
        content_digest: "sha256:aaaa",
        manifest: null,
        published_at: "2026-09-01T00:00:00.000Z",
      },
      {
        version: "2.1.0",
        runtime_min: "0.4.0",
        runtime_max: "1.0.0",
        content_digest: "sha256:bbbb",
        manifest: null,
        published_at: "2026-09-20T00:00:00.000Z",
      },
    ],
    install: install(),
    ...overrides,
  };
}

function renderTable(props: Partial<Parameters<typeof PluginTable>[0]> = {}): string {
  return renderToStaticMarkup(
    <PluginTable
      items={[item()]}
      policy={policy()}
      status="ready"
      error={null}
      selectedId={null}
      onSelect={NOOP}
      onRetry={NOOP}
      emptyTitle="No plugins installed"
      emptyCopy="Install one."
      {...props}
    />,
  );
}

function renderDetail(props: Partial<Parameters<typeof PluginDetailView>[0]> = {}): string {
  return renderToStaticMarkup(
    <PluginDetailView
      detail={detail()}
      item={item()}
      policy={policy()}
      sectionRef={REF}
      diff={null}
      diffStatus="idle"
      diffError={null}
      canManage={true}
      busyAction={null}
      candidateVersion="2.1.0"
      onCandidateChange={NOOP}
      onLoadDiff={NOOP}
      onApprove={NOOP}
      onPin={NOOP}
      onBlock={NOOP}
      onUnblock={NOOP}
      {...props}
    />,
  );
}

function renderDiff(classes: PluginPermissionDiffFixture): string {
  return renderToStaticMarkup(<PermissionDiffView diff={classes} />);
}

type PluginPermissionDiffFixture = Parameters<typeof PermissionDiffView>[0]["diff"];

describe("the permission diff, and expansion dominance", () => {
  const expands = {
    from_version: "2.0.0",
    to_version: "2.1.0",
    expands: true,
    classes: [
      { class: "tools", verdict: "added" as const, added: ["web_fetch_raw"], removed: [] },
      {
        class: "network_destinations",
        verdict: "removed" as const,
        added: [],
        removed: ["https://api.example.com/*"],
      },
      { class: "secret_handles", verdict: "unchanged" as const, added: [], removed: [] },
    ],
  };

  const contracts = {
    from_version: "2.0.0",
    to_version: "2.1.0",
    expands: false,
    classes: [
      {
        class: "network_destinations",
        verdict: "removed" as const,
        added: [],
        removed: ["https://api.example.com/*"],
      },
    ],
  };

  it("states the overall verdict as an expansion when any class grew", () => {
    const markup = renderDiff(expands);
    expect(markup).toContain("Expands capability");
    // Apostrophe-free fragments: `renderToStaticMarkup` HTML-escapes `'`, so an
    // assertion containing one would fail on a correct render.
    expect(markup).toContain("widens the plugin");
    expect(markup).toContain("authority in");
    expect(markup).toContain("Tools");
  });

  it("puts the growing classes in their own block, ABOVE the full table", () => {
    // The layout is the control. A reviewer who reads top to bottom meets the
    // gain before the reduction, so "networking was reduced" cannot be the last
    // thing they saw.
    const markup = renderDiff(expands);
    const gains = markup.indexOf("This update gains");
    const table = markup.indexOf("Every class");
    expect(gains).toBeGreaterThan(-1);
    expect(table).toBeGreaterThan(-1);
    expect(gains).toBeLessThan(table);
  });

  it("marks the growing class rows so the dominance is in the markup, not only in order", () => {
    const markup = renderDiff(expands);
    expect(markup).toContain('data-expanding="true"');
    expect(markup).toContain('data-expanding="false"');
    expect(markup).toContain("Newly permitted");
    // The growth block carries the 3px severity rail, per DESIGN.md §8.2.
    expect(markup).toContain("border-l-[var(--danger)]");
  });

  it("says a reduction does not offset a gain, in the diff itself", () => {
    const markup = renderDiff(expands);
    expect(markup).toContain("A reduction does not offset a gain");
    expect(markup).toContain("needs renewed approval in managed mode");
  });

  it("says the update does not widen anything when it truly does not", () => {
    const markup = renderDiff(contracts);
    expect(markup).toContain("No expansion");
    expect(markup).toContain("does not widen");
    expect(markup).not.toContain("This update gains");
    expect(markup).not.toContain("A reduction does not offset a gain");
  });

  it("refuses to under-read a diff whose flag and classes disagree", () => {
    const contradictory = {
      from_version: "2.0.0",
      to_version: "2.1.0",
      // The server says expansion; no class grew.
      expands: true,
      classes: [{ class: "tools", verdict: "unchanged" as const, added: [], removed: [] }],
    };
    const markup = renderDiff(contradictory);
    expect(markup).toContain("The diff contradicts itself");
    expect(markup).toContain("Treat it as an expansion");
  });

  it("names both versions in the diff so a reviewer knows what is being compared", () => {
    const markup = renderDiff(expands);
    expect(markup).toContain("2.0.0");
    expect(markup).toContain("2.1.0");
  });

  it("announces the verdict as a status for assistive technology", () => {
    expect(renderDiff(expands)).toContain('aria-label="This update expands capability"');
    expect(renderDiff(contracts)).toContain('aria-label="This update does not expand capability"');
  });
});

describe("registered vs unregistered tools", () => {
  it("shows a denied tool rather than filtering it out", () => {
    // F13 default-deny: a tool the organization never registered is refused. An
    // operator who cannot see it will believe the plugin is fully available.
    const markup = renderDetail();
    expect(markup).toContain("web_fetch_raw");
    expect(markup).toContain("1 declared tool is denied");
    expect(markup).toContain("plugin_tool_unregistered");
    expect(markup).toContain('data-usable="false"');
    expect(markup).toContain('data-usable="true"');
  });

  it("counts usable and denied tools in the summary", () => {
    const markup = renderDetail();
    expect(markup).toContain("1 usable · 1 denied");
  });

  it("says a version with no tools has nothing to register", () => {
    const markup = renderDetail({
      detail: detail({ install: install({ registered_tools: [], unregistered_tools: [] }) }),
    });
    expect(markup).toContain("declares no tools");
  });

  it("says a not-installed package needs a host agent, and does not offer install here", () => {
    const markup = renderDetail({
      detail: detail({ install: null }),
      item: item({ install: null }),
    });
    expect(markup).toContain("Not installed");
    expect(markup).toContain("reporting host does");
    expect(markup).not.toContain("Install plugin");
  });
});

describe("the policy summary", () => {
  it("names every policy field an operator has to set", () => {
    const markup = renderToStaticMarkup(<PolicySummary policy={policy()} />);
    expect(markup).toContain("Approved publisher list");
    expect(markup).toContain("Managed — expanding updates need approval");
    expect(markup).toContain("Policy version");
    expect(markup).toContain("v4");
  });

  it("gives a conflict its own state, above everything else, and never hides it", () => {
    const selfContradictory = policy({
      allowed_packages: ["pkg_web_search"],
      blocked_packages: ["pkg_web_search"],
      conflicts: ["pkg_web_search"],
    });
    const markup = renderToStaticMarkup(<PolicySummary policy={selfContradictory} />);
    expect(markup).toContain("Policy conflict (1)");
    expect(markup).toContain("Blocked wins");
    expect(markup).toContain("pkg_web_search");
    expect(markup).toContain('role="alert"');
  });

  it("says direct mode applies an expansion rather than holding it", () => {
    const markup = renderToStaticMarkup(
      <PolicySummary policy={policy({ update_mode: "direct", auto_update: true })} />,
    );
    expect(markup).toContain("Direct mode");
    expect(markup).toContain("applied and audited");
  });

  it("shows a pin as a package@version pair rather than an opaque map", () => {
    const markup = renderToStaticMarkup(
      <PolicySummary policy={policy({ pinned_versions: { pkg_web_search: "2.0.0" } })} />,
    );
    expect(markup).toContain("pkg_web_search @ 2.0.0");
  });
});

describe("the installed-plugins and catalog tables", () => {
  it("shows package, version, review state, policy verdict, and notes", () => {
    const markup = renderTable();
    expect(markup).toContain("Web search");
    expect(markup).toContain("2.0.0");
    expect(markup).toContain("Approved");
    expect(markup).toContain("Permitted");
  });

  it("shows a blocked package as blocked, with the reason it can honestly give", () => {
    const markup = renderTable({
      items: [item({ blocked: true })],
      policy: policy({ blocked_packages: ["pkg_web_search"] }),
    });
    expect(markup).toContain("Blocked by this organization");
    expect(markup).toContain("security audit log");
  });

  it("shows a quarantined version as a platform decision, distinct from an org block", () => {
    const markup = renderTable({ items: [item({ quarantined: true })] });
    expect(markup).toContain("Quarantined");
    expect(markup).toContain("New executions are denied even if the files are on disk");
  });

  it("shows a pin on the row and says a pin blocks a security update", () => {
    const markup = renderTable({ items: [item({ pinned_version: "2.0.0" })] });
    expect(markup).toContain("Pinned to 2.0.0");
  });

  it("shows a catalog-only package as catalog rather than as a broken install", () => {
    const markup = renderTable({ items: [item({ install: null })], installedOnly: false });
    expect(markup).toContain("Catalog");
    expect(markup).toContain("Not installed");
  });

  it("shows a pending review with the reason it is pending", () => {
    const markup = renderTable({
      items: [
        item({
          install: {
            version: "2.0.0",
            review_state: "pending_review",
            pending_review_version: "2.1.0",
            review_reason: "plugin.permission_expansion_detected.v1",
            blocked_reason: null,
          },
        }),
      ],
    });
    expect(markup).toContain("Pending review");
    expect(markup).toContain("widens the plugin");
  });

  it("renders an empty state that says installing code is a supply-chain decision", () => {
    // The copy is the panel's, because the table takes it as a prop: a component
    // that hard-coded the empty copy would be unusable in both contexts.
    const markup = renderTable({
      items: [],
      emptyTitle: "No plugins installed",
      emptyCopy: "Installing third-party code is a supply-chain decision.",
    });
    expect(markup).toContain("No plugins installed");
    expect(markup).toContain("supply-chain decision");
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
    const markup = renderTable({ items: [], status: "error", error });
    expect(markup).toContain("Plugins are unavailable");
    expect(markup).toContain("Reason code permission_denied");
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
    const markup = renderTable({ status: "ready", error });
    expect(markup).toContain("Web search");
    expect(markup).toContain("Refreshing plugins failed");
  });

  it("uses a real table with a caption, so the columns are announced", () => {
    const markup = renderTable();
    expect(markup).toContain("<table");
    expect(markup).toContain("<caption");
    expect(markup).toContain('scope="col"');
    expect(markup).toContain('scope="row"');
  });
});

describe("the policy verdict", () => {
  it("denies a quarantined version ahead of everything else", () => {
    // A quarantine is a platform security fact that no org policy can override,
    // so it must not be reported as merely blocked.
    const verdict = packagePolicyVerdict(
      item({ quarantined: true, blocked: true }),
      policy({ blocked_packages: ["pkg_web_search"] }),
    );
    expect(verdict.verdict).toBe("quarantined");
    expect(verdict.tone).toBe("danger");
  });

  it("reports a self-contradictory package as a conflict, not as plain blocked", () => {
    const verdict = packagePolicyVerdict(
      item({ blocked: true }),
      policy({ blocked_packages: ["pkg_web_search"], conflicts: ["pkg_web_search"] }),
    );
    expect(verdict.verdict).toBe("conflict");
  });

  it("denies a package from a publisher the policy does not approve", () => {
    const verdict = packagePolicyVerdict(item(), policy({ approved_publishers: ["pub_other"] }));
    expect(verdict.label).toBe("Permitted");
    expect(verdict.detail).toContain("is not on it");
  });

  it("warns that a pin blocks a security update", () => {
    const verdict = packagePolicyVerdict(item({ pinned_version: "2.0.0" }), policy());
    expect(verdict.verdict).toBe("pinned");
    expect(verdict.detail).toContain("including a security update");
  });
});

describe("plugin permission gating", () => {
  it("grants read to every member and manage to an admin only", () => {
    // P07-CG: `plugins.read` is member-visible because a member can see which
    // tools exist and why a tool is denied; `plugins.manage` is admin-only because
    // installing code is a supply-chain decision.
    for (const role of ["owner", "admin"] as const) {
      expect(pluginPermissions(role)).toEqual({ canRead: true, canManage: true });
    }
    for (const role of ["member", "viewer"] as const) {
      expect(pluginPermissions(role)).toEqual({ canRead: true, canManage: false });
    }
    expect(pluginPermissions(undefined).canRead).toBe(false);
  });

  it("renders a read-only surface with no manage controls for a member", () => {
    const markup = renderDetail({ canManage: false });
    expect(markup).not.toContain("Block package");
    expect(markup).not.toContain("Pin version");
    expect(markup).not.toContain("Unblock package");
    // The state stays fully readable.
    expect(markup).toContain("Web search");
    expect(markup).toContain("web_search");
  });

  it("offers block and pin to an admin, with the reason each demands", () => {
    const markup = renderDetail({ canManage: true });
    expect(markup).toContain("Block package");
    expect(markup).toContain("Pin version");
  });

  it("says a member can see what is waiting and why, even without approving it", () => {
    const pending = item({
      install: {
        version: "2.0.0",
        review_state: "pending_review",
        pending_review_version: "2.1.0",
        review_reason: "plugin.permission_expansion_detected.v1",
        blocked_reason: null,
      },
    });
    const markup = renderDetail({ canManage: false, item: pending });
    expect(markup).toContain("Waiting for approval");
    expect(markup).not.toContain("Approve this version");
    expect(markup).toContain("Approving is an administrator action");
  });

  it("names the read and manage rules in the panel's own copy", () => {
    expect(PLUGIN_READ_COPY).toContain("every member");
    expect(PLUGIN_MANAGE_COPY).toContain("administrator action");
    expect(PLUGIN_REFUSAL_COPY).toContain("no plugin state at all without permission");
  });
});
