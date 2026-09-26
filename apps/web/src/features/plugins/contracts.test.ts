/**
 * Plugin governance rules, with the expansion detector as the centre of gravity.
 *
 * P07-CG: "**Expansion in any class is expansion.** A version that adds a tool,
 * widens a network destination, adds a secret handle, or raises
 * `browser_capability` from `read` to `computer_use` is an expansion even if it
 * removes something else." The tests below exist because the failure they prevent
 * is not a crash — it is a reviewer reading "networking was reduced", concluding
 * the update is a tightening, and approving a version that gained a tool.
 */

import { describe, expect, it } from "vitest";

import type { PluginInstall, PluginListItem, PluginPermissionDiff, PluginPolicy } from "./api";
import {
  PIN_NOTE,
  blockedReason,
  canPin,
  classVerdicts,
  conflictingPackages,
  conflictExplanation,
  diffExpands,
  expansionDetail,
  expansionHeadline,
  expandingClasses,
  isConflicting,
  isPendingReview,
  pendingReviewReason,
  reviewStateDetail,
  reviewStateLabel,
  reviewStateTone,
  toolRegistrations,
  unusableToolCount,
  usableToolCount,
  verdictLabel,
} from "./contracts";

function classDiff(
  className: string,
  verdict: "added" | "removed" | "unchanged",
  added: string[] = [],
  removed: string[] = [],
): PluginPermissionDiff["classes"][number] {
  return { class: className, verdict, added, removed };
}

function diff(expands: boolean, classes: PluginPermissionDiff["classes"]): PluginPermissionDiff {
  return { from_version: "2.0.0", to_version: "2.1.0", classes, expands };
}

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

function listItem(overrides: Partial<PluginListItem> = {}): PluginListItem {
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
    registered_tools: ["web_search", "web_open"],
    unregistered_tools: ["web_fetch_raw"],
    created_at: "2026-09-01T00:00:00.000Z",
    updated_at: "2026-09-20T00:00:00.000Z",
    ...overrides,
  };
}

describe("the expansion detector", () => {
  it("treats an added tool as an expansion even when a network destination was removed", () => {
    // This is THE case. A reviewer skimming the diff sees a reduction and misses
    // the gain; the function exists so that cannot be the deciding signal.
    const result = diff(true, [
      classDiff("tools", "added", ["web_fetch_raw"]),
      classDiff("network_destinations", "removed", [], ["https://api.example.com/*"]),
    ]);
    const growing = expandingClasses(result);
    expect(growing).toHaveLength(1);
    expect(growing[0]?.class).toBe("tools");
    expect(growing[0]?.added).toEqual(["web_fetch_raw"]);
    expect(growing[0]?.expanding).toBe(true);
  });

  it("names a reduction as NOT expanding, so it cannot masquerade as a gain", () => {
    const result = diff(false, [classDiff("network_destinations", "removed", [], ["https://a/*"])]);
    expect(expandingClasses(result)).toEqual([]);
    expect(diffExpands(result).expands).toBe(false);
  });

  it("treats an added secret handle and a raised browser capability as expansions", () => {
    const result = diff(true, [
      classDiff("secret_handles", "added", ["(stripe_key, billing writes)"]),
      classDiff("browser_capability", "added", ["computer_use"]),
      classDiff("tools", "removed", [], ["legacy_tool"]),
    ]);
    expect(
      expandingClasses(result)
        .map((entry) => entry.class)
        .sort(),
    ).toEqual(["browser_capability", "secret_handles"]);
  });

  it("does not treat a class that moved in both directions as a reduction", () => {
    // The server reports a class that both gained and lost as `added`, because
    // the table answers one question: did capability grow. Reading it as a net
    // reduction is exactly the misreading this surface is built against.
    const result = diff(true, [classDiff("tools", "added", ["new_tool"], ["old_tool"])]);
    expect(expandingClasses(result)).toHaveLength(1);
    expect(classVerdicts(result)[0]?.removed).toEqual(["old_tool"]);
  });

  it("reports no expansion when every class is unchanged", () => {
    const result = diff(false, [
      classDiff("tools", "unchanged"),
      classDiff("network_destinations", "unchanged"),
    ]);
    expect(expandingClasses(result)).toEqual([]);
    expect(expansionHeadline(result)).toContain("does not widen");
    expect(expansionDetail(result)[0]).toContain("Nothing was gained and nothing was lost");
  });

  it("trusts the server's expands flag when it agrees with the classes", () => {
    const result = diff(true, [classDiff("tools", "added", ["t"])]);
    expect(diffExpands(result)).toEqual({ expands: true, contradictsServer: false });
  });

  /**
   * The server's `expands` is authoritative. A disagreement is a contract
   * inconsistency, and the surface reports it rather than picking a winner — an
   * expansion flagged as a contraction is the dangerous direction to guess in.
   */
  it("reports a contradiction between the flag and the per-class verdicts", () => {
    const flagsExpansion = diff(true, [classDiff("tools", "unchanged")]);
    expect(diffExpands(flagsExpansion)).toEqual({ expands: true, contradictsServer: true });
    expect(expansionHeadline(flagsExpansion)).toContain("no growing class is named");

    const hidesExpansion = diff(false, [classDiff("tools", "added", ["t"])]);
    expect(diffExpands(hidesExpansion)).toEqual({ expands: false, contradictsServer: true });
  });

  it("says a reduction does not offset a gain, in words a reviewer will read", () => {
    const result = diff(true, [
      classDiff("tools", "added", ["web_fetch_raw"]),
      classDiff("filesystem_scopes", "removed", [], ["/var/lib/*"]),
    ]);
    // Only the GROWING class is named in the headline; the reduction is reported
    // separately so it cannot be read as the verdict.
    expect(expansionHeadline(result)).toContain("Tools");
    expect(expansionHeadline(result)).toContain("whatever else was reduced");
    const detail = expansionDetail(result).join(" ");
    expect(detail).toContain("Gained authority");
    expect(detail).toContain("Reduced authority");
    expect(detail).toContain("A reduction does not offset a gain");
    expect(detail).toContain("needs renewed approval");
  });

  it("labels the verdicts in a reviewer's language rather than the wire tokens", () => {
    expect(verdictLabel("added")).toBe("Gained");
    expect(verdictLabel("removed")).toBe("Lost");
    expect(verdictLabel("unchanged")).toBe("Unchanged");
  });

  it("gives a growth class a warning tone and a shrink class an informational one", () => {
    const result = diff(true, [
      classDiff("tools", "added", ["t"]),
      classDiff("mcp_servers", "removed", [], ["s"]),
    ]);
    const verdicts = classVerdicts(result);
    expect(verdicts.find((entry) => entry.class === "tools")?.expanding).toBe(true);
    expect(verdicts.find((entry) => entry.class === "mcp_servers")?.expanding).toBe(false);
  });
});

describe("tool registration, and F13 default-deny made visible", () => {
  it("lists a registered tool as usable and an unregistered one as denied", () => {
    const tools = toolRegistrations(install());
    const byId = new Map(tools.map((tool) => [tool.toolId, tool]));
    expect(byId.get("web_search")?.usable).toBe(true);
    expect(byId.get("web_fetch_raw")?.usable).toBe(false);
    expect(byId.get("web_fetch_raw")?.detail).toContain("plugin_tool_unregistered");
  });

  it("counts usable and denied tools separately", () => {
    expect(usableToolCount(install())).toBe(2);
    expect(unusableToolCount(install())).toBe(1);
    expect(usableToolCount(null)).toBe(0);
    expect(unusableToolCount(null)).toBe(0);
  });

  it("does not report a tool as both usable and denied when it appears on both lists", () => {
    // A malformed projection must not make a denied tool look usable; the denied
    // list wins, because that is the direction the server refuses in.
    const tools = toolRegistrations(
      install({ registered_tools: ["web_fetch_raw"], unregistered_tools: ["web_fetch_raw"] }),
    );
    expect(tools.filter((tool) => tool.toolId === "web_fetch_raw")).toHaveLength(1);
    expect(tools[0]?.usable).toBe(false);
    expect(
      usableToolCount(
        install({ registered_tools: ["web_fetch_raw"], unregistered_tools: ["web_fetch_raw"] }),
      ),
    ).toBe(0);
  });

  it("returns nothing for a package that is not installed", () => {
    expect(toolRegistrations(null)).toEqual([]);
  });
});

describe("review state", () => {
  it("never lets a blocked or unreviewed install read as approved", () => {
    // The property that matters is not that every state is visually distinct —
    // blocked and quarantined are both "refused" and sharing a tone is correct —
    // it is that nothing refused looks like something permitted.
    const tones = {
      approved: reviewStateTone("approved"),
      pending: reviewStateTone("pending_review"),
      blocked: reviewStateTone("blocked"),
      quarantined: reviewStateTone("quarantined"),
      unreviewed: reviewStateTone("unreviewed"),
    };
    expect(tones.approved).toBe("success");
    expect(tones.blocked).toBe("danger");
    expect(tones.quarantined).toBe("danger");
    expect(tones.pending).toBe("warning");
    for (const refused of ["blocked", "quarantined", "pending_review", "unreviewed"] as const) {
      expect(reviewStateTone(refused)).not.toBe(tones.approved);
    }
    // And every state has its own label, so a screenshot is unambiguous.
    const labels = (
      ["approved", "pending_review", "blocked", "quarantined", "unreviewed"] as const
    ).map(reviewStateLabel);
    expect(new Set(labels).size).toBe(5);
  });

  it("says a pending review is not running yet", () => {
    const state = listItem({
      install: {
        version: "2.0.0",
        review_state: "pending_review",
        pending_review_version: "2.1.0",
        review_reason: null,
        blocked_reason: null,
      },
    });
    const detail = reviewStateDetail(state.install);
    expect(detail).toContain("not installed");
    expect(detail).toContain("nothing about it runs");
  });

  it("says an unreviewed install has every tool denied", () => {
    const detail = reviewStateDetail(
      listItem({ install: { ...listItem().install!, review_state: "unreviewed" } }).install,
    );
    expect(detail).toContain("plugin_tool_unregistered");
  });

  it("explains a pending review as an expansion when that is the recorded reason", () => {
    const state = listItem({
      install: {
        version: "2.0.0",
        review_state: "pending_review",
        pending_review_version: "2.1.0",
        review_reason: "plugin.permission_expansion_detected.v1",
        blocked_reason: null,
      },
    });
    expect(isPendingReview(state.install)).toBe(true);
    const reason = pendingReviewReason(state.install);
    expect(reason).toContain("widens the plugin's declared capability");
    expect(reason).toContain("Read the permission diff");
  });

  it("distinguishes an unrecorded pending review from an expansion one", () => {
    const unrecorded = listItem({
      install: {
        version: "2.0.0",
        review_state: "pending_review",
        pending_review_version: "2.1.0",
        review_reason: null,
        blocked_reason: null,
      },
    });
    expect(pendingReviewReason(unrecorded.install)).toContain("No reason was recorded");
    expect(pendingReviewReason(null)).toBe("");
    expect(pendingReviewReason(listItem().install)).toBe("");
  });
});

describe("policy conflicts", () => {
  it("reports a package on both lists as a conflict rather than resolving it", () => {
    const selfContradictory = policy({
      allowed_packages: ["pkg_web_search"],
      blocked_packages: ["pkg_web_search"],
      conflicts: ["pkg_web_search"],
    });
    expect(conflictingPackages(selfContradictory)).toEqual(["pkg_web_search"]);
    expect(isConflicting(selfContradictory, "pkg_web_search")).toBe(true);
    expect(conflictExplanation(selfContradictory, "pkg_web_search")).toContain("Blocked wins");
    expect(conflictExplanation(selfContradictory, "pkg_web_search")).toContain("reported");
  });

  it("reports no conflict for a consistent policy", () => {
    const consistent = policy();
    expect(isConflicting(consistent, "pkg_web_search")).toBe(false);
    expect(conflictExplanation(consistent, "pkg_web_search")).toBe("");
  });

  it("blocks a pin on a self-contradictory package, and explains why", () => {
    const selfContradictory = policy({
      blocked_packages: ["pkg_web_search"],
      conflicts: ["pkg_web_search"],
    });
    const reason = canPin(selfContradictory, "pkg_web_search");
    expect(reason).toContain("on both the allow and the block list");
    expect(reason).toContain("Remove one of the two entries");
  });

  it("blocks re-pinning a package that is already pinned, because lifting is a separate act", () => {
    const pinned = policy({ pinned_versions: { pkg_web_search: "2.0.0" } });
    const reason = canPin(pinned, "pkg_web_search");
    expect(reason).toContain("already pinned");
    expect(reason).toContain("separate action");
  });

  it("permits a first pin on a clean package", () => {
    expect(canPin(policy(), "pkg_web_search")).toBeNull();
  });

  it("states that a pin is exact and blocks a security update", () => {
    expect(PIN_NOTE).toContain("exact");
    expect(PIN_NOTE).toContain("including a security update");
    expect(PIN_NOTE).toContain("explicit");
  });
});

describe("the blocked reason a projection can honestly show", () => {
  it("prefers the reason the organization recorded over anything else", () => {
    const item = listItem({
      blocked: true,
      install: {
        version: "2.0.0",
        review_state: "blocked",
        pending_review_version: null,
        // A managed-mode expansion writes `review_reason`; a block writes
        // `blocked_reason`. When both are present the block's reason is the one
        // that explains the block, so it wins.
        review_reason: "plugin.permission_expansion_detected.v1",
        blocked_reason: "untrusted publisher",
      },
    });
    expect(blockedReason(item)).toContain("untrusted publisher");
  });

  it("falls back to the review reason when no block reason was recorded", () => {
    const item = listItem({
      blocked: true,
      install: {
        version: "2.0.0",
        review_state: "blocked",
        pending_review_version: null,
        review_reason: "untrusted publisher",
        blocked_reason: null,
      },
    });
    expect(blockedReason(item)).toContain("untrusted publisher");
  });

  /**
   * F25's Web UX asks for a visible blocked reason, and the block action records
   * it on the install's `blocked_reason`, so the reason the operator typed is the
   * reason the surface shows. This test previously pinned the opposite — that the
   * reason reached only the audit log — because the projection had no reason
   * column. The backend now records it, so the honest fallback is only for a
   * policy block with no install row, which has no reason to attach.
   */
  it("falls back honestly when a policy block has no install row to carry a reason", () => {
    const reason = blockedReason(listItem({ blocked: true, install: null }));
    expect(reason).toContain("no installation to attach a reason to");
  });

  it("returns nothing for a package that is not blocked", () => {
    expect(blockedReason(listItem())).toBe("");
  });
});
