/**
 * The frozen `p07-contracts-v1.json` plugin-governance blocks, run through the
 * REAL decoders and the REAL presentation helpers.
 *
 * WHY A SEPARATE FILE, following the P06 precedent in
 * `features/data-governance/api.test.ts`. `contracts.test.ts` hand-writes its
 * diffs, which is the right way to cover combinations and the wrong way to pin a
 * contract: a hand-written diff is whatever the author believed, so a server
 * change and a UI change can drift together and every test still passes. This
 * file takes the diffs, the policy, and the pending-review install from the
 * document `P07-CG.md` §Fixtures froze BEFORE the backend existed.
 *
 * The assertions are on what an operator WOULD READ, not only on the decoded
 * shape. A diff that decodes correctly and then renders as "tightening" is the
 * failure P07-CG calls out by name, and a structural assertion cannot catch it.
 */

import { describe, expect, it } from "vitest";

import fixture from "../../../../../docs/implementation/fixtures/p07-contracts-v1.json";

import {
  PLUGIN_PERMISSION_CLASSES,
  decodeInstall,
  decodePermissionDiff,
  decodePolicy,
  permissionClassLabel,
  type PluginListItem,
  type PluginPermissionDiff,
} from "./api";
import {
  blockedReason,
  classVerdicts,
  conflictingPackages,
  diffExpands,
  expansionDetail,
  expansionHeadline,
  expandingClasses,
  isPendingReview,
  pendingReviewReason,
  reviewStateLabel,
  unusableToolCount,
  usableToolCount,
} from "./contracts";

/** The fixture's annotations are not wire fields; a decoder must never see them. */
function stripped(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripped);
  if (typeof value !== "object" || value === null) return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key]) => !key.startsWith("_"))
      .map(([key, entry]) => [key, stripped(entry)]),
  );
}

function frozenDiff(key: "permission_diff_expands" | "permission_diff_contraction") {
  const decoded = decodePermissionDiff(stripped(fixture[key]));
  expect(decoded).toBeDefined();
  return decoded as PluginPermissionDiff;
}

describe("the frozen expanding diff", () => {
  const diff = frozenDiff("permission_diff_expands");

  it("decodes field-for-field and covers every manifest class exactly once", () => {
    // The frozen block minus its annotations IS the wire payload, so the decoder
    // is handed it untouched and the result compared to it. That is the whole
    // point: a decoder that dropped a field, or a fixture that had grown one the
    // decoder never sees, both fail here rather than in a reader's head.
    const { _note, before: _before, after: _after, ...wire } = fixture.permission_diff_expands;
    expect(diff).toEqual(wire);
    // A class the UI cannot render a label for, or a class rendered twice, both
    // mean a reviewer is not seeing every row the server reported.
    expect(diff.classes.map((entry) => entry.class)).toEqual(PLUGIN_PERMISSION_CLASSES);
    for (const entry of diff.classes) {
      expect(permissionClassLabel(entry.class)).not.toBe(entry.class);
    }
  });

  it("is reported as an expansion, and says so in the reviewer's terms", () => {
    const { expands, contradictsServer } = diffExpands(diff);
    expect(expands).toBe(true);
    expect(contradictsServer).toBe(false);
    const headline = expansionHeadline(diff);
    expect(headline).toContain("widens the plugin's authority");
    // The tool the version added must be named in the headline, not only in a
    // row further down: a reviewer who reads the summary must not be able to
    // reach "this is a tightening" before seeing it.
    expect(headline).toContain("Tools");
  });

  it("names the added tool and does not let the reductions read as a mitigation", () => {
    const growing = expandingClasses(diff).map((entry) => entry.label);
    expect(growing).toEqual(["Tools"]);
    const detail = expansionDetail(diff);
    const joined = detail.join(" ");
    expect(joined).toContain("pkg_write");
    // Two classes shrank, so the reduction sentence must be present AND must be
    // immediately followed by the refusal to net them off.
    expect(joined).toContain("Reduced authority:");
    expect(joined).toContain("A reduction does not offset a gain");
    expect(joined).toContain("managed mode");
  });

  it("reduces its widening to the one class that grew", () => {
    // The three shrinking classes must not be counted as growing, and the one
    // growing class must not be lost inside a row that also shrank.
    const verdicts = classVerdicts(diff);
    expect(verdicts.filter((entry) => entry.expanding)).toHaveLength(1);
    expect(verdicts.filter((entry) => entry.verdict === "removed")).toHaveLength(2);
    expect(verdicts.filter((entry) => entry.verdict === "unchanged")).toHaveLength(5);
  });
});

describe("the frozen contracting diff", () => {
  const diff = frozenDiff("permission_diff_contraction");

  it("is its own version pair, not the expanding diff reversed", () => {
    // Asserting a contraction by running an expansion backwards would pass
    // whether or not the UI were direction-sensitive.
    expect(diff.from_version).toBe("2.0.0");
    expect(diff.to_version).toBe("2.1.0");
    expect(frozenDiff("permission_diff_expands").from_version).toBe("1.0.0");
  });

  it("is reported as NOT an expansion, with nothing to review", () => {
    const { expands, contradictsServer } = diffExpands(diff);
    expect(expands).toBe(false);
    expect(contradictsServer).toBe(false);
    expect(expandingClasses(diff)).toEqual([]);
    expect(expansionHeadline(diff)).toBe("This update does not widen what the plugin may do.");
    // F25-004: managed mode installs a contraction without renewed review, so the
    // detail must not manufacture a reason to send it back.
    const joined = expansionDetail(diff).join(" ");
    expect(joined).toContain("Reduced authority:");
    expect(joined).not.toContain("Gained authority");
    expect(joined).not.toContain("does not offset a gain");
  });

  it("still names every entry it dropped", () => {
    const joined = expansionDetail(diff).join(" ");
    expect(joined).toContain("pkg_write");
    expect(joined).toContain("https://telemetry.example.com");
    // Normalized to `scheme::purpose`, which is what an operator reads as a
    // credential, not as a database row id.
    expect(joined).toContain("aws::read-logs");
    expect(joined).toContain("gh::admin-org");
    // A class that shrank is reported `removed`, never `unchanged`.
    expect(diff.classes.filter((entry) => entry.verdict === "removed")).toHaveLength(3);
  });
});

describe("the frozen policy with a conflict", () => {
  const policy = decodePolicy(stripped(fixture.plugin_policy_with_a_conflict));

  it("decodes field-for-field, conflicts included", () => {
    expect(policy).toBeDefined();
    expect(policy).toEqual(stripped(fixture.plugin_policy_with_a_conflict));
  });

  it("surfaces the conflict rather than resolving it silently", () => {
    expect(policy).toBeDefined();
    if (!policy) return;
    // F25-004: the block WINS, and the fact that the two lists disagree is shown.
    // Dropping the allow entry quietly would leave an admin believing a package
    // is permitted when it is not.
    const conflicts = conflictingPackages(policy);
    expect(conflicts).toEqual(fixture.plugin_policy_with_a_conflict.conflicts);
    expect(conflicts).toHaveLength(1);
    const blocked = conflicts[0];
    expect(policy.blocked_packages).toContain(blocked);
    expect(policy.allowed_packages).toContain(blocked);
  });

  it("records the pin for the other package, which the block did not touch", () => {
    expect(policy).toBeDefined();
    if (!policy) return;
    const pinned = fixture.plugin_policy_with_a_conflict._verdicts;
    const pinnedPackage = Object.keys(pinned).find(
      (packageId) => !conflictingPackages(policy).includes(packageId),
    );
    expect(pinnedPackage).toBeDefined();
    expect(policy.pinned_versions[pinnedPackage as string]).toBe("1.0.0");
  });
});

describe("the frozen pending-review install", () => {
  const frozen = fixture.plugin_install_pending_review;
  const install = stripped(frozen) as Record<string, unknown>;
  const item: PluginListItem = {
    package: {
      package_id: frozen.package_id,
      publisher_id: "pub_0123456789abcdef0123456789abcdef",
      publisher_official: true,
      display_name: "Release helper",
      summary: "Reads release state.",
      status: "active",
      created_at: "2026-09-26T12:00:00.000Z",
      updated_at: "2026-09-26T12:00:00.000Z",
    },
    install: {
      version: frozen.version,
      review_state: "pending_review",
      pending_review_version: frozen.pending_review_version,
      review_reason: frozen.review_reason,
      blocked_reason: null,
    },
    quarantined: false,
    pinned_version: null,
    blocked: false,
  };

  /**
   * The cross-language half of the contract. `decodeInstall` is an allowlist that
   * returns `undefined` for a response missing any required field, and
   * `decodeDetail` then refuses the whole payload — so a field the server omits
   * is not a smaller response, it is a plugin detail page that renders nothing.
   * `routes/plugins.rs::install_json` pins its own key set to the same frozen
   * block, so the two halves are held together by this document rather than by
   * luck. `blocked_reason` is the field that was actually missing.
   */
  it("decodes the frozen install projection with nothing left over", () => {
    expect(decodeInstall(install)).toEqual(install);
    // The `org_id` the record holds is not in the projection: the route is
    // org-scoped by the path, so returning it would be state a client could hold
    // stale. Asserted so a future "just include everything" edit is caught.
    expect(install).not.toHaveProperty("org_id");
  });

  it("refuses a projection that dropped a field rather than showing a partial one", () => {
    // The failure this guards against is silent in production: no error, just a
    // page that never renders. So the refusal is asserted directly.
    for (const field of [
      "blocked_reason",
      "review_reason",
      "pending_review_version",
      "unregistered_tools",
      "review_state",
    ]) {
      const partial: Record<string, unknown> = { ...install };
      delete partial[field];
      expect(decodeInstall(partial), `${field} is required`).toBeUndefined();
    }
  });

  it("is not installed and says which version is waiting", () => {
    expect(isPendingReview(item.install)).toBe(true);
    expect(reviewStateLabel("pending_review")).toBe("Pending review");
    expect(item.install?.version).toBe(frozen.version);
    expect(item.install?.pending_review_version).toBe(frozen.pending_review_version);
    // A refusal is not a block, and the two must not read the same way: nothing
    // about the waiting version runs, but the installed version is not disabled.
    expect(item.blocked).toBe(false);
    expect(item.install?.blocked_reason).toBeNull();
  });

  it("names the class that grew instead of showing the raw reason string", () => {
    const reason = pendingReviewReason(item.install);
    expect(reason).toContain("widens the plugin's declared capability");
    // The payload after the event id is what tells a reviewer WHICH class grew,
    // so it must be read rather than echoed. The bare code and the raw JSON must
    // both be absent: that is what the operator would otherwise have been shown.
    expect(reason).toContain("1 class");
    expect(reason).toContain("Tools");
    expect(reason).not.toContain("plugin.permission_expansion_detected");
    expect(reason).not.toContain('{"expands"');
    // And it still says what to do about it.
    expect(reason).toContain("not installed");
    expect(reason).toContain("approve it deliberately");
  });

  it("separates the tools that work from the one the expansion added", () => {
    const install = {
      install_id: frozen.install_id,
      package_id: frozen.package_id,
      version: frozen.version,
      pending_review_version: frozen.pending_review_version,
      review_state: "pending_review" as const,
      review_reason: frozen.review_reason,
      blocked_reason: null,
      approved_by: null,
      approved_at: null,
      registered_tools: frozen.registered_tools,
      unregistered_tools: frozen.unregistered_tools,
      created_at: "2026-09-26T12:00:00.000Z",
      updated_at: "2026-09-26T12:00:00.000Z",
    };
    expect(usableToolCount(install)).toBe(1);
    expect(unusableToolCount(install)).toBe(1);
    // The tool the expansion wanted is exactly the one with no registration, so
    // "I approved this, why is the tool missing" has an answer on screen.
    expect(install.unregistered_tools).toContain("pkg_write");
    expect(install.registered_tools).not.toContain("pkg_write");
  });

  it("prefers the organization's own block reason over a generic one", () => {
    const blockedItem: PluginListItem = {
      ...item,
      blocked: true,
      install: { ...item.install!, review_state: "blocked", blocked_reason: "CVE-2026-0001" },
    };
    expect(blockedReason(blockedItem)).toContain("CVE-2026-0001");
  });
});
