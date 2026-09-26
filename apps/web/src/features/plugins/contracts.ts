/**
 * Plugin governance rules the control plane states before an operator acts.
 *
 * The API is authoritative. Everything here exists so a reviewer can see a
 * decision *before* making it, and so no affordance in this surface ever widens
 * what the server will accept.
 *
 * The load-bearing rule is expansion. P07-CG: "**Expansion in any class is
 * expansion.** A version that adds a tool, widens a network destination, adds a
 * secret handle, or raises `browser_capability` from `read` to `computer_use` is
 * an expansion even if it removes something else." {@link expandingClasses} is
 * the function that makes that impossible to misread: it names the growing
 * classes on their own, so a reviewer cannot see "networking was reduced" and miss
 * that a tool appeared.
 */

import {
  PERMISSION_EXPANSION_REASON,
  permissionClassLabel,
  type DiffClass,
  type PluginInstall,
  type PluginListItem,
  type PluginPermissionDiff,
  type PluginPolicy,
  type PluginReviewState,
} from "./api";

export type Tone = "neutral" | "info" | "success" | "warning" | "danger";

// ---------------------------------------------------------------------------
// Permission diff and expansion
// ---------------------------------------------------------------------------

export interface ClassVerdict {
  readonly class: string;
  readonly label: string;
  readonly verdict: DiffClass;
  readonly added: readonly string[];
  readonly removed: readonly string[];
  /** True when this class on its own widens what the plugin may do. */
  readonly expanding: boolean;
}

const VERDICT_TONE: Readonly<Record<DiffClass, Tone>> = {
  added: "warning",
  removed: "info",
  unchanged: "neutral",
};

const VERDICT_LABEL: Readonly<Record<DiffClass, string>> = {
  added: "Gained",
  removed: "Lost",
  unchanged: "Unchanged",
};

export function classVerdicts(diff: PluginPermissionDiff): ClassVerdict[] {
  return diff.classes.map((entry) => ({
    class: entry.class,
    label: permissionClassLabel(entry.class),
    verdict: entry.verdict,
    added: entry.added,
    removed: entry.removed,
    expanding: entry.verdict === "added" && entry.added.length > 0,
  }));
}

/**
 * The classes that widen authority, named on their own.
 *
 * This is deliberately NOT a weighted score, a count, or a majority. The gate
 * says an expansion is an expansion, and a reviewer who has to weigh eight rows
 * against each other will eventually get it wrong on exactly the row that
 * matters. One growing class is enough.
 */
export function expandingClasses(diff: PluginPermissionDiff): ClassVerdict[] {
  return classVerdicts(diff).filter((entry) => entry.expanding);
}

/**
 * `true` when any class grew.
 *
 * The server's own `expands` is authoritative; a disagreement between it and the
 * per-class verdicts is a contract inconsistency, so this function surfaces it
 * rather than picking a winner.
 */
export function diffExpands(diff: PluginPermissionDiff): {
  readonly expands: boolean;
  readonly contradictsServer: boolean;
} {
  const fromClasses = expandingClasses(diff).length > 0;
  return { expands: diff.expands, contradictsServer: diff.expands !== fromClasses };
}

export function expansionHeadline(diff: PluginPermissionDiff): string {
  const growing = expandingClasses(diff);
  if (diff.expands && growing.length === 0) {
    return "This update is reported as expanding capability, but no growing class is named below. Treat it as an expansion and review it before approving.";
  }
  if (growing.length === 0) {
    return "This update does not widen what the plugin may do.";
  }
  const names = growing.map((entry) => entry.label).join(", ");
  return `This update widens the plugin's authority in ${growing.length} ${growing.length === 1 ? "class" : "classes"}: ${names}. ${growing.length === 1 ? "That is" : "Those are"} an expansion, whatever else was reduced.`;
}

/** What a reviewer must read, in one paragraph, before approving. */
export function expansionDetail(diff: PluginPermissionDiff): string[] {
  const growing = expandingClasses(diff);
  const shrinking = classVerdicts(diff).filter(
    (entry) => entry.verdict === "removed" && entry.removed.length > 0,
  );
  const paragraphs: string[] = [];
  if (growing.length > 0) {
    paragraphs.push(
      `Gained authority: ${growing.map((entry) => `${entry.label} (${entry.added.join(", ")})`).join("; ")}.`,
    );
  }
  if (shrinking.length > 0) {
    paragraphs.push(
      `Reduced authority: ${shrinking.map((entry) => `${entry.label} (${entry.removed.join(", ")})`).join("; ")}.`,
    );
  }
  if (growing.length > 0 && shrinking.length > 0) {
    paragraphs.push(
      "A reduction does not offset a gain. The review gate reads the gain, so this update needs renewed approval in managed mode even though something was removed.",
    );
  }
  if (growing.length === 0 && shrinking.length === 0) {
    paragraphs.push(
      "Nothing was gained and nothing was lost. The declared capability set is identical.",
    );
  }
  return paragraphs;
}

export function verdictTone(verdict: DiffClass): Tone {
  return VERDICT_TONE[verdict];
}

export function verdictLabel(verdict: DiffClass): string {
  return VERDICT_LABEL[verdict];
}

// ---------------------------------------------------------------------------
// Install state
// ---------------------------------------------------------------------------

export function reviewStateTone(state: PluginReviewState): Tone {
  switch (state) {
    case "approved":
      return "success";
    case "pending_review":
      return "warning";
    case "blocked":
    case "quarantined":
      return "danger";
    case "unreviewed":
      return "neutral";
  }
}

export function reviewStateLabel(state: PluginReviewState): string {
  switch (state) {
    case "approved":
      return "Approved";
    case "pending_review":
      return "Pending review";
    case "blocked":
      return "Blocked";
    case "quarantined":
      return "Quarantined";
    case "unreviewed":
      return "Unreviewed";
  }
}

/** Why an install is in its state, in the reviewer's terms. */
export function reviewStateDetail(install: PluginListItem["install"]): string {
  if (!install) return "Not installed in this organization. It appears in the catalog only.";
  switch (install.review_state) {
    case "approved":
      return "Reviewed and approved. The declared tools are usable where they are also registered.";
    case "pending_review":
      return install.pending_review_version
        ? `Version ${install.pending_review_version} is waiting for approval. It is not installed, and nothing about it runs until it is approved.`
        : "An install is waiting for approval. Nothing about it runs until it is approved.";
    case "blocked":
      return "Blocked. New installs and new executions are denied.";
    case "quarantined":
      return "Quarantined by the platform for this exact version. New executions are denied; runs already in flight finish.";
    case "unreviewed":
      return "Installed but not reviewed. Every declared tool is denied with plugin_tool_unregistered until it is registered.";
  }
}

/**
 * F25-003: what a `pending_review` install is actually waiting for.
 *
 * The recorded reason distinguishes the two reasons a managed install can stall,
 * because they have different remediations: an expansion needs a human decision,
 * and a policy conflict needs the policy fixed.
 */
export function pendingReviewReason(install: PluginListItem["install"]): string {
  if (!install || install.review_state !== "pending_review") return "";
  if (install.review_reason === PERMISSION_EXPANSION_REASON) {
    return "The candidate version widens the plugin's declared capability, so managed mode refused to install it. Read the permission diff, then approve it deliberately if the gain is intended.";
  }
  if (install.review_reason) {
    return `Recorded reason: ${install.review_reason}`;
  }
  return "No reason was recorded with this pending review. Review the permission diff and the organization policy before approving.";
}

export function isPendingReview(install: PluginListItem["install"]): boolean {
  return install?.review_state === "pending_review";
}

// ---------------------------------------------------------------------------
// Tool registration, and F13 default-deny made visible
// ---------------------------------------------------------------------------

export interface ToolRegistration {
  readonly toolId: string;
  readonly usable: boolean;
  readonly detail: string;
}

/**
 * Registered vs unregistered tools.
 *
 * F25-007: a tool is usable only when a `PluginToolRegistration` exists for
 * `(package_id, version, tool_id)` and policy permits the package. A tool the
 * version declares but the organization did not register is **denied** — F13's
 * default-deny, and the specific control an install can no longer bypass. It is
 * shown here rather than hidden, because an operator who cannot see the denied
 * tools will believe the plugin is fully available when it is not.
 */
export function toolRegistrations(install: PluginInstall | null): ToolRegistration[] {
  if (!install) return [];
  const denied = new Set(install.unregistered_tools);
  const registered = install.registered_tools
    .filter((toolId) => !denied.has(toolId))
    .map((toolId) => ({
      toolId,
      usable: true,
      detail: "Registered for this organization at this version.",
    }));
  const unregistered = install.unregistered_tools.map((toolId) => ({
    toolId,
    usable: false,
    detail:
      "Declared by the version but not registered here. Denied with plugin_tool_unregistered.",
  }));
  return [...registered, ...unregistered];
}

export function unusableToolCount(install: PluginInstall | null): number {
  return install?.unregistered_tools.length ?? 0;
}

export function usableToolCount(install: PluginInstall | null): number {
  return (
    install?.registered_tools.filter((toolId) => !install.unregistered_tools.includes(toolId))
      .length ?? 0
  );
}

// ---------------------------------------------------------------------------
// Policy conflicts
//
// A package on BOTH the allow and the block list is a reported conflict, not
// something to hide: `blocked_packages` wins, and the organization is told its
// own policy contradicts itself.
// ---------------------------------------------------------------------------

export function conflictingPackages(policy: PluginPolicy): string[] {
  return policy.conflicts;
}

export function isConflicting(policy: PluginPolicy, packageId: string): boolean {
  return policy.conflicts.includes(packageId);
}

export function conflictExplanation(policy: PluginPolicy, packageId: string): string {
  if (!isConflicting(policy, packageId)) return "";
  return "This package is on both the allow list and the block list. Blocked wins, so installs and executions are denied. The conflict is reported rather than resolved: nothing silently removes one of the two entries.";
}

export interface PolicyVerdict {
  readonly verdict: "allowed" | "blocked" | "conflict" | "quarantined" | "pinned";
  readonly label: string;
  readonly detail: string;
  readonly tone: Tone;
}

/** Whether the organization's own policy permits a package, and why. */
export function packagePolicyVerdict(item: PluginListItem, policy: PluginPolicy): PolicyVerdict {
  const packageId = item.package.package_id;
  if (item.quarantined) {
    return {
      verdict: "quarantined",
      label: "Quarantined",
      detail:
        "The platform quarantined this exact package@version. New executions are denied for managed organizations even if the files are still on disk; the decision is server-side and authoritative. Runs already in flight finish under the policy they started with.",
      tone: "danger",
    };
  }
  if (isConflicting(policy, packageId)) {
    return {
      verdict: "conflict",
      label: "Policy conflict",
      detail: conflictExplanation(policy, packageId),
      tone: "danger",
    };
  }
  if (item.blocked) {
    return {
      verdict: "blocked",
      label: "Blocked by this organization",
      detail:
        "New installs and new executions are denied. Runs already in flight finish under the policy they started with.",
      tone: "danger",
    };
  }
  if (item.pinned_version) {
    return {
      verdict: "pinned",
      label: `Pinned to ${item.pinned_version}`,
      detail:
        "A pin is exact. This package cannot update to any other version, including a security update, until the pin is lifted as an explicit audited action.",
      tone: "warning",
    };
  }
  return {
    verdict: "allowed",
    label: "Permitted",
    detail: publisherModeDetail(policy, item),
    tone: "success",
  };
}

function publisherModeDetail(policy: PluginPolicy, item: PluginListItem): string {
  const publisher = item.package.publisher_id;
  if (policy.publisher_mode === "any") {
    return "This organization allows any publisher. Only the block list and the platform quarantine can stop an install.";
  }
  if (policy.publisher_mode === "official_only" && !item.package.publisher_official) {
    return "This organization allows official publishers only, and this package is not one.";
  }
  if (
    policy.publisher_mode === "approved_publishers" &&
    !policy.approved_publishers.includes(publisher)
  ) {
    return `This organization allows an approved publisher list, and ${publisher} is not on it.`;
  }
  return "The organization's publisher policy permits this package.";
}

/**
 * The reason this organization gave when it blocked the package.
 *
 * The block action records it on the install's `blocked_reason`, so the reason an
 * operator typed is the reason the surface shows. That was not true when this was
 * first written: the reason reached only the security audit log, the projection
 * carried no reason column, and the surface had to tell the operator to go and
 * read the audit log to find out why their own block had no text. F25's Web UX
 * asks for a visible blocked reason, so the backend now records it where the
 * projection can carry it.
 *
 * The fallback is still honest rather than blank: a policy block with no install
 * row has no reason to show, and saying so is better than rendering an empty
 * string that reads as "no reason was given".
 */
export function blockedReason(item: PluginListItem): string {
  if (!item.blocked) return "";
  const reason = item.install?.blocked_reason ?? item.install?.review_reason;
  if (reason) return `Recorded reason: ${reason}`;
  return "Blocked at the policy level, with no installation to attach a reason to. The reason you gave is in the security audit log.";
}

// ---------------------------------------------------------------------------
// Pin
// ---------------------------------------------------------------------------

export const PIN_NOTE =
  "A pin is exact. This package is frozen at one version and cannot update to any other version, including a security update. That is deliberate: a silent auto-patch would defeat the pin. Lifting it is a separate, explicit, audited action.";

export function canPin(policy: PluginPolicy, packageId: string): string | null {
  if (isConflicting(policy, packageId)) {
    return "This package is on both the allow and the block list. Blocked wins, so a pin would record a version that can never run. Remove one of the two entries first.";
  }
  if (policy.pinned_versions[packageId] !== undefined) {
    return "This package is already pinned. Lifting the pin is a separate action, not a change of value, so that the unfreeze is deliberate and audited.";
  }
  return null;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export function isPermissionFailure(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const candidate = error as { status?: unknown; code?: unknown };
  return (
    candidate.status === 403 ||
    candidate.code === "permission_denied" ||
    candidate.code === "not_found" ||
    candidate.code === "resource_not_found"
  );
}

export function isVersionConflict(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    (error as { code?: unknown }).code === "version_conflict"
  );
}

export function isAmbiguousMutationFailure(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const candidate = error as { kind?: unknown; code?: unknown; status?: unknown };
  return (
    candidate.kind === "network" ||
    candidate.kind === "invalid_response" ||
    candidate.code === "idempotency_in_progress" ||
    candidate.status === 408 ||
    candidate.status === 429 ||
    (typeof candidate.status === "number" && candidate.status >= 500)
  );
}
