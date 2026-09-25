/**
 * Downgrade and over-limit projection.
 *
 * The contract is blunt about this and so is this module:
 *
 * > A downgrade never deletes data. It blocks new/expanded resources above the
 * > new limit and exposes an over-limit remediation projection.
 * > — P06-CG / F18 FR-F18-006
 *
 * Two things are therefore structurally impossible here rather than merely
 * avoided in copy:
 *
 * - `deletesData` is typed as the literal `false`.
 * - `blocksNewWork` is the only consequence this module is allowed to state.
 */

import type {
  EntitlementEntry,
  OverLimitResource,
  PlanChangeDirection,
  PlanChangePreview,
  RemediationOption,
} from "./api";
import { findEntitlementKey, isBaselineEntitlementKey, orderEntitlements } from "./entitlements";

export const BLOCKED_OPERATIONS = [
  "create new resources above the limit",
  "expand an existing resource above the limit",
] as const;

export interface OverLimitProjection {
  entitlementKey: string;
  label: string;
  resource: string | null;
  limit: number;
  current: number;
  overBy: number;
  seatBased: boolean;
  /** Always ordered `reduce_to_limit`, then `suspend_seats`, then `upgrade_plan`. */
  remediation: RemediationOption[];
  outsideBaseline: boolean;
  /** `false` always. There is no path that produces `true`. */
  deletesData: false;
}

export const REMEDIATION_LABELS: Record<RemediationOption, string> = {
  reduce_to_limit: "Reduce to the limit",
  suspend_seats: "Suspend seats",
  upgrade_plan: "Upgrade the plan",
};

export const REMEDIATION_MEANING: Record<RemediationOption, string> = {
  reduce_to_limit:
    "Archive, pause, or delete the excess yourself until the count is inside the new limit.",
  suspend_seats:
    "Suspend the excess billable memberships. Suspended memberships stay in the organization and keep their data.",
  upgrade_plan: "Move to a plan that includes the current count. Nothing has to be removed first.",
};

function remediationFor(resource: OverLimitResource): RemediationOption[] {
  const options = new Set<RemediationOption>(resource.remediation);
  options.add("reduce_to_limit");
  options.add("upgrade_plan");
  if (resource.seat_based) options.add("suspend_seats");
  return (["reduce_to_limit", "suspend_seats", "upgrade_plan"] as const).filter((option) =>
    options.has(option),
  );
}

export function projectOverLimit(resource: OverLimitResource): OverLimitProjection {
  const info = findEntitlementKey(resource.entitlement_key);
  return {
    entitlementKey: resource.entitlement_key,
    label: info?.label ?? resource.entitlement_key,
    resource: info?.resource ?? null,
    limit: resource.limit,
    current: resource.current,
    overBy: Math.max(0, resource.current - resource.limit),
    seatBased: resource.seat_based,
    remediation: remediationFor(resource),
    outsideBaseline: !isBaselineEntitlementKey(resource.entitlement_key),
    deletesData: false,
  };
}

export function projectOverLimitList(
  resources: readonly OverLimitResource[],
): OverLimitProjection[] {
  return resources
    .map(projectOverLimit)
    .filter((item) => item.overBy > 0 || item.current > item.limit)
    .sort((left, right) => right.overBy - left.overBy || left.label.localeCompare(right.label));
}

export interface DowngradeAssessment {
  direction: PlanChangeDirection;
  isDowngrade: boolean;
  /** The browser never infers plan rank; `unknown` is not a downgrade. */
  previewRequired: boolean;
  previewAvailable: boolean;
  /** Why a direct submit is unavailable, in plain copy. Null when it is. */
  blockedReason: string | null;
  overLimit: OverLimitProjection[];
  blocksNewWork: boolean;
  deletesData: false;
  targetPlanKey: string;
  currentPlanKey: string | null;
  serverReason: string | null;
}

/**
 * Decide whether a direct plan change may be submitted from the browser.
 *
 * A change is only submittable when the server stated its direction AND the
 * result has been previewed. Everything else routes to the provider portal.
 */
export function assessPlanChange(input: {
  preview: PlanChangePreview | null;
  previewRequested: boolean;
  previewFailed: boolean;
  previewAvailable: boolean;
  currentPlanKey: string | null;
  targetPlanKey: string;
  serverReason?: string | null;
}): DowngradeAssessment {
  const overLimit = input.preview ? projectOverLimitList(input.preview.over_limit) : [];
  const direction = input.preview?.direction ?? "unknown";
  const isDowngrade = direction === "downgrade";

  let blockedReason: string | null = null;
  if (!input.previewAvailable) {
    blockedReason =
      "A downgrade must be previewed before it is submitted. This deployment does not publish a downgrade preview, so the change is made in the provider portal instead.";
  } else if (input.previewFailed) {
    blockedReason =
      "The downgrade preview could not be read. Nothing was submitted. Resolve the preview before changing the plan.";
  } else if (input.previewRequested && input.preview === null) {
    blockedReason = "The downgrade preview has not returned yet. Nothing has been submitted.";
  } else if (direction === "unknown") {
    blockedReason =
      "The server did not state whether this change is an upgrade or a downgrade, so the browser will not submit it. Confirm the direction in the provider portal.";
  }

  return {
    direction,
    isDowngrade,
    previewRequired: isDowngrade || direction === "unknown",
    previewAvailable: input.previewAvailable,
    blockedReason,
    overLimit,
    blocksNewWork: input.preview?.blocks_new_work ?? isDowngrade,
    deletesData: false,
    targetPlanKey: input.targetPlanKey,
    currentPlanKey: input.preview?.current_plan_key ?? input.currentPlanKey,
    serverReason: input.preview?.reason ?? input.serverReason ?? null,
  };
}

/**
 * The single sentence that must never be softened. It is exported so tests can
 * assert the panel renders it verbatim for a downgrade.
 */
export const DOWNGRADE_HONESTY_STATEMENT =
  "A downgrade blocks new and expanded work above the new limit. It does not delete anything that already exists.";

export const DOWNGRADE_BLOCKED_COPY =
  "Already-created resources stay in the organization, keep their history, and remain readable. Only creation and expansion above the new limit is blocked.";

/**
 * The countable limits the effective entitlement chain reports.
 *
 * The counts themselves are never inferred here. `over_limit` from the server
 * is the only authority for "how many exist"; a limit with no reported count is
 * shown as a limit whose usage is not reported, never as zero.
 */
export function countableLimits(
  entries: readonly EntitlementEntry[],
): { key: string; label: string; limit: number; unit: string | null }[] {
  const limits: { key: string; label: string; limit: number; unit: string | null }[] = [];
  for (const entry of orderEntitlements(entries)) {
    if (typeof entry.value !== "number" || !Number.isSafeInteger(entry.value) || entry.value < 0) {
      continue;
    }
    const info = findEntitlementKey(entry.key);
    if (!info || info.resource === null) continue;
    limits.push({ key: entry.key, label: info.label, limit: entry.value, unit: info.unit });
  }
  return limits;
}

/** Attach the authoritative count to a countable limit, when one was reported. */
export function reportedCount(
  key: string,
  reported: readonly OverLimitResource[],
): OverLimitResource | null {
  return reported.find((resource) => resource.entitlement_key === key) ?? null;
}
