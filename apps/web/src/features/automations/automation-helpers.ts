// Occurrence, target, policy, and entitlement presentation helpers.
//
// Every string here is Lumi copy about a *stable* reason code. No server prose
// and no raw provider/SQL text ever reaches this module.

import { ApiClientError } from "@/lib/errors";

import {
  OCCURRENCE_STATES,
  type AutomationDefinition,
  type AutomationEntitlements,
  type AutomationStatus,
  type Occurrence,
  type OccurrenceState,
  type OffPeakMode,
  type OffPeakPolicy,
  type TargetKind,
  type ToolPolicyScope,
} from "./api";
import { humanizeToken } from "./schedule-helpers";

export const AUTOMATION_STATUS_LABELS: Readonly<Record<AutomationStatus, string>> = {
  active: "Active",
  paused: "Paused",
  suspended: "Suspended",
  failed: "Failed",
};

export function isOccurrenceState(value: string): value is OccurrenceState {
  return (OCCURRENCE_STATES as readonly string[]).includes(value);
}

const TERMINAL_OCCURRENCE_STATES: ReadonlySet<OccurrenceState> = new Set([
  "succeeded",
  "failed",
  "cancelled",
  "missed",
  "skipped",
  "ambiguous",
]);

export function isTerminalOccurrenceState(state: OccurrenceState): boolean {
  return TERMINAL_OCCURRENCE_STATES.has(state);
}

export function occurrenceStateLabel(state: OccurrenceState): string {
  if (state === "dispatching") return "Dispatching";
  if (state === "ambiguous") return "Needs reconciliation";
  return humanizeToken(state);
}

export type OccurrenceTone = "neutral" | "info" | "success" | "warning" | "danger" | "ambiguous";

export function occurrenceTone(state: OccurrenceState): OccurrenceTone {
  if (state === "succeeded") return "success";
  if (state === "failed") return "danger";
  if (state === "cancelled") return "warning";
  if (state === "missed") return "warning";
  if (state === "skipped") return "neutral";
  // `ambiguous` is a reconciliation state, not a failed attempt. It is never
  // automatically retried, so it must not read as a retryable failure.
  if (state === "ambiguous") return "ambiguous";
  return "info";
}

/**
 * The frozen copy for `ambiguous`.
 *
 * The server cannot prove whether execution began, so it will not issue a
 * second lease and will not retry. This is an operator reconciliation, not a
 * retry button.
 */
export const AMBIGUOUS_EXPLANATION =
  "The server lost authority after execution may have begun, so it cannot prove whether this occurrence ran. It is never retried automatically and a second device cannot claim it. Resolve it through an audited operator action after checking the host.";

export function occurrenceStateExplanation(state: OccurrenceState): string | null {
  if (state === "ambiguous") return AMBIGUOUS_EXPLANATION;
  if (state === "skipped")
    return "The server deliberately produced no execution for this slot, usually because of the overlap or missed-run policy.";
  if (state === "missed")
    return "The slot passed without dispatch, usually because the control plane or the device was unavailable. The missed-run policy decides whether recovery work is created.";
  if (state === "leased")
    return "A device holds a time-bounded execution lease. If it expires before execution starts, the occurrence can be requeued; after execution starts it becomes ambiguous instead.";
  if (state === "dispatching")
    return "The server created this occurrence and is choosing an eligible device. No lease is held yet.";
  return null;
}

export function occurrenceKindLabel(occurrence: Pick<Occurrence, "kind">): string {
  if (occurrence.kind === "off_peak") return "Off-peak";
  return humanizeToken(occurrence.kind);
}

export function offPeakModeLabel(mode: OffPeakMode | null): string {
  if (mode === "off_peak") return "Off-peak";
  if (mode === "normal") return "Normal";
  return "Not recorded";
}

export function targetKindLabel(kind: TargetKind): string {
  if (kind === "eligible_device") return "Any eligible device";
  if (kind === "specific_device") return "Specific device";
  if (kind === "remote_workspace") return "Remote workspace";
  return "Server runner";
}

export function targetSummary(automation: AutomationDefinition): string {
  const parts = [targetKindLabel(automation.target.kind)];
  if (automation.target.device_id) parts.push(automation.target.device_id);
  if (automation.target.workspace_binding_id) parts.push(automation.target.workspace_binding_id);
  return parts.join(" · ");
}

export function toolPolicyScopeLabel(scope: ToolPolicyScope): string {
  if (scope === "organization") return "Organization";
  if (scope === "agent") return "Agent";
  return "Project";
}

export function executionPolicySummary(automation: AutomationDefinition): string {
  return [
    automation.execution_policy.model_alias ?? "Inherit model",
    automation.execution_policy.budget_id ?? "Inherit budget",
    `${toolPolicyScopeLabel(automation.execution_policy.tool_policy_scope)} tool policy`,
  ].join(" · ");
}

export function principalSummary(automation: AutomationDefinition): string {
  return `${humanizeToken(automation.execution_principal.kind)} · ${automation.execution_principal.id}`;
}

export function offPeakEligibilityLabel(policy: OffPeakPolicy | null): string {
  if (policy === null) return "Not configured";
  return policy.eligibility_source === "provider_ticket"
    ? "Provider ticket"
    : "Organization window";
}

/**
 * Plain-language consequence of each eligibility source.
 *
 * A provider-ticket occurrence has no clock schedule at all, and a ticket
 * renewal does not create a second logical occurrence. This is the single most
 * important thing to say out loud, because it is exactly what a cron window
 * would get wrong.
 */
export function offPeakEligibilityDetail(source: OffPeakPolicy["eligibility_source"]): string {
  if (source === "provider_ticket") {
    return "Runs when the provider grants an off-peak ticket. There is no clock schedule, and a ticket renewal does not create a second occurrence.";
  }
  return "Runs inside the organization's declared off-peak window. The window is an eligibility condition, not a separate schedule.";
}

export function offPeakConstraintSummary(policy: OffPeakPolicy): string {
  const parts: string[] = [];
  parts.push(
    policy.tool_constraints.deny_automation_mutation
      ? "no automation changes"
      : "automation changes allowed",
  );
  parts.push(
    policy.tool_constraints.deny_recursive_off_peak
      ? "no nested off-peak work"
      : "nested off-peak work allowed",
  );
  parts.push(
    policy.tool_constraints.allow_background_processes
      ? "background processes requested"
      : "no background processes",
  );
  return parts.join(" · ");
}

/** The narrowing-only rule the gate states for off-peak execution. */
export const OFF_PEAK_NARROWING_RULE =
  "The server re-checks this class at dispatch and at execution time, and it may narrow these restrictions but never widen them.";

export const OFF_PEAK_CLASS_NOTE =
  "Off-peak is a separate execution class, not a cron window. Network, browser, and computer access stay composed from the current tool policy and route configuration.";

export interface AutomationLimitState {
  /** The plan limit when the projection carries one. */
  limit: number | null;
  /** Active automations counted in the loaded result set. */
  activeLoaded: number;
  /** True when the loaded page is the complete set for this organization. */
  complete: boolean;
  atLimit: boolean;
  tone: "neutral" | "warning";
  headline: string;
  detail: string;
}

const MAX_ACTIVE_KEY = "automations.max_active";

/**
 * Present the entitlement/limit state as read context only.
 *
 * The count comes from the definitions this client has loaded, so it is only
 * reported as exact when the whole set is loaded. The server remains the sole
 * authority on whether a create or resume is allowed.
 */
export function automationLimitState(
  automations: AutomationDefinition[],
  entitlements: AutomationEntitlements | null,
  hasMore: boolean,
): AutomationLimitState {
  const activeLoaded = automations.filter((automation) => automation.status === "active").length;
  const rawLimit = entitlements?.values[MAX_ACTIVE_KEY];
  const limit = typeof rawLimit === "number" && Number.isInteger(rawLimit) ? rawLimit : null;
  const complete = !hasMore;
  const atLimit = limit !== null && complete && activeLoaded >= limit;
  const planLabel = entitlements?.plan_key ? `Plan ${entitlements.plan_key}` : "Current plan";

  if (limit === null) {
    return {
      limit,
      activeLoaded,
      complete,
      atLimit,
      tone: "neutral",
      headline: "Automation limit not readable",
      detail:
        "The entitlement projection did not return automations.max_active. The server still enforces the limit on every create, resume, and dispatch.",
    };
  }

  return {
    limit,
    activeLoaded,
    complete,
    atLimit,
    tone: atLimit ? "warning" : "neutral",
    headline: atLimit
      ? "Active automation limit reached"
      : `${activeLoaded} active of ${limit} allowed`,
    detail: atLimit
      ? `${planLabel}. ${limit} active automations are already in use. Pause or delete one before creating another; a downgrade never deletes data.`
      : `${planLabel}. ${limit} active automations allowed${
          complete ? "" : ", counted from the results loaded so far"
        }. The server re-checks this limit on every create, resume, and dispatch.`,
  };
}

// -----------------------------------------------------------------------------
// Action errors
// -----------------------------------------------------------------------------

const AUTOMATION_CONFLICT_CODES: ReadonlySet<string> = new Set([
  "version_conflict",
  "automation_invalid_state",
  "automation_overlap_policy",
  "automation_missed_schedule_limit",
  "organization_pending_deletion",
]);

/** A stale write: the client must refresh before it can retry. */
export function isAutomationConflict(error: unknown): boolean {
  if (!(error instanceof ApiClientError)) return false;
  if (error.code === "version_conflict") return true;
  return AUTOMATION_CONFLICT_CODES.has(error.code);
}

export function isPermissionFailure(error: unknown): boolean {
  return (
    error instanceof ApiClientError &&
    (error.status === 403 || ["permission_denied", "project_access_denied"].includes(error.code))
  );
}

/** A mutation whose outcome the server never confirmed. */
export function isUnconfirmedMutation(error: unknown): boolean {
  return (
    error instanceof ApiClientError &&
    (error.kind === "network" ||
      error.kind === "invalid_response" ||
      error.code === "idempotency_in_progress" ||
      error.status === 408 ||
      error.status === 429 ||
      (error.status !== undefined && error.status >= 500))
  );
}

/** The copy an action error shows, keyed off stable codes only. */
export function automationActionErrorMessage(error: unknown): string {
  if (isPermissionFailure(error)) {
    return "Your current membership cannot perform this action in this organization scope. Ask an administrator to review access.";
  }
  if (isAutomationConflict(error)) {
    return "The automation changed and no longer accepts that version. Refresh the automation before trying again.";
  }
  if (isUnconfirmedMutation(error)) {
    return "The server did not confirm the result, so the action may already have been applied. Refresh before retrying; the confirmation reuses the same idempotency key.";
  }
  return "The action could not be completed. Refresh and try again.";
}
