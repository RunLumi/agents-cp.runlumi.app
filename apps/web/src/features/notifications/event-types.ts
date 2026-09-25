/**
 * Notification event vocabulary and the mandatory-security rule.
 *
 * Source of truth: `docs/implementation/gates/P06-CG.md` → "Event and webhook
 * contract" (contract version `p06-cg-v1`).
 *
 * Two different things live here, and the difference matters:
 *
 *  1. **Informational** events. These come from the frozen P06 list and an
 *     operator may opt out of them per channel.
 *  2. **Mandatory security** events. The gate names them as families, not as an
 *     enumerated list: "`auth.*`, `device.revoked`, `organization.suspended`,
 *     approval/security denials, and credential revocation". They are delivered
 *     to the owning org's security recipients regardless of informational
 *     preferences, and the server refuses an opt-out that names one
 *     (`trg_notification_preferences_no_security_optout`).
 *
 * The mandatory set is therefore expressed as family rules, not as a guessed
 * name list. An opt-out naming anything the rules cover is refused here, with a
 * visible reason, instead of being silently dropped or sent to fail.
 */

import { P06_EVENT_TYPES, type P06EventType } from "@/features/webhooks/event-types";

import type { NotificationCategory } from "./api";

/**
 * Informational P06 events an operator may opt out of per channel.
 *
 * The `webhook.*` and `notification.delivery_*` names are intentionally absent:
 * they describe delivery plumbing rather than something a recipient acts on, and
 * a subscriber is not a notification recipient.
 */
export const INFORMATIONAL_EVENT_TYPES: readonly P06EventType[] = P06_EVENT_TYPES.filter(
  (eventType) =>
    !eventType.startsWith("webhook.") && !eventType.startsWith("notification.delivery_"),
);

type MandatoryRuleKind = "prefix" | "contains";

export interface MandatorySecurityRule {
  readonly kind: MandatoryRuleKind;
  readonly value: string;
  readonly label: string;
}

/**
 * The frozen families. These mirror the gate's sentence and the server-side
 * trigger's checks, so the UI refuses what the API refuses.
 *
 * `auth.`, `approval.`, and `credential.` are dotted prefixes.
 * `device.revoked` and `organization.suspended` are name *stems*: the registered
 * events are `device.revoked.v1` and `organization.suspended.v1`, and the
 * server trigger matches them by containment. The client mirrors that
 * containment instead of a stricter equality, because a stricter client would
 * present a mandatory event as optional and then let the write fail.
 */
export const MANDATORY_SECURITY_RULES: readonly MandatorySecurityRule[] = [
  { kind: "prefix", value: "auth.", label: "authentication and session events" },
  { kind: "contains", value: "device.revoked", label: "device revocation" },
  { kind: "contains", value: "organization.suspended", label: "organization suspension" },
  { kind: "prefix", value: "approval.", label: "approval and security denials" },
  { kind: "prefix", value: "credential.", label: "credential revocation" },
];

export function mandatoryRuleFor(eventType: string): MandatorySecurityRule | undefined {
  const value = eventType.trim();
  return MANDATORY_SECURITY_RULES.find((rule) =>
    rule.kind === "contains" ? value.includes(rule.value) : value.startsWith(rule.value),
  );
}

export function isMandatorySecurityEvent(eventType: string): boolean {
  return mandatoryRuleFor(eventType) !== undefined;
}

export const MANDATORY_SECURITY_COPY =
  "Mandatory security notifications cannot be switched off. The organization always receives them, on every channel that is configured, so a credential revocation or a device removal is never silently dropped.";

export const MANDATORY_SECURITY_REFUSAL_COPY =
  "This event family is mandatory, so it cannot be added to the opt-out list. Remove the informational events instead — the security events keep arriving.";

export interface OptOutRejection {
  readonly eventType: string;
  readonly rule: MandatorySecurityRule;
  readonly message: string;
}

export type OptOutValidation =
  | { readonly ok: true; readonly eventTypes: readonly string[] }
  | { readonly ok: false; readonly rejections: readonly OptOutRejection[] };

/**
 * Validate a proposed opt-out list. Mandatory security events are refused with
 * a reason; anything else is de-duplicated and sorted. An empty list is valid
 * and means "deliver everything on this channel".
 */
export function validateOptOutList(values: readonly string[]): OptOutValidation {
  const rejections: OptOutRejection[] = [];
  for (const eventType of values) {
    const rule = mandatoryRuleFor(eventType.trim());
    if (rule) {
      rejections.push({
        eventType: eventType.trim(),
        rule,
        message: `${eventType.trim()} covers ${rule.label}, which is mandatory. ${MANDATORY_SECURITY_REFUSAL_COPY}`,
      });
    }
  }
  if (rejections.length > 0) return { ok: false, rejections };
  return {
    ok: true,
    eventTypes: [
      ...new Set(values.map((value) => value.trim()).filter((value) => value.length > 0)),
    ].sort(),
  };
}

/**
 * Drop any mandatory event that a stored or stale preference row still carries.
 * The server refuses such a row, so the client must not present one as saved.
 */
export function enforcedOptOuts(values: readonly string[]): string[] {
  return [
    ...new Set(
      values
        .map((value) => value.trim())
        .filter((value) => value.length > 0 && !isMandatorySecurityEvent(value)),
    ),
  ].sort();
}

/** Notification category for an informational P06 event. */
export function notificationCategoryOf(eventType: string): NotificationCategory {
  if (eventType.startsWith("automation.")) return "automation";
  if (
    eventType.startsWith("billing.") ||
    eventType.startsWith("entitlement.") ||
    eventType.startsWith("license.")
  ) {
    return "billing";
  }
  if (
    eventType.startsWith("data_policy.") ||
    eventType.startsWith("export.") ||
    eventType.startsWith("deletion.")
  ) {
    return "policy";
  }
  return "operational";
}

export const CATEGORY_LABELS: Readonly<Record<NotificationCategory, string>> = {
  security: "Security",
  billing: "Billing and entitlement",
  automation: "Automation",
  policy: "Data policy, export, and deletion",
  operational: "Operational",
};

/** Human summary of one bounded notification body, built from known keys only. */
export function notificationSummary(
  body: Record<string, unknown>,
  fallback: string,
): { readonly title: string; readonly facts: readonly { key: string; value: string }[] } {
  const facts: { key: string; value: string }[] = [];
  for (const [key, value] of Object.entries(body)) {
    if (facts.length >= 6) break;
    if (value === null || value === undefined) continue;
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      facts.push({ key, value: String(value) });
    }
  }
  const title =
    typeof body["title"] === "string" && body["title"].length > 0
      ? body["title"]
      : typeof body["summary"] === "string" && body["summary"].length > 0
        ? body["summary"]
        : fallback;
  return { title, facts };
}
