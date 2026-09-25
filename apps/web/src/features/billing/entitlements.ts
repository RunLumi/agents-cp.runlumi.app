/**
 * Effective Lumi entitlement vocabulary.
 *
 * Product code speaks only these stable dotted Lumi keys. A payment-provider
 * product/price ID is adapter-private and has no representation here
 * (P06-CG "Stable entitlement keys", F18 FR-F18-001).
 */

import type { EntitlementAttribution, EntitlementEntry, EntitlementValue } from "./api";

export type EntitlementKind = "limit" | "toggle" | "retention";

export interface EntitlementKeyInfo {
  key: string;
  label: string;
  kind: EntitlementKind;
  /** The resource an over-limit projection counts for this key. */
  resource: string | null;
  /** Only a seat-based limit can be remediated by suspending seats. */
  seat_based: boolean;
  unit: string | null;
  meaning: string;
}

/**
 * The frozen baseline key set from P06-CG. A key outside this list is still
 * displayed — it is read from the server response — but it is marked as not part
 * of the baseline so an operator can see that it was added by a later plan
 * revision.
 */
export const BASELINE_ENTITLEMENT_KEYS: readonly EntitlementKeyInfo[] = [
  {
    key: "org.max_members",
    label: "Members",
    kind: "limit",
    resource: "members",
    seat_based: true,
    unit: null,
    meaning: "Billable and free seats the organization may hold at once.",
  },
  {
    key: "projects.max_active",
    label: "Active projects",
    kind: "limit",
    resource: "projects",
    seat_based: false,
    unit: null,
    meaning: "Projects that may be active at the same time.",
  },
  {
    key: "inference.platform_managed",
    label: "Platform-managed inference",
    kind: "toggle",
    resource: null,
    seat_based: false,
    unit: null,
    meaning: "Inference billed by Lumi on the platform route.",
  },
  {
    key: "inference.byok",
    label: "Bring your own key (BYOK)",
    kind: "toggle",
    resource: null,
    seat_based: false,
    unit: null,
    meaning: "Organization- or user-supplied provider credentials.",
  },
  {
    key: "audit.retention_days",
    label: "Audit retention",
    kind: "retention",
    resource: null,
    seat_based: false,
    unit: "days",
    meaning: "Days of audit and security events the plan retains.",
  },
  {
    key: "automations.max_active",
    label: "Active automations",
    kind: "limit",
    resource: "automations",
    seat_based: false,
    unit: null,
    meaning: "Automation definitions that may be active at the same time.",
  },
  {
    key: "devices.max_enrolled",
    label: "Enrolled devices",
    kind: "limit",
    resource: "devices",
    seat_based: false,
    unit: null,
    meaning: "Devices that may be enrolled for managed execution.",
  },
  {
    key: "exports.enabled",
    label: "Exports",
    kind: "toggle",
    resource: null,
    seat_based: false,
    unit: null,
    meaning: "Controlled export artifacts for this organization.",
  },
  {
    key: "deletion.self_service",
    label: "Self-service data deletion",
    kind: "toggle",
    resource: null,
    seat_based: false,
    unit: null,
    meaning: "Requesting an export or deletion workflow without a support step.",
  },
  {
    key: "webhooks.enabled",
    label: "Webhooks",
    kind: "toggle",
    resource: null,
    seat_based: false,
    unit: null,
    meaning: "Outbound webhook endpoints and delivery.",
  },
  {
    key: "sso.enabled",
    label: "Single sign-on",
    kind: "toggle",
    resource: null,
    seat_based: false,
    unit: null,
    meaning: "Federated single sign-on for organization members.",
  },
  {
    key: "scim.enabled",
    label: "SCIM provisioning",
    kind: "toggle",
    resource: null,
    seat_based: false,
    unit: null,
    meaning: "Directory-driven membership provisioning.",
  },
] as const;

const BASELINE_BY_KEY = new Map(BASELINE_ENTITLEMENT_KEYS.map((info) => [info.key, info]));

export function findEntitlementKey(key: string): EntitlementKeyInfo | null {
  return BASELINE_BY_KEY.get(key) ?? null;
}

export function isBaselineEntitlementKey(key: string): boolean {
  return BASELINE_BY_KEY.has(key);
}

/** The precedence chain, weakest to strongest, as the UI presents it. */
export const PRECEDENCE_CHAIN: readonly {
  source: Exclude<EntitlementAttribution, "unknown">;
  rank: number;
  label: string;
  meaning: string;
}[] = [
  {
    source: "platform_default",
    rank: 1,
    label: "Platform default",
    meaning: "The baseline every organization starts from.",
  },
  {
    source: "plan",
    rank: 2,
    label: "Plan",
    meaning: "The value the current plan version includes.",
  },
  {
    source: "subscription",
    rank: 3,
    label: "Subscription grant",
    meaning: "A time-bounded grant derived from the active subscription.",
  },
  {
    source: "internal_override",
    rank: 4,
    label: "Internal override",
    meaning: "An audited, scoped, expiring support override. Not editable here.",
  },
] as const;

const SOURCE_LABEL: Record<EntitlementAttribution, string> = {
  platform_default: "Platform default",
  plan: "Plan",
  subscription: "Subscription grant",
  internal_override: "Internal override",
  unknown: "Source not itemized",
};

export function sourceLabel(source: EntitlementAttribution): string {
  return SOURCE_LABEL[source];
}

export function sourceRank(source: EntitlementAttribution): number | null {
  if (source === "unknown") return null;
  return PRECEDENCE_CHAIN.find((step) => step.source === source)?.rank ?? null;
}

export function sourceMeaning(source: EntitlementAttribution): string {
  if (source === "unknown") {
    return "The server returned this value without itemizing which layer set it. Treat it as unproven; do not read it as a plan grant.";
  }
  return PRECEDENCE_CHAIN.find((step) => step.source === source)?.meaning ?? "";
}

export interface EntitlementDisplay {
  entry: EntitlementEntry;
  info: EntitlementKeyInfo | null;
  label: string;
  unit: string | null;
  /** `true` when the key is not in the frozen baseline set. */
  outsideBaseline: boolean;
  valueText: string;
  /** A protected capability with no value fails closed. */
  missing: boolean;
  enabled: boolean | null;
  numeric: number | null;
}

const BOOLEAN_LABEL_TRUE = "Included";
const BOOLEAN_LABEL_FALSE = "Not included";

export function describeEntitlement(entry: EntitlementEntry): EntitlementDisplay {
  const info = findEntitlementKey(entry.key);
  const missing = entry.value === null;
  const enabled = typeof entry.value === "boolean" ? entry.value : null;
  const numeric = typeof entry.value === "number" ? entry.value : null;
  const unit = info?.unit ?? null;

  let valueText: string;
  if (missing) {
    valueText = "Not granted";
  } else if (enabled !== null) {
    valueText = enabled ? BOOLEAN_LABEL_TRUE : BOOLEAN_LABEL_FALSE;
  } else if (numeric !== null) {
    valueText = unit ? `${numeric} ${unit}` : String(numeric);
  } else {
    valueText = String(entry.value);
  }

  return {
    entry,
    info,
    label: info?.label ?? humanizeKey(entry.key),
    unit,
    outsideBaseline: info === null,
    valueText,
    missing,
    enabled,
    numeric,
  };
}

/** `org.max_members` -> `Max members`. Used only for keys outside the baseline. */
export function humanizeKey(key: string): string {
  const tail = key.split(".").at(-1) ?? key;
  const words = tail.split("_").filter((word) => word.length > 0);
  if (words.length === 0) return key;
  const [first, ...rest] = words;
  return `${(first ?? "").charAt(0).toUpperCase()}${(first ?? "").slice(1)} ${rest.join(" ")}`.trim();
}

/** `trialing` -> `Trialing`. Used for statuses and states. */
export function humanizeStatus(value: string): string {
  const words = value.split(/[._]/).filter((word) => word.length > 0);
  if (words.length === 0) return value;
  return words.map((word) => `${word.charAt(0).toUpperCase()}${word.slice(1)}`).join(" ");
}

/**
 * Sort entries into a stable, scannable order: baseline keys in gate order
 * first, then any key a later plan revision introduced, alphabetically.
 */
export function orderEntitlements(entries: readonly EntitlementEntry[]): EntitlementEntry[] {
  const order = new Map(BASELINE_ENTITLEMENT_KEYS.map((info, index) => [info.key, index]));
  return [...entries].sort((left, right) => {
    const leftIndex = order.get(left.key);
    const rightIndex = order.get(right.key);
    if (leftIndex !== undefined && rightIndex !== undefined) return leftIndex - rightIndex;
    if (leftIndex !== undefined) return -1;
    if (rightIndex !== undefined) return 1;
    return left.key.localeCompare(right.key);
  });
}

export function countEntitlementSources(
  entries: readonly EntitlementEntry[],
): Record<EntitlementAttribution, number> {
  const counts: Record<EntitlementAttribution, number> = {
    platform_default: 0,
    plan: 0,
    subscription: 0,
    internal_override: 0,
    unknown: 0,
  };
  for (const entry of entries) counts[entry.source] += 1;
  return counts;
}

/** A toggle that is not included, or a limit of zero, is a hard stop. */
export function isDenyingValue(value: EntitlementValue | null): boolean {
  if (value === null) return false;
  if (typeof value === "boolean") return value === false;
  if (typeof value === "number") return value === 0;
  return value.length === 0;
}
