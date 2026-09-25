/**
 * Frozen P06 event vocabulary.
 *
 * Source of truth: `docs/implementation/gates/P06-CG.md` → "Event and webhook
 * contract" (contract version `p06-cg-v1`) and
 * `docs/implementation/fixtures/p06-contracts-v1.json`.
 *
 * A webhook endpoint may subscribe to an explicit finite set of *exact* event
 * names. The server never accepts a wildcard or a family prefix: fan-out is
 * exact-match only, and `trg_webhook_endpoints_no_wildcard` rejects a `*`
 * anywhere in the stored subscription list. This module mirrors that rule so
 * the control plane can explain a rejection before a request is made. The API
 * remains authoritative; nothing here grants or widens access.
 *
 * This is the single source of truth for the P06 event names in the web app.
 * The notifications feature imports it rather than restating the list.
 */

export const P06_EVENT_TYPES = [
  "automation.definition.created.v1",
  "automation.definition.updated.v1",
  "automation.definition.paused.v1",
  "automation.definition.resumed.v1",
  "automation.definition.deleted.v1",
  "automation.occurrence.created.v1",
  "automation.occurrence.dispatched.v1",
  "automation.occurrence.started.v1",
  "automation.occurrence.completed.v1",
  "automation.occurrence.failed.v1",
  "automation.occurrence.skipped.v1",
  "automation.occurrence.missed.v1",
  "automation.occurrence.lease_expired.v1",
  "automation.occurrence.ambiguous.v1",
  "webhook.endpoint_created.v1",
  "webhook.endpoint_updated.v1",
  "webhook.endpoint_rotated.v1",
  "webhook.endpoint_disabled.v1",
  "webhook.test.v1",
  "webhook.delivery_succeeded.v1",
  "webhook.delivery_retry_scheduled.v1",
  "webhook.delivery_dead_lettered.v1",
  "webhook.delivery_replayed.v1",
  "notification.created.v1",
  "notification.delivery_succeeded.v1",
  "notification.delivery_retry_scheduled.v1",
  "notification.delivery_dead_lettered.v1",
  "billing.subscription_updated.v1",
  "billing.grace_started.v1",
  "billing.grace_ended.v1",
  "entitlement.granted.v1",
  "entitlement.revoked.v1",
  "entitlement.override_created.v1",
  "entitlement.override_expired.v1",
  "license.snapshot_issued.v1",
  "billing.downgrade_over_limit.v1",
  "data_policy.updated.v1",
  "export.requested.v1",
  "export.started.v1",
  "export.completed.v1",
  "export.failed.v1",
  "export.expired.v1",
  "deletion.requested.v1",
  "deletion.started.v1",
  "deletion.step_completed.v1",
  "deletion.failed.v1",
  "deletion.resumed.v1",
  "deletion.completed.v1",
] as const;

export type P06EventType = (typeof P06_EVENT_TYPES)[number];

const P06_EVENT_TYPE_SET: ReadonlySet<string> = new Set(P06_EVENT_TYPES);

export function isP06EventType(value: string): boolean {
  return P06_EVENT_TYPE_SET.has(value);
}

/**
 * Event families, in the order the contract gate lists them. A family is a
 * display grouping only — it is never a valid subscription value.
 */
export interface EventFamily {
  readonly id: string;
  readonly label: string;
  readonly description: string;
  readonly eventTypes: readonly string[];
}

export const EVENT_FAMILIES: readonly EventFamily[] = [
  {
    id: "automation.definition",
    label: "Automation definitions",
    description: "Definition lifecycle: created, updated, paused, resumed, deleted.",
    eventTypes: [
      "automation.definition.created.v1",
      "automation.definition.updated.v1",
      "automation.definition.paused.v1",
      "automation.definition.resumed.v1",
      "automation.definition.deleted.v1",
    ],
  },
  {
    id: "automation.occurrence",
    label: "Automation occurrences",
    description:
      "One due occurrence: created, dispatched, started, completed, failed, skipped, missed, lease expired, ambiguous.",
    eventTypes: [
      "automation.occurrence.created.v1",
      "automation.occurrence.dispatched.v1",
      "automation.occurrence.started.v1",
      "automation.occurrence.completed.v1",
      "automation.occurrence.failed.v1",
      "automation.occurrence.skipped.v1",
      "automation.occurrence.missed.v1",
      "automation.occurrence.lease_expired.v1",
      "automation.occurrence.ambiguous.v1",
    ],
  },
  {
    id: "webhook.endpoint",
    label: "Webhook endpoints",
    description:
      "Never fanned out to a webhook endpoint. Fanning these out would make an endpoint receive its own lifecycle.",
    eventTypes: [
      "webhook.endpoint_created.v1",
      "webhook.endpoint_updated.v1",
      "webhook.endpoint_rotated.v1",
      "webhook.endpoint_disabled.v1",
    ],
  },
  {
    id: "webhook.delivery",
    label: "Webhook delivery",
    description:
      "Never fanned out to a webhook endpoint. Fanning these out would recurse through the delivery worker.",
    eventTypes: [
      "webhook.test.v1",
      "webhook.delivery_succeeded.v1",
      "webhook.delivery_retry_scheduled.v1",
      "webhook.delivery_dead_lettered.v1",
      "webhook.delivery_replayed.v1",
    ],
  },
  {
    id: "notification",
    label: "Notifications",
    description:
      "Informational notification projections. Notification delivery events are never fanned out.",
    eventTypes: [
      "notification.created.v1",
      "notification.delivery_succeeded.v1",
      "notification.delivery_retry_scheduled.v1",
      "notification.delivery_dead_lettered.v1",
    ],
  },
  {
    id: "billing",
    label: "Billing and subscription",
    description: "Subscription mapping, grace windows, and downgrade over-limit projection.",
    eventTypes: [
      "billing.subscription_updated.v1",
      "billing.grace_started.v1",
      "billing.grace_ended.v1",
      "billing.downgrade_over_limit.v1",
    ],
  },
  {
    id: "entitlement",
    label: "Entitlements",
    description: "Lumi entitlement grants, revocations, and expiring internal overrides.",
    eventTypes: [
      "entitlement.granted.v1",
      "entitlement.revoked.v1",
      "entitlement.override_created.v1",
      "entitlement.override_expired.v1",
    ],
  },
  {
    id: "license",
    label: "License snapshots",
    description: "Short-lived signed license snapshot issuance.",
    eventTypes: ["license.snapshot_issued.v1"],
  },
  {
    id: "data_policy",
    label: "Data governance policy",
    description: "Logging mode, retention, and legal-hold policy changes.",
    eventTypes: ["data_policy.updated.v1"],
  },
  {
    id: "export",
    label: "Export jobs",
    description: "Controlled export artifact job lifecycle.",
    eventTypes: [
      "export.requested.v1",
      "export.started.v1",
      "export.completed.v1",
      "export.failed.v1",
      "export.expired.v1",
    ],
  },
  {
    id: "deletion",
    label: "Deletion jobs",
    description: "Resumable, idempotent deletion workflow and per-class step completion.",
    eventTypes: [
      "deletion.requested.v1",
      "deletion.started.v1",
      "deletion.step_completed.v1",
      "deletion.failed.v1",
      "deletion.resumed.v1",
      "deletion.completed.v1",
    ],
  },
] as const;

export function eventFamilyOf(eventType: string): EventFamily | undefined {
  return EVENT_FAMILIES.find((family) => family.eventTypes.includes(eventType));
}

/**
 * Required payload fields per event family, frozen by the contract gate. No
 * family may add prompt/response content, raw tool arguments, credentials,
 * provider payloads, or unbounded URLs. Shown in the picker so an operator can
 * see what a subscription will carry before enabling it.
 *
 * The gate's table names only the seven families below. `webhook.*` and
 * `license.*` have no frozen field list, so `payloadFieldsFor` returns nothing
 * for them rather than inventing one.
 */
export const EVENT_FAMILY_PAYLOAD_FIELDS: Readonly<Partial<Record<string, readonly string[]>>> = {
  "automation.definition": [
    "automation_id",
    "org_id",
    "project_id",
    "version",
    "status",
    "next_run_at",
  ],
  "automation.occurrence": [
    "occurrence_id",
    "automation_id",
    "attempt",
    "state",
    "resource_version",
    "run_id",
    "reason_code",
  ],
  notification: ["notification_id", "event_id", "recipient_scope", "channel", "state"],
  billing: ["subscription_id", "org_id", "status", "effective_at"],
  entitlement: ["grant_id", "org_id", "entitlement_key", "value", "source", "effective_at"],
  data_policy: ["policy_id", "org_id", "version", "changed_keys"],
  export: [
    "job_id",
    "scope_type",
    "scope_id",
    "state",
    "attempt",
    "resource_version",
    "failure_code",
  ],
  deletion: [
    "job_id",
    "scope_type",
    "scope_id",
    "state",
    "attempt",
    "resource_version",
    "failure_code",
  ],
};

/**
 * The frozen gate's per-family table names no field list for the `webhook.*`
 * or `license.*` families, so this returns an empty list for them instead of
 * inventing one. The mapping is a display convenience only.
 */
export function payloadFieldsFor(eventType: string): readonly string[] {
  const family = eventFamilyOf(eventType);
  if (!family) return [];
  return EVENT_FAMILY_PAYLOAD_FIELDS[family.id] ?? [];
}

/**
 * Fan-out exclusions. The gate forbids fanning `webhook.delivery_*`,
 * `webhook.endpoint_*`, and notification-delivery events out to the same
 * webhook endpoint. `webhook.test.v1` is delivered only to the endpoint an
 * operator named when they asked for a test, and is not subscribable.
 */
const FANOUT_EXCLUDED_PREFIXES = [
  "webhook.delivery_",
  "webhook.endpoint_",
  "notification.delivery_",
] as const;

const FANOUT_EXCLUDED_EXACT = new Set<string>(["webhook.test.v1"]);

export function isFanoutExcluded(eventType: string): boolean {
  if (FANOUT_EXCLUDED_EXACT.has(eventType)) return true;
  return FANOUT_EXCLUDED_PREFIXES.some((prefix) => eventType.startsWith(prefix));
}

/** Every frozen name an endpoint may actually subscribe to. */
export const SUBSCRIBABLE_EVENT_TYPES: readonly string[] = P06_EVENT_TYPES.filter(
  (eventType) => !isFanoutExcluded(eventType),
);

export const SUBSCRIPTION_RULE_COPY =
  "Exact frozen event names only. A wildcard (*) or a family prefix such as automation.occurrence is rejected by the API, and delivery, endpoint, and notification-delivery events are never fanned back to an endpoint.";

export const MAX_SUBSCRIPTIONS = 64;

export type SubscriptionRejectionCode =
  | "empty"
  | "too_long"
  | "wildcard"
  | "family_prefix"
  | "unknown"
  | "fanout_excluded"
  | "too_many";

export interface SubscriptionRejection {
  readonly code: SubscriptionRejectionCode;
  readonly value: string;
  readonly message: string;
}

export interface SubscriptionValidationSuccess {
  readonly ok: true;
  readonly eventTypes: readonly string[];
}

export interface SubscriptionValidationFailure {
  readonly ok: false;
  readonly rejections: readonly SubscriptionRejection[];
}

export type SubscriptionValidation = SubscriptionValidationSuccess | SubscriptionValidationFailure;

/** A dotted, versioned Lumi event name: lowercase segments and an integer version. */
const EVENT_NAME_GRAMMAR = /^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*\.v[1-9][0-9]*$/;

function isFamilyPrefix(value: string): boolean {
  if (EVENT_FAMILIES.some((family) => family.id === value)) return true;
  return P06_EVENT_TYPES.some((eventType) => eventType.startsWith(`${value}.`));
}

/**
 * Validate a single candidate name against the exact-match rule. Returns `null`
 * when the name is an exact, subscribable, frozen P06 name.
 */
export function validateExactEventName(rawValue: string): SubscriptionRejection | null {
  const value = rawValue.trim();
  if (value.length === 0) {
    return { code: "empty", value, message: "Enter an exact event name." };
  }
  if (value.length > 96) {
    return {
      code: "too_long",
      value,
      message: "An event name may be at most 96 characters.",
    };
  }
  if (value.includes("*")) {
    return {
      code: "wildcard",
      value,
      message:
        "Wildcards are not accepted. Select one exact event name such as automation.occurrence.completed.v1.",
    };
  }
  if (isFanoutExcluded(value)) {
    return {
      code: "fanout_excluded",
      value,
      message: isP06EventType(value)
        ? `${value} is never fanned out to a webhook endpoint, so it cannot be subscribed.`
        : `${value} is not a frozen P06 event name.`,
    };
  }
  if (!isP06EventType(value)) {
    if (isFamilyPrefix(value)) {
      return {
        code: "family_prefix",
        value,
        message: `${value} is a family, not an event. Subscriptions use exact event names.`,
      };
    }
    return {
      code: "unknown",
      value,
      message: EVENT_NAME_GRAMMAR.test(value)
        ? `${value} is not a registered Lumi event.`
        : `${value} is not a valid dotted event name.`,
    };
  }
  return null;
}

/** De-duplicate and sort so a repeated selection cannot change the stored list. */
export function sortEventTypes(values: readonly string[]): string[] {
  return [
    ...new Set(values.map((value) => value.trim()).filter((value) => value.length > 0)),
  ].sort();
}

/**
 * Validate a whole subscription list. Every entry must be an exact, frozen,
 * subscribable P06 name; duplicates collapse.
 */
export function validateSubscription(values: readonly string[]): SubscriptionValidation {
  const rejections: SubscriptionRejection[] = [];
  for (const value of values) {
    const rejection = validateExactEventName(value);
    if (rejection) rejections.push(rejection);
  }
  if (rejections.length > 0) return { ok: false, rejections };
  const eventTypes = sortEventTypes(values);
  if (eventTypes.length === 0) {
    return {
      ok: false,
      rejections: [
        {
          code: "empty",
          value: "",
          message: "Select at least one exact event name.",
        },
      ],
    };
  }
  if (eventTypes.length > MAX_SUBSCRIPTIONS) {
    return {
      ok: false,
      rejections: [
        {
          code: "too_many",
          value: "",
          message: `Select at most ${MAX_SUBSCRIPTIONS} event names.`,
        },
      ],
    };
  }
  return { ok: true, eventTypes };
}

export interface PartitionedSubscription {
  /** Values present in the frozen P06 list. */
  readonly p06: readonly string[];
  /**
   * Already-stored values outside the P06 list — for example a P01/P05 frozen
   * name the server also accepts. The editor preserves these untouched rather
   * than silently dropping a live subscription.
   */
  readonly external: readonly string[];
}

export function partitionSubscription(values: readonly string[]): PartitionedSubscription {
  const p06: string[] = [];
  const external: string[] = [];
  for (const value of values) {
    if (isP06EventType(value)) p06.push(value);
    else external.push(value);
  }
  return { p06: sortEventTypes(p06), external: sortEventTypes(external) };
}

export function filterFamilies(query: string): readonly EventFamily[] {
  const needle = query.trim().toLowerCase();
  if (needle.length === 0) return EVENT_FAMILIES;
  return EVENT_FAMILIES.map((family) => ({
    ...family,
    eventTypes: family.eventTypes.filter((eventType) => eventType.toLowerCase().includes(needle)),
  })).filter((family) => family.eventTypes.length > 0);
}
