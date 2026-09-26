/**
 * The capability vocabulary a machine credential may hold.
 *
 * P07-CG: "A key's scope names capabilities using the existing `Permission`
 * vocabulary, so a machine's authority is expressed in the same language as a
 * human's but resolved by a different function." The list below is that
 * vocabulary, mirrored from `Permission::as_str()` in
 * `apps/api/src/modules/authorization.rs`, grouped so an operator reads it as
 * areas of authority rather than as a flat wall of identifiers.
 *
 * F14-001 is the load-bearing rule and it is enforced here, in the surface the
 * operator actually touches: there is **no wildcard option**, and
 * {@link HUMAN_ONLY_CAPABILITIES} are not in the offered set at all. A wildcard
 * would be implicit inheritance wearing a different name, and a human-only
 * capability offered in a checkbox is a control that always fails closed.
 */

/** The five permissions `is_human_only` refuses, before scope is consulted. */
export const HUMAN_ONLY_CAPABILITIES = [
  "org.ownership_transfer",
  "org.lifecycle",
  "org.leave",
  "billing.manage",
  "data.delete",
] as const;
export type HumanOnlyCapability = (typeof HUMAN_ONLY_CAPABILITIES)[number];

/** Why each of the five is structurally unavailable to a machine. */
export const HUMAN_ONLY_REASONS: Readonly<Record<HumanOnlyCapability, string>> = {
  "org.ownership_transfer":
    "Irreversible, and it changes who can delete the organization. A CI credential that can transfer ownership is a single-token blast radius.",
  "org.lifecycle": "Suspends or deletes the organization.",
  "org.leave": "Meaningless without a human.",
  "billing.manage":
    "Plan changes and cancellation are commercial acts with contractual consequence.",
  "data.delete":
    "Deletion is irreversible, and the confirmation copy assumes a human who can read it.",
};

export interface CapabilityOption {
  /** The exact string sent to the API. Never a label. */
  readonly name: string;
  /** What the credential may do, in one sentence, before saving. */
  readonly effect: string;
}

export interface CapabilityGroup {
  readonly id: string;
  readonly label: string;
  readonly options: readonly CapabilityOption[];
}

/**
 * Every machine-selectable capability, in the gate's `Permission` order.
 *
 * This is an explicit allowlist rather than a filter over a larger list, so a
 * permission added to the backend later cannot appear in the picker before
 * someone has decided whether a machine should hold it. Two consequences are
 * deliberate: the five human-only permissions are absent, and
 * `identity.*`/`plugins.*` management capabilities are present but carry a
 * consequence in their own words rather than a warning badge.
 */
export const CAPABILITY_GROUPS: readonly CapabilityGroup[] = [
  {
    id: "organization",
    label: "Organization",
    options: [
      { name: "org.read", effect: "Read this organization's record." },
      { name: "org.manage", effect: "Rename the organization and change its slug." },
    ],
  },
  {
    id: "people",
    label: "People",
    options: [
      { name: "members.read", effect: "List members and their roles." },
      { name: "members.manage", effect: "Invite, remove, and change member roles." },
      { name: "teams.read", effect: "List teams." },
      { name: "teams.manage", effect: "Create, rename, and delete teams." },
      { name: "audit.read", effect: "Read the organization's security audit log." },
    ],
  },
  {
    id: "delivery",
    label: "Devices and projects",
    options: [
      { name: "devices.read", effect: "List enrolled devices." },
      { name: "devices.manage", effect: "Approve, rename, and revoke devices." },
      { name: "projects.read", effect: "List projects." },
      { name: "projects.manage", effect: "Create, update, and archive projects." },
    ],
  },
  {
    id: "inference",
    label: "Models and inference",
    options: [
      { name: "models.read", effect: "Read the model catalog and provider health." },
      { name: "models.manage", effect: "Create models and change provider lifecycle." },
      { name: "routes.read", effect: "Read routing configuration and its history." },
      { name: "routes.manage", effect: "Create, publish, and roll back routes." },
      { name: "inference.use", effect: "Send inference requests through the platform." },
      { name: "usage.read", effect: "Read usage records." },
    ],
  },
  {
    id: "credentials",
    label: "Provider credentials",
    options: [
      {
        name: "credentials.read",
        effect: "List provider credential metadata, never their secrets.",
      },
      { name: "credentials.manage", effect: "Create, rotate, and revoke provider credentials." },
    ],
  },
  {
    id: "agents",
    label: "Agents, runs, and tools",
    options: [
      { name: "agents.read", effect: "List agent definitions." },
      { name: "agents.manage", effect: "Create, update, and delete agent definitions." },
      { name: "sessions.read", effect: "List sessions." },
      { name: "sessions.manage", effect: "Revoke sessions." },
      { name: "runs.read", effect: "Read run records and their timelines." },
      { name: "runs.start", effect: "Start runs." },
      { name: "runs.cancel", effect: "Cancel in-flight runs." },
      { name: "tools.read", effect: "List tools and their review state." },
      { name: "tools.manage", effect: "Change tool availability and review state." },
      { name: "approvals.read", effect: "List pending approvals." },
      { name: "approvals.resolve", effect: "Approve or deny pending work." },
      { name: "budgets.read", effect: "Read budgets and their reservations." },
      { name: "budgets.manage", effect: "Create budgets and change their limits." },
    ],
  },
  {
    id: "operations",
    label: "Automations, events, and notifications",
    options: [
      { name: "automations.read", effect: "List automations and their schedules." },
      { name: "automations.manage", effect: "Create, update, pause, and delete automations." },
      { name: "automations.run", effect: "Trigger an automation immediately." },
      { name: "webhooks.read", effect: "List webhook endpoints and delivery history." },
      { name: "webhooks.manage", effect: "Create, rotate, and disable webhook endpoints." },
      { name: "notifications.read", effect: "Read notification preferences." },
      { name: "notifications.manage", effect: "Change notification preferences." },
    ],
  },
  {
    id: "commercial",
    label: "Commercial and data",
    options: [
      { name: "billing.read", effect: "Read the subscription and invoices." },
      { name: "entitlements.read", effect: "Read the entitlement projection." },
      { name: "data.read", effect: "Read data-governance policy and job status." },
      { name: "data.manage", effect: "Change data-governance policy and logging modes." },
      { name: "data.export", effect: "Request an organization data export." },
    ],
  },
  {
    id: "identity",
    label: "Identity and plugins",
    options: [
      {
        name: "service_accounts.read",
        effect: "List service accounts and key metadata. Never a secret.",
      },
      {
        name: "service_accounts.manage",
        effect:
          "Create and suspend service accounts, and mint, rotate, and revoke API keys. Granting this lets the credential mint its own successors, so it is worth the narrowest possible project and model scope alongside it.",
      },
      {
        name: "plugins.read",
        effect: "Read installed plugins, the catalog, and org plugin policy.",
      },
      {
        name: "plugins.manage",
        effect:
          "Install, approve, pin, and block plugins. Installing third-party code from a CI pipeline is a supply-chain decision, and this capability records it in the audit log as the credential that made it.",
      },
    ],
  },
];

/** Flat, sorted, deduplicated. This is the only list the picker renders. */
export const MACHINE_CAPABILITIES: readonly string[] = Array.from(
  new Set(CAPABILITY_GROUPS.flatMap((group) => group.options.map((option) => option.name))),
).sort();

export function isHumanOnlyCapability(name: string): name is HumanOnlyCapability {
  return (HUMAN_ONLY_CAPABILITIES as readonly string[]).includes(name);
}

export function capabilityEffect(name: string): string | undefined {
  for (const group of CAPABILITY_GROUPS) {
    const option = group.options.find((entry) => entry.name === name);
    if (option) return option.effect;
  }
  return undefined;
}

/**
 * Order a selection for the wire.
 *
 * The server parses a capability array into a deduplicated, ordered set, so
 * sending the canonical sorted order makes an unchanged PATCH a genuine no-op
 * instead of a new version and a new audit entry.
 */
export function normalizeCapabilities(selected: readonly string[]): string[] {
  return Array.from(new Set(selected.filter((name) => MACHINE_CAPABILITIES.includes(name)))).sort();
}

export function toggleCapability(selected: readonly string[], name: string): string[] {
  return selected.includes(name)
    ? selected.filter((entry) => entry !== name)
    : normalizeCapabilities([...selected, name]);
}

/**
 * A capability the server returned that this surface does not know.
 *
 * It is rendered, never silently dropped: a scope the control plane cannot
 * explain is a scope an operator must be able to see. A credential carrying one
 * should be reviewed rather than trusted.
 */
export function unknownCapabilities(selected: readonly string[]): string[] {
  return selected.filter((name) => !MACHINE_CAPABILITIES.includes(name));
}

/** Plain-language scope summary, used by the preview and the detail surfaces. */
export function describeScope(selected: readonly string[]): string {
  if (selected.length === 0)
    return "No capability. This credential can authenticate and nothing else.";
  const count = selected.length;
  return `${count} explicit ${count === 1 ? "capability" : "capabilities"}. Each is checked independently on every request; there is no implicit inheritance and no wildcard.`;
}
