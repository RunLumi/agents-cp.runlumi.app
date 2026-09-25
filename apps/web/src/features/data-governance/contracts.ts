/**
 * Frozen P06 data-governance vocabulary and presentation logic.
 *
 * Everything here is pure: state labels, consequence copy, the retention
 * summary, the export category manifest, and the honesty rules that separate
 * "what Lumi deleted" from "what Lumi cannot delete". No React, no fetch, so the
 * rules are directly testable and the components stay thin.
 *
 * Sources: `docs/implementation/gates/P06-CG.md` ("Data governance contract",
 * "Error semantics") and the implemented `apps/api/src/modules/data_governance/`
 * (registry, retention, export, deletion).
 */

import { ApiClientError, presentApiError, type ErrorPresentation } from "@/lib/errors";

import {
  DELETION_CONFIRMATION_PHRASE,
  DOWNLOAD_GRANT_TTL_SECONDS,
  EXPORT_CATEGORIES,
  EXPORT_CONFIRMATION_PHRASE,
  LOGGING_MODES,
  PERSONAL_DELETION_GRACE_SECONDS,
  type BackupLifecycle,
  type DeletionSkipReason,
  type DeletionState,
  type DeletionStep,
  type DeletionStepState,
  type ExportCategory,
  type ExportState,
  type LoggingMode,
  type ProviderRetentionDisclosure,
  type ReferenceKind,
} from "./api";

export type Tone = "neutral" | "info" | "success" | "warning" | "danger";

/**
 * The three sentences every deletion result must carry.
 *
 * This mirrors the backend `DISCLOSURES` array so the disclosure cannot be lost
 * by a server that omits it; `mergeDisclosures` adds any that are missing. The
 * wording is a copy requirement, not a summary.
 */
export const DELETION_DISCLOSURES = [
  "Lumi retention applies to Lumi-managed records only.",
  "Data on managed devices and ZCode hosts is deleted on the host, not by this cloud job.",
  "Upstream AI provider data is governed by the provider's own retention and data-use policy; Lumi cannot delete it.",
] as const;

/**
 * Union of the server's disclosures with the frozen copy, in that order and
 * de-duplicated. A deletion result therefore always shows the local-device and
 * upstream-provider statements, even if the server omitted them.
 */
export function mergeDisclosures(server: readonly string[] | undefined | null): string[] {
  const merged: string[] = [];
  for (const item of [...(server ?? []), ...DELETION_DISCLOSURES]) {
    const normalized = item.trim();
    if (normalized.length === 0 || merged.includes(normalized)) continue;
    merged.push(normalized);
  }
  return merged;
}

// ---------------------------------------------------------------------------
// Logging modes
// ---------------------------------------------------------------------------

export interface LoggingModeCopy {
  readonly label: string;
  readonly summary: string;
  readonly includes: string;
  readonly doesNot: string;
  /** False when the server refuses to persist the mode from this surface. */
  readonly selectable: boolean;
  readonly unavailableReason?: string;
}

export const LOGGING_MODE_COPY: Readonly<Record<LoggingMode, LoggingModeCopy>> = {
  metadata_only: {
    label: "Metadata only",
    summary: "The default, and the narrowest mode.",
    includes:
      "Identifiers, versions, state, counts, bounded reason codes, and timing are recorded. That is enough to answer who did what, when, and with which outcome.",
    doesNot:
      "No prompt text, no model response, no tool arguments, no credentials, and no secrets are written to logs in any mode.",
    selectable: true,
  },
  redacted_content: {
    label: "Redacted diagnostic excerpts",
    summary: "Adds explicitly redacted diagnostic excerpts to the metadata set.",
    includes:
      "Excerpts are redacted before they are written. They are a diagnostic aid, not a data store, and they obey the same retention window as the class they belong to.",
    doesNot:
      "It widens no data class's field allowlist, it does not change the event, audit, webhook, or log schemas, and raw prompts, responses, tool arguments, credentials, and secrets stay prohibited.",
    selectable: true,
  },
  full_content: {
    label: "Full content (audited diagnostic only)",
    summary: "An audited, time-bounded diagnostic setting. It is not a self-service logging mode.",
    includes:
      "It exists so a support investigation can be unblocked under an explicit, expiring grant. A standing full-content capability is a standing privacy risk, so the policy surface will not accept one.",
    doesNot:
      "It never widens a class's field allowlist, never changes the normal event, audit, webhook, or log schemas, never becomes the default for inference or control-plane observability, and raw prompts, responses, tool arguments, credentials, and secrets stay prohibited.",
    selectable: false,
    unavailableReason:
      "A full-content window has to be an audited, time-bounded grant issued outside this page. This policy surface has no field for one, so the server refuses the mode rather than storing an unbounded capability.",
  },
};

/** Every mode, in the frozen declaration order, for display. */
export const LOGGING_MODE_ORDER = LOGGING_MODES;

/**
 * What "metadata only" means in practice, stated where the mode is chosen.
 * The gate's rule is that raw prompts, responses, tool arguments, credentials,
 * and secrets stay prohibited in every mode.
 */
export const ALWAYS_PROHIBITED = [
  "Raw prompt text",
  "Raw model responses",
  "Raw tool-call arguments",
  "Credentials and secrets",
] as const;

export const CONTENT_LOGGING_PRECEDENCE =
  "The active mode is the widest mode the organization may set. It never narrows a data class's own logging ceiling, and it never changes the field allowlist of a class.";

// ---------------------------------------------------------------------------
// Backup lifecycle and provider retention
// ---------------------------------------------------------------------------

export const BACKUP_LIFECYCLE_COPY: Readonly<
  Record<BackupLifecycle, { label: string; body: string; doesNot: string }>
> = {
  platform_35_day_expiry: {
    label: "Platform backups expire after 35 days",
    body: "Active data is deleted first; the platform backup copies expire on their own 35-day lifecycle rather than being selectively rewritten.",
    doesNot:
      "It is not a second copy you can ask us to forget early, and it is not a promise of a point-in-time erase.",
  },
  platform_no_backup: {
    label: "No platform backup for this scope",
    body: "This scope is not included in platform backups, so a deletion needs no backup-lifecycle propagation.",
    doesNot: "It says nothing about device backups or about an upstream provider's own copies.",
  },
};

export const PROVIDER_DISCLOSURE_COPY: Readonly<
  Record<ProviderRetentionDisclosure, { label: string; body: string }>
> = {
  external_policy: {
    label: "Upstream provider retention is governed by the provider",
    body: "Requests that reach an AI provider are governed by that provider's retention and data-use policy. Lumi publishes its own status; it cannot delete provider-held data and does not claim to.",
  },
  linked_policy: {
    label: "Upstream provider policy is linked below",
    body: "The linked policy is the provider's own retention and data-use policy. It is shown as a reference, not as a Lumi control, and Lumi cannot delete provider-held data.",
  },
};

/** BYOK is not zero upstream retention. Stated wherever the provider is named. */
export const BYOK_NOTE =
  "Bringing your own model key does not mean zero upstream retention. The provider's own data-use policy still applies to what it receives.";

// ---------------------------------------------------------------------------
// Retention summary
// ---------------------------------------------------------------------------

export type OwnerScope = "platform" | "organization" | "project" | "user" | "device" | "external";

export interface DataClassSummary {
  readonly key: string;
  readonly label: string;
  readonly owner: OwnerScope;
  /** Human window, already anchored, e.g. `90 days after terminal state`. */
  readonly defaultWindow: string;
  /** Human legal maximum, or `null` when the class is lifecycle-bound. */
  readonly legalMaximum: string | null;
  readonly exportBehavior: string;
  readonly deletionBehavior: string;
  readonly loggingRule: string;
  /** True when a tenant policy may name this class in an override map. */
  readonly overridable: boolean;
}

const DAYS = (days: number): string => (days === 1 ? "1 day" : `${days} days`);
const YEARS = (days: number): string =>
  days >= 365 ? `${Math.round(days / 365)} years` : DAYS(days);

/**
 * The retention summary, mirroring the two frozen governance tables in
 * `P06-CG.md`: the P06 classes and then the existing P01–P05 classes.
 *
 * `overridable` is false for a class whose window is a lifecycle rather than a
 * bounded number, and for secret material whose window is its key lifetime: a
 * policy cannot shorten those by writing a number, and offering the control
 * would suggest otherwise.
 */
export const DATA_CLASS_SUMMARIES: readonly DataClassSummary[] = [
  // -- P06 classes ---------------------------------------------------------
  {
    key: "automation_definition",
    label: "Automation definition",
    owner: "organization",
    defaultWindow: "Until deletion",
    legalMaximum: null,
    exportBehavior: "Included",
    deletionBehavior: "Tombstone",
    loggingRule: "Metadata only",
    overridable: false,
  },
  {
    key: "schedule_rule",
    label: "Schedule rule revision",
    owner: "organization",
    defaultWindow: "Until the definition is deleted",
    legalMaximum: null,
    exportBehavior: "Included; history retained, labels tombstoned",
    deletionBehavior: "Tombstone",
    loggingRule: "Metadata only",
    overridable: false,
  },
  {
    key: "occurrence",
    label: "Occurrence",
    owner: "organization",
    defaultWindow: "90 days after terminal state",
    legalMaximum: YEARS(365),
    exportBehavior: "Included",
    deletionBehavior: "Tombstone",
    loggingRule: "Status and reason only",
    overridable: true,
  },
  {
    key: "execution_lease",
    label: "Execution lease",
    owner: "device",
    defaultWindow: "90 days after terminal state",
    legalMaximum: YEARS(365),
    exportBehavior: "Redacted",
    deletionBehavior: "Tombstone",
    loggingRule: "State and fence only",
    overridable: true,
  },
  {
    key: "occurrence_attempt",
    label: "Occurrence attempt",
    owner: "organization",
    defaultWindow: "90 days after terminal state",
    legalMaximum: YEARS(365),
    exportBehavior: "Redacted",
    deletionBehavior: "Tombstone after certificate",
    loggingRule: "Attempt and state only",
    overridable: true,
  },
  {
    key: "automation_run_link",
    label: "Automation → run link",
    owner: "organization",
    defaultWindow: "90 days after terminal state",
    legalMaximum: YEARS(365),
    exportBehavior: "Redacted",
    deletionBehavior: "Tombstone",
    loggingRule: "IDs and state only",
    overridable: true,
  },
  {
    key: "webhook_endpoint",
    label: "Webhook endpoint",
    owner: "organization",
    defaultWindow: "Until disabled or deleted",
    legalMaximum: null,
    exportBehavior: "Sanitized",
    deletionBehavior: "Delete secret and config",
    loggingRule: "State and version only",
    overridable: false,
  },
  {
    key: "webhook_secret",
    label: "Webhook secret version",
    owner: "organization",
    defaultWindow: "Rotation or revocation lifetime",
    legalMaximum: null,
    exportBehavior: "Never exported",
    deletionBehavior: "Cryptographic erase",
    loggingRule: "Key ID only",
    overridable: false,
  },
  {
    key: "webhook_delivery",
    label: "Webhook delivery",
    owner: "organization",
    defaultWindow: DAYS(30),
    legalMaximum: DAYS(90),
    exportBehavior: "Sanitized",
    deletionBehavior: "Tombstone",
    loggingRule: "Event and status only",
    overridable: true,
  },
  {
    key: "webhook_delivery_attempt",
    label: "Webhook delivery attempt",
    owner: "organization",
    defaultWindow: DAYS(30),
    legalMaximum: DAYS(90),
    exportBehavior: "Sanitized",
    deletionBehavior: "Tombstone",
    loggingRule: "Outcome and error code only",
    overridable: true,
  },
  {
    key: "notification_preference",
    label: "Notification preference",
    owner: "user",
    defaultWindow: "Account lifetime",
    legalMaximum: null,
    exportBehavior: "Owner export",
    deletionBehavior: "Tombstone",
    loggingRule: "Channel and state only",
    overridable: false,
  },
  {
    key: "notification",
    label: "Notification",
    owner: "user",
    defaultWindow: DAYS(30),
    legalMaximum: DAYS(90),
    exportBehavior: "Owner export",
    deletionBehavior: "Tombstone",
    loggingRule: "Metadata only",
    overridable: true,
  },
  {
    key: "notification_delivery",
    label: "Notification delivery",
    owner: "user",
    defaultWindow: DAYS(30),
    legalMaximum: DAYS(90),
    exportBehavior: "Owner export",
    deletionBehavior: "Tombstone",
    loggingRule: "Channel and status only",
    overridable: true,
  },
  {
    key: "plan",
    label: "Plan and plan entitlement",
    owner: "platform",
    defaultWindow: "Immutable plan history",
    legalMaximum: null,
    exportBehavior: "Sanitized billing export",
    deletionBehavior: "Retain version, tombstone label",
    loggingRule: "Key and version only",
    overridable: false,
  },
  {
    key: "billing_account",
    label: "Billing account",
    owner: "organization",
    defaultWindow: "Subscription lifetime",
    legalMaximum: null,
    exportBehavior: "Redacted",
    deletionBehavior: "Tombstone provider reference",
    loggingRule: "Status only",
    overridable: false,
  },
  {
    key: "subscription",
    label: "Subscription and subscription event",
    owner: "organization",
    defaultWindow: "7 years (financial record)",
    legalMaximum: YEARS(3650),
    exportBehavior: "Redacted billing export",
    deletionBehavior: "Tombstone user reference, retain state",
    loggingRule: "State and version only",
    overridable: false,
  },
  {
    key: "provider_entitlement_projection",
    label: "Provider entitlement projection",
    owner: "organization",
    defaultWindow: "30 days after the last observation",
    legalMaximum: DAYS(90),
    exportBehavior: "Sanitized status",
    deletionBehavior: "Tombstone",
    loggingRule: "Normalized status and reason",
    overridable: true,
  },
  {
    key: "entitlement_grant",
    label: "Entitlement grant",
    owner: "organization",
    defaultWindow: "Grant expiry + 30 days",
    legalMaximum: DAYS(90),
    exportBehavior: "Sanitized values",
    deletionBehavior: "Revoke and tombstone",
    loggingRule: "Key, source, expiry only",
    overridable: true,
  },
  {
    key: "license_snapshot",
    label: "License snapshot and state",
    owner: "organization",
    defaultWindow: "Offline validity + 30 days",
    legalMaximum: DAYS(90),
    exportBehavior: "Sanitized state",
    deletionBehavior: "Tombstone",
    loggingRule: "State, key ID, expiry only",
    overridable: true,
  },
  {
    key: "data_governance_policy",
    label: "Data governance policy",
    owner: "organization",
    defaultWindow: "Until lifecycle deletion",
    legalMaximum: null,
    exportBehavior: "Included",
    deletionBehavior: "Tombstone",
    loggingRule: "Version and changed keys only",
    overridable: false,
  },
  {
    key: "export_job",
    label: "Export job metadata",
    owner: "organization",
    defaultWindow: DAYS(90),
    legalMaximum: YEARS(365),
    exportBehavior: "Metadata only",
    deletionBehavior: "Tombstone",
    loggingRule: "State and attempt only",
    overridable: true,
  },
  {
    key: "export_artifact",
    label: "Export artifact object",
    owner: "organization",
    defaultWindow: "24 hours by default",
    legalMaximum: DAYS(7),
    exportBehavior: "Downloadable only through a re-authorized grant",
    deletionBehavior: "Delete the object and its derived copies",
    loggingRule: "Status only, never content",
    overridable: true,
  },
  {
    key: "export_download_grant",
    label: "Export download grant",
    owner: "user",
    defaultWindow: "15 minutes",
    legalMaximum: DAYS(1),
    exportBehavior: "Metadata only",
    deletionBehavior: "Tombstone",
    loggingRule: "Opaque key and expiry only",
    overridable: false,
  },
  {
    key: "deletion_job",
    label: "Deletion job metadata",
    owner: "organization",
    defaultWindow: DAYS(90),
    legalMaximum: YEARS(365),
    exportBehavior: "Redacted job state",
    deletionBehavior: "Tombstone after completion",
    loggingRule: "State only",
    overridable: true,
  },
  {
    key: "deletion_step",
    label: "Deletion step",
    owner: "organization",
    defaultWindow: "90 days after the job completed",
    legalMaximum: YEARS(365),
    exportBehavior: "Redacted state",
    deletionBehavior: "Tombstone after certificate",
    loggingRule: "State, step, reason only",
    overridable: true,
  },
  {
    key: "deletion_certificate",
    label: "Deletion certificate",
    owner: "organization",
    defaultWindow: DAYS(365),
    legalMaximum: YEARS(3650),
    exportBehavior: "Restricted certificate",
    deletionBehavior: "Retain or tombstone",
    loggingRule: "Certificate ID and status only",
    overridable: false,
  },
  {
    key: "queue_job_envelope",
    label: "Queue job and dead-letter row",
    owner: "organization",
    defaultWindow: "90 days after terminal state",
    legalMaximum: YEARS(365),
    exportBehavior: "Never exported",
    deletionBehavior: "Tombstone",
    loggingRule: "Job, state, error code only",
    overridable: true,
  },
  // -- Existing P01–P05 classes -------------------------------------------
  {
    key: "identity",
    label: "Identity and login metadata",
    owner: "user",
    defaultWindow: "Account lifetime",
    legalMaximum: null,
    exportBehavior: "Personal export",
    deletionBehavior: "Tombstone identity where legal retention requires",
    loggingRule: "IDs and status only, never codes or key material",
    overridable: false,
  },
  {
    key: "passkey_authenticator",
    label: "Passkey authenticator",
    owner: "user",
    defaultWindow: "Account lifetime",
    legalMaximum: null,
    exportBehavior: "Owner export",
    deletionBehavior: "Cryptographic erase",
    loggingRule: "IDs and status only",
    overridable: false,
  },
  {
    key: "membership",
    label: "Organization and membership",
    owner: "organization",
    defaultWindow: "Organization lifetime",
    legalMaximum: null,
    exportBehavior: "Organization-authorized export",
    deletionBehavior: "Tombstone on lifecycle completion",
    loggingRule: "Metadata and status only",
    overridable: false,
  },
  {
    key: "device",
    label: "Device enrollment and workspace binding",
    owner: "device",
    defaultWindow: "Device lifetime",
    legalMaximum: null,
    exportBehavior: "Redacted organization export",
    deletionBehavior: "Revoke and tombstone audit correlation",
    loggingRule: "IDs, capability, status only",
    overridable: false,
  },
  {
    key: "credential",
    label: "Provider, route, and credential metadata",
    owner: "organization",
    defaultWindow: "Credential lifetime",
    legalMaximum: null,
    exportBehavior: "Redacted; secret material never exported",
    deletionBehavior: "Revoke and delete ciphertext",
    loggingRule: "No credential values, no secret-bearing URLs",
    overridable: false,
  },
  {
    key: "policy_snapshot",
    label: "Policy snapshots, acks, and tool policy",
    owner: "organization",
    defaultWindow: "Policy and audit retention",
    legalMaximum: YEARS(3650),
    exportBehavior: "Redacted",
    deletionBehavior: "Tombstone after policy retention",
    loggingRule: "Keys, version, status only",
    overridable: false,
  },
  {
    key: "usage_event",
    label: "Usage and cost records",
    owner: "project",
    defaultWindow: "7 years (financial record)",
    legalMaximum: YEARS(3650),
    exportBehavior: "Scoped export",
    deletionBehavior: "Tombstone and minimize; history is never rewritten",
    loggingRule: "Counts, cost, status only",
    overridable: false,
  },
  {
    key: "run",
    label: "Agent sessions, runs, run events, tool and approval metadata",
    owner: "project",
    defaultWindow: "Project lifetime",
    legalMaximum: null,
    exportBehavior: "Organization export; content follows retention policy",
    deletionBehavior: "Tombstone metadata, preserve required audit",
    loggingRule: "No prompts, responses, arguments, or raw content",
    overridable: false,
  },
  {
    key: "artifact",
    label: "Artifact references and object-backed artifacts",
    owner: "project",
    defaultWindow: "Run or project lifetime",
    legalMaximum: null,
    exportBehavior: "Approved artifact path only",
    deletionBehavior: "Delete metadata plus object, cache, and index copies",
    loggingRule: "Opaque references and checksums only",
    overridable: false,
  },
  {
    key: "audit_security_event",
    label: "Audit and security events",
    owner: "platform",
    defaultWindow: DAYS(365),
    legalMaximum: YEARS(3650),
    exportBehavior: "Restricted redacted export",
    deletionBehavior: "Retained or tombstoned where legally required",
    loggingRule: "Metadata only",
    overridable: false,
  },
  {
    key: "outbox_event",
    label: "Outbox, queue, and dead-letter rows",
    owner: "organization",
    defaultWindow: "90 days after terminal state",
    legalMaximum: YEARS(365),
    exportBehavior: "Not user-content export",
    deletionBehavior: "Tombstone after bounded delivery retention",
    loggingRule: "Event ID, status, error code only",
    overridable: true,
  },
  {
    key: "upstream_provider_data",
    label: "Upstream provider data and provider account state",
    owner: "external",
    defaultWindow: "The provider's own policy",
    legalMaximum: null,
    exportBehavior: "Lumi status and reference only",
    deletionBehavior: "Retained — not Lumi-deletable",
    loggingRule: "Provider status and reason only",
    overridable: false,
  },
  {
    key: "secret",
    label: "Secrets and credentials",
    owner: "organization",
    defaultWindow: "Key lifetime",
    legalMaximum: null,
    exportBehavior: "Never exported",
    deletionBehavior: "Revoke and delete ciphertext",
    loggingRule: "Never logged, never in errors",
    overridable: false,
  },
  {
    key: "operational_log",
    label: "Operational logs and traces",
    owner: "platform",
    defaultWindow: DAYS(30),
    legalMaximum: DAYS(90),
    exportBehavior: "Never exported",
    deletionBehavior: "Physical delete",
    loggingRule: "Metadata only",
    overridable: true,
  },
];

const SUMMARY_BY_KEY = new Map(DATA_CLASS_SUMMARIES.map((row) => [row.key, row]));

export function dataClassSummary(key: string): DataClassSummary | null {
  return SUMMARY_BY_KEY.get(key) ?? null;
}

/** The window a class is actually held for, after a policy override. */
export interface EffectiveRetention {
  readonly seconds: number;
  readonly source: "default" | "policy_override";
  readonly human: string;
  /** True when the override is shorter than the class baseline. */
  readonly shortened: boolean;
}

const SECONDS_PER_DAY = 86_400;

export function formatWindow(seconds: number): string {
  if (seconds <= 0) return "0 seconds";
  if (seconds % SECONDS_PER_DAY === 0) {
    const days = seconds / SECONDS_PER_DAY;
    if (days >= 365 && days % 365 === 0) {
      const years = days / 365;
      return years === 1 ? "1 year" : `${years} years`;
    }
    return days === 1 ? "1 day" : `${days} days`;
  }
  if (seconds % 3_600 === 0) {
    const hours = seconds / 3_600;
    return hours === 1 ? "1 hour" : `${hours} hours`;
  }
  if (seconds % 60 === 0) {
    const minutes = seconds / 60;
    return minutes === 1 ? "1 minute" : `${minutes} minutes`;
  }
  return `${seconds} seconds`;
}

/**
 * Resolve a class's effective window from the frozen default and the policy
 * override map. An override longer than the class baseline is surfaced as such
 * rather than being hidden: the server refuses to extend past the legal
 * maximum, and this helper keeps the direction of every number visible.
 */
export function effectiveRetention(
  key: string,
  overrides: Readonly<Record<string, number>>,
): EffectiveRetention | null {
  const summary = SUMMARY_BY_KEY.get(key);
  if (!summary) return null;
  const override = overrides[key];
  if (override === undefined) {
    return {
      seconds: 0,
      source: "default",
      human: summary.defaultWindow,
      shortened: false,
    };
  }
  return {
    seconds: override,
    source: "policy_override",
    human: formatWindow(override),
    shortened: true,
  };
}

/** The two rules a policy edit must state, stated once. */
export const RETENTION_RULES = [
  {
    title: "A policy can shorten retention. It cannot extend it.",
    body: "Writing a smaller window always works. Writing a longer one is refused unless an audited override exists, and a browser cannot create one — so a longer value here is simply rejected.",
  },
  {
    title: "Legal and financial retention is not a preference.",
    body: "Audit, security, billing, usage, and deletion-certificate records have a legal maximum. A policy may shorten a window; it may not erase an obligation, and a downgrade never deletes anything.",
  },
  {
    title: "A legal hold suspends expiry.",
    body: "While a hold is active, records in scope are not expired and not deleted. Only an audited support or legal release lifts it, and the release is recorded.",
  },
] as const;

// ---------------------------------------------------------------------------
// Export categories
// ---------------------------------------------------------------------------

export interface ExportCategoryCopy {
  readonly key: ExportCategory;
  readonly label: string;
  readonly contains: string;
  readonly personal: boolean;
  readonly personalNote?: string;
}

export const EXPORT_CATEGORY_COPY: readonly ExportCategoryCopy[] = [
  {
    key: "identity",
    label: "Identity",
    contains:
      "Your account identifiers, verification state, and profile fields. No credential or key material.",
    personal: true,
  },
  {
    key: "organization",
    label: "Organization",
    contains: "Organization configuration, teams, and membership records this organization owns.",
    personal: false,
    personalNote:
      "Organization data is not part of a personal export. Use the organization export.",
  },
  {
    key: "devices",
    label: "Devices",
    contains: "Device enrollment, capability, and workspace-binding metadata.",
    personal: false,
    personalNote: "Device records belong to the organization, not to your account export.",
  },
  {
    key: "runs_metadata",
    label: "Run metadata",
    contains:
      "Agent sessions, runs, run events, and tool and approval metadata. No prompts, responses, or tool arguments.",
    personal: false,
    personalNote: "Run metadata belongs to the organization and project scope.",
  },
  {
    key: "usage_billing",
    label: "Usage and billing",
    contains:
      "Usage counts, cost records, and the mapped subscription state. Provider account references are redacted.",
    personal: false,
    personalNote: "Billing records are an organization record, held for financial audit.",
  },
  {
    key: "audit_redacted",
    label: "Audit (redacted)",
    contains:
      "A redacted audit and security event projection. Restricted: platform-scoped and reviewed, never a raw log dump.",
    personal: false,
    personalNote: "The audit projection is platform-scoped and cannot be requested per account.",
  },
  {
    key: "notifications",
    label: "Notifications",
    contains: "Notifications addressed to you and their delivery status for the last 30 days.",
    personal: true,
  },
  {
    key: "data_governance",
    label: "Data governance",
    contains: "The retention, logging, and legal-hold settings that govern your own records.",
    personal: true,
  },
];

const CATEGORY_COPY_BY_KEY = new Map(EXPORT_CATEGORY_COPY.map((row) => [row.key, row]));

export function exportCategoryCopy(key: ExportCategory): ExportCategoryCopy | null {
  return CATEGORY_COPY_BY_KEY.get(key) ?? null;
}
/** Categories a scope may request. A personal scope gets a strict subset. */
export function allowedCategories(scope: "organization" | "user"): ExportCategory[] {
  return EXPORT_CATEGORIES.filter((key) => {
    const copy = CATEGORY_COPY_BY_KEY.get(key);
    if (copy === undefined) return false;
    // Every category is exportable for an organization; only the user-owned
    // three are exportable for a personal request.
    return scope === "organization" || copy.personal;
  });
}

/**
 * Why a manifest is what it is. A retry reuses the same frozen manifest and the
 * same snapshot cutoff, so a resumed export is consistent rather than fresh.
 */
export const EXPORT_SNAPSHOT_RULES = [
  "The category list and the snapshot cutoff are frozen when the request is accepted. A retry resumes the same manifest against the same cutoff, so a resumed export is internally consistent.",
  "A retry is not a fresh snapshot. Data written after the cutoff is not in the artifact, and the cutoff does not move.",
  "Secrets, credentials, and login sessions are in no category. They are never exported in any scope.",
] as const;

// ---------------------------------------------------------------------------
// Export job state
// ---------------------------------------------------------------------------

export interface StateCopy {
  readonly label: string;
  readonly tone: Tone;
  readonly body: string;
}

export const EXPORT_STATE_COPY: Readonly<Record<ExportState, StateCopy>> = {
  requested: {
    label: "Requested",
    tone: "neutral",
    body: "The request is recorded. The manifest and the snapshot cutoff are frozen now and will not move.",
  },
  queued: {
    label: "Queued",
    tone: "info",
    body: "The job is waiting for a worker. No data has been collected yet.",
  },
  collecting: {
    label: "Collecting",
    tone: "info",
    body: "Records inside the snapshot cutoff are being gathered. The cutoff does not move while this runs.",
  },
  packaging: {
    label: "Packaging",
    tone: "info",
    body: "The collected records are being written into the encrypted private artifact.",
  },
  verifying: {
    label: "Verifying",
    tone: "info",
    body: "The artifact is being checked. Nothing is downloadable until verification finishes.",
  },
  ready: {
    label: "Ready",
    tone: "success",
    body: "The artifact exists. Each download mints a new short-lived grant; there is no permanent link.",
  },
  expired: {
    label: "Expired",
    tone: "warning",
    body: "The artifact passed its expiry and is no longer downloadable. Request a new export to get a fresh snapshot.",
  },
  retry_wait: {
    label: "Waiting to retry",
    tone: "warning",
    body: "A retryable step failed. The retry resumes the same manifest and the same snapshot cutoff.",
  },
  failed: {
    label: "Failed",
    tone: "danger",
    body: "The job stopped on a permanent failure. It will not retry on its own.",
  },
  cancelled: {
    label: "Cancelled",
    tone: "neutral",
    body: "The job was cancelled before it produced an artifact.",
  },
};

export function exportStateCopy(state: ExportState): StateCopy {
  return EXPORT_STATE_COPY[state];
}

/** `ready` is the only state that can mint a grant. The server agrees. */
export function canMintDownloadGrant(state: ExportState): boolean {
  return state === "ready";
}

/**
 * Whether a download is available right now, and why not when it is not.
 *
 * The server already answers `downloadable`; the client re-checks the two facts
 * it can check locally so a stale list row cannot offer a dead button.
 */
export function downloadAvailability(input: {
  state: ExportState;
  serverDownloadable: boolean;
  artifactExpiresAt: string | null;
  now: Date;
}): { available: boolean; reason: string } {
  if (!canMintDownloadGrant(input.state)) {
    return {
      available: false,
      reason: `The export is ${EXPORT_STATE_COPY[input.state].label.toLowerCase()}. Only a ready export can mint a download grant.`,
    };
  }
  if (!input.serverDownloadable) {
    return {
      available: false,
      reason:
        "The artifact is not available for download. The server did not mark this export as downloadable.",
    };
  }
  if (input.artifactExpiresAt === null) {
    return {
      available: false,
      reason: "The artifact expiry is unknown, so no download can be offered.",
    };
  }
  const expiresAt = Date.parse(input.artifactExpiresAt);
  if (Number.isNaN(expiresAt)) {
    return {
      available: false,
      reason: "The artifact expiry could not be read, so no download can be offered.",
    };
  }
  if (input.now.getTime() >= expiresAt) {
    return {
      available: false,
      reason:
        "The artifact has passed its expiry. The grant is refused, and a new export is needed for a fresh snapshot.",
    };
  }
  return { available: true, reason: "" };
}

export const DOWNLOAD_GRANT_NOTES = [
  `A download mints a new short-lived, re-authorized grant. Authorization is checked again at download time, and the grant itself is valid for ${DOWNLOAD_GRANT_TTL_SECONDS / 60} minutes.`,
  "The grant is bound to this export, this principal, and this snapshot cutoff. It is not a link you can share or bookmark.",
  "When the grant lapses there is nothing left to reuse: mint a new one. There is no permanent artifact URL.",
] as const;

/** Copy for the row of a job that cannot be downloaded yet. */
export const NOT_DOWNLOADABLE_NOTE =
  "The download action is intentionally absent rather than disabled-and-hidden: a grant is only minted for a ready export, so offering the control earlier would promise something the server refuses.";

// ---------------------------------------------------------------------------
// Deletion job state
// ---------------------------------------------------------------------------

export const DELETION_STATE_COPY: Readonly<Record<DeletionState, StateCopy>> = {
  requested: {
    label: "Requested",
    tone: "neutral",
    body: "The lifecycle request is recorded. The cutoff is now; new work for this scope is fenced.",
  },
  awaiting_grace: {
    label: "Waiting out the grace window",
    tone: "warning",
    body: "The job can still be cancelled until the grace window closes. After that it proceeds.",
  },
  queued: {
    label: "Queued",
    tone: "info",
    body: "The job is waiting for a worker to build its plan.",
  },
  planning: {
    label: "Planning",
    tone: "info",
    body: "The planner is walking the data classes and their references. A plan is not a deletion.",
  },
  deleting: {
    label: "Deleting",
    tone: "info",
    body: "Steps are executing. Each step records its own outcome, so a failure is visible rather than hidden.",
  },
  verifying: {
    label: "Verifying",
    tone: "info",
    body: "Absence is being verified before the job may report completion. Completion is not inferred.",
  },
  completed: {
    label: "Completed",
    tone: "success",
    body: "Every step reached a terminal state. Read the coverage and the skipped steps: completion is not the same as having touched everything.",
  },
  retry_wait: {
    label: "Waiting to retry",
    tone: "warning",
    body: "A retryable step failed and will be retried automatically. Partial failure is not resumed silently.",
  },
  needs_attention: {
    label: "Needs attention",
    tone: "danger",
    body: "The job parked. It will not retry on its own; a human decides whether to resume it.",
  },
  cancelled: {
    label: "Cancelled",
    tone: "neutral",
    body: "The job was cancelled inside its grace window. Nothing was deleted.",
  },
};

export function deletionStateCopy(state: DeletionState): StateCopy {
  return DELETION_STATE_COPY[state];
}

/**
 * The three real reasons a job parks. The gate names exactly these: a legal
 * hold, an unresolved external reference, and exhausted retries.
 */
export type NeedsAttentionReason =
  | "legal_hold"
  | "unresolved_external_reference"
  | "exhausted_retries"
  | "unknown";

export const NEEDS_ATTENTION_REASONS: Readonly<
  Record<
    NeedsAttentionReason,
    { label: string; body: string; resumeBlocked: boolean; resumeNote: string }
  >
> = {
  legal_hold: {
    label: "A legal hold covers part of this scope",
    body: "Records under the hold are not deleted and not expired. The hold is lifted only by an audited support or legal release, which is a separate action from resuming this job.",
    resumeBlocked: true,
    resumeNote:
      "Resuming now would be refused while the hold is active. Ask for an audited release first.",
  },
  unresolved_external_reference: {
    label: "An external reference could not be resolved",
    body: "Something outside Lumi still points at this scope. Lumi will not claim that reference as deleted, and it is not resolved by retrying.",
    resumeBlocked: false,
    resumeNote:
      "Resuming re-runs the remaining steps. It does not change what the external system holds.",
  },
  exhausted_retries: {
    label: "Retries were exhausted",
    body: "A retryable step failed repeatedly. Resuming is an explicit decision by someone with delete permission, not an automatic action.",
    resumeBlocked: false,
    resumeNote:
      "Resuming starts another attempt of the same plan. Skipped and retained steps stay skipped and retained.",
  },
  unknown: {
    label: "The server did not publish a stable reason",
    body: "The job is parked and the reason code is not one this build recognizes. Treat the job as incomplete.",
    resumeBlocked: false,
    resumeNote: "Review the step list below before resuming.",
  },
};

const LEGAL_HOLD_CODES = new Set(["deletion_legal_hold"]);
const EXTERNAL_CODES = new Set(["deletion_reference_system_absent", "deletion_scope_conflict"]);
const RETRY_CODES = new Set([
  "deletion_executor_unavailable",
  "deletion_step_failed",
  "store_unavailable",
  "queue_job_lease_expired",
  "queue_job_claim_conflict",
  "export_artifact_unavailable",
]);

export function needsAttentionReason(failureCode: string | null): NeedsAttentionReason {
  if (failureCode === null) return "unknown";
  if (LEGAL_HOLD_CODES.has(failureCode)) return "legal_hold";
  if (EXTERNAL_CODES.has(failureCode)) return "unresolved_external_reference";
  if (RETRY_CODES.has(failureCode)) return "exhausted_retries";
  return "unknown";
}

export function needsAttentionCopy(failureCode: string | null) {
  return NEEDS_ATTENTION_REASONS[needsAttentionReason(failureCode)];
}

/**
 * Consequence copy for the explicit resume. Resume is a permission-checked
 * action, never an automatic retry, so the consequence is stated before the
 * confirmation.
 */
export const RESUME_COPY = {
  title: "Resume this deletion job?",
  body: [
    "Resuming re-runs the steps that are not in a terminal state, using the same plan. It is an explicit action by someone with delete permission.",
    "A step that already succeeded, was skipped, or is retained for legal reasons is not re-run. A resumed job can therefore reach completion without having deleted those records.",
    "It will not delete data on a managed device or ZCode host, and it will not delete data held by an upstream AI provider. Those references stay recorded as skipped.",
  ],
  confirmLabel: "Resume deletion",
  cancelLabel: "Leave it parked",
  busyLabel: "Resuming…",
} as const;

// ---------------------------------------------------------------------------
// Deletion steps: what was deleted and what was not
// ---------------------------------------------------------------------------

export const DELETION_STEP_STATE_COPY: Readonly<Record<DeletionStepState, StateCopy>> = {
  pending: { label: "Pending", tone: "neutral", body: "Planned, not started." },
  running: { label: "Running", tone: "info", body: "This step is executing now." },
  retry_wait: {
    label: "Waiting to retry",
    tone: "warning",
    body: "A retryable failure. The step has not finished.",
  },
  needs_attention: {
    label: "Needs attention",
    tone: "danger",
    body: "This step parked. It is not complete.",
  },
  succeeded: {
    label: "Deleted",
    tone: "success",
    body: "The reference was removed from a store Lumi owns.",
  },
  failed: {
    label: "Failed",
    tone: "danger",
    body: "The step did not complete. It only leaves this state through an explicit resume.",
  },
  skipped: {
    label: "Skipped",
    tone: "warning",
    body: "Not deleted. The reason is stated with the step.",
  },
};

export function deletionStepStateCopy(state: DeletionStepState): StateCopy {
  return DELETION_STEP_STATE_COPY[state];
}

/** Why a step was skipped. A skipped step always says why. */
export const SKIP_REASON_COPY: Readonly<
  Record<DeletionSkipReason, { label: string; body: string; lumiDeleted: false }>
> = {
  deletion_legal_hold: {
    label: "Held by a legal hold",
    body: "A legal hold covers this class. The record is retained on purpose, not deleted and not expired, until an audited support or legal release.",
    lumiDeleted: false,
  },
  retained_legal_only: {
    label: "Retained for a legal or security duty",
    body: "Audit, security, billing, and certificate records outlive deletion where a duty requires it. Personal content is minimized and identifiers are tombstoned; the history is not rewritten.",
    lumiDeleted: false,
  },
  deletion_not_lumi_owned: {
    label: "Not Lumi's data to delete",
    body: "The reference points at a store Lumi does not own. Lumi records it, reports it, and never claims it as deleted.",
    lumiDeleted: false,
  },
  deletion_reference_system_absent: {
    label: "No such system in this control plane",
    body: "The reference system is named by the deletion contract but is not part of this control plane, so nothing was traversed. It is reported as pending coverage rather than counted as deleted.",
    lumiDeleted: false,
  },
};

export function skipReasonCopy(reason: DeletionSkipReason) {
  return SKIP_REASON_COPY[reason];
}

/** Reference stores Lumi owns, and therefore can delete from. */
export const REFERENCE_KIND_COPY: Readonly<
  Record<ReferenceKind, { label: string; lumiOwned: boolean; body: string }>
> = {
  database_row: {
    label: "Lumi database row",
    lumiOwned: true,
    body: "A row in Lumi's own store, removed or tombstoned by this job.",
  },
  r2_object: {
    label: "Private export object",
    lumiOwned: true,
    body: "An object in Lumi's private export bucket, plus its derived copies. Deleting the row alone would not have been enough.",
  },
  local_device_data: {
    label: "Local device data",
    lumiOwned: false,
    body: "Data on a managed device or ZCode host. A cloud deletion cannot reach it; it is removed on the host.",
  },
  upstream_provider_data: {
    label: "Upstream provider data",
    lumiOwned: false,
    body: "Data held by an upstream AI provider. Lumi cannot delete it, so Lumi does not claim it as deleted.",
  },
};

export function referenceKindCopy(kind: ReferenceKind) {
  return REFERENCE_KIND_COPY[kind];
}

/**
 * The full honest presentation of one deletion step.
 *
 * `claim` is the sentence the step is allowed to make. It is deliberately
 * conservative: a step is only ever described as a deletion when the store is
 * Lumi-owned and the state is `succeeded`.
 */
export interface StepPresentation {
  readonly state: string;
  readonly tone: Tone;
  readonly stateLabel: string;
  readonly ownership: "lumi_owned" | "not_lumi_owned" | "not_established";
  readonly ownershipLabel: string;
  /** The one-line claim. Never stronger than the evidence. */
  readonly claim: string;
  /** The reason, when the step did not delete anything. */
  readonly reason: string;
  /** True when this step may be described as a deletion. */
  readonly deleted: boolean;
}

export function presentDeletionStep(step: DeletionStep): StepPresentation {
  const stateCopy = deletionStepStateCopy(step.state);
  const kindCopy = step.reference_kind === null ? null : REFERENCE_KIND_COPY[step.reference_kind];
  const ownership: StepPresentation["ownership"] =
    kindCopy === null ? "not_established" : kindCopy.lumiOwned ? "lumi_owned" : "not_lumi_owned";
  const ownershipLabel = kindCopy === null ? "Ownership not established" : kindCopy.label;

  if (step.state === "succeeded" && ownership === "lumi_owned") {
    return {
      state: step.state,
      tone: stateCopy.tone,
      stateLabel: stateCopy.label,
      ownership,
      ownershipLabel,
      claim: "Removed from a store Lumi owns.",
      reason: "",
      deleted: true,
    };
  }

  if (step.state === "succeeded") {
    // A `succeeded` step against a store Lumi does not own would be a contract
    // violation. Report it as not-established rather than as a deletion.
    return {
      state: step.state,
      tone: "warning",
      stateLabel: "Outcome not established",
      ownership,
      ownershipLabel,
      claim:
        "The server reports this step as succeeded against a reference Lumi does not own. No deletion is claimed here.",
      reason:
        "The reference is not a Lumi-owned store, so a successful step cannot mean a Lumi deletion.",
      deleted: false,
    };
  }

  if (step.state === "skipped") {
    if (step.skip_reason !== null) {
      const reason = SKIP_REASON_COPY[step.skip_reason];
      return {
        state: step.state,
        tone: "warning",
        stateLabel: stateCopy.label,
        ownership,
        ownershipLabel,
        claim: "Not deleted.",
        reason: `${reason.label}. ${reason.body}`,
        deleted: false,
      };
    }
    return {
      state: step.state,
      tone: "warning",
      stateLabel: stateCopy.label,
      ownership,
      ownershipLabel,
      claim: "Not deleted.",
      reason:
        step.unmapped_skip_reason === null
          ? "The server recorded no skip reason for this step, so the reason is not established."
          : `The server recorded an unrecognized skip reason (${step.unmapped_skip_reason}), so the reason is not established.`,
      deleted: false,
    };
  }

  return {
    state: step.state,
    tone: stateCopy.tone,
    stateLabel: stateCopy.label,
    ownership,
    ownershipLabel,
    claim: stateCopy.body,
    reason: step.failure_code === null ? "" : `Failure code ${step.failure_code}.`,
    deleted: false,
  };
}

/** Counts of the honest step outcomes, for the summary line. */
export interface StepTally {
  readonly total: number;
  readonly deleted: number;
  readonly skipped: number;
  readonly retained: number;
  readonly notLumiOwned: number;
  readonly open: number;
}

export function tallySteps(steps: readonly DeletionStep[]): StepTally {
  let deleted = 0;
  let skipped = 0;
  let retained = 0;
  let notLumiOwned = 0;
  let open = 0;
  for (const step of steps) {
    const presentation = presentDeletionStep(step);
    if (presentation.deleted) {
      deleted += 1;
      continue;
    }
    if (step.state !== "skipped") {
      open += 1;
      continue;
    }
    skipped += 1;
    if (step.skip_reason === "retained_legal_only" || step.skip_reason === "deletion_legal_hold") {
      retained += 1;
    }
    if (step.skip_reason === "deletion_not_lumi_owned") {
      notLumiOwned += 1;
    }
  }
  return { total: steps.length, deleted, skipped, retained, notLumiOwned, open };
}

// ---------------------------------------------------------------------------
// Certificate: coverage, not a claim of everything
// ---------------------------------------------------------------------------

export interface ReferenceCoverage {
  readonly traversed: string[];
  readonly pending: string[];
  readonly absentReason: string | null;
  /** True only when every named reference system was traversed. */
  readonly complete: boolean;
}

const EMPTY_COVERAGE: ReferenceCoverage = {
  traversed: [],
  pending: [],
  absentReason: null,
  complete: false,
};

/**
 * Read the certificate's `reference_coverage` block.
 *
 * The block lives inside `class_results`, next to the per-class counts. An
 * absent block is not full coverage: it reports zero traversed systems, so the
 * certificate cannot be read as "everything".
 */
export function readReferenceCoverage(
  classResults: Readonly<Record<string, unknown>>,
): ReferenceCoverage {
  const raw = classResults["reference_coverage"];
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return EMPTY_COVERAGE;
  const record = raw as Record<string, unknown>;
  const traversed = Array.isArray(record.traversed)
    ? record.traversed.filter(
        (item): item is string => typeof item === "string" && item.length <= 64,
      )
    : [];
  const pending = Array.isArray(record.pending)
    ? record.pending.filter((item): item is string => typeof item === "string" && item.length <= 64)
    : [];
  const absentReason = typeof record.absent_reason === "string" ? record.absent_reason : null;
  return {
    traversed,
    pending,
    absentReason,
    complete: pending.length === 0 && traversed.length > 0,
  };
}

export const COVERAGE_NOTE =
  "Coverage states which reference stores this job traversed and which named systems it did not. A completed deletion is not a claim that every system was covered.";

export const CERTIFICATE_NOTE =
  "A certificate records the classes this job reported, the coverage it achieved, and the classes deliberately retained. It is a statement about one traversal, not a guarantee about data elsewhere.";

/** Per-class outcome counts, rendered as a bounded list. */
export interface ClassResultRow {
  readonly dataClass: string;
  readonly label: string;
  readonly owner: OwnerScope | "unknown";
  readonly counts: ReadonlyArray<{ state: string; count: number }>;
}

export function readClassResults(
  classResults: Readonly<Record<string, unknown>>,
): ClassResultRow[] {
  const rows: ClassResultRow[] = [];
  for (const [key, value] of Object.entries(classResults)) {
    if (key === "reference_coverage" || key === "disclosures" || key === "organization_row")
      continue;
    if (typeof value !== "object" || value === null || Array.isArray(value)) continue;
    const counts = Object.entries(value as Record<string, unknown>)
      .filter((entry): entry is [string, number] => typeof entry[1] === "number")
      .map(([state, count]) => ({ state, count }))
      .sort((left, right) => left.state.localeCompare(right.state));
    const summary = SUMMARY_BY_KEY.get(key);
    rows.push({
      dataClass: key,
      label: summary?.label ?? key,
      owner: summary?.owner ?? "unknown",
      counts,
    });
  }
  return rows.sort((left, right) => left.dataClass.localeCompare(right.dataClass));
}

// ---------------------------------------------------------------------------
// Personal (account) surface
// ---------------------------------------------------------------------------

/** The organization-exit requirement, rendered before a user starts. */
export const ACCOUNT_DELETION_PREREQUISITES = [
  "Leave or transfer every organization where you are an owner or admin. A member or viewer role does not block the request.",
  "Export what you need first. A personal export is separate from this request and has its own short-lived download.",
  `Reauthenticate and type the confirmation phrase. Both are required even for a small account, and the workflow then waits out a ${PERSONAL_DELETION_GRACE_SECONDS / 86_400}-day grace window.`,
] as const;

export const ACCOUNT_DELETION_REQUIRES_ORG_EXIT =
  "Leave or transfer every organization you own or administer first. The server refuses the request rather than deleting an organization on your behalf.";

export const PERSONAL_DELETION_COPY = {
  requestTitle: "Delete this account?",
  requestBody: [
    `Lumi starts a deletion workflow for your account. It first waits out a ${PERSONAL_DELETION_GRACE_SECONDS / 86_400}-day grace window so you can change your mind.`,
    "It does not delete data on your managed devices or on a ZCode host, and it cannot delete data held by an upstream AI provider. Those records stay recorded as skipped.",
    "Records that a legal, security, or financial duty requires are retained in minimized, tombstoned form. The certificate states what was retained.",
  ],
  confirmPhraseLabel: "Type the confirmation phrase",
  confirmPhrase: DELETION_CONFIRMATION_PHRASE,
  requestLabel: "Request account deletion",
  busyLabel: "Requesting…",
  cancelTitle: "Cancel the pending account deletion?",
  cancelBody: [
    "Cancelling stops the workflow while it is still in its grace window. Nothing has been deleted at this point.",
    "This cannot be done after the grace window closes; the workflow proceeds instead.",
  ],
  cancelLabel: "Cancel the deletion",
  cancelBusyLabel: "Cancelling…",
} as const;

export const PERSONAL_EXPORT_COPY = {
  requestTitle: "Export your account data?",
  requestBody: [
    "A personal export contains only data Lumi holds about your account: your identity records, your notifications, and the retention settings that govern them.",
    "Organization, device, run, usage, and audit data belong to the organization scope and are not included here.",
    "You need a recent security check and the confirmation phrase. The artifact expires, and every download mints a new short-lived grant.",
  ],
  confirmPhraseLabel: "Type the confirmation phrase",
  confirmPhrase: EXPORT_CONFIRMATION_PHRASE,
  requestLabel: "Request my export",
  busyLabel: "Requesting…",
} as const;

export const REAUTH_NOTE =
  "A personal data action needs a recent security check. The check is consumed by the request it authorizes and is never stored.";

// ---------------------------------------------------------------------------
// Failure codes
// ---------------------------------------------------------------------------

/** Bounded copy for the job failure codes the worker and routes can record. */
export const JOB_FAILURE_COPY: Readonly<Record<string, { label: string; body: string }>> = {
  store_unavailable: {
    label: "Storage unavailable",
    body: "Lumi's store did not answer. Nothing is known to be deleted; the job is retryable.",
  },
  queue_job_lease_expired: {
    label: "Worker lease expired",
    body: "The worker's claim lapsed before it settled. Retryable, and a retry re-runs the same plan.",
  },
  queue_job_claim_conflict: {
    label: "Worker claim conflict",
    body: "Two workers claimed the same generation. One is refused; nothing is deleted twice.",
  },
  queue_job_dedupe_conflict: {
    label: "Duplicate job suppressed",
    body: "The job had already reached a terminal state, so a redelivered message was acknowledged rather than re-run.",
  },
  export_artifact_unavailable: {
    label: "Artifact unavailable",
    body: "The packaged object could not be read, so no download is offered. The job metadata is not a claim that the export succeeded.",
  },
  export_category_invalid: {
    label: "Category no longer exportable",
    body: "A named category is not exportable under the current registry, so the manifest was refused rather than silently narrowed.",
  },
  deletion_legal_hold: {
    label: "Legal hold",
    body: "A legal hold covers part of this scope. Deletion is blocked until an audited release.",
  },
  deletion_executor_unavailable: {
    label: "Deletion executor unavailable",
    body: "The step runner did not answer. The job parked; it does not retry on its own.",
  },
  deletion_step_failed: {
    label: "Step failed",
    body: "A step failed after its attempts. The job parked and needs an explicit resume.",
  },
  deletion_reference_system_absent: {
    label: "Reference system absent",
    body: "A named reference system is not part of this control plane, so nothing was traversed there. Reported as pending coverage.",
  },
  deletion_cutoff_reached: {
    label: "Deletion cutoff reached",
    body: "The scope is past its deletion cutoff, so this work is fenced and cannot create or resume data work.",
  },
  deletion_scope_conflict: {
    label: "A job already exists for this scope",
    body: "A second deletion job would fork the same scope, so it is refused.",
  },
  deletion_not_resumable: {
    label: "Not resumable",
    body: "This job is not in a resumable state. Only a job parked in needs attention can be resumed.",
  },
  deletion_reauth_required: {
    label: "Security check required",
    body: "Complete a recent security check and try again.",
  },
  deletion_requires_org_exit: {
    label: "Leave or transfer organizations first",
    body: ACCOUNT_DELETION_REQUIRES_ORG_EXIT,
  },
  cancelled_by_user: {
    label: "Cancelled by the requester",
    body: "The requester cancelled the workflow inside its grace window. Nothing was deleted.",
  },
  unsupported_event_type: {
    label: "Unsupported job type",
    body: "The message named a job type the workers do not implement. It is a permanent failure, not a retry.",
  },
  queue_job_envelope_invalid: {
    label: "Malformed job message",
    body: "The job message did not match the bounded envelope, so it was refused before any domain work.",
  },
};

export function jobFailureCopy(failureCode: string | null): { label: string; body: string } | null {
  if (failureCode === null) return null;
  return (
    JOB_FAILURE_COPY[failureCode] ?? {
      label: "Unrecognized failure code",
      body: "The server recorded a failure code this build does not recognize. Treat the job as incomplete and review the step list.",
    }
  );
}

/** Stable reasons the routes can return, mapped to safe presentation copy. */
export const DATA_ERROR_COPY: Readonly<
  Record<string, { title: string; message: string; tone: Tone }>
> = {
  data_policy_invalid: {
    title: "The policy change was refused",
    message:
      "One of the values is not permitted. A policy can shorten a retention window, and full-content logging is not a self-service mode.",
    tone: "warning",
  },
  data_policy_version_conflict: {
    title: "The policy changed",
    message:
      "Someone else saved this policy. Reload it and apply your change to the current version.",
    tone: "warning",
  },
  data_policy_retention_over_legal_maximum: {
    title: "Beyond the legal maximum",
    message:
      "A retention window cannot be extended past the class maximum without an audited override, and this page cannot create one. Shorten the window, or leave the baseline in place.",
    tone: "warning",
  },
  version_conflict: {
    title: "The record changed",
    message: "This record was updated elsewhere. Reload it and retry against the current version.",
    tone: "warning",
  },
  export_not_ready: {
    title: "The export is not ready",
    message: "Only a ready export can mint a download grant. Nothing was downloaded.",
    tone: "info",
  },
  export_expired: {
    title: "The export has expired",
    message:
      "The artifact passed its expiry, so the grant was refused. Request a new export for a fresh snapshot.",
    tone: "warning",
  },
  export_artifact_unavailable: {
    title: "The artifact is unavailable",
    message: "The packaged artifact could not be read, so no download is offered.",
    tone: "danger",
  },
  export_category_invalid: {
    title: "That category set is not available",
    message: "Select at least one category, and only categories the current scope may request.",
    tone: "warning",
  },
  deletion_not_resumable: {
    title: "This job is not resumable",
    message:
      "Only a job parked in needs attention can be resumed, and only with delete permission.",
    tone: "warning",
  },
  deletion_legal_hold: {
    title: "A legal hold blocks this",
    message:
      "Records under the hold are not deleted and not expired. An audited support or legal release is required first.",
    tone: "warning",
  },
  deletion_scope_conflict: {
    title: "A job already exists for this scope",
    message: "The existing job is the one to follow; a second job would fork the same scope.",
    tone: "warning",
  },
  deletion_requires_org_exit: {
    title: "Leave or transfer organizations first",
    message: ACCOUNT_DELETION_REQUIRES_ORG_EXIT,
    tone: "warning",
  },
  deletion_reauth_required: {
    title: "Security check required",
    message: "Complete a recent security check, then retry the request.",
    tone: "warning",
  },
  deletion_cutoff_reached: {
    title: "This scope is past its deletion cutoff",
    message:
      "New work is fenced for a scope being deleted, so this request was refused rather than queued.",
    tone: "warning",
  },
  organization_pending_deletion: {
    title: "The organization is being deleted",
    message:
      "New work is fenced while the deletion workflow runs. Job status and resume stay available.",
    tone: "warning",
  },
  resource_not_found: {
    title: "Not found in this scope",
    message: "The record is not available in your current organization scope.",
    tone: "neutral",
  },
  permission_denied: {
    title: "Access not permitted",
    message:
      "Your current role cannot perform this action. Ask an administrator to review the data permission.",
    tone: "neutral",
  },
  idempotency_conflict: {
    title: "A different request is in flight",
    message: "The same idempotency key was used for a different request. Start the action again.",
    tone: "warning",
  },
  idempotency_in_progress: {
    title: "The request is still running",
    message: "An identical request is already in progress. Wait a moment and refresh.",
    tone: "info",
  },
};

/**
 * Presentation for a P06 data error.
 *
 * The shared `presentApiError` owns the common cases; this adds the P06 data
 * codes, reading `details.reason` the same way the shared P05 table does. The
 * server's own message is never rendered: only the frozen copy and the stable
 * code are.
 */
export function presentDataError(error: unknown): ErrorPresentation & { tone: Tone } {
  if (error instanceof ApiClientError) {
    const reason = error.details.reason;
    const reasonCode = typeof reason === "string" ? reason : null;
    const candidates = [error.code, reasonCode];
    for (const candidate of candidates) {
      if (candidate !== null && candidate !== undefined) {
        const known = DATA_ERROR_COPY[candidate];
        if (known) {
          return {
            title: known.title,
            message: known.message,
            code: candidate,
            requestId: error.requestId,
            retryable: error.retryable,
            tone: known.tone,
          };
        }
      }
    }
  }
  const base = presentApiError(error);
  const tone: Tone = base.retryable ? "warning" : "danger";
  return { ...base, tone };
}
