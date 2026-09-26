/**
 * Data controls: the platform-level switches currently in effect, read-only.
 *
 * WHY this tab exists and why it is read-only. `docs/screens/lumi_export_history.webp`
 * shows Data & Retention as four tabs, and the fourth is "Data controls". The
 * first tab already owns the editor, so putting an editor here too would give an
 * operator two places to change the same thing. The division this file keeps is:
 *
 * - Retention policies — configure the per-class windows, and the full 72-class
 *   registry with each class's owner, window, legal maximum, export behavior, and
 *   deletion behavior.
 * - Data controls — read what the PLATFORM is currently doing, and what it means.
 *
 * These five controls are the ones whose effect is not visible from a per-class
 * window: they change what is written at all, whether anything expires while a
 * hold is active, how long an export artifact stays reachable, and whether an
 * upstream provider's own retention is in scope. An operator asking "what is
 * this policy actually doing right now?" wants the status, not the form.
 *
 * Every consequence sentence here is derived from the frozen contract, not
 * authored as product copy. Where the contract fixes a value, this file states
 * it; where the contract deliberately leaves a value to the provider, it says so
 * rather than guessing.
 */

import type {
  BackupLifecycle,
  DataGovernancePolicy,
  LoggingMode,
  ProviderRetentionDisclosure,
} from "./api";
import { DataTable, Notice, Pill, Surface, SurfaceHeader, TableCell } from "./ui";

/** What each logging mode permits, from the frozen logging-mode definition. */
const LOGGING_MODE_EFFECT: Readonly<Record<LoggingMode, string>> = {
  metadata_only:
    "IDs, versions, state, counts, bounded reason codes, and timing. Raw prompts, responses, tool arguments, credentials, and secrets are prohibited.",
  redacted_content:
    "Everything metadata_only permits, plus explicitly redacted diagnostic excerpts.",
  full_content:
    "An audited, time-bounded diagnostic setting. It never changes the normal event, audit, webhook, or log schemas, and the policy surface cannot persist it.",
};

const BACKUP_LIFECTIVE_EFFECT: Readonly<Record<BackupLifecycle, string>> = {
  platform_35_day_expiry:
    "Platform backups expire on their own lifecycle and are not selectively rewritten. A deletion propagates forward to future backups, not into ones already taken.",
  platform_no_backup:
    "This organization is not included in platform backups, so a deletion takes effect everywhere at once.",
};

const PROVIDER_DISCLOSURE_EFFECT: Readonly<Record<ProviderRetentionDisclosure, string>> = {
  external_policy:
    "An upstream provider's own retention policy governs what it holds. Lumi does not delete it and does not claim to.",
  linked_policy:
    "A provider policy is linked and its terms are shown alongside the linked policy document.",
};

/** `"1 day"` / `"2 days"` — the count is always part of the answer. */
function plural(count: number, singular: string, many?: string): string {
  return `${count} ${count === 1 ? singular : (many ?? `${singular}s`)}`;
}

function humanizeSeconds(seconds: number): string {
  if (seconds % 86400 === 0 && seconds >= 86400) return plural(seconds / 86400, "day");
  if (seconds % 3600 === 0 && seconds >= 3600) return plural(seconds / 3600, "hour");
  if (seconds % 60 === 0 && seconds >= 60) return plural(seconds / 60, "minute");
  return plural(seconds, "second");
}

export function DataControls({ policy }: { policy: DataGovernancePolicy }) {
  const overrideCount = Object.keys(policy.class_retention_overrides).length;

  return (
    <Surface ariaLabel="Data controls">
      <SurfaceHeader
        eyebrow="PLATFORM CONTROLS IN EFFECT"
        title="Data controls"
        description="What the platform is doing right now, independently of any per-class retention window. Read-only: these are changed on the Retention policies tab, which is where the editor lives."
        action={
          <Pill tone={policy.legal_hold ? "warning" : "neutral"}>
            {policy.legal_hold ? "Legal hold active" : "No legal hold"}
          </Pill>
        }
      />

      <div className="space-y-4 p-5">
        <DataTable
          caption="Platform-level data controls and their effect"
          headers={["Control", "In effect", "What it means"]}
        >
          <tr className="border-b border-[var(--border)] last:border-b-0">
            <TableCell header="Control">
              <span className="block font-medium text-[var(--civic-navy)]">Logging mode</span>
              <code className="mt-0.5 block font-mono text-xs text-[var(--muted)]">
                {policy.logging_mode}
              </code>
            </TableCell>
            <TableCell header="In effect">
              <Pill tone={policy.logging_mode === "metadata_only" ? "success" : "warning"}>
                {policy.logging_mode === "metadata_only" ? "Frozen default" : "Content permitted"}
              </Pill>
            </TableCell>
            <TableCell header="What it means">{LOGGING_MODE_EFFECT[policy.logging_mode]}</TableCell>
          </tr>

          <tr className="border-b border-[var(--border)] last:border-b-0">
            <TableCell header="Control">
              <span className="block font-medium text-[var(--civic-navy)]">Legal hold</span>
              <code className="mt-0.5 block font-mono text-xs text-[var(--muted)]">legal_hold</code>
            </TableCell>
            <TableCell header="In effect">
              <Pill tone={policy.legal_hold ? "danger" : "success"}>
                {policy.legal_hold ? "Suspending expiry" : "Not holding"}
              </Pill>
            </TableCell>
            <TableCell header="What it means">
              {policy.legal_hold ? (
                <>
                  Placed {policy.legal_hold_placed_at ?? "at an unrecorded time"}
                  {policy.legal_hold_reason ? ` — ${policy.legal_hold_reason}` : ""}. While it is
                  active, no window expires and no deletion proceeds for the classes it covers. Only
                  an audited release lifts it
                  {policy.legal_hold_released_at
                    ? `; one was recorded at ${policy.legal_hold_released_at} by ${policy.legal_hold_released_by ?? "an unrecorded principal"}.`
                    : "."}
                </>
              ) : (
                <>
                  Nothing is held. {plural(overrideCount, "class", "classes")}{" "}
                  {overrideCount === 1 ? "carries" : "carry"} a policy-specific window; the rest
                  keep the frozen baseline.
                </>
              )}
            </TableCell>
          </tr>

          <tr className="border-b border-[var(--border)] last:border-b-0">
            <TableCell header="Control">
              <span className="block font-medium text-[var(--civic-navy)]">Backup lifecycle</span>
              <code className="mt-0.5 block font-mono text-xs text-[var(--muted)]">
                {policy.backup_lifecycle}
              </code>
            </TableCell>
            <TableCell header="In effect">
              <Pill>
                {policy.backup_lifecycle === "platform_no_backup"
                  ? "Not backed up"
                  : "35-day expiry"}
              </Pill>
            </TableCell>
            <TableCell header="What it means">
              {BACKUP_LIFECTIVE_EFFECT[policy.backup_lifecycle]}
            </TableCell>
          </tr>

          <tr className="border-b border-[var(--border)] last:border-b-0">
            <TableCell header="Control">
              <span className="block font-medium text-[var(--civic-navy)]">
                Export artifact lifetime
              </span>
              <code className="mt-0.5 block font-mono text-xs text-[var(--muted)]">
                default_export_expiry_seconds
              </code>
            </TableCell>
            <TableCell header="In effect">
              <Pill tone="info">{humanizeSeconds(policy.default_export_expiry_seconds)}</Pill>
            </TableCell>
            <TableCell header="What it means">
              How long a finished export stays reachable. The download link is minted per request
              and bound to the job, the snapshot cutoff, and this expiry — it is never a permanent
              public URL, and the artifact itself is encrypted and access-controlled.
            </TableCell>
          </tr>

          <tr className="border-b border-[var(--border)] last:border-b-0">
            <TableCell header="Control">
              <span className="block font-medium text-[var(--civic-navy)]">
                Upstream provider retention
              </span>
              <code className="mt-0.5 block font-mono text-xs text-[var(--muted)]">
                {policy.provider_retention_disclosure}
              </code>
            </TableCell>
            <TableCell header="In effect">
              <Pill tone="warning">Not Lumi's to delete</Pill>
            </TableCell>
            <TableCell header="What it means">
              {PROVIDER_DISCLOSURE_EFFECT[policy.provider_retention_disclosure]}
              {policy.provider_retention_url ? (
                <>
                  {" "}
                  <a
                    href={policy.provider_retention_url}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="font-medium text-[var(--lumi-blue)] underline underline-offset-2 outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]"
                  >
                    Read the provider's policy
                  </a>
                </>
              ) : null}
            </TableCell>
          </tr>
        </DataTable>

        <Notice tone="info">
          <p className="font-semibold">These controls never widen a frozen limit.</p>
          <p className="mt-1">
            A policy may shorten a retention window, never extend one past its legal maximum, and
            the overrides above are the complete set. Nothing on this page authorizes a request,
            starts a deletion, or changes who can see this organization.
          </p>
        </Notice>
      </div>
    </Surface>
  );
}
