/**
 * The installed-plugins and catalog lists, plus the organization policy summary.
 *
 * F25 Web UX: "installed plugins", "available/approved catalog", "blocked reason".
 *
 * The list is a table rather than a card grid because the information an operator
 * needs per row is comparative — state, version, review, pin, blocked reason — and
 * `docs/screens/lumi_rate_limits.webp` is the reference for exactly this shape:
 * a dense table with a status pill, a notes column, and a row action. A card per
 * package would make scanning eight rows of state eight separate reading tasks.
 */

import type { PluginListItem, PluginPolicy } from "./api";
import {
  blockedReason,
  conflictExplanation,
  isConflicting,
  packagePolicyVerdict,
  pendingReviewReason,
  reviewStateDetail,
  reviewStateLabel,
  reviewStateTone,
} from "./contracts";
import {
  EmptyState,
  ErrorNotice,
  LoadingRows,
  Notice,
  Pill,
  StatusDot,
  Surface,
  SurfaceHeader,
  ghostButtonClass,
  selectedButtonClass,
} from "./ui";

export function PluginTable({
  items,
  policy,
  status,
  error,
  selectedId,
  onSelect,
  onRetry,
  emptyTitle,
  emptyCopy,
  installedOnly = true,
}: {
  items: readonly PluginListItem[];
  policy: PluginPolicy;
  status: "loading" | "refreshing" | "ready" | "error";
  error: unknown;
  selectedId: string | null;
  onSelect: (packageId: string) => void;
  onRetry: () => void;
  emptyTitle: string;
  emptyCopy: string;
  installedOnly?: boolean;
}) {
  if (status === "loading") {
    return (
      <Surface ariaLabel="Loading plugins">
        <LoadingRows label="Loading plugins…" rows={3} />
      </Surface>
    );
  }
  if (status === "error" && items.length === 0) {
    return (
      <Surface ariaLabel="Plugins unavailable">
        <div className="p-5">
          <ErrorNotice error={error} title="Plugins are unavailable" onRetry={onRetry} />
        </div>
      </Surface>
    );
  }
  if (items.length === 0) {
    return (
      <Surface ariaLabel="No plugins">
        <EmptyState title={emptyTitle} copy={emptyCopy} />
      </Surface>
    );
  }

  return (
    <Surface ariaLabel={installedOnly ? "Installed plugins" : "Plugin catalog"}>
      <SurfaceHeader
        eyebrow={installedOnly ? "Installed" : "Catalog"}
        title={installedOnly ? "Installed plugins" : "Available packages"}
        description={
          installedOnly
            ? "Package identity is stable and separate from display name and version, so renaming a plugin never orphans its install or its policy. Runs already in flight when a block or quarantine lands finish under the policy they started with; new executions are denied."
            : "Every package in the catalog with the publisher that signed it, and whether this organization's policy permits it. Policy decides, not the catalog order."
        }
        action={
          <span className="text-xs text-[var(--muted)]">
            {items.length} {installedOnly ? "installed" : "in catalog"}
          </span>
        }
      />
      {error ? (
        <div className="border-b border-[var(--danger)]/20 bg-[var(--danger)]/5 px-5 py-3">
          <ErrorNotice error={error} title="Refreshing plugins failed" onRetry={onRetry} />
        </div>
      ) : null}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[940px] text-left text-sm">
          <caption className="sr-only">
            {installedOnly
              ? "Plugins installed in this organization"
              : "Plugins available to this organization"}
          </caption>
          <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
            <tr>
              <th scope="col" className="px-5 py-3 font-medium">
                Package
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Version
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Review state
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Policy
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Notes
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                <span className="sr-only">Action</span>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border)]">
            {items.map((item) => {
              const selected = item.package.package_id === selectedId;
              const verdict = packagePolicyVerdict(item, policy);
              const conflict = isConflicting(policy, item.package.package_id);
              const reason = blockedReason(item);
              return (
                <tr key={item.package.package_id}>
                  <th scope="row" className="px-5 py-4 text-left font-normal">
                    <span className="block font-medium text-[var(--civic-navy)]">
                      {item.package.display_name}
                    </span>
                    <span className="mt-0.5 block max-w-[24rem] text-xs leading-5 text-[var(--muted-strong)]">
                      {item.package.summary}
                    </span>
                    <span className="mt-1 block font-mono text-xs text-[var(--muted)]">
                      {item.package.package_id}
                    </span>
                  </th>
                  <td className="px-5 py-4 align-top">
                    <span className="block font-mono text-xs text-[var(--civic-navy)]">
                      {item.install?.version ?? "Not installed"}
                    </span>
                    {item.pinned_version ? (
                      <span className="mt-1 block text-xs text-[var(--warning)]">
                        Pinned to {item.pinned_version}
                      </span>
                    ) : null}
                    {item.install?.pending_review_version ? (
                      <span className="mt-1 block text-xs text-[var(--warning)]">
                        {item.install.pending_review_version} awaiting review
                      </span>
                    ) : null}
                  </td>
                  <td className="px-5 py-4 align-top">
                    {item.install ? (
                      <>
                        <Pill tone={reviewStateTone(item.install.review_state)}>
                          <StatusDot tone={reviewStateTone(item.install.review_state)} />
                          {reviewStateLabel(item.install.review_state)}
                        </Pill>
                        {item.install.review_state === "pending_review" ? (
                          <span className="mt-1 block max-w-[16rem] text-xs leading-5 text-[var(--muted-strong)]">
                            {pendingReviewReason(item.install)}
                          </span>
                        ) : null}
                      </>
                    ) : (
                      <Pill tone="neutral">
                        <StatusDot tone="neutral" />
                        Catalog
                      </Pill>
                    )}
                  </td>
                  <td className="px-5 py-4 align-top">
                    <Pill tone={verdict.tone}>
                      <StatusDot tone={verdict.tone} />
                      {verdict.label}
                    </Pill>
                    {conflict ? (
                      <span className="mt-1 block max-w-[16rem] text-xs leading-5 text-[var(--danger)]">
                        {conflictExplanation(policy, item.package.package_id)}
                      </span>
                    ) : null}
                  </td>
                  <td className="px-5 py-4 align-top text-xs leading-5 text-[var(--muted-strong)]">
                    {item.quarantined ? (
                      <span className="block text-[var(--danger)]">
                        Quarantined at {item.install?.version ?? "this version"} by the platform.
                        New executions are denied even if the files are on disk.
                      </span>
                    ) : reason ? (
                      <span className="block">{reason}</span>
                    ) : item.install ? (
                      reviewStateDetail(item.install)
                    ) : (
                      <span className="text-[var(--muted)]">{verdict.detail}</span>
                    )}
                  </td>
                  <td className="px-5 py-4 align-top">
                    <button
                      type="button"
                      className={selected ? selectedButtonClass : ghostButtonClass}
                      onClick={() => onSelect(item.package.package_id)}
                      aria-pressed={selected}
                    >
                      {selected ? "Selected" : "View"}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Surface>
  );
}

/**
 * The organization plugin policy.
 *
 * The conflict list is its own block, above everything else, and it is never
 * folded into a summary line. A policy that contradicts itself is the one state on
 * this page where "the server will figure it out" is not an acceptable answer, and
 * an operator who has to spot a contradiction in a table of packages will
 * sometimes not.
 */
export function PolicySummary({ policy }: { policy: PluginPolicy }) {
  const conflicts = policy.conflicts;
  return (
    <Surface ariaLabel="Plugin policy">
      <SurfaceHeader
        eyebrow="Organization policy"
        title="What this organization permits"
        description="A customer control, not a platform one. Platform quarantine is separate and is not reachable from here, so nothing on this page can override it."
      />
      {conflicts.length > 0 ? (
        <div
          role="alert"
          className="border-b border-[var(--danger)]/40 border-l-[3px] border-l-[var(--danger)] bg-[var(--danger)]/5 px-5 py-4"
        >
          <p className="text-[11px] font-semibold tracking-[0.1em] text-[var(--danger)] uppercase">
            Policy conflict ({conflicts.length})
          </p>
          <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--civic-navy)]">
            {conflicts.length === 1 ? "This package is" : "These packages are"} on both the allow
            list and the block list. Blocked wins, so{" "}
            {conflicts.length === 1 ? "it is" : "they are"} denied — and nothing silently removed
            one of the two entries, because guessing which one you meant is how a supply-chain
            control quietly stops being one.
          </p>
          <ul className="mt-2 flex flex-wrap gap-1.5">
            {conflicts.map((packageId) => (
              <li
                key={packageId}
                className="rounded-md bg-[var(--panel)] px-2 py-1 font-mono text-xs text-[var(--danger)]"
              >
                {packageId}
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-[var(--muted)]">
            Remove the entry you did not intend. Until then the effective decision is “blocked”.
          </p>
        </div>
      ) : null}
      <dl className="grid gap-x-6 gap-y-5 p-5 sm:grid-cols-2 lg:grid-cols-3">
        <div>
          <dt className="text-xs font-medium text-[var(--muted)]">Publisher mode</dt>
          <dd className="mt-1 text-sm text-[var(--civic-navy)]">{publisherModeLabel(policy)}</dd>
        </div>
        <div>
          <dt className="text-xs font-medium text-[var(--muted)]">Update mode</dt>
          <dd className="mt-1 text-sm text-[var(--civic-navy)]">{updateModeLabel(policy)}</dd>
        </div>
        <div>
          <dt className="text-xs font-medium text-[var(--muted)]">Auto update</dt>
          <dd className="mt-1 text-sm text-[var(--civic-navy)]">
            {policy.auto_update ? "On" : "Off"}
          </dd>
        </div>
        <div>
          <dt className="text-xs font-medium text-[var(--muted)]">Policy version</dt>
          <dd className="mt-1 text-sm text-[var(--civic-navy)]">v{policy.version}</dd>
        </div>
        <PolicyList term="Approved publishers" values={policy.approved_publishers} />
        <PolicyList term="Explicitly allowed" values={policy.allowed_packages} />
        <PolicyList term="Blocked" values={policy.blocked_packages} />
        <div>
          <dt className="text-xs font-medium text-[var(--muted)]">Pinned versions</dt>
          <dd className="mt-1 text-sm text-[var(--civic-navy)]">
            {Object.keys(policy.pinned_versions).length === 0
              ? "None"
              : Object.entries(policy.pinned_versions)
                  .map(([packageId, version]) => `${packageId} @ ${version}`)
                  .join(", ")}
          </dd>
        </div>
      </dl>
      {policy.update_mode === "managed" ? (
        <div className="px-5 pb-5">
          <Notice tone="info" title="Managed mode">
            An update that widens a plugin's declared capability is refused and held for approval.
            It does not install and wait quietly; nothing about the new version runs. An update that
            only reduces capability installs without a second review.
          </Notice>
        </div>
      ) : (
        <div className="px-5 pb-5">
          <Notice tone="warning" title="Direct mode">
            Auto update is permitted and an expansion is not held for review — it is applied and
            audited. If you want expanding updates stopped before they install, change the update
            mode to managed.
          </Notice>
        </div>
      )}
    </Surface>
  );
}

function publisherModeLabel(policy: PluginPolicy): string {
  switch (policy.publisher_mode) {
    case "official_only":
      return "Official publishers only";
    case "approved_publishers":
      return "Approved publisher list";
    case "any":
      return "Any publisher";
  }
}

function updateModeLabel(policy: PluginPolicy): string {
  return policy.update_mode === "managed"
    ? "Managed — expanding updates need approval"
    : "Direct — updates apply";
}

function PolicyList({ term, values }: { term: string; values: readonly string[] }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-medium text-[var(--muted)]">
        {term} ({values.length})
      </dt>
      <dd className="mt-1 text-sm text-[var(--civic-navy)]">
        {values.length === 0 ? (
          <span className="text-[var(--muted)]">None</span>
        ) : (
          <ul className="flex flex-wrap gap-1.5">
            {values.map((value) => (
              <li
                key={value}
                className="rounded-md bg-[var(--panel-strong)] px-2 py-1 font-mono text-xs text-[var(--muted-strong)]"
              >
                {value}
              </li>
            ))}
          </ul>
        )}
      </dd>
    </div>
  );
}
