/**
 * The selected plugin's detail surface: versions, review state, registered and
 * unregistered tools, the permission diff for a candidate, and the approve, pin,
 * block, and unblock controls.
 *
 * Registered vs unregistered tools is the part worth calling out. F25-007: a tool
 * is usable only when a `PluginToolRegistration` exists for
 * `(package_id, version, tool_id)`. A tool the version declares but the
 * organization never registered is **denied** with `plugin_tool_unregistered` —
 * F13's default-deny, and the specific control an install can no longer bypass.
 * An operator who cannot see the denied tools will believe the plugin is fully
 * available when it is not, so they are listed with their denial reason rather
 * than filtered out.
 */

import { useId, useState } from "react";

import type { PluginDetail, PluginListItem, PluginPermissionDiff, PluginPolicy } from "./api";
import {
  PIN_NOTE,
  canPin,
  packagePolicyVerdict,
  pendingReviewReason,
  reviewStateLabel,
  toolRegistrations,
  unusableToolCount,
  usableToolCount,
  blockedReason,
} from "./contracts";
import { PermissionDiffView } from "./permission-diff";
import {
  Metadata,
  Notice,
  Pill,
  StatusDot,
  Surface,
  SurfaceHeader,
  dangerButtonClass,
  ghostButtonClass,
  primaryButtonClass,
  secondaryButtonClass,
} from "./ui";

export function PluginDetailView({
  detail,
  item,
  policy,
  sectionRef,
  diff,
  diffStatus,
  diffError,
  canManage,
  busyAction,
  candidateVersion,
  onCandidateChange,
  onLoadDiff,
  onApprove,
  onPin,
  onBlock,
  onUnblock,
}: {
  detail: PluginDetail;
  item: PluginListItem | null;
  policy: PluginPolicy;
  sectionRef: React.RefObject<HTMLDivElement | null>;
  diff: PluginPermissionDiff | null;
  diffStatus: "idle" | "loading" | "ready" | "error";
  diffError: unknown;
  canManage: boolean;
  busyAction: string | null;
  candidateVersion: string;
  onCandidateChange: (version: string) => void;
  onLoadDiff: () => void;
  onApprove: () => void;
  onPin: (version: string) => void;
  onBlock: () => void;
  onUnblock: () => void;
}) {
  const verdict = item ? packagePolicyVerdict(item, policy) : null;
  const install = detail.install;
  const tools = toolRegistrations(install);
  const pending = item ? pendingReviewReason(item.install) : "";

  return (
    <Surface ariaLabel="Selected plugin">
      <div ref={sectionRef} tabIndex={-1} className="outline-none">
        <SurfaceHeader
          eyebrow="Plugin"
          title={detail.package.display_name}
          description={detail.package.summary}
          action={
            canManage && verdict ? (
              <div className="flex flex-wrap gap-2">
                {item?.blocked ? (
                  <button
                    type="button"
                    className={secondaryButtonClass}
                    onClick={onUnblock}
                    disabled={busyAction !== null}
                  >
                    {busyAction === "unblock" ? "Unblocking…" : "Unblock package"}
                  </button>
                ) : (
                  <button
                    type="button"
                    className={dangerButtonClass}
                    onClick={onBlock}
                    disabled={busyAction !== null}
                  >
                    {busyAction === "block" ? "Blocking…" : "Block package"}
                  </button>
                )}
              </div>
            ) : null
          }
        />

        {verdict ? (
          <div
            className={[
              "border-b px-5 py-4",
              verdict.tone === "danger"
                ? "border-[var(--danger)]/30 bg-[var(--danger)]/5"
                : verdict.tone === "warning"
                  ? "border-[var(--warning)]/40 bg-[var(--warning)]/10"
                  : "border-[var(--border)] bg-[var(--panel-hover)]",
            ].join(" ")}
          >
            <div className="flex flex-wrap items-center gap-2">
              <Pill tone={verdict.tone}>
                <StatusDot tone={verdict.tone} />
                {verdict.label}
              </Pill>
              {item?.blocked ? <Pill tone="danger">Blocked</Pill> : null}
              {item?.quarantined ? <Pill tone="danger">Quarantined</Pill> : null}
            </div>
            <p className="mt-1.5 max-w-3xl text-sm leading-5 text-[var(--civic-navy)]">
              {verdict.detail}
            </p>
          </div>
        ) : null}

        {pending ? (
          <div className="border-b border-[var(--warning)]/40 bg-[var(--warning)]/10 px-5 py-4">
            <p className="text-[11px] font-semibold tracking-[0.08em] text-[var(--civic-navy)] uppercase">
              Waiting for approval
            </p>
            <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--civic-navy)]">{pending}</p>
            {canManage ? (
              <button
                type="button"
                className={`${primaryButtonClass} mt-3`}
                onClick={onApprove}
                disabled={busyAction !== null}
              >
                {busyAction === "approve" ? "Approving…" : "Approve this version"}
              </button>
            ) : (
              <p className="mt-2 text-xs text-[var(--muted)]">
                Approving is an administrator action. A member can see that a version is waiting and
                why, which is the diagnostic half of the problem.
              </p>
            )}
          </div>
        ) : null}

        <dl className="grid gap-x-6 gap-y-5 p-5 sm:grid-cols-2 lg:grid-cols-3">
          <Metadata label="Package ID" value={detail.package.package_id} mono />
          <Metadata
            label="Publisher"
            value={
              detail.package.publisher_official
                ? `${detail.package.publisher_id} (official)`
                : detail.package.publisher_id
            }
            mono
          />
          <Metadata label="Package status" value={detail.package.status} />
          <Metadata label="Installed version" value={install?.version ?? "Not installed"} mono />
          <Metadata
            label="Review state"
            value={install ? reviewStateLabel(install.review_state) : "Not installed"}
          />
          <Metadata
            label="Approved by"
            value={install?.approved_by ?? "Never approved"}
            mono={install?.approved_by !== null && install?.approved_by !== undefined}
          />
          <Metadata
            label="Pin"
            value={item?.pinned_version ? `Pinned to ${item.pinned_version}` : "Not pinned"}
          />
          <Metadata label="Available versions" value={String(detail.versions.length)} />
          <Metadata
            label="Registered tools"
            value={`${usableToolCount(install)} usable · ${unusableToolCount(install)} denied`}
          />
        </dl>

        {install ? (
          <div className="border-t border-[var(--border)] px-5 py-4">
            <p className="text-sm font-semibold text-[var(--civic-navy)]">Tools ({tools.length})</p>
            <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--muted-strong)]">
              A tool is usable only when this organization registered it at this exact version.
              Anything the version declares but the organization did not register is denied —
              unknown and new tools default to denied, and an install cannot bypass that.
            </p>
            {unusableToolCount(install) > 0 ? (
              <div className="mt-3">
                <Notice
                  tone="warning"
                  title={`${unusableToolCount(install)} declared ${unusableToolCount(install) === 1 ? "tool is" : "tools are"} denied`}
                >
                  These appear in the plugin's manifest but have no registration for this
                  organization. Calls to them fail with{" "}
                  <code className="font-mono">plugin_tool_unregistered</code>. Register a tool
                  deliberately if you intend to use it.
                </Notice>
              </div>
            ) : null}
            {tools.length === 0 ? (
              <p className="mt-2 text-sm text-[var(--muted)]">
                This version declares no tools, so there is nothing to register.
              </p>
            ) : (
              <ul className="mt-2 divide-y divide-[var(--border)] rounded-lg border border-[var(--border)]">
                {tools.map((tool) => (
                  <li
                    key={tool.toolId}
                    data-usable={tool.usable ? "true" : "false"}
                    className="flex flex-wrap items-start justify-between gap-2 px-3 py-2.5"
                  >
                    <div className="min-w-0">
                      <p className="font-mono text-xs text-[var(--civic-navy)]">{tool.toolId}</p>
                      <p className="mt-0.5 text-xs leading-5 text-[var(--muted-strong)]">
                        {tool.detail}
                      </p>
                    </div>
                    <Pill tone={tool.usable ? "success" : "danger"}>
                      <StatusDot tone={tool.usable ? "success" : "danger"} />
                      {tool.usable ? "Usable" : "Denied"}
                    </Pill>
                  </li>
                ))}
              </ul>
            )}
          </div>
        ) : (
          <div className="border-t border-[var(--border)] px-5 py-4">
            <p className="text-sm font-semibold text-[var(--civic-navy)]">Not installed</p>
            <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--muted-strong)]">
              Installing third-party code is a supply-chain decision and needs a host agent to
              report the runtime version and the artifact digest. This control plane does not
              fabricate either: the reporting host does, and the server verifies both before
              anything is recorded.
            </p>
          </div>
        )}

        <VersionBlock
          detail={detail}
          policy={policy}
          canManage={canManage}
          busyAction={busyAction}
          candidateVersion={candidateVersion}
          onCandidateChange={onCandidateChange}
          onPin={onPin}
        />

        <PermissionDiffBlock
          fromVersion={
            install?.version ?? detail.versions[detail.versions.length - 1]?.version ?? ""
          }
          candidateVersion={candidateVersion}
          status={diffStatus}
          error={diffError}
          diff={diff}
          onLoad={onLoadDiff}
        />

        {item?.blocked ? (
          <div className="border-t border-[var(--danger)]/30 bg-[var(--danger)]/5 px-5 py-4">
            <p className="text-[11px] font-semibold tracking-[0.08em] text-[var(--danger)] uppercase">
              Blocked
            </p>
            <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--civic-navy)]">
              {blockedReason(item)}
            </p>
          </div>
        ) : null}

        <div className="border-t border-[var(--border)] bg-[var(--panel-hover)] px-5 py-3 text-xs leading-5 text-[var(--muted-strong)]">
          The server decides. A plugin's declared capability set, its integrity digest, its host
          compatibility, and its tool registrations are all resolved server-side, and a host report
          is evidence rather than authority. This view never renders a plugin's runtime output, and
          an on-disk artifact is irrelevant to a denial.
        </div>
      </div>
    </Surface>
  );
}

function VersionBlock({
  detail,
  policy,
  canManage,
  busyAction,
  candidateVersion,
  onCandidateChange,
  onPin,
}: {
  detail: PluginDetail;
  policy: PluginPolicy;
  canManage: boolean;
  busyAction: string | null;
  candidateVersion: string;
  onCandidateChange: (version: string) => void;
  onPin: (version: string) => void;
}) {
  const [candidate, setCandidate] = useState(candidateVersion);
  const id = useId();
  const pinBlocked = canPin(policy, detail.package.package_id);
  return (
    <div className="border-t border-[var(--border)] px-5 py-4">
      <p className="text-sm font-semibold text-[var(--civic-navy)]">
        Versions ({detail.versions.length})
      </p>
      <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--muted-strong)]">
        A published version is immutable. Changing what a version declares means publishing a new
        one, so a version you approved today is the version that keeps running.
      </p>
      <div className="mt-3 overflow-x-auto">
        <table className="w-full min-w-[620px] text-left text-sm">
          <caption className="sr-only">Published versions of this plugin</caption>
          <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
            <tr>
              <th scope="col" className="px-3 py-2 font-medium">
                Version
              </th>
              <th scope="col" className="px-3 py-2 font-medium">
                Host runtime
              </th>
              <th scope="col" className="px-3 py-2 font-medium">
                Content digest
              </th>
              <th scope="col" className="px-3 py-2 font-medium">
                Published
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border)]">
            {detail.versions.map((version) => (
              <tr key={version.version}>
                <th
                  scope="row"
                  className="px-3 py-2 text-left font-mono text-xs font-normal text-[var(--civic-navy)]"
                >
                  {version.version}
                </th>
                <td className="px-3 py-2 font-mono text-xs text-[var(--muted-strong)]">
                  {version.runtime_min} – {version.runtime_max}
                </td>
                <td className="px-3 py-2 font-mono text-xs break-all text-[var(--muted)]">
                  {version.content_digest}
                </td>
                <td className="px-3 py-2 text-xs tabular-nums text-[var(--muted-strong)]">
                  {new Date(version.published_at).toLocaleDateString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="mt-3">
        <Notice tone="info" title="Version pin">
          {PIN_NOTE}
        </Notice>
      </div>

      {canManage ? (
        <div className="mt-3 flex flex-wrap items-end gap-3">
          <div>
            <label htmlFor={id} className="block text-sm font-medium text-[var(--civic-navy)]">
              Pin this package to a version
            </label>
            <select
              id={id}
              value={candidate}
              onChange={(event) => {
                setCandidate(event.target.value);
                onCandidateChange(event.target.value);
              }}
              className="mt-1.5 min-h-11 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 text-sm outline-none focus-visible:border-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
            >
              {detail.versions.map((version) => (
                <option key={version.version} value={version.version}>
                  {version.version}
                </option>
              ))}
            </select>
          </div>
          <button
            type="button"
            className={ghostButtonClass}
            onClick={() => onPin(candidate)}
            disabled={busyAction !== null || pinBlocked !== null || candidate === ""}
            title={pinBlocked ?? undefined}
          >
            {busyAction === "pin" ? "Pinning…" : "Pin version"}
          </button>
        </div>
      ) : null}
      {pinBlocked ? (
        <p className="mt-2 text-xs leading-5 text-[var(--warning)]">{pinBlocked}</p>
      ) : null}
    </div>
  );
}

function PermissionDiffBlock({
  fromVersion,
  candidateVersion,
  status,
  error,
  diff,
  onLoad,
}: {
  fromVersion: string;
  candidateVersion: string;
  status: "idle" | "loading" | "ready" | "error";
  error: unknown;
  diff: PluginPermissionDiff | null;
  onLoad: () => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border-t border-[var(--border)] px-5 py-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-sm font-semibold text-[var(--civic-navy)]">Permission diff</p>
          <p className="mt-1 max-w-2xl text-sm leading-5 text-[var(--muted-strong)]">
            Compare the installed version with a candidate, class by class. Expansion in any class
            is expansion: a reduction elsewhere does not offset a gain here.
          </p>
        </div>
        <button
          type="button"
          className={ghostButtonClass}
          onClick={() => setOpen((value) => !value)}
          aria-expanded={open}
        >
          {open ? "Hide diff" : "Show diff"}
        </button>
      </div>
      {open ? (
        <div className="mt-3 space-y-3">
          <div className="flex flex-wrap items-center gap-2 text-xs text-[var(--muted)]">
            <span className="font-mono">
              {fromVersion || "not installed"} → {candidateVersion || "no version"}
            </span>
            <button
              type="button"
              className={secondaryButtonClass}
              onClick={onLoad}
              disabled={status === "loading" || candidateVersion === ""}
            >
              {status === "loading" ? "Loading…" : "Load permission diff"}
            </button>
          </div>
          {status === "error" ? <DiffError error={error} /> : null}
          {status === "ready" && diff ? <PermissionDiffView diff={diff} /> : null}
          {status === "idle" ? (
            <p className="text-xs text-[var(--muted)]">
              No diff loaded. Loading it is a read; approving the candidate is the separate action
              below.
            </p>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function DiffError({ error }: { error: unknown }) {
  return (
    <div
      role="alert"
      className="rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/5 p-3 text-sm"
    >
      <p className="font-semibold text-[var(--danger)]">The permission diff could not be read</p>
      <p className="mt-1 leading-5 text-[var(--civic-navy)]">
        Without the diff you cannot tell whether an update widens capability, so approving on the
        strength of the version number alone is not safe. Fix the read and look again.
      </p>
      <p className="mt-1 text-xs text-[var(--muted)]">
        {error instanceof Error ? error.message : "The request could not be completed."}
      </p>
    </div>
  );
}
