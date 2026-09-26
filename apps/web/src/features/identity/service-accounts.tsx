/**
 * Service accounts — the list, the create form with permission preview, and the
 * suspend/resume transitions.
 *
 * F14-001 is the reason this surface is shaped the way it is: a service account
 * has an explicit capability set, never a role and never an implicit inheritance
 * from whoever created it. A reader who cannot see the whole scope on the row
 * cannot audit it later, so the capability count and a sample of the names are on
 * the row, and the full set is on the detail surface.
 */

import { useState } from "react";

import type { ServiceAccount } from "./api";
import {
  AccountScopeSummary,
  CapabilityPicker,
  CapabilityPreview,
  HumanOnlyNotice,
} from "./capability-picker";
import { normalizeCapabilities, unknownCapabilities } from "./capabilities";
import { MAX_ACTIVE_SERVICE_ACCOUNTS_PER_ORG } from "./api";
import type { IdentityPermissions } from "./permissions";
import {
  EmptyState,
  ErrorNotice,
  LoadingRows,
  Metadata,
  Notice,
  PaginationFooter,
  Pill,
  StatusDot,
  Surface,
  SurfaceHeader,
  dangerButtonClass,
  ghostButtonClass,
  inputClass,
  primaryButtonClass,
  secondaryButtonClass,
  selectedButtonClass,
  type Tone,
} from "./ui";

export function serviceAccountStatusTone(status: ServiceAccount["status"]): Tone {
  return status === "active" ? "success" : "warning";
}

export function serviceAccountStatusLabel(status: ServiceAccount["status"]): string {
  return status === "active" ? "Active" : "Suspended";
}

/** The operational consequence of each state, in the reviewer's terms. */
export function serviceAccountStatusDetail(account: ServiceAccount): string {
  if (account.status === "suspended") {
    return account.suspend_reason
      ? `Every key on this account is denied, whatever its scope or expiry. Recorded reason: ${account.suspend_reason}`
      : "Every key on this account is denied, whatever its scope or expiry.";
  }
  return "Keys on this account authenticate and are limited to the capabilities listed below.";
}

export function ServiceAccountTable({
  accounts,
  status,
  error,
  hasMore,
  selectedId,
  canManage,
  onSelect,
  onRetry,
  onLoadMore,
}: {
  accounts: readonly ServiceAccount[];
  status: "loading" | "refreshing" | "ready" | "error";
  error: unknown;
  hasMore: boolean;
  selectedId: string | null;
  canManage: boolean;
  onSelect: (id: string) => void;
  onRetry: () => void;
  onLoadMore: () => void;
}) {
  if (status === "loading") {
    return (
      <Surface ariaLabel="Loading service accounts">
        <LoadingRows label="Loading service accounts…" rows={3} />
      </Surface>
    );
  }
  if (status === "error" && accounts.length === 0) {
    return (
      <Surface ariaLabel="Service accounts unavailable">
        <div className="p-5">
          <ErrorNotice error={error} title="Service accounts are unavailable" onRetry={onRetry} />
        </div>
      </Surface>
    );
  }
  if (accounts.length === 0) {
    return (
      <Surface ariaLabel="No service accounts">
        <EmptyState
          title="No service accounts"
          copy="This organization has no machine identity. Create one to let CI, an integration, or a managed runner call the control plane without borrowing a person's session."
        />
      </Surface>
    );
  }

  return (
    <Surface ariaLabel="Service accounts">
      <SurfaceHeader
        eyebrow="Machine identity"
        title="Service accounts"
        description="A service account is a non-human account with an explicit capability set. It never has a membership role and never inherits the permissions of whoever created it."
        action={
          <span className="text-xs text-[var(--muted)]">
            {accounts.length} loaded · {MAX_ACTIVE_SERVICE_ACCOUNTS_PER_ORG} active accounts maximum
          </span>
        }
      />
      {error ? (
        <div className="border-b border-[var(--danger)]/20 bg-[var(--danger)]/5 px-5 py-3">
          <ErrorNotice error={error} title="Refreshing service accounts failed" onRetry={onRetry} />
        </div>
      ) : null}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[900px] text-left text-sm">
          <caption className="sr-only">Service accounts in this organization</caption>
          <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
            <tr>
              <th scope="col" className="px-5 py-3 font-medium">
                Account
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Status
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Capabilities
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Created by
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Updated
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                <span className="sr-only">Action</span>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border)]">
            {accounts.map((account) => {
              const selected = account.id === selectedId;
              const unknown = unknownCapabilities(account.capabilities);
              return (
                <tr key={account.id}>
                  <th scope="row" className="px-5 py-4 text-left font-normal">
                    <span className="block font-medium text-[var(--civic-navy)]">
                      {account.name}
                    </span>
                    {account.description ? (
                      <span className="mt-0.5 block max-w-[22rem] text-xs leading-5 text-[var(--muted-strong)]">
                        {account.description}
                      </span>
                    ) : null}
                    <span className="mt-1 block font-mono text-xs text-[var(--muted)]">
                      {account.id}
                    </span>
                  </th>
                  <td className="px-5 py-4 align-top">
                    <Pill tone={serviceAccountStatusTone(account.status)}>
                      <StatusDot tone={serviceAccountStatusTone(account.status)} />
                      {serviceAccountStatusLabel(account.status)}
                    </Pill>
                    {account.status === "suspended" ? (
                      <span className="mt-1 block max-w-[14rem] text-xs leading-5 text-[var(--muted-strong)]">
                        {account.suspend_reason ?? "Reason not recorded on this projection."}
                      </span>
                    ) : null}
                  </td>
                  <td className="px-5 py-4 align-top">
                    <AccountScopeSummary account={account} />
                    {unknown.length > 0 ? (
                      <p className="mt-1 text-xs text-[var(--warning)]">
                        {unknown.length} capability {unknown.length === 1 ? "is" : "are"} not
                        recognised by this control plane.
                      </p>
                    ) : null}
                  </td>
                  <td className="px-5 py-4 align-top">
                    <span className="block max-w-[14rem] truncate font-mono text-xs text-[var(--muted-strong)]">
                      {account.created_by_principal_id}
                    </span>
                    <span className="mt-0.5 block text-xs text-[var(--muted)]">
                      {new Date(account.created_at).toLocaleDateString()}
                    </span>
                  </td>
                  <td className="px-5 py-4 align-top text-xs tabular-nums text-[var(--muted-strong)]">
                    {new Date(account.updated_at).toLocaleDateString()}
                  </td>
                  <td className="px-5 py-4 align-top">
                    <button
                      type="button"
                      className={selected ? selectedButtonClass : ghostButtonClass}
                      onClick={() => onSelect(account.id)}
                      aria-pressed={selected}
                    >
                      {selected ? "Selected" : "View"}
                    </button>
                    {!canManage ? (
                      <span className="sr-only">
                        Changing this account requires administrator access
                      </span>
                    ) : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <PaginationFooter
        loaded={accounts.length}
        hasMore={hasMore}
        loading={status === "refreshing"}
        onLoadMore={onLoadMore}
        noun="account"
        limitNote={`${MAX_ACTIVE_SERVICE_ACCOUNTS_PER_ORG} active maximum`}
      />
    </Surface>
  );
}

export function ServiceAccountDetail({
  account,
  sectionRef,
  permissions,
  busyAction,
  onSuspend,
  onResume,
}: {
  account: ServiceAccount;
  sectionRef: React.RefObject<HTMLDivElement | null>;
  permissions: IdentityPermissions;
  busyAction: string | null;
  onSuspend: () => void;
  onResume: () => void;
}) {
  const suspended = account.status === "suspended";
  const unknown = unknownCapabilities(account.capabilities);

  return (
    <Surface ariaLabel="Selected service account">
      <div ref={sectionRef} tabIndex={-1} className="outline-none">
        <SurfaceHeader
          eyebrow="Service account"
          title={account.name}
          description={serviceAccountStatusDetail(account)}
          action={
            permissions.canManage ? (
              suspended ? (
                <button
                  type="button"
                  className={primaryButtonClass}
                  onClick={onResume}
                  disabled={busyAction !== null}
                >
                  {busyAction === "resume" ? "Resuming…" : "Resume account"}
                </button>
              ) : (
                <button
                  type="button"
                  className={dangerButtonClass}
                  onClick={onSuspend}
                  disabled={busyAction !== null}
                >
                  {busyAction === "suspend" ? "Suspending…" : "Suspend account"}
                </button>
              )
            ) : null
          }
        />

        {suspended ? (
          <div className="border-b border-[var(--warning)]/40 bg-[var(--warning)]/10 px-5 py-4">
            <p className="text-[11px] font-semibold tracking-[0.08em] text-[var(--civic-navy)] uppercase">
              Suspended
            </p>
            <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--civic-navy)]">
              Suspension is the off-switch for this account and everything on it. Every key is
              denied with <code className="font-mono">machine_key_suspended</code>, including a key
              that has not expired. Runs already in flight finish under the policy they started
              with; new invocations are refused. Resuming restores exactly the scope below — it does
              not re-issue or reveal any key.
            </p>
          </div>
        ) : null}

        <dl className="grid gap-x-6 gap-y-5 p-5 sm:grid-cols-2 lg:grid-cols-3">
          <Metadata label="Account ID" value={account.id} mono />
          <Metadata label="Version" value={`v${account.version}`} />
          <Metadata label="Description" value={account.description ?? "Not set"} />
          <Metadata label="Created by" value={account.created_by_principal_id} mono />
          <Metadata label="Created" value={new Date(account.created_at).toLocaleString()} />
          <Metadata label="Updated" value={new Date(account.updated_at).toLocaleString()} />
          <Metadata
            label="Expiry"
            value={account.expires_at ? new Date(account.expires_at).toLocaleString() : "No expiry"}
          />
          <Metadata
            label="Suspended at"
            value={account.suspended_at ? new Date(account.suspended_at).toLocaleString() : "Never"}
          />
          <Metadata label="Suspend reason" value={account.suspend_reason ?? "None recorded"} />
        </dl>

        <div className="border-t border-[var(--border)] px-5 py-4">
          <p className="text-sm font-semibold text-[var(--civic-navy)]">
            Capabilities ({account.capabilities.length})
          </p>
          <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--muted-strong)]">
            This is the whole authority of the account and of every key on it. A key may hold a
            subset of this list and nothing outside it.
          </p>
          {account.capabilities.length === 0 ? (
            <p className="mt-2 text-sm text-[var(--muted)]">
              No capability. Keys on this account authenticate and can do nothing.
            </p>
          ) : (
            <ul className="mt-2 flex flex-wrap gap-1.5">
              {account.capabilities.map((capability) => (
                <li
                  key={capability}
                  className={[
                    "rounded-md px-2 py-1 font-mono text-xs",
                    unknown.includes(capability)
                      ? "bg-[var(--warning)]/20 text-[var(--civic-navy)]"
                      : "bg-[var(--panel-strong)] text-[var(--muted-strong)]",
                  ].join(" ")}
                >
                  {capability}
                </li>
              ))}
            </ul>
          )}
          {unknown.length > 0 ? (
            <div className="mt-3">
              <Notice tone="warning" title="Unrecognised capability">
                {unknown.join(", ")} is granted but is not in the vocabulary this control plane can
                describe. It was accepted by the server, so it is shown rather than hidden, but it
                should be reviewed before you rely on this account.
              </Notice>
            </div>
          ) : null}
        </div>

        <div className="border-t border-[var(--border)] bg-[var(--panel-hover)] px-5 py-3 text-xs leading-5 text-[var(--muted-strong)]">
          A service account is created by, and attributable to, a human principal. A machine
          credential cannot create another one. The API is authoritative for permission, membership,
          and organization state; this view never displays a key secret.
        </div>
      </div>
    </Surface>
  );
}

export function CreateServiceAccountForm({
  busy,
  error,
  onSubmit,
  onCancel,
}: {
  busy: boolean;
  error: unknown;
  onSubmit: (input: { name: string; description: string | null; capabilities: string[] }) => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [capabilities, setCapabilities] = useState<string[]>([]);

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit({
          name: name.trim(),
          description: description.trim() === "" ? null : description.trim(),
          capabilities: normalizeCapabilities(capabilities),
        });
      }}
      className="space-y-5 p-5"
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <label
            htmlFor="identity-sa-name"
            className="block text-sm font-medium text-[var(--civic-navy)]"
          >
            Name
          </label>
          <input
            id="identity-sa-name"
            required
            maxLength={120}
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="Release pipeline"
            className={inputClass}
          />
        </div>
        <div>
          <label
            htmlFor="identity-sa-description"
            className="block text-sm font-medium text-[var(--civic-navy)]"
          >
            Description <span className="font-normal text-[var(--muted)]">(optional)</span>
          </label>
          <input
            id="identity-sa-description"
            maxLength={500}
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            placeholder="Publishes releases on merge to main"
            className={inputClass}
          />
        </div>
      </div>

      <div>
        <p className="text-sm font-semibold text-[var(--civic-navy)]">Capabilities</p>
        <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--muted-strong)]">
          Choose the narrowest set the job needs. There is no wildcard, and a capability is never
          inherited from the person creating the account.
        </p>
        <div className="mt-3 max-h-[26rem] overflow-y-auto rounded-lg border border-[var(--border)]">
          <div className="p-3">
            <CapabilityPicker selected={capabilities} onChange={setCapabilities} />
          </div>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <CapabilityPreview
          kind="service_account"
          subject="this service account"
          selected={capabilities}
        />
        <HumanOnlyNotice />
      </div>

      {error ? <ErrorNotice error={error} title="The service account was not created" /> : null}

      <div className="flex flex-col gap-2 sm:flex-row sm:justify-end">
        <button type="button" className={secondaryButtonClass} onClick={onCancel} disabled={busy}>
          Cancel
        </button>
        <button
          type="submit"
          className={primaryButtonClass}
          disabled={busy || name.trim().length === 0 || capabilities.length === 0}
        >
          {busy ? "Creating…" : "Create service account"}
        </button>
      </div>
      {capabilities.length === 0 ? (
        <p className="text-right text-xs text-[var(--muted)]">
          A service account needs at least one capability. An account with none can authenticate and
          do nothing.
        </p>
      ) : null}
    </form>
  );
}
