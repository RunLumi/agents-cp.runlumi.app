/**
 * API keys — the list, the create form, and the rotate/revoke transitions.
 *
 * F14-002: the secret is shown once, at creation, and never again. Everything on
 * this surface therefore works from metadata: the public `key_prefix`, the
 * `fingerprint`, the scope, and last-used time. The row deliberately has no
 * "reveal" affordance because there is nothing behind it to reveal.
 *
 * F14-005: `last_used_at` and a bounded `last_used_source` are recorded. The
 * source is a derived network prefix or device slug — never a request body, a
 * header bag, or a URL with a query string — and the copy below says so, because
 * "we record when a key was used" invites the question "and what did it send?".
 */

import { useState } from "react";

import { MAX_ACTIVE_KEYS_PER_ACCOUNT, type ApiKey, type ServiceAccount } from "./api";
import {
  CapabilityPicker,
  CapabilityPreview,
  KeyScopeSummary,
  HumanOnlyNotice,
} from "./capability-picker";
import { normalizeCapabilities } from "./capabilities";
import type { IdentityPermissions } from "./permissions";
import {
  EmptyState,
  ErrorNotice,
  ListField,
  LoadingRows,
  Metadata,
  Notice,
  PaginationFooter,
  Pill,
  SelectField,
  StatusDot,
  Surface,
  SurfaceHeader,
  TextField,
  dangerButtonClass,
  ghostButtonClass,
  parseListField,
  primaryButtonClass,
  secondaryButtonClass,
  selectedButtonClass,
  type Tone,
} from "./ui";

export function apiKeyStatusTone(status: ApiKey["status"]): Tone {
  if (status === "active") return "success";
  if (status === "expired") return "warning";
  return "neutral";
}

export function apiKeyStatusLabel(status: ApiKey["status"]): string {
  switch (status) {
    case "active":
      return "Active";
    case "revoked":
      return "Revoked";
    case "rotated":
      return "Rotated out";
    case "expired":
      return "Expired";
  }
}

/** `revoked` and `expired` are terminal; `rotated` is terminal too, by construction. */
export function isApiKeyTerminal(status: ApiKey["status"]): boolean {
  return status !== "active";
}

export function apiKeyStatusDetail(key: ApiKey): string {
  switch (key.status) {
    case "active":
      return "This key authenticates and is limited to the scope below.";
    case "revoked":
      return key.revoke_reason
        ? `Permanently refused. Recorded reason: ${key.revoke_reason}. There is no un-revoke; create a new key on the same account.`
        : "Permanently refused. There is no un-revoke; create a new key on the same account.";
    case "rotated":
      return "Replaced by a rotation. The prior key stops working once its replacement exists, and it cannot be rotated again.";
    case "expired":
      return "Past its expiry and refused regardless of scope. Create a new key with a later expiry.";
  }
}

export function apiKeyRotationBlockedReason(key: ApiKey): string | null {
  if (key.status === "active") return null;
  if (key.status === "revoked")
    return "A revoked key cannot be rotated. Create a new key on the account.";
  if (key.status === "expired")
    return "An expired key cannot be rotated. Create a new key on the account.";
  return "This key has already been rotated. Rotate the current key instead.";
}

export function ApiKeyTable({
  keys,
  status,
  error,
  hasMore,
  selectedId,
  onSelect,
  onRetry,
  onLoadMore,
}: {
  keys: readonly ApiKey[];
  status: "loading" | "refreshing" | "ready" | "error";
  error: unknown;
  hasMore: boolean;
  selectedId: string | null;
  onSelect: (id: string) => void;
  onRetry: () => void;
  onLoadMore: () => void;
}) {
  if (status === "loading") {
    return (
      <Surface ariaLabel="Loading API keys">
        <LoadingRows label="Loading API keys…" rows={3} />
      </Surface>
    );
  }
  if (status === "error" && keys.length === 0) {
    return (
      <Surface ariaLabel="API keys unavailable">
        <div className="p-5">
          <ErrorNotice error={error} title="API keys are unavailable" onRetry={onRetry} />
        </div>
      </Surface>
    );
  }
  if (keys.length === 0) {
    return (
      <Surface ariaLabel="No API keys">
        <EmptyState
          title="No API keys"
          copy="This organization has no API key. Create one on a service account to call the control plane from CI or a managed runner. The secret is shown once, at creation, and cannot be retrieved again."
        />
      </Surface>
    );
  }

  return (
    <Surface ariaLabel="API keys">
      <SurfaceHeader
        eyebrow="Credentials"
        title="API keys"
        description="The public prefix and the fingerprint identify a key without revealing it. The secret is hashed at rest and is not recoverable by anyone, including this page."
        action={
          <span className="text-xs text-[var(--muted)]">
            {keys.length} loaded · {MAX_ACTIVE_KEYS_PER_ACCOUNT} active keys per account
          </span>
        }
      />
      {error ? (
        <div className="border-b border-[var(--danger)]/20 bg-[var(--danger)]/5 px-5 py-3">
          <ErrorNotice error={error} title="Refreshing API keys failed" onRetry={onRetry} />
        </div>
      ) : null}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[980px] text-left text-sm">
          <caption className="sr-only">API keys in this organization</caption>
          <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
            <tr>
              <th scope="col" className="px-5 py-3 font-medium">
                Key
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Status
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Capabilities
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Last used
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Expiry
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                Created
              </th>
              <th scope="col" className="px-5 py-3 font-medium">
                <span className="sr-only">Action</span>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border)]">
            {keys.map((key) => {
              const selected = key.id === selectedId;
              return (
                <tr key={key.id}>
                  <th scope="row" className="px-5 py-4 text-left font-normal">
                    <span className="block font-medium text-[var(--civic-navy)]">{key.name}</span>
                    <span className="mt-1 block font-mono text-xs text-[var(--muted)]">
                      {key.key_prefix}…
                    </span>
                    <span className="mt-0.5 block font-mono text-xs text-[var(--muted)]">
                      fp {key.fingerprint}
                    </span>
                  </th>
                  <td className="px-5 py-4 align-top">
                    <Pill tone={apiKeyStatusTone(key.status)}>
                      <StatusDot tone={apiKeyStatusTone(key.status)} />
                      {apiKeyStatusLabel(key.status)}
                    </Pill>
                    {key.status === "revoked" && key.revoke_reason ? (
                      <span className="mt-1 block max-w-[14rem] text-xs leading-5 text-[var(--muted-strong)]">
                        {key.revoke_reason}
                      </span>
                    ) : null}
                  </td>
                  <td className="px-5 py-4 align-top">
                    <KeyScopeSummary apiKey={key} />
                  </td>
                  <td className="px-5 py-4 align-top text-xs text-[var(--muted-strong)]">
                    {key.last_used_at ? (
                      <>
                        <span className="block tabular-nums">
                          {new Date(key.last_used_at).toLocaleString()}
                        </span>
                        {key.last_used_source ? (
                          <span className="mt-0.5 block font-mono text-[var(--muted)]">
                            {key.last_used_source}
                          </span>
                        ) : null}
                      </>
                    ) : (
                      <span className="text-[var(--muted)]">Never used</span>
                    )}
                  </td>
                  <td className="px-5 py-4 align-top text-xs text-[var(--muted-strong)]">
                    {key.expires_at ? (
                      new Date(key.expires_at).toLocaleDateString()
                    ) : (
                      <span className="text-[var(--muted)]">No expiry</span>
                    )}
                  </td>
                  <td className="px-5 py-4 align-top text-xs tabular-nums text-[var(--muted-strong)]">
                    {new Date(key.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-5 py-4 align-top">
                    <button
                      type="button"
                      className={selected ? selectedButtonClass : ghostButtonClass}
                      onClick={() => onSelect(key.id)}
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
      <PaginationFooter
        loaded={keys.length}
        hasMore={hasMore}
        loading={status === "refreshing"}
        onLoadMore={onLoadMore}
        noun="key"
        limitNote={`${MAX_ACTIVE_KEYS_PER_ACCOUNT} active per account`}
      />
    </Surface>
  );
}

export function ApiKeyDetail({
  apiKey,
  account,
  sectionRef,
  permissions,
  busyAction,
  onRotate,
  onRevoke,
}: {
  apiKey: ApiKey;
  account: ServiceAccount | null;
  sectionRef: React.RefObject<HTMLDivElement | null>;
  permissions: IdentityPermissions;
  busyAction: string | null;
  onRotate: () => void;
  onRevoke: () => void;
}) {
  const rotationBlocked = apiKeyRotationBlockedReason(apiKey);

  return (
    <Surface ariaLabel="Selected API key">
      <div ref={sectionRef} tabIndex={-1} className="outline-none">
        <SurfaceHeader
          eyebrow="API key"
          title={apiKey.name}
          description={apiKeyStatusDetail(apiKey)}
          action={
            permissions.canManage ? (
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  className={secondaryButtonClass}
                  onClick={onRotate}
                  disabled={busyAction !== null || rotationBlocked !== null}
                  title={rotationBlocked ?? undefined}
                >
                  {busyAction === "rotate" ? "Rotating…" : "Rotate key"}
                </button>
                <button
                  type="button"
                  className={dangerButtonClass}
                  onClick={onRevoke}
                  disabled={busyAction !== null || apiKey.status !== "active"}
                >
                  {busyAction === "revoke" ? "Revoking…" : "Revoke key"}
                </button>
              </div>
            ) : null
          }
        />

        {apiKey.status === "active" ? (
          <div className="border-b border-[var(--border)] bg-[var(--panel-hover)] px-5 py-4">
            <p className="text-[11px] font-semibold tracking-[0.08em] text-[var(--muted-strong)] uppercase">
              Rotation creates an overlap
            </p>
            <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--civic-navy)]">
              Rotation creates the replacement first and only then marks this key
              <code className="font-mono"> rotated</code>. A failed rotation leaves both keys
              untouched, so a pipeline is never left with no working credential because a request
              half-succeeded. The replacement carries the same scope.
            </p>
          </div>
        ) : null}

        {rotationBlocked ? (
          <div className="border-b border-[var(--warning)]/40 bg-[var(--warning)]/10 px-5 py-4">
            <p className="text-[11px] font-semibold tracking-[0.08em] text-[var(--civic-navy)] uppercase">
              Terminal state
            </p>
            <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--civic-navy)]">
              {rotationBlocked}
            </p>
          </div>
        ) : null}

        <dl className="grid gap-x-6 gap-y-5 p-5 sm:grid-cols-2 lg:grid-cols-3">
          <Metadata label="Key ID" value={apiKey.id} mono />
          <Metadata label="Public prefix" value={`${apiKey.key_prefix}…`} mono />
          <Metadata label="Fingerprint" value={apiKey.fingerprint} mono />
          <Metadata
            label="Service account"
            value={account ? `${account.name} (${account.id})` : apiKey.service_account_id}
            mono={account === null}
          />
          <Metadata label="Version" value={`v${apiKey.version}`} />
          <Metadata label="Created" value={new Date(apiKey.created_at).toLocaleString()} />
          <Metadata
            label="Last used"
            value={apiKey.last_used_at ? new Date(apiKey.last_used_at).toLocaleString() : "Never"}
          />
          <Metadata
            label="Last used source"
            value={apiKey.last_used_source ?? "Not recorded"}
            mono
          />
          <Metadata
            label="Expiry"
            value={apiKey.expires_at ? new Date(apiKey.expires_at).toLocaleString() : "No expiry"}
          />
          <Metadata
            label="Revoked at"
            value={apiKey.revoked_at ? new Date(apiKey.revoked_at).toLocaleString() : "Never"}
          />
          <Metadata label="Revoke reason" value={apiKey.revoke_reason ?? "None recorded"} />
          <Metadata
            label="Rotated from"
            value={apiKey.rotated_from_key_id ?? "Not a rotation"}
            mono
          />
          <Metadata label="Rotated to" value={apiKey.rotated_to_key_id ?? "Not rotated"} mono />
        </dl>

        <div className="border-t border-[var(--border)] px-5 py-4">
          <p className="text-sm font-semibold text-[var(--civic-navy)]">
            Scope ({apiKey.capabilities.length}{" "}
            {apiKey.capabilities.length === 1 ? "capability" : "capabilities"})
          </p>
          <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--muted-strong)]">
            A key may hold only what its service account holds. A project-scoped key cannot reach
            another project inside this organization, and a network-restricted key is denied
            outright when the edge cannot report a caller address.
          </p>
          {apiKey.capabilities.length === 0 ? (
            <p className="mt-2 text-sm text-[var(--muted)]">
              No capability. This key authenticates and can do nothing.
            </p>
          ) : (
            <ul className="mt-2 flex flex-wrap gap-1.5">
              {apiKey.capabilities.map((capability) => (
                <li
                  key={capability}
                  className="rounded-md bg-[var(--panel-strong)] px-2 py-1 font-mono text-xs text-[var(--muted-strong)]"
                >
                  {capability}
                </li>
              ))}
            </ul>
          )}
        </div>

        <ScopeConstraints apiKey={apiKey} />

        <div className="border-t border-[var(--border)] bg-[var(--panel-hover)] px-5 py-3 text-xs leading-5 text-[var(--muted-strong)]">
          The secret is returned once, by create and by rotation, and is not stored in Lumi in any
          recoverable form. This page can show the prefix, the fingerprint, the scope, and when the
          key was last used — never the secret. A compromise of the key table alone yields no usable
          credential.
        </div>
      </div>
    </Surface>
  );
}

function ScopeConstraints({ apiKey }: { apiKey: ApiKey }) {
  return (
    <div className="border-t border-[var(--border)] px-5 py-4">
      <p className="text-sm font-semibold text-[var(--civic-navy)]">Restrictions</p>
      <div className="mt-2 space-y-3">
        <Constraint
          term="Projects"
          values={apiKey.project_ids}
          empty="No project restriction. Any project in this organization that the key is otherwise permitted to reach."
        />
        <Constraint
          term="Model aliases"
          values={apiKey.model_aliases}
          empty="No alias restriction. Any alias the key is otherwise permitted to use."
        />
        <Constraint
          term="Network allowlist"
          values={apiKey.network_allowlist}
          empty="No network restriction. Any caller address is accepted."
        />
      </div>
    </div>
  );
}

function Constraint({
  term,
  values,
  empty,
}: {
  term: string;
  values: readonly string[];
  empty: string;
}) {
  return (
    <div>
      <p className="text-xs font-medium text-[var(--muted)]">
        {term} {values.length > 0 ? `(${values.length})` : ""}
      </p>
      {values.length === 0 ? (
        <p className="mt-0.5 text-sm text-[var(--muted-strong)]">{empty}</p>
      ) : (
        <ul className="mt-1 flex flex-wrap gap-1.5">
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
    </div>
  );
}

export function CreateApiKeyForm({
  accounts,
  busy,
  error,
  onSubmit,
  onCancel,
}: {
  accounts: readonly ServiceAccount[];
  busy: boolean;
  error: unknown;
  onSubmit: (input: {
    service_account_id: string;
    name: string;
    capabilities: string[];
    project_ids: string[];
    model_aliases: string[];
    network_allowlist: string[];
  }) => void;
  onCancel: () => void;
}) {
  const [accountId, setAccountId] = useState(accounts[0]?.id ?? "");
  const [name, setName] = useState("");
  const [capabilities, setCapabilities] = useState<string[]>([]);
  const [projects, setProjects] = useState("");
  const [aliases, setAliases] = useState("");
  const [network, setNetwork] = useState("");
  const account = accounts.find((entry) => entry.id === accountId) ?? null;
  const suspended = account?.status === "suspended";

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit({
          service_account_id: accountId,
          name: name.trim(),
          capabilities: normalizeCapabilities(capabilities),
          project_ids: parseListField(projects),
          model_aliases: parseListField(aliases),
          network_allowlist: parseListField(network),
        });
      }}
      className="space-y-5 p-5"
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <SelectField
          label="Service account"
          value={accountId}
          onChange={(next) => {
            setAccountId(next);
            // A key cannot hold more than its account, so changing the account
            // invalidates anything outside the new account's set.
            setCapabilities((current) =>
              current.filter((entry) => account?.capabilities.includes(entry)),
            );
          }}
          disabled={busy || accounts.length === 0}
          hint={
            accounts.length === 0
              ? "This organization has no service account. Create one first."
              : "The key belongs to exactly one service account."
          }
        >
          {accounts.map((entry) => (
            <option key={entry.id} value={entry.id}>
              {entry.name}
              {entry.status === "suspended" ? " (suspended)" : ""}
            </option>
          ))}
        </SelectField>
        <TextField
          label="Key name"
          value={name}
          onChange={setName}
          placeholder="Release publisher"
          maxLength={120}
          required
          hint="How the operator will recognise this key in the list."
        />
      </div>

      {suspended ? (
        <Notice tone="warning" title="This service account is suspended">
          A key created on a suspended account authenticates and is then denied with{" "}
          <code className="font-mono">machine_key_suspended</code> on every request. Resume the
          account first, or choose a different one.
        </Notice>
      ) : null}

      <div>
        <p className="text-sm font-semibold text-[var(--civic-navy)]">Capabilities</p>
        <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--muted-strong)]">
          A key may hold only a subset of what its service account holds. Capabilities the account
          does not have are shown so the gap is visible rather than silently ignored.
        </p>
        <div className="mt-3 max-h-[26rem] overflow-y-auto rounded-lg border border-[var(--border)]">
          <div className="p-3">
            <CapabilityPicker
              selected={capabilities}
              onChange={setCapabilities}
              {...(account ? { inheritedFrom: account.capabilities } : {})}
            />
          </div>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <ListField
          label="Project IDs"
          value={projects}
          onChange={setProjects}
          placeholder="prj_1, prj_2"
          hint="Leave empty for no project restriction."
        />
        <ListField
          label="Model aliases"
          value={aliases}
          onChange={setAliases}
          placeholder="fast, quality"
          hint="Leave empty for no alias restriction."
        />
        <ListField
          label="Network allowlist"
          value={network}
          onChange={setNetwork}
          placeholder="203.0.113.0/24"
          hint="Fails closed when the edge cannot report a caller address."
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <CapabilityPreview
          kind="api_key"
          subject="this key"
          selected={capabilities}
          {...(account ? { available: account.capabilities } : {})}
          projectIds={parseListField(projects)}
          modelAliases={parseListField(aliases)}
          networkAllowlist={parseListField(network)}
          expiresAt={null}
        />
        <HumanOnlyNotice />
      </div>

      {error ? <ErrorNotice error={error} title="The key was not created" /> : null}

      <div className="flex flex-col gap-2 sm:flex-row sm:justify-end">
        <button type="button" className={secondaryButtonClass} onClick={onCancel} disabled={busy}>
          Cancel
        </button>
        <button
          type="submit"
          className={primaryButtonClass}
          disabled={
            busy || accountId === "" || name.trim().length === 0 || capabilities.length === 0
          }
        >
          {busy ? "Creating…" : "Create key and show secret"}
        </button>
      </div>
      <p className="text-right text-xs text-[var(--muted)]">
        The secret is shown once, in a dialog you must acknowledge. It is not recoverable
        afterwards.
      </p>
    </form>
  );
}
