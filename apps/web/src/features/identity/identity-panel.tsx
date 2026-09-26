/**
 * Identity & access — the organization settings sub-page (`settings/identity`).
 *
 * P07-CG §"Web information architecture" adds this as one of two P07 settings
 * sub-pages, beside `Plugins`, and adds no top-level nav item. It holds service
 * accounts and API keys, and nothing else: F06's human sign-in surface is frozen
 * and unimplemented, so reusing F22's "Security / Identity" name would promise an
 * SSO screen that does not exist.
 *
 * The section is two tabs rather than one long page because the two resources have
 * opposite shapes — an account is configured once and then rarely touched, while
 * a key is rotated and revoked repeatedly — and because a reader who came to
 * revoke one key should not have to scroll past the account list to find it.
 *
 * Load behaviour follows every other P07/P06 panel: one abortable load per
 * resource, a generation counter so a late response cannot overwrite a newer one,
 * a stale marker instead of a flash of empty, and a full reset on organization
 * change so another tenant's credentials are never on screen.
 */

import { useCallback, useEffect, useId, useRef, useState } from "react";

import {
  createApiKey,
  createServiceAccount,
  listApiKeys,
  listServiceAccounts,
  resumeServiceAccount,
  revokeApiKey,
  rotateApiKey,
  suspendServiceAccount,
  type ApiKey,
  type Page,
  type ServiceAccount,
} from "./api";
import { ApiKeyDetail, ApiKeyTable, CreateApiKeyForm, apiKeyStatusLabel } from "./api-keys";
import {
  IDENTITY_MANAGE_ONLY_COPY,
  IDENTITY_REFUSAL_COPY,
  identityPermissions,
  type IdentityPermissions,
  type MembershipRole,
} from "./permissions";
import { KeySecretReveal } from "./secret-reveal";
import { useSecretReveal } from "./one-time-secret";
import {
  CreateServiceAccountForm,
  ServiceAccountDetail,
  ServiceAccountTable,
} from "./service-accounts";
import {
  ErrorNotice,
  Notice,
  PermissionState,
  ReasonDialog,
  Surface,
  SurfaceHeader,
  TabPanel,
  TabStrip,
  primaryButtonClass,
  secondaryButtonClass,
} from "./ui";

const PAGE_SIZE = 25;

const TABS = [
  { id: "accounts", label: "Service accounts" },
  { id: "keys", label: "API keys" },
] as const;
type Tab = (typeof TABS)[number]["id"];

type LoadStatus = "loading" | "refreshing" | "ready" | "error";

interface AccountsState {
  readonly orgId: string;
  readonly status: LoadStatus;
  readonly items: ServiceAccount[];
  readonly nextCursor: string | null;
  readonly hasMore: boolean;
  readonly error: unknown;
}

interface KeysState {
  readonly orgId: string;
  readonly status: LoadStatus;
  readonly items: ApiKey[];
  readonly nextCursor: string | null;
  readonly hasMore: boolean;
  readonly error: unknown;
}

type ConfirmState =
  | { readonly kind: "suspend"; readonly account: ServiceAccount }
  | { readonly kind: "resume"; readonly account: ServiceAccount }
  | { readonly kind: "rotate"; readonly key: ApiKey }
  | { readonly kind: "revoke"; readonly key: ApiKey };

export interface IdentityPanelProps {
  orgId: string;
  /** The current membership. The server enforces the same matrix independently. */
  role?: MembershipRole;
}

export function IdentityPanel({ orgId, role }: IdentityPanelProps) {
  const panelId = useId();
  const permissions: IdentityPermissions = identityPermissions(role);
  const [tab, setTab] = useState<Tab>("accounts");
  const [accounts, setAccounts] = useState<AccountsState>(() => emptyAccounts(orgId));
  const [keys, setKeys] = useState<KeysState>(() => emptyKeys(orgId));
  const [selectedAccountId, setSelectedAccountId] = useState<string | null>(null);
  const selectedAccountIdRef = useRef<string | null>(null);
  const [selectedKeyId, setSelectedKeyId] = useState<string | null>(null);
  const [creating, setCreating] = useState<"account" | "key" | null>(null);
  const [formError, setFormError] = useState<unknown>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<ConfirmState | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [copyFailed, setCopyFailed] = useState(false);

  const accountsController = useRef<AbortController | null>(null);
  const keysController = useRef<AbortController | null>(null);
  const accountsGeneration = useRef(0);
  const keysGeneration = useRef(0);
  const mutationGeneration = useRef(0);
  const idempotencyKeys = useRef(new Map<string, string>());
  const accountDetailRef = useRef<HTMLDivElement | null>(null);
  const keyDetailRef = useRef<HTMLDivElement | null>(null);

  const secret = useSecretReveal();

  // A new organization is a new tenant boundary: drop the in-flight work, the
  // idempotency keys, the selections, and any secret that has not been
  // acknowledged, rather than carrying any of them across.
  useEffect(() => {
    mutationGeneration.current += 1;
    idempotencyKeys.current.clear();
    accountsController.current?.abort();
    keysController.current?.abort();
    setSelectedAccountId(null);
    selectedAccountIdRef.current = null;
    setSelectedKeyId(null);
    setCreating(null);
    setFormError(null);
    setActionError(null);
    setNotice(null);
    setConfirm(null);
    setBusyAction(null);
    secret.acknowledge();
    return () => {
      mutationGeneration.current += 1;
    };
    // `secret.acknowledge` is a stable `useCallback`; depending on it would
    // re-run this reset on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId]);

  const refreshAccounts = useCallback(async () => {
    accountsController.current?.abort();
    const controller = new AbortController();
    accountsController.current = controller;
    const generation = ++accountsGeneration.current;
    setAccounts((current) =>
      current.orgId === orgId && current.items.length > 0
        ? { ...current, status: "refreshing", error: null }
        : { ...emptyAccounts(orgId), status: "loading" },
    );
    try {
      const page = await listServiceAccounts(orgId, { limit: PAGE_SIZE }, controller.signal);
      if (controller.signal.aborted || generation !== accountsGeneration.current) return;
      const current = selectedAccountIdRef.current;
      const nextSelection =
        current && page.items.some((item) => item.id === current)
          ? current
          : (page.items[0]?.id ?? null);
      selectedAccountIdRef.current = nextSelection;
      setSelectedAccountId(nextSelection);
      setAccounts({
        orgId,
        status: "ready",
        items: page.items,
        nextCursor: page.next_cursor,
        hasMore: page.has_more,
        error: null,
      });
    } catch (error) {
      if (controller.signal.aborted || generation !== accountsGeneration.current) return;
      setAccounts((current) => ({
        ...(current.orgId === orgId ? current : emptyAccounts(orgId)),
        status: current.orgId === orgId && current.items.length > 0 ? "ready" : "error",
        error,
      }));
    }
  }, [orgId]);

  const loadMoreAccounts = useCallback(async () => {
    if (accounts.orgId !== orgId || !accounts.hasMore || !accounts.nextCursor) return;
    accountsController.current?.abort();
    const controller = new AbortController();
    accountsController.current = controller;
    const generation = ++accountsGeneration.current;
    setAccounts((current) => ({ ...current, status: "refreshing", error: null }));
    try {
      const page = await listServiceAccounts(
        orgId,
        { limit: PAGE_SIZE, cursor: accounts.nextCursor },
        controller.signal,
      );
      if (controller.signal.aborted || generation !== accountsGeneration.current) return;
      setAccounts((current) => ({
        ...current,
        status: "ready",
        items: [...current.items, ...page.items],
        nextCursor: page.next_cursor,
        hasMore: page.has_more,
        error: null,
      }));
    } catch (error) {
      if (controller.signal.aborted || generation !== accountsGeneration.current) return;
      setAccounts((current) => ({ ...current, status: "ready", error }));
    }
  }, [accounts.hasMore, accounts.nextCursor, accounts.orgId, orgId]);

  const refreshKeys = useCallback(async () => {
    keysController.current?.abort();
    const controller = new AbortController();
    keysController.current = controller;
    const generation = ++keysGeneration.current;
    setKeys((current) =>
      current.orgId === orgId && current.items.length > 0
        ? { ...current, status: "refreshing", error: null }
        : { ...emptyKeys(orgId), status: "loading" },
    );
    try {
      const page: Page<ApiKey> = await listApiKeys(orgId, { limit: PAGE_SIZE }, controller.signal);
      if (controller.signal.aborted || generation !== keysGeneration.current) return;
      setKeys((current) => {
        const merged = current.orgId === orgId ? [...current.items, ...page.items] : page.items;
        const keep = selectedKeyId;
        setSelectedKeyId(
          keep && merged.some((item) => item.id === keep) ? keep : (merged[0]?.id ?? null),
        );
        return {
          orgId,
          status: "ready",
          items: merged,
          nextCursor: page.next_cursor,
          hasMore: page.has_more,
          error: null,
        };
      });
    } catch (error) {
      if (controller.signal.aborted || generation !== keysGeneration.current) return;
      setKeys((current) => ({
        ...(current.orgId === orgId ? current : emptyKeys(orgId)),
        status: current.orgId === orgId && current.items.length > 0 ? "ready" : "error",
        error,
      }));
    }
  }, [orgId]);

  const loadMoreKeys = useCallback(async () => {
    if (keys.orgId !== orgId || !keys.hasMore || !keys.nextCursor) return;
    keysController.current?.abort();
    const controller = new AbortController();
    keysController.current = controller;
    const generation = ++keysGeneration.current;
    setKeys((current) => ({ ...current, status: "refreshing", error: null }));
    try {
      const page = await listApiKeys(
        orgId,
        { limit: PAGE_SIZE, cursor: keys.nextCursor },
        controller.signal,
      );
      if (controller.signal.aborted || generation !== keysGeneration.current) return;
      setKeys((current) => ({
        ...current,
        status: "ready",
        items: [...current.items, ...page.items],
        nextCursor: page.next_cursor,
        hasMore: page.has_more,
        error: null,
      }));
    } catch (error) {
      if (controller.signal.aborted || generation !== keysGeneration.current) return;
      setKeys((current) => ({ ...current, status: "ready", error }));
    }
  }, [keys.hasMore, keys.nextCursor, keys.orgId, orgId]);

  useEffect(() => {
    if (!permissions.canRead) return;
    void refreshAccounts();
    return () => {
      accountsController.current?.abort();
      accountsGeneration.current += 1;
    };
  }, [permissions.canRead, refreshAccounts]);

  useEffect(() => {
    if (!permissions.canRead) return;
    void refreshKeys();
    return () => {
      keysController.current?.abort();
      keysGeneration.current += 1;
    };
  }, [permissions.canRead, refreshKeys]);

  useEffect(() => {
    if (selectedAccountId) accountDetailRef.current?.focus();
  }, [selectedAccountId, tab]);

  useEffect(() => {
    if (selectedKeyId) keyDetailRef.current?.focus();
  }, [selectedKeyId, tab]);

  function operationKey(name: string): string {
    const existing = idempotencyKeys.current.get(name);
    if (existing) return existing;
    const created = crypto.randomUUID();
    idempotencyKeys.current.set(name, created);
    return created;
  }

  function releaseOperationKey(name: string) {
    idempotencyKeys.current.delete(name);
  }

  const visibleAccounts = accounts.orgId === orgId ? accounts : emptyAccounts(orgId);
  const visibleKeys = keys.orgId === orgId ? keys : emptyKeys(orgId);
  const selectedAccount =
    visibleAccounts.items.find((item) => item.id === selectedAccountId) ?? null;
  const selectedKey = visibleKeys.items.find((item) => item.id === selectedKeyId) ?? null;
  const selectedKeyAccount =
    selectedKey === null
      ? null
      : (visibleAccounts.items.find((item) => item.id === selectedKey.service_account_id) ?? null);

  async function createAccount(input: {
    name: string;
    description: string | null;
    capabilities: string[];
  }) {
    setBusyAction("create-account");
    setFormError(null);
    setNotice(null);
    setActionError(null);
    const keyName = "create-account";
    const generation = mutationGeneration.current;
    try {
      const created = await createServiceAccount(
        orgId,
        {
          name: input.name,
          capabilities: input.capabilities,
          ...(input.description ? { description: input.description } : {}),
        },
        operationKey(keyName),
      );
      releaseOperationKey(keyName);
      setCreating(null);
      setNotice(
        `Service account ${created.name} created with ${created.capabilities.length} ${created.capabilities.length === 1 ? "capability" : "capabilities"}. Create a key on it to give a caller something to authenticate with.`,
      );
      await refreshAccounts();
    } catch (error) {
      if (mutationGeneration.current !== generation) return;
      setFormError(error);
    } finally {
      if (mutationGeneration.current === generation) setBusyAction(null);
    }
  }

  async function createKey(input: {
    service_account_id: string;
    name: string;
    capabilities: string[];
    project_ids: string[];
    model_aliases: string[];
    network_allowlist: string[];
  }) {
    setBusyAction("create-key");
    setFormError(null);
    setNotice(null);
    setActionError(null);
    const keyName = "create-key";
    const generation = mutationGeneration.current;
    try {
      const created = await createApiKey(
        orgId,
        {
          service_account_id: input.service_account_id,
          name: input.name,
          capabilities: input.capabilities,
          project_ids: input.project_ids,
          model_aliases: input.model_aliases,
          network_allowlist: input.network_allowlist,
        },
        operationKey(keyName),
      );
      releaseOperationKey(keyName);
      setCreating(null);
      setCopyFailed(false);
      secret.reveal({
        secret: created.secret,
        reason: "created",
        keyName: created.name,
        keyPrefix: created.key_prefix,
        notice: created.secret_notice,
      });
      await refreshKeys();
    } catch (error) {
      if (mutationGeneration.current !== generation) return;
      setFormError(error);
    } finally {
      if (mutationGeneration.current === generation) setBusyAction(null);
    }
  }

  async function runConfirmedAction(reason: string) {
    if (!confirm) return;
    if (confirm.kind === "suspend") {
      await performSuspend(confirm.account, reason);
      return;
    }
    if (confirm.kind === "resume") {
      await performResume(confirm.account);
      return;
    }
    if (confirm.kind === "rotate") {
      await performRotate(confirm.key, reason);
      return;
    }
    await performRevoke(confirm.key, reason);
  }

  async function performSuspend(account: ServiceAccount, reason: string) {
    setBusyAction("suspend");
    setActionError(null);
    setNotice(null);
    const keyName = `suspend:${account.id}`;
    try {
      const updated = await suspendServiceAccount(
        orgId,
        account.id,
        { version: account.version, reason },
        operationKey(keyName),
      );
      releaseOperationKey(keyName);
      setConfirm(null);
      setNotice(
        `Service account ${updated.name} is suspended. Every key on it is denied with machine_key_suspended until it is resumed. The keys themselves are untouched and work again on resume.`,
      );
      await refreshAccounts();
    } catch (error) {
      releaseOperationKey(keyName);
      setConfirm(null);
      setActionError(error);
      void refreshAccounts();
    } finally {
      setBusyAction(null);
    }
  }

  async function performResume(account: ServiceAccount) {
    setBusyAction("resume");
    setActionError(null);
    setNotice(null);
    const keyName = `resume:${account.id}`;
    try {
      const updated = await resumeServiceAccount(
        orgId,
        account.id,
        { version: account.version },
        operationKey(keyName),
      );
      releaseOperationKey(keyName);
      setConfirm(null);
      setNotice(
        `Service account ${updated.name} is active again. Its existing keys work again with exactly the scope they already had; no key was re-issued.`,
      );
      await refreshAccounts();
    } catch (error) {
      releaseOperationKey(keyName);
      setConfirm(null);
      setActionError(error);
      void refreshAccounts();
    } finally {
      setBusyAction(null);
    }
  }

  async function performRotate(key: ApiKey, reason: string) {
    setBusyAction("rotate");
    setActionError(null);
    setNotice(null);
    const keyName = `rotate:${key.id}`;
    try {
      const replacement = await rotateApiKey(key.id, { reason }, operationKey(keyName));
      releaseOperationKey(keyName);
      setConfirm(null);
      setCopyFailed(false);
      setSelectedKeyId(replacement.id);
      secret.reveal({
        secret: replacement.secret,
        reason: "rotated",
        keyName: replacement.name,
        keyPrefix: replacement.key_prefix,
        notice: replacement.secret_notice,
      });
      await refreshKeys();
    } catch (error) {
      releaseOperationKey(keyName);
      setConfirm(null);
      setActionError(error);
    } finally {
      setBusyAction(null);
    }
  }

  async function performRevoke(key: ApiKey, reason: string) {
    setBusyAction("revoke");
    setActionError(null);
    setNotice(null);
    const keyName = `revoke:${key.id}`;
    try {
      const revoked = await revokeApiKey(
        key.id,
        { version: key.version, reason },
        operationKey(keyName),
      );
      releaseOperationKey(keyName);
      setConfirm(null);
      setNotice(
        `Key ${revoked.name} is revoked and is refused from now on. Revocation is terminal; to restore access, create a new key on the same service account.`,
      );
      await refreshKeys();
    } catch (error) {
      releaseOperationKey(keyName);
      setConfirm(null);
      setActionError(error);
      void refreshKeys();
    } finally {
      setBusyAction(null);
    }
  }

  return (
    <section aria-labelledby={`${panelId}-title`} className="space-y-5">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-[11px] font-semibold tracking-[0.1em] text-[var(--lumi-blue)] uppercase">
            Settings / Identity
          </p>
          <h2
            id={`${panelId}-title`}
            className="mt-2 text-2xl font-semibold tracking-[-0.03em] text-[var(--civic-navy)]"
          >
            Identity &amp; access
          </h2>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-[var(--muted-strong)]">
            Service accounts and API keys let CI, integrations, and managed runners call the control
            plane as themselves. A machine credential is a scope, not a role: it never inherits
            anyone's permissions, and there is no wildcard.
          </p>
        </div>
        {permissions.canRead ? (
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              className={secondaryButtonClass}
              onClick={() => {
                if (tab === "accounts") void refreshAccounts();
                else void refreshKeys();
              }}
              disabled={
                (tab === "accounts" ? visibleAccounts.status : visibleKeys.status) === "refreshing"
              }
            >
              Refresh
            </button>
            {permissions.canManage ? (
              <button
                type="button"
                className={primaryButtonClass}
                onClick={() => {
                  setFormError(null);
                  setCreating(tab === "accounts" ? "account" : "key");
                }}
                disabled={busyAction !== null}
              >
                {tab === "accounts" ? "New service account" : "New API key"}
              </button>
            ) : null}
          </div>
        ) : null}
      </header>

      {!permissions.canRead ? (
        <PermissionState title="Access not permitted" copy={IDENTITY_REFUSAL_COPY} />
      ) : (
        <>
          {!permissions.canManage ? (
            <Notice tone="info" title="Read-only">
              {IDENTITY_MANAGE_ONLY_COPY}
            </Notice>
          ) : null}

          {notice ? (
            <p
              role="status"
              className="rounded-lg border border-[var(--success)]/30 bg-[var(--success)]/5 p-3 text-sm text-[var(--civic-navy)]"
            >
              {notice}
            </p>
          ) : null}
          {actionError ? (
            <ErrorNotice error={actionError} title="The action could not be completed" />
          ) : null}
          {copyFailed ? (
            <Notice tone="warning" title="The clipboard was not available">
              Select the value and copy it manually. It is still shown in full in the dialog.
            </Notice>
          ) : null}

          <TabStrip
            tabs={TABS}
            active={tab}
            onChange={setTab}
            label="Identity and access"
            idPrefix="identity"
          />

          {tab === "accounts" ? (
            <TabPanel id="accounts" idPrefix="identity">
              {creating === "account" ? (
                <Surface ariaLabel="Create service account">
                  <SurfaceHeader
                    title="New service account"
                    description="Choose the narrowest capability set the job needs. The preview below states exactly what the account — and every key on it — will be able to do."
                  />
                  <CreateServiceAccountForm
                    busy={busyAction === "create-account"}
                    error={formError}
                    onSubmit={(input) => void createAccount(input)}
                    onCancel={() => {
                      setCreating(null);
                      setFormError(null);
                    }}
                  />
                </Surface>
              ) : null}

              <ServiceAccountTable
                accounts={visibleAccounts.items}
                status={visibleAccounts.status}
                error={visibleAccounts.error}
                hasMore={visibleAccounts.hasMore}
                selectedId={selectedAccountId}
                canManage={permissions.canManage}
                onSelect={(id) => {
                  selectedAccountIdRef.current = id;
                  setSelectedAccountId(id);
                  setActionError(null);
                  setNotice(null);
                }}
                onRetry={() => void refreshAccounts()}
                onLoadMore={() => void loadMoreAccounts()}
              />

              {selectedAccount ? (
                <ServiceAccountDetail
                  account={selectedAccount}
                  sectionRef={accountDetailRef}
                  permissions={permissions}
                  busyAction={busyAction}
                  onSuspend={() => setConfirm({ kind: "suspend", account: selectedAccount })}
                  onResume={() => setConfirm({ kind: "resume", account: selectedAccount })}
                />
              ) : visibleAccounts.status === "ready" ? (
                <Surface ariaLabel="No service account selected">
                  <div className="p-6">
                    <p className="text-sm font-semibold text-[var(--civic-navy)]">
                      {visibleAccounts.items.length === 0
                        ? "No service accounts"
                        : "Select a service account"}
                    </p>
                    <p className="mt-1 max-w-2xl text-sm leading-5 text-[var(--muted-strong)]">
                      {visibleAccounts.items.length === 0
                        ? "Create a service account to give a machine an identity. It starts with an explicit capability set and no key."
                        : "Capabilities, provenance, and the suspend control appear here."}
                    </p>
                  </div>
                </Surface>
              ) : null}
            </TabPanel>
          ) : (
            <TabPanel id="keys" idPrefix="identity">
              {creating === "key" ? (
                <Surface ariaLabel="Create API key">
                  <SurfaceHeader
                    title="New API key"
                    description="A key belongs to exactly one service account and may hold only a subset of that account's capabilities. The secret is shown once, after creation."
                  />
                  <CreateApiKeyForm
                    accounts={visibleAccounts.items.filter((item) => item.status === "active")}
                    busy={busyAction === "create-key"}
                    error={formError}
                    onSubmit={(input) => void createKey(input)}
                    onCancel={() => {
                      setCreating(null);
                      setFormError(null);
                    }}
                  />
                </Surface>
              ) : null}

              <ApiKeyTable
                keys={visibleKeys.items}
                status={visibleKeys.status}
                error={visibleKeys.error}
                hasMore={visibleKeys.hasMore}
                selectedId={selectedKeyId}
                onSelect={(id) => {
                  setSelectedKeyId(id);
                  setActionError(null);
                  setNotice(null);
                }}
                onRetry={() => void refreshKeys()}
                onLoadMore={() => void loadMoreKeys()}
              />

              {selectedKey ? (
                <ApiKeyDetail
                  apiKey={selectedKey}
                  account={selectedKeyAccount}
                  sectionRef={keyDetailRef}
                  permissions={permissions}
                  busyAction={busyAction}
                  onRotate={() => setConfirm({ kind: "rotate", key: selectedKey })}
                  onRevoke={() => setConfirm({ kind: "revoke", key: selectedKey })}
                />
              ) : visibleKeys.status === "ready" ? (
                <Surface ariaLabel="No API key selected">
                  <div className="p-6">
                    <p className="text-sm font-semibold text-[var(--civic-navy)]">
                      {visibleKeys.items.length === 0 ? "No API keys" : "Select an API key"}
                    </p>
                    <p className="mt-1 max-w-2xl text-sm leading-5 text-[var(--muted-strong)]">
                      {visibleKeys.items.length === 0
                        ? "Create a key to give a caller something to authenticate with. The secret is shown once and never again."
                        : "Scope, last use, and the rotate and revoke controls appear here."}
                    </p>
                  </div>
                </Surface>
              ) : null}
            </TabPanel>
          )}
        </>
      )}

      {tab === "keys" && visibleKeys.items.length > 0 ? (
        <p className="text-xs text-[var(--muted)]">
          {visibleKeys.items.filter((item) => item.status === "active").length} active of{" "}
          {visibleKeys.items.length} loaded
          {visibleKeys.items.some((item) => item.status !== "active")
            ? ` · ${visibleKeys.items
                .filter((item) => item.status !== "active")
                .map((item) => `${item.name}: ${apiKeyStatusLabel(item.status)}`)
                .join(", ")}`
            : ""}
        </p>
      ) : null}

      <ConfirmDialog
        state={confirm}
        busy={busyAction}
        onClose={() => {
          if (busyAction === null) setConfirm(null);
        }}
        onConfirm={(reason) => void runConfirmedAction(reason)}
      />

      <KeySecretReveal
        state={secret.state}
        onAcknowledge={() => {
          secret.acknowledge();
          setCopyFailed(false);
        }}
        onCopyFailed={() => setCopyFailed(true)}
      />
    </section>
  );
}

interface ConfirmCopy {
  readonly eyebrow: string;
  readonly title: string;
  readonly body: readonly string[];
  readonly reasonLabel: string;
  readonly reasonHint: string;
  readonly confirmLabel: string;
  readonly cancelLabel: string;
  readonly busyLabel: string;
  readonly destructive: boolean;
  /** Resume and rotate are not destructive, so no reason is demanded. */
  readonly reasonRequired: boolean;
}

function confirmCopy(state: ConfirmState | null): ConfirmCopy {
  if (!state) {
    return {
      eyebrow: "",
      title: "",
      body: [],
      reasonLabel: "Reason",
      reasonHint: "",
      confirmLabel: "Continue",
      cancelLabel: "Close",
      busyLabel: "Working…",
      destructive: false,
      reasonRequired: true,
    };
  }
  if (state.kind === "suspend") {
    return {
      eyebrow: "Suspend service account",
      title: `Suspend ${state.account.name}?`,
      body: [
        "Every API key on this account is refused from now on, whatever its scope and even if it has not expired. The refusal code is machine_key_suspended.",
        "The keys are not deleted and nothing is re-issued on resume: resuming restores exactly the scope these keys already had. Runs already in flight finish under the policy they started with.",
      ],
      reasonLabel: "Why are you suspending this account?",
      reasonHint: "Recorded on the account and in the security audit log. Required.",
      confirmLabel: "Suspend account",
      cancelLabel: "Keep account active",
      busyLabel: "Suspending…",
      destructive: true,
      reasonRequired: true,
    };
  }
  if (state.kind === "resume") {
    return {
      eyebrow: "Resume service account",
      title: `Resume ${state.account.name}?`,
      body: [
        "The account and every key on it start working again immediately, with exactly the capabilities they already held.",
        "No key is re-issued and no secret is shown: if a key was lost, rotate or create one separately.",
      ],
      reasonLabel: "",
      reasonHint: "",
      confirmLabel: "Resume account",
      cancelLabel: "Keep account suspended",
      busyLabel: "Resuming…",
      destructive: false,
      reasonRequired: false,
    };
  }
  if (state.kind === "rotate") {
    return {
      eyebrow: "Rotate API key",
      title: `Rotate ${state.key.name}?`,
      body: [
        "A replacement key is created first and only then is this one marked rotated, so a pipeline is never left without a working credential because a request half-succeeded.",
        `The replacement carries the same scope: ${state.key.capabilities.length} ${state.key.capabilities.length === 1 ? "capability" : "capabilities"}, the same projects, the same model aliases, and the same network allowlist. Its secret is shown once.`,
        "Anything still configured with the old secret will start failing at that point, not before.",
      ],
      reasonLabel: "Why are you rotating this key?",
      reasonHint: "Recorded in the security audit log. Required.",
      confirmLabel: "Rotate and show new secret",
      cancelLabel: "Keep current key",
      busyLabel: "Rotating…",
      destructive: false,
      reasonRequired: true,
    };
  }
  return {
    eyebrow: "Revoke API key",
    title: `Revoke ${state.key.name}?`,
    body: [
      "This key is refused from now on. Revocation is terminal: there is no un-revoke, and the key stays visible in the list with its reason and revocation time so the record survives.",
      "Anything using it — a CI pipeline, a scheduled job, an integration — will start failing. Rotate first if you need an overlap.",
    ],
    reasonLabel: "Why are you revoking this key?",
    reasonHint: "Recorded on the key and in the security audit log. Required.",
    confirmLabel: "Revoke key",
    cancelLabel: "Keep key active",
    busyLabel: "Revoking…",
    destructive: true,
    reasonRequired: true,
  };
}

function ConfirmDialog({
  state,
  busy,
  onClose,
  onConfirm,
}: {
  state: ConfirmState | null;
  busy: string | null;
  onClose: () => void;
  onConfirm: (reason: string) => void;
}) {
  const copy = confirmCopy(state);
  return (
    <ReasonDialog
      open={state !== null}
      eyebrow={copy.eyebrow}
      title={copy.title}
      body={copy.body}
      reasonLabel={copy.reasonLabel}
      reasonHint={copy.reasonHint}
      confirmLabel={copy.confirmLabel}
      cancelLabel={copy.cancelLabel}
      busyLabel={copy.busyLabel}
      busy={busy !== null}
      destructive={copy.destructive}
      onClose={onClose}
      onConfirm={onConfirm}
    />
  );
}

function emptyAccounts(orgId: string): AccountsState {
  return { orgId, status: "loading", items: [], nextCursor: null, hasMore: false, error: null };
}

function emptyKeys(orgId: string): KeysState {
  return { orgId, status: "loading", items: [], nextCursor: null, hasMore: false, error: null };
}
