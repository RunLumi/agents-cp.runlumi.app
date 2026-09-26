/**
 * Plugins — the organization settings sub-page (`settings/plugins`).
 *
 * P07-CG §"Web information architecture" adds this beside `Identity & access` and
 * adds no top-level nav item. Supply-chain governance is organization
 * configuration: it sits with the other settings because F22's tree has no other
 * place for it, and it sits near credentials conceptually because both concern
 * what may act on the organization's behalf.
 *
 * The panel is deliberately read-mostly. `plugins.read` is member-visible, because
 * a member who can see which tools exist and why a tool is denied gets diagnostic
 * value for free; `plugins.manage` is admin-only, because installing code is a
 * supply-chain decision. The panel therefore renders a read-only surface with
 * every manage control absent, rather than a disabled surface full of buttons
 * that would fail closed with a 403.
 */

import { useCallback, useEffect, useId, useRef, useState } from "react";

import {
  approvePluginInstall,
  blockPlugin,
  getPlugin,
  getPluginPermissionDiff,
  listPlugins,
  pinPluginVersion,
  unblockPlugin,
  type PluginDetail,
  type PluginListItem,
  type PluginOverview,
  type PluginPermissionDiff,
  type PluginPolicy,
} from "./api";
import { PIN_NOTE, isAmbiguousMutationFailure, isPermissionFailure } from "./contracts";
import { PluginDetailView } from "./plugin-detail";
import { PluginTable, PolicySummary } from "./plugin-lists";
import {
  ErrorNotice,
  Notice,
  PermissionState,
  Pill,
  ReasonDialog,
  StatusDot,
  Surface,
  TabPanel,
  TabStrip,
  secondaryButtonClass,
} from "./ui";

export type PluginRole = "owner" | "admin" | "member" | "viewer";

export interface PluginsPanelProps {
  orgId: string;
  /** The current membership. The server enforces the same matrix independently. */
  role?: PluginRole;
}

const TABS = [
  { id: "installed", label: "Installed" },
  { id: "catalog", label: "Catalog" },
  { id: "policy", label: "Policy" },
] as const;
type Tab = (typeof TABS)[number]["id"];

/** P07-CG: `plugins.read` is member-visible; `plugins.manage` is admin-only. */
export function pluginPermissions(role: PluginRole | null | undefined): {
  canRead: boolean;
  canManage: boolean;
} {
  if (role === "owner" || role === "admin") return { canRead: true, canManage: true };
  if (role === "member" || role === "viewer") return { canRead: true, canManage: false };
  return { canRead: false, canManage: false };
}

export const PLUGIN_READ_COPY =
  "Reading installed plugins, the catalog, and the organization's plugin policy is available to every member. A member who can see which tools exist and why a tool is denied can diagnose a failure without asking an administrator.";

export const PLUGIN_MANAGE_COPY =
  "Installing, approving, pinning, and blocking plugins is an administrator action. Everything on this page stays readable, so you can see the current state and the reason for it, but no control here will change it.";

export const PLUGIN_REFUSAL_COPY =
  "Your current membership cannot read this organization's plugin governance. Ask an administrator for access. This page shows no plugin state at all without permission.";

type LoadStatus = "loading" | "refreshing" | "ready" | "error";

interface OverviewState {
  readonly orgId: string;
  readonly status: LoadStatus;
  readonly data: PluginOverview | null;
  readonly error: unknown;
}

interface DetailState {
  readonly orgId: string;
  readonly packageId: string | null;
  readonly status: LoadStatus;
  readonly data: PluginDetail | null;
  readonly error: unknown;
}

interface DiffState {
  readonly status: "idle" | "loading" | "ready" | "error";
  readonly diff: PluginPermissionDiff | null;
  readonly error: unknown;
}

type ConfirmState =
  | { readonly kind: "block"; readonly item: PluginListItem; readonly policy: PluginPolicy }
  | { readonly kind: "unblock"; readonly item: PluginListItem; readonly policy: PluginPolicy }
  | {
      readonly kind: "pin";
      readonly item: PluginListItem;
      readonly policy: PluginPolicy;
      readonly version: string;
    };

export function PluginsPanel({ orgId, role }: PluginsPanelProps) {
  const panelId = useId();
  const permissions = pluginPermissions(role);
  const [tab, setTab] = useState<Tab>("installed");
  const [overview, setOverview] = useState<OverviewState>(() => emptyOverview(orgId));
  const [detail, setDetail] = useState<DetailState>(() => emptyDetail(orgId));
  const [diff, setDiff] = useState<DiffState>({ status: "idle", diff: null, error: null });
  const [selectedPackageId, setSelectedPackageId] = useState<string | null>(null);
  const selectedPackageIdRef = useRef<string | null>(null);
  const [candidateVersion, setCandidateVersion] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [confirm, setConfirm] = useState<ConfirmState | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);

  const overviewController = useRef<AbortController | null>(null);
  const detailController = useRef<AbortController | null>(null);
  const overviewGeneration = useRef(0);
  const detailGeneration = useRef(0);
  const mutationGeneration = useRef(0);
  const idempotencyKeys = useRef(new Map<string, string>());
  const detailRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    mutationGeneration.current += 1;
    idempotencyKeys.current.clear();
    overviewController.current?.abort();
    detailController.current?.abort();
    setSelectedPackageId(null);
    selectedPackageIdRef.current = null;
    setCandidateVersion("");
    setDiff({ status: "idle", diff: null, error: null });
    setNotice(null);
    setActionError(null);
    setConfirm(null);
    setBusyAction(null);
    return () => {
      mutationGeneration.current += 1;
    };
  }, [orgId]);

  const refreshOverview = useCallback(async () => {
    overviewController.current?.abort();
    const controller = new AbortController();
    overviewController.current = controller;
    const generation = ++overviewGeneration.current;
    setOverview((current) =>
      current.orgId === orgId && current.data !== null
        ? { ...current, status: "refreshing", error: null }
        : { ...emptyOverview(orgId), status: "loading" },
    );
    try {
      const data = await listPlugins(orgId, controller.signal);
      if (controller.signal.aborted || generation !== overviewGeneration.current) return;
      const current = selectedPackageIdRef.current;
      const nextSelection =
        current && data.items.some((item) => item.package.package_id === current)
          ? current
          : (data.items.find((item) => item.install !== null)?.package.package_id ??
            data.items[0]?.package.package_id ??
            null);
      selectedPackageIdRef.current = nextSelection;
      setSelectedPackageId(nextSelection);
      setOverview({ orgId, status: "ready", data, error: null });
    } catch (error) {
      if (controller.signal.aborted || generation !== overviewGeneration.current) return;
      setOverview((current) => ({
        ...(current.orgId === orgId ? current : emptyOverview(orgId)),
        status: current.orgId === orgId && current.data !== null ? "ready" : "error",
        error,
      }));
    }
  }, [orgId]);

  const loadDetail = useCallback(async () => {
    const packageId = selectedPackageIdRef.current;
    if (!packageId) {
      setDetail(emptyDetail(orgId));
      return;
    }
    detailController.current?.abort();
    const controller = new AbortController();
    detailController.current = controller;
    const generation = ++detailGeneration.current;
    setDetail({ orgId, packageId, status: "loading", data: null, error: null });
    setDiff({ status: "idle", diff: null, error: null });
    try {
      const data = await getPlugin(orgId, packageId, controller.signal);
      if (controller.signal.aborted || generation !== detailGeneration.current) return;
      setDetail({ orgId, packageId, status: "ready", data, error: null });
      const latest = data.versions[data.versions.length - 1]?.version ?? "";
      setCandidateVersion((current) => (current === "" ? latest : current));
    } catch (error) {
      if (controller.signal.aborted || generation !== detailGeneration.current) return;
      setDetail({ orgId, packageId, status: "error", data: null, error });
    }
  }, [orgId]);

  useEffect(() => {
    if (!permissions.canRead) return;
    void refreshOverview();
    return () => {
      overviewController.current?.abort();
      overviewGeneration.current += 1;
    };
  }, [permissions.canRead, refreshOverview]);

  useEffect(() => {
    if (!permissions.canRead) return;
    void loadDetail();
    return () => {
      detailController.current?.abort();
      detailGeneration.current += 1;
    };
  }, [loadDetail, permissions.canRead, selectedPackageId]);

  useEffect(() => {
    if (selectedPackageId) detailRef.current?.focus();
  }, [selectedPackageId]);

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

  async function loadDiff() {
    const data = detail.data;
    const packageId = selectedPackageIdRef.current;
    if (!data || !packageId || candidateVersion === "") return;
    setDiff({ status: "loading", diff: null, error: null });
    try {
      const result = await getPluginPermissionDiff(
        orgId,
        packageId,
        candidateVersion,
        data.install?.version ?? "",
      );
      setDiff({ status: "ready", diff: result, error: null });
    } catch (error) {
      setDiff({ status: "error", diff: null, error });
    }
  }

  async function approve() {
    const packageId = selectedPackageIdRef.current;
    if (!packageId) return;
    setBusyAction("approve");
    setActionError(null);
    setNotice(null);
    const keyName = `approve:${packageId}`;
    try {
      const install = await approvePluginInstall(
        orgId,
        packageId,
        { request_id: crypto.randomUUID() },
        operationKey(keyName),
      );
      releaseOperationKey(keyName);
      setConfirm(null);
      setNotice(
        `Version ${install.version} of ${install.package_id} is approved. It is now reviewable for this organization, and any tool it declares still needs a registration before it is usable.`,
      );
      await refreshOverview();
      await loadDetail();
    } catch (error) {
      releaseOperationKey(keyName);
      setActionError(error);
    } finally {
      setBusyAction(null);
    }
  }

  async function runConfirmed(reason: string) {
    if (!confirm) return;
    const { kind, item, policy } = confirm;
    if (kind === "block") {
      await performBlock(item, policy, reason);
      return;
    }
    if (kind === "unblock") {
      await performUnblock(item, policy, reason);
      return;
    }
    await performPin(item, policy, confirm.version, reason);
  }

  async function performBlock(item: PluginListItem, policy: PluginPolicy, reason: string) {
    setBusyAction("block");
    setActionError(null);
    setNotice(null);
    const keyName = `block:${item.package.package_id}`;
    try {
      const updated = await blockPlugin(
        orgId,
        item.package.package_id,
        { version: policy.version, reason },
        operationKey(keyName),
      );
      releaseOperationKey(keyName);
      setConfirm(null);
      setNotice(
        `${item.package.display_name} is blocked at policy v${updated.version}. New installs and new executions are denied; the reason is in the security audit log. Runs already in flight finish.`,
      );
      await refreshOverview();
      await loadDetail();
    } catch (error) {
      releaseOperationKey(keyName);
      setConfirm(null);
      setActionError(error);
      void refreshOverview();
    } finally {
      setBusyAction(null);
    }
  }

  async function performUnblock(item: PluginListItem, policy: PluginPolicy, reason: string) {
    setBusyAction("unblock");
    setActionError(null);
    setNotice(null);
    const keyName = `unblock:${item.package.package_id}`;
    try {
      const updated = await unblockPlugin(
        orgId,
        item.package.package_id,
        { version: policy.version, reason },
        operationKey(keyName),
      );
      releaseOperationKey(keyName);
      setConfirm(null);
      setNotice(
        `${item.package.display_name} is no longer blocked (policy v${updated.version}). Its declared capability set is unchanged; nothing is re-approved by unblocking.`,
      );
      await refreshOverview();
      await loadDetail();
    } catch (error) {
      releaseOperationKey(keyName);
      setConfirm(null);
      setActionError(error);
      void refreshOverview();
    } finally {
      setBusyAction(null);
    }
  }

  async function performPin(
    item: PluginListItem,
    policy: PluginPolicy,
    version: string,
    reason: string,
  ) {
    setBusyAction("pin");
    setActionError(null);
    setNotice(null);
    const keyName = `pin:${item.package.package_id}`;
    try {
      const updated = await pinPluginVersion(
        orgId,
        item.package.package_id,
        { version: policy.version, version_to_pin: version, reason },
        operationKey(keyName),
      );
      releaseOperationKey(keyName);
      setConfirm(null);
      setNotice(
        `${item.package.display_name} is pinned to ${version} (policy v${updated.version}). ${PIN_NOTE}`,
      );
      await refreshOverview();
      await loadDetail();
    } catch (error) {
      releaseOperationKey(keyName);
      setConfirm(null);
      setActionError(error);
      void refreshOverview();
    } finally {
      setBusyAction(null);
    }
  }

  const visibleOverview = overview.orgId === orgId ? overview : emptyOverview(orgId);
  const visibleDetail = detail.orgId === orgId ? detail : emptyDetail(orgId);
  const policy = visibleOverview.data?.policy ?? null;
  const items = visibleOverview.data?.items ?? [];
  const selectedItem = items.find((item) => item.package.package_id === selectedPackageId) ?? null;

  return (
    <section aria-labelledby={`${panelId}-title`} className="space-y-5">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-[11px] font-semibold tracking-[0.1em] text-[var(--lumi-blue)] uppercase">
            Settings / Plugins
          </p>
          <h2
            id={`${panelId}-title`}
            className="mt-2 text-2xl font-semibold tracking-[-0.03em] text-[var(--civic-navy)]"
          >
            Plugins
          </h2>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-[var(--muted-strong)]">
            What third-party code this organization may run, and exactly what that code is allowed
            to reach. An update cannot silently gain network, secret, or tool capability: expansion
            in any class is expansion, and it is held for approval.
          </p>
        </div>
        {permissions.canRead ? (
          <button
            type="button"
            className={secondaryButtonClass}
            onClick={() => {
              void refreshOverview();
              void loadDetail();
            }}
            disabled={visibleOverview.status === "refreshing"}
          >
            {visibleOverview.status === "refreshing" ? "Refreshing…" : "Refresh"}
          </button>
        ) : null}
      </header>

      {!permissions.canRead ? (
        <PermissionState title="Access not permitted" copy={PLUGIN_REFUSAL_COPY} />
      ) : (
        <>
          {permissions.canRead && !permissions.canManage ? (
            <Notice tone="info" title="Read-only">
              {PLUGIN_MANAGE_COPY}
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
            <ErrorNotice
              error={actionError}
              title={
                isAmbiguousMutationFailure(actionError)
                  ? "The server did not confirm the result"
                  : "The action could not be completed"
              }
            />
          ) : null}
          {isAmbiguousMutationFailure(actionError) ? (
            <Notice tone="warning">
              The request may already have been applied. Refresh before retrying; the retry reuses
              the same idempotency key, so it cannot duplicate the mutation.
            </Notice>
          ) : null}

          {visibleOverview.status === "error" && isPermissionFailure(visibleOverview.error) ? (
            <PermissionState title="Access not permitted" copy={PLUGIN_READ_COPY} />
          ) : null}

          {policy ? <PolicySummary policy={policy} /> : null}

          {policy && policy.conflicts.length > 0 ? (
            <ConflictBanner count={policy.conflicts.length} packages={policy.conflicts} />
          ) : null}

          <TabStrip
            tabs={TABS}
            active={tab}
            onChange={setTab}
            label="Plugin governance"
            idPrefix="plugins"
          />

          <TabPanel id={tab} idPrefix="plugins">
            {tab === "policy" ? (
              <Surface ariaLabel="Plugin policy detail">
                <div className="p-5 text-sm leading-6 text-[var(--muted-strong)]">
                  <p className="font-semibold text-[var(--civic-navy)]">
                    The policy above is the whole of this organization's control.
                  </p>
                  <p className="mt-2">
                    Publisher mode decides who may publish here. Update mode decides what happens
                    when a new version widens capability: managed holds it for approval, direct
                    applies it and audits it. A pin is exact and blocks every other version,
                    including a security update, until it is lifted as a separate audited action.
                  </p>
                  <p className="mt-2">
                    Block and allow are separate lists, and blocked wins when a package appears on
                    both. Platform quarantine is not on this page and cannot be overridden from
                    here.
                  </p>
                </div>
              </Surface>
            ) : (
              <PluginTable
                items={tab === "installed" ? items.filter((item) => item.install !== null) : items}
                policy={policy ?? EMPTY_POLICY}
                status={visibleOverview.status}
                error={visibleOverview.error}
                selectedId={selectedPackageId}
                onSelect={(packageId) => {
                  selectedPackageIdRef.current = packageId;
                  setSelectedPackageId(packageId);
                  setCandidateVersion("");
                  setDiff({ status: "idle", diff: null, error: null });
                  setActionError(null);
                  setNotice(null);
                }}
                onRetry={() => void refreshOverview()}
                emptyTitle={tab === "installed" ? "No plugins installed" : "The catalog is empty"}
                emptyCopy={
                  tab === "installed"
                    ? "This organization has no plugin installed. Installing third-party code is a supply-chain decision: the host agent reports the runtime version and artifact digest, and the server verifies both before anything is recorded."
                    : "No package is available to this organization. Ask an administrator about the approved publisher list."
                }
                installedOnly={tab === "installed"}
              />
            )}

            {tab !== "policy" ? (
              visibleDetail.status === "loading" ? (
                <Surface ariaLabel="Loading plugin detail">
                  <div className="p-5" role="status" aria-live="polite" aria-busy="true">
                    <p className="text-sm text-[var(--muted-strong)]">Loading plugin detail…</p>
                  </div>
                </Surface>
              ) : visibleDetail.status === "error" ? (
                <Surface ariaLabel="Plugin detail unavailable">
                  <div className="p-5">
                    <ErrorNotice
                      error={visibleDetail.error}
                      title="The plugin detail is unavailable"
                      onRetry={() => void loadDetail()}
                    />
                  </div>
                </Surface>
              ) : visibleDetail.data ? (
                <PluginDetailView
                  detail={visibleDetail.data}
                  item={selectedItem}
                  policy={policy ?? EMPTY_POLICY}
                  sectionRef={detailRef}
                  diff={diff.diff}
                  diffStatus={diff.status}
                  diffError={diff.error}
                  canManage={permissions.canManage}
                  busyAction={busyAction}
                  candidateVersion={candidateVersion}
                  onCandidateChange={setCandidateVersion}
                  onLoadDiff={() => void loadDiff()}
                  onApprove={() => void approve()}
                  onPin={(version) => {
                    if (!selectedItem || !policy) return;
                    setConfirm({ kind: "pin", item: selectedItem, policy, version });
                  }}
                  onBlock={() => {
                    if (!selectedItem || !policy) return;
                    setConfirm({ kind: "block", item: selectedItem, policy });
                  }}
                  onUnblock={() => {
                    if (!selectedItem || !policy) return;
                    setConfirm({ kind: "unblock", item: selectedItem, policy });
                  }}
                />
              ) : null
            ) : null}
          </TabPanel>
        </>
      )}

      <ConfirmDialog
        state={confirm}
        busy={busyAction}
        onClose={() => {
          if (busyAction === null) setConfirm(null);
        }}
        onConfirm={(reason) => void runConfirmed(reason)}
      />
    </section>
  );
}

function ConflictBanner({ count, packages }: { count: number; packages: readonly string[] }) {
  return (
    <div
      role="alert"
      className="rounded-xl border border-[var(--danger)]/40 border-l-[3px] border-l-[var(--danger)] bg-[var(--panel)] p-4 shadow-[var(--shadow)]"
    >
      <div className="flex flex-wrap items-center gap-2">
        <Pill tone="danger">
          <StatusDot tone="danger" />
          {count} reported {count === 1 ? "conflict" : "conflicts"}
        </Pill>
      </div>
      <p className="mt-2 max-w-3xl text-sm leading-5 text-[var(--civic-navy)]">
        A package on both the allow list and the block list is a contradiction in your own policy,
        not a detail. Blocked wins, and the contradiction is reported rather than resolved.{" "}
        {packages.join(", ")} {count === 1 ? "is" : "are"} affected.
      </p>
    </div>
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
    };
  }
  if (state.kind === "block") {
    return {
      eyebrow: "Block plugin",
      title: `Block ${state.item.package.display_name}?`,
      body: [
        "New installs and new executions of this package are denied for this organization. Existing installations stay on disk; the deny decision is server-side and does not depend on the files being removed.",
        "Runs already in flight finish under the policy they started with. Only new invocations are refused, and the refusal is immediate.",
        "Blocking does not revoke a tool registration or change the package's declared capability set. Unblocking does not re-approve anything.",
      ],
      reasonLabel: "Why are you blocking this package?",
      reasonHint: "Recorded in the security audit log with your name. Required.",
      confirmLabel: "Block package",
      cancelLabel: "Keep package allowed",
      busyLabel: "Blocking…",
      destructive: true,
    };
  }
  if (state.kind === "unblock") {
    return {
      eyebrow: "Unblock plugin",
      title: `Unblock ${state.item.package.display_name}?`,
      body: [
        "New installs and new executions are permitted again, subject to the rest of the organization policy — the publisher mode, the platform quarantine, and the tool registrations all still apply.",
        "Nothing is re-approved by unblocking, and no version is installed. If a candidate version is waiting for review, it is still waiting.",
      ],
      reasonLabel: "Why are you unblocking this package?",
      reasonHint: "Recorded in the security audit log. Required.",
      confirmLabel: "Unblock package",
      cancelLabel: "Keep package blocked",
      busyLabel: "Unblocking…",
      destructive: false,
    };
  }
  return {
    eyebrow: "Pin plugin version",
    title: `Pin ${state.item.package.display_name} to ${state.version}?`,
    body: [
      "A pin is exact. From now on this package cannot update to any other version — including a security update that fixes a published vulnerability.",
      "That is deliberate. A silent auto-patch would defeat the pin, so lifting it is a separate, explicit, audited action rather than a side effect of any update.",
      "Auto-update does not override a pin. If you need a security fix, lift the pin, install the fix, then decide deliberately whether to pin again.",
    ],
    reasonLabel: "Why are you pinning this version?",
    reasonHint: "Recorded in the security audit log. Required.",
    confirmLabel: "Pin version",
    cancelLabel: "Do not pin",
    busyLabel: "Pinning…",
    destructive: true,
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

const EMPTY_POLICY: PluginPolicy = {
  publisher_mode: "official_only",
  approved_publishers: [],
  allowed_packages: [],
  blocked_packages: [],
  pinned_versions: {},
  auto_update: false,
  update_mode: "managed",
  version: 0,
  conflicts: [],
};

function emptyOverview(orgId: string): OverviewState {
  return { orgId, status: "loading", data: null, error: null };
}

function emptyDetail(orgId: string): DetailState {
  return { orgId, packageId: null, status: "loading", data: null, error: null };
}
