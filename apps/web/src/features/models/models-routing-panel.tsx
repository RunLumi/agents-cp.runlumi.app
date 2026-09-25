import { useEffect, useId, useMemo, useRef, useState } from "react";

import {
  createCredential,
  revokeCredential,
  rotateCredential,
  createRoute,
  getCatalog,
  listCredentials,
  listRouteHistory,
  listRoutes,
  listUsage,
  publishRoute,
  rollbackRoute,
  type CatalogProvider,
  type CatalogResponse,
  type CredentialMetadata,
  type OrganizationSummary,
  type Route,
  type RouteConfig,
  type RouteVersion,
  type UsageMetadata,
} from "@/lib/api";
import { presentApiError } from "@/lib/errors";

interface ModelsRoutingPanelProps {
  orgId: string;
  membership: OrganizationSummary | undefined;
}

type PanelState =
  | { kind: "loading" }
  | {
      kind: "ready";
      catalog: CatalogResponse;
      credentials: CredentialMetadata[];
      routes: Route[];
      usage: UsageMetadata[];
      history: Record<string, RouteVersion[]>;
    }
  | { kind: "error"; error: unknown };

export function ModelsRoutingPanel({ orgId, membership }: ModelsRoutingPanelProps) {
  const [state, setState] = useState<PanelState>({ kind: "loading" });
  const [notice, setNotice] = useState<string | null>(null);
  const [activeRouteId, setActiveRouteId] = useState<string | null>(null);
  const canManage = membership?.role === "owner" || membership?.role === "admin";
  const canReadUsage =
    membership?.role === "owner" || membership?.role === "admin" || membership?.role === "member";

  async function refresh() {
    setState({ kind: "loading" });
    try {
      const [catalog, credentials, routes, usage] = await Promise.all([
        getCatalog(orgId),
        canManage ? listCredentials(orgId) : Promise.resolve(null),
        listRoutes(orgId),
        canReadUsage ? listUsage(orgId) : Promise.resolve(null),
      ]);
      const selected = routes.items[0]?.route_id ?? null;
      const history: Record<string, RouteVersion[]> = {};
      if (selected) history[selected] = (await listRouteHistory(orgId, selected)).items;
      setActiveRouteId(selected);
      setState({
        kind: "ready",
        catalog,
        credentials: credentials?.items ?? [],
        routes: routes.items,
        usage: usage?.items ?? [],
        history,
      });
    } catch (error) {
      setState({ kind: "error", error });
    }
  }

  useEffect(() => {
    void refresh();
    // The request generation is intentionally scoped to the selected tenant.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId, membership?.role]);

  async function selectRoute(routeId: string) {
    setActiveRouteId(routeId);
    if (state.kind !== "ready") return;
    try {
      const history = await listRouteHistory(orgId, routeId);
      setState({ ...state, history: { ...state.history, [routeId]: history.items } });
    } catch (error) {
      setNotice(presentApiError(error).message);
    }
  }

  if (state.kind === "loading") return <PanelMessage label="Loading model catalog and routes…" />;
  if (state.kind === "error") {
    return <ErrorPanel error={state.error} onRetry={() => void refresh()} />;
  }

  const activeRoute =
    state.routes.find((route) => route.route_id === activeRouteId) ?? state.routes[0];
  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-xs font-semibold tracking-[0.1em] text-[var(--lumi-blue)]">
            MODELS & ROUTING
          </p>
          <h1 className="mt-2 text-2xl font-semibold tracking-[-0.03em] text-[var(--civic-navy)]">
            Provider catalog
          </h1>
          <p className="mt-1 text-sm text-[var(--muted-strong)]">
            Stable aliases, capability filters, credentials, and immutable route versions.
          </p>
        </div>
        <button type="button" className={secondaryButton} onClick={() => void refresh()}>
          Refresh
        </button>
      </header>

      {notice ? (
        <p role="status" className={noticeClass}>
          {notice}
        </p>
      ) : null}
      <CatalogTable catalog={state.catalog} />
      {canManage ? (
        <CredentialPanel
          orgId={orgId}
          providers={state.catalog.providers}
          credentials={state.credentials}
          onChanged={refresh}
        />
      ) : (
        <ReadOnlyCredentials />
      )}
      {canManage ? (
        <RoutePanel
          orgId={orgId}
          credentials={state.credentials}
          catalog={state.catalog}
          routes={state.routes}
          activeRoute={activeRoute}
          onChanged={refresh}
          onSelect={selectRoute}
        />
      ) : (
        <ReadOnlyRoutes routes={state.routes} />
      )}
      {activeRoute ? (
        <RouteHistory
          orgId={orgId}
          route={activeRoute}
          versions={state.history[activeRoute.route_id] ?? []}
          canManage={canManage}
          onChanged={refresh}
        />
      ) : null}
      <UsagePanel usage={state.usage} canRead={canReadUsage} />
    </div>
  );
}

function CatalogTable({ catalog }: { catalog: CatalogResponse }) {
  return (
    <section className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]">
      <div className="border-b border-[var(--border)] px-5 py-4">
        <h2 className="text-base font-semibold text-[var(--civic-navy)]">Model catalog</h2>
        <p className="mt-1 text-sm text-[var(--muted-strong)]">
          Catalog IDs stay stable when display names or upstream models change.
        </p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px] text-left text-sm">
          <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
            <tr>
              <th className="px-5 py-3 font-medium">Model</th>
              <th className="px-5 py-3 font-medium">Provider</th>
              <th className="px-5 py-3 font-medium">Capabilities</th>
              <th className="px-5 py-3 font-medium">State</th>
              <th className="px-5 py-3 font-medium">Health</th>
              <th className="px-5 py-3 font-medium">Pricing source</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border)]">
            {catalog.models.map((model) => (
              <tr key={model.model_id}>
                <td className="px-5 py-4">
                  <p className="font-medium text-[var(--civic-navy)]">{model.display_name}</p>
                  <code className="mt-1 block text-xs text-[var(--muted)]">{model.model_id}</code>
                </td>
                <td className="px-5 py-4 text-[var(--muted-strong)]">
                  {catalog.providers.find((provider) => provider.provider_id === model.provider_id)
                    ?.display_name ?? model.provider_id}
                </td>
                <td className="px-5 py-4">
                  <div className="flex flex-wrap gap-1.5">
                    {model.capabilities.map((capability) => (
                      <span className={tagClass} key={capability}>
                        {capability.replace("_", " ")}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="px-5 py-4">
                  <StatusPill status={model.lifecycle} />
                </td>
                <td className="px-5 py-4">
                  <StatusPill
                    status={
                      catalog.health.find((health) => health.provider_id === model.provider_id)
                        ?.state ?? "ready"
                    }
                  />
                </td>
                <td className="px-5 py-4 text-xs text-[var(--muted)]">
                  {model.pricing_version ?? "Not recorded"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {catalog.aliases.length > 0 ? (
        <div className="border-t border-[var(--border)] px-5 py-4">
          <p className="text-xs font-medium text-[var(--muted)]">Stable aliases</p>
          <div className="mt-2 flex flex-wrap gap-2">
            {catalog.aliases.map((alias) => (
              <span className={tagClass} key={alias.alias_id}>
                {alias.alias}
              </span>
            ))}
          </div>
        </div>
      ) : null}
    </section>
  );
}

function CredentialPanel({
  orgId,
  providers,
  credentials,
  onChanged,
}: {
  orgId: string;
  providers: CatalogProvider[];
  credentials: CredentialMetadata[];
  onChanged: () => Promise<void>;
}) {
  const id = useId();
  const [providerId, setProviderId] = useState(providers[0]?.provider_id ?? "");
  const [label, setLabel] = useState("");
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const createKey = useRef<string | undefined>(undefined);
  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await createCredential(
        orgId,
        { provider_id: providerId, owner_type: "organization", label, secret },
        (createKey.current ??= crypto.randomUUID()),
      );
      createKey.current = undefined;
      setSecret("");
      setLabel("");
      await onChanged();
    } catch (requestError) {
      setError(requestError);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)]">
      <h2 className="text-base font-semibold text-[var(--civic-navy)]">Credentials</h2>
      <p className="mt-1 text-sm text-[var(--muted-strong)]">
        Secrets are encrypted once and never shown again after saving.
      </p>
      <form
        onSubmit={(event) => void submit(event)}
        className="mt-4 grid gap-3 lg:grid-cols-[1fr_1fr_1fr_auto] lg:items-end"
      >
        <label className="text-sm font-medium" htmlFor={`${id}-provider`}>
          Provider
          <select
            id={`${id}-provider`}
            value={providerId}
            onChange={(event) => setProviderId(event.target.value)}
            className={inputClass}
          >
            {providers.map((provider) => (
              <option value={provider.provider_id} key={provider.provider_id}>
                {provider.display_name}
              </option>
            ))}
          </select>
        </label>
        <label className="text-sm font-medium" htmlFor={`${id}-label`}>
          Label
          <input
            id={`${id}-label`}
            required
            value={label}
            onChange={(event) => setLabel(event.target.value)}
            className={inputClass}
            placeholder="Production key"
          />
        </label>
        <label className="text-sm font-medium" htmlFor={`${id}-secret`}>
          Secret
          <input
            id={`${id}-secret`}
            required
            type="password"
            autoComplete="new-password"
            value={secret}
            onChange={(event) => setSecret(event.target.value)}
            className={inputClass}
          />
        </label>
        <button type="submit" className={primaryButton} disabled={busy || !providerId}>
          {busy ? "Saving…" : "Save credential"}
        </button>
      </form>
      {error ? <ErrorPanel error={error} /> : null}
      <CredentialList orgId={orgId} credentials={credentials} onChanged={onChanged} />
    </section>
  );
}

function CredentialList({
  orgId,
  credentials,
  onChanged,
}: {
  orgId: string;
  credentials: CredentialMetadata[];
  onChanged?: () => Promise<void>;
}) {
  const [rotateId, setRotateId] = useState<string | null>(null);
  const [rotateSecret, setRotateSecret] = useState("");
  const [rotateLabel, setRotateLabel] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const operationKeys = useRef<Record<string, string>>({});
  function operationKey(operation: "rotate" | "revoke", credentialId: string) {
    const key = `${operation}:${credentialId}`;
    operationKeys.current[key] ??= crypto.randomUUID();
    return operationKeys.current[key];
  }
  if (credentials.length === 0)
    return <p className="mt-4 text-sm text-[var(--muted)]">No organization credentials yet.</p>;

  async function rotate(event: React.FormEvent<HTMLFormElement>, credential: CredentialMetadata) {
    event.preventDefault();
    setBusyId(credential.credential_id);
    setError(null);
    try {
      await rotateCredential(
        credential.org_id ?? "",
        credential.credential_id,
        { secret: rotateSecret, ...(rotateLabel ? { label: rotateLabel } : {}) },
        operationKey("rotate", credential.credential_id),
      );
      delete operationKeys.current[`rotate:${credential.credential_id}`];
      setRotateId(null);
      setRotateSecret("");
      setRotateLabel("");
      await onChanged?.();
    } catch (requestError) {
      setError(requestError);
    } finally {
      setBusyId(null);
    }
  }

  async function revoke(credential: CredentialMetadata) {
    const confirmed = window.confirm(
      `Revoke “${credential.label}”? New requests will fail immediately; existing usage and audit history remain.`,
    );
    if (!confirmed) return;
    setBusyId(credential.credential_id);
    setError(null);
    try {
      await revokeCredential(
        credential.org_id ?? "",
        credential.credential_id,
        credential.version,
        operationKey("revoke", credential.credential_id),
      );
      delete operationKeys.current[`revoke:${credential.credential_id}`];
      await onChanged?.();
    } catch (requestError) {
      setError(requestError);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <>
      {error ? <ErrorPanel error={error} /> : null}
      <ul className="mt-5 divide-y divide-[var(--border)] border-t border-[var(--border)]">
        {credentials.map((credential) => (
          <li
            className="flex flex-wrap items-center justify-between gap-3 py-3"
            key={credential.credential_id}
          >
            <div>
              <p className="text-sm font-medium text-[var(--civic-navy)]">{credential.label}</p>
              <p className="mt-1 font-mono text-xs text-[var(--muted)]">
                {credential.fingerprint} · v{credential.version}
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <StatusPill status={credential.status} />
              {onChanged && credential.org_id === orgId && credential.status !== "revoked" ? (
                <>
                  <button
                    type="button"
                    className={secondaryButton}
                    onClick={() => setRotateId(credential.credential_id)}
                    disabled={busyId === credential.credential_id}
                  >
                    Rotate
                  </button>
                  <button
                    type="button"
                    className={dangerButton}
                    onClick={() => void revoke(credential)}
                    disabled={busyId === credential.credential_id}
                  >
                    Revoke
                  </button>
                </>
              ) : null}
            </div>
            {onChanged && rotateId === credential.credential_id ? (
              <form
                className="grid w-full gap-2 sm:grid-cols-[1fr_1fr_auto] sm:items-end"
                onSubmit={(event) => void rotate(event, credential)}
              >
                <label
                  className="text-xs font-medium"
                  htmlFor={`${credential.credential_id}-rotate-label`}
                >
                  New label
                  <input
                    id={`${credential.credential_id}-rotate-label`}
                    className={inputClass}
                    value={rotateLabel}
                    onChange={(event) => setRotateLabel(event.target.value)}
                  />
                </label>
                <label
                  className="text-xs font-medium"
                  htmlFor={`${credential.credential_id}-rotate-secret`}
                >
                  Replacement secret
                  <input
                    id={`${credential.credential_id}-rotate-secret`}
                    className={inputClass}
                    type="password"
                    autoComplete="new-password"
                    required
                    value={rotateSecret}
                    onChange={(event) => setRotateSecret(event.target.value)}
                  />
                </label>
                <button
                  type="submit"
                  className={primaryButton}
                  disabled={busyId === credential.credential_id}
                >
                  {busyId === credential.credential_id ? "Saving…" : "Save rotation"}
                </button>
              </form>
            ) : null}
          </li>
        ))}
      </ul>
    </>
  );
}

function ReadOnlyCredentials() {
  return (
    <section className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)]">
      <h2 className="text-base font-semibold text-[var(--civic-navy)]">Credentials</h2>
      <p className="mt-1 text-sm text-[var(--muted-strong)]">
        Your organization role does not include credential metadata or management access.
      </p>
    </section>
  );
}

function RoutePanel({
  orgId,
  catalog,
  credentials,
  routes,
  activeRoute,
  onChanged,
  onSelect,
}: {
  orgId: string;
  catalog: CatalogResponse;
  credentials: CredentialMetadata[];
  routes: Route[];
  activeRoute: Route | undefined;
  onChanged: () => Promise<void>;
  onSelect: (routeId: string) => Promise<void>;
}) {
  const id = useId();
  const [alias, setAlias] = useState("coding-default");
  const [displayName, setDisplayName] = useState("Coding default");
  const [strategy, setStrategy] = useState<RouteConfig["strategy"]>("ordered_fallback");
  const [firstModel, setFirstModel] = useState(catalog.models[0]?.model_id ?? "");
  const [secondModel, setSecondModel] = useState(
    catalog.models[1]?.model_id ?? catalog.models[0]?.model_id ?? "",
  );
  const [firstWeight, setFirstWeight] = useState(70);
  const [secondWeight, setSecondWeight] = useState(30);
  const [firstTimeout, setFirstTimeout] = useState(45_000);
  const [secondTimeout, setSecondTimeout] = useState(45_000);
  const [firstRetries, setFirstRetries] = useState(1);
  const [secondRetries, setSecondRetries] = useState(0);
  const [firstCredential, setFirstCredential] = useState("");
  const [secondCredential, setSecondCredential] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const createKey = useRef<string | undefined>(undefined);
  const publishKey = useRef<string | undefined>(undefined);
  const first = catalog.models.find((model) => model.model_id === firstModel);
  const second = catalog.models.find((model) => model.model_id === secondModel);
  const config = useMemo<RouteConfig | null>(() => {
    if (!first || !second) return null;
    return {
      strategy,
      candidates: [
        {
          provider_id: first.provider_id,
          model_id: first.model_id,
          weight: firstWeight,
          timeout_ms: firstTimeout,
          max_retries: firstRetries,
          credential_id: firstCredential || null,
        },
        {
          provider_id: second.provider_id,
          model_id: second.model_id,
          weight: secondWeight,
          timeout_ms: secondTimeout,
          max_retries: secondRetries,
          credential_id: secondCredential || null,
        },
      ],
    };
  }, [
    first,
    second,
    strategy,
    firstWeight,
    secondWeight,
    firstTimeout,
    secondTimeout,
    firstRetries,
    secondRetries,
    firstCredential,
    secondCredential,
  ]);
  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!config) return;
    setBusy(true);
    setError(null);
    try {
      const created = await createRoute(
        orgId,
        { alias, display_name: displayName, strategy, config },
        (createKey.current ??= crypto.randomUUID()),
      );
      await publishRoute(
        orgId,
        created.route.route_id,
        { version: created.route.version, config },
        (publishKey.current ??= crypto.randomUUID()),
      );
      createKey.current = undefined;
      publishKey.current = undefined;
      await onChanged();
    } catch (requestError) {
      setError(requestError);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)]">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2 className="text-base font-semibold text-[var(--civic-navy)]">Route editor</h2>
          <p className="mt-1 text-sm text-[var(--muted-strong)]">
            Publish a typed configuration; history remains immutable.
          </p>
        </div>
        <span className={tagClass}>No graph rules</span>
      </div>
      <form onSubmit={(event) => void submit(event)} className="mt-4 grid gap-3 lg:grid-cols-2">
        <label className="text-sm font-medium" htmlFor={`${id}-alias`}>
          Alias
          <input
            id={`${id}-alias`}
            required
            value={alias}
            onChange={(event) => setAlias(event.target.value)}
            className={inputClass}
          />
        </label>
        <label className="text-sm font-medium" htmlFor={`${id}-name`}>
          Display name
          <input
            id={`${id}-name`}
            required
            value={displayName}
            onChange={(event) => setDisplayName(event.target.value)}
            className={inputClass}
          />
        </label>
        <label className="text-sm font-medium" htmlFor={`${id}-strategy`}>
          Strategy
          <select
            id={`${id}-strategy`}
            value={strategy}
            onChange={(event) => setStrategy(event.target.value as RouteConfig["strategy"])}
            className={inputClass}
          >
            <option value="ordered_fallback">Ordered fallback</option>
            <option value="weighted_health_aware">Weighted + health</option>
            <option value="fixed">Fixed</option>
          </select>
        </label>
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="text-sm font-medium" htmlFor={`${id}-first`}>
            First candidate
            <select
              id={`${id}-first`}
              value={firstModel}
              onChange={(event) => setFirstModel(event.target.value)}
              className={inputClass}
            >
              {catalog.models.map((model) => (
                <option value={model.model_id} key={model.model_id}>
                  {model.display_name}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm font-medium" htmlFor={`${id}-second`}>
            Fallback candidate
            <select
              id={`${id}-second`}
              value={secondModel}
              onChange={(event) => setSecondModel(event.target.value)}
              className={inputClass}
            >
              {catalog.models.map((model) => (
                <option value={model.model_id} key={model.model_id}>
                  {model.display_name}
                </option>
              ))}
            </select>
          </label>
        </div>
        <div className="grid gap-3 lg:col-span-2 sm:grid-cols-2">
          <fieldset className="grid gap-2 rounded-lg border border-[var(--border)] p-3">
            <legend className="px-1 text-xs font-semibold text-[var(--muted-strong)]">
              First candidate policy
            </legend>
            <div className="grid grid-cols-3 gap-2">
              <label className="text-xs" htmlFor={`${id}-first-weight`}>
                Weight
                <input
                  id={`${id}-first-weight`}
                  className={inputClass}
                  type="number"
                  min="1"
                  max="1000"
                  value={firstWeight}
                  onChange={(event) => setFirstWeight(Number(event.target.value))}
                />
              </label>
              <label className="text-xs" htmlFor={`${id}-first-timeout`}>
                Timeout ms
                <input
                  id={`${id}-first-timeout`}
                  className={inputClass}
                  type="number"
                  min="250"
                  max="120000"
                  step="250"
                  value={firstTimeout}
                  onChange={(event) => setFirstTimeout(Number(event.target.value))}
                />
              </label>
              <label className="text-xs" htmlFor={`${id}-first-retries`}>
                Retries
                <input
                  id={`${id}-first-retries`}
                  className={inputClass}
                  type="number"
                  min="0"
                  max="3"
                  value={firstRetries}
                  onChange={(event) => setFirstRetries(Number(event.target.value))}
                />
              </label>
            </div>
            <label className="text-xs" htmlFor={`${id}-first-credential`}>
              Credential
              <select
                id={`${id}-first-credential`}
                className={inputClass}
                value={firstCredential}
                onChange={(event) => setFirstCredential(event.target.value)}
              >
                <option value="">Managed resolution</option>
                {credentials
                  .filter((credential) => credential.provider_id === first?.provider_id)
                  .map((credential) => (
                    <option value={credential.credential_id} key={credential.credential_id}>
                      {credential.label}
                    </option>
                  ))}
              </select>
            </label>
          </fieldset>
          <fieldset className="grid gap-2 rounded-lg border border-[var(--border)] p-3">
            <legend className="px-1 text-xs font-semibold text-[var(--muted-strong)]">
              Fallback candidate policy
            </legend>
            <div className="grid grid-cols-3 gap-2">
              <label className="text-xs" htmlFor={`${id}-second-weight`}>
                Weight
                <input
                  id={`${id}-second-weight`}
                  className={inputClass}
                  type="number"
                  min="1"
                  max="1000"
                  value={secondWeight}
                  onChange={(event) => setSecondWeight(Number(event.target.value))}
                />
              </label>
              <label className="text-xs" htmlFor={`${id}-second-timeout`}>
                Timeout ms
                <input
                  id={`${id}-second-timeout`}
                  className={inputClass}
                  type="number"
                  min="250"
                  max="120000"
                  step="250"
                  value={secondTimeout}
                  onChange={(event) => setSecondTimeout(Number(event.target.value))}
                />
              </label>
              <label className="text-xs" htmlFor={`${id}-second-retries`}>
                Retries
                <input
                  id={`${id}-second-retries`}
                  className={inputClass}
                  type="number"
                  min="0"
                  max="3"
                  value={secondRetries}
                  onChange={(event) => setSecondRetries(Number(event.target.value))}
                />
              </label>
            </div>
            <label className="text-xs" htmlFor={`${id}-second-credential`}>
              Credential
              <select
                id={`${id}-second-credential`}
                className={inputClass}
                value={secondCredential}
                onChange={(event) => setSecondCredential(event.target.value)}
              >
                <option value="">Managed resolution</option>
                {credentials
                  .filter((credential) => credential.provider_id === second?.provider_id)
                  .map((credential) => (
                    <option value={credential.credential_id} key={credential.credential_id}>
                      {credential.label}
                    </option>
                  ))}
              </select>
            </label>
          </fieldset>
        </div>
        <div className="lg:col-span-2 flex justify-end">
          <button type="submit" className={primaryButton} disabled={busy || !config}>
            {busy ? "Publishing…" : "Publish route"}
          </button>
        </div>
      </form>
      {error ? <ErrorPanel error={error} /> : null}
      {routes.length > 0 ? (
        <div className="mt-5 border-t border-[var(--border)] pt-4">
          <p className="text-xs font-medium text-[var(--muted)]">Existing routes</p>
          <ul className="mt-2 space-y-2">
            {routes.map((route) => (
              <li key={route.route_id}>
                <button
                  type="button"
                  onClick={() => void onSelect(route.route_id)}
                  className={`flex w-full items-center justify-between rounded-lg border px-3 py-2 text-left text-sm ${activeRoute?.route_id === route.route_id ? "border-[var(--lumi-blue)] bg-[var(--lumi-blue-soft)]" : "border-[var(--border)] hover:bg-[var(--panel-hover)]"}`}
                >
                  <span className="font-medium text-[var(--civic-navy)]">{route.alias}</span>
                  <span className="text-xs text-[var(--muted)]">
                    {route.lifecycle} · v{route.version}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}

function ReadOnlyRoutes({ routes }: { routes: Route[] }) {
  return (
    <section className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)]">
      <h2 className="text-base font-semibold text-[var(--civic-navy)]">Routes</h2>
      <p className="mt-1 text-sm text-[var(--muted-strong)]">
        Only owners and admins can change routing.
      </p>
      {routes.length === 0 ? (
        <p className="mt-4 text-sm text-[var(--muted)]">No routes published.</p>
      ) : (
        <ul className="mt-4 space-y-2">
          {routes.map((route) => (
            <li
              className="flex justify-between rounded-lg border border-[var(--border)] px-3 py-2 text-sm"
              key={route.route_id}
            >
              <span>{route.alias}</span>
              <span className="text-xs text-[var(--muted)]">{route.lifecycle}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function RouteHistory({
  orgId,
  route,
  versions,
  canManage,
  onChanged,
}: {
  orgId: string;
  route: Route;
  versions: RouteVersion[];
  canManage: boolean;
  onChanged: () => Promise<void>;
}) {
  const [busy, setBusy] = useState<number | null>(null);
  const [error, setError] = useState<unknown>(null);
  const rollbackKeys = useRef<Record<number, string>>({});
  async function rollback(version: number) {
    setBusy(version);
    setError(null);
    try {
      rollbackKeys.current[version] ??= crypto.randomUUID();
      await rollbackRoute(orgId, route.route_id, version, rollbackKeys.current[version]);
      delete rollbackKeys.current[version];
      await onChanged();
    } catch (requestError) {
      setError(requestError);
    } finally {
      setBusy(null);
    }
  }
  return (
    <section className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)]">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-[var(--civic-navy)]">Version history</h2>
          <p className="mt-1 text-sm text-[var(--muted-strong)]">
            Rollback changes the active pointer; it does not rewrite a version.
          </p>
        </div>
        <span className={tagClass}>{route.alias}</span>
      </div>
      {error ? <ErrorPanel error={error} /> : null}
      {versions.length === 0 ? (
        <p className="mt-4 text-sm text-[var(--muted)]">No published versions yet.</p>
      ) : (
        <ol className="mt-4 space-y-2">
          {versions.map((version) => (
            <li
              className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-[var(--border)] px-3 py-2"
              key={version.route_version_id}
            >
              <div>
                <p className="text-sm font-medium text-[var(--civic-navy)]">
                  Version {version.version}
                </p>
                <p className="mt-1 text-xs text-[var(--muted)]">
                  {version.published_at ? formatDate(version.published_at) : "Draft"}
                </p>
              </div>
              {route.active_version_id === version.route_version_id ? (
                <span className={tagClass}>Active</span>
              ) : canManage ? (
                <button
                  type="button"
                  className={secondaryButton}
                  disabled={busy !== null}
                  onClick={() => void rollback(version.version)}
                >
                  {busy === version.version ? "Rolling back…" : "Roll back"}
                </button>
              ) : (
                <span className="text-xs text-[var(--muted)]">Historical</span>
              )}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

function UsagePanel({ usage, canRead }: { usage: UsageMetadata[]; canRead: boolean }) {
  return (
    <section className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)]">
      <h2 className="text-base font-semibold text-[var(--civic-navy)]">Recent usage</h2>
      <p className="mt-1 text-sm text-[var(--muted-strong)]">
        Prompt and response content is not stored in usage metadata.
      </p>
      {!canRead ? (
        <p className="mt-4 text-sm text-[var(--muted)]">
          Your organization role does not include usage access.
        </p>
      ) : usage.length === 0 ? (
        <p className="mt-4 text-sm text-[var(--muted)]">No inference usage recorded.</p>
      ) : (
        <div className="mt-4 overflow-x-auto">
          <table className="w-full min-w-[620px] text-left text-sm">
            <thead className="text-xs text-[var(--muted)]">
              <tr>
                <th className="px-2 py-2 font-medium">Alias</th>
                <th className="px-2 py-2 font-medium">Provider</th>
                <th className="px-2 py-2 font-medium">Tokens</th>
                <th className="px-2 py-2 font-medium">Budget</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border)]">
              {usage.slice(0, 10).map((event) => (
                <tr key={event.usage_event_id}>
                  <td className="px-2 py-3">{event.model_alias}</td>
                  <td className="px-2 py-3 text-[var(--muted-strong)]">{event.provider_id}</td>
                  <td className="px-2 py-3 tabular-nums">
                    {event.input_tokens ?? "—"} / {event.output_tokens ?? "—"}
                  </td>
                  <td className="px-2 py-3">
                    <StatusPill status={event.budget_decision} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function PanelMessage({ label }: { label: string }) {
  return (
    <div
      className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-8 text-sm text-[var(--muted)]"
      aria-live="polite"
    >
      {label}
    </div>
  );
}
function ErrorPanel({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const presentation = presentApiError(error);
  return (
    <div
      role="alert"
      className="mt-4 rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/5 p-3 text-sm text-[var(--danger)]"
    >
      <p>{presentation.message}</p>
      {onRetry ? (
        <button
          type="button"
          className="mt-2 min-h-10 rounded-lg border border-[var(--danger)]/40 px-3"
          onClick={onRetry}
        >
          Try again
        </button>
      ) : null}
    </div>
  );
}
function StatusPill({ status }: { status: string }) {
  return (
    <span
      className={`inline-flex rounded-full px-2 py-1 text-xs font-medium ${status === "active" || status === "allow" ? "bg-[var(--success)]/10 text-[var(--success)]" : "bg-[var(--panel-strong)] text-[var(--muted-strong)]"}`}
    >
      {status}
    </span>
  );
}
function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}
const inputClass =
  "mt-1.5 min-h-11 w-full rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 text-sm outline-none focus-visible:border-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)]";
const primaryButton =
  "min-h-11 rounded-lg bg-[var(--lumi-blue)] px-4 py-2 text-sm font-semibold text-white outline-none hover:bg-[var(--lumi-blue-hover)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] disabled:opacity-50";
const secondaryButton =
  "min-h-11 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-4 py-2 text-sm font-medium outline-none hover:bg-[var(--panel-hover)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] disabled:opacity-50";
const dangerButton =
  "min-h-11 rounded-lg border border-[var(--danger)]/40 bg-[var(--danger)]/5 px-4 py-2 text-sm font-medium text-[var(--danger)] outline-none hover:bg-[var(--danger)]/10 focus-visible:ring-2 focus-visible:ring-[var(--ring)] disabled:opacity-50";
const tagClass =
  "inline-flex rounded-md bg-[var(--lumi-blue-soft)] px-2 py-1 text-xs font-medium text-[var(--lumi-blue)]";
const noticeClass =
  "rounded-lg border border-[var(--success)]/30 bg-[var(--success)]/5 p-3 text-sm text-[var(--success)]";
