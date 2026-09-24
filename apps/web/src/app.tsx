import { useEffect, useId, useRef, useState } from "react";

import lumiLogoUrl from "../../../brand/lumi-logo.svg";
import {
  createFoundationCheck,
  getFoundationCheckStatus,
  getHealth,
  type FoundationCheckResponse,
  type HealthResponse,
} from "@/lib/api";
import { ApiClientError, presentApiError } from "@/lib/errors";

type HealthState =
  | { kind: "loading" }
  | { kind: "ready"; data: HealthResponse }
  | { kind: "error"; error: unknown };

const nav = ["Overview", "Members", "Teams", "Agents", "Security", "Audit log"];

export function App() {
  const [health, setHealth] = useState<HealthState>({ kind: "loading" });
  const [healthAttempt, setHealthAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setHealth({ kind: "loading" });

    void getHealth(controller.signal)
      .then((data) => setHealth({ kind: "ready", data }))
      .catch((error: unknown) => {
        if (
          controller.signal.aborted ||
          (error instanceof ApiClientError && error.kind === "aborted")
        ) {
          return;
        }
        setHealth({ kind: "error", error });
      });

    return () => controller.abort();
  }, [healthAttempt]);

  function retryHealth() {
    setHealth({ kind: "loading" });
    setHealthAttempt((attempt) => attempt + 1);
  }

  return (
    <div className="app-root min-h-dvh bg-[var(--surface)] text-[var(--foreground)]">
      <header className="border-b border-[var(--border)] bg-[var(--panel)]">
        <div className="mx-auto flex h-14 max-w-[1440px] items-center justify-between px-4 sm:px-6">
          <div className="flex items-center gap-3">
            <img src={lumiLogoUrl} alt="" aria-hidden="true" className="size-7" />
            <div>
              <div className="text-sm font-semibold tracking-[-0.01em]">Lumi Agents</div>
              <div className="text-[11px] text-[var(--muted)]">Control plane</div>
            </div>
          </div>
        </div>
      </header>

      <div className="mx-auto grid max-w-[1440px] grid-cols-1 md:grid-cols-[220px_minmax(0,1fr)]">
        <aside className="hidden min-h-[calc(100dvh-3.5rem)] border-r border-[var(--border)] px-3 py-5 md:block">
          <nav aria-label="Control plane">
            <ul className="space-y-1">
              {nav.map((item, index) => (
                <li key={item}>
                  <span
                    aria-current={index === 0 ? "page" : undefined}
                    aria-disabled={index === 0 ? undefined : "true"}
                    className={[
                      "flex min-h-10 w-full items-center rounded-lg border-l-2 px-3 py-2 text-sm",
                      index === 0
                        ? "border-l-[var(--lumi-blue)] bg-[var(--lumi-blue-soft)] font-medium text-[var(--lumi-blue)]"
                        : "border-l-transparent text-[var(--muted)]",
                    ].join(" ")}
                  >
                    {item}
                  </span>
                </li>
              ))}
            </ul>
          </nav>
        </aside>

        <main className="min-w-0 px-4 py-8 sm:px-6 lg:px-10">
          <div className="mx-auto max-w-5xl">
            <div className="mb-8 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <p className="mb-1 text-xs font-medium text-[var(--muted)]">ORGANIZATION</p>
                <h1 className="text-2xl font-semibold tracking-[-0.025em]">Overview</h1>
                <p className="mt-1 max-w-xl text-sm leading-6 text-[var(--muted-strong)]">
                  Fast, edge-native administration for Lumi Agents.
                </p>
              </div>
              <div
                className="flex items-center gap-2 text-xs text-[var(--muted-strong)]"
                aria-live="polite"
              >
                <span
                  className={[
                    "size-1.5 rounded-full",
                    health.kind === "ready"
                      ? "bg-emerald-500"
                      : health.kind === "error"
                        ? "bg-red-500"
                        : "animate-pulse bg-amber-400",
                  ].join(" ")}
                  aria-hidden="true"
                />
                {health.kind === "ready"
                  ? `API connected · ${health.data.service}`
                  : health.kind === "error"
                    ? "API unavailable"
                    : "Checking API"}
              </div>
            </div>

            {health.kind === "error" && <ErrorNotice error={health.error} onRetry={retryHealth} />}

            <section aria-label="Platform status" className="grid gap-3 md:grid-cols-3">
              <StatusCard
                eyebrow="Runtime"
                title="Cloudflare Workers"
                detail="Rust + Axum at the edge"
              />
              <StatusCard
                eyebrow="Interface"
                title="React + Base UI"
                detail="Accessible primitives, minimal client cost"
              />
              <StatusCard
                eyebrow="Build"
                title="Vite 8"
                detail="Rolldown-powered development loop"
              />
            </section>

            <section className="mt-8 overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]">
              <div className="border-b border-[var(--border)] px-5 py-4">
                <h2 className="text-sm font-semibold">Foundation</h2>
                <p className="mt-1 text-xs leading-5 text-[var(--muted)]">
                  The skeleton is intentionally small. Product complexity should be earned by real
                  requirements.
                </p>
              </div>
              <div className="divide-y divide-[var(--border)]">
                <Row label="Backend" value="Axum 0.8 / workers-rs" />
                <Row label="Frontend" value="React 19.3 / Vite 8 / TypeScript 7" />
                <Row label="UI primitives" value="shadcn/ui / Base UI / Tailwind CSS 4" />
                <Row label="Repository" value="pnpm workspace / Cargo workspace" />
              </div>
            </section>

            {import.meta.env.DEV ? <FoundationCheckPanel /> : null}
          </div>
        </main>
      </div>
    </div>
  );
}

function ErrorNotice({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  const presentation = presentApiError(error);
  const titleId = useId();

  return (
    <section
      role="alert"
      aria-labelledby={titleId}
      className="mb-6 rounded-xl border border-[var(--border)] border-l-4 border-l-red-600 bg-[var(--panel)] p-5"
    >
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2 id={titleId} className="text-sm font-semibold">
            {presentation.title}
          </h2>
          <p className="mt-1 text-sm leading-5 text-[var(--muted-strong)]">
            {presentation.message}
          </p>
          <dl className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs text-[var(--muted)]">
            <div className="flex gap-1.5">
              <dt>Error code</dt>
              <dd>
                <code>{presentation.code}</code>
              </dd>
            </div>
            {presentation.requestId && (
              <div className="flex gap-1.5">
                <dt>Request ID</dt>
                <dd>
                  <code>{presentation.requestId}</code>
                </dd>
              </div>
            )}
          </dl>
        </div>
        {presentation.retryable && (
          <button
            type="button"
            onClick={onRetry}
            className="min-h-11 shrink-0 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-4 py-2 text-sm font-medium outline-none transition hover:bg-[var(--panel-hover)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--surface)]"
          >
            Try again
          </button>
        )}
      </div>
    </section>
  );
}

function FoundationCheckPanel() {
  const [result, setResult] = useState<FoundationCheckResponse | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [creating, setCreating] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const idempotencyKey = useRef<string | null>(null);
  const activeController = useRef<AbortController | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      activeController.current?.abort();
    };
  }, []);

  async function runCheck() {
    if (activeController.current !== null) return;
    const controller = new AbortController();
    activeController.current = controller;
    setCreating(true);
    setResult(null);
    setError(null);

    try {
      const key = idempotencyKey.current ?? crypto.randomUUID();
      idempotencyKey.current = key;
      const created = await createFoundationCheck(key, controller.signal);
      idempotencyKey.current = null;
      if (mounted.current) setResult(created);
    } catch (requestError: unknown) {
      if (
        controller.signal.aborted ||
        (requestError instanceof ApiClientError && requestError.kind === "aborted")
      ) {
        return;
      }
      if (!presentApiError(requestError).retryable) idempotencyKey.current = null;
      if (mounted.current) setError(requestError);
    } finally {
      if (activeController.current === controller) activeController.current = null;
      if (mounted.current) setCreating(false);
    }
  }

  async function refreshStatus() {
    if (!result || activeController.current !== null) return;
    const controller = new AbortController();
    activeController.current = controller;
    setRefreshing(true);
    setError(null);

    try {
      const latest = await getFoundationCheckStatus(result.event_id, controller.signal);
      if (mounted.current) setResult(latest);
    } catch (requestError: unknown) {
      if (
        controller.signal.aborted ||
        (requestError instanceof ApiClientError && requestError.kind === "aborted")
      ) {
        return;
      }
      if (mounted.current) setError(requestError);
    } finally {
      if (activeController.current === controller) activeController.current = null;
      if (mounted.current) setRefreshing(false);
    }
  }

  const errorRetryAction = result ? refreshStatus : runCheck;

  return (
    <section
      aria-labelledby="foundation-check-title"
      className="mt-8 overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)]"
    >
      <div className="border-b border-[var(--border)] px-5 py-4">
        <p className="text-[11px] font-semibold tracking-[0.08em] text-[var(--muted)]">
          DEVELOPMENT ONLY
        </p>
        <h2 id="foundation-check-title" className="mt-1 text-sm font-semibold">
          Foundation integration check
        </h2>
        <p className="mt-1 text-xs leading-5 text-[var(--muted-strong)]">
          Creates a local outbox event with an idempotency key. It contains no customer data.
        </p>
      </div>
      <div className="flex flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between">
        <div aria-live="polite" className="min-w-0 text-sm">
          {result ? (
            <>
              <p>
                Outbox delivery: <strong>{formatDeliveryStatus(result.delivery_status)}</strong>
              </p>
              <p className="mt-1 break-all text-xs text-[var(--muted)]">
                Event ID: <code>{result.event_id}</code>
              </p>
            </>
          ) : (
            <p className="text-[var(--muted-strong)]">
              {creating ? "Creating check…" : "No check has been created in this session."}
            </p>
          )}
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          <button
            type="button"
            onClick={() => void runCheck()}
            disabled={creating || refreshing}
            className="min-h-11 rounded-lg bg-[var(--lumi-blue)] px-4 py-2 text-sm font-medium text-white outline-none transition hover:bg-[var(--lumi-blue-hover)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--surface)] disabled:cursor-not-allowed disabled:opacity-50"
          >
            {creating
              ? "Creating…"
              : error && !result && presentApiError(error).retryable
                ? "Retry check"
                : result
                  ? "Run another check"
                  : "Create foundation check"}
          </button>
          {result && (
            <button
              type="button"
              onClick={() => void refreshStatus()}
              disabled={creating || refreshing}
              className="min-h-11 rounded-lg border border-[var(--border)] bg-[var(--panel)] px-4 py-2 text-sm font-medium outline-none transition hover:bg-[var(--panel-hover)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--surface)] disabled:cursor-not-allowed disabled:opacity-50"
            >
              {refreshing ? "Refreshing…" : "Refresh status"}
            </button>
          )}
        </div>
      </div>
      {error !== null && (
        <div className="px-5 pb-5">
          <ErrorNotice error={error} onRetry={() => void errorRetryAction()} />
        </div>
      )}
    </section>
  );
}

function formatDeliveryStatus(status: FoundationCheckResponse["delivery_status"]): string {
  return status.replaceAll("_", " ");
}

function StatusCard({
  eyebrow,
  title,
  detail,
}: {
  eyebrow: string;
  title: string;
  detail: string;
}) {
  return (
    <article className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)]">
      <p className="text-[11px] font-semibold tracking-[0.08em] text-[var(--muted)]">
        {eyebrow.toUpperCase()}
      </p>
      <h2 className="mt-3 text-base font-semibold tracking-[-0.015em]">{title}</h2>
      <p className="mt-1 text-sm leading-5 text-[var(--muted-strong)]">{detail}</p>
    </article>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-1 px-5 py-3.5 sm:grid-cols-[160px_1fr] sm:items-center">
      <div className="text-xs font-medium text-[var(--muted)]">{label}</div>
      <div className="text-sm">{value}</div>
    </div>
  );
}
