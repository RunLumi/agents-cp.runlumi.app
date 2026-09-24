import { useEffect, useState } from "react";

import { getHealth, type HealthResponse } from "@/lib/api";

type HealthState =
  | { kind: "loading" }
  | { kind: "ready"; data: HealthResponse }
  | { kind: "error" };

const nav = ["Overview", "Members", "Teams", "Agents", "Security", "Audit log"];

export function App() {
  const [health, setHealth] = useState<HealthState>({ kind: "loading" });

  useEffect(() => {
    const controller = new AbortController();

    void getHealth(controller.signal)
      .then((data) => setHealth({ kind: "ready", data }))
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setHealth({ kind: "error" });
      });

    return () => controller.abort();
  }, []);

  return (
    <div className="app-root min-h-dvh bg-[var(--surface)] text-[var(--foreground)]">
      <header className="border-b border-[var(--border)] bg-[color-mix(in_oklab,var(--panel)_92%,transparent)] backdrop-blur-xl">
        <div className="mx-auto flex h-14 max-w-[1440px] items-center justify-between px-4 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="grid size-7 place-items-center rounded-lg bg-neutral-950 text-[11px] font-semibold text-white dark:bg-white dark:text-neutral-950">
              L
            </div>
            <div>
              <div className="text-sm font-semibold tracking-[-0.01em]">Lumi Agents</div>
              <div className="text-[11px] text-[var(--muted)]">Control plane</div>
            </div>
          </div>

          <button
            type="button"
            className="rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 py-1.5 text-xs font-medium shadow-xs outline-none transition hover:bg-[var(--panel-hover)] focus-visible:ring-2 focus-visible:ring-[var(--ring)]"
          >
            Lumi ▾
          </button>
        </div>
      </header>

      <div className="mx-auto grid max-w-[1440px] grid-cols-1 md:grid-cols-[220px_minmax(0,1fr)]">
        <aside className="hidden min-h-[calc(100dvh-3.5rem)] border-r border-[var(--border)] px-3 py-5 md:block">
          <nav aria-label="Control plane">
            <ul className="space-y-1">
              {nav.map((item, index) => (
                <li key={item}>
                  <button
                    type="button"
                    className={[
                      "w-full rounded-lg px-3 py-2 text-left text-sm outline-none transition focus-visible:ring-2 focus-visible:ring-[var(--ring)]",
                      index === 0
                        ? "bg-[var(--panel-strong)] font-medium"
                        : "text-[var(--muted-strong)] hover:bg-[var(--panel-hover)] hover:text-[var(--foreground)]",
                    ].join(" ")}
                  >
                    {item}
                  </button>
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
              <div className="flex items-center gap-2 text-xs text-[var(--muted-strong)]">
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
                  ? "API connected"
                  : health.kind === "error"
                    ? "API unavailable"
                    : "Checking API"}
              </div>
            </div>

            <section aria-label="Platform status" className="grid gap-3 md:grid-cols-3">
              <StatusCard eyebrow="Runtime" title="Cloudflare Workers" detail="Rust + Axum at the edge" />
              <StatusCard eyebrow="Interface" title="React + Base UI" detail="Accessible primitives, minimal client cost" />
              <StatusCard eyebrow="Build" title="Vite 8" detail="Rolldown-powered development loop" />
            </section>

            <section className="mt-8 overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]">
              <div className="border-b border-[var(--border)] px-5 py-4">
                <h2 className="text-sm font-semibold">Foundation</h2>
                <p className="mt-1 text-xs leading-5 text-[var(--muted)]">
                  The skeleton is intentionally small. Product complexity should be earned by real requirements.
                </p>
              </div>
              <div className="divide-y divide-[var(--border)]">
                <Row label="Backend" value="Axum 0.8 / workers-rs" />
                <Row label="Frontend" value="React 19.3 / Vite 8 / TypeScript 7" />
                <Row label="UI primitives" value="shadcn/ui / Base UI / Tailwind CSS 4" />
                <Row label="Repository" value="pnpm workspace / Cargo workspace" />
              </div>
            </section>
          </div>
        </main>
      </div>
    </div>
  );
}

function StatusCard({ eyebrow, title, detail }: { eyebrow: string; title: string; detail: string }) {
  return (
    <article className="rounded-2xl border border-[var(--border)] bg-[var(--panel)] p-5 shadow-[var(--shadow)]">
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
