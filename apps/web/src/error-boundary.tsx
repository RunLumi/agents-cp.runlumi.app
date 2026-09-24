import { Component, type ReactNode } from "react";

interface AppErrorBoundaryProps {
  children: ReactNode;
}

interface AppErrorBoundaryState {
  hasError: boolean;
}

/** Catch render/lifecycle failures and keep a keyboard-accessible recovery path. */
export class AppErrorBoundary extends Component<AppErrorBoundaryProps, AppErrorBoundaryState> {
  state: AppErrorBoundaryState = { hasError: false };

  static getDerivedStateFromError(): AppErrorBoundaryState {
    return { hasError: true };
  }

  render() {
    if (!this.state.hasError) return this.props.children;

    return (
      <main
        role="alert"
        aria-labelledby="app-error-title"
        className="grid min-h-dvh place-items-center bg-[var(--surface)] px-5 py-12 text-[var(--foreground)]"
      >
        <section className="w-full max-w-lg rounded-xl border border-[var(--border)] bg-[var(--panel)] p-6 shadow-[var(--shadow)] sm:p-8">
          <p className="text-xs font-semibold tracking-[0.08em] text-[var(--muted)]">LUMI AGENTS</p>
          <h1 id="app-error-title" className="mt-3 text-xl font-semibold tracking-[-0.025em]">
            The control plane could not load
          </h1>
          <p className="mt-2 text-sm leading-6 text-[var(--muted-strong)]">
            Reload the page to try again. If the problem continues, contact your administrator.
          </p>
          <button
            type="button"
            onClick={() => window.location.reload()}
            className="mt-5 min-h-11 rounded-lg bg-[var(--lumi-blue)] px-4 py-2 text-sm font-medium text-white outline-none transition hover:bg-[var(--lumi-blue-hover)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--surface)]"
          >
            Reload page
          </button>
        </section>
      </main>
    );
  }
}
