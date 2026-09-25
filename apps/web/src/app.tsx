import { useCallback, useEffect, useRef, useState } from "react";

import { LumiMark } from "@/components/brand";
import { AuthScreen } from "@/features/auth/auth-screen";
import { OrgDashboard } from "@/features/organizations/org-dashboard";
import { getMe, logout, type MeResponse } from "@/lib/api";
import { ApiClientError, presentApiError } from "@/lib/errors";

type SessionState =
  | { kind: "loading" }
  | { kind: "anonymous" }
  | { kind: "authenticated"; me: MeResponse }
  | { kind: "error"; error: unknown };

export function App() {
  const [session, setSession] = useState<SessionState>({ kind: "loading" });
  const requestId = useRef(0);

  const loadSession = useCallback(async () => {
    const currentRequest = ++requestId.current;
    setSession({ kind: "loading" });
    try {
      const me = await getMe();
      if (currentRequest === requestId.current) setSession({ kind: "authenticated", me });
    } catch (error) {
      if (currentRequest !== requestId.current) return;
      if (error instanceof ApiClientError && error.status === 401) {
        setSession({ kind: "anonymous" });
      } else {
        setSession({ kind: "error", error });
      }
    }
  }, []);

  useEffect(() => {
    void loadSession();
  }, [loadSession]);

  async function signOut() {
    try {
      await logout();
    } catch (error) {
      if (!(error instanceof ApiClientError && error.status === 401)) {
        setSession({ kind: "error", error });
        return;
      }
    }
    setSession({ kind: "anonymous" });
  }

  if (session.kind === "loading") return <LoadingScreen />;
  if (session.kind === "anonymous")
    return <AuthScreen onAuthenticated={() => void loadSession()} />;
  if (session.kind === "error") {
    return <SessionError error={session.error} onRetry={() => void loadSession()} />;
  }
  return (
    <OrgDashboard
      me={session.me}
      onSignOut={() => void signOut()}
      onOrganizationsChanged={() => void loadSession()}
    />
  );
}

function LoadingScreen() {
  return (
    <main
      className="grid min-h-dvh place-items-center bg-[var(--surface)] px-4 text-[var(--foreground)]"
      aria-live="polite"
    >
      <div className="text-center">
        <LumiMark className="mx-auto size-12" />
        <p className="mt-4 text-sm text-[var(--muted-strong)]">Loading your workspace…</p>
      </div>
    </main>
  );
}

function SessionError({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  const presentation = presentApiError(error);
  return (
    <main className="grid min-h-dvh place-items-center bg-[var(--surface)] px-4 text-[var(--foreground)]">
      <section
        role="alert"
        className="w-full max-w-md rounded-xl border border-[var(--border)] bg-[var(--panel)] p-6 text-center shadow-[var(--shadow)]"
      >
        <h1 className="text-lg font-semibold text-[var(--civic-navy)]">{presentation.title}</h1>
        <p className="mt-2 text-sm leading-6 text-[var(--muted-strong)]">{presentation.message}</p>
        {presentation.requestId ? (
          <p className="mt-2 text-xs text-[var(--muted)]">Request {presentation.requestId}</p>
        ) : null}
        <button
          type="button"
          onClick={onRetry}
          className="mt-6 min-h-11 rounded-lg bg-[var(--lumi-blue)] px-4 text-sm font-semibold text-white outline-none hover:bg-[var(--lumi-blue-hover)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
        >
          Try again
        </button>
      </section>
    </main>
  );
}
