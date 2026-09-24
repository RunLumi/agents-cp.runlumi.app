import { useId, useState } from "react";

import { loginComplete, loginStart, signup, verifyEmail, type ChallengeResponse } from "@/lib/api";
import { presentApiError } from "@/lib/errors";

interface AuthScreenProps {
  onAuthenticated: () => void;
}

type Mode = "login" | "signup";
type Stage = "email" | "code";

export function AuthScreen({ onAuthenticated }: AuthScreenProps) {
  const [mode, setMode] = useState<Mode>("login");
  const [stage, setStage] = useState<Stage>("email");
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [code, setCode] = useState("");
  const [challenge, setChallenge] = useState<ChallengeResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const emailId = useId();
  const nameId = useId();
  const codeId = useId();

  const presentation = error === null ? null : presentApiError(error);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (stage === "email") {
        const nextChallenge =
          mode === "signup"
            ? (await signup({ email, display_name: displayName })).verification
            : await loginStart({ email });
        if (!nextChallenge) throw new Error("The sign-in challenge was not returned.");
        setChallenge(nextChallenge);
        setCode(nextChallenge.development_code ?? "");
        setStage("code");
      } else if (mode === "signup") {
        if (!challenge) throw new Error("The verification challenge is missing.");
        await verifyEmail({ challenge_id: challenge.challenge_id, code });
        const loginChallenge = await loginStart({ email });
        setMode("login");
        setChallenge(loginChallenge);
        setCode(loginChallenge.development_code ?? "");
      } else {
        if (!challenge) throw new Error("The sign-in challenge is missing.");
        await loginComplete({ challenge_id: challenge.challenge_id, code });
        onAuthenticated();
      }
    } catch (requestError) {
      setError(requestError);
    } finally {
      setBusy(false);
    }
  }

  function changeMode(nextMode: Mode) {
    setMode(nextMode);
    setStage("email");
    setChallenge(null);
    setCode("");
    setError(null);
  }

  return (
    <main className="grid min-h-dvh place-items-center bg-[var(--surface)] px-4 py-10 text-[var(--foreground)] sm:px-6">
      <section className="w-full max-w-md rounded-2xl border border-[var(--border)] bg-[var(--panel)] p-6 shadow-[var(--shadow)] sm:p-8">
        <div className="mb-8">
          <p className="text-xs font-semibold tracking-[0.12em] text-[var(--lumi-blue)]">
            LUMI AGENTS
          </p>
          <h1 className="mt-3 text-2xl font-semibold tracking-[-0.03em]">
            {mode === "login" ? "Sign in to your workspace" : "Create your Lumi account"}
          </h1>
          <p className="mt-2 text-sm leading-6 text-[var(--muted-strong)]">
            {stage === "email"
              ? "Use a verified email to access your organizations and teams."
              : "Enter the one-time code sent to your email. Development builds may show it below."}
          </p>
        </div>

        <div
          className="mb-6 grid grid-cols-2 rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-1"
          role="tablist"
          aria-label="Authentication mode"
        >
          <button
            type="button"
            role="tab"
            aria-selected={mode === "login"}
            onClick={() => changeMode("login")}
            className={tabClass(mode === "login")}
          >
            Sign in
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={mode === "signup"}
            onClick={() => changeMode("signup")}
            className={tabClass(mode === "signup")}
          >
            Create account
          </button>
        </div>

        <form onSubmit={(event) => void submit(event)} className="space-y-4">
          {stage === "email" ? (
            <>
              <Field label="Email" id={emailId}>
                <input
                  id={emailId}
                  type="email"
                  autoComplete="email"
                  required
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  className={inputClass}
                  placeholder="you@company.com"
                />
              </Field>
              {mode === "signup" ? (
                <Field label="Name" id={nameId}>
                  <input
                    id={nameId}
                    type="text"
                    autoComplete="name"
                    required
                    value={displayName}
                    onChange={(event) => setDisplayName(event.target.value)}
                    className={inputClass}
                    placeholder="Your name"
                  />
                </Field>
              ) : null}
            </>
          ) : (
            <Field label="One-time code" id={codeId}>
              <input
                id={codeId}
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                required
                value={code}
                onChange={(event) => setCode(event.target.value)}
                className={inputClass}
                placeholder="Enter code"
              />
            </Field>
          )}

          {challenge?.development_code ? (
            <div className="rounded-lg border border-[var(--lumi-blue)]/30 bg-[var(--lumi-blue-soft)] p-3 text-sm text-[var(--civic-navy)]">
              <p className="font-medium">Development verification code</p>
              <code className="mt-1 block break-all text-xs">{challenge.development_code}</code>
            </div>
          ) : null}

          {presentation ? (
            <p
              role="alert"
              className="rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/5 p-3 text-sm text-[var(--danger)]"
            >
              {presentation.message}
              {presentation.requestId ? (
                <span className="mt-1 block text-xs opacity-75">
                  Request {presentation.requestId}
                </span>
              ) : null}
            </p>
          ) : null}

          <button type="submit" disabled={busy} className={primaryClass}>
            {busy
              ? "Working…"
              : stage === "email"
                ? mode === "login"
                  ? "Send sign-in code"
                  : "Create account"
                : mode === "signup" && stage === "code"
                  ? "Verify email"
                  : "Complete sign in"}
          </button>
        </form>

        <p className="mt-6 text-center text-xs leading-5 text-[var(--muted)]">
          By continuing, you agree to your organization&apos;s access and security policies.
        </p>
      </section>
    </main>
  );
}

function Field({ label, id, children }: { label: string; id: string; children: React.ReactNode }) {
  return (
    <div>
      <label htmlFor={id} className="mb-1.5 block text-sm font-medium text-[var(--civic-navy)]">
        {label}
      </label>
      {children}
    </div>
  );
}

const inputClass =
  "min-h-11 w-full rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 text-sm outline-none transition placeholder:text-[var(--muted)] focus-visible:border-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--panel)]";
const primaryClass =
  "min-h-11 w-full rounded-lg bg-[var(--lumi-blue)] px-4 py-2 text-sm font-semibold text-white outline-none transition hover:bg-[var(--lumi-blue-hover)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--panel)] disabled:cursor-not-allowed disabled:opacity-50";

function tabClass(active: boolean): string {
  return [
    "min-h-10 rounded-md px-3 text-sm font-medium outline-none transition focus-visible:ring-2 focus-visible:ring-[var(--ring)]",
    active
      ? "bg-[var(--panel)] text-[var(--civic-navy)] shadow-[var(--shadow)]"
      : "text-[var(--muted)] hover:text-[var(--foreground)]",
  ].join(" ");
}
