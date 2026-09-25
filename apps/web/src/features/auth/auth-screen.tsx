import { useId, useState } from "react";

import { LumiWordmark } from "@/components/brand";
import {
  passkeyLoginComplete,
  passkeyLoginStart,
  passkeySignupComplete,
  passkeySignupStart,
  passwordLogin,
  passwordReset,
  passwordForgot,
  passwordSignup,
  type ChallengeResponse,
} from "@/lib/api";
import { presentApiError } from "@/lib/errors";
import { createPasskeyCredential, getPasskeyAssertion, passkeysSupported } from "@/lib/webauthn";

interface AuthScreenProps {
  onAuthenticated: () => void;
}

type Mode = "login" | "signup";
type Method = "passkey" | "password" | "code";

export function AuthScreen({ onAuthenticated }: AuthScreenProps) {
  const [mode, setMode] = useState<Mode>("login");
  const [method, setMethod] = useState<Method>("passkey");
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [challenge, setChallenge] = useState<ChallengeResponse | null>(null);
  const [recoveryChallenge, setRecoveryChallenge] = useState<ChallengeResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const emailId = useId();
  const nameId = useId();
  const passwordId = useId();
  const codeId = useId();
  const recoveryId = useId();

  const presentation = error === null ? null : presentApiError(error);
  const passkeyAvailable = passkeysSupported();

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mode === "signup" && method === "passkey") {
        const start = await passkeySignupStart({ email, display_name: displayName });
        const credential = await createPasskeyCredential(start.public_key);
        const result = await passkeySignupComplete({
          ceremony_id: start.ceremony_id,
          credential,
        });
        if (result.verification) {
          setChallenge(result.verification);
          setCode(result.verification.development_code ?? "");
          setMethod("code");
        } else {
          onAuthenticated();
        }
        return;
      }
      if (mode === "signup" && method === "password") {
        const result = await passwordSignup({ email, display_name: displayName, password });
        if (result.verification) {
          setChallenge(result.verification);
          setCode(result.verification.development_code ?? "");
          setMethod("code");
        } else {
          onAuthenticated();
        }
        return;
      }
      if (mode === "login" && method === "passkey") {
        const start = await passkeyLoginStart();
        const credential = await getPasskeyAssertion(start.public_key);
        await passkeyLoginComplete({ ceremony_id: start.ceremony_id, credential });
        onAuthenticated();
        return;
      }
      if (mode === "login" && method === "password") {
        await passwordLogin({ email, password });
        onAuthenticated();
        return;
      }
    } catch (requestError) {
      setError(requestError);
    } finally {
      setBusy(false);
    }
  }

  async function forgot() {
    setBusy(true);
    setError(null);
    try {
      const next = await passwordForgot({ email });
      setRecoveryChallenge(next);
      setCode(next.development_code ?? "");
    } catch (requestError) {
      setError(requestError);
    } finally {
      setBusy(false);
    }
  }

  async function reset(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!recoveryChallenge) return;
    setBusy(true);
    setError(null);
    try {
      await passwordReset({
        challenge_id: recoveryChallenge.challenge_id,
        code,
        password,
      });
      setRecoveryChallenge(null);
      setMethod("password");
    } catch (requestError) {
      setError(requestError);
    } finally {
      setBusy(false);
    }
  }

  function changeMode(nextMode: Mode) {
    setMode(nextMode);
    setMethod("passkey");
    setChallenge(null);
    setRecoveryChallenge(null);
    setCode("");
    setError(null);
  }

  return (
    <main className="grid min-h-dvh place-items-center bg-[var(--surface)] px-4 py-10 text-[var(--foreground)] sm:px-6">
      <section className="w-full max-w-md rounded-xl border border-[var(--border)] bg-[var(--panel)] p-6 shadow-[var(--shadow)] sm:p-8">
        <div className="mb-8">
          <LumiWordmark className="h-9 w-auto" />
          <h1 className="mt-5 text-2xl font-semibold tracking-[-0.03em] text-[var(--civic-navy)]">
            {mode === "login" ? "Sign in to your workspace" : "Create your Lumi account"}
          </h1>
          <p className="mt-2 text-sm leading-6 text-[var(--muted-strong)]">
            {method === "code"
              ? "Enter the verification code sent to your email. Development builds may show it below."
              : "Passkeys are the primary sign-in method. Email and password remain available as fallback."}
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

        {method === "code" && challenge ? (
          <div className="space-y-4">
            <p className="text-sm text-[var(--muted-strong)]">
              Verification required for {email || "your email"}. Complete this step, then sign in
              with your new passkey or password.
            </p>
            {challenge.development_code ? (
              <div className="rounded-lg border border-[var(--lumi-blue)]/30 bg-[var(--lumi-blue-soft)] p-3 text-sm text-[var(--civic-navy)]">
                <p className="font-medium">Development verification code</p>
                <code className="mt-1 block break-all text-xs">{challenge.development_code}</code>
              </div>
            ) : null}
            <button type="button" onClick={() => changeMode("login")} className={primaryClass}>
              Continue to sign in
            </button>
          </div>
        ) : recoveryChallenge ? (
          <form onSubmit={(event) => void reset(event)} className="space-y-4">
            <Field label="Reset code" id={recoveryId}>
              <input
                id={recoveryId}
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                required
                value={code}
                onChange={(event) => setCode(event.target.value)}
                className={inputClass}
                placeholder="Enter reset code"
              />
            </Field>
            <Field label="New password" id={passwordId}>
              <input
                id={passwordId}
                type="password"
                autoComplete="new-password"
                required
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className={inputClass}
                placeholder="Choose a password"
              />
            </Field>
            {presentation ? (
              <ErrorAlert message={presentation.message} requestId={presentation.requestId} />
            ) : null}
            <button type="submit" disabled={busy} className={primaryClass}>
              {busy ? "Working…" : "Reset password"}
            </button>
            <button
              type="button"
              onClick={() => setRecoveryChallenge(null)}
              className={secondaryClass}
            >
              Back to sign in
            </button>
          </form>
        ) : (
          <form onSubmit={(event) => void submit(event)} className="space-y-4">
            {mode === "login" && method === "passkey" ? (
              <>
                {!passkeyAvailable ? (
                  <p
                    role="note"
                    className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-3 text-sm text-[var(--muted-strong)]"
                  >
                    This browser does not expose passkeys. Use email and password below without a
                    dead-end.
                  </p>
                ) : null}
                <button type="submit" disabled={busy || !passkeyAvailable} className={primaryClass}>
                  {busy ? "Waiting for authenticator…" : "Sign in with passkey"}
                </button>
                <Separator label="or use password" />
                <Field label="Email" id={emailId}>
                  <input
                    id={emailId}
                    type="email"
                    autoComplete="username webauthn"
                    required={false}
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    className={inputClass}
                    placeholder="you@company.com"
                  />
                </Field>
                <Field label="Password" id={passwordId}>
                  <input
                    id={passwordId}
                    type="password"
                    autoComplete="current-password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    className={inputClass}
                    placeholder="Your password"
                  />
                </Field>
                <button
                  type="button"
                  disabled={busy || !email || !password}
                  onClick={() => {
                    setMethod("password");
                    requestAnimationFrame(() => {
                      const form = document.querySelector("form");
                      form?.requestSubmit();
                    });
                  }}
                  className={secondaryClass}
                >
                  Sign in with password
                </button>
                <button
                  type="button"
                  disabled={busy || !email}
                  onClick={() => void forgot()}
                  className={linkClass}
                >
                  Forgot password?
                </button>
              </>
            ) : null}

            {mode === "signup" && method === "passkey" ? (
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
                <button type="submit" disabled={busy || !passkeyAvailable} className={primaryClass}>
                  {busy ? "Waiting for authenticator…" : "Create account with passkey"}
                </button>
                {!passkeyAvailable ? (
                  <p role="note" className="text-sm text-[var(--muted-strong)]">
                    Passkeys are unavailable here. Continue with password below.
                  </p>
                ) : null}
                <Separator label="or use password" />
                <button
                  type="button"
                  onClick={() => setMethod("password")}
                  className={secondaryClass}
                >
                  Continue with password
                </button>
              </>
            ) : null}

            {method === "password" && mode === "signup" ? (
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
                <Field label="Password" id={passwordId}>
                  <input
                    id={passwordId}
                    type="password"
                    autoComplete="new-password"
                    required
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    className={inputClass}
                    placeholder="Choose a password"
                  />
                </Field>
                <button type="submit" disabled={busy} className={primaryClass}>
                  {busy ? "Working…" : "Create account with password"}
                </button>
                <button
                  type="button"
                  onClick={() => setMethod("passkey")}
                  className={secondaryClass}
                >
                  Back to passkey
                </button>
              </>
            ) : null}

            {challenge?.development_code ? (
              <div className="rounded-lg border border-[var(--lumi-blue)]/30 bg-[var(--lumi-blue-soft)] p-3 text-sm text-[var(--civic-navy)]">
                <p className="font-medium">Development verification code</p>
                <code className="mt-1 block break-all text-xs">{challenge.development_code}</code>
              </div>
            ) : null}

            {presentation ? (
              <ErrorAlert message={presentation.message} requestId={presentation.requestId} />
            ) : null}

            {method === "password" && mode === "login" && password === "" ? (
              <input type="hidden" value="" readOnly />
            ) : null}
          </form>
        )}

        {method === "code" && code ? (
          <div className="mt-4">
            <Field label="One-time code" id={codeId}>
              <input
                id={codeId}
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={code}
                onChange={(event) => setCode(event.target.value)}
                className={inputClass}
                placeholder="Enter code"
              />
            </Field>
          </div>
        ) : null}

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

function Separator({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-3 text-xs text-[var(--muted)]" aria-hidden="true">
      <span className="h-px flex-1 bg-[var(--border)]" />
      <span>{label}</span>
      <span className="h-px flex-1 bg-[var(--border)]" />
    </div>
  );
}

function ErrorAlert({ message, requestId }: { message: string; requestId: string | undefined }) {
  return (
    <p
      role="alert"
      className="rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/5 p-3 text-sm text-[var(--danger)]"
    >
      {message}
      {requestId ? (
        <span className="mt-1 block text-xs opacity-75">Request {requestId}</span>
      ) : null}
    </p>
  );
}

const inputClass =
  "min-h-11 w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-3 text-sm outline-none transition placeholder:text-[var(--muted)] focus-visible:border-[var(--lumi-blue)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--panel)]";
const primaryClass =
  "min-h-11 w-full rounded-lg bg-[var(--lumi-blue)] px-4 py-2 text-sm font-semibold text-white shadow-[var(--shadow-button)] outline-none transition hover:bg-[var(--lumi-blue-hover)] active:translate-y-px focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--panel)] disabled:cursor-not-allowed disabled:opacity-50";
const secondaryClass =
  "min-h-11 w-full rounded-lg border border-[var(--border)] bg-[var(--panel)] px-4 py-2 text-sm font-medium text-[var(--civic-navy)] outline-none transition hover:bg-[var(--panel-hover)] active:translate-y-px focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";
const linkClass =
  "mx-auto block min-h-10 text-sm text-[var(--lumi-blue)] underline-offset-4 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-[var(--ring)] disabled:cursor-not-allowed disabled:opacity-50";

function tabClass(active: boolean): string {
  return [
    "min-h-10 rounded-md px-3 text-sm font-medium outline-none transition focus-visible:ring-2 focus-visible:ring-[var(--ring)]",
    active
      ? "bg-[var(--panel)] text-[var(--civic-navy)] shadow-[var(--shadow)]"
      : "text-[var(--muted)] hover:text-[var(--foreground)]",
  ].join(" ");
}
