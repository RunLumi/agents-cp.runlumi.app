/**
 * One-time secret reveal.
 *
 * The value is rendered exactly as returned, never masked into something that
 * could be mistaken for the real secret, and never persisted. Dismissing the
 * panel clears it from React state; there is no way to bring it back from this
 * surface.
 */

import { useEffect, useRef, useState } from "react";

import { dangerButtonClass, secondaryButtonClass } from "./ui";
import {
  oneTimeSecretTitle,
  oneTimeSecretWarning,
  type OneTimeSecretState,
} from "./one-time-secret";

export function SecretReveal({
  state,
  onForget,
}: {
  state: OneTimeSecretState;
  onForget: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const headingRef = useRef<HTMLHeadingElement | null>(null);
  const secret = state.secret;

  useEffect(() => {
    if (secret) headingRef.current?.focus();
  }, [secret]);

  useEffect(() => {
    setCopied(false);
  }, [secret]);

  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 4000);
    return () => window.clearTimeout(timer);
  }, [copied]);

  if (!secret) return null;

  async function copy() {
    if (!secret) return;
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <section
      role="alert"
      aria-labelledby="webhook-secret-reveal-title"
      className="overflow-hidden rounded-xl border border-[var(--danger)]/30 border-l-[3px] border-l-[var(--danger)] bg-[var(--panel)] shadow-[var(--shadow)]"
    >
      <div className="border-b border-[var(--danger)]/25 bg-[var(--danger)]/5 px-5 py-4">
        <p className="text-xs font-semibold tracking-[0.1em] text-[var(--danger)]">SHOWN ONCE</p>
        <h3
          id="webhook-secret-reveal-title"
          ref={headingRef}
          tabIndex={-1}
          className="mt-2 text-base font-semibold text-[var(--civic-navy)] outline-none"
        >
          {oneTimeSecretTitle(state.reason)}
        </h3>
        <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--muted-strong)]">
          {oneTimeSecretWarning(state.reason)}
        </p>
      </div>
      <div className="space-y-4 px-5 py-4">
        <div>
          <p className="text-xs font-medium text-[var(--muted)]">Signing secret</p>
          <p className="mt-1.5 select-all break-all rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-3 font-mono text-sm text-[var(--civic-navy)]">
            {secret}
          </p>
        </div>
        <p className="text-xs leading-5 text-[var(--muted-strong)]">
          Verify the signature with{" "}
          <code className="font-mono">
            HMAC-SHA256(secret, timestamp + &quot;.&quot; + event_id + &quot;.&quot; + raw_body)
          </code>{" "}
          and compare it to the <code className="font-mono">X-Lumi-Signature</code> header. Reject
          timestamps outside the endpoint replay window. Deduplicate on the stable event ID.
        </p>
        <div aria-live="polite" className="text-xs font-medium text-[var(--success)]">
          {copied ? "Copied to the clipboard." : ""}
        </div>
        <div className="flex flex-col gap-2 sm:flex-row">
          <button type="button" className={secondaryButtonClass} onClick={() => void copy()}>
            Copy secret
          </button>
          <button type="button" className={dangerButtonClass} onClick={onForget}>
            I have stored it — hide and forget
          </button>
        </div>
        <p className="text-xs leading-5 text-[var(--muted)]">
          Hiding clears this value from the page. It is never written to browser storage, the URL,
          or any log.
        </p>
      </div>
    </section>
  );
}
