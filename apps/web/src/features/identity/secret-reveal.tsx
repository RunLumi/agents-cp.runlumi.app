/**
 * The one-time key reveal dialog.
 *
 * Design constraints, all load bearing:
 *
 * - **No accidental dismissal.** There is no close button, no backdrop click, and
 *   Escape is cancelled. The only way out is an explicit acknowledgement that
 *   says what the operator is confirming. A dialog that closes on a stray Enter
 *   would lose the only copy of a credential that cannot be retrieved again.
 * - **No re-entry.** This component renders only when the reducer holds a
 *   `RevealedSecret`, and the only way it gets one is the create or rotate
 *   response. It has no fetch, no store lookup, and no "show again" affordance.
 * - **No persistence.** The value lives in the reducer's state and in this
 *   subtree. Nothing writes it to `localStorage`, `sessionStorage`, a cookie, the
 *   URL, or a log.
 */

import { useEffect, useRef, useState } from "react";

import {
  isRevealOpen,
  revealAcknowledgementLabel,
  revealTitle,
  revealWarning,
  type RevealState,
} from "./one-time-secret";
import { dangerButtonClass, Notice, secondaryButtonClass } from "./ui";

export function KeySecretReveal({
  state,
  onAcknowledge,
  onCopyFailed,
}: {
  state: RevealState;
  onAcknowledge: () => void;
  onCopyFailed: () => void;
}) {
  const open = isRevealOpen(state);
  const revealed = state.revealed;

  if (!open || !revealed) return null;

  return (
    <KeySecretRevealBody
      key={revealed.secret}
      secret={revealed.secret}
      reason={revealed.reason}
      keyName={revealed.keyName}
      keyPrefix={revealed.keyPrefix}
      notice={revealed.notice}
      onAcknowledge={onAcknowledge}
      onCopyFailed={onCopyFailed}
    />
  );
}

function KeySecretRevealBody({
  secret,
  reason,
  keyName,
  keyPrefix,
  notice,
  onAcknowledge,
  onCopyFailed,
}: {
  secret: string;
  reason: "created" | "rotated";
  keyName: string;
  keyPrefix: string;
  notice: string;
  onAcknowledge: () => void;
  onCopyFailed: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const headingRef = useRef<HTMLHeadingElement | null>(null);

  // Focus the heading, not the close control: the operator's next action is to
  // read, and the acknowledgement is a decision they should not make by reflex.
  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 4000);
    return () => window.clearTimeout(timer);
  }, [copied]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
    } catch {
      setCopied(false);
      onCopyFailed();
    }
  }

  return (
    <div className="fixed inset-0 z-40 grid place-items-center bg-[var(--civic-navy)]/40 p-4">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="identity-key-reveal-title"
        aria-describedby="identity-key-reveal-warning"
        className="w-full max-w-2xl overflow-hidden rounded-xl border border-[var(--danger)]/40 bg-[var(--panel)] shadow-[var(--shadow)]"
      >
        <div className="border-b border-[var(--danger)]/30 bg-[var(--danger)]/5 px-5 py-4">
          <p className="text-[11px] font-semibold tracking-[0.1em] text-[var(--danger)] uppercase">
            Shown once — not stored
          </p>
          <h3
            id="identity-key-reveal-title"
            ref={headingRef}
            tabIndex={-1}
            className="mt-2 text-lg font-semibold text-[var(--civic-navy)] outline-none"
          >
            {revealTitle(reason)}
          </h3>
          <p
            id="identity-key-reveal-warning"
            className="mt-1 max-w-2xl text-sm leading-5 text-[var(--civic-navy)]"
          >
            {revealWarning(reason)}
          </p>
        </div>

        <div className="space-y-4 px-5 py-4">
          <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
            <div>
              <dt className="text-xs font-medium text-[var(--muted)]">Key</dt>
              <dd className="mt-1 text-sm text-[var(--civic-navy)]">{keyName}</dd>
            </div>
            <div className="min-w-0">
              <dt className="text-xs font-medium text-[var(--muted)]">Public prefix</dt>
              <dd className="mt-1 break-all font-mono text-xs text-[var(--civic-navy)]">
                {keyPrefix}
              </dd>
            </div>
          </dl>

          <div>
            <p className="text-xs font-medium text-[var(--muted)]">Secret</p>
            <p className="mt-1.5 rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-3 font-mono text-sm break-all text-[var(--civic-navy)] select-all">
              {secret}
            </p>
          </div>

          <Notice>{notice}</Notice>

          <p className="text-xs leading-5 text-[var(--muted)]">
            Send it as <code className="font-mono">Authorization: Bearer {keyPrefix}…</code> from
            your CI or runner. It is never written to browser storage, the address bar, or any log,
            and it cannot be shown again from this or any other screen.
          </p>

          <div aria-live="polite" className="min-h-5 text-xs font-medium text-[var(--success)]">
            {copied ? "Copied to the clipboard." : ""}
          </div>

          <div className="flex flex-col gap-2 sm:flex-row">
            <button type="button" className={secondaryButtonClass} onClick={() => void copy()}>
              Copy secret
            </button>
            <button type="button" className={dangerButtonClass} onClick={onAcknowledge}>
              {revealAcknowledgementLabel(reason)}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
