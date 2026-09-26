/**
 * One-time API key reveal.
 *
 * F14-002 and P07-CG: the secret is returned exactly once, by create and by
 * rotate, and the server persists only a hash, the prefix, and a fingerprint. A
 * compromise of the `api_keys` table therefore yields no usable credential, and
 * the browser is the only place the plaintext ever exists.
 *
 * The reducer is pure so the invariant is testable without a DOM, and it is the
 * reason the reveal cannot be re-entered:
 *
 *  - `reveal` is the ONLY action that can put a secret into state, and only the
 *    create and rotate response handlers dispatch it. A list refresh, a re-read,
 *    a re-render, a back navigation, and a remount all dispatch nothing.
 *  - `acknowledge` is the only way out, it clears the value, and it is terminal:
 *    there is no `restore`, no `reopen`, and no derived value.
 *  - nothing is written to `localStorage`, `sessionStorage`, a cookie, the URL,
 *    or a log. A test asserts the absence of those.
 */

import { useCallback, useReducer } from "react";

export type RevealReason = "created" | "rotated";

export interface RevealedSecret {
  readonly secret: string;
  readonly reason: RevealReason;
  /** Shown next to the secret so an operator can tell which key it belongs to. */
  readonly keyName: string;
  readonly keyPrefix: string;
  /** The server's own one-time notice, rendered verbatim. */
  readonly notice: string;
}

export interface RevealState {
  readonly revealed: RevealedSecret | null;
  readonly acknowledged: boolean;
}

export type RevealAction =
  | { readonly type: "reveal"; readonly secret: RevealedSecret }
  | { readonly type: "acknowledge" };

export const INITIAL_REVEAL_STATE: RevealState = { revealed: null, acknowledged: false };

export function revealSecretReducer(state: RevealState, action: RevealAction): RevealState {
  switch (action.type) {
    case "reveal": {
      // An empty secret is a contract violation, not a reveal. Ignoring it keeps
      // the dialog from opening on nothing, which would train an operator to
      // dismiss a panel that matters.
      if (action.secret.secret.length === 0) return state;
      return { revealed: action.secret, acknowledged: false };
    }
    case "acknowledge":
      if (state.revealed === null) return state;
      return { revealed: null, acknowledged: true };
  }
}

export interface SecretReveal {
  readonly state: RevealState;
  readonly reveal: (secret: RevealedSecret) => void;
  readonly acknowledge: () => void;
}

export function useSecretReveal(): SecretReveal {
  const [state, dispatch] = useReducer(revealSecretReducer, INITIAL_REVEAL_STATE);
  const reveal = useCallback((secret: RevealedSecret) => dispatch({ type: "reveal", secret }), []);
  const acknowledge = useCallback(() => dispatch({ type: "acknowledge" }), []);
  return { state, reveal, acknowledge };
}

export function revealTitle(reason: RevealReason | null): string {
  if (reason === "rotated") return "Replacement key created — shown once";
  return "Key created — shown once";
}

export function revealWarning(reason: RevealReason | null): string {
  if (reason === "rotated") {
    return "The previous key stopped working when this one was created. Copy this value now: it is not stored anywhere in Lumi and cannot be shown again. If you lose it, rotate the replacement.";
  }
  return "Copy this value now. Lumi keeps only a hash, the public prefix, and a fingerprint, so this secret cannot be recovered or re-sent. If you lose it, revoke the key and create another.";
}

export function revealAcknowledgementLabel(reason: RevealReason | null): string {
  if (reason === "rotated") return "I have stored the replacement key — close";
  return "I have stored this key — close";
}

/** True while the dialog must be shown. The ONLY path to it is a create/rotate. */
export function isRevealOpen(state: RevealState): boolean {
  return state.revealed !== null;
}
