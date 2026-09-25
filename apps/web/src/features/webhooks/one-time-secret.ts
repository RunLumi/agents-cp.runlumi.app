/**
 * One-time secret handling.
 *
 * A webhook signing secret is returned exactly once, by create and by
 * rotate-secret. Lumi stores only encrypted ciphertext and a fingerprint, so
 * the plaintext cannot be recovered after this view is dismissed.
 *
 * The reducer is pure so the invariant is testable without a DOM:
 *
 *  - `reveal` replaces any previous value; there is at most one live secret;
 *  - `forget` drops it;
 *  - nothing is written to `sessionStorage`, `localStorage`, a cookie, the URL,
 *    a log, or an error message;
 *  - `dismissed` stays true after `forget`, so re-rendering cannot bring the
 *    value back.
 */

import { useCallback, useReducer } from "react";

export type OneTimeSecretReason = "created" | "rotated";

export interface OneTimeSecretState {
  readonly secret: string | null;
  readonly reason: OneTimeSecretReason | null;
  readonly dismissed: boolean;
}

export type OneTimeSecretAction =
  | { readonly type: "reveal"; readonly secret: string; readonly reason: OneTimeSecretReason }
  | { readonly type: "forget" };

export const INITIAL_ONE_TIME_SECRET: OneTimeSecretState = {
  secret: null,
  reason: null,
  dismissed: false,
};

export function oneTimeSecretReducer(
  state: OneTimeSecretState,
  action: OneTimeSecretAction,
): OneTimeSecretState {
  switch (action.type) {
    case "reveal":
      if (action.secret.length === 0) return state;
      return { secret: action.secret, reason: action.reason, dismissed: false };
    case "forget":
      if (state.secret === null && state.dismissed) return state;
      return { secret: null, reason: null, dismissed: true };
  }
}

export interface OneTimeSecret {
  readonly state: OneTimeSecretState;
  readonly reveal: (secret: string, reason: OneTimeSecretReason) => void;
  readonly forget: () => void;
}

export function useOneTimeSecret(): OneTimeSecret {
  const [state, dispatch] = useReducer(oneTimeSecretReducer, INITIAL_ONE_TIME_SECRET);
  const reveal = useCallback(
    (secret: string, reason: OneTimeSecretReason) => dispatch({ type: "reveal", secret, reason }),
    [],
  );
  const forget = useCallback(() => dispatch({ type: "forget" }), []);
  return { state, reveal, forget };
}

export function oneTimeSecretTitle(reason: OneTimeSecretReason | null): string {
  if (reason === "rotated") return "New signing secret — shown once";
  return "Signing secret — shown once";
}

export function oneTimeSecretWarning(reason: OneTimeSecretReason | null): string {
  if (reason === "rotated") {
    return "The previous secret stops verifying new deliveries immediately. Copy this value now: it is not stored in the control plane and cannot be shown again. If you lose it, rotate again.";
  }
  return "Copy this value now: it is not stored in the control plane and cannot be shown again. If you lose it, rotate the secret. Only the fingerprint and an encrypted version are retained.";
}
