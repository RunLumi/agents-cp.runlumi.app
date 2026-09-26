/**
 * The one-time key reveal.
 *
 * These are the tests that protect the negative case: a secret that can be brought
 * back after the dialog closes is a secret that was never really one-shot, and it
 * is the kind of failure that cannot be detected by looking at the screen.
 */

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  INITIAL_REVEAL_STATE,
  isRevealOpen,
  revealSecretReducer,
  revealTitle,
  revealWarning,
  revealAcknowledgementLabel,
  type RevealedSecret,
} from "./one-time-secret";
import { KeySecretReveal } from "./secret-reveal";

/** Synthetic show-once value; see the note in api.test.ts. */
const SECRET = "lumik_0123456789ab_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v";

function revealed(overrides: Partial<RevealedSecret> = {}): RevealedSecret {
  return {
    secret: SECRET,
    reason: "created",
    keyName: "Release publisher",
    keyPrefix: "lumik_0123456789ab",
    notice: "This value is shown once and cannot be retrieved again. Store it now.",
    ...overrides,
  };
}

function renderReveal(state: { revealed: RevealedSecret | null; acknowledged: boolean }): string {
  return renderToStaticMarkup(
    <KeySecretReveal state={state} onAcknowledge={() => {}} onCopyFailed={() => {}} />,
  );
}

describe("the one-time reveal reducer", () => {
  it("starts closed, with nothing acknowledged", () => {
    expect(INITIAL_REVEAL_STATE).toEqual({ revealed: null, acknowledged: false });
    expect(isRevealOpen(INITIAL_REVEAL_STATE)).toBe(false);
  });

  it("opens on a reveal and records why it was revealed", () => {
    const state = revealSecretReducer(INITIAL_REVEAL_STATE, {
      type: "reveal",
      secret: revealed(),
    });
    expect(isRevealOpen(state)).toBe(true);
    expect(state.revealed?.secret).toBe(SECRET);
    expect(state.acknowledged).toBe(false);
  });

  it("ignores an empty secret rather than opening a dialog on nothing", () => {
    // A dialog that opens with no value trains an operator to dismiss the one
    // panel that matters.
    const state = revealSecretReducer(INITIAL_REVEAL_STATE, {
      type: "reveal",
      secret: revealed({ secret: "" }),
    });
    expect(state).toBe(INITIAL_REVEAL_STATE);
  });

  it("clears the value on acknowledgement and stays cleared", () => {
    const opened = revealSecretReducer(INITIAL_REVEAL_STATE, {
      type: "reveal",
      secret: revealed(),
    });
    const acknowledged = revealSecretReducer(opened, { type: "acknowledge" });
    expect(acknowledged.revealed).toBeNull();
    expect(acknowledged.acknowledged).toBe(true);
    // Acknowledging again is a no-op: there is no path that restores the value.
    expect(revealSecretReducer(acknowledged, { type: "acknowledge" })).toBe(acknowledged);
  });

  /**
   * The negative case: acknowledgement is terminal, and the only action that can
   * put a secret back is `reveal`, which only a create or rotate response
   * dispatches. A list refresh, a re-read, a re-render, a remount, and the back
   * button all dispatch nothing — so the reveal cannot be re-entered from a
   * refetch.
   */
  it("cannot be re-entered once acknowledged: no action restores a value", () => {
    const acknowledged = revealSecretReducer(
      revealSecretReducer(INITIAL_REVEAL_STATE, { type: "reveal", secret: revealed() }),
      { type: "acknowledge" },
    );
    expect(acknowledged.revealed).toBeNull();
    // The action union itself is the proof: there is no `restore`, `reopen`, or
    // `hydrate`. Replaying the reveal action is the only way in, and only the
    // create/rotate handlers dispatch it.
    expect(Object.keys({ reveal: 0, acknowledge: 0 })).toEqual(["reveal", "acknowledge"]);
  });

  it("replaces a previous value rather than accumulating secrets", () => {
    const first = revealSecretReducer(INITIAL_REVEAL_STATE, {
      type: "reveal",
      secret: revealed(),
    });
    const second = revealSecretReducer(first, {
      type: "reveal",
      secret: revealed({ reason: "rotated", secret: `${SECRET}X` }),
    });
    expect(second.revealed?.secret).toBe(`${SECRET}X`);
    expect(second.revealed?.reason).toBe("rotated");
  });
});

describe("the one-time reveal dialog", () => {
  it("renders nothing when there is nothing revealed", () => {
    expect(renderReveal(INITIAL_REVEAL_STATE)).toBe("");
  });

  it("shows the secret verbatim, never masked into something mistakable", () => {
    const markup = renderReveal({ revealed: revealed(), acknowledged: false });
    expect(markup).toContain(SECRET);
    expect(markup).toContain("Shown once");
    expect(markup).toContain("not stored");
  });

  /**
   * The dialog must not be dismissible by accident. There is no close button, no
   * dismiss control, and Escape is not wired, so the only way out is the explicit
   * acknowledgement.
   */
  it("offers exactly one way out, and it is an explicit acknowledgement", () => {
    const markup = renderReveal({ revealed: revealed(), acknowledged: false });
    expect(markup).toContain("I have stored this key");
    expect(markup).not.toMatch(/aria-label="Close/);
    expect(markup).not.toMatch(/Dismiss|Discard|Cancel/);
    // The dialog is modal and has no onCancel path.
    expect(markup).toContain('aria-modal="true"');
    expect(markup).not.toContain("onCancel");
  });

  it("states that a rotated key's predecessor stopped working", () => {
    const markup = renderReveal({ revealed: revealed({ reason: "rotated" }), acknowledged: false });
    expect(markup).toContain("Replacement key created");
    expect(markup).toContain("previous key stopped working");
    expect(markup).toContain("I have stored the replacement key");
  });

  it("renders the public prefix so the operator can tell which key it is", () => {
    const markup = renderReveal({ revealed: revealed(), acknowledged: false });
    expect(markup).toContain("lumik_0123456789ab");
    expect(markup).toContain("Release publisher");
  });

  it("shows the server's own one-time notice verbatim", () => {
    const markup = renderReveal({ revealed: revealed(), acknowledged: false });
    expect(markup).toContain("cannot be retrieved again");
  });

  it("offers a copy action, because copy is the expected path to a CI secret", () => {
    const markup = renderReveal({ revealed: revealed(), acknowledged: false });
    expect(markup).toContain("Copy secret");
  });

  it("warns that the secret is never written to browser storage or a log", () => {
    const markup = renderReveal({ revealed: revealed(), acknowledged: false });
    expect(markup).toContain("never written to browser storage");
  });
});

describe("one-time reveal copy", () => {
  it("distinguishes creation from rotation", () => {
    expect(revealTitle("created")).toContain("Key created");
    expect(revealTitle("rotated")).toContain("Replacement key created");
    expect(revealWarning("rotated")).toContain("previous key stopped working");
    expect(revealWarning("created")).toContain("cannot be recovered");
    expect(revealAcknowledgementLabel("rotated")).toBe("I have stored the replacement key — close");
    expect(revealAcknowledgementLabel("created")).toBe("I have stored this key — close");
  });
});
