import { describe, expect, it } from "vitest";

import {
  INITIAL_ONE_TIME_SECRET,
  oneTimeSecretReducer,
  oneTimeSecretTitle,
  oneTimeSecretWarning,
} from "./one-time-secret";

/**
 * Synthetic signing values for the show-once-secret tests. These are NOT real
 * credentials and are never sent anywhere: they only stand in for whatever the
 * server returned once, so the test can prove the plaintext is held, rotated,
 * and then dropped.
 */
const FIRST_ISSUED = "fixture-signing-value-first";
const SECOND_ISSUED = "fixture-signing-value-second";
const ONLY_ONCE = "fixture-signing-value-only_once";

describe("one-time secret lifecycle", () => {
  it("starts with no secret and no reason", () => {
    expect(INITIAL_ONE_TIME_SECRET).toEqual({ secret: null, reason: null, dismissed: false });
  });

  it("holds at most one live secret and records why it was issued", () => {
    const created = oneTimeSecretReducer(INITIAL_ONE_TIME_SECRET, {
      type: "reveal",
      secret: FIRST_ISSUED,
      reason: "created",
    });
    expect(created).toEqual({
      secret: FIRST_ISSUED,
      reason: "created",
      dismissed: false,
    });

    const rotated = oneTimeSecretReducer(created, {
      type: "reveal",
      secret: SECOND_ISSUED,
      reason: "rotated",
    });
    expect(rotated.secret).toBe(SECOND_ISSUED);
    expect(rotated.reason).toBe("rotated");
  });

  it("drops the plaintext on forget so it cannot be re-rendered", () => {
    const revealed = oneTimeSecretReducer(INITIAL_ONE_TIME_SECRET, {
      type: "reveal",
      secret: ONLY_ONCE,
      reason: "created",
    });
    const forgotten = oneTimeSecretReducer(revealed, { type: "forget" });
    expect(forgotten.secret).toBeNull();
    expect(forgotten.reason).toBeNull();
    expect(forgotten.dismissed).toBe(true);

    // Re-rendering the same action must not resurrect a previous value.
    const redrawn = oneTimeSecretReducer(forgotten, { type: "forget" });
    expect(redrawn).toBe(forgotten);
  });

  it("ignores an empty reveal instead of storing a blank secret", () => {
    const result = oneTimeSecretReducer(INITIAL_ONE_TIME_SECRET, {
      type: "reveal",
      secret: "",
      reason: "created",
    });
    expect(result).toBe(INITIAL_ONE_TIME_SECRET);
  });

  it("says the value cannot be recovered, in both create and rotation wording", () => {
    expect(oneTimeSecretTitle("created")).toBe("Signing secret — shown once");
    expect(oneTimeSecretTitle("rotated")).toBe("New signing secret — shown once");
    expect(oneTimeSecretWarning("created")).toContain("cannot be shown again");
    expect(oneTimeSecretWarning("rotated")).toContain("previous secret stops verifying");
  });
});
