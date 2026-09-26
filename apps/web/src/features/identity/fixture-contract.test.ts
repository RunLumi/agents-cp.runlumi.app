/**
 * The frozen `p07-contracts-v1.json` machine-identity blocks, decoded by the
 * REAL decoders.
 *
 * WHY A SEPARATE FILE, following the P06 precedent in
 * `features/data-governance/api.test.ts`. The rest of this suite hand-writes wire
 * bodies, which is the right way to cover malformed input and the wrong way to
 * pin a contract: a hand-written body is whatever the author believed, so the
 * decoders and the server can drift together and every test still passes. This
 * file takes the shapes from the document `P07-CG.md` §Fixtures froze BEFORE the
 * backend existed, so a projection change on either side fails here.
 *
 * The fixture carries `_note` / `_expected` / `_derivation` keys next to its data.
 * They are the reasoning, and `stripped` removes them rather than ignoring them,
 * so an annotation can never satisfy a data assertion.
 */

import { describe, expect, it } from "vitest";

import fixture from "../../../../../docs/implementation/fixtures/p07-contracts-v1.json";

import { API_KEY_PREFIX_PATTERN, decodeApiKey, decodeServiceAccount } from "./api";
import {
  MACHINE_CAPABILITIES,
  describeScope,
  isHumanOnlyCapability,
  normalizeCapabilities,
  unknownCapabilities,
} from "./capabilities";

/** The fixture's annotations are not wire fields; a decoder must never see them. */
function stripped(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripped);
  if (typeof value !== "object" || value === null) return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key]) => !key.startsWith("_"))
      .map(([key, entry]) => [key, stripped(entry)]),
  );
}

describe("the frozen service account", () => {
  const body = fixture.service_account as Record<string, unknown>;

  it("decodes field-for-field with nothing dropped and nothing added", () => {
    const decoded = decodeServiceAccount(stripped(body));
    expect(decoded).toBeDefined();
    // Exact equality, not a field-by-field walk: an allowlist decoder that quietly
    // stopped copying a field would otherwise pass, because "defined" is all the
    // assertions above it check.
    expect(decoded).toEqual(stripped(body));
  });

  it("is a shape the capability helpers accept, and the set is normalized", () => {
    const declared = body.capabilities as string[];
    const capabilities = normalizeCapabilities(declared);
    expect(capabilities).toEqual(["agents.read", "runs.read", "runs.start"]);
    expect(capabilities.every((name) => MACHINE_CAPABILITIES.includes(name))).toBe(true);
    // Nothing the server sent was quietly dropped, because a scope this surface
    // cannot explain is a scope an operator must still be able to see.
    expect(unknownCapabilities(declared)).toEqual([]);
    expect(describeScope(capabilities)).toContain("3 explicit capabilities");
  });

  it("names a human-only capability this surface refuses to offer", () => {
    // The gate's coordinator decision 2: five human-only permissions, refused
    // before scope is consulted. The picker must not offer them, so an operator
    // is never shown a control the API will reject.
    const refused = fixture.service_account_with_a_human_only_capability._refused;
    expect(isHumanOnlyCapability(refused)).toBe(true);
    expect(MACHINE_CAPABILITIES).not.toContain(refused);
    expect(normalizeCapabilities([refused])).toEqual([]);
    // Adding it to a real set is a no-op here, which is what keeps the frozen
    // three-capability set from silently gaining a fourth in the picker.
    const declared = body.capabilities as string[];
    expect(normalizeCapabilities([...declared, refused])).toEqual(normalizeCapabilities(declared));
  });

  it("carries no field a credential could occupy", () => {
    for (const absent of ["secret", "secret_hash", "wire_value", "api_key_id", "key"]) {
      expect(body).not.toHaveProperty(absent);
      // And a decoder that copied the whole object instead of an allowlist could
      // not add one either, because there is nothing there to copy.
      expect(decodeServiceAccount(stripped(body))).not.toHaveProperty(absent);
    }
  });
});

describe("the frozen API key", () => {
  const body = fixture.api_key as Record<string, unknown>;

  it("decodes field-for-field with nothing dropped and nothing added", () => {
    const decoded = decodeApiKey(stripped(body));
    expect(decoded).toBeDefined();
    expect(decoded).toEqual(stripped(body));
  });

  it("carries no field a raw credential could use", () => {
    // F14-002 / the gate: a read projection has no secret, so a compromise of
    // this response is not a compromise of the key.
    for (const absent of ["secret", "secret_hash", "wire_value", "raw"]) {
      expect(body).not.toHaveProperty(absent);
      expect(decodeApiKey(stripped(body))).not.toHaveProperty(absent);
    }
  });

  it("agrees with the derivation the fixture documents for the two hashes", () => {
    // `api_key._derivation`, asserted rather than trusted: a projection that
    // grew a `sha256:` scheme prefix, or a prefix that carried the `lumik_`
    // scheme, would still satisfy both decoders, which type-check any string.
    const prefix = body.key_prefix as string;
    expect(prefix).toHaveLength(12);
    expect(prefix).toMatch(/^[0-9a-f]{12}$/);
    const fingerprint = body.fingerprint as string;
    expect(fingerprint).toHaveLength(16);
    expect(fingerprint).toMatch(/^[0-9a-f]{16}$/);
    expect(fingerprint.startsWith(prefix)).toBe(true);

    // The wire form the create/rotate response returns once is a different
    // shape, and the one place a `lumik_` prefix belongs.
    const wire = `lumik_${prefix}_${"A".repeat(43)}`;
    expect(API_KEY_PREFIX_PATTERN.test(wire)).toBe(true);
    expect(API_KEY_PREFIX_PATTERN.test(prefix)).toBe(false);
  });

  it("agrees with the rotation shape the fixture documents", () => {
    // F14-004: the replacement records the key it supersedes, so an audit trail
    // can answer "which key did this replace" without a second query.
    const replacement = fixture.api_key_rotation.replacement as Record<string, unknown>;
    expect(replacement.rotated_from_key_id).toBe(body.id);
    expect(replacement.same_scope_as).toBe("api_key");
    const prior = fixture.api_key_rotation.prior_key_after as Record<string, unknown>;
    expect(prior.status).toBe("rotated");
    expect(prior.revoke_reason).toBeTypeOf("string");
    expect(prior.revoke_reason as string).not.toBe("");
    // A rotated key is a distinct status, not `revoked`: conflating them would
    // tell an operator their key was cancelled when it was superseded.
    expect(body.status).toBe("active");
    expect(prior.status).not.toBe(body.status);
  });

  it("agrees with the scope rules the frozen allowlist implies", () => {
    // `*.ci.trusted.example` is a strict subdomain pattern, so the frozen
    // allowlist covers `build.ci.trusted.example` and not the bare parent.
    const allowlist = body.network_allowlist as string[];
    expect(allowlist).toEqual(["*.ci.trusted.example"]);
    const modelAliases = body.model_aliases as string[];
    expect(modelAliases).toEqual(["coding-default"]);
    // A single project is named, so the key is narrower than every project.
    expect(body.project_ids).toHaveLength(1);
  });
});
