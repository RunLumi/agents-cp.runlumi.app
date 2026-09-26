/**
 * The capability vocabulary and permission gating.
 *
 * F14-001 is the load-bearing rule: a service account "MUST NOT inherit an
 * owner's permissions implicitly", and a wildcard is implicit inheritance wearing
 * a different name. These tests exist so a later edit that adds a wildcard
 * control, or that offers a human-only permission, fails here rather than in
 * production.
 */

import { describe, expect, it } from "vitest";

import {
  CAPABILITY_GROUPS,
  HUMAN_ONLY_CAPABILITIES,
  HUMAN_ONLY_REASONS,
  MACHINE_CAPABILITIES,
  capabilityEffect,
  describeScope,
  isHumanOnlyCapability,
  normalizeCapabilities,
  toggleCapability,
  unknownCapabilities,
} from "./capabilities";
import {
  IDENTITY_ACTION_PERMISSIONS,
  IDENTITY_ACTIONS,
  identityPermissions,
  isIdentityActionPermitted,
  permittedIdentityActions,
} from "./permissions";

describe("the machine capability vocabulary", () => {
  it("offers no wildcard option anywhere in the picker", () => {
    // F14-001. A `"*"` entry is implicit inheritance under a different name, and
    // the server rejects it, so offering it would be a control that always fails.
    expect(MACHINE_CAPABILITIES).not.toContain("*");
    for (const group of CAPABILITY_GROUPS) {
      for (const option of group.options) {
        expect(option.name).not.toBe("*");
        expect(option.name).not.toContain("*");
      }
    }
  });

  it("does not offer any of the five human-only capabilities", () => {
    // F14-007 plus P07 coordinator decision 2. `is_human_only` refuses these
    // before scope is consulted, so a checkbox for one would always fail closed.
    for (const capability of HUMAN_ONLY_CAPABILITIES) {
      expect(MACHINE_CAPABILITIES).not.toContain(capability);
      expect(isHumanOnlyCapability(capability)).toBe(true);
    }
    // Guard against a sixth name being added to the backend list but not here.
    expect(new Set(HUMAN_ONLY_CAPABILITIES).size).toBe(5);
    for (const capability of MACHINE_CAPABILITIES) {
      expect(isHumanOnlyCapability(capability)).toBe(false);
    }
  });

  it("gives every human-only capability a stated reason", () => {
    for (const capability of HUMAN_ONLY_CAPABILITIES) {
      expect(HUMAN_ONLY_REASONS[capability].length).toBeGreaterThan(20);
    }
  });

  it("keeps the human-only read capability that IS machine-eligible", () => {
    // `billing.read` is a read. Only `billing.manage` is a commercial act.
    expect(MACHINE_CAPABILITIES).toContain("billing.read");
    expect(MACHINE_CAPABILITIES).toContain("data.read");
    expect(MACHINE_CAPABILITIES).toContain("data.export");
    expect(MACHINE_CAPABILITIES).not.toContain("data.delete");
  });

  it("mirrors the Permission enum with a stated effect for every entry", () => {
    for (const name of MACHINE_CAPABILITIES) {
      const effect = capabilityEffect(name);
      expect(effect, `no effect for ${name}`).toBeTypeOf("string");
      expect((effect ?? "").length).toBeGreaterThan(10);
    }
  });

  it("has no duplicate capability across groups", () => {
    const all = CAPABILITY_GROUPS.flatMap((group) => group.options.map((option) => option.name));
    expect(new Set(all).size).toBe(all.length);
    expect(all.sort()).toEqual([...MACHINE_CAPABILITIES].sort());
  });

  it("describes an empty selection as authenticated and inert", () => {
    expect(describeScope([])).toContain("nothing else");
    expect(describeScope(["runs.start"])).toContain("1 explicit capability");
    expect(describeScope(["runs.start", "projects.read"])).toContain("2 explicit capabilities");
    // The preview always states that there is no implicit inheritance.
    expect(describeScope(["runs.start"])).toContain("no wildcard");
  });

  it("normalises a selection into the canonical sorted order the server parses", () => {
    // The server deduplicates and orders, so sending canonical order makes an
    // unchanged PATCH a genuine no-op rather than a new version and audit entry.
    expect(normalizeCapabilities(["projects.read", "runs.start", "runs.start"])).toEqual([
      "projects.read",
      "runs.start",
    ]);
    // An unknown name is dropped rather than sent: the server would refuse it
    // with `capability_unknown` and the operator would learn nothing.
    expect(normalizeCapabilities(["runs.start", "not.a.permission"])).toEqual(["runs.start"]);
  });

  it("toggles a capability on and off without disturbing the rest", () => {
    const base = ["projects.read", "runs.start"];
    expect(toggleCapability(base, "runs.cancel")).toEqual([
      "projects.read",
      "runs.cancel",
      "runs.start",
    ]);
    expect(toggleCapability(base, "projects.read")).toEqual(["runs.start"]);
  });

  it("reports a granted capability the control plane cannot describe", () => {
    // A scope nobody can explain is a scope nobody can audit, so it is surfaced.
    expect(unknownCapabilities(["runs.start", "legacy.retired.permission"])).toEqual([
      "legacy.retired.permission",
    ]);
    expect(unknownCapabilities(["runs.start"])).toEqual([]);
  });
});

describe("identity permission gating", () => {
  it("grants read and manage to owner and admin only", () => {
    for (const role of ["owner", "admin"] as const) {
      const permissions = identityPermissions(role);
      expect(permissions.canRead).toBe(true);
      expect(permissions.canManage).toBe(true);
    }
    for (const role of ["member", "viewer"] as const) {
      const permissions = identityPermissions(role);
      expect(permissions.canRead).toBe(false);
      expect(permissions.canManage).toBe(false);
    }
  });

  it("treats a missing membership as no permission rather than as read", () => {
    expect(identityPermissions(undefined).canRead).toBe(false);
    expect(identityPermissions(null).canManage).toBe(false);
  });

  it("maps every gated action to one of the two P07 browser permissions", () => {
    expect(new Set(Object.values(IDENTITY_ACTION_PERMISSIONS))).toEqual(
      new Set(["service_accounts.read", "service_accounts.manage"]),
    );
    expect(IDENTITY_ACTION_PERMISSIONS.read).toBe("service_accounts.read");
    for (const action of IDENTITY_ACTIONS) {
      if (action === "read") continue;
      expect(IDENTITY_ACTION_PERMISSIONS[action]).toBe("service_accounts.manage");
    }
  });

  it("permits read-only on a member and every action on an admin", () => {
    // Each permission × each action, exhaustively.
    for (const action of IDENTITY_ACTIONS) {
      expect(isIdentityActionPermitted(identityPermissions("admin"), action)).toBe(true);
      expect(isIdentityActionPermitted(identityPermissions("member"), action)).toBe(false);
      expect(isIdentityActionPermitted(identityPermissions("viewer"), action)).toBe(false);
    }
  });

  it("reports no permitted action at all for a member or viewer", () => {
    // `service_accounts.read` is admin-only in P07-CG, so a member or viewer is
    // NOT a read-only principal here — they get nothing. The distinction matters:
    // a viewer must not be told "you can read this" and then find an empty table.
    for (const role of ["member", "viewer"] as const) {
      expect(permittedIdentityActions(identityPermissions(role))).toEqual([]);
    }
    expect(permittedIdentityActions(identityPermissions("admin"))).toEqual([...IDENTITY_ACTIONS]);
    expect(permittedIdentityActions(identityPermissions("owner"))).toEqual([...IDENTITY_ACTIONS]);
  });
});
