/**
 * Organization section routing.
 *
 * WHY these helpers are extracted and tested at all: a section is reachable
 * three ways — a nav click, a bookmark or pasted deep link, and the browser's
 * back button — and only the first goes through `navigate`. The other two land
 * directly on `sectionFromPath`, where a wrong answer drops the reader on
 * Overview with no error, no warning, and no way to tell that it happened. That
 * is a silent failure, which is the kind this repository's tests exist to catch.
 *
 * The Settings grouping is why this is load bearing now rather than before:
 * Settings pushed a second path segment, so the parser has to understand a
 * group, a sub-page, and a bare group — not just a single trailing word. The
 * previous implementation read the last path segment and compared it against a
 * list, which cannot express `/org/x/settings/data` at all: it would have read
 * `data` and, before the grouping, silently ignored any nesting.
 */
import { describe, expect, it } from "vitest";

import { isSettingsSection, pathForSection, sectionFromPath } from "./org-dashboard";

const SLUG = "acme";

describe("sectionFromPath", () => {
  it("resolves a top-level section", () => {
    expect(sectionFromPath(`/org/${SLUG}/overview`)).toBe("overview");
    expect(sectionFromPath(`/org/${SLUG}/projects`)).toBe("projects");
    expect(sectionFromPath(`/org/${SLUG}/automations`)).toBe("automations");
    expect(sectionFromPath(`/org/${SLUG}/webhooks`)).toBe("webhooks");
    expect(sectionFromPath(`/org/${SLUG}/policy`)).toBe("policy");
  });

  it("resolves a settings sub-page to its panel", () => {
    expect(sectionFromPath(`/org/${SLUG}/settings/billing`)).toBe("billing");
    expect(sectionFromPath(`/org/${SLUG}/settings/data`)).toBe("data");
    expect(sectionFromPath(`/org/${SLUG}/settings/webhooks`)).toBe("webhooks");
    expect(sectionFromPath(`/org/${SLUG}/settings/security`)).toBe("account");
  });

  /**
   * P07-CG §"Web information architecture" adds exactly two Settings sub-pages
   * and no top-level nav item. The gate is explicit that F22's tree has no place
   * for either, so these are a recorded deviation rather than a licence to invent
   * a location; these assertions exist so a later reader cannot "fix" the tree
   * back by moving them out of Settings.
   */
  it("resolves both P07 settings sub-pages without adding a top-level item", () => {
    expect(sectionFromPath(`/org/${SLUG}/settings/identity`)).toBe("identity");
    expect(sectionFromPath(`/org/${SLUG}/settings/plugins`)).toBe("plugins");
    expect(isSettingsSection("identity")).toBe(true);
    expect(isSettingsSection("plugins")).toBe(true);
    expect(pathForSection(SLUG, "identity")).toBe(`/org/${SLUG}/settings/identity`);
    expect(pathForSection(SLUG, "plugins")).toBe(`/org/${SLUG}/settings/plugins`);
  });

  /**
   * The reason the machine-identity page is NOT called `Security / Identity`.
   * In F22 that name means human sign-in and SSO; F06 is frozen and unimplemented,
   * so a sub-page claiming it would promise a surface that does not exist.
   */
  it("does not claim F22's Security / Identity name for the machine-identity page", () => {
    // `security` remains the account page's segment, unchanged by P07.
    expect(pathForSection(SLUG, "account")).toBe(`/org/${SLUG}/settings/security`);
    expect(pathForSection(SLUG, "identity")).not.toContain("security");
  });

  /**
   * F22's tree, encoded.
   *
   * `docs/specs/f22-web-control-plane-ux-information-architecture.md` puts
   * Billing, Data / Retention, AND Webhooks all under Settings, with
   * `Integrations / MCP` as a separate top-level item. An earlier revision of
   * the shell promoted webhooks to the top level and renamed it
   * "Integrations / MCP" on the strength of a "Go to Integrations/MCP ->" link
   * in `lumi_billing_overview.webp` — but that link is about connecting a
   * provider billing account, which is an integration, not an outbound webhook.
   * The spec settles it, and these assertions exist so the mistake cannot be
   * reintroduced by reading the same screenshot again.
   */
  it("keeps all three P06 settings surfaces under Settings, per F22", () => {
    for (const page of ["billing", "data", "webhooks"] as const) {
      expect(isSettingsSection(page)).toBe(true);
    }
    // `Integrations / MCP` is a different top-level destination in F22's tree.
    // Nothing in this codebase is the MCP surface yet, so there is correctly no
    // nav item claiming the name — and webhooks must not be standing in for it.
    expect(isSettingsSection("webhooks")).toBe(true);
    expect(pathForSection(SLUG, "webhooks")).toBe(`/org/${SLUG}/settings/webhooks`);
  });

  /**
   * A bare group path is a real destination, not a malformed link. It resolves
   * to the group rather than to some default sub-page, so the Settings landing
   * page can be linked to and bookmarked.
   */
  it("resolves a bare settings path to the group", () => {
    expect(sectionFromPath(`/org/${SLUG}/settings`)).toBe("settings");
    expect(sectionFromPath(`/org/${SLUG}/settings/`)).toBe("settings");
  });

  /**
   * An unknown sub-page falls back to the group, never to Overview. A reader who
   * follows a stale or hand-edited link should land somewhere that at least
   * contains the settings they were reaching for, and the group page lists all
   * of them. Landing on Overview instead would look like the link was dead.
   */
  it("falls back to the group for an unknown settings sub-page", () => {
    expect(sectionFromPath(`/org/${SLUG}/settings/nonexistent`)).toBe("settings");
    expect(sectionFromPath(`/org/${SLUG}/settings/billing/extra`)).toBe("settings");
  });

  it("falls back to Overview for an unknown top-level section", () => {
    expect(sectionFromPath(`/org/${SLUG}/nonexistent`)).toBe("overview");
    expect(sectionFromPath(`/org/${SLUG}`)).toBe("overview");
    expect(sectionFromPath(`/org/${SLUG}/`)).toBe("overview");
  });

  /**
   * A settings sub-page must not be reachable as a bare top-level path any
   * more, but an OLD bookmark of that shape has to keep working. `/org/x/billing`
   * was the address this panel had before the grouping, and links to it are
   * already in people's history and in any shared URL.
   */
  it("still accepts the pre-grouping flat path for a settings sub-page", () => {
    expect(sectionFromPath(`/org/${SLUG}/billing`)).toBe("billing");
    expect(sectionFromPath(`/org/${SLUG}/data`)).toBe("data");
    expect(sectionFromPath(`/org/${SLUG}/webhooks`)).toBe("webhooks");
    expect(sectionFromPath(`/org/${SLUG}/account`)).toBe("account");
  });

  it("does not mistake an organization slug for a section", () => {
    // A slug that collides with a section name must not win. The org segment is
    // always dropped before the section is read.
    expect(sectionFromPath("/org/settings/overview")).toBe("overview");
    expect(sectionFromPath("/org/billing/overview")).toBe("overview");
  });

  it("tolerates a path with no organization at all", () => {
    expect(sectionFromPath("/settings/data")).toBe("data");
    expect(sectionFromPath("/")).toBe("overview");
    expect(sectionFromPath("")).toBe("overview");
  });
});

describe("pathForSection", () => {
  it("round-trips every section through sectionFromPath", () => {
    // The property that actually matters: whatever a nav click writes into the
    // address bar must resolve back to the same panel. A mismatch would make the
    // back button land on the wrong page while the address bar claimed
    // otherwise.
    for (const section of [
      "overview",
      "members",
      "teams",
      "projects",
      "runs",
      "tools",
      "usage",
      "devices",
      "policy",
      "models",
      "automations",
      "webhooks",
      "settings",
      "billing",
      "data",
      "identity",
      "plugins",
      "account",
    ] as const) {
      const path = pathForSection(SLUG, section);
      expect(sectionFromPath(path)).toBe(section);
    }
  });

  it("nests settings sub-pages under the group", () => {
    expect(pathForSection(SLUG, "billing")).toBe(`/org/${SLUG}/settings/billing`);
    expect(pathForSection(SLUG, "data")).toBe(`/org/${SLUG}/settings/data`);
    expect(pathForSection(SLUG, "webhooks")).toBe(`/org/${SLUG}/settings/webhooks`);
    expect(pathForSection(SLUG, "account")).toBe(`/org/${SLUG}/settings/security`);
  });

  it("keeps top-level sections flat", () => {
    expect(pathForSection(SLUG, "settings")).toBe(`/org/${SLUG}/settings`);
    expect(pathForSection(SLUG, "overview")).toBe(`/org/${SLUG}/overview`);
    expect(pathForSection(SLUG, "automations")).toBe(`/org/${SLUG}/automations`);
  });

  it("keeps the organization slug in the path", () => {
    expect(pathForSection("a-b-c", "data")).toContain("/org/a-b-c/");
  });
});

describe("isSettingsSection", () => {
  it("is true only for the group's own sub-pages, not the group itself", () => {
    expect(isSettingsSection("billing")).toBe(true);
    expect(isSettingsSection("data")).toBe(true);
    expect(isSettingsSection("webhooks")).toBe(true);
    expect(isSettingsSection("identity")).toBe(true);
    expect(isSettingsSection("plugins")).toBe(true);
    expect(isSettingsSection("account")).toBe(true);
    // The group landing is not a sub-page of itself, and top-level sections are
    // not settings at all.
    expect(isSettingsSection("settings")).toBe(false);
    expect(isSettingsSection("overview")).toBe(false);
    expect(isSettingsSection("policy")).toBe(false);
    expect(isSettingsSection("automations")).toBe(false);
  });
});
