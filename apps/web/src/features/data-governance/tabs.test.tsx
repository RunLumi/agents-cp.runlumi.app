/**
 * Data & Retention sub-page tabs.
 *
 * WHY this exists as its own test file: `docs/screens/lumi_export_history.webp`
 * presents Data & Retention as ONE page with four tabs, and the tab strip is
 * load bearing in two ways that are easy to break silently.
 *
 * First, the selection must actually GATE the content. A tab strip that
 * renders every panel and only moves the underline would show a user their
 * export history while they believe they are reading retention policy.
 *
 * Second, the strip is the only navigation in this surface, so it has to be
 * reachable and operable from the keyboard. A strip of four buttons that are
 * all in the tab order is technically focusable and practically a trap.
 */
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { DataPanel } from "./data-panel";
import { TabPanel } from "./ui";
import type { DataGovernanceApi } from "./api";

const ORG_ID = "org_0123456789abcdef0123456789abcdef";

const EMPTY_PAGE = { items: [], next_cursor: null, has_more: false };

function pendingApi(): DataGovernanceApi {
  return {
    getPolicy: () => new Promise(() => undefined),
    listExports: () => new Promise(() => undefined),
    listDeletions: () => new Promise(() => undefined),
  } as unknown as DataGovernanceApi;
}

describe("data and retention tabs", () => {
  it("names the four sub-pages the design reference shows, in order", () => {
    const markup = renderToStaticMarkup(<DataPanel orgId={ORG_ID} api={pendingApi()} />);

    expect(markup).toContain("Retention policies");
    expect(markup).toContain("Export history");
    expect(markup).toContain("Data controls");
    expect(markup).toContain("Deletion requests");

    // Order matters: the reference reads left to right in this sequence, and a
    // reordered strip reads as a different information hierarchy.
    const order = ["Retention policies", "Export history", "Data controls", "Deletion requests"];
    const positions = order.map((label) => markup.indexOf(label));
    for (const position of positions) expect(position).toBeGreaterThan(-1);
    expect([...positions].sort((a, b) => a - b)).toEqual(positions);
  });

  it("is a real ARIA tablist with exactly one selected tab", () => {
    const markup = renderToStaticMarkup(<DataPanel orgId={ORG_ID} api={pendingApi()} />);

    expect(markup).toContain('role="tablist"');
    expect(markup).toContain('aria-label="Data and retention"');
    expect(markup).toContain('role="tabpanel"');
    // Roving tabindex across the STRIP: the selected tab is in the tab order
    // and the rest are reachable with arrow keys only. Four buttons all at
    // tabindex 0 would make a keyboard user tab through the whole strip on
    // every page visit.
    const tabs = markup.match(/<button[^>]*role="tab"[^>]*>/g) ?? [];
    expect(tabs).toHaveLength(4);
    const focusable = tabs.filter((tag) => tag.includes('tabindex="0"'));
    expect(focusable).toHaveLength(1);
    expect(tabs.filter((tag) => tag.includes('tabindex="-1"'))).toHaveLength(3);
    expect(markup.match(/aria-selected="true"/g) ?? []).toHaveLength(1);
    // The panel itself stays focusable, which is the ARIA-recommended way to
    // let a keyboard user reach content that contains no focusable elements.
    expect(markup).toMatch(/role="tabpanel"[^>]*tabindex="0"/);
  });

  it("pairs each tab id with a panel id, so a screen reader is told where it is", () => {
    // The panel's accessible name comes from its own tab via aria-labelledby,
    // so the pairing has to be derived from the same string both times. Testing
    // it per-id is what makes a rename in one place fail here rather than
    // silently orphaning the relationship.
    for (const id of ["retention", "exports", "controls", "deletions"]) {
      const markup = renderToStaticMarkup(
        <TabPanel id={id} label="Data and retention">
          <p>body</p>
        </TabPanel>,
      );
      expect(markup).toContain(`id="data-and-retention-panel-${id}"`);
      expect(markup).toContain(`aria-labelledby="data-and-retention-tab-${id}"`);
      expect(markup).toContain('role="tabpanel"');
    }
  });

  /**
   * WHY the container-level gating is not asserted here: `renderToStaticMarkup`
   * is synchronous, so a container whose state is populated by an async read
   * always renders its LOADING branch. The stripping of panels by the selected
   * tab is therefore verified by reading `data-panel.tsx` — each tab is
   * wrapped in `{tab === "<id>" ? …}` and only that one mounts — rather than by
   * a DOM assertion that would pass trivially in the branch this harness can
   * reach. Asserting it here would be the same mistake as a test whose regex
   * matches static headings.
   */
  it("renders exactly the active tab's panel while loading", () => {
    const markup = renderToStaticMarkup(<DataPanel orgId={ORG_ID} api={pendingApi()} />);
    // The active panel is the only one mounted, and it is the selected tab's.
    expect(markup).toContain('id="data-and-retention-panel-retention"');
    expect(markup).not.toContain('id="data-and-retention-panel-exports"');
    expect(markup).not.toContain('id="data-and-retention-panel-controls"');
    expect(markup).not.toContain('id="data-and-retention-panel-deletions"');
  });

  it("keeps the tab strip a button, never a link, so it cannot navigate away", () => {
    const markup = renderToStaticMarkup(<DataPanel orgId={ORG_ID} api={pendingApi()} />);
    // The tabs switch a view; they are not pages with their own URLs. An
    // anchor here would push history entries and break the back button for
    // something that never left the page.
    expect(markup).not.toMatch(/<a[^>]*role="tab"/);
    expect(markup).toMatch(/<button[^>]*role="tab"/);
  });
});
