import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { DataGovernanceApi } from "./api";
import { DataPanel } from "./data-panel";

const hookState = vi.hoisted(() => ({
  values: [] as unknown[],
  setters: [] as ReturnType<typeof vi.fn>[],
  effects: [] as (() => unknown)[],
  index: 0,
}));
vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useState(initial: unknown) {
      const index = hookState.index++;
      const setter = vi.fn();
      hookState.setters[index] = setter;
      return [index < hookState.values.length ? hookState.values[index] : initial, setter];
    },
    useEffect(effect: () => unknown) {
      hookState.effects.push(effect);
    },
  };
});

const ready = {
  kind: "ready",
  data: { items: [], next_cursor: null, has_more: false },
  stale: false,
};
const forbidden = { kind: "permission" };
const page = { items: [], next_cursor: "next-page", has_more: true };
const api = {
  getPolicy: vi.fn().mockResolvedValue({}),
  listExports: vi.fn().mockResolvedValue(page),
  listDeletions: vi.fn().mockResolvedValue(page),
  listPersonalExports: vi.fn().mockResolvedValue(page),
  getPersonalDeletion: vi.fn().mockResolvedValue({}),
} as unknown as DataGovernanceApi;

beforeEach(() => {
  hookState.values = [];
  hookState.setters = [];
  hookState.effects = [];
  hookState.index = 0;
});

describe("DataPanel partial access", () => {
  it("keeps deletion history available when policy and export reads are forbidden", () => {
    hookState.values = [forbidden, forbidden, null, ready, null, null, null, false, "deletions"];
    const html = renderToStaticMarkup(<DataPanel orgId="org_test" api={api} />);

    expect(html).toContain('role="tablist"');
    expect(html).toContain('id="data-and-retention-panel-deletions"');
    expect(html).toContain("No deletion job exists for this organization");
  });

  it("shows a denied resource inside its selected tab and preserves navigation", () => {
    hookState.values = [forbidden, forbidden, null, ready, null, null, null, false, "exports"];
    const html = renderToStaticMarkup(<DataPanel orgId="org_test" api={api} />);

    expect(html).toContain('role="tablist"');
    expect(html).toContain('id="data-and-retention-panel-exports"');
    expect(html).toContain("Access not permitted");
  });

  it("seeds organization export and deletion pagination from the first pages", async () => {
    renderToStaticMarkup(<DataPanel orgId="org_test" api={api} />);
    hookState.effects[0]!();

    await vi.waitFor(() => expect(hookState.setters[2]).toHaveBeenCalledWith("next-page"));
    expect(hookState.setters[4]).toHaveBeenCalledWith("next-page");
  });

  it("seeds personal export pagination from the first page", async () => {
    const { PersonalDataPanel } = await import("./data-panel");
    renderToStaticMarkup(<PersonalDataPanel api={api} />);
    hookState.effects[0]!();

    await vi.waitFor(() => expect(hookState.setters[1]).toHaveBeenCalledWith("next-page"));
  });
});
