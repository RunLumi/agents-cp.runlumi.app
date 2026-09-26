/**
 * Data controls: the platform-level status view.
 *
 * WHY this needed its own coverage. The "Data controls" tab shipped as a single
 * paragraph pointing at the Retention policies tab — a placeholder wearing a
 * real tab's name. It is now a five-row status table built from the frozen
 * policy fields, which means a new way for the panel to state something the
 * server did not say.
 *
 * The specific failure this guards against is a control reading as settled when
 * it is not. A legal hold that is active but whose reason is missing, a logging
 * mode that permits content, an upstream provider the platform cannot delete
 * from: each of those has a consequence an operator must be able to act on, and
 * each is easy to render as a neutral value.
 */
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { DataGovernancePolicy } from "./api";
import { DataControls } from "./data-controls";

const ORG_ID = "org_0123456789abcdef0123456789abcdef";

function policy(overrides: Partial<DataGovernancePolicy> = {}): DataGovernancePolicy {
  return {
    policy_id: "pol_1",
    persisted: true,
    org_id: ORG_ID,
    project_id: null,
    logging_mode: "metadata_only",
    class_retention_overrides: {},
    legal_hold: false,
    legal_hold_reason: null,
    legal_hold_placed_at: null,
    legal_hold_released_at: null,
    legal_hold_released_by: null,
    backup_lifecycle: "platform_35_day_expiry",
    provider_retention_disclosure: "external_policy",
    provider_retention_url: null,
    default_export_expiry_seconds: 86400,
    version: 3,
    created_at: "2026-01-01T00:00:00.000Z",
    updated_at: "2026-02-01T00:00:00.000Z",
    ...overrides,
  };
}

function render(overrides: Partial<DataGovernancePolicy> = {}): string {
  return renderToStaticMarkup(<DataControls policy={policy(overrides)} />);
}

function text(overrides: Partial<DataGovernancePolicy> = {}): string {
  return render(overrides)
    .replaceAll("<!-- -->", "")
    .replaceAll("&#x27;", "'")
    .replaceAll("&amp;", "&")
    .replaceAll("&quot;", '"')
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">");
}

describe("data controls", () => {
  it("names all five platform controls from the frozen policy fields", () => {
    const html = render();

    expect(html).toContain("Logging mode");
    expect(html).toContain("Legal hold");
    expect(html).toContain("Backup lifecycle");
    expect(html).toContain("Export artifact lifetime");
    expect(html).toContain("Upstream provider retention");

    // The stable field names are shown, so a reader can correlate a row with
    // what the API actually returned.
    expect(html).toContain("default_export_expiry_seconds");
    expect(html).toContain("metadata_only");
    expect(html).toContain("platform_35_day_expiry");
  });

  it("reports the frozen default logging mode as the default, not as a choice", () => {
    const html = render();
    expect(html).toContain("Frozen default");
    // The prohibition is the part that matters: a reader must not come away
    // thinking prompts or tool arguments are being kept.
    expect(html).toContain(
      "Raw prompts, responses, tool arguments, credentials, and secrets are prohibited",
    );
  });

  it("flags a content-permitting logging mode rather than rendering it neutrally", () => {
    const html = render({ logging_mode: "redacted_content" });
    expect(html).toContain("Content permitted");
    expect(html).not.toContain("Frozen default");
    expect(html).toContain("explicitly redacted diagnostic excerpts");
  });

  it("shows that full_content cannot be persisted here rather than implying it can", () => {
    const html = text({ logging_mode: "full_content" });
    expect(html).toContain("the policy surface cannot persist it");
  });

  it("states that a hold suspends expiry, and names the reason when there is one", () => {
    const held = text({
      legal_hold: true,
      legal_hold_reason: "Litigation hold, matter 2026-114",
      legal_hold_placed_at: "2026-02-01T00:00:00.000Z",
    });

    expect(held).toContain("Suspending expiry");
    expect(held).toContain("Litigation hold, matter 2026-114");
    expect(held).toContain("no window expires and no deletion proceeds");
    expect(held).toContain("Only an audited release lifts it");
  });

  it("does not invent a hold reason when the server sent none", () => {
    // A hold with no recorded reason is still a hold, and the missing reason is
    // itself the fact an operator needs. Fabricating a plausible one would be
    // worse than showing the gap.
    const held = text({ legal_hold: true, legal_hold_placed_at: null });
    expect(held).toContain("Suspending expiry");
    expect(held).toContain("at an unrecorded time");
  });

  it("reports the absence of a hold as a fact, not as a blank", () => {
    const clear = text();
    expect(clear).toContain("Not holding");
    expect(clear).toContain("Nothing is held");
  });

  it("agrees with itself about singular and plural override counts", () => {
    // The first draft of this file asserted "1 class currently carry", which
    // locked a subject-verb disagreement into a test. Both forms are asserted
    // now so neither can drift.
    expect(text({ class_retention_overrides: { "runs.audit": 604800 } })).toContain(
      "1 class carries a policy-specific window",
    );
    expect(
      text({ class_retention_overrides: { "runs.audit": 604800, "usage.daily": 604800 } }),
    ).toContain("2 classes carry a policy-specific window");
  });

  it("never claims Lumi can delete what a provider holds", () => {
    const html = text();
    expect(html).toContain("Not Lumi's to delete");
    expect(html).toContain("Lumi does not delete it and does not claim to");
  });

  it("links the provider policy when one is published, and omits the link when not", () => {
    const linked = render({
      provider_retention_disclosure: "linked_policy",
      provider_retention_url: "https://provider.example/retention",
    });
    expect(linked).toContain('href="https://provider.example/retention"');
    // An external link that opens a new tab must not hand the opener over.
    expect(linked).toMatch(/rel="noreferrer noopener"/);
    expect(linked).toContain("Read the provider&#x27;s policy");

    expect(render()).not.toContain("Read the provider");
  });

  it("states that backup expiry is not selectively rewritten", () => {
    expect(text()).toContain("not selectively rewritten");
    expect(text({ backup_lifecycle: "platform_no_backup" })).toContain(
      "a deletion takes effect everywhere at once",
    );
  });

  it("humanizes the export artifact lifetime without a singular/plural mismatch", () => {
    expect(text()).toContain(">1 day<");
    expect(text({ default_export_expiry_seconds: 172800 })).toContain(">2 days<");
    // The first draft rendered "1 hours". The exact-cell assertion is what
    // catches it: a bare `toContain("1 hour")` would also match "1 hours".
    expect(text({ default_export_expiry_seconds: 3600 })).toContain(">1 hour<");
    expect(text({ default_export_expiry_seconds: 3600 })).not.toContain("1 hours");
  });

  it("says plainly that these controls never widen a frozen limit", () => {
    const html = text();
    expect(html).toContain("These controls never widen a frozen limit");
    expect(html).toContain(
      "may shorten a retention window, never extend one past its legal maximum",
    );
    expect(html).toContain("Nothing on this page authorizes a request");
  });
});

/**
 * WHY there is no test that the "Data controls" TAB renders this component.
 *
 * Checked, and it does not hold: replacing `<DataControls policy={...} />` in
 * `data-panel.tsx` with a placeholder paragraph leaves this file fully green,
 * because the tests above render `DataControls` directly.
 *
 * `renderToStaticMarkup` is synchronous, so `DataPanel` — whose state comes from
 * an async read — can only ever render its loading branch, and that branch
 * renders `LoadingRows` rather than any tab's content. With no `act()` and no
 * DOM in this harness, the tab-to-component wiring is unreachable from a test.
 *
 * This is the same gap already recorded for the data panel's export and deletion
 * surfaces, and it is why a placeholder shipped under a real tab's name in the
 * first place. Closing it properly means adding a DOM test dependency, which is
 * a deliberate decision for a follow-up rather than something to slip in at the
 * end of a phase. Recorded here so the coverage above is not read as more than
 * it is.
 */
