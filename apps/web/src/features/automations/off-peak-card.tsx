// The off-peak execution class.
//
// The gate is explicit that `OffPeakPolicy` is "a distinct execution class, not
// a cron window or a generic interval". This component therefore never renders
// off-peak as a schedule: it shows the eligibility source, whether that source
// even has a clock, the restrictions that survive re-evaluation, and the
// narrowing-only rule.

import {
  OFF_PEAK_CLASS_NOTE,
  OFF_PEAK_NARROWING_RULE,
  offPeakConstraintSummary,
  offPeakEligibilityDetail,
  offPeakEligibilityLabel,
} from "./automation-helpers";
import type { OffPeakPolicy } from "./api";
import { Metadata, Notice, Panel, PanelHeader, Pill } from "./ui";

export function OffPeakCard({ policy }: { policy: OffPeakPolicy | null }) {
  if (policy === null) {
    return (
      <Panel ariaLabel="Off-peak execution class">
        <PanelHeader
          title="Off-peak execution class"
          description="Off-peak is a separate execution class, not a cron window. This automation does not request one."
        />
        <div className="px-5 py-4">
          <Notice tone="info">{OFF_PEAK_CLASS_NOTE}</Notice>
        </div>
      </Panel>
    );
  }

  const hasClock = policy.eligibility_source === "org_window";

  return (
    <Panel ariaLabel="Off-peak execution class">
      <PanelHeader
        title="Off-peak execution class"
        description="A distinct execution class, never a schedule window. The server re-evaluates the class at dispatch and at execution."
        action={<Pill tone="info">{offPeakEligibilityLabel(policy)}</Pill>}
      />
      <dl className="grid gap-x-6 gap-y-5 px-5 py-4 sm:grid-cols-2">
        <Metadata label="Eligibility source" value={offPeakEligibilityLabel(policy)} />
        <Metadata
          label="Clock schedule"
          value={hasClock ? "Inside the organization window" : "None — no clock schedule"}
        />
        <Metadata label="Policy schema" value={`v${policy.schema_version}`} />
        <Metadata
          label="Lower-cost route aliases"
          value={
            policy.allowed_route_aliases.length > 0
              ? policy.allowed_route_aliases.join(", ")
              : "No alias restriction"
          }
          mono
        />
        <div className="sm:col-span-2">
          <Metadata label="Host safety restrictions" value={offPeakConstraintSummary(policy)} />
        </div>
      </dl>
      <div className="space-y-3 border-t border-[var(--border)] px-5 py-4">
        <Notice tone="info">{offPeakEligibilityDetail(policy.eligibility_source)}</Notice>
        {policy.eligibility_source === "provider_ticket" ? (
          <Notice tone="warning">
            A ticket renewal does not create a second logical occurrence. Each off-peak occurrence
            keeps one identity, so a renewal never doubles the work.
          </Notice>
        ) : null}
        <p className="text-xs leading-5 text-[var(--muted-strong)]">
          {OFF_PEAK_NARROWING_RULE} {OFF_PEAK_CLASS_NOTE}
        </p>
      </div>
    </Panel>
  );
}
