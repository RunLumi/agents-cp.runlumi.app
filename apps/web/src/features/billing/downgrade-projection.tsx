import {
  BLOCKED_OPERATIONS,
  DOWNGRADE_BLOCKED_COPY,
  DOWNGRADE_HONESTY_STATEMENT,
  REMEDIATION_LABELS,
  REMEDIATION_MEANING,
  type DowngradeAssessment,
  type OverLimitProjection,
} from "./downgrade";
import {
  BillingNotice,
  BillingPanel,
  BillingPanelHeader,
  BillingPill,
  BillingTableCaption,
} from "./ui";

export function OverLimitProjectionPanel({
  assessment,
  title,
  description,
}: {
  assessment: DowngradeAssessment;
  title: string;
  description: string;
}) {
  return (
    <BillingPanel ariaLabel="Over-limit projection and remediation">
      <BillingPanelHeader
        eyebrow="OVER-LIMIT PROJECTION"
        title={title}
        description={description}
        action={
          <BillingPill tone={assessment.overLimit.length > 0 ? "danger" : "success"}>
            {assessment.overLimit.length} resource
            {assessment.overLimit.length === 1 ? "" : "s"} over limit
          </BillingPill>
        }
      />
      <div className="space-y-4 p-5">
        <BillingNotice tone="warning">
          <p className="font-semibold">{DOWNGRADE_HONESTY_STATEMENT}</p>
          <p className="mt-1">{DOWNGRADE_BLOCKED_COPY}</p>
        </BillingNotice>

        {assessment.overLimit.length === 0 ? (
          <p className="text-sm leading-5 text-[var(--muted-strong)]">
            The server reported no resource above the new limit. Counts are derived from
            authoritative rows, not from browser input.
          </p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-[var(--border)]">
            <table className="w-full min-w-[720px] text-left text-sm">
              <BillingTableCaption>
                Resources above the new plan limit, with the remediation each one allows
              </BillingTableCaption>
              <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
                <tr>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Resource
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Entitlement key
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Current
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    New limit
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Over by
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Remediation
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {assessment.overLimit.map((item) => (
                  <OverLimitRow key={item.entitlementKey} item={item} />
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div>
          <p className="text-[11px] font-semibold tracking-[0.08em] text-[var(--muted)]">
            WHAT A DOWNGRADE BLOCKS
          </p>
          <ul className="mt-2 space-y-1.5 text-xs leading-5 text-[var(--muted-strong)]">
            {BLOCKED_OPERATIONS.map((operation) => (
              <li key={operation} className="flex gap-2">
                <span aria-hidden="true" className="text-[var(--danger)]">
                  —
                </span>
                <span>{capitalize(operation)}</span>
              </li>
            ))}
            <li className="flex gap-2">
              <span aria-hidden="true" className="text-[var(--success)]">
                +
              </span>
              <span>Existing resources, their history, and their data are all retained.</span>
            </li>
          </ul>
        </div>

        {assessment.blockedReason ? (
          <BillingNotice tone="danger">
            <p className="font-semibold">This change was not submitted.</p>
            <p className="mt-1">{assessment.blockedReason}</p>
          </BillingNotice>
        ) : null}
      </div>
    </BillingPanel>
  );
}

function OverLimitRow({ item }: { item: OverLimitProjection }) {
  return (
    <tr className="align-top">
      <th scope="row" className="px-4 py-4 text-left align-top font-medium">
        <span className="text-[var(--civic-navy)]">{item.label}</span>
        {item.seatBased ? (
          <span className="mt-1 block text-xs font-normal text-[var(--muted)]">
            Seat-based limit
          </span>
        ) : null}
        {item.outsideBaseline ? (
          <span className="mt-1 block text-xs font-normal text-[var(--danger)]">
            Not in the frozen baseline key set.
          </span>
        ) : null}
      </th>
      <td className="px-4 py-4">
        <code className="break-all font-mono text-xs text-[var(--muted-strong)]">
          {item.entitlementKey}
        </code>
      </td>
      <td className="px-4 py-4 text-sm font-medium tabular-nums text-[var(--civic-navy)]">
        {item.current}
      </td>
      <td className="px-4 py-4 text-sm tabular-nums text-[var(--muted-strong)]">{item.limit}</td>
      <td className="px-4 py-4">
        <BillingPill tone="danger">+{item.overBy}</BillingPill>
      </td>
      <td className="max-w-[22rem] px-4 py-4">
        <ul className="space-y-1.5 text-xs leading-4 text-[var(--muted-strong)]">
          {item.remediation.map((option) => (
            <li key={option}>
              <span className="font-semibold text-[var(--civic-navy)]">
                {REMEDIATION_LABELS[option]}.
              </span>{" "}
              {REMEDIATION_MEANING[option]}
            </li>
          ))}
        </ul>
      </td>
    </tr>
  );
}

function capitalize(value: string): string {
  return value.length === 0 ? value : `${value.charAt(0).toUpperCase()}${value.slice(1)}`;
}
