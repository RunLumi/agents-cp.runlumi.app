import type { EntitlementAttribution, EntitlementProjection, OverLimitResource } from "./api";
import {
  countEntitlementSources,
  describeEntitlement,
  orderEntitlements,
  PRECEDENCE_CHAIN,
  sourceLabel,
  sourceMeaning,
  sourceRank,
} from "./entitlements";
import {
  BillingEmpty,
  BillingLimitBar,
  BillingNotice,
  BillingPanel,
  BillingPanelHeader,
  BillingPill,
  BillingTableCaption,
  type BillingTone,
} from "./ui";

function sourceTone(source: EntitlementAttribution): BillingTone {
  if (source === "internal_override") return "warning";
  if (source === "subscription") return "info";
  if (source === "plan") return "success";
  if (source === "platform_default") return "neutral";
  return "danger";
}

export function EntitlementTable({
  projection,
  onRefresh,
}: {
  projection: EntitlementProjection;
  onRefresh: () => void;
}) {
  const entries = orderEntitlements(projection.entitlements);
  const counts = countEntitlementSources(projection.entitlements);
  const reported = new Map<string, OverLimitResource>(
    projection.over_limit.map((resource) => [resource.entitlement_key, resource]),
  );
  const unattributed = counts.unknown;

  return (
    <BillingPanel ariaLabel="Effective Lumi entitlements">
      <BillingPanelHeader
        eyebrow="EFFECTIVE LUMI ENTITLEMENTS"
        title="What the plan includes"
        description="The effective value of each stable Lumi entitlement key, and which layer of the precedence chain set it. The plan pointer and the included limits come from here; usage and budgets are measured elsewhere."
        action={
          <button
            type="button"
            className="min-h-10 rounded-lg border border-[var(--lumi-blue)]/40 px-3 text-sm font-medium text-[var(--lumi-blue)] outline-none transition hover:bg-[var(--lumi-blue-soft)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
            onClick={onRefresh}
          >
            Refresh
          </button>
        }
      />

      <div className="space-y-4 p-5">
        <PrecedenceLegend counts={counts} />

        {unattributed > 0 ? (
          <BillingNotice tone="warning">
            <span className="font-semibold">
              {unattributed} value{unattributed === 1 ? "" : "s"} arrived without source
              attribution.
            </span>{" "}
            The browser will not assume a plan grant for an unattributed value. The server is
            authoritative; this surface only reports what it was told.
          </BillingNotice>
        ) : null}

        {entries.length === 0 ? (
          <BillingEmpty
            title="No entitlement values were returned"
            description="An empty projection is not a statement that everything is included. A missing value fails closed for a protected capability. Reload the projection before making a plan decision."
          />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-[var(--border)]">
            <table className="w-full min-w-[720px] text-left text-sm">
              <BillingTableCaption>
                Effective Lumi entitlement values with precedence-chain source and reported usage
              </BillingTableCaption>
              <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
                <tr>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Capability
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Key
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Included
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Source in the chain
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Current use
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {entries.map((entry) => {
                  const display = describeEntitlement(entry);
                  const count = reported.get(entry.key) ?? null;
                  return (
                    <tr key={entry.key} className="align-top">
                      <td className="px-4 py-4">
                        <p className="font-medium text-[var(--civic-navy)]">{display.label}</p>
                        {display.info ? (
                          <p className="mt-0.5 text-xs leading-4 text-[var(--muted)]">
                            {display.info.meaning}
                          </p>
                        ) : null}
                        {display.outsideBaseline ? (
                          <p className="mt-1 text-xs font-medium text-[var(--danger)]">
                            Not in the frozen baseline key set.
                          </p>
                        ) : null}
                      </td>
                      <td className="px-4 py-4">
                        <code className="break-all font-mono text-xs text-[var(--muted-strong)]">
                          {entry.key}
                        </code>
                      </td>
                      <td className="px-4 py-4">
                        <span
                          className={
                            display.missing
                              ? "font-medium text-[var(--danger)]"
                              : "font-medium tabular-nums text-[var(--civic-navy)]"
                          }
                        >
                          {display.valueText}
                        </span>
                        {entry.expires_at ? (
                          <p className="mt-1 text-xs leading-4 text-[var(--muted)]">
                            Expires{" "}
                            <span className="tabular-nums">
                              {new Date(entry.expires_at).toLocaleString()}
                            </span>
                          </p>
                        ) : null}
                        {entry.reason ? (
                          <p className="mt-1 text-xs leading-4 text-[var(--muted-strong)]">
                            Reason: {entry.reason}
                          </p>
                        ) : null}
                      </td>
                      <td className="px-4 py-4">
                        <div className="flex flex-col items-start gap-1.5">
                          <BillingPill tone={sourceTone(entry.source)}>
                            {sourceRank(entry.source) === null
                              ? sourceLabel(entry.source)
                              : `P${sourceRank(entry.source)} · ${sourceLabel(entry.source)}`}
                          </BillingPill>
                          <p className="text-xs leading-4 text-[var(--muted)]">
                            {sourceMeaning(entry.source)}
                          </p>
                          {entry.scope ? (
                            <p className="text-xs leading-4 text-[var(--muted)]">
                              Scope: {entry.scope}
                            </p>
                          ) : null}
                        </div>
                      </td>
                      <td className="px-4 py-4">
                        {count && count.current > 0 ? (
                          <BillingLimitBar
                            current={count.current}
                            limit={count.limit}
                            label={display.label}
                          />
                        ) : display.numeric !== null ? (
                          <p className="text-xs text-[var(--muted)]">
                            {count ? "Within limit" : "Usage not reported here"}
                          </p>
                        ) : (
                          <p className="text-xs text-[var(--muted)]">Not a counted limit</p>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        <p className="text-xs leading-5 text-[var(--muted)]">
          There is no override control on this surface. An internal override is created by support
          with an expiry, a reason, a grant scope, and an audit event; this view only shows its
          effect on a key and the instant it expires.
        </p>
      </div>
    </BillingPanel>
  );
}

function PrecedenceLegend({ counts }: { counts: Record<EntitlementAttribution, number> }) {
  return (
    <div>
      <p className="text-[11px] font-semibold tracking-[0.1em] text-[var(--muted)]">
        PRECEDENCE CHAIN, WEAKEST TO STRONGEST
      </p>
      <ol className="mt-2 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        {PRECEDENCE_CHAIN.map((step) => {
          const count = counts[step.source];
          return (
            <li
              key={step.source}
              className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-3"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold text-[var(--civic-navy)]">
                  P{step.rank} · {step.label}
                </span>
                <BillingPill tone={count > 0 ? sourceTone(step.source) : "neutral"}>
                  {count > 0 ? `${count} key${count === 1 ? "" : "s"}` : "none"}
                </BillingPill>
              </div>
              <p className="mt-1.5 text-xs leading-4 text-[var(--muted-strong)]">{step.meaning}</p>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
