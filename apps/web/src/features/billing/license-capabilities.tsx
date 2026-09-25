import {
  capabilityMeaning,
  FROZEN_CAPABILITY_MATRIX,
  type CapabilityDecision,
  type LicenseClocks,
  type LicenseProjection,
  type LicenseWindowBasis,
} from "./license-state";
import { humanizeStatus } from "./entitlements";
import {
  BillingDate,
  BillingNotice,
  BillingPanel,
  BillingPanelHeader,
  BillingPill,
  BillingTableCaption,
  type BillingTone,
} from "./ui";

const VERDICT_LABEL: Record<CapabilityDecision["verdict"], string> = {
  allowed: "Allowed",
  allowed_until: "Allowed until a deadline",
  in_flight_only: "In-flight work only",
  denied: "Denied",
};

const VERDICT_TONE: Record<CapabilityDecision["verdict"], BillingTone> = {
  allowed: "success",
  allowed_until: "warning",
  in_flight_only: "warning",
  denied: "danger",
};

const BASIS_LABEL: Record<LicenseWindowBasis, string> = {
  offline_valid_until: "signed offline validity",
  policy_fresh_until: "policy freshness",
  grace_expires_at: "cloud grace window",
  none: "no time bound",
};

function stateTone(state: LicenseProjection["state"]): BillingTone {
  if (state === "active") return "success";
  if (state === "grace" || state === "past_due") return "warning";
  if (state === "expired" || state === "provider_unavailable") return "danger";
  return "neutral";
}

export function LicenseCapabilityMatrix({
  license,
  clocks,
}: {
  license: LicenseProjection;
  clocks: LicenseClocks;
}) {
  return (
    <BillingPanel ariaLabel="License state and capability matrix">
      <BillingPanelHeader
        eyebrow="LICENSE STATE"
        title="What the current state allows"
        description="The license state is a server-side projection, not a client judgment. Each capability class is answered on its own clock, so one expiry never silently stands in for another."
        action={
          <BillingPill tone={stateTone(license.state)}>{humanizeStatus(license.state)}</BillingPill>
        }
      />

      <div className="space-y-5 p-5">
        <p className="max-w-3xl text-sm leading-6 text-[var(--muted-strong)]">
          {license.stateMeaning}
        </p>

        <TwoClocks clocks={clocks} />

        <div className="overflow-x-auto rounded-lg border border-[var(--border)]">
          <table className="w-full min-w-[760px] text-left text-sm">
            <BillingTableCaption>
              Capability decisions for the current license state
            </BillingTableCaption>
            <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
              <tr>
                <th scope="col" className="px-4 py-3 font-medium">
                  Capability
                </th>
                <th scope="col" className="px-4 py-3 font-medium">
                  Decision
                </th>
                <th scope="col" className="px-4 py-3 font-medium">
                  Bound until
                </th>
                <th scope="col" className="px-4 py-3 font-medium">
                  What it means
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border)]">
              {license.decisions.map((decision) => (
                <tr key={decision.capability} className="align-top">
                  <th scope="row" className="px-4 py-4 text-left align-top font-medium">
                    <span className="text-[var(--civic-navy)]">{decision.capabilityLabel}</span>
                    <span className="mt-1 block text-xs font-normal leading-4 text-[var(--muted)]">
                      {capabilityMeaning(decision.capability)}
                    </span>
                  </th>
                  <td className="px-4 py-4">
                    <div className="flex flex-col items-start gap-1.5">
                      <BillingPill tone={VERDICT_TONE[decision.verdict]}>
                        {VERDICT_LABEL[decision.verdict]}
                      </BillingPill>
                      {decision.degraded ? (
                        <BillingPill tone="warning">Degraded</BillingPill>
                      ) : null}
                      <code className="font-mono text-[11px] text-[var(--muted)]">
                        {decision.reason}
                      </code>
                    </div>
                  </td>
                  <td className="px-4 py-4">
                    {decision.until ? (
                      <>
                        <span
                          className={
                            decision.lapsed
                              ? "block text-sm font-medium tabular-nums text-[var(--danger)]"
                              : "block text-sm font-medium tabular-nums text-[var(--civic-navy)]"
                          }
                        >
                          <BillingDate value={decision.until} />
                        </span>
                        {decision.lapsed ? (
                          <span className="mt-1 block text-xs text-[var(--danger)]">
                            This instant has passed.
                          </span>
                        ) : null}
                        {decision.untilBasis.length > 0 ? (
                          <span className="mt-1 block text-xs leading-4 text-[var(--muted)]">
                            Basis:{" "}
                            {decision.untilBasis.map((item) => BASIS_LABEL[item]).join(" and ")}
                          </span>
                        ) : null}
                      </>
                    ) : (
                      <span className="text-sm text-[var(--muted)]">—</span>
                    )}
                  </td>
                  <td className="max-w-[26rem] px-4 py-4 text-xs leading-5 text-[var(--muted-strong)]">
                    {decision.meaning}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {license.paidInferenceGraceSeconds === 0 ? (
          <BillingNotice tone="warning">
            <span className="font-semibold">
              Platform-paid inference receives no billing grace.
            </span>{" "}
            The policy default for this window is 0 seconds. Local-only work has a longer, separate
            window, so a transient billing or provider outage does not brick local execution.
          </BillingNotice>
        ) : null}

        <details className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)]">
          <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-[var(--civic-navy)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2">
            Frozen capability matrix for every license state
          </summary>
          <div className="overflow-x-auto border-t border-[var(--border)]">
            <table className="w-full min-w-[720px] text-left text-sm">
              <BillingTableCaption>
                Capability matrix for every license state, from the frozen contract
              </BillingTableCaption>
              <thead className="bg-[var(--panel)] text-xs text-[var(--muted)]">
                <tr>
                  <th scope="col" className="px-4 py-3 font-medium">
                    License state
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Local-only new work
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Cloud control-plane work
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Platform-paid inference
                  </th>
                  <th scope="col" className="px-4 py-3 font-medium">
                    Current
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {FROZEN_CAPABILITY_MATRIX.map((row) => (
                  <tr
                    key={row.state}
                    className={row.state === license.state ? "bg-[var(--lumi-blue-soft)]" : ""}
                  >
                    <th
                      scope="row"
                      className="px-4 py-3 text-left text-xs font-semibold text-[var(--civic-navy)]"
                    >
                      {humanizeStatus(row.state)}
                    </th>
                    <td className="px-4 py-3 text-xs text-[var(--muted-strong)]">{row.local}</td>
                    <td className="px-4 py-3 text-xs text-[var(--muted-strong)]">{row.cloud}</td>
                    <td className="px-4 py-3 text-xs text-[var(--muted-strong)]">
                      {row.paidInference}
                    </td>
                    <td className="px-4 py-3 text-xs">
                      {row.state === license.state ? (
                        <BillingPill tone="info">Current state</BillingPill>
                      ) : (
                        <span className="text-[var(--muted)]">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      </div>
    </BillingPanel>
  );
}

function TwoClocks({ clocks }: { clocks: LicenseClocks }) {
  return (
    <section aria-label="Two separate license clocks" className="grid gap-3 sm:grid-cols-2">
      <article className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-4">
        <p className="text-[11px] font-semibold tracking-[0.08em] text-[var(--muted)]">
          LOCAL CLOCK
        </p>
        <h3 className="mt-1 text-sm font-semibold text-[var(--civic-navy)]">
          Signed offline validity
        </h3>
        <p className="mt-2 text-sm tabular-nums text-[var(--civic-navy)]">
          <BillingDate value={clocks.localUntil} />
        </p>
        <p className="mt-2 text-xs leading-4 text-[var(--muted-strong)]">
          Governs local-only work on a previously signed snapshot. Defaults to a longer window than
          cloud work.
        </p>
      </article>
      <article className="rounded-lg border border-[var(--border)] bg-[var(--panel-hover)] p-4">
        <p className="text-[11px] font-semibold tracking-[0.08em] text-[var(--muted)]">
          CLOUD CLOCKS
        </p>
        <h3 className="mt-1 text-sm font-semibold text-[var(--civic-navy)]">Policy freshness</h3>
        <p className="mt-2 text-sm tabular-nums text-[var(--civic-navy)]">
          <BillingDate value={clocks.cloudPolicyFreshUntil} />
        </p>
        <h3 className="mt-3 text-sm font-semibold text-[var(--civic-navy)]">Grace window</h3>
        <p className="mt-2 text-sm tabular-nums text-[var(--civic-navy)]">
          <BillingDate value={clocks.cloudGraceExpiresAt} />
        </p>
        <p className="mt-2 text-xs leading-4 text-[var(--muted-strong)]">
          Cloud managed work needs both: a current policy snapshot and an open grace window. A
          transient provider outage must not brick unrelated local work.
        </p>
      </article>
    </section>
  );
}
