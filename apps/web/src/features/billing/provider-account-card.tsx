import type { ReactNode } from "react";

import type { ProviderEntitlementProjection } from "./api";
import { humanizeStatus } from "./entitlements";
import {
  BillingDate,
  BillingNotice,
  BillingPanel,
  BillingPanelHeader,
  BillingPill,
  type BillingTone,
} from "./ui";

const STATUS_TONE: Record<ProviderEntitlementProjection["status"], BillingTone> = {
  available: "success",
  degraded: "warning",
  unavailable: "danger",
  unknown: "neutral",
};

const STATUS_MEANING: Record<ProviderEntitlementProjection["status"], string> = {
  available:
    "The adapter observed the upstream provider account as usable. This is an observation, not a grant.",
  degraded:
    "The adapter observed the upstream provider account in a reduced state. Provider-managed routes may run in a degraded state with a stable reason.",
  unavailable:
    "The adapter could not reach the upstream provider account. Provider-managed routes are denied or degraded with a stable reason.",
  unknown:
    "The upstream provider account has not been observed yet. Treated as unavailable rather than assumed healthy.",
};

/**
 * The upstream provider projection, deliberately walled off from the Lumi
 * subscription and entitlement surfaces above it (F18 FR-F18-008, P06-CR-002).
 */
export function ProviderAccountCard({
  projection,
  observedStateStaleAfterSeconds,
}: {
  projection: ProviderEntitlementProjection;
  observedStateStaleAfterSeconds: number | null;
}) {
  const observation = observationAgeSeconds(projection.observed_at);
  const stale =
    observation !== null &&
    observedStateStaleAfterSeconds !== null &&
    observation > observedStateStaleAfterSeconds;

  return (
    <BillingPanel ariaLabel="Upstream provider account status">
      <BillingPanelHeader
        eyebrow="UPSTREAM PROVIDER ACCOUNT — NOT A LUMI ENTITLEMENT"
        title={humanizeStatus(projection.provider)}
        description="A read-only status projection of an upstream AI provider account or coding plan. It is not a Lumi product entitlement, and it never grants or revokes one."
        action={
          <BillingPill tone={STATUS_TONE[projection.status]}>
            {humanizeStatus(projection.status)}
          </BillingPill>
        }
      />
      <div className="space-y-4 p-5">
        <p className="text-sm leading-5 text-[var(--muted-strong)]">
          {STATUS_MEANING[projection.status]}
        </p>

        <dl className="grid gap-4 sm:grid-cols-3">
          <Field label="Capability class" value={humanizeStatus(projection.capability_class)} />
          <Field label="Projection ID" value={projection.projection_id} mono />
          <Field label="Observed at" value={<BillingDate value={projection.observed_at} />} />
        </dl>

        {stale ? (
          <BillingNotice tone="warning">
            <span className="font-semibold">This observation is old.</span> It is older than the
            policy freshness window. Do not read a stale provider status as a current fact, and do
            not read it as a Lumi entitlement either way.
          </BillingNotice>
        ) : null}

        <ul className="space-y-1.5 text-xs leading-5 text-[var(--muted-strong)]">
          <li>
            <span className="font-semibold text-[var(--civic-navy)]">Can change:</span> whether a
            provider-specific route may run, and whether it runs degraded.
          </li>
          <li>
            <span className="font-semibold text-[var(--civic-navy)]">Cannot change:</span> your Lumi
            plan, your Lumi subscription state, your effective entitlement values, your
            authorization permissions, or your usage budget.
          </li>
          <li>
            <span className="font-semibold text-[var(--civic-navy)]">Never shown:</span> the
            provider's product, price, or customer reference. Those stay inside the adapter.
          </li>
        </ul>
      </div>
    </BillingPanel>
  );
}

function observationAgeSeconds(observedAt: string): number | null {
  const parsed = Date.parse(observedAt);
  if (Number.isNaN(parsed)) return null;
  const age = Math.floor((Date.now() - parsed) / 1000);
  return age >= 0 ? age : null;
}

function Field({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: ReactNode;
  mono?: boolean;
}) {
  return (
    <div>
      <dt className="text-xs font-medium text-[var(--muted)]">{label}</dt>
      <dd
        className={
          mono
            ? "mt-1 break-all font-mono text-xs text-[var(--muted-strong)]"
            : "mt-1 text-sm text-[var(--civic-navy)]"
        }
      >
        {value}
      </dd>
    </div>
  );
}
