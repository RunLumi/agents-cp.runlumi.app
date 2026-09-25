import type { ReactNode } from "react";

import type { LicenseReason, LicenseProjection } from "./license-state";
import { DOWNGRADE_HONESTY_STATEMENT } from "./downgrade";
import type { Subscription, SubscriptionStatus } from "./api";
import { humanizeStatus } from "./entitlements";
import {
  BillingDate,
  BillingNotice,
  BillingPanel,
  BillingPanelHeader,
  BillingPill,
  type BillingTone,
} from "./ui";

const STATUS_TONE: Record<SubscriptionStatus, BillingTone> = {
  trialing: "info",
  active: "success",
  grace: "warning",
  past_due: "warning",
  suspended: "danger",
  cancelled: "neutral",
};

export function SubscriptionSummary({
  subscription,
  license,
  canManage,
  onRefresh,
  refreshing,
}: {
  subscription: Subscription;
  license: LicenseProjection;
  canManage: boolean;
  onRefresh: () => void;
  refreshing: boolean;
}) {
  const isGrace = subscription.status === "grace" || subscription.status === "past_due";
  const local = license.decisions.find((item) => item.capability === "local_only");
  const cloud = license.decisions.find((item) => item.capability === "cloud_control_plane");

  return (
    <BillingPanel ariaLabel="Subscription summary">
      <BillingPanelHeader
        eyebrow="LUMI SUBSCRIPTION"
        title="Plan and subscription"
        description="The commercial plan and the Lumi subscription state. Provider billing details are never shown here; the provider is adapter-private."
        action={
          <div className="flex flex-wrap items-center justify-end gap-2">
            <BillingPill tone={STATUS_TONE[subscription.status]}>
              {humanizeStatus(subscription.status)}
            </BillingPill>
            {canManage ? (
              <button
                type="button"
                className="min-h-10 rounded-lg border border-[var(--lumi-blue)]/40 px-3 text-sm font-medium text-[var(--lumi-blue)] outline-none transition hover:bg-[var(--lumi-blue-soft)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                onClick={onRefresh}
                disabled={refreshing}
              >
                {refreshing ? "Refreshing…" : "Refresh"}
              </button>
            ) : null}
          </div>
        }
      />
      <div className="space-y-4 p-5">
        <dl className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <Field label="Plan" value={subscription.plan_key} mono />
          <Field label="Status" value={humanizeStatus(subscription.status)} />
          <Field
            label="Current period ends"
            value={<BillingDate value={subscription.current_period_ends_at} />}
            tabular
          />
          <Field
            label="Subscription version"
            value={String(subscription.version)}
            tabular
            hint="Optimistic concurrency. A stale version is rejected."
          />
        </dl>

        {isGrace ? (
          <GraceWindow
            graceExpiresAt={subscription.grace_expires_at}
            localUntil={local?.until ?? null}
            localReason={local?.reason ?? null}
            cloudUntil={cloud?.until ?? null}
            cloudReason={cloud?.reason ?? null}
            status={subscription.status}
          />
        ) : null}

        {subscription.status === "suspended" || subscription.status === "cancelled" ? (
          <BillingNotice tone="danger">
            <span className="font-semibold">
              {humanizeStatus(subscription.status)} subscription.
            </span>{" "}
            No new work of any class starts. Work that was already authorized and in flight may
            finish under its existing policy. {DOWNGRADE_HONESTY_STATEMENT}
          </BillingNotice>
        ) : null}

        <p className="text-xs leading-5 text-[var(--muted)]">
          Seat counts are derived from authoritative membership rows, not from anything entered in a
          browser. A pending invitation, a removed member, and a viewer are not billable unless the
          plan contract says otherwise.
        </p>
      </div>
    </BillingPanel>
  );
}

function GraceWindow({
  graceExpiresAt,
  localUntil,
  localReason,
  cloudUntil,
  cloudReason,
  status,
}: {
  graceExpiresAt: string | null;
  localUntil: string | null;
  localReason: LicenseReason | null;
  cloudUntil: string | null;
  cloudReason: LicenseReason | null;
  status: SubscriptionStatus;
}) {
  return (
    <section
      aria-label="Grace window"
      className="rounded-lg border-l-[3px] border-l-[var(--warning)] border-y border-r border-[var(--warning)]/40 bg-[var(--warning)]/10 p-4 text-[var(--civic-navy)]"
    >
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-semibold">Billing grace is active and time-limited</h3>
        <BillingPill tone="warning">
          {status === "past_due" ? "Payment failed" : "Awaiting payment"}
        </BillingPill>
      </div>
      <p className="mt-2 text-sm leading-5 text-[var(--muted-strong)]">
        Grace does not renew. It started at the first accepted provider transition and expires
        against the server clock, and it never extends because a check failed again.
      </p>

      <dl className="mt-4 grid gap-4 sm:grid-cols-2">
        <div>
          <dt className="text-xs font-semibold tracking-[0.08em] text-[var(--muted)]">
            CLOUD CONTROL-PLANE GRACE ENDS
          </dt>
          <dd className="mt-1 text-sm font-medium tabular-nums text-[var(--civic-navy)]">
            <BillingDate value={graceExpiresAt ?? cloudUntil} />
          </dd>
          <dd className="mt-1 text-xs leading-4 text-[var(--muted-strong)]">
            {cloudReason === "policy_snapshot_stale"
              ? "Cloud managed work is already denied because the policy snapshot is stale. That is a separate failure from the grace clock, and it fails closed on its own."
              : cloudReason === "license_grace_expired"
                ? "This window has ended. Cloud managed work is denied."
                : "When this instant passes, cloud control-plane managed work stops. Cloud work also needs a current policy snapshot, which can lapse independently."}
          </dd>
        </div>
        <div>
          <dt className="text-xs font-semibold tracking-[0.08em] text-[var(--muted)]">
            SIGNED OFFLINE VALIDITY ENDS
          </dt>
          <dd className="mt-1 text-sm font-medium tabular-nums text-[var(--civic-navy)]">
            <BillingDate value={localUntil} />
          </dd>
          <dd className="mt-1 text-xs leading-4 text-[var(--muted-strong)]">
            {localReason === "license_snapshot_expired"
              ? "This window has ended. New local work is denied until a current license snapshot is issued."
              : "Local-only work continues on the previously signed snapshot until this instant. This is a different clock from the one above."}
          </dd>
        </div>
      </dl>

      <ul className="mt-4 space-y-1.5 text-xs leading-5 text-[var(--muted-strong)]">
        <li>
          <span className="font-semibold text-[var(--civic-navy)]">Stops first:</span> cloud
          control-plane managed work, when the shorter cloud window ends.
        </li>
        <li>
          <span className="font-semibold text-[var(--civic-navy)]">Stops last:</span> local-only
          work, when the signed offline validity instant passes.
        </li>
        <li>
          <span className="font-semibold text-[var(--civic-navy)]">No grace at all:</span>{" "}
          platform-paid inference. It follows the provider account, not the grace clock.
        </li>
      </ul>
    </section>
  );
}

function Field({
  label,
  value,
  mono = false,
  tabular = false,
  hint,
}: {
  label: string;
  value: ReactNode;
  mono?: boolean;
  tabular?: boolean;
  hint?: string;
}) {
  return (
    <div>
      <dt className="text-xs font-medium text-[var(--muted)]">{label}</dt>
      <dd
        className={[
          "mt-1 break-words text-sm text-[var(--civic-navy)]",
          mono ? "font-mono text-xs" : "",
          tabular ? "tabular-nums" : "",
        ].join(" ")}
      >
        {value}
      </dd>
      {hint ? <p className="mt-1 text-xs leading-4 text-[var(--muted)]">{hint}</p> : null}
    </div>
  );
}
