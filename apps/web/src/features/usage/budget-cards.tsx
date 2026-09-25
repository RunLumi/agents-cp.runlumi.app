import type {
  Budget,
  BudgetReservation,
  RateLimitPolicy,
  UsageDenial,
  UsageEvent,
} from "./usage-contracts";
import {
  budgetUsage,
  buildUsageBreakdown,
  formatCost,
  formatScopeLabel,
  formatShortId,
  formatUsageDate,
  formatUsageTimestamp,
  recordedCostForEvent,
} from "./helpers";
import { formatMinorUnits, formatPercent } from "./money";
import type { UsageSummary } from "./helpers";

export interface BudgetCardsProps {
  summary: UsageSummary;
  budgets: readonly Budget[];
  usage: readonly UsageEvent[];
  reservations: readonly BudgetReservation[];
  denials: readonly UsageDenial[];
  budgetState: "ready" | "loading" | "unavailable" | "permission" | "error";
}

export function BudgetCards({
  summary,
  budgets,
  usage,
  reservations,
  denials,
  budgetState,
}: BudgetCardsProps) {
  const budgetPressure = summarizeBudgetPressure(budgets, usage, reservations);
  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Usage summary">
      <SummaryCard
        label="Recorded spend"
        value={formatSummaryAmount(summary)}
        detail={spendDetail(summary)}
        tone="blue"
      />
      <SummaryCard
        label="Budget pressure"
        value={budgetState === "ready" ? budgetPressure : "Unavailable"}
        detail={
          budgetState === "ready"
            ? budgetPressureDetail(budgetPressure)
            : "Budget state is not available"
        }
        tone={budgetPressureTone(budgets, usage, reservations, budgetState)}
      />
      <SummaryCard
        label="Denied requests"
        value={formatCount(denials.length || summary.deniedCount)}
        detail="Budget and rate-limit decisions"
        tone={denials.length > 0 || summary.deniedCount > 0 ? "amber" : "green"}
      />
      <SummaryCard
        label="Usage events"
        value={formatCount(summary.eventCount)}
        detail={`${formatCount(summary.inputTokens)} in · ${formatCount(summary.outputTokens)} out`}
        tone="navy"
      />
    </div>
  );
}

export function BudgetList({
  budgets,
  usage,
  reservations,
}: {
  budgets: readonly Budget[];
  usage: readonly UsageEvent[];
  reservations: readonly BudgetReservation[];
}) {
  if (budgets.length === 0) {
    return (
      <EmptyPanel
        title="No budgets configured"
        copy="Create a budget policy to make spend limits and reset periods visible here."
      />
    );
  }

  return (
    <div className="grid gap-3 lg:grid-cols-2">
      {budgets.map((budget) => (
        <BudgetProgressCard
          key={budget.budget_id}
          budget={budget}
          usage={usage}
          reservations={reservations}
        />
      ))}
    </div>
  );
}

export function BudgetProgressCard({
  budget,
  usage,
  reservations,
}: {
  budget: Budget;
  usage: readonly UsageEvent[];
  reservations: readonly BudgetReservation[];
}) {
  const usageSummary = budgetUsage(budget, usage, reservations);
  const hasLimit = budget.limit_minor > 0;
  const percentage =
    hasLimit && usageSummary.usedMinor !== null
      ? (usageSummary.usedMinor / budget.limit_minor) * 100
      : null;
  const progressValue = percentage === null ? 0 : Math.min(100, Math.max(0, percentage));
  const overLimit = percentage !== null && percentage > 100;
  const status = budgetStatus(budget, percentage);
  const titleId = `budget-${budget.budget_id}`;

  return (
    <article
      aria-labelledby={titleId}
      className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-4 shadow-[var(--shadow)]"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 id={titleId} className="text-sm font-semibold text-[var(--civic-navy)]">
            {scopeTitle(budget.scope_type, budget.scope_id)}
          </h3>
          <p className="mt-1 text-xs text-[var(--muted)]">
            {budget.hard ? "Hard limit" : "Soft limit"} · resets{" "}
            {formatUsageDate(budget.period_end)}
            {budget.updated_at ? ` · updated ${formatUsageTimestamp(budget.updated_at)}` : ""}
          </p>
        </div>
        <StatusPill status={status} />
      </div>

      <div className="mt-4 flex items-end justify-between gap-3">
        <p className="text-2xl font-semibold tabular-nums tracking-[-0.03em] text-[var(--civic-navy)]">
          {usageSummary.usedMinor === null
            ? "Not reported"
            : formatMinorUnits(usageSummary.usedMinor, usageSummary.currency ?? budget.currency, {
                showCode: true,
              })}
        </p>
        <p className="text-right text-xs tabular-nums text-[var(--muted-strong)]">
          {percentage === null
            ? "Limit unavailable"
            : formatPercent(usageSummary.usedMinor ?? 0, budget.limit_minor)}
          <span className="block text-[var(--muted)]">
            of {formatMinorUnits(budget.limit_minor, budget.currency, { showCode: true })}
          </span>
        </p>
      </div>

      <div
        className="mt-3 h-2 overflow-hidden rounded-full bg-[var(--panel-strong)]"
        role="progressbar"
        aria-label={`${scopeTitle(budget.scope_type, budget.scope_id)} budget usage`}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percentage === null ? undefined : Math.round(progressValue)}
        aria-valuetext={
          usageSummary.usedMinor === null
            ? "Spend not reported"
            : `${formatPercent(usageSummary.usedMinor, budget.limit_minor)} of limit`
        }
      >
        <div className={progressClass(status, overLimit)} style={{ width: `${progressValue}%` }} />
      </div>

      <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-3 border-t border-[var(--border)] pt-3 text-xs sm:grid-cols-4">
        <BudgetDatum
          label="Reserved"
          value={formatMinorUnits(
            usageSummary.reservedMinor,
            usageSummary.currency ?? budget.currency,
            { showCode: true },
          )}
        />
        <BudgetDatum label="Scope" value={formatScopeLabel(budget.scope_type, budget.scope_id)} />
        <BudgetDatum
          label="Period"
          value={`${formatUsageDate(budget.period_start)} – ${formatUsageDate(budget.period_end)}`}
        />
        <BudgetDatum
          label="Provenance"
          value={
            usageSummary.derived
              ? usageSummary.pricingVersions.length > 0
                ? `Loaded events · ${usageSummary.pricingVersions.length} pricing version${usageSummary.pricingVersions.length === 1 ? "" : "s"}`
                : "Loaded events · pricing version not recorded"
              : "Server-reported spend"
          }
        />
      </dl>
    </article>
  );
}

export function BudgetReservationsTable({
  reservations,
}: {
  reservations: readonly BudgetReservation[];
}) {
  return (
    <section
      aria-labelledby="reservation-heading"
      className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]"
    >
      <div className="border-b border-[var(--border)] px-4 py-3">
        <h3 id="reservation-heading" className="text-sm font-semibold text-[var(--civic-navy)]">
          Recent reservations
        </h3>
        <p className="mt-1 text-xs text-[var(--muted-strong)]">
          Holds are reconciled after the run reaches a terminal state; unused holds are released.
        </p>
      </div>
      {reservations.length === 0 ? (
        <p className="px-4 py-5 text-sm text-[var(--muted)]">
          No reservation records in the loaded snapshot.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-left text-sm">
            <caption className="sr-only">Budget reservation history</caption>
            <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
              <tr>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Request
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Reserved
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Committed
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Status
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Expires
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border)]">
              {reservations.slice(0, 12).map((reservation) => (
                <tr key={reservation.reservation_id}>
                  <td className="px-4 py-3">
                    <p className="font-mono text-xs text-[var(--civic-navy)]">
                      {formatShortId(reservation.request_id)}
                    </p>
                    <p className="mt-0.5 text-xs text-[var(--muted)]">
                      {formatShortId(reservation.run_id)}
                    </p>
                  </td>
                  <td className="px-4 py-3 tabular-nums">
                    {formatMinorUnits(reservation.reserved_minor, reservation.currency, {
                      showCode: true,
                    })}
                  </td>
                  <td className="px-4 py-3 tabular-nums">
                    {formatMinorUnits(reservation.committed_minor, reservation.currency, {
                      showCode: true,
                    })}
                  </td>
                  <td className="px-4 py-3">
                    <StatusPill status={reservation.status} />
                  </td>
                  <td className="px-4 py-3 text-xs tabular-nums text-[var(--muted-strong)]">
                    {formatUsageTimestamp(reservation.expires_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export function RateLimitPoliciesTable({ policies }: { policies: readonly RateLimitPolicy[] }) {
  return (
    <section
      aria-labelledby="rate-limit-heading"
      className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]"
    >
      <div className="border-b border-[var(--border)] px-4 py-3">
        <h3 id="rate-limit-heading" className="text-sm font-semibold text-[var(--civic-navy)]">
          Rate limit policies
        </h3>
        <p className="mt-1 text-xs text-[var(--muted-strong)]">
          The most restrictive applicable request, token, and concurrency limit wins.
        </p>
      </div>
      {policies.length === 0 ? (
        <p className="px-4 py-5 text-sm text-[var(--muted)]">
          No rate-limit policies are configured.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[900px] text-left text-sm">
            <caption className="sr-only">Organization rate-limit policies</caption>
            <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
              <tr>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Scope
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Requests/min
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Tokens/min
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Concurrent
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Models
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Status
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Updated
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border)]">
              {policies.map((policy) => (
                <tr key={policy.rate_limit_policy_id}>
                  <td className="px-4 py-3">
                    <p className="font-medium text-[var(--civic-navy)]">
                      {formatScopeLabel(policy.scope_type, policy.scope_id)}
                    </p>
                    <p className="mt-0.5 font-mono text-xs text-[var(--muted)]">
                      {formatShortId(policy.rate_limit_policy_id)}
                    </p>
                  </td>
                  <td className="px-4 py-3 tabular-nums">
                    {formatLimit(policy.requests_per_minute)}
                  </td>
                  <td className="px-4 py-3 tabular-nums">
                    {formatLimit(policy.tokens_per_minute)}
                  </td>
                  <td className="px-4 py-3 tabular-nums">
                    {formatLimit(policy.max_concurrent_requests)}
                  </td>
                  <td className="max-w-[220px] truncate px-4 py-3 text-[var(--muted-strong)]">
                    {policy.applicable_model_aliases.length > 0
                      ? policy.applicable_model_aliases.join(", ")
                      : "All models"}
                  </td>
                  <td className="px-4 py-3">
                    <StatusPill status={policy.status} />
                  </td>
                  <td className="px-4 py-3 text-xs tabular-nums text-[var(--muted-strong)]">
                    {formatUsageTimestamp(policy.updated_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export function DenialTable({ denials }: { denials: readonly UsageDenial[] }) {
  return (
    <section
      aria-labelledby="denial-heading"
      className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]"
    >
      <div className="border-b border-[var(--border)] px-4 py-3">
        <h3 id="denial-heading" className="text-sm font-semibold text-[var(--civic-navy)]">
          Denied requests
        </h3>
        <p className="mt-1 text-xs text-[var(--muted-strong)]">
          Only stable decision codes and opaque correlation IDs are shown. Request bodies and tool
          arguments are not included.
        </p>
      </div>
      {denials.length === 0 ? (
        <p className="px-4 py-5 text-sm text-[var(--muted)]">
          No denied requests in the loaded snapshot.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] text-left text-sm">
            <caption className="sr-only">Budget and rate-limit denied requests</caption>
            <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
              <tr>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Time
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Request / run
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Scope
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Code
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Limit
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Retry after
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border)]">
              {denials.map((denial) => (
                <tr key={`${denial.denial_id}-${denial.created_at}`}>
                  <td className="whitespace-nowrap px-4 py-3 text-xs tabular-nums text-[var(--muted-strong)]">
                    {formatUsageTimestamp(denial.created_at)}
                  </td>
                  <td className="px-4 py-3">
                    <p className="font-mono text-xs text-[var(--civic-navy)]">
                      {formatShortId(denial.request_id)}
                    </p>
                    <p className="mt-0.5 text-xs text-[var(--muted)]">
                      {formatShortId(denial.run_id)}
                    </p>
                  </td>
                  <td className="px-4 py-3 text-[var(--muted-strong)]">
                    {denial.scope_type
                      ? formatScopeLabel(denial.scope_type, denial.scope_id)
                      : "Organization"}
                  </td>
                  <td className="px-4 py-3">
                    <code className="rounded bg-[var(--panel-strong)] px-1.5 py-0.5 text-xs text-[var(--civic-navy)]">
                      {denial.code}
                    </code>
                  </td>
                  <td className="px-4 py-3 text-xs capitalize text-[var(--muted-strong)]">
                    {denial.limit_type.replaceAll("_", " ")}
                  </td>
                  <td className="px-4 py-3 tabular-nums text-[var(--muted-strong)]">
                    {denial.retry_after_seconds === null ? "—" : `${denial.retry_after_seconds}s`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export function UsageBreakdownTable({
  events,
  dimension,
}: {
  events: readonly UsageEvent[];
  dimension: "project" | "user" | "model" | "provider";
}) {
  const rows = buildUsageBreakdown(events, dimension);
  return (
    <section
      aria-labelledby="usage-breakdown-heading"
      className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]"
    >
      <div className="border-b border-[var(--border)] px-4 py-3">
        <h3 id="usage-breakdown-heading" className="text-sm font-semibold text-[var(--civic-navy)]">
          Usage breakdown
        </h3>
        <p className="mt-1 text-xs text-[var(--muted-strong)]">
          Grouped from the loaded immutable page. Currency groups are kept separate; user and
          service-account values are opaque IDs, not profile data.
        </p>
      </div>
      {rows.length === 0 ? (
        <p className="px-4 py-5 text-sm text-[var(--muted)]">No usage events to break down.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[620px] text-left text-sm">
            <caption className="sr-only">Usage grouped by {dimension}</caption>
            <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
              <tr>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  {dimension === "project"
                    ? "Project"
                    : dimension === "user"
                      ? "User / service account"
                      : dimension === "model"
                        ? "Model"
                        : "Provider"}
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Events
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Tokens
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Recorded cost
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border)]">
              {rows.map((row) => (
                <tr key={row.key}>
                  <td className="max-w-[320px] truncate px-4 py-3 font-medium text-[var(--civic-navy)]">
                    {row.label}
                  </td>
                  <td className="px-4 py-3 tabular-nums">{formatCount(row.eventCount)}</td>
                  <td className="px-4 py-3 text-xs tabular-nums text-[var(--muted-strong)]">
                    {formatCount(row.inputTokens)} in / {formatCount(row.outputTokens)} out
                  </td>
                  <td className="px-4 py-3 tabular-nums text-[var(--civic-navy)]">
                    {formatMinorUnits(row.costMinor, row.currency, { showCode: true })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export function UsageEventsTable({ events }: { events: readonly UsageEvent[] }) {
  return (
    <section
      aria-labelledby="usage-events-heading"
      className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--panel)] shadow-[var(--shadow)]"
    >
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-[var(--border)] px-4 py-3">
        <div>
          <h3 id="usage-events-heading" className="text-sm font-semibold text-[var(--civic-navy)]">
            Recent recorded usage
          </h3>
          <p className="mt-1 text-xs text-[var(--muted-strong)]">
            Immutable accounting metadata only. The latest page is shown; the API remains the source
            of truth.
          </p>
        </div>
        <span className="rounded-md bg-[var(--lumi-blue-soft)] px-2 py-1 text-xs font-medium text-[var(--lumi-blue)]">
          {formatCount(events.length)} loaded
        </span>
      </div>
      {events.length === 0 ? (
        <p className="px-4 py-5 text-sm text-[var(--muted)]">
          No usage events recorded for this organization.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[980px] text-left text-sm">
            <caption className="sr-only">Immutable usage events</caption>
            <thead className="bg-[var(--panel-hover)] text-xs text-[var(--muted)]">
              <tr>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Event
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Scope
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Model / provider
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Tokens
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Recorded cost
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Decision
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Reconciliation
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Recorded at
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border)]">
              {events.slice(0, 25).map((event) => {
                const cost = recordedCostForEvent(event);
                return (
                  <tr key={event.usage_event_id}>
                    <td className="px-4 py-3">
                      <p className="font-mono text-xs text-[var(--civic-navy)]">
                        {formatShortId(event.usage_event_id)}
                      </p>
                      <p className="mt-0.5 text-xs text-[var(--muted)]">
                        {formatShortId(event.request_id)}
                      </p>
                    </td>
                    <td className="px-4 py-3 text-xs text-[var(--muted-strong)]">
                      {event.project_id
                        ? `Project · ${formatShortId(event.project_id)}`
                        : "Organization"}
                    </td>
                    <td className="px-4 py-3">
                      <p className="text-xs font-medium text-[var(--civic-navy)]">
                        {event.model_alias}
                      </p>
                      <p className="mt-0.5 text-xs text-[var(--muted)]">{event.provider_id}</p>
                    </td>
                    <td className="px-4 py-3 text-xs tabular-nums text-[var(--muted-strong)]">
                      {event.input_tokens ?? "—"} in / {event.output_tokens ?? "—"} out
                      {event.cached_tokens === null ? "" : ` / ${event.cached_tokens} cached`}
                    </td>
                    <td className="px-4 py-3">
                      <p className="text-xs tabular-nums text-[var(--civic-navy)]">
                        {formatCost(cost, true)}
                      </p>
                      <p className="mt-0.5 text-xs text-[var(--muted)]">
                        {cost.kind === "actual"
                          ? "actual"
                          : cost.kind === "estimated"
                            ? "estimated"
                            : "not recorded"}
                        {cost.pricingVersion
                          ? ` · ${cost.pricingVersion}`
                          : " · pricing version not recorded"}
                      </p>
                    </td>
                    <td className="px-4 py-3">
                      <StatusPill status={event.budget_decision} />
                    </td>
                    <td className="px-4 py-3 text-xs text-[var(--muted-strong)]">
                      {event.source ? `${event.source} · ` : ""}
                      {event.reconciliation_status ?? "recorded"}
                      {event.reconciled_at ? (
                        <span className="mt-0.5 block text-xs text-[var(--muted)]">
                          {formatUsageTimestamp(event.reconciled_at)}
                        </span>
                      ) : null}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-xs tabular-nums text-[var(--muted-strong)]">
                      {formatUsageTimestamp(event.created_at)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export function EmptyPanel({ title, copy }: { title: string; copy: string }) {
  return (
    <div className="rounded-xl border border-dashed border-[var(--border-strong)] bg-[var(--panel)] p-5">
      <h3 className="text-sm font-semibold text-[var(--civic-navy)]">{title}</h3>
      <p className="mt-1 text-sm leading-5 text-[var(--muted-strong)]">{copy}</p>
    </div>
  );
}

function SummaryCard({
  label,
  value,
  detail,
  tone,
}: {
  label: string;
  value: string;
  detail: string;
  tone: "blue" | "green" | "amber" | "navy";
}) {
  return (
    <article className="rounded-xl border border-[var(--border)] bg-[var(--panel)] p-4 shadow-[var(--shadow)]">
      <p className="text-xs font-medium text-[var(--muted)]">{label}</p>
      <p className={summaryValueClass(tone)}>{value}</p>
      <p className="mt-1 text-xs leading-4 text-[var(--muted)]">{detail}</p>
    </article>
  );
}

function summaryValueClass(tone: "blue" | "green" | "amber" | "navy"): string {
  return [
    "mt-2 text-xl font-semibold tracking-[-0.02em] tabular-nums",
    tone === "blue"
      ? "text-[var(--lumi-blue)]"
      : tone === "green"
        ? "text-[var(--success)]"
        : tone === "amber"
          ? "text-[var(--danger)]"
          : "text-[var(--civic-navy)]",
  ].join(" ");
}

function BudgetDatum({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-[var(--muted)]">{label}</dt>
      <dd className="mt-1 break-words text-xs text-[var(--muted-strong)]">{value}</dd>
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const normalized = status.toLowerCase();
  const tone =
    normalized === "active" ||
    normalized === "healthy" ||
    normalized === "allow" ||
    normalized === "allowed" ||
    normalized === "committed" ||
    normalized === "released"
      ? "green"
      : normalized === "unavailable" ||
          normalized.includes("unavailable") ||
          normalized === "denied" ||
          normalized.includes("denied") ||
          normalized === "blocked" ||
          normalized.includes("blocked") ||
          normalized.includes("exceeded") ||
          normalized === "rate_limited" ||
          normalized === "unhealthy" ||
          normalized === "expired" ||
          normalized === "failed" ||
          normalized === "disabled" ||
          normalized === "conflict"
        ? "red"
        : normalized === "soft" ||
            normalized === "near_limit" ||
            normalized === "near limit" ||
            normalized === "soft limit" ||
            normalized === "pending" ||
            normalized === "degraded"
          ? "amber"
          : "blue";
  return (
    <span
      className={[
        "inline-flex max-w-full items-center rounded-full px-2 py-1 text-xs font-medium",
        tone === "green"
          ? "bg-[var(--success)]/10 text-[var(--success)]"
          : tone === "red"
            ? "bg-[var(--danger)]/10 text-[var(--danger)]"
            : tone === "amber"
              ? "bg-[var(--warning)]/15 text-[var(--danger)]"
              : "bg-[var(--lumi-blue-soft)] text-[var(--lumi-blue)]",
      ].join(" ")}
    >
      {status.replaceAll("_", " ")}
    </span>
  );
}

function formatSummaryAmount(summary: UsageSummary): string {
  if (summary.mixedCurrencies) return "Mixed currencies";
  if (summary.primaryCurrency === null || summary.recordedMinor === null) return "Not recorded";
  return formatMinorUnits(summary.recordedMinor, summary.primaryCurrency, { showCode: true });
}

function spendDetail(summary: UsageSummary): string {
  if (summary.unknownCostCount > 0 && summary.recordedMinor !== null) {
    return `${formatCount(summary.unknownCostCount)} event${summary.unknownCostCount === 1 ? "" : "s"} without a cost`;
  }
  if (summary.primaryCurrency === null) return "No priced events in this page";
  if (summary.pricingVersions.length > 1) {
    return `${summary.pricingVersions.length} pricing versions · no recalculation`;
  }
  const actual =
    summary.actualMinor === null
      ? "0"
      : formatMinorUnits(summary.actualMinor, summary.primaryCurrency);
  const estimated =
    summary.estimatedMinor === null
      ? "0"
      : formatMinorUnits(summary.estimatedMinor, summary.primaryCurrency);
  return `${actual} actual · ${estimated} estimated`;
}

function summarizeBudgetPressure(
  budgets: readonly Budget[],
  usage: readonly UsageEvent[],
  reservations: readonly BudgetReservation[],
): string {
  if (budgets.length === 0) return "No budget configured";
  const highest = budgets
    .map((budget) => {
      const summary = budgetUsage(budget, usage, reservations);
      if (summary.usedMinor === null || budget.limit_minor <= 0) return null;
      return (summary.usedMinor / budget.limit_minor) * 100;
    })
    .filter((value): value is number => value !== null)
    .sort((left, right) => right - left)[0];
  return highest === undefined ? "Spend not reported" : formatPercent(highest, 100);
}

function budgetPressureDetail(value: string): string {
  return value === "No budget configured"
    ? "Set a limit to make pressure visible"
    : "Highest applicable recorded usage in loaded page";
}

function budgetPressureTone(
  budgets: readonly Budget[],
  usage: readonly UsageEvent[],
  reservations: readonly BudgetReservation[],
  state: BudgetCardsProps["budgetState"],
): "blue" | "green" | "amber" {
  if (state !== "ready" || budgets.length === 0) return "blue";
  const percentages = budgets
    .map((budget) => {
      const summary = budgetUsage(budget, usage, reservations);
      if (summary.usedMinor === null || budget.limit_minor <= 0) return null;
      return (summary.usedMinor / budget.limit_minor) * 100;
    })
    .filter((value): value is number => value !== null);
  const highest = Math.max(...percentages);
  if (!Number.isFinite(highest)) return "blue";
  return highest >= 80 ? "amber" : "green";
}

function budgetStatus(budget: Budget, percentage: number | null): string {
  if (budget.state === "unavailable") return budget.state;
  if (budget.lifecycle !== "active") return budget.lifecycle;
  if (percentage === null) return "unavailable";
  if (percentage >= 100) return budget.hard ? "blocked" : "soft limit";
  if (percentage >= 80) return "near limit";
  return "healthy";
}

function progressClass(status: string, overLimit: boolean): string {
  if (overLimit || status === "blocked" || status === "unavailable")
    return "h-full bg-[var(--danger)]";
  if (status === "near limit" || status === "soft limit" || status === "degraded")
    return "h-full bg-[var(--warning)]";
  return "h-full bg-[var(--lumi-blue)]";
}

function scopeTitle(scope: Budget["scope_type"], scopeId: string | null): string {
  const label =
    scope === "organization" ? "Organization budget" : `${scope.replaceAll("_", " ")} budget`;
  return scopeId && scope !== "organization" ? `${label} · ${formatShortId(scopeId)}` : label;
}

function formatLimit(value: number | null): string {
  return value === null ? "—" : new Intl.NumberFormat("en-US").format(value);
}

function formatCount(value: number): string {
  return new Intl.NumberFormat("en-US").format(Math.max(0, value));
}
