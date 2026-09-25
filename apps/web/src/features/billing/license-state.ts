/**
 * `LicenseState` projection and the frozen capability matrix.
 *
 * The matrix is a server-side contract (P06-CG "Subscription and license"), not
 * a client decision. This module turns the subscription status, the upstream
 * provider projection, and the two signed license clocks into plain statements
 * about what a user can actually do — and it keeps the two clocks apart:
 *
 * - `policy_fresh_until`  — the CLOUD clock. Cloud control-plane managed work
 *   requires a current policy snapshot.
 * - `offline_valid_until` — the LOCAL clock. Local-only work may continue on a
 *   previously signed snapshot.
 *
 * They are not the same clock and are never collapsed into one "expiry".
 */

import {
  CAPABILITY_CLASSES,
  type CapabilityClass,
  type LicenseState,
  type ProviderProjectionStatus,
  type SubscriptionStatus,
} from "./api";

export type CapabilityVerdict = "allowed" | "allowed_until" | "in_flight_only" | "denied";

/** Which signed clock or provider fact bounds an allowance. */
export type LicenseWindowBasis =
  | "offline_valid_until"
  | "policy_fresh_until"
  | "grace_expires_at"
  | "none";

export type LicenseReason =
  | "license_active"
  | "license_trialing"
  | "license_grace_active"
  | "license_grace_expired"
  | "license_past_due"
  | "license_past_due_offline_expired"
  | "license_suspended"
  | "license_cancelled"
  | "license_snapshot_expired"
  | "policy_snapshot_stale"
  | "provider_available"
  | "provider_degraded"
  | "provider_unavailable"
  | "provider_unknown"
  | "paid_inference_no_billing_grace";

export interface CapabilityDecision {
  capability: CapabilityClass;
  capabilityLabel: string;
  verdict: CapabilityVerdict;
  /** New work allowed right now. False for `in_flight_only` and `denied`. */
  allowed: boolean;
  /** The exact instant the allowance lapses, or null when unbounded. */
  until: string | null;
  untilBasis: LicenseWindowBasis[];
  reason: LicenseReason;
  /** Plain copy. Never a server string. */
  meaning: string;
  /** True when the time-bounded allowance has already lapsed. */
  lapsed: boolean;
  degraded: boolean;
}

export interface LicenseProjection {
  state: LicenseState;
  stateLabel: string;
  stateMeaning: string;
  subscriptionStatus: SubscriptionStatus;
  providerStatus: ProviderProjectionStatus;
  decisions: CapabilityDecision[];
  /** The local clock, kept separate from the cloud clock. */
  localUntil: string | null;
  cloudUntil: string | null;
  /** The P03 policy default: platform-paid inference receives no grace. */
  paidInferenceGraceSeconds: number;
  evaluatedAt: string;
}

export const CAPABILITY_LABELS: Record<CapabilityClass, string> = {
  local_only: "Local-only work",
  cloud_control_plane: "Cloud control-plane managed work",
  platform_paid_inference: "Platform-paid inference",
};

const CAPABILITY_MEANING: Record<CapabilityClass, string> = {
  local_only: "Work executed on an enrolled device against local files, shell, and tools.",
  cloud_control_plane: "Managed sessions, automation dispatch, and device coordination.",
  platform_paid_inference: "Inference Lumi pays for on the platform route.",
};

/**
 * The frozen matrix, preserved verbatim from P06-CG so an operator can read the
 * contract next to the current decision. This is reference text, not a client
 * evaluation.
 */
export const FROZEN_CAPABILITY_MATRIX: readonly {
  state: LicenseState;
  local: string;
  cloud: string;
  paidInference: string;
}[] = [
  {
    state: "active",
    local: "allowed by policy",
    cloud: "allowed by policy and entitlement",
    paidInference: "allowed by provider and budget",
  },
  {
    state: "grace",
    local: "allowed until the signed offline expiry",
    cloud: "allowed until the cloud grace expiry",
    paidInference: "denied once provider billing is uncertain or grace ends",
  },
  {
    state: "past_due",
    local: "allowed only until the signed offline expiry",
    cloud: "denied",
    paidInference: "denied",
  },
  {
    state: "suspended",
    local: "no new work; already-authorized in-flight work only",
    cloud: "denied",
    paidInference: "denied",
  },
  {
    state: "cancelled",
    local: "no new work; already-authorized in-flight work only",
    cloud: "denied",
    paidInference: "denied",
  },
  {
    state: "expired",
    local: "denied",
    cloud: "denied",
    paidInference: "denied",
  },
  {
    state: "provider_unavailable",
    local: "unaffected by policy",
    cloud: "follows the subscription grace state",
    paidInference: "denied or provider-degraded with a stable reason",
  },
] as const;

export interface LicenseInput {
  subscriptionStatus: SubscriptionStatus;
  providerStatus: ProviderProjectionStatus;
  /** Signed offline validity clock from the license block. */
  offlineValidUntil: string | null;
  /** Cloud policy freshness clock from the license block. */
  policyFreshUntil: string | null;
  /** Cloud grace expiry reported by the subscription. */
  graceExpiresAt: string | null;
  /** P03 `entitlements.platform_paid_inference_grace_seconds`. */
  paidInferenceGraceSeconds?: number;
  /** Evaluation instant. Injected so the projection is deterministic. */
  now: Date;
}

const STATE_MEANING: Record<LicenseState, string> = {
  active:
    "The subscription is in good standing. Every capability class is evaluated on its own clock.",
  grace:
    "Payment is not settled. Local work continues on a previously signed snapshot; cloud managed work continues only inside the cloud grace window.",
  past_due:
    "Payment failed. Local work continues only until the signed offline expiry; cloud managed work and platform-paid inference are denied.",
  suspended:
    "The subscription is suspended. No new work of any class starts; already-authorized in-flight work may finish.",
  cancelled:
    "The subscription is cancelled and does not silently reactivate. No new work starts; already-authorized in-flight work may finish.",
  expired:
    "The signed license snapshot has lapsed. No new work of any class may start until a current snapshot is issued.",
  provider_unavailable:
    "The subscription is in good standing but the upstream provider account could not be observed. This is a provider routing fact, not a Lumi entitlement change.",
};

function toEpoch(value: string | null): number | null {
  if (value === null) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

/** The earliest of a set of instants. `null` and `undefined` are ignored. */
export function earliest(...values: (string | null | undefined)[]): string | null {
  let best: number | null = null;
  let bestIso: string | null = null;
  for (const value of values) {
    if (value === null || value === undefined) continue;
    const epoch = toEpoch(value);
    if (epoch === null) continue;
    if (best === null || epoch < best) {
      best = epoch;
      bestIso = value;
    }
  }
  return bestIso;
}

function resolveState(input: LicenseInput): LicenseState {
  const { subscriptionStatus, providerStatus } = input;
  if (subscriptionStatus === "cancelled" || subscriptionStatus === "suspended") {
    return subscriptionStatus;
  }
  const now = input.now.getTime();
  const offline = toEpoch(input.offlineValidUntil);
  if (subscriptionStatus === "past_due") {
    return offline !== null && offline <= now ? "expired" : "past_due";
  }
  if (subscriptionStatus === "grace") {
    return offline !== null && offline <= now ? "expired" : "grace";
  }
  if (providerStatus === "unavailable") return "provider_unavailable";
  return "active";
}

function localDecision(input: LicenseInput, state: LicenseState): CapabilityDecision {
  const now = input.now.getTime();
  const offline = toEpoch(input.offlineValidUntil);
  const offlineLapsed = offline !== null && offline <= now;

  const base = {
    capability: "local_only" as const,
    capabilityLabel: CAPABILITY_LABELS.local_only,
    untilBasis: [] as LicenseWindowBasis[],
    degraded: false,
  };

  if (state === "expired" || offlineLapsed) {
    return {
      ...base,
      verdict: "denied",
      allowed: false,
      until: input.offlineValidUntil,
      untilBasis: input.offlineValidUntil === null ? [] : ["offline_valid_until"],
      reason: "license_snapshot_expired",
      lapsed: true,
      meaning:
        "The signed offline snapshot has expired. New local work stops until a current license snapshot is issued.",
    };
  }
  if (state === "suspended" || state === "cancelled") {
    return {
      ...base,
      verdict: "in_flight_only",
      allowed: false,
      until: input.offlineValidUntil,
      untilBasis: input.offlineValidUntil === null ? [] : ["offline_valid_until"],
      reason: state === "suspended" ? "license_suspended" : "license_cancelled",
      lapsed: false,
      meaning:
        "No new local work may start. Work that was already authorized and in flight may finish under its existing policy.",
    };
  }
  if (state === "past_due") {
    return {
      ...base,
      verdict: "allowed_until",
      allowed: true,
      until: input.offlineValidUntil,
      untilBasis: input.offlineValidUntil === null ? [] : ["offline_valid_until"],
      reason: "license_past_due",
      lapsed: false,
      meaning:
        "Local work continues on the previously signed snapshot until the offline validity clock expires. A billing problem does not brick local work before that instant.",
    };
  }
  if (state === "grace") {
    return {
      ...base,
      verdict: "allowed_until",
      allowed: true,
      until: input.offlineValidUntil,
      untilBasis: input.offlineValidUntil === null ? [] : ["offline_valid_until"],
      reason: "license_grace_active",
      lapsed: false,
      meaning:
        "Local work continues on the previously signed snapshot until the offline validity clock expires. This is the longer of the two grace windows.",
    };
  }
  return {
    ...base,
    verdict: "allowed",
    allowed: true,
    until: input.offlineValidUntil,
    untilBasis: input.offlineValidUntil === null ? [] : ["offline_valid_until"],
    reason: input.subscriptionStatus === "trialing" ? "license_trialing" : "license_active",
    lapsed: false,
    meaning:
      "Local work is allowed by policy, bounded by the signed license snapshot. This is the local clock, not the cloud policy clock.",
  };
}

function cloudDecision(input: LicenseInput, state: LicenseState): CapabilityDecision {
  const now = input.now.getTime();
  const policyFresh = toEpoch(input.policyFreshUntil);
  const grace = toEpoch(input.graceExpiresAt);
  const policyStale = policyFresh !== null && policyFresh <= now;
  const graceEnded = grace !== null && grace <= now;

  const base = {
    capability: "cloud_control_plane" as const,
    capabilityLabel: CAPABILITY_LABELS.cloud_control_plane,
    degraded: false,
  };
  const bases: LicenseWindowBasis[] = [];
  if (input.policyFreshUntil !== null) bases.push("policy_fresh_until");
  if (input.graceExpiresAt !== null) bases.push("grace_expires_at");

  if (
    state === "expired" ||
    state === "past_due" ||
    state === "suspended" ||
    state === "cancelled"
  ) {
    return {
      ...base,
      verdict: "denied",
      allowed: false,
      until: null,
      untilBasis: [],
      reason:
        state === "expired"
          ? "license_snapshot_expired"
          : state === "past_due"
            ? "license_past_due"
            : state === "suspended"
              ? "license_suspended"
              : "license_cancelled",
      lapsed: true,
      meaning:
        "Cloud control-plane managed work is denied. This class is billed, so it does not continue on a signed offline snapshot.",
    };
  }
  if (policyStale) {
    return {
      ...base,
      verdict: "denied",
      allowed: false,
      until: input.policyFreshUntil,
      untilBasis: ["policy_fresh_until"],
      reason: "policy_snapshot_stale",
      lapsed: true,
      meaning:
        "The policy snapshot is stale, so managed cloud work fails closed until the device fetches a current snapshot.",
    };
  }
  if (graceEnded) {
    return {
      ...base,
      verdict: "denied",
      allowed: false,
      until: input.graceExpiresAt,
      untilBasis: ["grace_expires_at"],
      reason: "license_grace_expired",
      lapsed: true,
      meaning:
        "The cloud grace window has ended. Cloud managed work stays denied until billing settles.",
    };
  }

  const until = earliest(input.policyFreshUntil, input.graceExpiresAt);
  if (state === "grace") {
    return {
      ...base,
      verdict: "allowed_until",
      allowed: true,
      until,
      untilBasis: bases,
      reason: "license_grace_active",
      lapsed: false,
      meaning:
        "Cloud managed work continues only while the policy snapshot is fresh and the cloud grace window is open. Both conditions end independently.",
    };
  }
  return {
    ...base,
    verdict: "allowed_until",
    allowed: true,
    until,
    untilBasis: bases,
    reason: "license_active",
    lapsed: false,
    meaning:
      "Cloud managed work is allowed by entitlement and policy while the policy snapshot stays fresh. It never runs on a stale snapshot.",
  };
}

function providerReason(status: ProviderProjectionStatus): LicenseReason {
  if (status === "available") return "provider_available";
  if (status === "degraded") return "provider_degraded";
  if (status === "unavailable") return "provider_unavailable";
  return "provider_unknown";
}

function paidInferenceDecision(input: LicenseInput, state: LicenseState): CapabilityDecision {
  const { providerStatus } = input;
  const base = {
    capability: "platform_paid_inference" as const,
    capabilityLabel: CAPABILITY_LABELS.platform_paid_inference,
    until: null,
    untilBasis: [] as LicenseWindowBasis[],
    lapsed: false,
  };

  if (
    state === "past_due" ||
    state === "suspended" ||
    state === "cancelled" ||
    state === "expired"
  ) {
    return {
      ...base,
      verdict: "denied",
      allowed: false,
      reason:
        state === "expired"
          ? "license_snapshot_expired"
          : state === "past_due"
            ? "license_past_due"
            : state === "suspended"
              ? "license_suspended"
              : "license_cancelled",
      degraded: false,
      meaning:
        "Platform-paid inference is denied. This class is billed directly, so it is not covered by any billing grace window.",
    };
  }

  const degraded = providerStatus === "degraded";
  const deniedByProvider = providerStatus === "unavailable" || providerStatus === "unknown";

  if (deniedByProvider) {
    return {
      ...base,
      verdict: "denied",
      allowed: false,
      reason: providerReason(providerStatus),
      degraded: false,
      meaning:
        providerStatus === "unknown"
          ? "The upstream provider account has not been observed, so this class fails closed. This says nothing about the provider's actual account."
          : "The upstream provider account could not be reached, so this class is denied. This is a provider routing fact; your Lumi entitlements are unchanged.",
    };
  }

  if (state === "grace") {
    return {
      ...base,
      verdict: "allowed",
      allowed: true,
      reason:
        degraded && input.paidInferenceGraceSeconds === 0
          ? "provider_degraded"
          : "paid_inference_no_billing_grace",
      degraded,
      meaning: degraded
        ? "The provider reports a degraded account, so this class runs in a degraded state with a stable reason. There is no additional billing grace for platform-paid inference, so it stops the moment the provider reports a billing problem."
        : "Platform-paid inference receives no additional billing grace. It is allowed only while the provider account is healthy, and stops the moment the provider reports a billing problem.",
    };
  }

  return {
    ...base,
    verdict: "allowed",
    allowed: true,
    reason: providerReason(providerStatus),
    degraded,
    meaning: degraded
      ? "The provider reports a degraded account. Inference runs in a degraded state with a stable reason; your Lumi entitlements are unchanged."
      : "Allowed by the provider account and separately by the usage budget. Neither of those is an authorization permission.",
  };
}

/**
 * Project the license state and the three capability decisions. Pure and
 * deterministic: the evaluation instant is always supplied by the caller.
 */
export function projectLicense(input: LicenseInput): LicenseProjection {
  const state = resolveState(input);
  const decisions = CAPABILITY_CLASSES.map((capability) => {
    if (capability === "local_only") return localDecision(input, state);
    if (capability === "cloud_control_plane") return cloudDecision(input, state);
    return paidInferenceDecision(input, state);
  });
  const local = decisions.find((item) => item.capability === "local_only");
  const cloud = decisions.find((item) => item.capability === "cloud_control_plane");
  return {
    state,
    stateLabel: state.replaceAll("_", " "),
    stateMeaning: STATE_MEANING[state],
    subscriptionStatus: input.subscriptionStatus,
    providerStatus: input.providerStatus,
    decisions,
    localUntil: local?.until ?? null,
    cloudUntil: cloud?.until ?? null,
    paidInferenceGraceSeconds: input.paidInferenceGraceSeconds ?? 0,
    evaluatedAt: input.now.toISOString(),
  };
}

/** The two signed clocks, labelled as the distinct facts they are. */
export interface LicenseClocks {
  localUntil: string | null;
  cloudPolicyFreshUntil: string | null;
  cloudGraceExpiresAt: string | null;
  separate: true;
}

export function readLicenseClocks(input: {
  offlineValidUntil: string | null;
  policyFreshUntil: string | null;
  graceExpiresAt: string | null;
}): LicenseClocks {
  return {
    localUntil: input.offlineValidUntil,
    cloudPolicyFreshUntil: input.policyFreshUntil,
    cloudGraceExpiresAt: input.graceExpiresAt,
    separate: true,
  };
}

/** Human copy for the capability class, reused by both the panel and the tests. */
export function capabilityMeaning(capability: CapabilityClass): string {
  return CAPABILITY_MEANING[capability];
}
