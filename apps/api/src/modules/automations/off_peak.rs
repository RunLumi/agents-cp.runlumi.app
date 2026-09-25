//! P06 off-peak execution class.
//!
//! WHY this is a separate class and not a cron window: ZCode's off-peak work is
//! a provider-ticket-driven, no-clock queue with its own safety restrictions. A
//! scheduled off-peak window would erase that distinction and would let a
//! normal recurring schedule silently acquire off-peak's narrower tool surface.
//! P06-CR-001 freezes the separation, and F15 keeps the organization-window mode
//! alongside the provider-ticket mode as an explicit, named eligibility source.
//!
//! The controlling rule is that the SERVER MAY NARROW, NEVER BROADEN. The
//! execution host enforces its own safety restrictions; the control plane can
//! only remove capability from an occurrence, never grant capability the host
//! would refuse. [`narrow_off_peak_policy`] is the only way to combine the two,
//! and it is written so that broadening is unrepresentable rather than merely
//! discouraged.
//!
//! Network, browser, and computer-use decisions deliberately do NOT live here.
//! Those belong to the P05 tool-policy evaluator and the route configuration;
//! freezing blanket booleans here would create a second, divergent tool gate.

use serde::{Deserialize, Serialize};

use super::DomainError;

/// The frozen P06 off-peak policy schema version.
pub const MAX_OFF_PEAK_SCHEMA_VERSION: u32 = 1;

/// Provider-ticket mode: the ZCode-native class with no clock schedule.
pub const ELIGIBILITY_SOURCE_PROVIDER_TICKET: &str = "provider_ticket";
/// Organization-window mode: the F15 org-designated off-peak window.
pub const ELIGIBILITY_SOURCE_ORG_WINDOW: &str = "org_window";

/// Upper bound on the route aliases an off-peak policy may name.
pub const MAX_OFF_PEAK_ROUTE_ALIASES: usize = 16;

/// How an automation becomes eligible for off-peak execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OffPeakEligibilitySource {
    /// A provider ticket authorizes the run. There is no clock schedule, and a
    /// ticket RENEWAL does not create a second logical occurrence.
    ProviderTicket,
    /// The organization designated an off-peak window.
    OrgWindow,
}

impl OffPeakEligibilitySource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderTicket => ELIGIBILITY_SOURCE_PROVIDER_TICKET,
            Self::OrgWindow => ELIGIBILITY_SOURCE_ORG_WINDOW,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            ELIGIBILITY_SOURCE_PROVIDER_TICKET => Some(Self::ProviderTicket),
            ELIGIBILITY_SOURCE_ORG_WINDOW => Some(Self::OrgWindow),
            _ => None,
        }
    }

    /// Whether this source has a clock schedule at all.
    pub const fn has_clock_schedule(self) -> bool {
        matches!(self, Self::OrgWindow)
    }
}

/// Which execution class an occurrence runs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OffPeakMode {
    Normal,
    OffPeak,
}

impl OffPeakMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::OffPeak => "off_peak",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "normal" => Some(Self::Normal),
            "off_peak" => Some(Self::OffPeak),
            _ => None,
        }
    }
}

/// The ZCode off-peak safety restrictions the control plane understands.
///
/// These mirror the host's own restrictions. The control plane may clear them
/// (narrow to fewer restrictions is not possible — clearing a DENY would
/// broaden), so in practice a `false` here means the host already denies it and
/// the control plane never asserts otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ToolConstraints {
    /// Normal automations may not create/update/delete automations.
    pub deny_automation_mutation: bool,
    /// An off-peak run may not spawn another off-peak run, which would allow
    /// unbounded self-derivation.
    pub deny_recursive_off_peak: bool,
    /// Background processes are refused while off-peak.
    pub allow_background_processes: bool,
}

impl ToolConstraints {
    /// The frozen ZCode-derived baseline.
    pub const fn baseline() -> Self {
        Self {
            deny_automation_mutation: true,
            deny_recursive_off_peak: true,
            allow_background_processes: false,
        }
    }

    /// The most restrictive combination: everything denied.
    pub const fn maximally_restrictive() -> Self {
        Self {
            deny_automation_mutation: true,
            deny_recursive_off_peak: true,
            allow_background_processes: false,
        }
    }
}

/// The server-side off-peak policy attached to an automation or occurrence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OffPeakPolicy {
    pub schema_version: u32,
    pub eligibility_source: OffPeakEligibilitySource,
    #[serde(default)]
    pub allowed_route_aliases: Vec<String>,
    pub tool_constraints: ToolConstraints,
}

impl OffPeakPolicy {
    /// Validate the bounded shape of a stored policy.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.schema_version == 0 || self.schema_version > MAX_OFF_PEAK_SCHEMA_VERSION {
            return Err(DomainError::OffPeakNotAllowed);
        }
        if self.allowed_route_aliases.len() > MAX_OFF_PEAK_ROUTE_ALIASES {
            return Err(DomainError::OffPeakNotAllowed);
        }
        for alias in &self.allowed_route_aliases {
            if alias.is_empty()
                || alias.len() > 64
                || !alias.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
                })
            {
                return Err(DomainError::OffPeakNotAllowed);
            }
        }
        Ok(())
    }
}

/// Combine the host's baseline restrictions with the server's policy so the
/// result is at least as restrictive as BOTH.
///
/// This is deliberately asymmetric:
///
/// - a `deny_*` flag is combined with OR, so either side denying wins;
/// - `allow_background_processes` is combined with AND, so either side
///   refusing wins.
///
/// A caller therefore cannot pass a permissive server policy and end up with a
/// weaker effective policy than the host already enforces.
pub fn narrow_off_peak_policy(
    host_baseline: &ToolConstraints,
    server_policy: &ToolConstraints,
) -> ToolConstraints {
    ToolConstraints {
        deny_automation_mutation: host_baseline.deny_automation_mutation
            || server_policy.deny_automation_mutation,
        deny_recursive_off_peak: host_baseline.deny_recursive_off_peak
            || server_policy.deny_recursive_off_peak,
        allow_background_processes: host_baseline.allow_background_processes
            && server_policy.allow_background_processes,
    }
}

/// Why an occurrence may not run under the off-peak class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OffPeakDenialReason {
    /// The occurrence is not an off-peak occurrence.
    NotOffPeak,
    /// The policy shape is invalid, so the run fails closed.
    InvalidPolicy,
    /// The eligibility source is not currently satisfied (no ticket, or outside
    /// the organization window).
    NotEligible,
    /// An off-peak run tried to create another off-peak run.
    RecursiveOffPeak,
    /// An off-peak run tried to mutate automations.
    AutomationMutationDenied,
    /// A background process was requested while off-peak.
    BackgroundProcessDenied,
    /// The requested route alias is not in the allowed set.
    RouteAliasNotAllowed,
}

/// The facts a decision needs, all supplied by the adapter.
///
/// Not `Copy`: it owns the server policy so the decision can borrow it without
/// cloning on every turn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OffPeakContext<'a> {
    pub mode: OffPeakMode,
    pub policy: Option<OffPeakPolicy>,
    /// The host's own current restrictions for this turn.
    pub host_baseline: ToolConstraints,
    /// Whether the eligibility source is currently satisfied.
    pub eligibility_satisfied: bool,
    /// What the turn is trying to do.
    pub creates_off_peak: bool,
    pub mutates_automation: bool,
    pub starts_background_process: bool,
    /// The lower-cost route alias the turn requested, if any.
    pub requested_route_alias: Option<&'a str>,
}

/// The outcome of an off-peak admission check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OffPeakDecision {
    /// The occurrence may proceed. Carries the effective, narrowed constraints
    /// the host must enforce for this turn.
    Allowed {
        effective: ToolConstraints,
    },
    Denied(OffPeakDenialReason),
}

/// Evaluate whether an occurrence may run under its declared off-peak class.
///
/// A NORMAL occurrence is never constrained by off-peak policy; it simply is not
/// an off-peak run. Every denial path fails closed with a stable reason and no
/// caller-supplied text.
pub fn evaluate_off_peak(context: &OffPeakContext<'_>) -> OffPeakDecision {
    if context.mode == OffPeakMode::Normal {
        return OffPeakDecision::Allowed {
            effective: context.host_baseline,
        };
    }

    let Some(policy) = context.policy.as_ref() else {
        // An off-peak occurrence with no server policy cannot be evaluated, so
        // it is refused rather than silently treated as normal.
        return OffPeakDecision::Denied(OffPeakDenialReason::InvalidPolicy);
    };
    if policy.validate().is_err() {
        return OffPeakDecision::Denied(OffPeakDenialReason::InvalidPolicy);
    }
    if !context.eligibility_satisfied {
        return OffPeakDecision::Denied(OffPeakDenialReason::NotEligible);
    }

    // The effective policy is the intersection of what the host already
    // enforces and what the server requires.
    let effective = narrow_off_peak_policy(&context.host_baseline, &policy.tool_constraints);

    if context.creates_off_peak && effective.deny_recursive_off_peak {
        return OffPeakDecision::Denied(OffPeakDenialReason::RecursiveOffPeak);
    }
    if context.mutates_automation && effective.deny_automation_mutation {
        return OffPeakDecision::Denied(OffPeakDenialReason::AutomationMutationDenied);
    }
    if context.starts_background_process && !effective.allow_background_processes {
        return OffPeakDecision::Denied(OffPeakDenialReason::BackgroundProcessDenied);
    }
    if let Some(alias) = context.requested_route_alias
        && !policy
            .allowed_route_aliases
            .iter()
            .any(|allowed| allowed == alias)
    {
        return OffPeakDecision::Denied(OffPeakDenialReason::RouteAliasNotAllowed);
    }

    OffPeakDecision::Allowed { effective }
}
