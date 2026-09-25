//! Billing/entitlement provider and license-signing adapter boundaries (P06-BE-03).
//!
//! Two boundaries live here and they are deliberately separate:
//!
//! 1. [`provider`] — the [`BillingProviderAdapter`](provider::BillingProviderAdapter)
//!    boundary that maps an external billing provider onto Lumi subscription
//!    vocabulary. Product/price identifiers live *only* inside that module's
//!    private table, are never persisted in a Lumi column, and never appear in a
//!    public response, an event payload, an audit row, or a log line.
//! 2. [`signing`] — the license-signing boundary that produces the short-lived
//!    signed `LicenseSnapshot` carried inside the EXISTING `/devices/policy`
//!    response. It is not a second policy authority and there is no
//!    `/devices/license` route (P06-CR-002).
//!
//! Both boundaries keep the pure decision logic out: the domain answers *what*
//! a commercial state means (`modules::entitlements`), and only these adapters
//! answer *how* a provider or a signature is produced.

pub mod provider;
pub mod signing;

pub use provider::{
    BillingProviderAdapter, CancellationRequest, LocalBillingAdapter, PlanChangeRequest,
    PortalSession, PortalSessionRequest, ProviderCallback, ProviderError, ProviderErrorKind,
    portal_unavailable_json,
};
pub use signing::{LicenseSignatureError, LicenseSigningSecret};
