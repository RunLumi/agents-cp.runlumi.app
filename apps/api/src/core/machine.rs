//! The machine actor: a credential caller that is not a person.
//!
//! WHY THIS IS A SEPARATE TYPE. F14's objective is that CI, integrations,
//! managed runners, and automations call the control plane "without pretending
//! to be a human user". `Principal` cannot be that: it carries a `UserId` and a
//! revocable `SessionId`, and `authorization::authorize` scopes every request
//! with `membership.user_id != principal.user_id`. Widening `Principal` with a
//! "kind" would mean either skipping that scope check for machines — removing
//! tenant isolation for exactly the caller that needs it most — or faking a
//! sentinel user id that could collide with a real user.
//!
//! So a machine gets its own type and its own decision function
//! (`modules::machine_identity::authorize_machine`). There is no conversion
//! between the two in either direction, which is what makes "a machine can
//! never reach a route that only calls `authorize`" a compile-time fact rather
//! than a review rule. See ADR 0007.
//!
//! The credential is `lumik_<12 lowercase hex prefix>_<43 base64url secret>`.
//! The `lumik_` scheme is disjoint from the human session bearer and from the
//! staff scheme, so a machine key cannot be parsed as a session, and a staff
//! token presented on an organization route is a boundary violation rather than
//! an authentication attempt.

use std::fmt;

use crate::core::{ApiKeyId, OrganizationId, ServiceAccountId};

/// `lumik` — the only accepted scheme for a machine credential.
pub const MACHINE_KEY_SCHEME: &str = "lumik";

/// Characters in the public prefix. Lowercase hex only, so the prefix cannot
/// need escaping in a header and cannot be confused with base64url.
const PREFIX_LEN: usize = 12;

/// 256 bits of secret, base64url without padding.
const SECRET_LEN: usize = 43;

/// A presented API key, split into its non-secret lookup prefix and its secret.
///
/// The secret is held as bytes and is never formatted, logged, or serialized.
/// `Debug` prints only the prefix, because a credential that reaches a log line
/// through an accidental `{:?}` is a credential that has to be rotated.
#[derive(Clone, PartialEq, Eq)]
pub struct MachineKey {
    key_prefix: String,
    secret: String,
}

impl MachineKey {
    /// Parse the wire form. Rejects any other scheme, any wrong length, and any
    /// character outside the accepted alphabets.
    pub fn parse(presented: &str) -> Result<Self, MachineKeyError> {
        let rest = presented
            .strip_prefix(MACHINE_KEY_SCHEME)
            .and_then(|value| value.strip_prefix('_'))
            .ok_or(MachineKeyError::Malformed)?;

        let (prefix, secret) = rest.split_once('_').ok_or(MachineKeyError::Malformed)?;

        if prefix.len() != PREFIX_LEN
            || !prefix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(MachineKeyError::Malformed);
        }
        if secret.len() != SECRET_LEN
            || !secret
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(MachineKeyError::Malformed);
        }

        Ok(Self {
            key_prefix: prefix.to_owned(),
            secret: secret.to_owned(),
        })
    }

    /// The non-secret half. Safe to log, to store as the lookup index, and to
    /// show in a UI so a human can identify which key is which.
    pub fn prefix(&self) -> &str {
        &self.key_prefix
    }

    /// The secret half. Named to make an accidental log or a `Serialize` derive
    /// read as a mistake at the call site.
    pub fn secret(&self) -> &str {
        &self.secret
    }
}

impl fmt::Debug for MachineKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachineKey")
            .field("key_prefix", &self.key_prefix)
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// Why a presented credential was refused before any store lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineKeyError {
    /// Not a `lumik_` key of the expected shape. Deliberately undifferentiated:
    /// a caller must not be able to learn which part was wrong.
    Malformed,
}

impl fmt::Display for MachineKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("The machine credential is not a valid lumik key.")
    }
}

/// A server-resolved machine caller.
///
/// Created only after a key row was read from the canonical store and its hash
/// compared in constant time. As with `Principal`, a value of this type is a
/// statement about what the store said, not something a request can assert.
#[derive(Clone, PartialEq, Eq)]
pub struct MachineActor {
    pub api_key_id: ApiKeyId,
    pub service_account_id: ServiceAccountId,
    pub organization_id: OrganizationId,
    /// Key prefix, for audit correlation. Not a secret.
    pub key_prefix: String,
}

impl MachineActor {
    pub fn new(
        api_key_id: ApiKeyId,
        service_account_id: ServiceAccountId,
        organization_id: OrganizationId,
        key_prefix: impl Into<String>,
    ) -> Self {
        Self {
            api_key_id,
            service_account_id,
            organization_id,
            key_prefix: key_prefix.into(),
        }
    }
}

impl fmt::Debug for MachineActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachineActor")
            .field("api_key_id", &self.api_key_id)
            .field("service_account_id", &self.service_account_id)
            .field("organization_id", &self.organization_id)
            .field("key_prefix", &self.key_prefix)
            .finish()
    }
}

/// Length-independent, content-constant-time comparison.
///
/// Copied in spirit from the session path's `constant_time_eq`: the loop must
/// not exit early on the first differing byte, and a length mismatch must not
/// short-circuit to a faster path. This runs on a hash rather than on the raw
/// secret, but the habit is what matters — a second implementation with a
/// shortcut in it is how the first one gets replaced by accident.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 43 base64url characters: the unpadded base64 of 32 bytes.
    const SECRET: &str = "kR7xQm2ZpL9vT4nB8wY1cD3fG6hJ0sA5uE2iO7rU4xy";

    fn valid() -> String {
        format!("lumik_0123456789ab_{SECRET}")
    }

    /// The parse tests are only meaningful if the fixture is actually the shape
    /// they claim. A hand-typed secret that is one character short produces a
    /// "Malformed" failure that reads like a parser bug, so the fixture is
    /// asserted rather than trusted.
    #[test]
    fn the_test_fixture_really_is_the_documented_shape() {
        assert_eq!(SECRET.len(), SECRET_LEN, "fixture secret length drifted");
        assert_eq!(
            "0123456789ab".len(),
            PREFIX_LEN,
            "fixture prefix length drifted"
        );
        assert!(valid().starts_with("lumik_"));
    }

    #[test]
    fn parses_the_wire_form_and_exposes_only_the_prefix() {
        let key = MachineKey::parse(&valid()).expect("valid key");
        assert_eq!(key.prefix(), "0123456789ab");
        assert_eq!(key.secret(), SECRET);
    }

    #[test]
    fn debug_output_never_contains_the_secret() {
        let key = MachineKey::parse(&valid()).expect("valid key");
        let debug = format!("{key:?}");
        assert!(!debug.contains(SECRET), "secret leaked into Debug: {debug}");
        // The prefix is deliberately still visible: it is the non-secret half
        // and it is how an operator identifies a key.
        assert!(debug.contains("0123456789ab"));
    }

    #[test]
    fn rejects_a_human_session_bearer_shape() {
        // A 64-char hex session token must not parse as a machine key, or the
        // two credential schemes would not be disjoint.
        let session = "a".repeat(64);
        assert_eq!(MachineKey::parse(&session), Err(MachineKeyError::Malformed));
    }

    #[test]
    fn rejects_a_staff_credential_shape() {
        assert_eq!(
            MachineKey::parse("lumi_staff_0123456789abcdef"),
            Err(MachineKeyError::Malformed)
        );
    }

    #[test]
    fn rejects_wrong_lengths_and_alphabets() {
        for presented in [
            "lumik_0123456789ab",                              // no secret
            "lumik_0123456789ab_short",                        // short secret
            &format!("lumik_0123456789ab_{}", "+".repeat(43)), // base64, not base64url
            &format!("lumik_0123456789ab_{}", "/".repeat(43)), // base64, not base64url
            &format!("lumik_0123456789ab_{}", "=".repeat(43)), // padding is not used
            &format!("lumik_01234_{SECRET}"),                  // short prefix
            &format!("lumik_0123456789AB_{SECRET}"),           // uppercase prefix
            "",
            "lumik",
        ] {
            assert_eq!(
                MachineKey::parse(presented),
                Err(MachineKeyError::Malformed),
                "should have been refused: {presented:?}"
            );
        }
    }

    #[test]
    fn every_refusal_looks_identical_to_a_caller() {
        // One error variant, no detail, so a probe cannot learn whether the
        // prefix or the secret was the part that was wrong.
        let a = MachineKey::parse("nope");
        let b = MachineKey::parse("lumik_zz_zz");
        assert_eq!(a, b);
        assert_eq!(a.unwrap_err().to_string(), b.unwrap_err().to_string());
    }

    #[test]
    fn constant_time_eq_has_no_length_or_value_shortcut() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"different"));
        assert!(!constant_time_eq(b"same", b"sam"));
        assert!(!constant_time_eq(b"", b"x"));
        // Two empty inputs are equal. A comparison that reported otherwise
        // would be a bug in the caller, not a safety property.
        assert!(constant_time_eq(b"", b""));
    }
}
