//! The internal staff credential: the third scheme, and the most restricted.
//!
//! `lumi_staff_<16 hex prefix>_<43 base64url secret>`. The scheme string is
//! deliberately longer and the prefix twice as long as `lumik_`'s, for one
//! reason: a staff token that is mistyped into an organization route must be
//! unmistakably not a machine key, and a machine key mistyped into a staff route
//! must be unmistakably not a staff token. The prefixes do not overlap, so the
//! two parsers cannot produce a successful result for the other's input.
//!
//! The raw value is shown once to the operator who provisioned the principal and
//! is never stored. What is stored is the same shape `api_keys` uses — prefix,
//! hash, fingerprint — with a 16-character prefix because staff credentials are
//! few, long-lived, and issued by a human who has to copy them exactly.

use std::fmt;

use crate::core::StaffPrincipalId;

/// `lumi_staff` — the only accepted scheme for a staff credential.
pub const STAFF_KEY_SCHEME: &str = "lumi_staff";

/// Lowercase hex. Twice `lumik_`'s length, so no `lumik_` value can be a staff
/// value with a different suffix.
const PREFIX_LEN: usize = 16;

/// 256 bits of secret, base64url without padding — identical to `lumik_`.
const SECRET_LEN: usize = 43;

/// A presented staff credential, split into its lookup prefix and its secret.
#[derive(Clone, PartialEq, Eq)]
pub struct StaffKey {
    prefix: String,
    secret: String,
}

impl StaffKey {
    pub fn parse(presented: &str) -> Result<Self, StaffKeyError> {
        let rest = presented
            .strip_prefix(STAFF_KEY_SCHEME)
            .and_then(|value| value.strip_prefix('_'))
            .ok_or(StaffKeyError::Malformed)?;
        let (prefix, secret) = rest.split_once('_').ok_or(StaffKeyError::Malformed)?;
        if prefix.len() != PREFIX_LEN
            || !prefix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(StaffKeyError::Malformed);
        }
        if secret.len() != SECRET_LEN
            || !secret
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(StaffKeyError::Malformed);
        }
        Ok(Self {
            prefix: prefix.to_owned(),
            secret: secret.to_owned(),
        })
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }
}

impl fmt::Debug for StaffKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaffKey")
            .field("prefix", &self.prefix)
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// One error variant, no detail, for the same reason `core::machine` has one: a
/// probe must not be able to learn which part of a credential was wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaffKeyError {
    Malformed,
}

impl fmt::Display for StaffKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("The staff credential is not a valid lumi_staff token.")
    }
}

/// A server-resolved staff caller.
///
/// As with `Principal` and `MachineActor`, a value of this type is a statement
/// about what the store said, and it is produced only after a row was read and
/// its hash compared.
#[derive(Clone, PartialEq, Eq)]
pub struct StaffPrincipal {
    pub staff_principal_id: StaffPrincipalId,
    pub email: String,
    pub display_name: String,
    pub credential_prefix: String,
}

impl fmt::Debug for StaffPrincipal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaffPrincipal")
            .field("staff_principal_id", &self.staff_principal_id)
            .field("credential_prefix", &self.credential_prefix)
            // The email is an internal identity and is not logged. F24's thesis
            // is that staff access is auditable; an audit trail that leaks the
            // staff list into a log aggregator defeats the point of naming people
            // in the first place.
            .field("email", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "kR7xQm2ZpL9vT4nB8wY1cD3fG6hJ0sA5uE2iO7rU4xy";

    fn valid() -> String {
        format!("{STAFF_KEY_SCHEME}_0123456789abcdef_{SECRET}")
    }

    #[test]
    fn the_test_fixture_really_is_the_documented_shape() {
        assert_eq!(SECRET.len(), SECRET_LEN);
        assert_eq!("0123456789abcdef".len(), PREFIX_LEN);
    }

    #[test]
    fn parses_the_wire_form_and_exposes_only_the_prefix() {
        let key = StaffKey::parse(&valid()).expect("valid staff key");
        assert_eq!(key.prefix(), "0123456789abcdef");
        assert_eq!(key.secret(), SECRET);
    }

    /// The property the whole three-scheme design rests on: the staff parser
    /// rejects a machine key and a session bearer, so a credential of one kind
    /// can never be interpreted as another.
    #[test]
    fn a_machine_key_is_not_a_staff_credential() {
        let machine = format!("lumik_0123456789ab_{SECRET}");
        assert_eq!(StaffKey::parse(&machine), Err(StaffKeyError::Malformed));
        // ...and because the staff prefix is 16 characters, a 12-character one
        // cannot be a staff prefix with a different reading.
        assert_eq!(
            StaffKey::parse(&format!("lumi_staff_0123456789ab_{SECRET}")),
            Err(StaffKeyError::Malformed)
        );
    }

    #[test]
    fn rejects_wrong_lengths_and_alphabets() {
        for presented in [
            String::new(),
            "lumi_staff".to_owned(),
            "lumi_staff_0123456789abcdef".to_owned(),
            "lumi_staff_0123456789abcde_SeCrEt".to_owned(),
            "lumi_staff_0123456789ABCDEF_0123456789abcdef0123456789abcdef".to_owned(),
            "lumi_staff_0123456789abcdef_".to_owned(),
            format!("lumi_staff_0123456789abcdef_{}", "+".repeat(SECRET_LEN)),
        ] {
            assert_eq!(
                StaffKey::parse(&presented),
                Err(StaffKeyError::Malformed),
                "should have been refused: {presented:?}"
            );
        }
    }

    #[test]
    fn debug_output_never_contains_the_secret() {
        let key = StaffKey::parse(&valid()).expect("valid staff key");
        let debug = format!("{key:?}");
        assert!(!debug.contains(SECRET), "secret leaked into Debug: {debug}");
        assert!(debug.contains("0123456789abcdef"));
    }

    #[test]
    fn a_staff_principal_debug_does_not_print_the_email() {
        let principal = StaffPrincipal {
            staff_principal_id: StaffPrincipalId::new("stf_0123456789abcdef0123456789abcdef")
                .expect("staff id"),
            email: "someone@internal.example".into(),
            display_name: "Someone".into(),
            credential_prefix: "0123456789abcdef".into(),
        };
        let debug = format!("{principal:?}");
        assert!(!debug.contains("someone@internal.example"));
        assert!(debug.contains("[redacted]"));
    }
}
