use std::fmt;

use serde::{Deserialize, Serialize};

/// Maximum password length accepted at the HTTP boundary. This is deliberately
/// well above the 64-character product minimum while keeping the KDF input
/// bounded for an edge Worker.
pub const MAX_PASSWORD_CHARS: usize = 256;
pub const MAX_PASSWORD_BYTES: usize = 1_024;

pub const PASSKEY_EVENT_REGISTERED: &str = "passkey.registered.v1";
pub const PASSKEY_EVENT_AUTHENTICATED: &str = "passkey.authentication_succeeded.v1";
pub const PASSKEY_EVENT_REVOKED: &str = "passkey.revoked.v1";
pub const PASSKEY_EVENT_SUSPICIOUS_COUNTER: &str = "passkey.suspicious_counter.v1";
pub const PASSWORD_EVENT_CONFIGURED: &str = "password.configured.v1";
pub const PASSWORD_EVENT_CHANGED: &str = "password.changed.v1";
pub const PASSWORD_EVENT_RESET: &str = "password.reset.v1";
pub const RECOVERY_EVENT_COMPLETED: &str = "authentication.recovery_completed.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebAuthnCeremonyKind {
    PasskeySignup,
    PasskeyLogin,
    PasskeyAdd,
    Reauthenticate,
}

impl WebAuthnCeremonyKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PasskeySignup => "passkey_signup",
            Self::PasskeyLogin => "passkey_login",
            Self::PasskeyAdd => "passkey_add",
            Self::Reauthenticate => "reauthenticate",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "passkey_signup" => Some(Self::PasskeySignup),
            "passkey_login" => Some(Self::PasskeyLogin),
            "passkey_add" => Some(Self::PasskeyAdd),
            "reauthenticate" => Some(Self::Reauthenticate),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyStatus {
    Pending,
    Consumed,
    Expired,
    Revoked,
}

impl CeremonyStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CounterAssessment {
    Accept,
    SuspiciousPositiveRegression,
}

/// The public WebAuthn credential is separate from the user's email identity.
/// Only public verification material and bounded metadata belong here; a
/// private key is never represented by this type.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub passkey_id: String,
    pub user_id: String,
    pub credential_id: String,
    pub public_key_cose: String,
    pub sign_count: i64,
    pub transports: Vec<String>,
    pub backup_eligible: Option<bool>,
    pub backup_state: Option<bool>,
    pub label: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

impl PasskeyCredential {
    pub fn is_usable(&self) -> bool {
        self.revoked_at.is_none()
    }

    pub fn belongs_to(&self, user_id: &str) -> bool {
        self.user_id == user_id
    }
}

impl fmt::Debug for PasskeyCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyCredential")
            .field("passkey_id", &self.passkey_id)
            .field("user_id", &self.user_id)
            .field("credential_id", &"[redacted]")
            .field("public_key_cose", &"[public-material-redacted]")
            .field("sign_count", &self.sign_count)
            .field("transports", &self.transports)
            .field("label", &self.label)
            .field("created_at", &self.created_at)
            .field("last_used_at", &self.last_used_at)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

/// The encoded KDF result is sensitive authentication material. It is kept in
/// this domain value for persistence but is redacted from diagnostics.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordCredential {
    pub user_id: String,
    pub encoded_hash: String,
    pub algorithm: String,
    pub memory_kib: i64,
    pub time_cost: i64,
    pub parallelism: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl fmt::Debug for PasswordCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordCredential")
            .field("user_id", &self.user_id)
            .field("encoded_hash", &"[redacted]")
            .field("algorithm", &self.algorithm)
            .field("memory_kib", &self.memory_kib)
            .field("time_cost", &self.time_cost)
            .field("parallelism", &self.parallelism)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Server-side ceremony state. `state_json` is an opaque verifier state
/// payload; it must never be returned to the browser or written to logs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnCeremony {
    pub ceremony_id: String,
    pub kind: WebAuthnCeremonyKind,
    pub user_id: Option<String>,
    pub pending_user_id: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub session_id: Option<String>,
    pub state_json: String,
    pub status: CeremonyStatus,
    pub attempts: i64,
    pub expires_at: String,
    pub consumed_at: Option<String>,
    pub created_at: String,
}

impl fmt::Debug for WebAuthnCeremony {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebAuthnCeremony")
            .field("ceremony_id", &self.ceremony_id)
            .field("kind", &self.kind)
            .field("user_id", &self.user_id)
            .field("pending_user_id", &self.pending_user_id)
            .field("email", &self.email.as_ref().map(|_| "[redacted]"))
            .field("display_name", &self.display_name)
            .field("session_id", &self.session_id)
            .field("state_json", &"[redacted]")
            .field("status", &self.status)
            .field("attempts", &self.attempts)
            .field("expires_at", &self.expires_at)
            .field("consumed_at", &self.consumed_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordInputError {
    Empty,
    TooLong,
}

pub fn validate_password(value: &str) -> Result<(), PasswordInputError> {
    let chars = value.chars().count();
    if chars == 0 {
        return Err(PasswordInputError::Empty);
    }
    if chars > MAX_PASSWORD_CHARS || value.len() > MAX_PASSWORD_BYTES {
        return Err(PasswordInputError::TooLong);
    }
    Ok(())
}

/// A counter of zero on both sides is a valid synced-passkey state. A positive
/// stored counter followed by a lower/equal new counter is suspicious and the
/// verifier's policy decides whether to reject or step up; this function keeps
/// the domain rule explicit for tests and audit classification.
pub fn assess_counter(stored: u32, observed: u32) -> CounterAssessment {
    if (stored == 0 && observed == 0) || observed > stored {
        CounterAssessment::Accept
    } else {
        CounterAssessment::SuspiciousPositiveRegression
    }
}

/// Removing a credential must leave at least one usable sign-in or recovery
/// method. A verified-email recovery anchor is not itself a sign-in method, so
/// the caller must pass `password_configured` or another active passkey.
pub fn can_revoke_passkey(
    target: &PasskeyCredential,
    active_passkeys: usize,
    password_configured: bool,
) -> bool {
    target.is_usable() && (active_passkeys > 1 || password_configured)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(counter: u32) -> PasskeyCredential {
        PasskeyCredential {
            passkey_id: "psk_00000000000000000000000000000001".to_owned(),
            user_id: "usr_00000000000000000000000000000001".to_owned(),
            credential_id: "credential".to_owned(),
            public_key_cose: "public".to_owned(),
            sign_count: i64::from(counter),
            transports: vec!["internal".to_owned()],
            backup_eligible: None,
            backup_state: None,
            label: "MacBook".to_owned(),
            created_at: "2026-09-25T00:00:00.000Z".to_owned(),
            last_used_at: None,
            revoked_at: None,
        }
    }

    #[test]
    fn synced_zero_counter_is_accepted_but_positive_regression_is_suspicious() {
        assert_eq!(assess_counter(0, 0), CounterAssessment::Accept);
        assert_eq!(assess_counter(0, 1), CounterAssessment::Accept);
        assert_eq!(
            assess_counter(4, 4),
            CounterAssessment::SuspiciousPositiveRegression
        );
        assert_eq!(
            assess_counter(4, 0),
            CounterAssessment::SuspiciousPositiveRegression
        );
    }

    #[test]
    fn final_passkey_cannot_be_removed_without_password_fallback() {
        let passkey = credential(0);
        assert!(!can_revoke_passkey(&passkey, 1, false));
        assert!(can_revoke_passkey(&passkey, 1, true));
        assert!(can_revoke_passkey(&passkey, 2, false));
    }

    #[test]
    fn password_validation_allows_unicode_and_long_manager_values() {
        assert!(validate_password("a").is_ok());
        assert!(validate_password("🔐 passkey fallback 密码").is_ok());
        assert!(validate_password("🔐").is_ok());
        assert!(validate_password("").is_err());
        assert!(validate_password(&"a".repeat(MAX_PASSWORD_CHARS + 1)).is_err());
    }

    #[test]
    fn password_and_ceremony_debug_output_redacts_sensitive_state() {
        let password = PasswordCredential {
            user_id: "usr_00000000000000000000000000000001".to_owned(),
            encoded_hash: "$argon2id$secret".to_owned(),
            algorithm: "argon2id".to_owned(),
            memory_kib: 19_456,
            time_cost: 2,
            parallelism: 1,
            created_at: "2026-09-25T00:00:00.000Z".to_owned(),
            updated_at: "2026-09-25T00:00:00.000Z".to_owned(),
        };
        let ceremony = WebAuthnCeremony {
            ceremony_id: "cer_00000000000000000000000000000001".to_owned(),
            kind: WebAuthnCeremonyKind::PasskeyLogin,
            user_id: None,
            pending_user_id: None,
            email: Some("person@example.com".to_owned()),
            display_name: None,
            session_id: None,
            state_json: "challenge-secret".to_owned(),
            status: CeremonyStatus::Pending,
            attempts: 0,
            expires_at: "2026-09-25T00:05:00.000Z".to_owned(),
            consumed_at: None,
            created_at: "2026-09-25T00:00:00.000Z".to_owned(),
        };
        let debug = format!("{password:?} {ceremony:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("person@example.com"));
        assert!(debug.contains("[redacted]"));
    }
}
