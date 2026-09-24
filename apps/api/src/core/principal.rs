use std::fmt;

use serde::{Deserialize, Serialize};

use super::{SessionId, UserId};

/// Server-resolved user principal. A value of this type is created only after
/// a revocable session has been looked up in the canonical store.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub user_id: UserId,
    pub session_id: SessionId,
    pub email: String,
    pub display_name: String,
    pub email_verified: bool,
}

impl Principal {
    pub fn new(
        user_id: UserId,
        session_id: SessionId,
        email: impl Into<String>,
        display_name: impl Into<String>,
        email_verified: bool,
    ) -> Self {
        Self {
            user_id,
            session_id,
            email: email.into(),
            display_name: display_name.into(),
            email_verified,
        }
    }
}

impl fmt::Debug for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Principal")
            .field("user_id", &self.user_id)
            .field("session_id", &self.session_id)
            .field("email", &"[redacted]")
            .field("display_name", &self.display_name)
            .field("email_verified", &self.email_verified)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_debug_redacts_email_but_keeps_safe_display_name() {
        let principal = Principal::new(
            "usr_0123456789abcdef0123456789abcdef".parse().unwrap(),
            "ses_0123456789abcdef0123456789abcdef".parse().unwrap(),
            "person@example.com",
            "Person",
            true,
        );
        let debug = format!("{principal:?}");
        assert!(!debug.contains("person@example.com"));
        assert!(debug.contains("Person"));
    }
}
