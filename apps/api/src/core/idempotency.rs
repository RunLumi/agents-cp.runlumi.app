use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ActorId, CoreError, OrganizationId, Timestamp};

/// Client-supplied key, validated at the request boundary and never persisted.
#[derive(Clone, PartialEq, Eq)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        {
            return Err(CoreError::InvalidIdempotencyKey);
        }
        Ok(Self(value))
    }

    /// Returns the header value for hashing at the trusted server boundary.
    pub fn expose_for_digest(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdempotencyKey([redacted])")
    }
}

/// Server-side digest of an idempotency key. The raw key is not part of records.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdempotencyKeyDigest(String);

impl IdempotencyKeyDigest {
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        if value.is_empty() || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
            return Err(CoreError::InvalidIdempotencyDigest);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for IdempotencyKeyDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdempotencyKeyDigest([redacted])")
    }
}

/// Server-side digest of the normalized request content.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestFingerprint(String);

impl RequestFingerprint {
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        if value.is_empty() || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
            return Err(CoreError::InvalidRequestFingerprint);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RequestFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequestFingerprint([redacted])")
    }
}

/// Uppercase method plus normalized path; query data is never part of the scope.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotencyScope {
    pub principal_id: ActorId,
    pub organization_id: Option<OrganizationId>,
    pub method: String,
    pub path: String,
}

impl IdempotencyScope {
    pub fn new(
        principal_id: ActorId,
        organization_id: Option<OrganizationId>,
        method: impl Into<String>,
        path: impl Into<String>,
    ) -> Result<Self, CoreError> {
        let method = method.into();
        let path = path.into();
        if method.is_empty()
            || method.len() > 16
            || !method
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
            || !path.starts_with('/')
            || path.contains('?')
            || path.contains('#')
            || path.chars().any(char::is_control)
        {
            return Err(CoreError::InvalidEndpointScope);
        }
        Ok(Self {
            principal_id,
            organization_id,
            method,
            path,
        })
    }
}

impl fmt::Debug for IdempotencyScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdempotencyScope")
            .field("principal_id", &"[redacted]")
            .field(
                "organization_id",
                &self.organization_id.as_ref().map(|_| "[redacted]"),
            )
            .field("method", &self.method)
            .field("path", &self.path)
            .finish()
    }
}

/// Successful response saved for a safe idempotency replay.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredSuccess {
    pub status: u16,
    pub body: Value,
}

impl StoredSuccess {
    pub fn new(status: u16, body: Value) -> Result<Self, CoreError> {
        if !(200..300).contains(&status) {
            return Err(CoreError::InvalidSuccessStatus);
        }
        Ok(Self { status, body })
    }
}

impl fmt::Debug for StoredSuccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredSuccess")
            .field("status", &self.status)
            .field("body", &"[redacted]")
            .finish()
    }
}

/// Whether a scoped idempotency operation is executing or can be replayed.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", content = "result", rename_all = "snake_case")]
pub enum IdempotencyState {
    Pending,
    Completed(StoredSuccess),
}

impl fmt::Debug for IdempotencyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => f.write_str("Pending"),
            Self::Completed(_) => f.write_str("Completed([redacted])"),
        }
    }
}

/// Persistable idempotency state. Expiry is bounded to 24 hours by the caller.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    pub scope: IdempotencyScope,
    pub key_digest: IdempotencyKeyDigest,
    pub request_fingerprint: RequestFingerprint,
    pub expires_at: Timestamp,
    pub state: IdempotencyState,
}

impl fmt::Debug for IdempotencyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdempotencyRecord")
            .field("scope", &self.scope)
            .field("key_digest", &"[redacted]")
            .field("request_fingerprint", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .field("state", &self.state)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn scope() -> IdempotencyScope {
        IdempotencyScope::new(
            "anonymous-local".parse().unwrap(),
            None,
            "POST",
            "/api/v1/_internal/foundation-checks",
        )
        .unwrap()
    }

    #[test]
    fn idempotency_header_validation_follows_frozen_byte_bounds() {
        assert!(IdempotencyKey::new("").is_err());
        assert!(IdempotencyKey::new("contains\nnewline").is_err());
        assert!(IdempotencyKey::new("x".repeat(129)).is_err());
        let key = IdempotencyKey::new("client-key-123").unwrap();
        assert_eq!(key.expose_for_digest(), "client-key-123");
        assert_eq!(format!("{key:?}"), "IdempotencyKey([redacted])");
    }

    #[test]
    fn scope_excludes_query_and_normalizes_method_by_contract() {
        assert!(
            IdempotencyScope::new("principal".parse().unwrap(), None, "post", "/api/v1/items")
                .is_err()
        );
        assert!(
            IdempotencyScope::new(
                "principal".parse().unwrap(),
                None,
                "POST",
                "/api/v1/items?x=1"
            )
            .is_err()
        );
        let scope = scope();
        assert_eq!(scope.method, "POST");
        assert_eq!(scope.path, "/api/v1/_internal/foundation-checks");
    }

    #[test]
    fn record_shape_uses_digest_and_replayable_success_without_raw_key() {
        let record = IdempotencyRecord {
            scope: scope(),
            key_digest: IdempotencyKeyDigest::new("sha256:0123456789abcdef").unwrap(),
            request_fingerprint: RequestFingerprint::new("sha256:fedcba9876543210").unwrap(),
            expires_at: "2026-09-25T12:00:00.000Z".parse().unwrap(),
            state: IdempotencyState::Completed(
                StoredSuccess::new(202, json!({ "delivery_status": "pending" })).unwrap(),
            ),
        };
        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(value["key_digest"], "sha256:0123456789abcdef");
        assert_eq!(value["request_fingerprint"], "sha256:fedcba9876543210");
        assert_eq!(value["state"]["status"], "completed");
        assert_eq!(value["state"]["result"]["status"], 202);
        assert!(value.get("raw_key").is_none());
        assert!(!format!("{record:?}").contains("pending"));
    }

    #[test]
    fn stored_result_accepts_only_2xx_status() {
        assert!(StoredSuccess::new(200, json!({})).is_ok());
        assert_eq!(
            StoredSuccess::new(409, json!({})),
            Err(CoreError::InvalidSuccessStatus)
        );
    }
}
