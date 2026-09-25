//! The private R2 bucket adapter itself.
//!
//! Everything Cloudflare-specific about export artifacts lives here: the
//! binding name, key construction, checksum handling, and the streaming read.
//! Callers receive plain owned values, so a domain module never imports
//! `worker::r2` or holds a `Bucket`.

use std::fmt;

use worker::{Bucket, Env, Headers, HttpMetadata, Object, Response};

/// Wrangler binding name for the single private export-artifact bucket.
///
/// The coordinator adds `r2_buckets: [{ binding: "EXPORT_ARTIFACTS", ... }]` to
/// `apps/api/wrangler.jsonc` (top level and in each `env`). There is
/// intentionally exactly one bucket: a second "public" bucket would violate
/// ADR 0006.
pub const ARTIFACT_BINDING: &str = "EXPORT_ARTIFACTS";

/// Every export artifact key starts with this prefix. Keeping the namespace
/// explicit makes `list` traversal provable and lets a scheduled expiry sweep
/// enumerate only artifact objects.
pub const ARTIFACT_KEY_PREFIX: &str = "exports/";

/// Schema bound: `export_artifacts.object_key` accepts 1..=512 bytes.
pub const MAX_OBJECT_KEY_LEN: usize = 512;

/// Schema bound: `export_artifacts.size_bytes` is a 32-bit integer column, and
/// an export larger than this is not something a Worker-mediated download is
/// meant to serve anyway.
pub const MAX_ARTIFACT_BYTES: u64 = 2_000_000_000;

/// Bounds one `list` call. Artifact listing is an expiry sweep, not a browse
/// surface, so it is deliberately tiny.
pub const MAX_LIST_RESULTS: u32 = 1_000;

/// Content types this adapter is willing to store or serve. An export artifact
/// is a structured document; refusing anything else keeps a caller from
/// smuggling an executable payload into a download the Worker will serve with
/// `Content-Disposition: attachment`.
pub const ALLOWED_CONTENT_TYPES: [&str; 3] =
    ["application/json", "application/x-ndjson", "text/csv"];

/// A validated, opaque R2 object key.
///
/// Construction is the only way to obtain one, and it rejects anything that is
/// not a bounded `exports/<scope>/<export>/<opaque>` path, so a traversal
/// segment or a client-supplied string can never reach the bucket API.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjectKey(String);

impl ObjectKey {
    pub fn new(value: impl Into<String>) -> Result<Self, ArtifactError> {
        let value = value.into();
        if !is_valid_object_key(&value) {
            return Err(ArtifactError::InvalidKey);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The `exports/<scope>/<export>/` prefix, used to enumerate one export's
    /// objects without touching another export's.
    pub fn export_prefix(&self) -> &str {
        self.0
            .rsplit_once('/')
            .map_or(self.0.as_str(), |(prefix, _)| prefix)
    }
}

impl fmt::Debug for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The opaque segment is a capability-shaped value; a log line has no
        // need to print it.
        f.debug_tuple("ObjectKey").field(&"[redacted]").finish()
    }
}

impl fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Adapter failures. No variant carries the key, the body, or a provider
/// string, so a `Debug` or `Display` cannot leak artifact content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactError {
    InvalidKey,
    InvalidContentType,
    BodyTooLarge,
    BindingUnavailable,
    ObjectAbsent,
    ProviderUnavailable,
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidKey => "export object key is invalid",
            Self::InvalidContentType => "export content type is not allowed",
            Self::BodyTooLarge => "export artifact exceeds the supported size",
            Self::BindingUnavailable => "export artifact storage is unavailable",
            Self::ObjectAbsent => "export artifact object is absent",
            Self::ProviderUnavailable => "export artifact storage is unavailable",
        })
    }
}

impl std::error::Error for ArtifactError {}

impl From<ArtifactError> for worker::Error {
    fn from(error: ArtifactError) -> Self {
        // The stable code is the whole point, so no key, body, or provider
        // string is attached to the error.
        worker::Error::RustError(error.to_string())
    }
}

/// Build the opaque key for one export artifact.
///
/// Shape: `exports/{scope}/{export_id}/{opaque}`. The `opaque` segment must be
/// CSPRNG hex of at least 32 characters; the `org_`/`usr_` segments are
/// authorization metadata and are deliberately not sufficient to reach the
/// object, because the download route re-authorizes before it ever uses the key.
pub fn build_object_key(
    scope_segment: &str,
    export_id: &str,
    opaque: &str,
) -> Result<ObjectKey, ArtifactError> {
    if !valid_segment(scope_segment) || !valid_segment(export_id) {
        return Err(ArtifactError::InvalidKey);
    }
    if opaque.len() < 32 || !opaque.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ArtifactError::InvalidKey);
    }
    ObjectKey::new(format!(
        "{ARTIFACT_KEY_PREFIX}{scope_segment}/{export_id}/{opaque}"
    ))
}

/// True when `value` is an acceptable artifact object key.
pub fn is_valid_object_key(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_OBJECT_KEY_LEN {
        return false;
    }
    if !value.starts_with(ARTIFACT_KEY_PREFIX) {
        return false;
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'.'))
    {
        return false;
    }
    let segments: Vec<&str> = value.split('/').collect();
    // `exports`, scope, export id, opaque. Exactly four, all non-empty, and no
    // `..`/`.` segment, so no traversal expression is representable.
    segments.len() == 4
        && segments[0] == "exports"
        && segments[1..]
            .iter()
            .all(|segment| !segment.is_empty() && *segment != "." && *segment != "..")
}

fn valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// A `put` request. `sha256` is the hex digest of `body`; the adapter passes it
/// to R2 so the stored object carries a verifiable checksum and `head` can
/// prove the bytes are the ones that were packaged.
pub struct PutArtifact<'a> {
    pub key: &'a ObjectKey,
    pub body: Vec<u8>,
    pub content_type: &'a str,
    pub sha256_hex: &'a str,
}

impl fmt::Debug for PutArtifact<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PutArtifact")
            .field("key", &"[redacted]")
            .field("body", &"[redacted]")
            .field("body_len", &self.body.len())
            .field("content_type", &self.content_type)
            .field("sha256_hex", &self.sha256_hex)
            .finish()
    }
}

/// What a successful `put` produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredObject {
    pub key: String,
    pub size_bytes: u64,
    pub etag: String,
    /// R2's own SHA-256 of the stored bytes, when the platform reported one.
    pub sha256_hex: Option<String>,
}

/// Object metadata for `head`. The key is intentionally absent: callers already
/// hold the `ObjectKey` they asked about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactHead {
    pub size_bytes: u64,
    pub etag: String,
    pub sha256_hex: Option<String>,
    pub content_type: Option<String>,
}

/// Response metadata for the Worker-mediated stream. Values are validated by
/// the adapter, so a caller cannot inject a header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamDescriptor {
    pub content_type: String,
    pub filename: String,
}

impl StreamDescriptor {
    pub fn new(content_type: &str, filename: &str) -> Result<Self, ArtifactError> {
        if !ALLOWED_CONTENT_TYPES.contains(&content_type) {
            return Err(ArtifactError::InvalidContentType);
        }
        if filename.is_empty()
            || filename.len() > 96
            || !filename
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(ArtifactError::InvalidKey);
        }
        Ok(Self {
            content_type: content_type.to_owned(),
            filename: filename.to_owned(),
        })
    }
}

/// The single private export-artifact bucket.
///
/// `Bucket` is a `wasm_bindgen` handle, so it is neither `Send` nor `Sync` by
/// default. `worker-rs` makes the same assertion for `Queue`, `KvStore`,
/// `D1Database`, `Hyperdrive`, and `Ai`: inside a Worker there is exactly one
/// thread and the handle is only ever used from the request or queue task that
/// created it. Declaring it here lets the binding travel through the axum
/// request extensions alongside the existing `Queue` and `SendEmail` bindings.
#[derive(Clone)]
pub struct ExportArtifactStore {
    bucket: Bucket,
}

// SAFETY: see the type-level note. A Worker isolate is single-threaded and the
// R2 handle is used only within the task that resolved it.
unsafe impl Send for ExportArtifactStore {}
// SAFETY: see the type-level note.
unsafe impl Sync for ExportArtifactStore {}

impl ExportArtifactStore {
    /// Resolve the private binding. A missing binding is a configuration error,
    /// reported as unavailable rather than as a panic, so the rest of the
    /// control plane keeps serving reads.
    pub fn from_env(env: &Env) -> Result<Self, ArtifactError> {
        env.bucket(ARTIFACT_BINDING)
            .map(|bucket| Self { bucket })
            .map_err(|_| ArtifactError::BindingUnavailable)
    }

    pub const fn new(bucket: Bucket) -> Self {
        Self { bucket }
    }

    /// Store a packaged export. Idempotent for one key: a retry overwrites the
    /// same opaque key rather than creating a second object.
    pub async fn put(&self, artifact: PutArtifact<'_>) -> Result<StoredObject, ArtifactError> {
        if !ALLOWED_CONTENT_TYPES.contains(&artifact.content_type) {
            return Err(ArtifactError::InvalidContentType);
        }
        if artifact.body.len() as u64 > MAX_ARTIFACT_BYTES {
            return Err(ArtifactError::BodyTooLarge);
        }
        let checksum = hex_decode(artifact.sha256_hex).ok_or(ArtifactError::InvalidKey)?;
        if checksum.len() != 32 {
            return Err(ArtifactError::InvalidKey);
        }
        let metadata = HttpMetadata {
            content_type: Some(artifact.content_type.to_owned()),
            // Belt and braces: even if a browser is pointed at the Worker
            // download route, the object is an attachment, never inline HTML.
            content_disposition: Some("attachment".to_owned()),
            content_language: None,
            content_encoding: None,
            cache_control: Some("no-store".to_owned()),
            cache_expiry: None,
        };
        let object = self
            .bucket
            .put(artifact.key.as_str().to_owned(), artifact.body)
            .http_metadata(metadata)
            .sha256(checksum)
            .execute()
            .await
            .map_err(|_| ArtifactError::ProviderUnavailable)?
            .ok_or(ArtifactError::ProviderUnavailable)?;
        Ok(StoredObject {
            key: object.key(),
            size_bytes: object.size(),
            etag: object.http_etag(),
            sha256_hex: object.checksum().sha256.as_deref().and_then(bytes_to_hex),
        })
    }

    /// Read object metadata without the body.
    pub async fn head(&self, key: &ObjectKey) -> Result<Option<ArtifactHead>, ArtifactError> {
        let Some(object) = self
            .bucket
            .head(key.as_str().to_owned())
            .await
            .map_err(|_| ArtifactError::ProviderUnavailable)?
        else {
            return Ok(None);
        };
        Ok(Some(head_metadata(&object)))
    }

    /// Enumerate artifact keys under a prefix, bounded. Used by the expiry
    /// sweep and by the deletion traversal; never by a browser.
    pub async fn list(&self, prefix: &str, limit: u32) -> Result<Vec<ObjectKey>, ArtifactError> {
        if !prefix.starts_with(ARTIFACT_KEY_PREFIX) || prefix.len() > MAX_OBJECT_KEY_LEN {
            return Err(ArtifactError::InvalidKey);
        }
        let listed = self
            .bucket
            .list()
            .prefix(prefix.to_owned())
            .limit(limit.clamp(1, MAX_LIST_RESULTS))
            .execute()
            .await
            .map_err(|_| ArtifactError::ProviderUnavailable)?;
        Ok(listed
            .objects()
            .iter()
            .filter_map(|object| ObjectKey::new(object.key()).ok())
            .collect())
    }

    /// Delete an object. Idempotent: the caller learns whether the object was
    /// there, and a delete of an absent object is not an error.
    pub async fn delete(&self, key: &ObjectKey) -> Result<bool, ArtifactError> {
        let existed = self.head(key).await?.is_some();
        self.bucket
            .delete(key.as_str().to_owned())
            .await
            .map_err(|_| ArtifactError::ProviderUnavailable)?;
        Ok(existed)
    }

    /// Prove absence. A deletion certificate may only claim an object is gone
    /// when this returns `true`; D1 metadata is not sufficient evidence
    /// (ADR 0006, F20-007).
    pub async fn is_absent(&self, key: &ObjectKey) -> Result<bool, ArtifactError> {
        Ok(self.head(key).await?.is_none())
    }

    /// Build the streaming download response.
    ///
    /// The object body is handed to the Workers runtime as a stream, so neither
    /// the artifact nor a bounded prefix of it is buffered in Worker memory.
    /// The caller must have re-authorized before calling this.
    pub async fn stream(
        &self,
        key: &ObjectKey,
        descriptor: &StreamDescriptor,
    ) -> Result<StreamingDownload, ArtifactError> {
        let Some(object) = self
            .bucket
            .get(key.as_str().to_owned())
            .execute()
            .await
            .map_err(|_| ArtifactError::ProviderUnavailable)?
        else {
            return Err(ArtifactError::ObjectAbsent);
        };
        let head = head_metadata(&object);
        let body = object
            .body()
            .ok_or(ArtifactError::ObjectAbsent)?
            .response_body()
            .map_err(|_| ArtifactError::ProviderUnavailable)?;
        let headers = Headers::new();
        headers
            .set("content-type", &descriptor.content_type)
            .map_err(|_| ArtifactError::ProviderUnavailable)?;
        headers
            .set(
                "content-disposition",
                &format!("attachment; filename=\"{}\"", descriptor.filename),
            )
            .map_err(|_| ArtifactError::ProviderUnavailable)?;
        // The artifact is a snapshot of one tenant's data; it must not be
        // cached by a browser or an intermediary.
        headers
            .set("cache-control", "no-store, private")
            .map_err(|_| ArtifactError::ProviderUnavailable)?;
        headers
            .set("x-content-type-options", "nosniff")
            .map_err(|_| ArtifactError::ProviderUnavailable)?;
        headers
            .set("content-length", &head.size_bytes.to_string())
            .map_err(|_| ArtifactError::ProviderUnavailable)?;
        if let Some(checksum) = head.sha256_hex.as_deref() {
            headers
                .set("x-lumi-content-sha256", checksum)
                .map_err(|_| ArtifactError::ProviderUnavailable)?;
        }
        let response = Response::from_body(body)
            .map_err(|_| ArtifactError::ProviderUnavailable)?
            .with_headers(headers);
        Ok(StreamingDownload {
            response,
            size_bytes: head.size_bytes,
            etag: head.etag,
        })
    }
}

fn head_metadata(object: &Object) -> ArtifactHead {
    ArtifactHead {
        size_bytes: object.size(),
        etag: object.http_etag(),
        sha256_hex: object.checksum().sha256.as_deref().and_then(bytes_to_hex),
        content_type: object.http_metadata().content_type,
    }
}

/// A ready-to-serve streaming download. The route converts it into the axum
/// response; the adapter never builds an `axum` type itself.
pub struct StreamingDownload {
    response: Response,
    pub size_bytes: u64,
    pub etag: String,
}

impl StreamingDownload {
    pub fn into_response(self) -> Response {
        self.response
    }
}

impl fmt::Debug for StreamingDownload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingDownload")
            .field("response", &"[streamed]")
            .field("size_bytes", &self.size_bytes)
            .field("etag", &self.etag)
            .finish()
    }
}

fn bytes_to_hex(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    Some(encoded)
}

/// Lowercase hex encode, used for checksum columns and token fingerprints.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes_to_hex(bytes).unwrap_or_default()
}

/// Lowercase hex decode. Rejects an odd length and any non-hex byte, so a
/// fingerprint column can never be populated from an arbitrary string.
pub fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        decoded.push((hex_value(pair[0])? << 4) | hex_value(pair[1])?);
    }
    Some(decoded)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORG: &str = "org_0123456789abcdef0123456789abcdef";
    const EXPORT: &str = "exp_0123456789abcdef0123456789abcdef";
    const OPAQUE: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn object_key_is_namespaced_and_opaque() {
        let key = build_object_key(ORG, EXPORT, OPAQUE).unwrap();
        assert_eq!(key.as_str(), format!("exports/{ORG}/{EXPORT}/{OPAQUE}"));
        assert!(is_valid_object_key(key.as_str()));
        assert_eq!(key.export_prefix(), format!("exports/{ORG}/{EXPORT}"));
    }

    #[test]
    fn object_key_requires_a_csprng_segment() {
        // The org and export IDs alone are not an access token.
        assert!(build_object_key(ORG, EXPORT, "org").is_err());
        assert!(build_object_key(ORG, EXPORT, "").is_err());
        assert!(build_object_key(ORG, EXPORT, &"a".repeat(31)).is_err());
        assert!(build_object_key(ORG, EXPORT, &"z".repeat(32)).is_err());
        assert!(build_object_key("../etc", EXPORT, OPAQUE).is_err());
        assert!(build_object_key(ORG, "exp_x y", OPAQUE).is_err());
    }

    #[test]
    fn object_key_rejects_traversal_and_foreign_namespaces() {
        for invalid in [
            "",
            "exports/",
            "public/anything",
            "exports/org_1/exp_1",
            "exports/org_1/exp_1/obj/extra",
            "exports/org_1/../exp_1/obj",
            "exports//exp_1/obj",
            "exports/org_1/exp_1/../../secret",
            "exports/org_1/exp_1/ob j",
        ] {
            assert!(!is_valid_object_key(invalid), "accepted {invalid}");
            assert!(ObjectKey::new(invalid).is_err(), "constructed {invalid}");
        }
    }

    #[test]
    fn object_key_debug_does_not_print_the_opaque_segment() {
        let key = build_object_key(ORG, EXPORT, OPAQUE).unwrap();
        let debug = format!("{key:?}");
        assert!(!debug.contains(OPAQUE));
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn put_input_debug_never_prints_the_artifact_body() {
        let key = build_object_key(ORG, EXPORT, OPAQUE).unwrap();
        let artifact = PutArtifact {
            key: &key,
            body: b"{\"prompt\":\"private\"}".to_vec(),
            content_type: "application/json",
            sha256_hex: &"a".repeat(64),
        };
        let debug = format!("{artifact:?}");
        assert!(!debug.contains("private"));
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn stream_descriptor_only_allows_structured_document_types() {
        assert!(StreamDescriptor::new("application/json", "exp_1.json").is_ok());
        assert_eq!(
            StreamDescriptor::new("text/html", "exp_1.html"),
            Err(ArtifactError::InvalidContentType)
        );
        assert_eq!(
            StreamDescriptor::new("application/json", "../evil"),
            Err(ArtifactError::InvalidKey)
        );
    }

    #[test]
    fn hex_helpers_round_trip_and_reject_malformed_input() {
        let bytes = [0x00u8, 0x0f, 0xa5, 0xff];
        assert_eq!(hex_encode(&bytes), "000fa5ff");
        assert_eq!(hex_decode("000fa5ff"), Some(bytes.to_vec()));
        assert_eq!(hex_decode(""), None);
        assert_eq!(hex_decode("0"), None);
        assert_eq!(hex_decode("0g"), None);
        assert_eq!(hex_decode("00FA5FF"), None);
        assert_eq!(hex_encode(&[]), "");
    }
}
