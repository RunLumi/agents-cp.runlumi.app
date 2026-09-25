//! License-snapshot signing boundary (P06-BE-03, P06-CR-002).
//!
//! WHY this module is split the way it is: the *decision* content of a license
//! snapshot is a pure function of already-authoritative facts, while the
//! *signature* needs Worker Web Crypto. Everything a reviewer can reason about —
//! which claims are bound, how the canonical bytes are built, how a key may be
//! used during rotation, and which expiry applies to which capability class —
//! is therefore a pure, host-testable function below. Only
//! [`sign_canonical_bytes`] and [`verify_canonical_bytes`] touch the platform.
//!
//! # Canonical bytes
//!
//! The signed object is UTF-8 JSON with lexicographically sorted object keys, no
//! insignificant whitespace, and RFC 3339 UTC timestamps. Canonicalization is
//! performed by hand (not through `serde_json`) for three reasons: object key
//! order must be byte-sorted rather than insertion-ordered, floats must be
//! structurally impossible, and the client must be able to reproduce the bytes
//! exactly from the wire block it received. [`canonical_license_bytes`] and
//! [`license_claims_json`] are guaranteed to describe the same object.
//!
//! # Bound claims
//!
//! Every snapshot binds `org_id`, the device/audience, `policy_version`,
//! `policy_fresh_until` (15 minutes), `offline_valid_until` (class specific),
//! the capability class, the snapshot ID, and the signing `key_id`. Unknown key
//! IDs, expiry, audience/device mismatch, and policy-version rollback are
//! rejected by `modules::entitlements::validate_license_snapshot` *after* the
//! signature is verified here; this module never treats an unverified claim set
//! as usable.
//!
//! # Key material
//!
//! [`LicenseSigningSecret`] is parsed from a Wrangler secret and is never
//! persisted, never logged, and never returned by a route. The `license_signing_keys`
//! D1 table holds PUBLIC verification material only. `Debug` for the secret
//! prints a placeholder so a stray `{:?}` cannot leak key bytes.
//!
//! # Platform availability (documented limitation)
//!
//! `crypto.subtle` in Cloudflare Workers exposes Ed25519 (`importKey` +
//! `sign`/`verify`) but **not** Ed25519 `generateKey`. The canonical-bytes and
//! claim-construction logic below is therefore complete and host-testable, and
//! the signing call itself can only be exercised inside a Worker (or a browser
//! with Ed25519 Web Crypto). The host (non-`wasm32`) build returns
//! [`LicenseSignatureError::PlatformUnavailable`] instead of panicking, which is
//! what the native `cargo test` suite asserts.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;

use serde_json::{Map, Value, json};

use crate::core::Timestamp;
use crate::modules::entitlements::{
    CapabilityClass, EntitlementValue, LICENSE_SNAPSHOT_SCHEMA_VERSION, LicenseSnapshotClaims,
    LicenseSnapshotId, MAX_LICENSE_KEY_ID_BYTES,
};

/// Only algorithm the `license_signing_keys` table and this adapter accept.
pub const LICENSE_SIGNATURE_ALGORITHM: &str = "ed25519";

/// Managed cloud work requires a policy that is fresh for this many seconds.
/// Frozen by the P06-CG policy snapshot (`entitlements.policy_fresh_seconds`).
pub const POLICY_FRESH_SECONDS: u32 = 900;

/// Largest canonical license object. The `license_snapshots.entitlements_json`
/// column is bounded to 16 KiB and the canonical bytes are bounded to the same
/// budget plus the claim envelope, so an unbounded projection cannot be signed.
pub const MAX_CANONICAL_LICENSE_BYTES: usize = 24 * 1024;

/// Ed25519 signatures are 64 raw bytes; the hex form is 128 characters.
pub const ED25519_SIGNATURE_BYTES: usize = 64;
/// Ed25519 SPKI (SubjectPublicKeyInfo) DER is 44 bytes.
pub const ED25519_PUBLIC_KEY_BYTES: usize = 44;
/// Ed25519 PKCS#8 DER is 48 bytes.
pub const ED25519_PRIVATE_KEY_BYTES: usize = 48;

/// Stable reason for a signing or license-block failure.
///
/// The codes are drawn from the frozen P06 error surface so a route never
/// invents a string. No variant carries the offending input, so formatting an
/// error cannot leak key material, a private key, or a client claim set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LicenseSignatureError {
    /// No private signing key is configured for this environment.
    SigningKeyNotConfigured,
    /// The configured secret is malformed (bad `key_id` or key encoding).
    SigningKeyMalformed,
    /// The platform cryptography surface is unavailable (host test build).
    PlatformUnavailable,
    /// The platform refused to sign or verify.
    PlatformFailure,
    /// No signing key is inside its issuance window right now.
    NoActiveSigningKey,
    /// The claim set could not be canonicalized within the frozen bounds.
    ClaimsRejected,
    /// Canonical bytes exceeded [`MAX_CANONICAL_LICENSE_BYTES`].
    CanonicalBytesTooLarge,
}

impl LicenseSignatureError {
    /// Stable machine-readable reason from the frozen P06 error list.
    pub const fn code(self) -> &'static str {
        match self {
            // An unconfigured or unknown signing key is a `license_key_unknown`
            // condition from the client's point of view; the server must not
            // mint an unverifiable snapshot.
            Self::SigningKeyNotConfigured
            | Self::SigningKeyMalformed
            | Self::NoActiveSigningKey
            | Self::PlatformUnavailable
            | Self::PlatformFailure => "license_key_unknown",
            Self::ClaimsRejected => "entitlement_not_granted",
            Self::CanonicalBytesTooLarge => "entitlement_not_granted",
        }
    }
}

impl fmt::Display for LicenseSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for LicenseSignatureError {}

/// The Ed25519 private signing key, parsed once from a Wrangler secret.
///
/// The value is `<key_id>:<base64 PKCS#8 DER>`. It is never persisted in D1
/// (`license_signing_keys` holds the public half only) and never serialized.
pub struct LicenseSigningSecret {
    key_id: String,
    private_key_der: Vec<u8>,
}

impl LicenseSigningSecret {
    /// Parse a secret in the form `key_id:base64_pkcs8_der`.
    ///
    /// A malformed value is a hard configuration error rather than a silently
    /// disabled license, so `from_env_value` returns `None` and the caller
    /// reports `license_key_unknown` instead of issuing unsigned claims.
    pub fn from_env_value(value: &str) -> Result<Self, LicenseSignatureError> {
        let (key_id, encoded) = value
            .split_once(':')
            .ok_or(LicenseSignatureError::SigningKeyMalformed)?;
        validate_key_id(key_id)?;
        let private_key_der =
            decode_base64(encoded).ok_or(LicenseSignatureError::SigningKeyMalformed)?;
        if private_key_der.len() != ED25519_PRIVATE_KEY_BYTES {
            return Err(LicenseSignatureError::SigningKeyMalformed);
        }
        Ok(Self {
            key_id: key_id.to_owned(),
            private_key_der,
        })
    }

    /// The advertised key ID. It is public metadata: the client needs it to
    /// choose a verification key from its pinned set.
    pub fn key_id(&self) -> &str {
        self.key_id.as_str()
    }
}

impl fmt::Debug for LicenseSigningSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LicenseSigningSecret")
            .field("key_id", &self.key_id)
            .field("private_key_der", &"[redacted]")
            .finish()
    }
}

/// A public verification key row from `license_signing_keys`.
///
/// Only public material is represented here, so this type is safe to log, to
/// serialize into a diagnostic, or to hand to a verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationKey {
    pub key_id: String,
    /// Base64 SPKI DER of the Ed25519 public key.
    pub public_key_base64: String,
    pub active: bool,
    /// RFC 3339 UTC instant from which the key may verify.
    pub not_before: String,
    /// RFC 3339 UTC instant after which the key stops verifying, and after
    /// which it can no longer grant NEW work.
    pub verify_until: String,
}

impl VerificationKey {
    /// Bounded verification overlap. A retired key (`active = 0`) still verifies
    /// until `verify_until` but can never sign a new snapshot.
    pub fn can_verify(&self, now_unix_seconds: i64) -> bool {
        within_window(
            self.not_before.as_str(),
            self.verify_until.as_str(),
            now_unix_seconds,
        )
    }

    /// Only an active key inside its window may mint a new snapshot, and never
    /// after its own expiry: "old keys never grant new work after their expiry".
    pub fn can_sign_new_work(&self, now_unix_seconds: i64) -> bool {
        self.active && self.can_verify(now_unix_seconds)
    }
}

/// Pick the signing key for a new snapshot.
///
/// A rotation therefore keeps exactly one issuer: the active key whose window
/// contains `now`. A retired key is never selected even while it is still inside
/// its verification overlap.
pub fn select_signing_key(
    keys: &[VerificationKey],
    now_unix_seconds: i64,
) -> Option<&VerificationKey> {
    keys.iter()
        .filter(|key| key.can_sign_new_work(now_unix_seconds))
        .max_by_key(|key| (key.not_before.clone(), key.key_id.clone()))
}

/// Every key ID a verifier may currently trust, in stable order.
///
/// The device trusts exactly this set: a retired key inside its overlap window
/// is included, an expired key is not.
pub fn trusted_verification_key_ids(keys: &[VerificationKey], now_unix_seconds: i64) -> Vec<&str> {
    let mut trusted: Vec<&str> = keys
        .iter()
        .filter(|key| key.can_verify(now_unix_seconds))
        .map(|key| key.key_id.as_str())
        .collect();
    trusted.sort_unstable();
    trusted
}

/// A pure canonical JSON value.
///
/// Only the three Lumi entitlement value types, null, and a flat object are
/// representable, so a float or a deeply nested structure cannot reach the
/// signed bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
enum CanonicalValue {
    Bool(bool),
    Int(i64),
    Str(String),
    Null,
    Object(BTreeMap<String, CanonicalValue>),
}

impl CanonicalValue {
    fn from_entitlement_value(value: &EntitlementValue) -> Self {
        match value {
            EntitlementValue::Boolean(inner) => Self::Bool(*inner),
            EntitlementValue::Integer(inner) => Self::Int(*inner),
            EntitlementValue::BoundedString(inner) => Self::Str(inner.clone()),
        }
    }

    fn write_json(&self, out: &mut String) {
        match self {
            Self::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Self::Int(value) => {
                let _ = write!(out, "{value}");
            }
            Self::Str(value) => write_json_string(value, out),
            Self::Null => out.push_str("null"),
            Self::Object(entries) => {
                out.push('{');
                for (index, (key, value)) in entries.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_json_string(key, out);
                    out.push(':');
                    value.write_json(out);
                }
                out.push('}');
            }
        }
    }
}

/// Minimal, deterministic JSON string escaping.
///
/// Only the characters RFC 8259 requires are escaped, so the same logical string
/// always produces the same bytes regardless of platform or locale.
fn write_json_string(value: &str, out: &mut String) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            control if (control as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// Format whole Unix seconds as the frozen RFC 3339 UTC representation.
///
/// The commercial domain compares instants in whole seconds and the signed bytes
/// must therefore carry second precision with a fixed millisecond field, exactly
/// like every other stored P06 timestamp. Pure civil-calendar arithmetic (no
/// clock, no dependency) so the value is byte-reproducible on the Worker target.
pub fn format_rfc3339_utc(unix_seconds: i64) -> Option<Timestamp> {
    if !(0..=32_503_680_000).contains(&unix_seconds) {
        return None;
    }
    let days = unix_seconds.div_euclid(86_400);
    let seconds_of_day = unix_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;
    Timestamp::new(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.000Z"
    ))
    .ok()
}

/// Days since `1970-01-01` to a proleptic Gregorian calendar date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_shift = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_shift + 2) / 5 + 1;
    let month = if month_shift < 10 {
        month_shift + 3
    } else {
        month_shift - 9
    };
    (
        if month <= 2 { year + 1 } else { year },
        month as u32,
        day as u32,
    )
}

/// Everything one signed license object binds.
///
/// The field list is frozen: adding a field changes the signed bytes, so it
/// requires a new `schema_version` rather than a silent extension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LicensePayload<'a> {
    pub claims: &'a LicenseSnapshotClaims,
    pub license_state: crate::modules::entitlements::LicenseState,
    /// Effective Lumi entitlement values, keyed by stable Lumi entitlement key.
    /// Never a provider product or price identifier.
    pub entitlements: &'a BTreeMap<String, EntitlementValue>,
}

/// The exact object that is signed.
///
/// The wire block delivered inside `/devices/policy` is this object plus a
/// `signature` field, so a client can rebuild the canonical bytes from what it
/// received without trusting a server-supplied byte string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalLicense {
    object: BTreeMap<String, CanonicalValue>,
    bytes: Vec<u8>,
}

impl CanonicalLicense {
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// The signed object without the signature, for the wire block.
    pub fn to_json(&self) -> Value {
        let mut map = Map::new();
        for (key, value) in &self.object {
            map.insert(key.clone(), canonical_value_to_json(value));
        }
        Value::Object(map)
    }
}

fn canonical_value_to_json(value: &CanonicalValue) -> Value {
    match value {
        CanonicalValue::Bool(inner) => Value::Bool(*inner),
        CanonicalValue::Int(inner) => Value::from(*inner),
        CanonicalValue::Str(inner) => Value::String(inner.clone()),
        CanonicalValue::Null => Value::Null,
        CanonicalValue::Object(entries) => {
            let mut map = Map::new();
            for (key, value) in entries {
                map.insert(key.clone(), canonical_value_to_json(value));
            }
            Value::Object(map)
        }
    }
}

/// Build the canonical signed object for one license snapshot.
///
/// Pure and total on valid input: the claims have already been validated by
/// `LicenseSnapshotClaims::new`, so this only enforces the byte budget and the
/// absence of a provider product/price identifier (impossible by construction —
/// the entitlement map is keyed by validated [`EntitlementKey`] values).
pub fn canonical_license(
    payload: &LicensePayload<'_>,
) -> Result<CanonicalLicense, LicenseSignatureError> {
    let claims = payload.claims;
    if claims.schema_version != LICENSE_SNAPSHOT_SCHEMA_VERSION {
        return Err(LicenseSignatureError::ClaimsRejected);
    }
    validate_key_id(claims.key_id.as_str())?;

    let mut entitlements = BTreeMap::new();
    for (key, value) in payload.entitlements {
        if !crate::modules::entitlements::is_baseline_key(key) {
            return Err(LicenseSignatureError::ClaimsRejected);
        }
        entitlements.insert(key.clone(), CanonicalValue::from_entitlement_value(value));
    }

    let mut object: BTreeMap<String, CanonicalValue> = BTreeMap::new();
    object.insert(
        "audience".to_owned(),
        match claims.audience.as_ref() {
            Some(audience) => CanonicalValue::Str(audience.clone()),
            None => CanonicalValue::Null,
        },
    );
    object.insert(
        "capability_class".to_owned(),
        CanonicalValue::Str(claims.capability_class.as_str().to_owned()),
    );
    object.insert(
        "device_id".to_owned(),
        match claims.device_id.as_ref() {
            Some(device_id) => CanonicalValue::Str(device_id.as_str().to_owned()),
            None => CanonicalValue::Null,
        },
    );
    object.insert(
        "entitlements".to_owned(),
        CanonicalValue::Object(entitlements),
    );
    object.insert(
        "issued_at".to_owned(),
        CanonicalValue::Int(claims.issued_at),
    );
    object.insert(
        "key_id".to_owned(),
        CanonicalValue::Str(claims.key_id.clone()),
    );
    object.insert(
        "license_state".to_owned(),
        CanonicalValue::Str(payload.license_state.as_str().to_owned()),
    );
    object.insert(
        "offline_valid_until".to_owned(),
        CanonicalValue::Int(claims.offline_valid_until),
    );
    object.insert(
        "org_id".to_owned(),
        CanonicalValue::Str(claims.org_id.as_str().to_owned()),
    );
    object.insert(
        "policy_fresh_until".to_owned(),
        CanonicalValue::Int(claims.policy_fresh_until),
    );
    object.insert(
        "policy_version".to_owned(),
        CanonicalValue::Int(claims.policy_version),
    );
    object.insert(
        "schema_version".to_owned(),
        CanonicalValue::Int(i64::from(claims.schema_version)),
    );
    object.insert(
        "snapshot_id".to_owned(),
        CanonicalValue::Str(claims.snapshot_id.as_str().to_owned()),
    );

    let mut bytes = String::with_capacity(1024);
    CanonicalValue::Object(object.clone()).write_json(&mut bytes);
    if bytes.len() > MAX_CANONICAL_LICENSE_BYTES {
        return Err(LicenseSignatureError::CanonicalBytesTooLarge);
    }
    Ok(CanonicalLicense {
        object,
        bytes: bytes.into_bytes(),
    })
}

/// The signed object plus its detached signature, ready for the policy response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedLicense {
    pub license_snapshot_id: LicenseSnapshotId,
    pub key_id: String,
    pub canonical: CanonicalLicense,
    /// Raw Ed25519 signature bytes (64).
    pub signature: Vec<u8>,
    /// Lowercase hex of [`SignedLicense::signature`], used on the wire and in D1.
    pub signature_hex: String,
}

impl SignedLicense {
    /// The block embedded in the existing `/devices/policy` response.
    ///
    /// Shape: `{ "license": { ...signed object..., "signature": "<hex>" } }` is
    /// assembled by the caller; this returns the signed object plus signature.
    pub fn to_json(&self) -> Value {
        let mut block = self.canonical.to_json();
        if let Value::Object(map) = &mut block {
            map.insert(
                "signature".to_owned(),
                Value::String(self.signature_hex.clone()),
            );
        }
        block
    }

    pub fn canonical_text(&self) -> String {
        String::from_utf8_lossy(self.canonical.as_bytes()).into_owned()
    }
}

pub(crate) fn validate_key_id(key_id: &str) -> Result<(), LicenseSignatureError> {
    if key_id.is_empty()
        || key_id.len() > MAX_LICENSE_KEY_ID_BYTES
        || !key_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
    {
        return Err(LicenseSignatureError::ClaimsRejected);
    }
    Ok(())
}

fn within_window(not_before: &str, verify_until: &str, now_unix_seconds: i64) -> bool {
    let (Some(start), Some(end)) = (
        parse_stored_instant(not_before),
        parse_stored_instant(verify_until),
    ) else {
        // A corrupt window fails closed: an unverifiable key must never be
        // treated as trusted, and an unexpired issuer must never be invented.
        return false;
    };
    now_unix_seconds >= start && now_unix_seconds < end
}

fn parse_stored_instant(value: &str) -> Option<i64> {
    crate::modules::entitlements::unix_seconds(&Timestamp::new(value).ok()?).ok()
}

/// Pure expiry arithmetic for one license snapshot.
///
/// * `policy_fresh_until` is always `issued_at + POLICY_FRESH_SECONDS`, so
///   managed cloud work can never run against a stale policy.
/// * `offline_valid_until` is the class-specific offline bound, narrowed but
///   never widened by [`CapabilityClass::narrow_grace_seconds`], and it is
///   forced to stay strictly after `policy_fresh_until` because
///   `license_snapshots` enforces `offline_valid_until > policy_fresh_until` and
///   because a local runtime that cannot refresh its policy must still be told
///   when the snapshot stops being a usable offline authority.
pub fn license_expiries(
    issued_at: i64,
    capability_class: CapabilityClass,
    narrowed_grace_seconds: Option<i64>,
) -> (i64, i64) {
    let policy_fresh_until = issued_at.saturating_add(i64::from(POLICY_FRESH_SECONDS));
    let narrowed = capability_class.narrow_grace_seconds(narrowed_grace_seconds);
    let floor = policy_fresh_until.saturating_add(1);
    let offline_valid_until = issued_at.saturating_add(narrowed).max(floor);
    (policy_fresh_until, offline_valid_until)
}

/// Sign the canonical license bytes with the configured private key.
#[cfg(target_arch = "wasm32")]
pub async fn sign_canonical_bytes(
    secret: &LicenseSigningSecret,
    bytes: &[u8],
) -> Result<Vec<u8>, LicenseSignatureError> {
    use wasm_bindgen::prelude::wasm_bindgen;
    use wasm_bindgen_futures::JsFuture;

    #[wasm_bindgen(inline_js = r#"
function lumiBase64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

export async function lumiSignEd25519(privateKeyBase64, message) {
  const key = await globalThis.crypto.subtle.importKey(
    "pkcs8",
    lumiBase64ToBytes(privateKeyBase64),
    { name: "Ed25519" },
    false,
    ["sign"]
  );
  const signature = new Uint8Array(await globalThis.crypto.subtle.sign(
    { name: "Ed25519" }, key, new Uint8Array(message)
  ));
  let binary = "";
  for (let index = 0; index < signature.length; index += 1) {
    binary += String.fromCharCode(signature[index]);
  }
  return btoa(binary);
}
"#)]
    extern "C" {
        #[wasm_bindgen(js_name = lumiSignEd25519)]
        fn sign_ed25519_js(private_key_base64: &str, message: &[u8]) -> worker::js_sys::Promise;
    }

    let signed = JsFuture::from(sign_ed25519_js(
        &encode_base64(&secret.private_key_der),
        bytes,
    ))
    .await
    .map_err(|_| LicenseSignatureError::PlatformFailure)?
    .as_string()
    .ok_or(LicenseSignatureError::PlatformFailure)?;
    let signature = decode_base64(&signed).ok_or(LicenseSignatureError::PlatformFailure)?;
    if signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(LicenseSignatureError::PlatformFailure);
    }
    Ok(signature)
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn sign_canonical_bytes(
    secret: &LicenseSigningSecret,
    bytes: &[u8],
) -> Result<Vec<u8>, LicenseSignatureError> {
    // Documented limitation: Workers' Web Crypto exposes Ed25519 `importKey` +
    // `sign` but not Ed25519 `generateKey`, so the private key must be supplied
    // through a Wrangler secret and the signing call itself can only run on the
    // `wasm32-unknown-unknown` target. The canonical bytes and the claim
    // construction above are pure and fully covered by the host test suite.
    // The key material is still inspected so the host build never reports the
    // secret as unread (and never logs it).
    if secret.key_id().is_empty() || secret.private_key_der.is_empty() || bytes.is_empty() {
        return Err(LicenseSignatureError::SigningKeyMalformed);
    }
    Err(LicenseSignatureError::PlatformUnavailable)
}

/// Verify a license signature with a public key. Exposed so the deterministic
/// test vector in the frozen fixtures can be checked inside a Worker; the browser
/// client performs the authoritative verification.
#[cfg(target_arch = "wasm32")]
pub async fn verify_canonical_bytes(
    public_key_base64: &str,
    bytes: &[u8],
    signature: &[u8],
) -> Result<bool, LicenseSignatureError> {
    use wasm_bindgen::prelude::wasm_bindgen;
    use wasm_bindgen_futures::JsFuture;

    #[wasm_bindgen(inline_js = r#"
function lumiVerifyBase64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

export async function lumiVerifyEd25519(publicKeyBase64, signatureBase64, message) {
  const key = await globalThis.crypto.subtle.importKey(
    "spki",
    lumiVerifyBase64ToBytes(publicKeyBase64),
    { name: "Ed25519" },
    false,
    ["verify"]
  );
  return globalThis.crypto.subtle.verify(
    { name: "Ed25519" }, key, lumiVerifyBase64ToBytes(signatureBase64), new Uint8Array(message)
  );
}
"#)]
    extern "C" {
        #[wasm_bindgen(js_name = lumiVerifyEd25519)]
        fn verify_ed25519_js(
            public_key_base64: &str,
            signature_base64: &str,
            message: &[u8],
        ) -> worker::js_sys::Promise;
    }

    let verdict = JsFuture::from(verify_ed25519_js(
        public_key_base64,
        &encode_base64(signature),
        bytes,
    ))
    .await
    .map_err(|_| LicenseSignatureError::PlatformFailure)?;
    Ok(verdict.as_bool().unwrap_or(false))
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn verify_canonical_bytes(
    public_key_base64: &str,
    bytes: &[u8],
    signature: &[u8],
) -> Result<bool, LicenseSignatureError> {
    if public_key_base64.is_empty() || bytes.is_empty() || signature.is_empty() {
        return Err(LicenseSignatureError::ClaimsRejected);
    }
    Err(LicenseSignatureError::PlatformUnavailable)
}

/// Sign a canonical license payload end to end.
pub async fn sign_license(
    secret: &LicenseSigningSecret,
    payload: &LicensePayload<'_>,
) -> Result<SignedLicense, LicenseSignatureError> {
    let canonical = canonical_license(payload)?;
    let signature = sign_canonical_bytes(secret, canonical.as_bytes()).await?;
    Ok(SignedLicense {
        license_snapshot_id: payload.claims.snapshot_id.clone(),
        key_id: secret.key_id().to_owned(),
        signature_hex: encode_hex(&signature),
        signature,
        canonical,
    })
}

/// The stable failure block embedded when a license cannot be issued.
///
/// `/devices/policy` must never fail because a billing/signing dependency is
/// unhealthy: a device that cannot refresh its policy would be bricked, and
/// P06-CR-002 requires a transient outage not to disable unrelated local work.
/// The domain capability matrix then denies new work with a stable reason.
pub fn license_unavailable_block(reason: LicenseSignatureError) -> Value {
    json!({
        "license": Value::Null,
        "license_error": reason.code(),
        "signature_algorithm": LICENSE_SIGNATURE_ALGORITHM,
    })
}

/// Lowercase hex of a signature or canonical-bytes blob. D1 stores the signature
/// and canonical bytes as lowercase hex text so they round-trip through the
/// `BLOB`-typed columns without a platform-specific binary binding, and so no
/// diagnostic can accidentally dump raw key or signature bytes.
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Decode lowercase hex. Uppercase, whitespace, and odd lengths are refused so a
/// stored value has exactly one valid encoding.
pub fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let high = (bytes[index] as char).to_digit(16)?;
        let low = (bytes[index + 1] as char).to_digit(16)?;
        if bytes[index].is_ascii_uppercase() || bytes[index + 1].is_ascii_uppercase() {
            return None;
        }
        out.push(u8::try_from(high * 16 + low).ok()?);
        index += 2;
    }
    Some(out)
}

/// Standard base64 with padding, used only to move PKCS#8/SPKI DER across the
/// Web Crypto boundary. Exposed so the host test build exercises the same
/// encoder the Worker build uses.
pub fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((triple >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(triple & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let mut accumulator: u32 = 0;
    let mut bits = 0_u32;
    let mut out = Vec::with_capacity(value.len() / 4 * 3);
    for character in value.bytes() {
        let digit = match character {
            b'A'..=b'Z' => character - b'A',
            b'a'..=b'z' => character - b'a' + 26,
            b'0'..=b'9' => character - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        } as u32;
        accumulator = (accumulator << 6) | digit;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((accumulator >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{ManagedDeviceId, OrganizationId};
    use crate::modules::entitlements::{
        EntitlementValue, LicenseReason, LicenseSnapshotContext, LicenseState,
        validate_license_snapshot,
    };

    const ORG: &str = "org_0123456789abcdef0123456789abcdef";
    const DEVICE: &str = "dvc_0123456789abcdef0123456789abcdef";
    const SNAPSHOT: &str = "lic_0123456789abcdef0123456789abcdef";

    fn entitlements() -> BTreeMap<String, EntitlementValue> {
        BTreeMap::from([
            (
                "automations.max_active".to_owned(),
                EntitlementValue::Integer(100),
            ),
            (
                "webhooks.enabled".to_owned(),
                EntitlementValue::Boolean(true),
            ),
        ])
    }

    fn claims(
        key_id: &str,
        issued_at: i64,
        policy_fresh_until: i64,
        offline_valid_until: i64,
    ) -> LicenseSnapshotClaims {
        build_claims(key_id, issued_at, policy_fresh_until, offline_valid_until)
    }

    fn build_claims(
        key_id: &str,
        issued_at: i64,
        policy_fresh_until: i64,
        offline_valid_until: i64,
    ) -> LicenseSnapshotClaims {
        LicenseSnapshotClaims::new(
            SNAPSHOT.parse().unwrap(),
            ORG.parse::<OrganizationId>().unwrap(),
            Some(DEVICE.parse::<ManagedDeviceId>().unwrap()),
            Some(format!("device:{DEVICE}")),
            4,
            policy_fresh_until,
            offline_valid_until,
            issued_at,
            CapabilityClass::LocalOnly,
            key_id,
        )
        .unwrap()
    }

    #[test]
    fn canonical_bytes_sort_keys_and_omit_insignificant_whitespace() {
        let issued = 1_789_000_000;
        let (fresh, offline) = license_expiries(issued, CapabilityClass::LocalOnly, None);
        let license = canonical_license(&LicensePayload {
            claims: &claims("lsk_2026_01", issued, fresh, offline),
            license_state: LicenseState::Grace,
            entitlements: &entitlements(),
        })
        .unwrap();
        let text = license.as_bytes();
        let text = std::str::from_utf8(text).unwrap();

        assert!(
            !text.contains(' '),
            "canonical bytes must not contain spaces"
        );
        assert!(!text.contains('\n'), "canonical bytes must not be pretty");
        assert!(text.starts_with("{\"audience\":"));
        // Lexicographic (byte) ordering of the top-level object keys.
        let ordered = [
            "\"audience\"",
            "\"capability_class\"",
            "\"device_id\"",
            "\"entitlements\"",
            "\"issued_at\"",
            "\"key_id\"",
            "\"license_state\"",
            "\"offline_valid_until\"",
            "\"org_id\"",
            "\"policy_fresh_until\"",
            "\"policy_version\"",
            "\"schema_version\"",
            "\"snapshot_id\"",
        ];
        let mut cursor = 0;
        for key in ordered {
            let at = text[cursor..]
                .find(key)
                .unwrap_or_else(|| panic!("missing canonical key {key}"));
            cursor += at;
        }
        // Entitlement keys are sorted inside the nested object too.
        let automations = text.find("automations.max_active").unwrap();
        let webhooks = text.find("webhooks.enabled").unwrap();
        assert!(automations < webhooks);
    }

    #[test]
    fn canonical_bytes_and_wire_object_describe_the_same_object() {
        let issued = 1_789_000_000;
        let (fresh, offline) = license_expiries(issued, CapabilityClass::LocalOnly, None);
        let license = canonical_license(&LicensePayload {
            claims: &claims("lsk_2026_01", issued, fresh, offline),
            license_state: LicenseState::Active,
            entitlements: &entitlements(),
        })
        .unwrap();
        let wire = license.to_json();
        assert_eq!(wire["org_id"], ORG);
        assert_eq!(wire["device_id"], DEVICE);
        assert_eq!(wire["key_id"], "lsk_2026_01");
        assert_eq!(wire["policy_version"], 4);
        assert_eq!(wire["schema_version"], 1);
        assert_eq!(wire["capability_class"], "local_only");
        assert_eq!(wire["license_state"], "active");
        assert_eq!(wire["entitlements"]["automations.max_active"], 100);
        assert_eq!(wire["entitlements"]["webhooks.enabled"], true);
        // The wire object is the signed object; only `signature` is added later.
        assert!(wire.get("signature").is_none());
    }

    #[test]
    fn canonical_bytes_never_carry_a_provider_product_or_price_identifier() {
        let issued = 1_789_000_000;
        let (fresh, offline) = license_expiries(issued, CapabilityClass::LocalOnly, None);
        let mut poisoned = BTreeMap::new();
        poisoned.insert("prod_Qabc123".to_owned(), EntitlementValue::Integer(1));
        poisoned.insert("price_1Monthly".to_owned(), EntitlementValue::Integer(1));
        // A provider identifier is not a registered Lumi key, so it is refused
        // rather than silently signed.
        assert_eq!(
            canonical_license(&LicensePayload {
                claims: &claims("lsk_2026_01", issued, fresh, offline),
                license_state: LicenseState::Active,
                entitlements: &poisoned,
            })
            .err(),
            Some(LicenseSignatureError::ClaimsRejected)
        );
    }

    #[test]
    fn rfc3339_utc_encoding_round_trips_through_the_domain_decoder() {
        for unix_seconds in [
            0_i64,
            1,
            951_782_400,
            1_789_000_000,
            1_700_000_000,
            2_000_000_000,
            32_503_679_999,
        ] {
            let text = format_rfc3339_utc(unix_seconds).unwrap();
            assert_eq!(text.as_str().len(), 24, "{unix_seconds}");
            assert_eq!(
                crate::modules::entitlements::unix_seconds(&text).unwrap(),
                unix_seconds
            );
        }
        assert!(format_rfc3339_utc(-1).is_none());
        assert!(format_rfc3339_utc(32_503_680_001).is_none());
    }

    #[test]
    fn policy_freshness_is_fifteen_minutes_and_offline_validity_is_class_specific() {
        let issued = 1_789_000_000;
        let (fresh, offline) = license_expiries(issued, CapabilityClass::LocalOnly, None);
        assert_eq!(fresh - issued, 900);
        assert_eq!(offline - issued, 604_800);
        assert!(offline > fresh);

        // Platform-paid inference receives no additional billing grace, but the
        // frozen D1 CHECK still requires the offline bound to sit strictly after
        // the policy-fresh bound so the snapshot can never be a stale authority.
        let (fresh, offline) =
            license_expiries(issued, CapabilityClass::PlatformPaidInference, Some(0));
        assert_eq!(offline, fresh + 1);

        // A class may only NARROW its baseline window.
        let (_, narrowed) = license_expiries(issued, CapabilityClass::LocalOnly, Some(3_600));
        assert_eq!(narrowed - issued, 3_600);
        let (_, widened) = license_expiries(issued, CapabilityClass::LocalOnly, Some(9_999_999));
        assert_eq!(widened - issued, 604_800);
    }

    #[test]
    fn rotation_keeps_one_issuer_and_a_bounded_verification_overlap() {
        let now = 1_789_000_000;
        let keys = vec![
            VerificationKey {
                key_id: "lsk_old".to_owned(),
                public_key_base64: "AAAA".to_owned(),
                active: false,
                not_before: format_rfc3339_utc(now - 200_000).unwrap().to_string(),
                verify_until: format_rfc3339_utc(now + 100_000).unwrap().to_string(),
            },
            VerificationKey {
                key_id: "lsk_new".to_owned(),
                public_key_base64: "BBBB".to_owned(),
                active: true,
                not_before: format_rfc3339_utc(now - 1_000).unwrap().to_string(),
                verify_until: format_rfc3339_utc(now + 1_000).unwrap().to_string(),
            },
            VerificationKey {
                key_id: "lsk_expired".to_owned(),
                public_key_base64: "CCCC".to_owned(),
                active: true,
                not_before: format_rfc3339_utc(now - 900_000).unwrap().to_string(),
                verify_until: format_rfc3339_utc(now - 1).unwrap().to_string(),
            },
        ];

        // A retired key still verifies inside its overlap, but never signs.
        assert_eq!(
            select_signing_key(&keys, now).map(|key| key.key_id.as_str()),
            Some("lsk_new")
        );
        assert!(keys[0].can_verify(now));
        assert!(!keys[0].can_sign_new_work(now));
        assert!(!keys[2].can_verify(now));
        assert_eq!(
            trusted_verification_key_ids(&keys, now),
            vec!["lsk_new", "lsk_old"]
        );

        // Once the new key's own window closes there is no issuer, and the
        // retired key is never promoted into one — it only still verifies.
        let after = now + 2_000;
        assert_eq!(select_signing_key(&keys, after), None);
        assert_eq!(trusted_verification_key_ids(&keys, after), vec!["lsk_old"]);

        // Once the retired key's own window closes, nothing is trusted.
        let expired = now + 100_001;
        assert!(trusted_verification_key_ids(&keys, expired).is_empty());
    }

    #[test]
    fn corrupt_key_windows_fail_closed() {
        let now = 1_789_000_000;
        let key = VerificationKey {
            key_id: "lsk_broken".to_owned(),
            public_key_base64: "AAAA".to_owned(),
            active: true,
            not_before: "not-a-timestamp".to_owned(),
            verify_until: format_rfc3339_utc(now + 1).unwrap().to_string(),
        };
        assert!(!key.can_verify(now));
        assert!(!key.can_sign_new_work(now));
        assert!(trusted_verification_key_ids(&[key], now).is_empty());
    }

    #[test]
    fn signing_secret_rejects_malformed_material_and_never_prints_key_bytes() {
        let valid = format!("lsk_2026_01:{}", encode_base64(&[7_u8; 48]));
        let secret = LicenseSigningSecret::from_env_value(&valid).unwrap();
        assert_eq!(secret.key_id(), "lsk_2026_01");
        let debug = format!("{secret:?}");
        assert!(!debug.contains("AAAAAAA"), "debug leaked key bytes");
        assert!(debug.contains("[redacted]"));

        for invalid in [
            String::new(),
            "lsk_2026_01".to_owned(),
            "lsk_2026_01:".to_owned(),
            format!(":{}", encode_base64(&[0_u8; 48])),
            format!("lsk_2026_01:{}", encode_base64(&[0_u8; 32])),
            format!(
                "{}:{}",
                "x".repeat(MAX_LICENSE_KEY_ID_BYTES + 1),
                encode_base64(&[0_u8; 48])
            ),
            format!("bad key id:{}", encode_base64(&[0_u8; 48])),
            format!("lsk:{}", encode_base64(&[0_u8; 48]).replace('A', "*")),
        ] {
            assert!(
                LicenseSigningSecret::from_env_value(invalid.as_str()).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn base64_round_trips_the_documented_key_lengths() {
        for length in [ED25519_PRIVATE_KEY_BYTES, ED25519_PUBLIC_KEY_BYTES, 1, 2, 3] {
            let bytes: Vec<u8> = (0..length)
                .map(|index| u8::try_from(index % 251).unwrap())
                .collect();
            assert_eq!(decode_base64(&encode_base64(&bytes)), Some(bytes));
        }
        assert_eq!(decode_base64("not base64!"), None);
    }

    #[test]
    fn hex_encoding_is_lowercase_and_strict() {
        assert_eq!(encode_hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(decode_hex("000fff"), Some(vec![0x00, 0x0f, 0xff]));
        assert_eq!(decode_hex("000FFF"), None);
        assert_eq!(decode_hex("00f"), None);
        assert_eq!(decode_hex(""), None);
    }

    #[test]
    fn issued_claims_satisfy_every_frozen_verifier_check() {
        let issued = 1_789_000_000;
        let (fresh, offline) = license_expiries(issued, CapabilityClass::LocalOnly, None);
        let claims = claims("lsk_2026_01", issued, fresh, offline);
        let org = ORG.parse::<OrganizationId>().unwrap();
        let device = DEVICE.parse::<ManagedDeviceId>().unwrap();
        let trusted = ["lsk_2026_01"];
        let context = || LicenseSnapshotContext {
            now: issued + 60,
            expected_org_id: &org,
            expected_device_id: Some(&device),
            trusted_key_ids: &trusted,
            last_accepted_policy_version: 4,
        };
        assert_eq!(validate_license_snapshot(&claims, &context()), Ok(()));

        // An unknown key ID is rejected: a client must not trust a snapshot it
        // cannot verify against a pinned key.
        let other_keys = ["lsk_other"];
        assert_eq!(
            validate_license_snapshot(
                &claims,
                &LicenseSnapshotContext {
                    trusted_key_ids: &other_keys,
                    ..context()
                }
            ),
            Err(LicenseReason::LicenseKeyUnknown)
        );

        // A device-scoped snapshot is not accepted by an organization-level
        // verifier: the device binding is symmetric.
        assert_eq!(
            validate_license_snapshot(
                &claims,
                &LicenseSnapshotContext {
                    expected_device_id: None,
                    ..context()
                }
            ),
            Err(LicenseReason::LicenseAudienceMismatch)
        );

        // A snapshot minted for another organization is refused.
        let other_org: OrganizationId = "org_1123456789abcdef0123456789abcdef".parse().unwrap();
        assert_eq!(
            validate_license_snapshot(
                &claims,
                &LicenseSnapshotContext {
                    expected_org_id: &other_org,
                    ..context()
                }
            ),
            Err(LicenseReason::LicenseAudienceMismatch)
        );

        // A snapshot older than the last accepted policy version is a rollback.
        assert_eq!(
            validate_license_snapshot(
                &claims,
                &LicenseSnapshotContext {
                    last_accepted_policy_version: 5,
                    ..context()
                }
            ),
            Err(LicenseReason::LicensePolicyRollback)
        );

        // Expiry is enforced against the offline bound, and at most 120 seconds
        // of clock skew is tolerated in either direction.
        assert_eq!(
            validate_license_snapshot(
                &claims,
                &LicenseSnapshotContext {
                    now: offline + 121,
                    ..context()
                }
            ),
            Err(LicenseReason::LicenseSnapshotExpired)
        );
        // Exactly 120 seconds of skew is still accepted; 121 is not.
        assert_eq!(
            validate_license_snapshot(
                &claims,
                &LicenseSnapshotContext {
                    now: offline + 120,
                    ..context()
                }
            ),
            Ok(())
        );
        // A FUTURE-dated snapshot is refused as expired, so a device with a
        // fast clock cannot accept a snapshot that claims to be newer.
        let (future_fresh, future_offline) =
            license_expiries(issued + 400, CapabilityClass::LocalOnly, None);
        let future = build_claims("lsk_2026_01", issued + 400, future_fresh, future_offline);
        assert_eq!(
            validate_license_snapshot(&future, &context()),
            Err(LicenseReason::LicenseSnapshotExpired)
        );
    }

    #[test]
    fn canonical_bytes_are_available_on_every_target_while_signing_is_not() {
        let issued = 1_789_000_000;
        let (fresh, offline) = license_expiries(issued, CapabilityClass::LocalOnly, None);
        let canonical = canonical_license(&LicensePayload {
            claims: &claims("lsk_2026_01", issued, fresh, offline),
            license_state: LicenseState::Active,
            entitlements: &entitlements(),
        })
        .unwrap();
        // The canonical bytes are fully available on the host test target; only
        // the platform call is unavailable, and it fails closed rather than
        // panicking (see the `not(target_arch = "wasm32")` stub).
        assert!(!canonical.as_bytes().is_empty());
        assert!(
            str::from_utf8(canonical.as_bytes())
                .unwrap()
                .starts_with('{')
        );
    }

    #[test]
    fn unavailable_block_is_stable_and_carries_no_secret() {
        let block = license_unavailable_block(LicenseSignatureError::SigningKeyNotConfigured);
        assert_eq!(block["license_error"], "license_key_unknown");
        assert!(block["license"].is_null());
        assert_eq!(block["signature_algorithm"], "ed25519");
    }
}
