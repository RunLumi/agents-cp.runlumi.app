//! Worker-host crypto and clock operations used at trusted request boundaries.

use crate::core::{EventId, ResourceId, Timestamp};

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(inline_js = r#"
export function lumiEventUuid() {
  return globalThis.crypto.randomUUID();
}

export function lumiSecret() {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function lumiSha256Hex(value) {
  const input = new TextEncoder().encode(value);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", input);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function lumiAddIdempotencyTtl(value) {
  return new Date(Date.parse(value) + 24 * 60 * 60 * 1000).toISOString();
}

export function lumiAddSeconds(value, seconds) {
  return new Date(Date.parse(value) + seconds * 1000).toISOString();
}
"#)]
extern "C" {
    #[wasm_bindgen::prelude::wasm_bindgen(js_name = lumiEventUuid)]
    fn event_uuid() -> String;

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = lumiSecret)]
    fn secret_js() -> String;

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = lumiSha256Hex)]
    fn sha256_hex_js(value: &str) -> worker::js_sys::Promise;

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = lumiAddIdempotencyTtl)]
    fn add_idempotency_ttl_js(value: &str) -> String;

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = lumiAddSeconds)]
    fn add_seconds_js(value: &str, seconds: u32) -> String;
}

/// Generate an opaque event ID with Web Crypto's UUID v4 implementation.
#[cfg(target_arch = "wasm32")]
pub fn new_event_id() -> EventId {
    let compact_uuid = event_uuid().replace('-', "").to_ascii_lowercase();
    EventId::new(format!("evt_{compact_uuid}"))
        .expect("Web Crypto randomUUID returns a valid UUID v4")
}

/// Generate a typed opaque resource ID using the Worker CSPRNG.
#[cfg(target_arch = "wasm32")]
pub fn new_resource_id(prefix: &str) -> ResourceId {
    let compact_uuid = event_uuid().replace('-', "").to_ascii_lowercase();
    ResourceId::new(format!("{prefix}_{compact_uuid}"))
        .expect("validated prefix and Worker UUID form a resource ID")
}

/// Generate a high-entropy secret for a session, challenge, or device code.
/// The returned value is never persisted directly; callers hash it first.
#[cfg(target_arch = "wasm32")]
pub fn new_secret() -> String {
    secret_js()
}

/// Add a bounded number of seconds using the Worker clock.
#[cfg(target_arch = "wasm32")]
pub fn add_seconds(now: &Timestamp, seconds: u32) -> worker::Result<Timestamp> {
    Timestamp::new(add_seconds_js(now.as_str(), seconds))
        .map_err(|_| worker::Error::RustError("Worker clock returned an invalid timestamp".into()))
}

/// Hash client idempotency keys and canonical request fingerprints before
/// persisting them. Raw keys and request bytes never reach D1 or logs.
#[cfg(target_arch = "wasm32")]
pub async fn sha256_hex(value: &str) -> worker::Result<String> {
    use wasm_bindgen_futures::JsFuture;

    let value = JsFuture::from(sha256_hex_js(value))
        .await
        .map_err(|_| worker::Error::RustError("Worker SHA-256 operation failed".to_owned()))?;
    value
        .as_string()
        .ok_or_else(|| worker::Error::RustError("Worker SHA-256 result was invalid".to_owned()))
}

/// Expiry uses exactly 24 hours from the trusted Worker clock and preserves
/// the contract's fixed millisecond UTC representation.
#[cfg(target_arch = "wasm32")]
pub fn add_idempotency_ttl(now: &Timestamp) -> worker::Result<Timestamp> {
    Timestamp::new(add_idempotency_ttl_js(now.as_str()))
        .map_err(|_| worker::Error::RustError("Worker clock returned an invalid timestamp".into()))
}

// Host-side tests must never generate deployable IDs or digests. These
// deterministic stubs exist only so the crate can be unit-tested natively.
#[cfg(not(target_arch = "wasm32"))]
pub fn new_event_id() -> EventId {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);
    let value = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    EventId::new(format!("evt_{value:032x}")).expect("formatted test event ID is valid")
}

#[cfg(not(target_arch = "wasm32"))]
pub fn new_resource_id(prefix: &str) -> ResourceId {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);
    let value = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    ResourceId::new(format!("{prefix}_{value:032x}")).expect("formatted test resource ID is valid")
}

#[cfg(not(target_arch = "wasm32"))]
pub fn new_secret() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_SECRET: AtomicU64 = AtomicU64::new(1);
    let value = NEXT_TEST_SECRET.fetch_add(1, Ordering::Relaxed);
    format!("{value:064x}")
}

#[cfg(not(target_arch = "wasm32"))]
pub fn add_seconds(_now: &Timestamp, _seconds: u32) -> worker::Result<Timestamp> {
    Err(worker::Error::RustError(
        "Worker clock is unavailable in host tests".to_owned(),
    ))
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn sha256_hex(_value: &str) -> worker::Result<String> {
    Err(worker::Error::RustError(
        "Worker Web Crypto is unavailable in host tests".to_owned(),
    ))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn add_idempotency_ttl(_now: &Timestamp) -> worker::Result<Timestamp> {
    Err(worker::Error::RustError(
        "Worker clock is unavailable in host tests".to_owned(),
    ))
}

#[cfg(target_arch = "wasm32")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_event_ids_use_the_frozen_opaque_uuid_shape() {
        let id = new_event_id();
        assert!(id.as_str().starts_with("evt_"));
        assert_eq!(id.as_str().len(), 36);
    }
}
