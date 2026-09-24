//! Tiny runtime primitives supplied by the Workers JavaScript host.

use crate::core::{CorrelationId, RequestId, Timestamp};

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(inline_js = r#"
export function lumiRequestUuid() {
  return globalThis.crypto.randomUUID();
}

export function lumiNowIso() {
  return new Date().toISOString();
}

export function lumiMonotonicNow() {
  return globalThis.performance.now();
}
"#)]
extern "C" {
    #[wasm_bindgen::prelude::wasm_bindgen(js_name = lumiRequestUuid)]
    fn request_uuid() -> String;

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = lumiNowIso)]
    fn now_iso() -> String;

    #[wasm_bindgen::prelude::wasm_bindgen(js_name = lumiMonotonicNow)]
    fn monotonic_now() -> f64;
}

#[cfg(target_arch = "wasm32")]
pub fn new_request_id() -> RequestId {
    // Workers provide Web Crypto. Strip the UUID separators and add the frozen
    // resource prefix; the resulting value is validated by the shared type.
    request_id_from_uuid(&request_uuid())
}

#[cfg(any(target_arch = "wasm32", test))]
fn request_id_from_uuid(uuid: &str) -> RequestId {
    let value = uuid.replace('-', "").to_ascii_lowercase();
    RequestId::new(format!("req_{value}")).expect("Web Crypto returns a UUID")
}

#[cfg(not(target_arch = "wasm32"))]
pub fn new_request_id() -> RequestId {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);
    let value = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    RequestId::new(format!("req_{value:032x}")).expect("formatted test request ID is valid")
}

#[cfg(target_arch = "wasm32")]
pub fn received_at() -> Timestamp {
    Timestamp::new(now_iso()).expect("JavaScript Date.toISOString returns UTC RFC 3339")
}

#[cfg(not(target_arch = "wasm32"))]
pub fn received_at() -> Timestamp {
    // Host-side tests need deterministic timestamps; deployed Workers use the
    // platform clock above.
    Timestamp::new("2026-09-24T00:00:00.000Z").expect("fixed test timestamp is valid")
}

#[cfg(target_arch = "wasm32")]
pub fn monotonic_now_ms() -> f64 {
    monotonic_now()
}

#[cfg(not(target_arch = "wasm32"))]
pub fn monotonic_now_ms() -> f64 {
    use std::sync::OnceLock;
    use std::time::Instant;

    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs_f64() * 1_000.0
}

pub fn correlation_id(value: Option<&str>, request_id: &RequestId) -> CorrelationId {
    value
        .and_then(|value| CorrelationId::new(value.to_owned()).ok())
        .unwrap_or_else(|| {
            CorrelationId::new(request_id.as_str().to_owned())
                .expect("request ID is a valid correlation ID")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_host_ids_are_unique_and_match_the_contract() {
        let first = new_request_id();
        let second = new_request_id();

        assert_ne!(first, second);
        assert!(first.as_str().starts_with("req_"));
        assert_eq!(first.as_str().len(), 36);
    }

    #[test]
    fn uuid_v4_is_compacted_into_the_frozen_request_id_shape() {
        let request_id = request_id_from_uuid("550E8400-E29B-41D4-A716-446655440000");

        assert_eq!(request_id.as_str(), "req_550e8400e29b41d4a716446655440000");
    }

    #[test]
    fn invalid_or_oversized_correlation_values_default_to_request_id() {
        let request_id = new_request_id();

        assert_eq!(
            correlation_id(Some("trace-alpha/1"), &request_id).as_str(),
            "trace-alpha/1"
        );
        assert_eq!(
            correlation_id(Some(&"x".repeat(129)), &request_id).as_str(),
            request_id.as_str()
        );
        assert_eq!(
            correlation_id(Some("bad\nvalue"), &request_id).as_str(),
            request_id.as_str()
        );
    }
}
