//! Secret encryption boundary for provider credentials.
//!
//! The Worker implementation uses AES-GCM through Web Crypto. Plaintext is
//! accepted only at this adapter boundary and is never returned to a route,
//! repository, log, or frontend response.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::modules::credentials::{mask_fingerprint, metadata_fingerprint};

pub const CREDENTIAL_KEY_VERSION: &str = "v1";

/// A deterministic key used only by the explicit local development fixture.
/// Production must provide a 32-byte secret through the Worker environment and
/// fails closed when it is absent.
pub const DEVELOPMENT_CREDENTIAL_KEY_HEX: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSecret {
    pub ciphertext: String,
    pub nonce: String,
}

impl fmt::Debug for EncryptedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedSecret")
            .field("ciphertext", &"[redacted]")
            .field("nonce", &"[redacted]")
            .finish()
    }
}

pub fn validate_key_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub async fn fingerprint_secret(secret: &str) -> worker::Result<String> {
    let digest = crate::adapters::sha256_hex(secret).await?;
    metadata_fingerprint(&digest)
        .ok_or_else(|| worker::Error::RustError("credential fingerprint unavailable".to_owned()))
}

pub fn masked_fingerprint(fingerprint: &str) -> String {
    mask_fingerprint(fingerprint)
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    use wasm_bindgen::prelude::wasm_bindgen;
    use wasm_bindgen_futures::JsFuture;

    #[wasm_bindgen(inline_js = r#"
function lumiHexBytes(value) {
  if (typeof value !== "string" || value.length !== 64) throw new Error("invalid key");
  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function lumiBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let index = 0; index < bytes.length; index += chunk) {
    binary += String.fromCharCode(...bytes.subarray(index, Math.min(index + chunk, bytes.length)));
  }
  return btoa(binary);
}

function lumiFromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

export async function lumiEncryptSecret(keyHex, plaintext) {
  const key = await crypto.subtle.importKey(
    "raw", lumiHexBytes(keyHex), { name: "AES-GCM" }, false, ["encrypt"]
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce }, key, new TextEncoder().encode(plaintext)
  ));
  return JSON.stringify({ ciphertext: lumiBase64(ciphertext), nonce: lumiBase64(nonce) });
}

export async function lumiDecryptSecret(keyHex, ciphertext, nonce) {
  const key = await crypto.subtle.importKey(
    "raw", lumiHexBytes(keyHex), { name: "AES-GCM" }, false, ["decrypt"]
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: lumiFromBase64(nonce) }, key, lumiFromBase64(ciphertext)
  );
  return new TextDecoder().decode(plaintext);
}
"#)]
    extern "C" {
        #[wasm_bindgen(js_name = lumiEncryptSecret)]
        fn encrypt_secret_js(key_hex: &str, plaintext: &str) -> worker::js_sys::Promise;
        #[wasm_bindgen(js_name = lumiDecryptSecret)]
        fn decrypt_secret_js(
            key_hex: &str,
            ciphertext: &str,
            nonce: &str,
        ) -> worker::js_sys::Promise;
    }

    pub async fn encrypt_secret(key_hex: &str, plaintext: &str) -> worker::Result<EncryptedSecret> {
        if !validate_key_hex(key_hex) {
            return Err(worker::Error::RustError(
                "credential encryption unavailable".to_owned(),
            ));
        }
        let value = JsFuture::from(encrypt_secret_js(key_hex, plaintext))
            .await
            .map_err(|_| worker::Error::RustError("credential encryption failed".to_owned()))?
            .as_string()
            .ok_or_else(|| worker::Error::RustError("credential encryption failed".to_owned()))?;
        serde_json::from_str(&value)
            .map_err(|_| worker::Error::RustError("credential encryption failed".to_owned()))
    }

    pub async fn decrypt_secret(
        key_hex: &str,
        ciphertext: &str,
        nonce: &str,
    ) -> worker::Result<String> {
        if !validate_key_hex(key_hex) {
            return Err(worker::Error::RustError(
                "credential decryption unavailable".to_owned(),
            ));
        }
        JsFuture::from(decrypt_secret_js(key_hex, ciphertext, nonce))
            .await
            .map_err(|_| worker::Error::RustError("credential decryption failed".to_owned()))?
            .as_string()
            .ok_or_else(|| worker::Error::RustError("credential decryption failed".to_owned()))
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm::{decrypt_secret, encrypt_secret};

#[cfg(not(target_arch = "wasm32"))]
pub async fn encrypt_secret(_key_hex: &str, _plaintext: &str) -> worker::Result<EncryptedSecret> {
    Err(worker::Error::RustError(
        "Worker Web Crypto is unavailable in host tests".to_owned(),
    ))
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn decrypt_secret(
    _key_hex: &str,
    _ciphertext: &str,
    _nonce: &str,
) -> worker::Result<String> {
    Err(worker::Error::RustError(
        "Worker Web Crypto is unavailable in host tests".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_validation_accepts_only_a_32_byte_hex_key() {
        assert!(validate_key_hex(DEVELOPMENT_CREDENTIAL_KEY_HEX));
        assert!(!validate_key_hex("short"));
        assert!(!validate_key_hex(&"A".repeat(64)));
    }

    #[test]
    fn encrypted_envelope_debug_is_not_derived_from_plaintext() {
        let envelope = EncryptedSecret {
            ciphertext: "super-secret-ciphertext".to_owned(),
            nonce: "super-secret-nonce".to_owned(),
        };
        let debug = format!("{envelope:?}");
        assert!(!debug.contains("super-secret-ciphertext"));
        assert!(!debug.contains("super-secret-nonce"));
    }
}
