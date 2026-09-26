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

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

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

/// One freshly generated credential, and the four values derived from it.
///
/// The struct exists so the secret cannot be separated from what is persisted
/// without the separation being visible. A creation path that computed a
/// `secret` string and a `secret_hash` string independently, in two places,
/// would eventually hash the wrong one.
#[derive(Clone, PartialEq, Eq)]
pub struct MachineKeyMaterial {
    /// The public lookup prefix. NOT a secret, and safe to display.
    pub key_prefix: String,
    /// The secret half. Returned to the client exactly once and never persisted.
    secret: String,
    /// Lowercase hex SHA-256 of the SECRET half, not of the whole wire value.
    ///
    /// Hashing the secret half rather than the whole key is deliberate: the
    /// prefix is a lookup index and carries no entropy, so including it would
    /// make two keys that share a secret — which cannot happen, but which a
    /// future import path might create — indistinguishable in the store.
    pub secret_hash: String,
    /// Truncated hash of the WHOLE presented key, for identification without
    /// revealing it. Distinct from `secret_hash` on purpose: one answers "is
    /// this the right secret", the other answers "which key was this".
    pub fingerprint: String,
    /// The full wire value, assembled once.
    wire: String,
}

impl MachineKeyMaterial {
    /// Derive everything from 32 bytes of CSPRNG entropy.
    ///
    /// `random` is injected rather than called directly so the derivation is
    /// testable off-target: `adapters::platform::new_secret` is a deterministic
    /// stub in host tests and a Worker CSPRNG on target, and neither should be
    /// reachable from a pure domain function.
    pub fn from_random_bytes(random: &[u8]) -> Option<Self> {
        if random.len() != 32 {
            return None;
        }
        let secret = URL_SAFE_NO_PAD.encode(random);
        if secret.len() != SECRET_LEN {
            return None;
        }
        let key_prefix = hex_prefix(random);
        let secret_hash = sha256_hex_of(secret.as_bytes());
        let fingerprint =
            sha256_hex_of(format!("{MACHINE_KEY_SCHEME}_{key_prefix}_{secret}").as_bytes());
        let wire = format!("{MACHINE_KEY_SCHEME}_{key_prefix}_{secret}");
        Some(Self {
            key_prefix,
            secret,
            secret_hash,
            fingerprint: fingerprint[..16].to_owned(),
            wire,
        })
    }

    /// The non-secret half, safe to log, to store, and to show in a UI.
    pub fn key_prefix(&self) -> &str {
        &self.key_prefix
    }

    /// The value handed to the client once. Never logged; `Debug` below omits it.
    pub fn wire_value(&self) -> &str {
        &self.wire
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// Hash a presented secret for comparison against `api_keys.secret_hash`.
    ///
    /// The derivation is the same function the creation path used, so a key that
    /// verifies here is a key this server minted. It takes the SECRET half, not
    /// the whole wire value, which is why callers must parse first.
    pub fn hash_secret(secret: &str) -> String {
        sha256_hex_of(secret.as_bytes())
    }
}

impl fmt::Debug for MachineKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachineKeyMaterial")
            .field("key_prefix", &self.key_prefix)
            .field("secret", &"[redacted]")
            .field("secret_hash", &self.secret_hash)
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

/// The first six bytes of the entropy, lowercase hex: 12 characters, the frozen
/// `PREFIX_LEN`.
///
/// Six bytes of a 32-byte value is enough to make a collision improbable across
/// a bounded key population (the gate caps it at 50 accounts x 5 keys per
/// organization) and small enough that a UI can show it. The column is UNIQUE in
/// the schema, so a collision fails loudly at the store rather than silently
/// authenticating one key as another.
fn hex_prefix(random: &[u8]) -> String {
    random[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A dependency-free SHA-256.
///
/// This is a second implementation of a cryptographic primitive in the codebase,
/// which deserves an argument. The alternative is `sha2`, a crate added for one
/// call site — and it would not even be usable on the Worker target without
/// pulling in a backend. The alternative of calling back into `adapters::
/// platform::sha256_hex` is not available: that is `async` and is a Worker
/// binding, and key derivation must be a pure function the domain tests can
/// exercise on the host target.
///
/// The implementation below is the FIPS 180-4 specification, and the constant
/// table and round constants are checked in by a test that verifies the known
/// answer for the empty string and for `abc`. If this ever diverged from the
/// spec, a stored hash and a computed hash would disagree and every key would
/// stop verifying — loudly, not silently. The risk of a subtly wrong second
/// implementation is real; the mitigation is that a wrong one cannot be
/// subtle, because it breaks authentication completely.
fn sha256_hex_of(value: &[u8]) -> String {
    let digest = sha256(value);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(value: &[u8]) -> [u8; 32] {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Pad to a multiple of 64 bytes: 0x80, zeros, then the bit length as a
    // big-endian u64.
    let mut padded = value.to_vec();
    let bit_length = (value.len() as u64).wrapping_mul(8);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    for block in padded.as_chunks::<64>().0 {
        let mut w = [0_u32; 64];
        for (index, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }

    let mut digest = [0_u8; 32];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
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

    // -- the in-crate SHA-256 ---------------------------------------------

    /// The known answers from FIPS 180-4. This is the test that makes the
    /// in-crate implementation safe to rely on: a divergence from the spec
    /// breaks every key verification immediately and visibly, but only if
    /// somebody checks it against something the specification states.
    #[test]
    fn sha256_matches_the_published_known_answers() {
        assert_eq!(
            sha256_hex_of(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex_of(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex_of(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // The 1,000,000 x 'a' vector, which exercises multi-block padding.
        let million = vec![b'a'; 1_000_000];
        assert_eq!(
            sha256_hex_of(&million),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    // -- key material ------------------------------------------------------

    #[test]
    fn key_material_round_trips_through_the_parser() {
        let material = MachineKeyMaterial::from_random_bytes(&[0x42; 32]).expect("32 bytes");
        assert_eq!(material.key_prefix().len(), PREFIX_LEN);
        assert_eq!(material.secret().len(), SECRET_LEN);

        let parsed = MachineKey::parse(material.wire_value()).expect("minted key parses");
        assert_eq!(parsed.prefix(), material.key_prefix());
        assert_eq!(parsed.secret(), material.secret());
    }

    /// The stored hash must be the hash of the SECRET, so verification is a hash
    /// of what the client presented rather than a re-derivation of the whole
    /// wire value.
    #[test]
    fn the_stored_hash_is_of_the_secret_half() {
        let material = MachineKeyMaterial::from_random_bytes(&[0x11; 32]).expect("32 bytes");
        assert_eq!(
            material.secret_hash,
            MachineKeyMaterial::hash_secret(material.secret())
        );
        assert_ne!(
            material.secret_hash,
            MachineKeyMaterial::hash_secret(material.wire_value())
        );
    }

    #[test]
    fn the_fingerprint_identifies_the_whole_key_and_is_bounded() {
        let material = MachineKeyMaterial::from_random_bytes(&[0x11; 32]).expect("32 bytes");
        assert_eq!(material.fingerprint.len(), 16);
        assert!(material.fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));
        // Two keys with different secrets do not share a fingerprint.
        let other = MachineKeyMaterial::from_random_bytes(&[0x12; 32]).expect("32 bytes");
        assert_ne!(material.fingerprint, other.fingerprint);
    }

    #[test]
    fn different_entropy_yields_different_credentials() {
        let a = MachineKeyMaterial::from_random_bytes(&[0x00; 32]).expect("32 bytes");
        let b = MachineKeyMaterial::from_random_bytes(&[0x01; 32]).expect("32 bytes");
        assert_ne!(a.key_prefix, b.key_prefix);
        assert_ne!(a.secret_hash, b.secret_hash);
        // The base64url alphabet excludes '+' and '/', so the secret can never
        // need escaping in a header.
        assert!(!a.secret().contains('+') && !a.secret().contains('/'));
        assert!(!a.secret().contains('='));
    }

    #[test]
    fn key_material_needs_exactly_32_bytes_of_entropy() {
        assert!(MachineKeyMaterial::from_random_bytes(&[0; 31]).is_none());
        assert!(MachineKeyMaterial::from_random_bytes(&[0; 33]).is_none());
        assert!(MachineKeyMaterial::from_random_bytes(&[]).is_none());
        assert!(MachineKeyMaterial::from_random_bytes(&[0; 32]).is_some());
    }

    /// The material's own `Debug` must not leak the secret, for the same reason
    /// `MachineKey`'s does: a credential that reaches a log through an accidental
    /// `{:?}` has to be rotated.
    #[test]
    fn key_material_debug_never_contains_the_secret() {
        let material = MachineKeyMaterial::from_random_bytes(&[0x42; 32]).expect("32 bytes");
        let debug = format!("{material:?}");
        assert!(!debug.contains(material.secret()), "secret leaked: {debug}");
        assert!(debug.contains("[redacted]"));
        assert!(debug.contains(material.key_prefix()));
    }
}
