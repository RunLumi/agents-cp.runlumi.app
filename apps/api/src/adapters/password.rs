//! Password KDF boundary.
//!
//! New credentials use Argon2id with the current OWASP Worker baseline:
//! 19 MiB, two iterations, and one lane. The encoded PHC string carries the
//! parameters for verification; plaintext is accepted only at this boundary
//! and is never returned, persisted, or logged by the adapter.

use argon2::{
    Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version,
    password_hash::phc::PasswordHash,
};

pub const ARGON2ID: &str = "argon2id";
pub const ARGON2_VERSION: u32 = 19;
pub const ARGON2_MEMORY_KIB: u32 = 19_456;
pub const ARGON2_TIME_COST: u32 = 2;
pub const ARGON2_PARALLELISM: u32 = 1;

/// A fixed, non-secret Argon2id hash used to make unknown-account password
/// verification perform comparable work. It is never associated with a user.
pub const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$fuWJhNZSHOMIvFzWuQeMRQ$dgWxOyUQ4IKh84IN0jY2sSD3waidCsBKhIkB+6qSkLs";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordCryptoError {
    InvalidConfiguration,
    HashingFailed,
}

pub fn hash_password(password: &str) -> Result<String, PasswordCryptoError> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        None,
    )
    .map_err(|_| PasswordCryptoError::InvalidConfiguration)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|_| PasswordCryptoError::HashingFailed)
}

pub fn verify_password(encoded_hash: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded_hash) else {
        return false;
    };
    if !is_supported_hash(&parsed) {
        return false;
    }
    let Ok(params) = Params::try_from(&parsed) else {
        return false;
    };
    if params.m_cost() < ARGON2_MEMORY_KIB
        || params.t_cost() < ARGON2_TIME_COST
        || params.p_cost() != ARGON2_PARALLELISM
    {
        return false;
    }
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub fn needs_rehash(encoded_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded_hash) else {
        return true;
    };
    let Ok(params) = Params::try_from(&parsed) else {
        return true;
    };
    if !is_supported_hash(&parsed) {
        return true;
    }
    params.m_cost() < ARGON2_MEMORY_KIB
        || params.t_cost() < ARGON2_TIME_COST
        || params.p_cost() != ARGON2_PARALLELISM
}

pub fn algorithm_metadata(encoded_hash: &str) -> (String, i64, i64, i64) {
    let Ok(parsed) = PasswordHash::new(encoded_hash) else {
        return (
            ARGON2ID.to_owned(),
            i64::from(ARGON2_MEMORY_KIB),
            i64::from(ARGON2_TIME_COST),
            i64::from(ARGON2_PARALLELISM),
        );
    };
    let params = Params::try_from(&parsed).ok();
    (
        parsed.algorithm.to_string(),
        params.as_ref().map_or(0, Params::m_cost).into(),
        params.as_ref().map_or(0, Params::t_cost).into(),
        params.as_ref().map_or(0, Params::p_cost).into(),
    )
}

fn is_supported_hash(hash: &PasswordHash) -> bool {
    hash.algorithm.as_str() == ARGON2ID
        && hash
            .version
            .as_ref()
            .is_some_and(|version| version.to_string() == ARGON2_VERSION.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_argon2id_with_owasp_baseline_and_verify() {
        let encoded = hash_password("correct horse battery staple").unwrap();
        assert!(encoded.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify_password(&encoded, "correct horse battery staple"));
        assert!(!verify_password(&encoded, "wrong password"));
        assert!(!needs_rehash(&encoded));
    }

    #[test]
    fn fast_or_wrong_algorithm_hashes_are_rejected() {
        assert!(!verify_password(
            "$argon2id$v=19$m=1024,t=1,p=1$c29tZS1maXhlZC1zYWx0$Yn5J8w8H8Wf0VY2x5l3Jx4zM7Qm1s6Yw8u4n0Qd2Tg",
            "password"
        ));
        assert!(!verify_password(
            "$2b$12$abcdefghijklmnopqrstuv",
            "password"
        ));
    }

    #[test]
    fn dummy_hash_has_the_same_verification_cost() {
        assert!(!verify_password(DUMMY_PASSWORD_HASH, "not-the-password"));
    }
}
