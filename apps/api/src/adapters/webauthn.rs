//! Maintained WebAuthn verifier boundary.
//!
//! The application depends on `passkey-auth` for CBOR/COSE parsing and
//! signature verification. This adapter owns trusted RP configuration, wire
//! conversion, and stable failure classification; library types do not leak
//! into the domain or HTTP modules.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use passkey_auth::{
    Attachment, AuthenticationResponse as VerifierAuthenticationResponse,
    AuthenticationState as VerifierAuthenticationState, CosePublicKey, CredentialId,
    Error as VerifierError, PasskeyCredential as VerifierCredential,
    RegistrationResponse as VerifierRegistrationResponse,
    RegistrationState as VerifierRegistrationState, Webauthn,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub origins: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebAuthnConfigError {
    MissingRpId,
    InvalidRpId,
    InvalidRpName,
    MissingOrigin,
    InvalidOrigin,
    TooManyOrigins,
}

impl WebAuthnConfig {
    pub fn new(
        rp_id: Option<String>,
        rp_name: Option<String>,
        origins: Option<String>,
    ) -> Result<Self, WebAuthnConfigError> {
        let rp_id = rp_id
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .ok_or(WebAuthnConfigError::MissingRpId)?;
        if rp_id.contains("://")
            || rp_id.contains('/')
            || rp_id.contains(':')
            || rp_id.chars().any(char::is_whitespace)
        {
            return Err(WebAuthnConfigError::InvalidRpId);
        }
        let rp_name = rp_name
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .ok_or(WebAuthnConfigError::InvalidRpName)?;
        let origins = origins
            .ok_or(WebAuthnConfigError::MissingOrigin)?
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if origins.is_empty() {
            return Err(WebAuthnConfigError::MissingOrigin);
        }
        if origins.len() > 4 {
            return Err(WebAuthnConfigError::TooManyOrigins);
        }
        for origin in &origins {
            validate_origin(origin, &rp_id)?;
        }
        Ok(Self {
            rp_id,
            rp_name,
            origins,
        })
    }

    fn verifier(&self, origin: &str) -> Webauthn {
        Webauthn::new(&self.rp_id, &self.rp_name, origin)
            .authenticator_attachment(Attachment::Any)
            .require_user_verification(true)
            .strict_base64(true)
    }
}

fn validate_origin(origin: &str, rp_id: &str) -> Result<(), WebAuthnConfigError> {
    let parsed = Url::parse(origin).map_err(|_| WebAuthnConfigError::InvalidOrigin)?;
    if !matches!(parsed.scheme(), "https" | "http")
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(WebAuthnConfigError::InvalidOrigin);
    }
    let Some(host) = parsed.host_str() else {
        return Err(WebAuthnConfigError::InvalidOrigin);
    };
    let valid_host = host == rp_id
        || (rp_id != "localhost"
            && host
                .strip_suffix(rp_id)
                .is_some_and(|prefix| prefix.ends_with('.')));
    if !valid_host {
        return Err(WebAuthnConfigError::InvalidOrigin);
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistrationOptions {
    pub ceremony_id: String,
    pub expires_at: String,
    pub public_key: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticationOptions {
    pub ceremony_id: String,
    pub expires_at: String,
    pub public_key: Value,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RegistrationResponse {
    pub id: String,
    pub raw_id: String,
    #[serde(default)]
    pub transports: Vec<String>,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuthenticationResponse {
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedRegistration {
    pub credential_id: String,
    pub public_key_cose: String,
    pub sign_count: i64,
    pub transports: Vec<String>,
    pub aaguid: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedAuthentication {
    pub credential_id: String,
    pub new_counter: u32,
    pub user_verified: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebAuthnFailure {
    InvalidInput,
    Expired,
    ChallengeMismatch,
    OriginMismatch,
    RpIdMismatch,
    UserVerification,
    BadSignature,
    CounterRegression,
    UnsupportedAlgorithm,
    UnknownCredential,
    UserHandleMismatch,
}

impl WebAuthnFailure {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "passkey_invalid",
            Self::Expired => "ceremony_expired",
            Self::ChallengeMismatch => "ceremony_challenge_mismatch",
            Self::OriginMismatch => "ceremony_origin_mismatch",
            Self::RpIdMismatch => "ceremony_rp_id_mismatch",
            Self::UserVerification => "user_verification_required",
            Self::BadSignature => "passkey_signature_invalid",
            Self::CounterRegression => "passkey_counter_regression",
            Self::UnsupportedAlgorithm => "passkey_algorithm_unsupported",
            Self::UnknownCredential => "passkey_not_found",
            Self::UserHandleMismatch => "passkey_user_handle_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdapterError(pub WebAuthnFailure);

impl AdapterError {
    pub const fn invalid_input() -> Self {
        Self(WebAuthnFailure::InvalidInput)
    }
}

#[derive(Clone)]
pub struct WebAuthnAdapter {
    config: WebAuthnConfig,
}

impl WebAuthnAdapter {
    pub fn new(config: WebAuthnConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &WebAuthnConfig {
        &self.config
    }

    pub fn start_registration(
        &self,
        user_handle: &[u8],
        username: &str,
        display_name: &str,
        existing_credential_ids: &[String],
    ) -> Result<(Value, VerifierRegistrationState), AdapterError> {
        if user_handle.is_empty() || user_handle.len() > 64 {
            return Err(AdapterError::invalid_input());
        }
        let existing = existing_credential_ids
            .iter()
            .map(|value| {
                CredentialId::from_b64url(value).map_err(|_| AdapterError::invalid_input())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (mut options, mut state) = self
            .config
            .verifier(&self.config.origins[0])
            .start_registration(user_handle, username, display_name, &existing);
        // The library's public state timestamp uses host time. D1 ceremony
        // expiry is authoritative in the Worker, so avoid depending on WASI
        // clock behavior and let the verifier use its serialized challenge.
        state.created_at = 0;
        options.authenticator_selection.resident_key = Some("required");
        options.authenticator_selection.user_verification = "required";
        let mut public_key =
            serde_json::to_value(options).map_err(|_| AdapterError::invalid_input())?;
        public_key["authenticatorSelection"]["requireResidentKey"] = json!(true);
        Ok((public_key, state))
    }

    pub fn start_authentication(
        &self,
        credentials: &[VerifierCredential],
    ) -> Result<(Value, VerifierAuthenticationState), AdapterError> {
        let (options, mut state) = self
            .config
            .verifier(&self.config.origins[0])
            .start_authentication_with_creds(credentials);
        state.created_at = 0;
        let public_key =
            serde_json::to_value(options).map_err(|_| AdapterError::invalid_input())?;
        Ok((public_key, state))
    }

    pub fn finish_registration(
        &self,
        state: &VerifierRegistrationState,
        response: &RegistrationResponse,
    ) -> Result<VerifiedRegistration, AdapterError> {
        validate_raw_id(&response.id, &response.raw_id)?;
        validate_transports(&response.transports)?;
        let verifier_response = VerifierRegistrationResponse {
            id: response.id.clone(),
            transports: response.transports.clone(),
            attestation_object: response.attestation_object.clone(),
            client_data_json: response.client_data_json.clone(),
        };
        let mut last_error = None;
        for origin in &self.config.origins {
            match self
                .config
                .verifier(origin)
                .finish_registration(state, &verifier_response)
            {
                Ok(credential) => {
                    return Ok(VerifiedRegistration {
                        credential_id: credential.id.to_b64url(),
                        public_key_cose: encode_base64(credential.public_key_cose.as_bytes()),
                        sign_count: i64::from(credential.counter),
                        transports: credential.transports,
                        aaguid: encode_base64(&credential.aaguid),
                    });
                }
                Err(error) => last_error = Some(classify_verifier_error(error)),
            }
        }
        Err(last_error.unwrap_or(AdapterError(WebAuthnFailure::InvalidInput)))
    }

    pub fn finish_authentication(
        &self,
        state: &VerifierAuthenticationState,
        response: &AuthenticationResponse,
        stored: &VerifierCredential,
    ) -> Result<VerifiedAuthentication, AdapterError> {
        validate_raw_id(&response.id, &response.raw_id)?;
        let verifier_response = VerifierAuthenticationResponse {
            id: response.id.clone(),
            authenticator_data: response.authenticator_data.clone(),
            signature: response.signature.clone(),
            client_data_json: response.client_data_json.clone(),
            user_handle: response.user_handle.clone(),
        };
        let mut last_error = None;
        for origin in &self.config.origins {
            match self.config.verifier(origin).finish_authentication(
                state,
                &verifier_response,
                stored,
            ) {
                Ok(result) => {
                    return Ok(VerifiedAuthentication {
                        credential_id: result.credential_id.to_b64url(),
                        new_counter: result.new_counter,
                        user_verified: result.user_verified,
                    });
                }
                Err(error) => last_error = Some(classify_verifier_error(error)),
            }
        }
        Err(last_error.unwrap_or(AdapterError(WebAuthnFailure::InvalidInput)))
    }

    pub fn verifier_credential(
        &self,
        credential_id: &str,
        public_key_cose: &str,
        counter: i64,
        transports: Vec<String>,
    ) -> Result<VerifierCredential, AdapterError> {
        let counter = u32::try_from(counter).map_err(|_| AdapterError::invalid_input())?;
        let id = CredentialId::from_b64url(credential_id)
            .map_err(|_| AdapterError(WebAuthnFailure::UnknownCredential))?;
        let public_key = decode_base64(public_key_cose)
            .map_err(|_| AdapterError(WebAuthnFailure::BadSignature))?;
        Ok(VerifierCredential {
            id,
            public_key_cose: CosePublicKey(public_key),
            counter,
            transports,
            aaguid: [0; 16],
        })
    }
}

pub fn user_handle_matches(encoded: Option<&str>, user_id: &str) -> bool {
    let Some(encoded) = encoded else {
        return true;
    };
    decode_base64(encoded).is_ok_and(|value| value == user_id.as_bytes())
}

fn validate_raw_id(id: &str, raw_id: &str) -> Result<(), AdapterError> {
    if id.is_empty() || id.len() > 2048 || raw_id != id {
        return Err(AdapterError::invalid_input());
    }
    Ok(())
}

fn validate_transports(transports: &[String]) -> Result<(), AdapterError> {
    if transports.len() > 8
        || transports.iter().any(|transport| {
            transport.is_empty()
                || transport.len() > 32
                || !transport
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-' || byte.is_ascii_digit())
        })
    {
        return Err(AdapterError::invalid_input());
    }
    Ok(())
}

fn classify_verifier_error(error: VerifierError) -> AdapterError {
    let failure = match error {
        VerifierError::Base64(_)
        | VerifierError::ClientData(_)
        | VerifierError::AuthData(_)
        | VerifierError::Cbor(_) => WebAuthnFailure::InvalidInput,
        VerifierError::ClientDataType { .. } => WebAuthnFailure::InvalidInput,
        VerifierError::ChallengeMismatch => WebAuthnFailure::ChallengeMismatch,
        VerifierError::OriginMismatch { .. } => WebAuthnFailure::OriginMismatch,
        VerifierError::RpIdHashMismatch => WebAuthnFailure::RpIdMismatch,
        VerifierError::UserNotPresent | VerifierError::UserNotVerified => {
            WebAuthnFailure::UserVerification
        }
        VerifierError::BadSignature => WebAuthnFailure::BadSignature,
        VerifierError::CounterReplay { .. } => WebAuthnFailure::CounterRegression,
        VerifierError::CeremonyExpired { .. } => WebAuthnFailure::Expired,
        VerifierError::UserHandleMismatch => WebAuthnFailure::UserHandleMismatch,
        VerifierError::UnsupportedAlg(_) => WebAuthnFailure::UnsupportedAlgorithm,
        VerifierError::Internal(_) => WebAuthnFailure::InvalidInput,
    };
    AdapterError(failure)
}

fn encode_base64(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

fn decode_base64(value: &str) -> Result<Vec<u8>, ()> {
    URL_SAFE_NO_PAD.decode(value).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> WebAuthnConfig {
        WebAuthnConfig::new(
            Some("example.com".to_owned()),
            Some("Example".to_owned()),
            Some("https://example.com".to_owned()),
        )
        .unwrap()
    }

    #[test]
    fn trusted_origin_validation_rejects_host_confusion() {
        assert!(
            WebAuthnConfig::new(
                Some("example.com".to_owned()),
                Some("Example".to_owned()),
                Some("https://evil.example.com.attacker".to_owned()),
            )
            .is_err()
        );
        assert!(
            WebAuthnConfig::new(
                Some("example.com".to_owned()),
                Some("Example".to_owned()),
                Some("https://example.com.evil".to_owned()),
            )
            .is_err()
        );
        assert!(
            WebAuthnConfig::new(
                Some("example.com".to_owned()),
                Some("Example".to_owned()),
                Some("https://example.com/path".to_owned()),
            )
            .is_err()
        );
    }

    #[test]
    fn registration_policy_is_discoverable_and_uv_required() {
        let adapter = WebAuthnAdapter::new(config());
        let (options, _) = adapter
            .start_registration(b"opaque-user", "a@example.com", "A", &[])
            .unwrap();
        assert_eq!(options["authenticatorSelection"]["residentKey"], "required");
        assert_eq!(
            options["authenticatorSelection"]["requireResidentKey"],
            true
        );
        assert_eq!(
            options["authenticatorSelection"]["userVerification"],
            "required"
        );
        assert!(options["authenticatorSelection"]["authenticatorAttachment"].is_null());
        assert_eq!(options["attestation"], "none");
    }

    #[test]
    fn normal_login_omits_allow_credentials() {
        let adapter = WebAuthnAdapter::new(config());
        let (options, _) = adapter.start_authentication(&[]).unwrap();
        assert!(options.get("allowCredentials").is_none());
        assert_eq!(options["userVerification"], "required");
    }

    #[test]
    fn raw_id_substitution_is_rejected_before_crypto() {
        let adapter = WebAuthnAdapter::new(config());
        let (_, state) = adapter
            .start_registration(b"u", "u@example.com", "U", &[])
            .unwrap();
        let response = RegistrationResponse {
            id: "a".to_owned(),
            raw_id: "b".to_owned(),
            transports: vec![],
            attestation_object: "a".to_owned(),
            client_data_json: "a".to_owned(),
        };
        assert_eq!(
            adapter.finish_registration(&state, &response),
            Err(AdapterError(WebAuthnFailure::InvalidInput))
        );
    }
}
