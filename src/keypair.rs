use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::errors::{OnewayError, Result};
use crate::utils::{decode_b64, encode_b64};

pub const PUB_PREFIX: &str = "OWSWP-pub-";
pub const SEC_PREFIX: &str = "OWSWP-sec-";

#[derive(Clone)]
pub struct KeyPair {
    pub secret: SigningKey,
    pub public: VerifyingKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let secret = SigningKey::generate(&mut OsRng);
        let public = secret.verifying_key();
        Self { secret, public }
    }

    pub fn from_secret(secret_bytes: &[u8; 32]) -> Self {
        let secret = SigningKey::from_bytes(secret_bytes);
        let public = secret.verifying_key();
        Self { secret, public }
    }

    pub fn validate(secret: &SigningKey, public: &VerifyingKey) -> bool {
        secret.verifying_key() == *public
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.secret.sign(message)
    }

    pub fn verify(public: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
        public.verify(message, signature).is_ok()
    }

    pub fn secret_to_string(&self) -> String {
        format!("{}{}", SEC_PREFIX, encode_b64(self.secret.as_bytes()))
    }

    pub fn public_to_string(&self) -> String {
        format!("{}{}", PUB_PREFIX, encode_b64(self.public.as_bytes()))
    }
}

pub fn parse_secret(s: &str) -> Result<SigningKey> {
    if !s.starts_with(SEC_PREFIX) {
        return Err(OnewayError::SecurityError(
            "Client cannot use secret key. Use public key instead.".into(),
        ));
    }
    let raw = s
        .strip_prefix(SEC_PREFIX)
        .ok_or(OnewayError::InvalidKeyFormat)?;
    let bytes = decode_b64(raw)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| OnewayError::InvalidKeyFormat)?;
    Ok(SigningKey::from_bytes(&arr))
}

pub fn parse_public(s: &str) -> Result<VerifyingKey> {
    if s.starts_with(SEC_PREFIX) {
        return Err(OnewayError::SecurityError(
            "Security error: you provided a secret key. Use public key.".into(),
        ));
    }
    if !s.starts_with(PUB_PREFIX) {
        return Err(OnewayError::InvalidKeyFormat);
    }
    let raw = s
        .strip_prefix(PUB_PREFIX)
        .ok_or(OnewayError::InvalidKeyFormat)?;
    let bytes = decode_b64(raw)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| OnewayError::InvalidKeyFormat)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| OnewayError::InvalidKeyFormat)
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        let mut bytes = self.secret.to_bytes();
        bytes.zeroize();
    }
}