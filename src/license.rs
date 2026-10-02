use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::crypto::{decrypt, derive_key, encrypt};
use crate::errors::{OnewayError, Result};
use crate::keypair::KeyPair;
use crate::utils::{decode_b64, encode_b64, now_unix};

pub const LICENSE_MAGIC: &[u8; 4] = b"OWSL";
pub const LICENSE_VERSION: u32 = 1;
pub const ENCRYPT_CONTEXT: &[u8] = b"owswp-license-encryption-v1";
pub const SIGN_CONTEXT: &[u8] = b"owswp-license-signature-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    pub version: u32,
    #[serde(rename = "type")]
    pub license_type: String,
    pub created_at: i64,
    pub created_date: String,
    pub expires_at: Option<i64>,
    pub credits: Option<i64>,
    pub duration_seconds: Option<i64>,
    pub nonce: String,
    #[serde(default)]
    pub additional_data: Value,
}

impl LicensePayload {
    pub fn new(
        license_type: &str,
        expires_at: Option<i64>,
        credits: Option<i64>,
        duration_seconds: Option<i64>,
        additional_data: Value,
    ) -> Self {
        let now = now_unix();
        let created_date = chrono::DateTime::from_timestamp(now, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_default();

        let nonce = hex::encode(rand::random::<[u8; 16]>());

        Self {
            version: LICENSE_VERSION,
            license_type: license_type.to_string(),
            created_at: now,
            created_date,
            expires_at,
            credits,
            duration_seconds,
            nonce,
            additional_data,
        }
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| OnewayError::SerializationError(e.to_string()))
    }

    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s)
            .map_err(|e| OnewayError::SerializationError(e.to_string()))
    }
}

pub fn create_license_token(keypair: &KeyPair, payload: &LicensePayload) -> Result<String> {
    let json = payload.to_json()?;
    let json_bytes = json.as_bytes();

    let signature = keypair.sign(json_bytes);
    let sig_bytes = signature.to_bytes();

    let mut inner = Vec::with_capacity(8 + json_bytes.len() + 64);
    inner.extend_from_slice(LICENSE_MAGIC);
    inner.extend_from_slice(&LICENSE_VERSION.to_be_bytes());
    inner.extend_from_slice(json_bytes);
    inner.extend_from_slice(&sig_bytes);

    let encryption_seed = keypair.public.as_bytes();
    let key = derive_key(encryption_seed, ENCRYPT_CONTEXT);
    let encrypted = encrypt(&key, &inner, SIGN_CONTEXT)?;

    Ok(format!("OWSWP-{}", encode_b64(&encrypted)))
}

pub fn parse_license_token(token: &str, public: &VerifyingKey) -> Result<LicensePayload> {
    let raw = token
        .strip_prefix("OWSWP-")
        .ok_or(OnewayError::InvalidKeyFormat)?;

    let encrypted = decode_b64(raw)?;

    let encryption_seed = public.as_bytes();
    let key = derive_key(encryption_seed, ENCRYPT_CONTEXT);
    let inner = decrypt(&key, &encrypted, SIGN_CONTEXT)?;

    if inner.len() < 8 + 64 {
        return Err(OnewayError::CorruptedFile);
    }

    if &inner[..4] != LICENSE_MAGIC {
        return Err(OnewayError::InvalidMagic);
    }

    let version = u32::from_be_bytes(inner[4..8].try_into().unwrap());
    if version != LICENSE_VERSION {
        return Err(OnewayError::UnsupportedVersion(version));
    }

    let sig_offset = inner.len() - 64;
    let json_bytes = &inner[8..sig_offset];
    let sig_bytes: [u8; 64] = inner[sig_offset..]
        .try_into()
        .map_err(|_| OnewayError::CorruptedFile)?;

    let signature = Signature::from_bytes(&sig_bytes);
    public
        .verify(json_bytes, &signature)
        .map_err(|_| OnewayError::InvalidSignature)?;

    let json = std::str::from_utf8(json_bytes).map_err(|_| OnewayError::CorruptedFile)?;
    LicensePayload::from_json(json)
}