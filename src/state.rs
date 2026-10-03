use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::crypto::{decrypt, derive_key, encrypt, hmac_sign, hmac_verify};
use crate::errors::{OnewayError, Result};
use crate::utils::now_unix;

pub const STATE_MAGIC: &[u8; 4] = b"SWPB";
pub const STATE_VERSION: u32 = 0x01000000;
pub const STATE_ENCRYPT_CONTEXT: &[u8] = b"owswp-state-encryption-v1";
pub const STATE_HMAC_CONTEXT: &[u8] = b"owswp-state-hmac-v1";
pub const HMAC_SIZE: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateData {
    pub version: u32,
    pub license_type: String,
    pub created_at: i64,
    pub last_known_timestamp: i64,
    pub remaining_credits: i64,
    pub expires_at: Option<i64>,
    pub duration_seconds: Option<i64>,
    pub additional_data: Value,
}

impl StateData {
    pub fn new(license_type: &str) -> Self {
        let now = now_unix();
        Self {
            version: STATE_VERSION,
            license_type: license_type.to_string(),
            created_at: now,
            last_known_timestamp: now,
            remaining_credits: 0,
            expires_at: None,
            duration_seconds: None,
            additional_data: Value::Object(Default::default()),
        }
    }
}

pub fn save_state(path: &str, public_bytes: &[u8; 32], state: &StateData) -> Result<()> {
    let json = serde_json::to_string(state)
        .map_err(|e| OnewayError::SerializationError(e.to_string()))?;

    let encryption_key = derive_key(public_bytes, STATE_ENCRYPT_CONTEXT);
    let encrypted = encrypt(&encryption_key, json.as_bytes(), STATE_HMAC_CONTEXT)?;

    let mut signed = Vec::with_capacity(8 + encrypted.len());
    signed.extend_from_slice(STATE_MAGIC);
    signed.extend_from_slice(&STATE_VERSION.to_be_bytes());
    signed.extend_from_slice(&encrypted);

    let hmac_key = derive_key(public_bytes, STATE_HMAC_CONTEXT);
    let signature = hmac_sign(&hmac_key, &signed);

    let mut blob = signed;
    blob.extend_from_slice(&signature);

    let tmp = format!("{}.tmp", path);
    std::fs::write(&tmp, &blob).map_err(|e| OnewayError::IoError(e.to_string()))?;
    std::fs::rename(&tmp, path).map_err(|e| OnewayError::IoError(e.to_string()))?;

    Ok(())
}

pub fn load_state(path: &str, public_bytes: &[u8; 32]) -> Result<StateData> {
    let blob = std::fs::read(path).map_err(|e| OnewayError::IoError(e.to_string()))?;

    if blob.len() < 8 + HMAC_SIZE {
        return Err(OnewayError::CorruptedFile);
    }

    if &blob[..4] != STATE_MAGIC {
        return Err(OnewayError::InvalidMagic);
    }

    let hmac_offset = blob.len() - HMAC_SIZE;
    let signed_data = &blob[..hmac_offset];
    let signature = &blob[hmac_offset..];

    let hmac_key = derive_key(public_bytes, STATE_HMAC_CONTEXT);
    if !hmac_verify(&hmac_key, signed_data, signature) {
        return Err(OnewayError::InvalidSignature);
    }

    let encrypted = &signed_data[8..];

    let encryption_key = derive_key(public_bytes, STATE_ENCRYPT_CONTEXT);
    let json_bytes = decrypt(&encryption_key, encrypted, STATE_HMAC_CONTEXT)?;

    let json = std::str::from_utf8(&json_bytes).map_err(|_| OnewayError::CorruptedFile)?;
    serde_json::from_str(json).map_err(|e| OnewayError::SerializationError(e.to_string()))
}