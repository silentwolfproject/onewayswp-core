use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::errors::{OnewayError, Result};

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const HMAC_SIZE: usize = 32;

type HmacSha256 = Hmac<Sha256>;

pub fn derive_key(seed: &[u8], context: &[u8]) -> [u8; KEY_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(context);
    hasher.update(seed);
    let result = hasher.finalize();
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&result);
    key
}

pub fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_bytes = rand::random::<[u8; NONCE_SIZE]>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| OnewayError::CryptoError(e.to_string()))?;

    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn decrypt(key: &[u8], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_SIZE + 16 {
        return Err(OnewayError::CorruptedFile);
    }

    let nonce = Nonce::from_slice(&blob[..NONCE_SIZE]);
    let ciphertext = &blob[NONCE_SIZE..];

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| OnewayError::InvalidSignature)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

pub fn hmac_sign(key: &[u8], message: &[u8]) -> [u8; HMAC_SIZE] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .expect("HMAC key length valid");
    mac.update(message);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; HMAC_SIZE];
    out.copy_from_slice(&result);
    out
}

pub fn hmac_verify(key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if signature.len() != HMAC_SIZE {
        return false;
    }
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .expect("HMAC key length valid");
    mac.update(message);
    mac.verify_slice(signature).is_ok()
}