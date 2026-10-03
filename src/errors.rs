use thiserror::Error;

#[derive(Error, Debug)]
pub enum OnewayError {
    #[error("Invalid magic header")]
    InvalidMagic,

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u32),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid key format")]
    InvalidKeyFormat,

    #[error("Key mismatch: client cannot use secret key")]
    KeyMismatch,

    #[error("Token expired")]
    Expired,

    #[error("Clock rollback detected")]
    ClockRollback,

    #[error("Corrupted file")]
    CorruptedFile,

    #[error("Insufficient credits")]
    InsufficientCredits,

    #[error("File locked")]
    FileLocked,

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("FFI error: {0}")]
    FfiError(String),

    #[error("Security error: {0}")]
    SecurityError(String),
}

pub type Result<T> = std::result::Result<T, OnewayError>;

impl OnewayError {
    pub fn code(&self) -> &'static str {
        match self {
            OnewayError::InvalidMagic => "INVALID_MAGIC",
            OnewayError::UnsupportedVersion(_) => "UNSUPPORTED_VERSION",
            OnewayError::InvalidSignature => "INVALID_SIGNATURE",
            OnewayError::InvalidKeyFormat => "INVALID_KEY_FORMAT",
            OnewayError::KeyMismatch => "KEY_MISMATCH",
            OnewayError::Expired => "EXPIRED",
            OnewayError::ClockRollback => "CLOCK_ROLLBACK_DETECTED",
            OnewayError::CorruptedFile => "CORRUPTED_FILE",
            OnewayError::InsufficientCredits => "INSUFFICIENT_CREDITS",
            OnewayError::FileLocked => "FILE_LOCKED",
            OnewayError::IoError(_) => "IO_ERROR",
            OnewayError::CryptoError(_) => "CRYPTO_ERROR",
            OnewayError::SerializationError(_) => "SERIALIZATION_ERROR",
            OnewayError::FfiError(_) => "FFI_ERROR",
            OnewayError::SecurityError(_) => "SECURITY_ERROR",
        }
    }
}