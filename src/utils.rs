use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::errors::{OnewayError, Result};

pub fn encode_b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn decode_b64(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| OnewayError::InvalidKeyFormat)
}

pub fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

pub fn parse_date(s: &str) -> Result<i64> {
    let dt = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .map_err(|_| OnewayError::SerializationError("Invalid date format".into()))?;
    let datetime = dt.and_hms_opt(23, 59, 59)
        .ok_or(OnewayError::SerializationError("Invalid time".into()))?;
    Ok(datetime.and_utc().timestamp())
}