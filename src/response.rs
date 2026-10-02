use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::errors::OnewayError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub status: bool,
    pub code: String,
    pub message: String,
    #[serde(rename = "type")]
    pub license_type: Option<String>,
    pub remaining: Option<i64>,
    pub additional_data: Value,
}

impl Response {
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            status: true,
            code: "SUCCESS".to_string(),
            message: message.into(),
            license_type: None,
            remaining: None,
            additional_data: Value::Object(Default::default()),
        }
    }

    pub fn success_with(
        message: impl Into<String>,
        license_type: Option<String>,
        remaining: Option<i64>,
        additional_data: Value,
    ) -> Self {
        Self {
            status: true,
            code: "SUCCESS".to_string(),
            message: message.into(),
            license_type,
            remaining,
            additional_data,
        }
    }

    pub fn failure(error: &OnewayError) -> Self {
        Self {
            status: false,
            code: error.code().to_string(),
            message: error.to_string(),
            license_type: None,
            remaining: None,
            additional_data: Value::Object(Default::default()),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"status":false,"code":"SERIALIZATION_ERROR","message":"Failed","type":null,"remaining":null,"additional_data":{}}"#.to_string()
        })
    }
}