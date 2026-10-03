use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::errors::OnewayError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub status: bool,
    pub code: String,
    pub message: String,
    pub additional_data: Value,
}

impl Response {
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            status: true,
            code: "SUCCESS".to_string(),
            message: message.into(),
            additional_data: Value::Object(Default::default()),
        }
    }

    pub fn success_with_data(message: impl Into<String>, data: Value) -> Self {
        Self {
            status: true,
            code: "SUCCESS".to_string(),
            message: message.into(),
            additional_data: data,
        }
    }

    pub fn failure(error: &OnewayError) -> Self {
        Self {
            status: false,
            code: error.code().to_string(),
            message: error.to_string(),
            additional_data: Value::Object(Default::default()),
        }
    }

    pub fn to_json(&self) -> String {
        let mut map = serde_json::Map::new();
        map.insert("status".into(), serde_json::json!(self.status));
        map.insert("code".into(), serde_json::json!(self.code));
        map.insert("message".into(), serde_json::json!(self.message));

        if self.status {
            if let Some(obj) = self.additional_data.as_object() {
                for (k, v) in obj {
                    if !v.is_null() {
                        map.insert(k.clone(), v.clone());
                    }
                }
            }
        }

        serde_json::to_string(&Value::Object(map)).unwrap_or_else(|_| {
            r#"{"status":false,"code":"SERIALIZATION_ERROR","message":"Failed"}"#.to_string()
        })
    }
}