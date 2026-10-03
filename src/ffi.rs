use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use crate::clock::check_clock;
use crate::errors::OnewayError;
use crate::keypair::{parse_public, parse_secret, KeyPair};
use crate::license::{create_license_token, parse_license_token, LicensePayload};
use crate::response::Response;
use crate::state::{load_state, save_state, StateData};
use crate::utils::{now_unix, parse_date};

fn cstr_to_str(ptr: *const c_char) -> Result<String, OnewayError> {
    if ptr.is_null() {
        return Err(OnewayError::FfiError("null pointer".into()));
    }
    unsafe {
        CStr::from_ptr(ptr)
            .to_str()
            .map(|s| s.to_string())
            .map_err(|_| OnewayError::FfiError("invalid utf-8".into()))
    }
}

fn string_to_c(s: String) -> *mut c_char {
    CString::new(s)
        .map(|c| c.into_raw())
        .unwrap_or(ptr::null_mut())
}

fn format_timestamp(ts: i64) -> Option<String> {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
}

fn format_date(ts: i64) -> Option<String> {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.format("%Y-%m-%d").to_string())
}

fn build_success_response(
    license_type: &str,
    payload: &LicensePayload,
    now: i64,
    last_known: i64,
) -> Response {
    let mut map = serde_json::Map::new();

    map.insert("type".into(), serde_json::json!(license_type));

    match license_type {
        "credit" => {
            let credits = payload.credits.unwrap_or(0);
            map.insert("credit_value".into(), serde_json::json!(credits));
            map.insert("remaining_credits".into(), serde_json::json!(credits));
        }
        "duration" => {
            let duration_sec = payload.duration_seconds.unwrap_or(0);
            let hours = duration_sec as f64 / 3600.0;
            let elapsed = (now - payload.created_at).max(0);
            let remaining_sec = (duration_sec - elapsed).max(0);
            let remaining_hours = remaining_sec as f64 / 3600.0;
            map.insert("duration_hours".into(), serde_json::json!(hours));
            map.insert("remaining_hours".into(), serde_json::json!(remaining_hours));
        }
        "date" => {
            if let Some(exp) = payload.expires_at {
                let remaining_sec = (exp - now).max(0);
                let remaining_days = remaining_sec / 86400;
                if let Some(exp_str) = format_date(exp) {
                    map.insert("expired".into(), serde_json::json!(exp_str));
                }
                map.insert("remaining_days".into(), serde_json::json!(remaining_days));
            }
        }
        _ => {}
    }

    if let Some(created) = format_timestamp(payload.created_at) {
        map.insert("created_at".into(), serde_json::json!(created));
    }

    if let Some(last) = format_timestamp(last_known) {
        map.insert("last_time".into(), serde_json::json!(last));
    }

    if let Some(obj) = payload.additional_data.as_object() {
        if !obj.is_empty() {
            map.insert("additional_data".into(), payload.additional_data.clone());
        }
    }

    Response {
        status: true,
        code: "SUCCESS".into(),
        message: "License valid and activated".into(),
        additional_data: serde_json::Value::Object(map),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn owswp_generate_key_pair() -> *mut c_char {
    let kp = KeyPair::generate();
    let response = Response {
        status: true,
        code: "SUCCESS".into(),
        message: "Key pair generated".into(),
        additional_data: serde_json::json!({
            "secret_key": kp.secret_to_string(),
            "public_key": kp.public_to_string(),
        }),
    };
    string_to_c(response.to_json())
}

#[unsafe(no_mangle)]
pub extern "C" fn owswp_validate_key_pair(
    secret_key: *const c_char,
    public_key: *const c_char,
) -> *mut c_char {
    let result = (|| -> Result<bool, OnewayError> {
        let sec = cstr_to_str(secret_key)?;
        let pub_str = cstr_to_str(public_key)?;

        let signing = parse_secret(&sec)?;
        let verifying = parse_public(&pub_str)?;

        Ok(KeyPair::validate(&signing, &verifying))
    })();

    let response = match result {
        Ok(true) => Response::success("Keys match"),
        Ok(false) => Response::failure(&OnewayError::KeyMismatch),
        Err(e) => Response::failure(&e),
    };

    string_to_c(response.to_json())
}

#[unsafe(no_mangle)]
pub extern "C" fn owswp_create_license(
    secret_key: *const c_char,
    license_type: *const c_char,
    payload_json: *const c_char,
) -> *mut c_char {
    let result = (|| -> Result<(String, String, Option<i64>, Option<i64>, Option<i64>), OnewayError> {
        let sec = cstr_to_str(secret_key)?;
        let ltype = cstr_to_str(license_type)?;
        let payload_str = cstr_to_str(payload_json)?;

        let signing = parse_secret(&sec)?;
        let public = signing.verifying_key();
        let kp = KeyPair {
            secret: signing,
            public,
        };

        let payload: serde_json::Value = serde_json::from_str(&payload_str)
            .map_err(|e| OnewayError::SerializationError(e.to_string()))?;

        let expires_at = payload
            .get("expires")
            .and_then(|v| v.as_str())
            .map(parse_date)
            .transpose()?;

        let credits = payload.get("credits").and_then(|v| v.as_i64());
        let duration_seconds = payload.get("duration_seconds").and_then(|v| v.as_i64());

        let additional = payload
            .get("additional_data")
            .cloned()
            .unwrap_or(serde_json::json!({}));

        let license = LicensePayload::new(
            &ltype,
            expires_at,
            credits,
            duration_seconds,
            additional,
        );

        let token = create_license_token(&kp, &license)?;

        Ok((token, ltype, expires_at, credits, duration_seconds))
    })();

    let response = match result {
        Ok((token, license_type, expires_at, credits, duration_seconds)) => {
            let mut map = serde_json::Map::new();
            map.insert("token".into(), serde_json::json!(token));
            map.insert("type".into(), serde_json::json!(license_type));

            if let Some(exp) = expires_at {
                if let Some(exp_str) = format_date(exp) {
                    map.insert("expired".into(), serde_json::json!(exp_str));
                }
                map.insert("expires_at".into(), serde_json::json!(exp));
            }

            if let Some(c) = credits {
                map.insert("credit_value".into(), serde_json::json!(c));
            }

            if let Some(d) = duration_seconds {
                let hours = d as f64 / 3600.0;
                map.insert("duration_hours".into(), serde_json::json!(hours));
            }

            Response {
                status: true,
                code: "SUCCESS".into(),
                message: "License created".into(),
                additional_data: serde_json::Value::Object(map),
            }
        }
        Err(e) => Response::failure(&e),
    };

    string_to_c(response.to_json())
}

#[unsafe(no_mangle)]
pub extern "C" fn owswp_validate_key(
    token: *const c_char,
    public_key: *const c_char,
    swpb_path: *const c_char,
) -> *mut c_char {
    let result = (|| -> Result<Response, OnewayError> {
        let token_str = cstr_to_str(token)?;
        let pub_str = cstr_to_str(public_key)?;
        let path = cstr_to_str(swpb_path)?;

        let verifying = parse_public(&pub_str)?;
        let payload = parse_license_token(&token_str, &verifying)?;

        let now = now_unix();

        if now < payload.created_at {
            return Err(OnewayError::ClockRollback);
        }

        if let Some(exp) = payload.expires_at {
            if now > exp {
                return Err(OnewayError::Expired);
            }
        }

        let mut state = StateData::new(&payload.license_type);
        state.created_at = payload.created_at;
        state.last_known_timestamp = now;
        state.remaining_credits = payload.credits.unwrap_or(0);
        state.expires_at = payload.expires_at;
        state.duration_seconds = payload.duration_seconds;
        state.additional_data = payload.additional_data.clone();

        save_state(&path, verifying.as_bytes(), &state)?;

        Ok(build_success_response(
            &payload.license_type,
            &payload,
            now,
            now,
        ))
    })();

    let response = match result {
        Ok(r) => r,
        Err(e) => Response::failure(&e),
    };

    string_to_c(response.to_json())
}

#[unsafe(no_mangle)]
pub extern "C" fn owswp_inspect_key(
    token: *const c_char,
    public_key: *const c_char,
) -> *mut c_char {
    let result = (|| -> Result<Response, OnewayError> {
        let token_str = cstr_to_str(token)?;
        let pub_str = cstr_to_str(public_key)?;

        let verifying = parse_public(&pub_str)?;
        let payload = parse_license_token(&token_str, &verifying)?;

        let now = now_unix();

        let mut map = serde_json::Map::new();
        map.insert("type".into(), serde_json::json!(payload.license_type));

        match payload.license_type.as_str() {
            "credit" => {
                let credits = payload.credits.unwrap_or(0);
                map.insert("credit_value".into(), serde_json::json!(credits));
                map.insert("remaining_credits".into(), serde_json::json!(credits));
            }
            "duration" => {
                let duration_sec = payload.duration_seconds.unwrap_or(0);
                let hours = duration_sec as f64 / 3600.0;
                map.insert("duration_hours".into(), serde_json::json!(hours));
                map.insert("remaining_hours".into(), serde_json::json!(hours));
            }
            "date" => {
                if let Some(exp) = payload.expires_at {
                    let remaining_sec = (exp - now).max(0);
                    let remaining_days = remaining_sec / 86400;
                    if let Some(exp_str) = format_date(exp) {
                        map.insert("expired".into(), serde_json::json!(exp_str));
                    }
                    map.insert("remaining_days".into(), serde_json::json!(remaining_days));
                }
            }
            _ => {}
        }

        if let Some(created) = format_timestamp(payload.created_at) {
            map.insert("created_at".into(), serde_json::json!(created));
        }

        map.insert("is_expired".into(), serde_json::json!(payload.is_expired()));

        if let Some(obj) = payload.additional_data.as_object() {
            if !obj.is_empty() {
                map.insert("additional_data".into(), payload.additional_data.clone());
            }
        }

        Ok(Response {
            status: true,
            code: "SUCCESS".into(),
            message: "License inspected".into(),
            additional_data: serde_json::Value::Object(map),
        })
    })();

    let response = match result {
        Ok(r) => r,
        Err(e) => Response::failure(&e),
    };

    string_to_c(response.to_json())
}

#[unsafe(no_mangle)]
pub extern "C" fn owswp_protection_verify(
    public_key: *const c_char,
    swpb_path: *const c_char,
) -> *mut c_char {
    let result = (|| -> Result<Response, OnewayError> {
        let pub_str = cstr_to_str(public_key)?;
        let path = cstr_to_str(swpb_path)?;

        let verifying = parse_public(&pub_str)?;
        let mut state = load_state(&path, verifying.as_bytes())?;

        let now = now_unix();

        check_clock(state.last_known_timestamp, now)?;

        if now < state.created_at {
            return Err(OnewayError::ClockRollback);
        }

        if let Some(exp) = state.expires_at {
            if now > exp {
                return Err(OnewayError::Expired);
            }
        }

        state.last_known_timestamp = now;
        save_state(&path, verifying.as_bytes(), &state)?;

        let mut map = serde_json::Map::new();
        map.insert("type".into(), serde_json::json!(state.license_type));

        match state.license_type.as_str() {
            "credit" => {
                map.insert("credit_value".into(), serde_json::json!(state.remaining_credits));
                map.insert("remaining_credits".into(), serde_json::json!(state.remaining_credits));
            }
            "duration" => {
                let duration_sec = state.duration_seconds.unwrap_or(0);
                let hours = duration_sec as f64 / 3600.0;
                let elapsed = (now - state.created_at).max(0);
                let remaining_sec = (duration_sec - elapsed).max(0);
                let remaining_hours = remaining_sec as f64 / 3600.0;
                map.insert("duration_hours".into(), serde_json::json!(hours));
                map.insert("remaining_hours".into(), serde_json::json!(remaining_hours));
            }
            "date" => {
                if let Some(exp) = state.expires_at {
                    let remaining_sec = (exp - now).max(0);
                    let remaining_days = remaining_sec / 86400;
                    if let Some(exp_str) = format_date(exp) {
                        map.insert("expired".into(), serde_json::json!(exp_str));
                    }
                    map.insert("remaining_days".into(), serde_json::json!(remaining_days));
                }
            }
            _ => {}
        }

        if let Some(created) = format_timestamp(state.created_at) {
            map.insert("created_at".into(), serde_json::json!(created));
        }

        if let Some(last) = format_timestamp(now) {
            map.insert("last_time".into(), serde_json::json!(last));
        }

        if let Some(obj) = state.additional_data.as_object() {
            if !obj.is_empty() {
                map.insert("additional_data".into(), state.additional_data.clone());
            }
        }

        Ok(Response {
            status: true,
            code: "SUCCESS".into(),
            message: "Protection verified".into(),
            additional_data: serde_json::Value::Object(map),
        })
    })();

    let response = match result {
        Ok(r) => r,
        Err(e) => Response::failure(&e),
    };

    string_to_c(response.to_json())
}

#[unsafe(no_mangle)]
pub extern "C" fn owswp_decrement_credit(
    public_key: *const c_char,
    swpb_path: *const c_char,
    amount: i64,
) -> *mut c_char {
    let result = (|| -> Result<Response, OnewayError> {
        let pub_str = cstr_to_str(public_key)?;
        let path = cstr_to_str(swpb_path)?;

        let verifying = parse_public(&pub_str)?;
        let mut state = load_state(&path, verifying.as_bytes())?;

        if state.license_type != "credit" {
            return Err(OnewayError::CryptoError(
                "Not a credit license".into(),
            ));
        }

        if amount <= 0 {
            return Err(OnewayError::CryptoError(
                "Amount must be greater than zero".into(),
            ));
        }

        let now = now_unix();
        check_clock(state.last_known_timestamp, now)?;

        if state.remaining_credits < amount {
            return Err(OnewayError::InsufficientCredits);
        }

        state.remaining_credits -= amount;
        state.last_known_timestamp = now;
        save_state(&path, verifying.as_bytes(), &state)?;

        let mut map = serde_json::Map::new();
        map.insert("type".into(), serde_json::json!("credit"));
        map.insert("credit_value".into(), serde_json::json!(state.remaining_credits));
        map.insert("remaining_credits".into(), serde_json::json!(state.remaining_credits));
        map.insert("used".into(), serde_json::json!(amount));

        Ok(Response {
            status: true,
            code: "SUCCESS".into(),
            message: "Credit decremented".into(),
            additional_data: serde_json::Value::Object(map),
        })
    })();

    let response = match result {
        Ok(r) => r,
        Err(e) => Response::failure(&e),
    };

    string_to_c(response.to_json())
}

#[unsafe(no_mangle)]
pub extern "C" fn owswp_start_session(
    public_key: *const c_char,
    swpb_path: *const c_char,
) -> *mut c_char {
    let result = (|| -> Result<Response, OnewayError> {
        let pub_str = cstr_to_str(public_key)?;
        let path = cstr_to_str(swpb_path)?;

        let verifying = parse_public(&pub_str)?;
        let mut state = load_state(&path, verifying.as_bytes())?;

        if state.license_type != "duration" {
            return Err(OnewayError::CryptoError(
                "Not a duration license".into(),
            ));
        }

        let now = now_unix();
        check_clock(state.last_known_timestamp, now)?;

        state.last_known_timestamp = now;
        save_state(&path, verifying.as_bytes(), &state)?;

        let mut map = serde_json::Map::new();
        map.insert("type".into(), serde_json::json!("duration"));
        if let Some(started) = format_timestamp(now) {
            map.insert("started_at".into(), serde_json::json!(started));
        }

        Ok(Response {
            status: true,
            code: "SUCCESS".into(),
            message: "Session started".into(),
            additional_data: serde_json::Value::Object(map),
        })
    })();

    let response = match result {
        Ok(r) => r,
        Err(e) => Response::failure(&e),
    };

    string_to_c(response.to_json())
}

#[unsafe(no_mangle)]
pub extern "C" fn owswp_stop_session(
    public_key: *const c_char,
    swpb_path: *const c_char,
) -> *mut c_char {
    let result = (|| -> Result<Response, OnewayError> {
        let pub_str = cstr_to_str(public_key)?;
        let path = cstr_to_str(swpb_path)?;

        let verifying = parse_public(&pub_str)?;
        let mut state = load_state(&path, verifying.as_bytes())?;

        if state.license_type != "duration" {
            return Err(OnewayError::CryptoError(
                "Not a duration license".into(),
            ));
        }

        let now = now_unix();
        check_clock(state.last_known_timestamp, now)?;

        let elapsed = (now - state.last_known_timestamp).max(0);

        let duration_sec = state.duration_seconds.unwrap_or(0);
        let total_elapsed = (now - state.created_at).max(0);
        let remaining_sec = (duration_sec - total_elapsed).max(0);
        let remaining_hours = remaining_sec as f64 / 3600.0;

        state.last_known_timestamp = now;
        state.remaining_credits = remaining_sec;
        save_state(&path, verifying.as_bytes(), &state)?;

        let mut map = serde_json::Map::new();
        map.insert("type".into(), serde_json::json!("duration"));
        map.insert("elapsed_seconds".into(), serde_json::json!(elapsed));
        map.insert("remaining_hours".into(), serde_json::json!(remaining_hours));
        if let Some(stopped) = format_timestamp(now) {
            map.insert("stopped_at".into(), serde_json::json!(stopped));
        }

        Ok(Response {
            status: true,
            code: "SUCCESS".into(),
            message: "Session stopped".into(),
            additional_data: serde_json::Value::Object(map),
        })
    })();

    let response = match result {
        Ok(r) => r,
        Err(e) => Response::failure(&e),
    };

    string_to_c(response.to_json())
}

#[unsafe(no_mangle)]
pub extern "C" fn owswp_export_state(
    public_key: *const c_char,
    swpb_path: *const c_char,
) -> *mut c_char {
    let result = (|| -> Result<Response, OnewayError> {
        let pub_str = cstr_to_str(public_key)?;
        let path = cstr_to_str(swpb_path)?;

        let verifying = parse_public(&pub_str)?;
        let state = load_state(&path, verifying.as_bytes())?;

        let data = serde_json::to_string(&state)
            .map_err(|e| OnewayError::SerializationError(e.to_string()))?;

        let mut map = serde_json::Map::new();
        map.insert("data".into(), serde_json::json!(data));

        Ok(Response {
            status: true,
            code: "SUCCESS".into(),
            message: "State exported".into(),
            additional_data: serde_json::Value::Object(map),
        })
    })();

    let response = match result {
        Ok(r) => r,
        Err(e) => Response::failure(&e),
    };

    string_to_c(response.to_json())
}

#[unsafe(no_mangle)]
pub extern "C" fn owswp_import_state(
    public_key: *const c_char,
    swpb_path: *const c_char,
    data: *const c_char,
) -> *mut c_char {
    let result = (|| -> Result<Response, OnewayError> {
        let pub_str = cstr_to_str(public_key)?;
        let path = cstr_to_str(swpb_path)?;
        let data_str = cstr_to_str(data)?;

        let verifying = parse_public(&pub_str)?;

        let state: StateData = serde_json::from_str(&data_str)
            .map_err(|e| OnewayError::SerializationError(e.to_string()))?;

        save_state(&path, verifying.as_bytes(), &state)?;

        Ok(Response::success("State imported"))
    })();

    let response = match result {
        Ok(r) => r,
        Err(e) => Response::failure(&e),
    };

    string_to_c(response.to_json())
}

#[unsafe(no_mangle)]
pub extern "C" fn owswp_version() -> *mut c_char {
    let response = Response {
        status: true,
        code: "SUCCESS".into(),
        message: "Version".into(),
        additional_data: serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
        }),
    };
    string_to_c(response.to_json())
}

#[unsafe(no_mangle)]
pub extern "C" fn owswp_info() -> *mut c_char {
    let response = Response {
        status: true,
        code: "SUCCESS".into(),
        message: "Library info".into(),
        additional_data: serde_json::json!({
            "author": "Juan Hulu - silentwolfproject",
            "oneway_version": env!("CARGO_PKG_VERSION"),
            "author_github": "https://github.com/juanhulu",
            "swp_github": "https://github.com/silentwolfproject",
            "author_tiktok": "https://tiktok.com/@juanhulu.xyz",
            "swp_tiktok": "https://tiktok.com/@juanhulu.xyz",
            "author_instagram": "https://www.instagram.com/juanhulu.xyz",
            "swp_instagram": "https://www.instagram.com/silentwolfproject",
            "swp_github_pages": "https://silentwolfproject.github.io",
            "description": "OnewaySWP is a lightweight license framework designed for offline verification. It works entirely without a server or internet connection, ensuring that licensed applications remain verifiable anywhere, anytime. Built with strong security in mind, it protects license integrity and prevents tampering through a self-contained verification system. The internal security methods are kept private to discourage duplication and reverse engineering. OnewaySWP provides a simple, dependable licensing solution for developers who value portability, privacy, and protection.",
        }),
    };
    string_to_c(response.to_json())
}

#[unsafe(no_mangle)]
pub extern "C" fn owswp_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}