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

#[unsafe(no_mangle)]
pub extern "C" fn owswp_generate_key_pair() -> *mut c_char {
    let kp = KeyPair::generate();
    let response = Response {
        status: true,
        code: "SUCCESS".into(),
        message: "Key pair generated".into(),
        license_type: None,
        remaining: None,
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
    let result = (|| -> Result<(String, String, Option<i64>), OnewayError> {
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

        let remaining = credits.or(duration_seconds);

        Ok((token, ltype, remaining))
    })();

    let response = match result {
        Ok((token, license_type, remaining)) => Response {
            status: true,
            code: "SUCCESS".into(),
            message: "License created".into(),
            license_type: Some(license_type),
            remaining,
            additional_data: serde_json::json!({ "token": token }),
        },
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
        state.additional_data = payload.additional_data.clone();

        save_state(&path, verifying.as_bytes(), &state)?;

        let remaining = payload.credits.or(payload.duration_seconds);

        Ok(Response::success_with(
            "License valid and activated",
            Some(payload.license_type.clone()),
            remaining,
            payload.additional_data.clone(),
        ))
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

        check_clock(state.last_known_timestamp)?;

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

        let remaining = if state.license_type == "credit" {
            Some(state.remaining_credits)
        } else if state.license_type == "duration" {
            let elapsed = now - state.created_at;
            let total = state.remaining_credits.max(0);
            Some((total - elapsed).max(0))
        } else {
            None
        };

        Ok(Response::success_with(
            "Protection verified",
            Some(state.license_type.clone()),
            remaining,
            state.additional_data.clone(),
        ))
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
        license_type: None,
        remaining: None,
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
        license_type: None,
        remaining: None,
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