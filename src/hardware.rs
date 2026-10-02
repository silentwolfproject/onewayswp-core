use crate::crypto::blake3_hash;

pub fn hardware_id() -> String {
    let mut parts: Vec<String> = Vec::new();

    if let Ok(uid) = machine_uid::get() {
        parts.push(uid);
    }

    if let Ok(hostname) = hostname::get() {
        parts.push(hostname.to_string_lossy().to_string());
    }

    parts.push(std::env::consts::OS.to_string());
    parts.push(std::env::consts::ARCH.to_string());

    let raw = parts.join("|");
    let hash = blake3_hash(raw.as_bytes());
    hex::encode(&hash[..16])
}