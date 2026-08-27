//! File-backed cache for RSA profiles.
//!
//! Key = hash of `clmods.dll` (or fallback: hash of `system` folder listing).
//! Value = (N_LE hex, D_LE hex) as captured from live client.
//! On next run we try cached profile before injecting.

use std::io::Read;
use std::path::Path;

use crate::crypto::hex::hex_to_bytes;
use crate::format::aac;
use sha1::{Digest, Sha1};

fn hash_file(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; 1024 * 1024];
    let mut hasher = Sha1::new();
    let mut total = 0usize;
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n;
        if total >= 1024 * 1024 {
            break; // only first 1 MiB for speed
        }
    }
    if total == 0 {
        return None;
    }
    let digest = hasher.finalize();
    // 16 hex = 8 bytes of SHA-1, enough for cache key
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]
    ))
}

pub fn cache_key(system_dir: &Path, client_exe: &str) -> String {
    let clmods = system_dir.join("clmods.dll");
    if let Some(h) = hash_file(&clmods) {
        return h;
    }
    let client = system_dir.join(client_exe);
    if let Ok(mut file) = std::fs::File::open(&client) {
        let mut buf = vec![0u8; 64 * 1024];
        let mut hasher = Sha1::new();
        let mut any = false;
        while let Ok(n) = file.read(&mut buf) {
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            any = true;
            if any && n < buf.len() {
                break;
            }
        }
        if any {
            let d = hasher.finalize();
            return format!(
                "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
            );
        }
    }
    // fallback: SHA-1 of sorted file names
    if let Ok(entries) = std::fs::read_dir(system_dir) {
        let mut names: Vec<String> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        let mut hasher = Sha1::new();
        for n in &names {
            hasher.update(n.as_bytes());
            hasher.update(b"\0");
        }
        let d = hasher.finalize();
        return format!(
            "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
        );
    }
    "unknown".to_owned()
}

fn cache_dir() -> std::path::PathBuf {
    std::env::temp_dir().join("AACDecoder")
}

fn cache_path(key: &str) -> std::path::PathBuf {
    let dir = cache_dir();
    let _ = std::fs::create_dir_all(&dir);
    dir.join(format!("rsa_{key}.bin"))
}

pub fn load_cached_profile(system_dir: &Path, client_exe: &str) -> Option<aac::RsaProfile> {
    let key = cache_key(system_dir, client_exe);
    let path = cache_path(&key);
    let bytes = std::fs::read(&path).ok()?;
    // format: N_LE hex \n D_LE hex \n
    let text = String::from_utf8_lossy(&bytes);
    let mut lines = text.lines();
    let n_hex = lines.next()?.trim();
    let d_hex = lines.next()?.trim();
    if n_hex.is_empty() || d_hex.is_empty() {
        return None;
    }
    let n_le = hex_to_bytes(n_hex)?;
    let d_le = hex_to_bytes(d_hex)?;
    aac::RsaProfile::from_le_components("cache", &n_le, &d_le).ok()
}

pub fn save_cached_profile(system_dir: &Path, client_exe: &str, profile: &aac::RsaProfile) {
    let key = cache_key(system_dir, client_exe);
    let path = cache_path(&key);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let n_le_hex =
        profile.modulus.to_bytes_le().iter().map(|b| format!("{b:02x}")).collect::<String>();
    // private_exponent_be is BE, convert back to LE for storage
    let mut d_le = profile.private_exponent_be.clone();
    d_le.reverse();
    let d_le_hex = d_le.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let content = format!("{n_le_hex}\n{d_le_hex}\n");
    let _ = std::fs::write(&path, content.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hex_roundtrip() {
        assert_eq!(hex_to_bytes("0100ff"), Some(vec![0x01, 0x00, 0xff]));
        assert_eq!(hex_to_bytes(""), None);
        assert_eq!(hex_to_bytes("abc"), None);
    }
    #[test]
    fn cache_key_is_stable() {
        let dir = std::env::temp_dir().join("aac_decoder_test_cache_key_stable");
        let _ = std::fs::create_dir_all(&dir);
        let k1 = cache_key(&dir, "l2.exe");
        let k2 = cache_key(&dir, "l2.exe");
        assert_eq!(k1, k2);
        let _ = std::fs::remove_dir(&dir);
    }
    #[test]
    fn cache_path_is_in_temp() {
        let key = "abcdef1234567890";
        let path = cache_path(key);
        assert!(path.starts_with(std::env::temp_dir()));
        assert_eq!(path.file_name().unwrap().to_string_lossy(), "rsa_abcdef1234567890.bin");
        assert!(!path.to_string_lossy().contains("aa_key_cache"));
        assert!(!path.to_string_lossy().contains("clmods_"));
    }
}
