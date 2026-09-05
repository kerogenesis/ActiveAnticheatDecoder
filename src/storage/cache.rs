//! File-backed RSA profiles: keyed by SHA1 of clmods.dll (head+tail),
//! tried before live capture; poisoned entries are invalidated and retried.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use obfstr::obfstr;

use crate::crypto::hex::{hex_to_bytes, to_hex};
use crate::format::aac;
use crate::storage::read_prefix;
use sha1::{Digest, Sha1};

fn hash_file(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    if len == 0 {
        return None;
    }
    let mut hasher = Sha1::new();
    hasher.update(len.to_le_bytes());

    let head = read_prefix(path, 512 * 1024)?;
    hasher.update(&head);

    if len > 1024 * 1024 {
        let tail_size = (512 * 1024).min(len as usize);
        if file.seek(SeekFrom::End(-(tail_size as i64))).is_ok() {
            let mut tail = vec![0u8; tail_size];
            let mut filled = 0usize;
            while filled < tail_size {
                match file.read(&mut tail[filled..]) {
                    Ok(0) | Err(_) => break,
                    Ok(m) => filled += m,
                }
            }
            hasher.update(&tail[..filled]);
        }
    }
    let digest = hasher.finalize();
    Some(to_hex(&digest))
}

pub fn cache_key(system_dir: &Path, client_exe: &str) -> String {
    let clmods = system_dir.join(obfstr!("clmods.dll"));
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
        }
        if any {
            let d = hasher.finalize();
            return to_hex(&d);
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
        return to_hex(&d);
    }
    "unknown".to_owned()
}

fn cache_dir() -> std::path::PathBuf {
    std::env::temp_dir().join(obfstr!("AACDecoder"))
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
    aac::RsaProfile::from_le_components(obfstr!("cache"), &n_le, &d_le).ok()
}

pub fn save_cached_profile(system_dir: &Path, client_exe: &str, profile: &aac::RsaProfile) {
    let key = cache_key(system_dir, client_exe);
    let path = cache_path(&key);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let n_le_hex =
        profile.modulus.to_bytes_le().iter().map(|b| format!("{b:02x}")).collect::<String>();
    let d_le_hex = profile
        .private_exponent
        .to_bytes_le()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let content = format!("{n_le_hex}\n{d_le_hex}\n");
    let _ = std::fs::write(&path, content.as_bytes());
}

pub fn invalidate_cache(system_dir: &Path, client_exe: &str) {
    let key = cache_key(system_dir, client_exe);
    let path = cache_path(&key);
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;
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
    #[test]
    fn cached_profile_roundtrips_through_disk() {
        let dir = std::env::temp_dir().join("aac_decoder_test_cache_roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        // Odd modulus (LSB set); small values keep the stored hex short.
        let profile =
            aac::RsaProfile::from_le_components("live", &[0x03, 0x01], &[0x05, 0x02]).unwrap();
        save_cached_profile(&dir, "l2.exe", &profile);
        let loaded = load_cached_profile(&dir, "l2.exe").expect("saved profile must load back");
        assert_eq!(loaded.modulus, profile.modulus);
        assert_eq!(loaded.private_exponent, profile.private_exponent);
        assert_eq!(loaded.source, "cache");
        invalidate_cache(&dir, "l2.exe");
        assert!(load_cached_profile(&dir, "l2.exe").is_none());
        let _ = std::fs::remove_dir(&dir);
    }
}
