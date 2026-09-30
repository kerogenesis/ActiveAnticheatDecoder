//! High-level decode helpers: `run.rs` decides what, this decides how.

use std::path::{Path, PathBuf};

use obfstr::obfstr;

use crate::error::Result;
use crate::format::{aac, gamekit, manifest};
use crate::storage::output;

pub fn decrypt_aac_bytes(
    bytes: Vec<u8>,
    profiles: &[aac::RsaProfile],
    auto_decode_gamekit: bool,
) -> Result<(Vec<u8>, bool)> {
    let decrypted = aac::try_decrypt_with_keys(bytes, profiles)?;
    let mut plaintext = decrypted.plaintext;
    let mut gamekit = false;
    if auto_decode_gamekit {
        gamekit = gamekit::patch_to_lineage2(&mut plaintext);
    }
    Ok((plaintext, gamekit))
}

pub fn decrypt_aac_file(
    path: &Path,
    bytes: Vec<u8>,
    profiles: &[aac::RsaProfile],
    root: &Path,
    output_root: &Path,
    auto_decode_gamekit: bool,
) -> Result<(PathBuf, bool)> {
    let (plaintext, gamekit) = decrypt_aac_bytes(bytes, profiles, auto_decode_gamekit)?;
    let destination = output::mirrored_output_path(root, path, output_root);
    output::write_output(&destination, &plaintext)?;
    Ok((destination, gamekit))
}

/// Hash manifest `ft_*` -> RC4 -> manifest text -> write with `_clean.txt` suffix.
pub fn decrypt_hash_manifest_file(
    path: &Path,
    bytes: &[u8],
    root: &Path,
    output_root: &Path,
) -> Result<PathBuf> {
    let text = manifest::decrypt_manifest_text(bytes)?;
    let destination = output::manifest_output_path(root, path, output_root, obfstr!("_clean.txt"));
    output::write_output(&destination, text.as_bytes())?;
    Ok(destination)
}
