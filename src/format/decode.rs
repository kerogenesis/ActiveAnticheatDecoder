//! High-level decode helpers used by run.rs.
//! Extracted from orchestrator — run decides what to do, format::decode decides how.

use std::path::{Path, PathBuf};

use obfstr::obfstr;

use crate::error::Result;
use crate::format::{aac, gamekit, manifest};
use crate::storage::output;

/// AAC -> RC4 -> optional Gamekit to Lineage2Ver -> write to mirrored path.
/// Returns the destination plus whether Gamekit conversion applied.
pub fn decode_aac_file(
    path: &Path,
    bytes: &[u8],
    profiles: &[aac::RsaProfile],
    root: &Path,
    output_root: &Path,
    auto_decode_gamekit: bool,
) -> Result<(PathBuf, bool)> {
    let decoded = aac::decode_any(bytes, profiles)?;
    let destination = output::mirrored_path(root, path, output_root);
    let mut plaintext = decoded.plaintext;
    let mut gamekit = false;
    if auto_decode_gamekit {
        gamekit = gamekit::patch_to_lineage2(&mut plaintext);
    }
    output::write_output(&destination, &plaintext)?;
    Ok((destination, gamekit))
}

/// Hash manifest ft_* -> RC4 -> manifest text -> write with _clean.txt suffix.
pub fn decode_hash_manifest_file(
    path: &Path,
    bytes: &[u8],
    root: &Path,
    output_root: &Path,
) -> Result<PathBuf> {
    let text = manifest::decode(bytes)?;
    let destination = output::output_path_for(root, path, output_root, obfstr!("_clean.txt"));
    output::write_output(&destination, text.as_bytes())?;
    Ok(destination)
}
