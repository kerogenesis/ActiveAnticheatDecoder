pub mod cache;
pub mod output;
pub mod scan;

use std::path::Path;

pub use output::{
    executable_directory, hash_manifest_name, is_hash_manifest_path, mirrored_path,
    output_path_for, output_root, relative, write_output,
};
pub use scan::{Found, ScanResult, scan_tree};

/// Open path and read up to count leading bytes (fewer at EOF).
pub(crate) fn read_prefix(path: &Path, count: usize) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path).ok()?;
    let mut buffer = vec![0u8; count];
    let mut filled = 0;
    while filled < count {
        match file.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(_) => return None,
        }
    }
    buffer.truncate(filled);
    Some(buffer)
}
