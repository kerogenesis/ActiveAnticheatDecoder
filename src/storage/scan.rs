//! Recursive discovery of ActiveAnticheatCrypt containers under a client root.
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::format::aac;

#[derive(Debug, Clone)]
pub struct Found {
    pub path: PathBuf,
}

#[derive(Debug, Default)]
pub struct ScanResult {
    pub aac: Vec<Found>,
    pub files_examined: usize,
}

fn read_header(path: &Path, count: usize) -> Option<Vec<u8>> {
    let mut file = File::open(path).ok()?;
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

pub fn scan_tree(root: &Path, on_progress: &mut dyn FnMut(usize)) -> ScanResult {
    let mut result = ScanResult::default();

    for entry in WalkDir::new(root).max_depth(32).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            result.files_examined += 1;
            let path = entry.path();
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);

            if size > aac::PAYLOAD_OFFSET as u64
                && let Some(header) = read_header(path, 20)
                && aac::header_is_aac(&header)
            {
                result.aac.push(Found { path: path.to_path_buf() });
            }
            on_progress(result.files_examined);
        }
    }

    result
}
