//! Recursive discovery of ActiveAnticheatCrypt containers under a client root.
use crate::format::aac;
use rayon::prelude::*;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

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
    let mut all_files: Vec<PathBuf> = Vec::new();
    let mut files_examined = 0usize;
    for entry in WalkDir::new(root)
        .max_depth(32)
        .follow_links(false)
        .into_iter()
        .filter_map(|r| r.map_err(|e| eprintln!("scan: walk error: {e}")).ok())
    {
        if entry.file_type().is_file() {
            files_examined += 1;
            all_files.push(entry.path().to_path_buf());
            on_progress(files_examined);
        }
    }

    // parallel header check
    let aac: Vec<Found> = all_files
        .par_iter()
        .filter_map(|path| {
            let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            if size <= aac::PAYLOAD_OFFSET as u64 {
                return None;
            }
            let header = read_header(path, 20)?;
            if aac::header_is_aac(&header) { Some(Found { path: path.clone() }) } else { None }
        })
        .collect();

    ScanResult { aac, files_examined }
}
