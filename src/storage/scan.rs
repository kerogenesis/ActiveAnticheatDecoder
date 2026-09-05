//! Recursive discovery of ActiveAnticheatCrypt containers under a client root.
use crate::format::aac;
use crate::storage::read_prefix;
use rayon::prelude::*;
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
    pub walk_errors: Vec<String>,
}

pub fn scan_tree(root: &Path, on_progress: &mut dyn FnMut(usize)) -> ScanResult {
    let mut all_files: Vec<(PathBuf, u64)> = Vec::new();
    let mut files_examined = 0usize;
    let mut walk_errors = Vec::new();
    for entry in WalkDir::new(root)
        .max_depth(32)
        .follow_links(false)
        .into_iter()
        .filter_map(|r| r.map_err(|e| walk_errors.push(e.to_string())).ok())
    {
        if entry.file_type().is_file() {
            files_examined += 1;
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            all_files.push((entry.path().to_path_buf(), size));
            on_progress(files_examined);
        }
    }

    // parallel header check
    let aac: Vec<Found> = all_files
        .par_iter()
        .filter_map(|(path, size)| {
            if *size <= aac::PAYLOAD_OFFSET as u64 {
                return None;
            }
            let header = read_prefix(path, 20)?;
            if aac::header_is_aac(&header) { Some(Found { path: path.clone() }) } else { None }
        })
        .collect();

    ScanResult { aac, files_examined, walk_errors }
}
