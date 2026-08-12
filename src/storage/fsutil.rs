//! Shared filesystem traversal for the client walk and the container scan.

use std::fs::{self, Metadata};
use std::path::{Path, PathBuf};

pub const MAX_DEPTH: usize = 32;

pub struct Entry {
    pub path: PathBuf,
    pub metadata: Metadata,
}

pub fn sorted_entries(directory: &Path) -> Vec<Entry> {
    let Ok(read) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut entries: Vec<Entry> = read
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).ok()?;
            Some(Entry { path, metadata })
        })
        .collect();
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    entries
}
