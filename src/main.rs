//! Decryptor for ActiveAnticheatCrypt files.

#![cfg_attr(not(test), windows_subsystem = "windows")]

use obfstr::obfstr;
use std::env;
use std::path::PathBuf;

use std::collections::HashSet;

use decoder::client::resolve_client_layout_with_ancestors;
use decoder::run;
use decoder::storage::output;
use decoder::system::{term, ui};

fn main() {
    let arguments: Vec<PathBuf> = env::args().skip(1).map(PathBuf::from).collect();
    if arguments.is_empty() {
        let Some(root) = ui::choose_client_root() else {
            return;
        };
        term::ensure_console();
        run::banner();
        if root.is_dir() {
            run::run_scan(&root, true);
        } else {
            term::error(&format!("{} {}", obfstr!("not a folder:"), root.display()));
            run::finish(true);
        }
        return;
    }
    let mut directories = Vec::new();
    let mut files = Vec::new();
    let mut missing = Vec::new();
    for path in arguments {
        if path.is_dir() {
            directories.push(path);
        } else if path.is_file() {
            files.push(path);
        } else {
            missing.push(path);
        }
    }
    let hash_manifest_drop = !files.is_empty()
        && directories.is_empty()
        && missing.is_empty()
        && files.iter().all(|path| output::is_hash_manifest_path(path));
    if hash_manifest_drop {
        run::run_hash_manifest_files(&files);
        return;
    }
    term::ensure_console();
    run::banner();
    for path in &missing {
        term::error(&format!("{} {}", obfstr!("path not found:"), path.display()));
    }
    if !files.is_empty() {
        run::run_dropped_files(&files);
    }

    let mut seen_roots: HashSet<String> = HashSet::new();
    for directory in &directories {
        let Some(layout) = resolve_client_layout_with_ancestors(directory) else {
            term::error(&format!("{} {}", obfstr!("not a client folder:"), directory.display()));
            continue;
        };
        // Windows paths are case-insensitive,
        // so normalize before dedup to avoid scanning
        // and capturing the key for one client twice.
        let key = normalize_root_key(layout.root.as_str());
        if seen_roots.insert(key) {
            run::run_scan(layout.root.as_std_path(), true);
        }
    }
}

/// Lowercase, slash-normalized root key for dedup on Windows.
fn normalize_root_key(root: &str) -> String {
    root.replace('/', "\\").trim_end_matches('\\').to_lowercase()
}
