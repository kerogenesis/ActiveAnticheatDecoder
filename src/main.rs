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
            term::error_line(&format!("{} {}", obfstr!("not a folder:"), root.display()));
            run::wait_before_exit(true);
        }
        return;
    }
    let CliPaths { directories, files, missing } = split_cli_paths(arguments);
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
        term::error_line(&format!("{} {}", obfstr!("path not found:"), path.display()));
    }
    if !files.is_empty() {
        run::run_dropped_files(&files);
    }

    let mut seen_roots: HashSet<String> = HashSet::new();
    for directory in &directories {
        let Some(layout) = resolve_client_layout_with_ancestors(directory) else {
            term::error_line(&format!("{} {}", obfstr!("not a client folder:"), directory.display()));
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

#[derive(Default)]
struct CliPaths {
    directories: Vec<PathBuf>,
    files: Vec<PathBuf>,
    missing: Vec<PathBuf>,
}

fn split_cli_paths(arguments: Vec<PathBuf>) -> CliPaths {
    let mut paths = CliPaths::default();
    for path in arguments {
        if path.is_dir() {
            paths.directories.push(path);
        } else if path.is_file() {
            paths.files.push(path);
        } else {
            paths.missing.push(path);
        }
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_dirs_files_and_missing() {
        let dir = std::env::temp_dir().join("aac-decoder-cli-split-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).expect("scratch dir");
        std::fs::write(dir.join("sub").join("f.dat"), b"x").expect("scratch file");
        let missing = dir.join("nope");
        let split = split_cli_paths(vec![
            dir.join("sub"),
            dir.join("sub").join("f.dat"),
            missing.clone(),
        ]);
        assert_eq!(split.directories, vec![dir.join("sub")]);
        assert_eq!(split.files, vec![dir.join("sub").join("f.dat")]);
        assert_eq!(split.missing, vec![missing]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
