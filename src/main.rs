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
    let CliPaths { directories, dropped_files, missing_paths } = split_cli_paths(arguments);
    let hash_manifest_drop = !dropped_files.is_empty()
        && directories.is_empty()
        && missing_paths.is_empty()
        && dropped_files.iter().all(|path| output::is_hash_manifest_path(path));
    if hash_manifest_drop {
        run::run_hash_manifest_files(&dropped_files);
        return;
    }
    term::ensure_console();
    run::banner();
    for path in &missing_paths {
        term::error_line(&format!("{} {}", obfstr!("path not found:"), path.display()));
    }
    if !dropped_files.is_empty() {
        run::run_dropped_files(&dropped_files);
    }

    let mut seen_roots: HashSet<String> = HashSet::new();
    for directory in &directories {
        let Some(layout) = resolve_client_layout_with_ancestors(directory) else {
            term::error_line(&format!(
                "{} {}",
                obfstr!("not a client folder:"),
                directory.display()
            ));
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
    dropped_files: Vec<PathBuf>,
    missing_paths: Vec<PathBuf>,
}

fn split_cli_paths(arguments: Vec<PathBuf>) -> CliPaths {
    let mut paths = CliPaths::default();
    for path in arguments {
        if path.is_dir() {
            paths.directories.push(path);
        } else if path.is_file() {
            paths.dropped_files.push(path);
        } else {
            paths.missing_paths.push(path);
        }
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_dirs_dropped_and_missing() {
        let dir = std::env::temp_dir().join("aac-decoder-cli-split-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).expect("scratch dir");
        std::fs::write(dir.join("sub").join("f.dat"), b"x").expect("scratch file");
        let missing = dir.join("nope");
        let split =
            split_cli_paths(vec![dir.join("sub"), dir.join("sub").join("f.dat"), missing.clone()]);
        assert_eq!(split.directories, vec![dir.join("sub")]);
        assert_eq!(split.dropped_files, vec![dir.join("sub").join("f.dat")]);
        assert_eq!(split.missing_paths, vec![missing]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
