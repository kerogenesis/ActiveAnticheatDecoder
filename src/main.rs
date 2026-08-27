//! Decryptor for ActiveAnticheatCrypt files.

#![cfg_attr(not(test), windows_subsystem = "windows")]

use obfstr::obfstr;
use std::env;
use std::path::PathBuf;

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
    let silent_legacy_drop = !files.is_empty()
        && directories.is_empty()
        && missing.is_empty()
        && files.iter().all(|path| output::is_legacy_path(path));
    if silent_legacy_drop {
        run::run_silent_legacy_files(&files);
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
    for directory in &directories {
        run::run_scan(directory, true);
    }
}
