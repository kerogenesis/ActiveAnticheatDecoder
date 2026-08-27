use obfstr::obfstr;
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::capture::acquire::acquire_profile;
use crate::client::{config, resolve_client_layout};
use crate::error::{Error, IoAction, Result};
use crate::format::{aac, decode as fmt_decode, manifest};
use crate::storage::{output, scan};
use crate::system::term;

const CAPTURE_TIMEOUT: Duration = Duration::from_secs(30);

/// The C++ proxy DLL, embedded at build time (see build.rs).
const PROXY_DLL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/aa_proxy.dll"));

#[derive(Default)]
struct Outcome {
    clean_paths: Vec<PathBuf>,
    failures: Vec<(PathBuf, Error)>,
}

pub fn finish(interactive: bool) {
    if interactive && term::owns_console() {
        term::press_any_key(obfstr!("Press any key to exit . . ."));
    }
}

pub fn banner() {
    term::banner();
}

pub fn run_scan(picked: &Path, interactive: bool) {
    let Some(layout) = resolve_client_layout(picked) else {
        term::field_line("+ Client:", &picked.display().to_string());
        term::error(obfstr!("I can't find the client here: expected system\\l2.exe..."));
        finish(interactive);
        return;
    };

    let root = layout.root.as_std_path();
    let system_dir = layout.system_dir.as_std_path();

    term::field_line("+ Client:", &root.display().to_string());

    let config_path = output::executable_directory().join(obfstr!("config.ini"));
    let candidates = config::proxy_candidates(&config_path);
    let auto_decode_gamekit =
        layout.is_scryde() && config::scryde_gamekitdata_auto_decode(&config_path);

    // cache -> live injection
    let profile = match acquire_profile(
        system_dir,
        &layout.executable,
        &candidates,
        PROXY_DLL,
        CAPTURE_TIMEOUT,
    ) {
        Ok(p) => p,
        Err(error) => {
            term::field_line("+ Status:", &format!("Key capture failed: {error}"));
            finish(interactive);
            return;
        }
    };

    let mut spinner = term::Spinner::new(obfstr!("scanning tree"));
    let result = scan::scan_tree(root, &mut |examined| spinner.tick(examined));
    spinner.finish();

    let targets: Vec<String> =
        result.aac.iter().map(|found| output::relative(&found.path, root)).collect();

    term::field_line(
        "+ Status:",
        &format!("Key captured -> Scanned tree ({} targets found)", targets.len()),
    );

    if targets.is_empty() {
        finish(interactive);
        return;
    }

    let profiles = [profile];
    let output_root = output::output_root();

    println!();
    term::plain_label("Decoding:");

    let completed_counter = AtomicUsize::new(0);
    let outcome_mutex = Mutex::new(Outcome::default());

    result.aac.par_iter().for_each(|found| {
        let source = &found.path;
        let target_rel = output::relative(source, root);

        let decoded = fs::read(source)
            .map_err(|source_err| Error::io(IoAction::Read, source, source_err))
            .and_then(|bytes| {
                fmt_decode::decode_aac_file(
                    source,
                    &bytes,
                    &profiles,
                    root,
                    &output_root,
                    auto_decode_gamekit,
                )
            });

        let current_step = completed_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let is_ok = decoded.is_ok();
        let err_str = decoded.as_ref().err().map(|e| e.to_string());

        term::step_result(current_step, result.aac.len(), &target_rel, is_ok, err_str.as_deref());

        let mut outcome_guard = outcome_mutex.lock().unwrap_or_else(|e| e.into_inner());
        match decoded {
            Ok(destination) => outcome_guard.clean_paths.push(destination),
            Err(error) => outcome_guard.failures.push((source.to_path_buf(), error)),
        }
    });

    let outcome = outcome_mutex.into_inner().unwrap_or_else(|e| e.into_inner());

    println!();
    term::plain_line(
        "Result:",
        &format!("{} succeeded, {} failed", outcome.clean_paths.len(), outcome.failures.len()),
    );
    term::plain_line("Clean files:", &output_root.display().to_string());

    if !outcome.failures.is_empty() {
        println!();
        term::error(&format!("{} {}", obfstr!("Failed files:"), outcome.failures.len()));
        for (path, reason) in &outcome.failures {
            println!("    {}", path.display());
            println!("      {reason}");
        }
    }

    finish(interactive);
}

fn decode_dropped_file(path: &Path, name: &str, output_root: &Path) -> Result<PathBuf> {
    let bytes = fs::read(path).map_err(|source| Error::io(IoAction::Read, path, source))?;
    let root = path.parent().unwrap_or(Path::new(""));

    if manifest::is_hash_manifest_name(name) {
        return fmt_decode::decode_hash_manifest_file(path, &bytes, root, output_root);
    }

    if aac::is_aac_container(&bytes) {
        return Err(Error::DroppedAacNeedsClient);
    }

    Err(Error::DroppedUnknownFormat)
}

pub fn run_dropped_files(paths: &[PathBuf]) {
    let output_root = output::output_root();
    let outcome_mutex = Mutex::new(Outcome::default());
    let completed_counter = AtomicUsize::new(0);

    term::field_line("+ Files:", &format!("{} dropped files", paths.len()));
    println!();
    term::plain_label("Decoding:");

    paths.par_iter().for_each(|path| {
        let name =
            path.file_name().map(|value| value.to_string_lossy().into_owned()).unwrap_or_default();

        let decoded = decode_dropped_file(path, &name, &output_root);

        let current_step = completed_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let is_ok = decoded.is_ok();
        let err_str = decoded.as_ref().err().map(|e| e.to_string());

        term::step_result(current_step, paths.len(), &name, is_ok, err_str.as_deref());

        let mut outcome_guard = outcome_mutex.lock().unwrap_or_else(|e| e.into_inner());
        match decoded {
            Ok(destination) => outcome_guard.clean_paths.push(destination),
            Err(error) => outcome_guard.failures.push((path.to_path_buf(), error)),
        }
    });

    let outcome = outcome_mutex.into_inner().unwrap_or_else(|e| e.into_inner());

    println!();
    term::plain_line(
        "Result:",
        &format!("{} succeeded, {} failed", outcome.clean_paths.len(), outcome.failures.len()),
    );
    term::plain_line("Clean files:", &output_root.display().to_string());

    if !outcome.failures.is_empty() {
        println!();
        term::error(&format!("{} {}", obfstr!("Failed files:"), outcome.failures.len()));
        for (path, reason) in &outcome.failures {
            println!("    {}", path.display());
            println!("      {reason}");
        }
    }

    finish(true);
}

pub fn run_hash_manifest_files(paths: &[PathBuf]) {
    let destination_root = output::executable_directory();
    let failures_mutex = Mutex::new(Vec::new());
    let suffix = obfstr!("_clean.txt").to_owned();

    paths.par_iter().for_each(|path| {
        let destination = destination_root.join(output::hash_manifest_name(path, &suffix));

        let decoded = fs::read(path)
            .map_err(|source| Error::io(IoAction::Read, path, source))
            .and_then(|bytes| manifest::decode(&bytes))
            .and_then(|text| output::write_output(&destination, text.as_bytes()));

        if let Err(error) = decoded {
            let mut failures_guard = failures_mutex.lock().unwrap_or_else(|e| e.into_inner());
            failures_guard.push((path.clone(), error));
        }
    });

    let failures = failures_mutex.into_inner().unwrap_or_else(|e| e.into_inner());

    if failures.is_empty() {
        return;
    }

    term::ensure_console();
    banner();
    term::error(&format!("{} {}", obfstr!("Failed files:"), failures.len()));
    for (path, reason) in &failures {
        println!("    {}", path.display());
        println!("      {reason}");
    }
    finish(true);
}
