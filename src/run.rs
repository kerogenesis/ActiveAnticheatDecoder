use obfstr::obfstr;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::mpsc::channel;
use std::time::Duration;

use crate::capture::acquire::{KeyOrigin, load_or_capture_key};
use crate::client::{config, resolve_from_client_dir};
use crate::error::{Error, IoAction, Result};
use crate::format::{aac, manifest, pipeline};
use crate::storage::{cache, output, scan};
use crate::system::term;

const CAPTURE_TIMEOUT: Duration = Duration::from_secs(60);

/// The proxy DLL, embedded at build time (see `build.rs`).
const PROXY_DLL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/aa_proxy.dll"));

#[derive(Default)]
struct BatchResult {
    decrypted_paths: Vec<PathBuf>,
    failures: Vec<(PathBuf, Error)>,
}

type DecryptOutcome = (PathBuf, String, Result<(PathBuf, bool)>);
type OrderedOutcome<T> = (usize, T);
type DroppedOutcome = (PathBuf, String, Result<PathBuf>);

fn drain_ordered<T>(
    count: usize,
    rx: &std::sync::mpsc::Receiver<(usize, T)>,
    mut emit_in_order: impl FnMut(usize, usize, T),
) {
    let mut pending: BTreeMap<usize, T> = BTreeMap::new();
    let mut next = 0usize;
    while next < count {
        let Ok((idx, item)) = rx.recv() else {
            break;
        };
        pending.insert(idx, item);
        while let Some(item) = pending.remove(&next) {
            emit_in_order(next + 1, count, item);
            next += 1;
        }
    }
}

fn file_name_fallback(path: &Path) -> String {
    path.file_name()
        .map(|file_name| file_name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn report_outcome(outcome: &BatchResult, output_root: &Path) {
    println!();
    let total = outcome.decrypted_paths.len() + outcome.failures.len();
    if total == 1 {
        if outcome.failures.is_empty() {
            let name = file_name_fallback(&outcome.decrypted_paths[0]);
            term::result_line(obfstr!("Result:"), &format!("{name} decrypted"));
        } else {
            let name = file_name_fallback(&outcome.failures[0].0);
            let msg = if outcome.failures[0].1.is_key_mismatch() {
                format!("{name} failed ({})", failure_detail(outcome))
            } else {
                format!("{name} failed")
            };
            term::result_line(obfstr!("Result:"), &msg);
        }
    } else if total == 2 && outcome.decrypted_paths.len() == 1 && outcome.failures.len() == 1 {
        let ok_name = file_name_fallback(&outcome.decrypted_paths[0]);
        let fail_name = file_name_fallback(&outcome.failures[0].0);
        let msg = if outcome.failures[0].1.is_key_mismatch() {
            format!("{ok_name} decrypted, {fail_name} failed ({})", failure_detail(outcome))
        } else {
            format!("{ok_name} decrypted, {fail_name} failed")
        };
        term::result_line(obfstr!("Result:"), &msg);
    } else if outcome.failures.is_empty() {
        let decrypted_count = outcome.decrypted_paths.len();
        let msg = if decrypted_count == 1 {
            obfstr!("all 1 file decrypted").to_owned()
        } else {
            format!("all {decrypted_count} files decrypted")
        };
        term::result_line(obfstr!("Result:"), &msg);
    } else if outcome.decrypted_paths.is_empty() {
        term::result_line(
            obfstr!("Result:"),
            &format!(
                "0 decrypted, {} failed ({})",
                outcome.failures.len(),
                failure_detail(outcome)
            ),
        );
    } else {
        term::result_line(
            obfstr!("Result:"),
            &format!(
                "{} decrypted, {} failed ({})",
                outcome.decrypted_paths.len(),
                outcome.failures.len(),
                failure_detail(outcome),
            ),
        );
    }
    if !outcome.decrypted_paths.is_empty() {
        term::result_line(obfstr!("Clean files:"), &output_root.display().to_string());
    }
}

fn failure_detail(outcome: &BatchResult) -> String {
    let mut key_files = Vec::new();
    let mut other_files = Vec::new();
    for (path, error) in &outcome.failures {
        if error.is_key_mismatch() {
            key_files.push(file_name_fallback(path));
        } else {
            other_files.push(file_name_fallback(path));
        }
    }
    let mut parts = Vec::new();
    if !key_files.is_empty() {
        parts.push(format!(
            "looks like we're missing the right key in memory for these files: {}",
            key_files.join(", ")
        ));
    }
    if !other_files.is_empty() {
        parts.push(other_files.join(", "));
    }
    parts.join("; ")
}

/// Parallel decrypt of every found container with one profile.
fn decrypt_all_containers(
    files: &[scan::FoundContainer],
    rsa_profile: &aac::RsaProfile,
    root: &Path,
    output_root: &Path,
    auto_decode_gamekit: bool,
) -> BatchResult {
    let (tx, rx) = channel::<OrderedOutcome<DecryptOutcome>>();
    std::thread::scope(|s| {
        s.spawn(|| {
            files.par_iter().enumerate().for_each(|(idx, found)| {
                let source = &found.path;
                let relative_path = output::relative_display(source, root);
                let decoded = fs::read(source)
                    .map_err(|source_err| Error::io(IoAction::Read, source, source_err))
                    .and_then(|bytes| {
                        pipeline::decrypt_aac_file(
                            source,
                            bytes,
                            std::slice::from_ref(rsa_profile),
                            root,
                            output_root,
                            auto_decode_gamekit,
                        )
                    });
                let _ = tx.send((idx, (source.to_path_buf(), relative_path, decoded)));
            });
        });

        let mut outcome = BatchResult::default();
        drain_ordered(
            files.len(),
            &rx,
            |position, total, (source, relative_path, decoded): DecryptOutcome| {
                let (succeeded, label, err_str) = match &decoded {
                    Ok((_, gamekit)) => {
                        let label = if *gamekit {
                            format!("{} {relative_path}", term::gamekit_tag())
                        } else {
                            relative_path.clone()
                        };
                        (true, label, None)
                    }
                    Err(error) => {
                        let reason = (!error.is_key_mismatch()).then(|| error.to_string());
                        (false, relative_path.clone(), reason)
                    }
                };
                term::print_indexed_result(position, total, &label, succeeded, err_str.as_deref());
                match decoded {
                    Ok((destination, _)) => outcome.decrypted_paths.push(destination),
                    Err(error) => outcome.failures.push((source, error)),
                }
            },
        );
        outcome
    })
}

fn cached_key_failed_all(outcome: &BatchResult, source: KeyOrigin) -> bool {
    source == KeyOrigin::Cached
        && outcome.decrypted_paths.is_empty()
        && !outcome.failures.is_empty()
        && outcome.failures.iter().all(|(_, e)| matches!(e, Error::DecodeAttemptsFailed { .. }))
}

pub fn wait_before_exit(interactive: bool) {
    if interactive && term::owns_console() {
        term::press_any_key(obfstr!("Press any key to exit . . ."));
    }
}

pub fn banner() {
    term::banner();
}

pub fn run_scan(picked: &Path, interactive: bool) {
    let Some(layout) = resolve_from_client_dir(picked) else {
        term::status_line(obfstr!("+ Client:"), &picked.display().to_string());
        term::error_line(obfstr!("I can't find the client here: expected system\\l2.exe..."));
        wait_before_exit(interactive);
        return;
    };

    let root = layout.client_dir.as_std_path();
    let system_dir = layout.system_dir.as_std_path();

    term::status_line(obfstr!("+ Client:"), &root.display().to_string());

    let config_path = output::executable_directory().join(obfstr!("config.ini"));
    let proxy_dll_names = config::proxy_candidates(&config_path);
    let auto_decode_gamekit =
        layout.is_scryde() && config::scryde_gamekitdata_auto_decode(&config_path);

    let mut acquired = match load_or_capture_key(
        system_dir,
        &layout.exe_name,
        &proxy_dll_names,
        PROXY_DLL,
        CAPTURE_TIMEOUT,
    ) {
        Ok(captured_key) => captured_key,
        Err(error) => {
            if error.is_elevation_required() {
                term::status_line(
                    obfstr!("+ Status:"),
                    obfstr!("run the program as administrator"),
                );
                crate::system::elevation::show_elevation_required();
            } else {
                term::status_line(obfstr!("+ Status:"), &format!("Key capture failed: {error}"));
            }
            wait_before_exit(interactive);
            return;
        }
    };
    match acquired.source {
        KeyOrigin::Cached => term::status_line(obfstr!("+ Key:"), obfstr!("from cache")),
        KeyOrigin::Captured => {
            term::status_line(obfstr!("+ Key:"), obfstr!("captured live, cached for next run"))
        }
    }

    let mut spinner = term::Spinner::new(obfstr!("scanning tree"));
    let result = scan::scan_tree(root, &mut |examined| spinner.tick_files(examined));
    spinner.finish();
    for error in &result.walk_errors {
        term::error_line(&format!("{} {error}", obfstr!("scan walk error:")));
    }

    let status =
        format!("scanned {} files ({} targets found)", result.files_examined, result.aac.len());
    term::status_line(obfstr!("+ Status:"), &status);

    if result.aac.is_empty() {
        wait_before_exit(interactive);
        return;
    }

    let output_root = output::new_run_output_dir();

    let mut outcome = decrypt_all_containers(
        &result.aac,
        &acquired.rsa_profile,
        root,
        &output_root,
        auto_decode_gamekit,
    );

    if cached_key_failed_all(&outcome, acquired.source) {
        term::error_line(obfstr!("Cached key failed for all files — retrying live capture..."));
        cache::invalidate_cache(system_dir, &layout.exe_name);
        if let Ok(live) = load_or_capture_key(
            system_dir,
            &layout.exe_name,
            &proxy_dll_names,
            PROXY_DLL,
            CAPTURE_TIMEOUT,
        ) {
            match live.source {
                KeyOrigin::Cached => {
                    term::status_line(obfstr!("+ Key:"), obfstr!("from cache (retry)"))
                }
                KeyOrigin::Captured => {
                    term::status_line(obfstr!("+ Key:"), obfstr!("captured live (retry)"))
                }
            }
            acquired = live;
            println!();
            term::section_title(obfstr!("Retrying decoding with live key:"));
            outcome = decrypt_all_containers(
                &result.aac,
                &acquired.rsa_profile,
                root,
                &output_root,
                auto_decode_gamekit,
            );
        }
    }

    report_outcome(&outcome, &output_root);
    wait_before_exit(interactive);
}

fn decode_dropped_file(path: &Path, name: &str, output_root: &Path) -> Result<PathBuf> {
    let bytes = fs::read(path).map_err(|source| Error::io(IoAction::Read, path, source))?;
    let root = path.parent().unwrap_or(Path::new(""));

    if manifest::is_hash_manifest_name(name) {
        return pipeline::decrypt_hash_manifest_file(path, &bytes, root, output_root);
    }

    if aac::is_aac_container(&bytes) {
        return Err(Error::DroppedAacNeedsClient);
    }

    Err(Error::NotAacContainer)
}

pub fn run_dropped_files(paths: &[PathBuf]) {
    let output_root = output::new_run_output_dir();

    term::status_line(obfstr!("+ Files:"), &format!("{} dropped files", paths.len()));
    println!();
    term::section_title(obfstr!("Decoding:"));

    let (tx, rx) = channel::<OrderedOutcome<DroppedOutcome>>();
    let outcome = std::thread::scope(|s| {
        s.spawn(|| {
            paths.par_iter().enumerate().for_each(|(idx, path)| {
                let name = path
                    .file_name()
                    .map(|value| value.to_string_lossy().into_owned())
                    .unwrap_or_default();

                let decoded = decode_dropped_file(path, &name, &output_root);

                let _ = tx.send((idx, (path.to_path_buf(), name, decoded)));
            });
        });

        let mut outcome = BatchResult::default();
        drain_ordered(
            paths.len(),
            &rx,
            |position, total, (path, name, decoded): DroppedOutcome| {
                let succeeded = decoded.is_ok();
                let err_str = decoded.as_ref().err().map(|error| error.to_string());
                term::print_indexed_result(position, total, &name, succeeded, err_str.as_deref());
                match decoded {
                    Ok(destination) => outcome.decrypted_paths.push(destination),
                    Err(error) => outcome.failures.push((path, error)),
                }
            },
        );
        outcome
    });

    report_outcome(&outcome, &output_root);
    wait_before_exit(true);
}

pub fn run_hash_manifest_files(paths: &[PathBuf]) {
    let destination_root = output::executable_directory();
    let failures_mutex = Mutex::new(Vec::new());
    let suffix = obfstr!("_clean.txt").to_owned();

    paths.par_iter().for_each(|path| {
        let destination = destination_root.join(output::hash_manifest_name(path, &suffix));

        let decoded = fs::read(path)
            .map_err(|source| Error::io(IoAction::Read, path, source))
            .and_then(|bytes| manifest::decrypt_manifest_text(&bytes))
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
    term::error_line(&format!("{} {}", obfstr!("Failed files:"), failures.len()));
    for (path, reason) in &failures {
        println!("    {}", path.display());
        println!("      {reason}");
    }
    wait_before_exit(true);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PerKeyFailure;

    fn key_mismatch_failure(name: &str) -> (PathBuf, Error) {
        (
            PathBuf::from(name),
            Error::DecodeAttemptsFailed {
                failures: vec![PerKeyFailure {
                    key_origin: "cache".to_owned(),
                    error: Error::Pkcs1PaddingInvalid,
                }],
            },
        )
    }

    fn batch_with_failures(failures: Vec<(PathBuf, Error)>) -> BatchResult {
        BatchResult { decrypted_paths: Vec::new(), failures }
    }

    #[test]
    fn detail_explains_key_mismatch_only() {
        let detail =
            failure_detail(&batch_with_failures(vec![key_mismatch_failure("a/Service.u")]));
        assert_eq!(
            detail,
            "looks like we're missing the right key in memory for these files: Service.u"
        );
    }

    #[test]
    fn detail_splits_mixed_failures() {
        let detail = failure_detail(&batch_with_failures(vec![
            key_mismatch_failure("Service.u"),
            (PathBuf::from("Maps/x.unr"), Error::NotAacContainer),
        ]));
        assert!(detail.starts_with("looks like we're missing the right key"), "{detail}");
        assert!(detail.contains("Service.u"), "{detail}");
        assert!(detail.contains("x.unr"), "{detail}");
    }

    #[test]
    fn detail_keeps_plain_names_without_key_mismatch() {
        let detail = failure_detail(&batch_with_failures(vec![(
            PathBuf::from("Maps/x.unr"),
            Error::NotAacContainer,
        )]));
        assert_eq!(detail, "x.unr");
    }
}
