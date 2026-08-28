//! Embed the C++ proxy DLL and the application icon into the executable.
//! The proxy is built separately with MSVC in CI, which points us at the
//! result through `AA_PROXY_DLL`; we copy those bytes into `OUT_DIR` so
//! `main.rs` can `include_bytes!` them. When the variable is unset -- a plain
//! local build without the C++ toolchain -- an empty placeholder is embedded so
//! the binary still links; it simply reports that no proxy was embedded if key
//! capture is attempted.
//!
//! The icon is compiled with `rc.exe`, which ships with the Windows SDK and is
//! only on PATH inside a Developer Command Prompt. Relying on PATH silently
//! lost the icon in CI: the proxy action calls `vcvars32.bat` inside its own
//! step, those variables never reach the later `cargo build` step, and `rustc`
//! finds `link.exe` through its own lookup, so the build kept linking without
//! the resource. We therefore look `rc.exe` up ourselves -- `AA_RC_EXE`, then
//! PATH, then the installed Windows Kits -- and set `AA_REQUIRE_ICON` in the
//! release workflow so a failure there stops the build instead of printing a
//! warning nobody reads. Without that variable a missing icon or `rc.exe` is
//! still skipped, which keeps check-only jobs and bare local builds working.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn main() {
    println!("cargo:rerun-if-changed=proxy/aa_proxy.cpp");
    println!("cargo:rerun-if-changed=proxy/vendor/UltimateProxyDLL.h");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is always set by cargo"));
    stage_proxy_dll(&out_dir);
    #[cfg(windows)]
    embed_windows_icon(&out_dir);
}

fn stage_proxy_dll(out_dir: &Path) {
    let destination = out_dir.join("aa_proxy.dll");
    println!("cargo:rerun-if-env-changed=AA_PROXY_DLL");
    match env::var_os("AA_PROXY_DLL") {
        Some(path) => {
            let path = PathBuf::from(path);
            println!("cargo:rerun-if-changed={}", path.display());
            let bytes = fs::read(&path)
                .unwrap_or_else(|error| panic!("cannot read AA_PROXY_DLL at {path:?}: {error}"));
            fs::write(&destination, bytes).expect("cannot stage the embedded proxy DLL");
        }
        None => {
            fs::write(&destination, []).expect("cannot stage the empty proxy placeholder");
        }
    }
}

#[cfg(windows)]
fn embed_windows_icon(out_dir: &Path) {
    const ICON: &str = "res/app.ico";
    println!("cargo:rerun-if-changed={ICON}");
    println!("cargo:rerun-if-changed=build.rs");
    // Whether the icon can be embedded depends on the environment, not only on
    // the tracked files, so a cached run that skipped the icon must not survive
    // a fixed environment.
    println!("cargo:rerun-if-env-changed=PATH");
    println!("cargo:rerun-if-env-changed=AA_RC_EXE");
    println!("cargo:rerun-if-env-changed=AA_REQUIRE_ICON");

    let required = icon_is_required();
    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set by cargo"),
    );
    let icon_path = manifest_dir.join(ICON);
    if !icon_path.is_file() {
        report_icon_failure(required, &format!("{ICON} not found"));
        return;
    }

    let compiler = match find_resource_compiler() {
        Some(compiler) => compiler,
        None => {
            report_icon_failure(
                required,
                "cannot find rc.exe: install the Windows SDK, build from a Developer Command \
                 Prompt, or point AA_RC_EXE at it",
            );
            return;
        }
    };

    // Resource 1 is the lowest id,
    // which is the icon Explorer shows for the application.
    let icon_ref = icon_path.display().to_string().replace('\\', "/");
    let script = out_dir.join("app.rc");
    fs::write(&script, format!("1 ICON \"{icon_ref}\"\n")).expect("cannot write the icon script");

    let resource = out_dir.join("app.res");
    let status =
        Command::new(&compiler).arg("/nologo").arg("/fo").arg(&resource).arg(&script).status();

    match status {
        Ok(code) if code.success() => {
            println!("cargo:rustc-link-arg-bin=decoder={}", resource.display());
        }
        Ok(code) => {
            let reason = format!("{} exited with {code}", compiler.display());
            report_icon_failure(required, &reason);
        }
        Err(error) => {
            let reason = format!("cannot run {} ({error})", compiler.display());
            report_icon_failure(required, &reason);
        }
    }
}

/// Release builds must ship the icon, so they set `AA_REQUIRE_ICON`
/// to turn a skipped icon into a build failure.
#[cfg(windows)]
fn icon_is_required() -> bool {
    match env::var("AA_REQUIRE_ICON") {
        Ok(value) => !value.is_empty() && value != "0",
        Err(_) => false,
    }
}

#[cfg(windows)]
fn report_icon_failure(required: bool, reason: &str) {
    if required {
        panic!("cannot embed the application icon: {reason}");
    }
    println!("cargo:warning=skipping icon: {reason}");
}

#[cfg(windows)]
fn find_resource_compiler() -> Option<PathBuf> {
    if let Some(explicit) = env::var_os("AA_RC_EXE") {
        return Some(PathBuf::from(explicit));
    }

    let on_path = Command::new("rc.exe")
        .arg("/?")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if on_path.is_ok() {
        return Some(PathBuf::from("rc.exe"));
    }

    newest_sdk_resource_compiler()
}

#[cfg(windows)]
fn newest_sdk_resource_compiler() -> Option<PathBuf> {
    let host = match env::consts::ARCH {
        "x86" => "x86",
        "aarch64" => "arm64",
        _ => "x64",
    };

    let mut roots: Vec<PathBuf> = Vec::new();
    for variable in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Some(program_files) = env::var_os(variable) {
            let root = PathBuf::from(program_files).join("Windows Kits").join("10").join("bin");
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
    }

    let mut candidates: Vec<(Vec<u64>, PathBuf)> = Vec::new();
    for root in &roots {
        let entries = match fs::read_dir(root) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            // The versioned layout is <kit>\bin\<sdk version>\<host arch>\rc.exe.
            let name = entry.file_name();
            let version = match sdk_version_key(&name.to_string_lossy()) {
                Some(version) => version,
                None => continue,
            };
            let compiler = entry.path().join(host).join("rc.exe");
            if compiler.is_file() {
                candidates.push((version, compiler));
            }
        }

        // Kits older than the versioned layout keep rc.exe directly in bin.
        let legacy = root.join("rc.exe");
        if legacy.is_file() {
            candidates.push((vec![0], legacy));
        }
    }

    candidates.sort();
    candidates.pop().map(|(_, compiler)| compiler)
}

/// Parses `10.0.22621.0` into a comparable key, rejecting anything that is not a
/// dotted version so unrelated directories are ignored.
#[cfg(windows)]
fn sdk_version_key(version: &str) -> Option<Vec<u64>> {
    version.split('.').map(|part| part.parse::<u64>().ok()).collect()
}
