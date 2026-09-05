//! Embed the proxy DLL and the app icon.
//!
//! AA_PROXY_DLL overrides the embedded DLL with a hand-built one;
//! non-Windows/non-x86 hosts embed an empty placeholder instead.
//! `rc.exe` (Windows SDK) is looked up explicitly because it is only on PATH
//! inside a Developer Prompt; `AA_REQUIRE_ICON=1` turns a missing icon into
//! a hard error for release builds.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn main() {
    println!("cargo:rerun-if-changed=src/proxy");
    println!("cargo:rerun-if-env-changed=AA_PROXY_DLL");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is always set by cargo"));
    stage_proxy_dll(&out_dir);
    #[cfg(windows)]
    embed_windows_icon(&out_dir);
}

fn stage_proxy_dll(out_dir: &Path) {
    let destination = out_dir.join("aa_proxy.dll");
    let bytes = match env::var_os("AA_PROXY_DLL") {
        Some(path) => {
            let path = PathBuf::from(path);
            println!("cargo:rerun-if-changed={}", path.display());
            fs::read(&path).unwrap_or_else(|error| {
                panic!("cannot read AA_PROXY_DLL at {path}: {error}", path = path.display())
            })
        }
        None => compile_proxy_dll(),
    };
    fs::write(&destination, bytes).expect("cannot stage the embedded proxy DLL");
}

/// Build the proxy member in-process and return its bytes. A nested cargo
/// must not see the outer build's `CARGO_*` variables, so they are scrubbed
/// (a few unrelated ones are kept). It also gets its own target dir: sharing
/// the workspace one would deadlock on cargo's build lock, and this keeps
/// the DLL path predictable.
fn compile_proxy_dll() -> Vec<u8> {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"));
    let target: String = env::var("TARGET").expect("TARGET is set by cargo");
    // The proxy is x86 machine code; anything else (and any non-Windows
    // host) gets an empty placeholder instead of a failed build. Live
    // capture then reports ProxyDllMissing.
    let arch = target.split('-').next().unwrap_or("");
    if !cfg!(windows) || arch != "i686" {
        println!(
            "cargo:warning=proxy DLL is x86-only, embedding an empty placeholder for {target}"
        );
        return Vec::new();
    }
    let profile = env::var("PROFILE").expect("PROFILE is set by cargo");
    let profile_dir = if profile == "release" { "release" } else { "debug" };
    let dll = manifest_dir
        .join("target")
        .join("proxy")
        .join(&target)
        .join(profile_dir)
        .join("aa_proxy.dll");

    let cargo = env!("CARGO");
    let mut child = Command::new(cargo);
    child
        .args(["build", "-p", "aa_proxy", "--target", &target])
        .current_dir(&manifest_dir)
        .env("CARGO_TARGET_DIR", manifest_dir.join("target").join("proxy"))
        .env_remove("TARGET")
        .env_remove("PROFILE")
        .env_remove("OUT_DIR")
        .env_remove("HOST");
    if profile == "release" {
        child.arg("--release");
    }
    for (key, _) in env::vars() {
        if key.starts_with("CARGO_")
            && !matches!(key.as_str(), "CARGO_HOME" | _ if key.starts_with("CARGO_NET_") || key.starts_with("CARGO_REGISTRIES_"))
        {
            child.env_remove(OsString::from(key));
        }
    }
    let output = child.output().expect("cannot spawn cargo for the proxy DLL");
    assert!(
        output.status.success(),
        "proxy build failed:\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("cargo:rerun-if-changed={}", dll.display());
    fs::read(&dll)
        .unwrap_or_else(|error| panic!("proxy built but {} is missing: {error}", dll.display()))
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

    let Some(compiler) = find_resource_compiler() else {
        report_icon_failure(
            required,
            "cannot find rc.exe: install the Windows SDK, build from a Developer Command \
             Prompt, or point AA_RC_EXE at it",
        );
        return;
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
    assert!(!required, "cannot embed the application icon: {reason}");
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
        let Ok(entries) = fs::read_dir(root) else { continue };

        for entry in entries.flatten() {
            // The versioned layout is <kit>\bin\<sdk version>\<host arch>\rc.exe.
            let name = entry.file_name();
            let Some(version) = sdk_version_key(&name.to_string_lossy()) else { continue };
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

#[cfg(windows)]
fn sdk_version_key(version: &str) -> Option<Vec<u64>> {
    version.split('.').map(|part| part.parse::<u64>().ok()).collect()
}
