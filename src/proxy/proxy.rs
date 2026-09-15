//! Runtime export forwarding: parse the real DLL, hook one spin-wait thunk
//! per export, resolve every thunk to `module_base + rva` on a worker thread
//! past the loader lock. Load failure is fail-safe: hooked stubs become a
//! bare `ret` instead of spinning forever.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetProcAddress};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::{
    FORWARD_ORDINAL_TABLE, FORWARD_SHARED_TABLE, FORWARD_TABLE,
    image::{Export, parse_image},
    pool,
    thunk::{hook_stub, retire_stub, set_thunk_target, thunk_template, write_bytes},
    util::wide_nul,
};

static READY: AtomicBool = AtomicBool::new(false);

const SHARED: [&str; 3] = ["DllCanUnloadNow", "DllGetClassObject", "SetAppCompatStringPointer"];

/// One hooked stub per export, in ordinal order: where the stub lives and how
/// the worker thread resolves its jump target.
struct Binding {
    thunk: usize,
    stub: usize,
    target: BindingTarget,
}

enum BindingTarget {
    Rva(u32),
    Forwarded { name: Option<String>, ordinal: u32 },
}

impl BindingTarget {
    fn from_export(export: &Export) -> Self {
        if export.forwarded {
            Self::Forwarded { name: export.name.clone(), ordinal: export.ordinal }
        } else {
            Self::Rva(export.rva)
        }
    }
}

pub(super) static ORIGINAL_PATH: OnceLock<Vec<u16>> = OnceLock::new();
static BINDINGS: OnceLock<Vec<Binding>> = OnceLock::new();

fn own_file_name(module: HANDLE) -> Option<String> {
    // 32K, not MAX_PATH: a truncated name would bind the wrong exports.
    // Boxed: 64 KB is too much for a stack array (clippy::large_stack_arrays).
    let mut buffer = vec![0u16; 32767];
    let len = unsafe { GetModuleFileNameW(module, buffer.as_mut_ptr(), buffer.len() as u32) };
    if len == 0 {
        return None;
    }
    let path = String::from_utf16_lossy(&buffer[..len as usize]);
    path.rsplit(['\\', '/']).next().map(str::to_owned)
}

fn file_exists(path: &str) -> bool {
    std::fs::metadata(path).is_ok()
}

/// `_name` next to the client first, then the real one in System32.
fn find_original(own: &str) -> Option<Vec<u16>> {
    let underscored = format!("_{own}");
    if file_exists(&underscored) {
        return Some(wide_nul(&underscored));
    }
    let mut buffer = vec![0u16; 32767];
    let len = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if len == 0 || len as usize >= buffer.len() {
        return None;
    }
    let mut dir = String::from_utf16_lossy(&buffer[..len as usize]);
    dir.push('\\');
    dir.push_str(own);
    if file_exists(&dir) { Some(wide_nul(&dir)) } else { None }
}

fn shared_slot(name: &str) -> Option<usize> {
    SHARED.iter().position(|shared| *shared == name)
}

/// Hook one thunk per export and collect the bindings for the worker thread.
/// Slots stay in ordinal order so they line up with the static overlay.
///
/// # Safety
/// Call once, from DLL_PROCESS_ATTACH, before any other thread exists.
unsafe fn bind_exports(exports: &[Export]) -> Option<Vec<Binding>> {
    let mut bindings = Vec::with_capacity(exports.len() * 2);
    for (i, export) in exports.iter().enumerate() {
        let stub = match &export.name {
            Some(name) => match shared_slot(name) {
                Some(shared) => FORWARD_SHARED_TABLE[shared] as usize,
                None => (*FORWARD_TABLE.get(i)?) as usize,
            },
            None => (*FORWARD_ORDINAL_TABLE.get(export.ordinal.wrapping_sub(1) as usize)?) as usize,
        };
        let mut thunk = thunk_template();
        let flag: *const AtomicBool = &READY;
        thunk[1..5].copy_from_slice(&(flag as usize).to_le_bytes());
        let thunk_addr = unsafe { pool::alloc(thunk.len())? };
        unsafe {
            write_bytes(thunk_addr, &thunk);
            hook_stub(stub, thunk_addr);
            // Named exports stay reachable by ordinal as well, shared ones
            // included: same thunk, second stub.
            if export.name.is_some() {
                let ordinal_stub =
                    (*FORWARD_ORDINAL_TABLE.get(export.ordinal.wrapping_sub(1) as usize)?) as usize;
                hook_stub(ordinal_stub, thunk_addr);
                bindings.push(Binding {
                    thunk: thunk_addr,
                    stub: ordinal_stub,
                    target: BindingTarget::from_export(export),
                });
            }
            bindings.push(Binding {
                thunk: thunk_addr,
                stub,
                target: BindingTarget::from_export(export),
            });
        }
    }
    Some(bindings)
}

/// Parse the original DLL and hook every stub.
/// Returns the wide original path for the worker thread.
///
/// # Safety
/// Call once, from DLL_PROCESS_ATTACH, before any other thread exists.
pub(super) unsafe fn create_proxy(module: HANDLE) -> Option<Vec<u16>> {
    let own = own_file_name(module)?;
    let original = find_original(&own)?;
    let path = String::from_utf16_lossy(&original[..original.len().saturating_sub(1)]);
    let bytes = std::fs::read(&path).ok()?;
    let image = parse_image(bytes)?;
    let exports = image.exports()?;

    #[cfg(debug_assertions)]
    {
        let mut stubs: Vec<usize> = FORWARD_TABLE
            .iter()
            .chain(FORWARD_ORDINAL_TABLE.iter())
            .chain(FORWARD_SHARED_TABLE.iter())
            .map(|stub| *stub as usize)
            .collect();
        stubs.sort_unstable();
        assert!(
            stubs.windows(2).all(|pair| pair[1] - pair[0] >= 5),
            "forward stubs packed tighter than the 5-byte hook"
        );
    }

    unsafe {
        pool::set_hint(module as usize);
    }
    let bindings = unsafe { bind_exports(&exports)? };
    unsafe {
        let _ = FlushInstructionCache(GetCurrentProcess(), core::ptr::null(), 0);
    }
    let _ = BINDINGS.set(bindings);
    Some(original)
}

/// Turn every hooked stub into a bare ret (load/resolve failure path).
///
/// # Safety
/// Call with fully hooked bindings only.
unsafe fn retire_all(bindings: &[Binding]) {
    unsafe {
        for binding in bindings {
            retire_stub(binding.stub);
            // Threads already spinning inside the thunk exit through the
            // patched jump: aim it at the stub itself, now a bare ret.
            set_thunk_target(binding.thunk, binding.stub);
        }
    }
}

/// Point every thunk at the loaded original.
///
/// # Safety
/// `module` must be the loaded original; call once per binding set.
unsafe fn resolve_all(bindings: &[Binding], module: HANDLE) {
    unsafe {
        for binding in bindings {
            let target = match &binding.target {
                BindingTarget::Rva(rva) => (module as usize).wrapping_add(*rva as usize),
                BindingTarget::Forwarded { name, ordinal } => {
                    let Some(address) = resolve_forwarder(module, name.as_deref(), *ordinal) else {
                        retire_stub(binding.stub);
                        continue;
                    };
                    address
                }
            };
            set_thunk_target(binding.thunk, target);
        }
    }
}

/// Resolve a re-export against the loaded original, by name or by ordinal.
///
/// # Safety
/// `module` must be a loaded module handle.
unsafe fn resolve_forwarder(module: HANDLE, name: Option<&str>, ordinal: u32) -> Option<usize> {
    unsafe {
        let address = match name {
            Some(name) => {
                let named = std::ffi::CString::new(name).ok()?;
                GetProcAddress(module, named.as_bytes_with_nul().as_ptr())
            }
            // Ordinals double as resource IDs below 64K.
            None => GetProcAddress(module, ordinal as usize as *const u8),
        };
        address.map(|func| func as usize)
    }
}

/// Worker thread: resolve every thunk against the loaded original and go live.
/// Runs after `DllMain` returns, so `LoadLibrary` is loader-lock safe.
///
/// # Safety
/// ORIGINAL_PATH must have been written by [create_proxy] before the
/// thread starts; call once.
pub(super) unsafe extern "system" fn init_thread(_: *mut c_void) -> u32 {
    let (Some(path), Some(bindings)) = (ORIGINAL_PATH.get(), BINDINGS.get()) else {
        READY.store(true, Ordering::Release);
        return 1;
    };
    let module = unsafe { windows_sys::Win32::System::LibraryLoader::LoadLibraryW(path.as_ptr()) };
    if module.is_null() {
        // Fail safe: make every hooked stub a bare ret so the client keeps
        // running instead of spinning forever.
        unsafe {
            retire_all(bindings);
            pool::seal_readonly();
            let _ = FlushInstructionCache(GetCurrentProcess(), core::ptr::null(), 0);
        }
        READY.store(true, Ordering::Release);
        return 1;
    }

    unsafe {
        resolve_all(bindings, module);
        pool::seal_readonly();
        let _ = FlushInstructionCache(GetCurrentProcess(), core::ptr::null(), 0);
    }
    READY.store(true, Ordering::Release);
    0
}

#[cfg(test)]
mod tests {
    use crate::image::parse_image;

    /// The DLL under test. cargo test emits no cdylib artifact itself, so
    /// look next to the test binary (direct -p aa_proxy build) and in the
    /// nested-build dir the decoder build script fills
    /// (target/proxy/..., always fresh after any decoder build).
    #[cfg(windows)]
    fn built_dll_path() -> std::path::PathBuf {
        let exe = std::env::current_exe().expect("test exe");
        // .../target/<triple>/<profile>/deps/xxx.exe
        let profile_dir = exe.parent().and_then(|deps| deps.parent()).expect("profile");
        let direct = profile_dir.join("aa_proxy.dll");
        if direct.is_file() {
            return direct;
        }
        let triple_dir = profile_dir.parent().expect("triple");
        let target_dir = triple_dir.parent().expect("target");
        let profile_name =
            profile_dir.file_name().and_then(|name| name.to_str()).unwrap_or("release");
        let triple_name = triple_dir.file_name().and_then(|name| name.to_str()).unwrap_or("");
        let nested =
            target_dir.join("proxy").join(triple_name).join(profile_name).join("aa_proxy.dll");
        if nested.is_file() {
            return nested;
        }
        panic!(
            "aa_proxy.dll not found; run `cargo build -p aa_proxy --target i686-pc-windows-msvc` first"
        );
    }

    #[cfg(windows)]
    fn proc_address(
        module: windows_sys::Win32::Foundation::HMODULE,
        name: &str,
    ) -> windows_sys::Win32::Foundation::FARPROC {
        use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
        let named = std::ffi::CString::new(name).expect("ascii export name");
        unsafe { GetProcAddress(module, named.as_bytes_with_nul().as_ptr()) }
    }

    /// End-to-end forwarding: stage the freshly built DLL under each
    /// supported system name, resolve every export and call the safe ones.
    /// Runs in-process; the image pins itself and its threads die with the
    /// test process, so scratch cleanup is best-effort.
    #[cfg(windows)]
    #[test]
    fn smoke_forwards_all_exports() {
        use std::os::windows::ffi::OsStrExt as _;
        use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;

        let dll = built_dll_path();
        let dir = std::env::temp_dir().join(format!("aa-proxy-smoke-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch");
        for name in ["ddraw.dll", "d3d9.dll", "xinput1_4.dll"] {
            let staged = dir.join(name);
            std::fs::copy(&dll, &staged).expect("stage copy");
            let bytes = std::fs::read(&staged).expect("read back");
            let exports = parse_image(bytes).expect("parse").exports().expect("exports");
            let wide: Vec<u16> =
                staged.as_os_str().encode_wide().chain(core::iter::once(0)).collect();
            let module = unsafe { LoadLibraryW(wide.as_ptr()) };
            assert!(!module.is_null(), "{name} loads");
            for export in &exports {
                let address = if let Some(named) = &export.name {
                    proc_address(module, named)
                } else {
                    unsafe {
                        use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
                        GetProcAddress(module, export.ordinal as usize as *const u8)
                    }
                };
                let what = export.name.as_deref().unwrap_or("ordinal");
                assert!(address.is_some(), "{name}:{what}@{} resolves", export.ordinal);
            }
            if name == "ddraw.dll" {
                let direct_draw_create: unsafe extern "system" fn(u32, u32, u32) -> i32 =
                    unsafe { std::mem::transmute(proc_address(module, "DirectDrawCreate")) };
                assert_ne!(unsafe { direct_draw_create(0, 0, 0) }, 0);
            }
            if name == "xinput1_4.dll" {
                #[repr(C)]
                struct XInputState {
                    packet: u32,
                    buttons: u16,
                    left_trigger: u8,
                    right_trigger: u8,
                    thumb_lx: i16,
                    thumb_ly: i16,
                    thumb_rx: i16,
                    thumb_ry: i16,
                }
                let get_state: unsafe extern "system" fn(u32, *mut XInputState) -> u32 =
                    unsafe { std::mem::transmute(proc_address(module, "XInputGetState")) };
                let mut state: XInputState = unsafe { std::mem::zeroed() };
                let rc = unsafe { get_state(0, &mut state) };
                assert!(rc == 0 || rc == 1167, "present or disconnected pad");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
