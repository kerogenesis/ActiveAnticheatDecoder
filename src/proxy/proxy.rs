//! Runtime export forwarding: parse the real DLL, hook one spin-wait thunk
//! per export, resolve every thunk to module_base + rva on a worker thread
//! past the loader lock. Load failure is fail-safe: hooked stubs become a
//! bare ret instead of spinning forever.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, VirtualAlloc,
    VirtualProtect,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::{
    FORWARD_ORDINAL_TABLE, FORWARD_SHARED_TABLE, FORWARD_TABLE,
    util::{read_u16, read_u32, wide_nul},
};

static READY: AtomicBool = AtomicBool::new(false);

mod pool {
    use super::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, VirtualAlloc};
    use windows_sys::Win32::System::Memory::VirtualProtect;

    const PAGE: usize = 4096;
    const ALIGN: usize = 32;

    static mut BASE: usize = 0;
    static mut USED: usize = 0;
    static mut HINT: usize = 0;
    static mut PAGES: Vec<usize> = Vec::new();

    /// Prefer executable pages near our image so thunk jumps always fit a
    /// 32-bit displacement.
    ///
    /// # Safety
    /// Call once during DllMain initialisation, before any allocation.
    pub(super) unsafe fn set_hint(base: usize) {
        unsafe {
            HINT = base;
        }
    }

    /// Carve size bytes out of pooled RWX pages.
    ///
    /// # Safety
    /// Single-threaded use during DllMain initialisation only.
    pub(super) unsafe fn alloc(size: usize) -> Option<usize> {
        loop {
            let aligned = size.next_multiple_of(ALIGN);
            // SAFETY: only called from the single DllMain thread during init.
            let (base, used, hint) = unsafe { (BASE, USED, HINT) };
            if base != 0 && used + aligned <= PAGE {
                unsafe {
                    USED = used + aligned;
                }
                return Some(base + used);
            }
            let mut page = unsafe {
                VirtualAlloc(
                    hint as *const core::ffi::c_void,
                    PAGE,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_EXECUTE_READWRITE,
                )
            };
            if page.is_null() {
                page = unsafe {
                    VirtualAlloc(
                        core::ptr::null(),
                        PAGE,
                        MEM_RESERVE | MEM_COMMIT,
                        PAGE_EXECUTE_READWRITE,
                    )
                };
            }
            if page.is_null() {
                return None;
            }
            unsafe {
                BASE = page as usize;
                USED = 0;
                (*core::ptr::addr_of_mut!(PAGES)).push(page as usize);
            }
        }
    }

    /// Drop the write bit on every pooled page. Called by the worker thread
    /// once all thunks are patched: from then on the pool is execute-only
    /// data, unreachable for overwrites.
    ///
    /// # Safety
    /// Call once, after the last thunk patch, before [super::READY] is set.
    pub(super) unsafe fn seal_readonly() {
        // SAFETY: pages were fully written during init (happens-before the
        // worker thread was spawned); nobody allocates anymore.
        unsafe {
            for page in &*core::ptr::addr_of!(PAGES) {
                let mut ignored = 0u32;
                VirtualProtect(
                    *page as *const core::ffi::c_void,
                    PAGE,
                    PAGE_EXECUTE_READ,
                    &mut ignored,
                );
            }
        }
    }
}

const SHARED: [&str; 3] = ["DllCanUnloadNow", "DllGetClassObject", "SetAppCompatStringPointer"];

/// x86 spin-wait thunk
fn thunk_template() -> [u8; 26] {
    [
        0xb8, 0, 0, 0, 0, // mov eax, flag
        0x38, 0x00, // cmp [eax], al
        0x74, 0x05, // je spin
        0xe9, 0, 0, 0, 0, // jmp target
        0xf3, 0x90, // pause
        0xf0, 0x00, 0x00, // lock add [eax], al
        0x74, 0xf9, // je spin
        0xe9, 0xef, 0xff, 0xff, 0xff, // jmp back to the jmp
    ]
}

/// Raw byte writer for thunks and patches.
///
/// # Safety
/// dst must be writable for src.len() bytes.
unsafe fn write_bytes(dst: usize, src: &[u8]) {
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst as *mut u8, src.len());
    }
}

/// Temporarily make [addr, addr + size) writable, returning the old flags.
///
/// # Safety
/// The range must belong to the current process.
unsafe fn set_writable(addr: usize, size: usize) -> u32 {
    let mut old = 0u32;
    unsafe {
        VirtualProtect(addr as *const c_void, size, PAGE_EXECUTE_READWRITE, &mut old);
    }
    old
}

/// Restore protection saved by [set_writable].
///
/// # Safety
/// Same range, flags previously returned for it.
unsafe fn restore_protection(addr: usize, size: usize, old: u32) {
    let mut ignored = 0u32;
    unsafe {
        VirtualProtect(addr as *const c_void, size, old, &mut ignored);
    }
}

/// Overwrite the first 5 bytes of stub with a jump to thunk.
///
/// # Safety
/// stub must be one of our generated stubs (at least 5 bytes of patchable
/// code) and thunk a valid thunk within ±2 GB.
unsafe fn hook_stub(stub: usize, thunk: usize) {
    const CLEARANCE: usize = 5;
    unsafe {
        let old = set_writable(stub, CLEARANCE);
        core::ptr::write_bytes(stub as *mut u8, 0x90, CLEARANCE);
        core::ptr::write(stub as *mut u8, 0xe9u8);
        let rel = thunk.wrapping_sub(stub + CLEARANCE) as i32;
        core::ptr::copy_nonoverlapping(rel.to_le_bytes().as_ptr(), (stub + 1) as *mut u8, 4);
        restore_protection(stub, CLEARANCE, old);
    }
}

/// Patch the thunk's jump to land on target.
///
/// # Safety
/// thunk must be a thunk allocated by [pool::alloc] (26 bytes).
unsafe fn set_thunk_target(thunk: usize, target: usize) {
    // E9 sits at thunk+9; next-ip is thunk+14.
    let rel = target.wrapping_sub(thunk + 14) as i32;
    unsafe {
        write_bytes(thunk + 10, &rel.to_le_bytes());
    }
}

/// Turn one hooked stub into a bare ret (load/resolve failure path).
///
/// # Safety
/// stub must be a hooked stub.
unsafe fn retire_stub(stub: usize) {
    unsafe {
        let old = set_writable(stub, 1);
        core::ptr::write(stub as *mut u8, 0xC3);
        restore_protection(stub, 1, old);
    }
}

/// Resolve a re-export against the loaded original, by name or by ordinal.
///
/// # Safety
/// module must be a loaded module handle.
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

struct Export {
    name: Option<String>,
    ordinal: u32,
    rva: u32,
    /// Re-exported from another DLL: no static address, resolve by name (or
    /// ordinal) after loading instead of module_base + rva.
    forwarded: bool,
}

struct Image {
    bytes: Vec<u8>,
    sections: Vec<(u32, u32, u32)>, // (virt_begin, virt_end, raw)
    export_rva: u32,
    export_size: u32,
}

fn parse_image(bytes: Vec<u8>) -> Option<Image> {
    if read_u16(&bytes, 0)? != 0x5A4D {
        return None;
    }
    let pe = read_u32(&bytes, 0x3C)? as usize;
    if read_u32(&bytes, pe)? != 0x0000_4550 {
        return None;
    }
    let num_sections = read_u16(&bytes, pe + 6)? as usize;
    let opt_size = read_u16(&bytes, pe + 20)? as usize;
    let opt = pe + 24;
    // We only ever proxy 32-bit DLLs.
    if read_u16(&bytes, opt)? != 0x10B {
        return None;
    }
    let export_rva = read_u32(&bytes, opt + 96)?;
    let export_size = read_u32(&bytes, opt + 100)?;
    if export_rva == 0 {
        return None;
    }
    let sections_at = opt + opt_size;
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let at = sections_at + i * 40;
        let virt = read_u32(&bytes, at + 12)?;
        // Crafted images love overflowing this: fail closed instead.
        let end = virt.checked_add(read_u32(&bytes, at + 8)?)?;
        let raw = read_u32(&bytes, at + 20)?;
        sections.push((virt, end, raw));
    }
    let image = Image { bytes, sections, export_rva, export_size };
    Some(image)
}

impl Image {
    fn raw_of(&self, rva: u32) -> Option<usize> {
        self.sections.iter().find_map(|(begin, end, raw)| {
            (*begin <= rva && rva < *end)
                .then(|| u64::from(rva - *begin) + u64::from(*raw))
                .and_then(|offset| usize::try_from(offset).ok())
        })
    }

    fn is_forwarder(&self, rva: u32) -> bool {
        rva >= self.export_rva && rva < self.export_rva + self.export_size
    }

    fn read_cstring(&self, raw: usize) -> Option<String> {
        let end = self.bytes.get(raw..)?.iter().position(|byte| *byte == 0)?;
        String::from_utf8(self.bytes[raw..raw + end].to_vec()).ok()
    }

    fn exports(&self) -> Option<Vec<Export>> {
        let dir = self.raw_of(self.export_rva)?;
        let base = read_u32(&self.bytes, dir + 16)?;
        let count = read_u32(&self.bytes, dir + 20)?;
        let name_count = read_u32(&self.bytes, dir + 24)?;
        // Unbounded pre-allocation from hostile input is a DoS vector (and a
        // hang via the loops below); no real export table is this large.
        if count > 1_000_000 || name_count > 1_000_000 {
            return None;
        }
        let names_rva = read_u32(&self.bytes, dir + 32)?;
        let rva_table = self.raw_of(names_rva)?;
        let ordinals_rva = read_u32(&self.bytes, dir + 36)?;
        let ordinals_raw = self.raw_of(ordinals_rva)?;
        let funcs_rva = read_u32(&self.bytes, dir + 28)?;
        let funcs_raw = self.raw_of(funcs_rva)?;

        // Ordinal -> name index, to tell named exports apart from NONAME ones.
        // NOTE: +32 is AddressOfNames; +24 is just the name *count*. Mixing
        // them up fails silently and scrambles every name<->slot mapping.
        let mut name_of_ordinal = vec![None; count as usize];
        for i in 0..name_count {
            let entry_rva = read_u32(&self.bytes, rva_table + 4 * i as usize)?;
            let ordinal = u32::from(read_u16(&self.bytes, ordinals_raw + 2 * i as usize)?);
            let name = self.read_cstring(self.raw_of(entry_rva)?)?;
            if let Some(slot) = name_of_ordinal.get_mut(ordinal as usize) {
                *slot = Some(name);
            }
        }

        let mut out = Vec::with_capacity(count as usize);
        for i in 0..count {
            let rva = read_u32(&self.bytes, funcs_raw + 4 * i as usize)?;
            // Keep the slot even for re-exports so later ordinals stay
            // aligned with the static /EXPORT overlay.
            let forwarded = self.is_forwarder(rva);
            out.push(Export {
                name: name_of_ordinal.get(i as usize).cloned().flatten(),
                ordinal: base.checked_add(i)?,
                rva,
                forwarded,
            });
        }
        Some(out)
    }
}

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

/// _name next to the client first, then the real one in System32.
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

/// Parse the original DLL and hook every stub.
/// Returns the wide original path for the worker thread.
///
/// # Safety
/// Call once, from DLL_PROCESS_ATTACH, before any other thread exists.
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

/// Worker thread: resolve every thunk against the loaded original and go live.
/// Runs after DllMain returns, so LoadLibrary is loader-lock safe.
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
    use super::parse_image;

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
        use std::os::windows::ffi::OsStrExt;
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

    /// Guards the IMAGE_EXPORT_DIRECTORY layout (+24 count vs +32 names RVA):
    /// mixing them up fails silently and scrambles every name<->slot mapping.
    #[test]
    fn parses_ddraw_export_table() {
        let bytes =
            std::fs::read(r"C:\Windows\SysWOW64\ddraw.dll").expect("SysWOW64 ddraw must exist");
        let image = parse_image(bytes).expect("valid PE32 image");
        let exports = image.exports().expect("export table parses");
        assert_eq!(exports.len(), 22);
        assert_eq!(exports[0].name.as_deref(), Some("AcquireDDThreadLock"));
        assert_eq!(exports[0].ordinal, 1);
        assert_eq!(exports[7].name.as_deref(), Some("DirectDrawCreate"));
        assert_eq!(exports[21].name.as_deref(), Some("SetAppCompatData"));
        assert_eq!(exports[21].ordinal, 22);
    }

    #[test]
    fn parses_d3d9_with_nontrivial_base() {
        let bytes = std::fs::read(r"C:\Windows\SysWOW64\d3d9.dll").expect("d3d9 must exist");
        let image = parse_image(bytes).expect("valid PE32 image");
        let exports = image.exports().expect("export table parses");
        assert_eq!(exports.len(), 23);
        assert_eq!(exports[21].name.as_deref(), Some("Direct3DCreate9"));
        assert_eq!(exports[21].ordinal, 37);
        assert!(exports[0].name.is_none());
        assert_eq!(exports[0].ordinal, 16);
    }

    #[test]
    fn parses_xinput_ordinals_with_gaps() {
        let bytes = std::fs::read(r"C:\Windows\SysWOW64\xinput1_4.dll").expect("xinput must exist");
        let image = parse_image(bytes).expect("valid PE32 image");
        let exports = image.exports().expect("export table parses");
        assert_eq!(exports.len(), 109);
        assert_eq!(exports[1].name.as_deref(), Some("XInputGetState"));
        assert!(exports[5].name.is_none());
        assert_eq!(exports[5].ordinal, 6);
        assert!(exports[108].name.is_none());
        assert_eq!(exports[108].ordinal, 109);
    }

    #[test]
    fn forwarder_free_targets_keep_slots_aligned() {
        for (dll, count) in
            [(r"C:\Windows\SysWOW64\ddraw.dll", 22), (r"C:\Windows\SysWOW64\d3d9.dll", 23)]
        {
            let bytes = std::fs::read(dll).expect("system DLL must exist");
            let exports = parse_image(bytes).expect("image parses").exports().expect("exports");
            assert_eq!(exports.len(), count);
            assert!(exports.iter().all(|export| !export.forwarded));
            // Ordinals must run unbroken: any gap or shift would bind the
            // static /EXPORT overlay to the wrong stubs.
            let base = exports.first().map(|export| export.ordinal).unwrap_or(0);
            for (i, export) in exports.iter().enumerate() {
                assert_eq!(export.ordinal, base + i as u32, "slot {i} misaligned");
            }
        }
    }

    /// A section running past 4 GB must fail closed, not panic (fuzz-found)
    /// or wrap into a wrong mapping (release).
    #[test]
    fn overflowing_section_fails_closed() {
        let mut bytes = vec![0u8; 0x200];
        bytes[0..2].copy_from_slice(&[0x4D, 0x5A]);
        bytes[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        let pe = 0x40;
        bytes[pe..pe + 4].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]);
        bytes[pe + 6..pe + 8].copy_from_slice(&1u16.to_le_bytes());
        bytes[pe + 20..pe + 22].copy_from_slice(&0xE0u16.to_le_bytes());
        let opt = pe + 24;
        bytes[opt..opt + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
        bytes[opt + 96..opt + 100].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[opt + 100..opt + 104].copy_from_slice(&40u32.to_le_bytes());
        let section = opt + 0xE0;
        bytes[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        assert!(parse_image(bytes).is_none());
    }
}
