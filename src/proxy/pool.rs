//! Pooled executable pages for thunks.
//!
//! Prefer pages near our image so thunk jumps always fit a 32-bit
//! displacement. Single-threaded use during `DllMain` initialisation,
//! sealed read-only by the worker thread once patching is done.

use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, VirtualAlloc,
    VirtualProtect,
};

const PAGE: usize = 4096;
const ALIGN: usize = 32;

static mut BASE: usize = 0;
static mut USED: usize = 0;
static mut HINT: usize = 0;
static mut PAGES: Vec<usize> = Vec::new();

/// Remember our image base for the first allocation attempt.
///
/// # Safety
/// Call once during `DllMain` initialisation, before any allocation.
pub(super) unsafe fn set_hint(base: usize) {
    unsafe {
        HINT = base;
    }
}

/// Carve size bytes out of pooled RWX pages.
///
/// # Safety
/// Single-threaded use during `DllMain` initialisation only.
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
/// Call once, after the last thunk patch, before the ready flag is set.
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
