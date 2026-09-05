//! Universal proxy DLL: forward every export to the real system DLL, capture
//! the live RSA key. DllMain only parses and hooks; everything else runs on
//! threads past the loader lock.

use core::ffi::c_void;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, TRUE};
use windows_sys::Win32::System::LibraryLoader::{
    DisableThreadLibraryCalls, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
    GET_MODULE_HANDLE_EX_FLAG_PIN, GetModuleHandleExW,
};
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows_sys::Win32::System::Threading::CreateThread;
use windows_sys::core::BOOL;

mod payload;
mod proxy;
mod util;

include!(concat!(env!("OUT_DIR"), "/stubs.rs"));

/// # Safety
/// Call from `DLL_PROCESS_ATTACH` only; pins the calling module permanently.
unsafe fn pin_self() {
    unsafe {
        let mut pinned: HANDLE = core::ptr::null_mut();
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            DllMain as *const u16,
            &mut pinned,
        );
    }
}

/// # Safety
/// `entry` must be a valid thread routine; call during attach only.
unsafe fn spawn(entry: unsafe extern "system" fn(*mut c_void) -> u32) {
    unsafe {
        let thread = CreateThread(
            core::ptr::null(),
            0,
            Some(entry),
            core::ptr::null(),
            0,
            core::ptr::null_mut(),
        );
        if !thread.is_null() {
            CloseHandle(thread);
        }
    }
}

/// # Safety
/// Called by the OS loader only, with a valid module handle.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(module: HANDLE, reason: u32, _reserved: *mut c_void) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            DisableThreadLibraryCalls(module);
            pin_self();
            if let Some(original) = proxy::create_proxy(module) {
                let _ = proxy::ORIGINAL_PATH.set(original);
                spawn(proxy::init_thread);
                spawn(payload::capture_thread);
            }
        }
    }
    if reason == DLL_PROCESS_DETACH {
        payload::STOP.store(true, core::sync::atomic::Ordering::Release);
    }
    TRUE
}
