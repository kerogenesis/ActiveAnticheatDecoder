//! x86 spin-wait thunks and the 5-byte stub patches pointing at them.

use core::ffi::c_void;

use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};

/// x86 spin-wait thunk: read-only flag check, patched jump, pause loop.
pub(super) fn thunk_template() -> [u8; 26] {
    [
        0xB8, 0, 0, 0, 0, // mov eax, flag
        0x80, 0x38, 0x00, // cmp byte [eax], 0
        0x75, 0x0C, // jne ready (+12 -> 22)
        0xE9, 0, 0, 0, 0, // jmp target (patched)
        0xF3, 0x90, // pause
        0x80, 0x38, 0x00, // cmp byte [eax], 0
        0x74, 0xF9, // je spin (-7 -> 15)
        0xEB, 0xF2, // jmp dispatch (-14 -> 10)
        0x90, 0x90, // pad
    ]
}

/// Raw byte writer for thunks and patches.
///
/// # Safety
/// `dst` must be writable for `src.len()` bytes.
pub(super) unsafe fn write_bytes(dst: usize, src: &[u8]) {
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst as *mut u8, src.len());
    }
}

/// Temporarily make `[addr, addr + size)` writable, returning the old flags.
///
/// # Safety
/// The range must belong to the current process.
pub(super) unsafe fn set_writable(addr: usize, size: usize) -> u32 {
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
pub(super) unsafe fn restore_protection(addr: usize, size: usize, old: u32) {
    let mut ignored = 0u32;
    unsafe {
        VirtualProtect(addr as *const c_void, size, old, &mut ignored);
    }
}

/// Overwrite the first 5 bytes of stub with a jump to thunk.
///
/// # Safety
/// `stub` must be one of our generated stubs (at least 5 bytes of patchable
/// code) and `thunk` a valid thunk within ±2 GB.
pub(super) unsafe fn hook_stub(stub: usize, thunk: usize) {
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
/// `thunk` must be a thunk allocated by the pool (26 bytes).
pub(super) unsafe fn set_thunk_target(thunk: usize, target: usize) {
    // E9 sits at thunk+10; next-ip is thunk+15.
    let rel = target.wrapping_sub(thunk + 15) as i32;
    unsafe {
        write_bytes(thunk + 11, &rel.to_le_bytes());
    }
}

/// Turn one hooked stub into a bare ret (load/resolve failure path).
///
/// # Safety
/// `stub` must be a hooked stub.
pub(super) unsafe fn retire_stub(stub: usize) {
    unsafe {
        let old = set_writable(stub, 1);
        core::ptr::write(stub as *mut u8, 0xC3);
        restore_protection(stub, 1, old);
    }
}

#[cfg(test)]
mod tests {
    use super::thunk_template;

    #[test]
    fn thunk_layout_matches_the_patcher() {
        let thunk = thunk_template();
        let rel8 = |at: usize| (thunk[at] as i8) as isize;
        assert_eq!(thunk.len(), 26);
        assert_eq!(thunk[10], 0xE9, "dispatch E9 must sit at +10");
        assert_eq!(8isize + 2 + rel8(9), 22, "jne must land on the back-jump");
        assert_eq!(10 + 5, 15, "unpatched dispatch falls into the pause loop");
        assert_eq!(20isize + 2 + rel8(21), 15, "je must loop back to pause");
        assert_eq!(22isize + 2 + rel8(23), 10, "back-jump must land on the dispatch");
    }
}
