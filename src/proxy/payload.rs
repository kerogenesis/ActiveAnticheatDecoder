//! Live RSA key capture: sweep memory for the 0x78-byte context fingerprint
//! and send (N_LE, D_LE) over the AA_DECODER_PIPE named pipe.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING, WriteFile};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Environment::GetEnvironmentVariableW;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
    PAGE_WRITECOPY, VirtualQuery,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, GetTickCount64};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, Sleep};

const GENERIC_WRITE: u32 = 0x4000_0000;

const CONTEXT_SIZE: usize = 0x78;
const CHUNK: usize = 4 * 1024 * 1024;
const MAX_REGION: usize = 128 * 1024 * 1024;
const MAX_MPI: usize = 256;

pub(super) static STOP: AtomicBool = AtomicBool::new(false);

use crate::util::{read_u16, read_u32, wide_nul};

struct RsaKey {
    n_le: Vec<u8>,
    d_le: Vec<u8>,
}

/// Fault-safe read of our own address space.
///
/// # Safety
/// out must be a valid writable buffer; arbitrary address values are
/// safe — unreadable pages fail instead of faulting.
unsafe fn read_exact(address: usize, out: &mut [u8]) -> bool {
    let mut got = 0usize;
    unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            address as *const c_void,
            out.as_mut_ptr().cast::<c_void>(),
            out.len(),
            &mut got,
        ) != 0
            && got == out.len()
    }
}

fn descriptor_matches(ctx: &[u8], offset: usize, limbs: u16) -> bool {
    read_u16(ctx, offset + 4) == Some(1) && read_u16(ctx, offset + 6) == Some(limbs)
}

/// The 0x78-byte fingerprint: 256-bit modulus plus the expected MPI shapes.
fn context_matches(ctx: &[u8]) -> bool {
    read_u32(ctx, 4) == Some(0x100)
        && descriptor_matches(ctx, 0x08, 64)
        && descriptor_matches(ctx, 0x10, 1)
        && descriptor_matches(ctx, 0x18, 64)
        && descriptor_matches(ctx, 0x20, 32)
        && descriptor_matches(ctx, 0x28, 32)
        && descriptor_matches(ctx, 0x30, 32)
        && descriptor_matches(ctx, 0x38, 32)
        && descriptor_matches(ctx, 0x40, 32)
}

/// Follow one MPI descriptor and copy its limbs out of memory.
///
/// # Safety
/// Same contract as [read_exact].
unsafe fn read_mpi(ctx: &[u8], offset: usize) -> Option<Vec<u8>> {
    let pointer = read_u32(ctx, offset)? as usize;
    let size = read_u16(ctx, offset + 6)? as usize * 4;
    if pointer == 0 || size == 0 || size > MAX_MPI {
        return None;
    }
    let mut out = vec![0u8; size];
    unsafe { read_exact(pointer, &mut out).then_some(out) }
}

/// Extract (N, D) from a matching context.
///
/// # Safety
/// Same contract as [read_exact].
unsafe fn extract_key(ctx: &[u8]) -> Option<RsaKey> {
    unsafe { Some(RsaKey { n_le: read_mpi(ctx, 0x08)?, d_le: read_mpi(ctx, 0x18)? }) }
}

fn is_readable(protect: u32) -> bool {
    if protect & (PAGE_GUARD | PAGE_NOACCESS) != 0 {
        return false;
    }
    matches!(
        protect & 0xFF,
        PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY
    )
}

/// Sweep one committed region for the fingerprint.
///
/// # Safety
/// Same contract as [read_exact].
unsafe fn scan_region(base: usize, size: usize, buffer: &mut [u8]) -> Option<RsaKey> {
    let mut offset = 0;
    while offset < size {
        let remaining = size - offset;
        let wanted = remaining.min(buffer.len());
        if !unsafe { read_exact(base + offset, &mut buffer[..wanted]) } {
            offset += 4096;
            continue;
        }
        if wanted >= CONTEXT_SIZE {
            let mut local = 0;
            while local + CONTEXT_SIZE <= wanted {
                let ctx = &buffer[local..local + CONTEXT_SIZE];
                if context_matches(ctx) {
                    // SAFETY: same fault-safe reads as everywhere else.
                    if let Some(key) = unsafe { extract_key(ctx) } {
                        return Some(key);
                    }
                }
                local += 4;
            }
        }
        if remaining <= CHUNK {
            break;
        }
        offset += CHUNK;
    }
    None
}

/// Sweep the whole address space; None if the key is not live yet.
///
/// # Safety
/// Reads only our own process memory via fault-safe probes.
unsafe fn find_rsa_key(buffer: &mut [u8]) -> Option<RsaKey> {
    let mut info = unsafe { core::mem::zeroed() };
    unsafe {
        GetSystemInfo(&mut info);
    }

    debug_assert!(buffer.len() >= CHUNK + CONTEXT_SIZE - 1);
    let mut cursor = info.lpMinimumApplicationAddress as usize;
    let maximum = info.lpMaximumApplicationAddress as usize;
    while cursor < maximum {
        let mut region: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
        let queried = unsafe {
            VirtualQuery(
                cursor as *const c_void,
                &mut region,
                core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if queried != core::mem::size_of::<MEMORY_BASIC_INFORMATION>() {
            break;
        }
        let base = region.BaseAddress as usize;
        let next = base.wrapping_add(region.RegionSize);
        if next <= cursor {
            break;
        }
        if region.State == MEM_COMMIT
            && is_readable(region.Protect)
            && region.RegionSize >= CONTEXT_SIZE
            && region.RegionSize <= MAX_REGION
            && let Some(key) = unsafe { scan_region(base, region.RegionSize, buffer) }
        {
            return Some(key);
        }
        cursor = next;
    }
    None
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0F) as usize] as char);
    }
    out
}

fn send_key(key: &RsaKey) {
    let var = wide_nul("AA_DECODER_PIPE");
    let mut name = [0u16; 256];
    let len =
        unsafe { GetEnvironmentVariableW(var.as_ptr(), name.as_mut_ptr(), name.len() as u32) };
    if len == 0 || len as usize >= name.len() {
        return;
    }
    let message = format!("N_LE={}\r\nD_LE={}\r\n", to_hex(&key.n_le), to_hex(&key.d_le));
    let pipe = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            0,
            core::ptr::null(),
            OPEN_EXISTING,
            0,
            core::ptr::null_mut(),
        )
    };
    if pipe == INVALID_HANDLE_VALUE {
        return;
    }
    let mut written = 0u32;
    unsafe {
        WriteFile(
            pipe,
            message.as_ptr(),
            message.len() as u32,
            &mut written,
            core::ptr::null_mut(),
        );
        CloseHandle(pipe);
    }
}

/// Payload thread entry. Waits for the game crypto to initialise, then scans.
///
/// # Safety
/// Run once on a dedicated thread; stops early when [STOP] is set.
pub(super) unsafe extern "system" fn capture_thread(_: *mut c_void) -> u32 {
    const MODULE_WAIT_MS: u64 = 30_000;
    let clmods = wide_nul("clmods.dll");
    let start = unsafe { GetTickCount64() };
    let mut ready = false;
    while unsafe { GetTickCount64() }.wrapping_sub(start) < MODULE_WAIT_MS {
        if STOP.load(Ordering::Acquire) {
            return 0;
        }
        if !unsafe { GetModuleHandleW(clmods.as_ptr()) }.is_null() {
            ready = true;
            break;
        }
        unsafe {
            Sleep(120);
        }
    }
    if !ready {
        return 0;
    }
    unsafe {
        Sleep(200);
    }
    // One reusable scratch buffer for every sweep attempt.
    let mut buffer = vec![0u8; CHUNK + CONTEXT_SIZE - 1];
    for _ in 0..180 {
        if STOP.load(Ordering::Acquire) {
            return 0;
        }
        if let Some(key) = unsafe { find_rsa_key(&mut buffer) } {
            send_key(&key);
            return 0;
        }
        unsafe {
            Sleep(150);
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        modulus: Vec<u8>,
        exponent: Vec<u8>,
        ones: Vec<Vec<u8>>,
        ctx: [u8; CONTEXT_SIZE],
    }

    /// A live-looking RSA context: the backing limb buffers stay alive in the
    /// fixture while the 0x78-byte fingerprint points at them. Pointers fit
    /// u32 because tests run as x86, like the client.
    fn live_fixture() -> Fixture {
        let modulus = vec![0xABu8; 256];
        let exponent = vec![0xCDu8; 256];
        let ones: Vec<Vec<u8>> = (0u32..6).map(|i| vec![i as u8 + 1; 128]).collect();
        let one_limb = vec![0x01u8; 4];
        let mut ctx = [0u8; CONTEXT_SIZE];
        ctx[4..8].copy_from_slice(&0x100u32.to_le_bytes());

        let mut descriptor = |offset: usize, target: &[u8], limbs: u16| {
            let pointer = target.as_ptr() as u32;
            ctx[offset..offset + 4].copy_from_slice(&pointer.to_le_bytes());
            ctx[offset + 4..offset + 6].copy_from_slice(&1u16.to_le_bytes());
            ctx[offset + 6..offset + 8].copy_from_slice(&limbs.to_le_bytes());
        };
        descriptor(0x08, &modulus, 64);
        descriptor(0x10, &one_limb, 1);
        descriptor(0x18, &exponent, 64);
        for (slot, offset) in [0x20, 0x28, 0x30, 0x38, 0x40].iter().enumerate() {
            descriptor(*offset, &ones[slot % ones.len()], 32);
        }
        Fixture { modulus, exponent, ones, ctx }
    }

    #[test]
    fn live_context_matches_and_extracts() {
        let fixture = live_fixture();
        assert!(context_matches(&fixture.ctx));
        let key = unsafe { extract_key(&fixture.ctx) }.expect("key extracts");
        assert_eq!(key.n_le, fixture.modulus);
        assert_eq!(key.d_le, fixture.exponent);
        assert_eq!(fixture.ones.len(), 6);
    }

    #[test]
    fn broken_fingerprint_does_not_match() {
        let mut fixture = live_fixture();
        fixture.ctx[4..8].copy_from_slice(&0xFFu32.to_le_bytes());
        assert!(!context_matches(&fixture.ctx));
    }

    #[test]
    fn oversized_mpi_is_rejected() {
        let mut fixture = live_fixture();
        fixture.ctx[0x08 + 6..0x08 + 8].copy_from_slice(&65u16.to_le_bytes());
        assert!(unsafe { extract_key(&fixture.ctx) }.is_none());
    }
}
