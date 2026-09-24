//! Administrator-rights check

use obfstr::obfstr;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, SECURITY_MAX_SID_SIZE,
    TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation, WinBuiltinAdministratorsSid,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONWARNING, MB_OK, MB_TOPMOST, MessageBoxW};

use crate::system::winutil::to_wide;

#[must_use]
pub fn is_elevated() -> bool {
    token_is_elevated() && is_admin_member()
}

fn token_is_elevated() -> bool {
    let mut token = std::ptr::null_mut();
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 || token.is_null() {
        return true;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0u32;
    let queried = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            core::ptr::addr_of_mut!(elevation).cast::<core::ffi::c_void>(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    unsafe {
        CloseHandle(token);
    }
    if queried == 0 {
        return true;
    }
    elevation.TokenIsElevated != 0
}

fn is_admin_member() -> bool {
    let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_len = sid.len() as u32;
    let created = unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            sid.as_mut_ptr().cast::<core::ffi::c_void>(),
            &mut sid_len,
        )
    };
    if created == 0 {
        return true;
    }
    let mut member = 0;
    let checked = unsafe {
        CheckTokenMembership(
            std::ptr::null_mut(),
            sid.as_mut_ptr().cast::<core::ffi::c_void>(),
            &mut member,
        )
    };
    if checked == 0 {
        return true;
    }
    member != 0
}

pub fn show_elevation_required() {
    let text = to_wide(obfstr!("Please run this program as administrator."));
    let caption = to_wide(obfstr!("Administrator rights required"));
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            caption.as_ptr(),
            MB_OK | MB_ICONWARNING | MB_TOPMOST,
        );
    }
}

#[must_use]
pub fn require_elevation() -> bool {
    if is_elevated() {
        return true;
    }
    show_elevation_required();
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elevation_check_does_not_panic() {
        let _ = is_elevated();
    }
}
