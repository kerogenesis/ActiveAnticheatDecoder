//! Native "browse for folder" dialog, for the double-click case.
//!
//! The modern IFileOpenDialog (no MAX_PATH cap) is tried first; any
//! technical failure falls back to the legacy SHBrowseForFolderW dialog.
//! windows-sys ships no COM interfaces, so the modern dialog is driven
//! through its raw vtable.

use obfstr::obfstr;
use std::path::PathBuf;

enum Pick {
    Chosen(PathBuf),
    Cancelled,
    Failed,
}

mod modern_dialog {
    use super::Pick;
    use crate::system::winutil::to_wide;
    use std::ffi::{OsString, c_void};
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use windows_sys::Win32::Foundation::{HWND, S_OK};
    use windows_sys::Win32::System::Com::{
        CLSCTX_ALL, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx, CoTaskMemFree,
        CoUninitialize,
    };
    use windows_sys::core::{GUID, HRESULT, PCWSTR, PWSTR};

    const CLSID_FILE_OPEN_DIALOG: GUID = GUID {
        data1: 0xDC1C_5A9C,
        data2: 0xE88A,
        data3: 0x4DDE,
        data4: [0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7],
    };
    const IID_IFILE_OPEN_DIALOG: GUID = GUID {
        data1: 0xD57C_7288,
        data2: 0xD4AD,
        data3: 0x4768,
        data4: [0xBE, 0x02, 0x9D, 0x96, 0x95, 0x32, 0xD9, 0x60],
    };

    const S_FALSE: HRESULT = 1;
    const HRESULT_CANCELLED: HRESULT = 0x8007_04C7_u32 as HRESULT;
    const FOS_PICKFOLDERS: u32 = 0x20;
    const FOS_FORCEFILESYSTEM: u32 = 0x40;
    const SIGDN_FILESYSPATH: u32 = 0x8005_8000;

    // Absolute vtable slots: IUnknown(0-2), IModalWindow::Show(3),
    // IFileDialog::SetOptions(9)/SetTitle(17)/GetResult(20).
    const VT_RELEASE: usize = 2;
    const VT_SHOW: usize = 3;
    const VT_SET_OPTIONS: usize = 9;
    const VT_SET_TITLE: usize = 17;
    const VT_GET_RESULT: usize = 20;
    // IShellItem::GetDisplayName(5), after its own IUnknown(0-2).
    const VT_GET_DISPLAY_NAME: usize = 5;

    unsafe fn vtable_entry(this: *mut c_void, index: usize) -> *const c_void {
        unsafe {
            let vtbl = *(this as *const *const *const c_void);
            *vtbl.add(index)
        }
    }

    unsafe fn release(this: *mut c_void) {
        unsafe {
            let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                std::mem::transmute(vtable_entry(this, VT_RELEASE));
            release(this);
        }
    }

    unsafe fn wide_len(ptr: PWSTR) -> usize {
        let mut len = 0;
        unsafe {
            while *ptr.add(len) != 0 {
                len += 1;
            }
        }
        len
    }

    pub fn pick_folder(title: &str) -> Pick {
        let init = unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32) };
        if init != S_OK && init != S_FALSE {
            // Wrong threading model (or COM down): let the legacy dialog try.
            return Pick::Failed;
        }
        let result = unsafe { pick_folder_inner(title) };
        if init == S_OK {
            unsafe {
                CoUninitialize();
            }
        }
        result
    }

    unsafe fn pick_folder_inner(title: &str) -> Pick {
        let mut dialog: *mut c_void = std::ptr::null_mut();
        let hr = unsafe {
            CoCreateInstance(
                &CLSID_FILE_OPEN_DIALOG,
                std::ptr::null_mut(),
                CLSCTX_ALL,
                &IID_IFILE_OPEN_DIALOG,
                &mut dialog,
            )
        };
        if hr != S_OK || dialog.is_null() {
            return Pick::Failed;
        }

        let failed = |dialog: *mut c_void| {
            unsafe {
                release(dialog);
            }
            Pick::Failed
        };

        let set_options: unsafe extern "system" fn(*mut c_void, u32) -> HRESULT =
            unsafe { std::mem::transmute(vtable_entry(dialog, VT_SET_OPTIONS)) };
        if unsafe { set_options(dialog, FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM) } != S_OK {
            return failed(dialog);
        }

        let wide_title = to_wide(title);
        let set_title: unsafe extern "system" fn(*mut c_void, PCWSTR) -> HRESULT =
            unsafe { std::mem::transmute(vtable_entry(dialog, VT_SET_TITLE)) };
        unsafe {
            set_title(dialog, wide_title.as_ptr());
        }

        let show: unsafe extern "system" fn(*mut c_void, HWND) -> HRESULT =
            unsafe { std::mem::transmute(vtable_entry(dialog, VT_SHOW)) };
        let hr = unsafe { show(dialog, std::ptr::null_mut()) };
        if hr == HRESULT_CANCELLED {
            unsafe {
                release(dialog);
            }
            return Pick::Cancelled;
        }
        if hr != S_OK {
            return failed(dialog);
        }

        let get_result: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> HRESULT =
            unsafe { std::mem::transmute(vtable_entry(dialog, VT_GET_RESULT)) };
        let mut item: *mut c_void = std::ptr::null_mut();
        if unsafe { get_result(dialog, &mut item) } != S_OK || item.is_null() {
            return failed(dialog);
        }
        unsafe {
            release(dialog);
        }

        let get_name: unsafe extern "system" fn(*mut c_void, u32, *mut PWSTR) -> HRESULT =
            unsafe { std::mem::transmute(vtable_entry(item, VT_GET_DISPLAY_NAME)) };
        let mut raw: PWSTR = std::ptr::null_mut();
        if unsafe { get_name(item, SIGDN_FILESYSPATH, &mut raw) } != S_OK || raw.is_null() {
            unsafe {
                release(item);
            }
            return Pick::Failed;
        }
        let path = unsafe {
            let text = OsString::from_wide(std::slice::from_raw_parts(raw, wide_len(raw)));
            CoTaskMemFree(raw.cast());
            release(item);
            PathBuf::from(text)
        };
        Pick::Chosen(path)
    }
}

mod legacy_dialog {
    use super::Pick;
    use crate::system::winutil::to_wide;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use windows_sys::Win32::Foundation::MAX_PATH;
    use windows_sys::Win32::System::Com::{CoInitialize, CoTaskMemFree};
    use windows_sys::Win32::UI::Shell::{
        BIF_EDITBOX, BIF_NEWDIALOGSTYLE, BIF_RETURNONLYFSDIRS, BROWSEINFOW, SHBrowseForFolderW,
        SHGetPathFromIDListW,
    };

    pub fn pick_folder(title: &str) -> Pick {
        let wide_title = to_wide(title);
        let mut display = [0u16; MAX_PATH as usize];
        let info = BROWSEINFOW {
            hwndOwner: std::ptr::null_mut(),
            pidlRoot: std::ptr::null_mut(),
            pszDisplayName: display.as_mut_ptr(),
            lpszTitle: wide_title.as_ptr(),
            ulFlags: BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_EDITBOX,
            lpfn: None,
            lParam: 0,
            iImage: 0,
        };
        unsafe {
            CoInitialize(std::ptr::null());
            let pidl = SHBrowseForFolderW(&info);
            if pidl.is_null() {
                return Pick::Cancelled;
            }
            let mut buffer = [0u16; MAX_PATH as usize];
            let ok = SHGetPathFromIDListW(pidl, buffer.as_mut_ptr());
            CoTaskMemFree(pidl.cast());
            if ok == 0 {
                return Pick::Failed;
            }
            let length = buffer.iter().position(|value| *value == 0).unwrap_or(0);
            let text = OsString::from_wide(&buffer[..length]);
            Pick::Chosen(PathBuf::from(text))
        }
    }
}

pub fn choose_client_root() -> Option<PathBuf> {
    let title = obfstr!("Select the Lineage 2 client folder").to_owned();
    match modern_dialog::pick_folder(&title) {
        Pick::Chosen(path) => Some(path),
        Pick::Cancelled => None,
        // The legacy dialog is still capped at MAX_PATH, but it beats no
        // dialog at all when COM is unavailable.
        Pick::Failed => match legacy_dialog::pick_folder(&title) {
            Pick::Chosen(path) => Some(path),
            Pick::Cancelled | Pick::Failed => None,
        },
    }
}
