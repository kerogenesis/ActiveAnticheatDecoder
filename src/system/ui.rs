//! Native "browse for folder" dialog, for the double-click case.

use obfstr::obfstr;
use std::path::PathBuf;

mod windows_dialog {
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

    pub fn pick_folder(title: &str) -> Option<PathBuf> {
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
                return None;
            }
            let mut buffer = [0u16; MAX_PATH as usize];
            let ok = SHGetPathFromIDListW(pidl, buffer.as_mut_ptr());
            CoTaskMemFree(pidl.cast());
            if ok == 0 {
                return None;
            }
            let length = buffer.iter().position(|value| *value == 0).unwrap_or(0);
            let text = OsString::from_wide(&buffer[..length]);
            Some(PathBuf::from(text))
        }
    }
}

pub fn choose_client_root() -> Option<PathBuf> {
    windows_dialog::pick_folder(obfstr!("Select the Lineage 2 client folder"))
}
