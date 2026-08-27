//! Resolving the L2 client layout from a folder the user points at.

use camino::{Utf8Path, Utf8PathBuf};
use obfstr::obfstr;
use walkdir::WalkDir;

pub struct ClientLayout {
    pub root: Utf8PathBuf,
    pub system_dir: Utf8PathBuf,
    pub executable: String,
}

impl ClientLayout {
    pub fn is_scryde(&self) -> bool {
        self.executable.eq_ignore_ascii_case(obfstr!("ScrydeGame.exe"))
    }
}

pub fn resolve_client_layout(picked: &std::path::Path) -> Option<ClientLayout> {
    let picked = Utf8Path::from_path(picked)?;
    let sys_dir_name = obfstr!("system").to_owned();
    let l2_exe_name = obfstr!("l2.exe").to_owned();
    let scryde_dir_name = obfstr!("Scryde").to_owned();
    let scryde_exe_name = obfstr!("ScrydeGame.exe").to_owned();

    let layouts = [(&sys_dir_name, &l2_exe_name), (&scryde_dir_name, &scryde_exe_name)];

    for (_, exe) in &layouts {
        if picked.join(exe).is_file() {
            let root = picked.parent().unwrap_or(picked).to_path_buf();
            return Some(ClientLayout {
                root,
                system_dir: picked.to_path_buf(),
                executable: (*exe).clone(),
            });
        }
    }

    for (system_name, exe) in &layouts {
        let system_dir = picked.join(system_name);
        if system_dir.join(exe).is_file() {
            return Some(ClientLayout {
                root: picked.to_path_buf(),
                system_dir,
                executable: (*exe).clone(),
            });
        }
    }

    for entry in WalkDir::new(picked).max_depth(32).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file()
            && let Some(utf8_path) = Utf8Path::from_path(entry.path())
            && let Some(name) = utf8_path.file_name()
        {
            for (_, exe) in &layouts {
                if name.eq_ignore_ascii_case(exe) {
                    let system_dir = utf8_path.parent().unwrap_or(picked).to_path_buf();
                    let root = system_dir.parent().unwrap_or(&system_dir).to_path_buf();
                    return Some(ClientLayout { root, system_dir, executable: (*exe).clone() });
                }
            }
        }
    }

    None
}
