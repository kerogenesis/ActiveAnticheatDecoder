//! Resolving the L2 client layout from a folder the user points at.

use camino::{Utf8Path, Utf8PathBuf};
use obfstr::obfstr;
use std::sync::LazyLock;
use walkdir::WalkDir;

pub struct ClientLayout {
    pub client_dir: Utf8PathBuf,
    pub system_dir: Utf8PathBuf,
    pub exe_name: String,
}
impl ClientLayout {
    pub fn is_scryde(&self) -> bool {
        self.exe_name.eq_ignore_ascii_case(scryde_executable())
    }
}

struct ClientVariant {
    system_dir: String,
    exe_name: String,
}

static CLIENT_VARIANTS: LazyLock<[ClientVariant; 2]> = LazyLock::new(|| {
    [
        ClientVariant {
            system_dir: obfstr!("system").to_owned(),
            exe_name: obfstr!("l2.exe").to_owned(),
        },
        ClientVariant {
            system_dir: obfstr!("Scryde").to_owned(),
            exe_name: obfstr!("ScrydeGame.exe").to_owned(),
        },
    ]
});

const SCRYDE_VARIANT: usize = 1;

fn scryde_variant() -> &'static ClientVariant {
    &CLIENT_VARIANTS[SCRYDE_VARIANT]
}

fn scryde_executable() -> &'static str {
    scryde_variant().exe_name.as_str()
}

fn resolve_nearby(picked: &Utf8Path) -> Option<ClientLayout> {
    for variant in CLIENT_VARIANTS.iter() {
        if picked.join(&variant.exe_name).is_file() {
            let client_dir = picked.parent().unwrap_or(picked).to_path_buf();
            return Some(ClientLayout {
                client_dir,
                system_dir: picked.to_path_buf(),
                exe_name: variant.exe_name.clone(),
            });
        }
    }

    for variant in CLIENT_VARIANTS.iter() {
        let system_dir = picked.join(&variant.system_dir);
        if system_dir.join(&variant.exe_name).is_file() {
            return Some(ClientLayout {
                client_dir: picked.to_path_buf(),
                system_dir,
                exe_name: variant.exe_name.clone(),
            });
        }
    }

    None
}

fn search_executable_tree(picked: &Utf8Path) -> Option<ClientLayout> {
    for entry in WalkDir::new(picked).max_depth(32).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file()
            && let Some(utf8_path) = Utf8Path::from_path(entry.path())
            && let Some(name) = utf8_path.file_name()
        {
            for variant in CLIENT_VARIANTS.iter() {
                if name.eq_ignore_ascii_case(&variant.exe_name) {
                    let system_dir = utf8_path.parent().unwrap_or(picked).to_path_buf();
                    let client_dir = system_dir.parent().unwrap_or(&system_dir).to_path_buf();
                    return Some(ClientLayout {
                        client_dir,
                        system_dir,
                        exe_name: variant.exe_name.clone(),
                    });
                }
            }
        }
    }

    None
}

pub fn resolve_from_client_dir(picked: &std::path::Path) -> Option<ClientLayout> {
    let picked = Utf8Path::from_path(picked)?;
    resolve_nearby(picked).or_else(|| search_executable_tree(picked))
}

pub fn resolve_from_nested_path(picked: &std::path::Path) -> Option<ClientLayout> {
    let mut top = picked;
    for _ in 0..4 {
        let Some(utf8) = Utf8Path::from_path(top) else { break };
        if let Some(layout) = resolve_nearby(utf8) {
            return Some(layout);
        }
        match top.parent() {
            Some(parent) => top = parent,
            None => break,
        }
    }
    let utf8 = Utf8Path::from_path(picked)?;
    search_executable_tree(utf8)
}
