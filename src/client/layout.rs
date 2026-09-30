//! Resolving the L2 client layout from a folder the user points at.

use camino::{Utf8Path, Utf8PathBuf};
use obfstr::obfstr;
use std::sync::LazyLock;
use walkdir::WalkDir;

pub struct ClientLayout {
    pub root: Utf8PathBuf,
    pub system_dir: Utf8PathBuf,
    pub executable: String,
}
impl ClientLayout {
    pub fn is_scryde(&self) -> bool {
        self.executable.eq_ignore_ascii_case(scryde_executable())
    }
}

struct ClientVariant {
    system_dir: String,
    executable: String,
}

static CLIENT_VARIANTS: LazyLock<[ClientVariant; 2]> = LazyLock::new(|| {
    [
        ClientVariant {
            system_dir: obfstr!("system").to_owned(),
            executable: obfstr!("l2.exe").to_owned(),
        },
        ClientVariant {
            system_dir: obfstr!("Scryde").to_owned(),
            executable: obfstr!("ScrydeGame.exe").to_owned(),
        },
    ]
});

const SCRYDE_VARIANT: usize = 1;

fn scryde_variant() -> &'static ClientVariant {
    &CLIENT_VARIANTS[SCRYDE_VARIANT]
}

fn scryde_executable() -> &'static str {
    scryde_variant().executable.as_str()
}

fn resolve_shallow(picked: &Utf8Path) -> Option<ClientLayout> {
    for variant in CLIENT_VARIANTS.iter() {
        if picked.join(&variant.executable).is_file() {
            let root = picked.parent().unwrap_or(picked).to_path_buf();
            return Some(ClientLayout {
                root,
                system_dir: picked.to_path_buf(),
                executable: variant.executable.clone(),
            });
        }
    }

    for variant in CLIENT_VARIANTS.iter() {
        let system_dir = picked.join(&variant.system_dir);
        if system_dir.join(&variant.executable).is_file() {
            return Some(ClientLayout {
                root: picked.to_path_buf(),
                system_dir,
                executable: variant.executable.clone(),
            });
        }
    }

    None
}

fn walk_for_executable(picked: &Utf8Path) -> Option<ClientLayout> {
    for entry in WalkDir::new(picked).max_depth(32).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file()
            && let Some(utf8_path) = Utf8Path::from_path(entry.path())
            && let Some(name) = utf8_path.file_name()
        {
            for variant in CLIENT_VARIANTS.iter() {
                if name.eq_ignore_ascii_case(&variant.executable) {
                    let system_dir = utf8_path.parent().unwrap_or(picked).to_path_buf();
                    let root = system_dir.parent().unwrap_or(&system_dir).to_path_buf();
                    return Some(ClientLayout {
                        root,
                        system_dir,
                        executable: variant.executable.clone(),
                    });
                }
            }
        }
    }

    None
}

pub fn resolve_client_layout(picked: &std::path::Path) -> Option<ClientLayout> {
    let picked = Utf8Path::from_path(picked)?;
    resolve_shallow(picked).or_else(|| walk_for_executable(picked))
}

pub fn resolve_client_layout_with_ancestors(picked: &std::path::Path) -> Option<ClientLayout> {
    let mut top = picked;
    for _ in 0..4 {
        let Some(utf8) = Utf8Path::from_path(top) else { break };
        if let Some(layout) = resolve_shallow(utf8) {
            return Some(layout);
        }
        match top.parent() {
            Some(parent) => top = parent,
            None => break,
        }
    }
    let utf8 = Utf8Path::from_path(picked)?;
    walk_for_executable(utf8)
}
