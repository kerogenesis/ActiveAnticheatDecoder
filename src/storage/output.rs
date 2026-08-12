//! Output-path construction, plus the small date helper for the output folder.

use obfstr::obfstr;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, IoAction, Result};
use crate::format::manifest;

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

fn today_stamp() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0);
    let (year, month, day) = civil_from_days(seconds / 86_400);
    format!("{day:02}_{month:02}_{year:04}")
}

pub fn executable_directory() -> PathBuf {
    env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from(obfstr!(".")))
}

pub fn output_root() -> PathBuf {
    executable_directory().join(format!("{}_{}", obfstr!("clean_files"), today_stamp()))
}

pub fn relative(path: &Path, base: &Path) -> String {
    let trimmed = path.strip_prefix(base).unwrap_or(path);
    trimmed.display().to_string()
}

pub fn mirrored_path(root: &Path, source: &Path, output_root: &Path) -> PathBuf {
    let relative = source.strip_prefix(root).unwrap_or(source);
    output_root.join(relative)
}

pub fn output_path_for(root: &Path, source: &Path, output_root: &Path, suffix: &str) -> PathBuf {
    let relative = source.strip_prefix(root).unwrap_or(source);
    let mut destination = output_root.join(relative);
    destination.set_file_name(legacy_name(source, suffix));
    destination
}

pub fn legacy_name(source: &Path, suffix: &str) -> String {
    let stem = source
        .file_stem()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| obfstr!("output").to_owned());
    format!("{stem}{suffix}")
}

pub fn is_legacy_path(path: &Path) -> bool {
    path.file_name()
        .map(|value| manifest::is_legacy_name(&value.to_string_lossy()))
        .unwrap_or(false)
}

pub fn write_output(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|source| Error::io(IoAction::CreateDir, parent, source))?;
    }
    fs::write(path, bytes).map_err(|source| Error::io(IoAction::Write, path, source))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
    }

    #[test]
    fn output_path_mirrors_relative_layout() {
        let root = Path::new("/client");
        let source = Path::new("/client/system/armorgrp.dat");
        let out = Path::new("/out");
        assert_eq!(
            mirrored_path(root, source, out),
            PathBuf::from("/out/system/armorgrp.dat")
        );
        assert_eq!(
            output_path_for(root, source, out, "_clean.txt"),
            PathBuf::from("/out/system/armorgrp_clean.txt")
        );
    }

    #[test]
    fn files_sharing_a_stem_do_not_collide() {
        let root = Path::new("/client");
        let out = Path::new("/out");
        let unreal = mirrored_path(root, Path::new("/client/system/interface.u"), out);
        let xdat = mirrored_path(root, Path::new("/client/system/interface.xdat"), out);
        assert_eq!(unreal, PathBuf::from("/out/system/interface.u"));
        assert_eq!(xdat, PathBuf::from("/out/system/interface.xdat"));
        assert_ne!(unreal, xdat);
    }

    #[test]
    fn relative_paths_are_trimmed_to_the_root() {
        let root = Path::new("/client");
        let source = Path::new("/client/system/armorgrp.dat");
        assert_eq!(relative(source, root), "system/armorgrp.dat");
    }

    #[test]
    fn dropped_legacy_file_is_routed_by_name() {
        assert!(manifest::is_legacy_name("ft_12.dat"));
        assert!(!manifest::is_legacy_name("armorgrp.dat"));
        assert!(is_legacy_path(Path::new("D:/downloads/FT_1223859.dat")));
        assert!(!is_legacy_path(Path::new("D:/client/system/armorgrp.dat")));
    }

    #[test]
    fn silent_legacy_output_sits_next_to_the_exe() {
        let name = legacy_name(Path::new("D:/downloads/ft_1223859.dat"), "_clean.txt");
        assert_eq!(name, "ft_1223859_clean.txt");
    }
}
