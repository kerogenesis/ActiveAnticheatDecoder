//! Runtime configuration from config.ini next to the executable; missing
//! file or key falls back to built-in defaults (ddraw first, auto-decode on).
use obfstr::obfstr;
use std::collections::HashSet;
use std::path::Path;

fn with_dll_extension(name: &str) -> String {
    if name.to_ascii_lowercase().ends_with(obfstr!(".dll")) {
        name.to_owned()
    } else {
        format!("{}{}", name, obfstr!(".dll"))
    }
}

/// A configured name must be a plain file name
fn valid_proxy_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.contains(['/', '\\'])
        && name != "."
        && name != ".."
}

fn parse_ini_key(text: &str, target_key: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=')
            && key.trim().eq_ignore_ascii_case(target_key)
        {
            let val = value.trim();
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

fn read_config(config_path: &Path) -> Option<String> {
    std::fs::read_to_string(config_path).ok()
}

fn candidates_from(configured: Option<String>) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(name) = configured.filter(|name| valid_proxy_name(name)) {
        names.push(with_dll_extension(&name));
    }
    names.push(obfstr!("ddraw.dll").to_owned());
    names.push(obfstr!("d3d9.dll").to_owned());
    names.push(obfstr!("xinput1_4.dll").to_owned());

    let mut seen = HashSet::new();
    names.retain(|name| seen.insert(name.to_ascii_lowercase()));
    names
}

pub fn proxy_candidates(config_path: &Path) -> Vec<String> {
    let configured = read_config(config_path)
        .and_then(|text| parse_ini_key(&text, obfstr!("proxy_name")))
        .unwrap_or_else(|| obfstr!("ddraw.dll").to_owned());
    candidates_from(Some(configured))
}

pub fn scryde_gamekitdata_auto_decode(config_path: &Path) -> bool {
    read_config(config_path)
        .and_then(|text| parse_ini_key(&text, obfstr!("scryde_gamekitdata_auto_decode")))
        .map(|val| !matches!(val.trim().to_lowercase().as_str(), "false" | "0" | "no"))
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_is_added_when_missing() {
        assert_eq!(with_dll_extension("ddraw"), "ddraw.dll");
        assert_eq!(with_dll_extension("WindowsCodecs.dll"), "WindowsCodecs.dll");
        assert_eq!(with_dll_extension("XInput1_3.DLL"), "XInput1_3.DLL");
    }

    #[test]
    fn default_candidates_are_ddraw_d3d9_xinput() {
        let names = candidates_from(None);
        assert_eq!(names, vec!["ddraw.dll", "d3d9.dll", "xinput1_4.dll"]);
    }

    #[test]
    fn missing_config_file_defaults_to_ddraw_first() {
        let missing = std::env::temp_dir().join("aac-decoder-missing-config-test.ini");
        let _ = std::fs::remove_file(&missing);
        let names = proxy_candidates(&missing);
        assert_eq!(names, vec!["ddraw.dll", "d3d9.dll", "xinput1_4.dll"]);
    }

    #[test]
    fn configured_name_leads_and_is_not_duplicated() {
        let names = candidates_from(Some("d3d9".to_owned()));
        assert_eq!(names, vec!["d3d9.dll", "ddraw.dll", "xinput1_4.dll"]);
    }

    #[test]
    fn traversal_names_fall_back_to_default() {
        for evil in ["../evil", r"sub\dir", "..", "", "a/b.dll"] {
            let names = candidates_from(Some(evil.to_owned()));
            assert_eq!(names, vec!["ddraw.dll", "d3d9.dll", "xinput1_4.dll"], "{evil}");
        }
    }
}
