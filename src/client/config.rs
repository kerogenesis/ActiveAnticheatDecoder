//! Runtime configuration read from `config.ini` next to the executable.
//!
//! A missing file or key falls back to built-in defaults:
//! * `proxy_name` = `ddraw.dll`
//! * `scryde_gamekitdata_auto_decode` = `true`
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
    if let Some(name) = configured {
        names.push(with_dll_extension(&name));
    }
    names.push(obfstr!("ddraw.dll").to_owned());
    names.push(obfstr!("xinput1_4.dll").to_owned());
    names.push(obfstr!("RESAMPLEDMO.dll").to_owned());
    names.push(obfstr!("WindowsCodecs.dll").to_owned());

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
    fn default_candidates_end_with_windowscodecs() {
        let names = candidates_from(None);
        assert_eq!(names.len(), 4);
        assert_eq!(names[0], "ddraw.dll");
        assert_eq!(*names.last().unwrap(), "WindowsCodecs.dll");
    }

    #[test]
    fn missing_config_file_defaults_to_ddraw_first() {
        let missing = std::env::temp_dir().join("aac-decoder-missing-config-test.ini");
        let _ = std::fs::remove_file(&missing);
        let names = proxy_candidates(&missing);
        assert_eq!(names[0], "ddraw.dll");
        assert_eq!(*names.last().unwrap(), "WindowsCodecs.dll");
        assert_eq!(names.len(), 4);
    }

    #[test]
    fn configured_name_leads_and_is_not_duplicated() {
        let names = candidates_from(Some("ddraw".to_owned()));
        assert_eq!(names[0], "ddraw.dll");
        assert_eq!(names.len(), 4);
        assert_eq!(names.iter().filter(|name| *name == "ddraw.dll").count(), 1);
    }
}
