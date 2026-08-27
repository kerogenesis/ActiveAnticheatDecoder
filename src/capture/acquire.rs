use std::path::Path;
use std::time::Duration;

use crate::format::aac::RsaProfile;
use crate::storage::cache;
use crate::system::term;

/// Returns `RsaProfile` via cache or client launch.
pub fn acquire_profile(
    system_dir: &Path,
    client_exe: &str,
    candidates: &[String],
    proxy_dll: &[u8],
    timeout: Duration,
) -> Result<RsaProfile, crate::error::Error> {
    if let Some(cached) = cache::load_cached_profile(system_dir, client_exe) {
        term::field_line("+ Key:", "from cache");
        return Ok(cached);
    }

    let mut spinner = term::Spinner::new("capturing key");
    let result = crate::capture::live::capture_key(
        system_dir,
        client_exe,
        candidates,
        proxy_dll,
        timeout,
        &mut || spinner.spin(),
    );
    spinner.finish();

    match result {
        Ok(profile) => {
            cache::save_cached_profile(system_dir, client_exe, &profile);
            term::field_line("+ Key:", "captured live, cached for next run");
            Ok(profile)
        }
        Err(e) => Err(e),
    }
}
