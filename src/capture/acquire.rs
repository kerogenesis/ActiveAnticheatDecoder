use std::path::Path;
use std::time::Duration;

use crate::error::Result;
use crate::format::aac::RsaProfile;
use crate::storage::cache;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOrigin {
    Cached,
    Captured,
}

pub struct CapturedKey {
    pub rsa_profile: RsaProfile,
    pub source: KeyOrigin,
}

/// Returns an [`RsaProfile`] via cache or client launch.
pub fn load_or_capture_key(
    system_dir: &Path,
    exe_name: &str,
    proxy_candidates: &[String],
    proxy_dll: &[u8],
    timeout: Duration,
) -> Result<CapturedKey> {
    if let Some(cached) = cache::load_cached_profile(system_dir, exe_name) {
        return Ok(CapturedKey { rsa_profile: cached, source: KeyOrigin::Cached });
    }

    let mut spinner = crate::system::term::Spinner::new("capturing key");
    let result = crate::capture::live::capture_key(
        system_dir,
        exe_name,
        proxy_candidates,
        proxy_dll,
        timeout,
        &mut || spinner.pulse(),
    );
    spinner.finish();

    match result {
        Ok(rsa_profile) => {
            cache::save_cached_profile(system_dir, exe_name, &rsa_profile);
            Ok(CapturedKey { rsa_profile, source: KeyOrigin::Captured })
        }
        Err(capture_error) => Err(capture_error),
    }
}
