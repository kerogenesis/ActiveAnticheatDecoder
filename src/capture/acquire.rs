use std::path::Path;
use std::time::Duration;

use crate::error::Result;
use crate::format::aac::RsaProfile;
use crate::storage::cache;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireSource {
    Cache,
    Live,
}

pub struct Acquired {
    pub profile: RsaProfile,
    pub source: AcquireSource,
}

/// Returns RsaProfile via cache or client launch
pub fn acquire_profile(
    system_dir: &Path,
    client_exe: &str,
    candidates: &[String],
    proxy_dll: &[u8],
    timeout: Duration,
) -> Result<Acquired> {
    if let Some(cached) = cache::load_cached_profile(system_dir, client_exe) {
        return Ok(Acquired { profile: cached, source: AcquireSource::Cache });
    }

    let mut spinner = crate::system::term::Spinner::new("capturing key");
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
            Ok(Acquired { profile, source: AcquireSource::Live })
        }
        Err(e) => Err(e),
    }
}
