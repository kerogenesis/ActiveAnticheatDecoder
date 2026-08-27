pub mod acquire;
pub mod live;

pub mod strings {
    use obfstr::obfstr;

    #[inline(never)]
    pub fn pipe_env() -> String {
        obfstr!("AA_DECODER_PIPE").to_owned()
    }

    #[inline(never)]
    fn pipe_prefix() -> String {
        obfstr!(r"\\.\pipe\aa_decoder").to_owned()
    }

    #[inline(never)]
    pub fn pipe_name(process_id: u32, nonce: u128) -> String {
        let prefix = pipe_prefix();
        format!("{prefix}_{process_id}_{nonce}")
    }

    #[inline(never)]
    pub fn allow_debug_env() -> String {
        obfstr!("AA_DECODER_ALLOW_DEBUG").to_owned()
    }
}

pub mod noise {
    #[inline(never)]
    pub fn stir(tag: u32) -> u32 {
        let mut state = std::hint::black_box(tag ^ 0x9E37_79B9);
        let rounds = 5 + (state & 7);
        for round in 0..rounds {
            state =
                state.rotate_left(5).wrapping_mul(0x045D_9F3B).wrapping_add(round ^ 0xA5A5_5A5A);
            let selector = std::hint::black_box(state) & 1;
            let mask = 0u32.wrapping_sub(selector);
            state ^= mask & round.wrapping_mul(0x27D4_EB2D);
            state = std::hint::black_box(state.rotate_right(selector + 1));
        }
        std::hint::black_box(state)
    }
}

pub mod runtime {
    use std::ffi::OsStr;
    use std::time::{Duration, Instant};

    use super::{noise, strings};
    use crate::error::{Error, Result};

    const DEBUGGER_THRESHOLD: u32 = 2;

    pub fn pre_capture_gate() -> Result<()> {
        noise::stir(0xC4A7_0011);
        if allow_debug_override() {
            return Ok(());
        }

        let score = debugger_score();
        if score >= DEBUGGER_THRESHOLD {
            return Err(Error::ProtectedEnvironment { override_name: strings::allow_debug_env() });
        }
        Ok(())
    }

    fn allow_debug_override() -> bool {
        let key = strings::allow_debug_env();
        let Some(value) = std::env::var_os(OsStr::new(&key)) else {
            return false;
        };
        matches!(value.to_string_lossy().as_ref(), "1" | "true" | "TRUE" | "yes" | "YES")
    }

    #[cfg(windows)]
    fn debugger_score() -> u32 {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            CheckRemoteDebuggerPresent, IsDebuggerPresent,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let mut score = 0;
        unsafe {
            if IsDebuggerPresent() != 0 {
                score += 1;
            }
            let mut present = 0;
            if CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut present) != 0 && present != 0 {
                score += 1;
            }
        }
        if timing_anomaly() {
            score += 1;
        }
        score
    }

    #[cfg(not(windows))]
    fn debugger_score() -> u32 {
        0
    }

    fn timing_anomaly() -> bool {
        let start = Instant::now();
        let mut value = 0x6A09_E667u32;
        for round in 0..20_000u32 {
            value = std::hint::black_box(
                value.rotate_left((round & 15) + 1).wrapping_add(round ^ 0xBB67_AE85),
            );
        }
        std::hint::black_box(value);
        start.elapsed() > Duration::from_millis(250)
    }
}

#[cfg(test)]
mod tests {
    use super::strings;

    #[test]
    fn protected_strings_decode_to_their_runtime_values() {
        assert_eq!(strings::pipe_env(), "AA_DECODER_PIPE");
        assert_eq!(strings::allow_debug_env(), "AA_DECODER_ALLOW_DEBUG");
        assert_eq!(strings::pipe_name(7, 11), r"\\.\pipe\aa_decoder_7_11");
    }
}
