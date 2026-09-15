//! Re-export of the shared helpers so `proxy`/`payload` keep one import path.

pub(super) use aa_shared::{read_u16, read_u32, to_hex, wide_nul};
