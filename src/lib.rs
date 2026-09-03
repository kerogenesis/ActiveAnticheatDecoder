//! Decoder library for `ActiveAnticheat` files.
//!
//! Lint gates live in `Cargo.toml` (`[lints.clippy]`) so they apply to the
//! library, the binary and `build.rs` alike.

pub mod capture;
pub mod client;
pub mod crypto;
pub mod error;
pub mod format;
pub mod run;
pub mod storage;
pub mod system;
