//! Decoder library for `ActiveAnticheat` files.

#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::large_stack_arrays)]
#![allow(clippy::incompatible_msrv)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::implicit_clone)]
#![allow(clippy::format_collect)]

pub mod capture;
pub mod client;
pub mod crypto;
pub mod error;
pub mod format;
pub mod run;
pub mod storage;
pub mod system;
