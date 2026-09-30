pub mod elevation;
pub mod term;
pub mod ui;
pub mod winutil;

pub use elevation::{is_elevated, require_elevation, show_elevation_required};

pub use term::{
    Spinner, banner, ensure_console, error_line, owns_console, press_any_key, print_indexed_result,
    result_line, section_title, status_line,
};
pub use ui::choose_client_root;
pub use winutil::{OwnedHandle, to_wide};
