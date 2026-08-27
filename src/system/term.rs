//! Console presentation: colour, spinners and small animations.

use obfstr::obfstr;
use std::io::{self, IsTerminal, Write};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum Color {
    Green,
    Red,
    Yellow,
    Dim,
}

impl Color {
    const fn ansi(self) -> &'static str {
        match self {
            Self::Green => "\x1b[32m",
            Self::Red => "\x1b[31m",
            Self::Yellow => "\x1b[33m",
            Self::Dim => "\x1b[90m",
        }
    }
}

const RESET: &str = "\x1b[0m";

const SPINNER_FRAMES: [&str; 4] = ["|", "/", "-", "\\"];
const SPINNER_INTERVAL: Duration = Duration::from_millis(80);

static STYLED: OnceLock<bool> = OnceLock::new();
static CONSOLE_MUTEX: Mutex<()> = Mutex::new(());

mod windows_console {
    use crate::system::winutil::to_wide;
    use std::sync::atomic::{AtomicBool, Ordering};
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Globalization::CP_UTF8;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Console::{
        ATTACH_PARENT_PROCESS, AllocConsole, AttachConsole, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        GetConsoleMode, GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        SetConsoleMode, SetConsoleOutputCP, SetStdHandle,
    };

    static READY: AtomicBool = AtomicBool::new(false);
    static OWNED: AtomicBool = AtomicBool::new(false);

    unsafe fn open_console_device(name: &str) -> *mut core::ffi::c_void {
        let wide = to_wide(name);
        unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                core::ptr::null(),
                OPEN_EXISTING,
                0,
                core::ptr::null_mut(),
            )
        }
    }

    pub fn ensure() -> bool {
        if READY.load(Ordering::Relaxed) {
            return OWNED.load(Ordering::Relaxed);
        }
        let owned = unsafe { wire() };
        OWNED.store(owned, Ordering::Relaxed);
        READY.store(true, Ordering::Relaxed);
        owned
    }

    pub fn owns() -> bool {
        OWNED.load(Ordering::Relaxed)
    }

    unsafe fn wire() -> bool {
        unsafe {
            let existing = GetStdHandle(STD_OUTPUT_HANDLE);
            if !existing.is_null() && existing != INVALID_HANDLE_VALUE {
                return false;
            }
            let owned = if AttachConsole(ATTACH_PARENT_PROCESS) != 0 {
                false
            } else {
                AllocConsole();
                true
            };
            let out = open_console_device("CONOUT$");
            if out != INVALID_HANDLE_VALUE {
                SetStdHandle(STD_OUTPUT_HANDLE, out);
                SetStdHandle(STD_ERROR_HANDLE, out);
            }
            let input = open_console_device("CONIN$");
            if input != INVALID_HANDLE_VALUE {
                SetStdHandle(STD_INPUT_HANDLE, input);
            }
            owned
        }
    }

    pub fn enable_ansi() -> bool {
        unsafe {
            SetConsoleOutputCP(CP_UTF8);
            let handle = GetStdHandle(STD_OUTPUT_HANDLE);
            if handle.is_null() {
                return false;
            }
            let mut mode = 0u32;
            if GetConsoleMode(handle, &mut mode) == 0 {
                return false;
            }
            SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
        }
    }
}

#[link(name = "ucrt")]
unsafe extern "C" {
    fn _getch() -> i32;
}

pub fn ensure_console() {
    windows_console::ensure();
    let interactive = io::stdout().is_terminal();
    let styled = interactive && windows_console::enable_ansi();
    let _ = STYLED.set(styled);
}

pub fn owns_console() -> bool {
    windows_console::owns()
}

fn styled() -> bool {
    *STYLED.get().unwrap_or(&false)
}

fn paint(colour: Color, text: &str) -> String {
    if styled() { format!("{}{text}{RESET}", colour.ansi()) } else { text.to_owned() }
}

pub fn banner() {
    println!();
    println!("ActiveAnticheat Decoder");
    println!();
}

pub fn field_line(label: &str, value: &str) {
    let _guard = CONSOLE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    println!("{}  {value}", paint(Color::Yellow, label));
}

pub fn field_label(label: &str) {
    let _guard = CONSOLE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    println!("{}", paint(Color::Yellow, label));
}

pub fn plain_line(label: &str, value: &str) {
    let _guard = CONSOLE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    println!("{label}  {value}");
}

pub fn plain_label(label: &str) {
    let _guard = CONSOLE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    println!("{label}");
}

pub fn error(text: &str) {
    let _guard = CONSOLE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    println!("  {}", paint(Color::Red, text));
}

pub fn step_result(index: usize, total: usize, label: &str, is_ok: bool, reason: Option<&str>) {
    let _guard = CONSOLE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let width = total.to_string().len();
    if is_ok {
        let prefix = paint(Color::Green, &format!("  [{index:>width$}/{total}]"));
        println!("  {prefix} {label}");
    } else {
        let prefix = paint(Color::Red, &format!("  [{index:>width$}/{total}]"));
        let err = reason.unwrap_or_default();
        println!("  {prefix} {label} (Error: {err})");
    }
}

pub struct Spinner {
    label: String,
    frame: usize,
    last_draw: Option<Instant>,
    active: bool,
}

impl Spinner {
    pub fn new(label: &str) -> Self {
        Self { label: label.to_owned(), frame: 0, last_draw: None, active: styled() }
    }

    fn ready(&mut self) -> bool {
        if !self.active {
            return false;
        }
        if let Some(last) = self.last_draw
            && last.elapsed() < SPINNER_INTERVAL
        {
            return false;
        }
        self.last_draw = Some(Instant::now());
        self.frame += 1;
        true
    }

    fn current_frame(&self) -> &'static str {
        SPINNER_FRAMES[(self.frame - 1) % SPINNER_FRAMES.len()]
    }

    pub fn tick(&mut self, count: usize) {
        if !self.ready() {
            return;
        }
        let (frame, label) = (self.current_frame(), &self.label);
        print!("\r  {frame} {label} {count} {}\x1b[K", obfstr!("files"));
        let _ = io::stdout().flush();
    }

    pub fn spin(&mut self) {
        if !self.ready() {
            return;
        }
        let (frame, label) = (self.current_frame(), &self.label);
        print!("\r  {frame} {label} ...\x1b[K");
        let _ = io::stdout().flush();
    }

    pub fn finish(self) {
        if self.active {
            print!("\r\x1b[K");
            let _ = io::stdout().flush();
        }
    }
}

pub fn press_any_key(message: &str) {
    println!();
    print!("  {}", paint(Color::Dim, message));
    let _ = io::stdout().flush();
    unsafe {
        _getch();
    }
    println!();
}
