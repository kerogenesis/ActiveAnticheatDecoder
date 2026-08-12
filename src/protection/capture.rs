//! Live RSA key capture.

use obfstr::obfstr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::{
    ERROR_PIPE_CONNECTED, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{PIPE_ACCESS_INBOUND, ReadFile};
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use windows_sys::Win32::System::Environment::SetEnvironmentVariableW;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, PROCESS_INFORMATION, ResumeThread, STARTUPINFOW,
    TerminateProcess, WaitForSingleObject,
};
use windows_sys::core::BOOL;

use super::{noise, runtime, strings};
use crate::error::{Error, IoAction, Result};
use crate::format::aac;
use crate::system::winutil::{OwnedHandle, to_wide};

const PIPE_IN_BUFFER: u32 = 64 * 1024;
const EXIT_WAIT_MS: u32 = 5_000;
const DELETE_ATTEMPTS: usize = 40;
const DELETE_RETRY: Duration = Duration::from_millis(50);
const TERMINATED_BY_DECODER: u32 = 1;

static PROXY_TO_CLEAN: Mutex<Option<PathBuf>> = Mutex::new(None);
static JOB_HANDLE: AtomicUsize = AtomicUsize::new(0);

unsafe extern "system" fn console_ctrl_handler(_ctrl_type: u32) -> BOOL {
    let job = JOB_HANDLE.swap(0, Ordering::SeqCst);
    if job != 0
        && let Some(job) = OwnedHandle::from_raw(job as HANDLE)
    {
        unsafe {
            TerminateJobObject(job.as_raw(), TERMINATED_BY_DECODER);
        }
    }
    if let Some(path) = take_pending_proxy() {
        remove_proxy(&path);
    }
    0
}

fn take_pending_proxy() -> Option<PathBuf> {
    PROXY_TO_CLEAN.lock().ok()?.take()
}

fn remove_proxy(path: &Path) {
    for _ in 0..DELETE_ATTEMPTS {
        match std::fs::remove_file(path) {
            Ok(()) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => thread::sleep(DELETE_RETRY),
        }
    }
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or(0)
}

pub fn capture_key(
    system_dir: &Path,
    client_exe: &str,
    candidates: &[String],
    dll_bytes: &[u8],
    timeout: Duration,
    on_wait: &mut dyn FnMut(),
) -> Result<aac::RsaProfile> {
    if dll_bytes.is_empty() {
        return Err(Error::ProxyDllMissing);
    }
    if !system_dir.is_dir() {
        return Err(Error::NoSystemFolder {
            path: system_dir.to_path_buf(),
        });
    }
    let client = system_dir.join(client_exe);
    if !client.is_file() {
        return Err(Error::NoClientExe {
            exe: client_exe.to_owned(),
            directory: system_dir.to_path_buf(),
        });
    }
    runtime::pre_capture_gate()?;
    noise::stir(0xC4A7_0011);
    let dll_path = write_proxy(system_dir, candidates, dll_bytes)?;
    if let Ok(mut guard) = PROXY_TO_CLEAN.lock() {
        *guard = Some(dll_path);
    }
    unsafe {
        SetConsoleCtrlHandler(Some(console_ctrl_handler), 1);
    }
    let result = capture(&client, system_dir, timeout, on_wait);
    if let Some(path) = take_pending_proxy() {
        remove_proxy(&path);
    }
    unsafe {
        SetConsoleCtrlHandler(Some(console_ctrl_handler), 0);
    }
    result
}

fn write_proxy(system_dir: &Path, candidates: &[String], bytes: &[u8]) -> Result<PathBuf> {
    for name in candidates {
        let path = system_dir.join(name);
        if path.exists() {
            continue;
        }
        std::fs::write(&path, bytes).map_err(|source| Error::io(IoAction::Write, &path, source))?;
        return Ok(path);
    }
    Err(Error::ProxyNamesTaken)
}

fn capture(
    client: &Path,
    cwd: &Path,
    timeout: Duration,
    on_wait: &mut dyn FnMut(),
) -> Result<aac::RsaProfile> {
    let pipe_name = strings::pipe_name(std::process::id(), now_millis());
    let wide_pipe = to_wide(&pipe_name);
    let pipe_raw = unsafe {
        CreateNamedPipeW(
            wide_pipe.as_ptr(),
            PIPE_ACCESS_INBOUND,
            0,
            1,
            0,
            PIPE_IN_BUFFER,
            0,
            std::ptr::null(),
        )
    };
    let pipe = OwnedHandle::from_raw(pipe_raw).ok_or(Error::PipeCreate)?;
    let env_var = strings::pipe_env();
    let env_name = to_wide(&env_var);
    unsafe {
        SetEnvironmentVariableW(env_name.as_ptr(), wide_pipe.as_ptr());
    }
    let job_raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    let job = OwnedHandle::from_raw(job_raw);
    let job_handle = job
        .as_ref()
        .map(OwnedHandle::as_raw)
        .unwrap_or(std::ptr::null_mut());
    let (process, main_thread) = match launch_suspended(client, cwd, job_handle) {
        Ok(pair) => pair,
        Err(error) => {
            unsafe {
                SetEnvironmentVariableW(env_name.as_ptr(), std::ptr::null());
            }
            return Err(error);
        }
    };
    unsafe {
        SetEnvironmentVariableW(env_name.as_ptr(), std::ptr::null());
    }
    let job_bits = job
        .map(OwnedHandle::into_raw)
        .unwrap_or(std::ptr::null_mut()) as usize;
    JOB_HANDLE.store(job_bits, Ordering::SeqCst);
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    thread::spawn(move || {
        let pipe = pipe;
        let raw = pipe.as_raw();
        let mut data = Vec::new();
        unsafe {
            let connected = ConnectNamedPipe(raw, std::ptr::null_mut());
            if connected != 0 || GetLastError() == ERROR_PIPE_CONNECTED {
                let mut buffer = [0u8; 1024];
                loop {
                    let mut read = 0u32;
                    let ok = ReadFile(
                        raw,
                        buffer.as_mut_ptr(),
                        buffer.len() as u32,
                        &mut read,
                        std::ptr::null_mut(),
                    );
                    if ok == 0 || read == 0 {
                        break;
                    }
                    data.extend_from_slice(&buffer[..read as usize]);
                    if data.len() > PIPE_IN_BUFFER as usize {
                        break;
                    }
                }
            }
        }
        drop(pipe);
        let _ = tx.send(data);
    });
    unsafe {
        ResumeThread(main_thread.as_raw());
    }
    let deadline = Instant::now() + timeout;
    let mut captured: Option<Vec<u8>> = None;
    loop {
        match rx.recv_timeout(Duration::from_millis(150)) {
            Ok(data) => {
                captured = Some(data);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                on_wait();
                if Instant::now() >= deadline {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let job_to_close = JOB_HANDLE.swap(0, Ordering::SeqCst);
    let job = if job_to_close != 0 {
        OwnedHandle::from_raw(job_to_close as HANDLE)
    } else {
        None
    };
    unsafe {
        if let Some(ref job) = job {
            TerminateJobObject(job.as_raw(), TERMINATED_BY_DECODER);
        }
        TerminateProcess(process.as_raw(), TERMINATED_BY_DECODER);
        WaitForSingleObject(process.as_raw(), EXIT_WAIT_MS);
    }
    drop(main_thread);
    drop(process);
    drop(job);
    let data = captured
        .filter(|bytes| !bytes.is_empty())
        .ok_or(Error::CaptureTimeout)?;
    noise::stir((data.len() as u32) ^ 0xAADE_C0DE);
    let text = String::from_utf8_lossy(&data);
    aac::parse_rsa_log(&text, obfstr!("client memory"))
}

fn launch_suspended(client: &Path, cwd: &Path, job: HANDLE) -> Result<(OwnedHandle, OwnedHandle)> {
    let application = to_wide(&client.to_string_lossy());
    let mut command_line = to_wide(&format!("\"{}\"", client.to_string_lossy()));
    let directory = to_wide(&cwd.to_string_lossy());
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_SUSPENDED,
            std::ptr::null(),
            directory.as_ptr(),
            &startup,
            &mut info,
        )
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(Error::ProcessStart {
            path: client.to_path_buf(),
            code,
        });
    }
    let process = OwnedHandle::from_raw(info.hProcess).ok_or_else(|| Error::ProcessStart {
        path: client.to_path_buf(),
        code: 0,
    })?;
    let Some(main_thread) = OwnedHandle::from_raw(info.hThread) else {
        return Err(Error::ProcessStart {
            path: client.to_path_buf(),
            code: 0,
        });
    };
    if !job.is_null() && job != INVALID_HANDLE_VALUE {
        unsafe {
            AssignProcessToJobObject(job, process.as_raw());
        }
    }
    Ok((process, main_thread))
}
