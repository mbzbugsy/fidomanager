//! Process-lifecycle primitives for the killable native worker.
//!
//! Only macOS and Linux are implemented. Windows is served by the elevated-broker design (ADR-013),
//! not by this module, so non-Unix builds get stubs that fail closed rather than pretending.

#[cfg(unix)]
mod unix {
    use std::ffi::c_int;
    use std::fs;
    use std::io;

    unsafe extern "C" {
        fn close(fd: c_int) -> c_int;
        fn _exit(status: c_int) -> !;
    }

    /// Directory listing the calling process's open descriptors on this platform.
    #[cfg(target_os = "linux")]
    const FD_DIRECTORY: &str = "/proc/self/fd";
    #[cfg(not(target_os = "linux"))]
    const FD_DIRECTORY: &str = "/dev/fd";

    /// Used only when the descriptor directory cannot be listed.
    const FALLBACK_FD_LIMIT: c_int = 4_096;

    pub fn parent_process_id() -> u32 {
        std::os::unix::process::parent_id()
    }

    pub fn exit_immediately(code: i32) -> ! {
        // SAFETY: `_exit` takes no pointers and never returns. It deliberately skips atexit
        // handlers and static destructors, which may not be run safely while another thread is
        // blocked inside native library code.
        unsafe { _exit(code) }
    }

    pub fn close_inherited_descriptors() -> io::Result<usize> {
        // Collect first and drop the directory handle before closing, so the handle's own
        // descriptor is not closed out from under the iterator.
        let mut open: Option<Vec<c_int>> = None;
        if let Ok(entries) = fs::read_dir(FD_DIRECTORY) {
            let mut numbers = Vec::new();
            for entry in entries.flatten() {
                if let Some(fd) = entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.parse::<c_int>().ok())
                    .filter(|fd| *fd > 2)
                {
                    numbers.push(fd);
                }
            }
            open = Some(numbers);
        }

        let candidates = open.unwrap_or_else(|| (3..FALLBACK_FD_LIMIT).collect());
        let mut closed = 0usize;
        for fd in candidates {
            // SAFETY: closing an arbitrary descriptor number is memory-safe; `EBADF` (including
            // the already-dropped directory handle) is expected and ignored. This runs at process
            // start before any thread or library owns a descriptor above stderr.
            if unsafe { close(fd) } == 0 {
                closed += 1;
            }
        }
        Ok(closed)
    }
}

#[cfg(unix)]
pub use unix::{close_inherited_descriptors, exit_immediately, parent_process_id};

/// Process id of this process's parent as the OS reports it right now.
///
/// If the parent has died the OS reparents this process, so the value changes. The worker's
/// watchdog compares it with the pid the service declared in its hello.
#[cfg(not(unix))]
pub fn parent_process_id() -> u32 {
    0
}

/// Terminates the process without running exit handlers.
#[cfg(not(unix))]
pub fn exit_immediately(code: i32) -> ! {
    std::process::exit(code)
}

/// Closes every descriptor above stderr and returns how many were closed.
#[cfg(not(unix))]
pub fn close_inherited_descriptors() -> std::io::Result<usize> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "worker process hygiene is only implemented for Unix platforms",
    ))
}
